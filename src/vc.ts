// Verifiable Credentials bridge - express a signed disclosure as a W3C VC.
//
// A SignedDisclosure already is, structurally, a verifiable credential: a claim set
// (the disclosure) plus an asymmetric proof (the ed25519 envelope signature) that a
// counterparty checks with the public key alone. This module re-shapes it into the
// W3C VC Data Model so it interoperates with VC tooling (wallets, presentation
// exchange, status lists) without re-signing or weakening the original guarantee.
//
// Proof suite. We surface an Ed25519Signature2020-STYLE proof. The "-style" is
// deliberate: a strict Ed25519Signature2020 proof signs over the RDF-canonicalized
// (URDNA2015) credential, which would require a JSON-LD processor and a fresh
// signature - heavyweight, and it would discard the existing envelope signature that
// is already the protocol's trust anchor. Instead the proof REUSES the envelope's
// ed25519 signature verbatim: `proofValue` is the same hex signature, computed over
// `canonicalize(disclosure)` (the package's deterministic JSON, sorted keys). So the
// VC verifies through exactly the same path as the bare envelope - we delegate to
// `verifyDisclosureSignature` on the reconstructed SignedDisclosure - and no second
// trust root is introduced. `cryptosuite: "adp-canonicalize-2024"` names the
// canonicalization so a verifier never mistakes this for URDNA2015-based JCS.

import { verifyDisclosureSignature } from "./attestation.ts";
import { agentIdToDidKey, didKeyToAgentId } from "./did.ts";
import { SignedDisclosureSchema, type AgentDisclosure, type SignedDisclosure } from "./schema.ts";

const VC_CONTEXT = "https://www.w3.org/2018/credentials/v1";
const SECURITY_CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1";
const CREDENTIAL_TYPE = "AgentDisclosureCredential";
const PROOF_TYPE = "Ed25519Signature2020";
const PROOF_PURPOSE = "assertionMethod";
// Names the bytes the proof is over: the package's canonicalize(), NOT URDNA2015.
const PROOF_CRYPTOSUITE = "adp-canonicalize-2024";

export interface VerifiableCredentialProof {
  type: typeof PROOF_TYPE;
  /** the canonicalization the proofValue is computed over (package canonicalize) */
  cryptosuite: typeof PROOF_CRYPTOSUITE;
  proofPurpose: typeof PROOF_PURPOSE;
  /** the issuer's did:key#<fragment> - the ed25519 verification method */
  verificationMethod: string;
  created: string;
  /** the ed25519 envelope signature (hex), reused verbatim */
  proofValue: string;
}

export interface AgentDisclosureCredentialSubject extends AgentDisclosure {
  /** the credential subject id = the agent's did:key */
  id: string;
}

export interface VerifiableCredential {
  "@context": [typeof VC_CONTEXT, typeof SECURITY_CONTEXT];
  id?: string;
  type: ["VerifiableCredential", typeof CREDENTIAL_TYPE];
  issuer: string;
  issuanceDate: string;
  credentialSubject: AgentDisclosureCredentialSubject;
  proof: VerifiableCredentialProof;
}

export interface ToVerifiableCredentialOptions {
  /** the credential issuer; defaults to the agentId's did:key */
  issuer?: string;
  /** an id for this credential (a URI); omitted if unset */
  id?: string;
  /** ISO-8601 issuanceDate; defaults to the disclosure's issuedAt */
  issuanceDate?: string;
}

/** Wrap a SignedDisclosure as a W3C Verifiable Credential. The credentialSubject is
 *  the disclosure plus a did:key subject id; the proof carries the existing ed25519
 *  envelope signature, so the VC verifies via the same canonicalization as the
 *  bare envelope (no re-signing). */
export function toVerifiableCredential(
  signed: SignedDisclosure,
  opts: ToVerifiableCredentialOptions = {},
): VerifiableCredential {
  const did = agentIdToDidKey(signed.disclosure.agentId);
  const issuer = opts.issuer ?? did;
  const issuanceDate = opts.issuanceDate ?? signed.disclosure.issuedAt;

  const vc: VerifiableCredential = {
    "@context": [VC_CONTEXT, SECURITY_CONTEXT],
    type: ["VerifiableCredential", CREDENTIAL_TYPE],
    issuer,
    issuanceDate,
    credentialSubject: { id: did, ...signed.disclosure },
    proof: {
      type: PROOF_TYPE,
      cryptosuite: PROOF_CRYPTOSUITE,
      proofPurpose: PROOF_PURPOSE,
      // did:key fragment is the multibase key id - identical to the method-specific id.
      verificationMethod: `${did}#${did.slice("did:key:".length)}`,
      created: issuanceDate,
      proofValue: signed.signature.value,
    },
  };
  if (opts.id !== undefined) vc.id = opts.id;
  return vc;
}

/** Reconstruct the SignedDisclosure from a VC: strip the subject `id`, lift the
 *  disclosure out of credentialSubject, and rebuild the ed25519 envelope from the
 *  proof (the publicKey is the agentId, the value is the proofValue). */
export function fromVerifiableCredential(vc: VerifiableCredential): SignedDisclosure {
  const { id: _id, ...disclosure } = vc.credentialSubject;
  return SignedDisclosureSchema.parse({
    disclosure,
    signature: {
      algorithm: "ed25519",
      publicKey: disclosure.agentId,
      value: vc.proof.proofValue,
    },
  });
}

export interface CredentialCheck {
  ok: boolean;
  reason?: string;
}

/** Verify a VC: the embedded proof must verify (delegated to the envelope check on
 *  the reconstructed SignedDisclosure) AND the subject's did:key must resolve to the
 *  agentId that signed. Returns the first failure reason. */
export function verifyVerifiableCredential(vc: VerifiableCredential): CredentialCheck {
  let signed: SignedDisclosure;
  try {
    signed = fromVerifiableCredential(vc);
  } catch (err) {
    return { ok: false, reason: `malformed credential: ${(err as Error).message}` };
  }

  let subjectAgentId: string;
  try {
    subjectAgentId = didKeyToAgentId(vc.credentialSubject.id);
  } catch (err) {
    return { ok: false, reason: `subject id is not an ed25519 did:key: ${(err as Error).message}` };
  }
  if (subjectAgentId !== signed.disclosure.agentId) {
    return { ok: false, reason: "subject did:key does not match the disclosure agentId" };
  }

  return verifyDisclosureSignature(signed);
}
