// Verifiable Credentials bridge - express a signed disclosure as a W3C VC (Data Model 2.0).
//
// A SignedDisclosure already is, structurally, a verifiable credential: a claim set
// (the disclosure) plus an asymmetric proof (the ed25519 envelope signature) that a
// counterparty checks with the public key alone. This module re-shapes it into the
// W3C VC Data Model 2.0 so it interoperates with VC tooling (wallets, presentation
// exchange, status lists) without re-signing or weakening the original guarantee.
//
// Proof suite. The proof is a `DataIntegrityProof` whose `cryptosuite` is the
// ADP-namespaced, deliberately NON-registered `adp-jcs-2024` - it is NOT the
// registered `eddsa-jcs-2022` or `Ed25519Signature2020` (squatting a registered suite
// name while signing different bytes is exactly the mislabel this bridge used to ship).
// `adp-jcs-2024` reuses the envelope's ed25519 signature verbatim, computed over the
// package's RFC 8785 (JCS) canonicalization of the disclosure, multibase-encoded as the
// `proofValue` per Data Integrity. So the VC verifies through the same path as the bare
// envelope - we delegate to `verifyDisclosureSignature` on the reconstructed
// SignedDisclosure - and no second trust root is introduced. A generic VC verifier that
// does not recognise `adp-jcs-2024` will (correctly) decline to verify the proof rather
// than be misled into running URDNA2015/JCS Data Integrity over different bytes.

import { Buffer } from "node:buffer";
import { verifyDisclosureSignature } from "./attestation.ts";
import { agentIdToDidKey, didKeyToAgentId, multibaseBase58btcDecode, multibaseBase58btcEncode } from "./did.ts";
import { SignedDisclosureSchema, type AgentDisclosure, type SignedDisclosure } from "./schema.ts";

// VC Data Model 2.0: a single base context that folds in the Data Integrity terms.
const VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";
const CREDENTIAL_TYPE = "AgentDisclosureCredential";
const PROOF_TYPE = "DataIntegrityProof";
const PROOF_PURPOSE = "assertionMethod";
// ADP-namespaced, NON-registered: names the JCS canonicalization + reused ed25519
// envelope signature, so a verifier never mistakes it for a registered DI cryptosuite.
const PROOF_CRYPTOSUITE = "adp-jcs-2024";

export interface VerifiableCredentialProof {
  type: typeof PROOF_TYPE;
  /** the ADP-namespaced cryptosuite the proofValue is computed under (JCS + ed25519) */
  cryptosuite: typeof PROOF_CRYPTOSUITE;
  proofPurpose: typeof PROOF_PURPOSE;
  /** the issuer's did:key#<fragment> - the ed25519 verification method */
  verificationMethod: string;
  created: string;
  /** the ed25519 envelope signature, multibase base58btc encoded (Data Integrity form) */
  proofValue: string;
}

export interface AgentDisclosureCredentialSubject extends AgentDisclosure {
  /** the credential subject id = the agent's did:key */
  id: string;
}

export interface VerifiableCredential {
  "@context": [typeof VC_CONTEXT_V2];
  id?: string;
  type: ["VerifiableCredential", typeof CREDENTIAL_TYPE];
  issuer: string;
  /** VC 2.0 validity window (replaces v1.1 issuanceDate / expirationDate) */
  validFrom: string;
  validUntil: string;
  credentialSubject: AgentDisclosureCredentialSubject;
  proof: VerifiableCredentialProof;
}

export interface ToVerifiableCredentialOptions {
  /** the credential issuer; defaults to the agentId's did:key */
  issuer?: string;
  /** an id for this credential (a URI); omitted if unset */
  id?: string;
  /** ISO-8601 validFrom; defaults to the disclosure's issuedAt */
  validFrom?: string;
  /** ISO-8601 validUntil; defaults to the disclosure's validUntil */
  validUntil?: string;
}

/** Wrap a SignedDisclosure as a W3C Verifiable Credential (Data Model 2.0). The
 *  credentialSubject is the disclosure plus a did:key subject id; the DataIntegrityProof
 *  carries the existing ed25519 envelope signature (multibase), so the VC verifies via
 *  the same canonicalization as the bare envelope (no re-signing). */
export function toVerifiableCredential(
  signed: SignedDisclosure,
  opts: ToVerifiableCredentialOptions = {},
): VerifiableCredential {
  const did = agentIdToDidKey(signed.disclosure.agentId);
  const issuer = opts.issuer ?? did;
  const validFrom = opts.validFrom ?? signed.disclosure.issuedAt;
  const validUntil = opts.validUntil ?? signed.disclosure.validUntil;

  const vc: VerifiableCredential = {
    "@context": [VC_CONTEXT_V2],
    type: ["VerifiableCredential", CREDENTIAL_TYPE],
    issuer,
    validFrom,
    validUntil,
    credentialSubject: { id: did, ...signed.disclosure },
    proof: {
      type: PROOF_TYPE,
      cryptosuite: PROOF_CRYPTOSUITE,
      proofPurpose: PROOF_PURPOSE,
      // did:key fragment is the multibase key id - identical to the method-specific id.
      verificationMethod: `${did}#${did.slice("did:key:".length)}`,
      created: validFrom,
      proofValue: multibaseBase58btcEncode(Buffer.from(signed.signature.value, "hex")),
    },
  };
  if (opts.id !== undefined) vc.id = opts.id;
  return vc;
}

/** Reconstruct the SignedDisclosure from a VC: strip the subject `id`, lift the
 *  disclosure out of credentialSubject, and rebuild the ed25519 envelope from the
 *  proof (the publicKey is the agentId, the value is the multibase proofValue decoded
 *  back to hex). */
export function fromVerifiableCredential(vc: VerifiableCredential): SignedDisclosure {
  const { id: _id, ...disclosure } = vc.credentialSubject;
  return SignedDisclosureSchema.parse({
    disclosure,
    signature: {
      algorithm: "ed25519",
      publicKey: disclosure.agentId,
      value: Buffer.from(multibaseBase58btcDecode(vc.proof.proofValue)).toString("hex"),
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
