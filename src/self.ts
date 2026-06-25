// Self (self.xyz) attestation scheme - ZK proof-of-personhood as an operator attestation.
//
// Self (https://self.xyz, https://github.com/selfxyz) proves a real human is behind an
// identity via a zero-knowledge proof over a government passport/ID (NFC + zk-SNARK),
// disclosing only selected predicates (e.g. "over 18", "nationality", "not on an OFAC
// list") without revealing the document. Its agent path (`selfxyz/self-agent-id`) is
// itself ERC-8004-based, so the on-chain reference reuses the same registry seam ADP
// already has for ERC-8004.
//
// Full verification (the Groth16 ZK proof + the Celo on-chain `isVerifiedAgent` read)
// needs `@selfxyz/core` + a Celo RPC - NOT dep-light. So ADP does LIGHT recognition:
// STRUCTURAL validation of the attestation shapes + an INJECTED verifier seam, exactly
// how `erc8004*.ts` treats the on-chain half. The disclosure schema's attestation
// `scheme` already permits reverse-domain / custom values, so "Self" is recognized at
// the module level - the frozen enum is untouched.

/** The module-level recognition name for the Self scheme - the discriminant on a
 *  `SelfOnchainRef` and the human-readable label. NOT the value written into a
 *  disclosure's `operator.attestation.scheme` (that field's open arm requires a
 *  reverse-domain id; see `SELF_ATTESTATION_SCHEME`). The frozen schema enum is
 *  untouched - Self is recognized here, not added to the core grammar. */
export const SELF_SCHEME = "Self";

/** The reverse-domain id Self maps to in a disclosure's `operator.attestation.scheme`
 *  (self.xyz reversed). The schema's attestation `scheme` accepts a known enum value OR
 *  a reverse-domain custom id; "Self" is not in the frozen enum, so the disclosure-field
 *  form is this namespaced id - a vendor-namespace publication, not a core enum edit. */
export const SELF_ATTESTATION_SCHEME = "xyz.self";

/** An on-chain Self reference: the agent's verification is anchored in a Self/ERC-8004
 *  registry on `chainId` (Celo for Self's mainnet). Verifying it is an onchain read
 *  (`isVerifiedAgent` / `ownerOf`), delegated to the injected verifier. */
export interface SelfOnchainRef {
  scheme: "Self";
  chainId: number;
  /** the Self / ERC-8004 registry contract address (0x...) */
  registry: string;
  /** the agent's id in the registry (ERC-721 tokenId), when applicable */
  agentId?: string;
  /** the agent's verified key / address, when the registry records one */
  agentKey?: string;
  /** the proof's nullifier - the per-scope unique value that prevents double-registration */
  nullifier?: string;
}

/** An off-chain Self verification result (the shape `@selfxyz/core`'s backend verifier
 *  returns). `isValidDetails` carries the proof's predicate outcomes; `disclose` carries
 *  whatever attributes the holder chose to reveal. */
export interface SelfOffchainResult {
  /** the attestation document type (1 = passport, 2 = EU ID card, ...) */
  attestationId: number | string;
  /** the application scope the proof was bound to (anti-cross-app replay) */
  scope: string;
  /** the per-scope unique nullifier (prevents the same human registering twice) */
  nullifier: string;
  isValidDetails: {
    /** the ZK proof itself verified */
    isValid: boolean;
    /** the disclosed age predicate (e.g. >= minimumAge) held, when requested */
    isMinimumAgeValid?: boolean;
    /** INVERTED LOGIC: `true` means the user IS on a sanctions (OFAC) list. A valid,
     *  NON-sanctioned user therefore has `isOfacValid === false`. */
    isOfacValid?: boolean;
  };
  /** the attributes the holder chose to disclose */
  disclose?: {
    nationality?: string;
    minimumAge?: number;
    /** echoes the OFAC predicate; same inverted meaning (`true` => sanctioned) */
    ofac?: boolean;
  };
}

/** A Self attestation is either an on-chain reference or an off-chain proof result. */
export type SelfAttestation = SelfOnchainRef | SelfOffchainResult;

/** True if the attestation is the on-chain reference shape (vs the off-chain result). */
export function isSelfOnchainRef(att: SelfAttestation): att is SelfOnchainRef {
  return (att as SelfOnchainRef).scheme === SELF_SCHEME;
}

/** Inject the heavy verification (the Groth16 ZK proof check via `@selfxyz/core`, or an
 *  on-chain `isVerifiedAgent` read). Returns `{ valid, nullifier? }`; ADP bundles no
 *  implementation - the consumer wires it. */
export type SelfVerifier = (
  att: SelfAttestation,
) => Promise<{ valid: boolean; nullifier?: string }>;

export interface VerifySelfOptions {
  verifier?: SelfVerifier;
}

export interface SelfVerification {
  ok: boolean;
  /** the proof nullifier (from the attestation or the injected verifier) */
  nullifier?: string;
  /** the attributes Self disclosed (nationality, minimumAge, ...) */
  disclosed?: Record<string, unknown>;
  reason?: string;
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function structurallyValid(att: SelfAttestation): { ok: boolean; reason?: string } {
  if (isSelfOnchainRef(att)) {
    if (!Number.isInteger(att.chainId) || att.chainId < 0) {
      return { ok: false, reason: "Self onchain ref needs a non-negative chainId" };
    }
    if (!ADDRESS.test(att.registry)) {
      return { ok: false, reason: "Self onchain ref registry must be a 0x EVM address" };
    }
    return { ok: true };
  }
  // off-chain result
  if (typeof att.scope !== "string" || att.scope.length === 0) {
    return { ok: false, reason: "Self result needs a non-empty scope" };
  }
  if (typeof att.nullifier !== "string" || att.nullifier.length === 0) {
    return { ok: false, reason: "Self result needs a nullifier" };
  }
  if (att.isValidDetails === undefined || typeof att.isValidDetails.isValid !== "boolean") {
    return { ok: false, reason: "Self result needs isValidDetails.isValid" };
  }
  return { ok: true };
}

/** Verify a Self attestation.
 *
 *  STRUCTURAL (always): the shape is well-formed (required fields present); and for an
 *  off-chain result the embedded `isValidDetails.isValid` must be true AND
 *  `isOfacValid` must NOT be true (remember: `isOfacValid === true` means the user is on
 *  a sanctions list, so a sanctioned user fails). The on-chain ref is structure-only
 *  without a verifier - it carries no self-contained proof to check locally.
 *
 *  HEAVY (opt-in): when `opts.verifier` is supplied (the consumer wiring `@selfxyz/core`
 *  or an on-chain `isVerifiedAgent` read), its `valid === true` is also required, and its
 *  `nullifier` (if any) is surfaced.
 *
 *  Returns the nullifier and disclosed attributes on success. */
export async function verifySelfAttestation(
  att: SelfAttestation,
  opts: VerifySelfOptions = {},
): Promise<SelfVerification> {
  const structural = structurallyValid(att);
  if (!structural.ok) return { ok: false, reason: structural.reason };

  const onchain = isSelfOnchainRef(att);
  let nullifier = att.nullifier;
  let disclosed: Record<string, unknown> | undefined;

  if (!onchain) {
    if (!att.isValidDetails.isValid) {
      return {
        ok: false,
        nullifier,
        reason: "Self proof is not valid (isValidDetails.isValid is false)",
      };
    }
    // Inverted OFAC: true => the user IS sanctioned.
    if (att.isValidDetails.isOfacValid === true) {
      return { ok: false, nullifier, reason: "Self subject is on a sanctions (OFAC) list" };
    }
    if (att.disclose !== undefined) disclosed = { ...att.disclose };
  } else if (opts.verifier === undefined) {
    // An on-chain ref carries no self-contained proof; without a verifier we can only
    // confirm the shape, not that the chain actually attests the agent.
    return {
      ok: false,
      nullifier,
      reason: "Self onchain ref needs an injected verifier (no local proof to check)",
    };
  }

  if (opts.verifier !== undefined) {
    const result = await opts.verifier(att);
    if (!result.valid) {
      return { ok: false, nullifier, reason: "injected Self verifier rejected the attestation" };
    }
    if (result.nullifier !== undefined) nullifier = result.nullifier;
  }

  const out: SelfVerification = { ok: true };
  if (nullifier !== undefined) out.nullifier = nullifier;
  if (disclosed !== undefined) out.disclosed = disclosed;
  return out;
}

/** ADP's `operator.attestation` shape (scheme + level + optional evidence). Mirrors the
 *  inferred type of the schema's attestation object, without importing the zod type, so
 *  this module stays decoupled from the document layer. */
export interface OperatorAttestation {
  scheme: string;
  level: "none" | "signed" | "registry_attested";
  evidence?: string;
}

/** Map a verified Self attestation into ADP's `operator.attestation` field. The scheme
 *  is the reverse-domain `SELF_ATTESTATION_SCHEME` (the schema enum is frozen). An
 *  on-chain ref that verified is `registry_attested` (the chain attests it); a verified
 *  off-chain result is `signed` (a proof, not a registry record). A failed verification
 *  is `none`. The nullifier (when present) is recorded as `evidence`. */
export function selfToOperatorAttestation(
  att: SelfAttestation,
  result: SelfVerification,
): OperatorAttestation {
  if (!result.ok) return { scheme: SELF_ATTESTATION_SCHEME, level: "none" };
  const level = isSelfOnchainRef(att) ? "registry_attested" : "signed";
  const out: OperatorAttestation = { scheme: SELF_ATTESTATION_SCHEME, level };
  if (result.nullifier !== undefined) out.evidence = `self:nullifier:${result.nullifier}`;
  return out;
}
