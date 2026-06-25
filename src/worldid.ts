// World ID (Worldcoin) attestation scheme - proof-of-personhood as an operator attestation.
//
// World ID (https://world.org, https://docs.world.org) proves a unique human is behind an
// action via a Groth16 zero-knowledge proof over a Semaphore membership tree: a person's
// World ID is a leaf, the proof shows membership without revealing which leaf, and a
// per-(person, action) `nullifier_hash` makes a second submission for the same action
// detectable (the sybil key) without linking it to identity. Verification levels grade the
// credential strength ("orb" = an iris-scanned unique-human credential; "device" = a weaker
// device-bound one; "secure_document" / "document" = NFC passport reads).
//
// The proof is a Groth16 ZK proof over a Semaphore tree and the canonical check is an
// on-chain / Developer Portal call against the live merkle root - NOT locally verifiable
// dep-free. So ADP does LIGHT recognition: STRUCTURAL validation of the proof shape + an
// INJECTED verifier seam, exactly how `self.ts` / `erc8004*.ts` treat the heavy half. The
// disclosure schema's attestation `scheme` already permits reverse-domain custom values, so
// World ID is recognized at the module level - the frozen enum is untouched.

import type { OperatorAttestation } from "./self.ts";

/** The module-level recognition name for the World ID scheme - the discriminant on a
 *  `WorldIdAttestation` and the human-readable label. NOT the value written into a
 *  disclosure's `operator.attestation.scheme` (that field's open arm requires a
 *  reverse-domain id; see `WORLDID_ATTESTATION_SCHEME`). The frozen schema enum is
 *  untouched - World ID is recognized here, not added to the core grammar. */
export const WORLDID_SCHEME = "WorldID";

/** The reverse-domain id World ID maps to in a disclosure's `operator.attestation.scheme`
 *  (world.org reversed). The schema's attestation `scheme` accepts a known enum value OR a
 *  reverse-domain custom id; "WorldID" is not in the frozen enum, so the disclosure-field
 *  form is this namespaced id - a vendor-namespace publication, not a core enum edit. */
export const WORLDID_ATTESTATION_SCHEME = "org.world";

/** World ID's verification levels, strongest first. "orb" is the iris-scanned unique-human
 *  credential; the rest are progressively weaker (device-bound / document reads). */
export const WORLDID_VERIFICATION_LEVELS = [
  "orb",
  "device",
  "secure_document",
  "document",
] as const;

export type WorldIdVerificationLevel = (typeof WORLDID_VERIFICATION_LEVELS)[number];

/** A World ID proof, the shape IDKit produces and the Developer Portal / on-chain router
 *  verifies. `nullifier_hash` is the per-(person, action) sybil key; `merkle_root` is the
 *  tree root the membership is proven against; `proof` is the ABI-encoded Groth16 proof. */
export interface WorldIdAttestation {
  scheme: "WorldID";
  /** the World ID app id the action belongs to ("app_..." from the Developer Portal) */
  app_id: string;
  /** the external-nullifier action the proof is scoped to (anti-cross-action replay) */
  action: string;
  /** the optional signal the proof is bound to (e.g. a recipient address) */
  signal?: string;
  /** the per-(person, action) nullifier (hex) - the sybil-resistance key */
  nullifier_hash: string;
  /** the Semaphore merkle root the membership is proven against (hex) */
  merkle_root: string;
  /** the ABI-encoded Groth16 proof (hex) */
  proof: string;
  /** the credential strength the proof carries */
  verification_level: WorldIdVerificationLevel;
}

/** Inject the heavy verification (the Groth16 proof check via the Developer Portal
 *  `/verify` endpoint or the on-chain `World ID Router`). Returns `{ valid, nullifier? }`;
 *  ADP bundles no implementation - the consumer wires it. */
export type WorldIdVerifier = (
  att: WorldIdAttestation,
) => Promise<{ valid: boolean; nullifier?: string }>;

export interface VerifyWorldIdOptions {
  verifier?: WorldIdVerifier;
}

export interface WorldIdVerification {
  /** the structural shape is well-formed */
  structural: boolean;
  /** the proof is cryptographically valid (only an injected verifier can assert this) */
  valid: boolean;
  /** the proof nullifier (from the attestation or the injected verifier) */
  nullifier?: string;
  reason?: string;
}

const HEX = /^0x[0-9a-fA-F]+$/;
const VERIFICATION_LEVELS: ReadonlySet<string> = new Set(WORLDID_VERIFICATION_LEVELS);

/** STRUCTURAL validation: the right scheme, an "app_"-prefixed app id, a non-empty action,
 *  hex `nullifier_hash` / `merkle_root` / `proof`, and a known `verification_level`. This is
 *  shape-only - it does NOT check the Groth16 proof (that is the injected verifier's job). */
export function validateWorldIdStructural(att: WorldIdAttestation): boolean {
  if (att.scheme !== WORLDID_SCHEME) return false;
  if (typeof att.app_id !== "string" || !att.app_id.startsWith("app_")) return false;
  if (typeof att.action !== "string" || att.action.length === 0) return false;
  if (typeof att.nullifier_hash !== "string" || !HEX.test(att.nullifier_hash)) return false;
  if (typeof att.merkle_root !== "string" || !HEX.test(att.merkle_root)) return false;
  if (typeof att.proof !== "string" || !HEX.test(att.proof)) return false;
  if (!VERIFICATION_LEVELS.has(att.verification_level)) return false;
  return true;
}

/** Verify a World ID attestation.
 *
 *  STRUCTURAL (always): the shape is well-formed (`validateWorldIdStructural`). A World ID
 *  proof carries no self-contained, dep-free check, so WITHOUT a verifier the result is
 *  `{ structural: true, valid: false, nullifier }` - crypto-pending, fully representable, it
 *  does NOT throw. The nullifier is surfaced from the attestation so a consumer can still do
 *  sybil bookkeeping on the structurally-valid claim.
 *
 *  HEAVY (opt-in): when `opts.verifier` is supplied (the consumer wiring the Developer Portal
 *  `/verify` call or the on-chain router), its `valid` is the answer and its `nullifier` (if
 *  any) is surfaced. */
export async function verifyWorldId(
  att: WorldIdAttestation,
  opts: VerifyWorldIdOptions = {},
): Promise<WorldIdVerification> {
  if (!validateWorldIdStructural(att)) {
    return { structural: false, valid: false, reason: "World ID attestation is malformed" };
  }

  let nullifier = att.nullifier_hash;

  if (opts.verifier === undefined) {
    // No verifier: structurally sound but the proof is unverified (crypto-pending). Not an
    // error - the nullifier is still usable for sybil bookkeeping on the claimed proof.
    return {
      structural: true,
      valid: false,
      nullifier,
      reason: "World ID proof needs an injected verifier (Groth16 not locally checkable)",
    };
  }

  const result = await opts.verifier(att);
  if (result.nullifier !== undefined) nullifier = result.nullifier;
  if (!result.valid) {
    return {
      structural: true,
      valid: false,
      nullifier,
      reason: "injected World ID verifier rejected the proof",
    };
  }
  return { structural: true, valid: true, nullifier };
}

/** Map a verified World ID attestation into ADP's `operator.attestation` field. The scheme
 *  is the reverse-domain `WORLDID_ATTESTATION_SCHEME` (the schema enum is frozen). A proof
 *  that the injected verifier accepted is `registry_attested` at the "orb" level (the
 *  iris-scanned unique-human credential anchored on-chain) and `signed` otherwise; a proof
 *  that did not verify is `none`. The nullifier (when present) is recorded as `evidence`. */
export function worldIdToOperatorAttestation(
  att: WorldIdAttestation,
  result: WorldIdVerification,
): OperatorAttestation {
  if (!result.valid) return { scheme: WORLDID_ATTESTATION_SCHEME, level: "none" };
  const level = att.verification_level === "orb" ? "registry_attested" : "signed";
  const out: OperatorAttestation = { scheme: WORLDID_ATTESTATION_SCHEME, level };
  if (result.nullifier !== undefined) out.evidence = `worldid:nullifier:${result.nullifier}`;
  return out;
}
