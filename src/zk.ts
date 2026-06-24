// ZK selective disclosure - prove a PREDICATE over a hidden field.
//
// redaction.ts hides whole fields behind salted commitments: a holder either reveals a
// field (value + salt) or withholds it entirely. That is all-or-nothing per field. A
// zero-knowledge proof is the finer instrument: a verifier checks a PREDICATE over a
// committed field - "grade >= B", "capital is between X and Y" - and learns the
// predicate holds WITHOUT learning the field's value.
//
// This module defines the predicate/proof/backend interfaces and ships ONE backend:
//
//   commitmentBackend - REAL and dependency-free. It serves EQUALITY predicates only
//   ("the committed field equals this disclosed value") by reusing the exact salted-
//   commitment scheme from redaction.ts. Proving equality means opening the commitment
//   to the asserted value; the verifier recomputes commit(value, salt) and checks it
//   against the signed commitment. This is genuinely sound and binding, but note it is
//   NOT zero-knowledge for equality: opening the commitment discloses the value. It is
//   the honest floor - selective disclosure of a single value, framed in the predicate
//   interface so it composes with future ZK backends.
//
//   range / threshold / set-membership predicates (">= B", "in [lo, hi]") are the
//   genuine ZK case: prove a relation while keeping the value hidden. That requires a
//   real ZK backend (BBS+ selective disclosure, bulletproofs range proofs, or a
//   SNARK/STARK circuit). We DELIBERATELY DO NOT fake one: commitmentBackend throws
//   "not implemented: requires a ZK backend" for any non-equality predicate. Wiring a
//   real backend is the open research/integration item.
//
// Vendor-neutral: node:crypto via attestation.ts, no extra deps.

import { canonicalize, sha256Hex } from "./attestation.ts";

/** A predicate over one committed field. `equals` is the real, dep-free case; the
 *  others name the ZK-requiring relations a real backend would serve. */
export type ZkPredicate =
  | { kind: "equals"; field: string; value: unknown }
  | { kind: "gte"; field: string; value: number }
  | { kind: "lte"; field: string; value: number }
  | { kind: "range"; field: string; min: number; max: number }
  | { kind: "memberOf"; field: string; set: unknown[] };

/** A proof object that a verifier checks against a commitment + predicate. `scheme`
 *  tags which backend produced it so a verifier rejects a proof it can't validate.
 *  `payload` is backend-specific (for the commitment backend: the opened value+salt). */
export interface ZkProof {
  scheme: string;
  predicate: ZkPredicate;
  /** the commitment the proof is made against (binds the proof to a specific field) */
  commitment: string;
  payload: Record<string, unknown>;
}

export interface ZkVerifyResult {
  ok: boolean;
  reason?: string;
}

/** A pluggable ZK backend: produce a proof that a committed field satisfies a
 *  predicate, and verify such a proof. `commitment` is the salted commitment the field
 *  was published under (the same commitments redaction.ts signs over), so a ZK proof
 *  slots into the existing signed disclosure without re-signing. */
export interface ZkBackend {
  readonly scheme: string;
  /** Prove `predicate` over `field`. The prover supplies the cleartext `value` and the
   *  `salt` the commitment was built with; returns a proof bound to `commitment`. */
  prove(args: {
    predicate: ZkPredicate;
    value: unknown;
    salt: string;
    commitment: string;
  }): ZkProof;
  /** Verify a proof against its commitment + predicate. No cleartext needed beyond
   *  what the proof itself discloses. */
  verify(proof: ZkProof): ZkVerifyResult;
}

const NOT_IMPLEMENTED =
  "not implemented: requires a ZK backend (BBS+ / bulletproofs / SNARK) for range/threshold/membership predicates";

/** Commitment for a value under a salt - identical to redaction.ts's `commit`, so a
 *  proof made here checks against the SAME commitments a redactable disclosure signs.
 *  Kept local to avoid widening redaction.ts's export surface. */
function commit(value: unknown, salt: string): string {
  return sha256Hex(`${canonicalize(value)}:${salt}`);
}

/** The real, dependency-free backend. Serves EQUALITY predicates by opening the
 *  salted commitment to the asserted value; rejects everything else with the
 *  documented not-implemented error (it does NOT fabricate a ZK proof).
 *
 *  Soundness: a proof verifies iff commit(payload.value, payload.salt) equals the
 *  commitment AND payload.value equals the predicate's asserted value. The salt's
 *  entropy is what stops a verifier from brute-forcing the value out of the commitment
 *  before disclosure - the same property redaction.ts relies on.
 *
 *  Honesty: equality here is selective DISCLOSURE, not zero-knowledge - opening the
 *  commitment reveals the value. The interface is shared so a true ZK backend can
 *  replace this for the hiding predicates without changing callers. */
export const commitmentBackend: ZkBackend = {
  scheme: "salted-commitment-equality",

  prove({ predicate, value, salt, commitment }) {
    if (predicate.kind !== "equals") {
      throw new Error(NOT_IMPLEMENTED);
    }
    // The prover must actually hold a value matching both the commitment and the claim.
    if (commit(value, salt) !== commitment) {
      throw new Error("value+salt do not open the commitment");
    }
    if (canonicalize(value) !== canonicalize(predicate.value)) {
      throw new Error("value does not satisfy the equality predicate");
    }
    return {
      scheme: this.scheme,
      predicate,
      commitment,
      payload: { value, salt },
    };
  },

  verify(proof) {
    if (proof.scheme !== this.scheme) {
      return { ok: false, reason: `unknown proof scheme '${proof.scheme}'` };
    }
    if (proof.predicate.kind !== "equals") {
      return { ok: false, reason: NOT_IMPLEMENTED };
    }
    const { value, salt } = proof.payload as { value?: unknown; salt?: unknown };
    if (typeof salt !== "string") {
      return { ok: false, reason: "proof payload missing salt" };
    }
    // 1. the disclosed value+salt must open the commitment the proof is bound to,
    if (commit(value, salt) !== proof.commitment) {
      return { ok: false, reason: "proof does not open its commitment" };
    }
    // 2. and that value must equal the predicate's asserted value.
    if (canonicalize(value) !== canonicalize(proof.predicate.value)) {
      return { ok: false, reason: "opened value does not satisfy the equality predicate" };
    }
    return { ok: true };
  },
};
