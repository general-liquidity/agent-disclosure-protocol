// Bridge: carry zero-knowledge range proofs ABOUT a hidden disclosure attribute
// alongside the disclosure itself, so a verifier's policy can require one.
//
// A disclosure (schema.ts) publishes some fields and may withhold others. Sometimes a
// counterparty does not need a withheld field's VALUE, only a relation over it: "the
// red-team score is >= 80", "the capital tier is in [2, 4]". This module lets an agent
// attach a real, sound, zero-knowledge range proof (zkRange.ts) for such an attribute,
// and lets a verifier state which attributes it requires a valid range proof for.
//
// HONEST BINDING NOTE (the same no-algebraic-bridge caveat as zkRange.ts / zk.ts):
//   The proven attribute is bound to the proof's OWN Pedersen commitment (a curve point
//   carried inside the FieldRangeProof), NOT cryptographically into the signed
//   disclosure's hash. zkRange commits the value under its own secp256k1 Pedersen scheme;
//   the disclosure is signed over the salted-SHA256 / canonical-JSON document. There is no
//   algebraic bridge between a hash commitment and a Pedersen commitment without a circuit.
//   So a FieldRangeProof is a VERIFIABLE CLAIM THAT TRAVELS WITH the disclosure: it proves,
//   in zero knowledge, that SOME committed value satisfies the predicate, and the verifier
//   checks that claim. It does NOT prove that value is the same one bound into the signed
//   document. Closing that gap (binding the Pedersen commitment into the signed disclosure)
//   needs a circuit that relates the two commitments, and is the open item. Stated plainly:
//   the attribute name in `FieldRangeProof.attribute` is an ASSERTED label, attested by the
//   agent carrying the proof, not a cryptographic link to the disclosure field of that name.

import { z } from "zod";
import { proveRange, verifyRange } from "./zkRange.ts";

// ── Predicate schema (mirrors the range-capable ZkPredicate kinds) ───────────
// Only the hiding predicates zkRange serves: gte / lte / range. (equals is handled by
// commitmentBackend in zk.ts and is not zero-knowledge, so it is out of scope here.)
const RangePredicateSchema = z.union([
  z.object({ kind: z.literal("gte"), field: z.string(), value: z.number() }),
  z.object({ kind: z.literal("lte"), field: z.string(), value: z.number() }),
  z.object({ kind: z.literal("range"), field: z.string(), min: z.number(), max: z.number() }),
]);

/** A zero-knowledge range proof about ONE hidden disclosure attribute, packaged to travel
 *  alongside a disclosure. Carries the zkRange Pedersen commitment + proof payload. */
export const FieldRangeProofSchema = z.object({
  /** the disclosure attribute this proof is about (an asserted label, see binding note) */
  attribute: z.string(),
  /** the predicate proven over the hidden value (gte / lte / range) */
  predicate: RangePredicateSchema,
  /** the zkRange Pedersen commitment the proof binds to (compressed-point hex) */
  commitment: z.string(),
  /** the zkRange proof scheme tag + backend payload */
  scheme: z.string(),
  payload: z.record(z.string(), z.unknown()),
});

export type FieldRangeProof = z.infer<typeof FieldRangeProofSchema>;

/** A range predicate restricted to the zk-hiding kinds zkRange serves. */
export type RangePredicate = z.infer<typeof RangePredicateSchema>;

/** Prove (in zero knowledge) that a hidden attribute `value` satisfies `predicate`, and
 *  package the result as a FieldRangeProof that can travel with a disclosure.
 *
 *  Throws if the value does not satisfy the predicate (an honest prover cannot build a
 *  proof for a false statement), or if @noble/curves is not installed. */
export async function proveDisclosureAttribute(
  attribute: string,
  value: unknown,
  predicate: RangePredicate,
  salt: string,
): Promise<FieldRangeProof> {
  const proof = await proveRange({ predicate, value, salt });
  return {
    attribute,
    predicate,
    commitment: proof.commitment,
    scheme: proof.scheme,
    payload: proof.payload,
  };
}

/** Verify a FieldRangeProof: the carried proof is sound AND it proves exactly its stated
 *  predicate. Returns ok + a reason on failure. Does not throw on a bad proof (only an
 *  absent curve dependency surfaces as a reason). */
export async function verifyDisclosureAttribute(
  fp: FieldRangeProof,
): Promise<{ ok: boolean; reason?: string }> {
  const result = await verifyRange({
    scheme: fp.scheme,
    predicate: fp.predicate,
    commitment: fp.commitment,
    payload: fp.payload,
  });
  return result.ok ? { ok: true } : { ok: false, reason: result.reason };
}

// ── Verifier-side: require a valid range proof per attribute ─────────────────

/** A verifier's statement that it needs a valid range proof for `attribute` meeting (or
 *  stronger than) `predicate`. */
export const AttributeRequirementSchema = z.object({
  attribute: z.string(),
  predicate: RangePredicateSchema,
});

export type AttributeRequirement = z.infer<typeof AttributeRequirementSchema>;

/** Does `proven` meet OR exceed the strength of what `required` asks? Both must be the
 *  same predicate kind over the same attribute (checked by the caller). "Stronger" means
 *  the proven relation logically implies the required one:
 *    gte:   proving `>= P` satisfies a requirement `>= R` iff P >= R.
 *    lte:   proving `<= P` satisfies a requirement `<= R` iff P <= R.
 *    range: proving `v in [pMin, pMax]` satisfies `v in [rMin, rMax]` iff
 *           [pMin, pMax] is contained in [rMin, rMax] (a tighter band implies the wider one). */
function satisfies(required: RangePredicate, proven: RangePredicate): boolean {
  if (required.kind !== proven.kind) return false;
  if (required.kind === "gte" && proven.kind === "gte") return proven.value >= required.value;
  if (required.kind === "lte" && proven.kind === "lte") return proven.value <= required.value;
  if (required.kind === "range" && proven.kind === "range") {
    return proven.min >= required.min && proven.max <= required.max;
  }
  return false;
}

/** A verifier supplies the range proofs an agent attached + the requirements its policy
 *  states. For each requirement, this checks there is a proof for that attribute that
 *  (a) cryptographically verifies and (b) proves a predicate at least as strong as the one
 *  required. `missing` lists requirements with no satisfying proof; `reasons` explains why
 *  each missing requirement was not met. ok iff `missing` is empty.
 *
 *  Binding caveat applies (see the module header): a satisfying proof attests that SOME
 *  committed value meets the predicate under the asserted attribute label, not that it is
 *  the disclosure's signed field of that name. */
export async function requireAttributeProofs(
  proofs: FieldRangeProof[],
  requirements: AttributeRequirement[],
): Promise<{ ok: boolean; missing: string[]; reasons: string[] }> {
  const missing: string[] = [];
  const reasons: string[] = [];

  for (const req of requirements) {
    const candidates = proofs.filter((p) => p.attribute === req.attribute);
    if (candidates.length === 0) {
      missing.push(req.attribute);
      reasons.push(`${req.attribute}: no range proof provided`);
      continue;
    }

    let met = false;
    let lastReason = `${req.attribute}: no provided proof satisfies the required predicate`;
    for (const candidate of candidates) {
      if (!satisfies(req.predicate, candidate.predicate)) {
        lastReason = `${req.attribute}: proof predicate ${describe(candidate.predicate)} is weaker than required ${describe(req.predicate)}`;
        continue;
      }
      const verified = await verifyDisclosureAttribute(candidate);
      if (!verified.ok) {
        lastReason = `${req.attribute}: proof does not verify (${verified.reason})`;
        continue;
      }
      met = true;
      break;
    }

    if (!met) {
      missing.push(req.attribute);
      reasons.push(lastReason);
    }
  }

  return { ok: missing.length === 0, missing, reasons };
}

function describe(pred: RangePredicate): string {
  switch (pred.kind) {
    case "gte":
      return `>= ${pred.value}`;
    case "lte":
      return `<= ${pred.value}`;
    case "range":
      return `in [${pred.min}, ${pred.max}]`;
  }
}
