import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import {
  type AttributeRequirement,
  type FieldRangeProof,
  proveDisclosureAttribute,
  requireAttributeProofs,
  verifyDisclosureAttribute,
} from "../src/zkDisclosure.ts";

// Skip the whole suite cleanly if the optional curve dependency is absent.
let nobleAvailable = true;
try {
  await import("@noble/curves/secp256k1");
} catch {
  nobleAvailable = false;
}

const maybe = nobleAvailable ? test : test.skip;
if (!nobleAvailable) {
  test("zkDisclosure suite skipped: @noble/curves not installed", { skip: true }, () => {});
}

const salt = () => randomBytes(16).toString("hex");

// --- proveDisclosureAttribute / verifyDisclosureAttribute ---

maybe("attribute in range -> proves and verifies ok", async () => {
  const fp = await proveDisclosureAttribute(
    "score",
    95,
    { kind: "gte", field: "score", value: 80 },
    salt(),
  );
  assert.equal(fp.attribute, "score");
  const result = await verifyDisclosureAttribute(fp);
  assert.equal(result.ok, true, result.reason);
});

maybe("range predicate: attribute in [lo, hi] proves and verifies", async () => {
  const fp = await proveDisclosureAttribute(
    "tier",
    3,
    { kind: "range", field: "tier", min: 2, max: 4 },
    salt(),
  );
  assert.equal((await verifyDisclosureAttribute(fp)).ok, true);
});

maybe("attribute out of range -> prover throws", async () => {
  await assert.rejects(
    () => proveDisclosureAttribute("score", 50, { kind: "gte", field: "score", value: 80 }, salt()),
    /does not satisfy predicate/,
  );
});

maybe("verifier rejects a tampered proof", async () => {
  const fp = await proveDisclosureAttribute(
    "score",
    95,
    { kind: "gte", field: "score", value: 80 },
    salt(),
  );
  // Flip a sub-challenge so the Fiat-Shamir check fails.
  const payload = fp.payload as { proofs: { bitProofs: { c0: string }[] }[] };
  const orig = payload.proofs[0].bitProofs[0].c0;
  payload.proofs[0].bitProofs[0].c0 = (BigInt(`0x${orig}`) ^ 1n).toString(16);
  const result = await verifyDisclosureAttribute(fp);
  assert.equal(result.ok, false);
});

// --- requireAttributeProofs ---

maybe("verifier requiring score>=80 accepts a proof of score>=80", async () => {
  const fp = await proveDisclosureAttribute(
    "score",
    95,
    { kind: "gte", field: "score", value: 80 },
    salt(),
  );
  const reqs: AttributeRequirement[] = [
    { attribute: "score", predicate: { kind: "gte", field: "score", value: 80 } },
  ];
  const result = await requireAttributeProofs([fp], reqs);
  assert.equal(result.ok, true, result.reasons.join("; "));
  assert.deepEqual(result.missing, []);
});

maybe("verifier requiring score>=80 accepts a STRONGER proof of score>=90", async () => {
  const fp = await proveDisclosureAttribute(
    "score",
    95,
    { kind: "gte", field: "score", value: 90 },
    salt(),
  );
  const reqs: AttributeRequirement[] = [
    { attribute: "score", predicate: { kind: "gte", field: "score", value: 80 } },
  ];
  const result = await requireAttributeProofs([fp], reqs);
  assert.equal(result.ok, true, result.reasons.join("; "));
});

maybe("range: a tighter band [2,3] satisfies a wider requirement [2,4]", async () => {
  const fp = await proveDisclosureAttribute(
    "tier",
    2,
    { kind: "range", field: "tier", min: 2, max: 3 },
    salt(),
  );
  const reqs: AttributeRequirement[] = [
    { attribute: "tier", predicate: { kind: "range", field: "tier", min: 2, max: 4 } },
  ];
  assert.equal((await requireAttributeProofs([fp], reqs)).ok, true);
});

maybe("reports missing when no proof for a required attribute is present", async () => {
  const fp = await proveDisclosureAttribute(
    "score",
    95,
    { kind: "gte", field: "score", value: 80 },
    salt(),
  );
  const reqs: AttributeRequirement[] = [
    { attribute: "capital", predicate: { kind: "gte", field: "capital", value: 1000 } },
  ];
  const result = await requireAttributeProofs([fp], reqs);
  assert.equal(result.ok, false);
  assert.deepEqual(result.missing, ["capital"]);
  assert.match(result.reasons.join("; "), /no range proof provided/);
});

maybe("a proof for a WEAKER predicate than required does not satisfy", async () => {
  // Required: score >= 90. Provided: score >= 80 (weaker; does not imply >= 90).
  const fp = await proveDisclosureAttribute(
    "score",
    85,
    { kind: "gte", field: "score", value: 80 },
    salt(),
  );
  const reqs: AttributeRequirement[] = [
    { attribute: "score", predicate: { kind: "gte", field: "score", value: 90 } },
  ];
  const result = await requireAttributeProofs([fp], reqs);
  assert.equal(result.ok, false);
  assert.deepEqual(result.missing, ["score"]);
  assert.match(result.reasons.join("; "), /weaker than required/);
});

maybe("a proof of a DIFFERENT predicate kind than required does not satisfy", async () => {
  // Required: score >= 80. Provided: score <= 80. Different relation, not satisfying.
  const fp = await proveDisclosureAttribute(
    "score",
    50,
    { kind: "lte", field: "score", value: 80 },
    salt(),
  );
  const reqs: AttributeRequirement[] = [
    { attribute: "score", predicate: { kind: "gte", field: "score", value: 80 } },
  ];
  const result = await requireAttributeProofs([fp], reqs);
  assert.equal(result.ok, false);
  assert.deepEqual(result.missing, ["score"]);
});

maybe("a satisfying-predicate-but-tampered proof does not count (verification leg)", async () => {
  const fp = await proveDisclosureAttribute(
    "score",
    95,
    { kind: "gte", field: "score", value: 80 },
    salt(),
  );
  const payload = fp.payload as { proofs: { bitProofs: { z1: string }[] }[] };
  const orig = payload.proofs[0].bitProofs[1].z1;
  payload.proofs[0].bitProofs[1].z1 = (BigInt(`0x${orig}`) ^ 1n).toString(16);
  const reqs: AttributeRequirement[] = [
    { attribute: "score", predicate: { kind: "gte", field: "score", value: 80 } },
  ];
  const result = await requireAttributeProofs([fp], reqs);
  assert.equal(result.ok, false);
  assert.match(result.reasons.join("; "), /does not verify/);
});

maybe("multiple requirements: all met -> ok, with a mix of attributes", async () => {
  const fpScore = await proveDisclosureAttribute(
    "score",
    95,
    { kind: "gte", field: "score", value: 80 },
    salt(),
  );
  const fpTier = await proveDisclosureAttribute(
    "tier",
    3,
    { kind: "range", field: "tier", min: 2, max: 4 },
    salt(),
  );
  const reqs: AttributeRequirement[] = [
    { attribute: "score", predicate: { kind: "gte", field: "score", value: 80 } },
    { attribute: "tier", predicate: { kind: "range", field: "tier", min: 2, max: 4 } },
  ];
  const result = await requireAttributeProofs([fpScore, fpTier], reqs);
  assert.equal(result.ok, true, result.reasons.join("; "));
});

// Type-only: FieldRangeProof is exported and usable as a value shape.
maybe("FieldRangeProof shape is stable", async () => {
  const fp: FieldRangeProof = await proveDisclosureAttribute(
    "x",
    5,
    { kind: "gte", field: "x", value: 1 },
    salt(),
  );
  assert.ok(typeof fp.commitment === "string");
  assert.ok(typeof fp.scheme === "string");
  assert.equal(fp.predicate.kind, "gte");
});
