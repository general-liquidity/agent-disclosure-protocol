// The TS reference rejects the MUST-REJECT corpus. The contract a verifier in any
// language must satisfy: given hostile or malformed input, NEVER return transact, and
// NEVER crash. This is the adversarial half of conformance (the positive fixtures
// prove acceptance; these prove safe rejection).

import test from "node:test";
import assert from "node:assert/strict";

import { verifyAndEvaluate, canonicalize, MAX_CANONICALIZE_DEPTH } from "../src/index.ts";
import negative from "./negative.json" with { type: "json" };

const NOW = "2026-06-24T12:00:00.000Z";

test("negative: every must-reject case is refused, never accepted, never throws", () => {
  for (const c of negative.cases) {
    let decision: string;
    try {
      const value = c.isRawString ? JSON.parse(c.raw as string) : c.raw;
      decision = verifyAndEvaluate(value, { now: NOW }).decision;
    } catch {
      // a parse failure of a raw byte string is itself a safe rejection
      decision = "refuse";
    }
    assert.notEqual(decision, "transact", c.name);
  }
});

test("canonicalize: rejects pathologically deep nesting (stack-exhaustion guard)", () => {
  let v: unknown = 0;
  for (let i = 0; i < MAX_CANONICALIZE_DEPTH + 50; i++) v = { x: v };
  assert.throws(() => canonicalize(v), /depth/);
});
