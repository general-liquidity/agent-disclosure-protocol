import assert from "node:assert/strict";
import { test } from "node:test";
import { bench, buildPolicy, buildSampleSigned } from "../scripts/bench.ts";
import {
  canonicalize,
  generateAgentKeyPair,
  verifyDisclosureSignature,
} from "../src/attestation.ts";
import { evaluateDisclosure } from "../src/verify.ts";

// Not a perf assertion - just that the bench harness executes and produces sane,
// positive throughput numbers over a tiny iteration count.
test("bench harness runs and reports positive ops/sec", () => {
  const now = new Date().toISOString();
  const key = generateAgentKeyPair();
  const signed = buildSampleSigned(key, now);
  const policy = buildPolicy(now);

  // The sample disclosure the bench builds must actually be valid + clear the policy,
  // or the throughput numbers would be measuring a rejected path.
  assert.equal(verifyDisclosureSignature(signed).ok, true);
  assert.equal(evaluateDisclosure(signed, policy).decision, "transact");

  const ops: { name: string; fn: () => unknown }[] = [
    { name: "canonicalize", fn: () => canonicalize(signed.disclosure) },
    { name: "verifyDisclosureSignature", fn: () => verifyDisclosureSignature(signed) },
    { name: "evaluateDisclosure", fn: () => evaluateDisclosure(signed, policy) },
  ];

  for (const { name, fn } of ops) {
    const r = bench(name, fn, 200, 20);
    assert.ok(r.opsPerSec > 0, `${name} ops/sec should be positive, got ${r.opsPerSec}`);
    assert.ok(r.medianMicros >= 0, `${name} median latency should be non-negative`);
    assert.ok(Number.isFinite(r.meanMicros), `${name} mean latency should be finite`);
  }
});
