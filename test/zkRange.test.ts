import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import type { ZkProof } from "../src/zk.ts";
import { proveRange, verifyRange } from "../src/zkRange.ts";

// Skip the whole suite cleanly if the optional curve dependency is absent.
let nobleAvailable = true;
try {
  await import("@noble/curves/secp256k1");
} catch {
  nobleAvailable = false;
}

const maybe = nobleAvailable ? test : test.skip;
if (!nobleAvailable) {
  test("zkRange suite skipped: @noble/curves not installed", { skip: true }, () => {});
}

const salt = () => randomBytes(16).toString("hex");

// --- Acceptance: in-range value produces a proof the verifier accepts ---

maybe("gte: in-range value proves and verifies", async () => {
  const proof = await proveRange({ predicate: { kind: "gte", field: "score", value: 80 }, value: 95, salt: salt() });
  const result = await verifyRange(proof);
  assert.equal(result.ok, true, result.reason);
});

maybe("gte: value exactly at the threshold verifies (shifted value 0)", async () => {
  const proof = await proveRange({ predicate: { kind: "gte", field: "score", value: 80 }, value: 80, salt: salt() });
  assert.equal((await verifyRange(proof)).ok, true);
});

maybe("lte: in-range value proves and verifies", async () => {
  const proof = await proveRange({ predicate: { kind: "lte", field: "leverage", value: 10 }, value: 3, salt: salt() });
  assert.equal((await verifyRange(proof)).ok, true);
});

maybe("range: value inside [lo, hi] proves and verifies", async () => {
  const proof = await proveRange({
    predicate: { kind: "range", field: "capital", min: 1000, max: 5000 },
    value: 2500,
    salt: salt(),
  });
  assert.equal((await verifyRange(proof)).ok, true);
});

maybe("range: value at both endpoints verifies", async () => {
  for (const v of [1000, 5000]) {
    const proof = await proveRange({
      predicate: { kind: "range", field: "capital", min: 1000, max: 5000 },
      value: v,
      salt: salt(),
    });
    assert.equal((await verifyRange(proof)).ok, true, `endpoint ${v}`);
  }
});

maybe("accepts numeric-string and bigint values", async () => {
  const a = await proveRange({ predicate: { kind: "gte", field: "x", value: 5 }, value: "42", salt: salt() });
  assert.equal((await verifyRange(a)).ok, true);
  const b = await proveRange({ predicate: { kind: "gte", field: "x", value: 5 }, value: 42n, salt: salt() });
  assert.equal((await verifyRange(b)).ok, true);
});

// --- Out-of-range: prover cannot build a valid proof ---

maybe("gte: value below threshold cannot produce a proof", async () => {
  await assert.rejects(
    () => proveRange({ predicate: { kind: "gte", field: "score", value: 80 }, value: 50, salt: salt() }),
    /does not satisfy predicate/,
  );
});

maybe("lte: value above threshold cannot produce a proof", async () => {
  await assert.rejects(
    () => proveRange({ predicate: { kind: "lte", field: "leverage", value: 10 }, value: 25, salt: salt() }),
    /does not satisfy predicate/,
  );
});

maybe("range: value outside [lo, hi] cannot produce a proof", async () => {
  await assert.rejects(
    () => proveRange({ predicate: { kind: "range", field: "capital", min: 1000, max: 5000 }, value: 9000, salt: salt() }),
    /does not satisfy predicate/,
  );
});

maybe("rejects negative / non-integer values", async () => {
  await assert.rejects(
    () => proveRange({ predicate: { kind: "gte", field: "x", value: 0 }, value: -5, salt: salt() }),
    /non-negative integer/,
  );
  await assert.rejects(
    () => proveRange({ predicate: { kind: "gte", field: "x", value: 0 }, value: 3.14, salt: salt() }),
    /non-negative integer/,
  );
});

// --- Soundness probes: a tampered proof is rejected ---

maybe("soundness: flipping a challenge in a bit OR-proof is rejected", async () => {
  const proof = await proveRange({ predicate: { kind: "gte", field: "score", value: 80 }, value: 95, salt: salt() });
  assert.equal((await verifyRange(proof)).ok, true);

  const payload = proof.payload as { proofs: { bitProofs: { c0: string }[] }[] };
  const orig = payload.proofs[0].bitProofs[0].c0;
  // Flip the low nibble of the first sub-challenge so c0 + c1 no longer equals the FS challenge.
  const flipped = (BigInt(`0x${orig}`) ^ 1n).toString(16);
  payload.proofs[0].bitProofs[0].c0 = flipped;

  const result = await verifyRange(proof);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /rejected/);
});

maybe("soundness: flipping a response (z) in a bit OR-proof is rejected", async () => {
  const proof = await proveRange({ predicate: { kind: "gte", field: "score", value: 80 }, value: 95, salt: salt() });
  const payload = proof.payload as { proofs: { bitProofs: { z1: string }[] }[] };
  const orig = payload.proofs[0].bitProofs[2].z1;
  payload.proofs[0].bitProofs[2].z1 = (BigInt(`0x${orig}`) ^ 1n).toString(16);
  assert.equal((await verifyRange(proof)).ok, false);
});

maybe("soundness: tampering a bit commitment breaks the compose check", async () => {
  // Re-point one bit commitment to a different valid point: the OR-proof or the
  // sum_i 2^i C_i == C compose check must fail.
  const proof = await proveRange({ predicate: { kind: "gte", field: "score", value: 80 }, value: 95, salt: salt() });
  const other = await proveRange({ predicate: { kind: "gte", field: "score", value: 80 }, value: 96, salt: salt() });
  const p = proof.payload as { proofs: { bitCommitments: string[] }[] };
  const o = other.payload as { proofs: { bitCommitments: string[] }[] };
  p.proofs[0].bitCommitments[0] = o.proofs[0].bitCommitments[0];
  assert.equal((await verifyRange(proof)).ok, false);
});

maybe("soundness: shrinking the bit-length is rejected", async () => {
  const proof = await proveRange({ predicate: { kind: "gte", field: "score", value: 80 }, value: 95, salt: salt() });
  const payload = proof.payload as { bits: number[] };
  payload.bits[0] = payload.bits[0] - 1;
  const result = await verifyRange(proof);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /bit-length/);
});

maybe("verify rejects an unknown scheme", async () => {
  const proof: ZkProof = {
    scheme: "not-the-range-scheme",
    predicate: { kind: "gte", field: "x", value: 1 },
    commitment: "00",
    payload: {},
  };
  const result = await verifyRange(proof);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /unknown proof scheme/);
});

// --- Zero-knowledge sanity: the value does not appear in cleartext ---

maybe("zero-knowledge: the value is not present in the proof or commitment", async () => {
  // A large, distinctive value (14-digit decimal): a coincidental substring in the
  // randomized proof is statistically impossible. A short value can collide by chance
  // with the variable-width hex of the proof scalars, so it must be wide. The gte range
  // proof bounds (value - threshold) under 2^32, so keep that offset small while the
  // value itself stays large and distinctive.
  const threshold = 10000000000000; // 10^13
  const secret = threshold + 312345671; // 10000312345671, offset well under 2^32
  const proof = await proveRange({
    predicate: { kind: "gte", field: "capital", value: threshold },
    value: secret,
    salt: salt(),
  });
  const serialized = JSON.stringify(proof);
  assert.ok(!serialized.includes(String(secret)), "value leaked into the proof");
  // The commitment is a curve point, not the value.
  assert.ok(!proof.commitment.includes(String(secret)), "value leaked into the commitment");
});

maybe("zero-knowledge: two proofs of the same value differ (fresh randomness)", async () => {
  const pred = { kind: "gte", field: "x", value: 10 } as const;
  const a = await proveRange({ predicate: pred, value: 50, salt: salt() });
  const b = await proveRange({ predicate: pred, value: 50, salt: salt() });
  // Different salts -> different commitments and proofs, so a verifier cannot link them.
  assert.notEqual(a.commitment, b.commitment);
  assert.equal((await verifyRange(a)).ok, true);
  assert.equal((await verifyRange(b)).ok, true);
});

maybe("determinism: same salt reproduces the same commitment", async () => {
  const s = salt();
  const pred = { kind: "gte", field: "x", value: 10 } as const;
  const a = await proveRange({ predicate: pred, value: 50, salt: s });
  const b = await proveRange({ predicate: pred, value: 50, salt: s });
  assert.equal(a.commitment, b.commitment);
});
