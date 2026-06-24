import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalize, sha256Hex } from "../src/attestation.ts";
import { commitmentBackend, type ZkProof } from "../src/zk.ts";

// Build a commitment the same way redaction.ts does, so the backend operates over the
// exact published commitment a signed disclosure would carry.
function commit(value: unknown, salt: string): string {
  return sha256Hex(`${canonicalize(value)}:${salt}`);
}

test("commitmentBackend proves and verifies an equality predicate", () => {
  const value = { grade: "A", score: 95 };
  const salt = randomBytes(16).toString("hex");
  const commitment = commit(value, salt);

  const proof = commitmentBackend.prove({
    predicate: { kind: "equals", field: "redTeam", value },
    value,
    salt,
    commitment,
  });

  assert.equal(proof.scheme, "salted-commitment-equality");
  assert.equal(commitmentBackend.verify(proof).ok, true);
});

test("a proof for the wrong value fails verification", () => {
  const value = { grade: "A" };
  const salt = randomBytes(16).toString("hex");
  const commitment = commit(value, salt);

  const proof = commitmentBackend.prove({
    predicate: { kind: "equals", field: "redTeam", value },
    value,
    salt,
    commitment,
  });

  // Tamper the opened value: it no longer opens the commitment.
  const tampered: ZkProof = {
    ...proof,
    payload: { value: { grade: "B" }, salt },
  };
  const result = commitmentBackend.verify(tampered);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /commitment/);
});

test("proving against a value that does not open the commitment throws", () => {
  const salt = randomBytes(16).toString("hex");
  const commitment = commit({ grade: "A" }, salt);

  assert.throws(
    () =>
      commitmentBackend.prove({
        predicate: { kind: "equals", field: "redTeam", value: { grade: "B" } },
        value: { grade: "B" },
        salt,
        commitment,
      }),
    /open the commitment/,
  );
});

test("a verifier rejects a proof from an unknown scheme", () => {
  const value = "x";
  const salt = randomBytes(16).toString("hex");
  const proof: ZkProof = {
    scheme: "some-other-scheme",
    predicate: { kind: "equals", field: "f", value },
    commitment: commit(value, salt),
    payload: { value, salt },
  };
  const result = commitmentBackend.verify(proof);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /unknown proof scheme/);
});

test("a range predicate throws the documented not-implemented error", () => {
  const salt = randomBytes(16).toString("hex");
  const value = 95;
  const commitment = commit(value, salt);

  assert.throws(
    () =>
      commitmentBackend.prove({
        predicate: { kind: "range", field: "score", min: 80, max: 100 },
        value,
        salt,
        commitment,
      }),
    /requires a ZK backend/,
  );
});

test("a threshold (gte) predicate throws the documented not-implemented error", () => {
  const salt = randomBytes(16).toString("hex");
  const value = 95;
  const commitment = commit(value, salt);

  assert.throws(
    () =>
      commitmentBackend.prove({
        predicate: { kind: "gte", field: "score", value: 80 },
        value,
        salt,
        commitment,
      }),
    /requires a ZK backend/,
  );
});

test("verify also refuses a non-equality predicate carried in a proof", () => {
  const proof: ZkProof = {
    scheme: "salted-commitment-equality",
    predicate: { kind: "gte", field: "score", value: 80 },
    commitment: "00".repeat(32),
    payload: { value: 95, salt: "11".repeat(16) },
  };
  const result = commitmentBackend.verify(proof);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /requires a ZK backend/);
});
