import assert from "node:assert/strict";
import test from "node:test";
import { generateLeaderboard } from "../scripts/leaderboard.ts";
import { generateAgentKeyPair, signDisclosure } from "../src/attestation.ts";
import {
  type AgentDisclosure,
  DISCLOSURE_SCHEMA_VERSION,
  type SignedDisclosure,
} from "../src/schema.ts";
import { TransparencyLog } from "../src/transparency.ts";
import { consistencyProof, verifyConsistency, Witness } from "../src/witness.ts";

function disclosure(agentId: string, disclosureId: string): AgentDisclosure {
  return {
    version: DISCLOSURE_SCHEMA_VERSION,
    disclosureId,
    agentId,
    issuedAt: "2026-06-24T12:00:00.000Z",
    validUntil: "2026-06-25T12:00:00.000Z",
    nonce: `nonce_${disclosureId}`,
    systemPrompt: { algorithm: "sha256", digest: "abc123" },
    constitution: {
      hardConstraints: [{ id: "deny_unknown_payee", description: "...", kind: "deny" }],
      digest: "c0ffee",
      enforced: true,
    },
    tools: { tools: [{ name: "pay", access: "gated", movesValue: true }] },
    capital: { mandates: [], custody: "non_custodial" },
    operator: {
      operatorId: "op_xyz",
      attestation: { scheme: "AIP", level: "signed" },
      deniabilityBoundary: "spend within mandates only",
    },
    history: {
      chainAnchor: "f00dface",
      summary: { totalDecisions: 1, settledCount: 1, blockedCount: 0 },
    },
  };
}

function sign(disclosureId: string): SignedDisclosure {
  const key = generateAgentKeyPair();
  return signDisclosure(
    { ...disclosure(key.publicKeyHex, disclosureId), agentId: key.publicKeyHex },
    key,
  );
}

test("a forward-extending log passes verifyConsistency", () => {
  const log = new TransparencyLog();
  log.append(sign("d1"));
  log.append(sign("d2"));
  const oldHead = log.head();
  const oldSize = log.entries().length;

  log.append(sign("d3"));
  log.append(sign("d4"));

  const proof = consistencyProof(log, oldSize);
  assert.equal(proof.oldHead, oldHead);
  assert.equal(proof.newHead, log.head());
  assert.equal(proof.entries.length, 2);
  assert.equal(verifyConsistency(oldHead, proof), true);
});

test("an empty proof verifies only against the unchanged head", () => {
  const log = new TransparencyLog();
  log.append(sign("d1"));
  const head = log.head();
  const proof = consistencyProof(log, log.entries().length);
  assert.equal(proof.entries.length, 0);
  assert.equal(verifyConsistency(head, proof), true);
  assert.equal(verifyConsistency("0".repeat(64), proof), false);
});

test("a forward-extending log passes checkAppendOnly", () => {
  const w = new Witness();
  const log = new TransparencyLog();
  log.append(sign("d1"));
  log.append(sign("d2"));
  w.observe("agent-1", log);

  // operator appends more and re-presents the same (extended) log
  log.append(sign("d3"));
  const check = w.checkAppendOnly("agent-1", log);
  assert.equal(check.ok, true);
});

test("a fresh agent (never observed) is trivially append-only", () => {
  const w = new Witness();
  const log = new TransparencyLog();
  log.append(sign("d1"));
  assert.equal(w.checkAppendOnly("unseen", log).ok, true);
});

test("a rewritten log (different entry at an earlier index) fails checkAppendOnly", () => {
  const w = new Witness();

  // The history the witness pins.
  const original = new TransparencyLog();
  original.append(sign("d1"));
  original.append(sign("d2"));
  w.observe("agent-1", original);

  // A divergent history of the same length: a different entry sits at index 0, so the
  // hash chain diverges before the witness's pinned head - a split-view.
  const rewritten = new TransparencyLog();
  rewritten.append(sign("forged-d1"));
  rewritten.append(sign("d2"));

  const check = w.checkAppendOnly("agent-1", rewritten);
  assert.equal(check.ok, false);
  assert.ok(check.reason);
});

test("a shortened log fails checkAppendOnly", () => {
  const w = new Witness();
  const log = new TransparencyLog();
  log.append(sign("d1"));
  log.append(sign("d2"));
  log.append(sign("d3"));
  w.observe("agent-1", log);

  const shorter = new TransparencyLog();
  shorter.append(sign("d1"));
  const check = w.checkAppendOnly("agent-1", shorter);
  assert.equal(check.ok, false);
});

test("generateLeaderboard orders A above B and higher score first", () => {
  const md = generateLeaderboard([
    { agentId: "b-agent", grade: "B", score: 99, corpus: "c@1" },
    { agentId: "a-low", grade: "A", score: 80, corpus: "c@1" },
    { agentId: "a-high", grade: "A", score: 90, corpus: "c@1" },
  ]);
  const lines = md.split("\n");
  // first two data rows are the header + separator
  const order = lines.slice(2).map((l) => l.split("|")[2].trim());
  assert.deepEqual(order, ["a-high", "a-low", "b-agent"]);
});
