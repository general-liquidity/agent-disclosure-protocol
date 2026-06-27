import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import {
  prepareRedactable,
  REDACTABLE_FIELDS,
  reveal,
  verifyRedacted,
} from "../src/redaction.ts";
import type { AgentDisclosure } from "../src/schema.ts";

// A minimal but structurally complete disclosure. Hand-built to stay vendor-neutral
// (no AgentWorth builders). Includes every redactable field so REDACTABLE_FIELDS is
// fully exercised.
function buildDisclosure(agentId: string): AgentDisclosure {
  return {
    version: 1,
    disclosureId: "d-1",
    agentId,
    issuedAt: "2026-01-01T00:00:00.000Z",
    validUntil: "2026-12-31T00:00:00.000Z",
    nonce: "n-abc",
    auditAnchor: "ab".repeat(32),
    systemPrompt: { algorithm: "sha256", digest: "aa".repeat(32) },
    constitution: {
      hardConstraints: [{ id: "deny-wire", description: "no wires over cap", kind: "deny" }],
      digest: "bb".repeat(32),
      enforced: true,
    },
    tools: {
      tools: [{ name: "place_order", access: "gated", movesValue: true }],
    },
    capital: {
      mandates: [
        {
          label: "ops",
          scope: "saas",
          currency: "USD",
          perTxCapMinor: 10000,
          perPeriodCapMinor: 500000,
          period: "month",
          allowedRails: ["card"],
          expiresAt: "2026-12-31T00:00:00.000Z",
        },
      ],
      custody: "non_custodial",
    },
    operator: {
      operatorId: "op-1",
      attestation: { scheme: "none", level: "none" },
      deniabilityBoundary: "operator funds the mandate; agent picks vendors",
    },
    history: {
      chainAnchor: "cc".repeat(32),
      summary: { totalDecisions: 10, settledCount: 8, blockedCount: 2 },
    },
    redTeam: {
      corpus: { name: "va-corpus", version: "1" },
      result: { grade: "A", score: 95, passed: true, hardFails: [] },
      attestedAt: "2026-01-01T00:00:00.000Z",
    },
    model: { name: "fable", fingerprintAlgorithm: "sha256", digest: "dd".repeat(32) },
    provenance: { constitution: { derivedFrom: "agentworth-gate" } },
  };
}

test("full reveal verifies and proves all present redactable fields", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);
  const { holder } = prepareRedactable(disclosure, key);

  const view = reveal(holder, [...REDACTABLE_FIELDS]);
  const result = verifyRedacted(view);

  assert.equal(result.ok, true);
  assert.deepEqual(new Set(result.revealedFields), new Set(REDACTABLE_FIELDS));
});

test("partial reveal proves only the disclosed fields; others stay committed but opaque", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);
  const { holder } = prepareRedactable(disclosure, key);

  const view = reveal(holder, ["constitution", "history"]);
  const result = verifyRedacted(view);

  assert.equal(result.ok, true);
  assert.deepEqual(new Set(result.revealedFields), new Set(["constitution", "history"]));

  // withheld fields are absent from the revealed set but their commitments remain
  assert.equal("capital" in view.revealed, false);
  assert.ok(view.commitments.capital);
  assert.ok(view.commitments.tools);
});

test("tampering a revealed value fails verification", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);
  const { holder } = prepareRedactable(disclosure, key);

  const view = reveal(holder, ["operator"]);
  (view.revealed.operator.value as { operatorId: string }).operatorId = "attacker";

  const result = verifyRedacted(view);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /commitment/);
});

test("wrong salt fails verification", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);
  const { holder } = prepareRedactable(disclosure, key);

  const view = reveal(holder, ["model"]);
  view.revealed.model.salt = "00".repeat(16);

  const result = verifyRedacted(view);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /commitment/);
});

test("forged signature fails verification", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);
  const { holder } = prepareRedactable(disclosure, key);

  const view = reveal(holder, ["constitution"]);
  // flip the last hex nibble of the signature
  const sig = view.signature.value;
  view.signature.value = sig.slice(0, -1) + (sig.endsWith("0") ? "1" : "0");

  const result = verifyRedacted(view);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /signature/);
});

test("agentId not matching the signing key fails verification", () => {
  const key = generateAgentKeyPair();
  const other = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);
  const { holder } = prepareRedactable(disclosure, key);

  const view = reveal(holder, ["constitution"]);
  view.meta.agentId = other.publicKeyHex;

  const result = verifyRedacted(view);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /agentId/);
});

test("attacker cannot inject a field that was never committed", () => {
  const key = generateAgentKeyPair();
  const attacker = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);
  const { holder } = prepareRedactable(disclosure, key);

  const view = reveal(holder, ["constitution"]);

  // Add a brand-new commitment for a forged field. The original signature no longer
  // covers the mutated commitment set, so verification must fail.
  view.commitments.injected = "ff".repeat(32);
  view.revealed.injected = { value: { evil: true }, salt: "11".repeat(16) };

  const result = verifyRedacted(view);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /signature/);

  // And even re-signing with a different key cannot help: the agentId binding fails.
  view.signature.publicKey = attacker.publicKeyHex;
  const result2 = verifyRedacted(view);
  assert.equal(result2.ok, false);
  assert.match(result2.reason ?? "", /agentId/);
});
