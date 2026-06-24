import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import { prepareRedactable, reveal } from "../src/redaction.ts";
import type { AgentDisclosure } from "../src/schema.ts";
import type { VerificationPolicy } from "../src/verify.ts";
import { discloseFor, requiredFields, satisfiesPolicy } from "../src/negotiate.ts";

// A structurally complete disclosure carrying every redactable field, so any policy's
// required fields can in principle be revealed. Hand-built (no OpenSolvency builders).
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
    tools: { tools: [{ name: "place_order", access: "gated", movesValue: true }] },
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
    provenance: { constitution: { derivedFrom: "opensolvency-gate" } },
  };
}

const NOW = "2026-06-01T00:00:00.000Z";

test("requiredFields maps policy predicates to the minimum field set", () => {
  const policy: VerificationPolicy = {
    now: NOW,
    requireEnforcedConstitution: true,
    requireDeploymentHistory: true,
  };
  assert.deepEqual(new Set(requiredFields(policy)), new Set(["constitution", "history"]));
});

test("discloseFor reveals exactly the policy's fields; verifyRedacted passes; satisfiesPolicy ok", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);
  const { holder } = prepareRedactable(disclosure, key);

  const policy: VerificationPolicy = {
    now: NOW,
    requireEnforcedConstitution: true,
    requireDeploymentHistory: true,
  };

  const view = discloseFor(holder, policy);

  // Exactly constitution + history are revealed, nothing else.
  assert.deepEqual(new Set(Object.keys(view.revealed)), new Set(["constitution", "history"]));
  assert.equal("capital" in view.revealed, false);
  assert.equal("operator" in view.revealed, false);
  assert.equal("redTeam" in view.revealed, false);

  const result = satisfiesPolicy(view, policy);
  assert.equal(result.ok, true);
  assert.deepEqual(result.missing, []);
});

test("satisfiesPolicy reports a field the holder did not reveal as missing", () => {
  const key = generateAgentKeyPair();
  const disclosure = buildDisclosure(key.publicKeyHex);
  const { holder } = prepareRedactable(disclosure, key);

  const policy: VerificationPolicy = {
    now: NOW,
    requireEnforcedConstitution: true,
    requireNonCustodial: true, // needs "capital"
  };

  // Holder reveals only constitution, withholding the capital field the policy needs.
  const view = reveal(holder, ["constitution"]);

  const result = satisfiesPolicy(view, policy);
  assert.equal(result.ok, false);
  assert.deepEqual(result.missing, ["capital"]);
});
