import test from "node:test";
import assert from "node:assert/strict";

import {
  generateAgentKeyPair,
  signDisclosure,
  sha256Hex,
  type AgentDisclosure,
} from "../src/index.ts";
import { handleVerify } from "../src/verifierService.ts";

const NOW = "2026-06-24T12:00:00.000Z";
const key = generateAgentKeyPair();
const H = sha256Hex("anchor");

function disclosure(): AgentDisclosure {
  return {
    version: 1,
    disclosureId: "disc_1",
    agentId: key.publicKeyHex,
    issuedAt: NOW,
    validUntil: "2026-06-24T13:00:00.000Z",
    nonce: "n1",
    auditAnchor: H,
    systemPrompt: { algorithm: "sha256", digest: H },
    constitution: { hardConstraints: [], digest: H, enforced: true },
    tools: { tools: [] },
    capital: { mandates: [], custody: "non_custodial" },
    operator: { operatorId: "op", attestation: { scheme: "none", level: "none" }, deniabilityBoundary: "x" },
    history: { chainAnchor: H, summary: { totalDecisions: 1, settledCount: 1, blockedCount: 0 } },
  };
}

test("handleVerify transacts on a valid disclosure that meets policy", () => {
  const signed = signDisclosure(disclosure(), key);
  const result = handleVerify(JSON.stringify(signed), { requireEnforcedConstitution: true, requireAuditAnchor: true }, NOW);
  assert.equal(result.status, 200);
  const body = result.body as { decision: string; checks: Record<string, boolean>; reasons: string[] };
  assert.equal(body.decision, "transact", body.reasons.join("; "));
  assert.equal(body.checks.enforcedConstitution, true);
  assert.deepEqual(body.reasons, []);
});

test("handleVerify refuses a policy the disclosure cannot meet", () => {
  const signed = signDisclosure(disclosure(), key);
  const result = handleVerify(JSON.stringify(signed), { requireRedTeam: true }, NOW);
  assert.equal(result.status, 200);
  const body = result.body as { decision: string; reasons: string[] };
  assert.equal(body.decision, "refuse");
  assert.ok(body.reasons.length > 0);
});

test("handleVerify returns 400 on malformed JSON", () => {
  const result = handleVerify("{not json", {}, NOW);
  assert.equal(result.status, 400);
  const body = result.body as { error: string };
  assert.match(body.error, /malformed JSON/);
});
