import test from "node:test";
import assert from "node:assert/strict";

import {
  generateAgentKeyPair,
  signDisclosure,
  respondToChallenge,
  sha256Hex,
  type AgentDisclosure,
  type FetchLike,
  type Challenge,
} from "../src/index.ts";
import { verifyBeforePay, createVerifyCounterpartyTool } from "../src/adapters.ts";

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

// A payee served over an in-memory wire: serves its disclosure and answers challenges.
function payee(signed: unknown): FetchLike {
  return async (url, init) => {
    const path = new URL(url).pathname;
    if (path === "/.well-known/agent-disclosure") {
      return { ok: true, status: 200, json: async () => signed };
    }
    if (path === "/agent-disclosure/respond") {
      const challenge = JSON.parse(init?.body ?? "{}") as Challenge;
      return { ok: true, status: 200, json: async () => respondToChallenge(challenge, key, H, NOW) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
}

test("verifyBeforePay allows a compliant payee", async () => {
  const signed = signDisclosure(disclosure(), key);
  const res = await verifyBeforePay(payee(signed), "http://payee", {
    now: NOW,
    requireEnforcedConstitution: true,
    requireAuditAnchor: true,
  });
  assert.equal(res.allow, true, res.verdict.reasons.join("; "));
  assert.equal(res.verdict.decision, "transact");
});

test("verifyBeforePay refuses a stricter policy the payee cannot meet", async () => {
  const signed = signDisclosure(disclosure(), key);
  const res = await verifyBeforePay(payee(signed), "http://payee", { now: NOW, requireRedTeam: true });
  assert.equal(res.allow, false);
  assert.equal(res.verdict.decision, "refuse");
});

test("createVerifyCounterpartyTool.execute mirrors the guard - allow", async () => {
  const signed = signDisclosure(disclosure(), key);
  const tool = createVerifyCounterpartyTool({
    fetch: payee(signed),
    policy: { now: NOW, requireEnforcedConstitution: true, requireAuditAnchor: true },
  });
  assert.equal(tool.name, "verify_counterparty");
  // the input schema is the plain { baseUrl } zod object both frameworks accept
  assert.deepEqual(tool.inputSchema.parse({ baseUrl: "http://payee" }), { baseUrl: "http://payee" });
  const res = await tool.execute({ baseUrl: "http://payee" });
  assert.equal(res.allow, true, res.verdict.reasons.join("; "));
});

test("createVerifyCounterpartyTool.execute mirrors the guard - refuse", async () => {
  const signed = signDisclosure(disclosure(), key);
  const tool = createVerifyCounterpartyTool({
    fetch: payee(signed),
    policy: { now: NOW, requireRedTeam: true },
  });
  const res = await tool.execute({ baseUrl: "http://payee" });
  assert.equal(res.allow, false);
  assert.equal(res.verdict.decision, "refuse");
});
