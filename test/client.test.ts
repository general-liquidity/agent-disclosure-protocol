import test from "node:test";
import assert from "node:assert/strict";

import {
  generateAgentKeyPair,
  signDisclosure,
  respondToChallenge,
  verifyCounterparty,
  sha256Hex,
  type AgentDisclosure,
  type FetchLike,
  type Challenge,
} from "../src/index.ts";

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

// A peer served over an in-memory wire: serves its disclosure and answers challenges.
function peer(signed: unknown, responderKey = key): FetchLike {
  return async (url, init) => {
    const path = new URL(url).pathname;
    if (path === "/.well-known/agent-disclosure") {
      return { ok: true, status: 200, json: async () => signed };
    }
    if (path === "/agent-disclosure/respond") {
      const challenge = JSON.parse(init?.body ?? "{}") as Challenge;
      return { ok: true, status: 200, json: async () => respondToChallenge(challenge, responderKey, H, NOW) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
}

test("verifyCounterparty transacts on a valid disclosure + live handshake", async () => {
  const signed = signDisclosure(disclosure(), key);
  const v = await verifyCounterparty(peer(signed), "http://peer", {
    now: NOW, requireEnforcedConstitution: true, requireAuditAnchor: true,
  });
  assert.equal(v.decision, "transact", v.reasons.join("; "));
  assert.equal(v.handshake?.ok, true);
});

test("verifyCounterparty refuses a stricter policy the peer cannot meet", async () => {
  const signed = signDisclosure(disclosure(), key);
  const v = await verifyCounterparty(peer(signed), "http://peer", { now: NOW, requireRedTeam: true });
  assert.equal(v.decision, "refuse");
});

test("verifyCounterparty fails closed when the peer is unreachable", async () => {
  const fetch: FetchLike = async () => {
    throw new Error("down");
  };
  const v = await verifyCounterparty(fetch, "http://peer", { now: NOW });
  assert.equal(v.decision, "refuse");
});

test("verifyCounterparty refuses when the handshake is signed by the wrong key", async () => {
  const signed = signDisclosure(disclosure(), key);
  const impostor = generateAgentKeyPair();
  const v = await verifyCounterparty(peer(signed, impostor), "http://peer", { now: NOW });
  assert.equal(v.decision, "refuse");
  assert.ok(v.reasons.some((r) => /handshake/.test(r)));
});
