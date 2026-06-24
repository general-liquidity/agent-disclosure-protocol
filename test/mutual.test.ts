import test from "node:test";
import assert from "node:assert/strict";

import { mutualVerify } from "../src/mutual.ts";
import {
  generateAgentKeyPair,
  signDisclosure,
  respondToChallenge,
  sha256Hex,
  type AgentDisclosure,
  type FetchLike,
  type Challenge,
} from "../src/index.ts";

const NOW = "2026-06-24T12:00:00.000Z";

// An agent node served over an in-memory wire (serves its disclosure + answers the handshake).
function node() {
  const key = generateAgentKeyPair();
  const H = sha256Hex(`anchor-${key.publicKeyHex.slice(0, 8)}`);
  const disclosure: AgentDisclosure = {
    version: 1,
    disclosureId: "d",
    agentId: key.publicKeyHex,
    issuedAt: NOW,
    validUntil: "2026-06-24T13:00:00.000Z",
    nonce: "n",
    auditAnchor: H,
    systemPrompt: { algorithm: "sha256", digest: H },
    constitution: { hardConstraints: [], digest: H, enforced: true },
    tools: { tools: [] },
    capital: { mandates: [], custody: "non_custodial" },
    operator: { operatorId: "op", attestation: { scheme: "none", level: "none" }, deniabilityBoundary: "x" },
    history: { chainAnchor: H, summary: { totalDecisions: 1, settledCount: 1, blockedCount: 0 } },
  };
  const signed = signDisclosure(disclosure, key);
  const fetch: FetchLike = async (url, init) => {
    const path = new URL(url).pathname;
    if (path === "/.well-known/agent-disclosure") return { ok: true, status: 200, json: async () => signed };
    if (path === "/agent-disclosure/respond") {
      const c = JSON.parse(init?.body ?? "{}") as Challenge;
      return { ok: true, status: 200, json: async () => respondToChallenge(c, key, H, NOW) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  return { fetch };
}

test("mutualVerify transacts when both sides clear", async () => {
  const a = node();
  const b = node();
  const v = await mutualVerify({
    ourFetch: a.fetch, ourBaseUrl: "http://a",
    theirFetch: b.fetch, theirBaseUrl: "http://b",
    ourPolicy: { now: NOW, requireEnforcedConstitution: true },
    theirPolicy: { now: NOW, requireEnforcedConstitution: true },
  });
  assert.equal(v.decision, "transact", v.reasons.join("; "));
});

test("mutualVerify refuses when one side fails its check (labeled by side)", async () => {
  const a = node();
  const b = node();
  const v = await mutualVerify({
    ourFetch: a.fetch, ourBaseUrl: "http://a",
    theirFetch: b.fetch, theirBaseUrl: "http://b",
    ourPolicy: { now: NOW },
    theirPolicy: { now: NOW, requireRedTeam: true }, // we publish no red-team attestation
  });
  assert.equal(v.decision, "refuse");
  assert.ok(v.reasons.some((r) => r.startsWith("us:")));
});
