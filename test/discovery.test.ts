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
import { fetchDisclosure, AgentDirectory, discoverAndVerify } from "../src/discovery.ts";

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
function peer(signed: unknown): FetchLike {
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

test("fetchDisclosure parses a disclosure served over the wire", async () => {
  const signed = signDisclosure(disclosure(), key);
  const got = await fetchDisclosure(peer(signed), "http://peer");
  assert.equal(got.disclosure.agentId, key.publicKeyHex);
});

test("fetchDisclosure throws on a non-200 response", async () => {
  const fetch: FetchLike = async () => ({ ok: false, status: 503, json: async () => ({}) });
  await assert.rejects(() => fetchDisclosure(fetch, "http://peer"), /HTTP 503/);
});

test("AgentDirectory register / lookup / json round-trip", () => {
  const dir = new AgentDirectory();
  dir.register("agent_a", "http://a");
  dir.register("agent_b", "http://b");
  assert.equal(dir.lookup("agent_a"), "http://a");
  assert.equal(dir.lookup("missing"), undefined);
  assert.equal(dir.entries().length, 2);

  const restored = AgentDirectory.fromJSON(JSON.parse(JSON.stringify(dir.toJSON())));
  assert.equal(restored.lookup("agent_b"), "http://b");
  assert.deepEqual(restored.entries(), dir.entries());
});

test("discoverAndVerify transacts for a known agent", async () => {
  const signed = signDisclosure(disclosure(), key);
  const dir = new AgentDirectory();
  dir.register(key.publicKeyHex, "http://peer");
  const v = await discoverAndVerify(peer(signed), dir, key.publicKeyHex, {
    now: NOW, requireEnforcedConstitution: true, requireAuditAnchor: true,
  });
  assert.equal(v.decision, "transact", v.reasons.join("; "));
});

test("discoverAndVerify refuses an unknown agent without touching the wire", async () => {
  const fetch: FetchLike = async () => {
    throw new Error("should not be called");
  };
  const dir = new AgentDirectory();
  const v = await discoverAndVerify(fetch, dir, "unknown_agent", { now: NOW });
  assert.equal(v.decision, "refuse");
  assert.ok(v.reasons.some((r) => /unknown agent/.test(r)));
});
