// Two agents, end to end - agent A verifies agent B over an in-memory wire and decides
// transact / refuse before any value moves. No network: both nodes are served through
// an injected FetchLike (the same pattern the tests use), so this runs anywhere.
//
// Shows: (1) a baseline policy clears B and A transacts; (2) a stricter policy that B
// cannot meet refuses BEFORE value moves. Both verdicts are printed.
//
// Run: node --import tsx examples/two-agents.ts

import {
  generateAgentKeyPair,
  signDisclosure,
  respondToChallenge,
  verifyCounterparty,
  sha256Hex,
  type AgentDisclosure,
  type SignedDisclosure,
  type FetchLike,
  type Challenge,
} from "../src/index.ts";

const NOW = "2026-06-24T12:00:00.000Z";

// --- Agent B: the counterparty A is deciding whether to pay. ---
const bKey = generateAgentKeyPair();
const bAnchor = sha256Hex("agent-b-audit-head");

const bDisclosure: AgentDisclosure = {
  version: 1,
  disclosureId: "disc_b_1",
  agentId: bKey.publicKeyHex,
  issuedAt: NOW,
  validUntil: "2026-06-24T13:00:00.000Z",
  nonce: "n-b-1",
  auditAnchor: bAnchor,
  systemPrompt: { algorithm: "sha256", digest: sha256Hex("b system prompt") },
  constitution: {
    hardConstraints: [{ id: "no-wire", description: "no wire transfers", kind: "deny" }],
    digest: sha256Hex("b constitution"),
    enforced: true,
  },
  tools: { tools: [{ name: "pay", access: "gated", movesValue: true }], valuePath: "pay" },
  capital: { mandates: [], custody: "non_custodial" },
  operator: {
    operatorId: "b-ops",
    attestation: { scheme: "none", level: "none" },
    deniabilityBoundary: "operator accountable for mandate config only",
  },
  history: { chainAnchor: bAnchor, summary: { totalDecisions: 42, settledCount: 40, blockedCount: 2 } },
  // NOTE: B carries no red-team attestation - the stricter policy below will refuse on this.
};

const bSigned = signDisclosure(bDisclosure, bKey);

// Serve an agent node over an in-memory wire: GET its disclosure, POST routes into the
// real challenge responder so the live handshake actually runs.
function serveAgent(signed: SignedDisclosure, key = bKey, anchor = bAnchor): FetchLike {
  return async (url, init) => {
    const path = new URL(url).pathname;
    if (path === "/.well-known/agent-disclosure") {
      return { ok: true, status: 200, json: async () => signed };
    }
    if (path === "/agent-disclosure/respond") {
      const challenge = JSON.parse(init?.body ?? "{}") as Challenge;
      return { ok: true, status: 200, json: async () => respondToChallenge(challenge, key, anchor, NOW) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
}

const bNode = serveAgent(bSigned);

async function main() {
  // Agent A, baseline policy: require an enforced constitution + a tamper-evident
  // audit anchor. B meets these, so A transacts.
  const baseline = await verifyCounterparty(bNode, "http://agent-b", {
    now: NOW,
    requireEnforcedConstitution: true,
    requireAuditAnchor: true,
  });
  console.log("[A -> B] baseline policy:", baseline.decision);
  if (baseline.decision === "transact") {
    console.log("  value moves: A pays B (disclosure cleared + live handshake ok)");
  } else {
    console.log("  refused:", baseline.reasons.join("; "));
  }

  // Agent A, stricter policy: additionally require a red-team attestation. B has none,
  // so A REFUSES before a single unit of value moves.
  const strict = await verifyCounterparty(bNode, "http://agent-b", {
    now: NOW,
    requireEnforcedConstitution: true,
    requireAuditAnchor: true,
    requireRedTeam: true,
  });
  console.log("[A -> B] strict policy:", strict.decision);
  if (strict.decision === "refuse") {
    console.log("  no value moved. reasons:", strict.reasons.join("; "));
  }
}

main();
