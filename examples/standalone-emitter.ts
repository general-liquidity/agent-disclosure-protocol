// Standalone emitter - how ANY agent emits a disclosure, with no OpenSolvency and no
// product internals. The schema is vendor-neutral: you build a plain AgentDisclosure
// literal from ordinary values you already have, sign it with a generated key, and
// serve the signed envelope at /.well-known/agent-disclosure. That is the whole job.
//
// Run: node --import tsx examples/standalone-emitter.ts

import {
  generateAgentKeyPair,
  signDisclosure,
  sha256Hex,
  type AgentDisclosure,
} from "../src/index.ts";

// 1. Mint (or load) the agent's signing identity. The public key IS the agentId, so a
//    counterparty can verify the envelope with no shared secret. Persist the private
//    key with exportAgentKey/agentKeyFromPrivateHex to keep a stable identity.
const key = generateAgentKeyPair();

// 2. Build the disclosure from ordinary values you already maintain. Digests are just
//    sha256 hex of whatever you are fingerprinting (the system prompt, the constitution
//    text, the audit-chain head). Nothing here is OpenSolvency-shaped.
const disclosure: AgentDisclosure = {
  version: 1,
  disclosureId: "disc_standalone_1",
  agentId: key.publicKeyHex,
  issuedAt: "2026-06-24T12:00:00.000Z",
  validUntil: "2026-06-24T13:00:00.000Z", // a short freshness window; re-issue on expiry
  nonce: "n-standalone-1",
  auditAnchor: sha256Hex("my-audit-chain-head"),

  systemPrompt: { algorithm: "sha256", digest: sha256Hex("my composed system prompt") },

  // The constitution: declare the hard constraints the agent runs under. `enforced`
  // is the load-bearing field - set it true ONLY if a gate the agent cannot override
  // actually enforces these at runtime.
  constitution: {
    hardConstraints: [
      { id: "no-wire-transfer", description: "never initiate a wire transfer", kind: "deny" },
      { id: "per-tx-cap", description: "no single payment over 50.00 USD", kind: "cap" },
    ],
    digest: sha256Hex("canonical constitution text"),
    enforced: true,
    enforcementEvidence: "gate:my-runtime-gate",
  },

  // Tool inventory + the single value-moving path, if you funnel spend through one.
  tools: {
    tools: [
      { name: "get_price", access: "read_only", movesValue: false },
      { name: "pay_invoice", access: "gated", movesValue: true },
    ],
    valuePath: "pay_invoice",
  },

  // The capital envelope: scoped, capped, expiring spend authority. This is the field
  // no model's weights can tell you - what envelope the agent operates inside.
  capital: {
    mandates: [
      {
        label: "vendor-payments",
        scope: "allowlisted SaaS vendors",
        currency: "USD",
        perTxCapMinor: 5000, // 50.00 USD in minor units
        perPeriodCapMinor: 50000,
        period: "day",
        allowedRails: ["x402"],
        expiresAt: "2026-07-01T00:00:00.000Z",
      },
    ],
    custody: "non_custodial",
  },

  // Operator identity + the explicit deniability boundary.
  operator: {
    operatorId: "acme-ops",
    attestation: { scheme: "none", level: "none" },
    deniabilityBoundary:
      "operator is accountable for mandate configuration; not for market outcomes within the envelope",
  },

  // Cumulative deployment history, anchored to a tamper-evident chain head.
  history: {
    chainAnchor: sha256Hex("my-audit-chain-head"),
    summary: { totalDecisions: 128, settledCount: 120, blockedCount: 8 },
  },
};

// 3. Sign it. The envelope carries the disclosure + an ed25519 signature over its
//    canonical bytes, plus the public key - everything a counterparty needs.
const signed = signDisclosure(disclosure, key);

// 4. This is exactly what you would serve at GET /.well-known/agent-disclosure.
console.log(JSON.stringify(signed, null, 2));
