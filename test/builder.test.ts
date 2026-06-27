import test from "node:test";
import assert from "node:assert/strict";

import { generateAgentKeyPair, verifyDisclosureSignature } from "../src/attestation.ts";
import {
  parseDisclosure,
  type CapitalEnvelope,
  type DeploymentHistory,
  type OperatorIdentity,
  type Tool,
} from "../src/schema.ts";
import { DisclosureBuilder } from "../src/builder.ts";

const NOW = "2026-06-24T12:00:00.000Z";

const TOOLS: Tool[] = [
  { name: "pay", access: "gated", movesValue: true },
  { name: "list_mandates", access: "read_only", movesValue: false },
];

const CAPITAL: CapitalEnvelope = {
  mandates: [
    {
      label: "groceries",
      scope: "class:groceries",
      currency: "GBP",
      perTxCapMinor: 50_000,
      perPeriodCapMinor: 100_000,
      period: "week",
      allowedRails: ["card"],
      expiresAt: "2026-07-20T00:00:00.000Z",
    },
  ],
  custody: "non_custodial",
};

const OPERATOR: OperatorIdentity = {
  operatorId: "op_xyz",
  attestation: { scheme: "AIP", level: "signed" },
  deniabilityBoundary: "The operator authorizes spend within the mandates only.",
};

const HISTORY: DeploymentHistory = {
  chainAnchor: "f00dface",
  summary: { totalDecisions: 42, settledCount: 30, blockedCount: 5 },
};

function builder(): DisclosureBuilder {
  return new DisclosureBuilder()
    .systemPrompt("you are a careful spending agent")
    .constitution({
      hardConstraints: [
        { id: "no_unknown_payee", description: "deny irreversible to unknown payee", kind: "deny" },
      ],
      enforced: true,
      enforcementEvidence: "gate:agentworth",
    })
    .tools(TOOLS, "executor")
    .capital(CAPITAL)
    .operator(OPERATOR)
    .history(HISTORY)
    .validFor(60 * 60 * 1000);
}

test("build produces a disclosure parseDisclosure accepts", () => {
  const key = generateAgentKeyPair();
  const d = builder().build({ agentKey: key, now: NOW, nonce: "n0nce" });

  assert.doesNotThrow(() => parseDisclosure(d));
  assert.equal(d.agentId, key.publicKeyHex);
  assert.equal(d.issuedAt, NOW);
  assert.equal(d.validUntil, "2026-06-24T13:00:00.000Z");
  assert.equal(d.nonce, "n0nce");
  assert.equal(d.systemPrompt.algorithm, "sha256");
  assert.equal(d.constitution.digest.length, 64);
});

test("a missing required field group throws at build", () => {
  const key = generateAgentKeyPair();
  const incomplete = new DisclosureBuilder().systemPrompt("partial");
  assert.throws(() => incomplete.build({ agentKey: key, now: NOW, nonce: "n0nce" }));
});

test("buildAndSign -> verifyDisclosureSignature is ok", () => {
  const key = generateAgentKeyPair();
  const signed = builder().buildAndSign({ agentKey: key, now: NOW, nonce: "n0nce" });

  assert.equal(signed.signature.algorithm, "ed25519");
  assert.equal(signed.signature.publicKey, key.publicKeyHex);
  assert.deepEqual(verifyDisclosureSignature(signed), { ok: true });
});
