import test from "node:test";
import assert from "node:assert/strict";

import {
  parseDisclosure,
  parseSignedDisclosure,
  AgentDisclosureSchema,
  DISCLOSURE_SCHEMA_VERSION,
  type AgentDisclosure,
} from "../src/index.ts";

const NOW = "2026-06-24T12:00:00.000Z";

function sample(over: Partial<AgentDisclosure> = {}): AgentDisclosure {
  return {
    version: DISCLOSURE_SCHEMA_VERSION,
    disclosureId: "disc_1",
    agentId: "agent_abc",
    issuedAt: NOW,
    validUntil: "2026-06-25T12:00:00.000Z",
    nonce: "n0nce",
    auditAnchor: "deadbeef",
    systemPrompt: { algorithm: "sha256", digest: "abc123" },
    constitution: {
      hardConstraints: [{ id: "irreversible_to_unknown_payee", description: "...", kind: "deny" }],
      digest: "c0ffee",
      enforced: true,
      enforcementEvidence: "gate:opensolvency",
    },
    tools: {
      tools: [
        { name: "pay", access: "gated", movesValue: true },
        { name: "list_mandates", access: "read_only", movesValue: false },
        { name: "kill_switch", access: "operator_only", movesValue: false },
      ],
      valuePath: "executor",
    },
    capital: {
      mandates: [
        { label: "groceries", scope: "class:groceries", currency: "GBP", perTxCapMinor: 500_00, perPeriodCapMinor: 1000_00, period: "week", allowedRails: ["card"], expiresAt: "2026-07-20T00:00:00.000Z" },
      ],
      custody: "non_custodial",
    },
    operator: {
      operatorId: "op_xyz",
      attestation: { scheme: "AIP", level: "registry_attested" },
      deniabilityBoundary: "The operator authorizes spend within the mandates only; it is not liable for counterparty conduct.",
    },
    history: {
      chainAnchor: "f00dface",
      summary: { totalDecisions: 42, settledCount: 30, blockedCount: 5 },
    },
    redTeam: {
      corpus: { name: "spendtrust", version: "0.1.1" },
      result: { grade: "A", score: 96, passed: true, hardFails: [] },
      attestedAt: NOW,
    },
    ...over,
  };
}

test("a complete disclosure validates", () => {
  const d = parseDisclosure(sample());
  assert.equal(d.constitution.enforced, true);
  assert.equal(d.capital.custody, "non_custodial");
  assert.equal(d.redTeam?.result.grade, "A");
});

test("redTeam is optional; the rest is required", () => {
  const { redTeam, ...rest } = sample();
  void redTeam;
  assert.doesNotThrow(() => parseDisclosure(rest));
});

test("a wrong schema version is rejected", () => {
  assert.throws(() => parseDisclosure({ ...sample(), version: 99 }));
});

test("an invalid tool access level is rejected", () => {
  const bad = sample();
  (bad.tools.tools[0] as { access: string }).access = "superuser";
  assert.throws(() => parseDisclosure(bad));
});

test("a non-hex digest is rejected (binding fields must be hashes)", () => {
  const bad = sample();
  bad.systemPrompt.digest = "not hex!!";
  assert.throws(() => parseDisclosure(bad));
});

test("the signed envelope wraps a disclosure with an ed25519 signature", () => {
  const signed = parseSignedDisclosure({
    disclosure: sample(),
    signature: { algorithm: "ed25519", publicKey: "aa", value: "bb" },
  });
  assert.equal(signed.signature.algorithm, "ed25519");
  // a non-ed25519 algorithm is rejected (the protocol pins asymmetric signing)
  assert.throws(() =>
    parseSignedDisclosure({ disclosure: sample(), signature: { algorithm: "hmac", publicKey: "aa", value: "bb" } }),
  );
});

test("the schema covers all seven disclosure field groups", () => {
  const shape = AgentDisclosureSchema.shape;
  for (const f of ["systemPrompt", "constitution", "tools", "capital", "operator", "history", "redTeam"]) {
    assert.ok(f in shape, `missing field group: ${f}`);
  }
});
