import assert from "node:assert/strict";
import test from "node:test";
import { detectDowngrade, diffDisclosures } from "../src/monitor.ts";
import { type AgentDisclosure, DISCLOSURE_SCHEMA_VERSION } from "../src/schema.ts";

const NOW = "2026-06-24T12:00:00.000Z";

function sample(over: Partial<AgentDisclosure> = {}): AgentDisclosure {
  return {
    version: DISCLOSURE_SCHEMA_VERSION,
    disclosureId: "disc_1",
    agentId: "agent_abc",
    issuedAt: NOW,
    validUntil: "2026-06-25T12:00:00.000Z",
    nonce: "n0nce",
    systemPrompt: { algorithm: "sha256", digest: "abc123" },
    constitution: {
      hardConstraints: [{ id: "irreversible_to_unknown_payee", description: "...", kind: "deny" }],
      digest: "c0ffee",
      enforced: true,
    },
    tools: { tools: [{ name: "pay", access: "gated", movesValue: true }] },
    capital: {
      mandates: [],
      custody: "non_custodial",
    },
    operator: {
      operatorId: "op_xyz",
      attestation: { scheme: "AIP", level: "registry_attested" },
      deniabilityBoundary: "scoped to mandates only",
    },
    history: {
      chainAnchor: "f00dface",
      summary: { totalDecisions: 1, settledCount: 1, blockedCount: 0 },
    },
    redTeam: {
      corpus: { name: "spendtrust", version: "0.1.1" },
      result: { grade: "A", score: 96, passed: true, hardFails: [] },
      attestedAt: NOW,
    },
    ...over,
  };
}

test("identical disclosures -> no changes, no downgrade", () => {
  const a = sample();
  const b = sample();
  assert.deepEqual(diffDisclosures(a, b), []);
  assert.equal(detectDowngrade(a, b).downgraded, false);
});

test("enforced flipped off -> downgrade", () => {
  const prev = sample();
  const next = sample({ constitution: { ...sample().constitution, enforced: false } });
  const changes = diffDisclosures(prev, next);
  assert.ok(changes.some((c) => c.field === "constitution.enforced"));
  const dg = detectDowngrade(prev, next);
  assert.equal(dg.downgraded, true);
  assert.match(dg.reasons.join(" "), /enforced/);
});

test("grade A->C -> downgrade", () => {
  const prev = sample();
  const next = sample({
    redTeam: {
      ...sample().redTeam!,
      result: { grade: "C", score: 70, passed: true, hardFails: [] },
    },
  });
  assert.ok(diffDisclosures(prev, next).some((c) => c.field === "redTeam.grade"));
  const dg = detectDowngrade(prev, next);
  assert.equal(dg.downgraded, true);
  assert.match(dg.reasons.join(" "), /grade/);
});

test("custody flip non_custodial->custodial -> downgrade", () => {
  const prev = sample();
  const next = sample({ capital: { ...sample().capital, custody: "custodial" } });
  assert.ok(diffDisclosures(prev, next).some((c) => c.field === "capital.custody"));
  assert.equal(detectDowngrade(prev, next).downgraded, true);
});

test("removing a hard constraint -> downgrade", () => {
  const prev = sample();
  const next = sample({ constitution: { ...sample().constitution, hardConstraints: [] } });
  assert.ok(diffDisclosures(prev, next).some((c) => c.field === "constitution.hardConstraints"));
  const dg = detectDowngrade(prev, next);
  assert.equal(dg.downgraded, true);
  assert.match(dg.reasons.join(" "), /irreversible_to_unknown_payee/);
});

test("an UPGRADE (grade D->A) is a change but not a downgrade", () => {
  const prev = sample({
    redTeam: {
      ...sample().redTeam!,
      result: { grade: "D", score: 50, passed: false, hardFails: [] },
    },
  });
  const next = sample();
  assert.ok(diffDisclosures(prev, next).some((c) => c.field === "redTeam.grade"));
  assert.equal(detectDowngrade(prev, next).downgraded, false);
});
