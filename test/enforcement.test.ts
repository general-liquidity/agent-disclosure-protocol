import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalize,
  computePolicyHash,
  DISCLOSURE_SCHEMA_VERSION,
  ENFORCEMENT_EXTENSION_KEY,
  sha256Hex,
  verifyEnforcement,
  type AgentDisclosure,
  type DecisionRecord,
  type EffectivePolicy,
  type PoEAttestation,
  type ReplaySeam,
} from "../src/index.ts";

const NOW = "2026-06-24T12:00:00.000Z";

// A small EffectivePolicy with deliberately UNSORTED arrays, to exercise normalization.
const POLICY: EffectivePolicy = {
  mandates: [
    { id: "m_subscriptions", currency: "GBP", perTxCapMinor: 2000 },
    { id: "m_groceries", currency: "GBP", perTxCapMinor: 50000 },
  ],
  gateConfig: { minRationaleChars: 10, velocityCeiling: 5 },
  denyRuleIds: ["irreversible_to_unknown_payee", "amount_over_cap"],
  riskConfig: { model: "spendtrust", version: "0.1.1" },
};

const POLICY_HASH = computePolicyHash(POLICY);

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
      enforcementEvidence: "gate:agentworth",
    },
    tools: { tools: [{ name: "pay", access: "gated", movesValue: true }], valuePath: "executor" },
    capital: {
      mandates: [
        {
          label: "groceries",
          scope: "class:groceries",
          currency: "GBP",
          perTxCapMinor: 50000,
          perPeriodCapMinor: 100000,
          period: "week",
          allowedRails: ["card"],
          expiresAt: "2026-07-20T00:00:00.000Z",
        },
      ],
      custody: "non_custodial",
    },
    operator: {
      operatorId: "op_xyz",
      attestation: { scheme: "AIP", level: "registry_attested" },
      deniabilityBoundary: "Operator authorizes spend within mandates only.",
    },
    history: { chainAnchor: "f00dface", summary: { totalDecisions: 42, settledCount: 30, blockedCount: 5 } },
    extensions: { [ENFORCEMENT_EXTENSION_KEY]: { policyHash: POLICY_HASH, auditAnchor: "deadbeef" } },
    ...over,
  };
}

function decision(over: Partial<DecisionRecord> = {}): DecisionRecord {
  return {
    intent: { payee: "merchant_1", amountMinor: 1500, currency: "GBP", rationale: "weekly groceries top-up" },
    ctxDigest: "ctx_aaa",
    verdict: { decision: "allow" },
    policyHash: POLICY_HASH,
    at: NOW,
    ...over,
  };
}

function attestation(over: Partial<PoEAttestation> = {}): PoEAttestation {
  return {
    policyHash: POLICY_HASH,
    auditHead: "deadbeef",
    recentDecisions: [decision({ ctxDigest: "ctx_aaa" }), decision({ ctxDigest: "ctx_bbb" })],
    generatedAt: NOW,
    ...over,
  };
}

// An honest replay seam: re-running any record under the disclosed policy reproduces its
// signed verdict. Stands in for OS's pure `replayDecision`.
const honestReplay: ReplaySeam = () => ({ matches: true });

test("honest attestation ⇒ bound + fresh + replayed:passed, ok:true", () => {
  const result = verifyEnforcement(sample(), attestation(), { replay: honestReplay, policy: POLICY });
  assert.equal(result.bound, true);
  assert.equal(result.fresh, true);
  assert.equal(result.replayed, "passed");
  assert.equal(result.ok, true);
  assert.equal(result.reason, undefined);
});

test("tampered decision verdict ⇒ replayed:FAILED, ok:false (falsifiability)", () => {
  // The injected replay detects that ONE record's signed verdict cannot be reproduced under
  // the disclosed policy — a gate claiming enforcement it doesn't perform is now caught.
  const tamperedReplay: ReplaySeam = (record) => ({ matches: record.ctxDigest !== "ctx_bbb" });
  const result = verifyEnforcement(sample(), attestation(), { replay: tamperedReplay, policy: POLICY });
  assert.equal(result.bound, true);
  assert.equal(result.fresh, true);
  assert.equal(result.replayed, "FAILED");
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /replay mismatch/);
});

test("differing policyHash ⇒ bound:false, ok:false", () => {
  const result = verifyEnforcement(sample(), attestation({ policyHash: "0".repeat(64) }), {
    replay: honestReplay,
    policy: POLICY,
  });
  assert.equal(result.bound, false);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /does not match/);
});

test("no replay seam ⇒ replayed:skipped (binding-only verification)", () => {
  const result = verifyEnforcement(sample(), attestation());
  assert.equal(result.replayed, "skipped");
  assert.equal(result.bound, true);
  assert.equal(result.fresh, true);
  assert.equal(result.ok, true);
});

test("replay seam without policy ⇒ skipped (both required to run the leg)", () => {
  const result = verifyEnforcement(sample(), attestation(), { replay: honestReplay });
  assert.equal(result.replayed, "skipped");
  assert.equal(result.ok, true);
});

test("disclosure missing the enforcement extension ⇒ bound:false with an actionable reason", () => {
  const { extensions, ...rest } = sample();
  void extensions;
  const result = verifyEnforcement(rest as AgentDisclosure, attestation(), { replay: honestReplay, policy: POLICY });
  assert.equal(result.bound, false);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /no enforcement binding/);
});

test("empty live audit head ⇒ fresh:false, ok:false", () => {
  const result = verifyEnforcement(sample(), attestation({ auditHead: "" }));
  assert.equal(result.fresh, false);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /no live audit head/);
});

test("a malformed enforcement extension is treated as absent (bound:false, never throws)", () => {
  const result = verifyEnforcement(sample({ extensions: { [ENFORCEMENT_EXTENSION_KEY]: { policyHash: 123 } } }), attestation());
  assert.equal(result.bound, false);
  assert.match(result.reason ?? "", /no enforcement binding/);
});

test("replay over zero recent decisions ⇒ passed (vacuously)", () => {
  const result = verifyEnforcement(sample(), attestation({ recentDecisions: [] }), { replay: honestReplay, policy: POLICY });
  assert.equal(result.replayed, "passed");
  assert.equal(result.ok, true);
});

// ── policyHash determinism + OS cross-check ─────────────────────────────────
test("computePolicyHash is a stable, well-formed sha256 hex", () => {
  assert.match(POLICY_HASH, /^[0-9a-f]{64}$/);
  assert.equal(computePolicyHash(POLICY), POLICY_HASH);
});

test("policyHash is independent of mandate / denyRule array order (normalization)", () => {
  const shuffled: EffectivePolicy = {
    ...POLICY,
    mandates: [...POLICY.mandates].reverse(),
    denyRuleIds: [...POLICY.denyRuleIds].reverse(),
  };
  assert.equal(computePolicyHash(shuffled), POLICY_HASH);
});

test("policyHash is independent of gateConfig / riskConfig KEY order (canonicalize)", () => {
  const reordered: EffectivePolicy = {
    ...POLICY,
    gateConfig: { velocityCeiling: 5, minRationaleChars: 10 },
    riskConfig: { version: "0.1.1", model: "spendtrust" },
  };
  assert.equal(computePolicyHash(reordered), POLICY_HASH);
});

test("a different policy ⇒ a different hash (collision sanity)", () => {
  const altered: EffectivePolicy = { ...POLICY, denyRuleIds: [...POLICY.denyRuleIds, "extra_rule"] };
  assert.notEqual(computePolicyHash(altered), POLICY_HASH);
});

// Cross-check the serialization OS must match: ADP's computePolicyHash MUST equal
// sha256Hex(canonicalize(<normalized policy>)) — the exact recipe an OS agent reports.
// This pins the byte contract both sides hash against.
test("cross-check: computePolicyHash == sha256Hex(canonicalize(normalized policy))", () => {
  // mirror production normalizePolicy: project mandates to the stable OS field set
  // (drop volatile/extra fields, sort allowedRails) + project gateConfig/riskConfig.
  const g = POLICY.gateConfig as Record<string, unknown>;
  const r = POLICY.riskConfig as Record<string, unknown>;
  const normalized = {
    mandates: [...POLICY.mandates]
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .map((x) => {
        const m = x as Record<string, unknown>;
        return {
          id: m.id,
          scope: m.scope,
          currency: m.currency,
          allowedRails: Array.isArray(m.allowedRails) ? [...(m.allowedRails as unknown[])].sort() : m.allowedRails,
          perTxCap: m.perTxCap,
          perPeriodCap: m.perPeriodCap,
          period: m.period,
          expiresAt: m.expiresAt,
          status: m.status,
        };
      }),
    gateConfig: {
      minRationaleChars: g.minRationaleChars,
      velocityWindowMinutes: g.velocityWindowMinutes,
      velocityMaxCount: g.velocityMaxCount,
      anomalyMultiple: g.anomalyMultiple,
    },
    denyRuleIds: [...POLICY.denyRuleIds].sort(),
    riskConfig: {
      velocityWindowMinutes: r.velocityWindowMinutes,
      velocityMaxCount: r.velocityMaxCount,
      anomalyMultiple: r.anomalyMultiple,
    },
  };
  assert.equal(POLICY_HASH, sha256Hex(canonicalize(normalized)));
});
