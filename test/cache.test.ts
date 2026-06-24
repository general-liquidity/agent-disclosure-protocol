import test from "node:test";
import assert from "node:assert/strict";

import { VerificationCache, verifyTiered } from "../src/cache.ts";
import { generateAgentKeyPair, signDisclosure, sha256Hex } from "../src/attestation.ts";
import type { AgentDisclosure } from "../src/schema.ts";

const key = generateAgentKeyPair();
const H = sha256Hex("anchor");

function mkSigned(nonce: string, issuedAt: string, validUntil: string) {
  const d: AgentDisclosure = {
    version: 1,
    disclosureId: `disc_${nonce}`,
    agentId: key.publicKeyHex,
    issuedAt,
    validUntil,
    nonce,
    auditAnchor: H,
    systemPrompt: { algorithm: "sha256", digest: H },
    constitution: { hardConstraints: [], digest: H, enforced: true },
    tools: { tools: [] },
    capital: { mandates: [], custody: "non_custodial" },
    operator: { operatorId: "op", attestation: { scheme: "none", level: "none" }, deniabilityBoundary: "x" },
    history: { chainAnchor: H, summary: { totalDecisions: 1, settledCount: 1, blockedCount: 0 } },
  };
  return signDisclosure(d, key);
}

test("first verify is fresh, a repeat within the validity window is cached", () => {
  const cache = new VerificationCache();
  const s = mkSigned("n1", "2026-06-24T12:00:00.000Z", "2026-06-24T13:00:00.000Z");
  const a = verifyTiered(cache, s, { now: "2026-06-24T12:00:00.000Z" });
  assert.equal(a.tier, "fresh");
  assert.equal(a.verdict.decision, "transact");
  const b = verifyTiered(cache, s, { now: "2026-06-24T12:30:00.000Z" });
  assert.equal(b.tier, "cached");
  assert.equal(cache.size(), 1);
});

test("an entry past validUntil is evicted and re-evaluated (never served stale)", () => {
  const cache = new VerificationCache();
  const s = mkSigned("n2", "2026-06-24T12:00:00.000Z", "2026-06-24T13:00:00.000Z");
  verifyTiered(cache, s, { now: "2026-06-24T12:00:00.000Z" });
  const c = verifyTiered(cache, s, { now: "2026-06-24T13:00:00.001Z" });
  // the stale entry was evicted and the disclosure re-evaluated (tier "fresh");
  // re-evaluation now fails freshness -> refuse, proving the cached transact was never served
  assert.equal(c.tier, "fresh");
  assert.equal(c.verdict.decision, "refuse");
});

test("distinct disclosure instances cache independently", () => {
  const cache = new VerificationCache();
  const t = { now: "2026-06-24T12:00:00.000Z" };
  verifyTiered(cache, mkSigned("a", "2026-06-24T12:00:00.000Z", "2026-06-24T13:00:00.000Z"), t);
  verifyTiered(cache, mkSigned("b", "2026-06-24T12:00:00.000Z", "2026-06-24T13:00:00.000Z"), t);
  assert.equal(cache.size(), 2);
});
