// The conformance suite. A conformant Verifiable Agency implementation MUST pass
// every check here: the portable canonicalization + digest vectors (byte-identical
// across languages) plus the behavioural invariants the protocol depends on. This
// file runs the REFERENCE (this package) against the suite; another implementation
// ports the same vectors + invariants. See SPEC.md section "Conformance".

import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  canonicalize,
  sha256Hex,
  generateAgentKeyPair,
  signDisclosure,
  verifyDisclosureSignature,
  isFresh,
  createChallenge,
  respondToChallenge,
  verifyChallengeResponse,
  type AgentDisclosure,
} from "../src/index.ts";
import { CANONICALIZATION_VECTORS, SHA256_VECTORS } from "./vectors.ts";

const NOW = "2026-06-24T12:00:00.000Z";
const H = sha256Hex("anchor");

function disclosure(): AgentDisclosure {
  const key = generateAgentKeyPair();
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

// ── Canonicalization: the interoperability crux ──────────────────────────────
test("conformance: canonicalization vectors are reproduced byte for byte", () => {
  for (const v of CANONICALIZATION_VECTORS) {
    assert.equal(canonicalize(v.input), v.canonical, `canonicalize(${JSON.stringify(v.input)})`);
  }
});

test("conformance: canonicalization is key-order independent", () => {
  assert.equal(canonicalize({ a: 1, b: 2 }), canonicalize({ b: 2, a: 1 }));
  assert.equal(canonicalize({ x: { p: 1, q: 2 } }), canonicalize({ x: { q: 2, p: 1 } }));
});

// ── Digests ──────────────────────────────────────────────────────────────────
test("conformance: sha256 vectors match", () => {
  for (const v of SHA256_VECTORS) {
    assert.equal(sha256Hex(v.input), v.sha256);
  }
});

test("conformance: sha256Hex is a real sha256 (cross-checked against node:crypto)", () => {
  for (const s of ["a", "the quick brown fox", "{}"]) {
    assert.equal(sha256Hex(s), createHash("sha256").update(s).digest("hex"));
  }
});

// ── Signing + identity binding ───────────────────────────────────────────────
test("conformance: sign then verify holds", () => {
  const key = generateAgentKeyPair();
  const signed = signDisclosure(disclosure(), key);
  // agentId must equal the signing key for the binding to verify
  signed.disclosure.agentId = key.publicKeyHex;
  const resigned = signDisclosure(signed.disclosure, key);
  assert.equal(verifyDisclosureSignature(resigned).ok, true);
});

test("conformance: ed25519 signatures are deterministic", () => {
  const key = generateAgentKeyPair();
  const d = disclosure();
  d.agentId = key.publicKeyHex;
  assert.equal(signDisclosure(d, key).signature.value, signDisclosure(d, key).signature.value);
});

test("conformance: the agentId MUST equal the signing public key", () => {
  const key = generateAgentKeyPair();
  const d = disclosure();
  d.agentId = key.publicKeyHex;
  const signed = signDisclosure(d, key);
  signed.disclosure.agentId = `${"0".repeat(63)}1`; // claim a different identity
  assert.equal(verifyDisclosureSignature(signed).ok, false);
});

test("conformance: tampering any signed field breaks verification", () => {
  const key = generateAgentKeyPair();
  const d = disclosure();
  d.agentId = key.publicKeyHex;
  const signed = signDisclosure(d, key);
  signed.disclosure.constitution.enforced = false;
  assert.equal(verifyDisclosureSignature(signed).ok, false);
});

// ── Freshness ────────────────────────────────────────────────────────────────
test("conformance: freshness boundaries", () => {
  const d = disclosure();
  assert.equal(isFresh(d, d.issuedAt), true); // inclusive lower bound
  assert.equal(isFresh(d, d.validUntil), true); // inclusive upper bound
  assert.equal(isFresh(d, "2026-06-24T13:00:00.001Z"), false); // just past
  assert.equal(isFresh(d, "2026-06-24T11:59:59.999Z"), false); // just before
});

// ── Handshake ────────────────────────────────────────────────────────────────
test("conformance: a correct challenge response verifies; a replay does not", () => {
  const key = generateAgentKeyPair();
  const challenge = createChallenge(NOW, { nonce: "c1", verifierId: "v" });
  const response = respondToChallenge(challenge, key, H, NOW);
  assert.equal(
    verifyChallengeResponse(response, challenge, { expectedAgentId: key.publicKeyHex, now: NOW }).ok,
    true,
  );
  const other = createChallenge(NOW, { nonce: "c2" });
  assert.equal(verifyChallengeResponse(response, other, { expectedAgentId: key.publicKeyHex }).ok, false);
});
