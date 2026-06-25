import assert from "node:assert/strict";
import test from "node:test";

import { type AgentKeyPair, generateAgentKeyPair, sha256Hex, signDisclosure, verifyDisclosureSignature } from "../src/attestation.ts";
import { KeyRing, keyFromFile, keyToFile, rotateKey, verifyRotation } from "../src/keys.ts";
import type { AgentDisclosure, SignedDisclosure } from "../src/schema.ts";

const NOW = "2026-06-24T12:00:00.000Z";
const H = sha256Hex("anchor");

// A minimal valid disclosure whose stable `agentId` is fixed independently of the
// signing key — the case that exercises the rotation-chain binding.
function disclosureFor(agentId: string): AgentDisclosure {
  return {
    version: 1,
    disclosureId: "d",
    agentId,
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
}

/** Sign a disclosure that keeps `original`'s identity but is signed by `signer`,
 *  attaching the rotation chain that authorizes the move. */
function signedUnderRotation(original: AgentKeyPair, signer: AgentKeyPair, chain: SignedDisclosure["rotationChain"]): SignedDisclosure {
  return { ...signDisclosure(disclosureFor(original.publicKeyHex), signer), rotationChain: chain };
}

test("rotate -> verifyRotation ok (old key authorizes the new identity)", () => {
  const oldKey = generateAgentKeyPair();
  const newKey = generateAgentKeyPair();
  const statement = rotateKey(oldKey, newKey, NOW);
  assert.equal(statement.from, oldKey.publicKeyHex);
  assert.equal(statement.to, newKey.publicKeyHex);
  const check = verifyRotation(statement);
  assert.equal(check.ok, true);
});

test("a forged rotation fails (signed by a key that is not `from`)", () => {
  const oldKey = generateAgentKeyPair();
  const newKey = generateAgentKeyPair();
  const impostor = generateAgentKeyPair();
  // attacker claims rotation from oldKey but only holds impostor's private key
  const statement = rotateKey(impostor, newKey, NOW);
  statement.from = oldKey.publicKeyHex;
  const check = verifyRotation(statement);
  assert.equal(check.ok, false);
  assert.match(check.reason ?? "", /signature/);
});

test("keyToFile/keyFromFile round-trip preserves the signing identity", () => {
  const key = generateAgentKeyPair();
  const hex = keyToFile(key);
  const restored = keyFromFile(hex);
  assert.equal(restored.publicKeyHex, key.publicKeyHex);
  // and a rotation signed by the restored key verifies
  const newKey = generateAgentKeyPair();
  assert.equal(verifyRotation(rotateKey(restored, newKey, NOW)).ok, true);
});

test("rotation chain: a disclosure signed by a rotated key verifies under the original agentId", () => {
  const k0 = generateAgentKeyPair();
  const k1 = generateAgentKeyPair();
  const signed = signedUnderRotation(k0, k1, [rotateKey(k0, k1, NOW)]);
  // identity (k0) differs from the signing key (k1), but the chain authorizes it
  assert.notEqual(signed.disclosure.agentId, signed.signature.publicKey);
  assert.equal(verifyDisclosureSignature(signed).ok, true);
});

test("rotation chain: a two-hop chain (k0 -> k1 -> k2) verifies", () => {
  const k0 = generateAgentKeyPair();
  const k1 = generateAgentKeyPair();
  const k2 = generateAgentKeyPair();
  const signed = signedUnderRotation(k0, k2, [rotateKey(k0, k1, NOW), rotateKey(k1, k2, NOW)]);
  assert.equal(verifyDisclosureSignature(signed).ok, true);
});

test("rotation chain: a non-contiguous chain is rejected", () => {
  const k0 = generateAgentKeyPair();
  const k1 = generateAgentKeyPair();
  const k2 = generateAgentKeyPair();
  const stray = generateAgentKeyPair();
  // second hop starts from `stray`, not k1 — the chain is broken
  const signed = signedUnderRotation(k0, k2, [rotateKey(k0, k1, NOW), rotateKey(stray, k2, NOW)]);
  const r = verifyDisclosureSignature(signed);
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /contiguous|end at the signing key/);
});

test("rotation chain: a chain that does not reach the signing key is rejected", () => {
  const k0 = generateAgentKeyPair();
  const k1 = generateAgentKeyPair();
  const k2 = generateAgentKeyPair();
  // chain ends at k1 but k2 actually signed
  const signed = signedUnderRotation(k0, k2, [rotateKey(k0, k1, NOW)]);
  const r = verifyDisclosureSignature(signed);
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /end at the signing key/);
});

test("rotation chain: a forged hop (signed by the wrong from key) is rejected", () => {
  const k0 = generateAgentKeyPair();
  const k1 = generateAgentKeyPair();
  const impostor = generateAgentKeyPair();
  const hop = rotateKey(impostor, k1, NOW);
  hop.from = k0.publicKeyHex; // claim k0 authorized it, but impostor signed
  const signed = signedUnderRotation(k0, k1, [hop]);
  const r = verifyDisclosureSignature(signed);
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /signature does not verify/);
});

test("rotation chain: without a chain, a mismatched agentId is still rejected (v1 behavior preserved)", () => {
  const k0 = generateAgentKeyPair();
  const k1 = generateAgentKeyPair();
  const signed = signDisclosure(disclosureFor(k0.publicKeyHex), k1); // no rotationChain
  assert.equal(verifyDisclosureSignature(signed).ok, false);
});

test("KeyRing add/get and agentIds", () => {
  const ring = new KeyRing();
  const a = generateAgentKeyPair();
  const b = generateAgentKeyPair();
  ring.add(a);
  ring.add(b);
  assert.equal(ring.get(a.publicKeyHex)?.publicKeyHex, a.publicKeyHex);
  assert.equal(ring.get(b.publicKeyHex)?.publicKeyHex, b.publicKeyHex);
  assert.equal(ring.get("missing"), undefined);
  assert.deepEqual(new Set(ring.agentIds()), new Set([a.publicKeyHex, b.publicKeyHex]));
});
