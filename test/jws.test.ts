import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import {
  generateAgentKeyPair,
  sha256Hex,
  signDisclosure,
  signDisclosureJws,
  verifyAnyDisclosureSignature,
  verifyDisclosureJws,
} from "../src/attestation.ts";
import { agentIdToDidKey } from "../src/did.ts";
import { rotateKey } from "../src/keys.ts";
import { getDisclosure, isJwsSignedDisclosure, parseAnySignedDisclosure, type AgentDisclosure } from "../src/schema.ts";

const NOW = "2026-06-24T12:00:00.000Z";
const H = sha256Hex("anchor");

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

test("JWS: sign then verify holds, and the envelope is a flattened JWS shape", () => {
  const key = generateAgentKeyPair();
  const signed = signDisclosureJws(disclosureFor(key.publicKeyHex), key);
  assert.equal(isJwsSignedDisclosure(signed), true);
  assert.equal(signed.header.jwk.kty, "OKP");
  assert.equal(signed.header.jwk.crv, "Ed25519");
  // protected header is base64url JSON declaring EdDSA
  const header = JSON.parse(Buffer.from(signed.protected, "base64url").toString("utf8"));
  assert.equal(header.alg, "EdDSA");
  assert.equal(verifyDisclosureJws(signed).ok, true);
});

test("JWS: the jwk.x key recovers the signer's agentId", () => {
  const key = generateAgentKeyPair();
  const signed = signDisclosureJws(disclosureFor(key.publicKeyHex), key);
  assert.equal(Buffer.from(signed.header.jwk.x, "base64url").toString("hex"), key.publicKeyHex);
});

test("JWS: a tampered payload fails verification", () => {
  const key = generateAgentKeyPair();
  const signed = signDisclosureJws(disclosureFor(key.publicKeyHex), key);
  const doc = JSON.parse(Buffer.from(signed.payload, "base64url").toString("utf8"));
  doc.constitution.enforced = false; // tamper without re-signing
  signed.payload = Buffer.from(JSON.stringify(doc), "utf8").toString("base64url");
  assert.equal(verifyDisclosureJws(signed).ok, false);
});

test("JWS: tampering the protected header (alg) fails — header is integrity-protected", () => {
  const key = generateAgentKeyPair();
  const signed = signDisclosureJws(disclosureFor(key.publicKeyHex), key);
  signed.protected = Buffer.from(JSON.stringify({ alg: "none", typ: "application/adp+json" }), "utf8").toString("base64url");
  const r = verifyDisclosureJws(signed);
  assert.equal(r.ok, false);
  // either the alg gate or the now-broken signature rejects it
  assert.match(r.reason ?? "", /alg|signature/);
});

test("JWS: a substituted key (jwk.x) fails verification", () => {
  const key = generateAgentKeyPair();
  const other = generateAgentKeyPair();
  const signed = signDisclosureJws(disclosureFor(key.publicKeyHex), key);
  signed.header.jwk.x = Buffer.from(other.publicKeyHex, "hex").toString("base64url");
  assert.equal(verifyDisclosureJws(signed).ok, false);
});

test("JWS: an agentId expressed as the signer's did:key verifies (self-certifying form)", () => {
  const key = generateAgentKeyPair();
  const signed = signDisclosureJws(disclosureFor(agentIdToDidKey(key.publicKeyHex)), key);
  assert.equal(verifyDisclosureJws(signed).ok, true);
});

test("JWS: an unrelated agentId without a rotation chain is rejected", () => {
  const key = generateAgentKeyPair();
  const stranger = generateAgentKeyPair();
  const signed = signDisclosureJws(disclosureFor(stranger.publicKeyHex), key);
  const r = verifyDisclosureJws(signed);
  assert.equal(r.ok, false);
  assert.match(r.reason ?? "", /agentId does not match/);
});

test("JWS: a rotated key with a valid chain verifies under the original agentId", () => {
  const k0 = generateAgentKeyPair();
  const k1 = generateAgentKeyPair();
  const signed = { ...signDisclosureJws(disclosureFor(k0.publicKeyHex), k1), rotationChain: [rotateKey(k0, k1, NOW)] };
  assert.equal(verifyDisclosureJws(signed).ok, true);
});

test("verifyAnyDisclosureSignature dispatches on shape for both v1 and v2", () => {
  const key = generateAgentKeyPair();
  const v1 = signDisclosure(disclosureFor(key.publicKeyHex), key);
  const v2 = signDisclosureJws(disclosureFor(key.publicKeyHex), key);
  assert.equal(verifyAnyDisclosureSignature(v1).ok, true);
  assert.equal(verifyAnyDisclosureSignature(v2).ok, true);
});

test("getDisclosure + parseAnySignedDisclosure work for both envelope shapes", () => {
  const key = generateAgentKeyPair();
  const v1 = signDisclosure(disclosureFor(key.publicKeyHex), key);
  const v2 = signDisclosureJws(disclosureFor(key.publicKeyHex), key);
  // round-trip the v2 envelope through JSON (as it would travel on the wire)
  const v2parsed = parseAnySignedDisclosure(JSON.parse(JSON.stringify(v2)));
  assert.equal(isJwsSignedDisclosure(v2parsed), true);
  assert.deepEqual(getDisclosure(v1), v1.disclosure);
  assert.deepEqual(getDisclosure(v2parsed), v1.disclosure);
});
