import assert from "node:assert/strict";
import test from "node:test";

import { generateAgentKeyPair } from "../src/attestation.ts";
import { KeyRing, keyFromFile, keyToFile, rotateKey, verifyRotation } from "../src/keys.ts";

const NOW = "2026-06-24T12:00:00.000Z";

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
