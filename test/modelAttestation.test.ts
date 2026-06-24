import test from "node:test";
import assert from "node:assert/strict";

import { generateAgentKeyPair } from "../src/attestation.ts";
import { attestModel, verifyModelAttestation } from "../src/modelAttestation.ts";

const NOW = "2026-06-24T12:00:00.000Z";

const MODEL = {
  name: "claude-opus-4",
  fingerprintAlgorithm: "sha256" as const,
  digest: "deadbeef",
};

test("attest -> verify is ok and binds the agentId to the key", () => {
  const key = generateAgentKeyPair();
  const att = attestModel(key, MODEL, NOW);
  assert.equal(att.agentId, key.publicKeyHex);
  assert.deepEqual(att.model, MODEL);
  assert.deepEqual(verifyModelAttestation(att), { ok: true });
});

test("a tampered digest fails verification", () => {
  const key = generateAgentKeyPair();
  const att = attestModel(key, MODEL, NOW);
  const tampered = { ...att, model: { ...att.model, digest: "c0ffee" } };
  const result = verifyModelAttestation(tampered);
  assert.equal(result.ok, false);
});

test("a tampered agentId fails verification", () => {
  const key = generateAgentKeyPair();
  const other = generateAgentKeyPair();
  const att = attestModel(key, MODEL, NOW);
  const tampered = { ...att, agentId: other.publicKeyHex };
  assert.equal(verifyModelAttestation(tampered).ok, false);
});
