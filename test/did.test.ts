import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import { agentIdToDidDocument, agentIdToDidKey, didKeyToAgentId, didWeb } from "../src/did.ts";

test("agentIdToDidKey produces a did:key:z... for an ed25519 key", () => {
  const key = generateAgentKeyPair();
  const did = agentIdToDidKey(key.publicKeyHex);
  assert.match(did, /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
});

test("agentIdToDidDocument emits a DID Document with the key and an AgentDisclosure service", () => {
  const key = generateAgentKeyPair();
  const did = agentIdToDidKey(key.publicKeyHex);
  const doc = agentIdToDidDocument(key.publicKeyHex, { disclosureEndpoint: "https://agent.example/.well-known/agent-disclosure" });
  assert.equal(doc.id, did);
  assert.equal(doc.verificationMethod[0].controller, did);
  assert.match(doc.verificationMethod[0].publicKeyMultibase, /^z[1-9A-HJ-NP-Za-km-z]+$/);
  assert.equal(doc.authentication[0], `${did}#${did.slice("did:key:".length)}`);
  assert.deepEqual(doc.assertionMethod, doc.authentication);
  assert.equal(doc.service?.[0].type, "AgentDisclosure");
  assert.equal(doc.service?.[0].serviceEndpoint, "https://agent.example/.well-known/agent-disclosure");
});

test("agentIdToDidDocument omits service when no endpoint is given", () => {
  const key = generateAgentKeyPair();
  assert.equal(agentIdToDidDocument(key.publicKeyHex).service, undefined);
});

test("didKey round-trips back to the agentId", () => {
  const key = generateAgentKeyPair();
  const did = agentIdToDidKey(key.publicKeyHex);
  assert.equal(didKeyToAgentId(did), key.publicKeyHex);
});

test("round-trip holds across many keys", () => {
  for (let i = 0; i < 50; i++) {
    const id = generateAgentKeyPair().publicKeyHex;
    assert.equal(didKeyToAgentId(agentIdToDidKey(id)), id);
  }
});

test("agentIdToDidKey rejects a non-32-byte key", () => {
  assert.throws(() => agentIdToDidKey("abcd"), /32-byte/);
});

test("didKeyToAgentId rejects a non-did:key string", () => {
  assert.throws(() => didKeyToAgentId("did:web:example.com"), /did:key/);
});

test("didKeyToAgentId rejects a non-ed25519 did:key (wrong multicodec)", () => {
  const key = generateAgentKeyPair();
  // Take a valid did:key, then corrupt the multicodec prefix by re-encoding a
  // payload with an secp256k1 multicodec (0xe7 0x01) instead of ed25519 (0xed 0x01).
  const did = agentIdToDidKey(key.publicKeyHex);
  // Decode is internal; instead build a known non-ed25519 did:key vector.
  // did:key for an secp256k1 key (multicodec 0xe701) from the W3C test vectors.
  const secp = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
  assert.notEqual(secp, did);
  assert.throws(() => didKeyToAgentId(secp), /ed25519/);
});

test("didWeb formats a bare domain and a path", () => {
  assert.equal(didWeb("example.com"), "did:web:example.com");
  assert.equal(didWeb("example.com", "agents/gordon"), "did:web:example.com:agents:gordon");
  assert.equal(didWeb("example.com", "/leading/and/trailing/"), "did:web:example.com:leading:and:trailing");
});

test("didWeb rejects an empty domain", () => {
  assert.throws(() => didWeb(""), /domain/);
});
