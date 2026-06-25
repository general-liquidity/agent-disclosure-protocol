import test from "node:test";
import assert from "node:assert/strict";

import {
  generateAgentKeyPair,
  createChallenge,
  respondToChallenge,
  verifyChallengeResponse,
} from "../src/index.ts";

const NOW = "2026-06-24T12:00:00.000Z";
const HEAD = "a".repeat(64);

test("a live challenge-response from the right key verifies", () => {
  const key = generateAgentKeyPair();
  const challenge = createChallenge(NOW, { nonce: "chal-1", verifierId: "verifier-A" });
  const response = respondToChallenge(challenge, key, HEAD, NOW);
  const check = verifyChallengeResponse(response, challenge, {
    expectedAgentId: key.publicKeyHex,
    disclosureAnchor: HEAD,
    now: NOW,
  });
  assert.equal(check.ok, true);
});

test("a replayed response to a different challenge fails (nonce mismatch)", () => {
  const key = generateAgentKeyPair();
  const first = createChallenge(NOW, { nonce: "chal-1" });
  const response = respondToChallenge(first, key, HEAD, NOW);
  const second = createChallenge(NOW, { nonce: "chal-2" });
  const check = verifyChallengeResponse(response, second, { expectedAgentId: key.publicKeyHex });
  assert.equal(check.ok, false);
  assert.match(check.reason ?? "", /nonce/);
});

test("a response signed by a different key is rejected", () => {
  const key = generateAgentKeyPair();
  const impostor = generateAgentKeyPair();
  const challenge = createChallenge(NOW, { nonce: "chal-1" });
  const response = respondToChallenge(challenge, impostor, HEAD, NOW);
  const check = verifyChallengeResponse(response, challenge, { expectedAgentId: key.publicKeyHex });
  assert.equal(check.ok, false);
});

test("a stale response is rejected", () => {
  const key = generateAgentKeyPair();
  const challenge = createChallenge(NOW, { nonce: "chal-1" });
  const response = respondToChallenge(challenge, key, HEAD, NOW);
  const check = verifyChallengeResponse(response, challenge, {
    expectedAgentId: key.publicKeyHex,
    now: "2026-06-24T12:05:00.000Z", // 5 min later, past the default 60s window
  });
  assert.equal(check.ok, false);
  assert.match(check.reason ?? "", /stale/);
});

test("a tampered covered component (auditHead) breaks verification (RFC 9421 base)", () => {
  const key = generateAgentKeyPair();
  const challenge = createChallenge(NOW, { nonce: "chal-1", verifierId: "verifier-A" });
  const response = respondToChallenge(challenge, key, HEAD, NOW);
  response.auditHead = "b".repeat(64); // swap the live head after signing
  const check = verifyChallengeResponse(response, challenge, { expectedAgentId: key.publicKeyHex, now: NOW });
  assert.equal(check.ok, false);
  assert.match(check.reason ?? "", /signature/);
});

test("the response carries an RFC 9421 Signature-Input value", () => {
  const key = generateAgentKeyPair();
  const challenge = createChallenge(NOW, { nonce: "chal-1", verifierId: "verifier-A" });
  const response = respondToChallenge(challenge, key, HEAD, NOW);
  assert.match(response.signatureInput, /^sig=\("adp-agent-id" "adp-audit-head"\);created=/);
  assert.match(response.signatureInput, /alg="ed25519"/);
  assert.match(response.signatureInput, /nonce="chal-1"/);
  assert.match(response.signatureInput, /tag="verifier-A"/);
});

// ── Version negotiation ────────────────────────────────────────────────────────
test("negotiation: a response declaring a supported version verifies", () => {
  const key = generateAgentKeyPair();
  const challenge = createChallenge(NOW, { nonce: "chal-1", supportedVersions: [1, 2] });
  const response = respondToChallenge(challenge, key, HEAD, NOW, { disclosureVersion: 2 });
  const check = verifyChallengeResponse(response, challenge, {
    expectedAgentId: key.publicKeyHex,
    now: NOW,
    supportedVersions: [1, 2],
  });
  assert.equal(check.ok, true);
});

test("negotiation: a response declaring an unsupported version is refused", () => {
  const key = generateAgentKeyPair();
  const challenge = createChallenge(NOW, { nonce: "chal-1", supportedVersions: [1] });
  const response = respondToChallenge(challenge, key, HEAD, NOW, { disclosureVersion: 9 });
  const check = verifyChallengeResponse(response, challenge, {
    expectedAgentId: key.publicKeyHex,
    now: NOW,
    supportedVersions: [1],
  });
  assert.equal(check.ok, false);
  assert.match(check.reason ?? "", /unsupported disclosure version 9/);
});

test("negotiation: a response that declares no version stays interoperable (no constraint)", () => {
  const key = generateAgentKeyPair();
  const challenge = createChallenge(NOW, { nonce: "chal-1" });
  const response = respondToChallenge(challenge, key, HEAD, NOW); // no disclosureVersion
  const check = verifyChallengeResponse(response, challenge, {
    expectedAgentId: key.publicKeyHex,
    now: NOW,
    supportedVersions: [1],
  });
  assert.equal(check.ok, true);
});

test("negotiation: the declared version is signed — tampering it breaks the signature", () => {
  const key = generateAgentKeyPair();
  const challenge = createChallenge(NOW, { nonce: "chal-1", supportedVersions: [1, 2] });
  const response = respondToChallenge(challenge, key, HEAD, NOW, { disclosureVersion: 1 });
  response.disclosureVersion = 2; // downgrade-attack: claim a different version post-signing
  const check = verifyChallengeResponse(response, challenge, {
    expectedAgentId: key.publicKeyHex,
    now: NOW,
    supportedVersions: [1, 2],
  });
  assert.equal(check.ok, false);
  assert.match(check.reason ?? "", /signature invalid/);
});
