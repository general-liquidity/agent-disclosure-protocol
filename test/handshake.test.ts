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
