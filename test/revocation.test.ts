import test from "node:test";
import assert from "node:assert/strict";

import { generateAgentKeyPair } from "../src/attestation.ts";
import {
  RevocationList,
  signRevocation,
  verifyRevocation,
} from "../src/revocation.ts";

const AT = "2026-06-24T12:00:00.000Z";

test("revoke then isRevoked + status reflect the entry", () => {
  const list = new RevocationList();
  list.revoke("disc_1", "key compromised", AT);
  assert.equal(list.isRevoked("disc_1"), true);
  assert.deepEqual(list.status("disc_1"), {
    revoked: true,
    reason: "key compromised",
    revokedAt: AT,
  });
});

test("a non-revoked id reports not revoked", () => {
  const list = new RevocationList();
  assert.equal(list.isRevoked("agent_xyz"), false);
  assert.deepEqual(list.status("agent_xyz"), { revoked: false });
});

test("toJSON/fromJSON round-trip preserves entries", () => {
  const list = new RevocationList();
  list.revoke("disc_1", "compromised", AT);
  list.revoke("agent_xyz", "decommissioned", "2026-06-25T00:00:00.000Z");

  const restored = RevocationList.fromJSON(JSON.parse(JSON.stringify(list.toJSON())));
  assert.deepEqual(restored.entries(), list.entries());
  assert.equal(restored.isRevoked("disc_1"), true);
  assert.equal(restored.status("agent_xyz").reason, "decommissioned");
});

test("signRevocation then verifyRevocation is true", () => {
  const key = generateAgentKeyPair();
  const rec = signRevocation("disc_1", "key compromised", AT, key);
  assert.equal(rec.publicKey, key.publicKeyHex);
  assert.equal(verifyRevocation(rec), true);
});

test("a tampered signed-revocation fails verification", () => {
  const key = generateAgentKeyPair();
  const rec = signRevocation("disc_1", "key compromised", AT, key);
  const tampered = { ...rec, reason: "no longer the signed reason" };
  assert.equal(verifyRevocation(tampered), false);
});
