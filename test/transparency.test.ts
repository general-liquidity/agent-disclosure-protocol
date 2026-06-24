import test from "node:test";
import assert from "node:assert/strict";

import {
  canonicalize,
  generateAgentKeyPair,
  sha256Hex,
  signDisclosure,
} from "../src/attestation.ts";
import { DISCLOSURE_SCHEMA_VERSION, type AgentDisclosure, type SignedDisclosure } from "../src/schema.ts";
import { TransparencyLog, type TransparencyLogEntry } from "../src/transparency.ts";

function disclosure(agentId: string, disclosureId: string): AgentDisclosure {
  return {
    version: DISCLOSURE_SCHEMA_VERSION,
    disclosureId,
    agentId,
    issuedAt: "2026-06-24T12:00:00.000Z",
    validUntil: "2026-06-25T12:00:00.000Z",
    nonce: `nonce_${disclosureId}`,
    systemPrompt: { algorithm: "sha256", digest: "abc123" },
    constitution: {
      hardConstraints: [{ id: "deny_unknown_payee", description: "...", kind: "deny" }],
      digest: "c0ffee",
      enforced: true,
    },
    tools: { tools: [{ name: "pay", access: "gated", movesValue: true }] },
    capital: { mandates: [], custody: "non_custodial" },
    operator: {
      operatorId: "op_xyz",
      attestation: { scheme: "AIP", level: "signed" },
      deniabilityBoundary: "spend within mandates only",
    },
    history: { chainAnchor: "f00dface", summary: { totalDecisions: 1, settledCount: 1, blockedCount: 0 } },
  };
}

function sign(agentId: string, disclosureId: string): SignedDisclosure {
  const key = generateAgentKeyPair();
  return signDisclosure({ ...disclosure(agentId, disclosureId), agentId: key.publicKeyHex }, key);
}

test("a chain of appended disclosures verifies", () => {
  const log = new TransparencyLog();
  log.append(sign("a", "d1"));
  log.append(sign("b", "d2"));
  log.append(sign("c", "d3"));
  assert.deepEqual(log.verify(), { ok: true });
  assert.equal(log.entries().length, 3);
});

test("tampering an entry's digest breaks verify at that index", () => {
  const log = new TransparencyLog();
  log.append(sign("a", "d1"));
  log.append(sign("b", "d2"));
  log.append(sign("c", "d3"));

  // reach into the internal array to corrupt a stored digest
  const internal = log.entries() as TransparencyLogEntry[];
  internal[1].disclosureDigest = sha256Hex("forged");

  const result = log.verify();
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt, 1);
});

test("contains is true for an appended disclosure's digest", () => {
  const log = new TransparencyLog();
  const signed = sign("a", "d1");
  log.append(signed);
  const digest = sha256Hex(canonicalize(signed.disclosure));
  assert.equal(log.contains(digest), true);
  assert.equal(log.contains(sha256Hex("never appended")), false);
});

test("inclusionProof recomputes for a valid index, null out of range", () => {
  const log = new TransparencyLog();
  log.append(sign("a", "d1"));
  log.append(sign("b", "d2"));

  const proof = log.inclusionProof(1);
  assert.ok(proof);
  assert.equal(proof.entry.index, 1);
  assert.equal(proof.recomputes, true);

  assert.equal(log.inclusionProof(5), null);
  assert.equal(log.inclusionProof(-1), null);
});

test("head advances with appends and is GENESIS when empty", () => {
  const log = new TransparencyLog();
  assert.equal(log.head(), "0".repeat(64));
  const e = log.append(sign("a", "d1"));
  assert.equal(log.head(), e.hash);
});
