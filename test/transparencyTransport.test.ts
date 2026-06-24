import test from "node:test";
import assert from "node:assert/strict";

import {
  canonicalize,
  generateAgentKeyPair,
  sha256Hex,
  signDisclosure,
} from "../src/attestation.ts";
import { DISCLOSURE_SCHEMA_VERSION, type AgentDisclosure, type SignedDisclosure } from "../src/schema.ts";
import { TransparencyLog } from "../src/transparency.ts";
import {
  fetchInclusionProof,
  submitToLog,
  verifyInclusionProof,
} from "../src/transparencyTransport.ts";
import type { FetchLike } from "../src/client.ts";

function sign(disclosureId: string): SignedDisclosure {
  const key = generateAgentKeyPair();
  const d: AgentDisclosure = {
    version: DISCLOSURE_SCHEMA_VERSION,
    disclosureId,
    agentId: key.publicKeyHex,
    issuedAt: "2026-06-24T12:00:00.000Z",
    validUntil: "2026-06-25T12:00:00.000Z",
    nonce: `nonce_${disclosureId}`,
    systemPrompt: { algorithm: "sha256", digest: "abc123" },
    constitution: { hardConstraints: [], digest: "c0ffee", enforced: true },
    tools: { tools: [] },
    capital: { mandates: [], custody: "non_custodial" },
    operator: { operatorId: "op", attestation: { scheme: "none", level: "none" }, deniabilityBoundary: "x" },
    history: { chainAnchor: "f00dface", summary: { totalDecisions: 1, settledCount: 1, blockedCount: 0 } },
  };
  return signDisclosure(d, key);
}

// A log server over an in-memory wire: POST appends, GET ?digest= returns a proof.
function logServer(log: TransparencyLog): FetchLike {
  return async (url, init) => {
    if (init?.method === "POST") {
      const signed = JSON.parse(init.body ?? "{}") as SignedDisclosure;
      return { ok: true, status: 200, json: async () => log.append(signed) };
    }
    const digest = new URL(url).searchParams.get("digest") ?? "";
    const entry = log.entries().find((e) => e.disclosureDigest === digest);
    if (!entry) return { ok: false, status: 404, json: async () => null };
    return { ok: true, status: 200, json: async () => entry };
  };
}

test("submit then fetch-proof round-trips, and the proof verifies", async () => {
  const log = new TransparencyLog();
  const fetch = logServer(log);
  const signed = sign("d1");

  const submitted = await submitToLog(fetch, "http://log/submit", signed);
  assert.equal(submitted.index, 0);

  const digest = sha256Hex(canonicalize(signed.disclosure));
  const proof = await fetchInclusionProof(fetch, "http://log/proof", digest);
  assert.ok(proof);
  assert.equal(proof.disclosureDigest, digest);
  assert.equal(verifyInclusionProof(proof), true);
});

test("fetchInclusionProof returns null for a digest the log has never seen", async () => {
  const log = new TransparencyLog();
  const proof = await fetchInclusionProof(logServer(log), "http://log/proof", sha256Hex("absent"));
  assert.equal(proof, null);
});

test("a tampered proof fails verifyInclusionProof", async () => {
  const log = new TransparencyLog();
  const fetch = logServer(log);
  const signed = sign("d1");
  await submitToLog(fetch, "http://log/submit", signed);

  const digest = sha256Hex(canonicalize(signed.disclosure));
  const proof = await fetchInclusionProof(fetch, "http://log/proof", digest);
  assert.ok(proof);

  const tampered = { ...proof, disclosureDigest: sha256Hex("forged") };
  assert.equal(verifyInclusionProof(tampered), false);
});

test("verifyInclusionProof accepts a genuine entry from the log directly", () => {
  const log = new TransparencyLog();
  const entry = log.append(sign("d1"));
  assert.equal(verifyInclusionProof(entry), true);
});
