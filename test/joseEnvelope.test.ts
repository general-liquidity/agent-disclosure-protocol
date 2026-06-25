import { createPublicKey, verify as edVerify } from "node:crypto";
import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair, signDisclosureJws } from "../src/attestation.ts";
import type { AgentDisclosure } from "../src/schema.ts";
import { __setJoseLoader, verifyDisclosureJwsWithJose } from "../src/joseEnvelope.ts";

// Minimal disclosure (vendor-neutral). agentId === the signing public key so the binding
// resolves by direct hex match.
function buildDisclosure(agentId: string): AgentDisclosure {
  return {
    version: 1,
    disclosureId: "d-jose",
    agentId,
    issuedAt: "2026-01-01T00:00:00.000Z",
    validUntil: "2026-12-31T00:00:00.000Z",
    nonce: "n-1",
    systemPrompt: { algorithm: "sha256", digest: "aa".repeat(32) },
    constitution: { hardConstraints: [], digest: "bb".repeat(32), enforced: true },
    tools: { tools: [] },
    capital: { mandates: [], custody: "non_custodial" },
    operator: {
      operatorId: "op-1",
      attestation: { scheme: "none", level: "none" },
      deniabilityBoundary: "operator funds the mandate; agent picks vendors",
    },
    history: { chainAnchor: "cc".repeat(32), summary: { totalDecisions: 0, settledCount: 0, blockedCount: 0 } },
    model: { name: "fable", fingerprintAlgorithm: "sha256", digest: "dd".repeat(32) },
  } as AgentDisclosure;
}

// A mock `jose` whose importJWK/flattenedVerify use node:crypto to verify the EdDSA
// signature — so the test proves a STOCK JOSE-shaped verifier accepts the bespoke envelope
// (same signing-input bytes, same EdDSA alg) without installing the real package.
function joseMockLoader() {
  return async () => ({
    importJWK: async (jwk: Record<string, unknown>) => {
      const raw = Buffer.from(jwk.x as string, "base64url");
      const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
      return createPublicKey({ key: spki, format: "der", type: "spki" });
    },
    flattenedVerify: async (
      jws: { protected?: string; payload: string; signature: string },
      key: unknown,
      options?: { algorithms?: string[] },
    ) => {
      if (options?.algorithms && !options.algorithms.includes("EdDSA")) {
        throw new Error("alg not allowed");
      }
      const ok = edVerify(
        null,
        Buffer.from(`${jws.protected}.${jws.payload}`, "ascii"),
        key as ReturnType<typeof createPublicKey>,
        Buffer.from(jws.signature, "base64url"),
      );
      if (!ok) throw new Error("signature verification failed");
      return { payload: new Uint8Array(Buffer.from(jws.payload, "base64url")), protectedHeader: {} };
    },
  });
}

test("jose verifies a bespoke-signed v2 JWS envelope (valid)", async () => {
  __setJoseLoader(joseMockLoader());
  const key = generateAgentKeyPair();
  const signed = signDisclosureJws(buildDisclosure(key.publicKeyHex), key);

  const res = await verifyDisclosureJwsWithJose(signed);
  assert.equal(res.ok, true, res.reason);
});

test("jose path rejects a tampered payload", async () => {
  __setJoseLoader(joseMockLoader());
  const key = generateAgentKeyPair();
  const signed = signDisclosureJws(buildDisclosure(key.publicKeyHex), key);

  // Flip the payload after signing — signing input no longer matches.
  const forged = { ...signed, payload: Buffer.from('{"agentId":"x"}', "utf8").toString("base64url") };
  const res = await verifyDisclosureJwsWithJose(forged);
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /jose verify failed/);
});

test("jose path rejects a non-EdDSA protected header", async () => {
  __setJoseLoader(joseMockLoader());
  const key = generateAgentKeyPair();
  const signed = signDisclosureJws(buildDisclosure(key.publicKeyHex), key);
  const badHeader = Buffer.from(JSON.stringify({ alg: "RS256" }), "utf8").toString("base64url");
  const res = await verifyDisclosureJwsWithJose({ ...signed, protected: badHeader });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /unsupported JWS alg/);
});

test("jose path rejects an agentId that does not bind to the key", async () => {
  __setJoseLoader(joseMockLoader());
  const key = generateAgentKeyPair();
  const other = generateAgentKeyPair();
  // Sign with `other` over a disclosure whose agentId claims `key` — signature is valid for
  // `other`'s embedded JWK, but the agentId does not match.
  const signed = signDisclosureJws(buildDisclosure(key.publicKeyHex), other);
  const res = await verifyDisclosureJwsWithJose(signed);
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /agentId/);
});

test("jose path throws an install hint when jose is absent", async () => {
  __setJoseLoader(async () => {
    throw new Error("Cannot find module 'jose'");
  });
  const key = generateAgentKeyPair();
  const signed = signDisclosureJws(buildDisclosure(key.publicKeyHex), key);
  await assert.rejects(() => verifyDisclosureJwsWithJose(signed), /jose/);
});
