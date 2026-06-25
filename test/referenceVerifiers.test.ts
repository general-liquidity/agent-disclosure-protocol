import assert from "node:assert/strict";
import { test } from "node:test";
import {
  LOOKUP_HUMAN_SELECTOR,
  makePassportReferenceScorer,
  makeSelfReferenceVerifier,
  makeWorldAgentReferenceResolver,
  makeWorldIdReferenceVerifier,
} from "../src/referenceVerifiers.ts";
import { verifyPassportAttestation, type HumanPassportAttestation } from "../src/humanpassport.ts";
import { verifySelfAttestation, type SelfOffchainResult } from "../src/self.ts";
import { verifyWorldId, type WorldIdAttestation } from "../src/worldid.ts";

// ── Self reference verifier (mocked @selfxyz/core SelfBackendVerifier) ─────────

const SELF_OFFCHAIN: SelfOffchainResult = {
  attestationId: 1,
  scope: "adp-app",
  nullifier: "0xnull",
  isValidDetails: { isValid: true, isOfacValid: false },
  disclose: { nationality: "US" },
};

test("Self reference verifier returns the seam's { valid, nullifier } from the backend", async () => {
  const verifier = makeSelfReferenceVerifier({
    backend: {
      verify: async () => ({
        isValidDetails: { isValid: true, isOfacValid: false },
        discloseOutput: { nullifier: "0xfromBackend" },
      }),
    },
  });
  const out = await verifier(SELF_OFFCHAIN);
  assert.deepEqual(out, { valid: true, nullifier: "0xfromBackend" });

  // Plugs into the real verifySelfAttestation as opts.verifier.
  const v = await verifySelfAttestation(SELF_OFFCHAIN, { verifier });
  assert.equal(v.ok, true, v.reason);
});

test("Self reference verifier marks OFAC-sanctioned proofs invalid (inverted flag)", async () => {
  const verifier = makeSelfReferenceVerifier({
    backend: {
      verify: async () => ({ isValidDetails: { isValid: true, isOfacValid: true } }),
    },
  });
  const out = await verifier(SELF_OFFCHAIN);
  assert.equal(out.valid, false);
});

test("Self reference verifier throws an install hint when @selfxyz/core is absent", async () => {
  const verifier = makeSelfReferenceVerifier({
    loader: async () => {
      throw new Error("Cannot find module '@selfxyz/core'");
    },
  });
  await assert.rejects(() => verifier(SELF_OFFCHAIN), /@selfxyz\/core/);
});

// ── World ID reference verifier (mocked Developer-Portal /verify fetch) ────────

const WORLDID_ATT: WorldIdAttestation = {
  scheme: "WorldID",
  app_id: "app_123",
  action: "login",
  nullifier_hash: "0xabc",
  merkle_root: "0xdef",
  proof: "0x01",
  verification_level: "orb",
};

function mockFetch(body: unknown, ok = true): typeof fetch {
  return (async () => ({ ok, status: ok ? 200 : 400, json: async () => body }) as unknown as Response) as unknown as typeof fetch;
}

test("World ID reference verifier maps portal success to the seam contract", async () => {
  const verifier = makeWorldIdReferenceVerifier({ fetchImpl: mockFetch({ success: true }) });
  const out = await verifier(WORLDID_ATT);
  assert.deepEqual(out, { valid: true, nullifier: "0xabc" });

  const v = await verifyWorldId(WORLDID_ATT, { verifier });
  assert.equal(v.valid, true, v.reason);
});

test("World ID reference verifier maps a portal failure to valid:false", async () => {
  const verifier = makeWorldIdReferenceVerifier({ fetchImpl: mockFetch({ success: false }) });
  const out = await verifier(WORLDID_ATT);
  assert.equal(out.valid, false);
});

// ── Human Passport reference scorer (mocked Passport API; STRING parsing) ──────

const PASSPORT_ATT: HumanPassportAttestation = {
  scheme: "HumanPassport",
  address: `0x${"ab".repeat(20)}`,
};

test("Passport reference scorer parses the API's numeric STRINGS into numbers", async () => {
  const scorer = makePassportReferenceScorer({
    scorerId: "42",
    apiKey: "k",
    fetchImpl: mockFetch({ score: "27.5", passing_score: true, threshold: "20" }),
  });
  const out = await scorer(PASSPORT_ATT.address);
  assert.equal(out.score, 27.5);
  assert.equal(out.passing, true);
  assert.equal(out.threshold, 20);

  const v = await verifyPassportAttestation(PASSPORT_ATT, { scorer });
  assert.equal(v.passing, true);
  assert.equal(v.score, 27.5);
});

test("Passport reference scorer sends the X-API-KEY header", async () => {
  let seenKey: string | undefined;
  const scorer = makePassportReferenceScorer({
    scorerId: "1",
    apiKey: "secret-key",
    fetchImpl: (async (_url: string, init?: { headers?: Record<string, string> }) => {
      seenKey = init?.headers?.["X-API-KEY"];
      return { ok: true, status: 200, json: async () => ({ score: "5" }) } as unknown as Response;
    }) as unknown as typeof fetch,
  });
  await scorer(PASSPORT_ATT.address);
  assert.equal(seenKey, "secret-key");
});

// ── World Agent reference resolver (injected eth_call transport) ───────────────

test("World Agent reference resolver decodes a non-zero lookupHuman as registered", async () => {
  let seenData: string | undefined;
  const resolver = makeWorldAgentReferenceResolver({
    transport: async ({ data }) => {
      seenData = data;
      return `0x${"0".repeat(63)}7`; // humanId = 7
    },
  });
  const out = await resolver(`0x${"cd".repeat(20)}`);
  assert.deepEqual(out, { registered: true, humanNullifier: "0x7" });
  // ABI-encoded call: selector + 32-byte left-padded address.
  assert.ok(seenData?.startsWith(LOOKUP_HUMAN_SELECTOR));
  assert.equal(seenData?.length, 2 + 8 + 64);
});

test("World Agent reference resolver decodes a zero return as unregistered", async () => {
  const resolver = makeWorldAgentReferenceResolver({
    transport: async () => `0x${"0".repeat(64)}`,
  });
  const out = await resolver(`0x${"cd".repeat(20)}`);
  assert.deepEqual(out, { registered: false });
});
