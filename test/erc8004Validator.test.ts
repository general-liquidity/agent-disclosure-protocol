import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ADP_VALIDATION_TAG,
  ERC8004_RESPONSE_FAIL,
  ERC8004_RESPONSE_PASS,
  Erc8004ValidationAttestationSchema,
  confirmAttestationOnchain,
  validationRequestForAttestation,
  verdictToValidationAttestation,
  verifyValidationEvidence,
} from "../src/erc8004Validator.ts";
import type { ValidationStatus } from "../src/erc8004Validation.ts";
import type { DisclosureVerdict } from "../src/verify.ts";

const REQ_HASH = `0x${"ab".repeat(32)}`;
const VALIDATOR = "0x2222222222222222222222222222222222222222";

function transactVerdict(): DisclosureVerdict {
  return {
    decision: "transact",
    checks: { signature: true, freshness: true },
    reasons: [],
    cost: { checksRun: 2, wallMicros: 5 },
  };
}

function refuseVerdict(): DisclosureVerdict {
  return {
    decision: "refuse",
    checks: { signature: true, freshness: false },
    reasons: ["disclosure not fresh"],
    cost: { checksRun: 2, wallMicros: 5 },
  };
}

const ctx = {
  requestHash: REQ_HASH,
  agentId: "a".repeat(64),
  disclosureId: "disc-1",
  erc8004AgentId: 7n,
};

test("a transact verdict maps to an ERC-8004 validationResponse with score 100", () => {
  const { attestation } = verdictToValidationAttestation(transactVerdict(), ctx);
  // shape verifies against the validationResponse-mirroring schema
  assert.doesNotThrow(() => Erc8004ValidationAttestationSchema.parse(attestation));
  assert.equal(attestation.requestHash, REQ_HASH);
  assert.equal(attestation.response, ERC8004_RESPONSE_PASS);
  assert.equal(attestation.tag, ADP_VALIDATION_TAG);
  assert.match(attestation.responseHash, /^0x[0-9a-f]{64}$/);
});

test("a refuse verdict maps to score 0", () => {
  const { attestation } = verdictToValidationAttestation(refuseVerdict(), ctx);
  assert.equal(attestation.response, ERC8004_RESPONSE_FAIL);
});

test("responseHash binds the off-chain evidence and verifies (round-trip)", () => {
  const { attestation, evidence } = verdictToValidationAttestation(transactVerdict(), ctx, {
    responseURI: "https://verifier.example/evidence/1",
  });
  assert.equal(attestation.responseURI, "https://verifier.example/evidence/1");
  // the evidence is the preimage of responseHash
  const check = verifyValidationEvidence(attestation, evidence);
  assert.equal(check.ok, true, check.reason);
  // tamper the evidence -> binding breaks
  const tampered = { ...evidence, agentId: "deadbeef" };
  assert.equal(verifyValidationEvidence(attestation, tampered).ok, false);
});

test("the attestation is deterministic for the same verdict + context", () => {
  const a = verdictToValidationAttestation(transactVerdict(), ctx);
  const b = verdictToValidationAttestation(transactVerdict(), ctx);
  assert.equal(a.attestation.responseHash, b.attestation.responseHash);
});

test("a graded score override is accepted within [0,100]", () => {
  const { attestation } = verdictToValidationAttestation(transactVerdict(), ctx, { score: 75 });
  assert.equal(attestation.response, 75);
  assert.throws(
    () => verdictToValidationAttestation(transactVerdict(), ctx, { score: 101 }),
    /\[0, 100\]/,
  );
});

test("validationRequestForAttestation reuses the requestHash and the ValidationRequestInput shape", () => {
  const { attestation } = verdictToValidationAttestation(transactVerdict(), ctx);
  const reqInput = validationRequestForAttestation(attestation, {
    validatorAddress: VALIDATOR,
    agentId: 7n,
    requestURI: "https://verifier.example/request/1",
  });
  assert.equal(reqInput.requestHash, attestation.requestHash);
  assert.equal(reqInput.validatorAddress, VALIDATOR);
  assert.equal(reqInput.agentId, 7n);
});

test("verdictToValidationAttestation rejects a non-bytes32 requestHash", () => {
  assert.throws(
    () => verdictToValidationAttestation(transactVerdict(), { ...ctx, requestHash: "0x1234" }),
    /32-byte hash/,
  );
});

// ── injected on-chain seam (no live RPC) ──────────────────────────────────────

function statusReader(seed: Partial<ValidationStatus>) {
  return async (requestHash: string): Promise<ValidationStatus> => ({
    requestHash,
    validatorAddress: VALIDATOR.toLowerCase(),
    agentId: 7n,
    response: 0,
    responseHash: `0x${"00".repeat(32)}`,
    tag: ADP_VALIDATION_TAG,
    lastUpdate: 0n,
    ...seed,
  });
}

test("confirmAttestationOnchain matches a registered status via the injected reader", async () => {
  const { attestation } = verdictToValidationAttestation(transactVerdict(), ctx);
  const ok = await confirmAttestationOnchain(
    attestation,
    statusReader({
      response: attestation.response,
      responseHash: attestation.responseHash,
      lastUpdate: 1_700_000_000n,
    }),
  );
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.status?.response, ERC8004_RESPONSE_PASS);
});

test("confirmAttestationOnchain refuses an unanswered request (lastUpdate 0)", async () => {
  const { attestation } = verdictToValidationAttestation(transactVerdict(), ctx);
  const res = await confirmAttestationOnchain(attestation, statusReader({}));
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /no validationResponse recorded/);
});

test("confirmAttestationOnchain refuses a score / responseHash mismatch", async () => {
  const { attestation } = verdictToValidationAttestation(transactVerdict(), ctx);
  const scoreMismatch = await confirmAttestationOnchain(
    attestation,
    statusReader({ response: 50, responseHash: attestation.responseHash, lastUpdate: 1n }),
  );
  assert.equal(scoreMismatch.ok, false);
  assert.match(scoreMismatch.reason ?? "", /does not match attestation/);

  const hashMismatch = await confirmAttestationOnchain(
    attestation,
    statusReader({
      response: attestation.response,
      responseHash: `0x${"ff".repeat(32)}`,
      lastUpdate: 1n,
    }),
  );
  assert.equal(hashMismatch.ok, false);
  assert.match(hashMismatch.reason ?? "", /responseHash does not match/);
});
