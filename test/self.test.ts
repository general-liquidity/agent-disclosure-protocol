import assert from "node:assert/strict";
import { test } from "node:test";
import {
  SELF_ATTESTATION_SCHEME,
  type SelfOffchainResult,
  type SelfOnchainRef,
  selfToOperatorAttestation,
  verifySelfAttestation,
} from "../src/self.ts";

const ONCHAIN: SelfOnchainRef = {
  scheme: "Self",
  chainId: 42220, // Celo
  registry: "0x1111111111111111111111111111111111111111",
  agentId: "7",
  nullifier: "0xabc123",
};

function offchain(overrides: Partial<SelfOffchainResult> = {}): SelfOffchainResult {
  return {
    attestationId: 1,
    scope: "adp-login",
    nullifier: "0xnull1234",
    isValidDetails: { isValid: true, isMinimumAgeValid: true, isOfacValid: false },
    disclose: { nationality: "USA", minimumAge: 18, ofac: false },
    ...overrides,
  };
}

test("a well-formed off-chain result verifies structurally", async () => {
  const result = await verifySelfAttestation(offchain());
  assert.equal(result.ok, true);
  assert.equal(result.nullifier, "0xnull1234");
  assert.deepEqual(result.disclosed, { nationality: "USA", minimumAge: 18, ofac: false });
});

test("a sanctioned subject (isOfacValid === true) fails", async () => {
  const result = await verifySelfAttestation(
    offchain({ isValidDetails: { isValid: true, isOfacValid: true } }),
  );
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /sanctions/i);
});

test("an invalid proof (isValid false) fails", async () => {
  const result = await verifySelfAttestation(
    offchain({ isValidDetails: { isValid: false, isOfacValid: false } }),
  );
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /not valid/);
});

test("a structurally malformed result fails", async () => {
  // missing nullifier
  const bad = {
    attestationId: 1,
    scope: "s",
    isValidDetails: { isValid: true },
  } as unknown as SelfOffchainResult;
  const result = await verifySelfAttestation(bad);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /nullifier/);
});

test("an on-chain ref needs an injected verifier", async () => {
  const noVerifier = await verifySelfAttestation(ONCHAIN);
  assert.equal(noVerifier.ok, false);
  assert.match(noVerifier.reason ?? "", /injected verifier/);

  const verified = await verifySelfAttestation(ONCHAIN, {
    verifier: async () => ({ valid: true, nullifier: "0xfromchain" }),
  });
  assert.equal(verified.ok, true);
  assert.equal(verified.nullifier, "0xfromchain");
});

test("an on-chain ref with a bad registry fails structurally", async () => {
  const bad: SelfOnchainRef = { ...ONCHAIN, registry: "not-an-address" };
  const result = await verifySelfAttestation(bad, { verifier: async () => ({ valid: true }) });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /0x EVM address/);
});

test("an injected verifier returning valid:false fails an otherwise-valid result", async () => {
  const result = await verifySelfAttestation(offchain(), {
    verifier: async () => ({ valid: false }),
  });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /verifier rejected/);
});

test("selfToOperatorAttestation maps into ADP's attestation field", async () => {
  const offResult = await verifySelfAttestation(offchain());
  const offAtt = selfToOperatorAttestation(offchain(), offResult);
  assert.equal(offAtt.scheme, SELF_ATTESTATION_SCHEME);
  assert.equal(offAtt.level, "signed");
  assert.equal(offAtt.evidence, "self:nullifier:0xnull1234");

  const onResult = await verifySelfAttestation(ONCHAIN, {
    verifier: async () => ({ valid: true }),
  });
  const onAtt = selfToOperatorAttestation(ONCHAIN, onResult);
  assert.equal(onAtt.level, "registry_attested");

  const failed = selfToOperatorAttestation(offchain(), { ok: false });
  assert.equal(failed.level, "none");
});

test("the Self attestation is wireable into a disclosure operator field", async () => {
  // The mapped attestation satisfies ADP's OperatorIdentity.attestation shape (scheme is
  // an open string, level is one of the frozen ATTESTATION_LEVELS).
  const result = await verifySelfAttestation(offchain());
  const att = selfToOperatorAttestation(offchain(), result);
  const operator = {
    operatorId: "op_self",
    attestation: att,
    deniabilityBoundary: "Operator is a verified human (Self proof-of-personhood).",
  };
  const { OperatorIdentitySchema } = await import("../src/schema.ts");
  assert.doesNotThrow(() => OperatorIdentitySchema.parse(operator));
});
