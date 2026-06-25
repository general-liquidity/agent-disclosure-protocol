import assert from "node:assert/strict";
import { test } from "node:test";
import {
  HUMAN_THRESHOLD,
  HUMANPASSPORT_ATTESTATION_SCHEME,
  type HumanPassportAttestation,
  passportToAdpLevel,
  passportToOperatorAttestation,
  validatePassportAttestation,
  verifyPassportAttestation,
} from "../src/humanpassport.ts";

function passport(overrides: Partial<HumanPassportAttestation> = {}): HumanPassportAttestation {
  return {
    scheme: "HumanPassport",
    address: "0x1111111111111111111111111111111111111111",
    score: 28.5,
    threshold: HUMAN_THRESHOLD,
    passing: true,
    stamps: { Google: { score: 1.2, dedup: false }, ENS: { score: 2.4, dedup: false } },
    timestamp: "2026-06-25T00:00:00Z",
    ...overrides,
  };
}

test("a well-formed attestation validates structurally", () => {
  assert.equal(validatePassportAttestation(passport()), true);
});

test("a bad address fails structurally", () => {
  assert.equal(validatePassportAttestation(passport({ address: "0xnope" })), false);
});

test("a non-finite score fails structurally", () => {
  assert.equal(validatePassportAttestation(passport({ score: Number.NaN })), false);
});

test("verifyPassportAttestation without a scorer uses the embedded score / passing", async () => {
  const result = await verifyPassportAttestation(passport());
  assert.equal(result.structural, true);
  assert.equal(result.passing, true);
  assert.equal(result.score, 28.5);
});

test("a malformed attestation fails before any scorer runs", async () => {
  const result = await verifyPassportAttestation(passport({ address: "0xnope" }));
  assert.equal(result.structural, false);
  assert.equal(result.passing, false);
  assert.match(result.reason ?? "", /malformed/);
});

test("an injected scorer overrides the embedded score and recomputes passing", async () => {
  // Embedded claims passing:true, but the live score is below threshold -> not passing.
  const result = await verifyPassportAttestation(passport({ score: 30, passing: true }), {
    scorer: async () => ({ score: 12 }),
  });
  assert.equal(result.score, 12);
  assert.equal(result.passing, false);
});

test("an injected scorer's explicit passing verdict wins", async () => {
  const result = await verifyPassportAttestation(passport(), {
    scorer: async () => ({ score: 5, passing: true, threshold: 4 }),
  });
  assert.equal(result.passing, true);
  assert.equal(result.score, 5);
});

test("passportToAdpLevel bands score against the threshold", () => {
  assert.equal(passportToAdpLevel(undefined), "unverified");
  assert.equal(passportToAdpLevel(5), "low"); // < 20
  assert.equal(passportToAdpLevel(20), "medium"); // >= 20 (1x)
  assert.equal(passportToAdpLevel(29), "medium"); // >= 20, < 30
  assert.equal(passportToAdpLevel(30), "high"); // >= 30 (1.5x)
});

test("passportToOperatorAttestation maps a passing attestation to signed", async () => {
  const result = await verifyPassportAttestation(passport());
  const att = passportToOperatorAttestation(passport(), result);
  assert.equal(att.scheme, HUMANPASSPORT_ATTESTATION_SCHEME);
  assert.equal(att.level, "signed");
  assert.equal(att.evidence, "humanpassport:medium:28.5");
});

test("passportToOperatorAttestation maps a non-passing attestation to none", () => {
  const att = passportToOperatorAttestation(passport(), { structural: true, passing: false });
  assert.equal(att.level, "none");
});

test("the Human Passport attestation is wireable into a disclosure operator field", async () => {
  const result = await verifyPassportAttestation(passport());
  const att = passportToOperatorAttestation(passport(), result);
  const operator = {
    operatorId: "op_humanpassport",
    attestation: att,
    deniabilityBoundary: "Operator's address has a passing Unique Humanity Score (Human Passport).",
  };
  const { OperatorIdentitySchema } = await import("../src/schema.ts");
  assert.doesNotThrow(() => OperatorIdentitySchema.parse(operator));
});
