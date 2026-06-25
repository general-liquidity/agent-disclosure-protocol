import assert from "node:assert/strict";
import { test } from "node:test";
import {
  WORLDID_ATTESTATION_SCHEME,
  type WorldIdAttestation,
  validateWorldIdStructural,
  verifyWorldId,
  worldIdToOperatorAttestation,
} from "../src/worldid.ts";

function proof(overrides: Partial<WorldIdAttestation> = {}): WorldIdAttestation {
  return {
    scheme: "WorldID",
    app_id: "app_staging_abc123",
    action: "adp-operator-login",
    signal: "0x0000000000000000000000000000000000000001",
    nullifier_hash: "0xabc123",
    merkle_root: "0xdef456",
    proof: "0x0102030405",
    verification_level: "orb",
    ...overrides,
  };
}

test("a well-formed proof validates structurally", () => {
  assert.equal(validateWorldIdStructural(proof()), true);
});

test("a bad app_id (no app_ prefix) fails structurally", () => {
  assert.equal(validateWorldIdStructural(proof({ app_id: "staging_abc" })), false);
});

test("a non-hex nullifier_hash fails structurally", () => {
  assert.equal(validateWorldIdStructural(proof({ nullifier_hash: "nothex" })), false);
});

test("an unknown verification_level fails structurally", () => {
  assert.equal(
    validateWorldIdStructural(
      proof({ verification_level: "selfie" as unknown as WorldIdAttestation["verification_level"] }),
    ),
    false,
  );
});

test("verifyWorldId without a verifier is structural-only (crypto-pending), surfacing the nullifier", async () => {
  const result = await verifyWorldId(proof());
  assert.equal(result.structural, true);
  assert.equal(result.valid, false);
  assert.equal(result.nullifier, "0xabc123");
  assert.match(result.reason ?? "", /injected verifier/);
});

test("a structurally malformed proof fails before any verifier runs", async () => {
  const result = await verifyWorldId(proof({ proof: "not-hex" }));
  assert.equal(result.structural, false);
  assert.equal(result.valid, false);
  assert.match(result.reason ?? "", /malformed/);
});

test("an injected verifier returning valid:true verifies and can override the nullifier", async () => {
  const result = await verifyWorldId(proof(), {
    verifier: async () => ({ valid: true, nullifier: "0xfromportal" }),
  });
  assert.equal(result.valid, true);
  assert.equal(result.nullifier, "0xfromportal");
});

test("an injected verifier returning valid:false fails an otherwise-valid proof", async () => {
  const result = await verifyWorldId(proof(), { verifier: async () => ({ valid: false }) });
  assert.equal(result.structural, true);
  assert.equal(result.valid, false);
  assert.match(result.reason ?? "", /verifier rejected/);
});

test("worldIdToOperatorAttestation maps an orb proof to registry_attested", async () => {
  const result = await verifyWorldId(proof(), { verifier: async () => ({ valid: true }) });
  const att = worldIdToOperatorAttestation(proof(), result);
  assert.equal(att.scheme, WORLDID_ATTESTATION_SCHEME);
  assert.equal(att.level, "registry_attested");
  assert.equal(att.evidence, "worldid:nullifier:0xabc123");
});

test("worldIdToOperatorAttestation maps a non-orb proof to signed, and a failure to none", async () => {
  const device = proof({ verification_level: "device" });
  const result = await verifyWorldId(device, { verifier: async () => ({ valid: true }) });
  assert.equal(worldIdToOperatorAttestation(device, result).level, "signed");

  const failed = worldIdToOperatorAttestation(proof(), {
    structural: true,
    valid: false,
  });
  assert.equal(failed.level, "none");
});

test("the World ID attestation is wireable into a disclosure operator field", async () => {
  const result = await verifyWorldId(proof(), { verifier: async () => ({ valid: true }) });
  const att = worldIdToOperatorAttestation(proof(), result);
  const operator = {
    operatorId: "op_worldid",
    attestation: att,
    deniabilityBoundary: "Operator is a verified unique human (World ID orb proof-of-personhood).",
  };
  const { OperatorIdentitySchema } = await import("../src/schema.ts");
  assert.doesNotThrow(() => OperatorIdentitySchema.parse(operator));
});
