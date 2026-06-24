import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import { DisclosureBuilder } from "../src/builder.ts";
import { agentIdToDidKey } from "../src/did.ts";
import type { CapitalEnvelope, DeploymentHistory, OperatorIdentity, SignedDisclosure, Tool } from "../src/schema.ts";
import {
  fromVerifiableCredential,
  toVerifiableCredential,
  verifyVerifiableCredential,
} from "../src/vc.ts";

const NOW = "2026-06-24T12:00:00.000Z";

const TOOLS: Tool[] = [
  { name: "pay", access: "gated", movesValue: true },
  { name: "list_mandates", access: "read_only", movesValue: false },
];

const CAPITAL: CapitalEnvelope = {
  mandates: [
    {
      label: "groceries",
      scope: "class:groceries",
      currency: "GBP",
      perTxCapMinor: 50_000,
      perPeriodCapMinor: 100_000,
      period: "week",
      allowedRails: ["card"],
      expiresAt: "2026-07-20T00:00:00.000Z",
    },
  ],
  custody: "non_custodial",
};

const OPERATOR: OperatorIdentity = {
  operatorId: "op_xyz",
  attestation: { scheme: "AIP", level: "signed" },
  deniabilityBoundary: "The operator authorizes spend within the mandates only.",
};

const HISTORY: DeploymentHistory = {
  chainAnchor: "f00dface",
  summary: { totalDecisions: 42, settledCount: 30, blockedCount: 5 },
};

function signedDisclosure(): { signed: SignedDisclosure; key: ReturnType<typeof generateAgentKeyPair> } {
  const key = generateAgentKeyPair();
  const signed = new DisclosureBuilder()
    .systemPrompt("you are a careful spending agent")
    .constitution({
      hardConstraints: [
        { id: "no_unknown_payee", description: "deny irreversible to unknown payee", kind: "deny" },
      ],
      enforced: true,
      enforcementEvidence: "gate:opensolvency",
    })
    .tools(TOOLS, "executor")
    .capital(CAPITAL)
    .operator(OPERATOR)
    .history(HISTORY)
    .validFor(60 * 60 * 1000)
    .buildAndSign({ agentKey: key, now: NOW, nonce: "n0nce" });
  return { signed, key };
}

test("toVerifiableCredential -> verifyVerifiableCredential is ok", () => {
  const { signed } = signedDisclosure();
  const vc = toVerifiableCredential(signed);

  assert.deepEqual(vc["@context"], [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
  ]);
  assert.deepEqual(vc.type, ["VerifiableCredential", "AgentDisclosureCredential"]);
  assert.equal(vc.proof.type, "Ed25519Signature2020");
  assert.equal(vc.proof.proofValue, signed.signature.value);
  assert.deepEqual(verifyVerifiableCredential(vc), { ok: true });
});

test("issuer defaults to the agentId did:key and the subject id matches", () => {
  const { signed } = signedDisclosure();
  const did = agentIdToDidKey(signed.disclosure.agentId);
  const vc = toVerifiableCredential(signed);

  assert.equal(vc.issuer, did);
  assert.equal(vc.credentialSubject.id, did);
  assert.ok(vc.proof.verificationMethod.startsWith(`${did}#`));
});

test("issuer / id / issuanceDate overrides are honored", () => {
  const { signed } = signedDisclosure();
  const vc = toVerifiableCredential(signed, {
    issuer: "did:web:example.com",
    id: "urn:uuid:1234",
    issuanceDate: "2026-06-24T00:00:00.000Z",
  });

  assert.equal(vc.issuer, "did:web:example.com");
  assert.equal(vc.id, "urn:uuid:1234");
  assert.equal(vc.issuanceDate, "2026-06-24T00:00:00.000Z");
  // a custom issuer does not break proof verification (proof binds to the subject key)
  assert.deepEqual(verifyVerifiableCredential(vc), { ok: true });
});

test("fromVerifiableCredential round-trips to the original SignedDisclosure", () => {
  const { signed } = signedDisclosure();
  const vc = toVerifiableCredential(signed);
  const back = fromVerifiableCredential(vc);
  assert.deepEqual(back, signed);
});

test("a tampered credentialSubject fails verification", () => {
  const { signed } = signedDisclosure();
  const vc = toVerifiableCredential(signed);

  // Mutate a disclosure field inside the credentialSubject without re-signing.
  vc.credentialSubject.operator = {
    ...vc.credentialSubject.operator,
    deniabilityBoundary: "the operator is accountable for everything (forged)",
  };

  const result = verifyVerifiableCredential(vc);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /signature/);
});

test("a subject did:key not matching the agentId fails verification", () => {
  const { signed } = signedDisclosure();
  const vc = toVerifiableCredential(signed);

  // Point the subject at a different agent's did:key.
  vc.credentialSubject.id = agentIdToDidKey(generateAgentKeyPair().publicKeyHex);

  const result = verifyVerifiableCredential(vc);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /does not match the disclosure agentId/);
});
