import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { test } from "node:test";
import {
  ADP_A2A_EXTENSION_URI,
  type A2aAgentCard,
  canonicalCardPayload,
  disclosureExtension,
  extractDisclosure,
  findDisclosureExtension,
  signAgentCard,
  verifyAgentCardSignature,
  verifyCardDisclosure,
  withDisclosureExtension,
} from "../src/a2a.ts";
import { type AgentKeyPair, generateAgentKeyPair } from "../src/attestation.ts";
import { DisclosureBuilder } from "../src/builder.ts";
import type { CapitalEnvelope, DeploymentHistory, OperatorIdentity, SignedDisclosure, Tool } from "../src/schema.ts";

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

function signedDisclosure(key: AgentKeyPair): SignedDisclosure {
  return new DisclosureBuilder()
    .systemPrompt("you are a careful spending agent")
    .constitution({
      hardConstraints: [
        { id: "no_unknown_payee", description: "deny irreversible to unknown payee", kind: "deny" },
      ],
      enforced: true,
      enforcementEvidence: "gate:agentworth",
    })
    .tools(TOOLS, "executor")
    .capital(CAPITAL)
    .operator(OPERATOR)
    .history(HISTORY)
    .validFor(60 * 60 * 1000)
    .buildAndSign({ agentKey: key, now: NOW, nonce: "n0nce" });
}

function baseCard(): A2aAgentCard {
  return {
    protocolVersion: "0.3.0",
    name: "Careful Spender",
    description: "A spending agent that discloses before it transacts.",
    version: "1.0.0",
    url: "https://agent.example.com/a2a",
    capabilities: { streaming: true },
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain"],
    skills: [{ id: "pay", name: "Pay" }],
  };
}

// ── emit ───────────────────────────────────────────────────────────────────────

test("disclosureExtension embeds the disclosure under the ADP uri", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  const ext = disclosureExtension(signed);

  assert.equal(ext.uri, ADP_A2A_EXTENSION_URI);
  assert.equal(ext.required, false);
  assert.ok(typeof ext.description === "string" && ext.description.length > 0);
  assert.equal(ext.params?.agentId, signed.disclosure.agentId);
  assert.deepEqual(ext.params?.disclosure, signed);
});

test("disclosureExtension carries url and respects required", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  const ext = disclosureExtension(signed, { url: "https://a.example/.well-known/agent-disclosure", required: true });
  assert.equal(ext.required, true);
  assert.equal(ext.params?.url, "https://a.example/.well-known/agent-disclosure");
  assert.deepEqual(ext.params?.disclosure, signed);
});

test("disclosureExtension embed:false carries only {agentId,url} and requires url", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  const ext = disclosureExtension(signed, { embed: false, url: "https://a.example/.well-known/agent-disclosure" });
  assert.equal(ext.params?.disclosure, undefined);
  assert.equal(ext.params?.agentId, signed.disclosure.agentId);
  assert.equal(ext.params?.url, "https://a.example/.well-known/agent-disclosure");

  assert.throws(() => disclosureExtension(signed, { embed: false }), /requires opts\.url/);
});

test("embedded disclosure round-trips through extractDisclosure", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  const card = withDisclosureExtension(baseCard(), signed);

  const back = extractDisclosure(card);
  assert.deepEqual(back, signed);
});

test("withDisclosureExtension appends and dedups by uri", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);

  const once = withDisclosureExtension(baseCard(), signed);
  assert.equal(once.capabilities.extensions?.length, 1);
  assert.ok(findDisclosureExtension(once));

  // applying again replaces, does not duplicate
  const twice = withDisclosureExtension(once, signed, { required: true });
  const adpExts = twice.capabilities.extensions?.filter((e) => e.uri === ADP_A2A_EXTENSION_URI) ?? [];
  assert.equal(adpExts.length, 1);
  assert.equal(adpExts[0].required, true);

  // original card untouched (pure)
  assert.equal(baseCard().capabilities.extensions, undefined);
});

test("withDisclosureExtension preserves a pre-existing unrelated extension", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  const card = baseCard();
  card.capabilities.extensions = [{ uri: "https://other.example/ext/v1" }];

  const out = withDisclosureExtension(card, signed);
  assert.equal(out.capabilities.extensions?.length, 2);
  assert.ok(out.capabilities.extensions?.some((e) => e.uri === "https://other.example/ext/v1"));
  assert.ok(findDisclosureExtension(out));
});

test("extractDisclosure returns undefined when absent or link-only", () => {
  assert.equal(extractDisclosure(baseCard()), undefined);

  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  const linkOnly = withDisclosureExtension(baseCard(), signed, {
    embed: false,
    url: "https://a.example/.well-known/agent-disclosure",
  });
  assert.equal(extractDisclosure(linkOnly), undefined);
});

// ── verify: disclosure envelope is the trust root ───────────────────────────────

test("verifyCardDisclosure ok on a card with an embedded valid disclosure", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  const card = withDisclosureExtension(baseCard(), signed);

  const res = verifyCardDisclosure(card);
  assert.equal(res.ok, true);
  assert.equal(res.agentId, signed.disclosure.agentId);
  assert.equal(res.cardSignatureChecked, false);
  assert.equal(res.boundToCardSigner, false);
});

test("verifyCardDisclosure uses opts.fetched for a link-only card", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  const card = withDisclosureExtension(baseCard(), signed, {
    embed: false,
    url: "https://a.example/.well-known/agent-disclosure",
  });

  assert.equal(verifyCardDisclosure(card).ok, false); // nothing embedded, nothing fetched
  const res = verifyCardDisclosure(card, { fetched: signed });
  assert.equal(res.ok, true);
  assert.equal(res.agentId, signed.disclosure.agentId);
});

test("verifyCardDisclosure fails when no disclosure is available", () => {
  const res = verifyCardDisclosure(baseCard());
  assert.equal(res.ok, false);
  assert.equal(res.reason, "no disclosure");
});

test("a tampered embedded disclosure fails the envelope check", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  const card = withDisclosureExtension(baseCard(), signed);

  // mutate a disclosure field inside the embedded extension params without re-signing
  const ext = findDisclosureExtension(card);
  const tampered = ext?.params?.disclosure as SignedDisclosure;
  tampered.disclosure.operator = {
    ...tampered.disclosure.operator,
    deniabilityBoundary: "the operator is accountable for everything (forged)",
  };

  const res = verifyCardDisclosure(card);
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /signature|match/);
});

// ── card JWS (A2A §8.4): EdDSA self-signed card ──────────────────────────────────

test("signAgentCard + verifyAgentCardSignature round-trip (EdDSA, jwk in header)", () => {
  const key = generateAgentKeyPair();
  const signed = signAgentCard(baseCard(), { privateKey: key.privateKey, kid: "agent-key-1" });

  assert.equal(signed.signatures?.length, 1);
  const sig = signed.signatures![0];
  // attach the signer key as an OKP/Ed25519 jwk so the verifier can recover it
  sig.header = { jwk: { kty: "OKP", crv: "Ed25519", x: Buffer.from(key.publicKeyHex, "hex").toString("base64url") } };

  const check = verifyAgentCardSignature(signed, sig);
  assert.equal(check.ok, true);
  assert.equal(check.kid, "agent-key-1");
  assert.equal(check.signerKeyHex, key.publicKeyHex);
});

test("verifyAgentCardSignature fails after the card is mutated post-signing", () => {
  const key = generateAgentKeyPair();
  const signed = signAgentCard(baseCard(), { privateKey: key.privateKey });
  const sig = signed.signatures![0];
  sig.header = { jwk: { kty: "OKP", crv: "Ed25519", x: Buffer.from(key.publicKeyHex, "hex").toString("base64url") } };

  signed.description = "a different description (forged origin)";
  const check = verifyAgentCardSignature(signed, sig);
  assert.equal(check.ok, false);
  assert.match(check.reason ?? "", /mismatch/);
});

test("verifyCardDisclosure reports cardSignatureChecked + boundToCardSigner for a self-signed card", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  let card = withDisclosureExtension(baseCard(), signed);
  // sign the card with the SAME agent key → signer == agentId
  card = signAgentCard(card, { privateKey: key.privateKey, kid: "agent-key-1" });
  card.signatures![0].header = {
    jwk: { kty: "OKP", crv: "Ed25519", x: Buffer.from(key.publicKeyHex, "hex").toString("base64url") },
  };

  const res = verifyCardDisclosure(card);
  assert.equal(res.ok, true);
  assert.equal(res.cardSignatureChecked, true);
  assert.equal(res.boundToCardSigner, true);
});

test("a different signer key verifies the card but does not bind to the agentId", () => {
  const agentKey = generateAgentKeyPair();
  const cardKey = generateAgentKeyPair(); // a different key signs the card
  const signed = signedDisclosure(agentKey);
  let card = withDisclosureExtension(baseCard(), signed);
  card = signAgentCard(card, { privateKey: cardKey.privateKey });
  card.signatures![0].header = {
    jwk: { kty: "OKP", crv: "Ed25519", x: Buffer.from(cardKey.publicKeyHex, "hex").toString("base64url") },
  };

  const res = verifyCardDisclosure(card);
  assert.equal(res.ok, true);
  assert.equal(res.cardSignatureChecked, true);
  assert.equal(res.boundToCardSigner, false); // card signer != agentId
});

test("a broken card signature does not fail the disclosure (envelope is the trust root)", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  let card = withDisclosureExtension(baseCard(), signed);
  card = signAgentCard(card, { privateKey: key.privateKey });
  card.signatures![0].header = {
    jwk: { kty: "OKP", crv: "Ed25519", x: Buffer.from(key.publicKeyHex, "hex").toString("base64url") },
  };

  // flip the card name AFTER signing → the card JWS no longer verifies, but the embedded
  // disclosure envelope is intact, so the overall result stays ok.
  card.name = "Tampered Name";

  const res = verifyCardDisclosure(card);
  assert.equal(res.ok, true);
  assert.equal(res.cardSignatureChecked, false);
  assert.equal(res.boundToCardSigner, false);
});

// ── graceful unsupported / unresolvable algs ─────────────────────────────────────

test("verifyAgentCardSignature returns a graceful reason for an unsupported alg", () => {
  const card = baseCard();
  const sig = {
    protected: Buffer.from(JSON.stringify({ alg: "HS256" }), "utf8").toString("base64url"),
    signature: "AAAA",
  };
  const check = verifyAgentCardSignature(card, sig);
  assert.equal(check.ok, false);
  assert.match(check.reason ?? "", /unsupported alg/);
});

test("EdDSA with no recoverable key returns a graceful reason, not a throw", () => {
  const card = baseCard();
  const sig = {
    protected: Buffer.from(JSON.stringify({ alg: "EdDSA" }), "utf8").toString("base64url"),
    signature: "AAAA",
  };
  const check = verifyAgentCardSignature(card, sig);
  assert.equal(check.ok, false);
  assert.match(check.reason ?? "", /no ed25519 key/);
});

test("ES256 verifies when resolveKey supplies the public key", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const card = baseCard();

  // sign the card payload ourselves with ES256 (raw R||S = ieee-p1363)
  const protectedB64 = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JOSE" }), "utf8").toString("base64url");
  const payloadB64 = Buffer.from(canonicalCardPayload(card), "utf8").toString("base64url");
  const signature = nodeSign(
    "SHA256",
    Buffer.from(`${protectedB64}.${payloadB64}`, "ascii"),
    { key: privateKey, dsaEncoding: "ieee-p1363" },
  ).toString("base64url");

  const check = verifyAgentCardSignature(
    card,
    { protected: protectedB64, signature },
    { resolveKey: () => publicKey },
  );
  assert.equal(check.ok, true);
});
