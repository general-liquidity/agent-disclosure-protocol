import assert from "node:assert/strict";
import { test } from "node:test";
import { type AgentKeyPair, generateAgentKeyPair } from "../src/attestation.ts";
import { DisclosureBuilder } from "../src/builder.ts";
import type {
  CapitalEnvelope,
  DeploymentHistory,
  OperatorIdentity,
  SignedDisclosure,
  Tool,
} from "../src/schema.ts";
import {
  TAP_ALG_ED25519,
  TAP_DEFAULT_LABEL,
  TAP_TAG_PAYER_AUTH,
  type TapSignatureMaterial,
  type TapSignedRequest,
  defaultTapKeyResolver,
  extractTapDisclosure,
  isoToUnixSeconds,
  parseTapSignatureInput,
  parseTapSignatureValue,
  signTapRequest,
  tapSignatureBase,
  verifyTapRequest,
} from "../src/visatap.ts";

const NOW = "2026-06-24T12:00:00.000Z";
const NOW_SECONDS = isoToUnixSeconds(NOW);

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
  attestation: { scheme: "VisaTAP", level: "signed" },
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
    })
    .tools(TOOLS, "executor")
    .capital(CAPITAL)
    .operator(OPERATOR)
    .history(HISTORY)
    .validFor(60 * 60 * 1000)
    .buildAndSign({ agentKey: key, now: NOW, nonce: "n0nce" });
}

function material(key: AgentKeyPair): TapSignatureMaterial {
  return {
    authority: "merchant.example",
    path: "/checkout",
    keyId: key.publicKeyHex, // ADP case: keyId IS the ed25519 agentId
    nonce: "11111111-2222-3333-4444-555555555555",
    created: NOW_SECONDS,
    expires: NOW_SECONDS + 8 * 60,
    tag: TAP_TAG_PAYER_AUTH,
  };
}

// ── sign → verify round-trip (the core success criterion) ─────────────────────

test("a disclosure round-trips through the TAP bridge (sign -> verify)", async () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  const req = signTapRequest(signed, "https://directory.example.com", material(key), key);

  const res = await verifyTapRequest(req, {
    authority: "merchant.example",
    path: "/checkout",
    nowSeconds: NOW_SECONDS + 10,
    allowedTags: [TAP_TAG_PAYER_AUTH],
  });

  assert.equal(res.ok, true, res.reason);
  assert.equal(res.signerKeyHex, key.publicKeyHex);
  assert.equal(res.boundToDisclosure, true);
  assert.equal(res.disclosure?.disclosure.agentId, key.publicKeyHex);
  assert.equal(res.parsed?.alg, TAP_ALG_ED25519);
  assert.equal(res.parsed?.tag, TAP_TAG_PAYER_AUTH);
});

test("the signed request carries the three TAP headers + the disclosure", () => {
  const key = generateAgentKeyPair();
  const req = signTapRequest(
    signedDisclosure(key),
    "https://directory.example.com",
    material(key),
    key,
  );

  assert.equal(req.signatureAgent, "https://directory.example.com");
  assert.equal(req.label, TAP_DEFAULT_LABEL);
  assert.match(req.signatureInput, /^sig2=\("@authority" "@path"\);/);
  assert.match(req.signatureInput, /alg="ed25519"/);
  assert.match(req.signature, /^sig2=:[A-Za-z0-9+/=]+:$/); // sf-binary base64
  assert.ok(req.adpDisclosure);
});

test("the TAP signature base matches the RFC-9421 reference shape", () => {
  const key = generateAgentKeyPair();
  const base = tapSignatureBase(material(key));
  const lines = base.split("\n");
  assert.equal(lines[0], `"@authority": merchant.example`);
  assert.equal(lines[1], `"@path": /checkout`);
  assert.match(lines[2], /^"@signature-params": \("@authority" "@path"\); created=/);
});

// ── parsing ───────────────────────────────────────────────────────────────────

test("parseTapSignatureInput extracts the covered set + params", () => {
  const key = generateAgentKeyPair();
  const req = signTapRequest(
    signedDisclosure(key),
    "https://directory.example.com",
    material(key),
    key,
  );
  const parsed = parseTapSignatureInput(req.signatureInput);
  assert.ok(parsed);
  assert.deepEqual(parsed?.components, ["@authority", "@path"]);
  assert.equal(parsed?.keyId, key.publicKeyHex);
  assert.equal(parsed?.tag, TAP_TAG_PAYER_AUTH);
  assert.equal(parsed?.created, NOW_SECONDS);

  const sigB64 = parseTapSignatureValue(req.signature, "sig2");
  assert.ok(sigB64 && sigB64.length > 0);
});

test("extractTapDisclosure validates the embedded disclosure, undefined on junk", () => {
  const key = generateAgentKeyPair();
  const signed = signedDisclosure(key);
  const extracted = extractTapDisclosure(JSON.stringify(signed));
  assert.equal(extracted?.disclosure.agentId, signed.disclosure.agentId);
  assert.equal(extracted?.signature.value, signed.signature.value);
  assert.equal(extractTapDisclosure(undefined), undefined);
  assert.equal(extractTapDisclosure("not json"), undefined);
  assert.equal(extractTapDisclosure(JSON.stringify({ nope: true })), undefined);
});

// ── failure modes ─────────────────────────────────────────────────────────────

test("a tampered authority fails verification (signature binds to @authority)", async () => {
  const key = generateAgentKeyPair();
  const req = signTapRequest(
    signedDisclosure(key),
    "https://directory.example.com",
    material(key),
    key,
  );
  const res = await verifyTapRequest(req, { authority: "attacker.example", path: "/checkout" });
  assert.equal(res.ok, false);
});

test("an expired signature is refused under the freshness window", async () => {
  const key = generateAgentKeyPair();
  const req = signTapRequest(
    signedDisclosure(key),
    "https://directory.example.com",
    material(key),
    key,
  );
  const res = await verifyTapRequest(req, {
    authority: "merchant.example",
    path: "/checkout",
    nowSeconds: NOW_SECONDS + 9 * 60, // past expires (created + 8min)
  });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /expired/);
});

test("a disallowed tag is refused", async () => {
  const key = generateAgentKeyPair();
  const req = signTapRequest(
    signedDisclosure(key),
    "https://directory.example.com",
    material(key),
    key,
  );
  const res = await verifyTapRequest(req, {
    authority: "merchant.example",
    path: "/checkout",
    allowedTags: ["agent-browser-auth"],
  });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /not in allowed set/);
});

test("a keyId that does not resolve to a trusted key is refused", async () => {
  const key = generateAgentKeyPair();
  const req = signTapRequest(
    signedDisclosure(key),
    "https://directory.example.com",
    material(key),
    key,
  );
  const res = await verifyTapRequest(req, {
    authority: "merchant.example",
    path: "/checkout",
    resolveKey: () => null,
  });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /did not resolve/);
});

test("a signer key not matching the embedded disclosure agentId fails the binding", async () => {
  const key = generateAgentKeyPair();
  const other = generateAgentKeyPair();
  // sign with `key` but embed a disclosure from `other`
  const req = signTapRequest(
    signedDisclosure(other),
    "https://directory.example.com",
    material(key),
    key,
  );
  const res = await verifyTapRequest(req, { authority: "merchant.example", path: "/checkout" });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /does not match the embedded disclosure/);
});

test("an injected directory resolver is used to resolve the keyId", async () => {
  const key = generateAgentKeyPair();
  const mat: TapSignatureMaterial = { ...material(key), keyId: "tap-key-1" };
  const req = signTapRequest(signedDisclosure(key), "https://directory.example.com", mat, key);
  const res = await verifyTapRequest(req, {
    authority: "merchant.example",
    path: "/checkout",
    requireDisclosureBinding: false,
    resolveKey: ({ keyId, signatureAgent }) => {
      assert.equal(keyId, "tap-key-1");
      assert.equal(signatureAgent, "https://directory.example.com");
      return key.publicKeyHex;
    },
  });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.signerKeyHex, key.publicKeyHex);
});

test("a link-only request (no embedded disclosure) still authenticates the request", async () => {
  const key = generateAgentKeyPair();
  const req = signTapRequest(
    signedDisclosure(key),
    "https://directory.example.com",
    material(key),
    key,
    {
      embedDisclosure: false,
    },
  );
  assert.equal(req.adpDisclosure, undefined);
  const res = await verifyTapRequest(req, { authority: "merchant.example", path: "/checkout" });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.boundToDisclosure, false);
  assert.equal(res.disclosure, undefined);
});

test("defaultTapKeyResolver maps an ed25519 keyId to itself, null otherwise", () => {
  const key = generateAgentKeyPair();
  assert.equal(
    defaultTapKeyResolver({ keyId: key.publicKeyHex, signatureAgent: "x" }),
    key.publicKeyHex,
  );
  assert.equal(defaultTapKeyResolver({ keyId: "not-hex", signatureAgent: "x" }), null);
});

test("a swapped signature value fails (signed bytes are committed)", async () => {
  const key = generateAgentKeyPair();
  const req = signTapRequest(
    signedDisclosure(key),
    "https://directory.example.com",
    material(key),
    key,
  );
  // corrupt one base64 char of the signature payload
  const tampered: TapSignedRequest = {
    ...req,
    signature: req.signature.replace(
      /:([A-Za-z0-9+/=])/,
      (_m, c: string) => `:${c === "A" ? "B" : "A"}`,
    ),
  };
  const res = await verifyTapRequest(tampered, {
    authority: "merchant.example",
    path: "/checkout",
  });
  assert.equal(res.ok, false);
});
