import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import { DisclosureBuilder } from "../src/builder.ts";
import type {
  CapitalEnvelope,
  DeploymentHistory,
  OperatorIdentity,
  SignedDisclosure,
  Tool,
} from "../src/schema.ts";
import {
  agentRegistryCaip10,
  disclosureToSiwaMessage,
  formatSiwaMessage,
  parseSiwaMessage,
  type SiwaMessage,
  verifySiwa,
  verifySiwaAgainstDisclosure,
} from "../src/siwa.ts";

// The secp256k1 EIP-191 path needs the optional @noble extras. If they're absent the
// signature tests SKIP (the pure format/parse tests still run), matching erc8004Onchain.test.
async function nobleAvailable(): Promise<boolean> {
  try {
    await import("@noble/curves/secp256k1");
    await import("@noble/hashes/sha3");
    return true;
  } catch {
    return false;
  }
}
const HAS_NOBLE = await nobleAvailable();
if (!HAS_NOBLE) {
  console.log(
    "[siwa.test] @noble/curves not installed - skipping secp256k1 SIWA signature tests. " +
      "Install with `npm install @noble/curves @noble/hashes`.",
  );
}

// Sign a SIWA message with a test secp256k1 wallet via EIP-191 personal_sign, returning
// the 65-byte r||s||v hex and the wallet address - so a dynamic message round-trips
// through verifySiwa without a precomputed vector.
async function signWithTestWallet(message: string): Promise<{ wallet: string; signature: string }> {
  const { secp256k1 } = await import("@noble/curves/secp256k1");
  const { keccak_256 } = await import("@noble/hashes/sha3");

  // A fixed (well-known test) private key - never a real wallet.
  const priv = Uint8Array.from(
    Buffer.from("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", "hex"),
  );
  const pub = secp256k1.getPublicKey(priv, false); // uncompressed 65 bytes
  const addrHash = keccak_256(pub.subarray(1));
  const wallet = `0x${Buffer.from(addrHash.subarray(addrHash.length - 20)).toString("hex")}`;

  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const full = new Uint8Array(prefix.length + body.length);
  full.set(prefix, 0);
  full.set(body, prefix.length);
  const digest = keccak_256(full);

  const sig = secp256k1.sign(digest, priv);
  const v = 27 + sig.recovery;
  const signature = `0x${sig.toCompactHex()}${v.toString(16).padStart(2, "0")}`;
  return { wallet, signature };
}

const CHAIN_ID = 8453;
const REGISTRY = "0x1111111111111111111111111111111111111111";
const TOKEN_ID = "42";

function baseMessage(address: string): SiwaMessage {
  return {
    domain: "example.com",
    address,
    uri: "https://example.com/login",
    version: "1",
    agentId: TOKEN_ID,
    agentRegistry: agentRegistryCaip10(CHAIN_ID, REGISTRY),
    chainId: CHAIN_ID,
    nonce: "abcd1234efgh",
    issuedAt: "2026-06-24T12:00:00.000Z",
    statement: "Sign in to authorize the disclosed agent.",
  };
}

const TOOLS: Tool[] = [{ name: "pay", access: "gated", movesValue: true }];
const CAPITAL: CapitalEnvelope = {
  mandates: [
    {
      label: "ops",
      scope: "class:ops",
      currency: "USD",
      perTxCapMinor: 10_000,
      perPeriodCapMinor: 50_000,
      period: "week",
      allowedRails: ["x402"],
      expiresAt: "2026-07-20T00:00:00.000Z",
    },
  ],
  custody: "non_custodial",
};
const OPERATOR: OperatorIdentity = {
  operatorId: "op_self",
  attestation: { scheme: "ERC8004", level: "signed" },
  deniabilityBoundary: "Operator authorizes spend within mandates only.",
};
const HISTORY: DeploymentHistory = {
  chainAnchor: "f00dface",
  summary: { totalDecisions: 1, settledCount: 1, blockedCount: 0 },
};

function signedDisclosure(): SignedDisclosure {
  const key = generateAgentKeyPair();
  return new DisclosureBuilder()
    .systemPrompt("careful agent")
    .constitution({ hardConstraints: [], enforced: true })
    .tools(TOOLS, "executor")
    .capital(CAPITAL)
    .operator(OPERATOR)
    .history(HISTORY)
    .validFor(60 * 60 * 1000)
    .buildAndSign({ agentKey: key, now: "2026-06-24T12:00:00.000Z", nonce: "n0nce" });
}

test("formatSiwaMessage <-> parseSiwaMessage round-trips", () => {
  const m = baseMessage("0x2c7536e3605d9c16a7a3d7b1898e529396a65c23");
  m.expirationTime = "2026-06-24T13:00:00.000Z";
  m.requestId = "req-1";
  const text = formatSiwaMessage(m);
  assert.match(text, /wants you to sign in with your Agent account:/);
  assert.match(text, /Agent Registry: eip155:8453:0x1111/);
  assert.deepEqual(parseSiwaMessage(text), m);
});

test("parseSiwaMessage handles an absent statement", () => {
  const m = baseMessage("0x2c7536e3605d9c16a7a3d7b1898e529396a65c23");
  delete m.statement;
  const round = parseSiwaMessage(formatSiwaMessage(m));
  assert.equal(round.statement, undefined);
  assert.deepEqual(round, m);
});

test("disclosureToSiwaMessage builds a message from the binding fields", () => {
  const signed = signedDisclosure();
  const m = disclosureToSiwaMessage(signed, {
    domain: "example.com",
    uri: "https://example.com/login",
    nonce: "abcd1234efgh",
    issuedAt: "2026-06-24T12:00:00.000Z",
    chainId: CHAIN_ID,
    registry: REGISTRY,
    walletAddress: "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    agentTokenId: TOKEN_ID,
  });
  assert.equal(m.address, "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23");
  assert.equal(m.agentId, TOKEN_ID);
  assert.equal(m.agentRegistry, `eip155:${CHAIN_ID}:${REGISTRY}`);
  assert.equal(m.version, "1");
});

test("verifySiwa returns signed for a wallet-signed message", { skip: !HAS_NOBLE }, async () => {
  // The test wallet is deterministic (fixed key), so bind the message address to it,
  // then sign over the final bytes.
  const { wallet } = await signWithTestWallet("probe");
  const msg = { ...baseMessage(wallet) };
  const { signature } = await signWithTestWallet(formatSiwaMessage(msg));
  const result = await verifySiwa(msg, signature, {
    expectedDomain: "example.com",
    nonceValid: () => true,
    now: new Date("2026-06-24T12:30:00.000Z"),
  });
  assert.equal(result.ok, true);
  assert.equal(result.attestation, "signed");
  assert.equal(result.signer, wallet.toLowerCase());
});

test("verifySiwa reaches registry_attested when ownerOf == signer", {
  skip: !HAS_NOBLE,
}, async () => {
  const { wallet } = await signWithTestWallet("probe");
  const msg = baseMessage(wallet);
  const { signature } = await signWithTestWallet(formatSiwaMessage(msg));

  const result = await verifySiwa(msg, signature, {
    expectedDomain: "example.com",
    nonceValid: () => true,
    now: new Date("2026-06-24T12:30:00.000Z"),
    resolveRegistry: async (_reg, _id) => ({ owner: wallet }),
  });
  assert.equal(result.ok, true);
  assert.equal(result.attestation, "registry_attested");
});

test("verifySiwa fails when the registry owner disagrees", { skip: !HAS_NOBLE }, async () => {
  const { wallet } = await signWithTestWallet("probe");
  const msg = baseMessage(wallet);
  const { signature } = await signWithTestWallet(formatSiwaMessage(msg));

  const result = await verifySiwa(msg, signature, {
    expectedDomain: "example.com",
    nonceValid: () => true,
    now: new Date("2026-06-24T12:30:00.000Z"),
    resolveRegistry: async () => ({ owner: "0x0000000000000000000000000000000000000099" }),
  });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /registry owner does not match/);
});

test("verifySiwa rejects a bad domain / nonce / expiry", { skip: !HAS_NOBLE }, async () => {
  const { wallet } = await signWithTestWallet("probe");
  const msg = { ...baseMessage(wallet), expirationTime: "2026-06-24T12:10:00.000Z" };
  const { signature } = await signWithTestWallet(formatSiwaMessage(msg));
  const opts = {
    expectedDomain: "example.com",
    nonceValid: () => true,
    now: new Date("2026-06-24T12:05:00.000Z"),
  };

  const badDomain = await verifySiwa({ ...msg, domain: "evil.com" }, signature, opts);
  assert.equal(badDomain.ok, false);
  assert.match(badDomain.reason ?? "", /domain/);

  const badNonce = await verifySiwa(msg, signature, { ...opts, nonceValid: () => false });
  assert.equal(badNonce.ok, false);
  assert.match(badNonce.reason ?? "", /nonce rejected/);

  const expired = await verifySiwa(msg, signature, {
    ...opts,
    now: new Date("2026-06-24T12:20:00.000Z"),
  });
  assert.equal(expired.ok, false);
  assert.match(expired.reason ?? "", /expired/);
});

test("verifySiwa fails for the wrong signer", { skip: !HAS_NOBLE }, async () => {
  const draft = baseMessage("0x0000000000000000000000000000000000000001");
  const { signature } = await signWithTestWallet(formatSiwaMessage(draft));
  // address (the claimed signer) differs from the test wallet -> mismatch.
  const result = await verifySiwa(draft, signature, {
    expectedDomain: "example.com",
    nonceValid: () => true,
    now: new Date("2026-06-24T12:30:00.000Z"),
  });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /signer does not match/);
});

test("verifySiwaAgainstDisclosure passes when the binding matches", {
  skip: !HAS_NOBLE,
}, async () => {
  const signed = signedDisclosure();
  const { wallet } = await signWithTestWallet("probe");
  const msg = baseMessage(wallet);
  const { signature } = await signWithTestWallet(formatSiwaMessage(msg));

  const result = await verifySiwaAgainstDisclosure(msg, signature, signed, {
    expectedDomain: "example.com",
    nonceValid: () => true,
    now: new Date("2026-06-24T12:30:00.000Z"),
    binding: { wallet },
    expectedAgentTokenId: TOKEN_ID,
  });
  assert.equal(result.ok, true);
  assert.equal(result.attestation, "signed");
});

test("verifySiwaAgainstDisclosure fails when agentId or address differ", {
  skip: !HAS_NOBLE,
}, async () => {
  const signed = signedDisclosure();
  const { wallet } = await signWithTestWallet("probe");
  const msg = baseMessage(wallet);
  const { signature } = await signWithTestWallet(formatSiwaMessage(msg));
  const base = {
    expectedDomain: "example.com",
    nonceValid: () => true,
    now: new Date("2026-06-24T12:30:00.000Z"),
  };

  const wrongToken = await verifySiwaAgainstDisclosure(msg, signature, signed, {
    ...base,
    binding: { wallet },
    expectedAgentTokenId: "999",
  });
  assert.equal(wrongToken.ok, false);
  assert.match(wrongToken.reason ?? "", /agentId does not match/);

  const wrongWallet = await verifySiwaAgainstDisclosure(msg, signature, signed, {
    ...base,
    binding: { wallet: "0x0000000000000000000000000000000000000abc" },
    expectedAgentTokenId: TOKEN_ID,
  });
  assert.equal(wrongWallet.ok, false);
  assert.match(wrongWallet.reason ?? "", /address does not match/);
});
