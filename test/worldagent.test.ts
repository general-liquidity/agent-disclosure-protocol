import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AGENT_BOOK_ADDRESS,
  WORLDAGENT_ATTESTATION_SCHEME,
  WORLDAGENT_SCHEME,
  type AgentBookResolver,
  type WorldAgentAttestation,
  validateWorldAgentStructural,
  verifyWorldAgent,
  worldAgentToOperatorAttestation,
} from "../src/worldagent.ts";

// Probe whether the optional @noble extras are installed. The EIP-191 recovery round-trip
// (and the signing helper that drives it) need secp256k1 + keccak; if absent, those tests
// SKIP rather than fail - the core package must stay usable without them.
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
    "[worldagent.test] @noble/curves not installed - skipping secp256k1 recovery tests. " +
      "Install with `npm install @noble/curves @noble/hashes` to exercise the signed path.",
  );
}

// A fixed (well-known, non-secret) test private key. Deterministic - no network, no generated
// keypair persisted. Used only to sign the CAIP-122 / SIWE challenge so the recover round-trip
// is exercised end-to-end rather than against a frozen vector we cannot re-derive.
const TEST_PRIV = "0x1111111111111111111111111111111111111111111111111111111111111111";

// A standard SIWE / EIP-4361 (CAIP-122) challenge - the message format worldcoin/agentkit
// produces via viem's `createSiweMessage`. The exact bytes are the signed string `M`.
function siweMessage(address: string): string {
  return [
    "world.org wants you to sign in with your Ethereum account:",
    address,
    "",
    "Verify this agent is backed by a World ID-verified human.",
    "",
    "URI: https://world.org",
    "Version: 1",
    "Chain ID: 480",
    "Nonce: 0123456789abcdef",
    "Issued At: 2026-06-25T00:00:00.000Z",
  ].join("\n");
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

// Sign `message` with the test key via EIP-191 personal_sign, producing the 65-byte r||s||v
// hex a wallet emits. Mirrors `eip191Hash` in erc8004Onchain.ts so the recover round-trips.
async function signEip191(message: string): Promise<{ address: string; signature: string }> {
  const { secp256k1 } = await import("@noble/curves/secp256k1");
  const { keccak_256 } = await import("@noble/hashes/sha3");

  const priv = TEST_PRIV.slice(2);
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const full = new Uint8Array(prefix.length + body.length);
  full.set(prefix, 0);
  full.set(body, prefix.length);
  const hash = keccak_256(full);

  const sig = secp256k1.sign(hash, priv);
  const v = 27 + sig.recovery;
  const signature = `0x${bytesToHex(sig.toBytes("compact"))}${v.toString(16)}`;

  const pub = secp256k1.getPublicKey(priv, false);
  const addrHash = keccak_256(pub.subarray(1));
  const address = `0x${bytesToHex(addrHash.subarray(addrHash.length - 20))}`;
  return { address, signature };
}

function att(overrides: Partial<WorldAgentAttestation> = {}): WorldAgentAttestation {
  return {
    scheme: "WorldAgent",
    address: "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    message: "world.org wants you to sign in with your Ethereum account:\n...",
    signature: `0x${"ab".repeat(65)}`,
    chainId: "eip155:480",
    ...overrides,
  };
}

test("AGENT_BOOK_ADDRESS is the canonical World Chain deployment", () => {
  assert.equal(AGENT_BOOK_ADDRESS, "0xA23aB2712eA7BBa896930544C7d6636a96b944dA");
});

test("a well-formed attestation validates structurally", () => {
  assert.equal(validateWorldAgentStructural(att()), true);
});

test("a bad address (not 0x+40hex) fails structurally", () => {
  assert.equal(validateWorldAgentStructural(att({ address: "0x1234" })), false);
});

test("a bad signature (not 65-byte hex) fails structurally", () => {
  assert.equal(validateWorldAgentStructural(att({ signature: "0xdeadbeef" })), false);
});

test("an empty message fails structurally", () => {
  assert.equal(validateWorldAgentStructural(att({ message: "" })), false);
});

test("a wrong scheme fails structurally", () => {
  assert.equal(
    validateWorldAgentStructural(att({ scheme: "WorldID" as WorldAgentAttestation["scheme"] })),
    false,
  );
});

test("a structurally malformed attestation fails before any recovery", async () => {
  const result = await verifyWorldAgent(att({ signature: "0xnothex" }));
  assert.equal(result.structural, false);
  assert.equal(result.valid, false);
  assert.equal(result.humanBacked, false);
  assert.match(result.reason ?? "", /malformed/);
});

test(
  "verifyWorldAgent without a resolver: signature valid but human-backing unverified",
  { skip: !HAS_NOBLE },
  async () => {
    const { address, signature } = await signEip191(siweMessage("placeholder"));
    const message = siweMessage(address);
    const signed = await signEip191(message);
    const result = await verifyWorldAgent(
      att({ address: signed.address, message, signature: signed.signature }),
    );
    assert.equal(result.structural, true);
    assert.equal(result.valid, true);
    assert.equal(result.address?.toLowerCase(), signed.address.toLowerCase());
    assert.equal(result.humanBacked, false);
    assert.match(result.reason ?? "", /AgentBook resolver/);
    // silence the unused first-sign destructure (the placeholder priming the helper)
    assert.ok(address && signature);
  },
);

test(
  "verifyWorldAgent with a resolver returning registered:true is human-backed + surfaces the nullifier",
  { skip: !HAS_NOBLE },
  async () => {
    const message = siweMessage("0x0000000000000000000000000000000000000000");
    const signed = await signEip191(message);
    const m = siweMessage(signed.address);
    const real = await signEip191(m);

    const resolver: AgentBookResolver = async (address) => {
      assert.equal(address.toLowerCase(), real.address.toLowerCase());
      return { registered: true, humanNullifier: "0xdeadbeefhuman" };
    };
    const result = await verifyWorldAgent(
      att({ address: real.address, message: m, signature: real.signature }),
      { resolver },
    );
    assert.equal(result.valid, true);
    assert.equal(result.humanBacked, true);
    assert.equal(result.nullifier, "0xdeadbeefhuman");
  },
);

test(
  "verifyWorldAgent with a resolver returning registered:false is valid but not human-backed",
  { skip: !HAS_NOBLE },
  async () => {
    const message = siweMessage("0x0000000000000000000000000000000000000000");
    const signed = await signEip191(message);
    const m = siweMessage(signed.address);
    const real = await signEip191(m);

    const resolver: AgentBookResolver = async () => ({ registered: false });
    const result = await verifyWorldAgent(
      att({ address: real.address, message: m, signature: real.signature }),
      { resolver },
    );
    assert.equal(result.valid, true);
    assert.equal(result.humanBacked, false);
    assert.match(result.reason ?? "", /not registered in AgentBook/);
  },
);

test(
  "a null resolver result is treated as unregistered (not human-backed)",
  { skip: !HAS_NOBLE },
  async () => {
    const message = siweMessage("0x0000000000000000000000000000000000000000");
    const signed = await signEip191(message);
    const m = siweMessage(signed.address);
    const real = await signEip191(m);

    const result = await verifyWorldAgent(
      att({ address: real.address, message: m, signature: real.signature }),
      { resolver: async () => null },
    );
    assert.equal(result.valid, true);
    assert.equal(result.humanBacked, false);
  },
);

test(
  "verifyWorldAgent fails when the recovered signer != claimed address",
  { skip: !HAS_NOBLE },
  async () => {
    const message = siweMessage("0x0000000000000000000000000000000000000000");
    const signed = await signEip191(message);
    const m = siweMessage(signed.address);
    const real = await signEip191(m);

    // Same valid signature, but claim a different wallet -> recovery mismatch.
    const result = await verifyWorldAgent(
      att({
        address: "0x0000000000000000000000000000000000000001",
        message: m,
        signature: real.signature,
      }),
    );
    assert.equal(result.valid, false);
    assert.equal(result.humanBacked, false);
    assert.match(result.reason ?? "", /does not match the claimed agent wallet/);
  },
);

test("a malformed signature surfaces as valid:false, never throws", { skip: !HAS_NOBLE }, async () => {
  // Structurally valid hex (130 chars) but not a real signature -> recovery throws internally,
  // caught and returned as a reason.
  const result = await verifyWorldAgent(att({ signature: `0x${"00".repeat(65)}` }));
  assert.equal(result.structural, true);
  assert.equal(result.valid, false);
  assert.ok(typeof result.reason === "string");
});

test("worldAgentToOperatorAttestation maps a human-backed agent to registry_attested", () => {
  const out = worldAgentToOperatorAttestation(att(), {
    structural: true,
    valid: true,
    address: att().address,
    humanBacked: true,
    nullifier: "0xhuman1",
  });
  assert.equal(out.scheme, WORLDAGENT_ATTESTATION_SCHEME);
  assert.equal(out.level, "registry_attested");
  assert.equal(out.evidence, "worldagent:human:0xhuman1");
});

test("worldAgentToOperatorAttestation maps valid-but-unbacked to signed, and invalid to none", () => {
  const unbacked = worldAgentToOperatorAttestation(att(), {
    structural: true,
    valid: true,
    address: att().address,
    humanBacked: false,
  });
  assert.equal(unbacked.level, "signed");
  assert.equal(unbacked.evidence, undefined);

  const invalid = worldAgentToOperatorAttestation(att(), {
    structural: true,
    valid: false,
    humanBacked: false,
  });
  assert.equal(invalid.level, "none");
});

test("the World Agent attestation is wireable into a disclosure operator field", async () => {
  const result: Awaited<ReturnType<typeof verifyWorldAgent>> = {
    structural: true,
    valid: true,
    address: att().address,
    humanBacked: true,
    nullifier: "0xhuman1",
  };
  const operator = {
    operatorId: "op_worldagent",
    attestation: worldAgentToOperatorAttestation(att(), result),
    deniabilityBoundary:
      "Operator is an agent backed by a World ID-verified human registered in AgentBook.",
  };
  const { OperatorIdentitySchema } = await import("../src/schema.ts");
  assert.doesNotThrow(() => OperatorIdentitySchema.parse(operator));
});

test("WORLDAGENT_SCHEME is the module-level discriminant", () => {
  assert.equal(WORLDAGENT_SCHEME, "WorldAgent");
});
