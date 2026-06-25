import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import { bindWallet, verifyBindingOnchain } from "../src/erc8004.ts";
import {
  ADP_KEY_METADATA_KEY,
  createIdentityRegistryClient,
  createRegistryResolver,
} from "../src/erc8004Registry.ts";

// Probe whether the optional viem extra is installed. If not, the registry tests SKIP
// (with a logged note) rather than fail - the core package must stay usable without it.
async function viemAvailable(): Promise<boolean> {
  try {
    await import("viem");
    return true;
  } catch {
    return false;
  }
}

const HAS_VIEM = await viemAvailable();
if (!HAS_VIEM) {
  console.log(
    "[erc8004Registry.test] viem not installed - skipping registry eth_call tests. " +
      "Install with `npm install viem` to exercise the on-chain registry read.",
  );
}

const REGISTRY = "0x000000000000000000000000000000000000dEaD";
const WALLET = "0xabc0000000000000000000000000000000000001";
const TOKEN_ID = 42n;

// A viem `custom` transport that answers eth_call against the REAL Identity Registry ABI.
// It decodes the inbound call to pick the function, then ABI-encodes a canned return.
// `getAgentWallet(tokenId) -> wallet`, `getMetadata(tokenId, ADP_KEY_METADATA_KEY) ->
// the ed25519 agentId as bytes`. An unseeded wallet/metadata returns the empty/zero
// encoding (an unregistered / unpublished read).
async function mockTransport(seed: { wallet?: string; agentIdHex?: string }) {
  const { custom, decodeFunctionData, encodeAbiParameters } = await import("viem");
  const { IDENTITY_REGISTRY_ABI } = await import("../src/erc8004Registry.ts");
  const ZERO_ADDR = "0x0000000000000000000000000000000000000000";

  return custom({
    async request({ method, params }: { method: string; params?: unknown }) {
      if (method === "eth_chainId") return "0x2105"; // Base
      if (method !== "eth_call") throw new Error(`unexpected JSON-RPC method ${method}`);

      const call = (params as [{ data: `0x${string}` }])[0];
      const decoded = decodeFunctionData({ abi: IDENTITY_REGISTRY_ABI, data: call.data });

      if (decoded.functionName === "getAgentWallet") {
        return encodeAbiParameters(
          [{ type: "address" }],
          [(seed.wallet ?? ZERO_ADDR) as `0x${string}`],
        );
      }
      if (decoded.functionName === "getMetadata") {
        const bytes = seed.agentIdHex ? (`0x${seed.agentIdHex}` as `0x${string}`) : "0x";
        return encodeAbiParameters([{ type: "bytes" }], [bytes]);
      }
      throw new Error(`unexpected registry function ${decoded.functionName}`);
    },
  });
}

const indexTo = (tokenId: bigint | null) => async () => tokenId;

test("IdentityRegistryClient reads getAgentWallet + the published ed25519 agentId", {
  skip: !HAS_VIEM,
}, async () => {
  const key = generateAgentKeyPair();
  const client = createIdentityRegistryClient({
    registryAddress: REGISTRY,
    transport: await mockTransport({ wallet: WALLET, agentIdHex: key.publicKeyHex }),
  });

  assert.equal(await client.getAgentWallet(TOKEN_ID), WALLET.toLowerCase());
  assert.equal(await client.getPublishedAgentId(TOKEN_ID), key.publicKeyHex.toLowerCase());

  const record = await client.getRecord(TOKEN_ID);
  assert.equal(record.tokenId, TOKEN_ID);
  assert.equal(record.wallet, WALLET.toLowerCase());
  assert.equal(record.agentId, key.publicKeyHex.toLowerCase());
});

test("getAgentWallet maps the zero address to null", { skip: !HAS_VIEM }, async () => {
  const client = createIdentityRegistryClient({
    registryAddress: REGISTRY,
    transport: await mockTransport({}),
  });
  assert.equal(await client.getAgentWallet(TOKEN_ID), null);
  assert.equal(await client.getPublishedAgentId(TOKEN_ID), null);
});

test("createRegistryResolver confirms wallet + published agentId via the real reads", {
  skip: !HAS_VIEM,
}, async () => {
  const key = generateAgentKeyPair();
  const resolver = createRegistryResolver(
    {
      registryAddress: REGISTRY,
      transport: await mockTransport({ wallet: WALLET, agentIdHex: key.publicKeyHex }),
    },
    indexTo(TOKEN_ID),
  );

  const entry = await resolver(WALLET);
  assert.ok(entry, "indexed wallet whose on-chain wallet matches should resolve");
  assert.equal(entry?.agentId, key.publicKeyHex.toLowerCase());
});

test("createRegistryResolver returns null when the index does not know the wallet", {
  skip: !HAS_VIEM,
}, async () => {
  const key = generateAgentKeyPair();
  const resolver = createRegistryResolver(
    {
      registryAddress: REGISTRY,
      transport: await mockTransport({ wallet: WALLET, agentIdHex: key.publicKeyHex }),
    },
    indexTo(null),
  );
  assert.equal(await resolver(WALLET), null);
});

test("createRegistryResolver rejects a stale index whose on-chain wallet differs", {
  skip: !HAS_VIEM,
}, async () => {
  const key = generateAgentKeyPair();
  // The registry's getAgentWallet for this tokenId returns a DIFFERENT wallet than the
  // one we are resolving -> the resolver must reject (stale / spoofed index entry).
  const resolver = createRegistryResolver(
    {
      registryAddress: REGISTRY,
      transport: await mockTransport({
        wallet: "0x1111111111111111111111111111111111111111",
        agentIdHex: key.publicKeyHex,
      }),
    },
    indexTo(TOKEN_ID),
  );
  assert.equal(await resolver(WALLET), null);
});

test("verifyBindingOnchain closes the loop through the real registry reads", {
  skip: !HAS_VIEM,
}, async () => {
  const key = generateAgentKeyPair();
  const binding = bindWallet(key, WALLET, 8453, REGISTRY);

  // Registry: wallet matches AND publishes this agent's ed25519 id -> the loop passes.
  const ok = createRegistryResolver(
    {
      registryAddress: REGISTRY,
      transport: await mockTransport({ wallet: WALLET, agentIdHex: key.publicKeyHex }),
    },
    indexTo(TOKEN_ID),
  );
  const matched = await verifyBindingOnchain(binding, ok);
  assert.equal(matched.ok, true);

  // Registry publishes a DIFFERENT ed25519 agentId -> the loop must reject it.
  const other = generateAgentKeyPair();
  const mismatch = createRegistryResolver(
    {
      registryAddress: REGISTRY,
      transport: await mockTransport({ wallet: WALLET, agentIdHex: other.publicKeyHex }),
    },
    indexTo(TOKEN_ID),
  );
  const wrong = await verifyBindingOnchain(binding, mismatch);
  assert.equal(wrong.ok, false);
  assert.match(wrong.reason ?? "", /different agentId/);

  // Wallet the index does not know -> no entry.
  const empty = createRegistryResolver(
    {
      registryAddress: REGISTRY,
      transport: await mockTransport({ wallet: WALLET, agentIdHex: key.publicKeyHex }),
    },
    indexTo(null),
  );
  const miss = await verifyBindingOnchain(binding, empty);
  assert.equal(miss.ok, false);
  assert.match(miss.reason ?? "", /no on-chain registry entry/);
});

// The metadata-key constant is part of the public surface; assert it is stable so a
// rename is a deliberate, reviewed change.
test("ADP_KEY_METADATA_KEY is the reserved on-chain key", () => {
  assert.equal(ADP_KEY_METADATA_KEY, "adp.ed25519AgentId");
});

// Config guard runs regardless of viem: neither rpcUrl nor transport is a clear error.
test("createIdentityRegistryClient requires an rpcUrl or a transport", () => {
  assert.throws(
    () => createIdentityRegistryClient({ registryAddress: REGISTRY }),
    /rpcUrl or an injected transport/,
  );
});
