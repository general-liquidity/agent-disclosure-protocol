import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import { bindWallet, verifyBindingOnchain } from "../src/erc8004.ts";
import { createRegistryResolver } from "../src/erc8004Registry.ts";

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
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

// A viem `custom` transport that answers eth_call from a wallet->bytes32 table. ADP
// agentIds are 32-byte ed25519 keys, which the registry records as a bytes32 (= the
// agentId hex with a 0x prefix). Any wallet absent from the table reads as the all-zero
// bytes32 (an unregistered wallet).
async function mockTransport(table: Record<string, string>) {
  const { custom } = await import("viem");
  return custom({
    async request({ method }: { method: string; params?: unknown }) {
      if (method === "eth_chainId") return "0x2105"; // Base
      if (method === "eth_call") {
        // The single registry function (agentOf) is the only call this client makes; we
        // return the canned result regardless of which wallet (the resolver under test
        // is built per-wallet table below, so one entry is in flight at a time).
        return Object.values(table)[0] ?? ZERO_BYTES32;
      }
      throw new Error(`unexpected JSON-RPC method ${method}`);
    },
  });
}

test("createRegistryResolver resolves a mapped wallet to its agentId", {
  skip: !HAS_VIEM,
}, async () => {
  const key = generateAgentKeyPair();
  // The registry stores the 32-byte ed25519 agentId as a bytes32 (0x-prefixed).
  const agentIdBytes32 = `0x${key.publicKeyHex}`;

  const resolver = createRegistryResolver({
    registryAddress: REGISTRY,
    transport: await mockTransport({ [WALLET]: agentIdBytes32 }),
  });

  const entry = await resolver(WALLET);
  assert.ok(entry, "mapped wallet should resolve to an entry");
  // Decoded back to the raw hex form ADP uses (no 0x prefix).
  assert.equal(entry?.agentId, key.publicKeyHex);
});

test("createRegistryResolver maps a zero result to null", { skip: !HAS_VIEM }, async () => {
  const resolver = createRegistryResolver({
    registryAddress: REGISTRY,
    transport: await mockTransport({ [WALLET]: ZERO_BYTES32 }),
  });

  const entry = await resolver("0x0000000000000000000000000000000000000002");
  assert.equal(entry, null);
});

test("verifyBindingOnchain closes the loop through a live-shaped registry read", {
  skip: !HAS_VIEM,
}, async () => {
  const key = generateAgentKeyPair();
  const binding = bindWallet(key, WALLET, 8453, REGISTRY);

  // Registry records the wallet -> this agent's id; the resolver confirms it.
  const ok = createRegistryResolver({
    registryAddress: REGISTRY,
    transport: await mockTransport({ [WALLET]: `0x${key.publicKeyHex}` }),
  });
  const matched = await verifyBindingOnchain(binding, ok);
  assert.equal(matched.ok, true);

  // Registry binds the wallet to a DIFFERENT agentId -> the loop must reject it.
  const other = generateAgentKeyPair();
  const mismatch = createRegistryResolver({
    registryAddress: REGISTRY,
    transport: await mockTransport({ [WALLET]: `0x${other.publicKeyHex}` }),
  });
  const wrong = await verifyBindingOnchain(binding, mismatch);
  assert.equal(wrong.ok, false);
  assert.match(wrong.reason ?? "", /different agentId/);

  // Unregistered wallet (all-zero bytes32) -> no entry.
  const empty = createRegistryResolver({
    registryAddress: REGISTRY,
    transport: await mockTransport({ [WALLET]: ZERO_BYTES32 }),
  });
  const miss = await verifyBindingOnchain(binding, empty);
  assert.equal(miss.ok, false);
  assert.match(miss.reason ?? "", /no on-chain registry entry/);
});

// Config guard runs regardless of viem: neither rpcUrl nor transport is a clear error.
test("createRegistryResolver requires an rpcUrl or a transport", () => {
  assert.throws(
    () => createRegistryResolver({ registryAddress: REGISTRY }),
    /rpcUrl or an injected transport/,
  );
});
