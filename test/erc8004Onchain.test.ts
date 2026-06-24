import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import { verifyBindingOnchain } from "../src/erc8004.ts";
import {
  onchainResolverFromRegistry,
  recoverWalletAddress,
  verifyWalletAttestation,
} from "../src/erc8004Onchain.ts";

// Probe whether the optional @noble extras are installed. If not, the secp256k1 tests
// SKIP (with a logged note) rather than fail - the core package must stay usable
// without them.
async function nobleAvailable(): Promise<boolean> {
  try {
    await import("@noble/curves/secp256k1");
    await import("@noble/hashes/sha3");
    return true;
  } catch {
    return false;
  }
}

// Stable test vector, generated from a fixed (well-known) secp256k1 test private key
// signing the message below via EIP-191 personal_sign. No private key is shipped - only
// the wallet address + message + 65-byte signature a counterparty would receive.
const VECTOR = {
  wallet: "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
  message: "I bind wallet to agent f00dcafe on chain 8453",
  signature:
    "0x2c63890b2148ccabeb532ba41c3a768fd5087d7068bdc5248a8cc7e0f0adbcc9297d85542ebf876bd2c25d941331dcc29ec506566be4224018b88aac1e4cb90f1b",
};

const HAS_NOBLE = await nobleAvailable();
if (!HAS_NOBLE) {
  console.log(
    "[erc8004Onchain.test] @noble/curves not installed - skipping secp256k1 recovery tests. " +
      "Install with `npm install @noble/curves @noble/hashes` to exercise the on-chain path.",
  );
}

test("recoverWalletAddress recovers the signing address", { skip: !HAS_NOBLE }, async () => {
  const recovered = await recoverWalletAddress(VECTOR.message, VECTOR.signature);
  assert.equal(recovered.toLowerCase(), VECTOR.wallet.toLowerCase());
});

test("verifyWalletAttestation passes for a matching wallet", { skip: !HAS_NOBLE }, async () => {
  const result = await verifyWalletAttestation({
    agentId: "f00dcafe",
    wallet: VECTOR.wallet,
    message: VECTOR.message,
    signature: VECTOR.signature,
  });
  assert.equal(result.ok, true);
});

test("verifyWalletAttestation fails for a mismatching wallet", { skip: !HAS_NOBLE }, async () => {
  const result = await verifyWalletAttestation({
    agentId: "f00dcafe",
    wallet: "0x0000000000000000000000000000000000000001",
    message: VECTOR.message,
    signature: VECTOR.signature,
  });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /does not match/);
});

test("verifyWalletAttestation fails when the message is altered", {
  skip: !HAS_NOBLE,
}, async () => {
  // A different signed message recovers a different (here, effectively random) address.
  const result = await verifyWalletAttestation({
    agentId: "f00dcafe",
    wallet: VECTOR.wallet,
    message: "a different statement",
    signature: VECTOR.signature,
  });
  assert.equal(result.ok, false);
});

test("recoverWalletAddress rejects a malformed signature", { skip: !HAS_NOBLE }, async () => {
  await assert.rejects(() => recoverWalletAddress(VECTOR.message, "0xdeadbeef"), /65 bytes/);
});

// The resolver adapter is dependency-free, so it runs regardless of @noble.
test("onchainResolverFromRegistry adapts a registry read into the OnchainResolver seam", async () => {
  const key = generateAgentKeyPair();
  const wallet = "0xabc0000000000000000000000000000000000001";

  // A fake registry client: maps the wallet back to the agentId.
  const read = async (w: string) => (w === wallet ? { agentId: key.publicKeyHex } : null);
  const resolver = onchainResolverFromRegistry(read);

  // Build the agent-side binding and close the loop through the adapted resolver.
  const { bindWallet } = await import("../src/erc8004.ts");
  const binding = bindWallet(key, wallet, 8453);
  const result = await verifyBindingOnchain(binding, resolver);
  assert.equal(result.ok, true);

  // A wallet the registry does not know resolves to null -> no entry.
  const unknown = onchainResolverFromRegistry(async () => null);
  const miss = await verifyBindingOnchain(binding, unknown);
  assert.equal(miss.ok, false);
  assert.match(miss.reason ?? "", /no on-chain registry entry/);
});
