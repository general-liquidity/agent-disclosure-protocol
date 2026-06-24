import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import {
  bindWallet,
  verifyWalletBinding,
  verifyBindingOnchain,
  type OnchainResolver,
} from "../src/erc8004.ts";

const WALLET = "0xabc0000000000000000000000000000000000001";
const CHAIN_ID = 8453; // Base

test("bindWallet -> verifyWalletBinding ok", () => {
  const key = generateAgentKeyPair();
  const binding = bindWallet(key, WALLET, CHAIN_ID, "0xregistry");

  assert.equal(binding.agentId, key.publicKeyHex);
  assert.equal(binding.wallet, WALLET);
  assert.equal(binding.chainId, CHAIN_ID);
  assert.equal(binding.registry, "0xregistry");

  assert.equal(verifyWalletBinding(binding).ok, true);
});

test("tampered binding fails verification", () => {
  const key = generateAgentKeyPair();
  const binding = bindWallet(key, WALLET, CHAIN_ID);

  // Swap the wallet without re-signing - the signature no longer covers it.
  const tampered = { ...binding, wallet: "0xattacker" };
  const result = verifyWalletBinding(tampered);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /signature/);
});

test("verifyBindingOnchain passes with a matching resolver", async () => {
  const key = generateAgentKeyPair();
  const binding = bindWallet(key, WALLET, CHAIN_ID);

  // Fake registry: the wallet resolves back to the same agentId.
  const resolve: OnchainResolver = async (wallet) =>
    wallet === WALLET ? { agentId: key.publicKeyHex } : null;

  const result = await verifyBindingOnchain(binding, resolve);
  assert.equal(result.ok, true);
});

test("verifyBindingOnchain fails with a mismatching resolver", async () => {
  const key = generateAgentKeyPair();
  const other = generateAgentKeyPair();
  const binding = bindWallet(key, WALLET, CHAIN_ID);

  // Registry binds the wallet to a DIFFERENT agentId.
  const resolve: OnchainResolver = async () => ({ agentId: other.publicKeyHex });

  const result = await verifyBindingOnchain(binding, resolve);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /different agentId/);
});

test("verifyBindingOnchain fails when the wallet has no registry entry", async () => {
  const key = generateAgentKeyPair();
  const binding = bindWallet(key, WALLET, CHAIN_ID);

  const resolve: OnchainResolver = async () => null;

  const result = await verifyBindingOnchain(binding, resolve);
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /no on-chain registry entry/);
});
