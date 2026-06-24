// ERC-8004 on-chain half - the WALLET-side (secp256k1) attestation.
//
// erc8004.ts closes the AGENT half: the agent (an ed25519 key) signs a claim that it
// controls a wallet. This module closes the REVERSE half: proof that the Ethereum
// WALLET itself signed a statement acknowledging the binding. The wallet signs with
// secp256k1 over an EIP-191 personal-sign hash, and we recover the signing address
// from the signature - the same recovery an on-chain `ecrecover` performs. So a
// counterparty gets a mutual attestation: the agent claims the wallet AND the wallet
// claims the agent, neither relying on a shared secret.
//
// secp256k1 + keccak are NOT node:crypto primitives, so they are an OPTIONAL extra.
// The core ADP package stays zero-extra-dependency: @noble/curves + @noble/hashes are
// imported DYNAMICALLY inside the functions, and a missing install throws a clear,
// actionable error rather than breaking package import. Install them only if you use
// this subpath.
//
// HONEST SCOPE: this provides the signature-recovery half. A full ERC-8004 registry
// client (JSON-RPC transport + the registry contract ABI + a wallet -> agentId read)
// is the remaining integration. `onchainResolverFromRegistry` is the adapter seam for
// that client: give it a read fn and it plugs into the existing OnchainResolver used
// by `verifyBindingOnchain` in erc8004.ts.

import type { BindingCheck, OnchainResolver } from "./erc8004.ts";

// Loaded lazily so the dep stays optional. `@noble/hashes/sha3` exports keccak_256.
type NobleSecp = typeof import("@noble/curves/secp256k1");
type NobleSha3 = typeof import("@noble/hashes/sha3");

const INSTALL_HINT =
  "on-chain wallet verification needs @noble/curves and @noble/hashes. " +
  "Install them: `npm install @noble/curves @noble/hashes` (optional extras for the erc8004Onchain subpath).";

async function loadNoble(): Promise<{
  secp256k1: NobleSecp["secp256k1"];
  keccak_256: NobleSha3["keccak_256"];
}> {
  try {
    const [{ secp256k1 }, { keccak_256 }] = await Promise.all([
      import("@noble/curves/secp256k1"),
      import("@noble/hashes/sha3"),
    ]);
    return { secp256k1, keccak_256 };
  } catch {
    throw new Error(INSTALL_HINT);
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** keccak-256 of the EIP-191 personal_sign envelope:
 *  keccak256("\x19Ethereum Signed Message:\n" + len(message) + message). The byte
 *  length is over the UTF-8 encoding, matching every wallet's personal_sign. */
function eip191Hash(message: string, keccak: NobleSha3["keccak_256"]): Uint8Array {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const full = new Uint8Array(prefix.length + body.length);
  full.set(prefix, 0);
  full.set(body, prefix.length);
  return keccak(full);
}

/** Ethereum address (0x + 40 lowercase hex) from a 65-byte uncompressed public key:
 *  the low 20 bytes of keccak256 over the 64-byte body (drop the 0x04 prefix). */
function addressFromUncompressed(pub: Uint8Array, keccak: NobleSha3["keccak_256"]): string {
  const body = pub.subarray(1);
  const hash = keccak(body);
  return `0x${bytesToHex(hash.subarray(hash.length - 20))}`;
}

/** Recover the Ethereum address that produced an EIP-191 personal-sign signature over
 *  `message`. `signatureHex` is the 65-byte r||s||v form (with or without 0x), where
 *  v is 27/28 (or 0/1). Throws on a malformed signature or a missing noble install. */
export async function recoverWalletAddress(message: string, signatureHex: string): Promise<string> {
  const { secp256k1, keccak_256 } = await loadNoble();

  const raw = signatureHex.startsWith("0x") ? signatureHex.slice(2) : signatureHex;
  if (raw.length !== 130) {
    throw new Error("signature must be 65 bytes (r||s||v) hex");
  }
  const rs = raw.slice(0, 128);
  const vByte = Number.parseInt(raw.slice(128, 130), 16);
  // EIP-155-free personal_sign: v is 27/28; some libraries emit 0/1.
  const recovery = vByte >= 27 ? vByte - 27 : vByte;
  if (recovery !== 0 && recovery !== 1) {
    throw new Error("signature recovery byte (v) must be 0/1 or 27/28");
  }

  const hash = eip191Hash(message, keccak_256);
  const sig = secp256k1.Signature.fromCompact(rs).addRecoveryBit(recovery);
  const point = sig.recoverPublicKey(hash);
  return addressFromUncompressed(point.toBytes(false), keccak_256);
}

/** A wallet's signed acknowledgement of the binding: the wallet (secp256k1) signed
 *  `message` and claims `wallet` as its address, all referencing `agentId`. `message`
 *  is whatever human-readable statement the wallet signed - it travels in the clear. */
export interface WalletAttestation {
  agentId: string;
  wallet: string;
  message: string;
  signature: string;
}

/** Verify the wallet half: recover the signer from `signature` over `message` and
 *  confirm it equals `att.wallet` (case-insensitive - addresses are compared
 *  lowercased). Proves the WALLET acknowledged the binding; pair with
 *  `verifyWalletBinding` (the agent half) for a mutual attestation. A malformed
 *  signature or a missing noble install surfaces as `{ ok: false, reason }`. */
export async function verifyWalletAttestation(att: WalletAttestation): Promise<BindingCheck> {
  let recovered: string;
  try {
    recovered = await recoverWalletAddress(att.message, att.signature);
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : "signature recovery failed" };
  }
  if (recovered.toLowerCase() !== att.wallet.toLowerCase()) {
    return { ok: false, reason: "recovered address does not match the claimed wallet" };
  }
  return { ok: true };
}

/** Adapt a registry-read fn (wallet -> the agentId the registry records) into the
 *  existing OnchainResolver seam consumed by `verifyBindingOnchain`. `read` is the
 *  thin part a real ERC-8004 client provides: a JSON-RPC call into the registry
 *  contract. This wrapper just normalizes its result to the resolver contract, so the
 *  rest of erc8004.ts is unchanged whether the resolver is a fake or a live chain read.
 *
 *  REMAINING INTEGRATION: `read` itself - the RPC transport + registry ABI + the
 *  wallet->agentId mapping - is not in this package. This is the adapter, not the
 *  client. */
export function onchainResolverFromRegistry(
  read: (wallet: string) => Promise<{ agentId?: string } | null>,
): OnchainResolver {
  return async (wallet: string) => read(wallet);
}
