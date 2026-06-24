// ERC-8004 identity bridge - the agent-side wallet binding.
//
// ERC-8004 anchors an agent's identity to a wallet address in an on-chain registry
// and names a pluggable verification layer it does NOT itself fill. ADP fills the
// agent half: the agent attests a link from its agentId (an ed25519 public key) to a
// wallet address, signed with the same key that signs its disclosures. So a
// counterparty can verify the agent->wallet CLAIM with no shared secret and no chain
// access (ed25519, node:crypto only).
//
// The reverse direction - confirming the on-chain registry actually points the wallet
// back at this agentId - needs a real secp256k1/registry client (an Ethereum read).
// That is the INJECTED seam (OnchainResolver): ADP deliberately does not bundle a
// chain client, to stay zero-extra-dependency. `verifyBindingOnchain` composes the
// local signature check with the injected lookup so both halves close the loop.

import { z } from "zod";
import { canonicalize, verifyMessage, signMessage, type AgentKeyPair } from "./attestation.ts";

const Hex = z.string().regex(/^[0-9a-fA-F]+$/, "hex string");

/** The agent's signed claim that its identity (agentId) controls `wallet`. The
 *  signature is over canonicalize({agentId, wallet, chainId, registry}); `statement`
 *  is a human-readable label and is NOT part of the signed payload. */
export const Erc8004BindingSchema = z.object({
  /** the agent's ed25519 public key (hex) - the same id that signs disclosures */
  agentId: Hex,
  /** the wallet address the agent claims to control (chain-native form, e.g. 0x...) */
  wallet: z.string(),
  /** EVM chain id the wallet/registry lives on */
  chainId: z.number().int().nonnegative(),
  /** the ERC-8004 registry contract address this binding targets, if any */
  registry: z.string().optional(),
  /** human-readable statement of intent (not signed) */
  statement: z.string(),
  /** ed25519 signature (hex) over the canonical {agentId, wallet, chainId, registry} */
  signature: Hex,
});

export type Erc8004Binding = z.infer<typeof Erc8004BindingSchema>;

/** The payload that is actually signed - kept separate from the human `statement` so
 *  the signed bytes are exactly the identity tuple a verifier reconstructs. */
function bindingPayload(b: Pick<Erc8004Binding, "agentId" | "wallet" | "chainId" | "registry">): string {
  return canonicalize({ agentId: b.agentId, wallet: b.wallet, chainId: b.chainId, registry: b.registry });
}

/** The agent signs a link from its agentId to `wallet` on `chainId`. The resulting
 *  binding travels in the open; any counterparty verifies it with the agentId alone. */
export function bindWallet(
  key: AgentKeyPair,
  wallet: string,
  chainId: number,
  registry?: string,
): Erc8004Binding {
  const core = { agentId: key.publicKeyHex, wallet, chainId, registry };
  return {
    ...core,
    statement: `agent ${key.publicKeyHex} controls wallet ${wallet} on chain ${chainId}`,
    signature: signMessage(bindingPayload(core), key),
  };
}

export interface BindingCheck {
  ok: boolean;
  reason?: string;
}

/** Verify the agent->wallet claim: the ed25519 signature must verify against the
 *  binding's own agentId. Pure + offline; proves the agent ASSERTED the link, not
 *  that any chain agrees (see verifyBindingOnchain for that). */
export function verifyWalletBinding(binding: Erc8004Binding): BindingCheck {
  return verifyMessage(bindingPayload(binding), binding.agentId, binding.signature)
    ? { ok: true }
    : { ok: false, reason: "wallet-binding signature mismatch" };
}

/** Resolve a wallet to its on-chain registry entry. The injected seam for the reverse
 *  direction (wallet -> registered agentId). A real implementation is a secp256k1 /
 *  ERC-8004 registry client doing an Ethereum read; it is deliberately not bundled
 *  here so this module stays zero-extra-dependency. Returns null when the wallet has
 *  no entry, or `{ agentId? }` carrying whatever the registry records. */
export type OnchainResolver = (wallet: string) => Promise<{ agentId?: string } | null>;

/** Close the loop: the agent's signed claim AND the on-chain registry must agree.
 *   1. the local ed25519 signature proves the agent claims the wallet, and
 *   2. the injected resolver confirms the wallet points back at the SAME agentId.
 *  A binding that passes (1) but fails (2) is an unconfirmed (or spoofed) claim. */
export async function verifyBindingOnchain(
  binding: Erc8004Binding,
  resolve: OnchainResolver,
): Promise<BindingCheck> {
  const local = verifyWalletBinding(binding);
  if (!local.ok) return local;

  const entry = await resolve(binding.wallet);
  if (!entry) return { ok: false, reason: "wallet has no on-chain registry entry" };
  if (entry.agentId !== binding.agentId) {
    return { ok: false, reason: "on-chain registry binds the wallet to a different agentId" };
  }
  return { ok: true };
}
