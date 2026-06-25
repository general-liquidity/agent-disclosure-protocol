// World Agent (worldcoin/agentkit) attestation scheme - "this agent is backed by a real,
// World ID-verified human" as an operator-attestation.
//
// agentkit (https://github.com/worldcoin/agentkit) gives an autonomous agent a wallet that is
// registered, via a World ID proof, in an on-chain AgentBook that maps the agent wallet to the
// nullifier of the unique human who registered it. Accountability flow: a server challenges the
// agent to sign a CAIP-122 / SIWE (EIP-4361) message; the verifier recovers the signer
// (EIP-191 / personal_sign) and requires it to equal the claimed agent wallet; then it looks the
// wallet up in AgentBook (`lookupHuman(address) -> uint256`, 0 ⇒ unregistered) to confirm the
// agent is human-backed and to surface the human nullifier. That is agent↔human accountability -
// ADP's exact thesis.
//
// Recovering the signer is dep-free in spirit but needs secp256k1 + keccak (an OPTIONAL extra,
// reused from `erc8004Onchain.ts`'s `recoverWalletAddress`). The AgentBook `eth_call`
// (`lookupHuman`) is an on-chain read - viem/RPC, NOT something ADP bundles. So this module does
// LIGHT recognition: STRUCTURAL validation of the CAIP-122 message + address/signature shape,
// EIP-191 signer recovery, and an INJECTED `AgentBookResolver` seam for the on-chain lookup,
// exactly how `worldid.ts` / `self.ts` / `erc8004Onchain.ts` treat their heavy halves. The
// disclosure schema's attestation `scheme` already permits reverse-domain custom values, so World
// Agent is recognized at the module level - the frozen enum is untouched.
//
// Grounded against the real repo (worldcoin/agentkit, core/src): the payload is the agentkit
// SIWE payload (`domain`, `address`, `statement?`, `uri`, `version`, `chainId` [CAIP-2],
// `nonce`, `issuedAt`, `signature`, …); the EVM message is a standard SIWE / EIP-4361 string
// (`formatSIWEMessage` → viem `createSiweMessage`); and AgentBook lives at
// `0xA23aB2712eA7BBa896930544C7d6636a96b944dA` on World Chain (`lookupHuman(address)`).

import type { OperatorAttestation } from "./self.ts";
import { recoverWalletAddress } from "./erc8004Onchain.ts";

/** The module-level recognition name for the World Agent scheme - the discriminant on a
 *  `WorldAgentAttestation` and the human-readable label. NOT the value written into a
 *  disclosure's `operator.attestation.scheme` (that field's open arm requires a reverse-domain
 *  id; see `WORLDAGENT_ATTESTATION_SCHEME`). The frozen schema enum is untouched - World Agent is
 *  recognized here, not added to the core grammar. */
export const WORLDAGENT_SCHEME = "WorldAgent";

/** The reverse-domain id World Agent maps to in a disclosure's `operator.attestation.scheme`
 *  (world.org, agent sub-namespace). The schema's attestation `scheme` accepts a known enum value
 *  OR a reverse-domain custom id; "WorldAgent" is not in the frozen enum, so the disclosure-field
 *  form is this namespaced id - a vendor-namespace publication, not a core enum edit. (Sibling of
 *  World ID's `org.world`; the `.agent` leaf distinguishes the human-backed-agent scheme.) */
export const WORLDAGENT_ATTESTATION_SCHEME = "org.world.agent";

/** AgentBook deployment from worldcoin/agentkit (`AGENT_BOOK_ADDRESS`, World Chain). Surfaced so a
 *  consumer wiring the `AgentBookResolver` can default to the canonical registry. */
export const AGENT_BOOK_ADDRESS = "0xA23aB2712eA7BBa896930544C7d6636a96b944dA";

/** World Chain mainnet chainId - where AgentBook is deployed. CAIP-2: `eip155:480`. */
export const WORLDCHAIN_ID = 480;

/** A World Agent attestation: an agent wallet (`address`) that signed a CAIP-122 / SIWE challenge
 *  (`message`) with `signature` (EIP-191 / personal_sign). This is the agentkit SIWE payload's
 *  verification surface - the signed message string, the claimed signer, and the signature -
 *  reduced to what ADP recovers and resolves. `chainId` is the optional CAIP-2 id the challenge
 *  was scoped to (e.g. `eip155:480`). */
export interface WorldAgentAttestation {
  scheme: "WorldAgent";
  /** the agent wallet that signed the challenge (0x + 40 hex) */
  address: string;
  /** the CAIP-122 / SIWE (EIP-4361) message the agent signed - travels in the clear */
  message: string;
  /** the EIP-191 / personal_sign signature over `message` (65-byte r||s||v hex) */
  signature: string;
  /** the CAIP-2 chain id the challenge was scoped to (e.g. "eip155:480" for World Chain) */
  chainId?: string;
}

/** The AgentBook on-chain lookup, INJECTED. A consumer wires a viem/ethers `eth_call` into
 *  `lookupHuman(address) -> uint256` against the AgentBook deployment (World Chain). Returns
 *  `{ registered, humanNullifier? }` - `registered: false` (or a null return) means the wallet is
 *  not in the book (the agent is not human-backed); `humanNullifier` is the registering human's
 *  nullifier (the on-chain `humanId`, hex). ADP bundles no implementation - the consumer wires it. */
export type AgentBookResolver = (
  address: string,
  chainId?: string,
) => Promise<{ registered: boolean; humanNullifier?: string } | null>;

export interface VerifyWorldAgentOptions {
  resolver?: AgentBookResolver;
}

export interface WorldAgentVerification {
  /** the structural shape is well-formed */
  structural: boolean;
  /** the signature recovered to the claimed agent wallet (EIP-191 round-trip held) */
  valid: boolean;
  /** the recovered/claimed agent wallet, when the signature recovered */
  address?: string;
  /** the agent is registered in AgentBook against a real human (only an injected resolver can
   *  assert this; false without one - structural + signature only) */
  humanBacked: boolean;
  /** the registering human's nullifier (from AgentBook, when human-backed) */
  nullifier?: string;
  reason?: string;
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;

/** STRUCTURAL validation: the right scheme, a 0x+40-hex agent `address`, a 65-byte (r||s||v) hex
 *  `signature`, and a non-empty `message` (the CAIP-122 / SIWE challenge). This is shape-only - it
 *  does NOT recover the signer (that is `verifyWorldAgent`) or hit AgentBook (the injected
 *  resolver). */
export function validateWorldAgentStructural(att: WorldAgentAttestation): boolean {
  if (att.scheme !== WORLDAGENT_SCHEME) return false;
  if (typeof att.address !== "string" || !ADDRESS.test(att.address)) return false;
  if (typeof att.signature !== "string" || !SIGNATURE.test(att.signature)) return false;
  if (typeof att.message !== "string" || att.message.length === 0) return false;
  return true;
}

/** Verify a World Agent attestation.
 *
 *  STRUCTURAL (always): the shape is well-formed (`validateWorldAgentStructural`).
 *
 *  SIGNATURE (always, dep-permitting): EIP-191-recover the signer from `signature` over `message`
 *  (reusing `recoverWalletAddress`) and require it to equal the claimed `address`. A malformed
 *  signature / missing @noble install / signer-mismatch surfaces as `{ valid: false, reason }` -
 *  it does NOT throw.
 *
 *  HUMAN-BACKED (opt-in): when `opts.resolver` is supplied (the consumer wiring the AgentBook
 *  `lookupHuman` eth_call), a `registered: true` result sets `humanBacked: true` and surfaces the
 *  registering human's nullifier. WITHOUT a resolver the agent's human backing is unverifiable
 *  on-chain, so `humanBacked: false` - the signature can still be valid (the agent controls the
 *  wallet), it is just not confirmed registered. Never throws on a missing resolver. */
export async function verifyWorldAgent(
  att: WorldAgentAttestation,
  opts: VerifyWorldAgentOptions = {},
): Promise<WorldAgentVerification> {
  if (!validateWorldAgentStructural(att)) {
    return {
      structural: false,
      valid: false,
      humanBacked: false,
      reason: "World Agent attestation is malformed",
    };
  }

  let recovered: string;
  try {
    recovered = await recoverWalletAddress(att.message, att.signature);
  } catch (err) {
    return {
      structural: true,
      valid: false,
      humanBacked: false,
      reason: err instanceof Error ? err.message : "signature recovery failed",
    };
  }
  if (recovered.toLowerCase() !== att.address.toLowerCase()) {
    return {
      structural: true,
      valid: false,
      humanBacked: false,
      reason: "recovered signer does not match the claimed agent wallet",
    };
  }

  const base: WorldAgentVerification = {
    structural: true,
    valid: true,
    address: recovered,
    humanBacked: false,
  };

  if (opts.resolver === undefined) {
    // No resolver: the agent controls the wallet (signature valid), but its registration against a
    // real human is an on-chain read we cannot do dep-free. Representable, not an error.
    return {
      ...base,
      reason: "World Agent human-backing needs an injected AgentBook resolver (on-chain lookup)",
    };
  }

  const lookup = await opts.resolver(recovered, att.chainId);
  if (lookup === null || !lookup.registered) {
    return {
      ...base,
      reason: "agent wallet is not registered in AgentBook (not human-backed)",
    };
  }

  const out: WorldAgentVerification = { ...base, humanBacked: true };
  if (lookup.humanNullifier !== undefined) out.nullifier = lookup.humanNullifier;
  return out;
}

/** Map a verified World Agent attestation into ADP's `operator.attestation` field. The scheme is
 *  the reverse-domain `WORLDAGENT_ATTESTATION_SCHEME` (the schema enum is frozen). An agent the
 *  AgentBook resolver confirms is human-backed is `registry_attested` (a real human is recorded
 *  on-chain behind it); a wallet-controlled-but-unbacked agent (signature valid, no registration
 *  confirmed) is `signed`; a signature that did not recover to the claimed wallet is `none`. The
 *  human nullifier (when present) is recorded as `evidence`. */
export function worldAgentToOperatorAttestation(
  _att: WorldAgentAttestation,
  result: WorldAgentVerification,
): OperatorAttestation {
  if (!result.valid) return { scheme: WORLDAGENT_ATTESTATION_SCHEME, level: "none" };
  const level = result.humanBacked ? "registry_attested" : "signed";
  const out: OperatorAttestation = { scheme: WORLDAGENT_ATTESTATION_SCHEME, level };
  if (result.nullifier !== undefined) out.evidence = `worldagent:human:${result.nullifier}`;
  return out;
}
