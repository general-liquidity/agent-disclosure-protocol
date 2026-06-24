// ERC-8004 registry client - the JSON-RPC read that closes the reverse direction.
//
// erc8004.ts defines the OnchainResolver seam (wallet -> the agentId the registry
// records) and `verifyBindingOnchain` consumes it; erc8004Onchain.ts supplies the
// secp256k1 wallet-signature half and `onchainResolverFromRegistry`, an adapter for a
// registry read fn it does NOT itself implement. THIS module implements that read: a
// real EVM `eth_call` into an ERC-8004 identity registry over JSON-RPC, decoded into
// the resolver contract. With it, `verifyBindingOnchain` confirms the on-chain registry
// actually points the wallet back at the same agentId - no longer a fake.
//
// viem (the EVM client) is NOT a node:crypto primitive, so it is an OPTIONAL extra,
// the same pattern as @noble in erc8004Onchain.ts: the core ADP package stays
// zero-extra-dependency, viem is imported DYNAMICALLY, and a missing install throws a
// clear, actionable error instead of breaking package import. Install it only if you
// resolve bindings against a live chain.
//
// ABI SHAPE (documented, not a hardcoded mainnet deployment). The exact ERC-8004
// registry ABI and its deployed address are network-specific. This client targets a
// minimal, documented shape:
//
//     function agentOf(address wallet) view returns (bytes32 agentId)
//
// The returned bytes32 IS the agent's ed25519 public key (ADP agentIds are 32-byte
// ed25519 keys, which fit a bytes32 exactly), so the decode is a direct hex compare
// against `Erc8004Binding.agentId`. A registry that records the agentId as a string
// instead can set `functionName` + a custom ABI via config; the all-zero bytes32 (an
// unregistered wallet) maps to null. This is a working client against a documented ABI,
// NOT a claim about any specific mainnet contract.

import { z } from "zod";
import type { OnchainResolver } from "./erc8004.ts";

// Loaded lazily so the dep stays optional. We only touch a handful of viem exports.
type Viem = typeof import("viem");

const INSTALL_HINT =
  "on-chain registry resolution needs viem. " +
  "Install it: `npm install viem` (an optional extra for the erc8004Registry subpath).";

async function loadViem(): Promise<Viem> {
  try {
    return await import("viem");
  } catch {
    throw new Error(INSTALL_HINT);
  }
}

/** The documented default ABI: `agentOf(address) view returns (bytes32)`. The bytes32
 *  return is interpreted as the raw 32-byte ed25519 agentId. Override `registryAbi` +
 *  `functionName` in the config for a registry with a different shape (e.g. a `string`
 *  return). */
export const DEFAULT_REGISTRY_ABI = [
  {
    type: "function",
    name: "agentOf",
    stateMutability: "view",
    inputs: [{ name: "wallet", type: "address" }],
    outputs: [{ name: "agentId", type: "bytes32" }],
  },
] as const;

const DEFAULT_FUNCTION_NAME = "agentOf";

export const RegistryConfigSchema = z.object({
  /** JSON-RPC endpoint for the chain the registry lives on. Required unless `transport`
   *  is injected (e.g. a mock transport in tests). */
  rpcUrl: z.string().url().optional(),
  /** EVM chain id; advisory metadata for the client (the read does not depend on it). */
  chainId: z.number().int().nonnegative().optional(),
  /** the deployed ERC-8004 registry contract address (0x...). */
  registryAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/, "registry must be a 0x EVM address"),
  /** the registry read function name; defaults to the documented `agentOf`. */
  functionName: z.string().optional(),
  /** an ABI override for a non-default registry shape. Passed straight to viem. */
  registryAbi: z.unknown().optional(),
  /** inject a viem transport (e.g. `custom(...)` for tests) INSTEAD of an `rpcUrl`. When
   *  absent, an `http(rpcUrl)` transport is built. Typed `unknown` to keep viem off the
   *  core type surface. */
  transport: z.unknown().optional(),
});

export type RegistryConfig = z.input<typeof RegistryConfigSchema>;

/** Normalize a registry return value to the agentId hex ADP compares against. The
 *  default ABI returns a bytes32 like `0x00..2a`; ADP `agentId`s are raw hex with no
 *  `0x` prefix (per the `Hex` schema in erc8004.ts), so strip it. An all-zero result is
 *  an unregistered wallet -> null. A `string` return passes through unchanged (empty
 *  string -> null). */
function decodeAgentId(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length === 0) return null;
  const hex = raw.startsWith("0x") ? raw.slice(2) : raw;
  // All-zero bytes32 (or empty hex) == no registry entry.
  if (hex.length > 0 && /^0+$/.test(hex)) return null;
  if (raw.startsWith("0x")) return hex;
  return raw;
}

/** Build an OnchainResolver that does a live `eth_call` into the ERC-8004 registry to
 *  look up the agentId bound to a wallet, plugging directly into `verifyBindingOnchain`
 *  from erc8004.ts. Provide either `config.rpcUrl` (an `http` transport is built) or
 *  `config.transport` (injected, e.g. a viem `custom` mock for deterministic tests).
 *  Returns `{ agentId }` for a registered wallet, or null for an unregistered one (the
 *  all-zero bytes32). Throws the install hint if viem is absent, or a config error if
 *  neither `rpcUrl` nor `transport` is given. */
export function createRegistryResolver(config: RegistryConfig): OnchainResolver {
  const cfg = RegistryConfigSchema.parse(config);
  if (!cfg.rpcUrl && cfg.transport === undefined) {
    throw new Error("createRegistryResolver needs either an rpcUrl or an injected transport");
  }

  const abi = (cfg.registryAbi ?? DEFAULT_REGISTRY_ABI) as never;
  const functionName = cfg.functionName ?? DEFAULT_FUNCTION_NAME;
  const address = cfg.registryAddress as `0x${string}`;

  // The client is built once (lazily) and reused across lookups.
  let clientPromise: Promise<import("viem").PublicClient> | undefined;
  async function client(): Promise<import("viem").PublicClient> {
    if (!clientPromise) {
      clientPromise = (async () => {
        const viem = await loadViem();
        const transport =
          cfg.transport !== undefined
            ? (cfg.transport as import("viem").Transport)
            : viem.http(cfg.rpcUrl);
        return viem.createPublicClient({ transport });
      })();
    }
    return clientPromise;
  }

  return async (wallet: string) => {
    const c = await client();
    const result = await c.readContract({
      address,
      abi,
      functionName,
      args: [wallet as `0x${string}`],
    });
    const agentId = decodeAgentId(result);
    return agentId ? { agentId } : null;
  };
}
