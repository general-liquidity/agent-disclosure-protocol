// ERC-8004 Identity Registry client - the real JSON-RPC reads that close the reverse
// direction against the on-chain registry.
//
// erc8004.ts defines the OnchainResolver seam (wallet -> the agentId the registry
// records) and `verifyBindingOnchain` consumes it; erc8004Onchain.ts supplies the
// secp256k1 wallet-signature half. THIS module implements the registry reads: real EVM
// `eth_call`s into the ERC-8004 Identity Registry over JSON-RPC.
//
// THE REAL ERC-8004 MODEL (https://eips.ethereum.org/EIPS/eip-8004, reference
// contracts at github.com/erc-8004/erc-8004-contracts):
//   - The Identity Registry is an ERC-721. An agent's identifier is a `uint256` agentId
//     (the tokenId), NOT a bytes32 and NOT an ed25519 key.
//   - `getAgentWallet(uint256 agentId) view returns (address)` is the agent's declared
//     operational wallet (set via an EIP-712 / ERC-1271 signed `setAgentWallet`).
//   - `tokenURI(uint256 agentId) view returns (string)` resolves to the off-chain agent
//     registration file (ipfs:// / https:// / data:).
//   - `getMetadata(uint256 agentId, string key) view returns (bytes)` reads arbitrary
//     on-chain metadata entries set via `setMetadata`.
//   - There is NO on-chain `address -> agentId` getter. The EIP expects consumers to
//     index the `Registered(agentId, agentURI, owner)` / ERC-721 `Transfer` events
//     off-chain. So wallet -> agentId resolution needs an injected off-chain index.
//
// HOW ADP BINDS. ADP's agentId is an ed25519 public key, which has no native home in
// the ERC-8004 record. The binding path is therefore: ADP publishes its ed25519 key
// either as an on-chain metadata entry (`getMetadata(agentId, ADP_KEY_METADATA_KEY)`)
// or inside the registration file the `tokenURI` points at. The reverse check then is:
// confirm the registry's `getAgentWallet(agentId)` equals the bound wallet AND the
// registry-published ed25519 key equals the binding's agentId. That is what plugs into
// `verifyBindingOnchain` - no fictional `agentOf(address)->bytes32`.
//
// viem (the EVM client) is NOT a node:crypto primitive, so it is an OPTIONAL extra, the
// same pattern as @noble in erc8004Onchain.ts: the core ADP package stays
// zero-extra-dependency, viem is imported DYNAMICALLY, and a missing install throws a
// clear, actionable error instead of breaking package import. Install it only if you
// resolve bindings against a live chain.

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

/** The real ERC-8004 Identity Registry ABI (read subset), verbatim from the reference
 *  contracts' `abis/IdentityRegistry.json`. agentId is a uint256 tokenId throughout. */
export const IDENTITY_REGISTRY_ABI = [
  {
    type: "function",
    name: "getAgentWallet",
    stateMutability: "view",
    inputs: [{ name: "agentId", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "tokenURI",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "", type: "string" }],
  },
  {
    type: "function",
    name: "getMetadata",
    stateMutability: "view",
    inputs: [
      { name: "agentId", type: "uint256" },
      { name: "metadataKey", type: "string" },
    ],
    outputs: [{ name: "", type: "bytes" }],
  },
  {
    type: "function",
    name: "ownerOf",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "owner", type: "address" }],
  },
] as const;

/** The on-chain metadata key under which an ADP agent publishes its ed25519 agentId.
 *  ERC-8004 leaves metadata keys application-defined; ADP reserves this one. The value
 *  is the raw 32-byte ed25519 key (the on-chain `bytes` returned by `getMetadata`),
 *  hex-encoded here to match ADP's `agentId` form. SPECULATIVE: the exact reserved key
 *  string is an ADP convention, not pinned by the ERC-8004 Draft. */
export const ADP_KEY_METADATA_KEY = "adp.ed25519AgentId";

export const RegistryConfigSchema = z.object({
  /** JSON-RPC endpoint for the chain the registry lives on. Required unless `transport`
   *  is injected (e.g. a mock transport in tests). */
  rpcUrl: z.string().url().optional(),
  /** EVM chain id; advisory metadata for the client (the read does not depend on it). */
  chainId: z.number().int().nonnegative().optional(),
  /** the deployed ERC-8004 Identity Registry contract address (0x...). */
  registryAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/, "registry must be a 0x EVM address"),
  /** the on-chain metadata key the ed25519 agentId is published under. */
  metadataKey: z.string().optional(),
  /** inject a viem transport (e.g. `custom(...)` for tests) INSTEAD of an `rpcUrl`. When
   *  absent, an `http(rpcUrl)` transport is built. Typed `unknown` to keep viem off the
   *  core type surface. */
  transport: z.unknown().optional(),
});

export type RegistryConfig = z.input<typeof RegistryConfigSchema>;

/** The on-chain record ADP reads for an agentId: the declared wallet plus the published
 *  ed25519 key (if any). `agentId` here is the ed25519 key in ADP's hex form, decoded
 *  from the `getMetadata` bytes; `tokenId` is the ERC-8004 uint256. */
export interface AgentRecord {
  tokenId: bigint;
  wallet: string | null;
  agentId: string | null;
}

/** Decode the `getMetadata` bytes (a viem `0x...` hex string) holding the ed25519 key
 *  into ADP's agentId form (raw hex, no 0x prefix). Empty / all-zero bytes -> null. */
function decodePublishedAgentId(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length === 0) return null;
  const hex = raw.startsWith("0x") ? raw.slice(2) : raw;
  if (hex.length === 0 || /^0+$/.test(hex)) return null;
  return hex.toLowerCase();
}

function normalizeAddress(raw: unknown): string | null {
  if (typeof raw !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(raw)) return null;
  const lower = raw.toLowerCase();
  return lower === "0x0000000000000000000000000000000000000000" ? null : lower;
}

/** A reader bound to one Identity Registry: typed reads against the real ABI, keyed by
 *  the uint256 agentId. Build it with `createIdentityRegistryClient`. */
export interface IdentityRegistryClient {
  /** `getAgentWallet(agentId)` -> the declared wallet (null if unset / zero address). */
  getAgentWallet(agentId: bigint): Promise<string | null>;
  /** `tokenURI(agentId)` -> the registration-file URI. */
  getAgentURI(agentId: bigint): Promise<string>;
  /** `getMetadata(agentId, ADP_KEY_METADATA_KEY)` decoded to ADP's ed25519 agentId. */
  getPublishedAgentId(agentId: bigint): Promise<string | null>;
  /** wallet + published ed25519 key for an agentId, in one shape. */
  getRecord(agentId: bigint): Promise<AgentRecord>;
}

function buildClient(config: RegistryConfig) {
  const cfg = RegistryConfigSchema.parse(config);
  if (!cfg.rpcUrl && cfg.transport === undefined) {
    throw new Error("ERC-8004 registry client needs either an rpcUrl or an injected transport");
  }
  const address = cfg.registryAddress as `0x${string}`;
  const metadataKey = cfg.metadataKey ?? ADP_KEY_METADATA_KEY;

  let clientPromise: Promise<import("viem").PublicClient> | undefined;
  async function viemClient(): Promise<import("viem").PublicClient> {
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
  return { address, metadataKey, viemClient };
}

/** A typed client over the real ERC-8004 Identity Registry. Provide either
 *  `config.rpcUrl` (an `http` transport is built) or `config.transport` (injected, e.g.
 *  a viem `custom` mock for deterministic tests). Throws the install hint if viem is
 *  absent, or a config error if neither is given. */
export function createIdentityRegistryClient(config: RegistryConfig): IdentityRegistryClient {
  const { address, metadataKey, viemClient } = buildClient(config);

  async function read(functionName: string, args: readonly unknown[]): Promise<unknown> {
    const c = await viemClient();
    // The const-asserted ABI gives viem per-function typed overloads; a dynamic
    // functionName cannot satisfy them, so the call shape is widened to `never` here.
    // The runtime args match the ABI (asserted by the per-method callers below).
    return c.readContract({ address, abi: IDENTITY_REGISTRY_ABI, functionName, args } as never);
  }

  const getAgentWallet = async (agentId: bigint) =>
    normalizeAddress(await read("getAgentWallet", [agentId]));
  const getAgentURI = async (agentId: bigint) => (await read("tokenURI", [agentId])) as string;
  const getPublishedAgentId = async (agentId: bigint) =>
    decodePublishedAgentId(await read("getMetadata", [agentId, metadataKey]));

  return {
    getAgentWallet,
    getAgentURI,
    getPublishedAgentId,
    async getRecord(agentId: bigint): Promise<AgentRecord> {
      const [wallet, agentIdHex] = await Promise.all([
        getAgentWallet(agentId),
        getPublishedAgentId(agentId),
      ]);
      return { tokenId: agentId, wallet, agentId: agentIdHex };
    },
  };
}

/** Off-chain index from a wallet to the agentId(s) that declare it. ERC-8004 has no
 *  on-chain `address -> agentId` getter (the EIP indexes `Registered` / ERC-721
 *  `Transfer` events off-chain), so this seam is injected by the caller - e.g. a subgraph
 *  query or an event-log scan. Returns the candidate tokenId, or null if unknown. */
export type WalletToAgentIdIndex = (wallet: string) => Promise<bigint | null>;

/** Build the OnchainResolver `verifyBindingOnchain` consumes, around the REAL registry.
 *  Given a wallet, the resolver:
 *    1. asks the injected `index` for the candidate agentId (uint256 tokenId),
 *    2. confirms the registry's `getAgentWallet(agentId)` actually equals that wallet
 *       (defends a stale / spoofed index entry), and
 *    3. returns the registry-published ed25519 agentId for that record.
 *  `verifyBindingOnchain` then equates that against the binding's ed25519 agentId. A
 *  wallet the index does not know, or whose on-chain wallet no longer matches, resolves
 *  to null (no entry). */
export function createRegistryResolver(
  config: RegistryConfig,
  index: WalletToAgentIdIndex,
): OnchainResolver {
  const client = createIdentityRegistryClient(config);
  return async (wallet: string) => {
    const tokenId = await index(wallet);
    if (tokenId === null) return null;
    const onchainWallet = await client.getAgentWallet(tokenId);
    if (onchainWallet === null || onchainWallet !== wallet.toLowerCase()) return null;
    const agentId = await client.getPublishedAgentId(tokenId);
    return agentId ? { agentId } : null;
  };
}
