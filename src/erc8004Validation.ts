// ERC-8004 Validation Registry client - the positioning upgrade.
//
// ERC-8004 defines a Validation Registry (https://eips.ethereum.org/EIPS/eip-8004,
// reference contracts at github.com/erc-8004/erc-8004-contracts) as the pluggable
// verification socket the spec itself defers to: a validator posts a
// `validationResponse` carrying a `uint8` 0-100 score for an agent's `validationRequest`.
// That is exactly ADP's role - an ADP verifier's verdict IS the off-chain evidence
// behind a `validationResponse`. So ADP is not "filling a hole" in ERC-8004; it plugs
// into a socket ERC-8004 already names. This client reads that socket.
//
// REAL ABI (verbatim from the reference contracts' `abis/ValidationRegistry.json`):
//   validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash)
//   validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag)
//   getValidationStatus(bytes32 requestHash) view
//     returns (address validatorAddress, uint256 agentId, uint8 response, bytes32 responseHash, string tag, uint256 lastUpdate)
//   getSummary(uint256 agentId, address[] validatorAddresses, string tag) view returns (uint64 count, uint8 avgResponse)
//   getAgentValidations(uint256 agentId) view returns (bytes32[] requestHashes)
//   getValidatorRequests(address validatorAddress) view returns (bytes32[] requestHashes)
//   getIdentityRegistry() view returns (address)
//
// READ PATH at minimum (this client). The write path (a validator submitting a
// `validationResponse`) is a state-changing tx that needs a wallet/account - out of scope
// for a zero-key read client; the request SHAPE is modeled here as a typed helper so a
// caller can construct/encode one. viem is an OPTIONAL extra, dynamically imported, the
// same pattern as erc8004Registry.ts.

import { z } from "zod";

// Loaded lazily so the dep stays optional.
type Viem = typeof import("viem");

const INSTALL_HINT =
  "on-chain validation reads need viem. " +
  "Install it: `npm install viem` (an optional extra for the erc8004Validation subpath).";

async function loadViem(): Promise<Viem> {
  try {
    return await import("viem");
  } catch {
    throw new Error(INSTALL_HINT);
  }
}

/** The real ERC-8004 Validation Registry ABI, verbatim from the reference contracts'
 *  `abis/ValidationRegistry.json`. `response` is a uint8 0-100 score throughout. */
export const VALIDATION_REGISTRY_ABI = [
  {
    type: "function",
    name: "validationRequest",
    stateMutability: "nonpayable",
    inputs: [
      { name: "validatorAddress", type: "address" },
      { name: "agentId", type: "uint256" },
      { name: "requestURI", type: "string" },
      { name: "requestHash", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "validationResponse",
    stateMutability: "nonpayable",
    inputs: [
      { name: "requestHash", type: "bytes32" },
      { name: "response", type: "uint8" },
      { name: "responseURI", type: "string" },
      { name: "responseHash", type: "bytes32" },
      { name: "tag", type: "string" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "getValidationStatus",
    stateMutability: "view",
    inputs: [{ name: "requestHash", type: "bytes32" }],
    outputs: [
      { name: "validatorAddress", type: "address" },
      { name: "agentId", type: "uint256" },
      { name: "response", type: "uint8" },
      { name: "responseHash", type: "bytes32" },
      { name: "tag", type: "string" },
      { name: "lastUpdate", type: "uint256" },
    ],
  },
  {
    type: "function",
    name: "getSummary",
    stateMutability: "view",
    inputs: [
      { name: "agentId", type: "uint256" },
      { name: "validatorAddresses", type: "address[]" },
      { name: "tag", type: "string" },
    ],
    outputs: [
      { name: "count", type: "uint64" },
      { name: "avgResponse", type: "uint8" },
    ],
  },
  {
    type: "function",
    name: "getAgentValidations",
    stateMutability: "view",
    inputs: [{ name: "agentId", type: "uint256" }],
    outputs: [{ name: "", type: "bytes32[]" }],
  },
  {
    type: "function",
    name: "getValidatorRequests",
    stateMutability: "view",
    inputs: [{ name: "validatorAddress", type: "address" }],
    outputs: [{ name: "", type: "bytes32[]" }],
  },
  {
    type: "function",
    name: "getIdentityRegistry",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
] as const;

export const ValidationConfigSchema = z.object({
  /** JSON-RPC endpoint. Required unless `transport` is injected (e.g. a test mock). */
  rpcUrl: z.string().url().optional(),
  /** EVM chain id; advisory metadata for the client. */
  chainId: z.number().int().nonnegative().optional(),
  /** the deployed ERC-8004 Validation Registry contract address (0x...). */
  registryAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/, "registry must be a 0x EVM address"),
  /** inject a viem transport INSTEAD of an `rpcUrl`. Typed `unknown` to keep viem off
   *  the core type surface. */
  transport: z.unknown().optional(),
});

export type ValidationConfig = z.input<typeof ValidationConfigSchema>;

/** A single validation record, as `getValidationStatus(requestHash)` returns it. An
 *  unanswered request reads as `response: 0`, `lastUpdate: 0n`. */
export interface ValidationStatus {
  requestHash: string;
  validatorAddress: string | null;
  agentId: bigint;
  /** the uint8 0-100 score; 0 (failed) .. 100 (passed), intermediate allowed. */
  response: number;
  responseHash: string;
  tag: string;
  /** unix seconds of the last update; 0n if the request has no response yet. */
  lastUpdate: bigint;
}

/** Aggregate across an agent's validations, as `getSummary` returns it. */
export interface ValidationSummary {
  count: bigint;
  /** mean uint8 0-100 score across the matched responses. */
  avgResponse: number;
}

/** The fields a validator (e.g. an ADP verifier) puts on-chain to OPEN a validation. The
 *  write itself needs a wallet/account and is out of this read client's scope; this is
 *  the typed shape a caller encodes for `validationRequest`. `requestHash` is the
 *  agreed off-chain handle (the ADP verifier binds its evidence to it). */
export interface ValidationRequestInput {
  validatorAddress: string;
  agentId: bigint;
  requestURI: string;
  requestHash: string;
}

/** A read client over the real ERC-8004 Validation Registry. */
export interface ValidationRegistryClient {
  /** `getValidationStatus(requestHash)` -> the validator, score, tag, and last-update. */
  getValidationStatus(requestHash: string): Promise<ValidationStatus>;
  /** `getSummary(agentId, validatorAddresses, tag)` -> count + mean score. Pass `[]`
   *  for `validatorAddresses` to aggregate across all validators, `""` for any tag. */
  getSummary(
    agentId: bigint,
    validatorAddresses: readonly string[],
    tag: string,
  ): Promise<ValidationSummary>;
  /** `getAgentValidations(agentId)` -> the request hashes recorded for an agent. */
  getAgentValidations(agentId: bigint): Promise<string[]>;
  /** `getValidatorRequests(validatorAddress)` -> the request hashes a validator answered. */
  getValidatorRequests(validatorAddress: string): Promise<string[]>;
  /** `getIdentityRegistry()` -> the Identity Registry this validation registry is bound to. */
  getIdentityRegistry(): Promise<string | null>;
}

function normalizeAddress(raw: unknown): string | null {
  if (typeof raw !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(raw)) return null;
  const lower = raw.toLowerCase();
  return lower === "0x0000000000000000000000000000000000000000" ? null : lower;
}

/** A read client over the real ERC-8004 Validation Registry. Provide either
 *  `config.rpcUrl` or an injected `config.transport`. Throws the install hint if viem is
 *  absent, or a config error if neither is given. */
export function createValidationRegistryClient(
  config: ValidationConfig,
): ValidationRegistryClient {
  const cfg = ValidationConfigSchema.parse(config);
  if (!cfg.rpcUrl && cfg.transport === undefined) {
    throw new Error("ERC-8004 validation client needs either an rpcUrl or an injected transport");
  }
  const address = cfg.registryAddress as `0x${string}`;

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

  async function read(functionName: string, args: readonly unknown[]): Promise<unknown> {
    const c = await viemClient();
    // The const-asserted ABI gives viem per-function typed overloads; a dynamic
    // functionName cannot satisfy them, so the call shape is widened to `never` here.
    return c.readContract({ address, abi: VALIDATION_REGISTRY_ABI, functionName, args } as never);
  }

  return {
    async getValidationStatus(requestHash: string): Promise<ValidationStatus> {
      const r = (await read("getValidationStatus", [
        requestHash as `0x${string}`,
      ])) as readonly [string, bigint, number, string, string, bigint];
      return {
        requestHash,
        validatorAddress: normalizeAddress(r[0]),
        agentId: r[1],
        response: Number(r[2]),
        responseHash: r[3],
        tag: r[4],
        lastUpdate: r[5],
      };
    },
    async getSummary(
      agentId: bigint,
      validatorAddresses: readonly string[],
      tag: string,
    ): Promise<ValidationSummary> {
      const r = (await read("getSummary", [agentId, validatorAddresses, tag])) as readonly [
        bigint,
        number,
      ];
      return { count: r[0], avgResponse: Number(r[1]) };
    },
    async getAgentValidations(agentId: bigint): Promise<string[]> {
      return [...((await read("getAgentValidations", [agentId])) as readonly string[])];
    },
    async getValidatorRequests(validatorAddress: string): Promise<string[]> {
      return [
        ...((await read("getValidatorRequests", [
          validatorAddress as `0x${string}`,
        ])) as readonly string[]),
      ];
    },
    async getIdentityRegistry(): Promise<string | null> {
      return normalizeAddress(await read("getIdentityRegistry", []));
    },
  };
}
