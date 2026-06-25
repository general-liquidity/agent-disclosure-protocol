// Sign-In-With-Agent (SIWA) bridge - a SIWE-style login message anchored to an
// ERC-8004 agent identity.
//
// ADP already owns the agent<->wallet<->ERC-8004 binding: `erc8004.ts` (`bindWallet`)
// is the agent's signed agentId->wallet claim, `erc8004Onchain.ts` recovers the wallet
// address from an EIP-191 personal-sign signature, and `erc8004Registry.ts` reads
// `ownerOf` against the on-chain Identity Registry. SIWA (Sign-In-With-Agent) is the
// SIWE (EIP-4361) message shape whose subject is an AGENT account: its
// `(address, agentRegistry, agentId)` triple is exactly an ERC-8004 binding. So ADP can
// MINT a SIWA message describing a disclosed agent, and VERIFY one the wallet signed -
// reusing the same secp256k1 EIP-191 recovery, with an injected `ownerOf` resolver
// closing the registry-attested tier.
//
// Like the rest of the on-chain surface, the secp256k1 recovery is an OPTIONAL extra
// (@noble, imported lazily inside `recoverWalletAddress`); minting + parsing are pure.
// The registry tier is an injected seam (`resolveRegistry`) - ADP does not bundle a
// chain client.

import { recoverWalletAddress } from "./erc8004Onchain.ts";
import type { Erc8004Binding } from "./erc8004.ts";
import type { SignedDisclosure } from "./schema.ts";

/** A SIWA (Sign-In-With-Agent) message: SIWE/EIP-4361 fields whose subject is an agent
 *  account. `(address, agentRegistry, agentId)` is an ERC-8004 binding - the wallet, the
 *  CAIP-10 registry, and the ERC-721 tokenId the registry mints for the agent. */
export interface SiwaMessage {
  /** the relying party requesting sign-in (e.g. "example.com") */
  domain: string;
  /** the agent's operational wallet (an EVM 0x address; compared case-insensitively) */
  address: string;
  /** the relying-party URI the sign-in authorizes */
  uri: string;
  version: "1";
  /** the ERC-8004 agent identifier (the ERC-721 uint256 tokenId, as a decimal string) */
  agentId: string;
  /** the registry the agentId lives in, CAIP-10: `eip155:<chainId>:<registryAddress>` */
  agentRegistry: string;
  /** EVM chain id the wallet + registry live on */
  chainId: number;
  /** anti-replay nonce, >= 8 alphanumeric chars (SIWE rule) */
  nonce: string;
  /** RFC3339 issuance time */
  issuedAt: string;
  /** optional RFC3339 expiry; a verifier rejects a message past it */
  expirationTime?: string;
  /** optional RFC3339 not-before; a verifier rejects a message before it */
  notBefore?: string;
  /** optional opaque request correlation id */
  requestId?: string;
  /** optional human-readable statement shown to the operator */
  statement?: string;
}

const CAIP10_REGISTRY = /^eip155:\d+:0x[0-9a-fA-F]{40}$/;
const NONCE = /^[a-zA-Z0-9]{8,}$/;

/** CAIP-10 account id for an ERC-8004 registry: `eip155:<chainId>:<registry>`. */
export function agentRegistryCaip10(chainId: number, registry: string): string {
  return `eip155:${chainId}:${registry}`;
}

/** Render a SIWA message to the exact EIP-4361-style text the wallet signs (EIP-191
 *  personal_sign). Optional lines (`Expiration Time`, `Not Before`, `Request ID`) are
 *  emitted only when present, in that order, after `Issued At`. */
export function formatSiwaMessage(m: SiwaMessage): string {
  const lines = [
    `${m.domain} wants you to sign in with your Agent account:`,
    m.address,
    "",
    m.statement ?? "",
    "",
    `URI: ${m.uri}`,
    `Version: ${m.version}`,
    `Agent ID: ${m.agentId}`,
    `Agent Registry: ${m.agentRegistry}`,
    `Chain ID: ${m.chainId}`,
    `Nonce: ${m.nonce}`,
    `Issued At: ${m.issuedAt}`,
  ];
  if (m.expirationTime !== undefined) lines.push(`Expiration Time: ${m.expirationTime}`);
  if (m.notBefore !== undefined) lines.push(`Not Before: ${m.notBefore}`);
  if (m.requestId !== undefined) lines.push(`Request ID: ${m.requestId}`);
  return lines.join("\n");
}

function requireLine(map: Map<string, string>, key: string): string {
  const v = map.get(key);
  if (v === undefined) throw new Error(`SIWA message missing "${key}" line`);
  return v;
}

/** Parse SIWA message text back to its structured form (the inverse of
 *  `formatSiwaMessage`). Throws on a malformed header, a missing required line, or a
 *  bad `version` / `chainId`. The statement is the text between the address and the
 *  `URI:` line (empty string when absent). */
export function parseSiwaMessage(text: string): SiwaMessage {
  const lines = text.split("\n");
  const header = lines[0] ?? "";
  const suffix = " wants you to sign in with your Agent account:";
  if (!header.endsWith(suffix)) throw new Error("SIWA message has a malformed header line");
  const domain = header.slice(0, header.length - suffix.length);
  const address = lines[1] ?? "";

  // The "URI:" line is the boundary between the optional statement block and the fields.
  const uriIdx = lines.findIndex((l) => l.startsWith("URI: "));
  if (uriIdx < 0) throw new Error('SIWA message missing "URI:" line');
  // statement sits between the blank line after the address (index 3 onward) and the
  // blank line before "URI:". An absent statement collapses to "".
  const statement = lines.slice(3, uriIdx - 1).join("\n");

  const fields = new Map<string, string>();
  for (const line of lines.slice(uriIdx)) {
    const sep = line.indexOf(": ");
    if (sep > 0) fields.set(line.slice(0, sep), line.slice(sep + 2));
  }

  const version = requireLine(fields, "Version");
  if (version !== "1") throw new Error('SIWA "Version" must be "1"');
  const chainId = Number.parseInt(requireLine(fields, "Chain ID"), 10);
  if (!Number.isInteger(chainId)) throw new Error('SIWA "Chain ID" must be an integer');

  const msg: SiwaMessage = {
    domain,
    address,
    uri: requireLine(fields, "URI"),
    version: "1",
    agentId: requireLine(fields, "Agent ID"),
    agentRegistry: requireLine(fields, "Agent Registry"),
    chainId,
    nonce: requireLine(fields, "Nonce"),
    issuedAt: requireLine(fields, "Issued At"),
  };
  if (statement !== "") msg.statement = statement;
  const exp = fields.get("Expiration Time");
  if (exp !== undefined) msg.expirationTime = exp;
  const nbf = fields.get("Not Before");
  if (nbf !== undefined) msg.notBefore = nbf;
  const rid = fields.get("Request ID");
  if (rid !== undefined) msg.requestId = rid;
  return msg;
}

/** What `disclosureToSiwaMessage` needs to describe the disclosed agent as a SIWA
 *  login. The wallet / registry / tokenId are the ERC-8004 binding fields; the rest is
 *  the relying-party request (domain, uri, nonce, issuedAt). */
export interface DisclosureToSiwaOptions {
  domain: string;
  uri: string;
  nonce: string;
  issuedAt: string;
  chainId: number;
  /** the ERC-8004 Identity Registry contract address (0x...) */
  registry: string;
  /** the agent's operational wallet (0x...) */
  walletAddress: string;
  /** the ERC-721 tokenId the registry minted for this agent (decimal string) */
  agentTokenId: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  statement?: string;
}

/** Mint a SIWA message describing a disclosed agent. The wallet/registry/tokenId come
 *  from the agent's ERC-8004 binding (carried in `opts`); the disclosure is the trust
 *  context the login authorizes. The result is the structured message - `formatSiwaMessage`
 *  renders the bytes the wallet then signs (EIP-191). */
export function disclosureToSiwaMessage(
  _signed: SignedDisclosure,
  opts: DisclosureToSiwaOptions,
): SiwaMessage {
  const msg: SiwaMessage = {
    domain: opts.domain,
    address: opts.walletAddress,
    uri: opts.uri,
    version: "1",
    agentId: opts.agentTokenId,
    agentRegistry: agentRegistryCaip10(opts.chainId, opts.registry),
    chainId: opts.chainId,
    nonce: opts.nonce,
    issuedAt: opts.issuedAt,
  };
  if (opts.expirationTime !== undefined) msg.expirationTime = opts.expirationTime;
  if (opts.notBefore !== undefined) msg.notBefore = opts.notBefore;
  if (opts.requestId !== undefined) msg.requestId = opts.requestId;
  if (opts.statement !== undefined) msg.statement = opts.statement;
  return msg;
}

/** The attestation tier a verified SIWA message reaches:
 *  - `none`: no valid signature recovered
 *  - `signed`: the recovered signer == the message `address` (wallet self-proof)
 *  - `registry_attested`: additionally, the injected `ownerOf` resolver confirms the
 *    registry binds the agentId to that same wallet (the ERC-8004 record agrees). */
export type SiwaAttestation = "none" | "signed" | "registry_attested";

/** Resolve the on-chain owner an ERC-8004 registry records for an agentId - the
 *  `ownerOf(tokenId)` read. Injected (ADP bundles no chain client); returns the owner
 *  address, or null when the agentId is unknown. */
export type SiwaRegistryResolver = (
  agentRegistry: string,
  agentId: string,
) => Promise<{ owner: string } | null>;

export interface VerifySiwaOptions {
  /** the relying party that must match the message `domain` */
  expectedDomain: string;
  /** validate the nonce (e.g. a one-time challenge the relying party issued) */
  nonceValid: (nonce: string) => boolean;
  /** clock for expiry / not-before checks; defaults to `new Date()` */
  now?: Date;
  /** optional `ownerOf` resolver; when supplied and `owner == signer`, the result is
   *  `registry_attested` instead of `signed` */
  resolveRegistry?: SiwaRegistryResolver;
}

export interface SiwaVerification {
  ok: boolean;
  /** the recovered signer address (lowercased), when recovery succeeded */
  signer?: string;
  attestation: SiwaAttestation;
  reason?: string;
}

function nonceValidShape(nonce: string): boolean {
  return NONCE.test(nonce);
}

/** Verify a signed SIWA message:
 *   1. structural checks - domain matches, nonce is well-formed AND accepted by
 *      `opts.nonceValid`, registry is a CAIP-10 eip155 id, issuedAt/expiry/not-before
 *      bound the validity window;
 *   2. EIP-191 recover the signer from `signature` (reusing `erc8004Onchain` recovery)
 *      and require it equals the message `address` -> `signed`;
 *   3. if `resolveRegistry` is supplied, require the registry's `ownerOf(agentId)` to
 *      equal the signer -> `registry_attested`.
 *  Any failure short-circuits to `{ ok:false, attestation:"none"|... , reason }`. */
export async function verifySiwa(
  msg: SiwaMessage,
  signature: string,
  opts: VerifySiwaOptions,
): Promise<SiwaVerification> {
  if (msg.version !== "1")
    return { ok: false, attestation: "none", reason: "SIWA version must be 1" };
  if (msg.domain !== opts.expectedDomain) {
    return {
      ok: false,
      attestation: "none",
      reason: "SIWA domain does not match the expected domain",
    };
  }
  if (!nonceValidShape(msg.nonce)) {
    return { ok: false, attestation: "none", reason: "SIWA nonce must be >= 8 alphanumeric chars" };
  }
  if (!opts.nonceValid(msg.nonce)) {
    return { ok: false, attestation: "none", reason: "SIWA nonce rejected by the verifier" };
  }
  if (!CAIP10_REGISTRY.test(msg.agentRegistry)) {
    return {
      ok: false,
      attestation: "none",
      reason: "SIWA agentRegistry must be a CAIP-10 eip155 id",
    };
  }

  const now = opts.now ?? new Date();
  if (msg.expirationTime !== undefined && now.getTime() >= Date.parse(msg.expirationTime)) {
    return { ok: false, attestation: "none", reason: "SIWA message has expired" };
  }
  if (msg.notBefore !== undefined && now.getTime() < Date.parse(msg.notBefore)) {
    return { ok: false, attestation: "none", reason: "SIWA message is not yet valid (notBefore)" };
  }

  let signer: string;
  try {
    signer = (await recoverWalletAddress(formatSiwaMessage(msg), signature)).toLowerCase();
  } catch (err) {
    return {
      ok: false,
      attestation: "none",
      reason: err instanceof Error ? err.message : "signature recovery failed",
    };
  }
  if (signer !== msg.address.toLowerCase()) {
    return {
      ok: false,
      signer,
      attestation: "none",
      reason: "recovered signer does not match the SIWA address",
    };
  }

  if (opts.resolveRegistry) {
    const entry = await opts.resolveRegistry(msg.agentRegistry, msg.agentId);
    if (entry && entry.owner.toLowerCase() === signer) {
      return { ok: true, signer, attestation: "registry_attested" };
    }
    if (entry) {
      return {
        ok: false,
        signer,
        attestation: "signed",
        reason: "registry owner does not match the SIWA signer",
      };
    }
    // No registry entry: the signature still proves wallet control -> `signed`.
  }

  return { ok: true, signer, attestation: "signed" };
}

/** What the SIWA message must agree with on the disclosure's ERC-8004 binding: the
 *  wallet address and the registry tokenId. ADP does not (yet) carry a binding inside
 *  the disclosure document, so the expected binding is supplied explicitly - either as
 *  an `Erc8004Binding` plus its tokenId, or as bare expected values. */
export interface VerifySiwaAgainstDisclosureOptions extends VerifySiwaOptions {
  /** the ERC-8004 binding the disclosure's agent published (its `wallet` is checked) */
  binding?: Pick<Erc8004Binding, "wallet">;
  /** the wallet the SIWA `address` must equal (defaults to `binding.wallet`) */
  expectedWallet?: string;
  /** the ERC-721 tokenId the SIWA `agentId` must equal */
  expectedAgentTokenId: string;
}

/** Verify a SIWA message AND cross-check that it describes the SAME agent as `signed`:
 *  the SIWA `address` must equal the disclosure's bound wallet and the SIWA `agentId`
 *  must equal the disclosure agent's registry tokenId. So a counterparty knows the SIWA
 *  login and the disclosure are one agent, not two stitched together. */
export async function verifySiwaAgainstDisclosure(
  msg: SiwaMessage,
  signature: string,
  _signed: SignedDisclosure,
  opts: VerifySiwaAgainstDisclosureOptions,
): Promise<SiwaVerification> {
  const expectedWallet = opts.expectedWallet ?? opts.binding?.wallet;
  if (expectedWallet === undefined) {
    return {
      ok: false,
      attestation: "none",
      reason: "verifySiwaAgainstDisclosure needs an expected wallet (binding or expectedWallet)",
    };
  }
  if (msg.address.toLowerCase() !== expectedWallet.toLowerCase()) {
    return {
      ok: false,
      attestation: "none",
      reason: "SIWA address does not match the disclosure binding wallet",
    };
  }
  if (msg.agentId !== opts.expectedAgentTokenId) {
    return {
      ok: false,
      attestation: "none",
      reason: "SIWA agentId does not match the disclosure binding tokenId",
    };
  }
  return verifySiwa(msg, signature, opts);
}
