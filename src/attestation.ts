// Attestation primitives - sign a disclosure so it resists post-hoc rewriting, and
// let a COUNTERPARTY verify it with no shared secret. ed25519 (asymmetric): the
// signer holds the private key; the public key travels in the envelope and is
// bound to the agent's id. Vendor-neutral (node:crypto only) so it lifts into the
// standalone repo with the schema.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import type { AgentDisclosure, SignedDisclosure } from "./schema.ts";

// SPKI DER prefix for an ed25519 public key; prepended to the raw 32-byte key so
// Node can import a bare hex public key (the interoperable on-wire form).
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface AgentKeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** raw 32-byte public key as hex - this is the agentId + envelope publicKey */
  publicKeyHex: string;
}

/** Mint a fresh agent signing identity. */
export function generateAgentKeyPair(): AgentKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ type: "spki", format: "der" });
  const raw = der.subarray(der.length - 32);
  return { privateKey, publicKey, publicKeyHex: raw.toString("hex") };
}

function publicKeyFromHex(hex: string): KeyObject {
  const raw = Buffer.from(hex, "hex");
  if (raw.length !== 32) throw new Error("ed25519 public key must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
}

/** Sign an arbitrary UTF-8 message with the agent key (hex signature). The generic
 *  primitive the disclosure signing + the challenge handshake both build on. */
export function signMessage(message: string, key: AgentKeyPair): string {
  return edSign(null, Buffer.from(message, "utf8"), key.privateKey).toString("hex");
}

/** Verify a hex signature over a UTF-8 message against an ed25519 public key (hex). */
export function verifyMessage(message: string, publicKeyHex: string, signatureHex: string): boolean {
  try {
    return edVerify(null, Buffer.from(message, "utf8"), publicKeyFromHex(publicKeyHex), Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

/** Serialize the private key (PKCS8 DER hex) so an agent's signing identity is
 *  stable across restarts. Pair with `agentKeyFromPrivateHex`. */
export function exportAgentKey(key: AgentKeyPair): string {
  return (key.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString("hex");
}

/** Reconstruct a full key pair from a persisted private key (PKCS8 DER hex). */
export function agentKeyFromPrivateHex(hex: string): AgentKeyPair {
  const privateKey = createPrivateKey({ key: Buffer.from(hex, "hex"), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  const der = publicKey.export({ type: "spki", format: "der" });
  return { privateKey, publicKey, publicKeyHex: der.subarray(der.length - 32).toString("hex") };
}

/** Defense-in-depth: cap recursion so a hostile, deeply-nested value cannot exhaust
 *  the stack. No valid disclosure nests anywhere near this; the byte output for any
 *  in-range value is unchanged. */
export const MAX_CANONICALIZE_DEPTH = 256;

/** Deterministic JSON: keys sorted recursively, so the signed bytes are stable
 *  across producers (the same canonicalization the audit chain uses). */
export function canonicalize(value: unknown): string {
  return canonicalizeAt(value, 0);
}

function canonicalizeAt(value: unknown, depth: number): string {
  if (depth > MAX_CANONICALIZE_DEPTH) throw new Error("canonicalize: maximum nesting depth exceeded");
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalizeAt(v, depth + 1)).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const body = Object.keys(obj)
    .sort()
    .filter((k) => obj[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonicalizeAt(obj[k], depth + 1)}`)
    .join(",");
  return `{${body}}`;
}

/** sha256 hex of a string - used for the various digest/fingerprint fields. */
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Sign a disclosure with an agent key, returning the signed envelope. */
export function signDisclosure(disclosure: AgentDisclosure, key: AgentKeyPair): SignedDisclosure {
  return {
    disclosure,
    signature: { algorithm: "ed25519", publicKey: key.publicKeyHex, value: signMessage(canonicalize(disclosure), key) },
  };
}

export interface SignatureCheck {
  ok: boolean;
  reason?: string;
}

/** Verify the ed25519 signature over the disclosure. Pure; no policy applied here
 *  (see verify.ts for the counterparty decision). Also enforces the agentId↔key
 *  binding: a disclosure must be signed by the key it claims as its identity. */
export function verifyDisclosureSignature(signed: SignedDisclosure): SignatureCheck {
  if (signed.disclosure.agentId !== signed.signature.publicKey) {
    return { ok: false, reason: "agentId does not match the signing public key" };
  }
  return verifyMessage(canonicalize(signed.disclosure), signed.signature.publicKey, signed.signature.value)
    ? { ok: true }
    : { ok: false, reason: "signature mismatch" };
}

/** Freshness: a disclosure is valid only within [issuedAt, validUntil]. ISO-8601
 *  timestamps compare lexically, so string comparison is correct here. */
export function isFresh(disclosure: AgentDisclosure, now: string): boolean {
  return now >= disclosure.issuedAt && now <= disclosure.validUntil;
}
