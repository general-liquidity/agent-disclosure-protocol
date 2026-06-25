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
import { agentIdToDidKey } from "./did.ts";
import type { AgentDisclosure, JwsSignedDisclosure, SignedDisclosure } from "./schema.ts";
// Type-only (erased at runtime) so attestation stays the lowest layer: keys.ts
// imports the shared body-builder below, this only borrows the shape. No runtime cycle.
import type { RotationStatement } from "./keys.ts";

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

/** Canonical signed body of a key-rotation statement. Single source of truth shared
 *  with keys.ts (which imports it) so the signing side and the chain-verifying side
 *  here can never disagree on the bytes. */
export function rotationStatementBody(from: string, to: string, rotatedAt: string): string {
  return canonicalize({ type: "rotation", from, to, rotatedAt });
}

/** Defense: cap a rotation chain so a hostile envelope can't force unbounded work. */
export const MAX_ROTATION_CHAIN = 32;

/** Verify that a chain of signed rotation statements links the stable `agentId` to the
 *  key that actually signed a disclosure (`signingKey`). Each hop's `from` must itself
 *  sign the move to its `to`, the hops must be contiguous, acyclic, and end at the
 *  signing key. This is what lets an identity survive key rotation: `agentId` stays
 *  fixed while the signing key advances. */
export function verifyRotationChain(
  agentId: string,
  signingKey: string,
  chain: readonly RotationStatement[],
): SignatureCheck {
  if (chain.length === 0) return { ok: false, reason: "empty rotation chain" };
  if (chain.length > MAX_ROTATION_CHAIN) return { ok: false, reason: "rotation chain exceeds maximum length" };
  let cursor = agentId;
  const seen = new Set<string>([agentId]);
  for (const s of chain) {
    if (s.from !== cursor) return { ok: false, reason: "rotation chain is not contiguous from agentId" };
    if (!verifyMessage(rotationStatementBody(s.from, s.to, s.rotatedAt), s.from, s.signature)) {
      return { ok: false, reason: "a rotation statement signature does not verify against its from key" };
    }
    if (seen.has(s.to)) return { ok: false, reason: "rotation chain contains a cycle" };
    seen.add(s.to);
    cursor = s.to;
  }
  if (cursor !== signingKey) return { ok: false, reason: "rotation chain does not end at the signing key" };
  return { ok: true };
}

/** Bind a disclosure's stable `agentId` to the key that actually signed it: a direct hex
 *  match, the did:key encoding of that key (self-certifying form), or a verified rotation
 *  chain back to the agentId. Shared by both envelope shapes. */
export function verifyKeyBinding(
  agentId: string,
  signingKeyHex: string,
  rotationChain?: readonly RotationStatement[],
): SignatureCheck {
  if (agentId === signingKeyHex) return { ok: true };
  try {
    if (agentId === agentIdToDidKey(signingKeyHex)) return { ok: true };
  } catch {
    // signingKeyHex is a valid 32-byte key on every call path here; defensive only.
  }
  if (rotationChain?.length) return verifyRotationChain(agentId, signingKeyHex, rotationChain);
  return { ok: false, reason: "agentId does not match the signing public key" };
}

/** Verify the ed25519 signature over the disclosure (v1 object envelope). Pure; no policy
 *  applied here (see verify.ts for the counterparty decision). Also enforces the
 *  agentId↔key binding via `verifyKeyBinding`. */
export function verifyDisclosureSignature(signed: SignedDisclosure): SignatureCheck {
  if (!verifyMessage(canonicalize(signed.disclosure), signed.signature.publicKey, signed.signature.value)) {
    return { ok: false, reason: "signature mismatch" };
  }
  return verifyKeyBinding(signed.disclosure.agentId, signed.signature.publicKey, signed.rotationChain);
}

// ── v2: flattened JWS (EdDSA) envelope ───────────────────────────────────────
const JWS_PROTECTED_HEADER = { alg: "EdDSA", typ: "application/adp+json" } as const;

/** Sign a disclosure as a flattened JWS (EdDSA) envelope — the JOSE-interoperable v2
 *  wrapping. The signature covers ASCII(b64u(protected) + "." + b64u(payload)), so the
 *  protected header (carrying `alg`) is integrity-protected — closing the v1 gap where
 *  the algorithm field sat outside the signed bytes. Payload is the same RFC 8785 (JCS)
 *  canonical document, so a JOSE library can verify it. */
export function signDisclosureJws(disclosure: AgentDisclosure, key: AgentKeyPair): JwsSignedDisclosure {
  const protectedB64 = Buffer.from(JSON.stringify(JWS_PROTECTED_HEADER), "utf8").toString("base64url");
  const payloadB64 = Buffer.from(canonicalize(disclosure), "utf8").toString("base64url");
  const signature = edSign(null, Buffer.from(`${protectedB64}.${payloadB64}`, "ascii"), key.privateKey).toString("base64url");
  return {
    payload: payloadB64,
    protected: protectedB64,
    header: { jwk: { kty: "OKP", crv: "Ed25519", x: Buffer.from(key.publicKeyHex, "hex").toString("base64url") } },
    signature,
  };
}

/** Verify a v2 JWS envelope: the protected header must declare EdDSA, the signature must
 *  verify over the signing input against the JWK key, and the payload's `agentId` must
 *  bind to that key (direct, did:key, or rotation chain). */
export function verifyDisclosureJws(signed: JwsSignedDisclosure): SignatureCheck {
  let header: { alg?: unknown };
  try {
    header = JSON.parse(Buffer.from(signed.protected, "base64url").toString("utf8"));
  } catch {
    return { ok: false, reason: "unreadable protected header" };
  }
  if (header.alg !== "EdDSA") return { ok: false, reason: `unsupported JWS alg: ${String(header.alg)}` };

  const pubHex = Buffer.from(signed.header.jwk.x, "base64url").toString("hex");
  if (pubHex.length !== 64) return { ok: false, reason: "jwk.x is not a 32-byte ed25519 key" };

  let okSig = false;
  try {
    okSig = edVerify(
      null,
      Buffer.from(`${signed.protected}.${signed.payload}`, "ascii"),
      publicKeyFromHex(pubHex),
      Buffer.from(signed.signature, "base64url"),
    );
  } catch {
    return { ok: false, reason: "jws signature mismatch" };
  }
  if (!okSig) return { ok: false, reason: "jws signature mismatch" };

  let agentId: unknown;
  try {
    agentId = (JSON.parse(Buffer.from(signed.payload, "base64url").toString("utf8")) as { agentId?: unknown }).agentId;
  } catch {
    return { ok: false, reason: "unreadable payload" };
  }
  if (typeof agentId !== "string") return { ok: false, reason: "payload has no agentId" };
  return verifyKeyBinding(agentId, pubHex, signed.rotationChain);
}

/** Verify either envelope shape (v1 object or v2 flattened JWS), discriminated by shape. */
export function verifyAnyDisclosureSignature(signed: SignedDisclosure | JwsSignedDisclosure): SignatureCheck {
  return "payload" in signed && "protected" in signed ? verifyDisclosureJws(signed) : verifyDisclosureSignature(signed);
}

/** Freshness: a disclosure is valid only within [issuedAt, validUntil]. ISO-8601
 *  timestamps compare lexically, so string comparison is correct here. */
export function isFresh(disclosure: AgentDisclosure, now: string): boolean {
  return now >= disclosure.issuedAt && now <= disclosure.validUntil;
}
