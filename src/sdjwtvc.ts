// SD-JWT-VC alternate wire encoding for an agent disclosure.
//
// The native selective-disclosure form (redaction.ts) signs per-field salted
// commitments. It hides field VALUES but leaks the field NAMES (the commitment map
// is keyed by name) and the COUNT (you can see exactly how many fields exist). This
// module gives the same disclosure a second, standards-track encoding —
// SD-JWT-VC (RFC 9901 + draft-ietf-oauth-sd-jwt-vc) — which closes three gaps the
// native form has:
//
//   1. hidden field NAMES — a redactable field becomes an SD-JWT *Disclosure*
//      (base64url(["<salt>","<name>",<value>])) whose only on-wire trace in the
//      signed JWT is an opaque digest in `_sd`. Withhold it and the verifier never
//      learns the name existed.
//   2. decoy digests — `_sd` is padded with random digests for non-existent claims,
//      so the count of real selectively-disclosable fields is hidden too.
//   3. presentation-to-verifier binding — at presentation the holder appends a
//      KB-JWT (key-binding JWT) signed over {iat, aud, nonce, sd_hash}, binding the
//      exact presented bytes to one verifier + one challenge nonce (anti-replay).
//
// This is ADDITIVE: a disclosure can be carried as the native SignedDisclosure OR as
// an SD-JWT-VC string. Nothing here replaces redaction.ts.
//
// Dependency posture: node:crypto + the existing ed25519 primitives only (the holder
// and issuer key are the same agent ed25519 key, expressed as an OKP/Ed25519 JWK in
// `cnf`). No @noble hard-require, no jose.

import {
  createHash,
  createPublicKey,
  randomBytes,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";
import {
  type AgentKeyPair,
  agentKeyFromPrivateHex,
  generateAgentKeyPair,
} from "./attestation.ts";
import { agentIdToDidKey, didKeyToAgentId } from "./did.ts";
import { REDACTABLE_FIELDS } from "./redaction.ts";
import type { AgentDisclosure } from "./schema.ts";

// The credential type id (`vct`) all ADP SD-JWT-VCs carry. Stable, dereferenceable.
export const ADP_VCT = "https://adp.dev/credential/agent-disclosure/v1";

// Header `typ` per draft-ietf-oauth-sd-jwt-vc (the modern "dc+sd-jwt", née
// "vc+sd-jwt") for the issuer JWT, and "kb+jwt" for the key-binding JWT.
const TYP_SD_JWT_VC = "dc+sd-jwt";
const TYP_KB_JWT = "kb+jwt";

// Per SD-JWT-VC, the registered claims iss/nbf/exp/cnf/vct/status MUST NOT be
// selectively disclosed — they stay in the clear so a verifier can decide
// issuer/type/freshness/holder-key before touching any Disclosure. ADP additionally
// keeps the native always-clear meta (disclosureId, nonce, auditAnchor, version)
// clear for parity with redaction.ts. None of those names overlaps REDACTABLE_FIELDS,
// so the `_sd` set is exactly the redactable fields and the rule holds by construction.

// ── base64url helpers (no padding) ───────────────────────────────────────────
function b64url(input: Buffer | string): string {
  return (typeof input === "string" ? Buffer.from(input, "utf8") : input).toString("base64url");
}
function b64urlDecodeToString(s: string): string {
  return Buffer.from(s, "base64url").toString("utf8");
}

/** SD-JWT digest of a Disclosure string: base64url(sha256(US-ASCII bytes of the
 *  base64url Disclosure)). Note: the hash is over the ENCODED disclosure string. */
function disclosureDigest(encodedDisclosure: string): string {
  return b64url(createHash("sha256").update(Buffer.from(encodedDisclosure, "ascii")).digest());
}

/** A random 128-bit salt, base64url — the per-Disclosure salt (RFC 9901 §5). */
function randomSalt(): string {
  return b64url(randomBytes(16));
}

// ── Ed25519 JWK <-> agent key ────────────────────────────────────────────────
export interface Ed25519Jwk {
  kty: "OKP";
  crv: "Ed25519";
  /** base64url of the raw 32-byte public key */
  x: string;
}

/** Express an agent's ed25519 public key (hex) as an OKP/Ed25519 public JWK for `cnf`. */
export function agentKeyToJwk(publicKeyHex: string): Ed25519Jwk {
  return { kty: "OKP", crv: "Ed25519", x: b64url(Buffer.from(publicKeyHex, "hex")) };
}

// ── JWS compact (EdDSA) over the existing ed25519 primitives ──────────────────
function jwsSign(header: object, payload: object, key: AgentKeyPair): string {
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = edSign(null, Buffer.from(signingInput, "ascii"), key.privateKey);
  return `${signingInput}.${b64url(sig)}`;
}

interface JwsParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
}

function jwsDecode(jws: string): JwsParts {
  const parts = jws.split(".");
  if (parts.length !== 3) throw new Error("malformed JWS (expected 3 dot-separated parts)");
  const [h, p, s] = parts;
  return {
    header: JSON.parse(b64urlDecodeToString(h)),
    payload: JSON.parse(b64urlDecodeToString(p)),
    signingInput: `${h}.${p}`,
    signature: Buffer.from(s, "base64url"),
  };
}

/** Verify a compact EdDSA JWS against a raw ed25519 public key (32-byte hex). */
function jwsVerify(parts: JwsParts, publicKeyHex: string): boolean {
  try {
    const raw = Buffer.from(publicKeyHex, "hex");
    if (raw.length !== 32) return false;
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
    const pub = createPublicKey({ key: spki, format: "der", type: "spki" });
    return edVerify(null, Buffer.from(parts.signingInput, "ascii"), pub, parts.signature);
  } catch {
    return false;
  }
}

function jwkToPublicKeyHex(jwk: unknown): string | undefined {
  if (!jwk || typeof jwk !== "object") return undefined;
  const j = jwk as Record<string, unknown>;
  if (j.kty !== "OKP" || j.crv !== "Ed25519" || typeof j.x !== "string") return undefined;
  const raw = Buffer.from(j.x, "base64url");
  if (raw.length !== 32) return undefined;
  return raw.toString("hex");
}

// ── public API ────────────────────────────────────────────────────────────────

export interface ToSdJwtVcOptions {
  /** number of decoy digests to mix into `_sd` (count-hiding). Default 2. */
  decoys?: number;
  /** override `vct` (credential type id). Default ADP_VCT. */
  vct?: string;
  /** holder key for `cnf`; defaults to the issuer key (self-held credential). */
  holderKey?: AgentKeyPair;
}

/** The issuer-signed SD-JWT-VC: combined serialization `<JWT>~<D1>~...~<DN>~`.
 *  The redactable disclosure fields become SD-JWT Disclosures (their NAMES live only
 *  as digests in `_sd`); the non-redactable meta stays as clear claims. */
export function toSdJwtVc(
  disclosure: AgentDisclosure,
  key: AgentKeyPair,
  opts: ToSdJwtVcOptions = {},
): string {
  const decoys = opts.decoys ?? 2;
  const holderKey = opts.holderKey ?? key;

  // Build a Disclosure for every PRESENT redactable field. The redactable set is
  // imported from redaction.ts so the two encodings stay in lockstep.
  const disclosures: string[] = [];
  const sd: string[] = [];
  for (const field of REDACTABLE_FIELDS) {
    const value = (disclosure as Record<string, unknown>)[field];
    if (value === undefined) continue;
    const encoded = b64url(JSON.stringify([randomSalt(), field, value]));
    disclosures.push(encoded);
    sd.push(disclosureDigest(encoded));
  }

  // Decoy digests: digests of well-formed-but-fictional Disclosures the holder will
  // never reveal. Indistinguishable on the wire from real ones, so they hide the
  // count of real selectively-disclosable claims.
  for (let i = 0; i < decoys; i++) {
    const decoy = b64url(JSON.stringify([randomSalt(), `_decoy_${randomSalt()}`, null]));
    sd.push(disclosureDigest(decoy));
  }

  // Shuffle so real and decoy digests are not positionally distinguishable, and so
  // `_sd` order leaks nothing about field identity (RFC 9901 recommends no ordering).
  shuffle(sd);

  const header = { typ: TYP_SD_JWT_VC, alg: "EdDSA" };
  const payload: Record<string, unknown> = {
    iss: agentIdToDidKey(disclosure.agentId),
    vct: opts.vct ?? ADP_VCT,
    iat: toEpoch(disclosure.issuedAt),
    exp: toEpoch(disclosure.validUntil),
    cnf: { jwk: agentKeyToJwk(holderKey.publicKeyHex) },
    // native always-clear meta carried through (parity with redaction.ts) — never `_sd`
    version: disclosure.version,
    disclosureId: disclosure.disclosureId,
    nonce: disclosure.nonce,
    ...(disclosure.auditAnchor ? { auditAnchor: disclosure.auditAnchor } : {}),
    _sd: sd,
    _sd_alg: "sha-256",
  };

  const issuerJwt = jwsSign(header, payload, key);
  // Combined serialization always ends with a trailing '~' after the last disclosure.
  return [issuerJwt, ...disclosures, ""].join("~");
}

export interface PresentOptions {
  /** the verifier this presentation is bound to (KB-JWT `aud`). */
  aud: string;
  /** the verifier's challenge nonce (handshake nonce) — KB-JWT `nonce`. */
  nonce: string;
  /** KB-JWT `iat`, epoch seconds. Defaults to now. */
  iat?: number;
}

/** Present a subset: keep only the Disclosures whose claim name is in
 *  `revealFieldNames`, drop the rest (their digests stay in `_sd` but with no
 *  matching Disclosure they are unrevealed), then append a holder-signed KB-JWT that
 *  binds the exact presented bytes to {aud, nonce}. */
export function presentSdJwtVc(
  issued: string,
  revealFieldNames: string[],
  holderKey: AgentKeyPair,
  opts: PresentOptions,
): string {
  const reveal = new Set(revealFieldNames);
  const segments = issued.split("~");
  const issuerJwt = segments[0];
  // Middle segments are the Disclosures; a trailing "" (and possibly an existing
  // KB-JWT) sits at the end. Keep only object Disclosures whose name is selected.
  const kept: string[] = [];
  for (const seg of segments.slice(1)) {
    if (seg === "") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(b64urlDecodeToString(seg));
    } catch {
      continue; // not a Disclosure (e.g. a pre-existing KB-JWT) — drop it
    }
    if (Array.isArray(parsed) && parsed.length === 3 && reveal.has(parsed[1] as string)) {
      kept.push(seg);
    }
  }

  // The string the KB-JWT signs over: <JWT>~<kept disclosures...>~  (trailing '~').
  const presented = [issuerJwt, ...kept, ""].join("~");
  const sdHash = b64url(createHash("sha256").update(Buffer.from(presented, "ascii")).digest());

  const kbHeader = { typ: TYP_KB_JWT, alg: "EdDSA" };
  const kbPayload = {
    iat: opts.iat ?? Math.floor(Date.now() / 1000),
    aud: opts.aud,
    nonce: opts.nonce,
    sd_hash: sdHash,
  };
  const kbJwt = jwsSign(kbHeader, kbPayload, holderKey);

  // Final SD-JWT+KB: <JWT>~<disclosures...>~<KB-JWT>  (no trailing '~' after KB-JWT).
  return presented + kbJwt;
}

export interface VerifySdJwtVcOptions {
  /** require this `vct` if set. */
  expectedVct?: string;
  /** require the KB-JWT `aud` to equal this if set. */
  aud?: string;
  /** require the KB-JWT `nonce` to equal this if set. */
  nonce?: string;
  /** clock (epoch seconds) for exp/nbf checks; if set and exp < now → expired. */
  now?: number;
}

export interface VerifySdJwtVcResult {
  ok: boolean;
  reason?: string;
  /** the reconstructed claim set: clear claims + spliced-in revealed Disclosures. */
  claims?: Record<string, unknown>;
  /** names of the fields the holder actually revealed. */
  revealedFields?: string[];
  /** the issuer (did:key from `iss`). */
  issuer?: string;
}

/** Verify an SD-JWT-VC presentation:
 *   1. issuer JWS valid (key recovered from `iss` did:key — self-certifying);
 *   2. each received Disclosure's recomputed digest is in `_sd` (reject unreferenced),
 *      and no digest is consumed twice (reject duplicate);
 *   3. splice each revealed claim back into the payload;
 *   4. if a KB-JWT is present (or aud/nonce required): verify it is signed by the
 *      `cnf` key, its aud/nonce match expectations, and its sd_hash matches the exact
 *      presented `<JWT>~<disclosures...>~` bytes (presentation binding). */
export function verifySdJwtVc(
  presentation: string,
  opts: VerifySdJwtVcOptions = {},
): VerifySdJwtVcResult {
  const segments = presentation.split("~");
  const issuerJwt = segments[0];

  let issuerParts: JwsParts;
  try {
    issuerParts = jwsDecode(issuerJwt);
  } catch (e) {
    return { ok: false, reason: `issuer JWT decode failed: ${(e as Error).message}` };
  }

  const payload = issuerParts.payload;
  const iss = payload.iss;
  if (typeof iss !== "string") return { ok: false, reason: "issuer JWT missing iss" };

  // Recover the issuer signing key from the did:key (self-certifying, no registry).
  let issuerKeyHex: string;
  try {
    issuerKeyHex = didKeyToAgentId(iss);
  } catch (e) {
    return { ok: false, reason: `iss is not a resolvable did:key: ${(e as Error).message}` };
  }

  if (!jwsVerify(issuerParts, issuerKeyHex)) {
    return { ok: false, reason: "issuer signature invalid (tampered or wrong key)", issuer: iss };
  }

  if (opts.expectedVct && payload.vct !== opts.expectedVct) {
    return { ok: false, reason: `vct mismatch: ${String(payload.vct)}`, issuer: iss };
  }
  if (opts.now !== undefined && typeof payload.exp === "number" && payload.exp < opts.now) {
    return { ok: false, reason: "credential expired", issuer: iss };
  }
  if (opts.now !== undefined && typeof payload.nbf === "number" && payload.nbf > opts.now) {
    return { ok: false, reason: "credential not yet valid", issuer: iss };
  }

  const sdDigests = Array.isArray(payload._sd) ? (payload._sd as string[]) : [];
  const sdSet = new Set(sdDigests);

  // Separate Disclosures from an optional trailing KB-JWT. A Disclosure is a 3-element
  // JSON array; a KB-JWT is a 3-part JWS string (not JSON-array-parseable).
  const middle = segments.slice(1).filter((s) => s !== "");
  let kbJwt: string | undefined;
  const disclosureSegs: string[] = [];
  for (const seg of middle) {
    try {
      const parsed = JSON.parse(b64urlDecodeToString(seg));
      if (Array.isArray(parsed)) {
        disclosureSegs.push(seg);
        continue;
      }
    } catch {
      // fallthrough
    }
    kbJwt = seg; // a non-array segment is the KB-JWT
  }
  // A trailing KB-JWT ends the string with no '~', so it survives the filter above as
  // the last segment; the presentation ends without "" only when a KB-JWT is present.
  const hasTrailingEmpty = segments[segments.length - 1] === "";

  // Reconstruct claims: clear payload minus the SD machinery, then splice revealed.
  const claims: Record<string, unknown> = { ...payload };
  delete claims._sd;
  delete claims._sd_alg;

  const revealedFields: string[] = [];
  const consumed = new Set<string>();
  for (const seg of disclosureSegs) {
    const digest = disclosureDigest(seg);
    if (!sdSet.has(digest)) {
      return { ok: false, reason: "disclosure not referenced by any _sd digest", issuer: iss };
    }
    if (consumed.has(digest)) {
      return { ok: false, reason: "duplicate disclosure digest", issuer: iss };
    }
    consumed.add(digest);
    const arr = JSON.parse(b64urlDecodeToString(seg)) as [string, string, unknown];
    const [, name, value] = arr;
    claims[name] = value;
    revealedFields.push(name);
  }

  // ── KB-JWT (presentation binding) ──
  const kbRequired = opts.aud !== undefined || opts.nonce !== undefined;
  if (kbJwt) {
    let kbParts: JwsParts;
    try {
      kbParts = jwsDecode(kbJwt);
    } catch (e) {
      return { ok: false, reason: `KB-JWT decode failed: ${(e as Error).message}`, issuer: iss };
    }
    if (kbParts.header.typ !== TYP_KB_JWT) {
      return { ok: false, reason: "KB-JWT has wrong typ", issuer: iss };
    }
    const cnfKey = jwkToPublicKeyHex((payload.cnf as Record<string, unknown> | undefined)?.jwk);
    if (!cnfKey) return { ok: false, reason: "no holder key in cnf to verify KB-JWT", issuer: iss };
    if (!jwsVerify(kbParts, cnfKey)) {
      return { ok: false, reason: "KB-JWT signature invalid (not signed by holder key)", issuer: iss };
    }
    const kb = kbParts.payload;
    if (opts.aud !== undefined && kb.aud !== opts.aud) {
      return { ok: false, reason: "KB-JWT aud mismatch", issuer: iss };
    }
    if (opts.nonce !== undefined && kb.nonce !== opts.nonce) {
      return { ok: false, reason: "KB-JWT nonce mismatch", issuer: iss };
    }
    // sd_hash binds the exact presented bytes: <JWT>~<kept disclosures...>~
    const presented = [issuerJwt, ...disclosureSegs, ""].join("~");
    const expectedSdHash = b64url(
      createHash("sha256").update(Buffer.from(presented, "ascii")).digest(),
    );
    if (kb.sd_hash !== expectedSdHash) {
      return { ok: false, reason: "KB-JWT sd_hash does not match presented disclosures", issuer: iss };
    }
  } else if (kbRequired) {
    return { ok: false, reason: "KB-JWT required (aud/nonce expected) but absent", issuer: iss };
  } else if (!hasTrailingEmpty) {
    // No '~' terminator and no parseable KB-JWT: malformed.
    return { ok: false, reason: "malformed presentation (no terminator, no KB-JWT)", issuer: iss };
  }

  return { ok: true, claims, revealedFields, issuer: iss };
}

// ── internals ─────────────────────────────────────────────────────────────────

/** Fisher–Yates in place; uses crypto randomness so digest ordering is unbiased. */
function shuffle<T>(arr: T[]): void {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomBytes(1)[0] % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
}

/** ISO-8601 → epoch seconds for iat/exp. */
function toEpoch(iso: string): number {
  return Math.floor(Date.parse(iso) / 1000);
}

// Re-export key helpers so callers can mint a holder/issuer key without reaching into
// attestation.ts directly when working purely in the SD-JWT-VC encoding.
export { agentKeyFromPrivateHex, generateAgentKeyPair };
export type { AgentKeyPair };
