// Visa Trusted Agent Protocol (TAP) interop — surface an ADP disclosure inside a TAP-style
// RFC-9421 signed-request flow.
//
// TAP (github.com/visa/trusted-agent-protocol) lets a merchant answer "is this a legitimate,
// trusted agent acting for an authenticated user?" by having the agent send an RFC-9421
// (HTTP Message Signatures) signed request. The handshake is the SAME primitive ADP already
// runs in handshake.ts: an ed25519 signature over an RFC-9421 *signature base* (covered
// components + an `@signature-params` line). So an ADP agent and a TAP merchant already
// speak the same cryptographic language — this module is the mapping between them.
//
// TAP wire format (confirmed verbatim from the reference impl, `tap-agent/agent_app.py`
// `create_ed25519_signature` + `merchant-backend/app/security/signature_verification.py`):
//   - Three headers: `Signature-Agent`, `Signature-Input`, `Signature`.
//   - `Signature-Agent`: the agent-directory URL (the trust root that resolves `keyId`).
//   - `Signature-Input`: `<label>=("@authority" "@path"); created=<int>; expires=<int>;
//       keyId="<id>"; alg="ed25519"; nonce="<uuid>"; tag="<tag>"`  (label `sig2` in the
//       agent, `sig1` in the merchant sample — so it is configurable here).
//   - `Signature`: `<label>=:<base64>:`  (RFC-9421 sf-binary; base64, NOT hex).
//   - Signature base lines: `"@authority": <authority>`, `"@path": <path>`,
//       `"@signature-params": (...)...`  joined by "\n".
//   - `created`/`expires` are unix-SECONDS integers; ed25519 is a first-class TAP alg.
//   - `tag` is TAP's binding label, e.g. "agent-browser-auth" / "agent-payer-auth".
//
// ADP↔TAP deviations bridged here (and why):
//   - ADP timestamps are ISO-8601; TAP `created`/`expires` are unix-seconds — converted.
//   - ADP signatures are hex; TAP `Signature` is base64 sf-binary — converted at the edge,
//     the SIGNED BYTES (the RFC-9421 base) are identical so the same ed25519 key verifies.
//   - The disclosure itself does not fit in an RFC-9421 covered component; it rides in a
//     `Signature-Agent`-adjacent header (`ADP-Disclosure`) and/or a `.well-known` URL the
//     `Signature-Agent` directory serves. The disclosure's OWN ed25519 envelope stays the
//     trust root (verified separately); the TAP signature is live-request authentication.
//
// REUSE: ADP's EXPORTED ed25519 primitives `signMessage` / `verifyMessage` (attestation.ts)
// — the exact functions handshake.ts builds its RFC-9421 base on. handshake.ts is NOT
// imported or edited; this is an independent TAP profile over the same primitive.
//
// INJECTED seam: resolving a TAP `keyId` (and `Signature-Agent` directory) to the ed25519
// public key that must verify a request is a directory lookup TAP delegates to its
// agent-registry. That is `TapKeyResolver` here — injected, so core pulls in no registry
// client; a test supplies a stub. Anything TAP leaves merchant/directory-specific stays
// behind this seam.

import { Buffer } from "node:buffer";
import { signMessage, verifyMessage } from "./attestation.ts";
import { SignedDisclosureSchema, type SignedDisclosure } from "./schema.ts";

// ── TAP wire constants ────────────────────────────────────────────────────────

/** TAP's three RFC-9421 headers. */
export const TAP_HEADER_SIGNATURE_AGENT = "Signature-Agent";
export const TAP_HEADER_SIGNATURE_INPUT = "Signature-Input";
export const TAP_HEADER_SIGNATURE = "Signature";

/** ADP carries its disclosure alongside the TAP handshake in this header (embedded JSON) —
 *  the TAP signature authenticates the live request, the disclosure envelope is the trust
 *  root a merchant verifies separately (see `verifyTapRequest`). */
export const TAP_HEADER_ADP_DISCLOSURE = "ADP-Disclosure";

/** TAP's signature-base covered components: derived components only (no body), matching the
 *  reference agent's `("@authority" "@path")`. */
export const TAP_COVERED_COMPONENTS = ["@authority", "@path"] as const;

/** The ed25519 alg label TAP declares in `Signature-Input` (`alg="ed25519"`). */
export const TAP_ALG_ED25519 = "ed25519";

/** TAP `tag` values (the binding label), from the reference agent. */
export const TAP_TAG_BROWSER_AUTH = "agent-browser-auth";
export const TAP_TAG_PAYER_AUTH = "agent-payer-auth";

/** Default `Signature-Input` label; the reference agent uses `sig2` (`sig1` in the merchant
 *  sample), so it is overridable. */
export const TAP_DEFAULT_LABEL = "sig2";

// ── The signed request ────────────────────────────────────────────────────────

/** The materials covered by (or carried alongside) a TAP RFC-9421 signature. */
export interface TapSignatureMaterial {
  /** the `@authority` derived component (the request's host, e.g. "merchant.example"). */
  authority: string;
  /** the `@path` derived component (the request path, e.g. "/checkout"). */
  path: string;
  /** the TAP `keyId` — the directory-resolvable id of the signing key. */
  keyId: string;
  /** a fresh per-request nonce (the reference agent uses a uuid). */
  nonce: string;
  /** signature creation time, unix SECONDS. */
  created: number;
  /** signature expiry, unix SECONDS. */
  expires: number;
  /** the TAP binding tag (e.g. `TAP_TAG_BROWSER_AUTH`). */
  tag: string;
  /** the `Signature-Input` label (default `sig2`). */
  label?: string;
}

/** A TAP-style signed request: the three RFC-9421 header values plus the (optional) ADP
 *  disclosure header. Drop these straight onto an outbound HTTP request's headers. */
export interface TapSignedRequest {
  /** `Signature-Agent` — the agent-directory URL. */
  signatureAgent: string;
  /** `Signature-Input` — the covered set + params. */
  signatureInput: string;
  /** `Signature` — `<label>=:<base64>:`. */
  signature: string;
  /** `ADP-Disclosure` — the embedded SignedDisclosure JSON, when carried inline. */
  adpDisclosure?: string;
  /** the label used (echoed for convenience; also embedded in the headers). */
  label: string;
}

const SECONDS_PER_MS = 1000;

/** ISO-8601 (ADP convention) → unix seconds (TAP convention). */
export function isoToUnixSeconds(iso: string): number {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) throw new Error(`not an ISO-8601 timestamp: ${iso}`);
  return Math.floor(ms / SECONDS_PER_MS);
}

/** The RFC-9421 `@signature-params` value for a TAP signature: the inner covered-list plus
 *  `created/expires/keyId/alg/nonce/tag`, in the exact order the reference agent emits. */
function signatureParams(m: TapSignatureMaterial): string {
  const inner = TAP_COVERED_COMPONENTS.map((c) => `"${c}"`).join(" ");
  return (
    `(${inner}); created=${m.created}; expires=${m.expires}; ` +
    `keyId="${m.keyId}"; alg="${TAP_ALG_ED25519}"; nonce="${m.nonce}"; tag="${m.tag}"`
  );
}

/** The RFC-9421 signature base: `"@authority": <authority>`, `"@path": <path>`, then the
 *  `"@signature-params": (...)` line — joined by "\n", verbatim per the TAP reference. */
export function tapSignatureBase(m: TapSignatureMaterial): string {
  return [
    `"@authority": ${m.authority}`,
    `"@path": ${m.path}`,
    `"@signature-params": ${signatureParams(m)}`,
  ].join("\n");
}

/** The `Signature-Input` header value: `<label>=<params>`. */
export function tapSignatureInput(m: TapSignatureMaterial): string {
  return `${m.label ?? TAP_DEFAULT_LABEL}=${signatureParams(m)}`;
}

/** Hex (ADP `signMessage` output) → base64 (TAP `Signature` sf-binary value). The signed
 *  bytes are unchanged; only the encoding of the signature differs at the wire edge. */
function hexToBase64(hex: string): string {
  return Buffer.from(hex, "hex").toString("base64");
}

/** base64 (TAP `Signature` value) → hex (ADP `verifyMessage` input). */
function base64ToHex(b64: string): string {
  return Buffer.from(b64, "base64").toString("hex");
}

export interface SignTapRequestOptions {
  /** carry the full SignedDisclosure inline in `ADP-Disclosure` (default true). When false,
   *  the merchant fetches it from the `Signature-Agent` directory `.well-known` instead. */
  embedDisclosure?: boolean;
}

/** Produce a TAP-style RFC-9421 signed request that surfaces an ADP disclosure. The
 *  ed25519 signature is computed with ADP's EXPORTED `signMessage` (the same primitive the
 *  ADP handshake uses) over the TAP signature base, then encoded base64 into the `Signature`
 *  header. The disclosure rides in `ADP-Disclosure` (when embedded). `keyId` SHOULD be the
 *  agent's ADP agentId so the TAP signer binds to the disclosure subject.
 *
 *  `key` is the ADP agent key pair (only `privateKey` is used to sign; `publicKeyHex` is the
 *  agentId a verifier resolves the `keyId` to). */
export function signTapRequest(
  signed: SignedDisclosure,
  signatureAgent: string,
  material: TapSignatureMaterial,
  key: Parameters<typeof signMessage>[1],
  opts: SignTapRequestOptions = {},
): TapSignedRequest {
  const label = material.label ?? TAP_DEFAULT_LABEL;
  const sigHex = signMessage(tapSignatureBase(material), key);
  const req: TapSignedRequest = {
    signatureAgent,
    signatureInput: tapSignatureInput(material),
    signature: `${label}=:${hexToBase64(sigHex)}:`,
    label,
  };
  if (opts.embedDisclosure ?? true) {
    req.adpDisclosure = JSON.stringify(signed);
  }
  return req;
}

// ── Parsing a received TAP request ────────────────────────────────────────────

/** A parsed TAP `Signature-Input`: the covered components + params, extracted from the
 *  header so a verifier can reconstruct the signature base. */
export interface ParsedTapSignatureInput {
  label: string;
  components: string[];
  keyId: string;
  nonce: string;
  created: number;
  expires: number;
  tag: string;
  alg: string;
}

const COMPONENTS_RE = /^([^=]+)=\(([^)]*)\);\s*(.+)$/;

function parseParam(params: string, name: string): string | undefined {
  // matches `name="value"` (quoted) or `name=value` (bare int)
  const quoted = new RegExp(`${name}="([^"]*)"`).exec(params);
  if (quoted) return quoted[1];
  const bare = new RegExp(`${name}=([^;\\s]+)`).exec(params);
  return bare ? bare[1] : undefined;
}

/** Parse a TAP `Signature-Input` header value into its covered set + params. Returns null on
 *  a value that does not match the TAP RFC-9421 shape. */
export function parseTapSignatureInput(input: string): ParsedTapSignatureInput | null {
  const m = COMPONENTS_RE.exec(input.trim());
  if (!m) return null;
  const [, label, componentList, params] = m;
  const components = componentList
    .split(/\s+/)
    .map((c) => c.replace(/"/g, "").trim())
    .filter((c) => c.length > 0);
  const keyId = parseParam(params, "keyId");
  const nonce = parseParam(params, "nonce");
  const created = parseParam(params, "created");
  const expires = parseParam(params, "expires");
  const tag = parseParam(params, "tag");
  const alg = parseParam(params, "alg");
  if (!keyId || !nonce || created === undefined || expires === undefined || !tag || !alg) {
    return null;
  }
  return {
    label,
    components,
    keyId,
    nonce,
    created: Number(created),
    expires: Number(expires),
    tag,
    alg,
  };
}

/** Extract the `<base64>` payload from a TAP `Signature` header value `<label>=:<b64>:`. */
export function parseTapSignatureValue(signature: string, label: string): string | null {
  const m = new RegExp(`${label}=:([^:]+):`).exec(signature.trim());
  return m ? m[1] : null;
}

/** Pull the embedded `SignedDisclosure` out of an `ADP-Disclosure` header, schema-validated.
 *  Returns undefined when absent or malformed. */
export function extractTapDisclosure(
  adpDisclosureHeader: string | undefined,
): SignedDisclosure | undefined {
  if (adpDisclosureHeader === undefined) return undefined;
  let raw: unknown;
  try {
    raw = JSON.parse(adpDisclosureHeader);
  } catch {
    return undefined;
  }
  const parsed = SignedDisclosureSchema.safeParse(raw);
  return parsed.success ? parsed.data : undefined;
}

// ── Verifying a received TAP request ───────────────────────────────────────────

/** The injected seam: resolve a TAP `keyId` (+ `Signature-Agent` directory) to the ed25519
 *  public key (hex) it must verify against. TAP delegates this to its agent-registry; it is
 *  injected so core pulls in no registry client. For the common ADP case the `keyId` IS the
 *  ed25519 agentId, so `defaultTapKeyResolver` returns it directly. Returns null when the
 *  key is unknown/untrusted (the request is then refused). */
export type TapKeyResolver = (ctx: {
  keyId: string;
  signatureAgent: string;
}) => Promise<string | null> | string | null;

/** The default resolver: treat the `keyId` as the ed25519 agentId itself (the self-certifying
 *  ADP case — no directory round-trip). A deployment wanting a real directory lookup injects
 *  its own resolver instead. */
export const defaultTapKeyResolver: TapKeyResolver = ({ keyId }) =>
  /^[0-9a-fA-F]{64}$/.test(keyId) ? keyId.toLowerCase() : null;

export interface TapVerificationPolicy {
  /** the expected `@authority` (the merchant host the signature is bound to). */
  authority: string;
  /** the expected `@path`. */
  path: string;
  /** the resolver for `keyId` → ed25519 public key (hex). Default `defaultTapKeyResolver`. */
  resolveKey?: TapKeyResolver;
  /** clock for the freshness window, unix seconds. When set, created ≤ now ≤ expires. */
  nowSeconds?: number;
  /** accept only these tags (e.g. [TAP_TAG_PAYER_AUTH]); any tag accepted when unset. */
  allowedTags?: string[];
  /** require the resolved signing key to equal the embedded disclosure's agentId (the
   *  strong binding: the live TAP request is signed by the same key as the disclosure).
   *  Default true; only enforced when a disclosure is present. */
  requireDisclosureBinding?: boolean;
}

export interface TapVerificationResult {
  ok: boolean;
  reason?: string;
  /** the resolved ed25519 key (hex) the signature verified against, when it verified. */
  signerKeyHex?: string;
  /** the parsed signature-input, when parseable. */
  parsed?: ParsedTapSignatureInput;
  /** the embedded disclosure, when present + schema-valid. */
  disclosure?: SignedDisclosure;
  /** true iff the signer key binds to the embedded disclosure's agentId. */
  boundToDisclosure: boolean;
}

/** Verify a received TAP-style request. Reconstructs the RFC-9421 signature base from the
 *  parsed `Signature-Input` + the expected `@authority`/`@path`, resolves the `keyId` to an
 *  ed25519 key (injected seam), and verifies the base64 `Signature` with ADP's EXPORTED
 *  `verifyMessage`. Enforces alg=ed25519, freshness, allowed tags, and (when a disclosure is
 *  embedded) that the signer key equals the disclosure agentId. The disclosure's own
 *  envelope is NOT re-verified here — that is `evaluateDisclosure`'s job; this layer is the
 *  live-request authentication leg. */
export async function verifyTapRequest(
  req: TapSignedRequest,
  policy: TapVerificationPolicy,
): Promise<TapVerificationResult> {
  const parsed = parseTapSignatureInput(req.signatureInput);
  if (!parsed) {
    return { ok: false, reason: "unparseable Signature-Input", boundToDisclosure: false };
  }
  if (parsed.alg !== TAP_ALG_ED25519) {
    return { ok: false, reason: `unsupported alg ${parsed.alg}`, parsed, boundToDisclosure: false };
  }
  if (policy.allowedTags && !policy.allowedTags.includes(parsed.tag)) {
    return {
      ok: false,
      reason: `tag ${parsed.tag} not in allowed set`,
      parsed,
      boundToDisclosure: false,
    };
  }
  if (policy.nowSeconds !== undefined) {
    if (policy.nowSeconds < parsed.created) {
      return {
        ok: false,
        reason: "signature created in the future",
        parsed,
        boundToDisclosure: false,
      };
    }
    if (policy.nowSeconds > parsed.expires) {
      return { ok: false, reason: "signature expired", parsed, boundToDisclosure: false };
    }
  }

  const sigB64 = parseTapSignatureValue(req.signature, parsed.label);
  if (!sigB64) {
    return { ok: false, reason: "unparseable Signature header", parsed, boundToDisclosure: false };
  }

  const resolver = policy.resolveKey ?? defaultTapKeyResolver;
  const signerKeyHex = await resolver({ keyId: parsed.keyId, signatureAgent: req.signatureAgent });
  if (!signerKeyHex) {
    return {
      ok: false,
      reason: `keyId ${parsed.keyId} did not resolve to a trusted key`,
      parsed,
      boundToDisclosure: false,
    };
  }

  // Reconstruct the exact signature base from OUR expected authority/path + the request's
  // own params — so any tampered covered value or param fails verification.
  const material: TapSignatureMaterial = {
    authority: policy.authority,
    path: policy.path,
    keyId: parsed.keyId,
    nonce: parsed.nonce,
    created: parsed.created,
    expires: parsed.expires,
    tag: parsed.tag,
    label: parsed.label,
  };
  // The Signature-Input the request carried must equal what we reconstruct (no param
  // smuggling), then the ed25519 signature must verify over the reconstructed base.
  if (req.signatureInput.trim() !== tapSignatureInput(material)) {
    return {
      ok: false,
      reason: "Signature-Input does not match the expected covered set",
      parsed,
      signerKeyHex,
      boundToDisclosure: false,
    };
  }
  if (!verifyMessage(tapSignatureBase(material), signerKeyHex, base64ToHex(sigB64))) {
    return {
      ok: false,
      reason: "TAP signature did not verify",
      parsed,
      signerKeyHex,
      boundToDisclosure: false,
    };
  }

  const disclosure = extractTapDisclosure(req.adpDisclosure);
  let boundToDisclosure = false;
  if (disclosure) {
    boundToDisclosure = disclosure.disclosure.agentId.toLowerCase() === signerKeyHex.toLowerCase();
    if ((policy.requireDisclosureBinding ?? true) && !boundToDisclosure) {
      return {
        ok: false,
        reason: "TAP signer key does not match the embedded disclosure agentId",
        parsed,
        signerKeyHex,
        disclosure,
        boundToDisclosure,
      };
    }
  }

  return { ok: true, signerKeyHex, parsed, disclosure, boundToDisclosure };
}
