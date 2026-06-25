// A2A Agent Card bridge — let an ADP signed disclosure ride A2A agent discovery.
//
// A2A (Agent2Agent) publishes an unauthenticated **Agent Card** at
// `/.well-known/agent-card.json`. The card advertises capabilities, skills, and — via
// `capabilities.extensions[]` — protocol extensions a counterparty can opt into. This
// bridge defines one such extension (`ADP_A2A_EXTENSION_URI`) that carries (or links)
// an ADP `SignedDisclosure` inside the card, so an A2A agent's disclosure travels with
// its discovery document.
//
// Dual-signature trust model. The card itself MAY carry `signatures[]` — RFC 7515 JWS
// in flattened-JSON form, computed over the card's RFC 8785 (JCS) canonicalization with
// `signatures` removed (A2A spec §8.4). That is **tamper-evidence on the card origin**,
// not the trust root. The trust root is the disclosure's OWN ed25519 envelope, which a
// counterparty verifies with the agent's public key alone — the same guarantee the bare
// disclosure carries. So `verifyCardDisclosure` REQUIRES the disclosure envelope to
// verify and only REPORTS the card-signature result + the agentId↔card-signer binding.
// `signAgentCard` defaults to EdDSA over the ADP ed25519 agent key, so an ADP agent can
// publish a self-signed card whose signer == agentId → a strong, provable binding.
//
// Dependency posture: zod + node:crypto only (no `@a2a` package, no jose). The A2A type
// subset we touch is defined locally and permissive (passthrough of unknown fields), so
// a real, fuller AgentCard round-trips through these helpers unchanged.

import {
  createPublicKey,
  createVerify,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { canonicalize, verifyDisclosureSignature } from "./attestation.ts";
import { agentIdToDidKey } from "./did.ts";
import { SignedDisclosureSchema, type SignedDisclosure } from "./schema.ts";

// SPKI DER prefix for an ed25519 public key (same as attestation.ts/sdjwtvc.ts): prepend
// to the raw 32-byte key so node:crypto can import a bare hex public key.
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** The ADP × A2A extension URI. Declared in `capabilities.extensions[].uri`; its `params`
 *  carry the disclosure (embedded) and/or a `.well-known/agent-disclosure` URL. */
export const ADP_A2A_EXTENSION_URI = "https://adp.dev/a2a/agent-disclosure/v1";

const EXTENSION_DESCRIPTION =
  "Agent Disclosure Protocol (ADP) signed disclosure — verify before transacting.";

// ── A2A type subset (local, minimal, permissive) ─────────────────────────────

export interface A2aAgentExtension {
  uri: string;
  description?: string;
  required?: boolean;
  params?: Record<string, unknown>;
}

/** RFC 7515 JWS in flattened-JSON form (A2A `AgentCardSignature`). */
export interface A2aAgentCardSignature {
  /** base64url(UTF8(JSON protected header)) — MUST carry `alg`; SHOULD carry `kid`/`typ`. */
  protected: string;
  /** base64url( signature over ASCII(protected + "." + b64url(JCS(card-without-signatures))) ) */
  signature: string;
  /** unprotected header (e.g. `jwk`, `jku`) — not integrity-protected. */
  header?: Record<string, unknown>;
}

/** The subset of A2A AgentCard we read/produce. Permissive: unknown fields pass through. */
export interface A2aAgentCard {
  protocolVersion: string;
  name: string;
  description: string;
  version: string;
  capabilities: {
    extensions?: A2aAgentExtension[];
    streaming?: boolean;
    pushNotifications?: boolean;
    [k: string]: unknown;
  };
  defaultInputModes: string[];
  defaultOutputModes: string[];
  skills: unknown[];
  signatures?: A2aAgentCardSignature[];
  url?: string;
  [k: string]: unknown;
}

// ── Emit ──────────────────────────────────────────────────────────────────────

export interface DisclosureExtensionOptions {
  /** the `.well-known/agent-disclosure` URI, for fetch-based flows. */
  url?: string;
  /** mark the extension required on the card (default false). */
  required?: boolean;
  /** embed the full SignedDisclosure inline so a counterparty needs no second fetch
   *  (default true). When false, only `{ agentId, url }` is carried (requires `url`). */
  embed?: boolean;
}

/** Build the ADP disclosure A2A extension. With `embed` (default) the full
 *  `SignedDisclosure` rides in `params.disclosure`, so a counterparty can verify it with
 *  no second fetch; `url` (if given) is also carried for fetch-based flows. With
 *  `embed: false` only `{ agentId, url }` is carried. */
export function disclosureExtension(
  signed: SignedDisclosure,
  opts: DisclosureExtensionOptions = {},
): A2aAgentExtension {
  const embed = opts.embed ?? true;
  const agentId = signed.disclosure.agentId;
  const params: Record<string, unknown> = { agentId };
  if (embed) params.disclosure = signed;
  if (opts.url !== undefined) params.url = opts.url;
  if (!embed && opts.url === undefined) {
    throw new Error("disclosureExtension: embed:false requires opts.url (nothing to carry otherwise)");
  }
  return {
    uri: ADP_A2A_EXTENSION_URI,
    description: EXTENSION_DESCRIPTION,
    required: opts.required ?? false,
    params,
  };
}

/** Return a copy of `card` with the ADP disclosure extension appended to
 *  `capabilities.extensions` (replacing any existing entry with the same uri — dedup). */
export function withDisclosureExtension(
  card: A2aAgentCard,
  signed: SignedDisclosure,
  opts: DisclosureExtensionOptions = {},
): A2aAgentCard {
  const ext = disclosureExtension(signed, opts);
  const existing = card.capabilities.extensions ?? [];
  const extensions = [...existing.filter((e) => e.uri !== ext.uri), ext];
  return { ...card, capabilities: { ...card.capabilities, extensions } };
}

/** Locate the ADP disclosure extension on a card by its URI, if present. */
export function findDisclosureExtension(card: A2aAgentCard): A2aAgentExtension | undefined {
  return card.capabilities.extensions?.find((e) => e.uri === ADP_A2A_EXTENSION_URI);
}

/** Pull the embedded `SignedDisclosure` out of the card's ADP extension and validate it
 *  against `SignedDisclosureSchema`. Returns undefined if the extension is absent or carries
 *  no embedded disclosure (a link-only/`embed:false` extension), or if the embedded value
 *  fails schema validation. */
export function extractDisclosure(card: A2aAgentCard): SignedDisclosure | undefined {
  const ext = findDisclosureExtension(card);
  const raw = ext?.params?.disclosure;
  if (raw === undefined) return undefined;
  const parsed = SignedDisclosureSchema.safeParse(raw);
  return parsed.success ? parsed.data : undefined;
}

// ── Card JWS (A2A §8.4) ─────────────────────────────────────────────────────

// REQUIRED AgentCard fields (A2A §8.4.1) — always present in the JCS-canonicalized
// signing payload. The non-required, empty-array omission rule (§8.4.1) is handled by
// `canonicalize`, which already drops `undefined`-valued keys; empty arrays on REQUIRED
// fields stay (they are required), and our local card type makes the required arrays
// non-optional. Optional-but-set fields are included verbatim (their presence in the
// object is the signal), matching the spec's default-value-omission table.

/** The bytes signed by an Agent Card signature: the card with `signatures` removed, then
 *  RFC 8785 (JCS) canonicalized (the package's `canonicalize`, which is JCS over ADP's
 *  value domain and drops `undefined`-valued keys per §8.4.1 omission). */
export function canonicalCardPayload(card: A2aAgentCard): string {
  const { signatures: _signatures, ...rest } = card;
  return canonicalize(rest);
}

export interface SignAgentCardOptions {
  /** the ed25519 private key to sign with (a node:crypto KeyObject). */
  privateKey: KeyObject;
  /** the JWS `kid` (key id) for the protected header; SHOULD identify the signer. */
  kid?: string;
  /** signing algorithm. Only EdDSA (ed25519) is produced here — the ADP agent key. */
  alg?: "EdDSA";
}

/** Produce a `signatures[0]` JWS over the canonicalized card and append it (default alg
 *  EdDSA using the ADP ed25519 agent key, so an ADP agent publishes a self-signed card
 *  whose signer == agentId → strong binding). The signing input is
 *  `b64url(protected) + "." + b64url(JCS(card-without-signatures))`, per A2A §8.4. */
export function signAgentCard(card: A2aAgentCard, opts: SignAgentCardOptions): A2aAgentCard {
  const alg = opts.alg ?? "EdDSA";
  const protectedHeader: Record<string, unknown> = { alg, typ: "JOSE" };
  if (opts.kid !== undefined) protectedHeader.kid = opts.kid;

  const protectedB64 = Buffer.from(JSON.stringify(protectedHeader), "utf8").toString("base64url");
  const payloadB64 = Buffer.from(canonicalCardPayload(card), "utf8").toString("base64url");
  const signingInput = Buffer.from(`${protectedB64}.${payloadB64}`, "ascii");
  const signature = edSign(null, signingInput, opts.privateKey).toString("base64url");

  const sig: A2aAgentCardSignature = { protected: protectedB64, signature };
  return { ...card, signatures: [...(card.signatures ?? []), sig] };
}

export interface VerifyAgentCardSignatureOptions {
  /** resolve a public verification key from the signature's protected + unprotected headers.
   *  Required for ES256/RS256; for EdDSA, an `jwk` (OKP/Ed25519) in the unprotected header is
   *  used automatically when no resolver is given. */
  resolveKey?: (
    header: { protected: Record<string, unknown>; unprotected?: Record<string, unknown> },
  ) => KeyObject | undefined;
}

export interface AgentCardSignatureCheck {
  ok: boolean;
  reason?: string;
  /** the `kid` from the protected header, if present. */
  kid?: string;
  /** the ed25519 public key (hex) the signature verified against, when recoverable.
   *  Lets a caller bind the card signer to a disclosure agentId. */
  signerKeyHex?: string;
}

/** Verify a single Agent Card signature (A2A §8.4.3): strip `signatures`, JCS-canonicalize,
 *  rebuild the signing input `received_protected + "." + b64url(JCS(payload))`, and verify
 *  with the header `alg` + a resolved key. EdDSA (ed25519) verifies natively against an
 *  OKP/Ed25519 `jwk` in the unprotected header (or a resolver-supplied key); ES256/RS256
 *  verify when `resolveKey` supplies a key. An alg we cannot handle returns a graceful
 *  `{ ok:false, reason:"unsupported alg" }` rather than throwing. */
export function verifyAgentCardSignature(
  card: A2aAgentCard,
  sig: A2aAgentCardSignature,
  opts: VerifyAgentCardSignatureOptions = {},
): AgentCardSignatureCheck {
  let header: { alg?: unknown; kid?: unknown };
  try {
    header = JSON.parse(Buffer.from(sig.protected, "base64url").toString("utf8"));
  } catch {
    return { ok: false, reason: "unreadable protected header" };
  }
  const kid = typeof header.kid === "string" ? header.kid : undefined;
  const alg = header.alg;

  const payloadB64 = Buffer.from(canonicalCardPayload(card), "utf8").toString("base64url");
  const signingInput = Buffer.from(`${sig.protected}.${payloadB64}`, "ascii");

  if (alg === "EdDSA") {
    const key = resolveEdDsaKey(header as Record<string, unknown>, sig.header, opts.resolveKey);
    if (!key) return { ok: false, reason: "no ed25519 key to verify EdDSA signature", kid };
    let okSig = false;
    try {
      okSig = edVerify(null, signingInput, key.key, Buffer.from(sig.signature, "base64url"));
    } catch {
      return { ok: false, reason: "card signature mismatch", kid };
    }
    if (!okSig) return { ok: false, reason: "card signature mismatch", kid };
    return { ok: true, kid, signerKeyHex: key.hex };
  }

  if (alg === "ES256" || alg === "RS256") {
    const key = opts.resolveKey?.({ protected: header as Record<string, unknown>, unprotected: sig.header });
    if (!key) return { ok: false, reason: `no key resolved for ${alg}`, kid };
    const verifier = createVerify(alg === "ES256" ? "SHA256" : "RSA-SHA256");
    verifier.update(signingInput);
    verifier.end();
    // ES256 JWS signatures are raw R||S; node's verify expects DER unless told ieee-p1363.
    const dsa = alg === "ES256" ? ({ key, dsaEncoding: "ieee-p1363" } as const) : key;
    let okSig = false;
    try {
      okSig = verifier.verify(dsa, Buffer.from(sig.signature, "base64url"));
    } catch {
      return { ok: false, reason: "card signature mismatch", kid };
    }
    return okSig ? { ok: true, kid } : { ok: false, reason: "card signature mismatch", kid };
  }

  return { ok: false, reason: `unsupported alg: ${String(alg)}`, kid };
}

/** Resolve an ed25519 verification key for an EdDSA card signature: a caller-supplied
 *  resolver wins; otherwise an OKP/Ed25519 `jwk` in the unprotected header is used. Returns
 *  both the KeyObject and the raw 32-byte hex (for agentId binding), or undefined. */
function resolveEdDsaKey(
  protectedHeader: Record<string, unknown>,
  unprotected: Record<string, unknown> | undefined,
  resolveKey: VerifyAgentCardSignatureOptions["resolveKey"],
): { key: KeyObject; hex: string } | undefined {
  if (resolveKey) {
    const k = resolveKey({ protected: protectedHeader, unprotected });
    if (k) return { key: k, hex: ed25519KeyObjectToHex(k) };
  }
  const jwk = unprotected?.jwk as Record<string, unknown> | undefined;
  if (jwk && jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string") {
    const raw = Buffer.from(jwk.x, "base64url");
    if (raw.length !== 32) return undefined;
    return { key: ed25519PublicKeyFromHex(raw.toString("hex")), hex: raw.toString("hex") };
  }
  return undefined;
}

function ed25519PublicKeyFromHex(hex: string): KeyObject {
  const raw = Buffer.from(hex, "hex");
  if (raw.length !== 32) throw new Error("ed25519 public key must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
}

function ed25519KeyObjectToHex(key: KeyObject): string {
  const der = (key.export({ type: "spki", format: "der" }) as Buffer);
  return der.subarray(der.length - 32).toString("hex");
}

// ── Extract + verify ─────────────────────────────────────────────────────────

export interface VerifyCardDisclosureOptions {
  /** a disclosure fetched out of band (e.g. via the extension `url`), used when the card
   *  carries no embedded disclosure. Takes precedence over the embedded one. */
  fetched?: SignedDisclosure;
  /** resolver for non-EdDSA card signatures (passed through to verifyAgentCardSignature). */
  resolveKey?: VerifyAgentCardSignatureOptions["resolveKey"];
}

export interface VerifyCardDisclosureResult {
  ok: boolean;
  reason?: string;
  /** the disclosure's agentId when the envelope verified. */
  agentId?: string;
  /** true iff at least one card signature was present AND verified. */
  cardSignatureChecked: boolean;
  /** true iff a verified card signature's signer key resolves to the disclosure agentId
   *  (the strong self-signed-card binding). */
  boundToCardSigner: boolean;
}

/** Verify a disclosure carried by an A2A Agent Card. The disclosure's own ed25519 envelope
 *  is the security-critical leg and MUST verify (`verifyDisclosureSignature`). The card's own
 *  `signatures[]` are best-effort tamper-evidence on the card origin: a card-signature
 *  failure does NOT fail the result, but a verified one is reported, and if its signer key
 *  equals the disclosure agentId the binding is reported as strong. Resolution order for the
 *  disclosure: `opts.fetched` ?? embedded extension. */
export function verifyCardDisclosure(
  card: A2aAgentCard,
  opts: VerifyCardDisclosureOptions = {},
): VerifyCardDisclosureResult {
  const signed = opts.fetched ?? extractDisclosure(card);
  if (!signed) {
    return { ok: false, reason: "no disclosure", cardSignatureChecked: false, boundToCardSigner: false };
  }

  const envelope = verifyDisclosureSignature(signed);
  if (!envelope.ok) {
    return { ok: false, reason: envelope.reason, cardSignatureChecked: false, boundToCardSigner: false };
  }

  const agentId = signed.disclosure.agentId;
  let cardSignatureChecked = false;
  let boundToCardSigner = false;
  for (const sig of card.signatures ?? []) {
    const check = verifyAgentCardSignature(card, sig, { resolveKey: opts.resolveKey });
    if (!check.ok) continue;
    cardSignatureChecked = true;
    if (check.signerKeyHex && signerBindsToAgentId(check.signerKeyHex, agentId)) {
      boundToCardSigner = true;
    }
  }

  return { ok: true, agentId, cardSignatureChecked, boundToCardSigner };
}

/** A card signer's ed25519 key binds to the disclosure agentId when it equals the agentId
 *  directly (raw-hex form) or via that key's did:key encoding (the self-certifying form). */
function signerBindsToAgentId(signerKeyHex: string, agentId: string): boolean {
  if (signerKeyHex === agentId) return true;
  try {
    return agentIdToDidKey(signerKeyHex) === agentId;
  } catch {
    return false;
  }
}
