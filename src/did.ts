// DID bridge - express the agentId in the W3C DID ecosystem.
//
// ADP's agentId is the raw 32-byte ed25519 public key (hex). The DID world already
// has a canonical, deterministic encoding for exactly that key type: did:key with
// the ed25519-pub multicodec. So an agentId IS a did:key, with no registry and no
// extra trust assumptions - the same key that signs disclosures names the DID, and
// resolving the DID back to a verification key recovers the agentId. did:web is the
// hosted alternative (identity anchored at a domain), constructed here but resolved
// out of band by fetching the domain's did.json.
//
// Dependency posture: node:crypto + an inline base58btc codec only, matching the
// rest of the package (no multiformats/did-resolver pulled in).

// The multicodec prefix for an ed25519 public key, varint-encoded: 0xed 0x01.
// did:key for ed25519 = "did:key:z" + base58btc(0xed01 || rawPubKey).
const MULTICODEC_ED25519_PUB = Uint8Array.from([0xed, 0x01]);

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** base58btc encode (Bitcoin alphabet). Leading zero bytes map to leading '1's. */
function base58Encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]];
  return out;
}

/** base58btc decode (Bitcoin alphabet). Leading '1's map to leading zero bytes. */
function base58Decode(str: string): Uint8Array {
  let zeros = 0;
  while (zeros < str.length && str[zeros] === "1") zeros++;

  const bytes: number[] = [];
  for (let i = zeros; i < str.length; i++) {
    const value = BASE58_ALPHABET.indexOf(str[i]);
    if (value === -1) throw new Error(`invalid base58 character: ${str[i]}`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + bytes.length - 1 - i] = bytes[i];
  return out;
}

/** Multibase base58btc encode (the 'z' prefix), the encoding W3C Data Integrity uses
 *  for `proofValue` and `publicKeyMultibase`. */
export function multibaseBase58btcEncode(bytes: Uint8Array): string {
  return `z${base58Encode(bytes)}`;
}

/** Inverse of `multibaseBase58btcEncode`. Throws if the 'z' multibase prefix is absent. */
export function multibaseBase58btcDecode(str: string): Uint8Array {
  if (!str.startsWith("z")) throw new Error("not a base58btc multibase string (expected 'z' prefix)");
  return base58Decode(str.slice(1));
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string must have an even length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error("invalid hex string");
    out[i] = byte;
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Express an agentId (raw 32-byte ed25519 public key, hex) as a did:key. The result
 *  is a self-certifying DID: it resolves to the same key with no registry lookup. */
export function agentIdToDidKey(agentId: string): string {
  const raw = hexToBytes(agentId);
  if (raw.length !== 32) throw new Error("agentId must be a 32-byte ed25519 public key (64 hex chars)");
  const prefixed = new Uint8Array(MULTICODEC_ED25519_PUB.length + raw.length);
  prefixed.set(MULTICODEC_ED25519_PUB, 0);
  prefixed.set(raw, MULTICODEC_ED25519_PUB.length);
  return `did:key:z${base58Encode(prefixed)}`;
}

/** Inverse of `agentIdToDidKey`: decode a did:key back to the 64-hex agentId. Throws
 *  if the DID is not an ed25519 did:key (wrong method, prefix, or key length). */
export function didKeyToAgentId(did: string): string {
  const prefix = "did:key:z";
  if (!did.startsWith(prefix)) throw new Error("not a did:key with base58btc (z) multibase prefix");
  const decoded = base58Decode(did.slice(prefix.length));
  if (decoded[0] !== MULTICODEC_ED25519_PUB[0] || decoded[1] !== MULTICODEC_ED25519_PUB[1]) {
    throw new Error("did:key is not an ed25519 key (multicodec is not 0xed01)");
  }
  const raw = decoded.subarray(MULTICODEC_ED25519_PUB.length);
  if (raw.length !== 32) throw new Error("did:key payload is not a 32-byte ed25519 public key");
  return bytesToHex(raw);
}

export interface DidVerificationMethod {
  id: string;
  type: "Ed25519VerificationKey2020";
  controller: string;
  publicKeyMultibase: string;
}
export interface DidServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string;
}
export interface DidDocument {
  "@context": string[];
  id: string;
  verificationMethod: DidVerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  service?: DidServiceEndpoint[];
}

/** Emit a W3C DID Core document for an agentId. The id is the agent's did:key, the
 *  verification method is its ed25519 key (multibase), and — when a disclosure endpoint
 *  is given — a `service` entry of type `AgentDisclosure` points at it, so any DID-aware
 *  verifier resolves to the `.well-known/agent-disclosure` through standard rails. This
 *  COMPLEMENTS the raw-key model (it doesn't replace agentId with a DID); ADP stays
 *  DID-native-optional. */
export function agentIdToDidDocument(agentId: string, opts: { disclosureEndpoint?: string } = {}): DidDocument {
  const did = agentIdToDidKey(agentId); // also validates the 32-byte key
  const fragment = did.slice("did:key:".length);
  const vmId = `${did}#${fragment}`;
  const raw = hexToBytes(agentId);
  const prefixed = new Uint8Array(MULTICODEC_ED25519_PUB.length + raw.length);
  prefixed.set(MULTICODEC_ED25519_PUB, 0);
  prefixed.set(raw, MULTICODEC_ED25519_PUB.length);
  const doc: DidDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
    id: did,
    verificationMethod: [
      { id: vmId, type: "Ed25519VerificationKey2020", controller: did, publicKeyMultibase: multibaseBase58btcEncode(prefixed) },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
  if (opts.disclosureEndpoint) {
    doc.service = [{ id: `${did}#agent-disclosure`, type: "AgentDisclosure", serviceEndpoint: opts.disclosureEndpoint }];
  }
  return doc;
}

/** Construct a did:web identifier for a domain (optionally a path). did:web encodes
 *  the host as the method-specific id, with ':'-separated, percent-encoded path
 *  segments. The DID document is served out of band at
 *  https://<domain>/.well-known/did.json (no path) or https://<domain>/<path>/did.json. */
export function didWeb(domain: string, path?: string): string {
  if (!domain) throw new Error("did:web requires a domain");
  const host = encodeURIComponent(domain);
  if (!path) return `did:web:${host}`;
  const segments = path
    .split("/")
    .filter((s) => s.length > 0)
    .map((s) => encodeURIComponent(s));
  return `did:web:${host}:${segments.join(":")}`;
}

/** Translate a `did:web:...` identifier to the HTTPS URL its DID document is served at.
 *  Per the did:web method: no path → `https://<host>/.well-known/did.json`; with
 *  `:`-separated path segments → `https://<host>/<seg>/.../did.json`. Inverse of `didWeb`
 *  for URL construction. Throws if the input is not a did:web. */
export function didWebToUrl(did: string): string {
  const prefix = "did:web:";
  if (!did.startsWith(prefix)) throw new Error("not a did:web identifier");
  const parts = did.slice(prefix.length).split(":").map(decodeURIComponent);
  const host = parts[0];
  if (!host) throw new Error("did:web is missing a host");
  if (parts.length === 1) return `https://${host}/.well-known/did.json`;
  return `https://${host}/${parts.slice(1).join("/")}/did.json`;
}

// ── did:web resolution (optional, via web-did-resolver/did-resolver) ──────────
//
// `didWeb` / `agentIdToDidDocument` only CONSTRUCT a did:web; actually RESOLVING one
// means fetching the domain's did.json. ADP stays dep-light by default — the bespoke
// `resolveDidWebFetch` uses only `fetch` (built into Node ≥20). When the consumer wants
// the canonical W3C resolver (caching, did:web edge cases, a uniform `DIDResolver`
// surface), `resolveDidWebWithResolver` dynamically imports the OPTIONAL
// `web-did-resolver` + `did-resolver` packages. Neither is a required dependency.

export interface ResolveDidWebOptions {
  /** override the network fetch (tests / custom transports). Defaults to global `fetch`. */
  fetchImpl?: typeof fetch;
}

export interface DidWebResolution {
  ok: boolean;
  /** the resolved DID document (when ok). */
  document?: DidDocument;
  reason?: string;
}

/** Resolve a did:web with the built-in `fetch` only — no optional dep. Fetches the
 *  method's did.json URL and returns the parsed document. The returned `id` MUST equal
 *  the requested DID (binds the document to the identifier it was fetched for). */
export async function resolveDidWebFetch(
  did: string,
  opts: ResolveDidWebOptions = {},
): Promise<DidWebResolution> {
  let url: string;
  try {
    url = didWebToUrl(did);
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }
  const doFetch = opts.fetchImpl ?? (globalThis.fetch as typeof fetch | undefined);
  if (!doFetch) return { ok: false, reason: "no fetch implementation available" };

  let res: Response;
  try {
    res = await doFetch(url);
  } catch (e) {
    return { ok: false, reason: `did:web fetch failed: ${(e as Error).message}` };
  }
  if (!res.ok) return { ok: false, reason: `did:web fetch returned HTTP ${res.status}` };

  let document: DidDocument;
  try {
    document = (await res.json()) as DidDocument;
  } catch (e) {
    return { ok: false, reason: `did:web document is not valid JSON: ${(e as Error).message}` };
  }
  if (document.id !== did) {
    return { ok: false, reason: `did:web document id '${document.id}' does not match '${did}'` };
  }
  return { ok: true, document };
}

const DID_RESOLVER_HINT =
  "did:web resolution via the standard resolver needs web-did-resolver and did-resolver. " +
  "Install them: `npm install web-did-resolver did-resolver` (optional extras), or use " +
  "`resolveDidWebFetch` for the dep-free fetch path.";

// Overridable loader so tests can supply a mock without installing the optional packages.
type WebDidResolverModule = { getResolver: () => Record<string, unknown> };
type DidResolverModule = {
  Resolver: new (registry: Record<string, unknown>) => {
    resolve: (did: string) => Promise<{
      didDocument: DidDocument | null;
      didResolutionMetadata: { error?: string };
    }>;
  };
};

let webDidResolverLoader: () => Promise<WebDidResolverModule> = () =>
  import("web-did-resolver") as unknown as Promise<WebDidResolverModule>;
let didResolverLoader: () => Promise<DidResolverModule> = () =>
  import("did-resolver") as unknown as Promise<DidResolverModule>;

/** Test seam: inject mock `web-did-resolver` / `did-resolver` modules (so the optional
 *  path is exercised without installing them). Pass `undefined` to restore the real loaders. */
export function __setDidResolverLoaders(loaders: {
  webDidResolver?: () => Promise<WebDidResolverModule>;
  didResolver?: () => Promise<DidResolverModule>;
}): void {
  if (loaders.webDidResolver) webDidResolverLoader = loaders.webDidResolver;
  if (loaders.didResolver) didResolverLoader = loaders.didResolver;
}

/** Resolve a did:web via the OPTIONAL `web-did-resolver` + `did-resolver` packages — the
 *  canonical W3C `DIDResolver` surface. Same result shape as `resolveDidWebFetch`. Throws
 *  with an install hint if the optional deps are absent. */
export async function resolveDidWebWithResolver(did: string): Promise<DidWebResolution> {
  let webDid: WebDidResolverModule;
  let didRes: DidResolverModule;
  try {
    [webDid, didRes] = await Promise.all([webDidResolverLoader(), didResolverLoader()]);
  } catch {
    throw new Error(DID_RESOLVER_HINT);
  }
  const resolver = new didRes.Resolver(webDid.getResolver());
  const { didDocument, didResolutionMetadata } = await resolver.resolve(did);
  if (didResolutionMetadata.error || !didDocument) {
    return { ok: false, reason: didResolutionMetadata.error ?? "did:web resolution returned no document" };
  }
  return { ok: true, document: didDocument };
}
