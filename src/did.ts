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
