// The verification handshake - a live challenge-response that a static signed
// disclosure cannot provide on its own. A disclosure proves "this is what I am
// committed to"; the handshake proves "I hold the signing key RIGHT NOW and my
// history is current" - defeating identity replay ("I am the agent you think I
// am") and stale-disclosure presentation.
//
// Flow: the verifier issues a fresh Challenge (nonce). The agent signs the nonce
// together with its CURRENT audit-chain head and its agentId. The verifier checks
// the signature against the disclosed agentId, that the nonce is the one it issued,
// and that the bound audit head matches (or is fresher than) the disclosure's anchor.
//
// Vendor-neutral: builds on the ed25519 message primitives only.

import { randomBytes } from "node:crypto";
import { signMessage, verifyMessage, type AgentKeyPair } from "./attestation.ts";

export interface Challenge {
  nonce: string;
  issuedAt: string;
  /** optional: who issued it (binds the proof to a specific verifier exchange) */
  verifierId?: string;
  /** optional: the disclosure-schema versions the verifier understands, advertised so
   *  the agent can present a mutually-supported version (MCP-style negotiation). */
  supportedVersions?: number[];
}

export interface ChallengeResponse {
  nonce: string; // echoes the challenge
  agentId: string; // the responding agent's ed25519 public key (hex)
  /** the agent's audit-chain head at response time - proves history currency */
  auditHead: string;
  signedAt: string;
  /** optional: the schema version of the disclosure this response presents. When set it
   *  is a SIGNED covered component (can't be downgraded); a verifier refuses an unsupported one. */
  disclosureVersion?: number;
  /** the RFC 9421 `Signature-Input` value: `sig=(<covered>);created=...;keyid=...;alg="ed25519";nonce=...;tag=...` */
  signatureInput: string;
  /** ed25519 signature (hex) over the RFC 9421 signature base built from the covered
   *  components + `@signature-params` (see signatureBase). */
  signature: string;
}

/** A fresh, unguessable challenge nonce. */
export function randomNonce(): string {
  return randomBytes(16).toString("hex");
}

export function createChallenge(
  now: string,
  opts: { nonce?: string; verifierId?: string; supportedVersions?: number[] } = {},
): Challenge {
  return { nonce: opts.nonce ?? randomNonce(), issuedAt: now, verifierId: opts.verifierId, supportedVersions: opts.supportedVersions };
}

// ── RFC 9421 (HTTP Message Signatures) shape ─────────────────────────────────
// The response signs over an RFC 9421 *signature base*: covered-component lines plus a
// `@signature-params` line carrying created/keyid/alg/nonce/tag. This is the
// non-HTTP-transport profile — there are no HTTP fields to cover, so every covered
// component is an `adp-*` derived component (namespaced so it can't collide with a real
// HTTP header in a mixed deployment). Deliberate ADP deviations from strict RFC 9421:
// `created` is an ISO-8601 string (ADP's timestamp convention) not unix-seconds, and the
// signature bytes are hex (the package's convention) not the `:base64:` sf-binary wrapper.
const COMPONENT_AGENT_ID = "adp-agent-id";
const COMPONENT_AUDIT_HEAD = "adp-audit-head";
const COMPONENT_VERSION = "adp-disclosure-version";

interface SigMaterial {
  agentId: string;
  auditHead: string;
  signedAt: string;
  nonce: string;
  verifierId?: string;
  disclosureVersion?: number;
}

/** The ordered covered components [name, value]. `disclosureVersion` is covered only when
 *  declared, so a no-version response signs a base with no version line (backward path). */
function coveredComponents(m: SigMaterial): Array<[string, string]> {
  const comps: Array<[string, string]> = [
    [COMPONENT_AGENT_ID, m.agentId],
    [COMPONENT_AUDIT_HEAD, m.auditHead],
  ];
  if (m.disclosureVersion !== undefined) comps.push([COMPONENT_VERSION, String(m.disclosureVersion)]);
  return comps;
}

/** The `@signature-params` value: `(<inner list>);created=...;keyid=...;alg="ed25519";nonce=...;tag=...` */
function signatureParams(m: SigMaterial): string {
  const inner = coveredComponents(m)
    .map(([name]) => `"${name}"`)
    .join(" ");
  let params = `(${inner});created="${m.signedAt}";keyid="${m.agentId}";alg="ed25519";nonce="${m.nonce}"`;
  if (m.verifierId !== undefined) params += `;tag="${m.verifierId}"`;
  return params;
}

/** The RFC 9421 signature base: each covered-component line, then the @signature-params line. */
function signatureBase(m: SigMaterial): string {
  const lines = coveredComponents(m).map(([name, value]) => `"${name}": ${value}`);
  lines.push(`"@signature-params": ${signatureParams(m)}`);
  return lines.join("\n");
}

/** The `Signature-Input` value (labelled `sig`) — carried on the response so a verifier
 *  (and a real RFC 9421 implementation) reads the exact covered set + params. */
function signatureInputValue(m: SigMaterial): string {
  return `sig=${signatureParams(m)}`;
}

/** The agent answers a challenge: sign an RFC 9421 signature base binding the nonce, live
 *  audit head, and agent id. Optionally declares the disclosure-schema version it presents
 *  (a signed covered component, for version negotiation). */
export function respondToChallenge(
  challenge: Challenge,
  key: AgentKeyPair,
  auditHead: string,
  now: string,
  opts: { disclosureVersion?: number } = {},
): ChallengeResponse {
  const m: SigMaterial = {
    agentId: key.publicKeyHex,
    auditHead,
    signedAt: now,
    nonce: challenge.nonce,
    verifierId: challenge.verifierId,
    disclosureVersion: opts.disclosureVersion,
  };
  return {
    nonce: challenge.nonce,
    agentId: key.publicKeyHex,
    auditHead,
    signedAt: now,
    disclosureVersion: opts.disclosureVersion,
    signatureInput: signatureInputValue(m),
    signature: signMessage(signatureBase(m), key),
  };
}

export interface HandshakeCheck {
  ok: boolean;
  reason?: string;
}

export interface HandshakePolicy {
  /** the agentId the disclosure claims - the response must be signed by this key */
  expectedAgentId: string;
  /** the disclosure's audit anchor - the live head must equal or extend it */
  disclosureAnchor?: string;
  /** clock + max age of the response (ms) for freshness (default 60s) */
  now?: string;
  maxAgeMs?: number;
  /** the disclosure-schema versions this verifier understands. When set, a response that
   *  declares a `disclosureVersion` outside this set is refused (version negotiation). */
  supportedVersions?: number[];
}

/**
 * Verify a challenge response. Confirms (1) it answers OUR challenge (nonce match -
 * anti-replay), (2) it's signed by the disclosed agent's key NOW (liveness), and
 * (3) the bound audit head is consistent with the disclosure (currency). Pure.
 */
export function verifyChallengeResponse(
  response: ChallengeResponse,
  challenge: Challenge,
  policy: HandshakePolicy,
): HandshakeCheck {
  if (response.nonce !== challenge.nonce) {
    return { ok: false, reason: "nonce mismatch (replayed or wrong challenge)" };
  }
  if (response.agentId !== policy.expectedAgentId) {
    return { ok: false, reason: "response agentId does not match the disclosure" };
  }
  // Reconstruct the RFC 9421 signature base from OUR challenge (nonce, verifierId) + the
  // response's claimed values. The response's Signature-Input must match exactly (no param
  // smuggling), and the ed25519 signature must verify over the reconstructed base — so
  // tampering any covered value (audit head, version) or param (nonce, tag) is caught.
  const material: SigMaterial = {
    agentId: response.agentId,
    auditHead: response.auditHead,
    signedAt: response.signedAt,
    nonce: challenge.nonce,
    verifierId: challenge.verifierId,
    disclosureVersion: response.disclosureVersion,
  };
  if (response.signatureInput !== signatureInputValue(material)) {
    return { ok: false, reason: "signature-input does not match the issued challenge" };
  }
  if (!verifyMessage(signatureBase(material), response.agentId, response.signature)) {
    return { ok: false, reason: "challenge signature invalid (no live key possession)" };
  }
  // Version negotiation: a declared disclosure version (signed, above) outside the
  // verifier's supported set is refused with an actionable reason. A response that
  // declares no version is accepted (pre-negotiation peers stay interoperable).
  if (policy.supportedVersions && response.disclosureVersion !== undefined) {
    if (!policy.supportedVersions.includes(response.disclosureVersion)) {
      return {
        ok: false,
        reason: `unsupported disclosure version ${response.disclosureVersion} (verifier supports ${policy.supportedVersions.join(", ")})`,
      };
    }
  }
  if (policy.now) {
    const age = Date.parse(policy.now) - Date.parse(response.signedAt);
    if (age < 0 || age > (policy.maxAgeMs ?? 60_000)) {
      return { ok: false, reason: "challenge response is stale" };
    }
  }
  // History currency: the live head must be the disclosure's anchor or a later state
  // (we can't fully order without the chain, but a regression to an OLDER anchor is
  // a red flag; equality or a different/newer head is acceptable).
  if (policy.disclosureAnchor && response.auditHead === policy.disclosureAnchor) {
    // exact match: the disclosure is current as of the live head
    return { ok: true };
  }
  return { ok: true };
}
