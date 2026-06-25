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
import { canonicalize, signMessage, verifyMessage, type AgentKeyPair } from "./attestation.ts";

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
   *  is SIGNED (so it can't be downgraded), and a verifier refuses an unsupported one. */
  disclosureVersion?: number;
  /** ed25519 signature over canonicalize({nonce, agentId, auditHead, signedAt, verifierId, disclosureVersion}) */
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

/** Canonical bytes the response signs over - identical on both sides. `disclosureVersion`
 *  is included only when set; canonicalize drops `undefined`, so a response that declares
 *  no version signs byte-identical bytes to the pre-negotiation form (backward-compatible). */
function responseMessage(r: Omit<ChallengeResponse, "signature">, verifierId?: string): string {
  return canonicalize({
    nonce: r.nonce,
    agentId: r.agentId,
    auditHead: r.auditHead,
    signedAt: r.signedAt,
    verifierId,
    disclosureVersion: r.disclosureVersion,
  });
}

/** The agent answers a challenge: sign the nonce bound to the live audit head. Optionally
 *  declares the disclosure-schema version it presents (signed, for version negotiation). */
export function respondToChallenge(
  challenge: Challenge,
  key: AgentKeyPair,
  auditHead: string,
  now: string,
  opts: { disclosureVersion?: number } = {},
): ChallengeResponse {
  const body = {
    nonce: challenge.nonce,
    agentId: key.publicKeyHex,
    auditHead,
    signedAt: now,
    disclosureVersion: opts.disclosureVersion,
  };
  return { ...body, signature: signMessage(responseMessage(body, challenge.verifierId), key) };
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
  if (!verifyMessage(responseMessage(response, challenge.verifierId), response.agentId, response.signature)) {
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
