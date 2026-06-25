// The verifier side, over the wire. Given a counterparty's base URL, fetch its
// signed disclosure, evaluate it against your policy, and run the live handshake -
// then decide transact / refuse before a single unit of value moves. This is the
// "before the transaction clears rather than after the loss" loop, end to end.
//
// Vendor-neutral: depends on the schema/verify/handshake + an injected fetch.

import { getDisclosure, parseAnySignedDisclosure, type AnySignedDisclosure } from "./schema.ts";
import { evaluateDisclosure, type VerificationPolicy, type DisclosureVerdict } from "./verify.ts";
import {
  createChallenge,
  randomNonce,
  verifyChallengeResponse,
  type ChallengeResponse,
  type HandshakeCheck,
} from "./handshake.ts";

export interface HttpResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}
export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<HttpResponse>;

export interface CounterpartyVerdict {
  decision: "transact" | "refuse";
  /** the static-disclosure policy result */
  disclosure: DisclosureVerdict;
  /** the live handshake result (omitted if disabled) */
  handshake?: HandshakeCheck;
  reasons: string[];
}

export interface VerifyCounterpartyOptions {
  /** run the live challenge-response (default true). Off = trust the static doc. */
  liveHandshake?: boolean;
  verifierId?: string;
}

/**
 * Verify a counterparty before transacting. Transacts only if BOTH the disclosure
 * clears the policy AND (when enabled) the live handshake proves current key
 * possession. Any transport/parse failure is a refuse - fail closed.
 */
export async function verifyCounterparty(
  fetch: FetchLike,
  baseUrl: string,
  policy: VerificationPolicy,
  opts: VerifyCounterpartyOptions = {},
): Promise<CounterpartyVerdict> {
  const base = baseUrl.replace(/\/$/, "");
  const refuse = (reason: string, disclosure?: DisclosureVerdict): CounterpartyVerdict => ({
    decision: "refuse",
    disclosure: disclosure ?? { decision: "refuse", checks: {}, reasons: [reason], cost: { checksRun: 0, wallMicros: 0 } },
    reasons: [reason],
  });

  // 1. Fetch + structurally parse the disclosure (either envelope shape).
  let signed: AnySignedDisclosure;
  try {
    const res = await fetch(`${base}/.well-known/agent-disclosure`);
    if (!res.ok) return refuse(`disclosure fetch failed (HTTP ${res.status})`);
    signed = parseAnySignedDisclosure(await res.json());
  } catch (e) {
    return refuse(`disclosure unreachable: ${e instanceof Error ? e.message : String(e)}`);
  }

  // 2. Evaluate the disclosure against policy (signature, freshness, the lot).
  const disclosure = evaluateDisclosure(signed, policy);
  const reasons = [...disclosure.reasons];
  const doc = getDisclosure(signed);

  // 3. Live handshake — defeats replay of a captured (valid) disclosure.
  let handshake: HandshakeCheck | undefined;
  if (opts.liveHandshake !== false) {
    const challenge = createChallenge(policy.now, { nonce: randomNonce(), verifierId: opts.verifierId });
    try {
      const res = await fetch(`${base}/agent-disclosure/respond`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(challenge),
      });
      const response = (await res.json()) as ChallengeResponse;
      handshake = verifyChallengeResponse(response, challenge, {
        expectedAgentId: doc.agentId,
        disclosureAnchor: doc.auditAnchor,
        now: policy.now,
      });
    } catch (e) {
      handshake = { ok: false, reason: `handshake unreachable: ${e instanceof Error ? e.message : String(e)}` };
    }
    if (!handshake.ok) reasons.push(`handshake: ${handshake.reason}`);
  }

  return {
    decision: reasons.length === 0 ? "transact" : "refuse",
    disclosure,
    handshake,
    reasons,
  };
}
