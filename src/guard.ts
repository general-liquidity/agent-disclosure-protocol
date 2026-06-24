// Outbound disclose-before-settle, plus mutual disclosure. The inbound side serves
// /.well-known/agent-disclosure; this is the other half - an agent about to SEND
// value first verifies the counterparty it is paying. Wire `guardSettlement` in
// front of a rail's settle() to refuse paying an agent that does not clear your
// policy, before any value moves.
//
// Vendor-neutral: composes the client + verify layers over an injected fetch.

import {
  verifyCounterparty,
  type FetchLike,
  type VerifyCounterpartyOptions,
  type CounterpartyVerdict,
} from "./client.ts";
import type { VerificationPolicy } from "./verify.ts";

export interface SettlementGuardResult {
  /** true iff the payee cleared the policy (and the live handshake, when enabled) */
  allow: boolean;
  verdict: CounterpartyVerdict;
}

/** Verify a payee before settling. `allow === (decision === "transact")`. Any
 *  transport/parse failure refuses - fail closed, the same stance as the gate. */
export async function guardSettlement(
  fetch: FetchLike,
  payeeBaseUrl: string,
  policy: VerificationPolicy,
  opts?: VerifyCounterpartyOptions,
): Promise<SettlementGuardResult> {
  const verdict = await verifyCounterparty(fetch, payeeBaseUrl, policy, opts);
  return { allow: verdict.decision === "transact", verdict };
}

// Mutual disclosure: a transaction between two agents clears only if EACH has
// verified the OTHER. Each side runs verifyCounterparty independently; this combines
// the two verdicts so neither party transacts on a one-sided check.
export interface MutualVerdict {
  decision: "transact" | "refuse";
  ourViewOfThem: CounterpartyVerdict;
  theirViewOfUs: CounterpartyVerdict;
  reasons: string[];
}

/** Combine the two directional verdicts. Transacts only if both sides cleared. */
export function combineMutual(
  ourViewOfThem: CounterpartyVerdict,
  theirViewOfUs: CounterpartyVerdict,
): MutualVerdict {
  const reasons = [
    ...ourViewOfThem.reasons.map((r) => `counterparty: ${r}`),
    ...theirViewOfUs.reasons.map((r) => `us: ${r}`),
  ];
  return {
    decision:
      ourViewOfThem.decision === "transact" && theirViewOfUs.decision === "transact"
        ? "transact"
        : "refuse",
    ourViewOfThem,
    theirViewOfUs,
    reasons,
  };
}
