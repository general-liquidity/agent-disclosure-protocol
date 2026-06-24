// Mutual disclosure over the wire. A transaction between two agents clears only if
// EACH has verified the OTHER: each side fetches the counterparty's disclosure, runs
// its own policy, and runs the live handshake. `guard.ts` has the combiner; this runs
// both directions. Fail-closed - any refusing leg refuses the exchange.

import { verifyCounterparty, type FetchLike } from "./client.ts";
import { combineMutual, type MutualVerdict } from "./guard.ts";
import type { VerificationPolicy } from "./verify.ts";

export interface MutualVerifyOptions {
  /** how the counterparty reaches US (serves our disclosure + answers our handshake) */
  ourFetch: FetchLike;
  ourBaseUrl: string;
  /** how WE reach the counterparty */
  theirFetch: FetchLike;
  theirBaseUrl: string;
  /** what we require of them */
  ourPolicy: VerificationPolicy;
  /** what they require of us */
  theirPolicy: VerificationPolicy;
}

/** Both agents verify each other before either transacts. Transacts only if both
 *  directional verdicts clear; the two checks run concurrently. */
export async function mutualVerify(opts: MutualVerifyOptions): Promise<MutualVerdict> {
  const [ourViewOfThem, theirViewOfUs] = await Promise.all([
    verifyCounterparty(opts.theirFetch, opts.theirBaseUrl, opts.ourPolicy),
    verifyCounterparty(opts.ourFetch, opts.ourBaseUrl, opts.theirPolicy),
  ]);
  return combineMutual(ourViewOfThem, theirViewOfUs);
}
