// Framework adapters - a drop-in "verify-before-pay" guard any agent stack can use.
// Zero extra deps: this builds on verifyCounterparty + zod (already a dependency) and
// emits a plain tool descriptor, so it registers directly into a Vercel AI SDK or
// Mastra tool set WITHOUT this package importing either of those frameworks.

import { z } from "zod";
import { verifyCounterparty, type FetchLike, type CounterpartyVerdict } from "./client.ts";
import type { VerificationPolicy } from "./verify.ts";

/** The result of the guard: a single allow/refuse boolean plus the full verdict for
 *  logging or display. `allow` is true iff the counterparty cleared the policy AND the
 *  live handshake - i.e. the verifier decided to transact. */
export interface VerifyBeforePayResult {
  allow: boolean;
  verdict: CounterpartyVerdict;
}

/**
 * The framework-agnostic guard. Call it before moving any value to `payeeBaseUrl`:
 * it fetches the payee's signed disclosure, evaluates it against your policy, runs the
 * live challenge-response handshake, and returns whether to proceed. `allow` mirrors
 * the verifier's transact/refuse decision - fail closed on any transport error.
 */
export async function verifyBeforePay(
  fetch: FetchLike,
  payeeBaseUrl: string,
  policy: VerificationPolicy,
): Promise<VerifyBeforePayResult> {
  const verdict = await verifyCounterparty(fetch, payeeBaseUrl, policy);
  return { allow: verdict.decision === "transact", verdict };
}

/** A plain tool descriptor - the common shape across the Vercel AI SDK and Mastra. We
 *  expose it structurally (name/description/inputSchema/execute) so neither framework
 *  needs to be a dependency; register it by spreading it where the framework expects a
 *  tool. `inputSchema` is a zod schema, which both frameworks accept directly. */
export interface VerifyCounterpartyTool {
  name: string;
  description: string;
  inputSchema: z.ZodObject<{ baseUrl: z.ZodString }>;
  execute: (input: { baseUrl: string }) => Promise<VerifyBeforePayResult>;
}

export interface CreateVerifyCounterpartyToolOptions {
  /** the policy every counterparty is held to before a payment is allowed */
  policy: VerificationPolicy;
  /** the transport. Defaults to global fetch adapted to FetchLike (Node 20+ has fetch). */
  fetch?: FetchLike;
}

/** Adapt the global fetch to the injected FetchLike shape used throughout this package. */
function globalFetch(): FetchLike {
  return async (url, init) => {
    const res = await fetch(url, init);
    return { ok: res.ok, status: res.status, json: () => res.json() };
  };
}

/**
 * Build a `verify_counterparty` tool an agent can call before paying. The tool takes a
 * single `baseUrl` and runs `verifyBeforePay` against the configured policy. Drop it
 * straight into a Vercel AI SDK `tools` map or a Mastra tool set.
 */
export function createVerifyCounterpartyTool(
  opts: CreateVerifyCounterpartyToolOptions,
): VerifyCounterpartyTool {
  const fetchImpl = opts.fetch ?? globalFetch();
  return {
    name: "verify_counterparty",
    description:
      "Verify a counterparty's signed agent disclosure before sending any payment. " +
      "Returns allow=true only if the disclosure clears the verifier policy and the live " +
      "handshake proves current key possession. Always call this before moving value.",
    inputSchema: z.object({ baseUrl: z.string() }),
    execute: ({ baseUrl }) => verifyBeforePay(fetchImpl, baseUrl, opts.policy),
  };
}
