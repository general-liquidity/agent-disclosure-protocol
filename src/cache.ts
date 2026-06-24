// Tiered verification + a validity-window cache. The proposal's economic thesis is
// that verification must be cheap enough to run before EVERY transaction. Two levers
// make it so: (1) tiering - a fast path (signature + freshness + the policy checks,
// all deterministic) vs a deep path (the live challenge-response handshake + a corpus
// re-run, which the caller adds via client.ts); (2) caching - a disclosure is
// constant within its own validity window, so a verifier that sees the same
// (agentId, nonce) again reuses the verdict at ~zero cost. See ./economics.ts for
// which markets that makes viable.
//
// Vendor-neutral. The cache is per-verifier: a verifier holds a fixed policy, so a
// cached verdict keyed by the disclosure instance is sound.

import { evaluateDisclosure, type VerificationPolicy, type DisclosureVerdict } from "./verify.ts";
import type { SignedDisclosure } from "./schema.ts";

export type VerificationTier = "cached" | "fresh";

export interface TieredVerdict {
  verdict: DisclosureVerdict;
  tier: VerificationTier;
}

interface CacheEntry {
  verdict: DisclosureVerdict;
  /** = disclosure.validUntil; the entry is dead once `now` passes it */
  cachedUntil: string;
}

/** A specific disclosure instance: agentId pins the signer, nonce pins the issuance. */
function cacheKey(signed: SignedDisclosure): string {
  return `${signed.disclosure.agentId}:${signed.disclosure.nonce}`;
}

export class VerificationCache {
  private readonly entries = new Map<string, CacheEntry>();

  /** Fast-path lookup. Returns the cached verdict only while the disclosure is still
   *  within its validity window (ISO-8601 strings compare lexically). */
  get(signed: SignedDisclosure, now: string): DisclosureVerdict | null {
    const hit = this.entries.get(cacheKey(signed));
    if (!hit) return null;
    if (now > hit.cachedUntil) {
      this.entries.delete(cacheKey(signed));
      return null;
    }
    return hit.verdict;
  }

  put(signed: SignedDisclosure, verdict: DisclosureVerdict): void {
    this.entries.set(cacheKey(signed), { verdict, cachedUntil: signed.disclosure.validUntil });
  }

  size(): number {
    return this.entries.size;
  }

  clear(): void {
    this.entries.clear();
  }
}

/**
 * The fast tier: serve a cached verdict when the same disclosure was already
 * verified within its window, otherwise evaluate the policy once and cache it. The
 * deep tier (live handshake) is the caller's job - run it on the cache miss or when
 * the stakes warrant it; see client.ts `verifyCounterparty`.
 */
export function verifyTiered(
  cache: VerificationCache,
  signed: SignedDisclosure,
  policy: VerificationPolicy,
): TieredVerdict {
  const cached = cache.get(signed, policy.now);
  if (cached) return { verdict: cached, tier: "cached" };
  const verdict = evaluateDisclosure(signed, policy);
  cache.put(signed, verdict);
  return { verdict, tier: "fresh" };
}
