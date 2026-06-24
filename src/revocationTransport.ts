// Revocation, over the wire. revocation.ts holds the status list + signed entries
// but has no transport: a verifier still has to FETCH a publisher's list and turn
// it into the oracle that VerificationPolicy.isRevoked consumes. This module is
// that seam - GET the list, wrap it, hand back a predicate.
//
// Fail-closed is the CALLER's call. fetchRevocationList rejects on an unreachable
// or malformed list rather than silently returning an empty (allow-all) list; the
// verifier decides whether a missing list blocks the transaction (treat unreachable
// as revoked) or degrades to a cached copy. We never fabricate a not-revoked answer
// from a transport failure.

import { RevocationList } from "./revocation.ts";
import type { FetchLike } from "./client.ts";

/** GET a publisher's status list and parse it via RevocationList.fromJSON. Throws
 *  on a non-200 or unparseable body - an unreachable list is NOT an empty list, so
 *  the caller chooses the fail-closed policy rather than inheriting allow-all. */
export async function fetchRevocationList(fetch: FetchLike, url: string): Promise<RevocationList> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`revocation list fetch failed (HTTP ${res.status})`);
  const raw = await res.json();
  if (!Array.isArray(raw)) throw new Error("revocation list body is not an array");
  return RevocationList.fromJSON(raw as Parameters<typeof RevocationList.fromJSON>[0]);
}

/** Wrap a list as the oracle VerificationPolicy.isRevoked expects: id -> revoked?.
 *  The id may be a disclosureId or an agentId (the list is keyed by either). */
export function revocationOracle(list: RevocationList): (id: string) => boolean {
  return (id) => list.isRevoked(id);
}

/** Fetch + wrap in one call - the convenience the verifier wires into its policy. */
export async function loadRevocationOracle(fetch: FetchLike, url: string): Promise<(id: string) => boolean> {
  return revocationOracle(await fetchRevocationList(fetch, url));
}

/** The JSON body a publisher serves at its status-list URL (the inverse of fetch). */
export function serveRevocationList(list: RevocationList): string {
  return JSON.stringify(list.toJSON());
}
