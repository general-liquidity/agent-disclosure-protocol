// Transparency log, over the wire. transparency.ts is in-memory only: it appends,
// hash-links, and proves inclusion, but a counterparty cannot SUBMIT a disclosure
// to a remote log or PULL a proof back. This module is the publish/fetch/verify
// seam - POST a disclosure to a log endpoint, GET a proof for a digest, and verify
// that proof standalone (recompute the entry hash from its own fields).
//
// Deferred extension: a full witness/gossip network - multiple witnesses
// co-signing the log head and gossiping it - is what defeats a log that serves
// different histories to different verifiers (a split-view attack). Out of scope
// here; this is the single-log transport the witness mesh would later layer on.

import { canonicalize, sha256Hex } from "./attestation.ts";
import type { SignedDisclosure } from "./schema.ts";
import type { TransparencyLogEntry } from "./transparency.ts";
import type { FetchLike } from "./client.ts";

/** POST a signed disclosure to a log endpoint; the log assigns + returns its entry. */
export async function submitToLog(
  fetch: FetchLike,
  url: string,
  signed: SignedDisclosure,
): Promise<TransparencyLogEntry> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(signed),
  });
  if (!res.ok) throw new Error(`log submit failed (HTTP ${res.status})`);
  return (await res.json()) as TransparencyLogEntry;
}

/** GET an inclusion proof for a disclosure digest. Null = the log has no such entry
 *  (a clean miss), distinct from a transport failure which throws. */
export async function fetchInclusionProof(
  fetch: FetchLike,
  url: string,
  disclosureDigest: string,
): Promise<TransparencyLogEntry | null> {
  const res = await fetch(`${url}?digest=${encodeURIComponent(disclosureDigest)}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`inclusion proof fetch failed (HTTP ${res.status})`);
  const raw = await res.json();
  return raw === null ? null : (raw as TransparencyLogEntry);
}

/** Verify a fetched proof standalone: recompute the entry hash from its own fields
 *  and confirm it matches. This catches a log that hands back a tampered entry; it
 *  does NOT prove the entry sits in the live chain (that needs the head + the link
 *  to prevHash, which a witness network would anchor). */
export function verifyInclusionProof(entry: TransparencyLogEntry): boolean {
  const expected = sha256Hex(
    canonicalize({
      index: entry.index,
      disclosureDigest: entry.disclosureDigest,
      agentId: entry.agentId,
      issuedAt: entry.issuedAt,
      prevHash: entry.prevHash,
    }),
  );
  return expected === entry.hash;
}
