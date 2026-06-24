// Transparency witness / consistency monitor. A witness watches a TransparencyLog
// and detects split-views: an operator presenting one history to one verifier and a
// divergent history to another (or silently rewriting an entry it already showed).
// The log is hash-linked and append-only, so an honest update can only EXTEND what a
// witness last saw - the older head must be a prefix of the newer chain. Any entry
// that differs at an index the witness has already pinned is a history-rewrite alarm.

import { canonicalize, sha256Hex } from "./attestation.ts";
import type { TransparencyLog, TransparencyLogEntry } from "./transparency.ts";

const GENESIS = "0".repeat(64);

function hashEntry(e: TransparencyLogEntry): string {
  return sha256Hex(
    canonicalize({
      index: e.index,
      disclosureDigest: e.disclosureDigest,
      agentId: e.agentId,
      issuedAt: e.issuedAt,
      prevHash: e.prevHash,
    }),
  );
}

export interface ConsistencyProof {
  /** the head the proof extends FROM (head at oldSize) */
  oldHead: string;
  /** the head after the appended entries */
  newHead: string;
  /** the entries appended since oldSize, in order */
  entries: TransparencyLogEntry[];
}

/** The entries appended to `log` since it had `oldSize` entries, plus the old and new
 *  head hashes. The witness replays these to confirm the log only grew. */
export function consistencyProof(log: TransparencyLog, oldSize: number): ConsistencyProof {
  const all = log.entries();
  const oldHead =
    oldSize <= 0 ? GENESIS : oldSize > all.length ? log.head() : all[oldSize - 1].hash;
  return {
    oldHead,
    newHead: log.head(),
    entries: all.slice(oldSize).map((e) => ({ ...e })),
  };
}

/** Confirm a consistency proof: the appended entries hash-chain forward, the first
 *  one extends `oldHead` (so the old head is a prefix of the newer chain), and the
 *  final link equals the claimed newHead. An empty proof is valid iff newHead == oldHead. */
export function verifyConsistency(oldHead: string, proof: ConsistencyProof): boolean {
  if (proof.oldHead !== oldHead) return false;
  if (proof.entries.length === 0) return proof.newHead === oldHead;

  let prevHash = oldHead;
  for (const e of proof.entries) {
    if (e.prevHash !== prevHash) return false;
    if (hashEntry(e) !== e.hash) return false;
    prevHash = e.hash;
  }
  return prevHash === proof.newHead;
}

export interface AppendOnlyCheck {
  ok: boolean;
  reason?: string;
}

/** A witness remembers the last head it saw per agentId, so it can catch an operator
 *  re-presenting a divergent or shortened history (a split-view). */
export class Witness {
  readonly #lastHead = new Map<string, { head: string; size: number }>();

  /** Record the current head + size of `log` for `agentId`. Call after a successful
   *  append-only check to advance the pin. */
  observe(agentId: string, log: TransparencyLog): void {
    this.#lastHead.set(agentId, { head: log.head(), size: log.entries().length });
  }

  /** Last head pinned for an agent, or GENESIS if never seen. */
  lastHead(agentId: string): string {
    return this.#lastHead.get(agentId)?.head ?? GENESIS;
  }

  /** Flag if a re-presented `log` does NOT extend what the witness last saw for this
   *  agent. A fresh agent (no pin) is trivially consistent. A log shorter than the
   *  pinned size, or one whose entry at the pinned boundary differs, is a rewrite. */
  checkAppendOnly(agentId: string, log: TransparencyLog): AppendOnlyCheck {
    const pinned = this.#lastHead.get(agentId);
    if (!pinned) return { ok: true };

    const all = log.entries();
    if (all.length < pinned.size) {
      return { ok: false, reason: "log shortened: fewer entries than last observed" };
    }
    const boundary = pinned.size === 0 ? GENESIS : all[pinned.size - 1]?.hash;
    if (boundary !== pinned.head) {
      return { ok: false, reason: "split-view: history rewritten before the last observed head" };
    }
    const proof = consistencyProof(log, pinned.size);
    if (!verifyConsistency(pinned.head, proof)) {
      return { ok: false, reason: "appended entries do not extend the last observed head" };
    }
    return { ok: true };
  }
}
