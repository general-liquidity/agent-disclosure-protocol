// Transparency log - Certificate-Transparency-for-agents. An append-only,
// hash-linked log of disclosure digests so disclosures are third-party auditable
// and re-issuance is publicly visible (a counterparty can watch the log and notice
// when an agent silently re-issues under the same identity). Mirrors core/audit.ts:
// each entry commits to the previous entry's hash, so any post-hoc edit, insertion,
// or deletion breaks the recomputed chain.

import { canonicalize, sha256Hex } from "./attestation.ts";
import type { SignedDisclosure } from "./schema.ts";

const GENESIS = "0".repeat(64);

export interface TransparencyLogEntry {
  index: number;
  disclosureDigest: string;
  agentId: string;
  issuedAt: string;
  prevHash: string;
  hash: string;
}

function hashEntry(
  index: number,
  disclosureDigest: string,
  agentId: string,
  issuedAt: string,
  prevHash: string,
): string {
  return sha256Hex(canonicalize({ index, disclosureDigest, agentId, issuedAt, prevHash }));
}

export class TransparencyLog {
  readonly #entries: TransparencyLogEntry[] = [];

  /** Append a signed disclosure's digest. The digest commits to the disclosure
   *  document (not the signature), so re-issuance under a fresh signature with the
   *  same content is detectable and a changed document yields a new digest. */
  append(signed: SignedDisclosure): TransparencyLogEntry {
    const index = this.#entries.length;
    const prevHash = index === 0 ? GENESIS : this.#entries[index - 1].hash;
    const disclosureDigest = sha256Hex(canonicalize(signed.disclosure));
    const { agentId, issuedAt } = signed.disclosure;
    const entry: TransparencyLogEntry = {
      index,
      disclosureDigest,
      agentId,
      issuedAt,
      prevHash,
      hash: hashEntry(index, disclosureDigest, agentId, issuedAt, prevHash),
    };
    this.#entries.push(entry);
    return entry;
  }

  entries(): readonly TransparencyLogEntry[] {
    return this.#entries;
  }

  /** Current head hash - what a watcher pins to detect any later mutation. */
  head(): string {
    return this.#entries.length === 0 ? GENESIS : this.#entries[this.#entries.length - 1].hash;
  }

  /** Recompute the whole chain: link integrity + content hash on every entry. */
  verify(): { ok: boolean; brokenAt?: number } {
    let prevHash = GENESIS;
    for (const e of this.#entries) {
      if (e.prevHash !== prevHash) return { ok: false, brokenAt: e.index };
      const expected = hashEntry(e.index, e.disclosureDigest, e.agentId, e.issuedAt, e.prevHash);
      if (expected !== e.hash) return { ok: false, brokenAt: e.index };
      prevHash = e.hash;
    }
    return { ok: true };
  }

  contains(disclosureDigest: string): boolean {
    return this.#entries.some((e) => e.disclosureDigest === disclosureDigest);
  }

  /** Inclusion proof for an index: hand back the entry plus whether its hash
   *  recomputes from its own fields (a minimal, self-contained membership check). */
  inclusionProof(index: number): { entry: TransparencyLogEntry; recomputes: boolean } | null {
    const entry = this.#entries[index];
    if (!entry) return null;
    const recomputes =
      hashEntry(entry.index, entry.disclosureDigest, entry.agentId, entry.issuedAt, entry.prevHash) === entry.hash;
    return { entry, recomputes };
  }
}
