// W3C StatusList-aligned revocation (the StatusList2021 pattern). Instead of an
// explicit per-id entry list (see revocation.ts), status lives as a single bit per
// index in a compressed bitstring: a disclosure/credential carries a (url, index)
// reference, the verifier fetches the list once and checks one bit. This is the
// shape the verifiable-credentials world already speaks, so an ADP status list is
// interoperable with VC revocation tooling.

import { gunzipSync, gzipSync } from "node:zlib";
import { z } from "zod";

// Default bitstring length (in bits) of a fresh list; W3C uses a 16KB minimum
// (131072 bits) so a single index does not leak the population size. We grow on
// demand past this if a higher index is set.
const DEFAULT_SIZE_BITS = 131_072;

/** A compressed bitstring status list: one bit per index, bit set = revoked. */
export class StatusList {
  #bits: Uint8Array;

  constructor(sizeBits: number = DEFAULT_SIZE_BITS) {
    this.#bits = new Uint8Array(Math.ceil(sizeBits / 8));
  }

  /** Number of addressable indices in the list. */
  get size(): number {
    return this.#bits.length * 8;
  }

  #grow(minIndex: number): void {
    const needBytes = Math.floor(minIndex / 8) + 1;
    if (needBytes <= this.#bits.length) return;
    const next = new Uint8Array(needBytes);
    next.set(this.#bits);
    this.#bits = next;
  }

  setRevoked(index: number): void {
    if (index < 0 || !Number.isInteger(index))
      throw new Error("status index must be a non-negative integer");
    this.#grow(index);
    this.#bits[index >> 3] |= 1 << (index & 7);
  }

  isRevoked(index: number): boolean {
    if (index < 0 || !Number.isInteger(index))
      throw new Error("status index must be a non-negative integer");
    if (index >= this.size) return false;
    return (this.#bits[index >> 3] & (1 << (index & 7))) !== 0;
  }

  /** gzip the raw bitstring + base64-encode it - the W3C `encodedList` form. */
  encode(): string {
    return gzipSync(this.#bits).toString("base64");
  }

  /** Reconstruct a list from its `encodedList` form. */
  static decode(encoded: string): StatusList {
    const raw = gunzipSync(Buffer.from(encoded, "base64"));
    const list = new StatusList(raw.length * 8);
    list.#bits.set(raw);
    return list;
  }
}

/** The reference a disclosure/credential carries to point at one bit in a list. */
export const StatusListEntrySchema = z.object({
  statusListUrl: z.string(),
  statusListIndex: z.number().int().nonnegative(),
});

export type StatusListEntry = z.infer<typeof StatusListEntrySchema>;

/** Resolve an entry against a (already-fetched) list: true iff that index is set. */
export function checkStatus(entry: StatusListEntry, list: StatusList): boolean {
  return list.isRevoked(entry.statusListIndex);
}
