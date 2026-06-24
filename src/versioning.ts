// Schema version negotiation. A disclosure carries `version`; a verifier that does
// not support a counterparty's version should refuse with a clear reason rather than
// fail an opaque parse. New major versions are added here as implementations adopt
// them, so a verifier can advertise what it understands.

import { DISCLOSURE_SCHEMA_VERSION } from "./schema.ts";

export const SUPPORTED_DISCLOSURE_VERSIONS: readonly number[] = [DISCLOSURE_SCHEMA_VERSION];

export function isSupportedVersion(version: unknown): version is number {
  return typeof version === "number" && SUPPORTED_DISCLOSURE_VERSIONS.includes(version);
}

/** Peek at the declared version of an untrusted signed envelope WITHOUT full schema
 *  validation. A strict parse rejects a future version outright; peeking first lets a
 *  verifier return "unsupported version N" before that, which is the actionable signal. */
export function peekDisclosureVersion(rawSigned: unknown): number | null {
  const v = (rawSigned as { disclosure?: { version?: unknown } } | null | undefined)?.disclosure?.version;
  return typeof v === "number" ? v : null;
}
