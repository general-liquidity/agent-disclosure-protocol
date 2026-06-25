// Human Passport (formerly Gitcoin Passport) attestation scheme - a humanity / sybil-
// resistance reputation score as an operator attestation.
//
// Human Passport (https://passport.human.tech, the Human Tech "Passport") aggregates many
// identity "stamps" (each a verified credential - a held account, an on-chain history, a
// proof-of-personhood) into a single Unique Humanity Score. A score at or above a chosen
// threshold (the canonical default is 20) marks an address as "passing" / likely-unique;
// each stamp carries its own weight and a `dedup` flag (whether it was already counted for
// another address). The score is fetched from the Passport API (an `X-API-KEY` call) or read
// on-chain via EAS - NOT a local computation.
//
// GOTCHA: the Passport API returns `score` and `threshold` as numeric STRINGS. This
// attestation interface stores them as NUMBERS; the consumer's `scorer` is the boundary that
// parses the API's strings into numbers before they reach this module.
//
// Because the score is fetched (API / EAS), ADP does LIGHT recognition: STRUCTURAL validation
// of the attestation shape + an INJECTED scorer seam, exactly how `self.ts` / `worldid.ts`
// treat their heavy half. The disclosure schema's attestation `scheme` permits reverse-domain
// custom values, so Human Passport is recognized at the module level - the frozen enum is
// untouched.

import type { OperatorAttestation } from "./self.ts";

/** The module-level recognition name for the Human Passport scheme - the discriminant on a
 *  `HumanPassportAttestation` and the human-readable label. NOT the value written into a
 *  disclosure's `operator.attestation.scheme` (that field's open arm requires a reverse-domain
 *  id; see `HUMANPASSPORT_ATTESTATION_SCHEME`). The frozen schema enum is untouched. */
export const HUMANPASSPORT_SCHEME = "HumanPassport";

/** The reverse-domain id Human Passport maps to in a disclosure's `operator.attestation.scheme`
 *  (passport.human.tech reversed to a vendor namespace). The schema's attestation `scheme`
 *  accepts a known enum value OR a reverse-domain custom id; "HumanPassport" is not in the
 *  frozen enum, so the disclosure-field form is this namespaced id. */
export const HUMANPASSPORT_ATTESTATION_SCHEME = "tech.human.passport";

/** The canonical default Unique-Humanity passing threshold: an address scoring >= 20 is
 *  treated as likely-unique. A consumer may override per scorer call. */
export const HUMAN_THRESHOLD = 20;

/** A single Passport stamp's contribution: its weighted score, whether it was deduplicated
 *  against another address, and an optional expiry. */
export interface HumanPassportStamp {
  score: number;
  dedup: boolean;
  expiration_date?: string;
}

/** A Human Passport attestation: an address and its Unique Humanity Score. `score` /
 *  `threshold` are NUMBERS here (the API's numeric strings are parsed at the consumer's
 *  scorer boundary, not stored as strings). */
export interface HumanPassportAttestation {
  scheme: "HumanPassport";
  /** the scored EVM address (0x + 40 hex) */
  address: string;
  /** the Unique Humanity Score, parsed from the API's numeric string */
  score?: number;
  /** the passing threshold this score was evaluated against (default `HUMAN_THRESHOLD`) */
  threshold?: number;
  /** score >= threshold */
  passing?: boolean;
  /** the per-stamp breakdown, keyed by stamp provider id */
  stamps?: Record<string, HumanPassportStamp>;
  /** the `last_score_timestamp` (ISO-8601) the score was computed at */
  timestamp?: string;
}

/** Inject the heavy lookup (the Passport API `X-API-KEY` call or an EAS on-chain read). It
 *  receives the address and returns the live score; ADP bundles no implementation. The scorer
 *  is also the boundary that parses the API's numeric-string `score`/`threshold` into numbers. */
export type PassportScorer = (
  address: string,
) => Promise<{ score: number; passing?: boolean; threshold?: number }>;

export interface VerifyPassportOptions {
  scorer?: PassportScorer;
}

export interface PassportVerification {
  /** the structural shape is well-formed */
  structural: boolean;
  /** the score is at or above the threshold */
  passing: boolean;
  /** the score used for the verdict (embedded, or fetched when a scorer is injected) */
  score?: number;
  reason?: string;
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** STRUCTURAL validation: the right scheme, a 0x-prefixed 40-hex `address`, and - when
 *  present - finite numeric `score` / `threshold`. Shape-only; it does NOT fetch the live
 *  score (that is the injected scorer's job). */
export function validatePassportAttestation(att: HumanPassportAttestation): boolean {
  if (att.scheme !== HUMANPASSPORT_SCHEME) return false;
  if (typeof att.address !== "string" || !ADDRESS.test(att.address)) return false;
  if (att.score !== undefined && !Number.isFinite(att.score)) return false;
  if (att.threshold !== undefined && !Number.isFinite(att.threshold)) return false;
  return true;
}

/** Verify a Human Passport attestation.
 *
 *  STRUCTURAL (always): the shape is well-formed (`validatePassportAttestation`).
 *
 *  With a scorer (opt-in): fetch the live score, recompute `passing` against the threshold
 *  (the attestation's, else `HUMAN_THRESHOLD`), and use the scorer's verdict if it supplies
 *  one. Without a scorer: fall back to the embedded `score` / `passing` (crypto/network-
 *  pending, representable - it does NOT throw). */
export async function verifyPassportAttestation(
  att: HumanPassportAttestation,
  opts: VerifyPassportOptions = {},
): Promise<PassportVerification> {
  if (!validatePassportAttestation(att)) {
    return { structural: false, passing: false, reason: "Human Passport attestation is malformed" };
  }

  const threshold = att.threshold ?? HUMAN_THRESHOLD;

  if (opts.scorer !== undefined) {
    const live = await opts.scorer(att.address);
    const effectiveThreshold = live.threshold ?? threshold;
    const passing = live.passing ?? live.score >= effectiveThreshold;
    return { structural: true, passing, score: live.score };
  }

  // No scorer: use the embedded score / passing flag.
  const passing = att.passing ?? (att.score !== undefined ? att.score >= threshold : false);
  const out: PassportVerification = { structural: true, passing };
  if (att.score !== undefined) out.score = att.score;
  return out;
}

/** Map a Unique Humanity Score to an ADP recognition level. Banded against the threshold:
 *  >= 1.5x the threshold is `high` (a strong humanity signal), >= 1x is `medium` (passing),
 *  a present-but-below score is `low`, and an absent score is `unverified`. */
export function passportToAdpLevel(score?: number, threshold = HUMAN_THRESHOLD): string {
  if (score === undefined) return "unverified";
  if (score >= threshold * 1.5) return "high";
  if (score >= threshold) return "medium";
  return "low";
}

/** Map a verified Human Passport attestation into ADP's `operator.attestation` field. The
 *  scheme is the reverse-domain `HUMANPASSPORT_ATTESTATION_SCHEME` (the schema enum is
 *  frozen). A passing score is `signed` (a reputation attestation, not a registry record); a
 *  non-passing one is `none`. The score band (`passportToAdpLevel`) and the score are recorded
 *  as `evidence`. */
export function passportToOperatorAttestation(
  att: HumanPassportAttestation,
  result: PassportVerification,
): OperatorAttestation {
  if (!result.passing) return { scheme: HUMANPASSPORT_ATTESTATION_SCHEME, level: "none" };
  const score = result.score ?? att.score;
  const band = passportToAdpLevel(score, att.threshold ?? HUMAN_THRESHOLD);
  const out: OperatorAttestation = { scheme: HUMANPASSPORT_ATTESTATION_SCHEME, level: "signed" };
  if (score !== undefined) out.evidence = `humanpassport:${band}:${score}`;
  return out;
}
