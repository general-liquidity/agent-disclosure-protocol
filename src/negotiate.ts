// Policy-driven selective disclosure.
//
// A verifier's VerificationPolicy implies a MINIMUM set of disclosure fields it must
// read to reach a verdict. This module maps the policy's predicates to that field set
// and produces a redacted view revealing exactly those - no more. That is the privacy
// + deniability boundary made operational: the agent discloses what the counterparty's
// policy needs and withholds the rest, while the signature still verifies over the
// full committed set (see redaction.ts).
//
// Vendor-neutral: composes the policy shape + the redaction primitives only.

import type { VerificationPolicy } from "./verify.ts";
import { reveal, verifyRedacted, type RedactableHolder, type RedactedView } from "./redaction.ts";

/** The top-level disclosure field each policy predicate reads. signature + freshness
 *  are checked against the always-clear meta, so they pull in NO redactable field. */
export function requiredFields(policy: VerificationPolicy): string[] {
  const fields = new Set<string>();

  if (policy.requireEnforcedConstitution || policy.requiredHardConstraints?.length) {
    fields.add("constitution");
  }
  if (policy.requireRedTeam || policy.minRedTeamGrade || policy.maxRedTeamHardFails !== undefined) {
    fields.add("redTeam");
  }
  if (policy.requireNonCustodial) fields.add("capital");
  if (policy.minAttestationLevel) fields.add("operator");
  if (policy.requireDeploymentHistory || policy.requireAuditAnchor) fields.add("history");
  if (policy.requireModelFingerprint || policy.allowedModelDigests?.length) fields.add("model");
  if (policy.requireProvenanceFor?.length) fields.add("provenance");

  return [...fields];
}

/** Reveal exactly the fields `policy` requires - the minimum disclosure for this
 *  verifier. Withheld fields stay as opaque, still-signed commitments. */
export function discloseFor(holder: RedactableHolder, policy: VerificationPolicy): RedactedView {
  return reveal(holder, requiredFields(policy));
}

/** Confirm a redacted view is sufficient for `policy`: the redaction itself verifies
 *  (signature + every revealed field recomputes) AND the revealed set covers every
 *  field the policy needs. `missing` names fields the policy requires that the holder
 *  did not (or could not) reveal. */
export function satisfiesPolicy(
  view: RedactedView,
  policy: VerificationPolicy,
): { ok: boolean; missing: string[] } {
  const result = verifyRedacted(view);
  if (!result.ok) {
    return { ok: false, missing: requiredFields(policy) };
  }

  const revealed = new Set(result.revealedFields);
  const missing = requiredFields(policy).filter((f) => !revealed.has(f));
  return { ok: missing.length === 0, missing };
}
