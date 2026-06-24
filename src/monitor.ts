// Disclosure monitoring: diff two snapshots of the same agent's disclosure and
// flag SECURITY-RELEVANT regressions. A counterparty that verified once should not
// silently inherit a weaker posture later (a constitution that stopped being
// enforced, a red-team grade that fell, custody that flipped). diffDisclosures
// surfaces the changes; detectDowngrade is the alarm on the directional ones.

import type { AgentDisclosure } from "./schema.ts";

/** A single observed change between two disclosure snapshots. */
export interface DisclosureChange {
  /** dotted path of the field that changed, e.g. "constitution.enforced" */
  field: string;
  from: unknown;
  to: unknown;
}

// Grade ordering: A is strongest, F weakest. Index = strength rank (lower = better).
const GRADE_ORDER = ["A", "B", "C", "D", "F"] as const;
const ATTESTATION_ORDER = ["none", "signed", "registry_attested"] as const;

function gradeRank(grade: string | undefined): number {
  if (grade === undefined) return GRADE_ORDER.length; // absent = weakest
  const i = GRADE_ORDER.indexOf(grade as (typeof GRADE_ORDER)[number]);
  return i === -1 ? GRADE_ORDER.length : i;
}

function attestationRank(level: string): number {
  const i = ATTESTATION_ORDER.indexOf(level as (typeof ATTESTATION_ORDER)[number]);
  return i === -1 ? 0 : i;
}

function constraintIds(d: AgentDisclosure): Set<string> {
  return new Set(d.constitution.hardConstraints.map((c) => c.id));
}

/** Structured diff of the security-relevant fields between two snapshots. Only the
 *  fields that gate trust are compared; cosmetic or volatile fields are ignored. */
export function diffDisclosures(prev: AgentDisclosure, next: AgentDisclosure): DisclosureChange[] {
  const changes: DisclosureChange[] = [];

  if (prev.constitution.enforced !== next.constitution.enforced) {
    changes.push({
      field: "constitution.enforced",
      from: prev.constitution.enforced,
      to: next.constitution.enforced,
    });
  }

  const prevGrade = prev.redTeam?.result.grade;
  const nextGrade = next.redTeam?.result.grade;
  if (prevGrade !== nextGrade) {
    changes.push({ field: "redTeam.grade", from: prevGrade, to: nextGrade });
  }

  if (prev.capital.custody !== next.capital.custody) {
    changes.push({
      field: "capital.custody",
      from: prev.capital.custody,
      to: next.capital.custody,
    });
  }

  const prevIds = constraintIds(prev);
  const nextIds = constraintIds(next);
  const removed = [...prevIds].filter((id) => !nextIds.has(id));
  const added = [...nextIds].filter((id) => !prevIds.has(id));
  if (removed.length > 0 || added.length > 0) {
    changes.push({
      field: "constitution.hardConstraints",
      from: [...prevIds].sort(),
      to: [...nextIds].sort(),
    });
  }

  if (prev.operator.attestation.level !== next.operator.attestation.level) {
    changes.push({
      field: "operator.attestation.level",
      from: prev.operator.attestation.level,
      to: next.operator.attestation.level,
    });
  }

  if (prev.systemPrompt.digest !== next.systemPrompt.digest) {
    changes.push({
      field: "systemPrompt.digest",
      from: prev.systemPrompt.digest,
      to: next.systemPrompt.digest,
    });
  }

  return changes;
}

/** The "silent constitution downgrade" alarm: flag DIRECTIONAL regressions in
 *  posture. An upgrade (e.g. grade D->A, attestation signed->registry_attested) is
 *  a change but not a downgrade. */
export function detectDowngrade(
  prev: AgentDisclosure,
  next: AgentDisclosure,
): { downgraded: boolean; reasons: string[] } {
  const reasons: string[] = [];

  if (prev.constitution.enforced && !next.constitution.enforced) {
    reasons.push("constitution.enforced went from true to false");
  }

  if (gradeRank(next.redTeam?.result.grade) > gradeRank(prev.redTeam?.result.grade)) {
    reasons.push(
      `redTeam grade decreased from ${prev.redTeam?.result.grade ?? "none"} to ${next.redTeam?.result.grade ?? "none"}`,
    );
  }

  if (prev.capital.custody === "non_custodial" && next.capital.custody === "custodial") {
    reasons.push("capital.custody went from non_custodial to custodial");
  }

  const prevIds = constraintIds(prev);
  const nextIds = constraintIds(next);
  const removed = [...prevIds].filter((id) => !nextIds.has(id));
  if (removed.length > 0) {
    reasons.push(`hard constraint(s) removed: ${removed.sort().join(", ")}`);
  }

  if (
    attestationRank(next.operator.attestation.level) <
    attestationRank(prev.operator.attestation.level)
  ) {
    reasons.push(
      `operator attestation level decreased from ${prev.operator.attestation.level} to ${next.operator.attestation.level}`,
    );
  }

  return { downgraded: reasons.length > 0, reasons };
}
