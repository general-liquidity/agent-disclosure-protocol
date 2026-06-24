// The counterparty verification layer. Given a signed disclosure and the verifier's
// own policy (what it requires of anyone it transacts with), produce a transact /
// refuse verdict with reasons. This is the "pluggable behavioural-trust layer" the
// rest of the agentic-commerce stack defers - made concrete and cheap to run.
//
// Vendor-neutral: operates on the schema + signature primitives only.

import { parseSignedDisclosure, type SignedDisclosure } from "./schema.ts";
import { verifyDisclosureSignature, isFresh } from "./attestation.ts";

export type Grade = "A" | "B" | "C" | "D" | "F";
const GRADE_RANK: Record<Grade, number> = { A: 4, B: 3, C: 2, D: 1, F: 0 };

export type AttestationLevel = "none" | "signed" | "registry_attested";
const ATTESTATION_RANK: Record<AttestationLevel, number> = {
  none: 0,
  signed: 1,
  registry_attested: 2,
};

/** What a verifier demands of a counterparty before transacting. Every field is
 *  optional; an empty policy only checks the signature + freshness (the baseline). */
export interface VerificationPolicy {
  /** clock for the freshness check (ISO-8601) */
  now: string;
  /** reject if the signature doesn't verify (default true) */
  requireValidSignature?: boolean;
  /** reject if outside [issuedAt, validUntil] (default true) */
  requireFresh?: boolean;
  /** the constitution must be ENFORCED at runtime, not merely declared */
  requireEnforcedConstitution?: boolean;
  /** these hard-constraint ids must be present in the constitution */
  requiredHardConstraints?: string[];
  /** the disclosure must carry a red-team attestation */
  requireRedTeam?: boolean;
  /** minimum acceptable red-team grade */
  minRedTeamGrade?: Grade;
  /** maximum tolerated red-team hard-fails (default 0) */
  maxRedTeamHardFails?: number;
  /** require non-custodial operation */
  requireNonCustodial?: boolean;
  /** minimum operator identity-attestation level */
  minAttestationLevel?: AttestationLevel;
  /** require a non-empty deployment history */
  requireDeploymentHistory?: boolean;
  /** require the disclosure be bound to an audit anchor (tamper-evidence) */
  requireAuditAnchor?: boolean;
  /** the disclosure must declare a model identity (model-swap defense, declared half) */
  requireModelFingerprint?: boolean;
  /** the declared model digest must be one of these (pin the counterparty's model) */
  allowedModelDigests?: string[];
  /** these top-level fields must carry provenance, so the verifier can weight them */
  requireProvenanceFor?: string[];
  /** revocation oracle: returns true if the disclosureId OR agentId is revoked.
   *  Injected so this layer stays vendor-neutral (see ./revocation.ts). */
  isRevoked?: (id: string) => boolean;
  /** operator reputation oracle (0..1), for the collusion / sock-puppet signal.
   *  The hard deny-list is the floor (requiredHardConstraints); reputation is the
   *  graded signal a colluding operator cannot fake without a track record. */
  operatorReputation?: (operatorId: string) => number;
  /** minimum operator reputation; only enforced when operatorReputation is supplied */
  minOperatorReputation?: number;
}

export interface DisclosureVerdict {
  decision: "transact" | "refuse";
  /** per-check pass/fail, for transparency */
  checks: Record<string, boolean>;
  /** human-readable failures (empty when transact) */
  reasons: string[];
  /** marginal-cost instrumentation: makes the proposal's economic thesis literal.
   *  `checksRun` is the number of policy predicates evaluated; `wallMicros` the
   *  wall time. Verification is deterministic + cheap, which is what lets it run
   *  before every transaction (see ./economics.ts). */
  cost: { checksRun: number; wallMicros: number };
}

/**
 * Evaluate a signed disclosure against a verifier's policy. Deterministic + cheap
 * (the proposal's economic point: verification has a low marginal cost). Refuses
 * on the FIRST principle that fails to hold but reports every failed check.
 */
export function evaluateDisclosure(
  signed: SignedDisclosure,
  policy: VerificationPolicy,
): DisclosureVerdict {
  const startedAt = performance.now();
  const checks: Record<string, boolean> = {};
  const reasons: string[] = [];
  const fail = (name: string, reason: string) => {
    checks[name] = false;
    reasons.push(reason);
  };
  const pass = (name: string) => {
    checks[name] = true;
  };

  const d = signed.disclosure;

  // signature (default on)
  if (policy.requireValidSignature !== false) {
    const sig = verifyDisclosureSignature(signed);
    sig.ok ? pass("signature") : fail("signature", `signature invalid: ${sig.reason}`);
  }

  // freshness (default on)
  if (policy.requireFresh !== false) {
    isFresh(d, policy.now)
      ? pass("freshness")
      : fail("freshness", `disclosure not fresh (valid until ${d.validUntil})`);
  }

  if (policy.requireEnforcedConstitution) {
    d.constitution.enforced
      ? pass("enforcedConstitution")
      : fail("enforcedConstitution", "constitution is declared but not enforced at runtime");
  }

  if (policy.requiredHardConstraints?.length) {
    const present = new Set(d.constitution.hardConstraints.map((c) => c.id));
    const missing = policy.requiredHardConstraints.filter((id) => !present.has(id));
    missing.length === 0
      ? pass("requiredHardConstraints")
      : fail("requiredHardConstraints", `missing required hard constraints: ${missing.join(", ")}`);
  }

  if (policy.requireRedTeam && !d.redTeam) {
    fail("redTeamPresent", "no red-team attestation");
  } else if (d.redTeam) {
    if (policy.minRedTeamGrade) {
      GRADE_RANK[d.redTeam.result.grade] >= GRADE_RANK[policy.minRedTeamGrade]
        ? pass("redTeamGrade")
        : fail("redTeamGrade", `red-team grade ${d.redTeam.result.grade} below minimum ${policy.minRedTeamGrade}`);
    }
    const maxFails = policy.maxRedTeamHardFails ?? 0;
    d.redTeam.result.hardFails.length <= maxFails
      ? pass("redTeamHardFails")
      : fail("redTeamHardFails", `red-team hard-fails ${d.redTeam.result.hardFails.length} exceed max ${maxFails}`);
  }

  if (policy.requireNonCustodial) {
    d.capital.custody === "non_custodial"
      ? pass("nonCustodial")
      : fail("nonCustodial", "operation is custodial");
  }

  if (policy.minAttestationLevel) {
    ATTESTATION_RANK[d.operator.attestation.level] >= ATTESTATION_RANK[policy.minAttestationLevel]
      ? pass("attestationLevel")
      : fail("attestationLevel", `attestation level ${d.operator.attestation.level} below ${policy.minAttestationLevel}`);
  }

  if (policy.requireDeploymentHistory) {
    d.history.summary.totalDecisions > 0
      ? pass("deploymentHistory")
      : fail("deploymentHistory", "no deployment history");
  }

  if (policy.requireAuditAnchor) {
    d.auditAnchor
      ? pass("auditAnchor")
      : fail("auditAnchor", "disclosure is not bound to an audit anchor");
  }

  // Declared model identity (the model-swap defense's declarable half).
  if (policy.requireModelFingerprint) {
    d.model ? pass("modelFingerprint") : fail("modelFingerprint", "no declared model identity");
  }
  if (policy.allowedModelDigests?.length) {
    d.model && policy.allowedModelDigests.includes(d.model.digest)
      ? pass("modelDigest")
      : fail("modelDigest", d.model ? "declared model digest is not in the allowed set" : "no declared model to match");
  }

  // Provenance: a verifier that weights claims can demand to know how a field was derived.
  if (policy.requireProvenanceFor?.length) {
    const prov = d.provenance ?? {};
    const missing = policy.requireProvenanceFor.filter((f) => !prov[f]);
    missing.length === 0
      ? pass("provenance")
      : fail("provenance", `missing provenance for: ${missing.join(", ")}`);
  }

  // Revocation: a compromised or decommissioned identity is refused even if the
  // (still-signed, still-fresh) disclosure looks valid.
  if (policy.isRevoked) {
    policy.isRevoked(d.disclosureId) || policy.isRevoked(d.agentId)
      ? fail("revocation", "disclosure or agent identity is revoked")
      : pass("revocation");
  }

  // Operator reputation (collusion / sock-puppet signal). The deny-list floor is the
  // hard guarantee; this is the graded signal that needs a real track record.
  if (policy.operatorReputation && policy.minOperatorReputation !== undefined) {
    const score = policy.operatorReputation(d.operator.operatorId);
    score >= policy.minOperatorReputation
      ? pass("operatorReputation")
      : fail("operatorReputation", `operator reputation ${score.toFixed(2)} below minimum ${policy.minOperatorReputation}`);
  }

  return {
    decision: reasons.length === 0 ? "transact" : "refuse",
    checks,
    reasons,
    cost: { checksRun: Object.keys(checks).length, wallMicros: Math.round((performance.now() - startedAt) * 1000) },
  };
}

/** Convenience: parse an untrusted JSON envelope and evaluate it in one call. */
export function verifyAndEvaluate(rawSigned: unknown, policy: VerificationPolicy): DisclosureVerdict {
  let signed: SignedDisclosure;
  try {
    signed = parseSignedDisclosure(rawSigned);
  } catch (e) {
    return {
      decision: "refuse",
      checks: { schema: false },
      reasons: [`malformed disclosure: ${e instanceof Error ? e.message : String(e)}`],
      cost: { checksRun: 1, wallMicros: 0 },
    };
  }
  return evaluateDisclosure(signed, policy);
}
