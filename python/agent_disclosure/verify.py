"""Counterparty verification layer. Port of `src/verify.ts`.

Given a signed disclosure and a verifier policy, produce a transact/refuse
verdict with a per-check pass/fail map. Refuses if any required check fails;
reports every failed check (sorted-name comparison is the conformance contract).
"""

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .attestation import verify_disclosure_signature, is_fresh

GRADE_RANK = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
ATTESTATION_RANK = {"none": 0, "signed": 1, "registry_attested": 2}


@dataclass
class VerificationPolicy:
    now: str
    require_valid_signature: bool = True
    require_fresh: bool = True
    require_enforced_constitution: bool = False
    required_hard_constraints: Optional[list] = None
    require_red_team: bool = False
    min_red_team_grade: Optional[str] = None
    max_red_team_hard_fails: Optional[int] = None
    require_non_custodial: bool = False
    min_attestation_level: Optional[str] = None
    require_deployment_history: bool = False
    require_audit_anchor: bool = False
    require_model_fingerprint: bool = False
    allowed_model_digests: Optional[list] = None
    require_provenance_for: Optional[list] = None
    is_revoked: Optional[Callable[[str], bool]] = None
    operator_reputation: Optional[Callable[[str], float]] = None
    min_operator_reputation: Optional[float] = None

    @classmethod
    def from_json(cls, p: dict) -> "VerificationPolicy":
        """Build a policy from the camelCase JSON form used in the fixtures."""
        return cls(
            now=p["now"],
            require_valid_signature=p.get("requireValidSignature", True),
            require_fresh=p.get("requireFresh", True),
            require_enforced_constitution=p.get("requireEnforcedConstitution", False),
            required_hard_constraints=p.get("requiredHardConstraints"),
            require_red_team=p.get("requireRedTeam", False),
            min_red_team_grade=p.get("minRedTeamGrade"),
            max_red_team_hard_fails=p.get("maxRedTeamHardFails"),
            require_non_custodial=p.get("requireNonCustodial", False),
            min_attestation_level=p.get("minAttestationLevel"),
            require_deployment_history=p.get("requireDeploymentHistory", False),
            require_audit_anchor=p.get("requireAuditAnchor", False),
            require_model_fingerprint=p.get("requireModelFingerprint", False),
            allowed_model_digests=p.get("allowedModelDigests"),
            require_provenance_for=p.get("requireProvenanceFor"),
        )


@dataclass
class Verdict:
    decision: str  # "transact" | "refuse"
    checks: dict
    reasons: list
    cost: dict = field(default_factory=dict)

    @property
    def failed(self) -> list:
        """Sorted names of checks that failed — the conformance comparison key."""
        return sorted(name for name, ok in self.checks.items() if not ok)


def evaluate_disclosure(signed: dict, policy: VerificationPolicy) -> Verdict:
    started_at = time.perf_counter()
    checks: dict = {}
    reasons: list = []

    def fail(name: str, reason: str) -> None:
        checks[name] = False
        reasons.append(reason)

    def passed(name: str) -> None:
        checks[name] = True

    d = signed["disclosure"]

    # signature (default on)
    if policy.require_valid_signature is not False:
        ok, reason = verify_disclosure_signature(signed)
        passed("signature") if ok else fail("signature", f"signature invalid: {reason}")

    # freshness (default on)
    if policy.require_fresh is not False:
        if is_fresh(d, policy.now):
            passed("freshness")
        else:
            fail("freshness", f"disclosure not fresh (valid until {d['validUntil']})")

    if policy.require_enforced_constitution:
        if d["constitution"]["enforced"]:
            passed("enforcedConstitution")
        else:
            fail("enforcedConstitution", "constitution is declared but not enforced at runtime")

    if policy.required_hard_constraints:
        present = {c["id"] for c in d["constitution"]["hardConstraints"]}
        missing = [cid for cid in policy.required_hard_constraints if cid not in present]
        if not missing:
            passed("requiredHardConstraints")
        else:
            fail("requiredHardConstraints", f"missing required hard constraints: {', '.join(missing)}")

    red_team = d.get("redTeam")
    if policy.require_red_team and not red_team:
        fail("redTeamPresent", "no red-team attestation")
    elif red_team:
        if policy.min_red_team_grade:
            if GRADE_RANK[red_team["result"]["grade"]] >= GRADE_RANK[policy.min_red_team_grade]:
                passed("redTeamGrade")
            else:
                fail(
                    "redTeamGrade",
                    f"red-team grade {red_team['result']['grade']} below minimum {policy.min_red_team_grade}",
                )
        max_fails = policy.max_red_team_hard_fails if policy.max_red_team_hard_fails is not None else 0
        if len(red_team["result"]["hardFails"]) <= max_fails:
            passed("redTeamHardFails")
        else:
            fail(
                "redTeamHardFails",
                f"red-team hard-fails {len(red_team['result']['hardFails'])} exceed max {max_fails}",
            )

    if policy.require_non_custodial:
        if d["capital"]["custody"] == "non_custodial":
            passed("nonCustodial")
        else:
            fail("nonCustodial", "operation is custodial")

    if policy.min_attestation_level:
        level = d["operator"]["attestation"]["level"]
        if ATTESTATION_RANK[level] >= ATTESTATION_RANK[policy.min_attestation_level]:
            passed("attestationLevel")
        else:
            fail("attestationLevel", f"attestation level {level} below {policy.min_attestation_level}")

    if policy.require_deployment_history:
        if d["history"]["summary"]["totalDecisions"] > 0:
            passed("deploymentHistory")
        else:
            fail("deploymentHistory", "no deployment history")

    if policy.require_audit_anchor:
        if d.get("auditAnchor"):
            passed("auditAnchor")
        else:
            fail("auditAnchor", "disclosure is not bound to an audit anchor")

    if policy.require_model_fingerprint:
        if d.get("model"):
            passed("modelFingerprint")
        else:
            fail("modelFingerprint", "no declared model identity")

    if policy.allowed_model_digests:
        model = d.get("model")
        if model and model["digest"] in policy.allowed_model_digests:
            passed("modelDigest")
        else:
            fail(
                "modelDigest",
                "declared model digest is not in the allowed set" if model else "no declared model to match",
            )

    if policy.require_provenance_for:
        prov = d.get("provenance") or {}
        missing = [f for f in policy.require_provenance_for if not prov.get(f)]
        if not missing:
            passed("provenance")
        else:
            fail("provenance", f"missing provenance for: {', '.join(missing)}")

    if policy.is_revoked:
        if policy.is_revoked(d["disclosureId"]) or policy.is_revoked(d["agentId"]):
            fail("revocation", "disclosure or agent identity is revoked")
        else:
            passed("revocation")

    if policy.operator_reputation and policy.min_operator_reputation is not None:
        score = policy.operator_reputation(d["operator"]["operatorId"])
        if score >= policy.min_operator_reputation:
            passed("operatorReputation")
        else:
            fail("operatorReputation", f"operator reputation {score:.2f} below minimum {policy.min_operator_reputation}")

    wall_micros = round((time.perf_counter() - started_at) * 1_000_000)
    return Verdict(
        decision="transact" if not reasons else "refuse",
        checks=checks,
        reasons=reasons,
        cost={"checksRun": len(checks), "wallMicros": wall_micros},
    )
