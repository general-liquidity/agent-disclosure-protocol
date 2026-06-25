"""Counterparty verification layer. Port of `src/verify.ts`.

Given a signed disclosure and a verifier policy, produce a transact/refuse
verdict with a per-check pass/fail map. Refuses if any required check fails;
reports every failed check (sorted-name comparison is the conformance contract).
"""

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .attestation import (
    verify_any_disclosure_signature,
    disclosure_of,
    is_jws_signed_disclosure,
    is_fresh,
)

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

    # Either envelope shape (v1 object or v2 flattened JWS); the disclosure document
    # is the same JCS document under both, so every policy check below is unchanged.
    d = disclosure_of(signed)

    # signature (default on)
    if policy.require_valid_signature is not False:
        ok, reason = verify_any_disclosure_signature(signed)
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


def evaluate_raw(raw: str, policy: Optional[VerificationPolicy] = None) -> Verdict:
    """Parse an untrusted raw JSON string and evaluate it in one call.

    Fail-closed mirror of the TS `verifyAndEvaluate`: any parse error or
    structural defect is surfaced as a `refuse` verdict with a `schema` check
    set to False, never an exception. `now` defaults to issue-time epoch so a
    caller need not supply a policy just to reject garbage.
    """
    if policy is None:
        policy = VerificationPolicy(now="1970-01-01T00:00:00.000Z")
    try:
        signed = json.loads(raw)
    except Exception as e:  # noqa: BLE001 — fail closed on any parser fault
        return Verdict(
            decision="refuse",
            checks={"schema": False},
            reasons=[f"malformed disclosure: {e}"],
            cost={"checksRun": 1, "wallMicros": 0},
        )
    try:
        _require_envelope_shape(signed)
        return evaluate_disclosure(signed, policy)
    except Exception as e:  # noqa: BLE001 — any defect is a safe rejection
        return Verdict(
            decision="refuse",
            checks={"schema": False},
            reasons=[f"malformed disclosure: {e}"],
            cost={"checksRun": 1, "wallMicros": 0},
        )


# Enum / literal closed sets, mirroring src/schema.ts. A disclosure can carry a
# valid ed25519 signature yet still be schema-INVALID (a malicious or buggy emitter
# signed a document outside the schema); these must reject on schema grounds, so
# the check runs in the structural path BEFORE the signature is consulted.
_KNOWN_ATTESTATION_SCHEMES = frozenset({"AIP", "VisaTAP", "ERC8004", "DID", "none"})
_ATTESTATION_LEVELS = frozenset({"none", "signed", "registry_attested"})
_CUSTODY = frozenset({"non_custodial", "custodial"})
# Reverse-domain namespace id (e.g. "com.visa.tap"): at least one dot, so a bare word
# is NOT valid. Mirrors the `ReverseDomain` regex in schema.ts.
_REVERSE_DOMAIN = re.compile(r"^[a-z0-9]+(\.[a-z0-9-]+)+$")


def _validate_disclosure_schema(disclosure: dict) -> None:
    """Mirror the closed enums / literals of AgentDisclosureSchema (src/schema.ts).
    Raises ValueError on the first violation so `evaluate_raw` rejects without
    consulting the (possibly valid) signature."""
    if disclosure.get("version") != 1:
        raise ValueError("disclosure.version must be the literal 1")

    custody = disclosure.get("capital", {}).get("custody")
    if custody not in _CUSTODY:
        raise ValueError(f"capital.custody must be one of {sorted(_CUSTODY)}")

    attestation = disclosure.get("operator", {}).get("attestation", {})
    scheme = attestation.get("scheme")
    if scheme not in _KNOWN_ATTESTATION_SCHEMES and not (
        isinstance(scheme, str) and _REVERSE_DOMAIN.match(scheme)
    ):
        raise ValueError("operator.attestation.scheme must be a known value or a reverse-domain id")
    if attestation.get("level") not in _ATTESTATION_LEVELS:
        raise ValueError(f"operator.attestation.level must be one of {sorted(_ATTESTATION_LEVELS)}")

    if disclosure.get("systemPrompt", {}).get("algorithm") != "sha256":
        raise ValueError("systemPrompt.algorithm must be the literal 'sha256'")


def _require_envelope_shape(signed: Any) -> None:
    """Minimal structural gate so a defect raises here (caught by `evaluate_raw`)
    rather than producing an undefined verdict. Deep field validation is left to
    the signature check, which fails closed on any tamper or type error."""
    if not isinstance(signed, dict):
        raise TypeError("envelope must be a JSON object")
    disclosure = signed.get("disclosure")
    signature = signed.get("signature")
    if not isinstance(disclosure, dict):
        raise TypeError("missing or non-object 'disclosure'")
    if not isinstance(signature, dict):
        raise TypeError("missing or non-object 'signature'")
    if signature.get("algorithm") != "ed25519":
        raise ValueError("signature.algorithm must be 'ed25519'")
    for key in ("publicKey", "value"):
        if not isinstance(signature.get(key), str):
            raise TypeError(f"signature.{key} must be a string")
    if not isinstance(disclosure.get("agentId"), str):
        raise TypeError("disclosure.agentId must be a string")
    if disclosure["agentId"] != signature["publicKey"]:
        raise ValueError("agentId does not match the signing public key")
    _validate_disclosure_schema(disclosure)


def verify_raw(raw: str, policy: Optional[VerificationPolicy] = None) -> bool:
    """Returns True if the raw input is REJECTED (refused), False if it would
    transact. Never raises on any input — JSON parse error, missing keys, wrong
    types, agentId/publicKey mismatch, non-hex or bad signature all reject."""
    try:
        return evaluate_raw(raw, policy).decision != "transact"
    except Exception:  # noqa: BLE001 — last-resort guard; rejection is always safe
        return True
