package agentdisclosure

import (
	"encoding/json"
)

var gradeRank = map[string]int{"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
var attestationRank = map[string]int{"none": 0, "signed": 1, "registry_attested": 2}

// mapAt returns the nested map[string]any at key k, or nil.
func mapAt(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	return v
}

// sliceAt returns the []any at key k, or nil.
func sliceAt(m map[string]any, k string) []any {
	v, _ := m[k].([]any)
	return v
}

// strAt returns the string at key k, or "".
func strAt(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

// boolAt returns the bool at key k, or false.
func boolAt(m map[string]any, k string) bool {
	v, _ := m[k].(bool)
	return v
}

// numAt returns the integer value at key k. Numbers arrive as json.Number when
// decoded with UseNumber(); also tolerate float64.
func numAt(m map[string]any, k string) int64 {
	switch n := m[k].(type) {
	case json.Number:
		i, _ := n.Int64()
		return i
	case float64:
		return int64(n)
	}
	return 0
}

// EvaluateDisclosure evaluates a signed disclosure against a policy and returns a
// deterministic transact/refuse verdict with a per-check breakdown (SPEC.md
// section 8). Ports evaluateDisclosure in src/verify.ts. Every failed check is
// reported; the decision is transact only when zero reasons accumulated.
func EvaluateDisclosure(signed SignedDisclosure, policy VerificationPolicy) Verdict {
	checks := map[string]bool{}
	reasons := []string{}
	fail := func(name, reason string) {
		checks[name] = false
		reasons = append(reasons, reason)
	}
	pass := func(name string) { checks[name] = true }

	d := signed.Disclosure

	// signature (default on)
	if policy.RequireValidSignature == nil || *policy.RequireValidSignature {
		if ok, reason := VerifyDisclosureSignature(signed); ok {
			pass("signature")
		} else {
			fail("signature", "signature invalid: "+reason)
		}
	}

	// freshness (default on)
	if policy.RequireFresh == nil || *policy.RequireFresh {
		if IsFresh(d, policy.Now) {
			pass("freshness")
		} else {
			fail("freshness", "disclosure not fresh (valid until "+strAt(d, "validUntil")+")")
		}
	}

	constitution := mapAt(d, "constitution")

	if policy.RequireEnforcedConstitution {
		if boolAt(constitution, "enforced") {
			pass("enforcedConstitution")
		} else {
			fail("enforcedConstitution", "constitution is declared but not enforced at runtime")
		}
	}

	if len(policy.RequiredHardConstraints) > 0 {
		present := map[string]bool{}
		for _, c := range sliceAt(constitution, "hardConstraints") {
			if cm, ok := c.(map[string]any); ok {
				present[strAt(cm, "id")] = true
			}
		}
		missing := []string{}
		for _, id := range policy.RequiredHardConstraints {
			if !present[id] {
				missing = append(missing, id)
			}
		}
		if len(missing) == 0 {
			pass("requiredHardConstraints")
		} else {
			fail("requiredHardConstraints", "missing required hard constraints: "+join(missing))
		}
	}

	redTeam := mapAt(d, "redTeam")
	if policy.RequireRedTeam && redTeam == nil {
		fail("redTeamPresent", "no red-team attestation")
	} else if redTeam != nil {
		result := mapAt(redTeam, "result")
		if policy.MinRedTeamGrade != "" {
			if gradeRank[strAt(result, "grade")] >= gradeRank[policy.MinRedTeamGrade] {
				pass("redTeamGrade")
			} else {
				fail("redTeamGrade", "red-team grade "+strAt(result, "grade")+" below minimum "+policy.MinRedTeamGrade)
			}
		}
		maxFails := 0
		if policy.MaxRedTeamHardFails != nil {
			maxFails = *policy.MaxRedTeamHardFails
		}
		if len(sliceAt(result, "hardFails")) <= maxFails {
			pass("redTeamHardFails")
		} else {
			fail("redTeamHardFails", "red-team hard-fails exceed max")
		}
	}

	capital := mapAt(d, "capital")
	if policy.RequireNonCustodial {
		if strAt(capital, "custody") == "non_custodial" {
			pass("nonCustodial")
		} else {
			fail("nonCustodial", "operation is custodial")
		}
	}

	operator := mapAt(d, "operator")
	if policy.MinAttestationLevel != "" {
		level := strAt(mapAt(operator, "attestation"), "level")
		if attestationRank[level] >= attestationRank[policy.MinAttestationLevel] {
			pass("attestationLevel")
		} else {
			fail("attestationLevel", "attestation level "+level+" below "+policy.MinAttestationLevel)
		}
	}

	if policy.RequireDeploymentHistory {
		if numAt(mapAt(mapAt(d, "history"), "summary"), "totalDecisions") > 0 {
			pass("deploymentHistory")
		} else {
			fail("deploymentHistory", "no deployment history")
		}
	}

	if policy.RequireAuditAnchor {
		if strAt(d, "auditAnchor") != "" {
			pass("auditAnchor")
		} else {
			fail("auditAnchor", "disclosure is not bound to an audit anchor")
		}
	}

	model := mapAt(d, "model")
	if policy.RequireModelFingerprint {
		if model != nil {
			pass("modelFingerprint")
		} else {
			fail("modelFingerprint", "no declared model identity")
		}
	}
	if len(policy.AllowedModelDigests) > 0 {
		if model != nil && contains(policy.AllowedModelDigests, strAt(model, "digest")) {
			pass("modelDigest")
		} else if model != nil {
			fail("modelDigest", "declared model digest is not in the allowed set")
		} else {
			fail("modelDigest", "no declared model to match")
		}
	}

	if len(policy.RequireProvenanceFor) > 0 {
		prov := mapAt(d, "provenance")
		missing := []string{}
		for _, f := range policy.RequireProvenanceFor {
			if prov == nil || prov[f] == nil {
				missing = append(missing, f)
			}
		}
		if len(missing) == 0 {
			pass("provenance")
		} else {
			fail("provenance", "missing provenance for: "+join(missing))
		}
	}

	if policy.IsRevoked != nil {
		if policy.IsRevoked(strAt(d, "disclosureId")) || policy.IsRevoked(strAt(d, "agentId")) {
			fail("revocation", "disclosure or agent identity is revoked")
		} else {
			pass("revocation")
		}
	}

	if policy.OperatorReputation != nil && policy.MinOperatorReputation != nil {
		score := policy.OperatorReputation(strAt(operator, "operatorId"))
		if score >= *policy.MinOperatorReputation {
			pass("operatorReputation")
		} else {
			fail("operatorReputation", "operator reputation below minimum")
		}
	}

	decision := "transact"
	if len(reasons) != 0 {
		decision = "refuse"
	}
	return Verdict{Decision: decision, Checks: checks, Reasons: reasons}
}

func contains(xs []string, target string) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}

func join(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}
