package agentdisclosure

import "time"

// responseMessage builds the canonical bytes the challenge response signs over
// (SPEC.md section 7.3): canonicalize({nonce, agentId, auditHead, signedAt,
// verifierId}), where verifierId comes from the challenge. An absent verifierId
// is omitted from the map entirely so it is dropped by canonicalization, exactly
// matching the TS `undefined` behaviour.
func responseMessage(r ChallengeResponse, verifierID string) string {
	body := map[string]any{
		"nonce":     r.Nonce,
		"agentId":   r.AgentID,
		"auditHead": r.AuditHead,
		"signedAt":  r.SignedAt,
	}
	if verifierID != "" {
		body["verifierId"] = verifierID
	}
	return Canonicalize(body)
}

// VerifyChallengeResponse verifies a challenge response against the original
// challenge, the expected agentId, and a verifier clock (SPEC.md section 7.4).
// maxAgeMs defaults to 60000. Returns (ok, reason). Checks, in order: nonce
// match, agentId match, signature, freshness (when now is supplied). Audit-head
// currency is a non-fatal signal in the reference, so ok is returned.
func VerifyChallengeResponse(response ChallengeResponse, challenge Challenge, expectedAgentID, now string) (bool, string) {
	return verifyChallengeResponse(response, challenge, expectedAgentID, now, 60000)
}

func verifyChallengeResponse(response ChallengeResponse, challenge Challenge, expectedAgentID, now string, maxAgeMs int64) (bool, string) {
	if response.Nonce != challenge.Nonce {
		return false, "nonce mismatch (replayed or wrong challenge)"
	}
	if response.AgentID != expectedAgentID {
		return false, "response agentId does not match the disclosure"
	}
	if !VerifyMessage(responseMessage(response, challenge.VerifierID), response.AgentID, response.Signature) {
		return false, "challenge signature invalid (no live key possession)"
	}
	if now != "" {
		nowMs, ok1 := parseMs(now)
		signedMs, ok2 := parseMs(response.SignedAt)
		if ok1 && ok2 {
			age := nowMs - signedMs
			if age < 0 || age > maxAgeMs {
				return false, "challenge response is stale"
			}
		}
	}
	return true, ""
}

// parseMs parses an ISO-8601 timestamp to milliseconds since the epoch, matching
// JavaScript's Date.parse. Returns ok=false on a parse failure (mirrors NaN).
func parseMs(iso string) (int64, bool) {
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		t, err = time.Parse(time.RFC3339, iso)
		if err != nil {
			return 0, false
		}
	}
	return t.UnixMilli(), true
}
