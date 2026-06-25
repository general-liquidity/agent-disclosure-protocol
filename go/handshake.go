package agentdisclosure

import (
	"strconv"
	"strings"
	"time"
)

// --- RFC 9421 (HTTP Message Signatures) handshake (port of src/handshake.ts) ----
//
// The response signs over an RFC 9421 *signature base*: covered-component lines plus a
// `@signature-params` line carrying created/keyid/alg/nonce/tag. This is the non-HTTP
// profile — every covered component is an `adp-*` derived component. ADP deviations:
// `created` is an ISO-8601 string (not unix-seconds) and the signature bytes are hex
// (not the `:base64:` sf-binary wrapper).

const (
	componentAgentID   = "adp-agent-id"
	componentAuditHead = "adp-audit-head"
	componentVersion   = "adp-disclosure-version"
)

// sigMaterial is the input to the signature base. DisclosureVersion 0 means "not
// declared" (no version line), matching the TS `undefined` covered-component behaviour.
type sigMaterial struct {
	AgentID           string
	AuditHead         string
	SignedAt          string
	Nonce             string
	VerifierID        string
	DisclosureVersion int
}

// coveredComponents is the ordered [name, value] set; the version component is covered
// only when declared (>0), so a no-version response signs a base with no version line.
func coveredComponents(m sigMaterial) [][2]string {
	comps := [][2]string{
		{componentAgentID, m.AgentID},
		{componentAuditHead, m.AuditHead},
	}
	if m.DisclosureVersion > 0 {
		comps = append(comps, [2]string{componentVersion, strconv.Itoa(m.DisclosureVersion)})
	}
	return comps
}

// signatureParams is the `@signature-params` value:
// `(<inner list>);created=...;keyid=...;alg="ed25519";nonce=...;tag=...`.
func signatureParams(m sigMaterial) string {
	inner := make([]string, 0, 3)
	for _, c := range coveredComponents(m) {
		inner = append(inner, `"`+c[0]+`"`)
	}
	params := "(" + strings.Join(inner, " ") + `);created="` + m.SignedAt + `";keyid="` + m.AgentID + `";alg="ed25519";nonce="` + m.Nonce + `"`
	if m.VerifierID != "" {
		params += `;tag="` + m.VerifierID + `"`
	}
	return params
}

// signatureBase is the RFC 9421 signature base: each covered-component line, then the
// `@signature-params` line, joined by newlines.
func signatureBase(m sigMaterial) string {
	lines := make([]string, 0, 4)
	for _, c := range coveredComponents(m) {
		lines = append(lines, `"`+c[0]+`": `+c[1])
	}
	lines = append(lines, `"@signature-params": `+signatureParams(m))
	return strings.Join(lines, "\n")
}

// signatureInputValue is the `Signature-Input` value (labelled `sig`), carried on the
// response so a verifier reads the exact covered set + params.
func signatureInputValue(m sigMaterial) string {
	return "sig=" + signatureParams(m)
}

// RespondToChallenge is the emit side of the handshake (port of respondToChallenge):
// the agent answers a verifier's challenge by signing the RFC 9421 signature base
// binding the nonce, live audit head, and agent id. disclosureVersion (when >0) is a
// signed covered component for version negotiation. The produced signature is
// byte-identical to the TS responder for the same inputs.
func RespondToChallenge(challenge Challenge, key AgentKeyPair, auditHead, now string, disclosureVersion int) ChallengeResponse {
	m := sigMaterial{
		AgentID:           key.PublicKeyHex,
		AuditHead:         auditHead,
		SignedAt:          now,
		Nonce:             challenge.Nonce,
		VerifierID:        challenge.VerifierID,
		DisclosureVersion: disclosureVersion,
	}
	return ChallengeResponse{
		Nonce:             challenge.Nonce,
		AgentID:           key.PublicKeyHex,
		AuditHead:         auditHead,
		SignedAt:          now,
		DisclosureVersion: disclosureVersion,
		SignatureInput:    signatureInputValue(m),
		Signature:         SignMessage(signatureBase(m), key.Private),
	}
}

// VerifyChallengeResponse verifies a challenge response against the original challenge,
// the expected agentId, and a verifier clock (port of verifyChallengeResponse).
// maxAgeMs defaults to 60000. Returns (ok, reason). Checks, in order: nonce match,
// agentId match, the response's Signature-Input matches the base reconstructed from OUR
// challenge (no param smuggling), the ed25519 signature verifies over that base, then
// freshness. Audit-head currency is a non-fatal signal, so ok is returned.
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
	// Reconstruct the signature base from OUR challenge (nonce, verifierId) + the
	// response's claimed values. The response's Signature-Input must match exactly, and
	// the ed25519 signature must verify over the reconstructed base — so tampering any
	// covered value or param is caught.
	m := sigMaterial{
		AgentID:           response.AgentID,
		AuditHead:         response.AuditHead,
		SignedAt:          response.SignedAt,
		Nonce:             challenge.Nonce,
		VerifierID:        challenge.VerifierID,
		DisclosureVersion: response.DisclosureVersion,
	}
	if response.SignatureInput != signatureInputValue(m) {
		return false, "signature-input does not match the issued challenge"
	}
	if !VerifyMessage(signatureBase(m), response.AgentID, response.Signature) {
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
