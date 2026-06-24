package agentdisclosure

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// decodeNumberAware unmarshals JSON bytes into a generic any with UseNumber() so
// integers stay literal (5, not 5.0) for byte-exact canonicalization.
func decodeNumberAware(t *testing.T, data []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func readFixture(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return decodeNumberAware(t, data).(map[string]any)
}

func TestCanonicalizationVectors(t *testing.T) {
	v := readFixture(t, "../conformance/vectors.json")
	for i, raw := range v["canonicalization"].([]any) {
		c := raw.(map[string]any)
		got := Canonicalize(c["input"])
		want := c["canonical"].(string)
		if got != want {
			t.Errorf("canonicalization[%d]: got %q want %q", i, got, want)
		}
	}
}

func TestSha256Vectors(t *testing.T) {
	v := readFixture(t, "../conformance/vectors.json")
	for i, raw := range v["sha256"].([]any) {
		c := raw.(map[string]any)
		got := Sha256Hex(c["input"].(string))
		want := c["sha256"].(string)
		if got != want {
			t.Errorf("sha256[%d]: got %q want %q", i, got, want)
		}
	}
}

// signedFromAny builds a SignedDisclosure from a number-aware decoded map,
// keeping the disclosure as a generic map for byte-exact canonicalization.
func signedFromAny(m map[string]any) SignedDisclosure {
	sig := m["signature"].(map[string]any)
	return SignedDisclosure{
		Disclosure: m["disclosure"].(map[string]any),
		Signature: Signature{
			Algorithm: sig["algorithm"].(string),
			PublicKey: sig["publicKey"].(string),
			Value:     sig["value"].(string),
		},
	}
}

func policyFromAny(m map[string]any) VerificationPolicy {
	p := VerificationPolicy{Now: str(m, "now")}
	if v, ok := m["requireEnforcedConstitution"].(bool); ok {
		p.RequireEnforcedConstitution = v
	}
	if v, ok := m["requireNonCustodial"].(bool); ok {
		p.RequireNonCustodial = v
	}
	if v, ok := m["requireDeploymentHistory"].(bool); ok {
		p.RequireDeploymentHistory = v
	}
	if v, ok := m["requireAuditAnchor"].(bool); ok {
		p.RequireAuditAnchor = v
	}
	if v, ok := m["requireRedTeam"].(bool); ok {
		p.RequireRedTeam = v
	}
	if v, ok := m["minRedTeamGrade"].(string); ok {
		p.MinRedTeamGrade = v
	}
	if v, ok := m["requireModelFingerprint"].(bool); ok {
		p.RequireModelFingerprint = v
	}
	if v, ok := m["minAttestationLevel"].(string); ok {
		p.MinAttestationLevel = v
	}
	if v, ok := m["requiredHardConstraints"].([]any); ok {
		p.RequiredHardConstraints = strSlice(v)
	}
	if v, ok := m["allowedModelDigests"].([]any); ok {
		p.AllowedModelDigests = strSlice(v)
	}
	if v, ok := m["requireProvenanceFor"].([]any); ok {
		p.RequireProvenanceFor = strSlice(v)
	}
	return p
}

func str(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

func strSlice(xs []any) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// failedChecks returns the sorted names of checks that failed.
func failedChecks(v Verdict) []string {
	out := []string{}
	for name, ok := range v.Checks {
		if !ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func TestInteropDisclosures(t *testing.T) {
	interop := readFixture(t, "../conformance/interop.json")
	for _, raw := range interop["disclosures"].([]any) {
		c := raw.(map[string]any)
		name := c["name"].(string)
		signed := signedFromAny(c["signed"].(map[string]any))
		policy := policyFromAny(c["policy"].(map[string]any))
		verdict := EvaluateDisclosure(signed, policy)

		expect := c["expect"].(map[string]any)
		wantDecision := expect["decision"].(string)
		if verdict.Decision != wantDecision {
			t.Errorf("%s: decision got %q want %q (reasons: %v)", name, verdict.Decision, wantDecision, verdict.Reasons)
		}

		wantFailed := strSlice(expect["failed"].([]any))
		sort.Strings(wantFailed)
		gotFailed := failedChecks(verdict)
		if !equalStrings(gotFailed, wantFailed) {
			t.Errorf("%s: failed checks got %v want %v", name, gotFailed, wantFailed)
		}
	}
}

func TestInteropHandshakes(t *testing.T) {
	interop := readFixture(t, "../conformance/interop.json")
	for _, raw := range interop["handshakes"].([]any) {
		c := raw.(map[string]any)
		name := c["name"].(string)
		ch := c["challenge"].(map[string]any)
		challenge := Challenge{
			Nonce:      str(ch, "nonce"),
			IssuedAt:   str(ch, "issuedAt"),
			VerifierID: str(ch, "verifierId"),
		}
		rs := c["response"].(map[string]any)
		response := ChallengeResponse{
			Nonce:     str(rs, "nonce"),
			AgentID:   str(rs, "agentId"),
			AuditHead: str(rs, "auditHead"),
			SignedAt:  str(rs, "signedAt"),
			Signature: str(rs, "signature"),
		}
		ok, _ := VerifyChallengeResponse(response, challenge, str(c, "expectedAgentId"), str(c, "now"))
		want := c["expect"].(bool)
		if ok != want {
			t.Errorf("handshake %s: got %v want %v", name, ok, want)
		}
	}
}

// TestInteropSignaturesVerify confirms every valid-key interop disclosure (those
// whose agentId equals the signing public key) produces a verifying signature -
// proof the Go canonicalization byte-matches the TS reference that signed them.
func TestInteropSignaturesVerify(t *testing.T) {
	interop := readFixture(t, "../conformance/interop.json")
	pub := interop["key"].(map[string]any)["publicKeyHex"].(string)
	verified := 0
	for _, raw := range interop["disclosures"].([]any) {
		c := raw.(map[string]any)
		signed := signedFromAny(c["signed"].(map[string]any))
		// Only those bound to the fixed key with an untampered body should verify.
		if signed.Signature.PublicKey != pub {
			continue
		}
		if str(signed.Disclosure, "agentId") != pub {
			continue // forged-agentid case: binding fails by design
		}
		if VerifyMessage(Canonicalize(signed.Disclosure), pub, signed.Signature.Value) {
			verified++
		}
	}
	if verified == 0 {
		t.Fatal("no interop signatures verified - canonicalization does not match the TS reference")
	}
	t.Logf("%d interop disclosure signatures verify against the reference key", verified)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
