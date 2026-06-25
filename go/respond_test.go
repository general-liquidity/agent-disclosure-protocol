package agentdisclosure

import "testing"

// firstHandshake returns the named handshake case from the interop fixture.
func handshakeByName(t *testing.T, interop map[string]any, name string) map[string]any {
	t.Helper()
	for _, raw := range interop["handshakes"].([]any) {
		c := raw.(map[string]any)
		if str(c, "name") == name {
			return c
		}
	}
	t.Fatalf("handshake %q not found in interop fixture", name)
	return nil
}

func challengeFromAny(m map[string]any) Challenge {
	return Challenge{
		Nonce:      str(m, "nonce"),
		IssuedAt:   str(m, "issuedAt"),
		VerifierID: str(m, "verifierId"),
	}
}

func responseFromAny(m map[string]any) ChallengeResponse {
	return ChallengeResponse{
		Nonce:             str(m, "nonce"),
		AgentID:           str(m, "agentId"),
		AuditHead:         str(m, "auditHead"),
		SignedAt:          str(m, "signedAt"),
		DisclosureVersion: intAt(m, "disclosureVersion"),
		SignatureInput:    str(m, "signatureInput"),
		Signature:         str(m, "signature"),
	}
}

// intAt returns the integer at key k (numbers arrive as json.Number under UseNumber),
// or 0 when absent.
func intAt(m map[string]any, k string) int {
	return int(numAt(m, k))
}

// TestRespondByteMatchesInterop is the byte-match gate: the Go responder, loaded
// with the fixed private key and the "valid" interop challenge, MUST reproduce the
// exact signature the TS signer committed to the fixture. Proves the two stacks
// sign byte-identical canonical bytes for the handshake.
func TestRespondByteMatchesInterop(t *testing.T) {
	interop := readFixture(t, "../conformance/interop.json")

	key, err := AgentKeyFromPrivateHex(interop["key"].(map[string]any)["privateKeyHex"].(string))
	if err != nil {
		t.Fatalf("load fixed key: %v", err)
	}

	c := handshakeByName(t, interop, "valid")
	challenge := challengeFromAny(c["challenge"].(map[string]any))
	want := responseFromAny(c["response"].(map[string]any))

	got := RespondToChallenge(challenge, key, want.AuditHead, want.SignedAt, want.DisclosureVersion)

	if got.Signature != want.Signature {
		t.Fatalf("responder signature mismatch:\n got  %s\n want %s", got.Signature, want.Signature)
	}
	if got.SignatureInput != want.SignatureInput {
		t.Fatalf("responder signature-input mismatch:\n got  %s\n want %s", got.SignatureInput, want.SignatureInput)
	}
	if got.Nonce != want.Nonce || got.AgentID != want.AgentID ||
		got.AuditHead != want.AuditHead || got.SignedAt != want.SignedAt {
		t.Fatalf("responder body mismatch: got %+v want %+v", got, want)
	}
}

// TestRespondRoundTrip confirms a fresh responder output verifies under the
// existing verifier - the emit and check sides agree end to end.
func TestRespondRoundTrip(t *testing.T) {
	key, err := GenerateAgentKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := "2026-06-24T12:30:00.000Z"
	challenge := Challenge{Nonce: "chal_rt", IssuedAt: now, VerifierID: "verifier-rt"}

	resp := RespondToChallenge(challenge, key, "audithead_rt", now, 0)

	ok, reason := VerifyChallengeResponse(resp, challenge, key.PublicKeyHex, now)
	if !ok {
		t.Fatalf("round-trip verify failed: %s", reason)
	}
}

// TestRespondNoVerifierID confirms the verifierId is dropped (not signed as empty)
// when the challenge omits it, so a no-verifier handshake also round-trips.
func TestRespondNoVerifierID(t *testing.T) {
	key, err := GenerateAgentKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := "2026-06-24T12:30:00.000Z"
	challenge := Challenge{Nonce: "chal_nov", IssuedAt: now}

	resp := RespondToChallenge(challenge, key, "audithead_nov", now, 0)

	ok, reason := VerifyChallengeResponse(resp, challenge, key.PublicKeyHex, now)
	if !ok {
		t.Fatalf("no-verifierId round-trip failed: %s", reason)
	}
}
