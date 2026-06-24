package agentdisclosure

import (
	"encoding/json"
	"sort"
	"testing"
)

// TestEmitterByteMatchesTSFixtures re-signs each interop disclosure that is bound
// to the fixed key with an untampered, verifying signature, and asserts the Go
// emitter reproduces the EXACT signature hex the TS signer produced. This proves
// the Go emitter is byte-identical to the TS attestation path.
func TestEmitterByteMatchesTSFixtures(t *testing.T) {
	interop := readFixture(t, "../conformance/interop.json")
	keyMap := interop["key"].(map[string]any)
	pub := keyMap["publicKeyHex"].(string)

	key, err := AgentKeyFromPrivateHex(keyMap["privateKeyHex"].(string))
	if err != nil {
		t.Fatalf("load fixed key: %v", err)
	}
	if key.PublicKeyHex != pub {
		t.Fatalf("derived public key %q != fixture public key %q", key.PublicKeyHex, pub)
	}

	matched := 0
	for _, raw := range interop["disclosures"].([]any) {
		c := raw.(map[string]any)
		name := c["name"].(string)
		signed := signedFromAny(c["signed"].(map[string]any))

		// Only re-sign cases bound to the fixed key whose stored signature already
		// verifies (skips the deliberately tampered / forged-agentid cases).
		if signed.Signature.PublicKey != pub || str(signed.Disclosure, "agentId") != pub {
			continue
		}
		if !VerifyMessage(Canonicalize(signed.Disclosure), pub, signed.Signature.Value) {
			continue
		}

		resigned := SignDisclosure(signed.Disclosure, key)
		if resigned.Signature.Value != signed.Signature.Value {
			t.Errorf("%s: Go emitter signature %q != TS fixture %q", name, resigned.Signature.Value, signed.Signature.Value)
			continue
		}
		matched++
	}
	if matched == 0 {
		t.Fatal("no bound interop disclosures re-signed - emitter byte-match unproven")
	}
	t.Logf("%d interop disclosure signatures byte-match the Go emitter", matched)
}

// TestEmitterRoundTrip emits a fresh disclosure with a generated key and confirms
// the existing VerifyDisclosureSignature accepts it.
func TestEmitterRoundTrip(t *testing.T) {
	key, err := GenerateAgentKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	disclosure := Disclosure{
		"version":      json.Number("1"),
		"disclosureId": "disc_roundtrip",
		"issuedAt":     "2026-06-24T12:00:00.000Z",
		"validUntil":   "2026-06-24T13:00:00.000Z",
		"nonce":        "nonce_roundtrip",
	}
	signed := SignDisclosure(disclosure, key)

	if got := str(signed.Disclosure, "agentId"); got != key.PublicKeyHex {
		t.Fatalf("SignDisclosure did not bind agentId: got %q want %q", got, key.PublicKeyHex)
	}
	if signed.Signature.PublicKey != key.PublicKeyHex {
		t.Fatalf("signature publicKey %q != key %q", signed.Signature.PublicKey, key.PublicKeyHex)
	}
	if ok, reason := VerifyDisclosureSignature(signed); !ok {
		t.Fatalf("round-trip verify failed: %s", reason)
	}
}

// TestInteropRedactions runs the redaction fixtures and asserts VerifyRedacted
// reproduces each expect (ok, plus sorted revealedFields when ok).
func TestInteropRedactions(t *testing.T) {
	interop := readFixture(t, "../conformance/interop.json")
	for _, raw := range interop["redactions"].([]any) {
		c := raw.(map[string]any)
		name := c["name"].(string)
		v := c["view"].(map[string]any)
		sig := v["signature"].(map[string]any)
		view := RedactedView{
			Meta:        v["meta"].(map[string]any),
			Commitments: v["commitments"].(map[string]any),
			Revealed:    v["revealed"].(map[string]any),
			Signature: Signature{
				Algorithm: sig["algorithm"].(string),
				PublicKey: sig["publicKey"].(string),
				Value:     sig["value"].(string),
			},
		}

		ok, revealedFields := VerifyRedacted(view)
		expect := c["expect"].(map[string]any)
		wantOK := expect["ok"].(bool)
		if ok != wantOK {
			t.Errorf("redaction %s: ok got %v want %v", name, ok, wantOK)
			continue
		}
		if wantOK {
			wantFields := strSlice(expect["revealedFields"].([]any))
			sort.Strings(wantFields)
			if !equalStrings(revealedFields, wantFields) {
				t.Errorf("redaction %s: revealedFields got %v want %v", name, revealedFields, wantFields)
			}
		} else if len(revealedFields) != 0 {
			t.Errorf("redaction %s: expected empty revealedFields, got %v", name, revealedFields)
		}
	}
}

// TestInteropRevocations runs the revocation fixtures and asserts VerifyRevocation
// reproduces each expect.
func TestInteropRevocations(t *testing.T) {
	interop := readFixture(t, "../conformance/interop.json")
	for _, raw := range interop["revocations"].([]any) {
		c := raw.(map[string]any)
		name := c["name"].(string)
		r := c["record"].(map[string]any)
		rec := SignedRevocation{
			ID:        str(r, "id"),
			Reason:    str(r, "reason"),
			RevokedAt: str(r, "revokedAt"),
			PublicKey: str(r, "publicKey"),
			Signature: str(r, "signature"),
		}
		got := VerifyRevocation(rec)
		want := c["expect"].(bool)
		if got != want {
			t.Errorf("revocation %s: got %v want %v", name, got, want)
		}
	}
}

// TestInteropTransparency runs the transparency fixtures and asserts
// VerifyInclusionProof reproduces each expect.
func TestInteropTransparency(t *testing.T) {
	interop := readFixture(t, "../conformance/interop.json")
	for _, raw := range interop["transparency"].([]any) {
		c := raw.(map[string]any)
		name := c["name"].(string)
		e := c["entry"].(map[string]any)
		entry := TransparencyLogEntry{
			Index:            e["index"],
			DisclosureDigest: str(e, "disclosureDigest"),
			AgentID:          str(e, "agentId"),
			IssuedAt:         str(e, "issuedAt"),
			PrevHash:         e["prevHash"],
			Hash:             str(e, "hash"),
		}
		got := VerifyInclusionProof(entry)
		want := c["expect"].(bool)
		if got != want {
			t.Errorf("transparency %s: got %v want %v", name, got, want)
		}
	}
}
