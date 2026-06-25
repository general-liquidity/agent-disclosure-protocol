package agentdisclosure

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// --- v2: flattened JWS (EdDSA) envelope (port of src/attestation.ts) ------------
//
// The JOSE-interoperable v2 wrapping of the SAME disclosure document. The signature
// covers ASCII(protected + "." + payload), so the protected header (carrying `alg`)
// is integrity-protected — closing the v1 gap where the algorithm sat outside the
// signed bytes. The payload is the same RFC 8785 (JCS) canonical document.

// JwsJwk is the unprotected-header signing key as an OKP / Ed25519 JWK.
type JwsJwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// JwsHeader is the unprotected header carrying the JWK.
type JwsHeader struct {
	Jwk JwsJwk `json:"jwk"`
}

// RotationStatement links one signing key to its successor; a chain of these binds a
// stable agentId to the key that actually signed post-rotation (port of keys.ts).
type RotationStatement struct {
	From      string `json:"from"`
	To        string `json:"to"`
	RotatedAt string `json:"rotatedAt"`
	Signature string `json:"signature"`
}

// JwsSignedDisclosure is the v2 flattened-JWS envelope (port of JwsSignedDisclosure).
type JwsSignedDisclosure struct {
	Payload       string              `json:"payload"`
	Protected     string              `json:"protected"`
	Header        JwsHeader           `json:"header"`
	Signature     string              `json:"signature"`
	RotationChain []RotationStatement `json:"rotationChain,omitempty"`
}

// IsJwsSignedDisclosure reports whether a decoded envelope map is the v2 flattened-JWS
// form, discriminated by the presence of string `payload` + `protected` (matches the
// TS isJwsSignedDisclosure shape check).
func IsJwsSignedDisclosure(m map[string]any) bool {
	_, p := m["payload"].(string)
	_, h := m["protected"].(string)
	return p && h
}

// jwsFromAny builds a JwsSignedDisclosure from a number-aware decoded map.
func jwsFromAny(m map[string]any) JwsSignedDisclosure {
	out := JwsSignedDisclosure{
		Payload:   strAt(m, "payload"),
		Protected: strAt(m, "protected"),
		Signature: strAt(m, "signature"),
	}
	if hdr := mapAt(m, "header"); hdr != nil {
		jwk := mapAt(hdr, "jwk")
		out.Header = JwsHeader{Jwk: JwsJwk{
			Kty: strAt(jwk, "kty"),
			Crv: strAt(jwk, "crv"),
			X:   strAt(jwk, "x"),
		}}
	}
	for _, raw := range sliceAt(m, "rotationChain") {
		rc, _ := raw.(map[string]any)
		out.RotationChain = append(out.RotationChain, RotationStatement{
			From:      strAt(rc, "from"),
			To:        strAt(rc, "to"),
			RotatedAt: strAt(rc, "rotatedAt"),
			Signature: strAt(rc, "signature"),
		})
	}
	return out
}

// VerifyDisclosureJws verifies a v2 JWS envelope (port of verifyDisclosureJws): the
// protected header must declare EdDSA, the signature must verify over the signing
// input against the JWK key, and the payload's agentId must bind to that key (direct
// hex, did:key, or a verified rotation chain). Returns (ok, reason).
func VerifyDisclosureJws(signed JwsSignedDisclosure) (bool, string) {
	protBytes, err := base64.RawURLEncoding.DecodeString(signed.Protected)
	if err != nil {
		return false, "unreadable protected header"
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(protBytes, &header); err != nil {
		return false, "unreadable protected header"
	}
	if header.Alg != "EdDSA" {
		return false, fmt.Sprintf("unsupported JWS alg: %s", header.Alg)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(signed.Header.Jwk.X)
	if err != nil || len(xBytes) != ed25519.PublicKeySize {
		return false, "jwk.x is not a 32-byte ed25519 key"
	}
	pubHex := hex.EncodeToString(xBytes)

	sig, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil {
		return false, "jws signature mismatch"
	}
	signingInput := []byte(signed.Protected + "." + signed.Payload)
	if !ed25519.Verify(ed25519.PublicKey(xBytes), signingInput, sig) {
		return false, "jws signature mismatch"
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(signed.Payload)
	if err != nil {
		return false, "unreadable payload"
	}
	var payload struct {
		AgentID string `json:"agentId"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false, "unreadable payload"
	}
	if payload.AgentID == "" {
		return false, "payload has no agentId"
	}
	return VerifyKeyBinding(payload.AgentID, pubHex, signed.RotationChain)
}

// jwsDisclosure decodes the JCS payload of a v2 envelope into a generic disclosure map
// (for the policy engine). Decoded number-aware so integers stay literal.
func jwsDisclosure(signed JwsSignedDisclosure) (Disclosure, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(signed.Payload)
	if err != nil {
		return nil, err
	}
	v := decodeNumberAwareBytes(payloadBytes)
	d, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("jws payload is not a JSON object")
	}
	return d, nil
}

// EvaluateJwsDisclosure runs the same policy engine over a v2 JWS envelope (port of the
// TS evaluateDisclosure path for the JWS shape): the signature check uses the JWS
// verifier; every other check reads the decoded JCS payload. Returns the same Verdict.
func EvaluateJwsDisclosure(signed JwsSignedDisclosure, policy VerificationPolicy) Verdict {
	d, err := jwsDisclosure(signed)
	if err != nil {
		return Verdict{Decision: "refuse", Checks: map[string]bool{"signature": false}, Reasons: []string{"unreadable jws payload"}}
	}
	ok, reason := VerifyDisclosureJws(signed)
	return evaluateWithSignature(d, policy, ok, reason)
}
