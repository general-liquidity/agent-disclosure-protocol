package agentdisclosure

import (
	"crypto/ed25519"
	"encoding/hex"
)

// VerifyMessage verifies a hex ed25519 signature over the UTF-8 bytes of message
// against a raw 32-byte public key (hex). Any decoding error or wrong length is a
// non-fatal false, matching the reference verifyMessage's try/catch.
func VerifyMessage(message, publicKeyHex, signatureHex string) bool {
	pub, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(signatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(message), sig)
}

// VerifyDisclosureSignature verifies the ed25519 signature over the canonical
// disclosure bytes AND enforces the agentId <-> signing-key binding (SPEC.md
// section 5): agentId MUST equal signature.publicKey, checked before the
// signature value. Returns (ok, reason).
func VerifyDisclosureSignature(signed SignedDisclosure) (bool, string) {
	agentID, _ := signed.Disclosure["agentId"].(string)
	if agentID != signed.Signature.PublicKey {
		return false, "agentId does not match the signing public key"
	}
	if VerifyMessage(Canonicalize(signed.Disclosure), signed.Signature.PublicKey, signed.Signature.Value) {
		return true, ""
	}
	return false, "signature mismatch"
}

// IsFresh reports whether now is within [issuedAt, validUntil], compared as
// ISO-8601 lexical strings (SPEC.md section 6).
func IsFresh(disclosure Disclosure, now string) bool {
	issuedAt, _ := disclosure["issuedAt"].(string)
	validUntil, _ := disclosure["validUntil"].(string)
	return now >= issuedAt && now <= validUntil
}
