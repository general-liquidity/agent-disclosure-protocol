package agentdisclosure

import (
	"encoding/hex"
)

// --- DID bridge + key binding (port of src/did.ts + verifyKeyBinding) -----------

// multicodecEd25519Pub is the varint-encoded multicodec prefix for an ed25519 public
// key (0xed 0x01). did:key for ed25519 = "did:key:z" + base58btc(0xed01 || rawPubKey).
var multicodecEd25519Pub = []byte{0xed, 0x01}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode is base58btc (Bitcoin alphabet); leading zero bytes map to leading '1's.
func base58Encode(input []byte) string {
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}
	digits := []int{}
	for i := zeros; i < len(input); i++ {
		carry := int(input[i])
		for j := 0; j < len(digits); j++ {
			carry += digits[j] << 8
			digits[j] = carry % 58
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, carry%58)
			carry /= 58
		}
	}
	out := make([]byte, 0, zeros+len(digits))
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	for i := len(digits) - 1; i >= 0; i-- {
		out = append(out, base58Alphabet[digits[i]])
	}
	return string(out)
}

// AgentIDToDidKey expresses an agentId (raw 32-byte ed25519 public key, hex) as a
// self-certifying did:key (port of agentIdToDidKey). Returns ("", false) if the input
// is not a 32-byte hex key.
func AgentIDToDidKey(agentID string) (string, bool) {
	raw, err := hex.DecodeString(agentID)
	if err != nil || len(raw) != 32 {
		return "", false
	}
	prefixed := append(append([]byte{}, multicodecEd25519Pub...), raw...)
	return "did:key:z" + base58Encode(prefixed), true
}

// rotationStatementBody is the canonical signed body of a rotation statement, shared
// with the chain verifier (port of rotationStatementBody).
func rotationStatementBody(from, to, rotatedAt string) string {
	return Canonicalize(map[string]any{"type": "rotation", "from": from, "to": to, "rotatedAt": rotatedAt})
}

// maxRotationChain caps a rotation chain so a hostile envelope can't force unbounded work.
const maxRotationChain = 32

// VerifyRotationChain verifies that a chain of signed rotation statements links the
// stable agentId to the key that actually signed (port of verifyRotationChain).
func VerifyRotationChain(agentID, signingKey string, chain []RotationStatement) (bool, string) {
	if len(chain) == 0 {
		return false, "empty rotation chain"
	}
	if len(chain) > maxRotationChain {
		return false, "rotation chain exceeds maximum length"
	}
	cursor := agentID
	seen := map[string]bool{agentID: true}
	for _, s := range chain {
		if s.From != cursor {
			return false, "rotation chain is not contiguous from agentId"
		}
		if !VerifyMessage(rotationStatementBody(s.From, s.To, s.RotatedAt), s.From, s.Signature) {
			return false, "a rotation statement signature does not verify against its from key"
		}
		if seen[s.To] {
			return false, "rotation chain contains a cycle"
		}
		seen[s.To] = true
		cursor = s.To
	}
	if cursor != signingKey {
		return false, "rotation chain does not end at the signing key"
	}
	return true, ""
}

// VerifyKeyBinding binds a disclosure's stable agentId to the key that actually signed
// it: a direct hex match, the did:key encoding of that key, or a verified rotation chain
// back to the agentId (port of verifyKeyBinding). Shared by both envelope shapes.
func VerifyKeyBinding(agentID, signingKeyHex string, rotationChain []RotationStatement) (bool, string) {
	if agentID == signingKeyHex {
		return true, ""
	}
	if did, ok := AgentIDToDidKey(signingKeyHex); ok && agentID == did {
		return true, ""
	}
	if len(rotationChain) > 0 {
		return VerifyRotationChain(agentID, signingKeyHex, rotationChain)
	}
	return false, "agentId does not match the signing public key"
}
