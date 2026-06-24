package agentdisclosure

import (
	"crypto/ed25519"
	"encoding/hex"
)

// AgentKeyPair is a Go-side agent signing identity. PublicKeyHex is the raw
// 32-byte ed25519 public key as hex - this is both the agentId and the envelope
// signature.publicKey (SPEC.md section 5). Mirrors the TS AgentKeyPair.
type AgentKeyPair struct {
	Private      ed25519.PrivateKey
	Public       ed25519.PublicKey
	PublicKeyHex string
}

// pkcs8Ed25519Prefix is the PKCS8 DER prefix that precedes the 32-byte seed in a
// stored ed25519 private key (the form the TS reference exports). The full DER is
// this prefix + the 32-byte seed; ed25519.NewKeyFromSeed reconstructs the pair.
const pkcs8Ed25519Prefix = "302e020100300506032b657004220420"

// GenerateAgentKeyPair mints a fresh agent signing identity.
func GenerateAgentKeyPair() (AgentKeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return AgentKeyPair{}, err
	}
	return AgentKeyPair{Private: priv, Public: pub, PublicKeyHex: hex.EncodeToString(pub)}, nil
}

// AgentKeyFromPrivateHex reconstructs a key pair from a persisted private key in
// PKCS8 DER hex (the `key.privateKeyHex` form in the conformance fixture). The
// trailing 32 bytes of the DER are the ed25519 seed.
func AgentKeyFromPrivateHex(privateKeyHex string) (AgentKeyPair, error) {
	der, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return AgentKeyPair{}, err
	}
	seed := der[len(der)-ed25519.SeedSize:]
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return AgentKeyPair{Private: priv, Public: pub, PublicKeyHex: hex.EncodeToString(pub)}, nil
}

// SignMessage signs the UTF-8 bytes of message with the agent private key and
// returns the hex signature - the generic primitive the disclosure signing and
// the challenge handshake both build on (mirrors TS signMessage).
func SignMessage(message string, priv ed25519.PrivateKey) string {
	return hex.EncodeToString(ed25519.Sign(priv, []byte(message)))
}

// SignDisclosure signs a disclosure with an agent key, returning the signed
// envelope. It sets the disclosure's agentId and the signature.publicKey to the
// key's derived public hex, and signs over Canonicalize(disclosure) - byte-for-byte
// the TS signDisclosure scheme. The input disclosure map is mutated to bind agentId.
func SignDisclosure(disclosure Disclosure, key AgentKeyPair) SignedDisclosure {
	disclosure["agentId"] = key.PublicKeyHex
	return SignedDisclosure{
		Disclosure: disclosure,
		Signature: Signature{
			Algorithm: "ed25519",
			PublicKey: key.PublicKeyHex,
			Value:     SignMessage(Canonicalize(disclosure), key.Private),
		},
	}
}
