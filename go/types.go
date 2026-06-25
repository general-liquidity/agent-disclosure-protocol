package agentdisclosure

// Disclosure is the signed content. It is held as a generic decoded-JSON map so
// that Canonicalize reproduces the reference bytes exactly (numbers stay literal
// when decoded with json.Decoder.UseNumber()).
type Disclosure = map[string]any

// Signature is the ed25519 envelope signature (SPEC.md section 3.12).
type Signature struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
	Value     string `json:"value"`
}

// SignedDisclosure wraps a disclosure document with its signature.
type SignedDisclosure struct {
	Disclosure Disclosure `json:"disclosure"`
	Signature  Signature  `json:"signature"`
}

// VerificationPolicy is what a verifier demands of a counterparty (SPEC.md
// section 8). Every field beyond `Now` is optional; pointer/slice nil means
// "not set". An empty policy checks only signature + freshness (both default on).
type VerificationPolicy struct {
	Now                         string   // clock for freshness (ISO-8601), REQUIRED
	RequireValidSignature       *bool    // default true
	RequireFresh                *bool    // default true
	RequireEnforcedConstitution bool     //
	RequiredHardConstraints     []string //
	RequireRedTeam              bool     //
	MinRedTeamGrade             string   // "" = unset; one of A/B/C/D/F
	MaxRedTeamHardFails         *int     // default 0 when a redTeam attestation is present
	RequireNonCustodial         bool     //
	MinAttestationLevel         string   // "" = unset; none/signed/registry_attested
	RequireDeploymentHistory    bool     //
	RequireAuditAnchor          bool     //
	RequireModelFingerprint     bool     //
	AllowedModelDigests         []string //
	RequireProvenanceFor        []string //
	IsRevoked                   func(id string) bool
	OperatorReputation          func(operatorID string) float64
	MinOperatorReputation       *float64
}

// Verdict is the deterministic transact/refuse outcome with a per-check breakdown.
type Verdict struct {
	Decision string          // "transact" | "refuse"
	Checks   map[string]bool // per-check pass/fail
	Reasons  []string        // human-readable failures
}

// Challenge is a verifier-issued liveness challenge (SPEC.md section 7.1).
type Challenge struct {
	Nonce      string `json:"nonce"`
	IssuedAt   string `json:"issuedAt"`
	VerifierID string `json:"verifierId,omitempty"`
}

// ChallengeResponse is the agent's signed answer (SPEC.md section 7.2). The signature
// is hex over the RFC 9421 signature base (see handshake.go); SignatureInput carries the
// covered set + params so a verifier reads the exact material that was signed.
type ChallengeResponse struct {
	Nonce     string `json:"nonce"`
	AgentID   string `json:"agentId"`
	AuditHead string `json:"auditHead"`
	SignedAt  string `json:"signedAt"`
	// DisclosureVersion, when declared (>0), is a SIGNED covered component used for
	// version negotiation; 0 means "not declared" (the no-version backward path).
	DisclosureVersion int    `json:"disclosureVersion,omitempty"`
	SignatureInput    string `json:"signatureInput"`
	Signature         string `json:"signature"`
}
