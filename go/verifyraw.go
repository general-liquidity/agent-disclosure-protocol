package agentdisclosure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

// VerifyRaw is the adversarial entry point: it takes the raw bytes of an
// untrusted disclosure envelope (as a string), structurally parses them, and runs
// the full verify pipeline (signature + agentId binding). It mirrors the TS
// reference verifyAndEvaluate's fail-closed contract: ANY failure — parse error,
// missing/extra fields, wrong types, agentId != signature.publicKey, non-hex or a
// bad signature — is a rejection, and NO input may panic.
//
// rejected is true exactly when the disclosure must NOT be accepted.
func VerifyRaw(raw string) (rejected bool) {
	accepted, _ := VerifyRawReason(raw)
	return !accepted
}

// VerifyRawReason is VerifyRaw with a human-readable reason on rejection. accepted
// is true only for a structurally-valid, correctly-bound, signature-verifying
// disclosure. A panic anywhere in parse/canonicalize/verify is recovered and turned
// into a rejection — the contract is "never accept malformed/tampered, never crash".
func VerifyRawReason(raw string) (accepted bool, reason string) {
	defer func() {
		if r := recover(); r != nil {
			accepted = false
			reason = fmt.Sprintf("panic recovered during verification: %v", r)
		}
	}()

	signed, err := parseSignedDisclosureStrict([]byte(raw))
	if err != nil {
		return false, "malformed disclosure: " + err.Error()
	}

	if ok, why := VerifyDisclosureSignature(signed); !ok {
		return false, "signature invalid: " + why
	}
	return true, ""
}

// hexRe matches a non-empty hex string, mirroring the TS Hex schema (/^[0-9a-fA-F]+$/).
var hexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// reverseDomainRe matches a reverse-domain attestation-scheme id (e.g. "com.visa.tap"),
// compiled from the named AttestationSchemeReverseDomainPattern (constraints.json).
// At least one dot is required, so a bare word ("Unknown") is not a valid namespace.
var reverseDomainRe = regexp.MustCompile(AttestationSchemeReverseDomainPattern)

// decodeNumberAwareBytes decodes JSON bytes into a generic any with UseNumber() so
// integers stay literal (5, not 5.0) for byte-exact canonicalization. Returns nil on a
// decode error (callers treat that as a structural rejection).
func decodeNumberAwareBytes(data []byte) any {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	return v
}

// parseSignedDisclosureStrict decodes the raw bytes number-aware and validates the
// signed-envelope structure against the same shape the TS zod schema enforces
// (SignedDisclosureSchema): the top level is an object with exactly `disclosure`
// and `signature`; the signature is {algorithm:"ed25519", publicKey:hex,
// value:hex}; the disclosure carries the required typed fields. Extra top-level
// keys, missing keys, and wrong types are all rejected. It does NOT verify the
// signature — VerifyRawReason does that next.
func parseSignedDisclosureStrict(data []byte) (SignedDisclosure, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return SignedDisclosure{}, err
	}
	// Reject trailing garbage after the JSON value.
	if dec.More() {
		return SignedDisclosure{}, fmt.Errorf("unexpected trailing data after JSON value")
	}

	top, ok := root.(map[string]any)
	if !ok {
		return SignedDisclosure{}, fmt.Errorf("envelope is not a JSON object")
	}
	if err := exactKeys(top, "disclosure", "signature"); err != nil {
		return SignedDisclosure{}, err
	}

	sigMap, ok := top["signature"].(map[string]any)
	if !ok {
		return SignedDisclosure{}, fmt.Errorf("signature is not an object")
	}
	if err := exactKeys(sigMap, "algorithm", "publicKey", "value"); err != nil {
		return SignedDisclosure{}, fmt.Errorf("signature: %w", err)
	}
	algorithm, err := reqString(sigMap, "algorithm")
	if err != nil {
		return SignedDisclosure{}, fmt.Errorf("signature: %w", err)
	}
	if algorithm != "ed25519" {
		return SignedDisclosure{}, fmt.Errorf("signature.algorithm must be ed25519, got %q", algorithm)
	}
	publicKey, err := reqHex(sigMap, "publicKey")
	if err != nil {
		return SignedDisclosure{}, fmt.Errorf("signature: %w", err)
	}
	value, err := reqHex(sigMap, "value")
	if err != nil {
		return SignedDisclosure{}, fmt.Errorf("signature: %w", err)
	}

	disclosure, ok := top["disclosure"].(map[string]any)
	if !ok {
		return SignedDisclosure{}, fmt.Errorf("disclosure is not an object")
	}
	if err := validateDisclosureShape(disclosure); err != nil {
		return SignedDisclosure{}, fmt.Errorf("disclosure: %w", err)
	}

	return SignedDisclosure{
		Disclosure: disclosure,
		Signature:  Signature{Algorithm: algorithm, PublicKey: publicKey, Value: value},
	}, nil
}

// validateDisclosureShape enforces the required-field/type contract of
// AgentDisclosureSchema. It checks the load-bearing structural invariants the
// verifier and policy engine depend on (version literal, required scalars, the
// nested objects' presence), so a structurally-broken disclosure is rejected
// before it can reach the signature stage. It does not re-list every optional
// field; absent optionals are valid.
func validateDisclosureShape(d map[string]any) error {
	// version is the literal integer SchemaVersion.
	switch v := d["version"].(type) {
	case json.Number:
		if v.String() != strconv.Itoa(SchemaVersion) {
			return fmt.Errorf("version must be %d, got %s", SchemaVersion, v.String())
		}
	default:
		return fmt.Errorf("version must be the integer %d", SchemaVersion)
	}

	for _, k := range []string{"disclosureId", "agentId", "issuedAt", "validUntil", "nonce"} {
		if _, err := reqString(d, k); err != nil {
			return err
		}
	}

	for _, k := range []string{"systemPrompt", "constitution", "tools", "capital", "operator", "history"} {
		if _, ok := d[k].(map[string]any); !ok {
			return fmt.Errorf("%s is missing or not an object", k)
		}
	}

	constitution := d["constitution"].(map[string]any)
	if _, ok := constitution["enforced"].(bool); !ok {
		return fmt.Errorf("constitution.enforced is missing or not a boolean")
	}
	if _, ok := constitution["hardConstraints"].([]any); !ok {
		return fmt.Errorf("constitution.hardConstraints is missing or not an array")
	}

	// Enum / literal validation (mirrors the TS zod enums). These cases carry a VALID
	// ed25519 signature, so a signature-only verifier would wrongly accept them; the
	// schema layer must reject on enum grounds before the signature is even consulted.
	if err := validateEnums(d); err != nil {
		return err
	}

	return nil
}

// validateEnums enforces the closed-set fields the TS schema declares as zod enums /
// literals: capital.custody, operator.attestation.scheme (known value OR reverse-domain
// id), operator.attestation.level, and systemPrompt.algorithm. A value outside its set
// is a structural rejection.
func validateEnums(d map[string]any) error {
	systemPrompt := d["systemPrompt"].(map[string]any)
	if alg, _ := systemPrompt["algorithm"].(string); alg != DigestAlgorithm {
		return fmt.Errorf("systemPrompt.algorithm must be %s, got %q", DigestAlgorithm, alg)
	}

	capital := d["capital"].(map[string]any)
	if custody, _ := capital["custody"].(string); !custodyModeSet[custody] {
		return fmt.Errorf("capital.custody must be one of %v, got %q", CustodyModes, custody)
	}

	operator := d["operator"].(map[string]any)
	attestation, ok := operator["attestation"].(map[string]any)
	if !ok {
		return fmt.Errorf("operator.attestation is missing or not an object")
	}
	scheme, _ := attestation["scheme"].(string)
	if !knownAttestationSchemeSet[scheme] && !reverseDomainRe.MatchString(scheme) {
		return fmt.Errorf("operator.attestation.scheme must be a known value or a reverse-domain id, got %q", scheme)
	}
	if level, _ := attestation["level"].(string); !attestationLevelSet[level] {
		return fmt.Errorf("operator.attestation.level must be one of %v, got %q", AttestationLevels, level)
	}

	return nil
}

// exactKeys verifies m's key set is exactly `allowed` — no missing, no extra.
func exactKeys(m map[string]any, allowed ...string) error {
	want := map[string]bool{}
	for _, k := range allowed {
		want[k] = true
		if _, ok := m[k]; !ok {
			return fmt.Errorf("missing required field %q", k)
		}
	}
	for k := range m {
		if !want[k] {
			return fmt.Errorf("unexpected field %q", k)
		}
	}
	return nil
}

func reqString(m map[string]any, k string) (string, error) {
	v, ok := m[k].(string)
	if !ok {
		return "", fmt.Errorf("field %q is missing or not a string", k)
	}
	return v, nil
}

func reqHex(m map[string]any, k string) (string, error) {
	s, err := reqString(m, k)
	if err != nil {
		return "", err
	}
	if !hexRe.MatchString(s) {
		return "", fmt.Errorf("field %q is not a hex string", k)
	}
	return s, nil
}
