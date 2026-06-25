package agentdisclosure

// This file mirrors the disclosure enum grammar that the cross-language source of
// truth — schema/constraints.json, generated from src/schema.ts — declares. The
// validator (verifyraw.go) and the policy engine (verify.go) source their allowed
// values from these named sets so that schema_sync_test.go can pin them to the
// manifest: if src/schema.ts adds an enum value and constraints.json is regenerated
// but this file is not, `go test` fails with a clear message.

// SchemaVersion is the literal disclosure version (constraints.json `version`).
const SchemaVersion = 1

// DigestAlgorithm is the only accepted content-digest algorithm
// (constraints.json `digestAlgorithm`).
const DigestAlgorithm = "sha256"

// AttestationSchemeReverseDomainPattern matches a reverse-domain attestation-scheme
// id (e.g. "com.visa.tap"), mirroring constraints.json
// `attestationSchemeReverseDomainPattern`. At least one dot is required, so a bare
// word ("Unknown") is not a valid namespace.
const AttestationSchemeReverseDomainPattern = `^[a-z0-9]+(\.[a-z0-9-]+)+$`

// CustodyModes is the closed set of capital.custody values (constraints.json `custody`).
var CustodyModes = []string{"non_custodial", "custodial"}

// AttestationLevels is the closed set of operator.attestation.level values
// (constraints.json `attestationLevel`), ordered weakest-to-strongest.
var AttestationLevels = []string{"none", "signed", "registry_attested"}

// KnownAttestationSchemes is the closed set of named operator.attestation.scheme
// values (constraints.json `attestationSchemeKnown`); a value outside it is valid
// only if it matches AttestationSchemeReverseDomainPattern.
var KnownAttestationSchemes = []string{"AIP", "VisaTAP", "ERC8004", "DID", "none"}

// ConstraintKinds is the closed set of constitution constraint kinds
// (constraints.json `constraintKind`).
var ConstraintKinds = []string{"deny", "cap", "velocity", "rationale", "scope", "other"}

// ToolAccessLevels is the closed set of tool-access levels (constraints.json `toolAccess`).
var ToolAccessLevels = []string{"gated", "read_only", "operator_only"}

// MandatePeriods is the closed set of mandate velocity periods (constraints.json `mandatePeriod`).
var MandatePeriods = []string{"day", "week", "month"}

// RedTeamGrades is the closed set of red-team grades (constraints.json `redTeamGrade`),
// ordered best-to-worst.
var RedTeamGrades = []string{"A", "B", "C", "D", "F"}

// knownAttestationSchemeSet is the membership-test form of KnownAttestationSchemes,
// derived from it so the two cannot drift.
var knownAttestationSchemeSet = stringSet(KnownAttestationSchemes)

// custodyModeSet is the membership-test form of CustodyModes.
var custodyModeSet = stringSet(CustodyModes)

// attestationLevelSet is the membership-test form of AttestationLevels.
var attestationLevelSet = stringSet(AttestationLevels)

// stringSet builds a membership map from a value list.
func stringSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
