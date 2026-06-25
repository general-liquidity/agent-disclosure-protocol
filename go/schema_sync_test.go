package agentdisclosure

import (
	"encoding/json"
	"os"
	"testing"
)

// schemaConstraints mirrors schema/constraints.json — the single cross-language source
// of the disclosure enum grammar, generated from src/schema.ts. The Go port's named
// constants (schema.go) MUST equal these; if src/schema.ts adds an enum value and the
// manifest is regenerated but schema.go is not, the asserts below fail with a clear
// message naming the field.
type schemaConstraints struct {
	Version                               int      `json:"version"`
	DigestAlgorithm                       string   `json:"digestAlgorithm"`
	Custody                               []string `json:"custody"`
	AttestationLevel                      []string `json:"attestationLevel"`
	AttestationSchemeKnown                []string `json:"attestationSchemeKnown"`
	AttestationSchemeReverseDomainPattern string   `json:"attestationSchemeReverseDomainPattern"`
	ConstraintKind                        []string `json:"constraintKind"`
	ToolAccess                            []string `json:"toolAccess"`
	MandatePeriod                         []string `json:"mandatePeriod"`
	RedTeamGrade                          []string `json:"redTeamGrade"`
}

func loadConstraints(t *testing.T) schemaConstraints {
	t.Helper()
	data, err := os.ReadFile("../schema/constraints.json")
	if err != nil {
		t.Fatalf("read ../schema/constraints.json: %v", err)
	}
	var c schemaConstraints
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("decode constraints.json: %v", err)
	}
	return c
}

// TestSchemaConstantsMatchManifest pins every named enum/literal in schema.go to its
// counterpart in schema/constraints.json. Regenerate the manifest with
// `node --import tsx scripts/generate-schema.ts`; if this fails, the Go port is out of
// sync with src/schema.ts and must be updated to match.
func TestSchemaConstantsMatchManifest(t *testing.T) {
	c := loadConstraints(t)

	if SchemaVersion != c.Version {
		t.Errorf("SchemaVersion: Go %d != manifest %d", SchemaVersion, c.Version)
	}
	if DigestAlgorithm != c.DigestAlgorithm {
		t.Errorf("DigestAlgorithm: Go %q != manifest %q", DigestAlgorithm, c.DigestAlgorithm)
	}
	if AttestationSchemeReverseDomainPattern != c.AttestationSchemeReverseDomainPattern {
		t.Errorf("AttestationSchemeReverseDomainPattern: Go %q != manifest %q",
			AttestationSchemeReverseDomainPattern, c.AttestationSchemeReverseDomainPattern)
	}

	for _, tc := range []struct {
		field string
		got   []string
		want  []string
	}{
		{"custody", CustodyModes, c.Custody},
		{"attestationLevel", AttestationLevels, c.AttestationLevel},
		{"attestationSchemeKnown", KnownAttestationSchemes, c.AttestationSchemeKnown},
		{"constraintKind", ConstraintKinds, c.ConstraintKind},
		{"toolAccess", ToolAccessLevels, c.ToolAccess},
		{"mandatePeriod", MandatePeriods, c.MandatePeriod},
		{"redTeamGrade", RedTeamGrades, c.RedTeamGrade},
	} {
		if !equalStrings(tc.got, tc.want) {
			t.Errorf("%s: Go %v != manifest %v — regenerate constraints.json and update go/schema.go",
				tc.field, tc.got, tc.want)
		}
	}
}
