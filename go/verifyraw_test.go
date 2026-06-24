package agentdisclosure

import (
	"encoding/json"
	"os"
	"testing"
)

// negativeCase mirrors a conformance/negative.json entry. `Raw` is captured as
// json.RawMessage so the exact JSON bytes are preserved; for isRawString cases
// it is a JSON string whose contents are the literal (possibly non-JSON) input.
type negativeCase struct {
	Name        string          `json:"name"`
	Raw         json.RawMessage `json:"raw"`
	IsRawString bool            `json:"isRawString"`
}

// rejectsWithoutPanic runs VerifyRaw inside a recover guard so a panic is reported
// as a test failure rather than crashing the suite. The contract under test is
// "never accept malformed/tampered, never crash", so a panic is itself a failure.
func rejectsWithoutPanic(t *testing.T, name, raw string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: VerifyRaw panicked: %v", name, r)
		}
	}()
	if !VerifyRaw(raw) {
		accepted, reason := VerifyRawReason(raw)
		t.Errorf("%s: VerifyRaw accepted a must-reject case (accepted=%v reason=%q)", name, accepted, reason)
	}
}

// TestNegativeCorpus replays the MUST-REJECT corpus. Each case's raw input is fed
// to VerifyRaw as a STRING: for ordinary cases the JSON value is re-marshalled to
// its text form; for isRawString cases the literal string contents are fed (which
// the parser must reject). Every case must be rejected with no panic.
func TestNegativeCorpus(t *testing.T) {
	data, err := os.ReadFile("../conformance/negative.json")
	if err != nil {
		t.Fatalf("read negative.json: %v", err)
	}
	var doc struct {
		Cases []negativeCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse negative.json: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("negative.json has no cases")
	}

	for _, c := range doc.Cases {
		var rawInput string
		if c.IsRawString {
			// raw is a JSON string; its decoded contents are the literal bytes.
			if err := json.Unmarshal(c.Raw, &rawInput); err != nil {
				t.Fatalf("%s: decode isRawString raw: %v", c.Name, err)
			}
		} else {
			// Feed the JSON value's own text as the raw input.
			rawInput = string(c.Raw)
		}
		rejectsWithoutPanic(t, c.Name, rawInput)
	}
}

// TestVerifyRawPanicSafety feeds a battery of hostile/degenerate inputs that have
// caused real parsers to panic (empty, truncated, deep nesting, NUL bytes, huge
// numbers, lone surrogates) and asserts each is rejected without crashing.
func TestVerifyRawPanicSafety(t *testing.T) {
	deep := ""
	for i := 0; i < 5000; i++ {
		deep += "{\"x\":"
	}
	deep += "0"
	for i := 0; i < 5000; i++ {
		deep += "}"
	}

	inputs := []string{
		"",
		" ",
		"\x00",
		"{",
		"[",
		"null",
		"true",
		"\"a string\"",
		"{\"disclosure\":}",
		"{\"disclosure\":{},\"signature\":{}}",
		"{\"disclosure\":{},\"signature\":{},\"extra\":1}",
		"99999999999999999999999999999999999999999999",
		"{\"\\ud800\":1}",
		deep,
	}
	for _, in := range inputs {
		rejectsWithoutPanic(t, "panic-safety", in)
	}
}
