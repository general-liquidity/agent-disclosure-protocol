package agentdisclosure

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// jsonString emits a value as a JSON string literal, matching JavaScript's
// JSON.stringify for strings: standard JSON escaping with NO HTML escaping
// (Go's default would escape <, >, & as \u00XX, which JS does not).
func jsonString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// Encoder appends a trailing newline; trim it.
	_ = enc.Encode(s)
	return strings.TrimRight(buf.String(), "\n")
}

// Canonicalize reproduces the reference `canonicalize` (SPEC.md section 4):
//   - null / scalar: the JSON scalar form
//   - array: "[" + elements canonicalized in order joined by "," + "]"
//   - object: "{" + keys sorted lexicographically, each as
//     JSON.stringify(key) + ":" + canonicalize(value), joined by "," + "}"
//
// Inputs are expected to be decoded with json.Decoder.UseNumber() so integers
// stay literal (5, not 5.0). A json.Number canonicalizes to its literal string.
func Canonicalize(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case bool:
		if v {
			return "true"
		}
		return "false"
	case string:
		return jsonString(v)
	case json.Number:
		return v.String()
	case float64:
		// Fallback when input was not decoded with UseNumber().
		b, _ := json.Marshal(v)
		return string(b)
	case int:
		b, _ := json.Marshal(v)
		return string(b)
	case int64:
		b, _ := json.Marshal(v)
		return string(b)
	case []any:
		parts := make([]string, len(v))
		for i, el := range v {
			parts[i] = Canonicalize(el)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			// Drop keys whose value is undefined. JSON has no undefined; an
			// absent optional field simply is not a key in the map, so there
			// is nothing to drop here. A field set to JSON null is kept.
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, jsonString(k)+":"+Canonicalize(v[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		// Any other concrete type: best-effort via the JSON marshaller.
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// Sha256Hex returns the lowercase hex sha256 of the UTF-8 bytes of input.
func Sha256Hex(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}
