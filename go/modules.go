package agentdisclosure

import "sort"

// --- Redaction (port of src/redaction.ts verifyRedacted) ------------------------
//
// A redacted view reveals only a subset of fields; the signature is over the
// per-field COMMITMENTS, not the cleartext, so withheld fields stay opaque but
// verifiable. The view is held as generic decoded-JSON maps so the canonical bytes
// match the TS reference exactly (meta + commitments under the signature, and each
// revealed value inside its commitment recompute).

// RedactedView is a holder view revealing only a subset of committed fields. meta,
// commitments, and the revealed values are kept as raw decoded-JSON for byte-exact
// canonicalization. Decode the fixture with json.Decoder.UseNumber().
type RedactedView struct {
	Meta        map[string]any
	Commitments map[string]any
	Revealed    map[string]any // field -> {value, salt}
	Signature   Signature
}

// commit reproduces the redaction commitment: sha256Hex(canonicalize(value)+":"+salt).
func commit(value any, salt string) string {
	return Sha256Hex(Canonicalize(value) + ":" + salt)
}

// VerifyRedacted verifies a redacted view (SPEC.md selective-disclosure):
//  1. meta.agentId equals signature.publicKey (identity binding),
//  2. the signature covers canonicalize({meta, commitments}),
//  3. each revealed field recomputes to its committed value.
//
// Returns (ok, revealedFields) where revealedFields is the sorted set of fields
// whose disclosure is cryptographically proven (empty when ok is false).
func VerifyRedacted(view RedactedView) (bool, []string) {
	agentID, _ := view.Meta["agentId"].(string)
	if agentID != view.Signature.PublicKey {
		return false, nil
	}

	signed := Canonicalize(map[string]any{"meta": view.Meta, "commitments": view.Commitments})
	if !VerifyMessage(signed, view.Signature.PublicKey, view.Signature.Value) {
		return false, nil
	}

	revealedFields := []string{}
	for field, raw := range view.Revealed {
		rv, _ := raw.(map[string]any)
		salt, _ := rv["salt"].(string)
		expected, ok := view.Commitments[field].(string)
		if !ok {
			return false, nil
		}
		if commit(rv["value"], salt) != expected {
			return false, nil
		}
		revealedFields = append(revealedFields, field)
	}
	sort.Strings(revealedFields)
	return true, revealedFields
}

// --- Revocation (port of src/revocation.ts verifyRevocation) --------------------

// SignedRevocation is a revocation attributable to the issuing key. The signed
// bytes are canonicalize({id, reason, revokedAt}).
type SignedRevocation struct {
	ID        string `json:"id"`
	Reason    string `json:"reason"`
	RevokedAt string `json:"revokedAt"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

// VerifyRevocation verifies a signed revocation against its embedded public key.
func VerifyRevocation(rec SignedRevocation) bool {
	body := Canonicalize(map[string]any{
		"id":        rec.ID,
		"reason":    rec.Reason,
		"revokedAt": rec.RevokedAt,
	})
	return VerifyMessage(body, rec.PublicKey, rec.Signature)
}

// --- Transparency (port of src/transparencyTransport.ts verifyInclusionProof) ---

// TransparencyLogEntry is a hash-linked transparency-log entry. Fields are kept as
// raw decoded-JSON (index as json.Number, prevHash as string-or-null) so the entry
// hash recomputes byte-exact. Decode the fixture with json.Decoder.UseNumber().
type TransparencyLogEntry struct {
	Index            any    // json.Number after UseNumber decode
	DisclosureDigest string
	AgentID          string
	IssuedAt         string
	PrevHash         any // string, or nil for the genesis entry
	Hash             string
}

// VerifyInclusionProof recomputes the entry hash from its own fields and confirms
// it matches the stored hash. This catches a log handing back a tampered entry; it
// does not prove the entry sits in the live chain.
func VerifyInclusionProof(entry TransparencyLogEntry) bool {
	expected := Sha256Hex(Canonicalize(map[string]any{
		"index":            entry.Index,
		"disclosureDigest": entry.DisclosureDigest,
		"agentId":          entry.AgentID,
		"issuedAt":         entry.IssuedAt,
		"prevHash":         entry.PrevHash,
	}))
	return expected == entry.Hash
}
