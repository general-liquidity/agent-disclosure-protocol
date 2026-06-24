#![allow(clippy::result_large_err)]
//! Native Rust verifier for the Agent Disclosure Protocol (ADP).
//!
//! Ports the normative primitives from the TypeScript reference
//! (`src/attestation.ts`, `src/verify.ts`, `src/handshake.ts`) so that a Rust
//! verifier interoperates byte-for-byte with the TS emitter: identical
//! canonicalization, identical ed25519 message bytes, identical policy verdicts.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

// ── Canonicalization ─────────────────────────────────────────────────────────

/// Deterministic JSON: object keys sorted lexicographically, recursively, with
/// `null`-valued keys preserved (JSON has no `undefined`). Byte-identical to the
/// reference `canonicalize` in `src/attestation.ts`.
pub fn canonicalize(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => json_string(s),
        Value::Array(arr) => {
            let body: Vec<String> = arr.iter().map(canonicalize).collect();
            format!("[{}]", body.join(","))
        }
        Value::Object(map) => {
            // serde_json's default Map is a BTreeMap (already sorted), but sort
            // explicitly so the algorithm holds regardless of the build's feature
            // flags. Keys are sorted by raw byte/code-unit order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let body: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", json_string(k), canonicalize(&map[*k])))
                .collect();
            format!("{{{}}}", body.join(","))
        }
    }
}

/// JSON-escape a string into a quoted literal (`"hi"`), matching `JSON.stringify`.
fn json_string(s: &str) -> String {
    serde_json::to_string(s).expect("string serialization is infallible")
}

/// sha256 hex of a UTF-8 string.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ── ed25519 message verification ─────────────────────────────────────────────

/// Verify a hex ed25519 signature over the UTF-8 bytes of `message` against a raw
/// 32-byte hex public key. Returns false on any decode/length/verify failure.
pub fn verify_message(message: &str, public_key_hex: &str, signature_hex: &str) -> bool {
    let pk_bytes = match hex::decode(public_key_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk_arr: [u8; 32] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let key = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_arr);
    key.verify_strict(message.as_bytes(), &sig).is_ok()
}

// ── Emitter (signer) ─────────────────────────────────────────────────────────

/// Load an ed25519 signing key from a PKCS8 DER hex string (the persisted form
/// emitted by the TS `exportAgentKey`). The 32-byte ed25519 seed is the trailing
/// 32 bytes after the fixed PKCS8 prefix `302e020100300506032b657004220420`.
/// Returns None if the hex is malformed or not the expected 48-byte PKCS8 shape.
pub fn signing_key_from_pkcs8_hex(pkcs8_hex: &str) -> Option<SigningKey> {
    const PKCS8_PREFIX: &str = "302e020100300506032b657004220420";
    let lower = pkcs8_hex.to_ascii_lowercase();
    let seed_hex = lower.strip_prefix(PKCS8_PREFIX)?;
    let seed_bytes = hex::decode(seed_hex).ok()?;
    let seed: [u8; 32] = seed_bytes.try_into().ok()?;
    Some(SigningKey::from_bytes(&seed))
}

/// The raw 32-byte verifying (public) key as hex — the agentId + envelope publicKey.
pub fn verifying_key_hex(signing_key: &SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_bytes())
}

/// Sign an arbitrary UTF-8 message, returning the hex signature. Byte-identical to
/// the reference `signMessage` (ed25519 over the message's UTF-8 bytes).
pub fn sign_message(message: &str, signing_key: &SigningKey) -> String {
    hex::encode(signing_key.sign(message.as_bytes()).to_bytes())
}

/// Sign a disclosure, producing the signed envelope. The signature is over
/// `canonicalize(disclosure)`; `agentId` (inside the disclosure) and
/// `signature.publicKey` both carry the derived verifying-key hex. Mirrors the TS
/// `signDisclosure` so the resulting `signature.value` is byte-identical.
pub fn sign_disclosure(disclosure: &Value, signing_key: &SigningKey) -> SignedDisclosure {
    let public_key = verifying_key_hex(signing_key);
    let value = sign_message(&canonicalize(disclosure), signing_key);
    SignedDisclosure {
        disclosure: disclosure.clone(),
        signature_algorithm: "ed25519".to_string(),
        signature_public_key: public_key,
        signature_value: value,
    }
}

// ── Signed disclosure types ──────────────────────────────────────────────────

/// A signed disclosure envelope: the disclosure document plus its ed25519 signature.
/// Held as raw JSON so canonicalization sees exactly what was on the wire.
pub struct SignedDisclosure {
    pub disclosure: Value,
    pub signature_algorithm: String,
    pub signature_public_key: String,
    pub signature_value: String,
}

impl SignedDisclosure {
    /// Parse from a `{ disclosure, signature: { algorithm, publicKey, value } }` JSON value.
    pub fn from_value(v: &Value) -> Result<SignedDisclosure, String> {
        let disclosure = v
            .get("disclosure")
            .ok_or_else(|| "missing disclosure".to_string())?
            .clone();
        let sig = v
            .get("signature")
            .ok_or_else(|| "missing signature".to_string())?;
        let get_str = |k: &str| -> Result<String, String> {
            sig.get(k)
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| format!("missing signature.{k}"))
        };
        Ok(SignedDisclosure {
            disclosure,
            signature_algorithm: get_str("algorithm")?,
            signature_public_key: get_str("publicKey")?,
            signature_value: get_str("value")?,
        })
    }

    fn agent_id(&self) -> Option<&str> {
        self.disclosure.get("agentId").and_then(|v| v.as_str())
    }
}

/// Verify the ed25519 signature over the disclosure, enforcing the identity binding
/// `agentId == signature.publicKey` BEFORE checking the signature value.
pub fn verify_disclosure_signature(signed: &SignedDisclosure) -> Result<(), String> {
    if signed.agent_id() != Some(signed.signature_public_key.as_str()) {
        return Err("agentId does not match the signing public key".to_string());
    }
    let canonical = canonicalize(&signed.disclosure);
    if verify_message(
        &canonical,
        &signed.signature_public_key,
        &signed.signature_value,
    ) {
        Ok(())
    } else {
        Err("signature mismatch".to_string())
    }
}

/// Freshness: `now >= issuedAt && now <= validUntil`, by ISO-8601 lexical comparison.
pub fn is_fresh(disclosure: &Value, now: &str) -> bool {
    let issued_at = disclosure.get("issuedAt").and_then(|v| v.as_str());
    let valid_until = disclosure.get("validUntil").and_then(|v| v.as_str());
    match (issued_at, valid_until) {
        (Some(i), Some(u)) => now >= i && now <= u,
        _ => false,
    }
}

// ── Counterparty policy ──────────────────────────────────────────────────────

fn grade_rank(g: &str) -> i32 {
    match g {
        "A" => 4,
        "B" => 3,
        "C" => 2,
        "D" => 1,
        "F" => 0,
        _ => -1,
    }
}

fn attestation_rank(l: &str) -> i32 {
    match l {
        "registry_attested" => 2,
        "signed" => 1,
        "none" => 0,
        _ => -1,
    }
}

/// What a verifier demands of a counterparty before transacting. Every field is
/// optional; defaults mirror the TS `VerificationPolicy`.
#[derive(Default)]
pub struct VerificationPolicy {
    pub now: String,
    pub require_valid_signature: Option<bool>,
    pub require_fresh: Option<bool>,
    pub require_enforced_constitution: bool,
    pub required_hard_constraints: Vec<String>,
    pub require_red_team: bool,
    pub min_red_team_grade: Option<String>,
    pub max_red_team_hard_fails: Option<usize>,
    pub require_non_custodial: bool,
    pub min_attestation_level: Option<String>,
    pub require_deployment_history: bool,
    pub require_audit_anchor: bool,
    pub require_model_fingerprint: bool,
    pub allowed_model_digests: Vec<String>,
    pub require_provenance_for: Vec<String>,
}

/// The verdict: a transact/refuse decision and a per-check pass/fail map.
pub struct Verdict {
    pub decision: String,
    pub checks: std::collections::BTreeMap<String, bool>,
    pub reasons: Vec<String>,
}

impl Verdict {
    /// Sorted names of the checks that failed.
    pub fn failed_checks(&self) -> Vec<String> {
        let mut failed: Vec<String> = self
            .checks
            .iter()
            .filter(|(_, &ok)| !ok)
            .map(|(name, _)| name.clone())
            .collect();
        failed.sort();
        failed
    }
}

/// Evaluate a signed disclosure against a verifier's policy. Mirrors
/// `evaluateDisclosure` in `src/verify.ts`: every enabled predicate runs, the
/// decision is `transact` only when zero reasons accumulated.
pub fn evaluate_disclosure(signed: &SignedDisclosure, policy: &VerificationPolicy) -> Verdict {
    let mut checks: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
    let mut reasons: Vec<String> = Vec::new();

    let d = &signed.disclosure;

    // signature (default on)
    if policy.require_valid_signature != Some(false) {
        match verify_disclosure_signature(signed) {
            Ok(()) => {
                checks.insert("signature".into(), true);
            }
            Err(reason) => {
                checks.insert("signature".into(), false);
                reasons.push(format!("signature invalid: {reason}"));
            }
        }
    }

    // freshness (default on)
    if policy.require_fresh != Some(false) {
        if is_fresh(d, &policy.now) {
            checks.insert("freshness".into(), true);
        } else {
            let vu = d
                .get("validUntil")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            checks.insert("freshness".into(), false);
            reasons.push(format!("disclosure not fresh (valid until {vu})"));
        }
    }

    if policy.require_enforced_constitution {
        let enforced = d
            .pointer("/constitution/enforced")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if enforced {
            checks.insert("enforcedConstitution".into(), true);
        } else {
            checks.insert("enforcedConstitution".into(), false);
            reasons.push("constitution is declared but not enforced at runtime".into());
        }
    }

    if !policy.required_hard_constraints.is_empty() {
        let present: std::collections::HashSet<String> = d
            .pointer("/constitution/hardConstraints")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| c.get("id").and_then(|x| x.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let missing: Vec<String> = policy
            .required_hard_constraints
            .iter()
            .filter(|id| !present.contains(*id))
            .cloned()
            .collect();
        if missing.is_empty() {
            checks.insert("requiredHardConstraints".into(), true);
        } else {
            checks.insert("requiredHardConstraints".into(), false);
            reasons.push(format!(
                "missing required hard constraints: {}",
                missing.join(", ")
            ));
        }
    }

    let red_team = d.get("redTeam").filter(|v| !v.is_null());
    if policy.require_red_team && red_team.is_none() {
        checks.insert("redTeamPresent".into(), false);
        reasons.push("no red-team attestation".into());
    } else if let Some(rt) = red_team {
        if let Some(min_grade) = &policy.min_red_team_grade {
            let grade = rt
                .pointer("/result/grade")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if grade_rank(grade) >= grade_rank(min_grade) {
                checks.insert("redTeamGrade".into(), true);
            } else {
                checks.insert("redTeamGrade".into(), false);
                reasons.push(format!(
                    "red-team grade {grade} below minimum {min_grade}"
                ));
            }
        }
        let max_fails = policy.max_red_team_hard_fails.unwrap_or(0);
        let hard_fails = rt
            .pointer("/result/hardFails")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        if hard_fails <= max_fails {
            checks.insert("redTeamHardFails".into(), true);
        } else {
            checks.insert("redTeamHardFails".into(), false);
            reasons.push(format!(
                "red-team hard-fails {hard_fails} exceed max {max_fails}"
            ));
        }
    }

    if policy.require_non_custodial {
        let custody = d
            .pointer("/capital/custody")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if custody == "non_custodial" {
            checks.insert("nonCustodial".into(), true);
        } else {
            checks.insert("nonCustodial".into(), false);
            reasons.push("operation is custodial".into());
        }
    }

    if let Some(min_level) = &policy.min_attestation_level {
        let level = d
            .pointer("/operator/attestation/level")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if attestation_rank(level) >= attestation_rank(min_level) {
            checks.insert("attestationLevel".into(), true);
        } else {
            checks.insert("attestationLevel".into(), false);
            reasons.push(format!(
                "attestation level {level} below {min_level}"
            ));
        }
    }

    if policy.require_deployment_history {
        let total = d
            .pointer("/history/summary/totalDecisions")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if total > 0 {
            checks.insert("deploymentHistory".into(), true);
        } else {
            checks.insert("deploymentHistory".into(), false);
            reasons.push("no deployment history".into());
        }
    }

    if policy.require_audit_anchor {
        let has_anchor = d
            .get("auditAnchor")
            .map(|v| !v.is_null())
            .unwrap_or(false);
        if has_anchor {
            checks.insert("auditAnchor".into(), true);
        } else {
            checks.insert("auditAnchor".into(), false);
            reasons.push("disclosure is not bound to an audit anchor".into());
        }
    }

    if policy.require_model_fingerprint {
        let has_model = d.get("model").map(|v| !v.is_null()).unwrap_or(false);
        if has_model {
            checks.insert("modelFingerprint".into(), true);
        } else {
            checks.insert("modelFingerprint".into(), false);
            reasons.push("no declared model identity".into());
        }
    }

    if !policy.allowed_model_digests.is_empty() {
        let model_digest = d.pointer("/model/digest").and_then(|v| v.as_str());
        match model_digest {
            Some(dig) if policy.allowed_model_digests.iter().any(|a| a == dig) => {
                checks.insert("modelDigest".into(), true);
            }
            Some(_) => {
                checks.insert("modelDigest".into(), false);
                reasons.push("declared model digest is not in the allowed set".into());
            }
            None => {
                checks.insert("modelDigest".into(), false);
                reasons.push("no declared model to match".into());
            }
        }
    }

    if !policy.require_provenance_for.is_empty() {
        let prov = d.get("provenance");
        let missing: Vec<String> = policy
            .require_provenance_for
            .iter()
            .filter(|f| {
                prov.and_then(|p| p.get(f.as_str()))
                    .map(|v| v.is_null())
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if missing.is_empty() {
            checks.insert("provenance".into(), true);
        } else {
            checks.insert("provenance".into(), false);
            reasons.push(format!("missing provenance for: {}", missing.join(", ")));
        }
    }

    Verdict {
        decision: if reasons.is_empty() {
            "transact".into()
        } else {
            "refuse".into()
        },
        checks,
        reasons,
    }
}

// ── Handshake ────────────────────────────────────────────────────────────────

/// A live challenge-response proving the counterparty holds the signing key now.
pub struct ChallengeResponse {
    pub nonce: String,
    pub agent_id: String,
    pub audit_head: String,
    pub signed_at: String,
    pub signature: String,
}

/// A verifier-issued challenge.
pub struct Challenge {
    pub nonce: String,
    pub verifier_id: Option<String>,
}

/// Canonical bytes the response signs over: `canonicalize({nonce, agentId,
/// auditHead, signedAt, verifierId})`. An absent `verifierId` is dropped.
fn response_message(response: &ChallengeResponse, verifier_id: Option<&str>) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("nonce".into(), Value::String(response.nonce.clone()));
    obj.insert("agentId".into(), Value::String(response.agent_id.clone()));
    obj.insert(
        "auditHead".into(),
        Value::String(response.audit_head.clone()),
    );
    obj.insert("signedAt".into(), Value::String(response.signed_at.clone()));
    if let Some(vid) = verifier_id {
        obj.insert("verifierId".into(), Value::String(vid.to_string()));
    }
    canonicalize(&Value::Object(obj))
}

/// Answer a challenge: build `{nonce, agentId, auditHead, signedAt}` and sign over
/// `canonicalize({nonce, agentId, auditHead, signedAt, verifierId})` (the `verifierId`
/// taken from the challenge, dropped if absent). Byte-identical to the reference
/// `respondToChallenge` in `src/handshake.ts`. `agentId` is the signer's verifying key.
pub fn respond_to_challenge(
    challenge: &Challenge,
    signing_key: &SigningKey,
    audit_head: &str,
    now: &str,
) -> ChallengeResponse {
    let mut response = ChallengeResponse {
        nonce: challenge.nonce.clone(),
        agent_id: verifying_key_hex(signing_key),
        audit_head: audit_head.to_string(),
        signed_at: now.to_string(),
        signature: String::new(),
    };
    let message = response_message(&response, challenge.verifier_id.as_deref());
    response.signature = sign_message(&message, signing_key);
    response
}

/// Verify a challenge response, in the spec's MUST order: nonce match, agentId
/// match, signature, freshness. Audit-head currency is treated as a non-fatal
/// signal (matching the reference). `now` is optional; when supplied the response
/// must be within `max_age_ms` (default 60_000) and not from the future.
pub fn verify_challenge_response(
    response: &ChallengeResponse,
    challenge: &Challenge,
    expected_agent_id: &str,
    now: Option<&str>,
) -> Result<(), String> {
    verify_challenge_response_with_max_age(response, challenge, expected_agent_id, now, 60_000)
}

/// As [`verify_challenge_response`] but with an explicit max response age in ms.
pub fn verify_challenge_response_with_max_age(
    response: &ChallengeResponse,
    challenge: &Challenge,
    expected_agent_id: &str,
    now: Option<&str>,
    max_age_ms: i64,
) -> Result<(), String> {
    if response.nonce != challenge.nonce {
        return Err("nonce mismatch (replayed or wrong challenge)".to_string());
    }
    if response.agent_id != expected_agent_id {
        return Err("response agentId does not match the disclosure".to_string());
    }
    let message = response_message(response, challenge.verifier_id.as_deref());
    if !verify_message(&message, &response.agent_id, &response.signature) {
        return Err("challenge signature invalid (no live key possession)".to_string());
    }
    if let Some(now_str) = now {
        let now_ms = parse_iso_millis(now_str)
            .ok_or_else(|| "could not parse now timestamp".to_string())?;
        let signed_ms = parse_iso_millis(&response.signed_at)
            .ok_or_else(|| "could not parse signedAt timestamp".to_string())?;
        let age = now_ms - signed_ms;
        if age < 0 || age > max_age_ms {
            return Err("challenge response is stale".to_string());
        }
    }
    Ok(())
}

/// Parse an ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SS.sssZ`) to epoch
/// milliseconds. Mirrors `Date.parse` for the zero-padded UTC form the protocol
/// mandates; returns None on a shape it does not recognize.
fn parse_iso_millis(s: &str) -> Option<i64> {
    // Expected: 2026-06-24T12:30:00.000Z  (millis + trailing Z optional but present in fixtures)
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;
    let millis: i64 = if s.len() >= 23 && s.as_bytes().get(19) == Some(&b'.') {
        s.get(20..23)?.parse().ok()?
    } else {
        0
    };

    // Days from civil date (Howard Hinnant's algorithm) -> days since 1970-01-01.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;

    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + millis)
}

// ── Redaction (selective disclosure) ─────────────────────────────────────────

/// Commitment for a field: `sha256(canonicalize(value):salt)`. Byte-identical to
/// the reference `commit` in `src/redaction.ts`.
fn redaction_commit(value: &Value, salt: &str) -> String {
    sha256_hex(&format!("{}:{}", canonicalize(value), salt))
}

/// Verify a redacted view (port of `verifyRedacted`):
///   1. `meta.agentId == signature.publicKey` (identity binding),
///   2. the signature covers `{meta, commitments}`,
///   3. each revealed field recomputes to its committed value.
///
/// Returns `(ok, revealedFields)` — on success `revealedFields` is the sorted set
/// of cryptographically-proven field names; on any failure it is empty.
pub fn verify_redacted(view: &Value) -> (bool, Vec<String>) {
    let meta = match view.get("meta") {
        Some(m) => m,
        None => return (false, Vec::new()),
    };
    let signature = match view.get("signature") {
        Some(s) => s,
        None => return (false, Vec::new()),
    };
    let agent_id = meta.get("agentId").and_then(|v| v.as_str());
    let public_key = signature.get("publicKey").and_then(|v| v.as_str());
    if agent_id.is_none() || agent_id != public_key {
        return (false, Vec::new());
    }
    let commitments = match view.get("commitments") {
        Some(c) => c,
        None => return (false, Vec::new()),
    };

    let mut signed_obj = serde_json::Map::new();
    signed_obj.insert("meta".into(), meta.clone());
    signed_obj.insert("commitments".into(), commitments.clone());
    let signed = canonicalize(&Value::Object(signed_obj));
    let sig_value = signature.get("value").and_then(|v| v.as_str()).unwrap_or("");
    if !verify_message(&signed, public_key.unwrap(), sig_value) {
        return (false, Vec::new());
    }

    let revealed = match view.get("revealed").and_then(|v| v.as_object()) {
        Some(r) => r,
        None => return (true, Vec::new()),
    };
    let commitment_map = match commitments.as_object() {
        Some(c) => c,
        None => return (false, Vec::new()),
    };

    let mut revealed_fields: Vec<String> = Vec::new();
    for (field, rv) in revealed {
        let expected = match commitment_map.get(field).and_then(|v| v.as_str()) {
            Some(e) => e,
            None => return (false, Vec::new()),
        };
        let value = match rv.get("value") {
            Some(v) => v,
            None => return (false, Vec::new()),
        };
        let salt = rv.get("salt").and_then(|v| v.as_str()).unwrap_or("");
        if redaction_commit(value, salt) != expected {
            return (false, Vec::new());
        }
        revealed_fields.push(field.clone());
    }
    revealed_fields.sort();
    (true, revealed_fields)
}

// ── Revocation ───────────────────────────────────────────────────────────────

/// Verify a signed revocation record against its embedded public key (port of
/// `verifyRevocation`): the signed bytes are `canonicalize({id, reason, revokedAt})`.
pub fn verify_revocation(record: &Value) -> bool {
    let get = |k: &str| record.get(k).and_then(|v| v.as_str());
    let (id, reason, revoked_at, public_key, signature) = match (
        get("id"),
        get("reason"),
        get("revokedAt"),
        get("publicKey"),
        get("signature"),
    ) {
        (Some(i), Some(r), Some(a), Some(p), Some(s)) => (i, r, a, p, s),
        _ => return false,
    };
    let mut obj = serde_json::Map::new();
    obj.insert("id".into(), Value::String(id.to_string()));
    obj.insert("reason".into(), Value::String(reason.to_string()));
    obj.insert("revokedAt".into(), Value::String(revoked_at.to_string()));
    let message = canonicalize(&Value::Object(obj));
    verify_message(&message, public_key, signature)
}

// ── Transparency (inclusion proof) ───────────────────────────────────────────

/// Verify a transparency-log inclusion proof standalone (port of
/// `verifyInclusionProof`): recompute the entry hash from its own fields and
/// confirm it matches `entry.hash`. Hashed bytes are
/// `canonicalize({index, disclosureDigest, agentId, issuedAt, prevHash})`.
pub fn verify_inclusion_proof(entry: &Value) -> bool {
    let index = match entry.get("index") {
        Some(i) if i.is_number() => i.clone(),
        _ => return false,
    };
    let get = |k: &str| entry.get(k).and_then(|v| v.as_str());
    let (disclosure_digest, agent_id, issued_at, prev_hash, hash) = match (
        get("disclosureDigest"),
        get("agentId"),
        get("issuedAt"),
        get("prevHash"),
        get("hash"),
    ) {
        (Some(d), Some(a), Some(i), Some(p), Some(h)) => (d, a, i, p, h),
        _ => return false,
    };
    let mut obj = serde_json::Map::new();
    obj.insert("index".into(), index);
    obj.insert(
        "disclosureDigest".into(),
        Value::String(disclosure_digest.to_string()),
    );
    obj.insert("agentId".into(), Value::String(agent_id.to_string()));
    obj.insert("issuedAt".into(), Value::String(issued_at.to_string()));
    obj.insert("prevHash".into(), Value::String(prev_hash.to_string()));
    let expected = sha256_hex(&canonicalize(&Value::Object(obj)));
    expected == hash
}

// ── Robust raw-input rejection ───────────────────────────────────────────────

/// Strict structural + cryptographic acceptance check for an untrusted, raw JSON
/// envelope. Returns `true` if the input is REJECTED (the safe default) and `false`
/// only for a structurally valid, correctly-bound, validly-signed disclosure.
///
/// This is the hostile-input entry point: it parses with serde_json and runs the
/// full verify pipeline, treating ANY failure — parse error, missing/extra fields,
/// wrong types, non-hex material, an `agentId` that does not match
/// `signature.publicKey`, or a signature that does not verify — as a rejection. It
/// never panics: every step propagates through `Result`, so no `unwrap`/`expect`
/// touches untrusted data. A malformed or tampered disclosure is never accepted.
pub fn verify_raw(raw: &str) -> bool {
    accept_raw(raw).is_err()
}

/// Internal: returns `Ok(())` only for an acceptable disclosure, `Err(reason)` for
/// anything else. `verify_raw` is the negated public surface.
fn accept_raw(raw: &str) -> Result<(), String> {
    let value: Value = serde_json::from_str(raw).map_err(|e| format!("parse error: {e}"))?;
    let envelope = value.as_object().ok_or("top-level value is not an object")?;
    require_only_keys(envelope, &["disclosure", "signature"])?;

    let disclosure = envelope
        .get("disclosure")
        .ok_or("missing disclosure")?
        .as_object()
        .ok_or("disclosure is not an object")?;
    validate_disclosure(disclosure)?;

    let signature = envelope
        .get("signature")
        .ok_or("missing signature")?
        .as_object()
        .ok_or("signature is not an object")?;
    require_only_keys(signature, &["algorithm", "publicKey", "value"])?;
    require_literal_str(signature, "algorithm", "ed25519")?;
    let public_key = require_hex(signature, "publicKey")?;
    let sig_value = require_hex(signature, "value")?;

    let signed = SignedDisclosure {
        disclosure: envelope["disclosure"].clone(),
        signature_algorithm: "ed25519".to_string(),
        signature_public_key: public_key,
        signature_value: sig_value,
    };
    verify_disclosure_signature(&signed)
}

/// Reject if `obj` carries any key outside `allowed` (no extra fields).
fn require_only_keys(
    obj: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), String> {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("unexpected field: {key}"));
        }
    }
    Ok(())
}

fn require_str<'a>(
    obj: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, String> {
    obj.get(key)
        .ok_or_else(|| format!("missing {key}"))?
        .as_str()
        .ok_or_else(|| format!("{key} is not a string"))
}

fn require_literal_str(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    want: &str,
) -> Result<(), String> {
    if require_str(obj, key)? == want {
        Ok(())
    } else {
        Err(format!("{key} is not the expected literal {want:?}"))
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn require_hex(
    obj: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, String> {
    let s = require_str(obj, key)?;
    if is_hex(s) {
        Ok(s.to_string())
    } else {
        Err(format!("{key} is not a hex string"))
    }
}

fn require_array<'a>(
    obj: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a Vec<Value>, String> {
    obj.get(key)
        .ok_or_else(|| format!("missing {key}"))?
        .as_array()
        .ok_or_else(|| format!("{key} is not an array"))
}

fn require_object<'a>(
    obj: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    obj.get(key)
        .ok_or_else(|| format!("missing {key}"))?
        .as_object()
        .ok_or_else(|| format!("{key} is not an object"))
}

fn require_bool(obj: &serde_json::Map<String, Value>, key: &str) -> Result<bool, String> {
    obj.get(key)
        .ok_or_else(|| format!("missing {key}"))?
        .as_bool()
        .ok_or_else(|| format!("{key} is not a bool"))
}

/// Validate the disclosure document against the normative schema (mirror of the TS
/// `AgentDisclosureSchema`): required typed fields, hex digests, and the version
/// literal. Optional fields are only type-checked when present. Returns `Err` on the
/// first violation so an invalid disclosure can never be accepted.
fn validate_disclosure(d: &serde_json::Map<String, Value>) -> Result<(), String> {
    if d.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("version must be the integer literal 1".to_string());
    }
    require_str(d, "disclosureId")?;
    require_hex(d, "agentId")?;
    require_str(d, "issuedAt")?;
    require_str(d, "validUntil")?;
    require_str(d, "nonce")?;

    let system_prompt = require_object(d, "systemPrompt")?;
    require_literal_str(system_prompt, "algorithm", "sha256")?;
    require_hex(system_prompt, "digest")?;

    let constitution = require_object(d, "constitution")?;
    require_array(constitution, "hardConstraints")?;
    require_hex(constitution, "digest")?;
    require_bool(constitution, "enforced")?;

    let tools = require_object(d, "tools")?;
    require_array(tools, "tools")?;

    let capital = require_object(d, "capital")?;
    require_array(capital, "mandates")?;
    let custody = require_str(capital, "custody")?;
    if custody != "non_custodial" && custody != "custodial" {
        return Err("capital.custody is not a valid enum value".to_string());
    }

    let operator = require_object(d, "operator")?;
    require_str(operator, "operatorId")?;
    require_object(operator, "attestation")?;
    require_str(operator, "deniabilityBoundary")?;

    let history = require_object(d, "history")?;
    require_hex(history, "chainAnchor")?;
    let summary = require_object(history, "summary")?;
    for key in ["totalDecisions", "settledCount", "blockedCount"] {
        if summary.get(key).and_then(Value::as_u64).is_none() {
            return Err(format!("history.summary.{key} is not a non-negative integer"));
        }
    }

    // `auditAnchor`, `redTeam`, `model`, `provenance` are optional; if a verifier
    // policy demands them it checks them in `evaluate_disclosure`. The structural
    // gate here mirrors the required core of the TS schema.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn load(path: &str) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn vectors() -> Value {
        load(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../conformance/vectors.json"
        ))
    }

    fn interop() -> Value {
        load(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../conformance/interop.json"
        ))
    }

    fn fuzz() -> Value {
        load(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../conformance/fuzz.json"
        ))
    }

    // Replay the differential fuzz corpus produced by the TS reference
    // (conformance/generate-fuzz.ts). Rust MUST reproduce each recorded canonical
    // byte-for-byte: proof the two stacks agree on random inputs, not just vectors.
    #[test]
    fn fuzz_canonicalization() {
        let f = fuzz();
        let cases = f.as_array().unwrap();
        assert!(cases.len() >= 200, "fuzz.json corpus missing or too small");
        for (i, case) in cases.iter().enumerate() {
            let got = canonicalize(&case["input"]);
            let want = case["canonical"].as_str().unwrap();
            assert_eq!(got, want, "fuzz[{i}] canonicalize mismatch");
        }
    }

    #[test]
    fn canonicalization_vectors() {
        let v = vectors();
        let cases = v["canonicalization"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let got = canonicalize(&case["input"]);
            let want = case["canonical"].as_str().unwrap();
            assert_eq!(got, want, "canonicalize mismatch for {:?}", case["input"]);
        }
    }

    #[test]
    fn sha256_vectors() {
        let v = vectors();
        let cases = v["sha256"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let input = case["input"].as_str().unwrap();
            let want = case["sha256"].as_str().unwrap();
            assert_eq!(sha256_hex(input), want, "sha256 mismatch for {input:?}");
        }
    }

    fn policy_from(p: &Value) -> VerificationPolicy {
        let str_vec = |key: &str| -> Vec<String> {
            p.get(key)
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };
        VerificationPolicy {
            now: p["now"].as_str().unwrap_or("").to_string(),
            require_valid_signature: p.get("requireValidSignature").and_then(|v| v.as_bool()),
            require_fresh: p.get("requireFresh").and_then(|v| v.as_bool()),
            require_enforced_constitution: p
                .get("requireEnforcedConstitution")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            required_hard_constraints: str_vec("requiredHardConstraints"),
            require_red_team: p
                .get("requireRedTeam")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            min_red_team_grade: p
                .get("minRedTeamGrade")
                .and_then(|v| v.as_str())
                .map(String::from),
            max_red_team_hard_fails: p
                .get("maxRedTeamHardFails")
                .and_then(|v| v.as_u64())
                .map(|n| n as usize),
            require_non_custodial: p
                .get("requireNonCustodial")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            min_attestation_level: p
                .get("minAttestationLevel")
                .and_then(|v| v.as_str())
                .map(String::from),
            require_deployment_history: p
                .get("requireDeploymentHistory")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            require_audit_anchor: p
                .get("requireAuditAnchor")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            require_model_fingerprint: p
                .get("requireModelFingerprint")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            allowed_model_digests: str_vec("allowedModelDigests"),
            require_provenance_for: str_vec("requireProvenanceFor"),
        }
    }

    #[test]
    fn interop_disclosures() {
        let i = interop();
        let cases = i["disclosures"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let signed = SignedDisclosure::from_value(&case["signed"]).unwrap();
            let policy = policy_from(&case["policy"]);
            let verdict = evaluate_disclosure(&signed, &policy);

            let want_decision = case["expect"]["decision"].as_str().unwrap();
            assert_eq!(verdict.decision, want_decision, "decision for {name}");

            let want_failed: Vec<String> = case["expect"]["failed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            assert_eq!(verdict.failed_checks(), want_failed, "failed checks for {name}");
        }
    }

    #[test]
    fn interop_signatures_verify() {
        // Every disclosure whose expected verdict is NOT a signature failure must
        // have a valid signature; the canonical bytes therefore matched the TS emitter.
        let i = interop();
        for case in i["disclosures"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let failed: Vec<&str> = case["expect"]["failed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            let signed = SignedDisclosure::from_value(&case["signed"]).unwrap();
            let sig_ok = verify_disclosure_signature(&signed).is_ok();
            if failed.contains(&"signature") {
                assert!(!sig_ok, "expected signature failure for {name}");
            } else {
                assert!(sig_ok, "expected valid signature for {name}");
            }
        }
    }

    #[test]
    fn interop_handshakes() {
        let i = interop();
        let cases = i["handshakes"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let resp = &case["response"];
            let response = ChallengeResponse {
                nonce: resp["nonce"].as_str().unwrap().to_string(),
                agent_id: resp["agentId"].as_str().unwrap().to_string(),
                audit_head: resp["auditHead"].as_str().unwrap().to_string(),
                signed_at: resp["signedAt"].as_str().unwrap().to_string(),
                signature: resp["signature"].as_str().unwrap().to_string(),
            };
            let chal = &case["challenge"];
            let challenge = Challenge {
                nonce: chal["nonce"].as_str().unwrap().to_string(),
                verifier_id: chal.get("verifierId").and_then(|v| v.as_str()).map(String::from),
            };
            let expected_agent_id = case["expectedAgentId"].as_str().unwrap();
            let now = case.get("now").and_then(|v| v.as_str());

            let ok = verify_challenge_response(&response, &challenge, expected_agent_id, now).is_ok();
            let want = case["expect"].as_bool().unwrap();
            assert_eq!(ok, want, "handshake {name}");
        }
    }

    #[test]
    fn responder_byte_matches_fixture() {
        // The responder, signing with the fixed key over the fixture's challenge +
        // audit head + signedAt, MUST reproduce the recorded response.signature
        // byte-for-byte — proof the Rust signer agrees with the TS `respondToChallenge`.
        let i = interop();
        let key = fixed_signing_key();
        let case = &i["handshakes"][0];
        assert_eq!(case["name"].as_str().unwrap(), "valid");
        let chal = &case["challenge"];
        let challenge = Challenge {
            nonce: chal["nonce"].as_str().unwrap().to_string(),
            verifier_id: chal.get("verifierId").and_then(|v| v.as_str()).map(String::from),
        };
        let resp = &case["response"];
        let audit_head = resp["auditHead"].as_str().unwrap();
        let signed_at = resp["signedAt"].as_str().unwrap();

        let produced = respond_to_challenge(&challenge, &key, audit_head, signed_at);
        let want = resp["signature"].as_str().unwrap();
        assert_eq!(produced.signature, want, "responder signature bytes");
        assert_eq!(produced.nonce, resp["nonce"].as_str().unwrap());
        assert_eq!(produced.agent_id, resp["agentId"].as_str().unwrap());
        assert_eq!(produced.audit_head, audit_head);
        assert_eq!(produced.signed_at, signed_at);
    }

    #[test]
    fn responder_round_trips_through_verifier() {
        // A response the Rust responder produces must pass the Rust verifier.
        let i = interop();
        let key = fixed_signing_key();
        let challenge = Challenge {
            nonce: "rt_nonce".to_string(),
            verifier_id: Some("verifier-rt".to_string()),
        };
        let agent_id = i["key"]["publicKeyHex"].as_str().unwrap();
        let now = "2026-06-24T12:30:00.000Z";
        let response = respond_to_challenge(&challenge, &key, "head_rt", now);
        assert!(
            verify_challenge_response(&response, &challenge, agent_id, Some(now)).is_ok(),
            "responder output must verify"
        );
    }

    #[test]
    fn responder_drops_absent_verifier_id() {
        // With no verifierId on the challenge, the signed bytes omit it — and the
        // response still round-trips through the verifier (which also omits it).
        let key = fixed_signing_key();
        let challenge = Challenge { nonce: "no_vid".to_string(), verifier_id: None };
        let agent_id = verifying_key_hex(&key);
        let now = "2026-06-24T12:30:00.000Z";
        let response = respond_to_challenge(&challenge, &key, "head_x", now);
        assert!(
            verify_challenge_response(&response, &challenge, &agent_id, Some(now)).is_ok(),
            "verifierId-absent response must verify"
        );
    }

    fn fixed_signing_key() -> SigningKey {
        let i = interop();
        let pkcs8 = i["key"]["privateKeyHex"].as_str().unwrap();
        signing_key_from_pkcs8_hex(pkcs8).expect("fixed key parses")
    }

    #[test]
    fn emitter_derives_fixture_public_key() {
        let i = interop();
        let key = fixed_signing_key();
        let want = i["key"]["publicKeyHex"].as_str().unwrap();
        assert_eq!(verifying_key_hex(&key), want, "derived public key");
    }

    #[test]
    fn emitter_byte_matches_ts_signer() {
        // Re-sign each correctly-bound, non-tampered interop disclosure with the
        // fixed key and assert the hex signature EQUALS the fixture's value. This
        // proves the Rust signer produces byte-identical canonical bytes + ed25519
        // output to the TS emitter. Tampered/forged cases are excluded: they fail
        // the identity binding or carry a mismatched digest, so re-signing them
        // would not (and must not) reproduce the fixture signature.
        let i = interop();
        let key = fixed_signing_key();
        let mut signed_count = 0;
        for case in i["disclosures"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let failed: Vec<&str> = case["expect"]["failed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            if failed.contains(&"signature") {
                continue;
            }
            let disclosure = &case["signed"]["disclosure"];
            let emitted = sign_disclosure(disclosure, &key);
            let want = case["signed"]["signature"]["value"].as_str().unwrap();
            assert_eq!(emitted.signature_value, want, "signature bytes for {name}");
            assert_eq!(
                emitted.signature_public_key,
                case["signed"]["signature"]["publicKey"].as_str().unwrap(),
                "public key for {name}"
            );
            signed_count += 1;
        }
        assert!(signed_count > 0, "expected at least one byte-match case");
    }

    #[test]
    fn emitter_round_trip_with_fresh_key() {
        // Emit with a fresh key; the own verifier must accept (and the binding holds).
        let seed: [u8; 32] = [7u8; 32];
        let key = SigningKey::from_bytes(&seed);
        let public_key = verifying_key_hex(&key);
        let disclosure = serde_json::json!({
            "version": 1,
            "disclosureId": "disc_roundtrip",
            "agentId": public_key,
            "issuedAt": "2026-06-24T12:00:00.000Z",
            "validUntil": "2026-06-24T13:00:00.000Z",
            "nonce": "nonce_roundtrip",
            "capital": { "mandates": [], "custody": "non_custodial" }
        });
        let emitted = sign_disclosure(&disclosure, &key);

        let mut envelope = serde_json::Map::new();
        envelope.insert("disclosure".into(), emitted.disclosure.clone());
        let mut sig = serde_json::Map::new();
        sig.insert("algorithm".into(), Value::String(emitted.signature_algorithm.clone()));
        sig.insert("publicKey".into(), Value::String(emitted.signature_public_key.clone()));
        sig.insert("value".into(), Value::String(emitted.signature_value.clone()));
        envelope.insert("signature".into(), Value::Object(sig));

        let parsed = SignedDisclosure::from_value(&Value::Object(envelope)).unwrap();
        assert!(
            verify_disclosure_signature(&parsed).is_ok(),
            "own verifier accepts a freshly-emitted disclosure"
        );
    }

    #[test]
    fn interop_redactions() {
        let i = interop();
        let cases = i["redactions"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let (ok, revealed) = verify_redacted(&case["view"]);
            let want_ok = case["expect"]["ok"].as_bool().unwrap();
            assert_eq!(ok, want_ok, "redaction ok for {name}");
            let want_fields: Vec<String> = case["expect"]["revealedFields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            assert_eq!(revealed, want_fields, "redaction revealed fields for {name}");
        }
    }

    #[test]
    fn interop_revocations() {
        let i = interop();
        let cases = i["revocations"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let ok = verify_revocation(&case["record"]);
            assert_eq!(ok, case["expect"].as_bool().unwrap(), "revocation {name}");
        }
    }

    #[test]
    fn interop_transparency() {
        let i = interop();
        let cases = i["transparency"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let ok = verify_inclusion_proof(&case["entry"]);
            assert_eq!(ok, case["expect"].as_bool().unwrap(), "transparency {name}");
        }
    }

    fn negative() -> Value {
        load(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../conformance/negative.json"
        ))
    }

    // The MUST-REJECT corpus: every case is a malformed, tampered, or forged
    // envelope a verifier MUST refuse and MUST NOT crash on. We feed `verify_raw`
    // the raw bytes (serialized JSON, or the literal string for `isRawString`) and
    // assert rejection. A panic on any case fails the test by definition.
    #[test]
    fn negative_corpus_all_rejected() {
        let n = negative();
        let cases = n["cases"].as_array().unwrap();
        assert!(!cases.is_empty(), "negative.json corpus missing");
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let raw: String = if case["isRawString"].as_bool().unwrap_or(false) {
                case["raw"].as_str().unwrap().to_string()
            } else {
                serde_json::to_string(&case["raw"]).unwrap()
            };
            assert!(
                verify_raw(&raw),
                "negative case {name} MUST be rejected"
            );
        }
    }

    // A correctly-bound, validly-signed envelope is NOT rejected by `verify_raw` —
    // proving the gate is a real accept/reject decision, not a blanket reject.
    #[test]
    fn verify_raw_accepts_valid_envelope() {
        let seed: [u8; 32] = [9u8; 32];
        let key = SigningKey::from_bytes(&seed);
        let public_key = verifying_key_hex(&key);
        let disclosure = serde_json::json!({
            "version": 1,
            "disclosureId": "disc_raw_ok",
            "agentId": public_key,
            "issuedAt": "2026-06-24T12:00:00.000Z",
            "validUntil": "2026-06-24T13:00:00.000Z",
            "nonce": "nonce_raw_ok",
            "systemPrompt": { "algorithm": "sha256", "digest": "abcdef" },
            "constitution": { "hardConstraints": [], "digest": "abcdef", "enforced": true },
            "tools": { "tools": [] },
            "capital": { "mandates": [], "custody": "non_custodial" },
            "operator": {
                "operatorId": "op",
                "attestation": { "scheme": "none", "level": "none" },
                "deniabilityBoundary": "x"
            },
            "history": {
                "chainAnchor": "abcdef",
                "summary": { "totalDecisions": 1, "settledCount": 1, "blockedCount": 0 }
            }
        });
        let emitted = sign_disclosure(&disclosure, &key);
        let envelope = serde_json::json!({
            "disclosure": emitted.disclosure,
            "signature": {
                "algorithm": emitted.signature_algorithm,
                "publicKey": emitted.signature_public_key,
                "value": emitted.signature_value
            }
        });
        let raw = serde_json::to_string(&envelope).unwrap();
        assert!(!verify_raw(&raw), "valid envelope must NOT be rejected");
    }

    // verify_raw must survive arbitrary hostile bytes without panicking.
    #[test]
    fn verify_raw_never_panics_on_garbage() {
        for raw in [
            "",
            "{",
            "[[[[[[",
            "null",
            "\"a string\"",
            "{\"disclosure\":{},\"signature\":{}}",
            "{\"disclosure\":null,\"signature\":null}",
            "1e999",
            "{\"disclosure\":{\"version\":1},\"signature\":{\"algorithm\":\"ed25519\",\"publicKey\":1,\"value\":2}}",
        ] {
            assert!(verify_raw(raw), "garbage {raw:?} must be rejected");
        }
    }
}
