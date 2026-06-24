#![allow(clippy::result_large_err)]
//! Native Rust verifier for the Agent Disclosure Protocol (ADP).
//!
//! Ports the normative primitives from the TypeScript reference
//! (`src/attestation.ts`, `src/verify.ts`, `src/handshake.ts`) so that a Rust
//! verifier interoperates byte-for-byte with the TS emitter: identical
//! canonicalization, identical ed25519 message bytes, identical policy verdicts.

use ed25519_dalek::{Signature, VerifyingKey};
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
}
