#![allow(clippy::result_large_err)]
//! `verify-url` — fetch a counterparty's published disclosure over HTTP and verify it.
//!
//! Usage: `verify-url <base-url>`
//!
//! Issues an HTTP GET to `<base-url>/.well-known/agent-disclosure`, parses the signed
//! envelope, and runs the core acceptance check: the ed25519 signature over the
//! canonical disclosure plus the identity binding `agentId == signature.publicKey`.
//! Prints the decision and exits 0 when the disclosure is valid, 1 on any
//! invalid-or-transport error (unreachable host, non-200, malformed body, bad binding,
//! signature mismatch). Policy evaluation (freshness, red-team, etc.) is out of scope
//! here — this is the wire-level "is this a genuinely signed, correctly-bound
//! disclosure" gate.

use agent_disclosure::{verify_disclosure_signature, SignedDisclosure};
use serde_json::Value;

const WELL_KNOWN_PATH: &str = "/.well-known/agent-disclosure";

fn main() {
    let mut args = std::env::args().skip(1);
    let base = match args.next() {
        Some(b) => b,
        None => {
            eprintln!("usage: verify-url <base-url>");
            std::process::exit(1);
        }
    };

    match run(&base) {
        Ok(report) => {
            println!("{report}");
            std::process::exit(0);
        }
        Err(reason) => {
            eprintln!("INVALID: {reason}");
            std::process::exit(1);
        }
    }
}

fn run(base: &str) -> Result<String, String> {
    let url = format!("{}{}", base.trim_end_matches('/'), WELL_KNOWN_PATH);

    let body = ureq::get(&url)
        .call()
        .map_err(|e| format!("transport error fetching {url}: {e}"))?
        .into_string()
        .map_err(|e| format!("could not read response body: {e}"))?;

    let value: Value =
        serde_json::from_str(&body).map_err(|e| format!("response is not valid JSON: {e}"))?;

    let signed = SignedDisclosure::from_value(&value)?;
    verify_disclosure_signature(&signed)?;

    let agent_id = value
        .pointer("/disclosure/agentId")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    let disclosure_id = value
        .pointer("/disclosure/disclosureId")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");

    Ok(format!(
        "VALID: disclosure {disclosure_id} from agent {agent_id} (signature + identity binding verified) at {url}"
    ))
}
