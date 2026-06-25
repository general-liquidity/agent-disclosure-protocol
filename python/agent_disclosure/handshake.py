"""Challenge-response handshake. Port of `src/handshake.ts`.

The response signs over an RFC 9421 (HTTP Message Signatures) *signature base*:
covered-component lines (`adp-*` derived components — no HTTP fields in this
non-HTTP-transport profile) followed by an `@signature-params` line carrying
created/keyid/alg/nonce/tag. A verifier confirms: (1) the nonce answers its own
challenge (anti-replay), (2) the Signature-Input matches the reconstructed params
exactly (no param smuggling), (3) the ed25519 signature verifies over the
reconstructed base (liveness), (4) the response is within max age (default 60s).

ADP deviations from strict RFC 9421 (matching the TS reference): `created` is an
ISO-8601 string (not unix-seconds) and the signature is hex (not an sf-binary
`:base64:` wrapper).
"""

from datetime import datetime

from .attestation import verify_message_hex
from .emit import AgentKey, sign_message

_DEFAULT_MAX_AGE_MS = 60_000

_COMPONENT_AGENT_ID = "adp-agent-id"
_COMPONENT_AUDIT_HEAD = "adp-audit-head"
_COMPONENT_VERSION = "adp-disclosure-version"


def _covered_components(material: dict):
    """Ordered (name, value) covered components. `disclosureVersion` is covered
    only when declared, so a no-version response signs a base with no version
    line (the backward-compatible path)."""
    comps = [
        (_COMPONENT_AGENT_ID, material["agentId"]),
        (_COMPONENT_AUDIT_HEAD, material["auditHead"]),
    ]
    if material.get("disclosureVersion") is not None:
        comps.append((_COMPONENT_VERSION, str(material["disclosureVersion"])))
    return comps


def _signature_params(material: dict) -> str:
    """The `@signature-params` value:
    `(<inner list>);created=...;keyid=...;alg="ed25519";nonce=...;tag=...`."""
    inner = " ".join(f'"{name}"' for name, _ in _covered_components(material))
    params = (
        f"({inner})"
        f';created="{material["signedAt"]}"'
        f';keyid="{material["agentId"]}"'
        f';alg="ed25519"'
        f';nonce="{material["nonce"]}"'
    )
    if material.get("verifierId") is not None:
        params += f';tag="{material["verifierId"]}"'
    return params


def _signature_base(material: dict) -> str:
    """The RFC 9421 signature base: each covered-component line, then the
    `@signature-params` line, joined by newlines."""
    lines = [f'"{name}": {value}' for name, value in _covered_components(material)]
    lines.append(f'"@signature-params": {_signature_params(material)}')
    return "\n".join(lines)


def _signature_input_value(material: dict) -> str:
    """The `Signature-Input` value (labelled `sig`)."""
    return f"sig={_signature_params(material)}"


def respond_to_challenge(
    challenge: dict, key: AgentKey, audit_head: str, now: str, disclosure_version=None
) -> dict:
    """The agent answers a challenge: sign an RFC 9421 signature base binding the
    nonce, live audit head, and agent id.

    Port of `respondToChallenge` (src/handshake.ts). Optionally declares the
    disclosure-schema version it presents (a signed covered component)."""
    material = {
        "agentId": key.public_key_hex,
        "auditHead": audit_head,
        "signedAt": now,
        "nonce": challenge["nonce"],
        "verifierId": challenge.get("verifierId"),
        "disclosureVersion": disclosure_version,
    }
    response = {
        "nonce": challenge["nonce"],
        "agentId": key.public_key_hex,
        "auditHead": audit_head,
        "signedAt": now,
    }
    if disclosure_version is not None:
        response["disclosureVersion"] = disclosure_version
    response["signatureInput"] = _signature_input_value(material)
    response["signature"] = sign_message(_signature_base(material), key)
    return response


def _parse_iso_ms(ts: str) -> float:
    # Match JS Date.parse: ISO-8601 with trailing Z -> epoch milliseconds.
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000.0


def verify_challenge_response(
    response: dict,
    challenge: dict,
    expected_agent_id: str,
    now=None,
    max_age_ms: int = _DEFAULT_MAX_AGE_MS,
    supported_versions=None,
):
    """Verify a challenge response. Returns (ok, reason); reason is None on ok.

    Reconstructs the RFC 9421 signature base from OUR challenge (nonce, verifierId)
    plus the response's claimed values; the response's Signature-Input must match
    exactly (no param smuggling) and the ed25519 signature must verify over the
    reconstructed base — so tampering any covered value or param is caught."""
    if response["nonce"] != challenge["nonce"]:
        return False, "nonce mismatch (replayed or wrong challenge)"
    if response["agentId"] != expected_agent_id:
        return False, "response agentId does not match the disclosure"
    material = {
        "agentId": response["agentId"],
        "auditHead": response["auditHead"],
        "signedAt": response["signedAt"],
        "nonce": challenge["nonce"],
        "verifierId": challenge.get("verifierId"),
        "disclosureVersion": response.get("disclosureVersion"),
    }
    if response.get("signatureInput") != _signature_input_value(material):
        return False, "signature-input does not match the issued challenge"
    if not verify_message_hex(_signature_base(material), response["agentId"], response["signature"]):
        return False, "challenge signature invalid (no live key possession)"
    if supported_versions is not None and response.get("disclosureVersion") is not None:
        if response["disclosureVersion"] not in supported_versions:
            return (
                False,
                f"unsupported disclosure version {response['disclosureVersion']}",
            )
    if now:
        age = _parse_iso_ms(now) - _parse_iso_ms(response["signedAt"])
        if age < 0 or age > max_age_ms:
            return False, "challenge response is stale"
    return True, None
