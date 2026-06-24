"""Challenge-response handshake. Port of `src/handshake.ts`.

The response signs canonicalize({nonce, agentId, auditHead, signedAt, verifierId}).
A verifier confirms: (1) the nonce answers its own challenge (anti-replay),
(2) the response is signed by the disclosed agent's key now (liveness),
(3) the response is within max age (default 60s).
"""

from datetime import datetime

from .canonical import canonicalize
from .attestation import verify_message

_DEFAULT_MAX_AGE_MS = 60_000


def _response_message(response: dict, verifier_id) -> str:
    return canonicalize(
        {
            "nonce": response["nonce"],
            "agentId": response["agentId"],
            "auditHead": response["auditHead"],
            "signedAt": response["signedAt"],
            "verifierId": verifier_id,
        }
    )


def _parse_iso_ms(ts: str) -> float:
    # Match JS Date.parse: ISO-8601 with trailing Z -> epoch milliseconds.
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000.0


def verify_challenge_response(
    response: dict,
    challenge: dict,
    expected_agent_id: str,
    now=None,
    max_age_ms: int = _DEFAULT_MAX_AGE_MS,
):
    """Verify a challenge response. Returns (ok, reason); reason is None on ok."""
    if response["nonce"] != challenge["nonce"]:
        return False, "nonce mismatch (replayed or wrong challenge)"
    if response["agentId"] != expected_agent_id:
        return False, "response agentId does not match the disclosure"
    message = _response_message(response, challenge.get("verifierId"))
    if not verify_message(message, response["agentId"], response["signature"]):
        return False, "challenge signature invalid (no live key possession)"
    if now:
        age = _parse_iso_ms(now) - _parse_iso_ms(response["signedAt"])
        if age < 0 or age > max_age_ms:
            return False, "challenge response is stale"
    return True, None
