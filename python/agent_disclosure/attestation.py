"""ed25519 signature verification + freshness. Port of `src/attestation.ts`.

Asymmetric verification: the raw 32-byte public key travels as hex in the
envelope and is bound to `agentId`. A disclosure must be signed by the key it
claims as its identity (agentId == signature.publicKey).
"""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize


def verify_message(message: str, public_key_hex: str, signature_hex: str) -> bool:
    """Verify a hex ed25519 signature over a UTF-8 message against a 32-byte
    raw public key (hex). Returns False on any malformed input."""
    try:
        raw = bytes.fromhex(public_key_hex)
        if len(raw) != 32:
            return False
        key = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        key.verify(bytes.fromhex(signature_hex), message.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_disclosure_signature(signed: dict):
    """Verify the ed25519 signature over the disclosure and the agentId<->key
    binding. Returns (ok, reason) where reason is None on success."""
    disclosure = signed["disclosure"]
    signature = signed["signature"]
    if disclosure["agentId"] != signature["publicKey"]:
        return False, "agentId does not match the signing public key"
    if verify_message(canonicalize(disclosure), signature["publicKey"], signature["value"]):
        return True, None
    return False, "signature mismatch"


def is_fresh(disclosure: dict, now: str) -> bool:
    """A disclosure is valid only within [issuedAt, validUntil]. ISO-8601
    timestamps compare lexically, matching the TS string comparison."""
    return disclosure["issuedAt"] <= now <= disclosure["validUntil"]
