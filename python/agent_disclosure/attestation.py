"""ed25519 signature verification + freshness. Port of `src/attestation.ts`.

Asymmetric verification: the raw 32-byte public key travels as hex in the
envelope and is bound to `agentId`. A disclosure must be signed by the key it
claims as its identity — bound by a direct hex match, the `did:key` encoding of
that key (self-certifying form), or a verified rotation chain (`verify_key_binding`).

Two envelope shapes are supported, discriminated by shape:
  - v1 object envelope: `{disclosure, signature}` — `verify_disclosure_signature`.
  - v2 flattened JWS (EdDSA): `{payload, protected, header, signature}` —
    `verify_disclosure_jws`. The protected header (carrying `alg`) is part of the
    signed input, closing the v1 gap where the algorithm field sat outside the bytes.
"""

import base64
import json

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize

# Multicodec prefix for an ed25519 public key (varint 0xed 0x01); did:key for ed25519
# is "did:key:z" + base58btc(0xed01 || rawPubKey). Mirrors src/did.ts.
_MULTICODEC_ED25519_PUB = bytes([0xED, 0x01])
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b64u_decode(s: str) -> bytes:
    """base64url-decode, restoring the stripped `=` padding (JWS uses unpadded form)."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u_encode(b: bytes) -> str:
    """base64url-encode without padding (the JWS on-wire form)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _base58_encode(data: bytes) -> str:
    """base58btc (Bitcoin alphabet) encode; leading zero bytes map to leading '1's."""
    zeros = 0
    while zeros < len(data) and data[zeros] == 0:
        zeros += 1
    num = int.from_bytes(data, "big")
    digits = ""
    while num > 0:
        num, rem = divmod(num, 58)
        digits = _BASE58_ALPHABET[rem] + digits
    return "1" * zeros + digits


def _agent_id_to_did_key(agent_id_hex: str) -> str:
    """Express an agentId (raw 32-byte ed25519 public key, hex) as a did:key.
    Mirrors `agentIdToDidKey` in src/did.ts. Raises on a non-32-byte key."""
    raw = bytes.fromhex(agent_id_hex)
    if len(raw) != 32:
        raise ValueError("agentId must be a 32-byte ed25519 public key (64 hex chars)")
    return "did:key:z" + _base58_encode(_MULTICODEC_ED25519_PUB + raw)


def verify_message(message: str, public_key_hex: str, signature: bytes) -> bool:
    """Verify an ed25519 `signature` (raw bytes) over a UTF-8 message against a
    32-byte raw public key (hex). Returns False on any malformed input."""
    try:
        raw = bytes.fromhex(public_key_hex)
        if len(raw) != 32:
            return False
        key = ed25519.Ed25519PublicKey.from_public_bytes(raw)
        key.verify(signature, message.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_message_hex(message: str, public_key_hex: str, signature_hex: str) -> bool:
    """Verify a hex ed25519 signature over a UTF-8 message (v1 + handshake form)."""
    try:
        return verify_message(message, public_key_hex, bytes.fromhex(signature_hex))
    except ValueError:
        return False


def verify_key_binding(agent_id: str, signing_key_hex: str, rotation_chain=None):
    """Bind a disclosure's stable `agentId` to the key that actually signed it: a
    direct hex match, the did:key encoding of that key, or a verified rotation
    chain back to the agentId. Returns (ok, reason). Mirrors `verifyKeyBinding`."""
    if agent_id == signing_key_hex:
        return True, None
    try:
        if agent_id == _agent_id_to_did_key(signing_key_hex):
            return True, None
    except ValueError:
        # signing_key_hex is a valid 32-byte key on every call path here; defensive.
        pass
    if rotation_chain:
        return _verify_rotation_chain(agent_id, signing_key_hex, rotation_chain)
    return False, "agentId does not match the signing public key"


_MAX_ROTATION_CHAIN = 32


def _rotation_statement_body(frm: str, to: str, rotated_at: str) -> str:
    return canonicalize({"type": "rotation", "from": frm, "to": to, "rotatedAt": rotated_at})


def _verify_rotation_chain(agent_id: str, signing_key: str, chain):
    """Mirror `verifyRotationChain`: each hop's `from` must sign the move to its
    `to`; hops must be contiguous, acyclic, and end at the signing key."""
    if len(chain) == 0:
        return False, "empty rotation chain"
    if len(chain) > _MAX_ROTATION_CHAIN:
        return False, "rotation chain exceeds maximum length"
    cursor = agent_id
    seen = {agent_id}
    for s in chain:
        if s["from"] != cursor:
            return False, "rotation chain is not contiguous from agentId"
        if not verify_message_hex(
            _rotation_statement_body(s["from"], s["to"], s["rotatedAt"]), s["from"], s["signature"]
        ):
            return False, "a rotation statement signature does not verify against its from key"
        if s["to"] in seen:
            return False, "rotation chain contains a cycle"
        seen.add(s["to"])
        cursor = s["to"]
    if cursor != signing_key:
        return False, "rotation chain does not end at the signing key"
    return True, None


def verify_disclosure_signature(signed: dict):
    """Verify the ed25519 signature over the disclosure (v1 object envelope) and
    the agentId<->key binding. Returns (ok, reason); reason is None on success."""
    disclosure = signed["disclosure"]
    signature = signed["signature"]
    if not verify_message_hex(canonicalize(disclosure), signature["publicKey"], signature["value"]):
        return False, "signature mismatch"
    return verify_key_binding(disclosure["agentId"], signature["publicKey"], signed.get("rotationChain"))


def verify_disclosure_jws(signed: dict):
    """Verify a v2 JWS envelope: the protected header must declare EdDSA, the
    signature must verify over ASCII(protected + "." + payload) against the JWK
    key, and the payload's `agentId` must bind to that key. Mirrors
    `verifyDisclosureJws`. Returns (ok, reason)."""
    try:
        header = json.loads(_b64u_decode(signed["protected"]).decode("utf-8"))
    except Exception:  # noqa: BLE001 — any decode fault is a safe rejection
        return False, "unreadable protected header"
    if header.get("alg") != "EdDSA":
        return False, f"unsupported JWS alg: {header.get('alg')}"

    try:
        pub_hex = _b64u_decode(signed["header"]["jwk"]["x"]).hex()
    except Exception:  # noqa: BLE001
        return False, "unreadable jwk.x"
    if len(pub_hex) != 64:
        return False, "jwk.x is not a 32-byte ed25519 key"

    signing_input = f"{signed['protected']}.{signed['payload']}"
    try:
        sig = _b64u_decode(signed["signature"])
    except Exception:  # noqa: BLE001
        return False, "unreadable signature"
    if not verify_message(signing_input, pub_hex, sig):
        return False, "jws signature mismatch"

    try:
        agent_id = json.loads(_b64u_decode(signed["payload"]).decode("utf-8")).get("agentId")
    except Exception:  # noqa: BLE001
        return False, "unreadable payload"
    if not isinstance(agent_id, str):
        return False, "payload has no agentId"
    return verify_key_binding(agent_id, pub_hex, signed.get("rotationChain"))


def is_jws_signed_disclosure(signed) -> bool:
    """True if the envelope is the v2 flattened-JWS form (discriminated by shape)."""
    return (
        isinstance(signed, dict)
        and isinstance(signed.get("payload"), str)
        and isinstance(signed.get("protected"), str)
    )


def verify_any_disclosure_signature(signed: dict):
    """Verify either envelope shape (v1 object or v2 flattened JWS)."""
    if is_jws_signed_disclosure(signed):
        return verify_disclosure_jws(signed)
    return verify_disclosure_signature(signed)


def disclosure_of(signed: dict) -> dict:
    """Extract the disclosure document from either envelope shape. For v2 it
    base64url-decodes the JCS payload."""
    if is_jws_signed_disclosure(signed):
        return json.loads(_b64u_decode(signed["payload"]).decode("utf-8"))
    return signed["disclosure"]


def is_fresh(disclosure: dict, now: str) -> bool:
    """A disclosure is valid only within [issuedAt, validUntil]. ISO-8601
    timestamps compare lexically, matching the TS string comparison."""
    return disclosure["issuedAt"] <= now <= disclosure["validUntil"]
