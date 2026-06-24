"""Native Python emitter. Port of the signing half of `src/attestation.ts`.

Mints/loads an ed25519 signing identity and produces signed envelopes whose
bytes are identical to the TS reference: the value is the hex ed25519 signature
over the UTF-8 bytes of `canonicalize(disclosure)`, and the agentId / envelope
publicKey is the raw 32-byte public key as hex.

Key loading mirrors `agentKeyFromPrivateHex`: the fixture stores the private key
as PKCS8 DER hex. For ed25519 the DER is the fixed prefix
`302e020100300506032b657004220420` followed by the 32-byte seed, so the seed is
the trailing 32 bytes and `Ed25519PrivateKey.from_private_bytes` reconstructs it.
"""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from .canonical import canonicalize


class AgentKey:
    """An ed25519 signing identity: the private key plus its raw public hex
    (the agentId + envelope publicKey)."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey):
        self.private_key = private_key
        self.public_key_hex = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()


def generate_agent_key() -> AgentKey:
    """Mint a fresh signing identity."""
    return AgentKey(ed25519.Ed25519PrivateKey.generate())


def agent_key_from_private_hex(hex_str: str) -> AgentKey:
    """Reconstruct a signing identity from a persisted PKCS8 DER private key (hex).

    The 32-byte seed is the trailing 32 bytes of the DER (after the
    `302e020100300506032b657004220420` ed25519 PKCS8 prefix)."""
    der = bytes.fromhex(hex_str)
    seed = der[-32:]
    return AgentKey(ed25519.Ed25519PrivateKey.from_private_bytes(seed))


def sign_message(message: str, priv: AgentKey) -> str:
    """Hex ed25519 signature over the UTF-8 bytes of `message`."""
    return priv.private_key.sign(message.encode("utf-8")).hex()


def sign_disclosure(disclosure: dict, priv: AgentKey) -> dict:
    """Sign a disclosure, returning the signed envelope. agentId and the envelope
    publicKey are the derived raw public hex; the value signs over
    `canonicalize(disclosure)` (the disclosure is signed as-is — set its agentId
    to the key's public hex before signing to satisfy the identity binding)."""
    return {
        "disclosure": disclosure,
        "signature": {
            "algorithm": "ed25519",
            "publicKey": priv.public_key_hex,
            "value": sign_message(canonicalize(disclosure), priv),
        },
    }
