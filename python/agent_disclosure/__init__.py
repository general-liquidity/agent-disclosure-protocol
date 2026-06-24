"""Native Python verifier for the Agent Disclosure Protocol (ADP).

A from-scratch port of the TypeScript reference (`src/attestation.ts`,
`src/verify.ts`, `src/handshake.ts`). It byte-matches the reference's
canonicalization so ed25519 signatures verify across stacks, and reproduces the
counterparty verdict + challenge-response handshake the conformance contract pins.
"""

from .canonical import canonicalize, sha256_hex
from .attestation import verify_disclosure_signature, is_fresh
from .verify import (
    evaluate_disclosure,
    evaluate_raw,
    verify_raw,
    Verdict,
    VerificationPolicy,
)
from .handshake import verify_challenge_response
from .emit import (
    AgentKey,
    generate_agent_key,
    agent_key_from_private_hex,
    sign_message,
    sign_disclosure,
)
from .modules import verify_redacted, verify_revocation, verify_inclusion_proof

__all__ = [
    "canonicalize",
    "sha256_hex",
    "verify_disclosure_signature",
    "is_fresh",
    "evaluate_disclosure",
    "evaluate_raw",
    "verify_raw",
    "Verdict",
    "VerificationPolicy",
    "verify_challenge_response",
    "AgentKey",
    "generate_agent_key",
    "agent_key_from_private_hex",
    "sign_message",
    "sign_disclosure",
    "verify_redacted",
    "verify_revocation",
    "verify_inclusion_proof",
]
