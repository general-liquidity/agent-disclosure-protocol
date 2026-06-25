"""Native Python verifier for the Agent Disclosure Protocol (ADP).

A from-scratch port of the TypeScript reference (`src/attestation.ts`,
`src/verify.ts`, `src/handshake.ts`). It byte-matches the reference's
canonicalization so ed25519 signatures verify across stacks, and reproduces the
counterparty verdict + challenge-response handshake the conformance contract pins.
"""

from .canonical import canonicalize, sha256_hex
from .attestation import (
    verify_disclosure_signature,
    verify_disclosure_jws,
    verify_any_disclosure_signature,
    verify_key_binding,
    is_jws_signed_disclosure,
    is_fresh,
)
from .verify import (
    evaluate_disclosure,
    evaluate_raw,
    verify_raw,
    Verdict,
    VerificationPolicy,
)
from .handshake import verify_challenge_response, respond_to_challenge
from .emit import (
    AgentKey,
    generate_agent_key,
    agent_key_from_private_hex,
    sign_message,
    sign_disclosure,
    sign_disclosure_jws,
)
from .modules import verify_redacted, verify_revocation, verify_inclusion_proof

__all__ = [
    "canonicalize",
    "sha256_hex",
    "verify_disclosure_signature",
    "verify_disclosure_jws",
    "verify_any_disclosure_signature",
    "verify_key_binding",
    "is_jws_signed_disclosure",
    "is_fresh",
    "evaluate_disclosure",
    "evaluate_raw",
    "verify_raw",
    "Verdict",
    "VerificationPolicy",
    "verify_challenge_response",
    "respond_to_challenge",
    "AgentKey",
    "generate_agent_key",
    "agent_key_from_private_hex",
    "sign_message",
    "sign_disclosure",
    "sign_disclosure_jws",
    "verify_redacted",
    "verify_revocation",
    "verify_inclusion_proof",
]
