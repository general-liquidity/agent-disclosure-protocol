"""Native Python verifier for the Agent Disclosure Protocol (ADP).

A from-scratch port of the TypeScript reference (`src/attestation.ts`,
`src/verify.ts`, `src/handshake.ts`). It byte-matches the reference's
canonicalization so ed25519 signatures verify across stacks, and reproduces the
counterparty verdict + challenge-response handshake the conformance contract pins.
"""

from .canonical import canonicalize, sha256_hex
from .attestation import verify_disclosure_signature, is_fresh
from .verify import evaluate_disclosure, Verdict, VerificationPolicy
from .handshake import verify_challenge_response

__all__ = [
    "canonicalize",
    "sha256_hex",
    "verify_disclosure_signature",
    "is_fresh",
    "evaluate_disclosure",
    "Verdict",
    "VerificationPolicy",
    "verify_challenge_response",
]
