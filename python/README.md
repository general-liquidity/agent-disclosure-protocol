# agent-disclosure (Python)

A native **Python** verifier for the Agent Disclosure Protocol (ADP). It is a
from-scratch port of the TypeScript reference (`../src/`) that passes the shared
cross-language conformance contract in `../conformance/`, proving the protocol is
implementable from the spec in a second stack and interoperates with the TS
reference (signatures produced by the TS signer verify here byte-for-byte).

## What it does

- **`canonicalize(value) -> str`** — deterministic JSON (lexicographically sorted
  keys, no whitespace) that byte-matches `src/attestation.ts`. This is the
  interoperability crux: the ed25519 signature is over the UTF-8 bytes of
  `canonicalize(disclosure)`, so the bytes must be identical across languages.
- **`sha256_hex(s) -> str`** — sha256 hex of a UTF-8 string.
- **`verify_disclosure_signature(signed) -> (ok, reason)`** — ed25519 verification
  plus the `agentId == signature.publicKey` binding (a disclosure must be signed
  by the key it claims as its identity). Raw 32-byte public key, hex everywhere.
- **`is_fresh(disclosure, now) -> bool`** — `issuedAt <= now <= validUntil`
  (ISO-8601 lexical comparison).
- **`evaluate_disclosure(signed, policy) -> Verdict`** — the counterparty
  transact/refuse decision with a per-check pass/fail map. `Verdict.failed`
  returns the sorted names of failed checks. `policy` is a `VerificationPolicy`
  (build from the fixture JSON via `VerificationPolicy.from_json(dict)`).
- **`verify_challenge_response(response, challenge, expected_agent_id, now) -> (ok, reason)`**
  — live challenge-response handshake; signs over
  `canonicalize({nonce, agentId, auditHead, signedAt, verifierId})`.

## Setup

```bash
cd python
python -m venv .venv
.venv/Scripts/python -m pip install -e .        # installs cryptography
.venv/Scripts/python -m pytest test_conformance.py   # or: python -m unittest test_conformance
```

`test_conformance.py` loads `../conformance/vectors.json` and
`../conformance/interop.json` and asserts every canonicalization vector, every
sha256 vector, every interop disclosure verdict (decision + sorted failed
checks), and every handshake case. It runs under both `pytest` and stdlib
`unittest`.

## Why this matters

The canonicalization is the load-bearing piece. Because the Python
`canonicalize` emits byte-identical output to the TS reference, an ed25519
signature minted by the TS signer verifies under this Python verifier with no
shared secret — that is what "interoperates across stacks" means for ADP.
