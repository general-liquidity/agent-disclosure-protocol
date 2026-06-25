"""Ports of the redaction, revocation, and transparency-transport verifiers.

  - `verify_redacted`  -> `src/redaction.ts::verifyRedacted`
  - `verify_revocation`-> `src/revocation.ts::verifyRevocation`
  - `verify_inclusion_proof` -> `src/transparencyTransport.ts::verifyInclusionProof`

All three reuse the byte-matched `canonicalize` / `sha256_hex` and the asymmetric
`verify_message`, so they accept exactly the vectors the TS reference emits.
"""

from .canonical import canonicalize, sha256_hex
from .attestation import verify_message_hex


def _commit(value, salt: str) -> str:
    """Salted commitment for a field: sha256(canonicalize(value) + ':' + salt)."""
    return sha256_hex(f"{canonicalize(value)}:{salt}")


def verify_redacted(view: dict):
    """Verify a redacted view. Returns (ok, revealed_fields):
      1. meta.agentId == signature.publicKey (identity binding),
      2. signature covers canonicalize({meta, commitments}),
      3. each revealed field recomputes to its committed value.
    On any failure returns (False, []); on success revealed_fields is sorted."""
    meta = view["meta"]
    commitments = view["commitments"]
    signature = view["signature"]

    if meta["agentId"] != signature["publicKey"]:
        return False, []

    signed = canonicalize({"meta": meta, "commitments": commitments})
    if not verify_message_hex(signed, signature["publicKey"], signature["value"]):
        return False, []

    revealed_fields = []
    for field, payload in view["revealed"].items():
        expected = commitments.get(field)
        if expected is None:
            return False, []
        if _commit(payload["value"], payload["salt"]) != expected:
            return False, []
        revealed_fields.append(field)

    return True, sorted(revealed_fields)


def verify_revocation(record: dict) -> bool:
    """Verify a signed revocation against its embedded public key: ed25519 over
    canonicalize({id, reason, revokedAt})."""
    return verify_message_hex(
        canonicalize(
            {"id": record["id"], "reason": record["reason"], "revokedAt": record["revokedAt"]}
        ),
        record["publicKey"],
        record["signature"],
    )


def verify_inclusion_proof(entry: dict) -> bool:
    """Recompute the transparency-log entry hash from its own fields and confirm
    it matches: hash == sha256(canonicalize({index, disclosureDigest, agentId,
    issuedAt, prevHash}))."""
    expected = sha256_hex(
        canonicalize(
            {
                "index": entry["index"],
                "disclosureDigest": entry["disclosureDigest"],
                "agentId": entry["agentId"],
                "issuedAt": entry["issuedAt"],
                "prevHash": entry["prevHash"],
            }
        )
    )
    return expected == entry["hash"]
