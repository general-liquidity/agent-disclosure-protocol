# Revocation and Transparency

## Revocation

A disclosure, or the agent behind it, can be revoked: a compromised key, a decommissioned
agent, a rotated identity (`src/revocation.ts`). A verifier fetches a portable status list
and refuses any revoked id, the way a CRL or OCSP list gates a certificate.

- The status list (`RevocationList`) is keyed by string id. The id MAY be a `disclosureId`
  (revoke one document) or an `agentId` (revoke the whole agent). It is portable (`toJSON`
  / `fromJSON`) and exposes `isRevoked(id)` and `status(id)`. A verifier wires it into
  policy as the `isRevoked` oracle.
- A revocation SHOULD be signed so it is attributable to the issuing key and a third party
  cannot forge a denial-of-service revocation. A `SignedRevocation` carries
  `{ id, reason, revokedAt, publicKey, signature }`, where the signature is over
  `canonicalize({ id, reason, revokedAt })` (`signRevocation`). A verifier verifies it
  against the embedded public key (`verifyRevocation`).

Revocation is the mitigation for a compromised private key: even an attacker holding the
agent's key can be cut off by a signed revocation that verifiers consult before they
transact (see the [threat model](./threat-model.md), threat 3).

## Transparency log

The transparency log is Certificate-Transparency-for-agents: an append-only, hash-linked
log of disclosure digests, so re-issuance under the same identity is publicly visible
(`src/transparency.ts`).

Each `TransparencyLogEntry` is `{ index, disclosureDigest, agentId, issuedAt, prevHash,
hash }`. On append (`TransparencyLog.append`):

- `index` is the 0-based position.
- `prevHash` is the previous entry's `hash`, or the GENESIS value for index 0.
- `disclosureDigest = sha256Hex(canonicalize(signed.disclosure))`. The digest commits to
  the **document**, not the signature, so a content change yields a new digest, and
  re-issuance under a fresh signature with the same content is detectable.
- `hash = sha256Hex(canonicalize({ index, disclosureDigest, agentId, issuedAt, prevHash }))`.

The GENESIS previous-hash is `"0".repeat(64)` (64 zero hex characters). The head is the
last entry's `hash`, or GENESIS when empty.

`verify()` recomputes the whole chain: for each entry the stored `prevHash` MUST equal the
running previous hash and the stored `hash` MUST recompute from the entry's own fields.
Any post-hoc edit, insertion, or deletion breaks the chain and is reported as
`brokenAt: index`. `contains(digest)` and `inclusionProof(index)` provide membership
checks.

An implementation MUST reproduce the GENESIS value and the `hash` preimage exactly for
cross-implementation log compatibility. The log is the defense against silent re-issuance:
a counterparty watching it sees when an agent re-issues under the same identity, so
re-issuance is publicly visible rather than silent (threat 5).
