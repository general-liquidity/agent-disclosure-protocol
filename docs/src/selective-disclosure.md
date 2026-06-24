# Selective Disclosure

An agent MAY commit to its fields and later reveal only a subset, without breaking the
signature, via salted hash commitments (`src/redaction.ts`). This serves privacy and the
operator's deniability boundary: a verifier learns exactly the fields its policy requires,
and nothing more.

## Always-clear meta

The identity and freshness fields (`version`, `disclosureId`, `agentId`, `issuedAt`,
`validUntil`, `nonce`, `auditAnchor`) are carried in clear in the `meta` block. A verifier
needs identity and freshness before deciding whether to look at the rest.

## Redactable fields

The following MAY be withheld (`REDACTABLE_FIELDS`): `systemPrompt`, `constitution`,
`tools`, `capital`, `operator`, `history`, `redTeam`, `model`, `provenance`.

## Commitment scheme

For each present redactable field, the emitter draws a fresh per-field salt (reference: 16
random bytes hex) and computes the commitment:

```
commitment(field) = sha256Hex( canonicalize(value) + ":" + salt )
```

(function `commit`). The salt is per-field, so revealing one field leaks nothing about
another, and the salt prevents a verifier from brute-forcing a low-entropy value out of
its commitment. The emitter then signs over the commitment set plus the meta:

```
signature.value = ed25519( canonicalize({ meta, commitments }) )
```

(`prepareRedactable`). The holder retains the cleartext `fields` and `salts` and never
ships them; it ships a `RedactedView` containing `meta`, all `commitments`, the
`signature`, and a `revealed` map of only the disclosed fields, each as `{ value, salt }`
(`reveal`).

## Verifier checks

`verifyRedacted` performs three checks, all MUST:

1. `meta.agentId` MUST equal `signature.publicKey` (the identity binding from
   [signing and identity](./signing-and-identity.md)).
2. The signature MUST verify over `canonicalize({ meta, commitments })`. No field can be
   added, removed, or edited without breaking it.
3. For each revealed field, `commit(value, salt)` MUST recompute to the field's committed
   value. A mismatch, or a revealed field with no commitment, fails the whole view.

The result names exactly the fields whose disclosure is cryptographically proven.

## Privacy property

A withheld field is present only as an opaque, salted commitment. It is **binding** (the
agent cannot later open it to a different value) and **hiding** (the verifier learns
nothing about the value, and cannot brute-force it, without the salt). Revealing a subset
proves those fields against the same single signature that covers the whole commitment
set.
