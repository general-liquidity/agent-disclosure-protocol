# Stability guarantees

ADP is an interoperability protocol, not just a library. Its value depends on a
TypeScript verifier, a Go verifier, a Python verifier, a Rust verifier, and a C
verifier all agreeing, byte for byte, on what a given disclosure signs to. This
chapter states what is frozen at v1.0, what may evolve, and how anything is removed.

## What is frozen

These are the interoperability contract. Changing any of them changes the bytes a
disclosure signs to, which silently breaks signature verification across stacks.
They MUST NOT change without a major version bump.

### The canonicalization algorithm

The mapping from a disclosure value to its canonical string, defined normatively in
`SPEC.md` and implemented in `canonicalize` in `src/attestation.ts`:

- Primitives and `null` serialize as their JSON form.
- Arrays serialize as their elements canonicalized in order, comma-joined, in
  brackets.
- Objects serialize with keys sorted lexicographically by UTF-16 code unit, each key
  JSON-stringified, joined to its canonicalized value by a colon, the pairs
  comma-joined, in braces.
- A key whose value is `undefined` is omitted, so an absent field and a field
  explicitly set to `undefined` canonicalize identically.

Two implementations that canonicalize identically produce signatures that verify
across stacks; one that does not will fail verification on every cross-stack
disclosure. The golden vectors in `conformance/vectors.json` pin the exact output and
are the regression gate against drift.

### The signed-bytes format

The bytes that are signed and verified:

- A disclosure is signed by computing `canonicalize(disclosure)`, encoding it as
  UTF-8, and producing an ed25519 signature over those bytes.
- The signature algorithm is ed25519. The envelope carries the raw 32-byte public
  key as hex; the `value` is the signature as hex.
- The `agentId` MUST equal the signing public key, and a verifier MUST reject a
  disclosure whose `agentId` does not match the key that signed it.
- The handshake response signs the canonical bytes of its response body, binding in
  the challenge nonce and the current audit head.

### The freshness model

A disclosure is valid only within the inclusive window `[issuedAt, validUntil]`,
compared as ISO-8601 strings. A verifier MUST reject a disclosure outside that
window.

## What may evolve

These can change in a minor release without breaking existing verifiers, because an
older verifier that does not understand them simply does not act on them.

- New OPTIONAL disclosure fields. An older verifier ignores a field it does not
  recognize; because absent and `undefined` fields canonicalize away, adding an
  optional field a producer does not populate does not change existing signed bytes.
- New policy predicates in `VerificationPolicy`. A predicate is opt-in: a verifier
  that does not set it is unaffected, and the verdict is computed only over the
  predicates a verifier actually states.
- New composition modules (transports, bridges, negotiation, witnesses) that build
  on the frozen core without altering it.
- Additional conformance cases that tighten coverage, as long as they do not
  contradict an existing frozen vector.

A change that would make a previously REQUIRED field optional, alter an enum's
meaning, or otherwise change how a conformant verifier decides on an existing
disclosure is breaking and requires a major version bump.

## Deprecation policy

- A field or predicate is first marked deprecated in `SPEC.md` and in this chapter,
  with the release it was deprecated in and the replacement, while continuing to
  work unchanged.
- Deprecated surfaces are removed only in a major version bump, never in a minor or
  patch release.
- Anything that affects the frozen interoperability contract (the canonicalization
  algorithm, the signed-bytes format, the freshness model) can only change in a
  major version, and such a change ships with updated conformance vectors and a
  migration note in the changelog so every stack can re-pin in lockstep.
