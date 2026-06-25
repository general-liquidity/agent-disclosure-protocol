# Conformance

A conformant implementation MUST satisfy the runnable conformance suite under
`conformance/`, which carries two kinds of artifact: language-neutral **vectors** (the
contract) and **behavioural checks** (the invariants). An emitter and a verifier from
independent teams are interoperable when both pass the suite: the canonicalization vectors
guarantee identical signed bytes, and the behavioural checks guarantee identical
accept/refuse decisions.

## What a conformant implementation must do

- Reproduce every canonicalization vector byte for byte, including the worked examples in
  the [canonicalization](./canonicalization.md) chapter: object key sort, recursive sort,
  preserved array order, dropped `undefined` values, and the absent-`verifierId` object
  case.
- Produce ed25519 signatures over the canonical UTF-8 bytes that the reference verifier
  accepts, and verify reference-produced signatures — for **both** envelope shapes (the v1
  object envelope and the v2 flattened JWS; `conformance/interop.json` carries a
  `jwsDisclosures` fixture set).
- Enforce the agentId-to-key binding including the did:key and rotation-chain forms, the
  freshness window, the [RFC 9421 handshake MUST-checks](./verification-handshake.md)
  including the `Signature-Input` match and version negotiation, and the
  [policy semantics](./policy-and-verdict.md) including the empty-policy baseline.
- Reproduce the [selective-disclosure](./selective-disclosure.md) commitment and
  verification, the signed-revocation preimage, and the
  [transparency-log](./revocation-and-transparency.md) GENESIS value and `hash` preimage.

## The two contract files

### `conformance/vectors.json`

Language-neutral canonicalization and sha256 vectors, defined by the protocol and not by
any one implementation. Every conformant emitter and verifier MUST reproduce them. The
canonicalization vectors are the interoperability crux: the signed bytes must be
byte-identical across languages or signatures will not verify across stacks.

### `conformance/interop.json`

A deterministic set of signed disclosures plus policies plus expected verdicts, and
challenge-response handshake fixtures, that every native implementation verifies against.
It is generated from the TypeScript reference with a fixed ed25519 key (ed25519 is
deterministic, so the output is stable and the file is committed; it only diffs when the
contract itself changes). The expectations are computed by the **real** verifier, so the
fixtures are correct by construction and another language reproduces them.

For each disclosure case, a verifier in any language MUST reproduce `expect.decision` (the
primary contract: `transact` or `refuse`) and SHOULD reproduce `expect.failed` (the sorted
set of failed check names). The committed disclosure cases include:

- `valid-transact` (a strict policy met in full),
- `unenforced-refuse` (constitution not enforced),
- `stale-refuse` (outside the freshness window),
- `custodial-refuse` (custody is not non-custodial),
- `low-grade-refuse` (red-team grade below the minimum),
- `no-history-refuse` (no deployment history),
- `tampered-signature-refuse` (a field mutated after signing),
- `forged-agentid-refuse` (agentId no longer equals the signing key).

For each handshake case it MUST reproduce `expect` (a boolean). The committed handshake
cases cover `valid`, `nonce-mismatch`, `wrong-agent`, `bad-signature`, and `stale`.

Regenerate the fixture from the reference with:

```bash
node --import tsx conformance/generate-interop.ts
```

## Running the suite

```bash
npm run conformance   # the portable vectors + behavioural invariants
```

The reference suite runs this package against the vectors and invariants
(`conformance/conformance.test.ts` and `conformance/interop.test.ts`). Another
implementation ports the same vectors and invariants and runs them against its own emitter
and verifier. Native verifiers in Go, Python, Rust, and C live in the `go/`, `python/`,
`rust/`, and `c/` directories and verify the same committed `interop.json`, which is what
demonstrates that the contract is language-neutral rather than tied to the reference
runtime.
