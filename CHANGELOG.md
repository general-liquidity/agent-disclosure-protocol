# Changelog

All notable changes to the Agent Disclosure Protocol (ADP) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The interoperability contract (the canonicalization algorithm and the signed-bytes
format) is frozen at v1.0; see [Stability guarantees](docs/src/stability.md) for what
may and may not change without a version bump.

## [0.1.0]

The first published release: the protocol, the reference verifier, a five-stack
interop contract, and a portable conformance suite.

### The protocol

- The Agent Disclosure Protocol (ADP): a vendor-neutral disclosure an agent
  publishes BEFORE it transacts, so a counterparty can verify it and decide
  transact or refuse before any value moves. One runtime dependency (zod), signing
  via `node:crypto` only, so any agent stack can emit or verify a disclosure.
- The disclosure document: a system-prompt fingerprint, an operating constitution
  with an `enforced` flag, a tool inventory with permission boundaries, a capital
  and risk envelope, operator identity with a deniability boundary, a
  deployment-history summary bound to a signed audit chain, and optional red-team,
  model-identity, and per-field provenance attestations.
- The signed envelope (`SignedDisclosure`): an ed25519 signature over the
  canonical disclosure bytes, whose public key IS the `agentId`. A counterparty
  verifies with no shared secret and no registry.
- The live verification handshake: a fresh-nonce challenge-response that proves
  current key possession and a current audit head, defeating identity replay that a
  captured static document cannot.
- `SPEC.md`: the normative protocol document covering the structures, the
  canonicalization and signing algorithm, the handshake, and conformance.

### The modules (vendor-neutral core)

- `schema` - the disclosure document and the signed envelope (zod schemas + types).
- `attestation` - ed25519 sign and verify, the deterministic canonicalization, the
  `agentId`-to-key binding, sha256 digests, and the freshness window. Keys export
  and reload so an agent's identity is stable across restarts.
- `handshake` - the live challenge-response.
- `verify` + `client` - the `VerificationPolicy`, the deterministic
  `evaluateDisclosure` verdict with a per-check breakdown, and the over-the-wire
  `verifyCounterparty` loop.
- `guard` + `cache` - outbound disclose-before-settle and mutual disclosure; tiered
  verification with a validity-window cache (the economic enabler).
- `redaction`, `revocation`, `transparency` - salted-commitment selective
  disclosure, a portable revocation status list, and an append-only
  transparency log with inclusion proofs.
- `economics` - the viability model for which agent-to-agent markets clear at a
  given verification cost.
- Composition modules: versioning, revocation and transparency transports, the
  ERC-8004 identity bridge (off-chain and on-chain), policy-driven negotiation,
  framework adapters, a verifier-as-a-service plus discovery, key management and
  monitoring, W3C StatusList revocation, model-attestation envelopes, a generic
  disclosure builder, a transparency witness, and a ZK selective-disclosure
  interface with a dependency-free equality backend.

### Five-stack interop

- Native verifiers and emitters in TypeScript, Go, Python, Rust, and C, each
  reproducing the canonicalization and digest vectors and cross-verifying
  TypeScript-minted ed25519 signatures.
- A real-socket disclosure server (`scripts/serveDisclosure.ts`) serving a freshly
  signed disclosure at `GET /.well-known/agent-disclosure`, plus a cross-process
  harness (`scripts/crossProcess.ts`) that fetches and verifies it over real HTTP.
- A `cross-process` CI job that starts the server and runs the TypeScript, Go, and
  Python clients against one live origin, asserting each exits 0.

### Conformance

- `conformance/` - a portable suite any implementation must pass: golden
  canonicalization and sha256 digest vectors (defined by the protocol, not the
  code), a differential canonicalization fuzz corpus, behavioural invariants
  (signature and identity binding, ed25519 determinism, freshness boundaries, the
  handshake), and an adversarial MUST-reject corpus.
- `conformance/vectors.json` and `conformance/interop.json` - the language-neutral
  fixtures the native verifiers load.

[0.1.0]: https://github.com/general-liquidity/agent-disclosure-protocol/releases/tag/v0.1.0
