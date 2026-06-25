# Changelog

All notable changes to the Agent Disclosure Protocol (ADP) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The interoperability contract (the canonicalization algorithm and the signed
disclosure-document bytes) is frozen at v1.0; see [Stability guarantees](docs/src/stability.md)
for what may and may not change without a version bump.

## [Unreleased]

### Added

- **A2A Agent Card bridge** (`src/a2a.ts`). Carry, extract, and verify an ADP
  `SignedDisclosure` on an [A2A](https://a2a-protocol.org) Agent Card via a
  `capabilities.extensions[]` entry under `ADP_A2A_EXTENSION_URI`
  (`https://adp.dev/a2a/agent-disclosure/v1`). `disclosureExtension` /
  `withDisclosureExtension` embed (or link, `embed:false`) the disclosure;
  `findDisclosureExtension` / `extractDisclosure` lift it back out. `verifyCardDisclosure`
  enforces a dual-signature trust model: the disclosure's own ed25519 envelope is the
  required trust root (`verifyDisclosureSignature`), while the card's optional RFC 7515
  `signatures[]` JWS (A2A §8.4) are best-effort origin tamper-evidence — reported via
  `cardSignatureChecked` / `boundToCardSigner`, never required. `signAgentCard` produces a
  self-signed card JWS (default EdDSA over the ADP agent key → signer == agentId);
  `verifyAgentCardSignature` implements §8.4.3 (JCS over the card without `signatures`,
  EdDSA native + ES256/RS256 via a `resolveKey` callback, graceful unsupported-alg). No new
  runtime dependency (zod + `node:crypto`).

---

## [0.1.1]

First CI-automated release — published via OIDC trusted publishing
(`.github/workflows/release.yml`), tokenless and with provenance. The published package
contents (`dist/` + docs) are **unchanged** from `0.1.0`; the specification-version-2
additions below shipped in the `0.1.0` tarball and are recorded here for completeness.

### Added (tooling)

- `.github/workflows/release.yml` + `RELEASING.md`: tag-triggered, OIDC trusted publishing
  to npm (and, behind opt-in flags, PyPI and crates.io), mirroring the OpenSolvency
  release pattern.

---

Specification version 2 — a wire-layer hardening that brings ADP into line with the
standards it interoperates with. It is **additive**: the disclosure-document structure,
the canonicalization algorithm, and the signed document bytes are all unchanged, so v1 and
v2 coexist and a v2 verifier accepts a v1 envelope unchanged.

### Added

- **Canonicalization named as RFC 8785 (JCS).** The frozen `canonicalize` algorithm is
  byte-equivalent to JCS over ADP's value domain; it is now documented under that name,
  with the two ADP profile rules (`undefined`-key drop, no `NaN`/`Infinity`) called out.
  No signature or fixture changed.
- **Flattened JWS (EdDSA) envelope** (`JwsSignedDisclosureSchema`, `signDisclosureJws` /
  `verifyDisclosureJws`). A second, JOSE-interoperable wrapping of the same disclosure:
  `{ payload, protected, header.jwk, signature }`, where the signature covers
  `ASCII(b64url(protected) + "." + b64url(payload))`, so the protected header (with `alg`)
  is integrity-protected — closing the v1 gap where the algorithm sat outside the signed
  bytes. The two envelopes coexist (dual-encode), discriminated by shape; a verifier
  accepts either (`verifyAnyDisclosureSignature`, `parseAnySignedDisclosure`).
- **Key-rotation binding.** The signed rotation chain (`src/keys.ts`) is wired into the
  identity check (`verifyKeyBinding` / `verifyRotationChain`): an `agentId` now binds to
  the signing key directly (hex), via that key's did:key form, OR via a verified rotation
  chain carried as the optional `rotationChain` envelope field — so an identity survives a
  key change.
- **RFC 9421 handshake.** The challenge-response now signs an RFC 9421 signature base over
  `adp-agent-id` / `adp-audit-head` / `adp-disclosure-version` plus an `@signature-params`
  line (`created`/`keyid`/`alg`/`nonce`/`tag`), carried as `signatureInput` + `signature`.
  Two deliberate ADP deviations: ISO-8601 `created` and hex signature.
- **Version negotiation.** `Challenge.supportedVersions` advertises accepted schema
  versions; the agent declares a signed `disclosureVersion`; a verifier refuses an
  unsupported one (a no-version response stays interoperable).
- **Namespaced operator-attestation schemes + `extensions` bucket.** `attestation.scheme`
  is now a known value (`AIP` / `VisaTAP` / `ERC8004` / `DID` / `none`) OR a reverse-domain
  id; a top-level `extensions` record (reverse-domain keys) carries third-party fields a
  verifier ignores unless it recognizes them.
- **Standards bridges.** A W3C VC 2.0 / `DataIntegrityProof` bridge (`src/vc.ts`, the
  non-registered `adp-jcs-2024` cryptosuite over the same ed25519 signature); an SD-JWT-VC
  bridge (`src/sdjwtvc.ts`, hidden field names + decoy digests + KB-JWT presentation
  binding); and a DID Document emit with an `AgentDisclosure` `service` entry plus a
  `did:web` constructor (`src/did.ts`).

### Changed

- `SPEC.md` updated to specification version 2: dual envelope (§3.12), namespaced
  attestation scheme + `extensions` (§3.6), rotation binding (§5/§5.1), RFC 9421 handshake
  + version negotiation (§7), a new standards-bridges section (§11), and a normative IANA
  pointer to the companion Internet-Draft (§14).
- `docs/src/` chapters updated to match (signing-and-identity, verification-handshake,
  selective-disclosure, disclosure-document), with a new **Standards Bridges** chapter.

### Governance

- Added `docs/drafts/draft-gl-adp-disclosure-00.md`, an IETF Internet-Draft-shaped
  document for the ADP wire format requesting registration of the `agent-disclosure`
  well-known URI per RFC 8615.

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

[0.1.1]: https://github.com/general-liquidity/agent-disclosure-protocol/releases/tag/v0.1.1
[0.1.0]: https://github.com/general-liquidity/agent-disclosure-protocol/releases/tag/v0.1.0
