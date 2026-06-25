# Changelog

All notable changes to the Agent Disclosure Protocol (ADP) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The interoperability contract (the canonicalization algorithm and the signed
disclosure-document bytes) is frozen at v1.0; see [Stability guarantees](docs/src/stability.md)
for what may and may not change without a version bump.

## [0.1.5] - 2026-06-25

### Added

- **World Agent (worldcoin/agentkit) attestation scheme** (`src/worldagent.ts`). Recognizes a
  worldcoin/agentkit **human-backed agent** — an agent wallet registered, via a World ID proof, in
  the on-chain **AgentBook** that maps the wallet to the registering human's nullifier — as an
  operator-attestation scheme, without bundling a chain client. The agent signs a **CAIP-122 / SIWE
  (EIP-4361)** challenge; ADP does STRUCTURAL validation of the message + address/signature
  (`validateWorldAgentStructural`: the `WorldAgent` scheme, a `0x`+40-hex `address`, a 65-byte
  `signature`, a non-empty `message`), **EIP-191-recovers** the signer (reusing
  `recoverWalletAddress` from `erc8004Onchain.ts`) and requires it to equal the claimed agent
  wallet, then delegates the AgentBook `lookupHuman(address) -> uint256` on-chain read to an
  injected `AgentBookResolver` seam. `verifyWorldAgent` returns
  `{ structural, valid, address?, humanBacked, nullifier?, reason? }` — without a resolver the
  signature can be valid but `humanBacked` is `false` (the on-chain registration is unconfirmed),
  and it never throws on a missing resolver or a malformed signature. `worldAgentToOperatorAttestation`
  maps a human-backed agent to `registry_attested`, a wallet-controlled-but-unregistered one to
  `signed`, and a non-recovering signature to `none`, under the reverse-domain scheme
  `org.world.agent` (`WORLDAGENT_ATTESTATION_SCHEME`) — the frozen attestation `scheme` enum in
  `schema.ts` is untouched. Exports the canonical `AGENT_BOOK_ADDRESS`
  (`0xA23aB2712eA7BBa896930544C7d6636a96b944dA`, World Chain) and `WORLDCHAIN_ID` (480). No new
  runtime dependency (the secp256k1 recovery reuses the optional `@noble` extras, loaded
  dynamically).

---

## [0.1.4] - 2026-06-25

### Added

- **World ID (Worldcoin) attestation scheme** (`src/worldid.ts`). Recognizes World ID —
  proof-of-*unique*-personhood via a Groth16 ZK proof over a Semaphore membership tree — as an
  operator-attestation scheme without a chain client. ADP does STRUCTURAL validation of the
  proof shape (`validateWorldIdStructural`: an `app_`-prefixed `app_id`, a non-empty `action`,
  hex `nullifier_hash` / `merkle_root` / `proof`, a known `verification_level`) and delegates the
  heavy Groth16 check (the Developer Portal `/verify` call or the on-chain World ID Router) to an
  injected `verifier` seam. `verifyWorldId` is crypto-pending without a verifier
  (`{ structural: true, valid: false, nullifier }`, surfacing the sybil-key nullifier — it does
  not throw). `worldIdToOperatorAttestation` maps a verified `orb` proof to `registry_attested`
  and any other level to `signed`, under the reverse-domain scheme `org.world`
  (`WORLDID_ATTESTATION_SCHEME`) — the frozen attestation `scheme` enum in `schema.ts` is
  untouched. No new runtime dependency.
- **Human Passport (Gitcoin) attestation scheme** (`src/humanpassport.ts`). Recognizes Human
  Passport — a Unique Humanity Score aggregated from identity stamps — as an operator-attestation
  scheme. ADP does STRUCTURAL validation (`validatePassportAttestation`: a `0x`+40-hex address,
  finite `score` / `threshold`) and delegates the score lookup (the Passport API `X-API-KEY` call
  or an EAS on-chain read) to an injected `scorer` seam — also the boundary that parses the API's
  numeric-STRING `score` / `threshold` into numbers. `verifyPassportAttestation` recomputes
  `passing` against the threshold (default `HUMAN_THRESHOLD` = 20); `passportToAdpLevel` bands the
  score (`>= 1.5×` → high, `>= 1×` → medium, below → low, absent → unverified);
  `passportToOperatorAttestation` maps a passing score to `signed` under the reverse-domain scheme
  `tech.human.passport` (`HUMANPASSPORT_ATTESTATION_SCHEME`) — the frozen `scheme` enum is
  untouched. No new runtime dependency.

---

## [0.1.3] - 2026-06-25

### Added

- **SIWA (Sign-In-With-Agent) bridge** (`src/siwa.ts`). A SIWE/EIP-4361 login message whose
  subject is an *agent* account: its `(address, agentRegistry, agentId)` triple is exactly an
  ERC-8004 binding. `formatSiwaMessage` / `parseSiwaMessage` render and parse the signed text;
  `disclosureToSiwaMessage` mints a message describing a disclosed agent from its binding;
  `verifySiwa` EIP-191-recovers the signer (reusing the `erc8004Onchain` secp256k1 path) and
  checks domain / nonce / expiry / not-before → `signed`, escalating to `registry_attested`
  when an injected `ownerOf` resolver confirms the registry binds the agentId to that signer;
  `verifySiwaAgainstDisclosure` additionally cross-checks that the SIWA address + agentId match
  the disclosure's ERC-8004 binding (so the login and the disclosure describe one agent). The
  secp256k1 recovery is the optional `@noble` extra (lazy import); minting + parsing are pure,
  the registry tier is an injected seam. No new runtime dependency.
- **Self (self.xyz) attestation scheme** (`src/self.ts`). Recognizes Self — ZK
  proof-of-personhood — as an operator-attestation scheme without a chain client. ADP does
  STRUCTURAL validation of Self's `SelfOnchainRef` (chain registry ref) and `SelfOffchainResult`
  (proof + disclosed predicates) and delegates the heavy Groth16 / Celo `isVerifiedAgent`
  verification to an injected `verifier` seam — exactly how it treats ERC-8004. The **inverted
  OFAC** semantics are documented and enforced: `isOfacValid === true` means the subject IS on a
  sanctions list, so a sanctioned subject fails. `selfToOperatorAttestation` maps a verified
  attestation into ADP's `operator.attestation` field under the reverse-domain scheme `xyz.self`
  (`SELF_ATTESTATION_SCHEME`) — the frozen attestation `scheme` enum in `schema.ts` is untouched.
  No new runtime dependency (zod + `node:crypto`; optional `@noble` reused for the SIWA recovery).

---

## [0.1.2] - 2026-06-25

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
