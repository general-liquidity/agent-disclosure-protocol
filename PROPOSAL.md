# Agent Disclosure Protocol (ADP): A Proposal

**The wire format for Verifiable Agency.**

- Status: proposal, pointing at running, interoperable reference code.
- Specification: [`SPEC.md`](SPEC.md) (normative). Threat analysis:
  [`THREAT_MODEL.md`](THREAT_MODEL.md). Positioning and the trust model:
  [`README.md`](README.md).
- Author: General Liquidity.

## 1. The problem

Agents are starting to transact with each other, and with merchants, with no way to answer
the first question of commerce: who am I dealing with, and what are they committed to?

The payment rails are arriving. x402, AP2, the Agentic Commerce Protocol, and on-chain
stablecoin settlement all let one agent move value to another. The identity protocols are
arriving too. ERC-8004 anchors an agent's identity to a wallet; AIP and the Visa Trusted
Agent Protocol bind an agent to a KYC'd operator. What is missing is the layer between
them: a way for one agent to learn, **before** it transacts, what the counterparty is
committed to, whether that commitment is enforced rather than merely claimed, and whether
the counterparty holds the key it claims right now.

Without that layer, an agent either transacts blind (and absorbs the loss after the fact)
or falls back to a closed allow-list (and forgoes the open agent-to-agent market entirely).
ERC-8004 itself names a pluggable verification layer and does not fill it. This proposal
fills it.

## 2. The protocol

ADP is a disclose-before-settle protocol. Before an agent transacts, it exposes a signed
disclosure document. A counterparty fetches that disclosure, evaluates it against its own
policy, optionally runs a live challenge-response handshake to prove the counterparty holds
the signing key right now, and only then decides to transact or refuse. The decision
happens before value moves, not after a loss. The default posture is fail-closed: a
disclosure that fails policy, has expired, is unreachable, or fails the liveness handshake
all resolve to refuse.

The protocol uses asymmetric (ed25519) signatures, so a counterparty verifies with no
shared secret and no prior relationship. The signer holds a private key; the matching
public key travels in the envelope and, by convention, **is** the agent's identity
(`agentId`). Anyone can check the claim, not just the party that issued it.

### The disclose-before-settle loop

```
counterparty                                          agent
    |  GET /.well-known/agent-disclosure  ------------>|
    |<-------------  signed disclosure (ed25519)        |
    |  evaluateDisclosure(disclosure, policy)           |  signature, freshness, enforced,
    |                                                   |  grade, custody, history, anchor
    |  POST /agent-disclosure/respond  (fresh nonce) -->|
    |<----  signed response (nonce + live audit head)   |  live key possession + currency
    v  decision: transact / refuse   (before any value moves)
```

### The three artifacts

The protocol is built from three signed, self-contained artifacts:

1. **The disclosure document.** A signed envelope carrying the agent's commitments: a
   system-prompt fingerprint, an enforced constitution (the hard deny-list and gate
   parameters), the tool inventory and permission boundaries, the capital envelope (scoped,
   capped, expiring spend mandates), the operator identity and deniability boundary, the
   deployment history bound to a hash-linked audit chain, and an optional red-team
   attestation and model fingerprint. The single load-bearing field is
   `constitution.enforced`: when true, the disclosed constitution **is** the gate actually
   running, not a claim. That is the difference between a disclosure and a promise.

2. **The verification handshake.** A live challenge-response. The verifier issues a fresh
   nonce; the agent signs that nonce together with its current audit head, its agentId, and
   the timestamp. It proves the counterparty holds the signing key right now and that its
   audit head is current, which a captured static document cannot. This defeats identity
   replay.

3. **The transparency and revocation surface.** A portable, signed revocation status list
   (the way a CRL gates a certificate) and an append-only, hash-linked transparency log of
   disclosure digests (Certificate-Transparency-for-agents), so a compromised identity can
   be cut off and silent re-issuance under the same identity is publicly visible.

## 3. The threat model in brief

ADP makes a fixed set of attacks legible and pairs each with a concrete defending module or
field, and states the residual gap for each honestly. The full analysis is in
[`THREAT_MODEL.md`](THREAT_MODEL.md).

| # | Attack | Defense | Residual gap |
|---|---|---|---|
| 1 | Constitution substitution via prompt injection | Enforced-constitution binding | Gate-config drift between issuance and runtime |
| 2 | Deployment-history forgery | History bound to the signed audit chain | A new agent legitimately has no history |
| 3 | Identity replay | Live challenge-response | A compromised private key |
| 4 | Stale-disclosure presentation | Validity window, nonce, audit-head currency | Clock skew between parties |
| 5 | Disclosure post-hoc rewriting | ed25519 signature, audit-anchor binding | Re-issuance with a fresh nonce |
| 6 | Operator collusion / sock-puppets | Cross-operator reputation, deny-list floor | New operators have no reputation (Sybil) |
| 7 | Model swap | Declared model fingerprint | Proving the running model needs TEE attestation |
| 8 | Self-grading on a private rubric | Public adversarial corpus | Corpus coverage gaps |
| 9 | Verification-cost DoS | Tiered verification, validity-window caching | Markets below break-even margin |

The protocol does not claim to close every gap. It claims to make each one explicit and to
let the verifier's policy decide what to require.

## 4. The interoperability proof

A protocol is only a wire format if independent implementations interoperate. ADP carries a
language-neutral conformance contract in [`conformance/`](conformance/) that multiple
native implementations pass.

- **`conformance/vectors.json`** pins the canonicalization and sha256 vectors. These are
  defined by the protocol, not by any one implementation. Canonicalization is the
  interoperability crux: the signed bytes must be byte-identical across languages or
  signatures will not verify across stacks.
- **`conformance/interop.json`** is a deterministic set of signed disclosures, policies,
  and expected verdicts, plus challenge-response handshake fixtures, generated from the
  TypeScript reference with a fixed ed25519 key. Because ed25519 is deterministic, the
  fixture is stable and committed; it diffs only when the contract changes. The
  expectations are computed by the real verifier, so they are correct by construction, and
  any other language reproduces them. A verifier MUST reproduce each `expect.decision`
  (`transact` or `refuse`) and SHOULD reproduce the sorted set of failed check names.

The TypeScript reference is the emitter and a verifier. Native verifiers in four other
languages verify the same committed `interop.json`, which is what demonstrates the contract
is language-neutral rather than tied to the reference runtime:

- **Go** (`go/`): a full verifier with canonicalization, attestation, handshake, and a
  conformance test (`canonicalize.go`, `attestation.go`, `handshake.go`, `verify.go`,
  `conformance_test.go`).
- **Python** (`python/`): the `agent_disclosure` package (`canonical.py`, `attestation.py`,
  `handshake.py`, `verify.py`) with `test_conformance.py`.
- **Rust** (`rust/`): a `lib.rs` verifier with its own Cargo crate.
- **C** (`c/`): a header implementation (`agent_disclosure.h`) over vendored cJSON and
  libsodium.

When an emitter and a verifier from independent teams both pass the suite, they are
interoperable: the canonicalization vectors guarantee identical signed bytes, and the
behavioural fixtures guarantee identical accept/refuse decisions.

## 5. The economic argument

The standard objection is that verifying every counterparty before every transaction is too
expensive: if verification is costly it gets skipped, and skipping it defeats the protocol.
This is an economic denial of service on the whole approach.

The viability model in [`src/economics.ts`](src/economics.ts) answers it with a
per-transaction account. Verification splits into a cheap, cacheable fast path and a deep
path (live handshake plus corpus re-run). Only a small `deepFraction` of transactions take
the deep path; a high `cacheHitRate` serves fast-path checks from the validity window at
near-zero marginal cost. The blended per-transaction cost is:

```
(1 - deepFraction) * fastCost * (1 - cacheHitRate)  +  deepFraction * deepCost
```

A market is viable when `margin + fraudSaving - verificationCost > 0`, where `fraudSaving`
credits verification with the fraud it removes. The model is pure and deterministic (no
I/O, integer minor units) and exposes `viabilityOf`, `surviving`, and
`breakEvenVerificationCostMinor`.

The honest conclusion, which the model states plainly: cheap deterministic verification plus
caching and tiering keeps most markets viable, but a sub-margin micropayment market that
deep-verifies every transaction can still net negative. The model does not pretend those
markets survive.

## 6. What is built, and the honest open items

### Built and running

- The full disclosure schema and signed envelope, with strict structural validation
  (`src/schema.ts`).
- ed25519 signing and verification, deterministic canonicalization, the agentId-to-key
  binding, sha256 digests, and the freshness window (`src/attestation.ts`).
- The live challenge-response handshake (`src/handshake.ts`).
- The declarative verification policy, the deterministic verdict with a per-check
  breakdown, and the over-the-wire verifier loop (`src/verify.ts`, `src/client.ts`).
- Outbound disclose-before-settle and mutual disclosure, plus tiered verification with a
  validity-window cache (`src/guard.ts`, `src/cache.ts`).
- Selective disclosure via salted commitments (`src/redaction.ts`), a portable signed
  revocation list (`src/revocation.ts`), and the append-only transparency log
  (`src/transparency.ts`).
- The economic-viability model (`src/economics.ts`).
- The language-neutral conformance contract and four native verifiers (`conformance/`,
  `go/`, `python/`, `rust/`, `c/`).

The protocol has one runtime dependency (`zod`) and signs with `node:crypto` only.
AgentWorth is the reference implementation that populates a disclosure from a live,
enforced governance gate.

### Honest open items

These are stated plainly rather than hidden:

- **TEE model-swap proof.** The declared model fingerprint is the cheap declarable half of
  the model-swap defense. Cryptographically proving that the running model matches the
  declaration at transact-time needs hardware (TEE) attestation, which the protocol does not
  yet carry. The field is versioned so a hardware-attested successor can supersede it
  without a breaking change.
- **Hosted transparency log.** The transparency log is implemented as an append-only,
  hash-linked structure with inclusion proofs, but a publicly hosted, third-party-operated
  log (the deployment that makes re-issuance watchable by anyone) is not yet stood up.
- **On-chain ERC-8004 registry.** The operator attestation field carries an `ERC8004`
  scheme, and the `agentId` is an ed25519 key bindable to a wallet-anchored identity, but a
  live on-chain registry binding agentId to an ERC-8004 record is integration work in the
  reference implementation, not part of the protocol core.

These are integration and hardware items, not gaps in the wire format. The protocol is
designed so each can be added without a breaking change to the disclosure structure.

## 7. The ask

We are seeking three things:

1. **Independent implementations and conformance.** Build an emitter or verifier in your own
   stack against [`SPEC.md`](SPEC.md), pass [`conformance/`](conformance/), and report any
   ambiguity in the spec that the vectors do not already pin down. Every independent
   implementation that passes the suite strengthens the claim that ADP is a wire format
   rather than one vendor's library.

2. **Standards-track review.** Review the protocol with an eye to a well-known URI
   registration for `agent-disclosure` and alignment with the identity and rail efforts it
   composes with (ERC-8004, AIP, Visa Trusted Agent Protocol, x402, AP2, ACP). The
   discovery transport (`/.well-known/agent-disclosure` and `/agent-disclosure/respond`) is
   currently the reference convention, pending registration.

3. **Support for the open items.** Concretely: a TEE attestation design for the model-swap
   proof, a hosted transparency-log deployment, and an on-chain ERC-8004 registry binding.
   These are the pieces that move ADP from a complete wire format with a reference
   implementation to a deployed, watchable, regulated-rails-ready trust layer.

The thesis is unchanged throughout: ADP is the wire format for **Verifiable Agency**, an
agent that can prove, before it acts, what it is committed to, that the commitment is
enforced rather than promised, and that it holds the key it claims right now.
