<!-- prettier-ignore -->
<div align="center">

# Agent Disclosure Protocol (ADP)

### The wire format for Verifiable Agency

*Agents are starting to transact with each other with no way to answer the first question of commerce: who am I dealing with, and what are they committed to? ADP is the disclosure an agent publishes **before** it transacts - so a counterparty can verify and decide before value moves, not after a loss.*

[![CI](https://img.shields.io/github/actions/workflow/status/general-liquidity/agent-disclosure-protocol/ci.yml?style=flat-square&label=CI)](https://github.com/general-liquidity/agent-disclosure-protocol/actions)
[![npm](https://img.shields.io/npm/v/@general-liquidity/agent-disclosure?style=flat-square&label=npm&logo=npm)](https://www.npmjs.com/package/@general-liquidity/agent-disclosure)
[![tests](https://img.shields.io/badge/tests-229%20passing-success?style=flat-square)](#develop)
[![conformance](https://img.shields.io/badge/conformance-vectors%20%2B%20fuzz%20%2B%20adversarial-success?style=flat-square)](#conformance)
[![interop](https://img.shields.io/badge/interop-5%20stacks-success?style=flat-square)](#conformance)
[![node](https://img.shields.io/badge/node-%E2%89%A520-5FA04E?style=flat-square&logo=nodedotjs&logoColor=white)](#develop)
[![runtime dep](https://img.shields.io/badge/runtime%20dep-zod-3E67B1?style=flat-square&logo=zod&logoColor=white)](#tech-stack)
[![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](#license)
[![types](https://img.shields.io/badge/types-strict-3178C6?style=flat-square&logo=typescript&logoColor=white)](#tech-stack)

**[Why](#why) · [Install](#install) · [Disclose & verify](#disclose-and-verify) · [The disclosure](#the-disclosure-document) · [Where it fits](#where-it-fits) · [Conformance](#conformance) · [Spec](SPEC.md) · [Threat model](THREAT_MODEL.md)**

</div>

---

## Why

ADP is **not** a wallet, a rail, or an identity registry. It is the vendor-neutral disclosure layer that sits *above* the payment rails (x402, AP2, ACP, cards) and *beside* the identity protocols (ERC-8004, AIP, Visa TAP), enforcing a single loop:

> **An agent reveals what it is committed to before it transacts; a counterparty verifies that disclosure against its own policy and a live key-possession handshake, and decides transact or refuse - before any value moves. Asymmetric signatures mean anyone can check, with no shared secret and no registry.**

This is the "pluggable behavioural-trust layer" the rest of the agentic-commerce stack openly defers. ERC-8004 anchors an agent's identity to a wallet and names a verification layer it does not itself fill. ADP is that layer: not just *who is this agent*, but *what is it committed to, is that commitment enforced, and has it behaved* - checked before the transaction clears.

The protocol has **one runtime dependency** (`zod`) and signs with `node:crypto` only. It is not just claimed to be language-neutral, it is **proven** to be: native verifiers *and* emitters in **TypeScript, Go, Python, Rust, and C** all reproduce the canonicalization byte-for-byte and cross-verify each other's ed25519 signatures, gated by a shared conformance contract on every commit (see [Conformance](#conformance)). [OpenSolvency](https://github.com/general-liquidity/opensolvency) is the reference implementation that populates a disclosure from a live, enforced governance gate.

## Install

```bash
npm install @general-liquidity/agent-disclosure
```

**Verify a counterparty before you transact** - the whole disclose-before-settle loop, end to end:

```ts
import { verifyCounterparty } from "@general-liquidity/agent-disclosure";

const verdict = await verifyCounterparty(fetch, "https://agent.example", {
  now: new Date().toISOString(),
  requireEnforcedConstitution: true,   // the constitution must BE the running gate, not a claim
  requireNonCustodial: true,
  minRedTeamGrade: "B",
});

if (verdict.decision === "transact") {
  // proven: valid signature, fresh, policy met, live key possession - before any value moves
} else {
  verdict.reasons;   // every failed check, for transparency
}
```

**Emit a signed disclosure** other agents can verify (serve it at `/.well-known/agent-disclosure`):

```ts
import { generateAgentKeyPair, signDisclosure } from "@general-liquidity/agent-disclosure";

const key = generateAgentKeyPair();          // agentId === key.publicKeyHex
const signed = signDisclosure(myDisclosure, key);   // an ed25519 envelope, verifiable with no shared secret
```

Build `myDisclosure` from your own runtime (a fluent `DisclosureBuilder` is exported), or use the OpenSolvency builders to populate it from a live gate, mandate set, and signed audit chain.

**Or from the CLI** (`agent-disclosure`, shipped in the package):

```bash
agent-disclosure keygen                                        # mint an ed25519 identity
agent-disclosure sign --in disclosure.json --key key.hex       # sign a disclosure document
agent-disclosure verify-file signed.json --require-enforced    # verify a file against a policy
agent-disclosure verify-url https://agent.example              # fetch + verify a peer over HTTP
```

## Disclose and verify

A verifier runs four steps. `verifyCounterparty` implements all of them; any failure on either the static or the live leg is a **refuse**, and the default posture is fail-closed.

```
counterparty                                          agent
    │  GET /.well-known/agent-disclosure  ─────────────►│
    │◄──────────────  signed disclosure (ed25519)       │
    │                                                   │
    │  evaluateDisclosure(disclosure, policy)           │  signature · freshness · enforced ·
    │                                                   │  grade · custody · history · anchor
    │                                                   │
    │  POST /agent-disclosure/respond  (fresh nonce) ──►│
    │◄────  signed response (nonce + live audit head)   │  live key possession + history currency
    │                                                   │
    ▼  decision: transact / refuse   (before any value moves)
```

| Step | What it proves |
|:--|:--|
| **1 · Fetch** | Resolve the counterparty's commitments from a well-known URI on its own origin. No registry, no directory, no out-of-band exchange. |
| **2 · Evaluate** | `evaluateDisclosure` runs the verifier's `VerificationPolicy`. Signature + freshness are on by default; every other requirement (enforced constitution, required hard constraints, red-team grade, non-custodial, attestation level, history, audit anchor) is an opt-in field set to the verifier's risk appetite. |
| **3 · Handshake** | A fresh-nonce challenge proves the counterparty holds the signing key *right now* and that its audit head is current - which a captured static document cannot. The response signs an **RFC 9421 (HTTP Message Signatures) signature base**, so a standard implementation reads the exact covered set + params. Defeats identity replay. |
| **4 · Decide** | `transact` only when both legs pass. Cheap and deterministic, so it can run before every transaction (see the [economic-viability model](src/economics.ts)). |

## The disclosure document

What an agent exposes. Each field group maps to a surface serious agent products already maintain, and each carries the threat it makes legible. `SignedDisclosure` wraps the document in an ed25519 envelope whose public key *is* the `agentId`. The same disclosure also serializes as a **flattened JWS (EdDSA) envelope** (`signDisclosureJws`) for JOSE-native stacks; `verifyAnyDisclosureSignature` accepts either shape, discriminated by structure, so both encodings share one signature path.

| Field group | What it is | Threat it makes legible |
|:--|:--|:--|
| **System-prompt fingerprint** | sha256 of the composed system prompt | injection-mediated substitution |
| **Constitution** (`enforced`) | the hard deny-list + gate parameters; `enforced` = these rules ARE the running gate | a promise vs an enforced gate |
| **Tool inventory** | tools + permission boundaries (gated · read-only · operator-only) | hidden capability / privilege |
| **Capital envelope** | the mandate set - scoped, capped, expiring spend authority - and custody | unbounded spend |
| **Operator identity** | who deployed it, the deniability boundary, the attestation level + scheme | an unaccountable operator |
| **Deployment history** | a summary bound to a signed, hash-linked audit chain (`chainAnchor`) | history forgery |
| **Red-team attestation** | a grade against a *public* adversarial corpus | self-grading on a private rubric |
| *Model identity · provenance* (optional) | a declared model fingerprint; how each field was derived | model swap; claim-weighting |

#### The load-bearing field: `enforced`

When `enforced` is true, the disclosed constitution **is the gate actually running**, not a description of intent. In the OpenSolvency reference implementation it is populated directly from the live deny-list and gate config, and `enforcementEvidence` names the gate. A verifier that sets `requireEnforcedConstitution: true` refuses any counterparty whose constitution is merely declared. This is the difference between a disclosure and a promise: the rules are not prose a model can be talked out of, they are the function that decides whether value moves.

#### Extending without a core edit

The attestation `scheme` and the document-level `extensions` map are **open by reverse-domain id** (e.g. `com.visa.tap`): a new attestation scheme or vendor field is a namespace publication, not a core enum edit that forces a five-way re-port. A verifier acts only on extension keys it recognizes and ignores the rest, so the wire format stays forward-compatible across stacks.

## Where it fits

ADP rides *above* the payment rails an agent settles on and composes *with* the identity protocols it authenticates with. The protocol is vendor-neutral; live rail and identity adapters live in the [OpenSolvency](https://github.com/general-liquidity/opensolvency) reference implementation.

#### Payment rails it gates settlement over

| Rail | Relationship |
|:--|:--|
| <img height="14" align="top" src="assets/integrations/x402.jpg" />&nbsp; **x402** | [HTTP-402 + stablecoin settlement](https://www.x402.org) - the disclosure is checked before the 402 is authorized. |
| <img height="14" align="top" src="assets/integrations/ap2.svg" />&nbsp; **AP2** | [Agent Payments Protocol](https://ap2-protocol.org) (Google + FIDO) - an AP2 payment mandate maps onto the disclosed capital envelope. |
| <img height="14" align="top" src="assets/integrations/agentic-commerce-protocol.png" />&nbsp; **Agentic Commerce Protocol** | [ACP](https://www.agenticcommerce.dev) (OpenAI + Stripe) - verify the merchant agent before the delegated checkout settles. |
| <img height="14" align="top" src="assets/integrations/ucp.svg" />&nbsp; **UCP** · <img height="14" align="top" src="assets/integrations/mpp.svg" />&nbsp; **MPP** | Delegated-checkout and rail-agnostic machine-payment protocols. |
| <img height="14" align="top" src="https://cdn.simpleicons.org/ethereum/3C3C3D" />&nbsp; **On-chain (ERC-20 / USDC)** | The `agentId` is an ed25519 key the disclosure signs with - bindable to a wallet-anchored identity. |

#### Identity & trust protocols it composes with

| Protocol | Relationship |
|:--|:--|
| <img height="14" align="top" src="https://cdn.simpleicons.org/ethereum/3C3C3D" />&nbsp; **ERC-8004** | Anchors agent identity to a wallet and names a pluggable verification layer it does not fill. **ADP is that layer.** |
| <img height="14" align="top" src="assets/integrations/aip.jpg" />&nbsp; **AIP** (Agent Identity Protocol) · <img height="14" align="top" src="https://cdn.simpleicons.org/visa/1A1F71" />&nbsp; **Visa Trusted Agent Protocol** | Carried in the operator `attestation` field; the evidence KYC-bound rails recognize, so a regulated rail can terminate at an agent endpoint. |
| <img height="14" align="top" src="assets/integrations/agent-client-protocol.svg" />&nbsp; **Agent Client Protocol** · <img height="14" align="top" src="https://cdn.simpleicons.org/modelcontextprotocol" />&nbsp; **MCP** | Editor/agent surfaces a disclosed agent is driven from. |

#### Agent discovery & messaging

| Protocol | Relationship |
|:--|:--|
| <img height="14" align="top" src="assets/integrations/a2a.svg" />&nbsp; **A2A (Agent2Agent)** | [A2A](https://a2a-protocol.org) (Linux Foundation) - the disclosure rides an Agent Card as a `capabilities.extensions[]` entry ([`src/a2a.ts`](src/a2a.ts)). A counterparty fetches the card at discovery, verifies the disclosure's ed25519 envelope (the trust root) - the card's own RFC 7515 `signatures[]` JWS is treated as origin tamper-evidence - and decides transact/refuse before the A2A task runs. |

#### Discovery transport

The disclosure is served at **`/.well-known/agent-disclosure`**, a well-known URI on the agent's own origin; the live handshake sits beside it at `/agent-disclosure/respond`. Any verifier that can resolve a counterparty's base URL can fetch its commitments - turning the agent-discovery proposals circulating in the space into the concrete transport for the disclosure.

## Conformance

Canonicalization is the interoperability crux: the signed bytes must be byte-identical across implementations, or signatures will not verify across stacks. [`conformance/`](conformance/) is a portable contract that **five independent implementations** (TypeScript, [Go](go/), [Python](python/), [Rust](rust/), [C](c/)) all pass on every commit:

| Layer | What it proves |
|:--|:--|
| **Canonicalization + digest vectors** ([`vectors.json`](conformance/vectors.json)) | Every stack reproduces the canonical bytes + sha256 digests exactly. |
| **Differential fuzzer** ([`fuzz.json`](conformance/fuzz.json)) | 200 seeded-random values; all five stacks agree byte-for-byte. It already caught a real C-only divergence (embedded-NUL truncation). |
| **Interop fixtures** ([`interop.json`](conformance/interop.json)) | TS-minted, ed25519-signed disclosures; native **verifiers** reproduce every verdict + handshake, and native **emitters** reproduce the signatures byte-for-byte (bidirectional interop, no shared secret). Plus redaction / revocation / transparency cases. |
| **Adversarial corpus** ([`negative.json`](conformance/negative.json)) | A MUST-REJECT set (malformed, tampered, hostile input); every verifier rejects all of it and never crashes. It caught a real `signature.algorithm` check gap in two stacks. |
| **Live cross-process** | A TS server serves a disclosure over a real socket; the TS, Go, Python, and Rust clients verify it against one live origin. |
| **Schema drift guard** ([`schema/`](schema/)) | The committed JSON-Schema artifacts are generated from the zod source (`npm run schema`); a drift test (TS [`schema-drift`](conformance/schema-drift.test.ts) + Go [`schema_sync_test`](go/schema_sync_test.go)) fails CI if an enum is edited without regenerating, keeping the schema and every port in sync. |

[`SPEC.md`](SPEC.md) is the normative protocol and [`docs/drafts/draft-gl-adp-disclosure-00.md`](docs/drafts/draft-gl-adp-disclosure-00.md) is the IETF Internet-Draft; [`docs/`](docs/) is a browsable mdBook and [`RELEASING.md`](RELEASING.md) covers tokenless (OIDC trusted-publishing) releases; the canonicalization + signed-bytes format is frozen (see the [stability guarantees](docs/src/stability.md)).

```bash
npm run conformance       # the TS conformance + fuzz + interop suite
node --import tsx scripts/conformanceReport.ts   # a pass/fail report across suites
```

## Architecture

The vendor-neutral core has **one runtime dependency** (`zod`); the ERC-8004 on-chain and ZK range-proof modules use optional `@noble` / `viem` deps behind dynamic imports, so they never weigh on the core.

| Group | Modules |
|:--|:--|
| **Core** | [`schema`](src/schema.ts) (document + both signed envelopes; namespaced attestation schemes + `extensions`), [`attestation`](src/attestation.ts) (ed25519, deterministic canonicalization, the `agentId`-to-key binding, freshness, recursion-depth guard, the v2 flattened-JWS `EdDSA` envelope), [`versioning`](src/versioning.ts) (schema version negotiation). |
| **Verify** | [`verify`](src/verify.ts) + [`client`](src/client.ts) (the policy language, deterministic verdict, the over-the-wire loop), [`cache`](src/cache.ts) (tiered + validity-window), [`guard`](src/guard.ts) + [`mutual`](src/mutual.ts) (disclose-before-settle, both-sides verification), [`adapters`](src/adapters.ts) (a verify-before-pay tool for any framework), [`verifierService`](src/verifierService.ts) (verify-as-a-service HTTP). |
| **Handshake** | [`handshake`](src/handshake.ts) (live nonce challenge-response, defeats identity replay). |
| **Selective disclosure + ZK** | [`redaction`](src/redaction.ts) (salted-commitment field hiding), [`negotiate`](src/negotiate.ts) (reveal exactly what a policy needs), [`zk`](src/zk.ts) (equality backend) + [`zkRange`](src/zkRange.ts) (real Pedersen + bit-decomposition range proofs over secp256k1), [`zkDisclosure`](src/zkDisclosure.ts) (attach + require range proofs about hidden attributes as a disclosure feature). |
| **Revocation + transparency** | [`revocation`](src/revocation.ts) + [`revocationTransport`](src/revocationTransport.ts) (status list + fetch/honor over the wire), [`transparency`](src/transparency.ts) + [`transparencyTransport`](src/transparencyTransport.ts) + [`witness`](src/witness.ts) (CT-for-agents log, inclusion proofs, split-view monitor). |
| **Identity (ERC-8004)** | [`erc8004`](src/erc8004.ts) (agent-to-wallet binding), [`erc8004Onchain`](src/erc8004Onchain.ts) (secp256k1 EIP-191 recovery), [`erc8004Registry`](src/erc8004Registry.ts) (viem registry read), [`erc8004Validation`](src/erc8004Validation.ts) (read on-chain `validationResponse` scores), [`modelAttestation`](src/modelAttestation.ts) (declared model fingerprint). |
| **Standards bridges** | [`did`](src/did.ts) (the `agentId` as a `did:key` / `did:web`), [`vc`](src/vc.ts) (a disclosure as a W3C VC Data Model 2.0 with an ADP-namespaced `adp-jcs-2024` Data Integrity proof - same signature, no second trust root), [`sdjwtvc`](src/sdjwtvc.ts) (an SD-JWT-VC encoding that hides field *names* + count via decoy digests and binds a presentation to one verifier + nonce), [`a2a`](src/a2a.ts) (carry/extract/verify a disclosure on an A2A Agent Card via a `capabilities.extensions[]` entry - the disclosure envelope is the trust root, the card's RFC 7515 `signatures[]` JWS is origin tamper-evidence). |
| **Discovery + ops** | [`discovery`](src/discovery.ts) (.well-known fetcher + agent directory), [`keys`](src/keys.ts) (keyring, key files, and a signed key-rotation statement - the old key signs the move to the new one, chaining identity across a key change), [`monitor`](src/monitor.ts) (disclosure diffing + downgrade alarm), [`statusList`](src/statusList.ts) (W3C StatusList revocation), [`builder`](src/builder.ts) (a fluent disclosure builder), [`economics`](src/economics.ts) (which markets clear at verification cost C). |
| **CLI** | [`cli`](src/cli.ts) - `keygen` / `sign` / `verify-file` / `verify-url`. |
| **Native implementations** | Verifiers + emitters in [`go/`](go/) · [`python/`](python/) · [`rust/`](rust/) · [`c/`](c/), each gated by the conformance contract. |

The OpenSolvency-specific half (the field *builders* that populate a disclosure from a live gate / mandate set / audit chain / SpendTrust run) deliberately does **not** lift out; it is the reference implementation. Any other agent product implements its own builders against the same schema.

## Develop

`tsx` is bundled; the suite runs on Node ≥ 20.

```bash
npm install
npm test          # 229 TS tests across the protocol + every module
npm run conformance # the conformance vectors + fuzz + interop suite
npm run typecheck # tsc --noEmit, strict
npm run build     # tsc -> dist
```

The native implementations carry their own suites, all gated in CI:

```bash
( cd go && go test ./... )
( cd rust && cargo test )
( cd python && python -m pytest )
( cd c && make SODIUM_INC= SODIUM_LIB= LDLIBS=-lsodium test )   # needs libsodium
```

## Tech stack

| Technology | Role |
|:--|:--|
| <img height="14" align="top" src="https://cdn.simpleicons.org/typescript/3178C6" />&nbsp; [TypeScript](https://www.typescriptlang.org) | The whole protocol - strict, ESM, `.ts` imports |
| <img height="14" align="top" src="https://cdn.simpleicons.org/nodedotjs/5FA04E" />&nbsp; [Node ≥ 20](https://nodejs.org) | `node:crypto` for ed25519; no native build step |
| <img height="14" align="top" src="https://cdn.simpleicons.org/zod/3E67B1" />&nbsp; [Zod](https://zod.dev) | The single runtime dependency - schema validation + parse at the boundary |
| **ed25519** | Asymmetric signing - a counterparty verifies with no shared secret |
| <img height="14" align="top" src="https://cdn.simpleicons.org/go/00ADD8" />&nbsp; Go · <img height="14" align="top" src="https://cdn.simpleicons.org/python/3776AB" />&nbsp; Python · <img height="14" align="top" src="https://cdn.simpleicons.org/rust/DEA584" />&nbsp; Rust · <img height="14" align="top" src="https://cdn.simpleicons.org/c/A8B9CC" />&nbsp; C | Native verifiers + emitters, each gated by the conformance contract (crypto/ed25519 · cryptography · ed25519-dalek · libsodium) |
| **@noble/curves · viem** | Optional, behind dynamic imports - secp256k1 (ERC-8004 + ZK range proofs) and the on-chain registry read |
| <img height="14" align="top" src="https://cdn.simpleicons.org/githubactions/2088FF" />&nbsp; GitHub Actions | CI matrix: TypeScript · Go · Python · Rust · C · cross-process · mdBook |

## License

[MIT](LICENSE) © General Liquidity. A General Liquidity protocol - the wire format for Verifiable Agency, so an agent can prove what it is committed to before it transacts.

---
