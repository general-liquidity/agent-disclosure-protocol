<!-- prettier-ignore -->
<div align="center">

# Agent Disclosure Protocol

### The wire format for Verifiable Agency

*Agents are starting to transact with each other with no way to answer the first question of commerce: who am I dealing with, and what are they committed to? ADP is the disclosure an agent publishes **before** it transacts - so a counterparty can verify and decide before value moves, not after a loss.*

[![CI](https://img.shields.io/github/actions/workflow/status/general-liquidity/agent-disclosure-protocol/ci.yml?style=flat-square&label=CI)](https://github.com/general-liquidity/agent-disclosure-protocol/actions)
[![tests](https://img.shields.io/badge/tests-43%20passing-success?style=flat-square)](#develop)
[![conformance](https://img.shields.io/badge/conformance-10%20checks-success?style=flat-square)](#conformance)
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

The protocol has **one runtime dependency** (`zod`) and signs with `node:crypto` only, so any agent stack in any language can emit or verify a disclosure. [OpenSolvency](https://github.com/general-liquidity/opensolvency) is the reference implementation that populates a disclosure from a live, enforced governance gate.

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

Build `myDisclosure` from your own runtime, or use the OpenSolvency builders to populate it from a live gate, mandate set, and signed audit chain.

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
| **3 · Handshake** | A fresh-nonce challenge proves the counterparty holds the signing key *right now* and that its audit head is current - which a captured static document cannot. Defeats identity replay. |
| **4 · Decide** | `transact` only when both legs pass. Cheap and deterministic, so it can run before every transaction (see the [economic-viability model](src/economics.ts)). |

## The disclosure document

What an agent exposes. Each field group maps to a surface serious agent products already maintain, and each carries the threat it makes legible. `SignedDisclosure` wraps the document in an ed25519 envelope whose public key *is* the `agentId`.

| Field group | What it is | Threat it makes legible |
|:--|:--|:--|
| **System-prompt fingerprint** | sha256 of the composed system prompt | injection-mediated substitution |
| **Constitution** (`enforced`) | the hard deny-list + gate parameters; `enforced` = these rules ARE the running gate | a promise vs an enforced gate |
| **Tool inventory** | tools + permission boundaries (gated · read-only · operator-only) | hidden capability / privilege |
| **Capital envelope** | the mandate set - scoped, capped, expiring spend authority - and custody | unbounded spend |
| **Operator identity** | who deployed it, the deniability boundary, the attestation level | an unaccountable operator |
| **Deployment history** | a summary bound to a signed, hash-linked audit chain (`chainAnchor`) | history forgery |
| **Red-team attestation** | a grade against a *public* adversarial corpus | self-grading on a private rubric |
| *Model identity · provenance* (optional) | a declared model fingerprint; how each field was derived | model swap; claim-weighting |

#### The load-bearing field: `enforced`

When `enforced` is true, the disclosed constitution **is the gate actually running**, not a description of intent. In the OpenSolvency reference implementation it is populated directly from the live deny-list and gate config, and `enforcementEvidence` names the gate. A verifier that sets `requireEnforcedConstitution: true` refuses any counterparty whose constitution is merely declared. This is the difference between a disclosure and a promise: the rules are not prose a model can be talked out of, they are the function that decides whether value moves.

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

#### Discovery transport

The disclosure is served at **`/.well-known/agent-disclosure`**, a well-known URI on the agent's own origin; the live handshake sits beside it at `/agent-disclosure/respond`. Any verifier that can resolve a counterparty's base URL can fetch its commitments - turning the agent-discovery proposals circulating in the space into the concrete transport for the disclosure.

## Conformance

Canonicalization is the interoperability crux: the signed bytes must be byte-identical across implementations, or signatures will not verify across stacks. [`conformance/`](conformance/) is a portable suite any implementation must pass - golden canonicalization + digest vectors (defined by the protocol, not this code) plus behavioural invariants (signature + identity binding, ed25519 determinism, freshness boundaries, the handshake). [`SPEC.md`](SPEC.md) is the normative protocol; a conformant implementation reproduces the vectors and passes the checks.

```bash
npm run conformance   # the portable vectors + behavioural invariants
```

## Architecture

The vendor-neutral core, one runtime dependency, no I/O in the protocol itself.

| Module | What it is |
|:--|:--|
| [`schema`](src/schema.ts) | The disclosure document + the `SignedDisclosure` envelope (zod schemas + inferred types). |
| [`attestation`](src/attestation.ts) | ed25519 sign / verify, the deterministic canonicalization, the `agentId`-to-key binding, sha256 digests, and the freshness window. Keys export and reload so an agent's identity is stable across restarts. |
| [`handshake`](src/handshake.ts) | The live challenge-response: sign a fresh nonce bound to the current audit head. Defeats identity replay. |
| [`verify`](src/verify.ts) + [`client`](src/client.ts) | `VerificationPolicy` (the declarative language a verifier states its demands in), `evaluateDisclosure` (deterministic verdict + per-check breakdown), and `verifyCounterparty` (the over-the-wire loop). |
| [`guard`](src/guard.ts) + [`cache`](src/cache.ts) | Outbound disclose-before-settle + mutual disclosure; tiered verification with a validity-window cache (the economic enabler). |
| [`redaction`](src/redaction.ts) · [`revocation`](src/revocation.ts) · [`transparency`](src/transparency.ts) | Salted-commitment selective disclosure; a portable revocation status list; an append-only Certificate-Transparency-for-agents log. |
| [`economics`](src/economics.ts) | The viability model - which agent-to-agent markets clear at verification cost C. |

The OpenSolvency-specific half (the field *builders* that populate a disclosure from a live gate / mandate set / audit chain / SpendTrust run) deliberately does **not** lift out; it is the reference implementation. Any other agent product implements its own builders against the same schema.

## Develop

`tsx` is bundled; the suite runs on Node ≥ 20.

```bash
npm install
npm test          # 43 tests - schema, attestation, handshake, verify, client, guard, cache, redaction, revocation, transparency, economics
npm run conformance # 10 portable conformance checks
npm run typecheck # tsc --noEmit, strict
npm run build     # tsc -> dist
```

## Tech stack

| Technology | Role |
|:--|:--|
| <img height="14" align="top" src="https://cdn.simpleicons.org/typescript/3178C6" />&nbsp; [TypeScript](https://www.typescriptlang.org) | The whole protocol - strict, ESM, `.ts` imports |
| <img height="14" align="top" src="https://cdn.simpleicons.org/nodedotjs/5FA04E" />&nbsp; [Node ≥ 20](https://nodejs.org) | `node:crypto` for ed25519; no native build step |
| <img height="14" align="top" src="https://cdn.simpleicons.org/zod/3E67B1" />&nbsp; [Zod](https://zod.dev) | The single runtime dependency - schema validation + parse at the boundary |
| **ed25519** | Asymmetric signing - a counterparty verifies with no shared secret |
| <img height="14" align="top" src="https://cdn.simpleicons.org/githubactions/2088FF" />&nbsp; GitHub Actions | CI: lint · typecheck · build · tests · conformance |

## License

[MIT](LICENSE) © General Liquidity. A General Liquidity protocol - the wire format for Verifiable Agency, so an agent can prove what it is committed to before it transacts.

---
