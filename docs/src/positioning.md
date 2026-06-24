# Positioning

ADP is the vendor-neutral disclosure layer that sits **above** the payment rails and
**beside** the identity protocols. It is not a wallet, a rail, or an identity registry.
This chapter places it next to ERC-8004, x402, and AP2, and states the regulated-rails
argument.

## The layer the stack defers

Several agentic-commerce efforts name a behavioural-trust layer and then leave it
unfilled. ERC-8004 anchors an agent's identity to a wallet and names a pluggable
verification layer it does not itself fill. ADP is that layer: not just *who is this
agent*, but *what is it committed to, is that commitment enforced, and has it behaved*,
checked before the transaction clears.

## Where it fits among rails and identity

ADP rides above the payment rails an agent settles on and composes with the identity
protocols it authenticates with.

### Payment rails it gates settlement over

| Rail | Relationship |
|---|---|
| **x402** | HTTP-402 plus stablecoin settlement; the disclosure is checked before the 402 is authorized. |
| **AP2** | Agent Payments Protocol (Google + FIDO); an AP2 payment mandate maps onto the disclosed capital envelope. |
| **Agentic Commerce Protocol (ACP)** | OpenAI + Stripe; verify the merchant agent before the delegated checkout settles. |
| **UCP / MPP** | Delegated-checkout and rail-agnostic machine-payment protocols. |
| **On-chain (ERC-20 / USDC)** | The `agentId` is an ed25519 key the disclosure signs with, bindable to a wallet-anchored identity. |

### Identity and trust protocols it composes with

| Protocol | Relationship |
|---|---|
| **ERC-8004** | Anchors agent identity to a wallet and names a pluggable verification layer it does not fill. ADP is that layer. |
| **AIP (Agent Identity Protocol)** and **Visa Trusted Agent Protocol** | Carried in the operator `attestation` field; the evidence KYC-bound rails recognize, so a regulated rail can terminate at an agent endpoint. |
| **Agent Client Protocol** and **MCP** | Editor and agent surfaces a disclosed agent is driven from. |

The protocol is vendor-neutral. Live rail and identity adapters live in the OpenSolvency
reference implementation, not in the protocol core.

## The regulated-rails argument

A regulated rail (a card network, a bank rail, a KYC-bound stablecoin issuer) cannot
settle to a counterparty it cannot hold accountable. ADP makes an agent endpoint
terminable for such a rail in three ways:

- The operator `attestation` field carries the evidence a KYC-bound rail recognizes (AIP,
  Visa Trusted Agent Protocol, ERC-8004 registry attestation), so the rail can demand a
  minimum attestation level via policy.
- The `deniabilityBoundary` is the operator's explicit, signed statement of what it is and
  is not accountable for, which is exactly the artifact a regulated counterparty needs on
  file.
- The `enforced` constitution turns the agent's rules from a claim into a checkable gate,
  so the rail is not relying on a promise.

The result is that a regulated rail can terminate at an agent endpoint and still satisfy
its own accountability requirements, because the disclosure carries the evidence rather
than asking the rail to trust the agent.

## The economic argument

The objection to verifying every counterparty before every transaction is cost: if
verification is expensive, it gets skipped, and skipping it defeats the protocol. The
viability model (`src/economics.ts`) answers this with a per-transaction account.

Verification splits into a cheap, cacheable fast path and a deep path (live handshake plus
corpus re-run). Only a small `deepFraction` of transactions take the deep path, and a high
`cacheHitRate` serves fast-path checks from the validity window at near-zero marginal cost.
The blended per-transaction cost is:

```
(1 - deepFraction) * fastCost * (1 - cacheHitRate)  +  deepFraction * deepCost
```

A market is viable when `margin + fraudSaving - verificationCost > 0`, where `fraudSaving`
credits verification with the fraud it removes (the delta between the no-verification and
residual fraud rates). The model exposes `viabilityOf`, `surviving` (which markets stay
net-positive), and `breakEvenVerificationCostMinor` (the maximum cost a market can bear).

The honest conclusion the model states plainly: cheap deterministic verification plus
caching and tiering keeps most markets viable, but a sub-margin micropayment market that
deep-verifies every transaction can still net negative. Tiering and caching lift thin
markets back above break-even; a market whose margin plus fraud-saving is smaller than even
the blended verification cost does not survive, and the model does not pretend otherwise.

## The thesis

ADP is the wire format for **Verifiable Agency**: an agent that can prove, before it acts,
what it is committed to, that the commitment is enforced rather than promised, and that it
holds the key it claims right now. The protocol defines the bytes on the wire and the exact
rules a verifier applies; the rails, registries, and reputation oracles above it are
pluggable. That is the layer the rest of the agentic-commerce stack openly defers, and it
is the layer ADP fills.
