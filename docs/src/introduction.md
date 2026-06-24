# Introduction

## What ADP is

The Agent Disclosure Protocol (ADP) is a disclose-before-settle protocol for
agent-to-agent commerce. Before an agent transacts, it exposes a signed disclosure
document: the rules it runs under, the capital envelope it operates inside, who deployed
it, what it has done, the model it declares, and how the whole document was signed.

A counterparty fetches that disclosure, evaluates it against its own policy, optionally
runs a live challenge-response handshake to prove the counterparty holds the signing key
right now, and only then decides to transact or refuse. The decision happens before value
moves, not after a loss.

ADP is **not** a wallet, a rail, or an identity registry. It is the vendor-neutral
disclosure layer that sits *above* the payment rails (x402, AP2, ACP, cards) and *beside*
the identity protocols (ERC-8004, AIP, Visa Trusted Agent Protocol). It enforces a single
loop and leaves settlement and identity to the layers built for them.

## The disclose-before-settle loop

```
counterparty                                          agent
    |  GET /.well-known/agent-disclosure  ------------>|
    |<-------------  signed disclosure (ed25519)        |
    |                                                   |
    |  evaluateDisclosure(disclosure, policy)           |  signature, freshness, enforced,
    |                                                   |  grade, custody, history, anchor
    |                                                   |
    |  POST /agent-disclosure/respond  (fresh nonce) -->|
    |<----  signed response (nonce + live audit head)   |  live key possession + currency
    |                                                   |
    v  decision: transact / refuse   (before any value moves)
```

A verifier runs four steps:

1. **Fetch.** Resolve the counterparty's commitments from a well-known URI on its own
   origin. No registry, no directory, no out-of-band exchange.
2. **Evaluate.** Run the verifier's policy over the static document. Signature and
   freshness are checked by default; every other requirement is an opt-in field set to
   the verifier's risk appetite.
3. **Handshake.** A fresh-nonce challenge proves the counterparty holds the signing key
   right now and that its audit head is current, which a captured static document cannot.
4. **Decide.** `transact` only when both legs pass. The evaluation is cheap and
   deterministic, so it can run before every transaction.

The default posture is **fail-closed**: a disclosure that fails policy, has expired, is
unreachable, or fails the live liveness handshake all resolve to refuse.

## The wire format for Verifiable Agency

ADP uses asymmetric (ed25519) signatures, so a counterparty verifies a disclosure with no
shared secret and no prior relationship. The signer holds a private key; the matching
public key travels in the envelope and, by convention, **is** the agent's identity
(`agentId`). Anyone can check the claim, not just the party that issued it.

This is what makes ADP a wire format rather than a service. A disclosure is a
self-contained, signed artifact. It can be served from a well-known URI, cached, relayed,
or pinned in a transparency log, and a verifier anywhere can check it against the public
key it carries. The protocol defines the bytes on the wire and the exact rules a verifier
applies. Everything above it (rails, registries, reputation oracles) is pluggable.

The phrase **Verifiable Agency** names the goal: an agent that can prove, before it acts,
what it is committed to, that the commitment is enforced rather than promised, and that it
holds the key it claims right now. The chapters that follow define each of those proofs.

## The killer differentiator: `enforced`

The single most load-bearing field in the disclosure is `constitution.enforced`. When it
is true, the disclosed constitution **is the gate actually running**, not a description of
intent. A verifier that sets `requireEnforcedConstitution: true` refuses any counterparty
whose constitution is merely declared. This is the difference between a disclosure and a
promise: the rules are not prose a model can be talked out of, they are the function that
decides whether value moves. The [disclosure document](./disclosure-document.md) chapter
returns to this field in detail.
