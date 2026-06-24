# Agent Disclosure Protocol

**The wire format for Verifiable Agency.**

Agents are starting to transact with each other with no way to answer the first
question of commerce: who am I dealing with, and what are they committed to? The Agent
Disclosure Protocol (ADP) is the disclosure an agent publishes *before* it transacts, so
a counterparty can verify and decide before value moves, not after a loss.

This book is a browsable rendering of the protocol. It tracks the normative
specification in [`SPEC.md`](https://github.com/general-liquidity/agent-disclosure-protocol/blob/main/SPEC.md)
and the attack analysis in
[`THREAT_MODEL.md`](https://github.com/general-liquidity/agent-disclosure-protocol/blob/main/THREAT_MODEL.md).
Where the two disagree, the source documents in the repository are authoritative.

## The loop

> An agent reveals what it is committed to before it transacts. A counterparty verifies
> that disclosure against its own policy and a live key-possession handshake, and decides
> transact or refuse, before any value moves. Asymmetric signatures mean anyone can
> check, with no shared secret and no registry.

## How to read this book

- [Introduction](./introduction.md) frames what ADP is, the disclose-before-settle loop,
  and why it is the wire format for Verifiable Agency.
- The next chapters walk the protocol surface in order: the
  [disclosure document](./disclosure-document.md), [canonicalization](./canonicalization.md),
  [signing and identity](./signing-and-identity.md), the
  [verification handshake](./verification-handshake.md), and the
  [policy and verdict](./policy-and-verdict.md).
- [Selective disclosure](./selective-disclosure.md) and
  [revocation and transparency](./revocation-and-transparency.md) cover the privacy and
  lifecycle surfaces.
- [Conformance](./conformance.md) is how an independent implementation proves itself.
- [Threat model](./threat-model.md) and [positioning](./positioning.md) close the book.

The protocol has one runtime dependency (`zod`) and signs with `node:crypto` only, so any
agent stack in any language can emit or verify a disclosure.
