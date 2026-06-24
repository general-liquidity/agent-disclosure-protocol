# Threat Model

This chapter summarizes the protocol's threat model. The full attack-by-attack analysis,
including every residual gap, is in
[`THREAT_MODEL.md`](https://github.com/general-liquidity/agent-disclosure-protocol/blob/main/THREAT_MODEL.md)
and is normative context for any deployment.

ADP makes a fixed set of attacks legible and pairs each with a concrete defending module
or field, and states the residual gap for each honestly. The verification runs before
value moves, not after a loss. A disclosure that fails policy, has expired, is unreachable,
or fails the live liveness handshake all resolve to refuse, and the default posture is
fail-closed.

## Summary

| # | Attack | Defense | Concrete locus | Residual gap |
|---|---|---|---|---|
| 1 | Constitution substitution via prompt injection | Enforced-constitution binding | `ConstitutionSchema.enforced` | Gate-config drift between issuance and runtime |
| 2 | Deployment-history forgery | History bound to the signed audit chain | `DeploymentHistory.chainAnchor` | A new agent legitimately has no history |
| 3 | Identity replay | Live challenge-response | `handshake.ts` | A compromised private key |
| 4 | Stale-disclosure presentation | Validity window, nonce, audit-head currency | `validUntil` + `handshake.ts` | Clock skew between parties |
| 5 | Disclosure post-hoc rewriting | ed25519 signature, audit-anchor binding | `attestation.ts` + `auditAnchor` | Re-issuance with a fresh nonce |
| 6 | Operator collusion / sock-puppets | Cross-operator reputation, deny-list floor | `OperatorIdentitySchema` + the deny-list | Brand-new operators have no reputation (Sybil) |
| 7 | Model swap | Declared model fingerprint | `ModelIdentitySchema` | Proving the running model needs TEE attestation |
| 8 | Self-grading on a private rubric | Public adversarial corpus, contamination canary | `RedTeamAttestation` | Corpus coverage gaps |
| 9 | Verification-cost DoS | Tiered verification, validity-window caching | `economics.ts` | Markets below break-even margin |

## How to read the table

Each row is a complete unit: an attack, the field or module that defends against it, and
the part of the attack the defense does **not** cover. The protocol does not claim to
close every gap; it claims to make each one explicit and to let the verifier's policy
decide what to require.

A few of the defenses are worth drawing out:

- **Threat 1** is the reason `constitution.enforced` is the load-bearing field. When the
  flag is true the disclosed constitution is the gate actually running, built from the
  live deny-list and gate config, not prose a model can be talked out of. The residual gap
  is bounded by the short freshness window plus the audit anchor.
- **Threat 3** is what the [verification handshake](./verification-handshake.md) exists
  for: a replayed static disclosure cannot answer a fresh nonce. The residual gap, a
  compromised key, is handled by [revocation](./revocation-and-transparency.md).
- **Threat 7** is the honest open research item. The declared model fingerprint is the
  cheap declarable half; cryptographically proving the running model at transact-time needs
  hardware (TEE) attestation, which the protocol does not yet carry. The field is versioned
  so a hardware-attested successor can supersede it without a breaking change.
- **Threat 9** is the economic objection: if verifying every counterparty before every
  transaction is too expensive, verification gets skipped. Tiered verification plus
  validity-window caching keeps the marginal cost low; the `economics.ts` model names which
  markets stay net-positive and which do not. See the
  [positioning](./positioning.md) chapter.
