# Agent Disclosure Protocol (ADP): Threat Model

The Agent Disclosure Protocol (ADP), the wire format for Verifiable Agency, rests on asymmetric signatures. The agent holds a private ed25519 key; the matching public key travels in the disclosure envelope and, by convention, is the agent's identity. A counterparty therefore verifies a disclosure with no shared secret and no prior relationship: anyone can check the claim, not just the party that issued it. The verification runs before value moves, not after a loss. A disclosure that fails policy, has expired, is unreachable, or fails the live liveness handshake all resolve to refuse, and the default posture is fail-closed. The threats below are the ones the protocol is built to make legible, each paired with the concrete module or field that defends against it and an honest statement of what residual gap remains.

## Summary

| # | Attack | Defense | Concrete locus | Residual gap |
|---|--------|---------|----------------|--------------|
| 1 | Constitution substitution via prompt injection | Enforced-constitution binding | `ConstitutionSchema.enforced`, `builders.ts` | Gate-config drift between issuance and runtime |
| 2 | Deployment-history forgery | History bound to the signed audit chain | `DeploymentHistory.chainAnchor` | A new agent legitimately has no history |
| 3 | Identity replay | Live challenge-response | `handshake.ts` | A compromised private key |
| 4 | Stale-disclosure presentation | Validity window, nonce, audit-head currency | `validUntil` + `handshake.ts` | Clock skew between parties |
| 5 | Disclosure post-hoc rewriting | ed25519 signature, audit-anchor binding | `attestation.ts` + `auditAnchor` | Re-issuance with a fresh nonce |
| 6 | Operator collusion / sock-puppets | Cross-operator reputation, deny-list floor | `OperatorIdentitySchema` + the deny-list | Brand-new operators have no reputation (Sybil) |
| 7 | Model swap | Declared model fingerprint | `ModelIdentitySchema` | Proving the running model needs TEE attestation |
| 8 | Self-grading on a private rubric | Public adversarial corpus, contamination canary | `spendTrust.ts`, `RedTeamAttestation` | Corpus coverage gaps |
| 9 | Verification-cost DoS | Tiered verification, validity-window caching | `economics.ts` | Markets below break-even margin |

## 1. Constitution substitution via prompt injection

**Attack.** A prompt injection persuades the agent to disclose a constitution it is not actually running, or to soften the rules it claims to enforce, so a counterparty transacts on the strength of a constitution that no longer governs the agent.

**Defense.** The `enforced` flag on `ConstitutionSchema` is the binding. When true, the disclosed constitution IS the gate actually running, not model text. In the reference implementation `builders.ts` sets `enforced: true` and constructs the constitution directly from the live `DEFAULT_DENY_RULES` (the hard constraints) and `DEFAULT_GATE_CONFIG` (the parameters: minimum rationale length, velocity window, velocity ceiling, anomaly multiple). These are structured predicates and numbers a verifier can check, not prose a model can be talked out of. `enforcementEvidence` names the gate. A verifier that sets `requireEnforcedConstitution: true` and lists `requiredHardConstraints` refuses any counterparty whose constitution is declared-only or missing a required rule.

**Residual gap.** The disclosure asserts the gate config as of issuance. If the operator changes the gate config after issuance, the disclosed constitution can drift from the runtime one. This is mitigated, not eliminated, by the short freshness window (a one-hour default validity) plus the audit anchor: a stale disclosure expires, and the anchor binds the disclosure to the audit-chain state at issuance, so post-issuance drift is bounded by how recently the disclosure was minted.

## 2. Deployment-history forgery

**Attack.** An agent inflates its record, claiming thousands of clean settlements and zero blocks to manufacture trust it has not earned.

**Defense.** `DeploymentHistory` is derived from, and verifiable against, the signed hash-linked audit chain. `builders.ts` computes the summary (total decisions, settled count, blocked count, first-seen, last-active) by walking the real audit entries, and stamps `chainAnchor` with the head hash of that chain. `verificationHint` tells a counterparty how to re-verify the exported chain. Because every audit entry commits to the previous entry's hash, the summary cannot claim numbers the chain does not support without breaking the recomputed link.

**Residual gap.** A brand-new agent legitimately has no history; its summary is genuinely empty. The protocol does not, and cannot, distinguish "new and honest" from "evasive." The verifier's policy decides whether that is acceptable: `requireDeploymentHistory: true` refuses agents with no track record, but that is a business choice, not a cryptographic guarantee.

## 3. Identity replay

**Attack.** A captured, validly signed disclosure is replayed by a party that is not the agent, asserting "I am the agent you think I am" while holding none of the agent's keys or current state.

**Defense.** The live challenge-response in `handshake.ts`. The verifier issues a fresh random nonce; the agent signs that nonce together with its current audit-chain head, its agentId, the timestamp, and the verifier id, over the canonical bytes both sides reconstruct. `verifyChallengeResponse` confirms the nonce matches the one issued (anti-replay), that the response is signed by the disclosed agentId (live key possession), and that the response is fresh within the configured age window. A replayed static disclosure cannot answer a nonce it has never seen.

**Residual gap.** A compromised private key. If an attacker holds the agent's signing key, it can answer challenges as the agent. The mitigation is revocation (`revocation.ts`): a portable, signed status list keyed by disclosureId or agentId that a verifier fetches and consults the same way a CRL gates a certificate, refusing any revoked identity.

## 4. Stale-disclosure presentation

**Attack.** An agent presents an old disclosure that was accurate once but no longer reflects its current constitution, mandates, or history.

**Defense.** Three layers. The validity window: every disclosure carries `issuedAt` and `validUntil`, and `isFresh` (`attestation.ts`) rejects anything outside the window; the reference builder defaults to a one-hour window. The nonce: each disclosure carries a fresh nonce, paired with the handshake challenge for liveness. And the handshake's audit-head currency check: the response binds the agent's live audit head, which the verifier compares against the disclosure's anchor, so a regression to an older state is a red flag.

**Residual gap.** Clock skew between the two parties. The freshness comparison is against the verifier's clock; if the parties' clocks disagree, the window's edges move. ISO-8601 lexical comparison is exact, but it is only as accurate as the clocks feeding it.

## 5. Disclosure post-hoc rewriting

**Attack.** After issuing a disclosure, the agent edits its content (softens a constraint, inflates the history) while keeping it looking authentic.

**Defense.** The ed25519 signature over the canonicalized disclosure (`attestation.ts`). Any edit to the document changes the canonical bytes and breaks `verifyDisclosureSignature`, which also enforces the agentId-to-key binding so a disclosure must be signed by the very key it claims as its identity. The optional `auditAnchor` binds the disclosure to the tamper-evident audit-chain head, so the document cannot be retro-edited without breaking the link to a state the agent actually committed.

**Residual gap.** The signer can always re-issue: mint a new, validly signed disclosure with a fresh nonce and different content. The defense against silent re-issuance is the transparency log (`transparency.ts`), a Certificate-Transparency-for-agents append-only hash-linked log of disclosure digests. A counterparty watching the log sees when an agent re-issues under the same identity, so re-issuance is publicly visible rather than silent.

## 6. Operator collusion / sock-puppet operators

**Attack.** A bad operator spins up multiple operator identities, or colludes with others, to vouch for an agent and manufacture trust.

**Defense.** Two parts. Cross-operator reputation through `OperatorIdentitySchema`: the operator carries a stable id, an attestation scheme and level (AIP, Visa Trusted Agent Protocol, ERC-8004, signed or registry-attested), and an explicit `deniabilityBoundary` stating what the operator is and is not accountable for. And the deny-list floor: a colluding operator cannot quietly disable the hard deny-list, because the deny-list is part of the disclosed, enforced constitution (attack 1). Turning it off would show in the disclosure as a missing hard constraint, which a verifier requiring those constraints refuses.

**Residual gap.** A brand-new operator has no reputation, so the Sybil case is only partially defended. Cross-operator reputation raises the cost of sock-puppets over time but cannot stop a fresh, unattested operator on day one; `minAttestationLevel` in the policy lets a verifier demand registry-attested operators, trading reach for assurance.

## 7. Model swap

**Attack.** The agent declares one model but runs another, for instance disclosing a safety-tuned model while serving a jailbroken or cheaper one.

**Defense.** The declared model fingerprint (`ModelIdentitySchema`, a v0 field): a sha256 digest of a declared model identifier or weights manifest, so a verifier can at least pin and compare the claimed model across disclosures and detect a changed declaration.

**Residual gap.** This is the declarable half only. Cryptographically proving that the running model matches the declared one at transact-time requires hardware (TEE) attestation, which the protocol does not yet carry. This is flagged as the honest open research item, not hidden: the schema comment states it plainly, and the field is versioned so a hardware-attested successor can supersede it without a breaking change.

## 8. Self-grading on a private rubric

**Attack.** An agent claims a strong safety record by grading itself against a private, favorable rubric a counterparty cannot inspect or reproduce.

**Defense.** The red-team attestation (`RedTeamAttestation`) is scored against a versioned public adversarial corpus, so results are comparable across agents and the agent cannot mark its own homework. In the reference implementation the corpus is SpendTrust (`spendTrust.ts`): a deterministic, explainable scorer where a single catastrophic behaviour (retrying a gate-blocked payment, or attempting an injected rationale) hard-fails the agent regardless of an otherwise clean record. The `corpus` field carries the corpus name and version; `hardFails` lists the catastrophic failures explicitly. The injection-pattern set in the scorer acts as a contamination canary: manipulative rationales are detected by pattern and pin the grade, so an agent that tries to talk past the gate cannot attest a passing grade.

**Residual gap.** Corpus coverage gaps. The attestation is only as strong as the corpus is comprehensive; an attack the public corpus does not encode is not caught by it. Versioning the corpus lets coverage grow, and the verifier can demand a minimum grade and a maximum hard-fail count, but no fixed corpus is exhaustive.

## 9. Verification-cost DoS / economic non-viability

**Attack.** Verifying every counterparty before every transaction is made expensive enough that either verification is skipped (defeating the protocol) or the market becomes uneconomic (an economic denial of service on the whole approach).

**Defense.** Tiered verification plus validity-window caching, with the trade-off made explicit by the economic-viability model (`economics.ts`). Verification splits into a cheap, cacheable fast path and a deep path (live handshake plus corpus re-run); only a small `deepFraction` of transactions take the deep path, and a high `cacheHitRate` serves fast-path checks from the validity window at near-zero marginal cost. `economics.ts` computes the blended per-transaction cost, credits verification with the fraud it removes, and names which markets stay net-positive (`viabilityOf`, `surviving`) and the maximum cost a market can bear (`breakEvenVerificationCostMinor`). Deterministic verification keeps the marginal cost low by design.

**Residual gap.** Markets below the break-even margin. Sub-margin micropayments, deep-verified on every transaction, can still net negative, as the model states plainly. Tiering and caching lift thin markets back above break-even, but a market whose margin plus fraud-saving is smaller than even the blended verification cost does not survive, and the model is honest that those markets exist.
