# Agent Disclosure Protocol (ADP)

The Agent Disclosure Protocol (ADP) - the wire format for Verifiable Agency.

A vendor-neutral disclosure protocol for agent-to-agent commerce. Before an agent transacts, it exposes what it is committed to: the rules it runs under, the capital envelope it operates inside, who deployed it, what it has done, and how it was signed. A counterparty fetches that disclosure, evaluates it against its own policy, and decides to transact or refuse. The decision happens before value moves, not after a loss.

The reference implementation lives inside OpenSolvency. The vendor-neutral core (`schema`, `attestation`, `verify`, `handshake`, `client`) depends only on `zod` and `node:crypto`, so it is designed to lift cleanly into a standalone `agent-disclosure` repo.

## The trust model

ADP uses asymmetric signatures. The agent holds a private ed25519 key; the matching public key travels in the disclosure envelope and, by convention, IS the agent's identity (`agentId`). A counterparty verifies a disclosure with no shared secret, no prior relationship, and no registration step. This is the one capability symmetric signing (OpenSolvency's HMAC audit chain) cannot provide: anyone can check the claim, not just the party that wrote it.

The check runs before the transaction clears. A disclosure that fails policy, an expired disclosure, an unreachable endpoint, or a failed liveness handshake all produce a refuse verdict. The default posture is fail-closed.

## The disclose-before-settle loop

A verifier runs four steps before transacting. `client.ts` `verifyCounterparty` implements the whole loop end to end:

1. **Fetch.** GET `<base>/.well-known/agent-disclosure` and structurally parse the signed envelope. A non-200 response or a parse failure is a refuse.
2. **Evaluate against policy.** Run `evaluateDisclosure` (`verify.ts`) over the signed disclosure with the verifier's `VerificationPolicy`. The signature and freshness checks are on by default; every other requirement (enforced constitution, required hard constraints, red-team grade, non-custodial operation, operator attestation level, deployment history, audit anchor) is an opt-in field the verifier sets to its own risk appetite.
3. **Live handshake.** Issue a fresh nonce challenge to `<base>/agent-disclosure/respond` and verify the response (`handshake.ts`). This proves the counterparty holds the signing key right now and that its audit head is current, which a captured static document cannot prove.
4. **Transact or refuse.** The verdict is `transact` only when both the static policy evaluation and the live handshake pass. Any reason on either leg flips the decision to refuse and reports every failed check for transparency.

The handshake is on by default and can be disabled (`liveHandshake: false`) when a verifier chooses to trust the static document alone.

## The three artifacts

**1. The disclosure schema (`schema.ts`).** What an agent exposes. Seven field groups, each mapping to a surface serious agent products already maintain and each carrying the threat it is meant to make legible: a system-prompt fingerprint, the operating constitution and its hard constraints, the tool inventory and permission boundaries, the capital and risk envelope (the mandate set), operator identity and the deniability boundary, cumulative deployment history bound to a signed audit chain, and red-team attestations. An optional declared model identity and per-field provenance let a verifier weight claims. `SignedDisclosure` wraps the document in an ed25519 envelope.

**2. The attestation primitives (`attestation.ts`).** ed25519 sign and verify, a stable canonicalization (recursively key-sorted JSON, the same scheme the audit chain uses), the `signDisclosure` / `verifyDisclosureSignature` pair, the agentId-to-key binding check, sha256 digests for the fingerprint fields, and an `isFresh` freshness window. Key material can be exported and reloaded so an agent's identity is stable across restarts, which is what makes a counterparty's reputation of it meaningful over time.

**3. The verification handshake and counterparty policy language (`verify.ts` + `handshake.ts`).** `VerificationPolicy` is the declarative language a verifier uses to state what it demands of anyone it transacts with. `evaluateDisclosure` produces a deterministic `transact` / `refuse` verdict with a per-check breakdown. The handshake adds the live challenge-response that closes the replay gap.

## The killer differentiator: `enforced`

The load-bearing field in the constitution is `enforced`. When it is true, the disclosed constitution IS the gate actually running, not a description of intent. In the OpenSolvency reference implementation, `builders.ts` sets `enforced: true` and populates the constitution directly from the live `DEFAULT_DENY_RULES` and `DEFAULT_GATE_CONFIG`. The disclosed hard constraints are structured predicates over intent, and the disclosed parameters (minimum rationale length, velocity window, velocity ceiling, anomaly multiple) are the numbers the gate evaluates. The `enforcementEvidence` field names the gate: `opensolvency-gate (evaluateGate over structured intent)`.

A verifier that sets `requireEnforcedConstitution: true` refuses any counterparty whose constitution is merely declared. This is the difference between a disclosure and a promise. The rules are not prose a model can be talked out of; they are the function that decides whether value moves.

## Positioning vs ERC-8004

ERC-8004 anchors agent identity to a wallet and openly describes a pluggable verification layer it does not itself fill. ADP is that layer. A disclosure binds to its wallet-bound identity through the same ed25519 key that signs it, and the counterparty policy language supplies the behavioural trust check ERC-8004 leaves open: not just "who is this agent" but "what is it committed to, is that commitment enforced, and has it behaved." ADP is the pluggable behavioural-trust layer the rest of the agentic-commerce stack defers.

## Discovery transport

The disclosure is served at `.well-known/agent-disclosure`, a well-known URI on the agent's own origin. This turns the agent-discovery proposals circulating in the space into the concrete transport for the disclosure: a verifier that can resolve a counterparty's base URL can fetch its commitments without any registry, directory, or out-of-band exchange. The live handshake endpoint sits alongside it at `agent-disclosure/respond`.

## The regulated-rails argument

KYC-bound payment rails will not terminate at an anonymous agent endpoint. A disclosure is designed to satisfy what those rails require to settle: a stable, signed identity; a declared operator with an explicit deniability boundary; an enforced constitution including the deny-list floor; a non-custodial custody declaration; and a verifiable history. The operator attestation field carries the identity-protocol evidence (AIP, Visa Trusted Agent Protocol, ERC-8004) the rails recognize. The stake is physical-world: a disclosure that meets these requirements is what lets regulated rails terminate at agent endpoints at all.

## Status

The reference implementation runs inside OpenSolvency. `builders.ts` is the OpenSolvency-specific half: it populates a vendor-neutral disclosure from the live governance primitives (the enforced gate, the granted mandates, the signed audit chain, a SpendTrust run), so every field is derived from something real rather than asserted. That file does not lift out.

The vendor-neutral core does. `schema.ts`, `attestation.ts`, `verify.ts`, `handshake.ts`, and `client.ts` carry no OpenSolvency dependency and are designed to lift into a standalone `agent-disclosure` repo, where any agent product can implement its own builders against the same schema and any verifier can run the same policy language. Supporting modules (`revocation.ts`, a CRL-style portable status list, and `transparency.ts`, a Certificate-Transparency-for-agents append-only log) extend the core with revocation and public auditability.

See `THREAT_MODEL.md` for the attack-by-attack analysis, including the honest open items.
