# Verification Policy and Verdict

A verifier evaluates a signed disclosure against its own `VerificationPolicy` and gets a
deterministic `transact` / `refuse` verdict with a per-check breakdown (`evaluateDisclosure`
in `src/verify.ts`). The evaluation is deterministic and cheap by design; the verdict
carries a `cost` instrument (`checksRun`, `wallMicros`).

A verifier MUST refuse when any enabled predicate fails. The verdict's `decision` is
`transact` only when zero reasons accumulated; otherwise `refuse`. Every failed check is
reported (the verdict does not short-circuit on the first failure for reporting purposes,
though it refuses if any failed).

## Baseline: an empty policy

With no requirements set, only two predicates run, both default-ON:

- `requireValidSignature` (default true): the ed25519 signature MUST verify and the
  agentId-to-key binding MUST hold.
- `requireFresh` (default true): the disclosure MUST be within `[issuedAt, validUntil]`
  against `policy.now`.

An empty policy therefore checks **only** signature and freshness. Either can be disabled
by setting it to `false`.

## Opt-in predicates

Every other field is optional and enforced only when set. The verifier states its risk
appetite as a declarative policy.

| Policy field | Predicate (refuse when it fails) |
|---|---|
| `requireEnforcedConstitution` | `constitution.enforced` MUST be true. |
| `requiredHardConstraints: string[]` | Every listed hard-constraint id MUST be present in `constitution.hardConstraints`. |
| `requireRedTeam` | A `redTeam` attestation MUST be present. |
| `minRedTeamGrade: Grade` | `redTeam.result.grade` MUST rank at or above the minimum (A > B > C > D > F). Evaluated only when a `redTeam` attestation is present. |
| `maxRedTeamHardFails` (default 0) | `redTeam.result.hardFails.length` MUST be at most the max. Evaluated when a `redTeam` attestation is present. |
| `requireNonCustodial` | `capital.custody` MUST equal `non_custodial`. |
| `minAttestationLevel: AttestationLevel` | `operator.attestation.level` MUST rank at or above the minimum (`registry_attested` > `signed` > `none`). |
| `requireDeploymentHistory` | `history.summary.totalDecisions` MUST be greater than 0. |
| `requireAuditAnchor` | `disclosure.auditAnchor` MUST be present. |
| `requireModelFingerprint` | A `model` identity MUST be present. |
| `allowedModelDigests: string[]` | `model.digest` MUST be in the allowed set (refuse if no model or not in set). |
| `requireProvenanceFor: string[]` | Each listed field MUST have a `provenance` entry. |
| `isRevoked(id)` | Refuse if the oracle reports `disclosureId` OR `agentId` revoked. |
| `operatorReputation(id)` + `minOperatorReputation` | The operator's reputation MUST be at or above the minimum. Enforced only when both the oracle and the minimum are supplied. |

`requireRedTeam` set with no attestation present is itself a failed check ("no red-team
attestation"). `now` (ISO-8601) is REQUIRED on the policy for the freshness check. The
revocation and reputation oracles are injected, so the verifier layer stays
vendor-neutral.

## The over-the-wire entry points

- `verifyAndEvaluate` parses an untrusted JSON envelope and evaluates it in one call; a
  parse failure yields an immediate `refuse` with check `schema: false`.
- `verifyCounterparty` (in `src/client.ts`) implements the full four-step loop: fetch the
  disclosure from the well-known URI, evaluate it against the policy, run the live
  handshake, and decide. Any failure on either the static or the live leg is a refuse, and
  the default posture is fail-closed.

```ts
const verdict = await verifyCounterparty(fetch, "https://agent.example", {
  now: new Date().toISOString(),
  requireEnforcedConstitution: true,
  requireNonCustodial: true,
  minRedTeamGrade: "B",
});

if (verdict.decision === "transact") {
  // proven: valid signature, fresh, policy met, live key possession
} else {
  verdict.reasons;   // every failed check, for transparency
}
```

The evaluation is cheap and deterministic, which is what lets it run before every
transaction rather than only on a sampled basis. The
[positioning](./positioning.md) chapter covers the economic argument for that in full.
