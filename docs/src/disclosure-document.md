# The Disclosure Document

The disclosure document is the signed content; the [signed envelope](./signing-and-identity.md)
wraps it with the signature. The reference type is `AgentDisclosureSchema` in
`src/schema.ts`. All fields are JSON. Hex fields match `^[0-9a-fA-F]+$`; ISO fields are
ISO-8601 timestamp strings.

The document is grouped into an envelope-meta block plus a set of field groups. Each group
maps to a surface a serious agent product already maintains, and each carries the threat
it makes legible.

## Envelope meta (document level)

These top-level fields establish identity, freshness, and tamper-evidence. They are the
always-clear fields a verifier needs before it looks at anything else.

| Field | Type | Req | Semantics |
|---|---|---|---|
| `version` | integer literal `1` | REQUIRED | Schema version; MUST equal `DISCLOSURE_SCHEMA_VERSION`. |
| `disclosureId` | string | REQUIRED | Unique id for this disclosure instance; used as a revocation key. |
| `agentId` | string | REQUIRED | The agent's stable id. By the binding rule it MUST equal the signing public key (hex). |
| `issuedAt` | ISO-8601 string | REQUIRED | When the disclosure was minted; lower bound of the freshness window. |
| `validUntil` | ISO-8601 string | REQUIRED | Expiry; upper bound of the freshness window. A verifier rejects an expired disclosure. |
| `nonce` | string | REQUIRED | A fresh, unguessable nonce per disclosure; paired with a handshake challenge for liveness. |
| `auditAnchor` | hex string | OPTIONAL | Binds the disclosure to the audit-chain head, so it cannot be retro-edited without breaking the link. |

## `systemPrompt` (REQUIRED)

A hash of the agent's composed system prompt, pinning the behavioural surface
(`SystemPromptFingerprintSchema`).

| Field | Type | Req | Semantics |
|---|---|---|---|
| `algorithm` | string literal `"sha256"` | REQUIRED | Digest algorithm. |
| `digest` | hex string | REQUIRED | sha256 of the canonical system prompt. |
| `promptVersion` | string | OPTIONAL | A human label for the prompt revision. |

Combined with the enforced constitution, a pinned prompt fingerprint raises the cost of a
prompt-injection-mediated substitution, because the disclosed prompt no longer matches the
running one.

## `constitution` (REQUIRED)

The structured, declared rules the agent operates under (`ConstitutionSchema`).

| Field | Type | Req | Semantics |
|---|---|---|---|
| `hardConstraints` | array of `HardConstraint` | REQUIRED | The hard deny-list: predicates over structured intent, not model text. |
| `parameters` | record of string to number/string/boolean | OPTIONAL | Declared gate parameters, for example minimum rationale length or velocity ceiling. |
| `digest` | hex string | REQUIRED | A digest of the canonical constitution, for binding and diffing. |
| `enforced` | boolean | REQUIRED | TRUE iff these constraints are enforced at runtime by a gate the agent cannot override. |
| `enforcementEvidence` | string | OPTIONAL | How `enforced` can be checked, for example a reference to the gate or audit. |

Each `HardConstraint` has `id` (string), `description` (string), and `kind` (one of
`deny`, `cap`, `velocity`, `rationale`, `scope`, `other`).

### The load-bearing field: `enforced`

The `enforced` flag is load-bearing. When `true`, the disclosed constitution **is** the
gate actually running, not a claim. This is the difference between a disclosure and a
promise. A verifier that sets `requireEnforcedConstitution: true` refuses any counterparty
whose constitution is declared-only. In the AgentWorth reference implementation the flag
is populated directly from the live deny-list and gate config, and `enforcementEvidence`
names the gate. This defends against constitution substitution via prompt injection
(threat 1).

## `tools` (REQUIRED)

The tool inventory and permission boundaries (`ToolInventorySchema`).

| Field | Type | Req | Semantics |
|---|---|---|---|
| `tools` | array of `Tool` | REQUIRED | The agent's tool surface. |
| `valuePath` | string | OPTIONAL | The single value-moving path, if the product funnels all spend through one. |

Each `Tool` has `name` (string), `description` (string, optional), `access` (one of
`gated` = passes the governance gate, `read_only` = no value movement, `operator_only` =
exists but is not reachable by the agent), and `movesValue` (boolean). This makes an
undisclosed value-moving capability legible.

## `capital` (REQUIRED)

The mandate set: scoped, capped, expiring spend authority (`CapitalEnvelopeSchema`). This
is the field no model's weights can tell you.

| Field | Type | Req | Semantics |
|---|---|---|---|
| `mandates` | array of `MandateDisclosure` | REQUIRED | The granted spend mandates. |
| `aggregatePerPeriodCapMinor` | non-negative integer | OPTIONAL | Aggregate ceiling across all mandates over the period, in minor units. |
| `custody` | enum `non_custodial` / `custodial` | REQUIRED | Custody model. |
| `riskModel` | object `{ name, version }` | OPTIONAL | Declared risk-classifier identity and version. |

Each `MandateDisclosure` has `label`, `scope` (what it can pay), `currency`,
`perTxCapMinor`, `perPeriodCapMinor`, `period` (one of `day`, `week`, `month`),
`allowedRails` (array of string), and `expiresAt` (ISO-8601). This makes unbounded or
unexpiring spend authority legible.

## `operator` (REQUIRED)

Operator identity and the deniability boundary (`OperatorIdentitySchema`).

| Field | Type | Req | Semantics |
|---|---|---|---|
| `operatorId` | string | REQUIRED | A stable identifier for the deploying party; MAY be pseudonymous. |
| `attestation` | object | REQUIRED | Identity-attestation evidence. |
| `deniabilityBoundary` | string | REQUIRED | Explicit statement of what the operator is and is NOT accountable for. |

`attestation` has `scheme`, `level` (one of `none`, `signed`, `registry_attested`), and
`evidence` (optional). The `deniabilityBoundary` is load-bearing for the regulated-rails
argument: it is the operator's explicit accountability statement.

`scheme` is **a known value OR a reverse-domain id**: the known values are `AIP`,
`VisaTAP`, `ERC8004`, `DID`, `none`; any other value MUST be a reverse-domain namespace
(matching `^[a-z0-9]+(\.[a-z0-9-]+)+$`, e.g. `com.visa.tap`), so a new attestation scheme
is a vendor-namespace publication rather than a core enum edit and a five-language re-port.
A bare unknown word (no dot) is rejected at validation; a verifier acts only on schemes it
recognizes.

## `history` (REQUIRED)

Cumulative deployment history, derived from a tamper-evident hash-linked audit chain
(`DeploymentHistorySchema`).

| Field | Type | Req | Semantics |
|---|---|---|---|
| `chainAnchor` | hex string | REQUIRED | Head hash of the signed audit chain this summary is computed from. |
| `summary` | object | REQUIRED | The aggregate record. |
| `verificationHint` | string | OPTIONAL | How the chain can be independently verified. |

`summary` has `totalDecisions`, `settledCount`, `blockedCount` (all non-negative
integers), and `firstSeen`, `lastActive` (optional ISO-8601). Because every audit entry
commits to the previous entry's hash, the summary cannot claim numbers the chain does not
support without breaking the recomputed link. This makes deployment-history forgery
legible.

## `redTeam` (OPTIONAL)

Red-team pass/fail attestation against a public adversarial corpus, so the agent cannot
grade itself on a private rubric (`RedTeamAttestationSchema`).

| Field | Type | Req | Semantics |
|---|---|---|---|
| `corpus` | object `{ name, version }` | REQUIRED | The versioned public corpus the agent was scored against. |
| `result` | object | REQUIRED | The graded outcome. |
| `attestedAt` | ISO-8601 string | REQUIRED | When the attestation was produced. |
| `attestationRef` | string | OPTIONAL | A signed reference, or where the run can be re-verified. |

`result` has `grade` (one of `A`, `B`, `C`, `D`, `F`), `score` (number in `[0, 100]`),
`passed` (boolean), and `hardFails` (array of string, defaults to `[]`). A single
catastrophic behaviour belongs in `hardFails` regardless of an otherwise clean score.

## `model` (OPTIONAL)

A fingerprint of the model the agent declares it runs on (`ModelIdentitySchema`).

| Field | Type | Req | Semantics |
|---|---|---|---|
| `name` | string | REQUIRED | Declared model name. |
| `fingerprintAlgorithm` | string literal `"sha256"` | REQUIRED | Digest algorithm. |
| `digest` | hex string | REQUIRED | sha256 of a declared model identifier or weights manifest. |

This is the cheap declarable half only. Cryptographically proving the running model
matches the declaration at transact-time needs hardware (TEE) attestation, the honest open
item. The field is versioned so a hardware-attested successor can supersede it without a
breaking change.

## `provenance` (OPTIONAL)

A record keyed by top-level field name, each value a `FieldProvenance` with `derivedFrom`
(string, for example `agentworth-gate` or `audit-chain`) and `attestedBy` (optional).
This lets a verifier weight claims: a field bound to an enforced gate is worth more than a
self-asserted one. A verifier MAY require provenance for named fields.

## `extensions` (OPTIONAL)

A top-level record keyed by reverse-domain id (matching the namespace regex above), each
value an arbitrary JSON value. This is the namespaced extension bucket: a vendor can add a
field under `com.vendor.feature` without a core spec change or a five-language validator
re-port. A verifier acts only on extension keys it recognizes; unknown extensions are
carried and ignored. Extensions canonicalize like any other field, so they are covered by
the signature, and an absent `extensions` field canonicalizes away (minor-version-safe).

## Structural validation

A verifier MUST structurally validate an untrusted document against the schema before
trusting any field (`parseDisclosure` / `parseSignedDisclosure`). A malformed envelope is
a refuse with no further checks.
