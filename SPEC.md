# Agent Disclosure Protocol (ADP) Specification

## 1. Status and version

This document is the normative protocol specification for the **Agent Disclosure
Protocol (ADP)**, the wire format for Verifiable Agency: a disclosure protocol for
agent-to-agent commerce. It defines the on-wire data
structures, the canonicalization and signing algorithm, the verification handshake,
the counterparty policy semantics, selective disclosure, revocation, and a
transparency log, in sufficient detail that an independent team can implement an
interoperable emitter and verifier from this document alone.

- Specification version: 1
- Disclosure schema version: `DISCLOSURE_SCHEMA_VERSION = 1`. Every disclosure
  document MUST carry `version: 1`. This integer is bumped only on a breaking change
  to the disclosure structure.

The reference implementation is the `agent-disclosure` source tree (`src/schema.ts`,
`src/attestation.ts`, `src/handshake.ts`, `src/verify.ts`, `src/redaction.ts`,
`src/revocation.ts`, `src/transparency.ts`). Where this document states a rule it
cites the function or field that implements it. For positioning and the trust model
see `README.md`; for the attack-by-attack analysis see `THREAT_MODEL.md`. This
document does not restate either.

### Key words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

## 2. Overview

ADP is a disclose-before-settle protocol. Before an agent transacts, it
exposes a signed disclosure document: the rules it runs under, the capital envelope it
operates inside, who deployed it, what it has done, the model it declares, and how the
whole document was signed. A counterparty fetches that disclosure, evaluates it against
its own policy, optionally runs a live challenge-response handshake to prove the
counterparty holds the signing key right now, and only then decides to transact or
refuse. The decision happens before value moves, not after a loss. The default posture
is fail-closed: a disclosure that fails policy, has expired, is unreachable, or fails
the liveness handshake all resolve to refuse.

The protocol uses asymmetric (ed25519) signatures, so a counterparty verifies a
disclosure with no shared secret and no prior relationship. The signer holds a private
key; the matching public key travels in the envelope and, by convention, IS the agent's
identity (`agentId`). Anyone can check the claim, not just the party that issued it. See
`README.md` for the full positioning, the disclose-before-settle loop, and the
relationship to ERC-8004.

## 3. The disclosure document

The disclosure document is the signed CONTENT; the envelope (Section 3.13) wraps it
with the signature. The reference type is `AgentDisclosureSchema` in `src/schema.ts`.
All fields are JSON. Hex fields are lowercase-or-uppercase hexadecimal strings matching
`^[0-9a-fA-F]+$`. ISO fields are ISO-8601 timestamp strings.

### 3.1 Envelope meta (document level)

These top-level fields establish identity, freshness, and tamper-evidence. They are the
always-clear fields a verifier needs before it looks at anything else (see also the
selective-disclosure meta in Section 9).

| Field | Type | Req | Semantics | Threat addressed |
|---|---|---|---|---|
| `version` | integer literal `1` | REQUIRED | Schema version; MUST equal `DISCLOSURE_SCHEMA_VERSION`. | Structural drift between implementations. |
| `disclosureId` | string | REQUIRED | Unique id for this disclosure instance. Used as a revocation key. | Document-level revocation. |
| `agentId` | string | REQUIRED | The agent's stable id. By binding rule (Section 5) it MUST equal the signing public key (hex). | Identity binding; impersonation. |
| `issuedAt` | ISO-8601 string | REQUIRED | When the disclosure was minted. Lower bound of the freshness window. | Stale-disclosure presentation. |
| `validUntil` | ISO-8601 string | REQUIRED | Expiry. Upper bound of the freshness window. A verifier rejects an expired disclosure. | Stale-disclosure presentation. |
| `nonce` | string | REQUIRED | A fresh, unguessable nonce per disclosure; paired with a handshake challenge for liveness. | Replay. |
| `auditAnchor` | hex string | OPTIONAL | Binds the disclosure to a tamper-evident anchor (the audit-chain head), so it cannot be retro-edited without breaking the link. | Post-hoc rewriting. |

### 3.2 `systemPrompt` (REQUIRED) - `SystemPromptFingerprintSchema`

A hash of the agent's composed system prompt, pinning the behavioural surface.

| Field | Type | Req | Semantics |
|---|---|---|---|
| `algorithm` | string literal `"sha256"` | REQUIRED | Digest algorithm. |
| `digest` | hex string | REQUIRED | sha256 of the canonical system prompt. |
| `promptVersion` | string | OPTIONAL | A human label for the prompt revision. |

Threat: combined with the enforced constitution, a pinned prompt fingerprint raises the
cost of a prompt-injection-mediated substitution, because the disclosed prompt no longer
matches the running one.

### 3.3 `constitution` (REQUIRED) - `ConstitutionSchema`

The structured, declared rules the agent operates under.

| Field | Type | Req | Semantics |
|---|---|---|---|
| `hardConstraints` | array of `HardConstraint` | REQUIRED | The hard deny-list: predicates over structured intent, not model text. |
| `parameters` | record of string to (number\|string\|boolean) | OPTIONAL | Declared gate parameters, for example minimum rationale length or velocity ceiling. |
| `digest` | hex string | REQUIRED | A digest of the canonical constitution, for binding and diffing. |
| `enforced` | boolean | REQUIRED | TRUE iff these constraints are enforced at runtime by a gate the agent cannot override. |
| `enforcementEvidence` | string | OPTIONAL | How `enforced` can be checked, for example a reference to the gate or audit. |

Each `HardConstraint` (`HardConstraintSchema`) is an object with: `id` (string,
REQUIRED), `description` (string, REQUIRED), and `kind` (REQUIRED enum, one of `"deny"`,
`"cap"`, `"velocity"`, `"rationale"`, `"scope"`, `"other"`).

The `enforced` flag is load-bearing. When `true` the disclosed constitution IS the gate
actually running, not a claim. This is the difference between a disclosure and a promise.
A verifier that sets `requireEnforcedConstitution: true` (Section 8) refuses any
counterparty whose constitution is declared-only. Threat: constitution substitution via
prompt injection. See `README.md` ("The killer differentiator: `enforced`") and
`THREAT_MODEL.md` attack 1.

### 3.4 `tools` (REQUIRED) - `ToolInventorySchema`

The tool inventory and permission boundaries.

| Field | Type | Req | Semantics |
|---|---|---|---|
| `tools` | array of `Tool` | REQUIRED | The agent's tool surface. |
| `valuePath` | string | OPTIONAL | The single value-moving path, if the product funnels all spend through one. |

Each `Tool` (`ToolSchema`) has: `name` (string, REQUIRED), `description` (string,
OPTIONAL), `access` (REQUIRED enum, one of `"gated"` = passes the governance gate,
`"read_only"` = no value movement, `"operator_only"` = exists but is not reachable by
the agent), and `movesValue` (boolean, REQUIRED). Threat: an undisclosed value-moving
capability.

### 3.5 `capital` (REQUIRED) - `CapitalEnvelopeSchema`

The mandate set: scoped, capped, expiring spend authority. This is the field no model's
weights can tell you - the capital envelope the agent operates inside.

| Field | Type | Req | Semantics |
|---|---|---|---|
| `mandates` | array of `MandateDisclosure` | REQUIRED | The granted spend mandates. |
| `aggregatePerPeriodCapMinor` | non-negative integer | OPTIONAL | Aggregate ceiling across all mandates over the stated period, in minor units. |
| `custody` | enum `"non_custodial"` \| `"custodial"` | REQUIRED | Custody model. |
| `riskModel` | object `{ name: string, version: string }` | OPTIONAL | Declared risk-classifier identity and version. |

Each `MandateDisclosure` (`MandateDisclosureSchema`) has: `label` (string, REQUIRED),
`scope` (string, REQUIRED, what it can pay), `currency` (string, REQUIRED),
`perTxCapMinor` (non-negative integer, REQUIRED), `perPeriodCapMinor` (non-negative
integer, REQUIRED), `period` (REQUIRED enum, one of `"day"`, `"week"`, `"month"`),
`allowedRails` (array of string, REQUIRED), and `expiresAt` (ISO-8601, REQUIRED).
Threat: unbounded or unexpiring spend authority.

### 3.6 `operator` (REQUIRED) - `OperatorIdentitySchema`

Operator identity and the deniability boundary.

| Field | Type | Req | Semantics |
|---|---|---|---|
| `operatorId` | string | REQUIRED | A stable identifier for the deploying party; MAY be pseudonymous. |
| `attestation` | object (below) | REQUIRED | Identity-attestation evidence. |
| `deniabilityBoundary` | string | REQUIRED | Explicit statement of what the operator is and is NOT accountable for. |

`attestation` has: `scheme` (REQUIRED enum, one of `"AIP"`, `"VisaTAP"`, `"ERC8004"`,
`"none"`), `level` (REQUIRED enum, one of `"none"`, `"signed"`, `"registry_attested"`),
and `evidence` (string, OPTIONAL). The `deniabilityBoundary` is REQUIRED and load-bearing
for the regulated-rails argument: it is the operator's explicit accountability statement.
Threat: operator collusion / sock-puppets, and unaccountable deployment. See
`THREAT_MODEL.md` attack 6.

### 3.7 `history` (REQUIRED) - `DeploymentHistorySchema`

Cumulative deployment history, derived from a tamper-evident hash-linked audit chain.

| Field | Type | Req | Semantics |
|---|---|---|---|
| `chainAnchor` | hex string | REQUIRED | Head hash of the signed audit chain this summary is computed from. |
| `summary` | object (below) | REQUIRED | The aggregate record. |
| `verificationHint` | string | OPTIONAL | How the chain can be independently verified. |

`summary` has: `totalDecisions`, `settledCount`, `blockedCount` (all REQUIRED
non-negative integers), and `firstSeen`, `lastActive` (both OPTIONAL ISO-8601). The
`chainAnchor` lets a counterparty verify the summary against the real history rather than
trust it: because every audit entry commits to the previous entry's hash, the summary
cannot claim numbers the chain does not support without breaking the recomputed link.
Threat: deployment-history forgery. See `THREAT_MODEL.md` attack 2.

### 3.8 `redTeam` (OPTIONAL) - `RedTeamAttestationSchema`

Red-team pass/fail attestation against a public adversarial corpus, so the agent cannot
grade itself on a private rubric.

| Field | Type | Req | Semantics |
|---|---|---|---|
| `corpus` | object `{ name: string, version: string }` | REQUIRED | The versioned public corpus the agent was scored against. |
| `result` | object (below) | REQUIRED | The graded outcome. |
| `attestedAt` | ISO-8601 string | REQUIRED | When the attestation was produced. |
| `attestationRef` | string | OPTIONAL | A signed reference / where the run can be re-verified. |

`result` has: `grade` (REQUIRED enum, one of `"A"`, `"B"`, `"C"`, `"D"`, `"F"`), `score`
(REQUIRED number in `[0, 100]`), `passed` (boolean, REQUIRED), and `hardFails` (array of
string, defaults to `[]`). A single catastrophic behaviour belongs in `hardFails`
regardless of an otherwise clean score. Threat: self-grading on a private rubric. See
`THREAT_MODEL.md` attack 8.

### 3.9 `model` (OPTIONAL) - `ModelIdentitySchema`

A fingerprint of the model the agent declares it runs on - the declarable half of the
model-swap defense.

| Field | Type | Req | Semantics |
|---|---|---|---|
| `name` | string | REQUIRED | Declared model name. |
| `fingerprintAlgorithm` | string literal `"sha256"` | REQUIRED | Digest algorithm. |
| `digest` | hex string | REQUIRED | sha256 of a declared model identifier or weights manifest. |

This is the cheap declarable half only. Cryptographically proving the running model
matches the declaration at transact-time needs hardware (TEE) attestation, the honest
open item. Threat: model swap. See `THREAT_MODEL.md` attack 7.

### 3.10 `provenance` (OPTIONAL)

A record keyed by top-level field name (for example `"constitution"`, `"history"`),
each value a `FieldProvenance` (`FieldProvenanceSchema`): `derivedFrom` (string,
REQUIRED, for example `"opensolvency-gate"`, `"audit-chain"`) and `attestedBy` (string,
OPTIONAL). This lets a verifier WEIGHT claims: a field bound to an enforced gate is worth
more than a self-asserted one. A verifier MAY require provenance for named fields via
`requireProvenanceFor` (Section 8).

### 3.11 Structural validation

A verifier MUST structurally validate an untrusted document against the schema before
trusting any field (`parseDisclosure` / `parseSignedDisclosure` in `src/schema.ts`). A
malformed envelope is a refuse with no further checks (`verifyAndEvaluate` in
`src/verify.ts`).

### 3.12 The signed envelope - `SignedDisclosureSchema`

The envelope wraps the disclosure document with an ed25519 signature.

```
{
  "disclosure": <AgentDisclosure>,
  "signature": {
    "algorithm": "ed25519",
    "publicKey": <hex>,   // the signer's raw 32-byte public key, = agentId's key material
    "value":     <hex>    // ed25519 signature over canonicalize(disclosure)
  }
}
```

`algorithm` MUST be the literal `"ed25519"`. `publicKey` is the signer's raw 32-byte
ed25519 public key as hex. `value` is the signature over the canonical bytes of the
disclosure document (Section 4), as hex. See `signDisclosure` in `src/attestation.ts`.

## 4. Canonicalization

Signing and digesting operate over a canonical byte string, not over arbitrary JSON
whitespace or key order. Every implementation MUST reproduce the exact algorithm of
`canonicalize` in `src/attestation.ts`. This is the interoperability crux: two
implementations that canonicalize identically produce verifiable signatures across
vendor boundaries.

ADP canonicalization is **RFC 8785 (JSON Canonicalization Scheme, JCS)** over ADP's
value domain: sorted object keys by UTF-16 code unit, ECMAScript `Number::toString`
number formatting, JSON string escaping, no insignificant whitespace, UTF-8 output. For
every value an ADP disclosure can carry, the algorithm below emits byte-identical output
to a conformant JCS implementation. ADP adds two profile rules JCS does not legislate
(it canonicalizes already-parsed JSON; ADP canonicalizes in-memory documents):

- **`undefined`-valued object keys are dropped** (equivalent to never having been
  present). An absent optional field and one set to `undefined` MUST canonicalize
  identically. JSON `null` is NOT dropped.
- **The input MUST NOT contain `NaN` or `Infinity`** (not representable in JSON).

Implementers porting to another language MUST satisfy JCS exactly — in particular the
**UTF-16 code-unit** key sort (NOT Unicode code point, NOT UTF-8 byte order: a
supplementary-plane key such as an emoji sorts before a BMP key like `U+FB33` because its
lead surrogate `D83D` is the smaller code unit) and ECMAScript number formatting. The
conformance vectors in `conformance/vectors.json` include a non-ASCII key-sort case that
a code-point- or byte-sorting port will fail. ADP carries no exponential-range doubles,
so no Ryu/exotic-float corner is exercised; numeric fields are integers or short decimals.

### 4.1 Algorithm

`canonicalize(value)` returns a string, defined recursively:

1. If `value` is `null`, or is not of type object (that is, a string, number, or
   boolean primitive), return `JSON.stringify(value)`. This means:
   - strings are emitted as JSON string literals (quoted, with JSON escaping),
   - numbers are emitted in their JSON form,
   - booleans are emitted as `true` / `false`,
   - `null` is emitted as `null`.
2. If `value` is an array, return `"[" + value.map(canonicalize).join(",") + "]"`.
   Array order is PRESERVED. Array elements are never sorted or filtered (an
   `undefined` element, if one occurs, stringifies as `null` per step 1, matching
   `JSON.stringify`).
3. Otherwise `value` is an object. Take its keys, sort them lexicographically
   (ascending, by UTF-16 code unit, the default JavaScript string sort), DROP every key
   whose value is `undefined`, then for each surviving key `k` emit
   `JSON.stringify(k) + ":" + canonicalize(value[k])`. Join the pieces with `","` and
   wrap in `"{" ... "}"`.

Notes for implementers in other languages:

- "Drop undefined" applies to OBJECT VALUES. JSON has no `undefined`, so in a strict
  JSON pipeline this rule only ever fires when serializing an in-memory document that
  carries optional fields left unset. An optional field that is absent and an optional
  field set to `undefined` MUST canonicalize identically (both produce no key). A field
  explicitly set to JSON `null` is NOT dropped; it is emitted as `null`.
- Key sort is over the raw key strings, ascending. There is no normalization of the
  key strings beyond JSON string escaping at emit time.
- No insignificant whitespace is ever emitted. The output is a compact string.
- Number formatting follows the host JSON serializer; implementations SHOULD restrict
  numeric fields to integers and exactly-representable values to avoid cross-language
  float-formatting divergence. The schema's count and cap fields are all integers.

### 4.2 Worked examples

Each line is `input` then the exact canonical output string. An implementation MUST
reproduce these byte for byte.

Example 1 - object key sort:

```
input:  { "b": 1, "a": 2 }
output: {"a":2,"b":1}
```

Example 2 - recursive sort, preserved array order, dropped undefined value:

```
input:  { "z": [3, 1, 2], "a": { "d": undefined, "c": "x" } }
output: {"a":{"c":"x"},"z":[3,1,2]}
```

(The array `[3,1,2]` keeps its order; the key `d` is dropped because its value is
`undefined`; the keys `a` and `z` are sorted.)

Example 3 - the handshake response body, with a trailing `undefined` verifierId
dropped (Section 7):

```
input:  { "nonce": "ab12", "agentId": "ff00", "auditHead": "deadbeef",
          "signedAt": "2026-06-24T10:00:00Z", "verifierId": undefined }
output: {"agentId":"ff00","auditHead":"deadbeef","nonce":"ab12","signedAt":"2026-06-24T10:00:00Z"}
```

Example 4 - a bare primitive and an array of objects with an interleaved null:

```
input:  "hi"
output: "hi"

input:  [ { "b": 2, "a": 1 }, null ]
output: [{"a":1,"b":2},null]
```

## 5. Signing and identity

Signatures are ed25519 over the UTF-8 bytes of the canonical string.

- To sign a disclosure: compute `canonicalize(disclosure)`, encode as UTF-8, ed25519-sign
  with the agent's private key, and place the hex signature in `signature.value`
  (`signDisclosure`, `signMessage`).
- The envelope's `signature.publicKey` is the signer's raw 32-byte ed25519 public key,
  hex-encoded.
- **Identity binding (MUST).** A disclosure MUST be signed by the key it claims as its
  identity: `disclosure.agentId` MUST equal `signature.publicKey`. A verifier MUST reject
  a disclosure where they differ, before checking the signature value
  (`verifyDisclosureSignature` in `src/attestation.ts`: it returns failure with reason
  "agentId does not match the signing public key" when `agentId !== publicKey`). The same
  binding is enforced for redacted views (Section 9) and is the convention by which the
  public key IS the agent's identity.
- Signature verification verifies the hex signature over `canonicalize(disclosure)`
  against the 32-byte public key. A mismatch is a refuse.

Informative (key import): the reference imports a bare 32-byte ed25519 public key by
prepending the SPKI DER prefix `302a300506032b6570032100` and importing as SPKI DER;
private keys are persisted as PKCS8 DER hex (`publicKeyFromHex`, `exportAgentKey`,
`agentKeyFromPrivateHex`). These are encoding conventions of the reference runtime and
do not affect the on-wire form, which is always the raw 32-byte public key as hex and the
raw signature as hex. An implementation MAY use any ed25519 library that produces and
verifies standard ed25519 signatures over the canonical UTF-8 bytes.

## 6. Freshness

A disclosure is valid only within its `[issuedAt, validUntil]` window. A verifier MUST
reject a disclosure outside the window (`isFresh` in `src/attestation.ts`).

The comparison is `now >= issuedAt && now <= validUntil`, performed as ISO-8601 LEXICAL
(string) comparison. ISO-8601 timestamps in a fixed, zero-padded, same-zone form sort
lexically in chronological order, so string comparison is correct. Emitters MUST therefore
produce timestamps in a consistent, zero-padded ISO-8601 form (and SHOULD use UTC `Z`) so
that lexical order equals chronological order. `now` is the verifier's clock; clock skew
between parties moves the window edges and is an acknowledged residual gap
(`THREAT_MODEL.md` attack 4).

## 7. The verification handshake

The handshake is a live challenge-response proving the counterparty holds the signing key
RIGHT NOW and that its audit head is current. A static signed disclosure cannot prove
either. Reference: `src/handshake.ts`.

### 7.1 Challenge message

The verifier issues a `Challenge` (`createChallenge`):

```
{
  "nonce":      <string>,   // fresh, unguessable; reference uses 16 random bytes hex
  "issuedAt":   <ISO-8601>,
  "verifierId": <string>    // OPTIONAL; binds the proof to a specific verifier exchange
}
```

The nonce MUST be fresh and unguessable per challenge (`randomNonce`).

### 7.2 ChallengeResponse message

The agent answers with a `ChallengeResponse` (`respondToChallenge`):

```
{
  "nonce":     <string>,   // echoes the challenge nonce
  "agentId":   <string>,   // the responding agent's ed25519 public key (hex)
  "auditHead": <string>,   // the agent's audit-chain head at response time
  "signedAt":  <ISO-8601>,
  "signature": <hex>       // ed25519 over the canonical response body (below)
}
```

### 7.3 Signed bytes

The signature is over the canonical bytes of the body, with the challenge's `verifierId`
folded in (`responseMessage`):

```
canonicalize({ nonce, agentId, auditHead, signedAt, verifierId })
```

where `nonce`, `agentId`, `auditHead`, `signedAt` come from the response and `verifierId`
comes from the challenge. When `verifierId` is absent it is `undefined` and is therefore
dropped by canonicalization (Section 4, Example 3), so both sides reconstruct identical
bytes whether or not a verifier id is in play. Both sides MUST construct this message
identically.

### 7.4 Verifier MUST-checks

`verifyChallengeResponse` takes the response, the original challenge, and a
`HandshakePolicy` (`expectedAgentId`, optional `disclosureAnchor`, optional `now`,
optional `maxAgeMs` defaulting to 60000). A verifier MUST check, in order:

1. **Nonce match.** `response.nonce` MUST equal `challenge.nonce`. A mismatch is a refuse
   ("replayed or wrong challenge"). Defeats identity replay.
2. **AgentId match.** `response.agentId` MUST equal `policy.expectedAgentId` (the agentId
   the disclosure claims). A mismatch is a refuse.
3. **Signature.** The ed25519 signature MUST verify over the Section 7.3 canonical bytes
   against `response.agentId`. A failure is a refuse ("no live key possession").
4. **Freshness.** When `policy.now` is supplied, `Date.parse(now) - Date.parse(signedAt)`
   MUST be `>= 0` and `<= maxAgeMs` (default 60000 ms). Outside that range is a refuse
   ("stale").
5. **Audit-head currency.** The bound `auditHead` is checked against the disclosure's
   anchor. An exact match means the disclosure is current as of the live head. A
   regression to an OLDER anchor is a red flag; equality or a newer/different head is
   acceptable (the verifier cannot fully order the chain without it). The reference
   treats this as a non-fatal signal and returns ok; a stricter verifier MAY refuse on a
   detected regression.

## 8. Counterparty policy and verdict

A verifier evaluates a signed disclosure against its own `VerificationPolicy` and gets a
deterministic `transact` / `refuse` verdict with a per-check breakdown
(`evaluateDisclosure` in `src/verify.ts`). The evaluation is deterministic and cheap by
design; the verdict carries a `cost` instrument (`checksRun`, `wallMicros`).

A verifier MUST refuse when any enabled predicate fails. The verdict's `decision` is
`transact` only when zero reasons accumulated; otherwise `refuse`. Every failed check is
reported (the verdict does not short-circuit on the first failure for reporting purposes,
though it refuses if any failed).

**Baseline (an empty policy).** With no requirements set, only two predicates run, both
default-ON:

- `requireValidSignature` (default true): the ed25519 signature MUST verify and the
  agentId-to-key binding MUST hold (Section 5).
- `requireFresh` (default true): the disclosure MUST be within `[issuedAt, validUntil]`
  against `policy.now` (Section 6).

An empty policy therefore checks ONLY signature and freshness. Either can be disabled by
setting it to `false`.

**Opt-in predicates.** Every other field is optional and enforced only when set:

| Policy field | Predicate (refuse when it fails) |
|---|---|
| `requireEnforcedConstitution` | `constitution.enforced` MUST be true. |
| `requiredHardConstraints: string[]` | Every listed hard-constraint id MUST be present in `constitution.hardConstraints`. |
| `requireRedTeam` | A `redTeam` attestation MUST be present. |
| `minRedTeamGrade: Grade` | `redTeam.result.grade` MUST rank at or above the minimum (A>B>C>D>F). Evaluated only when a `redTeam` attestation is present. |
| `maxRedTeamHardFails` (default 0) | `redTeam.result.hardFails.length` MUST be at most the max. Evaluated when a `redTeam` attestation is present. |
| `requireNonCustodial` | `capital.custody` MUST equal `"non_custodial"`. |
| `minAttestationLevel: AttestationLevel` | `operator.attestation.level` MUST rank at or above the minimum (`registry_attested` > `signed` > `none`). |
| `requireDeploymentHistory` | `history.summary.totalDecisions` MUST be greater than 0. |
| `requireAuditAnchor` | `disclosure.auditAnchor` MUST be present. |
| `requireModelFingerprint` | A `model` identity MUST be present. |
| `allowedModelDigests: string[]` | `model.digest` MUST be in the allowed set (refuse if no model or not in set). |
| `requireProvenanceFor: string[]` | Each listed field MUST have a `provenance` entry. |
| `isRevoked(id)` | Refuse if the oracle reports `disclosureId` OR `agentId` revoked (Section 10). |
| `operatorReputation(id)` + `minOperatorReputation` | The operator's reputation MUST be at or above the minimum. Enforced only when both the oracle and the minimum are supplied. |

`requireRedTeam` set with no attestation present is itself a failed check
("no red-team attestation"). `now` (ISO-8601) is REQUIRED on the policy for the freshness
check. The revocation and reputation oracles are injected so the verifier layer stays
vendor-neutral.

The convenience entry point `verifyAndEvaluate` parses an untrusted JSON envelope and
evaluates it in one call; a parse failure yields an immediate `refuse` with check
`schema: false`.

## 9. Selective disclosure

An agent MAY commit to its fields and later reveal only a subset, without breaking the
signature, via salted hash commitments (`src/redaction.ts`). This serves privacy and the
operator's deniability boundary.

**Always-clear meta.** The identity/freshness fields (`version`, `disclosureId`,
`agentId`, `issuedAt`, `validUntil`, `nonce`, `auditAnchor`) are carried in clear in the
`meta` block; a verifier needs identity and freshness before deciding whether to look at
the rest.

**Redactable fields.** The following MAY be withheld: `systemPrompt`, `constitution`,
`tools`, `capital`, `operator`, `history`, `redTeam`, `model`, `provenance`
(`REDACTABLE_FIELDS`).

**Commitment scheme.** For each present redactable field, the emitter draws a fresh
per-field salt (reference: 16 random bytes hex) and computes the commitment:

```
commitment(field) = sha256Hex( canonicalize(value) + ":" + salt )
```

(function `commit`). The salt is per-field, so revealing one field leaks nothing about
another, and the salt prevents a verifier from brute-forcing a low-entropy value out of
its commitment. The emitter then signs over the COMMITMENT SET plus the meta:

```
signature.value = ed25519( canonicalize({ meta, commitments }) )
```

(`prepareRedactable`). The holder retains the cleartext `fields` and `salts` and never
ships them; it ships a `RedactedView` containing `meta`, all `commitments`, the
`signature`, and a `revealed` map of only the disclosed fields, each as
`{ value, salt }` (`reveal`).

**Verifier checks (`verifyRedacted`), all MUST:**

1. `meta.agentId` MUST equal `signature.publicKey` (identity binding, Section 5).
2. The signature MUST verify over `canonicalize({ meta, commitments })`. No field can be
   added, removed, or edited without breaking it.
3. For each revealed field, `commit(value, salt)` MUST recompute to the field's committed
   value. A mismatch, or a revealed field with no commitment, fails the whole view.

The result names exactly the fields whose disclosure is cryptographically proven.

**Privacy property.** A withheld field is present only as an opaque, salted commitment:
it is binding (the agent cannot later open it to a different value) and hiding (the
verifier learns nothing about the value, and cannot brute-force it, without the salt).
Revealing a subset proves those fields against the same single signature that covers the
whole commitment set.

## 10. Revocation and transparency

### 10.1 Revocation

A disclosure, or the agent behind it, can be revoked: a compromised key, a decommissioned
agent, a rotated identity (`src/revocation.ts`). A verifier fetches a portable status
list and refuses any revoked id, as a CRL/OCSP list gates a certificate.

- The status list (`RevocationList`) is keyed by string id. The id MAY be a `disclosureId`
  (revoke one document) or an `agentId` (revoke the whole agent). It is portable
  (`toJSON` / `fromJSON`) and exposes `isRevoked(id)` and `status(id)`. A verifier wires
  it into policy as the `isRevoked` oracle (Section 8).
- A revocation SHOULD be signed so it is attributable to the issuing key and a third party
  cannot forge a denial-of-service revocation. A `SignedRevocation` carries
  `{ id, reason, revokedAt, publicKey, signature }`, where the signature is over
  `canonicalize({ id, reason, revokedAt })` (`signRevocation`). A verifier verifies it
  against the embedded public key (`verifyRevocation`).

### 10.2 Transparency log

The transparency log is Certificate-Transparency-for-agents: an append-only,
hash-linked log of disclosure digests, so re-issuance under the same identity is publicly
visible (`src/transparency.ts`).

Each `TransparencyLogEntry` is
`{ index, disclosureDigest, agentId, issuedAt, prevHash, hash }`. On append
(`TransparencyLog.append`):

- `index` is the 0-based position.
- `prevHash` is the previous entry's `hash`, or the GENESIS value for index 0.
- `disclosureDigest = sha256Hex(canonicalize(signed.disclosure))` - the digest commits
  to the DOCUMENT, not the signature, so a content change yields a new digest and
  re-issuance under a fresh signature with the same content is detectable.
- `hash = sha256Hex(canonicalize({ index, disclosureDigest, agentId, issuedAt, prevHash }))`.

The GENESIS previous-hash is `"0".repeat(64)` (64 zero hex characters). The head is the
last entry's `hash`, or GENESIS when empty. `verify()` recomputes the whole chain: for
each entry the stored `prevHash` MUST equal the running previous hash and the stored
`hash` MUST recompute from the entry's own fields; any post-hoc edit, insertion, or
deletion breaks the chain and is reported as `brokenAt: index`. `contains(digest)` and
`inclusionProof(index)` provide membership checks. An implementation MUST reproduce the
GENESIS value and the `hash` preimage exactly for cross-implementation log compatibility.

## 11. Conformance

A conformant implementation MUST satisfy the runnable conformance suite under
`conformance/`, which carries (a) canonicalization vectors and (b) behavioural checks.
Specifically, a conformant implementation:

- MUST reproduce every canonicalization vector byte for byte, including the Section 4.2
  worked examples (object key sort, recursive sort, preserved array order, dropped
  `undefined` values, and the handshake-body absent-`verifierId` case).
- MUST produce ed25519 signatures over the canonical UTF-8 bytes that the reference
  verifier accepts, and MUST verify reference-produced signatures.
- MUST enforce the agentId-to-key binding (Section 5), the freshness window (Section 6),
  the handshake MUST-checks (Section 7.4), and the policy semantics including the
  empty-policy baseline (Section 8).
- MUST reproduce the selective-disclosure commitment and verification (Section 9), the
  signed-revocation preimage (Section 10.1), and the transparency-log GENESIS value and
  `hash` preimage (Section 10.2).

An emitter and a verifier from independent teams are interoperable when both pass the
suite: the canonicalization vectors guarantee identical signed bytes, and the behavioural
checks guarantee identical accept/refuse decisions.

## 12. Security considerations

The protocol makes a fixed set of attacks legible and pairs each with a concrete
defending module or field, and states the residual gap for each honestly: constitution
substitution (the `enforced` binding), deployment-history forgery (audit-chain anchor),
identity replay (the live handshake), stale presentation (freshness window plus nonce
plus audit-head currency), post-hoc rewriting (signature plus audit anchor plus
transparency log), operator collusion (operator attestation plus the deny-list floor),
model swap (declared fingerprint, TEE attestation being the open item), self-grading
(public corpus), and verification-cost DoS (deterministic, cacheable, tiered
verification). The full attack-by-attack analysis, including every residual gap, is in
`THREAT_MODEL.md` and is normative context for any deployment. Implementers MUST treat
the default posture as fail-closed: any unverifiable, expired, unreachable, or
policy-failing disclosure resolves to refuse.

## 13. IANA and well-known URI (informational)

This section is informational. The disclosure is served from a well-known URI on the
agent's own origin, so a verifier that can resolve a counterparty's base URL can fetch
its commitments with no registry or out-of-band exchange:

- Discovery: `GET <base>/.well-known/agent-disclosure` returns the signed disclosure
  envelope (`SignedDisclosure`). A non-200 response or a parse failure is a refuse.
- Live handshake: `POST <base>/agent-disclosure/respond` accepts a `Challenge` and
  returns a `ChallengeResponse` (Section 7).

These paths are the reference discovery transport (`src/client.ts`); registration of
`agent-disclosure` as a well-known URI suffix is left to a future submission. Until then,
implementers SHOULD use these paths for interoperability.
