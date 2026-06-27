# Agent Disclosure Protocol (ADP) Specification

## 1. Status and version

This document is the normative protocol specification for the **Agent Disclosure
Protocol (ADP)**, the wire format for Verifiable Agency: a disclosure protocol for
agent-to-agent commerce. It defines the on-wire data
structures, the canonicalization and signing algorithm, the verification handshake,
the counterparty policy semantics, selective disclosure, revocation, and a
transparency log, in sufficient detail that an independent team can implement an
interoperable emitter and verifier from this document alone.

- Specification version: 2
- Disclosure schema version: `DISCLOSURE_SCHEMA_VERSION = 1`. Every disclosure
  document MUST carry `version: 1`. This integer is bumped only on a breaking change
  to the disclosure *structure* — and the v2 work below deliberately did not change the
  document structure, only added a second *envelope* wrapping and additional encodings.
  The signed disclosure-document bytes are therefore unchanged from specification
  version 1.

Specification version 2 is additive at the wire layer: it introduces a second,
JOSE-interoperable envelope (a flattened JWS), an RFC 9421 handshake form, key-rotation
binding, namespaced operator-attestation schemes and an `extensions` bucket, and three
standards bridges (W3C VC 2.0, SD-JWT-VC, and a DID Document emit). A v2 verifier
accepts a v1 object envelope and a v2 JWS envelope interchangeably (Section 3.12), and
the disclosure document inside either is identical. None of these additions changes the
frozen canonicalization algorithm or the signed disclosure-document bytes.

The reference implementation is the `agent-disclosure` source tree (`src/schema.ts`,
`src/attestation.ts`, `src/handshake.ts`, `src/verify.ts`, `src/redaction.ts`,
`src/revocation.ts`, `src/transparency.ts`, plus the bridges `src/keys.ts`, `src/did.ts`,
`src/vc.ts`, `src/sdjwtvc.ts`). Where this document states a rule it cites the function
or field that implements it. For positioning and the trust model see `README.md`; for
the attack-by-attack analysis see `THREAT_MODEL.md`. This document does not restate
either.

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
| `agentId` | string | REQUIRED | The agent's stable id. By binding rule (Section 5) it MUST be the signing public key (hex), that key's did:key form, OR linked to the signing key by a verified rotation chain. | Identity binding; impersonation. |
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

`attestation` has: `scheme` (REQUIRED; see below), `level` (REQUIRED enum, one of
`"none"`, `"signed"`, `"registry_attested"`), and `evidence` (string, OPTIONAL). The
`deniabilityBoundary` is REQUIRED and load-bearing for the regulated-rails argument: it
is the operator's explicit accountability statement. Threat: operator collusion /
sock-puppets, and unaccountable deployment. See `THREAT_MODEL.md` attack 6.

`scheme` is **a known value OR a reverse-domain id** (`AttestationScheme` in
`src/schema.ts`). The known values are `"AIP"`, `"VisaTAP"`, `"ERC8004"`, `"DID"`, and
`"none"`. Any other value MUST be a reverse-domain namespace id matching
`^[a-z0-9]+(\.[a-z0-9-]+)+$` (e.g. `"com.visa.tap"`), so a third party can publish a new
attestation scheme as a vendor-namespaced string rather than forcing a core enum edit and
a five-language re-port. A bare unknown word (no dot, e.g. `"banana"`) is NOT a valid
scheme and MUST be rejected at structural validation. A verifier acts only on schemes it
recognizes; an unrecognized but well-formed reverse-domain scheme is carried and treated
as unattested by a verifier that does not understand it.

#### `extensions` (OPTIONAL, document level)

The disclosure document MAY carry a top-level `extensions` field: a record keyed by
reverse-domain id (matching the namespace regex above), each value an arbitrary JSON value
(`extensions` in `AgentDisclosureSchema`). This is the namespaced extension bucket: a
vendor can add a field under `com.vendor.feature` without a core spec change or a
five-language validator re-port. A verifier MUST act only on extension keys it recognizes;
unknown extensions are carried and ignored. Extensions canonicalize deterministically like
any other field, so they are covered by the signature and an absent `extensions` field
canonicalizes away (minor-version-safe).

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
REQUIRED, for example `"agentworth-gate"`, `"audit-chain"`) and `attestedBy` (string,
OPTIONAL). This lets a verifier WEIGHT claims: a field bound to an enforced gate is worth
more than a self-asserted one. A verifier MAY require provenance for named fields via
`requireProvenanceFor` (Section 8).

### 3.11 Structural validation

A verifier MUST structurally validate an untrusted document against the schema before
trusting any field (`parseDisclosure` / `parseSignedDisclosure` in `src/schema.ts`). A
malformed envelope is a refuse with no further checks (`verifyAndEvaluate` in
`src/verify.ts`).

### 3.12 The signed envelope

A signed disclosure has **two interchangeable envelope wrappings** over the SAME
disclosure document: the v1 object envelope and the v2 flattened JWS. They carry the
identical ed25519 crypto over the identical canonical disclosure bytes; only the packaging
differs. An emitter MAY produce either (dual-encode); a verifier MUST accept either,
discriminated by the envelope's SHAPE (`verifyAnyDisclosureSignature` /
`parseAnySignedDisclosure` in the reference). The two forms exist so ADP interoperates with
JOSE/JWS tooling without a fork: a verifier with no ADP code can read the v2 JWS.

#### 3.12.1 v1 object envelope - `SignedDisclosureSchema`

```
{
  "disclosure": <AgentDisclosure>,
  "signature": {
    "algorithm": "ed25519",
    "publicKey": <hex>,   // the signer's raw 32-byte public key, = agentId's key material
    "value":     <hex>    // ed25519 signature over canonicalize(disclosure)
  },
  "rotationChain": [ <RotationStatement>, ... ]   // OPTIONAL; see Section 5.1
}
```

`algorithm` MUST be the literal `"ed25519"`. `publicKey` is the signer's raw 32-byte
ed25519 public key as hex. `value` is the signature over the canonical bytes of the
disclosure document (Section 4), as hex. See `signDisclosure` in `src/attestation.ts`.
`rotationChain` is OPTIONAL key-rotation metadata (Section 5.1); it is NOT part of the
signed bytes.

In the v1 form, `signature.algorithm` sits OUTSIDE the signed bytes (it is not part of
`canonicalize(disclosure)`). A verifier MUST treat `algorithm` as a literal `"ed25519"`
constraint at structural validation and MUST NOT use it to select a verification
algorithm; the v2 form below closes this gap by signing the algorithm in.

#### 3.12.2 v2 flattened JWS envelope - `JwsSignedDisclosureSchema`

The v2 form is a JOSE flattened JWS (RFC 7515) using EdDSA (RFC 8037, the same RFC 8032
ed25519 primitive as v1).

```
{
  "payload":   <base64url>,   // base64url( UTF8( canonicalize(disclosure) ) ) — RFC 8785 (JCS) bytes
  "protected": <base64url>,   // base64url( UTF8( JSON{ "alg":"EdDSA", "typ":"application/adp+json" } ) )
  "header": {                 // unprotected header carrying the signing key
    "jwk": { "kty": "OKP", "crv": "Ed25519", "x": <base64url 32-byte pubkey> }
  },
  "signature": <base64url>,   // EdDSA over ASCII( b64url(protected) + "." + b64url(payload) )
  "rotationChain": [ ... ]    // OPTIONAL; see Section 5.1
}
```

The signature covers `ASCII(b64url(protected) + "." + b64url(payload))` — the JWS signing
input. Because the protected header (carrying `alg`) is part of the signed input, the
algorithm is integrity-protected: an attacker cannot substitute the algorithm without
breaking the signature, closing the v1 deviation. The payload is the byte-identical
RFC 8785 (JCS) canonical disclosure document, so the same bytes are signed in both forms.

A verifier of a v2 envelope MUST (`verifyDisclosureJws`):
1. decode `protected` and require `alg === "EdDSA"` (reject otherwise);
2. recover the 32-byte signing key from `header.jwk.x` (reject if not 32 bytes);
3. verify the EdDSA signature over `ASCII(protected + "." + payload)` against that key;
4. decode `payload`, read its `agentId`, and verify the agentId-to-key binding (Section 5).

#### 3.12.3 Discriminating the two shapes

A v2 envelope carries `payload` AND `protected`; a v1 envelope carries `disclosure` AND a
`signature` object. A parser keys off the presence of `payload`/`protected` to pick the
schema (`isJwsSignedDisclosure`, `parseAnySignedDisclosure`). `getDisclosure` extracts the
document from either: for v2 it base64url-decodes and schema-validates the JCS payload.

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

Example 3 - an object with a trailing `undefined` key dropped (the same shape that
recurs wherever an optional field is left unset):

```
input:  { "nonce": "ab12", "agentId": "ff00", "auditHead": "deadbeef",
          "signedAt": "2026-06-24T10:00:00Z", "verifierId": undefined }
output: {"agentId":"ff00","auditHead":"deadbeef","nonce":"ab12","signedAt":"2026-06-24T10:00:00Z"}
```

(The v2 handshake signs an RFC 9421 signature base, not this object — Section 7.3 — but
`canonicalize` still governs the disclosure document, the redaction commitment set, the
rotation-statement body, the revocation body, and the transparency-log preimage, each of
which exercises the same `undefined`-drop rule.)

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
- The envelope's `signature.publicKey` (v1) / `header.jwk.x` (v2) is the signer's raw
  32-byte ed25519 public key.
- **Identity binding (MUST).** A disclosure MUST be bound to the key that actually signed
  it. The binding holds (`verifyKeyBinding` in `src/attestation.ts`) when ANY of:
  1. `agentId` equals the signing public key (hex) — the common self-certifying case;
  2. `agentId` equals that key's **did:key** form (`did:key:z…`, Section 11.1) — the same
     self-certifying key expressed in the DID encoding;
  3. a verified **rotation chain** (Section 5.1) links `agentId` to the signing key.

  A verifier MUST reject a disclosure where none of these holds, before relying on its
  contents (`verifyDisclosureSignature` returns "agentId does not match the signing public
  key"). The same binding is enforced for redacted views (Section 9) and both envelope
  shapes (Section 3.12). It is the convention by which the public key IS the agent's
  identity, now extended so the identity can survive a key change.
- Signature verification verifies the signature over `canonicalize(disclosure)` against the
  32-byte public key (v1 over the hex signature; v2 over the JWS signing input, Section
  3.12.2). A mismatch is a refuse.

### 5.1 Key rotation

Because `agentId` is, by default, the signing key itself, a naive key change would mint a
new, unrelated identity and orphan every cached reference. A signed rotation chain lets a
stable `agentId` survive rotation: the OLD key signs a statement moving identity to the new
key, so a verifier that trusted the old identity can follow the chain forward.

A `RotationStatement` (`RotationStatementSchema` in `src/keys.ts`) is:

```
{
  "type":      "rotation",
  "from":      <hex>,       // agentId/public key being rotated AWAY from
  "to":        <hex>,       // agentId/public key being rotated TO
  "rotatedAt": <ISO-8601>,
  "signature": <hex>        // the FROM key's ed25519 signature over the canonical body
}
```

The signed body is `canonicalize({ type: "rotation", from, to, rotatedAt })`
(`rotationStatementBody`); only the `from` key signs (`rotateKey`). Trust flows forward
from the established identity; the new key never signs the move.

A `rotationChain` is an ordered array of such statements carried in the envelope (NOT part
of the signed disclosure bytes — it is verification metadata; it cannot be forged because
it must root at the signed `agentId`). To verify (`verifyRotationChain`), a verifier MUST:

1. start a cursor at `agentId`;
2. for each hop in order, require `hop.from == cursor`, verify `hop.signature` against
   `hop.from`, and require the chain be acyclic (a repeated `to` is a refuse);
3. advance the cursor to `hop.to`;
4. require the final cursor to equal the signing public key.

A chain MUST contain at least one hop and at most `MAX_ROTATION_CHAIN` (32) hops; an empty
or over-long chain is a refuse. A disclosure with no rotation carries no `rotationChain`
and binds by case (1) or (2) above.

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

The handshake proof is shaped as an **RFC 9421 (HTTP Message Signatures)** signature: the
agent signs a *signature base* built from named covered components plus an
`@signature-params` line, and carries it as a `Signature-Input` value (`signatureInput`)
and a `signature`. This is the non-HTTP-transport profile of RFC 9421 — there are no HTTP
fields to cover, so every covered component is an `adp-*` derived component (namespaced so
it cannot collide with a real HTTP header in a mixed deployment).

Two deliberate ADP deviations from strict RFC 9421: `created` is an ISO-8601 string (ADP's
timestamp convention) rather than a Unix-seconds integer, and the signature bytes are hex
(the package's convention) rather than the `:base64:` structured-field binary wrapper.

### 7.1 Challenge message

The verifier issues a `Challenge` (`createChallenge`):

```
{
  "nonce":             <string>,   // fresh, unguessable; reference uses 16 random bytes hex
  "issuedAt":          <ISO-8601>,
  "verifierId":        <string>,   // OPTIONAL; binds the proof to a specific verifier exchange (the 9421 `tag`)
  "supportedVersions": <number[]>  // OPTIONAL; disclosure-schema versions the verifier understands
}
```

The nonce MUST be fresh and unguessable per challenge (`randomNonce`). `supportedVersions`
advertises the disclosure-schema versions the verifier accepts, so the agent can present a
mutually-supported version (Section 7.5).

### 7.2 ChallengeResponse message

The agent answers with a `ChallengeResponse` (`respondToChallenge`):

```
{
  "nonce":             <string>,   // echoes the challenge nonce
  "agentId":           <string>,   // the responding agent's ed25519 public key (hex)
  "auditHead":         <string>,   // the agent's audit-chain head at response time
  "signedAt":          <ISO-8601>,
  "disclosureVersion": <number>,   // OPTIONAL; the schema version this response presents (a SIGNED covered component)
  "signatureInput":    <string>,   // the RFC 9421 Signature-Input value (covered set + params)
  "signature":         <hex>       // ed25519 over the RFC 9421 signature base (below)
}
```

### 7.3 The signature base

The signature is an ed25519 signature over the RFC 9421 **signature base**: one line per
covered component, then the `@signature-params` line. The covered components, in order, are
(`coveredComponents`):

```
"adp-agent-id":           <agentId>
"adp-audit-head":         <auditHead>
"adp-disclosure-version": <disclosureVersion>   // present ONLY when disclosureVersion is declared
"@signature-params": (<covered names>);created="<signedAt>";keyid="<agentId>";alg="ed25519";nonce="<nonce>";tag="<verifierId>"
```

`tag` is emitted only when the challenge carried a `verifierId`; the
`adp-disclosure-version` component (and its name in the inner list) is present only when the
response declares a `disclosureVersion`, so a no-version response signs a base with no
version line (backward-compatible path). The `Signature-Input` value carried on the wire is
`sig=<@signature-params value>` (`signatureInputValue`). Both sides MUST construct the base
byte-identically.

### 7.4 Verifier MUST-checks

`verifyChallengeResponse` takes the response, the original challenge, and a
`HandshakePolicy` (`expectedAgentId`, optional `disclosureAnchor`, optional `now`, optional
`maxAgeMs` defaulting to 60000, optional `supportedVersions`). A verifier MUST check, in
order:

1. **Nonce match.** `response.nonce` MUST equal `challenge.nonce`. A mismatch is a refuse
   ("replayed or wrong challenge"). Defeats identity replay.
2. **AgentId match.** `response.agentId` MUST equal `policy.expectedAgentId` (the agentId
   the disclosure claims). A mismatch is a refuse.
3. **Signature-Input match.** The verifier reconstructs the expected `signatureInput` from
   ITS challenge (nonce, verifierId) plus the response's claimed values, and `response.
   signatureInput` MUST equal it exactly. This prevents covered-set / parameter smuggling.
4. **Signature.** The ed25519 signature MUST verify over the reconstructed Section 7.3
   signature base against `response.agentId`. A failure is a refuse ("no live key
   possession"). Because the base covers the audit head and version, tampering any covered
   value is caught here.
5. **Version negotiation.** When `policy.supportedVersions` is set and the response declares
   a `disclosureVersion` outside it, the verifier MUST refuse with an actionable reason. A
   response that declares no version is accepted (pre-negotiation peers stay interoperable).
   See Section 7.5.
6. **Freshness.** When `policy.now` is supplied, `Date.parse(now) - Date.parse(signedAt)`
   MUST be `>= 0` and `<= maxAgeMs` (default 60000 ms). Outside that range is a refuse
   ("stale").
7. **Audit-head currency.** The bound `auditHead` is checked against the disclosure's
   anchor. An exact match means the disclosure is current as of the live head. A regression
   to an OLDER anchor is a red flag; equality or a newer/different head is acceptable (the
   verifier cannot fully order the chain without it). The reference treats this as a
   non-fatal signal and returns ok; a stricter verifier MAY refuse on a detected regression.

### 7.5 Version negotiation

The handshake binds not just liveness but the protocol version in play. The verifier
advertises `Challenge.supportedVersions`; the agent MAY declare a `disclosureVersion` in its
response, which is a SIGNED covered component (Section 7.3) and therefore cannot be
downgraded by a man-in-the-middle. A verifier whose `supportedVersions` does not include a
declared version MUST refuse-with-reason. A response that declares no version is accepted, so
a v1 (pre-negotiation) peer and a v2 verifier remain interoperable. This is the MCP-style
round-trip negotiation adapted to the signed handshake.

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

## 11. Standards bridges (additive encodings)

A signed disclosure has additional, OPTIONAL standards-track encodings that re-express the
SAME signed claims for ecosystems that speak DID / VC / SD-JWT. None of these replaces the
native form or introduces a second trust root; each reuses the agent's ed25519 key over the
same RFC 8785 (JCS) bytes, so a verifier can always fall back to the native check.

### 11.1 DID Document and did:key (`src/did.ts`)

The `agentId` (raw 32-byte ed25519 public key, hex) maps deterministically to a **did:key**
of the ed25519-pub multicodec: `did:key:z` followed by base58btc of `0xed01 || rawKey`
(`agentIdToDidKey`; the inverse is `didKeyToAgentId`). This is self-certifying — resolving
the DID recovers the same key, with no registry. The identity binding (Section 5) accepts an
`agentId` in this did:key form.

`agentIdToDidDocument(agentId, { disclosureEndpoint })` emits a W3C DID Core document whose
`id` is the did:key, whose single `verificationMethod` is the ed25519 key as
`Ed25519VerificationKey2020` (`publicKeyMultibase`, base58btc with the multicodec prefix),
listed under `authentication` and `assertionMethod`. When a disclosure endpoint is supplied,
the document carries a `service` entry of `type: "AgentDisclosure"` whose `serviceEndpoint`
points at the `.well-known/agent-disclosure` URI (Section 14), so any DID-aware verifier
resolves to the disclosure through standard rails. This COMPLEMENTS the raw-key model — it
does not make ADP DID-native. `didWeb(domain, path)` constructs a `did:web` identifier
(host as method-specific id, `:`-separated percent-encoded path segments); the corresponding
`did.json` is served and resolved out of band.

### 11.2 W3C Verifiable Credential 2.0 (`src/vc.ts`)

`toVerifiableCredential` re-shapes a `SignedDisclosure` into a **W3C VC Data Model 2.0**
credential: `@context` is `https://www.w3.org/ns/credentials/v2`; the type is
`["VerifiableCredential", "AgentDisclosureCredential"]`; `validFrom` / `validUntil` carry
the disclosure's freshness window (VC 2.0 names, replacing v1.1 `issuanceDate` /
`expirationDate`); `credentialSubject` is the disclosure plus a did:key subject `id`.

The `proof` is a `DataIntegrityProof` whose `cryptosuite` is the ADP-namespaced,
deliberately **non-registered** `adp-jcs-2024`. It reuses the envelope's ed25519 signature
verbatim, computed over the RFC 8785 (JCS) canonical disclosure, multibase base58btc-encoded
as `proofValue`. The non-registered suite name is intentional: ADP does NOT squat the
registered `eddsa-jcs-2022` / `Ed25519Signature2020`, so a generic DI verifier that does not
recognize `adp-jcs-2024` correctly declines rather than running registered Data Integrity
over different bytes. `verifyVerifiableCredential` checks the subject did:key resolves to the
disclosure's `agentId` and then delegates to the native envelope check on the reconstructed
`SignedDisclosure` — the same canonicalization path, no second trust root.

### 11.3 SD-JWT-VC (`src/sdjwtvc.ts`)

`toSdJwtVc` re-encodes a disclosure as an **SD-JWT-VC** (RFC 9901 + draft-ietf-oauth-sd-jwt-
vc) — a JOSE EdDSA JWT with selective disclosure, the standards-track sibling of the native
redaction form (Section 9). It closes three gaps the native commitment map has:

- **Hidden field names.** Each present redactable field (`REDACTABLE_FIELDS`) becomes an
  SD-JWT *Disclosure* — `base64url(["<salt>","<name>",<value>])` — whose only trace in the
  signed JWT is an opaque digest in the `_sd` array. Withhold it and the verifier never
  learns the name existed (the native form leaks names as visible map keys).
- **Hidden count.** `_sd` is padded with **decoy digests** of fictional Disclosures
  (default 2) and shuffled, so the number of real selectively-disclosable claims is hidden.
- **Presentation-to-verifier binding.** `presentSdJwtVc` drops the unrevealed Disclosures
  and appends a **KB-JWT** (key-binding JWT) signed by the holder's `cnf` key over
  `{ iat, aud, nonce, sd_hash }`, binding the exact presented bytes to one verifier and one
  challenge nonce — closing the replay gap a bare `RedactedView` has.

The issuer JWT carries `iss` (the agent's did:key, self-certifying), `vct`
(`https://adp.dev/credential/agent-disclosure/v1`), `iat`/`exp` from the freshness window,
`cnf` (the holder's OKP/Ed25519 JWK), the native always-clear meta (`version`,
`disclosureId`, `nonce`, `auditAnchor`), and `_sd` + `_sd_alg: "sha-256"`. The header is
`{ typ: "dc+sd-jwt", alg: "EdDSA" }`. `verifySdJwtVc` recovers the issuer key from the
did:key, checks every received Disclosure's digest is in `_sd` (rejecting unreferenced or
duplicated digests), splices the revealed claims back in, and — when a KB-JWT is present or
an `aud`/`nonce` is required — verifies it against the `cnf` key with a matching `sd_hash`
over the exact presented bytes. This is additive: a disclosure can be carried as the native
`SignedDisclosure` or as an SD-JWT-VC string, by content negotiation.

## 12. Conformance

A conformant implementation MUST satisfy the runnable conformance suite under
`conformance/`, which carries (a) canonicalization vectors and (b) behavioural checks.
Specifically, a conformant implementation:

- MUST reproduce every canonicalization vector byte for byte, including the Section 4.2
  worked examples (object key sort, recursive sort, preserved array order, dropped
  `undefined` values, and the absent-`verifierId` object case).
- MUST produce ed25519 signatures over the canonical UTF-8 bytes that the reference
  verifier accepts, and MUST verify reference-produced signatures — for BOTH envelope
  shapes: the v1 object envelope and the v2 flattened JWS (`conformance/interop.json`
  carries a `jwsDisclosures` fixture set the native verifiers reproduce).
- MUST enforce the agentId-to-key binding including the did:key and rotation-chain forms
  (Section 5), the freshness window (Section 6), the RFC 9421 handshake MUST-checks
  including the `Signature-Input` match and version negotiation (Section 7.4), and the
  policy semantics including the empty-policy baseline (Section 8).
- MUST reproduce the selective-disclosure commitment and verification (Section 9), the
  signed-revocation preimage (Section 10.1), and the transparency-log GENESIS value and
  `hash` preimage (Section 10.2).
- MUST reject the adversarial corpus (`conformance/negative.json`), which now includes
  invalid-enum and malformed-namespace cases (e.g. a bare-word attestation `scheme`), so a
  malformed-but-honestly-signed document is rejected at structural validation, not waved
  through on a valid signature.

An emitter and a verifier from independent teams are interoperable when both pass the
suite: the canonicalization vectors guarantee identical signed bytes, and the behavioural
checks guarantee identical accept/refuse decisions.

## 13. Security considerations

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

## 14. IANA and well-known URI (informational)

This section is informational; the normative registration request lives in the companion
Internet-Draft (`docs/drafts/draft-gl-adp-disclosure-00.md`), which requests registration of
the `agent-disclosure` well-known URI suffix per RFC 8615. The disclosure is served from a
well-known URI on the agent's own origin, so a verifier that can resolve a counterparty's
base URL can fetch its commitments with no registry or out-of-band exchange:

- Discovery: `GET <base>/.well-known/agent-disclosure` returns the signed disclosure
  envelope (`SignedDisclosure`). A non-200 response or a parse failure is a refuse.
- Live handshake: `POST <base>/agent-disclosure/respond` accepts a `Challenge` and
  returns a `ChallengeResponse` (Section 7).

These paths are the reference discovery transport (`src/client.ts`); registration of
`agent-disclosure` as a well-known URI suffix is left to a future submission. Until then,
implementers SHOULD use these paths for interoperability.
