---
title: "The Agent Disclosure Protocol (ADP) Wire Format"
abbrev: "ADP Disclosure"
docname: draft-gl-adp-disclosure-00
category: std
ipr: trust200902
area: Security
workgroup: Independent Submission
keyword: [agent, disclosure, ed25519, verifiable agency, agentic commerce]
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
  -
    ins: General Liquidity
    name: General Liquidity
    org: General Liquidity
--- abstract

Autonomous software agents are beginning to transact with one another over machine
payment rails with no standard way for a counterparty to answer the first question of
commerce before value moves: who is this agent, and what is it committed to? The Agent
Disclosure Protocol (ADP) defines a signed disclosure document that an agent publishes
BEFORE it transacts, plus the canonicalization, signing, freshness, and live
challenge-response handshake a counterparty uses to verify it and decide transact-or-
refuse before any value moves. Disclosures are signed with Ed25519 over a JSON
Canonicalization Scheme (RFC 8785) byte string, so a counterparty verifies with no shared
secret and no prior relationship. This document specifies the ADP wire format: the
disclosure document, its two interchangeable signed envelopes (an object envelope and a
flattened JWS), the freshness window, the RFC 9421-shaped verification handshake, and the
well-known URI by which a disclosure is discovered.

--- middle

# Introduction

The Agent Disclosure Protocol (ADP) is a disclose-before-settle protocol. Before an agent
transacts, it exposes a signed disclosure document describing the rules it runs under, the
capital envelope it operates inside, who deployed it, what it has done, the model it
declares, and how the document was signed. A counterparty (the verifier) fetches the
disclosure, evaluates it against its own policy, optionally runs a live challenge-response
handshake to prove the emitter holds the signing key right now, and only then decides to
transact or refuse. The decision happens before value moves, not after a loss. The default
posture is fail-closed: a disclosure that fails policy, has expired, is unreachable, or
fails the liveness handshake all resolve to refuse.

ADP uses asymmetric (Ed25519, {{RFC8032}}) signatures, so a verifier checks a disclosure
with no shared secret and no registry: the public key travels in the envelope and, by the
binding rule of {{identity}}, IS the agent's identifier (the `agentId`).

This document specifies the ADP wire format only. It does not mandate a runtime, a rail, or
a registry. ADP composes ABOVE payment rails and BESIDE identity protocols; the disclosure
is the vendor-neutral behavioural-trust layer those protocols defer.

This document describes what is implemented in the reference implementation. Where a
feature is partial or has an acknowledged residual gap (for example, proving the running
model matches its declared fingerprint, which requires hardware attestation), this document
says so rather than overstating it.

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear
in all capitals, as shown here.

This document uses the following terms:

Disclosure:
: The signed JSON document an agent publishes describing what it is committed to. The
  CONTENT that is signed (the disclosure document), as distinct from the envelope that
  wraps it with a signature.

Emitter:
: The party (an agent) that produces and signs a disclosure and answers the verification
  handshake. The emitter holds the Ed25519 private key.

Verifier:
: The party that fetches a disclosure, evaluates it against its own policy, runs the
  handshake, and decides transact or refuse. Also called the counterparty.

Counterparty:
: A synonym for the verifier — the other party to a prospective transaction, evaluating an
  emitter's disclosure before value moves.

agentId:
: The emitter's stable identifier. By the binding rule of {{identity}} it is the Ed25519
  signing public key (as lowercase hex), that key's `did:key` form, or an identifier linked
  to the signing key by a verified rotation chain.

All canonicalization, digest, and signature octets are produced as specified in
{{canonicalization}} and {{signing}}. JSON {{RFC8259}} is the interchange syntax; hex
fields match `^[0-9a-fA-F]+$`; timestamp fields are ISO-8601 strings.

# Protocol Overview

A verifier runs four steps; any failure on either the static or the live leg is a refuse:

1. Fetch the disclosure from the emitter's well-known URI ({{well-known}}).
2. Evaluate the disclosure against the verifier's policy (signature and freshness are
   checked by default; every other requirement is opt-in).
3. Run the live challenge-response handshake ({{handshake}}) to prove current key
   possession and a current audit head.
4. Decide transact or refuse. The verdict is deterministic and cheap, so it can run before
   every transaction.

# Canonicalization {#canonicalization}

Signing and digesting operate over a canonical byte string, not over arbitrary JSON
whitespace or key order. ADP canonicalization is the JSON Canonicalization Scheme (JCS)
{{RFC8785}} over ADP's value domain: object keys sorted by UTF-16 code unit, ECMAScript
Number-to-string number formatting, JSON string escaping, no insignificant whitespace, and
UTF-8 output. For every value an ADP disclosure can carry, the algorithm emits
byte-identical output to a conformant JCS implementation.

ADP adds two profile rules that JCS does not legislate, because JCS canonicalizes
already-parsed JSON while ADP canonicalizes in-memory documents:

- Object keys whose value is `undefined` are dropped (an absent optional field and one set
  to `undefined` MUST canonicalize identically). JSON `null` is NOT dropped.
- The input MUST NOT contain `NaN` or `Infinity` (not representable in JSON).

Implementers porting to another language MUST satisfy JCS exactly, in particular the
UTF-16 code-unit key sort (NOT Unicode code point, NOT UTF-8 byte order: a supplementary-
plane key such as an emoji sorts before a BMP key like U+FB33 because its lead surrogate is
the smaller code unit) and ECMAScript number formatting. ADP carries no exponential-range
doubles; numeric fields are integers or short decimals.

# The Disclosure Document

The disclosure document is the signed content. It carries an always-clear meta block
(identity and freshness fields a verifier needs first) and a set of field groups, each of
which makes a specific threat legible:

- `version` (integer literal 1), `disclosureId`, `agentId`, `issuedAt`, `validUntil`,
  `nonce` (all REQUIRED), and `auditAnchor` (OPTIONAL hex) — the meta block.
- `systemPrompt`: a SHA-256 {{RFC6234}} fingerprint of the composed system prompt.
- `constitution`: the structured hard-constraint deny-list, with an `enforced` flag that,
  when true, asserts the disclosed rules ARE the gate actually running.
- `tools`: the tool inventory and permission boundaries.
- `capital`: the mandate set — scoped, capped, expiring spend authority — and custody.
- `operator`: operator identity, attestation, and an explicit deniability boundary. The
  attestation `scheme` is a known value (`AIP`, `VisaTAP`, `ERC8004`, `DID`, `none`) or a
  reverse-domain namespace id.
- `history`: a deployment-history summary bound to a signed hash-linked audit chain anchor.
- `redTeam`, `model`, `provenance` (all OPTIONAL): a public-corpus red-team grade, a
  declared model fingerprint, and per-field derivation metadata.
- `extensions` (OPTIONAL): a record keyed by reverse-domain id carrying third-party fields
  a verifier ignores unless it recognizes them.

A verifier MUST structurally validate an untrusted document against the schema before
relying on any field. A malformed document is a refuse with no further checks.

# The Signed Envelopes {#envelope}

A signed disclosure has two interchangeable envelope wrappings over the same disclosure
document, carrying the same Ed25519 crypto over the same canonical bytes. An emitter MAY
produce either; a verifier MUST accept either, discriminated by shape.

## Object envelope

~~~
{
  "disclosure": <disclosure document>,
  "signature": {
    "algorithm": "ed25519",
    "publicKey": <hex>,   // raw 32-byte Ed25519 public key
    "value":     <hex>    // Ed25519 signature over canonicalize(disclosure)
  },
  "rotationChain": [ ... ]   // OPTIONAL; see Identity Binding
}
~~~

`algorithm` MUST be the literal `"ed25519"`. In this form `algorithm` is OUTSIDE the signed
bytes; a verifier MUST treat it as a literal constraint and MUST NOT use it to select a
verification algorithm.

## Flattened JWS envelope

A JOSE flattened JWS {{RFC7515}} using EdDSA {{RFC8037}} (the same Ed25519 primitive):

~~~
{
  "payload":   <base64url(UTF8(canonicalize(disclosure)))>,
  "protected": <base64url(UTF8({ "alg":"EdDSA", "typ":"application/adp+json" }))>,
  "header":    { "jwk": { "kty":"OKP", "crv":"Ed25519", "x":<base64url pubkey> } },
  "signature": <base64url( EdDSA over ASCII(protected + "." + payload) )>,
  "rotationChain": [ ... ]   // OPTIONAL
}
~~~

The signature covers ASCII(b64url(protected) + "." + b64url(payload)). Because the
protected header (carrying `alg`) is part of the signed input, the algorithm is
integrity-protected. The payload is the byte-identical JCS canonical disclosure, so a
generic JOSE library can verify it. A verifier MUST require `alg` to be `"EdDSA"`, recover
the 32-byte key from `header.jwk.x`, verify the signature over the signing input, and bind
the payload's `agentId` to that key ({{identity}}).

# Signing and Identity Binding {#signing}

Signatures are Ed25519 {{RFC8032}} over the UTF-8 octets of the canonical string
({{canonicalization}}).

## Signing {#signing-sign}

To sign a disclosure: compute the canonical string, encode as UTF-8, and Ed25519-sign with
the emitter's private key. In the object envelope the signature is hex in `signature.value`;
in the JWS envelope it is base64url over the JWS signing input.

## Identity binding {#identity}

A disclosure MUST be bound to the key that actually signed it. The binding holds when ANY of
the following is true:

1. `agentId` equals the signing public key (hex) — the common self-certifying case;
2. `agentId` equals that key's `did:key` form (the same key in the W3C DID encoding);
3. a verified rotation chain links `agentId` to the signing key.

A verifier MUST reject a disclosure where none holds, before relying on its contents.

A rotation statement is `{ "type":"rotation", "from":<hex>, "to":<hex>, "rotatedAt":<ISO>,
"signature":<hex> }`, where the OLD (`from`) key signs `canonicalize({type,from,to,
rotatedAt})`. A `rotationChain` is an ordered array of such statements carried in the
envelope; it is NOT part of the signed disclosure bytes. To verify a chain: start a cursor
at `agentId`; for each hop, require `from` equals the cursor, verify the hop signature
against `from`, reject cycles, and advance the cursor to `to`; require the final cursor to
equal the signing key. A chain MUST have between 1 and 32 hops.

# Freshness {#freshness}

A disclosure is valid only within its `[issuedAt, validUntil]` window. A verifier MUST
reject a disclosure outside the window. The comparison is performed as ISO-8601 lexical
(string) comparison; emitters MUST therefore produce timestamps in a consistent,
zero-padded ISO-8601 form (and SHOULD use UTC `Z`) so that lexical order equals
chronological order. Clock skew between parties moves the window edges and is an
acknowledged residual gap.

# The Verification Handshake {#handshake}

The handshake is a live challenge-response proving the emitter holds the signing key right
now and that its audit head is current — neither of which a captured static disclosure can
prove. The proof is shaped as an HTTP Message Signature {{RFC9421}}, in the non-HTTP-
transport profile: there are no HTTP fields to cover, so every covered component is a
namespaced `adp-*` derived component.

The verifier issues a Challenge `{ nonce, issuedAt, verifierId?, supportedVersions? }` with
a fresh, unguessable nonce. The emitter answers with a ChallengeResponse carrying `nonce`,
`agentId`, `auditHead`, `signedAt`, an optional `disclosureVersion`, a `signatureInput`,
and a `signature`.

The signature is an Ed25519 signature over the {{RFC9421}} signature base: one line per
covered component, then the `@signature-params` line:

~~~
"adp-agent-id":           <agentId>
"adp-audit-head":         <auditHead>
"adp-disclosure-version": <disclosureVersion>   // only when declared
"@signature-params": (<covered names>);created="<signedAt>";keyid="<agentId>";alg="ed25519";nonce="<nonce>";tag="<verifierId>"
~~~

`tag` is emitted only when the challenge carried a `verifierId`; the version line only when
a `disclosureVersion` is declared. Two deliberate ADP deviations from strict {{RFC9421}}:
`created` is an ISO-8601 string (ADP's timestamp convention) rather than Unix seconds, and
the signature octets are hex rather than the `:base64:` structured-field binary wrapper.

A verifier MUST, in order: (1) require the response nonce equals the challenge nonce; (2)
require `agentId` equals the expected agentId; (3) reconstruct the expected
`signatureInput` from its own challenge plus the response values and require an exact match;
(4) verify the Ed25519 signature over the reconstructed signature base; (5) if it advertised
`supportedVersions` and the response declares a `disclosureVersion` outside that set, refuse
with reason (a no-version response is accepted); (6) if a clock is supplied, require the
response age to be within bounds (default 60 s); (7) compare the bound `auditHead` against
the disclosure's anchor (a regression to an older anchor is a red flag).

# Discovery: the well-known URI {#well-known}

A disclosure is served from a well-known URI {{RFC8615}} on the emitter's own origin, so a
verifier that can resolve a counterparty's base URL can fetch its commitments with no
registry or out-of-band exchange:

- Discovery: `GET <base>/.well-known/agent-disclosure` returns the signed disclosure
  envelope ({{envelope}}). A non-200 response or a parse failure is a refuse.
- Live handshake: `POST <base>/agent-disclosure/respond` accepts a Challenge and returns a
  ChallengeResponse ({{handshake}}).

This document requests registration of the `agent-disclosure` well-known URI suffix
({{iana}}).

# Security Considerations

ADP makes a fixed set of attacks legible and pairs each with a concrete defending field or
mechanism, stating the residual gap honestly:

- Constitution substitution (via prompt injection): the `enforced` binding asserts the
  disclosed rules ARE the running gate. Residual: a verifier must trust the
  `enforcementEvidence` it cannot itself execute.
- Deployment-history forgery: the summary is bound to a hash-linked audit-chain anchor, so
  it cannot claim numbers the chain does not support without breaking the recomputed link.
- Identity replay ("I am the agent you think I am"): the live nonce handshake
  ({{handshake}}) defeats a captured static disclosure, which cannot answer a fresh nonce.
- Stale presentation: the freshness window ({{freshness}}), the per-disclosure nonce, and
  the live audit-head currency check together bound how old a presented disclosure can be.
- Post-hoc rewriting: the signature, the `auditAnchor`, and an append-only transparency log
  make a retro-edited disclosure detectable.
- Algorithm substitution: the JWS envelope ({{envelope}}) signs `alg` into the protected
  header. The object envelope's `algorithm` field is outside the signed bytes and MUST be
  treated as a literal constraint only.
- Operator collusion / unaccountable deployment: the operator attestation and the explicit
  deniability boundary make the deploying party and its accountability legible.
- Model swap: the declared model fingerprint is the cheap, declarable half only.
  Cryptographically proving the RUNNING model matches the declaration needs hardware (TEE)
  attestation; this is an acknowledged open item.
- Verification-cost denial of service: the verdict is deterministic and cacheable within a
  disclosure's validity window, so a verifier is not forced into unbounded work.

Canonicalization is security-relevant: a port that sorts keys by code point or UTF-8 byte
order instead of UTF-16 code unit will produce un-verifiable signatures cross-stack on
supplementary-plane keys. Implementers MUST satisfy JCS {{RFC8785}} exactly.

Key rotation ({{identity}}) extends trust across a key change; a verifier MUST verify the
full chain (contiguous, acyclic, each hop signed by its `from` key, ending at the signing
key) and MUST bound the chain length, since the chain is attacker-supplied metadata.

The default posture is fail-closed: any unverifiable, expired, unreachable, or
policy-failing disclosure resolves to refuse.

# IANA Considerations {#iana}

This document requests that IANA register the following well-known URI suffix in the
"Well-Known URIs" registry established by {{RFC8615}}.

URI suffix:
: agent-disclosure

Change controller:
: General Liquidity (or, on adoption, the IETF)

Specification document:
: This document

Status:
: permanent

Related information:
: Used by the Agent Disclosure Protocol. `GET <origin>/.well-known/agent-disclosure`
  returns a signed disclosure envelope as specified in {{envelope}}. The companion live
  handshake endpoint `<origin>/agent-disclosure/respond` is NOT a well-known URI and is not
  registered here.

This document defines no new IANA registries and requests no other registrations. The JWS
`typ` media-type token `application/adp+json` used in {{envelope}} is descriptive within
this document and is not requested for registration in the media-types registry at this
time.

--- back

# Acknowledgements
{:numbered="false"}

ADP's canonicalization, freshness, handshake, and well-known transport were independently
derived and then aligned to the named standards referenced here.

<reference anchor="RFC2119" target="https://www.rfc-editor.org/info/rfc2119">
  <front><title>Key words for use in RFCs to Indicate Requirement Levels</title>
  <author initials="S." surname="Bradner"/><date year="1997"/></front>
</reference>

# Normative References
{:numbered="false"}

The following standards are normative for an ADP implementation:

- {{RFC2119}} — Key words for use in RFCs to Indicate Requirement Levels (BCP 14).
- {{RFC8174}} — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words (BCP 14).
- {{RFC8032}} — Edwards-Curve Digital Signature Algorithm (EdDSA); Ed25519 is the ADP
  signature primitive.
- {{RFC6234}} — US Secure Hash Algorithms (SHA-256), used for digests and fingerprints.
- {{RFC8615}} — Well-Known Uniform Resource Identifiers (URIs); the discovery transport and
  the registration in {{iana}}.
- {{RFC8785}} — JSON Canonicalization Scheme (JCS); the canonical byte string over which
  ADP signs and digests.
- {{RFC9421}} — HTTP Message Signatures; the shape of the verification handshake signature.
- {{RFC7515}} — JSON Web Signature (JWS); the flattened JWS envelope.
- {{RFC8037}} — CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE; the
  EdDSA (Ed25519) JOSE binding.
- {{RFC8259}} — The JavaScript Object Notation (JSON) Data Interchange Format.

# Informative References
{:numbered="false"}

The following are informative context and interoperability targets, not required to
implement the ADP wire format:

- ERC-8004 (Ethereum, "Trustless Agents") — anchors an agent's identity to a wallet and
  names a pluggable verification layer; ADP is a candidate for that layer.
- {{RFC9901}} — Selective Disclosure for JWTs (SD-JWT), with draft-ietf-oauth-sd-jwt-vc —
  the standards-track sibling of ADP's native selective disclosure; ADP offers an
  SD-JWT-VC alternate encoding.
- W3C Decentralized Identifiers (DID Core) and the `did:key` / `did:web` methods — the DID
  encodings ADP bridges to.
- W3C Verifiable Credentials Data Model 2.0 — the credential shape ADP re-expresses a
  disclosure into via a DataIntegrityProof bridge.
