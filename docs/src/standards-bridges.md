# Standards Bridges

A signed disclosure has additional, **optional** standards-track encodings that re-express
the same signed claims for ecosystems that speak DID, W3C VC, or SD-JWT. None of these
replaces the native form or introduces a second trust root: each reuses the agent's ed25519
key over the same [RFC 8785 (JCS)](./canonicalization.md) bytes, so a verifier can always
fall back to the native check.

## DID Document and did:key (`src/did.ts`)

The `agentId` (raw 32-byte ed25519 public key, hex) maps deterministically to a **did:key**
of the ed25519-pub multicodec: `did:key:z` followed by base58btc of `0xed01 || rawKey`
(`agentIdToDidKey`; the inverse is `didKeyToAgentId`). This is self-certifying — resolving
the DID recovers the same key, with no registry. The [identity binding](./signing-and-identity.md)
accepts an `agentId` in this did:key form.

`agentIdToDidDocument(agentId, { disclosureEndpoint })` emits a W3C DID Core document whose
`id` is the did:key, whose single `verificationMethod` is the ed25519 key as
`Ed25519VerificationKey2020` (`publicKeyMultibase`, base58btc with the multicodec prefix),
listed under `authentication` and `assertionMethod`. When a disclosure endpoint is supplied,
the document carries a `service` entry of `type: "AgentDisclosure"` whose `serviceEndpoint`
points at the `.well-known/agent-disclosure` URI, so any DID-aware verifier resolves to the
disclosure through standard rails. This **complements** the raw-key model — it does not make
ADP DID-native. `didWeb(domain, path)` constructs a `did:web` identifier; the corresponding
`did.json` is served and resolved out of band.

## W3C Verifiable Credential 2.0 (`src/vc.ts`)

`toVerifiableCredential` re-shapes a `SignedDisclosure` into a **W3C VC Data Model 2.0**
credential: `@context` is `https://www.w3.org/ns/credentials/v2`; the type is
`["VerifiableCredential", "AgentDisclosureCredential"]`; `validFrom` / `validUntil` carry the
freshness window (VC 2.0 names, replacing v1.1 `issuanceDate` / `expirationDate`);
`credentialSubject` is the disclosure plus a did:key subject `id`.

The `proof` is a `DataIntegrityProof` whose `cryptosuite` is the ADP-namespaced,
deliberately **non-registered** `adp-jcs-2024`. It reuses the envelope's ed25519 signature
verbatim, computed over the JCS canonical disclosure, multibase base58btc-encoded as
`proofValue`. The non-registered name is intentional: ADP does **not** squat the registered
`eddsa-jcs-2022` / `Ed25519Signature2020`, so a generic Data Integrity verifier that does not
recognize `adp-jcs-2024` correctly declines rather than running registered DI over different
bytes. `verifyVerifiableCredential` checks the subject did:key resolves to the disclosure's
`agentId` and then delegates to the native envelope check — the same canonicalization path,
no second trust root.

## SD-JWT-VC (`src/sdjwtvc.ts`)

`toSdJwtVc` re-encodes a disclosure as an **SD-JWT-VC** (RFC 9901 +
draft-ietf-oauth-sd-jwt-vc) — a JOSE EdDSA JWT with selective disclosure, the standards-track
sibling of the native [redaction](./selective-disclosure.md) form. It closes three gaps the
native commitment map has:

- **Hidden field names.** Each present redactable field (`REDACTABLE_FIELDS`) becomes an
  SD-JWT *Disclosure* — `base64url(["<salt>","<name>",<value>])` — whose only trace in the
  signed JWT is an opaque digest in the `_sd` array. Withhold it and the verifier never learns
  the name existed.
- **Hidden count.** `_sd` is padded with **decoy digests** of fictional Disclosures (default
  2) and shuffled, so the number of real selectively-disclosable claims is hidden.
- **Presentation-to-verifier binding.** `presentSdJwtVc` drops the unrevealed Disclosures and
  appends a **KB-JWT** signed by the holder's `cnf` key over `{ iat, aud, nonce, sd_hash }`,
  binding the exact presented bytes to one verifier and one challenge nonce.

The issuer JWT carries `iss` (the agent's did:key), `vct`
(`https://adp.dev/credential/agent-disclosure/v1`), `iat`/`exp` from the freshness window,
`cnf` (the holder's OKP/Ed25519 JWK), the native always-clear meta (`version`, `disclosureId`,
`nonce`, `auditAnchor`), and `_sd` + `_sd_alg: "sha-256"`. The header is
`{ typ: "dc+sd-jwt", alg: "EdDSA" }`. `verifySdJwtVc` recovers the issuer key from the
did:key, checks every received Disclosure's digest is in `_sd` (rejecting unreferenced or
duplicated digests), splices the revealed claims back in, and — when a KB-JWT is present or an
`aud`/`nonce` is required — verifies it against the `cnf` key with a matching `sd_hash` over
the exact presented bytes.

This is additive: a disclosure can be carried as the native `SignedDisclosure` / `RedactedView`
or as an SD-JWT-VC string, by content negotiation.

## A2A Agent Card (`src/a2a.ts`)

[A2A](https://a2a-protocol.org) (Agent2Agent) publishes an unauthenticated **Agent Card** at
`/.well-known/agent-card.json` that advertises an agent's capabilities, skills, and — via
`capabilities.extensions[]` — protocol extensions a counterparty can opt into. This bridge
defines one such extension so an ADP disclosure travels with A2A discovery.

**The extension.** `disclosureExtension(signed, opts)` builds an `AgentExtension` under the
URI `https://adp.dev/a2a/agent-disclosure/v1` (`ADP_A2A_EXTENSION_URI`). By default it
**embeds** the full `SignedDisclosure` in `params.disclosure` (with `params.agentId`), so a
counterparty verifies with no second fetch; an optional `params.url` points at a
`.well-known/agent-disclosure` for fetch-based flows. With `embed: false` the extension carries
only `{ agentId, url }` (and `url` is then required). `withDisclosureExtension(card, signed)`
returns a copy of the card with the extension appended to `capabilities.extensions` (dedup by
URI); `findDisclosureExtension` / `extractDisclosure` locate it and lift the embedded disclosure
back out (re-validated against `SignedDisclosureSchema`).

**Dual-signature trust model.** An Agent Card MAY itself carry `signatures[]` —
[RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) JWS in flattened-JSON form, each
`{ protected, signature, header? }`. The signed payload is the card with `signatures` removed,
[RFC 8785 (JCS)](./canonicalization.md)-canonicalized, with the A2A §8.4.1 default-value
omission applied; the signing input is `BASE64URL(protected) + "." + BASE64URL(JCS(payload))`.
That JWS is **tamper-evidence on the card origin**, not the trust root. The trust root is the
disclosure's **own ed25519 envelope**, which a counterparty verifies with the agent's public key
alone — the same guarantee the bare disclosure carries.

So `verifyCardDisclosure(card, opts?)` **requires** the disclosure envelope to verify
(`verifyDisclosureSignature`) and only **reports** the card-signature result: it returns
`{ ok, agentId, cardSignatureChecked, boundToCardSigner }`, where a card-signature failure does
**not** fail `ok`, but a verified card signature whose signer key resolves to the disclosure
`agentId` (directly or via that key's did:key form) sets `boundToCardSigner`. `signAgentCard`
defaults to **EdDSA over the ADP ed25519 agent key**, so an ADP agent can publish a self-signed
card whose signer == agentId → a strong, provable binding. `verifyAgentCardSignature` implements
§8.4.3: it verifies EdDSA natively against an OKP/Ed25519 `jwk` in the signature header (or a
resolver-supplied key), and ES256/RS256 when a `resolveKey` callback supplies the key; an
algorithm it cannot handle returns a graceful `{ ok:false, reason:"unsupported alg" }` rather
than throwing.

Like the other bridges, this is dependency-free (zod + `node:crypto`) and additive — a fuller,
real `AgentCard` round-trips through these helpers unchanged (unknown fields pass through).
