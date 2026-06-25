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
