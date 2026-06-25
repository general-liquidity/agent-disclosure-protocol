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

## Sign-In-With-Agent / SIWA (`src/siwa.ts`)

[SIWE (EIP-4361)](https://eips.ethereum.org/EIPS/eip-4361) is "Sign-In With Ethereum" — a
human-readable message a wallet signs to authenticate to a relying party. **SIWA** is the
same shape with an *agent* account as the subject: its `(address, agentRegistry, agentId)`
triple is exactly an [ERC-8004 binding](./signing-and-identity.md) — the operational wallet, the CAIP-10
registry (`eip155:<chainId>:<registry>`), and the ERC-721 `agentId` tokenId. ADP already owns
that binding (`erc8004.ts` mints the agent→wallet claim, `erc8004Onchain.ts` recovers a wallet
from an EIP-191 signature, `erc8004Registry.ts` reads `ownerOf`), so it both **mints** a SIWA
message describing a disclosed agent and **verifies** one the wallet signed.

`formatSiwaMessage` / `parseSiwaMessage` render and parse the signed text:

```
{domain} wants you to sign in with your Agent account:
{address}

{statement}

URI: {uri}
Version: 1
Agent ID: {agentId}
Agent Registry: eip155:{chainId}:{registry}
Chain ID: {chainId}
Nonce: {nonce}
Issued At: {issuedAt}
```

with optional `Expiration Time:`, `Not Before:`, `Request ID:` lines appended after `Issued At`.
`disclosureToSiwaMessage(signed, opts)` builds the structured message from the agent's binding
fields (wallet / registry / tokenId) carried in `opts`.

`verifySiwa(msg, signature, opts)` does the structural checks (domain matches `expectedDomain`,
the nonce is ≥ 8 alphanumeric chars **and** accepted by `opts.nonceValid`, the registry is a
CAIP-10 `eip155` id, `issuedAt` / `expirationTime` / `notBefore` bound the window), then
**EIP-191 recovers** the signer (reusing `erc8004Onchain`'s secp256k1 path) and requires it
equals the message `address` → **`signed`**. When an `opts.resolveRegistry` (`ownerOf`) seam is
injected and the registry's owner for the agentId equals the signer, the result escalates to
**`registry_attested`**. `verifySiwaAgainstDisclosure` additionally asserts the SIWA `address`
and `agentId` match the disclosure's ERC-8004 binding, so a counterparty knows the login and the
disclosure describe **one** agent, not two stitched together.

The secp256k1 recovery is the optional `@noble` extra (lazy import, the same pattern as the rest
of the on-chain surface); minting and parsing are pure, and the registry tier is an injected seam
— ADP bundles no chain client.

## Proof-of-personhood attestation schemes

Three schemes recognize a **human** (or a unique human, or a humanity-reputation score)
behind the operator, recorded in a disclosure's `operator.attestation` field. None is locally
verifiable dep-free — each delegates the heavy half (a ZK proof check, an on-chain read, an
API/EAS score fetch) to an **injected seam** while ADP does the **structural** validation and
the level mapping. Each maps to a **reverse-domain** scheme id because the attestation
`scheme` enum in `schema.ts` is frozen — they are recognized through the schema's open
reverse-domain arm, **not** a core enum edit: Self → `xyz.self`, World ID → `org.world`,
Human Passport → `tech.human.passport`.

### Self / proof-of-personhood (`src/self.ts`)

[Self](https://self.xyz) (self.xyz) proves a real human is behind an identity with a
zero-knowledge proof over a government passport/ID (NFC read + zk-SNARK), disclosing only
selected predicates — "over 18", "nationality", "not on an OFAC list" — without revealing the
document. Its agent path (`selfxyz/self-agent-id`) is itself ERC-8004-based, so the on-chain
reference reuses the same registry seam ADP already has.

Full verification (the Groth16 proof + a Celo on-chain `isVerifiedAgent` read) needs
`@selfxyz/core` + an RPC — **not** dep-light. So this bridge does **light recognition + an
injected verifier seam**, exactly how ADP treats ERC-8004. Two attestation shapes are modeled:
`SelfOnchainRef` (a chain registry reference — `chainId`, `registry`, `agentId`, `nullifier`)
and `SelfOffchainResult` (an off-chain proof result — `attestationId`, `scope`, `nullifier`,
`isValidDetails`, and the disclosed attributes).

`verifySelfAttestation(att, opts?)` does **structural** validation always: required fields
present, shapes correct, and for an off-chain result the embedded `isValidDetails.isValid` must
be true. **The OFAC flag is inverted** — `isOfacValid === true` means the subject **IS** on a
sanctions list — so a sanctioned subject is **rejected** (`ok: false`). An on-chain ref carries
no self-contained proof, so without a verifier it is shape-only and not accepted. When
`opts.verifier` is supplied (the consumer wiring `@selfxyz/core` or an `isVerifiedAgent` reader),
its `valid === true` is additionally required and its `nullifier` surfaced. On success the
nullifier and disclosed attributes are returned.

`selfToOperatorAttestation(att, result)` maps a verified attestation into ADP's
`operator.attestation` field: a verified on-chain ref is `registry_attested`, a verified
off-chain result is `signed`, a failure is `none`. The scheme is the reverse-domain
`xyz.self` (`SELF_ATTESTATION_SCHEME`) — the attestation `scheme` enum in `schema.ts` is frozen,
so Self is recognized through the schema's open reverse-domain arm, **not** a core enum edit.

### World ID / proof-of-personhood (`src/worldid.ts`)

[World ID](https://world.org) (Worldcoin) proves a **unique human** is behind an action with a
Groth16 zero-knowledge proof over a Semaphore membership tree: the person's World ID is a leaf,
the proof shows membership without revealing which leaf, and a per-(person, action)
`nullifier_hash` makes a second submission for the same action detectable (the sybil key)
without linking it to identity. The `verification_level` grades credential strength: `orb` (an
iris-scanned unique-human credential), `device`, `secure_document`, `document`.

Full verification is a Groth16 proof check against a live merkle root — the Developer Portal
`/verify` call or the on-chain **World ID Router** — **not** locally checkable dep-free. So this
bridge does **structural** validation (`validateWorldIdStructural`: the `WorldID` scheme, an
`app_`-prefixed `app_id`, a non-empty `action`, hex `nullifier_hash` / `merkle_root` / `proof`,
and a known `verification_level`) plus an **injected verifier seam**.

`verifyWorldId(att, opts?)` returns `{ structural, valid, nullifier?, reason? }`. **Without** a
verifier the result is `{ structural: true, valid: false, nullifier }` — crypto-pending, fully
representable, it does **not** throw, and the nullifier is surfaced so a consumer can do sybil
bookkeeping on the structurally-valid claim. **With** `opts.verifier` (the consumer wiring the
`/verify` call or the on-chain router), its `valid` is the answer and its `nullifier` is surfaced.
`worldIdToOperatorAttestation` maps a verified `orb` proof to `registry_attested` (the anchored
unique-human credential) and any other verified level to `signed`; a non-verified proof is `none`.
The scheme is the reverse-domain `org.world` (`WORLDID_ATTESTATION_SCHEME`).

### World Agent / human-backed agent (`src/worldagent.ts`)

[worldcoin/agentkit](https://github.com/worldcoin/agentkit) verifies that an autonomous agent is
**backed by a real, World ID-verified human**. The agent's wallet is registered — via a World ID
proof — in an on-chain **AgentBook** that maps the agent wallet to the **nullifier of the unique
human** who registered it. Accountability flow: a server challenges the agent to sign a **CAIP-122
/ SIWE (EIP-4361)** message; the verifier recovers the signer (EIP-191 / `personal_sign`), requires
it to equal the claimed agent wallet, then looks the wallet up in AgentBook to confirm it is
human-backed and to surface the human nullifier. This is agent↔human accountability — ADP's exact
thesis. (Distinct from World ID above: World ID proves *a human*; World Agent proves *an agent has a
human behind it*, recorded on-chain — hence the sibling scheme id `org.world.agent`.)

Recovering the signer needs secp256k1 + keccak (the same optional `@noble` extras `erc8004Onchain.ts`
uses — `recoverWalletAddress` is reused directly), and the AgentBook lookup
(`lookupHuman(address) -> uint256`, `0` ⇒ unregistered) is an on-chain `eth_call` — **not** something
ADP bundles. So this bridge does **structural** validation (`validateWorldAgentStructural`: the
`WorldAgent` scheme, a `0x`+40-hex `address`, a 65-byte `signature`, a non-empty `message`), EIP-191
**signer recovery** against the claimed wallet, and an **injected `AgentBookResolver` seam** for the
human-backing read.

`verifyWorldAgent(att, opts?)` returns `{ structural, valid, address?, humanBacked, nullifier?, reason? }`.
The signature half always runs (dep-permitting) — a malformed signature or a signer mismatch is
`{ valid: false }`, never a throw. **Without** a resolver the signature can be valid (the agent
controls the wallet) but `humanBacked` is `false` — the on-chain registration is unconfirmed.
**With** `opts.resolver` (the consumer wiring the AgentBook `lookupHuman` `eth_call`), a
`registered: true` result sets `humanBacked: true` and surfaces the registering human's nullifier.
`worldAgentToOperatorAttestation` maps a human-backed agent to `registry_attested` (a real human is
recorded on-chain behind it), a wallet-controlled-but-unregistered one to `signed`, and a
non-recovering signature to `none`. The scheme is the reverse-domain `org.world.agent`
(`WORLDAGENT_ATTESTATION_SCHEME`); `AGENT_BOOK_ADDRESS`
(`0xA23aB2712eA7BBa896930544C7d6636a96b944dA`, World Chain) and `WORLDCHAIN_ID` (480) are exported
for a consumer defaulting the resolver to the canonical deployment.

### Human Passport / humanity score (`src/humanpassport.ts`)

[Human Passport](https://passport.human.tech) (formerly Gitcoin Passport) aggregates many
identity **stamps** — each a verified credential — into a single **Unique Humanity Score**. A
score at or above a chosen threshold (the canonical default is **20**, `HUMAN_THRESHOLD`) marks
an address as *passing* / likely-unique; each stamp carries a weight and a `dedup` flag. The
score is fetched from the Passport API (an `X-API-KEY` call) or read on-chain via EAS — **not** a
local computation. **Gotcha:** the API returns `score` / `threshold` as numeric **strings**; this
module stores them as **numbers**, and the consumer's injected scorer is the boundary that parses
them.

`verifyPassportAttestation(att, opts?)` does structural validation (`validatePassportAttestation`:
the `HumanPassport` scheme, a `0x`+40-hex `address`, finite `score` / `threshold` when present)
always. **With** `opts.scorer` it fetches the live score and recomputes `passing` against the
threshold; **without** one it falls back to the embedded `score` / `passing` — representable, it
does **not** throw. `passportToAdpLevel(score, threshold)` bands the score: `>= 1.5×` the
threshold is `high`, `>= 1×` is `medium`, a present-but-below score is `low`, and an absent score
is `unverified`. `passportToOperatorAttestation` maps a passing attestation to `signed` (a
reputation attestation, not a registry record) with the band + score as `evidence`, and a
non-passing one to `none`. The scheme is the reverse-domain `tech.human.passport`
(`HUMANPASSPORT_ATTESTATION_SCHEME`).

## Other ecosystem standards (no new code)

Three further agent-ecosystem standards relate to ADP but need **no new bridge** — they either
already resolve through the bridges above, or are orthogonal. They are recorded here so the
positioning is explicit.

- **Eclipse LMOS** resolves agents via **`did:web`** and defines a `VerifiableCredentialService`
  entry in the agent's DID document. ADP already emits both halves — [`did`](./signing-and-identity.md)
  (`didWeb` + the DID document with an `AgentDisclosure` service entry) and [`vc`](#w3c-verifiable-credential-20-srcvcts)
  (the disclosure as a W3C VC). So an ADP disclosure is a **drop-in credential** for LMOS's slot:
  ADP supplies the *disclosure schema* (capital / custody / operator / attestation), LMOS supplies
  the *identity envelope*. No new module — wire `toVerifiableCredential` output into the
  LMOS `VerifiableCredentialService` endpoint.
- **IAB Tech Lab AAMP** (Agentic Advertising Management Protocols) declares agent identity through a
  **centralized hosted Agent Registry** and carries no capital/custody/financial-attestation fields.
  ADP is the **decentralized, self-served, cryptographically-signed complement** — "`sellers.json`
  for autonomous agents, but signed at `/.well-known/agent-disclosure`." An AAMP registry entry can
  *reference and verify against* an ADP disclosure for the financial-trust dimension the registry
  omits; no protocol change is required on either side.
- **Agora** standardizes only a runtime-negotiated, SHA-1-referenced *communication* layer (protocol
  documents) with **no identity, attestation, or payment surface**. It is **orthogonal** to ADP —
  there is nothing to bridge; ADP's disclosure check sits above whatever transport (Agora included)
  two agents negotiate.
