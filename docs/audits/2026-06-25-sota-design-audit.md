# ADP SOTA-Design Audit — Is ADP built to (or ahead of) the standard?

**Date:** 2026-06-25
**Scope:** ADP's own protocol design, audited axis-by-axis against the established
standards it would interoperate with. This is the **design** audit ("are we built the way
the best agentic/web protocols are built?") — distinct from the **integration-conformance**
audit (`2026-06-25-integration-conformance.md`), which asks "do our adapters match the
upstream specs they call."
**Method:** six parallel deep-dive agents, one per design axis, each comparing the live ADP
implementation against the normative standard and returning an *adopt / wrap / defensibly-differ*
verdict with alignment cost and signed-bytes/version-break impact.
**Status:** findings only — no code changes made (operator decision; publishing remains on hold).

---

## One-line verdict

ADP's cryptographic, canonicalization, and **conformance** core is genuinely SOTA-grade — and
on one dimension (differential cross-language fuzzing) ahead of the entire field, including
W3C VC and the IETF — but it is **wire-incompatible** with every ecosystem it names in its own
keywords, and carries **two latent lifecycle gaps** (key rotation, schema drift) that are bugs,
not design choices. None of the divergences are *crypto* mistakes; they are *packaging* and
*governance* gaps.

The recurring pattern across all six axes: **we independently re-derived the right primitive,
then wrapped it in a bespoke envelope no standard library can read.**

---

## Per-axis scorecard

| Axis | Verdict | Move | Breaks signed bytes? |
|---|---|---|---|
| 1. Canonicalization vs RFC 8785 (JCS) | Accidentally JCS-equivalent for our value domain | Adopt the name + harden vectors | **No** — zero fixture regen |
| 2. Selective disclosure vs SD-JWT (RFC 9901) | Re-derived SD-JWT; weaker on 3 privacy props, stronger on 1 (ZK range) | Add SD-JWT-VC as alternate wire (additive) | No (new encoding) |
| 3. Signing envelope vs JOSE/JWS + RFC 9421 | Bespoke flattened-JWS-that-lost-its-header; identical crypto, custom packaging | Adopt flattened JWS (EdDSA); handshake → RFC 9421 | **Yes → v2** (dual-encode) |
| 4. Identity vs W3C DID/VC | On the 2026 SOTA frontier (AIP rejected DIDs too); real flaw = agentId==key can't survive rotation | Wire the existing rotation chain into verify (additive); DID-complement not DID-native | No (fix A) / Yes (full decouple) |
| 5. Schema / versioning / extensibility | Real, measured drift across 5 ports; no version negotiation; no extension namespacing | Enum cases in negative.json (hours) → JSON Schema source + codegen | No |
| 6. Governance + conformance rigor | Governance weak (vendor repo, one mechanical step from an IETF I-D); conformance ahead of the direct competitive set | File `draft-*-adp-disclosure-00`; lead with conformance | No |

**Keystone insight:** **RFC 8785 (JCS) is the unlock.** Adopting it by name is *free* (axis 1
proved our bytes already match) and is simultaneously the prerequisite that makes three other
axes standard at once — the JWS envelope signs over JCS, the W3C VC proof becomes a real
`eddsa-jcs-2022` `DataIntegrityProof`, and the SD-JWT-VC bridge canonicalizes cleanly. Rename
first; the rest of the interop story stops being bespoke.

---

## Axis 1 — Canonicalization vs RFC 8785 (JCS)

**Verdict: accidentally JCS-equivalent in all but name, for ADP's actual value domain.**

The JS reference `canonicalize` (`src/attestation.ts:79-94`) leans on `JSON.stringify`
(ECMAScript `Number::toString`) for scalars and `Object.keys().sort()` (UTF-16 code-unit order)
for keys — which is *exactly* what JCS mandates. Every rule that matters (key sort, integer/float
formatting, short escapes `\b\t\n\f\r`, lowercase `\uXXXX`, unescaped `/`, raw non-ASCII, compact
whitespace, UTF-8 output) is byte-identical to a conformant JCS implementation. The feared
"`JSON.stringify` ≠ JCS numbers" gap does not exist *in JavaScript* (both share the same
ECMAScript algorithm). Every vector in `conformance/vectors.json` is JCS-identical.

The only true divergences are JS-domain concepts JCS never sees: the `undefined`-key drop
(correct and necessary for canonicalizing in-memory objects pre-parse) and `NaN`/`Infinity`
(unreachable in the schema). Both are outside JCS's domain, not violations of it.

**The real risk is cross-language, and our conformance gate is currently blind to it.** All our
canonicalization vectors use ASCII keys. A native port that sorts by **code-point** (naive Python
`sorted()`, Go byte-order) instead of **code-unit** passes our suite but produces un-verifiable
signatures cross-stack on supplementary-plane keys. Concrete failing case: keys `{"😀":1, "דּ":2}`
— JCS/our-JS put the emoji first (`D83D < FB33`); a code-point port puts Hebrew first → different
bytes → signature breaks. Same story for exponential-notation numbers (`1e+21`) on ports that use
`strconv`/`repr` instead of ECMAScript `Number::toString`.

**Recommendation — adopt JCS as the named profile.** Rename `adp-canonicalize-2024` → "RFC 8785
(JCS)" in `SPEC.md` and the envelope, plus a thin profile note (our `undefined`-drop; no
`NaN`/`Infinity`). **Cost: hours. Breaks no signatures, regenerates no fixtures** — the JS bytes
are already JCS. Independently and at higher priority, **extend `conformance/vectors.json` with
the non-ASCII key-sort and exponential-number cases** (importable from the cyberphone JCS test
suite) — this proves the native ports are JCS-*correct* rather than coincidentally-correct, and
is the single highest-value change on this axis. Adopting the name also buys the IETF spec
reference and that ready-made cross-language test suite.

---

## Axis 2 — Selective disclosure vs SD-JWT (RFC 9901) / SD-JWT-VC

**Verdict: a correct, independently-sound re-derivation of SD-JWT — weaker on three
privacy/replay properties, stronger on one — and wire-incompatible with the SD-JWT ecosystem.**

ADP's `redaction.ts` core (`commit = sha256(canonicalize(value) + ":" + salt)`, 128-bit salt,
reveal-subset, verifier-recomputes, signature covers the full committed set) is the SD-JWT
pattern re-derived. Same core security: hiding via 128-bit salt, binding via SHA-256, integrity
via an asymmetric signature.

**Weaker than SD-JWT on three properties:**
- **Withheld field *names* leak** — `commitments` keeps the field name as a visible map key
  (`"redTeam"`, `"systemPrompt"`), so a verifier learns *which* fields exist but were withheld.
  SD-JWT hides the name inside the Disclosure.
- **No decoy digests** — SD-JWT pads `_sd` to obscure the *count* of hidden claims; ADP reveals
  both the names and the exact number.
- **No presentation-to-verifier binding** — a `RedactedView` is replayable; nothing ties the
  revealed subset to a verifier/nonce. SD-JWT's KB-JWT (`{iat, aud, nonce, sd_hash}`) closes
  exactly this. ADP's `handshake.ts` binds *liveness + audit head* but **not the disclosed
  subset** — so the two should converge.

**Stronger on one:** `zkDisclosure.ts` real Pedersen/secp256k1 ZK range proofs (`>=`/`<=`/range)
— SD-JWT has no predicate-disclosure equivalent at all. (Caveat: the Pedersen commitment isn't
yet algebraically bound to the SHA-256 disclosure commitment — circuit is an open item.)

**Recommendation — add SD-JWT-VC as an alternate wire encoding (additive, not rip-and-replace).**
A new `src/sdjwtvc.ts` (sibling to `vc.ts`): header `{typ:"dc+sd-jwt", alg:"EdDSA"}`, reuse the
agent's Ed25519 key as an OKP JWK, `vct` type id, self-issued `cnf` = the agent key, the 9
`REDACTABLE_FIELDS` → `_sd` Disclosures (this *automatically fixes the name-leak*), decoy padding
(fixes count-leak), and a KB-JWT at presentation folding in the handshake nonce (fixes
replay-binding). Keep the native form as the audit-chain default; offer SD-JWT-VC by content
negotiation — exactly the dual-encoding `vc.ts` already models. Gains instant EUDI / OpenID4VC /
AP2 wallet interop. The ZK path has no SD-JWT home — carry it as an out-of-band attachment.
**Cost: medium, additive. No signed-bytes break.**

---

## Axis 3 — Signing envelope vs JOSE/JWS (EdDSA, RFC 8037) + RFC 9421

**Verdict: the `{algorithm, publicKey, value}` envelope is a non-standard reinvention of a
flattened JWS that lost its protected header. The crypto is correct; the packaging is gratuitously
custom and no JOSE library can parse it.**

JOSE fully supports Ed25519 via `alg:"EdDSA"` (RFC 8037) — the *identical* RFC 8032 primitive ADP
already calls — so there is **zero cryptographic justification** for the custom envelope. Three
deviations: (1) `algorithm` is a Zod literal *outside* the signed bytes (JWS puts `alg` inside the
signed protected header, defeating algorithm-substitution); (2) ADP signs `canonicalize(disclosure)`
directly rather than `b64(header).b64(payload)`; (3) hex everywhere instead of base64url.

- **Handshake** (`handshake.ts`) is conceptually RFC 9421 (nonce, key possession, freshness via
  `signedAt`+`maxAgeMs`, verifier binding via `verifierId` ≈ 9421's `tag`) — but signs a
  canonical-JSON blob instead of an HTTP signature base, and carries the proof in a body object
  rather than `Signature`/`Signature-Input` headers. **Not wire-interoperable with TAP/HTTP-signing**
  — even though `OperatorIdentitySchema.attestation.scheme` already lists `"VisaTAP"`.
- **VC bridge** (`vc.ts`) is honest about non-URDNA2015 canonicalization but **squats the
  registered `Ed25519Signature2020` `type`** while shipping a hex `proofValue` over ADP-canonical
  JSON that no conformant DI verifier will accept — and it only "verifies" by delegating back to
  ADP's own verifier. This is a correctness liability, not just interop.

**Recommendation — represent `SignedDisclosure` as a flattened JWS (EdDSA)** with payload
canonicalized via JCS (axis 1), derive `agentId` from `header.jwk.x` to keep the self-certifying
binding; **align the handshake to RFC 9421** (sign a signature base over `nonce`/`created`/`keyid`/
`tag`/audit-head, carry in `Signature`/`Signature-Input`); **fix the VC bridge** to a real
`eddsa-jcs-2022` `DataIntegrityProof` with multibase `proofValue` (you already have JCS +
base58btc) or stop using the registered type name. **Cost: medium-high. Breaking on the wire →
v2** (`{disclosure,signature}` → `{payload,protected,header,signature}`; body → headers), but the
crypto primitive is unchanged, so v1/v2 can **dual-encode** through a transition; `versioning.ts`
is the seam. Changes are concentrated in `attestation.ts`/`schema.ts`/`handshake.ts`/`vc.ts`; the
~30 consumer modules inherit it via `verifyDisclosureSignature` if its signature stays stable.

---

## Axis 4 — Identity vs W3C DID / DID Document / VC Data Model 2.0

**Verdict: SOTA-frontier on encoding, behind on lifecycle. Do NOT go DID-native.**

The strongest external signal: **AIP (arXiv 2026), the newest agent-identity protocol, explicitly
*rejected* W3C DIDs** for the hot path and independently reinvented ADP's exact two-scheme model
(`aip:key:ed25519:<multibase>` ≈ our did:key, `aip:web:<domain>` ≈ did:web). ADP's `did:key`
encoding is byte-correct per spec (`0xed01` multicodec, `z` base58btc, `did.ts:16`). The field is
voting *against* mandatory DID-nativeness — so "make it DID-native" is **not** a SOTA requirement;
we already converged where the field landed.

**The one real flaw is lifecycle: `agentId` IS the signing key** (`attestation.ts:118` hard-binds
`agentId === signature.publicKey`), so it **cannot survive key rotation**. ADP *half-knows this* —
`keys.ts` ships a signed `RotationStatement` chain, but it is **orphaned from identity**: after
rotation the agent mints disclosures under a new `agentId`, and every cached reference points at a
dead identity. For a long-lived agent (Gordon is exactly that), an identifier that dies on every
rotation is a genuine design hole. (did:key wouldn't fix it — it's also key-derived; **did:web**
or an internal indirection layer is the fix.)

**Recommendations (keep raw-key + bridge; fix the lifecycle):**
- **A. Decouple identity from the signing key.** *Minimal/additive:* wire `keys.ts`'s rotation
  chain into `verifyDisclosureSignature` (accept a signature from any key in a verified chain
  rooted at `agentId`, carry the `RotationStatement[]` in the envelope) — counterparties verify
  continuity automatically instead of out-of-band. *Full/breaking:* a stable `did:web` `agentId`
  with a separate `currentKey`, rotation updates the key not the id (recommended for Gordon's
  long-lived case; bump `DISCLOSURE_SCHEMA_VERSION`).
- **B.** Emit a real DID Document with a `service` entry pointing at `.well-known/agent-disclosure`
  (additive ~60 LOC) — any DID-aware verifier resolves to the disclosure via standard rails.
- **C.** Bump the VC bridge to **VC 2.0** (`@context` → `…/credentials/v2`, `issuanceDate` →
  `validFrom`/`validUntil`). ~10 LOC, additive.
- **D.** Add `"did"` to `OperatorIdentitySchema.attestation.scheme`. 1 line.

**Cost: A-minimal/B/C/D additive; A-full breaking.** Bottom line: go DID-*complementary* and
rotation-stable, not DID-native.

---

## Axis 5 — Schema-as-source, versioning, extensibility

**Verdict: behind SOTA, with confirmed (not hypothetical) drift already present across the five
implementations.**

There is **no JSON Schema source-of-truth and no codegen** — `src/schema.ts` (zod) is normative
for TS only; the four native ports hand-roll validation, and the grammar has **measurably
diverged**:

| Constraint | TS (zod) | Rust | Go | Python | C |
|---|---|---|---|---|---|
| `version == 1` literal | ✅ | ✅ | ✅ | ❌ | ❌ |
| `sha256` literal | ✅ | ✅ | ❌ | ❌ | ❌ |
| `custody` enum | ✅ | ✅ | ❌ | ❌ | ❌ |
| `access`/`period`/`kind`/`scheme`/`level` enums | ✅ | ❌ | ❌ | ❌ | ❌ |

A disclosure with `access:"banana"` or `version:2`-as-honestly-signed passes every native
verifier (the signature checks out because the emitter signed exactly those bytes). The ports lean
on the signature as a substitute for schema validation — which catches *tampering* but not a
*malformed-but-honestly-signed* document. **`conformance/negative.json` has no invalid-enum-value
cases, so CI is blind to exactly the dimension that drifted.**

Two forward-looking gaps: **no version negotiation** (literal-1 + `peek`; the handshake binds
liveness but not protocol version — MCP/x402/ACP all negotiate by round-trip) and **no
namespaced extension model** (closed zod object + fixed `scheme` enum → a third party can't add a
field/scheme without a 5-way re-port; UCP's reverse-domain `com.vendor.*` is the pattern).
`stability.md`'s "optional fields canonicalize away → minor-version-safe" reasoning is genuinely
correct and worth keeping.

**Recommendations (in priority order):**
1. **Add invalid-enum cases to `negative.json`** (`access:"banana"`, `period:"fortnight"`,
   `scheme:"unknown"`, `version:2`). **Cost: ~1 hour.** Makes the existing 5-language drift
   CI-visible immediately — cheapest highest-value change in the whole audit.
2. **JSON Schema 2020-12 as source** → generate zod (`z.toJSONSchema()`) + wire a JSON-Schema
   validator into each port (`santhosh-tekuri/jsonschema`, Python `jsonschema`, Rust `jsonschema`,
   C codegen). Ports keep hand-written *policy*/*canonicalization*; only the field grammar becomes
   generated. **Cost: ~2-3 days. No signed-bytes break.**
3. **Handshake version negotiation** — `Challenge.supportedVersions` + refuse-with-reason on no
   mutual version (MCP `initialize`, adapted). Additive optional field.
4. **Namespaced extensions** — an `extensions`/`experimental` bucket + convert `attestation.scheme`
   to a namespaced string. Additive.

None touch the frozen canonicalization/signing contract.

---

## Axis 6 — Governance + conformance rigor

**Verdict: governance is the weak axis; conformance is the strong axis — genuinely ahead of the
entire direct competitive set, matched only by W3C VC.**

**Governance:** ADP is a single-vendor GitHub repo (MIT, © General Liquidity) with an
unusually RFC-shaped `SPEC.md` (RFC 2119 keywords, normative tables, Security Considerations,
informational IANA/well-known section, worked byte-exact examples). It is **not** on a standards
track. The three real paths and where the field sits:

| Path | Body | Entry | Live examples |
|---|---|---|---|
| IETF I-D → RFC | IETF | write an I-D, submit to datatracker — no fee/membership | RFC 9421 (final); MPP = `draft-ryan-httpauth-payment` (stage 1) |
| EIP/ERC | Ethereum | PR to `ethereum/ERCs` per EIP-1 | ERC-8004 "Trustless Agents" (still Draft) |
| Donate to a foundation | LF / FIDO | contribute spec+IP under a charter | A2A (LF), x402 (LF, Apr 2026), MCP (LF + BDFL), AP2 (FIDO) |

The donate-to-foundation path dominates the 2026 wave, but a foundation standard is *governance*-
neutral, not *adversarially ratified* (only RFC 9421 here is fully ratified). **The right path is
split by layer:** the wire format (canonicalization, ed25519 signing, freshness, handshake,
well-known URI) → **IETF Internet-Draft** (RFC 9421 is the natural normative reference; the
`/.well-known/agent-disclosure` path needs an RFC 8615 registration, an IETF/IANA action); the
ERC-8004 binding → **comment on the ERC-8004 Magicians thread** as the verification layer it
defers, *not* a competing ERC; a foundation → premature until ≥2 independent implementations exist.

**Concrete next step:** reformat `SPEC.md` into `draft-gl-adp-disclosure-00` (add Abstract,
Terminology, Normative/Informative References, promote §13 to a normative IANA Considerations
requesting the `agent-disclosure` well-known URI). ~1-2 days mechanical on an already-RFC-shaped
doc; submitting confers a citeable "I-D Exists" status — the same stage MPP occupies.

**Conformance rigor (honest ranking, most → least):**

| Rank | Protocol | Differential fuzzer | Byte-identical cross-lang signing gate | MUST-REJECT corpus | Live cross-process CI |
|---|---|---|---|---|---|
| 1 | **W3C VC** | ❌ | ✅ best-in-class (rdf-canon 86 cases × 11 impls) | ✅ thin | ✅ opt-in |
| 2 | **ADP (ours)** | ✅ **200 cases** | ✅ 20 cases × 5 langs | ✅ 12 cases | ✅ **default PR gate** |
| 3 | MCP | ❌ | ❌ (nothing signed) | ⚠️ | ⚠️ per-SDK |
| 4 | UCP | ❌ | ❌ (mandates RFC 9421+JCS, ships **zero** vectors) | ⚠️ | ✅ single-impl |
| 5 | x402 | ❌ | ❌ | ❌ | ⚠️ manual |
| 6 | ACP (Zed) | ❌ | ❌ (signing named, undefined) | ❌ | ❌ |
| 7 | AP2 | ❌ | ❌ (SD-JWT, untested) | ❌ | ❌ |

- **The differential canonicalization fuzzer is unique across the *entire* field** — not x402, AP2,
  MCP, ACP, UCP, and *not even W3C VC or RFC 9421* ship one.
- Cross-implementation verification is our **default PR gate**, not an opt-in flag (W3C VC) or
  manual dispatch (x402).
- Only **W3C VC out-ranks us overall** — rdf-canon's broader corpus (8 langs vs our 5) + the
  institutional 2-independent-implementation Candidate-Recommendation exit gate a single vendor
  can't replicate.

**Messaging guidance:** lead with the conformance differentiator. The sharpest true line:
*"UCP and ACP mandate or name signing/canonicalization in spec text and ship zero test vectors and
no implementation. ADP defines the canonical bytes and proves them byte-identical across five
languages on every commit."* Do **not** claim to out-rigor W3C VC wholesale; frame ADP as *"aligned
with the W3C bar, plus a differential fuzzer none of them have."* Honest and stronger than an
overclaim a reviewer can puncture.

---

## Consolidated roadmap (lens-2 alignment)

**Tier 0 — free, hours, no break, do regardless:**
1. Rename `adp-canonicalize-2024` → "RFC 8785 (JCS)" + profile note. *(axis 1; zero signature change)*
2. Add non-ASCII key-sort + exponential-number vectors to `vectors.json`. *(axis 1; proves ports JCS-correct)*
3. Add invalid-enum cases to `negative.json`. *(axis 5; makes existing drift CI-visible)*

**Tier 1 — additive, low/med, no signed-bytes break:**
4. Wire the `keys.ts` rotation chain into `verifyDisclosureSignature`. *(axis 4 — the one real identity flaw)*
5. JSON Schema 2020-12 source → generate zod + native validators. *(axis 5 — kills drift structurally)*
6. VC bridge → VC 2.0 + real `DataIntegrityProof`/multibase; emit DID Document `service`; add `did` scheme. *(axes 3/4)*
7. Handshake version negotiation + namespaced extension bucket. *(axis 5)*
8. File `draft-gl-adp-disclosure-00` + comment on the ERC-8004 Magicians thread. *(axis 6)*

**Tier 2 — breaking, v2-gated, dual-encode transition:**
9. Flattened JWS (EdDSA) envelope + RFC 9421 handshake. *(axis 3 — same crypto, new wire)*
10. SD-JWT-VC alternate encoding (brings name-hiding + decoys + KB-JWT binding). *(axis 2)*
11. Full identity decouple (`agentId` ≠ key via did:web). *(axis 4 — only if agents are long-lived; Gordon's are)*

---

## Key files cited

- `src/attestation.ts` — `canonicalize` (`:79-94`), `signMessage`/`verifyMessage`, `agentId===publicKey` (`:118`)
- `src/schema.ts` — `SignedDisclosureSchema` (`:199-208`), `DISCLOSURE_SCHEMA_VERSION` (`:17`), `attestation.scheme` enum (`:103`)
- `src/handshake.ts` — challenge-response (liveness + audit head; not subset/version binding)
- `src/redaction.ts` — salted-commitment core; `src/zkDisclosure.ts`/`src/zkRange.ts` — ZK range path
- `src/did.ts` — byte-correct did:key + base58btc; `src/vc.ts` — VC 1.1 bridge, `Ed25519Signature2020` type squat
- `src/keys.ts` — orphaned signed-rotation chain (the unwired fix for the identity flaw)
- `src/versioning.ts` — literal-1 + peek (the version-negotiation seam)
- `conformance/{vectors,interop,negative,fuzz}.json` — the cross-language gate; `vectors.json` + `negative.json` are the two with coverage holes
- `SPEC.md` §1/§3.11/§11/§12/§13 — the RFC-shaped spec that is ~80% of an Internet-Draft
