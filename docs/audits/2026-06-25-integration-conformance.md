# Integration-Conformance Audit — ADP & OpenSolvency adapters vs upstream specs

**Date:** 2026-06-25
**Scope:** the **integration** lens — do ADP's and OpenSolvency's adapters faithfully implement
the upstream protocol specs they call (x402, AP2, Agentic Commerce, UCP, MPP, Visa Intelligent
Commerce, Visa Trusted Agent Protocol, Mastercard Agent Pay, ERC-8004, MCP, Agent Client Protocol,
ERC-20/EIP-3009, Stripe Issuing)? Distinct from the **design** lens
(`2026-06-25-sota-design-audit.md`), which audits ADP's *own* protocol design against the
standards.
**Method:** parallel deep-dive agents, each pulling the upstream org's repos/specs and diffing
against our adapter code.
**Status:** findings only — no code changes made (publishing on hold). Severities: **CRITICAL**
(adapter is fictional / will not work against real counterparties), **INTEGRITY** (compiles and
"works" but a claimed security property is not actually enforced), **CORRECTNESS** (wrong
behavior / inverted logic), **COSMETIC** (naming/labelling).

> **OpenSolvency rail findings live in that repo:** `opensolvency/docs/audits/2026-06-25-rail-conformance.md`.
> This document covers the **ADP-side** integration item (ERC-8004) in full and summarizes the
> OpenSolvency rail verdicts for cross-reference.

---

## ADP-side finding — ERC-8004 registry client is fictional (CRITICAL) + a positioning upgrade

`src/erc8004Registry.ts` calls an **invented ABI**: `agentOf(address) returns bytes32`. That
function **does not exist in ERC-8004**, and the data model is wrong in two ways:
- ERC-8004's agent identifier is a **`uint256` tokenId** (ERC-721-style registration), **not** a
  32-byte value, and **not** an ed25519 key. Our client treats it as a `bytes32` it can equate to
  an agent's ed25519 `agentId`.
- There is no forward resolution from an EOA `address` to an agent record of the shape we assume.

As written, the client cannot work against the real ERC-8004 Identity Registry. It must be
reworked around the actual registration model (tokenId-keyed records, the registry's real getters)
before it can be claimed as an ERC-8004 integration.

**The same finding is a positioning *upgrade*.** The ERC-8004 Draft **does** specify a
verification layer we currently treat as missing: a **Validation Registry** with
`validationRequest` / `validationResponse` and a `uint8` 0–100 score. That means **ADP is not
"filling a hole" in ERC-8004 — it is a validator that plugs into a socket ERC-8004 already
defines.** The reframe:
- ADP composes with ERC-8004 as the *off-chain verification evidence* behind a
  `validationResponse`, rather than inventing an on-chain identity binding.
- Action: rework `erc8004Registry.ts` to the real identity model **and** add a Validation-Registry
  client path; position ADP in the ERC-8004 Ethereum-Magicians thread as the pluggable verification
  layer (this ties into the design audit's governance axis 6).

---

## OpenSolvency rail verdicts (summary — detail in the OpenSolvency repo)

| Protocol / adapter | Verdict | Severity |
|---|---|---|
| **AP2 content schemas** (`rails/ap2/`) | Field-exact against the upstream JSON Schemas — **the strongest adapter we ship** | ✅ conformant |
| **MCP** (`src/mcp/server.ts`, `opensolvency-mcp/`) | Real `@modelcontextprotocol/sdk` server, conformant | ✅ conformant |
| **Agent Client Protocol (Zed)** (`src/acp/`) | Conformant | ✅ conformant |
| **Visa Trusted Agent Protocol** (`identity/verifier.ts`) | Claims RFC 9421 but ships only a string-map `staticIdentityVerifier` — the attestation is **self-assertable**, the claimed signature verification is not actually performed | **INTEGRITY** |
| **x402** (`rails/x402.ts`, clients/proxy) | V1-shaped but **wire-incomplete** — missing required fields vs the live x402 header/payload format | CORRECTNESS |
| **UCP** (`rails/ucp.ts`) | A capability comment is **inverted** and the reversibility flag is **wrong** — and because the gate reads reversibility, this feeds a real **gate risk** (a reversible action mis-flagged as irreversible, or vice-versa) | CORRECTNESS (gate-affecting) |
| **onchainClient** (`rails/clients/onchainClient.ts`) | **Mislabeled** — does not do what its name/docs claim | COSMETIC→CORRECTNESS |
| **Stripe Issuing** | No real adapter behind the surface | CRITICAL (absent) |

### Cross-cutting

- **`RailKind` "checkout" routing collision** — multiple distinct rails map to the same
  `"checkout"` kind, so routing cannot disambiguate them. Needs distinct kinds or a sub-discriminator.
- **Two-ACP naming trap** — `src/rails/acp.ts` is the **Agentic Commerce Protocol** (OpenAI/Stripe),
  while `src/acp/` is the **Agent Client Protocol** (Zed). Same acronym, unrelated protocols,
  adjacent paths. High risk of a future contributor wiring one into the other. Rename one (e.g.
  `agentic-commerce/`) to break the collision.

---

## Priority order (integration fixes)

1. **Visa TAP integrity gate** (INTEGRITY) — either implement real RFC 9421 verification or stop
   claiming it; a self-assertable identity that the gate treats as verified is the most dangerous
   class of bug here.
2. **ERC-8004 rework + Validation-Registry reframe** (CRITICAL + positioning) — see above.
3. **x402 header/payload completion** (CORRECTNESS) — required before any real x402 counterparty.
4. **UCP reversibility/comment fix** (gate-affecting CORRECTNESS) — small change, real gate impact.
5. **RailKind "checkout" disambiguation** + **two-ACP rename** (cross-cutting) — cheap, prevents
   future mis-wiring.
6. **Stripe Issuing** — build the real adapter or remove the surface claim.

These compose with the design-audit roadmap at the same v2 boundary; nothing here is blocked by
the publish hold, since all of it lives on the public ADP repo / local OpenSolvency tree.
