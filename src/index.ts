// The Agent Disclosure Protocol (ADP) - a vendor-neutral disclosure protocol for
// agent-to-agent commerce, and the wire format for Verifiable Agency. An agent
// exposes, BEFORE transacting, what it is committed to (its constitution, capital
// envelope, tool boundary, history, red-team posture); a counterparty verifies that
// disclosure and decides transact / refuse before a single unit of value moves.
//
// This package is the protocol + a reference verifier. It has ONE runtime
// dependency (zod) and uses only node:crypto for signing, so any agent stack can
// emit or verify a disclosure. OpenSolvency is the reference implementation that
// populates these structures from a live, enforced governance gate.
//
// See SPEC.md for the normative protocol and conformance/ for the test vectors.

// The disclosure document + signed envelope (zod schemas + inferred types).
export * from "./schema.ts";

// Attestation primitives: ed25519 signing, canonicalization, freshness. A
// counterparty verifies with the public key in the envelope - no shared secret.
export * from "./attestation.ts";

// The live challenge-response handshake (defeats identity replay).
export * from "./handshake.ts";

// Counterparty verification: evaluate a disclosure against a policy -> verdict.
export * from "./verify.ts";

// The verifier-side over-the-wire loop (fetch -> evaluate -> handshake -> decide).
export * from "./client.ts";

// Outbound disclose-before-settle + mutual disclosure.
export * from "./guard.ts";

// Tiered verification + a validity-window cache (the economic enabler).
export * from "./cache.ts";

// Selective / redactable disclosure (reveal only what a policy requires).
export * from "./redaction.ts";

// Revocation status list (revoke a compromised or decommissioned identity).
export * from "./revocation.ts";

// Transparency log - an append-only, third-party-auditable anchor.
export * from "./transparency.ts";

// The economic-viability model (which markets survive at verification cost C).
export * from "./economics.ts";

// Mutual disclosure over the wire (both agents verify each other before clearing).
export * from "./mutual.ts";

// Schema version negotiation.
export * from "./versioning.ts";

// Revocation transport (fetch + honor a status list over the wire).
export * from "./revocationTransport.ts";

// Transparency-log transport (publish + fetch + verify inclusion proofs).
export * from "./transparencyTransport.ts";

// ERC-8004 identity bridge (bind the ed25519 agentId to a wallet-anchored identity).
export * from "./erc8004.ts";

// Policy-driven selective disclosure (reveal exactly what a verifier's policy needs).
export * from "./negotiate.ts";

// Framework adapters (a verify-before-pay tool/guard for any agent framework).
export * from "./adapters.ts";

// Verifier-as-a-service (HTTP) + discovery (a .well-known fetcher + agent directory).
export * from "./verifierService.ts";
export * from "./discovery.ts";

// Key management (rotation, keyring, key files) + disclosure diffing / downgrade alarm.
export * from "./keys.ts";
export * from "./monitor.ts";

// W3C StatusList revocation + model-attestation envelope + a generic disclosure builder.
export * from "./statusList.ts";
export * from "./modelAttestation.ts";
export * from "./builder.ts";

// Transparency witness (append-only / split-view monitor).
export * from "./witness.ts";

// ERC-8004 on-chain bridge (secp256k1 wallet-signature recovery; optional @noble dep).
export * from "./erc8004Onchain.ts";

// ERC-8004 Identity Registry client (real ERC-721 tokenId model; optional viem dep).
export * from "./erc8004Registry.ts";

// ERC-8004 Validation Registry client (read validationResponse scores; optional viem dep).
export * from "./erc8004Validation.ts";

// ZK selective disclosure (interface + a dep-free equality backend).
export * from "./zk.ts";

// ZK range proofs (Pedersen + bit-decomposition over secp256k1; optional @noble dep).
export * from "./zkRange.ts";

// ZK range proofs as a disclosure feature (attach + require proofs about hidden attributes).
export * from "./zkDisclosure.ts";

// DID bridge (did:key / did:web for the agentId).
export * from "./did.ts";

// W3C Verifiable Credential bridge (a disclosure as a VC).
export * from "./vc.ts";

// SD-JWT-VC bridge (a disclosure as a selective-disclosure JWT VC: hidden field names,
// decoy digests, and KB-JWT presentation-to-verifier binding).
export * from "./sdjwtvc.ts";

// A2A Agent Card bridge (carry/extract/verify a disclosure on an A2A agent-discovery card;
// the disclosure envelope is the trust root, the card JWS is origin tamper-evidence).
export * from "./a2a.ts";

// Sign-In-With-Agent (SIWA) bridge - a SIWE-style login message anchored to an ERC-8004
// binding; EIP-191 recover + an injected ownerOf resolver -> signed / registry_attested.
export * from "./siwa.ts";

// Self (self.xyz) attestation scheme - ZK proof-of-personhood as an operator attestation
// (structural validation + an injected ZK/onchain verifier seam; the OFAC flag is inverted).
export * from "./self.ts";
