# The Verification Handshake

The handshake is a live challenge-response proving the counterparty holds the signing key
right now and that its audit head is current. A static signed disclosure cannot prove
either. The proof is shaped as an **RFC 9421 (HTTP Message Signatures)** signature.
Reference: `src/handshake.ts`.

## Challenge message

The verifier issues a `Challenge` (`createChallenge`):

```
{
  "nonce":             <string>,   // fresh, unguessable; reference uses 16 random bytes hex
  "issuedAt":          <ISO-8601>,
  "verifierId":        <string>,   // OPTIONAL; binds the proof to a verifier exchange (the 9421 `tag`)
  "supportedVersions": <number[]>  // OPTIONAL; disclosure-schema versions the verifier accepts
}
```

The nonce MUST be fresh and unguessable per challenge (`randomNonce`).

## ChallengeResponse message

The agent answers with a `ChallengeResponse` (`respondToChallenge`):

```
{
  "nonce":             <string>,   // echoes the challenge nonce
  "agentId":           <string>,   // the responding agent's ed25519 public key (hex)
  "auditHead":         <string>,   // the agent's audit-chain head at response time
  "signedAt":          <ISO-8601>,
  "disclosureVersion": <number>,   // OPTIONAL; the presented schema version (a SIGNED component)
  "signatureInput":    <string>,   // the RFC 9421 Signature-Input value (covered set + params)
  "signature":         <hex>       // ed25519 over the RFC 9421 signature base (below)
}
```

## The signature base (RFC 9421)

The signature is over an RFC 9421 **signature base**: one line per covered component, then
the `@signature-params` line. This is the non-HTTP-transport profile — there are no HTTP
fields to cover, so every covered component is a namespaced `adp-*` derived component:

```
"adp-agent-id":           <agentId>
"adp-audit-head":         <auditHead>
"adp-disclosure-version": <disclosureVersion>   // only when a version is declared
"@signature-params": (<covered names>);created="<signedAt>";keyid="<agentId>";alg="ed25519";nonce="<nonce>";tag="<verifierId>"
```

`tag` appears only when the challenge carried a `verifierId`; the version line appears only
when the response declares a `disclosureVersion`. The wire `Signature-Input` value is
`sig=<@signature-params value>`. Both sides MUST build the base byte-identically.

Two **deliberate ADP deviations** from strict RFC 9421: `created` is an ISO-8601 string (ADP's
timestamp convention) rather than Unix seconds, and the signature is hex rather than the
`:base64:` structured-field binary wrapper.

## Verifier MUST-checks

`verifyChallengeResponse` takes the response, the original challenge, and a `HandshakePolicy`
(`expectedAgentId`, optional `disclosureAnchor`, `now`, `maxAgeMs` defaulting to 60000,
`supportedVersions`). A verifier MUST check, in order:

1. **Nonce match.** `response.nonce` MUST equal `challenge.nonce`. A mismatch is a refuse.
   Defeats identity replay.
2. **AgentId match.** `response.agentId` MUST equal `policy.expectedAgentId`.
3. **Signature-Input match.** The verifier reconstructs the expected `signatureInput` from
   ITS challenge plus the response's claimed values; `response.signatureInput` MUST equal it
   exactly (no covered-set or parameter smuggling).
4. **Signature.** The ed25519 signature MUST verify over the reconstructed signature base
   against `response.agentId`. A failure is a refuse ("no live key possession"). Because the
   base covers the audit head and version, tampering any covered value is caught here.
5. **Version negotiation.** When `policy.supportedVersions` is set and the response declares a
   `disclosureVersion` outside it, the verifier MUST refuse with an actionable reason. A
   response that declares no version is accepted (pre-negotiation peers stay interoperable).
6. **Freshness.** When `policy.now` is supplied, `Date.parse(now) - Date.parse(signedAt)` MUST
   be `>= 0` and `<= maxAgeMs`. Outside that range is a refuse ("stale").
7. **Audit-head currency.** The bound `auditHead` is checked against the disclosure's anchor. An
   exact match means the disclosure is current; a regression to an older anchor is a red flag.
   The reference treats a regression as non-fatal; a stricter verifier MAY refuse on it.

A replayed static disclosure cannot answer a nonce it has never seen, which is what makes the
handshake the defense against identity replay (see the [threat model](./threat-model.md),
threat 3).
