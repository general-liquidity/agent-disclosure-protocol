# The Verification Handshake

The handshake is a live challenge-response proving the counterparty holds the signing key
right now and that its audit head is current. A static signed disclosure cannot prove
either. Reference: `src/handshake.ts`.

## Challenge message

The verifier issues a `Challenge` (`createChallenge`):

```
{
  "nonce":      <string>,   // fresh, unguessable; reference uses 16 random bytes hex
  "issuedAt":   <ISO-8601>,
  "verifierId": <string>    // OPTIONAL; binds the proof to a specific verifier exchange
}
```

The nonce MUST be fresh and unguessable per challenge (`randomNonce`).

## ChallengeResponse message

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

## Signed bytes

The signature is over the canonical bytes of the body, with the challenge's `verifierId`
folded in (`responseMessage`):

```
canonicalize({ nonce, agentId, auditHead, signedAt, verifierId })
```

where `nonce`, `agentId`, `auditHead`, `signedAt` come from the response and `verifierId`
comes from the challenge. When `verifierId` is absent it is `undefined` and is therefore
dropped by [canonicalization](./canonicalization.md), so both sides reconstruct identical
bytes whether or not a verifier id is in play. Both sides MUST construct this message
identically.

## Verifier MUST-checks

`verifyChallengeResponse` takes the response, the original challenge, and a
`HandshakePolicy` (`expectedAgentId`, optional `disclosureAnchor`, optional `now`,
optional `maxAgeMs` defaulting to 60000). A verifier MUST check, in order:

1. **Nonce match.** `response.nonce` MUST equal `challenge.nonce`. A mismatch is a refuse
   ("replayed or wrong challenge"). Defeats identity replay.
2. **AgentId match.** `response.agentId` MUST equal `policy.expectedAgentId` (the agentId
   the disclosure claims). A mismatch is a refuse.
3. **Signature.** The ed25519 signature MUST verify over the canonical bytes above against
   `response.agentId`. A failure is a refuse ("no live key possession").
4. **Freshness.** When `policy.now` is supplied, `Date.parse(now) - Date.parse(signedAt)`
   MUST be `>= 0` and `<= maxAgeMs` (default 60000 ms). Outside that range is a refuse
   ("stale").
5. **Audit-head currency.** The bound `auditHead` is checked against the disclosure's
   anchor. An exact match means the disclosure is current as of the live head. A
   regression to an older anchor is a red flag; equality or a newer/different head is
   acceptable. The reference treats a regression as a non-fatal signal and returns ok; a
   stricter verifier MAY refuse on a detected regression.

A replayed static disclosure cannot answer a nonce it has never seen, which is what makes
the handshake the defense against identity replay (see the
[threat model](./threat-model.md), threat 3).
