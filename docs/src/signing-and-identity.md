# Signing and Identity

Signatures are ed25519 over the UTF-8 bytes of the [canonical string](./canonicalization.md).
Reference: `signDisclosure` and `verifyDisclosureSignature` in `src/attestation.ts`.

## The signed envelope (two interchangeable shapes)

A signed disclosure has **two wrappings** over the same disclosure document, with the same
ed25519 crypto over the same canonical bytes — only the packaging differs. An emitter MAY
produce either (dual-encode); a verifier MUST accept either, discriminated by shape
(`verifyAnyDisclosureSignature`, `parseAnySignedDisclosure`).

### v1 object envelope (`SignedDisclosureSchema`)

```
{
  "disclosure": <AgentDisclosure>,
  "signature": {
    "algorithm": "ed25519",
    "publicKey": <hex>,   // the signer's raw 32-byte public key, = agentId's key material
    "value":     <hex>    // ed25519 signature over canonicalize(disclosure)
  },
  "rotationChain": [ ... ]   // OPTIONAL, see Key rotation below
}
```

`algorithm` MUST be the literal `"ed25519"`. `publicKey` is the raw 32-byte ed25519 public
key as hex; `value` is the signature over the canonical disclosure bytes, as hex. Note that
`algorithm` sits **outside** the signed bytes — a verifier treats it as a literal constraint
and never uses it to select an algorithm. The v2 form closes this gap.

### v2 flattened JWS envelope (`JwsSignedDisclosureSchema`)

A JOSE flattened JWS (RFC 7515) using EdDSA (RFC 8037 — the same ed25519 primitive):

```
{
  "payload":   <base64url>,   // base64url(UTF8(canonicalize(disclosure))) — JCS bytes
  "protected": <base64url>,   // base64url(UTF8({ "alg":"EdDSA", "typ":"application/adp+json" }))
  "header":    { "jwk": { "kty":"OKP", "crv":"Ed25519", "x":<base64url pubkey> } },
  "signature": <base64url>,   // EdDSA over ASCII(b64url(protected) + "." + b64url(payload))
  "rotationChain": [ ... ]    // OPTIONAL
}
```

The signature covers `ASCII(b64url(protected) + "." + b64url(payload))`, so the protected
header — and therefore `alg` — is **integrity-protected**: the algorithm can't be substituted
without breaking the signature. The payload is the byte-identical JCS canonical document, so a
JOSE library with no ADP code can verify it. To verify (`verifyDisclosureJws`): require
`alg === "EdDSA"`, recover the 32-byte key from `header.jwk.x`, verify over the signing input,
then bind the payload's `agentId` to that key.

A v2 envelope is distinguished by carrying `payload` + `protected`; a v1 envelope carries
`disclosure` + a `signature` object.

## Signing

To sign a disclosure: compute `canonicalize(disclosure)`, encode as UTF-8, ed25519-sign with
the agent's private key. In the v1 form the hex signature lands in `signature.value`; in the
v2 form the signature is over the JWS signing input and is base64url-encoded
(`signDisclosure` / `signDisclosureJws`).

## Identity binding (MUST)

A disclosure MUST be bound to the key that actually signed it. The binding holds
(`verifyKeyBinding`) when **any** of:

1. `agentId` equals the signing public key (hex) — the common self-certifying case;
2. `agentId` equals that key's **did:key** form (see [standards bridges](./standards-bridges.md));
3. a verified **rotation chain** links `agentId` to the signing key (below).

A verifier MUST reject a disclosure where none holds, **before** relying on its contents
(`verifyDisclosureSignature` returns "agentId does not match the signing public key"). The same
binding is enforced for [redacted views](./selective-disclosure.md) and both envelope shapes.
It is the convention by which the public key **is** the agent's identity — now extended so the
identity can survive a key change.

## Key rotation

Because `agentId` is by default the signing key itself, a naive key change would mint an
unrelated identity. A signed rotation chain lets a stable `agentId` survive rotation: the OLD
key signs a statement moving identity to the new key (`rotateKey`, `RotationStatementSchema` in
`src/keys.ts`):

```
{ "type": "rotation", "from": <hex>, "to": <hex>, "rotatedAt": <ISO-8601>, "signature": <hex> }
```

The `from` key signs `canonicalize({ type:"rotation", from, to, rotatedAt })`; only the old key
signs (trust flows forward from the established identity). A `rotationChain` is an ordered array
of such hops carried in the envelope — it is **not** part of the signed disclosure bytes (it is
verification metadata, unforgeable because it must root at the signed `agentId`). To verify
(`verifyRotationChain`): start a cursor at `agentId`; for each hop require `from == cursor`,
verify the hop signature against `from`, reject cycles, advance the cursor to `to`; require the
final cursor to equal the signing key. A chain has 1..32 hops; an empty or over-long chain is a
refuse.

## Freshness

A disclosure is valid only within its `[issuedAt, validUntil]` window. A verifier MUST
reject a disclosure outside the window (`isFresh` in `src/attestation.ts`).

The comparison is `now >= issuedAt && now <= validUntil`, performed as ISO-8601 lexical
(string) comparison. ISO-8601 timestamps in a fixed, zero-padded, same-zone form sort
lexically in chronological order, so string comparison is correct. Emitters MUST therefore
produce timestamps in a consistent, zero-padded ISO-8601 form, and SHOULD use UTC `Z`, so
that lexical order equals chronological order.

`now` is the verifier's clock. Clock skew between parties moves the window edges and is an
acknowledged residual gap (see the [threat model](./threat-model.md), threat 4).

## Key encoding (informative)

The reference imports a bare 32-byte ed25519 public key by prepending the SPKI DER prefix
`302a300506032b6570032100` and importing as SPKI DER; private keys are persisted as PKCS8
DER hex (`publicKeyFromHex`, `exportAgentKey`, `agentKeyFromPrivateHex`). These are
encoding conventions of the reference runtime and do not affect the on-wire form, which is
always the raw 32-byte public key as hex and the raw signature as hex. An implementation
MAY use any ed25519 library that produces and verifies standard ed25519 signatures over
the canonical UTF-8 bytes.

Keys export and reload, so an agent's identity is stable across restarts.
