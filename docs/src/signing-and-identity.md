# Signing and Identity

Signatures are ed25519 over the UTF-8 bytes of the [canonical string](./canonicalization.md).
Reference: `signDisclosure` and `verifyDisclosureSignature` in `src/attestation.ts`.

## The signed envelope

The envelope wraps the disclosure document with an ed25519 signature
(`SignedDisclosureSchema`):

```
{
  "disclosure": <AgentDisclosure>,
  "signature": {
    "algorithm": "ed25519",
    "publicKey": <hex>,   // the signer's raw 32-byte public key, = agentId's key material
    "value":     <hex>    // ed25519 signature over canonicalize(disclosure)
  }
}
```

`algorithm` MUST be the literal `"ed25519"`. `publicKey` is the signer's raw 32-byte
ed25519 public key as hex. `value` is the signature over the canonical bytes of the
disclosure document, as hex.

## Signing

To sign a disclosure: compute `canonicalize(disclosure)`, encode as UTF-8, ed25519-sign
with the agent's private key, and place the hex signature in `signature.value`. The
envelope's `signature.publicKey` is the signer's raw 32-byte ed25519 public key,
hex-encoded.

## Identity binding (MUST)

A disclosure MUST be signed by the key it claims as its identity: `disclosure.agentId`
MUST equal `signature.publicKey`. A verifier MUST reject a disclosure where they differ,
**before** checking the signature value. In the reference, `verifyDisclosureSignature`
returns failure with reason "agentId does not match the signing public key" when
`agentId !== publicKey`.

This binding is the convention by which the public key **is** the agent's identity. The
same binding is enforced for [redacted views](./selective-disclosure.md). Signature
verification then verifies the hex signature over `canonicalize(disclosure)` against the
32-byte public key; a mismatch is a refuse.

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
