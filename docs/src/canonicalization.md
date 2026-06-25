# Canonicalization

Signing and digesting operate over a canonical byte string, not over arbitrary JSON
whitespace or key order. Every implementation MUST reproduce the exact algorithm of
`canonicalize` in `src/attestation.ts`. This is the interoperability crux: two
implementations that canonicalize identically produce verifiable signatures across vendor
boundaries.

ADP canonicalization is **RFC 8785 (JSON Canonicalization Scheme, JCS)** over ADP's value
domain — sorted keys by UTF-16 code unit, ECMAScript `Number::toString` numbers, JSON
string escaping, compact, UTF-8 — plus two profile rules JCS leaves to the caller because
it canonicalizes already-parsed JSON while ADP canonicalizes in-memory documents:
`undefined`-valued keys are dropped (an absent optional field ≡ one set to `undefined`;
JSON `null` is kept), and the input must not contain `NaN`/`Infinity`. The
**UTF-16 code-unit** key sort is normative: a supplementary-plane key (emoji, lead
surrogate `D83D`) sorts before a BMP key like `U+FB33`. A port that sorts by code point or
UTF-8 byte produces different bytes and its signatures will not verify cross-stack — the
conformance vectors include a case that catches exactly this.

## The algorithm

`canonicalize(value)` returns a string, defined recursively:

1. If `value` is `null`, or is a string, number, or boolean primitive, return
   `JSON.stringify(value)`. So strings are emitted as JSON string literals (quoted, with
   JSON escaping), numbers in their JSON form, booleans as `true` / `false`, and `null` as
   `null`.
2. If `value` is an array, return `"[" + value.map(canonicalize).join(",") + "]"`. Array
   order is **preserved**. Array elements are never sorted or filtered. An `undefined`
   element, if one occurs, stringifies as `null` per step 1, matching `JSON.stringify`.
3. Otherwise `value` is an object. Take its keys, sort them lexicographically (ascending,
   by UTF-16 code unit, the default JavaScript string sort), **drop** every key whose
   value is `undefined`, then for each surviving key `k` emit
   `JSON.stringify(k) + ":" + canonicalize(value[k])`. Join the pieces with `,` and wrap
   in `{ ... }`.

## Notes for implementers in other languages

- **Drop undefined** applies to object values. JSON has no `undefined`, so in a strict
  JSON pipeline this rule only fires when serializing an in-memory document that carries
  optional fields left unset. An optional field that is absent and one set to `undefined`
  MUST canonicalize identically (both produce no key). A field explicitly set to JSON
  `null` is NOT dropped; it is emitted as `null`.
- **Key sort** is over the raw key strings, ascending. There is no normalization of the
  key strings beyond JSON string escaping at emit time.
- **No insignificant whitespace** is ever emitted. The output is a compact string.
- **Number formatting** follows the host JSON serializer. Implementations SHOULD restrict
  numeric fields to integers and exactly-representable values to avoid cross-language
  float-formatting divergence. The schema's count and cap fields are all integers.

## Worked vectors

The following vectors are carried in `conformance/vectors.json`. An implementation MUST
reproduce each canonical output byte for byte.

| Input | Canonical output |
|---|---|
| `{ "b": 1, "a": 2 }` | `{"a":2,"b":1}` |
| `{ "a": "x", "c": [3, 1, 2], "b": true }` | `{"a":"x","b":true,"c":[3,1,2]}` |
| `{ "z": { "y": 1, "x": 2 }, "a": null }` | `{"a":null,"z":{"x":2,"y":1}}` |
| `{ "list": [{ "b": 1, "a": 2 }, { "d": 4, "c": 3 }] }` | `{"list":[{"a":2,"b":1},{"c":3,"d":4}]}` |
| `"hi"` | `"hi"` |
| `5` | `5` |
| `true` | `true` |
| `null` | `null` |

Two further cases from the specification show preserved array order, dropped `undefined`
values, and the handshake body:

```
input:  { "z": [3, 1, 2], "a": { "d": undefined, "c": "x" } }
output: {"a":{"c":"x"},"z":[3,1,2]}
```

The array `[3,1,2]` keeps its order; the key `d` is dropped because its value is
`undefined`; the keys `a` and `z` are sorted.

```
input:  { "nonce": "ab12", "agentId": "ff00", "auditHead": "deadbeef",
          "signedAt": "2026-06-24T10:00:00Z", "verifierId": undefined }
output: {"agentId":"ff00","auditHead":"deadbeef","nonce":"ab12","signedAt":"2026-06-24T10:00:00Z"}
```

This last case is the handshake response body with a trailing `undefined` `verifierId`
dropped; the same shape recurs in the [verification handshake](./verification-handshake.md).

## Digest vectors

`conformance/vectors.json` also pins two sha256 vectors so that digest output is identical
across stacks:

| Input | sha256 (hex) |
|---|---|
| `""` (empty string) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `"agent-disclosure"` | `ceecf41688c07988a4d0a06590c68c5e7b045f12bd5be848de406e97117427b2` |
