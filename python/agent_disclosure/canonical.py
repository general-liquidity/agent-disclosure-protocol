"""Deterministic canonicalization + sha256, byte-matched to the TS reference.

`canonicalize` mirrors `src/attestation.ts`:
  - object: "{" + lexicographically-sorted keys, each non-absent key rendered as
    json.dumps(key) + ":" + canonicalize(value), joined by "," + "}"
  - array: "[" + elements joined by "," + "]"
  - scalar leaf: the JSON scalar form (json.dumps with ensure_ascii=False so the
    escaping matches JS JSON.stringify); True/False/None -> true/false/null.

The ed25519 signature is over the UTF-8 bytes of canonicalize(disclosure).
"""

import hashlib
import json


def canonicalize(value) -> str:
    if value is None or isinstance(value, (str, bool, int, float)):
        # bool is a subclass of int; json.dumps renders both correctly
        # (true/false, ints without trailing .0). ensure_ascii=False matches
        # JS JSON.stringify for our ASCII data.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        # TS drops only `=== undefined` keys; JSON-decoded data has no undefined
        # (a present `null` is kept), so every key is serialized.
        #
        # JS `Array.prototype.sort()` (what `Object.keys(obj).sort()` uses in the TS
        # reference) orders strings by UTF-16 code unit, NOT by Unicode code point.
        # They diverge for supplementary-plane characters: a surrogate pair (lead unit
        # 0xD800–0xDBFF) sorts BEFORE a BMP character above 0xE000. Python's default
        # `sorted(str)` is code-point, which would mis-order e.g. "😀" (U+1F600) vs a
        # high-BMP key. Sort on the UTF-16-BE encoding to reproduce the JS order
        # byte-for-byte (big-endian preserves code-unit ordering).
        parts = [
            json.dumps(key, ensure_ascii=False) + ":" + canonicalize(value[key])
            for key in sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        ]
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"cannot canonicalize value of type {type(value)!r}")


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
