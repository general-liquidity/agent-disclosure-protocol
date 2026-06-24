"""Cross-language conformance: the Python verifier against the TS reference vectors.

Asserts every canonicalization vector, every sha256 vector, every interop
disclosure case (decision AND sorted failed-check names), and every handshake
case (ok == expect). Loads the shared fixtures from ../conformance/.
"""

import copy
import json
import pathlib
import unittest

from agent_disclosure import (
    canonicalize,
    sha256_hex,
    evaluate_disclosure,
    verify_challenge_response,
    respond_to_challenge,
    verify_disclosure_signature,
    agent_key_from_private_hex,
    generate_agent_key,
    sign_disclosure,
    verify_raw,
    verify_redacted,
    verify_revocation,
    verify_inclusion_proof,
)
from agent_disclosure.verify import VerificationPolicy

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = json.loads((ROOT / "conformance" / "vectors.json").read_text(encoding="utf-8"))
INTEROP = json.loads((ROOT / "conformance" / "interop.json").read_text(encoding="utf-8"))
FUZZ = json.loads((ROOT / "conformance" / "fuzz.json").read_text(encoding="utf-8"))
NEGATIVE = json.loads((ROOT / "conformance" / "negative.json").read_text(encoding="utf-8"))


class TestCanonicalization(unittest.TestCase):
    def test_vectors(self):
        for vec in VECTORS["canonicalization"]:
            self.assertEqual(canonicalize(vec["input"]), vec["canonical"], msg=repr(vec["input"]))


class TestFuzzCanonicalization(unittest.TestCase):
    def test_corpus(self):
        # Replay the differential fuzz corpus produced by the TS reference
        # (conformance/generate-fuzz.ts). Python MUST reproduce each recorded
        # canonical byte-for-byte: agreement on random inputs, not just fixed vectors.
        self.assertGreaterEqual(len(FUZZ), 200, "fuzz.json corpus is missing or too small")
        for i, case in enumerate(FUZZ):
            self.assertEqual(canonicalize(case["input"]), case["canonical"], msg=f"fuzz[{i}]")


class TestSha256(unittest.TestCase):
    def test_vectors(self):
        for vec in VECTORS["sha256"]:
            self.assertEqual(sha256_hex(vec["input"]), vec["sha256"], msg=repr(vec["input"]))


class TestInteropDisclosures(unittest.TestCase):
    def test_cases(self):
        for case in INTEROP["disclosures"]:
            policy = VerificationPolicy.from_json(case["policy"])
            verdict = evaluate_disclosure(case["signed"], policy)
            self.assertEqual(verdict.decision, case["expect"]["decision"], msg=case["name"])
            self.assertEqual(verdict.failed, sorted(case["expect"]["failed"]), msg=case["name"])

    def test_signatures_verify_for_transact_cases(self):
        # Every non-tampered/non-forged case has a valid signature: proves the
        # Python canonicalization byte-matches the TS reference (cross-stack interop).
        for case in INTEROP["disclosures"]:
            if "signature" not in case["expect"]["failed"]:
                ok, reason = verify_disclosure_signature(case["signed"])
                self.assertTrue(ok, msg=f"{case['name']}: {reason}")


class TestInteropHandshakes(unittest.TestCase):
    def test_cases(self):
        for case in INTEROP["handshakes"]:
            ok, _ = verify_challenge_response(
                case["response"],
                case["challenge"],
                case["expectedAgentId"],
                now=case.get("now"),
            )
            self.assertEqual(ok, case["expect"], msg=case["name"])


class TestResponder(unittest.TestCase):
    def test_byte_match_against_fixed_key(self):
        # Re-build the "valid" handshake response with the fixed PKCS8 key and
        # assert the signature hex EQUALS the fixture's value: proves the Python
        # responder is byte-identical to the TS `respondToChallenge` signer.
        priv = agent_key_from_private_hex(INTEROP["key"]["privateKeyHex"])
        case = INTEROP["handshakes"][0]
        self.assertEqual(case["name"], "valid")
        fixture = case["response"]
        response = respond_to_challenge(
            case["challenge"], priv, fixture["auditHead"], fixture["signedAt"]
        )
        self.assertEqual(response["signature"], fixture["signature"], msg=case["name"])

    def test_round_trip_verifies(self):
        # The responder's output passes verify_challenge_response (the verifier
        # half accepts what the responder half produces).
        priv = agent_key_from_private_hex(INTEROP["key"]["privateKeyHex"])
        case = INTEROP["handshakes"][0]
        fixture = case["response"]
        response = respond_to_challenge(
            case["challenge"], priv, fixture["auditHead"], fixture["signedAt"]
        )
        ok, reason = verify_challenge_response(
            response, case["challenge"], priv.public_key_hex, now=case.get("now")
        )
        self.assertTrue(ok, msg=reason)

    def test_round_trip_fresh_key_no_verifier_id(self):
        # A fresh key + a challenge without a verifierId still round-trips
        # (verifierId dropped, not rendered null — matches the TS responder).
        key = generate_agent_key()
        challenge = {"nonce": "chal_fresh", "issuedAt": "2026-06-24T12:30:00.000Z"}
        response = respond_to_challenge(
            challenge, key, "audithead-deadbeef", "2026-06-24T12:30:00.000Z"
        )
        ok, reason = verify_challenge_response(
            response, challenge, key.public_key_hex, now="2026-06-24T12:30:00.000Z"
        )
        self.assertTrue(ok, msg=reason)


class TestEmitter(unittest.TestCase):
    def test_byte_match_against_fixed_key(self):
        # Re-sign each correctly-bound, non-tampered disclosure with the fixed
        # PKCS8 key and assert the signature hex EQUALS the fixture's value:
        # proves the Python emitter is byte-identical to the TS signer.
        priv = agent_key_from_private_hex(INTEROP["key"]["privateKeyHex"])
        self.assertEqual(priv.public_key_hex, INTEROP["key"]["publicKeyHex"])
        checked = 0
        for case in INTEROP["disclosures"]:
            if "signature" in case["expect"]["failed"]:
                continue  # tampered or forged-binding: not signed by the fixed key
            signed = sign_disclosure(case["signed"]["disclosure"], priv)
            self.assertEqual(
                signed["signature"]["value"],
                case["signed"]["signature"]["value"],
                msg=case["name"],
            )
            self.assertEqual(signed["signature"]["publicKey"], priv.public_key_hex, msg=case["name"])
            checked += 1
        self.assertGreater(checked, 0)

    def test_round_trip_fresh_key(self):
        # Emit with a fresh key and the own verifier accepts (agentId rebound to
        # the fresh public hex to satisfy the identity binding).
        key = generate_agent_key()
        disclosure = copy.deepcopy(INTEROP["disclosures"][0]["signed"]["disclosure"])
        disclosure["agentId"] = key.public_key_hex
        signed = sign_disclosure(disclosure, key)
        ok, reason = verify_disclosure_signature(signed)
        self.assertTrue(ok, msg=reason)


class TestInteropRedactions(unittest.TestCase):
    def test_cases(self):
        for case in INTEROP["redactions"]:
            ok, revealed = verify_redacted(case["view"])
            self.assertEqual(ok, case["expect"]["ok"], msg=case["name"])
            self.assertEqual(revealed, case["expect"]["revealedFields"], msg=case["name"])


class TestInteropRevocations(unittest.TestCase):
    def test_cases(self):
        for case in INTEROP["revocations"]:
            self.assertEqual(verify_revocation(case["record"]), case["expect"], msg=case["name"])


class TestInteropTransparency(unittest.TestCase):
    def test_cases(self):
        for case in INTEROP["transparency"]:
            self.assertEqual(verify_inclusion_proof(case["entry"]), case["expect"], msg=case["name"])


class TestNegativeCorpus(unittest.TestCase):
    """MUST-REJECT corpus: every hostile/malformed raw input must reject (verify_raw
    returns True) and no exception may escape. The adversarial half of conformance."""

    def test_every_case_rejects_without_raising(self):
        cases = NEGATIVE["cases"]
        self.assertGreater(len(cases), 0, "negative.json corpus is empty")
        policy = VerificationPolicy(now="2026-06-24T12:00:00.000Z")
        for case in cases:
            # Feed verify_raw a STRING: for isRawString feed the literal bytes,
            # otherwise json.dumps the structured value into raw JSON text.
            if case.get("isRawString"):
                raw = case["raw"]
            else:
                raw = json.dumps(case["raw"])
            try:
                rejected = verify_raw(raw, policy)
            except Exception as e:  # noqa: BLE001 — the whole point is nothing escapes
                self.fail(f"{case['name']}: verify_raw raised {e!r}")
            self.assertTrue(rejected, msg=f"{case['name']}: not rejected")

    def test_default_policy_also_rejects(self):
        # verify_raw must reject even with no policy supplied (fail-closed default).
        for case in NEGATIVE["cases"]:
            raw = case["raw"] if case.get("isRawString") else json.dumps(case["raw"])
            self.assertTrue(verify_raw(raw), msg=f"{case['name']}: not rejected (default policy)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
