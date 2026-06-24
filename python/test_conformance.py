"""Cross-language conformance: the Python verifier against the TS reference vectors.

Asserts every canonicalization vector, every sha256 vector, every interop
disclosure case (decision AND sorted failed-check names), and every handshake
case (ok == expect). Loads the shared fixtures from ../conformance/.
"""

import json
import pathlib
import unittest

from agent_disclosure import (
    canonicalize,
    sha256_hex,
    evaluate_disclosure,
    verify_challenge_response,
    verify_disclosure_signature,
)
from agent_disclosure.verify import VerificationPolicy

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = json.loads((ROOT / "conformance" / "vectors.json").read_text(encoding="utf-8"))
INTEROP = json.loads((ROOT / "conformance" / "interop.json").read_text(encoding="utf-8"))


class TestCanonicalization(unittest.TestCase):
    def test_vectors(self):
        for vec in VECTORS["canonicalization"]:
            self.assertEqual(canonicalize(vec["input"]), vec["canonical"], msg=repr(vec["input"]))


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
