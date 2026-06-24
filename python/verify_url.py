"""Live HTTP verify client for the Agent Disclosure Protocol.

Fetches a counterparty's signed disclosure from its well-known endpoint, then
runs the native verifier (signature + agentId<->publicKey binding) and prints a
transact/refuse decision. The native side of the live cross-process interop test
against the TS `verify-url` / `verifierService`.

    python verify_url.py <baseUrl> [--now <iso8601>]

Exit 0 when the disclosure is valid (would transact), 1 on any invalid
disclosure OR transport error. Never crashes on hostile input.
"""

import argparse
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

from agent_disclosure import evaluate_raw
from agent_disclosure.verify import VerificationPolicy


def _now_iso() -> str:
    """Current UTC instant as an ISO-8601 string, the freshness clock for a live verify."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

WELL_KNOWN_PATH = "/.well-known/agent-disclosure"


def fetch_disclosure(base_url: str, timeout: float = 10.0) -> str:
    """GET <base>/.well-known/agent-disclosure and return the raw body text."""
    url = base_url.rstrip("/") + WELL_KNOWN_PATH
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — operator-supplied URL
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify_url.py",
        description="Fetch and verify a counterparty's Agent Disclosure over HTTP.",
    )
    parser.add_argument("base_url", help="Base URL hosting /.well-known/agent-disclosure")
    parser.add_argument(
        "--now",
        default=None,
        help="ISO-8601 instant for the freshness window (default: current UTC time).",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10)."
    )
    args = parser.parse_args(argv)

    try:
        raw = fetch_disclosure(args.base_url, timeout=args.timeout)
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"decision: refuse")
        print(f"transport error: {e}")
        return 1

    policy = VerificationPolicy(now=args.now or _now_iso())
    verdict = evaluate_raw(raw, policy)

    print(f"decision: {verdict.decision}")
    if verdict.failed:
        print(f"failed checks: {', '.join(verdict.failed)}")
    for reason in verdict.reasons:
        print(f"  - {reason}")

    return 0 if verdict.decision == "transact" else 1


if __name__ == "__main__":
    sys.exit(main())
