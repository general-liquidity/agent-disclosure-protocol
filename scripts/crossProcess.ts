// The cross-process interop harness. Starts the real-socket disclosure server
// (scripts/serveDisclosure.ts), then over REAL HTTP - the global `fetch`, a real
// TCP socket, not the in-memory FetchLike the tests use - GETs the disclosure and
// verifies it with `verifyDisclosureSignature` plus a `VerificationPolicy`. This
// proves the server actually works over a socket, end to end, in a separate I/O path
// from the unit suite.
//
// Prints PASS / FAIL and exits nonzero on failure, so it doubles as a gate.
//
// The cross-LANGUAGE leg - running the Go (go/cmd/verify-url) and Python
// (python/verify_url.py) verify-url binaries against this same server - is wired in
// the `cross-process` job in .github/workflows/ci.yml: CI starts this server on a
// port and asserts each native client exits 0 against http://localhost:<port>. This
// script is the TypeScript leg of that same matrix, runnable locally with no Go or
// Python toolchain.
//
// Run: node --import tsx scripts/crossProcess.ts [port]

import {
  verifyDisclosureSignature,
  evaluateDisclosure,
  parseSignedDisclosure,
  type VerificationPolicy,
} from "../src/index.ts";
import { startDisclosureServer, DISCLOSURE_PATH } from "./serveDisclosure.ts";

async function main(): Promise<number> {
  const port = Number(process.argv[2] ?? process.env.PORT ?? 8799);
  const { server, port: boundPort } = await startDisclosureServer(port);
  const url = `http://localhost:${boundPort}${DISCLOSURE_PATH}`;
  const failures: string[] = [];

  try {
    // Leg 1: fetch the disclosure over a real socket with the global fetch.
    const res = await fetch(url);
    if (!res.ok) failures.push(`GET ${url} returned HTTP ${res.status}`);
    const raw = await res.json();

    // Leg 2: structural parse (the untrusted-boundary check).
    const signed = parseSignedDisclosure(raw);

    // Leg 3: the ed25519 signature + agentId-to-key binding.
    const sig = verifyDisclosureSignature(signed);
    if (!sig.ok) failures.push(`signature did not verify: ${sig.reason}`);

    // Leg 4: a real policy verdict against the fetched document.
    const policy: VerificationPolicy = {
      now: new Date().toISOString(),
      requireEnforcedConstitution: true,
      requireAuditAnchor: true,
      requireNonCustodial: true,
    };
    const verdict = evaluateDisclosure(signed, policy);
    if (verdict.decision !== "transact") {
      failures.push(`policy verdict was ${verdict.decision}: ${verdict.reasons.join("; ")}`);
    }

    console.log(`fetched ${url} over a real socket`);
    console.log(`  signature: ${sig.ok ? "ok" : "FAILED"}`);
    console.log(`  verdict:   ${verdict.decision} (${verdict.cost.checksRun} checks)`);
  } catch (e) {
    failures.push(`unexpected error: ${e instanceof Error ? e.message : String(e)}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  if (failures.length === 0) {
    console.log("PASS: real-socket disclosure served, fetched, and verified end to end");
    return 0;
  }
  for (const f of failures) console.error(`  - ${f}`);
  console.error("FAIL: cross-process verification failed");
  return 1;
}

main().then((code) => process.exit(code));
