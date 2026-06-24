// Verifier-as-a-service. The reference verifier, exposed as a tiny HTTP endpoint so
// a fleet can centralize its counterparty policy: POST a SignedDisclosure, get back
// a transact / refuse verdict. The pure handler (handleVerify) carries the logic and
// is fully testable without a socket; createVerifierService is the thin node:http shell.
//
// Vendor-neutral: depends only on the schema + verify layer + an injected clock.

import { createServer, type Server } from "node:http";
import { verifyAndEvaluate, type VerificationPolicy, type DisclosureVerdict } from "./verify.ts";

export interface VerifyResult {
  status: number;
  body: unknown;
}

/**
 * Evaluate a posted SignedDisclosure against the verifier's policy. Pure: parses the
 * raw JSON body, injects `now` into the policy, and returns the verdict's decision /
 * checks / reasons. Malformed JSON is a 400 (a schema-invalid envelope is a refuse,
 * not a 400 — verifyAndEvaluate fails closed on it).
 */
export function handleVerify(
  rawBody: string,
  policyBase: Omit<VerificationPolicy, "now">,
  now: string,
): VerifyResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch (e) {
    return { status: 400, body: { error: `malformed JSON: ${e instanceof Error ? e.message : String(e)}` } };
  }
  const policy: VerificationPolicy = { ...policyBase, now };
  const verdict: DisclosureVerdict = verifyAndEvaluate(parsed, policy);
  return { status: 200, body: { decision: verdict.decision, checks: verdict.checks, reasons: verdict.reasons } };
}

export interface VerifierServiceOptions {
  /** injectable clock (ISO-8601); defaults to wall time per request */
  clock?: () => string;
}

/**
 * A minimal node:http verifier service. POST /verify -> handleVerify; GET /health -> ok.
 * The clock is read per request so the freshness check tracks real time.
 */
export function createVerifierService(
  policyBase: Omit<VerificationPolicy, "now">,
  opts: VerifierServiceOptions = {},
): Server {
  const clock = opts.clock ?? (() => new Date().toISOString());
  return createServer((req, res) => {
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };

    if (req.method === "GET" && req.url === "/health") {
      send(200, { ok: true });
      return;
    }

    if (req.method === "POST" && req.url === "/verify") {
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
      });
      req.on("end", () => {
        const result = handleVerify(raw, policyBase, clock());
        send(result.status, result.body);
      });
      return;
    }

    send(404, { error: "not found" });
  });
}
