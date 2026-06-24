// A deployable REFERENCE AGENT for the Agent Disclosure Protocol. It is a runnable
// node:http service that exposes its OWN agent surface (disclosure + live handshake)
// AND verifies a counterparty before it pays - the full "adopt ADP" loop in one
// process. Two of these, pointed at each other, demonstrate mutual verify-before-pay
// over a real socket.
//
// Surface:
//   GET  /.well-known/agent-disclosure  -> this agent's freshly signed disclosure
//   POST /agent-disclosure/respond      -> respondToChallenge over the live key + audit head
//   GET  /health                        -> { ok: true }
//   POST /pay { payeeBaseUrl, amount }  -> verify-before-pay gate: guardSettlement against
//                                          the payee; "pays" (settled) iff the payee clears,
//                                          else refused with reasons. No real money moves.
//
// The agent mints a fresh ed25519 key on boot (the agentId IS the public key, so a
// counterparty verifies with no shared secret), builds a minimal real disclosure, and
// signs it once. The handshake binds a stub audit head, proving live key possession.
//
// Run: node --import tsx examples/reference-agent/server.ts   (PORT env, default 8800)

import { createServer, type Server } from "node:http";

import {
  generateAgentKeyPair,
  signDisclosure,
  respondToChallenge,
  guardSettlement,
  sha256Hex,
  type AgentDisclosure,
  type SignedDisclosure,
  type AgentKeyPair,
  type Challenge,
  type FetchLike,
  type VerificationPolicy,
} from "../../src/index.ts";

export const DISCLOSURE_PATH = "/.well-known/agent-disclosure";
export const RESPOND_PATH = "/agent-disclosure/respond";
export const HEALTH_PATH = "/health";
export const PAY_PATH = "/pay";
const DEFAULT_PORT = 8800;

/** Options for a reference agent. Every field has a sensible default. */
export interface ReferenceAgentOptions {
  port?: number;
  /** the agent's signing identity (default: mint a fresh ed25519 key on boot) */
  key?: AgentKeyPair;
  /** human label for this agent, surfaced in operator + log lines */
  operatorId?: string;
  /** how long the minted disclosure stays fresh (default one hour) */
  disclosureWindowMs?: number;
  /** the verify-before-pay policy this agent applies to any payee (the gate config).
   *  `now` is supplied per-request from the live clock, so it is omitted here. */
  payPolicy?: Omit<VerificationPolicy, "now">;
  /** clock, for tests that need a fixed `now`; default: live wall clock */
  now?: () => Date;
  /** tolerance (ms) for clock skew + round-trip latency when verifying a payee. The
   *  handshake rejects a response timestamped AFTER the verifier's `now`; a payee on
   *  a real socket signs a few ms later than the verifier captured `now`, and across
   *  hosts clocks are never perfectly synced. The verifier's `now` is advanced by this
   *  much so a freshly-signed response is not falsely "stale" (default 2000ms). */
  handshakeSkewMs?: number;
}

export interface ReferenceAgent {
  server: Server;
  port: number;
  baseUrl: string;
  disclosureUrl: string;
  /** the agentId (ed25519 public key hex) this agent presents */
  agentId: string;
  signed: SignedDisclosure;
  close(): Promise<void>;
}

/** Mint a minimal, valid disclosure signed by `key`, fresh for `windowMs`. The
 *  auditAnchor is a stub head the handshake also binds, so the live challenge proves
 *  the disclosure is current as of that head. */
function mintDisclosure(
  key: AgentKeyPair,
  operatorId: string,
  now: Date,
  windowMs: number,
): { signed: SignedDisclosure; auditHead: string } {
  const auditHead = sha256Hex(`${operatorId}:audit-head:${now.toISOString()}`);
  const disclosure: AgentDisclosure = {
    version: 1,
    disclosureId: `disc_${operatorId}_${now.getTime()}`,
    agentId: key.publicKeyHex,
    issuedAt: now.toISOString(),
    validUntil: new Date(now.getTime() + windowMs).toISOString(),
    nonce: `n-${operatorId}-${now.getTime()}`,
    auditAnchor: auditHead,
    systemPrompt: { algorithm: "sha256", digest: sha256Hex(`${operatorId} system prompt`) },
    constitution: {
      hardConstraints: [{ id: "no-wire", description: "no wire transfers", kind: "deny" }],
      digest: sha256Hex(`${operatorId} constitution`),
      enforced: true,
    },
    tools: { tools: [{ name: "pay", access: "gated", movesValue: true }], valuePath: "pay" },
    capital: { mandates: [], custody: "non_custodial" },
    operator: {
      operatorId,
      attestation: { scheme: "none", level: "none" },
      deniabilityBoundary: "operator accountable for mandate config only",
    },
    history: { chainAnchor: auditHead, summary: { totalDecisions: 7, settledCount: 6, blockedCount: 1 } },
  };
  return { signed: signDisclosure(disclosure, key), auditHead };
}

/** Bridge node's global fetch into the protocol's injected FetchLike shape, so the
 *  agent can verify a real counterparty over a real socket. Any thrown error
 *  propagates and verifyCounterparty fails closed. */
const httpFetch: FetchLike = async (url, init) => {
  const res = await fetch(url, init);
  return { ok: res.ok, status: res.status, json: () => res.json() };
};

function readJsonBody(req: import("node:http").IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (c) => {
      raw += c;
      if (raw.length > 1_000_000) reject(new Error("request body too large"));
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) {
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });
    req.on("error", reject);
  });
}

/**
 * Start a reference agent, resolving once it is listening. Exposes the full ADP
 * surface and a verify-before-pay gate. In-process callers get a handle they can
 * drive directly (the smoke test does this); the CLI entry below runs it standalone.
 */
export async function startReferenceAgent(opts: ReferenceAgentOptions = {}): Promise<ReferenceAgent> {
  const now = opts.now ?? (() => new Date());
  const key = opts.key ?? generateAgentKeyPair();
  const operatorId = opts.operatorId ?? "reference-agent";
  const windowMs = opts.disclosureWindowMs ?? 60 * 60 * 1000;
  const { signed, auditHead } = mintDisclosure(key, operatorId, now(), windowMs);
  const disclosureBody = JSON.stringify(signed);

  const json = (res: import("node:http").ServerResponse, status: number, payload: unknown) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(payload));
  };

  const server = createServer((req, res) => {
    void (async () => {
      try {
        if (req.method === "GET" && req.url === DISCLOSURE_PATH) {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(disclosureBody);
          return;
        }
        if (req.method === "GET" && req.url === HEALTH_PATH) {
          json(res, 200, { ok: true, agentId: key.publicKeyHex, operatorId });
          return;
        }
        if (req.method === "POST" && req.url === RESPOND_PATH) {
          const challenge = (await readJsonBody(req)) as Challenge;
          // Prove live key possession by signing the challenge bound to the live audit head.
          json(res, 200, respondToChallenge(challenge, key, auditHead, now().toISOString()));
          return;
        }
        if (req.method === "POST" && req.url === PAY_PATH) {
          const body = (await readJsonBody(req)) as { payeeBaseUrl?: unknown; amount?: unknown };
          const payeeBaseUrl = typeof body.payeeBaseUrl === "string" ? body.payeeBaseUrl : "";
          const amount = typeof body.amount === "number" ? body.amount : Number(body.amount);
          if (!payeeBaseUrl || !Number.isFinite(amount) || amount <= 0) {
            json(res, 400, { settled: false, error: "body requires { payeeBaseUrl: string, amount: number > 0 }" });
            return;
          }
          // The gate: verify the payee BEFORE any value moves. guardSettlement fails
          // closed on any transport/parse/policy failure. `now` is advanced by the
          // skew tolerance so a payee's freshly-signed handshake (a few ms in our
          // future on a real socket) is not rejected as stale.
          const skewMs = opts.handshakeSkewMs ?? 2000;
          const policy: VerificationPolicy = {
            ...opts.payPolicy,
            now: new Date(now().getTime() + skewMs).toISOString(),
          };
          const { allow, verdict } = await guardSettlement(httpFetch, payeeBaseUrl, policy, {
            verifierId: operatorId,
          });
          if (allow) {
            // No real money - this is the gate demo. A real agent would call its rail here.
            json(res, 200, {
              settled: true,
              amount,
              payeeBaseUrl,
              checks: verdict.disclosure.checks,
            });
          } else {
            json(res, 402, { settled: false, refused: true, reasons: verdict.reasons, payeeBaseUrl });
          }
          return;
        }
        json(res, 404, { error: "not found" });
      } catch (e) {
        json(res, 500, { error: e instanceof Error ? e.message : String(e) });
      }
    })();
  });

  const port = opts.port ?? Number(process.env.PORT ?? DEFAULT_PORT);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, () => resolve());
  });
  const addr = server.address();
  const boundPort = typeof addr === "object" && addr ? addr.port : port;
  const baseUrl = `http://localhost:${boundPort}`;

  return {
    server,
    port: boundPort,
    baseUrl,
    disclosureUrl: `${baseUrl}${DISCLOSURE_PATH}`,
    agentId: key.publicKeyHex,
    signed,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

// Run directly: serve until killed.
if (process.argv[1]?.endsWith("server.ts")) {
  startReferenceAgent().then((agent) => {
    console.log(`reference agent listening on ${agent.baseUrl}`);
    console.log(`  disclosure: ${agent.disclosureUrl}`);
    console.log(`  health:     ${agent.baseUrl}${HEALTH_PATH}`);
    console.log(`  agentId:    ${agent.agentId}`);
  });
}
