// A real-socket disclosure server. Serves a freshly signed `SignedDisclosure` at
// GET /.well-known/agent-disclosure over node:http, so any verifier - in any
// language - can fetch and verify a live disclosure over a real socket. This is the
// concrete transport behind the well-known URI the protocol specifies; the in-memory
// FetchLike in examples/two-agents.ts proves the loop, this proves it over a port.
//
// The disclosure is minted at startup from a freshly generated ed25519 key and a
// minimal hand-built disclosure (issuedAt = now, a one-hour freshness window), then
// signed once. The agentId is the signing key, so a counterparty can verify with no
// shared secret and no registry.
//
// Run: node --import tsx scripts/serveDisclosure.ts [port]
//   env PORT overrides; arg overrides env; default 8799.

import { createServer, type Server } from "node:http";

import {
  generateAgentKeyPair,
  signDisclosure,
  sha256Hex,
  type AgentDisclosure,
  type SignedDisclosure,
  type AgentKeyPair,
} from "../src/index.ts";

export const DISCLOSURE_PATH = "/.well-known/agent-disclosure";
const DEFAULT_PORT = 8799;

/** Mint a minimal, valid disclosure signed by a fresh key, fresh for `windowMs`. */
export function mintDisclosure(now = new Date(), windowMs = 60 * 60 * 1000): {
  signed: SignedDisclosure;
  key: AgentKeyPair;
} {
  const key = generateAgentKeyPair();
  const anchor = sha256Hex(`served-audit-head:${now.toISOString()}`);
  const disclosure: AgentDisclosure = {
    version: 1,
    disclosureId: `disc_served_${now.getTime()}`,
    agentId: key.publicKeyHex,
    issuedAt: now.toISOString(),
    validUntil: new Date(now.getTime() + windowMs).toISOString(),
    nonce: `n-served-${now.getTime()}`,
    auditAnchor: anchor,
    systemPrompt: { algorithm: "sha256", digest: sha256Hex("served system prompt") },
    constitution: {
      hardConstraints: [{ id: "no-wire", description: "no wire transfers", kind: "deny" }],
      digest: sha256Hex("served constitution"),
      enforced: true,
    },
    tools: { tools: [{ name: "pay", access: "gated", movesValue: true }], valuePath: "pay" },
    capital: { mandates: [], custody: "non_custodial" },
    operator: {
      operatorId: "served-ops",
      attestation: { scheme: "none", level: "none" },
      deniabilityBoundary: "operator accountable for mandate config only",
    },
    history: { chainAnchor: anchor, summary: { totalDecisions: 7, settledCount: 6, blockedCount: 1 } },
  };
  return { signed: signDisclosure(disclosure, key), key };
}

/** Start the disclosure server on `port`, resolving once it is listening. */
export function startDisclosureServer(
  port = DEFAULT_PORT,
  signed: SignedDisclosure = mintDisclosure().signed,
): Promise<{ server: Server; port: number; url: string }> {
  const body = JSON.stringify(signed);
  const server = createServer((req, res) => {
    if (req.method === "GET" && req.url === DISCLOSURE_PATH) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, () => {
      const addr = server.address();
      const boundPort = typeof addr === "object" && addr ? addr.port : port;
      resolve({ server, port: boundPort, url: `http://localhost:${boundPort}${DISCLOSURE_PATH}` });
    });
  });
}

// Run directly: serve until killed.
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("serveDisclosure.ts")) {
  const port = Number(process.argv[2] ?? process.env.PORT ?? DEFAULT_PORT);
  startDisclosureServer(port).then(({ url }) => {
    console.log(`serving signed disclosure at ${url}`);
  });
}
