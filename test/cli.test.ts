import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runCli, type CliIo } from "../src/cli.ts";
import {
  generateAgentKeyPair,
  exportAgentKey,
  signDisclosure,
  respondToChallenge,
  sha256Hex,
  type AgentDisclosure,
  type FetchLike,
  type Challenge,
} from "../src/index.ts";

const NOW = "2026-06-24T12:00:00.000Z";
const LATER = "2026-06-24T13:00:00.000Z";
const H = sha256Hex("anchor");

// Capture stdout/stderr; verify-url tests inject a fetch, others never touch it.
function harness(fetch?: FetchLike): { io: CliIo; out: () => string; err: () => string } {
  const outLines: string[] = [];
  const errLines: string[] = [];
  const io: CliIo = {
    out: (line) => outLines.push(line),
    err: (line) => errLines.push(line),
    fetch: fetch ?? (async () => {
      throw new Error("network access not permitted in test");
    }),
  };
  return { io, out: () => outLines.join("\n"), err: () => errLines.join("\n") };
}

function disclosure(agentId: string, opts: { enforced?: boolean } = {}): AgentDisclosure {
  return {
    version: 1,
    disclosureId: "disc_1",
    agentId,
    issuedAt: NOW,
    validUntil: LATER,
    nonce: "n1",
    auditAnchor: H,
    systemPrompt: { algorithm: "sha256", digest: H },
    constitution: { hardConstraints: [], digest: H, enforced: opts.enforced ?? true },
    tools: { tools: [] },
    capital: { mandates: [], custody: "non_custodial" },
    operator: { operatorId: "op", attestation: { scheme: "none", level: "none" }, deniabilityBoundary: "x" },
    history: { chainAnchor: H, summary: { totalDecisions: 1, settledCount: 1, blockedCount: 0 } },
  };
}

async function withTmp(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "adp-cli-"));
  try {
    await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("keygen prints a 64-hex public key", async () => {
  const { io, out } = harness();
  const code = await runCli(["keygen"], io);
  assert.equal(code, 0);
  const match = out().match(/publicKeyHex \(agentId\): ([0-9a-f]+)/);
  assert.ok(match, out());
  assert.equal(match[1].length, 64);
});

test("keygen --out writes a usable key file", async () => {
  await withTmp(async (dir) => {
    const keyPath = join(dir, "key.json");
    const { io, out } = harness();
    const code = await runCli(["keygen", "--out", keyPath], io);
    assert.equal(code, 0);
    assert.match(out(), /wrote key to/);
    const parsed = JSON.parse(readFileSync(keyPath, "utf8"));
    assert.equal(parsed.publicKeyHex.length, 64);
    assert.ok(typeof parsed.privateKeyHex === "string" && parsed.privateKeyHex.length > 0);
  });
});

test("sign then verify-file returns transact and exits 0", async () => {
  await withTmp(async (dir) => {
    const key = generateAgentKeyPair();
    const discPath = join(dir, "disclosure.json");
    const keyPath = join(dir, "key.hex");
    const signedPath = join(dir, "signed.json");
    writeFileSync(discPath, JSON.stringify(disclosure(key.publicKeyHex)));
    writeFileSync(keyPath, exportAgentKey(key));

    const sign = harness();
    const signCode = await runCli(["sign", "--in", discPath, "--key", keyPath, "--out", signedPath], sign.io);
    assert.equal(signCode, 0, sign.err());

    const verify = harness();
    const verifyCode = await runCli(["verify-file", signedPath, "--now", NOW], verify.io);
    assert.equal(verifyCode, 0, verify.out());
    assert.match(verify.out(), /decision: transact/);
  });
});

test("verify-file with --require-enforced on a non-enforced disclosure refuses (nonzero)", async () => {
  await withTmp(async (dir) => {
    const key = generateAgentKeyPair();
    const signed = signDisclosure(disclosure(key.publicKeyHex, { enforced: false }), key);
    const signedPath = join(dir, "signed.json");
    writeFileSync(signedPath, JSON.stringify(signed));

    const { io, out } = harness();
    const code = await runCli(["verify-file", signedPath, "--now", NOW, "--require-enforced"], io);
    assert.equal(code, 1);
    assert.match(out(), /decision: refuse/);
    assert.match(out(), /not enforced/);
  });
});

test("verify-file refuses a malformed envelope (nonzero)", async () => {
  await withTmp(async (dir) => {
    const signedPath = join(dir, "bad.json");
    writeFileSync(signedPath, JSON.stringify({ not: "a disclosure" }));
    const { io, out } = harness();
    const code = await runCli(["verify-file", signedPath, "--now", NOW], io);
    assert.equal(code, 1);
    assert.match(out(), /decision: refuse/);
  });
});

test("verify-url transacts against an in-memory peer (no real network)", async () => {
  const key = generateAgentKeyPair();
  const signed = signDisclosure(disclosure(key.publicKeyHex), key);
  const peer: FetchLike = async (url, init) => {
    const path = new URL(url).pathname;
    if (path === "/.well-known/agent-disclosure") {
      return { ok: true, status: 200, json: async () => signed };
    }
    if (path === "/agent-disclosure/respond") {
      const challenge = JSON.parse(init?.body ?? "{}") as Challenge;
      return { ok: true, status: 200, json: async () => respondToChallenge(challenge, key, H, NOW) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };

  const { io, out } = harness(peer);
  const code = await runCli(["verify-url", "http://peer", "--now", NOW, "--require-enforced"], io);
  assert.equal(code, 0, out());
  assert.match(out(), /decision: transact/);
  assert.match(out(), /handshake: ok/);
});

test("verify-url fails closed when the peer is unreachable (nonzero)", async () => {
  const peer: FetchLike = async () => {
    throw new Error("down");
  };
  const { io, out } = harness(peer);
  const code = await runCli(["verify-url", "http://peer", "--now", NOW], io);
  assert.equal(code, 1);
  assert.match(out(), /decision: refuse/);
});

test("sign with a missing --key reports an error and exits nonzero", async () => {
  await withTmp(async (dir) => {
    const discPath = join(dir, "disclosure.json");
    const key = generateAgentKeyPair();
    writeFileSync(discPath, JSON.stringify(disclosure(key.publicKeyHex)));
    const { io, err } = harness();
    const code = await runCli(["sign", "--in", discPath], io);
    assert.equal(code, 2);
    assert.match(err(), /--key/);
  });
});

test("an unknown command exits nonzero with usage", async () => {
  const { io, err } = harness();
  const code = await runCli(["frobnicate"], io);
  assert.equal(code, 2);
  assert.match(err(), /unknown command/);
});

test("help exits 0 and prints usage", async () => {
  const { io, out } = harness();
  const code = await runCli(["help"], io);
  assert.equal(code, 0);
  assert.match(out(), /Usage:/);
});

test("no args prints usage and exits nonzero", async () => {
  const { io, out } = harness();
  const code = await runCli([], io);
  assert.equal(code, 1);
  assert.match(out(), /Usage:/);
});
