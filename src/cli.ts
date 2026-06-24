#!/usr/bin/env node
// A dependency-free CLI for the Agent Disclosure Protocol. Mints signing keys,
// signs a caller-supplied AgentDisclosure JSON, and verifies a disclosure (from a
// file or over the wire) against a policy assembled from flags. This package has no
// disclosure builders (those live in OpenSolvency), so `sign` consumes a disclosure
// document the user already has.
//
// `runCli` returns an exit code and accepts injected io (out/err writers + fetch) so
// it is unit-testable with no real network or process exit.

import { readFileSync, writeFileSync } from "node:fs";
import process from "node:process";
import { pathToFileURL } from "node:url";

import {
  generateAgentKeyPair,
  exportAgentKey,
  agentKeyFromPrivateHex,
  signDisclosure,
  parseDisclosure,
  evaluateDisclosure,
  verifyAndEvaluate,
  verifyCounterparty,
  type VerificationPolicy,
  type DisclosureVerdict,
  type CounterpartyVerdict,
  type Grade,
  type FetchLike,
} from "./index.ts";

export interface CliIo {
  out: (line: string) => void;
  err: (line: string) => void;
  /** injected for verify-url so tests need no real network */
  fetch: FetchLike;
}

function defaultIo(): CliIo {
  return {
    out: (line) => process.stdout.write(`${line}\n`),
    err: (line) => process.stderr.write(`${line}\n`),
    fetch: globalThis.fetch as unknown as FetchLike,
  };
}

const USAGE = `agent-disclosure - sign and verify Agent Disclosure Protocol documents

Usage:
  agent-disclosure keygen [--out <file>]
  agent-disclosure sign --in <disclosure.json> --key <hex|file> [--out <file>]
  agent-disclosure verify-file <signed.json> [policy flags]
  agent-disclosure verify-url <baseUrl> [policy flags]
  agent-disclosure help

Policy flags (verify-file / verify-url):
  --require-enforced     constitution must be enforced at runtime
  --non-custodial        require non-custodial operation
  --min-grade <A-F>      minimum red-team grade
  --require-history      require a non-empty deployment history
  --now <iso>            clock for the freshness check (default: now)

keygen   mint an ed25519 identity; prints the private key (PKCS8 hex) + public key (agentId)
sign     sign an AgentDisclosure JSON, writing the SignedDisclosure envelope
verify   parse + evaluate a disclosure, print the verdict; exit nonzero on refuse`;

// Tiny flag parser: collects --flag <value> pairs, boolean --flag toggles, and
// leading positional args. No external arg library.
interface ParsedArgs {
  positionals: string[];
  flags: Map<string, string>;
  bools: Set<string>;
}

const VALUE_FLAGS = new Set(["out", "in", "key", "min-grade", "now"]);

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags = new Map<string, string>();
  const bools = new Set<string>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const name = arg.slice(2);
      if (VALUE_FLAGS.has(name)) {
        const value = argv[++i];
        if (value === undefined) throw new Error(`flag --${name} requires a value`);
        flags.set(name, value);
      } else {
        bools.add(name);
      }
    } else {
      positionals.push(arg);
    }
  }
  return { positionals, flags, bools };
}

const GRADES: ReadonlySet<string> = new Set<Grade>(["A", "B", "C", "D", "F"]);

// Build a VerificationPolicy from the parsed policy flags.
function buildPolicy(args: ParsedArgs): VerificationPolicy {
  const policy: VerificationPolicy = { now: args.flags.get("now") ?? new Date().toISOString() };
  if (args.bools.has("require-enforced")) policy.requireEnforcedConstitution = true;
  if (args.bools.has("non-custodial")) policy.requireNonCustodial = true;
  if (args.bools.has("require-history")) policy.requireDeploymentHistory = true;
  const minGrade = args.flags.get("min-grade");
  if (minGrade !== undefined) {
    if (!GRADES.has(minGrade)) throw new Error(`--min-grade must be one of A B C D F (got ${minGrade})`);
    policy.minRedTeamGrade = minGrade as Grade;
  }
  return policy;
}

// A hex key may be passed inline or via a file path. A 64+ char hex string is read
// as inline material; anything else is treated as a file to read.
function resolveKeyHex(keyArg: string): string {
  const trimmed = keyArg.trim();
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length >= 32) return trimmed;
  return readFileSync(keyArg, "utf8").trim();
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

// Render a static-disclosure verdict for the terminal.
function renderVerdict(io: CliIo, verdict: DisclosureVerdict): void {
  io.out(`decision: ${verdict.decision}`);
  const checks = Object.entries(verdict.checks);
  if (checks.length > 0) {
    io.out("checks:");
    for (const [name, ok] of checks) io.out(`  ${ok ? "pass" : "fail"} ${name}`);
  }
  if (verdict.reasons.length > 0) {
    io.out("reasons:");
    for (const reason of verdict.reasons) io.out(`  - ${reason}`);
  }
  io.out(`cost: ${verdict.cost.checksRun} checks, ${verdict.cost.wallMicros}us`);
}

function cmdKeygen(io: CliIo, args: ParsedArgs): number {
  const key = generateAgentKeyPair();
  const privateHex = exportAgentKey(key);
  const out = args.flags.get("out");
  if (out !== undefined) {
    writeFileSync(out, `${JSON.stringify({ privateKeyHex: privateHex, publicKeyHex: key.publicKeyHex }, null, 2)}\n`);
    io.out(`wrote key to ${out}`);
    io.out(`agentId (publicKey): ${key.publicKeyHex}`);
  } else {
    io.out(`privateKeyHex: ${privateHex}`);
    io.out(`publicKeyHex (agentId): ${key.publicKeyHex}`);
  }
  return 0;
}

function cmdSign(io: CliIo, args: ParsedArgs): number {
  const inPath = args.flags.get("in");
  const keyArg = args.flags.get("key");
  if (inPath === undefined) {
    io.err("sign: --in <disclosure.json> is required");
    return 2;
  }
  if (keyArg === undefined) {
    io.err("sign: --key <hex|file> is required");
    return 2;
  }
  const disclosure = parseDisclosure(readJson(inPath));
  const key = agentKeyFromPrivateHex(resolveKeyHex(keyArg));
  const signed = signDisclosure(disclosure, key);
  const serialized = `${JSON.stringify(signed, null, 2)}\n`;
  const out = args.flags.get("out");
  if (out !== undefined) {
    writeFileSync(out, serialized);
    io.out(`wrote signed disclosure to ${out}`);
  } else {
    io.out(serialized.trimEnd());
  }
  return 0;
}

function cmdVerifyFile(io: CliIo, args: ParsedArgs): number {
  const path = args.positionals[0];
  if (path === undefined) {
    io.err("verify-file: a <signed.json> path is required");
    return 2;
  }
  const policy = buildPolicy(args);
  const verdict = verifyAndEvaluate(readJson(path), policy);
  renderVerdict(io, verdict);
  return verdict.decision === "transact" ? 0 : 1;
}

async function cmdVerifyUrl(io: CliIo, args: ParsedArgs): Promise<number> {
  const baseUrl = args.positionals[0];
  if (baseUrl === undefined) {
    io.err("verify-url: a <baseUrl> is required");
    return 2;
  }
  const policy = buildPolicy(args);
  const verdict: CounterpartyVerdict = await verifyCounterparty(io.fetch, baseUrl, policy);
  io.out(`decision: ${verdict.decision}`);
  io.out("disclosure:");
  renderVerdict(
    { ...io, out: (line) => io.out(`  ${line}`) },
    verdict.disclosure,
  );
  if (verdict.handshake) {
    io.out(`handshake: ${verdict.handshake.ok ? "ok" : `fail (${verdict.handshake.reason})`}`);
  }
  if (verdict.reasons.length > 0) {
    io.out("reasons:");
    for (const reason of verdict.reasons) io.out(`  - ${reason}`);
  }
  return verdict.decision === "transact" ? 0 : 1;
}

/** Run the CLI. Returns a process exit code. Errors print to stderr and return
 *  nonzero. `io` is injected so callers (and tests) can capture output + fetch. */
export async function runCli(argv: string[], io: CliIo = defaultIo()): Promise<number> {
  const [command, ...rest] = argv;

  if (command === undefined || command === "help" || command === "--help" || command === "-h") {
    io.out(USAGE);
    return command === undefined ? 1 : 0;
  }

  let args: ParsedArgs;
  try {
    args = parseArgs(rest);
  } catch (e) {
    io.err(e instanceof Error ? e.message : String(e));
    return 2;
  }

  try {
    switch (command) {
      case "keygen":
        return cmdKeygen(io, args);
      case "sign":
        return cmdSign(io, args);
      case "verify-file":
        return cmdVerifyFile(io, args);
      case "verify-url":
        return await cmdVerifyUrl(io, args);
      default:
        io.err(`unknown command: ${command}`);
        io.err(USAGE);
        return 2;
    }
  } catch (e) {
    io.err(`error: ${e instanceof Error ? e.message : String(e)}`);
    return 1;
  }
}

// `evaluateDisclosure` is re-exported for callers that already hold a parsed,
// signature-checked envelope and want to skip the JSON round-trip.
export { evaluateDisclosure };

const entry = process.argv[1];
const isMain = entry !== undefined && import.meta.url === pathToFileURL(entry).href;
if (isMain) {
  runCli(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (e) => {
      process.stderr.write(`fatal: ${e instanceof Error ? e.stack : String(e)}\n`);
      process.exitCode = 1;
    },
  );
}
