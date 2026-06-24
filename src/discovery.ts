// Discovery. Before a verifier can verify a counterparty it has to FIND it: resolve
// an agentId to a base URL, then fetch + verify the disclosure served there. This is
// the portable directory + the well-known fetch that sit in front of verifyCounterparty.
//
// Vendor-neutral: depends only on the schema + client layer + an injected fetch.

import { parseSignedDisclosure, type SignedDisclosure } from "./schema.ts";
import {
  verifyCounterparty,
  type FetchLike,
  type VerifyCounterpartyOptions,
  type CounterpartyVerdict,
} from "./client.ts";
import type { VerificationPolicy } from "./verify.ts";

/**
 * Fetch a counterparty's signed disclosure from its well-known endpoint and parse it.
 * Throws on non-200 or a parse failure — discovery fails loud, the policy decides.
 */
export async function fetchDisclosure(fetch: FetchLike, baseUrl: string): Promise<SignedDisclosure> {
  const base = baseUrl.replace(/\/$/, "");
  const res = await fetch(`${base}/.well-known/agent-disclosure`);
  if (!res.ok) throw new Error(`disclosure fetch failed (HTTP ${res.status})`);
  return parseSignedDisclosure(await res.json());
}

export interface AgentDirectoryEntry {
  agentId: string;
  baseUrl: string;
}

/**
 * An in-memory agentId -> base-URL registry. The portable directory a verifier
 * resolves a counterparty's serving location from before discovering its disclosure.
 * Serializable so a fleet can persist / ship a shared directory.
 */
export class AgentDirectory {
  private readonly map = new Map<string, string>();

  register(agentId: string, baseUrl: string): void {
    this.map.set(agentId, baseUrl);
  }

  lookup(agentId: string): string | undefined {
    return this.map.get(agentId);
  }

  entries(): AgentDirectoryEntry[] {
    return [...this.map.entries()].map(([agentId, baseUrl]) => ({ agentId, baseUrl }));
  }

  toJSON(): AgentDirectoryEntry[] {
    return this.entries();
  }

  static fromJSON(entries: AgentDirectoryEntry[]): AgentDirectory {
    const dir = new AgentDirectory();
    for (const { agentId, baseUrl } of entries) dir.register(agentId, baseUrl);
    return dir;
  }
}

/**
 * Resolve an agentId through the directory, then verify the counterparty served there.
 * Refuses (fail closed) if the agentId is unknown — an unresolvable identity is not a
 * counterparty you transact with.
 */
export async function discoverAndVerify(
  fetch: FetchLike,
  directory: AgentDirectory,
  agentId: string,
  policy: VerificationPolicy,
  opts?: VerifyCounterpartyOptions,
): Promise<CounterpartyVerdict> {
  const baseUrl = directory.lookup(agentId);
  if (!baseUrl) {
    const reason = `unknown agent: ${agentId}`;
    return {
      decision: "refuse",
      disclosure: { decision: "refuse", checks: {}, reasons: [reason], cost: { checksRun: 0, wallMicros: 0 } },
      reasons: [reason],
    };
  }
  return verifyCounterparty(fetch, baseUrl, policy, opts);
}
