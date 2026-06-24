// Smoke test for the reference agent: two real node:http agents over real sockets,
// each verifying the other before paying. Proves the deployable "adopt ADP" loop end
// to end - not the in-memory FetchLike the unit tests use, but the actual service.
//
// Run: node --import tsx --test examples/reference-agent/smoke.test.ts

import test from "node:test";
import assert from "node:assert/strict";

import { startReferenceAgent, type ReferenceAgent } from "./server.ts";

async function getJson(url: string): Promise<{ status: number; body: any }> {
  const res = await fetch(url);
  return { status: res.status, body: await res.json() };
}

async function postJson(url: string, payload: unknown): Promise<{ status: number; body: any }> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  return { status: res.status, body: await res.json() };
}

test("reference agent serves /health and a signed disclosure", async () => {
  const a = await startReferenceAgent({ port: 0, operatorId: "agent-a" });
  try {
    const health = await getJson(`${a.baseUrl}/health`);
    assert.equal(health.status, 200);
    assert.equal(health.body.ok, true);
    assert.equal(health.body.agentId, a.agentId);

    const disc = await getJson(a.disclosureUrl);
    assert.equal(disc.status, 200);
    assert.equal(disc.body.disclosure.agentId, a.agentId);
    assert.equal(disc.body.signature.publicKey, a.agentId);
    assert.equal(disc.body.disclosure.constitution.enforced, true);
  } finally {
    await a.close();
  }
});

test("A's /pay transacts against B with a met policy", async () => {
  let a: ReferenceAgent | undefined;
  let b: ReferenceAgent | undefined;
  try {
    b = await startReferenceAgent({ port: 0, operatorId: "agent-b" });
    a = await startReferenceAgent({
      port: 0,
      operatorId: "agent-a",
      payPolicy: { requireEnforcedConstitution: true, requireAuditAnchor: true },
    });

    const pay = await postJson(`${a.baseUrl}/pay`, { payeeBaseUrl: b.baseUrl, amount: 25 });
    assert.equal(pay.status, 200, JSON.stringify(pay.body));
    assert.equal(pay.body.settled, true);
    assert.equal(pay.body.amount, 25);
    assert.equal(pay.body.checks.signature, true);
    assert.equal(pay.body.checks.freshness, true);
  } finally {
    await a?.close();
    await b?.close();
  }
});

test("A's /pay refuses B under a stricter policy B cannot meet", async () => {
  let a: ReferenceAgent | undefined;
  let b: ReferenceAgent | undefined;
  try {
    b = await startReferenceAgent({ port: 0, operatorId: "agent-b" });
    // B carries no red-team attestation; this policy demands one -> refuse before value moves.
    a = await startReferenceAgent({ port: 0, operatorId: "agent-a", payPolicy: { requireRedTeam: true } });

    const pay = await postJson(`${a.baseUrl}/pay`, { payeeBaseUrl: b.baseUrl, amount: 25 });
    assert.equal(pay.status, 402, JSON.stringify(pay.body));
    assert.equal(pay.body.settled, false);
    assert.equal(pay.body.refused, true);
    assert.ok(pay.body.reasons.some((r: string) => /red-team/.test(r)), pay.body.reasons.join("; "));
  } finally {
    await a?.close();
    await b?.close();
  }
});

test("A's /pay fails closed against an unreachable payee", async () => {
  const a = await startReferenceAgent({ port: 0, operatorId: "agent-a" });
  try {
    // Port 1 is not listening; the gate must refuse rather than pay blind.
    const pay = await postJson(`${a.baseUrl}/pay`, { payeeBaseUrl: "http://localhost:1", amount: 10 });
    assert.equal(pay.status, 402, JSON.stringify(pay.body));
    assert.equal(pay.body.settled, false);
    assert.equal(pay.body.refused, true);
    assert.ok(pay.body.reasons.length > 0);
  } finally {
    await a.close();
  }
});

test("mutual: A pays B and B pays A over real sockets", async () => {
  let a: ReferenceAgent | undefined;
  let b: ReferenceAgent | undefined;
  try {
    const payPolicy = { requireEnforcedConstitution: true, requireAuditAnchor: true };
    a = await startReferenceAgent({ port: 0, operatorId: "agent-a", payPolicy });
    b = await startReferenceAgent({ port: 0, operatorId: "agent-b", payPolicy });

    const aToB = await postJson(`${a.baseUrl}/pay`, { payeeBaseUrl: b.baseUrl, amount: 5 });
    const bToA = await postJson(`${b.baseUrl}/pay`, { payeeBaseUrl: a.baseUrl, amount: 5 });

    assert.equal(aToB.body.settled, true, JSON.stringify(aToB.body));
    assert.equal(bToA.body.settled, true, JSON.stringify(bToA.body));
  } finally {
    await a?.close();
    await b?.close();
  }
});

test("/pay rejects a malformed body", async () => {
  const a = await startReferenceAgent({ port: 0, operatorId: "agent-a" });
  try {
    const pay = await postJson(`${a.baseUrl}/pay`, { amount: 10 });
    assert.equal(pay.status, 400);
    assert.equal(pay.body.settled, false);
  } finally {
    await a.close();
  }
});
