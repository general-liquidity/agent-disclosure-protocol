import assert from "node:assert/strict";
import { test } from "node:test";
import { generateAgentKeyPair } from "../src/attestation.ts";
import {
  __setDidResolverLoaders,
  agentIdToDidDocument,
  didWeb,
  didWebToUrl,
  resolveDidWebFetch,
  resolveDidWebWithResolver,
  type DidDocument,
} from "../src/did.ts";

test("didWebToUrl maps bare domain to the .well-known did.json URL", () => {
  assert.equal(didWebToUrl("did:web:example.com"), "https://example.com/.well-known/did.json");
});

test("didWebToUrl maps a path did:web to the path did.json URL", () => {
  assert.equal(
    didWebToUrl(didWeb("example.com", "agents/gordon")),
    "https://example.com/agents/gordon/did.json",
  );
});

test("didWebToUrl rejects a non-did:web", () => {
  assert.throws(() => didWebToUrl("did:key:zabc"), /did:web/);
});

// ── bespoke fetch resolution (no optional dep) ────────────────────────────────

function mockFetch(doc: DidDocument | undefined, status = 200): typeof fetch {
  return (async () =>
    ({
      ok: status >= 200 && status < 300,
      status,
      json: async () => doc,
    }) as unknown as Response) as unknown as typeof fetch;
}

test("resolveDidWebFetch returns the expected document for a matching id", async () => {
  const key = generateAgentKeyPair();
  const did = didWeb("agent.example");
  const doc = { ...agentIdToDidDocument(key.publicKeyHex), id: did } as DidDocument;

  const res = await resolveDidWebFetch(did, { fetchImpl: mockFetch(doc) });
  assert.equal(res.ok, true, res.reason);
  assert.deepEqual(res.document, doc);
});

test("resolveDidWebFetch rejects a document whose id does not match the DID", async () => {
  const key = generateAgentKeyPair();
  const doc = { ...agentIdToDidDocument(key.publicKeyHex), id: "did:web:other.example" } as DidDocument;
  const res = await resolveDidWebFetch("did:web:agent.example", { fetchImpl: mockFetch(doc) });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /does not match/);
});

test("resolveDidWebFetch surfaces a non-200 as an error", async () => {
  const res = await resolveDidWebFetch("did:web:agent.example", {
    fetchImpl: mockFetch(undefined, 404),
  });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /HTTP 404/);
});

// ── optional web-did-resolver path (mocked deps) ──────────────────────────────

test("resolveDidWebWithResolver returns the document from the injected resolver modules", async () => {
  const did = "did:web:agent.example";
  const doc = { "@context": ["https://www.w3.org/ns/did/v1"], id: did } as unknown as DidDocument;

  __setDidResolverLoaders({
    webDidResolver: async () => ({ getResolver: () => ({ web: () => {} }) }),
    didResolver: async () => ({
      Resolver: class {
        async resolve(_d: string) {
          return { didDocument: doc, didResolutionMetadata: {} };
        }
      },
    }),
  });

  const res = await resolveDidWebWithResolver(did);
  assert.equal(res.ok, true, res.reason);
  assert.deepEqual(res.document, doc);
});

test("resolveDidWebWithResolver surfaces a resolver error", async () => {
  __setDidResolverLoaders({
    webDidResolver: async () => ({ getResolver: () => ({}) }),
    didResolver: async () => ({
      Resolver: class {
        async resolve(_d: string) {
          return { didDocument: null, didResolutionMetadata: { error: "notFound" } };
        }
      },
    }),
  });

  const res = await resolveDidWebWithResolver("did:web:missing.example");
  assert.equal(res.ok, false);
  assert.equal(res.reason, "notFound");
});

test("resolveDidWebWithResolver throws an install hint when the optional dep is absent", async () => {
  __setDidResolverLoaders({
    webDidResolver: async () => {
      throw new Error("Cannot find module 'web-did-resolver'");
    },
  });
  await assert.rejects(() => resolveDidWebWithResolver("did:web:agent.example"), /web-did-resolver/);
});
