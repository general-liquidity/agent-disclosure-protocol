import test from "node:test";
import assert from "node:assert/strict";

import { RevocationList } from "../src/revocation.ts";
import {
  fetchRevocationList,
  loadRevocationOracle,
  revocationOracle,
  serveRevocationList,
} from "../src/revocationTransport.ts";
import type { FetchLike } from "../src/client.ts";

const AT = "2026-06-24T12:00:00.000Z";

// A publisher served over an in-memory wire: GETs return the JSON it serves.
function publisher(list: RevocationList): FetchLike {
  return async () => ({ ok: true, status: 200, json: async () => JSON.parse(serveRevocationList(list)) });
}

test("a revoked id is caught after fetch + wrap", async () => {
  const list = new RevocationList();
  list.revoke("disc_1", "key compromised", AT);

  const oracle = await loadRevocationOracle(publisher(list), "http://pub/revocations");
  assert.equal(oracle("disc_1"), true);
});

test("a fresh-list miss returns not-revoked", async () => {
  const list = new RevocationList();
  list.revoke("disc_1", "key compromised", AT);

  const oracle = await loadRevocationOracle(publisher(list), "http://pub/revocations");
  assert.equal(oracle("agent_never_revoked"), false);
});

test("fetchRevocationList round-trips entries off the wire", async () => {
  const list = new RevocationList();
  list.revoke("disc_1", "compromised", AT);
  list.revoke("agent_xyz", "decommissioned", "2026-06-25T00:00:00.000Z");

  const fetched = await fetchRevocationList(publisher(list), "http://pub/revocations");
  assert.deepEqual(fetched.entries(), list.entries());
});

test("revocationOracle wraps a list directly", () => {
  const list = new RevocationList();
  list.revoke("agent_xyz", "decommissioned", AT);
  const oracle = revocationOracle(list);
  assert.equal(oracle("agent_xyz"), true);
  assert.equal(oracle("disc_other"), false);
});

test("fetchRevocationList fails closed on an unreachable list (does not return empty)", async () => {
  const down: FetchLike = async () => ({ ok: false, status: 503, json: async () => ({}) });
  await assert.rejects(() => fetchRevocationList(down, "http://pub/revocations"), /503/);
});
