import test from "node:test";
import assert from "node:assert/strict";

import { StatusList, StatusListEntrySchema, checkStatus } from "../src/statusList.ts";

test("setRevoked / isRevoked set and read individual bits", () => {
  const list = new StatusList();
  assert.equal(list.isRevoked(0), false);
  assert.equal(list.isRevoked(42), false);

  list.setRevoked(42);
  assert.equal(list.isRevoked(42), true);
  assert.equal(list.isRevoked(41), false);
  assert.equal(list.isRevoked(43), false);
});

test("size reflects the bitstring length and grows on a high index", () => {
  const list = new StatusList(64);
  assert.equal(list.size, 64);
  assert.equal(list.isRevoked(10_000), false);
  list.setRevoked(10_000);
  assert.ok(list.size > 10_000);
  assert.equal(list.isRevoked(10_000), true);
});

test("encode -> decode round-trips and preserves revocations", () => {
  const list = new StatusList();
  list.setRevoked(1);
  list.setRevoked(7);
  list.setRevoked(4096);

  const restored = StatusList.decode(list.encode());
  assert.equal(restored.isRevoked(1), true);
  assert.equal(restored.isRevoked(7), true);
  assert.equal(restored.isRevoked(4096), true);
  assert.equal(restored.isRevoked(2), false);
  assert.equal(restored.isRevoked(8), false);
});

test("checkStatus resolves an entry against a list", () => {
  const entry = StatusListEntrySchema.parse({
    statusListUrl: "https://x/list",
    statusListIndex: 99,
  });
  const list = new StatusList();
  assert.equal(checkStatus(entry, list), false);
  list.setRevoked(99);
  assert.equal(checkStatus(entry, list), true);
});

test("a non-integer status index is rejected", () => {
  const list = new StatusList();
  assert.throws(() => list.setRevoked(1.5));
  assert.throws(() => list.setRevoked(-1));
});
