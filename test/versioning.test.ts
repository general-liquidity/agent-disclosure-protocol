import test from "node:test";
import assert from "node:assert/strict";

import { SUPPORTED_DISCLOSURE_VERSIONS, isSupportedVersion, peekDisclosureVersion } from "../src/versioning.ts";
import { DISCLOSURE_SCHEMA_VERSION } from "../src/index.ts";

test("supported versions include the current schema version", () => {
  assert.ok(SUPPORTED_DISCLOSURE_VERSIONS.includes(DISCLOSURE_SCHEMA_VERSION));
  assert.equal(isSupportedVersion(DISCLOSURE_SCHEMA_VERSION), true);
  assert.equal(isSupportedVersion(999), false);
  assert.equal(isSupportedVersion("1"), false);
});

test("peekDisclosureVersion reads the version without a full parse", () => {
  assert.equal(peekDisclosureVersion({ disclosure: { version: 1 } }), 1);
  assert.equal(peekDisclosureVersion({ disclosure: { version: 2 } }), 2); // a future version, still peekable
  assert.equal(peekDisclosureVersion({}), null);
  assert.equal(peekDisclosureVersion(null), null);
  assert.equal(peekDisclosureVersion({ disclosure: {} }), null);
});
