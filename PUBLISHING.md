# Publishing `@general-liquidity/agent-disclosure`

This package is the TypeScript reference implementation of the Agent Disclosure Protocol
(ADP). The native ports (`go/`, `python/`, `rust/`, `c/`) are conformance reference
implementations that ride in the repo — they are **not** published to npm (the tarball
ships only `dist/` + `SPEC.md`, `THREAT_MODEL.md`, `LICENSE`, `README.md`).

## What ships

`npm pack --dry-run` confirms the tarball: `dist/` (compiled JS + `.d.ts`) plus the four
docs. The `files` field in `package.json` excludes everything else (tests, conformance,
schema, scripts, native ports). Current package: **`@general-liquidity/agent-disclosure@0.1.0`**.

## Pre-publish checklist

```sh
npm run build            # tsc -> dist/ (also runs automatically via prepublishOnly)
npm test                 # 253 tests
npm run conformance      # cross-language contract (TS leg)
npm run schema           # regenerate schema artifacts (no-op diff if in sync)
npm pack --dry-run       # confirm tarball contents + version
```

## First publish (manual — do this once)

A brand-new package has to be created by an authenticated publish; npm Trusted Publishing
can only be configured for a package that already exists. So the **first** publish is
manual, from a maintainer's machine with npm login + 2FA:

```sh
npm login                                   # if not already logged in
npm publish --access public --provenance    # creates the package on npm
```

`--access public` is required for a scoped (`@general-liquidity/…`) package.
`--provenance` attaches a supply-chain attestation (needs npm >= 11.5.1: `npm i -g npm@latest`).

## Subsequent releases (automated, tokenless)

After the first publish, wire up **Trusted Publishing** so GitHub Releases publish
automatically with no NPM_TOKEN secret:

1. On npmjs.com → the package → **Settings → Trusted Publisher** → add a GitHub Actions
   publisher: repository `general-liquidity/agent-disclosure-protocol`, workflow
   `publish.yml`, environment (leave blank).
2. Thereafter, to release version `X.Y.Z`:
   ```sh
   npm version X.Y.Z          # bumps package.json + creates a git tag vX.Y.Z
   git push && git push --tags
   ```
   Then publish a **GitHub Release** for tag `vX.Y.Z`. `.github/workflows/publish.yml`
   builds, tests, verifies the version matches the tag, and runs
   `npm publish --provenance --access public` over OIDC — no token.

(If you prefer a token instead of OIDC: add an `NPM_TOKEN` repo secret and set
`NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}` on the publish step. OIDC is recommended.)

## Downstream follow-up: OpenSolvency

OpenSolvency depends on this package. During development its `package.json` uses a local
`file:../agent-disclosure-protocol` link (the held rewire commit), which **cannot** be
pushed — it breaks OpenSolvency CI because `npm ci` can't resolve a sibling `file:` link
on a runner. Once this package is on npm:

1. In `opensolvency/package.json`, swap the dependency
   `"@general-liquidity/agent-disclosure": "file:../agent-disclosure-protocol"` →
   `"^0.1.0"` (or the published version).
2. `npm install` to refresh the lockfile, run the OpenSolvency suite, commit, and push
   `opensolvency` — CI now resolves the dependency from npm and stays green.
