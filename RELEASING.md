# Releasing

The published artifacts of this repo (the npm package, and optionally the PyPI and
crates.io ports) publish from CI via [`.github/workflows/release.yml`](.github/workflows/release.yml)
using **OIDC Trusted Publishing** — there are **no tokens to store or rotate**. Each
registry trusts this workflow directly; GitHub mints a short-lived identity per run.

The native ports (`go/`, `python/`, `rust/`, `c/`) are conformance reference
implementations. The **npm** package (`@general-liquidity/agent-disclosure`) is the
primary artifact; PyPI and crates.io are optional and off by default.

## One-time setup (per registry, on the registry's own website)

You configure a *trusted publisher* once. Nothing is stored in GitHub except an opt-in
variable. For all three, the publisher is: **GitHub** owner `general-liquidity`, repo
`agent-disclosure-protocol`, workflow file `release.yml`.

| Registry | Package | Where | First-publish note |
|---|---|---|---|
| **npm** | `@general-liquidity/agent-disclosure` | package page → *Settings → Trusted Publisher* | The package is **new**, so a trusted publisher can't be added until it exists. Do **one** initial manual publish to claim the name (below), then add the trusted publisher and never use a token again. Needs npm ≥ 11.5 (the workflow upgrades it); provenance is automatic. |
| **PyPI** | `agent-disclosure` | Account → Publishing → *Add a pending publisher* | Fully tokenless, **including the first publish** (a pending publisher covers a not-yet-existing project). |
| **crates.io** | `agent-disclosure` | crate → *Settings → Trusted Publishing* | A crate must exist first. Do **one** initial `cargo publish` with a token to claim the name, then add the trusted publisher and never use a token again. |

Then, in **Settings → Variables → Actions**, set the opt-in flag(s):
`PUBLISH_NPM=true`, `PUBLISH_PYPI=true`, `PUBLISH_CRATES=true`. With a variable unset,
that job is skipped — so the workflow is safe to land before anything is configured.

### Initial manual publish (npm — claim the name, do this once)

```sh
npm install -g npm@latest                   # provenance needs npm >= 11.5
npm publish --access public --provenance     # from the repo root; runs prepublishOnly (build)
```

Then add the npm Trusted Publisher (above) and flip `PUBLISH_NPM=true`. From then on,
releases are just a tag.

## Cutting a release

1. Bump the version in each artifact you're releasing:
   - `package.json` (npm), `python/pyproject.toml` (PyPI), `rust/Cargo.toml` (crates.io)
2. Update `CHANGELOG.md`.
3. Commit, then tag and push:
   ```sh
   git tag v0.1.1 && git push origin v0.1.1
   ```
   The tag triggers `release.yml`; each **enabled** registry publishes (and skips a
   version that already exists, so re-runs are idempotent). Or run it from the Actions
   tab via *workflow_dispatch*.

With OIDC trusted publishing, npm attaches **provenance** automatically, so each release
carries a signed attestation that it was built from this repo + commit.

## Go (no registry — git is the registry)

The Go port is consumed straight from the repo, so "publishing" is just a tag in the
**subdirectory module** form Go expects:

```sh
git tag go/v0.1.1 && git push origin go/v0.1.1
```

Consumers then `go get github.com/general-liquidity/agent-disclosure-protocol/go@v0.1.1`.

## C

No central registry. Distributed as source (`c/agent_disclosure.{c,h}` + the vendored
cJSON), vendored into a downstream build. The release is the git tag.

## Name availability (check before the first publish)

The npm name is owned by the `general-liquidity` org. Verify the others are free before
enabling their jobs: `pip index versions agent-disclosure` (PyPI) and
`cargo search agent-disclosure` (crates.io). If taken, scope/rename in the manifest.

## Downstream: OpenSolvency

OpenSolvency depends on this package via a local `file:../agent-disclosure-protocol`
link (the held rewire commit) that **cannot** be pushed — it breaks OpenSolvency CI. Once
`@general-liquidity/agent-disclosure` is on npm, swap that dependency to `^0.1.0`,
`npm install`, run the suite, and push OpenSolvency — CI then resolves it from npm.
