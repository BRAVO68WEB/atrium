# Testing

Go tests cover the packages. A Playwright suite drives the browser and
the protocol. The commands a pull request must pass are also listed in
[Contributing](../CONTRIBUTING.md).

## Prerequisites

Go 1.26 and `just`. Install the extra tools once:

```bash
just install-tools
```

That installs `air`, `golangci-lint`, and `goimports`. Postgres tests
and the browser suite need Docker.

## Go tests

```bash
just test
just test-cover
just check          # fmt, vet, lint, then test
```

Narrow runs:

```bash
go test ./pkg/crypto/... -v
go test ./internal/... -count=1
go test ./tests/integration/... -count=1
```

`just fmt` runs `go fmt` and goimports. `just lint` runs golangci-lint.
`just vet` runs `go vet ./...`. `just tidy` runs `go mod tidy`.

The Postgres job starts a database with testcontainers. Docker must be
running for `go test ./internal/database/ ./tests/integration/ ...` when
those tests open Postgres. SQLite is still what `just run` uses.

## Browser and protocol suite

```bash
cd e2e
npm install
npx playwright install chromium
npm test
```

`npm test` starts Postgres through `e2e/pgserve`, then starts
`oauth-server` and drives Chromium. The same command is the E2E check
on every pull request. The lockfile is `e2e/package-lock.json`.

Show the browser:

```bash
HEADED=1 npm test
```

`HEADLESS=false` is the same switch. The suite covers grants, CIBA,
refresh and signing-key rotation, webhooks, brute-force detection,
password rules, PKCE, closed registration, MFA enrollment, DPoP, client
ID metadata documents, JWT access tokens, out-of-band codes, the
combined-code helper, on-behalf-of delegation, login identifier, pairwise
subjects, organizations, encrypted ID tokens and AAuth discovery. Default access tokens
in these tests stay opaque unless a case sets
`security.access_token_format` to `jwt`.

Mocha is serial. The spec pattern is `test/**/*.test.js`, so naming one
file still runs the whole suite unless you pass Mocha `--no-config` and
`--require ./test/hooks.js` yourself.

## GitHub checks

A pull request to `main` runs:

| Check | What it runs |
| --- | --- |
| Build | `oauth-server`, `oauth-cli`, `oauth-mobile` |
| Test | `go test ./...` with the race detector and a coverage profile |
| Lint | golangci-lint |
| Vet | `go vet ./...` |
| Format | `gofmt -l` |
| Tidy | `go mod tidy` leaves `go.mod` and `go.sum` clean |
| Test Postgres | tests that need Postgres |
| E2E | `cd e2e && npm test` |

The Test check runs through `gotestsum` and writes `junit.xml` plus
`coverage.out`. Both files are uploaded with `codecov-action`. The
JUnit upload sets `report_type` to `test_results` and still runs when
tests fail. The README badge reads the `main` coverage report.
`disable_search` limits each upload to the named file.
`codecov.yml` leaves `e2e`, docs, migrations, hasher examples, and
test files out of that percentage. The project status compares the
branch with its base and allows a one point drop. The test run
instruments `internal` and `pkg` in every package, so an integration
test counts toward the handler, controller, and repository it calls.

## Related

[Deploy](DEPLOY.md) is the server you point a manual client at.
[API](API.md) is the route map the suites call.
