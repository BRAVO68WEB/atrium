# Contributing

Thanks for helping with Atrium. This page is how a change gets onto
`main`. Behavior and operator setup live in the [docs](docs/CONFIG.md).

## Setup

You need Go 1.26 and [`just`](https://github.com/casey/just). Postgres
tests and the browser suite need Docker.

```bash
just install-tools
just test
```

`just install-tools` installs `air`, `golangci-lint`, and `goimports`.

## Pull requests

`main` accepts changes through a pull request. Run `just check` before you
open one. That runs format, vet, lint, and the Go tests.

GitHub also runs these checks:

- Build
- Test
- Lint
- Vet
- Format
- Tidy
- Test Postgres
- E2E

Format is `gofmt`. Tidy is `go mod tidy` with a clean `go.mod` and
`go.sum`. Details of the test commands are in
[Testing](docs/TESTING.md).

Change the behavior you were asked to change, and match the packages
around it. A behavior change updates the matching page under `docs/`.

## Password hasher

`internal/hashalgo/algo.go` is the hasher compiled into the server. The
file exports `Hash()` and nothing else. Edit the function body, then
rebuild with `just run` or `just build`. The server exits when the file
on disk does not match the binary. Do not add a second way to pick an
algorithm from the config file. `security.hash_algo` names that same
file. Copy a starting point from `internal/hashalgo/examples/`. See
[Configuration](docs/CONFIG.md).

## Files to leave untracked

Do not commit `certs/`, `atrium.db`, or a `package-lock.json` at the
repository root. The end-to-end lockfile is `e2e/package-lock.json`.

## License

Contributions are under the MIT license in [LICENSE](LICENSE). Copyright
(c) 2026 Jyotirmoy Bandyopadhayaya.
