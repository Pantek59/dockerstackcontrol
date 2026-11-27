# Development

Maintainer and contributor notes: building from source, testing, repository
layout and how releases are produced. For deploying and operating stackctl,
see the [README](README.md).

## Requirements

- [Go](https://go.dev/) (the version pinned in `go.mod`; CI uses the same
  pin via `actions/setup-go` with `go-version-file`).
- No Docker daemon is needed to run the test suite: tests drive fake
  `docker` binaries and an in-process OIDC provider.

## Build and run from source

```sh
go build -trimpath -ldflags "-s -w" -o stackctl ./cmd/stackctl
./stackctl -config config.yaml
```

A bare `go build` reports the version as `dev`. Releases stamp the version
into the binary with `-ldflags "-X main.version=vX.Y.Z"`; the Docker build
passes it as the `VERSION` build argument. The stamp appears in the startup
audit line (`msg: listening`), so a running instance always declares exactly
which build it is.

## Tests and static analysis

The publish job only runs after this full gate has passed:

```sh
go vet ./...
staticcheck ./...        # CI pins honnef.co/go/tools/cmd/staticcheck@2026.2.2
go test -race ./...      # all packages
```

For manual testing without a real identity provider, a mock OIDC provider can
be stood up next to the server (e.g. `github.com/oauth2-proxy/mockoidc`):
point `oidc.issuer` at the mock, set `cookie_secure: false` and log in through
the UI. The server tests already run the full login flow against a mock.

## Repository layout

| Path | Purpose |
| --- | --- |
| `cmd/stackctl` | Entry point: config load, runner and server wiring, signal handling |
| `internal/config` | YAML loading, `${ENV}` expansion, validation, SIGHUP hot reload |
| `internal/auth` | OIDC login (PKCE), stateless session cookies, CSRF middleware |
| `internal/authz` | Rule evaluation (deny-by-default, union of matching rules) |
| `internal/docker` | Compose runner: fixed argument lists, status parsing, timeouts |
| `internal/server` | HTTP handlers, templates, per-stack locks |
| `internal/stackfiles` | Editor file access: guards, atomic writes, backups |
| `internal/audit` | Structured JSON audit events |
| `web/` | Embedded templates, stylesheet and scripts (no build step) |

## Releasing a new version

CI publishes the container image to GHCR automatically. Push a release tag
and the `publish` job builds the image with the version stamped into the
binary, then pushes `ghcr.io/pantek59/dockerstackcontrol` tagged with the
version (`1.2.3`) and the minor line (`1.2`), but **no `latest`** — versions
are pinned on purpose (see the note in `compose.example.yaml`).

```sh
git tag v1.2.3
git push origin v1.2.3
```

The same job attaches static **release binaries** to the GitHub release —
`stackctl-linux-amd64`, `stackctl-linux-arm64` and `stackctl-windows-amd64`
(each stamped with the version) plus a `checksums.txt` — so hosts without a
container registry pull can download them from the release page directly.

When behavior or configuration changes, keep `config.example.yaml`,
`compose.example.yaml` and the README examples in sync.
