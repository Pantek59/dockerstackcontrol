# Stack Control

A small self-hosted web application to start, stop and restart individual
[Docker Compose](https://docs.docker.com/compose/) stacks — with per-user
permissions. Users log in with an external OpenID Connect provider, see only
the stacks they are allowed to see, and can perform only the actions they are
allowed to perform.

Written in Go as a single static binary. No database: all state is the
configuration file plus the Docker daemon. No framework, no build step for
the GUI: server-rendered templates with one small embedded script and
stylesheet.

```
┌────────────┐   HTTPS    ┌───────────────┐  docker compose   ┌───────────────┐
│   Browser  │──────────▶│ reverse proxy  │  ◀────────────── │ stackctl :8080 │
└────────────┘            │ (TLS, OIDC not │                   │  ▲ docker.sock │
      │ OIDC login flow   │  handled here) │                   └───────┬────────┘
      ▼                   └───────────────┘                            │
┌─────────────────┐                                            ┌──────────────┐
│ OIDC provider    │                                          │ Docker daemon │
└─────────────────┘                                            └──────────────┘
```

> ⚠️ **Security warning.** Access to the Docker socket is equivalent to root
> on the host. stackctl is a privilege boundary in front of it and is written
> accordingly (strict allowlist of stacks, arguments validated before any
> command, no shell, CSRF and Origin checks, authorization on every request,
> secrets never logged), but deploying it means giving its container that
> socket access. Only expose it behind TLS, keep the container isolated, and
> treat anyone with `group add`/exec rights on the host as effectively root.

## Features

- OIDC login: authorization code flow with PKCE, `state`/`nonce` checks, ID
  token signature/issuer/audience/expiry validation, optional required group.
- Stateless encrypted session cookie (`HttpOnly`, `Secure`, `SameSite=Lax`,
  bounded lifetime); no server-side session store.
- Dashboard listing visible stacks with live status and per-action buttons;
  actions: `start`, `stop`, `restart` on a whole Compose project.
- Server-side authorization on every request (the UI is a convenience, never
  the enforcement point), CSRF token + `Origin` check on every state change.
- Structured JSON audit log (`log/slog`) of every action attempt, login,
  logout, denial and config reload.
- Hot reload of permissions via `SIGHUP`; sessions stay valid.
- Deliberately **not** included: creating/editing/deleting stacks, volumes or
  networks, log viewing, shells, multi-host support, local user accounts, a
  database.

## Configuration

Everything is configured in one YAML file
(`$STACKCTL_CONFIG`, default `/etc/stackctl/config.yaml`, or `stackctl -config
<path>`). See [`config.example.yaml`](config.example.yaml) for a documented
example. `${ENV_NAME}` references are expanded from the environment on load;
unknown keys and invalid values fail startup.

Authorization is deny-by-default and defined by rules:

```yaml
rules:
  - subjects:
      users: ["alice"]
      groups: ["admins"]
    stacks: ["*"]                        # "*" = all configured stacks
    actions: ["start", "stop", "restart"]
  - subjects:
      users: ["bob"]
    stacks: ["media"]
    actions: ["restart"]
```

A user's effective permissions are the union of all rules whose subjects
match (username equals an entry in `users`, or any of the user's groups equals
an entry in `groups`). A stack is visible if the user has at least one action
on it; only the allowed buttons are rendered. With no rules a user can log in
and sees an empty list.

On `SIGHUP` the file is re-read and validated; on success the new rules apply
to the next request without restarting or invalidating sessions (as long as
the session keys are unchanged). On error the previous configuration keeps
serving and the outcome is audited.

## Setup

### 1. Register the OIDC client

Create a confidential OIDC client for stackctl at your provider (Keycloak,
Authentik, Authelia, …). Set the exact redirect URI to

```
<external_url>/auth/callback
```

i.e. for `external_url: "https://stacks.example.com"` the redirect URI is
`https://stacks.example.com/auth/callback`. Allow the `openid`, `profile`,
`email` and `groups` scopes (or configure `oidc.scopes` accordingly). Take
note of the client ID and secret.

### 2. Generate the session keys

```sh
openssl rand -base64 32   # STACKCTL_HASH_KEY (32 or 64 bytes)
openssl rand -base64 32   # STACKCTL_BLOCK_KEY (exactly 32 bytes)
```

### 3. Find your Compose project names

stackctl addresses whole Compose projects by their *project name*, never by a
path. List them on the Docker host:

```sh
docker compose ls
```

Only stacks that contain the Compose project label respond — i.e. they were
created with `docker compose up` (or `docker compose -p <name> up`), not by
starting single `docker run` containers. Starting/stopping/restarting a
project does **not** require the compose file; it operates on the existing
containers of that project.

### 4. Configure and deploy

Copy `config.example.yaml` to `config.yaml`, fill in your values and deploy
with the example Compose file:

```sh
cp compose.example.yaml compose.yaml
# put the secrets into .env (see comments in compose.example.yaml)
docker compose up -d --build
```

Run it behind a reverse proxy that terminates TLS and forwards to port 8080.
Set `server.trusted_proxies` to your proxy's addresses so client addresses in
the audit log come from `X-Forwarded-For` instead of the proxy address.

To grant the container access to the socket, add the host `docker` group
(compose.example.yaml does this via `group_add`; find the GID with
`getent group docker | cut -d: -f3`). The container user is non-root
(`uid 1000`).

To reload the configuration after editing it:

```sh
docker compose kill -s HUP stackctl
```

### Compose version

stackctl invokes the compose CLI as
`<compose_binary> compose -p <project> ps|start|stop|restart`. This project
addressing without a compose file was verified with **Compose v5.8.0**
(bundle that ships with the `docker:cli` image). Status output parsers accept
both the line-delimited JSON objects used by older releases and the single
JSON array form, so both Compose output styles work.

## HTTP interface

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `GET /` | session | Dashboard (HTML); redirects to `/login` without a session |
| `GET /login` | none | Starts the OIDC flow (state, nonce, PKCE) |
| `GET /auth/callback` | none | Validates and creates the session |
| `POST /logout` | session + CSRF | Clears the session, redirects to `/` |
| `GET /api/stacks` | session | JSON list of visible stacks with state and allowed actions |
| `POST /api/stacks/{name}/{action}` | session + CSRF | Performs an action, returns the new status |
| `GET /healthz` | none | Health of the web service (no Docker call) |

Statuses: `running`, `stopped`, `partial`, `not_found` (no containers for the
project), `unknown` (Docker command failed). Stack names come only from the
configuration; unknown or invisible stacks return `404`, disallowed actions
`403` (nothing is executed), a concurrently running action `409`, docker
failures `502` and timeouts `504` — command output is never returned to
clients.

Audit log example (stdout, JSON):

```json
{"time":"...","level":"INFO","msg":"stack_action","user":"bob","groups":["family"],"stack":"media","project":"media","action":"restart","result":"ok","duration_ms":2310,"remote_ip":"203.0.113.5"}
```

## Development

```sh
go test -race ./...      # all packages
go vet ./...
staticcheck ./...
```

For manual testing without a real identity provider, a mock OIDC provider can
be stood up next to it (e.g. `github.com/oauth2-proxy/mockoidc`): point
`oidc.issuer` at the mock, set `cookie_secure: false` and log in through the
UI. The tests already run this flow against a mock provider.
