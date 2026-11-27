# Stack Control

A small self-hosted web application to start, stop and restart individual
[Docker Compose](https://docs.docker.com/compose/) stacks — with per-user
permissions. Users log in with an external OpenID Connect provider, see only
the stacks they are allowed to see, and can perform only the actions they are
allowed to perform.

A single self-contained Go binary with a server-rendered web UI. No database:
all state is the configuration file plus the Docker daemon.

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
> on the host. stackctl is a privilege boundary in front of it (strict
> allowlist of stacks, authorization on every request, CSRF and Origin checks,
> secrets never logged), but deploying it means giving its container that
> socket access. Only expose it behind TLS, keep the container isolated, and
> treat anyone with `group add`/exec rights on the host as effectively root.
>
> The same holds, and then some, for the `edit` permission: whoever may edit
> a stack's `docker-compose.yml` decides what containers with what mounts,
> resources and images the next `up` creates — an arbitrary compose file
> plus Docker socket access is effectively root configuration. Grant `edit`
> deliberately, to administrators. Every file read (including `.env`, which
> usually holds secrets) and every save is authorized, audited, backed up
> and validated before it is written.

## Features

- Login through your OIDC provider (Keycloak, Authentik, Authelia, …).
- Dashboard listing the stacks a user may see, with live status and one
  button per allowed action: `start`, `stop`, `restart` on a whole Compose
  project — plus, for stacks with a configured `dir`, `pull` (fetch newer
  images), `up` (recreate from the compose model), `update` (pull and then
  recreate, best effort) and a file editor for the stack's
  `docker-compose.yml` and `.env`.
- Server-side authorization on every request (the UI is a convenience, never
  the enforcement point); unknown actions and stacks never reach Docker.
- Structured JSON audit log of every action attempt, file read/save, login,
  logout, denial and config reload.
- Permission changes apply on `SIGHUP` without restarting; sessions stay
  valid.
- Deliberately **not** included: creating/deleting stacks, volumes or
  networks, compose override files (only the main model is editable), log
  viewing, shells, multi-host support, local user accounts, a database.

## Configuration

Everything is configured in one YAML file
(`$STACKCTL_CONFIG`, default `/etc/stackctl/config.yaml`, or `stackctl -config
<path>`). See [`config.example.yaml`](config.example.yaml) for a documented
example. `${ENV_NAME}` references are expanded from the environment on load;
unknown keys and invalid values fail startup.

### Permissions

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

Actions: `start`, `stop`, `restart` need no compose files; `pull`, `up`,
`update` and `edit` need the stack to declare `stacks[].dir` (see below) and
are hidden from users when it is missing.

On `SIGHUP` the file is re-read and validated; on success the new rules apply
to the next request without restarting or invalidating sessions (as long as
the session keys are unchanged). On error the previous configuration keeps
serving and the outcome is audited.

## Setup

### 1. Register the OIDC client

Create a confidential OIDC client for stackctl at your provider. Set the exact
redirect URI to

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

Copy `config.example.yaml` to `config.yaml` and put your secrets into `.env`
(see the comments in `compose.example.yaml`). Then pick one of the deployment
paths below — the server needs **no Go toolchain** in any of them.

**A. Pull the pre-built image (recommended).** Pre-built images are published
to `ghcr.io/pantek59/dockerstackcontrol` for every release tag:

```sh
cp compose.example.yaml compose.yaml    # pulls ghcr.io/pantek59/dockerstackcontrol:<tag>
docker compose up -d
```

The first GHCR package publish is **private** — either make the package
public in the repository's *Packages* settings, or authenticate the server
once (`echo <PAT> | docker login ghcr.io -u <user> --password-stdin`).
Versions are pinned on purpose: bump the tag in `compose.yaml` to update, and
rolling back is restoring the previous tag line.

**B. Build with Compose on the server** (the build runs inside a throwaway Go
container, no Go installation needed):

```sh
cp compose.example.yaml compose.yaml
# switch the service to: build: .  /  image: stackctl:dev  (commented in compose.example.yaml)
docker compose up -d --build
```

**C. Plain binary, no Compose for stackctl itself.** Download a release
binary from the GitHub release page (or build on any machine with Go: see
[DEVELOPMENT.md](DEVELOPMENT.md)), copy it to the target host, and run it from
a systemd unit; `stackctl -help` lists the flags (`-config <path>` selects the
configuration file).

Run it behind a reverse proxy that terminates TLS and forwards to port 8080.
Set `server.trusted_proxies` to your proxy's addresses so client addresses in
the audit log come from `X-Forwarded-For` instead of the proxy address.

To grant the container access to the socket, add the host `docker` group
(compose.example.yaml does this via `group_add`; find the GID with
`getent group docker | cut -d: -f3`). The container user is non-root
(`uid 1000`).

### Reloading and upgrading

To reload the configuration after editing it:

```sh
docker compose kill -s HUP stackctl
```

To upgrade, bump the image tag in `compose.yaml` and `docker compose up -d`
(rollback: restore the previous tag line). The running version shows up in
the startup audit line (`msg: listening`), so an instance always declares
exactly which build it is.

## Pull, up, update and editing stack files

Four actions exist besides `start`/`stop`/`restart`. All of them are bound
to `stacks[].dir` and are only offered/accepted when a stack declares one:

- **pull** — `docker compose -p <project> -f <file> pull`: fetches newer
  images for the services in the model. Running containers stay on the old
  image until an `up`.
- **up** — `docker compose -p <project> -f <file> up -d`: recreates
  containers from the model on disk, applying image, compose and `.env`
  changes. This is the counterpart of `pull` — and of every edit.
- **update** — `pull` and `up -d` in one click, **best effort**: the
  recreation runs even when the pull failed or timed out (the newest images
  that are already local are used, and compose recreates only what the model
  changed). A pull-only failure is reported as a warning in the UI and the
  audit log records `result: ok, reason: pull_failed`; a failed recreation
  is an error like any other action. Both steps are bounded by
  `docker.pull_timeout` each.
- **edit** — permission for the editor page (`GET /stacks/<stack>/edit`) and
  its file API: read and replace the main compose file and `.env`

  - saves are guarded by the sha256 of the version the editor last saw
    (concurrent changes fail with a conflict instead of silently winning),
  - the previous content is backed up to `<dir>/.stackctl-backups/`
    (timestamped, last 10 kept) before it is replaced,
  - the write itself is atomic (temp file + rename) and preserves the
    file's mode (new files get `0644`, `.env` `0600`),
  - a compose model is schema-checked with
    `docker compose -p <project> -f <file> config --quiet` *before* it is
    written; a broken file is rejected (HTTP 422) and never reaches `up`.
    This check does not need the daemon. Symlinks are never followed:
    a stack directory whose compose file or `.env` is a symlink is refused.

The editor shows both files as tabs and reports the save state inline;
errors on save are generic (compose validation output is only in the audit
log), and a stale hash asks the editor to reload.

### Deployment requirement for file-backed actions

The stackctl container must have each stack directory mounted **at the same
in-container path as on the host** and writable by the container user
(`uid 1000`):

```yaml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /srv:/srv     # if stacks live in /srv/stacks/<name>
```

Why "same path": relative bind mounts and build contexts inside a compose
file are resolved against the project directory — but *the daemon resolves
them on the host*. If `dir` were `/srv/stacks/media` on the host but mounted
as `/stacks/media` inside the container, an edited `volumes: - ./data:/data`
would be applied by `up` as the (nonexistent) host path
`/stacks/media/data`. Identical paths keep `up` byte-for-byte consistent
with manual host-side usage.

Without a configured `dir`, a stack keeps the label-based behavior: only
`start`, `stop` and `restart` (and no editor) are possible; `pull` and `up`
would fail with "no configuration file provided" because compose cannot
address a project without its model.

## Compose compatibility

stackctl invokes the compose CLI as
`<compose_binary> compose -p <project> ps|start|stop|restart` and — for
stacks with a configured directory —
`<compose_binary> compose -p <project> -f <dir>/<file> pull|up -d|config`.
Project addressing without a compose file was verified with **Compose
v5.8.0** (the bundle that ships with the `docker:cli` image); pull and up
resolve `.env` from the model's directory, matching host-side behavior. The
status parser accepts both the line-delimited JSON objects used by older
releases and the single JSON array form, so both Compose output styles work.

## HTTP interface

The UI is only a convenience; everything it does goes through the same
server-rendered pages and JSON API listed here, so you can script or audit
against them directly.

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `GET /` | session | Dashboard (HTML); redirects to `/login` without a session |
| `GET /login` | none | Starts the OIDC flow (state, nonce, PKCE) |
| `GET /auth/callback` | none | Validates and creates the session |
| `POST /logout` | session + CSRF | Clears the session, redirects to `/` |
| `GET /api/stacks` | session | JSON list of visible stacks with state and allowed actions |
| `POST /api/stacks/{name}/{action}` | session + CSRF | Performs `start`\|`stop`\|`restart`\|`pull`\|`up`\|`update`, returns the new status |
| `GET /api/stacks/{name}/files` | session + `edit` | Which files are editable (or none, without `dir`) |
| `GET /api/stacks/{name}/files/{kind}` | session + `edit` | One file's content + sha256 (`kind` = `compose` or `env`) |
| `PUT /api/stacks/{name}/files/{kind}` | session + CSRF + `edit` | Validates, backs up and atomically replaces the file |
| `GET /stacks/{name}/edit` | session | The file editor page (HTML) |
| `GET /healthz` | none | Health of the web service (no Docker call) |

Statuses: `running`, `stopped`, `partial`, `not_found` (no containers for the
project), `unknown` (Docker command failed). Stack names come only from the
configuration; unknown or invisible stacks return `404`, disallowed actions
`403` (nothing is executed), file-backed actions on stacks without a usable
compose model `400`, a concurrently running action `409`, docker failures
`502` and timeouts `504` — command output is never returned to clients. File
saves answer `422` when compose rejects the model, `409` on a stale hash, and
`413`/`400` for oversized or non-text content. An `update` whose pull step
failed answers `200` with a `warning` field on the status object.

## Audit log

Every action attempt, file operation, login/logout, denial and config reload
produces one structured JSON line on stdout:

```json
{"time":"...","level":"INFO","msg":"stack_action","user":"bob","groups":["family"],"stack":"media","project":"media","action":"restart","result":"ok","duration_ms":2310,"remote_ip":"203.0.113.5"}
{"time":"...","level":"INFO","msg":"stack_action","user":"alice","groups":["editors"],"stack":"media","project":"media","action":"update","result":"ok","duration_ms":61200,"remote_ip":"203.0.113.5","reason":"pull_failed"}
{"time":"...","level":"INFO","msg":"file_op","user":"alice","groups":["editors"],"stack":"media","file":"compose","op":"save","result":"ok","duration_ms":640,"remote_ip":"203.0.113.5"}
```

File saves can also log `result:"error"` with reasons like
`compose_validation`, `conflict` or `not_regular_file`; a `result:"ok"` with a
`reason` means a partially successful action (a best-effort `update` whose
image pull failed).

## Development

To build stackctl from source, hack on it or cut a release, see
[DEVELOPMENT.md](DEVELOPMENT.md).
