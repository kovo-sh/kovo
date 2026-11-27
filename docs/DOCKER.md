# Running Kovo with Docker Compose (Option B)

Kovo runs as two unprivileged containers without Docker-in-Docker or `--privileged`:

1. **`kovo`** (UID `10001`, Playwright + Node UI/orchestrator) talks only to `docker-proxy` over an internal bridge network (`docker_socket_net`).
2. **`docker-proxy`** ([`tecnativa/docker-socket-proxy`](https://github.com/tecnativa/docker-socket-proxy)) exposes only the minimal Docker API endpoints (`CONTAINERS=1`, `IMAGES=1`, `POST=1`, `INFO=1`, `PING=1`) so `kovo` can spawn isolated, `--network none`, `--read-only`, `--cap-drop ALL`, UID `10001` **`kovo-worker`** sibling containers.

## Quick start (2 commands)

```sh
docker compose pull
docker compose up
```

Then open the one-time `?bootstrap=<secret>` URL printed in the `kovo` logs (for example, `http://127.0.0.1:8000/?bootstrap=...`).

To build `kovo` from your local checkout instead of pulling from GHCR:

```sh
npm run worker:build
docker compose up --build
```

### Common environment overrides

- `KOVO_PORT` (default `8000`): host port published to `127.0.0.1:${KOVO_PORT}` (set before `docker compose up`, e.g. `KOVO_PORT=8080 docker compose up`).
- `KOVO_VERSION` (default `latest`): image tag for `ghcr.io/kovo-sh/kovo`.
- `KOVO_PUBLIC_ORIGIN`: optional static HTTPS origin override if terminating TLS behind a reverse proxy. When omitted, opening your HTTPS proxy URL (`X-Forwarded-Proto: https`) and signing in with the one-time setup token automatically pins that single origin in `/data/pinned-origin` (mode `0600`) across restarts.

## GHCR images & tags

Multi-arch (`linux/amd64`, `linux/arm64`) images are published by [`.github/workflows/docker-publish.yml`](../.github/workflows/docker-publish.yml) with SBOMs and build provenance attestations:

- `ghcr.io/kovo-sh/kovo` — web UI, scope broker, verification RPC server, and Playwright runtime
- `ghcr.io/kovo-sh/kovo-worker` — hardened `--network none` verification sandbox

Tag conventions:

| Trigger | Tag(s) |
| --- | --- |
| Approved release (`release.yml`, `vX.Y.Z`) | `vX.Y.Z`, `X.Y`, `latest` (non-prerelease, unless `publish_latest=false`) |
| Approved prerelease (`release.yml`, `vX.Y.Z-rc.1`) | `vX.Y.Z-rc.1` |
| Push to `main` | `edge`, `sha-<7-char>` |

## `docker-socket-proxy` security model

`kovo` never mounts `/var/run/docker.sock` directly. Instead:

- `docker-proxy` mounts `/var/run/docker.sock:ro` on an `internal: true` Docker network (`docker_socket_net`) with `EXEC=0`, `BUILD=0`, `VOLUMES=0`, `NETWORKS=0`, `SECRETS=0`, `SWARM=0`, and `SYSTEM=0`.
- `kovo` connects via `DOCKER_HOST=tcp://docker-proxy:2375` to inspect/pull `kovo-worker` and create/start/stop/remove ephemeral worker containers.
- Each sibling worker runs with `--network none`, `--read-only`, `--user 10001:10001`, `--cap-drop ALL`, and `--security-opt no-new-privileges`.

## Scratch storage: `kovo_scratch` vs `KOVO_HOST_SCRATCH_DIR`

Worker IPC (`/kovo-ipc`), staged repositories (`/repos`), and verification RPC sockets (`/kovo-rpc`) are mounted per session—never the scratch root itself.

1. **Named volume + `volume-subpath` (default, Docker Engine 26.0+):**
   - `KOVO_WORKER_SCRATCH_VOLUME=kovo_scratch` mounts `/scratch` in `kovo`, and each worker receives only `type=volume,source=kovo_scratch,volume-subpath=<sessionId>/...`.
   - Works out of the box on Linux, macOS Docker Desktop, and WSL2 with zero host path configuration.

2. **Host bind-mount (`KOVO_HOST_SCRATCH_DIR`, older Docker daemons or host inspection):**
   - In [`docker-compose.yml`](../docker-compose.yml), comment out `KOVO_WORKER_SCRATCH_VOLUME` and `kovo_scratch:/scratch`, uncomment `KOVO_HOST_SCRATCH_DIR`, and mount `${KOVO_HOST_SCRATCH_DIR}:/scratch`.
   - Set `KOVO_HOST_SCRATCH_DIR` to an absolute host path in `.env` (must be writable by UID `10001`). Each worker receives only `${KOVO_HOST_SCRATCH_DIR}/<sessionId>/...`.

## End-to-end Compose smoke test

Verify a local build against `docker-proxy` and `kovo-worker:v4` on an isolated Compose project:

```sh
docker build -t kovo:local --build-arg KOVO_WORKER_IMAGE=kovo-worker:v4 .
newgrp docker -c 'bash scripts/docker-compose-smoke.sh'
```

## Releasing a versioned tag (human-approved)

Versioned releases are triggered via [`.github/workflows/release.yml`](../.github/workflows/release.yml) and gated by the GitHub **`release`** Protected Environment (`RELEASE_APP_ID` + `RELEASE_APP_PRIVATE_KEY` environment secrets) plus a `v*` Tag Ruleset (`Restrict creations`, `Restrict updates`, `Restrict deletions`, bypassed only by the release GitHub App). Direct `git push origin v*` tag pushes are blocked and cannot publish versioned container images.

1. Kick off the release workflow from the GitHub Actions UI (**Release Kovo → Run workflow**) or via CLI:

   ```sh
   gh workflow run release.yml -f version=v0.8.0
   # Optional: target a specific commit on main or skip updating :latest
   gh workflow run release.yml -f version=v0.8.0-rc.1 -f ref=main -f publish_latest=false
   ```

2. The **`prepare`** job validates the semver string, confirms the commit is on `main`, checks that `Verify Kovo` passed on that exact SHA, ensures the tag does not already exist, and posts a release preview in the workflow summary.
3. The **`approve-and-tag`** job pauses on the `release` environment until a required reviewer clicks **Review deployments → Approve and deploy**, then mints a short-lived `contents: write` token from the release GitHub App and pushes the annotated `vX.Y.Z` tag.
4. Once tagged, **`publish-containers`** builds and publishes multi-arch `kovo` and `kovo-worker` images with SBOMs and provenance attestations, and **`publish-release`** creates the GitHub Release with the published manifest digests.
