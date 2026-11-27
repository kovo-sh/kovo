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
- `KOVO_PUBLIC_ORIGIN`: optional single HTTPS origin if terminating TLS behind a local reverse proxy.

## GHCR images & tags

Multi-arch (`linux/amd64`, `linux/arm64`) images are published by [`.github/workflows/docker-publish.yml`](../.github/workflows/docker-publish.yml) with SBOMs and build provenance attestations:

- `ghcr.io/kovo-sh/kovo` — web UI, scope broker, verification RPC server, and Playwright runtime
- `ghcr.io/kovo-sh/kovo-worker` — hardened `--network none` verification sandbox

Tag conventions:

| Trigger | Tag(s) |
| --- | --- |
| Release tag `vX.Y.Z` | `vX.Y.Z`, `X.Y`, `latest` (non-prerelease) |
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

## Releasing a versioned tag

Pushing a `v*` tag builds and publishes multi-arch `kovo` and `kovo-worker` images, updates `latest` (for non-prerelease tags), and attaches provenance attestations:

```sh
git tag v0.8.0
git push origin v0.8.0
```
