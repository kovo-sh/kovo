#!/usr/bin/env bash
# End-to-end smoke test for the Option B Docker Compose sibling-container stack.
#
# Boots an isolated temporary Compose project (`kovo-smoke`), verifies:
#   1. Host-accessible `/health` returns `200 ok` and unauthenticated `/` returns `401` (fail-closed)
#   2. `kovo` runs as non-root UID 10001
#   3. `kovo` connects to `docker-proxy` (`DOCKER_HOST=tcp://docker-proxy:2375`)
#   4. `LinuxWorkerBackend` spawns a sibling `kovo-worker:v4` container with per-session
#      isolated `volume-subpath` mounts (no root `/scratch` exposure) and cleans up
#   5. Unconditional `docker compose -p kovo-smoke down -v` leaves zero containers/volumes
#
# Usage:
#   newgrp docker -c 'bash scripts/docker-compose-smoke.sh'
#   KOVO_PORT=18000 KOVO_VERSION=local KOVO_WORKER_IMAGE=kovo-worker:v4 bash scripts/docker-compose-smoke.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${KOVO_SMOKE_PROJECT:-kovo-smoke}"
PORT="${KOVO_PORT:-18000}"
KOVO_VERSION="${KOVO_VERSION:-local}"
KOVO_IMAGE="${KOVO_IMAGE:-kovo:${KOVO_VERSION}}"
WORKER_IMAGE="${KOVO_WORKER_IMAGE:-kovo-worker:v4}"
AUTO_PULL="${KOVO_WORKER_AUTO_PULL:-0}"
SCRATCH_VOLUME="${KOVO_WORKER_SCRATCH_VOLUME:-${PROJECT}_kovo_scratch}"

fail() {
  echo "DOCKER COMPOSE SMOKE FAIL: $*" >&2
  exit 1
}

if ! command -v docker >/dev/null 2>&1; then
  fail "docker CLI not found in PATH."
fi

if ! docker info >/dev/null 2>&1; then
  fail "Docker daemon is not reachable. Run under: newgrp docker -c 'bash scripts/docker-compose-smoke.sh'"
fi

if ! docker compose version >/dev/null 2>&1; then
  fail "'docker compose' plugin is not available."
fi

if ! docker image inspect "$KOVO_IMAGE" >/dev/null 2>&1; then
  fail "Image '$KOVO_IMAGE' not found locally. Build it with: docker build -t $KOVO_IMAGE --build-arg KOVO_WORKER_IMAGE=$WORKER_IMAGE ."
fi

if ! docker image inspect "$WORKER_IMAGE" >/dev/null 2>&1; then
  fail "Worker image '$WORKER_IMAGE' not found locally. Build it with: npm run worker:build"
fi

OVERRIDE_FILE="$(mktemp "${TMPDIR:-/tmp}/kovo-compose-smoke.XXXXXX.yml")"
cat > "$OVERRIDE_FILE" <<EOF
services:
  kovo:
    image: ${KOVO_IMAGE}
    environment:
      KOVO_WORKER_IMAGE: ${WORKER_IMAGE}
      KOVO_WORKER_AUTO_PULL: "${AUTO_PULL}"
EOF

COMPOSE_ARGS=(
  -p "$PROJECT"
  -f "$ROOT/docker-compose.yml"
  -f "$OVERRIDE_FILE"
)

cleanup() {
  docker compose "${COMPOSE_ARGS[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$OVERRIDE_FILE"
}
trap cleanup EXIT

export KOVO_PORT="$PORT"
export KOVO_VERSION
export KOVO_WORKER_SCRATCH_VOLUME="$SCRATCH_VOLUME"

echo "docker-compose-smoke: starting project '$PROJECT' on 127.0.0.1:${PORT} (kovo=${KOVO_IMAGE}, worker=${WORKER_IMAGE})..."
docker compose "${COMPOSE_ARGS[@]}" up -d --no-build --wait-timeout 30

echo "docker-compose-smoke: waiting for http://127.0.0.1:${PORT}/health -> 200 ok..."
HEALTH_OK=0
for _ in $(seq 1 30); do
  BODY="$(curl -sS -w '\n%{http_code}' --max-time 2 "http://127.0.0.1:${PORT}/health" 2>/dev/null || true)"
  STATUS="${BODY##*$'\n'}"
  TEXT="${BODY%$'\n'*}"
  if [[ "$STATUS" == "200" && "$TEXT" == "ok" ]]; then
    HEALTH_OK=1
    break
  fi
  sleep 1
done

if [[ "$HEALTH_OK" != "1" ]]; then
  docker compose "${COMPOSE_ARGS[@]}" logs --tail 60 >&2 || true
  fail "Timed out waiting for http://127.0.0.1:${PORT}/health to return '200 ok'."
fi

# Verify fail-closed bootstrap gate on root `/` from the host.
ROOT_STATUS="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/")"
if [[ "$ROOT_STATUS" != "401" ]]; then
  fail "Expected unauthenticated GET / to return 401, got HTTP $ROOT_STATUS."
fi

# Verify UID 10001 and proxy connectivity inside kovo.
UID_OUT="$(docker compose "${COMPOSE_ARGS[@]}" exec -T kovo id -u)"
if [[ "$UID_OUT" != "10001" ]]; then
  fail "Expected kovo UID 10001, got '$UID_OUT'."
fi

docker compose "${COMPOSE_ARGS[@]}" exec -T kovo docker version >/dev/null \
  || fail "kovo failed to query Docker daemon via DOCKER_HOST=tcp://docker-proxy:2375."

echo "docker-compose-smoke: spawning sibling worker (${WORKER_IMAGE}) via docker-proxy + volume-subpath..."
docker compose "${COMPOSE_ARGS[@]}" exec -T -e KOVO_WARM_WORKERS=0 kovo node -e '
  import("./src/server/worker-backend.ts").then(async m => {
    const { mkdirSync, readdirSync, rmSync, writeFileSync } = await import("node:fs");
    const { randomUUID } = await import("node:crypto");
    const cfg = m.resolveDoodScratchConfig();
    if (!cfg || cfg.mode !== "volume_subpath") {
      throw new Error("Expected volume_subpath DooD scratch config, got: " + JSON.stringify(cfg));
    }

    const srcRepo = "/tmp/smoke-repo-" + randomUUID();
    mkdirSync(srcRepo, { recursive: true, mode: 0o700 });
    writeFileSync(srcRepo + "/app.ts", "export const ok = true;\n", { mode: 0o600 });

    const backend = new m.LinuxWorkerBackend({ image: process.env.KOVO_WORKER_IMAGE });
    const session = await backend.openSession(
      "00000000-0000-4000-8000-000000000099",
      AbortSignal.timeout(25000),
      { reposDir: srcRepo },
    );
    try {
      const stagedPath = await session.stage("probe.txt", "compose-subpath-ok", AbortSignal.timeout(10000));
      const res = await session.exec(
        "cat " + stagedPath + " && printf \"|\" && cat /repos/app.ts",
        [],
        AbortSignal.timeout(10000),
      );
      if (res.exitCode !== 0 || !String(res.stdout).includes("compose-subpath-ok|export const ok = true;")) {
        throw new Error("Unexpected sibling worker exec output: " + JSON.stringify(res));
      }
      console.log("sibling worker exec OK:", JSON.stringify(res.stdout));
    } finally {
      await session.close();
      await backend.closeWarmPool?.();
      rmSync(srcRepo, { recursive: true, force: true });
    }

    const remaining = readdirSync("/scratch");
    if (remaining.length !== 0) {
      throw new Error("Expected /scratch to be clean after session close, found: " + remaining.join(", "));
    }
  }).catch(err => {
    console.error("SIBLING_WORKER_FAIL:", err);
    process.exit(1);
  });
'

echo "docker-compose-smoke: tearing down compose project '$PROJECT'..."
docker compose "${COMPOSE_ARGS[@]}" down -v --remove-orphans >/dev/null
rm -f "$OVERRIDE_FILE"
trap - EXIT

LEFTOVER_CONTAINERS="$(docker ps -a --filter "label=com.docker.compose.project=${PROJECT}" -q)"
LEFTOVER_VOLUMES="$(docker volume ls --filter "name=^${SCRATCH_VOLUME}$" -q)"
if [[ -n "$LEFTOVER_CONTAINERS" || -n "$LEFTOVER_VOLUMES" ]]; then
  fail "Leftover Compose resources detected (containers='$LEFTOVER_CONTAINERS', volumes='$LEFTOVER_VOLUMES')."
fi

echo "docker-compose-smoke: PASS (project=${PROJECT}, port=${PORT}, worker=${WORKER_IMAGE})"
