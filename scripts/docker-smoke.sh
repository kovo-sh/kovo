#!/usr/bin/env bash
# Fast (<5s) preflight smoke gate for the hardened Kovo worker Docker image.
# Verifies UID 10001 readability under --read-only --network none --cap-drop ALL
# --security-opt no-new-privileges and boots bridge.ts --session for an NDJSON handshake.
#
# Usage:
#   bash scripts/docker-smoke.sh
#   KOVO_WORKER_IMAGE=kovo-worker:local bash scripts/docker-smoke.sh
#   newgrp docker -c 'bash scripts/docker-smoke.sh'
set -euo pipefail

IMAGE="${KOVO_WORKER_IMAGE:-kovo-worker:v4}"

fail() {
  echo "DOCKER SMOKE FAIL: $*" >&2
  exit 1
}

if ! command -v docker >/dev/null 2>&1; then
  fail "docker CLI not found in PATH."
fi

if ! docker info >/dev/null 2>&1; then
  fail "Docker daemon is not reachable for the current shell. Run under: newgrp docker -c 'bash scripts/docker-smoke.sh'"
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  fail "Docker image '$IMAGE' not found locally. Build it with: npm run worker:build"
fi

COMMON_FLAGS=(
  --rm
  --user 10001:10001
  --read-only
  --network none
  --cap-drop ALL
  --security-opt no-new-privileges
)

echo "docker-smoke: checking UID 10001 readability in $IMAGE..."
if ! timeout 10 docker run "${COMMON_FLAGS[@]}" --entrypoint sh "$IMAGE" -c \
  'test -r /opt/kovo-worker/package.json && test -r /opt/kovo-worker/bridge.ts && test -r /opt/kovo-rules && test -x /opt/kovo-rules'; then
  fail "Image '$IMAGE' failed UID 10001 readability check for /opt/kovo-worker/{package.json,bridge.ts} or /opt/kovo-rules. Rebuild with: npm run worker:build"
fi

echo "docker-smoke: booting bridge.ts --session NDJSON handshake in $IMAGE..."
PING_ID="smoke-ping-$$"
# --tmpfs /tmp is required under --read-only so /evidence -> /tmp/kovo-evidence can be created by UID 10001.
if ! RESP="$(printf '{"id":"%s","op":"shutdown"}\n' "$PING_ID" | \
  timeout 10 docker run -i "${COMMON_FLAGS[@]}" \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
    --entrypoint node \
    "$IMAGE" \
    /opt/kovo-worker/bridge.ts --session 2>&1)"; then
  fail "bridge.ts --session exited non-zero in '$IMAGE'. Output: $RESP"
fi

if ! printf '%s\n' "$RESP" | node -e '
  const fs = require("node:fs");
  const expectedId = process.argv[1];
  const lines = fs.readFileSync(0, "utf8").split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const parsed = [];
  for (const line of lines) {
    try { parsed.push(JSON.parse(line)); } catch {}
  }
  const match = parsed.find(obj => obj && obj.id === expectedId && obj.ok === true);
  if (!match) {
    console.error("Expected NDJSON frame with id=" + expectedId + " and ok=true, got:", lines.join(" | "));
    process.exit(1);
  }
' "$PING_ID"; then
  fail "Invalid NDJSON handshake response from '$IMAGE' bridge.ts --session."
fi

echo "docker-smoke: PASS ($IMAGE)"
