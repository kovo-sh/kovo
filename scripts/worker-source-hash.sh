#!/usr/bin/env bash
# Compute deterministic worker/ source hash and build kovo-worker Docker image with
# KOVO_WORKER_SOURCE_HASH and KOVO_WORKER_SDK_VERSION build args (R3-02 Step 4).
#
# Usage:
#   bash scripts/worker-source-hash.sh --print-hash
#   bash scripts/worker-source-hash.sh [--tag kovo-worker:v4 --tag kovo-worker:local]
#                                      [--sdk-version kovo_verify/v8] [-- <extra docker args>]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PRINT_HASH=0
SDK_VERSION="${KOVO_WORKER_SDK_VERSION:-kovo_verify/v8}"
TAGS=()
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --print-hash) PRINT_HASH=1; shift ;;
    --sdk-version) SDK_VERSION="${2:?--sdk-version requires a value}"; shift 2 ;;
    -t|--tag) TAGS+=("${2:?--tag requires a value}"); shift 2 ;;
    --) shift; EXTRA_ARGS+=("$@"); break ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) EXTRA_ARGS+=("$1"); shift ;;
  esac
done

compute_worker_source_hash() {
  local hash=""
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    hash="$(git rev-parse --verify HEAD:worker 2>/dev/null || true)"
  fi

  if [[ ! "$hash" =~ ^[0-9a-f]{40}$ ]]; then
    if [[ ! -d "$ROOT/worker" ]]; then
      echo "FAIL: worker/ directory not found under $ROOT" >&2
      return 1
    fi
    hash="$(node --input-type=module - "$ROOT/worker" <<'EOF'
import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

const workerRoot = process.argv[2]
const SKIP = new Set(['node_modules', '.git', 'dist', 'out'])
const files = []
function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (SKIP.has(entry.name)) continue
    const full = join(dir, entry.name)
    if (entry.isDirectory()) walk(full)
    else if (entry.isFile()) files.push(full)
  }
}
walk(workerRoot)
const h = createHash('sha1')
h.update('kovo-worker-source:v1\0')
for (const f of files) {
  const rel = relative(workerRoot, f).split(sep).join('/')
  h.update(rel)
  h.update('\0')
  h.update(readFileSync(f))
  h.update('\0')
}
process.stdout.write(h.digest('hex'))
EOF
)"
  fi

  if [[ ! "$hash" =~ ^[0-9a-f]{40}$ || "$hash" == "unknown" ]]; then
    echo "FAIL: unable to compute deterministic 40-hex hash for worker/ (got '$hash')" >&2
    return 1
  fi
  printf '%s\n' "$hash"
}

WORKER_SOURCE_HASH="$(compute_worker_source_hash)"

if (( PRINT_HASH == 1 )); then
  printf '%s\n' "$WORKER_SOURCE_HASH"
  exit 0
fi

if (( ${#TAGS[@]} == 0 )); then
  TAGS=("kovo-worker:v4" "kovo-worker:local")
fi

DOCKER_CMD=(
  docker build
  -f worker/Dockerfile
  --build-arg "KOVO_WORKER_SOURCE_HASH=${WORKER_SOURCE_HASH}"
  --build-arg "KOVO_WORKER_SDK_VERSION=${SDK_VERSION}"
)
for tag in "${TAGS[@]}"; do
  DOCKER_CMD+=(-t "$tag")
done
if (( ${#EXTRA_ARGS[@]} > 0 )); then
  DOCKER_CMD+=("${EXTRA_ARGS[@]}")
fi
DOCKER_CMD+=(worker)

echo "[worker:build] KOVO_WORKER_SOURCE_HASH=${WORKER_SOURCE_HASH} KOVO_WORKER_SDK_VERSION=${SDK_VERSION}"
exec "${DOCKER_CMD[@]}"
