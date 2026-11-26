#!/usr/bin/env bash
# Fast hill-climb loop. Runs the cheap, independent checks in parallel:
#   - realistic dev smoke matrix (seed 42, 3 apps)
#   - agentic smoke matrix (Execution, 90 s / $0.25 per cell) when Docker is reachable
#   - typecheck
#
# Usage: scripts/hillclimb-loop.sh [--smoke|--full]
#   --smoke (default): one dev seed + agentic smoke; use between tweaks.
#   --full:            full dev matrix (3 seeds) + 600 s agentic matrix; use once per batch.
#
# Env:
#   HILLCLIMB_OUT              output directory (default /tmp/hillclimb-loop-<timestamp>)
#   KOVO_DATA_DIR          model data dir (default /home/omarchy/guardian-data)
#   HILLCLIMB_SKIP_AGENTIC=1   skip the agentic leg
#   HILLCLIMB_SKIP_REALISTIC=1 skip the realistic leg
#
# Agentic needs the docker group: run as
#   newgrp docker -c 'bash scripts/hillclimb-loop.sh'
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
MODE="${1:---smoke}"
if [[ "$MODE" != "--smoke" && "$MODE" != "--full" ]]; then
  echo "usage: $0 [--smoke|--full]" >&2
  exit 2
fi
OUT="${HILLCLIMB_OUT:-/tmp/hillclimb-loop-$(date +%Y%m%d-%H%M%S)}"
DATA_DIR="${KOVO_DATA_DIR:-/home/omarchy/guardian-data}"
mkdir -p "$OUT"

run() {
  local name="$1"; shift
  ( "$@" >"$OUT/$name.log" 2>&1; echo $? >"$OUT/$name.rc" ) &
}

if [[ "${HILLCLIMB_SKIP_REALISTIC:-0}" != "1" ]]; then
  if [[ "$MODE" == "--full" ]]; then
    run realistic env KOVO_ALLOW_LOCAL_LAB=1 node "$ROOT/scripts/benchmark-realistic-matrix.ts" \
      --apps acme-saas,shopflow,opsportal --seeds 42,1,2 --concurrency 9 --out-dir "$OUT/rb"
  else
    run realistic env KOVO_ALLOW_LOCAL_LAB=1 node "$ROOT/scripts/benchmark-realistic-matrix.ts" \
      --apps acme-saas,shopflow,opsportal --seeds 42 --concurrency 9 --out-dir "$OUT/rb"
  fi
fi

if [[ "${HILLCLIMB_SKIP_AGENTIC:-0}" != "1" ]]; then
  if ! docker ps >/dev/null 2>&1; then
    echo "agentic: skipped (docker socket unavailable; run under: newgrp docker -c 'bash scripts/hillclimb-loop.sh')" >"$OUT/agentic.log"
    echo 1 >"$OUT/agentic.rc"
  elif [[ "$MODE" == "--full" ]]; then
    run agentic env KOVO_ALLOW_LOCAL_LAB=1 node "$ROOT/scripts/benchmark-agentic-matrix.ts" \
      --apps acme-saas,shopflow,opsportal --seeds 1 --modes grey-box --budget-usd 2 \
      --max-duration-ms 600000 --concurrency 3 --data-dir "$DATA_DIR" --verifier docker --out-dir "$OUT/ag"
  else
    run agentic env KOVO_ALLOW_LOCAL_LAB=1 node "$ROOT/scripts/benchmark-agentic-matrix.ts" \
      --apps acme-saas,shopflow,opsportal --seeds 1 --modes grey-box --smoke \
      --concurrency 3 --data-dir "$DATA_DIR" --verifier docker --out-dir "$OUT/ag"
  fi
fi

run check npm run check --prefix "$ROOT"

wait

status=0
section() { printf '\n== %s ==\n' "$1"; }

section "realistic ($MODE)"
if [[ -f "$OUT/realistic.log" ]]; then
  grep -E '^\[matrix\]' "$OUT/realistic.log" || tail -2 "$OUT/realistic.log"
  [[ "$(cat "$OUT/realistic.rc" 2>/dev/null)" == "0" ]] || status=1
else
  echo "skipped"
fi

section "agentic ($MODE)"
if [[ -f "$OUT/agentic.log" ]]; then
  grep -E 'TOTAL|confirmed=|workerFailureRate|inert=|skipped' "$OUT/agentic.log" | tail -6
  [[ "$(cat "$OUT/agentic.rc" 2>/dev/null)" == "0" ]] || status=1
else
  echo "skipped"
fi

section "typecheck"
tail -3 "$OUT/check.log" 2>/dev/null || true
[[ "$(cat "$OUT/check.rc" 2>/dev/null)" == "0" ]] || status=1

printf '\nlogs: %s\n' "$OUT"
exit "$status"
