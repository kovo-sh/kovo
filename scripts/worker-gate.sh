#!/usr/bin/env bash
# Mandatory pre-handoff gate for v5.1 hill-climb branches.
# Fast by default (<~30 s): typecheck + contract invariants + optional targeted slice.
#
# Usage:
#   scripts/worker-gate.sh [--app <app> --class <class> [--seed N] [--split dev|heldout]]
#   scripts/worker-gate.sh --full     # additionally runs the full reverify gate (slow)
#
# A branch must not be handed off unless this exits 0.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
FULL=0
SLICE_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full) FULL=1; shift;;
    --app|--class|--seed|--split) SLICE_ARGS+=("$1" "${2:?}"); shift 2;;
    -h|--help) sed -n '2,12p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

cd "$ROOT"
fail=0
step() { printf '\n== %s\n' "$1"; }
run() { step "$1"; shift; if "$@"; then :; else echo "FAILED: $1" >&2; fail=1; fi; }

run "typecheck" npm run check

# Fast contract invariants: planner/dedupe/orchestration behavior that engine-port broke.
run "contract invariants" node --test \
  tests/v4-m7-orch.test.ts \
  tests/v5-m1-wiring-correctness.test.ts \
  tests/v5-m2-state.test.ts

if (( ${#SLICE_ARGS[@]} > 0 )); then
  run "targeted slice" bash scripts/bench-slice.sh "${SLICE_ARGS[@]}"
else
  step "targeted slice"
  echo "skipped (pass --app <app> [--class <class>] to include it)"
fi

if (( FULL == 1 )); then
  step "full release gate"
  if newgrp docker -c "cd '$ROOT' && bash docs/reverify-v5.sh --full"; then :; else
    # newgrp may be unavailable; fall back only if docker is already accessible.
    if bash docs/reverify-v5.sh --full; then :; else echo "FAILED: full gate" >&2; fail=1; fi
  fi
fi

printf '\nworker-gate: %s\n' "$([[ $fail -eq 0 ]] && echo PASS || echo FAIL)"
exit "$fail"
