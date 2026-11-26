#!/usr/bin/env bash
# Mandatory pre-handoff behavioral merge gate (`cq-3-merge-gate`).
# Fast (<60s): typecheck + v8 contamination lint + contract-change trailer lint +
# wiring invariants + quarantine/orphan check + all non-quarantined fast unit suites
# in parallel + optional targeted slice.
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

# Guard the coordinator's primary checkout on main: a subagent writing here instead of its worktree
# corrupts production runs (seen: a TS parameter property broke `Execution --no-llm`).
# Primary checkouts have a `.git` directory; linked worktrees have a `.git` file.
if [[ -d "$ROOT/.git" && "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)" == "main" ]]; then
  if [[ "${WORKER_GATE_ALLOW_DIRTY_MAIN:-0}" != "1" && -n "$(git status --porcelain -uno 2>/dev/null | head -1)" ]]; then
    echo "FAIL: main checkout has uncommitted tracked changes; subagents must work in their worktrees (coordinator override: WORKER_GATE_ALLOW_DIRTY_MAIN=1)." >&2
    git status --porcelain -uno | head -5 >&2
    exit 1
  fi
fi

gate_t0="$(date +%s)"
fail=0
step() { printf '\n== %s\n' "$1"; }
run() { step "$1"; shift; if "$@"; then :; else echo "FAILED: $1" >&2; fail=1; fi; }

# 1. Fast static lints & structural wiring invariants (<2s total).
run "v8 anti-contamination lint" node scripts/check-v8-contamination.ts
run "fixture-contamination ratchet lint" node scripts/check-fixture-contamination.ts
if [[ -n "${KOVO_CONTRACT_BASE:-}" ]]; then
  run "contract-change trailer lint" node scripts/check-contract-change.ts --base "$KOVO_CONTRACT_BASE"
else
  run "contract-change trailer lint" node scripts/check-contract-change.ts
fi

step "dispatch funnel wiring invariant"
if grep -q 'evaluateDispatchStop(' src/server/execution.ts \
   && grep -q 'planMultiTrialExpansion(' src/server/execution.ts; then
  echo "PASS: dispatch funnel wiring present in src/server/execution.ts"
else
  echo "FAILED: dispatch funnel wiring invariant missing from src/server/execution.ts" >&2
  fail=1
fi

step "confirmation-consistency wiring invariant"
if grep -q "invariant.confirmation_evidence" src/server/store.ts \
   && grep -q 'findings_confirmation_evidence_insert' src/server/store.ts \
   && grep -q 'enforceConfirmationEvidence(' src/server/store.ts; then
  echo "PASS: confirmation-consistency wiring present in src/server/store.ts"
else
  echo "FAILED: confirmation-consistency wiring invariant missing from src/server/store.ts" >&2
  fail=1
fi

# 2. Run typecheck (`npm run check`), unwired-export ratchet (`check-unwired.ts`), and all
#    non-quarantined fast behavioral suites in parallel (stays <60s; never runs Playwright/Docker/dogfood).
GATE_LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kovo-worker-gate-XXXXXX")"
trap 'rm -rf "$GATE_LOG_DIR"' EXIT

npm run check >"$GATE_LOG_DIR/tsc.log" 2>&1 &
tsc_pid=$!

node scripts/check-unwired.ts >"$GATE_LOG_DIR/unwired.log" 2>&1 &
unwired_pid=$!

bash scripts/run-fast-tests.sh --suites-only --quarantine tests/QUARANTINE.json >"$GATE_LOG_DIR/fast.log" 2>&1 &
fast_pid=$!

wait "$tsc_pid"
tsc_rc=$?
wait "$unwired_pid"
unwired_rc=$?
wait "$fast_pid"
fast_rc=$?

step "typecheck"
cat "$GATE_LOG_DIR/tsc.log"
if (( tsc_rc != 0 )); then
  echo "FAILED: typecheck (npm run check)" >&2
  fail=1
else
  echo "PASS: typecheck"
fi

step "unwired-export / cycle / doc-citation ratchet"
cat "$GATE_LOG_DIR/unwired.log"
if (( unwired_rc != 0 )); then
  echo "FAILED: unwired-export ratchet (node scripts/check-unwired.ts)" >&2
  fail=1
fi

step "fast behavioral suites + quarantine/orphan gate"
cat "$GATE_LOG_DIR/fast.log"
if (( fast_rc != 0 )); then
  echo "FAILED: fast behavioral suites / quarantine / orphan check" >&2
  fail=1
fi

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

gate_elapsed=$(( $(date +%s) - gate_t0 ))
printf '\nworker-gate: %s (%ss)\n' "$([[ $fail -eq 0 ]] && echo PASS || echo FAIL)" "$gate_elapsed"
exit "$fail"
