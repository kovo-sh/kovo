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

fail=0
step() { printf '\n== %s\n' "$1"; }
run() { step "$1"; shift; if "$@"; then :; else echo "FAILED: $1" >&2; fail=1; fi; }

run "typecheck" npm run check

# v8 anti-contamination invariant (<1s): zero v8 benchmark literals in src/server/ or src/skills/.
run "v8 anti-contamination lint" node scripts/check-v8-contamination.ts

# v7 dispatch-funnel invariant (<=15 lines): the pure helpers must be wired into the engine and the
# synthetic fixture must prove (a) a dry/coordinator stop never strands dispatchable ready steps and
# (b) multi-trial fanout only spends surplus worker slots. Catches this coverage class in minutes.
step "dispatch funnel invariant"
if grep -q 'evaluateDispatchStop(' src/server/execution.ts \
   && grep -q 'planMultiTrialExpansion(' src/server/execution.ts \
   && node --test tests/v7-dispatch-funnel.test.ts >/dev/null 2>&1; then :; else
  echo "FAILED: dispatch funnel invariant (dry-stop stranding / multi-trial slot starvation)" >&2
  fail=1
fi

# Confirmation-consistency invariant (precision integrity): a confirmed finding may only persist
# while its own persisted evidence confirms. Pins the store gate + DB trigger + demotion path so an
# inconclusive result can never be persisted as a confirmed claim.
step "confirmation-consistency invariant"
if grep -q "invariant.confirmation_evidence" src/server/store.ts \
   && grep -q 'findings_confirmation_evidence_insert' src/server/store.ts \
   && grep -q 'enforceConfirmationEvidence(' src/server/store.ts \
   && node --test tests/v7-confirm-consistency.test.ts >/dev/null 2>&1; then :; else
  echo "FAILED: confirmation-consistency invariant (confirmed claim without confirming evidence)" >&2
  fail=1
fi

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
