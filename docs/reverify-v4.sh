#!/usr/bin/env bash
# Re-run the Guardian v4 / M7 release gate.
#
#   bash docs/reverify-v4.sh                 # 524 node tests + 8 Playwright (Docker required for Playwright)
#   bash docs/reverify-v4.sh --fast          # typecheck + build + M7 suites only (59 tests)
#   bash docs/reverify-v4.sh --with-bench    # gate + realistic-bench 142 tests + benchmark typecheck
#
# The script only reads the repository and writes logs under /tmp. It never mutates source,
# never contacts a non-loopback target, and never prints credential material.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=1536}"
export GUARDIAN_ALLOW_LOCAL_LAB=1

FAST=0
WITH_BENCH=0
for arg in "$@"; do
  case "$arg" in
    --fast) FAST=1 ;;
    --with-bench) WITH_BENCH=1 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [[ ! -d node_modules ]]; then
  echo "node_modules missing: run 'npm ci' first (or symlink the repo node_modules)." >&2
  exit 1
fi

if [[ "$FAST" -eq 0 ]]; then
  if ! docker info >/dev/null 2>&1; then
    echo "The full gate requires the Docker daemon (worker + lab + Playwright)." >&2
    echo "Add this user to the 'docker' group, or run: bash docs/reverify-v4.sh --fast" >&2
    exit 2
  fi
  if ! docker image inspect guardian-worker:v4 >/dev/null 2>&1; then
    echo "worker image missing: run 'npm run worker:build' first." >&2
    exit 2
  fi
fi

TMP="$(mktemp -d /tmp/guardian-reverify.XXXXXX)"
TOTAL=0
NUM=0

run_node() {
  local label="$1"; shift
  NUM=$((NUM + 1))
  local log="$TMP/$(printf '%02d' "$NUM")-$(echo "$label" | tr ' /' '__').log"
  echo "== $label"
  if ! node --test "$@" >"$log" 2>&1; then
    echo "-- failing output (tail) --"
    tail -40 "$log"
    echo "FAILED: $label (full log: $log)" >&2
    exit 1
  fi
  grep -E '^ℹ (tests|pass|fail|cancelled|skipped) ' "$log" | sed 's/^/   /'
  local n
  n="$(awk '/^ℹ tests /{print $3}' "$log" | tail -1)"
  TOTAL=$((TOTAL + n))
}

echo "Guardian v4 gate — repo: $ROOT"
echo "logs: $TMP"
echo

echo "== typecheck"
npm run check >"$TMP/check.log" 2>&1 || { tail -20 "$TMP/check.log"; exit 1; }
echo "   0 errors"

echo "== build"
npm run build >"$TMP/build.log" 2>&1 || { tail -30 "$TMP/build.log"; exit 1; }
grep -E '✓ built' "$TMP/build.log" | tail -2 | sed 's/^/   /'

echo
if [[ "$FAST" -eq 0 ]]; then
  run_node "v2/v3 core boundaries" \
    tests/boundaries.test.ts tests/persona-login.test.ts tests/approval-judge.test.ts \
    tests/report-comparison.test.ts tests/provider-stream.test.ts tests/v2-upgrades.test.ts
  run_node "v3 + v3 protocol + v4 boundaries" \
    tests/v3-boundaries.test.ts tests/v3-protocol-browser.test.ts tests/v4-boundaries.test.ts
  run_node "v4 M1-M6 milestone suites" \
    tests/v4-m1-schema-verify-routing.test.ts tests/v4-m2-broker-browser-probes.test.ts \
    tests/v4-m3-worker-sast-templates.test.ts tests/v4-m4-surface-orchestration.test.ts \
    tests/v4-m5-lab-iast-ui.test.ts tests/v4-m6-benchmarks.test.ts
fi

run_node "v4 M7 discovery/held-out/heldout2/probes2/synthesis" \
  tests/v4-m7-discovery.test.ts tests/v4-m7-heldout.test.ts tests/v4-m7-heldout2.test.ts \
  tests/v4-m7-probes2.test.ts tests/v4-m7-specs.test.ts

if [[ "$FAST" -eq 0 ]]; then
  run_node "v4 tiered E2E matrix (single concurrency)" \
    --test-concurrency=1 tests/v4-e2e-tiers.test.ts
fi

echo
echo "node tests: $TOTAL"

if [[ "$FAST" -eq 0 ]]; then
  if docker info >/dev/null 2>&1; then
    echo "== Playwright UI E2E"
    if ! npx playwright test >"$TMP/playwright.log" 2>&1; then
      tail -40 "$TMP/playwright.log"
      echo "FAILED: Playwright (full log: $TMP/playwright.log)" >&2
      exit 1
    fi
    PW="$(grep -oE '[0-9]+ passed' "$TMP/playwright.log" | tail -1 | awk '{print $1}')"
    grep -E '[0-9]+ (passed|failed|flaky)' "$TMP/playwright.log" | tail -2 | sed 's/^/   /'
    TOTAL=$((TOTAL + PW))
    echo "gate total: $TOTAL (expected 532)"
  else
    echo "!! Docker socket not reachable: skipping 8 Playwright tests."
    echo "   gate total: $TOTAL node tests (532 requires Docker)."
  fi
else
  echo "fast mode: $TOTAL node tests (full gate is 532)."
fi

if [[ "$WITH_BENCH" -eq 1 ]]; then
  echo
  echo "== realistic-bench typecheck"
  node_modules/.bin/tsc -p benchmarks/realistic-bench/tsconfig.json --noEmit
  local_before=$TOTAL
  run_node "realistic-bench harness" --test-concurrency=1 benchmarks/realistic-bench/tests/
  echo "realistic-bench tests: $((TOTAL - local_before)) (separate from the 532 gate total)"
fi

echo
echo "done. logs: $TMP"
