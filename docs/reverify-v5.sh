#!/usr/bin/env bash
# Re-run the Kovo Hunter v5 release gate on the current tree.
#
#   bash docs/reverify-v5.sh --full    # release gate: build + all suites + Playwright + orphan hygiene
#   bash docs/reverify-v5.sh --fast    # no Docker: typecheck, build, Docker-free unit suites only
#
# --full fails closed with exit 2 when the Docker daemon, worker image, or Playwright
# browser is unavailable; it never prints a partial "passed". Every suite is attempted
# (a failure does not stop the run) and a gate table plus a non-zero exit reports the
# truth. Exit 0 is reserved for: every suite green, 0 skips, 0 Docker orphans.
#
# Orphan hygiene fails the gate when a `kovo-*` container is stuck in `created`
# for longer than 2 minutes (create succeeded, start never did) or when a
# `kovo-*` / `dev.kovo.*` network was left behind. Active `Up` containers
# from a concurrent stream are not gate failures. Set KOVO_GATE_SKIP_NETWORKS=1
# only when another stream is intentionally running a lab network.
#
# Run under `newgrp docker -c 'bash docs/reverify-v5.sh --full'` when docker group
# membership is not the login shell's default. Logs go to /tmp; source is not mutated.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=2048}"
export KOVO_ALLOW_LOCAL_LAB=1

MODE=""
for arg in "$@"; do
  case "$arg" in
    --fast) MODE=fast ;;
    --full) MODE=full ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg (use --fast or --full)" >&2; exit 2 ;;
  esac
done
if [[ -z "$MODE" ]]; then
  echo "choose a mode: bash docs/reverify-v5.sh --fast | --full" >&2
  exit 2
fi

if [[ ! -d node_modules ]]; then
  echo "node_modules missing: run 'npm ci' (or symlink the repo node_modules) first." >&2
  exit 2
fi
if [[ "$MODE" == full && ! -d worker/node_modules ]]; then
  echo "worker/node_modules missing: run 'npm run worker:install' (in-process AST tests need @swc/core)." >&2
  exit 2
fi

if [[ "$MODE" == full ]]; then
  if ! docker info >/dev/null 2>&1; then
    echo "FULL GATE UNAVAILABLE (exit 2): Docker daemon is not reachable." >&2
    echo "Run under: newgrp docker -c 'bash docs/reverify-v5.sh --full'" >&2
    echo "Use --fast for the Docker-free subset; it does not certify the release gate." >&2
    exit 2
  fi
  if ! docker image inspect kovo-worker:v4 >/dev/null 2>&1; then
    echo "FULL GATE UNAVAILABLE (exit 2): kovo-worker:v4 image not found." >&2
    echo "Build it with: npm run worker:build" >&2
    exit 2
  fi
fi

TMP="$(mktemp -d /tmp/kovo-reverify-v5.XXXXXX)"
declare -a ROWS=()
TOTAL=0 PASS=0 FAIL=0 SKIP=0 SUITES=0 GATE_FAIL=0

record_row() { # label tests pass fail skipped status
  ROWS+=("$(printf '%-38s %7s %7s %7s %8s  %s' "$1" "$2" "$3" "$4" "$5" "$6")")
}

run_node() { # label timeout_ms file...
  local label="$1" timeout="$2"; shift 2
  SUITES=$((SUITES + 1))
  local safe="${label//[^a-zA-Z0-9._-]/_}"
  local log="$TMP/$(printf '%02d' "$SUITES")-$safe.log"
  echo "== $label"
  timeout "$timeout" node --test --test-concurrency=1 "$@" >"$log" 2>&1
  local rc=$?
  local t p f s
  t="$(awk '/^ℹ tests /{print $3}' "$log" | tail -1)"
  p="$(awk '/^ℹ pass /{print $3}' "$log" | tail -1)"
  f="$(awk '/^ℹ fail /{print $3}' "$log" | tail -1)"
  s="$(awk '/^ℹ skipped /{print $3}' "$log" | tail -1)"
  t="${t:-0}"; p="${p:-0}"; f="${f:-0}"; s="${s:-0}"
  TOTAL=$((TOTAL + t)); PASS=$((PASS + p)); FAIL=$((FAIL + f)); SKIP=$((SKIP + s))
  if [[ "$rc" -ne 0 || "$f" -ne 0 ]]; then
    GATE_FAIL=1
    echo "-- FAILED: $label (rc=$rc, log: $log)" >&2
    grep -E '^✖|AssertionError|Error:' "$log" | head -12
    record_row "$label" "$t" "$p" "$f" "$s" "FAIL"
  elif [[ "$s" -ne 0 && "$MODE" == full ]]; then
    GATE_FAIL=1
    echo "-- FAILED: $label reported $s skip(s); the release gate requires 0 skips (log: $log)" >&2
    grep -E '^﹣|# SKIP|skipped' "$log" | head -8
    record_row "$label" "$t" "$p" "$f" "$s" "FAIL(skip)"
  elif [[ "$s" -ne 0 ]]; then
    record_row "$label" "$t" "$p" "$f" "$s" "pass(skip)"
  else
    record_row "$label" "$t" "$p" "$f" "$s" "pass"
  fi
}

run_cmd() { # label timeout_ms command...
  local label="$1" timeout="$2"; shift 2
  SUITES=$((SUITES + 1))
  local safe="${label//[^a-zA-Z0-9._-]/_}"
  local log="$TMP/$(printf '%02d' "$SUITES")-$safe.log"
  echo "== $label"
  timeout "$timeout" "$@" >"$log" 2>&1
  local rc=$?
  if [[ "$rc" -ne 0 ]]; then
    GATE_FAIL=1
    echo "-- FAILED: $label (rc=$rc, log: $log)" >&2
    tail -20 "$log"
    record_row "$label" "-" "-" "-" "-" "FAIL"
  else
    record_row "$label" "-" "-" "-" "-" "pass"
  fi
}

orphan_check() {
  SUITES=$((SUITES + 1))
  if ! docker info >/dev/null 2>&1; then
    record_row "orphan hygiene" "-" "-" "-" "-" "SKIP(no docker)"
    echo "!! orphan hygiene skipped: Docker unreachable" >&2
    GATE_FAIL=1
    return
  fi
  local now created stale_rows networks
  now="$(date +%s)"
  stale_rows=""
  while IFS=$'\t' read -r id created_at name status; do
    [[ "$id" ]] || continue
    case "$status" in
      Created*|Exited*|Dead*) ;;
      *) continue ;;
    esac
    created="$(date -d "$created_at" +%s 2>/dev/null || echo "$now")"
    if (( now - created > 120 )); then
      stale_rows+=$'\n'"  $name  ($id, $status, $(( (now - created) / 60 ))m old)"
    fi
  done < <(docker ps -a --filter name=^kovo- --format '{{.ID}}\t{{.CreatedAt}}\t{{.Names}}\t{{.Status}}' 2>/dev/null)

  # A network still attached to a running container belongs to an active stream, not a leak.
  local leaked_networks="" active_networks=""
  while IFS= read -r net; do
    [[ -z "$net" ]] && continue
    local attached
    attached="$(docker network inspect "$net" --format '{{len .Containers}}' 2>/dev/null || echo 0)"
    if [[ "${attached:-0}" -gt 0 ]]; then active_networks+=" $net"
    else leaked_networks+=$'\n'"  $net"
    fi
  done < <(docker network ls --filter name=^kovo- --format '{{.Name}}' 2>/dev/null; docker network ls --filter label=dev.kovo --format '{{.Name}}' 2>/dev/null | sed '/^$/d' | sort -u)
  networks="$leaked_networks"
  if [[ -n "$stale_rows" ]]; then
    GATE_FAIL=1
    echo "-- ORPHAN FAILURE: kovo containers abandoned in created state >2m:" >&2
    printf '%s\n' "$stale_rows" >&2
  fi
  if [[ -n "$networks" && "${KOVO_GATE_SKIP_NETWORKS:-0}" != "1" ]]; then
    GATE_FAIL=1
    echo "-- ORPHAN FAILURE: detached kovo networks left behind:" >&2
    printf '%s\n' "$networks" >&2
  elif [[ -n "$networks" ]]; then
    echo "!! detached networks present but KOVO_GATE_SKIP_NETWORKS=1: $(printf '%s ' $networks)"
  fi
  if [[ -n "$active_networks" ]]; then
    echo "   active kovo networks (attached to running containers, not failures):$active_networks"
  fi
  local up
  up="$(docker ps --filter name=^kovo- --format '{{.Names}}' 2>/dev/null | wc -l | tr -d ' ')"
  if [[ -z "$stale_rows" && ( -z "$networks" || "${KOVO_GATE_SKIP_NETWORKS:-0}" == "1" ) ]]; then
    record_row "orphan hygiene" "-" "-" "-" "-" "pass"
  else
    record_row "orphan hygiene" "-" "-" "-" "-" "FAIL"
  fi
  echo "   active kovo containers (not a gate failure): $up"
}

echo "Kovo Hunter v5 gate ($MODE) — repo: $ROOT"
echo "logs: $TMP"
echo

run_cmd "typecheck" 600 npm run check
run_cmd "build" 600 npm run build

if [[ "$MODE" == fast ]]; then
  # Docker-free subset: unit suites that use stubs only. Docker-gated cases may skip,
  # and the result is explicitly labelled non-certifying.
  run_node "v4 M7 suites" 1800 \
    tests/v4-m7-discovery.test.ts tests/v4-m7-heldout.test.ts tests/v4-m7-heldout2.test.ts \
    tests/v4-m7-orch.test.ts tests/v4-m7-probes2.test.ts tests/v4-m7-spa.test.ts \
    tests/v4-m7-specs.test.ts tests/v4-m7-specs2.test.ts
  run_node "v5 pure unit suites" 1800 \
    tests/v5-board-store.test.ts tests/v5-m2-auth.test.ts tests/v5-m2-recon-probing.test.ts \
    tests/v5-m3-probes.test.ts
  run_node "security regression suites" 900 \
    tests/v5-security-approvals.test.ts tests/v5-security-repo.test.ts \
    tests/v5-security-authbrowser.test.ts
  run_node "worker lifecycle hygiene (stubs)" 300 tests/v5-gate-worker-lifecycle.test.ts
else
  run_node "v2 core boundaries" 900 \
    tests/boundaries.test.ts tests/persona-login.test.ts tests/approval-judge.test.ts \
    tests/report-comparison.test.ts tests/provider-stream.test.ts tests/v2-upgrades.test.ts
  run_node "v3/v4/v5 boundaries" 1800 \
    tests/v3-boundaries.test.ts tests/v3-protocol-browser.test.ts tests/v4-boundaries.test.ts \
    tests/v5-board-boundaries.test.ts
  run_node "v4 M1-M7 milestone suites" 3600 \
    tests/v4-m1-schema-verify-routing.test.ts tests/v4-m2-broker-browser-probes.test.ts \
    tests/v4-m3-worker-sast-templates.test.ts tests/v4-m4-surface-orchestration.test.ts \
    tests/v4-m5-lab-iast-ui.test.ts tests/v4-m6-benchmarks.test.ts \
    tests/v4-m7-discovery.test.ts tests/v4-m7-heldout.test.ts tests/v4-m7-heldout2.test.ts \
    tests/v4-m7-orch.test.ts tests/v4-m7-probes2.test.ts tests/v4-m7-spa.test.ts \
    tests/v4-m7-specs.test.ts tests/v4-m7-specs2.test.ts
  V5_SUITES="$(find tests -maxdepth 1 -name 'v5-*.test.ts' ! -name 'v5-board-boundaries.test.ts' ! -name 'v5-gate-worker-lifecycle.test.ts' | sort | tr '\n' ' ')"
  run_node "v5 suites (all)" 3600 $V5_SUITES
  run_node "v5 gate worker lifecycle" 600 tests/v5-gate-worker-lifecycle.test.ts
  run_node "v4 tiered E2E matrix (322)" 3600 tests/v4-e2e-tiers.test.ts
  run_node "realistic-bench harness" 1800 benchmarks/realistic-bench/tests/

  SUITES=$((SUITES + 1))
  echo "== Playwright UI E2E (v2, v4, v5 board)"
  if timeout 1800 npx playwright test tests/guardian-v2.spec.ts tests/guardian-v4.spec.ts tests/guardian-v5-board.spec.ts >"$TMP/playwright.log" 2>&1; then
    p="$(grep -oE '[0-9]+ passed' "$TMP/playwright.log" | tail -1 | awk '{print $1}')"
    f="$(grep -oE '[0-9]+ failed' "$TMP/playwright.log" | tail -1 | awk '{print $1}')"
    s="$(grep -oE '[0-9]+ skipped' "$TMP/playwright.log" | tail -1 | awk '{print $1}')"
    TOTAL=$((TOTAL + ${p:-0} + ${f:-0} + ${s:-0}))
    PASS=$((PASS + ${p:-0})); FAIL=$((FAIL + ${f:-0})); SKIP=$((SKIP + ${s:-0}))
    if [[ "${f:-0}" -ne 0 || "${s:-0}" -ne 0 ]]; then
      GATE_FAIL=1
      record_row "Playwright UI E2E" "$(( ${p:-0} + ${f:-0} + ${s:-0} ))" "${p:-0}" "${f:-0}" "${s:-0}" "FAIL"
      tail -20 "$TMP/playwright.log"
    else
      record_row "Playwright UI E2E" "${p:-0}" "${p:-0}" "0" "0" "pass"
    fi
  else
    GATE_FAIL=1
    grep -E '[0-9]+ (passed|failed|flaky)' "$TMP/playwright.log" | tail -2
    tail -25 "$TMP/playwright.log"
    echo "-- FAILED: Playwright (log: $TMP/playwright.log)" >&2
    record_row "Playwright UI E2E" "-" "-" "-" "-" "FAIL"
  fi

  orphan_check
fi

echo
echo "gate table"
printf '%-38s %7s %7s %7s %8s  %s\n' "suite" "tests" "pass" "fail" "skipped" "status"
printf '%-38s %7s %7s %7s %8s  %s\n' "--------------------------------------" "-------" "-------" "-------" "--------" "------"
for row in "${ROWS[@]}"; do printf '%s\n' "$row"; done
echo
if [[ "$MODE" == fast ]]; then
  echo "FAST (Docker-free) subset: $PASS/$TOTAL passed, $FAIL failed, $SKIP skipped across $SUITES checks."
  echo "This is NOT the release gate. Run --full under Docker for certification."
else
  echo "FULL GATE: $PASS/$TOTAL passed, $FAIL failed, $SKIP skipped across $SUITES checks."
fi
echo "logs: $TMP"

if [[ "$GATE_FAIL" -ne 0 ]]; then
  exit 1
fi
if [[ "$MODE" == full ]]; then
  echo "release gate: PASS (0 failures, 0 skips, 0 orphans)"
fi
exit 0
