#!/usr/bin/env bash
# Batch-boundary / pre-push deterministic regression floor (`cq-3-merge-gate`).
#
# Runs (NOT per-merge worker-gate.sh — run at batch boundaries / pre-push / CI):
#   1. Golden E2E multi-hop chain suite (`tests/v8-seam1-golden-e2e.test.ts`)
#   2. Boundary contract suites (`npm run test:boundaries`)
#   3. Optional deterministic floor checks (`--with-xben`, `--with-heldout-saas`, or `--all-suites`),
#      diffed against a committed baseline JSON (default: `benchmarks/baselines/floor.json`).
#      Fails closed on any lost TP (confirmedCount drop or previously confirmed target lost)
#      or any gained FP (falsePositiveCount increase).
#
# Usage:
#   bash scripts/regression-floor.sh [--with-xben] [--with-heldout-saas] [--all-suites]
#                                    [--baseline <path>] [--out-dir <dir>]
#                                    [--skip-boundaries] [--skip-golden]
#                                    [--verifier-backend <auto|docker|local-jq>]
#                                    [--write-baseline]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WITH_XBEN=0
WITH_HELDOUT_SAAS=0
SKIP_BOUNDARIES=0
SKIP_GOLDEN=0
WRITE_BASELINE=0
BASELINE_PATH="benchmarks/baselines/floor.json"
OUT_DIR="${TMPDIR:-/tmp}/kovo-regression-floor-$$"
VERIFIER_BACKEND="auto"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-xben) WITH_XBEN=1; shift;;
    --with-heldout-saas) WITH_HELDOUT_SAAS=1; shift;;
    --all-suites) WITH_XBEN=1; WITH_HELDOUT_SAAS=1; shift;;
    --skip-boundaries) SKIP_BOUNDARIES=1; shift;;
    --skip-golden) SKIP_GOLDEN=1; shift;;
    --write-baseline) WRITE_BASELINE=1; shift;;
    --baseline) BASELINE_PATH="${2:?--baseline requires a path}"; shift 2;;
    --out-dir) OUT_DIR="${2:?--out-dir requires a directory}"; shift 2;;
    --verifier-backend) VERIFIER_BACKEND="${2:?--verifier-backend requires a value}"; shift 2;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

mkdir -p "$OUT_DIR"
fail=0
step() { printf '\n== %s\n' "$1"; }

if (( SKIP_GOLDEN == 0 )); then
  step "golden E2E (tests/v8-seam1-golden-e2e.test.ts)"
  if node --test tests/v8-seam1-golden-e2e.test.ts; then
    echo "PASS: golden E2E"
  else
    echo "FAIL: golden E2E" >&2
    fail=1
  fi
fi

if (( SKIP_BOUNDARIES == 0 )); then
  step "boundary suites (npm run test:boundaries)"
  if npm run test:boundaries; then
    echo "PASS: test:boundaries"
  else
    echo "FAIL: test:boundaries" >&2
    fail=1
  fi
fi

SUITES=()
if (( WITH_XBEN == 1 )); then SUITES+=("xben-25"); fi
if (( WITH_HELDOUT_SAAS == 1 )); then SUITES+=("held-out-saas"); fi

if (( ${#SUITES[@]} > 0 )); then
  if (( WRITE_BASELINE == 0 )) && [[ ! -f "$BASELINE_PATH" ]]; then
    echo "FAIL: baseline JSON not found at '$BASELINE_PATH' (pass --baseline <path> or --write-baseline to initialize)." >&2
    fail=1
  else
    for suite in "${SUITES[@]}"; do
      step "deterministic floor: $suite"
      out_json="$OUT_DIR/${suite}.json"
      if KOVO_ALLOW_LOCAL_LAB=1 node scripts/benchmark-recall.ts \
           --suite "$suite" \
           --verifier-backend "$VERIFIER_BACKEND" \
           --out-json "$out_json"; then
        echo "Completed $suite -> $out_json"
      else
        echo "FAIL: benchmark-recall.ts failed for $suite" >&2
        fail=1
        continue
      fi

      if (( WRITE_BASELINE == 1 )); then
        node --input-type=module - "$BASELINE_PATH" "$suite" "$out_json" <<'EOF'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

const [baselinePath, suite, outJsonPath] = process.argv.slice(2)
const actual = JSON.parse(readFileSync(outJsonPath, 'utf8'))
const baseline = existsSync(baselinePath)
  ? JSON.parse(readFileSync(baselinePath, 'utf8'))
  : { schemaVersion: 1, suites: {} }
baseline.suites = baseline.suites || {}
const confirmedIds = Array.isArray(actual.perTarget)
  ? actual.perTarget.filter(t => t && t.confirmed).map(t => t.id).sort()
  : []
baseline.updatedAt = new Date().toISOString()
baseline.suites[suite] = {
  gitSha: actual.gitSha || null,
  targetsTotal: Number(actual.targetsTotal ?? 0),
  confirmedCount: Number(actual.confirmedCount ?? 0),
  falsePositiveCount: Number(actual.falsePositiveCount ?? 0),
  confirmedIds,
}
mkdirSync(dirname(baselinePath), { recursive: true })
writeFileSync(baselinePath, `${JSON.stringify(baseline, null, 2)}\n`, 'utf8')
console.log(`Updated baseline ${baselinePath} [${suite}]: confirmed=${baseline.suites[suite].confirmedCount}/${baseline.suites[suite].targetsTotal}, fp=${baseline.suites[suite].falsePositiveCount}`)
EOF
      else
        if node --input-type=module - "$BASELINE_PATH" "$suite" "$out_json" <<'EOF'
import { readFileSync } from 'node:fs'

const [baselinePath, suite, outJsonPath] = process.argv.slice(2)
const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'))
const actual = JSON.parse(readFileSync(outJsonPath, 'utf8'))
const expected = baseline?.suites?.[suite] ?? baseline?.[suite]
if (!expected || typeof expected !== 'object') {
  console.error(`FAIL: baseline ${baselinePath} has no entry for suite "${suite}"`)
  process.exit(1)
}

const actualConfirmed = Number(actual.confirmedCount ?? 0)
const actualFp = Number(actual.falsePositiveCount ?? 0)
const expectedConfirmed = Number(expected.confirmedCount ?? 0)
const expectedFp = Number(expected.falsePositiveCount ?? 0)

const actualIds = new Set(
  Array.isArray(actual.perTarget)
    ? actual.perTarget.filter(t => t && t.confirmed).map(t => String(t.id))
    : [],
)
const expectedIds = Array.isArray(expected.confirmedIds) ? expected.confirmedIds.map(String) : []
const lostIds = expectedIds.filter(id => !actualIds.has(id))

const reasons = []
if (actualConfirmed < expectedConfirmed) {
  reasons.push(`lost TP count: ${actualConfirmed} < baseline ${expectedConfirmed}`)
}
if (lostIds.length > 0) {
  reasons.push(`lost confirmed TP(s): ${lostIds.join(', ')}`)
}
if (actualFp > expectedFp) {
  reasons.push(`gained FP(s): ${actualFp} > baseline ${expectedFp}`)
}

if (reasons.length > 0) {
  console.error(`FAIL [${suite}] regression floor breached: ${reasons.join('; ')}`)
  process.exit(1)
}
console.log(`PASS [${suite}] regression floor: confirmed=${actualConfirmed} (baseline ${expectedConfirmed}), fp=${actualFp} (baseline ${expectedFp})`)
EOF
        then :; else
          fail=1
        fi
      fi
    done
  fi
fi

printf '\nregression-floor: %s\n' "$([[ $fail -eq 0 ]] && echo PASS || echo FAIL)"
exit "$fail"
