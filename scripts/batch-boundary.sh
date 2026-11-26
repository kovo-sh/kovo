#!/usr/bin/env bash
# Batch-boundary certification & measurement orchestrator (`R3-02`, `plans/claude_quality_3.md` §2).
#
# Runs the binding batch-close workflow:
#   1. Dirty-tree provenance check (`git status --porcelain` MUST be empty for certifying runs).
#   2. Fresh salted held-out seed draw (`drawUnburnedHeldoutSeeds`, >= 3 unburned seeds; salt never printed).
#   3. Execution benchmark legs (dev + held-out, `--no-llm` + agentic), writing per-run ledger rows
#      into an isolated batch `KOVO_LEDGER_ROOT` directory.
#   4. Promote validated per-run rows into `benchmarks/results/ledger.jsonl` via `promoteLedgerRows`.
#   5. Deterministic regression floor check via `scripts/regression-floor.sh` against baseline.
#   6. Render verification tables via `scripts/render-verification-tables.ts` (when present).
#
# Usage:
#   bash scripts/batch-boundary.sh [--dry-run|--plan] [--allow-dirty]
#                                  [--apps <a,b|all>] [--modes <m,...>]
#                                  [--dev-seeds <a,b>] [--heldout-seeds <a,b,c>] [--heldout-count <n>]
#                                  [--data-dir <dir>] [--verifier <auto|docker|local-jq>]
#                                  [--out-dir <dir>] [--runs-dir <dir>]
#                                  [--ledger <path>] [--baseline <path>] [--tables-out <path>]
#                                  [--skip-agentic] [--skip-heldout]
#                                  [--skip-regression-floor] [--skip-render]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DRY_RUN=0
ALLOW_DIRTY=0
APPS="all"
MODES="grey-box"
DEV_SEEDS="1"
HELDOUT_SEEDS=""
HELDOUT_COUNT=3
DATA_DIR="${KOVO_DATA_DIR:-}"
VERIFIER="docker"
NO_LLM_VERIFIER="auto"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR=".kovo/batch-boundary/${STAMP}"
RUNS_DIR=""
LEDGER_PATH="benchmarks/results/ledger.jsonl"
BASELINE_PATH="benchmarks/baselines/floor.json"
TABLES_OUT="benchmarks/results/VERIFICATION-TABLES.md"
SKIP_AGENTIC=0
SKIP_HELDOUT=0
SKIP_REGRESSION_FLOOR=0
SKIP_RENDER=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run|--plan) DRY_RUN=1; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    --apps) APPS="${2:?--apps requires a value}"; shift 2 ;;
    --modes) MODES="${2:?--modes requires a value}"; shift 2 ;;
    --dev-seeds) DEV_SEEDS="${2:?--dev-seeds requires a value}"; shift 2 ;;
    --heldout-seeds) HELDOUT_SEEDS="${2:?--heldout-seeds requires a value}"; shift 2 ;;
    --heldout-count) HELDOUT_COUNT="${2:?--heldout-count requires a positive integer}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:?--data-dir requires a path}"; shift 2 ;;
    --verifier) VERIFIER="${2:?--verifier requires a value}"; shift 2 ;;
    --no-llm-verifier) NO_LLM_VERIFIER="${2:?--no-llm-verifier requires a value}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:?--out-dir requires a directory}"; shift 2 ;;
    --runs-dir) RUNS_DIR="${2:?--runs-dir requires a directory}"; shift 2 ;;
    --ledger) LEDGER_PATH="${2:?--ledger requires a path}"; shift 2 ;;
    --baseline) BASELINE_PATH="${2:?--baseline requires a path}"; shift 2 ;;
    --tables-out) TABLES_OUT="${2:?--tables-out requires a path}"; shift 2 ;;
    --skip-agentic) SKIP_AGENTIC=1; shift ;;
    --skip-heldout) SKIP_HELDOUT=1; shift ;;
    --skip-regression-floor) SKIP_REGRESSION_FLOOR=1; shift ;;
    --skip-render) SKIP_RENDER=1; shift ;;
    -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; exit 2 ;;
  esac
done

if ! [[ "$HELDOUT_COUNT" =~ ^[1-9][0-9]*$ ]]; then
  echo "error: --heldout-count must be a positive integer (got '$HELDOUT_COUNT')" >&2
  exit 2
fi

# Validate --apps, --modes, --verifier, --no-llm-verifier, and seed lists BEFORE any
# dirty-tree / seed-draw work so invalid invocations fail fast with zero side effects.
validate_csv_enum() {
  local flag="$1"
  local raw="$2"
  shift 2
  local -a allowed=("$@")
  if [[ -z "$raw" ]]; then
    echo "error: ${flag} must not be empty" >&2
    exit 2
  fi
  local IFS=','
  local -a items=()
  read -r -a items <<< "$raw"
  local seen=0
  local item trimmed ok val
  for item in "${items[@]}"; do
    trimmed="${item#"${item%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    if [[ -z "$trimmed" ]]; then
      continue
    fi
    seen=1
    ok=0
    for val in "${allowed[@]}"; do
      if [[ "$trimmed" == "$val" ]]; then
        ok=1
        break
      fi
    done
    if (( ok == 0 )); then
      echo "error: unknown ${flag} value '${trimmed}' (allowed: ${allowed[*]})" >&2
      exit 2
    fi
  done
  if (( seen == 0 )); then
    echo "error: ${flag} must specify at least one value" >&2
    exit 2
  fi
}

validate_seed_list() {
  local flag="$1"
  local raw="$2"
  local IFS=','
  local -a items=()
  read -r -a items <<< "$raw"
  local seen=0
  local item trimmed
  for item in "${items[@]}"; do
    trimmed="${item#"${item%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    if [[ -z "$trimmed" ]]; then
      continue
    fi
    seen=1
    if ! [[ "$trimmed" =~ ^[1-9][0-9]*$ ]]; then
      echo "error: ${flag} seed '${trimmed}' must be a positive integer" >&2
      exit 2
    fi
  done
  if (( seen == 0 )); then
    echo "error: ${flag} must specify at least one seed" >&2
    exit 2
  fi
}

if [[ "$APPS" != "all" ]]; then
  validate_csv_enum "--apps" "$APPS" acme-saas shopflow opsportal
fi
validate_csv_enum "--modes" "$MODES" black-box grey-box white-box
validate_csv_enum "--verifier" "$VERIFIER" auto docker local-jq
validate_csv_enum "--no-llm-verifier" "$NO_LLM_VERIFIER" auto docker local-jq
validate_seed_list "--dev-seeds" "$DEV_SEEDS"
if [[ -n "$HELDOUT_SEEDS" ]]; then
  validate_seed_list "--heldout-seeds" "$HELDOUT_SEEDS"
fi

if (( SKIP_AGENTIC == 0 && DRY_RUN == 0 )) && [[ -z "$DATA_DIR" ]]; then
  echo "FAIL: agentic legs require --data-dir or KOVO_DATA_DIR (or pass --skip-agentic for non-certifying floor-only runs)." >&2
  exit 2
fi

if [[ -z "$RUNS_DIR" ]]; then
  RUNS_DIR="${OUT_DIR}/ledger-runs"
fi

step() { printf '\n== [batch-boundary] %s\n' "$1"; }

# ---------------------------------------------------------------------------
# 1. Dirty-tree & git provenance gate
# ---------------------------------------------------------------------------
GIT_SHA="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
DIRTY_STATUS="$(git status --porcelain 2>/dev/null || true)"
IS_DIRTY=0
if [[ -n "$DIRTY_STATUS" ]]; then
  IS_DIRTY=1
fi

CERTIFYING=1
if (( IS_DIRTY == 1 || ALLOW_DIRTY == 1 || SKIP_AGENTIC == 1 || SKIP_HELDOUT == 1 )); then
  CERTIFYING=0
fi

if (( IS_DIRTY == 1 && ALLOW_DIRTY == 0 )); then
  echo "FAIL: certifying batch-boundary run refuses a dirty working tree (git status --porcelain is non-empty)." >&2
  echo "      Commit or stash local changes first, or pass --allow-dirty for a non-certifying run." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. Fresh salted held-out seed draw (salt is never printed or logged)
#    Draw with recordExposure: false so EXPOSED_SEEDS.json is NOT written before
#    the certifying benchmark legs run (keeping `git status --porcelain` clean
#    so every certifying leg observes `dirty: false`). Exposure is recorded only
#    after held-out legs actually run.
# ---------------------------------------------------------------------------
HELDOUT_DRAWN=0
HELDOUT_START_INDEX=""
HELDOUT_END_INDEX=""
HELDOUT_STARTED=0
HELDOUT_EXPOSURE_RECORDED=0

if (( SKIP_HELDOUT == 0 )) && [[ -z "$HELDOUT_SEEDS" ]]; then
  if [[ -z "${KOVO_RB_HELDOUT_SALT:-}" ]] && [[ -f "${HOME}/.config/guardian-bench/heldout.salt" ]]; then
    KOVO_RB_HELDOUT_SALT="$(tr -d '\r\n' < "${HOME}/.config/guardian-bench/heldout.salt")"
    export KOVO_RB_HELDOUT_SALT
  fi
  if [[ -n "${KOVO_RB_HELDOUT_SALT:-}" ]]; then
    DRAW_META="$(node --input-type=module - "$HELDOUT_COUNT" <<'EOF'
import { drawUnburnedHeldoutSeedsWithMeta } from './scripts/bench-ledger.ts'

const [countRaw] = process.argv.slice(2)
const count = Number(countRaw)
const salt = process.env.KOVO_RB_HELDOUT_SALT ?? ''
const drawn = drawUnburnedHeldoutSeedsWithMeta(count, salt, undefined, process.cwd(), {
  domain: 'certify',
  recordExposure: false,
})
process.stdout.write(`${drawn.seeds.join(',')}\t${drawn.startIndex}\t${drawn.endIndex}`)
EOF
)"
    IFS=$'\t' read -r HELDOUT_SEEDS HELDOUT_START_INDEX HELDOUT_END_INDEX <<< "$DRAW_META"
    HELDOUT_DRAWN=1
  elif (( DRY_RUN == 1 )); then
    HELDOUT_SEEDS="<draw:${HELDOUT_COUNT}-fresh-salted-seeds>"
  else
    echo "FAIL: KOVO_RB_HELDOUT_SALT is required to draw fresh salted held-out seeds (or pass --heldout-seeds / --skip-heldout)." >&2
    exit 2
  fi
fi

record_heldout_exposure() {
  if (( DRY_RUN == 1 || HELDOUT_DRAWN == 0 || HELDOUT_STARTED == 0 || HELDOUT_EXPOSURE_RECORDED == 1 )); then
    return 0
  fi
  HELDOUT_EXPOSURE_RECORDED=1
  node --input-type=module - "$HELDOUT_SEEDS" "$HELDOUT_START_INDEX" "$HELDOUT_END_INDEX" "$GIT_SHA" "$STAMP" <<'EOF'
import { recordExposedHeldoutSeeds } from './scripts/bench-ledger.ts'

const [seedsRaw, startRaw, endRaw, gitSha, stamp] = process.argv.slice(2)
const seeds = seedsRaw
  .split(',')
  .map(s => Number(s.trim()))
  .filter(n => Number.isInteger(n) && n > 0)
const startIndex = Number(startRaw)
const endIndex = Number(endRaw)
recordExposedHeldoutSeeds(
  {
    certificateId: `batch-boundary-${stamp}`,
    domain: 'certify',
    startIndex,
    endIndex,
    seeds,
    gitSha,
  },
  undefined,
  process.cwd(),
)
EOF
}

DEV_RUNS_DIR="${RUNS_DIR}/dev"
HELDOUT_RUNS_DIR="${RUNS_DIR}/heldout"
HAS_RENDERER=0
if [[ -f "scripts/render-verification-tables.ts" ]]; then
  HAS_RENDERER=1
fi

# ---------------------------------------------------------------------------
# Plan / Dry-run output
# ---------------------------------------------------------------------------
print_plan() {
  cat <<EOF
batch-boundary plan:
  gitSha:            ${GIT_SHA}
  dirty:             $([[ $IS_DIRTY -eq 1 ]] && echo true || echo false)
  certifying:        $([[ $CERTIFYING -eq 1 ]] && echo true || echo false)
  apps:              ${APPS}
  modes:             ${MODES}
  devSeeds:          ${DEV_SEEDS}
  heldoutSeeds:      $([[ $SKIP_HELDOUT -eq 1 ]] && echo skipped || echo "${HELDOUT_SEEDS}")
  outDir:            ${OUT_DIR}
  runsDir:           ${RUNS_DIR}
  ledger:            ${LEDGER_PATH}
  baseline:          ${BASELINE_PATH}
  tablesOut:         ${TABLES_OUT}
steps:
  1. dev --no-llm:       KOVO_ALLOW_LOCAL_LAB=1 KOVO_LEDGER_ROOT=${DEV_RUNS_DIR} node scripts/benchmark-agentic-matrix.ts --apps ${APPS} --seeds ${DEV_SEEDS} --modes ${MODES} --no-llm --verifier ${NO_LLM_VERIFIER} --out-dir ${OUT_DIR}/dev-no-llm
EOF
  if (( SKIP_AGENTIC == 0 )); then
    printf '  2. dev agentic:        KOVO_ALLOW_LOCAL_LAB=1 KOVO_LEDGER_ROOT=%s node scripts/benchmark-agentic-matrix.ts --apps %s --seeds %s --modes %s --verifier %s --data-dir %s --out-dir %s/dev-agentic\n' \
      "${DEV_RUNS_DIR}" "${APPS}" "${DEV_SEEDS}" "${MODES}" "${VERIFIER}" "${DATA_DIR:-<KOVO_DATA_DIR>}" "${OUT_DIR}"
  else
    printf '  2. dev agentic:        SKIPPED (--skip-agentic)\n'
  fi
  if (( SKIP_HELDOUT == 0 )); then
    printf '  3. held-out --no-llm:  KOVO_ALLOW_LOCAL_LAB=1 KOVO_LEDGER_ROOT=%s node scripts/benchmark-agentic-matrix.ts --apps %s --seeds %s --modes %s --no-llm --verifier %s --out-dir %s/heldout-no-llm\n' \
      "${HELDOUT_RUNS_DIR}" "${APPS}" "${HELDOUT_SEEDS}" "${MODES}" "${NO_LLM_VERIFIER}" "${OUT_DIR}"
    if (( SKIP_AGENTIC == 0 )); then
      printf '  4. held-out agentic:   KOVO_ALLOW_LOCAL_LAB=1 KOVO_LEDGER_ROOT=%s node scripts/benchmark-agentic-matrix.ts --apps %s --seeds %s --modes %s --certify --verifier %s --data-dir %s --out-dir %s/heldout-agentic\n' \
        "${HELDOUT_RUNS_DIR}" "${APPS}" "${HELDOUT_SEEDS}" "${MODES}" "${VERIFIER}" "${DATA_DIR:-<KOVO_DATA_DIR>}" "${OUT_DIR}"
    else
      printf '  4. held-out agentic:   SKIPPED (--skip-agentic)\n'
    fi
  else
    printf '  3. held-out --no-llm:  SKIPPED (--skip-heldout)\n'
    printf '  4. held-out agentic:   SKIPPED (--skip-heldout)\n'
  fi
  printf '  5. promoteLedgerRows:  promote %s (requireValid=true) & %s (requireCertifying=%s) -> %s\n' \
    "${DEV_RUNS_DIR}" "${HELDOUT_RUNS_DIR}" "$([[ $CERTIFYING -eq 1 ]] && echo true || echo false)" "${LEDGER_PATH}"
  if (( SKIP_REGRESSION_FLOOR == 0 )); then
    printf '  6. regression-floor:   bash scripts/regression-floor.sh --all-suites --baseline %s --out-dir %s/regression-floor\n' \
      "${BASELINE_PATH}" "${OUT_DIR}"
  else
    printf '  6. regression-floor:   SKIPPED (--skip-regression-floor)\n'
  fi
  if (( SKIP_RENDER == 0 && HAS_RENDERER == 1 )); then
    printf '  7. render tables:      node scripts/render-verification-tables.ts --ledger %s --out %s\n' \
      "${LEDGER_PATH}" "${TABLES_OUT}"
  else
    printf '  7. render tables:      SKIPPED\n'
  fi
}

if (( DRY_RUN == 1 )); then
  print_plan
  exit 0
fi

mkdir -p "$OUT_DIR" "$DEV_RUNS_DIR" "$HELDOUT_RUNS_DIR"
trap record_heldout_exposure EXIT

# ---------------------------------------------------------------------------
# 3. Execute benchmark legs into isolated per-batch KOVO_LEDGER_ROOT
# ---------------------------------------------------------------------------
step "dev --no-llm (seeds=${DEV_SEEDS})"
KOVO_ALLOW_LOCAL_LAB=1 KOVO_LEDGER_ROOT="$DEV_RUNS_DIR" \
  node scripts/benchmark-agentic-matrix.ts \
  --apps "$APPS" \
  --seeds "$DEV_SEEDS" \
  --modes "$MODES" \
  --no-llm \
  --verifier "$NO_LLM_VERIFIER" \
  --out-dir "${OUT_DIR}/dev-no-llm"

if (( SKIP_AGENTIC == 0 )); then
  step "dev agentic (seeds=${DEV_SEEDS})"
  KOVO_ALLOW_LOCAL_LAB=1 KOVO_LEDGER_ROOT="$DEV_RUNS_DIR" \
    node scripts/benchmark-agentic-matrix.ts \
    --apps "$APPS" \
    --seeds "$DEV_SEEDS" \
    --modes "$MODES" \
    --verifier "$VERIFIER" \
    --data-dir "$DATA_DIR" \
    --out-dir "${OUT_DIR}/dev-agentic"
fi

if (( SKIP_HELDOUT == 0 )); then
  HELDOUT_STARTED=1
  step "held-out --no-llm (seeds=${HELDOUT_SEEDS})"
  KOVO_ALLOW_LOCAL_LAB=1 KOVO_LEDGER_ROOT="$HELDOUT_RUNS_DIR" \
    node scripts/benchmark-agentic-matrix.ts \
    --apps "$APPS" \
    --seeds "$HELDOUT_SEEDS" \
    --modes "$MODES" \
    --no-llm \
    --verifier "$NO_LLM_VERIFIER" \
    --out-dir "${OUT_DIR}/heldout-no-llm"

  if (( SKIP_AGENTIC == 0 )); then
    step "held-out agentic (certifying, seeds=${HELDOUT_SEEDS})"
    KOVO_ALLOW_LOCAL_LAB=1 KOVO_LEDGER_ROOT="$HELDOUT_RUNS_DIR" \
      node scripts/benchmark-agentic-matrix.ts \
      --apps "$APPS" \
      --seeds "$HELDOUT_SEEDS" \
      --modes "$MODES" \
      --certify \
      --verifier "$VERIFIER" \
      --data-dir "$DATA_DIR" \
      --out-dir "${OUT_DIR}/heldout-agentic"
  fi

  if (( HELDOUT_DRAWN == 1 )); then
    step "recordExposedHeldoutSeeds (seeds=${HELDOUT_SEEDS})"
    record_heldout_exposure
  fi
fi

# ---------------------------------------------------------------------------
# 4. Promote validated per-run ledger rows into committed ledger
# ---------------------------------------------------------------------------
step "promoteLedgerRows -> ${LEDGER_PATH}"
node --input-type=module - "$DEV_RUNS_DIR" "$HELDOUT_RUNS_DIR" "$LEDGER_PATH" "$CERTIFYING" "$SKIP_HELDOUT" <<'EOF'
import { promoteLedgerRows } from './scripts/bench-ledger.ts'

const [devDir, heldoutDir, targetLedgerPath, certifyingRaw, skipHeldoutRaw] = process.argv.slice(2)
const certifying = certifyingRaw === '1'
const skipHeldout = skipHeldoutRaw === '1'

const devPromo = promoteLedgerRows(devDir, {
  targetLedgerPath,
  repoRoot: process.cwd(),
  requireValid: true,
  requireCertifying: false,
})
console.log(
  `promoted dev rows: promoted=${devPromo.promoted} skippedInvalid=${devPromo.skippedInvalid} skippedDup=${devPromo.skippedDuplicate}`,
)

if (!skipHeldout) {
  const heldPromo = promoteLedgerRows(heldoutDir, {
    targetLedgerPath,
    repoRoot: process.cwd(),
    requireValid: true,
    requireCertifying: certifying,
  })
  console.log(
    `promoted held-out rows: promoted=${heldPromo.promoted} skippedInvalid=${heldPromo.skippedInvalid} skippedNonCertifying=${heldPromo.skippedNonCertifying} skippedDup=${heldPromo.skippedDuplicate}`,
  )
  if (certifying && heldPromo.promoted === 0 && heldPromo.skippedDuplicate === 0) {
    console.error('FAIL: certifying batch-boundary promoted 0 held-out rows')
    process.exit(1)
  }
}
EOF

# ---------------------------------------------------------------------------
# 5. Deterministic regression floor against baseline
# ---------------------------------------------------------------------------
if (( SKIP_REGRESSION_FLOOR == 0 )); then
  step "regression-floor.sh (baseline=${BASELINE_PATH})"
  bash scripts/regression-floor.sh \
    --all-suites \
    --baseline "$BASELINE_PATH" \
    --out-dir "${OUT_DIR}/regression-floor"
fi

# ---------------------------------------------------------------------------
# 6. Render verification tables from committed ledger
# ---------------------------------------------------------------------------
if (( SKIP_RENDER == 0 && HAS_RENDERER == 1 )); then
  step "render-verification-tables.ts -> ${TABLES_OUT}"
  node scripts/render-verification-tables.ts \
    --ledger "$LEDGER_PATH" \
    --out "$TABLES_OUT"
fi

printf '\nbatch-boundary: PASS (gitSha=%s certifying=%s ledger=%s)\n' \
  "$GIT_SHA" "$([[ $CERTIFYING -eq 1 ]] && echo true || echo false)" "$LEDGER_PATH"
