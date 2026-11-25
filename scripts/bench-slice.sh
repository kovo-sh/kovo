#!/usr/bin/env bash
# Targeted one-app, one-class realistic slice. Prints a compact funnel + per-target
# statuses for the selected class. Uses the existing procedural driver; no ad-hoc scripts.
#
# Usage:
#   KOVO_ALLOW_LOCAL_LAB=1 scripts/bench-slice.sh --app shopflow [--class jwt]
#       [--seed 42] [--split dev|heldout] [--mode grey-box] [--out-dir /tmp/...]
#
# Held-out requires KOVO_RB_HELDOUT_SALT in the environment.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
APP=""; CLASS=""; SEED="42"; SPLIT="dev"; MODE="grey-box"; OUT="${TMPDIR:-/tmp}/bench-slice-$$"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --app) APP="${2:?}"; shift 2;;
    --class) CLASS="${2:?}"; shift 2;;
    --seed) SEED="${2:?}"; shift 2;;
    --split) SPLIT="${2:?}"; shift 2;;
    --mode) MODE="${2:?}"; shift 2;;
    --out-dir) OUT="${2:?}"; shift 2;;
    -h|--help) sed -n '2,12p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
[[ -n "$APP" ]] || { echo "--app is required" >&2; exit 2; }
[[ "$SPLIT" == "heldout" && "${KOVO_RB_HELDOUT_SALT:-}" == "" ]] && { echo "heldout requires KOVO_RB_HELDOUT_SALT" >&2; exit 2; }
mkdir -p "$OUT"
JSON="$OUT/score.json"
LOG="$OUT/run.log"

SLICE_ARGS=(--app "$APP" --seed "$SEED" --split "$SPLIT" --mode "$MODE" --out-json "$JSON" --out-findings "$OUT/findings.json")
if ! KOVO_ALLOW_LOCAL_LAB=1 node "$ROOT/benchmarks/realistic-bench/benchmark-realistic.ts" "${SLICE_ARGS[@]}" >"$LOG" 2>&1; then
  echo "slice failed; tail:" >&2; tail -12 "$LOG" >&2; exit 1
fi

node -e '
const c = require(process.argv[1]);
const cls = process.argv[2] || "";
const pct = v => (v * 100).toFixed(1) + "%";
const f = c.funnel || {};
console.log(`slice app=${c.app} seed=${c.seed} split=${c.seedSet} mode=${c.mode}`);
console.log(`funnel target=${f.targetVulns} surface=${f.surfaceDiscovered} hyp=${f.hypothesisFormed} signal=${f.signalObserved} spec=${f.specSubmitted} confirmed=${f.zeroLlmConfirmed}`);
console.log(`confirmed=${c.confirmed}/${c.targets} (${pct(c.recall||0)}) precision=${pct(c.precision||0)} decoyFP=${c.decoyFalsePositives}/${c.decoys} unmatchedFP=${c.unmatchedFalsePositives}`);
const classes = c.recallByClass || {};
for (const [k, v] of Object.entries(classes)) {
  if (cls && k !== cls) continue;
  console.log(`class ${k}: ${v.confirmed}/${v.targets}`);
}
const vulns = (c.vulns || []).filter(v => !cls || (v.vulnClass||v.class) === cls);
for (const v of vulns) console.log(`  ${v.siteId||v.id} ${v.vulnClass||v.class} -> ${v.outcome||v.status} ${v.failureBucket||""}`);
' "$JSON" "$CLASS"
echo "artifacts: $OUT"
