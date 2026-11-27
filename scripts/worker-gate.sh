#!/usr/bin/env bash
# Mandatory pre-handoff behavioral merge gate (`cq-3-merge-gate`).
# Fast (<60s): typecheck (seeded incremental `tsc`) + v8 contamination lint +
# contract-change trailer lint + wiring invariants + quarantine/orphan check +
# all non-quarantined fast unit suites in parallel + optional targeted slice.
#
# Narrow-diff scoping (fail-closed):
#   - Only activates when `KOVO_GATE_FULL != 1`, `--full` was NOT passed, a valid
#     non-empty changed-file list is resolved against base (`KOVO_GATE_BASE_REF` /
#     `KOVO_CONTRACT_BASE` / merge-base against `main`), and ZERO files touch
#     `src/`, `scripts/`, `worker/`, `benchmarks/`, `public/`, `tsconfig*.json`,
#     `package*.json`, `tests/parity/`, `.githooks/`, confirmation-kernel files,
#     or non-`*.test.ts` helpers/fixtures under `tests/`.
#   - Pure non-code diffs (e.g. `.github/**`, `docs/**`, `plans/**`, `*.md`) skip
#     `tsc` and the 505 fast suites while still enforcing all fast static & trailer
#     guards (`check-unwired.ts` still runs whenever `ARCHITECTURE.md` changed).
#   - Test-only diffs (top-level `tests/*.test.ts` + optional non-code files) run
#     seeded incremental `tsc` and ONLY the touched `tests/*.test.ts` file(s).
#   - Any code/config/helper change or undetermined/empty diff fails closed to FULL.
#
# Usage:
#   scripts/worker-gate.sh [--app <app> --class <class> [--seed N] [--split dev|heldout]]
#   scripts/worker-gate.sh --full        # forces full gate + additionally runs reverify-v5.sh --full
#   scripts/worker-gate.sh --print-plan  # print resolved narrow/full scope plan JSON and exit 0
#   KOVO_GATE_FULL=1 scripts/worker-gate.sh  # forces full fast gate (disables narrow scoping)
#
# A branch must not be handed off unless this exits 0.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
FULL=0
FORCE_FULL_SCOPE="${KOVO_GATE_FULL:-0}"
PRINT_PLAN=0
SLICE_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full) FULL=1; FORCE_FULL_SCOPE=1; shift;;
    --print-plan) PRINT_PLAN=1; shift;;
    --app|--class|--seed|--split) SLICE_ARGS+=("$1" "${2:?}"); shift 2;;
    -h|--help) sed -n '2,28p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

cd "$ROOT"

# Guard the coordinator's primary checkout on main: a subagent writing here instead of its worktree
# corrupts production runs (seen: a TS parameter property broke `Execution --no-llm`).
# Primary checkouts have a `.git` directory; linked worktrees have a `.git` file.
if [[ "$PRINT_PLAN" -eq 0 && -d "$ROOT/.git" && "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)" == "main" ]]; then
  if [[ "${WORKER_GATE_ALLOW_DIRTY_MAIN:-0}" != "1" && -n "$(git status --porcelain -uno 2>/dev/null | head -1)" ]]; then
    echo "FAIL: main checkout has uncommitted tracked changes; subagents must work in their worktrees (coordinator override: WORKER_GATE_ALLOW_DIRTY_MAIN=1)." >&2
    git status --porcelain -uno | head -5 >&2
    exit 1
  fi
fi

# Classify the diff (fail-closed) to decide full vs narrow scoping.
SCOPE_PLAN_JSON="$(
  ROOT_DIR="$ROOT" \
  FORCE_FULL_SCOPE="$FORCE_FULL_SCOPE" \
  SLICE_COUNT="${#SLICE_ARGS[@]}" \
  KOVO_GATE_BASE_REF="${KOVO_GATE_BASE_REF:-}" \
  KOVO_CONTRACT_BASE="${KOVO_CONTRACT_BASE:-}" \
  node - <<'EOF'
const { execFileSync } = require('node:child_process');
const { existsSync, lstatSync, readFileSync } = require('node:fs');
const { join } = require('node:path');

const root = process.env.ROOT_DIR || process.cwd();
const forceFull = process.env.FORCE_FULL_SCOPE === '1';
const sliceCount = Number(process.env.SLICE_COUNT || '0');
const explicitBase = (process.env.KOVO_GATE_BASE_REF || process.env.KOVO_CONTRACT_BASE || '').trim();

function git(...args) {
  return execFileSync('git', ['-c', 'core.quotepath=false', ...args], {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
}

function gitOk(...args) {
  try {
    return git(...args);
  } catch {
    return null;
  }
}

function fullPlan(reason, extra = {}) {
  return {
    mode: 'full',
    reason,
    baseRef: extra.baseRef ?? null,
    changedFiles: extra.changedFiles ?? [],
    runTsc: true,
    runUnwired: true,
    fastTestMode: 'full',
    scopedTestFiles: [],
  };
}

function classify() {
  if (forceFull) {
    return fullPlan('forced full gate (KOVO_GATE_FULL=1 or --full)');
  }
  if (sliceCount > 0) {
    return fullPlan('targeted slice requested');
  }

  let baseSha = null;
  if (explicitBase) {
    baseSha = gitOk('rev-parse', '--verify', `${explicitBase}^{commit}`);
    if (!baseSha) {
      return fullPlan(`base ref '${explicitBase}' could not be resolved`);
    }
  } else {
    const branch = gitOk('rev-parse', '--abbrev-ref', 'HEAD');
    if (!branch) {
      return fullPlan('not inside a git repository');
    }
    if (branch !== 'main' && gitOk('rev-parse', '--verify', 'main^{commit}')) {
      baseSha = gitOk('merge-base', 'main', 'HEAD');
    } else if (branch !== 'main' && gitOk('rev-parse', '--verify', 'origin/main^{commit}')) {
      baseSha = gitOk('merge-base', 'origin/main', 'HEAD');
    } else if (branch === 'main') {
      baseSha = gitOk('rev-parse', '--verify', 'HEAD^{commit}');
    }
    if (!baseSha) {
      return fullPlan('base commit could not be determined');
    }
  }

  const changedSet = new Set();
  const addLines = (raw) => {
    if (!raw) return;
    for (const line of raw.split(/\r?\n/)) {
      const f = line.trim().replace(/\\/g, '/').replace(/^\.\//, '');
      if (f) changedSet.add(f);
    }
  };

  // Committed diff against base (two-dot when baseSha is ancestor of HEAD, else merge-base diff).
  let committedDiff = null;
  if (gitOk('merge-base', '--is-ancestor', baseSha, 'HEAD') !== null) {
    committedDiff = gitOk('diff', '--name-only', baseSha, 'HEAD');
  } else {
    committedDiff = gitOk('diff', '--name-only', `${baseSha}...HEAD`);
  }
  if (committedDiff === null) {
    return fullPlan('failed to compute git diff against base', { baseRef: baseSha });
  }
  addLines(committedDiff);

  // Staged, unstaged, and untracked non-ignored working-tree changes.
  // Ignore ephemeral directory symlinks (`node_modules`, `worker/node_modules`, `build`)
  // created by `merge-stream.sh`/worktree setups (git's trailing-slash `.gitignore` rules
  // like `/build/` do not match symlinks).
  const EPHEMERAL_WORKTREE_SYMLINKS = new Set(['node_modules', 'worker/node_modules', 'build']);
  const staged = gitOk('diff', '--cached', '--name-only');
  const unstaged = gitOk('diff', '--name-only');
  const untracked = gitOk('ls-files', '--others', '--exclude-standard');
  if (staged === null || unstaged === null || untracked === null) {
    return fullPlan('failed to inspect working tree status', { baseRef: baseSha });
  }
  addLines(staged);
  addLines(unstaged);
  if (untracked) {
    for (const line of untracked.split(/\r?\n/)) {
      const f = line.trim().replace(/\\/g, '/').replace(/^\.\//, '');
      if (!f) continue;
      if (EPHEMERAL_WORKTREE_SYMLINKS.has(f)) {
        try {
          if (lstatSync(join(root, f)).isSymbolicLink()) continue;
        } catch {}
      }
      changedSet.add(f);
    }
  }

  const changedFiles = [...changedSet].sort();
  if (changedFiles.length === 0) {
    return fullPlan('empty changed-file list', { baseRef: baseSha, changedFiles });
  }

  // Load confirmation-kernel manifest if present (fail-closed guard).
  const kernelFiles = new Set();
  const manifestPath = join(root, 'scripts', 'kernel-manifest.json');
  if (existsSync(manifestPath)) {
    try {
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
      if (Array.isArray(manifest?.files)) {
        for (const f of manifest.files) {
          if (typeof f === 'string' && f.trim()) kernelFiles.add(f.trim());
        }
      }
    } catch {
      return fullPlan('failed to parse scripts/kernel-manifest.json', { baseRef: baseSha, changedFiles });
    }
  }

  const DENIED_PREFIXES = [
    'src/',
    'scripts/',
    'worker/',
    'benchmarks/',
    'public/',
    'tests/parity/',
    '.githooks/',
    'drizzle/',
    'local-lab/',
    'dist/',
  ];
  const DENIED_EXACT_OR_RE = [
    /^tsconfig[^/]*\.json$/i,
    /^package[^/]*\.json$/i,
  ];
  const TOP_LEVEL_TEST_RE = /^tests\/[^/]+\.test\.ts$/;
  const CODE_EXT_RE = /\.(?:ts|tsx|mts|cts|js|jsx|mjs|cjs|sh|bash|zsh|sql|py|rb|go|rs|c|cc|cpp|h|hpp)$/i;
  const ALLOWED_NON_CODE_ROOT_RE = /^(?:[^/]+\.md|LICENSE(?:\.[^/]+)?|\.gitignore|\.dockerignore|\.env\.example|\.editorconfig|\.gitattributes|\.nvmrc|\.node-version|CODEOWNERS|CITATION\.cff)$/i;

  const touchedTests = [];
  let hasTsFiles = false;
  let touchesArchitectureDoc = false;

  for (const f of changedFiles) {
    if (kernelFiles.has(f)) {
      return fullPlan(`touches confirmation-kernel file: ${f}`, { baseRef: baseSha, changedFiles });
    }
    if (DENIED_PREFIXES.some((p) => f.startsWith(p))) {
      return fullPlan(`touches code/config path: ${f}`, { baseRef: baseSha, changedFiles });
    }
    if (DENIED_EXACT_OR_RE.some((re) => re.test(f))) {
      return fullPlan(`touches project config file: ${f}`, { baseRef: baseSha, changedFiles });
    }
    if (f.startsWith('tests/')) {
      if (!TOP_LEVEL_TEST_RE.test(f)) {
        return fullPlan(`touches non-test or nested path under tests/: ${f}`, { baseRef: baseSha, changedFiles });
      }
      if (!existsSync(join(root, f))) {
        return fullPlan(`deleted/missing test file requires full inventory check: ${f}`, { baseRef: baseSha, changedFiles });
      }
      touchedTests.push(f);
      hasTsFiles = true;
      continue;
    }

    // Strict allowlist for non-code paths.
    const inAllowedNonCodeDir =
      f.startsWith('.github/') ||
      f.startsWith('docs/') ||
      f.startsWith('plans/');
    const isAllowedNonCode =
      (inAllowedNonCodeDir && !CODE_EXT_RE.test(f)) ||
      ALLOWED_NON_CODE_ROOT_RE.test(f);

    if (!isAllowedNonCode) {
      return fullPlan(`path outside narrow allowlist: ${f}`, { baseRef: baseSha, changedFiles });
    }
    if (f === 'ARCHITECTURE.md') {
      touchesArchitectureDoc = true;
    }
  }

  // Note on check-unwired.ts: it scans `src/`, `scripts/`, `worker/`, `tests/`, `scripts/unwired-baseline.json`,
  // and `ARCHITECTURE.md`; its pass/fail verdict only depends on `src/`, `scripts/`, `worker/`,
  // `scripts/unwired-baseline.json`, and `ARCHITECTURE.md` (tests/** never change cycles, unwired exports, or
  // ARCHITECTURE.md citations). Therefore narrow diffs only need check-unwired.ts when ARCHITECTURE.md changed.
  return {
    mode: 'narrow',
    reason: touchedTests.length > 0
      ? `narrow test-only diff (${touchedTests.length} test file(s), ${changedFiles.length} total file(s))`
      : `narrow non-TS diff (${changedFiles.length} file(s))`,
    baseRef: baseSha,
    changedFiles,
    runTsc: hasTsFiles,
    runUnwired: touchesArchitectureDoc,
    fastTestMode: touchedTests.length > 0 ? 'scoped' : 'skip',
    scopedTestFiles: touchedTests,
  };
}

process.stdout.write(JSON.stringify(classify()));
EOF
)"

if (( PRINT_PLAN == 1 )); then
  printf '%s\n' "$SCOPE_PLAN_JSON"
  exit 0
fi

SCOPE_MODE="full"
SCOPE_REASON="default full gate"
RUN_TSC=1
RUN_UNWIRED=1
FAST_TEST_MODE="full"
CHANGED_FILE_COUNT=0
SCOPED_TEST_FILES=()

eval "$(
  SCOPE_PLAN_JSON="$SCOPE_PLAN_JSON" node - <<'EOF'
const plan = JSON.parse(process.env.SCOPE_PLAN_JSON || '{}');
const sh = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
console.log(`SCOPE_MODE=${sh(plan.mode || 'full')}`);
console.log(`SCOPE_REASON=${sh(plan.reason || 'default full gate')}`);
console.log(`RUN_TSC=${plan.runTsc === false ? 0 : 1}`);
console.log(`RUN_UNWIRED=${plan.runUnwired === false ? 0 : 1}`);
console.log(`FAST_TEST_MODE=${sh(plan.fastTestMode || 'full')}`);
console.log(`CHANGED_FILE_COUNT=${Array.isArray(plan.changedFiles) ? plan.changedFiles.length : 0}`);
const files = Array.isArray(plan.scopedTestFiles) ? plan.scopedTestFiles : [];
console.log(`SCOPED_TEST_FILES=(${files.map(sh).join(' ')})`);
EOF
)"

gate_t0="$(date +%s)"
fail=0
step() { printf '\n== %s\n' "$1"; }
run() { step "$1"; shift; if "$@"; then :; else echo "FAILED: $1" >&2; fail=1; fi; }

step "gate scope"
echo "mode=${SCOPE_MODE} (${SCOPE_REASON})"

# 1. Fast static lints & structural wiring invariants (<2s total).
#    Always run even for narrow diffs so git/trailer/ratchet invariants remain 100% enforced.
run "v8 anti-contamination lint" node scripts/check-v8-contamination.ts
run "fixture-contamination ratchet lint" node scripts/check-fixture-contamination.ts
run "direct DB writes ratchet" node scripts/check-direct-db-writes.ts
run "run-scoped state ratchet" node scripts/check-run-scoped-state.ts
run "clone & safety-primitive dedup ratchet" node scripts/check-clones.ts
run "function growth & file size baseline ratchet" node scripts/check-function-growth.ts --baseline
run "test-shape source-text regex ratchet" node scripts/check-test-shape.ts
run "security-optional & test-seam boundary ratchet" node scripts/check-security-optional.ts
run "empty-catch lifecycle settlement ratchet" node scripts/check-empty-catch.ts
run "exhaustive union switch lint" node scripts/check-exhaustive.ts
CONTRACT_BASE="${KOVO_CONTRACT_BASE:-${KOVO_GATE_BASE_REF:-}}"
if [[ -n "$CONTRACT_BASE" ]]; then
  run "contract-change trailer lint" node scripts/check-contract-change.ts --base "$CONTRACT_BASE"
  run "verdict-flip & gate-repair guard" node scripts/check-verdict-flip.ts --base "$CONTRACT_BASE"
  run "fix provenance trailer guard" node scripts/check-fix-provenance.ts --base "$CONTRACT_BASE"
else
  run "contract-change trailer lint" node scripts/check-contract-change.ts
  run "verdict-flip & gate-repair guard" node scripts/check-verdict-flip.ts
  if [[ "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)" != "main" ]] && git rev-parse --verify main^{commit} >/dev/null 2>&1; then
    run "fix provenance trailer guard" node scripts/check-fix-provenance.ts --base main
  else
    run "fix provenance trailer guard" node scripts/check-fix-provenance.ts --head
  fi
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

# 2. Run typecheck (seeded incremental `tsc`), unwired-export ratchet (`check-unwired.ts`),
#    and fast behavioral suites in parallel according to the resolved scope plan
#    (stays <60s; never runs Playwright/Docker/dogfood).
GATE_LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kovo-worker-gate-XXXXXX")"
trap 'rm -rf "$GATE_LOG_DIR"' EXIT

TSC_CACHE_DIR="${KOVO_TSC_CACHE_DIR:-${HOME}/.cache/kovo}"
TSC_CACHE_FILE="${KOVO_TSC_CACHE_FILE:-${TSC_CACHE_DIR}/main.tsbuildinfo}"
TSC_LOCAL_BUILDINFO="${ROOT}/.kovo/tsc.tsbuildinfo"
TSC_INCREMENTAL="${KOVO_TSC_INCREMENTAL:-1}"
TSC_SEEDED=0

run_typecheck_incremental() {
  if [[ "$TSC_INCREMENTAL" == "0" ]]; then
    npm run check
    return $?
  fi

  mkdir -p "${ROOT}/.kovo"

  # Validate any existing local .tsbuildinfo and seed from host cache when absent or older.
  # Rebases symlinked node_modules/ relative prefixes in `fileNames` so cross-worktree seeds
  # achieve full incremental cache reuse even when worktrees sit at different directory depths.
  if [[ -f "$TSC_CACHE_FILE" ]] && [[ ! -f "$TSC_LOCAL_BUILDINFO" || "$TSC_CACHE_FILE" -nt "$TSC_LOCAL_BUILDINFO" ]]; then
    node - "$ROOT" "$TSC_CACHE_FILE" "$TSC_LOCAL_BUILDINFO" <<'EOF' 2>/dev/null || rm -f "$TSC_LOCAL_BUILDINFO"
const fs = require('node:fs');
const path = require('node:path');

const [rootDir, seedFile, localFile] = process.argv.slice(2);
const raw = fs.readFileSync(seedFile, 'utf8');
const data = JSON.parse(raw);
if (!data || typeof data !== 'object' || !Array.isArray(data.fileNames)) {
  process.exit(1);
}

const localDir = path.dirname(localFile);
const toPosix = (p) => p.split(path.sep).join('/');
const nmPath = path.join(rootDir, 'node_modules');
const wnmPath = path.join(rootDir, 'worker', 'node_modules');
const nmRel = fs.existsSync(nmPath) ? toPosix(path.relative(localDir, fs.realpathSync(nmPath))) : null;
const wnmRel = fs.existsSync(wnmPath) ? toPosix(path.relative(localDir, fs.realpathSync(wnmPath))) : null;

if (nmRel || wnmRel) {
  data.fileNames = data.fileNames.map((entry) => {
    if (typeof entry !== 'string') return entry;
    if (wnmRel) {
      const wm = entry.match(/^(?:\.\.\/)+.*?(?:^|\/)worker\/node_modules(\/.*)$/);
      if (wm) return `${wnmRel}${wm[1]}`;
    }
    if (nmRel) {
      const nm = entry.match(/^(?:\.\.\/)+.*?(?:^|\/)node_modules(\/.*)$/);
      if (nm) return `${nmRel}${nm[1]}`;
    }
    return entry;
  });
}

const tmpFile = `${localFile}.tmp.${process.pid}`;
fs.writeFileSync(tmpFile, JSON.stringify(data));
fs.renameSync(tmpFile, localFile);
EOF
  elif [[ -f "$TSC_LOCAL_BUILDINFO" ]]; then
    # Discard corrupt local buildinfo before running tsc so it rebuilds cleanly.
    node -e '
      const fs = require("node:fs");
      const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      if (!d || typeof d !== "object" || !Array.isArray(d.fileNames)) process.exit(1);
    ' "$TSC_LOCAL_BUILDINFO" 2>/dev/null || rm -f "$TSC_LOCAL_BUILDINFO"
  fi

  local tsc_bin="${ROOT}/node_modules/.bin/tsc"
  if [[ -x "$tsc_bin" ]]; then
    "$tsc_bin" --noEmit --incremental --tsBuildInfoFile .kovo/tsc.tsbuildinfo
  else
    npx tsc --noEmit --incremental --tsBuildInfoFile .kovo/tsc.tsbuildinfo
  fi
}

tsc_pid=""
unwired_pid=""
fast_pid=""
tsc_rc=0
unwired_rc=0
fast_rc=0

if (( RUN_TSC == 1 )); then
  if [[ "$TSC_INCREMENTAL" != "0" && -f "$TSC_CACHE_FILE" ]] && [[ ! -f "$TSC_LOCAL_BUILDINFO" || "$TSC_CACHE_FILE" -nt "$TSC_LOCAL_BUILDINFO" ]]; then
    TSC_SEEDED=1
  fi
  run_typecheck_incremental >"$GATE_LOG_DIR/tsc.log" 2>&1 &
  tsc_pid=$!
fi

if (( RUN_UNWIRED == 1 )); then
  node scripts/check-unwired.ts >"$GATE_LOG_DIR/unwired.log" 2>&1 &
  unwired_pid=$!
fi

if [[ "$FAST_TEST_MODE" == "full" ]]; then
  bash scripts/run-fast-tests.sh --suites-only --quarantine tests/QUARANTINE.json >"$GATE_LOG_DIR/fast.log" 2>&1 &
  fast_pid=$!
elif [[ "$FAST_TEST_MODE" == "scoped" && ${#SCOPED_TEST_FILES[@]} -gt 0 ]]; then
  scoped_flags=()
  for tf in "${SCOPED_TEST_FILES[@]}"; do
    scoped_flags+=(--file "$tf")
  done
  bash scripts/run-fast-tests.sh --suites-only --quarantine tests/QUARANTINE.json "${scoped_flags[@]}" >"$GATE_LOG_DIR/fast.log" 2>&1 &
  fast_pid=$!
fi

if [[ -n "$tsc_pid" ]]; then
  wait "$tsc_pid"
  tsc_rc=$?
fi
if [[ -n "$unwired_pid" ]]; then
  wait "$unwired_pid"
  unwired_rc=$?
fi
if [[ -n "$fast_pid" ]]; then
  wait "$fast_pid"
  fast_rc=$?
fi

step "typecheck"
if (( RUN_TSC == 0 )); then
  echo "typecheck: SKIPPED (narrow non-TS diff: ${CHANGED_FILE_COUNT} files)"
else
  cat "$GATE_LOG_DIR/tsc.log"
  if (( tsc_rc != 0 )); then
    echo "FAILED: typecheck (tsc --noEmit --incremental)" >&2
    fail=1
  else
    if [[ "$TSC_INCREMENTAL" != "0" ]]; then
      echo "PASS: typecheck (incremental${TSC_SEEDED:+, seeded=${TSC_SEEDED}})"
      # Atomically refresh host seed cache when running cleanly on main.
      if [[ -f "$TSC_LOCAL_BUILDINFO" && "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)" == "main" ]]; then
        if [[ -z "$(git status --porcelain --untracked-files=no 2>/dev/null | head -1)" ]]; then
          if mkdir -p "$(dirname "$TSC_CACHE_FILE")" 2>/dev/null; then
            tmp_cache="${TSC_CACHE_FILE}.tmp.$$"
            if cp "$TSC_LOCAL_BUILDINFO" "$tmp_cache" 2>/dev/null && mv -f "$tmp_cache" "$TSC_CACHE_FILE" 2>/dev/null; then
              :
            else
              rm -f "$tmp_cache" 2>/dev/null || true
            fi
          fi
        fi
      fi
    else
      echo "PASS: typecheck"
    fi
  fi
fi

step "unwired-export / cycle / doc-citation ratchet"
if (( RUN_UNWIRED == 0 )); then
  echo "unwired-export ratchet: SKIPPED (narrow diff does not touch src/, scripts/, worker/, or ARCHITECTURE.md)"
else
  cat "$GATE_LOG_DIR/unwired.log"
  if (( unwired_rc != 0 )); then
    echo "FAILED: unwired-export ratchet (node scripts/check-unwired.ts)" >&2
    fail=1
  fi
fi

step "fast behavioral suites + quarantine/orphan gate"
if [[ "$FAST_TEST_MODE" == "skip" ]]; then
  echo "fast-tests: SKIPPED (narrow non-code diff)"
else
  cat "$GATE_LOG_DIR/fast.log"
  if (( fast_rc != 0 )); then
    echo "FAILED: fast behavioral suites / quarantine / orphan check" >&2
    fail=1
  fi
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
