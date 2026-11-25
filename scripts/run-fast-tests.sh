#!/usr/bin/env bash
# Unified fast zero-LLM verification gate + parallel test suite runner.
#
# Runs:
#   1. npx tsc --noEmit
#   2. bash scripts/worker-gate.sh
#   3. All fast zero-LLM tests/*.test.ts suites in parallel via `node --test`,
#      excluding live-LLM, Docker-only, and Playwright-browser-only suites.
#
# Usage:
#   bash scripts/run-fast-tests.sh
#   KOVO_FAST_TEST_JOBS=8 bash scripts/run-fast-tests.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -d node_modules ]]; then
  echo "FAIL: node_modules missing — run 'npm ci' (or symlink main checkout's node_modules) first." >&2
  exit 2
fi

export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=2048}"

# Clean documented exclude list for tests/*.test.ts (exact relative filenames).
# Note: Playwright browser specs (tests/*.spec.ts) are already excluded by the *.test.ts glob.
EXCLUDE_TESTS=(
  # Live-LLM / Docker-daemon / real kovo-worker:v4 container suites:
  "tests/boundaries.test.ts"                    # requires Docker daemon + live-LLM env checks
  "tests/v2-upgrades.test.ts"                   # spawns real Docker worker container for source audit
  "tests/v3-boundaries.test.ts"                 # spawns real Docker worker & LabRunner containers
  "tests/v4-boundaries.test.ts"                 # spawns real Docker worker & multi-service LabRunner
  "tests/v4-e2e-tiers.test.ts"                  # 322-test full Docker + Playwright E2E matrix (>60s)
  "tests/v4-m1-schema-verify-routing.test.ts"   # M1.7 runs real Docker LinuxWorkerBackend
  "tests/v4-m3-worker-sast-templates.test.ts"   # runs real kovo-worker:v4 SAST container tests
  "tests/v4-m5-lab-iast-ui.test.ts"             # M5-4 runs real Docker multi-service LabRunner
  "tests/v5-gate-worker-lifecycle.test.ts"      # Docker-gated container lifecycle/reclaim tests
  "tests/v5-m4-sast-templates-patch.test.ts"    # Docker-gated kovo-worker:v4 SAST template tests
  "tests/v6-verify.test.ts"                     # Docker-gated kovo-worker:v4 verification tests

  # Playwright-browser-only suites:
  "tests/v7-realism1-spa.test.ts"               # launches real Playwright Chromium ScopedBrowser (>60s)
)

gate_fail=0

echo "== 1/3 Typecheck (npx tsc --noEmit)"
if npx tsc --noEmit; then
  echo "PASS: tsc --noEmit"
else
  echo "FAIL: tsc --noEmit" >&2
  gate_fail=1
fi

echo
echo "== 2/3 Worker gate (bash scripts/worker-gate.sh)"
if bash scripts/worker-gate.sh; then
  echo "PASS: worker-gate.sh"
else
  echo "FAIL: worker-gate.sh" >&2
  gate_fail=1
fi

echo
echo "== 3/3 Fast zero-LLM unit suites (node --test in parallel)"
JOBS="${KOVO_FAST_TEST_JOBS:-$(nproc 2>/dev/null || echo 8)}"
if (( JOBS > 12 )); then JOBS=12; fi
if (( JOBS < 1 )); then JOBS=1; fi

EXCLUDED_JOINED="$(printf '%s\n' "${EXCLUDE_TESTS[@]}")"
export EXCLUDED_JOINED FAST_TEST_JOBS="$JOBS"

node --input-type=module <<'EOF'
import { readdirSync } from 'node:fs'
import { execFile } from 'node:child_process'

const excluded = new Set(
  (process.env.EXCLUDED_JOINED || '')
    .split(/\r?\n/)
    .map(s => s.trim())
    .filter(Boolean),
)
const allFiles = readdirSync('tests')
  .filter(f => f.endsWith('.test.ts'))
  .map(f => `tests/${f}`)
  .sort()

const runFiles = allFiles.filter(f => !excluded.has(f))
const skippedByExclude = allFiles.filter(f => excluded.has(f))
const jobs = Math.max(1, Number(process.env.FAST_TEST_JOBS) || 8)

console.log(
  `Discovered ${allFiles.length} test files (${runFiles.length} fast zero-LLM, ${skippedByExclude.length} excluded; concurrency=${jobs})`,
)

const tStart = Date.now()
let idx = 0
const results = []

function runOne(file) {
  const t0 = Date.now()
  return new Promise(resolve => {
    execFile(
      process.execPath,
      ['--test', file],
      { timeout: 120_000, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const ms = Date.now() - t0
        const out = `${stdout || ''}\n${stderr || ''}`
        const tests = Number((out.match(/^ℹ tests (\d+)/m) || [])[1] || 0)
        const pass = Number((out.match(/^ℹ pass (\d+)/m) || [])[1] || 0)
        const fail = Number((out.match(/^ℹ fail (\d+)/m) || [])[1] || 0)
        const skipped = Number((out.match(/^ℹ skipped (\d+)/m) || [])[1] || 0)
        let reason = ''
        if (err) {
          if (err.killed) {
            reason = 'TIMEOUT (>120s)'
          } else {
            const lines = out
              .split(/\r?\n/)
              .map(l => l.trim())
              .filter(l => /^(✖|AssertionError|Error:|TypeError:|ReferenceError:|ERR_)/.test(l) && !/'test failed'/.test(l))
            reason = (lines[0] || `exit ${err.code}`).slice(0, 140)
          }
        }
        resolve({ file, ok: !err && fail === 0, ms, tests, pass, fail, skipped, reason })
      },
    )
  })
}

async function worker() {
  while (idx < runFiles.length) {
    const file = runFiles[idx++]
    results.push(await runOne(file))
  }
}

await Promise.all(Array.from({ length: jobs }, worker))
results.sort((a, b) => a.file.localeCompare(b.file))

const wallSec = ((Date.now() - tStart) / 1000).toFixed(1)
const passedFiles = results.filter(r => r.ok)
const failedFiles = results.filter(r => !r.ok)
const totalTests = results.reduce((n, r) => n + r.tests, 0)
const totalPass = results.reduce((n, r) => n + r.pass, 0)
const totalFail = results.reduce((n, r) => n + r.fail, 0)
const totalSkip = results.reduce((n, r) => n + r.skipped, 0)

console.log(
  `\nFast-test summary (${wallSec}s): ${passedFiles.length}/${results.length} files passed, ${failedFiles.length} failed` +
    ` (${totalPass}/${totalTests} cases passed, ${totalFail} failed, ${totalSkip} skipped)`,
)

if (failedFiles.length > 0) {
  console.log('\nFailing test files:')
  for (const r of failedFiles) {
    console.log(`  FAIL ${r.file} (${r.fail}/${r.tests} failed, ${r.ms}ms) — ${r.reason}`)
  }
  process.exitCode = 1
}
EOF
suite_rc=$?

if [[ $gate_fail -ne 0 || $suite_rc -ne 0 ]]; then
  echo
  echo "run-fast-tests: FAIL"
  exit 1
fi

echo
echo "run-fast-tests: PASS"
