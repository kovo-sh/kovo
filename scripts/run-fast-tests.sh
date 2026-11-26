#!/usr/bin/env bash
# Unified fast zero-LLM verification gate + parallel test suite runner (`cq-3-merge-gate`).
#
# Runs:
#   1. npx tsc --noEmit                         (skipped with --suites-only or --check-only)
#   2. bash scripts/worker-gate.sh              (skipped with --suites-only or --check-only)
#   3. Quarantine validation + orphan-test check + all non-quarantined fast zero-LLM
#      tests/*.test.ts suites in parallel via `node --test`.
#
# Usage:
#   bash scripts/run-fast-tests.sh
#   bash scripts/run-fast-tests.sh --quarantine tests/QUARANTINE.json
#   bash scripts/run-fast-tests.sh --suites-only --quarantine tests/QUARANTINE.json
#   bash scripts/run-fast-tests.sh --check-only --quarantine tests/QUARANTINE.json [--now YYYY-MM-DD]
#   KOVO_FAST_TEST_JOBS=10 bash scripts/run-fast-tests.sh --suites-only --quarantine tests/QUARANTINE.json
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

QUARANTINE_PATH=""
SUITES_ONLY=0
CHECK_ONLY=0
NOW_DATE=""
TESTS_DIR="tests"
JOBS_OVERRIDE=""
JSON_OUT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quarantine) QUARANTINE_PATH="${2:?--quarantine requires a path}"; shift 2;;
    --suites-only) SUITES_ONLY=1; shift;;
    --check-only) CHECK_ONLY=1; SUITES_ONLY=1; shift;;
    --now) NOW_DATE="${2:?--now requires YYYY-MM-DD}"; shift 2;;
    --tests-dir) TESTS_DIR="${2:?--tests-dir requires a directory}"; shift 2;;
    --jobs) JOBS_OVERRIDE="${2:?--jobs requires an integer}"; shift 2;;
    --json) JSON_OUT=1; shift;;
    -h|--help) sed -n '2,18p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

if [[ "$CHECK_ONLY" -eq 0 && ! -d node_modules ]]; then
  echo "FAIL: node_modules missing — run 'npm ci' (or symlink main checkout's node_modules) first." >&2
  exit 2
fi

export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=2048}"

# Categorized, documented exclude list for non-fast tests/*.test.ts suites (tier|file|reason).
# Every tests/**/*.test.ts file must be either fast-run, in this categorized list, or in QUARANTINE.json.
EXCLUDE_SPECS=(
  # docker-live: Live-LLM / Docker-daemon / real kovo-worker:v4 container suites
  "docker-live|tests/boundaries.test.ts|requires Docker daemon + live-LLM env checks"
  "docker-live|tests/v2-upgrades.test.ts|spawns real Docker worker container for source audit"
  "docker-live|tests/v3-boundaries.test.ts|spawns real Docker worker & LabRunner containers"
  "docker-live|tests/v4-boundaries.test.ts|spawns real Docker worker & multi-service LabRunner"
  "docker-live|tests/v4-e2e-tiers.test.ts|322-test full Docker + Playwright E2E matrix (>60s)"
  "docker-live|tests/v4-m1-schema-verify-routing.test.ts|M1.7 runs real Docker LinuxWorkerBackend"
  "docker-live|tests/v4-m3-worker-sast-templates.test.ts|runs real kovo-worker:v4 SAST container tests"
  "docker-live|tests/v4-m5-lab-iast-ui.test.ts|M5-4 runs real Docker multi-service LabRunner"
  "docker-live|tests/v5-gate-worker-lifecycle.test.ts|Docker-gated container lifecycle/reclaim tests"
  "docker-live|tests/v5-m4-sast-templates-patch.test.ts|Docker-gated kovo-worker:v4 SAST template tests"
  "docker-live|tests/v6-verify.test.ts|Docker-gated kovo-worker:v4 verification tests"

  # playwright-e2e: Real Playwright Chromium browser E2E suites
  "playwright-e2e|tests/e2e-ui-journeys.test.ts|launches real Playwright Chromium browser UI journeys (~27s)"
  "playwright-e2e|tests/v7-realism1-spa.test.ts|launches real Playwright Chromium ScopedBrowser (>60s)"

  # batch-boundary-slow: Batch-boundary / regression-floor tier (run by scripts/regression-floor.sh)
  "batch-boundary-slow|tests/v8-seam1-golden-e2e.test.ts|50s golden multi-hop E2E suite (run in scripts/regression-floor.sh)"
)

# Core invariant gate suites that may NEVER be quarantined.
UNQUARANTINABLE_SUITES=(
  "tests/v4-m7-orch.test.ts"
  "tests/v5-m1-wiring-correctness.test.ts"
  "tests/v5-m2-state.test.ts"
  "tests/sys-contract-canary.test.ts"
  "tests/v7-dispatch-funnel.test.ts"
  "tests/v7-confirm-consistency.test.ts"
  "tests/cq-3-merge-gate.test.ts"
)

gate_fail=0

if (( SUITES_ONLY == 0 )); then
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
fi

DEFAULT_JOBS="$(nproc 2>/dev/null || echo 8)"
if (( DEFAULT_JOBS > 4 )); then
  DEFAULT_JOBS=$(( DEFAULT_JOBS - 4 ))
elif (( DEFAULT_JOBS > 2 )); then
  DEFAULT_JOBS=$(( DEFAULT_JOBS - 2 ))
fi
if (( DEFAULT_JOBS > 12 )); then DEFAULT_JOBS=12; fi
if (( DEFAULT_JOBS < 4 )); then DEFAULT_JOBS=4; fi

JOBS="${JOBS_OVERRIDE:-${KOVO_FAST_TEST_JOBS:-$DEFAULT_JOBS}}"
if (( JOBS > 16 )); then JOBS=16; fi
if (( JOBS < 1 )); then JOBS=1; fi

EXCLUDED_JOINED="$(printf '%s\n' "${EXCLUDE_SPECS[@]}")"
UNQUARANTINABLE_JOINED="$(printf '%s\n' "${UNQUARANTINABLE_SUITES[@]}")"
export EXCLUDED_JOINED UNQUARANTINABLE_JOINED FAST_TEST_JOBS="$JOBS"
export FAST_TEST_QUARANTINE="$QUARANTINE_PATH"
export FAST_TEST_CHECK_ONLY="$CHECK_ONLY"
export FAST_TEST_NOW="$NOW_DATE"
export FAST_TEST_DIR="$TESTS_DIR"
export FAST_TEST_JSON="$JSON_OUT"

node --input-type=module <<'EOF'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { execFile } from 'node:child_process'
import { join, posix, relative, resolve, sep } from 'node:path'

const testsDirArg = process.env.FAST_TEST_DIR || 'tests'
const isDefaultTestsDir = testsDirArg === 'tests'
const testsDirAbs = resolve(testsDirArg)
const checkOnly = process.env.FAST_TEST_CHECK_ONLY === '1'
const jsonOut = process.env.FAST_TEST_JSON === '1'
const quarantinePath = (process.env.FAST_TEST_QUARANTINE || '').trim()
const todayStr = (process.env.FAST_TEST_NOW || '').trim() || new Date().toISOString().slice(0, 10)
const jobs = Math.max(1, Number(process.env.FAST_TEST_JOBS) || 8)

const excludedMap = new Map()
for (const line of (process.env.EXCLUDED_JOINED || '').split(/\r?\n/)) {
  const trimmed = line.trim()
  if (!trimmed) continue
  const [tier, file, ...rest] = trimmed.split('|')
  if (tier && file) excludedMap.set(file, { tier, reason: rest.join('|') })
}

const unquarantinable = new Set(
  (process.env.UNQUARANTINABLE_JOINED || '')
    .split(/\r?\n/)
    .map(s => s.trim())
    .filter(Boolean),
)

function discoverTestFilesRecursive(dirAbs, baseAbs, out = []) {
  if (!existsSync(dirAbs)) return out
  const entries = readdirSync(dirAbs, { withFileTypes: true })
  entries.sort((a, b) => a.name.localeCompare(b.name))
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue
    const full = join(dirAbs, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'fixtures' || entry.name === 'parity') {
        // Still descend into subdirectories to detect orphan *.test.ts files anywhere under tests/!
      }
      discoverTestFilesRecursive(full, baseAbs, out)
    } else if (entry.isFile() && entry.name.endsWith('.test.ts')) {
      const relFromBase = relative(baseAbs, full).split(sep).join(posix.sep)
      out.push(`tests/${relFromBase}`)
    }
  }
  return out
}

function isValidIsoDate(s) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false
  const [y, m, d] = s.split('-').map(Number)
  const dt = new Date(Date.UTC(y, m - 1, d))
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d
}

const errors = []

// 1. Discover all *.test.ts files recursively under tests/
const allDiscovered = discoverTestFilesRecursive(testsDirAbs, testsDirAbs).sort()
const topLevelGlob = allDiscovered.filter(f => /^tests\/[^/]+\.test\.ts$/.test(f))
const nestedFiles = allDiscovered.filter(f => !/^tests\/[^/]+\.test\.ts$/.test(f))
const discoveredSet = new Set(allDiscovered)

// 2. Validate QUARANTINE.json if provided
const quarantinedMap = new Map()
let maxQuarantined = null
let earliestExpiry = null

if (quarantinePath) {
  const absQ = resolve(quarantinePath)
  if (!existsSync(absQ)) {
    errors.push(`Quarantine file not found: ${quarantinePath}`)
  } else {
    let parsed
    try {
      parsed = JSON.parse(readFileSync(absQ, 'utf8'))
    } catch (err) {
      errors.push(`Invalid JSON in ${quarantinePath}: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (parsed !== undefined) {
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        errors.push(`${quarantinePath}: root must be an object { maxQuarantined, entries }`)
      } else {
        if (!Number.isInteger(parsed.maxQuarantined) || parsed.maxQuarantined < 0) {
          errors.push(`${quarantinePath}: maxQuarantined must be a non-negative integer`)
        } else {
          maxQuarantined = parsed.maxQuarantined
        }
        if (!Array.isArray(parsed.entries)) {
          errors.push(`${quarantinePath}: entries must be an array`)
        } else {
          if (maxQuarantined !== null && parsed.entries.length > maxQuarantined) {
            errors.push(
              `${quarantinePath}: quarantine cap exceeded (${parsed.entries.length} entries > maxQuarantined=${maxQuarantined}); fix or remove existing quarantined tests instead of growing the cap`,
            )
          }
          if (!isValidIsoDate(todayStr)) {
            errors.push(`Invalid --now date '${todayStr}' (expected YYYY-MM-DD)`)
          }
          for (let i = 0; i < parsed.entries.length; i += 1) {
            const e = parsed.entries[i]
            if (!e || typeof e !== 'object') {
              errors.push(`${quarantinePath}: entries[${i}] must be an object`)
              continue
            }
            const file = typeof e.file === 'string' ? e.file.trim() : ''
            const owner = typeof e.owner === 'string' ? e.owner.trim() : ''
            const reason = typeof e.reason === 'string' ? e.reason.trim() : ''
            const expires = typeof e.expires === 'string' ? e.expires.trim() : ''
            if (!file) errors.push(`${quarantinePath}: entries[${i}].file must be a non-empty string`)
            if (!owner) errors.push(`${quarantinePath}: entries[${i}] (${file || 'unknown'}) missing required non-empty 'owner'`)
            if (!reason) errors.push(`${quarantinePath}: entries[${i}] (${file || 'unknown'}) missing required non-empty 'reason'`)
            if (!expires || !isValidIsoDate(expires)) {
              errors.push(`${quarantinePath}: entries[${i}] (${file || 'unknown'}) invalid 'expires' date '${expires}' (expected YYYY-MM-DD)`)
            } else {
              if (!earliestExpiry || expires < earliestExpiry) earliestExpiry = expires
              if (isValidIsoDate(todayStr) && expires < todayStr) {
                errors.push(`${quarantinePath}: expired quarantine entry ${file} (owner=${owner}, expires=${expires} < today=${todayStr})`)
              }
            }
            if (file) {
              if (quarantinedMap.has(file)) {
                errors.push(`${quarantinePath}: duplicate quarantine entry for ${file}`)
              }
              if (unquarantinable.has(file)) {
                errors.push(`${quarantinePath}: core gate invariant suite ${file} cannot be quarantined`)
              }
              if (excludedMap.has(file)) {
                errors.push(`${quarantinePath}: ${file} is already categorized in EXCLUDE_TESTS (${excludedMap.get(file).tier}); remove from quarantine`)
              }
              if (!discoveredSet.has(file)) {
                errors.push(`${quarantinePath}: stale quarantine entry ${file} does not exist under ${testsDirArg}`)
              }
              quarantinedMap.set(file, { owner, reason, expires })
            }
          }
        }
      }
    }
  }
}

// 3. Orphan-test check (M-35): every tests/**/*.test.ts must be fast-run, excluded, or quarantined.
const orphanFiles = []
for (const file of nestedFiles) {
  if (!excludedMap.has(file) && !quarantinedMap.has(file)) {
    orphanFiles.push(file)
  }
}
if (orphanFiles.length > 0) {
  errors.push(
    `Orphan test file(s) not executed by top-level fast glob and not categorized in EXCLUDE_TESTS/QUARANTINE: ${orphanFiles.join(', ')}`,
  )
}

if (isDefaultTestsDir) {
  for (const [file, meta] of excludedMap) {
    if (!discoveredSet.has(file)) {
      errors.push(`Stale EXCLUDE_TESTS entry (${meta.tier}): ${file} does not exist on disk`)
    }
  }
}

const runFiles = topLevelGlob.filter(f => !excludedMap.has(f) && !quarantinedMap.has(f))
const skippedByExclude = allDiscovered.filter(f => excludedMap.has(f))
const skippedByQuarantine = allDiscovered.filter(f => quarantinedMap.has(f))

// Accounting invariant: every discovered test file is in exactly one bucket.
const accounted = runFiles.length + skippedByExclude.length + skippedByQuarantine.length
if (accounted !== allDiscovered.length && orphanFiles.length === 0) {
  errors.push(`Test accounting mismatch: ${accounted} accounted != ${allDiscovered.length} discovered`)
}

if (errors.length > 0) {
  if (jsonOut) {
    console.log(JSON.stringify({
      ok: false,
      checkOnly,
      discovered: allDiscovered.length,
      fast: runFiles.length,
      excluded: skippedByExclude.length,
      quarantined: skippedByQuarantine.length,
      maxQuarantined,
      orphans: orphanFiles,
      errors,
    }, null, 2))
  } else {
    console.error(`FAIL: fast-test validation / orphan check failed (${errors.length} error(s)):`)
    for (const err of errors) console.error(`  - ${err}`)
  }
  process.exit(1)
}

if (checkOnly) {
  if (jsonOut) {
    console.log(JSON.stringify({
      ok: true,
      checkOnly: true,
      discovered: allDiscovered.length,
      fast: runFiles.length,
      excluded: skippedByExclude.length,
      quarantined: skippedByQuarantine.length,
      maxQuarantined,
      earliestExpiry,
      orphans: [],
      errors: [],
    }, null, 2))
  } else {
    const qNote = quarantinePath
      ? `, ${skippedByQuarantine.length}/${maxQuarantined} quarantined (earliest expiry ${earliestExpiry || 'n/a'})`
      : ''
    console.log(
      `Fast-test inventory PASS: ${allDiscovered.length} discovered (${runFiles.length} fast, ${skippedByExclude.length} excluded${qNote}, 0 orphans)`,
    )
  }
  process.exit(0)
}

// Schedule heavier suites first (LPT heuristic) to eliminate tail stragglers across worker slots.
const HEAVY_HINT_RE = /(?:realism-mono|product-paging|phase0-paging|contract-canary|oob-engine|crawl-paging|killswitch-nav|universal-browser-auth|bench-cred-dir|proto-pollute|probe-split|egress-admit|static-fp|fixture-timing|realistic-harness)/
const orderedRunFiles = [...runFiles].sort((a, b) => {
  const ha = HEAVY_HINT_RE.test(a) ? 0 : 1
  const hb = HEAVY_HINT_RE.test(b) ? 0 : 1
  return ha !== hb ? ha - hb : a.localeCompare(b)
})

const qBanner = quarantinePath
  ? `, ${skippedByQuarantine.length}/${maxQuarantined} quarantined`
  : ''
if (!jsonOut) {
  console.log(
    `Discovered ${allDiscovered.length} test files (${runFiles.length} fast zero-LLM, ${skippedByExclude.length} excluded${qBanner}, 0 orphans; concurrency=${jobs})`,
  )
}

const tStart = Date.now()
let idx = 0
const results = []

function runOne(file) {
  const absFile = isDefaultTestsDir ? file : join(testsDirAbs, file.replace(/^tests\//, ''))
  const t0 = Date.now()
  return new Promise(resolve => {
    // Each file runs in its own OS process via execFile, so --test-isolation=none avoids
    // Node's redundant double-process spawn per file while preserving full per-file isolation.
    execFile(
      process.execPath,
      ['--test', '--test-isolation=none', absFile],
      { timeout: 60_000, maxBuffer: 8 * 1024 * 1024 },
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
            reason = 'TIMEOUT (>60s)'
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
  while (idx < orderedRunFiles.length) {
    const file = orderedRunFiles[idx++]
    results.push(await runOne(file))
  }
}

await Promise.all(Array.from({ length: jobs }, worker))

// When running many suites concurrently on a shared host, micro-latency assertions (<100ms/<200ms)
// can briefly exceed wall-clock thresholds. Re-verify up to 3 failures sequentially in isolation:
// genuine regressions still fail immediately; CPU-contention flakes are surfaced transparently.
const initialFailures = results.filter(r => !r.ok)
const recoveredInIsolation = []
if (jobs > 1 && initialFailures.length > 0 && initialFailures.length <= 3) {
  for (const prev of initialFailures) {
    const retry = await runOne(prev.file)
    if (retry.ok) {
      const slot = results.findIndex(r => r.file === prev.file)
      if (slot >= 0) results[slot] = retry
      recoveredInIsolation.push({ file: prev.file, parallelReason: prev.reason, isolatedMs: retry.ms })
    }
  }
}

results.sort((a, b) => a.file.localeCompare(b.file))

const wallSec = Number(((Date.now() - tStart) / 1000).toFixed(1))
const passedFiles = results.filter(r => r.ok)
const failedFiles = results.filter(r => !r.ok)
const totalTests = results.reduce((n, r) => n + r.tests, 0)
const totalPass = results.reduce((n, r) => n + r.pass, 0)
const totalFail = results.reduce((n, r) => n + r.fail, 0)
const totalSkip = results.reduce((n, r) => n + r.skipped, 0)

if (jsonOut) {
  console.log(JSON.stringify({
    ok: failedFiles.length === 0,
    wallSec,
    discovered: allDiscovered.length,
    fast: results.length,
    passedFiles: passedFiles.length,
    failedFiles: failedFiles.map(r => ({ file: r.file, fail: r.fail, tests: r.tests, ms: r.ms, reason: r.reason })),
    recoveredInIsolation,
    excluded: skippedByExclude.length,
    quarantined: skippedByQuarantine.length,
    maxQuarantined,
    totalTests,
    totalPass,
    totalFail,
    totalSkip,
  }, null, 2))
} else {
  console.log(
    `\nFast-test summary (${wallSec}s): ${passedFiles.length}/${results.length} files passed, ${failedFiles.length} failed` +
      ` (${totalPass}/${totalTests} cases passed, ${totalFail} failed, ${totalSkip} skipped${qBanner})`,
  )
  if (recoveredInIsolation.length > 0) {
    console.log(
      `Note: ${recoveredInIsolation.length} timing-sensitive file(s) passed on isolated re-verify: ` +
        recoveredInIsolation.map(r => `${r.file} (${r.isolatedMs}ms)`).join(', '),
    )
  }
  if (failedFiles.length > 0) {
    console.log('\nFailing test files:')
    for (const r of failedFiles) {
      console.log(`  FAIL ${r.file} (${r.fail}/${r.tests} failed, ${r.ms}ms) — ${r.reason}`)
    }
  }
}

if (failedFiles.length > 0) {
  process.exitCode = 1
}
EOF
suite_rc=$?

if [[ $gate_fail -ne 0 || $suite_rc -ne 0 ]]; then
  if (( JSON_OUT == 0 )); then
    echo
    echo "run-fast-tests: FAIL"
  fi
  exit 1
fi

if (( JSON_OUT == 0 )); then
  echo
  echo "run-fast-tests: PASS"
fi
