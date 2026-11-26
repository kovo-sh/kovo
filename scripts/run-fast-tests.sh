#!/usr/bin/env bash
# Unified fast zero-LLM verification gate + parallel hermetic test runner (`cq-3-merge-gate`, `R2-02`).
#
# Runs:
#   1. npx tsc --noEmit                         (skipped with --suites-only or --check-only)
#   2. bash scripts/worker-gate.sh              (skipped with --suites-only or --check-only)
#   3. Per-case v2 QUARANTINE.json validation + recursive orphan-test check + all non-excluded
#      fast zero-LLM tests/*.test.ts suites (INCLUDING files with per-case quarantine entries)
#      in parallel via `node --test` under `scripts/runtime-profile.ts` hermetic env + hardened
#      Node flags, with TAP per-case drift detection and 2-pass stale-entry verification.
#
# Usage:
#   bash scripts/run-fast-tests.sh
#   bash scripts/run-fast-tests.sh --quarantine tests/QUARANTINE.json
#   bash scripts/run-fast-tests.sh --suites-only --quarantine tests/QUARANTINE.json
#   bash scripts/run-fast-tests.sh --check-only --quarantine tests/QUARANTINE.json [--now YYYY-MM-DD]
#   KOVO_FAST_TEST_JOBS=12 bash scripts/run-fast-tests.sh --suites-only --quarantine tests/QUARANTINE.json
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
SKIP_GIT_CAP_CHECK=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quarantine) QUARANTINE_PATH="${2:?--quarantine requires a path}"; shift 2;;
    --suites-only) SUITES_ONLY=1; shift;;
    --check-only) CHECK_ONLY=1; SUITES_ONLY=1; shift;;
    --now) NOW_DATE="${2:?--now requires YYYY-MM-DD}"; shift 2;;
    --tests-dir) TESTS_DIR="${2:?--tests-dir requires a directory}"; shift 2;;
    --jobs) JOBS_OVERRIDE="${2:?--jobs requires an integer}"; shift 2;;
    --json) JSON_OUT=1; shift;;
    --skip-git-cap-check) SKIP_GIT_CAP_CHECK=1; shift;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

if [[ "$CHECK_ONLY" -eq 0 && ! -d node_modules ]]; then
  echo "FAIL: node_modules missing — run 'npm ci' (or symlink main checkout's node_modules) first." >&2
  exit 2
fi

export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=2048}"

# Categorized, documented exclude list for non-fast tests/*.test.ts suites (tier|file|reason).
# Every tests/**/*.test.ts file must be either fast-run (possibly with per-case quarantine entries)
# or in this categorized list.
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
  echo "== 3/3 Fast zero-LLM unit suites (hermetic node --test in parallel)"
fi

DEFAULT_JOBS="$(nproc 2>/dev/null || echo 8)"
if (( DEFAULT_JOBS > 4 )); then
  DEFAULT_JOBS=$(( DEFAULT_JOBS - 4 ))
elif (( DEFAULT_JOBS > 2 )); then
  DEFAULT_JOBS=$(( DEFAULT_JOBS - 2 ))
fi
if (( DEFAULT_JOBS > 10 )); then DEFAULT_JOBS=10; fi
if (( DEFAULT_JOBS < 4 )); then DEFAULT_JOBS=4; fi

JOBS="${JOBS_OVERRIDE:-${KOVO_FAST_TEST_JOBS:-$DEFAULT_JOBS}}"
if (( JOBS > 16 )); then JOBS=16; fi
if (( JOBS < 1 )); then JOBS=1; fi

EXCLUDED_JOINED="$(printf '%s\n' "${EXCLUDE_SPECS[@]}")"
export EXCLUDED_JOINED FAST_TEST_JOBS="$JOBS"
export FAST_TEST_QUARANTINE="$QUARANTINE_PATH"
export FAST_TEST_CHECK_ONLY="$CHECK_ONLY"
export FAST_TEST_NOW="$NOW_DATE"
export FAST_TEST_DIR="$TESTS_DIR"
export FAST_TEST_JSON="$JSON_OUT"
export FAST_TEST_SKIP_GIT_CAP="$SKIP_GIT_CAP_CHECK"

node --input-type=module <<'EOF'
import { execFile, execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { join, posix, relative, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

const repoRoot = resolve('.')
const tiersMod = await import(pathToFileURL(resolve(repoRoot, 'scripts/test-tiers.ts')).href)
const profileMod = await import(pathToFileURL(resolve(repoRoot, 'scripts/runtime-profile.ts')).href)

const {
  isCoreGateInvariantTestFile,
  isKernelOrCriticalTestFile,
  isGenericTriageOwner,
  MAX_KERNEL_QUARANTINE_DAYS,
} = tiersMod

const {
  buildHermeticNodeTestArgs,
  buildHermeticTestEnv,
  prepareHermeticTestDir,
  parseTapOutput,
} = profileMod

const testsDirArg = process.env.FAST_TEST_DIR || 'tests'
const isDefaultTestsDir = testsDirArg === 'tests'
const testsDirAbs = resolve(testsDirArg)
const checkOnly = process.env.FAST_TEST_CHECK_ONLY === '1'
const jsonOut = process.env.FAST_TEST_JSON === '1'
const quarantinePath = (process.env.FAST_TEST_QUARANTINE || '').trim()
const todayStr = (process.env.FAST_TEST_NOW || '').trim() || new Date().toISOString().slice(0, 10)
const jobs = Math.max(1, Number(process.env.FAST_TEST_JOBS) || 8)
const skipGitCapCheck = process.env.FAST_TEST_SKIP_GIT_CAP === '1' || !isDefaultTestsDir

const excludedMap = new Map()
for (const line of (process.env.EXCLUDED_JOINED || '').split(/\r?\n/)) {
  const trimmed = line.trim()
  if (!trimmed) continue
  const [tier, file, ...rest] = trimmed.split('|')
  if (tier && file) excludedMap.set(file, { tier, reason: rest.join('|') })
}

function discoverTestFilesRecursive(dirAbs, baseAbs, out = []) {
  if (!existsSync(dirAbs)) return out
  const entries = readdirSync(dirAbs, { withFileTypes: true })
  entries.sort((a, b) => a.name.localeCompare(b.name))
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue
    const full = join(dirAbs, entry.name)
    if (entry.isDirectory()) {
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

function diffCalendarDays(laterIso, earlierIso) {
  const [y1, m1, d1] = laterIso.split('-').map(Number)
  const [y2, m2, d2] = earlierIso.split('-').map(Number)
  const t1 = Date.UTC(y1, m1 - 1, d1)
  const t2 = Date.UTC(y2, m2 - 1, d2)
  return Math.round((t1 - t2) / 86_400_000)
}

function readGitV2QuarantineCap(ref, relPath) {
  try {
    const raw = execFileSync('git', ['show', `${ref}:${relPath}`], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    const parsed = JSON.parse(raw)
    if (parsed && parsed.version === 2 && Number.isInteger(parsed.maxQuarantinedCases)) {
      return parsed.maxQuarantinedCases
    }
  } catch {
    // Ref or file absent in git history; ignore.
  }
  return null
}

const errors = []

// 1. Discover all *.test.ts files recursively under tests/
const allDiscovered = discoverTestFilesRecursive(testsDirAbs, testsDirAbs).sort()
const topLevelGlob = allDiscovered.filter(f => /^tests\/[^/]+\.test\.ts$/.test(f))
const nestedFiles = allDiscovered.filter(f => !/^tests\/[^/]+\.test\.ts$/.test(f))
const discoveredSet = new Set(allDiscovered)

// 2. Validate QUARANTINE.json (schema v2: per-case entries)
// Map<file, Map<testName, entry>>
const quarantinedByFile = new Map()
const seenCaseKeys = new Set()
let maxQuarantinedCases = null
let totalQuarantinedCases = 0
let earliestExpiry = null
let kernelQuarantinedCases = 0

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
        errors.push(`${quarantinePath}: root must be an object { version: 2, maxQuarantinedCases, entries }`)
      } else {
        if (parsed.version !== 2) {
          errors.push(`${quarantinePath}: schema version must be 2 (per-case quarantine); whole-file v1 schema is forbidden`)
        }
        const hasV2Cap = Number.isInteger(parsed.maxQuarantinedCases) && parsed.maxQuarantinedCases >= 0
        const hasLegacyCap = Number.isInteger(parsed.maxQuarantined) && parsed.maxQuarantined >= 0
        if (hasV2Cap) {
          maxQuarantinedCases = parsed.maxQuarantinedCases
        } else if (hasLegacyCap) {
          maxQuarantinedCases = parsed.maxQuarantined
          if (parsed.version === 2) {
            errors.push(`${quarantinePath}: maxQuarantinedCases must be a non-negative integer`)
          }
        } else {
          errors.push(`${quarantinePath}: maxQuarantinedCases must be a non-negative integer`)
        }

        if (!skipGitCapCheck && maxQuarantinedCases !== null && parsed.version === 2) {
          const relQ = relative(repoRoot, absQ).split(sep).join(posix.sep)
          for (const ref of ['HEAD', 'main']) {
            const prevCap = readGitV2QuarantineCap(ref, relQ)
            if (prevCap !== null && maxQuarantinedCases > prevCap) {
              errors.push(
                `${quarantinePath}: quarantine cap grew (${maxQuarantinedCases} > ${prevCap} on ${ref}); maxQuarantinedCases may only decrease`,
              )
              break
            }
          }
        }

        if (!Array.isArray(parsed.entries)) {
          errors.push(`${quarantinePath}: entries must be an array`)
        } else {
          totalQuarantinedCases = parsed.entries.length
          if (maxQuarantinedCases !== null && parsed.entries.length > maxQuarantinedCases) {
            errors.push(
              `${quarantinePath}: quarantine cap exceeded (${parsed.entries.length} entries > maxQuarantinedCases=${maxQuarantinedCases}); fix or remove existing quarantined tests instead of growing the cap`,
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
            const testName = typeof e.testName === 'string' ? e.testName.trim() : ''
            const assertionLocation = typeof e.assertionLocation === 'string' ? e.assertionLocation.trim() : ''
            const ownerStream = typeof e.ownerStream === 'string' ? e.ownerStream.trim() : ''
            const legacyOwner = typeof e.owner === 'string' ? e.owner.trim() : ''
            const effectiveOwner = ownerStream || legacyOwner
            const reason = typeof e.reason === 'string' ? e.reason.trim() : ''
            const expires = typeof e.expires === 'string' ? e.expires.trim() : ''

            if (!file) {
              errors.push(`${quarantinePath}: entries[${i}].file must be a non-empty string`)
            }
            if (!testName) {
              errors.push(
                `${quarantinePath}: entries[${i}] (${file || 'unknown'}) missing required non-empty 'testName' (whole-file quarantine is forbidden)`,
              )
            }
            if (e.assertionLocation !== undefined && (typeof e.assertionLocation !== 'string' || !assertionLocation)) {
              errors.push(`${quarantinePath}: entries[${i}] (${file || 'unknown'}) invalid 'assertionLocation' (must be non-empty string if provided)`)
            }
            if (!effectiveOwner) {
              errors.push(`${quarantinePath}: entries[${i}] (${file || 'unknown'}) missing required non-empty 'owner' ('ownerStream')`)
            } else if (!ownerStream && parsed.version === 2) {
              errors.push(`${quarantinePath}: entries[${i}] (${file || 'unknown'}) must use 'ownerStream' instead of legacy 'owner'`)
            }
            if (!reason) {
              errors.push(`${quarantinePath}: entries[${i}] (${file || 'unknown'}) missing required non-empty 'reason'`)
            }

            let expiresValid = false
            if (!expires || !isValidIsoDate(expires)) {
              errors.push(`${quarantinePath}: entries[${i}] (${file || 'unknown'}) invalid 'expires' date '${expires}' (expected YYYY-MM-DD)`)
            } else {
              expiresValid = true
              if (!earliestExpiry || expires < earliestExpiry) earliestExpiry = expires
              if (isValidIsoDate(todayStr) && expires < todayStr) {
                errors.push(
                  `${quarantinePath}: expired quarantine entry ${file}${testName ? ` :: ${testName}` : ''} (owner=${effectiveOwner}, expires=${expires} < today=${todayStr})`,
                )
              }
            }

            if (file) {
              if (isCoreGateInvariantTestFile(file)) {
                errors.push(`${quarantinePath}: core gate invariant suite ${file} cannot be quarantined`)
              } else if (isKernelOrCriticalTestFile(file)) {
                kernelQuarantinedCases += 1
                if (expiresValid && isValidIsoDate(todayStr)) {
                  const days = diffCalendarDays(expires, todayStr)
                  if (days > MAX_KERNEL_QUARANTINE_DAYS) {
                    errors.push(
                      `${quarantinePath}: kernel/critical suite ${file}${testName ? ` :: ${testName}` : ''} expires in ${days}d > max ${MAX_KERNEL_QUARANTINE_DAYS}d (expires=${expires}, today=${todayStr})`,
                    )
                  }
                }
                if (effectiveOwner && isGenericTriageOwner(effectiveOwner)) {
                  errors.push(
                    `${quarantinePath}: kernel/critical suite ${file}${testName ? ` :: ${testName}` : ''} forbids generic triage owner '${effectiveOwner}'; assign a concrete ownerStream (e.g. triage-kernel-<slug>)`,
                  )
                }
              }

              if (excludedMap.has(file)) {
                errors.push(`${quarantinePath}: ${file} is already categorized in EXCLUDE_TESTS (${excludedMap.get(file).tier}); remove from quarantine`)
              }
              if (!discoveredSet.has(file)) {
                errors.push(`${quarantinePath}: stale quarantine entry ${file} does not exist under ${testsDirArg}`)
              }

              if (testName) {
                const caseKey = `${file}\0${testName}`
                if (seenCaseKeys.has(caseKey)) {
                  errors.push(`${quarantinePath}: duplicate quarantine entry for ${file} :: ${testName}`)
                } else {
                  seenCaseKeys.add(caseKey)
                  if (!quarantinedByFile.has(file)) quarantinedByFile.set(file, new Map())
                  quarantinedByFile.get(file).set(testName, {
                    file,
                    testName,
                    assertionLocation: assertionLocation || undefined,
                    ownerStream: effectiveOwner,
                    reason,
                    expires,
                  })
                }
              }
            }
          }
        }
      }
    }
  }
}

// 3. Orphan-test check (M-35): every tests/**/*.test.ts must be fast-run or excluded.
const orphanFiles = []
for (const file of nestedFiles) {
  if (!excludedMap.has(file)) {
    orphanFiles.push(file)
  }
}
if (orphanFiles.length > 0) {
  errors.push(
    `Orphan test file(s) not executed by top-level fast glob and not categorized in EXCLUDE_TESTS: ${orphanFiles.join(', ')}`,
  )
}

if (isDefaultTestsDir) {
  for (const [file, meta] of excludedMap) {
    if (!discoveredSet.has(file)) {
      errors.push(`Stale EXCLUDE_TESTS entry (${meta.tier}): ${file} does not exist on disk`)
    }
  }
}

// ALWAYS execute all non-excluded fast files, INCLUDING those with per-case quarantine entries!
const runFiles = topLevelGlob.filter(f => !excludedMap.has(f))
const skippedByExclude = allDiscovered.filter(f => excludedMap.has(f))
const quarantinedFileCount = quarantinedByFile.size

// Accounting invariant: every discovered test file is either executed or excluded.
const accounted = runFiles.length + skippedByExclude.length
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
      quarantined: totalQuarantinedCases,
      quarantinedCases: totalQuarantinedCases,
      quarantinedFiles: quarantinedFileCount,
      kernelQuarantinedCases,
      maxQuarantined: maxQuarantinedCases,
      maxQuarantinedCases,
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
      quarantined: totalQuarantinedCases,
      quarantinedCases: totalQuarantinedCases,
      quarantinedFiles: quarantinedFileCount,
      kernelQuarantinedCases,
      maxQuarantined: maxQuarantinedCases,
      maxQuarantinedCases,
      earliestExpiry,
      orphans: [],
      errors: [],
    }, null, 2))
  } else {
    const qNote = quarantinePath
      ? `, ${totalQuarantinedCases}/${maxQuarantinedCases} quarantined cases across ${quarantinedFileCount} files (${kernelQuarantinedCases} kernel/critical, earliest expiry ${earliestExpiry || 'n/a'})`
      : ''
    console.log(
      `Fast-test inventory PASS: ${allDiscovered.length} discovered (${runFiles.length} fast, ${skippedByExclude.length} excluded${qNote}, 0 orphans)`,
    )
  }
  process.exit(0)
}

// Schedule heavier suites first (LPT heuristic) to eliminate tail stragglers across worker slots.
const HEAVY_HINT_RE = /(?:v6-auth|v8-concurrency-12|v4-m4-surface-orchestration|ux-inventory-batch|ux-consent-sticky|ux-zero-persona-warn|ux-approval-scopes|ux-round0-stepper|r3-node-hardening|v8-seam2-docs-mock-exec|v8-phasea-overlap|ux-workflow-list|fix-project-tabs|v7-exec-throughput|gb-planner-wiring|realism-mono|product-paging|phase0-paging|contract-canary|oob-engine|crawl-paging|killswitch-nav|universal-browser-auth|bench-cred-dir|proto-pollute|probe-split|egress-admit|static-fp|fixture-timing|realistic-harness)/
const orderedRunFiles = [...runFiles].sort((a, b) => {
  const ha = HEAVY_HINT_RE.test(a) ? 0 : 1
  const hb = HEAVY_HINT_RE.test(b) ? 0 : 1
  return ha !== hb ? ha - hb : a.localeCompare(b)
})

const qBanner = quarantinePath
  ? `, ${totalQuarantinedCases}/${maxQuarantinedCases} quarantined cases in ${quarantinedFileCount} files`
  : ''
if (!jsonOut) {
  console.log(
    `Discovered ${allDiscovered.length} test files (${runFiles.length} fast zero-LLM, ${skippedByExclude.length} excluded${qBanner}, 0 orphans; concurrency=${jobs})`,
  )
}

const tStart = Date.now()
let idx = 0
const results = []
const preferredTmpRoot = process.env.TMPDIR || undefined

function evaluateFileExecution(file, execRes) {
  const qMap = quarantinedByFile.get(file) || new Map()
  const { parsed, err, ms, timedOut, stderrSnippet } = execRes
  const failingCases = parsed.cases.filter(c => c.status === 'fail')
  const passingCases = parsed.cases.filter(c => c.status === 'pass')
  const skippedCases = parsed.cases.filter(c => c.status === 'skipped' || c.status === 'todo')
  const passingSet = new Set(passingCases.map(c => c.name))
  const observedSet = new Set(parsed.cases.map(c => c.name))

  const unlistedFailures = []
  const quarantinedFailures = []
  for (const c of failingCases) {
    if (qMap.has(c.name)) {
      quarantinedFailures.push(c)
    } else {
      unlistedFailures.push(c)
    }
  }

  // Catch file-level crashes, syntax errors, timeouts, or post-test unhandled rejections
  // that did not emit a matching leaf failure.
  if (err && failingCases.length === 0) {
    unlistedFailures.push({
      name: timedOut ? '<timeout>' : '<process-error>',
      status: 'fail',
      failureType: timedOut ? 'timeout' : 'processError',
      location: file,
      error: timedOut ? 'TIMEOUT (>55s)' : stderrSnippet || `exit ${err.code ?? 1}`,
    })
  } else if (err && unlistedFailures.length === 0 && quarantinedFailures.length === 0) {
    unlistedFailures.push({
      name: '<process-error>',
      status: 'fail',
      failureType: 'processError',
      location: file,
      error: stderrSnippet || `exit ${err.code ?? 1}`,
    })
  }

  const nowPassingQuarantined = []
  const missingQuarantined = []
  for (const [testName, entry] of qMap) {
    if (passingSet.has(testName)) {
      nowPassingQuarantined.push(entry)
    } else if (!observedSet.has(testName) && !timedOut && observedSet.size > 0) {
      missingQuarantined.push(entry)
    }
  }

  let reason = ''
  if (unlistedFailures.length > 0) {
    const first = unlistedFailures[0]
    const errPart = first.error ? ` — ${first.error}` : ''
    reason = `${first.name}${errPart}`.slice(0, 180)
  }

  return {
    file,
    ok: unlistedFailures.length === 0,
    ms,
    timedOut,
    tests: parsed.cases.length || parsed.summary.tests,
    pass: passingCases.length,
    fail: unlistedFailures.length,
    quarantinedFail: quarantinedFailures.length,
    skipped: skippedCases.length,
    unlistedFailures,
    quarantinedFailures,
    nowPassingQuarantined,
    missingQuarantined,
    passingSet,
    reason,
  }
}

function runOneRaw(file) {
  const absFile = isDefaultTestsDir ? file : join(testsDirAbs, file.replace(/^tests\//, ''))
  const sandboxDir = prepareHermeticTestDir(preferredTmpRoot, 'kf-')
  const tapPath = join(sandboxDir, 'r.tap')
  const env = buildHermeticTestEnv(sandboxDir)
  const args = buildHermeticNodeTestArgs(absFile, [
    '--test-timeout=25000',
    '--test-force-exit',
    `--test-reporter-destination=${tapPath}`,
  ])
  const t0 = Date.now()
  return new Promise(res => {
    execFile(
      process.execPath,
      args,
      { env, timeout: 55_000, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const ms = Date.now() - t0
        const tapText = existsSync(tapPath) ? readFileSync(tapPath, 'utf8') : ''
        rmSync(sandboxDir, { recursive: true, force: true })
        const parsed = parseTapOutput(tapText, repoRoot)
        const timedOut = Boolean(err && err.killed)
        const combined = `${stderr || ''}\n${stdout || ''}`
        const errLine = combined
          .split(/\r?\n/)
          .map(l => l.trim())
          .find(l => /^(Error:|TypeError:|ReferenceError:|SyntaxError:|AssertionError|ERR_)/.test(l))
        res({
          parsed,
          err,
          ms,
          timedOut,
          stderrSnippet: (errLine || '').slice(0, 140),
        })
      },
    )
  })
}

async function runOne(file) {
  const raw = await runOneRaw(file)
  return evaluateFileExecution(file, raw)
}

async function worker() {
  while (idx < orderedRunFiles.length) {
    const file = orderedRunFiles[idx++]
    results.push(await runOne(file))
  }
}

await Promise.all(Array.from({ length: jobs }, worker))

// 2nd verification pass on files where any quarantined case passed on run 1,
// guarding against nondeterminism before declaring a stale quarantine entry.
const staleEntries = []
const flakyQuarantined = []

const filesWithNowPassing = results.filter(r => r.nowPassingQuarantined.length > 0)
if (filesWithNowPassing.length > 0) {
  let sIdx = 0
  const verifyJobs = Math.min(jobs, filesWithNowPassing.length)
  async function verifyWorker() {
    while (sIdx < filesWithNowPassing.length) {
      const firstRun = filesWithNowPassing[sIdx++]
      const secondRun = await runOne(firstRun.file)
      for (const entry of firstRun.nowPassingQuarantined) {
        if (secondRun.passingSet.has(entry.testName)) {
          staleEntries.push({
            file: entry.file,
            testName: entry.testName,
            ownerStream: entry.ownerStream,
            kind: 'passed_2x',
            message: `stale quarantine entry — remove: ${entry.file} :: ${entry.testName} (passed 2/2 consecutive runs; owner=${entry.ownerStream})`,
          })
        } else {
          flakyQuarantined.push({
            file: entry.file,
            testName: entry.testName,
            ownerStream: entry.ownerStream,
          })
        }
      }
      // If an unlisted failure surfaced on the 2nd verification pass, keep it visible too.
      if (!secondRun.ok && firstRun.ok) {
        const slot = results.findIndex(r => r.file === firstRun.file)
        if (slot >= 0) results[slot] = secondRun
      }
    }
  }
  await Promise.all(Array.from({ length: verifyJobs }, verifyWorker))
}

for (const r of results) {
  for (const entry of r.missingQuarantined) {
    staleEntries.push({
      file: entry.file,
      testName: entry.testName,
      ownerStream: entry.ownerStream,
      kind: 'missing_case',
      message: `stale quarantine entry — remove: ${entry.file} :: ${entry.testName} (test case not found in suite; owner=${entry.ownerStream})`,
    })
  }
}

// Re-verify timing-sensitive unlisted-failure files sequentially in isolation to separate
// CPU-contention micro-latency flakes from deterministic regressions.
const CONTENTION_HINT_RE = /(?:\d|\b)ms\b|\b(?:timeout|timed out|latency|wall.?clock|stall|rps|duration|playwright|chromium|locator)\b/i
const initialFailures = results.filter(r => !r.ok)
const recoveredInIsolation = []
if (jobs > 1 && initialFailures.length > 0) {
  const retryCandidates =
    initialFailures.length <= 3
      ? initialFailures
      : initialFailures
          .filter(r =>
            r.timedOut ||
            r.unlistedFailures.some(f => CONTENTION_HINT_RE.test(`${f.name} ${f.error}`)),
          )
          .slice(0, 8)
  for (const prev of retryCandidates) {
    const retry = await runOne(prev.file)
    if (retry.ok) {
      const slot = results.findIndex(r => r.file === prev.file)
      if (slot >= 0) results[slot] = retry
      recoveredInIsolation.push({ file: prev.file, parallelReason: prev.reason, isolatedMs: retry.ms })
    }
  }
}

results.sort((a, b) => a.file.localeCompare(b.file))
staleEntries.sort((a, b) => `${a.file}\0${a.testName}`.localeCompare(`${b.file}\0${b.testName}`))

const wallSec = Number(((Date.now() - tStart) / 1000).toFixed(1))
const passedFiles = results.filter(r => r.ok)
const failedFiles = results.filter(r => !r.ok)
const totalTests = results.reduce((n, r) => n + r.tests, 0)
const totalPass = results.reduce((n, r) => n + r.pass, 0)
const totalUnlistedFail = results.reduce((n, r) => n + r.fail, 0)
const totalQuarantinedFail = results.reduce((n, r) => n + r.quarantinedFail, 0)
const totalSkip = results.reduce((n, r) => n + r.skipped, 0)
const overallOk = failedFiles.length === 0 && staleEntries.length === 0

if (jsonOut) {
  console.log(JSON.stringify({
    ok: overallOk,
    wallSec,
    discovered: allDiscovered.length,
    fast: results.length,
    passedFiles: passedFiles.length,
    failedFiles: failedFiles.map(r => ({
      file: r.file,
      fail: r.fail,
      quarantinedFail: r.quarantinedFail,
      tests: r.tests,
      ms: r.ms,
      reason: r.reason,
      unlistedFailures: r.unlistedFailures.map(f => ({ name: f.name, location: f.location, error: f.error })),
    })),
    staleEntries,
    flakyQuarantined,
    recoveredInIsolation,
    excluded: skippedByExclude.length,
    quarantined: totalQuarantinedCases,
    quarantinedCases: totalQuarantinedCases,
    quarantinedFiles: quarantinedFileCount,
    kernelQuarantinedCases,
    maxQuarantined: maxQuarantinedCases,
    maxQuarantinedCases,
    totalTests,
    totalPass,
    totalFail: totalUnlistedFail,
    totalQuarantinedFail,
    totalSkip,
  }, null, 2))
} else {
  console.log(
    `\nFast-test summary (${wallSec}s): ${passedFiles.length}/${results.length} files passed, ${failedFiles.length} failed` +
      ` (${totalPass}/${totalTests} cases passed, ${totalUnlistedFail} unlisted fail, ${totalQuarantinedFail} quarantined fail, ${totalSkip} skipped${qBanner})`,
  )
  if (recoveredInIsolation.length > 0) {
    console.log(
      `Note: ${recoveredInIsolation.length} timing-sensitive file(s) passed on isolated re-verify: ` +
        recoveredInIsolation.map(r => `${r.file} (${r.isolatedMs}ms)`).join(', '),
    )
  }
  if (flakyQuarantined.length > 0) {
    console.log(
      `Note: ${flakyQuarantined.length} quarantined case(s) passed run 1 but failed verification run 2 (kept quarantined): ` +
        flakyQuarantined.map(f => `${f.file} :: ${f.testName}`).join(', '),
    )
  }
  if (failedFiles.length > 0) {
    console.log('\nFailing test files (unlisted failures):')
    for (const r of failedFiles) {
      console.log(`  FAIL ${r.file} (${r.fail} unlisted / ${r.tests} cases, ${r.ms}ms) — ${r.reason}`)
      for (const f of r.unlistedFailures.slice(0, 5)) {
        console.log(`    - [unlisted] ${f.name}${f.location ? ` (${f.location})` : ''}`)
      }
    }
  }
  if (staleEntries.length > 0) {
    console.log(`\nStale quarantine entries (${staleEntries.length} — remove from ${quarantinePath}):`)
    for (const s of staleEntries) {
      console.log(`  STALE ${s.message}`)
    }
  }
}

if (!overallOk) {
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
