/**
 * R3-09 Ledger Field Producer Truth & Honest Missing Agentic Cost (`tests/ledger-field-producers.test.ts`).
 *
 * 1. Parses `interface LedgerRow` in `scripts/bench-ledger.ts` via TypeScript AST and asserts
 *    that EVERY field has a real non-test producer across `scripts/**` / `benchmarks/**` (or sits
 *    on an explicit, non-expired ticketed allowlist tracking its wiring stream).
 * 2. Verifies missing agentic cost telemetry produces `null` (NEVER coerced to `0`),
 *    `computeCostPerConfirmed(null, N)` returns `null`, and legitimate `--no-llm` rows keep `0`.
 */
import assert from 'node:assert/strict'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, posix, relative, resolve, sep } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'
import {
  compareLedgerRows,
  computeCostPerConfirmed,
  resolveGitState,
  type LedgerRow,
} from '../scripts/bench-ledger.ts'
import { ScorecardReader, buildLedgerRow } from '../scripts/score-primitives.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const BENCH_LEDGER_PATH = join(REPO_ROOT, 'scripts/bench-ledger.ts')

interface TicketedFieldAllowlistEntry {
  field: string
  owner: string
  ticket: string
  expires: string
  reason: string
}

/**
 * Explicit ticketed allowlist for `LedgerRow` fields not yet populated by any non-test runner.
 * Every entry requires `{ field, owner, ticket, expires, reason }` and fails once expired or
 * once a non-test producer lands (prune-fail).
 */
const TICKETED_UNPRODUCED_LEDGER_FIELDS: readonly TicketedFieldAllowlistEntry[] = [
  {
    field: 'wastedUsd',
    owner: 'r3-02-stream-b',
    ticket: 'R3-02-STREAM-B-WASTED-USD',
    expires: '2026-12-31',
    reason: 'Record-only wasted spend telemetry; pending Stream B runner wiring from getRunTokenTelemetrySummary().retryStallWasteUsd.',
  },
]

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'out', 'coverage'])
const TEST_FILE_RE = /(?:^|\/)(?:tests?|__tests__)\/|(?:\.test|\.spec)\.[^./\\]+$/i
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/

function toPosixRel(absPath: string): string {
  const rel = relative(REPO_ROOT, absPath)
  return sep === '/' ? rel : rel.split(sep).join(posix.sep)
}

function isValidIsoDate(s: string): boolean {
  if (!ISO_DATE_RE.test(s)) return false
  const ms = Date.parse(`${s}T00:00:00Z`)
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 10) === s
}

function collectNonTestTsFiles(relDirs: readonly string[]): string[] {
  const out: string[] = []
  const walk = (absDir: string): void => {
    if (!existsSync(absDir)) return
    for (const entry of readdirSync(absDir, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue
      const full = join(absDir, entry.name)
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue
        walk(full)
      } else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
        const rel = toPosixRel(full)
        if (!TEST_FILE_RE.test(rel)) out.push(full)
      }
    }
  }
  for (const rel of relDirs) walk(join(REPO_ROOT, rel))
  out.sort()
  return out
}

function extractLedgerRowFields(): string[] {
  const src = readFileSync(BENCH_LEDGER_PATH, 'utf8')
  const sf = ts.createSourceFile(BENCH_LEDGER_PATH, src, ts.ScriptTarget.Latest, true)
  const fields: string[] = []
  for (const stmt of sf.statements) {
    if (ts.isInterfaceDeclaration(stmt) && stmt.name.text === 'LedgerRow') {
      for (const member of stmt.members) {
        if (ts.isPropertySignature(member) && ts.isIdentifier(member.name)) {
          fields.push(member.name.text)
        }
      }
    }
  }
  return fields
}

/**
 * Find non-test object-literal producers of each `LedgerRow` field across `scripts/**` and
 * `benchmarks/**`. For `scripts/bench-ledger.ts`, only counts assignments that actually compute
 * a value (e.g. `costPerConfirmed: ... computeCostPerConfirmed(...)`), NOT pass-through `null`
 * defaults like `wastedUsd: row.wastedUsd !== undefined ? row.wastedUsd : null`.
 */
function findLedgerFieldProducers(fields: readonly string[]): Map<string, Set<string>> {
  const fieldSet = new Set(fields)
  const producers = new Map<string, Set<string>>(fields.map(f => [f, new Set<string>()]))
  const files = collectNonTestTsFiles(['scripts', 'benchmarks'])

  for (const absFile of files) {
    const rel = toPosixRel(absFile)
    const src = readFileSync(absFile, 'utf8')
    const sf = ts.createSourceFile(rel, src, ts.ScriptTarget.Latest, true)
    const isBenchLedger = rel === 'scripts/bench-ledger.ts'

    const visit = (node: ts.Node): void => {
      if (ts.isPropertyAssignment(node) && ts.isIdentifier(node.name)) {
        const name = node.name.text
        if (fieldSet.has(name)) {
          if (isBenchLedger) {
            // In bench-ledger.ts, only count real computed producers (not `: row.X !== undefined ? row.X : null`).
            const initText = node.initializer.getText(sf)
            const isNullPassThrough = new RegExp(`row\\.${name}\\s*!==\\s*undefined\\s*\\?\\s*row\\.${name}\\s*:\\s*null`).test(initText)
            if (!isNullPassThrough) {
              producers.get(name)!.add(rel)
            }
          } else {
            producers.get(name)!.add(rel)
          }
        }
      } else if (ts.isShorthandPropertyAssignment(node)) {
        const name = node.name.text
        if (fieldSet.has(name) && !isBenchLedger) {
          producers.get(name)!.add(rel)
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(sf)
  }

  return producers
}

const HASH_A = 'a'.repeat(64)
const HASH_B = 'b'.repeat(64)

describe('R3-09 Ledger Field Producer Truth', () => {
  test('every LedgerRow field has a real non-test producer or a valid non-expired ticketed allowlist entry', () => {
    const fields = extractLedgerRowFields()
    assert.ok(fields.length >= 25, `expected >= 25 LedgerRow fields, got ${fields.length}`)

    const producers = findLedgerFieldProducers(fields)
    const today = new Date().toISOString().slice(0, 10)
    const allowlist = new Map<string, TicketedFieldAllowlistEntry>()

    for (const entry of TICKETED_UNPRODUCED_LEDGER_FIELDS) {
      assert.ok(fields.includes(entry.field), `allowlisted field '${entry.field}' does not exist on LedgerRow`)
      assert.ok(entry.owner.trim().length > 0, `allowlist entry '${entry.field}' requires owner`)
      assert.ok(entry.ticket.trim().length > 0, `allowlist entry '${entry.field}' requires ticket`)
      assert.ok(entry.reason.trim().length > 0, `allowlist entry '${entry.field}' requires reason`)
      assert.ok(isValidIsoDate(entry.expires), `allowlist entry '${entry.field}' has invalid ISO date: ${entry.expires}`)
      assert.ok(entry.expires >= today, `allowlist entry '${entry.field}' expired on ${entry.expires}`)
      const liveProducers = [...(producers.get(entry.field) ?? [])]
      assert.equal(
        liveProducers.length,
        0,
        `stale allowlist entry '${entry.field}': now produced by ${liveProducers.join(', ')} — remove from allowlist`,
      )
      allowlist.set(entry.field, entry)
    }

    const unproduced: string[] = []
    for (const field of fields) {
      const count = producers.get(field)?.size ?? 0
      if (count === 0 && !allowlist.has(field)) {
        unproduced.push(field)
      }
    }

    assert.deepEqual(
      unproduced,
      [],
      `LedgerRow field(s) have ZERO non-test producers and no ticketed allowlist entry: ${unproduced.join(', ')}`,
    )
  })
})

describe('R3-09 Honest missing agentic cost (null, never coerced to 0)', () => {
  test('ScorecardReader.read returns costUsd=null for agentic cells missing cost telemetry, while --no-llm stays 0', () => {
    // 1. Agentic cell with NO costUsd / totalCostUsd -> MUST be null (never 0!)
    const agenticMissing = ScorecardReader.read({
      app: 'acme-saas',
      seed: 42,
      llm: 'agentic',
      targets: 10,
      confirmed: 4,
      decoyFalsePositives: 0,
      unmatchedFalsePositives: 0,
    })
    assert.equal(agenticMissing.llm, 'agentic')
    assert.equal(agenticMissing.costUsd, null, 'absent agentic cost MUST be null, never 0')

    // 2. Failed/missing agentic scorecard with no meta.costUsd -> MUST be null (never 0!)
    const failedAgentic = ScorecardReader.read(null, { app: 'acme-saas', llm: 'agentic' })
    assert.equal(failedAgentic.state, 'failed_inert')
    assert.equal(failedAgentic.costUsd, null, 'failed agentic cell with absent cost MUST be null')

    // 3. Agentic cell with real cost telemetry -> preserved verbatim
    const agenticWithCost = ScorecardReader.read({
      app: 'acme-saas',
      seed: 42,
      llm: 'agentic',
      targets: 10,
      confirmed: 4,
      totalCostUsd: 1.25,
    })
    assert.equal(agenticWithCost.costUsd, 1.25)

    // 4. Legitimate deterministic --no-llm cell with omitted cost -> stays 0
    const noLlmOmitted = ScorecardReader.read({
      app: 'acme-saas',
      seed: 42,
      llm: 'deterministic-no-llm',
      targets: 10,
      confirmed: 4,
    })
    assert.equal(noLlmOmitted.llm, 'deterministic-no-llm')
    assert.equal(noLlmOmitted.costUsd, 0, '--no-llm cost MUST stay 0')

    // 5. Failed deterministic --no-llm cell -> stays 0
    const failedNoLlm = ScorecardReader.read(null, { app: 'acme-saas', llm: 'deterministic-no-llm' })
    assert.equal(failedNoLlm.costUsd, 0)
  })

  test('computeCostPerConfirmed(null, N) returns null while computeCostPerConfirmed(0, N) returns 0', () => {
    assert.equal(computeCostPerConfirmed(null, 5), null)
    assert.equal(computeCostPerConfirmed(undefined, 5), null)
    assert.equal(computeCostPerConfirmed(Number.NaN, 5), null)
    assert.equal(computeCostPerConfirmed(-1, 5), null)
    assert.equal(computeCostPerConfirmed(0, 5), 0)
    assert.equal(computeCostPerConfirmed(2.5, 5), 0.5)
    assert.equal(computeCostPerConfirmed(2.5, 0), null)
  })

  test('buildLedgerRow & compareLedgerRows preserve null agentic cost without coercing to 0', () => {
    const headSha = resolveGitState(REPO_ROOT).gitSha
    const agenticRow: LedgerRow = buildLedgerRow({
      cell: {
        app: 'acme-saas',
        seed: 42,
        llm: 'agentic',
        targets: 10,
        confirmed: 5,
      },
      suite: 'realistic-bench',
      gitSha: headSha,
      dirty: false,
      benchmarkVersion: HASH_A,
      effectiveConfigHash: HASH_B,
    })
    assert.equal(agenticRow.costUsd, null)
    assert.equal(computeCostPerConfirmed(agenticRow.costUsd, agenticRow.confirmed), null)

    const noLlmRow: LedgerRow = buildLedgerRow({
      cell: {
        app: 'acme-saas',
        seed: 42,
        llm: 'deterministic-no-llm',
        targets: 10,
        confirmed: 3,
      },
      suite: 'realistic-bench',
      gitSha: headSha,
      dirty: false,
      benchmarkVersion: HASH_A,
      effectiveConfigHash: HASH_B,
    })
    assert.equal(noLlmRow.costUsd, 0)
    assert.equal(computeCostPerConfirmed(noLlmRow.costUsd, noLlmRow.confirmed), 0)

    const cmp = compareLedgerRows(noLlmRow, agenticRow)
    assert.equal(cmp.costDeltaUsd, null, 'costDeltaUsd MUST be null when either row has null costUsd')
    assert.equal(cmp.costPerConfirmedDelta, null, 'costPerConfirmedDelta MUST be null when either row has null costUsd')
  })
})
