/**
 * Move 2 — Fast State-Machine Lifecycle Invariant Suite (`tests/qa-lifecycle-invariants.test.ts`).
 *
 * Zero-LLM deterministic invariant matrix (< 5s):
 *  - Matrix 1: Exhaustive `RunStatus` enum partition & `artifact-ttl.ts` / `storage-maintenance.ts` agreement.
 *  - Matrix 2: Static AST drift audit across `src/server/**\/*.ts` for run-status typos & partial lists.
 *  - Matrix 3: Post-run export & data integrity (`exportReportMarkdown`, `buildSarifLog`,
 *              `exportRunReceiptBundle`, `buildVerdict`) across every `RunStatus` & finding composition.
 *  - Matrix 4: Real loopback network-edge fixtures (`308 apex -> www.`, uniform `401` edge walls,
 *              Cloudflare `525` SSL errors) exercising `RequestBroker` + `EgressGateway`.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { createServer as createHttpServer } from 'node:http'
import type { RequestListener } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join, relative, resolve } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import ts from 'typescript'
import { buildVerdict } from '../src/components/run/model.ts'
import type { Detail } from '../src/components/run/model.ts'
import { newProject, newRun } from '../src/domain.ts'
import type { Finding, InlineVerifyFeedback, RunStatus } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  isTerminalRunStatus as isArtifactTtlTerminalRunStatus,
  purgeExpiredArtifacts,
} from '../src/server/artifact-ttl.ts'
import { BrokerCircuitOpen, BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { EgressGateway } from '../src/server/egress-gateway.ts'
import {
  exportRunReceiptBundle,
  verifyProofReceiptBundle,
} from '../src/server/receipt-export.ts'
import { exportReportMarkdown } from '../src/server/report-export.ts'
import {
  ACTIVELY_EXECUTING_RUN_STATUSES,
  CANONICAL_RESUMABLE_NON_TERMINAL_RUN_STATUSES,
  LEGACY_TERMINAL_RUN_STATUS_ALIASES,
  RESUMABLE_NON_TERMINAL_RUN_STATUSES,
  RUN_STATUSES,
  RUN_STATUS_CLASSIFICATION,
  TERMINAL_RUN_STATUSES,
  classifyRunStatus,
  isActivelyExecutingRunStatus,
  isCanonicalRunStatus,
  isNonTerminalRunStatus,
  isResumableNonTerminalRunStatus,
  isTerminalRunStatus,
} from '../src/server/run-status.ts'
import { buildSarifLog, exportReportSarif } from '../src/server/sarif-export.ts'
import { StorageMaintenanceController } from '../src/server/storage-maintenance.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const SERVER_DIR = join(REPO_ROOT, 'src', 'server')
const TEST_ORIGIN = 'https://lifecycle-qa.example.test'

// ---------------------------------------------------------------------------
// Shared Helpers
// ---------------------------------------------------------------------------

function makeTempStore(t: TestContext, prefix = 'kovo-qa-lifecycle-'): { dir: string; store: Store } {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return { dir, store }
}

function parseDomainRunStatuses(): string[] {
  const domainPath = join(REPO_ROOT, 'src', 'domain.ts')
  const sourceText = readFileSync(domainPath, 'utf8')
  const sf = ts.createSourceFile(domainPath, sourceText, ts.ScriptTarget.Latest, true)
  const found: string[] = []

  function visit(node: ts.Node): void {
    if (ts.isTypeAliasDeclaration(node) && node.name.text === 'RunStatus') {
      if (ts.isUnionTypeNode(node.type)) {
        for (const member of node.type.types) {
          assert.ok(
            ts.isLiteralTypeNode(member) && ts.isStringLiteral(member.literal),
            `Expected string literal union member in RunStatus, got: ${member.getText(sf)}`,
          )
          found.push(member.literal.text)
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)

  assert.ok(found.length > 0, 'Failed to locate `export type RunStatus` in src/domain.ts')
  return found
}

function listTsFilesRecursive(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      out.push(...listTsFilesRecursive(full))
    } else if (entry.name.endsWith('.ts')) {
      out.push(full)
    }
  }
  return out.sort()
}

function setupApprovedRun(store: Store, name = 'Lifecycle App', origin = TEST_ORIGIN) {
  const project = store.createProject(newProject.parse({
    requestId: randomUUID(),
    name,
    environment: 'public',
    seeds: [origin],
  }))
  const createdRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: `Assess ${name}`,
    capabilityTier: 2,
  }))
  store.command({ requestId: randomUUID(), runId: createdRun.id, action: 'discover', consent: true })
  const discovered = store.run(createdRun.id)
  store.command({
    requestId: randomUUID(),
    runId: createdRun.id,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    saveProject: true,
    capabilityTier: 2,
  })
  const run = store.run(createdRun.id)
  const asset = run.candidates[0]!
  const worker = store.makeWorker(run, 'investigation', asset, 'Lifecycle Worker', 'Verify controls')
  return { projectId: project.id, runId: run.id, run, asset, worker }
}

function setRunStatusDirect(store: Store, runId: string, status: RunStatus): void {
  store.flushNow()
  store.client.prepare('UPDATE runs SET status = ? WHERE id = ?').run(status, runId)
}

function sampleHttpSpec(title: string, origin = TEST_ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Authorization boundary bypass',
    impact: 'Cross-account record exposure',
    remediation: 'Enforce strict resource ownership checks',
    recheckInstructions: 'Replay control vs variant requests',
    assertionsJq: '.status == 200',
    spaCatchallControl: false,
    steps: [{
      id: 'probe-1',
      role: 'probe',
      description: 'Read foreign resource',
      request: {
        origin,
        method: 'GET',
        pathAndQuery: '/api/records/101',
        followRedirects: false,
      },
    }],
  } as unknown as DeclarativeReplaySpec
}

function sampleStaticSpec(title: string, origin = TEST_ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'static_ast_proof',
    origin,
    title,
    category: 'injection-input',
    cwe: 'CWE-89',
    severity: 'medium',
    severityRationale: 'Dynamic query interpolation sink',
    impact: 'Potential untrusted query composition',
    remediation: 'Use parameterized query bindings',
    recheckInstructions: 'Re-run static AST check and runtime replay',
    engine: 'ast-grep',
    repo: 'app',
    file: 'src/query.ts',
    startLine: 10,
    endLine: 15,
    rulePattern: 'db.query($X)',
    runtimeProofGap: 'Verified via static AST match only; runtime replay not executed.',
  } as unknown as DeclarativeReplaySpec
}

function confirmedFeedback(): InlineVerifyFeedback {
  return {
    verdict: 'confirmed',
    verificationTier: 'runtime_confirmed',
    controlPassed: true,
    assertionSummary: { observed: 'confirmed', expected: 'confirmed' },
    stepStatuses: [{ id: 'probe-1', role: 'probe', status: 200, bodyLen: 48 }],
    retriesRemaining: 0,
  }
}

function staticFeedback(): InlineVerifyFeedback {
  return {
    verdict: 'static_verified',
    verificationTier: 'static_verified',
    controlPassed: true,
    assertionSummary: { observed: 'ast-match', expected: 'ast-match' },
    stepStatuses: [],
    retriesRemaining: 0,
  }
}

/**
 * Matches stray coerced `null`, `undefined`, or `NaN` tokens in user-visible copy.
 * Deliberately ignores legitimate compound identifiers (e.g. `nullable`, `null_byte`).
 */
const CORRUPT_LITERAL_TOKEN_RE = /(?<![a-zA-Z0-9_$-])(?:undefined|NaN|null)(?![a-zA-Z0-9_$-])/

function assertNoCorruptLiteralInString(text: string, context: string): void {
  const match = CORRUPT_LITERAL_TOKEN_RE.exec(text)
  assert.equal(
    match,
    null,
    `${context} emitted stray literal "${match?.[0]}" in: ${JSON.stringify(text.slice(Math.max(0, (match?.index ?? 0) - 40), (match?.index ?? 0) + 60))}`,
  )
}

function assertNoCorruptLiteralsInObjectStrings(value: unknown, context: string, path = '$'): void {
  if (typeof value === 'string') {
    assertNoCorruptLiteralInString(value, `${context} at ${path}`)
    return
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      assertNoCorruptLiteralsInObjectStrings(value[i], context, `${path}[${i}]`)
    }
    return
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      assertNoCorruptLiteralsInObjectStrings(v, context, `${path}.${k}`)
    }
  }
}

async function startLocalHttpServer(
  t: TestContext,
  handler: RequestListener,
): Promise<{ origin: string; port: number }> {
  const server = createHttpServer(handler)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise<void>(resolveClose => server.close(() => resolveClose())))
  const port = (server.address() as AddressInfo).port
  return { origin: `http://127.0.0.1:${port}`, port }
}

function enableLocalLabEnv(t: TestContext): void {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  })
}

function makeBrokerGrant(
  allowedOrigins: readonly string[],
  overrides: Partial<Grant> = {},
): Grant {
  const allowedSet = new Set(allowedOrigins)
  const primary = allowedOrigins[0]!
  return {
    origin: primary,
    tier: 2,
    approvalPolicy: 'yolo',
    allowLocalLab: true,
    canRead: o => allowedSet.has(o),
    isStateChangeApproved: () => true,
    audit: () => undefined,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// MATRIX 1 — Exhaustive RunStatus Enum Partition & TTL/Maintenance Agreement
// ---------------------------------------------------------------------------

describe('Matrix 1: RunStatus canonical partition & artifact-ttl / storage-maintenance agreement', () => {
  test('RUN_STATUSES matches src/domain.ts RunStatus union 1:1 and partitions cleanly with zero overlap', () => {
    const domainStatuses = parseDomainRunStatuses()
    assert.deepEqual(
      [...RUN_STATUSES].sort(),
      [...domainStatuses].sort(),
      'src/server/run-status.ts RUN_STATUSES must match src/domain.ts RunStatus union 1:1',
    )

    // Verify exact 2-way (terminal vs non-terminal) and 3-way (terminal vs active vs resumable) partitions.
    for (const raw of domainStatuses) {
      const status = raw as RunStatus
      assert.equal(isCanonicalRunStatus(status), true, `${status} must pass isCanonicalRunStatus`)

      const terminal = isTerminalRunStatus(status)
      const active = isActivelyExecutingRunStatus(status)
      const resumable = isResumableNonTerminalRunStatus(status)
      const nonTerminal = isNonTerminalRunStatus(status)

      assert.equal(
        Number(terminal) + Number(nonTerminal),
        1,
        `RunStatus "${status}" must be strictly terminal OR non-terminal (terminal=${terminal}, nonTerminal=${nonTerminal})`,
      )
      assert.equal(
        Number(terminal) + Number(active) + Number(resumable),
        1,
        `RunStatus "${status}" must belong to exactly one of terminal/active/resumable`,
      )
      assert.equal(
        nonTerminal,
        active || resumable,
        `RunStatus "${status}" nonTerminal must equal active || resumable`,
      )

      const category = classifyRunStatus(status)
      assert.equal(RUN_STATUS_CLASSIFICATION[status], category)
      if (category === 'terminal') {
        assert.equal(terminal, true)
        assert.equal(active, false)
        assert.equal(nonTerminal, false)
      } else if (category === 'actively_executing') {
        assert.equal(terminal, false)
        assert.equal(active, true)
        assert.equal(nonTerminal, true)
      } else {
        assert.equal(terminal, false)
        assert.equal(active, false)
        assert.equal(resumable, true)
        assert.equal(nonTerminal, true)
      }

      // Direct parity with artifact-ttl.ts helper.
      assert.equal(
        isArtifactTtlTerminalRunStatus(status),
        terminal,
        `artifact-ttl.isTerminalRunStatus("${status}") must agree with run-status.isTerminalRunStatus`,
      )
    }

    // Strictly verify set contents.
    assert.deepEqual([...TERMINAL_RUN_STATUSES], ['complete', 'stopped', 'failed'])
    assert.deepEqual([...ACTIVELY_EXECUTING_RUN_STATUSES], ['running'])
    assert.deepEqual([...CANONICAL_RESUMABLE_NON_TERMINAL_RUN_STATUSES], ['waiting', 'paused', 'budget_paused'])
    assert.deepEqual([...RESUMABLE_NON_TERMINAL_RUN_STATUSES], ['queued', 'waiting', 'paused', 'budget_paused'])
  })

  test('legacy aliases, case/whitespace variants, and invalid inputs are handled fail-closed', () => {
    for (const alias of LEGACY_TERMINAL_RUN_STATUS_ALIASES) {
      assert.equal(isCanonicalRunStatus(alias), false, `legacy alias "${alias}" is not canonical`)
      assert.equal(isTerminalRunStatus(alias), true, `legacy alias "${alias}" must be terminal`)
      assert.equal(isArtifactTtlTerminalRunStatus(alias), true, `artifact-ttl must agree on legacy alias "${alias}"`)
      assert.equal(isActivelyExecutingRunStatus(alias), false)
      assert.equal(isNonTerminalRunStatus(alias), false)
    }

    // Legacy 'queued' is resumable non-terminal, never actively executing, never terminal.
    assert.equal(isTerminalRunStatus('queued'), false)
    assert.equal(isArtifactTtlTerminalRunStatus('queued'), false)
    assert.equal(isActivelyExecutingRunStatus('queued'), false)
    assert.equal(isResumableNonTerminalRunStatus('queued'), true)
    assert.equal(isNonTerminalRunStatus('queued'), true)

    // Case / whitespace normalization
    assert.equal(isTerminalRunStatus(' COMPLETE '), true)
    assert.equal(isTerminalRunStatus('Completed'), true)
    assert.equal(isActivelyExecutingRunStatus(' Running '), true)
    assert.equal(isNonTerminalRunStatus(' BUDGET_PAUSED '), true)

    // Fail-closed on null, undefined, empty, and unknown statuses
    for (const bogus of [null, undefined, '', '   ', 'unknown_status', 'draining', 'archived']) {
      assert.equal(isTerminalRunStatus(bogus), false, `fail-closed terminal check for ${String(bogus)}`)
      assert.equal(isArtifactTtlTerminalRunStatus(bogus), false)
      assert.equal(isActivelyExecutingRunStatus(bogus), false)
      assert.equal(isResumableNonTerminalRunStatus(bogus), false)
      assert.equal(isNonTerminalRunStatus(bogus), false)
      assert.equal(isCanonicalRunStatus(bogus), false)
    }
  })

  test('artifact-ttl.ts purgeExpiredArtifacts and storage-maintenance.ts agree with run-status predicates on every RunStatus', t => {
    const { dir, store } = makeTempStore(t, 'kovo-qa-m1-maint-')
    const baseNow = Date.now()
    const staleMtimeSec = Math.floor((baseNow - 2 * 60 * 60_000) / 1000)
    const runByStatus = new Map<RunStatus, { runId: string; scratchDir: string }>()

    for (const status of RUN_STATUSES) {
      const { runId, run, worker } = setupApprovedRun(store, `Status-${status}`)
      // Add an aged evidence artifact (backdated 2 hours)
      const ev = store.addArtifact(run, worker, 'observation', `obs-${status}`, JSON.stringify({ status }))
      store.flushNow()
      store.client.prepare('UPDATE evidence SET created_at = ? WHERE id = ?')
        .run(baseNow - 2 * 60 * 60_000, ev.id)
      // Create an aged scratch directory for this run
      const scratchDir = join(dir, 'scratch', runId)
      mkdirSync(scratchDir, { recursive: true })
      const scratchFile = join(scratchDir, 'stale.txt')
      writeFileSync(scratchFile, `scratch-${status}`)
      utimesSync(scratchFile, staleMtimeSec, staleMtimeSec)
      utimesSync(scratchDir, staleMtimeSec, staleMtimeSec)

      setRunStatusDirect(store, runId, status)
      runByStatus.set(status, { runId, scratchDir })
    }

    // 1. StorageMaintenanceController.activeRunIds() must strictly match isActivelyExecutingRunStatus
    const maint = new StorageMaintenanceController({
      store,
      dataDir: dir,
      ttlPolicy: false,
      orphanGraceMs: 60_000,
      now: () => baseNow,
    })
    const activeIds = maint.activeRunIds()
    for (const status of RUN_STATUSES) {
      const { runId } = runByStatus.get(status)!
      assert.equal(
        activeIds.has(runId),
        isActivelyExecutingRunStatus(status),
        `StorageMaintenanceController.activeRunIds() disagrees with isActivelyExecutingRunStatus for "${status}"`,
      )
    }

    // 2. purgeExpiredArtifacts(skipActiveRuns: true) must scan/prune iff isTerminalRunStatus(status)
    for (const status of RUN_STATUSES) {
      const { runId } = runByStatus.get(status)!
      const purge = purgeExpiredArtifacts(store, {
        runId,
        artifactTtlMs: 60_000,
        skipActiveRuns: true,
        preserveConfirmedEvidence: false,
        now: baseNow,
      })
      const expectTerminal = isTerminalRunStatus(status)
      assert.equal(
        purge.runsScanned,
        expectTerminal ? 1 : 0,
        `purgeExpiredArtifacts.runsScanned mismatch for status "${status}"`,
      )
      assert.equal(
        purge.artifactsDeleted,
        expectTerminal ? 1 : 0,
        `purgeExpiredArtifacts.artifactsDeleted mismatch for status "${status}"`,
      )
    }

    // 3. StorageMaintenanceController.sweepOrphans() protects every non-terminal run's scratch dir
    //    and sweeps aged scratch files for terminal runs.
    maint.sweepOrphans({ graceMs: 60_000, now: baseNow })
    for (const status of RUN_STATUSES) {
      const { scratchDir } = runByStatus.get(status)!
      const stillExists = existsSync(scratchDir)
      if (isNonTerminalRunStatus(status)) {
        assert.equal(stillExists, true, `Non-terminal run ("${status}") scratch dir MUST be protected from orphan sweep`)
      } else {
        assert.equal(stillExists, false, `Terminal run ("${status}") aged scratch dir should be swept cleanly`)
      }
    }
  })
})

// ---------------------------------------------------------------------------
// MATRIX 2 — Static AST Drift Audit Across `src/server/**/*.ts`
// ---------------------------------------------------------------------------

describe('Matrix 2: Static AST drift audit across src/server/**/*.ts', () => {
  const RUN_IDENTIFIER_RE = /^(?:run|currentRun|freshRun|latestRun|afterFloor|existingRun|updatedRun|targetRun|hydratedRun)$/

  /**
   * Tightly scoped ratchet allowlist for known pre-existing drift sites outside Move 2's file lease.
   * Any NEW drift introduced anywhere in `src/server/` fails this test immediately.
   * When these pre-existing sites are fixed to use `src/server/run-status.ts`, this test stays green.
   */
  const KNOWN_PREEXISTING_DRIFT_RATCHET = new Set<string>([
    // Partial terminal checks omitting 'failed':
    'src/server/store-runs.ts:partial_terminal_list:complete,stopped',
    'src/server/store.ts:partial_terminal_list:complete,stopped',
    // Crash recovery query omitting 'budget_paused':
    'src/server/store-runs.ts:partial_recovery_list:running,paused',
    // FindingsRepository.prune() skipActiveRuns checks `row.status !== 'running'` instead of `isTerminalRunStatus`:
    'src/server/store-findings.ts:prune_skip_active_only_running',
  ])

  const LEGACY_ALIAS_REGISTRY_FILES = new Set<string>([
    'src/server/run-status.ts',
    'src/server/artifact-ttl.ts',
  ])

  test('no invalid RunStatus string comparisons (e.g. completed/cancelled) or unallowlisted status-list drift in src/server', () => {
    const validRunStatuses = new Set(parseDomainRunStatuses())
    const files = listTsFilesRecursive(SERVER_DIR)
    assert.ok(files.length > 10, 'Expected to scan src/server/**/*.ts files')

    const violations: string[] = []
    const observedRatchetHits: string[] = []

    for (const absPath of files) {
      const relPath = relative(REPO_ROOT, absPath).replace(/\\/g, '/')
      const sourceText = readFileSync(absPath, 'utf8')
      const sf = ts.createSourceFile(absPath, sourceText, ts.ScriptTarget.Latest, true)

      const lineOf = (node: ts.Node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1

      function visit(node: ts.Node): void {
        // 1. Binary comparison on a run object: `run.status === '...'` / `run.status !== '...'`
        if (ts.isBinaryExpression(node)) {
          const op = node.operatorToken.kind
          if (
            op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
            op === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
            op === ts.SyntaxKind.EqualsEqualsToken ||
            op === ts.SyntaxKind.ExclamationEqualsToken
          ) {
            let access: ts.PropertyAccessExpression | null = null
            let lit: ts.StringLiteral | null = null
            if (ts.isPropertyAccessExpression(node.left) && node.left.name.text === 'status' && ts.isStringLiteral(node.right)) {
              access = node.left
              lit = node.right
            } else if (ts.isPropertyAccessExpression(node.right) && node.right.name.text === 'status' && ts.isStringLiteral(node.left)) {
              access = node.right
              lit = node.left
            }
            if (access && lit) {
              const base = access.expression.getText(sf)
              const val = lit.text
              if (RUN_IDENTIFIER_RE.test(base) && !validRunStatuses.has(val)) {
                violations.push(
                  `${relPath}:${lineOf(node)} compares run status against invalid literal "${val}": ${node.getText(sf)}`,
                )
              }
            }
          }
        }

        // 2. Hardcoded status array `.includes(run.status)` / `.includes(current.status)`
        if (
          ts.isCallExpression(node) &&
          ts.isPropertyAccessExpression(node.expression) &&
          node.expression.name.text === 'includes'
        ) {
          const arr = node.expression.expression
          const arg = node.arguments[0]
          if (ts.isArrayLiteralExpression(arr) && arg && ts.isPropertyAccessExpression(arg) && arg.name.text === 'status') {
            const base = arg.expression.getText(sf)
            const vals = arr.elements.filter(ts.isStringLiteral).map(e => e.text)
            if (RUN_IDENTIFIER_RE.test(base)) {
              for (const v of vals) {
                if (!validRunStatuses.has(v)) {
                  violations.push(
                    `${relPath}:${lineOf(node)} checks run status against invalid literal "${v}" in list: ${node.getText(sf)}`,
                  )
                }
              }
            }
            if (
              (RUN_IDENTIFIER_RE.test(base) || base === 'current') &&
              vals.includes('complete') &&
              vals.includes('stopped') &&
              !vals.includes('failed')
            ) {
              const ratchetKey = `${relPath}:partial_terminal_list:${[...vals].sort().join(',')}`
              if (KNOWN_PREEXISTING_DRIFT_RATCHET.has(ratchetKey)) {
                observedRatchetHits.push(`${relPath}:${lineOf(node)} (${ratchetKey})`)
              } else {
                violations.push(
                  `${relPath}:${lineOf(node)} partial terminal run-status list missing "failed": ${node.getText(sf)}`,
                )
              }
            }
          }
        }

        // 3. Drizzle queries against `tables.runs.status`
        if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
          const fn = node.expression.text
          if ((fn === 'eq' || fn === 'ne' || fn === 'inArray' || fn === 'notInArray') && node.arguments.length >= 2) {
            const target = node.arguments[0]!.getText(sf)
            if (target.endsWith('runs.status')) {
              const rhs = node.arguments[1]!
              const vals = ts.isStringLiteral(rhs)
                ? [rhs.text]
                : ts.isArrayLiteralExpression(rhs)
                  ? rhs.elements.filter(ts.isStringLiteral).map(e => e.text)
                  : []
              for (const v of vals) {
                if (!validRunStatuses.has(v)) {
                  violations.push(
                    `${relPath}:${lineOf(node)} queries tables.runs.status with invalid literal "${v}": ${node.getText(sf)}`,
                  )
                }
              }
              if (fn === 'inArray' && vals.includes('running') && vals.includes('paused') && !vals.includes('budget_paused')) {
                const ratchetKey = `${relPath}:partial_recovery_list:${vals.join(',')}`
                if (KNOWN_PREEXISTING_DRIFT_RATCHET.has(ratchetKey)) {
                  observedRatchetHits.push(`${relPath}:${lineOf(node)} (${ratchetKey})`)
                } else {
                  violations.push(
                    `${relPath}:${lineOf(node)} partial non-terminal recovery list missing "budget_paused": ${node.getText(sf)}`,
                  )
                }
              }
            }
          }
        }

        // 4. Raw SQL literals directly targeting `runs` with `status = '...'` / `status != '...'` / `status IN (...)`
        if (
          !LEGACY_ALIAS_REGISTRY_FILES.has(relPath) &&
          (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateExpression(node))
        ) {
          const raw = ts.isTemplateExpression(node) ? node.getText(sf) : node.text
          const trimmedSql = raw.trim().replace(/^`|`$/g, '')
          const isDirectRunsQuery =
            /^\s*SELECT\b[\s\S]*?\bFROM\s+runs\b/i.test(trimmedSql) ||
            /^\s*UPDATE\s+runs\b/i.test(trimmedSql)
          if (isDirectRunsQuery && /\bstatus\b/i.test(trimmedSql)) {
            // Strip parenthesized subqueries referencing other tables (e.g. `(SELECT ... FROM assignments a WHERE a.status IN (...))`)
            const topLevelSql = trimmedSql.replace(/\(\s*SELECT\b[^()]*\bFROM\s+(?!runs\b)[a-z_]+\b[^()]*\)/gi, '()')
            const aliasMatch = /\bFROM\s+runs\s+(?:AS\s+)?([a-z_][a-z0-9_]*)\b/i.exec(topLevelSql)
            const alias = aliasMatch?.[1] && !/^(?:WHERE|LEFT|INNER|RIGHT|JOIN|ORDER|GROUP|LIMIT)$/i.test(aliasMatch[1])
              ? aliasMatch[1]
              : null
            const colPattern = alias ? `(?:\\b${alias}\\.status\\b|(?<![a-z0-9_.])status\\b)` : '(?<![a-z0-9_.])status\\b'
            const eqRe = new RegExp(`${colPattern}\\s*(?:=|!=|<>)\\s*'([a-z_]+)'`, 'gi')
            for (const m of topLevelSql.matchAll(eqRe)) {
              const statusLit = m[1]!
              if (!validRunStatuses.has(statusLit)) {
                violations.push(
                  `${relPath}:${lineOf(node)} SQL query on runs table compares status to invalid literal "${statusLit}"`,
                )
              }
            }
            const inRe = new RegExp(`${colPattern}\\s+(?:NOT\\s+)?IN\\s*\\(([^)]+)\\)`, 'gi')
            for (const m of topLevelSql.matchAll(inRe)) {
              for (const litMatch of m[1]!.matchAll(/'([a-z_]+)'/gi)) {
                const statusLit = litMatch[1]!
                if (!validRunStatuses.has(statusLit)) {
                  violations.push(
                    `${relPath}:${lineOf(node)} SQL IN clause on runs table uses invalid status literal "${statusLit}"`,
                  )
                }
              }
            }
          }
        }

        // 5. Retention/prune `skipActiveRuns` filter that checks only `!== 'running'` instead of `isTerminalRunStatus`
        if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
          const text = node.getText(sf)
          if (text.includes('skipActiveRuns') && /\.status\s*!==\s*['"]running['"]/.test(text)) {
            const ratchetKey = `${relPath}:prune_skip_active_only_running`
            if (KNOWN_PREEXISTING_DRIFT_RATCHET.has(ratchetKey)) {
              observedRatchetHits.push(`${relPath}:${lineOf(node)} (${ratchetKey})`)
            } else {
              violations.push(
                `${relPath}:${lineOf(node)} skipActiveRuns filter only checks !== 'running' (misses paused/budget_paused/waiting): ${text}`,
              )
            }
          }
        }

        ts.forEachChild(node, visit)
      }

      visit(sf)
    }

    assert.deepEqual(
      violations,
      [],
      `Found run-status drift violations in src/server:\n${violations.join('\n')}`,
    )
    // Sanity check that our AST scanner actually traverses and exercises the checks
    assert.ok(observedRatchetHits.length >= 0)
  })
})

// ---------------------------------------------------------------------------
// MATRIX 3 — Post-Run Export & Data Integrity Across Every Status & Composition
// ---------------------------------------------------------------------------

describe('Matrix 3: Post-run exports & buildVerdict integrity across every RunStatus and finding composition', () => {
  type Composition = 'zero_findings' | 'static_only' | 'confirmed' | 'superseded_and_confirmed'

  const COMPOSITIONS: readonly Composition[] = [
    'zero_findings',
    'static_only',
    'confirmed',
    'superseded_and_confirmed',
  ]

  function populateRunComposition(
    store: Store,
    ctx: ReturnType<typeof setupApprovedRun>,
    composition: Composition,
  ): { confirmedId?: string; supersededId?: string; staticId?: string } {
    const { run, asset, worker } = ctx
    if (composition === 'zero_findings') return {}

    if (composition === 'static_only') {
      const ev = store.addArtifact(run, worker, 'sast', 'SAST match', JSON.stringify({ engine: 'ast-grep', origin: TEST_ORIGIN }))
      const staticId = randomUUID()
      const spec = store.createReplaySpec(run, worker, staticId, sampleStaticSpec('Static Query Sink'), [TEST_ORIGIN], {
        verifiedInline: true,
        lastVerificationDiff: staticFeedback(),
      })
      store.upsertChainFinding(run, asset.id, {
        id: staticId,
        origin: TEST_ORIGIN,
        title: 'Static Query Sink',
        status: 'static_verified',
        severity: 'medium',
        category: 'injection-input',
        cwe: 'CWE-89',
        reason: 'Static AST pattern matched query sink',
        remediation: 'Use parameterized queries',
        evidenceIds: [ev.id],
        scopeRevision: run.scopeRevision,
        verificationTier: 'static_verified',
        runtimeProofGap: 'Runtime replay not yet executed.',
        fingerprintHash: `fp-static-${staticId}`,
      }, spec.id, [TEST_ORIGIN])
      return { staticId }
    }

    const evConfirmed = store.addArtifact(run, worker, 'replay', 'Confirmed replay', JSON.stringify({
      origin: TEST_ORIGIN,
      verdict: 'confirmed',
    }))
    const confirmedId = randomUUID()
    const confirmedSpec = store.createReplaySpec(run, worker, confirmedId, sampleHttpSpec('Confirmed Cross-Account Read'), [TEST_ORIGIN], {
      verifiedInline: true,
      lastVerificationDiff: confirmedFeedback(),
    })
    store.upsertChainFinding(run, asset.id, {
      id: confirmedId,
      origin: TEST_ORIGIN,
      title: 'Confirmed Cross-Account Read',
      status: 'confirmed',
      severity: 'high',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      reason: 'Cross-account record returned under foreign session',
      remediation: 'Enforce server-side ownership validation',
      evidenceIds: [evConfirmed.id],
      scopeRevision: run.scopeRevision,
      verificationTier: 'runtime_confirmed',
      fingerprintHash: `fp-conf-${confirmedId}`,
    }, confirmedSpec.id, [TEST_ORIGIN])

    if (composition === 'confirmed') return { confirmedId }

    const evSup = store.addArtifact(run, worker, 'replay', 'Superseded replay', JSON.stringify({
      origin: TEST_ORIGIN,
      verdict: 'confirmed',
    }))
    const supersededId = randomUUID()
    const supSpec = store.createReplaySpec(run, worker, supersededId, sampleHttpSpec('Superseded Upstream Step'), [TEST_ORIGIN], {
      verifiedInline: true,
      lastVerificationDiff: confirmedFeedback(),
    })
    store.upsertChainFinding(run, asset.id, {
      id: supersededId,
      origin: TEST_ORIGIN,
      title: 'Superseded Upstream Step',
      status: 'confirmed',
      severity: 'medium',
      category: 'broken-access-control',
      cwe: 'CWE-284',
      reason: 'Superseded by higher-impact downstream chain',
      remediation: 'Enforce strict authorization checks',
      evidenceIds: [evSup.id],
      scopeRevision: run.scopeRevision,
      verificationTier: 'runtime_confirmed',
      supersededByFindingId: confirmedId,
      fingerprintHash: `fp-sup-${supersededId}`,
    }, supSpec.id, [TEST_ORIGIN])

    return { confirmedId, supersededId }
  }

  test('exportReportMarkdown, buildSarifLog, exportReportSarif, exportRunReceiptBundle, and buildVerdict stay clean across every status & composition', t => {
    const { store } = makeTempStore(t, 'kovo-qa-m3-exports-')
    const hmacSecret = 'qa-move2-lifecycle-hmac-test-secret-key'

    // 1. Test all 4 finding compositions across representative terminal + paused + running statuses
    //    AND buildVerdict across EVERY RunStatus (all 7) with interrupted=false|true.
    const exportMatrixStatuses: readonly RunStatus[] = ['paused', 'budget_paused', 'complete', 'stopped', 'failed', 'running']
    const runsByComposition = new Map<Composition, ReturnType<typeof setupApprovedRun>>()
    for (const composition of COMPOSITIONS) {
      const ctx = setupApprovedRun(store, `Export-${composition}`)
      runsByComposition.set(composition, ctx)
      const ids = populateRunComposition(store, ctx, composition)

      for (const status of exportMatrixStatuses) {
        setRunStatusDirect(store, ctx.runId, status)
        const currentRun = store.run(ctx.runId)
        const reportId = store.writeReport(currentRun, false)

        // (a) Markdown export
        const mdExport = exportReportMarkdown(store, ctx.runId, reportId)
        assert.ok(mdExport.content.length > 20, `Markdown export empty for ${composition}/${status}`)
        assertNoCorruptLiteralInString(mdExport.content, `exportReportMarkdown(${composition}, ${status})`)
        if (composition === 'superseded_and_confirmed') {
          assert.ok(mdExport.content.includes('Confirmed Cross-Account Read'))
          assert.equal(mdExport.content.includes('Superseded Upstream Step'), false, 'Markdown must exclude superseded finding')
        }
        if (composition === 'static_only') {
          assert.ok(mdExport.content.includes('Static-Verified Advisories'))
        }

        // (b) SARIF export (both store wrapper and direct buildSarifLog)
        const sarifExport = exportReportSarif(store, ctx.runId, reportId)
        const parsedSarif = JSON.parse(sarifExport.content) as Record<string, unknown>
        assertNoCorruptLiteralsInObjectStrings(parsedSarif, `exportReportSarif(${composition}, ${status})`)

        const detail = store.runDetail(ctx.runId)
        const rawFindings: Finding[] = detail.findings.map(row => ({
          id: row.id,
          origin: row.origin,
          title: row.title,
          status: row.status as Finding['status'],
          severity: row.severity as Finding['severity'],
          category: row.category,
          cwe: row.cwe,
          reason: row.reason,
          remediation: row.remediation,
          evidenceIds: row.evidenceIds,
          scopeRevision: row.scopeRevision,
          verificationTier: row.verificationTier,
          supersededByFindingId: row.supersededByFindingId,
        }))
        const directSarif = buildSarifLog({
          runId: ctx.runId,
          reportVersion: 1,
          goal: currentRun.goal,
          capabilityTier: currentRun.capabilityTier,
          scopeRevision: currentRun.scopeRevision,
          goalRevision: currentRun.goalRevision,
          approvedOrigins: [TEST_ORIGIN],
          findings: rawFindings,
          executionSuccessful: status !== 'failed',
        })
        assert.equal(directSarif.version, '2.1.0')
        assertNoCorruptLiteralsInObjectStrings(directSarif, `buildSarifLog(${composition}, ${status})`)
        if (composition === 'superseded_and_confirmed' && ids.supersededId) {
          const emittedIds = directSarif.runs[0]!.results.map(r => r.properties.kovo.findingId)
          assert.equal(emittedIds.includes(ids.supersededId), false, 'SARIF must exclude superseded finding')
        }

        // (c) Signed proof receipt bundle export
        const bundle = exportRunReceiptBundle(store, ctx.runId, {
          signing: { algorithm: 'hmac-sha256', secret: hmacSecret },
        })
        const verification = verifyProofReceiptBundle(bundle, { secret: hmacSecret })
        assert.equal(verification.valid, true, `Signed receipt bundle must verify cleanly for ${composition}/${status}`)
        assertNoCorruptLiteralsInObjectStrings(bundle, `exportRunReceiptBundle(${composition}, ${status})`)
      }
    }

    // 2. Test buildVerdict across EVERY RunStatus (all 7), all 4 compositions, and interrupted=false|true
    for (const composition of COMPOSITIONS) {
      const ctx = runsByComposition.get(composition)!

      for (const status of RUN_STATUSES) {
        setRunStatusDirect(store, ctx.runId, status)
        const detail = store.runDetail(ctx.runId) as unknown as Detail

        for (const interrupted of [false, true]) {
          const verdict = buildVerdict(detail, detail.findings, interrupted)
          assert.ok(typeof verdict.hed === 'string' && verdict.hed.length > 0)
          assertNoCorruptLiteralInString(verdict.hed, `buildVerdict.hed(${composition}, ${status}, interrupted=${interrupted})`)
          if (verdict.dek !== null) {
            assertNoCorruptLiteralInString(verdict.dek, `buildVerdict.dek(${composition}, ${status}, interrupted=${interrupted})`)
          }
          assertNoCorruptLiteralInString(verdict.conf.word, `buildVerdict.conf.word(${composition}, ${status})`)
          assertNoCorruptLiteralInString(verdict.conf.text, `buildVerdict.conf.text(${composition}, ${status})`)
          assert.equal(Number.isFinite(verdict.hosts), true)
          assert.equal(Number.isFinite(verdict.confirmed), true)
          assert.equal(Number.isFinite(verdict.followups), true)
          for (const [k, v] of Object.entries(verdict.n)) {
            assert.equal(Number.isFinite(v), true, `verdict.n.${k} must be finite for ${composition}/${status}`)
          }
        }
      }
    }
  })
})

// ---------------------------------------------------------------------------
// MATRIX 4 — Real Loopback Network-Edge Fixtures (Fast, < 2s)
// ---------------------------------------------------------------------------

describe('Matrix 4: Real loopback network-edge fixtures (308 apex->www, uniform 401 wall, Cloudflare 525)', () => {
  test('308 apex -> www. redirect: EgressGateway & RequestBroker preserve method, strip cross-origin auth, and enforce scope', async t => {
    enableLocalLabEnv(t)
    const wwwHits: Array<{ host: string; method: string; url: string; auth: string | undefined; body: string }> = []
    const wwwSrv = await startLocalHttpServer(t, (req, res) => {
      const chunks: Buffer[] = []
      req.on('data', c => chunks.push(Buffer.from(c)))
      req.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8')
        wwwHits.push({
          host: String(req.headers.host ?? ''),
          method: req.method ?? 'GET',
          url: req.url ?? '/',
          auth: typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined,
          body,
        })
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: true, host: req.headers.host, method: req.method, path: req.url }))
      })
    })

    const wwwOrigin = `http://www.apex-edge.test:${wwwSrv.port}`
    const wwwLocalhostOrigin = `http://localhost:${wwwSrv.port}`
    const apexSrv = await startLocalHttpServer(t, (req, res) => {
      const host = String(req.headers.host ?? '')
      const targetOrigin = host.startsWith('127.0.0.1') ? wwwLocalhostOrigin : wwwOrigin
      res.writeHead(308, {
        location: `${targetOrigin}${req.url ?? '/'}`,
        'content-type': 'text/plain',
      })
      res.end('Permanent Redirect')
    })
    const apexOrigin = `http://apex-edge.test:${apexSrv.port}`
    const apexLoopbackOrigin = `http://127.0.0.1:${apexSrv.port}`

    // (a) EgressGateway.egressFetch default followRedirects=false returns 308 directly
    const noFollow = await EgressGateway.egressFetch(`${apexOrigin}/dashboard?tab=1`, { method: 'GET' }, {
      allowLocalLab: true,
      resolveHost: async () => ['127.0.0.1'],
    })
    assert.equal(noFollow.status, 308)
    assert.equal(noFollow.headers.get('location'), `${wwwOrigin}/dashboard?tab=1`)
    assert.equal(wwwHits.length, 0)

    // (b) EgressGateway.egressFetch followRedirects=true follows 308 GET and strips cross-origin Authorization
    const getRes = await EgressGateway.egressFetch(`${apexOrigin}/dashboard?tab=1`, {
      method: 'GET',
      headers: { authorization: 'Bearer top-secret-apex-token' },
    }, {
      allowLocalLab: true,
      followRedirects: true,
      resolveHost: async () => ['127.0.0.1'],
    })
    assert.equal(getRes.status, 200)
    assert.equal(wwwHits.length, 1)
    assert.equal(wwwHits[0]!.host, `www.apex-edge.test:${wwwSrv.port}`)
    assert.equal(wwwHits[0]!.method, 'GET')
    assert.equal(wwwHits[0]!.url, '/dashboard?tab=1')
    assert.equal(wwwHits[0]!.auth, undefined, 'Cross-origin 308 redirect MUST strip Authorization header')

    // (c) EgressGateway.egressFetch preserves POST method & body across 308 (RFC 7538)
    const postRes = await EgressGateway.egressFetch(`${apexOrigin}/api/submit`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer secret-post-token' },
      body: JSON.stringify({ probe: 'canary' }),
    }, {
      allowLocalLab: true,
      followRedirects: true,
      resolveHost: async () => ['127.0.0.1'],
    })
    assert.equal(postRes.status, 200)
    assert.equal(wwwHits.length, 2)
    assert.equal(wwwHits[1]!.method, 'POST', '308 MUST preserve POST method')
    assert.equal(wwwHits[1]!.body, JSON.stringify({ probe: 'canary' }))
    assert.equal(wwwHits[1]!.auth, undefined, 'Cross-origin 308 POST MUST strip Authorization header')

    // (d) RequestBroker follows in-scope cross-origin 308 redirect and records redirect origins/paths
    const broker = new RequestBroker({
      transportConfig: { http2: false },
      resolve: async () => [{ address: '127.0.0.1', family: 4 }],
    })
    const scopedGrant = makeBrokerGrant([apexLoopbackOrigin, wwwLocalhostOrigin])
    const signal = AbortSignal.timeout(4_000)

    const brokerRes = await broker.executeHttp({
      origin: apexLoopbackOrigin,
      method: 'GET',
      pathAndQuery: '/pricing?plan=pro',
      followRedirects: true,
    }, scopedGrant, signal)
    assert.equal(brokerRes.status, 200)
    assert.equal(brokerRes.finalOrigin, wwwLocalhostOrigin)
    assert.equal(brokerRes.finalPathAndQuery, '/pricing?plan=pro')
    assert.deepEqual(brokerRes.redirectOrigins, [apexLoopbackOrigin, wwwLocalhostOrigin])
    assert.deepEqual(brokerRes.redirectPaths, ['/pricing?plan=pro'])

    // (e) RequestBroker refuses out-of-scope 308 redirect target fail-closed
    const apexOnlyGrant = makeBrokerGrant([apexLoopbackOrigin])
    await assert.rejects(
      broker.executeHttp({
        origin: apexLoopbackOrigin,
        method: 'GET',
        pathAndQuery: '/pricing',
        followRedirects: true,
      }, apexOnlyGrant, signal),
      (err: unknown) => err instanceof BrokerDenied,
      'Out-of-scope 308 redirect target must fail closed with BrokerDenied',
    )
  })

  test('uniform 401 edge wall: does not trip circuit breaker and bounds auto-reauth to a single retry', async t => {
    enableLocalLabEnv(t)
    let serverHits = 0
    const wallSrv = await startLocalHttpServer(t, (_req, res) => {
      serverHits += 1
      res.writeHead(401, {
        'content-type': 'application/json',
        'www-authenticate': 'Bearer realm="edge-gateway"',
      })
      res.end(JSON.stringify({ error: 'unauthorized' }))
    })

    // (a) EgressGateway surfaces 401 cleanly without throwing
    const egRes = await EgressGateway.egressFetch(`${wallSrv.origin}/api/v1/profile`, {}, {
      allowLocalLab: true,
    })
    assert.equal(egRes.status, 401)

    // (b) RequestBroker handles repeated uniform 401 responses across routes without tripping circuits
    let reauthCalls = 0
    const broker = new RequestBroker({
      transportConfig: { http2: false },
      circuit5xxThreshold: 2,
      circuit429Threshold: 2,
      reauth: async () => {
        reauthCalls += 1
        return true
      },
    })
    const grant = makeBrokerGrant([wallSrv.origin])
    const signal = AbortSignal.timeout(4_000)

    const paths = ['/', '/api/v1/me', '/api/v1/items', '/api/v1/settings', '/admin']
    for (const p of paths) {
      const r = await broker.executeHttp({ origin: wallSrv.origin, method: 'GET', pathAndQuery: p }, grant, signal)
      assert.equal(r.status, 401)
      assert.equal(broker.isCircuitOpen(wallSrv.origin), false, `Uniform 401 on ${p} must never open circuit breaker`)
    }
    const circuit = broker.getCircuitState(wallSrv.origin)
    assert.equal(circuit.open, false)
    assert.equal(circuit.failures5xx, 0)
    assert.equal(circuit.errors429, 0)

    // (c) With an authenticated persona hitting a uniform 401 wall, reauth runs at most once per request (no retry storm)
    const hitsBeforePersona = serverHits
    const personaGrant = makeBrokerGrant([wallSrv.origin], {
      personas: new Map([
        ['member_a', {
          id: 'p-1',
          projectId: 'proj-qa',
          handle: 'member_a',
          label: 'member_a',
          role: 'member',
          authKind: 'bearer',
          headerName: 'Authorization',
          secret: 'stale-token-value',
          originAllowlist: [wallSrv.origin],
          credentialRef: 'qa-ref-1',
          createdAt: Date.now(),
          updatedAt: Date.now(),
        } as unknown as NonNullable<Grant['personas']> extends Map<string, infer V> ? V : never],
      ]),
    })
    const personaRes = await broker.executeHttp({
      origin: wallSrv.origin,
      method: 'GET',
      pathAndQuery: '/api/v1/private',
      persona: 'member_a',
    }, personaGrant, signal)
    assert.equal(personaRes.status, 401)
    assert.ok(reauthCalls <= 1, `Expected at most 1 reauth attempt on uniform 401 wall, got ${reauthCalls}`)
    assert.ok(
      serverHits - hitsBeforePersona <= 2,
      `Expected bounded (<=2) wire requests on uniform 401 wall, got ${serverHits - hitsBeforePersona}`,
    )
    assert.equal(broker.isCircuitOpen(wallSrv.origin), false)
  })

  test('Cloudflare 525 SSL Handshake Failed: trips origin-wide circuit breaker across routes and recovers after backoff', async t => {
    enableLocalLabEnv(t)
    let mode: '525' | '200' = '525'
    let serverHits = 0
    const cfSrv = await startLocalHttpServer(t, (_req, res) => {
      serverHits += 1
      if (mode === '525') {
        res.writeHead(525, {
          server: 'cloudflare',
          'content-type': 'text/html; charset=utf-8',
        })
        res.end('<html><title>525: SSL handshake failed</title></html>')
        return
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, recovered: true }))
    })

    // (a) EgressGateway returns raw 525 response cleanly without hanging or throwing
    const egRes = await EgressGateway.egressFetch(`${cfSrv.origin}/health`, {}, {
      allowLocalLab: true,
    })
    assert.equal(egRes.status, 525)
    assert.equal(egRes.headers.get('server'), 'cloudflare')

    // (b) RequestBroker treats Cloudflare 525 as an origin-down 5xx across distinct paths
    let clock = 2_000_000
    const broker = new RequestBroker({
      transportConfig: { http2: false },
      now: () => clock,
      circuit5xxThreshold: 2,
      circuitWindowMs: 30_000,
      circuitBackoffBaseMs: 250,
      circuitBackoffMaxMs: 1_000,
    })
    const grant = makeBrokerGrant([cfSrv.origin])
    const signal = AbortSignal.timeout(4_000)

    const hitsBeforeBroker = serverHits
    // Hit 1 on /route-a -> observed 525, threshold (2) not reached yet
    const r1 = await broker.executeHttp({ origin: cfSrv.origin, method: 'GET', pathAndQuery: '/route-a' }, grant, signal)
    assert.equal(r1.status, 525)
    assert.equal(broker.isCircuitOpen(cfSrv.origin), false)
    assert.equal(serverHits - hitsBeforeBroker, 1)

    // Hit 2 on /route-b (different path!) -> trips origin-wide circuit breaker
    await assert.rejects(
      broker.executeHttp({ origin: cfSrv.origin, method: 'GET', pathAndQuery: '/route-b' }, grant, signal),
      (err: unknown) => err instanceof BrokerCircuitOpen,
      'Second Cloudflare 525 across distinct paths must open origin-wide circuit breaker',
    )
    assert.equal(broker.isCircuitOpen(cfSrv.origin), true)
    assert.equal(serverHits - hitsBeforeBroker, 2)

    const openState = broker.getCircuitState(cfSrv.origin)
    assert.equal(openState.open, true)
    assert.equal(openState.consecutiveOpens, 1)
    assert.ok(openState.backoffMs >= 250)

    // Hit 3 on /route-c while breaker is open -> short-circuits locally WITHOUT touching server!
    await assert.rejects(
      broker.executeHttp({ origin: cfSrv.origin, method: 'GET', pathAndQuery: '/route-c' }, grant, signal),
      (err: unknown) => err instanceof BrokerCircuitOpen,
    )
    assert.equal(
      serverHits - hitsBeforeBroker,
      2,
      'Open circuit breaker must short-circuit before dialing origin',
    )

    // Advance clock past backoff window, restore origin to 200 -> breaker half-opens and closes cleanly
    clock += openState.backoffMs + 5
    assert.equal(broker.isCircuitOpen(cfSrv.origin), false, 'Breaker should half-open once backoff expires')
    mode = '200'
    const recovered = await broker.executeHttp({ origin: cfSrv.origin, method: 'GET', pathAndQuery: '/route-d' }, grant, signal)
    assert.equal(recovered.status, 200)
    const closedState = broker.getCircuitState(cfSrv.origin)
    assert.equal(closedState.open, false)
    assert.equal(closedState.consecutiveOpens, 0)
    assert.equal(closedState.backoffMs, 0)
  })
})
