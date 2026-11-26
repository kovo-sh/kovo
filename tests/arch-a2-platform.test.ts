import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'
import { newRun } from '../src/domain.ts'
import { Execution, execution } from '../src/server/execution.ts'
import { LabRunner, bindLabSignalHooks } from '../src/server/lab-runner.ts'
import * as tables from '../src/server/schema.ts'
import { Store, store as defaultStore } from '../src/server/store.ts'
import { installLiveExitHooks } from '../src/server/worker-backend.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function loadRunDataSseHelpers(): {
  SSE_REFRESH_DEBOUNCE_MS: number
  shouldRefreshRunShell: (eventKind: string) => boolean
  sseStreamSinceCursor: (initialCursor: number) => number
} {
  const src = readFileSync(join(REPO_ROOT, 'src', 'components', 'run', 'data.tsx'), 'utf8')
  const startIdx = src.indexOf('export const SSE_REFRESH_DEBOUNCE_MS')
  const endIdx = src.indexOf('export function RunDataProvider(')
  assert.ok(startIdx >= 0 && endIdx > startIdx, 'Expected SSE helpers block in src/components/run/data.tsx')
  const helperSrc = src.slice(startIdx, endIdx)
  const { outputText } = ts.transpileModule(helperSrc, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  })
  const mod = { exports: {} as Record<string, unknown> }
  vm.runInNewContext(outputText, { exports: mod.exports, module: mod })
  return mod.exports as {
    SSE_REFRESH_DEBOUNCE_MS: number
    shouldRefreshRunShell: (eventKind: string) => boolean
    sseStreamSinceCursor: (initialCursor: number) => number
  }
}

function withTempStore(fn: (ctx: { dir: string; store: Store }) => Promise<void> | void) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-arch-a2-'))
    const store = new Store(dir, { ftsMode: 'preview' })
    try {
      await fn({ dir, store })
    } finally {
      store.close()
      rmSync(dir, { recursive: true, force: true })
    }
  }
}

test('LabRunner split-brain eliminated: actions.ts uses execution().labRunner with zero separate instances', withTempStore(({ store }) => {
  const actionsSrc = readFileSync(join(REPO_ROOT, 'src', 'actions.ts'), 'utf8')
  assert.equal(/\bnew\s+LabRunner\s*\(/.test(actionsSrc), false, 'actions.ts must not instantiate a second LabRunner')
  assert.equal(/\bsharedLabRunner\b/.test(actionsSrc), false, 'sharedLabRunner singleton must be removed from actions.ts')
  assert.equal(/execution\(\)\.labRunner|exec\.labRunner/.test(actionsSrc), true, 'actions.ts must read labRunner from execution()')

  // Execution singleton exposes one stable LabRunner instance across calls
  const execDir = mkdtempSync(join(tmpdir(), 'kovo-arch-a2-exec-'))
  const prevDir = process.env.KOVO_DATA_DIR
  process.env.KOVO_DATA_DIR = execDir
  try {
    const execA = execution()
    const execB = execution()
    assert.strictEqual(execA, execB)
    assert.strictEqual(execA.labRunner, execB.labRunner)
    assert.ok(execA.labRunner instanceof LabRunner)
  } finally {
    try { defaultStore().close() } catch { /* ignore */ }
    if (prevDir === undefined) delete process.env.KOVO_DATA_DIR
    else process.env.KOVO_DATA_DIR = prevDir
    rmSync(execDir, { recursive: true, force: true })
  }

  // Explicitly injected LabRunner is also preserved identically on Execution
  const injected = new LabRunner()
  const customExec = new Execution(store, { labRunner: injected })
  assert.strictEqual(customExec.labRunner, injected)
}))

test('actions.ts eliminates 4x duplicate runData queries and all raw SQL preparation', () => {
  const actionsSrc = readFileSync(join(REPO_ROOT, 'src', 'actions.ts'), 'utf8')
  assert.equal(/\.client\.prepare\(/.test(actionsSrc), false, 'actions.ts must not contain raw SQL client.prepare calls')
  assert.equal(/db\.listEndpoints\(/.test(actionsSrc), false, 'runData must not re-query listEndpoints already returned by runDetail')
  assert.equal(/db\.listEndpointParams\(/.test(actionsSrc), false, 'runData must not re-query listEndpointParams already returned by runDetail')
  assert.equal(/db\.listApiDependencies\(/.test(actionsSrc), false, 'runData must not re-query listApiDependencies already returned by runDetail')
  assert.equal(/db\.listLabTelemetry\(/.test(actionsSrc), false, 'runData must not re-query listLabTelemetry already returned by runDetail')
  assert.equal(/db\.workspaceSummary\(/.test(actionsSrc), true, 'workspaceData must delegate to Store.workspaceSummary()')
  assert.equal(/\.runShellSummary\(/.test(actionsSrc), true, 'runShellData must delegate to Store.runShellSummary()')
})

test('Store.workspaceSummary and Store.runShellSummary match expected rollups and exclude superseded findings', withTempStore(({ store }) => {
  const projA = store.createProject({
    requestId: randomUUID(),
    name: 'Alpha App',
    seeds: ['https://alpha.example.com'],
    environment: 'public',
    includeSubdomains: true,
  })
  const projB = store.createProject({
    requestId: randomUUID(),
    name: 'Beta App',
    seeds: ['https://beta.example.com', 'https://api.beta.example.com'],
    environment: 'public',
    includeSubdomains: false,
  })

  const runA1 = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: projA.id,
    goal: 'First alpha sweep',
    capabilityTier: 1,
  }))
  const runA2 = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: projA.id,
    goal: 'Second alpha sweep',
    capabilityTier: 2,
  }))
  const runB1 = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: projB.id,
    goal: 'Beta baseline',
    capabilityTier: 1,
  }))

  // Give deterministic distinct timestamps
  const baseTs = Date.now() - 10_000
  store.client.prepare('UPDATE runs SET created_at = ? WHERE id = ?').run(baseTs, runA1.id)
  store.client.prepare('UPDATE runs SET created_at = ?, status = ?, phase = ? WHERE id = ?').run(baseTs + 1000, 'complete', 'report', runA2.id)
  store.client.prepare('UPDATE runs SET created_at = ? WHERE id = ?').run(baseTs + 2000, runB1.id)

  // Seed an assignment + 2 broker exchanges + 3 extra events on runA2
  const assignmentId = randomUUID()
  store.db.insert(tables.assignments).values({
    id: assignmentId,
    runId: runA2.id,
    phase: 'investigation',
    status: 'complete',
    scopeRevision: 1,
    goalRevision: 1,
    sessionId: `sess-${randomUUID()}`,
    parentFactIds: [],
    sourceOrigins: ['https://alpha.example.com'],
    title: 'Worker',
    objective: 'Check',
    createdAt: baseTs + 1000,
  }).run()
  const exchangeIds: string[] = []
  for (let i = 0; i < 2; i++) {
    const exId = randomUUID()
    exchangeIds.push(exId)
    store.db.insert(tables.brokerExchanges).values({
      id: exId,
      runId: runA2.id,
      assignmentId,
      scopeRevision: 1,
      origin: 'https://alpha.example.com',
      finalOrigin: 'https://alpha.example.com',
      redirectOrigins: [],
      method: 'GET',
      pathAndQuery: `/api/item/${i}`,
      status: 200,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: {},
      bodyPreview: '{}',
      bodySha256: 'abc',
      secretMatches: [],
      durationMs: 5,
      createdAt: baseTs + 1100 + i,
    }).run()
  }

  // Seed findings on runA2: 1 confirmed, 1 static_verified, 1 open, 1 superseded confirmed (must be excluded)
  const insertFinding = (runId: string, origin: string, status: string, supersededBy?: string) => {
    const fid = randomUUID()
    let replaySpecId: string | null = null
    if (status === 'confirmed') {
      replaySpecId = randomUUID()
      store.db.insert(tables.replaySpecs).values({
        id: replaySpecId,
        runId,
        findingId: fid,
        assignmentId,
        scopeRevision: 1,
        goalRevision: 1,
        spec: { version: 1, vulnClass: 'bola', steps: [], assertions: [] } as never,
        specSha256: `sha-${fid}`,
        sourceOrigins: [origin],
        verifiedInline: true,
        lastVerificationDiff: { verdict: 'confirmed' } as never,
        proofKind: 'agent_script',
        proofVerdict: 'confirmed',
        proofReceipt: {
          receipt: {
            vulnClass: 'bola',
            target: { origin },
            exchangeIds: [exchangeIds[0]!],
            oobEventIds: [],
            browserTraceIds: [],
            claimedDelta: 'cross-tenant read',
          },
          verification: {
            confirmed: true,
            vulnClass: 'bola',
            rule: 'bola',
            reason: 'verified',
            observed: '200',
            expected: '403',
          },
        },
        createdAt: baseTs + 1200,
      }).run()
    }
    store.db.insert(tables.findings).values({
      id: fid,
      runId,
      assetId: origin,
      goalRevision: 1,
      checkId: 'chain',
      caseId: fid,
      findingKind: 'multi_step_chain',
      replaySpecId,
      provenance: 'agent_only',
      verificationClass: status === 'confirmed' ? 'runtime_confirmed' : status === 'static_verified' ? 'static_advisory' : 'open_proof_gap',
      sourceOrigins: [origin],
      supersededByFindingId: supersededBy ?? null,
      finding: {
        id: fid,
        title: `Finding ${status}`,
        severity: 'high',
        status,
        summary: 'Summary',
        remediation: 'Fix',
        evidenceIds: [],
      } as never,
    }).run()
    return fid
  }

  const confirmedId = insertFinding(runA2.id, 'https://alpha.example.com', 'confirmed')
  insertFinding(runA2.id, 'https://alpha.example.com', 'static_verified')
  insertFinding(runA2.id, 'https://alpha.example.com', 'open')
  insertFinding(runA2.id, 'https://alpha.example.com', 'confirmed', confirmedId)

  store.event(runA2.id, 'fact.recorded', 'Fact 1')
  store.event(runA2.id, 'fact.recorded', 'Fact 2')

  const ws = store.workspaceSummary()
  assert.equal(ws.workspace.id, store.workspace.id)
  assert.equal(ws.projects.length, 2)

  const summaryA = ws.projects.find(p => p.id === projA.id)!
  assert.equal(summaryA.runCount, 2)
  assert.equal(summaryA.hostCount, 1)
  assert.ok(summaryA.latestRun)
  assert.equal(summaryA.latestRun.id, runA2.id)
  assert.equal(summaryA.latestRun.status, 'complete')
  assert.equal(summaryA.latestRun.phase, 'report')
  assert.equal(summaryA.latestRun.findingCount, 3) // excludes superseded
  assert.equal(summaryA.latestRun.confirmedCount, 1) // runtime_confirmed + confirmed, excludes static_verified, superseded & open

  const summaryB = ws.projects.find(p => p.id === projB.id)!
  assert.equal(summaryB.runCount, 1)
  assert.equal(summaryB.hostCount, 2)
  assert.equal(summaryB.latestRun?.id, runB1.id)
  assert.equal(summaryB.latestRun?.findingCount, 0)
  assert.equal(summaryB.latestRun?.confirmedCount, 0)

  // recentRuns ordered newest first: runB1, runA2, runA1
  assert.deepEqual(ws.recentRuns.map(r => r.id), [runB1.id, runA2.id, runA1.id])
  const recentA2 = ws.recentRuns.find(r => r.id === runA2.id)!
  assert.equal(recentA2.projectName, 'Alpha App')
  assert.equal(recentA2.findings, 3)
  assert.equal(recentA2.confirmedCount, 1)

  // runShellSummary returns all workspace runs newest first + exact exchange & event counts
  const shell = store.runShellSummary(runA2.id)
  assert.deepEqual(shell.runs.map(r => r.id), [runB1.id, runA2.id, runA1.id])
  assert.equal(shell.runs.find(r => r.id === runA2.id)?.findings, 3)
  assert.equal(shell.runs.find(r => r.id === runB1.id)?.projectName, 'Beta App')
  assert.equal(shell.counts.exchanges, 2)
  const expectedEvents = store.client.prepare('SELECT count(*) AS c FROM events WHERE run_id = ?').get(runA2.id) as { c: number }
  assert.equal(shell.counts.events, Number(expectedEvents.c))
  assert.ok(shell.counts.events >= 2)
}))

test('SSE stream helpers debounce refreshes, filter runShellData triggers, and resume from initial cursor', () => {
  const { SSE_REFRESH_DEBOUNCE_MS, shouldRefreshRunShell, sseStreamSinceCursor } = loadRunDataSseHelpers()
  assert.equal(SSE_REFRESH_DEBOUNCE_MS, 350)

  assert.equal(sseStreamSinceCursor(0), 0)
  assert.equal(sseStreamSinceCursor(128), 128)
  assert.equal(sseStreamSinceCursor(-1), 0)
  assert.equal(sseStreamSinceCursor(Number.NaN), 0)

  // Run-status / finding-count-changing events refresh runShellData
  for (const kind of [
    'run.paused',
    'run.resumed',
    'run.budget_paused',
    'run.created',
    'finding.updated',
    'finding.verified',
    'report.complete',
    'report.partial',
    'goal.revised',
    'scope.approved',
    'interrupted',
    'agent.script_proof_confirmed',
    'oob.receipt_confirmed',
  ]) {
    assert.equal(shouldRefreshRunShell(kind), true, `Expected ${kind} to refresh runShellData`)
  }

  // High-frequency telemetry / exchange / worker / planner ticks do NOT refresh runShellData
  for (const kind of [
    'broker.allowed',
    'broker.denied',
    'broker.route_circuit',
    'surface.probe',
    'fact.recorded',
    'board.message',
    'board.wakeup',
    'worker.started',
    'worker.complete',
    'planner.round',
    'phase0.discovery',
    'sast.run',
    'graph.compacted',
  ]) {
    assert.equal(shouldRefreshRunShell(kind), false, `Expected ${kind} NOT to refresh runShellData`)
  }

  const dataSrc = readFileSync(join(REPO_ROOT, 'src', 'components', 'run', 'data.tsx'), 'utf8')
  assert.equal(dataSrc.includes('?since=0'), false, 'EventSource must not hardcode ?since=0')
  assert.equal(dataSrc.includes('?since=${startCursor}'), true, 'EventSource must start from initial cursor')
  assert.equal(dataSrc.includes('clearTimeout(refreshTimer)'), true, 'Debounced refresh timer must be cleared on unmount')
})

test('worker-backend signal handler cleans containers without preempting sibling shutdown listeners', () => {
  // Case 1: Sibling SIGTERM listener registered BEFORE worker-backend hook (e.g. HTTP server + SQLite WAL)
  {
    const emitter = new EventEmitter()
    const order: string[] = []
    let exitCode: number | null = null

    emitter.once('SIGTERM', () => { order.push('server-sqlite-shutdown') })
    const hooks = installLiveExitHooks({
      target: emitter,
      cleanup: budgetMs => { order.push(`worker-cleanup:${budgetMs}`) },
      exit: code => { exitCode = code },
    })

    emitter.emit('SIGTERM')
    hooks.dispose()

    assert.deepEqual(order, ['worker-cleanup:2000', 'server-sqlite-shutdown'])
    assert.equal(exitCode, null, 'must NOT call process.exit when a sibling SIGTERM handler is registered before it')
  }

  // Case 2: Sibling SIGTERM listener registered AFTER worker-backend hook
  {
    const emitter = new EventEmitter()
    const order: string[] = []
    let exitCode: number | null = null

    const hooks = installLiveExitHooks({
      target: emitter,
      cleanup: budgetMs => { order.push(`worker-cleanup:${budgetMs}`) },
      exit: code => { exitCode = code },
    })
    emitter.once('SIGTERM', () => { order.push('late-sibling-shutdown') })

    emitter.emit('SIGTERM')
    hooks.dispose()

    assert.deepEqual(order, ['worker-cleanup:2000', 'late-sibling-shutdown'])
    assert.equal(exitCode, null, 'must NOT call process.exit when a sibling SIGTERM handler is registered after it')
  }

  // Case 3: Sibling SIGINT listener registered -> cleanup runs, no preemptive exit
  {
    const emitter = new EventEmitter()
    const order: string[] = []
    let exitCode: number | null = null

    emitter.once('SIGINT', () => { order.push('sigint-sibling') })
    const hooks = installLiveExitHooks({
      target: emitter,
      cleanup: () => { order.push('worker-cleanup') },
      exit: code => { exitCode = code },
    })

    emitter.emit('SIGINT')
    hooks.dispose()

    assert.deepEqual(order, ['worker-cleanup', 'sigint-sibling'])
    assert.equal(exitCode, null)
  }

  // Case 4: No sibling listener registered -> cleanup runs and exits cleanly with 143 / 130
  {
    const emitter = new EventEmitter()
    const events: string[] = []
    const exitCodes: number[] = []

    const hooks = installLiveExitHooks({
      target: emitter,
      cleanup: () => { events.push('cleanup') },
      exit: code => { exitCodes.push(code) },
    })
    emitter.emit('SIGTERM')
    hooks.dispose()

    assert.deepEqual(events, ['cleanup'])
    assert.deepEqual(exitCodes, [143])
  }
  {
    const emitter = new EventEmitter()
    const exitCodes: number[] = []

    const hooks = installLiveExitHooks({
      target: emitter,
      cleanup: () => {},
      exit: code => { exitCodes.push(code) },
    })
    emitter.emit('SIGINT')
    hooks.dispose()

    assert.deepEqual(exitCodes, [130])
  }

  // Case 5: LabRunner + worker-backend + HTTP/SQLite shutdown all run together with zero preemption
  {
    const emitter = new EventEmitter()
    const order: string[] = []
    let exitCode: number | null = null
    let reraised: string | null = null

    emitter.once('SIGTERM', () => { order.push('http-and-sqlite-close') })
    const workerHooks = installLiveExitHooks({
      target: emitter,
      cleanup: () => { order.push('worker-containers-reaped') },
      exit: code => { exitCode = code },
    })
    const labHooks = bindLabSignalHooks({
      target: emitter,
      reap: () => { order.push('lab-containers-reaped') },
      reraise: sig => { reraised = sig },
    })

    emitter.emit('SIGTERM')
    workerHooks.dispose()
    labHooks.dispose()

    assert.deepEqual(order, ['lab-containers-reaped', 'worker-containers-reaped', 'http-and-sqlite-close'])
    assert.equal(exitCode, null)
    assert.equal(reraised, null)
  }

  // Case 6: LabRunner + worker-backend with NO sibling listener -> BOTH clean up, then last exits cleanly
  {
    const emitter = new EventEmitter()
    const order: string[] = []
    let exitCode: number | null = null
    let reraised: string | null = null

    const workerHooks = installLiveExitHooks({
      target: emitter,
      cleanup: () => { order.push('worker-containers-reaped') },
      exit: code => { exitCode = code },
    })
    const labHooks = bindLabSignalHooks({
      target: emitter,
      reap: () => { order.push('lab-containers-reaped') },
      reraise: sig => { reraised = sig },
    })

    emitter.emit('SIGTERM')
    workerHooks.dispose()
    labHooks.dispose()

    assert.deepEqual(order, ['lab-containers-reaped', 'worker-containers-reaped'])
    assert.equal(reraised, null, 'lab-runner must not reraise before worker-backend runs')
    assert.equal(exitCode, 143, 'final cleanup listener exits cleanly when no sibling remains')
  }
})
