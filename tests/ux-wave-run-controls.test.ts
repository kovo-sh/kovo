import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import ts from 'typescript'
import { newRun, runCommand } from '../src/domain.ts'
import { WarmSpecialistController } from '../src/server/agent-session.ts'
import { ExecBoardManager } from '../src/server/exec-board.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function makeStore(t: { after(fn: () => void): void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-run-controls-'))
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return store
}

function setupApprovedRun(
  store: Store,
  origins: { origin: string; thirdParty?: boolean }[] = [{ origin: 'https://app.example.test' }],
  approveCount = 1,
) {
  const project = store.createProject({
    requestId: randomUUID(),
    name: `Run Controls ${randomUUID().slice(0, 6)}`,
    seeds: [origins[0]!.origin],
    environment: 'public',
  })
  const { id: runId } = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify run controls, resume semantics, and board wakeups',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 25,
    budgetRequests: 2000,
    maxRpsPerOrigin: 5,
  }))
  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  for (const extra of origins.slice(1)) {
    store.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'candidate',
      candidate: {
        origin: extra.origin,
        source: 'Manual inventory',
        thirdParty: Boolean(extra.thirdParty),
      },
    }))
  }
  const discovered = store.run(runId)
  const assetIds = discovered.candidates.slice(0, approveCount).map(c => c.id)
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds,
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    capabilityTier: 2,
  }))
  store.updateRun(runId, { phase: 'investigation', status: 'running' })
  return { projectId: project.id, runId, run: store.run(runId) }
}

/**
 * Extract and compile a pure exported function from a TSX component file without mounting React/router.
 */
function loadExportedTsxFn<T extends (...args: never[]) => unknown>(
  relPath: string,
  fnName: string,
  scopeVars: Record<string, unknown> = {},
): T {
  const fullPath = join(REPO_ROOT, relPath)
  const src = readFileSync(fullPath, 'utf8')
  const sf = ts.createSourceFile(fullPath, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TSX)
  let fnText: string | null = null
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name?.text === fnName) {
      fnText = src.slice(stmt.getStart(sf), stmt.getEnd())
      break
    }
  }
  assert.ok(fnText, `Expected exported function ${fnName} in ${relPath}`)
  const cleaned = fnText.replace(/^export\s+/, '')
  const js = ts.transpileModule(cleaned, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText
  const keys = Object.keys(scopeVars)
  const vals = Object.values(scopeVars)
  const factory = new Function(...keys, `${js}\nreturn ${fnName};`)
  return factory(...vals) as T
}

// ---------------------------------------------------------------------------
// 1. Resume (setStatus(run, 'running')) invariants
// ---------------------------------------------------------------------------

test('Resume only re-queues paused assignments in current goalRevision and never resurrects failed/denied or stale-goal workers', t => {
  const store = makeStore(t)
  const { runId, run } = setupApprovedRun(store)
  const candidate = run.candidates[0]!

  // Goal revision 0: one paused worker and one failed worker (must NOT resurrect after goal revision!)
  const oldPaused = store.makeWorker(run, 'investigation', candidate, 'Old goal paused', 'Check old goal')
  store.updateWorker(oldPaused.id, { status: 'paused', outcome: 'Paused before revise' })
  const oldFailed = store.makeWorker(run, 'investigation', candidate, 'Old goal failed', 'Check old goal')
  store.updateWorker(oldFailed.id, { status: 'failed', outcome: 'Denied by policy' })

  // Revise goal to revision 1
  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'revise', goal: 'Focus on tenant isolation only' }))
  // Re-force oldPaused/oldFailed statuses to directly test goalRevision filtering on setStatus(run, 'running')
  store.updateWorker(oldPaused.id, { status: 'paused' })
  store.updateWorker(oldFailed.id, { status: 'failed' })

  const rev1Run = store.run(runId)
  assert.equal(rev1Run.goalRevision, 1)
  store.updateRun(runId, { phase: 'investigation', status: 'running' })

  // Goal revision 1 workers in every relevant status
  const curPaused = store.makeWorker(rev1Run, 'investigation', candidate, 'Current paused', 'Active work')
  store.updateWorker(curPaused.id, { status: 'running', lease: randomUUID() })

  const curFailed = store.makeWorker(rev1Run, 'investigation', candidate, 'Current failed', 'Denied probe')
  store.updateWorker(curFailed.id, { status: 'failed', outcome: 'Approval denied by operator' })

  const curCanceled = store.makeWorker(rev1Run, 'investigation', candidate, 'Current canceled', 'Revoked')
  store.updateWorker(curCanceled.id, { status: 'canceled', outcome: 'Canceled by operator' })

  const curComplete = store.makeWorker(rev1Run, 'investigation', candidate, 'Current complete', 'Done')
  store.updateWorker(curComplete.id, { status: 'complete', outcome: 'Finished' })

  // Pause run -> running worker becomes paused; failed/canceled/complete stay untouched
  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'pause' }))
  assert.equal(store.worker(curPaused.id).status, 'paused')
  assert.equal(store.worker(curFailed.id).status, 'failed')

  // Resume run -> ONLY curPaused (current goalRevision & paused) is re-queued
  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'resume' }))
  assert.equal(store.run(runId).status, 'running')
  assert.equal(store.worker(curPaused.id).status, 'queued', 'current goalRevision paused worker must be re-queued')
  assert.equal(store.worker(curFailed.id).status, 'failed', 'failed/denied worker must NEVER be resurrected by Resume')
  assert.equal(store.worker(curCanceled.id).status, 'canceled', 'canceled worker must stay canceled')
  assert.equal(store.worker(curComplete.id).status, 'complete', 'complete worker must stay complete')
  assert.equal(store.worker(oldPaused.id).status, 'paused', 'old goalRevision paused worker must NOT be resurrected')
  assert.equal(store.worker(oldFailed.id).status, 'failed', 'old goalRevision failed worker must NOT be resurrected')
})

test('RPS-only raise_budget succeeds near budget cap, and budget_paused resume preserves failed-worker invariant', t => {
  const store = makeStore(t)
  const { runId, run } = setupApprovedRun(store)
  const candidate = run.candidates[0]!

  const failedWorker = store.makeWorker(run, 'investigation', candidate, 'Denied worker', 'Should stay failed')
  store.updateWorker(failedWorker.id, { status: 'failed', outcome: 'Denied' })

  // Spend right up to budget cap ($24.98 of $25.00)
  store.recordLlmSpend(runId, { usd: 24.98, tokens: 1000, turns: 5 })

  // RPS-only edit (budgetUsd and budgetRequests omitted) succeeds cleanly!
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'raise_budget',
    maxRpsPerOrigin: 14,
    resume: false,
  }))
  assert.equal(store.run(runId).maxRpsPerOrigin, 14)
  assert.equal(store.run(runId).budgetUsd, 25)

  // Hit budget cap -> budget_paused -> raise_budget + resume must NOT resurrect failedWorker
  store.recordLlmSpend(runId, { usd: 0.05, tokens: 100, turns: 1 })
  assert.equal(store.checkBudgetExceeded(runId), true)
  assert.equal(store.run(runId).status, 'budget_paused')

  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'raise_budget',
    budgetUsd: 40,
    resume: true,
  }))
  assert.equal(store.run(runId).status, 'running')
  assert.equal(store.worker(failedWorker.id).status, 'failed')
})

// ---------------------------------------------------------------------------
// 2. Operator board_post sourceOrigins defaulting + cold @specialist wakeup
// ---------------------------------------------------------------------------

test('Operator board_post defaults sourceOrigins to approved origins and wakes cold @specialist mentions', t => {
  const store = makeStore(t)
  const { runId } = setupApprovedRun(store, [
    { origin: 'https://app.example.test' },
    { origin: 'https://unapproved.example.test', thirdParty: true },
  ], 1)

  // 1. Operator board_post command defaults sourceOrigins to approved origins only
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'board_post',
    body: '@bola check cross-tenant object reads on /api/orders',
  }))
  const msgsAfterCmd = store.listBoardMessages(runId)
  const post = msgsAfterCmd.at(-1)!
  assert.equal(post.authorHandle, 'operator')
  assert.deepEqual(post.mentions, ['bola'])
  assert.deepEqual(post.sourceOrigins, ['https://app.example.test'])

  // 2. Cold @bola mention actually wakes @bola via ExecBoardManager (creates step + roster row)
  assert.equal(store.boardMember(runId, 'bola'), undefined, '@bola starts cold (not on roster yet)')
  let wakeScheduled = 0
  const execBoard = new ExecBoardManager({
    storage: store,
    warm: new WarmSpecialistController(),
    boardHandleByAssignment: new Map(),
    approvedOriginsSet: r => new Set(r.candidates.filter(c => r.approved.includes(c.id)).map(c => c.origin)),
    scheduleWake: () => { wakeScheduled += 1 },
  })
  execBoard.routeOperatorBoardMessages(store.run(runId))

  const bolaMember = store.boardMember(runId, 'bola')
  assert.ok(bolaMember, 'cold @bola specialist must be spawned on the roster')
  assert.equal(bolaMember.specialistProfile, 'bola-bfla-specialist')
  assert.deepEqual(bolaMember.sourceOrigins, ['https://app.example.test'])
  const steps = store.listChainSteps(runId)
  assert.equal(steps.length, 1)
  assert.equal(steps[0]!.specialistProfile, 'bola-bfla-specialist')
  assert.deepEqual(steps[0]!.sourceOrigins, ['https://app.example.test'])
  assert.ok(wakeScheduled >= 1)

  // 3. Direct postBoardMessage with empty sourceOrigins: [] for operator still defaults to approved origins
  const emptyOrigPost = store.postBoardMessage(runId, {
    authorHandle: 'operator',
    authorRole: 'operator',
    kind: 'handoff',
    body: '@injection inspect search filter',
    sourceOrigins: [],
  })
  assert.deepEqual(emptyOrigPost.sourceOrigins, ['https://app.example.test'])
})

// ---------------------------------------------------------------------------
// 3. ScopeCard / ConsentView third-party defaultScope inclusion & UI logic
// ---------------------------------------------------------------------------

test('defaultScopeAssetIds lets project defaultScope override !thirdParty so approved 3P hosts stay checked', () => {
  type DefaultScopeFn = (
    run: {
      scopeRevision: number
      approved: readonly string[]
      candidates: readonly { id: string; origin: string; thirdParty: boolean; dnsSource?: unknown }[]
    },
    projectDefaultScope: readonly string[],
  ) => string[]

  const defaultScopeAssetIds = loadExportedTsxFn<DefaultScopeFn>(
    'src/components/run/views/consent.tsx',
    'defaultScopeAssetIds',
  )

  const candidates = [
    { id: 'c-first', origin: 'https://app.example.test', thirdParty: false, dnsSource: null },
    { id: 'c-sub', origin: 'https://api.example.test', thirdParty: false, dnsSource: { source: 'ct' } },
    { id: 'c-3p-approved', origin: 'https://docs.example.test', thirdParty: true, dnsSource: { externalAliases: ['hosting.gitbook.io'] } },
    { id: 'c-3p-unapproved', origin: 'https://status.example.test', thirdParty: true, dnsSource: { externalAliases: ['statuspage.io'] } },
  ]

  // Saved project defaultScope includes a third-party host -> MUST stay checked!
  assert.deepEqual(
    defaultScopeAssetIds(
      { scopeRevision: 0, approved: [], candidates },
      ['https://app.example.test', 'https://docs.example.test'],
    ),
    ['c-first', 'c-3p-approved'],
  )

  // Empty project defaultScope -> falls back to first-party non-DNS seeds only
  assert.deepEqual(
    defaultScopeAssetIds({ scopeRevision: 0, approved: [], candidates }, []),
    ['c-first'],
  )

  // Existing scopeRevision > 0 -> always honors run.approved verbatim
  assert.deepEqual(
    defaultScopeAssetIds(
      { scopeRevision: 2, approved: ['c-3p-approved'], candidates },
      ['https://app.example.test'],
    ),
    ['c-3p-approved'],
  )
})

test('Header BudgetPopover RPS cap and RPS-only command builder work cleanly for public vs local-lab', () => {
  const effectiveRpsCap = loadExportedTsxFn<(env: string) => number>(
    'src/components/run/header.tsx',
    'effectiveRpsCap',
    { maxRpsPerOriginCeiling: 100, PUBLIC_MAX_RPS_CAP: 20 },
  )
  assert.equal(effectiveRpsCap('public'), 20)
  assert.equal(effectiveRpsCap('local-lab'), 100)

  type BuildBudgetFn = (
    run: { status: string; budgetUsd: number; spentUsd: number; budgetRequests: number; spentRequests: number; maxRpsPerOrigin: number },
    draft: { usd: number; unlimited: boolean; cap: number; rps: number },
    rpsMax: number,
  ) => Record<string, unknown> | null

  const buildBudgetCommand = loadExportedTsxFn<BuildBudgetFn>(
    'src/components/run/header.tsx',
    'buildBudgetCommand',
    { maxBudgetRequests: 250_000 },
  )

  // Near budget cap ($24.97 / $25.00): RPS-only edit omits budgetUsd and budgetRequests and clamps public RPS to 20
  const rpsOnly = buildBudgetCommand(
    { status: 'running', budgetUsd: 25, spentUsd: 24.97, budgetRequests: 1000, spentRequests: 999, maxRpsPerOrigin: 5 },
    { usd: 25, unlimited: false, cap: 1000, rps: 35 },
    20,
  )
  assert.deepEqual(rpsOnly, { action: 'raise_budget', resume: false, maxRpsPerOrigin: 20 })

  // No-op when nothing changed on a running run
  assert.equal(
    buildBudgetCommand(
      { status: 'running', budgetUsd: 25, spentUsd: 10, budgetRequests: 0, spentRequests: 100, maxRpsPerOrigin: 5 },
      { usd: 25, unlimited: true, cap: 2500, rps: 5 },
      20,
    ),
    null,
  )

  // budget_paused sends raised budgetUsd + resume: true
  const resumeBudget = buildBudgetCommand(
    { status: 'budget_paused', budgetUsd: 25, spentUsd: 25, budgetRequests: 0, spentRequests: 100, maxRpsPerOrigin: 5 },
    { usd: 35, unlimited: true, cap: 2500, rps: 5 },
    20,
  )
  assert.deepEqual(resumeBudget, { action: 'raise_budget', resume: true, budgetUsd: 35 })
})

test('Overview live strip emits Authenticating test accounts… during threat_model with pending login personas and 0 workers', () => {
  type LiveSummaryFn = (input: {
    phase: string
    roundNo: number
    runningWorkers: readonly { title: string }[]
    approvedPersonaIds: readonly string[]
    personas: readonly { id: string; handle: string; authKind: string }[]
    events: readonly { id: number; kind: string; detail?: Record<string, unknown> | null }[]
    hasThreatModel: boolean
  }) => string

  const liveOverviewSummary = loadExportedTsxFn<LiveSummaryFn>(
    'src/components/run/views/overview.tsx',
    'liveOverviewSummary',
    { PHASE_LABEL: { threat_model: 'Threat model', investigation: 'Investigation' } },
  )

  // Pending login persona in threat_model with 0 workers -> Authenticating test accounts…
  const pendingMsg = liveOverviewSummary({
    phase: 'threat_model',
    roundNo: 0,
    runningWorkers: [],
    approvedPersonaIds: ['p-alice', 'p-static'],
    personas: [
      { id: 'p-alice', handle: 'alice', authKind: 'login' },
      { id: 'p-static', handle: 'bob', authKind: 'cookie' },
    ],
    events: [{ id: 10, kind: 'scope.approved', detail: {} }],
    hasThreatModel: false,
  })
  assert.match(pendingMsg, /^Authenticating test accounts…/)
  assert.match(pendingMsg, /alice/)

  // Once persona.authenticated arrives after scope.approved -> falls back to phase label
  const authedMsg = liveOverviewSummary({
    phase: 'threat_model',
    roundNo: 0,
    runningWorkers: [],
    approvedPersonaIds: ['p-alice'],
    personas: [{ id: 'p-alice', handle: 'alice', authKind: 'login' }],
    events: [
      { id: 10, kind: 'scope.approved', detail: {} },
      { id: 11, kind: 'persona.authenticated', detail: { personaId: 'p-alice' } },
    ],
    hasThreatModel: false,
  })
  assert.equal(authedMsg, 'Threat model · Round 0')

  // Static-only personas do not trigger Authenticating test accounts…
  const staticOnlyMsg = liveOverviewSummary({
    phase: 'threat_model',
    roundNo: 0,
    runningWorkers: [],
    approvedPersonaIds: ['p-static'],
    personas: [{ id: 'p-static', handle: 'bob', authKind: 'cookie' }],
    events: [{ id: 10, kind: 'scope.approved', detail: {} }],
    hasThreatModel: false,
  })
  assert.equal(staticOnlyMsg, 'Threat model · Round 0')
})

test('Header and Consent/ScopeOverlay structural invariants hold cleanly', () => {
  const headerSrc = readFileSync(join(REPO_ROOT, 'src/components/run/header.tsx'), 'utf8')
  assert.doesNotMatch(headerSrc, /startRunLabAction|stopRunLabAction|checkRunLabHealthAction/, 'duplicate Local Lab actions must be removed from header')
  assert.doesNotMatch(headerSrc, /approve_all_pending/, 'redundant Approve all pending item removed from header menu')
  assert.match(headerSrc, /hasActiveWorkers/)
  assert.match(headerSrc, /hasRunningLab/)
  assert.match(headerSrc, /Stop lab & delete run/)

  const consentSrc = readFileSync(join(REPO_ROOT, 'src/components/run/views/consent.tsx'), 'utf8')
  assert.doesNotMatch(consentSrc, /workerMaxTurns|workerConcurrency/, 'ScopeCard KV must omit Workers / Max turns')
  assert.match(consentSrc, /\{!discovery && <button[\s\S]*?\{editing \? 'Reset' : 'Edit scope'\}/, 'Edit scope button must be hidden during phase === consent')
  assert.match(consentSrc, /<ScopeCard[\s\S]*?inDialog[\s\S]*?scopeOnly/, 'ScopeOverlay must render scopeOnly (hosts + personas + tier only)')
  assert.match(consentSrc, /await send\(command\)[\s\S]*?overlays\.closeScope\(\)/, 'ScopeOverlay must commit BEFORE closing modal')
  assert.match(consentSrc, /Reload latest scope/, 'ScopeOverlay must offer inline 1-click Reload latest scope on revision conflict')
  assert.match(consentSrc, /<select[\s\S]*?value=\{scanMode\}[\s\S]*?aria-label="Scan mode"/, 'ScopeCard Scan mode must render as a compact <select> dropdown')
  assert.match(consentSrc, /label:\s*'Passive Scan'[\s\S]*?label:\s*'Supervised Scan'[\s\S]*?label:\s*'Autonomous Scan'/, 'ScopeCard Scan mode options must include Passive Scan, Supervised Scan, and Autonomous Scan')
  assert.doesNotMatch(consentSrc, /role="group"\s+aria-label="Scan mode"/, 'ScopeCard Scan mode must not use the old segmented button group')
  assert.doesNotMatch(consentSrc, /Safe checks auto-approve; deletes, uploads, and execution proofs ask first\./, 'Scope Review must not render redundant per-mode Scan Mode helper line')
  assert.doesNotMatch(consentSrc, /q\.decide\(ck,\s*'scope'/, 'Approve & start must execute immediately via send(command), without delayed undo toast')
})
