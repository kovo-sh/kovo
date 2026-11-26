import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'
import { eq } from 'drizzle-orm'
import { canonicalBoardHandles, maxBoardBodyLength, parseBoardMentions } from '../src/domain.ts'
import { fmtEventKind } from '../src/components/run/format.ts'
import { buildRunModel, computeRunEnd, isApprovalExpired } from '../src/components/run/model.ts'
import type { Detail, RunEvent } from '../src/components/run/model.ts'
import { Execution } from '../src/server/execution.ts'
import { messages as messagesTable } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function readRepoFile(...segments: string[]): string {
  return readFileSync(join(REPO_ROOT, ...segments), 'utf8')
}

function evalTsSlice<T extends Record<string, unknown>>(
  fileSegments: string[],
  startMarker: string,
  endMarker: string,
  sandbox: Record<string, unknown> = {},
): T {
  const src = readRepoFile(...fileSegments)
  const start = src.indexOf(startMarker)
  const end = src.indexOf(endMarker, start)
  assert.ok(start >= 0 && end > start, `Expected slice [${startMarker} .. ${endMarker}] in ${fileSegments.join('/')}`)
  const { outputText } = ts.transpileModule(src.slice(start, end), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  })
  const mod = { exports: {} as Record<string, unknown> }
  vm.runInNewContext(outputText, {
    exports: mod.exports,
    module: mod,
    setTimeout,
    clearTimeout,
    AbortController,
    TextDecoder,
    Date,
    Number,
    Math,
    Map,
    Set,
    JSON,
    Error,
    Promise,
    ...sandbox,
  })
  return mod.exports as T
}

function makeFakeDetail(overrides: Partial<Detail> = {}): Detail {
  const createdAt = 1_700_000_000_000
  const baseRun = {
    id: 'run-1',
    projectId: 'proj-1',
    workspaceId: 'ws-1',
    tenantId: 'default',
    originalGoal: 'Verify auth boundaries',
    goal: 'Verify auth boundaries',
    goalRevision: 1,
    scopeRevision: 1,
    coordinatorId: 'coord-1',
    phase: 'investigation',
    status: 'running',
    sourceMode: 'public',
    capabilityTier: 2,
    approvalPolicy: 'auto_review',
    approvedEndpointPatterns: [],
    approvedPersonaIds: [],
    roundNo: 1,
    budgetUsd: 25,
    budgetRequests: 0,
    spentUsd: 1,
    spentTokens: 1000,
    spentRequests: 10,
    turnsUsed: 2,
    maxRpsPerOrigin: 5,
    workerConcurrency: 6,
    workerMaxTurns: 150,
    dynamicStepBudget: null,
    multiTrialEnabled: true,
    phase0CompletedAt: null,
    reviewPlan: null,
    candidates: [{ id: 'asset-1', origin: 'https://app.example.test', source: 'seed', thirdParty: false }],
    approved: ['asset-1'],
    authOrigins: [],
    assetOrigins: [],
    environmentMode: 'prod_readonly',
    routeDenylist: [],
    createdAt,
  }
  const base = {
    run: baseRun,
    project: {
      id: 'proj-1',
      workspaceId: 'ws-1',
      tenantId: 'default',
      name: 'Demo',
      environment: 'public',
      seeds: ['https://app.example.test'],
      defaultScope: ['https://app.example.test'],
      labConfig: null,
      sandboxWriteAllowlist: [],
      createdAt,
    },
    personas: [],
    specs: [],
    threatModel: null,
    chainSteps: [],
    facts: [],
    graphEdges: [],
    digests: [],
    assignments: [],
    approvals: [],
    exchangesSummary: [],
    coverageEntries: [],
    endpoints: [],
    endpointParams: [],
    apiDependencies: [],
    labTelemetry: [],
    openProofGaps: [],
    sastRuns: [],
    surfaceProbes: [],
    patchProposals: [],
    replaySpecs: [],
    retestRuns: [],
    findings: [],
    provenanceCounts: { deterministic_floor: 0, agent_confirmed: 0, static_advisory: 0, open_proof_gap: 0 },
    messages: [],
    boardMembers: [],
    boardMessages: [],
    evidence: [],
    reports: [],
    cursor: 0,
    hasModel: true,
    labTarget: null,
    localLabEnvEnabled: false,
  } as unknown as Detail
  return { ...base, ...overrides }
}

// ---------------------------------------------------------------------------
// A4: Toast controller shows, replaces, and dismisses non-blocking toasts
// ---------------------------------------------------------------------------

test('A4: toast.show() replaces previous toast and dismiss() clears timer', async () => {
  const { createToastController } = evalTsSlice<{
    createToastController: (hooks: {
      onPush: (item: { id: number; message: unknown; tone: string; ms: number }) => void
      onClose: (id?: number) => void
      setTimer?: (fn: () => void, ms: number) => ReturnType<typeof setTimeout>
      clearTimer?: (h: ReturnType<typeof setTimeout> | undefined) => void
    }) => {
      show: (msg: unknown, opts?: { tone?: 'default' | 'error'; ms?: number }) => void
      dismiss: () => void
      dispose: () => void
    }
  }>(['src', 'components', 'run', 'toast.tsx'], 'export function createToastController(', 'interface Item {')

  const pushed: Array<{ id: number; message: unknown; tone: string; ms: number }> = []
  const closed: Array<number | undefined> = []
  const timers: { fn: (() => void) | null } = { fn: null }
  let cleared = 0
  const ctrl = createToastController({
    onPush: item => pushed.push(item),
    onClose: id => closed.push(id),
    setTimer: fn => { timers.fn = fn; return 1 as unknown as ReturnType<typeof setTimeout> },
    clearTimer: () => { timers.fn = null; cleared += 1 },
  })

  ctrl.show('Stopping the run')
  assert.equal(pushed.length, 1)
  assert.equal(pushed[0]!.tone, 'default')
  assert.equal(pushed[0]!.ms, 2000)

  ctrl.show('Error saving', { tone: 'error' })
  assert.equal(pushed.length, 2)
  assert.equal(pushed[1]!.tone, 'error')
  assert.equal(pushed[1]!.ms, 4000)
  assert.ok(cleared >= 2)

  timers.fn?.()
  assert.deepEqual(closed, [2])

  ctrl.dismiss()
  assert.deepEqual(closed, [2, undefined])
})

// ---------------------------------------------------------------------------
// A5: Historical event hydration on reload / finished runs + ActivityView
// ---------------------------------------------------------------------------

test('A5: historical SSE backfill hydrates events up to initial.cursor cleanly and deduplicates live events', async () => {
  const helpers = evalTsSlice<{
    sseStreamSinceCursor: (n: number) => number
    mergeRunEvents: (a: readonly RunEvent[], b: readonly RunEvent[]) => RunEvent[]
    parseSseEventsChunk: (carry: string, chunk: string) => { events: RunEvent[]; carry: string }
    hydrateHistoricalEvents: (
      runId: string,
      targetCursor: number,
      opts: { signal: AbortSignal; onBatch: (batch: RunEvent[]) => void; fetchImpl?: typeof fetch; idleMs?: number },
    ) => Promise<void>
  }>(['src', 'components', 'run', 'data.tsx'], 'export const SSE_REFRESH_DEBOUNCE_MS', 'export function RunDataProvider(')

  // Chunked SSE parsing across partial boundaries + comment/retry lines
  const ev1: RunEvent = { id: 1, runId: 'r1', kind: 'run.created', message: 'Run created', detail: {}, createdAt: 100 }
  const ev2: RunEvent = { id: 2, runId: 'r1', kind: 'broker.denied', message: 'Denied', detail: { reason: 'out_of_scope' }, createdAt: 200 }
  const ev3: RunEvent = { id: 3, runId: 'r1', kind: 'interrupted', message: 'Restarted', detail: {}, createdAt: 300 }
  const raw = `retry: 700\n\n: keepalive\n\nid: 1\ndata: ${JSON.stringify(ev1)}\n\nid: 2\ndata: ${JSON.stringify(ev2)}\n\nid: 3\ndata: ${JSON.stringify(ev3)}\n\n`
  const cut = Math.floor(raw.length / 2)
  const p1 = helpers.parseSseEventsChunk('', raw.slice(0, cut))
  const p2 = helpers.parseSseEventsChunk(p1.carry, raw.slice(cut))
  assert.deepEqual([...p1.events, ...p2.events].map(e => e.id), [1, 2, 3])

  // Merge deduplicates and keeps ascending id order
  const merged = helpers.mergeRunEvents([ev3, ev1], [ev2, ev1])
  assert.deepEqual(Array.from(merged, e => e.id), [1, 2, 3])

  // hydrateHistoricalEvents stops once targetCursor is reached and ignores id > targetCursor
  const encoder = new TextEncoder()
  let fetchedUrl = ''
  let aborted = false
  const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    fetchedUrl = String(input)
    init?.signal?.addEventListener('abort', () => { aborted = true })
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(`retry: 700\n\nid: 1\ndata: ${JSON.stringify(ev1)}\n\n`))
        controller.enqueue(encoder.encode(`id: 2\ndata: ${JSON.stringify(ev2)}\n\nid: 3\ndata: ${JSON.stringify(ev3)}\n\n`))
      },
    })
    return new Response(stream, { status: 200, headers: { 'content-type': 'text/event-stream' } })
  }) as unknown as typeof fetch

  const hydrated: RunEvent[] = []
  const outerAbort = new AbortController()
  await helpers.hydrateHistoricalEvents('r1', 2, {
    signal: outerAbort.signal,
    onBatch: batch => hydrated.push(...batch),
    fetchImpl: fakeFetch,
    idleMs: 100,
  })
  assert.equal(fetchedUrl, '/api/runs/r1/events')
  assert.equal(aborted, true, 'backfill stream must abort as soon as targetCursor is reached')
  assert.deepEqual(hydrated.map(e => e.id), [1, 2], 'must hydrate 1..targetCursor without leaking newer live events')

  // ActivityView never says "Quiet so far" when counts.events > 0
  const activitySrc = readRepoFile('src', 'components', 'run', 'views', 'activity.tsx')
  assert.equal(activitySrc.includes('eventsReady && !events.length && runCounts.events === 0'), true)
  assert.equal(activitySrc.includes('eventsReady && !events.length && runCounts.events > 0'), true)
})

// ---------------------------------------------------------------------------
// A6: Board composer @coordinator / @all, non-wakeable handles, header count, waiting-run copy
// ---------------------------------------------------------------------------

test('A6: ExecBoardManager mirrors @coordinator and @all board posts to coordinator thread without duplicates', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-wave-board-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const store = new Store(dir)
  const execution = new Execution(store)
  t.after(async () => { await execution.stop(); store.close() })

  const origin = 'https://board-a6.example'
  const { runId } = await setupApprovedRun(store, {
    seeds: [origin], tier: 2, environment: 'public', budgetUsd: 10, budgetRequests: 200,
  })
  store.updateRun(runId, { phase: 'investigation', status: 'running' })
  const run = store.run(runId)
  store.upsertBoardMember(run, {
    handle: 'auth', role: 'specialist', specialistProfile: 'auth-session-oauth-specialist',
    sessionId: 'warm-auth-a6', state: 'waiting', sourceOrigins: [origin],
  })

  const priv = execution as unknown as Record<string, any>
  assert.equal(priv.shouldCoordinatorAnswer('@coordinator status please'), true)
  assert.equal(priv.shouldCoordinatorAnswer('@all focus on admin endpoints'), true)
  assert.equal(priv.shouldCoordinatorAnswer('@auth @all check tokens'), true)
  assert.equal(priv.shouldCoordinatorAnswer('@auth only check tokens'), false)

  // Direct board_post mentioning @coordinator must mirror into coordinator thread
  store.command({
    requestId: randomUUID(),
    runId,
    action: 'board_post',
    body: '@coordinator summarize findings so far',
    mentions: ['coordinator'],
  })
  priv.routeOperatorBoardMessages(store.run(runId))
  const coordMsgs1 = store.db.select().from(messagesTable).where(eq(messagesTable.runId, runId)).all()
    .filter(m => m.threadId === run.coordinatorId && m.role === 'operator' && m.content === '@coordinator summarize findings so far')
  assert.equal(coordMsgs1.length, 1, '@coordinator board_post must be mirrored to coordinator thread')

  // Direct board_post mentioning @all must mirror to coordinator thread AND wake @auth
  const stepsBeforeAll = store.listChainSteps(runId, run.goalRevision).length
  store.command({
    requestId: randomUUID(),
    runId,
    action: 'board_post',
    body: '@all prioritize /api/admin/export',
    mentions: ['all'],
  })
  priv.routeOperatorBoardMessages(store.run(runId))
  const coordMsgs2 = store.db.select().from(messagesTable).where(eq(messagesTable.runId, runId)).all()
    .filter(m => m.threadId === run.coordinatorId && m.role === 'operator' && m.content === '@all prioritize /api/admin/export')
  assert.equal(coordMsgs2.length, 1, '@all board_post must be mirrored to coordinator thread')
  assert.equal(store.listChainSteps(runId, run.goalRevision).length, stepsBeforeAll + 1, '@all must wake waiting peer @auth')

  // Sending via action: 'message' must NOT create a duplicate coordinator-thread message on routing
  store.command({
    requestId: randomUUID(),
    runId,
    action: 'message',
    message: '@coordinator no duplicate please',
  })
  priv.routeOperatorBoardMessages(store.run(runId))
  const coordMsgs3 = store.db.select().from(messagesTable).where(eq(messagesTable.runId, runId)).all()
    .filter(m => m.threadId === run.coordinatorId && m.role === 'operator' && m.content === '@coordinator no duplicate please')
  assert.equal(coordMsgs3.length, 1, 'message command must not duplicate coordinator-thread entries')
})

test('A6: Board autocomplete drops non-wakeable handles, routes @coordinator/@all to message, uses items.length, and fixes waiting copy', () => {
  const helpers = evalTsSlice<{
    NON_WAKEABLE_BOARD_HANDLES: Set<string>
    buildMentionHandles: (members: Array<{ handle: string; state: string }>) => string[]
    composerCommandForText: (content: string, rawText: string) => { action: string; message?: string; body?: string; mentions?: string[] }
  }>(
    ['src', 'components', 'run', 'coordinator.tsx'],
    'export const NON_WAKEABLE_BOARD_HANDLES',
    '/** One approval row:',
    { canonicalBoardHandles, maxBoardBodyLength, parseBoardMentions },
  )

  const handles = helpers.buildMentionHandles([
    { handle: 'coordinator', state: 'waiting' },
    { handle: 'broker', state: 'waiting' },
    { handle: 'canary', state: 'waiting' },
    { handle: 'verifier', state: 'waiting' },
    { handle: 'auth', state: 'working' },
    { handle: 'auth-2', state: 'retired' },
  ])
  for (const dropped of ['broker', 'canary', 'verifier']) {
    assert.equal(handles.includes(dropped), false, `Autocomplete must omit non-wakeable @${dropped}`)
  }
  assert.equal(handles.includes('coordinator'), true)
  assert.equal(handles.includes('auth'), true)
  assert.equal(handles.includes('all'), true)
  assert.equal(handles.includes('auth-2'), false, 'Retired handles must not appear in autocomplete')

  assert.equal(helpers.composerCommandForText('hello', 'hello').action, 'message')
  assert.equal(helpers.composerCommandForText('@coordinator status', '@coordinator status').action, 'message')
  assert.equal(helpers.composerCommandForText('@all focus', '@all focus').action, 'message')
  assert.equal(helpers.composerCommandForText('@auth @coordinator help', '@auth @coordinator help').action, 'message')
  const peerCmd = helpers.composerCommandForText('@auth inspect oauth', '@auth inspect oauth')
  assert.equal(peerCmd.action, 'board_post')
  assert.deepEqual(peerCmd.mentions, ['auth'])

  const coordSrc = readRepoFile('src', 'components', 'run', 'coordinator.tsx')
  assert.equal(coordSrc.includes("plural(items.length, 'message')"), true, 'Board header count must use items.length')
  assert.equal(coordSrc.includes('board.length + model.coordinatorMessages.length'), false, 'Board header count must not double-count')
  assert.equal(coordSrc.includes('Refine the goal before consenting'), false, 'Misleading waiting-run copy must be removed')
  assert.equal(coordSrc.includes('Edit goal'), true, 'Waiting run must provide an Edit goal trigger')
  assert.equal(coordSrc.includes('InlineApproval'), false, 'Duplicate InlineApproval component must be removed')
  assert.equal(coordSrc.includes('APPROVAL_RE'), false, 'Duplicate APPROVAL_RE timeline parser must be removed')
})

// ---------------------------------------------------------------------------
// B5: Banners (budget CTA + auth issue), event labels, activity error highlight, Queue Decide bulk approve + expiry
// ---------------------------------------------------------------------------

test('B5: RunBanners replaces duplicate budget form with Raise budget CTA and surfaces unresolved auth issues', () => {
  const { latestAuthIssue } = evalTsSlice<{
    latestAuthIssue: (events: readonly RunEvent[]) => RunEvent | null
  }>(['src', 'components', 'run', 'shell.tsx'], 'export function latestAuthIssue(', 'function openHeaderBudgetPopover(')

  const fail1: RunEvent = { id: 10, runId: 'r1', kind: 'persona.auth_failed', message: 'Login failed', detail: { error: '401' }, createdAt: 1000 }
  const ok1: RunEvent = { id: 12, runId: 'r1', kind: 'persona.authenticated', message: 'Signed in', detail: { handle: 'user_a' }, createdAt: 1200 }
  const refreshFail: RunEvent = { id: 15, runId: 'r1', kind: 'persona.refresh_failed', message: 'Refresh failed for user_a', detail: { handle: 'user_a' }, createdAt: 1500 }
  const ok2: RunEvent = { id: 18, runId: 'r1', kind: 'persona.authenticated', message: 'Signed in', detail: { handle: 'user_a' }, createdAt: 1800 }

  assert.equal(latestAuthIssue([]), null)
  assert.equal(latestAuthIssue([fail1])?.id, 10)
  assert.equal(latestAuthIssue([fail1, ok1]), null, 'Global auth_failed clears after subsequent persona.authenticated')
  assert.equal(latestAuthIssue([fail1, ok1, refreshFail])?.id, 15)
  assert.equal(latestAuthIssue([fail1, ok1, refreshFail, ok2]), null, 'Per-persona refresh_failed clears when that persona re-authenticates')

  const shellSrc = readRepoFile('src', 'components', 'run', 'shell.tsx')
  assert.equal(shellSrc.includes('Raise and resume'), false, 'Duplicate inline budget form must be removed from RunBanners')
  assert.equal(shellSrc.includes('Raise budget'), true, 'RunBanners must provide a Raise budget CTA button')
  assert.equal(shellSrc.includes('Auth issue.'), true, 'RunBanners must render an Auth issue banner')
  assert.equal(shellSrc.includes("tab: 'personas'"), true, 'Auth issue banner must link to /projects/$projectId?tab=personas')

  // Scope-review UX (#620): hide right-hand Coordinator / Board aside before scope approval
  const { isBoardHiddenBeforeApproval } = evalTsSlice<{
    isBoardHiddenBeforeApproval: (phase: string) => boolean
  }>(['src', 'components', 'run', 'shell.tsx'], 'export function isBoardHiddenBeforeApproval(', 'function Workspace(')
  assert.equal(isBoardHiddenBeforeApproval('consent'), true)
  assert.equal(isBoardHiddenBeforeApproval('review'), true)
  assert.equal(isBoardHiddenBeforeApproval('discovery'), false)
  assert.equal(isBoardHiddenBeforeApproval('threat_model'), false)
  assert.equal(isBoardHiddenBeforeApproval('investigation'), false)
  assert.equal(shellSrc.includes('{!hideBoardBeforeApproval && <aside'), true, 'Shell must omit rendering <aside> before scope approval')
  assert.equal(shellSrc.includes('if (hideBoardBeforeApproval) return false; nav.togglePane()'), true)
  assert.equal(shellSrc.includes('if (hideBoardBeforeApproval) return false; nav.openChat(null)'), true)

  // Event labels + activity error highlighting
  assert.equal(fmtEventKind('persona.authenticated'), 'Test account signed in')
  assert.equal(fmtEventKind('persona.refresh_failed'), 'Test account session refresh failed')
  assert.equal(fmtEventKind('persona.auth_failed'), 'Test account sign-in failed')

  const { isErrorActivityEvent } = evalTsSlice<{
    isErrorActivityEvent: (kind: string) => boolean
  }>(['src', 'components', 'run', 'views', 'activity.tsx'], 'const ERROR_ACTIVITY_KINDS', 'export function ActivityView(')
  assert.equal(isErrorActivityEvent('persona.auth_failed'), true)
  assert.equal(isErrorActivityEvent('persona.refresh_failed'), true)
  assert.equal(isErrorActivityEvent('broker.persona_scope_mismatch'), true)
  assert.equal(isErrorActivityEvent('broker.denied'), true)
  assert.equal(isErrorActivityEvent('worker.failed'), true)
  assert.equal(isErrorActivityEvent('broker.allowed'), false)

  // Queue Decide header has Approve all pending + client-side Expired handling
  const queueSrc = readRepoFile('src', 'components', 'run', 'views', 'queue.tsx')
  assert.equal(queueSrc.includes('Approve all pending'), true)
  assert.equal(queueSrc.includes("action: 'approve_all_pending'"), true)
  assert.equal(queueSrc.includes('isApprovalExpired'), true)
  const queueReadSrc = readRepoFile('src', 'components', 'run', 'views', 'queue-read.tsx')
  assert.equal(queueReadSrc.includes('isApprovalExpired'), true)
  assert.equal(queueReadSrc.includes('Expired'), true)

  const now = 1_700_000_500_000
  assert.equal(isApprovalExpired({ status: 'pending', expiresAt: now - 1 }, now), true)
  assert.equal(isApprovalExpired({ status: 'pending', expiresAt: now }, now), true)
  assert.equal(isApprovalExpired({ status: 'pending', expiresAt: now + 60_000 }, now), false)
  assert.equal(isApprovalExpired({ status: 'approved', expiresAt: now - 10_000 }, now), false)
})

// ---------------------------------------------------------------------------
// B7 + C: No localStorage finding triage, Queue progress <= 100%, unified Verify Fix & Patch, broker.denied detail, duration snap-back
// ---------------------------------------------------------------------------

test('B7 + C: Queue holds only real server decisions with progress <= 100%, and localStorage triage is removed', () => {
  const decisionsSrc = readRepoFile('src', 'components', 'run', 'decisions.tsx')
  assert.equal(decisionsSrc.includes('localStorage'), false, 'decisions.tsx must not persist local-only triage in localStorage')
  const inspectorSrc = readRepoFile('src', 'components', 'run', 'views', 'findings-inspector.tsx')
  assert.equal(inspectorSrc.includes('Local triage'), false, 'FindingInspector must not render local-only triage buttons')
  assert.equal(inspectorSrc.includes('False positive'), false)

  const { actionsFor, computeQueueProgress } = evalTsSlice<{
    actionsFor: (it: unknown, now?: number) => unknown[]
    computeQueueProgress: (openCount: number, handledCount: number) => { initialCount: number; handledCount: number; ratio: number }
  }>(['src', 'components', 'run', 'decisions.tsx'], 'export type DecisionAct =', 'export interface Decision {', { isApprovalExpired })

  // Findings offer no fake local actions; expired approvals offer no actions; active approvals offer approve/deny
  assert.deepEqual(Array.from(actionsFor({ kind: 'finding' })), [])
  const now = 1_700_000_500_000
  assert.deepEqual(Array.from(actionsFor({ kind: 'approval', ap: { status: 'pending', expiresAt: now - 1 } }, now)), [])
  assert.equal(actionsFor({ kind: 'approval', ap: { status: 'pending', expiresAt: now + 60_000 } }, now).length, 2)
  assert.equal(actionsFor({ kind: 'follow' }).length, 1)

  // Progress math always stays <= 100% even after items move to Done on server
  for (const [open, handled] of [[3, 0], [2, 1], [0, 3], [0, 0], [1, 5]]) {
    const p = computeQueueProgress(open, handled)
    assert.ok(p.handledCount <= p.initialCount, `handled (${p.handledCount}) must be <= initial (${p.initialCount})`)
    assert.ok(p.ratio >= 0 && p.ratio <= 1, `ratio (${p.ratio}) must be within [0, 1]`)
  }

  // buildRunModel excludes findings from queue.review and excludes follow-ups on finished runs
  const detail = makeFakeDetail({
    run: { ...makeFakeDetail().run, status: 'complete', phase: 'complete' },
    findings: [{
      id: 'f-1', title: 'Unverified lead', severity: 'medium', status: 'pending',
      origin: 'https://app.example.test', category: 'auth-session', reason: 'test',
      remediation: 'fix', evidenceIds: [], findingKind: 'multi_step_chain',
    } as never],
    coverageEntries: [{
      id: 'cov-1', runId: 'run-1', origin: 'https://app.example.test', category: 'auth-session',
      status: 'needs_follow_up', summary: 'Needs recheck', updatedAt: 1_700_000_010_000,
    } as never],
  })
  const model = buildRunModel(detail)
  assert.equal(model.queue.review.length, 0, 'Unverified findings must not populate local triage review queue')
  assert.equal(model.queue.follow.length, 0, 'Completed runs must not offer local-only follow-ups')
})

test('B7 + C: Verify Fix & Generate verified patch are unified and gated on replaySpecId / codeLocations with refresh()', () => {
  const { canVerifyFix, canGeneratePatch } = evalTsSlice<{
    canVerifyFix: (f: { status: string; replaySpecId?: string | null }) => boolean
    canGeneratePatch: (f: { status: string; codeLocations?: unknown[] }) => boolean
  }>(
    ['src', 'components', 'run', 'views', 'findings-inspector.tsx'],
    'export function canVerifyFix(',
    'const TIER_L:',
    { normFStatus: (s: string) => s === 'verified' || s === 'static_verified' ? 'confirmed' : s },
  )

  assert.equal(canVerifyFix({ status: 'confirmed', replaySpecId: 'spec-1' }), true)
  assert.equal(canVerifyFix({ status: 'confirmed', replaySpecId: null }), false, 'Verify Fix must require f.replaySpecId')
  assert.equal(canVerifyFix({ status: 'pending', replaySpecId: 'spec-1' }), false)

  assert.equal(canGeneratePatch({ status: 'confirmed', codeLocations: [{ repo: 'app', file: 'a.ts', startLine: 1, endLine: 2 }] }), true)
  assert.equal(canGeneratePatch({ status: 'static_verified', codeLocations: [{ repo: 'app', file: 'a.ts', startLine: 1, endLine: 2 }] }), true)
  assert.equal(canGeneratePatch({ status: 'confirmed', codeLocations: [] }), false)
  assert.equal(canGeneratePatch({ status: 'pending', codeLocations: [{ repo: 'app', file: 'a.ts', startLine: 1, endLine: 2 }] }), false)

  const inspectorSrc = readRepoFile('src', 'components', 'run', 'views', 'findings-inspector.tsx')
  assert.equal(inspectorSrc.includes('toast.undoable'), false, 'FindingInspector Verify Fix must run immediately without undoable delay')
  assert.equal(inspectorSrc.includes('generatePatchAction'), true, 'FindingInspector must support Generate verified patch')
  assert.equal(inspectorSrc.includes('await refresh()'), true, 'FindingInspector Generate Patch must await refresh()')

  const reportSrc = readRepoFile('src', 'components', 'run', 'views', 'report.tsx')
  assert.equal(reportSrc.includes('canVerifyFix(f)'), true, 'ReportView must share canVerifyFix gating')
  assert.equal(reportSrc.includes('canGeneratePatch(f)'), true, 'ReportView must share canGeneratePatch gating')
  assert.equal(reportSrc.includes('await refresh()'), true, 'ReportView Generate Patch must await refresh()')
})

test('C: broker.denied renders structured { reason, method, path, persona } and computeRunEnd prevents duration snap-back', () => {
  const { deniedEventToRow } = evalTsSlice<{
    deniedEventToRow: (ev: RunEvent) => {
      id: string; denied: boolean; method: string; origin: string; path: string; persona: string | null; reason?: string | null; note?: string
    }
  }>(['src', 'components', 'run', 'views', 'exchanges.tsx'], 'const str =', '/** Every exchange row')

  const rich = deniedEventToRow({
    id: 42,
    runId: 'run-1',
    kind: 'broker.denied',
    message: 'Broker denied for app.example.test.',
    detail: {
      origin: 'https://app.example.test',
      method: 'DELETE',
      path: '/api/users/99',
      persona: 'alice',
      reason: 'prod_readonly blocks state-changing DELETE',
      assignmentId: 'w-1',
    },
    createdAt: 1_700_000_050_000,
  })
  assert.equal(rich.method, 'DELETE')
  assert.equal(rich.path, '/api/users/99')
  assert.equal(rich.persona, 'alice')
  assert.equal(rich.reason, 'prod_readonly blocks state-changing DELETE')
  assert.equal(rich.note, 'prod_readonly blocks state-changing DELETE')

  // Fallback when detail omits structured fields
  const sparse = deniedEventToRow({
    id: 43,
    runId: 'run-1',
    kind: 'broker.denied',
    message: 'Broker denied for other.example.',
    detail: { origin: 'https://other.example' },
    createdAt: 1_700_000_060_000,
  })
  assert.equal(sparse.method, '—')
  assert.equal(sparse.path, '')
  assert.equal(sparse.persona, null)
  assert.equal(sparse.note, 'Broker denied for other.example.')

  // Duration snap-back fix: computeRunEnd respects endedAt, updatedAt, decidedAt
  const t0 = 1_700_000_000_000
  const detailWithUpdated = makeFakeDetail({
    run: { ...makeFakeDetail().run, createdAt: t0, status: 'complete' },
    assignments: [{ id: 'w-1', createdAt: t0 + 10_000 } as never],
    chainSteps: [{ id: 's-1', createdAt: t0 + 10_000, updatedAt: t0 + 180_000 } as never],
  })
  assert.equal(computeRunEnd(detailWithUpdated), t0 + 180_000)

  const detailWithEndedAt = makeFakeDetail({
    run: { ...makeFakeDetail().run, createdAt: t0, status: 'complete', endedAt: t0 + 300_000 } as never,
    assignments: [{ id: 'w-1', createdAt: t0 + 10_000 } as never],
  })
  assert.equal(computeRunEnd(detailWithEndedAt), t0 + 300_000)
})
