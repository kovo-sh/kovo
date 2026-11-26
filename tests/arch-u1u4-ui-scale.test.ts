import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import vm from 'node:vm'
import { and, desc, eq, inArray, lt, sql } from 'drizzle-orm'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import ts from 'typescript'
import {
  buildBoundedRunProjection,
  computeServerScopeRanking,
  queryRunEventsPage,
  RUN_DETAIL_PROJECTION_CAPS,
} from '../src/actions.ts'
import { buildRunModel, isApprovalExpired } from '../src/components/run/model.ts'
import type { Approval, Detail, QueueItem, QueueSection, RunEvent } from '../src/components/run/model.ts'
import * as tables from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { isMultiTenantPublicSuffix, rankScopeAssets, registrableApex } from '../src/server/subdomain-discovery.ts'

const SERVER_PROJECTION_DEPS = {
  rankScopeAssets,
  registrableApex,
  isMultiTenantPublicSuffix,
  tables,
  and,
  desc,
  eq,
  inArray,
  lt,
  sql,
}

const REPO_ROOT = resolve(import.meta.dirname, '..')

function readRepo(relPath: string): string {
  return readFileSync(join(REPO_ROOT, relPath), 'utf8')
}

function loadRunDataHelpers() {
  const src = readRepo('src/components/run/data.tsx')
  const startIdx = src.indexOf('export const SSE_REFRESH_DEBOUNCE_MS')
  const endIdx = src.indexOf('export function RunDataProvider(')
  assert.ok(startIdx >= 0 && endIdx > startIdx, 'Expected SSE helpers block in src/components/run/data.tsx')
  const helperSrc = src.slice(startIdx, endIdx)
  const { outputText } = ts.transpileModule(helperSrc, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  })
  const mod = { exports: {} as Record<string, unknown> }
  vm.runInNewContext(outputText, {
    exports: mod.exports,
    module: mod,
    setTimeout,
    clearTimeout,
    Date,
    AbortController,
    TextDecoder,
    Map,
    Set,
    Promise,
  })
  return mod.exports as {
    SSE_REFRESH_DEBOUNCE_MS: number
    MAX_CLIENT_RUN_EVENTS: number
    iterativeMax: (values: Iterable<number>, fallback?: number) => number
    iterativeMin: (values: Iterable<number>, fallback?: number) => number
    nextApprovalExpiryDelayMs: (
      approvals: readonly { status: string; expiresAt?: number | null }[],
      now: number,
      maxIntervalMs?: number,
    ) => number | null
    createSseRefreshCoalescer: (opts: {
      debounceMs?: number
      refreshDetail: () => Promise<unknown>
      refreshShell: () => Promise<unknown>
      setTimeoutFn?: typeof setTimeout
      clearTimeoutFn?: typeof clearTimeout
    }) => {
      schedule: (needsShell: boolean) => void
      forceSync: (needsShell?: boolean) => void
      dispose: () => void
      readonly pendingTimer: boolean
      readonly inFlight: boolean
    }
    mergeRunEvents: (existing: readonly RunEvent[], incoming: readonly RunEvent[], maxEvents?: number) => RunEvent[]
    shouldRefreshRunShell: (kind: string) => boolean
  }
}

function loadExportedTsxSymbols<T extends Record<string, unknown>>(
  relPath: string,
  symbolNames: readonly string[],
  scopeVars: Record<string, unknown> = {},
): T {
  const fullPath = join(REPO_ROOT, relPath)
  const src = readFileSync(fullPath, 'utf8')
  const sf = ts.createSourceFile(fullPath, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TSX)
  const wanted = new Set(symbolNames)
  const chunks: string[] = []
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name && wanted.has(stmt.name.text)) {
      chunks.push(src.slice(stmt.getStart(sf), stmt.getEnd()).replace(/^export\s+/, ''))
    } else if (
      ts.isVariableStatement(stmt)
      && stmt.declarationList.declarations.some(d => ts.isIdentifier(d.name) && wanted.has(d.name.text))
    ) {
      chunks.push(src.slice(stmt.getStart(sf), stmt.getEnd()).replace(/^export\s+/, ''))
    }
  }
  assert.equal(chunks.length, symbolNames.length, `Expected symbols (${symbolNames.join(', ')}) in ${relPath}`)
  const js = ts.transpileModule(chunks.join('\n\n'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText
  const factory = new Function(...Object.keys(scopeVars), `${js}\nreturn { ${symbolNames.join(', ')} };`)
  return factory(...Object.values(scopeVars)) as T
}

function makeFakeDetail(overrides: Partial<Detail> = {}): Detail {
  const now = 1_700_000_000_000
  return {
    run: {
      id: 'run-u1u4',
      projectId: 'proj-u1u4',
      goal: 'Verify auth boundaries',
      status: 'running',
      phase: 'investigation',
      createdAt: now - 60_000,
      phase0CompletedAt: now - 50_000,
      capabilityTier: 3,
      approvalPolicy: 'auto_review',
      scopeRevision: 1,
      goalRevision: 1,
      sourceMode: 'live',
      coordinatorId: 'coord-1',
      approved: ['a1'],
      approvedPersonaIds: [],
      candidates: [{ id: 'a1', origin: 'https://app.example.test', source: 'Project seed', thirdParty: false }],
      budgetUsd: 10,
      spentUsd: 1,
      budgetRequests: 500,
      spentRequests: 10,
      maxRpsPerOrigin: 10,
      approvedEndpointPatterns: [],
    },
    project: {
      id: 'proj-u1u4',
      name: 'Example',
      environment: 'public',
      seeds: ['https://app.example.test'],
      defaultScope: [],
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
    approvalLeases: [],
    approvedEndpointPatterns: [],
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
    provenanceCounts: { runtime_confirmed: 0, static_verified: 0, baseline_confirmed: 0, unverified: 0 },
    messages: [],
    boardMembers: [],
    boardMessages: [],
    evidence: [],
    reports: [],
    cursor: 10,
    subdomainDiscoveryPending: false,
    includeSubdomainOrigins: [],
    rankedAssets: [],
    recommendedScopeAssetIds: [],
    highSignalScopeAssetIds: [],
    projection: {
      bounded: true,
      caps: RUN_DETAIL_PROJECTION_CAPS,
      totals: { evidence: 0, facts: 0, exchanges: 0, endpoints: 0, endpointParams: 0, messages: 0, boardMessages: 0, events: 0 },
      truncated: { evidence: false, facts: false, exchanges: false, endpoints: false, messages: false, boardMessages: false, events: false },
      cursors: { eventsHead: 10, exchangesOffset: 0, messagesOffset: 0, factsOffset: 0, evidenceOffset: 0, endpointsOffset: 0, boardMessagesOffset: 0 },
    },
    labTarget: null,
    localLabEnvEnabled: false,
    hasModel: true,
    ...overrides,
  } as unknown as Detail
}

// ============================================================================
// Move U1: Bounded Run Projections, Cursor Pagination, Iterative Max, SSE Burst Coalescing
// ============================================================================

test('U1: buildBoundedRunProjection caps inline slices with exact totals and queryRunEventsPage paginates older history', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-u1-proj-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const db = new Store(dir, { ftsMode: 'preview' })
  t.after(() => db.close())

  const proj = db.createProject({
    requestId: randomUUID(),
    name: 'Scale Test App',
    seeds: ['https://app.acme.co.uk'],
    environment: 'public',
    includeSubdomains: true,
  })
  const run = db.createRun({
    requestId: randomUUID(),
    projectId: proj.id,
    goal: 'Check large-run bounded projection',
    sourceMode: 'public',
    capabilityTier: 1,
    approvalPolicy: 'auto_review',
    budgetUsd: 5,
    budgetRequests: 500,
    maxRpsPerOrigin: 10,
    workerConcurrency: 2,
    workerMaxTurns: 10,
  })

  // Consent to discovery so a real worker assignment exists for recording facts
  db.command({
    requestId: randomUUID(),
    runId: run.id,
    action: 'discover',
    consent: true,
  })
  const worker = db.workerList(run.id)[0]!
  assert.ok(worker, 'expected discovery worker assignment')

  // Seed 25 events, 18 messages, and 16 facts
  for (let i = 0; i < 25; i += 1) {
    db.event(run.id, 'broker.allowed', `Allowed request #${i + 1}`, { seq: i + 1 })
  }
  const runRow = db.run(run.id)
  for (let i = 0; i < 18; i += 1) {
    db.message(run.id, runRow.coordinatorId, 'coordinator', `Coordinator update ${i + 1}`)
  }
  for (let i = 0; i < 16; i += 1) {
    db.addFact(runRow, worker, {
      kind: 'endpoint',
      origin: 'https://app.acme.co.uk',
      summary: `Discovered /api/v1/item/${i}`,
      data: { path: `/api/v1/item/${i}` },
      sourceOrigins: ['https://app.acme.co.uk'],
    })
  }

  const projected = buildBoundedRunProjection(db, run.id, SERVER_PROJECTION_DEPS, {
    limits: { messages: 5, facts: 6, exchanges: 5, evidence: 5, endpoints: 5, boardMessages: 5, events: 10 },
  })

  assert.equal(projected.projection.bounded, true)
  assert.equal(projected.messages.length, 5, 'inline messages must respect projection cap')
  assert.equal(projected.facts.length, 6, 'inline facts must respect projection cap')
  assert.ok(projected.projection.totals.messages >= 18, 'totals.messages must reflect true DB count')
  assert.equal(projected.projection.totals.facts, 16, 'totals.facts must reflect true DB count')
  assert.ok(projected.projection.totals.events >= 25, 'totals.events must reflect true DB count')
  assert.equal(projected.projection.truncated.messages, true)
  assert.equal(projected.projection.truncated.facts, true)
  assert.equal(projected.projection.truncated.events, true)
  assert.equal(projected.projection.cursors.messagesOffset, 5)
  assert.equal(projected.projection.cursors.factsOffset, 6)
  assert.equal(projected.projection.cursors.eventsHead, projected.cursor)

  // On-demand older event pagination via queryRunEventsPage
  const newestPage = queryRunEventsPage(db, run.id, SERVER_PROJECTION_DEPS, { limit: 10 })
  assert.equal(newestPage.events.length, 10)
  assert.equal(newestPage.hasMore, true)
  assert.ok(newestPage.oldestId !== null && newestPage.newestId !== null)
  assert.ok(newestPage.oldestId! < newestPage.newestId!, 'events page must be ascending by id')

  const olderPage = queryRunEventsPage(db, run.id, SERVER_PROJECTION_DEPS, { beforeId: newestPage.oldestId!, limit: 10 })
  assert.equal(olderPage.events.length, 10)
  assert.ok(olderPage.newestId! < newestPage.oldestId!, 'older page must strictly precede cursor')
  for (let i = 1; i < olderPage.events.length; i += 1) {
    assert.ok(olderPage.events[i]!.id > olderPage.events[i - 1]!.id, 'page must stay strictly ascending')
  }

  // actions.ts must no longer call db.projectDetail() inside runData/buildBoundedRunProjection
  const actionsSrc = readRepo('src/actions.ts')
  const buildFnStart = actionsSrc.indexOf('export function buildBoundedRunProjection(')
  const buildFnEnd = actionsSrc.indexOf('export function queryRunEventsPage(')
  assert.ok(buildFnStart > 0 && buildFnEnd > buildFnStart)
  const buildFnBody = actionsSrc.slice(buildFnStart, buildFnEnd)
  assert.equal(buildFnBody.includes('projectDetail('), false, 'buildBoundedRunProjection must not aggregate full projectDetail')
})

test('U1: iterativeMax / iterativeMin handle 150,000 items without stack overflow and mergeRunEvents bounds client RAM', () => {
  const helpers = loadRunDataHelpers()
  const count = 150_000
  const huge = new Array<number>(count)
  for (let i = 0; i < count; i += 1) {
    huge[i] = i === 123_456 ? 999_999_999 : i
  }
  assert.equal(helpers.iterativeMax(huge), 999_999_999)
  assert.equal(helpers.iterativeMin(huge), 0)
  assert.equal(helpers.iterativeMax([], -1), -1)
  assert.equal(helpers.iterativeMin([Number.NaN, Infinity], 42), 42)

  // Client live event ring buffer caps at MAX_CLIENT_RUN_EVENTS (keeping newest events ascending)
  const incoming: RunEvent[] = []
  for (let i = 1; i <= 2500; i += 1) {
    incoming.push({ id: i, runId: 'r1', kind: 'broker.allowed', message: `e${i}`, detail: {}, createdAt: i * 10 })
  }
  const bounded = helpers.mergeRunEvents([], incoming)
  assert.equal(bounded.length, helpers.MAX_CLIENT_RUN_EVENTS)
  assert.equal(bounded[0]!.id, 501)
  assert.equal(bounded[bounded.length - 1]!.id, 2500)
})

test('U1: createSseRefreshCoalescer coalesces rapid bursts and NEVER drops the final tick arriving mid-flight', async () => {
  const helpers = loadRunDataHelpers()
  const timers = new Map<number, () => void>()
  let nextTimerId = 1
  const fakeSetTimeout = ((fn: () => void) => {
    const id = nextTimerId++
    timers.set(id, fn)
    return id as unknown as ReturnType<typeof setTimeout>
  }) as unknown as typeof setTimeout
  const fakeClearTimeout = ((id: ReturnType<typeof setTimeout>) => {
    timers.delete(id as unknown as number)
  }) as unknown as typeof clearTimeout

  let detailCalls = 0
  let shellCalls = 0
  let resolveFirstDetail: (() => void) | null = null

  const coalescer = helpers.createSseRefreshCoalescer({
    debounceMs: 350,
    setTimeoutFn: fakeSetTimeout,
    clearTimeoutFn: fakeClearTimeout,
    refreshDetail: () => {
      detailCalls += 1
      if (detailCalls === 1) {
        return new Promise<void>(r => { resolveFirstDetail = r })
      }
      return Promise.resolve()
    },
    refreshShell: () => {
      shellCalls += 1
      return Promise.resolve()
    },
  })

  // Rapid burst of 15 SSE events (only #7 requires shell refresh): must schedule ONE timer
  for (let i = 0; i < 15; i += 1) {
    coalescer.schedule(i === 7)
  }
  assert.equal(timers.size, 1, 'rapid burst must coalesce into one debounce timer')
  assert.equal(detailCalls, 0)

  // Fire timer -> starts first refresh (with shell = true because #7 flagged it)
  const firstTimer = [...timers.values()][0]!
  timers.clear()
  firstTimer()
  assert.equal(detailCalls, 1)
  assert.equal(shellCalls, 1)
  assert.equal(coalescer.inFlight, true)

  // Another burst arrives WHILE first refresh is in flight (including final tick!)
  coalescer.schedule(false)
  coalescer.schedule(true)
  coalescer.schedule(false)
  assert.equal(timers.size, 0, 'must not overlap refresh while in flight')

  // First refresh settles -> MUST schedule trailing refresh so final tick is never dropped!
  resolveFirstDetail!()
  await new Promise(r => setImmediate(r))
  assert.equal(coalescer.inFlight, false)
  assert.equal(timers.size, 1, 'trailing refresh MUST be scheduled after in-flight burst')

  // Fire trailing timer -> executes 2nd refresh AND honors accumulated shell flag
  const trailingTimer = [...timers.values()][0]!
  timers.clear()
  trailingTimer()
  await new Promise(r => setImmediate(r))
  assert.equal(detailCalls, 2)
  assert.equal(shellCalls, 2)
  assert.equal(timers.size, 0)

  // forceSync on reconnect bypasses debounce immediately
  coalescer.schedule(false)
  assert.equal(timers.size, 1)
  coalescer.forceSync(true)
  await new Promise(r => setImmediate(r))
  assert.equal(timers.size, 0)
  assert.equal(detailCalls, 3)
  assert.equal(shellCalls, 3)

  // dispose cancels pending timer cleanly
  coalescer.schedule(false)
  assert.equal(timers.size, 1)
  coalescer.dispose()
  assert.equal(timers.size, 0)
})

// ============================================================================
// Move U3: Reconciling Optimistic Decisions & Single Shared Expiry Clock
// ============================================================================

test('U3: reconcileOptimisticDecisions and deriveQueueDecisions drop settled/expired shadows on server refresh', () => {
  const { reconcileOptimisticDecisions, deriveQueueDecisions } = loadExportedTsxSymbols<{
    reconcileOptimisticDecisions: (
      all: Record<string, { act: string; at: number; state: string }>,
      queueItem: Map<string, QueueItem>,
      now?: number,
    ) => Record<string, { act: string; at: number; state: string }>
    deriveQueueDecisions: (
      base: Record<QueueSection, QueueItem[]>,
      queueItem: Map<string, QueueItem>,
      all: Record<string, { act: string; at: number; state: string }>,
      now?: number,
    ) => {
      sections: Record<QueueSection, QueueItem[]>
      activePendingApprovals: Approval[]
      activeDecideCount: number
    }
  }>(
    'src/components/run/decisions.tsx',
    ['computeQueueProgress', 'reconcileOptimisticDecisions', 'deriveQueueDecisions'],
    { isApprovalExpired },
  )

  const now = 1_700_000_500_000
  const apActive: Approval = {
    id: 'ap-active',
    runId: 'run-u1u4',
    assignmentId: 'w-1',
    origin: 'https://app.example.test',
    method: 'POST',
    pathAndQuery: '/api/items',
    status: 'pending',
    createdAt: now - 10_000,
    expiresAt: now + 60_000,
    decidedAt: null,
  } as unknown as Approval
  const apServerDenied: Approval = {
    ...apActive,
    id: 'ap-settled',
    status: 'denied',
    decidedAt: now - 1_000,
  } as unknown as Approval
  const apExpired: Approval = {
    ...apActive,
    id: 'ap-expired',
    status: 'pending',
    expiresAt: now - 100,
  } as unknown as Approval

  const model = buildRunModel(makeFakeDetail({ approvals: [apActive, apServerDenied, apExpired] }), now)

  const staleOptimistic = {
    'ap:ap-active': { act: 'approve', at: now - 500, state: 'sent' },
    'ap:ap-settled': { act: 'approve', at: now - 500, state: 'sent' },
    'ap:ap-expired': { act: 'approve', at: now - 500, state: 'sent' },
    'ap:ap-vanished': { act: 'approve', at: now - 500, state: 'sent' },
  }

  const reconciled = reconcileOptimisticDecisions(staleOptimistic, model.queueItem, now)
  assert.deepEqual(
    Object.keys(reconciled),
    ['ap:ap-active'],
    'Only still-pending non-expired approvals may retain an optimistic overlay',
  )

  // Even if caller passes raw stale map into deriveQueueDecisions, settled/expired items reconcile cleanly
  const derived = deriveQueueDecisions(model.queue, model.queueItem, staleOptimistic, now)
  assert.equal(derived.activeDecideCount, 0)
  assert.equal(derived.activePendingApprovals.length, 0)
  assert.equal(derived.sections.done.some(it => it.key === 'ap:ap-settled'), true)
  assert.equal(derived.sections.done.some(it => it.key === 'ap:ap-expired'), true)

  // Once ap-active ALSO expires on the shared clock, its optimistic overlay is reconciled away immediately
  const afterExpiry = now + 65_000
  const reconciledAfter = reconcileOptimisticDecisions(reconciled, model.queueItem, afterExpiry)
  assert.deepEqual(Object.keys(reconciledAfter), [])
})

test('U3: single shared expiry clock lives in RunDataProvider (exact next-expiry wakeup, zero duplicate interval in decisions.tsx)', () => {
  const helpers = loadRunDataHelpers()
  const now = 1_700_000_000_000
  assert.equal(helpers.nextApprovalExpiryDelayMs([], now), null)
  assert.equal(
    helpers.nextApprovalExpiryDelayMs([{ status: 'approved', expiresAt: now + 2000 }], now),
    null,
  )
  assert.equal(
    helpers.nextApprovalExpiryDelayMs(
      [
        { status: 'pending', expiresAt: now + 9_000 },
        { status: 'pending', expiresAt: now + 3_200 },
        { status: 'pending', expiresAt: now - 500 },
      ],
      now,
    ),
    3_200,
    'clock must schedule right at the earliest future pending approval expiry',
  )
  assert.equal(
    helpers.nextApprovalExpiryDelayMs([{ status: 'pending', expiresAt: now + 60_000 }], now, 15_000),
    15_000,
    'delay must cap at maxIntervalMs',
  )

  const decisionsSrc = readRepo('src/components/run/decisions.tsx')
  assert.equal(decisionsSrc.includes('setInterval'), false, 'decisions.tsx must not run a duplicate expiry setInterval')
  assert.match(decisionsSrc, /const \{[^}]*\bnow\b[^}]*\} = useRun\(\)/, 'decisions.tsx must read shared `now` from useRun()')

  const dataSrc = readRepo('src/components/run/data.tsx')
  assert.match(dataSrc, /needsSyncRef\.current = true/, 'data.tsx must mark needsSync on disconnect/refresh failure')
  assert.match(dataSrc, /coalescer\.forceSync\(true\)/, 'data.tsx must force-reconcile on SSE reconnect')
})

// ============================================================================
// Move U4: Server-Authoritative Scope Ranking (-142 KB PSL dropped from client) & ReportView Guard
// ============================================================================

test('U4: server computes authoritative PSL scope ranking and consent.tsx no longer imports public-suffix-list.ts', () => {
  const consentSrc = readRepo('src/components/run/views/consent.tsx')
  assert.equal(
    consentSrc.includes('public-suffix-list'),
    false,
    'consent.tsx must NOT import src/server/public-suffix-list.ts into the browser bundle',
  )
  assert.doesNotMatch(consentSrc, /from\s+['"]node:/, 'consent.tsx must remain free of Node builtins')
  assert.match(consentSrc, /detail\.recommendedScopeAssetIds/, 'consent.tsx must consume server recommendedScopeAssetIds')
  assert.match(consentSrc, /detail\.highSignalScopeAssetIds/, 'consent.tsx must consume server highSignalScopeAssetIds')

  // Server-authoritative PSL ranking handles .co.uk, shared PaaS isolation, and Top-30 sprawl suppression
  const ukCandidates = [
    { id: 'seed-uk', origin: 'https://app.acme.co.uk', source: 'Project seed', thirdParty: false, includeSubdomains: true },
    { id: 'api-uk', origin: 'https://api.acme.co.uk', source: 'subdomain_discovery', thirdParty: false, dnsSource: { zone: 'acme.co.uk' } },
    { id: 'evil-uk', origin: 'https://evil.co.uk', source: 'subdomain_discovery', thirdParty: false, dnsSource: { zone: 'co.uk' } },
    { id: 'third-party', origin: 'https://docs.acme.co.uk', source: 'subdomain_discovery', thirdParty: true, dnsSource: { externalAliases: ['hosting.gitbook.io'] } },
    ...Array.from({ length: 35 }, (_, i) => ({
      id: `pr-${i}`,
      origin: `https://pr-${100 + i}.acme.co.uk`,
      source: 'subdomain_discovery',
      thirdParty: false,
      dnsSource: { zone: 'acme.co.uk' },
    })),
  ]

  const ukRanking = computeServerScopeRanking(
    { scopeRevision: 0, approved: [], candidates: ukCandidates },
    { seeds: ['https://app.acme.co.uk'], defaultScope: [] },
    ['https://app.acme.co.uk'],
    SERVER_PROJECTION_DEPS,
  )
  assert.equal(ukRanking.recommendedScopeAssetIds.length, 30)
  assert.ok(ukRanking.recommendedScopeAssetIds.includes('seed-uk'))
  assert.ok(ukRanking.recommendedScopeAssetIds.includes('api-uk'))
  assert.equal(ukRanking.recommendedScopeAssetIds.includes('evil-uk'), false, 'unrelated .co.uk apex must be excluded')
  assert.equal(ukRanking.recommendedScopeAssetIds.includes('third-party'), false, 'third-party CNAME must stay unchecked')
  assert.equal(ukRanking.rankedAssets[0]?.id, 'seed-uk')
  assert.equal(ukRanking.rankedAssets[0]?.apex, 'acme.co.uk')

  // Shared PaaS tenant isolation on server ranking
  const paasRanking = computeServerScopeRanking(
    {
      scopeRevision: 0,
      approved: [],
      candidates: [
        { id: 'seed-paas', origin: 'https://my-app.vercel.app', source: 'Project seed', thirdParty: false, includeSubdomains: true },
        { id: 'own-sub', origin: 'https://api.my-app.vercel.app', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
        { id: 'other-tenant', origin: 'https://evil-tenant.vercel.app', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
      ],
    },
    { seeds: ['https://my-app.vercel.app'], defaultScope: [] },
    ['https://my-app.vercel.app'],
    SERVER_PROJECTION_DEPS,
  )
  assert.deepEqual(paasRanking.recommendedScopeAssetIds, ['seed-paas', 'own-sub'])

  // If production build assets exist, verify NO client asset leaks public-suffix-list.ts and runs._runId dropped 142 KB PSL
  const assetsDir = join(REPO_ROOT, 'build', 'client', 'assets')
  if (existsSync(assetsDir)) {
    const jsFiles = readdirSync(assetsDir).filter(f => f.endsWith('.js'))
    for (const file of jsFiles) {
      const body = readFileSync(join(assetsDir, file), 'utf8')
      assert.equal(body.includes('publicSuffixRules'), false, `client asset ${file} must not bundle publicSuffixRules`)
      assert.equal(body.includes('parliament.uk'), false, `client asset ${file} must not bundle vendored PSL rules`)
    }
    const runChunk = jsFiles.find(f => /^runs\._runId-.*\.js$/.test(f))
    if (runChunk) {
      const chunkBytes = statSync(join(assetsDir, runChunk)).size
      assert.ok(
        chunkBytes < 480_000,
        `expected client runs._runId bundle < 480 KB after dropping 142 KB PSL, got ${chunkBytes} bytes`,
      )
    }
  }
})

test('U4: ReportView safeReportText and normalizeReportBody prevent React crashes on sparse or object-typed finding fields', () => {
  const { safeReportText, normalizeReportBody } = loadExportedTsxSymbols<{
    safeReportText: (value: unknown, fallback?: string) => string
    normalizeReportBody: (raw: unknown) => {
      goal: string
      findings: Array<{
        id: string
        title: string
        origin: string
        severity: string
        status: string
        category: string
        reason: string
        remediation: string
        evidenceIds: string[]
        check?: { expected?: unknown; observed?: unknown }
      }>
      scope: unknown[]
      coverage: unknown[]
      gaps: string[]
    }
  }>('src/components/run/views/report.tsx', ['safeReportText', 'normalizeReportBody'])

  assert.equal(safeReportText(null, 'Unavailable'), 'Unavailable')
  assert.equal(safeReportText(undefined), '')
  assert.equal(safeReportText('plain'), 'plain')
  assert.equal(safeReportText(403), '403')
  assert.equal(safeReportText({ status: 200, header: null }), '{"status":200,"header":null}')

  // Sparse / malformed report body with object-typed `check.observed`, null arrays, and missing strings
  const normalized = normalizeReportBody({
    goal: { broken: true },
    findings: [
      null,
      {
        id: 'f-malformed',
        title: null,
        origin: undefined,
        severity: 'high',
        status: 'confirmed',
        reason: { detail: 'object reason' },
        remediation: null,
        evidenceIds: null,
        codeLocations: null,
        check: {
          expected: { header: 'strict-transport-security' },
          observed: { status: 200, header: null },
        },
      },
    ],
    scope: null,
    coverage: undefined,
    gaps: [null, { gap: 'timeout' }, 'DNS rate limited'],
  })

  assert.equal(normalized.goal, '{"broken":true}')
  assert.equal(normalized.findings.length, 1)
  assert.equal(normalized.findings[0]!.title, 'Untitled finding')
  assert.equal(normalized.findings[0]!.reason, '{"detail":"object reason"}')
  assert.deepEqual(normalized.findings[0]!.evidenceIds, [])
  assert.deepEqual(normalized.scope, [])
  assert.deepEqual(normalized.coverage, [])
  assert.deepEqual(normalized.gaps, ['{"gap":"timeout"}', 'DNS rate limited'])

  // Render the exact check-comparison structure with object-typed observed/expected through React SSR: must NOT throw
  const malformedFinding = normalized.findings[0]!
  const html = renderToStaticMarkup(
    React.createElement(
      'div',
      null,
      React.createElement('span', null, safeReportText(malformedFinding.check?.expected, 'Unavailable')),
      React.createElement('span', null, safeReportText(malformedFinding.check?.observed, 'Unavailable')),
    ),
  )
  assert.match(html, /strict-transport-security/)
  assert.match(html, /&quot;status&quot;:200/)

  // Source guard: report.tsx must never render raw `{f.check.observed}` or `{f.check.expected}` unguarded
  const reportSrc = readRepo('src/components/run/views/report.tsx')
  assert.equal(reportSrc.includes('{f.check.observed ??'), false, 'report.tsx must guard f.check.observed via safeReportText')
  assert.equal(reportSrc.includes('{f.check.observed}'), false, 'report.tsx must guard f.check.observed via safeReportText')
  assert.equal(reportSrc.includes('{f.check.expected}'), false, 'report.tsx must guard f.check.expected via safeReportText')
  assert.match(reportSrc, /safeReportText\(f\.check\.observed\)/, 'report.tsx must coerce f.check.observed through safeReportText')
  assert.match(reportSrc, /safeReportText\(f\.check\.expected\)/, 'report.tsx must coerce f.check.expected through safeReportText')
})
