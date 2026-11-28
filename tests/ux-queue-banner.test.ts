import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join, resolve } from 'node:path'
import test from 'node:test'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import ts from 'typescript'
import { host } from '../src/components/run/format.ts'
import { buildRunModel, isApprovalExpired } from '../src/components/run/model.ts'
import type { Approval, Detail, QueueItem, QueueSection } from '../src/components/run/model.ts'
import { cn, runBtn } from '../src/components/run/tw.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const require = createRequire(import.meta.url)

function readSrc(relPath: string): string {
  return readFileSync(join(REPO_ROOT, relPath), 'utf8')
}

function loadTsxExports<T extends Record<string, unknown>>(
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

  assert.equal(chunks.length, symbolNames.length, `Expected all symbols (${symbolNames.join(', ')}) in ${relPath}`)
  const js = ts.transpileModule(chunks.join('\n\n'), {
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.CommonJS,
      jsx: ts.JsxEmit.ReactJSX,
    },
  }).outputText

  const mod = { exports: {} as Record<string, unknown> }
  const factory = new Function(
    'require',
    'exports',
    'module',
    ...Object.keys(scopeVars),
    `${js}\nreturn { ${symbolNames.join(', ')} };`,
  )
  return factory(require, mod.exports, mod, ...Object.values(scopeVars)) as T
}

function makeDetail(overrides: Partial<Detail> = {}): Detail {
  const createdAt = 1_700_000_000_000
  const base = {
    run: {
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
      capabilityTier: 3,
      approvalPolicy: 'strict',
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
      label: null,
      createdAt,
    },
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

function makeApproval(id: string, overrides: Partial<Approval> = {}): Approval {
  const now = 1_700_000_500_000
  return {
    id,
    runId: 'run-1',
    assignmentId: 'worker-1',
    method: 'POST',
    origin: 'https://api.example.test',
    pathAndQuery: `/v1/users/${id}/reset`,
    status: 'pending',
    tier: 3,
    reason: 'State-changing check',
    decidedBy: null,
    decidedAt: null,
    createdAt: now - 10_000,
    expiresAt: now + 60_000,
    ...overrides,
  } as Approval
}

function loadDeriveQueueDecisions() {
  const { computeQueueProgress, deriveQueueDecisions } = loadTsxExports<{
    computeQueueProgress: (openCount: number, handledCount: number) => {
      openCount: number
      handledCount: number
      initialCount: number
      ratio: number
    }
    deriveQueueDecisions: (
      base: Record<QueueSection, QueueItem[]>,
      queueItem: Map<string, QueueItem>,
      all: Record<string, { act: string; at: number; state: string }>,
      now?: number,
    ) => {
      sections: Record<QueueSection, QueueItem[]>
      activePendingApprovals: Approval[]
      activeDecideCount: number
      openCount: number
      initialCount: number
      handledCount: number
      ratio: number
    }
  }>('src/components/run/decisions.tsx', ['computeQueueProgress', 'deriveQueueDecisions'], { isApprovalExpired })
  return { computeQueueProgress, deriveQueueDecisions }
}

test('activeDecideCount excludes follow items and client-expired approvals while counting active approvals and waiting consent', () => {
  const { deriveQueueDecisions } = loadDeriveQueueDecisions()
  const now = 1_700_000_500_000

  const active1 = makeApproval('a-active-1', { createdAt: now - 20_000, expiresAt: now + 30_000 })
  const active2 = makeApproval('a-active-2', { createdAt: now - 10_000, expiresAt: now + 40_000 })
  const expiredAtBuild = makeApproval('a-expired-build', { createdAt: now - 30_000, expiresAt: now - 5_000 })
  const expiresSoon = makeApproval('a-expires-soon', { createdAt: now - 5_000, expiresAt: now + 5_000 })

  const detail = makeDetail({
    approvals: [active1, active2, expiredAtBuild, expiresSoon],
    coverageEntries: [
      {
        id: 'cov-1',
        runId: 'run-1',
        origin: 'https://app.example.test',
        category: 'auth-session',
        status: 'needs_follow_up',
        summary: 'Verify session rotation after password change.',
        updatedAt: now - 2_000,
      } as unknown as Detail['coverageEntries'][number],
      {
        id: 'cov-2',
        runId: 'run-1',
        origin: 'https://app.example.test',
        category: 'access-control',
        status: 'needs_follow_up',
        summary: 'Check role escalation boundary.',
        updatedAt: now - 1_000,
      } as unknown as Detail['coverageEntries'][number],
    ],
  })

  // At `now`, `expiredAtBuild` is already placed in `done` by buildRunModel; 3 approvals are active; 2 follow-ups exist
  const model = buildRunModel(detail, now)
  assert.equal(model.queue.decide.length, 3)
  assert.equal(model.queue.follow.length, 2)
  assert.equal(model.queue.done.some(it => it.key === 'ap:a-expired-build'), true)

  const d0 = deriveQueueDecisions(model.queue, model.queueItem, {}, now)
  assert.equal(d0.activeDecideCount, 3)
  assert.deepEqual(d0.activePendingApprovals.map(a => a.id), ['a-active-1', 'a-active-2', 'a-expires-soon'])
  assert.equal(d0.sections.follow.length, 2, 'Follow up items remain accessible in Queue sections.follow')
  assert.equal(d0.openCount, 5, 'Queue openCount still includes follow items for Queue view header')

  // Advance clock past `expiresSoon.expiresAt` (now + 5_000): live tick excludes it from activeDecideCount & moves it to done
  const later = now + 10_000
  const d1 = deriveQueueDecisions(model.queue, model.queueItem, {}, later)
  assert.equal(d1.activeDecideCount, 2)
  assert.deepEqual(d1.activePendingApprovals.map(a => a.id), ['a-active-1', 'a-active-2'])
  assert.equal(d1.sections.done.some(it => it.key === 'ap:a-expires-soon'), true)

  // Optimistic decisions remove items from activeDecideCount and activePendingApprovals immediately
  const d2 = deriveQueueDecisions(
    model.queue,
    model.queueItem,
    {
      'ap:a-active-1': { act: 'approve', at: later, state: 'sent' },
      'ap:a-active-2': { act: 'deny', at: later + 1, state: 'sent' },
    },
    later,
  )
  assert.equal(d2.activeDecideCount, 0)
  assert.deepEqual(d2.activePendingApprovals, [])
  assert.equal(d2.sections.follow.length, 2, 'Follow-ups remain in Queue even when activeDecideCount drops to 0')

  // Waiting consent / scope review counts in activeDecideCount without inflating activePendingApprovals
  const waitingConsentDetail = makeDetail({
    run: {
      ...makeDetail().run,
      status: 'waiting',
      phase: 'consent',
    },
    coverageEntries: detail.coverageEntries,
  })
  const waitingModel = buildRunModel(waitingConsentDetail, now)
  const dConsent = deriveQueueDecisions(waitingModel.queue, waitingModel.queueItem, {}, now)
  assert.equal(dConsent.activeDecideCount, 1)
  assert.equal(dConsent.activePendingApprovals.length, 0)
  assert.equal(dConsent.sections.decide[0]?.kind, 'consent')

  const waitingReviewModel = buildRunModel(
    makeDetail({
      run: { ...makeDetail().run, status: 'waiting', phase: 'review' },
    }),
    now,
  )
  const dReview = deriveQueueDecisions(waitingReviewModel.queue, waitingReviewModel.queueItem, {}, now)
  assert.equal(dReview.activeDecideCount, 1)
  assert.equal(dReview.activePendingApprovals.length, 0)
})

test('QueueRailBadge hides at 0 and renders solid bg-accent text-accent-fg font-semibold pill when activeDecideCount > 0', () => {
  const { QueueRailBadge } = loadTsxExports<{
    QueueRailBadge: (props: { activeDecideCount: number; activePendingApprovalsCount?: number; pulse?: boolean }) => React.ReactNode
  }>('src/components/run/rail.tsx', ['QueueRailBadge'], { cn })

  const hiddenHtml = renderToStaticMarkup(React.createElement(QueueRailBadge, { activeDecideCount: 0 }))
  assert.equal(hiddenHtml, '', 'Queue rail badge must be hidden completely when activeDecideCount is 0')

  const approvalHtml = renderToStaticMarkup(
    React.createElement(QueueRailBadge, { activeDecideCount: 2, activePendingApprovalsCount: 2, pulse: true }),
  )
  assert.match(approvalHtml, /bg-accent/)
  assert.match(approvalHtml, /text-accent-fg/)
  assert.match(approvalHtml, /font-semibold/)
  assert.match(approvalHtml, /scale-\[1\.08\]/)
  assert.match(approvalHtml, /title="2 waiting for approval"/)
  assert.match(approvalHtml, />2<\/span>/)
  assert.doesNotMatch(approvalHtml, /bg-warn-soft|text-warn/)

  const consentHtml = renderToStaticMarkup(
    React.createElement(QueueRailBadge, { activeDecideCount: 1, activePendingApprovalsCount: 0, pulse: false }),
  )
  assert.match(consentHtml, /title="1 to decide"/)
  assert.match(consentHtml, />1<\/span>/)
})

test('ApprovalBanner visibility and rendering for count === 1 and count >= 2', () => {
  const MockIcon = ({ name }: { name: string }) => React.createElement('svg', { 'data-icon': name })
  const { isBoardHiddenBeforeApproval, shouldShowApprovalBanner, ApprovalBanner } = loadTsxExports<{
    isBoardHiddenBeforeApproval: (phase: string) => boolean
    shouldShowApprovalBanner: (input: { activeApprovalCount: number; view: string; phase: string }) => boolean
    ApprovalBanner: (props: {
      approvals: readonly Approval[]
      submitting: boolean
      onApprove: (ap: Approval) => void
      onDeny: (ap: Approval) => void
      onInspect: (ap: Approval) => void
      onReviewInQueue: () => void
      onApproveAll: () => void
    }) => React.ReactNode
  }>(
    'src/components/run/shell.tsx',
    ['isBoardHiddenBeforeApproval', 'shouldShowApprovalBanner', 'ApprovalBanner'],
    { host, runBtn, Icon: MockIcon },
  )

  assert.equal(isBoardHiddenBeforeApproval('consent'), true)
  assert.equal(shouldShowApprovalBanner({ activeApprovalCount: 0, view: 'overview', phase: 'investigation' }), false)
  assert.equal(shouldShowApprovalBanner({ activeApprovalCount: 2, view: 'queue', phase: 'investigation' }), false)
  assert.equal(shouldShowApprovalBanner({ activeApprovalCount: 1, view: 'overview', phase: 'consent' }), false)
  assert.equal(shouldShowApprovalBanner({ activeApprovalCount: 1, view: 'overview', phase: 'review' }), false)
  assert.equal(shouldShowApprovalBanner({ activeApprovalCount: 1, view: 'overview', phase: 'investigation' }), true)
  assert.equal(shouldShowApprovalBanner({ activeApprovalCount: 2, view: 'findings', phase: 'verification' }), true)

  const ap1 = makeApproval('ap-1', { method: 'POST', origin: 'https://auth.example.test', pathAndQuery: '/api/session/revoke' })
  const ap2 = makeApproval('ap-2', { method: 'DELETE', origin: 'https://api.example.test', pathAndQuery: '/v1/tokens/42' })

  const singleHtml = renderToStaticMarkup(
    React.createElement(ApprovalBanner, {
      approvals: [ap1],
      submitting: false,
      onApprove: () => {},
      onDeny: () => {},
      onInspect: () => {},
      onReviewInQueue: () => {},
      onApproveAll: () => {},
    }),
  )
  assert.match(singleHtml, /bg-accent-soft/)
  assert.match(singleHtml, /border-b border-accent-line/)
  assert.match(singleHtml, /bg-accent/)
  assert.match(singleHtml, /1 approval waiting/)
  assert.match(singleHtml, /POST/)
  assert.match(singleHtml, /auth\.example\.test/)
  assert.match(singleHtml, /\/api\/session\/revoke/)
  assert.match(singleHtml, /<button[^>]*class="[^"]*bg-accent[^"]*text-accent-fg[^"]*"[^>]*data-testid="approval-banner-approve"[^>]*>.*?Approve<\/button>/)
  assert.match(singleHtml, /data-testid="approval-banner-deny"[^>]*>Deny<\/button>/)
  assert.match(singleHtml, /data-testid="approval-banner-inspect"[^>]*>Inspect<\/button>/)

  const multiHtml = renderToStaticMarkup(
    React.createElement(ApprovalBanner, {
      approvals: [ap1, ap2],
      submitting: false,
      onApprove: () => {},
      onDeny: () => {},
      onInspect: () => {},
      onReviewInQueue: () => {},
      onApproveAll: () => {},
    }),
  )
  assert.match(multiHtml, /2 approvals waiting/)
  assert.match(multiHtml, /auth\.example\.test/)
  assert.match(multiHtml, /\(\+1 more\)/)
  assert.match(multiHtml, /data-testid="approval-banner-review"[^>]*>Review in Queue<\/button>/)
  assert.match(multiHtml, /<button[^>]*class="[^"]*bg-accent[^"]*text-accent-fg[^"]*"[^>]*data-testid="approval-banner-approve-all"[^>]*>.*?Approve all \(2\)<\/button>/)

  const submittingHtml = renderToStaticMarkup(
    React.createElement(ApprovalBanner, {
      approvals: [ap1, ap2],
      submitting: true,
      onApprove: () => {},
      onDeny: () => {},
      onInspect: () => {},
      onReviewInQueue: () => {},
      onApproveAll: () => {},
    }),
  )
  assert.match(submittingHtml, /disabled=""/)
  assert.match(submittingHtml, /Approving 2…/)
})

test('rail, shell, decisions, and queue wiring stay synchronized around activeDecideCount and activePendingApprovals', () => {
  const railSrc = readSrc('src/components/run/rail.tsx')
  const shellSrc = readSrc('src/components/run/shell.tsx')
  const queueSrc = readSrc('src/components/run/views/queue.tsx')
  const decisionsSrc = readSrc('src/components/run/decisions.tsx')

  // Rail uses activeDecideCount (not openCount) for Queue badge & pulse, and preserves Findings count
  assert.match(railSrc, /usePulse\(detail\.run\.id \+ ':' \+ q\.activeDecideCount\)/)
  assert.match(railSrc, /activeDecideCount=\{q\.activeDecideCount\}/)
  assert.match(railSrc, /findings:\s*model\.findings\.length > 0 \? fmtN\(model\.findings\.length\) : ''/)

  // Shell RunBanners reads shared useDecisions() state & handlers and hides on view === 'queue'
  assert.match(shellSrc, /activeApprovalCount:\s*q\.activePendingApprovals\.length/)
  assert.match(shellSrc, /view:\s*nav\.view/)
  assert.match(shellSrc, /q\.decide\('ap:' \+ ap\.id,\s*act/)
  assert.match(shellSrc, /q\.approveAllPending\(\)/)
  assert.match(shellSrc, /nav\.open\('queue',\s*\{\s*kind:\s*'queue',\s*id:\s*'ap:' \+ ap\.id\s*\}\)/)
  assert.match(shellSrc, /nav\.setView\('queue'\)/)

  // Decisions + Queue share activePendingApprovals and approveAllPending
  assert.match(decisionsSrc, /activeDecideCount/)
  assert.match(decisionsSrc, /activePendingApprovals/)
  assert.match(decisionsSrc, /approveAllPending/)
  assert.match(queueSrc, /q\.activePendingApprovals/)
  assert.match(queueSrc, /q\.approveAllPending\(\{\s*action:\s*'approve_all_pending'\s*\}\)/)
  assert.match(queueSrc, /QSEC\.filter/)
})
