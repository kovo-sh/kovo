/**
 * Kovo Hunter v5 M5 (execution wiring) — board tools in worker turns, deterministic 0-LLM posters,
 * operator routing, delta injection, warm specialist lifecycle and Tier-3 pause.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { Execution } from '../src/server/execution.ts'
import { Store } from '../src/server/store.ts'
import type { Assignment, ChainStep, Run } from '../src/server/store.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

const origin = 'https://board-exec.example'
const revokedOrigin = 'https://revoked-board.example'

type PrivateExecution = Record<string, any>

async function makeExecution(t: { after: (fn: () => void) => void }) {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v5-board-exec-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const store = new Store(dir)
  const execution = new Execution(store)
  t.after(async () => { await execution.stop(); store.close() })
  const { runId, assetIds } = await setupApprovedRun(store, {
    seeds: [origin], tier: 2, environment: 'public', budgetUsd: 10, budgetRequests: 200,
  })
  store.updateRun(runId, { phase: 'investigation', status: 'running' })
  const run = store.run(runId)
  return { store, execution, priv: execution as unknown as PrivateExecution, run, runId, assetIds }
}

function addStep(store: Store, run: Run, assetIds: readonly string[], profile: ChainStep['specialistProfile'] = 'auth-session-oauth-specialist') {
  return store.addChainStep(run, {
    title: 'Verify JWT session fixation',
    hypothesis: 'Session identifier is not rotated after login.',
    category: 'auth-session',
    priority: 90,
    targetAssetIds: [...assetIds],
    sourceOrigins: [origin],
    specialistProfile: profile,
  })
}

function stubWorker(priv: PrivateExecution, capture?: (job: { assignment: Assignment }, step: ChainStep) => void) {
  priv.runInvestigationWorker = async (job: { assignment: Assignment }, step: ChainStep) => {
    capture?.(job, step)
    await delay(5)
    priv.storage.updateWorker(job.assignment.id, { status: 'complete', outcome: 'Stub step complete.' })
  }
}

test('a dispatched chain step emits a @coordinator brief and keeps the warm member waiting', async t => {
  const { store, priv, run, assetIds, runId } = await makeExecution(t)
  const step = addStep(store, run, assetIds)
  let captured: { assignment: Assignment; step: ChainStep } | undefined
  stubWorker(priv, (job, started) => { captured = { assignment: job.assignment, step: started } })

  priv.startInvestigationStep(run, step, [])
  await delay(30)

  assert.ok(captured, 'worker was started')
  const brief = store.listBoardMessages(runId).find(message => message.kind === 'brief')
  assert.ok(brief, 'coordinator brief emitted')
  assert.equal(brief.authorHandle, 'coordinator')
  assert.deepEqual(brief.mentions, ['auth'])
  assert.equal(brief.refStepId, step.id)
  assert.deepEqual(brief.sourceOrigins, [origin])
  assert.match(brief.body, /Verify JWT session fixation/)

  const member = store.boardMember(runId, 'auth')
  assert.ok(member)
  assert.equal(member.state, 'waiting')
  assert.equal(member.activeAssignmentId, null)
  assert.equal(priv.warm.get('auth').state, 'waiting')
})

test('operator @handle posts route to that specialist and reuse the waiting warm session; plain text stays with @coordinator', async t => {
  const { store, priv, run, runId } = await makeExecution(t)
  store.upsertBoardMember(run, {
    handle: 'auth', role: 'specialist', specialistProfile: 'auth-session-oauth-specialist',
    sessionId: 'warm-auth-session', state: 'waiting', sourceOrigins: [origin],
  })

  store.command({ requestId: randomUUID(), runId, action: 'message', message: '@auth investigate the impersonation token mint' })
  const before = store.listChainSteps(runId, run.goalRevision).length
  priv.routeOperatorBoardMessages(store.run(runId))
  const steps = store.listChainSteps(runId, run.goalRevision)
  assert.equal(steps.length, before + 1, 'a follow-up step was queued for @auth')
  const wakeStep = steps[steps.length - 1]
  assert.equal(wakeStep.specialistProfile, 'auth-session-oauth-specialist')

  let captured: Assignment | undefined
  stubWorker(priv, job => { captured = job.assignment })
  priv.startInvestigationStep(store.run(runId), wakeStep, [])
  await delay(30)
  assert.equal(captured?.sessionId, 'warm-auth-session', 'wake resumed the durable warm session')
  assert.equal(store.listBoardMessages(runId).filter(message => message.kind === 'brief').length, 1)

  // Replaying the same operator cursor must not spawn a duplicate step.
  priv.routeOperatorBoardMessages(store.run(runId))
  assert.equal(store.listChainSteps(runId, run.goalRevision).length, before + 1)

  // Plain text (no @handle) and @coordinator both answer through the coordinator path.
  assert.equal(priv.shouldCoordinatorAnswer('Plain question without a handle'), true)
  assert.equal(priv.shouldCoordinatorAnswer('@coordinator what is happening?'), true)
  assert.equal(priv.shouldCoordinatorAnswer('@auth check the token route'), false)
  assert.equal(priv.shouldCoordinatorAnswer('@auth @coordinator coordinate this'), true)
  const afterCoordinator = store.listChainSteps(runId, run.goalRevision).length
  store.command({ requestId: randomUUID(), runId, action: 'message', message: 'status update please' })
  priv.routeOperatorBoardMessages(store.run(runId))
  assert.equal(store.listChainSteps(runId, run.goalRevision).length, afterCoordinator)
  const mirrored = store.listBoardMessages(runId).filter(message => message.authorHandle === 'operator')
  assert.ok(mirrored.some(message => message.mentions.includes('coordinator')))
})

test('turn-start board delta injects peer briefs once and persists the cursor', async t => {
  const { store, priv, run, runId } = await makeExecution(t)
  store.upsertBoardMember(run, {
    handle: 'bola', role: 'specialist', specialistProfile: 'bola-bfla-specialist',
    state: 'waiting', sourceOrigins: [origin],
  })
  const brief = store.postBoardMessage(run, {
    authorHandle: 'coordinator', authorRole: 'coordinator', kind: 'brief',
    body: 'Verify tenant isolation on /api/invoices/{id}', mentions: ['auth'],
    refStepId: 'step_delta', sourceOrigins: [origin],
  })
  store.postBoardMessage(run, {
    authorHandle: 'bola', authorRole: 'specialist', kind: 'claim',
    body: 'Working the invoice route', sourceOrigins: [origin],
  })

  const first = priv.boardTurnDelta(store.run(runId), 'bola', 0)
  assert.ok(first.text.startsWith('<board_delta'), first.text)
  assert.ok(first.text.includes(`[#${brief.seq}][brief] @coordinator -> @auth`))
  assert.equal(first.text.includes('Working the invoice route'), false, 'own posts are not echoed')
  assert.equal(first.cursor, brief.seq + 1)
  assert.equal(store.boardMember(runId, 'bola')?.lastReadSeq, first.cursor)

  const second = priv.boardTurnDelta(store.run(runId), 'bola', first.cursor)
  assert.equal(second.text, '')
  assert.equal(second.cursor, first.cursor)
})

test('verifier verdicts post a confirmed finding chip or sanitized failure feedback mentioning the author', async t => {
  const { store, priv, run, runId } = await makeExecution(t)
  const worker = store.makeWorker(run, 'verification', undefined, 'Verify replay spec', 'Zero-LLM replay', { sourceOrigins: [origin] })
  store.upsertBoardMember(run, {
    handle: 'auth', role: 'specialist', specialistProfile: 'auth-session-oauth-specialist',
    state: 'working', activeAssignmentId: worker.id, sourceOrigins: [origin],
  })
  priv.boardHandleByAssignment.set(worker.id, 'auth')

  priv.postVerificationVerdict(store.run(runId), {
    replaySpecId: 'spec_ok', findingId: 'finding_1', title: 'Cross-tenant token mint',
    status: 'confirmed', verificationTier: 'runtime_confirmed', assignmentId: worker.id,
  })
  const confirmed = store.listBoardMessages(runId).find(message => message.kind === 'verdict' && message.refFindingIds.includes('finding_1'))
  assert.ok(confirmed)
  assert.equal(confirmed.authorHandle, 'verifier')
  assert.match(confirmed.body, /confirmed/)
  assert.equal(confirmed.mentions.length, 0)

  priv.postVerificationVerdict(store.run(runId), {
    replaySpecId: 'spec_fail', findingId: 'finding_2', title: 'Stored payload render',
    status: 'inconclusive', assignmentId: worker.id, refStepId: 'step_9',
    feedback: {
      verdict: 'inconclusive', controlPassed: false,
      assertionSummary: { observed: 'control returned 500', expected: 'control 2xx' },
      failedStepId: 'step_2', jqError: 'expected status 200 got 500', stepStatuses: [], retriesRemaining: 1,
    } as any,
  })
  const failed = store.listBoardMessages(runId).find(message => message.kind === 'verdict' && message.body.includes('spec_fail'))
  assert.ok(failed)
  assert.deepEqual(failed.mentions, ['auth'])
  assert.match(failed.body, /control returned 500/)
  assert.match(failed.body, /expected control 2xx/)
  assert.match(failed.body, /step_2/)
  assert.equal(failed.refStepId, 'step_9')
})

test('broker circuit blockers and canary leads post deterministic system messages', async t => {
  const { store, priv, run, runId } = await makeExecution(t)

  priv.postBrokerBlocker(store.run(runId), origin, 429)
  const blocker = store.listBoardMessages(runId).find(message => message.kind === 'blocker')
  assert.ok(blocker)
  assert.equal(blocker.authorHandle, 'broker')
  assert.deepEqual(blocker.mentions, ['all'])
  assert.match(blocker.body, /429/)

  priv.postCanaryLead(store.run(runId), {
    marker: 'gn2o_deadbeef', origin, endpoint: '/admin/render', persona: 'tenant_b', exchangeId: 'ex_canary',
  })
  const lead = store.listBoardMessages(runId).find(message => message.kind === 'lead')
  assert.ok(lead)
  assert.equal(lead.authorHandle, 'canary')
  assert.deepEqual(lead.mentions, ['browser'])
  assert.deepEqual(lead.refExchangeIds, ['ex_canary'])

  priv.postCanaryLead(store.run(runId), {
    marker: 'gn2o_deadbeef2', origin, endpoint: '/api/v2/items', persona: 'tenant_a', exchangeId: 'ex_canary2',
  })
  const injectionLead = store.listBoardMessages(runId).find(message => message.kind === 'lead' && message.refExchangeIds.includes('ex_canary2'))
  assert.ok(injectionLead)
  assert.deepEqual(injectionLead.mentions, ['injection'])
})

test('Tier-3 approval cards pause the member and the resolution resumes it', async t => {
  const { store, priv, run, runId } = await makeExecution(t)
  const worker = store.makeWorker(run, 'investigation', undefined, 'Tier 3 burst', 'Race the checkout', { sourceOrigins: [origin] })
  store.upsertBoardMember(run, {
    handle: 'logic', role: 'specialist', specialistProfile: 'business-logic-race-specialist',
    sessionId: 'warm-logic-session', state: 'working', activeAssignmentId: worker.id, sourceOrigins: [origin],
  })
  priv.boardHandleByAssignment.set(worker.id, 'logic')

  priv.postApprovalCard(store.run(runId), worker.id, {
    approvalId: 'approval_1', origin, method: 'POST', pathAndQuery: '/api/checkout',
    rationale: 'State-changing burst needs operator approval.',
  })
  const card = store.listBoardMessages(runId).find(message => message.kind === 'approval')
  assert.ok(card)
  assert.equal(card.authorHandle, 'broker')
  assert.equal(card.refApprovalId, 'approval_1')
  assert.deepEqual(card.mentions, ['logic'])
  assert.equal(store.boardMember(runId, 'logic')?.state, 'paused')
  assert.equal(priv.warm.get('logic').state, 'paused')

  priv.postApprovalResolution(store.run(runId), worker.id, {
    approvalId: 'approval_1', decision: 'approved', origin, method: 'POST', pathAndQuery: '/api/checkout',
  })
  assert.equal(store.boardMember(runId, 'logic')?.state, 'working')
  assert.equal(priv.warm.get('logic').state, 'working')
  const resolution = store.listBoardMessages(runId).find(message => message.kind === 'status' && message.refApprovalId === 'approval_1')
  assert.ok(resolution)
  assert.match(resolution.body, /approved/)
})

test('warm retirement mirrors stop, turn ceilings and scope revocation', async t => {
  const { store, priv, runId } = await makeExecution(t)
  store.upsertBoardMember(store.run(runId), {
    handle: 'edge', role: 'specialist', specialistProfile: 'protocol-cache-edge-specialist',
    sessionId: 'warm-edge-session', state: 'working', sourceOrigins: [origin],
  })
  priv.warm.register('edge', { sessionId: 'warm-edge-session', state: 'working', contextWindow: 100 })

  priv.syncBoardRoster(store.run(runId))
  assert.equal(store.boardMember(runId, 'edge')?.state, 'working')
  priv.warm.completeTurn('edge', { contextTokens: 90 })
  assert.equal(priv.warm.get('edge').state, 'retired')
  assert.equal(priv.warm.get('edge').retiredReason, 'context_ceiling')

  store.updateRun(runId, { status: 'stopped' })
  priv.syncBoardRoster(store.run(runId))
  assert.equal(store.boardMember(runId, 'edge')?.state, 'retired')

  // Scope revocation retires warm members whose source origins are no longer approved.
  const { store: store2, priv: priv2, runId: runId2 } = await makeExecution(t)
  store2.upsertBoardMember(store2.run(runId2), {
    handle: 'graphql', role: 'specialist', specialistProfile: 'graphql-api-specialist',
    sessionId: 'warm-graphql-session', state: 'waiting', sourceOrigins: [revokedOrigin],
  })
  priv2.syncBoardRoster(store2.run(runId2))
  assert.equal(store2.boardMember(runId2, 'graphql')?.state, 'retired')
  assert.equal(priv2.warm.get('graphql').state, 'retired')
})

test('deterministic posters are wired into dispatch, verification, circuit, approval, canary and turn-start hooks', () => {
  const source = readFileSync(resolve(new URL('..', import.meta.url).pathname, 'src/server/execution.ts'), 'utf8')
  for (const fragment of [
    'this.postCoordinatorBrief(run, effectiveStep, boardHandle, targetOrigins)',
    'this.postVerificationVerdict(this.storage.run(params.job.assignment.runId)',
    'this.postBrokerBlocker(fresh, origin, status)',
    'this.postApprovalCard(run, job.assignment.id',
    'this.postApprovalResolution(run, job.assignment.id',
    'this.postCanaryLead(curRun',
    'onTurnStart: turn =>',
    "injectBoardTurnInstructions('', delta.text)",
    'boardTools.noteEvidence()',
    'this.boardTurnDelta(this.storage.run(run.id), boardHandle',
  ]) {
    assert.ok(source.includes(fragment), `execution wiring is missing: ${fragment}`)
  }
})

test('parallel steps for one profile use sharded handles instead of serializing behind a singleton', async t => {
  const { store, priv, run, assetIds, runId } = await makeExecution(t)
  const first = addStep(store, run, assetIds)
  const second = addStep(store, run, assetIds)
  const gates: Array<() => void> = []
  priv.runInvestigationWorker = (job: { assignment: Assignment }) => new Promise<void>(resolve => {
    gates.push(() => {
      priv.storage.updateWorker(job.assignment.id, { status: 'complete', outcome: 'Stub step complete.' })
      resolve()
    })
  })

  priv.startInvestigationStep(store.run(runId), first, [])
  priv.startInvestigationStep(store.run(runId), second, [])
  await delay(10)
  const handles = store.listBoardMembers(runId)
    .filter(member => member.specialistProfile === 'auth-session-oauth-specialist' && member.state === 'working')
    .map(member => member.handle)
    .sort()
  assert.deepEqual(handles, ['auth', 'auth-2'])

  for (const open of gates) open()
  await delay(20)
  const waiting = store.listBoardMembers(runId)
    .filter(member => member.specialistProfile === 'auth-session-oauth-specialist')
    .map(member => member.state)
  assert.ok(waiting.every(state => state === 'waiting'), `expected waiting, got ${waiting.join(',')}`)
})
