/**
 * v6 Phase B F2 — dispatch policy tests.
 *
 * The Phase-B diagnosis found that four det_lead upgrade steps (priority 88) consumed 80% of the
 * agentic wall clock while 8/11 unconfirmed target classes never ran. These tests pin the two
 * independent fixes:
 *
 *  1. leads only reach the queue with contrast evidence, and never outrank class/route steps;
 *  2. the scheduler fills slots round-robin with a hard concurrent-lead cap, so no category starves.
 *
 * All fixtures are generic/synthetic: no benchmark/app/route/seed literals.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  ASSIGNMENT_BRIEF_MAX_BYTES,
  assertAssignmentBriefSize,
  buildAssignmentBriefPacket,
} from '../src/server/assignment-brief.ts'
import {
  ASSIGNMENT_BOLA_QUEUE_MAX_BYTES,
  ASSIGNMENT_BOLA_QUEUE_MAX_ITEMS,
  DET_LEAD_CONCURRENT_CAP,
  DET_LEAD_STEP_PRIORITY,
  Execution,
  classifyDispatchLane,
  detLeadEvidenceGate,
  isDetLeadDispatchStep,
  measureBolaQueueBytes,
  planRoundRobinDispatch,
  selectAssignmentBolaQueueItems,
} from '../src/server/execution.ts'
import type { BolaTestQueueItem, DispatchLaneStep } from '../src/server/execution.ts'
import type { Run } from '../src/server/store.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const origin = 'https://app.example.invalid'

function step(overrides: Partial<DispatchLaneStep> & Pick<DispatchLaneStep, 'id'>): DispatchLaneStep {
  return {
    seq: Number(overrides.id.replace(/\D/g, '')) || 1,
    priority: 70,
    title: `Investigate ${overrides.id}`,
    category: 'broken-access-control',
    hypothesis: 'Probe the named route for a differential.',
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [origin],
    ...overrides,
  }
}

function lead(id: string, priority = 96): DispatchLaneStep {
  return step({
    id,
    priority,
    title: `det_lead upgrade · authz_matrix DELETE /api/items/:id (${id})`,
    hypothesis: 'The deterministic floor observed an unproven authz_matrix signal at DELETE /api/items/:id.',
  })
}

function queueItem(overrides: Partial<BolaTestQueueItem> = {}): BolaTestQueueItem {
  const resourceId = overrides.resourceId ?? 'res_1'
  const endpoint = overrides.endpoint ?? `/api/invoices/${resourceId}`
  return {
    origin,
    ownerPersona: 'persona_a',
    resourceId,
    endpoint,
    method: 'GET',
    resourceKey: 'invoices',
    source: 'fact',
    testAsPersonas: ['persona_b', 'anonymous'],
    variants: [
      { method: 'DELETE', endpoint, destructive: true, requiresTier: 3 },
      { method: 'GET', endpoint, destructive: false, requiresTier: 2 },
    ],
    ...overrides,
  }
}

// ============================================================================
// 1. Lead priority + evidence gate
// ============================================================================

test('lead priority sits below planner-authored class steps', () => {
  assert.ok(DET_LEAD_STEP_PRIORITY < 60, 'det_lead upgrades must not outrank class steps (planner default 60)')
  assert.ok(DET_LEAD_STEP_PRIORITY < 85, 'det_lead upgrades must not outrank crown-jewel class steps')
  assert.equal(DET_LEAD_CONCURRENT_CAP, 2)
})

test('lead gate rejects signals the control also produces', () => {
  const rejected = [
    // The Phase-B shape: non-owner mutating 2xx with no control contrast.
    detLeadEvidenceGate({ kind: 'det_lead', probeClass: 'authz_matrix', reason: 'other persona DELETE returned 200' }),
    detLeadEvidenceGate({ kind: 'det_lead', probeClass: 'authz_matrix', controlPassed: false }),
    detLeadEvidenceGate({ kind: 'det_lead', probeClass: 'authz_matrix', verifyFailureReason: 'control passed: control also returned 200 for a nonexistent id' }),
    detLeadEvidenceGate({ kind: 'det_lead', probeClass: 'authz_matrix', verifyFailureReason: 'handler is idempotent on missing ids' }),
  ]
  for (const gate of rejected) assert.equal(gate.admitted, false)
  assert.equal(rejected[0].reason, 'no_contrast_evidence')
  assert.equal(rejected[1].reason, 'control_collapsed')
})

test('lead gate admits a failed control or near-miss evidence', () => {
  const admitted = [
    detLeadEvidenceGate({ kind: 'det_lead', controlPassed: true }),
    detLeadEvidenceGate({ kind: 'det_lead', nearMiss: true }),
    detLeadEvidenceGate({ kind: 'det_lead', verifyFailureReason: 'status differs from control on the readback' }),
    detLeadEvidenceGate({ kind: 'det_lead', anomalies: [{ classification: 'near_miss_delta' } ] }),
  ]
  for (const gate of admitted) assert.equal(gate.admitted, true, gate.reason)
})

test('lead gate consumes the detlane-leads evidence contract', () => {
  for (const leadEvidenceKind of ['near_miss', 'denied_control', 'data_delta']) {
    assert.equal(detLeadEvidenceGate({ kind: 'det_lead', leadEvidenceKind }).admitted, true)
  }
  assert.equal(detLeadEvidenceGate({ kind: 'det_lead', leadEvidenceKind: 'bare_anomaly' }).admitted, false)
  assert.equal(detLeadEvidenceGate({ kind: 'det_lead', verifyFailureCode: 'status_only' }).admitted, false)
  assert.equal(detLeadEvidenceGate({ kind: 'det_lead', verifyFailureCode: 'missing_control_differential' }).admitted, false)
  assert.equal(detLeadEvidenceGate({ kind: 'det_lead', verifyFailureCode: 'missing_identifier_binding' }).admitted, true)
})

test('lead detection is contract-based, not priority-based', () => {
  assert.equal(isDetLeadDispatchStep(lead('step-1')), true)
  assert.equal(isDetLeadDispatchStep(step({ id: 'step-2', title: 'Cross-persona BOLA/IDOR matrix' })), false)
  assert.equal(classifyDispatchLane(lead('step-1')), 'lead')
})

test('lead queueing promotes only evidence-backed facts at low priority', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 200 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const run = storage.run(runId)
  const asset = run.candidates.find(candidate => run.approved.includes(candidate.id))!
  const assignment = storage.makeWorker(run, 'investigation', asset, 'lead worker', 'lead worker')
  const facts = [
    { endpoint: '/api/items/:id', method: 'DELETE', controlPassed: false },
    { endpoint: '/api/spaces/:id', method: 'DELETE', reason: 'non-owner delete returned 200' },
    { endpoint: '/api/hooks/:id', method: 'DELETE', controlPassed: true },
    { endpoint: '/api/invoices/:id', method: 'GET', verifyFailureReason: 'status differs from control' },
  ]
  for (const fact of facts) {
    storage.addFact(run, assignment, {
      kind: 'note',
      origin: asset.origin,
      summary: `Unverified deterministic lead on ${fact.method} ${fact.endpoint}`,
      data: {
        kind: 'det_lead',
        source: 'deterministic_engine',
        probeClass: 'authz_matrix',
        endpoint: fact.endpoint,
        method: fact.method,
        reason: fact.reason ?? 'other persona received 2xx',
        ...(fact.controlPassed !== undefined ? { controlPassed: fact.controlPassed } : {}),
        ...(fact.verifyFailureReason ? { verifyFailureReason: fact.verifyFailureReason } : {}),
      },
    })
  }

  const engine = new Execution(storage)
  t.after(() => engine.stop())
  const internals = engine as unknown as {
    queueDetLeadUpgradeSteps: (run: Run, approved: ReadonlySet<string>, budget: number) => number
    approvedOriginsSet: (run: Run) => ReadonlySet<string>
  }
  const created = internals.queueDetLeadUpgradeSteps(run, internals.approvedOriginsSet(run), 40)
  assert.equal(created, 2, 'only the two contrast-backed leads are queued')
  const steps = storage.listChainSteps(runId, run.goalRevision)
  for (const step of steps) assert.ok(step.priority <= DET_LEAD_STEP_PRIORITY)
  const deferred = storage.eventsAfter(runId, 0).filter(event => event.kind === 'deterministic_lane.lead_deferred')
  assert.equal(deferred.length, 2, 'rejected leads are recorded once with a reason')
})

// ============================================================================
// 2. Round-robin dispatch
// ============================================================================

test('4 leads and 6 slots: at most 2 leads, at least 4 class/route assignments', () => {
  const steps = [
    lead('lead-1'), lead('lead-2'), lead('lead-3'), lead('lead-4'),
    step({ id: 'route-1', priority: 92 }),
    step({ id: 'route-2', priority: 88 }),
    step({ id: 'wf-1', title: 'Checkout workflow state transition bypass', category: 'business-logic' }),
    step({ id: 'biz-1', title: 'Seat quantity invariant on billing', category: 'business-logic' }),
    step({ id: 'race-1', title: 'Race the credit redemption endpoint', category: 'business-logic' }),
    step({ id: 'chain-1', title: 'Chain stored canary into admin render', dependsOnStepIds: ['route-1'] }),
  ]
  const plan = planRoundRobinDispatch(steps, 6, { leadCap: DET_LEAD_CONCURRENT_CAP })
  assert.equal(plan.ordered.length, 6)
  assert.ok(plan.selectedByLane.lead <= DET_LEAD_CONCURRENT_CAP)
  const nonLead = plan.ordered.filter(candidate => !isDetLeadDispatchStep(candidate)).length
  assert.ok(nonLead >= 4, `expected at least 4 class/route assignments, got ${nonLead}`)
  assert.ok(plan.deferredLeads >= 2)
})

test('active leads consume the cap before new leads are scheduled', () => {
  const steps = [
    lead('lead-1'), lead('lead-2'), lead('lead-3'),
    step({ id: 'route-1' }), step({ id: 'route-2' }), step({ id: 'route-3' }), step({ id: 'route-4' }),
  ]
  const plan = planRoundRobinDispatch(steps, 4, { leadCap: DET_LEAD_CONCURRENT_CAP, activeLeadCount: 1 })
  assert.equal(plan.selectedByLane.lead, 1)
  assert.equal(plan.ordered.filter(candidate => !isDetLeadDispatchStep(candidate)).length, 3)
})

test('no ready class/route step starves while a lead beyond the cap is deferred', () => {
  const steps = [lead('lead-1'), lead('lead-2'), lead('lead-3'), lead('lead-4'), step({ id: 'route-1', priority: 99 }), step({ id: 'race-1', title: 'Concurrent refund race' })]
  const plan = planRoundRobinDispatch(steps, 4, { leadCap: DET_LEAD_CONCURRENT_CAP })
  assert.equal(plan.selectedByLane.lead, 2)
  assert.deepEqual(plan.ordered.filter(candidate => candidate.id.startsWith('route') || candidate.id.startsWith('race')).map(candidate => candidate.id).sort(), ['race-1', 'route-1'])
  assert.equal(plan.deferredLeads, 2)
})

test('leads may overflow only when no non-lead ready step remains', () => {
  const steps = [lead('lead-1'), lead('lead-2'), lead('lead-3'), step({ id: 'route-1' })]
  const plan = planRoundRobinDispatch(steps, 4, { leadCap: DET_LEAD_CONCURRENT_CAP })
  assert.equal(plan.selectedByLane.lead, 3)
  assert.equal(plan.selectedByLane.route, 1)
  assert.equal(plan.deferredLeads, 0)
})

test('round-robin is deterministic and input-order independent', () => {
  const steps = [
    lead('lead-1'), lead('lead-2'), lead('lead-3'), lead('lead-4'),
    step({ id: 'route-1', priority: 80 }), step({ id: 'route-2', priority: 80 }),
    step({ id: 'wf-1', title: 'Workflow transition skip' }),
    step({ id: 'biz-1', title: 'Business invariant on quantity' }),
    step({ id: 'race-1', title: 'Race condition on credits' }),
    step({ id: 'chain-1', title: 'Chain second-order canary', dependsOnStepIds: ['route-1'] }),
  ]
  const forward = planRoundRobinDispatch(steps, 6, { leadCap: 2 })
  const reversed = planRoundRobinDispatch([...steps].reverse(), 6, { leadCap: 2 })
  assert.deepEqual(forward.ordered.map(candidate => candidate.id), reversed.ordered.map(candidate => candidate.id))
  assert.deepEqual(forward.selectedByLane, reversed.selectedByLane)
})

test('semantic classes are classified and each lane gets a turn', () => {
  const lanes = [
    ['route', step({ id: 'r', title: 'Cross-persona read on invoices' })],
    ['workflow', step({ id: 'w', title: 'Workflow approval bypass' })],
    ['business_logic', step({ id: 'b', title: 'Seat quantity invariant' })],
    ['race', step({ id: 'c', title: 'Double-spend race on credits' })],
    ['chain', step({ id: 'ch', title: 'Chain the canary into admin render', dependsOnStepIds: ['x'] })],
  ] as const
  for (const [lane, candidate] of lanes) assert.equal(classifyDispatchLane(candidate), lane)
  const plan = planRoundRobinDispatch(lanes.map(([, candidate]) => candidate), 5, { leadCap: 2 })
  assert.deepEqual(plan.ordered.map(candidate => candidate.id).sort(), ['b', 'c', 'ch', 'r', 'w'])
})

// ============================================================================
// 3. Per-assignment BOLA queue slice
// ============================================================================

test('BOLA queue slice is relevance-filtered, read-first and bounded', () => {
  const queue = [
    ...Array.from({ length: 30 }, (_, index) => queueItem({
      resourceId: `invoice_${index}`,
      endpoint: `/api/invoices/invoice_${index}`,
      resourceKey: 'invoices',
    })),
    queueItem({ origin: 'https://other.example.invalid', resourceId: 'x1', endpoint: '/api/invoices/x1' }),
    queueItem({ resourceId: 'proj_1', endpoint: '/api/projects/proj_1', resourceKey: 'projects' }),
  ]
  const selected = selectAssignmentBolaQueueItems({
    queue,
    targetOrigins: [origin],
    step: {
      title: 'Cross-persona BOLA/IDOR matrix · resource:invoices',
      hypothesis: 'Replay invoice reads as another persona.',
      category: 'broken-access-control',
      skills: ['bola-idor-race', 'false-positive-elimination'],
      specialistProfile: 'bola-bfla-specialist',
    },
  })
  assert.ok(selected.length > 0)
  assert.ok(selected.length <= ASSIGNMENT_BOLA_QUEUE_MAX_ITEMS)
  assert.ok(measureBolaQueueBytes(selected) <= ASSIGNMENT_BOLA_QUEUE_MAX_BYTES)
  assert.ok(selected.every(item => item.origin === origin))
  assert.equal(selected[0].resourceKey, 'invoices')
  for (const item of selected) {
    assert.equal(item.variants[0].method, 'GET', 'read variants must come before destructive variants')
  }
})

test('non-BOLA assignments receive no queue at all', () => {
  const queue = Array.from({ length: 12 }, (_, index) => queueItem({ resourceId: `res_${index}`, endpoint: `/api/invoices/res_${index}` }))
  const selected = selectAssignmentBolaQueueItems({
    queue,
    targetOrigins: [origin],
    step: {
      title: 'Cache-key poisoning differential',
      hypothesis: 'Probe cache deception on the CDN edge.',
      category: 'misconfig-exposure',
      skills: ['cache-poisoning'],
      specialistProfile: 'protocol-cache-edge',
    },
  })
  assert.deepEqual(selected, [])
})

test('byte cap drops the remainder instead of bloating the prompt', () => {
  const queue = Array.from({ length: 25 }, (_, index) => queueItem({
    resourceId: `res_${index}_${'x'.repeat(120)}`,
    endpoint: `/api/invoices/${'y'.repeat(120)}/res_${index}`,
    summary: 'z'.repeat(300),
  }))
  const selected = selectAssignmentBolaQueueItems({
    queue,
    targetOrigins: [origin],
    step: {
      title: 'BOLA on invoices',
      hypothesis: 'Cross-persona read.',
      category: 'broken-access-control',
      skills: ['bola-idor-race'],
    },
    maxItems: 10,
    maxBytes: 2048,
  })
  assert.ok(selected.length >= 1)
  assert.ok(measureBolaQueueBytes(selected) <= 2048)
})

// ============================================================================
// 4. Assignment brief size assertion
// ============================================================================

test('brief size cap holds and the assertion fires on oversize text', () => {
  const packet = buildAssignmentBriefPacket({
    missionKind: 'class_scan',
    origin,
    routes: Array.from({ length: 40 }, (_, index) => ({
      method: 'GET',
      path: `/api/resource/${index}/${'x'.repeat(40)}`,
      params: ['id', 'owner', 'tenant'],
      riskScore: index,
    })),
    personas: Array.from({ length: 8 }, (_, index) => ({
      handle: `persona_${index}`,
      harvestedIds: [`res-${index}`],
    })),
  })
  assert.ok(packet.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES)
  assert.doesNotThrow(() => assertAssignmentBriefSize(packet.text))
  assert.throws(() => assertAssignmentBriefSize(packet.text, 32), RangeError)
})
