/**
 * v5 integrate-port Slice 2 invariants for the explicit --no-llm deterministic path.
 *
 * The deterministic engine must run only when Execution is constructed with
 * `deterministicOnly: true`. The legacy M1 no-profile fallback, dynamic step budget and K=6
 * diminishing-returns stop must remain intact. Runtime findings are verified-only; unproven
 * signals persist as det_lead facts.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'

import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  computeDynamicStepBudget,
  countConsecutiveDrySteps,
  diminishingReturnsDryThreshold,
  Execution,
} from '../src/server/execution.ts'
import type { EngineLead } from '../src/server/deterministic-engine.ts'
import { Store } from '../src/server/store.ts'
import type { Run } from '../src/server/store.ts'
import { makeStore, setupApprovedRun, withEnv } from './v4-tier-helpers.ts'

// scopedAssetOrigin accepts loopback origins only when local-lab mode is enabled.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

type EngineInternals = {
  driveInvestigation: (run: Run, profiles: readonly unknown[]) => void
  driveDeterministicInvestigation: (run: Run) => void
  driveEngineInvestigation: (run: Run) => void
  runEngineInvestigation: (run: Run) => Promise<void>
  plannerDoneRound: Map<string, number>
  persistDeterministicConfirmed: (input: unknown) => string | null
  persistDeterministicLead: (input: unknown) => void
}

function internals(execution: Execution): EngineInternals {
  return execution as unknown as EngineInternals
}

function defensiveSpec(origin: string): DeclarativeReplaySpec {
  const parsed = declarativeReplaySpecSchema.parse({
    version: 1,
    origin,
    title: 'Cross-tenant object read',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'The probe read an object owned by another persona.',
    impact: 'A tenant can read another tenant object by id.',
    remediation: 'Enforce an ownership predicate on the object lookup.',
    recheckInstructions: 'Replay owner control and cross-persona probe after the fix.',
    kind: 'http_chain',
    assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 200), observed: "probe 200", expected: "probe denied" }',
    steps: [
      { id: 'c1', role: 'control', description: 'Owner reads own object', request: { origin, method: 'GET', pathAndQuery: '/api/invoices/1', persona: 'owner' } },
      { id: 'p1', role: 'probe', description: 'Other persona reads the object', request: { origin, method: 'GET', pathAndQuery: '/api/invoices/1', persona: 'other' } },
    ],
  })
  return parsed
}

test('deterministicOnly selects the engine path; the default keeps the M1 fallback', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 100 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const run = storage.run(runId)

  const legacy = new Execution(storage)
  let m1 = 0
  let engine = 0
  internals(legacy).driveDeterministicInvestigation = () => { m1 += 1 }
  internals(legacy).driveEngineInvestigation = () => { engine += 1 }
  internals(legacy).driveInvestigation(run, [])
  assert.equal(m1, 1, 'no-flag no-profile runs must use the legacy M1 fallback')
  assert.equal(engine, 0)

  const explicit = new Execution(storage, { deterministicOnly: true })
  m1 = 0
  engine = 0
  internals(explicit).driveDeterministicInvestigation = () => { m1 += 1 }
  internals(explicit).driveEngineInvestigation = () => { engine += 1 }
  internals(explicit).driveInvestigation(run, [])
  assert.equal(engine, 1, 'deterministicOnly must use the engine path')
  assert.equal(m1, 0)
})

test('dynamicStepBudget stays correct and is never cleared by the engine path', async (t) => {
  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { budgetRequests: 100 })
  const origin = 'http://127.0.0.1:9'
  for (let i = 0; i < 25; i += 1) {
    storage.upsertEndpoint({
      runId, origin, method: 'GET', pathTemplate: `/api/resource-${i}`, source: 'openapi', riskScore: 90,
    })
  }
  assert.equal(computeDynamicStepBudget(storage, runId), 50, 'budget = clamp(24, crownJewels*2 + suspects, 200)')
  storage.updateRunDynamicStepBudget(runId, 77)
  const execution = new Execution(storage, { deterministicOnly: true })
  let engineStarted = 0
  internals(execution).driveEngineInvestigation = () => { engineStarted += 1 }
  internals(execution).driveInvestigation(storage.run(runId), [])
  assert.equal(engineStarted, 1)
  assert.equal(storage.run(runId).dynamicStepBudget, 77, 'engine path must not reset dynamicStepBudget')
  assert.equal(computeDynamicStepBudget(storage, runId), 50)
  assert.equal(run.dynamicStepBudget, null, 'the seeded run started with no budget')
})

test('K=6 consecutive dry steps still halt the investigation queue', async (t) => {
  const { storage } = makeStore(t)
  const { runId, run, assetIds } = await setupApprovedRun(storage, { budgetRequests: 2000 })
  for (let i = 0; i < diminishingReturnsDryThreshold; i += 1) {
    const step = storage.addChainStep(run, {
      title: `Dry step ${i}`, hypothesis: 'dry', category: 'misconfig-exposure', priority: 50, targetAssetIds: assetIds,
    })
    storage.updateChainStep(step.id, { status: 'complete' })
  }
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const current = storage.run(runId)
  assert.equal(countConsecutiveDrySteps(storage, current), diminishingReturnsDryThreshold)

  const execution = new Execution(storage)
  internals(execution).plannerDoneRound.set(runId, current.roundNo)
  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => {
    // A non-empty profile list takes the specialist scheduler; with no ready steps and K dry steps
    // already recorded it must advance to verification instead of queueing more work.
    internals(execution).driveInvestigation(current, [{ id: 'profile', model: 'test' }])
  })
  assert.ok(
    ['verification', 'complete'].includes(storage.run(runId).phase),
    `expected K=${diminishingReturnsDryThreshold} dry steps to halt investigation (phase ${storage.run(runId).phase})`,
  )
  assert.ok(storage.eventsAfter(runId, 0).some(e => e.kind === 'planner.diminishing_returns'))
})

test('runtime findings persist only when replay-confirmed', async (t) => {
  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { budgetRequests: 100 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const latest = storage.run(runId)
  const execution = new Execution(storage, { deterministicOnly: true })
  const asset = latest.candidates[0]
  const assignment = storage.makeWorker(latest, 'investigation', asset, 'engine', 'engine')
  const origin = asset.origin
  const spec = defensiveSpec(origin)

  const dismissed = internals(execution).persistDeterministicConfirmed({
    run: latest,
    assignment,
    asset,
    secrets: [],
    confirmed: {
      hypothesis: { probeClass: 'authz_matrix', intent: 'authz', method: 'GET', endpoint: { pathTemplate: '/api/invoices/:id', origin } },
      spec,
      specRecord: {},
      vulnClass: 'bola',
      endpoint: '/api/invoices/:id',
      result: { verdict: 'dismissed', verificationTier: 'runtime_confirmed', outcome: { controlPassed: true, observed: 'denied', reason: 'denied' }, exchangeIds: [] },
      exchangeIds: [],
    },
  })
  assert.equal(dismissed, null, 'a non-confirmed replay must never persist a finding')
  assert.equal(storage.runDetail(runId).findings.length, 0)

  const confirmed = internals(execution).persistDeterministicConfirmed({
    run: storage.run(runId),
    assignment,
    asset,
    secrets: [],
    confirmed: {
      hypothesis: { probeClass: 'authz_matrix', intent: 'authz', method: 'GET', endpoint: { pathTemplate: '/api/invoices/:id', origin } },
      spec,
      specRecord: {},
      vulnClass: 'bola',
      endpoint: '/api/invoices/:id',
      result: {
        verdict: 'confirmed',
        verificationTier: 'runtime_confirmed',
        outcome: { controlPassed: true, observed: 'probe 200', reason: 'cross-persona read', expected: 'probe denied' },
        exchangeIds: ['ex-confirmed'],
      },
      exchangeIds: ['ex-confirmed'],
    },
  })
  assert.ok(confirmed)
  const finding = storage.runDetail(runId).findings.find(f => f.id === confirmed)
  assert.ok(finding)
  assert.equal(finding!.status, 'confirmed')
  assert.equal(finding!.verificationTier, 'runtime_confirmed')
  assert.equal(finding!.cwe, 'CWE-639')
  assert.ok(finding!.fingerprintHash)
})

test('high-signal unconfirmed observations persist as det_lead facts only', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 100 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const latest = storage.run(runId)
  const execution = new Execution(storage, { deterministicOnly: true })
  const asset = latest.candidates[0]
  const assignment = storage.makeWorker(latest, 'investigation', asset, 'engine', 'engine')
  const lead: EngineLead = {
    hypothesis: {
      key: 'x', endpoint: { id: 'e', origin: asset.origin, method: 'GET', pathTemplate: '/api/invoices/:id', params: [] },
      probeClass: 'authz_matrix', intent: 'authz', method: 'GET', pathAndQuery: '/api/invoices/{{id}}',
      param: { name: 'id', location: 'path' },
    } as unknown as EngineLead['hypothesis'],
    probe: {
      probeClass: 'authz_matrix', origin: asset.origin, pathAndQuery: '/api/invoices/{{id}}', verdict: 'inconclusive',
      summary: 'similar responses, no replayable proof', anomalies: [{ type: 'unauthorized_access', canaryId: 'canary-1' }],
      details: {}, requestsSent: 4, exchangeIds: ['ex-lead-1'], stoppedReason: null, notes: [], durationMs: 10,
    },
    summary: 'similar responses, no replayable proof',
  }
  internals(execution).persistDeterministicLead({ run: latest, assignment, lead, secrets: [] })
  const fact = storage.listFacts(runId, { includeTainted: false, limit: 20 }).find(f => f.data?.kind === 'det_lead')
  assert.ok(fact, 'unconfirmed signal must persist as a det_lead fact')
  assert.equal(fact!.data?.subkind, 'deterministic_engine_lead')
  assert.equal(fact!.data?.endpoint, '/api/invoices/:id')
  assert.equal(fact!.data?.method, 'GET')
  assert.equal(fact!.data?.param, 'id')
  assert.equal(fact!.data?.exchangeId, 'ex-lead-1')
  assert.equal(fact!.data?.canaryId, 'canary-1')
  assert.equal(fact!.data?.reason, 'similar responses, no replayable proof')
  assert.equal(storage.runDetail(runId).findings.length, 0, 'a lead must never create a finding')
})
