/**
 * Queue 20 Bottleneck 3 — Source-First Code Audit settlement.
 *
 * Proves, without Docker:
 *  1. The code-audit settle prompt fires at 60% of the wall cap (54s of 90s) with an explicit
 *     `code_audit_suspect` wrap-up directive.
 *  2. `codeAuditPrompt` and the `code-auditor` system instructions require incremental
 *     `record_fact(kind="code_audit_suspect")` recording and the generic security priorities.
 *  3. Semantic-audit suspects are preserved (deduped by `codeAuditSuspectLocationKey`) when the
 *     interactive auditor rotates with zero suspects of its own.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  SOURCE_AUDIT_SETTLEMENT_SHARE,
  codeAuditSettlementMessage,
  resolveSourceAuditSettlementMs,
  settleCodeAuditSuspects,
} from '../src/server/execution.ts'
import { codeAuditPrompt, workerSessionInstructions } from '../src/server/agent-session.ts'
import type { SemanticAuditSuspect } from '../src/server/semantic-audit.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

function semanticSuspect(origin: string, file: string, line: number): SemanticAuditSuspect {
  return {
    id: `sem-${file}-${line}`,
    fingerprint: `fp-${file}-${line}`,
    stage: 'stage2_backward_taint',
    origin,
    repo: 'demo-repo',
    file,
    line,
    routeOrAction: '/api/v1/orders/:id',
    authCheck: 'missing tenant scope',
    ownershipCheck: 'none',
    sinkKind: 'api_route',
    severity: 'high',
    priorityScore: 88,
    recommendedTier: 2,
    specialistProfile: 'bola-bfla-specialist',
    hypothesis: 'Handler trusts a caller-supplied tenant id.',
    data: {
      subkind: 'code_audit_suspect',
      repo: 'demo-repo',
      file,
      line,
      routeOrAction: '/api/v1/orders/:id',
      authCheck: 'missing tenant scope',
      ownershipCheck: 'none',
      sinkKind: 'api_route',
      hypothesis: 'Handler trusts a caller-supplied tenant id.',
      recommendedTier: 2,
    },
  }
}

test('code-audit settlement fires at 60% of the wall cap with an explicit suspect directive', () => {
  assert.equal(SOURCE_AUDIT_SETTLEMENT_SHARE, 0.6)
  assert.equal(resolveSourceAuditSettlementMs(90_000), 54_000)
  assert.equal(resolveSourceAuditSettlementMs(45_000), 27_000)
  assert.equal(resolveSourceAuditSettlementMs(72_000), 43_200)
  assert.equal(resolveSourceAuditSettlementMs(120_000), 72_000)

  const message = codeAuditSettlementMessage(54_000)
  assert.match(message, /STOP reading more files/i)
  assert.match(message, /record_fact\(kind="code_audit_suspect"\)/)
  assert.match(message, /top 3-6/i)
  assert.match(message, /cross-service trust boundaries/i)
  assert.match(message, /multi-tenant/i)
  assert.match(message, /state-machine/i)
  assert.match(message, /webhook/i)
  assert.match(message, /async-worker/i)
  assert.match(message, /complete_intent/i)
})

test('codeAuditPrompt and code-auditor instructions require incremental record_fact', () => {
  const prompt = codeAuditPrompt({
    goal: 'Audit the mounted repositories.',
    capabilityTier: 2,
    approvedOrigins: ['http://127.0.0.1:9'],
    mountedRepos: ['demo-repo'],
    maxTurns: 8,
  })
  const parsed = JSON.parse(prompt) as {
    recordingPolicy?: { mode?: string; rule?: string; priorityOrder?: string[] }
  }
  assert.equal(parsed.recordingPolicy?.mode, 'incremental')
  assert.match(prompt, /record_fact/)
  assert.match(prompt, /code_audit_suspect/)
  assert.match(prompt, /IMMEDIATELY as soon as you spot each high-signal defect/i)
  assert.match(prompt, /cross-service trust boundaries/i)
  assert.match(prompt, /multi-tenant authorization or cache-key asymmetries/i)
  assert.match(prompt, /state-machine transitions/i)
  assert.match(prompt, /signing\/webhook verification boundaries/i)
  assert.match(prompt, /async-worker outbound fetch\/webhook\/log sinks/i)

  const instructions = workerSessionInstructions('code-auditor')
  assert.match(instructions, /Record incrementally/)
  assert.match(instructions, /record_fact.*kind="code_audit_suspect"/)
  assert.match(instructions, /cross-service trust boundaries/i)
  assert.match(instructions, /multi-tenant authz or cache-key asymmetries/i)
  assert.match(instructions, /entity creator\/approver and state-machine transitions/i)
  assert.match(instructions, /signing\/webhook verification boundaries/i)
  assert.match(instructions, /async-worker outbound fetch\/webhook\/log sinks/i)
})

test('semantic-audit suspects are preserved when the interactive auditor records none', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: ['http://127.0.0.1:9'], tier: 2 })
  const run = storage.run(runId)
  const asset = run.candidates.find(candidate => run.approved.includes(candidate.id))!
  const assignment = storage.makeWorker(run, 'threat_model', asset, 'Source-First Code Audit', 'Audit mounted source.')
  const approvedOrigins = new Set([asset.origin])
  const first = semanticSuspect(asset.origin, 'services/api/orders.ts', 42)
  const second = semanticSuspect(asset.origin, 'services/api/secrets.ts', 77)

  // Semantic audit already persisted one suspect; the interactive auditor recorded nothing new
  // before rotating at the wall-clock deadline.
  const persisted = storage.addFact(run, assignment, {
    kind: 'code_audit_suspect',
    origin: first.origin,
    summary: `[semantic ${first.stage}] ${first.file}:${first.line} — ${first.hypothesis}`,
    data: first.data as unknown as Record<string, unknown>,
  })
  const preInteractiveFactIds = new Set(
    storage.listFacts(runId, { includeTainted: false, kind: 'code_audit_suspect', limit: 100 }).map(fact => fact.id),
  )
  assert.equal(preInteractiveFactIds.size, 1)
  assert.equal(preInteractiveFactIds.has(persisted.id), true)

  const settled = settleCodeAuditSuspects({
    storage,
    run,
    assignment,
    approvedOrigins,
    semanticSuspects: [first, second],
    preInteractiveFactIds,
  })
  assert.equal(settled.interactiveRecorded, 0, 'interactive auditor recorded no suspects of its own')
  assert.equal(settled.promoted.length, 1, 'only the missing location is promoted')
  assert.equal(settled.promoted[0]!.summary.includes('secrets.ts:77'), true)
  assert.equal(settled.suspects.length, 2)

  // Idempotent: rerunning the settlement must not duplicate a location.
  const repeat = settleCodeAuditSuspects({
    storage,
    run,
    assignment,
    approvedOrigins,
    semanticSuspects: [first, second],
    preInteractiveFactIds: new Set(settled.suspects.map(fact => fact.id)),
  })
  assert.equal(repeat.interactiveRecorded, 0)
  assert.equal(repeat.promoted.length, 0)
  assert.equal(repeat.suspects.length, 2)

  // An interactive suspect of its own suppresses semantic promotion.
  const interactive = storage.addFact(run, assignment, {
    kind: 'code_audit_suspect',
    origin: asset.origin,
    summary: 'Interactive auditor suspect at services/api/audit.ts:5',
    data: { ...second.data, file: 'services/api/audit.ts', line: 5, sinkKind: 'webhook' },
  })
  const withInteractive = settleCodeAuditSuspects({
    storage,
    run,
    assignment,
    approvedOrigins,
    semanticSuspects: [semanticSuspect(asset.origin, 'services/api/worker.ts', 9)],
    preInteractiveFactIds: new Set([...settled.suspects.map(fact => fact.id)].filter(id => id !== interactive.id)),
  })
  assert.equal(withInteractive.interactiveRecorded, 1)
  assert.equal(withInteractive.promoted.length, 0)
})

test('semantic suspects alone never produce an empty audit when nothing was pre-persisted', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: ['http://127.0.0.1:9'], tier: 2 })
  const run = storage.run(runId)
  const asset = run.candidates.find(candidate => run.approved.includes(candidate.id))!
  const assignment = storage.makeWorker(run, 'threat_model', asset, 'Source-First Code Audit', 'Audit mounted source.')

  const settled = settleCodeAuditSuspects({
    storage,
    run,
    assignment,
    approvedOrigins: new Set([asset.origin]),
    semanticSuspects: [
      semanticSuspect(asset.origin, 'services/worker/exports.ts', 12),
      semanticSuspect(asset.origin, 'services/edge/proxy.ts', 31),
    ],
    preInteractiveFactIds: new Set(),
  })
  assert.equal(settled.suspects.length, 2)
  assert.equal(settled.promoted.length, 2)
  assert.equal(settled.interactiveRecorded, 0)
})
