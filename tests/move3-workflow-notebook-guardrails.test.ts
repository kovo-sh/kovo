/**
 * Move 3 class-level guardrails:
 *  1. Cross-round secret-free `workflowNotebook` in `HopCheckpointBrief` (`<= 2 KB` cap,
 *     secret scrubbing, `triedRecipes -> discoveredRoutes -> openHypotheses` trimming before
 *     dropping `verifiedHops` / `capabilityHandles`), `buildAssignmentBriefPacket` (`<= 4 KB`),
 *     and cross-round inheritance + bounded persistent workflow continuation on rotation.
 *  2. Low-privilege-first persona ordering (`SF-C3`) across `sortPersonasLowPrivFirst`,
 *     `assignmentBriefForStep`, `personasPub`, and prompt directives.
 *  3. Anti-premature-`ruled_out` / `no_issue_found` guardrail (`SF-C2`, `SF-C4`) backed by
 *     `FindingsRepository.inspectCoverageExchangeEvidence` (`personaHandle` + `status`),
 *     enforced on both `record_coverage` and `complete_intent` with a 1-strike non-looping cap.
 */
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { test } from 'node:test'

import {
  scenarioInstructions,
  workerInvestigationPrompt,
} from '../src/server/agent-prompts.ts'
import {
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  buildAssignmentBriefPacket,
  classifyPersonaPrivilege,
  fitHopCheckpointForBrief,
} from '../src/server/assignment-brief.ts'
import {
  DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES,
  computeArtifactDigest,
  finalizeHopCheckpointBrief,
  type HopCheckpointBrief,
} from '../src/server/capability-ledger.ts'
import { isMultiHopChainStep } from '../src/server/exec-dispatch.ts'
import {
  isPersistentWorkflowContinuationStep,
  sortPersonasLowPrivFirst,
  type ExecReconPlanner,
} from '../src/server/exec-recon-planner.ts'
import { Execution } from '../src/server/execution.ts'
import { resolveProfilePoolForRole, saveModelProfile } from '../src/server/model-settings.ts'
import { FindingsRepository } from '../src/server/store-findings.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN = 'https://move3-guard.example.invalid'
const OTHER_ORIGIN = 'https://move3-other.example.invalid'

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
    async verifyStaticAst(_aid, req) {
      return {
        verified: false, engine: req.engine, repo: req.repo, file: req.file,
        startLine: req.startLine, endLine: req.endLine, matchedLines: [],
        codeExcerpt: '', matchCount: 0, durationMs: 1,
      }
    },
    async openSession(): Promise<WorkerSession> {
      return {
        stage: async name => `/evidence/${name}`,
        exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
        analyze: async () => ({ ok: true }),
        sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
        runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
        verifyStaticAst: async req => ({
          verified: false, engine: req.engine, repo: req.repo, file: req.file,
          startLine: req.startLine, endLine: req.endLine, matchedLines: [],
          codeExcerpt: '', matchCount: 0, durationMs: 1,
        }),
        close: async () => undefined,
      }
    },
  }
}

function internals(engine: Execution) {
  return engine as unknown as {
    reconPlanner: ExecReconPlanner
  }
}

function seedExchange(
  storage: ReturnType<typeof makeStore>['storage'],
  input: {
    runId: string
    assignmentId: string
    origin: string
    method?: string
    pathAndQuery?: string
    status?: number
    personaHandle?: string | null
  },
) {
  return storage.recordExchange({
    runId: input.runId,
    assignmentId: input.assignmentId,
    scopeRevision: 1,
    origin: input.origin,
    finalOrigin: input.origin,
    redirectOrigins: [input.origin],
    method: input.method ?? 'GET',
    pathAndQuery: input.pathAndQuery ?? '/api/workflows/1',
    personaHandle: input.personaHandle ?? null,
    status: input.status ?? 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    body: '{"ok":true}',
    durationMs: 8,
  })
}

async function startMockLlm(
  t: { after: (fn: () => void | Promise<void>) => void },
  handler: (body: Record<string, unknown>, reqIndex: number) => {
    toolCall?: { callId: string; name: string; argumentsJson: string }
    text?: string
  },
): Promise<{ endpoint: string; calls: Array<Record<string, unknown>> }> {
  const calls: Array<Record<string, unknown>> = []
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(chunk as Buffer))
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as Record<string, unknown>
      calls.push(body)
      const reply = handler(body, calls.length)
      res.statusCode = 200
      res.setHeader('Content-Type', 'text/event-stream')
      res.setHeader('Cache-Control', 'no-cache')
      const idx = calls.length
      const itemId = `item_${idx}`
      const responseId = `resp_${idx}`
      const emit = (event: string, data: Record<string, unknown>) => {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
      }
      emit('response.created', { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } })
      if (reply.toolCall) {
        emit('response.output_item.added', {
          type: 'response.output_item.added',
          output_index: 0,
          item: { id: itemId, type: 'function_call', status: 'in_progress', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: '' },
        })
        emit('response.function_call_arguments.delta', {
          type: 'response.function_call_arguments.delta',
          output_index: 0,
          item_id: itemId,
          delta: reply.toolCall.argumentsJson,
        })
        emit('response.function_call_arguments.done', {
          type: 'response.function_call_arguments.done',
          output_index: 0,
          item_id: itemId,
          name: reply.toolCall.name,
          arguments: reply.toolCall.argumentsJson,
        })
        emit('response.output_item.done', {
          type: 'response.output_item.done',
          output_index: 0,
          item: { id: itemId, type: 'function_call', status: 'completed', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: reply.toolCall.argumentsJson },
        })
        emit('response.completed', {
          type: 'response.completed',
          response: {
            id: responseId,
            status: 'completed',
            output: [{ id: itemId, type: 'function_call', status: 'completed', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: reply.toolCall.argumentsJson }],
            usage: { input_tokens: 90, output_tokens: 30, total_tokens: 120, input_tokens_details: { cached_tokens: 0 } },
          },
        })
      } else {
        const text = reply.text ?? 'done'
        emit('response.output_item.added', {
          type: 'response.output_item.added',
          output_index: 0,
          item: { id: itemId, type: 'message', status: 'in_progress', role: 'assistant', content: [] },
        })
        emit('response.output_text.done', {
          type: 'response.output_text.done',
          output_index: 0,
          item_id: itemId,
          content_index: 0,
          text,
        })
        emit('response.output_item.done', {
          type: 'response.output_item.done',
          output_index: 0,
          item: { id: itemId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] },
        })
        emit('response.completed', {
          type: 'response.completed',
          response: {
            id: responseId,
            status: 'completed',
            output: [{ id: itemId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] }],
            usage: { input_tokens: 80, output_tokens: 20, total_tokens: 100, input_tokens_details: { cached_tokens: 0 } },
          },
        })
      }
      res.write('data: [DONE]\n\n')
      res.end()
    })
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port
  t.after(async () => {
    server.closeAllConnections?.()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })
  return { endpoint: `http://127.0.0.1:${port}/v1`, calls }
}

// ============================================================================
// 1. Workflow Notebook scrubbing, 2 KB cap, trimming order & 4 KB brief fit
// ============================================================================

test('Move3.1: finalizeHopCheckpointBrief scrubs secrets, keeps cap:hop_* handles, and trims notebook before verifiedHops/capabilityHandles', () => {
  const rawJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEiLCJyb2xlIjoiYWRtaW4ifQ.sig1234567890'
  const rawBrief: HopCheckpointBrief = {
    schema: 'v8.hop_checkpoint.v1',
    branchKey: 'cont:wf-1:d1',
    depth: 1,
    targetHop: 3,
    mode: 'pivot',
    evi: 0.9,
    verifiedHops: [
      {
        hop: 1,
        receiptId: 'hop:1',
        capId: 'cap:hop_1:tok',
        kind: 'scoped_token',
        surface: 'http',
        service: ORIGIN,
        tenant: 'tenant-b',
        actor: 'member_b',
        at: 'POST /api/drafts',
      },
    ],
    capabilityHandles: ['cap:hop_1:tok'],
    nextGoal: {
      targetSurfaceKey: `${ORIGIN}|http|/api/approvals`,
      surface: 'http',
      service: ORIGIN,
      endpoint: '/api/approvals',
      method: 'POST',
      hypothesisClass: 'workflow',
      goal: 'Advance approval transition with sealed handle',
    },
    workflowNotebook: {
      discoveredRoutes: [
        'POST /api/drafts',
        'GET /api/approvals',
        'POST /api/approvals/submit',
        'POST /api/approvals/finalize',
        'GET /api/audit-trail',
        'GET /api/export/status',
      ],
      verifiedHypotheses: [
        `Sealed cap:hop_1:tok from draft creation (ignored Authorization: Bearer ${rawJwt})`,
        'sessionid=supersecretcookievalue12345 must be redacted while keeping workflow state',
      ],
      triedRecipes: [
        'POST /api/drafts [member_b] -> 201',
        'POST /api/approvals/submit [member_b] -> 200',
        'POST /api/approvals/finalize [member_b] -> 403',
        'GET /api/audit-trail [member_b] -> 200',
        'GET /api/export/status [member_b] -> 202',
        'POST /api/approvals/reopen [member_b] -> 400',
      ],
      openHypotheses: [
        'Check whether approval skip works when reviewer token is replayed on finalize endpoint',
        'Test cross-tenant export status transition after draft state moves to pending_review',
        'Verify whether batch submit endpoint bypasses creator-approver separation invariant',
      ],
    },
    doNotRediscover: true,
  }

  // (a) Standard 2 KB cap preserves notebook, strips secrets, keeps opaque handle.
  const full = finalizeHopCheckpointBrief(rawBrief, DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES)
  assert.ok(full.checkpointBytes <= DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES)
  assert.ok(!full.checkpointJson.includes(rawJwt), 'raw JWT must never survive in workflowNotebook')
  assert.ok(!full.checkpointJson.includes('supersecretcookievalue12345'), 'raw cookie value must be scrubbed')
  assert.ok(full.checkpointJson.includes('cap:hop_1:tok'), 'opaque cap:hop_* handle must be preserved')
  assert.ok((full.brief.workflowNotebook?.discoveredRoutes?.length ?? 0) >= 5)

  // (b) Tight cap trims triedRecipes -> discoveredRoutes -> openHypotheses BEFORE dropping verifiedHops or capabilityHandles.
  const tightCap = 980
  const tight = finalizeHopCheckpointBrief(rawBrief, tightCap)
  assert.ok(tight.checkpointBytes <= tightCap, `expected <= ${tightCap} bytes, got ${tight.checkpointBytes}`)
  assert.equal(tight.brief.verifiedHops.length, 1, 'verifiedHops must remain intact while notebook trims first')
  assert.deepEqual(tight.brief.capabilityHandles, ['cap:hop_1:tok'], 'capabilityHandles must remain intact while notebook trims first')
  assert.ok(
    (tight.brief.workflowNotebook?.triedRecipes?.length ?? 0) < rawBrief.workflowNotebook!.triedRecipes!.length,
    'triedRecipes must trim first under tight budget',
  )

  // (c) Assignment brief surfaces workflowNotebook cleanly inside 4 KB cap.
  const fitted = fitHopCheckpointForBrief(full.brief, DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES)
  assert.ok(fitted.checkpoint.workflowNotebook?.discoveredRoutes?.includes('POST /api/drafts'))
  const packet = buildAssignmentBriefPacket({
    missionKind: 'workflow_skip',
    origin: ORIGIN,
    routes: [{ method: 'POST', path: '/api/approvals/finalize', params: ['draftId'] }],
    personas: [{ handle: 'member_b', role: 'member' }],
    hopCheckpoint: full.brief,
  })
  assert.ok(packet.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
  const parsed = JSON.parse(packet.text) as { hopCheckpoint?: { workflowNotebook?: { discoveredRoutes?: string[]; triedRecipes?: string[] } } }
  assert.ok(parsed.hopCheckpoint?.workflowNotebook?.discoveredRoutes?.includes('POST /api/drafts'))
  assert.ok(parsed.hopCheckpoint?.workflowNotebook?.triedRecipes?.includes('POST /api/drafts [member_b] -> 201'))
})

// ============================================================================
// 2. Cross-round notebook inheritance & bounded persistent workflow rotation
// ============================================================================

test('Move3.2: enqueueHopContinuationOnRotation persists & inherits workflowNotebook across rounds for workflow/business_logic/authz rotation', async t => {
  const { storage } = makeStore(t, 'kovo-move3-notebook-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  storage.updateRun(runId, { status: 'running', phase: 'investigation' })
  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { reconPlanner } = internals(engine)

  const wfStep = storage.addChainStep(run, {
    title: 'Approval workflow state check',
    hypothesis: 'Inspect state transition on /api/approvals',
    category: 'business-logic-race',
    skills: ['business-logic-workflow'],
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  assert.equal(isMultiHopChainStep(wfStep), false, 'test must exercise non-chain persistent workflow continuation')
  assert.equal(isPersistentWorkflowContinuationStep(wfStep), true)

  const w1 = storage.makeWorker(run, 'investigation', asset, wfStep.title, wfStep.hypothesis, {
    stepId: wfStep.id,
    sourceOrigins: [ORIGIN],
  })

  // Zero-progress rotation (only a 404, no facts, no sealed handles) -> must NOT enqueue.
  const only404 = seedExchange(storage, {
    runId, assignmentId: w1.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/missing', status: 404, personaHandle: 'member_b',
  })
  const noProgress = reconPlanner.enqueueHopContinuationOnRotation({
    run,
    step: wfStep,
    assignment: w1,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: 'Probed missing path only.',
    recordedFacts: [],
    recordedExchanges: [{ id: only404.id, origin: ORIGIN, method: 'GET', pathAndQuery: '/api/missing', status: 404, personaHandle: 'member_b' }],
    sealedCapHandles: [],
    trigger: 'wall_clock_rotated',
    maxContinuations: 2,
  })
  assert.equal(noProgress.enqueued, false)

  // Concrete progress in Round 1: non-404 route + workflow fact + sealed capability handle.
  const ex1 = seedExchange(storage, {
    runId, assignmentId: w1.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/drafts?step=1', status: 201, personaHandle: 'member_b',
  })
  const ex2 = seedExchange(storage, {
    runId, assignmentId: w1.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/approvals/submit', status: 200, personaHandle: 'member_b',
  })
  const ledger = storage.capabilityLedger(runId)
  const cap1 = 'cap:hop_wf1:draft_tok'
  ledger.addCapability({
    capId: cap1,
    kind: 'state_handle',
    provenance: 'derived_hop',
    tenantScope: 'tenant-b',
    actorPersona: 'member_b',
    serviceOrigin: ORIGIN,
    surface: 'http',
    artifactDigest: computeArtifactDigest('draft-1'),
    artifactSummary: 'Draft created by member_b',
    metadata: { endpoint: '/api/drafts' },
  })
  const fact1 = storage.addFact(run, w1, {
    kind: 'object_ref',
    origin: ORIGIN,
    summary: 'Verified draft creation succeeded with Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcdef12345678',
    data: { verified: true },
    exchangeIds: [ex1.id],
    sourceOrigins: [ORIGIN],
  })

  const cont1 = reconPlanner.enqueueHopContinuationOnRotation({
    run,
    step: wfStep,
    assignment: w1,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: 'Draft created; next test /api/approvals/finalize.',
    recordedFacts: [fact1],
    recordedExchanges: [
      { id: ex1.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/drafts?step=1', status: 201, personaHandle: 'member_b' },
      { id: ex2.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/approvals/submit', status: 200, personaHandle: 'member_b' },
    ],
    sealedCapHandles: [cap1],
    trigger: 'wall_clock_rotated',
    maxContinuations: 2,
  })
  assert.equal(cont1.enqueued, true, `expected continuation #1 enqueued: ${cont1.reason ?? ''}`)
  assert.equal(cont1.continuationDepth, 1)
  assert.ok(cont1.continuationStep)

  // Inspect Round 2 assignment brief (must surface Round 1 notebook cleanly even when hydrated from CapabilityLedger!).
  const cont1ParentFacts = storage.listFacts(runId, { includeTainted: false, limit: 100 })
    .filter(f => cont1.continuationStep!.dependsOnFactIds.includes(f.id))
  const briefRound2Text = reconPlanner.assignmentBriefForStep({
    run,
    step: cont1.continuationStep!,
    targetOrigins: [ORIGIN],
    personas: [
      { handle: 'admin_a', roleLabel: 'admin (org-a)' },
      { handle: 'member_b', roleLabel: 'member (org-b)' },
      { handle: 'viewer_c', roleLabel: 'viewer (org-c)' },
    ],
    parentFacts: cont1ParentFacts,
    confirmed: [],
    detLeads: [],
    maxTurns: 12,
  })
  assert.ok(briefRound2Text)
  const briefRound2 = JSON.parse(briefRound2Text!) as {
    hopCheckpoint?: { workflowNotebook?: { discoveredRoutes?: string[]; triedRecipes?: string[]; verifiedHypotheses?: string[] } }
  }
  assert.ok(briefRound2.hopCheckpoint?.workflowNotebook?.discoveredRoutes?.includes('POST /api/drafts'))
  assert.ok(briefRound2.hopCheckpoint?.workflowNotebook?.triedRecipes?.includes('POST /api/drafts [member_b] -> 201'))
  assert.ok(!briefRound2Text!.includes('eyJhbGciOiJIUzI1NiJ9'), 'raw JWT must be scrubbed from persisted notebook')

  // Round 2 rotates and enqueues continuation #2 -> must INHERIT Round 1 routes/recipes AND merge Round 2 progress!
  const w2 = storage.makeWorker(run, 'investigation', asset, cont1.continuationStep!.title, cont1.continuationStep!.hypothesis, {
    stepId: cont1.continuationStep!.id,
    sourceOrigins: [ORIGIN],
  })
  const ex3 = seedExchange(storage, {
    runId, assignmentId: w2.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/approvals/finalize', status: 200, personaHandle: 'member_b',
  })
  const cont2 = reconPlanner.enqueueHopContinuationOnRotation({
    run,
    step: cont1.continuationStep!,
    assignment: w2,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: 'Finalize accepted; readback remaining.',
    recordedFacts: [],
    recordedExchanges: [
      { id: ex3.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/approvals/finalize', status: 200, personaHandle: 'member_b' },
    ],
    sealedCapHandles: [cap1],
    trigger: 'wall_clock_rotated',
    maxContinuations: 2,
  })
  assert.equal(cont2.enqueued, true, `expected continuation #2 enqueued: ${cont2.reason ?? ''}`)
  assert.equal(cont2.continuationDepth, 2)

  const cont2AllParentFacts = storage.listFacts(runId, { includeTainted: false, limit: 100 })
    .filter(f => cont2.continuationStep!.dependsOnFactIds.includes(f.id))
  const cont2Facts = cont2AllParentFacts
    .filter(f => f.data?.subkind === 'hop_checkpoint')
    .sort((a, b) => {
      const da = (a.data?.checkpointBrief as HopCheckpointBrief | undefined)?.depth ?? 0
      const db = (b.data?.checkpointBrief as HopCheckpointBrief | undefined)?.depth ?? 0
      return (db - da) || (b.createdAt - a.createdAt)
    })
  const latestCp = cont2Facts[0]
  const latestBrief = latestCp?.data?.checkpointBrief as HopCheckpointBrief | undefined
  assert.ok(latestBrief?.workflowNotebook?.discoveredRoutes?.includes('POST /api/drafts'), 'Round 1 route must inherit into Round 3')
  assert.ok(latestBrief?.workflowNotebook?.discoveredRoutes?.includes('POST /api/approvals/finalize'), 'Round 2 route must merge into Round 3')
  assert.ok(latestBrief?.workflowNotebook?.triedRecipes?.includes('POST /api/drafts [member_b] -> 201'))
  assert.ok(latestBrief?.workflowNotebook?.triedRecipes?.includes('POST /api/approvals/finalize [member_b] -> 200'))
  const briefRound3Text = reconPlanner.assignmentBriefForStep({
    run,
    step: cont2.continuationStep!,
    targetOrigins: [ORIGIN],
    personas: [{ handle: 'member_b', roleLabel: 'member (org-b)' }],
    parentFacts: cont2AllParentFacts,
    confirmed: [],
    detLeads: [],
    maxTurns: 12,
  })
  const briefRound3 = JSON.parse(briefRound3Text!) as { hopCheckpoint?: { workflowNotebook?: { discoveredRoutes?: string[] } } }
  assert.ok(briefRound3.hopCheckpoint?.workflowNotebook?.discoveredRoutes?.includes('POST /api/drafts'))
  assert.ok(briefRound3.hopCheckpoint?.workflowNotebook?.discoveredRoutes?.includes('POST /api/approvals/finalize'))

  // Round 3 exceeds maxContinuations=2 -> strictly bounded!
  const w3 = storage.makeWorker(run, 'investigation', asset, cont2.continuationStep!.title, cont2.continuationStep!.hypothesis, {
    stepId: cont2.continuationStep!.id,
    sourceOrigins: [ORIGIN],
  })
  const cont3 = reconPlanner.enqueueHopContinuationOnRotation({
    run,
    step: cont2.continuationStep!,
    assignment: w3,
    targetOrigins: [ORIGIN],
    confirmed: false,
    partialSummary: 'Still working.',
    recordedFacts: [fact1],
    recordedExchanges: [
      { id: ex3.id, origin: ORIGIN, method: 'POST', pathAndQuery: '/api/approvals/finalize', status: 200, personaHandle: 'member_b' },
    ],
    sealedCapHandles: [cap1],
    trigger: 'wall_clock_rotated',
    maxContinuations: 2,
  })
  assert.equal(cont3.enqueued, false)
  assert.equal(cont3.reason, 'max_continuations_reached')
})

// ============================================================================
// 3. Low-Priv-First Exploration Guardrail (SF-C3)
// ============================================================================

test('Move3.3: low-privilege-first persona ordering beats alphabetical admin-first everywhere (SF-C3)', async t => {
  const inputPersonas = [
    { handle: 'admin_a', roleLabel: 'admin (org-a)', originAllowlist: [ORIGIN] },
    { handle: 'owner_root', roleLabel: 'owner (org-a)', originAllowlist: [ORIGIN] },
    { handle: 'editor_1', roleLabel: 'editor (org-a)', originAllowlist: [ORIGIN] },
    { handle: 'manager_1', roleLabel: 'manager (org-b)', originAllowlist: [ORIGIN] },
    { handle: 'member_b', roleLabel: 'member (org-b)', originAllowlist: [ORIGIN] },
    { handle: 'tenant_admin', roleLabel: 'tenant_admin (org-b)', originAllowlist: [ORIGIN] },
    { handle: 'guest_0', roleLabel: 'guest (public)', originAllowlist: [ORIGIN] },
    { handle: 'viewer_1', roleLabel: 'read_only viewer (org-c)', originAllowlist: [ORIGIN] },
  ]
  assert.equal(classifyPersonaPrivilege('viewer_1', 'readonly').rank, 0)
  assert.equal(classifyPersonaPrivilege('member_b', 'member').rank, 0)
  assert.equal(classifyPersonaPrivilege('manager_1', 'manager').rank, 1)
  assert.equal(classifyPersonaPrivilege('revoked_or_demoted', 'revoked member').rank, 3)
  assert.equal(classifyPersonaPrivilege('tenant_admin', 'tenant_admin').rank, 5)

  const sorted = sortPersonasLowPrivFirst(inputPersonas)
  assert.deepEqual(
    sorted.map(p => p.handle),
    ['member_b', 'guest_0', 'viewer_1', 'editor_1', 'manager_1', 'admin_a', 'owner_root', 'tenant_admin'],
  )

  // Verify assignmentBriefForStep picks lowest-privilege persona (NOT admin_a) as proofObligation.controlPersona.
  const { storage } = makeStore(t, 'kovo-move3-lowpriv-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  storage.updateRun(runId, { status: 'running', phase: 'investigation' })
  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { reconPlanner } = internals(engine)

  const worker = storage.makeWorker(run, 'investigation', asset, 'Seed', 'Seed', { sourceOrigins: [ORIGIN] })
  // Persisted typed `chain_hop` fact (shape produced by workers / earlier rounds).
  const hop = {
    hopId: 'hop-move3-1', roundNo: 1, hopIndex: 1, artifactKind: 'leaked_id', artifactRef: 'order_123',
    origin: ORIGIN, endpoint: '/api/orders/123', method: 'GET', verified: true, evidenceIds: [], factIds: [],
    summary: 'Observed order_123 at GET /api/orders/123',
  }
  const hopFact = storage.addFact(run, worker, {
    kind: 'note',
    origin: ORIGIN,
    summary: `ChainHop r${hop.roundNo} (${hop.artifactKind}): ${hop.artifactRef} at ${hop.method} ${hop.endpoint}`,
    data: {
      kind: 'chain_hop', subkind: 'chain_hop', roundNo: hop.roundNo, hopId: hop.hopId,
      artifactKind: hop.artifactKind, artifactRef: hop.artifactRef, verified: hop.verified,
      endpoint: hop.endpoint, method: hop.method, hop,
    },
    sourceOrigins: [ORIGIN],
  })
  const step = storage.addChainStep(run, {
    title: 'BOLA cross-tenant read check',
    hypothesis: 'Verify GET /api/orders/123 enforces tenant boundary',
    category: 'broken-access-control',
    skills: ['bola-bfla'],
    dependsOnFactIds: [hopFact.id],
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  const briefJson = reconPlanner.assignmentBriefForStep({
    run,
    step,
    targetOrigins: [ORIGIN],
    personas: [
      { handle: 'admin_a', roleLabel: 'admin (org-a)' },
      { handle: 'member_b', roleLabel: 'member (org-b)' },
    ],
    parentFacts: [hopFact],
    confirmed: [],
    detLeads: [],
    maxTurns: 12,
  })
  assert.ok(briefJson)
  const parsedBrief = JSON.parse(briefJson!) as { proofObligation?: { controlPersona?: string; variantPersona?: string } }
  assert.equal(parsedBrief.proofObligation?.controlPersona, 'member_b', 'lowest-priv persona must be selected ahead of admin_a')
  assert.equal(parsedBrief.proofObligation?.variantPersona, 'admin_a')

  // Verify prompt guidance carries both SF-C3 low-priv-first and SF-C2/SF-C4 closure evidence directives.
  assert.match(scenarioInstructions['worker-investigation'], /lowest-privilege persona first/i)
  assert.match(scenarioInstructions['worker-investigation'], /single 403\/404 probe/i)
  const prompt = JSON.parse(workerInvestigationPrompt({
    goal: 'defensive authz review',
    step: { id: step.id, title: step.title, hypothesis: step.hypothesis, category: step.category, skills: step.skills },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 12,
    personas: sorted.slice(0, 2),
  })) as { explorationGuardrails?: { lowPrivFirst?: string; closureEvidence?: string } }
  assert.match(prompt.explorationGuardrails?.lowPrivFirst ?? '', /lowest-privilege persona first/i)
  assert.match(prompt.explorationGuardrails?.closureEvidence ?? '', /single 403\/404 probe/i)
})

// ============================================================================
// 4. Anti-Premature-[ruled_out] / no_issue_found Guardrail (SF-C2, SF-C4)
// ============================================================================

test('Move3.4: inspectCoverageExchangeEvidence returns distinctPersonas/distinctExchanges without weakening R2-14 ownership', async t => {
  const { storage } = makeStore(t, 'kovo-move3-cov-ev-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN, OTHER_ORIGIN], tier: 2 })
  const { runId: otherRunId, run: otherRun } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => c.origin === ORIGIN && run.approved.includes(c.id))!
  const otherAsset = otherRun.candidates.find(c => c.origin === ORIGIN && otherRun.approved.includes(c.id))!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Cov worker', 'Probe', { sourceOrigins: [ORIGIN] })
  const otherWorker = storage.makeWorker(otherRun, 'investigation', otherAsset, 'Other worker', 'Probe', { sourceOrigins: [ORIGIN] })

  const exMemberA = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, status: 403, personaHandle: 'member_a' })
  const exMemberB = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, status: 200, personaHandle: 'member_b' })
  const exUnauth = seedExchange(storage, { runId, assignmentId: worker.id, origin: ORIGIN, status: 401, personaHandle: null })
  const exWrongOrigin = seedExchange(storage, { runId, assignmentId: worker.id, origin: OTHER_ORIGIN, status: 200, personaHandle: 'admin_a' })
  const exOtherRun = seedExchange(storage, { runId: otherRunId, assignmentId: otherWorker.id, origin: ORIGIN, status: 200, personaHandle: 'admin_a' })

  const single403 = FindingsRepository.inspectCoverageExchangeEvidence(storage.db, runId, ORIGIN, [exMemberA.id, exWrongOrigin.id, exOtherRun.id])
  assert.deepEqual(single403.verifiedExchangeIds, [exMemberA.id], 'wrong-origin and cross-run exchanges must stay excluded')
  assert.equal(single403.distinctExchanges, 1)
  assert.deepEqual(single403.distinctPersonas, ['member_a'])
  assert.equal(single403.allDenial403Or404, true)

  const multiPersona = FindingsRepository.inspectCoverageExchangeEvidence(storage.db, runId, ORIGIN, [exMemberA.id, exMemberB.id])
  assert.equal(multiPersona.distinctExchanges, 2)
  assert.deepEqual(multiPersona.distinctPersonas.sort(), ['member_a', 'member_b'])
  assert.equal(multiPersona.allDenial403Or404, false)

  const authPlusUnauth = FindingsRepository.inspectCoverageExchangeEvidence(storage.db, runId, ORIGIN, [exMemberA.id, exUnauth.id])
  assert.equal(authPlusUnauth.distinctExchanges, 2)
  assert.deepEqual(authPlusUnauth.distinctPersonas.sort(), ['member_a', 'unauthenticated'])
})

test('Move3.5: live worker rejects premature ruled_out on strike 1 (record_coverage & complete_intent) and never loops past 1 strike', async t => {
  // Scenario A: Worker calls record_coverage(status="ruled_out") with a single 403 probe on a 2-persona BOLA step ->
  // rejected on strike 1; repairs by citing 2 distinct personas (or file:line) and succeeds cleanly.
  const targetServer = createServer((req, res) => {
    res.statusCode = req.headers['x-test-persona'] === 'member_a' ? 403 : 200
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ ok: res.statusCode === 200 }))
  })
  await new Promise<void>(resolve => targetServer.listen(0, '127.0.0.1', () => resolve()))
  const targetPort = (targetServer.address() as AddressInfo).port
  const targetOrigin = `http://127.0.0.1:${targetPort}`
  t.after(async () => {
    targetServer.closeAllConnections?.()
    await new Promise<void>(resolve => targetServer.close(() => resolve()))
  })

  let capturedPersonasInPrompt: Array<{ handle: string }> = []
  let sawRejectionError = false
  let singleExId = ''
  let secondExId = ''

  const llm = await startMockLlm(t, (body, reqIndex) => {
    const inputText = JSON.stringify(body.input ?? '')
    if (reqIndex === 1) {
      const items = Array.isArray(body.input) ? body.input : []
      const userMsg = items.find((i: unknown) => i && typeof i === 'object' && (i as { role?: string }).role === 'user') as {
        content?: string | Array<{ text?: string }>
      } | undefined
      const rawContent = typeof userMsg?.content === 'string'
        ? userMsg.content
        : Array.isArray(userMsg?.content)
          ? userMsg.content.map(part => part?.text ?? '').join('')
          : ''
      if (rawContent) {
        const personaMatch = /"personas":(\[[\s\S]*?\])\s*,\s*"bolaTestQueue"/.exec(rawContent)
        if (personaMatch?.[1]) {
          capturedPersonasInPrompt = JSON.parse(personaMatch[1]) as Array<{ handle: string }>
        }
      }
      return {
        toolCall: {
          callId: `call_cov_strike1_${reqIndex}`,
          name: 'record_coverage',
          argumentsJson: JSON.stringify({
            origin: targetOrigin,
            category: 'broken-access-control',
            status: 'ruled_out',
            summary: 'Single 403 observed; prematurely ruling out BOLA.',
            enforcingControl: `Denied with 403 (${singleExId})`,
            exchangeIds: [singleExId],
          }),
        },
      }
    }
    if (/Premature .*ruled_out.* rejected \(strike 1\/1\)/.test(inputText)) {
      sawRejectionError = true
    }
    if (reqIndex === 2) {
      return {
        toolCall: {
          callId: `call_cov_repaired_${reqIndex}`,
          name: 'record_coverage',
          argumentsJson: JSON.stringify({
            origin: targetOrigin,
            category: 'broken-access-control',
            status: 'ruled_out',
            summary: 'Verified cross-persona control across member_a (403) and member_b (200).',
            enforcingControl: `Verified cross-persona controls (${singleExId}, ${secondExId})`,
            exchangeIds: [singleExId, secondExId],
          }),
        },
      }
    }
    return {
      toolCall: {
        callId: `call_done_${reqIndex}`,
        name: 'complete_intent',
        argumentsJson: JSON.stringify({
          status: 'ruled_out',
          summary: 'Verified cross-persona authorization control across two personas.',
        }),
      },
    }
  })

  const { storage } = makeStore(t, 'kovo-move3-live-guard-')
  await saveModelProfile({
    name: 'Move3-Guard-Mock',
    endpoint: llm.endpoint,
    model: 'mock-move3-guard',
    protocol: 'responses',
    key: 'sk-mock-move3-1234',
    priority: 100,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 4096,
    thinkingLevel: 'medium',
    roleAffinity: 'tactical',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
  }, storage, { skipConnectionCheck: true })

  const { runId, run } = await setupApprovedRun(storage, {
    seeds: [targetOrigin],
    tier: 2,
    personas: [
      { handle: 'admin_a', roleLabel: 'admin (org-a)', authKind: 'header', headerName: 'x-test-persona', secret: 'secret-token-admin-a-999' },
      { handle: 'member_b', roleLabel: 'member (org-b)', authKind: 'header', headerName: 'x-test-persona', secret: 'secret-token-member-b-888' },
    ],
  })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const step = storage.addChainStep(run, {
    title: 'BOLA cross-tenant read check',
    hypothesis: 'Test BOLA across personas on GET /api/orders/1',
    category: 'broken-access-control',
    skills: ['bola-bfla'],
    targetAssetIds: [asset.id],
    sourceOrigins: [targetOrigin],
  })
  const seedWorker = storage.makeWorker(run, 'investigation', asset, 'Seed exchanges', 'Seed', { sourceOrigins: [targetOrigin] })
  singleExId = seedExchange(storage, { runId, assignmentId: seedWorker.id, origin: targetOrigin, status: 403, personaHandle: 'member_b' }).id
  secondExId = seedExchange(storage, { runId, assignmentId: seedWorker.id, origin: targetOrigin, status: 200, personaHandle: 'admin_a' }).id

  storage.updateRun(runId, { status: 'running', phase: 'investigation' })
  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const createdAssignment = storage.makeWorker(run, 'investigation', asset, step.title, step.hypothesis, {
    stepId: step.id,
    sourceOrigins: [targetOrigin],
    maxTurns: 6,
  })
  const assignment = storage.updateWorker(createdAssignment.id, { status: 'running', lease: 'move3-lease-a' })
  const profilesA = resolveProfilePoolForRole('tactical', storage)
  await (engine as unknown as {
    workerRunner: {
      runInvestigationWorker: (
        job: { assignment: typeof assignment; origins: Set<string>; controller: AbortController },
        s: typeof step,
        origins: string[],
        profiles: typeof profilesA,
        budget: { kind: 'single_step' | 'chain'; maxTurns: number; wallClockMs: number },
      ) => Promise<void>
    }
  }).workerRunner.runInvestigationWorker(
    { assignment, origins: new Set([targetOrigin]), controller: new AbortController() },
    step,
    [targetOrigin],
    profilesA,
    { kind: 'single_step', maxTurns: 6, wallClockMs: 30_000 },
  )

  assert.equal(sawRejectionError, true, 'Strike 1 must reject premature ruled_out from single 403 probe')
  assert.deepEqual(
    capturedPersonasInPrompt.map(p => p.handle),
    ['member_b', 'admin_a'],
    'Worker prompt personasPub must be sorted low-privilege-first (member_b before admin_a)',
  )

  // Scenario B: 1-strike per-assignment non-looping cap on complete_intent(status="ruled_out") with 0 exchanges.
  let completeRejections = 0
  const llmLoopGuard = await startMockLlm(t, (body, reqIndex) => {
    if (/Premature .*ruled_out.* rejected \(strike 1\/1\)/.test(JSON.stringify(body.input ?? ''))) {
      completeRejections += 1
    }
    return {
      toolCall: {
        callId: `call_complete_loop_${reqIndex}`,
        name: 'complete_intent',
        argumentsJson: JSON.stringify({
          status: 'ruled_out',
          summary: 'Ruling out workflow without probing.',
        }),
      },
    }
  })
  const { storage: storageB } = makeStore(t, 'kovo-move3-1strike-')
  await saveModelProfile({
    name: 'Move3-1Strike-Mock',
    endpoint: llmLoopGuard.endpoint,
    model: 'mock-move3-1strike',
    protocol: 'responses',
    key: 'sk-mock-move3-5678',
    priority: 100,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 4096,
    thinkingLevel: 'medium',
    roleAffinity: 'tactical',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
  }, storageB, { skipConnectionCheck: true })
  const { runId: runIdB, run: runB } = await setupApprovedRun(storageB, { seeds: [targetOrigin], tier: 2 })
  const assetB = runB.candidates.find(c => runB.approved.includes(c.id))!
  const wfStepB = storageB.addChainStep(runB, {
    title: 'Workflow lifecycle check',
    hypothesis: 'Test multi-step workflow transition',
    category: 'business-logic-race',
    skills: ['business-logic-workflow'],
    targetAssetIds: [assetB.id],
    sourceOrigins: [targetOrigin],
  })
  storageB.updateRun(runIdB, { status: 'running', phase: 'investigation' })
  const engineB = new Execution(storageB, { backend: stubBackend() })
  t.after(() => engineB.stop())
  const createdAssignmentB = storageB.makeWorker(runB, 'investigation', assetB, wfStepB.title, wfStepB.hypothesis, {
    stepId: wfStepB.id,
    sourceOrigins: [targetOrigin],
    maxTurns: 6,
  })
  const assignmentB = storageB.updateWorker(createdAssignmentB.id, { status: 'running', lease: 'move3-lease-b' })
  const profilesB = resolveProfilePoolForRole('tactical', storageB)
  await (engineB as unknown as {
    workerRunner: {
      runInvestigationWorker: (
        job: { assignment: typeof assignmentB; origins: Set<string>; controller: AbortController },
        s: typeof wfStepB,
        origins: string[],
        profiles: typeof profilesB,
        budget: { kind: 'single_step' | 'chain'; maxTurns: number; wallClockMs: number },
      ) => Promise<void>
    }
  }).workerRunner.runInvestigationWorker(
    { assignment: assignmentB, origins: new Set([targetOrigin]), controller: new AbortController() },
    wfStepB,
    [targetOrigin],
    profilesB,
    { kind: 'single_step', maxTurns: 6, wallClockMs: 30_000 },
  )

  assert.equal(completeRejections, 1, 'complete_intent must reject once (strike 1/1) and allow retry without infinite loop')
  assert.equal(llmLoopGuard.calls.length, 2, '1-strike cap must finish in exactly 2 LLM turns')
})
