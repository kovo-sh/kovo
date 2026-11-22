import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { newRun, runCommand } from '../src/domain.ts'
import {
  evaluateTier3Approval,
  isLocalLabAutoApprovalOrigin,
} from '../src/server/approval-judge.ts'
import { BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant, PublicAddress } from '../src/server/broker.ts'
import { Store } from '../src/server/store.ts'
import type { Assignment } from '../src/server/store.ts'
import { Execution } from '../src/server/execution.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

// ============================================================================
// M5 / Tier-3 zero-trust safety invariants
//
// The realistic grey-box harness runs an authorized local-lab at Capability Tier 3 so
// state-changing probes work. These tests pin the five safety invariants that keep that
// unlock from weakening public-target HITL, origin scope, operator policy, broker
// fail-closed controls, or the audit trail.
// ============================================================================

const LOOPBACK_ORIGIN = 'http://127.0.0.1:43119'
const CONTAINER_ORIGIN = 'http://app:8080'
const PRIVATE_LAB_ORIGIN = 'http://172.18.0.4:3000'
const EXTERNAL_ORIGIN = 'https://staging.example.com'
const METADATA_HOST_ORIGIN = 'https://metadata.google.internal'

async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const previous: Record<string, string | undefined> = {}
  for (const [key, value] of Object.entries(vars)) {
    previous[key] = process.env[key]
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
  try {
    return await fn()
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

function localLabGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    origin: LOOPBACK_ORIGIN,
    tier: 3,
    maxRpsPerOrigin: 5,
    allowLocalLab: true,
    canRead: candidate => candidate === LOOPBACK_ORIGIN,
    // Simulate a Tier-3 auto-approval decision for state-changing methods.
    isStateChangeApproved: () => true,
    audit: () => {},
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Invariant 1 — public isolation
// ---------------------------------------------------------------------------

test('invariant 1: GUARDIAN_ALLOW_LOCAL_LAB=1 never relaxes Tier-3 approvals for public or unspecified environments', async () => {
  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const cases = [
      { label: 'DELETE', input: { method: 'DELETE' as const, pathAndQuery: '/api/items/42' } },
      { label: 'multipart', input: { method: 'POST' as const, pathAndQuery: '/api/upload', hasMultipart: true } },
      { label: 'rce_proof', input: { method: 'POST' as const, pathAndQuery: '/api/eval', isRceProof: true } },
      { label: 'high-risk keyword', input: { method: 'POST' as const, pathAndQuery: '/api/billing/refund' } },
    ]

    for (const environment of ['public', undefined] as const) {
      for (const probe of cases) {
        const result = await evaluateTier3Approval({
          policy: 'auto_review',
          environment,
          origin: LOOPBACK_ORIGIN,
          ...probe.input,
        })
        assert.equal(result.decision, 'escalate_human', `${probe.label} must escalate for environment=${environment ?? 'unspecified'}`)
        assert.equal(result.stage, 'hard_escalation', `${probe.label} must hit hard escalation for environment=${environment ?? 'unspecified'}`)
        assert.notEqual(result.decidedBy, 'auto-review:local-lab')
      }
    }

    // A mislabeled public environment on a loopback origin still never gets lab attribution.
    const publicLoopback = await evaluateTier3Approval({
      policy: 'auto_review',
      environment: 'public',
      origin: LOOPBACK_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/state-eval',
      bodyPreview: '{"probe":"benign-tier3-check"}',
      offline: true,
    })
    assert.notEqual(publicLoopback.decidedBy, 'auto-review:local-lab')
  })
})

// ---------------------------------------------------------------------------
// Invariant 2 — origin binding
// ---------------------------------------------------------------------------

test('invariant 2: local-lab auto-approval requires a loopback or LabRunner-internal origin', async () => {
  const allowed = [
    'http://127.0.0.1:8080',
    'http://127.1.2.3:9000',
    'http://localhost:3000',
    'http://[::1]:3000',
    CONTAINER_ORIGIN,
    'http://guardian-lab-web-1a2b3c4d5e:8080',
    PRIVATE_LAB_ORIGIN,
    'http://10.4.5.6:8080',
    'http://192.168.1.20:8080',
  ]
  const rejected = [
    EXTERNAL_ORIGIN,
    'https://localhost.evil.example.com',
    'http://169.254.169.254',
    'http://169.254.169.254/latest/meta-data',
    METADATA_HOST_ORIGIN,
    'http://metadata.goog',
    'http://0.0.0.0:8080',
    'http://8.8.8.8',
    'ftp://127.0.0.1:21',
  ]
  for (const origin of allowed) assert.equal(isLocalLabAutoApprovalOrigin(origin), true, `${origin} should be lab-internal`)
  for (const origin of rejected) assert.equal(isLocalLabAutoApprovalOrigin(origin), false, `${origin} must never be lab-internal`)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    // Authorized loopback/container origins auto-approve, including DELETE/multipart/RCE keys.
    for (const origin of [LOOPBACK_ORIGIN, CONTAINER_ORIGIN, PRIVATE_LAB_ORIGIN]) {
      const result = await evaluateTier3Approval({
        policy: 'auto_review',
        environment: 'local-lab',
        origin,
        method: 'DELETE',
        pathAndQuery: '/api/items/42',
      })
      assert.equal(result.decision, 'approve')
      assert.equal(result.decidedBy, 'auto-review:local-lab')
      assert.equal(result.stage, 'local_lab')
    }

    // A mislabeled external hostname must fall back to public hard-escalation rules.
    for (const origin of [EXTERNAL_ORIGIN, METADATA_HOST_ORIGIN]) {
      const result = await evaluateTier3Approval({
        policy: 'auto_review',
        environment: 'local-lab',
        origin,
        method: 'DELETE',
        pathAndQuery: '/api/items/42',
      })
      assert.equal(result.decision, 'escalate_human', `${origin} must not be auto-approved as local-lab`)
      assert.equal(result.stage, 'hard_escalation')
      assert.notEqual(result.decidedBy, 'auto-review:local-lab')
    }

    // High-risk keyword probes against an external mislabeled origin also escalate.
    const externalKeyword = await evaluateTier3Approval({
      policy: 'auto_review',
      environment: 'local-lab',
      origin: EXTERNAL_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/billing/refund',
    })
    assert.equal(externalKeyword.decision, 'escalate_human')
    assert.notEqual(externalKeyword.decidedBy, 'auto-review:local-lab')
  })
})

// ---------------------------------------------------------------------------
// Invariant 3 — strict policy precedence
// ---------------------------------------------------------------------------

test('invariant 3: explicit strict policy always escalates and never auto-approves', async () => {
  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    let llmCalled = false
    const llmCall = async () => {
      llmCalled = true
      return JSON.stringify({ decision: 'approve', riskLevel: 'low', reason: 'should never run' })
    }
    const strictInputs = [
      { environment: 'local-lab' as const, origin: LOOPBACK_ORIGIN, method: 'POST' as const, pathAndQuery: '/v1/client/sign_ins' },
      { environment: 'local-lab' as const, origin: LOOPBACK_ORIGIN, method: 'DELETE' as const, pathAndQuery: '/api/items/42' },
      { environment: 'public' as const, origin: LOOPBACK_ORIGIN, method: 'POST' as const, pathAndQuery: '/api/state-eval' },
    ]
    for (const input of strictInputs) {
      const result = await evaluateTier3Approval({ policy: 'strict', llmCall, ...input })
      assert.equal(result.decision, 'escalate_human', `strict must escalate ${input.method} ${input.pathAndQuery}`)
      assert.equal(result.decidedBy, 'operator')
      assert.equal(result.stage, 'strict')
      assert.equal(result.usedLlm, false)
    }
    assert.equal(llmCalled, false)

    // Operator-approved endpoint patterns cannot override strict either.
    const strictWithPattern = await evaluateTier3Approval({
      policy: 'strict',
      environment: 'local-lab',
      origin: LOOPBACK_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/7',
      approvedPatterns: [{ origin: LOOPBACK_ORIGIN, method: 'POST', pathPattern: '/api/items/*' }],
    })
    assert.equal(strictWithPattern.decision, 'escalate_human')
    assert.equal(strictWithPattern.stage, 'strict')

    // Auto-review is the only policy that authorizes local-lab auto-approval.
    const autoReview = await evaluateTier3Approval({
      policy: 'auto_review',
      environment: 'local-lab',
      origin: LOOPBACK_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/state-eval',
    })
    assert.equal(autoReview.decision, 'approve')
    assert.equal(autoReview.decidedBy, 'auto-review:local-lab')
  })
})

// ---------------------------------------------------------------------------
// Invariant 4 — broker fail-closed invariants survive Tier-3 auto-approval
// ---------------------------------------------------------------------------

test('invariant 4: local-lab auto-approval never bypasses destructive, webshell, metadata-SSRF, or RPS guards', async () => {
  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const labAddress: PublicAddress[] = [{ address: '127.0.0.1', family: 4 }]

    // 4a. Destructive-payload denylist (SQL/storage destruction) is enforced pre-flight.
    const destructiveBroker = new RequestBroker({
      resolve: async () => labAddress,
      transport: async () => {
        throw new Error('transport must not run for a denied destructive payload')
      },
    })
    await assert.rejects(
      destructiveBroker.executeHttp({
        origin: LOOPBACK_ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/items',
        body: 'DROP TABLE items',
      }, localLabGrant(), AbortSignal.timeout(5_000)),
      /destructive/i,
    )

    // 4b. Webshell signature filter still blocks multipart uploads in the lab.
    const webshellBroker = new RequestBroker({
      resolve: async () => labAddress,
      transport: async () => {
        throw new Error('transport must not run for a denied webshell upload')
      },
    })
    await assert.rejects(
      webshellBroker.executeHttp({
        origin: LOOPBACK_ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/upload',
        multipartParts: [{
          name: 'file',
          filename: 'avatar.php',
          contentType: 'application/x-php',
          content: '<?php echo "canary"; ?>',
        }],
      }, localLabGrant(), AbortSignal.timeout(5_000)),
      /webshell/i,
    )

    // 4c. Cloud metadata / link-local resolution is denied even with local-lab + auto-approval.
    let metadataDialed = false
    const metadataBroker = new RequestBroker({
      resolve: async () => [{ address: '169.254.169.254', family: 4 }],
      transport: async () => {
        metadataDialed = true
        return { status: 200, headers: {}, body: 'metadata' }
      },
    })
    await assert.rejects(
      metadataBroker.executeHttp({
        origin: 'http://lab-metadata:80',
        method: 'GET',
        pathAndQuery: '/latest/meta-data',
      }, localLabGrant({ origin: 'http://lab-metadata:80', canRead: () => true }), AbortSignal.timeout(5_000)),
      /link-local|metadata/i,
    )
    assert.equal(metadataDialed, false, 'metadata address must never be dialed')

    // 4d. RPS cap still throttles a local-lab origin that has Tier-3 auto-approval.
    const rpsBroker = new RequestBroker({
      resolve: async () => labAddress,
      transport: async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }),
    })
    const rpsGrant = localLabGrant({ maxRpsPerOrigin: 1 })
    const first = await rpsBroker.executeHttp(
      { origin: LOOPBACK_ORIGIN, method: 'GET', pathAndQuery: '/lab/one' },
      rpsGrant,
      AbortSignal.timeout(2_000),
    )
    assert.equal(first.status, 200)
    await assert.rejects(
      rpsBroker.executeHttp(
        { origin: LOOPBACK_ORIGIN, method: 'GET', pathAndQuery: '/lab/two' },
        rpsGrant,
        AbortSignal.timeout(80),
      ),
      /abort/i,
    )

    // 4e. Private-address denial is unchanged when the lab flag/grant are both absent.
    let publicDialed = false
    const publicBroker = new RequestBroker({
      resolve: async () => labAddress,
      transport: async () => {
        publicDialed = true
        return { status: 200, headers: {}, body: 'must-not-run' }
      },
    })
    await assert.rejects(
      publicBroker.executeHttp(
        { origin: LOOPBACK_ORIGIN, method: 'GET', pathAndQuery: '/lab' },
        localLabGrant({ allowLocalLab: false }),
        AbortSignal.timeout(5_000),
      ),
      error => error instanceof BrokerDenied && /scope|public addresses/i.test(error.message),
    )
    assert.equal(publicDialed, false, 'private address must never be dialed on a public grant')
  })
})

// ---------------------------------------------------------------------------
// Execution wiring — no unattributed local-lab Tier-3 bypass remains
// ---------------------------------------------------------------------------

test('execution Tier-3 gate: local-lab approval is origin-bound, strict-aware, and persisted', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-tier3-exec-'))
  const storage = new Store(dir)
  const execution = new Execution(storage)
  t.after(async () => {
    await execution.stop()
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })
  const priv = execution as unknown as Record<string, any>

  const makeJob = async (origin: string, tier: 3 | 2 = 3) => {
    const { runId } = await setupApprovedRun(storage, {
      seeds: [origin],
      tier,
      environment: 'local-lab',
    })
    storage.updateRun(runId, { phase: 'investigation', status: 'running' })
    const run = storage.run(runId)
    const created = storage.makeWorker(run, 'investigation', undefined, 'Tier 3 gate', 'Verify local-lab approval', { sourceOrigins: [origin] })
    storage.updateWorker(created.id, { status: 'running' })
    const assignment: Assignment = storage.worker(created.id)
    return {
      runId,
      job: { assignment, origins: new Set([origin]), controller: new AbortController() },
    }
  }

  const approvalInput = (origin: string) => ({
    origin,
    method: 'DELETE' as const,
    pathAndQuery: '/api/items/42',
    rationale: 'Local-lab Tier-3 state change',
    requestPreview: `DELETE ${origin}/api/items/42`,
    secrets: [],
  })

  // 1. Loopback local-lab auto-approval succeeds AND leaves a persisted audit row.
  const loopback = await makeJob(LOOPBACK_ORIGIN)
  const approved = await priv.waitForTier3Approval(
    loopback.job,
    approvalInput(LOOPBACK_ORIGIN),
    AbortSignal.timeout(5_000),
  )
  assert.equal(approved.approved, true)
  const autoRows = storage.listApprovalRequests(loopback.runId)
  assert.equal(autoRows.length, 1)
  assert.equal(autoRows[0]?.status, 'approved')
  assert.equal(autoRows[0]?.decidedBy, 'auto-review:local-lab')
  assert.equal(
    storage.eventsAfter(loopback.runId, 0, 200).filter(event => event.kind === 'approval.auto_approved').length,
    1,
  )

  // 2. Explicit strict policy still escalates instead of auto-approving the same loopback write.
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId: loopback.runId,
    action: 'set_approval_policy',
    approvalPolicy: 'strict',
  }))
  await assert.rejects(
    priv.waitForTier3Approval(loopback.job, approvalInput(LOOPBACK_ORIGIN), AbortSignal.timeout(120)),
    /abort|timeout/i,
  )
  const strictRows = storage.listApprovalRequests(loopback.runId, 'pending')
  assert.equal(strictRows.length, 1, 'strict policy must open a HITL card')
  assert.equal(strictRows[0]?.decidedBy, null)
  assert.equal(
    storage.eventsAfter(loopback.runId, 0, 200).filter(event => event.kind === 'approval.auto_approved').length,
    1,
    'strict policy must not add an auto-approval audit row',
  )

  // 3. An external hostname mislabeled as local-lab never auto-approves: it opens a HITL card.
  const external = await makeJob(EXTERNAL_ORIGIN)
  await assert.rejects(
    priv.waitForTier3Approval(external.job, approvalInput(EXTERNAL_ORIGIN), AbortSignal.timeout(120)),
    /abort|timeout/i,
  )
  const externalRows = storage.listApprovalRequests(external.runId, 'pending')
  assert.equal(externalRows.length, 1, 'external mislabeled origin must require human approval')
  assert.equal(externalRows[0]?.decidedBy, null)
  assert.equal(storage.listApprovalRequests(external.runId, 'approved').length, 0)
})

// ---------------------------------------------------------------------------
// Invariant 5 — audit attribution for every auto-approved Tier-3 action
// ---------------------------------------------------------------------------

test('invariant 5: local-lab auto-approval persists an audit record attributed to auto-review:local-lab', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-tier3-safety-'))
  const storage = new Store(dir)
  try {
    await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
      const project = storage.createProject({
        requestId: randomUUID(),
        name: 'Tier 3 safety audit',
        seeds: [LOOPBACK_ORIGIN],
        environment: 'local-lab',
      })
      const parsedNewRun = newRun.parse({
        requestId: randomUUID(),
        projectId: project.id,
        goal: 'Verify Tier-3 local-lab auto-approval audit attribution',
        capabilityTier: 3,
        approvalPolicy: 'auto_review',
      })
      const { id: runId } = storage.createRun(parsedNewRun)

      storage.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
      const discovered = storage.run(runId)
      storage.command(runCommand.parse({
        requestId: randomUUID(),
        runId,
        action: 'scope',
        assetIds: discovered.candidates.map(candidate => candidate.id),
        expectedScopeRevision: discovered.scopeRevision,
        consent: true,
        capabilityTier: 3,
      }))
      const scopedRun = storage.run(runId)
      const worker = storage.makeWorker(scopedRun, 'investigation', scopedRun.candidates[0], 'Worker 1', 'Tier 3 safety audit')

      const evaluation = await evaluateTier3Approval({
        policy: scopedRun.approvalPolicy,
        environment: 'local-lab',
        origin: LOOPBACK_ORIGIN,
        method: 'DELETE',
        pathAndQuery: '/api/items/42',
      })
      assert.equal(evaluation.decision, 'approve')
      assert.equal(evaluation.decidedBy, 'auto-review:local-lab')

      const row = storage.recordAutoApprovalDecision(scopedRun, worker, {
        origin: LOOPBACK_ORIGIN,
        method: 'DELETE',
        pathAndQuery: '/api/items/42',
        rationale: 'Local-lab Tier-3 state change',
        requestPreview: `DELETE ${LOOPBACK_ORIGIN}/api/items/42`,
        decision: 'approved',
        decidedBy: evaluation.decidedBy,
        riskLevel: evaluation.riskLevel,
        policyNote: evaluation.reason,
      })
      assert.equal(row.status, 'approved')
      assert.equal(row.decidedBy, 'auto-review:local-lab')
      assert.equal(row.riskLevel, 'medium')

      const persisted = storage.getApprovalRequest(runId, row.id)
      assert.equal(persisted.status, 'approved')
      assert.equal(persisted.decidedBy, 'auto-review:local-lab')
      assert.ok(persisted.decidedAt && persisted.decidedAt > 0, 'decidedAt must be persisted')

      const auditEvents = storage.eventsAfter(runId, 0, 500).filter(event => event.kind === 'approval.auto_approved')
      assert.equal(auditEvents.length, 1)
      assert.equal(auditEvents[0]?.detail?.decidedBy, 'auto-review:local-lab')

      // A strict-policy walk never produces an auto-approval audit row.
      storage.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'set_approval_policy', approvalPolicy: 'strict' }))
      const strictEvaluation = await evaluateTier3Approval({
        policy: storage.run(runId).approvalPolicy,
        environment: 'local-lab',
        origin: LOOPBACK_ORIGIN,
        method: 'DELETE',
        pathAndQuery: '/api/items/43',
      })
      assert.equal(strictEvaluation.decision, 'escalate_human')
      assert.equal(strictEvaluation.stage, 'strict')
      assert.equal(
        storage.eventsAfter(runId, 0, 500).filter(event => event.kind === 'approval.auto_approved').length,
        1,
        'strict policy must not add auto-approval audit rows',
      )
    })
  } finally {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  }
})
