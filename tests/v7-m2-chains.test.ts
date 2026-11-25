/**
 * v7 M2 — White-Box-First Program Analysis, Typed Multi-Round ChainHops & Mounted-Source Priority.
 *
 * Pure synthetic fixtures only (zero benchmark app/seed/site/token references):
 *   1. Interprocedural AST/dataflow slices with cross-file import disambiguation & inline route handlers.
 *   2. Middleware / RBAC policy diffing across sibling routes (`auth`, `admin`, `tenant`) + public-route exclusion.
 *   3. Repository-wide value-free secrets & IaC static leads (root/infra + module files, zero literal leakage).
 *   4. Typed multi-round `ChainHop` extraction, persistence, 4+ synthetic multi-step chain scenarios (2-4 hops),
 *      and bounded follow-on brief injection without prompt soup.
 *   5. White-box-first default when `sourceDir` / `mountedRepos` is mounted (black-box-first overrides deleted).
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import {
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  measureAssignmentBriefBytes,
} from '../src/server/assignment-brief.ts'
import {
  CODE_DATAFLOW_SLICE_MAX_BYTES,
  buildCodeDataflowSlice,
  deriveCodeToRuntimeHypotheses,
  diffMiddlewarePolicies,
  extractProgramGraph,
  extractStaticSecretsAndIacLeads,
} from '../src/server/program-graph.ts'
import {
  createGraphCoordinator,
  deriveChainPrimitives,
  extractChainHops,
  formatChainHopsBrief,
  planChainRound,
  type ChainHop,
  type CoordinatorEndpoint,
  type CoordinatorFact,
  type CoordinatorFinding,
} from '../src/server/graph-coordinator.ts'
import { codeToRuntimeLead } from '../src/server/graph-leads.ts'
import {
  DET_LEAD_CONCURRENT_CAP,
  TIER_A_MAX_SEEDED_STEPS,
  TIER_A_STEP_PRIORITY,
  WHITEBOX_BLACKBOX_CAP_PRIORITY,
  WHITEBOX_TIER_A_MAX_SEEDED_STEPS,
  chainHopFactPayload,
  chainHypothesisDispatchSteps,
  detLeadEvidenceGate,
  isWhiteBoxStep,
  planRoundRobinDispatch,
  prioritizeMountedSourceInitialSteps,
  readChainHopsFromFacts,
  selectUncoveredHighRiskEndpoints,
  type DispatchLaneStep,
} from '../src/server/exec-dispatch.ts'
import { ExecReconPlanner, type ExecReconPlannerHost } from '../src/server/exec-recon-planner.ts'
import { scoreAndBuildSuspects, type ProjectSecuritySpec } from '../src/server/semantic-audit.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { ProbePlanRegistry } from '../src/server/probe-plan.ts'
import { ReinvestigationGuard } from '../src/server/exec-dispatch.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const SYNTH_SECRET_JWT = 'super-synthetic-jwt-signing-material-do-not-echo-998877'
const SYNTH_SECRET_KEY = 'sk_live_SyntheticKeyMaterial9876543210'
const SYNTH_RAW_BEARER = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEiLCJyb2xlIjoiYWRtaW4ifQ.syntheticSignatureValue123456'

const MULTI_SERVICE_REPO: ReadonlyArray<{ path: string; content: string }> = [
  {
    path: 'services/gateway/src/app.ts',
    content: [
      "import { Router } from 'express'",
      "import { ordersRouter } from '../../orders/src/routes'",
      "import { payoutsRouter } from '../../payouts/src/routes'",
      'export const app = Router()',
      "app.use('/v1', ordersRouter)",
      "app.use('/v1', payoutsRouter)",
    ].join('\n'),
  },
  // Two modules BOTH define `findById` and `executeQuery` to test import-aware cross-file resolution.
  {
    path: 'services/orders/src/routes.ts',
    content: [
      "import { Router } from 'express'",
      "import { requireAuth, requireTenantScope } from './auth'",
      "import { getOrder, listOrders, exportOrder } from './controller'",
      "import { dispatchOrderWebhook } from './webhook-service'",
      'export const ordersRouter = Router()',
      "ordersRouter.get('/orders', requireAuth, requireTenantScope, listOrders)",
      "ordersRouter.get('/orders/:id', requireAuth, requireTenantScope, getOrder)",
      "ordersRouter.get('/orders/:id/export', requireAuth, exportOrder)",
      "ordersRouter.post('/orders/:id/notify', async (req: any, res: any) => {",
      '  const out = await dispatchOrderWebhook(req.params.id, req.body.callbackUrl)',
      '  res.json(out)',
      '})',
      "ordersRouter.get('/orders/healthz', (_req: any, res: any) => { res.json({ ok: true }) })",
    ].join('\n'),
  },
  {
    path: 'services/orders/src/controller.ts',
    content: [
      "import { loadOrder } from './service'",
      'export async function listOrders(_req: any, res: any) { res.json([]) }',
      'export async function getOrder(req: any, res: any) { res.json(await loadOrder(req.params.id)) }',
      'export async function exportOrder(req: any, res: any) { res.json(await loadOrder(req.params.id)) }',
    ].join('\n'),
  },
  {
    path: 'services/orders/src/service.ts',
    content: [
      "import { findById } from './repo'",
      'export async function loadOrder(id: string) { return findById(id) }',
    ].join('\n'),
  },
  {
    path: 'services/orders/src/repo.ts',
    content: [
      'export async function findById(id: string) {',
      "  return db.query('SELECT * FROM orders WHERE id = ' + id)",
      '}',
    ].join('\n'),
  },
  {
    path: 'services/orders/src/webhook-service.ts',
    content: [
      'export async function dispatchOrderWebhook(_id: string, callbackUrl: string) {',
      '  return fetch(callbackUrl)',
      '}',
    ].join('\n'),
  },
  {
    path: 'services/payouts/src/routes.ts',
    content: [
      "import { Router } from 'express'",
      "import { requireAdmin } from './admin-guard'",
      "import { approvePayout, listPayouts } from './controller'",
      'export const payoutsRouter = Router()',
      "payoutsRouter.get('/payouts', requireAdmin, listPayouts)",
      "payoutsRouter.post('/payouts/:id/approve', approvePayout)",
    ].join('\n'),
  },
  {
    path: 'services/payouts/src/controller.ts',
    content: [
      "import { findById } from './repo'",
      'export async function listPayouts(_req: any, res: any) { res.json([]) }',
      'export async function approvePayout(req: any, res: any) { res.json(await findById(req.params.id)) }',
    ].join('\n'),
  },
  {
    path: 'services/payouts/src/repo.ts',
    content: [
      'export async function findById(id: string) {',
      "  return db.execute('UPDATE payouts SET approved = 1 WHERE id = ' + id)",
      '}',
    ].join('\n'),
  },
  // Root/infra files outside any route module directory (secrets & IaC static leads).
  {
    path: 'infra/k8s/worker-deployment.yaml',
    content: [
      'apiVersion: apps/v1',
      'kind: Deployment',
      'spec:',
      '  template:',
      '    spec:',
      '      hostNetwork: true',
      '      containers:',
      '        - name: api',
      '          securityContext:',
      '            privileged: true',
      '            runAsUser: 0',
      '            capabilities:',
      '              add: ["CAP_SYS_ADMIN"]',
    ].join('\n'),
  },
  {
    path: 'infra/iam-policy.tf',
    content: [
      'resource "aws_iam_policy" "broad" {',
      '  policy = jsonencode({ Statement = [{ Effect = "Allow", "Action": "*", "Principal": "*" }] })',
      '}',
    ].join('\n'),
  },
  {
    path: 'config/.env.production',
    content: [
      `JWT_SECRET="${SYNTH_SECRET_JWT}"`,
      `BILLING_API_KEY=${SYNTH_SECRET_KEY}`,
      'NODE_TLS_REJECT_UNAUTHORIZED=0',
    ].join('\n'),
  },
]

describe('v7 M2: interprocedural AST/dataflow slices, RBAC diffing & static secrets/IaC', () => {
  test('import-aware interprocedural resolution disambiguates identically named helpers across services', () => {
    const graph = extractProgramGraph({ files: MULTI_SERVICE_REPO, repo: 'synth-monorepo' })

    const orderSlice = buildCodeDataflowSlice(graph, 'GET /v1/orders/:id/export', { files: MULTI_SERVICE_REPO })
    assert.ok(orderSlice, 'expected dataflow slice for GET /v1/orders/:id/export')
    assert.equal(orderSlice?.sink?.kind, 'db_query')
    assert.ok(orderSlice?.sink?.at.includes('orders/src/repo.ts') || orderSlice?.root?.includes('orders/src/'),
      `order sink must resolve into orders repo, got ${JSON.stringify(orderSlice)}`)
    assert.ok((orderSlice?.hops.length ?? 0) >= 4, `expected >= 4 hops, got ${orderSlice?.hops.length}`)
    assert.ok(Buffer.byteLength(JSON.stringify(orderSlice), 'utf8') <= CODE_DATAFLOW_SLICE_MAX_BYTES)

    const payoutSlice = buildCodeDataflowSlice(graph, 'POST /v1/payouts/:id/approve', { files: MULTI_SERVICE_REPO })
    assert.ok(payoutSlice, 'expected dataflow slice for POST /v1/payouts/:id/approve')
    assert.equal(payoutSlice?.sink?.kind, 'db_query')
    assert.ok(
      `${payoutSlice?.root ?? ''}${payoutSlice?.sink?.at ?? ''}`.includes('payouts/src/repo.ts'),
      `payout sink must resolve into payouts repo (not orders repo), got ${JSON.stringify(payoutSlice)}`,
    )
  })

  test('inline Express route handler joins the interprocedural call graph to outbound_fetch sink', () => {
    const graph = extractProgramGraph({ files: MULTI_SERVICE_REPO, repo: 'synth-monorepo' })
    const notifySlice = buildCodeDataflowSlice(graph, 'POST /v1/orders/:id/notify', { files: MULTI_SERVICE_REPO })
    assert.ok(notifySlice, 'expected dataflow slice for inline handler POST /v1/orders/:id/notify')
    assert.equal(notifySlice?.sink?.kind, 'outbound_fetch')
    assert.ok(
      `${notifySlice?.root ?? ''}${notifySlice?.sink?.at ?? ''}`.includes('webhook-service.ts'),
      `inline handler should trace to webhook-service.ts sink, got ${JSON.stringify(notifySlice)}`,
    )
  })

  test('diffMiddlewarePolicies identifies missing auth, tenant, and admin sibling guards while skipping public health routes', () => {
    const graph = extractProgramGraph({ files: MULTI_SERVICE_REPO, repo: 'synth-monorepo' })
    const diffs = diffMiddlewarePolicies(graph)

    const exportTenantDiff = diffs.find(d => d.path === '/v1/orders/:id/export' && d.missingFamily === 'tenant')
    assert.ok(exportTenantDiff, `expected tenant policy diff on /v1/orders/:id/export, got ${JSON.stringify(diffs)}`)
    assert.equal(exportTenantDiff?.siblingGuard, 'requireTenantScope')
    assert.equal(exportTenantDiff?.guardedSiblings, 2)

    const notifyAuthDiff = diffs.find(d => d.path === '/v1/orders/:id/notify' && d.missingFamily === 'auth')
    assert.ok(notifyAuthDiff, 'expected auth policy diff on unguarded POST /v1/orders/:id/notify')
    assert.equal(notifyAuthDiff?.siblingGuard, 'requireAuth')
    assert.equal(notifyAuthDiff?.guardedSiblings, 3)

    const payoutAdminDiff = diffs.find(d => d.path === '/v1/payouts/:id/approve' && d.missingFamily === 'admin')
    assert.ok(payoutAdminDiff, 'expected admin policy diff on POST /v1/payouts/:id/approve')
    assert.equal(payoutAdminDiff?.siblingGuard, 'requireAdmin')

    const healthAuthDiff = diffs.find(d => d.path === '/v1/orders/healthz' && d.missingFamily === 'auth')
    assert.equal(healthAuthDiff, undefined, 'public healthz route must not trigger auth policy diff')

    const hypotheses = deriveCodeToRuntimeHypotheses(graph)
    assert.ok(hypotheses.some(h => h.kind === 'middleware_policy_diff' && h.path === '/v1/orders/:id/export'))
    assert.ok(hypotheses.some(h => h.kind === 'middleware_policy_diff' && h.path === '/v1/payouts/:id/approve'))
  })

  test('extractStaticSecretsAndIacLeads surfaces root/infra secrets & IaC leads without leaking raw literals', () => {
    const graph = extractProgramGraph({ files: MULTI_SERVICE_REPO, repo: 'synth-monorepo' })
    const leads = extractStaticSecretsAndIacLeads(MULTI_SERVICE_REPO, graph.routes)

    assert.ok(leads.some(l => l.kind === 'secret' && l.file === 'config/.env.production' && /JWT\/signing/i.test(l.note)))
    assert.ok(leads.some(l => l.kind === 'secret' && l.file === 'config/.env.production' && /payment secret/i.test(l.note)))
    assert.ok(leads.some(l => l.kind === 'iac' && l.file === 'infra/k8s/worker-deployment.yaml' && /privileged|host network|root|SYS_ADMIN/i.test(l.note)))
    assert.ok(leads.some(l => l.kind === 'iac' && l.file === 'infra/iam-policy.tf' && /wildcard IAM/i.test(l.note)))
    assert.ok(leads.some(l => l.kind === 'iac' && l.file === 'config/.env.production' && /TLS certificate/i.test(l.note)))

    const serialized = JSON.stringify({ leads, staticLeads: graph.staticLeads, hypotheses: deriveCodeToRuntimeHypotheses(graph) })
    assert.ok(!serialized.includes(SYNTH_SECRET_JWT), 'JWT secret literal must never appear in leads/hypotheses')
    assert.ok(!serialized.includes(SYNTH_SECRET_KEY), 'API key literal must never appear in leads/hypotheses')

    // Wire into semantic-audit.ts scoreAndBuildSuspects
    const emptySpec: ProjectSecuritySpec = {
      repo: 'synth-monorepo',
      languages: ['typescript'],
      frameworks: ['express'],
      ormLibraries: [],
      authLibraries: [],
      sources: [],
      authTenantGuards: [],
      sanitizers: [],
      sinks: [],
      businessInvariants: [],
      generatedAt: Date.now(),
      usedLlm: false,
    }
    const suspects = scoreAndBuildSuspects({
      repo: 'synth-monorepo',
      approvedOrigins: ['https://app.synth.local'],
      spec: emptySpec,
      dynamicFindings: [],
      backwardPaths: [],
      programGraph: graph,
      liveEndpoints: [{ method: 'POST', path: '/v1/payouts/:id/approve' }],
    })
    assert.ok(suspects.some(s => s.routeOrAction === '/v1/payouts/:id/approve' && s.cwe === 'CWE-862'))
    assert.ok(suspects.some(s => s.file === 'config/.env.production' && s.cwe === 'CWE-798'))
    assert.ok(suspects.some(s => s.file === 'infra/k8s/worker-deployment.yaml' && s.cwe === 'CWE-250'))
    assert.ok(!JSON.stringify(suspects).includes(SYNTH_SECRET_JWT))
    assert.ok(!JSON.stringify(suspects).includes(SYNTH_SECRET_KEY))
  })
})

describe('v7 M2: typed multi-round ChainHop composition (5 synthetic multi-step scenarios)', () => {
  const ORIGIN_A = 'https://app.chain-synth.local'
  const ORIGIN_B = 'https://admin.chain-synth.local'

  test('Scenario 1 (4-hop same-origin): leaked_id -> workflow_state_handle -> role_transition -> admin_route', () => {
    const facts: CoordinatorFact[] = [
      {
        id: 'fact-id-1',
        origin: ORIGIN_A,
        kind: 'object_ref',
        summary: 'Discovered cross-tenant invoice handle',
        data: { subkind: 'persona_resource', roundNo: 1, resourceId: 'inv-9001', endpoint: '/api/invoices/inv-9001', method: 'GET', persona: 'member_a' },
      },
      {
        id: 'fact-wf-2',
        origin: ORIGIN_A,
        kind: 'note',
        summary: 'Pending payout approval state handle',
        data: { subkind: 'workflow_state_handle', roundNo: 2, workflowHandle: 'appr-442', endpoint: '/api/approvals/appr-442', method: 'POST', stateBefore: 'draft', stateAfter: 'pending_review', persona: 'member_a' },
      },
      {
        id: 'fact-role-3',
        origin: ORIGIN_A,
        kind: 'note',
        summary: 'Stale org-admin role transition persisted',
        data: { subkind: 'role_transition', roundNo: 2, roleBefore: 'viewer', roleAfter: 'approver', endpoint: '/api/memberships/invite', method: 'POST', persona: 'member_a', verified: true },
      },
    ]
    const endpoints: CoordinatorEndpoint[] = [
      { id: 'ep-admin-payout', origin: ORIGIN_A, method: 'POST', pathTemplate: '/api/admin/payouts/:id/release', roleExclusive: true },
    ]
    const hops = extractChainHops({ facts, endpoints, roundNo: 2 })
    assert.ok(hops.some(h => h.artifactKind === 'leaked_id' && h.artifactRef === 'inv-9001'))
    assert.ok(hops.some(h => h.artifactKind === 'workflow_state_handle' && h.stateBefore === 'draft' && h.stateAfter === 'pending_review'))
    assert.ok(hops.some(h => h.artifactKind === 'role_transition' && h.verified === true))

    const primitives = deriveChainPrimitives({ facts, endpoints })
    const planned = planChainRound({ primitives, endpoints, hops, maxHops: 4, limit: 20, approvedOrigins: [ORIGIN_A] })
    const fourHop = planned.find(h => h.hops === 4)
    assert.ok(fourHop, `expected a 4-hop chain hypothesis, got hops=${planned.map(p => p.hops).join(',')}`)
    assert.equal(fourHop?.chainHops?.length, 4)
    assert.ok(fourHop?.chainHops?.[1]?.parentHopId === fourHop?.chainHops?.[0]?.hopId, 'hops must link via parentHopId')
    assert.ok(fourHop?.capabilities.includes('race'), 'workflow_state_handle chains should advertise race capability')

    const briefJson = formatChainHopsBrief(fourHop!.chainHops!, 640)
    assert.ok(Buffer.byteLength(briefJson, 'utf8') <= 640)
    const parsedBrief = JSON.parse(briefJson) as Array<{ hop: number; kind: string; ref: string }>
    assert.equal(parsedBrief.length, 4)
  })

  test('Scenario 2 (3-hop cross-origin): token_ref + ssrf_redirect_target -> cross-origin admin_route (zero raw secret leak)', () => {
    const facts: CoordinatorFact[] = [
      {
        id: 'fact-secret-1',
        origin: ORIGIN_A,
        kind: 'secret',
        summary: 'Exposed bearer token handle',
        data: { subkind: 'leaked_token', roundNo: 1, token: SYNTH_RAW_BEARER, endpoint: '/api/debug/config', method: 'GET' },
      },
      {
        id: 'fact-ssrf-2',
        origin: ORIGIN_A,
        kind: 'note',
        summary: 'Open redirect / SSRF pivot to internal metadata',
        data: { subkind: 'open_redirect', roundNo: 1, redirectTarget: 'http://169.254.169.254/latest', endpoint: '/api/webhooks/preview', method: 'POST' },
      },
    ]
    const endpoints: CoordinatorEndpoint[] = [
      { id: 'ep-admin-b', origin: ORIGIN_B, method: 'POST', pathTemplate: '/admin/tokens/impersonate', roleExclusive: true },
    ]
    const hops = extractChainHops({ facts, endpoints, roundNo: 2 })
    const tokenHop = hops.find(h => h.artifactKind === 'token_ref')
    assert.ok(tokenHop, 'expected token_ref hop')
    assert.equal(tokenHop?.artifactRef, 'secret:fact-secret-1', 'token_ref must be an opaque secret:<factId> handle')

    const primitives = deriveChainPrimitives({ facts, endpoints })
    const planned = planChainRound({ primitives, endpoints, hops, maxHops: 3, limit: 15, approvedOrigins: [ORIGIN_A, ORIGIN_B] })
    const crossOrigin3 = planned.find(h => h.scope === 'cross_origin' && h.hops === 3)
    assert.ok(crossOrigin3, 'expected 3-hop cross-origin chain')
    assert.ok(crossOrigin3?.capabilities.includes('oob'))

    const dispatched = chainHypothesisDispatchSteps([crossOrigin3!])
    assert.equal(dispatched.length, 1)
    assert.ok(dispatched[0]!.hypothesis.includes('[chain_hops='), 'dispatched step must carry structured [chain_hops=...] block')
    assert.equal(dispatched[0]!.chainHops?.length, 3)
    const serialized = JSON.stringify({ hops, crossOrigin3, dispatched })
    assert.ok(!serialized.includes(SYNTH_RAW_BEARER), 'raw JWT/bearer credential must NEVER appear in ChainHop or dispatch text')
  })

  test('Scenario 3 (3-hop persisted round-trip): Round 1 hop persisted as fact feeds Round 2 & Round 3 composition', () => {
    const r1Hops = extractChainHops({
      facts: [{
        id: 'f-r1-stored',
        origin: ORIGIN_A,
        kind: 'note',
        summary: 'Second-order stored write resurfaced in admin console',
        data: { subkind: 'second_order_surface', roundNo: 1, marker: 'canary-77', endpoint: '/api/tickets', method: 'POST', persona: 'member_a' },
      }],
      roundNo: 1,
    })
    assert.equal(r1Hops.length, 1)
    const payload = chainHopFactPayload(r1Hops[0]!)
    const persistedR1Fact: CoordinatorFact = {
      id: 'fact-hop-r1',
      origin: ORIGIN_A,
      kind: 'note',
      summary: payload.summary,
      data: payload.data,
    }

    // Round 2 discovers a role transition and rehydrates Round 1 hop from persisted fact.
    const r2Facts: CoordinatorFact[] = [
      persistedR1Fact,
      {
        id: 'f-r2-role',
        origin: ORIGIN_A,
        kind: 'note',
        summary: 'Self-approval role transition granted org_admin',
        data: { subkind: 'self_approval', roundNo: 2, roleBefore: 'member', roleAfter: 'org_admin', endpoint: '/api/org/roles', method: 'PATCH', persona: 'member_a' },
      },
      {
        id: 'f-r2-id',
        origin: ORIGIN_A,
        kind: 'object_ref',
        summary: 'Cross-tenant secret ref id',
        data: { subkind: 'persona_resource', roundNo: 2, resourceId: 'sec-tenant-b-12', endpoint: '/api/secrets/sec-tenant-b-12', method: 'GET', persona: 'member_b' },
      },
    ]
    const rehydrated = readChainHopsFromFacts(r2Facts)
    assert.equal(rehydrated.length, 1)
    assert.equal(rehydrated[0]!.artifactKind, 'stored_write_handle')
    assert.equal(rehydrated[0]!.roundNo, 1)

    const allHops = extractChainHops({ facts: r2Facts, roundNo: 2 })
    assert.ok(allHops.some(h => h.artifactKind === 'stored_write_handle' && h.roundNo === 1))
    assert.ok(allHops.some(h => h.artifactKind === 'role_transition' && h.roundNo === 2))
    assert.ok(allHops.some(h => h.artifactKind === 'leaked_id' && h.artifactRef === 'sec-tenant-b-12'))

    const planned = planChainRound({
      primitives: deriveChainPrimitives({ facts: r2Facts }),
      hops: allHops,
      maxHops: 3,
      approvedOrigins: [ORIGIN_A],
    })
    const threeHop = planned.find(h => h.hops === 3)
    assert.ok(threeHop, 'expected 3-hop stored_write + leaked_id + role_transition chain across rounds')
    assert.ok(threeHop?.capabilities.includes('browser'))
  })

  test('Scenario 4 (confirmed finding escalation): weak_jwt finding + workflow handle + admin route compose deterministically', () => {
    const findings: CoordinatorFinding[] = [
      {
        id: 'find-jwt-1',
        origin: ORIGIN_A,
        title: 'Weak JWT signing secret allows token forgery',
        status: 'confirmed',
        severity: 'high',
        category: 'auth-identity',
        evidenceIds: ['ev-jwt-1'],
      },
    ]
    const facts: CoordinatorFact[] = [
      {
        id: 'f-wf-9',
        origin: ORIGIN_A,
        kind: 'note',
        summary: 'Staged deployment pipeline handle',
        data: { subkind: 'pipeline_run', roundNo: 1, workflowHandle: 'deploy-881', endpoint: '/api/pipelines/deploy-881/promote', method: 'POST', stateBefore: 'staged', stateAfter: 'prod' },
      },
    ]
    const endpoints: CoordinatorEndpoint[] = [
      { id: 'ep-admin-deploy', origin: ORIGIN_A, method: 'POST', pathTemplate: '/admin/deployments/:id/override', roleExclusive: true },
    ]
    const coordinator = createGraphCoordinator({
      deps: {
        listEndpoints: () => endpoints,
        listFacts: () => facts,
        listFindings: () => findings,
        approvedOrigins: () => [ORIGIN_A],
      },
      approvedOrigins: [ORIGIN_A],
    })
    const hops = coordinator.extractChainHops(2)
    assert.ok(hops.some(h => h.artifactKind === 'token_ref' && h.verified === true))
    assert.ok(hops.some(h => h.artifactKind === 'workflow_state_handle' && h.artifactRef === 'workflow:deploy-881'))
    const plannedA = coordinator.planChainRound({ maxHops: 3 })
    const plannedB = coordinator.planChainRound({ maxHops: 3 })
    assert.deepEqual(plannedA, plannedB, 'multi-round chain planning must be deterministic')
    assert.ok(plannedA.length >= 2)
  })

  test('Scenario 5 (Store + ExecReconPlanner integration): dispatchChainRound persists ChainHop facts & injects them into follow-on brief', async (t) => {
    const { storage } = makeStore(t, 'kovo-v7-m2-chain-')
    const setup = await setupApprovedRun(storage, { seeds: [ORIGIN_A], tier: 2 })
    const run = storage.run(setup.runId)
    const asset = run.candidates.find(c => c.origin === ORIGIN_A)!
    const worker = storage.makeWorker(run, 'investigation', asset, 'Round 1 worker', 'Initial probe', { sourceOrigins: [ORIGIN_A] })

    const f1 = storage.addFact(run, worker, {
      kind: 'object_ref',
      origin: ORIGIN_A,
      summary: 'Discovered tenant B transfer ID',
      data: { subkind: 'persona_resource', roundNo: 1, resourceId: 'xfer-b-701', endpoint: '/api/transfers/xfer-b-701', method: 'GET', persona: 'member_b' },
    })
    const f2 = storage.addFact(run, worker, {
      kind: 'note',
      origin: ORIGIN_A,
      summary: 'Pending transfer approval handle',
      data: { subkind: 'workflow_state_handle', roundNo: 1, workflowHandle: 'wf-701', endpoint: '/api/transfers/xfer-b-701/approve', method: 'POST', stateBefore: 'draft', stateAfter: 'pending', persona: 'member_a' },
    })
    const f3 = storage.addFact(run, worker, {
      kind: 'note',
      origin: ORIGIN_A,
      summary: 'Demoted reviewer retained approval privilege',
      data: { subkind: 'role_transition', roundNo: 2, roleBefore: 'reviewer', roleAfter: 'revoked_retained', endpoint: '/api/roles/reviewers', method: 'POST', persona: 'revoked_a', verified: true },
    })
    storage.upsertEndpoint({
      runId: run.id,
      scopeRevision: run.scopeRevision,
      origin: ORIGIN_A,
      method: 'POST',
      pathTemplate: '/admin/transfers/:id/release',
      source: 'repo_ast',
      authRequirement: 'admin',
      riskScore: 95,
    })

    const planner = makePlanner(storage, { mountedRepos: ['synth-repo'] })
    const coordinator = createGraphCoordinator({
      deps: planner.coordinatorDeps(run),
      approvedOrigins: [ORIGIN_A],
    })
    const enqueued = planner.dispatchChainRound(run, coordinator, 24, new Set([f1.id, f2.id, f3.id]))
    assert.ok(enqueued >= 1, `expected >= 1 chained step enqueued, got ${enqueued}`)

    // Re-running dispatchChainRound persists chain_hop facts idempotently (no duplicate chain_hop facts).
    const hopFactsBefore = storage.listFacts(run.id, { includeTainted: false, limit: 200 })
      .filter(f => f.data?.subkind === 'chain_hop')
    assert.ok(hopFactsBefore.length >= 3, `expected >= 3 persisted chain_hop facts, got ${hopFactsBefore.length}`)
    planner.dispatchChainRound(run, coordinator, 24, new Set([f1.id, f2.id, f3.id]))
    const hopFactsAfter = storage.listFacts(run.id, { includeTainted: false, limit: 200 })
      .filter(f => f.data?.subkind === 'chain_hop')
    assert.equal(hopFactsAfter.length, hopFactsBefore.length, 'chain_hop persistence must be idempotent by hopId')

    // Follow-on assignment brief receives typed ChainHop artifacts without prompt soup and <= 4 KB.
    const steps = storage.listChainSteps(run.id, run.goalRevision)
    const chainStep = steps.find(s =>
      s.hypothesis.includes('[chain_hops=')
      && (s.hypothesis.includes('xfer-b-701') || s.hypothesis.includes('wf-701')))
    assert.ok(chainStep, 'expected a dispatched multi-hop ChainStep carrying structured [chain_hops=...] metadata with discovered handles')
    const parentFacts = storage.listFacts(run.id, { includeTainted: false, limit: 200 })
      .filter(f => chainStep!.dependsOnFactIds.includes(f.id))
    assert.ok(parentFacts.some(f => f.data?.subkind === 'chain_hop'), 'follow-on step must link persisted chain_hop facts')

    const briefText = planner.assignmentBriefForStep({
      run,
      step: chainStep!,
      targetOrigins: [ORIGIN_A],
      personas: [
        { handle: 'member_a', roleLabel: 'member (org-a)' },
        { handle: 'member_b', roleLabel: 'member (org-b)' },
      ],
      parentFacts,
      confirmed: [],
      detLeads: [],
      maxTurns: 20,
    })
    assert.ok(briefText, 'expected rendered follow-on assignment brief')
    assert.ok(measureAssignmentBriefBytes(briefText!) <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
    const brief = JSON.parse(briefText!) as {
      mission: string
      linkedRoutes?: Array<{ path: string }>
      personas?: Array<{ handle: string; harvestedIds?: string[] }>
      proofObligation?: { chain?: string }
    }
    assert.equal(brief.mission, 'chain_step_2')
    assert.ok((brief.linkedRoutes?.length ?? 0) >= 1, 'hop endpoints must flow into linkedRoutes')
    assert.ok(
      brief.personas?.some(p => (p.harvestedIds ?? []).some(id => id.includes('xfer-b-701') || id.includes('wf-701'))),
      `hop handles must flow into personas.harvestedIds, got ${JSON.stringify(brief.personas)}`,
    )
    assert.ok(brief.proofObligation?.chain && brief.proofObligation.chain.includes('artifact') === false, 'compact typed hop JSON should live in proofObligation.chain')
  })
})

describe('v7 M2: white-box-first default when sourceDir / mountedRepos is mounted', () => {
  const ORIGIN = 'https://wb.synth.local'

  test('prioritizeMountedSourceInitialSteps removes black-box-first priority overrides when source is mounted', () => {
    const initial = [
      { title: 'Surface & chain investigation · wb.synth.local', hypothesis: 'Generic black-box crawl', priority: 95, skills: ['recon-modern-spa'] },
      { title: 'Source audit verify · /v1/payouts/:id/approve', hypothesis: 'RBAC policy diff missing requireAdmin', priority: 92, skills: ['source-first-audit'] },
      { title: 'Tier-A code lead · authz_matrix POST /v1/orders/:id/notify', hypothesis: 'A white-box dataflow slice proves outbound_fetch sink', priority: 90, skills: ['oob-ssrf-browser-chain'] },
    ]

    const mounted = prioritizeMountedSourceInitialSteps(initial, { sourceMounted: true, hasWhiteBoxSteps: true })
    assert.equal(mounted[0]!.title, 'Source audit verify · /v1/payouts/:id/approve')
    assert.equal(mounted[1]!.title, 'Tier-A code lead · authz_matrix POST /v1/orders/:id/notify')
    assert.equal(mounted[2]!.title, 'Surface & chain investigation · wb.synth.local')
    assert.ok(mounted[2]!.priority <= WHITEBOX_BLACKBOX_CAP_PRIORITY, `black-box step must be capped <= ${WHITEBOX_BLACKBOX_CAP_PRIORITY}, got ${mounted[2]!.priority}`)

    // Black-box mode (no mounted source) keeps original priority intact.
    const blackBox = prioritizeMountedSourceInitialSteps(initial, { sourceMounted: false })
    assert.equal(blackBox[0]!.priority, 95)
  })

  test('planRoundRobinDispatch schedules all white-box AST/RBAC/dataflow steps ahead of black-box steps when sourceMounted=true', () => {
    const mk = (id: string, seq: number, priority: number, title: string, skills: string[] = []): DispatchLaneStep => ({
      id, seq, priority, title, hypothesis: title, skills, sourceOrigins: [ORIGIN],
    })
    const steps: DispatchLaneStep[] = [
      mk('bb-1', 1, 95, 'Surface & chain investigation · wb.synth.local'),
      mk('bb-2', 2, 92, 'Cross-persona BOLA/IDOR matrix · resource:orders'),
      mk('wb-1', 3, 90, 'Tier-A code lead · authz_matrix GET /v1/orders/:id/export'),
      mk('wb-2', 4, 90, 'Tier-A code lead · ssrf_canary POST /v1/orders/:id/notify'),
      mk('wb-3', 5, 92, 'Source audit verify · /v1/payouts/:id/approve', ['source-first-audit']),
      mk('wb-4', 6, 88, 'Semantic audit · /v1/admin/tokens (auth.ts:44)', ['source-first-audit']),
    ]
    assert.ok(steps.filter(s => isWhiteBoxStep(s)).length === 4)

    // Even with 4 white-box steps (> DET_LEAD_CONCURRENT_CAP=2) and higher-priority black-box steps,
    // mounted-source dispatch fills the first 4 slots exclusively with white-box steps.
    const plan = planRoundRobinDispatch(steps, 5, {
      sourceMounted: true,
      leadCap: DET_LEAD_CONCURRENT_CAP,
    })
    assert.equal(plan.ordered.length, 5)
    assert.deepEqual(
      plan.ordered.slice(0, 4).map(s => s.id),
      ['wb-3', 'wb-1', 'wb-2', 'wb-4'],
      'all 4 white-box AST/RBAC/source-audit steps must dispatch strictly before generic black-box steps',
    )
    assert.ok(plan.ordered[4]!.id.startsWith('bb-'))
  })

  test('selectUncoveredHighRiskEndpoints prioritizes repo_ast & program_graph routes ahead of crawled routes when sourceMounted=true', () => {
    const endpoints = [
      { origin: ORIGIN, method: 'POST', pathTemplate: '/api/crawled/a', riskScore: 95, source: 'crawl' },
      { origin: ORIGIN, method: 'POST', pathTemplate: '/api/crawled/b', riskScore: 92, source: 'openapi' },
      { origin: ORIGIN, method: 'GET', pathTemplate: '/v1/orders/:id/export', riskScore: 75, source: 'repo_ast' },
      { origin: ORIGIN, method: 'POST', pathTemplate: '/v1/payouts/:id/approve', riskScore: 80, source: 'program_graph' },
    ]
    const selected = selectUncoveredHighRiskEndpoints({
      endpoints,
      approvedOrigins: new Set([ORIGIN]),
      confirmedPaths: new Set(),
      coveredRoutes: new Set(),
      limit: 3,
      sourceMounted: true,
    })
    assert.deepEqual(
      selected.map(e => e.pathTemplate),
      ['/v1/payouts/:id/approve', '/v1/orders/:id/export', '/api/crawled/a'],
    )
  })

  test('detLeadEvidenceGate admits program_graph RBAC policy diff and static secret/IaC leads', () => {
    assert.equal(detLeadEvidenceGate({ kind: 'det_lead', source: 'program_graph', policyDiff: true }).admitted, true)
    assert.equal(detLeadEvidenceGate({ kind: 'det_lead', source: 'program_graph', staticLeadKind: 'secret' }).admitted, true)
    assert.equal(detLeadEvidenceGate({ kind: 'det_lead', source: 'program_graph', staticLeadKind: 'iac' }).admitted, true)
    assert.equal(detLeadEvidenceGate({ kind: 'det_lead', source: 'program_graph' }).admitted, false)
  })

  test('queueTierALeadSteps seeds > legacy cap (up to WHITEBOX_TIER_A_MAX_SEEDED_STEPS) when source is mounted', async (t) => {
    const { storage } = makeStore(t, 'kovo-v7-m2-wb-')
    const setup = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
    const run = storage.run(setup.runId)
    const asset = run.candidates.find(c => c.origin === ORIGIN)!
    const worker = storage.makeWorker(run, 'threat_model', asset, 'Phase0', 'Program graph', { sourceOrigins: [ORIGIN] })

    const graph = extractProgramGraph({ files: MULTI_SERVICE_REPO, repo: 'synth-monorepo' })
    const sampleLead = codeToRuntimeLead(deriveCodeToRuntimeHypotheses(graph).find(h => h.kind === 'middleware_policy_diff')!)
    assert.equal(sampleLead.data.policyDiff, true)

    // Seed 10 distinct white-box Program-Graph leads (> TIER_A_MAX_SEEDED_STEPS=6).
    for (let i = 0; i < 10; i += 1) {
      storage.addFact(run, worker, {
        kind: 'note',
        origin: ORIGIN,
        summary: `Program-graph middleware_policy_diff on /v1/svc-${i}/action`,
        data: {
          kind: 'det_lead',
          source: 'program_graph',
          policyDiff: true,
          probeClass: 'authz_matrix',
          method: 'POST',
          endpoint: `/v1/svc-${i}/action`,
          reason: `missing tenant guard on /v1/svc-${i}/action`,
        },
      })
    }

    const planner = makePlanner(storage, { mountedRepos: ['synth-repo'] })
    const seeded = planner.queueTierALeadSteps(run, new Set([ORIGIN]), 40, { sourceMounted: true })
    assert.ok(seeded > TIER_A_MAX_SEEDED_STEPS, `mounted-source run must seed > ${TIER_A_MAX_SEEDED_STEPS} white-box leads, got ${seeded}`)
    assert.equal(seeded, 10)
    assert.ok(WHITEBOX_TIER_A_MAX_SEEDED_STEPS >= 16)
    const steps = storage.listChainSteps(run.id, run.goalRevision)
    assert.ok(steps.every(s => s.priority === TIER_A_STEP_PRIORITY))
  })
})

function makePlanner(
  storage: ReturnType<typeof makeStore>['storage'],
  opts: { mountedRepos?: string[] } = {},
): ExecReconPlanner {
  const tierAStepIds = new Set<string>()
  const tierAFactIds = new Set<string>()
  const host: ExecReconPlannerHost = {
    storage,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    browser: {} as ExecReconPlannerHost['browser'],
    canaryBroker: new CanaryBroker(),
    backend: {} as ExecReconPlannerHost['backend'],
    labRunner: {} as ExecReconPlannerHost['labRunner'],
    maxDurationMs: 0,
    active: new Map(),
    coordinator: new Map(),
    probePlans: new ProbePlanRegistry(),
    startedLabRuns: new Set(),
    startedLabHandles: new Map(),
    prePhase0SeededSteps: new Map(),
    plannerDoneRound: new Map(),
    dispatchFunnels: new Map(),
    detLeadConsumed: new Set(),
    tierAStepIds,
    tierAFactIds,
    approvedOriginsSet: run => new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin)),
    authorize: () => true,
    currentCoordinator: () => true,
    buildGrant: () => ({ grant: { personas: new Map() } as never, secrets: [], currentSecrets: () => [] }),
    projectReposMount: () => ({ mountedRepos: opts.mountedRepos ?? [] }),
    deterministicLaneKey: run => `${run.id}:${run.goalRevision}`,
    notifyCheckpoint: () => undefined,
    seedCodeToRuntimeLeads: () => 0,
    correlateSpecDependencies: async () => undefined,
    runSourceFirstCodeAudit: async () => ({ suspects: [], stepsCreated: [] }),
    baselineFinding: () => undefined,
    saveBaselineFinding: () => undefined,
    completeWorker: () => undefined,
    expandEligibleMultiTrialSteps: () => undefined,
    endpointGraphCatalog: () => ({ endpointParams: [], apiDependencies: [] }),
    noteDryStreak: () => undefined,
    reinvestigationGuardFor: () => new ReinvestigationGuard(),
    highPriorityQueueEmpty: () => false,
    noteCappedReinvestigation: () => undefined,
    recordDispatchFunnel: () => undefined,
    noteStrandedReadySteps: () => undefined,
    tracePlannerDecision: () => undefined,
    codeSliceForAssignment: () => undefined,
    shouldCoordinatorAnswer: () => false,
    resetBoardHops: () => undefined,
  }
  return new ExecReconPlanner(host)
}
