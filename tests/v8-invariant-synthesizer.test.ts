/**
 * Unit tests for v8 M2 General Invariant Synthesizer (`src/server/invariant-synthesizer.ts`).
 *
 * Uses strictly synthetic domain fixtures (no benchmark literals, routes, or app names).
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, test } from 'node:test'

import {
  DEFAULT_SEMANTIC_BUDGET_FRACTION,
  ENTITY_LIFECYCLE_SLICE_MAX_BYTES,
  MAX_SEMANTIC_BUDGET_FRACTION,
  buildEntityLifecycleSlices,
  buildGuardAsymmetryMatrix,
  buildTrustBoundaryGraph,
  synthesizeInvariants,
  toCapabilityLedgerSeeds,
} from '../src/server/invariant-synthesizer.ts'
import type {
  CapabilityKind,
  CapabilitySurface,
  InvariantHypothesis,
  SourceFileInput,
} from '../src/server/invariant-synthesizer.ts'
import { extractProgramGraph } from '../src/server/program-graph.ts'
import type { ProgramGraph, ProgramRoute, ServiceOriginMapping } from '../src/server/program-graph.ts'

const VALID_CAPABILITY_KINDS = new Set<CapabilityKind>([
  'identity_session',
  'scoped_token',
  'signing_material',
  'signed_artifact_or_url',
  'opaque_object_ref',
  'state_handle',
  'write_sink_handle',
  'internal_reach_handle',
  'parser_or_cache_primitive',
  'policy_asymmetry',
])

const VALID_SURFACES = new Set<CapabilitySurface>([
  'http',
  'graphql',
  'ws',
  'sse',
  'browser',
  'webhook',
  'async_job',
  'idp',
  'cdn',
  'storage',
])

function makeRoute(overrides: Partial<ProgramRoute> & Pick<ProgramRoute, 'id' | 'method' | 'path' | 'file' | 'line' | 'handler'>): ProgramRoute {
  return {
    framework: 'express',
    input: { params: [], query: [], body: [], schemas: [] },
    middleware: [],
    guards: [],
    mountedFrom: [],
    extraction: 'ast',
    ...overrides,
  }
}

function assertValidHypothesisSchema(h: InvariantHypothesis): void {
  assert.ok(typeof h.id === 'string' && h.id.length > 0)
  assert.equal(h.promotionStatus, 'capability_only', `hypothesis ${h.id} must stay quarantined as capability_only`)
  assert.ok(VALID_CAPABILITY_KINDS.has(h.capabilityKind), `invalid capabilityKind: ${h.capabilityKind}`)
  assert.ok(VALID_SURFACES.has(h.surface), `invalid surface: ${h.surface}`)
  assert.ok(h.score >= 0 && h.score <= 1, `score out of range: ${h.score}`)
  assert.ok(h.summary.length > 0)
  assert.ok(h.verificationHint.length > 0)
  assert.ok(Array.isArray(h.preconditions))
  assert.ok(Array.isArray(h.evidence) && h.evidence.length > 0)
}

describe('Analyzer 1: Entity x Surface Guard-Asymmetry Matrix', () => {
  test('groups REST, batch, SSE, GraphQL, WS, and async worker handlers by entity and diffs all 4 guard dimensions', () => {
    const sourceFiles: SourceFileInput[] = [
      {
        path: 'services/api/src/orders.ts',
        content: [
          'export async function getOrder(req, res) {',
          '  verifyActiveSession(req.token)',
          '  return db.query("SELECT * FROM orders WHERE tenantId = $1 AND id = $2", [req.tenantId, req.params.id])',
          '}',
          'export async function batchOrders(req, res) {',
          '  const ids = req.body.ids',
          '  return db.query("SELECT * FROM orders WHERE id = ANY($1)", [ids])',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/stream/src/orders-sse.ts',
        content: [
          'export function streamOrders(req, res) {',
          '  res.setHeader("Content-Type", "text/event-stream")',
          '  return subscribeOrderUpdates(req.params.id)',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/graphql/src/resolvers.ts',
        content: [
          'export const resolvers = {',
          '  Query: {',
          '    order: async (parent, args, ctx) => {',
          '      return ctx.db.findOne("orders", { id: args.id })',
          '    },',
          '  },',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/worker/src/export-worker.ts',
        content: [
          'registerWorker("export:orders", async (job) => {',
          '  return db.findMany("orders", { id: job.orderId })',
          '})',
        ].join('\n'),
      },
    ]

    const graph: ProgramGraph = {
      filesScanned: sourceFiles.length,
      frameworks: ['express'],
      globalMiddleware: [],
      warnings: [],
      routes: [
        makeRoute({
          id: 'r_order_get',
          method: 'GET',
          path: '/api/v1/orders/:id',
          file: 'services/api/src/orders.ts',
          line: 1,
          handler: 'getOrder',
          guards: ['requireAuth', 'requireTenantScope', 'requireRole', 'checkRevokedToken'],
          middleware: ['requireAuth', 'requireTenantScope', 'requireRole', 'checkRevokedToken'],
        }),
        makeRoute({
          id: 'r_order_batch',
          method: 'POST',
          path: '/api/v1/orders/batch',
          file: 'services/api/src/orders.ts',
          line: 5,
          handler: 'batchOrders',
          input: { params: [], query: [], body: ['ids'], schemas: [] },
          guards: ['requireAuth'],
          middleware: ['requireAuth'],
        }),
        makeRoute({
          id: 'r_order_sse',
          method: 'GET',
          path: '/events/orders/:id',
          file: 'services/stream/src/orders-sse.ts',
          line: 1,
          handler: 'streamOrders',
          guards: ['requireAuth', 'requireTenantScope'],
          middleware: ['requireAuth', 'requireTenantScope'],
        }),
        // Uniformly guarded entity: should emit 0 asymmetries
        makeRoute({
          id: 'r_ticket_get',
          method: 'GET',
          path: '/api/v1/tickets/:id',
          file: 'services/api/src/tickets.ts',
          line: 1,
          handler: 'getTicket',
          guards: ['requireAuth', 'requireTenantScope', 'checkRevokedToken'],
        }),
        makeRoute({
          id: 'r_ticket_sse',
          method: 'GET',
          path: '/events/tickets/:id',
          file: 'services/api/src/tickets.ts',
          line: 10,
          handler: 'streamTickets',
          guards: ['requireAuth', 'requireTenantScope', 'checkRevokedToken'],
        }),
        // Public exempt route should be ignored
        makeRoute({
          id: 'r_health',
          method: 'GET',
          path: '/healthz',
          file: 'services/api/src/health.ts',
          line: 1,
          handler: 'health',
        }),
      ],
      nodes: [
        {
          id: 'n_sink_batch',
          kind: 'sink',
          symbol: 'db.query',
          file: 'services/api/src/orders.ts',
          line: 7,
          sinkKind: 'db_query',
          guards: [],
          calls: [],
        },
      ],
      edges: [
        { fromId: 'r_order_batch', toId: 'n_sink_batch', file: 'services/api/src/orders.ts', line: 7 },
      ],
    }

    const serviceOrigins: ServiceOriginMapping[] = [
      { service: 'api', root: 'services/api', origin: 'https://api.example.test', confidence: 'exact', evidence: [] },
      { service: 'stream', root: 'services/stream', origin: 'https://stream.example.test', confidence: 'exact', evidence: [] },
    ]

    const result = buildGuardAsymmetryMatrix(graph, { sourceFiles, serviceOrigins })
    assert.ok(result.stats.handlersAnalyzed >= 6)

    const orderEntry = result.matrix.find(e => e.entity === 'order')
    assert.ok(orderEntry, 'expected grouped "order" entity in matrix')
    assert.ok(orderEntry.surfaces.includes('http'))
    assert.ok(orderEntry.surfaces.includes('sse'))
    assert.ok(orderEntry.surfaces.includes('graphql'))
    assert.ok(orderEntry.surfaces.includes('async_job'))

    const ticketEntry = result.matrix.find(e => e.entity === 'ticket')
    assert.ok(ticketEntry)
    assert.equal(ticketEntry.diffs.length, 0, 'uniformly guarded entity must emit 0 diffs')

    // Verify SSE revocation asymmetry was caught
    const sseDiff = orderEntry.diffs.find(d => d.weakerHandler.surface === 'sse')
    assert.ok(sseDiff, 'expected SSE handler diff')
    assert.ok(sseDiff.missingDimensions.includes('revocation'))
    assert.equal(sseDiff.crossSurface, true)

    // Verify batch tenant/role/revocation asymmetry was caught
    const batchDiff = orderEntry.diffs.find(d => d.weakerHandler.isBatch)
    assert.ok(batchDiff, 'expected batch handler diff')
    assert.equal(batchDiff.batchVsSingle, true)
    assert.ok(batchDiff.missingDimensions.includes('tenant_scope'))

    // Verify GraphQL and async_job cross-surface asymmetries were caught
    assert.ok(result.hypotheses.some(h => h.entity === 'order' && h.surface === 'graphql' && h.kind === 'policy_asymmetry'))
    assert.ok(result.hypotheses.some(h => h.entity === 'order' && h.surface === 'async_job' && h.kind === 'policy_asymmetry'))

    for (const h of result.hypotheses) {
      assertValidHypothesisSchema(h)
      assert.equal(h.mode, 'white-box')
    }
    // Verify descending score sort
    for (let i = 1; i < result.hypotheses.length; i += 1) {
      assert.ok(result.hypotheses[i - 1].score >= result.hypotheses[i].score)
    }
  })

  test('integrates directly with real extractProgramGraph output', () => {
    const files: SourceFileInput[] = [
      {
        path: 'src/routes/documents.ts',
        content: [
          "import { Router } from 'express'",
          'export const router = Router()',
          "router.get('/api/documents/:id', requireAuth, requireTenantScope, checkRevokedSession, getDocument)",
          "router.get('/stream/documents/:id', requireAuth, streamDocument)",
          'function getDocument(req: any, res: any) { return res.json({ ok: true }) }',
          'function streamDocument(req: any, res: any) { return res.json({ ok: true }) }',
        ].join('\n'),
      },
    ]
    const graph = extractProgramGraph({ files })
    const res = buildGuardAsymmetryMatrix(graph, { sourceFiles: files })
    assert.ok(res.hypotheses.some(h => h.entity === 'document' && h.surface === 'sse'))
  })
})

describe('Analyzer 2: Cross-Service Trust-Boundary & Token/Header Propagation Graph', () => {
  test('maps multi-tier services and flags header forwarding, tenant fallback, body reparse, cache divergence, prefix normalization, and signing', () => {
    const sourceFiles: SourceFileInput[] = [
      {
        path: 'services/edge-gateway/src/proxy.ts',
        content: [
          'export async function handleProxy(req, res) {',
          '  const parsed = JSON.parse(req.rawBody)',
          '  if (parsed.amount > 1000) return res.status(400).end()',
          '  const prefix = req.path.startsWith("/v1/public") ? "/public" : "/api"',
          '  return forwardTo("http://core-api:8080" + prefix, {',
          '    headers: { "x-internal-actor": req.headers["x-internal-actor"], "x-workspace-id": req.headers["x-workspace-id"] || "default-org" },',
          '    body: req.rawBody,',
          '  })',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/cdn-edge/src/cache.ts',
        content: [
          'export function serveCachedProfile(req, res) {',
          '  res.setHeader("Cache-Control", "public, max-age=120")',
          '  cache.set(cacheKey(req.path), req.headers.authorization)',
          '  return res.send(cache.get(cacheKey(req.path)))',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/core-api/src/oauth.ts',
        content: [
          'export function authorizeRedirect(req, res) {',
          '  const redirect_uri = String(req.query.redirect_uri || "")',
          '  if (redirect_uri.startsWith("https://app.example.test")) {',
          '    return res.redirect(redirect_uri + "?code=abc")',
          '  }',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/job-worker/src/webhooks.ts',
        content: [
          'import { createHmac } from "node:crypto"',
          'export async function runWebhookJob(job) {',
          '  const sig = createHmac("sha256", job.secret).update(job.payload).digest("hex")',
          '  return dispatchWebhook("http://kms-internal:9000/deliver", { headers: { "x-signature": sig }, body: job.payload })',
          '}',
        ].join('\n'),
      },
    ]

    const graph: ProgramGraph = {
      filesScanned: sourceFiles.length,
      frameworks: ['express'],
      globalMiddleware: [],
      warnings: [],
      routes: [
        makeRoute({
          id: 'r_edge',
          method: 'POST',
          path: '/v1/payouts',
          file: 'services/edge-gateway/src/proxy.ts',
          line: 1,
          handler: 'handleProxy',
          mountedFrom: ['/edge', '/v1'],
          handlerFile: 'services/core-api/src/oauth.ts',
        }),
        makeRoute({
          id: 'r_oauth',
          method: 'GET',
          path: '/oauth/authorize',
          file: 'services/core-api/src/oauth.ts',
          line: 1,
          handler: 'authorizeRedirect',
        }),
      ],
      nodes: [],
      edges: [],
    }

    const res = buildTrustBoundaryGraph(graph, {
      sourceFiles,
      services: [
        { name: 'edge-gateway', root: 'services/edge-gateway' },
        { name: 'cdn-edge', root: 'services/cdn-edge' },
        { name: 'core-api', root: 'services/core-api' },
        { name: 'job-worker', root: 'services/job-worker' },
        { name: 'kms-internal', root: 'services/kms-internal' },
      ],
      serviceOrigins: [
        { service: 'edge-gateway', root: 'services/edge-gateway', origin: 'https://edge.example.test', confidence: 'exact', evidence: [] },
        { service: 'core-api', root: 'services/core-api', origin: 'https://api.example.test', confidence: 'exact', evidence: [] },
      ],
    })

    const tierBySvc = new Map(res.nodes.map(n => [n.serviceId, n.tier]))
    assert.equal(tierBySvc.get('edge-gateway'), 'edge_cdn')
    assert.equal(tierBySvc.get('cdn-edge'), 'edge_cdn')
    assert.equal(tierBySvc.get('core-api'), 'app_api')
    assert.equal(tierBySvc.get('job-worker'), 'async_worker')
    assert.equal(tierBySvc.get('kms-internal'), 'internal_service')

    const riskSet = new Set(res.findings.map(f => f.riskClass))
    assert.ok(riskSet.has('identity_header_forwarding'), 'should flag identity_header_forwarding')
    assert.ok(riskSet.has('tenant_scope_propagation'), 'should flag tenant_scope_propagation')
    assert.ok(riskSet.has('path_prefix_normalization'), 'should flag path_prefix_normalization')
    assert.ok(riskSet.has('body_reparse_differential'), 'should flag body_reparse_differential')
    assert.ok(riskSet.has('cache_key_divergence'), 'should flag cache_key_divergence')
    assert.ok(riskSet.has('cross_boundary_signing'), 'should flag cross_boundary_signing')

    assert.ok(res.hypotheses.length >= 6)
    for (const h of res.hypotheses) {
      assertValidHypothesisSchema(h)
      assert.equal(h.kind, 'trust_boundary_mismatch')
    }
  })
})

describe('Analyzer 3: Bounded Semantic Slice Builder (<= 1,600 B & <= 10% Budget Guard)', () => {
  test('extracts dependency-resolved lifecycle clusters, enforces <= 1,600 B hard cap, scrubs literals, and enforces <= 10% budget cap', () => {
    const hugePadding = 'const note = "' + 'äöü€'.repeat(600) + '"\n'
    const fakeSecret = 'sk_live_ABCDEF1234567890XYZ'
    const sourceFiles: SourceFileInput[] = [
      {
        path: 'services/billing/src/invoices.ts',
        content: [
          'export async function editInvoice(req, res) {',
          `  const debugKey = "${fakeSecret}"`,
          '  invoice.createdBy = req.user.id',
          '  invoice.status = "draft"',
          hugePadding,
          '  return saveInvoice(invoice)',
          '}',
          'export async function approveInvoice(req, res) {',
          '  if (invoice.createdBy === req.user.id) return res.status(403).end()',
          '  invoice.approvedBy = req.user.id',
          '  invoice.status = "approved"',
          '  return settleLedgerBalance(invoice.amount)',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/billing/src/ledger.ts',
        content: [
          'export function settleLedgerBalance(amount: number) {',
          '  wallet.balance -= amount',
          '  ledger.settlement += amount',
          '  return wallet.balance',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/deploy/src/releases.ts',
        content: [
          'export async function reopenRelease(req, res) {',
          '  release.status = "disputed"',
          '  return release',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/iam/src/invites.ts',
        content: [
          'export async function redeemInvite(req, res) {',
          '  invite.status = "pending"',
          '  invite.invitedBy = req.user.id',
          '  return invite',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/store/src/refunds.ts',
        content: [
          'export async function issueRefund(req, res) {',
          '  account.balance += req.body.refund',
          '  return account',
          '}',
        ].join('\n'),
      },
    ]

    const graph: ProgramGraph = {
      filesScanned: sourceFiles.length,
      frameworks: ['express'],
      globalMiddleware: [],
      warnings: [],
      routes: [
        makeRoute({ id: 'r_inv_edit', method: 'PATCH', path: '/api/invoices/:id', file: 'services/billing/src/invoices.ts', line: 1, handler: 'editInvoice' }),
        makeRoute({ id: 'r_inv_approve', method: 'POST', path: '/api/invoices/:id/approve', file: 'services/billing/src/invoices.ts', line: 8, handler: 'approveInvoice' }),
        makeRoute({ id: 'r_rel_reopen', method: 'POST', path: '/api/releases/:id/reopen', file: 'services/deploy/src/releases.ts', line: 1, handler: 'reopenRelease' }),
        makeRoute({ id: 'r_inv_redeem', method: 'POST', path: '/api/invites/:id/redeem', file: 'services/iam/src/invites.ts', line: 1, handler: 'redeemInvite' }),
        makeRoute({ id: 'r_ref_issue', method: 'POST', path: '/api/refunds', file: 'services/store/src/refunds.ts', line: 1, handler: 'issueRefund' }),
      ],
      nodes: [
        {
          id: 'fn_settle',
          kind: 'function',
          symbol: 'settleLedgerBalance',
          file: 'services/billing/src/ledger.ts',
          line: 1,
          guards: [],
          calls: [],
        },
      ],
      edges: [
        { fromId: 'r_inv_approve', toId: 'fn_settle', file: 'services/billing/src/invoices.ts', line: 12 },
      ],
    }

    // 1. Standard budget ($5.00 * 10% = $0.50 -> allows all 4 entity clusters)
    const full = buildEntityLifecycleSlices(graph, {
      sourceFiles,
      totalRunBudgetUsd: 5.0,
      maxBudgetFraction: DEFAULT_SEMANTIC_BUDGET_FRACTION,
    })

    assert.equal(full.slices.length, 4)
    assert.equal(full.budgetGuard.enforcedBudgetFraction, 0.10)
    assert.ok(full.budgetGuard.estimatedCostUsd <= full.budgetGuard.allocatedBudgetUsd)
    assert.equal(full.budgetGuard.truncatedByBudget, false)

    const invoiceSlice = full.slices.find(s => s.entity === 'invoice')
    assert.ok(invoiceSlice, 'expected invoice lifecycle cluster')
    assert.ok(invoiceSlice.patterns.includes('state_transition'))
    assert.ok(invoiceSlice.patterns.includes('creator_approver_mutation'))
    assert.ok(invoiceSlice.patterns.includes('numeric_balance_billing'))
    assert.ok(invoiceSlice.dependencies.some(d => d.symbol === 'settleLedgerBalance'), 'must resolve callee dependency')
    assert.equal(invoiceSlice.truncated, true, 'oversized slice must be truncated')
    assert.ok(!invoiceSlice.renderedSlice.includes(fakeSecret), 'secret literals must be scrubbed from slices')

    // Hard <= 1,600 B UTF-8 ceiling on every slice
    for (const s of full.slices) {
      const actualBytes = Buffer.byteLength(s.renderedSlice, 'utf8')
      assert.equal(s.byteLength, actualBytes)
      assert.ok(actualBytes <= ENTITY_LIFECYCLE_SLICE_MAX_BYTES, `slice exceeded 1600 B: ${actualBytes}`)
    }

    // 2. Strict budget guard clamping: requesting 0.50 fraction MUST clamp to 0.10
    const tight = buildEntityLifecycleSlices(graph, {
      sourceFiles,
      totalRunBudgetUsd: 0.50,
      maxBudgetFraction: 0.50, // Caller attempts to exceed 10%
      estimatedCostPerSliceUsd: 0.02,
    })
    assert.equal(tight.budgetGuard.enforcedBudgetFraction, MAX_SEMANTIC_BUDGET_FRACTION)
    assert.equal(tight.budgetGuard.allocatedBudgetUsd, 0.05)
    assert.equal(tight.slices.length, 2, 'budget of $0.05 at $0.02/slice must cap at 2 slices')
    assert.equal(tight.budgetGuard.slicesDropped, 2)
    assert.equal(tight.budgetGuard.truncatedByBudget, true)
    assert.ok(tight.budgetGuard.estimatedCostUsd <= 0.50 * 0.10 + 1e-9)

    // 3. Zero budget emits 0 slices
    const zero = buildEntityLifecycleSlices(graph, { sourceFiles, totalRunBudgetUsd: 0 })
    assert.equal(zero.slices.length, 0)
    assert.equal(zero.budgetGuard.estimatedCostUsd, 0)
  })
})

describe('Unified Orchestrator', () => {
  test('white-box synthesizeInvariants combines all 3 analyzers, compose boundaries, and WS handlers into unified quarantined CapabilitySeeds', () => {
    const sourceFiles: SourceFileInput[] = [
      {
        path: 'services/api/src/payouts.ts',
        content: [
          'export async function approvePayout(req, res) {',
          '  payout.approvedBy = req.user.id',
          '  account.balance -= payout.amount',
          '  return enqueueJob("http://worker-pool:9100/settle", { headers: { "x-forwarded-user": req.user.id }, body: payout })',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/realtime/src/ws.ts',
        content: [
          'wss.on("payout:watch", (msg) => {',
          '  return db.findOne("payouts", { id: msg.id })',
          '})',
        ].join('\n'),
      },
    ]
    const graph: ProgramGraph = {
      filesScanned: sourceFiles.length,
      frameworks: ['express'],
      globalMiddleware: [],
      warnings: [],
      routes: [
        makeRoute({
          id: 'r_pay_approve',
          method: 'POST',
          path: '/api/v1/payouts/:id/approve',
          file: 'services/api/src/payouts.ts',
          line: 1,
          handler: 'approvePayout',
          guards: ['requireAuth', 'requireTenantScope', 'requireRole', 'checkRevokedToken'],
        }),
      ],
      nodes: [],
      edges: [],
    }
    const compose = [
      'services:',
      '  api:',
      '    environment:',
      '      - WORKER_URL=http://worker-pool:9100',
      '  worker-pool:',
      '    ports: ["9100:9100"]',
    ].join('\n')

    const wb = synthesizeInvariants({
      mode: 'white-box',
      graph,
      sourceFiles,
      compose,
      services: [{ name: 'api', root: 'services/api' }, { name: 'worker-pool', root: 'services/worker' }],
      totalRunBudgetUsd: 5.0,
    })

    assert.ok(wb.guardMatrix && wb.guardMatrix.hypotheses.some(h => h.surface === 'ws' && h.entity === 'payout'))
    assert.ok(wb.trustBoundaries && wb.trustBoundaries.edges.some(e => e.toService === 'worker-pool'))
    assert.ok(wb.lifecycleSlices && wb.lifecycleSlices.slices.some(s => s.entity === 'payout'))
    assert.ok(wb.hypotheses.length >= 3)
    assert.equal(wb.capabilitySeeds.length, wb.hypotheses.length)
    for (const h of wb.hypotheses) assertValidHypothesisSchema(h)
    for (const seed of wb.capabilitySeeds) {
      assert.equal(seed.promotionStatus, 'capability_only')
      assert.match(seed.artifactDigest, /^[0-9a-f]{64}$/)
      assert.ok(seed.capId.startsWith('cap:synth_'))
    }
    assert.deepEqual(wb.capabilitySeeds, toCapabilityLedgerSeeds(wb.hypotheses))
  })

  test('grey-box and black-box modes emit zero hypotheses (no-source planning is owned by the World Graph planner)', () => {
    for (const mode of ['grey-box', 'black-box'] as const) {
      const result = synthesizeInvariants({ mode })
      assert.equal(result.mode, mode)
      assert.deepEqual(result.hypotheses, [])
      assert.deepEqual(result.capabilitySeeds, [])
    }
  })
})

describe('Hard v8 M2 Compliance Gates (LOC Ceiling & Zero Benchmark Literals)', () => {
  const synthPath = resolve(import.meta.dirname, '../src/server/invariant-synthesizer.ts')
  const source = readFileSync(synthPath, 'utf8')

  test('src/server/invariant-synthesizer.ts stays strictly <= 1,100 LOC', () => {
    const lineCount = source.split('\n').length
    assert.ok(lineCount <= 1100, `expected <= 1,100 LOC, got ${lineCount}`)
  })

  test('src/server/invariant-synthesizer.ts contains ZERO benchmark literals (Anti-Goodhart gate)', () => {
    const forbiddenPatterns: RegExp[] = [
      new RegExp(['pay', 'grid'].join(''), 'i'),
      new RegExp(['ship', 'forge'].join(''), 'i'),
      new RegExp(['nexus', 'iam'].join(''), 'i'),
      new RegExp(['connect', 'hub'].join(''), 'i'),
      new RegExp(['\\b(?:PG|SF|NX|CH)-', '[CD]\\d+\\b'].join(''), 'i'),
      new RegExp(['(?:vault|registry|billing)\\.', 'internal'].join(''), 'i'),
      new RegExp(['shop', 'flow'].join(''), 'i'),
      new RegExp(['ledger', 'flow'].join(''), 'i'),
      new RegExp(['forge', 'cloud'].join(''), 'i'),
      new RegExp(['ops', 'portal'].join(''), 'i'),
      new RegExp(['multihop', '-saas'].join(''), 'i'),
      new RegExp(['reason', '-bench'].join(''), 'i'),
      new RegExp(['held-out', '-saas'].join(''), 'i'),
      new RegExp(['mh_', 'fake_'].join(''), 'i'),
    ]
    for (const re of forbiddenPatterns) {
      assert.equal(re.test(source), false, `forbidden benchmark literal matched pattern ${re}`)
    }
  })
})
