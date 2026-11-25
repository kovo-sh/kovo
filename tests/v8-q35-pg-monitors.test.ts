// Queue #35 regression: PayGrid monitor per-entity Map/Set state tracking and scope-aware
// control matching (both forward and retroactive, without ever fabricating controls).
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createChainOracle, sha256 as digest } from '../benchmarks/multihop-saas/lib/chain-oracle.ts'
import { generateDomainVariant } from '../benchmarks/multihop-saas/lib/domain-variant.ts'
import type { AuditEvent, Detail, PersonaKey } from '../benchmarks/multihop-saas/apps/paygrid/src/shared.ts'
import { CHAINS, TWINS } from '../benchmarks/multihop-saas/apps/paygrid/truth/blueprint.ts'
import { createPaygridMonitor } from '../benchmarks/multihop-saas/apps/paygrid/truth/monitors.ts'
import { startPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import { createSolverContext } from '../benchmarks/multihop-saas/apps/paygrid/solvers/index.ts'

function setupMonitor() {
  const runId = 'mh_run_q35_test'
  const plan = generateDomainVariant('paygrid', 42)
  const oracle = createChainOracle({ runId, specs: CHAINS, twins: TWINS })
  const monitor = createPaygridMonitor(oracle, plan, runId)
  let seq = 0
  let ts = 1_700_000_000_000

  const emit = (kind: string, detail: Detail, actorPersona?: PersonaKey): void => {
    ts += 10
    const event: AuditEvent = {
      seq: seq++,
      ts,
      kind,
      runId,
      actorPersona,
      detail: { runId, ...detail },
    }
    monitor.consume(event)
  }

  return { oracle, plan, runId, emit }
}

function confirmChain(oracle: ReturnType<typeof createChainOracle>, chainId: string) {
  const receipt = oracle.mintReceipt(chainId)
  assert.equal(oracle.verifyReceipt(receipt).ok, true)
  const evaluation = oracle.evaluate(chainId)
  assert.equal(evaluation.completed, true, evaluation.failureReason ?? 'incomplete')
  assert.equal(evaluation.confirmed, true, evaluation.failureReason ?? 'unconfirmed')
  return evaluation
}

// ---- Bug 1: Interleaved dual-run workflows (no single-scalar state overwrite) ----

test('PG-C1: interleaved dual-run workflows preserve per-entity state and exact digests', () => {
  const { oracle, plan, emit } = setupMonitor()
  const p1 = digest('fin1@org-a.test')
  const p2 = digest('fin2@org-a.test')
  const s1 = digest('sess_1')
  const s2 = digest('sess_2')

  emit('directory.public_view', { tenantId: 'org_a', slug: plan.tenants.a.slug, pendingEmailDigest: p1 }, 'member_b')
  emit('directory.public_view', { tenantId: 'org_a', slug: plan.tenants.a.slug, pendingEmailDigest: p2 }, 'member_b')

  emit('invite.resolved', { viaNfkc: true, tenantId: 'org_a', role: 'finance', pendingEmailDigest: p1, sessionDigest: s1, inviteId: 'inv_1' }, 'member_b')
  emit('invite.resolved', { viaNfkc: true, tenantId: 'org_a', role: 'finance', pendingEmailDigest: p2, sessionDigest: s2, inviteId: 'inv_2' }, 'member_b')

  emit('payout.rebound', { payoutId: 'po_1', tenantId: 'org_a', sessionDigest: s1 }, 'member_b')
  emit('payout.rebound', { payoutId: 'po_2', tenantId: 'org_a', sessionDigest: s2 }, 'member_b')

  // Control observed on a sibling payout in org_a by unprivileged member_a
  emit('payout.approve_denied', { payoutId: 'po_sibling', tenantId: 'org_a', reason: 'insufficient_role' }, 'member_a')

  // Cross-session settle attempt (s2 settling po_1 rebound only by s1) must be ignored
  emit('payout.settled', { payoutId: 'po_1', tenantId: 'org_a', sessionDigest: s2, makerCheckerBypassed: true }, 'member_b')
  assert.equal(oracle.events().terminals.length, 0)

  // First workflow completes AFTER second workflow created h1..h3 (would have been clobbered by scalar state)
  emit('payout.settled', { payoutId: 'po_1', tenantId: 'org_a', sessionDigest: s1, makerCheckerBypassed: true }, 'member_b')
  confirmChain(oracle, 'PG-C1')

  // Second workflow also completes cleanly
  emit('payout.settled', { payoutId: 'po_2', tenantId: 'org_a', sessionDigest: s2, makerCheckerBypassed: true }, 'member_b')
  const events = oracle.events()
  assert.equal(events.terminals.filter((t) => t.chainId === 'PG-C1').length, 2)
  assert.deepEqual(
    events.controls.filter((c) => c.chainId === 'PG-C1').map((c) => c.entityId).sort(),
    ['po_1', 'po_2'],
  )
})

test('PG-C2: interleaved dual-run workflows preserve per-template, per-job and per-salt digests', () => {
  const { oracle, emit } = setupMonitor()
  const sec1 = 'mh_fake_salt_one'
  const sec2 = 'mh_fake_salt_two'

  emit('template.updated', { rawStored: true, tenantId: 'org_a', templateId: 'tpl_1' }, 'member_a')
  emit('template.updated', { rawStored: true, tenantId: 'org_a', templateId: 'tpl_2' }, 'member_a')

  emit('worker.job_created', { kind: 'pdf', templateId: 'tpl_1', jobId: 'job_1' }, 'member_a')
  emit('worker.job_created', { kind: 'pdf', templateId: 'tpl_2', jobId: 'job_2' }, 'member_a')

  emit('worker.job_trace', { jobId: 'job_1', leakedSecret: sec1 }, 'member_a')
  emit('worker.job_trace', { jobId: 'job_2', leakedSecret: sec2 }, 'member_a')

  // First workflow completes webhook AFTER second workflow updated template/job/trace
  emit('vault.webhook_accepted', { derivedFromDigest: digest(sec1) }, 'member_a')
  confirmChain(oracle, 'PG-C2')

  // Second workflow also completes
  emit('vault.webhook_accepted', { derivedFromDigest: digest(sec2) }, 'member_a')
  const events = oracle.events()
  assert.equal(events.terminals.filter((t) => t.chainId === 'PG-C2').length, 2)
  const h3ToH4 = events.edges.filter((e) => e.chainId === 'PG-C2' && e.fromHopId === 'pg-c2-h3' && e.toHopId === 'pg-c2-h4')
  assert.deepEqual(h3ToH4.map((e) => e.derivedFromDigest), [digest(sec1), digest(sec2)])
})

test('PG-C3: interleaved dual-run workflows track multiple cacheKeys, jobs and signed URL handles', () => {
  const { oracle, plan, emit } = setupMonitor()
  const h1 = digest('job_exp_1:handle')
  const h2 = digest('job_exp_2:handle')

  emit('export.denied', { tenantId: 'org_b', cacheKey: 'perm:control_key', reason: 'insufficient_role' }, 'dual_member')

  emit('permission.cache_primed', { scoped: false, tenantId: 'org_a', cacheKey: 'perm:key_1' }, 'dual_member')
  emit('permission.cache_primed', { scoped: false, tenantId: 'org_a', cacheKey: 'perm:key_2' }, 'dual_member')

  emit('export.job_created', { viaCache: true, tenantId: 'org_b', cacheKey: 'perm:key_1', jobId: 'job_exp_1' }, 'dual_member')
  emit('export.job_created', { viaCache: true, tenantId: 'org_b', cacheKey: 'perm:key_2', jobId: 'job_exp_2' }, 'dual_member')

  emit('worker.job_polled', { kind: 'export', status: 'ready', jobId: 'job_exp_1' }, 'dual_member')
  // Duplicate poll on job_exp_1 is deduplicated, while job_exp_2 is still allowed to poll ready
  emit('worker.job_polled', { kind: 'export', status: 'ready', jobId: 'job_exp_1' }, 'dual_member')
  emit('worker.job_polled', { kind: 'export', status: 'ready', jobId: 'job_exp_2' }, 'dual_member')

  emit('export.signed_url', { jobId: 'job_exp_1', urlHandleDigest: h1 }, 'dual_member')
  emit('export.signed_url', { jobId: 'job_exp_2', urlHandleDigest: h2 }, 'dual_member')

  // First workflow downloads AFTER second workflow progressed through h1..h4
  emit('file.downloaded', {
    tenantSlug: plan.tenants.c.slug, signedTenant: plan.tenants.b.slug,
    urlHandleDigest: h1, path: `/files/export/${plan.tenants.c.slug}/treasury.csv`,
  }, 'dual_member')
  confirmChain(oracle, 'PG-C3')

  // Second workflow also downloads
  emit('file.downloaded', {
    tenantSlug: plan.tenants.c.slug, signedTenant: plan.tenants.b.slug,
    urlHandleDigest: h2, path: `/files/export/${plan.tenants.c.slug}/treasury.csv`,
  }, 'dual_member')
  const events = oracle.events()
  assert.equal(events.hops.filter((h) => h.hopId === 'pg-c3-h3').length, 2)
  assert.equal(events.terminals.filter((t) => t.chainId === 'PG-C3').length, 2)
})

test('PG-C4: interleaved dual-run workflows keep per-order state and per-order h3 deduplication', () => {
  const { oracle, emit } = setupMonitor()

  emit('settlement.control_denied', { orderId: 'ord_ctrl', tenantId: 'org_a', reason: 'state_not_authorized' }, 'member_a')

  emit('order.draft_created', { orderId: 'ord_1', tenantId: 'org_a', duplicateKey: true, amountCents: 9000, capCents: 5000, edgeAmount: 100 }, 'member_a')
  emit('order.draft_created', { orderId: 'ord_2', tenantId: 'org_a', duplicateKey: true, amountCents: 9500, capCents: 5000, edgeAmount: 100 }, 'member_a')

  emit('order.rebound', { orderId: 'ord_1', tenantId: 'org_a', status: 'authorized' }, 'member_a')
  emit('order.rebound', { orderId: 'ord_2', tenantId: 'org_a', status: 'authorized' }, 'member_a')

  // First order completes race AFTER second order was created and rebound
  emit('settlement.race', { orderId: 'ord_1', tenantId: 'org_a', credits: 2 }, 'member_a')
  // Duplicate race event for ord_1 (credits=3) is ignored
  emit('settlement.race', { orderId: 'ord_1', tenantId: 'org_a', credits: 3 }, 'member_a')
  confirmChain(oracle, 'PG-C4')

  // Second order can still complete race independently
  emit('settlement.race', { orderId: 'ord_2', tenantId: 'org_a', credits: 2 }, 'member_a')
  const events = oracle.events()
  assert.equal(events.hops.filter((h) => h.hopId === 'pg-c4-h3').length, 2)
  assert.equal(events.terminals.filter((t) => t.chainId === 'PG-C4').length, 2)
  assert.deepEqual(
    events.controls.filter((c) => c.chainId === 'PG-C4').map((c) => c.entityId).sort(),
    ['ord_1', 'ord_2'],
  )
})

// ---- Bug 2: Scope-aware control matching (before, retroactive after, dedupe, and rejection) ----

function runC1Chain(emit: ReturnType<typeof setupMonitor>['emit'], slug: string, payoutId: string) {
  const pending = digest(`pending:${payoutId}`)
  const session = digest(`sess:${payoutId}`)
  emit('directory.public_view', { tenantId: 'org_a', slug, pendingEmailDigest: pending }, 'member_b')
  emit('invite.resolved', { viaNfkc: true, tenantId: 'org_a', role: 'finance', pendingEmailDigest: pending, sessionDigest: session, inviteId: 'inv_1' }, 'member_b')
  emit('payout.rebound', { payoutId, tenantId: 'org_a', sessionDigest: session }, 'member_b')
  emit('payout.settled', { payoutId, tenantId: 'org_a', sessionDigest: session, makerCheckerBypassed: true }, 'member_b')
}

test('PG-C1 controls: retroactive sibling denial confirms, dedupes, and missing/wrong-scope denies', () => {
  // Retroactive sibling control (arrives AFTER payout.settled)
  const retro = setupMonitor()
  runC1Chain(retro.emit, retro.plan.tenants.a.slug, 'po_target')
  const before = retro.oracle.evaluate('PG-C1')
  assert.equal(before.completed, false)
  assert.equal(before.dropReason, 'edge_binding_rejected')
  assert.match(before.failureReason ?? '', /ablation control/)

  retro.emit('payout.approve_denied', { payoutId: 'po_sibling', tenantId: 'org_a', reason: 'insufficient_role' }, 'member_a')
  // Duplicate denied event must not emit duplicate ControlObservation
  retro.emit('payout.approve_denied', { payoutId: 'po_sibling_2', tenantId: 'org_a', reason: 'insufficient_role' }, 'viewer_a')
  confirmChain(retro.oracle, 'PG-C1')
  assert.equal(retro.oracle.events().controls.filter((c) => c.chainId === 'PG-C1').length, 1)

  // Missing control / wrong reason / wrong tenant must NOT fabricate control
  const missing = setupMonitor()
  missing.emit('payout.approve_denied', { payoutId: 'po_sibling', tenantId: 'org_a', reason: 'maker_checker' }, 'owner_a')
  missing.emit('payout.approve_denied', { payoutId: 'po_other_org', tenantId: 'org_b', reason: 'insufficient_role' }, 'member_b')
  runC1Chain(missing.emit, missing.plan.tenants.a.slug, 'po_target')
  const evalMissing = missing.oracle.evaluate('PG-C1')
  assert.equal(evalMissing.completed, false)
  assert.equal(evalMissing.confirmed, false)
  assert.equal(missing.oracle.events().controls.length, 0)
})

function runC3Chain(
  emit: ReturnType<typeof setupMonitor>['emit'],
  plan: ReturnType<typeof setupMonitor>['plan'],
  cacheKey: string,
  jobId: string,
) {
  const handle = digest(`${jobId}:handle`)
  emit('permission.cache_primed', { scoped: false, tenantId: 'org_a', cacheKey }, 'dual_member')
  emit('export.job_created', { viaCache: true, tenantId: 'org_b', cacheKey, jobId }, 'dual_member')
  emit('worker.job_polled', { kind: 'export', status: 'ready', jobId }, 'dual_member')
  emit('export.signed_url', { jobId, urlHandleDigest: handle }, 'dual_member')
  emit('file.downloaded', {
    tenantSlug: plan.tenants.c.slug, signedTenant: plan.tenants.b.slug,
    urlHandleDigest: handle, path: `/files/export/${plan.tenants.c.slug}/treasury.csv`,
  }, 'dual_member')
}

test('PG-C3 controls: retroactive org_b+actor denial confirms, dedupes, and missing/wrong-scope denies', () => {
  // Retroactive sibling cacheKey denial on org_b by same actor
  const retro = setupMonitor()
  runC3Chain(retro.emit, retro.plan, 'perm:user_1', 'job_c3_1')
  const before = retro.oracle.evaluate('PG-C3')
  assert.equal(before.completed, false)
  assert.equal(before.dropReason, 'edge_binding_rejected')
  assert.match(before.failureReason ?? '', /ablation control/)

  retro.emit('export.denied', { tenantId: 'org_b', cacheKey: 'perm:other_key', reason: 'insufficient_role' }, 'dual_member')
  retro.emit('export.denied', { tenantId: 'org_b', cacheKey: 'perm:user_1', reason: 'insufficient_role' }, 'dual_member')
  confirmChain(retro.oracle, 'PG-C3')
  assert.equal(retro.oracle.events().controls.filter((c) => c.chainId === 'PG-C3').length, 1)

  // Missing control / wrong tenant / wrong actor+key must NOT confirm
  const missing = setupMonitor()
  missing.emit('export.denied', { tenantId: 'org_a', cacheKey: 'perm:user_1', reason: 'insufficient_role' }, 'dual_member')
  missing.emit('export.denied', { tenantId: 'org_b', cacheKey: 'perm:other_key', reason: 'insufficient_role' }, 'member_a')
  runC3Chain(missing.emit, missing.plan, 'perm:user_1', 'job_c3_1')
  const evalMissing = missing.oracle.evaluate('PG-C3')
  assert.equal(evalMissing.completed, false)
  assert.equal(evalMissing.confirmed, false)
  assert.equal(missing.oracle.events().controls.length, 0)
})

function runC4Chain(emit: ReturnType<typeof setupMonitor>['emit'], orderId: string) {
  emit('order.draft_created', { orderId, tenantId: 'org_a', duplicateKey: true, amountCents: 9000, capCents: 5000, edgeAmount: 100 }, 'member_a')
  emit('order.rebound', { orderId, tenantId: 'org_a', status: 'authorized' }, 'member_a')
  emit('settlement.race', { orderId, tenantId: 'org_a', credits: 2 }, 'member_a')
}

test('PG-C4 controls: retroactive tenant+actor denial confirms, dedupes, and missing/wrong-scope denies', () => {
  // Retroactive sibling order denial in org_a by member_a
  const retro = setupMonitor()
  runC4Chain(retro.emit, 'ord_exploit')
  const before = retro.oracle.evaluate('PG-C4')
  assert.equal(before.completed, false)
  assert.equal(before.dropReason, 'edge_binding_rejected')
  assert.match(before.failureReason ?? '', /ablation control/)

  retro.emit('settlement.control_denied', { orderId: 'ord_sibling', tenantId: 'org_a', reason: 'state_not_authorized' }, 'member_a')
  retro.emit('settlement.control_denied', { orderId: 'ord_sibling_2', tenantId: 'org_a', reason: 'state_not_authorized' }, 'member_a')
  confirmChain(retro.oracle, 'PG-C4')
  assert.equal(retro.oracle.events().controls.filter((c) => c.chainId === 'PG-C4').length, 1)

  // Missing control / wrong actor / wrong tenant / wrong reason must NOT confirm
  const missing = setupMonitor()
  missing.emit('settlement.control_denied', { orderId: 'ord_sibling', tenantId: 'org_a', reason: 'state_not_authorized' }, 'owner_a')
  missing.emit('settlement.control_denied', { orderId: 'ord_sibling', tenantId: 'org_b', reason: 'state_not_authorized' }, 'member_a')
  missing.emit('settlement.control_denied', { orderId: 'ord_sibling', tenantId: 'org_a', reason: 'other_reason' }, 'member_a')
  runC4Chain(missing.emit, 'ord_exploit')
  const evalMissing = missing.oracle.evaluate('PG-C4')
  assert.equal(evalMissing.completed, false)
  assert.equal(evalMissing.confirmed, false)
  assert.equal(missing.oracle.events().controls.length, 0)
})

test('live paygrid: interleaved PG-C4 orders with retroactive sibling control confirm cleanly', async () => {
  const lab = await startPaygrid({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
  try {
    const ctx = createSolverContext(lab)
    const prefix = lab.plan.routePrefix
    const member = await ctx.login('member_a')
    const inflated = lab.plan.economics.payoutCapCents + lab.plan.economics.orderAmountCents
    const dupBody = `{"amountCents":${inflated},"beneficiary":"acct_vendor_1","amountCents":100}`

    // Create two interleaved over-cap orders before rebinding/racing the first
    const o1 = (await ctx.http('edge', `${prefix}/orders`, { method: 'POST', token: member, rawBody: dupBody }))
      .json<{ order: { id: string } }>().order.id
    const o2 = (await ctx.http('edge', `${prefix}/orders`, { method: 'POST', token: member, rawBody: dupBody }))
      .json<{ order: { id: string } }>().order.id

    assert.equal((await ctx.http('api', `${prefix}/orders/${o1}/rebind`, { method: 'PATCH', token: member, body: { beneficiary: 'acct_1' } })).status, 200)
    assert.equal((await ctx.http('api', `${prefix}/orders/${o2}/rebind`, { method: 'PATCH', token: member, body: { beneficiary: 'acct_2' } })).status, 200)

    await Promise.all([
      ctx.http('api', `${prefix}/orders/${o1}/settle-race`, { method: 'POST', token: member }),
      ctx.http('api', `${prefix}/orders/${o1}/settle-race`, { method: 'POST', token: member }),
    ])

    // Without any control denial yet, ChainOracle must reject PG-C4
    assert.equal(lab.oracle.evaluate('PG-C4').completed, false)

    // Now create a sibling draft order and observe genuine state_not_authorized denial AFTER the race
    const sibling = (await ctx.http('api', `${prefix}/orders`, {
      method: 'POST', token: member, body: { amountCents: 100, beneficiary: 'acct_vendor_1' },
    })).json<{ order: { id: string } }>().order.id
    const denied = await ctx.http('api', `${prefix}/orders/${sibling}/settle-race`, { method: 'POST', token: member })
    assert.equal(denied.status, 409)

    // Retroactive scoped control now lets PG-C4 confirm cleanly
    const receipt = await ctx.confirm('PG-C4')
    assert.ok(receipt, 'expected PG-C4 receipt after retroactive sibling control')
    assert.equal(lab.oracle.evaluate('PG-C4').confirmed, true)
  } finally {
    await lab.stop()
  }
})
