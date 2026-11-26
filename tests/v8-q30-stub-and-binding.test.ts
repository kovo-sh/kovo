/**
 * Queue #30 — verification soundness fixes:
 *  1. `isJobOrHandleStub` classifies async export/job/render/report/task creation and job-status
 *     metadata envelopes (incl. boolean flags, *Id/*At/*Key/*Slug scalars, job-collection routes)
 *     as intermediate stubs, so a job-status readback can never promote a benign job creation.
 *     Real business mutations and downloaded data payloads stay non-stub.
 *  2. `state_transition_binding` accepts unlabeled clean-session denied ablations that ran before
 *     Hop i or targeted a host-bound untouched sibling entity, never 2xx/dirty/mutated ones, and
 *     emits exact diagnostics on failure.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import '../src/server/terminal-oracle-registry.ts'
import { verifyCompositeReceipt } from '../src/server/composite-receipt.ts'
import type { CompositeProofReceipt, HostSignedTranscript, HostTranscriptEntry } from '../src/server/composite-receipt.ts'
import type { ImpactStep } from '../src/server/proof-receipt.ts'
import { isJobOrHandleStub } from '../src/server/v8-oracle-families.ts'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN = 'https://api.example.test'

function step(p: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return { actor: { handle: 'member_a', role: 'member', tenant: 'org-a', auth: 'bearer', sameSite: null }, ...p } as ImpactStep
}
function entry(exchangeId: string, s: ImpactStep, extra: Partial<HostTranscriptEntry> = {}): HostTranscriptEntry {
  return { exchangeId, step: s, timestampMs: 1_700_000_000_000, actorPersona: s.actor.handle, cleanSession: true, ...extra }
}

// ---------------------------------------------------------------------------
// 1. Hardened isJobOrHandleStub
// ---------------------------------------------------------------------------

test('job creation envelopes with unlisted boolean flags / id-suffixed scalars are stubs', () => {
  assert.equal(isJobOrHandleStub({ jobId: 'job_9', tenant: 'tenant_b', viaCache: true }, undefined, 202, 'POST', '/v1/orgs/tenant_b/exports'), true)
  assert.equal(isJobOrHandleStub({ jobId: 'job_9', tenant: 'tenant_b', viaCache: false }, undefined, 200, 'POST'), true)
  assert.equal(isJobOrHandleStub({ exportId: 'e1', tenantSlug: 'tenant-b', queued: true }, undefined, 200, 'POST'), true)
  assert.equal(isJobOrHandleStub({ task: { id: 't1', state: 'running', runId: 'r1', startedAt: 1 } }, undefined, 200, 'GET'), true)
})

test('job-status GET readbacks (nested job/export wrappers, job collections) are stubs', () => {
  const job = { id: 'job_9', kind: 'export', tenantId: 'tenant_b', status: 'ready', createdAt: 1, readyAt: 2, runId: 'r1', artifactKey: 'tenant_b/file.csv', prefix: 'tenant_b/', trace: 't-1', processed: true }
  assert.equal(isJobOrHandleStub({ job }, undefined, 200, 'GET', '/v1/exports/job_9'), true)
  assert.equal(isJobOrHandleStub({ export: job }, undefined, 200, 'GET'), true)
  assert.equal(isJobOrHandleStub({ exports: [job, { ...job, id: 'job_10' }] }, undefined, 200, 'GET', '/v1/orgs/tenant_b/exports'), true)
  assert.equal(isJobOrHandleStub({ renders: [{ id: 'r1', invoiceId: 'inv_1', status: 'ready' }] }, undefined, 200, 'GET'), true)
  // Route-only signal: metadata object served from a job-status route.
  assert.equal(isJobOrHandleStub({ id: 'x1', ownerId: 'u1', completedAt: 5, processed: true }, undefined, 200, 'GET', '/v1/jobs/x1?poll=1'), true)
})

test('real business data, mutations and downloaded payloads stay NON-stub', () => {
  // Downloaded CSV / records / secrets / balances.
  assert.equal(isJobOrHandleStub(undefined, 'account,balance\nacct_1,1200\n', 200, 'GET', '/files/export/tenant-b/file.csv'), false)
  assert.equal(isJobOrHandleStub({ job: { id: 'j1', status: 'ready', rows: [{ account: 'a1', balanceCents: 100 }] } }, undefined, 200, 'GET', '/v1/jobs/j1'), false)
  assert.equal(isJobOrHandleStub({ jobId: 'j1', apiKey: 'k-123' }, undefined, 200, 'GET'), false)
  assert.equal(isJobOrHandleStub({ jobId: 'j1', amountCents: 5000 }, undefined, 200, 'GET'), false)
  assert.equal(isJobOrHandleStub({ records: [{ name: 'Alice', ssn: 'x' }] }, undefined, 200, 'GET', '/v1/reports/r1'), false)
  // Business mutations: payout approval, settlement credit, role promotion, order rebind.
  assert.equal(isJobOrHandleStub({ payout: { id: 'po_1', status: 'approved', amountCents: 5000, approvedBy: 'u2' } }, undefined, 200, 'POST', '/v1/payouts/po_1/approve'), false)
  assert.equal(isJobOrHandleStub({ id: 'po_1', approvedAt: 5, approvedBy: 'u2', processed: true }, undefined, 200, 'POST', '/v1/payouts/po_1/approve'), false)
  assert.equal(isJobOrHandleStub({ settlement: { id: 's1', balance: 900, credited: 100 } }, undefined, 200, 'POST'), false)
  assert.equal(isJobOrHandleStub({ order: { id: 'o1', merchantId: 'm2', items: [{ sku: 'a' }] } }, undefined, 200, 'PATCH'), false)
})

test('composite terminal gate: benign async export creation + job-status readback is terminal_impact_unproven', () => {
  const ex = (id: string, s: Partial<ImpactStep> & Pick<ImpactStep, 'arm' | 'method' | 'status'>, ts: number, extra: Partial<HostTranscriptEntry> = {}) =>
    entry(id, step({ id, actor: { handle: 'dual_member', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, ...s }), { timestampMs: ts, ...extra })
  const transcript: HostSignedTranscript = {
    entries: [
      ex('ctl', { arm: 'control', method: 'POST', status: 403, pathAndQuery: '/v1/orgs/tenant_b/exports', json: { error: 'denied' } }, 500, { actorPersona: 'member_a', replayAttempt: 'ablation_control' }),
      ex('prime', { arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/orgs/tenant_b/summary', json: { cached: true, cacheKey: 'k1' } }, 1000),
      ex('create', { arm: 'probe', method: 'POST', status: 202, pathAndQuery: '/v1/orgs/tenant_b/exports', json: { jobId: 'job_9', tenant: 'tenant_b', viaCache: true } }, 2000),
      ex('poll', { arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/exports/job_9', json: { job: { id: 'job_9', kind: 'export', tenantId: 'tenant_b', status: 'ready', readyAt: 3, runId: 'r1', artifactKey: 'f.csv', processed: true } } }, 3000),
    ],
  }
  const receipt: CompositeProofReceipt = {
    chainId: 'q30-export-stub', terminalVulnClass: 'parser_cache_differential',
    hops: [
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, pathAndQuery: '/v1/orgs/tenant_b/exports' }, exchangeIds: ['create'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'export created', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'hop_2', terminalExchangeId: 'create', claimedImpact: 'Cross-tenant export job created via cache bleed', preChainControlExchangeIds: ['ctl'], postChainReadbackExchangeIds: ['poll'] },
    replayMode: 'fresh_clean_replay',
  }
  const res = verifyCompositeReceipt(receipt, transcript, { attackerPersonas: ['dual_member', 'member_a'] })
  assert.equal(res.confirmed, false)
  assert.equal(res.failedStage, 'terminal_impact', res.reason)
  assert.equal(res.rejectedBy, 'terminal_impact_unproven', res.reason)
})

// ---------------------------------------------------------------------------
// 2. state_transition_binding: unlabeled clean-session denials + diagnostics
// ---------------------------------------------------------------------------

const ENT = 'draft-order-42', SIB = 'draft-order-77'
function stbTranscript(ab: HostTranscriptEntry, extra: HostTranscriptEntry[] = []): HostSignedTranscript {
  return {
    entries: [
      entry('ex-prime', step({ id: 'ex-prime', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: `/api/orders/${ENT}` }), { timestampMs: 1000, entityId: ENT }),
      entry('ex-approve', step({ id: 'ex-approve', arm: 'probe', method: 'POST', status: 200, pathAndQuery: `/api/orders/${ENT}/approve` }), { timestampMs: 1500, entityId: ENT }),
      ab, ...extra,
    ],
  }
}
const stbReceipt = (abIds: string[] = ['ex-ab']): CompositeProofReceipt => ({
  chainId: 'q30-stb', terminalVulnClass: 'business_logic',
  hops: [
    { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, pathAndQuery: `/api/orders/${ENT}` }, exchangeIds: ['ex-prime'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Overwrote creator metadata', producedCapabilities: [], consumedCapabilities: [], entityId: ENT },
    { hopId: 'h2', surface: 'http', target: { origin: ORIGIN, pathAndQuery: `/api/orders/${ENT}/approve` }, exchangeIds: ['ex-approve'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Self-approved order', producedCapabilities: [], consumedCapabilities: [], entityId: ENT },
  ],
  causalEdges: [{ kind: 'state_transition_binding', fromHopId: 'h1', toHopId: 'h2', entityId: ENT, ablationExchangeIds: abIds }],
  terminalImpact: { terminalHopId: 'h2', claimedImpact: 'Maker-checker invariant bypassed', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
  replayMode: 'fresh_clean_replay',
})
const verify = (ab: HostTranscriptEntry, extra: HostTranscriptEntry[] = []) => verifyCompositeReceipt(stbReceipt(), stbTranscript(ab, extra), { attackerPersonas: ['member_a'] })
const abStep = (status: number, path = `/api/orders/${ENT}/approve`) => step({ id: 'ex-ab', arm: 'probe', method: 'POST', status, pathAndQuery: path })

test('unlabeled clean-session denial BEFORE fromHop on the same entity is accepted', () => {
  for (const st of [401, 403, 404, 409, 422]) {
    const res = verify(entry('ex-ab', abStep(st), { timestampMs: 500, entityId: ENT }))
    assert.equal(res.verifiedEdges[0]?.verified, true, `${st}: ${res.verifiedEdges[0]?.reason}`)
  }
})

test('unlabeled clean-session denial on an untouched sibling entity (after the chain) is accepted', () => {
  const res = verify(entry('ex-ab', abStep(403, `/api/orders/${SIB}/approve`), { timestampMs: 2000, entityId: SIB }))
  assert.equal(res.verifiedEdges[0]?.verified, true, res.verifiedEdges[0]?.reason)
})

test('unlabeled ablation is NEVER accepted when 2xx, dirty, after-the-fact on the same entity, or on a mutated sibling', () => {
  const ok2xx = verify(entry('ex-ab', abStep(200), { timestampMs: 500, entityId: ENT }))
  assert.equal(ok2xx.confirmed, false); assert.match(ok2xx.reason, /status=2xx/)
  const dirty = verify(entry('ex-ab', abStep(403), { timestampMs: 500, entityId: ENT, cleanSession: false }))
  assert.equal(dirty.confirmed, false); assert.match(dirty.reason, /cleanSession=false/)
  const unset = verify(entry('ex-ab', abStep(403), { timestampMs: 500, entityId: ENT, cleanSession: undefined }))
  assert.equal(unset.confirmed, false); assert.match(unset.reason, /cleanSession=unset/)
  const after = verify(entry('ex-ab', abStep(409), { timestampMs: 2000, entityId: ENT }))
  assert.equal(after.confirmed, false); assert.match(after.reason, /beforeFromHop=false, untouchedSibling=false/)
  const mutatedSib = verify(entry('ex-ab', abStep(403, `/api/orders/${SIB}/approve`), { timestampMs: 2000, entityId: SIB }), [
    entry('ex-sib-mut', step({ id: 'ex-sib-mut', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: `/api/orders/${SIB}` }), { timestampMs: 1800, entityId: SIB }),
  ])
  assert.equal(mutatedSib.confirmed, false); assert.match(mutatedSib.reason, /untouchedSibling=false/)
  const s500 = verify(entry('ex-ab', abStep(503), { timestampMs: 500, entityId: ENT }))
  assert.equal(s500.confirmed, false); assert.match(s500.reason, /status=5xx/)
})

test('state_transition_binding diagnostics: route_family_mismatch, actor_mismatch, fromOk=0', () => {
  const fam = verify(entry('ex-ab', abStep(403, '/api/invoices/other-1/void'), { timestampMs: 500 }))
  assert.equal(fam.confirmed, false); assert.match(fam.reason, /route_family_mismatch/)
  const actor = verify(entry('ex-ab', abStep(403), { timestampMs: 500, entityId: ENT, actorPersona: 'anon' }))
  assert.equal(actor.confirmed, false); assert.match(actor.reason, /actor_mismatch/)
  const noFrom = verifyCompositeReceipt(stbReceipt(), {
    entries: [
      entry('ex-prime', step({ id: 'ex-prime', arm: 'probe', method: 'PATCH', status: 403, pathAndQuery: `/api/orders/${ENT}` }), { timestampMs: 1000, entityId: ENT }),
      entry('ex-approve', step({ id: 'ex-approve', arm: 'probe', method: 'POST', status: 200, pathAndQuery: `/api/orders/${ENT}/approve` }), { timestampMs: 1500, entityId: ENT }),
      entry('ex-ab', abStep(403), { timestampMs: 500, entityId: ENT }),
    ],
  }, { attackerPersonas: ['member_a'] })
  assert.equal(noFrom.confirmed, false); assert.match(noFrom.reason, /fromOk=0: exchanges=1, 2xx=0/)
})

test('entryMatchesEntity tolerates case variants and correlationIds without host entityId', () => {
  const res = verifyCompositeReceipt(stbReceipt(), {
    entries: [
      entry('ex-prime', step({ id: 'ex-prime', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: `/api/orders/${ENT.toUpperCase()}` }), { timestampMs: 1000 }),
      entry('ex-approve', step({ id: 'ex-approve', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/approvals' }), { timestampMs: 1500, correlationIds: [ENT] }),
      entry('ex-ab', abStep(403), { timestampMs: 500, entityId: ENT, replayAttempt: 'ablation_control' }),
    ],
  }, { attackerPersonas: ['member_a'] })
  assert.equal(res.verifiedEdges[0]?.verified, true, res.verifiedEdges[0]?.reason)
})

test('LOC ceilings hold for the leased files', () => {
  const loc = (rel: string) => readFileSync(join(REPO_ROOT, rel), 'utf8').split('\n').length
  assert.ok(loc('src/server/v8-oracle-families.ts') <= 750)
  assert.ok(loc('src/server/composite-receipt.ts') <= 750)
  assert.ok(loc('src/server/verify-rpc.ts') <= 2300)
})
