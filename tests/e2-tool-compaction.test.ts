/**
 * Track E2 — Tool Output Compaction Tests.
 *
 * Verifies significant (>50%) serialized JSON byte-size reduction across the 4 compacted
 * read/query tools (`board_read`, `search_facts`, `search_exchanges`, `query_endpoints`)
 * while preserving every required ID, pagination cursor, non-empty metadata field, and
 * exact-lookup escape hatch.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import {
  boardReadDefaultLimit,
  boardReadMaxLimit,
  createBoardTools,
} from '../src/server/board-tools.ts'
import { coordinatorPlannerHandlers } from '../src/server/exec-dispatch.ts'
import {
  clampSearchLimit,
  compactSearchExchangeRow,
  compactSearchFactRow,
} from '../src/server/exec-worker-runner.ts'
import {
  createGraphCoordinator,
  type CoordinatorEndpoint,
} from '../src/server/graph-coordinator.ts'
import { Store } from '../src/server/store.ts'

const ORIGIN_A = 'https://app.example.test'

function makeBoardStore(t: test.TestContext): { store: Store; runId: string } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-e2-compact-'))
  const store = new Store(dir)
  t.after(() => {
    store.close()
    rmSync(dir, { recursive: true, force: true })
  })
  const { id: projectId } = store.createProject({
    requestId: randomUUID(),
    name: 'E2 Compaction Test',
    seeds: [ORIGIN_A],
    environment: 'public',
  })
  const { id: runId } = store.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Verify tool compaction',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 5,
    budgetRequests: 200,
    maxRpsPerOrigin: 30,
    workerConcurrency: 2,
    workerMaxTurns: 20,
  })
  const candidates = [{ id: randomUUID(), origin: ORIGIN_A, source: 'seed', thirdParty: false }]
  store.client.prepare('UPDATE runs SET phase = ?, status = ?, candidates = ?, approved = ?, scope_revision = ? WHERE id = ?')
    .run('investigation', 'paused', JSON.stringify(candidates), JSON.stringify([candidates[0]!.id]), 1, runId)
  store.upsertBoardMember(runId, {
    handle: 'bola',
    role: 'specialist',
    state: 'working',
    sourceOrigins: [ORIGIN_A],
  })
  store.upsertBoardMember(runId, {
    handle: 'auth',
    role: 'specialist',
    state: 'working',
    sourceOrigins: [ORIGIN_A],
  })
  return { store, runId }
}

test('board_read compacts bodies, omits empty/null optional keys, enforces 10/25 limits, and cuts JSON >50%', t => {
  assert.equal(boardReadDefaultLimit, 10)
  assert.equal(boardReadMaxLimit, 25)

  const { store, runId } = makeBoardStore(t)
  const longBody = `${'Observing route authorization differential across tenant invoices. '.repeat(14)}END_MARKER`
  assert.ok(longBody.length > 800)

  const postedSeqs: number[] = []
  for (let i = 0; i < 30; i++) {
    const row = store.postBoardMessage(runId, {
      authorHandle: 'auth',
      authorRole: 'specialist',
      kind: 'note',
      body: i === 0 ? longBody : `${longBody} #${i}`,
      mentions: i === 1 ? ['bola'] : [],
      refFactIds: i === 1 ? ['fact-101'] : [],
      refExchangeIds: i === 1 ? ['ex-202'] : [],
      refFindingIds: i === 1 ? ['find-303'] : [],
      refStepId: i === 1 ? 'step-404' : null,
      replyToSeq: i === 1 ? postedSeqs[0]! : null,
      sourceOrigins: [ORIGIN_A],
    })
    postedSeqs.push(row.seq)
  }

  const tools = createBoardTools({ store, run: runId, handle: 'bola' })

  // Default limit is 10
  const defRead = tools.board_read()
  assert.equal(defRead.ok, true)
  if (!defRead.ok) return
  assert.equal(defRead.messages.length, 10)
  assert.equal(defRead.cursor, defRead.messages[defRead.messages.length - 1]!.seq)
  assert.equal(defRead.latestSeq, defRead.cursor)

  // Sparse row omits empty arrays & null optional fields, clips body <= 360 with truncated: true
  const first = defRead.messages[0]!
  assert.equal(first.seq, postedSeqs[0])
  assert.equal(first.authorHandle, 'auth')
  assert.equal(first.kind, 'note')
  assert.equal(typeof first.createdAt, 'number')
  assert.ok(first.body.length <= 360)
  assert.equal(first.truncated, true)
  assert.equal('mentions' in first, false)
  assert.equal('refFactIds' in first, false)
  assert.equal('refExchangeIds' in first, false)
  assert.equal('refFindingIds' in first, false)
  assert.equal('refStepId' in first, false)
  assert.equal('replyToSeq' in first, false)

  // Populated row preserves every non-empty ID & reference verbatim
  const second = defRead.messages[1]!
  assert.deepEqual(second.mentions, ['bola'])
  assert.deepEqual(second.refFactIds, ['fact-101'])
  assert.deepEqual(second.refExchangeIds, ['ex-202'])
  assert.deepEqual(second.refFindingIds, ['find-303'])
  assert.equal(second.refStepId, 'step-404')
  assert.equal(second.replyToSeq, postedSeqs[0])

  // Escape hatch: includeFullBody returns unclipped body without truncated flag
  const fullRead = tools.board_read({ limit: 1, includeFullBody: true })
  assert.equal(fullRead.ok, true)
  if (!fullRead.ok) return
  assert.equal(fullRead.messages[0]!.body, longBody)
  assert.equal('truncated' in fullRead.messages[0]!, false)

  // Max limit clamped to 25 even when caller asks for 500
  const maxRead = tools.board_read({ limit: 500 })
  assert.equal(maxRead.ok, true)
  if (!maxRead.ok) return
  assert.equal(maxRead.messages.length, 25)

  // Byte-size reduction >50% vs legacy 20-row uncompacted payload
  const legacyRows = store.listBoardMessages(runId, { limit: 20, includeTainted: false }).map(m => ({
    seq: m.seq,
    authorHandle: m.authorHandle,
    kind: m.kind,
    mentions: [...m.mentions],
    body: m.body,
    refFactIds: [...m.refFactIds],
    refExchangeIds: [...m.refExchangeIds],
    refFindingIds: [...m.refFindingIds],
    refStepId: m.refStepId,
    replyToSeq: m.replyToSeq,
    createdAt: m.createdAt,
  }))
  const legacyBytes = Buffer.byteLength(JSON.stringify({ ok: true, messages: legacyRows, latestSeq: legacyRows[19]!.seq, cursor: legacyRows[19]!.seq }))
  const compactBytes = Buffer.byteLength(JSON.stringify(defRead))
  assert.ok(compactBytes < legacyBytes * 0.5, `expected >50% shrink (compact=${compactBytes}, legacy=${legacyBytes})`)
})

test('search_facts compaction clamps limits (15/40), projects compact rows, omits empty arrays, and cuts JSON >50%', () => {
  assert.equal(clampSearchLimit(undefined), 15)
  assert.equal(clampSearchLimit(0), 1)
  assert.equal(clampSearchLimit(-10), 1)
  assert.equal(clampSearchLimit(22), 22)
  assert.equal(clampSearchLimit(999), 40)

  const bigData = {
    route: '/api/v2/tenants/:tenantId/invoices',
    headers: Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`x-trace-${i}`, `val-${'a'.repeat(40)}-${i}`])),
    observedParameters: Array.from({ length: 30 }, (_, i) => `param_${i}_value`),
  }
  const longSummary = `Observed authorization control variance on nested tenant resource endpoints. ${'detail '.repeat(45)}`

  const rawFacts = Array.from({ length: 25 }, (_, i) => ({
    id: `fact-${i}`,
    runId: 'run-uuid-1234567890',
    assignmentId: 'assign-uuid-1234567890',
    scopeRevision: 2,
    goalRevision: 1,
    kind: 'auth' as const,
    origin: ORIGIN_A,
    summary: longSummary,
    data: i === 0 ? {} : i === 1 ? { subkind: 'bola_candidate' } : bigData,
    sourceOrigins: [ORIGIN_A],
    evidenceIds: i === 1 ? ['ev-1'] : [],
    exchangeIds: i === 1 ? ['ex-1'] : [],
    tainted: false,
    coldSinceRound: null,
    digestId: null,
    createdAt: 1_700_000_000_000 + i,
  }))

  const compactRows = rawFacts.slice(0, clampSearchLimit(undefined)).map(compactSearchFactRow)
  assert.equal(compactRows.length, 15)

  // Empty data + empty arrays omitted
  const row0 = compactRows[0]!
  assert.equal(row0.id, 'fact-0')
  assert.equal(row0.kind, 'auth')
  assert.equal(row0.origin, ORIGIN_A)
  assert.ok(row0.summary.length <= 200)
  assert.equal('dataPreview' in row0, false)
  assert.equal('dataTruncated' in row0, false)
  assert.equal('evidenceIds' in row0, false)
  assert.equal('exchangeIds' in row0, false)

  // Small data preserved verbatim without dataTruncated; non-empty IDs preserved
  const row1 = compactRows[1]!
  assert.equal(row1.dataPreview, '{"subkind":"bola_candidate"}')
  assert.equal('dataTruncated' in row1, false)
  assert.deepEqual(row1.evidenceIds, ['ev-1'])
  assert.deepEqual(row1.exchangeIds, ['ex-1'])

  // Large data clipped <= 240 with dataTruncated: true
  const row2 = compactRows[2]!
  assert.ok(row2.dataPreview && row2.dataPreview.length <= 240)
  assert.equal(row2.dataTruncated, true)

  const legacyBytes = Buffer.byteLength(JSON.stringify(rawFacts))
  const compactBytes = Buffer.byteLength(JSON.stringify(compactRows))
  assert.ok(compactBytes < legacyBytes * 0.5, `expected >50% shrink (compact=${compactBytes}, legacy=${legacyBytes})`)
})

test('search_exchanges compaction caps bodyPreview to 180, removes duplicate id, omits empty fields, and cuts JSON >50%', () => {
  const longBody = JSON.stringify({
    items: Array.from({ length: 20 }, (_, i) => ({ id: i, name: `invoice-record-${i}`, note: 'control-vs-variant-sample' })),
  })
  assert.ok(longBody.length > 600)

  const rawExchanges = Array.from({ length: 30 }, (_, i) => ({
    id: `ex-uuid-${String(i).padStart(4, '0')}`,
    origin: ORIGIN_A,
    method: 'GET',
    pathAndQuery: `/api/v1/invoices/${i}?expand=line_items`,
    status: 200,
    mediaType: i === 0 ? '' : 'application/json',
    bodyPreview: i === 0 ? '' : longBody.slice(0, 600),
  }))

  const compactRows = rawExchanges.slice(0, clampSearchLimit(undefined)).map(compactSearchExchangeRow)
  assert.equal(compactRows.length, 15)

  // Empty optional fields and duplicate `id` omitted
  const row0 = compactRows[0]!
  assert.equal(row0.exchangeId, 'ex-uuid-0000')
  assert.equal('id' in row0, false)
  assert.equal('mediaType' in row0, false)
  assert.equal('bodyPreview' in row0, false)

  // Non-empty fields preserved and bodyPreview capped <= 180
  const row1 = compactRows[1]!
  assert.equal(row1.exchangeId, 'ex-uuid-0001')
  assert.equal('id' in row1, false)
  assert.equal(row1.mediaType, 'application/json')
  assert.ok(row1.bodyPreview && row1.bodyPreview.length <= 180)

  const legacyPayload = rawExchanges.map(ex => ({
    id: ex.id,
    exchangeId: ex.id,
    origin: ex.origin,
    method: ex.method,
    pathAndQuery: ex.pathAndQuery,
    status: ex.status,
    mediaType: ex.mediaType,
    bodyPreview: ex.bodyPreview.slice(0, 600),
  }))
  const legacyBytes = Buffer.byteLength(JSON.stringify(legacyPayload))
  const compactBytes = Buffer.byteLength(JSON.stringify(compactRows))
  assert.ok(compactBytes < legacyBytes * 0.5, `expected >50% shrink (compact=${compactBytes}, legacy=${legacyBytes})`)
})

test('query_endpoints compacts default page to 15 (max 25), caps routes <= 140, omits sparse keys, preserves cursors, and cuts JSON >50%', async () => {
  const longRoute = `/api/v2/organizations/:orgId/workspaces/:workspaceId/deployments/${'segment/'.repeat(20)}:deploymentId/status`
  assert.ok(longRoute.length > 180)

  const endpoints: CoordinatorEndpoint[] = Array.from({ length: 50 }, (_, i) => ({
    id: `ep-${String(i).padStart(3, '0')}`,
    origin: ORIGIN_A,
    method: i % 2 === 0 ? 'GET' : 'POST',
    pathTemplate: i === 0 ? longRoute : `/api/v1/resource/${i}`,
    riskScore: i === 1 ? 85 : 20,
    coveragePct: i === 1 ? 0 : i === 2 ? 75 : null,
    testedClasses: i === 2 ? ['bola_idor'] : [],
    sinkKinds: i === 2 ? ['db_query'] : [],
    authRequirement: i === 2 ? 'bearerAuth' : null,
    ownershipGuard: i === 2 ? 'tenant' : null,
    roleExclusive: i === 2,
  }))

  const coordinator = createGraphCoordinator({
    deps: {
      listEndpoints: () => endpoints,
      listFacts: () => [],
      listFindings: () => [],
      approvedOrigins: () => [ORIGIN_A],
    },
  })
  const handlers = coordinatorPlannerHandlers({ coordinator })
  const sig = new AbortController().signal

  // Default page size is 15
  const page1 = (await handlers.query_endpoints!({}, sig)) as {
    items: Array<Record<string, unknown>>
    nextCursor: string | null
    total: number
  }
  assert.equal(page1.items.length, 15)
  assert.equal(page1.total, 50)
  assert.ok(page1.nextCursor)

  // Max page size clamped to 25
  const maxPage = (await handlers.query_endpoints!({ limit: 500 }, sig)) as {
    items: Array<Record<string, unknown>>
  }
  assert.equal(maxPage.items.length, 25)

  // Pagination cursor reaches all 50 unique endpoints without drops
  const byId = new Map<string, Record<string, unknown>>()
  let cursor: string | undefined
  for (;;) {
    const p = (await handlers.query_endpoints!({ cursor }, sig)) as {
      items: Array<Record<string, unknown>>
      nextCursor: string | null
    }
    for (const item of p.items) byId.set(String(item.id), item)
    if (!p.nextCursor) break
    cursor = p.nextCursor
  }
  assert.equal(byId.size, 50)

  // Route capped <= 140 and sparse keys omitted; non-empty/zero/true values preserved
  const ep0 = byId.get('ep-000')!
  assert.ok(String(ep0.route).length <= 140)
  assert.equal('coverage' in ep0, false)
  assert.equal('tested' in ep0, false)
  assert.equal('sinks' in ep0, false)
  assert.equal('auth' in ep0, false)
  assert.equal('guard' in ep0, false)
  assert.equal('roleExclusive' in ep0, false)

  // Numeric 0 coverage is preserved (only null/undefined omitted)
  const ep1 = byId.get('ep-001')!
  assert.equal(ep1.coverage, 0)

  // Populated fields preserved verbatim
  const ep2 = byId.get('ep-002')!
  assert.equal(ep2.coverage, 75)
  assert.deepEqual(ep2.tested, ['bola_idor'])
  assert.deepEqual(ep2.sinks, ['db_query'])
  assert.equal(ep2.auth, 'bearerAuth')
  assert.equal(ep2.guard, 'tenant')
  assert.equal(ep2.roleExclusive, true)

  // Byte-size reduction >50% vs legacy 25-row sparse page
  const legacyPage = {
    total: 50,
    nextCursor: page1.nextCursor,
    items: endpoints.slice(0, 25).map(ep => ({
      id: ep.id,
      method: ep.method,
      route: ep.pathTemplate.slice(0, 160),
      origin: ep.origin,
      risk: ep.riskScore ?? 0,
      coverage: ep.coveragePct ?? null,
      tested: ep.testedClasses ?? [],
      sinks: ep.sinkKinds ?? [],
      auth: ep.authRequirement ?? null,
      guard: ep.ownershipGuard ?? null,
      roleExclusive: ep.roleExclusive === true,
    })),
  }
  const legacyBytes = Buffer.byteLength(JSON.stringify(legacyPage))
  const compactBytes = Buffer.byteLength(JSON.stringify(page1))
  assert.ok(compactBytes < legacyBytes * 0.5, `expected >50% shrink (compact=${compactBytes}, legacy=${legacyBytes})`)
})
