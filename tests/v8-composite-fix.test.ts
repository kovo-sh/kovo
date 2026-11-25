/**
 * Regression suite for v8 composite verification fixes:
 *  1. `ctx.prove_composite` / `ctx.proveComposite` auto-records a host-backed `composite_receipt`
 *     claim in the TS SDK -> ZERO `claims_missing` on passing or failing DAGs.
 *  2. Rejected `composite.verify` calls surface exact `rejectedBy` + `missingEvidence` feedback
 *     instead of `claims_missing`, and forged client-only `composite_receipt` claims fail closed.
 *  3. Empty/short `terminalImpact.summary` is rejected with `rejectedBy: 'terminal_impact_summary_missing'`,
 *     and invalid `terminalExchangeId` not belonging to the final hop is rejected.
 *  4. Partial-hop hardened-twin decoy FPs (benign cache prime + export job creation stub without
 *     foreign-tenant data read or privileged mutation) are REJECTED by `composite.verify`,
 *     `evaluateDualTenantAbac`, and `evaluateParserCacheDifferential` with actionable
 *     `terminal_impact_unproven` guidance.
 *  5. Full end-to-end multi-hop chain proving actual unauthorized foreign-tenant data read +
 *     clean denied control (`401`/`403`/`404`) PASSES in the TS SDK.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { signHostRecord, verifyCompositeReceipt } from '../src/server/composite-receipt.ts'
import type { HostSignedTranscript, HostTranscriptEntry } from '../src/server/composite-receipt.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  evaluateDualTenantAbac,
  evaluateParserCacheDifferential,
  isJobOrHandleStub,
  type HostSignedRecord,
} from '../src/server/v8-oracle-families.ts'
import {
  TranscriptStore,
  createLocalAttemptFactory,
  evaluateClaims,
  verifyScript,
} from '../src/server/verify-rpc.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_DIR = join(REPO_ROOT, 'worker', 'kovo_verify')
const SIGNING_KEY = 'unit-test-composite-fix-key'

function makePersona(handle: string, roleLabel: string, token: string, origin: string): ResolvedPersona {
  return {
    id: `persona-${handle}`,
    handle,
    roleLabel,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: null,
    secret: token,
    canaryMarkers: [],
  }
}

function makeGrant(origin: string, personas: ResolvedPersona[]): Grant {
  return {
    canRead: (candidate: string) => {
      try { return new URL(candidate).origin === origin } catch { return false }
    },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map(personas.map(p => [p.handle, p])),
  }
}

/**
 * Dual-mode loopback fixture:
 *  - `hardenedTwin: true`: cache-prime (`GET /api/me/permissions`) and export job creation
 *    (`POST /api/exports`) succeed, returning a job stub `{ jobId, status: 'queued', downloadUrl }`,
 *    while downloading a foreign tenant's export (`GET /api/exports/exp-foreign-99/download`) is
 *    blocked with 403.
 *  - `hardenedTwin: false`: clean unprimed download returns 403; after priming cache on own org
 *    and creating export job with derived handle, following `downloadUrl` exposes foreign tenant
 *    records (`tenantId: 'org_target'`).
 */
async function startDualTenantExportFixture(options: { hardenedTwin: boolean }): Promise<{
  origin: string
  close: () => Promise<void>
}> {
  let cachePrimedByAttacker = false
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const auth = String(req.headers.authorization ?? '')
    res.setHeader('content-type', 'application/json')

    if (url.pathname === '/api/me/permissions' && req.method === 'GET') {
      if (auth !== 'Bearer tok-dual-attacker') {
        res.statusCode = 401
        res.end(JSON.stringify({ error: 'unauthorized' }))
        return
      }
      cachePrimedByAttacker = true
      res.statusCode = 200
      res.setHeader('x-cache', 'MISS')
      res.end(JSON.stringify({
        userId: 'usr-dual-1',
        tenantId: 'org_attacker',
        role: 'admin',
        permissions: ['exports:create', 'exports:read'],
        cacheToken: 'tok_cache_slot_prime_11',
        cached: true,
      }))
      return
    }

    if (url.pathname === '/api/exports' && req.method === 'POST') {
      if (auth !== 'Bearer tok-dual-attacker') {
        res.statusCode = 401
        res.end(JSON.stringify({ error: 'unauthorized' }))
        return
      }
      res.statusCode = 202
      res.end(JSON.stringify({
        jobId: 'exp-foreign-99',
        status: 'queued',
        tenantId: 'org_attacker',
        downloadUrl: '/api/exports/exp-foreign-99/download',
        exportToken: 'tok_export_handle_998877',
      }))
      return
    }

    if (url.pathname === '/api/exports/exp-foreign-99/download' && req.method === 'GET') {
      const exportHdr = String(req.headers['x-export-token'] ?? '')
      if (options.hardenedTwin) {
        res.statusCode = 403
        res.end(JSON.stringify({ error: 'cross_tenant_export_denied' }))
        return
      }
      if (cachePrimedByAttacker && exportHdr === 'tok_export_handle_998877') {
        res.statusCode = 200
        res.setHeader('x-cache', 'HIT')
        res.end(JSON.stringify({
          tenantId: 'org_target',
          classification: 'confidential',
          records: [
            { id: 'inv-9001', ownerEmail: 'finance@org-target.test', amountCents: 482000 },
            { id: 'inv-9002', ownerEmail: 'ops@org-target.test', amountCents: 195000 },
          ],
        }))
        return
      }
      res.statusCode = 403
      res.end(JSON.stringify({ error: 'forbidden_foreign_tenant_export' }))
      return
    }

    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not_found' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  return {
    origin: `http://127.0.0.1:${port}`,
    close: async () => {
      server.closeAllConnections()
      await new Promise<void>(resolveClose => server.close(() => resolveClose()))
    },
  }
}

function makeSignedEntry(
  exchangeId: string,
  overrides: Partial<HostTranscriptEntry> & {
    arm: 'control' | 'probe'
    method: string
    pathAndQuery: string
    status: number
    actorHandle?: string | null
    actorTenant?: string | null
    json?: unknown
    body?: string
  },
): HostTranscriptEntry {
  const entry: HostTranscriptEntry = {
    exchangeId,
    timestampMs: overrides.timestampMs ?? 1_700_000_000_000,
    actorPersona: overrides.actorPersona !== undefined ? overrides.actorPersona : (overrides.actorHandle ?? 'member_attacker'),
    actorRoleLabel: overrides.actorRoleLabel ?? `member (${overrides.actorTenant ?? 'org_attacker'})`,
    cleanSession: overrides.cleanSession ?? true,
    ...(overrides.emittedCapabilities ? { emittedCapabilities: overrides.emittedCapabilities } : {}),
    ...(overrides.consumedCapabilities ? { consumedCapabilities: overrides.consumedCapabilities } : {}),
    ...(overrides.entityId ? { entityId: overrides.entityId } : {}),
    ...(overrides.replayAttempt ? { replayAttempt: overrides.replayAttempt } : {}),
    step: {
      id: exchangeId,
      arm: overrides.arm,
      method: overrides.method,
      route: overrides.pathAndQuery.split('?')[0]!,
      pathAndQuery: overrides.pathAndQuery,
      status: overrides.status,
      actor: {
        handle: overrides.actorHandle ?? 'member_attacker',
        role: 'member',
        tenant: overrides.actorTenant ?? 'org_attacker',
        auth: 'bearer',
        sameSite: null,
      },
      ...(overrides.json !== undefined ? { json: overrides.json } : {}),
      ...(overrides.body !== undefined ? { body: overrides.body } : {}),
    },
  }
  return { ...entry, hostSignature: signHostRecord(entry, SIGNING_KEY) }
}

// ============================================================================
// 1. Empty terminalImpact.summary & invalid terminalExchangeId fail closed
// ============================================================================

test('composite.verify rejects empty/short terminalImpact.summary with rejectedBy=terminal_impact_summary_missing and rejects foreign terminalExchangeId', () => {
  const cap = 'cap:hop_1:export_tok'
  const transcript: HostSignedTranscript = {
    entries: [
      makeSignedEntry('ex-ctrl', { arm: 'control', method: 'GET', pathAndQuery: '/api/exports/exp-99/download', status: 403, timestampMs: 1000 }),
      makeSignedEntry('ex-1', { arm: 'probe', method: 'POST', pathAndQuery: '/api/exports', status: 202, timestampMs: 1100, emittedCapabilities: [cap], json: { jobId: 'exp-99', status: 'queued' } }),
      makeSignedEntry('ex-2', { arm: 'probe', method: 'GET', pathAndQuery: '/api/exports/exp-99/download', status: 200, timestampMs: 1200, consumedCapabilities: [cap], json: { tenantId: 'org_target', records: [{ id: 'r1', secret: 'val' }] } }),
    ],
  }
  const baseReceipt = {
    chainId: 'chain-summary-check',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/api/exports' }, exchangeIds: ['ex-1'], claimedDelta: 'Created export job handle.' },
      { hopId: 'hop_2', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/exports/exp-99/download' }, exchangeIds: ['ex-2'], claimedDelta: 'Downloaded foreign tenant records.' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    replayMode: 'fresh_clean_replay',
  }

  // Empty summary === "" MUST reject with terminal_impact_summary_missing
  const emptySummary = verifyCompositeReceipt({
    ...baseReceipt,
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: '',
      claimedImpact: 'Cross-tenant export downloaded.',
      terminalExchangeId: 'ex-2',
      preChainControlExchangeIds: ['ex-ctrl'],
    },
  }, transcript, { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY })
  assert.equal(emptySummary.confirmed, false)
  assert.equal(emptySummary.failedStage, 'terminal_impact')
  assert.equal(emptySummary.rejectedBy, 'terminal_impact_summary_missing')
  assert.ok(emptySummary.missingEvidence?.includes('terminal_impact_summary_missing'))

  // Short summary (< 12 non-whitespace chars) MUST reject with terminal_impact_summary_missing
  const shortSummary = verifyCompositeReceipt({
    ...baseReceipt,
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'too short',
      terminalExchangeId: 'ex-2',
      preChainControlExchangeIds: ['ex-ctrl'],
    },
  }, transcript, { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY })
  assert.equal(shortSummary.confirmed, false)
  assert.equal(shortSummary.rejectedBy, 'terminal_impact_summary_missing')

  // terminalExchangeId pointing to hop_1 (not final hop_2) MUST reject
  const wrongTermEx = verifyCompositeReceipt({
    ...baseReceipt,
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Unauthorized cross-tenant export download exposed foreign records.',
      terminalExchangeId: 'ex-1',
      preChainControlExchangeIds: ['ex-ctrl'],
    },
  }, transcript, { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY })
  assert.equal(wrongTermEx.confirmed, false)
  assert.equal(wrongTermEx.failedStage, 'terminal_impact')
  assert.equal(wrongTermEx.rejectedBy, 'terminal_exchange_invalid')

  // Valid summary + final-hop terminalExchangeId + clean denied control + foreign data -> PASSES!
  const valid = verifyCompositeReceipt({
    ...baseReceipt,
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Unauthorized cross-tenant export download exposed foreign tenant records.',
      terminalExchangeId: 'ex-2',
      preChainControlExchangeIds: ['ex-ctrl'],
    },
  }, transcript, { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY })
  assert.equal(valid.confirmed, true, valid.reason)
})

// ============================================================================
// 2. Hardened-twin decoy FP regression: cache prime + export job stub REJECTED
// ============================================================================

test('composite.verify & v8-oracle-families REJECT benign cache-prime + export-job-creation stubs with terminal_impact_unproven hint', () => {
  const cap = 'cap:hop_1:export_stub_handle'
  const decoyTranscript: HostSignedTranscript = {
    entries: [
      makeSignedEntry('ex-ctrl-403', { arm: 'control', method: 'POST', pathAndQuery: '/api/exports', status: 403, timestampMs: 900 }),
      makeSignedEntry('ex-prime', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/me/permissions', status: 200, timestampMs: 1000,
        emittedCapabilities: [cap],
        json: { userId: 'u1', tenantId: 'org_attacker', role: 'admin', permissions: ['exports:create'], cached: true },
      }),
      makeSignedEntry('ex-job-stub', {
        arm: 'probe', method: 'POST', pathAndQuery: '/api/exports', status: 202, timestampMs: 1100,
        consumedCapabilities: [cap],
        json: { jobId: 'exp-42', status: 'queued', tenantId: 'org_attacker', downloadUrl: '/api/exports/exp-42/download' },
      }),
    ],
  }

  assert.equal(isJobOrHandleStub({ jobId: 'exp-42', status: 'queued', downloadUrl: '/api/exports/exp-42/download' }, undefined, 202, 'POST'), true)
  assert.equal(isJobOrHandleStub({ userId: 'u1', tenantId: 'org_attacker', role: 'admin', permissions: ['exports:create'], cached: true }, undefined, 200, 'GET'), true)
  assert.equal(isJobOrHandleStub({ tenantId: 'org_target', records: [{ id: 'inv-1', amount: 500 }] }, undefined, 200, 'GET'), false)

  for (const vulnClass of ['parser_cache_differential', 'dual_tenant_abac', 'CWE-444', 'CWE-639']) {
    const decoyReceipt = {
      chainId: `chain-decoy-${vulnClass}`,
      terminalVulnClass: vulnClass,
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/me/permissions' }, exchangeIds: ['ex-prime'], claimedDelta: 'Primed permission cache on own tenant.' },
        { hopId: 'hop_2', surface: 'http', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/api/exports' }, exchangeIds: ['ex-job-stub'], claimedDelta: 'Created export job stub without downloading foreign data.' },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
      terminalImpact: {
        terminalHopId: 'hop_2',
        summary: 'Cache prime enabled export job creation stub on target.',
        terminalExchangeId: 'ex-job-stub',
        preChainControlExchangeIds: ['ex-ctrl-403'],
      },
      replayMode: 'fresh_clean_replay',
    }
    const res = verifyCompositeReceipt(decoyReceipt, decoyTranscript, { attackerPersonas: ['member_attacker'], signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, false, `Decoy stub must be REJECTED for ${vulnClass}`)
    assert.equal(res.failedStage, 'terminal_impact')
    assert.equal(res.rejectedBy, 'terminal_impact_unproven')
    assert.match(res.missingEvidence?.join(' ') ?? '', /terminal_impact_unproven.*record_coverage/i)
  }

  // Also verify direct v8-oracle-families evaluators reject job creation stubs!
  const mkRec = (id: string, ts: number, status: number, extra: Partial<HostSignedRecord> = {}): HostSignedRecord => ({
    id, hostSignature: 'sig-1234567890abcdef', timestampMs: ts, status, ...extra,
  })
  const stubDual = evaluateDualTenantAbac({
    mode: 'dual_org_cache_bleed',
    actor: { actorId: 'dual_user', rolesByTenant: { org_attacker: 'admin', org_target: 'viewer' } },
    primeTenantId: 'org_attacker',
    targetTenantId: 'org_target',
    baselineDeniedControl: mkRec('c1', 1000, 403),
    primeAction: mkRec('p1', 1100, 200),
    bledAccess: mkRec('b1', 1200, 202, { method: 'POST', json: { jobId: 'exp-42', status: 'queued', downloadUrl: '/dl/exp-42' } }),
    targetRecordId: 'exp-42',
  })
  assert.equal(stubDual.satisfied, false)
  assert.equal(stubDual.reason, 'terminal_impact_unproven_intermediate_stub')

  const stubParser = evaluateParserCacheDifferential({
    mode: 'parser_differential',
    differentialKind: 'header_normalization',
    differentialFeature: 'x-tenant-override',
    impactKind: 'read',
    cleanControl: mkRec('pc1', 1000, 403),
    differentialProbe: mkRec('pp1', 1100, 201, { method: 'POST', json: { exportId: 'exp-9', status: 'created', signedUrl: 'https://cdn.example.test/exp-9' } }),
  })
  assert.equal(stubParser.satisfied, false)
  assert.equal(stubParser.reason, 'terminal_impact_unproven_intermediate_stub')
})

// ============================================================================
// 3. TS SDK `ctx.prove_composite` end-to-end via `verifyScript()`:
//    - 0 `claims_missing` on passing chains
//    - Rejected decoy chain surfaces `terminal_impact_unproven` (NEVER `claims_missing`)
// ============================================================================

test('TS SDK ctx.prove_composite auto-records claims in verifyScript(): full foreign-read passes, decoy stub rejects without claims_missing', async (t) => {
  const vulnFixture = await startDualTenantExportFixture({ hardenedTwin: false })
  t.after(() => vulnFixture.close())
  const decoyFixture = await startDualTenantExportFixture({ hardenedTwin: true })
  t.after(() => decoyFixture.close())

  const makeFactory = (origin: string) => {
    const grant = makeGrant(origin, [
      makePersona('dual_attacker', 'member (org_attacker)', 'tok-dual-attacker', origin),
    ])
    return createLocalAttemptFactory({
      sdkDir: SDK_DIR,
      createRpcOptions: () => ({
        broker: new RequestBroker(),
        grant,
        runId: 'run-v8-composite-fix',
        assignmentId: 'assign-composite-fix',
        targetOrigins: [origin],
        compositeVerifyOptions: { attackerPersonas: ['dual_attacker'] },
      }),
    })
  }

  // (A) TypeScript SDK — FULL 3-hop chain proving foreign-tenant data read + denied clean control -> CONFIRMED (0 claims_missing!)
  const tsFullCode = `
    const ctrl = await ctx.http_send('/api/exports/exp-foreign-99/download', { as: 'dual_attacker', role: 'control' })
    const h1 = await ctx.http_send('/api/me/permissions', { as: 'dual_attacker', role: 'probe' })
    const cacheCap = await ctx.seal_capability({ exchange: h1, hopReceiptId: '1', slot: 'cache_tok', jsonPath: '$.cacheToken', kind: 'header_secret', defaultHeaderName: 'x-cache-token' })
    const h2 = await ctx.http_send('/api/exports', { method: 'POST', as: 'dual_attacker', capability: { handle: cacheCap.handle, target: 'header', headerName: 'x-cache-token' }, role: 'probe' })
    const cap = await ctx.seal_capability({ exchange: h2, hopReceiptId: '2', slot: 'export_tok', jsonPath: '$.exportToken', kind: 'header_secret', defaultHeaderName: 'x-export-token' })
    const h3 = await ctx.http_send('/api/exports/exp-foreign-99/download', { as: 'dual_attacker', capability: { handle: cap.handle, target: 'header', headerName: 'x-export-token' }, role: 'probe' })
    const verdict = await ctx.prove_composite({
      chainId: 'chain-ts-dual-abac-full',
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ctx.targetOrigin, method: 'GET', pathAndQuery: '/api/me/permissions' }, exchangeIds: [h1.exchangeId], producedCapabilities: [cacheCap.handle], claimedDelta: 'Primed permission cache on own tenant.' },
        { hopId: 'hop_2', surface: 'http', target: { origin: ctx.targetOrigin, method: 'POST', pathAndQuery: '/api/exports' }, exchangeIds: [h2.exchangeId], consumedCapabilities: [cacheCap.handle], producedCapabilities: [cap.handle], claimedDelta: 'Created export handle.' },
        { hopId: 'hop_3', surface: 'http', target: { origin: ctx.targetOrigin, method: 'GET', pathAndQuery: '/api/exports/exp-foreign-99/download' }, exchangeIds: [h3.exchangeId], consumedCapabilities: [cap.handle], claimedDelta: 'Downloaded foreign org_target confidential invoice records.' },
      ],
      causalEdges: [
        { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cacheCap.handle },
        { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: cap.handle },
      ],
      terminalImpact: {
        terminalHopId: 'hop_3',
        summary: 'Cross-tenant download exposed confidential org_target invoice records after cache prime.',
        terminalExchangeId: h3.exchangeId,
        preChainControlExchangeIds: [ctrl.exchangeId],
      },
      replayMode: 'fresh_clean_replay',
    })
    if (!verdict.ok || ctx.claims.length < 1) throw new Error('expected auto-recorded composite claim: ' + JSON.stringify(verdict))
    return ctx.result({ title: 'Dual-tenant ABAC cross-org export disclosure (TS)' })
  `
  const tsPass = await verifyScript({
    candidate: { name: 'ts-full.ts', runtime: 'ts', code: tsFullCode, title: 'Dual-tenant ABAC cross-org export disclosure (TS)' },
    openAttempt: makeFactory(vulnFixture.origin),
  })
  assert.equal(tsPass.confirmed, true, `TS full chain failed: ${tsPass.reason} / ${tsPass.detail}`)
  assert.equal(tsPass.reason, 'confirmed')
  assert.ok(tsPass.attempts.every(a => a.claimCount >= 1))

  // (B) Hardened-twin decoy FP attempt via TypeScript SDK: cache prime + export job stub -> REJECTED with terminal_impact_unproven (NOT claims_missing!)
  const tsDecoyCode = `
    const ctrl = await ctx.http_send('/api/exports/exp-foreign-99/download', { as: 'dual_attacker', role: 'control' })
    const h1 = await ctx.http_send('/api/me/permissions', { as: 'dual_attacker', role: 'probe' })
    const cacheCap = await ctx.seal_capability({ exchange: h1, hopReceiptId: '1', slot: 'cache_tok', jsonPath: '$.cacheToken', kind: 'header_secret', defaultHeaderName: 'x-cache-token' })
    const h2 = await ctx.http_send('/api/exports', { method: 'POST', as: 'dual_attacker', capability: { handle: cacheCap.handle, target: 'header', headerName: 'x-cache-token' }, role: 'probe' })
    const verdict = await ctx.prove_composite({
      chainId: 'chain-ts-decoy-stub',
      terminalVulnClass: 'parser_cache_differential',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ctx.targetOrigin, method: 'GET', pathAndQuery: '/api/me/permissions' }, exchangeIds: [h1.exchangeId], producedCapabilities: [cacheCap.handle], claimedDelta: 'Primed permission cache.' },
        { hopId: 'hop_2', surface: 'http', target: { origin: ctx.targetOrigin, method: 'POST', pathAndQuery: '/api/exports' }, exchangeIds: [h2.exchangeId], consumedCapabilities: [cacheCap.handle], claimedDelta: 'Created export job stub.' },
      ],
      causalEdges: [
        { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cacheCap.handle },
      ],
      terminalImpact: {
        terminalHopId: 'hop_2',
        summary: 'Cache prime enabled export job creation stub on hardened twin.',
        terminalExchangeId: h2.exchangeId,
        preChainControlExchangeIds: [ctrl.exchangeId],
      },
      replayMode: 'fresh_clean_replay',
    })
    if (verdict.ok !== false) throw new Error('expected decoy rejection: ' + JSON.stringify(verdict))
    return ctx.result({ title: 'Hardened twin decoy stub attempt (TS)' })
  `
  const tsDecoy = await verifyScript({
    candidate: { name: 'ts-decoy.ts', runtime: 'ts', code: tsDecoyCode, title: 'Hardened twin decoy stub attempt (TS)' },
    openAttempt: makeFactory(decoyFixture.origin),
  })
  assert.equal(tsDecoy.confirmed, false)
  assert.notEqual(tsDecoy.reason, 'claims_missing', 'Rejected composite.verify must surface exact composite rejection, NEVER claims_missing')
  assert.equal(tsDecoy.reason, 'oracle_failed')
  assert.equal(tsDecoy.rejectedBy, 'terminal_impact_unproven')
  assert.match(tsDecoy.missingEvidence.join(' '), /terminal_impact_unproven/i)

  // (C) Forged client-only composite_receipt claim without host verification MUST fail closed!
  const store = new TranscriptStore()
  const forged = evaluateClaims(store, [{
    kind: 'composite_receipt',
    verificationId: 'gc-forged-0000',
    chainId: 'chain-forged',
    terminalVulnClass: 'dual_tenant_abac',
    exchangeIds: [],
  }])
  assert.equal(forged.passed, false)
  assert.equal(forged.rejectedBy, 'composite_receipt')
})
