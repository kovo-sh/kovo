/**
 * Move A Part 3b (WS-12 + WS-13) regression suite:
 *   - R2-H-15 / H-19: positive-health allowlist `classifyRetestHealth` + side-tagged `ctx.require`
 *   - R2-H-14 / H-18: CWE-first `receiptVulnClassFor` + fail-closed keyword conflicts + OOB `canary.triggered`
 *   - H-5: default-deny `envelopeTrust` on `recipe` and `agentScript` envelopes
 *   - R2-H-29: linear verify-plane normalizers (< 20 ms on adversarial 100 KB inputs) + oversized value hashing
 *   - H-13 / H-17: drop declared-auth fallbacks in `verify-claims.ts`, BFLA planner `denied !== owner` + recipe abort
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import { performance } from 'node:perf_hooks'
import { RequestBroker } from '../src/server/broker.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { floorRecipe, runFloorRecipe } from '../src/server/floor-recipes.ts'
import type { AccessBoundaryArgs, FloorRecipeExecution } from '../src/server/floor-recipes.ts'
import {
  buildReplayReceipt,
  classifyRetestHealth,
  planFloorRecipe,
  receiptVulnClassFor,
  retestPersistedRecipe,
} from '../src/server/floor-recipe-engine.ts'
import { retestReplaySpec, verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { TranscriptStore, causalFingerprints, evaluateClaims, normalizeDynamic } from '../src/server/verify-claims.ts'
import { normalizeStructuralTokens, structuralDiff } from '../src/server/verify-support.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'http://127.0.0.1:4499'

function authzGrant() {
  const personas = new Map([
    ['admin', {
      handle: 'admin',
      roleLabel: 'Admin (acme)',
      authKind: 'bearer' as const,
      originAllowlist: [ORIGIN],
      secret: 'movea-admin-tok',
      session: { headerName: 'Authorization', headerType: 'Bearer', value: 'movea-admin-tok' },
    }],
    ['member', {
      handle: 'member',
      roleLabel: 'Member (acme)',
      authKind: 'bearer' as const,
      originAllowlist: [ORIGIN],
      secret: 'movea-member-tok',
      session: { headerName: 'Authorization', headerType: 'Bearer', value: 'movea-member-tok' },
    }],
    ['viewer', {
      handle: 'viewer',
      roleLabel: 'Viewer (acme)',
      authKind: 'bearer' as const,
      originAllowlist: [ORIGIN],
      secret: 'movea-viewer-tok',
      session: { headerName: 'Authorization', headerType: 'Bearer', value: 'movea-viewer-tok' },
    }],
  ])
  return makeLabGrant(ORIGIN, { tier: 3, personas: personas as never })
}

// ============================================================================
// 1. R2-H-15 / H-19: Allowlist-based `classifyRetestHealth` + tagged requires
// ============================================================================

test('R2-H-15 / H-19: access_boundary status matrix never marks 5xx, 429, 302, auth-401, or 2xx probe as fixed', async () => {
  const accessEnv = {
    recipeId: 'access_boundary' as const,
    args: {
      origin: ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/items/1',
      vulnClass: 'bola',
      owner: { handle: 'admin', role: 'admin' as const, tenant: 'acme' },
      probe: { handle: 'member', role: 'member' as const, tenant: 'acme' },
      denied: { handle: 'viewer', role: 'viewer' as const, tenant: 'acme' },
    },
  }
  const runWith = async (statuses: readonly number[]) => {
    let idx = 0
    const broker = new RequestBroker({
      transport: async () => {
        const status = statuses[idx++] ?? 500
        return {
          status,
          headers: { 'content-type': 'application/json' },
          body: status >= 200 && status < 300 ? '{"id":1,"secret":"x"}' : '{"error":"nope"}',
        }
      },
    })
    return retestPersistedRecipe({
      envelope: accessEnv,
      specKind: 'http_chain',
      vulnClass: 'bola',
      endpoint: '/api/items/1',
      origin: ORIGIN,
      broker,
      grant: authzGrant(),
      signal: AbortSignal.timeout(5_000),
    })
  }

  // Probe-side 5xx, 429, 302, authenticated 401, and control-side 429/302/500 must ALL be inconclusive.
  for (const statuses of [
    [200, 403, 500],
    [200, 403, 503],
    [200, 403, 429],
    [200, 403, 302],
    [200, 403, 401],
    [429, 403, 403],
    [302, 403, 403],
    [200, 429, 403],
    [200, 302, 403],
  ] as const) {
    const res = await runWith(statuses)
    assert.equal(res.verdict, 'inconclusive', `statuses ${statuses.join('/')} must be inconclusive, got ${res.verdict}`)
    const health = res.replay.evidencePayload.retestHealth as { healthy: boolean; code: string } | undefined
    assert.equal(health?.healthy, false, `retestHealth must be persisted as unhealthy for ${statuses.join('/')}`)
  }

  // Healthy baseline: entitled 200, denied peer 403, authenticated probe 403 -> fixed.
  const fixedRes = await runWith([200, 403, 403])
  assert.equal(fixedRes.verdict, 'fixed', fixedRes.replay.outcome.reason ?? '')
  assert.equal((fixedRes.replay.evidencePayload.retestHealth as { healthy: boolean }).healthy, true)
})

test('R2-H-15 / H-19: boolean probe 5xx, status tautology 429, HTML readback, and no-control recipes return inconclusive', async () => {
  // (a) Boolean mode probe 500 -> inconclusive (and tagged harness failure)
  const boolBroker500 = new RequestBroker({
    transport: async url => url.searchParams.get('q')?.includes('AND')
      ? { status: 500, headers: { 'content-type': 'text/plain' }, body: 'internal error' }
      : { status: 200, headers: { 'content-type': 'application/json' }, body: '{"rows":[1,2]}' },
  })
  const bool500 = await retestPersistedRecipe({
    envelope: {
      recipeId: 'boolean_or_timing',
      args: {
        origin: ORIGIN,
        method: 'GET',
        pathAndQuery: '/api/search?q=widget',
        controlPathAndQuery: '/api/search?q=widget',
        probePathAndQuery: '/api/search?q=widget%27%20AND%201%3D2',
        param: 'q',
        vulnClass: 'sqli',
        mode: 'boolean',
        rounds: 2,
      },
    },
    specKind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    endpoint: '/api/search',
    origin: ORIGIN,
    broker: boolBroker500,
    grant: authzGrant(),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(bool500.verdict, 'inconclusive')
  assert.ok(bool500.execution?.failure?.requireFailures?.some(f => f.role === 'non_error_arm' && f.side === 'harness'))

  // (b) Status mode tautology 429 -> inconclusive
  const statusBroker429 = new RequestBroker({
    transport: async url => {
      const q = url.searchParams.get('q') ?? ''
      if (q.includes('1=1')) return { status: 429, headers: {}, body: 'rate limited' }
      if (q.includes('1=2')) return { status: 404, headers: {}, body: 'not found' }
      return { status: 200, headers: {}, body: 'ok' }
    },
  })
  const status429 = await retestPersistedRecipe({
    envelope: {
      recipeId: 'boolean_or_timing',
      args: {
        origin: ORIGIN,
        method: 'GET',
        pathAndQuery: '/api/item?q=1',
        controlPathAndQuery: '/api/item?q=1',
        probePathAndQuery: '/api/item?q=1%20AND%201=1',
        contradictionPathAndQuery: '/api/item?q=1%20AND%201=2',
        param: 'q',
        vulnClass: 'sqli_status',
        mode: 'status',
        rounds: 2,
      },
    },
    specKind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    endpoint: '/api/item',
    origin: ORIGIN,
    broker: statusBroker429,
    grant: authzGrant(),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(status429.verdict, 'inconclusive')

  // (c) Persisted mutation with HTML post_mutation_read -> control require failed -> inconclusive
  let pmStep = 0
  const htmlReadbackBroker = new RequestBroker({
    transport: async () => {
      pmStep += 1
      if (pmStep === 1) return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"role":"member"}' }
      if (pmStep === 2) return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
      return { status: 200, headers: { 'content-type': 'text/html' }, body: '<html><body>Maintenance</body></html>' }
    },
  })
  const pmHtml = await retestPersistedRecipe({
    envelope: {
      recipeId: 'persisted_mutation',
      args: {
        origin: ORIGIN,
        method: 'PATCH',
        pathAndQuery: '/api/profile',
        vulnClass: 'mass_assignment',
        actor: { handle: 'member', role: 'member', tenant: 'acme' },
        body: { role: 'admin' },
      },
    },
    specKind: 'http_chain',
    vulnClass: 'mass_assignment',
    endpoint: '/api/profile',
    origin: ORIGIN,
    broker: htmlReadbackBroker,
    grant: authzGrant(),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(pmHtml.verdict, 'inconclusive')
  assert.ok(pmHtml.execution?.failure?.requireFailures?.some(f => f.role === 'post_mutation_read' && f.side === 'control'))

  // (d) No-control recipes: race_burst (all 429, all 500, and even all 409) and oob_callback MUST be inconclusive
  for (const burstStatus of [429, 500, 409] as const) {
    const raceBroker = new RequestBroker({
      transport: async () => ({ status: burstStatus, headers: { 'content-type': 'application/json' }, body: '{"err":true}' }),
    })
    const raceRes = await retestPersistedRecipe({
      envelope: {
        recipeId: 'race_burst',
        args: {
          origin: ORIGIN,
          method: 'POST',
          pathAndQuery: '/api/redeem',
          vulnClass: 'race_double_spend',
          actor: { handle: 'member', role: 'member', tenant: 'acme' },
          body: { code: 'PROMO' },
          burst: 4,
        },
      },
      specKind: 'race_burst',
      vulnClass: 'race_double_spend',
      endpoint: '/api/redeem',
      origin: ORIGIN,
      broker: raceBroker,
      grant: authzGrant(),
      signal: AbortSignal.timeout(5_000),
    })
    assert.equal(raceRes.verdict, 'inconclusive', `race_burst status=${burstStatus} must be inconclusive`)
  }

  // (e) oob_callback (no control arm) -> inconclusive
  const oobBroker = new RequestBroker({
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"queued":true}' }),
  })
  const oobRes = await retestPersistedRecipe({
    envelope: {
      recipeId: 'oob_callback',
      args: {
        origin: ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/fetch',
        vulnClass: 'ssrf',
        token: 'kovo-canary-0123456789abcdef01234567',
      },
    },
    specKind: 'http_chain',
    vulnClass: 'ssrf',
    endpoint: '/api/fetch',
    origin: ORIGIN,
    broker: oobBroker,
    grant: authzGrant(),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(oobRes.verdict, 'inconclusive')
})

test('R2-H-15 / H-19: classifyRetestHealth rejects step_budget, 2xx access probe, and oracle_disagreement', () => {
  const baseExecution = (overrides: Partial<FloorRecipeExecution>): FloorRecipeExecution => ({
    result: {
      recipeId: 'access_boundary',
      confirmed: false,
      steps: [
        { exchangeId: 'e1', role: 'entitled_read', arm: 'control', method: 'GET', pathAndQuery: '/a', status: 200, durationMs: 5 },
        { exchangeId: 'e2', role: 'denied_control', arm: 'control', method: 'GET', pathAndQuery: '/a', status: 403, durationMs: 5 },
        { exchangeId: 'e3', role: 'probe_request', arm: 'probe', method: 'GET', pathAndQuery: '/a', status: 200, durationMs: 5 },
      ],
      exchangeIds: ['e1', 'e2', 'e3'],
      oobEventIds: [],
      transcript: {
        entries: [
          { exchangeId: 'e3', step: { id: 's3', arm: 'probe', method: 'GET', route: '/a', status: 200, actor: { handle: 'member', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null } } },
        ],
      },
      verification: { confirmed: false, vulnClass: 'bola', rule: 'impact', reason: 'oracle rejected role differential', observed: '', expected: '' },
    },
    receipt: { vulnClass: 'bola', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/a' }, exchangeIds: ['e1', 'e2', 'e3'], oobEventIds: [], browserTraceIds: [], claimedDelta: '' } as never,
    failure: { code: 'receipt_rejected', message: 'oracle rejected role differential', missingRoles: ['role_or_tenant_differential'] },
    ...overrides,
  })

  // 2xx probe on access_boundary is NEVER fixed
  const twoXxProbe = classifyRetestHealth(baseExecution({}))
  assert.equal(twoXxProbe.healthy, false)
  assert.equal(twoXxProbe.code, 'access_probe_not_denied')

  // step_budget_exceeded is NEVER fixed
  const budget = classifyRetestHealth(baseExecution({
    failure: { code: 'step_budget_exceeded', message: 'exceeded 16 steps', missingRoles: ['step_budget'] },
  }))
  assert.equal(budget.healthy, false)
  assert.equal(budget.code, 'step_budget')

  // Unstable boolean baseline (oracle_disagreement) is NEVER fixed
  const unstableBool = classifyRetestHealth({
    ...baseExecution({}),
    result: {
      ...baseExecution({}).result,
      recipeId: 'boolean_or_timing',
      steps: [
        { exchangeId: 'c1', role: 'boolean_control', arm: 'control', method: 'GET', pathAndQuery: '/s?q=1', status: 200, durationMs: 5 },
        { exchangeId: 'p1', role: 'boolean_probe', arm: 'probe', method: 'GET', pathAndQuery: '/s?q=2', status: 200, durationMs: 5 },
      ],
      verification: { confirmed: false, vulnClass: 'sqli', rule: 'boolean', reason: 'control arm was unstable (moving baseline)', observed: '', expected: '' },
    },
    failure: { code: 'receipt_rejected', message: 'control arm was unstable', missingRoles: ['stable_differential'] },
  })
  assert.equal(unstableBool.healthy, false)
  assert.equal(unstableBool.code, 'oracle_disagreement')
})

// ============================================================================
// 2. R2-H-14: CWE-first `receiptVulnClassFor` + `canary.triggered`
// ============================================================================

test('R2-H-14: receiptVulnClassFor classifies strictly by CWE first and fails closed on keyword conflicts', () => {
  const makeSpec = (overrides: Partial<DeclarativeReplaySpec>): DeclarativeReplaySpec => ({
    version: 1,
    kind: 'http_chain',
    origin: ORIGIN,
    title: 'Neutral finding title',
    category: 'general',
    cwe: 'CWE-89',
    severity: 'high',
    severityRationale: 'test',
    impact: 'Neutral impact description',
    remediation: 'fix',
    recheckInstructions: 'recheck',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    steps: [
      { id: 'c', role: 'control', description: 'c', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/x', followRedirects: false } },
      { id: 'p', role: 'probe', description: 'p', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/x', followRedirects: false } },
    ],
    ...overrides,
  } as DeclarativeReplaySpec)

  // Unmodelled CWE-22 fails closed even with SSRF/redirect/XXE wording
  assert.equal(receiptVulnClassFor(makeSpec({ cwe: 'CWE-22', title: 'Path traversal read' })), null)
  assert.equal(receiptVulnClassFor(makeSpec({ cwe: 'CWE-22', title: 'SSRF via file fetch', impact: 'Server-side request to internal host' })), null)
  assert.equal(receiptVulnClassFor(makeSpec({ cwe: 'CWE-22', title: 'Open redirect via path' })), null)

  // CWE-89 with conflicting SSRF or open-redirect wording fails closed instead of swapping class
  assert.equal(receiptVulnClassFor(makeSpec({ cwe: 'CWE-89', title: 'SSRF in search parameter' })), null)
  assert.equal(receiptVulnClassFor(makeSpec({ cwe: 'CWE-89', title: 'Open redirect via SQLi' })), null)
  assert.equal(receiptVulnClassFor(makeSpec({ cwe: 'CWE-639', title: 'SQL injection IDOR' })), null)

  // Clean CWE matches succeed
  assert.equal(receiptVulnClassFor(makeSpec({ cwe: 'CWE-89', title: 'SQL injection in search' })), 'injection')
  assert.equal(receiptVulnClassFor(makeSpec({ cwe: 'CWE-918', title: 'SSRF in webhook fetcher' })), 'ssrf')
  assert.equal(receiptVulnClassFor(makeSpec({ cwe: 'CWE-639', title: 'Cross-tenant invoice read', impact: 'Exposes another tenant invoice' })), 'bola')
  assert.equal(receiptVulnClassFor(makeSpec({ cwe: 'CWE-601', title: 'Open redirect on /next' })), 'open_redirect')

  // R2-H-14: buildReplayReceipt refuses to build an OOB SSRF receipt when canary.triggered !== true
  const token = 'kovo-canary-abcdef0123456789abcdef01'
  const oobSpec = makeSpec({ cwe: 'CWE-918', title: 'SSRF via callback URL', impact: 'Server-side request forgery' })
  const untriggered = buildReplayReceipt({
    spec: oobSpec,
    evidencePayload: {
      canary: { triggered: false, token, callbackId: 'cb-1' },
      steps: { p: { exchangeId: 'ex-1', status: 200, requestBody: token } },
    },
    exchangeIds: ['ex-1'],
    exchanges: [{ origin: ORIGIN, method: 'POST', pathAndQuery: `/fetch?u=${token}`, status: 200, body: 'ok', respHeaders: {}, durationMs: 5 } as never],
    canaryBroker: { checkCanary: () => ({ hit: true, hits: [{ token }], detail: { timestamp: Date.now() } }) as never },
  })
  assert.equal(untriggered, null, 'SSRF receipt must require canary.triggered === true')
})

// ============================================================================
// 3. H-5: Default-deny `envelopeTrust` in `replay-verifier.ts`
// ============================================================================

test('H-5: verifyReplaySpec and retestReplaySpec default-deny recipe and agentScript envelopes when envelopeTrust is omitted', async () => {
  let requestsSent = 0
  const broker = new RequestBroker({
    transport: async url => {
      requestsSent += 1
      const q = url.searchParams.get('q') ?? ''
      const body = q.includes('1=2') ? '{"items":[]}' : '{"items":["alpha","beta"]}'
      return { status: 200, headers: { 'content-type': 'application/json' }, body }
    },
  })
  const backend = new LocalJqBackend()
  const grant = authzGrant()
  const signal = AbortSignal.timeout(5_000)

  const recipeSpec = {
    version: 1,
    kind: 'sql_boolean_diff',
    origin: ORIGIN,
    title: 'Boolean SQLi',
    category: 'sqli',
    cwe: 'CWE-89',
    severity: 'high',
    severityRationale: 'High severity SQL injection test rationale.',
    impact: 'Boolean differential',
    remediation: 'Parameterize query',
    recheckInstructions: 'Replay the recipe',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    targetOrigin: ORIGIN,
    method: 'GET',
    pathAndQuery: '/search?q=ok',
    paramName: 'q',
    paramLocation: 'query',
    baselineValue: 'ok',
    quoteStyle: 'single',
    recipe: {
      recipeId: 'boolean_or_timing',
      args: {
        origin: ORIGIN,
        method: 'GET',
        pathAndQuery: '/search?q=ok',
        controlPathAndQuery: '/search?q=ok%27%20AND%201%3D1--%20-',
        probePathAndQuery: '/search?q=ok%27%20AND%201%3D2--%20-',
        param: 'q',
        vulnClass: 'sqli',
        mode: 'boolean',
        rounds: 2,
      },
    },
  } as unknown as DeclarativeReplaySpec

  // Omitted envelopeTrust on verifyReplaySpec -> denied, 0 requests
  const verifyOmitted = await verifyReplaySpec({ spec: recipeSpec, broker, backend, grant, signal })
  assert.equal(verifyOmitted.verdict, 'inconclusive')
  assert.match(verifyOmitted.outcome.reason ?? '', /Untrusted model-supplied recipe/i)
  assert.equal(requestsSent, 0)

  // Omitted envelopeTrust on retestReplaySpec (recipe) -> denied, 0 requests
  const retestRecipeOmitted = await retestReplaySpec({ spec: recipeSpec, broker, backend, grant, signal })
  assert.equal(retestRecipeOmitted.verdict, 'inconclusive')
  assert.match(retestRecipeOmitted.replay.outcome.reason ?? '', /Untrusted model-supplied recipe/i)
  assert.equal(requestsSent, 0)

  // Omitted envelopeTrust on retestReplaySpec (agentScript) -> denied, never fixed
  const scriptSpec = {
    version: 1,
    kind: 'http_chain',
    origin: ORIGIN,
    title: 'Agent script proof',
    category: 'bola',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'High severity BOLA test rationale.',
    impact: 'Broken object level authorization',
    remediation: 'Check ownership',
    recheckInstructions: 'Replay the proof',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    steps: [
      { id: 'c', role: 'control', description: 'c', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/x', followRedirects: false } },
      { id: 'p', role: 'probe', description: 'p', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/x', followRedirects: false } },
    ],
    agentScript: {
      kind: 'agent_script',
      runtime: 'ts',
      script: 'return { ok: false, claims: [] }',
      scriptSha256: 'a'.repeat(64),
      verdict: 'confirmed',
      exchangeIds: [],
      transcriptDigests: [],
      confirmedAt: Date.now(),
    },
  } as unknown as DeclarativeReplaySpec
  const retestScriptOmitted = await retestReplaySpec({ spec: scriptSpec, broker, backend, grant, signal })
  assert.equal(retestScriptOmitted.verdict, 'inconclusive')
  assert.match(retestScriptOmitted.replay.outcome.reason ?? '', /Untrusted model-supplied agentScript/i)
  assert.equal(requestsSent, 0)

  // Explicit host_persisted succeeds cleanly
  const trusted = await verifyReplaySpec({ spec: recipeSpec, broker, backend, grant, signal, envelopeTrust: 'host_persisted' })
  assert.equal(trusted.verdict, 'confirmed', trusted.outcome.reason ?? '')
  assert.ok(requestsSent >= 4)
})

// ============================================================================
// 4. R2-H-29: Linear verify-plane normalizers (< 20 ms on 100 KB inputs)
// ============================================================================

test('R2-H-29: adversarial 100 KB inputs normalize in < 20 ms and oversized observed values are hashed', () => {
  const advHtml1 = '<meta name="' + 'csrf'.repeat(25_000) + '" content="tok123">'
  const advHtml2 = '<input name="' + 'a'.repeat(100_000)
  const advIds1 = 'ab_' + 'a1'.repeat(50_000)
  const advIds2 = 'ord_' + '9a'.repeat(50_000) + '_xy'

  const t0 = performance.now()
  normalizeStructuralTokens(advHtml1)
  normalizeStructuralTokens(advHtml2)
  structuralDiff(advHtml1, advHtml2)
  const dtStruct = performance.now() - t0
  assert.ok(dtStruct < 20, `normalizeStructuralTokens + structuralDiff took ${dtStruct.toFixed(2)} ms (expected < 20 ms)`)

  const t1 = performance.now()
  const normAdv1 = normalizeDynamic(advIds1, 'nonce-abc')
  const normAdv2 = normalizeDynamic(advIds2, 'nonce-abc')
  const dtDyn = performance.now() - t1
  assert.ok(dtDyn < 20, `normalizeDynamic took ${dtDyn.toFixed(2)} ms (expected < 20 ms)`)
  assert.match(normAdv1, /<sha256:[0-9a-f]{16}:\d+>$/)
  assert.match(normAdv2, /<sha256:[0-9a-f]{16}:\d+>$/)

  // Functional correctness preserved for normal tokens and tags
  const htmlA = '<form><input type="hidden" name="csrf_token" value="rot-alpha-111"><span>Hello</span></form>'
  const htmlB = '<form><input type="hidden" name="csrf_token" value="rot-beta-222"><span>Hello</span></form>'
  assert.equal(structuralDiff(htmlA, htmlB).normalizedEqual, true)
  assert.equal(
    normalizeDynamic('order mh_ord_9_5ed534 job mh_job_export_38_c4f8e5 [redacted:cap:hop_1:id]'),
    normalizeDynamic('order mh_ord_10_7ab912 job mh_job_export_39_a1b2c3 [redacted]'),
  )
  assert.equal(
    normalizeDynamic('CWE-639 vs CWE-1321 with SHA-256 and AES-256 hop_1 tenant_1'),
    'CWE-639 vs CWE-1321 with SHA-256 and AES-256 hop_1 tenant_1',
  )

  // Oversized observed string (> 2 KB) is hashed in causalFingerprints in < 20 ms
  const store = new TranscriptStore()
  const rec = store.record({
    op: 'http',
    startedAt: 1,
    durationMs: 5,
    request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/big', headers: {}, bodyBytes: 0, bodySha256: '', nonce: 'n-obs-1' },
    response: { status: 200, mediaType: 'application/json', headers: {}, bodyBytes: 100_000, bodySha256: 'abc' },
    body: 'x',
  })
  const t2 = performance.now()
  const fps = causalFingerprints(store, [{
    claim: { kind: 'jsonpath', exchangeId: rec.exchangeId, path: '$.blob', equals: 'x' },
    passed: true,
    detail: 'ok',
    observed: { value: 'payload_' + 'a1'.repeat(50_000) },
  }], 'n-obs-1')
  const dtFp = performance.now() - t2
  assert.ok(dtFp < 20, `causalFingerprints oversized observed took ${dtFp.toFixed(2)} ms (expected < 20 ms)`)
  const obsVal = (fps[0]?.observed as { value?: string })?.value ?? ''
  assert.match(obsVal, /^<hash:[0-9a-f]{16}:\d+>$/)
})

// ============================================================================
// 5. H-13 / H-17: Drop declared fallbacks in verify-claims + BFLA denied !== owner
// ============================================================================

test('H-13: verify-claims drops untrusted declared ambient/requestBody/oracleEvents fallbacks even without factLog', () => {
  const store = new TranscriptStore()
  const pre = store.record({
    op: 'http',
    startedAt: 1,
    durationMs: 5,
    request: {
      origin: ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/v1/profile',
      headers: { authorization: 'Bearer real-tok' },
      bodyBytes: 0,
      bodySha256: '',
      nonce: 'n1',
      personaHandle: 'member',
      actorRoleLabel: 'member (acme)',
    },
    response: { status: 200, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, bodyBytes: 24, bodySha256: 'h1' },
    body: '{"email":"old@acme.test"}',
  })
  const prb = store.record({
    op: 'http',
    startedAt: 2,
    durationMs: 5,
    request: {
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/v1/profile',
      headers: { authorization: 'Bearer real-tok', origin: 'https://evil.example' },
      bodyBytes: 25,
      bodySha256: 'h2',
      nonce: 'n1',
      personaHandle: 'member',
      actorRoleLabel: 'member (acme)',
    },
    response: { status: 200, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, bodyBytes: 24, bodySha256: 'h3' },
    body: '{"email":"new@acme.test"}',
    rawRequestBody: '{"email":"new@acme.test"}',
  })
  const post = store.record({
    op: 'http',
    startedAt: 3,
    durationMs: 5,
    request: {
      origin: ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/v1/profile',
      headers: { authorization: 'Bearer real-tok' },
      bodyBytes: 0,
      bodySha256: '',
      nonce: 'n1',
      personaHandle: 'member',
      actorRoleLabel: 'member (acme)',
    },
    response: { status: 200, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, bodyBytes: 24, bodySha256: 'h4' },
    body: '{"email":"new@acme.test"}',
  })

  // Calling evaluateClaims WITHOUT factLog must STILL ignore claim.ambient, claim.oracleEvents, and claim.requestBody!
  const result = evaluateClaims(store, [{
    kind: 'impact',
    impactClass: 'csrf',
    beforeExchangeId: pre.exchangeId,
    probeExchangeId: prb.exchangeId,
    afterExchangeId: post.exchangeId,
    ambient: { kind: 'cookie', sameSite: 'None' },
    oracleEvents: ['csrf_state_change'],
    requestBody: { email: 'spoofed@evil.example' },
  }])
  assert.equal(result.passed, false, 'Bearer request must not pass CSRF via declared ambient/oracleEvents fallbacks')
})

test('H-17: BFLA recipe planner never sets denied === owner on the same path, and access_boundary aborts on self-owner', async () => {
  const bflaHyp = {
    intent: 'bfla',
    probeClass: 'authz_diff',
    method: 'GET',
    pathAndQuery: '/api/admin/audit-logs',
    ownerPersona: 'admin',
    otherPersona: 'member',
    functionLevel: true,
    endpoint: { origin: ORIGIN, pathTemplate: '/api/admin/audit-logs', method: 'GET' },
  }
  const probeResult = {
    verdict: 'signal',
    details: { matrix: [] },
    anomalies: [{ type: 'unauthorized_access', actor: 'other_persona', method: 'GET', status: 200, functionLevel: true }],
  }

  // With 3 personas (admin, member, viewer): denied must be viewer (distinct lower-role peer, never owner!)
  const planWithPeer = planFloorRecipe({
    hypothesis: bflaHyp as never,
    probe: probeResult as never,
    specKind: 'http_chain',
    vulnClass: 'bfla',
    personas: [
      { handle: 'admin', roleLabel: 'Admin (acme)', tenant: 'acme' },
      { handle: 'member', roleLabel: 'Member (acme)', tenant: 'acme' },
      { handle: 'viewer', roleLabel: 'Viewer (acme)', tenant: 'acme' },
    ] as never,
  })
  assert.ok(planWithPeer && !planWithPeer.skipReason, `expected BFLA plan, got ${JSON.stringify(planWithPeer)}`)
  assert.equal(planWithPeer.recipeId, 'access_boundary')
  const args = planWithPeer.args as AccessBoundaryArgs
  assert.equal(args.owner.handle, 'admin')
  assert.equal(args.probe.handle, 'member')
  assert.equal(args.denied?.handle, 'viewer')
  assert.notEqual(args.denied?.handle, args.owner.handle)

  // With ONLY 2 personas (admin, member) and no distinct lower-role peer: must skip, NEVER set denied === owner!
  const planNoPeer = planFloorRecipe({
    hypothesis: bflaHyp as never,
    probe: probeResult as never,
    specKind: 'http_chain',
    vulnClass: 'bfla',
    personas: [
      { handle: 'admin', roleLabel: 'Admin (acme)', tenant: 'acme' },
      { handle: 'member', roleLabel: 'Member (acme)', tenant: 'acme' },
    ] as never,
  })
  assert.ok(planNoPeer?.skipReason, 'BFLA read without a distinct lower-role peer must return skipReason instead of denied=owner')

  // Recipe invariant: access_boundary with denied.handle === owner.handle on same method/path aborts with 0 requests!
  let sent = 0
  const exec = await runFloorRecipe(floorRecipe('access_boundary', {
    origin: ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/admin/audit-logs',
    vulnClass: 'bfla',
    owner: { handle: 'admin', role: 'admin', tenant: 'acme' },
    probe: { handle: 'member', role: 'member', tenant: 'acme' },
    denied: { handle: 'admin', role: 'admin', tenant: 'acme' },
  }), {
    request: async () => {
      sent += 1
      return { status: 200, body: '{}' }
    },
  })
  assert.equal(exec.result.confirmed, false)
  assert.equal(exec.failure?.code, 'recipe_error')
  assert.equal(sent, 0, 'access_boundary invariant must abort before sending requests when denied === owner on same path')
})
