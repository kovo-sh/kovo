// v6 verifier hardening: semantic impact gates shared by the declarative replay path and the
// guardian_verify transcript oracle.
//
// Every fixture below models the acme-saas authorization policy: the tenant is the object boundary,
// roles rank owner > admin > member > viewer, the plan price is catalog-authoritative, and the
// session cookie is SameSite=Lax. The over-claims are the three triaged agentic false positives plus
// a mass-assignment echo; the positive cases are the planted impacts they were confused with.
//
// Defensive framing: these are authorized local differential probes against an intentional fixture.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { once } from 'node:events'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import {
  ROLE_RANK,
  assessAuthorizationImpact,
  assessBoundary,
  assessBusinessLogicImpact,
  assessCsrfImpact,
  assessMarkupImpact,
  assessMassAssignmentImpact,
  classifyBoundaryClaim,
  classifyImpactDescriptor,
  parseRoleLabel,
  roleRank,
} from '../src/server/oracle-invariants.ts'
import {
  VerifyRpcServer,
  evaluateClaims,
  parseVerifyScriptResult,
} from '../src/server/verify-rpc.ts'
import type { VerifyClaim } from '../src/server/verify-rpc.ts'
import { request as httpRequest } from 'node:http'

type Json = Record<string, unknown>

// ---------------------------------------------------------------------------
// Fixture: acme-style tenant/role/plan/session surface
// ---------------------------------------------------------------------------

interface FixtureOptions {
  /** Planted invoice-write BOLA: cross-tenant PATCH persists instead of answering 404. */
  crossTenantInvoiceWrite?: boolean
  /** Planted invoice-read BOLA: cross-tenant GET returns the record instead of 404. */
  crossTenantRead?: boolean
  /** Planted CSRF: the settings route accepts a token-less cookie-authenticated write. */
  csrfTokenBypass?: boolean
  /** Planted admin BFLA: a viewer may reach /api/admin/audit. */
  adminBfla?: boolean
  /** Render stored markup as an executable payload instead of an inert presentation tag. */
  reportActiveMarkup?: boolean
}

interface Fixture {
  origin: string
  close(): Promise<void>
  state: {
    projects: Map<string, Json>
    invoices: Map<string, Json>
    billing: { plan: string; price: number; credits: number }
    settings: Json
    cached: string | null
    mfaSessions: Set<string>
  }
}

const PEOPLE: Record<string, { role: string; tenant: string }> = {
  viewer: { role: 'viewer', tenant: 'acme' },
  persona_a: { role: 'owner', tenant: 'acme' },
  persona_b: { role: 'owner', tenant: 'globex' },
  admin: { role: 'admin', tenant: 'acme' },
  cookie_viewer: { role: 'viewer', tenant: 'acme' },
}

const ROLE_RANK_FIXTURE: Record<string, number> = { viewer: 0, member: 1, admin: 2, owner: 3 }
const TWOFA_ENABLED = new Set(['persona_a'])

async function startFixture(options: FixtureOptions = {}): Promise<Fixture> {
  const state: Fixture['state'] = {
    projects: new Map([
      ['p1', { id: 'p1', tenant_id: 'acme', name: 'Alpha space', description: 'seed', owner: '', visibility: 'private' }],
      ['p2', { id: 'p2', tenant_id: 'globex', name: 'Globex space', description: 'seed', owner: '', visibility: 'private' }],
    ]),
    invoices: new Map([
      ['i1', { id: 'i1', tenant_id: 'acme', status: 'open', amount_cents: 4200, owner: 'persona_a' }],
      ['i2', { id: 'i2', tenant_id: 'globex', status: 'open', amount_cents: 9900, owner: 'persona_b' }],
    ]),
    billing: { plan: 'pro', price: 4900, credits: 100 },
    settings: { theme: 'light' },
    cached: null,
    mfaSessions: new Set<string>(),
  }
  const server = createServer((req, res) => {
    void handle(req, res, state, options).catch(error => {
      if (!res.headersSent) res.statusCode = 500
      res.end(String(error))
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture did not bind')
  return {
    origin: `http://127.0.0.1:${address.port}`,
    state,
    close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }),
  }
}

function json(res: ServerResponse, status: number, value: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers })
  res.end(JSON.stringify(value))
}

function actorOf(req: IncomingMessage): { handle: string | null; role: string | null; tenant: string | null } {
  const header = req.headers['x-persona']
  const cookie = String(req.headers.cookie ?? '')
  const handle = (typeof header === 'string' && header) ? header
    : /acme_sid=([a-z_]+)/.exec(cookie)?.[1] ?? null
  if (!handle) return { handle: null, role: null, tenant: null }
  const person = PEOPLE[handle]
  return { handle, role: person?.role ?? null, tenant: person?.tenant ?? null }
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf8')
}

async function handle(req: IncomingMessage, res: ServerResponse, state: Fixture['state'], options: FixtureOptions): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const actor = actorOf(req)
  const bodyText = req.method === 'GET' || req.method === 'HEAD' ? '' : await readBody(req)
  let body: Json = {}
  if (bodyText) { try { body = JSON.parse(bodyText) as Json } catch { body = {} } }

  // Existing classes must stay unaffected by the impact gates.
  if (url.pathname === '/api/blind-search') {
    const value = url.searchParams.get('id') ?? ''
    const match = /(\d+)=(\d+)/.exec(value)
    const isTrue = value === '1' || (match !== null && match[1] === match[2])
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end(`<html><body><div class="feed">${'<span>stable-shell</span>'.repeat(40)}</div><div class="state">${isTrue ? 'admin' : 'user'}</div></body></html>`)
    return
  }
  if (url.pathname === '/doc') {
    const poison = req.headers['x-poison']
    if (poison) {
      state.cached = '{"rendered":"<b>poisoned</b>","cached":false}'
      json(res, 200, { rendered: '<b>poisoned</b>', cached: false })
      return
    }
    if (state.cached) {
      res.writeHead(200, { 'content-type': 'application/json', age: '5', 'x-cache': 'HIT' })
      res.end(state.cached)
      return
    }
    state.cached = '{"rendered":"<b>clean</b>","cached":false}'
    res.writeHead(200, { 'content-type': 'application/json', age: '0', 'x-cache': 'MISS' })
    res.end(state.cached)
    return
  }

  // Decorative OTP endpoint: returns {ok:true} for any/absent code and gates nothing.
  if (url.pathname === '/api/auth/2fa' && req.method === 'POST') {
    if (!actor.handle) return json(res, 401, { error: 'unauthenticated' })
    return json(res, 200, { ok: true })
  }
  if (url.pathname === '/api/auth/2fa/verify' && req.method === 'POST') {
    if (!actor.handle) return json(res, 401, { error: 'unauthenticated' })
    // Only persona_a has 2FA enabled. For an account without 2FA there is no challenged control,
    // so a 200 here is not a bypass (the requested boundary never existed).
    if (!TWOFA_ENABLED.has(actor.handle)) return json(res, 200, { ok: true, two_factor: 'not_enabled' })
    const bypass = req.headers['x-2fa-bypass']
    const code = String(body.code ?? '')
    if (bypass === '1' || code === '123456') {
      state.mfaSessions.add(actor.handle)
      return json(res, 200, { ok: true, user: { id: 'u-42', email: 'owner@acme.test' } })
    }
    return json(res, 401, { error: 'mfa_required', challenge: 'totp', message: 'verification code required' })
  }
  if (url.pathname === '/api/me') {
    if (!actor.handle) return json(res, 401, { error: 'unauthenticated' })
    return json(res, 200, { handle: 'account', twofa_enabled: TWOFA_ENABLED.has(actor.handle) })
  }
  if (url.pathname === '/api/account') {
    if (!actor.handle) return json(res, 401, { error: 'unauthenticated' })
    // A real MFA gate: an enrolled account must complete the challenge before reading this resource.
    if (TWOFA_ENABLED.has(actor.handle) && !state.mfaSessions.has(actor.handle)) {
      return json(res, 401, { error: 'mfa_required', challenge: 'totp', message: 'verification code required' })
    }
    return json(res, 200, { id: 'acct-1', email: 'owner@acme.test', balance: 4200 })
  }
  if (url.pathname === '/api/plans') {
    json(res, 200, { plans: [{ code: 'free', price: 0 }, { code: 'pro', price: 4900 }] })
    return
  }
  if (url.pathname === '/api/billing') {
    if (!actor.handle) return json(res, 401, { error: 'unauthenticated' })
    json(res, 200, { plan: state.billing.plan, price: state.billing.price, credits: state.billing.credits })
    return
  }
  if (url.pathname === '/api/plans/current' && req.method === 'PATCH') {
    if (!actor.handle) return json(res, 401, { error: 'unauthenticated' })
    if (actor.role !== 'owner') return json(res, 403, { error: 'forbidden' })
    const planId = String(body.planId ?? body.plan ?? state.billing.plan)
    const catalog: Record<string, number> = { free: 0, pro: 4900 }
    state.billing = { ...state.billing, plan: planId, price: catalog[planId] ?? state.billing.price }
    json(res, 200, { ok: true, plan: state.billing.plan, price: state.billing.price, credits: state.billing.credits })
    return
  }
  if (url.pathname === '/api/settings') {
    if (req.method === 'GET') return json(res, 200, state.settings)
    if (req.method === 'POST') {
      // Cookie-authenticated state change; the hardened twin requires a bound CSRF token.
      if (actor.handle) {
        const token = req.headers['x-csrf-token']
        if (!options.csrfTokenBypass && (typeof token !== 'string' || token !== `tok-${actor.handle}`)) {
          return json(res, 403, { error: 'csrf' })
        }
        state.settings = { ...state.settings, ...body }
        return json(res, 200, { ok: true, ...state.settings })
      }
      return json(res, 401, { error: 'unauthenticated' })
    }
  }
  if (url.pathname === '/api/reports/9f1/render') {
    if (!actor.handle) return json(res, 401, { error: 'unauthenticated' })
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end(`<section class="report"><h2>${options.reportActiveMarkup ? '<img src=x onerror="alert(1)">' : '<b>gnmarker</b>'}</h2></section>`)
    return
  }
  if (url.pathname === '/api/reports/9f1/public') {
    // Public share route by design: id/name/summary/workspace + a tenant label reference.
    return json(res, 200, { id: '9f1', name: 'Quarterly', summary: 'internal', workspace: 'guardian_state_acme', ref: 'rbc_acme_0123456789ab' })
  }
  if (url.pathname === '/api/admin/audit') {
    if (!actor.handle) return json(res, 401, { error: 'unauthenticated' })
    const rank = ROLE_RANK_FIXTURE[actor.role ?? ''] ?? -1
    if (!options.adminBfla && rank < ROLE_RANK_FIXTURE.admin!) return json(res, 403, { error: 'forbidden' })
    return json(res, 200, { rows: [{ actor: 'admin', action: 'delete-user', target: 'user-42' }, { actor: 'admin', action: 'rotate-key' }] })
  }

  const projectMatch = /^\/api\/projects\/([a-z0-9]+)$/.exec(url.pathname)
  if (projectMatch) {
    const id = projectMatch[1]!
    const row = state.projects.get(id)
    if (!row) return json(res, 404, { error: 'not_found' })
    if (!actor.handle) return json(res, 401, { error: 'unauthenticated' })
    if (req.method === 'GET') {
      if (row.tenant_id !== actor.tenant) return json(res, 404, { error: 'not_found' })
      return json(res, 200, row)
    }
    if (req.method === 'PATCH') {
      if (row.tenant_id !== actor.tenant) return json(res, 404, { error: 'not_found' })
      // Content writes are in policy for every authenticated tenant member (viewer included).
      state.projects.set(id, { ...row, ...body })
      return json(res, 200, state.projects.get(id))
    }
    if (req.method === 'DELETE') {
      if (row.tenant_id !== actor.tenant) return json(res, 200, { ok: true })
      state.projects.delete(id)
      return json(res, 200, { ok: true })
    }
  }

  const invoiceMatch = /^\/api\/invoices\/([a-z0-9]+)$/.exec(url.pathname)
  if (invoiceMatch) {
    const id = invoiceMatch[1]!
    const row = state.invoices.get(id)
    if (!row) return json(res, 404, { error: 'not_found' })
    if (!actor.handle) return json(res, 401, { error: 'unauthenticated' })
    if (row.tenant_id !== actor.tenant && !(req.method === 'PATCH' && options.crossTenantInvoiceWrite) && !(req.method === 'GET' && options.crossTenantRead)) {
      return json(res, 404, { error: 'not_found' })
    }
    if (req.method === 'GET') return json(res, 200, row)
    if (req.method === 'PATCH') {
      state.invoices.set(id, { ...row, ...body })
      return json(res, 200, state.invoices.get(id))
    }
  }
  json(res, 404, { error: 'not_found' })
}

// ---------------------------------------------------------------------------
// Persona / grant helpers
// ---------------------------------------------------------------------------

function personaOf(handle: string, origin: string, authKind: 'header' | 'cookie' = 'header'): ResolvedPersona {
  const person = PEOPLE[handle]!
  const roleLabel = `${person.role} (${person.tenant})`
  if (authKind === 'cookie') {
    const cookieValue = `acme_sid=${handle}`
    return {
      id: handle,
      handle,
      roleLabel,
      originAllowlist: [origin],
      authKind: 'cookie',
      headerName: null,
      secret: cookieValue,
      canaryMarkers: [],
      session: {
        headerType: 'cookie',
        value: cookieValue,
        adapterUsed: 'fixture',
        bundle: {
          cookies: [
            { name: 'acme_sid', value: handle, domain: '', path: '/', sameSite: 'Lax' },
          ],
        },
      },
    }
  }
  return {
    id: handle,
    handle,
    roleLabel,
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-Persona',
    secret: handle,
    canaryMarkers: [],
  }
}

function grantFor(origin: string, handles: readonly string[] = Object.keys(PEOPLE)): Grant {
  const personas = new Map<string, ResolvedPersona>()
  for (const handle of handles) {
    personas.set(handle, personaOf(handle, origin, handle.startsWith('cookie_') ? 'cookie' : 'header'))
  }
  return {
    origin,
    tier: 3,
    allowLocalLab: true,
    maxRpsPerOrigin: 100,
    canRead: candidate => candidate === origin,
    isIdempotentPostAllowed: () => true,
    isStateChangeApproved: () => true,
    personas,
    audit: () => undefined,
  }
}

function baseFields(origin: string, overrides: Json): Json {
  return {
    version: 1,
    origin,
    title: 'Authorization differential',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'A lower-privileged actor reaches another actor or tenant resource.',
    impact: 'An authenticated attacker can read or mutate another tenant resource.',
    remediation: 'Authorize every object access against the caller tenant and required role.',
    recheckInstructions: 'Replay the control and probe arms; the probe must be denied after the fix.',
    ...overrides,
  }
}

async function verify(spec: Json, origin: string, browser?: unknown) {
  const parsed = declarativeReplaySpecSchema.safeParse(spec)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))
  return verifyReplaySpec({
    spec,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    backend: new LocalJqBackend(),
    grant: grantFor(origin),
    browser: browser as never,
    signal: AbortSignal.timeout(30_000),
  })
}

// ---------------------------------------------------------------------------
// 1. Viewer same-tenant content write is in policy (dismissed)
// ---------------------------------------------------------------------------

test('policy: a viewer same-tenant content write is dismissed even with a denied cross-tenant control', async () => {
  const fx = await startFixture()
  try {
    const spec = baseFields(fx.origin, {
      title: 'Vertical BFLA: read-only viewer can PATCH another user private space',
      category: 'broken-access-control',
      cwe: 'CWE-285',
      expectControlDenied: true,
      steps: [
        { id: 'before', role: 'control', description: 'Owner reads the workspace', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/projects/p1', persona: 'persona_a' } },
        { id: 'ctrl', role: 'control', description: 'Foreign tenant reads the workspace (denied boundary)', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/projects/p1', persona: 'persona_b' } },
        { id: 'probe', role: 'probe', description: 'Viewer writes a same-tenant workspace description', request: { origin: fx.origin, method: 'PATCH', pathAndQuery: '/api/projects/p1', persona: 'viewer', jsonBody: { description: 'policy-probe' } } },
        { id: 'after', role: 'control', description: 'Owner re-reads the workspace', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/projects/p1', persona: 'persona_a' } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.before.status == 200 and .steps.ctrl.status == 404),
        confirmed: (.steps.probe.status == 200 and .steps.after.json.description == "policy-probe"),
        observed: ("probe=" + (.steps.probe.status | tostring)),
        expected: "403 for a viewer"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.equal(res.outcome.confirmed, false)
    assert.match(res.outcome.reason ?? '', /in policy|differential/i)
    // The denied control was treated as boundary evidence, not as a spec error.
    assert.doesNotMatch(res.outcome.reason ?? '', /Unexpected HTTP 404/i)
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 2. Cross-tenant DELETE that is an idempotent no-op is not impact
// ---------------------------------------------------------------------------

test('policy: a cross-tenant no-op DELETE is dismissed without a persisted side effect', async () => {
  const fx = await startFixture()
  try {
    const spec = baseFields(fx.origin, {
      title: 'BOLA: cross-tenant project delete',
      cwe: 'CWE-639',
      resourceTenant: 'acme',
      steps: [
        { id: 'before', role: 'control', description: 'Owner reads the workspace', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/projects/p1', persona: 'persona_a' } },
        { id: 'probe', role: 'probe', description: 'Foreign tenant DELETEs the workspace', request: { origin: fx.origin, method: 'DELETE', pathAndQuery: '/api/projects/p1', persona: 'persona_b' } },
        { id: 'after', role: 'control', description: 'Owner re-reads the workspace', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/projects/p1', persona: 'persona_a' } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.before.status == 200 and .steps.after.status == 200),
        confirmed: (.steps.probe.status == 200),
        observed: ("delete=" + (.steps.probe.status | tostring)),
        expected: "403 or a real deletion"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.match(res.outcome.reason ?? '', /no-op|identical|without persisted impact|persisted|status-only|no genuine control-vs-probe differential/i)
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 3. Role hierarchy: owner > admin > member > viewer
// ---------------------------------------------------------------------------

test('policy: an owner read of an admin route is not a differential against an admin actor', async () => {
  const fx = await startFixture()
  try {
    const spec = baseFields(fx.origin, {
      title: 'Vertical BFLA: owner reads the admin audit surface',
      category: 'broken-access-control',
      cwe: 'CWE-285',
      requiredRole: 'admin',
      steps: [
        { id: 'ctrl', role: 'control', description: 'Admin reads the audit surface', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/admin/audit', persona: 'admin' } },
        { id: 'probe', role: 'probe', description: 'Owner reads the audit surface', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/admin/audit', persona: 'persona_a' } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.ctrl.status == 200),
        confirmed: (.steps.probe.status == 200 and .steps.probe.json.rows[0].action == "delete-user"),
        observed: ("owner=" + (.steps.probe.status | tostring)),
        expected: "owner denied on an admin-only route"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.match(res.outcome.reason ?? '', /already satisfies|in policy|no vertical differential/i)
    assert.equal(roleRank('owner'), ROLE_RANK.owner)
    assert.ok(roleRank('owner')! > roleRank('admin')!)
    assert.ok(roleRank('admin')! > roleRank('member')!)
    assert.ok(roleRank('member')! > roleRank('viewer')!)
    assert.deepEqual(parseRoleLabel('owner (acme)'), { role: 'owner', tenant: 'acme' })
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 4. Mass assignment: catalog-authoritative plan price is not an injected field
// ---------------------------------------------------------------------------

test('policy: catalog-authoritative plan price echo is dismissed as mass assignment', async () => {
  const fx = await startFixture()
  try {
    const spec = baseFields(fx.origin, {
      title: 'Mass assignment on PATCH plan: owner rewrites privileged price',
      category: 'mass-assignment',
      cwe: 'CWE-915',
      expectedImpactEvents: ['invariant_violation'],
      steps: [
        { id: 'catalog', role: 'control', description: 'Read the plan catalog', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/plans', persona: 'persona_a' } },
        { id: 'before', role: 'control', description: 'Read billing before the plan switch', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/billing', persona: 'persona_a' } },
        { id: 'probe', role: 'probe', description: 'Switch to the free tier and supply a price/limit', request: { origin: fx.origin, method: 'PATCH', pathAndQuery: '/api/plans/current', persona: 'persona_a', jsonBody: { planId: 'free', price: 0, seat_limit: 999, credits: 999999 } } },
        { id: 'after', role: 'control', description: 'Read billing after the plan switch', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/billing', persona: 'admin' } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.before.status == 200 and .steps.after.status == 200),
        confirmed: (.steps.probe.status == 200 and .steps.probe.json.ok == true and .steps.after.json.price == 0),
        observed: ("price=" + (.steps.after.json.price | tostring)),
        expected: "the body price is ignored"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.match(res.outcome.reason ?? '', /catalog/i)
    const gate = res.evidencePayload.impactGate as { satisfied?: boolean } | undefined
    assert.equal(gate?.satisfied, false)
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 5. CSRF: SameSite=Lax cookie cannot ride a cross-site form POST
// ---------------------------------------------------------------------------

test('policy: CSRF is dismissed when the session cookie is SameSite=Lax and the Origin is foreign', async () => {
  const fx = await startFixture({ csrfTokenBypass: true })
  try {
    const spec = baseFields(fx.origin, {
      title: 'CSRF: state-changing settings API accepts cross-origin form POST',
      category: 'csrf',
      cwe: 'CWE-352',
      expectedImpactEvents: ['csrf_state_change'],
      steps: [
        { id: 'before', role: 'control', description: 'Read settings before the cross-site write', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/settings' } },
        { id: 'probe', role: 'probe', description: 'Cross-site text/plain form POST with the ambient cookie', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/api/settings', persona: 'cookie_viewer', headers: { origin: 'https://evil.example', 'content-type': 'text/plain' }, textBody: 'theme=dark' } },
        { id: 'after', role: 'control', description: 'Read settings after the cross-site write', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/settings' } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.before.status == 200),
        confirmed: (.steps.probe.status == 200),
        observed: ("probe=" + (.steps.probe.status | tostring)),
        expected: "403 without a CSRF token"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.match(res.outcome.reason ?? '', /SameSite=Lax/i)
    const gate = res.evidencePayload.impactGate as { satisfied?: boolean } | undefined
    assert.equal(gate?.satisfied, false)
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 5b. Universal default-deny: no challenged control ⇒ no auth bypass
// ---------------------------------------------------------------------------

test('boundary: a decorative 2FA endpoint (any code, no state change) is dismissed', async () => {
  const fx = await startFixture()
  try {
    const spec = baseFields(fx.origin, {
      title: 'Two-factor (OTP) verification accepts any/absent code — 2FA bypass',
      category: 'auth-identity',
      cwe: 'CWE-287',
      steps: [
        { id: 'enrolled', role: 'control', description: 'Read the account security state', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'persona_a' } },
        { id: 'before', role: 'control', description: 'Read account data before any code (no challenge exists)', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/billing', persona: 'persona_a' } },
        { id: 'probe', role: 'probe', description: 'Post a bogus OTP code to the decorative endpoint', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/api/auth/2fa', persona: 'persona_a', jsonBody: { code: '000000' } } },
        { id: 'after', role: 'control', description: 'Read the same account data after the code (unchanged)', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/billing', persona: 'persona_a' } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.enrolled.status == 200 and .steps.enrolled.json.twofa_enabled == true),
        confirmed: (.steps.probe.status == 200 and .steps.probe.json.ok == true and .steps.after.json.plan == .steps.before.json.plan),
        observed: ("probe=" + (.steps.probe.status | tostring)),
        expected: "the 2FA challenge is bypassed"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.match(res.outcome.reason ?? '', /decorative 2FA|denied\/challenged control|advisory/i)
    const gate = res.evidencePayload.boundaryGate as { satisfied?: boolean; evidence?: { decorative?: boolean; enrolled?: boolean } } | undefined
    assert.equal(gate?.satisfied, false)
    assert.equal(gate?.evidence?.decorative, true)
  } finally { await fx.close() }
})

test('boundary: an unenrolled account is dismissed even with a 401/200 pair', async () => {
  const fx = await startFixture()
  try {
    const spec = baseFields(fx.origin, {
      title: 'MFA bypass: OTP verification accepts an absent code',
      category: 'auth-identity',
      cwe: 'CWE-287',
      steps: [
        { id: 'enrolled', role: 'control', description: 'Account security state (2FA not enabled)', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'persona_b' } },
        { id: 'control', role: 'control', description: 'A protected read is denied before the check', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/account', persona: 'persona_b' } },
        { id: 'probe', role: 'probe', description: 'OTP verify with an absent code', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/api/auth/2fa/verify', persona: 'persona_b', jsonBody: {} } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.enrolled.status == 200),
        confirmed: (.steps.probe.status == 200 and .steps.probe.json.ok == true),
        observed: ("probe=" + (.steps.probe.status | tostring)),
        expected: "the 2FA challenge is bypassed"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.notEqual(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.match(res.outcome.reason ?? '', /not enrolled|enrolled|decorative/i)
  } finally { await fx.close() }
})

test('boundary: a real MFA challenge with a pre/post access differential confirms', async () => {
  const fx = await startFixture()
  try {
    const spec = baseFields(fx.origin, {
      title: 'Two-factor (OTP) verification accepts any/absent code — 2FA bypass',
      category: 'auth-identity',
      cwe: 'CWE-287',
      steps: [
        { id: 'enrolled', role: 'control', description: 'Enrolled account state', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/me', persona: 'persona_a' } },
        { id: 'pre', role: 'control', description: 'Protected read is challenged before the code', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/account', persona: 'persona_a' } },
        { id: 'challenge', role: 'probe', description: 'OTP verify with a bypass header crosses the challenge', request: { origin: fx.origin, method: 'POST', pathAndQuery: '/api/auth/2fa/verify', persona: 'persona_a', headers: { 'x-2fa-bypass': '1' }, jsonBody: { code: '000000' } } },
        { id: 'post', role: 'probe', description: 'Same actor reads the protected account after the challenge', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/account', persona: 'persona_a' } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.enrolled.json.twofa_enabled == true and .steps.pre.status == 401),
        confirmed: (.steps.challenge.status == 200 and .steps.post.status == 200 and .steps.post.json.id == "acct-1"),
        observed: ("pre=" + (.steps.pre.status | tostring) + " post=" + (.steps.post.status | tostring)),
        expected: "the MFA challenge cannot be bypassed"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
    const gate = res.evidencePayload.boundaryGate as { satisfied?: boolean; evidence?: { enrolled?: boolean; sameActor?: boolean; sameRoute?: boolean } } | undefined
    assert.equal(gate?.satisfied, true)
    assert.equal(gate?.evidence?.enrolled, true)
    assert.equal(gate?.evidence?.sameActor, true)
    assert.equal(gate?.evidence?.sameRoute, true)
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 6. Genuine cross-tenant write with a persisted readback + oracle confirms
// ---------------------------------------------------------------------------

test('positive: a genuine cross-tenant write with a clean readback and oracle confirms', async () => {
  const fx = await startFixture({ crossTenantInvoiceWrite: true })
  try {
    const spec = baseFields(fx.origin, {
      title: 'Cross-tenant invoice write',
      cwe: 'CWE-639',
      resourceTenant: 'globex',
      expectedImpactEvents: ['cross_tenant_write'],
      steps: [
        { id: 'before', role: 'control', description: 'Globex owner reads the invoice', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/i2', persona: 'persona_b' } },
        { id: 'probe', role: 'probe', description: 'Acme viewer voids the Globex invoice', request: { origin: fx.origin, method: 'PATCH', pathAndQuery: '/api/invoices/i2', persona: 'viewer', jsonBody: { status: 'void' } } },
        { id: 'after', role: 'control', description: 'Globex owner re-reads the invoice', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/i2', persona: 'persona_b' } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.before.status == 200 and .steps.before.json.status == "open"),
        confirmed: (.steps.probe.status == 200 and .steps.after.json.status == "void"),
        observed: ("after=" + (.steps.after.json.status | tostring)),
        expected: "the foreign invoice is untouched"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
    const gate = res.evidencePayload.impactGate as { satisfied?: boolean; reason?: string } | undefined
    assert.equal(gate?.satisfied, true, gate?.reason ?? 'no impact gate evidence')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 7. Denied control is boundary evidence; a real impact still confirms
// ---------------------------------------------------------------------------

test('positive: expectControlDenied keeps the strongest control and confirms on real impact', async () => {
  const fx = await startFixture({ crossTenantInvoiceWrite: true })
  try {
    const spec = baseFields(fx.origin, {
      title: 'Cross-tenant invoice write with a boundary control',
      cwe: 'CWE-639',
      resourceTenant: 'globex',
      expectControlDenied: true,
      requiredRole: 'owner',
      expectedImpactEvents: ['cross_tenant_write'],
      steps: [
        { id: 'boundary', role: 'control', description: 'Foreign tenant reads the victim tenant invoice (404 boundary)', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/i1', persona: 'persona_b' } },
        { id: 'before', role: 'control', description: 'Globex owner reads the invoice', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/i2', persona: 'persona_b' } },
        { id: 'probe', role: 'probe', description: 'Acme viewer voids the Globex invoice', request: { origin: fx.origin, method: 'PATCH', pathAndQuery: '/api/invoices/i2', persona: 'viewer', jsonBody: { status: 'void' } } },
        { id: 'after', role: 'control', description: 'Globex owner re-reads the invoice', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/i2', persona: 'persona_b' } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.boundary.status == 404 and .steps.before.status == 200),
        confirmed: (.steps.probe.status == 200 and .steps.after.json.status == "void"),
        observed: ("boundary=" + (.steps.boundary.status | tostring) + " after=" + (.steps.after.json.status | tostring)),
        expected: "the boundary control holds"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
    assert.doesNotMatch(res.outcome.reason ?? '', /Unexpected HTTP 404/i)
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 8. Existing authz / sql / cache / xss classes still confirm
// ---------------------------------------------------------------------------

test('regression: a cross-actor authorization read still confirms with an owner-scoped field', async () => {
  const fx = await startFixture({ crossTenantRead: true })
  try {
    const spec = baseFields(fx.origin, {
      title: 'Cross-actor invoice read',
      cwe: 'CWE-639',
      steps: [
        { id: 'control', role: 'control', description: 'Acme owner reads its invoice', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/i1', persona: 'persona_a' } },
        { id: 'probe', role: 'probe', description: 'Globex owner reads the Acme invoice', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/i1', persona: 'persona_b' } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.control.status == 200 and .steps.control.json.id == "i1"),
        confirmed: (.steps.probe.status == 200 and .steps.probe.json.id == .steps.control.json.id and .steps.probe.json.owner == .steps.control.json.owner),
        observed: ("probe=" + (.steps.probe.status | tostring)),
        expected: "403 for a foreign tenant"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await fx.close() }
})

test('regression: sql_boolean_diff still confirms inside a large stable shell', async () => {
  const fx = await startFixture()
  try {
    const spec = {
      version: 1,
      kind: 'sql_boolean_diff',
      origin: fx.origin,
      targetOrigin: fx.origin,
      title: 'Boolean differential in a stable shell',
      category: 'injection-input',
      cwe: 'CWE-89',
      severity: 'high',
      severityRationale: 'True/false predicates change a stable field while the surrounding shell is identical.',
      impact: 'Boolean-based SQL injection.',
      remediation: 'Use parameterized queries.',
      recheckInstructions: 'Replay the randomized triplets.',
      method: 'GET',
      pathAndQuery: '/api/blind-search',
      paramName: 'id',
      paramLocation: 'query',
      baselineValue: '1',
      quoteStyle: 'single',
      assertionsJq: `{
        controlPassed: (.sqlDiff.controlPassed == true),
        confirmed: (.sqlDiff.passed == true),
        observed: "stable field delta",
        expected: "no differential"
      }`,
    }
    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await fx.close() }
})

test('regression: cache_differential still confirms a persisted poisoned entry', async () => {
  const fx = await startFixture()
  try {
    const spec = {
      version: 1,
      kind: 'cache_differential',
      origin: fx.origin,
      targetOrigin: fx.origin,
      title: 'Cache poisoning on a rendered document',
      category: 'cache-poisoning',
      cwe: 'CWE-524',
      severity: 'high',
      severityRationale: 'A poisoned cache entry is served to a clean client.',
      impact: 'An attacker can poison a shared cache response.',
      remediation: 'Include all cache-relevant inputs in the cache key.',
      recheckInstructions: 'Replay control, poison and verify.',
      mode: 'poison',
      method: 'GET',
      controlPath: '/doc?_gcb={{control_gcb}}',
      probePath: '/doc?_gcb={{probe_gcb}}',
      verifyPath: '/doc?_gcb={{probe_gcb}}',
      poisonHeaders: { 'x-poison': '1' },
      assertionsJq: `{
        controlPassed: (.cacheProof.cacheHitObserved == true),
        confirmed: (.cacheProof.poisonPersistedToVictim == true),
        observed: "poisoned cache entry served to a clean client",
        expected: "a clean response"
      }`,
    }
    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await fx.close() }
})

test('regression: a browser_dom XSS proof still confirms', async () => {
  const fx = await startFixture()
  try {
    const visit = (canary: boolean, token: string | null) => ({
      origin: fx.origin,
      finalUrl: `${fx.origin}/card`,
      title: 'Card',
      status: 200,
      domSnippet: '<div id="card"></div>',
      links: [],
      forms: [],
      xhrRequests: [],
      blockedOrigins: [],
      consoleMessages: [],
      postMessageListeners: { count: 0, originChecked: true, canaryHandledWithoutOriginCheck: false },
      cookieNames: [],
      localStorageKeys: [],
      sessionStorageKeys: [],
      canaryCheck: { token, triggered: canary, detail: canary ? 'active markup rendered' : null },
      domSinkTraces: [],
      exchangeIds: [],
      exchanges: [],
      durationMs: 1,
    })
    const browser = {
      async visitPage(req: { canaryToken?: string }) {
        return visit(Boolean(req.canaryToken), req.canaryToken ?? null)
      },
    }
    const spec = {
      version: 1,
      kind: 'browser_dom',
      origin: fx.origin,
      targetOrigin: fx.origin,
      title: 'Stored XSS rendered on the project card',
      category: 'xss',
      cwe: 'CWE-79',
      severity: 'high',
      severityRationale: 'Active markup from stored data executes in the victim browser.',
      impact: 'Stored cross-site scripting.',
      remediation: 'Escape stored markup on render.',
      recheckInstructions: 'Replay the card render with a fresh canary.',
      controlPath: '/card?mode=plain',
      probePath: '/card?q={{canary_token}}',
      checkKind: 'dom_xss',
      assertionsJq: `{
        controlPassed: (.control.status == 200 and .control.canaryCheck.triggered == false),
        confirmed: (.probe.canaryCheck.triggered == true),
        observed: "canary markup executed",
        expected: "escaped text"
      }`,
    }
    const res = await verify(spec, fx.origin, browser)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 9. Shared-validator units + transcript-oracle parity
// ---------------------------------------------------------------------------

test('units: impact classification and role hierarchy are mechanical', () => {
  assert.equal(classifyImpactDescriptor({ title: 'Vertical BFLA on the admin route' }), 'bfla')
  assert.equal(classifyImpactDescriptor({ title: 'Mass assignment on PATCH plan' }), 'mass_assignment')
  assert.equal(classifyImpactDescriptor({ title: 'CSRF: cross-origin form POST' }), 'csrf')
  assert.equal(classifyImpactDescriptor({ title: 'Cross-tenant invoice read' }), 'authorization')
  assert.equal(classifyImpactDescriptor({ title: 'Boolean SQL injection' }), 'other')
  assert.equal(classifyImpactDescriptor({ title: 'Cache poisoning' }), 'other')
  // Unmodelled classes are now gated by their own evidence model instead of falling to 'other'.
  assert.equal(classifyImpactDescriptor({ title: 'Stored XSS on the card' }), 'markup')
  assert.equal(classifyImpactDescriptor({ title: 'Stored HTML injection via report name' }), 'markup')
  assert.equal(classifyImpactDescriptor({ cwe: 'CWE-79' }), 'markup')
  assert.equal(classifyImpactDescriptor({ title: 'Invoice workflow step-skip: draft -> paid' }), 'business_logic')
  assert.equal(classifyImpactDescriptor({ cwe: 'CWE-841' }), 'business_logic')
  assert.equal(classifyImpactDescriptor({ title: 'Unauthenticated report disclosure via /public' }), 'disclosure')
  assert.equal(classifyImpactDescriptor({ cwe: 'CWE-200', category: 'information-disclosure' }), 'disclosure')
  assert.equal(classifyImpactDescriptor({ cwe: 'CWE-200', category: 'broken-access-control' }), 'authorization')
  assert.deepEqual(parseRoleLabel('admin (globex)'), { role: 'admin', tenant: 'globex' })
})

test('units: a viewer same-tenant mutation has no role differential', () => {
  const assessment = assessAuthorizationImpact({
    impactClass: 'bfla',
    requiredRole: 'owner',
    steps: [
      { id: 'p', arm: 'probe', method: 'PATCH', route: '/api/projects/p1', status: 200, actor: { handle: 'viewer', role: 'viewer', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' } },
    ],
  })
  assert.equal(assessment.satisfied, false)
  assert.equal(assessment.evidence.roleDifferential, true)
  // ...but without a readback the mutation still cannot confirm.
  assert.match(assessment.reason, /without persisted impact|pre-mutation readback|clean post-mutation/i)
})

test('units: CSRF requires an ambient cookie and a csrf_state_change oracle', () => {
  const base = {
    impactClass: 'csrf' as const,
    targetOrigin: 'http://app.local',
    steps: [
      { id: 'p', arm: 'probe' as const, method: 'POST', route: '/api/settings', status: 200, actor: { handle: 'cookie_viewer', role: 'viewer' as const, tenant: 'acme', auth: 'cookie' as const, sameSite: 'Lax' }, requestHeaders: { origin: 'https://evil.example' } },
    ],
  }
  assert.match(assessCsrfImpact(base).reason, /SameSite=Lax/i)
  assert.match(assessCsrfImpact({ ...base, steps: [{ ...base.steps[0]!, actor: { ...base.steps[0]!.actor, auth: 'bearer' as const } }] }).reason, /bearer/i)
  assert.match(assessCsrfImpact({ ...base, steps: [{ ...base.steps[0]!, actor: { ...base.steps[0]!.actor, sameSite: 'Strict' as const } }] }).reason, /SameSite=Strict/i)
})

test('units: mass assignment requires a protected persisted field read back by a control', () => {
  const assessment = assessMassAssignmentImpact({
    impactClass: 'mass_assignment',
    steps: [
      { id: 'before', arm: 'control', method: 'GET', status: 200, json: { role: 'viewer' }, actor: { handle: 'admin', role: 'admin', tenant: 'acme', auth: 'header', sameSite: null } },
      { id: 'probe', arm: 'probe', method: 'PATCH', status: 200, requestJson: { role: 'owner' }, json: { ok: true }, actor: { handle: 'viewer', role: 'viewer', tenant: 'acme', auth: 'header', sameSite: null } },
      { id: 'after', arm: 'control', method: 'GET', status: 200, json: { role: 'owner' }, actor: { handle: 'admin', role: 'admin', tenant: 'acme', auth: 'header', sameSite: null } },
    ],
  })
  assert.equal(assessment.satisfied, true)
  assert.deepEqual(assessment.evidence.protectedFields, ['role'])
})

// ---------------------------------------------------------------------------
// guardian_verify parity: the transcript oracle dismisses the same fixtures
// ---------------------------------------------------------------------------

interface RpcResponse { ok: boolean; result?: unknown; error?: string }

function rpc(server: VerifyRpcServer, op: string, args: Record<string, unknown> = {}): Promise<RpcResponse> {
  const payload = JSON.stringify({ op, args })
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      socketPath: server.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        'x-guardian-rpc-token': server.token,
        'x-guardian-verify-nonce': server.nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', (chunk: Buffer) => chunks.push(chunk))
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcResponse) } catch (error) { reject(error) }
      })
    })
    req.once('error', reject)
    req.end(payload)
  })
}

async function startRpc(fx: Fixture): Promise<VerifyRpcServer> {
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant: grantFor(fx.origin),
    runId: 'run-v6-harden',
    assignmentId: 'assignment-v6-harden',
    nonce: randomUUID().replace(/-/g, ''),
    targetOrigins: [fx.origin],
  })
  await server.start()
  return server
}

/** Run a script-shaped claim set through the transcript oracle the way `runAttempt` does. */
function oracleFor(
  server: VerifyRpcServer,
  title: string,
  claims: VerifyClaim[],
): ReturnType<typeof evaluateClaims> {
  const parsed = parseVerifyScriptResult({ title, claims })
  return evaluateClaims(server.transcript, parsed.claims, {
    allowedExchangeIds: new Set(server.transcript.list().map(record => record.exchangeId)),
    claimedImpact: classifyImpactDescriptor({ title: parsed.title }),
    claimedBoundary: classifyBoundaryClaim({ title: parsed.title }),
  })
}

test('parity: guardian_verify dismisses the viewer same-tenant write over the same exchanges', async () => {
  const fx = await startFixture()
  const server = await startRpc(fx)
  try {
    const before = await rpc(server, 'http', { path: '/api/projects/p1', persona: 'persona_a' })
    const boundary = await rpc(server, 'http', { path: '/api/projects/p1', persona: 'persona_b' })
    const probe = await rpc(server, 'http', { path: '/api/projects/p1', method: 'PATCH', body: JSON.stringify({ description: 'policy-probe' }), persona: 'viewer' })
    const after = await rpc(server, 'http', { path: '/api/projects/p1', persona: 'persona_a' })
    const id = (res: RpcResponse) => (res.result as { exchangeId: string }).exchangeId
    const beforeId = id(before)
    const boundaryId = id(boundary)
    const probeId = id(probe)
    const afterId = id(after)

    // A naive script: status + echo only, titled as a vertical BFLA.
    const naive: VerifyClaim[] = [
      { kind: 'status', exchangeId: probeId, expected: 200 },
      { kind: 'jsonpath', exchangeId: afterId, path: 'description', equals: 'policy-probe' },
    ]
    const dismissed = oracleFor(server, 'Vertical BFLA: viewer can patch another private space', naive)
    assert.equal(dismissed.passed, false, 'a status/echo-only BFLA claim must not pass the oracle')
    assert.match(dismissed.failures.join(' '), /impact: bfla claim requires/i)

    // Even an explicitly-declared impact claim is rejected by the shared validator.
    const explicit: VerifyClaim[] = [...naive, {
      kind: 'impact',
      impactClass: 'bfla',
      probeExchangeId: probeId,
      controlExchangeIds: [beforeId, boundaryId],
      afterExchangeId: afterId,
      expectControlDenied: true,
      actorRoles: { viewer: 'viewer', persona_a: 'owner', persona_b: 'owner' },
      actorTenants: { viewer: 'acme', persona_a: 'acme', persona_b: 'globex' },
    }]
    const explicitResult = oracleFor(server, 'Vertical BFLA: viewer can patch another private space', explicit)
    assert.equal(explicitResult.passed, false)
    assert.equal(explicitResult.checks.find(check => check.claim.kind === 'impact')?.passed, false)
    assert.match(explicitResult.failures.join(' '), /in policy|differential|privilege/i)
  } finally {
    await server.close()
    await fx.close()
  }
})

test('parity: guardian_verify dismisses the catalog-price mass assignment echo', async () => {
  const fx = await startFixture()
  const server = await startRpc(fx)
  try {
    const catalog = await rpc(server, 'http', { path: '/api/plans', persona: 'persona_a' })
    const before = await rpc(server, 'http', { path: '/api/billing', persona: 'persona_a' })
    const probe = await rpc(server, 'http', { path: '/api/plans/current', method: 'PATCH', body: JSON.stringify({ planId: 'free', price: 0, seat_limit: 999 }), persona: 'persona_a' })
    const after = await rpc(server, 'http', { path: '/api/billing', persona: 'admin' })
    const id = (res: RpcResponse) => (res.result as { exchangeId: string }).exchangeId
    const catalogId = id(catalog)
    const beforeId = id(before)
    const probeId = id(probe)
    const afterId = id(after)

    const claims: VerifyClaim[] = [
      { kind: 'status', exchangeId: probeId, expected: 200 },
      { kind: 'jsonpath', exchangeId: afterId, path: 'price', equals: 0 },
    ]
    const naive = oracleFor(server, 'Mass assignment: owner rewrites the plan price', claims)
    assert.equal(naive.passed, false)
    assert.match(naive.failures.join(' '), /mass_assignment claim requires/i)

    const explicit: VerifyClaim[] = [...claims, {
      kind: 'impact',
      impactClass: 'mass_assignment',
      probeExchangeId: probeId,
      controlExchangeIds: [catalogId, beforeId],
      beforeExchangeId: beforeId,
      afterExchangeId: afterId,
      requestBody: { planId: 'free', price: 0, seat_limit: 999 },
      oracleEvents: ['invariant_violation'],
      actorRoles: { persona_a: 'owner', admin: 'admin' },
      actorTenants: { persona_a: 'acme', admin: 'acme' },
    }]
    const explicitResult = oracleFor(server, 'Mass assignment: owner rewrites the plan price', explicit)
    assert.equal(explicitResult.passed, false)
    assert.match(explicitResult.checks.find(check => check.claim.kind === 'impact')?.detail ?? '', /catalog/i)
  } finally {
    await server.close()
    await fx.close()
  }
})

test('parity: guardian_verify dismisses the SameSite=Lax CSRF claim', async () => {
  const fx = await startFixture({ csrfTokenBypass: true })
  const server = await startRpc(fx)
  try {
    const before = await rpc(server, 'http', { path: '/api/settings' })
    const probe = await rpc(server, 'http', {
      path: '/api/settings',
      method: 'POST',
      persona: 'cookie_viewer',
      headers: { origin: 'https://evil.example', 'content-type': 'text/plain' },
      body: 'theme=dark',
    })
    const after = await rpc(server, 'http', { path: '/api/settings' })
    const id = (res: RpcResponse) => (res.result as { exchangeId: string }).exchangeId
    const beforeId = id(before)
    const probeId = id(probe)
    const afterId = id(after)

    const claims: VerifyClaim[] = [
      { kind: 'status', exchangeId: probeId, expected: [200, 403] },
    ]
    const naive = oracleFor(server, 'CSRF: cross-origin state change', claims)
    assert.equal(naive.passed, false)
    assert.match(naive.failures.join(' '), /csrf claim requires/i)

    const explicit: VerifyClaim[] = [...claims, {
      kind: 'impact',
      impactClass: 'csrf',
      probeExchangeId: probeId,
      controlExchangeIds: [beforeId],
      afterExchangeId: afterId,
      oracleEvents: ['csrf_state_change'],
      ambient: { kind: 'cookie', sameSite: 'Lax' },
      actorRoles: { cookie_viewer: 'viewer' },
      actorTenants: { cookie_viewer: 'acme' },
    }]
    const explicitResult = oracleFor(server, 'CSRF: cross-origin state change', explicit)
    assert.equal(explicitResult.passed, false)
    assert.match(explicitResult.checks.find(check => check.claim.kind === 'impact')?.detail ?? '', /SameSite=Lax/i)
  } finally {
    await server.close()
    await fx.close()
  }
})

test('parity: guardian_verify confirms a genuine cross-tenant write with a clean readback', async () => {
  const fx = await startFixture({ crossTenantInvoiceWrite: true })
  const server = await startRpc(fx)
  try {
    const before = await rpc(server, 'http', { path: '/api/invoices/i2', persona: 'persona_b' })
    const probe = await rpc(server, 'http', { path: '/api/invoices/i2', method: 'PATCH', body: JSON.stringify({ status: 'void' }), persona: 'viewer' })
    const after = await rpc(server, 'http', { path: '/api/invoices/i2', persona: 'persona_b' })
    const id = (res: RpcResponse) => (res.result as { exchangeId: string }).exchangeId
    const beforeId = id(before)
    const probeId = id(probe)
    const afterId = id(after)

    const claims: VerifyClaim[] = [
      { kind: 'status', exchangeId: probeId, expected: 200 },
      { kind: 'jsonpath', exchangeId: afterId, path: 'status', equals: 'void' },
      {
        kind: 'impact',
        impactClass: 'authorization',
        probeExchangeId: probeId,
        controlExchangeIds: [beforeId],
        beforeExchangeId: beforeId,
        afterExchangeId: afterId,
        resourceTenant: 'globex',
        oracleEvents: ['cross_tenant_write'],
        actorRoles: { viewer: 'viewer', persona_b: 'owner' },
        actorTenants: { viewer: 'acme', persona_b: 'globex' },
      },
    ]
    const result = oracleFor(server, 'Cross-tenant invoice write', claims)
    assert.equal(result.passed, true, result.failures.join('; '))
    assert.equal(result.checks.find(check => check.claim.kind === 'impact')?.passed, true)
  } finally {
    await server.close()
    await fx.close()
  }
})

test('parity: guardian_verify dismisses the decorative 2FA over-claim', async () => {
  const fx = await startFixture()
  const server = await startRpc(fx)
  try {
    const enrolled = await rpc(server, 'http', { path: '/api/me', persona: 'persona_a' })
    const probe = await rpc(server, 'http', {
      path: '/api/auth/2fa',
      method: 'POST',
      persona: 'persona_a',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: '000000' }),
    })
    const enrolledId = (enrolled.result as { exchangeId: string }).exchangeId
    const probeId = (probe.result as { exchangeId: string }).exchangeId
    const claims: VerifyClaim[] = [
      { kind: 'status', exchangeId: probeId, expected: 200 },
      { kind: 'jsonpath', exchangeId: probeId, path: 'ok', equals: true },
      // Even a generic boundary claim over the ungated endpoint cannot confirm an MFA bypass.
      { kind: 'boundary', boundaryClass: 'auth', controlExchangeId: enrolledId, probeExchangeId: probeId },
    ]
    const dismissed = oracleFor(server, '2FA bypass: verification accepts an absent code', claims)
    assert.equal(dismissed.passed, false)
    assert.match(dismissed.failures.join(' '), /MFA\/2FA claim requires an `mfa` claim/i)
  } finally {
    await server.close()
    await fx.close()
  }
})

test('parity: guardian_verify confirms a real MFA bypass with enrolled + pre/post access evidence', async () => {
  const fx = await startFixture()
  const server = await startRpc(fx)
  try {
    const enrolled = await rpc(server, 'http', { path: '/api/me', persona: 'persona_a' })
    const pre = await rpc(server, 'http', { path: '/api/account', persona: 'persona_a' })
    const challenge = await rpc(server, 'http', {
      path: '/api/auth/2fa/verify',
      method: 'POST',
      persona: 'persona_a',
      headers: { 'content-type': 'application/json', 'x-2fa-bypass': '1' },
      body: JSON.stringify({ code: '000000' }),
    })
    const post = await rpc(server, 'http', { path: '/api/account', persona: 'persona_a' })
    const id = (res: RpcResponse) => (res.result as { exchangeId: string }).exchangeId
    const claims: VerifyClaim[] = [
      { kind: 'status', exchangeId: id(pre), expected: 401 },
      { kind: 'status', exchangeId: id(challenge), expected: 200 },
      { kind: 'status', exchangeId: id(post), expected: 200 },
      {
        kind: 'mfa',
        enrolledExchangeId: id(enrolled),
        preChallengeExchangeId: id(pre),
        challengeExchangeId: id(challenge),
        postChallengeExchangeId: id(post),
        actorRoles: { persona_a: 'owner' },
        actorTenants: { persona_a: 'acme' },
      },
    ]
    const result = oracleFor(server, '2FA bypass: verification accepts an absent code', claims)
    assert.equal(result.passed, true, result.failures.join('; '))
    const mfaCheck = result.checks.find(check => check.claim.kind === 'mfa')
    assert.equal(mfaCheck?.passed, true)
  } finally {
    await server.close()
    await fx.close()
  }
})

test('units: boundary classification and the control-denied gate are mechanical', () => {
  assert.equal(classifyBoundaryClaim({ title: '2FA bypass on OTP verification' }), 'mfa')
  assert.equal(classifyBoundaryClaim({ title: 'MFA step-up bypass' }), 'mfa')
  assert.equal(classifyBoundaryClaim({ title: 'SSO confusion between tenants' }), 'auth')
  assert.equal(classifyBoundaryClaim({ cwe: 'CWE-287', title: 'Authentication bypass' }), 'auth')
  assert.equal(classifyBoundaryClaim({ title: 'IDOR on invoice read' }), 'access')
  assert.equal(classifyBoundaryClaim({ title: 'Privilege escalation to admin' }), 'access')
  assert.equal(classifyBoundaryClaim({ title: 'SQL injection in search' }), 'other')

  const actor = (handle: string, role: 'viewer' | 'owner') => ({ handle, role, tenant: 'acme', auth: 'cookie' as const, sameSite: null })
  const steps = [
    { id: 'ctrl', arm: 'control' as const, method: 'POST', route: '/api/auth/2fa/verify', pathAndQuery: '/api/auth/2fa/verify', status: 401, actor: actor('persona_a', 'owner'), responseHeaders: { 'www-authenticate': 'OTP' }, body: '{"error":"mfa_required"}' },
    { id: 'probe', arm: 'probe' as const, method: 'POST', route: '/api/auth/2fa/verify', pathAndQuery: '/api/auth/2fa/verify', status: 200, actor: actor('persona_a', 'owner'), json: { ok: true }, body: '{"ok":true}' },
  ]
  const passed = assessBoundary({ boundaryClass: 'auth', impactClass: 'other', steps })
  assert.equal(passed.satisfied, true)
  assert.equal(passed.arm, 'control_denied')

  const ungated = assessBoundary({ boundaryClass: 'auth', impactClass: 'other', steps: [
    { id: 'ctrl', arm: 'control', method: 'POST', route: '/api/auth/2fa/verify', status: 200, actor: actor('persona_b', 'viewer'), json: { ok: true } },
    { id: 'probe', arm: 'probe', method: 'POST', route: '/api/auth/2fa/verify', status: 200, actor: actor('persona_b', 'viewer'), json: { ok: true } },
  ] })
  assert.equal(ungated.satisfied, false)
})

test('regression: an authz read with a denied anonymous control still confirms (access boundary)', async () => {
  const fx = await startFixture({ crossTenantRead: true })
  try {
    const spec = baseFields(fx.origin, {
      title: 'Cross-tenant invoice read with a denied boundary',
      cwe: 'CWE-639',
      steps: [
        { id: 'boundary', role: 'control', description: 'Anonymous read is denied', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/i1' } },
        { id: 'control', role: 'control', description: 'Acme owner reads its invoice', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/i1', persona: 'persona_a' } },
        { id: 'probe', role: 'probe', description: 'Globex owner reads the Acme invoice', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/api/invoices/i1', persona: 'persona_b' } },
      ],
      assertionsJq: `{
        controlPassed: (.steps.boundary.status == 401 and .steps.control.status == 200 and .steps.control.json.id == "i1"),
        confirmed: (.steps.probe.status == 200 and .steps.probe.json.id == .steps.control.json.id and .steps.probe.json.owner == .steps.control.json.owner),
        observed: ("probe=" + (.steps.probe.status | tostring)),
        expected: "403 for a foreign tenant"
      }`,
    })
    const res = await verify(spec, fx.origin)
    assert.equal(res.verdict, 'confirmed', String(res.outcome.reason))
    const gate = res.evidencePayload.boundaryGate as { satisfied?: boolean; arm?: string } | undefined
    assert.equal(gate?.satisfied, true)
    assert.equal(gate?.arm, 'control_denied')
  } finally { await fx.close() }
})

// ---------------------------------------------------------------------------
// 10. Phase-B K=6 triage: business-logic, markup and anonymous-disclosure over-claims
// ---------------------------------------------------------------------------

const ownerActor = { handle: 'persona_a', role: 'owner' as const, tenant: 'acme', auth: 'cookie' as const, sameSite: 'Lax' as const }
const anonActor = { handle: null, role: null, tenant: null, auth: 'cookie' as const, sameSite: 'Lax' as const }

test('units: a self-service workflow transition is not business-logic impact (K=6 FP)', () => {
  // Owner PATCHes its own invoice draft -> paid: a state echo by an entitled actor.
  const selfService = assessBusinessLogicImpact({
    impactClass: 'business_logic',
    steps: [
      { id: 'before', arm: 'control', method: 'GET', route: '/api/invoices/i1', status: 200, actor: ownerActor, json: { id: 'i1', status: 'draft' } },
      { id: 'probe', arm: 'probe', method: 'PATCH', route: '/api/invoices/i1', status: 200, actor: ownerActor, requestJson: { status: 'paid' }, json: { ok: true } },
      { id: 'after', arm: 'control', method: 'GET', route: '/api/invoices/i1', status: 200, actor: ownerActor, json: { id: 'i1', status: 'paid' } },
    ],
  })
  assert.equal(selfService.required, true)
  assert.equal(selfService.satisfied, false)
  assert.match(selfService.reason, /self-service|non-protected/i)

  // The planted billing tamper moves a *protected* price field: still impact.
  const protectedPrice = assessBusinessLogicImpact({
    impactClass: 'business_logic',
    steps: [
      { id: 'before', arm: 'control', method: 'GET', route: '/api/billing', status: 200, actor: ownerActor, json: { plan: 'pro', price: 4900 } },
      { id: 'probe', arm: 'probe', method: 'PATCH', route: '/api/billing', status: 200, actor: ownerActor, requestJson: { price: 1 }, json: { ok: true } },
      { id: 'after', arm: 'control', method: 'GET', route: '/api/billing', status: 200, actor: ownerActor, json: { plan: 'pro', price: 1 } },
    ],
  })
  assert.equal(protectedPrice.satisfied, true, protectedPrice.reason)

  // The workflow step-skip shape: the identical terminal transition accepted twice.
  const repeated = assessBusinessLogicImpact({
    impactClass: 'business_logic',
    steps: [
      { id: 'first', arm: 'control', method: 'POST', route: '/api/invites/accept', status: 200, actor: ownerActor, requestJson: { token: 't1' } },
      { id: 'repeat', arm: 'probe', method: 'POST', route: '/api/invites/accept', status: 200, actor: ownerActor, requestJson: { token: 't1' } },
    ],
  })
  assert.equal(repeated.satisfied, true, repeated.reason)
})

test('units: markup needs executable content (K=6 FP)', () => {
  const inert = assessMarkupImpact({
    impactClass: 'markup',
    steps: [{ id: 'p', arm: 'probe', method: 'GET', route: '/api/reports/9f1/render', status: 200, actor: ownerActor, body: '<section><h2><b>gnmarker</b></h2></section>' }],
  })
  assert.equal(inert.satisfied, false)
  assert.match(inert.reason, /executable content|not script execution/i)

  const active = assessMarkupImpact({
    impactClass: 'markup',
    steps: [{ id: 'p', arm: 'probe', method: 'GET', route: '/api/reports/9f1/render', status: 200, actor: ownerActor, body: '<section><h2><img src=x onerror="alert(1)"></h2></section>' }],
  })
  assert.equal(active.satisfied, true, active.reason)
})

test('units: anonymous public-route reads need owner-scoped or credential evidence (K=6 FP)', () => {
  const labelsOnly = assessAuthorizationImpact({
    impactClass: 'disclosure',
    steps: [
      { id: 'control', arm: 'control', method: 'GET', route: '/api/reports/none/public', status: 404, actor: anonActor },
      { id: 'probe', arm: 'probe', method: 'GET', route: '/api/reports/9f1/public', status: 200, actor: anonActor, json: { id: '9f1', name: 'Quarterly', summary: 'internal', workspace: 'guardian_state_acme', ref: 'rbc_acme_0123456789ab' } },
    ],
  })
  assert.equal(labelsOnly.satisfied, false)

  const credential = assessAuthorizationImpact({
    impactClass: 'disclosure',
    steps: [
      { id: 'control', arm: 'control', method: 'GET', route: '/api/reports/none/public', status: 404, actor: anonActor },
      { id: 'probe', arm: 'probe', method: 'GET', route: '/api/reports/9f1/public', status: 200, actor: anonActor, json: { data_ref: '[redacted]' }, secretMatches: ['abcdef1234'] },
    ],
  })
  assert.equal(credential.satisfied, true, credential.reason)
})

test('parity: guardian_verify dismisses the K=6 business-logic, markup and disclosure over-claims', async () => {
  const fx = await startFixture()
  const server = await startRpc(fx)
  try {
    const id = (res: RpcResponse) => (res.result as { exchangeId: string }).exchangeId
    const before = id(await rpc(server, 'http', { path: '/api/invoices/i1', persona: 'persona_a' }))
    const patch = id(await rpc(server, 'http', { path: '/api/invoices/i1', method: 'PATCH', body: JSON.stringify({ status: 'paid' }), persona: 'persona_a' }))
    const after = id(await rpc(server, 'http', { path: '/api/invoices/i1', persona: 'persona_a' }))
    const logicNaive: VerifyClaim[] = [
      { kind: 'status', exchangeId: patch, expected: 200 },
      { kind: 'jsonpath', exchangeId: after, path: 'status', equals: 'paid' },
    ]
    const logicTitle = 'Invoice workflow step-skip: client PATCH sets status draft->paid without payment'
    const logic = oracleFor(server, logicTitle, logicNaive)
    assert.equal(logic.passed, false)
    assert.match(logic.failures.join(' '), /impact: business_logic claim requires/i)

    // Even a declared impact claim fails the shared validator for a non-protected self-service field.
    const logicExplicit: VerifyClaim[] = [...logicNaive, {
      kind: 'impact', impactClass: 'business_logic', probeExchangeId: patch,
      controlExchangeIds: [before], afterExchangeId: after, actorRoles: { persona_a: 'owner' },
    }]
    const logicExplicitResult = oracleFor(server, logicTitle, logicExplicit)
    assert.equal(logicExplicitResult.passed, false)
    assert.equal(logicExplicitResult.checks.find(check => check.claim.kind === 'impact')?.passed, false)
    assert.match(logicExplicitResult.failures.join(' '), /self-service|non-protected/i)

    const render = id(await rpc(server, 'http', { path: '/api/reports/9f1/render', persona: 'persona_a' }))
    const markup = oracleFor(server, 'Stored HTML injection via unescaped report name in GET /api/reports/:reportId/render', [
      { kind: 'status', exchangeId: render, expected: 200 },
      { kind: 'body_contains', exchangeId: render, text: '<b>gnmarker</b>' },
    ])
    assert.equal(markup.passed, false)
    assert.match(markup.failures.join(' '), /markup claim dismissed/i)

    const pub = id(await rpc(server, 'http', { path: '/api/reports/9f1/public' }))
    const disclosure = oracleFor(server, 'Unauthenticated report disclosure via /api/reports/:reportId/public (internal workspace + owner ref leaked, no visibility gate)', [
      { kind: 'status', exchangeId: pub, expected: 200 },
      { kind: 'body_contains', exchangeId: pub, text: 'guardian_state_acme' },
    ])
    assert.equal(disclosure.passed, false)
    assert.match(disclosure.failures.join(' '), /disclosure claim dismissed/i)
  } finally {
    await server.close()
    await fx.close()
  }
})

test('parity: executable markup still backs a markup claim', async () => {
  const fx = await startFixture({ reportActiveMarkup: true })
  const server = await startRpc(fx)
  try {
    const render = (await rpc(server, 'http', { path: '/api/reports/9f1/render', persona: 'persona_a' })).result as { exchangeId: string }
    const claims: VerifyClaim[] = [
      { kind: 'status', exchangeId: render.exchangeId, expected: 200 },
      { kind: 'impact', impactClass: 'markup', probeExchangeId: render.exchangeId },
    ]
    const res = oracleFor(server, 'Stored XSS via unescaped report name in render', claims)
    assert.equal(res.passed, true, res.failures.join('; '))
  } finally {
    await server.close()
    await fx.close()
  }
})
