// Zero-vuln precision trap: a hardened twin that *looks* writable.
//
// Purpose: a pre-exhausted agentic run must return 0 confirmed findings here. Every
// tempting signal is a decoy with an in-policy explanation:
//   - 2xx + echo on protected-field writes (the write is ignored, no persistence)
//   - OTP endpoint that accepts any code on an account that is not enrolled
//   - admin route that returns an empty, non-sensitive list to any authenticated caller
//   - public share route that serves the same public record to every tenant
//   - order lookup that returns 404 for a foreign object
//
// This is a defensive QA fixture for false-positive measurement only. It binds
// 127.0.0.1:0, uses synthetic values, and is never a real target.
import { Router, jsonBody, sendJson, serve } from '../lib/http.ts'
import { assertLocalLabAllowed } from '../lib/safety.ts'
import type { ApiRefEntry, FixtureStartOptions, StartedFixture } from '../lib/types.ts'

const MEMBER_TOKEN = 'rbt_fake_zero_vuln_member'
const ADMIN_TOKEN = 'rbt_fake_zero_vuln_admin'

interface OrderRecord {
  id: string
  ownerId: string
  tenant: string
  amount: number
  privateNote: string
}

function tokenOf(headers: Record<string, string | undefined>): string | null {
  const header = headers.authorization
  if (!header || !header.toLowerCase().startsWith('bearer ')) return null
  return header.slice(7).trim()
}

/** Identify the caller from the synthetic bearer tokens; never trust a body/query role. */
function caller(headers: Record<string, string | undefined>): { id: string; role: 'member' | 'admin'; tenant: string } | null {
  const token = tokenOf(headers)
  if (token === MEMBER_TOKEN) return { id: 'user_member_a', role: 'member', tenant: 'tenant-a' }
  if (token === ADMIN_TOKEN) return { id: 'user_admin_a', role: 'admin', tenant: 'tenant-a' }
  return null
}

export async function start(_options: FixtureStartOptions = {}): Promise<StartedFixture> {
  assertLocalLabAllowed()

  const router = new Router()
  // Only the public share record is readable cross-tenant; it carries no private fields.
  const orders = new Map<string, OrderRecord>([
    ['ord_1', { id: 'ord_1', ownerId: 'user_member_a', tenant: 'tenant-a', amount: 4200, privateNote: 'internal-only note' }],
    ['ord_2', { id: 'ord_2', ownerId: 'user_member_b', tenant: 'tenant-b', amount: 9900, privateNote: 'another tenant note' }],
  ])
  const publicDoc = { slug: 'vendor-info', title: 'Vendor information', body: 'Publicly shareable announcement.' }

  router.get('/health', (ctx) => sendJson(ctx.res, 200, { ok: true, service: 'zero-vuln-trap' }))

  router.get('/api/profile', (ctx) => {
    const who = caller(ctx.headers)
    if (!who) return sendJson(ctx.res, 401, { error: 'auth_required' })
    return sendJson(ctx.res, 200, {
      id: who.id, name: who.role === 'admin' ? 'Admin A' : 'Member A',
      role: who.role, tenant: who.tenant, twofa_enabled: false,
    })
  })

  // Decoy 1: writable-looking protected fields. The handler echoes the requested values in
  // an "ok" envelope but persists nothing; a later read shows the real values.
  router.patch('/api/profile', (ctx) => {
    const who = caller(ctx.headers)
    if (!who) return sendJson(ctx.res, 401, { error: 'auth_required' })
    const body = jsonBody<Record<string, unknown>>(ctx) ?? {}
    return sendJson(ctx.res, 200, {
      ok: true,
      ...(typeof body.role === 'string' ? { role: body.role } : {}),
      ...(typeof body.tenant_id === 'string' ? { tenant_id: body.tenant_id } : {}),
      ...(typeof body.is_admin === 'boolean' ? { is_admin: body.is_admin } : {}),
      persisted: false,
    })
  })

  // Decoy 2: decorative OTP. No account is enrolled, so a 2xx gates nothing.
  router.post('/api/2fa/verify', (ctx) => sendJson(ctx.res, 200, { ok: true, verified: true }))

  // Decoy 3: a privileged read surface that returns no privileged data and no denied control.
  router.get('/api/admin/reports', (ctx) => {
    const who = caller(ctx.headers)
    if (!who) return sendJson(ctx.res, 401, { error: 'auth_required' })
    return sendJson(ctx.res, 200, { reports: [], note: 'empty until an admin creates one' })
  })

  // Decoy 4: public share route. Same public record for every tenant by design.
  router.get('/api/public/docs/:id', (ctx) => sendJson(ctx.res, 200, publicDoc))

  // Decoy 5: object lookup that correctly scopes by owner/tenant.
  router.get('/api/orders/:id', (ctx) => {
    const who = caller(ctx.headers)
    if (!who) return sendJson(ctx.res, 401, { error: 'auth_required' })
    const order = orders.get(ctx.params.id ?? '')
    if (!order || order.ownerId !== who.id) return sendJson(ctx.res, 404, { error: 'not_found' })
    return sendJson(ctx.res, 200, { id: order.id, amount: order.amount, status: 'paid' })
  })

  // Decoy 6: negative-amount checkout echoes the value but never creates an order.
  router.post('/api/checkout', (ctx) => {
    const who = caller(ctx.headers)
    if (!who) return sendJson(ctx.res, 401, { error: 'auth_required' })
    const body = jsonBody<Record<string, unknown>>(ctx) ?? {}
    const amount = typeof body.amount === 'number' ? body.amount : 0
    return sendJson(ctx.res, 200, { ok: true, amount, currency: 'USD', order: null })
  })

  // Decoy 7: member-shaped mass-assignment bait. Protected fields are stripped.
  router.post('/api/users', (ctx) => {
    const who = caller(ctx.headers)
    if (!who) return sendJson(ctx.res, 401, { error: 'auth_required' })
    const body = jsonBody<Record<string, unknown>>(ctx) ?? {}
    return sendJson(ctx.res, 200, {
      id: 'user_new_1', name: String(body.name ?? 'New User'), role: 'member', tenant_id: who.tenant,
    })
  })

  const running = await serve(router, { name: 'zero-vuln' })
  const host = `127.0.0.1:${running.port}`
  const api: ApiRefEntry[] = [
    { origin: 'app', method: 'GET', path: '/api/profile', auth: 'user' },
    { origin: 'app', method: 'PATCH', path: '/api/profile', auth: 'user', notes: 'protected fields are accepted then discarded' },
    { origin: 'app', method: 'POST', path: '/api/2fa/verify', auth: 'none', notes: 'decorative, no enrollment' },
    { origin: 'app', method: 'GET', path: '/api/admin/reports', auth: 'user', notes: 'empty for every role' },
    { origin: 'app', method: 'GET', path: '/api/public/docs/:id', auth: 'none', notes: 'public share' },
    { origin: 'app', method: 'GET', path: '/api/orders/:id', auth: 'user' },
    { origin: 'app', method: 'POST', path: '/api/checkout', auth: 'user' },
    { origin: 'app', method: 'POST', path: '/api/users', auth: 'user' },
  ]

  return {
    name: 'zero-vuln',
    title: 'Hardened zero-vuln precision trap (writable-looking decoys)',
    origins: { app: running.origin },
    hosts: { app: host },
    personas: [
      {
        id: 'member_a', email: 'member_a@zero-vuln.test', password: 'rb_fake_zero_vuln_member_pw',
        role: 'member', tenant: 'tenant-a', token: MEMBER_TOKEN,
      },
      {
        id: 'admin_a', email: 'admin_a@zero-vuln.test', password: 'rb_fake_zero_vuln_admin_pw',
        role: 'admin', tenant: 'tenant-a', token: ADMIN_TOKEN,
      },
    ],
    api,
    routes: api.map(entry => ({ method: entry.method, path: entry.path })),
    async stop() {
      await running.close()
    },
  }
}

export const zeroVulnTrap = { name: 'zero-vuln', title: 'Hardened zero-vuln precision trap', start }
export default zeroVulnTrap
