// Realism Fixture #3 — staging safety contract + concurrency.
// A shared stateful store under `staging_isolated` semantics: run-scoped entity tagging
// (`guardian-qa-<runId>-`), write-BOLA, a multi-step checkout that trusts client pricing,
// and an HTTP/2 (h2c) transfer endpoint that loses the single-packet race.
import { createServer as createH2Server, type Http2ServerRequest, type Http2ServerResponse } from 'node:http2'
import { Router, bearer, headerValue, jsonBody, sendJson, serve, type Ctx } from '../../lib/http.ts'
import { assertLocalLabAllowed, closeServer, listenLoopback, originFor } from '../../lib/safety.ts'
import { MemStore, type Row } from '../../lib/store.ts'
import { hexToken } from '../../lib/rand.ts'
import type { ApiRefEntry, FixtureStartOptions, Persona, StartedFixture } from '../../lib/types.ts'

export const RUN_TAG_PREFIX = 'guardian-qa-'

interface UserRow {
  id: string
  email: string
  password: string
  role: 'member' | 'admin'
  tenant: string
}

const USERS: UserRow[] = [
  { id: 'stg-alice', email: 'alice@staging.example.invalid', password: 'rb_fake_stg_alice', role: 'member', tenant: 'tenant-alpha' },
  { id: 'stg-bob', email: 'bob@staging.example.invalid', password: 'rb_fake_stg_bob', role: 'member', tenant: 'tenant-beta' },
]

interface JournalEntry {
  table: string
  id: string
  previous: Row | null
}

export interface StagingFixture extends StartedFixture {
  h2Origin: string
  runTag: (runId: string, label: string) => string
  orphans: (runId?: string) => string[]
  cleanup: (runId: string) => { removed: number; restored: number }
  balance: (accountId: string) => number
}

function readH2Body(req: Http2ServerRequest, limit = 32 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    req.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > limit) {
        reject(new Error('body_limit_exceeded'))
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

function h2Json(res: Http2ServerResponse, status: number, value: unknown): void {
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.end(JSON.stringify(value))
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export async function start(options: FixtureStartOptions = {}): Promise<StagingFixture> {
  void options
  assertLocalLabAllowed()
  const store = new MemStore()
  const tokens = new Map<string, UserRow>()
  const journals = new Map<string, JournalEntry[]>()
  const trackedRuns = new Set<string>()
  let idSeq = 0

  for (const user of USERS) tokens.set(`stg_fake_${user.id}_${hexToken(() => 0.5, 4)}`, user)
  const tokenFor = (userId: string): string => {
    for (const [token, user] of tokens) if (user.id === userId) return token
    throw new Error(`unknown user ${userId}`)
  }

  store.insert('invoices', { id: 'inv-alpha-1', tenant: 'tenant-alpha', total: 100, canary: 'rbs_fake_alpha_invoice' })
  store.insert('invoices', { id: 'inv-beta-1', tenant: 'tenant-beta', total: 200, canary: 'rbs_fake_beta_invoice_canary' })
  store.insert('reports', { id: 'rep-alpha-1', tenant: 'tenant-alpha', title: 'Alpha usage', canary: 'rbs_fake_alpha_report' })
  store.insert('reports', { id: 'rep-beta-1', tenant: 'tenant-beta', title: 'Beta revenue', canary: 'rbs_fake_beta_report_canary' })
  store.insert('accounts', { id: 'acct-alpha', tenant: 'tenant-alpha', balance: 1000 })
  store.insert('accounts', { id: 'acct-beta', tenant: 'tenant-beta', balance: 500 })

  function authUser(ctx: Ctx): UserRow | null {
    const token = bearer(ctx)
    return (token ? tokens.get(token) : undefined) ?? null
  }

  function runIdOf(ctx: Ctx): string | null {
    const raw = headerValue(ctx, 'x-guardian-run-id')
    if (!raw) return null
    return /^[\w.-]{1,64}$/.test(raw) ? raw : null
  }

  function tag(runId: string, label: string): string {
    trackedRuns.add(runId)
    idSeq++
    return `${RUN_TAG_PREFIX}${runId}-${label}-${idSeq}`
  }

  function journal(runId: string | null, table: string, id: string): void {
    if (!runId) return
    trackedRuns.add(runId)
    const list = journals.get(runId) ?? []
    list.push({ table, id, previous: store.get(table, id) })
    journals.set(runId, list)
  }

  function orphans(runId?: string): string[] {
    const prefix = runId ? `${RUN_TAG_PREFIX}${runId}-` : RUN_TAG_PREFIX
    const out: string[] = []
    for (const table of ['invoices', 'reports', 'carts', 'orders']) {
      for (const row of store.all(table)) {
        if (String(row.id).startsWith(prefix)) out.push(`${table}:${String(row.id)}`)
      }
    }
    return out
  }

  function cleanup(runId: string): { removed: number; restored: number } {
    let restored = 0
    let removed = 0
    const entries = journals.get(runId) ?? []
    for (const entry of [...entries].reverse()) {
      if (entry.previous === null) {
        if (store.delete(entry.table, entry.id)) removed++
      } else {
        store.insert(entry.table, entry.previous)
        restored++
      }
    }
    journals.delete(runId)
    const prefix = `${RUN_TAG_PREFIX}${runId}-`
    for (const table of ['invoices', 'reports', 'carts', 'orders']) {
      for (const row of store.all(table)) {
        if (String(row.id).startsWith(prefix) && store.delete(table, String(row.id))) removed++
      }
    }
    return { removed, restored }
  }

  // ---------- HTTP/1.1 app ----------
  const api = new Router()
  api.get('/v1/health', (ctx) => sendJson(ctx.res, 200, { ok: true, mode: 'staging_isolated' }))

  api.get('/v1/invoices/:id', (ctx) => {
    const user = authUser(ctx)
    if (!user) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    const invoice = store.get('invoices', ctx.params.id)
    if (!invoice) {
      sendJson(ctx.res, 404, { error: 'not_found' })
      return
    }
    if (invoice.tenant !== user.tenant) {
      sendJson(ctx.res, 403, { error: 'tenant_scope_violation' })
      return
    }
    sendJson(ctx.res, 200, invoice)
  })

  api.patch('/v1/invoices/:id', (ctx) => {
    const user = authUser(ctx)
    if (!user) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    const body = jsonBody<{ total?: number }>(ctx)
    const invoice = store.get('invoices', ctx.params.id)
    if (!invoice) {
      sendJson(ctx.res, 404, { error: 'not_found' })
      return
    }
    if (typeof body?.total !== 'number') {
      sendJson(ctx.res, 400, { error: 'total_required' })
      return
    }
    const runId = runIdOf(ctx)
    journal(runId, 'invoices', String(invoice.id))
    // Deliberate realism gap: ownership is never compared with the caller's tenant.
    const updated = store.update('invoices', String(invoice.id), { total: body.total })
    sendJson(ctx.res, 200, { invoice: updated, actor: user.id })
  })

  api.get('/v1/reports/:id', (ctx) => {
    const user = authUser(ctx)
    if (!user) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    // Deliberate realism gap: report lookup ignores the tenant entirely.
    const report = store.get('reports', ctx.params.id)
    if (!report) {
      sendJson(ctx.res, 404, { error: 'not_found' })
      return
    }
    sendJson(ctx.res, 200, { report, actor: user.id })
  })

  api.post('/v1/checkout/start', (ctx) => {
    const user = authUser(ctx)
    if (!user) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    const runId = runIdOf(ctx)
    const id = runId ? tag(runId, 'cart') : `cart-${++idSeq}`
    journal(runId, 'carts', id)
    const cart = { id, tenant: user.tenant, unitPrice: 249, quote: null as number | null, status: 'open' }
    store.insert('carts', cart)
    sendJson(ctx.res, 201, { cartId: id, unitPrice: cart.unitPrice })
  })

  api.post('/v1/checkout/quote', (ctx) => {
    const user = authUser(ctx)
    if (!user) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    const body = jsonBody<{ cartId?: string }>(ctx)
    const cart = store.get('carts', String(body?.cartId ?? ''))
    if (!cart || cart.tenant !== user.tenant) {
      sendJson(ctx.res, 404, { error: 'cart_not_found' })
      return
    }
    const total = Number(cart.unitPrice) * 1
    store.update('carts', String(cart.id), { quote: total })
    sendJson(ctx.res, 200, { cartId: cart.id, total, currency: 'USD' })
  })

  api.post('/v1/checkout/pay', (ctx) => {
    const user = authUser(ctx)
    if (!user) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    const body = jsonBody<{ cartId?: string; unitPrice?: number }>(ctx)
    const cart = store.get('carts', String(body?.cartId ?? ''))
    if (!cart || cart.tenant !== user.tenant) {
      sendJson(ctx.res, 404, { error: 'cart_not_found' })
      return
    }
    const runId = runIdOf(ctx)
    const id = runId ? tag(runId, 'order') : `order-${++idSeq}`
    journal(runId, 'orders', id)
    // Deliberate realism gaps: the quote step is optional and client pricing is trusted.
    const total = typeof body?.unitPrice === 'number' ? body.unitPrice : Number(cart.quote ?? cart.unitPrice)
    const order = { id, tenant: user.tenant, cartId: cart.id, total, status: 'paid' }
    store.insert('orders', order)
    store.update('carts', String(cart.id), { status: 'paid' })
    sendJson(ctx.res, 200, { orderId: id, total, charged: true, quoteSkipped: cart.quote === null })
  })

  api.get('/v1/accounts/:id', (ctx) => {
    const user = authUser(ctx)
    if (!user) {
      sendJson(ctx.res, 401, { error: 'unauthorized' })
      return
    }
    const account = store.get('accounts', ctx.params.id)
    if (!account || account.tenant !== user.tenant) {
      sendJson(ctx.res, 404, { error: 'account_not_found' })
      return
    }
    sendJson(ctx.res, 200, account)
  })

  api.get('/__staging__/orphans', (ctx) => {
    const runId = ctx.query.get('runId') ?? undefined
    sendJson(ctx.res, 200, { runId: runId ?? null, orphans: orphans(runId) })
  })

  api.post('/__staging__/cleanup', (ctx) => {
    const runId = ctx.query.get('runId') ?? ''
    if (!/^[\w.-]{1,64}$/.test(runId)) {
      sendJson(ctx.res, 400, { error: 'invalid_run_id' })
      return
    }
    const result = cleanup(runId)
    sendJson(ctx.res, 200, { runId, ...result, remaining: orphans(runId) })
  })

  const apiServer = await serve(api, { name: 'staging.app' })

  // ---------- HTTP/2 (h2c) transfer service ----------
  const h2Sessions = new Set<import('node:http2').ServerHttp2Session>()
  const h2 = createH2Server((req: Http2ServerRequest, res: Http2ServerResponse) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      const authHeader = req.headers.authorization ?? ''
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : ''
      const user = tokens.get(token)
      if (url.pathname === '/v2/health') {
        h2Json(res, 200, { ok: true, protocol: 'h2c' })
        return
      }
      if (url.pathname === '/v2/transfers' && req.method === 'POST') {
        if (!user) {
          h2Json(res, 401, { error: 'unauthorized' })
          return
        }
        let body: { fromAccount?: string; amount?: number; idempotencyKey?: string }
        try {
          body = JSON.parse(await readH2Body(req)) as typeof body
        } catch {
          h2Json(res, 400, { error: 'invalid_json' })
          return
        }
        const accountId = body.fromAccount ?? 'acct-alpha'
        const account = store.get('accounts', accountId)
        if (!account || account.tenant !== user.tenant) {
          h2Json(res, 404, { error: 'account_not_found' })
          return
        }
        const amount = Number(body.amount ?? 0)
        const observed = Number(account.balance)
        // Deliberate realism gap: read-then-write with no atomic compare-and-set. Issuing
        // both streams in the same packet makes both observe the pre-transfer balance.
        await sleep(5)
        if (observed < amount) {
          h2Json(res, 409, { error: 'insufficient_funds', balance: observed })
          return
        }
        store.update('accounts', accountId, { balance: observed - amount })
        h2Json(res, 200, {
          transferred: amount,
          observedBalance: observed,
          idempotencyKey: body.idempotencyKey ?? null,
          deduplicated: false,
        })
        return
      }
      h2Json(res, 404, { error: 'not_found', path: url.pathname })
    })()
  })
  h2.on('session', (session) => {
    h2Sessions.add(session)
    session.on('close', () => h2Sessions.delete(session))
  })
  const h2Port = await listenLoopback(h2 as unknown as import('../../lib/safety.ts').Listenable)
  const h2Origin = originFor(h2Port)

  const personas: Persona[] = USERS.map((user) => ({
    id: user.id,
    email: user.email,
    password: user.password,
    role: user.role,
    tenant: user.tenant,
    token: tokenFor(user.id),
  }))

  const apiRef: ApiRefEntry[] = [
    { origin: 'app', method: 'GET', path: '/v1/invoices/:id', auth: 'tenant', notes: 'ownership enforced' },
    { origin: 'app', method: 'PATCH', path: '/v1/invoices/:id', auth: 'tenant', notes: 'JSON {total}; run-scoped tagging via X-Guardian-Run-Id' },
    { origin: 'app', method: 'GET', path: '/v1/reports/:id', auth: 'user' },
    { origin: 'app', method: 'POST', path: '/v1/checkout/start', auth: 'tenant' },
    { origin: 'app', method: 'POST', path: '/v1/checkout/quote', auth: 'tenant', notes: 'JSON {cartId}' },
    { origin: 'app', method: 'POST', path: '/v1/checkout/pay', auth: 'tenant', notes: 'JSON {cartId, unitPrice?}' },
    { origin: 'app', method: 'GET', path: '/v1/accounts/:id', auth: 'tenant' },
    { origin: 'h2', method: 'POST', path: '/v2/transfers', auth: 'tenant', notes: 'h2c; JSON {fromAccount,amount,idempotencyKey}' },
    { origin: 'app', method: 'POST', path: '/__staging__/cleanup?runId=', auth: 'none', notes: 'restores mutations, deletes run-tagged rows' },
    { origin: 'app', method: 'GET', path: '/__staging__/orphans?runId=', auth: 'none' },
  ]

  let stopped = false
  const stop = async () => {
    if (stopped) return
    stopped = true
    for (const runId of [...trackedRuns]) cleanup(runId)
    for (const session of h2Sessions) session.close()
    h2Sessions.clear()
    await Promise.all([apiServer.close(), closeServer(h2)])
    const leaked = orphans()
    store.clear()
    trackedRuns.clear()
    journals.clear()
    if (leaked.length > 0) throw new Error(`staging fixture leaked run-tagged records: ${leaked.join(', ')}`)
  }

  return {
    name: 'staging-concurrency',
    title: 'Staging isolated safety: write-BOLA, checkout workflow, HTTP/2 race, orphan-free cleanup',
    origins: { app: apiServer.origin, h2: h2Origin },
    hosts: { 'staging.local': `127.0.0.1:${apiServer.port}`, 'staging-h2.local': `127.0.0.1:${h2Port}` },
    personas,
    api: apiRef,
    h2Origin,
    runTag: (runId, label) => `${RUN_TAG_PREFIX}${runId}-${label}`,
    orphans,
    cleanup,
    balance: (accountId) => Number(store.get('accounts', accountId)?.balance ?? 0),
    stop,
  }
}
