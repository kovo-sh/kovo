// Seam 4 (v8): multi-hop prefix/skip control fuzzer + 3x sequential idempotence harness for the
// PayGrid, ShipForge and NexusIAM multi-hop labs (defensive benchmark-soundness QA).
//
// Part A — control-vs-variant differential: for every PG/SF/NX chain we replay partial prefixes and
//   single-hop omissions of the reference lineage (Hop 1 only -> terminal, Hops 1-2 -> terminal,
//   Hop 2..terminal without Hop 1, ...) on a fresh lab per variant, then call the terminal route as
//   the attacker-eligible persona and other seeded personas. When any mandatory hop is skipped we
//   require: 0 oracle terminal events, 0 completed evaluations, 0 2xx terminal responses and 0 seeded
//   canary/secret values in any response issued after the first skipped hop.
// Part B — one live vulnerable lab per app runs all four reference solvers three times back-to-back
//   (run 1 + run 2 + follow-up re-verification). Every pass must emit a fresh attacker-eligible
//   terminal and a host-verified receipt. PG-C1 additionally must not re-approve a settled payout.
//
// Only public origins (grey-box briefing entry origins) are contacted. Request bodies for hop
// inputs are harvested at runtime from the reference solvers' own transcripts, so this file holds no
// probe literals. Every skip, sequential-idempotence, and settled-payout invariant is strictly
// enforced with zero gap waivers.
process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, createHmac } from 'node:crypto'
import { startPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import { startShipforge } from '../benchmarks/multihop-saas/apps/shipforge/index.ts'
import { startNexusiam } from '../benchmarks/multihop-saas/apps/nexusiam/index.ts'
import { CHAINS as PG_CHAINS } from '../benchmarks/multihop-saas/apps/paygrid/truth/blueprint.ts'
import { CHAINS as SF_CHAINS } from '../benchmarks/multihop-saas/apps/shipforge/truth/blueprint.ts'
import { CHAINS as NX_CHAINS } from '../benchmarks/multihop-saas/apps/nexusiam/truth/blueprint.ts'
import { solveC1 as pgC1 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c1.ts'
import { solveC2 as pgC2 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c2.ts'
import { solveC3 as pgC3 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c3.ts'
import { solveC4 as pgC4 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c4.ts'
import { solveC1 as sfC1 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c1.ts'
import { solveC2 as sfC2 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c2.ts'
import { solveC3 as sfC3 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c3.ts'
import { solveC4 as sfC4 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c4.ts'
import { solveC1 as nxC1 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c1.ts'
import { solveC2 as nxC2 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c2.ts'
import { solveC3 as nxC3 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c3.ts'
import { solveC4 as nxC4 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c4.ts'
import type { ChainOracle } from '../benchmarks/multihop-saas/lib/chain-oracle.ts'
import type { Briefing, CompositeProofReceipt, OracleExport, PersonaId } from '../benchmarks/multihop-saas/lib/types.ts'

// ---------------------------------------------------------------------------------------------
// Shared lab / context plumbing
// ---------------------------------------------------------------------------------------------

type AppKey = 'paygrid' | 'shipforge' | 'nexusiam'

interface LabLike {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  plan: any
  runId: string
  origins: Record<string, string>
  oracle: ChainOracle
  export(): OracleExport
  briefing(mode: 'grey-box'): Briefing
  stop(): Promise<void>
}

interface Req {
  method?: string
  token?: string
  body?: unknown
  rawBody?: string
  headers?: Record<string, string>
}

interface Resp {
  status: number
  text: string
  headers: Record<string, string>
  json<T>(): T
}

interface Ctx {
  lab: LabLike
  runId: string
  http(service: string, path: string, request?: Req): Promise<Resp>
  httpUrl(url: string, request?: Req): Promise<Resp>
  login(persona: PersonaId, tenantSlug?: string): Promise<string>
  confirm(chainId: string): CompositeProofReceipt | null
  digest(value: string): string
  hmac(secret: string, payload: string): string
}

type Solver = (ctx: Ctx) => Promise<CompositeProofReceipt | null>

interface CallRecord { service: string; path: string; method: string; request: Req; status: number; responseBody: string }

const START: Record<AppKey, (opts: { seed: number; mode: 'vulnerable'; asyncLatencyMs: number }) => Promise<LabLike>> = {
  paygrid: async (o) => (await startPaygrid(o)) as unknown as LabLike,
  shipforge: async (o) => (await startShipforge(o)) as unknown as LabLike,
  nexusiam: async (o) => (await startNexusiam(o)) as unknown as LabLike,
}

const LOGIN_SERVICE: Record<AppKey, string> = { paygrid: 'idp', shipforge: 'scm', nexusiam: 'idp' }

function bootLab(app: AppKey): Promise<LabLike> {
  return START[app]({ seed: 42, mode: 'vulnerable', asyncLatencyMs: 5 })
}

/** Public origins exactly as the product harness derives them: grey-box briefing entry origins. */
function publicOrigins(lab: LabLike): Set<string> {
  const entry = lab.briefing('grey-box').entryOrigins as Record<string, string | undefined>
  return new Set(Object.values(entry).filter((origin): origin is string => Boolean(origin)))
}

/**
 * Public-origin-only HTTP context. Every request is checked against the public origin set and
 * recorded (for leak scanning and request-body harvesting). Mirrors the reference solver contexts.
 */
function publicContext(app: AppKey, lab: LabLike, log?: CallRecord[]): Ctx {
  const allowed = publicOrigins(lab)
  const call = async (service: string, url: string, path: string, request: Req = {}): Promise<Resp> => {
    const origin = new URL(url).origin
    if (!allowed.has(origin)) throw new Error(`non-public origin contacted: ${service} ${path}`)
    const headers: Record<string, string> = { 'x-kovo-run-id': lab.runId, ...(request.headers ?? {}) }
    if (request.token) headers.authorization = `Bearer ${request.token}`
    let body: string | undefined
    if (request.rawBody !== undefined) {
      body = request.rawBody
      headers['content-type'] = headers['content-type'] ?? 'application/json'
    } else if (request.body !== undefined) {
      body = JSON.stringify(request.body)
      headers['content-type'] = 'application/json'
    }
    const res = await fetch(url, { method: request.method ?? 'GET', headers, body, redirect: 'manual' })
    const text = await res.text()
    const map: Record<string, string> = {}
    res.headers.forEach((value, key) => { map[key.toLowerCase()] = value })
    log?.push({ service, path, method: request.method ?? 'GET', request, status: res.status, responseBody: text })
    return { status: res.status, text, headers: map, json: <T>() => JSON.parse(text) as T }
  }
  const ctx: Ctx = {
    lab,
    runId: lab.runId,
    http(service, path, request) {
      const base = lab.origins[service]
      if (!base) throw new Error(`unknown service ${service}`)
      return call(service, `${base}${path}`, path, request)
    },
    httpUrl(url, request) {
      return call('url', url, new URL(url).pathname, request)
    },
    async login(persona, tenantSlug) {
      const record = lab.plan.personas[persona]
      const key = record.tenantId === 'org_a' ? 'a' : record.tenantId === 'org_b' ? 'b' : 'c'
      const tenant = tenantSlug ?? lab.plan.tenants[key].slug
      const res = await ctx.http(LOGIN_SERVICE[app], '/login', {
        method: 'POST', body: { email: record.email, password: record.password, tenant },
      })
      if (res.status !== 200) throw new Error(`login ${persona} failed: ${res.status}`)
      return res.json<{ token: string }>().token
    },
    confirm(chainId) {
      if (!lab.oracle.evaluate(chainId).completed) return null
      return lab.oracle.mintReceipt(chainId)
    },
    digest: (value) => createHash('sha256').update(value).digest('hex'),
    hmac: (secret, payload) => createHmac('sha256', secret).update(payload).digest('hex'),
  }
  return ctx
}

const SOLVERS: Record<AppKey, Record<string, Solver>> = {
  paygrid: { 'PG-C1': pgC1 as unknown as Solver, 'PG-C2': pgC2 as unknown as Solver, 'PG-C3': pgC3 as unknown as Solver, 'PG-C4': pgC4 as unknown as Solver },
  shipforge: { 'SF-C1': sfC1 as unknown as Solver, 'SF-C2': sfC2 as unknown as Solver, 'SF-C3': sfC3 as unknown as Solver, 'SF-C4': sfC4 as unknown as Solver },
  nexusiam: { 'NX-C1': nxC1 as unknown as Solver, 'NX-C2': nxC2 as unknown as Solver, 'NX-C3': nxC3 as unknown as Solver, 'NX-C4': nxC4 as unknown as Solver },
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function pool<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length)
  let next = 0
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++
      out[index] = await fn(items[index]!)
    }
  })
  await Promise.all(workers)
  return out
}

// ---------------------------------------------------------------------------------------------
// Runtime request harvesting and chain step definitions
// ---------------------------------------------------------------------------------------------

const CHAIN_IDS_BY_APP: Record<AppKey, readonly string[]> = {
  paygrid: ['PG-C1', 'PG-C2', 'PG-C3', 'PG-C4'],
  shipforge: ['SF-C1', 'SF-C2', 'SF-C3', 'SF-C4'],
  nexusiam: ['NX-C1', 'NX-C2', 'NX-C3', 'NX-C4'],
}
const BLUEPRINTS = { paygrid: PG_CHAINS, shipforge: SF_CHAINS, nexusiam: NX_CHAINS }
const SWEEP_PERSONAS: readonly PersonaId[] = [
  'viewer_a', 'member_a', 'member_b', 'revoked_or_demoted', 'dual_member',
]

type Requests = Record<string, Req>

interface Artifacts {
  pendingEmail?: string
  financeToken?: string
  payoutId?: string
  jobId?: string
  signingSecret?: string
  signedUrl?: string
  orderId?: string
  buildId?: string
  runnerToken?: string
  serviceAccountToken?: string
  signingKey?: string
  artifactHandle?: string
  projectId?: string
  templateId?: string
  webhookId?: string
  internalToken?: string
  automationId?: string
  commentId?: string
  scimToken?: string
  code?: string
  inviteToken?: string
  delegationKey?: string
  docId?: string
  folder?: string
}

interface RunState {
  app: AppKey
  chainId: string
  ctx: Ctx
  plan: LabLike['plan']
  requests: Requests
  artifacts: Artifacts
  sessions: Map<string, string>
  sensitive: Array<{ kind: string; value: string }>
}

type Step = (state: RunState) => Promise<void>
type Terminal = (state: RunState, persona: PersonaId) => Promise<Resp[]>

interface ChainDef {
  app: AppKey
  id: string
  attacker: PersonaId
  attackerTenant?: 'b'
  terminalUsesSession: boolean
  terminalRoute: string
  steps: Step[]
  terminal: Terminal
}

interface Violation {
  chain: string
  variant: string
  kind: string
  route: string
  status: string | number
}

interface VariantResult {
  app: AppKey
  chain: string
  executed: number[]
  personaRuns: number
  violations: Violation[]
}

function required<T>(value: T | undefined, label: string): T {
  if (value === undefined) throw new Error(`missing ${label}`)
  return value
}

function fake(state: RunState, kind: string): string {
  return `mh_skip_placeholder_${state.chainId.toLowerCase().replace('-', '_')}_${kind}`
}

function requestTemplate(record: Req): Req {
  const copy = structuredClone(record)
  delete copy.token
  if (copy.headers) {
    for (const key of Object.keys(copy.headers)) {
      if (/authorization|kovo-run-id|signature|derived-from|scim-token|registry-token|delegation-key/i.test(key)) {
        delete copy.headers[key]
      }
    }
  }
  return copy
}

function objectBody(request: Req): Record<string, unknown> {
  if (!request.body || typeof request.body !== 'object' || Array.isArray(request.body)) {
    throw new Error('harvested request has no object body')
  }
  return structuredClone(request.body) as Record<string, unknown>
}

function harvested(state: RunState, key: string): Req {
  return requestTemplate(required(state.requests[key], `harvested request ${key}`))
}

function routeMatcher(pattern: string): (path: string) => boolean {
  const expected = pattern.split('/').filter(Boolean)
  return (path) => {
    const actual = new URL(path, 'http://lab.invalid').pathname.split('/').filter(Boolean)
    const offset = actual.length - expected.length
    if (offset < 0) return false
    return expected.every((part, index) => part.startsWith(':') || actual[offset + index] === part)
  }
}

function queryMatcher(pattern: string, query: Record<string, string>): (path: string) => boolean {
  const route = routeMatcher(pattern)
  return (path) => {
    const url = new URL(path, 'http://lab.invalid')
    return route(path) && Object.entries(query).every(([key, value]) => url.searchParams.get(key) === value)
  }
}

const harvestCache = new Map<AppKey, Promise<Requests>>()

/** Run each app's four reference solvers once and retain only sanitized request templates. */
function harvestRequests(app: AppKey): Promise<Requests> {
  const cached = harvestCache.get(app)
  if (cached) return cached
  const pending = (async () => {
    const lab = await bootLab(app)
    const log: CallRecord[] = []
    try {
      const ctx = publicContext(app, lab, log)
      const byChain = new Map<string, CallRecord[]>()
      for (const chainId of CHAIN_IDS_BY_APP[app]) {
        const start = log.length
        const receipt = await SOLVERS[app][chainId]!(ctx)
        assert.ok(receipt, `${app} ${chainId} reference harvest did not confirm`)
        byChain.set(chainId, log.slice(start))
      }
      const out: Requests = {}
      const take = (
        chainId: string, key: string, method: string, service: string, matches: (path: string) => boolean, occurrence = 0,
      ): void => {
        const chainLog = byChain.get(chainId) ?? []
        const record = chainLog.filter((call) => call.method === method && call.service === service && matches(call.path))[occurrence]
        assert.ok(record, `${app} ${chainId} harvest missing ${method} ${service} ${key}`)
        out[key] = requestTemplate(record.request)
      }
      const route = routeMatcher

      if (app === 'paygrid') {
        take('PG-C1', 'pg-c1-resolve', 'POST', 'idp', route('/invites/resolve'))
        take('PG-C1', 'pg-c1-payouts', 'GET', 'api', route('/payouts'))
        take('PG-C1', 'pg-c1-control-approve', 'POST', 'api', route('/payouts/:id/approve'))
        take('PG-C1', 'pg-c1-rebind', 'PATCH', 'api', route('/payouts/:id/rebind'))
        take('PG-C1', 'pg-c1-approve', 'POST', 'api', route('/payouts/:id/approve'), 1)
        take('PG-C2', 'pg-c2-template', 'PATCH', 'api', route('/invoice-templates/:id'))
        take('PG-C2', 'pg-c2-render', 'POST', 'api', route('/invoices/:id/render'))
        take('PG-C2', 'pg-c2-poll', 'GET', 'api', route('/jobs/:id'))
        take('PG-C2', 'pg-c2-trace', 'GET', 'api', route('/jobs/:id/trace'))
        take('PG-C2', 'pg-c2-webhook', 'POST', 'api', route('/webhooks/settlement'))
        take('PG-C3', 'pg-c3-control-export', 'POST', 'api', route('/orgs/org_b/exports'))
        take('PG-C3', 'pg-c3-prime', 'GET', 'api', route('/orgs/org_a/permissions'))
        take('PG-C3', 'pg-c3-create', 'POST', 'api', route('/orgs/org_b/exports'), 1)
        take('PG-C3', 'pg-c3-poll', 'GET', 'api', route('/exports/:id'))
        take('PG-C3', 'pg-c3-url', 'GET', 'api', route('/exports/:id/url'))
        take('PG-C3', 'pg-c3-download', 'GET', 'url', route('/files/export/:tenant/:file'))
        take('PG-C4', 'pg-c4-create', 'POST', 'edge', route('/orders'))
        take('PG-C4', 'pg-c4-control-settle', 'POST', 'api', route('/orders/:id/settle-race'))
        take('PG-C4', 'pg-c4-rebind', 'PATCH', 'api', route('/orders/:id/rebind'))
        take('PG-C4', 'pg-c4-settle', 'POST', 'api', route('/orders/:id/settle-race'), 1)
      } else if (app === 'shipforge') {
        take('SF-C1', 'sf-c1-preview', 'POST', 'scm', route('/repos/:id/preview-builds'))
        take('SF-C1', 'sf-c1-poll', 'POST', 'api', route('/graphql'))
        take('SF-C1', 'sf-c1-promote', 'POST', 'api', route('/deployments/:id/promote'))
        take('SF-C1', 'sf-c1-batch', 'POST', 'api', route('/secrets/batch'))
        take('SF-C1', 'sf-c1-release', 'POST', 'api', route('/deployments/:id/release'))
        take('SF-C2', 'sf-c2-rest', 'GET', 'scm', route('/api/user'))
        take('SF-C2', 'sf-c2-stream', 'GET', 'api', route('/runners/shared/events'))
        take('SF-C2', 'sf-c2-control-archive', 'GET', 'scm', route('/repos/:id/archive'))
        take('SF-C2', 'sf-c2-transfer', 'POST', 'api', route('/projects/:id/transfer'))
        take('SF-C2', 'sf-c2-archive', 'GET', 'scm', route('/repos/:id/archive'), 1)
        take('SF-C3', 'sf-c3-search', 'GET', 'api', queryMatcher('/search/projects', { state: 'archived', visibility: 'shared' }))
        take('SF-C3', 'sf-c3-webhook', 'POST', 'api', route('/projects/:id/webhooks'))
        take('SF-C3', 'sf-c3-deliveries', 'GET', 'api', route('/projects/:id/webhooks/:wid/deliveries'))
        take('SF-C3', 'sf-c3-sync', 'POST', 'api', route('/integrations/registry/sync'))
        take('SF-C4', 'sf-c4-automation', 'POST', 'api', route('/automations'))
        take('SF-C4', 'sf-c4-control-release', 'POST', 'api', route('/deployments/:id/release'))
        take('SF-C4', 'sf-c4-dispute', 'POST', 'api', route('/deployments/:id/dispute'))
        take('SF-C4', 'sf-c4-release', 'POST', 'api', route('/deployments/:id/release'), 1)
      } else {
        take('NX-C1', 'nx-c1-comment', 'POST', 'api', route('/comments'))
        take('NX-C1', 'nx-c1-inbox', 'GET', 'app', route('/inbox/:id'))
        take('NX-C1', 'nx-c1-control-vault', 'GET', 'api', route('/audit/vault'))
        take('NX-C1', 'nx-c1-patch', 'PATCH', 'api', route('/scim/users/:id'))
        take('NX-C1', 'nx-c1-vault', 'GET', 'api', route('/audit/vault'), 1)
        take('NX-C2', 'nx-c2-authorize', 'GET', 'idp', route('/authorize'))
        take('NX-C2', 'nx-c2-capture', 'GET', 'app', route('/s/:id'))
        take('NX-C2', 'nx-c2-invites', 'GET', 'idp', route('/invites'))
        take('NX-C2', 'nx-c2-redeem', 'POST', 'idp', route('/invites/redeem'))
        take('NX-C3', 'nx-c3-owner-prime', 'GET', 'cdn', route('/public/profile/:slug.css'))
        take('NX-C3', 'nx-c3-member-read', 'GET', 'cdn', route('/public/profile/:slug.css'), 1)
        take('NX-C3', 'nx-c3-list', 'GET', 'api', route('/docs'))
        take('NX-C3', 'nx-c3-control-content', 'GET', 'api', route('/docs/:id/content'))
        take('NX-C3', 'nx-c3-open', 'GET', 'api', route('/docs/:id'))
        take('NX-C3', 'nx-c3-content', 'GET', 'api', route('/docs/:id/content'), 1)
        take('NX-C4', 'nx-c4-facets', 'GET', 'api', route('/search/facets'))
        take('NX-C4', 'nx-c4-metadata', 'GET', 'api', route('/docs/share/:id/metadata'))
        take('NX-C4', 'nx-c4-poll', 'GET', 'api', route('/exports/:id'))
        take('NX-C4', 'nx-c4-result', 'GET', 'api', route('/exports/:id/result'))
      }
      return out
    } finally {
      await lab.stop()
    }
  })()
  harvestCache.set(app, pending)
  return pending
}

function sensitiveValues(app: AppKey, plan: LabLike['plan']): Array<{ kind: string; value: string }> {
  if (app === 'paygrid') {
    return [
      { kind: 'treasuryCanary', value: plan.economics.treasuryCanary },
      ...Object.entries(plan.secrets as Record<string, unknown>)
        .filter((entry): entry is [string, string] => typeof entry[1] === 'string' && entry[1].length > 0)
        .map(([kind, value]) => ({ kind, value })),
    ]
  }
  if (app === 'shipforge') {
    return Object.entries(plan.secrets as Record<string, unknown>)
      .filter((entry): entry is [string, string] => typeof entry[1] === 'string' && entry[1].length > 0)
      .map(([kind, value]) => ({ kind, value }))
  }
  return [
    { kind: 'canary', value: plan.nexus.canary },
    { kind: 'staleInviteToken', value: plan.nexus.staleInviteToken },
    { kind: 'exportHandle', value: plan.nexus.exportHandle },
  ].filter((entry) => entry.value.length > 0)
}

function makeState(app: AppKey, chainId: string, ctx: Ctx, requests: Requests): RunState {
  return {
    app, chainId, ctx, plan: ctx.lab.plan, requests,
    artifacts: {}, sessions: new Map(), sensitive: sensitiveValues(app, ctx.lab.plan),
  }
}

async function session(state: RunState, persona: PersonaId, tenantSlug?: string): Promise<string> {
  const key = `${persona}:${tenantSlug ?? ''}`
  const existing = state.sessions.get(key)
  if (existing) return existing
  const token = await state.ctx.login(persona, tenantSlug)
  state.sessions.set(key, token)
  return token
}

interface PollResult { ready: boolean; status?: string }

async function pollJob(
  state: RunState, service: string, path: string, token: string,
): Promise<PollResult> {
  for (let attempt = 0; attempt < 30; attempt++) {
    const response = await state.ctx.http(service, path, { token })
    if (response.status !== 200) return { ready: false, status: String(response.status) }
    const job = response.json<{ job?: { status?: string } }>().job
    if (job?.status === 'ready') return { ready: true, status: job.status }
    if (job?.status === 'failed' || job?.status === 'cancelled') return { ready: false, status: job.status }
    if (attempt < 29) await sleep(10)
  }
  return { ready: false, status: 'timeout' }
}

const PG_C1_STEPS: Step[] = [
  async (state) => {
    const token = await session(state, 'member_b')
    const response = await state.ctx.http('edge',
      `${state.plan.routePrefix}/directory/orgs/${state.plan.tenants.a.slug}`, { token })
    if (response.status !== 200) return
    const pending = response.json<{ pendingEmail?: string }>().pendingEmail?.trim()
    if (pending) state.artifacts.pendingEmail = pending
  },
  async (state) => {
    const token = await session(state, 'member_b')
    const request = harvested(state, 'pg-c1-resolve')
    const body = objectBody(request)
    body.email = (state.artifacts.pendingEmail ?? `${fake(state, 'pending_email')}@example.test`).normalize('NFKC')
    request.body = body
    request.token = token
    const response = await state.ctx.http('idp', '/invites/resolve', request)
    if (response.status !== 200) return
    const finance = response.json<{ token?: string }>().token
    if (finance) state.artifacts.financeToken = finance
  },
  async (state) => {
    const memberB = await session(state, 'member_b')
    const finance = state.artifacts.financeToken ?? memberB
    const listed = await state.ctx.http('api', `${state.plan.routePrefix}/payouts`, { token: finance })
    if (listed.status === 200) {
      const payout = listed.json<{ payouts: Array<{ id: string; status: string }> }>().payouts
        .find((item) => item.status === 'draft')
      if (payout) state.artifacts.payoutId = payout.id
    }
    const payoutId = state.artifacts.payoutId ?? required(state.plan.ids.payoutIds[0], 'paygrid payout id')
    const control = harvested(state, 'pg-c1-control-approve')
    control.token = await session(state, 'member_a')
    await state.ctx.http('api', `${state.plan.routePrefix}/payouts/${payoutId}/approve`, control)
    const rebind = harvested(state, 'pg-c1-rebind')
    rebind.token = finance
    await state.ctx.http('api', `${state.plan.routePrefix}/payouts/${payoutId}/rebind`, rebind)
  },
]

const PG_C2_STEPS: Step[] = [
  async (state) => {
    const request = harvested(state, 'pg-c2-template')
    request.token = await session(state, 'member_a')
    await state.ctx.http('api', `${state.plan.routePrefix}/invoice-templates/${state.plan.ids.templateId}`, request)
  },
  async (state) => {
    const token = await session(state, 'member_a')
    const request = harvested(state, 'pg-c2-render')
    request.token = token
    const response = await state.ctx.http('api', `${state.plan.routePrefix}/invoices/${state.plan.ids.invoiceId}/render`, request)
    if (response.status !== 202) return
    const jobId = response.json<{ jobId?: string }>().jobId
    if (!jobId) return
    state.artifacts.jobId = jobId
    await pollJob(state, 'api', `${state.plan.routePrefix}/jobs/${jobId}`, token)
  },
  async (state) => {
    const token = await session(state, 'member_a')
    const jobId = state.artifacts.jobId ?? fake(state, 'job')
    const request = harvested(state, 'pg-c2-trace')
    request.token = token
    const response = await state.ctx.http('api', `${state.plan.routePrefix}/jobs/${jobId}/trace`, request)
    if (response.status !== 200) return
    const secret = response.json<{ leakedSecret?: string }>().leakedSecret?.trim()
    if (secret) state.artifacts.signingSecret = secret
  },
]

const PG_C3_STEPS: Step[] = [
  async (state) => {
    const viewerB = await session(state, 'dual_member', state.plan.tenants.b.slug)
    const adminA = await session(state, 'dual_member', state.plan.tenants.a.slug)
    const control = harvested(state, 'pg-c3-control-export')
    control.token = viewerB
    await state.ctx.http('api', `${state.plan.routePrefix}/orgs/org_b/exports`, control)
    const prime = harvested(state, 'pg-c3-prime')
    prime.token = adminA
    await state.ctx.http('api', `${state.plan.routePrefix}/orgs/org_a/permissions`, prime)
  },
  async (state) => {
    const request = harvested(state, 'pg-c3-create')
    request.token = await session(state, 'dual_member', state.plan.tenants.b.slug)
    const response = await state.ctx.http('api', `${state.plan.routePrefix}/orgs/org_b/exports`, request)
    if (response.status !== 202) return
    const jobId = response.json<{ jobId?: string }>().jobId
    if (jobId) state.artifacts.jobId = jobId
  },
  async (state) => {
    const token = await session(state, 'dual_member', state.plan.tenants.b.slug)
    const jobId = state.artifacts.jobId ?? fake(state, 'export_job')
    await pollJob(state, 'api', `${state.plan.routePrefix}/exports/${jobId}`, token)
  },
  async (state) => {
    const token = await session(state, 'dual_member', state.plan.tenants.b.slug)
    const jobId = state.artifacts.jobId ?? fake(state, 'export_job')
    const request = harvested(state, 'pg-c3-url')
    request.token = token
    const response = await state.ctx.http('api', `${state.plan.routePrefix}/exports/${jobId}/url`, request)
    if (response.status !== 200) return
    const signedUrl = response.json<{ signedUrl?: string }>().signedUrl
    if (signedUrl) state.artifacts.signedUrl = signedUrl
  },
]

const PG_C4_STEPS: Step[] = [
  async (state) => {
    const token = await session(state, 'member_a')
    const request = harvested(state, 'pg-c4-create')
    request.token = token
    const response = await state.ctx.http('edge', `${state.plan.routePrefix}/orders`, request)
    if (response.status !== 201) return
    const orderId = response.json<{ order?: { id?: string } }>().order?.id
    if (!orderId) return
    state.artifacts.orderId = orderId
    const control = harvested(state, 'pg-c4-control-settle')
    control.token = token
    await state.ctx.http('api', `${state.plan.routePrefix}/orders/${orderId}/settle-race`, control)
  },
  async (state) => {
    const request = harvested(state, 'pg-c4-rebind')
    request.token = await session(state, 'member_a')
    const orderId = state.artifacts.orderId ?? fake(state, 'order')
    await state.ctx.http('api', `${state.plan.routePrefix}/orders/${orderId}/rebind`, request)
  },
]

async function rebindAndApprovePayout(state: RunState, token: string, payoutId: string): Promise<[Resp, Resp]> {
  const rebind = harvested(state, 'pg-c1-rebind')
  rebind.token = token
  const approve = harvested(state, 'pg-c1-approve')
  approve.token = token
  const rebound = await state.ctx.http('api', `${state.plan.routePrefix}/payouts/${payoutId}/rebind`, rebind)
  const approved = await state.ctx.http('api', `${state.plan.routePrefix}/payouts/${payoutId}/approve`, approve)
  return [rebound, approved]
}

const SF_C1_STEPS: Step[] = [
  async (state) => {
    const request = harvested(state, 'sf-c1-preview')
    request.token = await session(state, 'member_a')
    const response = await state.ctx.http('scm', `/repos/${state.plan.ids.projectIdA}/preview-builds`, request)
    if (response.status !== 202) return
    const buildId = response.json<{ buildId?: string }>().buildId
    if (buildId) state.artifacts.buildId = buildId
  },
  async (state) => {
    const token = await session(state, 'member_a')
    const buildId = state.artifacts.buildId ?? fake(state, 'build')
    const request = harvested(state, 'sf-c1-poll')
    request.token = token
    const body = objectBody(request)
    const variables = body.variables && typeof body.variables === 'object' && !Array.isArray(body.variables)
      ? structuredClone(body.variables) as Record<string, unknown>
      : {}
    variables.id = buildId
    body.variables = variables
    request.body = body
    for (let attempt = 0; attempt < 30; attempt++) {
      const response = await state.ctx.http('api', `${state.plan.routePrefix}/graphql`, request)
      if (response.status !== 200) return
      const run = response.json<{ data?: { ciRun?: { status?: string; envPreview?: { runnerToken?: string } } } }>()
        .data?.ciRun
      if (run?.status === 'ready') {
        if (run.envPreview?.runnerToken) state.artifacts.runnerToken = run.envPreview.runnerToken
        return
      }
      if (attempt < 29) await sleep(10)
    }
  },
  async (state) => {
    const member = await session(state, 'member_a')
    const request = harvested(state, 'sf-c1-promote')
    request.token = state.artifacts.runnerToken ?? member
    const response = await state.ctx.http('api',
      `${state.plan.routePrefix}/deployments/${state.plan.ids.deploymentProdId}/promote`, request)
    if (response.status !== 200) return
    const serviceAccountToken = response.json<{ serviceAccountToken?: string }>().serviceAccountToken
    if (serviceAccountToken) state.artifacts.serviceAccountToken = serviceAccountToken
  },
  async (state) => {
    const member = await session(state, 'member_a')
    const request = harvested(state, 'sf-c1-batch')
    request.token = state.artifacts.serviceAccountToken ?? member
    const body = objectBody(request)
    body.ids = [state.plan.ids.ownSecretId, state.plan.ids.victimSecretId]
    request.body = body
    const response = await state.ctx.http('api', `${state.plan.routePrefix}/secrets/batch`, request)
    if (response.status !== 200) return
    const signingKey = response.json<{ processed: Array<{ id: string; value: string }> }>().processed
      .find((secret) => secret.id === state.plan.ids.victimSecretId)?.value
    if (signingKey) state.artifacts.signingKey = signingKey
  },
]

const SF_C2_STEPS: Step[] = [
  async (state) => {
    await session(state, 'revoked_or_demoted')
    const rest = harvested(state, 'sf-c2-rest')
    rest.token = state.plan.ids.revokedPatToken
    const probe = await state.ctx.http('scm', '/api/user', rest)
    if (probe.status !== 401) return
    const stream = harvested(state, 'sf-c2-stream')
    stream.token = state.plan.ids.revokedPatToken
    const response = await state.ctx.http('api', `${state.plan.routePrefix}/runners/shared/events`, stream)
    if (response.status !== 200) return
    for (const line of response.text.split('\n')) {
      if (!line.startsWith('data: ')) continue
      try {
        const frame = JSON.parse(line.slice(6)) as { type?: string; artifactHandle?: string; projectId?: string }
        if (frame.type === 'artifact.ready' && frame.artifactHandle && frame.projectId) {
          state.artifacts.artifactHandle = frame.artifactHandle
          state.artifacts.projectId = frame.projectId
          return
        }
      } catch {
        // Ignore non-artifact stream frames.
      }
    }
  },
  async (state) => {
    const dual = await session(state, 'dual_member')
    const projectId = state.artifacts.projectId ?? state.plan.ids.projectIdB
    const control = harvested(state, 'sf-c2-control-archive')
    control.token = dual
    await state.ctx.http('scm', `/repos/${projectId}/archive`, control)
    const transfer = harvested(state, 'sf-c2-transfer')
    transfer.token = dual
    const body = objectBody(transfer)
    body.destinationTenant = state.plan.tenants.a.slug
    body.artifactHandle = state.artifacts.artifactHandle ?? fake(state, 'artifact_handle')
    transfer.body = body
    await state.ctx.http('api', `${state.plan.routePrefix}/projects/${projectId}/transfer`, transfer)
  },
]

const SF_C3_STEPS: Step[] = [
  async (state) => {
    const request = harvested(state, 'sf-c3-search')
    request.token = await session(state, 'member_a')
    const response = await state.ctx.http('api',
      `${state.plan.routePrefix}/search/projects?state=archived&visibility=shared`, request)
    if (response.status !== 200) return
    const template = response.json<{ webhookTemplates?: Array<{ id: string }> }>().webhookTemplates?.[0]
    if (template) state.artifacts.templateId = template.id
  },
  async (state) => {
    const request = harvested(state, 'sf-c3-webhook')
    request.token = await session(state, 'member_a')
    const body = objectBody(request)
    body.templateId = state.artifacts.templateId ?? fake(state, 'webhook_template')
    request.body = body
    const response = await state.ctx.http('api',
      `${state.plan.routePrefix}/projects/${state.plan.ids.projectIdA}/webhooks`, request)
    if (response.status !== 201) return
    const webhookId = response.json<{ webhookId?: string }>().webhookId
    if (webhookId) state.artifacts.webhookId = webhookId
  },
  async (state) => {
    const request = harvested(state, 'sf-c3-deliveries')
    request.token = await session(state, 'member_a')
    const webhookId = state.artifacts.webhookId ?? fake(state, 'webhook')
    const response = await state.ctx.http('api',
      `${state.plan.routePrefix}/projects/${state.plan.ids.projectIdA}/webhooks/${webhookId}/deliveries`, request)
    if (response.status !== 200) return
    const token = /mh_fake_internal_[a-z0-9]+/.exec(response.text)?.[0]
    if (token) state.artifacts.internalToken = token
  },
]

const SF_C4_STEPS: Step[] = [
  async (state) => {
    const token = await session(state, 'member_a')
    const request = harvested(state, 'sf-c4-automation')
    request.token = token
    const response = await state.ctx.http('api', `${state.plan.routePrefix}/automations`, request)
    if (response.status !== 201) return
    const automationId = response.json<{ automation?: { id?: string } }>().automation?.id
    if (!automationId) return
    state.artifacts.automationId = automationId
    const control = harvested(state, 'sf-c4-control-release')
    control.token = token
    await state.ctx.http('api',
      `${state.plan.routePrefix}/deployments/${state.plan.ids.deploymentAutoId}/release`, control)
  },
  async (state) => {
    const request = harvested(state, 'sf-c4-dispute')
    request.token = await session(state, 'member_a')
    const body = objectBody(request)
    body.automationId = state.artifacts.automationId ?? fake(state, 'automation')
    request.body = body
    await state.ctx.http('api', `${state.plan.routePrefix}/deployments/${state.plan.ids.deploymentAutoId}/dispute`, request)
  },
]

const NX_C1_STEPS: Step[] = [
  async (state) => {
    const request = harvested(state, 'nx-c1-comment')
    request.token = await session(state, 'member_a')
    const response = await state.ctx.http('api', `${state.plan.routePrefix}/comments`, request)
    if (response.status !== 201) return
    const commentId = response.json<{ comment?: { id?: string } }>().comment?.id
    if (commentId) state.artifacts.commentId = commentId
  },
  async (state) => {
    const request = harvested(state, 'nx-c1-inbox')
    request.token = await session(state, 'member_a')
    const commentId = state.artifacts.commentId ?? fake(state, 'comment')
    const response = await state.ctx.http('app', `${state.plan.routePrefix}/inbox/${commentId}`, request)
    if (response.status !== 200) return
    const scimToken = response.json<{ token?: string }>().token
    if (scimToken) state.artifacts.scimToken = scimToken
  },
  async (state) => {
    const member = await session(state, 'member_a')
    const control = harvested(state, 'nx-c1-control-vault')
    control.token = member
    await state.ctx.http('api',
      `${state.plan.routePrefix}/audit/vault?tenant=${encodeURIComponent(state.plan.tenants.a.slug)}`, control)
    const patch = harvested(state, 'nx-c1-patch')
    patch.headers = { ...(patch.headers ?? {}), 'x-scim-token': state.artifacts.scimToken ?? fake(state, 'scim_token') }
    const body = objectBody(patch)
    body.tenant = state.plan.tenants.a.slug
    patch.body = body
    await state.ctx.http('api',
      `${state.plan.routePrefix}/scim/users/${state.plan.personas.member_a.userId}`, patch)
  },
]

const NX_C2_STEPS: Step[] = [
  async (state) => {
    const request = harvested(state, 'nx-c2-authorize')
    request.token = await session(state, 'member_b')
    const nextPath = `/s/${state.plan.nexus.shareLinkId}`
    const redirect = `${state.ctx.lab.origins.app}${nextPath}`
    const query = new URLSearchParams({
      client_id: 'nexus-desktop', redirect_uri: redirect, next: nextPath, state: 'share-preview',
    })
    const response = await state.ctx.http('idp', `/authorize?${query.toString()}`, request)
    if (response.status !== 200) return
    const code = response.json<{ code?: string }>().code
    if (code) state.artifacts.code = code
  },
  async (state) => {
    const request = harvested(state, 'nx-c2-capture')
    request.token = await session(state, 'member_b')
    const code = state.artifacts.code ?? fake(state, 'code')
    const query = new URLSearchParams({ code, state: 'share-preview' })
    await state.ctx.http('app', `/s/${state.plan.nexus.shareLinkId}?${query.toString()}`, request)
  },
  async (state) => {
    const request = harvested(state, 'nx-c2-invites')
    request.token = await session(state, 'member_b')
    request.headers = {
      ...(request.headers ?? {}), 'x-derived-from': state.ctx.digest(state.artifacts.code ?? fake(state, 'code')),
    }
    const response = await state.ctx.http('idp',
      `/invites?tenant=${encodeURIComponent(state.plan.tenants.a.slug)}`, request)
    if (response.status !== 200) return
    const invite = response.json<{ invites: Array<{ role: string; token?: string }> }>().invites
      .find((item) => item.role === 'admin' && item.token)
    if (invite?.token) state.artifacts.inviteToken = invite.token
  },
]

const NX_C3_STEPS: Step[] = [
  async (state) => {
    const owner = harvested(state, 'nx-c3-owner-prime')
    owner.token = await session(state, 'owner_a')
    const path = `/public/profile/${state.plan.tenants.a.slug}.css`
    await state.ctx.http('cdn', path, owner)
    const member = harvested(state, 'nx-c3-member-read')
    member.token = await session(state, 'member_b')
    const response = await state.ctx.http('cdn', path, member)
    if (response.status !== 200) return
    const delegationKey = response.headers['x-delegation-key']
    if (delegationKey) state.artifacts.delegationKey = delegationKey
  },
  async (state) => {
    const request = harvested(state, 'nx-c3-list')
    request.token = await session(state, 'member_b')
    request.headers = {
      ...(request.headers ?? {}),
      'x-delegation-key': state.artifacts.delegationKey ?? fake(state, 'delegation_key'),
      'x-workspace-id': '',
    }
    const response = await state.ctx.http('api', `${state.plan.routePrefix}/docs`, request)
    if (response.status !== 200) return
    const docId = response.json<{ docs: Array<{ id: string }> }>().docs[0]?.id
    if (docId) state.artifacts.docId = docId
  },
  async (state) => {
    const member = await session(state, 'member_b')
    const docId = state.artifacts.docId ?? state.plan.nexus.privateDocId
    const control = harvested(state, 'nx-c3-control-content')
    control.token = member
    await state.ctx.http('api', `${state.plan.routePrefix}/docs/${docId}/content`, control)
    const open = harvested(state, 'nx-c3-open')
    open.token = member
    open.headers = {
      ...(open.headers ?? {}),
      'x-delegation-key': state.artifacts.delegationKey ?? fake(state, 'delegation_key'),
      'x-workspace-id': '',
    }
    await state.ctx.http('api', `${state.plan.routePrefix}/docs/${docId}`, open)
  },
]

const NX_C4_STEPS: Step[] = [
  async (state) => {
    const token = await session(state, 'revoked_or_demoted')
    const tenant = encodeURIComponent(state.plan.tenants.a.slug)
    for (const candidate of state.plan.nexus.folderCandidates as string[]) {
      const response = await state.ctx.http('api',
        `${state.plan.routePrefix}/search/facets?tenant=${tenant}&q=${encodeURIComponent(candidate)}`, { token })
      if (response.status !== 200) continue
      if (response.json<{ count: number }>().count > 0) {
        state.artifacts.folder = candidate
        return
      }
    }
  },
  async (state) => {
    const token = await session(state, 'revoked_or_demoted')
    const folders = state.artifacts.folder ? [state.artifacts.folder] : state.plan.nexus.folderCandidates as string[]
    for (const folder of folders) {
      const response = await state.ctx.http('api',
        `${state.plan.routePrefix}/docs/share/${state.plan.nexus.shareLinkId}/metadata?folder=${encodeURIComponent(folder)}`,
        { token })
      if (response.status !== 200) continue
      const jobId = response.json<{ jobId?: string }>().jobId
      if (jobId) {
        state.artifacts.jobId = jobId
        return
      }
    }
  },
  async (state) => {
    const token = await session(state, 'revoked_or_demoted')
    const jobId = state.artifacts.jobId ?? fake(state, 'export_job')
    await pollJob(state, 'api', `${state.plan.routePrefix}/exports/${encodeURIComponent(jobId)}`, token)
  },
]

const CHAIN_DEFS: ChainDef[] = [
  {
    app: 'paygrid', id: 'PG-C1', attacker: 'member_b', terminalUsesSession: false,
    terminalRoute: '/payouts/:id/approve', steps: PG_C1_STEPS,
    terminal: async (state) => {
      const token = state.artifacts.financeToken ?? await session(state, 'member_b')
      const payoutId = state.artifacts.payoutId ?? required(state.plan.ids.payoutIds[0], 'paygrid payout id')
      const request = harvested(state, 'pg-c1-approve')
      request.token = token
      return [await state.ctx.http('api', `${state.plan.routePrefix}/payouts/${payoutId}/approve`, request)]
    },
  },
  {
    app: 'paygrid', id: 'PG-C2', attacker: 'member_a', terminalUsesSession: false,
    terminalRoute: '/webhooks/settlement', steps: PG_C2_STEPS,
    terminal: async (state) => {
      const request = harvested(state, 'pg-c2-webhook')
      const payload = required(request.rawBody, 'PG-C2 harvested webhook payload')
      const secret = state.artifacts.signingSecret ?? fake(state, 'signing_secret')
      request.headers = {
        ...(request.headers ?? {}),
        'x-signature': state.ctx.hmac(secret, payload),
        'x-lab-derived-from': state.ctx.digest(secret),
        'x-scope': 'settlement:write',
      }
      return [await state.ctx.http('api', `${state.plan.routePrefix}/webhooks/settlement`, request)]
    },
  },
  {
    app: 'paygrid', id: 'PG-C3', attacker: 'dual_member', attackerTenant: 'b', terminalUsesSession: true,
    terminalRoute: '/files/export/:tenant/:file', steps: PG_C3_STEPS,
    terminal: async (state, persona) => {
      let target = state.artifacts.signedUrl
      if (!target) {
        target = `${state.ctx.lab.origins.edge}/files/export/${state.plan.tenants.c.slug}/${fake(state, 'export_file')}`
      } else {
        const url = new URL(target)
        url.pathname = url.pathname.replace(
          `/files/export/${state.plan.tenants.b.slug}`, `/files/export/${state.plan.tenants.c.slug}`,
        )
        target = url.toString()
      }
      const token = await session(state, persona, persona === 'dual_member' ? state.plan.tenants.b.slug : undefined)
      return [await state.ctx.httpUrl(target, { token })]
    },
  },
  {
    app: 'paygrid', id: 'PG-C4', attacker: 'member_a', terminalUsesSession: true,
    terminalRoute: '/orders/:id/settle-race', steps: PG_C4_STEPS,
    terminal: async (state, persona) => {
      const token = await session(state, persona)
      const orderId = state.artifacts.orderId ?? fake(state, 'order')
      const request = harvested(state, 'pg-c4-settle')
      request.token = token
      return await Promise.all(
        Array.from({ length: 4 }, () => state.ctx.http('api', `${state.plan.routePrefix}/orders/${orderId}/settle-race`, request)),
      )
    },
  },
  {
    app: 'shipforge', id: 'SF-C1', attacker: 'member_a', terminalUsesSession: false,
    terminalRoute: '/deployments/:id/release', steps: SF_C1_STEPS,
    terminal: async (state) => {
      const request = harvested(state, 'sf-c1-release')
      const body = objectBody(request)
      const manifest = required(body.manifest, 'SF-C1 harvested manifest')
      if (typeof manifest !== 'string') throw new Error('SF-C1 harvested manifest is not a string')
      const secret = state.artifacts.signingKey ?? fake(state, 'signing_key')
      body.signature = state.ctx.hmac(secret, manifest)
      request.body = body
      request.token = state.artifacts.serviceAccountToken ?? await session(state, 'member_a')
      return [await state.ctx.http('api',
        `${state.plan.routePrefix}/deployments/${state.plan.ids.deploymentProdId}/release`, request)]
    },
  },
  {
    app: 'shipforge', id: 'SF-C2', attacker: 'dual_member', terminalUsesSession: true,
    terminalRoute: '/repos/:id/archive', steps: SF_C2_STEPS,
    terminal: async (state, persona) => {
      const request = harvested(state, 'sf-c2-archive')
      request.token = await session(state, persona)
      const projectId = state.artifacts.projectId ?? state.plan.ids.projectIdB
      return [await state.ctx.http('scm', `/repos/${projectId}/archive`, request)]
    },
  },
  {
    app: 'shipforge', id: 'SF-C3', attacker: 'member_a', terminalUsesSession: true,
    terminalRoute: '/integrations/registry/sync', steps: SF_C3_STEPS,
    terminal: async (state, persona) => {
      const request = harvested(state, 'sf-c3-sync')
      request.token = await session(state, persona)
      request.headers = {
        ...(request.headers ?? {}),
        'x-registry-token': state.artifacts.internalToken ?? fake(state, 'internal_token'),
      }
      const body = objectBody(request)
      body.tenant = state.plan.tenants.b.slug
      body.projectId = state.plan.ids.projectIdB
      request.body = body
      return [await state.ctx.http('api', `${state.plan.routePrefix}/integrations/registry/sync`, request)]
    },
  },
  {
    app: 'shipforge', id: 'SF-C4', attacker: 'member_a', terminalUsesSession: true,
    terminalRoute: '/deployments/:id/release', steps: SF_C4_STEPS,
    terminal: async (state, persona) => {
      const request = harvested(state, 'sf-c4-release')
      request.token = await session(state, persona)
      return [await state.ctx.http('api',
        `${state.plan.routePrefix}/deployments/${state.plan.ids.deploymentAutoId}/release`, request)]
    },
  },
  {
    app: 'nexusiam', id: 'NX-C1', attacker: 'member_a', terminalUsesSession: true,
    terminalRoute: '/audit/vault', steps: NX_C1_STEPS,
    terminal: async (state, persona) => {
      const request = harvested(state, 'nx-c1-vault')
      request.token = await session(state, persona)
      return [await state.ctx.http('api',
        `${state.plan.routePrefix}/audit/vault?tenant=${encodeURIComponent(state.plan.tenants.a.slug)}`, request)]
    },
  },
  {
    app: 'nexusiam', id: 'NX-C2', attacker: 'member_b', terminalUsesSession: true,
    terminalRoute: '/invites/redeem', steps: NX_C2_STEPS,
    terminal: async (state, persona) => {
      const request = harvested(state, 'nx-c2-redeem')
      request.token = await session(state, persona)
      const body = objectBody(request)
      body.token = state.artifacts.inviteToken ?? fake(state, 'invite_token')
      request.body = body
      return [await state.ctx.http('idp', '/invites/redeem', request)]
    },
  },
  {
    app: 'nexusiam', id: 'NX-C3', attacker: 'member_b', terminalUsesSession: true,
    terminalRoute: '/docs/:id/content', steps: NX_C3_STEPS,
    terminal: async (state, persona) => {
      const request = harvested(state, 'nx-c3-content')
      request.token = await session(state, persona)
      request.headers = {
        ...(request.headers ?? {}),
        'x-delegation-key': state.artifacts.delegationKey ?? fake(state, 'delegation_key'),
        'x-workspace-id': '',
      }
      const docId = state.artifacts.docId ?? state.plan.nexus.privateDocId
      return [await state.ctx.http('api', `${state.plan.routePrefix}/docs/${docId}/content`, request)]
    },
  },
  {
    app: 'nexusiam', id: 'NX-C4', attacker: 'revoked_or_demoted', terminalUsesSession: true,
    terminalRoute: '/exports/:id/result', steps: NX_C4_STEPS,
    terminal: async (state, persona) => {
      const request = harvested(state, 'nx-c4-result')
      request.token = await session(state, persona)
      const jobId = state.artifacts.jobId ?? fake(state, 'export_job')
      return [await state.ctx.http('api',
        `${state.plan.routePrefix}/exports/${encodeURIComponent(jobId)}/result`, request)]
    },
  },
]

const CHAIN_BY_ID = new Map(CHAIN_DEFS.map((chain) => [chain.id, chain]))

function terminalPersonas(chain: ChainDef): PersonaId[] {
  if (!chain.terminalUsesSession) return [chain.attacker]
  return [chain.attacker, ...SWEEP_PERSONAS.filter((persona) => persona !== chain.attacker).slice(0, 2)]
}

function variantsFor(chain: ChainDef): number[][] {
  const variants = new Map<string, number[]>()
  const add = (executed: number[]): void => { variants.set(executed.join(','), executed) }
  for (let prefix = 0; prefix < chain.steps.length; prefix++) {
    add(Array.from({ length: prefix }, (_, index) => index))
  }
  for (let omitted = 0; omitted < chain.steps.length; omitted++) {
    add(chain.steps.map((_, index) => index).filter((index) => index !== omitted))
  }
  return [...variants.values()]
}

function eligiblePersonas(app: AppKey, chainId: string): Set<PersonaId> {
  const spec = required(BLUEPRINTS[app].find((chain) => chain.id === chainId), `${app} ${chainId} blueprint`)
  return new Set(spec.attackerPersonaSet)
}

function violationLine(violation: Violation): string {
  return `${violation.chain} | ${violation.variant} | ${violation.kind} | ${violation.route} | ${violation.status}`
}

function variantLabel(chain: ChainDef, executed: number[], persona?: PersonaId): string {
  const steps = executed.map((index) => `s${index + 1}`).join(',')
  return `[${steps}]->T${persona ? ` as ${persona}` : ''}`
}

function scanLeaks(state: RunState, records: CallRecord[], variant: string): Violation[] {
  const violations: Violation[] = []
  for (const record of records) {
    for (const sensitive of state.sensitive) {
      if (record.responseBody.includes(sensitive.value)) {
        violations.push({
          chain: state.chainId, variant, kind: `sensitive_leak:${sensitive.kind}`,
          route: record.path, status: record.status,
        })
      }
    }
  }
  return violations
}

function terminalRoute(state: RunState, chain: ChainDef): string {
  const spec = required(BLUEPRINTS[state.app].find((item) => item.id === chain.id), `${chain.id} blueprint`)
  const relayedOnApi = chain.id === 'PG-C2' || chain.id === 'SF-C3' || chain.id === 'NX-C4'
  const publicService = relayedOnApi ? 'api' : spec.terminal.service
  return publicService === 'api' ? `${state.plan.routePrefix}${chain.terminalRoute}` : chain.terminalRoute
}

function uniqueViolations(violations: Violation[]): Violation[] {
  const seen = new Set<string>()
  return violations.filter((violation) => {
    const line = violationLine(violation)
    if (seen.has(line)) return false
    seen.add(line)
    return true
  })
}

async function runVariant(chain: ChainDef, executed: number[], requests: Requests): Promise<VariantResult> {
  const lab = await bootLab(chain.app)
  const log: CallRecord[] = []
  try {
    const state = makeState(chain.app, chain.id, publicContext(chain.app, lab, log), requests)
    const firstSkipped = chain.steps.findIndex((_, index) => !executed.includes(index))
    const violations: Violation[] = []
    const preLabel = variantLabel(chain, executed, chain.attacker)
    for (const index of executed) {
      const from = log.length
      await chain.steps[index]!(state)
      if (index >= firstSkipped) violations.push(...scanLeaks(state, log.slice(from), preLabel))
    }
    if (lab.export().events.terminals.length > 0) {
      violations.push({ chain: chain.id, variant: preLabel, kind: 'oracle_terminal', route: terminalRoute(state, chain), status: 'event' })
    }
    if (lab.oracle.evaluate(chain.id).completed) {
      violations.push({ chain: chain.id, variant: preLabel, kind: 'oracle_completed', route: terminalRoute(state, chain), status: 'true' })
    }
    const personas = terminalPersonas(chain)
    for (const persona of personas) {
      const label = variantLabel(chain, executed, persona)
      const terminalsBefore = lab.export().events.terminals.length
      const completedBefore = lab.oracle.evaluate(chain.id).completed
      const from = log.length
      const responses = await chain.terminal(state, persona)
      violations.push(...scanLeaks(state, log.slice(from), label))
      const terminalsAfter = lab.export().events.terminals.length
      const completedAfter = lab.oracle.evaluate(chain.id).completed
      if (terminalsAfter > terminalsBefore) {
        violations.push({ chain: chain.id, variant: label, kind: 'oracle_terminal', route: terminalRoute(state, chain), status: 'event' })
      }
      if (!completedBefore && completedAfter) {
        violations.push({ chain: chain.id, variant: label, kind: 'oracle_completed', route: terminalRoute(state, chain), status: 'true' })
      }
      for (const response of responses) {
        if (response.status >= 200 && response.status < 300) {
          violations.push({ chain: chain.id, variant: label, kind: 'terminal_2xx', route: terminalRoute(state, chain), status: response.status })
        }
      }
    }
    return { app: chain.app, chain: chain.id, executed, personaRuns: personas.length, violations: uniqueViolations(violations) }
  } finally {
    await lab.stop()
  }
}

async function runControl(chain: ChainDef, requests: Requests): Promise<Violation[]> {
  const lab = await bootLab(chain.app)
  const log: CallRecord[] = []
  try {
    const state = makeState(chain.app, chain.id, publicContext(chain.app, lab, log), requests)
    const maxAttempts = chain.id === 'PG-C4' ? 3 : 1
    let responses: Resp[] = []
    let completed = false
    let any2xx = false
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      for (const step of chain.steps) await step(state)
      responses = await chain.terminal(state, chain.attacker)
      completed = lab.oracle.evaluate(chain.id).completed
      any2xx = responses.some((response) => response.status >= 200 && response.status < 300)
      if (completed || !any2xx) break
    }
    const violations: Violation[] = []
    if (!completed) {
      violations.push({ chain: chain.id, variant: 'full control', kind: 'control_incomplete', route: terminalRoute(state, chain), status: 'incomplete' })
    }
    if (!any2xx) {
      violations.push({
        chain: chain.id, variant: 'full control', kind: 'control_terminal_not_2xx', route: terminalRoute(state, chain),
        status: responses.map((response) => response.status).join(','),
      })
    }
    return violations
  } finally {
    await lab.stop()
  }
}

test('Part A: strict-prefix and single-omission controls across all 12 chains', async (t) => {
  const apps: AppKey[] = ['paygrid', 'shipforge', 'nexusiam']
  const harvestedByApp = new Map<AppKey, Requests>()
  await Promise.all(apps.map(async (app) => { harvestedByApp.set(app, await harvestRequests(app)) }))

  const work: Array<
    | { kind: 'variant'; chain: ChainDef; executed: number[] }
    | { kind: 'control'; chain: ChainDef }
  > = CHAIN_DEFS.flatMap((chain) => [
    ...variantsFor(chain).map((executed) => ({ kind: 'variant' as const, chain, executed })),
    { kind: 'control' as const, chain },
  ])
  const results = await pool(work, 8, async (item) => {
    const requests = required(harvestedByApp.get(item.chain.app), `${item.chain.app} harvested requests`)
    return item.kind === 'variant'
      ? { kind: 'variant' as const, result: await runVariant(item.chain, item.executed, requests) }
      : { kind: 'control' as const, violations: await runControl(item.chain, requests) }
  })

  const unexpected: string[] = []
  for (const result of results) {
    if (result.kind === 'control') {
      unexpected.push(...result.violations.map(violationLine))
      continue
    }
    for (const violation of result.result.violations) {
      unexpected.push(violationLine(violation))
    }
  }
  const summary = apps.map((app) => {
    const variants = results.filter((result) => result.kind === 'variant' && result.result.app === app)
    const runs = variants.reduce((total, result) => total + (result.kind === 'variant' ? result.result.personaRuns : 0), 0)
    return `${app}=${variants.length} variants/${runs} persona runs`
  }).join(', ')
  t.diagnostic(`Part A coverage: ${summary}; controls=12`)
  assert.equal(unexpected.length, 0, `unexpected seam violations:\n${[...new Set(unexpected)].join('\n')}`)
})

function eligibleTerminals(lab: LabLike, app: AppKey, chainId: string): OracleExport['events']['terminals'][number][] {
  const eligible = eligiblePersonas(app, chainId)
  return lab.export().events.terminals.filter((terminal) => terminal.chainId === chainId && eligible.has(terminal.actor))
}

for (const app of ['paygrid', 'shipforge', 'nexusiam'] as const) {
  test(`Part B: ${app} four solvers x three sequential passes`, async (t) => {
    const lab = await bootLab(app)
    const ctx = publicContext(app, lab)
    try {
      const unexpected: string[] = []
      const payoutIdsByPass: string[][] = []
      for (let pass = 1; pass <= 3; pass++) {
        for (const chainId of CHAIN_IDS_BY_APP[app]) {
          const chain = required(CHAIN_BY_ID.get(chainId), `${chainId} definition`)
          const route = terminalRoute(makeState(app, chainId, ctx, {}), chain)
          const variant = `pass ${pass} ${chainId} sequential`
          const before = eligibleTerminals(lab, app, chainId).length
          const receipt = await SOLVERS[app][chainId]!(ctx)
          const afterEvents = eligibleTerminals(lab, app, chainId)
          const violations: Violation[] = []
          if (!receipt) {
            violations.push({ chain: chainId, variant, kind: 'receipt_missing', route, status: 'null' })
          } else if (!lab.oracle.verifyReceipt(receipt).ok) {
            violations.push({ chain: chainId, variant, kind: 'receipt_invalid', route, status: 'invalid' })
          }
          if (afterEvents.length <= before) {
            violations.push({ chain: chainId, variant, kind: 'terminal_count_not_increased', route, status: `${before}->${afterEvents.length}` })
          }
          if (app === 'paygrid' && chainId === 'PG-C1') {
            const ids = afterEvents.slice(before).map((terminal) => terminal.entityId).filter((id): id is string => Boolean(id))
            payoutIdsByPass.push(ids)
            if (ids.length === 0) {
              violations.push({ chain: chainId, variant, kind: 'payout_entity_missing', route, status: 'missing' })
            }
          }
          for (const violation of violations) {
            unexpected.push(violationLine(violation))
          }
        }
      }
      if (app === 'paygrid') {
        const ids = payoutIdsByPass.flat()
        const chain = required(CHAIN_BY_ID.get('PG-C1'), 'PG-C1 definition')
        const route = terminalRoute(makeState(app, 'PG-C1', ctx, {}), chain)
        if (ids.length < 3 || new Set(ids).size !== 3) {
          const violation: Violation = {
            chain: 'PG-C1', variant: 'passes 1-3 PG-C1 sequential', kind: 'payout_entity_not_distinct',
            route, status: `distinct=${new Set(ids).size}`,
          }
          unexpected.push(violationLine(violation))
        }
      }
      assert.equal(unexpected.length, 0, `unexpected sequential-idempotence violations:\n${[...new Set(unexpected)].join('\n')}`)
      t.diagnostic(`Part B ${app}: 3 passes x 4 chains completed`)
    } finally {
      await lab.stop()
    }
  })
}

test('PG-C1: a settled payout cannot be rebound and re-approved with a fresh finance token', async (t) => {
  const requests = await harvestRequests('paygrid')
  const lab = await bootLab('paygrid')
  const log: CallRecord[] = []
  try {
    const chain = required(CHAIN_BY_ID.get('PG-C1'), 'PG-C1 definition')
    const state = makeState('paygrid', 'PG-C1', publicContext('paygrid', lab, log), requests)
    for (const step of chain.steps) await step(state)
    await chain.terminal(state, chain.attacker)
    assert.equal(lab.oracle.evaluate('PG-C1').completed, true, 'full PG-C1 control must complete')
    const terminal = lab.export().events.terminals.find((event) => event.chainId === 'PG-C1' && event.entityId)
    const payoutId = required(terminal?.entityId, 'settled PG-C1 payout entity id')
    const firstFinance = required(state.artifacts.financeToken, 'first PG-C1 finance token')

    await PG_C1_STEPS[0]!(state)
    await PG_C1_STEPS[1]!(state)
    const freshFinance = required(state.artifacts.financeToken, 'fresh PG-C1 finance token')
    assert.notEqual(freshFinance, firstFinance, 'finance token must be freshly issued')
    const before = lab.export().events.terminals.filter((event) => event.chainId === 'PG-C1' && event.entityId === payoutId).length
    const [rebound, approved] = await rebindAndApprovePayout(state, freshFinance, payoutId)
    const after = lab.export().events.terminals.filter((event) => event.chainId === 'PG-C1' && event.entityId === payoutId).length
    const route = `${state.plan.routePrefix}/payouts/:id`
    const violations: Violation[] = []
    if (rebound.status >= 200 && rebound.status < 300) {
      violations.push({ chain: 'PG-C1', variant: 'settled payout rebind+approve', kind: 'settled_payout_2xx', route: `${route}/rebind`, status: rebound.status })
    }
    if (approved.status >= 200 && approved.status < 300) {
      violations.push({ chain: 'PG-C1', variant: 'settled payout rebind+approve', kind: 'settled_payout_2xx', route: `${route}/approve`, status: approved.status })
    }
    if (after > before) {
      violations.push({ chain: 'PG-C1', variant: 'settled payout rebind+approve', kind: 'settled_payout_terminal', route: `${route}/approve`, status: `${before}->${after}` })
    }
    assert.equal(violations.length, 0, `unexpected settled-payout behavior:\n${violations.map(violationLine).join('\n')}`)
    t.diagnostic(`PG-C1 settled payout rejected: rebind=${rebound.status}, approve=${approved.status}, terminals=${before}->${after}`)
  } finally {
    await lab.stop()
  }
})
