// Fast (< 5 s) benchmark-app invariant harness for the three Dev multi-hop archetypes
// (paygrid, shipforge, nexusiam). The sealed archetype is intentionally never imported.
//
// Four invariant families, each per app:
//  1. Public-origin-only: reference solvers run through a guarded SolverContext that throws on any
//     internal service origin. Vulnerable => 4/4 confirm; hardened and every partial twin (D1..D3)
//     => zero terminal oracle events for the guarded chain.
//  2. Concurrent dual-pass: two interleaved full solver passes against one live lab instance
//     (simulating concurrent Phase B workers + dual replay) must each still confirm all 4 chains,
//     with a receipt that verifies and per-pass terminal evidence (no scalar monitor overwrite).
//  3. Direct-route control probe: every public catalog route (excluding chain entry hops and
//     session-teardown routes) is called directly with each attacker-eligible / lower-privilege
//     persona plus an anonymous control, using seeded identifiers only (no Hop 1). The oracle must
//     record zero terminals / edges / confirmations, chain terminal routes must deny the chain's
//     attacker personas, host secrets must never be echoed, and the victim canary must not reach
//     personas outside the victim tenant.
//  4. Leakage: every materialized white-box source tree is leakage-scan clean.
//
// Set V8_PBI_SUMMARY=<path.json> to dump a structured per-app summary (status codes, route keys,
// persona ids only — never response bodies).
process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { scanTreeForLeakage } from '../benchmarks/multihop-saas/lib/materialize.ts'
import type {
  ApiRef, Briefing, BenchMode, ChainSpec, CompositeProofReceipt, LabMode, OracleExport, PersonaId, TwinSpec,
} from '../benchmarks/multihop-saas/lib/types.ts'
import type { ChainOracle } from '../benchmarks/multihop-saas/lib/chain-oracle.ts'

import { startPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import type { StartedPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import { CHAINS as PG_CHAINS, TWINS as PG_TWINS } from '../benchmarks/multihop-saas/apps/paygrid/truth/blueprint.ts'
import { createSolverContext as createPgCtx } from '../benchmarks/multihop-saas/apps/paygrid/solvers/context.ts'
import type { SolverContext as PgCtx } from '../benchmarks/multihop-saas/apps/paygrid/solvers/context.ts'
import { solveC1 as pgC1 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c1.ts'
import { solveC2 as pgC2 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c2.ts'
import { solveC3 as pgC3 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c3.ts'
import { solveC4 as pgC4 } from '../benchmarks/multihop-saas/apps/paygrid/solvers/c4.ts'

import { startShipforge } from '../benchmarks/multihop-saas/apps/shipforge/index.ts'
import type { StartedShipforge } from '../benchmarks/multihop-saas/apps/shipforge/index.ts'
import { CHAINS as SF_CHAINS, TWINS as SF_TWINS } from '../benchmarks/multihop-saas/apps/shipforge/truth/blueprint.ts'
import { createSolverContext as createSfCtx } from '../benchmarks/multihop-saas/apps/shipforge/solvers/context.ts'
import type { SolverContext as SfCtx } from '../benchmarks/multihop-saas/apps/shipforge/solvers/context.ts'
import { solveC1 as sfC1 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c1.ts'
import { solveC2 as sfC2 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c2.ts'
import { solveC3 as sfC3 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c3.ts'
import { solveC4 as sfC4 } from '../benchmarks/multihop-saas/apps/shipforge/solvers/c4.ts'

import { startNexusiam } from '../benchmarks/multihop-saas/apps/nexusiam/index.ts'
import type { StartedNexusiam } from '../benchmarks/multihop-saas/apps/nexusiam/index.ts'
import { CHAINS as NX_CHAINS, TWINS as NX_TWINS } from '../benchmarks/multihop-saas/apps/nexusiam/truth/blueprint.ts'
import { createSolverContext as createNxCtx } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/context.ts'
import type { SolverContext as NxCtx } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/context.ts'
import { solveC1 as nxC1 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c1.ts'
import { solveC2 as nxC2 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c2.ts'
import { solveC3 as nxC3 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c3.ts'
import { solveC4 as nxC4 } from '../benchmarks/multihop-saas/apps/nexusiam/solvers/c4.ts'

// ---------------------------------------------------------------------------------------------
// Uniform adapter over the three apps
// ---------------------------------------------------------------------------------------------

interface ProbeResponse { status: number; text: string }
interface ProbeRequest { method?: string; token?: string; body?: unknown; headers?: Record<string, string> }

interface CtxLike {
  http(service: string, path: string, request?: ProbeRequest): Promise<ProbeResponse>
  httpUrl(url: string, request?: ProbeRequest): Promise<ProbeResponse>
  login(persona: PersonaId, tenantSlug?: string): Promise<string>
}

interface LabLike {
  runId: string
  plan: {
    routePrefix: string
    tenants: { a: { id: string; slug: string; treasuryFile: string }; b: { id: string; slug: string; treasuryFile: string }; c: { id: string; slug: string; treasuryFile: string } }
    personas: Record<PersonaId, { tenantId: string; userId: string; rolesByTenant: Partial<Record<string, string>> }>
    economics?: { treasuryCanary: string }
    secrets: Record<string, string>
    ids: unknown
  }
  origins: Record<string, string>
  oracle: ChainOracle
  briefing(mode: BenchMode): Briefing
  export(): OracleExport
  stop(): Promise<void>
}

type Solver = (ctx: CtxLike) => Promise<CompositeProofReceipt | null>

interface AppAdapter {
  name: 'paygrid' | 'shipforge' | 'nexusiam'
  chains: readonly ChainSpec[]
  twins: readonly TwinSpec[]
  start(mode: LabMode, twin?: string): Promise<LabLike>
  createCtx(lab: LabLike): CtxLike
  solvers: Record<string, Solver>
  leakRoot(lab: LabLike): string
}

const LATENCY_MS = 1
const SEED = 42

const APPS: AppAdapter[] = [
  {
    name: 'paygrid',
    chains: PG_CHAINS,
    twins: PG_TWINS,
    start: async (mode, twin) => await startPaygrid({ seed: SEED, mode, twin, asyncLatencyMs: LATENCY_MS }) as unknown as LabLike,
    createCtx: (lab) => createPgCtx(lab as unknown as StartedPaygrid) as unknown as CtxLike,
    solvers: {
      'PG-C1': (ctx) => pgC1(ctx as unknown as PgCtx),
      'PG-C2': (ctx) => pgC2(ctx as unknown as PgCtx),
      'PG-C3': (ctx) => pgC3(ctx as unknown as PgCtx),
      'PG-C4': (ctx) => pgC4(ctx as unknown as PgCtx),
    },
    leakRoot: (lab) => join((lab as unknown as StartedPaygrid).sourceDir, '..', '..', '..'),
  },
  {
    name: 'shipforge',
    chains: SF_CHAINS,
    twins: SF_TWINS,
    start: async (mode, twin) => await startShipforge({ seed: SEED, mode, twin, asyncLatencyMs: LATENCY_MS }) as unknown as LabLike,
    createCtx: (lab) => createSfCtx(lab as unknown as StartedShipforge) as unknown as CtxLike,
    solvers: {
      'SF-C1': (ctx) => sfC1(ctx as unknown as SfCtx),
      'SF-C2': (ctx) => sfC2(ctx as unknown as SfCtx),
      'SF-C3': (ctx) => sfC3(ctx as unknown as SfCtx),
      'SF-C4': (ctx) => sfC4(ctx as unknown as SfCtx),
    },
    leakRoot: (lab) => (lab as unknown as StartedShipforge).sourceRoot,
  },
  {
    name: 'nexusiam',
    chains: NX_CHAINS,
    twins: NX_TWINS,
    start: async (mode, twin) => await startNexusiam({ seed: SEED, mode, twin, asyncLatencyMs: LATENCY_MS }) as unknown as LabLike,
    createCtx: (lab) => createNxCtx(lab as unknown as StartedNexusiam) as unknown as CtxLike,
    solvers: {
      'NX-C1': (ctx) => nxC1(ctx as unknown as NxCtx),
      'NX-C2': (ctx) => nxC2(ctx as unknown as NxCtx),
      'NX-C3': (ctx) => nxC3(ctx as unknown as NxCtx),
      'NX-C4': (ctx) => nxC4(ctx as unknown as NxCtx),
    },
    leakRoot: (lab) => (lab as unknown as StartedNexusiam).sourceRoot,
  },
]

// Known benchmark-app gaps found by this harness (documented in the report, owned outside this
// file's lease). Entries are exact; anything new fails the suite.
const KNOWN_GAPS = {
  // SF-C1 h4 `api.secretsBatch` with mutate rotates the victim secret's stored value
  // (shipforge/src/service-api.ts ~L506) while `api.productionRelease` keeps verifying against the
  // original plan signing key (~L629): only the first pass per lab instance can release, so a
  // concurrent worker / dual replay of SF-C1 on the same instance gets 403.
  singleShotChains: new Set<string>(['SF-C1']),
  // nexusiam `api.exportResult` relays `/jobs/:id/result` to docs-worker with session-only auth
  // (nexusiam/src/service-api.ts ~L444); docs-worker serves the ready seeded export (canary)
  // with no tenant / persona / poll-lineage check (service-docs-worker.ts ~L127). Any
  // authenticated outsider holding the seeded export job id reads the victim canary directly,
  // and the oracle records no terminal (the monitor requires h3 lineage).
  canaryLeakRoutes: new Set<string>(['nexusiam:api.exportResult']),
}

const summary: Record<string, Record<string, unknown>> = {}
function note(app: string, key: string, value: unknown): void {
  summary[app] ??= {}
  summary[app]![key] = value
}
process.on('exit', () => {
  const out = process.env.V8_PBI_SUMMARY
  if (out) writeFileSync(out, JSON.stringify(summary, null, 2))
})

async function withLab<T>(app: AppAdapter, mode: LabMode, twin: string | undefined, fn: (lab: LabLike) => Promise<T>): Promise<T> {
  const lab = await app.start(mode, twin)
  try {
    return await fn(lab)
  } finally {
    await lab.stop()
  }
}

// ---------------------------------------------------------------------------------------------
// 1. Public-origin guard
// ---------------------------------------------------------------------------------------------

class InternalOriginError extends Error {}

interface GuardedCtx {
  ctx: CtxLike
  publicOrigins: Set<string>
  violations: string[]
  calls: number
}

function publicOriginsOf(lab: LabLike): Set<string> {
  const grey = lab.briefing('grey-box')
  const origins = new Set<string>()
  for (const origin of Object.values(grey.entryOrigins as Record<string, string | undefined>)) {
    if (origin) origins.add(new URL(origin).origin)
  }
  // Cross-check: every topology service flagged internal must be absent from the public set.
  for (const service of grey.services ?? []) {
    const raw = lab.origins[String(service.id)]
    if (service.internal && raw) assert.ok(!origins.has(new URL(raw).origin), `${String(service.id)} is internal but public`)
  }
  return origins
}

function guardCtx(lab: LabLike, base: CtxLike): GuardedCtx {
  const publicOrigins = publicOriginsOf(lab)
  const state: GuardedCtx = { ctx: base, publicOrigins, violations: [], calls: 0 }
  const check = (url: string, label: string): void => {
    state.calls++
    const origin = new URL(url).origin
    if (!publicOrigins.has(origin)) {
      state.violations.push(label)
      throw new InternalOriginError(`internal origin used: ${label}`)
    }
  }
  state.ctx = {
    ...base,
    http(service, path, request) {
      const origin = lab.origins[service]
      if (!origin) {
        state.violations.push(`unknown:${service}`)
        throw new InternalOriginError(`unknown service ${service}`)
      }
      check(`${origin}${path}`, `service:${service}`)
      return base.http(service, path, request)
    },
    httpUrl(url, request) {
      const service = Object.entries(lab.origins).find(([, origin]) => new URL(origin).origin === new URL(url).origin)?.[0]
      check(url, `url:${service ?? 'foreign'}`)
      return base.httpUrl(url, request)
    },
  } as CtxLike
  return state
}

async function runPass(app: AppAdapter, guarded: GuardedCtx): Promise<Record<string, CompositeProofReceipt | null>> {
  const receipts: Record<string, CompositeProofReceipt | null> = {}
  for (const [chainId, solve] of Object.entries(app.solvers)) {
    receipts[chainId] = await solve(guarded.ctx)
  }
  return receipts
}

for (const app of APPS) {
  test(`${app.name}: public-origin-only — vulnerable 4/4, hardened + twins D1..D3 silent`, async () => {
    // Vulnerable: 4/4 with the guard active.
    await withLab(app, 'vulnerable', undefined, async (lab) => {
      const guarded = guardCtx(lab, app.createCtx(lab))
      const receipts = await runPass(app, guarded)
      assert.deepEqual(guarded.violations, [], `${app.name}: internal origins used`)
      assert.ok(guarded.calls > 0)
      for (const chain of app.chains) {
        const receipt = receipts[chain.id]
        assert.ok(receipt, `${chain.id}: no receipt in vulnerable mode`)
        assert.equal(lab.oracle.verifyReceipt(receipt).ok, true, `${chain.id}: receipt does not verify`)
        const evaluation = lab.oracle.evaluate(chain.id)
        assert.equal(evaluation.confirmed, true, `${chain.id}: ${evaluation.failureReason ?? 'unconfirmed'}`)
      }
      assert.equal(lab.export().confirmed.length, 4)
      // 4. Leakage invariant on the materialized white-box tree of this live lab.
      assert.deepEqual(scanTreeForLeakage(app.leakRoot(lab)), [], `${app.name}: white-box tree leaks`)
      note(app.name, 'publicOrigins', guarded.publicOrigins.size)
      note(app.name, 'vulnerableCalls', guarded.calls)
    })

    // Hardened: zero oracle activity at all, guard still holds.
    await withLab(app, 'hardened', undefined, async (lab) => {
      const guarded = guardCtx(lab, app.createCtx(lab))
      const receipts = await runPass(app, guarded)
      assert.deepEqual(guarded.violations, [], `${app.name} hardened: internal origins used`)
      const exported = lab.export()
      assert.deepEqual(Object.values(receipts).filter(Boolean), [], `${app.name} hardened: receipts minted`)
      assert.equal(exported.events.terminals.length, 0, `${app.name} hardened: terminals`)
      assert.equal(exported.confirmed.length, 0)
      assert.deepEqual(scanTreeForLeakage(app.leakRoot(lab)), [], `${app.name} hardened: white-box tree leaks`)
    })

    // Partial twins: the twin's base chain must never reach a terminal.
    assert.equal(app.twins.length, 3)
    const twinRows: Array<Record<string, unknown>> = []
    for (const twin of app.twins) {
      await withLab(app, 'vulnerable', twin.id, async (lab) => {
        const guarded = guardCtx(lab, app.createCtx(lab))
        const receipts = await runPass(app, guarded)
        assert.deepEqual(guarded.violations, [], `${twin.id}: internal origins used`)
        const exported = lab.export()
        const baseTerminals = exported.events.terminals.filter((t) => t.chainId === twin.baseChainId)
        assert.equal(baseTerminals.length, 0, `${twin.id}: base chain terminal observed`)
        assert.equal(receipts[twin.baseChainId], null, `${twin.id}: base chain receipt minted`)
        assert.equal(lab.oracle.evaluate(twin.baseChainId).confirmed, false, `${twin.id}: base chain confirmed`)
        twinRows.push({
          twin: twin.id,
          confirmed: exported.confirmed.map((c) => c.chainId).sort(),
          baseHops: exported.events.hops.filter((h) => h.chainId === twin.baseChainId).length,
        })
      })
    }
    note(app.name, 'twins', twinRows)
  })
}

// ---------------------------------------------------------------------------------------------
// 2. Concurrent dual-pass stress
// ---------------------------------------------------------------------------------------------

for (const app of APPS) {
  test(`${app.name}: two interleaved solver passes on one lab both confirm 4/4 (no monitor overwrite)`, async () => {
    await withLab(app, 'vulnerable', undefined, async (lab) => {
      const a = guardCtx(lab, app.createCtx(lab))
      const b = guardCtx(lab, app.createCtx(lab))
      const [passA, passB] = await Promise.all([runPass(app, a), runPass(app, b)])
      assert.deepEqual([...a.violations, ...b.violations], [], `${app.name}: internal origins used`)
      const exported = lab.export()
      const rows: Array<Record<string, unknown>> = []
      for (const chain of app.chains) {
        const evaluation = lab.oracle.evaluate(chain.id)
        assert.equal(evaluation.confirmed, true, `${chain.id}: ${evaluation.failureReason ?? 'unconfirmed'} under concurrency`)
        const singleShot = KNOWN_GAPS.singleShotChains.has(chain.id)
        const passReceipts = [passA[chain.id], passB[chain.id]]
        for (const [index, receipt] of passReceipts.entries()) {
          if (!receipt) {
            assert.ok(singleShot, `${chain.id}: pass ${index ? 'B' : 'A'} returned no receipt under concurrency`)
            continue
          }
          assert.equal(lab.oracle.verifyReceipt(receipt).ok, true, `${chain.id}: pass ${index ? 'B' : 'A'} receipt invalid`)
        }
        assert.ok(passReceipts.some(Boolean), `${chain.id}: no pass confirmed under concurrency`)
        const terminals = exported.events.terminals.filter((t) => t.chainId === chain.id)
        rows.push({
          chain: chain.id,
          terminals: terminals.length,
          terminalEntities: new Set(terminals.map((t) => t.entityId ?? '')).size,
          hops: exported.events.hops.filter((h) => h.chainId === chain.id).length,
          passReceipts: passReceipts.filter(Boolean).length,
        })
        // Each pass drives its own terminal impact; a scalar monitor overwrite collapses this to 1.
        assert.ok(terminals.length >= (singleShot ? 1 : 2), `${chain.id}: expected a terminal per pass, saw ${terminals.length}`)
        if (singleShot && passReceipts.every(Boolean)) note(app.name, `fixed:${chain.id}`, 'single-shot gap no longer reproduces; drop it from KNOWN_GAPS')
      }
      note(app.name, 'concurrency', rows)
    })
  })
}

// ---------------------------------------------------------------------------------------------
// 3. Direct-route control probe (no Hop 1)
// ---------------------------------------------------------------------------------------------

interface Session { label: string; persona: PersonaId | 'anonymous'; token?: string; tenants: Set<string> }

function collectSeeded(value: unknown, key: string, out: Array<{ key: string; value: string }>): void {
  if (typeof value === 'string') {
    if (value.length > 0 && value.length < 200) out.push({ key: key.toLowerCase(), value })
  } else if (Array.isArray(value)) {
    for (const item of value) collectSeeded(item, key, out)
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) collectSeeded(v, k, out)
  }
}

function seededPool(lab: LabLike): Array<{ key: string; value: string }> {
  const pool: Array<{ key: string; value: string }> = []
  collectSeeded(lab.plan.ids, 'ids', pool)
  collectSeeded((lab.plan as unknown as { nexus?: unknown }).nexus, 'nexus', pool)
  for (const tenant of Object.values(lab.plan.tenants)) {
    pool.push({ key: 'tenantslug', value: tenant.slug }, { key: 'tenantid', value: tenant.id }, { key: 'file', value: tenant.treasuryFile })
  }
  for (const persona of Object.values(lab.plan.personas)) pool.push({ key: 'userid', value: persona.userId })
  // Never feed host secrets as identifiers.
  const secrets = new Set(Object.values(lab.plan.secrets))
  return pool.filter((entry) => !secrets.has(entry.value) && entry.value !== lab.plan.economics?.treasuryCanary)
}

function candidatesFor(param: string, pool: Array<{ key: string; value: string }>): string[] {
  const p = param.toLowerCase().replace(/[^a-z]/g, '')
  const stem = p.replace(/id$/, '')
  let hits = pool.filter((e) => (stem.length > 1 && e.key.includes(stem)) || (p.length > 2 && e.key.includes(p)))
  if (/tenant|org|slug/.test(p)) hits = hits.concat(pool.filter((e) => e.key === 'tenantslug' || e.key === 'tenantid'))
  if (hits.length === 0) hits = pool.filter((e) => /id$/.test(e.key) || e.key === 'ids')
  const values = [...new Set(hits.map((e) => e.value))]
  return values.length ? values : ['probe']
}

const MAX_VARIANTS = 6

function routeVariants(ref: ApiRef, pool: Array<{ key: string; value: string }>): Array<{ path: string; values: Record<string, string> }> {
  const names = [...ref.path.matchAll(/:([A-Za-z_]+)/g)].map((m) => m[1]!)
  if (names.length === 0) return [{ path: ref.path, values: {} }]
  const lists = names.map((name) => candidatesFor(name, pool))
  const count = Math.min(MAX_VARIANTS, Math.max(...lists.map((l) => l.length)))
  const variants: Array<{ path: string; values: Record<string, string> }> = []
  for (let i = 0; i < count; i++) {
    const values: Record<string, string> = {}
    let path = ref.path
    names.forEach((name, idx) => {
      const list = lists[idx]!
      const value = list[i % list.length]!
      values[name] = value
      path = path.replace(`:${name}`, encodeURIComponent(value))
    })
    variants.push({ path, values })
  }
  return variants
}

async function pool<T>(items: readonly T[], width: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0
  await Promise.all(Array.from({ length: Math.min(width, items.length) }, async () => {
    while (next < items.length) {
      const item = items[next++]!
      await fn(item)
    }
  }))
}

const TEARDOWN = /logout|revoke|login|token$/i

for (const app of APPS) {
  test(`${app.name}: direct sensitive-route control probes without Hop 1 yield no terminal / leak / escalation`, async () => {
    await withLab(app, 'vulnerable', undefined, async (lab) => {
      const guarded = guardCtx(lab, app.createCtx(lab))
      const ctx = guarded.ctx
      const catalog = lab.briefing('grey-box').apiReference ?? []
      assert.ok(catalog.length >= 20, `${app.name}: catalog too small`)

      const entryRouteKeys = new Set(app.chains.map((c) => c.hops[0]!.routeKey))
      const terminalRouteKeys = new Map<string, ChainSpec[]>()
      for (const chain of app.chains) {
        terminalRouteKeys.set(chain.terminal.routeKey, [...(terminalRouteKeys.get(chain.terminal.routeKey) ?? []), chain])
      }
      const publicRoutes = catalog.filter((ref) => {
        const origin = lab.origins[String(ref.service)]
        return origin && guarded.publicOrigins.has(new URL(origin).origin)
          && !entryRouteKeys.has(ref.routeKey) && !TEARDOWN.test(ref.routeKey)
      })

      // Sessions: attacker-eligible personas of every chain + lower-privilege personas + anonymous.
      const personaSet = new Set<PersonaId>(['member_a', 'member_b', 'viewer_a', 'dual_member', 'revoked_or_demoted'])
      for (const chain of app.chains) for (const persona of chain.attackerPersonaSet) personaSet.add(persona)
      personaSet.delete('owner_a')
      personaSet.delete('admin_bot')
      const sessions: Session[] = [{ label: 'anonymous', persona: 'anonymous', tenants: new Set() }]
      const loginFailures: string[] = []
      for (const persona of personaSet) {
        const record = lab.plan.personas[persona]
        const tenantKeys = Object.keys(record.rolesByTenant).length ? Object.keys(record.rolesByTenant) : [record.tenantId]
        for (const tenantId of tenantKeys) {
          const tenant = Object.values(lab.plan.tenants).find((t) => t.id === tenantId)
          if (!tenant) continue
          try {
            const token = await ctx.login(persona, tenant.slug)
            sessions.push({ label: `${persona}@${tenantId}`, persona, token, tenants: new Set(Object.keys(record.rolesByTenant)) })
          } catch {
            loginFailures.push(`${persona}@${tenantId}`)
          }
        }
      }

      const seeds = seededPool(lab)
      const victimTenant = lab.plan.tenants.a.id
      const secrets = Object.entries(lab.plan.secrets).filter(([, v]) => typeof v === 'string' && v.length >= 8)
      const canary = lab.plan.economics?.treasuryCanary ?? ''
      // Seeded entity identifiers (never tenant ids/slugs, which are public) — used to classify an
      // anonymous accept as sensitive and to report which hidden identifiers are discoverable.
      const hiddenIds = seeds.filter((e) => !['tenantslug', 'tenantid', 'file'].includes(e.key) && e.value.length >= 8)

      interface Job { ref: ApiRef; path: string; values: Record<string, string>; session: Session }
      const jobs: Job[] = []
      for (const ref of publicRoutes) {
        for (const variant of routeVariants(ref, seeds)) {
          for (const session of sessions) jobs.push({ ref, ...variant, session })
        }
      }

      const secretEchoes: string[] = []
      const canaryLeaks: string[] = []
      const terminalAccepts: string[] = []
      const anonSensitiveAccepts: string[] = []
      const anonCatalogDrift = new Set<string>()
      const discoverable = new Map<string, Set<string>>()
      const statusHistogram: Record<string, number> = {}
      let requests = 0

      await pool(jobs, 32, async (job) => {
        const method = job.ref.method.toUpperCase()
        const request: ProbeRequest = { method, token: job.session.token }
        if (method !== 'GET' && method !== 'HEAD') request.body = { ...job.values, tenant: lab.plan.tenants.a.slug }
        const isTerminal = terminalRouteKeys.has(job.ref.routeKey)
        // Terminal routes get a duplicated concurrent burst (double-credit / race control).
        const burst = isTerminal && method !== 'GET' ? 2 : 1
        const responses = await Promise.all(Array.from({ length: burst }, () => ctx.http(String(job.ref.service), job.path, request)))
        for (const res of responses) {
          requests++
          const tag = `${job.ref.routeKey}:${job.session.label}`
          statusHistogram[String(res.status)] = (statusHistogram[String(res.status)] ?? 0) + 1
          for (const [name, value] of secrets) if (res.text.includes(value)) secretEchoes.push(`${tag}:${name}:${res.status}`)
          const outsider = job.session.persona === 'anonymous' || !job.session.tenants.has(victimTenant)
          if (outsider && canary && res.text.includes(canary)) canaryLeaks.push(`${tag}:${res.status}`)
          const ok = res.status >= 200 && res.status < 300
          if (ok && isTerminal && job.session.persona !== 'anonymous') {
            for (const chain of terminalRouteKeys.get(job.ref.routeKey)!) {
              if (chain.attackerPersonaSet.includes(job.session.persona)) terminalAccepts.push(`${chain.id}:${tag}:${res.status}`)
            }
          }
          if (ok && job.session.persona === 'anonymous' && job.ref.auth !== 'none') {
            anonCatalogDrift.add(job.ref.routeKey)
            const exposesEntity = hiddenIds.some((e) => res.text.includes(e.value) && !Object.values(job.values).includes(e.value))
            if (exposesEntity || (canary && res.text.includes(canary))) anonSensitiveAccepts.push(`${tag}:${res.status}`)
          }
          if (ok && outsider) {
            for (const e of hiddenIds) {
              if (res.text.includes(e.value) && !Object.values(job.values).includes(e.value)) {
                discoverable.set(e.key, (discoverable.get(e.key) ?? new Set()).add(job.ref.routeKey))
              }
            }
          }
        }
      })

      const exported = lab.export()
      note(app.name, 'probe', {
        routes: publicRoutes.length,
        sessions: sessions.map((s) => s.label),
        loginFailures,
        requests,
        statusHistogram,
        terminals: exported.events.terminals.map((t) => `${t.chainId}:${t.routeKey}`),
        edges: exported.events.edges.map((e) => `${e.chainId}:${e.fromHopId}>${e.toHopId}`),
        hops: [...new Set(exported.events.hops.map((h) => h.hopId))],
        secretEchoes,
        canaryLeaks,
        terminalAccepts,
        anonSensitiveAccepts,
        anonCatalogDrift: [...anonCatalogDrift].sort(),
        discoverableWithoutHop1: Object.fromEntries([...discoverable].map(([k, v]) => [k, [...v].sort()])),
      })

      assert.deepEqual(guarded.violations, [])
      assert.ok(requests > 200, `${app.name}: probe coverage too small (${requests})`)
      assert.deepEqual(exported.events.terminals.map((t) => t.chainId), [], `${app.name}: terminal reached without Hop 1`)
      assert.deepEqual(exported.events.edges.map((e) => `${e.chainId}:${e.fromHopId}>${e.toHopId}`), [], `${app.name}: causal edge formed without Hop 1`)
      assert.equal(exported.confirmed.length, 0)
      assert.deepEqual(secretEchoes, [], `${app.name}: host secret echoed by a direct route`)
      const unknownLeaks = canaryLeaks.filter((leak) => !KNOWN_GAPS.canaryLeakRoutes.has(`${app.name}:${leak.split(':')[0]}`))
      assert.deepEqual(unknownLeaks, [], `${app.name}: victim canary reached an outsider directly`)
      assert.deepEqual(terminalAccepts, [], `${app.name}: chain terminal accepted the attacker persona directly`)
      assert.deepEqual(anonSensitiveAccepts, [], `${app.name}: authenticated route served seeded entity data to an anonymous control`)
    })
  })
}
