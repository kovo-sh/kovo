process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { performance } from 'node:perf_hooks'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  TranscriptStore,
  createLocalAttemptFactory,
  verifyScript,
  type VerifyAttemptSession,
} from '../src/server/verify-rpc.ts'
import type { AttemptExecution, VerifyVerdict } from '../src/server/verify-runner.ts'
import { gradeRun } from '../benchmarks/multihop-saas/lib/grader.ts'
import type {
  ChainSpec,
  CompositeProofReceipt as BenchmarkReceipt,
  Finding,
  GroundTruth,
  LabMode,
  OracleExport,
  Scorecard,
} from '../benchmarks/multihop-saas/lib/types.ts'
import { startPaygrid, type StartedPaygrid } from '../benchmarks/multihop-saas/apps/paygrid/index.ts'
import { startShipforge, type StartedShipforge } from '../benchmarks/multihop-saas/apps/shipforge/index.ts'
import { startNexusiam, type StartedNexusiam } from '../benchmarks/multihop-saas/apps/nexusiam/index.ts'
import {
  CHAINS as PG_CHAINS,
  TWINS as PG_TWINS,
} from '../benchmarks/multihop-saas/apps/paygrid/truth/blueprint.ts'
import {
  CHAINS as SF_CHAINS,
  TWINS as SF_TWINS,
} from '../benchmarks/multihop-saas/apps/shipforge/truth/blueprint.ts'
import {
  CHAINS as NX_CHAINS,
  TWINS as NX_TWINS,
} from '../benchmarks/multihop-saas/apps/nexusiam/truth/blueprint.ts'

// Seam 1: zero-LLM golden scripts through the real worker/RPC/broker/redaction/dual-replay path,
// joined to the independently observed multi-hop ChainOracle and scored by the Two-Side Grader.
// No solver context, direct fetch, internal origin, vault port, runner port, registry port, or
// docs-worker port is used by a candidate script.

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_DIR = join(REPO_ROOT, 'worker', 'kovo_verify')
const SEED = 42
const ASYNC_LATENCY_MS = 5

type AppId = 'paygrid' | 'shipforge' | 'nexusiam'
type StartedLab = StartedPaygrid | StartedShipforge | StartedNexusiam
type WorkerReceipt = Record<string, unknown> & {
  chainId?: unknown
  terminalVulnClass?: unknown
  hops?: unknown
  causalEdges?: unknown
  terminalImpact?: unknown
  replayMode?: unknown
}

interface CapturedAttempt {
  session: VerifyAttemptSession
  execution: AttemptExecution
}

interface HarnessRun {
  verdict: VerifyVerdict
  attempts: CapturedAttempt[]
  workerReceipts: WorkerReceipt[]
  requestedOrigins: string[]
  runtimeMs: number
}

interface ChainOutcome {
  chainId: string
  app: AppId
  mode: LabMode
  twin: string | null
  workerConfirmed: boolean
  workerReason: string | null
  workerRejectedBy: string | null
  oracleCompleted: boolean
  oracleConfirmed: boolean
  terminals: number
  confirmations: number
  decoyFps: number
  gradePass: boolean
  runtimeMs: number
  gap: string | null
}

const APP_DEFS = {
  paygrid: { chains: PG_CHAINS, twins: PG_TWINS, start: startPaygrid },
  shipforge: { chains: SF_CHAINS, twins: SF_TWINS, start: startShipforge },
  nexusiam: { chains: NX_CHAINS, twins: NX_TWINS, start: startNexusiam },
} as const

const ALL_CHAINS: readonly ChainSpec[] = [...PG_CHAINS, ...SF_CHAINS, ...NX_CHAINS]
const CHAIN_BY_ID = new Map(ALL_CHAINS.map((chain) => [chain.id, chain]))
const labs = new Map<string, StartedLab>()

function labKey(app: AppId, mode: LabMode, twin?: string): string {
  return `${app}:${mode}:${twin ?? '-'}`
}

async function sharedLab(app: AppId, mode: LabMode, twin?: string): Promise<StartedLab> {
  const key = labKey(app, mode, twin)
  const existing = labs.get(key)
  if (existing) return existing
  const def = APP_DEFS[app]
  const started = await def.start({
    seed: SEED,
    mode,
    ...(twin ? { twin } : {}),
    asyncLatencyMs: ASYNC_LATENCY_MS,
  } as never)
  labs.set(key, started)
  return started
}

test.after(async () => {
  await Promise.all([...labs.values()].map((lab) => lab.stop()))
  labs.clear()
})

function publicOrigins(lab: StartedLab): Record<string, string> {
  const entries = lab.briefing('grey-box').entryOrigins as Record<string, string>
  const origins = Object.fromEntries(Object.entries(entries).filter(([, value]) => typeof value === 'string' && value.length > 0))
  assert.ok(Object.keys(origins).length > 0, 'grey-box briefing must advertise public entry origins')
  for (const [service, origin] of Object.entries(origins)) {
    assert.equal(new URL(origin).origin, origin, `${service}: entry origin must be an origin, not a URL with a path`)
  }
  return origins
}

function personaLabel(id: string, tenant: string, roles: Record<string, string>): string {
  const role = roles[tenant] ?? Object.values(roles)[0] ?? 'member'
  return `${role} (${tenant})`
}

function makePersonas(lab: StartedLab, origins: Record<string, string>, app: AppId): ResolvedPersona[] {
  const allowlist = Object.values(origins)
  return lab.briefing('grey-box').personas.map((persona) => {
    // ShipForge's revoked credential is a PAT accepted by the public stream relay, not a login
    // password. It remains a host-injected persona secret and is never present in script source.
    const shipforgePat = app === 'shipforge' && persona.id === 'revoked_or_demoted'
      ? (lab as StartedShipforge).plan.ids.revokedPatToken
      : undefined
    return {
      id: `persona-${persona.id}`,
      handle: persona.id,
      roleLabel: personaLabel(persona.id, persona.tenant, persona.rolesByTenant as Record<string, string>),
      originAllowlist: allowlist,
      authKind: 'bearer',
      headerName: null,
      secret: shipforgePat ?? persona.password,
      canaryMarkers: [],
    }
  })
}

function makeGrant(origins: Record<string, string>, personas: ResolvedPersona[], requested: Set<string>): Grant {
  const allowed = new Set(Object.values(origins))
  return {
    canRead(candidate: string) {
      let origin: string
      try { origin = new URL(candidate).origin } catch { return false }
      requested.add(origin)
      return allowed.has(origin)
    },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map(personas.map((persona) => [persona.handle, persona])),
  }
}

interface ScriptConfig {
  title: string
  chainId: string
  terminalVulnClass: string
  publicOrigins: Record<string, string>
  loginService: string
  personas: Record<string, { email: string; password: string; tenant: string }>
  routePrefix: string
  tenantA: string
  tenantB: string
  tenantC: string
  ids: Record<string, unknown>
  economics: Record<string, unknown>
  memberUserId: string
  nexus?: Record<string, unknown>
}

function scriptConfig(lab: StartedLab, chain: ChainSpec): ScriptConfig {
  const plan = lab.plan
  const app = lab.app as AppId
  const briefing = lab.briefing('grey-box')
  return {
    title: chain.title,
    chainId: chain.id,
    terminalVulnClass: chain.vulnClass,
    publicOrigins: publicOrigins(lab),
    loginService: app === 'shipforge' ? 'scm' : 'idp',
    personas: Object.fromEntries(briefing.personas.map((persona) => [persona.id, {
      email: persona.email,
      password: persona.password,
      tenant: persona.tenant === 'org_a' ? plan.tenants.a.slug
        : persona.tenant === 'org_b' ? plan.tenants.b.slug
          : plan.tenants.c.slug,
    }])),
    routePrefix: plan.routePrefix,
    tenantA: plan.tenants.a.slug,
    tenantB: plan.tenants.b.slug,
    tenantC: plan.tenants.c.slug,
    ids: { ...plan.ids },
    economics: 'economics' in plan ? { ...plan.economics } : {},
    memberUserId: plan.personas.member_a.userId,
    ...('nexus' in plan ? { nexus: { ...plan.nexus } } : {}),
  }
}

const SCRIPT_PRELUDE = String.raw`
import { createHash } from 'node:crypto'
const cfg = __GOLDEN_CONFIG__
const title = cfg.title
const origin = (service: string): string => {
  const value = cfg.publicOrigins[service]
  if (!value) throw new Error('non-public service requested: ' + service)
  return value
}
const send = (service: string, path: string, options: Record<string, unknown> = {}) =>
  ctx.http_send(origin(service) + path, { role: 'probe', ...options })
const bearer = (cap: any, as?: string, extra: Record<string, unknown> = {}) => ({
  ...(as ? { as } : {}),
  capability: { handle: cap.handle, target: 'bearer' },
  ...extra,
})
const headerCap = (cap: any, headerName: string, as?: string, extra: Record<string, unknown> = {}) => ({
  ...(as ? { as } : {}),
  capability: { handle: cap.handle, target: 'header', headerName },
  ...extra,
})
const login = async (persona: string, tenant?: string) => {
  const record = cfg.personas[persona]
  if (!record) throw new Error('unknown briefing persona: ' + persona)
  const exchange = await send(cfg.loginService, '/login', {
    as: persona,
    role: 'setup',
    method: 'POST',
    body: { email: record.email, password: record.password, tenant: tenant ?? record.tenant },
  })
  if (exchange.status !== 200) return null
  return await ctx.seal_capability({
    exchange,
    hopReceiptId: 'setup',
    slot: persona + '_' + String(tenant ?? record.tenant).replace(/[^A-Za-z0-9_.-]/g, '_') + '_session',
    jsonPath: '$.token',
    kind: 'bearer_token',
    allowedOrigins: Object.values(cfg.publicOrigins),
  })
}
const seal = (exchange: any, hopReceiptId: string, slot: string, selector: Record<string, unknown>, kind = 'generic_secret') =>
  ctx.seal_capability({
    exchange,
    hopReceiptId,
    slot,
    allowedOrigins: Object.values(cfg.publicOrigins),
    kind,
    ...selector,
  })
const target = (service: string, method: string, pathAndQuery: string) => ({
  origin: origin(service), method, pathAndQuery,
})
const hop = (hopId: string, service: string, method: string, pathAndQuery: string, exchange: any, claimedDelta: string, extra: Record<string, unknown> = {}) => ({
  hopId,
  surface: 'http',
  target: target(service, method, pathAndQuery),
  exchangeIds: [exchange.exchangeId],
  claimedDelta,
  ...extra,
})
const finish = async (receipt: Record<string, unknown>) => {
  await ctx.prove_composite(receipt)
  return ctx.result({ title })
}
`

function withConfig(code: string, config: ScriptConfig): string {
  const unescaped = code.replace(/\\`/g, '`').replace(/\\\$\{/g, '${')
  return SCRIPT_PRELUDE.replace('__GOLDEN_CONFIG__', JSON.stringify(config)) + '\n' + unescaped
}

function goldenScript(chainId: string, config: ScriptConfig): string {
  switch (chainId) {
    case 'PG-C1': return withConfig(String.raw`
const memberB = await login('member_b')
if (!memberB) return ctx.result({ title })
const h1 = await send('edge', \`\${cfg.routePrefix}/directory/orgs/\${cfg.tenantA}\`, bearer(memberB, 'member_b'))
if (h1.status !== 200) return ctx.result({ title })
const pending = String(h1.json.pendingEmail ?? '').trim()
if (!pending) return ctx.result({ title })
const pendingCap = await seal(h1, 'pg-c1-h1', 'pending_email', { value: pending })
const pendingDerived = await ctx.hmac_sign(pendingCap.handle, pending)
const h2 = await send('idp', '/invites/resolve', {
  ...bearer(memberB, 'member_b'),
  method: 'POST',
  headers: { 'x-kovo-derivation': pendingDerived.signature },
  body: { email: pending.normalize('NFKC'), orgSlug: cfg.tenantA, role: 'finance' },
})
if (h2.status !== 200) return ctx.result({ title })
const financeCap = await seal(h2, 'pg-c1-h2', 'finance_session', { jsonPath: '$.token' }, 'bearer_token')
const listed = await send('api', \`\${cfg.routePrefix}/payouts\`, bearer(financeCap, 'member_b'))
if (listed.status !== 200) return ctx.result({ title })
const payout = listed.json.payouts.find((item: any) => item.status === 'draft')
if (!payout) return ctx.result({ title })
const memberA = await login('member_a')
if (!memberA) return ctx.result({ title })
const payoutPath = \`\${cfg.routePrefix}/payouts/\${payout.id}\`
const control = await send('api', \`\${payoutPath}/approve\`, {
  ...bearer(memberA, 'member_a'),
  method: 'POST',
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: payout.id,
})
const h3 = await send('api', \`\${payoutPath}/rebind\`, {
  ...bearer(financeCap, 'member_b'),
  method: 'PATCH',
  entityId: payout.id,
})
if (h3.status !== 200) return ctx.result({ title })
const h4 = await send('api', \`\${payoutPath}/approve\`, {
  ...bearer(financeCap, 'member_b'),
  method: 'POST',
  entityId: payout.id,
})
return await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('pg-c1-h1', 'edge', 'GET', \`\${cfg.routePrefix}/directory/orgs/\${cfg.tenantA}\`, h1, 'Directory disclosed a pending finance invitation.', { producedCapabilities: [pendingCap.handle] }),
    hop('pg-c1-h2', 'idp', 'POST', '/invites/resolve', h2, 'Normalization collision minted a finance session.', { producedCapabilities: [financeCap.handle] }),
    hop('pg-c1-h3', 'api', 'PATCH', \`\${payoutPath}/rebind\`, h3, 'Finance session rebound a draft payout.', { consumedCapabilities: [financeCap.handle], entityId: payout.id }),
    hop('pg-c1-h4', 'api', 'POST', \`\${payoutPath}/approve\`, h4, 'Rebound payout was self-approved.', { consumedCapabilities: [financeCap.handle], entityId: payout.id }),
  ],
  causalEdges: [
    { kind: 'derived_crypto_binding', fromHopId: 'pg-c1-h1', toHopId: 'pg-c1-h2', sourceCapabilityId: pendingCap.handle, alg: 'sha256' },
    { kind: 'value_binding', fromHopId: 'pg-c1-h2', toHopId: 'pg-c1-h3', capabilityHandle: financeCap.handle },
    { kind: 'state_transition_binding', fromHopId: 'pg-c1-h3', toHopId: 'pg-c1-h4', entityId: payout.id, ablationExchangeIds: [control.exchangeId], mutationKind: 'payout_rebind' },
  ],
  terminalImpact: {
    terminalHopId: 'pg-c1-h4',
    summary: 'A member-originated finance session approved the rebound payout without maker-checker separation.',
    terminalExchangeId: h4.exchangeId,
    preChainControlExchangeIds: [control.exchangeId],
  },
  replayMode: 'fresh_clean_replay',
})
`, config)

    case 'PG-C2': return withConfig(String.raw`
const member = await login('member_a')
if (!member) return ctx.result({ title })
const templatePath = \`\${cfg.routePrefix}/invoice-templates/\${cfg.ids.templateId}\`
const h1 = await send('api', templatePath, {
  ...bearer(member, 'member_a'),
  method: 'PATCH',
  body: { footer: '<p>amount due</p><img src="/internal/render-hook" alt="logo">' },
})
if (h1.status !== 200 || !h1.json.template?.rawStored) return ctx.result({ title })
const templateId = String(h1.json.template.id)
const renderPath = \`\${cfg.routePrefix}/invoices/\${cfg.ids.invoiceId}/render\`
const h2 = await send('api', renderPath, {
  ...bearer(member, 'member_a'),
  method: 'POST',
  headers: { 'x-kovo-correlation': templateId },
})
if (h2.status !== 202) return ctx.result({ title })
const jobId = String(h2.json.jobId)
const jobCap = await seal(h2, 'pg-c2-h2', 'render_job', { jsonPath: '$.jobId' })
let ready = false
for (let attempt = 0; attempt < 80; attempt++) {
  const polled = await send('api', \`\${cfg.routePrefix}/jobs/\${jobId}\`, bearer(member, 'member_a'))
  if (polled.status !== 200) return ctx.result({ title })
  if (polled.json.job?.status === 'ready') { ready = true; break }
  if (polled.json.job?.status === 'failed') break
  if (polled.json.job?.status === 'cancelled') return ctx.result({ title })
  await new Promise((resolve) => setTimeout(resolve, 10))
}
const tracePath = \`\${cfg.routePrefix}/jobs/\${jobCap.handle}/trace\`
const h3 = await send('api', tracePath, bearer(member, 'member_a'))
if (h3.status !== 200) return ctx.result({ title })
const secret = String(h3.json.leakedSecret ?? '').trim()
if (!secret) return ctx.result({ title })
const secretCap = await seal(h3, 'pg-c2-h3', 'signing_salt', { jsonPath: '$.leakedSecret' }, 'hmac_key')
const payload = JSON.stringify({ tenantId: 'org_a', amountCents: cfg.economics.settlementAmountCents, memo: \`settlement:\${jobId}\` })
const signed = await ctx.hmac_sign(secretCap.handle, payload)
const h4 = await send('api', \`\${cfg.routePrefix}/webhooks/settlement\`, {
  method: 'POST',
  body: payload,
  headers: {
    'content-type': 'application/json',
    'x-signature': signed.signature,
    'x-lab-derived-from': createHash('sha256').update(secret).digest('hex'),
    'x-scope': 'settlement:write',
  },
})
const readback = await send('api', \`\${cfg.routePrefix}/ledger\`, { ...bearer(member, 'member_a'), evidenceRole: 'post_chain_readback' })
return await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('pg-c2-h1', 'api', 'PATCH', templatePath, h1, 'Raw invoice footer was stored.', { producedCapabilities: [] }),
    hop('pg-c2-h2', 'api', 'POST', renderPath, h2, 'Render job consumed the raw footer.', { producedCapabilities: [jobCap.handle] }),
    hop('pg-c2-h3', 'api', 'GET', tracePath, h3, 'Worker trace disclosed signing material.', { consumedCapabilities: [jobCap.handle], producedCapabilities: [secretCap.handle] }),
    hop('pg-c2-h4', 'api', 'POST', \`\${cfg.routePrefix}/webhooks/settlement\`, h4, 'Forged settlement webhook was accepted.'),
  ],
  causalEdges: [
    { kind: 'async_pivot_binding', fromHopId: 'pg-c2-h1', toHopId: 'pg-c2-h2', correlationId: templateId, channel: 'async_job' },
    { kind: 'value_binding', fromHopId: 'pg-c2-h2', toHopId: 'pg-c2-h3', capabilityHandle: jobCap.handle },
    { kind: 'derived_crypto_binding', fromHopId: 'pg-c2-h3', toHopId: 'pg-c2-h4', sourceCapabilityId: secretCap.handle, alg: 'sha256' },
  ],
  terminalImpact: {
    terminalHopId: 'pg-c2-h4',
    summary: 'The worker-disclosed signing salt authenticated a forged settlement credit.',
    terminalExchangeId: h4.exchangeId,
    preChainControlExchangeIds: [],
    postChainReadbackExchangeIds: [readback.exchangeId],
  },
  replayMode: 'fresh_clean_replay',
})
`, config)

    case 'PG-C3': return withConfig(String.raw`
const viewerB = await login('dual_member', cfg.tenantB)
const adminA = await login('dual_member', cfg.tenantA)
if (!viewerB || !adminA) return ctx.result({ title })
const exportPath = \`\${cfg.routePrefix}/orgs/org_b/exports\`
const control = await send('api', exportPath, {
  ...bearer(viewerB, 'dual_member'),
  method: 'POST',
  role: 'control',
  replayAttempt: 'ablation_control',
})
const h1 = await send('api', \`\${cfg.routePrefix}/orgs/org_a/permissions\`, bearer(adminA, 'dual_member'))
if (h1.status !== 200 || h1.json.scoped) return ctx.result({ title })
const cacheKey = String(h1.json.cacheKey)
const cacheCap = await seal(h1, 'pg-c3-h1', 'permission_cache_key', { jsonPath: '$.cacheKey' })
const workerAblation = await send('api', exportPath, {
  as: 'dual_member',
  method: 'POST',
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: cacheKey,
})
const h2 = await send('api', exportPath, {
  ...bearer(viewerB, 'dual_member'),
  method: 'POST',
  entityId: cacheKey,
  body: { correlation: cacheKey },
  headers: { 'x-kovo-correlation': cacheKey },
})
if (h2.status !== 202) return ctx.result({ title })
const jobId = String(h2.json.jobId)
const jobCap = await seal(h2, 'pg-c3-h2', 'export_job', { jsonPath: '$.jobId' })
const poll = await ctx.await_async({
  pollRequest: \`\${origin('api')}\${cfg.routePrefix}/exports/\${jobId}?correlation=\${cacheKey}\`,
  as: 'dual_member',
  capability: { handle: viewerB.handle, target: 'bearer' },
  headers: { 'x-kovo-job': jobCap.handle, 'x-kovo-correlation': cacheKey },
  role: 'probe',
  triggerExchangeId: h2.exchangeId,
  correlationId: cacheKey,
  entityId: jobId,
  matchPredicate: { jsonPath: '$.job.status', equals: 'ready' },
  profile: 'fast_lab',
  timeoutMs: 5000,
  intervalMs: 10,
})
if (!poll.converged || !poll.exchange) return ctx.result({ title })
const h3 = poll.exchange
const h3JobCap = await seal(h3, 'pg-c3-h3', 'polled_export_job', { jsonPath: '$.job.id' })
const h4 = await send('api', \`\${cfg.routePrefix}/exports/\${h3JobCap.handle}/url\`, bearer(viewerB, 'dual_member'))
if (h4.status !== 200) return ctx.result({ title })
const signedUrl = String(h4.json.signedUrl)
const parsed = new URL(signedUrl)
if (parsed.origin !== origin('edge')) throw new Error('signed URL escaped public origins')
const sigMatch = /[?&]sig=([^&]+)/.exec(signedUrl)
if (!sigMatch) return ctx.result({ title })
const sigCap = await seal(h4, 'pg-c3-h4', 'export_signature', { regex: '[?&]sig=([^&]+)' }, 'signed_url')
parsed.pathname = parsed.pathname.replace(\`/files/export/\${cfg.tenantB}\`, \`/files/export/\${cfg.tenantC}\`)
const terminalPath = parsed.pathname + '?job=' + encodeURIComponent(jobId) + '&tenant=' + encodeURIComponent(cfg.tenantB)
const terminalControl = await ctx.http_send(parsed.origin + terminalPath + '&sig=invalid', {
  as: 'dual_member',
  capability: { handle: viewerB.handle, target: 'bearer' },
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: jobId,
})
const h5 = await ctx.http_send(parsed.origin + terminalPath + '&sig=' + encodeURIComponent(sigCap.handle), {
  as: 'dual_member',
  capability: { handle: viewerB.handle, target: 'bearer' },
  role: 'probe',
  entityId: jobId,
})
return await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('pg-c3-h1', 'api', 'GET', \`\${cfg.routePrefix}/orgs/org_a/permissions\`, h1, 'Tenantless permission cache was primed.', { producedCapabilities: [cacheCap.handle], entityId: cacheKey }),
    hop('pg-c3-h2', 'api', 'POST', exportPath, h2, 'Cached permissions allowed a foreign-tenant export job.', { entityId: cacheKey, producedCapabilities: [jobCap.handle] }),
    hop('pg-c3-h3', 'api', 'GET', \`\${cfg.routePrefix}/exports/\${jobCap.handle}\`, h3, 'Export job reached ready state.', { consumedCapabilities: [jobCap.handle], producedCapabilities: [h3JobCap.handle], entityId: jobId }),
    hop('pg-c3-h4', 'api', 'GET', \`\${cfg.routePrefix}/exports/\${h3JobCap.handle}/url\`, h4, 'A reusable signed export URL was minted.', { consumedCapabilities: [h3JobCap.handle], producedCapabilities: [sigCap.handle], entityId: jobId }),
    hop('pg-c3-h5', 'edge', 'GET', terminalPath + '&sig=' + encodeURIComponent(sigCap.handle), h5, 'Sibling-tenant treasury data was downloaded.', { consumedCapabilities: [sigCap.handle], entityId: jobId }),
  ],
  causalEdges: [
    { kind: 'state_transition_binding', fromHopId: 'pg-c3-h1', toHopId: 'pg-c3-h2', entityId: cacheKey, ablationExchangeIds: [workerAblation.exchangeId], mutationKind: 'permission_cache_prime' },
    { kind: 'async_pivot_binding', fromHopId: 'pg-c3-h2', toHopId: 'pg-c3-h3', correlationId: cacheKey, channel: 'async_job' },
    { kind: 'value_binding', fromHopId: 'pg-c3-h3', toHopId: 'pg-c3-h4', capabilityHandle: h3JobCap.handle },
    { kind: 'value_binding', fromHopId: 'pg-c3-h4', toHopId: 'pg-c3-h5', capabilityHandle: sigCap.handle },
  ],
  terminalImpact: {
    terminalHopId: 'pg-c3-h5',
    summary: 'A signed export handle was reused to download another tenant treasury file.',
    terminalExchangeId: h5.exchangeId,
    preChainControlExchangeIds: [terminalControl.exchangeId],
  },
  replayMode: 'fresh_clean_replay',
})
`, config)

    case 'PG-C4': return withConfig(String.raw`
const member = await login('member_a')
const viewer = await login('viewer_a')
if (!member || !viewer) return ctx.result({ title })
const inflated = cfg.economics.payoutCapCents + cfg.economics.orderAmountCents
const raw = '{"amountCents":' + inflated + ',"beneficiary":"acct_vendor_1","amountCents":100}'
const h1 = await send('edge', \`\${cfg.routePrefix}/orders\`, {
  ...bearer(member, 'member_a'),
  method: 'POST',
  body: raw,
  headers: { 'content-type': 'application/json' },
})
if (h1.status !== 201) return ctx.result({ title })
const orderId = String(h1.json.order.id)
const orderCap = await seal(h1, 'pg-c4-h1', 'order_id', { jsonPath: '$.order.id' })
const orderPath = \`\${cfg.routePrefix}/orders/\${orderCap.handle}\`
const terminalControl = await send('api', \`\${orderPath}/settle-race\`, {
  ...bearer(viewer, 'viewer_a'),
  method: 'POST',
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: orderId,
})
const ablation = await send('api', \`\${orderPath}/settle-race\`, {
  ...bearer(member, 'member_a'),
  method: 'POST',
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: orderId,
})
const h2 = await send('api', \`\${orderPath}/rebind\`, {
  ...bearer(member, 'member_a'),
  method: 'PATCH',
  body: { beneficiary: 'acct_attacker_controlled' },
  entityId: orderId,
})
if (h2.status !== 200) return ctx.result({ title })
const race = await ctx.prove_race_burst({
  requests: [
    { url: origin('api') + orderPath + '/settle-race', method: 'POST', as: 'member_a', capability: { handle: member.handle, target: 'bearer' }, role: 'probe', entityId: orderId },
    { url: origin('api') + orderPath + '/settle-race', method: 'POST', as: 'member_a', capability: { handle: member.handle, target: 'bearer' }, role: 'probe', entityId: orderId },
  ],
})
if (ctx.claims.at(-1)?.kind === 'race') ctx.claims.pop()
const h3 = race.exchanges.find((exchange: any) => exchange.status === 200) ?? race.exchanges.at(-1)
return await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('pg-c4-h1', 'api', 'POST', \`\${cfg.routePrefix}/orders\`, h1, 'Duplicate-key cap bypass created an inflated order.', { producedCapabilities: [orderCap.handle], entityId: orderId }),
    hop('pg-c4-h2', 'api', 'PATCH', \`\${orderPath}/rebind\`, h2, 'Authorized order was rebound to an attacker beneficiary.', { consumedCapabilities: [orderCap.handle], entityId: orderId }),
    hop('pg-c4-h3', 'api', 'POST', \`\${orderPath}/settle-race\`, h3, 'Concurrent captures overcredited the ledger.', { consumedCapabilities: [orderCap.handle], entityId: orderId }),
  ],
  causalEdges: [
    { kind: 'value_binding', fromHopId: 'pg-c4-h1', toHopId: 'pg-c4-h2', capabilityHandle: orderCap.handle },
    { kind: 'state_transition_binding', fromHopId: 'pg-c4-h2', toHopId: 'pg-c4-h3', entityId: orderId, ablationExchangeIds: [ablation.exchangeId], mutationKind: 'order_rebind' },
  ],
  terminalImpact: {
    terminalHopId: 'pg-c4-h3',
    summary: 'The rebound order was captured twice concurrently, breaking ledger conservation.',
    terminalExchangeId: h3.exchangeId,
    preChainControlExchangeIds: [terminalControl.exchangeId],
  },
  replayMode: 'fresh_clean_replay',
})
`, config)

    case 'SF-C1': return withConfig(String.raw`
const member = await login('member_a')
if (!member) return ctx.result({ title })
const previewPath = \`/repos/\${cfg.ids.projectIdA}/preview-builds\`
const h1 = await send('scm', previewPath, { ...bearer(member, 'member_a'), method: 'POST', body: { commit: 'refs/heads/main' } })
if (h1.status !== 202) return ctx.result({ title })
const buildId = String(h1.json.buildId)
const gqlBody = { query: 'query CiRun($id: ID!) { ciRun(id: $id) { id status envPreview { env runnerToken } } }', variables: { id: buildId } }
const poll = await ctx.await_async({
  pollRequest: { url: \`\${origin('api')}\${cfg.routePrefix}/graphql\`, method: 'POST', as: 'member_a', capability: { handle: member.handle, target: 'bearer' }, role: 'probe', body: gqlBody },
  triggerExchangeId: h1.exchangeId,
  correlationId: buildId,
  entityId: buildId,
  matchPredicate: { jsonPath: '$.data.ciRun.status', equals: 'ready' },
  profile: 'fast_lab',
  timeoutMs: 5000,
  intervalMs: 10,
})
if (!poll.converged || !poll.exchange) return ctx.result({ title })
const h2 = poll.exchange
const runnerToken = String(h2.json.data?.ciRun?.envPreview?.runnerToken ?? '')
if (!runnerToken) return ctx.result({ title })
const runnerCap = await seal(h2, 'sf-c1-h2', 'runner_token', { jsonPath: '$.data.ciRun.envPreview.runnerToken' }, 'bearer_token')
const promotePath = \`\${cfg.routePrefix}/deployments/\${cfg.ids.deploymentProdId}/promote\`
const h3 = await send('api', promotePath, { ...bearer(runnerCap), method: 'POST' })
if (h3.status !== 200) return ctx.result({ title })
const serviceCap = await seal(h3, 'sf-c1-h3', 'service_account', { jsonPath: '$.serviceAccountToken' }, 'bearer_token')
const h4 = await send('api', \`\${cfg.routePrefix}/secrets/batch\`, {
  ...bearer(serviceCap),
  method: 'POST',
  body: { ids: [cfg.ids.ownSecretId, cfg.ids.victimSecretId], mutate: true },
})
if (h4.status !== 200) return ctx.result({ title })
const signingKey = h4.json.processed?.find((item: any) => item.id === cfg.ids.victimSecretId)?.value
if (!signingKey) return ctx.result({ title })
const signingCap = await seal(h4, 'sf-c1-h4', 'prod_signing_key', { jsonPath: '$.processed[1].value' }, 'hmac_key')
const manifest = JSON.stringify({ deployment: cfg.ids.deploymentProdId, environment: 'prod', version: '2026.11.0', artifact: buildId })
const signed = await ctx.hmac_sign(signingCap.handle, manifest)
const releasePath = \`\${cfg.routePrefix}/deployments/\${cfg.ids.deploymentProdId}/release\`
const h5 = await send('api', releasePath, {
  ...bearer(serviceCap),
  method: 'POST',
  body: { manifest, signature: signed.signature, version: '2026.11.0' },
})
return await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('sf-c1-h1', 'scm', 'POST', previewPath, h1, 'Preview build exposed a development runner credential.'),
    hop('sf-c1-h2', 'api', 'POST', \`\${cfg.routePrefix}/graphql\`, h2, 'GraphQL projected the preview runner token.', { producedCapabilities: [runnerCap.handle], entityId: buildId }),
    hop('sf-c1-h3', 'api', 'POST', promotePath, h3, 'Development runner token promoted production.', { consumedCapabilities: [runnerCap.handle], producedCapabilities: [serviceCap.handle], entityId: cfg.ids.deploymentProdId }),
    hop('sf-c1-h4', 'api', 'POST', \`\${cfg.routePrefix}/secrets/batch\`, h4, 'Service account batch read foreign signing material.', { consumedCapabilities: [serviceCap.handle], producedCapabilities: [signingCap.handle] }),
    hop('sf-c1-h5', 'api', 'POST', releasePath, h5, 'Foreign signing key authorized a production release.', { consumedCapabilities: [serviceCap.handle] }),
  ],
  causalEdges: [
    { kind: 'async_pivot_binding', fromHopId: 'sf-c1-h1', toHopId: 'sf-c1-h2', correlationId: buildId, channel: 'poll_convergence', pollRecordId: poll.pollRecordId },
    { kind: 'value_binding', fromHopId: 'sf-c1-h2', toHopId: 'sf-c1-h3', capabilityHandle: runnerCap.handle },
    { kind: 'value_binding', fromHopId: 'sf-c1-h3', toHopId: 'sf-c1-h4', capabilityHandle: serviceCap.handle },
    { kind: 'derived_crypto_binding', fromHopId: 'sf-c1-h4', toHopId: 'sf-c1-h5', sourceCapabilityId: signingCap.handle, alg: 'sha256' },
  ],
  terminalImpact: {
    terminalHopId: 'sf-c1-h5',
    summary: 'A cross-tenant signing key signed an unauthorized production release manifest.',
    terminalExchangeId: h5.exchangeId,
    preChainControlExchangeIds: [],
  },
  replayMode: 'fresh_clean_replay',
})
`, config)

    case 'SF-C2': return withConfig(String.raw`
const dual = await login('dual_member')
if (!dual) return ctx.result({ title })
const streamPath = \`\${cfg.routePrefix}/runners/shared/events\`
const seed = await send('api', streamPath, { as: 'revoked_or_demoted', role: 'setup' })
if (seed.status !== 200) return ctx.result({ title })
const seedFrame = seed.text.split('\n').filter((line: string) => line.startsWith('data: '))
  .map((line: string) => { try { return JSON.parse(line.slice(6)) } catch { return null } })
  .find((item: any) => item?.type === 'artifact.ready' && item.artifactHandle && item.projectId)
if (!seedFrame) return ctx.result({ title })
const artifactHandle = String(seedFrame.artifactHandle)
const projectId = String(seedFrame.projectId)
const h1 = await send('api', streamPath, { as: 'revoked_or_demoted', correlationIds: [artifactHandle], entityId: artifactHandle })
if (h1.status !== 200) return ctx.result({ title })
const frame = h1.text.split('\n').filter((line: string) => line.startsWith('data: '))
  .map((line: string) => { try { return JSON.parse(line.slice(6)) } catch { return null } })
  .find((item: any) => item?.type === 'artifact.ready' && item.artifactHandle && item.projectId)
if (!frame) return ctx.result({ title })
const poll = await ctx.await_async({
  pollRequest: { url: origin('api') + streamPath, as: 'revoked_or_demoted', role: 'probe' },
  triggerExchangeId: h1.exchangeId,
  correlationId: artifactHandle,
  entityId: artifactHandle,
  matchPredicate: { bodyContains: 'artifact.ready' },
  profile: 'fast_lab',
  timeoutMs: 5000,
  intervalMs: 10,
})
if (!poll.converged || !poll.exchange) return ctx.result({ title })
const h2 = poll.exchange
const artifactCap = await seal(h2, 'sf-c2-h2', 'artifact_handle', { regex: 'artifactHandle":"([^"]+)' })
const workerAblation = await send('scm', \`/repos/\${projectId}/archive\`, {
  as: 'dual_member',
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: projectId,
})
const control = await send('scm', \`/repos/\${projectId}/archive\`, {
  ...bearer(dual, 'dual_member'),
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: projectId,
})
const h3 = await send('api', \`\${cfg.routePrefix}/projects/\${projectId}/transfer\`, {
  ...bearer(dual, 'dual_member'),
  method: 'POST',
  body: { destinationTenant: cfg.tenantA, artifactHandle: artifactCap.handle },
  entityId: projectId,
})
if (h3.status !== 200) return ctx.result({ title })
const h4 = await send('scm', \`/repos/\${projectId}/archive\`, { ...bearer(dual, 'dual_member'), entityId: projectId })
return await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('sf-c2-h1', 'api', 'GET', streamPath, h1, 'Revoked PAT opened the shared runner stream.'),
    hop('sf-c2-h2', 'api', 'GET', streamPath, h2, 'Stream converged on a cross-tenant artifact handle.', { producedCapabilities: [artifactCap.handle] }),
    hop('sf-c2-h3', 'api', 'POST', \`\${cfg.routePrefix}/projects/\${projectId}/transfer\`, h3, 'Artifact custody enabled a cross-tenant project transfer.', { consumedCapabilities: [artifactCap.handle], entityId: projectId }),
    hop('sf-c2-h4', 'scm', 'GET', \`/repos/\${projectId}/archive\`, h4, 'Transferred repository archive was exported.', { entityId: projectId }),
  ],
  causalEdges: [
    { kind: 'async_pivot_binding', fromHopId: 'sf-c2-h1', toHopId: 'sf-c2-h2', correlationId: artifactHandle, channel: 'poll_convergence', pollRecordId: poll.pollRecordId },
    { kind: 'value_binding', fromHopId: 'sf-c2-h2', toHopId: 'sf-c2-h3', capabilityHandle: artifactCap.handle },
    { kind: 'state_transition_binding', fromHopId: 'sf-c2-h3', toHopId: 'sf-c2-h4', entityId: projectId, ablationExchangeIds: [workerAblation.exchangeId], mutationKind: 'project_transfer' },
  ],
  terminalImpact: {
    terminalHopId: 'sf-c2-h4',
    summary: 'A revoked credential and stolen artifact handle enabled cross-tenant repository export.',
    terminalExchangeId: h4.exchangeId,
    preChainControlExchangeIds: [control.exchangeId],
  },
  replayMode: 'fresh_clean_replay',
})
`, config)

    case 'SF-C3': return withConfig(String.raw`
const member = await login('member_a')
if (!member) return ctx.result({ title })
const searchPath = \`\${cfg.routePrefix}/search/projects?state=archived&visibility=shared\`
const h1 = await send('api', searchPath, bearer(member, 'member_a'))
if (h1.status !== 200) return ctx.result({ title })
const template = h1.json.webhookTemplates?.[0]
if (!template?.id) return ctx.result({ title })
const templateId = String(template.id)
const templateCap = await seal(h1, 'sf-c3-h1', 'webhook_template', { jsonPath: '$.webhookTemplates[0].id' })
const templateDerived = await ctx.hmac_sign(templateCap.handle, templateId)
const webhookPath = \`\${cfg.routePrefix}/projects/\${cfg.ids.projectIdA}/webhooks\`
const h2 = await send('api', webhookPath, {
  ...bearer(member, 'member_a'),
  method: 'POST',
  headers: { 'x-kovo-derivation': templateDerived.signature },
  body: { templateId: templateCap.handle, targetHost: 'registry.internal', targetPath: '/sync', events: ['push'] },
})
if (h2.status !== 201) return ctx.result({ title })
const webhookId = String(h2.json.webhookId)
const webhookCap = await seal(h2, 'sf-c3-h2', 'webhook_id', { jsonPath: '$.webhookId' })
const deliveryPath = \`\${cfg.routePrefix}/projects/\${cfg.ids.projectIdA}/webhooks/\${webhookCap.handle}/deliveries\`
const h3 = await send('api', deliveryPath, bearer(member, 'member_a'))
if (h3.status !== 200) return ctx.result({ title })
const tokenMatch = /mh_fake_internal_[a-z0-9]+/.exec(h3.text)
if (!tokenMatch) return ctx.result({ title })
const token = tokenMatch[0]
const tokenCap = await seal(h3, 'sf-c3-h3', 'registry_token', { regex: 'mh_fake_internal_[a-z0-9]+' }, 'api_token')
const tokenDerived = await ctx.hmac_sign(tokenCap.handle, cfg.tenantB)
const h4 = await send('api', \`\${cfg.routePrefix}/integrations/registry/sync\`, {
  ...bearer(member, 'member_a'),
  method: 'POST',
  headers: { 'x-registry-token': tokenCap.handle, 'x-kovo-derivation': tokenDerived.signature },
  body: { tenant: cfg.tenantB, projectId: cfg.ids.projectIdB },
})
return await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('sf-c3-h1', 'api', 'GET', searchPath, h1, 'Search leaked an internal webhook template.', { producedCapabilities: [templateCap.handle] }),
    hop('sf-c3-h2', 'api', 'POST', webhookPath, h2, 'Leaked template created an internal delivery.', { consumedCapabilities: [templateCap.handle], producedCapabilities: [webhookCap.handle] }),
    hop('sf-c3-h3', 'api', 'GET', deliveryPath, h3, 'Delivery log disclosed an internal registry token.', { consumedCapabilities: [webhookCap.handle], producedCapabilities: [tokenCap.handle] }),
    hop('sf-c3-h4', 'api', 'POST', \`\${cfg.routePrefix}/integrations/registry/sync\`, h4, 'Registry token synchronized foreign tenant metadata.'),
  ],
  causalEdges: [
    { kind: 'derived_crypto_binding', fromHopId: 'sf-c3-h1', toHopId: 'sf-c3-h2', sourceCapabilityId: templateCap.handle, alg: 'sha256' },
    { kind: 'value_binding', fromHopId: 'sf-c3-h2', toHopId: 'sf-c3-h3', capabilityHandle: webhookCap.handle },
    { kind: 'derived_crypto_binding', fromHopId: 'sf-c3-h3', toHopId: 'sf-c3-h4', sourceCapabilityId: tokenCap.handle, alg: 'sha256' },
  ],
  terminalImpact: {
    terminalHopId: 'sf-c3-h4',
    summary: 'A delivery-log token exfiltrated foreign tenant metadata through the public registry relay.',
    terminalExchangeId: h4.exchangeId,
    preChainControlExchangeIds: [],
  },
  replayMode: 'fresh_clean_replay',
})
`, config)

    case 'SF-C4': return withConfig(String.raw`
const member = await login('member_a')
const viewer = await login('viewer_a')
if (!member || !viewer) return ctx.result({ title })
const h1 = await send('api', \`\${cfg.routePrefix}/automations\`, {
  ...bearer(member, 'member_a'),
  method: 'POST',
  body: { projectId: cfg.ids.projectIdA, name: 'nightly-release', schedule: 'on-dispute' },
})
if (h1.status !== 201) return ctx.result({ title })
const automationId = String(h1.json.automation.id)
const automationCap = await seal(h1, 'sf-c4-h1', 'automation_id', { jsonPath: '$.automation.id' })
const releasePath = \`\${cfg.routePrefix}/deployments/\${cfg.ids.deploymentAutoId}/release\`
const workerAblation = await send('api', releasePath, {
  as: 'member_a',
  method: 'POST',
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: cfg.ids.deploymentAutoId,
  body: { version: '2026.11.1' },
})
const terminalControl = await send('api', releasePath, {
  ...bearer(viewer, 'viewer_a'),
  method: 'POST',
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: cfg.ids.deploymentAutoId,
  body: { version: '2026.11.1' },
})
const ablation = await send('api', releasePath, {
  ...bearer(member, 'member_a'),
  method: 'POST',
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: cfg.ids.deploymentAutoId,
  body: { version: '2026.11.1' },
})
const h2 = await send('api', \`\${cfg.routePrefix}/deployments/\${cfg.ids.deploymentAutoId}/dispute\`, {
  ...bearer(member, 'member_a'),
  method: 'POST',
  body: { automationId: automationCap.handle },
  entityId: cfg.ids.deploymentAutoId,
})
if (h2.status !== 200) return ctx.result({ title })
const h3 = await send('api', releasePath, {
  ...bearer(member, 'member_a'),
  method: 'POST',
  entityId: cfg.ids.deploymentAutoId,
  body: { version: '2026.11.1' },
})
return await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('sf-c4-h1', 'api', 'POST', \`\${cfg.routePrefix}/automations\`, h1, 'Team automation inherited release administration.', { producedCapabilities: [automationCap.handle] }),
    hop('sf-c4-h2', 'api', 'POST', \`\${cfg.routePrefix}/deployments/\${cfg.ids.deploymentAutoId}/dispute\`, h2, 'Dispute retained the inherited release schedule.', { consumedCapabilities: [automationCap.handle], entityId: cfg.ids.deploymentAutoId }),
    hop('sf-c4-h3', 'api', 'POST', releasePath, h3, 'Scheduled automation released production without approval.', { entityId: cfg.ids.deploymentAutoId }),
  ],
  causalEdges: [
    { kind: 'value_binding', fromHopId: 'sf-c4-h1', toHopId: 'sf-c4-h2', capabilityHandle: automationCap.handle },
    { kind: 'state_transition_binding', fromHopId: 'sf-c4-h2', toHopId: 'sf-c4-h3', entityId: cfg.ids.deploymentAutoId, ablationExchangeIds: [workerAblation.exchangeId], mutationKind: 'deployment_dispute' },
  ],
  terminalImpact: {
    terminalHopId: 'sf-c4-h3',
    summary: 'An inherited automation schedule bypassed production release approval.',
    terminalExchangeId: h3.exchangeId,
    preChainControlExchangeIds: [terminalControl.exchangeId],
  },
  replayMode: 'fresh_clean_replay',
})
`, config)

    case 'NX-C1': return withConfig(String.raw`
const member = await login('member_a')
if (!member) return ctx.result({ title })
const h1 = await send('api', \`\${cfg.routePrefix}/comments\`, {
  ...bearer(member, 'member_a'),
  method: 'POST',
  body: { subject: 'Release notes', body: '<p data-widget="memo">shared workspace update</p>' },
})
if (h1.status !== 201) return ctx.result({ title })
const commentId = String(h1.json.comment.id)
const commentCap = await seal(h1, 'nx-c1-h1', 'comment_id', { jsonPath: '$.comment.id' })
const inboxPath = \`\${cfg.routePrefix}/inbox/\${commentCap.handle}\`
const h2 = await send('app', inboxPath, bearer(member, 'member_a'))
if (h2.status !== 200 || !h2.json.token) return ctx.result({ title })
const h2TokenCap = await seal(h2, 'nx-c1-h2', 'moderation_token', { jsonPath: '$.token' }, 'api_token')
const h3 = await send('app', inboxPath, {
  ...bearer(member, 'member_a'),
  headers: { 'x-kovo-value': h2TokenCap.handle },
})
if (h3.status !== 200 || !h3.json.token) return ctx.result({ title })
const scimCap = await seal(h3, 'nx-c1-h3', 'scim_token', { jsonPath: '$.token' }, 'api_token')
const vaultPath = \`\${cfg.routePrefix}/audit/vault?tenant=\${encodeURIComponent(cfg.tenantA)}\`
const control = await send('api', vaultPath, {
  ...bearer(member, 'member_a'),
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: cfg.memberUserId,
})
const h4 = await send('api', \`\${cfg.routePrefix}/scim/users/\${cfg.memberUserId}\`, {
  ...headerCap(scimCap, 'x-scim-token'),
  method: 'PATCH',
  body: { role: 'owner', tenant: cfg.tenantA },
  entityId: cfg.memberUserId,
})
if (h4.status !== 200) return ctx.result({ title })
const h5 = await send('api', vaultPath, {
  capability: { handle: member.handle, target: 'bearer' },
  headers: { 'x-kovo-value': scimCap.handle },
  entityId: cfg.memberUserId,
})
const result = await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('nx-c1-h1', 'api', 'POST', \`\${cfg.routePrefix}/comments\`, h1, 'Comment entered the moderation pipeline.', { producedCapabilities: [commentCap.handle] }),
    hop('nx-c1-h2', 'app', 'GET', inboxPath, h2, 'Moderation material exposed a bot-origin token.', { consumedCapabilities: [commentCap.handle], producedCapabilities: [h2TokenCap.handle] }),
    hop('nx-c1-h3', 'app', 'GET', inboxPath, h3, 'Bot-origin SCIM token was recovered for provisioning.', { consumedCapabilities: [h2TokenCap.handle], producedCapabilities: [scimCap.handle] }),
    hop('nx-c1-h4', 'api', 'PATCH', \`\${cfg.routePrefix}/scim/users/\${cfg.memberUserId}\`, h4, 'Bot token promoted the member to owner.', { consumedCapabilities: [scimCap.handle], entityId: cfg.memberUserId }),
    hop('nx-c1-h5', 'api', 'GET', vaultPath, h5, 'Promoted member read the audit vault.', { entityId: cfg.memberUserId }),
  ],
  causalEdges: [
    { kind: 'value_binding', fromHopId: 'nx-c1-h1', toHopId: 'nx-c1-h2', capabilityHandle: commentCap.handle },
    { kind: 'value_binding', fromHopId: 'nx-c1-h2', toHopId: 'nx-c1-h3', capabilityHandle: h2TokenCap.handle },
    { kind: 'value_binding', fromHopId: 'nx-c1-h3', toHopId: 'nx-c1-h4', capabilityHandle: scimCap.handle },
    { kind: 'state_transition_binding', fromHopId: 'nx-c1-h4', toHopId: 'nx-c1-h5', entityId: cfg.memberUserId, ablationExchangeIds: [control.exchangeId], mutationKind: 'role_promotion' },
  ],
  terminalImpact: {
    terminalHopId: 'nx-c1-h5',
    summary: 'A moderation-origin SCIM token promoted a member and exposed the audit vault.',
    terminalExchangeId: h5.exchangeId,
    preChainControlExchangeIds: [control.exchangeId],
  },
  replayMode: 'fresh_clean_replay',
})
// Restore the seeded role so the second fresh RPC replay starts from the same authorization state.
if (h4.status === 200) {
  await send('api', \`\${cfg.routePrefix}/scim/users/\${cfg.memberUserId}\`, {
    ...headerCap(scimCap, 'x-scim-token'),
    method: 'PATCH',
    role: 'cleanup',
    body: { role: 'member', tenant: cfg.tenantA },
    entityId: cfg.memberUserId,
  })
}
return result
`, config)

    case 'NX-C2': return withConfig(String.raw`
const member = await login('member_b')
if (!member) return ctx.result({ title })
const nextPath = \`/s/\${cfg.nexus.shareLinkId}\`
const authorizePath = \`/authorize?client_id=nexus-desktop&redirect_uri=\${encodeURIComponent(origin('app') + nextPath)}&next=\${encodeURIComponent(nextPath)}&state=share-preview\`
const h1 = await send('idp', authorizePath, bearer(member, 'member_b'))
if (h1.status !== 200 || !h1.json.code) return ctx.result({ title })
const code = String(h1.json.code)
const codeCap = await seal(h1, 'nx-c2-h1', 'delegated_code', { jsonPath: '$.code' }, 'oidc_assertion')
const codeAssertion = await ctx.jwt_sign(codeCap.handle, { sub: 'share-preview' }, {
  hopReceiptId: 'nx-c2-h2',
  slot: 'delegated_assertion',
  allowedOrigins: Object.values(cfg.publicOrigins),
})
const h2 = await send('app', \`\${nextPath}?code=\${encodeURIComponent(codeCap.handle)}&state=share-preview\`, {
  ...bearer(member, 'member_b'),
  headers: { 'x-kovo-assertion': codeAssertion.handle },
})
if (h2.status !== 200) return ctx.result({ title })
const codeDerived = await ctx.hmac_sign(codeAssertion.handle, code)
const h3 = await send('idp', \`/invites?tenant=\${encodeURIComponent(cfg.tenantA)}\`, {
  ...bearer(member, 'member_b'),
  headers: { 'x-derived-from': createHash('sha256').update(code).digest('hex'), 'x-kovo-derivation': codeDerived.signature },
})
if (h3.status !== 200) return ctx.result({ title })
const invite = h3.json.invites?.find((item: any) => item.role === 'admin' && item.token)
if (!invite?.token) return ctx.result({ title })
const inviteCap = await seal(h3, 'nx-c2-h3', 'stale_invite', { jsonPath: '$.invites[0].token' }, 'api_token')
const inviteDerived = await ctx.hmac_sign(inviteCap.handle, String(invite.token))
const h4 = await send('idp', '/invites/redeem', {
  ...bearer(member, 'member_b'),
  method: 'POST',
  headers: { 'x-kovo-derivation': inviteDerived.signature },
  body: { token: inviteCap.handle },
})
if (h4.status !== 200 || !h4.json.token) return ctx.result({ title })
const adminCap = await seal(h4, 'nx-c2-readback', 'redeemed_session', { jsonPath: '$.token' }, 'bearer_token')
const readback = await send('api', \`\${cfg.routePrefix}/me\`, { ...bearer(adminCap), evidenceRole: 'post_chain_readback' })
return await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('nx-c2-h1', 'idp', 'GET', authorizePath, h1, 'Open redirect issued a delegated authorization code.', { producedCapabilities: [codeCap.handle] }),
    hop('nx-c2-h2', 'app', 'GET', \`\${nextPath}?code=\${encodeURIComponent(codeCap.handle)}&state=share-preview\`, h2, 'Share preview captured the delegated code.', { consumedCapabilities: [codeCap.handle] }),
    hop('nx-c2-h3', 'idp', 'GET', \`/invites?tenant=\${encodeURIComponent(cfg.tenantA)}\`, h3, 'Delegated code disclosed a stale admin invite.', { producedCapabilities: [inviteCap.handle] }),
    hop('nx-c2-h4', 'idp', 'POST', '/invites/redeem', h4, 'Stale admin invite was redeemed.', { consumedCapabilities: [inviteCap.handle] }),
  ],
  causalEdges: [
    { kind: 'value_binding', fromHopId: 'nx-c2-h1', toHopId: 'nx-c2-h2', capabilityHandle: codeCap.handle },
    { kind: 'derived_crypto_binding', fromHopId: 'nx-c2-h2', toHopId: 'nx-c2-h3', sourceCapabilityId: codeAssertion.handle, alg: 'sha256' },
    { kind: 'derived_crypto_binding', fromHopId: 'nx-c2-h3', toHopId: 'nx-c2-h4', sourceCapabilityId: inviteCap.handle, alg: 'sha256' },
  ],
  terminalImpact: {
    terminalHopId: 'nx-c2-h4',
    summary: 'A stale administrator invitation was redeemed and the resulting admin session was read back.',
    terminalExchangeId: h4.exchangeId,
    preChainControlExchangeIds: [],
    postChainReadbackExchangeIds: [readback.exchangeId],
  },
  replayMode: 'fresh_clean_replay',
})
`, config)

    case 'NX-C3': return withConfig(String.raw`
const owner = await login('owner_a')
const member = await login('member_b')
if (!owner || !member) return ctx.result({ title })
const profilePath = \`/public/profile/\${cfg.tenantA}.css\`
await send('cdn', profilePath, bearer(owner, 'owner_a'))
const h1 = await send('cdn', profilePath, bearer(member, 'member_b'))
if (h1.status !== 200 || !h1.headers['x-delegation-key']) return ctx.result({ title })
const delegationCap = await seal(h1, 'nx-c3-h1', 'delegation_key', { header: 'x-delegation-key' }, 'header_secret')
const h2 = await send('api', \`\${cfg.routePrefix}/docs\`, {
  ...bearer(member, 'member_b'),
  headers: { 'x-delegation-key': delegationCap.handle, 'x-workspace-id': '' },
})
if (h2.status !== 200) return ctx.result({ title })
const docId = String(h2.json.docs?.[0]?.id ?? '')
if (!docId) return ctx.result({ title })
const docCap = await seal(h2, 'nx-c3-h2', 'private_doc', { jsonPath: '$.docs[0].id' })
const contentPath = \`\${cfg.routePrefix}/docs/\${docCap.handle}/content\`
const control = await send('api', contentPath, {
  ...bearer(member, 'member_b'),
  role: 'control',
  replayAttempt: 'ablation_control',
  entityId: docId,
})
const h3 = await send('api', \`\${cfg.routePrefix}/docs/\${docCap.handle}\`, {
  ...bearer(member, 'member_b'),
  headers: { 'x-delegation-key': delegationCap.handle, 'x-workspace-id': '' },
  entityId: docId,
})
if (h3.status !== 200) return ctx.result({ title })
const h4 = await send('api', contentPath, {
  ...bearer(member, 'member_b'),
  headers: { 'x-delegation-key': delegationCap.handle, 'x-workspace-id': '' },
  entityId: docId,
})
return await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('nx-c3-h1', 'cdn', 'GET', profilePath, h1, 'Cross-tenant profile cache disclosed a delegation key.', { producedCapabilities: [delegationCap.handle] }),
    hop('nx-c3-h2', 'api', 'GET', \`\${cfg.routePrefix}/docs\`, h2, 'Empty workspace fallback listed a private document.', { consumedCapabilities: [delegationCap.handle], producedCapabilities: [docCap.handle] }),
    hop('nx-c3-h3', 'api', 'GET', \`\${cfg.routePrefix}/docs/\${docCap.handle}\`, h3, 'Delegation key opened private document metadata.', { consumedCapabilities: [delegationCap.handle, docCap.handle], entityId: docId }),
    hop('nx-c3-h4', 'api', 'GET', contentPath, h4, 'Private document content was read cross-tenant.', { consumedCapabilities: [delegationCap.handle, docCap.handle], entityId: docId }),
  ],
  causalEdges: [
    { kind: 'value_binding', fromHopId: 'nx-c3-h1', toHopId: 'nx-c3-h2', capabilityHandle: delegationCap.handle },
    { kind: 'value_binding', fromHopId: 'nx-c3-h2', toHopId: 'nx-c3-h3', capabilityHandle: docCap.handle },
    { kind: 'state_transition_binding', fromHopId: 'nx-c3-h3', toHopId: 'nx-c3-h4', entityId: docId, ablationExchangeIds: [control.exchangeId], mutationKind: 'private_document_open' },
  ],
  terminalImpact: {
    terminalHopId: 'nx-c3-h4',
    summary: 'A cached cross-tenant delegation key exposed private document content.',
    terminalExchangeId: h4.exchangeId,
    preChainControlExchangeIds: [control.exchangeId],
  },
  replayMode: 'fresh_clean_replay',
})
`, config)

    case 'NX-C4': return withConfig(String.raw`
const member = await login('revoked_or_demoted')
if (!member) return ctx.result({ title })
let facet: any = null
let folder = ''
for (const candidate of cfg.nexus.folderCandidates) {
  const path = \`\${cfg.routePrefix}/search/facets?tenant=\${encodeURIComponent(cfg.tenantA)}&q=\${encodeURIComponent(candidate)}\`
  const exchange = await send('api', path, bearer(member, 'revoked_or_demoted'))
  if (exchange.status === 200 && exchange.json.count > 0) { facet = exchange; folder = candidate; break }
}
if (!facet) return ctx.result({ title })
const folderCap = await seal(facet, 'nx-c4-h1', 'private_folder', { jsonPath: '$.query' })
const metadataPath = \`\${cfg.routePrefix}/docs/share/\${cfg.nexus.shareLinkId}/metadata?folder=\${encodeURIComponent(folderCap.handle)}\`
const h2 = await send('api', metadataPath, {
  capability: { handle: member.handle, target: 'bearer' },
  body: undefined,
})
if (h2.status !== 200 || !h2.json.jobId) return ctx.result({ title })
const jobId = String(h2.json.jobId)
const jobCap = await seal(h2, 'nx-c4-h2', 'export_job', { jsonPath: '$.jobId' })
const poll = await ctx.await_async({
  pollRequest: \`\${origin('api')}\${cfg.routePrefix}/exports/\${jobId}\`,
  capability: { handle: member.handle, target: 'bearer' },
  headers: { 'x-kovo-job': jobCap.handle },
  role: 'probe',
  triggerExchangeId: h2.exchangeId,
  correlationId: jobId,
  entityId: jobId,
  matchPredicate: { jsonPath: '$.job.status', equals: 'ready' },
  profile: 'fast_lab',
  timeoutMs: 5000,
  intervalMs: 10,
})
if (!poll.converged || !poll.exchange) return ctx.result({ title })
const h3 = poll.exchange
const resultPath = \`\${cfg.routePrefix}/exports/\${jobCap.handle}/result\`
const terminalControl = await send('api', resultPath, { role: 'control', replayAttempt: 'ablation_control', entityId: jobId })
const h4 = await send('api', resultPath, {
  capability: { handle: member.handle, target: 'bearer' },
  entityId: jobId,
  correlationIds: [jobId],
})
return await finish({
  chainId: cfg.chainId,
  terminalVulnClass: cfg.terminalVulnClass,
  hops: [
    hop('nx-c4-h1', 'api', 'GET', \`\${cfg.routePrefix}/search/facets?tenant=\${encodeURIComponent(cfg.tenantA)}&q=\${encodeURIComponent(folder)}\`, facet, 'Facet count oracle identified a private folder.', { producedCapabilities: [folderCap.handle] }),
    hop('nx-c4-h2', 'api', 'GET', metadataPath, h2, 'Share metadata disclosed a stale export job.', { consumedCapabilities: [folderCap.handle], producedCapabilities: [jobCap.handle], entityId: jobId }),
    hop('nx-c4-h3', 'api', 'GET', \`\${cfg.routePrefix}/exports/\${jobCap.handle}\`, h3, 'Public export relay reached ready state.', { consumedCapabilities: [jobCap.handle], entityId: jobId }),
    hop('nx-c4-h4', 'api', 'GET', resultPath, h4, 'Export result exfiltrated the private artifact.', { consumedCapabilities: [jobCap.handle], entityId: jobId }),
  ],
  causalEdges: [
    { kind: 'value_binding', fromHopId: 'nx-c4-h1', toHopId: 'nx-c4-h2', capabilityHandle: folderCap.handle },
    { kind: 'value_binding', fromHopId: 'nx-c4-h2', toHopId: 'nx-c4-h3', capabilityHandle: jobCap.handle },
    { kind: 'async_pivot_binding', fromHopId: 'nx-c4-h3', toHopId: 'nx-c4-h4', correlationId: jobId, channel: 'async_job' },
  ],
  terminalImpact: {
    terminalHopId: 'nx-c4-h4',
    summary: 'A stale export job handle exfiltrated a private tenant artifact through the public relay.',
    terminalExchangeId: h4.exchangeId,
    preChainControlExchangeIds: [terminalControl.exchangeId],
  },
  replayMode: 'fresh_clean_replay',
})
`, config)

    default: throw new Error(`no golden script for ${chainId}`)
  }
}

function workerReceipts(attempts: CapturedAttempt[]): WorkerReceipt[] {
  const receipts: WorkerReceipt[] = []
  for (const attempt of attempts) {
    const result = attempt.execution.result as { claims?: Array<Record<string, unknown>> } | null
    for (const claim of result?.claims ?? []) {
      if (claim.kind !== 'composite_receipt') continue
      const raw = claim.compositeReceipt
      if (raw && typeof raw === 'object' && !Array.isArray(raw)) receipts.push(raw as WorkerReceipt)
    }
  }
  return receipts
}

function transcriptHasSecret(attempt: CapturedAttempt, secret: string): boolean {
  if (!secret || secret.length < 4) return false
  const records = attempt.session.transcript.list()
  if (JSON.stringify(records).includes(secret)) return true
  return records.some((record) => (attempt.session.transcript.body(record.exchangeId) ?? '').includes(secret))
}

async function runGolden(
  lab: StartedLab,
  chain: ChainSpec,
  mode: LabMode,
  twin?: string,
): Promise<HarnessRun> {
  const config = scriptConfig(lab, chain)
  const origins = Object.values(config.publicOrigins)
  const personas = makePersonas(lab, config.publicOrigins, lab.app as AppId)
  const requested = new Set<string>()
  const grant = makeGrant(config.publicOrigins, personas, requested)
  const captured: CapturedAttempt[] = []
  const factory = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    timeoutMs: 30_000,
    createRpcOptions: () => ({
      broker: new RequestBroker(),
      grant,
      runId: lab.runId,
      assignmentId: `seam1-${chain.id}-${mode}-${twin ?? 'base'}`,
      targetOrigins: origins,
      compositeVerifyOptions: {
        attackerPersonas: [...chain.attackerPersonaSet],
        forbiddenShortcutPersonas: [...chain.forbiddenShortcutPersonas],
        benchmarkMode: true,
      },
    }),
  })
  const openAttempt = async (input: { attempt: 1 | 2; nonce: string }): Promise<VerifyAttemptSession> => {
    const session = await factory(input)
    const execute = session.execute.bind(session)
    session.execute = async (candidate, signal) => {
      const execution = await execute(candidate, signal)
      captured.push({ session, execution })
      return execution
    }
    return session
  }
  const started = performance.now()
  const verdict = await verifyScript({
    candidate: {
      name: `${chain.id.toLowerCase()}-golden.ts`,
      runtime: 'ts',
      code: goldenScript(chain.id, config),
      title: chain.title,
    },
    openAttempt,
    timeoutMs: 90_000,
  })
  const runtimeMs = performance.now() - started

  assert.equal(captured.length, 2, `${chain.id}: verifyScript must execute exactly two fresh attempts`)
  assert.notEqual(captured[0]!.session.nonce, captured[1]!.session.nonce)
  assert.equal(new Set(captured.map((attempt) => attempt.session.transcript)).size, 2, 'each attempt needs a fresh TranscriptStore')
  for (const attempt of captured) {
    assert.ok(attempt.session.transcript instanceof TranscriptStore)
    assert.equal(attempt.session.transcript.verifySignatures(), true, `${chain.id}: transcript signatures must verify`)
    for (const persona of personas) {
      assert.equal(transcriptHasSecret(attempt, persona.secret), false, `${chain.id}: raw persona credential leaked into transcript`)
    }
    const bodies = attempt.session.transcript.list().map((record) => attempt.session.transcript.body(record.exchangeId) ?? '').join('\n')
    assert.match(bodies, /\[redacted(?::[^\]]+)?\]/, `${chain.id}: expected host redaction in the real broker transcript`)
  }
  for (const origin of requested) assert.ok(origins.includes(origin), `${chain.id}: non-public origin requested: ${origin}`)
  assert.equal(verdict.attempts.length, 2)
  assert.ok(verdict.attempts.every((attempt) => attempt.signaturesValid))

  return { verdict, attempts: captured, workerReceipts: workerReceipts(captured), requestedOrigins: [...requested], runtimeMs }
}

function compareTwoSides(chain: ChainSpec, worker: WorkerReceipt, benchmark: BenchmarkReceipt): void {
  assert.equal(worker.chainId, chain.id, 'worker composite chainId must survive RPC scrubbing')
  assert.equal(worker.terminalVulnClass, chain.vulnClass)
  assert.equal(worker.replayMode, 'fresh_clean_replay')
  assert.ok(Array.isArray(worker.hops) && Array.isArray(worker.causalEdges))
  const workerHops = worker.hops as Array<Record<string, unknown>>
  const workerEdges = worker.causalEdges as Array<Record<string, unknown>>
  assert.deepEqual(workerHops.map((hop) => hop.hopId), benchmark.hops.map((hop) => hop.hopId))
  assert.deepEqual(workerEdges.map((edge) => edge.kind), benchmark.causalEdges.map((edge) => edge.kind))
  assert.equal((worker.terminalImpact as Record<string, unknown>).terminalHopId, chain.hops.at(-1)!.hopId)
  assert.equal(benchmark.terminalVulnClass, chain.vulnClass)
  assert.equal(benchmark.terminalImpact.kind, chain.terminal.kind)
}

function gradeChain(lab: StartedLab, chain: ChainSpec, findings: Finding[]): Scorecard {
  const expected = lab.groundTruth.expectedChains.find((item) => item.chainId === chain.id)
  const groundTruth: GroundTruth = {
    ...lab.groundTruth,
    expectedChains: expected ? [expected] : [],
  }
  return gradeRun({ groundTruth, findings, oracle: lab.export() })
}

function exactKnownGap(
  chainId: string,
  run: HarnessRun,
  oracle: OracleExport,
): { id: string; reason: string } | null {
  const releases = run.attempts.flatMap((attempt) => attempt.session.transcript.list().filter((record) =>
    record.request?.method === 'POST' && /\/deployments\/[^/]+\/release$/.test(record.request?.pathAndQuery ?? '')))
  if (chainId === 'SF-C1' && !run.verdict.confirmed && releases.length >= 2) {
    const statuses = releases.slice(0, 2).map((record) => record.response?.status ?? null)
    const exact = statuses[0] === 200 && statuses[1] === 403
      && run.verdict.attempts.every((attempt) => attempt.claimCount >= 1)
      && run.verdict.rejectedBy === 'terminal_impact_unproven'
    if (exact) {
      return { id: 'sf_c1_run2_secret_rotation', reason: 'run_1_release_200_run_2_release_403_terminal_impact_unproven' }
    }
  }
  if (chainId === 'NX-C4') {
    const evaluation = oracle.evaluations.find((item) => item.chainId === chainId)
    const terminal = run.attempts.at(-1)?.session.transcript.list().find((record) =>
      record.request?.method === 'GET' && /\/exports\/[^/]+\/result$/.test(record.request?.pathAndQuery ?? ''))
    const exact = Boolean(terminal?.response?.status === 200)
      && Boolean(evaluation && !evaluation.completed && evaluation.missingHopIds.includes('nx-c4-h4'))
      && /terminal.*not observed/i.test(evaluation?.failureReason ?? '')
    if (exact) return { id: 'nx_c4_export_result_lineage', reason: 'export_result_200_but_nx_c4_h4_terminal_not_observed' }
  }
  for (const receipt of run.workerReceipts) {
    if (receipt.chainId === 'invalid' && run.verdict.rejectedBy === 'schema') {
      return { id: 'verify_rpc_chain_id_scrubbing', reason: 'worker_receipt_chain_id_scrubbed_to_invalid_schema_rejection' }
    }
  }
  if (/cross_surface_pivot.*correlationToken|correlationToken.*cross_surface_pivot/i.test(
    `${run.verdict.detail} ${run.verdict.missingEvidence.join(' ')}`,
  )) {
    return { id: 'composite_cross_surface_pivot_source_hop_correlation_token', reason: 'cross_surface_pivot_source_hop_correlationToken_rejected' }
  }
  return null
}

// Exact, narrow exceptions for the four documented unmerged fixes. Nothing else is swallowed.
const KNOWN_UNMERGED_GAPS = {
  'SF-C1': ['sf_c1_run2_secret_rotation'],
  'NX-C4': ['nx_c4_export_result_lineage'],
  '*': ['verify_rpc_chain_id_scrubbing', 'composite_cross_surface_pivot_source_hop_correlation_token'],
} as const

function assertKnownGapAllowed(chainId: string, id: string): void {
  const allowed = chainId === '*'
    ? KNOWN_UNMERGED_GAPS['*']
    : [...KNOWN_UNMERGED_GAPS['*'], ...(KNOWN_UNMERGED_GAPS[chainId as keyof typeof KNOWN_UNMERGED_GAPS] ?? [])]
  assert.ok((allowed as readonly string[]).includes(id), `unexpected failure is not a known unmerged gap: ${chainId}/${id}`)
}

function structuredFailure(run: HarnessRun, oracle: OracleExport): Record<string, unknown> {
  const bodyFacts = run.attempts.map((captured) => captured.session.transcript.list().flatMap((record) => {
    const raw = captured.session.transcript.body(record.exchangeId)
    if (!raw) return []
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>
      const job = parsed.job as Record<string, unknown> | undefined
      return [{
        exchangeId: record.exchangeId,
        ...(typeof job?.status === 'string' ? { jobStatus: job.status } : {}),
        ...(typeof parsed.count === 'number' ? { count: parsed.count } : {}),
        ...(typeof parsed.scoped === 'boolean' ? { scoped: parsed.scoped } : {}),
      }]
    } catch { return [] }
  }))
  return {
    reason: run.verdict.reason,
    detail: run.verdict.detail,
    rejectedBy: run.verdict.rejectedBy,
    missingEvidence: run.verdict.missingEvidence,
    bodyFacts,
    attempts: run.verdict.attempts.map((attempt) => ({
      attempt: attempt.attempt,
      exitCode: attempt.exitCode,
      oraclePassed: attempt.oraclePassed,
      claimCount: attempt.claimCount,
      exchangeCount: attempt.exchangeCount,
      rejectedBy: attempt.rejectedBy,
      missingEvidence: attempt.missingEvidence,
    })),
    transcripts: run.attempts.map((captured) => captured.session.transcript.list().map((record) => ({
      op: record.op,
      method: record.request?.method ?? null,
      pathAndQuery: record.request?.pathAndQuery ?? null,
      status: record.response?.status ?? null,
      role: record.request?.sessionRole ?? null,
      errorCode: record.errorCode ?? null,
    }))),
    oracle: oracle.evaluations.map((evaluation) => ({
      chainId: evaluation.chainId,
      completed: evaluation.completed,
      confirmed: evaluation.confirmed,
      missingHopIds: evaluation.missingHopIds,
      failureReason: evaluation.failureReason,
      dropReason: evaluation.dropReason,
    })),
  }
}

for (const app of ['paygrid', 'shipforge', 'nexusiam'] as const) {
  for (const chain of APP_DEFS[app].chains) {
    test(`${chain.id}: golden worker dual-replay + ChainOracle + Two-Side Grader; hardened/twins silent`, async (t) => {
      const outcomes: ChainOutcome[] = []
      for (const options of [
        { mode: 'vulnerable' as const, twin: undefined },
        { mode: 'hardened' as const, twin: undefined },
        ...APP_DEFS[app].twins.map((twin) => ({ mode: 'vulnerable' as const, twin: twin.id })),
      ]) {
        const lab = await sharedLab(app, options.mode, options.twin)
        const run = await runGolden(lab, chain, options.mode, options.twin)
        let oracle = lab.export()
        let terminals = oracle.events.terminals.filter((terminal) => terminal.chainId === chain.id).length
        let confirmations = oracle.confirmed.filter((confirmed) => confirmed.chainId === chain.id).length
        const findings: Finding[] = []
        let gap: string | null = null

        if (run.verdict.confirmed) {
          assert.equal(run.workerReceipts.length, 2, `${chain.id}: both attempts must expose the host-backed composite receipt`)
          for (const worker of run.workerReceipts) assert.equal(worker.chainId, chain.id)
          const evaluation = oracle.evaluations.find((item) => item.chainId === chain.id)
          assert.ok(evaluation, `${chain.id}: app oracle evaluation missing`)
          if (options.mode !== 'vulnerable' || options.twin) {
            assert.fail(`${chain.id}: hardened/twin worker false positive: ${JSON.stringify(structuredFailure(run, oracle))}`)
          }
          if (!evaluation.completed) {
            const known = exactKnownGap(chain.id, run, oracle)
            if (known) {
              assertKnownGapAllowed(chain.id, known.id)
              gap = `${known.id}:${known.reason}`
            } else {
              assert.equal(evaluation.completed, true, `${chain.id}: worker confirmed but app ChainOracle did not complete: ${JSON.stringify(structuredFailure(run, oracle))}`)
            }
          }
          if (!gap) {
            const benchmarkReceipt = lab.oracle.mintReceipt(chain.id)
            oracle = lab.export()
            terminals = oracle.events.terminals.filter((terminal) => terminal.chainId === chain.id).length
            confirmations = oracle.confirmed.filter((confirmed) => confirmed.chainId === chain.id).length
            for (const worker of run.workerReceipts) compareTwoSides(chain, worker, benchmarkReceipt)
            findings.push({ chainId: chain.id, terminalVulnClass: chain.vulnClass, receipt: benchmarkReceipt, reportedBy: 'seam1-golden-e2e' })
          }
        } else if (options.mode === 'vulnerable' && !options.twin) {
          const known = exactKnownGap(chain.id, run, oracle)
          if (known) {
            assertKnownGapAllowed(chain.id, known.id)
            gap = `${known.id}:${known.reason}`
          } else {
            assert.fail(`${chain.id}: vulnerable golden chain failed unexpectedly: ${JSON.stringify(structuredFailure(run, oracle))}`)
          }
        }

        const card = gradeChain(lab, chain, findings)
        if (options.mode === 'vulnerable' && !options.twin) {
          if (gap) {
            assert.equal(confirmations, 0, `${chain.id}: known gap must not manufacture a ChainOracle confirmation`)
            assert.equal(card.fp, 0, `${chain.id}: known gap must not create a decoy false positive`)
          } else {
            assert.equal(card.tp, 1, `${chain.id}: Two-Side Grader must count one true positive`)
            assert.equal(card.fp, 0)
            assert.equal(card.fn, 0)
            assert.equal(card.gate.pass, true)
            assert.equal(confirmations, 1)
            assert.ok(terminals >= 1, `${chain.id}: vulnerable replay must observe terminal impact`)
          }
        } else {
          assert.equal(run.verdict.confirmed, false, `${chain.id}: ${options.twin ?? options.mode} must stay worker-silent`)
          assert.equal(terminals, 0, `${chain.id}: ${options.twin ?? options.mode} must stay terminal-silent`)
          assert.equal(confirmations, 0)
          assert.equal(card.fp, 0, `${chain.id}: decoy false positive`)
          assert.equal(card.strictDecoyFps, 0)
          assert.equal(card.gate.pass, true)
        }

        outcomes.push({
          chainId: chain.id,
          app,
          mode: options.mode,
          twin: options.twin ?? null,
          workerConfirmed: run.verdict.confirmed,
          workerReason: run.verdict.reason,
          workerRejectedBy: run.verdict.rejectedBy,
          oracleCompleted: oracle.evaluations.find((item) => item.chainId === chain.id)?.completed ?? false,
          oracleConfirmed: confirmations > 0,
          terminals,
          confirmations,
          decoyFps: card.strictDecoyFps,
          gradePass: card.gate.pass,
          runtimeMs: Math.round(run.runtimeMs),
          gap,
        })
      }
      t.diagnostic(JSON.stringify({ chainId: chain.id, outcomes }))
    })
  }
}
