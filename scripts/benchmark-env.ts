/**
 * Engine environment for live benchmark runs: a throwaway Store, an approved run, personas,
 * a loopback-scoped Grant, the real RequestBroker and a loopback CanaryBroker.
 */
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { RequestBroker } from '../src/server/broker.ts'
import type { BrokerExchangeResult, Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { runPhase0Recon } from '../src/server/phase0-recon.ts'
import { probeSurface } from '../src/server/surface-engine.ts'
import { buildCorpus } from './benchmark-corpus.ts'
import { Store } from '../src/server/store.ts'
import type { BenchmarkServerHandle } from './benchmark-recall.ts'
import type { DiscoveredEndpoint, ProbeEnv, ProfileCaps } from './benchmark-probes.ts'

export interface EngineEnv {
  storage: Store
  broker: RequestBroker
  canaryBroker: CanaryBroker
  grant: Grant
  runId: string
  scopeRevision: number
  probeEnv: ProbeEnv
  controller: AbortController
  requestsUsed: () => number
  cleanup: () => Promise<void>
}

type PersonaRecord = BenchmarkServerHandle['personas'][string]

const handleOf = (name: string) => name.toLowerCase().replace(/[^a-z0-9_-]/g, '_').slice(0, 40)

function personaSpec(rec: PersonaRecord): { authKind: 'bearer' | 'header' | 'cookie'; headerName?: string; secret: string } | null {
  if (rec.token) {
    const header = rec.headerName ?? 'Authorization'
    if (header.toLowerCase() === 'authorization') {
      return { authKind: 'bearer', secret: rec.token.replace(/^Bearer\s+/i, '') }
    }
    if (header.toLowerCase() === 'cookie') return { authKind: 'cookie', secret: rec.token }
    return { authKind: 'header', headerName: header, secret: rec.token }
  }
  if (rec.jwt) return { authKind: 'bearer', secret: rec.jwt }
  if (rec.cookie) return { authKind: 'cookie', secret: rec.cookie }
  return null
}

export async function createEngineEnv(handle: BenchmarkServerHandle, caps: ProfileCaps, assignmentLabel: string): Promise<EngineEnv> {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-bench-run-'))
  const storage = new Store(dir)
  const origin = new URL(handle.origin).origin
  const project = storage.createProject({
    requestId: randomUUID(), name: `benchmark-${assignmentLabel}-${randomUUID().slice(0, 6)}`, seeds: [origin], environment: 'local-lab',
  } as unknown as Parameters<Store['createProject']>[0])

  const personaMap = new Map<string, ResolvedPersona>()
  const personaIds: string[] = []
  const userIds: string[] = []
  let jwtPersona: string | undefined
  for (const [name, rec] of Object.entries(handle.personas)) {
    const spec = personaSpec(rec)
    if (!spec) continue
    const h = handleOf(name)
    const created = createProjectPersona(storage, {
      requestId: randomUUID(), projectId: project.id, handle: h, roleLabel: rec.role ?? name, originAllowlist: [origin],
      authKind: spec.authKind, ...(spec.headerName ? { headerName: spec.headerName } : {}), secret: spec.secret, canaryMarkers: [],
    } as unknown as Parameters<typeof createProjectPersona>[1])
    personaIds.push(created.id)
    personaMap.set(h, {
      id: created.id, handle: h, roleLabel: rec.role ?? name, originAllowlist: [origin], authKind: spec.authKind,
      headerName: spec.headerName ?? null, secret: spec.secret, canaryMarkers: [],
    })
    if (rec.userId) userIds.push(rec.userId)
    if (!jwtPersona && spec.secret.split('.').length === 3 && spec.secret.startsWith('eyJ')) jwtPersona = h
  }

  const budgetRequests = 4000
  const run = storage.createRun({
    requestId: randomUUID(), projectId: project.id, goal: 'Recall benchmark: discover and verify surface', sourceMode: 'public',
    capabilityTier: caps.tier, approvalPolicy: 'auto_review', approvedPersonaIds: personaIds, budgetUsd: 25, budgetRequests,
    maxRpsPerOrigin: 20, workerConcurrency: 4, workerMaxTurns: 40, multiTrialEnabled: true,
  } as unknown as Parameters<Store['createRun']>[0])
  storage.command({ requestId: randomUUID(), runId: run.id, action: 'discover', consent: true })
  const assetIds = storage.runDetail(run.id).run.candidates.map(c => c.id)
  storage.command({
    requestId: randomUUID(), runId: run.id, action: 'scope', expectedScopeRevision: 0, assetIds, consent: true, approvedPersonaIds: personaIds,
  } as unknown as Parameters<Store['command']>[0])
  const scopeRevision = storage.runDetail(run.id).run.scopeRevision

  const canaryBroker = new CanaryBroker({ storage })
  await canaryBroker.startLocalListener()
  // The lab servers intentionally answer SQL-error probes with 5xx; keep the production circuit breaker
  // from tripping on that expected noise (loopback lab only, never applied to public targets).
  const broker = new RequestBroker({ source: 'fixture response', storage, canaryBroker, circuit5xxThreshold: 500, circuit429Threshold: 500 })
  let used = 0
  const stateChangesAllowed = caps.tier >= 3
  const grant: Grant = {
    origin, tier: caps.tier, maxRpsPerOrigin: 20, allowLocalLab: true, personas: personaMap, scopeRevision, storage, canaryBroker,
    canRead: o => o === origin,
    isIdempotentPostAllowed: () => true,
    isStateChangeApproved: () => stateChangesAllowed,
    audit: outcome => { if (outcome === 'allowed' || outcome === 'observed') used += 1 },
  }
  const controller = new AbortController()
  const handles = [...personaMap.keys()]
  const pick = (...names: string[]) => names.find(n => personaMap.has(n))
  const owner = pick('persona_a', 'user', 'alice') ?? handles[0]
  const other = pick('persona_b', 'bob') ?? handles.find(n => n !== owner)
  const probeEnv: ProbeEnv = {
    origin, broker, grant, canaryBroker, storage, runId: run.id, signal: controller.signal, caps,
    owner, other, admin: pick('admin'), viewer: pick('viewer'), jwtPersona, personaUserIds: userIds, session: 'bench',
    slowProbesLeft: 12,
  }
  return {
    storage, broker, canaryBroker, grant, runId: run.id, scopeRevision, probeEnv, controller, requestsUsed: () => used,
    cleanup: async () => {
      controller.abort()
      try { await canaryBroker.stop() } catch { /* best effort */ }
      try { storage.close() } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true })
    },
  }
}

/** Phase-0 recon (v4) or wordlist path/param probing (v3 baseline) -> discovered endpoints. */
export async function discoverEndpoints(env: EngineEnv, caps: ProfileCaps, onExchange: (ex: BrokerExchangeResult) => void): Promise<DiscoveredEndpoint[]> {
  const { probeEnv } = env
  if (caps.phase0Recon) {
    probeEnv.corpus = await buildCorpus(env.broker, env.grant, probeEnv.origin, env.controller.signal, [undefined, probeEnv.owner])
    await runPhase0Recon({
      storage: env.storage, runId: env.runId, scopeRevision: env.scopeRevision, tier: caps.tier, origins: [probeEnv.origin],
      budgetRequests: 900, broker: env.broker, canaryBroker: env.canaryBroker, grant: env.grant, signal: env.controller.signal,
      personas: [probeEnv.owner, probeEnv.other].filter((p): p is string => Boolean(p)), onExchange: ex => { onExchange(ex) },
    })
    const rows = env.storage.listEndpoints(env.runId)
    const params = env.storage.listEndpointParams(env.runId)
    return rows.map(r => ({
      method: r.method.toUpperCase(),
      path: r.pathTemplate,
      source: r.source,
      params: params.filter(p => p.endpointId === r.id).map(p => ({ name: p.name, location: p.location, isObjectId: p.isObjectId, isCsrf: p.isCsrf })),
    }))
  }
  const paths = await probeSurface(
    { origin: probeEnv.origin, mode: 'paths', persona: probeEnv.owner, maxRequests: 150, onExchange: ex => { onExchange(ex) } },
    env.broker, env.grant, env.controller.signal,
  )
  const found = [...new Set(paths.anomalies.filter(a => a.kind === 'path').map(a => a.path))].slice(0, 40)
  const out: DiscoveredEndpoint[] = []
  for (const path of found) {
    const res = await probeSurface(
      { origin: probeEnv.origin, mode: 'params', basePath: path, paramLocation: 'query', persona: probeEnv.owner, maxRequests: 60, onExchange: ex => { onExchange(ex) } },
      env.broker, env.grant, env.controller.signal,
    ).catch(() => null)
    const names = [...new Set((res?.anomalies ?? []).filter(a => a.kind === 'param').map(a => String(a.path)))]
    out.push({ method: 'GET', path, source: 'surface_probe', params: names.map(name => ({ name, location: 'query', isObjectId: false, isCsrf: false })) })
  }
  return out
}
