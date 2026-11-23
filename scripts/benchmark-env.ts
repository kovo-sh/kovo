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
  /** Loopback port(s) the target app was told to allow for out-of-band callbacks. */
  oobCallbackPorts: number[]
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

export interface EngineEnvOptions {
  /** Initial blind-SQLi allowance; the live pipeline recomputes it once hypotheses are known. */
  slowProbes?: number
  /**
   * Reuse an already-running CanaryBroker (started before the target app so its loopback port could
   * be passed to the app's egress allowlist). The caller keeps ownership: createEngineEnv will not
   * stop it during cleanup.
   */
  canaryBroker?: CanaryBroker
  /**
   * Exact loopback ports the started app permits for out-of-band callbacks. When a broker is
   * supplied (or created) its HTTP listener port must be one of these so probes and the app agree
   * on a single reachable callback endpoint.
   */
  oobCallbackPorts?: number[]
}

/**
 * Validate the OOB port wiring shared by the graded harness and the app:
 * a running listener must expose exactly a port the app's egress allowlist was given.
 */
export function resolveOobCallbackPorts(
  canaryBroker: CanaryBroker,
  oobCallbackPorts: number[] | undefined,
): number[] {
  const listener = canaryBroker.listenerInfo()
  const listenerPort = listener.running ? listener.port : null
  const allowed = [...new Set(oobCallbackPorts ?? (listenerPort != null ? [listenerPort] : []))]
  for (const port of allowed) {
    if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
      throw new Error(`oobCallbackPorts must be exact loopback ports (got ${port})`)
    }
  }
  if (listenerPort != null && !allowed.includes(listenerPort)) {
    throw new Error(
      `canary listener port ${listenerPort} is not in oobCallbackPorts [${allowed.join(', ')}]; `
      + 'the target app would block the callback',
    )
  }
  return allowed
}

export async function createEngineEnv(handle: BenchmarkServerHandle, caps: ProfileCaps, assignmentLabel: string, opts: EngineEnvOptions = {}): Promise<EngineEnv> {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-bench-run-'))
  const storage = new Store(dir)
  const origin = new URL(handle.origin).origin
  const project = storage.createProject({
    requestId: randomUUID(), name: `benchmark-${assignmentLabel}-${randomUUID().slice(0, 6)}`, seeds: [origin], environment: 'local-lab',
  } as unknown as Parameters<Store['createProject']>[0])

  const personaMap = new Map<string, ResolvedPersona>()
  const personaIds: string[] = []
  const userIds: string[] = []
  const userIdByHandle = new Map<string, string>()
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
    if (rec.userId) {
      userIds.push(rec.userId)
      userIdByHandle.set(h, rec.userId)
    }
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

  const canaryBroker = opts.canaryBroker ?? new CanaryBroker({ storage })
  const ownsCanaryBroker = !opts.canaryBroker
  if (!canaryBroker.listenerInfo().running) {
    // If the caller already told the app to allow one exact port, bind the listener there so both
    // sides agree. Otherwise let the OS pick a free loopback port.
    const explicitPort = opts.oobCallbackPorts?.length === 1 ? opts.oobCallbackPorts[0] : undefined
    await canaryBroker.startListener({ host: '127.0.0.1', ...(explicitPort ? { port: explicitPort } : {}) })
  }
  const oobCallbackPorts = resolveOobCallbackPorts(canaryBroker, opts.oobCallbackPorts)
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
  const viewer = pick('viewer')
  const admin = pick('admin')
  const probeEnv: ProbeEnv = {
    origin, broker, grant, canaryBroker, storage, runId: run.id, signal: controller.signal, caps,
    owner, other, admin, viewer, jwtPersona, personaUserIds: userIds, session: 'bench',
    // Adaptive budget: enough slow probes to cover every plausible blind-SQLi parameter class while
    // still bounding wall-clock (each hit costs ~3 interleaved delay rounds). The live pipeline
    // recomputes this from the formed plan and the M7 orchestration config.
    slowProbesLeft: opts.slowProbes ?? 20,
    ...(owner && userIdByHandle.get(owner) ? { ownerUserId: userIdByHandle.get(owner)! } : {}),
    ...(other && userIdByHandle.get(other) ? { otherUserId: userIdByHandle.get(other)! } : {}),
    ...(viewer && userIdByHandle.get(viewer) ? { viewerUserId: userIdByHandle.get(viewer)! } : {}),
    ...(admin && userIdByHandle.get(admin) ? { adminUserId: userIdByHandle.get(admin)! } : {}),
  }
  return {
    storage, broker, canaryBroker, grant, runId: run.id, scopeRevision, oobCallbackPorts, probeEnv, controller, requestsUsed: () => used,
    cleanup: async () => {
      controller.abort()
      if (ownsCanaryBroker) {
        try { await canaryBroker.stop() } catch { /* best effort */ }
      }
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
    const endpoints = rows.map(r => ({
      method: r.method.toUpperCase(),
      path: r.pathTemplate,
      source: r.source,
      params: params.filter(p => p.endpointId === r.id).map(p => ({ name: p.name, location: p.location, isObjectId: p.isObjectId, isCsrf: p.isCsrf })),
    }))
    probeEnv.endpoints = endpoints
    return endpoints
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
