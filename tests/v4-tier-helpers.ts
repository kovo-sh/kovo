import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHash, createHmac, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import type { TestContext } from 'node:test'
import type { Duplex } from 'node:stream'
import { setTimeout as delay } from 'node:timers/promises'
import { pathToFileURL } from 'node:url'
import { promisify } from 'node:util'
import type { ApprovedEndpointPattern, CapabilityTier, LabConfig, VerificationTier } from '../src/domain.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RawHttpResponse } from '../src/server/broker.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'
import { workerProcessSessionId } from '../src/server/worker-backend.ts'

export const execFileAsync = promisify(execFile)
export const repoRoot = resolve(new URL('..', import.meta.url).pathname)
export const RAW_STRIPE_SECRET = 'sk_live_TESTFIXTURE000000000000000000'
export const RAW_AWS_SECRET = 'AKIAIOSFODNN7EXAMPLE'
export const RAW_JWT_SECRET = 'super-secret-guardian-v4-hs256-signing-key-9988'

// ============================================================================
// Dynamic v4 Module & Contract Bridges (TS-safe before & after M1-M6 land)
// ============================================================================

export async function loadV4Module<T = Record<string, unknown>>(relPathFromRepoRoot: string): Promise<T> {
  const abs = resolve(repoRoot, relPathFromRepoRoot)
  assert.ok(
    existsSync(abs),
    `Expected Guardian v4 module "${relPathFromRepoRoot}" to exist at ${abs}`,
  )
  return await import(pathToFileURL(abs).href) as T
}

export function requireExport<T>(mod: Record<string, unknown>, exportName: string, moduleName: string): T {
  const val = mod[exportName]
  assert.notEqual(val, undefined, `Expected v4 export "${exportName}" on ${moduleName}`)
  return val as T
}

export function requireMethod<T extends (...args: never[]) => unknown>(
  target: unknown,
  methodName: string,
  targetLabel: string,
): T {
  assert.ok(target && typeof target === 'object', `${targetLabel} must be an object`)
  const fn = (target as Record<string, unknown>)[methodName]
  assert.equal(typeof fn, 'function', `Expected v4 method "${targetLabel}.${methodName}()" to be implemented`)
  return (fn as Function).bind(target) as T
}

// ============================================================================
// Structural v4 Interface Contracts (mirrors PROJECT.md & SPEC-v4.md)
// ============================================================================

export type RoleAffinity = 'reasoning' | 'tactical' | 'fast' | 'any'

export interface InlineVerifyFeedback {
  verdict: 'confirmed' | 'static_verified' | 'dismissed' | 'inconclusive'
  verificationTier?: VerificationTier
  failedStepId?: string
  controlPassed: boolean
  requireControlNonErrorTriggered?: boolean
  spaCatchallMatched?: boolean
  spaSimilarityScore?: number
  canaryTriggered?: boolean
  jqError?: string
  assertionSummary?: { observed: string; expected: string; reason?: string }
  stepStatuses: Array<{ id: string; role: string; status: number | null; mediaType?: string; bodyLen: number }>
  retriesRemaining: number
}

export interface V4AuthMutation {
  kind:
    | 'alg_none'
    | 'strip_signature'
    | 'expired_replay'
    | 'rs256_to_hs256_jwks'
    | 'kid_inject'
    | 'jku_x5u_canary'
    | 'claim_swap'
  skewSeconds?: number
  jwksUrl?: string
  value?: string
  header?: 'jku' | 'x5u'
  claims?: Record<string, string | number | boolean>
}

export type V4CsrfBind =
  | boolean
  | { headerName?: string; fieldName?: string; cookieName?: string }

export interface V4BrokerHttpRequest extends Omit<
  BrokerHttpRequest,
  'session' | 'csrfBind' | 'authMutation' | 'traceId' | 'probeClass' | 'runId' | 'assignmentId'
> {
  session?: string
  csrfBind?: V4CsrfBind
  authMutation?: V4AuthMutation
  traceId?: string
  probeClass?: string
  runId?: string
  assignmentId?: string
}

export function asBrokerRequest(req: V4BrokerHttpRequest): BrokerHttpRequest {
  return req as unknown as BrokerHttpRequest
}

export interface V4Grant extends Grant {
  sandboxWriteAllowlist?: ApprovedEndpointPattern[]
  scopeRevision?: number
}

export interface V4BrokerContract {
  executeHttp(req: V4BrokerHttpRequest, grant: V4Grant, signal: AbortSignal): Promise<BrokerExchangeResult>
  revokeOrigin?(origin: string, scopeRevision?: number): void
  purgeSessionJars?(runId?: string, origin?: string): void
}

export interface V4BrowserSessionStep {
  id: string
  role: 'setup' | 'control' | 'probe' | 'cleanup'
  description: string
  origin: string
  pathAndQuery?: string
  persona?: string
  action?: string
  selector?: string
  value?: string
  builtinCheck?: string
  urlPattern?: string
  enableSinkHook?: boolean
  reusePage?: boolean
  resetContext?: boolean
  waitAfterLoadMs?: number
}

export interface V4ScopedBrowserContract {
  runBrowserSession(
    steps: readonly V4BrowserSessionStep[],
    grant: Grant,
    signal: AbortSignal,
  ): Promise<Array<Record<string, unknown>>>
}

export interface V4StoreContract {
  initV4Schema(): void
  upsertEndpoint(input: {
    runId: string
    scopeRevision: number
    origin: string
    method: string
    pathTemplate: string
    source: 'spa_crawl' | 'js_ast' | 'openapi' | 'graphql' | 'repo_ast' | 'surface_probe'
    framework?: string | null
    authRequirement?: string | null
    ownershipGuard?: string | null
    sinkKinds?: string[]
    testedClasses?: string[]
    coveragePct?: number | null
    riskScore?: number
    codeLocation?: Record<string, unknown> | null
  }): { id: string }
  listEndpoints(
    runId: string,
    filter?: { origin?: string; method?: string; untestedClass?: string; minRiskScore?: number },
  ): Array<Record<string, unknown>>
  updateEndpointCoverage(endpointId: string, coveragePct: number, testedClasses?: string[]): void
  upsertEndpointParam(input: {
    runId: string
    endpointId: string
    name: string
    location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' | 'cookie'
    inferredType?: string | null
    isCsrf?: boolean
    isObjectId?: boolean
    source: string
  }): { id: string }
  listEndpointParams(runId: string, endpointId?: string): Array<Record<string, unknown>>
  recordApiDependency(input: {
    runId: string
    producerEndpointId: string
    consumerEndpointId: string
    resourceKey: string
    sampleResourceIdHash?: string | null
    personaHandle?: string | null
    observedTransitions?: string[]
    testedBola?: boolean
  }): { id: string }
  listApiDependencies(runId: string): Array<Record<string, unknown>>
  markApiDependencyTestedBola(id: string): void
  insertSecondOrderCanary(input: {
    runId: string
    assignmentId: string
    marker: string
    injectedOrigin: string
    injectedEndpoint: string
    injectedParam: string
    injectedPersona?: string | null
  }): { id: string }
  markSecondOrderCanarySurfaced(
    id: string,
    details: {
      surfacedOrigin: string
      surfacedEndpoint: string
      surfacedPersona?: string | null
      surfacedExchangeId?: string | null
      status?: 'surfaced' | 'verified'
    },
  ): void
  listSecondOrderCanaries(runId: string, status?: 'planted' | 'surfaced' | 'verified'): Array<Record<string, unknown>>
  insertLabTelemetry(input: {
    runId: string
    exchangeId: string
    traceId: string
    routesHit: string[]
    newLinesCovered: number
    sinkEventsCount: number
    hasUnhandledException: boolean
    artifactId: string
  }): { id: string }
  listLabTelemetry(runId: string): Array<Record<string, unknown>>
  insertBenchmarkRun(input: {
    suite: string
    gitSha: string
    modelRoutingConfig: Record<string, unknown>
    targetsTotal: number
    confirmedCount: number
    falsePositiveCount: number
    funnelCounts: Record<string, number>
    failureTaxonomy: Record<string, number>
    totalCostUsd: number
    durationMs: number
  }): { id: string }
  listBenchmarkRuns(suite?: string, limit?: number): Array<Record<string, unknown>>
  getLatestBenchmarkRun(suite: string): Record<string, unknown> | null
  updateRunPhase0Completed(runId: string, ts: number): void
  updateRunDynamicStepBudget(runId: string, budget: number): void
  incrementReplaySpecAttempt(id: string, feedback: InlineVerifyFeedback): void
}

export interface V4LabConfig extends Partial<LabConfig> {
  services?: Array<{
    name: string
    image?: string
    dockerfile?: string
    internalPort?: number
    env?: Record<string, string>
    command?: string
    dependsOn?: string[]
  }>
  seedCommand?: string
  iastEnabled?: boolean
  iastRuntime?: 'node' | 'python' | 'jvm' | 'generic'
}

export interface V4LabTargetHandle {
  targetId?: string
  runId: string
  networkName: string
  containerName: string
  origin: string
  baseUrls?: Record<string, string>
  seededPersonas?: Array<{ handle: string; roleLabel: string }>
  telemetryDir?: string
  stop?: () => Promise<void>
}

// ============================================================================
// Environment, Temp Workspace & SQLite Store Helpers
// ============================================================================

export async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T> | T): Promise<T> {
  const prev: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(vars)) {
    prev[k] = process.env[k]
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  try {
    return await fn()
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

export function makeTempDir(t: TestContext, prefix = 'guardian-v4-tier-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  // The hardened worker runs as UID 10001 and bind-mounts repo fixtures, so
  // the mount root must be traversable by that user (mkdtemp defaults to 0700).
  chmodSync(dir, 0o755)
  t.after(() => {
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* best-effort */ }
  })
  return dir
}

export function makeStore(t: TestContext, prefix = 'guardian-v4-db-'): { dir: string; storage: Store } {
  const dir = makeTempDir(t, prefix)
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
  })
  return { dir, storage }
}

export function hasTable(storage: Store, tableName: string): boolean {
  const row = storage.client
    .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`)
    .get(tableName) as { name?: string } | undefined
  return row?.name === tableName
}

export function tableColumns(storage: Store, tableName: string): string[] {
  const rows = storage.client
    .prepare(`PRAGMA table_info(${tableName})`)
    .all() as Array<{ name: string }>
  return rows.map(r => r.name)
}

export function tableIndexes(storage: Store, tableName: string): string[] {
  const rows = storage.client
    .prepare(`PRAGMA index_list(${tableName})`)
    .all() as Array<{ name: string }>
  return rows.map(r => r.name)
}

export async function setupApprovedRun(
  storage: Store,
  opts: {
    environment?: 'public' | 'local-lab'
    seeds?: string[]
    tier?: CapabilityTier
    budgetUsd?: number
    budgetRequests?: number
    maxRpsPerOrigin?: number
    personas?: Array<{
      handle: string
      roleLabel: string
      authKind: 'bearer' | 'cookie' | 'header'
      headerName?: string
      secret: string
      canaryMarkers?: string[]
    }>
    sandboxWriteAllowlist?: ApprovedEndpointPattern[]
    labConfig?: V4LabConfig
    goal?: string
  } = {},
) {
  const environment = opts.environment ?? 'local-lab'
  const seeds = opts.seeds ?? [environment === 'local-lab' ? 'http://127.0.0.1:9' : 'https://app.example.invalid']
  const projectPayload: Record<string, unknown> = {
    requestId: randomUUID(),
    name: `v4-tier-project-${randomUUID().slice(0, 8)}`,
    seeds,
    environment,
    ...(opts.labConfig ? { labConfig: opts.labConfig } : {}),
    ...(opts.sandboxWriteAllowlist ? { sandboxWriteAllowlist: opts.sandboxWriteAllowlist } : {}),
  }

  const runSetup = () => {
    const project = storage.createProject(projectPayload as unknown as Parameters<Store['createProject']>[0])
    const personaIds: string[] = []
    const personaMap = new Map<string, ResolvedPersona>()
    for (const p of opts.personas ?? []) {
      const created = createProjectPersona(storage, {
        requestId: randomUUID(),
        projectId: project.id,
        handle: p.handle,
        roleLabel: p.roleLabel,
        originAllowlist: seeds,
        authKind: p.authKind,
        ...(p.headerName ? { headerName: p.headerName } : {}),
        secret: p.secret,
        canaryMarkers: p.canaryMarkers ?? [],
      })
      personaIds.push(created.id)
      personaMap.set(p.handle, {
        id: created.id,
        handle: p.handle,
        roleLabel: p.roleLabel,
        originAllowlist: seeds,
        authKind: p.authKind,
        headerName: p.headerName ?? null,
        secret: p.secret,
        canaryMarkers: p.canaryMarkers ?? [],
      })
    }
    const createdRun = storage.createRun({
      requestId: randomUUID(),
      projectId: project.id,
      goal: opts.goal ?? 'Verify v4 security surface and zero-trust invariants',
      sourceMode: 'public',
      capabilityTier: opts.tier ?? 2,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: personaIds,
      budgetUsd: opts.budgetUsd ?? 25,
      budgetRequests: opts.budgetRequests ?? 1000,
      maxRpsPerOrigin: opts.maxRpsPerOrigin ?? 20,
      workerConcurrency: 4,
      workerMaxTurns: 40,
      multiTrialEnabled: true,
    } as unknown as Parameters<Store['createRun']>[0])
    storage.command({ requestId: randomUUID(), runId: createdRun.id, action: 'discover', consent: true })
    const detail = storage.runDetail(createdRun.id)
    const assetIds = detail.run.candidates.map(c => c.id)
    storage.command({
      requestId: randomUUID(),
      runId: createdRun.id,
      action: 'scope',
      expectedScopeRevision: 0,
      assetIds,
      consent: true,
      approvedPersonaIds: personaIds,
    })
    const refreshed = storage.runDetail(createdRun.id)
    return {
      projectId: project.id,
      runId: createdRun.id,
      run: refreshed.run,
      assetIds,
      personaIds,
      personaMap,
    }
  }

  return environment === 'local-lab'
    ? await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, runSetup)
    : runSetup()
}

// ============================================================================
// Loopback HTTP / WebSocket / Mock-LLM Servers
// ============================================================================

export interface RecordedWireRequest {
  method: string
  url: string
  headers: Record<string, string | string[] | undefined>
  body: string
}

export async function startHttpFixture(
  t: TestContext,
  handler: (req: IncomingMessage, body: string, res: ServerResponse, allRequests: RecordedWireRequest[]) => unknown | Promise<unknown>,
) {
  const requests: RecordedWireRequest[] = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(Buffer.from(chunk)))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      requests.push({
        method: req.method ?? 'GET',
        url: req.url ?? '/',
        headers: req.headers,
        body,
      })
      Promise.resolve(handler(req, body, res, requests)).catch(err => {
        if (!res.headersSent) {
          res.statusCode = 500
          res.end(err instanceof Error ? err.message : String(err))
        }
      })
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  assert.ok(addr && typeof addr !== 'string', 'Failed to bind loopback HTTP fixture')
  const origin = `http://127.0.0.1:${addr.port}`
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })
  return { origin, port: addr.port, requests, server }
}

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

export function encodeWsFrame(opcode: number, payload: Buffer): Buffer {
  const len = payload.length
  let header: Buffer
  if (len < 126) {
    header = Buffer.from([0x80 | (opcode & 0x0f), len])
  } else if (len < 65_536) {
    header = Buffer.alloc(4)
    header[0] = 0x80 | (opcode & 0x0f)
    header[1] = 126
    header.writeUInt16BE(len, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = 0x80 | (opcode & 0x0f)
    header[1] = 127
    header.writeBigUInt64BE(BigInt(len), 2)
  }
  return Buffer.concat([header, payload])
}

export async function startWsFixture(
  t: TestContext,
  onClientMessage: (msg: string, socket: Duplex, req: IncomingMessage) => void,
) {
  const upgradeSockets = new Set<Duplex>()
  const server = createServer((_req, res) => {
    res.statusCode = 200
    res.end('ws-fixture-http-ok')
  })
  server.on('upgrade', (req, socket) => {
    upgradeSockets.add(socket)
    socket.on('close', () => upgradeSockets.delete(socket))
    const key = req.headers['sec-websocket-key']
    if (typeof key !== 'string') {
      socket.destroy()
      return
    }
    const accept = createHash('sha1').update(key + WS_GUID).digest('base64')
    socket.write(
      [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Accept: ${accept}`,
        '',
        '',
      ].join('\r\n'),
    )
    let buf = Buffer.alloc(0)
    socket.on('data', chunk => {
      buf = Buffer.concat([buf, chunk])
      while (buf.length >= 2) {
        const b0 = buf[0]
        const b1 = buf[1]
        const masked = (b1 & 0x80) !== 0
        let len = b1 & 0x7f
        let pos = 2
        if (len === 126) {
          if (buf.length < 4) break
          len = buf.readUInt16BE(2)
          pos = 4
        } else if (len === 127) {
          if (buf.length < 10) break
          len = Number(buf.readBigUInt64BE(2))
          pos = 10
        }
        const maskLen = masked ? 4 : 0
        if (buf.length < pos + maskLen + len) break
        const payload = Buffer.from(buf.subarray(pos + maskLen, pos + maskLen + len))
        if (masked) {
          const mask = buf.subarray(pos, pos + 4)
          for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i & 3]
        }
        buf = buf.subarray(pos + maskLen + len)
        if ((b0 & 0x0f) === 0x08) {
          socket.end(encodeWsFrame(0x08, Buffer.alloc(0)))
          break
        }
        onClientMessage(payload.toString('utf8'), socket, req)
      }
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  assert.ok(addr && typeof addr !== 'string', 'Failed to bind WS fixture')
  const origin = `http://127.0.0.1:${addr.port}`
  t.after(async () => {
    for (const s of upgradeSockets) s.destroy()
    server.closeAllConnections()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })
  return { origin, port: addr.port, server }
}

export interface MockLlmCall {
  body: Record<string, unknown>
  headers: Record<string, string | string[] | undefined>
}

export async function startMockLlmServer(
  t: TestContext,
  responder: (
    call: MockLlmCall,
    callIndex: number,
  ) =>
    | { type: 'text'; text: string }
    | { type: 'tool_call'; callId: string; name: string; argumentsJson: string },
) {
  const calls: MockLlmCall[] = []
  const fixture = await startHttpFixture(t, (req, body, res) => {
    const parsed = body ? JSON.parse(body) as Record<string, unknown> : {}
    const tools = Array.isArray(parsed.tools) ? (parsed.tools as Array<{ name?: string }>) : []
    const isConnPing = tools.some(tl => tl.name === 'guardian_connection')
    const idx = isConnPing ? -1 : calls.length
    const reply = isConnPing
      ? { type: 'tool_call' as const, callId: `call_conn_${Date.now()}`, name: 'guardian_connection', argumentsJson: JSON.stringify({ status: 'ready' }) }
      : (() => {
          calls.push({ body: parsed, headers: req.headers })
          return responder({ body: parsed, headers: req.headers }, idx)
        })()
    res.setHeader('Content-Type', 'text/event-stream')
    res.setHeader('Cache-Control', 'no-cache')
    const itemId = `item_${isConnPing ? 'conn' : idx}`
    const responseId = `resp_${isConnPing ? 'conn' : idx}`
    const send = (event: string, data: Record<string, unknown>) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
    }
    send('response.created', { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } })
    if (reply.type === 'tool_call') {
      send('response.output_item.added', {
        type: 'response.output_item.added',
        output_index: 0,
        item: { id: itemId, type: 'function_call', status: 'in_progress', call_id: reply.callId, name: reply.name, arguments: '' },
      })
      send('response.function_call_arguments.delta', {
        type: 'response.function_call_arguments.delta',
        output_index: 0,
        item_id: itemId,
        delta: reply.argumentsJson,
      })
      send('response.function_call_arguments.done', {
        type: 'response.function_call_arguments.done',
        output_index: 0,
        item_id: itemId,
        name: reply.name,
        arguments: reply.argumentsJson,
      })
      send('response.output_item.done', {
        type: 'response.output_item.done',
        output_index: 0,
        item: { id: itemId, type: 'function_call', status: 'completed', call_id: reply.callId, name: reply.name, arguments: reply.argumentsJson },
      })
      send('response.completed', {
        type: 'response.completed',
        response: {
          id: responseId,
          status: 'completed',
          output: [{ id: itemId, type: 'function_call', status: 'completed', call_id: reply.callId, name: reply.name, arguments: reply.argumentsJson }],
          usage: { input_tokens: 120, output_tokens: 45, total_tokens: 165, input_tokens_details: { cached_tokens: 0 } },
        },
      })
    } else {
      send('response.output_item.added', {
        type: 'response.output_item.added',
        output_index: 0,
        item: { id: itemId, type: 'message', status: 'in_progress', role: 'assistant', content: [] },
      })
      send('response.output_text.delta', {
        type: 'response.output_text.delta',
        output_index: 0,
        item_id: itemId,
        content_index: 0,
        delta: reply.text,
      })
      send('response.output_text.done', {
        type: 'response.output_text.done',
        output_index: 0,
        item_id: itemId,
        content_index: 0,
        text: reply.text,
      })
      send('response.output_item.done', {
        type: 'response.output_item.done',
        output_index: 0,
        item: { id: itemId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: reply.text }] },
      })
      send('response.completed', {
        type: 'response.completed',
        response: {
          id: responseId,
          status: 'completed',
          output: [{ id: itemId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: reply.text }] }],
          usage: { input_tokens: 80, output_tokens: 30, total_tokens: 110, input_tokens_details: { cached_tokens: 0 } },
        },
      })
    }
    res.write('data: [DONE]\n\n')
    res.end()
  })
  return { endpoint: `${fixture.origin}/v1`, origin: fixture.origin, calls }
}

// ============================================================================
// Grants, Virtual Public Broker, JWT & Docker Helpers
// ============================================================================

export function makeLabGrant(origin: string, overrides: Partial<V4Grant> = {}): V4Grant {
  return {
    origin,
    tier: 2,
    maxRpsPerOrigin: 30,
    allowLocalLab: true,
    canRead: o => o === origin,
    audit: () => {},
    ...overrides,
  }
}

export function makePublicGrant(origin: string, overrides: Partial<V4Grant> = {}): V4Grant {
  return {
    origin,
    tier: 1,
    maxRpsPerOrigin: 10,
    allowLocalLab: false,
    canRead: o => o === origin,
    audit: () => {},
    ...overrides,
  }
}

export function makeVirtualPublicBroker(
  handler: (
    url: URL,
    options?: { method?: string; headers?: Record<string, string>; body?: string },
  ) => Promise<RawHttpResponse> | RawHttpResponse,
): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async (url, _addr, _signal, options) => await handler(url, options),
    source: 'fixture response',
  })
}

export function makeHs256Jwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  secret = RAW_JWT_SECRET,
): string {
  const h = Buffer.from(JSON.stringify(header)).toString('base64url')
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url')
  return `${h}.${p}.${sig}`
}

export function decodeJwtParts(token: string): {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
} {
  const parts = token.split('.')
  assert.equal(parts.length, 3, `Expected 3 JWT segments, got ${parts.length}`)
  return {
    header: JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as Record<string, unknown>,
    payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>,
    signature: parts[2],
  }
}

export async function dockerAvailable(): Promise<boolean> {
  try {
    await execFileAsync('docker', ['info', '--format', '{{.ServerVersion}}'])
    return true
  } catch {
    return false
  }
}

export async function assertZeroGuardianOrphans(runId?: string): Promise<void> {
  assert.equal(await dockerAvailable(), true, 'Docker daemon is required to verify zero Guardian orphans')
  // Scope the assertion to the caller: a run id covers worker + lab containers for that run.
  // Without one, only this process's worker containers are ours to assert on — a global
  // `dev.guardian.run` filter would flag concurrent streams' live containers as orphans.
  const runFilter = runId
    ? ['--filter', `label=dev.guardian.run=${runId}`]
    : ['--filter', `label=dev.guardian.session=${workerProcessSessionId()}`]
  // Cleanup is asynchronous at the edges (a close handler may still be in flight); poll briefly
  // so a container that is already being removed is not reported as a leak.
  const deadline = Date.now() + 5_000
  let psOut = ''
  do {
    psOut = (await execFileAsync('docker', ['ps', '-aq', ...runFilter])).stdout
    if (!psOut.trim()) break
    await delay(100)
  } while (Date.now() < deadline)
  assert.equal(psOut.trim(), '', `Expected zero orphan containers, found: ${psOut.trim()}`)
  if (runId) {
    const { stdout: netOut } = await execFileAsync('docker', ['network', 'ls', '-q', '--filter', `name=${runId.slice(0, 8)}`])
    assert.equal(netOut.trim(), '', `Expected zero orphan networks for run ${runId}, found: ${netOut.trim()}`)
  }
}

export function writeLabRepoFixture(
  rootDir: string,
  opts: { withCompose?: boolean; withVulns?: boolean; withEnvSecret?: boolean } = {},
): string {
  mkdirSync(join(rootDir, 'src'), { recursive: true })
  writeFileSync(
    join(rootDir, 'package.json'),
    JSON.stringify({ name: 'v4-test-lab', version: '1.0.0', private: true }, null, 2),
  )
  writeFileSync(
    join(rootDir, 'server.mjs'),
    [
      `import { createServer } from 'node:http'`,
      `const PORT = Number(process.env.PORT || 3000)`,
      `const server = createServer((req, res) => {`,
      `  const u = new URL(req.url || '/', 'http://localhost')`,
      `  if (u.pathname === '/health') { res.end('ok'); return }`,
      `  if (u.pathname === '/api/orders') {`,
      `    const id = u.searchParams.get('id') || '1'`,
      `    if (id.includes("'")) { res.statusCode = 500; res.end('SQLITE_ERROR: near syntax error'); return }`,
      `    res.setHeader('Content-Type', 'application/json')`,
      `    res.end(JSON.stringify({ id, owner: 'persona_a', total: 100 }))`,
      `    return`,
      `  }`,
      `  res.statusCode = 404; res.end('not found')`,
      `})`,
      `server.listen(PORT, '0.0.0.0')`,
    ].join('\n'),
  )
  writeFileSync(
    join(rootDir, 'Dockerfile'),
    ['FROM node:24-bookworm-slim', 'WORKDIR /app', 'COPY . .', 'EXPOSE 3000', 'CMD ["node", "server.mjs"]'].join('\n'),
  )
  if (opts.withVulns !== false) {
    writeFileSync(
      join(rootDir, 'src', 'orders.ts'),
      [
        `export async function getOrder(db: { query: (s: string) => unknown }, id: string) {`,
        `  return db.query("SELECT * FROM orders WHERE id = '" + id + "'")`,
        `}`,
        `export async function getInvoice(db: { query: (s: string) => unknown }, id: string) {`,
        `  return db.query("SELECT * FROM invoices WHERE id = '" + id + "'")`,
        `}`,
      ].join('\n'),
    )
  }
  if (opts.withCompose) {
    writeFileSync(
      join(rootDir, 'docker-compose.yml'),
      [
        'services:',
        '  app:',
        '    build: .',
        '    environment:',
        '      PORT: "3000"',
        '      CACHE_HOST: "cache"',
        '  cache:',
        '    image: node:24-bookworm-slim',
        '    command: ["node", "-e", "require(\'http\').createServer((_,r)=>r.end(\'ok\')).listen(6379)"]',
      ].join('\n'),
    )
  }
  if (opts.withEnvSecret) {
    writeFileSync(join(rootDir, '.env'), `STRIPE_KEY=${RAW_STRIPE_SECRET}\nAWS_ACCESS_KEY_ID=${RAW_AWS_SECRET}\n`)
    writeFileSync(join(rootDir, 'deploy.pem'), '-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n')
  }
  return rootDir
}

export function writePersonaSecretFile(dir: string, name: string, secret: string): string {
  const filePath = join(dir, `${name}.secret`)
  writeFileSync(filePath, secret, { mode: 0o600 })
  chmodSync(filePath, 0o600)
  return filePath
}

export function baseReplaySpecFields(origin: string) {
  return {
    version: 1 as const,
    origin,
    title: 'Guardian v4 Opaque-Box Replay Test',
    category: 'broken-access-control' as const,
    cwe: 'CWE-639',
    severity: 'high' as const,
    severityRationale: 'Unauthenticated or cross-tenant access verified deterministically.',
    impact: 'Cross-tenant sensitive data disclosure.',
    remediation: 'Enforce server-side ownership checks and input parameterization.',
    recheckInstructions: 'Replay with distinct control and probe requests.',
  }
}

export async function stopExecution(engine: {
  stop: () => Promise<void>
  active?: { size: number }
  coordinator?: { size: number }
  threatModeling?: { size: number }
  plannerTasks?: { size: number }
  runAuthInFlight?: { size: number }
}) {
  await engine.stop()
  const deadline = Date.now() + 5_000
  while (Date.now() < deadline) {
    const busy =
      (engine.active?.size ?? 0) +
      (engine.coordinator?.size ?? 0) +
      (engine.threatModeling?.size ?? 0) +
      (engine.plannerTasks?.size ?? 0) +
      (engine.runAuthInFlight?.size ?? 0)
    if (busy === 0) break
    await delay(25)
  }
  await delay(50)
}

export async function runWorkerAnalyze(
  backend: { openSession: (aid: string, signal: AbortSignal, opts?: { reposDir?: string }) => Promise<{ analyze: (tool: string, args: Record<string, unknown>, sig: AbortSignal) => Promise<Record<string, unknown>>; close: () => Promise<void> }> },
  tool: string,
  args: Record<string, unknown>,
  reposDir?: string,
) {
  const sig = AbortSignal.timeout(45_000)
  const session = await backend.openSession(randomUUID(), sig, reposDir ? { reposDir } : undefined)
  try {
    return await session.analyze(tool, args, sig)
  } finally {
    await session.close()
  }
}

export async function runWorkerSast(
  backend: { openSession: (aid: string, signal: AbortSignal, opts?: { reposDir?: string }) => Promise<{ sast: (req: Record<string, unknown>, sig: AbortSignal) => Promise<Record<string, unknown>>; close: () => Promise<void> }> },
  req: { repo: string; engines: string[]; reposDir: string },
) {
  const sig = AbortSignal.timeout(90_000)
  const session = await backend.openSession(randomUUID(), sig, { reposDir: req.reposDir })
  try {
    return await session.sast({ repo: req.repo, engines: req.engines }, sig)
  } finally {
    await session.close()
  }
}

export async function runWorkerScript(
  backend: { openSession: (aid: string, signal: AbortSignal) => Promise<{ runScript: (req: { runtime: 'node' | 'python'; code: string }, sig: AbortSignal) => Promise<{ exitCode: number; stdout: string; stderr: string }>; close: () => Promise<void> }> },
  req: { runtime: 'node' | 'python'; code: string },
) {
  const sig = AbortSignal.timeout(45_000)
  const session = await backend.openSession(randomUUID(), sig)
  try {
    return await session.runScript(req, sig)
  } finally {
    await session.close()
  }
}
