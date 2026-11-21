import { createHash, randomBytes, randomInt, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import { diffResponse, dnsTakeoverAnalyze } from '../../worker/analyzers.ts'
import {
  containsDestructivePayload,
  declarativeReplaySpecSchema,
  replayAssertionOutcomeSchema,
  replaySpecOrigins,
} from '../replay-spec.ts'
import type { DeclarativeReplaySpec, RaceBurstRequest, ReplayAssertionOutcome, ReplayStep } from '../replay-spec.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied, RequestBroker } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import type { Store } from './store.ts'
import type { WorkerBackend } from './worker-backend.ts'

export type ReplayVerdict = 'confirmed' | 'dismissed' | 'inconclusive'
export type RetestVerdict = 'reproduced' | 'fixed' | 'inconclusive'

export interface VerifyReplaySpecParams {
  spec: DeclarativeReplaySpec | unknown
  broker: RequestBroker
  browser?: ScopedBrowser
  canaryBroker?: CanaryBroker
  backend: WorkerBackend
  grant: Grant
  signal: AbortSignal
  storage?: Store
  runId?: string
  assignmentId?: string
  onExchange?: (exchange: BrokerExchangeResult) => string | void
}

export interface ReplayVerificationResult {
  verdict: ReplayVerdict
  outcome: ReplayAssertionOutcome
  exchangeIds: string[]
  exchanges: BrokerExchangeResult[]
  evidencePayload: Record<string, unknown>
  evidenceSha256: string
}

export interface RetestReplayResult {
  verdict: RetestVerdict
  replay: ReplayVerificationResult
}

function isPrime(n: number): boolean {
  if (n < 2) return false
  if (n % 2 === 0) return n === 2
  const limit = Math.floor(Math.sqrt(n))
  for (let i = 3; i <= limit; i += 2) {
    if (n % i === 0) return false
  }
  return true
}

function randomFiveDigitPrime(exclude?: number): number {
  for (;;) {
    const candidate = randomInt(10_007, 99_991) | 1
    if (candidate !== exclude && isPrime(candidate)) return candidate
  }
}

function randomAlphaToken(len = 7): string {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'
  const bytes = randomBytes(len)
  let out = ''
  for (let i = 0; i < len; i += 1) out += alphabet[bytes[i] % alphabet.length]
  return out
}

function interpolateString(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}/g, (full, name: string) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? vars[name] : full)
}

function interpolateValue(value: unknown, vars: Record<string, string>): unknown {
  if (typeof value === 'string') return interpolateString(value, vars)
  if (Array.isArray(value)) return value.map(v => interpolateValue(v, vars))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = interpolateValue(v, vars)
    }
    return out
  }
  return value
}

function readJsonPath(obj: unknown, path: string): string | null {
  const clean = path.replace(/^\$\.?/, '')
  const segments = clean.split('.').filter(Boolean)
  let cur: unknown = obj
  for (const seg of segments) {
    if (cur === null || cur === undefined) return null
    const arrayMatch = seg.match(/^([a-zA-Z0-9_-]*)\[(\d+)\]$/)
    if (arrayMatch) {
      const [, key, idxStr] = arrayMatch
      if (key) cur = (cur as Record<string, unknown>)[key]
      if (!Array.isArray(cur)) return null
      cur = cur[Number(idxStr)]
    } else if (typeof cur === 'object') {
      cur = (cur as Record<string, unknown>)[seg]
    } else {
      return null
    }
  }
  if (cur === null || cur === undefined) return null
  return typeof cur === 'string' ? cur : JSON.stringify(cur)
}

function extractVariables(step: ReplayStep, exchange: BrokerExchangeResult, vars: Record<string, string>) {
  for (const rule of step.extract ?? []) {
    let extracted: string | null = null
    if (rule.from === 'status') {
      extracted = String(exchange.status)
    } else if (rule.from === 'header') {
      extracted = exchange.respHeaders[rule.selector.toLowerCase()] ?? null
    } else if (rule.from === 'json') {
      try {
        const parsed = JSON.parse(exchange.body) as unknown
        extracted = readJsonPath(parsed, rule.selector)
      } catch {
        extracted = null
      }
    } else if (rule.from === 'regex') {
      try {
        const re = new RegExp(rule.selector)
        const m = exchange.body.match(re)
        extracted = m ? (m[1] ?? m[0] ?? null) : null
      } catch {
        extracted = null
      }
    }
    if (extracted !== null) vars[rule.varName] = extracted.slice(0, 512)
  }
}

function summarizeExchange(ex: BrokerExchangeResult) {
  let json: unknown = null
  if (ex.mediaType.includes('json')) {
    try { json = JSON.parse(ex.body) } catch { json = null }
  }
  return {
    origin: ex.origin,
    finalOrigin: ex.finalOrigin,
    redirectOrigins: ex.redirectOrigins,
    method: ex.method,
    pathAndQuery: ex.pathAndQuery,
    personaHandle: ex.personaHandle,
    status: ex.status,
    mediaType: ex.mediaType,
    headers: ex.respHeaders,
    setCookies: ex.setCookies,
    body: ex.body.slice(0, 64 * 1024),
    bodyPreview: ex.bodyPreview,
    bodyBytes: ex.bodyBytes,
    bodySha256: ex.bodySha256,
    durationMs: ex.durationMs,
    ...(json !== null ? { json } : {}),
  }
}

function hasDestructiveContent(text: string): boolean {
  if (containsDestructivePayload(text)) return true
  try {
    const decoded = decodeURIComponent(text.replaceAll('+', ' '))
    if (decoded !== text && containsDestructivePayload(decoded)) return true
  } catch {
    const plusDecoded = text.replaceAll('+', ' ')
    if (plusDecoded !== text && containsDestructivePayload(plusDecoded)) return true
  }
  return false
}

function singleQuoteEscape(value: string): string {
  return value.replaceAll("'", "'\\''")
}

function inconclusiveResult(
  reason: string,
  exchanges: BrokerExchangeResult[],
  exchangeIds: string[],
  evidencePayload: Record<string, unknown>,
): ReplayVerificationResult {
  const payload = { ...evidencePayload, error: reason }
  const evidenceSha256 = createHash('sha256').update(JSON.stringify(payload)).digest('hex')
  return {
    verdict: 'inconclusive',
    outcome: {
      confirmed: false,
      controlPassed: false,
      observed: reason.slice(0, 1200),
      expected: 'Clean replay execution passing control and deterministic assertions.',
      reason: reason.slice(0, 1200),
    },
    exchangeIds,
    exchanges,
    evidencePayload: payload,
    evidenceSha256,
  }
}

interface EphemeralCanarySession {
  mint(purpose: string): { token: string; url: string }
  check(token: string): { triggered: boolean; detail: Record<string, unknown> | null }
  close(): Promise<void>
}

async function openCanarySession(
  canaryBroker: CanaryBroker | undefined,
  storage: Store | undefined,
  runId: string | undefined,
  assignmentId: string,
  origin?: string,
): Promise<EphemeralCanarySession> {
  if (canaryBroker) {
    const info = await canaryBroker.startListener()
    const effectiveRunId = runId ?? 'replay-verifier'
    const baseUrl = info.effectiveBaseUrl ?? ''
    return {
      mint(purpose: string) {
        const minted = canaryBroker.mintCanary(
          effectiveRunId,
          purpose,
          origin,
          storage ? { storage, assignmentId } : undefined,
        )
        return {
          token: minted.token,
          url: minted.httpUrl || `${baseUrl}/c/${minted.token}`,
        }
      },
      check(token: string) {
        const res = canaryBroker.checkCanary(token, storage ? { storage, runId: effectiveRunId } : undefined)
        return { triggered: res.hit, detail: res.detail }
      },
      async close() { /* Managed by host CanaryBroker lifecycle */ },
    }
  }

  // Standalone ephemeral loopback canary listener (used in unit tests without a CanaryBroker).
  const callbacks = new Map<string, Record<string, unknown>>()
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const match = /^\/c\/(guardian-canary-[a-f0-9]{24})$/.exec(url.pathname)
    if (match) {
      callbacks.set(match[1], {
        method: req.method ?? 'GET',
        path: url.pathname,
        receivedAt: new Date().toISOString(),
      })
    }
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end('guardian-canary-ok')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  if (!addr || typeof addr === 'string') {
    server.close()
    throw new Error('Could not bind ephemeral replay canary listener.')
  }
  const baseUrl = `http://127.0.0.1:${addr.port}`
  return {
    mint() {
      const token = `guardian-canary-${randomBytes(12).toString('hex')}`
      return { token, url: `${baseUrl}/c/${token}` }
    },
    check(token: string) {
      const detail = callbacks.get(token) ?? null
      return { triggered: Boolean(detail), detail }
    },
    async close() {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

function requestShapeToBrokerRequest(
  req: ReplayStep['request'] | RaceBurstRequest,
  vars: Record<string, string>,
): BrokerHttpRequest {
  const pathAndQuery = interpolateString(req.pathAndQuery, vars)
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries(req.headers ?? {})) {
    headers[k] = interpolateString(v, vars)
  }
  let body: string | undefined
  if (req.textBody !== undefined) {
    body = interpolateString(req.textBody, vars)
  } else if (req.jsonBody !== undefined) {
    body = JSON.stringify(interpolateValue(req.jsonBody, vars))
    if (!headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = 'application/json'
    }
  }
  return {
    origin: req.origin,
    method: req.method,
    pathAndQuery,
    headers,
    body,
    persona: req.persona,
    followRedirects: req.followRedirects,
  }
}

function stepToBrokerRequest(step: ReplayStep, vars: Record<string, string>): BrokerHttpRequest {
  return requestShapeToBrokerRequest(step.request, vars)
}

async function sleepAbortable(ms: number, signal: AbortSignal) {
  if (signal.aborted) throw signal.reason
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = () => {
      clearTimeout(timer)
      reject(signal.reason)
    }
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

export async function verifyReplaySpec(params: VerifyReplaySpecParams): Promise<ReplayVerificationResult> {
  const { broker, backend, grant, signal } = params
  const assignmentId = params.assignmentId ?? randomUUID()
  const exchanges: BrokerExchangeResult[] = []
  const exchangeIds: string[] = []
  const recordExchange = (ex: BrokerExchangeResult) => {
    exchanges.push(ex)
    const id = params.onExchange?.(ex)
    if (typeof id === 'string' && id) exchangeIds.push(id)
  }

  // 1. Structural validation
  const parsed = declarativeReplaySpecSchema.safeParse(params.spec)
  if (!parsed.success) {
    return inconclusiveResult(`Invalid DeclarativeReplaySpec: ${parsed.error.issues[0]?.message ?? 'schema mismatch'}`, exchanges, exchangeIds, {})
  }
  const spec = parsed.data

  // 2. Policy & scope validation
  const origins = replaySpecOrigins(spec)
  for (const origin of origins) {
    if (!grant.canRead(origin)) {
      grant.audit('denied', origin)
      return inconclusiveResult(`Replay spec origin ${origin} is not in approved scope.`, exchanges, exchangeIds, { kind: spec.kind, origins })
    }
  }
  if (hasDestructiveContent(JSON.stringify(spec))) {
    grant.audit('denied', spec.origin)
    return inconclusiveResult('Replay spec rejected by Guardian destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
  }
  const tier = grant.tier ?? 1
  if (tier === 0) {
    return inconclusiveResult('Live replay verification is disabled in Tier 0.', exchanges, exchangeIds, { kind: spec.kind })
  }

  // Hard Tier 3 + HITL approval gate for rce_proof
  if (spec.kind === 'rce_proof') {
    if (tier < 3) {
      grant.audit('denied', spec.probeStep.request.origin)
      return inconclusiveResult('rce_proof replay specs are blocked below Tier 3.', exchanges, exchangeIds, { kind: spec.kind, proofMode: spec.proofMode })
    }
    const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
    const approvalFn = grant.isStateChangeApproved
    const approved = approvalFn
      ? approvalFn(spec.probeStep.request.origin, spec.probeStep.request.method, spec.probeStep.request.pathAndQuery)
      : localLab
    if (!approved) {
      grant.audit('denied', spec.probeStep.request.origin)
      return inconclusiveResult('rce_proof requires explicit Tier 3 HITL operator approval.', exchanges, exchangeIds, { kind: spec.kind, proofMode: spec.proofMode })
    }
  }

  // 3. Fresh Replay Execution
  let evidencePayload: Record<string, unknown> = {
    kind: spec.kind,
    origin: spec.origin,
    replayedAt: new Date().toISOString(),
  }
  let forcedInconclusiveReason: string | null = null
  let rceCryptoProofPassed = true

  try {
    if (spec.kind === 'http_chain') {
      const vars: Record<string, string> = {}
      const stepsOut: Record<string, unknown> = {}
      const probeStepExchanges: Array<{ id: string; exchange: BrokerExchangeResult }> = []
      let firstControlStep: Record<string, unknown> | undefined
      let firstProbeStep: Record<string, unknown> | undefined

      for (const step of spec.steps) {
        signal.throwIfAborted()
        const brokerReq = stepToBrokerRequest(step, vars)
        if (step.request.batchCount) {
          const batchReqs = Array.from({ length: step.request.batchCount }, () => ({ ...brokerReq }))
          const batchResults = await broker.executeBatch(batchReqs, grant, signal)
          for (const ex of batchResults) recordExchange(ex)
          const first = batchResults[0]
          if (first) extractVariables(step, first, vars)
          const stepEntry: Record<string, unknown> = {
            id: step.id,
            role: step.role,
            batchCount: batchResults.length,
            statuses: batchResults.map(r => r.status),
            responses: batchResults.map(summarizeExchange),
            ...(first ? summarizeExchange(first) : {}),
          }
          stepsOut[step.id] = stepEntry
          if (step.role === 'control' && !firstControlStep) firstControlStep = stepEntry
          if (step.role === 'probe') {
            if (!firstProbeStep) firstProbeStep = stepEntry
            if (first) probeStepExchanges.push({ id: step.id, exchange: first })
          }
        } else {
          const ex = await broker.executeHttp(brokerReq, grant, signal)
          recordExchange(ex)
          extractVariables(step, ex, vars)
          const stepEntry: Record<string, unknown> = {
            id: step.id,
            role: step.role,
            ...summarizeExchange(ex),
          }
          stepsOut[step.id] = stepEntry
          if (step.role === 'control' && !firstControlStep) firstControlStep = stepEntry
          if (step.role === 'probe') {
            if (!firstProbeStep) firstProbeStep = stepEntry
            probeStepExchanges.push({ id: step.id, exchange: ex })
          }
        }
      }

      let spaCatchall: Record<string, unknown> | undefined
      if (spec.spaCatchallControl) {
        const catchallPath = `/.guardian-nonexistent-${randomUUID()}`
        const catchallEx = await broker.executeHttp({
          origin: spec.origin,
          method: 'GET',
          pathAndQuery: catchallPath,
          followRedirects: true,
        }, grant, signal)
        recordExchange(catchallEx)

        const comparisons: Record<string, Record<string, unknown>> = {}
        let allProbesMatchedCatchall = probeStepExchanges.length > 0
        for (const probe of probeStepExchanges) {
          const diff = diffResponse(
            { status: catchallEx.status, body: catchallEx.body, mediaType: catchallEx.mediaType },
            { status: probe.exchange.status, body: probe.exchange.body, mediaType: probe.exchange.mediaType },
          )
          comparisons[probe.id] = diff
          if (!diff.likelySpaCatchall) allProbesMatchedCatchall = false
        }
        spaCatchall = {
          path: catchallPath,
          ...summarizeExchange(catchallEx),
          comparisons,
          allProbesMatchedCatchall,
        }
        if (allProbesMatchedCatchall) {
          forcedInconclusiveReason = 'Probe response is structurally indistinguishable from an HTTP 200 SPA catch-all route.'
        }
      }

      evidencePayload = {
        ...evidencePayload,
        steps: stepsOut,
        ...(firstControlStep ? { control: firstControlStep } : {}),
        ...(firstProbeStep ? { probe: firstProbeStep } : {}),
        extractedVars: vars,
        ...(spaCatchall ? { spaCatchall } : {}),
      }
    } else if (spec.kind === 'dns_takeover') {
      const dns = await broker.inspectDns(spec.targetOrigin, grant, signal)
      let http: Record<string, unknown> | null = null
      let httpError: string | null = null
      let body = ''
      let status: number | undefined
      try {
        const ex = await broker.executeHttp({
          origin: spec.targetOrigin,
          method: 'GET',
          pathAndQuery: spec.probePath,
          followRedirects: true,
        }, grant, signal)
        recordExchange(ex)
        http = summarizeExchange(ex)
        body = ex.body
        status = ex.status
      } catch (err) {
        httpError = err instanceof Error ? err.message : String(err)
      }
      const analysis = dnsTakeoverAnalyze({
        hostname: dns.hostname,
        cnames: dns.cname,
        a: dns.a,
        aaaa: dns.aaaa,
        status,
        body,
        nxdomain: dns.nxdomain,
      })
      evidencePayload = {
        ...evidencePayload,
        targetOrigin: spec.targetOrigin,
        dns,
        http,
        httpError,
        analysis,
      }
    } else if (spec.kind === 'tls_audit') {
      const tls = await broker.inspectTls(spec.targetOrigin, grant, signal)
      evidencePayload = {
        ...evidencePayload,
        targetOrigin: spec.targetOrigin,
        tls,
      }
    } else if (spec.kind === 'browser_dom') {
      const scopedBrowser = params.browser ?? new ScopedBrowser(broker)
      const canaryToken = `guardian-dom-${randomAlphaToken(10)}`
      const control = await scopedBrowser.visitPage({
        origin: spec.targetOrigin,
        pathAndQuery: spec.controlPath,
        persona: spec.persona,
        checkKind: spec.checkKind,
        onExchange: ex => {
          exchanges.push(ex)
          const id = params.onExchange?.(ex)
          if (typeof id === 'string' && id) exchangeIds.push(id)
          return id
        },
      }, grant, signal)

      const probe = await scopedBrowser.visitPage({
        origin: spec.targetOrigin,
        pathAndQuery: spec.probePath.replaceAll('{{canary_token}}', canaryToken),
        persona: spec.persona,
        checkKind: spec.checkKind,
        canaryToken,
        onExchange: ex => {
          exchanges.push(ex)
          const id = params.onExchange?.(ex)
          if (typeof id === 'string' && id) exchangeIds.push(id)
          return id
        },
      }, grant, signal)

      const stripExchanges = ({ exchanges: _omit, ...rest }: typeof control) => rest
      evidencePayload = {
        ...evidencePayload,
        targetOrigin: spec.targetOrigin,
        checkKind: spec.checkKind,
        canaryToken,
        control: stripExchanges(control),
        probe: stripExchanges(probe),
      }
    } else if (spec.kind === 'browser_chain') {
      const scopedBrowser = params.browser ?? new ScopedBrowser(broker)
      const canaryToken = `guardian-dom-${randomAlphaToken(10)}`
      const vars = { canary_token: canaryToken }
      const stepsOut: Record<string, unknown> = {}
      const pages: Record<string, unknown>[] = []
      const consoleMessages: Array<{ stepId: string; role: string; type: 'error' | 'warning'; text: string }> = []
      const requests: Array<{ stepId: string; role: string; method: string; url: string; origin: string; resourceType: string; status: number | null }> = []
      const domResults: Record<string, unknown>[] = []
      const probeSnapshots: Array<{
        id: string
        primaryExchange?: BrokerExchangeResult
        domSnippet: string
        status: number | null
        hadDynamicSignal: boolean
      }> = []
      let firstControlStep: Record<string, unknown> | undefined
      let firstProbeStep: Record<string, unknown> | undefined

      for (const step of spec.steps) {
        signal.throwIfAborted()
        const pathAndQuery = interpolateString(step.pathAndQuery, vars)
        const postMessagePayload = step.postMessagePayload !== undefined
          ? interpolateValue(step.postMessagePayload, vars)
          : undefined
        const resolvedCheckKind = step.checkKind
          ?? (step.action === 'postmessage_probe' ? 'postmessage'
            : step.action === 'dom_check' ? 'dom_xss'
              : undefined)

        const visit = await scopedBrowser.visitPage({
          origin: step.origin,
          pathAndQuery,
          persona: step.persona,
          checkKind: resolvedCheckKind,
          canaryToken,
          selector: step.selector,
          postMessageOrigin: step.action === 'postmessage_probe'
            ? (step.postMessageOrigin ?? 'https://untrusted-origin.invalid')
            : step.postMessageOrigin,
          postMessagePayload,
          sameSiteFetch: step.action === 'same_site_fetch' ? step.fetchTarget : undefined,
          waitAfterLoadMs: step.waitAfterLoadMs,
          onExchange: ex => {
            exchanges.push(ex)
            const id = params.onExchange?.(ex)
            if (typeof id === 'string' && id) exchangeIds.push(id)
            return id
          },
        }, grant, signal)

        const { exchanges: visitExchanges, ...visitSummary } = visit
        const stepEntry: Record<string, unknown> = {
          id: step.id,
          role: step.role,
          action: step.action,
          ...visitSummary,
        }
        stepsOut[step.id] = stepEntry
        pages.push({
          stepId: step.id,
          role: step.role,
          action: step.action,
          origin: visit.origin,
          finalUrl: visit.finalUrl,
          title: visit.title,
          status: visit.status,
          domSnippet: visit.domSnippet,
          links: visit.links,
          forms: visit.forms,
          blockedOrigins: visit.blockedOrigins,
          cookieNames: visit.cookieNames,
          localStorageKeys: visit.localStorageKeys,
          sessionStorageKeys: visit.sessionStorageKeys,
          postMessageListeners: visit.postMessageListeners,
          canaryCheck: visit.canaryCheck,
          selectorResult: visit.selectorResult ?? null,
          fetchResult: visit.fetchResult ?? null,
          redirectSummary: visit.redirectSummary ?? null,
          durationMs: visit.durationMs,
        })
        for (const msg of visit.consoleMessages) {
          consoleMessages.push({ stepId: step.id, role: step.role, ...msg })
        }
        for (const r of (visit.allRequests ?? visit.xhrRequests)) {
          requests.push({ stepId: step.id, role: step.role, ...r })
        }
        domResults.push({
          stepId: step.id,
          role: step.role,
          action: step.action,
          origin: visit.origin,
          finalUrl: visit.finalUrl,
          status: visit.status,
          title: visit.title,
          selectorResult: visit.selectorResult ?? null,
          canaryCheck: visit.canaryCheck,
          postMessageListeners: visit.postMessageListeners,
          fetchResult: visit.fetchResult ?? null,
          redirectSummary: visit.redirectSummary ?? null,
        })

        if (step.role === 'control' && !firstControlStep) firstControlStep = stepEntry
        if (step.role === 'probe') {
          if (!firstProbeStep) firstProbeStep = stepEntry
          const hadDynamicSignal = Boolean(
            visit.canaryCheck.triggered ||
            visit.selectorResult?.matched ||
            visit.postMessageListeners.canaryHandledWithoutOriginCheck ||
            visit.fetchResult !== null ||
            visit.redirectSummary?.redirected,
          )
          probeSnapshots.push({
            id: step.id,
            primaryExchange: visitExchanges[0],
            domSnippet: visit.domSnippet,
            status: visit.status,
            hadDynamicSignal,
          })
        }
      }

      let spaCatchall: Record<string, unknown> | undefined
      if (spec.spaCatchallControl) {
        const catchallPath = `/.guardian-nonexistent-${randomUUID()}`
        const catchallEx = await broker.executeHttp({
          origin: spec.origin,
          method: 'GET',
          pathAndQuery: catchallPath,
          followRedirects: true,
        }, grant, signal)
        recordExchange(catchallEx)

        const comparisons: Record<string, Record<string, unknown>> = {}
        let allProbesMatchedCatchall = probeSnapshots.length > 0
        for (const probe of probeSnapshots) {
          const diff = diffResponse(
            { status: catchallEx.status, body: catchallEx.body, mediaType: catchallEx.mediaType },
            {
              status: probe.primaryExchange?.status ?? (probe.status ?? 0),
              body: probe.primaryExchange?.body ?? probe.domSnippet,
              mediaType: probe.primaryExchange?.mediaType ?? 'text/html',
            },
          )
          comparisons[probe.id] = diff
          if (!diff.likelySpaCatchall || probe.hadDynamicSignal) {
            allProbesMatchedCatchall = false
          }
        }
        spaCatchall = {
          path: catchallPath,
          ...summarizeExchange(catchallEx),
          comparisons,
          allProbesMatchedCatchall,
        }
        if (allProbesMatchedCatchall) {
          forcedInconclusiveReason = 'Browser chain probe response is structurally indistinguishable from an HTTP 200 SPA catch-all route.'
        }
      }

      evidencePayload = {
        ...evidencePayload,
        canaryToken,
        steps: stepsOut,
        pages,
        consoleMessages,
        requests,
        domResults,
        ...(firstControlStep ? { control: firstControlStep } : {}),
        ...(firstProbeStep ? { probe: firstProbeStep } : {}),
        ...(spaCatchall ? { spaCatchall } : {}),
      }
    } else if (spec.kind === 'race_burst') {
      if (tier < 2) {
        grant.audit('denied', spec.origin)
        return inconclusiveResult('race_burst replay specs require Capability Tier 2 or Tier 3.', exchanges, exchangeIds, { kind: spec.kind })
      }
      const vars: Record<string, string> = {}
      let controlSummary: Record<string, unknown> | null = null
      let postCheckSummary: Record<string, unknown> | null = null

      if (spec.controlStep) {
        signal.throwIfAborted()
        const controlReq = stepToBrokerRequest(spec.controlStep, vars)
        if (hasDestructiveContent(JSON.stringify(controlReq))) {
          return inconclusiveResult('Interpolated race_burst controlStep matched destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
        }
        const controlEx = await broker.executeHttp(controlReq, grant, signal)
        recordExchange(controlEx)
        extractVariables(spec.controlStep, controlEx, vars)
        controlSummary = {
          id: spec.controlStep.id,
          role: spec.controlStep.role,
          ...summarizeExchange(controlEx),
        }
      }

      const burstReqs = spec.burst.map(req => requestShapeToBrokerRequest(req, vars))
      if (hasDestructiveContent(JSON.stringify(burstReqs))) {
        return inconclusiveResult('Interpolated race_burst requests matched destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
      }

      const burstResult = await broker.executeRaceBurst(burstReqs, grant, signal)
      for (const ex of burstResult.results) recordExchange(ex)

      if (spec.postCheckStep) {
        signal.throwIfAborted()
        const postReq = stepToBrokerRequest(spec.postCheckStep, vars)
        if (hasDestructiveContent(JSON.stringify(postReq))) {
          return inconclusiveResult('Interpolated race_burst postCheckStep matched destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
        }
        const postEx = await broker.executeHttp(postReq, grant, signal)
        recordExchange(postEx)
        extractVariables(spec.postCheckStep, postEx, vars)
        postCheckSummary = {
          id: spec.postCheckStep.id,
          role: spec.postCheckStep.role,
          ...summarizeExchange(postEx),
        }
      }

      evidencePayload = {
        ...evidencePayload,
        control: controlSummary,
        burst: {
          summary: burstResult.summary,
          results: burstResult.results.map(summarizeExchange),
        },
        postCheck: postCheckSummary,
        extractedVars: vars,
      }
    } else if (spec.kind === 'rce_proof') {
      const controlVars: Record<string, string> = {}
      const probeVars: Record<string, string> = {}
      const proofMeta: Record<string, unknown> = { mode: spec.proofMode }

      let canarySession: EphemeralCanarySession | undefined
      let controlCanaryToken: string | undefined
      let probeCanaryToken: string | undefined
      let expectedNonceProduct: string | undefined
      let expectedSplitAssembled: string | undefined

      if (spec.proofMode === 'dynamic_math') {
        const a = randomFiveDigitPrime()
        const b = randomFiveDigitPrime(a)
        expectedNonceProduct = String(a * b)
        probeVars.nonce_a = String(a)
        probeVars.nonce_b = String(b)
        proofMeta.nonceA = a
        proofMeta.nonceB = b
        proofMeta.expectedProduct = expectedNonceProduct
      } else if (spec.proofMode === 'split_echo') {
        const part1 = randomAlphaToken(7)
        const part2 = randomAlphaToken(7)
        expectedSplitAssembled = part1 + part2
        probeVars.nonce_part1 = part1
        probeVars.nonce_part2 = part2
        proofMeta.expectedAssembled = expectedSplitAssembled
      } else {
        canarySession = await openCanarySession(params.canaryBroker, params.storage, params.runId, assignmentId, spec.origin)
        const controlCanary = canarySession.mint(`rce_proof:control:${spec.title}`)
        const probeCanary = canarySession.mint(`rce_proof:probe:${spec.title}`)
        controlCanaryToken = controlCanary.token
        probeCanaryToken = probeCanary.token
        controlVars.canary_token = controlCanary.token
        controlVars.canary_url = controlCanary.url
        probeVars.canary_token = probeCanary.token
        probeVars.canary_url = probeCanary.url
        proofMeta.controlCanaryToken = controlCanary.token
        proofMeta.probeCanaryToken = probeCanary.token
      }

      try {
        const controlReq = stepToBrokerRequest(spec.controlStep, controlVars)
        const probeReq = stepToBrokerRequest(spec.probeStep, probeVars)
        const serializedProbeReq = JSON.stringify(probeReq)

        if (hasDestructiveContent(JSON.stringify(controlReq)) || hasDestructiveContent(serializedProbeReq)) {
          return inconclusiveResult('Interpolated rce_proof request matched destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
        }

        // For split_echo, the assembled token MUST NOT literally appear in the outbound request
        // (otherwise raw input reflection could spoof execution).
        if (spec.proofMode === 'split_echo' && expectedSplitAssembled && serializedProbeReq.includes(expectedSplitAssembled)) {
          return inconclusiveResult('Invalid split_echo template: nonce_part1 and nonce_part2 must be separated by execution concatenation syntax.', exchanges, exchangeIds, { kind: spec.kind })
        }

        const controlEx = await broker.executeHttp(controlReq, grant, signal)
        recordExchange(controlEx)
        const probeEx = await broker.executeHttp(probeReq, grant, signal)
        recordExchange(probeEx)

        if (spec.proofMode === 'dynamic_math' && expectedNonceProduct) {
          const inProbe = probeEx.body.includes(expectedNonceProduct)
          const inControl = controlEx.body.includes(expectedNonceProduct)
          const inOutbound = serializedProbeReq.includes(expectedNonceProduct)
          rceCryptoProofPassed = inProbe && !inControl && !inOutbound
          proofMeta.mathVerified = rceCryptoProofPassed
          proofMeta.productInProbe = inProbe
          proofMeta.productInControl = inControl
        } else if (spec.proofMode === 'split_echo' && expectedSplitAssembled) {
          const inProbe = probeEx.body.includes(expectedSplitAssembled)
          const inControl = controlEx.body.includes(expectedSplitAssembled)
          const inOutbound = serializedProbeReq.includes(expectedSplitAssembled)
          rceCryptoProofPassed = inProbe && !inControl && !inOutbound
          proofMeta.splitEchoVerified = rceCryptoProofPassed
          proofMeta.assembledInProbe = inProbe
          proofMeta.assembledInControl = inControl
        } else if (spec.proofMode === 'oob_canary' && canarySession && controlCanaryToken && probeCanaryToken) {
          // Wait briefly for asynchronous OOB callback (up to 1500ms, polling every 150ms)
          let probeCheck = canarySession.check(probeCanaryToken)
          for (let attempt = 0; attempt < 10 && !probeCheck.triggered; attempt += 1) {
            await sleepAbortable(150, signal)
            probeCheck = canarySession.check(probeCanaryToken)
          }
          const controlCheck = canarySession.check(controlCanaryToken)
          rceCryptoProofPassed = probeCheck.triggered && !controlCheck.triggered
          proofMeta.canaryProbeTriggered = probeCheck.triggered
          proofMeta.canaryProbeDetail = probeCheck.detail
          proofMeta.canaryControlTriggered = controlCheck.triggered
          proofMeta.canaryControlDetail = controlCheck.detail
        }

        proofMeta.cryptographicProofPassed = rceCryptoProofPassed
        evidencePayload = {
          ...evidencePayload,
          proofMode: spec.proofMode,
          control: summarizeExchange(controlEx),
          probe: summarizeExchange(probeEx),
          proof: proofMeta,
        }
      } finally {
        await canarySession?.close()
      }
    }
  } catch (err) {
    if (err instanceof BrokerDenied || err instanceof BrokerCircuitOpen || err instanceof BrokerApprovalRequired) {
      return inconclusiveResult(err.message, exchanges, exchangeIds, evidencePayload)
    }
    const message = err instanceof Error ? err.message : String(err)
    return inconclusiveResult(`Replay execution failed: ${message}`, exchanges, exchangeIds, evidencePayload)
  }

  // 4. Air-Gapped Assertion Evaluation via one-shot --network none just-bash worker
  const serializedPayload = JSON.stringify(evidencePayload, null, 2)
  const evidenceSha256 = createHash('sha256').update(serializedPayload).digest('hex')
  const jqCommand = `jq '${singleQuoteEscape(spec.assertionsJq)}' /evidence/replay-results.json > /work/outcome.json`

  let workerResult
  try {
    workerResult = await backend.run({
      assignmentId,
      files: [{ name: 'replay-results.json', content: serializedPayload }],
      command: jqCommand,
      outputs: ['outcome.json'],
      timeoutMs: 30_000,
    }, signal)
  } catch (err) {
    return inconclusiveResult(
      `Verification container failed: ${err instanceof Error ? err.message : String(err)}`,
      exchanges,
      exchangeIds,
      evidencePayload,
    )
  }

  const rawOutcome = (workerResult.outputs['outcome.json'] || workerResult.stdout || '').trim()
  if (workerResult.exitCode !== 0 || !rawOutcome) {
    return inconclusiveResult(
      `Replay jq assertion failed (exit ${workerResult.exitCode}): ${workerResult.stderr.slice(0, 400)}`,
      exchanges,
      exchangeIds,
      evidencePayload,
    )
  }

  let parsedJson: unknown
  try {
    parsedJson = JSON.parse(rawOutcome)
  } catch {
    return inconclusiveResult('Replay jq assertion did not emit valid JSON.', exchanges, exchangeIds, evidencePayload)
  }

  // Coerce structured observed/expected/reason fields to bounded strings while keeping confirmed/controlPassed strictly boolean.
  const coerceOutcomeText = (value: unknown): string => {
    if (typeof value === 'string') return value.slice(0, 1200)
    try {
      return (JSON.stringify(value) ?? String(value)).slice(0, 1200)
    } catch {
      return String(value).slice(0, 1200)
    }
  }
  if (parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)) {
    const obj = { ...(parsedJson as Record<string, unknown>) }
    if ('observed' in obj && obj.observed !== undefined) obj.observed = coerceOutcomeText(obj.observed)
    if ('expected' in obj && obj.expected !== undefined) obj.expected = coerceOutcomeText(obj.expected)
    if ('reason' in obj) {
      if (obj.reason === undefined || obj.reason === null) delete obj.reason
      else obj.reason = coerceOutcomeText(obj.reason)
    }
    parsedJson = obj
  }

  const validatedOutcome = replayAssertionOutcomeSchema.safeParse(parsedJson)
  if (!validatedOutcome.success) {
    return inconclusiveResult(
      `Replay assertion output violated schema: ${validatedOutcome.error.issues[0]?.message ?? 'invalid shape'}`,
      exchanges,
      exchangeIds,
      evidencePayload,
    )
  }

  const outcome = validatedOutcome.data

  // 5. Verdict Promotion (enforcing deterministic anti-false-positive guards)
  if (forcedInconclusiveReason) {
    return {
      verdict: 'inconclusive',
      outcome: {
        ...outcome,
        confirmed: false,
        controlPassed: false,
        reason: forcedInconclusiveReason,
      },
      exchangeIds,
      exchanges,
      evidencePayload,
      evidenceSha256,
    }
  }

  if (spec.kind === 'rce_proof' && !rceCryptoProofPassed) {
    return {
      verdict: outcome.controlPassed ? 'dismissed' : 'inconclusive',
      outcome: {
        ...outcome,
        confirmed: false,
        reason: 'Cryptographic non-destructive proof-of-execution check did not pass (possible reflection or unexecuted payload).',
      },
      exchangeIds,
      exchanges,
      evidencePayload,
      evidenceSha256,
    }
  }

  let verdict: ReplayVerdict
  if (outcome.controlPassed && outcome.confirmed) {
    verdict = 'confirmed'
  } else if (outcome.controlPassed && !outcome.confirmed) {
    verdict = 'dismissed'
  } else {
    verdict = 'inconclusive'
  }

  return {
    verdict,
    outcome,
    exchangeIds,
    exchanges,
    evidencePayload,
    evidenceSha256,
  }
}

export async function retestReplaySpec(params: VerifyReplaySpecParams): Promise<RetestReplayResult> {
  const replay = await verifyReplaySpec(params)
  const verdict: RetestVerdict = replay.verdict === 'confirmed'
    ? 'reproduced'
    : replay.verdict === 'dismissed'
      ? 'fixed'
      : 'inconclusive'
  return { verdict, replay }
}
