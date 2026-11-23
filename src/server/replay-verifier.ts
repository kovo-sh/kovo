import { createHash, createHmac, randomBytes, randomInt, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import { diffResponse, dnsTakeoverAnalyze } from '../../worker/analyzers.ts'
import { maxInlineVerifyRetries } from '../domain.ts'
import type { InlineVerifyFeedback, VerificationTier } from '../domain.ts'
import {
  cacheBusterValueRegex,
  containsDestructivePayload,
  declarativeReplaySpecSchema,
  extractCacheBusterParam,
  replayAssertionOutcomeSchema,
  replaySpecOrigins,
} from '../replay-spec.ts'
import type { AuthMutation, DeclarativeReplaySpec, RaceBurstRequest, ReplayAssertionOutcome, ReplayStep } from '../replay-spec.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied, RequestBroker, websocketResultToExchange } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { personaSecrets } from './persona-vault.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import type { BrowserDomSinkTrace, BrowserInteractiveAction, BrowserSessionStep } from './scoped-browser.ts'
import { injectUniversalParam, responseSimilarity } from './surface-engine.ts'
import type { Store } from './store.ts'
import type { WorkerBackend } from './worker-backend.ts'

export type ReplayVerdict = 'confirmed' | 'static_verified' | 'dismissed' | 'inconclusive'
export type RetestVerdict = 'reproduced' | 'fixed' | 'inconclusive'

export interface VerifyReplaySpecParams {
  spec: DeclarativeReplaySpec | unknown
  broker: RequestBroker
  browser?: ScopedBrowser
  canaryBroker?: CanaryBroker
  backend: WorkerBackend
  /** Host path of the read-only repo mount; required for static_ast_proof. */
  reposDir?: string
  grant: Grant
  signal: AbortSignal
  storage?: Store
  runId?: string
  assignmentId?: string
  onExchange?: (exchange: BrokerExchangeResult) => string | void
}

export interface ReplayVerificationResult {
  verdict: ReplayVerdict
  /** 'runtime_confirmed' only for runtime-confirmed verdicts; 'static_verified' for static_ast_proof; never both. */
  verificationTier?: VerificationTier
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

const BFLA_CWE_RE = /^CWE-(?:285|269|862|863)$/i
const BFLA_TEXT_RE = /\b(?:bfla|broken function[- ]level|function[- ]level|privilege escalation|vertical access)\b/i
const READ_ONLY_REPLAY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const MUTATING_REPLAY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

export interface BflaImpactAssessment {
  required: boolean
  satisfied: boolean
  reason: string
}

function readStepField(entry: Record<string, unknown> | undefined, key: string): unknown {
  return entry && typeof entry === 'object' ? entry[key] : undefined
}

function normalizedReplayPath(value: string | undefined): string {
  if (!value) return ''
  return value.split('?')[0].split('#')[0].replace(/\/{2,}/g, '/').replace(/\/+$/, '').toLowerCase() || '/'
}

/**
 * Vertical (function-level) BFLA needs *impact*, not just a 2xx from a lower-privileged actor.
 * A read-only route that every authenticated role may legitimately read must never confirm as
 * privilege escalation: the deterministic replay has to show either a successful privileged
 * mutation or a same-route role differential (one actor 2xx with real data, another actor denied).
 * Object-level BOLA (CWE-639) is intentionally unaffected.
 */
export function assessBflaImpact(
  spec: DeclarativeReplaySpec,
  stepsOut: Record<string, unknown>,
): BflaImpactAssessment {
  if (spec.kind !== 'http_chain') {
    return { required: false, satisfied: true, reason: 'Not an HTTP chain replay spec.' }
  }
  const descriptor = `${spec.cwe} ${spec.category} ${spec.title} ${spec.impact} ${spec.severityRationale}`
  const vertical = BFLA_CWE_RE.test(spec.cwe) || BFLA_TEXT_RE.test(descriptor)
  if (!vertical || spec.steps.length < 2) {
    return { required: false, satisfied: true, reason: 'Not a function-level BFLA proof.' }
  }

  const steps = spec.steps.map(step => {
    const entry = stepsOut[step.id] as Record<string, unknown> | undefined
    const status = readStepField(entry, 'status')
    const body = readStepField(entry, 'body')
    return {
      id: step.id,
      role: step.role,
      method: step.request.method.toUpperCase(),
      persona: step.request.persona ?? null,
      path: normalizedReplayPath(step.request.pathAndQuery),
      status: typeof status === 'number' ? status : null,
      bodyBytes: typeof body === 'string' ? body.length : 0,
    }
  })

  const mutating = steps.filter(step => MUTATING_REPLAY_METHODS.has(step.method))
  if (mutating.length > 0) {
    const succeeded = mutating.find(step => step.status !== null && step.status >= 200 && step.status < 300)
    if (succeeded) {
      return {
        required: true,
        satisfied: true,
        reason: `Privileged mutating step "${succeeded.id}" returned HTTP ${succeeded.status}.`,
      }
    }
    return {
      required: true,
      satisfied: false,
      reason: 'BFLA mutating step did not succeed, so no privileged side effect was demonstrated.',
    }
  }

  if (!steps.every(step => READ_ONLY_REPLAY_METHODS.has(step.method))) {
    return { required: true, satisfied: false, reason: 'BFLA proof used a non-read method without a 2xx mutation.' }
  }

  // Same-route role differential: a different actor is denied while the probe actor receives data.
  for (const probe of steps) {
    if (probe.status === null || probe.status < 200 || probe.status >= 300 || probe.bodyBytes < 64) continue
    for (const other of steps) {
      if (other.id === probe.id) continue
      if (other.path !== probe.path) continue
      if (other.status === null || other.status < 400) continue
      if (other.persona === probe.persona && other.role === probe.role) continue
      return {
        required: true,
        satisfied: true,
        reason: `Role differential: "${probe.id}" (${probe.persona ?? 'anonymous'}) received HTTP ${probe.status} while "${other.id}" (${other.persona ?? 'anonymous'}) was denied with HTTP ${other.status}.`,
      }
    }
  }

  return {
    required: true,
    satisfied: false,
    reason: 'Read-only BFLA proof lacks impact evidence: a 2xx from one actor on a read-only route is not privilege escalation unless another actor is denied on the same route or the response exposes data the actor cannot otherwise access. Add a same-route role-differential or a privileged mutation step.',
  }
}

function summarizeExchange(ex: BrokerExchangeResult) {  let json: unknown = null
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
    // Pre-redaction structural proof: fingerprints only (never the raw value), so an assertion can
    // prove a disclosed secret matched the entitled view even after the body was scrubbed.
    ...(ex.secretMatches?.length
      ? {
          secretMatches: ex.secretMatches.slice(0, 16).map(m => ({
            kind: m.kind,
            sha256Prefix: m.sha256Prefix,
            ...(m.fieldPath ? { fieldPath: m.fieldPath } : {}),
            count: m.count,
          })),
        }
      : {}),
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
  mint(purpose: string): { token: string; url: string; dnsHost: string }
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
          dnsHost: minted.dnsHost,
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
      return { token, url: `${baseUrl}/c/${token}`, dnsHost: `${token}.canary.guardian.invalid` }
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

/**
 * Mint a throw-away signing key and a fresh timestamp, then compute the HMAC over the documented
 * canonical form. Used only for self-signed webhook proof (no real secret ever enters the spec).
 */
function applyBodySignature(interpolated: unknown, signable: NonNullable<ReplayStep['request']['bodySignature']>): unknown {
  const input = interpolated && typeof interpolated === 'object' && !Array.isArray(interpolated)
    ? { ...(interpolated as Record<string, unknown>) }
    : {}
  const key = `guardian_whk_${randomBytes(8).toString('hex')}`
  const ts = String(Math.floor(Date.now() / 1000))
  if (signable.timestampField) input[signable.timestampField] = ts
  input[signable.keyField] = key
  const withoutSig = { ...input }
  delete withoutSig[signable.signatureField]
  const event = signable.eventField
    ? withoutSig[signable.eventField]
    : (withoutSig.event ?? withoutSig.payload ?? withoutSig.data ?? withoutSig)
  const asText = (value: unknown): string => (typeof value === 'string' ? value : JSON.stringify(value))
  const canonical = signable.canonical === 'ts_event'
    ? `${ts}.${asText(event)}`
    : signable.canonical === 'ts_body'
      ? `${ts}.${JSON.stringify(withoutSig)}`
      : signable.canonical === 'event'
        ? asText(event)
        : JSON.stringify(withoutSig)
  input[signable.signatureField] = createHmac('sha256', key).update(canonical).digest(signable.encoding)
  return input
}

function base64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
}

function requestShapeToBrokerRequest(
  req: ReplayStep['request'] | RaceBurstRequest,
  vars: Record<string, string>,
  opts?: {
    sessionId?: string
    sessionGroupRole?: 'setup' | 'control' | 'probe' | 'cleanup'
    runId?: string
    assignmentId?: string
  },
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
    const interpolated = interpolateValue(req.jsonBody, vars)
    const signable = (req as ReplayStep['request']).bodySignature
    const signed = signable ? applyBodySignature(interpolated, signable) : interpolated
    body = JSON.stringify(signed)
    if (!headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = 'application/json'
    }
  }
  const maybeReq = req as ReplayStep['request']
  let authMutation: AuthMutation | undefined = maybeReq.authMutation
  if (authMutation && authMutation.kind === 'jku_x5u_canary') {
    const rawUrl = authMutation.url ?? authMutation.value
    const interpUrl = rawUrl !== undefined ? interpolateString(rawUrl, vars) : undefined
    authMutation = {
      ...authMutation,
      ...(authMutation.url !== undefined && interpUrl !== undefined ? { url: interpUrl } : {}),
      ...(authMutation.value !== undefined && interpUrl !== undefined ? { value: interpUrl } : {}),
    }
  }
  return {
    origin: req.origin,
    method: req.method,
    pathAndQuery,
    headers,
    body,
    persona: req.persona,
    ...(opts?.sessionId ?? req.session ? { session: opts?.sessionId ?? req.session } : {}),
    ...(opts?.sessionGroupRole ? { sessionGroupRole: opts.sessionGroupRole } : {}),
    ...(req.csrfBind !== undefined ? { csrfBind: req.csrfBind } : {}),
    ...(authMutation ? { authMutation } : {}),
    ...(maybeReq.traceId ? { traceId: maybeReq.traceId } : {}),
    ...(opts?.runId ? { runId: opts.runId } : {}),
    ...(opts?.assignmentId ? { assignmentId: opts.assignmentId } : {}),
    followRedirects: req.followRedirects,
  }
}

function stepToBrokerRequest(
  step: ReplayStep,
  vars: Record<string, string>,
  opts?: { replayJarPrefix?: string; runId?: string; assignmentId?: string },
): BrokerHttpRequest {
  let sessionId: string | undefined
  if (step.request.session) {
    if (opts?.replayJarPrefix) {
      const candidate = `rv-${opts.replayJarPrefix}-${step.request.session}`
      sessionId = candidate.length <= 32
        ? candidate
        : `rv-${opts.replayJarPrefix}-${createHash('sha256').update(step.request.session).digest('hex').slice(0, 12)}`.slice(0, 32)
    } else {
      sessionId = step.request.session
    }
  }
  return requestShapeToBrokerRequest(step.request, vars, {
    sessionId,
    sessionGroupRole: step.role,
    runId: opts?.runId,
    assignmentId: opts?.assignmentId,
  })
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

const postureCwes = new Set([
  'CWE-16', 'CWE-200', 'CWE-209', 'CWE-284', 'CWE-285', 'CWE-287', 'CWE-288', 'CWE-306', 'CWE-319', 'CWE-326',
  'CWE-346', 'CWE-523', 'CWE-538', 'CWE-540', 'CWE-614', 'CWE-639', 'CWE-693', 'CWE-862', 'CWE-863', 'CWE-942',
  'CWE-1004', 'CWE-1021',
])
const postureCategoryPattern = /access|auth|bypass|cors|header|posture|misconfig|exposure|session|cookie|transport|tls|csp|policy|idor|bola|bfla/i

/** requireControlNonError defaults to true for posture / auth-bypass style specs. */
function defaultRequireControlNonError(spec: DeclarativeReplaySpec): boolean {
  if (spec.kind === 'static_ast_proof' || spec.kind === 'sql_boolean_diff' || spec.kind === 'sql_time_diff') return false
  return postureCwes.has(spec.cwe) || postureCategoryPattern.test(spec.category)
}

function statusMatchesExpected(expected: number | number[] | undefined, status: number): boolean {
  if (expected === undefined) return false
  return Array.isArray(expected) ? expected.includes(status) : expected === status
}

function isUnexpectedErrorStatus(status: number, ...expected: Array<number | number[] | undefined>): boolean {
  if (status !== 404 && status < 500) return false
  return !expected.some(e => statusMatchesExpected(e, status))
}

function setJsonPath(target: Record<string, unknown>, dotPath: string, value: unknown) {
  const parts = dotPath.split('.')
  let cur = target
  for (let i = 0; i < parts.length - 1; i += 1) {
    const next = cur[parts[i]]
    if (!next || typeof next !== 'object' || Array.isArray(next)) cur[parts[i]] = {}
    cur = cur[parts[i]] as Record<string, unknown>
  }
  cur[parts[parts.length - 1]] = value
}

function lightSummary(ex: BrokerExchangeResult) {
  return {
    status: ex.status,
    mediaType: ex.mediaType,
    bodySha256: ex.bodySha256,
    bodyBytes: ex.bodyBytes,
    bodyPreview: ex.body.slice(0, 2000),
    headers: ex.respHeaders,
  }
}

async function verifyReplaySpecInner(params: VerifyReplaySpecParams): Promise<ReplayVerificationResult> {
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
  const isStatic = spec.kind === 'static_ast_proof'
  const origins = replaySpecOrigins(spec)
  for (const origin of origins) {
    if (!grant.canRead(origin)) {
      grant.audit('denied', origin)
      return inconclusiveResult(`Replay spec origin ${origin} is not in approved scope.`, exchanges, exchangeIds, { kind: spec.kind, origins })
    }
  }
  if (!isStatic && hasDestructiveContent(JSON.stringify(spec))) {
    grant.audit('denied', spec.origin)
    return inconclusiveResult('Replay spec rejected by Guardian destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
  }
  const tier = grant.tier ?? 1
  if (tier === 0 && !isStatic) {
    return inconclusiveResult('Live replay verification is disabled in Tier 0.', exchanges, exchangeIds, { kind: spec.kind })
  }

  // Hard Tier 3 + HITL approval gate for rce_proof and upload_probe
  if (spec.kind === 'rce_proof' || spec.kind === 'upload_probe') {
    const gateRequest = spec.kind === 'rce_proof'
      ? spec.probeStep.request
      : { origin: spec.uploadStep.origin, method: spec.uploadStep.method, pathAndQuery: spec.uploadStep.pathAndQuery }
    if (tier < 3) {
      grant.audit('denied', gateRequest.origin)
      return inconclusiveResult(`${spec.kind} replay specs are blocked below Tier 3.`, exchanges, exchangeIds, { kind: spec.kind })
    }
    const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
    const approvalFn = grant.isStateChangeApproved
    const approved = approvalFn
      ? approvalFn(gateRequest.origin, gateRequest.method, gateRequest.pathAndQuery)
      : localLab
    if (!approved) {
      grant.audit('denied', gateRequest.origin)
      return inconclusiveResult(`${spec.kind} requires explicit Tier 3 HITL operator approval.`, exchanges, exchangeIds, { kind: spec.kind })
    }
  }
  const guardControlErrors = spec.requireControlNonError ?? defaultRequireControlNonError(spec)

  // 3. Fresh Replay Execution
  let evidencePayload: Record<string, unknown> = {
    kind: spec.kind,
    origin: spec.origin,
    replayedAt: new Date().toISOString(),
  }
  let forcedInconclusiveReason: string | null = null
  let deterministicProofPassed = true
  let proofFailureReason = ''

  try {
    if (spec.kind === 'http_chain') {
      const vars: Record<string, string> = {}
      const stepsOut: Record<string, unknown> = {}
      const probeStepExchanges: Array<{ id: string; exchange: BrokerExchangeResult }> = []
      const replayJarPrefix = randomUUID().slice(0, 8)
      let firstControlStep: Record<string, unknown> | undefined
      let firstProbeStep: Record<string, unknown> | undefined

      const serializedSteps = JSON.stringify(spec.steps)
      const needsCanary = /\{\{canary_(?:url|token|dns_host)\}\}/.test(serializedSteps) ||
        spec.steps.some(s => s.request.authMutation?.kind === 'jku_x5u_canary')
      let canarySession: EphemeralCanarySession | undefined
      let ctrlCanary: { url: string; token: string; dnsHost: string } | undefined
      let prbCanary: { url: string; token: string; dnsHost: string } | undefined
      if (needsCanary) {
        canarySession = await openCanarySession(params.canaryBroker, params.storage, params.runId, assignmentId, spec.origin)
        ctrlCanary = canarySession.mint(`http_chain:control:${spec.title}`)
        prbCanary = canarySession.mint(`http_chain:probe:${spec.title}`)
      }

      try {
        for (const step of spec.steps) {
          signal.throwIfAborted()
          const stepVars: Record<string, string> = { ...vars }
          if (ctrlCanary && prbCanary) {
            const activeCanary = step.role === 'control' ? ctrlCanary : prbCanary
            stepVars.canary_url = activeCanary.url
            stepVars.canary_token = activeCanary.token
            stepVars.canary_dns_host = activeCanary.dnsHost
          }
          const brokerReq = stepToBrokerRequest(step, stepVars, {
            replayJarPrefix,
            runId: params.runId,
            assignmentId,
          })
          if (brokerReq.authMutation?.kind === 'jku_x5u_canary' && !brokerReq.authMutation.url && !brokerReq.authMutation.value && ctrlCanary && prbCanary) {
            brokerReq.authMutation = {
              ...brokerReq.authMutation,
              url: step.role === 'control' ? ctrlCanary.url : prbCanary.url,
            }
          }
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

        if (guardControlErrors) {
          for (const step of spec.steps) {
            if (step.role !== 'control' && step.role !== 'probe') continue
            const status = (stepsOut[step.id] as { status?: number } | undefined)?.status
            if (typeof status === 'number' && isUnexpectedErrorStatus(status, step.expectedStatus, spec.expectedStatus)) {
              // On probe steps, allow error status if assertionsJq explicitly asserts that error status
              // (e.g. error-based SQLi testing `.steps.p1.status == 500` while control step is 200).
              if (step.role === 'probe') {
                const statusAssertedInJq =
                  new RegExp(`status\\s*==\\s*${status}\\b|\\b${status}\\s*==\\s*[^;]*status`).test(spec.assertionsJq) ||
                  (status >= 500 && /status\s*>=\s*500\b/.test(spec.assertionsJq))
                if (statusAssertedInJq) continue
              }
              forcedInconclusiveReason = `Unexpected HTTP ${status} on ${step.role} step "${step.id}" (requireControlNonError); declare expectedStatus ${status} to test error behavior.`
              break
            }
          }
        }

        let canaryEvidence: Record<string, unknown> | undefined
        if (canarySession && prbCanary && ctrlCanary) {
          let probeCheck = canarySession.check(prbCanary.token)
          for (let attempt = 0; attempt < 10 && !probeCheck.triggered; attempt += 1) {
            await sleepAbortable(150, signal)
            probeCheck = canarySession.check(prbCanary.token)
          }
          const controlCheck = canarySession.check(ctrlCanary.token)
          canaryEvidence = {
            proof: {
              canaryProbeTriggered: probeCheck.triggered,
              canaryControlTriggered: controlCheck.triggered,
              canaryProbeDetail: probeCheck.detail,
              canaryControlDetail: controlCheck.detail,
            },
            canary: {
              triggered: probeCheck.triggered && !controlCheck.triggered,
              probeTriggered: probeCheck.triggered,
              controlTriggered: controlCheck.triggered,
              probeDetail: probeCheck.detail,
              controlDetail: controlCheck.detail,
            },
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

        const bflaImpact = assessBflaImpact(spec, stepsOut)
        let proofMatches: Record<string, boolean[]> | undefined
        if (spec.proofPatterns?.length) {
          proofMatches = {}
          for (const [id, entry] of Object.entries(stepsOut)) {
            const body = entry && typeof entry === 'object' && typeof (entry as { body?: unknown }).body === 'string'
              ? (entry as { body: string }).body
              : ''
            proofMatches[id] = spec.proofPatterns.map(pattern => {
              // Harden the in-process matcher against pathological regexes: bounded length (schema),
              // no nested quantifiers, and only the first 16 KiB of the body.
              if (/\((?:\?:)?[^)]*[+*][^)]*\)[+*?]/.test(pattern)) return false
              try {
                return new RegExp(pattern).test(body.slice(0, 16 * 1024))
              } catch {
                return false
              }
            })
          }
        }
        evidencePayload = {
          ...evidencePayload,
          steps: stepsOut,
          ...(firstControlStep ? { control: firstControlStep } : {}),
          ...(firstProbeStep ? { probe: firstProbeStep } : {}),
          extractedVars: vars,
          ...(proofMatches ? { proofMatches } : {}),
          ...(canaryEvidence ?? {}),
          ...(spaCatchall ? { spaCatchall } : {}),
          bflaImpact,
        }
        if (bflaImpact.required && !bflaImpact.satisfied && !forcedInconclusiveReason) {
          forcedInconclusiveReason = bflaImpact.reason
        }
      } finally {
        await canarySession?.close()
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
      const domSinkTraces: Array<{ stepId: string; role: string } & BrowserDomSinkTrace> = []
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

      const buildStepActions = (step: typeof spec.steps[number]): BrowserInteractiveAction[] => {
        const stepActions: BrowserInteractiveAction[] = []
        if (step.action === 'fill' && step.selector) {
          stepActions.push({ type: 'fill', selector: step.selector, value: interpolateString(step.value ?? '', vars) })
        } else if (step.action === 'click' && step.selector) {
          stepActions.push({ type: 'click', selector: step.selector })
        } else if (step.action === 'select_option' && step.selector) {
          stepActions.push({ type: 'select_option', selector: step.selector, value: interpolateString(step.value ?? '', vars) })
        } else if (step.action === 'wait_for_selector' && step.selector) {
          stepActions.push({ type: 'wait_for_selector', selector: step.selector, timeoutMs: step.waitAfterLoadMs })
        } else if (step.action === 'wait_for_xhr') {
          stepActions.push({
            type: 'wait_for_xhr',
            urlPattern: step.urlPattern ? interpolateString(step.urlPattern, vars) : undefined,
            timeoutMs: step.waitAfterLoadMs,
          })
        } else if (step.action === 'evaluate_builtin' && step.builtinCheck) {
          stepActions.push({ type: 'evaluate_builtin', builtinCheck: step.builtinCheck })
        } else if (step.action === 'dom_xss_sink_hook') {
          stepActions.push({ type: 'dom_xss_sink_hook' })
        }
        return stepActions
      }

      const recordVisitStep = (step: typeof spec.steps[number], visit: Awaited<ReturnType<ScopedBrowser['visitPage']>>) => {
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
          domSinkTraces: visit.domSinkTraces,
          actionResults: visit.actionResults ?? [],
          builtinResults: visit.builtinResults ?? {},
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
        for (const trace of visit.domSinkTraces) {
          domSinkTraces.push({ stepId: step.id, role: step.role, ...trace })
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
          domSinkTraces: visit.domSinkTraces,
          actionResults: visit.actionResults ?? [],
          builtinResults: visit.builtinResults ?? {},
          postMessageListeners: visit.postMessageListeners,
          fetchResult: visit.fetchResult ?? null,
          redirectSummary: visit.redirectSummary ?? null,
        })
        if (step.role === 'control' && !firstControlStep) firstControlStep = stepEntry
        if (step.role === 'probe') {
          if (!firstProbeStep) firstProbeStep = stepEntry
          const hadDynamicSignal = Boolean(
            visit.canaryCheck.triggered ||
            visit.domSinkTraces.some(t => t.containsCanary) ||
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

      if (typeof (scopedBrowser as { runBrowserSession?: unknown }).runBrowserSession === 'function') {
        const sessionSteps: BrowserSessionStep[] = spec.steps.map(step => {
          const postMessagePayload = step.postMessagePayload !== undefined
            ? interpolateValue(step.postMessagePayload, vars)
            : undefined
          const resolvedCheckKind = step.checkKind
            ?? (step.action === 'postmessage_probe' ? 'postmessage'
              : (step.action === 'dom_check' || step.action === 'dom_xss_sink_hook') ? 'dom_xss'
                : undefined)
          const stepActions = buildStepActions(step)
          return {
            id: step.id,
            role: step.role,
            description: step.description,
            origin: step.origin,
            pathAndQuery: step.pathAndQuery !== undefined ? interpolateString(step.pathAndQuery, vars) : undefined,
            reusePage: step.reusePage,
            resetContext: step.resetContext,
            persona: step.persona,
            session: step.session,
            csrfBind: step.csrfBind,
            traceId: step.traceId,
            runId: params.runId,
            assignmentId,
            action: step.action,
            checkKind: resolvedCheckKind,
            canaryToken,
            selector: step.selector,
            value: step.value !== undefined ? interpolateString(step.value, vars) : undefined,
            builtinCheck: step.builtinCheck,
            urlPattern: step.urlPattern ? interpolateString(step.urlPattern, vars) : undefined,
            enableSinkHook: Boolean(step.enableSinkHook || step.action === 'dom_xss_sink_hook'),
            actions: stepActions.length > 0 ? stepActions : undefined,
            fetchTarget: step.action === 'same_site_fetch' ? step.fetchTarget : undefined,
            postMessageOrigin: step.action === 'postmessage_probe'
              ? (step.postMessageOrigin ?? 'https://untrusted-origin.invalid')
              : step.postMessageOrigin,
            postMessagePayload,
            waitAfterLoadMs: step.waitAfterLoadMs,
            onExchange: ex => {
              exchanges.push(ex)
              const id = params.onExchange?.(ex)
              if (typeof id === 'string' && id) exchangeIds.push(id)
              return id
            },
          }
        })
        const visits = await scopedBrowser.runBrowserSession(sessionSteps, grant, signal)
        for (let i = 0; i < spec.steps.length; i += 1) {
          const visit = visits[i]
          if (visit) recordVisitStep(spec.steps[i], visit)
        }
      } else {
        // Fallback for unit-test mocks (e.g. M1.10 fakeBrowser) implementing only visitPage()
        let lastPathAndQuery: string | undefined
        let activeRole: 'control' | 'probe' | null = null
        let lastPersona: string | undefined
        let lastOrigin: string | undefined

        for (const step of spec.steps) {
          signal.throwIfAborted()
          if (step.resetContext === true) {
            activeRole = null
          }
          const resetGroupBoundary =
            (step.role === 'control' && activeRole === 'probe') ||
            (step.role === 'probe' && activeRole === 'control') ||
            lastPersona !== (step.persona ?? undefined) ||
            lastOrigin !== step.origin ||
            step.resetContext === true ||
            step.reusePage === false
          if (resetGroupBoundary) {
            lastPathAndQuery = undefined
          }
          const rawPath = step.pathAndQuery ?? lastPathAndQuery ?? '/'
          const pathAndQuery = interpolateString(rawPath, vars)
          lastPathAndQuery = pathAndQuery
          if (step.role === 'control' || step.role === 'probe') {
            activeRole = step.role
          }
          lastPersona = step.persona ?? undefined
          lastOrigin = step.origin
          const postMessagePayload = step.postMessagePayload !== undefined
            ? interpolateValue(step.postMessagePayload, vars)
            : undefined
          const resolvedCheckKind = step.checkKind
            ?? (step.action === 'postmessage_probe' ? 'postmessage'
              : (step.action === 'dom_check' || step.action === 'dom_xss_sink_hook') ? 'dom_xss'
                : undefined)
          const enableSinkHook = Boolean(step.enableSinkHook || step.action === 'dom_xss_sink_hook')
          const stepActions = buildStepActions(step)

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
            actions: stepActions.length > 0 ? stepActions : undefined,
            enableSinkHook,
            waitAfterLoadMs: step.waitAfterLoadMs,
            onExchange: ex => {
              exchanges.push(ex)
              const id = params.onExchange?.(ex)
              if (typeof id === 'string' && id) exchangeIds.push(id)
              return id
            },
          }, grant, signal)
          recordVisitStep(step, visit)
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
        domSinkTraces,
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
      const setupSummaries: Array<Record<string, unknown>> = []
      const cleanupSummaries: Array<Record<string, unknown>> = []

      // Ordered prerequisites (create cart, read balance, mint stock) feed the burst through vars.
      for (const step of spec.setupSteps ?? []) {
        signal.throwIfAborted()
        const setupReq = stepToBrokerRequest(step, vars)
        if (hasDestructiveContent(JSON.stringify(setupReq))) {
          return inconclusiveResult('Interpolated race_burst setupStep matched destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
        }
        const setupEx = await broker.executeHttp(setupReq, grant, signal)
        recordExchange(setupEx)
        extractVariables(step, setupEx, vars)
        setupSummaries.push({ id: step.id, role: step.role, ...summarizeExchange(setupEx) })
      }

      const runCleanup = async (): Promise<void> => {
        for (const step of spec.cleanupSteps ?? []) {
          const cleanupReq = stepToBrokerRequest(step, vars)
          if (hasDestructiveContent(JSON.stringify(cleanupReq))) {
            cleanupSummaries.push({ id: step.id, role: step.role, skipped: 'destructive-denylist' })
            continue
          }
          try {
            const cleanupEx = await broker.executeHttp(cleanupReq, grant, signal)
            recordExchange(cleanupEx)
            extractVariables(step, cleanupEx, vars)
            cleanupSummaries.push({ id: step.id, role: step.role, ...summarizeExchange(cleanupEx) })
          } catch (err) {
            cleanupSummaries.push({
              id: step.id, role: step.role,
              error: redact(err instanceof Error ? err.message : String(err), grant.secrets ?? []).slice(0, 200),
            })
          }
        }
      }

      try {
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
          ...(setupSummaries.length > 0 ? { setup: setupSummaries } : {}),
          control: controlSummary,
          burst: {
            summary: burstResult.summary,
            results: burstResult.results.map(summarizeExchange),
          },
          postCheck: postCheckSummary,
          extractedVars: vars,
        }
      } finally {
        await runCleanup()
        if (cleanupSummaries.length > 0) evidencePayload = { ...evidencePayload, cleanup: cleanupSummaries }
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
        controlVars.canary_dns_host = controlCanary.dnsHost
        probeVars.canary_token = probeCanary.token
        probeVars.canary_url = probeCanary.url
        probeVars.canary_dns_host = probeCanary.dnsHost
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
          deterministicProofPassed = inProbe && !inControl && !inOutbound
          proofMeta.mathVerified = deterministicProofPassed
          proofMeta.productInProbe = inProbe
          proofMeta.productInControl = inControl
        } else if (spec.proofMode === 'split_echo' && expectedSplitAssembled) {
          const inProbe = probeEx.body.includes(expectedSplitAssembled)
          const inControl = controlEx.body.includes(expectedSplitAssembled)
          const inOutbound = serializedProbeReq.includes(expectedSplitAssembled)
          deterministicProofPassed = inProbe && !inControl && !inOutbound
          proofMeta.splitEchoVerified = deterministicProofPassed
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
          deterministicProofPassed = probeCheck.triggered && !controlCheck.triggered
          proofMeta.canaryProbeTriggered = probeCheck.triggered
          proofMeta.canaryProbeDetail = probeCheck.detail
          proofMeta.canaryControlTriggered = controlCheck.triggered
          proofMeta.canaryControlDetail = controlCheck.detail
        }

        proofMeta.cryptographicProofPassed = deterministicProofPassed
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
    } else if (spec.kind === 'sql_boolean_diff') {
      const roundCount = 3
      const usedKs = new Set<number>()
      const baseValue = spec.baselineValue
      const makeValue = (k: number, kind: 'true' | 'false'): string => {
        const expr = `${k}=${kind === 'true' ? k : k + 1}`
        if (spec.valueTemplate) {
          return spec.valueTemplate.replaceAll('{{baseline}}', baseValue).replaceAll('{{sql_expr}}', expr)
        }
        if (spec.quoteStyle === 'numeric') return `${baseValue} AND ${expr}`
        if (spec.quoteStyle === 'double') return `${baseValue}" AND ${expr}-- -`
        return `${baseValue}' AND ${expr}-- -`
      }
      const buildRequest = (value: string): BrokerHttpRequest => {
        const injected = injectUniversalParam({
          pathAndQuery: spec.pathAndQuery,
          param: spec.paramName,
          paramLocation: spec.paramLocation,
          value,
          method: spec.method,
          headers: spec.headers,
          jsonBody: (spec.jsonBody && typeof spec.jsonBody === 'object' && !Array.isArray(spec.jsonBody))
            ? spec.jsonBody as Record<string, unknown>
            : undefined,
          xmlTemplate: spec.xmlTemplate,
          graphqlQuery: spec.graphqlQuery,
          session: spec.session,
          csrfBind: spec.csrfBind,
          runId: params.runId,
          assignmentId,
        })
        return {
          origin: spec.targetOrigin,
          persona: spec.persona,
          followRedirects: false,
          // Share the priming step's jar so session cookies / CSRF tokens bound by it are visible.
          ...(spec.controlStep && spec.controlStep.role !== 'cleanup' ? { sessionGroupRole: spec.controlStep.role } : {}),
          ...injected,
        }
      }

      let controlSummary: Record<string, unknown> | null = null
      let controlHealthy = true
      if (spec.controlStep) {
        const controlEx = await broker.executeHttp(stepToBrokerRequest(spec.controlStep, {}, {
          runId: params.runId,
          assignmentId,
        }), grant, signal)
        recordExchange(controlEx)
        controlSummary = { id: spec.controlStep.id, role: spec.controlStep.role, ...summarizeExchange(controlEx) }
        if (isUnexpectedErrorStatus(controlEx.status, spec.controlStep.expectedStatus, spec.expectedStatus)) controlHealthy = false
      }

      const rounds: Array<Record<string, unknown>> = []
      let firstBaseline: BrokerExchangeResult | undefined
      let firstTrue: BrokerExchangeResult | undefined
      let firstFalse: BrokerExchangeResult | undefined
      let allPass = true
      let unstable = false
      let baselineDrift = false
      for (let r = 0; r < roundCount; r += 1) {
        signal.throwIfAborted()
        let k = randomInt(1000, 90_000)
        while (usedKs.has(k)) k = randomInt(1000, 90_000)
        usedKs.add(k)
        // Interleaved baseline / true / false triplet through RequestBroker.
        const baseEx = await broker.executeHttp(buildRequest(baseValue), grant, signal)
        recordExchange(baseEx)
        const trueEx = await broker.executeHttp(buildRequest(makeValue(k, 'true')), grant, signal)
        recordExchange(trueEx)
        const falseEx = await broker.executeHttp(buildRequest(makeValue(k, 'false')), grant, signal)
        recordExchange(falseEx)
        firstBaseline ??= baseEx
        firstTrue ??= trueEx
        firstFalse ??= falseEx
        const simBaselineTrue = responseSimilarity(baseEx.body, trueEx.body)
        const simBaselineFalse = responseSimilarity(baseEx.body, falseEx.body)
        const simTrueFalse = responseSimilarity(trueEx.body, falseEx.body)
        const isOrBranch = /\bOR\b/i.test(spec.valueTemplate ?? '')
        const statusDivergence = isOrBranch
          ? (falseEx.status === baseEx.status && trueEx.status !== falseEx.status && trueEx.status < 500) ||
            (baseEx.status === trueEx.status && falseEx.status !== trueEx.status && falseEx.status < 500)
          : (baseEx.status === trueEx.status && falseEx.status !== trueEx.status && falseEx.status < 500)
        const anyServerError = [baseEx, trueEx, falseEx].some(e => e.status >= 500)
        if (anyServerError) unstable = true
        if (isUnexpectedErrorStatus(baseEx.status, spec.expectedStatus) || isUnexpectedErrorStatus(trueEx.status, spec.expectedStatus)) {
          controlHealthy = false
        }
        if (responseSimilarity(firstBaseline.body, baseEx.body) < 0.9) baselineDrift = true
        const baselineMatch = isOrBranch ? Math.max(simBaselineTrue, simBaselineFalse) >= 0.9 : simBaselineTrue >= 0.9
        const pass = !anyServerError && baselineMatch && (simTrueFalse <= 0.75 || statusDivergence)
        if (!pass) allPass = false
        rounds.push({
          round: r + 1, k,
          trueExpression: `${k}=${k}`, falseExpression: `${k}=${k + 1}`,
          baseline: lightSummary(baseEx), true: lightSummary(trueEx), false: lightSummary(falseEx),
          similarityBaselineTrue: simBaselineTrue, similarityBaselineFalse: simBaselineFalse, similarityTrueFalse: simTrueFalse, statusDivergence, isOrBranch, pass,
        })
      }
      const controlPassed = controlHealthy && !unstable && !baselineDrift
      deterministicProofPassed = controlPassed && allPass
      if (!deterministicProofPassed) {
        proofFailureReason = !controlPassed
          ? 'sql_boolean_diff control unstable (5xx, unexpected 404 or drifting baseline).'
          : 'Boolean differential did not hold across all 3 randomized rounds.'
      }
      evidencePayload = {
        ...evidencePayload,
        targetOrigin: spec.targetOrigin,
        paramName: spec.paramName,
        quoteStyle: spec.quoteStyle,
        baseline: firstBaseline ? summarizeExchange(firstBaseline) : (rounds[0]?.baseline ?? null),
        trueProbe: firstTrue ? summarizeExchange(firstTrue) : (rounds[0]?.true ?? null),
        falseProbe: firstFalse ? summarizeExchange(firstFalse) : (rounds[0]?.false ?? null),
        sqlDiff: {
          passed: deterministicProofPassed,
          controlPassed,
          thresholds: { trueVsBaselineMin: 0.9, trueVsFalseMax: 0.75 },
          rounds,
        },
        control: controlSummary ?? (rounds[0] ? { role: 'control', ...(rounds[0].baseline as Record<string, unknown>) } : null),
        probe: rounds[0] ? { role: 'probe', ...(rounds[0].true as Record<string, unknown>) } : null,
      }
    } else if (spec.kind === 'ws_chain') {
      const stepsOut: Record<string, unknown> = {}
      let firstControl: Record<string, unknown> | undefined
      let firstProbe: Record<string, unknown> | undefined
      for (const step of spec.steps) {
        signal.throwIfAborted()
        const result = await broker.probeWebsocket({
          origin: step.origin,
          pathAndQuery: step.pathAndQuery,
          originHeader: step.originHeader,
          headers: step.headers,
          persona: step.persona,
          subprotocols: step.subprotocols,
          sendMessages: step.sendMessages,
          maxFrames: step.maxFrames,
          timeoutMs: Math.max(1500, step.waitMs + 1000),
        }, grant, signal)
        recordExchange(websocketResultToExchange(result))
        const received = result.frames.filter(f => f.direction === 'received')
        const messages = received.map(f => f.data)
        let firstJson: unknown = null
        if (messages[0]) {
          try { firstJson = JSON.parse(messages[0]) } catch { firstJson = null }
        }
        const entry: Record<string, unknown> = {
          id: step.id,
          role: step.role,
          status: result.upgradeStatus ?? 0,
          connected: result.connected,
          upgradeStatus: result.upgradeStatus,
          upgradeHeaders: result.upgradeHeaders,
          subprotocol: result.subprotocol,
          originHeader: result.originHeader,
          persona: result.personaHandle,
          sentFrames: result.sentFrames,
          receivedFrames: result.receivedFrames,
          messages,
          firstMessage: messages[0] ?? null,
          body: messages.join('\n'),
          ...(firstJson !== null ? { json: firstJson } : {}),
          closeCode: result.closeCode,
          closeReason: result.closeReason,
          error: result.error,
        }
        stepsOut[step.id] = entry
        if (step.role === 'control' && !firstControl) firstControl = entry
        if (step.role === 'probe' && !firstProbe) firstProbe = entry
        if (
          guardControlErrors && (step.role === 'control' || step.role === 'probe') && result.upgradeStatus !== null &&
          isUnexpectedErrorStatus(result.upgradeStatus, spec.expectedStatus)
        ) {
          forcedInconclusiveReason ??= `Unexpected HTTP ${result.upgradeStatus} on WebSocket ${step.role} step "${step.id}" (requireControlNonError).`
        }
      }
      evidencePayload = {
        ...evidencePayload,
        steps: stepsOut,
        ...(firstControl ? { control: firstControl } : {}),
        ...(firstProbe ? { probe: firstProbe } : {}),
      }
    } else if (spec.kind === 'upload_probe') {
      const vars: Record<string, string> = { upload_nonce: `gup${randomAlphaToken(18)}` }
      const nonce = vars.upload_nonce
      const stepsOut: Record<string, unknown> = {}
      let controlLeak = false
      if (spec.controlStep) {
        const controlEx = await broker.executeHttp(stepToBrokerRequest(spec.controlStep, vars), grant, signal)
        recordExchange(controlEx)
        extractVariables(spec.controlStep, controlEx, vars)
        controlLeak = controlEx.body.includes(nonce)
        stepsOut[spec.controlStep.id] = { id: spec.controlStep.id, role: spec.controlStep.role, ...summarizeExchange(controlEx) }
        if (guardControlErrors && isUnexpectedErrorStatus(controlEx.status, spec.controlStep.expectedStatus, spec.expectedStatus)) {
          forcedInconclusiveReason = `Unexpected HTTP ${controlEx.status} on upload_probe control step (requireControlNonError).`
        }
      }
      const up = spec.uploadStep
      const uploadHeaders: Record<string, string> = {}
      for (const [k, v] of Object.entries(up.headers ?? {})) uploadHeaders[k] = interpolateString(v, vars)
      const parts = [
        {
          name: up.fieldName,
          filename: interpolateString(up.filename, vars),
          contentType: up.contentType,
          content: interpolateString(up.contentTemplate, vars),
        },
        ...Object.entries(up.extraFields ?? {}).map(([name, value]) => ({
          name, contentType: 'text/plain', content: interpolateString(value, vars),
        })),
      ]
      let fetchExchange: BrokerExchangeResult | undefined
      try {
        const uploadEx = await broker.executeHttp({
          origin: up.origin, method: up.method, pathAndQuery: interpolateString(up.pathAndQuery, vars),
          headers: uploadHeaders, multipartParts: parts, persona: up.persona, followRedirects: false,
        }, grant, signal)
        recordExchange(uploadEx)
        extractVariables({ ...up, request: undefined as never, extract: up.extract } as unknown as ReplayStep, uploadEx, vars)
        stepsOut[up.id] = { id: up.id, role: up.role, ...summarizeExchange(uploadEx) }

        fetchExchange = await broker.executeHttp(stepToBrokerRequest(spec.fetchStep, vars), grant, signal)
        recordExchange(fetchExchange)
        stepsOut[spec.fetchStep.id] = { id: spec.fetchStep.id, role: spec.fetchStep.role, ...summarizeExchange(fetchExchange) }
      } finally {
        if (spec.cleanupStep) {
          try {
            const cleanupEx = await broker.executeHttp(stepToBrokerRequest(spec.cleanupStep, vars), grant, signal)
            recordExchange(cleanupEx)
            stepsOut[spec.cleanupStep.id] = { id: spec.cleanupStep.id, role: 'cleanup', ...summarizeExchange(cleanupEx) }
          } catch (cleanupErr) {
            stepsOut[spec.cleanupStep.id] = { id: spec.cleanupStep.id, role: 'cleanup', error: cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr) }
          }
        }
      }
      const fetched = fetchExchange
      const contentType = (fetched?.respHeaders['content-type'] ?? fetched?.mediaType ?? '').toLowerCase()
      const disposition = fetched?.respHeaders['content-disposition'] ?? null
      const attachment = Boolean(disposition && /^\s*attachment/i.test(disposition))
      const unsafeType = /text\/html|image\/svg\+xml|application\/xhtml\+xml/.test(contentType)
      const nonceInFetch = Boolean(fetched && fetched.body.includes(nonce))
      const fetchOk = Boolean(fetched && fetched.status >= 200 && fetched.status < 300)
      deterministicProofPassed = nonceInFetch && fetchOk && !controlLeak
      if (!deterministicProofPassed) proofFailureReason = 'Verifier-minted upload nonce was not retrievable from the fetch step (or leaked on control).'
      if (guardControlErrors && fetched && isUnexpectedErrorStatus(fetched.status, spec.fetchStep.expectedStatus, spec.expectedStatus)) {
        forcedInconclusiveReason ??= `Unexpected HTTP ${fetched.status} on upload_probe fetch step (requireControlNonError).`
      }
      evidencePayload = {
        ...evidencePayload,
        uploadNonce: nonce,
        steps: stepsOut,
        extractedVars: vars,
        uploadProof: {
          nonceInFetchBody: nonceInFetch,
          fetchStatus: fetched?.status ?? null,
          fetchContentType: contentType || null,
          contentDisposition: disposition,
          hasAttachmentDisposition: attachment,
          unsafeInlineRender: unsafeType && !attachment,
          controlLeak,
        },
        ...(spec.controlStep ? { control: stepsOut[spec.controlStep.id] } : {}),
        probe: stepsOut[spec.fetchStep.id],
      }
    } else if (spec.kind === 'static_ast_proof') {
      if (!params.reposDir) {
        return inconclusiveResult('static_ast_proof requires the read-only /repos mount (reposDir).', exchanges, exchangeIds, { kind: spec.kind })
      }
      const astResult = await backend.verifyStaticAst(assignmentId, {
        repo: spec.repo,
        file: spec.file,
        startLine: spec.startLine,
        endLine: spec.endLine,
        engine: spec.engine,
        ruleOrPattern: spec.ruleOrPattern,
      }, signal, { reposDir: params.reposDir })
      deterministicProofPassed = Boolean(astResult.verified)
      if (!deterministicProofPassed) proofFailureReason = `Static AST re-verification failed: ${astResult.reason ?? 'pattern not found in the cited range.'}`
      evidencePayload = {
        ...evidencePayload,
        repo: spec.repo,
        file: spec.file,
        startLine: spec.startLine,
        endLine: spec.endLine,
        engine: spec.engine,
        ruleOrPattern: spec.ruleOrPattern,
        sourceToSinkTrace: spec.sourceToSinkTrace ?? null,
        runtimeProofGap: spec.runtimeProofGap,
        verificationTier: 'static_verified',
        astVerify: astResult,
        static: {
          verified: astResult.verified,
          matchCount: astResult.matchCount,
          matchedLines: astResult.matchedLines,
          controlPassed: astResult.verified,
        },
      }
    } else if (spec.kind === 'auth_protocol_proof') {
      const vars: Record<string, string> = {}
      const stepsOut: Record<string, unknown> = {}
      const probeStepExchanges: Array<{ id: string; exchange: BrokerExchangeResult }> = []
      const replayJarPrefix = randomUUID().slice(0, 8)
      let firstControlStep: Record<string, unknown> | undefined
      let firstProbeStep: Record<string, unknown> | undefined

      // Body-token routes never expose the signing credential as a bearer header. Mint unsigned
      // token material locally from the spec's data-anchored claims, then let the step body carry it.
      const mintedTokens: Array<{ name: string; alg: string }> = []
      if (spec.tokenMints?.length) {
        const nowSeconds = Math.floor(Date.now() / 1000)
        vars.now = String(nowSeconds)
        vars.now_plus_1h = String(nowSeconds + 3600)
        for (const mint of spec.tokenMints) {
          const header = { alg: mint.signature === 'none' ? 'none' : 'HS256', typ: 'JWT', ...(mint.header ?? {}) }
          // Time claims stay numeric: `{{now}}`-style placeholders are resolved before generic
          // string interpolation (which would otherwise emit quoted numbers).
          const resolveClaims = (value: unknown): unknown => {
            if (value === '{{now}}') return nowSeconds
            if (value === '{{now_plus_1h}}') return nowSeconds + 3600
            if (Array.isArray(value)) return value.map(resolveClaims)
            if (value && typeof value === 'object') {
              return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, resolveClaims(v)]))
            }
            return value
          }
          const headerJson = interpolateValue(resolveClaims(header), vars) as Record<string, unknown>
          const payloadJson = interpolateValue(resolveClaims(mint.payload), vars) as Record<string, unknown>
          vars[mint.name] = `${base64urlJson(headerJson)}.${base64urlJson(payloadJson)}.`
          mintedTokens.push({ name: mint.name, alg: String(headerJson.alg ?? 'none') })
        }
      }

      const serializedSteps = JSON.stringify(spec.steps)
      const needsCanary = spec.steps.some(s => s.request.authMutation?.kind === 'jku_x5u_canary') ||
        /\{\{canary_(?:url|token|dns_host)\}\}/.test(serializedSteps)
      let canarySession: EphemeralCanarySession | undefined
      let ctrlCanary: { url: string; token: string; dnsHost: string } | undefined
      let prbCanary: { url: string; token: string; dnsHost: string } | undefined
      let controlCanaryToken: string | undefined
      let probeCanaryToken: string | undefined

      if (needsCanary) {
        canarySession = await openCanarySession(params.canaryBroker, params.storage, params.runId, assignmentId, spec.origin)
        ctrlCanary = canarySession.mint(`auth_protocol_proof:control:${spec.title}`)
        prbCanary = canarySession.mint(`auth_protocol_proof:probe:${spec.title}`)
        controlCanaryToken = ctrlCanary.token
        probeCanaryToken = prbCanary.token
      }

      try {
        for (const step of spec.steps) {
          signal.throwIfAborted()
          const stepVars: Record<string, string> = { ...vars }
          if (ctrlCanary && prbCanary) {
            const activeCanary = step.role === 'control' ? ctrlCanary : prbCanary
            stepVars.canary_url = activeCanary.url
            stepVars.canary_token = activeCanary.token
            stepVars.canary_dns_host = activeCanary.dnsHost
          }
          const brokerReq = stepToBrokerRequest(step, stepVars, {
            replayJarPrefix,
            runId: params.runId,
            assignmentId,
          })
          if (brokerReq.authMutation?.kind === 'jku_x5u_canary' && !brokerReq.authMutation.url && !brokerReq.authMutation.value && ctrlCanary && prbCanary) {
            const targetCanaryUrl = step.role === 'control' ? ctrlCanary.url : prbCanary.url
            brokerReq.authMutation = { ...brokerReq.authMutation, url: targetCanaryUrl }
          }
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

        if (guardControlErrors) {
          for (const step of spec.steps) {
            if (step.role !== 'control' && step.role !== 'probe') continue
            const status = (stepsOut[step.id] as { status?: number } | undefined)?.status
            if (typeof status === 'number' && isUnexpectedErrorStatus(status, step.expectedStatus, spec.expectedStatus)) {
              // On probe steps, allow error status if assertionsJq explicitly asserts that error status
              // (e.g. error-based SQLi testing `.steps.p1.status == 500` while control step is 200).
              if (step.role === 'probe') {
                const statusAssertedInJq =
                  new RegExp(`status\\s*==\\s*${status}\\b|\\b${status}\\s*==\\s*[^;]*status`).test(spec.assertionsJq) ||
                  (status >= 500 && /status\s*>=\s*500\b/.test(spec.assertionsJq))
                if (statusAssertedInJq) continue
              }
              forcedInconclusiveReason = `Unexpected HTTP ${status} on ${step.role} step "${step.id}" (requireControlNonError); declare expectedStatus ${status} to test error behavior.`
              break
            }
          }
        }

        let canaryProof: Record<string, unknown> | undefined
        if (canarySession && probeCanaryToken && controlCanaryToken) {
          let probeCheck = canarySession.check(probeCanaryToken)
          for (let attempt = 0; attempt < 10 && !probeCheck.triggered; attempt += 1) {
            await sleepAbortable(150, signal)
            probeCheck = canarySession.check(probeCanaryToken)
          }
          const controlCheck = canarySession.check(controlCanaryToken)
          deterministicProofPassed = probeCheck.triggered && !controlCheck.triggered
          if (!deterministicProofPassed) {
            proofFailureReason = 'auth_protocol_proof OOB canary callback did not trigger exclusively on probe step.'
          }
          canaryProof = {
            probeTriggered: probeCheck.triggered,
            controlTriggered: controlCheck.triggered,
            probeDetail: probeCheck.detail,
            controlDetail: controlCheck.detail,
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
          spaCatchall = { path: catchallPath, ...summarizeExchange(catchallEx), comparisons, allProbesMatchedCatchall }
          if (allProbesMatchedCatchall) {
            forcedInconclusiveReason = 'Probe response is structurally indistinguishable from an HTTP 200 SPA catch-all route.'
          }
        }

        evidencePayload = {
          ...evidencePayload,
          protocol: spec.protocol,
          steps: stepsOut,
          ...(firstControlStep ? { control: firstControlStep } : {}),
          ...(firstProbeStep ? { probe: firstProbeStep } : {}),
          extractedVars: vars,
          ...(mintedTokens.length > 0 ? { mintedTokens } : {}),
          ...(canaryProof ? { canaryProof } : {}),
          ...(spaCatchall ? { spaCatchall } : {}),
        }
      } finally {
        await canarySession?.close()
      }
    } else if (spec.kind === 'cache_differential') {
      const controlGcb = randomUUID()
      const probeGcb = randomUUID()
      const repeatGcb = randomUUID()
      const resolveCachePath = (raw: string, token: string): string =>
        raw.replaceAll('{{control_gcb}}', controlGcb)
          .replaceAll('{{probe_gcb}}', probeGcb)
          .replaceAll('{{repeat_gcb}}', repeatGcb)
          .replaceAll('{{cache_buster}}', token)

      const controlPath = resolveCachePath(spec.controlPath, controlGcb)
      const probePath = resolveCachePath(spec.probePath, probeGcb)
      const verifyPath = spec.verifyPath ? resolveCachePath(spec.verifyPath, probeGcb) : probePath
      const repeatPath = spec.repeatPath ? resolveCachePath(spec.repeatPath, repeatGcb) : null

      const actualCtrlGcb = extractCacheBusterParam(controlPath)
      const actualProbeGcb = extractCacheBusterParam(probePath)
      if (!actualCtrlGcb || !cacheBusterValueRegex.test(actualCtrlGcb) ||
          !actualProbeGcb || !cacheBusterValueRegex.test(actualProbeGcb)) {
        return inconclusiveResult('cache_differential requires valid ?_gcb=<16-36 hex/uuid> tokens.', exchanges, exchangeIds, { kind: spec.kind })
      }
      if (actualCtrlGcb.toLowerCase() === actualProbeGcb.toLowerCase()) {
        return inconclusiveResult('cache_differential cannot reuse _gcb between control and probe.', exchanges, exchangeIds, { kind: spec.kind })
      }
      if (spec.proofMode === 'body_repeat' && !repeatPath) {
        return inconclusiveResult('cache_differential body_repeat proof requires a repeatPath.', exchanges, exchangeIds, { kind: spec.kind })
      }

      const controlEx = await broker.executeHttp({
        origin: spec.targetOrigin,
        method: spec.method,
        pathAndQuery: controlPath,
        ...(spec.controlPersona ? { persona: spec.controlPersona } : {}),
        probeClass: 'cache_differential',
        followRedirects: false,
        runId: params.runId,
        assignmentId,
      }, grant, signal)
      recordExchange(controlEx)

      const probeEx = await broker.executeHttp({
        origin: spec.targetOrigin,
        method: spec.method,
        pathAndQuery: probePath,
        headers: spec.poisonHeaders,
        persona: spec.poisonPersona,
        probeClass: 'cache_poison_deception',
        followRedirects: false,
        runId: params.runId,
        assignmentId,
      }, grant, signal)
      recordExchange(probeEx)

      const verifyEx = await broker.executeHttp({
        origin: spec.targetOrigin,
        method: spec.method,
        pathAndQuery: verifyPath,
        ...(spec.verifyPersona ? { persona: spec.verifyPersona } : {}),
        probeClass: 'cache_differential',
        cacheVerify: true,
        followRedirects: false,
        runId: params.runId,
        assignmentId,
      }, grant, signal)
      recordExchange(verifyEx)

      // Header-free persistence: re-fetch the (broken) cache key after a short delay. A fresh
      // cache-buster is used so a cache that keys on the full query string cannot confirm by accident.
      let repeatEx: BrokerExchangeResult | null = null
      if (spec.proofMode === 'body_repeat' && repeatPath) {
        await sleepAbortable(150, signal)
        repeatEx = await broker.executeHttp({
          origin: spec.targetOrigin,
          method: spec.method,
          pathAndQuery: repeatPath,
          ...(spec.verifyPersona ? { persona: spec.verifyPersona } : {}),
          probeClass: 'cache_differential',
          cacheVerify: true,
          followRedirects: false,
          runId: params.runId,
          assignmentId,
        }, grant, signal)
        recordExchange(repeatEx)
      }

      if (guardControlErrors) {
        if (isUnexpectedErrorStatus(controlEx.status, spec.expectedStatus)) {
          forcedInconclusiveReason = `Unexpected HTTP ${controlEx.status} on cache_differential control step (requireControlNonError).`
        } else if (isUnexpectedErrorStatus(verifyEx.status, spec.expectedStatus)) {
          forcedInconclusiveReason = `Unexpected HTTP ${verifyEx.status} on cache_differential verify step (requireControlNonError).`
        }
      }

      const ageRaw = verifyEx.respHeaders.age
      const age = ageRaw !== undefined ? Number(ageRaw) : NaN
      const cacheHeaderSignal = [
        verifyEx.respHeaders['x-cache'],
        verifyEx.respHeaders['cf-cache-status'],
        verifyEx.respHeaders['x-cache-status'],
        verifyEx.respHeaders['x-proxy-cache'],
        verifyEx.respHeaders['cache-status'],
      ].some(v => typeof v === 'string' && /\bhit\b/i.test(v))
      const simControlVsVerify = responseSimilarity(controlEx.body, verifyEx.body)
      const simProbeVsVerify = responseSimilarity(probeEx.body, verifyEx.body)

      let cacheHitObserved: boolean
      let poisonPersistedToVictim: boolean
      let markerInControl = false
      let markerInProbe = false
      let markerInVerify = false
      let markerInRepeat = false
      let repeatBodyMatches = false
      let timingSignal = false
      if (spec.proofMode === 'body_repeat') {
        const marker = spec.marker
        markerInControl = Boolean(marker && controlEx.body.includes(marker))
        markerInProbe = Boolean(marker && probeEx.body.includes(marker))
        markerInVerify = Boolean(marker && verifyEx.body.includes(marker))
        markerInRepeat = Boolean(marker && repeatEx?.body.includes(marker))
        // Actor differential: the poisoned entry populated by one persona must be served to a
        // different (or anonymous) client. Same-actor repeats never prove cross-actor exposure.
        const actorDifferential = Boolean(spec.poisonPersona) &&
          (spec.verifyPersona ?? null) !== spec.poisonPersona
        // Cross-actor body equality is the header-free cache signature: a clean client receives the
        // warm client's exact body (or the warm marker) while the clean control differs.
        const bodyPersisted = verifyEx.body === probeEx.body && verifyEx.body !== controlEx.body
        repeatBodyMatches = Boolean(repeatEx && repeatEx.body === verifyEx.body && repeatEx.body !== controlEx.body)
        const markerPersisted = Boolean(marker) && markerInProbe && markerInVerify && !markerInControl
        cacheHitObserved = Boolean(marker) ? markerPersisted : bodyPersisted
        poisonPersistedToVictim = actorDifferential && cacheHitObserved && repeatBodyMatches &&
          (!marker || markerInRepeat)
        // Timing is a persistence signal (the poisoned entry survives past the warm request), not a
        // latency measurement: local caches render in <1 ms and wall-clock deltas are pure noise.
        timingSignal = Boolean(repeatEx) && repeatBodyMatches
      } else {
        cacheHitObserved = (Number.isFinite(age) && age > 0) || cacheHeaderSignal
        poisonPersistedToVictim =
          (simControlVsVerify < 0.95 || verifyEx.status !== controlEx.status) &&
          (simProbeVsVerify >= 0.85 || verifyEx.status === probeEx.status)
      }

      deterministicProofPassed = cacheHitObserved && poisonPersistedToVictim
      if (!deterministicProofPassed) {
        proofFailureReason = spec.proofMode === 'body_repeat'
          ? (!cacheHitObserved
            ? 'Header-free cache proof: the clean verify did not receive the warm marker/body.'
            : 'Header-free cache proof: repeat fetch did not reproduce the poisoned body, or the control did not differ.')
          : !cacheHitObserved
            ? 'Verify request did not observe a cache hit (missing HIT header or Age > 0).'
            : 'Clean unauthenticated verify response matched clean control rather than poisoned probe.'
      }

      let spaCatchall: Record<string, unknown> | undefined
      if (spec.spaCatchallControl) {
        const catchallPath = `/.guardian-nonexistent-${randomUUID()}`
        const catchallEx = await broker.executeHttp({
          origin: spec.targetOrigin,
          method: 'GET',
          pathAndQuery: catchallPath,
          followRedirects: true,
        }, grant, signal)
        recordExchange(catchallEx)
        const diff = diffResponse(
          { status: catchallEx.status, body: catchallEx.body, mediaType: catchallEx.mediaType },
          { status: verifyEx.status, body: verifyEx.body, mediaType: verifyEx.mediaType },
        )
        spaCatchall = {
          path: catchallPath,
          ...summarizeExchange(catchallEx),
          comparisons: { verify: diff },
          allProbesMatchedCatchall: diff.likelySpaCatchall,
        }
        if (diff.likelySpaCatchall) {
          forcedInconclusiveReason = 'cache_differential verify response is structurally indistinguishable from an HTTP 200 SPA catch-all route.'
        }
      }

      const controlSummary = { id: 'control', role: 'control', ...summarizeExchange(controlEx) }
      const probeSummary = { id: 'probe', role: 'probe', ...summarizeExchange(probeEx) }
      const verifySummary = { id: 'verify', role: 'probe', ...summarizeExchange(verifyEx) }
      const repeatSummary = repeatEx ? { id: 'repeat', role: 'probe', ...summarizeExchange(repeatEx) } : undefined

      evidencePayload = {
        ...evidencePayload,
        targetOrigin: spec.targetOrigin,
        mode: spec.mode,
        control: controlSummary,
        probe: probeSummary,
        verify: verifySummary,
        ...(repeatSummary ? { repeat: repeatSummary } : {}),
        steps: { control: controlSummary, probe: probeSummary, verify: verifySummary, ...(repeatSummary ? { repeat: repeatSummary } : {}) },
        ...(spaCatchall ? { spaCatchall } : {}),
        cacheProof: {
          mode: spec.mode,
          proofMode: spec.proofMode,
          controlGcb: actualCtrlGcb,
          probeGcb: actualProbeGcb,
          cacheHitObserved,
          poisonPersistedToVictim,
          simControlVsVerify,
          simProbeVsVerify,
          age: Number.isFinite(age) ? age : null,
          markerPresent: Boolean(spec.marker),
          markerInControl,
          markerInProbe,
          markerInVerify,
          markerInRepeat,
          repeatBodyMatches,
          timingSignal,
        },
      }
    } else if (spec.kind === 'sql_time_diff') {
      const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
      if (!localLab) {
        if (tier < 3) {
          grant.audit('denied', spec.targetOrigin)
          return inconclusiveResult('sql_time_diff is blocked on public projects below Tier 3 (requires local-lab or Tier 3 HITL approval).', exchanges, exchangeIds, { kind: spec.kind })
        }
        const approved = grant.isStateChangeApproved
          ? grant.isStateChangeApproved(spec.targetOrigin, spec.method, spec.pathAndQuery)
          : false
        if (!approved) {
          grant.audit('denied', spec.targetOrigin)
          return inconclusiveResult('sql_time_diff requires explicit Tier 3 HITL operator approval on public targets.', exchanges, exchangeIds, { kind: spec.kind })
        }
      }

      const delayMs = Math.max(1500, Math.min(3000, spec.delayMs ?? randomInt(1500, 2601)))
      const delaySec = Number((delayMs / 1000).toFixed(3))
      const delaySecInt = Math.max(1, Math.round(delayMs / 1000))
      const baseValue = spec.baselineValue

      const makeDelayPayload = (): string => {
        if (spec.valueTemplate) {
          return spec.valueTemplate
            .replaceAll('{{baseline}}', baseValue)
            .replaceAll('{{delay_ms}}', String(delayMs))
            .replaceAll('{{delay_sec}}', String(delaySec))
        }
        let fnExpr: string
        if (spec.dialect === 'mysql') fnExpr = `SLEEP(${delaySec})`
        else if (spec.dialect === 'mssql') fnExpr = `WAITFOR DELAY '0:0:${delaySecInt}'`
        else if (spec.dialect === 'sqlite') fnExpr = `1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(${Math.min(90_000_000, delayMs * 25_000)}))))`
        else fnExpr = `(SELECT 1 FROM pg_sleep(${delaySec})) IS NULL`

        if (spec.dialect === 'mssql') {
          return spec.quoteStyle === 'numeric'
            ? `${baseValue}; ${fnExpr}`
            : spec.quoteStyle === 'double'
              ? `${baseValue}"; ${fnExpr}-- -`
              : `${baseValue}'; ${fnExpr}-- -`
        }
        if (spec.quoteStyle === 'numeric') return `${baseValue} AND ${fnExpr}`
        if (spec.quoteStyle === 'double') return `${baseValue}" AND ${fnExpr}-- -`
        return `${baseValue}' AND ${fnExpr}-- -`
      }

      const buildRequest = (value: string): BrokerHttpRequest => {
        const injected = injectUniversalParam({
          pathAndQuery: spec.pathAndQuery,
          param: spec.paramName,
          paramLocation: spec.paramLocation,
          value,
          method: spec.method,
          headers: spec.headers,
          jsonBody: (spec.jsonBody && typeof spec.jsonBody === 'object' && !Array.isArray(spec.jsonBody))
            ? spec.jsonBody as Record<string, unknown>
            : undefined,
          xmlTemplate: spec.xmlTemplate,
          graphqlQuery: spec.graphqlQuery,
          session: spec.session,
          csrfBind: spec.csrfBind,
          runId: params.runId,
          assignmentId,
        })
        return {
          origin: spec.targetOrigin,
          persona: spec.persona,
          followRedirects: false,
          timeoutMs: Math.max(10_000, delayMs + 5_000),
          ...(spec.controlStep && spec.controlStep.role !== 'cleanup' ? { sessionGroupRole: spec.controlStep.role } : {}),
          ...injected,
        }
      }

      let controlSummary: Record<string, unknown> | null = null
      let controlHealthy = true
      if (spec.controlStep) {
        const ctrlEx = await broker.executeHttp(stepToBrokerRequest(spec.controlStep, {}, {
          runId: params.runId,
          assignmentId,
        }), grant, signal)
        recordExchange(ctrlEx)
        controlSummary = { id: spec.controlStep.id, role: spec.controlStep.role, ...summarizeExchange(ctrlEx) }
        if (isUnexpectedErrorStatus(ctrlEx.status, spec.controlStep.expectedStatus, spec.expectedStatus)) controlHealthy = false
      }

      const roundCount = 3
      const rounds: Array<Record<string, unknown>> = []
      const baseDurations: number[] = []
      const probeDurations: number[] = []
      let anyServerError = false
      const delayPayload = makeDelayPayload()

      for (let r = 0; r < roundCount; r += 1) {
        signal.throwIfAborted()
        const t0 = performance.now()
        const baseEx = await broker.executeHttp(buildRequest(baseValue), grant, signal)
        const baseMeasured = Math.max(baseEx.durationMs, Math.round(performance.now() - t0))
        recordExchange(baseEx)

        const t1 = performance.now()
        const probeEx = await broker.executeHttp(buildRequest(delayPayload), grant, signal)
        const probeMeasured = Math.max(probeEx.durationMs, Math.round(performance.now() - t1))
        recordExchange(probeEx)

        if (baseEx.status >= 500 || probeEx.status >= 500) anyServerError = true
        if (isUnexpectedErrorStatus(baseEx.status, spec.expectedStatus) || isUnexpectedErrorStatus(probeEx.status, spec.expectedStatus)) {
          controlHealthy = false
        }
        baseDurations.push(baseMeasured)
        probeDurations.push(probeMeasured)
        rounds.push({
          round: r + 1,
          baselineMs: baseMeasured,
          probeMs: probeMeasured,
          baseline: lightSummary(baseEx),
          delayProbe: lightSummary(probeEx),
        })
      }

      const median = (arr: number[]) => {
        const sorted = [...arr].sort((a, b) => a - b)
        const m = Math.floor(sorted.length / 2)
        return sorted.length % 2 === 1 ? sorted[m] : (sorted[m - 1] + sorted[m]) / 2
      }
      const baselineMedianMs = median(baseDurations)
      const probeMedianMs = median(probeDurations)
      const deltaMedianMs = probeMedianMs - baselineMedianMs
      const minProbeMs = Math.min(...probeDurations)
      const maxBaselineMs = Math.max(...baseDurations)
      const nonOverlapping = minProbeMs > maxBaselineMs
      const controlPassed = controlHealthy && !anyServerError
      deterministicProofPassed = controlPassed && nonOverlapping && deltaMedianMs >= 0.85 * delayMs
      if (!deterministicProofPassed) {
        proofFailureReason = !controlPassed
          ? 'sql_time_diff control unstable (5xx or unexpected error status).'
          : !nonOverlapping
            ? `Timing overlap detected across 3 rounds (minProbe=${minProbeMs}ms <= maxBaseline=${maxBaselineMs}ms).`
            : `Median timing delta (${deltaMedianMs}ms) fell below 0.85 * ${delayMs}ms.`
      }

      evidencePayload = {
        ...evidencePayload,
        targetOrigin: spec.targetOrigin,
        paramName: spec.paramName,
        paramLocation: spec.paramLocation,
        delayMs,
        sqlTimeDiff: {
          passed: deterministicProofPassed,
          controlPassed,
          delayMs,
          baselineMedianMs,
          probeMedianMs,
          deltaMedianMs,
          minProbeMs,
          maxBaselineMs,
          nonOverlapping,
          rounds,
        },
        control: controlSummary ?? (rounds[0] ? { role: 'control', ...(rounds[0].baseline as Record<string, unknown>) } : null),
        probe: rounds[0] ? { role: 'probe', ...(rounds[0].delayProbe as Record<string, unknown>) } : null,
      }
    }
  } catch (err) {
    const catchSecrets: NamedSecret[] = [
      ...(params.grant.secrets ?? []),
      ...(params.grant.personas ? personaSecrets(params.grant.personas) : []),
      ...(broker.getRegisteredSecrets?.() ?? []),
    ]
    const safePayload = redactJsonValue(evidencePayload, catchSecrets)
    if (err instanceof BrokerDenied || err instanceof BrokerCircuitOpen || err instanceof BrokerApprovalRequired) {
      return inconclusiveResult(redact(err.message, catchSecrets), exchanges, exchangeIds, safePayload)
    }
    const message = redact(err instanceof Error ? err.message : String(err), catchSecrets)
    return inconclusiveResult(`Replay execution failed: ${message}`, exchanges, exchangeIds, safePayload)
  }

  // Scrub any dynamic broker-registered secrets (jar cookies, CSRF tokens, mutated JWTs) + grant/persona secrets
  const dynamicSecrets: NamedSecret[] = [
    ...(params.grant.secrets ?? []),
    ...(params.grant.personas ? personaSecrets(params.grant.personas) : []),
    ...(broker.getRegisteredSecrets?.() ?? []),
  ]
  evidencePayload = redactJsonValue(evidencePayload, dynamicSecrets)

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
      `Verification container failed: ${redact(err instanceof Error ? err.message : String(err), dynamicSecrets)}`,
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

  if (!deterministicProofPassed) {
    return {
      verdict: outcome.controlPassed ? 'dismissed' : 'inconclusive',
      outcome: {
        ...outcome,
        confirmed: false,
        reason: proofFailureReason || 'Cryptographic non-destructive proof-of-execution check did not pass (possible reflection or unexecuted payload).',
      },
      exchangeIds,
      exchanges,
      evidencePayload,
      evidenceSha256,
    }
  }

  let verdict: ReplayVerdict
  if (outcome.controlPassed && outcome.confirmed) {
    // Strict tier separation: static_ast_proof can only ever reach 'static_verified'.
    verdict = spec.kind === 'static_ast_proof' ? 'static_verified' : 'confirmed'
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

export async function verifyReplaySpec(params: VerifyReplaySpecParams): Promise<ReplayVerificationResult> {
  const result = await verifyReplaySpecInner(params)
  const verificationTier: VerificationTier | undefined = result.verdict === 'static_verified'
    ? 'static_verified'
    : result.verdict === 'confirmed' ? 'runtime_confirmed' : undefined
  return { ...result, ...(verificationTier ? { verificationTier } : {}) }
}

export async function retestReplaySpec(params: VerifyReplaySpecParams): Promise<RetestReplayResult> {
  const replay = await verifyReplaySpec(params)
  const verdict: RetestVerdict = replay.verdict === 'confirmed' || replay.verdict === 'static_verified'
    ? 'reproduced'
    : replay.verdict === 'dismissed'
      ? 'fixed'
      : 'inconclusive'
  return { verdict, replay }
}

export interface VerifyReplaySpecInlineParams extends VerifyReplaySpecParams {
  findingId?: string
  attemptCount?: number
  maxRetries?: number
  secrets?: readonly NamedSecret[]
}

export interface InlineReplayVerificationResult {
  feedback: InlineVerifyFeedback
  replay: ReplayVerificationResult
}

function toStepStatusItem(
  id: string,
  role: string,
  entry: Record<string, unknown>,
): InlineVerifyFeedback['stepStatuses'][number] {
  const status = typeof entry.status === 'number' && Number.isFinite(entry.status) ? entry.status : null
  const mediaType = typeof entry.mediaType === 'string' && entry.mediaType ? entry.mediaType : undefined
  const bodyLen = typeof entry.bodyBytes === 'number' && Number.isFinite(entry.bodyBytes)
    ? Math.max(0, Math.round(entry.bodyBytes))
    : typeof entry.body === 'string'
      ? Buffer.byteLength(entry.body, 'utf8')
      : typeof entry.domSnippet === 'string'
        ? Buffer.byteLength(entry.domSnippet, 'utf8')
        : 0
  return {
    id,
    role,
    status,
    ...(mediaType ? { mediaType } : {}),
    bodyLen,
  }
}

export interface InlineExchangeHeaderSummary {
  stepId: string
  status: number
  contentType?: string
  location?: string
  cacheControl?: string
  xCache?: string
  age?: string
  vary?: string
  accessControl?: string
  setCookie?: Array<{ name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }>
}

export interface InlineStepBodyPreview {
  stepId: string
  status: number
  mediaType?: string
  preview: string
  truncated: boolean
}

export interface InlineSqlRoundSummary {
  round: number
  pass?: boolean
  baselineStatus?: number | null
  trueStatus?: number | null
  falseStatus?: number | null
  delayProbeStatus?: number | null
  similarityBaselineTrue?: number
  similarityTrueFalse?: number
  baselineMs?: number
  probeMs?: number
}

/**
 * Enriched inline verification feedback. Extra fields are additive on top of the persisted
 * `InlineVerifyFeedback` contract (the domain schema strips nothing on read), so older consumers
 * and stored rows keep working while the repairing agent gets actionable evidence.
 */
export interface EnrichedInlineVerifyFeedback extends InlineVerifyFeedback {
  replayExchangeIds?: string[]
  keyResponseHeaders?: InlineExchangeHeaderSummary[]
  stepBodyPreviews?: InlineStepBodyPreview[]
  extractedVars?: Array<{ key: string; preview: string }>
  sqlRoundSummaries?: InlineSqlRoundSummary[]
  verificationKind?: string
  /** True when a vertical BFLA (function-level) proof lacked impact evidence. */
  bflaImpactRequired?: boolean
  impactEvidenceMissing?: boolean
}

const inlinePreviewBytes = 512
const maxInlineExchanges = 8
const maxInlineExtractedVars = 12

function sanitizeInlinePreview(text: string, secrets: readonly NamedSecret[]): { preview: string; truncated: boolean } {
  const redacted = redact(text, secrets)
  const cleaned = redacted
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (Buffer.byteLength(cleaned, 'utf8') <= inlinePreviewBytes) return { preview: cleaned, truncated: false }
  const sliced = Buffer.from(cleaned, 'utf8').subarray(0, inlinePreviewBytes).toString('utf8').replace(/\uFFFD+$/, '')
  return { preview: `${sliced}…`, truncated: true }
}

function headerValue(headers: Record<string, string>, name: string): string | undefined {
  const key = Object.keys(headers).find(k => k.toLowerCase() === name)
  return key ? headers[key] : undefined
}

function summarizeKeyResponseHeaders(
  exchanges: readonly BrokerExchangeResult[],
  stepIds: readonly string[],
  secrets: readonly NamedSecret[],
): InlineExchangeHeaderSummary[] {
  const out: InlineExchangeHeaderSummary[] = []
  for (const [idx, ex] of exchanges.slice(0, maxInlineExchanges).entries()) {
    const headers = ex.respHeaders ?? {}
    const accessControl = Object.entries(headers)
      .filter(([k]) => k.toLowerCase().startsWith('access-control-'))
      .map(([k, v]) => `${k.toLowerCase()}: ${redact(v, secrets).slice(0, 120)}`)
      .sort()
      .join('; ')
    const setCookie = (ex.setCookies ?? []).slice(0, 8).map(c => ({
      name: c.name,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
    }))
    out.push({
      stepId: stepIds[idx] ?? `exchange-${idx + 1}`,
      status: ex.status,
      ...(headerValue(headers, 'content-type') ? { contentType: redact(headerValue(headers, 'content-type')!, secrets).slice(0, 120) } : {}),
      ...(headerValue(headers, 'location') ? { location: redact(headerValue(headers, 'location')!, secrets).slice(0, 240) } : {}),
      ...(headerValue(headers, 'cache-control') ? { cacheControl: redact(headerValue(headers, 'cache-control')!, secrets).slice(0, 160) } : {}),
      ...(headerValue(headers, 'x-cache') ? { xCache: redact(headerValue(headers, 'x-cache')!, secrets).slice(0, 80) } : {}),
      ...(headerValue(headers, 'age') ? { age: redact(headerValue(headers, 'age')!, secrets).slice(0, 40) } : {}),
      ...(headerValue(headers, 'vary') ? { vary: redact(headerValue(headers, 'vary')!, secrets).slice(0, 160) } : {}),
      ...(accessControl ? { accessControl } : {}),
      ...(setCookie.length ? { setCookie } : {}),
    })
  }
  return out
}

function summarizeSqlRounds(payload: Record<string, unknown>): InlineSqlRoundSummary[] {
  const sqlDiff = payload.sqlDiff as { rounds?: Array<Record<string, unknown>> } | undefined
  const sqlTimeDiff = payload.sqlTimeDiff as { rounds?: Array<Record<string, unknown>> } | undefined
  const rounds = Array.isArray(sqlDiff?.rounds) ? sqlDiff!.rounds : Array.isArray(sqlTimeDiff?.rounds) ? sqlTimeDiff!.rounds : []
  const num = (value: unknown): number | undefined =>
    typeof value === 'number' && Number.isFinite(value) ? value : undefined
  const status = (value: unknown): number | null =>
    value && typeof value === 'object' && typeof (value as { status?: unknown }).status === 'number'
      ? (value as { status: number }).status
      : null
  return rounds.slice(0, 5).map((r, idx) => ({
    round: num(r.round) ?? idx + 1,
    ...(typeof r.pass === 'boolean' ? { pass: r.pass } : {}),
    baselineStatus: status(r.baseline),
    trueStatus: status(r.true),
    falseStatus: status(r.false),
    ...(r.delayProbe !== undefined ? { delayProbeStatus: status(r.delayProbe) } : {}),
    ...(num(r.similarityBaselineTrue) !== undefined ? { similarityBaselineTrue: num(r.similarityBaselineTrue)! } : {}),
    ...(num(r.similarityTrueFalse) !== undefined ? { similarityTrueFalse: num(r.similarityTrueFalse)! } : {}),
    ...(num(r.baselineMs) !== undefined ? { baselineMs: Math.round(num(r.baselineMs)!) } : {}),
    ...(num(r.probeMs) !== undefined ? { probeMs: Math.round(num(r.probeMs)!) } : {}),
  }))
}

export function buildInlineVerifyFeedback(
  spec: DeclarativeReplaySpec | unknown,
  replay: ReplayVerificationResult,
  attemptCount: number,
  maxRetries = maxInlineVerifyRetries,
  secrets: readonly NamedSecret[] = [],
): EnrichedInlineVerifyFeedback {
  const maxAttempts = 1 + Math.max(0, maxRetries)
  const retriesRemaining = Math.max(0, maxAttempts - attemptCount)
  const payload = replay.evidencePayload ?? {}
  const kind = spec && typeof spec === 'object' && 'kind' in spec && typeof (spec as { kind?: unknown }).kind === 'string'
    ? (spec as { kind: string }).kind
    : (typeof payload.kind === 'string' ? payload.kind : '')

  const stepStatuses: InlineVerifyFeedback['stepStatuses'] = []
  if (payload.steps && typeof payload.steps === 'object' && !Array.isArray(payload.steps)) {
    for (const [key, val] of Object.entries(payload.steps as Record<string, unknown>)) {
      if (!val || typeof val !== 'object') continue
      const entry = val as Record<string, unknown>
      const id = typeof entry.id === 'string' ? entry.id : key
      const role = typeof entry.role === 'string' ? entry.role : 'probe'
      stepStatuses.push(toStepStatusItem(id, role, entry))
    }
  } else if (kind === 'race_burst') {
    if (payload.control && typeof payload.control === 'object') {
      const c = payload.control as Record<string, unknown>
      stepStatuses.push(toStepStatusItem(typeof c.id === 'string' ? c.id : 'control', 'control', c))
    }
    const burstResults = (payload.burst as { results?: unknown[] } | undefined)?.results
    if (Array.isArray(burstResults)) {
      burstResults.forEach((item, idx) => {
        if (item && typeof item === 'object') {
          stepStatuses.push(toStepStatusItem(`burst-${idx + 1}`, 'probe', item as Record<string, unknown>))
        }
      })
    }
    if (payload.postCheck && typeof payload.postCheck === 'object') {
      const p = payload.postCheck as Record<string, unknown>
      stepStatuses.push(toStepStatusItem(typeof p.id === 'string' ? p.id : 'postCheck', 'probe', p))
    }
  } else if (kind === 'rce_proof' || kind === 'browser_dom') {
    if (payload.control && typeof payload.control === 'object') {
      stepStatuses.push(toStepStatusItem('control', 'control', payload.control as Record<string, unknown>))
    }
    if (payload.probe && typeof payload.probe === 'object') {
      stepStatuses.push(toStepStatusItem('probe', 'probe', payload.probe as Record<string, unknown>))
    }
  } else if (kind === 'sql_boolean_diff') {
    const rounds = (payload.sqlDiff as { rounds?: Array<Record<string, unknown>> } | undefined)?.rounds
    const r0 = Array.isArray(rounds) ? rounds[0] : undefined
    if (r0) {
      if (r0.baseline && typeof r0.baseline === 'object') {
        stepStatuses.push(toStepStatusItem('baseline', 'control', r0.baseline as Record<string, unknown>))
      }
      if (r0.true && typeof r0.true === 'object') {
        stepStatuses.push(toStepStatusItem('true', 'probe', r0.true as Record<string, unknown>))
      }
      if (r0.false && typeof r0.false === 'object') {
        stepStatuses.push(toStepStatusItem('false', 'probe', r0.false as Record<string, unknown>))
      }
    }
  } else if (kind === 'dns_takeover') {
    if (payload.http && typeof payload.http === 'object') {
      stepStatuses.push(toStepStatusItem('http', 'probe', payload.http as Record<string, unknown>))
    }
  } else if (kind === 'cache_differential') {
    if (payload.control && typeof payload.control === 'object') {
      stepStatuses.push(toStepStatusItem('control', 'control', payload.control as Record<string, unknown>))
    }
    if (payload.probe && typeof payload.probe === 'object') {
      stepStatuses.push(toStepStatusItem('probe', 'probe', payload.probe as Record<string, unknown>))
    }
    if (payload.verify && typeof payload.verify === 'object') {
      stepStatuses.push(toStepStatusItem('verify', 'probe', payload.verify as Record<string, unknown>))
    }
  } else if (kind === 'sql_time_diff') {
    const rounds = (payload.sqlTimeDiff as { rounds?: Array<Record<string, unknown>> } | undefined)?.rounds
    const r0 = Array.isArray(rounds) ? rounds[0] : undefined
    if (r0) {
      if (r0.baseline && typeof r0.baseline === 'object') {
        stepStatuses.push(toStepStatusItem('baseline', 'control', r0.baseline as Record<string, unknown>))
      }
      if (r0.delayProbe && typeof r0.delayProbe === 'object') {
        stepStatuses.push(toStepStatusItem('delayProbe', 'probe', r0.delayProbe as Record<string, unknown>))
      }
    }
  }

  const reason = replay.outcome.reason ?? ''
  const requireControlNonErrorTriggered = /requireControlNonError/i.test(reason) ? true : undefined

  let failedStepId: string | undefined
  if (replay.verdict === 'dismissed' || replay.verdict === 'inconclusive') {
    const stepMatch = /step\s+"([^"]+)"/i.exec(reason)
    if (stepMatch) {
      failedStepId = stepMatch[1]
    } else if (/upload_probe\s+control\s+step/i.test(reason)) {
      failedStepId = 'control'
    } else if (/upload_probe\s+fetch\s+step/i.test(reason)) {
      failedStepId = 'fetch'
    } else {
      const errStep = stepStatuses.find(s => s.status === null || s.status === 0 || s.status === 404 || s.status >= 500)
      if (errStep) {
        failedStepId = errStep.id
      } else if (!replay.outcome.controlPassed) {
        failedStepId = stepStatuses.find(s => s.role === 'control')?.id ?? stepStatuses[0]?.id
      } else {
        failedStepId = stepStatuses.find(s => s.role === 'probe')?.id ?? stepStatuses[0]?.id
      }
    }
  }

  let spaCatchallMatched: boolean | undefined
  let spaSimilarityScore: number | undefined
  if (payload.spaCatchall && typeof payload.spaCatchall === 'object') {
    const spa = payload.spaCatchall as { allProbesMatchedCatchall?: unknown; comparisons?: Record<string, { tokenSimilarity?: unknown }> }
    spaCatchallMatched = Boolean(spa.allProbesMatchedCatchall)
    if (spa.comparisons && typeof spa.comparisons === 'object') {
      const scores = Object.values(spa.comparisons)
        .map(c => (c && typeof c.tokenSimilarity === 'number' && Number.isFinite(c.tokenSimilarity) ? c.tokenSimilarity : null))
        .filter((v): v is number => v !== null)
      if (scores.length) spaSimilarityScore = Math.max(...scores)
    }
  }

  let canaryTriggered: boolean | undefined
  const proofObj = payload.proof as { canaryProbeTriggered?: unknown } | undefined
  const probeObj = payload.probe as { canaryCheck?: { triggered?: unknown } } | undefined
  if (typeof proofObj?.canaryProbeTriggered === 'boolean') {
    canaryTriggered = proofObj.canaryProbeTriggered
  } else if (typeof probeObj?.canaryCheck?.triggered === 'boolean') {
    canaryTriggered = probeObj.canaryCheck.triggered
  } else if (Array.isArray(payload.pages)) {
    const probePages = (payload.pages as Array<{ role?: string; canaryCheck?: { triggered?: unknown } }>)
      .filter(p => p.role === 'probe' && typeof p.canaryCheck?.triggered === 'boolean')
    if (probePages.length) {
      canaryTriggered = probePages.some(p => p.canaryCheck?.triggered === true)
    }
  }

  const jqError = /^(?:Replay jq assertion|Replay assertion output violated schema|Verification container failed)/i.test(reason)
    ? redact(reason, secrets).slice(0, 400)
    : undefined

  const assertionSummary: InlineVerifyFeedback['assertionSummary'] = {
    observed: redact(replay.outcome.observed, secrets).slice(0, 400),
    expected: redact(replay.outcome.expected, secrets).slice(0, 400),
    ...(reason ? { reason: redact(reason, secrets).slice(0, 400) } : {}),
  }

  // --- M1.5 enrichment: actionable, bounded, redacted evidence for the repairing agent ---
  const enrichedHeaders = summarizeKeyResponseHeaders(replay.exchanges ?? [], stepStatuses.map(s => s.id), secrets)
  const bodyPreviews: InlineStepBodyPreview[] = []
  if (replay.verdict !== 'confirmed' && replay.verdict !== 'static_verified') {
    const failedIds = new Set<string>()
    if (failedStepId) failedIds.add(failedStepId)
    for (const step of stepStatuses) {
      if (step.id === failedStepId || step.status === null || step.status === 0 || step.status >= 400) failedIds.add(step.id)
    }
    for (const [idx, ex] of (replay.exchanges ?? []).slice(0, maxInlineExchanges).entries()) {
      const stepId = stepStatuses[idx]?.id ?? `exchange-${idx + 1}`
      if (failedIds.size && !failedIds.has(stepId)) continue
      if (!ex.body) continue
      const { preview, truncated } = sanitizeInlinePreview(ex.body, secrets)
      if (!preview) continue
      bodyPreviews.push({
        stepId,
        status: ex.status,
        ...(ex.mediaType ? { mediaType: ex.mediaType } : {}),
        preview,
        truncated,
      })
      if (bodyPreviews.length >= 4) break
    }
  }

  const extractedVarSummaries: Array<{ key: string; preview: string }> = []
  const rawExtractedVars = payload.extractedVars
  if (rawExtractedVars && typeof rawExtractedVars === 'object' && !Array.isArray(rawExtractedVars)) {
    for (const [key, value] of Object.entries(rawExtractedVars as Record<string, unknown>).slice(0, maxInlineExtractedVars)) {
      const { preview } = sanitizeInlinePreview(String(value ?? ''), secrets)
      extractedVarSummaries.push({ key, preview })
    }
  }

  const sqlRounds = kind === 'sql_boolean_diff' || kind === 'sql_time_diff' ? summarizeSqlRounds(payload) : []
  const bflaImpact = payload.bflaImpact as { required?: unknown; satisfied?: unknown; reason?: unknown } | undefined
  const bflaImpactRequired = bflaImpact?.required === true ? true : undefined
  const impactEvidenceMissing = bflaImpact?.required === true && bflaImpact?.satisfied === false ? true : undefined

  const rawFeedback: EnrichedInlineVerifyFeedback = {
    verdict: replay.verdict,
    ...(replay.verificationTier ? { verificationTier: replay.verificationTier } : {}),
    ...(failedStepId ? { failedStepId: redact(failedStepId, secrets) } : {}),
    controlPassed: replay.outcome.controlPassed,
    ...(requireControlNonErrorTriggered ? { requireControlNonErrorTriggered } : {}),
    ...(spaCatchallMatched !== undefined ? { spaCatchallMatched } : {}),
    ...(spaSimilarityScore !== undefined ? { spaSimilarityScore } : {}),
    ...(canaryTriggered !== undefined ? { canaryTriggered } : {}),
    ...(jqError ? { jqError } : {}),
    assertionSummary,
    stepStatuses,
    retriesRemaining,
    ...(replay.exchangeIds?.length ? { replayExchangeIds: replay.exchangeIds.slice(0, maxInlineExchanges) } : {}),
    ...(enrichedHeaders.length ? { keyResponseHeaders: enrichedHeaders } : {}),
    ...(bodyPreviews.length ? { stepBodyPreviews: bodyPreviews } : {}),
    ...(extractedVarSummaries.length ? { extractedVars: extractedVarSummaries } : {}),
    ...(sqlRounds.length ? { sqlRoundSummaries: sqlRounds } : {}),
    ...(kind ? { verificationKind: kind } : {}),
    ...(bflaImpactRequired ? { bflaImpactRequired } : {}),
    ...(impactEvidenceMissing ? { impactEvidenceMissing } : {}),
  }

  // Enrichment is built from already-redacted exchanges; this final pass catches anything that
  // slipped through and guarantees the persisted feedback never carries live credentials.
  return redactJsonValue(rawFeedback, secrets)
}

export async function verifyReplaySpecInline(
  params: VerifyReplaySpecInlineParams,
): Promise<InlineReplayVerificationResult> {
  const maxRetries = Math.max(0, params.maxRetries ?? maxInlineVerifyRetries)
  const maxAttempts = 1 + maxRetries
  const attemptCount = Math.max(1, params.attemptCount ?? 1)
  const allSecrets: NamedSecret[] = [
    ...(params.secrets ?? []),
    ...(params.grant.secrets ?? []),
    ...(params.grant.personas ? personaSecrets(params.grant.personas) : []),
  ]

  if (attemptCount > maxAttempts) {
    const reason = `Inline verification retry limit reached (maxInlineVerifyRetries=${maxRetries}).`
    const emptyReplay = inconclusiveResult(reason, [], [], { retryLimitExceeded: true })
    const feedback = redactJsonValue({
      verdict: 'inconclusive',
      controlPassed: false,
      assertionSummary: {
        observed: 'retry_limit_exceeded',
        expected: `<= ${maxAttempts} verification attempts`,
        reason,
      },
      stepStatuses: [],
      retriesRemaining: 0,
    } satisfies InlineVerifyFeedback, allSecrets)
    return { feedback, replay: emptyReplay }
  }

  const replay = await verifyReplaySpec(params)
  const finalSecrets: NamedSecret[] = [
    ...allSecrets,
    ...(params.broker.getRegisteredSecrets?.() ?? []),
  ]
  const feedback = buildInlineVerifyFeedback(params.spec, replay, attemptCount, maxRetries, finalSecrets)
  return { feedback, replay }
}
