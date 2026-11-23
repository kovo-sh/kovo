/**
 * guardian_verify (TypeScript) — zero-dependency verification SDK for Guardian v6 Layer 3.
 *
 * A verification script runs inside a `--network none` worker sandbox. Every network/DOM/OOB
 * action is an RPC call over a Unix-domain socket into the Guardian process, which owns scope,
 * persona credentials and the signed transcript. The script only ever sees response data and
 * exchange ids; it never sees a credential.
 *
 * Contract:
 *   setup(ctx)   optional — create synthetic entities (tagged by run)
 *   verify(ctx)  required — control/variant exchanges + assertions returning transcript ids
 *   cleanup(ctx) optional — remove synthetic entities
 *
 * Assertions are *claims*, not results. Guardian re-evaluates every claim against its own
 * transcript, then re-runs the whole script in a fresh session. Stdout is never evidence.
 *
 * Zero runtime dependencies; only `node:http` and `node:fs`/`node:path` builtins.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { dirname, join } from 'node:path'

export type ClaimKind = 'status' | 'header' | 'body_contains' | 'jsonpath' | 'css' | 'dom_sentinel' | 'oob' | 'timing'

export interface StatusClaim { kind: 'status'; exchangeId: string; expected: number | number[]; message?: string }
export interface HeaderClaim { kind: 'header'; exchangeId: string; name: string; equals?: string; matches?: string; absent?: boolean; message?: string }
export interface BodyClaim { kind: 'body_contains'; exchangeId: string; text: string; absent?: boolean; message?: string }
export interface JsonPathClaim { kind: 'jsonpath'; exchangeId: string; path: string; equals?: unknown; matches?: string; exists?: boolean; message?: string }
export interface CssClaim { kind: 'css'; exchangeId: string; selector: string; exists?: boolean; count?: number; textEquals?: string; textContains?: string; message?: string }
export interface SentinelsClaim { kind: 'dom_sentinel'; exchangeId: string; sentinel: string; mode?: 'source' | 'executed'; message?: string }
export interface OobClaim { kind: 'oob'; exchangeId: string; expectHit?: boolean; message?: string }
export interface TimingClaim { kind: 'timing'; controlIds: string[]; variantIds: string[]; minPairs?: number; maxPValue?: number; message?: string }
export interface StructuralDiffClaim { kind: 'structural_diff'; controlIds: string[]; variantIds: string[]; minRounds?: number; minDeltaTokens?: number; maxSimilarity?: number; message?: string }
export interface RaceClaim { kind: 'race'; exchangeIds: string[]; mode?: 'h2-single-packet' | 'http1-fallback'; minDistinctOutcomes?: number; expectAllSuccess?: boolean; message?: string }
export interface ImpactClaim {
  kind: 'impact'
  impactClass: 'authorization' | 'bfla' | 'mass_assignment' | 'csrf'
  probeExchangeId: string
  controlExchangeIds?: string[]
  beforeExchangeId?: string
  afterExchangeId?: string
  requiredRole?: string
  resourceTenant?: string
  expectControlDenied?: boolean
  oracleEvents?: string[]
  actorRoles?: Record<string, string>
  actorTenants?: Record<string, string>
  requestBody?: unknown
  ambient?: { kind: 'cookie' | 'bearer' | 'header' | 'unknown'; sameSite?: string }
  message?: string
}
export interface BoundaryClaim {
  kind: 'boundary'
  boundaryClass: 'auth' | 'mfa' | 'access' | 'other'
  controlExchangeId: string
  probeExchangeId: string
  expectControlDenied?: boolean
  actorRoles?: Record<string, string>
  actorTenants?: Record<string, string>
  message?: string
}
export type VerifyClaim = StatusClaim | HeaderClaim | BodyClaim | JsonPathClaim | CssClaim | SentinelsClaim | OobClaim | TimingClaim | StructuralDiffClaim | RaceClaim | ImpactClaim | BoundaryClaim

export type ProofRole =
  | 'setup' | 'control' | 'probe' | 'cleanup'
  | 'control_denied' | 'variant_crossed'
  | 'before_get' | 'mutation' | 'after_get'
  | 'oob_mint' | 'oob_injection' | 'oob_wait' | 'pending_oob'
  | 'race'

/** Compact, role-labelled transcript entry returned with every helper result. */
export interface ProofTranscriptEntry {
  exchangeId: string
  role: ProofRole
  personaHandle: string | null
  method: string | null
  pathAndQuery: string | null
  status: number | null
  durationMs: number
  note?: string
}

/**
 * Repair contract returned by every helper (and mirrored by the host oracle's verdict):
 * the first rejecting validator, the exact missing transcript evidence, and what was recorded.
 */
export interface ProofFeedback {
  rejectedBy: string | null
  missingEvidence: string[]
  transcriptSummary: ProofTranscriptEntry[]
}

export interface AccessBoundaryProof extends ProofFeedback {
  ok: boolean
  claim: BoundaryClaim
  control: HttpExchange
  probe: HttpExchange
  transcript: { control_denied: string; variant_crossed: string }
  evidence: { controlStatus: number; variantStatus: number; controlDenied: boolean; crossed: boolean }
}

export interface PersistedMutationProof extends ProofFeedback {
  ok: boolean
  claim: ImpactClaim
  before: HttpExchange
  mutation: HttpExchange
  after: HttpExchange
  delta: {
    fieldPath: string
    before: unknown
    after: unknown
    changed: boolean
    changedFields: string[]
    added: string[]
    removed: string[]
  }
  expectationMatched: boolean
}

export interface DifferentialProof extends ProofFeedback {
  ok: boolean
  mode: 'boolean' | 'timing'
  controlIds: string[]
  variantIds: string[]
  claim: StructuralDiffClaim | TimingClaim
  stats: Record<string, number | string | boolean | string[]>
  exchanges: { control: HttpExchange[]; variant: HttpExchange[] }
}

export interface OobCallbackProof extends ProofFeedback {
  ok: boolean
  claim: OobClaim
  token: string
  url: string
  dnsHost: string
  hit: boolean
  stage: 'immediate' | 'late' | 'pending' | 'none'
  promoted: boolean
  subscriptionId: string | null
  exchanges: { mint: string; injection: string | null; wait: string | null }
}

export interface RaceBurstProof extends ProofFeedback {
  ok: boolean
  claim: RaceClaim
  mode: 'h2-single-packet' | 'http1-fallback'
  fallbackReason: string | null
  summary: Record<string, unknown>
  exchanges: Array<{ exchangeId: string; status: number; durationMs: number; bodySha256: string }>
}

export interface AccessBoundaryInput {
  controlPersona: string
  probePersona: string
  route: HttpTarget
  expectControlDenied?: boolean
  method?: string
  controlOptions?: HttpOptions
  probeOptions?: HttpOptions
  controlSession?: string
  probeSession?: string
  boundaryClass?: 'auth' | 'access'
  actorRoles?: Record<string, string>
  actorTenants?: Record<string, string>
  message?: string
}

export interface PersistedMutationInput {
  readRoute: HttpTarget
  mutation: HttpTarget | {
    target: HttpTarget
    method?: string
    body?: string
    headers?: Record<string, string>
    as?: string
    session?: string
  }
  fieldPath: string
  expectDelta: unknown | ((before: unknown, after: unknown, delta: PersistedMutationProof['delta']) => boolean)
  readPersona?: string
  mutatePersona?: string
  readMethod?: string
  readSession?: string
  impactClass?: 'authorization' | 'bfla' | 'mass_assignment' | 'csrf'
  requiredRole?: string
  resourceTenant?: string
  oracleEvents?: string[]
  actorRoles?: Record<string, string>
  actorTenants?: Record<string, string>
  message?: string
}

export interface DifferentialArmInput {
  target: HttpTarget
  options?: HttpOptions
}

export interface BooleanOrTimingDiffInput {
  control: DifferentialArmInput | HttpTarget
  variant: DifferentialArmInput | HttpTarget
  mode: 'boolean' | 'timing'
  rounds?: number
  minSimilarityDelta?: number
  minDeltaTokens?: number
  maxSimilarity?: number
  maxPValue?: number
  session?: string
  message?: string
}

export interface OobInjectionInput {
  target: HttpTarget
  method?: string
  headers?: Record<string, string>
  body?: string
  as?: string
}

export interface OobCallbackInput {
  inject: ((canary: { url: string; token: string; dnsHost: string }) => Promise<HttpExchange | void> | HttpExchange | void) | OobInjectionInput
  /** Canary label (the broker mints a fresh token; never a credential). */
  token?: string
  timeoutMs?: number
  immediateMs?: number
  windowMs?: number
  message?: string
}

export interface RaceRequestInput {
  target?: HttpTarget
  url?: HttpTarget
  path?: string
  origin?: string
  method?: string
  headers?: Record<string, string>
  body?: string
  as?: string
}

export interface RaceBurstInput {
  requests: Array<RaceRequestInput | HttpTarget>
  barrier?: 'auto' | 'h2' | 'http1'
  session?: string
  minDistinctOutcomes?: number
  expectAllSuccess?: boolean
  message?: string
}

export interface ProofResult {
  sdk: 'guardian_verify.ts'
  nonce: string
  title: string
  severity: string
  description?: string
  claims: VerifyClaim[]
}

export interface RpcContext {
  nonce: string
  runId: string
  targetOrigins: string[]
  sdkVersion: string
}

interface RpcEnvelope {
  ok: boolean
  result?: unknown
  error?: string
}

function readContext(): RpcContext {
  const contextPath = process.env.GUARDIAN_RPC_CONTEXT_FILE ?? '/guardian-rpc/context.json'
  const raw = JSON.parse(readFileSync(contextPath, 'utf8')) as {
    nonce?: string
    runId?: string
    targetOrigins?: string[]
    sdkVersion?: string
  }
  return {
    nonce: typeof raw.nonce === 'string' ? raw.nonce : '',
    runId: typeof raw.runId === 'string' ? raw.runId : 'unknown-run',
    targetOrigins: Array.isArray(raw.targetOrigins) ? raw.targetOrigins.filter((v): v is string => typeof v === 'string') : [],
    sdkVersion: typeof raw.sdkVersion === 'string' ? raw.sdkVersion : 'guardian_verify/v6-mvp',
  }
}

function readToken(): string {
  const tokenPath = process.env.GUARDIAN_RPC_TOKEN_FILE ?? '/guardian-rpc/token'
  return readFileSync(tokenPath, 'utf8').trim()
}

function rpc(op: string, args: Record<string, unknown>, timeoutMs = 60_000): Promise<unknown> {
  const socketPath = process.env.GUARDIAN_RPC_SOCKET ?? '/guardian-rpc/verify.sock'
  const context = readContext()
  const nonce = process.env.GUARDIAN_VERIFY_NONCE ?? context.nonce
  const token = readToken()
  const payload = JSON.stringify({ op, args })
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        'x-guardian-rpc-token': token,
        'x-guardian-verify-nonce': nonce,
      },
      timeout: timeoutMs,
    }, res => {
      const chunks: Buffer[] = []
      let size = 0
      res.on('data', (chunk: Buffer) => {
        size += chunk.length
        if (size > 8 * 1024 * 1024) {
          res.destroy()
          reject(new Error('Verification RPC response exceeded the SDK limit.'))
          return
        }
        chunks.push(chunk)
      })
      res.on('end', () => {
        let body: RpcEnvelope
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcEnvelope } catch {
          reject(new Error('Verification RPC returned malformed JSON.'))
          return
        }
        if (!body.ok) reject(new Error(body.error ?? 'Verification RPC call failed.'))
        else resolve(body.result)
      })
    })
    req.on('timeout', () => { req.destroy(new Error('Verification RPC call timed out.')) })
    req.on('error', reject)
    req.end(payload)
  })
}

export interface HttpExchange {
  exchangeId: string
  status: number
  method: string
  pathAndQuery: string
  finalPathAndQuery?: string
  redirectOrigins?: string[]
  mediaType: string
  headers: Record<string, string>
  body: string
  bodyPreview: string
  bodyBytes: number
  bodySha256: string
  durationMs: number
  personaHandle: string | null
  protocol?: 'h2'
}

export interface BrowserExchange {
  exchangeId: string
  status: number
  url: string
  html: string
  title?: string
  executedSentinels: string[]
  durationMs: number
}

export interface OobHandle {
  exchangeId: string
  token: string
  url: string
  dnsHost: string
}

export interface OobCheck extends OobHandle {
  hit: boolean
  checkExchangeId?: string
  hits: Array<{ protocol: string; token: string; remoteIp?: string; timestamp?: number }>
}

export type HttpTarget = string | { url: string; origin?: string }

export interface HttpOptions {
  /** Approved persona handle; Layer 1 injects the credential. */
  as?: string
  session?: string
  role?: 'setup' | 'control' | 'probe' | 'cleanup'
  method?: string
  headers?: Record<string, string>
  body?: string
  followRedirects?: boolean
  timeoutMs?: number
}

function splitTarget(input: HttpTarget, defaultOrigin: string | undefined): { origin?: string; path: string } {
  if (typeof input === 'string') {
    if (/^https?:\/\//i.test(input)) {
      const url = new URL(input)
      return { origin: url.origin, path: url.pathname + url.search }
    }
    if (!input.startsWith('/')) throw new Error('Relative verification paths must start with "/".')
    return { path: input }
  }
  if (typeof input?.url !== 'string') throw new Error('HTTP target requires a url string.')
  if (/^https?:\/\//i.test(input.url)) {
    const url = new URL(input.url)
    return { origin: input.origin ?? url.origin, path: url.pathname + url.search }
  }
  return { ...(input.origin ? { origin: input.origin } : {}), path: input.url }
}

function isSuccessStatus(status: number): boolean {
  return status >= 200 && status < 300
}

function isDeniedStatus(status: number): boolean {
  return status === 401 || status === 403 || (status >= 300 && status < 400)
}

function transcriptEntry(
  role: ProofRole,
  exchange: Pick<HttpExchange, 'exchangeId' | 'personaHandle' | 'status' | 'durationMs' | 'method' | 'pathAndQuery'> | null,
  note?: string,
): ProofTranscriptEntry {
  return {
    exchangeId: exchange?.exchangeId ?? '',
    role,
    personaHandle: exchange?.personaHandle ?? null,
    method: exchange?.method ?? null,
    pathAndQuery: exchange?.pathAndQuery ?? null,
    status: exchange?.status ?? null,
    durationMs: exchange?.durationMs ?? 0,
    ...(note ? { note } : {}),
  }
}

function feedback(rejectedBy: string | null, missingEvidence: string[], transcriptSummary: ProofTranscriptEntry[]): ProofFeedback {
  return { rejectedBy, missingEvidence, transcriptSummary }
}

function parseJsonBody(body: string | undefined): unknown {
  if (!body) return undefined
  try { return JSON.parse(body) } catch { return undefined }
}

function parseFieldPath(path: string): Array<string | number> {
  const parts: Array<string | number> = []
  for (const raw of path.replace(/\[(\d+)\]/g, '.$1').split('.')) {
    if (!raw) continue
    parts.push(/^\d+$/.test(raw) ? Number(raw) : raw)
  }
  return parts
}

function readFieldValue(value: unknown, path: string): { found: boolean; value?: unknown } {
  let current: unknown = value
  for (const part of parseFieldPath(path)) {
    if (current === null || typeof current !== 'object') return { found: false }
    if (Array.isArray(current)) {
      if (typeof part !== 'number' || part < 0 || part >= current.length) return { found: false }
      current = current[part]
      continue
    }
    if (!(part in (current as Record<string, unknown>))) return { found: false }
    current = (current as Record<string, unknown>)[String(part)]
  }
  return { found: true, value: current }
}

function flattenFields(value: unknown, prefix = '', out = new Map<string, string>(), depth = 0): Map<string, string> {
  if (out.size >= 512 || depth > 6) return out
  if (value === null || typeof value !== 'object') {
    if (prefix) out.set(prefix, JSON.stringify(value))
    return out
  }
  if (Array.isArray(value)) {
    value.slice(0, 64).forEach((child, index) => flattenFields(child, `${prefix}[${index}]`, out, depth + 1))
    return out
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    flattenFields(child, prefix ? `${prefix}.${key}` : key, out, depth + 1)
  }
  return out
}

function computeFieldDelta(before: unknown, after: unknown): { changedFields: string[]; added: string[]; removed: string[] } {
  const beforeFields = flattenFields(before)
  const afterFields = flattenFields(after)
  const changedFields: string[] = []
  const added: string[] = []
  const removed: string[] = []
  for (const [path, value] of afterFields) {
    if (!beforeFields.has(path)) added.push(path)
    else if (beforeFields.get(path) !== value) changedFields.push(path)
  }
  for (const path of beforeFields.keys()) if (!afterFields.has(path)) removed.push(path)
  return { changedFields, added, removed }
}

const STRUCTURAL_KEYED_TOKEN_RE = /(["']?(?:csrf|xsrf|nonce|authenticity[_-]?token|request[_-]?id|trace[_-]?id|correlation[_-]?id|span[_-]?id|session[_-]?id|etag|server[_-]?time|request[_-]?time)["']?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&}<]+)/gi
const STRUCTURAL_TAG_NONCE_RE = /(\b(?:name|id)\s*=\s*["'][^"']*(?:csrf|xsrf|nonce|authenticity|request[_-]?id)[^"']*["'][^>]{0,200}?\b(?:content|value)\s*=\s*)("(?:[^"\\]|\\.)*"|'[^']*')/gi
const STRUCTURAL_UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi
const STRUCTURAL_ISO_TS_RE = /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?/g
const STRUCTURAL_EPOCH_RE = /\b1[5-9]\d{11}\b|\b2\d{12}\b/g
const STRUCTURAL_LONG_HEX_RE = /\b[0-9a-f]{16,}\b/gi
const STRUCTURAL_LONG_OPAQUE_RE = /[A-Za-z0-9+/_=-]{24,}/g

/** Strip per-request tokens before structural comparison (same normalization as the oracle). */
export function normalizeStructuralTokens(input: string): string {
  if (!input) return input
  let out = input
    .replace(STRUCTURAL_KEYED_TOKEN_RE, '$1"<dynamic>"')
    .replace(STRUCTURAL_TAG_NONCE_RE, '$1"<dynamic>"')
    .replace(STRUCTURAL_UUID_RE, '<uuid>')
    .replace(STRUCTURAL_ISO_TS_RE, '<timestamp>')
    .replace(STRUCTURAL_EPOCH_RE, '<epoch>')
    .replace(STRUCTURAL_LONG_HEX_RE, '<hex>')
  out = out.replace(STRUCTURAL_LONG_OPAQUE_RE, token => /[A-Za-z]/.test(token) && /\d/.test(token) ? '<opaque>' : token)
  return out
}

function tokenSet(normalized: string): Set<string> {
  return new Set(normalized.toLowerCase().split(/[^a-z0-9]+/).filter(token => token.length >= 2))
}

function changedTokens(a: string, b: string): string[] {
  const tokensA = tokenSet(normalizeStructuralTokens(a))
  const tokensB = tokenSet(normalizeStructuralTokens(b))
  const changed = new Set<string>()
  for (const token of tokensA) if (!tokensB.has(token)) changed.add(token)
  for (const token of tokensB) if (!tokensA.has(token)) changed.add(token)
  return [...changed].sort()
}

function normalizeEquals(a: string, b: string): boolean {
  return normalizeStructuralTokens(a) === normalizeStructuralTokens(b)
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 0 ? (sorted[middle - 1]! + sorted[middle]!) / 2 : sorted[middle]!
}

function mad(values: number[]): number {
  const center = median(values)
  return median(values.map(value => Math.abs(value - center)))
}

function erf(x: number): number {
  const sign = x < 0 ? -1 : 1
  const a = Math.abs(x)
  const t = 1 / (1 + 0.3275911 * a)
  const y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-a * a)
  return sign * y
}

function normalCdf(z: number): number {
  return 0.5 * (1 + erf(z / Math.SQRT2))
}

export interface MannWhitneyStats {
  pValue: number
  separation: number
  medianControl: number
  medianVariant: number
  madControl: number
  madVariant: number
  pairs: number
}

/** Mann-Whitney U (normal approximation) plus median/MAD separation, mirrored from the oracle. */
export function mannWhitneyU(control: number[], variant: number[]): MannWhitneyStats {
  const n1 = control.length
  const n2 = variant.length
  const pooled = [...control.map(value => ({ value, group: 0 })), ...variant.map(value => ({ value, group: 1 }))]
  pooled.sort((a, b) => a.value - b.value)
  let rankSum = 0
  let index = 0
  while (index < pooled.length) {
    let end = index
    while (end + 1 < pooled.length && pooled[end + 1]!.value === pooled[index]!.value) end += 1
    const averageRank = (index + end + 2) / 2
    for (let i = index; i <= end; i += 1) if (pooled[i]!.group === 0) rankSum += averageRank
    index = end + 1
  }
  const u1 = rankSum - (n1 * (n1 + 1)) / 2
  const meanU = (n1 * n2) / 2
  const sdU = Math.sqrt((n1 * n2 * (n1 + n2 + 1)) / 12)
  const pValue = sdU === 0 ? 1 : 2 * (1 - normalCdf(Math.abs(u1 - meanU) / sdU))
  const mc = median(control)
  const mv = median(variant)
  const pooledMad = Math.max(mad(control), mad(variant), 1e-9)
  return {
    pValue: Math.min(1, Math.max(0, pValue)),
    separation: Math.abs(mv - mc) / pooledMad,
    medianControl: mc,
    medianVariant: mv,
    madControl: mad(control),
    madVariant: mad(variant),
    pairs: Math.min(n1, n2),
  }
}

function valueEquals(actual: unknown, expected: unknown): boolean {
  return JSON.stringify(actual) === JSON.stringify(expected)
}

function renderInjection(template: string, canary: { url: string; token: string; dnsHost: string }): string {
  return template
    .split('{{canaryUrl}}').join(canary.url)
    .split('{{canaryToken}}').join(canary.token)
    .split('{{canaryHost}}').join(canary.dnsHost)
}

export interface TimingResult {
  controlIds: string[]
  variantIds: string[]
  claim: TimingClaim
}

export interface Expectations {
  status(exchange: { exchangeId: string }, expected: number | number[], message?: string): StatusClaim
  statusNot(exchange: { exchangeId: string }, unexpected: number, message?: string): StatusClaim
  header(exchange: { exchangeId: string }, name: string, expected?: string | { equals?: string; matches?: string; absent?: boolean }, message?: string): HeaderClaim
  bodyContains(exchange: { exchangeId: string }, text: string, message?: string): BodyClaim
  bodyAbsent(exchange: { exchangeId: string }, text: string, message?: string): BodyClaim
  jsonPath(exchange: { exchangeId: string }, path: string, expected?: unknown, message?: string): JsonPathClaim
  css(exchange: { exchangeId: string }, selector: string, expected?: { exists?: boolean; count?: number; textEquals?: string; textContains?: string }, message?: string): CssClaim
  domSentinel(exchange: { exchangeId: string }, sentinel: string, mode?: 'source' | 'executed', message?: string): SentinelsClaim
  oob(exchange: { exchangeId: string }, expectHit?: boolean, message?: string): OobClaim
  timing(result: TimingResult, message?: string): TimingClaim
}

export class VerifyContext {
  readonly nonce: string
  readonly runId: string
  readonly targetOrigins: string[]
  readonly sdkVersion: string
  readonly claims: VerifyClaim[] = []
  readonly expect: Expectations
  /** Alias for `expect`. */
  readonly assert: Expectations
  private readonly defaultOrigin: string | undefined

  constructor() {
    const context = readContext()
    this.nonce = process.env.GUARDIAN_VERIFY_NONCE ?? context.nonce
    this.runId = context.runId
    this.targetOrigins = context.targetOrigins
    this.sdkVersion = context.sdkVersion
    this.defaultOrigin = this.targetOrigins[0]
    const push = (claim: VerifyClaim): VerifyClaim => { this.claims.push(claim); return claim }
    const expectations: Expectations = {
      status(exchange, expected, message) {
        return push({ kind: 'status', exchangeId: exchange.exchangeId, expected, ...(message ? { message } : {}) }) as StatusClaim
      },
      statusNot(exchange, unexpected, message) {
        const expected = [200, 201, 202, 204, 301, 302, 400, 401, 403, 404, 405].filter(code => code !== unexpected)
        return push({ kind: 'status', exchangeId: exchange.exchangeId, expected, ...(message ? { message } : {}) }) as StatusClaim
      },
      header(exchange, name, expected, message) {
        const spec = typeof expected === 'string' ? { equals: expected } : (expected ?? {})
        return push({ kind: 'header', exchangeId: exchange.exchangeId, name, ...spec, ...(message ? { message } : {}) }) as HeaderClaim
      },
      bodyContains(exchange, text, message) {
        return push({ kind: 'body_contains', exchangeId: exchange.exchangeId, text, ...(message ? { message } : {}) }) as BodyClaim
      },
      bodyAbsent(exchange, text, message) {
        return push({ kind: 'body_contains', exchangeId: exchange.exchangeId, text, absent: true, ...(message ? { message } : {}) }) as BodyClaim
      },
      jsonPath(exchange, path, expected, message) {
        return push({ kind: 'jsonpath', exchangeId: exchange.exchangeId, path, ...(expected === undefined ? { exists: true } : { equals: expected }), ...(message ? { message } : {}) }) as JsonPathClaim
      },
      css(exchange, selector, expected, message) {
        return push({ kind: 'css', exchangeId: exchange.exchangeId, selector, ...(expected ?? {}), ...(message ? { message } : {}) }) as CssClaim
      },
      domSentinel(exchange, sentinel, mode, message) {
        return push({ kind: 'dom_sentinel', exchangeId: exchange.exchangeId, sentinel, mode: mode ?? 'executed', ...(message ? { message } : {}) }) as SentinelsClaim
      },
      oob(exchange, expectHit, message) {
        return push({ kind: 'oob', exchangeId: exchange.exchangeId, expectHit: expectHit ?? true, ...(message ? { message } : {}) }) as OobClaim
      },
      timing(result, message) {
        return push({ ...result.claim, ...(message ? { message } : {}) }) as TimingClaim
      },
    }
    this.expect = expectations
    this.assert = expectations
  }

  async http(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> {
    const target = splitTarget(input, this.defaultOrigin)
    const result = await rpc('http', {
      ...(target.origin ? { origin: target.origin } : {}),
      path: target.path,
      method: options.method ?? 'GET',
      ...(options.headers ? { headers: options.headers } : {}),
      ...(options.body !== undefined ? { body: options.body } : {}),
      ...(options.as ? { persona: options.as } : {}),
      ...(options.session ? { session: options.session } : {}),
      ...(options.role ? { sessionGroupRole: options.role } : {}),
      ...(options.followRedirects !== undefined ? { followRedirects: options.followRedirects } : {}),
    }, (options.timeoutMs ?? 60_000) + 10_000)
    return result as HttpExchange
  }

  async http2(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> {
    const target = splitTarget(input, this.defaultOrigin)
    const result = await rpc('http2', {
      ...(target.origin ? { origin: target.origin } : {}),
      path: target.path,
      method: options.method ?? 'GET',
      ...(options.headers ? { headers: options.headers } : {}),
      ...(options.body !== undefined ? { body: options.body } : {}),
      ...(options.as ? { persona: options.as } : {}),
      ...(options.session ? { session: options.session } : {}),
      ...(options.role ? { sessionGroupRole: options.role } : {}),
    }, (options.timeoutMs ?? 60_000) + 10_000)
    return result as HttpExchange
  }

  async browser(input: HttpTarget, options: { as?: string; waitForSelector?: string; timeoutMs?: number } = {}): Promise<BrowserExchange> {
    const target = splitTarget(input, this.defaultOrigin)
    const result = await rpc('browser', {
      ...(target.origin ? { origin: target.origin } : {}),
      path: target.path,
      ...(options.as ? { persona: options.as } : {}),
      ...(options.waitForSelector ? { waitForSelector: options.waitForSelector } : {}),
    }, (options.timeoutMs ?? 60_000) + 10_000)
    return result as BrowserExchange
  }

  readonly oob = {
    mint: async (label: string, origin?: string): Promise<OobHandle> => {
      const result = await rpc('oob', { action: 'mint', label, ...(origin ? { origin } : {}) }, 30_000)
      return result as OobHandle
    },
    check: async (handle: OobHandle): Promise<OobCheck> => {
      const result = await rpc('oob', { action: 'check', token: handle.token, exchangeId: handle.exchangeId }, 30_000)
      return { ...handle, ...(result as OobCheck) }
    },
  }

  readonly timing = {
    /**
     * Interleaved control/variant timing with 5–7 pairs. The oracle evaluates the recorded
     * durations with Mann-Whitney U + median/MAD separation, so a single lucky sample cannot
     * confirm a timing side channel.
     */
    compare: async (
      control: { target: HttpTarget; options?: HttpOptions },
      variant: { target: HttpTarget; options?: HttpOptions },
      options: { pairs?: number } = {},
    ): Promise<TimingResult> => {
      const pairs = Math.max(5, Math.min(Math.round(options.pairs ?? 6), 7))
      const controlIds: string[] = []
      const variantIds: string[] = []
      for (let i = 0; i < pairs; i += 1) {
        const order: Array<'control' | 'variant'> = i % 2 === 0 ? ['control', 'variant'] : ['variant', 'control']
        for (const which of order) {
          const call = which === 'control' ? control : variant
          const exchange = await this.http(call.target, call.options)
          if (which === 'control') controlIds.push(exchange.exchangeId)
          else variantIds.push(exchange.exchangeId)
        }
      }
      return {
        controlIds,
        variantIds,
        claim: { kind: 'timing', controlIds, variantIds, minPairs: pairs, maxPValue: 0.05 },
      }
    },
  }

  /**
   * Control-vs-variant access boundary. Records the denied control and the crossing variant on
   * the same route with distinct session-group roles, then emits a `boundary` claim the oracle
   * re-evaluates. `control_denied` + `variant_crossed` ids are returned.
   */
  async proveAccessBoundary(input: AccessBoundaryInput): Promise<AccessBoundaryProof> {
    const controlSession = input.controlSession ?? 'access-boundary-control'
    const probeSession = input.probeSession ?? 'access-boundary-probe'
    const method = input.method ?? 'GET'
    const control = await this.http(input.route, { ...input.controlOptions, method, as: input.controlPersona, role: 'control', session: controlSession })
    const probe = await this.http(input.route, { ...input.probeOptions, method, as: input.probePersona, role: 'probe', session: probeSession })
    const expectControlDenied = input.expectControlDenied !== false
    const controlDenied = isDeniedStatus(control.status)
    const crossed = isSuccessStatus(probe.status) && (probe.body?.length ?? 0) >= 8
    const claim: BoundaryClaim = {
      kind: 'boundary',
      boundaryClass: input.boundaryClass ?? 'access',
      controlExchangeId: control.exchangeId,
      probeExchangeId: probe.exchangeId,
      expectControlDenied,
      ...(input.actorRoles ? { actorRoles: input.actorRoles } : {}),
      ...(input.actorTenants ? { actorTenants: input.actorTenants } : {}),
      ...(input.message ? { message: input.message } : {}),
    }
    this.claims.push(claim)
    const missingEvidence: string[] = []
    if (expectControlDenied && !controlDenied) missingEvidence.push('control_denied')
    if (!crossed) missingEvidence.push('variant_crossed')
    if (!expectControlDenied && input.controlPersona === input.probePersona) missingEvidence.push('actor_differential')
    return {
      ok: missingEvidence.length === 0,
      claim,
      control,
      probe,
      transcript: { control_denied: control.exchangeId, variant_crossed: probe.exchangeId },
      evidence: { controlStatus: control.status, variantStatus: probe.status, controlDenied, crossed },
      ...feedback(missingEvidence.length ? 'boundary' : null, missingEvidence, [
        transcriptEntry('control_denied', control),
        transcriptEntry('variant_crossed', probe),
      ]),
    }
  }

  /**
   * Persisted state mutation: baseline GET, probe write, clean readback GET. Returns the field
   * delta and emits an `impact` claim (mass-assignment by default) with the write body attached.
   */
  async provePersistedMutation(input: PersistedMutationInput): Promise<PersistedMutationProof> {
    const mut = (typeof input.mutation === 'object' && input.mutation !== null && 'target' in input.mutation)
      ? input.mutation
      : { target: input.mutation as HttpTarget }
    const readPersona = input.readPersona ?? mut.as
    const mutatePersona = input.mutatePersona ?? mut.as
    const readSession = input.readSession ?? 'persisted-read'
    const before = await this.http(input.readRoute, { method: input.readMethod ?? 'GET', ...(readPersona ? { as: readPersona } : {}), role: 'control', session: readSession })
    const writeHeaders = mut.body !== undefined && !Object.keys(mut.headers ?? {}).some(key => key.toLowerCase() === 'content-type')
      ? { 'content-type': 'application/json', ...(mut.headers ?? {}) }
      : mut.headers
    const mutation = await this.http(mut.target, {
      method: mut.method ?? 'POST',
      ...(mut.body !== undefined ? { body: mut.body } : {}),
      ...(writeHeaders ? { headers: writeHeaders } : {}),
      ...(mutatePersona ? { as: mutatePersona } : {}),
      role: 'probe',
      session: mut.session ?? readSession,
    })
    const after = await this.http(input.readRoute, { method: input.readMethod ?? 'GET', ...(readPersona ? { as: readPersona } : {}), role: 'control', session: readSession })
    const beforeJson = parseJsonBody(before.body)
    const afterJson = parseJsonBody(after.body)
    const beforeField = readFieldValue(beforeJson, input.fieldPath)
    const afterField = readFieldValue(afterJson, input.fieldPath)
    const fields = computeFieldDelta(beforeJson, afterJson)
    const delta = {
      fieldPath: input.fieldPath,
      before: beforeField.found ? beforeField.value : undefined,
      after: afterField.found ? afterField.value : undefined,
      changed: beforeField.found && afterField.found && !valueEquals(beforeField.value, afterField.value),
      ...fields,
    }
    const expectationMatched = typeof input.expectDelta === 'function'
      ? Boolean(input.expectDelta(delta.before, delta.after, delta))
      : valueEquals(delta.after, input.expectDelta)
    const impactClass = input.impactClass ?? 'mass_assignment'
    const claim: ImpactClaim = {
      kind: 'impact',
      impactClass,
      probeExchangeId: mutation.exchangeId,
      beforeExchangeId: before.exchangeId,
      afterExchangeId: after.exchangeId,
      ...(input.requiredRole ? { requiredRole: input.requiredRole } : {}),
      ...(input.resourceTenant ? { resourceTenant: input.resourceTenant } : {}),
      ...(input.oracleEvents ? { oracleEvents: input.oracleEvents } : {}),
      ...(input.actorRoles ? { actorRoles: input.actorRoles } : {}),
      ...(input.actorTenants ? { actorTenants: input.actorTenants } : {}),
      ...(mut.body !== undefined && parseJsonBody(mut.body) !== undefined ? { requestBody: parseJsonBody(mut.body) } : {}),
      ...(input.message ? { message: input.message } : {}),
    }
    this.claims.push(claim)
    const missingEvidence: string[] = []
    if (!isSuccessStatus(before.status)) missingEvidence.push('before_get')
    if (!isSuccessStatus(mutation.status)) missingEvidence.push('mutation_success')
    if (!isSuccessStatus(after.status)) missingEvidence.push('after_get')
    if (beforeJson === undefined || afterJson === undefined) missingEvidence.push('json_readback')
    if (!delta.changed) missingEvidence.push(`field_delta:${input.fieldPath}`)
    if (!expectationMatched) missingEvidence.push('expected_delta')
    return {
      ok: missingEvidence.length === 0,
      claim,
      before,
      mutation,
      after,
      delta,
      expectationMatched,
      ...feedback(missingEvidence.length ? 'impact' : null, missingEvidence, [
        transcriptEntry('before_get', before),
        transcriptEntry('mutation', mutation),
        transcriptEntry('after_get', after),
      ]),
    }
  }

  /**
   * Boolean/content differential (token-stripped structural delta) or timing differential
   * (Mann-Whitney U + median/MAD). Records interleaved control/probe arms and emits the matching
   * `structural_diff` or `timing` claim.
   */
  async proveBooleanOrTimingDiff(input: BooleanOrTimingDiffInput): Promise<DifferentialProof> {
    const armOf = (arm: DifferentialArmInput | HttpTarget): DifferentialArmInput =>
      (typeof arm === 'string' || (typeof arm === 'object' && arm !== null && 'url' in arm && !('target' in arm)))
        ? { target: arm as HttpTarget }
        : arm as DifferentialArmInput
    const controlArm = armOf(input.control)
    const variantArm = armOf(input.variant)
    const session = input.session ?? `diff-${input.mode}`
    const controlExchanges: HttpExchange[] = []
    const variantExchanges: HttpExchange[] = []
    if (input.mode === 'timing') {
      const pairs = Math.max(5, Math.min(Math.round(input.rounds ?? 6), 7))
      for (let index = 0; index < pairs; index += 1) {
        const order: Array<'control' | 'variant'> = index % 2 === 0 ? ['control', 'variant'] : ['variant', 'control']
        for (const which of order) {
          const arm = which === 'control' ? controlArm : variantArm
          const exchange = await this.http(arm.target, { ...arm.options, role: which === 'control' ? 'control' : 'probe', session })
          if (which === 'control') controlExchanges.push(exchange)
          else variantExchanges.push(exchange)
        }
      }
      const controlIds = controlExchanges.map(exchange => exchange.exchangeId)
      const variantIds = variantExchanges.map(exchange => exchange.exchangeId)
      const claim: TimingClaim = { kind: 'timing', controlIds, variantIds, minPairs: pairs, maxPValue: input.maxPValue ?? 0.05, ...(input.message ? { message: input.message } : {}) }
      this.claims.push(claim)
      const stats = mannWhitneyU(controlExchanges.map(exchange => exchange.durationMs), variantExchanges.map(exchange => exchange.durationMs))
      const missingEvidence: string[] = []
      if (controlIds.length < pairs) missingEvidence.push('control_arm')
      if (variantIds.length < pairs) missingEvidence.push('variant_arm')
      if (stats.pValue > (input.maxPValue ?? 0.05)) missingEvidence.push('timing_separation')
      if (stats.separation < 3) missingEvidence.push('timing_separation')
      return {
        ok: missingEvidence.length === 0,
        mode: 'timing',
        controlIds,
        variantIds,
        claim,
        stats: { ...stats },
        exchanges: { control: controlExchanges, variant: variantExchanges },
        ...feedback(missingEvidence.length ? 'timing' : null, [...new Set(missingEvidence)], [
          ...controlExchanges.map(exchange => transcriptEntry('control', exchange, `timing ${exchange.durationMs}ms`)),
          ...variantExchanges.map(exchange => transcriptEntry('probe', exchange, `timing ${exchange.durationMs}ms`)),
        ]),
      }
    }

    const rounds = Math.max(2, Math.min(Math.round(input.rounds ?? 3), 6))
    for (let index = 0; index < rounds; index += 1) {
      const order: Array<'control' | 'variant'> = index % 2 === 0 ? ['control', 'variant'] : ['variant', 'control']
      for (const which of order) {
        const arm = which === 'control' ? controlArm : variantArm
        const exchange = await this.http(arm.target, { ...arm.options, role: which === 'control' ? 'control' : 'probe', session })
        if (which === 'control') controlExchanges.push(exchange)
        else variantExchanges.push(exchange)
      }
    }
    const controlIds = controlExchanges.map(exchange => exchange.exchangeId)
    const variantIds = variantExchanges.map(exchange => exchange.exchangeId)
    const controlBodies = controlExchanges.map(exchange => exchange.body ?? '')
    const variantBodies = variantExchanges.map(exchange => exchange.body ?? '')
    const stableControl = controlBodies.every(body => normalizeEquals(controlBodies[0]!, body))
    const stableVariant = variantBodies.every(body => normalizeEquals(variantBodies[0]!, body))
    const roundDeltas = controlBodies.map((body, index) => changedTokens(body, variantBodies[index] ?? variantBodies[0] ?? ''))
    const stableDelta = roundDeltas.length > 0
      ? roundDeltas[0]!.filter(token => roundDeltas.every(other => other.includes(token)))
      : []
    const controlTokens = tokenSet(normalizeStructuralTokens(controlBodies[0] ?? ''))
    const variantTokens = tokenSet(normalizeStructuralTokens(variantBodies[0] ?? ''))
    const union = new Set([...controlTokens, ...variantTokens])
    const shared = [...controlTokens].filter(token => variantTokens.has(token)).length
    const similarity = union.size === 0 ? 1 : shared / union.size
    const minRounds = rounds
    const minDeltaTokens = input.minDeltaTokens ?? input.minSimilarityDelta ?? 1
    const maxSimilarity = input.maxSimilarity ?? 1
    const claim: StructuralDiffClaim = {
      kind: 'structural_diff',
      controlIds,
      variantIds,
      minRounds,
      minDeltaTokens,
      maxSimilarity,
      ...(input.message ? { message: input.message } : {}),
    }
    this.claims.push(claim)
    const missingEvidence: string[] = []
    if (!stableControl) missingEvidence.push('stable_control_arm')
    if (!stableVariant) missingEvidence.push('stable_variant_arm')
    if (stableDelta.length < minDeltaTokens) missingEvidence.push('stable_variant_delta')
    if (normalizeEquals(controlBodies[0] ?? '', variantBodies[0] ?? '')) missingEvidence.push('arm_differential')
    else if (similarity >= maxSimilarity) missingEvidence.push('arm_differential')
    return {
      ok: missingEvidence.length === 0,
      mode: 'boolean',
      controlIds,
      variantIds,
      claim,
      stats: {
        stableDelta,
        similarity: Number(similarity.toFixed(4)),
        rounds,
        stableControl,
        stableVariant,
      },
      exchanges: { control: controlExchanges, variant: variantExchanges },
      ...feedback(missingEvidence.length ? 'structural_diff' : null, missingEvidence, [
        ...controlExchanges.map(exchange => transcriptEntry('control', exchange)),
        ...variantExchanges.map(exchange => transcriptEntry('probe', exchange)),
      ]),
    }
  }

  /**
   * OOB callback proof. Mints a canary, registers its durable `pending_oob` subscription *before*
   * injecting, then waits and promotes a late callback. Fixes the Realism #2 wiring where the
   * callback could arrive after a synchronous check and the proof was abandoned.
   */
  async proveOobCallback(input: OobCallbackInput): Promise<OobCallbackProof> {
    const handle = await this.oob.mint(input.token ?? 'oob', undefined)
    const immediateMs = input.immediateMs ?? 3_000
    const windowMs = input.windowMs
    const subscription = await rpc('oob', {
      action: 'subscribe',
      token: handle.token,
      exchangeId: handle.exchangeId,
      immediateMs,
      ...(windowMs !== undefined ? { windowMs } : {}),
    }, 30_000) as { subscriptionId?: string; createdAt?: number; status?: string }
    let injection: HttpExchange | null = null
    let injectionError: string | null = null
    try {
      if (typeof input.inject === 'function') {
        const returned = await input.inject(handle)
        injection = returned ?? null
      } else {
        const spec = input.inject
        injection = await this.http(spec.target, {
          method: spec.method ?? 'POST',
          ...(spec.body !== undefined ? { body: renderInjection(spec.body, handle) } : {}),
          ...(spec.headers ? { headers: spec.headers } : {}),
          ...(spec.as ? { as: spec.as } : {}),
          role: 'probe',
          session: 'oob-injection',
        })
      }
    } catch (error) {
      injectionError = error instanceof Error ? error.message : 'OOB injection failed.'
    }
    const wait = await rpc('oob', {
      action: 'wait',
      token: handle.token,
      ...(subscription.subscriptionId ? { subscriptionId: subscription.subscriptionId } : {}),
      ...(typeof subscription.createdAt === 'number' ? { subscriptionCreatedAt: subscription.createdAt } : {}),
      immediateMs,
      timeoutMs: input.timeoutMs ?? Math.max(immediateMs, 6_000),
    }, (input.timeoutMs ?? 6_000) + 10_000) as {
      exchangeId?: string
      checkExchangeId?: string
      hit?: boolean
      stage?: OobCallbackProof['stage']
      promoted?: boolean
      subscriptionId?: string | null
    }
    const claim: OobClaim = { kind: 'oob', exchangeId: handle.exchangeId, expectHit: true, ...(input.message ? { message: input.message } : {}) }
    this.claims.push(claim)
    const hit = wait.hit === true
    const missingEvidence: string[] = []
    if (!subscription.subscriptionId) missingEvidence.push('pending_oob_subscription')
    if (injectionError) missingEvidence.push('injection')
    if (!hit) missingEvidence.push('oob_callback_hit')
    const mintEntry: ProofTranscriptEntry = {
      exchangeId: handle.exchangeId,
      role: 'oob_mint',
      personaHandle: null,
      method: 'MINT',
      pathAndQuery: '/',
      status: null,
      durationMs: 0,
    }
    return {
      ok: missingEvidence.length === 0,
      claim,
      token: handle.token,
      url: handle.url,
      dnsHost: handle.dnsHost,
      hit,
      stage: wait.stage ?? (hit ? 'immediate' : subscription.subscriptionId ? 'pending' : 'none'),
      promoted: wait.promoted === true,
      subscriptionId: wait.subscriptionId ?? subscription.subscriptionId ?? null,
      exchanges: { mint: handle.exchangeId, injection: injection?.exchangeId ?? null, wait: wait.exchangeId ?? wait.checkExchangeId ?? null },
      ...feedback(missingEvidence.length ? (injectionError ? 'injection' : 'oob') : null, missingEvidence, [
        mintEntry,
        ...(subscription.subscriptionId ? [{ ...mintEntry, exchangeId: subscription.subscriptionId, role: 'pending_oob' as const, method: 'SUBSCRIBE', note: subscription.status ?? 'pending' }] : []),
        ...(injection ? [transcriptEntry('oob_injection', injection)] : []),
        ...(wait.exchangeId ? [{
          exchangeId: wait.exchangeId,
          role: 'oob_wait' as const,
          personaHandle: null,
          method: 'WAIT',
          pathAndQuery: '/oob/wait',
          status: null,
          durationMs: 0,
          note: hit ? 'hit' : 'no callback',
        }] : []),
      ]),
    }
  }

  /**
   * Race/TOCTOU burst through the broker's synchronized HTTP/2 single-packet barrier (fallback
   * reported explicitly). Emits a `race` claim that fails on an idempotent/serialized handler.
   */
  async proveRaceBurst(input: RaceBurstInput): Promise<RaceBurstProof> {
    if (input.requests.length < 2 || input.requests.length > 10) {
      const claim: RaceClaim = { kind: 'race', exchangeIds: [], mode: 'http1-fallback', minDistinctOutcomes: input.minDistinctOutcomes ?? 2 }
      return {
        ok: false,
        claim,
        mode: 'http1-fallback',
        fallbackReason: 'race requires between 2 and 10 requests',
        summary: {},
        exchanges: [],
        ...feedback('race', ['race_requests'], []),
      }
    }
    const requests = input.requests.map((request, index) => {
      if (typeof request === 'string') {
        const target = splitTarget(request, this.defaultOrigin)
        return { ...(target.origin ? { origin: target.origin } : { origin: this.defaultOrigin }), path: target.path, method: 'GET', sessionGroupRole: 'probe', session: input.session ?? 'race' }
      }
      if ('url' in request && !('target' in request) && !('path' in request)) {
        const target = splitTarget(request as HttpTarget, this.defaultOrigin)
        return { ...(target.origin ? { origin: target.origin } : { origin: this.defaultOrigin }), path: target.path, method: 'GET', sessionGroupRole: 'probe', session: input.session ?? 'race' }
      }
      const spec = request as RaceRequestInput
      const rawTarget = spec.target ?? spec.url ?? spec.path ?? '/'
      const target = splitTarget(rawTarget as HttpTarget, this.defaultOrigin)
      return {
        origin: spec.origin ?? target.origin ?? this.defaultOrigin,
        path: target.path,
        method: (spec.method ?? 'GET').toUpperCase(),
        ...(spec.headers ? { headers: spec.headers } : {}),
        ...(spec.body !== undefined ? { body: spec.body } : {}),
        ...(spec.as ? { persona: spec.as } : {}),
        sessionGroupRole: 'probe',
        session: input.session ?? `race-${index}`,
      }
    })
    const result = await rpc('race', { requests }, (this.timeoutFor(requests.length) + 10_000)) as {
      mode?: 'h2-single-packet' | 'http1-fallback'
      fallbackReason?: string | null
      summary?: Record<string, unknown>
      results?: Array<{ exchangeId: string; status: number; durationMs: number; bodySha256: string }>
    }
    const mode = result.mode ?? 'http1-fallback'
    const exchanges = (result.results ?? []).map(item => ({
      exchangeId: item.exchangeId,
      status: item.status,
      durationMs: item.durationMs,
      bodySha256: item.bodySha256,
    }))
    const distinctBodies = new Set(exchanges.map(item => item.bodySha256)).size
    const distinctStatuses = new Set(exchanges.map(item => item.status)).size
    const distinctOutcomes = Math.max(distinctBodies, distinctStatuses)
    const minDistinct = input.minDistinctOutcomes ?? 2
    const claim: RaceClaim = {
      kind: 'race',
      exchangeIds: exchanges.map(item => item.exchangeId),
      mode,
      minDistinctOutcomes: minDistinct,
      expectAllSuccess: input.expectAllSuccess !== false,
      ...(input.message ? { message: input.message } : {}),
    }
    this.claims.push(claim)
    const missingEvidence: string[] = []
    if (input.barrier === 'h2' && mode !== 'h2-single-packet') missingEvidence.push('h2_single_packet_barrier')
    if (distinctOutcomes < minDistinct) missingEvidence.push('duplicate_effect')
    if (input.expectAllSuccess !== false && exchanges.some(item => !isSuccessStatus(item.status))) missingEvidence.push('all_participants_success')
    return {
      ok: missingEvidence.length === 0,
      claim,
      mode,
      fallbackReason: result.fallbackReason ?? null,
      summary: result.summary ?? {},
      exchanges,
      ...feedback(missingEvidence.length ? 'race' : null, missingEvidence,
        exchanges.map((item, index) => ({
          exchangeId: item.exchangeId,
          role: 'race' as const,
          personaHandle: null,
          method: requests[index]?.method ?? null,
          pathAndQuery: requests[index]?.path ?? null,
          status: item.status,
          durationMs: item.durationMs,
          note: mode,
        }))),
    }
  }

  private timeoutFor(requestCount: number): number {
    return Math.max(30_000, Math.min(60_000, 15_000 + requestCount * 2_000))
  }

  /** snake_case aliases matching the documented helper contract. */
  prove_access_boundary(input: AccessBoundaryInput): Promise<AccessBoundaryProof> { return this.proveAccessBoundary(input) }
  prove_persisted_mutation(input: PersistedMutationInput): Promise<PersistedMutationProof> { return this.provePersistedMutation(input) }
  prove_boolean_or_timing_diff(input: BooleanOrTimingDiffInput): Promise<DifferentialProof> { return this.proveBooleanOrTimingDiff(input) }
  prove_oob_callback(input: OobCallbackInput): Promise<OobCallbackProof> { return this.proveOobCallback(input) }
  prove_race_burst(input: RaceBurstInput): Promise<RaceBurstProof> { return this.proveRaceBurst(input) }

  result(input: { title: string; severity?: string; description?: string }): ProofResult {
    if (!input.title || !input.title.trim()) throw new Error('Proof result requires a title.')
    return {
      sdk: 'guardian_verify.ts',
      nonce: this.nonce,
      title: input.title.slice(0, 300),
      severity: (input.severity ?? 'high').slice(0, 32),
      ...(input.description ? { description: input.description.slice(0, 4000) } : {}),
      claims: [...this.claims],
    }
  }
}

export interface VerificationScript {
  setup?(ctx: VerifyContext): Promise<void> | void
  verify(ctx: VerifyContext): Promise<ProofResult> | ProofResult
  cleanup?(ctx: VerifyContext): Promise<void> | void
}

export function defineVerification(script: VerificationScript): VerificationScript {
  return script
}

function resultPath(): string {
  return process.env.GUARDIAN_PROOF_RESULT_FILE ?? join(dirname(process.env.GUARDIAN_RPC_CONTEXT_FILE ?? '/guardian-rpc/context.json'), 'result.json')
}

function writeResult(value: unknown): void {
  const path = resultPath()
  writeFileSync(path, JSON.stringify(value), { mode: 0o600 })
}

/** Run the 3-hook contract and emit the claims document. Never prints success as evidence. */
export async function runVerification(script: VerificationScript): Promise<void> {
  const ctx = new VerifyContext()
  let result: ProofResult | null = null
  try {
    await script.setup?.(ctx)
    result = await script.verify(ctx)
    await script.cleanup?.(ctx)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Verification script failed.'
    writeResult({ sdk: 'guardian_verify.ts', nonce: ctx.nonce, error: message.slice(0, 2000), claims: [] })
    process.stderr.write(`guardian_verify: ${message}\n`)
    process.exitCode = 1
    return
  }
  writeResult(result)
  process.stdout.write(`guardian_verify: ${result.claims.length} transcript-backed claim(s) recorded\n`)
}
