/**
 * guardian_verify (TypeScript) — thin, zero-dependency verification SDK for Guardian Layer 3.
 *
 * Every network/DOM/OOB/crypto/proof action crosses a Unix-domain socket into the Guardian host
 * process (`VerifyRpcServer`), which owns scope, credentials, HMAC-signed transcripts, and the
 * authoritative oracle (`prove.*` / `composite.verify`). Zero runtime dependencies beyond Node builtins.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { dirname, join } from 'node:path'

export type ClaimKind = 'status' | 'header' | 'body_contains' | 'jsonpath' | 'css' | 'dom_sentinel' | 'oob' | 'timing' | 'composite_receipt'

export interface StatusClaim { kind: 'status'; exchangeId: string; expected: number | number[]; message?: string }
export interface HeaderClaim { kind: 'header'; exchangeId: string; name: string; equals?: string; matches?: string; absent?: boolean; message?: string }
export interface BodyClaim { kind: 'body_contains'; exchangeId: string; text: string; absent?: boolean; vulnClass?: string; controlRequestBody?: unknown; probeRequestBody?: unknown; message?: string }
export interface JsonPathClaim { kind: 'jsonpath'; exchangeId: string; path: string; equals?: unknown; matches?: string; exists?: boolean; message?: string }
export interface CssClaim { kind: 'css'; exchangeId: string; selector: string; exists?: boolean; count?: number; textEquals?: string; textContains?: string; message?: string }
export interface SentinelsClaim { kind: 'dom_sentinel'; exchangeId: string; sentinel: string; mode?: 'source' | 'executed'; message?: string }
export interface OobClaim { kind: 'oob'; exchangeId: string; expectHit?: boolean; message?: string }
export interface TimingClaim { kind: 'timing'; controlIds: string[]; variantIds: string[]; minPairs?: number; maxPValue?: number; message?: string }
export interface StructuralDiffClaim { kind: 'structural_diff'; controlIds: string[]; variantIds: string[]; minRounds?: number; minDeltaTokens?: number; maxSimilarity?: number; message?: string }
export interface RaceClaim {
  kind: 'race'; exchangeIds: string[]; burstExchangeIds?: string[]; baselineExchangeId?: string; postExchangeId?: string
  serialExchangeIds?: string[]; serialPreExchangeId?: string; serialPostExchangeId?: string
  balanceField?: string; capField?: string; unitDebit?: number; vulnClass?: string; requestBody?: unknown
  mode?: 'h2-single-packet' | 'http1-fallback'; minDistinctOutcomes?: number; expectAllSuccess?: boolean; message?: string
}
export interface ImpactClaim {
  kind: 'impact'; impactClass: 'authorization' | 'bfla' | 'mass_assignment' | 'csrf' | 'injection'; vulnClass?: string
  probeExchangeId: string; controlExchangeIds?: string[]; beforeExchangeId?: string; afterExchangeId?: string
  requiredRole?: string; resourceTenant?: string; expectControlDenied?: boolean; oracleEvents?: string[]
  proofPatterns?: string[]; actorRoles?: Record<string, string>; actorTenants?: Record<string, string>
  requestBody?: unknown; ambient?: { kind: 'cookie' | 'bearer' | 'header' | 'unknown'; sameSite?: string }; message?: string
}
export interface BoundaryClaim {
  kind: 'boundary'; boundaryClass: 'auth' | 'mfa' | 'access' | 'other'; vulnClass?: string
  controlExchangeId: string; probeExchangeId: string; expectControlDenied?: boolean
  controlRequestBody?: unknown; probeRequestBody?: unknown
  actorRoles?: Record<string, string>; actorTenants?: Record<string, string>; message?: string
}
export interface CompositeReceiptClaim {
  kind: 'composite_receipt'; verificationId?: string; chainId: string; terminalVulnClass: string; cwe?: string; route?: string
  exchangeIds: string[]; terminalExchangeId?: string; replayMode?: 'fresh_clean_replay' | 'one_shot_transcript'
  hopCount?: number; compositeReceipt?: Record<string, unknown>; rejectedBy?: string | null; missingEvidence?: string[]; reason?: string; message?: string
}
export type VerifyClaim =
  | StatusClaim | HeaderClaim | BodyClaim | JsonPathClaim | CssClaim | SentinelsClaim
  | OobClaim | TimingClaim | StructuralDiffClaim | RaceClaim | ImpactClaim | BoundaryClaim | CompositeReceiptClaim

export type ProofRole =
  | 'setup' | 'control' | 'probe' | 'cleanup' | 'control_denied' | 'variant_crossed'
  | 'before_get' | 'mutation' | 'after_get' | 'oob_mint' | 'oob_injection' | 'oob_wait' | 'pending_oob' | 'race'

export interface ProofTranscriptEntry {
  exchangeId: string; role: ProofRole; personaHandle: string | null; method: string | null
  pathAndQuery: string | null; status: number | null; durationMs: number; note?: string
}
export interface ProofFeedback { rejectedBy: string | null; missingEvidence: string[]; transcriptSummary: ProofTranscriptEntry[] }

export interface AccessBoundaryProof extends ProofFeedback {
  ok: boolean; confirmed?: boolean; claim: BoundaryClaim; control: HttpExchange; probe: HttpExchange
  transcript: { control_denied: string; variant_crossed: string }
  evidence: { controlStatus: number; variantStatus: number; controlDenied: boolean; crossed: boolean }
}
export interface PersistedMutationProof extends ProofFeedback {
  ok: boolean; confirmed?: boolean; claim: ImpactClaim; before: HttpExchange; mutation: HttpExchange; after: HttpExchange
  delta: { fieldPath: string; before: unknown; after: unknown; changed: boolean; changedFields: string[]; added: string[]; removed: string[] }
  expectationMatched: boolean
}
export interface DifferentialProof extends ProofFeedback {
  ok: boolean; confirmed?: boolean; mode: 'boolean' | 'timing'; controlIds: string[]; variantIds: string[]
  claim: StructuralDiffClaim | TimingClaim; stats: Record<string, number | string | boolean | string[]>
  exchanges: { control: HttpExchange[]; variant: HttpExchange[] }
}
export interface OobCallbackProof extends ProofFeedback {
  ok: boolean; confirmed?: boolean; claim: OobClaim; token: string; url: string; dnsHost: string
  hit: boolean; stage: 'immediate' | 'late' | 'pending' | 'none'; promoted: boolean; subscriptionId: string | null
  exchanges: { mint: string; injection: string | null; wait: string | null }
}
export interface RaceBurstProof extends ProofFeedback {
  ok: boolean; confirmed?: boolean; claim: RaceClaim; mode: 'h2-single-packet' | 'http1-fallback'
  fallbackReason: string | null; summary: Record<string, unknown>
  exchanges: Array<{ exchangeId: string; status: number; durationMs: number; bodySha256: string }>
  baseline?: HttpExchange | null; post?: HttpExchange | null; serial?: HttpExchange | null; serialPost?: HttpExchange | null
}
export interface InjectionDifferentialProof extends ProofFeedback {
  ok: boolean; confirmed?: boolean; control: HttpExchange; probe: HttpExchange; claim?: VerifyClaim; claims: VerifyClaim[]; evaluated: boolean
}

export interface AccessBoundaryInput {
  controlPersona?: string | null; probePersona?: string | null; route: HttpTarget; probeRoute?: HttpTarget
  expectControlDenied?: boolean; method?: string; controlOptions?: HttpOptions; probeOptions?: HttpOptions
  controlSession?: string; probeSession?: string; boundaryClass?: 'auth' | 'access'; vulnClass?: string
  actorRoles?: Record<string, string>; actorTenants?: Record<string, string>; message?: string
}
export interface PersistedMutationInput {
  readRoute: HttpTarget
  mutation: HttpTarget | { target: HttpTarget; method?: string; body?: string; headers?: Record<string, string>; as?: string; session?: string }
  fieldPath: string
  expectDelta: unknown | ((before: unknown, after: unknown, delta: PersistedMutationProof['delta']) => boolean)
  readPersona?: string; mutatePersona?: string; readMethod?: string; readSession?: string
  impactClass?: 'authorization' | 'bfla' | 'mass_assignment' | 'csrf'; requiredRole?: string; resourceTenant?: string
  oracleEvents?: string[]; actorRoles?: Record<string, string>; actorTenants?: Record<string, string>; message?: string
}
export interface DifferentialArmInput { target: HttpTarget; options?: HttpOptions }
export interface BooleanOrTimingDiffInput {
  control: DifferentialArmInput | HttpTarget; variant: DifferentialArmInput | HttpTarget; mode: 'boolean' | 'timing'
  rounds?: number; minSimilarityDelta?: number; minDeltaTokens?: number; maxSimilarity?: number; maxPValue?: number; session?: string; message?: string
}
export interface OobInjectionInput { target: HttpTarget; method?: string; headers?: Record<string, string>; body?: string; as?: string }
export interface OobCallbackInput {
  inject: ((canary: { url: string; token: string; dnsHost: string }) => Promise<HttpExchange | void> | HttpExchange | void) | OobInjectionInput
  token?: string; timeoutMs?: number; immediateMs?: number; windowMs?: number; message?: string
}
export interface RaceRequestInput {
  target?: HttpTarget; url?: HttpTarget; path?: string; origin?: string; method?: string
  headers?: Record<string, string>; body?: string | Record<string, unknown> | unknown[]; as?: string
}
export interface RaceBurstInput {
  requests: Array<RaceRequestInput | HttpTarget>; barrier?: 'auto' | 'h2' | 'http1'; session?: string
  minDistinctOutcomes?: number; expectAllSuccess?: boolean; readRoute?: HttpTarget; readMethod?: string; readPersona?: string
  serialRequest?: RaceRequestInput | HttpTarget; balanceField?: string; capField?: string; unitDebit?: number; vulnClass?: string
  baselineExchangeId?: string; postExchangeId?: string; serialExchangeIds?: string[]; serialPreExchangeId?: string; serialPostExchangeId?: string; message?: string
}
export interface InjectionDifferentialInput {
  control?: DifferentialArmInput | HttpTarget; probe?: DifferentialArmInput | HttpTarget; variant?: DifferentialArmInput | HttpTarget
  url?: string; path?: string; pathAndQuery?: string; endpoint?: string; route?: string; method?: string
  headers?: Record<string, string>; as?: string; controlBody?: string | Record<string, unknown>; probeBody?: string | Record<string, unknown>
  expectedOutput?: string; vulnClass?: string; session?: string; message?: string
}

export interface ProofResult { sdk: 'guardian_verify.ts'; nonce: string; title: string; severity: string; description?: string; claims: VerifyClaim[] }
export interface RpcContext { nonce: string; runId: string; targetOrigins: string[]; sdkVersion: string }
interface RpcEnvelope { ok: boolean; result?: unknown; error?: string }

export interface HttpExchange {
  exchangeId: string; status: number; method: string; pathAndQuery: string; finalPathAndQuery?: string
  redirectOrigins?: string[]; mediaType: string; headers: Record<string, string>; body: string; bodyPreview: string
  bodyBytes: number; bodySha256: string; durationMs: number; personaHandle: string | null
  consumedCapabilityId?: string | null; derivedFromCapabilityIds?: string[]; protocol?: 'h2'
}
export interface CapabilityInjectionSpec { handle: string; target?: 'bearer' | 'header' | 'cookie' | 'url'; headerName?: string; cookieName?: string; queryParam?: string }
export interface SealCapabilityInput {
  exchangeId?: string; exchange?: { exchangeId: string } | null; hopReceiptId?: string; hopId?: string; slot: string
  jsonPath?: string; header?: string; cookie?: string; regex?: string; value?: string
  kind?: 'bearer_token' | 'api_token' | 'cookie' | 'signed_url' | 'oidc_assertion' | 'signing_salt' | 'hmac_key' | 'jwt' | 'header_secret' | 'generic_secret'
  ttlMs?: number | null; defaultHeaderName?: string; defaultCookieName?: string; allowedOrigins?: string[]
}
export interface SealedCapabilityResult { handle: string; meta: Record<string, unknown>; exchangeId: string; sealExchangeId: string; scrubbedPreview: string }
export interface HmacSignInput {
  secretHandle?: string; secret_handle?: string; keyHandle?: string; key_handle?: string
  payload?: string | Record<string, unknown> | unknown[]; message?: string | Record<string, unknown> | unknown[]; body?: string | Record<string, unknown> | unknown[]
  alg?: 'sha256' | 'sha384' | 'sha512'; algorithm?: 'sha256' | 'sha384' | 'sha512'; encoding?: 'hex' | 'base64' | 'base64url'
}
export interface HmacSignResult {
  exchangeId: string; signature: string; handle: string; derivedHandle: string
  attestation: { derivedFromCapabilityId: string; alg: string; encoding: string; payloadDigest: string; signatureDigest: string; sourceSecretDigest: string; runId: string; timestampMs: number }
}
export interface JwtSignInput {
  secretHandle?: string; secret_handle?: string; keyHandle?: string; key_handle?: string
  claims?: Record<string, unknown>; payload?: Record<string, unknown>
  alg?: 'HS256' | 'HS384' | 'HS512'; algorithm?: 'HS256' | 'HS384' | 'HS512'; header?: Record<string, unknown>
  hopReceiptId?: string; hop_receipt_id?: string; slot?: string; ttlMs?: number | null; ttl_ms?: number | null; allowedOrigins?: string[]; allowed_origins?: string[]
}
export interface JwtSignResult {
  exchangeId: string; derivedHandle: string; handle: string; token: string
  attestation: { derivedFromCapabilityId: string; derivedHandle: string; alg: string; claimsDigest: string; tokenDigest: string; sourceSecretDigest: string; runId: string; timestampMs: number }
}
export interface AsyncMatchPredicate {
  status?: number | number[]; bodyContains?: string; bodyMatches?: string; jsonPath?: string; equals?: unknown
  in?: unknown[]; matches?: string; header?: { name: string; equals?: string; matches?: string }
}
export interface AsyncAwaitInput extends HttpOptions {
  pollRequest?: HttpTarget | (HttpOptions & { path?: string; url?: string; origin?: string })
  poll_request?: HttpTarget; request?: HttpTarget
  path?: string; url?: string; pathAndQuery?: string; endpoint?: string; route?: string; target?: HttpTarget; origin?: string
  matchPredicate?: AsyncMatchPredicate; match_predicate?: AsyncMatchPredicate; match?: AsyncMatchPredicate; predicate?: AsyncMatchPredicate
  until?: AsyncMatchPredicate | string | number | number[]; expectStatus?: number | number[]; expect_status?: number | number[]
  profile?: 'fast_lab' | 'wan'; timeoutMs?: number; timeout_ms?: number; intervalMs?: number; interval_ms?: number
  maxAttempts?: number; max_attempts?: number; triggerExchangeId?: string | { exchangeId: string }; trigger_exchange_id?: string | { exchangeId: string }
  tTriggerMs?: number; t_trigger_ms?: number; correlationId?: string; correlation_id?: string; correlationIds?: string[]; correlation_ids?: string[]
  entityId?: string; entity_id?: string
}
export interface AsyncAwaitResult {
  pollRecordId: string; converged: boolean; status: 'converged' | 'timeout' | 'aborted' | 'max_attempts' | 'monotonic_violation'
  exchangeId: string | null; exchange: HttpExchange | null; evidence: Record<string, unknown>
}
export interface CompositeVerificationResult {
  confirmed: boolean; ok?: boolean; verified?: boolean; verificationId?: string; chainId: string; terminalVulnClass: string
  replayMode: 'fresh_clean_replay' | 'one_shot_transcript'; modeBVerified: boolean; hopCount: number
  verifiedEdges: Array<Record<string, unknown>>; reason: string; failedStage?: string; rejectedBy?: string | null
  missingEvidence?: string[]; claim?: CompositeReceiptClaim; terminalVerification?: Record<string, unknown>; evidence?: Record<string, unknown>
}
export interface BrowserExchange { exchangeId: string; status: number; url: string; html: string; title?: string; executedSentinels: string[]; durationMs: number }
export interface OobHandle { exchangeId: string; token: string; url: string; dnsHost: string }
export interface OobCheck extends OobHandle { hit: boolean; checkExchangeId?: string; hits: Array<{ protocol: string; token: string; remoteIp?: string; timestamp?: number }> }

export interface HttpOptions {
  as?: string; persona?: string; session?: string; role?: 'setup' | 'control' | 'probe' | 'cleanup'
  method?: string; headers?: Record<string, string>; body?: string | Record<string, unknown> | unknown[]
  followRedirects?: boolean; timeoutMs?: number; capability?: string | CapabilityInjectionSpec
  capabilityTarget?: 'bearer' | 'header' | 'cookie' | 'url'; capabilityHeaderName?: string; capabilityCookieName?: string
  capabilityQueryParam?: string; entityId?: string; correlationIds?: string[]; evidenceRole?: string
  replayAttempt?: 'mode_a' | 'ablation_control' | 'primary'
}
export type HttpTarget = string | (HttpOptions & { url?: string; path?: string; pathAndQuery?: string; endpoint?: string; route?: string; target?: HttpTarget; origin?: string })
export interface TimingResult { controlIds: string[]; variantIds: string[]; claim: TimingClaim }

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

function readContext(): RpcContext {
  const raw = JSON.parse(readFileSync(process.env.GUARDIAN_RPC_CONTEXT_FILE ?? '/guardian-rpc/context.json', 'utf8')) as Record<string, unknown>
  return {
    nonce: typeof raw.nonce === 'string' ? raw.nonce : '',
    runId: typeof raw.runId === 'string' ? raw.runId : 'unknown-run',
    targetOrigins: Array.isArray(raw.targetOrigins) ? raw.targetOrigins.filter((v): v is string => typeof v === 'string') : [],
    sdkVersion: typeof raw.sdkVersion === 'string' ? raw.sdkVersion : 'guardian_verify/v6-mvp',
  }
}

function rpc(op: string, args: Record<string, unknown>, timeoutMs = 60_000): Promise<unknown> {
  const socketPath = process.env.GUARDIAN_RPC_SOCKET ?? '/guardian-rpc/verify.sock'
  const context = readContext()
  const nonce = process.env.GUARDIAN_VERIFY_NONCE ?? context.nonce
  const token = readFileSync(process.env.GUARDIAN_RPC_TOKEN_FILE ?? '/guardian-rpc/token', 'utf8').trim()
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
        if (size > 8 * 1024 * 1024) { res.destroy(); reject(new Error('Verification RPC response exceeded the SDK limit.')); return }
        chunks.push(chunk)
      })
      res.on('end', () => {
        let body: RpcEnvelope
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcEnvelope } catch {
          reject(new Error('Verification RPC returned malformed JSON.')); return
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

function normalizeBodyAndHeaders(rawBody: unknown, rawHeaders?: Record<string, string>): { body?: string; headers?: Record<string, string> } {
  const headers = rawHeaders ? { ...rawHeaders } : undefined
  if (rawBody === undefined || rawBody === null) return { ...(headers ? { headers } : {}) }
  if (typeof rawBody === 'string') return { body: rawBody, ...(headers ? { headers } : {}) }
  const hasCt = Object.keys(headers ?? {}).some(k => k.toLowerCase() === 'content-type')
  return { body: JSON.stringify(rawBody), headers: hasCt ? headers : { 'content-type': 'application/json', ...(headers ?? {}) } }
}

function splitTarget(input: HttpTarget, defaultOrigin: string | undefined): { origin?: string; path: string } {
  if (typeof input === 'string') {
    const trimmed = input.trim()
    if (!trimmed) throw new Error('HTTP target path/URL must be non-empty.')
    if (/^https?:\/\//i.test(trimmed)) {
      const u = new URL(trimmed)
      return { origin: u.origin, path: u.pathname + u.search }
    }
    return { ...(defaultOrigin ? { origin: defaultOrigin } : {}), path: trimmed.startsWith('/') ? trimmed : `/${trimmed}` }
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('HTTP target requires a path/URL string or an object with { url | path | pathAndQuery | endpoint }.')
  }
  const raw = input.url ?? input.path ?? input.pathAndQuery ?? input.endpoint ?? input.route
  if (typeof raw === 'string' && raw.trim()) {
    const res = splitTarget(raw, input.origin ?? defaultOrigin)
    return { ...(input.origin ? { origin: input.origin } : (res.origin ? { origin: res.origin } : {})), path: res.path }
  }
  if (input.target !== undefined) {
    const nested = splitTarget(input.target, input.origin ?? defaultOrigin)
    return { ...(input.origin ? { origin: input.origin } : (nested.origin ? { origin: nested.origin } : {})), path: nested.path }
  }
  throw new Error('HTTP target requires a path/URL string or an object with { url | path | pathAndQuery | endpoint }.')
}

function extractInlineHttpOptions(input: unknown): HttpOptions {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {}
  const r = input as Record<string, unknown>
  const out: HttpOptions = {}
  if (typeof r.method === 'string' && r.method.trim()) out.method = r.method.trim().toUpperCase()
  if (r.headers && typeof r.headers === 'object' && !Array.isArray(r.headers)) out.headers = r.headers as Record<string, string>
  if (r.body !== undefined) out.body = r.body as HttpOptions['body']
  const persona = typeof r.as === 'string' ? r.as : typeof r.persona === 'string' ? r.persona : undefined
  if (persona) out.as = persona
  for (const k of ['session', 'role', 'followRedirects', 'timeoutMs', 'capability', 'capabilityTarget', 'capabilityHeaderName', 'capabilityCookieName', 'capabilityQueryParam', 'entityId', 'correlationIds', 'evidenceRole', 'replayAttempt'] as const) {
    if (r[k] !== undefined) (out as Record<string, unknown>)[k] = r[k]
  }
  return out
}

function resolveCapHandle(value: unknown): string {
  if (typeof value === 'string') return value
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const r = value as Record<string, unknown>
    return String(r.handle ?? r.derivedHandle ?? r.cap_id ?? '')
  }
  return ''
}

function normalizePayloadStr(value: unknown): string {
  if (typeof value === 'string') return value
  return value === undefined || value === null ? '' : JSON.stringify(value)
}

function normalizeAsyncPredicate(raw: unknown, expectStatus?: unknown): AsyncMatchPredicate | undefined {
  const pred: Record<string, unknown> = {}
  if (typeof raw === 'string') pred.bodyContains = raw
  else if (typeof raw === 'number' || Array.isArray(raw)) pred.status = raw
  else if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    Object.assign(pred, raw as Record<string, unknown>)
    for (const [src, dst] of [['body_contains', 'bodyContains'], ['body_matches', 'bodyMatches'], ['json_path', 'jsonPath'], ['expect_status', 'status'], ['expectStatus', 'status']] as const) {
      if (src in pred && !(dst in pred)) { pred[dst] = pred[src]; delete pred[src] }
    }
  }
  if (expectStatus !== undefined && pred.status === undefined) pred.status = expectStatus
  return Object.keys(pred).length > 0 ? (pred as AsyncMatchPredicate) : undefined
}

export class VerifyContext {
  readonly nonce: string
  readonly runId: string
  readonly targetOrigins: string[]
  readonly targetOrigin: string
  readonly sdkVersion: string
  readonly claims: VerifyClaim[] = []
  readonly expect: Expectations
  readonly assert: Expectations
  private readonly defaultOrigin: string | undefined
  private _lastFailedCompositeClaim: CompositeReceiptClaim | null = null

  constructor() {
    const context = readContext()
    this.nonce = process.env.GUARDIAN_VERIFY_NONCE ?? context.nonce
    this.runId = context.runId
    this.targetOrigins = context.targetOrigins
    this.targetOrigin = this.targetOrigins[0] ?? ''
    this.sdkVersion = context.sdkVersion
    this.defaultOrigin = this.targetOrigins[0]
    const push = <T extends VerifyClaim>(claim: T): T => { this.claims.push(claim); return claim }
    const expectations: Expectations = {
      status: (ex, expected, message) => push({ kind: 'status', exchangeId: ex.exchangeId, expected, ...(message ? { message } : {}) }),
      statusNot: (ex, unexpected, message) => push({ kind: 'status', exchangeId: ex.exchangeId, expected: [200, 201, 202, 204, 301, 302, 400, 401, 403, 404, 405].filter(c => c !== unexpected), ...(message ? { message } : {}) }),
      header: (ex, name, expected, message) => push({ kind: 'header', exchangeId: ex.exchangeId, name, ...(typeof expected === 'string' ? { equals: expected } : (expected ?? {})), ...(message ? { message } : {}) }),
      bodyContains: (ex, text, message) => push({ kind: 'body_contains', exchangeId: ex.exchangeId, text, ...(message ? { message } : {}) }),
      bodyAbsent: (ex, text, message) => push({ kind: 'body_contains', exchangeId: ex.exchangeId, text, absent: true, ...(message ? { message } : {}) }),
      jsonPath: (ex, path, expected, message) => push({ kind: 'jsonpath', exchangeId: ex.exchangeId, path, ...(expected === undefined ? { exists: true } : { equals: expected }), ...(message ? { message } : {}) }),
      css: (ex, selector, expected, message) => push({ kind: 'css', exchangeId: ex.exchangeId, selector, ...(expected ?? {}), ...(message ? { message } : {}) }),
      domSentinel: (ex, sentinel, mode, message) => push({ kind: 'dom_sentinel', exchangeId: ex.exchangeId, sentinel, mode: mode ?? 'executed', ...(message ? { message } : {}) }),
      oob: (ex, expectHit, message) => push({ kind: 'oob', exchangeId: ex.exchangeId, expectHit: expectHit ?? true, ...(message ? { message } : {}) }),
      timing: (result, message) => push({ ...result.claim, ...(message ? { message } : {}) }),
    }
    this.expect = expectations
    this.assert = expectations
  }

  private buildHttpRpcArgs(input: HttpTarget, options: HttpOptions = {}): { args: Record<string, unknown>; timeoutMs: number } {
    const target = splitTarget(input, this.defaultOrigin)
    const merged: HttpOptions = { ...extractInlineHttpOptions(input), ...options }
    const { body, headers } = normalizeBodyAndHeaders(merged.body, merged.headers)
    const persona = merged.as ?? merged.persona
    return {
      args: {
        ...(target.origin ? { origin: target.origin } : {}),
        path: target.path,
        method: (merged.method ?? 'GET').toUpperCase(),
        ...(headers ? { headers } : {}),
        ...(body !== undefined ? { body } : {}),
        ...(persona ? { persona } : {}),
        ...(merged.session ? { session: merged.session } : {}),
        ...(merged.role ? { sessionGroupRole: merged.role } : {}),
        ...(merged.followRedirects !== undefined ? { followRedirects: merged.followRedirects } : {}),
        ...(merged.capability !== undefined ? { capability: merged.capability } : {}),
        ...(merged.capabilityTarget ? { capabilityTarget: merged.capabilityTarget } : {}),
        ...(merged.capabilityHeaderName ? { capabilityHeaderName: merged.capabilityHeaderName } : {}),
        ...(merged.capabilityCookieName ? { capabilityCookieName: merged.capabilityCookieName } : {}),
        ...(merged.capabilityQueryParam ? { capabilityQueryParam: merged.capabilityQueryParam } : {}),
        ...(merged.entityId ? { entityId: merged.entityId } : {}),
        ...(merged.correlationIds?.length ? { correlationIds: merged.correlationIds } : {}),
        ...(merged.evidenceRole ? { evidenceRole: merged.evidenceRole } : {}),
        ...(merged.replayAttempt ? { replayAttempt: merged.replayAttempt } : {}),
      },
      timeoutMs: (merged.timeoutMs ?? 60_000) + 10_000,
    }
  }

  async http(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> {
    const { args, timeoutMs } = this.buildHttpRpcArgs(input, options)
    return await rpc('http', args, timeoutMs) as HttpExchange
  }

  async httpSend(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> {
    const { args, timeoutMs } = this.buildHttpRpcArgs(input, options)
    return await rpc('http.send', args, timeoutMs) as HttpExchange
  }

  http_send(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> { return this.httpSend(input, options) }
  request(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> { return this.httpSend(input, options) }

  async sealCapability(input: SealCapabilityInput): Promise<SealedCapabilityResult> {
    const exchangeId = input.exchangeId ?? input.exchange?.exchangeId
    if (!exchangeId) throw new Error('sealCapability requires exchangeId or exchange.')
    return await rpc('capability.seal', {
      exchangeId,
      slot: input.slot,
      ...(input.hopReceiptId ? { hopReceiptId: input.hopReceiptId } : {}),
      ...(input.hopId ? { hopId: input.hopId } : {}),
      ...(input.jsonPath ? { jsonPath: input.jsonPath } : {}),
      ...(input.header ? { header: input.header } : {}),
      ...(input.cookie ? { cookie: input.cookie } : {}),
      ...(input.regex ? { regex: input.regex } : {}),
      ...(input.value !== undefined ? { value: input.value } : {}),
      ...(input.kind ? { kind: input.kind } : {}),
      ...(input.ttlMs !== undefined ? { ttlMs: input.ttlMs } : {}),
      ...(input.defaultHeaderName ? { defaultHeaderName: input.defaultHeaderName } : {}),
      ...(input.defaultCookieName ? { defaultCookieName: input.defaultCookieName } : {}),
      ...(input.allowedOrigins?.length ? { allowedOrigins: input.allowedOrigins } : {}),
    }, 30_000) as SealedCapabilityResult
  }

  seal_capability(input: SealCapabilityInput | Record<string, unknown>): Promise<SealedCapabilityResult> {
    const r = input as Record<string, unknown>
    return this.sealCapability({
      ...(r as unknown as SealCapabilityInput),
      ...((r.exchangeId ?? r.exchange_id) ? { exchangeId: String(r.exchangeId ?? r.exchange_id) } : {}),
      ...((r.hopReceiptId ?? r.hop_receipt_id) ? { hopReceiptId: String(r.hopReceiptId ?? r.hop_receipt_id) } : {}),
      ...((r.hopId ?? r.hop_id) ? { hopId: String(r.hopId ?? r.hop_id) } : {}),
      ...((r.jsonPath ?? r.json_path) ? { jsonPath: String(r.jsonPath ?? r.json_path) } : {}),
      ...((r.ttlMs ?? r.ttl_ms) !== undefined ? { ttlMs: (r.ttlMs ?? r.ttl_ms) as number | null } : {}),
      ...((r.defaultHeaderName ?? r.default_header_name) ? { defaultHeaderName: String(r.defaultHeaderName ?? r.default_header_name) } : {}),
      ...((r.defaultCookieName ?? r.default_cookie_name) ? { defaultCookieName: String(r.defaultCookieName ?? r.default_cookie_name) } : {}),
      ...((r.allowedOrigins ?? r.allowed_origins) ? { allowedOrigins: (r.allowedOrigins ?? r.allowed_origins) as string[] } : {}),
    })
  }

  async hmacSign(
    inputOrSecret: HmacSignInput | Record<string, unknown> | string,
    payloadArg?: string | Record<string, unknown> | unknown[],
    opts?: { alg?: string; algorithm?: string; encoding?: string } | string,
    encodingArg?: string,
  ): Promise<HmacSignResult> {
    let secretHandle = ''
    let rawPayload: unknown
    let alg: string | undefined
    let encoding: string | undefined
    const isPos = typeof inputOrSecret === 'string' || (
      payloadArg !== undefined && inputOrSecret && typeof inputOrSecret === 'object'
      && !('secretHandle' in inputOrSecret) && !('secret_handle' in inputOrSecret) && !('keyHandle' in inputOrSecret) && !('key_handle' in inputOrSecret)
    )
    if (isPos) {
      secretHandle = resolveCapHandle(inputOrSecret)
      rawPayload = payloadArg
      const o = typeof opts === 'string' ? { alg: opts } : (opts ?? {})
      alg = o.alg ?? o.algorithm
      encoding = encodingArg ?? o.encoding
    } else if (inputOrSecret && typeof inputOrSecret === 'object') {
      const r = inputOrSecret as Record<string, unknown>
      secretHandle = resolveCapHandle(r.secretHandle ?? r.secret_handle ?? r.keyHandle ?? r.key_handle ?? '')
      rawPayload = r.payload ?? r.message ?? r.body
      alg = (r.alg ?? r.algorithm) as string | undefined
      encoding = r.encoding as string | undefined
    }
    const res = await rpc('crypto.hmacSign', {
      secretHandle,
      payload: normalizePayloadStr(rawPayload),
      ...(alg ? { alg } : {}),
      ...(encoding ? { encoding } : {}),
    }, 30_000) as HmacSignResult
    const handle = res.handle ?? res.derivedHandle ?? res.signature
    return { ...res, signature: res.signature, handle, derivedHandle: res.derivedHandle ?? handle }
  }

  hmac_sign(
    inputOrSecret: HmacSignInput | Record<string, unknown> | string,
    payloadArg?: string | Record<string, unknown> | unknown[],
    opts?: { alg?: string; algorithm?: string; encoding?: string } | string,
    encodingArg?: string,
  ): Promise<HmacSignResult> { return this.hmacSign(inputOrSecret, payloadArg, opts, encodingArg) }

  async jwtSign(
    inputOrSecret: JwtSignInput | Record<string, unknown> | string,
    claimsArg?: Record<string, unknown>,
    opts?: Omit<JwtSignInput, 'secretHandle' | 'claims'> | Record<string, unknown> | string,
  ): Promise<JwtSignResult> {
    const isPos = typeof inputOrSecret === 'string' || (
      claimsArg !== undefined && inputOrSecret && typeof inputOrSecret === 'object'
      && !('secretHandle' in inputOrSecret) && !('secret_handle' in inputOrSecret) && !('keyHandle' in inputOrSecret) && !('key_handle' in inputOrSecret)
    )
    const r: Record<string, unknown> = isPos
      ? (typeof opts === 'string' ? { alg: opts } : { ...(opts ?? {}) })
      : ((inputOrSecret && typeof inputOrSecret === 'object' ? inputOrSecret : {}) as Record<string, unknown>)
    const secretHandle = isPos
      ? resolveCapHandle(inputOrSecret)
      : resolveCapHandle(r.secretHandle ?? r.secret_handle ?? r.keyHandle ?? r.key_handle ?? '')
    const claims = (isPos ? claimsArg : (r.claims ?? r.payload ?? {})) as Record<string, unknown>
    const alg = (r.alg ?? r.algorithm) as string | undefined
    const hopReceiptId = r.hopReceiptId ?? r.hop_receipt_id
    const ttlMs = r.ttlMs ?? r.ttl_ms
    const allowedOrigins = (r.allowedOrigins ?? r.allowed_origins) as string[] | undefined
    const res = await rpc('crypto.jwtSign', {
      secretHandle,
      claims: claims ?? {},
      ...(alg ? { alg } : {}),
      ...(r.header ? { header: r.header } : {}),
      ...(hopReceiptId ? { hopReceiptId: String(hopReceiptId) } : {}),
      ...(r.slot ? { slot: String(r.slot) } : {}),
      ...(ttlMs !== undefined ? { ttlMs } : {}),
      ...(allowedOrigins?.length ? { allowedOrigins } : {}),
    }, 30_000) as JwtSignResult
    return { ...res, handle: res.handle ?? res.derivedHandle, token: res.token ?? res.derivedHandle }
  }

  jwt_sign(
    inputOrSecret: JwtSignInput | Record<string, unknown> | string,
    claimsArg?: Record<string, unknown>,
    opts?: Omit<JwtSignInput, 'secretHandle' | 'claims'> | Record<string, unknown> | string,
  ): Promise<JwtSignResult> { return this.jwtSign(inputOrSecret, claimsArg, opts) }

  async awaitAsync(
    input: AsyncAwaitInput | Record<string, unknown> | string,
    matchPredicateArg?: AsyncMatchPredicate | Record<string, unknown> | string | number | number[],
    opts?: Record<string, unknown>,
  ): Promise<AsyncAwaitResult> {
    const r: Record<string, unknown> = typeof input === 'string'
      ? { ...(opts ?? {}), pollRequest: input }
      : { ...(input as Record<string, unknown>), ...(opts ?? {}) }
    const pollRaw = r.pollRequest ?? r.poll_request ?? r.request
    const { args: pollRequest } = pollRaw !== undefined
      ? this.buildHttpRpcArgs(pollRaw as HttpTarget, typeof pollRaw === 'string' ? extractInlineHttpOptions(r) : {})
      : this.buildHttpRpcArgs(r as HttpTarget)
    const matchPredicate = normalizeAsyncPredicate(
      matchPredicateArg ?? r.matchPredicate ?? r.match_predicate ?? r.match ?? r.predicate ?? r.until,
      r.expectStatus ?? r.expect_status,
    )
    const timeoutMs = (r.timeoutMs ?? r.timeout_ms) !== undefined ? Number(r.timeoutMs ?? r.timeout_ms) : undefined
    const intervalMs = (r.intervalMs ?? r.interval_ms) !== undefined ? Number(r.intervalMs ?? r.interval_ms) : undefined
    const maxAttempts = (r.maxAttempts ?? r.max_attempts) !== undefined ? Number(r.maxAttempts ?? r.max_attempts) : undefined
    const trigRaw = r.triggerExchangeId ?? r.trigger_exchange_id
    const triggerExchangeId = typeof trigRaw === 'string' ? trigRaw
      : (trigRaw && typeof trigRaw === 'object' ? String((trigRaw as Record<string, unknown>).exchangeId ?? '') : undefined)
    const tTriggerMs = (r.tTriggerMs ?? r.t_trigger_ms) !== undefined ? Number(r.tTriggerMs ?? r.t_trigger_ms) : undefined
    const correlationId = r.correlationId ?? r.correlation_id
    const correlationIds = (r.correlationIds ?? r.correlation_ids) as string[] | undefined
    const entityId = r.entityId ?? r.entity_id
    return await rpc('async.awaitResult', {
      pollRequest,
      ...(matchPredicate ? { matchPredicate } : {}),
      ...(r.profile ? { profile: r.profile } : {}),
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      ...(intervalMs !== undefined ? { intervalMs } : {}),
      ...(maxAttempts !== undefined ? { maxAttempts } : {}),
      ...(triggerExchangeId ? { triggerExchangeId } : {}),
      ...(tTriggerMs !== undefined ? { tTriggerMs } : {}),
      ...(correlationId ? { correlationId: String(correlationId) } : {}),
      ...(correlationIds?.length ? { correlationIds } : {}),
      ...(entityId ? { entityId: String(entityId) } : {}),
    }, Math.max((timeoutMs ?? 30_000) + 10_000, 15_000)) as AsyncAwaitResult
  }

  await_async(
    input: AsyncAwaitInput | Record<string, unknown> | string,
    matchPredicateArg?: AsyncMatchPredicate | Record<string, unknown> | string | number | number[],
    opts?: Record<string, unknown>,
  ): Promise<AsyncAwaitResult> { return this.awaitAsync(input, matchPredicateArg, opts) }

  async proveComposite(receipt: Record<string, unknown>): Promise<CompositeVerificationResult> {
    const payload = receipt && typeof receipt === 'object' && 'receipt' in receipt ? receipt : { receipt }
    const res = await rpc('composite.verify', payload as Record<string, unknown>, 30_000) as CompositeVerificationResult
    const confirmed = res.confirmed === true || res.ok === true || res.verified === true
    if (res.claim) {
      if (confirmed) { this._lastFailedCompositeClaim = null; this.claims.push(res.claim) }
      else { this._lastFailedCompositeClaim = res.claim }
    }
    return { ...res, confirmed, ok: confirmed, verified: confirmed }
  }

  prove_composite(receipt: Record<string, unknown>): Promise<CompositeVerificationResult> { return this.proveComposite(receipt) }

  effectiveClaims(): VerifyClaim[] {
    if (this.claims.length > 0) return [...this.claims]
    return this._lastFailedCompositeClaim ? [this._lastFailedCompositeClaim] : []
  }

  async http2(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> {
    const { args, timeoutMs } = this.buildHttpRpcArgs(input, options)
    return await rpc('http2', args, timeoutMs) as HttpExchange
  }

  async browser(input: HttpTarget, options: { as?: string; waitForSelector?: string; timeoutMs?: number } = {}): Promise<BrowserExchange> {
    const target = splitTarget(input, this.defaultOrigin)
    return await rpc('browser', {
      ...(target.origin ? { origin: target.origin } : {}),
      path: target.path,
      ...(options.as ? { persona: options.as } : {}),
      ...(options.waitForSelector ? { waitForSelector: options.waitForSelector } : {}),
    }, (options.timeoutMs ?? 60_000) + 10_000) as BrowserExchange
  }

  readonly oob = {
    mint: async (label: string, origin?: string): Promise<OobHandle> =>
      await rpc('oob', { action: 'mint', label, ...(origin ? { origin } : {}) }, 30_000) as OobHandle,
    check: async (handle: OobHandle): Promise<OobCheck> =>
      ({ ...handle, ...(await rpc('oob', { action: 'check', token: handle.token, exchangeId: handle.exchangeId }, 30_000) as OobCheck) }),
  }

  readonly timing = {
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
      return { controlIds, variantIds, claim: { kind: 'timing', controlIds, variantIds, minPairs: pairs, maxPValue: 0.05 } }
    },
  }

  // -- authoritative host-backed proof helpers (`prove.*`) ----------------

  async proveAccessBoundary(input: AccessBoundaryInput | Record<string, unknown>): Promise<AccessBoundaryProof> {
    if (!input || typeof input !== 'object') {
      throw new Error('prove_access_boundary requires { controlPersona?, probePersona?, route, method?, boundaryClass?, vulnClass?, expectControlDenied? }.')
    }
    const res = await rpc('prove.accessBoundary', input as Record<string, unknown>, 70_000) as AccessBoundaryProof
    if (res.claim) this.claims.push(res.claim)
    return res
  }

  async provePersistedMutation(input: PersistedMutationInput | Record<string, unknown>): Promise<PersistedMutationProof> {
    if (!input || typeof input !== 'object') {
      throw new Error('prove_persisted_mutation requires { readRoute, mutation, fieldPath, expectDelta }.')
    }
    const raw = input as Record<string, unknown>
    const expectFn = typeof raw.expectDelta === 'function' ? raw.expectDelta : (typeof raw.expect_delta === 'function' ? raw.expect_delta : null)
    const payload: Record<string, unknown> = { ...raw }
    if (expectFn) {
      delete payload.expectDelta
      delete payload.expect_delta
      payload.hasCustomExpectFn = true
    }
    const res = await rpc('prove.persistedMutation', payload, 70_000) as PersistedMutationProof
    if (res.claim) this.claims.push(res.claim)
    if (expectFn && !Boolean(expectFn(res.delta.before, res.delta.after, res.delta))) {
      const missingEvidence = [...new Set([...res.missingEvidence, 'expected_delta'])]
      return { ...res, ok: false, confirmed: false, expectationMatched: false, rejectedBy: res.rejectedBy ?? 'impact', missingEvidence }
    }
    return res
  }

  async proveBooleanOrTimingDiff(input: BooleanOrTimingDiffInput | Record<string, unknown>): Promise<DifferentialProof> {
    if (!input || typeof input !== 'object') {
      throw new Error('prove_boolean_or_timing_diff requires { control, variant, mode: "boolean"|"timing", rounds? }.')
    }
    const res = await rpc('prove.differential', input as Record<string, unknown>, 120_000) as DifferentialProof
    if (res.claim) this.claims.push(res.claim)
    return res
  }

  async proveOobCallback(input: OobCallbackInput | Record<string, unknown>): Promise<OobCallbackProof> {
    const raw = input as Record<string, unknown>
    const timeoutMs = Number(raw.timeoutMs ?? raw.timeout_ms ?? 6_000)
    let res: OobCallbackProof
    if (typeof raw.inject === 'function') {
      const injectFn = raw.inject as (canary: OobHandle) => Promise<HttpExchange | void> | HttpExchange | void
      const started = await rpc('prove.oob', {
        phase: 'start',
        ...(raw.token ? { token: raw.token } : {}),
        ...(raw.immediateMs !== undefined || raw.immediate_ms !== undefined ? { immediateMs: Number(raw.immediateMs ?? raw.immediate_ms) } : {}),
        ...(raw.windowMs !== undefined || raw.window_ms !== undefined ? { windowMs: Number(raw.windowMs ?? raw.window_ms) } : {}),
      }, 30_000) as { handle: OobHandle; subscription: Record<string, unknown> }
      let injection: HttpExchange | null = null
      let injectionError: string | null = null
      try {
        const returned = await injectFn(started.handle)
        injection = returned ?? null
      } catch (err) {
        injectionError = err instanceof Error ? err.message : 'OOB injection failed.'
      }
      res = await rpc('prove.oob', {
        phase: 'finish',
        handle: started.handle,
        subscription: started.subscription,
        ...(injection ? { injection } : {}),
        ...(injectionError ? { injectionError } : {}),
        ...(raw.immediateMs !== undefined || raw.immediate_ms !== undefined ? { immediateMs: Number(raw.immediateMs ?? raw.immediate_ms) } : {}),
        timeoutMs,
        ...(raw.message ? { message: raw.message } : {}),
      }, timeoutMs + 15_000) as OobCallbackProof
    } else {
      res = await rpc('prove.oob', raw, timeoutMs + 20_000) as OobCallbackProof
    }
    if (res.claim) this.claims.push(res.claim)
    return res
  }

  async proveRaceBurst(input: RaceBurstInput | Record<string, unknown>): Promise<RaceBurstProof> {
    const raw = (input && typeof input === 'object' ? input : {}) as Record<string, unknown>
    const reqCount = Array.isArray(raw.requests) ? raw.requests.length : 0
    const rpcTimeout = Math.max(40_000, Math.min(80_000, 25_000 + reqCount * 2_000))
    const res = await rpc('prove.race', raw, rpcTimeout) as RaceBurstProof
    if (res.claim && Array.isArray(res.claim.exchangeIds) && res.claim.exchangeIds.length >= 2) this.claims.push(res.claim)
    return res
  }

  async proveInjectionDifferential(input: InjectionDifferentialInput | Record<string, unknown>): Promise<InjectionDifferentialProof> {
    if (!input || typeof input !== 'object') {
      throw new Error('prove_injection_differential requires { control, probe, expectedOutput?, vulnClass? }.')
    }
    const res = await rpc('prove.injection', input as Record<string, unknown>, 70_000) as InjectionDifferentialProof
    if (Array.isArray(res.claims)) this.claims.push(...res.claims)
    else if (res.claim) this.claims.push(res.claim)
    return res
  }

  /** snake_case aliases matching the documented helper contract (host normalizes snake_case keys directly). */
  prove_access_boundary(
    inputOrControl: AccessBoundaryInput | Record<string, unknown> | string,
    probePersona?: string,
    route?: HttpTarget,
    options?: Partial<AccessBoundaryInput>,
  ): Promise<AccessBoundaryProof> {
    if (typeof inputOrControl === 'string') {
      return this.proveAccessBoundary({ ...(options ?? {}), controlPersona: inputOrControl, probePersona: probePersona ?? '', route: route ?? '/' })
    }
    return this.proveAccessBoundary(inputOrControl)
  }
  prove_persisted_mutation(input: PersistedMutationInput | Record<string, unknown>): Promise<PersistedMutationProof> { return this.provePersistedMutation(input) }
  prove_boolean_or_timing_diff(input: BooleanOrTimingDiffInput | Record<string, unknown>): Promise<DifferentialProof> { return this.proveBooleanOrTimingDiff(input) }
  prove_injection_differential(input: InjectionDifferentialInput | Record<string, unknown>): Promise<InjectionDifferentialProof> { return this.proveInjectionDifferential(input) }
  prove_oob_callback(input: OobCallbackInput | Record<string, unknown>): Promise<OobCallbackProof> { return this.proveOobCallback(input) }
  prove_race_burst(input: RaceBurstInput | Record<string, unknown>): Promise<RaceBurstProof> { return this.proveRaceBurst(input) }

  result(input: { title: string; severity?: string; description?: string }): ProofResult {
    if (!input.title || !input.title.trim()) throw new Error('Proof result requires a title.')
    return {
      sdk: 'guardian_verify.ts',
      nonce: this.nonce,
      title: input.title.slice(0, 300),
      severity: (input.severity ?? 'high').slice(0, 32),
      ...(input.description ? { description: input.description.slice(0, 4000) } : {}),
      claims: this.effectiveClaims(),
    }
  }
}

export interface VerificationScript {
  setup?(ctx: VerifyContext): Promise<void> | void
  verify(ctx: VerifyContext): Promise<ProofResult | unknown> | ProofResult | unknown
  cleanup?(ctx: VerifyContext): Promise<void> | void
}
export type VerificationEntrypoint = VerificationScript | ((ctx: VerifyContext) => Promise<ProofResult | unknown> | ProofResult | unknown)

export function defineVerification(script: VerificationScript): VerificationScript { return script }

function writeResult(value: unknown): void {
  const path = process.env.GUARDIAN_PROOF_RESULT_FILE ?? join(dirname(process.env.GUARDIAN_RPC_CONTEXT_FILE ?? '/guardian-rpc/context.json'), 'result.json')
  writeFileSync(path, JSON.stringify(value), { mode: 0o600 })
}

function normalizeProofResult(ctx: VerifyContext, returned: unknown, defaultTitle?: string): ProofResult {
  const fallbackTitle = (defaultTitle && defaultTitle.trim() ? defaultTitle.trim() : 'Verification script proof').slice(0, 300)
  const fallbackClaims = ctx.effectiveClaims()
  if (returned && typeof returned === 'object' && !Array.isArray(returned)) {
    const rec = returned as Record<string, unknown>
    if (Array.isArray(rec.claims)) {
      return {
        sdk: 'guardian_verify.ts',
        nonce: typeof rec.nonce === 'string' && rec.nonce ? rec.nonce : ctx.nonce,
        title: typeof rec.title === 'string' && rec.title.trim() ? rec.title.trim().slice(0, 300) : fallbackTitle,
        severity: typeof rec.severity === 'string' && rec.severity.trim() ? rec.severity.trim().slice(0, 32) : 'high',
        ...(typeof rec.description === 'string' && rec.description ? { description: rec.description.slice(0, 4000) } : {}),
        claims: rec.claims.length > 0 ? (rec.claims as VerifyClaim[]) : fallbackClaims,
      }
    }
  }
  return { sdk: 'guardian_verify.ts', nonce: ctx.nonce, title: fallbackTitle, severity: 'high', claims: fallbackClaims }
}

export async function runVerification(script: VerificationScript, defaultTitle?: string): Promise<void> {
  const ctx = new VerifyContext()
  let result: unknown = null
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
  const normalized = normalizeProofResult(ctx, result, defaultTitle)
  writeResult(normalized)
  process.stdout.write(`guardian_verify: ${normalized.claims.length} transcript-backed claim(s) recorded\n`)
}

export async function runEntrypoint(entry: VerificationEntrypoint, defaultTitle?: string): Promise<void> {
  if (typeof entry === 'function') { await runVerification({ verify: entry }, defaultTitle); return }
  if (entry && typeof entry === 'object' && typeof entry.verify === 'function') { await runVerification(entry, defaultTitle); return }
  const ctx = new VerifyContext()
  const message = 'guardian_verify script must export a default async (ctx) => ... function, an object with verify(ctx), or execute ctx.prove_* directly.'
  writeResult({ sdk: 'guardian_verify.ts', nonce: ctx.nonce, error: message, claims: [] })
  process.stderr.write(`guardian_verify: ${message}\n`)
  process.exitCode = 1
}
