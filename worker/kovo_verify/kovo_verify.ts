/**
 * kovo_verify (TypeScript) — thin, zero-dependency verification SDK for Kovo Hunter Layer 3.
 *
 * Every network/DOM/OOB/crypto/proof action crosses a Unix-domain socket into the Kovo Hunter host
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

export interface ProofResult { sdk: 'kovo_verify.ts'; nonce: string; title: string; severity: string; description?: string; claims: VerifyClaim[] }
export interface RpcContext { nonce: string; runId: string; targetOrigins: string[]; sdkVersion: string }
interface RpcEnvelope { ok: boolean; result?: unknown; error?: string }

export interface HttpExchange {
  exchangeId: string; status: number; method: string; pathAndQuery: string; finalPathAndQuery?: string
  redirectOrigins?: string[]; mediaType: string; headers: Record<string, string>; body: string; text: string
  json: unknown; data: unknown; bodyPreview: string
  bodyBytes: number; bodySha256: string; durationMs: number; personaHandle: string | null
  consumedCapabilityId?: string | null; derivedFromCapabilityIds?: string[]; protocol?: 'h2'
}
export interface CapabilityInjectionSpec { handle: string; target?: 'bearer' | 'header' | 'cookie' | 'url'; headerName?: string; cookieName?: string; queryParam?: string }
export interface SealCapabilityInput {
  exchangeId?: string; exchange?: { exchangeId: string } | null; hopReceiptId?: string; slot: string
  jsonPath?: string; header?: string; cookie?: string; regex?: string; value?: string
  kind?: 'bearer_token' | 'api_token' | 'cookie' | 'signed_url' | 'oidc_assertion' | 'signing_salt' | 'hmac_key' | 'jwt' | 'header_secret' | 'generic_secret'
  ttlMs?: number | null; defaultHeaderName?: string; defaultCookieName?: string; allowedOrigins?: string[]
}
export interface SealedCapabilityResult { handle: string; meta: Record<string, unknown>; exchangeId: string; sealExchangeId: string; scrubbedPreview: string }
export interface HmacSignInput {
  secretHandle: string
  payload: string | Record<string, unknown> | unknown[]
  alg?: 'sha256' | 'sha384' | 'sha512'
  encoding?: 'hex' | 'base64' | 'base64url'
}
export interface HmacSignResult {
  exchangeId: string; signature: string; handle: string; derivedHandle: string
  attestation: { derivedFromCapabilityId: string; alg: string; encoding: string; payloadDigest: string; signatureDigest: string; sourceSecretDigest: string; runId: string; timestampMs: number }
}
export interface JwtSignInput {
  secretHandle: string
  claims: Record<string, unknown>
  alg?: 'HS256' | 'HS384' | 'HS512'
  header?: Record<string, unknown>
  hopReceiptId?: string
  slot?: string
  ttlMs?: number | null
  allowedOrigins?: string[]
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
  path?: string; url?: string; pathAndQuery?: string; endpoint?: string; route?: string; target?: HttpTarget; origin?: string
  matchPredicate?: AsyncMatchPredicate; expectStatus?: number | number[]
  profile?: 'fast_lab' | 'wan'; timeoutMs?: number; intervalMs?: number; maxAttempts?: number
  triggerExchangeId?: string | { exchangeId: string }; tTriggerMs?: number
  correlationId?: string; correlationIds?: string[]; entityId?: string
}
export interface AsyncAwaitResult {
  pollRecordId: string; converged: boolean; status: 'converged' | 'timeout' | 'aborted' | 'max_attempts' | 'monotonic_violation'
  exchangeId: string | null; exchange: HttpExchange | null; evidence: Record<string, unknown>
}
export type HopSurface = 'http' | 'graphql' | 'ws' | 'sse' | 'browser' | 'webhook' | 'async_job' | 'idp' | 'cdn' | 'storage'
export type ReplayMode = 'fresh_clean_replay' | 'one_shot_transcript'
export type OracleFamily = 'dual_tenant_abac' | 'temporal_revocation' | 'economic_conservation' | 'cryptographic_scope_replay' | 'parser_cache_differential' | 'cross_surface_pivot'

export interface ProofReceiptInput {
  vulnClass: string
  target: { origin: string; method?: string; pathAndQuery?: string; param?: string }
  exchangeIds?: string[]; oobEventIds?: string[]; browserTraceIds?: string[]; claimedDelta: string
  oracleEvents?: string[]; requiredRole?: 'viewer' | 'member' | 'admin' | 'owner'; resourceTenant?: string
  expectControlDenied?: boolean; proofPatterns?: string[]; injectedAtMs?: number
  conservedBalance?: { balanceField?: string; capField?: string; unitDebit?: number }
}

export interface HopTargetObject { origin: string; method?: string; pathAndQuery?: string; param?: string }
export type HopTargetInput = string | HopTargetObject

export interface HopReceiptInput {
  hopId: string; surface?: HopSurface; target: HopTargetInput; method?: string
  exchangeIds?: string[]; oobEventIds?: string[]; browserTraceIds?: string[]; claimedDelta: string
  producedCapabilities?: string[]; consumedCapabilities?: string[]
  entityId?: string; canaryToken?: string; proofReceipt?: ProofReceiptInput
}

export type CausalEdgeInput =
  | ({ kind: 'value_binding'; fromHopId: string; toHopId: string; sourceExchangeId?: string; targetExchangeId?: string }
    & ({ capabilityHandle: string; valueDigest?: string } | { capabilityHandle?: string; valueDigest: string }))
  | { kind: 'derived_crypto_binding'; fromHopId: string; toHopId: string; sourceCapabilityId: string; derivedCapabilityId?: string; alg?: string }
  | { kind: 'state_transition_binding'; fromHopId: string; toHopId: string; entityId: string; ablationExchangeIds: string[]; mutationKind?: string }
  | { kind: 'async_pivot_binding'; fromHopId: string; toHopId: string; correlationId: string; channel: 'poll_convergence' | 'oob_relay' | 'browser_trace' | 'async_job'; oobEventId?: string; browserTraceId?: string; pollRecordId?: string }

export interface TerminalImpactInput {
  terminalHopId: string; claimedImpact?: string; summary?: string; terminalExchangeId?: string
  proofReceipt?: ProofReceiptInput; oracleFamily?: OracleFamily; oracleInput?: Record<string, unknown>
  preChainControlExchangeIds?: string[]; postChainReadbackExchangeIds?: string[]; modeAFailureExchangeId?: string
}

export interface CompositeProofReceiptInput {
  chainId: string; terminalVulnClass: string; hops: HopReceiptInput[]; causalEdges?: CausalEdgeInput[]
  terminalImpact: TerminalImpactInput; replayMode?: ReplayMode; benchmarkMode?: boolean
}

export interface CompositeVerificationResult {
  confirmed: boolean; ok?: boolean; verified?: boolean; verificationId?: string; chainId: string; terminalVulnClass: string
  replayMode: ReplayMode; modeBVerified: boolean; hopCount: number
  verifiedEdges: Array<Record<string, unknown>>; reason: string; failedStage?: string; rejectedBy?: string | null
  missingEvidence?: string[]; claim?: CompositeReceiptClaim; terminalVerification?: Record<string, unknown>; evidence?: Record<string, unknown>
}
export interface BrowserExchange { exchangeId: string; status: number; url: string; html: string; title?: string; executedSentinels: string[]; durationMs: number }
export interface OobHandle { exchangeId: string; token: string; url: string; dnsHost: string }
export interface OobCheck extends OobHandle { hit: boolean; checkExchangeId?: string; hits: Array<{ protocol: string; token: string; remoteIp?: string; timestamp?: number }> }

export interface HttpOptions {
  as?: string; persona?: string; session?: string
  /**
   * HTTP session group role (`'setup' | 'control' | 'probe' | 'cleanup'`).
   * Distinct from `ProofRole` values (such as `'control_denied'` or `'mutation'`) and persona handles.
   */
  role?: 'setup' | 'control' | 'probe' | 'cleanup'
  arm?: 'setup' | 'control' | 'probe' | 'cleanup'
  method?: string; headers?: Record<string, string>; body?: string | Record<string, unknown> | unknown[]
  followRedirects?: boolean; timeoutMs?: number; capability?: string | CapabilityInjectionSpec
  capabilityTarget?: 'bearer' | 'header' | 'cookie' | 'url'; capabilityHeaderName?: string; capabilityCookieName?: string
  capabilityQueryParam?: string; entityId?: string; correlationIds?: string[]; evidenceRole?: string
  replayAttempt?: 'mode_a' | 'ablation_control' | 'primary'
}
export type HttpTarget = string | (HttpOptions & { url?: string; path?: string; pathAndQuery?: string; endpoint?: string; route?: string; target?: HttpTarget; origin?: string })

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
}

function readContext(): RpcContext {
  const raw = JSON.parse(readFileSync(process.env.KOVO_RPC_CONTEXT_FILE ?? '/kovo-rpc/context.json', 'utf8')) as Record<string, unknown>
  return {
    nonce: typeof raw.nonce === 'string' ? raw.nonce : '',
    runId: typeof raw.runId === 'string' ? raw.runId : 'unknown-run',
    targetOrigins: Array.isArray(raw.targetOrigins) ? raw.targetOrigins.filter((v): v is string => typeof v === 'string') : [],
    sdkVersion: typeof raw.sdkVersion === 'string' ? raw.sdkVersion : 'kovo_verify/v8',
  }
}

function rpc(op: string, args: Record<string, unknown>, timeoutMs = 60_000): Promise<unknown> {
  const socketPath = process.env.KOVO_RPC_SOCKET ?? '/kovo-rpc/verify.sock'
  const context = readContext()
  const nonce = process.env.KOVO_VERIFY_NONCE ?? context.nonce
  const token = readFileSync(process.env.KOVO_RPC_TOKEN_FILE ?? '/kovo-rpc/token', 'utf8').trim()
  const payload = JSON.stringify({ op, args })
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        'x-kovo-rpc-token': token,
        'x-kovo-verify-nonce': nonce,
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
  for (const k of ['session', 'role', 'arm', 'followRedirects', 'timeoutMs', 'capability', 'capabilityTarget', 'capabilityHeaderName', 'capabilityCookieName', 'capabilityQueryParam', 'entityId', 'correlationIds', 'evidenceRole', 'replayAttempt'] as const) {
    if (r[k] !== undefined) (out as Record<string, unknown>)[k] = r[k]
  }
  return out
}

function parseJsonSafe(body: unknown): unknown {
  if (typeof body !== 'string') return null
  const cleaned = body.replace(/^\uFEFF/, '').trim()
  if (!cleaned) return null
  try { return JSON.parse(cleaned) } catch { return null }
}

export function hydrateExchange(raw: HttpExchange): HttpExchange {
  if (!raw || typeof raw !== 'object') return raw
  const body = typeof raw.body === 'string' ? raw.body : ''
  const parsed = raw.json != null ? raw.json : parseJsonSafe(body)
  return { ...raw, body, text: body, json: parsed, data: parsed, headers: raw.headers && typeof raw.headers === 'object' ? raw.headers : {} }
}

function hydrateFields<T extends Record<string, unknown>>(res: T, keys: readonly string[]): T {
  const out: Record<string, unknown> = { ...res }
  for (const k of keys) {
    const v = out[k]
    if (v && typeof v === 'object' && !Array.isArray(v) && 'exchangeId' in (v as Record<string, unknown>)) out[k] = hydrateExchange(v as HttpExchange)
  }
  return out as T
}

function resolveCapHandle(value: unknown): string {
  if (typeof value === 'string') return value
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const r = value as Record<string, unknown>
    return String(r.handle ?? r.derivedHandle ?? '')
  }
  return ''
}

function normalizePayloadStr(value: unknown): string {
  if (typeof value === 'string') return value
  return value === undefined || value === null ? '' : JSON.stringify(value)
}

function normalizeAsyncPredicate(raw: AsyncMatchPredicate | undefined, expectStatus?: number | number[]): AsyncMatchPredicate | undefined {
  const pred: AsyncMatchPredicate = raw && typeof raw === 'object' && !Array.isArray(raw) ? { ...raw } : {}
  if (expectStatus !== undefined && pred.status === undefined) pred.status = expectStatus
  return Object.keys(pred).length > 0 ? pred : undefined
}

function normalizeHopTarget(rawTarget: unknown, hopMethod: unknown, defaultOrigin: string | undefined): unknown {
  const fallbackMethod = typeof hopMethod === 'string' && hopMethod.trim() ? hopMethod.trim().toUpperCase() : undefined
  if (typeof rawTarget === 'string') {
    const trimmed = rawTarget.trim()
    if (!trimmed) return rawTarget
    const prefixed = /^([A-Za-z]{1,10})\s+(.+)$/.exec(trimmed)
    const method = prefixed ? prefixed[1]!.toUpperCase() : fallbackMethod
    const split = splitTarget(prefixed ? prefixed[2]!.trim() : trimmed, defaultOrigin)
    const origin = split.origin ?? defaultOrigin
    return { ...(origin ? { origin } : {}), ...(method ? { method } : {}), pathAndQuery: split.path }
  }
  if (!rawTarget || typeof rawTarget !== 'object' || Array.isArray(rawTarget)) return rawTarget
  const t = rawTarget as Record<string, unknown>
  const rawOrigin = typeof t.origin === 'string' && t.origin.trim() ? t.origin.trim() : undefined
  const rawMethod = typeof t.method === 'string' && t.method.trim() ? t.method.trim().toUpperCase() : fallbackMethod
  const rawPath = typeof t.pathAndQuery === 'string' && t.pathAndQuery.trim() ? t.pathAndQuery : undefined
  const split = rawPath !== undefined ? splitTarget(rawPath, rawOrigin ?? defaultOrigin) : undefined
  const origin = rawOrigin ?? split?.origin ?? defaultOrigin
  const param = typeof t.param === 'string' && t.param.trim() ? t.param.trim() : undefined
  return { ...(origin ? { origin } : {}), ...(rawMethod ? { method: rawMethod } : {}), ...(split ? { pathAndQuery: split.path } : {}), ...(param ? { param } : {}) }
}

function normalizeCompositeReceipt(receipt: unknown, defaultOrigin: string | undefined): Record<string, unknown> {
  const raw = receipt && typeof receipt === 'object' && !Array.isArray(receipt) && 'receipt' in receipt
    ? (receipt as Record<string, unknown>).receipt
    : receipt
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { receipt: raw }
  const rec = raw as Record<string, unknown>
  if (!Array.isArray(rec.hops)) return { receipt: rec }
  const hops = rec.hops.map(h => {
    if (!h || typeof h !== 'object' || Array.isArray(h)) return h
    const { method, target, ...rest } = h as Record<string, unknown>
    return { ...rest, target: normalizeHopTarget(target, method, defaultOrigin) }
  })
  return { receipt: { ...rec, hops } }
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
    this.nonce = process.env.KOVO_VERIFY_NONCE ?? context.nonce
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
        ...((merged.role ?? merged.arm) ? { sessionGroupRole: merged.role ?? merged.arm } : {}),
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
    return hydrateExchange(await rpc('http', args, timeoutMs) as HttpExchange)
  }

  async http_send(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> {
    const { args, timeoutMs } = this.buildHttpRpcArgs(input, options)
    return hydrateExchange(await rpc('http.send', args, timeoutMs) as HttpExchange)
  }

  request(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> { return this.http_send(input, options) }

  async seal_capability(input: SealCapabilityInput): Promise<SealedCapabilityResult> {
    const exchangeId = input.exchangeId ?? input.exchange?.exchangeId
    if (!exchangeId) throw new Error('seal_capability requires exchangeId or exchange.')
    return await rpc('capability.seal', {
      exchangeId,
      slot: input.slot,
      ...(input.hopReceiptId ? { hopReceiptId: input.hopReceiptId } : {}),
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

  sealCapability(input: SealCapabilityInput): Promise<SealedCapabilityResult> { return this.seal_capability(input) }

  async hmac_sign(
    inputOrSecret: HmacSignInput | Record<string, unknown> | string,
    payloadArg?: string | Record<string, unknown> | unknown[],
    opts?: { alg?: string; encoding?: string } | string,
    encodingArg?: string,
  ): Promise<HmacSignResult> {
    const isPos = typeof inputOrSecret === 'string' || (
      payloadArg !== undefined && inputOrSecret && typeof inputOrSecret === 'object' && !('secretHandle' in inputOrSecret)
    )
    let secretHandle = ''
    let rawPayload: unknown
    let alg: string | undefined
    let encoding: string | undefined
    if (isPos) {
      secretHandle = resolveCapHandle(inputOrSecret)
      rawPayload = payloadArg
      const o = typeof opts === 'string' ? { alg: opts } : (opts ?? {})
      alg = o.alg
      encoding = encodingArg ?? o.encoding
    } else if (inputOrSecret && typeof inputOrSecret === 'object') {
      const r = inputOrSecret as Partial<HmacSignInput>
      secretHandle = resolveCapHandle(r.secretHandle ?? '')
      rawPayload = r.payload
      alg = r.alg
      encoding = r.encoding
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

  hmacSign(
    inputOrSecret: HmacSignInput | Record<string, unknown> | string,
    payloadArg?: string | Record<string, unknown> | unknown[],
    opts?: { alg?: string; encoding?: string } | string,
    encodingArg?: string,
  ): Promise<HmacSignResult> { return this.hmac_sign(inputOrSecret, payloadArg, opts, encodingArg) }

  async jwt_sign(
    inputOrSecret: JwtSignInput | Record<string, unknown> | string,
    claimsArg?: Record<string, unknown>,
    opts?: Omit<JwtSignInput, 'secretHandle' | 'claims'> | string,
  ): Promise<JwtSignResult> {
    const isPos = typeof inputOrSecret === 'string' || (
      claimsArg !== undefined && inputOrSecret && typeof inputOrSecret === 'object' && !('secretHandle' in inputOrSecret)
    )
    const r: Partial<JwtSignInput> = isPos
      ? (typeof opts === 'string' ? { alg: opts as JwtSignInput['alg'] } : { ...(opts ?? {}) })
      : ((inputOrSecret && typeof inputOrSecret === 'object' ? inputOrSecret : {}) as Partial<JwtSignInput>)
    const secretHandle = resolveCapHandle(isPos ? inputOrSecret : (r.secretHandle ?? ''))
    const claims = (isPos ? claimsArg : r.claims) ?? {}
    const res = await rpc('crypto.jwtSign', {
      secretHandle,
      claims,
      ...(r.alg ? { alg: r.alg } : {}),
      ...(r.header ? { header: r.header } : {}),
      ...(r.hopReceiptId ? { hopReceiptId: String(r.hopReceiptId) } : {}),
      ...(r.slot ? { slot: String(r.slot) } : {}),
      ...(r.ttlMs !== undefined ? { ttlMs: r.ttlMs } : {}),
      ...(r.allowedOrigins?.length ? { allowedOrigins: r.allowedOrigins } : {}),
    }, 30_000) as JwtSignResult
    return { ...res, handle: res.handle ?? res.derivedHandle, token: res.token ?? res.derivedHandle }
  }

  jwtSign(
    inputOrSecret: JwtSignInput | Record<string, unknown> | string,
    claimsArg?: Record<string, unknown>,
    opts?: Omit<JwtSignInput, 'secretHandle' | 'claims'> | string,
  ): Promise<JwtSignResult> { return this.jwt_sign(inputOrSecret, claimsArg, opts) }

  async await_async(input: AsyncAwaitInput | Record<string, unknown>): Promise<AsyncAwaitResult> {
    const r = (input && typeof input === 'object' ? input : {}) as AsyncAwaitInput
    const { args: pollRequest } = r.pollRequest !== undefined
      ? this.buildHttpRpcArgs(r.pollRequest, typeof r.pollRequest === 'string' ? extractInlineHttpOptions(r) : {})
      : this.buildHttpRpcArgs(r as HttpTarget)
    const matchPredicate = normalizeAsyncPredicate(r.matchPredicate, r.expectStatus)
    const triggerExchangeId = typeof r.triggerExchangeId === 'string'
      ? r.triggerExchangeId
      : (r.triggerExchangeId && typeof r.triggerExchangeId === 'object' ? r.triggerExchangeId.exchangeId : undefined)
    const timeoutMs = r.timeoutMs !== undefined ? Number(r.timeoutMs) : undefined
    const res = await rpc('async.awaitResult', {
      pollRequest,
      ...(matchPredicate ? { matchPredicate } : {}),
      ...(r.profile ? { profile: r.profile } : {}),
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      ...(r.intervalMs !== undefined ? { intervalMs: Number(r.intervalMs) } : {}),
      ...(r.maxAttempts !== undefined ? { maxAttempts: Number(r.maxAttempts) } : {}),
      ...(triggerExchangeId ? { triggerExchangeId } : {}),
      ...(r.tTriggerMs !== undefined ? { tTriggerMs: Number(r.tTriggerMs) } : {}),
      ...(r.correlationId ? { correlationId: String(r.correlationId) } : {}),
      ...(r.correlationIds?.length ? { correlationIds: r.correlationIds } : {}),
      ...(r.entityId ? { entityId: String(r.entityId) } : {}),
    }, Math.max((timeoutMs ?? 30_000) + 10_000, 15_000)) as AsyncAwaitResult
    return res && res.exchange ? { ...res, exchange: hydrateExchange(res.exchange) } : res
  }

  awaitAsync(input: AsyncAwaitInput | Record<string, unknown>): Promise<AsyncAwaitResult> { return this.await_async(input) }

  async prove_composite(receipt: CompositeProofReceiptInput): Promise<CompositeVerificationResult> {
    const payload = normalizeCompositeReceipt(receipt, this.defaultOrigin)
    const res = await rpc('composite.verify', payload, 30_000) as CompositeVerificationResult
    const confirmed = res.confirmed === true || res.ok === true || res.verified === true
    if (res.claim) {
      if (confirmed) { this._lastFailedCompositeClaim = null; this.claims.push(res.claim) }
      else { this._lastFailedCompositeClaim = res.claim }
    }
    return { ...res, confirmed, ok: confirmed, verified: confirmed }
  }

  proveComposite(receipt: CompositeProofReceiptInput): Promise<CompositeVerificationResult> { return this.prove_composite(receipt) }

  effectiveClaims(): VerifyClaim[] {
    if (this.claims.length > 0) return [...this.claims]
    return this._lastFailedCompositeClaim ? [this._lastFailedCompositeClaim] : []
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

  // -- authoritative host-backed proof helpers (`prove.*`) ----------------

  async prove_access_boundary(input: AccessBoundaryInput | Record<string, unknown>): Promise<AccessBoundaryProof> {
    if (!input || typeof input !== 'object') {
      throw new Error('prove_access_boundary requires { controlPersona?, probePersona?, route, method?, boundaryClass?, vulnClass?, expectControlDenied? }.')
    }
    const res = hydrateFields(await rpc('prove.accessBoundary', input as Record<string, unknown>, 70_000) as Record<string, unknown>, ['control', 'probe']) as unknown as AccessBoundaryProof
    if (res.claim) this.claims.push(res.claim)
    return res
  }

  async prove_persisted_mutation(input: PersistedMutationInput | Record<string, unknown>): Promise<PersistedMutationProof> {
    if (!input || typeof input !== 'object') {
      throw new Error('prove_persisted_mutation requires { readRoute, mutation, fieldPath, expectDelta }.')
    }
    const raw = input as Record<string, unknown>
    const expectFn = typeof raw.expectDelta === 'function' ? raw.expectDelta : null
    const payload: Record<string, unknown> = { ...raw }
    if (expectFn) {
      delete payload.expectDelta
      payload.hasCustomExpectFn = true
    }
    const res = hydrateFields(await rpc('prove.persistedMutation', payload, 70_000) as Record<string, unknown>, ['before', 'mutation', 'after']) as unknown as PersistedMutationProof
    if (res.claim) this.claims.push(res.claim)
    if (expectFn && !Boolean(expectFn(res.delta.before, res.delta.after, res.delta))) {
      const missingEvidence = [...new Set([...res.missingEvidence, 'expected_delta'])]
      return { ...res, ok: false, confirmed: false, expectationMatched: false, rejectedBy: res.rejectedBy ?? 'impact', missingEvidence }
    }
    return res
  }

  async prove_boolean_or_timing_diff(input: BooleanOrTimingDiffInput | Record<string, unknown>): Promise<DifferentialProof> {
    if (!input || typeof input !== 'object') {
      throw new Error('prove_boolean_or_timing_diff requires { control, variant, mode: "boolean"|"timing", rounds? }.')
    }
    const res = await rpc('prove.differential', input as Record<string, unknown>, 120_000) as DifferentialProof
    if (res.claim) this.claims.push(res.claim)
    if (res.exchanges) {
      res.exchanges = { control: res.exchanges.control.map(hydrateExchange), variant: res.exchanges.variant.map(hydrateExchange) }
    }
    return res
  }

  async prove_oob_callback(input: OobCallbackInput | Record<string, unknown>): Promise<OobCallbackProof> {
    const raw = input as Record<string, unknown>
    const timeoutMs = Number(raw.timeoutMs ?? 6_000)
    let res: OobCallbackProof
    if (typeof raw.inject === 'function') {
      const injectFn = raw.inject as (canary: OobHandle) => Promise<HttpExchange | void> | HttpExchange | void
      const started = await rpc('prove.oob', {
        phase: 'start',
        ...(raw.token ? { token: raw.token } : {}),
        ...(raw.immediateMs !== undefined ? { immediateMs: Number(raw.immediateMs) } : {}),
        ...(raw.windowMs !== undefined ? { windowMs: Number(raw.windowMs) } : {}),
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
        ...(raw.immediateMs !== undefined ? { immediateMs: Number(raw.immediateMs) } : {}),
        timeoutMs,
        ...(raw.message ? { message: raw.message } : {}),
      }, timeoutMs + 15_000) as OobCallbackProof
    } else {
      res = await rpc('prove.oob', raw, timeoutMs + 20_000) as OobCallbackProof
    }
    if (res.claim) this.claims.push(res.claim)
    return res
  }

  async prove_race_burst(input: RaceBurstInput | Record<string, unknown>): Promise<RaceBurstProof> {
    const raw = (input && typeof input === 'object' ? input : {}) as Record<string, unknown>
    const reqCount = Array.isArray(raw.requests) ? raw.requests.length : 0
    const rpcTimeout = Math.max(40_000, Math.min(80_000, 25_000 + reqCount * 2_000))
    const res = hydrateFields(await rpc('prove.race', raw, rpcTimeout) as Record<string, unknown>, ['baseline', 'post', 'serial', 'serialPost']) as unknown as RaceBurstProof
    if (res.claim && Array.isArray(res.claim.exchangeIds) && res.claim.exchangeIds.length >= 2) this.claims.push(res.claim)
    return res
  }

  async prove_injection_differential(input: InjectionDifferentialInput | Record<string, unknown>): Promise<InjectionDifferentialProof> {
    if (!input || typeof input !== 'object') {
      throw new Error('prove_injection_differential requires { control, probe, expectedOutput?, vulnClass? }.')
    }
    const res = hydrateFields(await rpc('prove.injection', input as Record<string, unknown>, 70_000) as Record<string, unknown>, ['control', 'probe']) as unknown as InjectionDifferentialProof
    if (Array.isArray(res.claims)) this.claims.push(...res.claims)
    else if (res.claim) this.claims.push(res.claim)
    return res
  }

  /** Thin 1-line camelCase compatibility delegates for existing v6/v8 callers. */
  proveAccessBoundary(input: AccessBoundaryInput | Record<string, unknown>): Promise<AccessBoundaryProof> { return this.prove_access_boundary(input) }
  provePersistedMutation(input: PersistedMutationInput | Record<string, unknown>): Promise<PersistedMutationProof> { return this.prove_persisted_mutation(input) }
  proveBooleanOrTimingDiff(input: BooleanOrTimingDiffInput | Record<string, unknown>): Promise<DifferentialProof> { return this.prove_boolean_or_timing_diff(input) }
  proveInjectionDifferential(input: InjectionDifferentialInput | Record<string, unknown>): Promise<InjectionDifferentialProof> { return this.prove_injection_differential(input) }
  proveOobCallback(input: OobCallbackInput | Record<string, unknown>): Promise<OobCallbackProof> { return this.prove_oob_callback(input) }
  proveRaceBurst(input: RaceBurstInput | Record<string, unknown>): Promise<RaceBurstProof> { return this.prove_race_burst(input) }

  result(input: { title: string; severity?: string; description?: string }): ProofResult {
    if (!input.title || !input.title.trim()) throw new Error('Proof result requires a title.')
    return {
      sdk: 'kovo_verify.ts',
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
  const path = process.env.KOVO_PROOF_RESULT_FILE ?? join(dirname(process.env.KOVO_RPC_CONTEXT_FILE ?? '/kovo-rpc/context.json'), 'result.json')
  writeFileSync(path, JSON.stringify(value), { mode: 0o600 })
}

function normalizeProofResult(ctx: VerifyContext, returned: unknown, defaultTitle?: string): ProofResult {
  const fallbackTitle = (defaultTitle && defaultTitle.trim() ? defaultTitle.trim() : 'Verification script proof').slice(0, 300)
  const fallbackClaims = ctx.effectiveClaims()
  if (returned && typeof returned === 'object' && !Array.isArray(returned)) {
    const rec = returned as Record<string, unknown>
    if (Array.isArray(rec.claims)) {
      return {
        sdk: 'kovo_verify.ts',
        nonce: typeof rec.nonce === 'string' && rec.nonce ? rec.nonce : ctx.nonce,
        title: typeof rec.title === 'string' && rec.title.trim() ? rec.title.trim().slice(0, 300) : fallbackTitle,
        severity: typeof rec.severity === 'string' && rec.severity.trim() ? rec.severity.trim().slice(0, 32) : 'high',
        ...(typeof rec.description === 'string' && rec.description ? { description: rec.description.slice(0, 4000) } : {}),
        claims: rec.claims.length > 0 ? (rec.claims as VerifyClaim[]) : fallbackClaims,
      }
    }
  }
  return { sdk: 'kovo_verify.ts', nonce: ctx.nonce, title: fallbackTitle, severity: 'high', claims: fallbackClaims }
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
    writeResult({ sdk: 'kovo_verify.ts', nonce: ctx.nonce, error: message.slice(0, 2000), claims: [] })
    process.stderr.write(`kovo_verify: ${message}\n`)
    process.exitCode = 1
    return
  }
  const normalized = normalizeProofResult(ctx, result, defaultTitle)
  writeResult(normalized)
  process.stdout.write(`kovo_verify: ${normalized.claims.length} transcript-backed claim(s) recorded\n`)
}

export async function runEntrypoint(entry: VerificationEntrypoint, defaultTitle?: string): Promise<void> {
  if (typeof entry === 'function') { await runVerification({ verify: entry }, defaultTitle); return }
  if (entry && typeof entry === 'object' && typeof entry.verify === 'function') { await runVerification(entry, defaultTitle); return }
  const ctx = new VerifyContext()
  const message = 'kovo_verify script must export a default async (ctx) => ... function, an object with verify(ctx), or execute ctx.prove_* directly.'
  writeResult({ sdk: 'kovo_verify.ts', nonce: ctx.nonce, error: message, claims: [] })
  process.stderr.write(`kovo_verify: ${message}\n`)
  process.exitCode = 1
}
