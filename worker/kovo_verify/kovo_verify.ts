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

export type ClaimKind = 'status' | 'header' | 'body_contains' | 'jsonpath' | 'css' | 'dom_sentinel' | 'oob' | 'timing' | 'composite_receipt' | 'host_evaluated_expression'
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
  requiredRole?: string; resourceTenant?: string; expectControlDenied?: boolean; oracleEvents?: string[]; proofPatterns?: string[]
  actorRoles?: Record<string, string>; actorTenants?: Record<string, string>; requestBody?: unknown
  ambient?: { kind: 'cookie' | 'bearer' | 'header' | 'unknown'; sameSite?: string }; message?: string
}
export interface BoundaryClaim {
  kind: 'boundary'; boundaryClass: 'auth' | 'mfa' | 'access' | 'other'; vulnClass?: string; controlExchangeId: string; probeExchangeId: string
  expectControlDenied?: boolean; controlRequestBody?: unknown; probeRequestBody?: unknown
  actorRoles?: Record<string, string>; actorTenants?: Record<string, string>; message?: string
}
export interface CompositeReceiptClaim {
  kind: 'composite_receipt'; verificationId?: string; chainId: string; terminalVulnClass: string; cwe?: string; route?: string
  exchangeIds: string[]; terminalExchangeId?: string; replayMode?: 'fresh_clean_replay' | 'one_shot_transcript'; hopCount?: number
  compositeReceipt?: Record<string, unknown>; rejectedBy?: string | null; missingEvidence?: string[]; reason?: string; message?: string
}
export interface HostEvaluatedExpressionClaim { kind: 'host_evaluated_expression'; vulnClass?: string; controlIds: string[]; probeIds: string[]; hostMintedChallengeIds: string[]; message?: string }
export type VerifyClaim =
  | StatusClaim | HeaderClaim | BodyClaim | JsonPathClaim | CssClaim | SentinelsClaim
  | OobClaim | TimingClaim | StructuralDiffClaim | RaceClaim | ImpactClaim | BoundaryClaim | CompositeReceiptClaim | HostEvaluatedExpressionClaim
export type ProofRole =
  | 'setup' | 'control' | 'probe' | 'cleanup' | 'control_denied' | 'variant_crossed'
  | 'before_get' | 'mutation' | 'after_get' | 'oob_mint' | 'oob_injection' | 'oob_wait' | 'pending_oob' | 'race'
export interface ProofTranscriptEntry { exchangeId: string; role: ProofRole; personaHandle: string | null; method: string | null; pathAndQuery: string | null; status: number | null; durationMs: number; note?: string }
export interface ProofFeedback { rejectedBy: string | null; missingEvidence: string[]; transcriptSummary: ProofTranscriptEntry[] }
export interface AccessBoundaryProof extends ProofFeedback { ok: boolean; confirmed?: boolean; claim: BoundaryClaim; control: HttpExchange; probe: HttpExchange; transcript: { control_denied: string; variant_crossed: string }; evidence: { controlStatus: number; variantStatus: number; controlDenied: boolean; crossed: boolean } }
export interface PersistedMutationProof extends ProofFeedback { ok: boolean; confirmed?: boolean; claim: ImpactClaim; before: HttpExchange; mutation: HttpExchange; after: HttpExchange; delta: { fieldPath: string; before: unknown; after: unknown; changed: boolean; changedFields: string[]; added: string[]; removed: string[] }; expectationMatched: boolean }
export interface DifferentialProof extends ProofFeedback { ok: boolean; confirmed?: boolean; mode: 'boolean' | 'timing'; controlIds: string[]; variantIds: string[]; claim: StructuralDiffClaim | TimingClaim; stats: Record<string, number | string | boolean | string[]>; exchanges: { control: HttpExchange[]; variant: HttpExchange[] } }
export interface OobCallbackProof extends ProofFeedback { ok: boolean; confirmed?: boolean; claim: OobClaim; token: string; url: string; dnsHost: string; hit: boolean; stage: 'immediate' | 'late' | 'pending' | 'none'; promoted: boolean; subscriptionId: string | null; exchanges: { mint: string; injection: string | null; wait: string | null } }
export interface RaceBurstProof extends ProofFeedback { ok: boolean; confirmed?: boolean; claim: RaceClaim; mode: 'h2-single-packet' | 'http1-fallback'; fallbackReason: string | null; summary: Record<string, unknown>; exchanges: Array<{ exchangeId: string; status: number; durationMs: number; bodySha256: string }>; baseline?: HttpExchange | null; post?: HttpExchange | null; serial?: HttpExchange | null; serialPost?: HttpExchange | null }
export interface InjectionDifferentialProof extends ProofFeedback { ok: boolean; confirmed?: boolean; control: HttpExchange; probe: HttpExchange; claim?: VerifyClaim; claims: VerifyClaim[]; evaluated: boolean }
export interface SignedUrlMintProof extends ProofFeedback { ok: boolean; confirmed?: boolean; variant: 'key_traversal' | 'unauth_write_mint' | null; provider: 'gcs' | 'aws_s3' | 'azure_blob' | 'cloudflare_r2' | null; endpoint: string; control: HttpExchange; probe: HttpExchange; claim?: VerifyClaim; claims: VerifyClaim[]; evidence: Record<string, unknown>; reason: string }

export interface AccessBoundaryInput { controlPersona?: string | null; probePersona?: string | null; route: HttpTarget; probeRoute?: HttpTarget; expectControlDenied?: boolean; method?: string; controlOptions?: HttpOptions; probeOptions?: HttpOptions; controlSession?: string; probeSession?: string; boundaryClass?: 'auth' | 'access'; vulnClass?: string; actorRoles?: Record<string, string>; actorTenants?: Record<string, string>; message?: string }
export interface PersistedMutationInput { readRoute: HttpTarget; mutation: HttpTarget | { target: HttpTarget; method?: string; body?: string; headers?: Record<string, string>; as?: string; session?: string }; fieldPath: string; expectDelta: unknown | ((before: unknown, after: unknown, delta: PersistedMutationProof['delta']) => boolean); readPersona?: string; mutatePersona?: string; readMethod?: string; readSession?: string; impactClass?: 'authorization' | 'bfla' | 'mass_assignment' | 'csrf'; requiredRole?: string; resourceTenant?: string; oracleEvents?: string[]; actorRoles?: Record<string, string>; actorTenants?: Record<string, string>; message?: string }
export interface DifferentialArmInput { target: HttpTarget; options?: HttpOptions }
export interface BooleanOrTimingDiffInput { control: DifferentialArmInput | HttpTarget; variant: DifferentialArmInput | HttpTarget; mode: 'boolean' | 'timing'; rounds?: number; minSimilarityDelta?: number; minDeltaTokens?: number; maxSimilarity?: number; maxPValue?: number; session?: string; message?: string }
export interface OobInjectionInput { target: HttpTarget; method?: string; headers?: Record<string, string>; body?: string; as?: string }
export interface OobCallbackInput { inject: ((canary: { url: string; token: string; dnsHost: string }) => Promise<HttpExchange | void> | HttpExchange | void) | OobInjectionInput; token?: string; timeoutMs?: number; immediateMs?: number; windowMs?: number; message?: string }
export interface RaceRequestInput { target?: HttpTarget; url?: HttpTarget; path?: string; origin?: string; method?: string; headers?: Record<string, string>; body?: string | Record<string, unknown> | unknown[]; as?: string }
export interface RaceBurstInput { requests: Array<RaceRequestInput | HttpTarget>; barrier?: 'auto' | 'h2' | 'http1'; session?: string; minDistinctOutcomes?: number; expectAllSuccess?: boolean; readRoute?: HttpTarget; readMethod?: string; readPersona?: string; serialRequest?: RaceRequestInput | HttpTarget; balanceField?: string; capField?: string; unitDebit?: number; vulnClass?: string; baselineExchangeId?: string; postExchangeId?: string; serialExchangeIds?: string[]; serialPreExchangeId?: string; serialPostExchangeId?: string; message?: string }
export interface InjectionDifferentialInput { control?: DifferentialArmInput | HttpTarget; probe?: DifferentialArmInput | HttpTarget; variant?: DifferentialArmInput | HttpTarget; url?: string; path?: string; pathAndQuery?: string; endpoint?: string; route?: string; method?: string; headers?: Record<string, string>; as?: string; controlBody?: string | Record<string, unknown>; probeBody?: string | Record<string, unknown>; expectedOutput?: string; vulnClass?: string; session?: string; message?: string }
export interface SignedUrlMintInput { control?: DifferentialArmInput | HttpTarget; probe?: DifferentialArmInput | HttpTarget; controlExchangeId?: string; probeExchangeId?: string; variant?: 'auto' | 'key_traversal' | 'unauth_write_mint'; url?: string; path?: string; pathAndQuery?: string; endpoint?: string; route?: string; method?: string; headers?: Record<string, string>; as?: string; controlBody?: string | Record<string, unknown>; probeBody?: string | Record<string, unknown>; session?: string; message?: string }

export interface ProofResult { sdk: 'kovo_verify.ts'; nonce: string; title: string; severity: string; description?: string; claims: VerifyClaim[] }
export interface RpcContext { nonce: string; runId: string; targetOrigins: string[]; sdkVersion: string }
interface RpcEnvelope { ok: boolean; result?: unknown; error?: string }
export interface HttpExchange {
  exchangeId: string; status: number; method: string; pathAndQuery: string; finalPathAndQuery?: string; redirectOrigins?: string[]
  mediaType: string; headers: Record<string, string>; body: string; text: string; json: unknown; data: unknown; bodyPreview: string
  bodyBytes: number; bodySha256: string; durationMs: number; personaHandle: string | null; consumedCapabilityId?: string | null; consumedCapabilities?: string[]; derivedFromCapabilityIds?: string[]; protocol?: 'h2'
}
export interface CapabilityInjectionSpec { handle: string; target?: 'bearer' | 'header' | 'cookie' | 'url'; headerName?: string; cookieName?: string; queryParam?: string }
export interface SealCapabilityInput {
  exchangeId?: string | { exchangeId: string }; exchange?: string | { exchangeId: string } | null; hopReceiptId?: string; hopId?: string; slot: string
  jsonPath?: string; header?: string; cookie?: string; setCookie?: string; locationQuery?: string; queryParam?: string; regex?: string; value?: string
  kind?: 'bearer_token' | 'api_token' | 'cookie' | 'signed_url' | 'oidc_assertion' | 'signing_salt' | 'hmac_key' | 'jwt' | 'header_secret' | 'generic_secret'
  ttlMs?: number | null; defaultHeaderName?: string; defaultCookieName?: string; allowedOrigins?: string[]
}
export interface SealedCapabilityResult { handle: string; meta: Record<string, unknown>; exchangeId: string; sealExchangeId: string; scrubbedPreview: string }
export interface HmacSignInput { secretHandle: string; payload: string | Record<string, unknown> | unknown[]; alg?: 'sha256' | 'sha384' | 'sha512'; encoding?: 'hex' | 'base64' | 'base64url' }
export interface HmacSignResult { exchangeId: string; signature: string; handle: string; derivedHandle: string; attestation: { derivedFromCapabilityId: string; alg: string; encoding: string; payloadDigest: string; signatureDigest: string; sourceSecretDigest: string; runId: string; timestampMs: number } }
export interface JwtSignInput { secretHandle: string; claims: Record<string, unknown>; alg?: 'HS256' | 'HS384' | 'HS512'; header?: Record<string, unknown>; hopReceiptId?: string; slot?: string; ttlMs?: number | null; allowedOrigins?: string[] }
export interface JwtSignResult { exchangeId: string; derivedHandle: string; handle: string; token: string; attestation: { derivedFromCapabilityId: string; derivedHandle: string; alg: string; claimsDigest: string; tokenDigest: string; sourceSecretDigest: string; runId: string; timestampMs: number } }
export interface AsyncMatchPredicate { status?: number | number[]; bodyContains?: string; bodyMatches?: string; jsonPath?: string; equals?: unknown; in?: unknown[]; matches?: string; header?: { name: string; equals?: string; matches?: string } }
export interface AsyncAwaitInput extends HttpOptions {
  pollRequest?: HttpTarget | (HttpOptions & { path?: string; url?: string; origin?: string }); path?: string; url?: string; pathAndQuery?: string; endpoint?: string; route?: string; target?: HttpTarget; origin?: string
  matchPredicate?: AsyncMatchPredicate; expectStatus?: number | number[]; profile?: 'fast_lab' | 'wan'; timeoutMs?: number; intervalMs?: number; maxAttempts?: number
  triggerExchangeId?: string | { exchangeId: string }; tTriggerMs?: number; correlationId?: string; correlationIds?: string[]; entityId?: string
}
export interface AsyncAwaitResult { pollRecordId: string; converged: boolean; status: 'converged' | 'timeout' | 'aborted' | 'max_attempts' | 'monotonic_violation'; exchangeId: string | null; exchange: HttpExchange | null; evidence: Record<string, unknown> }
export type HopSurface = 'http' | 'graphql' | 'ws' | 'sse' | 'browser' | 'webhook' | 'async_job' | 'idp' | 'cdn' | 'storage'
export type ReplayMode = 'fresh_clean_replay' | 'one_shot_transcript'
export type OracleFamily = 'dual_tenant_abac' | 'temporal_revocation' | 'economic_conservation' | 'cryptographic_scope_replay' | 'parser_cache_differential' | 'cross_surface_pivot'
export interface ProofReceiptInput { vulnClass: string; target: { origin: string; method?: string; pathAndQuery?: string; param?: string }; exchangeIds?: string[]; oobEventIds?: string[]; browserTraceIds?: string[]; claimedDelta: string; oracleEvents?: string[]; requiredRole?: 'viewer' | 'member' | 'admin' | 'owner'; resourceTenant?: string; expectControlDenied?: boolean; proofPatterns?: string[]; injectedAtMs?: number; conservedBalance?: { balanceField?: string; capField?: string; unitDebit?: number } }
export interface HopTargetObject { origin: string; method?: string; pathAndQuery?: string; param?: string }
export type HopTargetInput = string | HopTargetObject
export interface HopReceiptInput { hopId: string; surface?: HopSurface; target: HopTargetInput; method?: string; exchangeIds?: string[]; oobEventIds?: string[]; browserTraceIds?: string[]; claimedDelta: string; producedCapabilities?: string[]; consumedCapabilities?: string[]; entityId?: string; canaryToken?: string; proofReceipt?: ProofReceiptInput }
export type CausalEdgeInput =
  | ({ kind: 'value_binding'; fromHopId: string; toHopId: string; sourceExchangeId?: string; targetExchangeId?: string } & ({ capabilityHandle: string; valueDigest?: string } | { capabilityHandle?: string; valueDigest: string }))
  | { kind: 'derived_crypto_binding'; fromHopId: string; toHopId: string; sourceCapabilityId: string; derivedCapabilityId?: string; alg?: string }
  | { kind: 'state_transition_binding'; fromHopId: string; toHopId: string; entityId: string; ablationExchangeIds: string[]; mutationKind?: string }
  | { kind: 'async_pivot_binding'; fromHopId: string; toHopId: string; correlationId: string; channel: 'poll_convergence' | 'oob_relay' | 'browser_trace' | 'async_job'; oobEventId?: string; browserTraceId?: string; pollRecordId?: string }
export interface TerminalImpactInput { terminalHopId: string; claimedImpact?: string; summary?: string; terminalExchangeId?: string; proofReceipt?: ProofReceiptInput; oracleFamily?: OracleFamily; oracleInput?: Record<string, unknown>; preChainControlExchangeIds?: string[]; postChainReadbackExchangeIds?: string[]; modeAFailureExchangeId?: string }
export interface CompositeProofReceiptInput { chainId: string; terminalVulnClass: string; hops: HopReceiptInput[]; causalEdges?: CausalEdgeInput[]; terminalImpact: TerminalImpactInput; replayMode?: ReplayMode; benchmarkMode?: boolean }
export interface CompositeVerificationResult { confirmed: boolean; ok?: boolean; verified?: boolean; verificationId?: string; chainId: string; terminalVulnClass: string; replayMode: ReplayMode; modeBVerified: boolean; hopCount: number; verifiedEdges: Array<Record<string, unknown>>; reason: string; failedStage?: string; rejectedBy?: string | null; missingEvidence?: string[]; claim?: CompositeReceiptClaim; terminalVerification?: Record<string, unknown>; evidence?: Record<string, unknown> }
export interface BrowserExchange { exchangeId: string; status: number; url: string; html: string; title?: string; executedSentinels: string[]; durationMs: number }
export interface OobHandle { exchangeId: string; token: string; url: string; dnsHost: string }
export interface OobCheck extends OobHandle { hit: boolean; checkExchangeId?: string; hits: Array<{ protocol: string; token: string; remoteIp?: string; timestamp?: number }> }

export interface HttpOptions {
  as?: string; persona?: string; session?: string
  /** HTTP session group role (`'setup' | 'control' | 'probe' | 'cleanup'`). Distinct from `ProofRole` and persona handles. */
  role?: 'setup' | 'control' | 'probe' | 'cleanup'; arm?: 'setup' | 'control' | 'probe' | 'cleanup'
  method?: string; headers?: Record<string, string>; body?: string | Record<string, unknown> | unknown[]
  followRedirects?: boolean; timeoutMs?: number; capability?: string | CapabilityInjectionSpec
  capabilityTarget?: 'bearer' | 'header' | 'cookie' | 'url'; capabilityHeaderName?: string; capabilityCookieName?: string
  capabilityQueryParam?: string; authMutation?: Record<string, unknown>; entityId?: string; correlationIds?: string[]; evidenceRole?: string
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

export type ExchangeRef = string | { exchangeId: string }
export interface ChainBuilderOptions { chainId: string; terminalVulnClass: string; replayMode?: ReplayMode; benchmarkMode?: boolean }
export interface ChainHopOptions { surface?: HopSurface; target?: HopTargetInput; method?: string; claimedDelta?: string; entityId?: string; canaryToken?: string; exchangeIds?: string[]; oobEventIds?: string[]; browserTraceIds?: string[]; producedCapabilities?: string[]; consumedCapabilities?: string[]; proofReceipt?: ProofReceiptInput }
export interface StateTransitionEdgeInput { fromHopId: string; toHopId: string; entityId: string; ablationExchange?: ExchangeRef | ExchangeRef[]; ablationExchangeIds?: string[]; mutationKind?: string }
export interface ChainProveOptions { terminalHopId?: string; claimedImpact?: string; summary?: string; terminalExchange?: ExchangeRef; terminalExchangeId?: string; control?: ExchangeRef | ExchangeRef[]; preChainControlExchangeIds?: string[]; readback?: ExchangeRef | ExchangeRef[]; postChainReadbackExchangeIds?: string[]; modeAFailureExchange?: ExchangeRef; modeAFailureExchangeId?: string; oracleFamily?: OracleFamily; oracleInput?: Record<string, unknown>; proofReceipt?: ProofReceiptInput; replayMode?: ReplayMode; benchmarkMode?: boolean }

interface HopRecorder {
  hopId: string; target?: HopTargetObject; exchangeIds: string[]; oobEventIds: string[]; browserTraceIds: string[]
  producedCapabilities: string[]; consumedCapabilities: string[]; entityId?: string; correlationIds: string[]
  capConsumeExchange: Map<string, string>
  cryptoConsumptions: Array<{ sourceCapabilityId: string; derivedCapabilityId?: string; alg?: string }>
  asyncPolls: Array<{ pollRecordId: string; correlationId?: string; triggerExchangeId?: string }>
  onProduce(cap: string, exchangeId?: string): void; onExchange(exchangeId: string): void; onCorrelation(correlationId: string): void
}
interface RpcTransport { socketPath: string; token: string; nonce: string }

function readContext(): RpcContext {
  const raw = JSON.parse(readFileSync(process.env.KOVO_RPC_CONTEXT_FILE ?? '/kovo-rpc/context.json', 'utf8')) as Record<string, unknown>
  return { nonce: typeof raw.nonce === 'string' ? raw.nonce : '', runId: typeof raw.runId === 'string' ? raw.runId : 'unknown-run', targetOrigins: Array.isArray(raw.targetOrigins) ? raw.targetOrigins.filter((v): v is string => typeof v === 'string') : [], sdkVersion: typeof raw.sdkVersion === 'string' ? raw.sdkVersion : 'kovo_verify/v8' }
}

function sendRpc(transport: RpcTransport, op: string, args: Record<string, unknown>, timeoutMs = 60_000): Promise<unknown> {
  const payload = JSON.stringify({ op, args })
  return new Promise((resolve, reject) => {
    const req = httpRequest({ socketPath: transport.socketPath, path: '/rpc', method: 'POST', timeout: timeoutMs, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), 'x-kovo-rpc-token': transport.token, 'x-kovo-verify-nonce': transport.nonce } }, res => {
      const chunks: Buffer[] = []; let size = 0
      res.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 8 * 1024 * 1024) { res.destroy(); reject(new Error('Verification RPC response exceeded the SDK limit.')); return } chunks.push(chunk) })
      res.on('end', () => {
        let body: RpcEnvelope; try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcEnvelope } catch { reject(new Error('Verification RPC returned malformed JSON.')); return }
        if (!body.ok) reject(new Error(body.error ?? 'Verification RPC call failed.')); else resolve(body.result)
      })
    })
    req.on('timeout', () => { req.destroy(new Error('Verification RPC call timed out.')) }); req.on('error', reject); req.end(payload)
  })
}

const pushUnique = (list: string[], value: string | undefined | null): void => {
  const trimmed = typeof value === 'string' ? value.trim() : ''
  if (trimmed && !list.includes(trimmed)) list.push(trimmed)
}

function extractExchangeIds(ref: ExchangeRef | ExchangeRef[] | undefined): string[] {
  const out: string[] = []
  for (const item of !ref ? [] : Array.isArray(ref) ? ref : [ref]) pushUnique(out, typeof item === 'string' ? item : item?.exchangeId)
  return out
}

function pickDefined(src: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const k of keys) if (src[k] !== undefined && src[k] !== '') out[k] = src[k]
  return out
}

function normalizeBodyAndHeaders(rawBody: unknown, rawHeaders?: Record<string, string>): { body?: string; headers?: Record<string, string> } {
  const headers = rawHeaders ? { ...rawHeaders } : undefined
  if (rawBody === undefined || rawBody === null) return headers ? { headers } : {}
  if (typeof rawBody === 'string') return { body: rawBody, ...(headers ? { headers } : {}) }
  const hasCt = Object.keys(headers ?? {}).some(k => k.toLowerCase() === 'content-type')
  return { body: JSON.stringify(rawBody), headers: hasCt ? headers : { 'content-type': 'application/json', ...(headers ?? {}) } }
}

function splitTarget(input: HttpTarget, defaultOrigin: string | undefined): { origin?: string; path: string } {
  if (typeof input === 'string') {
    const trimmed = input.trim()
    if (!trimmed) throw new Error('HTTP target path/URL must be non-empty.')
    if (/^https?:\/\//i.test(trimmed)) { const u = new URL(trimmed); return { origin: u.origin, path: u.pathname + u.search } }
    return { ...(defaultOrigin ? { origin: defaultOrigin } : {}), path: trimmed.startsWith('/') ? trimmed : `/${trimmed}` }
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('HTTP target requires a path/URL string or an object with { url | path | pathAndQuery | endpoint }.')
  const raw = input.url ?? input.path ?? input.pathAndQuery ?? input.endpoint ?? input.route
  if (typeof raw === 'string' && raw.trim()) {
    const res = splitTarget(raw, input.origin ?? defaultOrigin)
    return { ...(input.origin ? { origin: input.origin } : res.origin ? { origin: res.origin } : {}), path: res.path }
  }
  if (input.target !== undefined) {
    const nested = splitTarget(input.target, input.origin ?? defaultOrigin)
    return { ...(input.origin ? { origin: input.origin } : nested.origin ? { origin: nested.origin } : {}), path: nested.path }
  }
  throw new Error('HTTP target requires a path/URL string or an object with { url | path | pathAndQuery | endpoint }.')
}

const HTTP_OPT_KEYS = ['session', 'role', 'arm', 'followRedirects', 'timeoutMs', 'capability', 'capabilityTarget', 'capabilityHeaderName', 'capabilityCookieName', 'capabilityQueryParam', 'authMutation', 'entityId', 'correlationIds', 'evidenceRole', 'replayAttempt'] as const
function extractInlineHttpOptions(input: unknown): HttpOptions {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {}
  const r = input as Record<string, unknown>, out: HttpOptions = pickDefined(r, HTTP_OPT_KEYS) as HttpOptions
  if (typeof r.method === 'string' && r.method.trim()) out.method = r.method.trim().toUpperCase()
  if (r.headers && typeof r.headers === 'object' && !Array.isArray(r.headers)) out.headers = r.headers as Record<string, string>
  if (r.body !== undefined) out.body = r.body as HttpOptions['body']
  const persona = typeof r.as === 'string' ? r.as : typeof r.persona === 'string' ? r.persona : undefined
  if (persona) out.as = persona
  return out
}

function parseJsonSafe(body: unknown): unknown {
  if (typeof body !== 'string') return null
  const cleaned = body.replace(/^\uFEFF/, '').trim(); if (!cleaned) return null
  try { return JSON.parse(cleaned) } catch { return null }
}
export function hydrateExchange(raw: HttpExchange): HttpExchange {
  if (!raw || typeof raw !== 'object') return raw
  const body = typeof raw.body === 'string' ? raw.body : '', parsed = raw.json != null ? raw.json : parseJsonSafe(body)
  return { ...raw, body, text: body, json: parsed, data: parsed, headers: raw.headers && typeof raw.headers === 'object' ? raw.headers : {} }
}
function hydrateFields<T extends Record<string, unknown>>(res: T, keys: readonly string[]): T {
  const out: Record<string, unknown> = { ...res }
  for (const k of keys) { const v = out[k]; if (v && typeof v === 'object' && !Array.isArray(v) && 'exchangeId' in (v as Record<string, unknown>)) out[k] = hydrateExchange(v as HttpExchange) }
  return out as T
}

const resolveCapHandle = (value: unknown): string =>
  typeof value === 'string' ? value : value && typeof value === 'object' && !Array.isArray(value) ? String((value as Record<string, unknown>).handle ?? (value as Record<string, unknown>).derivedHandle ?? '') : ''
const normalizePayloadStr = (value: unknown): string =>
  typeof value === 'string' ? value : value === undefined || value === null ? '' : JSON.stringify(value)

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
  const rawPath = typeof t.pathAndQuery === 'string' && t.pathAndQuery.trim() ? t.pathAndQuery : typeof t.path === 'string' && t.path.trim() ? t.path : typeof t.url === 'string' && t.url.trim() ? t.url : undefined
  const split = rawPath !== undefined ? splitTarget(rawPath, rawOrigin ?? defaultOrigin) : undefined
  const origin = rawOrigin ?? split?.origin ?? defaultOrigin
  const param = typeof t.param === 'string' && t.param.trim() ? t.param.trim() : undefined
  return { ...(origin ? { origin } : {}), ...(rawMethod ? { method: rawMethod } : {}), ...(split ? { pathAndQuery: split.path } : {}), ...(param ? { param } : {}) }
}

const normExRef = (v: unknown): unknown => (v && typeof v === 'object' && !Array.isArray(v) && typeof (v as Record<string, unknown>).exchangeId === 'string') ? (v as Record<string, unknown>).exchangeId : v
const normExList = (v: unknown): unknown => Array.isArray(v) ? v.map(normExRef) : v
const normCapRef = (v: unknown): unknown => (v && typeof v === 'object' && !Array.isArray(v)) ? (resolveCapHandle(v) || v) : v
const normCapList = (v: unknown): unknown => Array.isArray(v) ? v.map(normCapRef) : v
const mapFields = (obj: Record<string, unknown>, map: Record<string, (v: unknown) => unknown>): Record<string, unknown> => {
  const out: Record<string, unknown> = { ...obj }
  for (const [k, fn] of Object.entries(map)) if (out[k] !== undefined) out[k] = fn(out[k])
  return out
}

function normalizeCompositeReceipt(receipt: unknown, defaultOrigin: string | undefined): Record<string, unknown> {
  const raw = receipt && typeof receipt === 'object' && !Array.isArray(receipt) && 'receipt' in receipt ? (receipt as Record<string, unknown>).receipt : receipt
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { receipt: raw }
  const rec = raw as Record<string, unknown>
  if (!Array.isArray(rec.hops)) return { receipt: rec }
  const hops = rec.hops.map(h => {
    if (!h || typeof h !== 'object' || Array.isArray(h)) return h
    const { method, target, ...rest } = h as Record<string, unknown>
    return mapFields({ ...rest, target: normalizeHopTarget(target, method, defaultOrigin) }, { exchangeIds: normExList, producedCapabilities: normCapList, consumedCapabilities: normCapList })
  })
  const rawEdges = Array.isArray(rec.causalEdges) ? rec.causalEdges : Array.isArray(rec.edges) ? rec.edges : undefined
  const causalEdges = rawEdges?.map(ed => {
    if (!ed || typeof ed !== 'object' || Array.isArray(ed)) return ed
    const e = ed as Record<string, unknown>
    const ab = e.ablationExchangeIds !== undefined ? normExList(e.ablationExchangeIds) : e.ablationExchange !== undefined ? extractExchangeIds(e.ablationExchange as ExchangeRef | ExchangeRef[]) : undefined
    return mapFields({ ...e, ...(ab !== undefined ? { ablationExchangeIds: ab } : {}) }, { capabilityHandle: normCapRef, sourceCapabilityId: normCapRef, derivedCapabilityId: normCapRef, sourceExchangeId: normExRef, targetExchangeId: normExRef })
  })
  const ti = rec.terminalImpact && typeof rec.terminalImpact === 'object' && !Array.isArray(rec.terminalImpact)
    ? mapFields(rec.terminalImpact as Record<string, unknown>, { terminalExchangeId: normExRef, modeAFailureExchangeId: normExRef, preChainControlExchangeIds: normExList, postChainReadbackExchangeIds: normExList })
    : rec.terminalImpact
  return { receipt: { ...rec, hops, ...(causalEdges !== undefined ? { causalEdges } : {}), ...(ti !== undefined ? { terminalImpact: ti } : {}) } }
}

interface RecordedHop {
  receipt: HopReceiptInput
  capConsumeExchange: Map<string, string>
  cryptoConsumptions: Array<{ sourceCapabilityId: string; derivedCapabilityId?: string; alg?: string }>
  asyncPolls: Array<{ pollRecordId: string; correlationId?: string; triggerExchangeId?: string }>
}

/**
 * Stateful multi-hop DAG builder bound to a `VerifyContext`. Auto-tracks hop exchanges, targets,
 * capabilities, crypto attestations, and async polls inside `chain.hop(...)`, wiring `value_binding`,
 * `derived_crypto_binding`, and `async_pivot_binding`. `state_transition_binding` ALWAYS requires
 * explicit `entityId` + `ablationExchange` (never auto-guessed).
 */
export class ChainBuilder {
  private readonly ctx: VerifyContext
  readonly chainId: string; readonly terminalVulnClass: string
  private readonly replayMode: ReplayMode; private readonly benchmarkMode?: boolean
  private readonly hops: RecordedHop[] = []
  private readonly capProducer = new Map<string, { hopId: string; exchangeId?: string }>()
  private readonly exchangeToHop = new Map<string, string>()
  private readonly correlationToHop = new Map<string, string>()
  private readonly explicitEdges: CausalEdgeInput[] = []
  private readonly controlIds: string[] = []; private readonly readbackIds: string[] = []

  constructor(ctx: VerifyContext, opts: ChainBuilderOptions) {
    if (!opts.chainId?.trim()) throw new Error('ChainBuilder requires a non-empty chainId.')
    if (!opts.terminalVulnClass?.trim()) throw new Error('ChainBuilder requires a non-empty terminalVulnClass.')
    this.ctx = ctx; this.chainId = opts.chainId.trim(); this.terminalVulnClass = opts.terminalVulnClass.trim()
    this.replayMode = opts.replayMode ?? 'fresh_clean_replay'; this.benchmarkMode = opts.benchmarkMode
  }

  control(ref: ExchangeRef | ExchangeRef[]): this { for (const id of extractExchangeIds(ref)) pushUnique(this.controlIds, id); return this }
  readback(ref: ExchangeRef | ExchangeRef[]): this { for (const id of extractExchangeIds(ref)) pushUnique(this.readbackIds, id); return this }

  stateTransition(input: StateTransitionEdgeInput): this {
    const fromHopId = input.fromHopId?.trim(), toHopId = input.toHopId?.trim(), entityId = input.entityId?.trim()
    if (!fromHopId || !toHopId) throw new Error('state_transition_binding requires non-empty fromHopId and toHopId.')
    if (!entityId) throw new Error('state_transition_binding requires an explicit non-empty entityId (never auto-guessed).')
    const ablationIds: string[] = []
    for (const id of [...extractExchangeIds(input.ablationExchange), ...(input.ablationExchangeIds ?? [])]) pushUnique(ablationIds, id)
    if (ablationIds.length === 0) throw new Error('state_transition_binding requires explicit ablationExchange / ablationExchangeIds (never auto-guessed).')
    this.explicitEdges.push({ kind: 'state_transition_binding', fromHopId, toHopId, entityId, ablationExchangeIds: ablationIds, ...(input.mutationKind ? { mutationKind: input.mutationKind } : {}) })
    return this
  }

  edge(edge: CausalEdgeInput): this {
    if (edge.kind === 'state_transition_binding') {
      if (!edge.entityId?.trim()) throw new Error('state_transition_binding requires an explicit non-empty entityId (never auto-guessed).')
      if (!Array.isArray(edge.ablationExchangeIds) || !edge.ablationExchangeIds.some(id => typeof id === 'string' && id.trim())) {
        throw new Error('state_transition_binding requires explicit ablationExchangeIds (never auto-guessed).')
      }
    }
    this.explicitEdges.push(edge)
    return this
  }

  recordHop(hop: HopReceiptInput): this {
    const target = normalizeHopTarget(hop.target, hop.method, this.ctx.targetOrigin || undefined) as HopTargetObject
    const receipt: HopReceiptInput = { ...hop, surface: hop.surface ?? 'http', target }
    for (const exId of receipt.exchangeIds ?? []) this.exchangeToHop.set(exId, receipt.hopId)
    for (const cap of receipt.producedCapabilities ?? []) if (!this.capProducer.has(cap)) this.capProducer.set(cap, { hopId: receipt.hopId, exchangeId: receipt.exchangeIds?.[0] })
    this.hops.push({ receipt, capConsumeExchange: new Map(), cryptoConsumptions: [], asyncPolls: [] })
    return this
  }

  async hop<T>(hopId: string, fn: () => Promise<T> | T): Promise<T>
  async hop<T>(hopId: string, meta: ChainHopOptions, fn: () => Promise<T> | T): Promise<T>
  async hop<T>(hopId: string, metaOrFn: ChainHopOptions | (() => Promise<T> | T), maybeFn?: () => Promise<T> | T): Promise<T> {
    const trimmedId = hopId.trim()
    if (!trimmedId) throw new Error('chain.hop requires a non-empty hopId.')
    const meta: ChainHopOptions = typeof metaOrFn === 'function' ? {} : (metaOrFn ?? {})
    const fn = typeof metaOrFn === 'function' ? metaOrFn : maybeFn
    if (typeof fn !== 'function') throw new Error(`chain.hop("${trimmedId}") requires a callback function.`)
    const rec: HopRecorder = {
      hopId: trimmedId, exchangeIds: [...(meta.exchangeIds ?? [])], oobEventIds: [...(meta.oobEventIds ?? [])],
      browserTraceIds: [...(meta.browserTraceIds ?? [])], producedCapabilities: [...(meta.producedCapabilities ?? [])],
      consumedCapabilities: [...(meta.consumedCapabilities ?? [])], entityId: meta.entityId, correlationIds: [],
      capConsumeExchange: new Map(), cryptoConsumptions: [], asyncPolls: [],
      onProduce: (cap, exId) => { pushUnique(rec.producedCapabilities, cap); if (!this.capProducer.has(cap)) this.capProducer.set(cap, { hopId: trimmedId, ...(exId ? { exchangeId: exId } : {}) }) },
      onExchange: exId => { pushUnique(rec.exchangeIds, exId); this.exchangeToHop.set(exId, trimmedId) },
      onCorrelation: cid => { pushUnique(rec.correlationIds, cid); if (!this.correlationToHop.has(cid)) this.correlationToHop.set(cid, trimmedId) },
    }
    for (const exId of rec.exchangeIds) this.exchangeToHop.set(exId, trimmedId)
    for (const cap of rec.producedCapabilities) if (!this.capProducer.has(cap)) this.capProducer.set(cap, { hopId: trimmedId, exchangeId: rec.exchangeIds[0] })

    this.ctx._pushHopRecorder(rec)
    let out: T
    try { out = await fn() } finally { this.ctx._popHopRecorder(rec) }

    const resolvedTarget = meta.target !== undefined
      ? normalizeHopTarget(meta.target, meta.method, this.ctx.targetOrigin || undefined) as HopTargetObject
      : (rec.target ?? { origin: this.ctx.targetOrigin, method: meta.method ?? 'GET', pathAndQuery: '/' })
    const receipt: HopReceiptInput = {
      hopId: trimmedId, surface: meta.surface ?? 'http', target: resolvedTarget, exchangeIds: rec.exchangeIds,
      ...(rec.oobEventIds.length ? { oobEventIds: rec.oobEventIds } : {}), ...(rec.browserTraceIds.length ? { browserTraceIds: rec.browserTraceIds } : {}),
      claimedDelta: meta.claimedDelta?.trim() || `Hop ${trimmedId} executed.`,
      ...(rec.producedCapabilities.length ? { producedCapabilities: rec.producedCapabilities } : {}),
      ...(rec.consumedCapabilities.length ? { consumedCapabilities: rec.consumedCapabilities } : {}),
      ...(rec.entityId ? { entityId: rec.entityId } : {}), ...(meta.canaryToken ? { canaryToken: meta.canaryToken } : {}), ...(meta.proofReceipt ? { proofReceipt: meta.proofReceipt } : {}),
    }
    this.hops.push({ receipt, capConsumeExchange: rec.capConsumeExchange, cryptoConsumptions: rec.cryptoConsumptions, asyncPolls: rec.asyncPolls })
    return out
  }

  build(opts: ChainProveOptions = {}): CompositeProofReceiptInput {
    if (this.hops.length === 0) throw new Error(`ChainBuilder "${this.chainId}" has no recorded hops.`)
    const edges: CausalEdgeInput[] = [], seenEdges = new Set<string>()
    const addEdge = (edge: CausalEdgeInput): void => {
      if (edge.fromHopId === edge.toHopId) return
      const key = `${edge.fromHopId}->${edge.toHopId}:${edge.kind}`
      if (!seenEdges.has(key)) { seenEdges.add(key); edges.push(edge) }
    }
    for (const explicit of this.explicitEdges) addEdge(explicit)
    const resolveProducer = (cap: string): { hopId: string; exchangeId?: string } | undefined => {
      const direct = this.capProducer.get(cap); if (direct) return direct
      const srcEx = this.ctx._capOriginOf(cap), hopId = srcEx ? this.exchangeToHop.get(srcEx) : undefined; if (!hopId) return undefined
      const prodHop = this.hops.find(h => h.receipt.hopId === hopId)?.receipt
      if (prodHop) { prodHop.producedCapabilities ??= []; pushUnique(prodHop.producedCapabilities, cap) }
      const resolved = { hopId, ...(srcEx ? { exchangeId: srcEx } : {}) }; this.capProducer.set(cap, resolved); return resolved
    }
    for (const hop of this.hops) {
      const toHopId = hop.receipt.hopId, cryptoBound = new Set<string>()
      for (const c of hop.cryptoConsumptions) {
        const prod = resolveProducer(c.sourceCapabilityId)
        if (!prod || prod.hopId === toHopId) continue
        cryptoBound.add(c.sourceCapabilityId)
        addEdge({ kind: 'derived_crypto_binding', fromHopId: prod.hopId, toHopId, sourceCapabilityId: c.sourceCapabilityId, ...(c.derivedCapabilityId && /^cap:/.test(c.derivedCapabilityId) ? { derivedCapabilityId: c.derivedCapabilityId } : {}), ...(c.alg ? { alg: c.alg } : {}) })
      }
      for (const cap of hop.receipt.consumedCapabilities ?? []) {
        if (cryptoBound.has(cap) && !hop.capConsumeExchange.has(cap)) continue
        const prod = resolveProducer(cap)
        if (!prod || prod.hopId === toHopId) continue
        const targetExchangeId = hop.capConsumeExchange.get(cap)
        addEdge({ kind: 'value_binding', fromHopId: prod.hopId, toHopId, capabilityHandle: cap, ...(prod.exchangeId ? { sourceExchangeId: prod.exchangeId } : {}), ...(targetExchangeId ? { targetExchangeId } : {}) })
      }
      for (const poll of hop.asyncPolls) {
        const fromHopId = (poll.triggerExchangeId ? this.exchangeToHop.get(poll.triggerExchangeId) : undefined) ?? (poll.correlationId ? this.correlationToHop.get(poll.correlationId) : undefined)
        if (fromHopId && fromHopId !== toHopId && poll.correlationId) {
          addEdge({ kind: 'async_pivot_binding', fromHopId, toHopId, correlationId: poll.correlationId, channel: 'poll_convergence', ...(poll.pollRecordId ? { pollRecordId: poll.pollRecordId } : {}) })
        }
      }
    }
    const lastHop = this.hops[this.hops.length - 1]!.receipt
    const preControl: string[] = [], postReadback: string[] = []
    for (const id of [...this.controlIds, ...extractExchangeIds(opts.control), ...(opts.preChainControlExchangeIds ?? [])]) pushUnique(preControl, id)
    for (const id of [...this.readbackIds, ...extractExchangeIds(opts.readback), ...(opts.postChainReadbackExchangeIds ?? [])]) pushUnique(postReadback, id)
    const terminalExchangeId = opts.terminalExchangeId ?? extractExchangeIds(opts.terminalExchange)[0]
    const modeAFailureExchangeId = opts.modeAFailureExchangeId ?? extractExchangeIds(opts.modeAFailureExchange)[0]
    return {
      chainId: this.chainId, terminalVulnClass: this.terminalVulnClass, replayMode: opts.replayMode ?? this.replayMode,
      ...(opts.benchmarkMode ?? this.benchmarkMode !== undefined ? { benchmarkMode: opts.benchmarkMode ?? this.benchmarkMode } : {}),
      hops: this.hops.map(h => h.receipt), causalEdges: edges,
      terminalImpact: {
        terminalHopId: opts.terminalHopId ?? lastHop.hopId, claimedImpact: opts.claimedImpact ?? opts.summary ?? lastHop.claimedDelta,
        ...(terminalExchangeId ? { terminalExchangeId } : {}), ...(preControl.length ? { preChainControlExchangeIds: preControl } : {}),
        ...(postReadback.length ? { postChainReadbackExchangeIds: postReadback } : {}), ...(modeAFailureExchangeId ? { modeAFailureExchangeId } : {}),
        ...(opts.oracleFamily ? { oracleFamily: opts.oracleFamily } : {}), ...(opts.oracleInput ? { oracleInput: opts.oracleInput } : {}), ...(opts.proofReceipt ? { proofReceipt: opts.proofReceipt } : {}),
      },
    }
  }

  prove(opts: ChainProveOptions = {}): Promise<CompositeVerificationResult> { return this.ctx.prove_composite(this.build(opts)) }
}

export class VerifyContext {
  readonly nonce: string; readonly runId: string; readonly targetOrigins: string[]; readonly targetOrigin: string; readonly sdkVersion: string
  readonly claims: VerifyClaim[] = []; readonly expect: Expectations; readonly assert: Expectations
  private readonly defaultOrigin: string | undefined; private readonly transport: RpcTransport
  private _lastRpcOp: string | null = null; private _lastFailedClaims: VerifyClaim[] = []
  private readonly _hopStack: HopRecorder[] = []; private readonly _capOrigins = new Map<string, string>()

  constructor() {
    const context = readContext()
    this.nonce = process.env.KOVO_VERIFY_NONCE ?? context.nonce; this.runId = context.runId; this.sdkVersion = context.sdkVersion
    this.targetOrigins = context.targetOrigins; this.targetOrigin = this.targetOrigins[0] ?? ''; this.defaultOrigin = this.targetOrigins[0]
    this.transport = { socketPath: process.env.KOVO_RPC_SOCKET ?? '/kovo-rpc/verify.sock', token: readFileSync(process.env.KOVO_RPC_TOKEN_FILE ?? '/kovo-rpc/token', 'utf8').trim(), nonce: this.nonce }
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
    this.expect = expectations; this.assert = expectations
  }

  get lastRpcOp(): string | null { return this._lastRpcOp }
  /** @internal */ _pushHopRecorder(rec: HopRecorder): void { this._hopStack.push(rec) }
  /** @internal */ _popHopRecorder(rec: HopRecorder): void { const i = this._hopStack.lastIndexOf(rec); if (i >= 0) this._hopStack.splice(i, 1) }
  /** @internal */ _capOriginOf(cap: string): string | undefined { return this._capOrigins.get(cap) }
  private activeHop(): HopRecorder | undefined { return this._hopStack[this._hopStack.length - 1] }
  private recordExCaps(hop: HopRecorder, ex: HttpExchange, explicitCap?: unknown): void {
    for (const c of [resolveCapHandle(explicitCap), ex.consumedCapabilityId, ...(ex.consumedCapabilities ?? [])]) if (typeof c === 'string' && c.trim()) { pushUnique(hop.consumedCapabilities, c); hop.capConsumeExchange.set(c, ex.exchangeId) }
    for (const src of ex.derivedFromCapabilityIds ?? []) if (src && !hop.cryptoConsumptions.some(c => c.sourceCapabilityId === src)) { pushUnique(hop.consumedCapabilities, src); hop.cryptoConsumptions.push({ sourceCapabilityId: src }) }
  }
  private callRpc(op: string, args: Record<string, unknown>, timeoutMs = 60_000): Promise<unknown> { this._lastRpcOp = op; return sendRpc(this.transport, op, args, timeoutMs) }

  chain(opts: ChainBuilderOptions): ChainBuilder
  chain(chainId: string, terminalVulnClass: string, opts?: Omit<ChainBuilderOptions, 'chainId' | 'terminalVulnClass'>): ChainBuilder
  chain(optsOrId: ChainBuilderOptions | string, terminalVulnClass?: string, extra?: Omit<ChainBuilderOptions, 'chainId' | 'terminalVulnClass'>): ChainBuilder {
    return new ChainBuilder(this, typeof optsOrId === 'string' ? { chainId: optsOrId, terminalVulnClass: terminalVulnClass ?? '', ...(extra ?? {}) } : optsOrId)
  }

  private buildHttpRpcArgs(input: HttpTarget, options: HttpOptions = {}): { args: Record<string, unknown>; timeoutMs: number } {
    const target = splitTarget(input, this.defaultOrigin)
    const merged: HttpOptions = { ...extractInlineHttpOptions(input), ...options }
    const { body, headers } = normalizeBodyAndHeaders(merged.body, merged.headers)
    const persona = merged.as ?? merged.persona
    const sessionGroupRole = merged.role ?? merged.arm
    return {
      args: {
        ...(target.origin ? { origin: target.origin } : {}), path: target.path, method: (merged.method ?? 'GET').toUpperCase(),
        ...(headers ? { headers } : {}), ...(body !== undefined ? { body } : {}), ...(persona ? { persona } : {}),
        ...(sessionGroupRole ? { sessionGroupRole } : {}),
        ...pickDefined(merged as Record<string, unknown>, ['session', 'followRedirects', 'capability', 'capabilityTarget', 'capabilityHeaderName', 'capabilityCookieName', 'capabilityQueryParam', 'authMutation', 'entityId', 'evidenceRole', 'replayAttempt']),
        ...(merged.correlationIds?.length ? { correlationIds: merged.correlationIds } : {}),
      },
      timeoutMs: (merged.timeoutMs ?? 60_000) + 10_000,
    }
  }

  private async sendHttp(op: 'http' | 'http.send', input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> {
    const { args, timeoutMs } = this.buildHttpRpcArgs(input, options)
    const ex = hydrateExchange(await this.callRpc(op, args, timeoutMs) as HttpExchange)
    const hop = this.activeHop()
    if (hop) {
      hop.onExchange(ex.exchangeId)
      if (!hop.target) hop.target = { origin: typeof args.origin === 'string' ? args.origin : this.targetOrigin, method: typeof args.method === 'string' ? args.method : ex.method, pathAndQuery: ex.pathAndQuery || (typeof args.path === 'string' ? args.path : '/') }
      this.recordExCaps(hop, ex, args.capability)
      if (!hop.entityId && typeof args.entityId === 'string' && args.entityId.trim()) hop.entityId = args.entityId.trim()
      if (Array.isArray(args.correlationIds)) for (const cid of args.correlationIds) if (typeof cid === 'string') hop.onCorrelation(cid)
    }
    return ex
  }

  http(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> { return this.sendHttp('http', input, options) }
  http_send(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> { return this.sendHttp('http.send', input, options) }
  request(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> { return this.sendHttp('http.send', input, options) }

  async seal_capability(input: SealCapabilityInput): Promise<SealedCapabilityResult> {
    const raw = (input && typeof input === 'object' ? input : {}) as unknown as Record<string, unknown>
    const exchangeId = extractExchangeIds((raw.exchangeId ?? raw.exchange ?? raw.exchange_id ?? raw.sourceExchangeId ?? raw.response) as ExchangeRef | undefined)[0]
    if (!exchangeId) throw new Error('seal_capability requires exchangeId (string) or exchange ({ exchangeId }).')
    const activeHop = this.activeHop(), hopReceiptId = (typeof raw.hopReceiptId === 'string' && raw.hopReceiptId.trim()) ? raw.hopReceiptId.trim() : (typeof raw.hopId === 'string' && raw.hopId.trim()) ? raw.hopId.trim() : activeHop?.hopId
    const cookieSel = typeof raw.cookie === 'string' && raw.cookie.trim() ? raw.cookie : typeof raw.setCookie === 'string' && raw.setCookie.trim() ? raw.setCookie : undefined
    const res = await this.callRpc('capability.seal', {
      exchangeId, slot: input.slot, ...(hopReceiptId ? { hopReceiptId } : {}), ...(cookieSel ? { cookie: cookieSel } : {}),
      ...pickDefined(raw, ['jsonPath', 'header', 'setCookie', 'locationQuery', 'queryParam', 'regex', 'kind', 'defaultHeaderName', 'defaultCookieName']),
      ...(input.value !== undefined ? { value: input.value } : {}), ...(input.ttlMs !== undefined ? { ttlMs: input.ttlMs } : {}), ...(input.allowedOrigins?.length ? { allowedOrigins: input.allowedOrigins } : {}),
    }, 30_000) as SealedCapabilityResult
    const srcEx = res.exchangeId || exchangeId; if (res.handle && srcEx) this._capOrigins.set(res.handle, srcEx); activeHop?.onProduce(res.handle, srcEx)
    return res
  }
  sealCapability(input: SealCapabilityInput): Promise<SealedCapabilityResult> { return this.seal_capability(input) }

  private recordCrypto(secretHandle: string, exchangeId: string | undefined, derivedHandle: string, alg?: string): void {
    const hop = this.activeHop()
    if (!hop) return
    if (exchangeId) hop.onExchange(exchangeId)
    if (secretHandle) { pushUnique(hop.consumedCapabilities, secretHandle); hop.cryptoConsumptions.push({ sourceCapabilityId: secretHandle, derivedCapabilityId: derivedHandle, alg }) }
    if (/^cap:/.test(derivedHandle)) hop.onProduce(derivedHandle, exchangeId)
  }

  async hmac_sign(inputOrSecret: HmacSignInput | Record<string, unknown> | string, payloadArg?: string | Record<string, unknown> | unknown[], opts?: { alg?: string; encoding?: string } | string, encodingArg?: string): Promise<HmacSignResult> {
    const isPos = typeof inputOrSecret === 'string' || (payloadArg !== undefined && inputOrSecret && typeof inputOrSecret === 'object' && !('secretHandle' in inputOrSecret))
    const r = !isPos && inputOrSecret && typeof inputOrSecret === 'object' ? (inputOrSecret as Partial<HmacSignInput>) : {}
    const posOpts = isPos ? (typeof opts === 'string' ? { alg: opts } : (opts ?? {})) : {}
    const secretHandle = resolveCapHandle(isPos ? inputOrSecret : (r.secretHandle ?? ''))
    const alg = isPos ? posOpts.alg : r.alg, encoding = isPos ? (encodingArg ?? posOpts.encoding) : r.encoding
    const res = await this.callRpc('crypto.hmacSign', { secretHandle, payload: normalizePayloadStr(isPos ? payloadArg : r.payload), ...(alg ? { alg } : {}), ...(encoding ? { encoding } : {}) }, 30_000) as HmacSignResult
    const handle = res.handle ?? res.derivedHandle ?? res.signature
    const out = { ...res, signature: res.signature ?? handle, handle, derivedHandle: res.derivedHandle ?? handle }
    this.recordCrypto(secretHandle, out.exchangeId, out.derivedHandle, out.attestation?.alg ?? alg)
    return out
  }
  hmacSign(...args: Parameters<VerifyContext['hmac_sign']>): Promise<HmacSignResult> { return this.hmac_sign(...args) }

  async jwt_sign(inputOrSecret: JwtSignInput | Record<string, unknown> | string, claimsArg?: Record<string, unknown>, opts?: Omit<JwtSignInput, 'secretHandle' | 'claims'> | string): Promise<JwtSignResult> {
    const isPos = typeof inputOrSecret === 'string' || (claimsArg !== undefined && inputOrSecret && typeof inputOrSecret === 'object' && !('secretHandle' in inputOrSecret))
    const r: Partial<JwtSignInput> = isPos ? (typeof opts === 'string' ? { alg: opts as JwtSignInput['alg'] } : { ...(opts ?? {}) }) : ((inputOrSecret && typeof inputOrSecret === 'object' ? inputOrSecret : {}) as Partial<JwtSignInput>)
    const secretHandle = resolveCapHandle(isPos ? inputOrSecret : (r.secretHandle ?? ''))
    const res = await this.callRpc('crypto.jwtSign', {
      secretHandle, claims: (isPos ? claimsArg : r.claims) ?? {},
      ...pickDefined(r as Record<string, unknown>, ['alg', 'header', 'hopReceiptId', 'slot']),
      ...(r.ttlMs !== undefined ? { ttlMs: r.ttlMs } : {}), ...(r.allowedOrigins?.length ? { allowedOrigins: r.allowedOrigins } : {}),
    }, 30_000) as JwtSignResult
    const out = { ...res, handle: res.handle ?? res.derivedHandle, token: res.token ?? res.derivedHandle }
    if (out.derivedHandle && out.exchangeId) this._capOrigins.set(out.derivedHandle, out.exchangeId)
    this.recordCrypto(secretHandle, out.exchangeId, out.derivedHandle, out.attestation?.alg ?? r.alg)
    return out
  }
  jwtSign(...args: Parameters<VerifyContext['jwt_sign']>): Promise<JwtSignResult> { return this.jwt_sign(...args) }

  async await_async(input: AsyncAwaitInput | Record<string, unknown>): Promise<AsyncAwaitResult> {
    const r = (input && typeof input === 'object' ? input : {}) as AsyncAwaitInput
    const { args: pollRequest } = r.pollRequest !== undefined ? this.buildHttpRpcArgs(r.pollRequest, typeof r.pollRequest === 'string' ? extractInlineHttpOptions(r) : {}) : this.buildHttpRpcArgs(r as HttpTarget)
    const matchPredicate = normalizeAsyncPredicate(r.matchPredicate, r.expectStatus)
    const triggerExchangeId = typeof r.triggerExchangeId === 'string' ? r.triggerExchangeId : (r.triggerExchangeId && typeof r.triggerExchangeId === 'object' ? r.triggerExchangeId.exchangeId : undefined)
    const timeoutMs = r.timeoutMs !== undefined ? Number(r.timeoutMs) : undefined
    const res = await this.callRpc('async.awaitResult', {
      pollRequest, ...(matchPredicate ? { matchPredicate } : {}), ...(r.profile ? { profile: r.profile } : {}),
      ...(timeoutMs !== undefined ? { timeoutMs } : {}), ...(r.intervalMs !== undefined ? { intervalMs: Number(r.intervalMs) } : {}),
      ...(r.maxAttempts !== undefined ? { maxAttempts: Number(r.maxAttempts) } : {}), ...(triggerExchangeId ? { triggerExchangeId } : {}),
      ...(r.tTriggerMs !== undefined ? { tTriggerMs: Number(r.tTriggerMs) } : {}), ...(r.correlationId ? { correlationId: String(r.correlationId) } : {}),
      ...(r.correlationIds?.length ? { correlationIds: r.correlationIds } : {}), ...(r.entityId ? { entityId: String(r.entityId) } : {}),
    }, Math.max((timeoutMs ?? 30_000) + 10_000, 15_000)) as AsyncAwaitResult
    const out = res && res.exchange ? { ...res, exchange: hydrateExchange(res.exchange) } : res
    const hop = this.activeHop()
    if (hop) {
      if (out.exchangeId) hop.onExchange(out.exchangeId)
      if (out.exchange) this.recordExCaps(hop, out.exchange, pollRequest.capability)
      if (!hop.target) hop.target = { origin: typeof pollRequest.origin === 'string' ? pollRequest.origin : this.targetOrigin, method: typeof pollRequest.method === 'string' ? pollRequest.method : 'GET', pathAndQuery: out.exchange?.pathAndQuery || (typeof pollRequest.path === 'string' ? pollRequest.path : '/') }
      const cid = r.correlationId ? String(r.correlationId) : (r.correlationIds?.[0] ? String(r.correlationIds[0]) : undefined)
      if (cid) hop.onCorrelation(cid)
      if (!hop.entityId && r.entityId) hop.entityId = String(r.entityId)
      if (out.pollRecordId) hop.asyncPolls.push({ pollRecordId: out.pollRecordId, ...(cid ? { correlationId: cid } : {}), ...(triggerExchangeId ? { triggerExchangeId } : {}) })
    }
    return out
  }
  awaitAsync(input: AsyncAwaitInput | Record<string, unknown>): Promise<AsyncAwaitResult> { return this.await_async(input) }

  private recordProofClaims(ok: boolean, claims: readonly VerifyClaim[]): void {
    if (claims.length) { if (ok) { this._lastFailedClaims = []; this.claims.push(...claims) } else { this._lastFailedClaims = [...claims] } }
  }
  async prove_composite(receipt: CompositeProofReceiptInput): Promise<CompositeVerificationResult> {
    const res = await this.callRpc('composite.verify', normalizeCompositeReceipt(receipt, this.defaultOrigin), 30_000) as CompositeVerificationResult
    const confirmed = res.confirmed === true || res.ok === true || res.verified === true
    if (res.claim) this.recordProofClaims(confirmed, [res.claim])
    return { ...res, confirmed, ok: confirmed, verified: confirmed }
  }
  proveComposite(receipt: CompositeProofReceiptInput): Promise<CompositeVerificationResult> { return this.prove_composite(receipt) }

  effectiveClaims(): VerifyClaim[] { return this.claims.length > 0 ? [...this.claims] : [...this._lastFailedClaims] }

  async browser(input: HttpTarget, options: { as?: string; waitForSelector?: string; timeoutMs?: number } = {}): Promise<BrowserExchange> {
    const target = splitTarget(input, this.defaultOrigin)
    const res = await this.callRpc('browser', { ...(target.origin ? { origin: target.origin } : {}), path: target.path, ...(options.as ? { persona: options.as } : {}), ...(options.waitForSelector ? { waitForSelector: options.waitForSelector } : {}) }, (options.timeoutMs ?? 60_000) + 10_000) as BrowserExchange
    const hop = this.activeHop()
    if (hop) { pushUnique(hop.browserTraceIds, res.exchangeId); if (!hop.target) hop.target = { origin: target.origin ?? this.targetOrigin, method: 'GET', pathAndQuery: target.path } }
    return res
  }

  readonly oob = {
    mint: async (label: string, origin?: string): Promise<OobHandle> => { const res = await this.callRpc('oob', { action: 'mint', label, ...(origin ? { origin } : {}) }, 30_000) as OobHandle; pushUnique(this.activeHop()?.oobEventIds ?? [], res.exchangeId); return res },
    check: async (handle: OobHandle): Promise<OobCheck> => { const res = { ...handle, ...(await this.callRpc('oob', { action: 'check', token: handle.token, exchangeId: handle.exchangeId }, 30_000) as OobCheck) }; pushUnique(this.activeHop()?.oobEventIds ?? [], res.checkExchangeId ?? res.exchangeId); return res },
  }

  // -- authoritative host-backed proof helpers (`prove.*`) ----------------

  private async callProof<T extends { ok?: boolean; confirmed?: boolean; claim?: VerifyClaim; claims?: VerifyClaim[] }>(op: string, input: unknown, errMsg: string, timeoutMs: number, hydrateKeys?: readonly string[]): Promise<T> {
    if (!input || typeof input !== 'object') throw new Error(errMsg)
    const raw = await this.callRpc(op, input as Record<string, unknown>, timeoutMs) as Record<string, unknown>
    const res = (hydrateKeys ? hydrateFields(raw, hydrateKeys) : raw) as unknown as T
    this.recordProofClaims(res.ok !== false && res.confirmed !== false, Array.isArray(res.claims) ? res.claims : res.claim ? [res.claim] : [])
    return res
  }

  prove_access_boundary(input: AccessBoundaryInput | Record<string, unknown>): Promise<AccessBoundaryProof> {
    return this.callProof<AccessBoundaryProof>('prove.accessBoundary', input, 'prove_access_boundary requires { controlPersona?, probePersona?, route, method?, boundaryClass?, vulnClass?, expectControlDenied? }.', 70_000, ['control', 'probe'])
  }

  async prove_persisted_mutation(input: PersistedMutationInput | Record<string, unknown>): Promise<PersistedMutationProof> {
    if (!input || typeof input !== 'object') throw new Error('prove_persisted_mutation requires { readRoute, mutation, fieldPath, expectDelta }.')
    const raw = input as Record<string, unknown>, expectFn = typeof raw.expectDelta === 'function' ? raw.expectDelta : null, payload: Record<string, unknown> = { ...raw }
    if (payload.mutation === undefined && payload.write === undefined) { const m = raw.mutate ?? raw.mutationRoute ?? raw.writeRoute ?? raw.mutationTarget; if (m !== undefined) payload.mutation = m }
    if (payload.readRoute === undefined && payload.read_route === undefined) { const rr = raw.read ?? raw.beforeRoute ?? raw.readTarget ?? (payload.mutation !== undefined || payload.write !== undefined ? raw.route : undefined); if (rr !== undefined) payload.readRoute = rr }
    if (expectFn) { delete payload.expectDelta; payload.hasCustomExpectFn = true }
    const res = hydrateFields(await this.callRpc('prove.persistedMutation', payload, 70_000) as Record<string, unknown>, ['before', 'mutation', 'after']) as unknown as PersistedMutationProof
    if (expectFn && !Boolean(expectFn(res.delta.before, res.delta.after, res.delta))) {
      if (res.claim) this.recordProofClaims(false, [res.claim])
      return { ...res, ok: false, confirmed: false, expectationMatched: false, rejectedBy: res.rejectedBy ?? 'impact', missingEvidence: [...new Set([...res.missingEvidence, 'expected_delta'])] }
    }
    if (res.claim) this.recordProofClaims(res.ok !== false && res.confirmed !== false, [res.claim])
    return res
  }

  async prove_boolean_or_timing_diff(input: BooleanOrTimingDiffInput | Record<string, unknown>): Promise<DifferentialProof> {
    const res = await this.callProof<DifferentialProof>('prove.differential', input, 'prove_boolean_or_timing_diff requires { control, variant, mode: "boolean"|"timing", rounds? }.', 120_000)
    if (res.exchanges) res.exchanges = { control: res.exchanges.control.map(hydrateExchange), variant: res.exchanges.variant.map(hydrateExchange) }
    return res
  }

  async prove_oob_callback(input: OobCallbackInput | Record<string, unknown>): Promise<OobCallbackProof> {
    const raw = input as Record<string, unknown>, timeoutMs = Number(raw.timeoutMs ?? 6_000)
    let res: OobCallbackProof
    if (typeof raw.inject === 'function') {
      const injectFn = raw.inject as (canary: OobHandle) => Promise<HttpExchange | void> | HttpExchange | void
      const started = await this.callRpc('prove.oob', { phase: 'start', ...(raw.token ? { token: raw.token } : {}), ...(raw.immediateMs !== undefined ? { immediateMs: Number(raw.immediateMs) } : {}), ...(raw.windowMs !== undefined ? { windowMs: Number(raw.windowMs) } : {}) }, 30_000) as { handle: OobHandle; subscription: Record<string, unknown> }
      let injection: HttpExchange | null = null, injectionError: string | null = null
      try { injection = (await injectFn(started.handle)) ?? null } catch (err) { injectionError = err instanceof Error ? err.message : 'OOB injection failed.' }
      res = await this.callRpc('prove.oob', { phase: 'finish', handle: started.handle, subscription: started.subscription, ...(injection ? { injection } : {}), ...(injectionError ? { injectionError } : {}), ...(raw.immediateMs !== undefined ? { immediateMs: Number(raw.immediateMs) } : {}), timeoutMs, ...(raw.message ? { message: raw.message } : {}) }, timeoutMs + 15_000) as OobCallbackProof
    } else { res = await this.callRpc('prove.oob', raw, timeoutMs + 20_000) as OobCallbackProof }
    if (res.claim) this.recordProofClaims(res.ok !== false && res.confirmed !== false, [res.claim])
    return res
  }

  async prove_race_burst(input: RaceBurstInput | Record<string, unknown>): Promise<RaceBurstProof> {
    const raw = (input && typeof input === 'object' ? input : {}) as Record<string, unknown>, reqCount = Array.isArray(raw.requests) ? raw.requests.length : 0
    const res = hydrateFields(await this.callRpc('prove.race', raw, Math.max(40_000, Math.min(80_000, 25_000 + reqCount * 2_000))) as Record<string, unknown>, ['baseline', 'post', 'serial', 'serialPost']) as unknown as RaceBurstProof
    if (res.claim && Array.isArray(res.claim.exchangeIds) && res.claim.exchangeIds.length >= 2) this.recordProofClaims(res.ok !== false && res.confirmed !== false, [res.claim])
    const hop = this.activeHop()
    if (hop) {
      for (const id of res.claim?.exchangeIds ?? res.exchanges?.map(e => e.exchangeId) ?? []) hop.onExchange(id)
      if (!hop.target && Array.isArray(raw.requests) && raw.requests.length > 0) {
        const first = raw.requests[0] as RaceRequestInput | HttpTarget
        try { const t = splitTarget(first as HttpTarget, this.defaultOrigin); hop.target = { origin: t.origin ?? this.targetOrigin, method: typeof first === 'object' && first && 'method' in first && typeof first.method === 'string' ? first.method.toUpperCase() : 'POST', pathAndQuery: t.path } } catch { /* explicit target */ }
      }
    }
    return res
  }

  prove_injection_differential(input: InjectionDifferentialInput | Record<string, unknown>): Promise<InjectionDifferentialProof> {
    return this.callProof<InjectionDifferentialProof>('prove.injection', input, 'prove_injection_differential requires { control, probe, expectedOutput?, vulnClass? }.', 70_000, ['control', 'probe'])
  }

  prove_signed_url_mint(input: SignedUrlMintInput | Record<string, unknown>): Promise<SignedUrlMintProof> {
    return this.callProof<SignedUrlMintProof>('prove.signedUrlMint', input, 'prove_signed_url_mint requires { control, probe } (or route + controlBody/probeBody, or controlExchangeId/probeExchangeId).', 70_000, ['control', 'probe'])
  }

  /** Thin camelCase compatibility delegates for existing v6/v8 callers. */
  proveAccessBoundary(input: AccessBoundaryInput | Record<string, unknown>): Promise<AccessBoundaryProof> { return this.prove_access_boundary(input) }
  provePersistedMutation(input: PersistedMutationInput | Record<string, unknown>): Promise<PersistedMutationProof> { return this.prove_persisted_mutation(input) }
  proveBooleanOrTimingDiff(input: BooleanOrTimingDiffInput | Record<string, unknown>): Promise<DifferentialProof> { return this.prove_boolean_or_timing_diff(input) }
  proveInjectionDifferential(input: InjectionDifferentialInput | Record<string, unknown>): Promise<InjectionDifferentialProof> { return this.prove_injection_differential(input) }
  proveSignedUrlMint(input: SignedUrlMintInput | Record<string, unknown>): Promise<SignedUrlMintProof> { return this.prove_signed_url_mint(input) }
  proveOobCallback(input: OobCallbackInput | Record<string, unknown>): Promise<OobCallbackProof> { return this.prove_oob_callback(input) }
  proveRaceBurst(input: RaceBurstInput | Record<string, unknown>): Promise<RaceBurstProof> { return this.prove_race_burst(input) }

  result(input: { title: string; severity?: string; description?: string }): ProofResult {
    if (!input.title || !input.title.trim()) throw new Error('Proof result requires a title.')
    return { sdk: 'kovo_verify.ts', nonce: this.nonce, title: input.title.slice(0, 300), severity: (input.severity ?? 'high').slice(0, 32), ...(input.description ? { description: input.description.slice(0, 4000) } : {}), claims: this.effectiveClaims() }
  }
}

export interface VerificationScript { setup?(ctx: VerifyContext): Promise<void> | void; verify(ctx: VerifyContext): Promise<ProofResult | unknown> | ProofResult | unknown; cleanup?(ctx: VerifyContext): Promise<void> | void }
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
        sdk: 'kovo_verify.ts', nonce: typeof rec.nonce === 'string' && rec.nonce ? rec.nonce : ctx.nonce,
        title: typeof rec.title === 'string' && rec.title.trim() ? rec.title.trim().slice(0, 300) : fallbackTitle,
        severity: typeof rec.severity === 'string' && rec.severity.trim() ? rec.severity.trim().slice(0, 32) : 'high',
        ...(typeof rec.description === 'string' && rec.description ? { description: rec.description.slice(0, 4000) } : {}),
        claims: rec.claims.length > 0 ? (rec.claims as VerifyClaim[]) : fallbackClaims,
      }
    }
  }
  return { sdk: 'kovo_verify.ts', nonce: ctx.nonce, title: fallbackTitle, severity: 'high', claims: fallbackClaims }
}

function failScript(ctx: VerifyContext, message: string, claims: VerifyClaim[]): void {
  writeResult({ sdk: 'kovo_verify.ts', nonce: ctx.nonce, error: message.slice(0, 2000), ...(ctx.lastRpcOp ? { lastRpcOp: ctx.lastRpcOp } : {}), claims })
  process.stderr.write(`kovo_verify: ${message}\n`)
  process.exitCode = 1
}

export async function runVerification(script: VerificationScript, defaultTitle?: string): Promise<void> {
  const ctx = new VerifyContext()
  let result: unknown = null
  try {
    await script.setup?.(ctx); result = await script.verify(ctx); await script.cleanup?.(ctx)
  } catch (error) {
    failScript(ctx, error instanceof Error ? error.message : 'Verification script failed.', ctx.effectiveClaims()); return
  }
  const normalized = normalizeProofResult(ctx, result, defaultTitle)
  writeResult(normalized)
  process.stdout.write(`kovo_verify: ${normalized.claims.length} transcript-backed claim(s) recorded\n`)
}

export async function runEntrypoint(entry: VerificationEntrypoint, defaultTitle?: string): Promise<void> {
  if (typeof entry === 'function') { await runVerification({ verify: entry }, defaultTitle); return }
  if (entry && typeof entry === 'object' && typeof entry.verify === 'function') { await runVerification(entry, defaultTitle); return }
  failScript(new VerifyContext(), 'kovo_verify script must export a default async (ctx) => ... function, an object with verify(ctx), or execute ctx.prove_* directly.', [])
}
