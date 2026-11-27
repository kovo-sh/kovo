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
export interface RaceClaim { kind: 'race'; exchangeIds: string[]; burstExchangeIds?: string[]; baselineExchangeId?: string; postExchangeId?: string; serialExchangeIds?: string[]; serialPreExchangeId?: string; serialPostExchangeId?: string; balanceField?: string; capField?: string; unitDebit?: number; vulnClass?: string; requestBody?: unknown; mode?: 'h2-single-packet' | 'http1-fallback'; minDistinctOutcomes?: number; expectAllSuccess?: boolean; message?: string }
export interface ImpactClaim { kind: 'impact'; impactClass: 'authorization' | 'bfla' | 'mass_assignment' | 'csrf' | 'injection'; vulnClass?: string; probeExchangeId: string; controlExchangeIds?: string[]; beforeExchangeId?: string; afterExchangeId?: string; requiredRole?: string; resourceTenant?: string; expectControlDenied?: boolean; oracleEvents?: string[]; proofPatterns?: string[]; actorRoles?: Record<string, string>; actorTenants?: Record<string, string>; requestBody?: unknown; ambient?: { kind: 'cookie' | 'bearer' | 'header' | 'unknown'; sameSite?: string }; message?: string }
export interface BoundaryClaim { kind: 'boundary'; boundaryClass: 'auth' | 'mfa' | 'access' | 'other'; vulnClass?: string; controlExchangeId: string; probeExchangeId: string; expectControlDenied?: boolean; controlRequestBody?: unknown; probeRequestBody?: unknown; actorRoles?: Record<string, string>; actorTenants?: Record<string, string>; message?: string }
export interface CompositeReceiptClaim { kind: 'composite_receipt'; verificationId?: string; chainId: string; terminalVulnClass: string; cwe?: string; route?: string; exchangeIds: string[]; terminalExchangeId?: string; replayMode?: 'fresh_clean_replay' | 'one_shot_transcript'; hopCount?: number; compositeReceipt?: Record<string, unknown>; rejectedBy?: string | null; missingEvidence?: string[]; reason?: string; message?: string }
export interface HostEvaluatedExpressionClaim { kind: 'host_evaluated_expression'; vulnClass?: string; controlIds: string[]; probeIds: string[]; hostMintedChallengeIds: string[]; message?: string }
export type VerifyClaim = StatusClaim | HeaderClaim | BodyClaim | JsonPathClaim | CssClaim | SentinelsClaim | OobClaim | TimingClaim | StructuralDiffClaim | RaceClaim | ImpactClaim | BoundaryClaim | CompositeReceiptClaim | HostEvaluatedExpressionClaim
export type ProofRole = 'setup' | 'control' | 'probe' | 'cleanup' | 'control_denied' | 'variant_crossed' | 'before_get' | 'mutation' | 'after_get' | 'oob_mint' | 'oob_injection' | 'oob_wait' | 'pending_oob' | 'race'
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
export interface RaceRequestInput { target?: HttpTarget; url?: HttpTarget; path?: string; origin?: string; method?: string; headers?: Record<string, string>; body?: string | Record<string, unknown> | unknown[]; jsonBody?: unknown; textBody?: string; as?: string }
export interface RaceBurstInput { requests: Array<RaceRequestInput | HttpTarget>; barrier?: 'auto' | 'h2' | 'http1'; session?: string; minDistinctOutcomes?: number; expectAllSuccess?: boolean; readRoute?: HttpTarget; readMethod?: string; readPersona?: string; serialRequest?: RaceRequestInput | HttpTarget; balanceField?: string; capField?: string; unitDebit?: number; vulnClass?: string; baselineExchangeId?: string; postExchangeId?: string; serialExchangeIds?: string[]; serialPreExchangeId?: string; serialPostExchangeId?: string; message?: string }
export interface InjectionDifferentialInput { control?: DifferentialArmInput | HttpTarget; probe?: DifferentialArmInput | HttpTarget; variant?: DifferentialArmInput | HttpTarget; url?: string; path?: string; pathAndQuery?: string; endpoint?: string; route?: string; method?: string; headers?: Record<string, string>; as?: string; controlBody?: string | Record<string, unknown>; probeBody?: string | Record<string, unknown>; expectedOutput?: string; vulnClass?: string; session?: string; message?: string }
export interface SignedUrlMintInput { control?: DifferentialArmInput | HttpTarget; probe?: DifferentialArmInput | HttpTarget; controlExchangeId?: string; probeExchangeId?: string; variant?: 'auto' | 'key_traversal' | 'unauth_write_mint'; url?: string; path?: string; pathAndQuery?: string; endpoint?: string; route?: string; method?: string; headers?: Record<string, string>; as?: string; controlBody?: string | Record<string, unknown>; probeBody?: string | Record<string, unknown>; session?: string; message?: string }
export interface ProofResult { sdk: 'kovo_verify.ts'; nonce: string; title: string; severity: string; description?: string; claims: VerifyClaim[] }
export interface RpcContext { nonce: string; runId: string; targetOrigins: string[]; sdkVersion: string }
interface RpcEnvelope { ok: boolean; result?: unknown; error?: string }
export interface HttpExchange { exchangeId: string; status: number; method: string; pathAndQuery: string; finalPathAndQuery?: string; redirectOrigins?: string[]; mediaType: string; headers: Record<string, string>; body: string; text: string; json: unknown; data: unknown; bodyPreview: string; bodyBytes: number; bodySha256: string; durationMs: number; personaHandle: string | null; raceBatchId?: string; consumedCapabilityId?: string | null; consumedCapabilities?: string[]; derivedFromCapabilityIds?: string[]; protocol?: 'h2' }
export interface RaceBurstHopResult { mode: 'h2-single-packet' | 'http1-fallback'; fallbackReason: string | null; raceBatchId: string; summary: Record<string, unknown>; results: HttpExchange[]; exchanges: HttpExchange[]; baseline?: HttpExchange; post?: HttpExchange }
export interface CapabilityInjectionSpec { handle: string; target?: 'bearer' | 'header' | 'cookie' | 'url'; headerName?: string; cookieName?: string; queryParam?: string }
export interface SealCapabilityInput { exchangeId?: string | { exchangeId: string }; exchange?: string | { exchangeId: string } | null; hopReceiptId?: string; hopId?: string; slot: string; jsonPath?: string; path?: string; header?: string; cookie?: string; setCookie?: string; locationQuery?: string; queryParam?: string; regex?: string; value?: string; kind?: 'bearer_token' | 'api_token' | 'cookie' | 'signed_url' | 'oidc_assertion' | 'signing_salt' | 'hmac_key' | 'jwt' | 'header_secret' | 'generic_secret'; ttlMs?: number | null; defaultHeaderName?: string; defaultCookieName?: string; allowedOrigins?: string[] }
export interface SealedCapabilityResult { handle: string; meta: Record<string, unknown>; exchangeId: string; sealExchangeId: string; scrubbedPreview: string }
export interface HmacSignInput { secretHandle: string; payload: string | Record<string, unknown> | unknown[]; alg?: 'sha256' | 'sha384' | 'sha512'; encoding?: 'hex' | 'base64' | 'base64url' }
export interface HmacSignResult { exchangeId: string; signature: string; handle: string; derivedHandle: string; attestation: { derivedFromCapabilityId: string; alg: string; encoding: string; payloadDigest: string; signatureDigest: string; sourceSecretDigest: string; runId: string; timestampMs: number } }
export interface JwtSignInput { secretHandle: string; claims: Record<string, unknown>; alg?: 'HS256' | 'HS384' | 'HS512'; header?: Record<string, unknown>; hopReceiptId?: string; slot?: string; ttlMs?: number | null; allowedOrigins?: string[] }
export interface JwtSignResult { exchangeId: string; derivedHandle: string; handle: string; token: string; attestation: { derivedFromCapabilityId: string; derivedHandle: string; alg: string; claimsDigest: string; tokenDigest: string; sourceSecretDigest: string; runId: string; timestampMs: number } }
export interface AsyncMatchPredicate { status?: number | number[]; bodyContains?: string; bodyMatches?: string; jsonPath?: string; equals?: unknown; in?: unknown[]; matches?: string; header?: { name: string; equals?: string; matches?: string } }
export interface AsyncAwaitInput extends HttpOptions { pollRequest?: HttpTarget | (HttpOptions & { path?: string; url?: string; origin?: string }); path?: string; url?: string; pathAndQuery?: string; endpoint?: string; route?: string; target?: HttpTarget; origin?: string; matchPredicate?: AsyncMatchPredicate; expectStatus?: number | number[]; profile?: 'fast_lab' | 'wan'; timeoutMs?: number; intervalMs?: number; maxAttempts?: number; triggerExchangeId?: string | { exchangeId: string }; tTriggerMs?: number; correlationId?: string; correlationIds?: string[]; entityId?: string }
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
export interface HttpOptions { as?: string; persona?: string; session?: string; role?: 'setup' | 'control' | 'probe' | 'cleanup'; arm?: 'setup' | 'control' | 'probe' | 'cleanup'; isControl?: boolean; control?: boolean; method?: string; headers?: Record<string, string>; body?: string | Record<string, unknown> | unknown[]; jsonBody?: unknown; textBody?: string; followRedirects?: boolean; timeoutMs?: number; capability?: string | CapabilityInjectionSpec; capabilityTarget?: 'bearer' | 'header' | 'cookie' | 'url'; capabilityHeaderName?: string; capabilityCookieName?: string; capabilityQueryParam?: string; authMutation?: Record<string, unknown>; entityId?: string; correlationIds?: string[]; evidenceRole?: string; replayAttempt?: 'mode_a' | 'ablation_control' | 'primary' }
export type HttpTargetString = `/${string}` | `http://${string}` | `https://${string}` | `cap:${string}` | `${'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS'} ${string}`
export type HttpTargetObj = HttpOptions & { exchangeId?: never; url?: string; path?: string; pathAndQuery?: string; endpoint?: string; route?: string; target?: HttpTarget; origin?: string }
export type HttpTarget = string | (HttpOptions & { url?: string; path?: string; pathAndQuery?: string; endpoint?: string; route?: string; target?: HttpTarget; origin?: string })
export interface Expectations {
  status(exchange: { exchangeId: string }, expected: number | number[], message?: string): StatusClaim; statusNot(exchange: { exchangeId: string }, unexpected: number, message?: string): StatusClaim
  header(exchange: { exchangeId: string }, name: string, expected?: string | { equals?: string; matches?: string; absent?: boolean }, message?: string): HeaderClaim
  bodyContains(exchange: { exchangeId: string }, text: string, message?: string): BodyClaim; bodyAbsent(exchange: { exchangeId: string }, text: string, message?: string): BodyClaim
  jsonPath(exchange: { exchangeId: string }, path: string, expected?: unknown, message?: string): JsonPathClaim
  css(exchange: { exchangeId: string }, selector: string, expected?: { exists?: boolean; count?: number; textEquals?: string; textContains?: string }, message?: string): CssClaim
  domSentinel(exchange: { exchangeId: string }, sentinel: string, mode?: 'source' | 'executed', message?: string): SentinelsClaim; oob(exchange: { exchangeId: string }, expectHit?: boolean, message?: string): OobClaim
}
export type ExchangeRef = string | { exchangeId: string }
export interface ChainBuilderOptions { chainId: string; terminalVulnClass: string; replayMode?: ReplayMode; benchmarkMode?: boolean }
export interface ChainHopOptions { surface?: HopSurface; target?: HopTargetInput; method?: string; role?: 'setup' | 'control' | 'probe' | 'cleanup'; arm?: 'setup' | 'control' | 'probe' | 'cleanup'; claimedDelta?: string; entityId?: string; canaryToken?: string; exchangeIds?: string[]; oobEventIds?: string[]; browserTraceIds?: string[]; producedCapabilities?: string[]; consumedCapabilities?: string[]; proofReceipt?: ProofReceiptInput }
export interface ChainStepOptions extends HttpOptions { hopId?: string; surface?: HopSurface; claimedDelta?: string; canaryToken?: string; proofReceipt?: ProofReceiptInput; producedCapabilities?: string[]; consumedCapabilities?: string[] }
export type ChainSealSelector = string | (Omit<SealCapabilityInput, 'exchangeId' | 'exchange' | 'slot'> & { slot?: string })
export interface ChainRaceBurstOptions extends ChainHopOptions, Omit<HttpOptions, 'role' | 'arm'> { hopId?: string; requests?: Array<RaceRequestInput | HttpTarget>; request?: RaceRequestInput | HttpTarget; count?: number; concurrency?: number; barrier?: 'auto' | 'h2' | 'http1'; readRoute?: HttpTarget; readMethod?: string; readPersona?: string; baseline?: ExchangeRef; readback?: ExchangeRef; url?: string; path?: string; pathAndQuery?: string; endpoint?: string; route?: string; origin?: string }
export interface StateTransitionEdgeInput { fromHopId: string; toHopId: string; entityId: string; ablationExchange?: ExchangeRef | ExchangeRef[]; ablationExchanges?: ExchangeRef | ExchangeRef[]; ablation?: ExchangeRef | ExchangeRef[]; ablationExchangeIds?: string[]; mutationKind?: string }
export interface ChainProveOptions { terminalHopId?: string; claimedImpact?: string; summary?: string; terminalExchange?: ExchangeRef; terminalExchangeId?: string; control?: ExchangeRef | ExchangeRef[]; controlExchanges?: ExchangeRef | ExchangeRef[]; preChainControlExchangeIds?: string[]; readback?: ExchangeRef | ExchangeRef[]; postChainReadbackExchangeIds?: string[]; modeAFailureExchange?: ExchangeRef; modeAFailureExchangeId?: string; oracleFamily?: OracleFamily; oracleInput?: Record<string, unknown>; proofReceipt?: ProofReceiptInput; replayMode?: ReplayMode; benchmarkMode?: boolean }
interface HopRecorder { hopId: string; target?: HopTargetObject; exchangeIds: string[]; oobEventIds: string[]; browserTraceIds: string[]; producedCapabilities: string[]; consumedCapabilities: string[]; entityId?: string; correlationIds: string[]; controlExCount: number; nonControlExCount: number; capConsumeExchange: Map<string, string>; cryptoConsumptions: Array<{ sourceCapabilityId: string; derivedCapabilityId?: string; alg?: string }>; asyncPolls: Array<{ pollRecordId: string; correlationId?: string; triggerExchangeId?: string }>; onProduce(cap: string, exchangeId?: string): void; onExchange(exchangeId: string, isControl?: boolean): void; onCorrelation(correlationId: string): void }
interface ExSealDiag { status: number; mediaType: string; isJson: boolean; parsedJson: unknown; topKeys: string[]; headerNames: string[]; hasLocation: boolean; locationParamNames: string[]; hasSetCookie: boolean }
interface RpcTransport { socketPath: string; token: string; nonce: string }
export const KOVO_VERIFY_SDK_VERSION = 'kovo_verify/v8'
function readContext(): RpcContext {
  const raw = JSON.parse(readFileSync(process.env.KOVO_RPC_CONTEXT_FILE ?? '/kovo-rpc/context.json', 'utf8')) as Record<string, unknown>
  return { nonce: typeof raw.nonce === 'string' ? raw.nonce : '', runId: typeof raw.runId === 'string' ? raw.runId : 'unknown-run', targetOrigins: Array.isArray(raw.targetOrigins) ? raw.targetOrigins.filter((v): v is string => typeof v === 'string') : [], sdkVersion: typeof raw.sdkVersion === 'string' ? raw.sdkVersion : KOVO_VERIFY_SDK_VERSION }
}
function sendRpc(transport: RpcTransport, op: string, args: Record<string, unknown>, timeoutMs = 60_000): Promise<unknown> {
  const payload = JSON.stringify({ op, args })
  return new Promise((resolve, reject) => {
    const req = httpRequest({ socketPath: transport.socketPath, path: '/rpc', method: 'POST', timeout: timeoutMs, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), 'x-kovo-rpc-token': transport.token, 'x-kovo-verify-nonce': transport.nonce, 'x-kovo-sdk-version': KOVO_VERIFY_SDK_VERSION } }, res => {
      const chunks: Buffer[] = []; let size = 0
      res.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 8 * 1024 * 1024) { res.destroy(); reject(new Error('Verification RPC response exceeded the SDK limit.')); return } chunks.push(chunk) })
      res.on('end', () => { let b: RpcEnvelope; try { b = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcEnvelope } catch { reject(new Error('Verification RPC returned malformed JSON.')); return } if (!b.ok) reject(new Error(b.error ?? 'Verification RPC call failed.')); else resolve(b.result) })
    })
    req.on('timeout', () => req.destroy(new Error('Verification RPC call timed out.'))); req.on('error', reject); req.end(payload)
  })
}
const pushUnique = (list: string[], value: string | undefined | null): void => { const t = typeof value === 'string' ? value.trim() : ''; if (t && !list.includes(t)) list.push(t) }
function extractExchangeIds(ref: ExchangeRef | ExchangeRef[] | undefined): string[] { const out: string[] = []; for (const item of !ref ? [] : Array.isArray(ref) ? ref : [ref]) pushUnique(out, typeof item === 'string' ? item : item?.exchangeId); return out }
function pickDefined(src: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> { const out: Record<string, unknown> = {}; for (const k of keys) if (src[k] !== undefined && src[k] !== '') out[k] = src[k]; return out }
function normalizeBodyAndHeaders(rawBody: unknown, rawHeaders?: Record<string, string>): { body?: string; headers?: Record<string, string> } {
  const headers = rawHeaders ? { ...rawHeaders } : undefined
  if (rawBody === undefined || rawBody === null) return headers ? { headers } : {}
  return typeof rawBody === 'string' ? { body: rawBody, ...(headers ? { headers } : {}) } : { body: JSON.stringify(rawBody), headers: Object.keys(headers ?? {}).some(k => k.toLowerCase() === 'content-type') ? headers : { 'content-type': 'application/json', ...(headers ?? {}) } }
}
function splitTarget(input: HttpTarget, defaultOrigin: string | undefined): { origin?: string; path: string; method?: string } {
  if (typeof input === 'string') {
    const trimmed = input.trim(); if (!trimmed) throw new Error('HTTP target path/URL must be non-empty.')
    const mp = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+)$/i.exec(trimmed), method = mp ? mp[1]!.toUpperCase() : undefined, raw = mp ? mp[2]!.trim() : trimmed
    if (/^https?:\/\//i.test(raw)) { const u = new URL(raw); return { origin: u.origin, path: u.pathname + u.search, ...(method ? { method } : {}) } }
    if (/^cap:[a-zA-Z0-9_.:-]+$/.test(raw)) return { ...(defaultOrigin ? { origin: defaultOrigin } : {}), path: raw, ...(method ? { method } : {}) }
    return { ...(defaultOrigin ? { origin: defaultOrigin } : {}), path: raw.startsWith('/') ? raw : `/${raw}`, ...(method ? { method } : {}) }
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('HTTP target requires a path/URL string or an object with { url | path | pathAndQuery | endpoint }.')
  const raw = input.url ?? input.path ?? input.pathAndQuery ?? input.endpoint ?? input.route
  if (typeof raw === 'string' && raw.trim()) { const res = splitTarget(raw, input.origin ?? defaultOrigin); return { ...(input.origin ? { origin: input.origin } : res.origin ? { origin: res.origin } : {}), path: res.path, ...(res.method ? { method: res.method } : {}) } }
  if (input.target !== undefined) { const nested = splitTarget(input.target, input.origin ?? defaultOrigin); return { ...(input.origin ? { origin: input.origin } : nested.origin ? { origin: nested.origin } : {}), path: nested.path, ...(nested.method ? { method: nested.method } : {}) } }
  throw new Error('HTTP target requires a path/URL string or an object with { url | path | pathAndQuery | endpoint }.')
}
const HTTP_OPT_KEYS = ['session', 'role', 'arm', 'isControl', 'control', 'followRedirects', 'timeoutMs', 'capability', 'capabilityTarget', 'capabilityHeaderName', 'capabilityCookieName', 'capabilityQueryParam', 'authMutation', 'entityId', 'correlationIds', 'evidenceRole', 'replayAttempt'] as const
function extractInlineHttpOptions(input: unknown): HttpOptions {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {}
  const r = input as Record<string, unknown>, out: HttpOptions = pickDefined(r, HTTP_OPT_KEYS) as HttpOptions
  if (typeof r.method === 'string' && r.method.trim()) out.method = r.method.trim().toUpperCase()
  if (r.headers && typeof r.headers === 'object' && !Array.isArray(r.headers)) out.headers = r.headers as Record<string, string>
  if (r.body !== undefined) out.body = r.body as HttpOptions['body']
  if (r.jsonBody !== undefined) out.jsonBody = r.jsonBody
  if (r.textBody !== undefined) out.textBody = r.textBody as string
  const persona = typeof r.as === 'string' ? r.as : typeof r.persona === 'string' ? r.persona : undefined; if (persona) out.as = persona; return out
}
function isHttpTargetArg(v: unknown, hasOpts: boolean): boolean {
  if (Array.isArray(v)) return false
  if (v && typeof v === 'object') return typeof (v as Record<string, unknown>).exchangeId !== 'string'
  if (typeof v !== 'string') return false
  const t = v.trim(); return hasOpts || t.startsWith('/') || /^https?:\/\//i.test(t) || /^cap:[a-zA-Z0-9_.:-]+$/.test(t) || /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/i.test(t)
}
function parseSealSelector(s: string): Record<string, unknown> {
  const t = s.trim()
  if (/^header:/i.test(t)) return { header: t.slice(7).trim() }
  if (/^(?:set)?cookie:/i.test(t)) return { setCookie: t.replace(/^(?:set)?cookie:/i, '').trim() }
  if (/^(?:location)?query:/i.test(t)) return { locationQuery: t.replace(/^(?:location)?query:/i, '').trim() }
  if (/^regex:/i.test(t)) return { regex: t.slice(6).trim() }
  return { jsonPath: t.startsWith('$') ? t : `$.${t}` }
}
function parseJsonSafe(body: unknown): unknown { if (typeof body !== 'string') return null; const c = body.replace(/^\uFEFF/, '').trim(); if (!c) return null; try { return JSON.parse(c) } catch { return null } }
export function hydrateExchange(raw: HttpExchange): HttpExchange {
  if (!raw || typeof raw !== 'object') return raw
  const body = typeof raw.body === 'string' ? raw.body : '', parsed = raw.json != null ? raw.json : parseJsonSafe(body)
  return { ...raw, body, text: body, json: parsed, data: parsed, headers: raw.headers && typeof raw.headers === 'object' ? raw.headers : {} }
}
function hydrateFields<T extends Record<string, unknown>>(res: T, keys: readonly string[]): T {
  const out: Record<string, unknown> = { ...res }; for (const k of keys) { const v = out[k]; if (v && typeof v === 'object' && !Array.isArray(v) && 'exchangeId' in (v as Record<string, unknown>)) out[k] = hydrateExchange(v as HttpExchange) }; return out as T
}
const CAP_OBJ_KEYS = ['handle', 'derivedHandle', 'capability', 'capabilityHandle', 'capability_handle', 'sealedHandle', 'sealedCapability', 'cap', 'cap_id', 'capId', 'capabilityId', 'sourceCapabilityId', 'derivedCapabilityId', 'tokenHandle', 'artifactHandle', 'secretHandle', 'token', 'id'] as const
export function unwrapCapabilityHandle(val: unknown, depth = 0): unknown {
  if (typeof val === 'string') return val.trim() || val
  if (depth > 4 || !val || typeof val !== 'object') return val
  if (Array.isArray(val)) return val.length === 1 ? unwrapCapabilityHandle(val[0], depth + 1) : val
  for (const k of CAP_OBJ_KEYS) { const c = (val as Record<string, unknown>)[k]; const u = typeof c === 'string' ? c.trim() : c && typeof c === 'object' ? unwrapCapabilityHandle(c, depth + 1) : ''; if (typeof u === 'string' && u) return u }
  return val
}
export function normalizeCapabilityInjection(val: unknown, depth = 0): unknown {
  if (Array.isArray(val)) return depth < 4 && val.length === 1 ? normalizeCapabilityInjection(val[0], depth + 1) : val
  if (!val || typeof val !== 'object') return typeof val === 'string' ? val.trim() : val
  const handle = unwrapCapabilityHandle(val); if (typeof handle !== 'string' || !handle) return val
  const spec = pickDefined(val as Record<string, unknown>, ['target', 'headerName', 'cookieName', 'queryParam', 'header_name', 'cookie_name', 'query_param']); return Object.keys(spec).length > 0 ? { handle, ...spec } : handle
}
const PROOF_NEST_KEYS = new Set(['control', 'probe', 'variant', 'baseline', 'ablation', 'before', 'after', 'attacker', 'victim', 'requests', 'steps', 'arms', 'options', 'controlOptions', 'control_options', 'probeOptions', 'probe_options', 'mutation', 'write', 'readRoute', 'read_route', 'route', 'probeRoute', 'probe_route', 'target', 'inject', 'serialRequest', 'serial_request'])
export function normalizeProofCapabilities(val: unknown, depth = 0): unknown {
  if (depth > 6 || !val || typeof val !== 'object') return val
  if (Array.isArray(val)) return val.map(v => normalizeProofCapabilities(v, depth + 1))
  const out: Record<string, unknown> = { ...(val as Record<string, unknown>) }; if (out.capability !== undefined) out.capability = normalizeCapabilityInjection(out.capability)
  for (const k of Object.keys(out)) if (PROOF_NEST_KEYS.has(k) && out[k] && typeof out[k] === 'object') out[k] = normalizeProofCapabilities(out[k], depth + 1)
  return out
}
const resolveCapHandle = (value: unknown): string => { const u = unwrapCapabilityHandle(value); return typeof u === 'string' ? u : '' }
const normalizePayloadStr = (value: unknown): string => typeof value === 'string' ? value : value === undefined || value === null ? '' : JSON.stringify(value)
function normalizeAsyncPredicate(raw: AsyncMatchPredicate | undefined, expectStatus?: number | number[]): AsyncMatchPredicate | undefined {
  const pred: AsyncMatchPredicate = raw && typeof raw === 'object' && !Array.isArray(raw) ? { ...raw } : {}; if (expectStatus !== undefined && pred.status === undefined) pred.status = expectStatus; return Object.keys(pred).length > 0 ? pred : undefined
}
function normalizeHopTarget(rawTarget: unknown, hopMethod: unknown, defaultOrigin: string | undefined): unknown {
  const fbMethod = typeof hopMethod === 'string' && hopMethod.trim() ? hopMethod.trim().toUpperCase() : undefined
  if (typeof rawTarget === 'string') {
    const trimmed = rawTarget.trim(); if (!trimmed) return rawTarget
    const pref = /^([A-Za-z]{1,10})\s+(.+)$/.exec(trimmed), method = pref ? pref[1]!.toUpperCase() : fbMethod, split = splitTarget(pref ? pref[2]!.trim() : trimmed, defaultOrigin), origin = split.origin ?? defaultOrigin
    return { ...(origin ? { origin } : {}), ...(method ? { method } : {}), pathAndQuery: split.path }
  }
  if (!rawTarget || typeof rawTarget !== 'object' || Array.isArray(rawTarget)) return rawTarget
  const t = rawTarget as Record<string, unknown>, rawOrigin = typeof t.origin === 'string' && t.origin.trim() ? t.origin.trim() : undefined, rawMethod = typeof t.method === 'string' && t.method.trim() ? t.method.trim().toUpperCase() : fbMethod
  const rawPath = typeof t.pathAndQuery === 'string' && t.pathAndQuery.trim() ? t.pathAndQuery : typeof t.path === 'string' && t.path.trim() ? t.path : typeof t.url === 'string' && t.url.trim() ? t.url : undefined
  const split = rawPath !== undefined ? splitTarget(rawPath, rawOrigin ?? defaultOrigin) : undefined, origin = rawOrigin ?? split?.origin ?? defaultOrigin, param = typeof t.param === 'string' && t.param.trim() ? t.param.trim() : undefined
  return { ...(origin ? { origin } : {}), ...(rawMethod ? { method: rawMethod } : {}), ...(split ? { pathAndQuery: split.path } : {}), ...(param ? { param } : {}) }
}
const normExRef = (v: unknown): unknown => (v && typeof v === 'object' && !Array.isArray(v) && typeof (v as Record<string, unknown>).exchangeId === 'string') ? (v as Record<string, unknown>).exchangeId : v
const normExList = (v: unknown): unknown => Array.isArray(v) ? v.map(normExRef) : v
const normCapList = (v: unknown): unknown => Array.isArray(v) ? v.map(x => unwrapCapabilityHandle(x)) : v
const mapFields = (obj: Record<string, unknown>, map: Record<string, (v: unknown) => unknown>): Record<string, unknown> => { const out: Record<string, unknown> = { ...obj }; for (const [k, fn] of Object.entries(map)) if (out[k] !== undefined) out[k] = fn(out[k]); return out }
const EDGE_KIND_ALIASES: Record<string, CausalEdgeInput['kind']> = {
  value_binding: 'value_binding', value: 'value_binding', valuebinding: 'value_binding', capability: 'value_binding', capability_binding: 'value_binding', cap_binding: 'value_binding',
  derived_crypto_binding: 'derived_crypto_binding', derived_crypto: 'derived_crypto_binding', derivedcrypto: 'derived_crypto_binding', crypto_binding: 'derived_crypto_binding', crypto: 'derived_crypto_binding', hmac_sign: 'derived_crypto_binding', jwt_sign: 'derived_crypto_binding', hmac: 'derived_crypto_binding', jwt: 'derived_crypto_binding',
  state_transition_binding: 'state_transition_binding', state_transition: 'state_transition_binding', statetransition: 'state_transition_binding', state_change: 'state_transition_binding', state_mutation: 'state_transition_binding',
  async_pivot_binding: 'async_pivot_binding', async_pivot: 'async_pivot_binding', asyncpivot: 'async_pivot_binding', await_async: 'async_pivot_binding', async: 'async_pivot_binding', async_binding: 'async_pivot_binding', poll_convergence: 'async_pivot_binding', oob_relay: 'async_pivot_binding',
}
function normalizeEdgeKind(e: Record<string, unknown>, idx: number): CausalEdgeInput['kind'] {
  const raw = e.kind ?? e.type ?? e.bindingKind ?? e.binding
  if (typeof raw === 'string') { const mapped = EDGE_KIND_ALIASES[raw.trim().toLowerCase().replace(/[\s-]+/g, '_')]; if (mapped) return mapped }
  throw new Error(`Invalid causalEdges[${idx}].kind "${String(raw ?? '')}". Valid causalEdges[].kind values: value_binding | derived_crypto_binding | state_transition_binding | async_pivot_binding.`)
}
const EDGE_CAP_ALIASES = ['capability', 'cap', 'handle', 'capability_handle', 'sealedHandle', 'sealedCapability', 'derivedHandle', 'cap_id', 'capId', 'capabilityId', 'tokenHandle', 'artifactHandle', 'secretHandle'] as const
function normalizeEdgeRecord(ed: unknown, idx: number): unknown {
  if (!ed || typeof ed !== 'object' || Array.isArray(ed)) return ed
  const src = ed as Record<string, unknown>, kind = normalizeEdgeKind(src, idx), { type: _t, bindingKind: _bk, binding: _b, ablationExchange, ...e } = src
  const aliasVals = EDGE_CAP_ALIASES.map(k => { const v = e[k]; delete e[k]; return v })
  const ab = e.ablationExchangeIds !== undefined ? normExList(e.ablationExchangeIds) : ablationExchange !== undefined ? extractExchangeIds(ablationExchange as ExchangeRef | ExchangeRef[]) : undefined
  const isVal = kind === 'value_binding', rawCap = [e.capabilityHandle, ...aliasVals, ...(isVal ? [e.derivedCapabilityId, e.sourceCapabilityId] : [])].find(v => v !== undefined && v !== null && (typeof v !== 'string' || v.trim().length > 0))
  const normCap = rawCap !== undefined ? unwrapCapabilityHandle(rawCap) : undefined, base: Record<string, unknown> = { ...e, kind, ...(ab !== undefined ? { ablationExchangeIds: ab } : {}) }
  if (isVal) { delete base.sourceCapabilityId; delete base.derivedCapabilityId; if (normCap !== undefined && normCap !== '') base.capabilityHandle = normCap; else delete base.capabilityHandle }
  else { if (e.capabilityHandle !== undefined) base.capabilityHandle = unwrapCapabilityHandle(e.capabilityHandle); if (kind === 'derived_crypto_binding' && base.sourceCapabilityId === undefined && normCap !== undefined && normCap !== '') base.sourceCapabilityId = normCap }
  return mapFields(base, { sourceCapabilityId: unwrapCapabilityHandle, derivedCapabilityId: unwrapCapabilityHandle, sourceExchangeId: normExRef, targetExchangeId: normExRef })
}
function inferValueBindingCap(edge: Record<string, unknown>, hops: unknown[], capOrigins?: ReadonlyMap<string, string>): string | undefined {
  const list = hops.filter((h): h is Record<string, unknown> => Boolean(h) && typeof h === 'object' && !Array.isArray(h))
  const fromHop = list.find(h => h.hopId === edge.fromHopId), toHop = list.find(h => h.hopId === edge.toHopId); if (!fromHop || !toHop) return undefined
  const strs = (v: unknown): string[] => Array.isArray(v) ? [...new Set(v.filter((x): x is string => typeof x === 'string' && x.trim().length > 0).map(x => x.trim()))] : []
  const prodOf = (h: Record<string, unknown>): string[] => { const ex = strs(h.producedCapabilities); if (ex.length || !capOrigins?.size) return ex; const ids = new Set(strs(h.exchangeIds)); return [...new Set([...capOrigins.entries()].filter(([, id]) => ids.has(id)).map(([c]) => c))] }
  const fromProd = prodOf(fromHop), cred = typeof toHop.credentialHandle === 'string' && /^cap[:_][A-Za-z0-9._:-]{1,180}$/.test(toHop.credentialHandle.trim()) ? [toHop.credentialHandle.trim()] : [], toCons = [...new Set([...strs(toHop.consumedCapabilities), ...cred])]
  const shared = fromProd.filter(c => toCons.includes(c)); if (shared.length === 1) return shared[0]; if (shared.length > 1) return undefined
  const tp = toHop.target && typeof toHop.target === 'object' && !Array.isArray(toHop.target) && typeof (toHop.target as Record<string, unknown>).pathAndQuery === 'string' ? (toHop.target as Record<string, unknown>).pathAndQuery as string : ''
  const inT = tp ? fromProd.filter(c => tp.includes(c)) : []; if (inT.length === 1) return inT[0]; if (inT.length > 1) return undefined
  if (fromProd.length === 1 && toCons.length === 0) return fromProd[0]
  return fromProd.length === 0 && toCons.length === 1 && !list.some(h => h.hopId !== fromHop.hopId && prodOf(h).includes(toCons[0]!)) ? toCons[0] : undefined
}
const normVulnClass = (v: string): string => v.trim().toLowerCase().replace(/[\s-]+/g, '_')
export function normalizeCompositeReceipt(receipt: unknown, defaultOrigin: string | undefined, capOrigins?: ReadonlyMap<string, string>): Record<string, unknown> {
  const raw = receipt && typeof receipt === 'object' && !Array.isArray(receipt) && 'receipt' in receipt ? (receipt as Record<string, unknown>).receipt : receipt
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { receipt: raw }
  const { controlExchanges: topCtrl, ...rec } = raw as Record<string, unknown>
  const tv = typeof rec.terminalVulnClass === 'string' && rec.terminalVulnClass.trim() ? { terminalVulnClass: normVulnClass(rec.terminalVulnClass) } : {}
  if (!Array.isArray(rec.hops)) return { receipt: { ...rec, ...tv } }
  const toArr = (v: unknown): unknown => v === undefined ? undefined : Array.isArray(v) ? v : [v]
  const hops = rec.hops.map(h => {
    if (!h || typeof h !== 'object' || Array.isArray(h)) return h
    const { method, target, role: _r, arm: _a, produces, consumes, sealedCapabilities, sealedCapability, ...rest } = h as Record<string, unknown>
    const rawProd = rest.producedCapabilities ?? toArr(produces ?? sealedCapabilities ?? sealedCapability), rawCons = rest.consumedCapabilities ?? toArr(consumes)
    return mapFields({ ...rest, target: normalizeHopTarget(target, method, defaultOrigin), ...(rawProd !== undefined ? { producedCapabilities: rawProd } : {}), ...(rawCons !== undefined ? { consumedCapabilities: rawCons } : {}) }, { exchangeIds: normExList, producedCapabilities: normCapList, consumedCapabilities: normCapList, credentialHandle: unwrapCapabilityHandle })
  })
  const rawEdges = Array.isArray(rec.causalEdges) ? rec.causalEdges : Array.isArray(rec.edges) ? rec.edges : undefined
  const causalEdges = rawEdges?.map((ed, idx) => {
    const norm = normalizeEdgeRecord(ed, idx) as Record<string, unknown> | unknown
    if (norm && typeof norm === 'object' && !Array.isArray(norm) && (norm as Record<string, unknown>).kind === 'value_binding' && (norm as Record<string, unknown>).capabilityHandle === undefined && (norm as Record<string, unknown>).valueDigest === undefined) { const inf = inferValueBindingCap(norm as Record<string, unknown>, hops, capOrigins); if (inf) return { ...(norm as Record<string, unknown>), capabilityHandle: inf } }
    return norm
  })
  let ti = rec.terminalImpact && typeof rec.terminalImpact === 'object' && !Array.isArray(rec.terminalImpact) ? mapFields(rec.terminalImpact as Record<string, unknown>, { terminalExchangeId: normExRef, modeAFailureExchangeId: normExRef, preChainControlExchangeIds: normExList, postChainReadbackExchangeIds: normExList }) : rec.terminalImpact
  if (topCtrl !== undefined && ti && typeof ti === 'object' && !Array.isArray(ti)) {
    const merged: string[] = []; for (const id of [...extractExchangeIds((ti as Record<string, unknown>).preChainControlExchangeIds as ExchangeRef[] | undefined), ...extractExchangeIds(topCtrl as ExchangeRef | ExchangeRef[])]) pushUnique(merged, id)
    if (merged.length) ti = { ...(ti as Record<string, unknown>), preChainControlExchangeIds: merged }
  }
  return { receipt: { ...rec, ...tv, hops, ...(causalEdges !== undefined ? { causalEdges } : {}), ...(ti !== undefined ? { terminalImpact: ti } : {}) } }
}
interface RecordedHop { receipt: HopReceiptInput; isControlOnly: boolean; capConsumeExchange: Map<string, string>; cryptoConsumptions: Array<{ sourceCapabilityId: string; derivedCapabilityId?: string; alg?: string }>; asyncPolls: Array<{ pollRecordId: string; correlationId?: string; triggerExchangeId?: string }> }
export class ChainBuilder {
  private readonly ctx: VerifyContext; readonly chainId: string; readonly terminalVulnClass: string
  private readonly replayMode: ReplayMode; private readonly benchmarkMode?: boolean
  private readonly hops: RecordedHop[] = []; private readonly capProducer = new Map<string, { hopId: string; exchangeId?: string }>()
  private readonly exchangeToHop = new Map<string, string>(); private readonly correlationToHop = new Map<string, string>()
  private readonly explicitEdges: CausalEdgeInput[] = []; private readonly controlIds: string[] = []; private readonly baselineReadbackIds: string[] = []; private readonly readbackIds: string[] = []; private readonly raceActionIds: string[] = []; private readonly exStatus = new Map<string, number>()
  private hopSeq = 0; private sealSeq = 0; private lastRaceHopId?: string
  constructor(ctx: VerifyContext, opts: ChainBuilderOptions) {
    if (!opts.chainId?.trim()) throw new Error('ChainBuilder requires a non-empty chainId.')
    if (!opts.terminalVulnClass?.trim()) throw new Error('ChainBuilder requires a non-empty terminalVulnClass.')
    this.ctx = ctx; this.chainId = opts.chainId.trim(); this.terminalVulnClass = normVulnClass(opts.terminalVulnClass)
    this.replayMode = opts.replayMode ?? 'fresh_clean_replay'; this.benchmarkMode = opts.benchmarkMode
  }
  private nextHopId(): string { let id: string; do { id = `hop_${++this.hopSeq}` } while (this.hops.some(h => h.receipt.hopId === id)); return id }
  private recordRefs(list: string[], ref: ExchangeRef | ExchangeRef[] | undefined): void { for (const x of !ref ? [] : Array.isArray(ref) ? ref : [ref]) { const id = typeof x === 'string' ? x : x?.exchangeId; pushUnique(list, id); if (id && x && typeof x === 'object' && typeof (x as Partial<HttpExchange>).status === 'number') this.exStatus.set(id, (x as Partial<HttpExchange>).status!) } }
  control(target: HttpTargetString | HttpTargetObj, opts?: HttpOptions): Promise<HttpExchange>
  control(target: string, opts: HttpOptions): Promise<HttpExchange>
  control(ref: ExchangeRef | ExchangeRef[]): this
  control(targetOrRef: ExchangeRef | ExchangeRef[] | HttpTarget, opts?: HttpOptions): this | Promise<HttpExchange> {
    if (!isHttpTargetArg(targetOrRef, opts !== undefined)) { this.recordRefs(this.controlIds, targetOrRef as ExchangeRef | ExchangeRef[]); return this }
    const inlineSess = targetOrRef && typeof targetOrRef === 'object' && !Array.isArray(targetOrRef) && typeof (targetOrRef as HttpOptions).session === 'string' ? (targetOrRef as HttpOptions).session : undefined
    return this.ctx._httpSendDetached(targetOrRef as HttpTarget, { ...(opts ?? {}), role: 'control', arm: 'control', session: opts?.session ?? inlineSess ?? `ctrl_${this.chainId.toLowerCase().replace(/[^a-z0-9_-]+/g, '_').slice(0, 27)}` }).then(ex => { pushUnique(this.controlIds, ex.exchangeId); this.exStatus.set(ex.exchangeId, ex.status); return ex })
  }
  readback(target: HttpTargetString | HttpTargetObj, opts?: HttpOptions): Promise<HttpExchange>
  readback(target: string, opts: HttpOptions): Promise<HttpExchange>
  readback(ref: ExchangeRef | ExchangeRef[]): this
  readback(targetOrRef: ExchangeRef | ExchangeRef[] | HttpTarget, opts?: HttpOptions): this | Promise<HttpExchange> {
    const dest = this.hops.length === 0 ? this.baselineReadbackIds : this.readbackIds
    if (!isHttpTargetArg(targetOrRef, opts !== undefined)) { this.recordRefs(dest, targetOrRef as ExchangeRef | ExchangeRef[]); return this }
    return this.ctx._httpSendDetached(targetOrRef as HttpTarget, { ...(opts ?? {}), role: 'control', arm: 'control' }).then(ex => { pushUnique(dest, ex.exchangeId); this.exStatus.set(ex.exchangeId, ex.status); return ex })
  }
  step<T = HttpExchange>(hopId: string, fn: () => Promise<T> | T): Promise<T>
  step<T = HttpExchange>(hopId: string, meta: ChainHopOptions, fn: () => Promise<T> | T): Promise<T>
  step(target: HttpTarget, opts?: ChainStepOptions): Promise<HttpExchange>
  step(target: HttpTarget, opts: ChainStepOptions | (() => Promise<unknown> | unknown) = {}, fn?: () => Promise<unknown> | unknown): Promise<unknown> {
    if (typeof opts === 'function' || typeof fn === 'function') return this.hop(String(target), typeof opts === 'function' ? {} : (opts as ChainHopOptions), (typeof opts === 'function' ? opts : fn)!)
    const { hopId, surface, claimedDelta, canaryToken, proofReceipt, producedCapabilities, consumedCapabilities, ...httpOpts } = opts
    const inline = extractInlineHttpOptions(target), hasRole = Boolean(httpOpts.role || httpOpts.arm || httpOpts.isControl || httpOpts.control || inline.role || inline.arm || inline.isControl || inline.control)
    return this.hop(hopId?.trim() || this.nextHopId(), { ...(surface ? { surface } : {}), ...(claimedDelta ? { claimedDelta } : {}), ...(canaryToken ? { canaryToken } : {}), ...(proofReceipt ? { proofReceipt } : {}), ...(producedCapabilities ? { producedCapabilities } : {}), ...(consumedCapabilities ? { consumedCapabilities } : {}) }, () => this.ctx.http_send(target, hasRole ? httpOpts : { role: 'probe', ...httpOpts }))
  }
  send(target: HttpTarget, opts?: ChainStepOptions): Promise<HttpExchange> { return this.step(target, opts) }
  async seal(exchange: ExchangeRef, selector: ChainSealSelector): Promise<string> {
    const exId = extractExchangeIds(exchange)[0]; if (!exId) throw new Error('chain.seal requires an exchange or exchangeId.')
    const sel: Record<string, unknown> = typeof selector === 'string' ? parseSealSelector(selector) : { ...(selector ?? {}) }
    if (sel.jsonPath === undefined && typeof sel.path === 'string' && sel.path.trim()) { sel.jsonPath = sel.path.trim(); delete sel.path }
    const slot = typeof sel.slot === 'string' && sel.slot.trim() ? sel.slot.trim() : `s${++this.sealSeq}`
    const hopId = (typeof sel.hopReceiptId === 'string' && sel.hopReceiptId.trim()) ? sel.hopReceiptId.trim() : (typeof sel.hopId === 'string' && sel.hopId.trim()) ? sel.hopId.trim() : this.exchangeToHop.get(exId)
    const res = await this.ctx.seal_capability({ ...(sel as Omit<SealCapabilityInput, 'slot'>), exchangeId: exId, slot, ...(hopId ? { hopReceiptId: hopId } : {}) })
    const srcEx = res.exchangeId || exId
    if (hopId && res.handle) {
      if (!this.capProducer.has(res.handle)) this.capProducer.set(res.handle, { hopId, exchangeId: srcEx })
      const recHop = this.hops.find(h => h.receipt.hopId === hopId); if (recHop) { recHop.receipt.producedCapabilities ??= []; pushUnique(recHop.receipt.producedCapabilities, res.handle) }
    }
    return res.handle
  }
  race(opts: ChainRaceBurstOptions): Promise<RaceBurstHopResult>
  race(hopId: string, opts: ChainRaceBurstOptions): Promise<RaceBurstHopResult>
  race(hopId: string, target: HttpTarget, opts?: ChainRaceBurstOptions): Promise<RaceBurstHopResult>
  race(target: HttpTarget, opts: ChainRaceBurstOptions): Promise<RaceBurstHopResult>
  race(a: ChainRaceBurstOptions | HttpTarget, b?: ChainRaceBurstOptions | HttpTarget, c?: ChainRaceBurstOptions): Promise<RaceBurstHopResult> {
    const isId = typeof a === 'string' && !isHttpTargetArg(a, false)
    const [hopId, target, opts]: [string | undefined, HttpTarget | undefined, ChainRaceBurstOptions] = c !== undefined ? [String(a), b as HttpTarget, c] : b === undefined ? [(a as ChainRaceBurstOptions).hopId, undefined, a as ChainRaceBurstOptions] : isId ? (typeof b === 'string' ? [a, b, {}] : [a, undefined, b as ChainRaceBurstOptions]) : [(b as ChainRaceBurstOptions).hopId, a as HttpTarget, b as ChainRaceBurstOptions]
    const reqObj: RaceRequestInput | HttpTarget | undefined = opts.request !== undefined ? opts.request : target !== undefined ? (typeof target === 'string' ? { ...extractInlineHttpOptions(opts), target } : { ...(target as Record<string, unknown>), ...extractInlineHttpOptions(opts) } as HttpTarget) : (!opts.requests?.length && ['url', 'path', 'pathAndQuery', 'endpoint', 'route', 'target'].some(k => (opts as Record<string, unknown>)[k] !== undefined) ? { ...pickDefined(opts as Record<string, unknown>, ['url', 'path', 'pathAndQuery', 'endpoint', 'route', 'target', 'origin']), ...extractInlineHttpOptions(opts) } as HttpTarget : undefined)
    const { hopId: _h, target: _t, url: _u, path: _p, pathAndQuery: _pq, endpoint: _ep, route: _rt, origin: _o, ...rest } = opts
    return this.raceBurst(hopId?.trim() || this.nextHopId(), { ...rest, ...(reqObj !== undefined ? { request: reqObj } : {}) })
  }
  stateTransition(input: StateTransitionEdgeInput): this {
    const fromHopId = input.fromHopId?.trim(), toHopId = input.toHopId?.trim(), entityId = input.entityId?.trim()
    if (!fromHopId || !toHopId) throw new Error('state_transition_binding requires non-empty fromHopId and toHopId.')
    if (!entityId) throw new Error('state_transition_binding requires an explicit non-empty entityId (never auto-guessed).')
    const ablationIds: string[] = []; for (const id of [...extractExchangeIds(input.ablationExchange), ...extractExchangeIds(input.ablationExchanges), ...extractExchangeIds(input.ablation), ...(input.ablationExchangeIds ?? [])]) pushUnique(ablationIds, id)
    if (ablationIds.length === 0) throw new Error('state_transition_binding requires explicit ablationExchange / ablationExchangeIds (never auto-guessed).')
    this.explicitEdges.push({ kind: 'state_transition_binding', fromHopId, toHopId, entityId, ablationExchangeIds: ablationIds, ...(input.mutationKind ? { mutationKind: input.mutationKind } : {}) }); return this
  }
  edge(edge: CausalEdgeInput): this {
    const norm = normalizeEdgeRecord(edge, this.explicitEdges.length) as CausalEdgeInput
    if (norm.kind === 'state_transition_binding') {
      if (!norm.entityId?.trim()) throw new Error('state_transition_binding requires an explicit non-empty entityId (never auto-guessed).')
      if (!Array.isArray(norm.ablationExchangeIds) || !norm.ablationExchangeIds.some(id => typeof id === 'string' && id.trim())) throw new Error('state_transition_binding requires explicit ablationExchangeIds (never auto-guessed).')
    }
    this.explicitEdges.push(norm); return this
  }
  recordHop(hop: HopReceiptInput & { role?: 'setup' | 'control' | 'probe' | 'cleanup'; arm?: 'setup' | 'control' | 'probe' | 'cleanup' }): this {
    const { role, arm, ...cleanHop } = hop, target = normalizeHopTarget(cleanHop.target, cleanHop.method, this.ctx.targetOrigin || undefined) as HopTargetObject
    const receipt: HopReceiptInput = { ...cleanHop, surface: cleanHop.surface ?? 'http', target, ...(cleanHop.producedCapabilities ? { producedCapabilities: normCapList(cleanHop.producedCapabilities) as string[] } : {}), ...(cleanHop.consumedCapabilities ? { consumedCapabilities: normCapList(cleanHop.consumedCapabilities) as string[] } : {}) }
    for (const exId of receipt.exchangeIds ?? []) if (!this.exchangeToHop.has(exId)) this.exchangeToHop.set(exId, receipt.hopId)
    for (const cap of receipt.producedCapabilities ?? []) if (!this.capProducer.has(cap)) this.capProducer.set(cap, { hopId: receipt.hopId, exchangeId: receipt.exchangeIds?.[0] })
    this.hops.push({ receipt, isControlOnly: (role ?? arm) === 'control', capConsumeExchange: new Map(), cryptoConsumptions: [], asyncPolls: [] }); return this
  }
  async hop<T>(hopId: string, fn: () => Promise<T> | T): Promise<T>
  async hop<T>(hopId: string, meta: ChainHopOptions, fn: () => Promise<T> | T): Promise<T>
  async hop<T>(hopId: string, metaOrFn: ChainHopOptions | (() => Promise<T> | T), maybeFn?: () => Promise<T> | T): Promise<T> {
    const trimmedId = hopId.trim(); if (!trimmedId) throw new Error('chain.hop requires a non-empty hopId.')
    const meta: ChainHopOptions = typeof metaOrFn === 'function' ? {} : (metaOrFn ?? {}), fn = typeof metaOrFn === 'function' ? metaOrFn : maybeFn
    if (typeof fn !== 'function') throw new Error(`chain.hop("${trimmedId}") requires a callback function.`)
    const rec: HopRecorder = {
      hopId: trimmedId, exchangeIds: [...(meta.exchangeIds ?? [])], oobEventIds: [...(meta.oobEventIds ?? [])], browserTraceIds: [...(meta.browserTraceIds ?? [])],
      producedCapabilities: [...(normCapList(meta.producedCapabilities ?? []) as string[])], consumedCapabilities: [...(normCapList(meta.consumedCapabilities ?? []) as string[])], entityId: meta.entityId, correlationIds: [],
      controlExCount: 0, nonControlExCount: 0, capConsumeExchange: new Map(), cryptoConsumptions: [], asyncPolls: [],
      onProduce: (cap, exId) => { pushUnique(rec.producedCapabilities, cap); if (!this.capProducer.has(cap)) this.capProducer.set(cap, { hopId: trimmedId, ...(exId ? { exchangeId: exId } : {}) }) },
      onExchange: (exId, isControl) => { pushUnique(rec.exchangeIds, exId); if (!this.exchangeToHop.has(exId)) this.exchangeToHop.set(exId, trimmedId); if (isControl) rec.controlExCount++; else rec.nonControlExCount++ },
      onCorrelation: cid => { pushUnique(rec.correlationIds, cid); if (!this.correlationToHop.has(cid)) this.correlationToHop.set(cid, trimmedId) },
    }
    for (const exId of rec.exchangeIds) if (!this.exchangeToHop.has(exId)) this.exchangeToHop.set(exId, trimmedId)
    for (const cap of rec.producedCapabilities) if (!this.capProducer.has(cap)) this.capProducer.set(cap, { hopId: trimmedId, exchangeId: rec.exchangeIds[0] })
    this.ctx._pushHopRecorder(rec); let out: T; try { out = await fn() } finally { this.ctx._popHopRecorder(rec) }
    const resolvedTarget = meta.target !== undefined ? normalizeHopTarget(meta.target, meta.method, this.ctx.targetOrigin || undefined) as HopTargetObject : (rec.target ?? { origin: this.ctx.targetOrigin, method: meta.method ?? 'GET', pathAndQuery: '/' })
    const receipt: HopReceiptInput = {
      hopId: trimmedId, surface: meta.surface ?? 'http', target: resolvedTarget, exchangeIds: rec.exchangeIds,
      ...(rec.oobEventIds.length ? { oobEventIds: rec.oobEventIds } : {}), ...(rec.browserTraceIds.length ? { browserTraceIds: rec.browserTraceIds } : {}),
      claimedDelta: meta.claimedDelta?.trim() || `Hop ${trimmedId} executed.`,
      ...(rec.producedCapabilities.length ? { producedCapabilities: rec.producedCapabilities } : {}), ...(rec.consumedCapabilities.length ? { consumedCapabilities: rec.consumedCapabilities } : {}),
      ...(rec.entityId ? { entityId: rec.entityId } : {}), ...(meta.canaryToken ? { canaryToken: meta.canaryToken } : {}), ...(meta.proofReceipt ? { proofReceipt: meta.proofReceipt } : {}),
    }
    const isControlOnly = (meta.role ?? meta.arm) === 'control' || (rec.controlExCount > 0 && rec.nonControlExCount === 0 && !rec.producedCapabilities.length && !rec.consumedCapabilities.length && !rec.cryptoConsumptions.length && !rec.asyncPolls.length && !rec.oobEventIds.length && !rec.browserTraceIds.length)
    this.hops.push({ receipt, isControlOnly, capConsumeExchange: rec.capConsumeExchange, cryptoConsumptions: rec.cryptoConsumptions, asyncPolls: rec.asyncPolls }); return out
  }
  async raceBurst(hopId: string, opts: ChainRaceBurstOptions): Promise<RaceBurstHopResult> {
    const trimmedId = hopId.trim(); if (!trimmedId) throw new Error('chain.raceBurst requires a non-empty hopId.')
    const rawReqs = Array.isArray(opts.requests) && opts.requests.length > 0 ? opts.requests : opts.request !== undefined ? Array.from({ length: Math.max(2, Math.min(10, Math.floor(opts.count ?? opts.concurrency ?? 4))) }, () => opts.request!) : []
    if (rawReqs.length < 2 || rawReqs.length > 10) throw new Error('chain.raceBurst requires between 2 and 10 requests (or { request, count }).')
    if (opts.baseline) this.recordRefs(this.baselineReadbackIds, opts.baseline)
    let baseline: HttpExchange | undefined
    if (!opts.baseline && opts.readRoute) { baseline = await this.ctx._httpSendDetached(opts.readRoute, { method: opts.readMethod ?? 'GET', ...(opts.readPersona ? { as: opts.readPersona } : {}), role: 'control', arm: 'control', ...(opts.session ? { session: `${opts.session}-base` } : {}) }); pushUnique(this.baselineReadbackIds, baseline.exchangeId); this.exStatus.set(baseline.exchangeId, baseline.status) }
    const { hopId: _h, requests: _rq, request: _r, count: _c, concurrency: _cc, barrier, session, readRoute, readMethod, readPersona, baseline: _b, readback: _rb, correlationIds, ...hopMeta } = opts
    const burst = await this.hop(trimmedId, { ...hopMeta, claimedDelta: hopMeta.claimedDelta ?? `Concurrent race burst (${rawReqs.length} requests) on ${trimmedId}.` }, () =>
      this.ctx.race_burst(rawReqs, { ...(barrier ? { barrier } : {}), ...(session ? { session } : {}), ...(opts.entityId ? { entityId: opts.entityId } : {}), ...(correlationIds?.length ? { correlationIds } : {}) }),
    )
    this.lastRaceHopId = trimmedId; for (const ex of burst.results) pushUnique(this.raceActionIds, ex.exchangeId)
    if (opts.readback) this.recordRefs(this.readbackIds, opts.readback)
    let post: HttpExchange | undefined
    if (!opts.readback && readRoute) { post = await this.ctx._httpSendDetached(readRoute, { method: readMethod ?? 'GET', ...(readPersona ? { as: readPersona } : {}), role: 'control', arm: 'control', ...(session ? { session: `${session}-post` } : {}) }); pushUnique(this.readbackIds, post.exchangeId); this.exStatus.set(post.exchangeId, post.status) }
    return { ...burst, ...(baseline ? { baseline } : {}), ...(post ? { post } : {}) }
  }
  private synthOracleInput(family: OracleFamily, raw: Record<string, unknown> | undefined, activeHops: RecordedHop[], edges: CausalEdgeInput[], preControl: string[], postReadback: string[], termEx: string | undefined, explicitFamily = false): Record<string, unknown> | undefined {
    const oi: Record<string, unknown> = raw ? { ...raw } : {}
    const fill = (k: string, aliases: readonly string[], v: unknown): void => { if (v !== undefined && aliases.every(a => oi[a] === undefined)) oi[k] = v }
    const stOf = (id: string) => this.exStatus.get(id) ?? this.ctx._exStatusOf(id)
    const pickOk = (ids: string[]) => { const r = [...ids].reverse(); return r.find(id => { const s = stOf(id); return s !== undefined && s >= 200 && s < 300 }) ?? r.find(id => stOf(id) === undefined) }
    const deniedCtrl = preControl.find(id => { const s = stOf(id); return s === 401 || s === 403 || s === 404 })
    const firstEx = activeHops[0]?.receipt.exchangeIds?.[0], prevEx = activeHops[activeHops.length - 2]?.receipt.exchangeIds?.[0] ?? firstEx, ctrl = deniedCtrl ?? preControl[0], rb = postReadback[0]
    if (family === 'economic_conservation') {
      fill('baselineReadbackExchangeId', ['baselineReadback', 'baselineReadbackExchangeId', 'baselineExchangeId'], pickOk(this.baselineReadbackIds) ?? pickOk(preControl))
      fill('finalReadbackExchangeId', ['finalReadback', 'finalReadbackExchangeId', 'finalExchangeId'], pickOk(postReadback))
      const acts = this.raceActionIds.length > 0 ? [...this.raceActionIds] : activeHops.flatMap(h => h.receipt.exchangeIds ?? []).filter(id => !preControl.includes(id) && !postReadback.includes(id))
      if (acts.length > 0) fill('actionExchangeIds', ['actions', 'actionExchangeIds', 'actionsExchangeIds'], acts)
    } else if (family === 'cryptographic_scope_replay') {
      fill('tamperedSignatureControlExchangeId', ['tamperedSignatureControl', 'tamperedSignatureControlExchangeId', 'tamperedControlExchangeId'], ctrl)
      if (activeHops.length >= 2 && firstEx && firstEx !== termEx) fill('sourceValidIssuanceExchangeId', ['sourceValidIssuance', 'sourceValidIssuanceExchangeId', 'sourceIssuanceExchangeId'], firstEx)
      fill('replayedAcceptanceExchangeId', ['replayedAcceptance', 'replayedAcceptanceExchangeId', 'replayedExchangeId'], termEx)
    } else if (family === 'temporal_revocation' && (activeHops.length >= 4 || (activeHops.length >= 3 && ctrl))) {
      fill('preRevocationBaselineExchangeId', ['preRevocationBaseline', 'preRevocationBaselineExchangeId'], firstEx)
      fill('revocationEventExchangeId', ['revocationEvent', 'revocationEventExchangeId'], activeHops[1]?.receipt.exchangeIds?.[0])
      fill('primaryDeniedCheckExchangeId', ['primaryDeniedCheck', 'primaryDeniedCheckExchangeId'], ctrl ?? activeHops[2]?.receipt.exchangeIds?.[0])
      fill('secondarySuccessExchangeId', ['secondarySuccess', 'secondarySuccessExchangeId'], termEx)
    } else if (family === 'parser_cache_differential') {
      fill('cleanControlExchangeId', ['cleanControl', 'cleanControlExchangeId'], ctrl)
      const isCache = oi.mode === 'cache_primed' || ['cacheKey', 'victimOrPrimeRequest', 'victimOrPrimeRequestExchangeId', 'victimPrimeExchangeId', 'attackerProbe', 'attackerProbeExchangeId'].some(k => oi[k] !== undefined)
      if (isCache) { if (activeHops.length >= 2 && firstEx && firstEx !== termEx) fill('victimOrPrimeRequestExchangeId', ['victimOrPrimeRequest', 'victimOrPrimeRequestExchangeId', 'victimPrimeExchangeId'], firstEx); fill('attackerProbeExchangeId', ['attackerProbe', 'attackerProbeExchangeId'], termEx) }
      else { fill('differentialProbeExchangeId', ['differentialProbe', 'differentialProbeExchangeId'], termEx); fill('postMutationReadbackExchangeId', ['postMutationReadback', 'postMutationReadbackExchangeId'], rb) }
    } else if (family === 'dual_tenant_abac') {
      const hasAny = (...ks: string[]) => ks.some(k => oi[k] !== undefined), rbOk = postReadback.find(id => { const s = stOf(id); return s !== undefined && s >= 200 && s < 300 })
      const eid = (typeof oi.entityId === 'string' && oi.entityId.trim()) || activeHops.map(h => h.receipt.entityId?.trim()).find(Boolean)
      const xferHop = [...activeHops].reverse().find(h => { const m = typeof h.receipt.target === 'object' ? h.receipt.target.method : ''; return Boolean(m && !/^(?:GET|HEAD|OPTIONS)$/i.test(m)) })
      if (oi.mode === undefined) {
        if (hasAny('transferRecord', 'transferRecordExchangeId', 'transferExchangeId', 'postTransferReadback', 'postTransferReadbackExchangeId', 'sourceControlDenied', 'sourceControlDeniedExchangeId', 'sourceControlExchangeId', 'sourceTenantId', 'destTenantId', 'observedOwnerTenantId', 'entityId')) oi.mode = 'cross_org_transfer'
        else if (hasAny('singleForeignControlDenied', 'singleForeignControlDeniedExchangeId', 'singleForeignControlExchangeId', 'batchRequest', 'batchRequestExchangeId', 'ownRecordId', 'foreignRecordId', 'requestedIds')) oi.mode = 'batch_partial_authz'
        else if (hasAny('baselineDeniedControl', 'baselineDeniedControlExchangeId', 'baselineControlExchangeId', 'primeAction', 'primeActionExchangeId', 'bledAccess', 'bledAccessExchangeId', 'primeTenantId', 'targetTenantId', 'observedTenantId', 'isolatedControl')) oi.mode = 'dual_org_cache_bleed'
        else if (!raw && deniedCtrl && termEx) { const m = rbOk && eid && xferHop ? 'cross_org_transfer' : ((explicitFamily || edges.length === 0) && activeHops.length >= 2 && prevEx && prevEx !== termEx ? 'dual_org_cache_bleed' : ''); if (m) oi.mode = m }
      }
      if (oi.mode === 'dual_org_cache_bleed') { fill('baselineDeniedControlExchangeId', ['baselineDeniedControl', 'baselineDeniedControlExchangeId', 'baselineControlExchangeId'], ctrl); if (activeHops.length >= 2 && prevEx && prevEx !== termEx) fill('primeActionExchangeId', ['primeAction', 'primeActionExchangeId'], prevEx); fill('bledAccessExchangeId', ['bledAccess', 'bledAccessExchangeId'], termEx) }
      else if (oi.mode === 'cross_org_transfer') { fill('sourceControlDeniedExchangeId', ['sourceControlDenied', 'sourceControlDeniedExchangeId', 'sourceControlExchangeId'], ctrl); fill('transferRecordExchangeId', ['transferRecord', 'transferRecordExchangeId', 'transferExchangeId'], xferHop?.receipt.exchangeIds?.[0] ?? termEx); fill('postTransferReadbackExchangeId', ['postTransferReadback', 'postTransferReadbackExchangeId'], rbOk ?? rb); if (eid) fill('entityId', ['entityId'], eid) }
      else if (oi.mode === 'batch_partial_authz') { fill('singleForeignControlDeniedExchangeId', ['singleForeignControlDenied', 'singleForeignControlDeniedExchangeId', 'singleForeignControlExchangeId'], ctrl); fill('batchRequestExchangeId', ['batchRequest', 'batchRequestExchangeId'], termEx); fill('postMutationReadbackExchangeId', ['postMutationReadback', 'postMutationReadbackExchangeId'], rbOk ?? rb) }
    } else if (family === 'cross_surface_pivot') {
      fill('preChainControlDenied', ['preChainControlDenied', 'preChainControlDeniedExchangeId', 'preChainControlExchangeId'], ctrl)
      if (oi.hops === undefined && activeHops.length >= 2) oi.hops = activeHops.map((h, i) => { const inE = edges.find(e => e.toHopId === h.receipt.hopId); return { surface: h.receipt.surface ?? 'http', role: i === activeHops.length - 1 ? 'terminal_impact' : h.receipt.surface === 'browser' ? 'browser_dom_trace' : h.receipt.surface === 'webhook' ? 'oob_callback' : 'trigger_write', record: i === activeHops.length - 1 ? (termEx ?? h.receipt.exchangeIds?.[0]) : h.receipt.exchangeIds?.[0], ...(inE ? { bindingKind: inE.kind } : {}) } })
      fill('terminalImpact', ['terminalImpact'], { kind: rb ? 'privileged_mutation' : 'privileged_read', ...(rb ? { postImpactReadback: rb } : {}) })
    }
    return Object.keys(oi).length > 0 ? oi : undefined
  }
  build(opts: ChainProveOptions = {}, pruneDangling = Boolean(opts.terminalHopId)): CompositeProofReceiptInput {
    if (this.hops.length === 0) throw new Error(`ChainBuilder "${this.chainId}" has no recorded hops.`)
    const hopIdx = new Map(this.hops.map((h, i) => [h.receipt.hopId, i])), edges: CausalEdgeInput[] = [], seenEdges = new Set<string>()
    const resHop = (id: string | undefined): string | undefined => { const t = id?.trim(); return !t ? undefined : (!hopIdx.has(t) && t.toLowerCase() === 'race' && this.lastRaceHopId && hopIdx.has(this.lastRaceHopId) ? this.lastRaceHopId : t) }
    const addEdge = (edge: CausalEdgeInput): void => { const f = resHop(edge.fromHopId) ?? edge.fromHopId, t = resHop(edge.toHopId) ?? edge.toHopId, fi = hopIdx.get(f) ?? -1, ti = hopIdx.get(t) ?? -1; if (fi < 0 || fi >= ti) return; const key = `${f}->${t}:${edge.kind}`; if (!seenEdges.has(key)) { seenEdges.add(key); edges.push(f === edge.fromHopId && t === edge.toHopId ? edge : { ...edge, fromHopId: f, toHopId: t }) } }
    for (const explicit of this.explicitEdges) addEdge(explicit)
    const resolveProducer = (cap: string): { hopId: string; exchangeId?: string } | undefined => {
      const direct = this.capProducer.get(cap); if (direct) return direct
      const srcEx = this.ctx._capOriginOf(cap), hopId = srcEx ? this.exchangeToHop.get(srcEx) : undefined; if (!hopId) return undefined
      const prodHop = this.hops.find(h => h.receipt.hopId === hopId)?.receipt; if (prodHop) { prodHop.producedCapabilities ??= []; pushUnique(prodHop.producedCapabilities, cap) }
      const resolved = { hopId, ...(srcEx ? { exchangeId: srcEx } : {}) }; if (!this.capProducer.has(cap)) this.capProducer.set(cap, resolved); return resolved
    }
    for (const hop of this.hops) {
      const toHopId = hop.receipt.hopId, cryptoBound = new Set<string>()
      for (const c of hop.cryptoConsumptions) {
        const prod = resolveProducer(c.sourceCapabilityId); if (!prod || prod.hopId === toHopId) continue; cryptoBound.add(c.sourceCapabilityId)
        addEdge({ kind: 'derived_crypto_binding', fromHopId: prod.hopId, toHopId, sourceCapabilityId: c.sourceCapabilityId, ...(c.derivedCapabilityId && /^cap:/.test(c.derivedCapabilityId) ? { derivedCapabilityId: c.derivedCapabilityId } : {}), ...(c.alg ? { alg: c.alg } : {}) })
      }
      for (const cap of hop.receipt.consumedCapabilities ?? []) {
        if (cryptoBound.has(cap) && !hop.capConsumeExchange.has(cap)) continue
        const prod = resolveProducer(cap); if (!prod || prod.hopId === toHopId) continue
        const targetExchangeId = hop.capConsumeExchange.get(cap)
        addEdge({ kind: 'value_binding', fromHopId: prod.hopId, toHopId, capabilityHandle: cap, ...(prod.exchangeId ? { sourceExchangeId: prod.exchangeId } : {}), ...(targetExchangeId ? { targetExchangeId } : {}) })
      }
      for (const poll of hop.asyncPolls) {
        const fromHopId = (poll.triggerExchangeId ? this.exchangeToHop.get(poll.triggerExchangeId) : undefined) ?? (poll.correlationId ? this.correlationToHop.get(poll.correlationId) : undefined)
        if (fromHopId && fromHopId !== toHopId && poll.correlationId) addEdge({ kind: 'async_pivot_binding', fromHopId, toHopId, correlationId: poll.correlationId, channel: 'poll_convergence', ...(poll.pollRecordId ? { pollRecordId: poll.pollRecordId } : {}) })
      }
    }
    const linkedHops = new Set<string>(edges.flatMap(e => [e.fromHopId, e.toHopId])), resolvedTermHopId = resHop(opts.terminalHopId)
    const controlOnlyHops = this.hops.filter(h => h.isControlOnly && !linkedHops.has(h.receipt.hopId) && h.receipt.hopId !== resolvedTermHopId)
    const keptHops = controlOnlyHops.length < this.hops.length ? this.hops.filter(h => !controlOnlyHops.includes(h)) : this.hops
    const demotedCtrlIds = keptHops.length < this.hops.length ? controlOnlyHops.flatMap(h => h.receipt.exchangeIds ?? []) : []
    const lastHop = keptHops[keptHops.length - 1]!.receipt, finalTermHopId = resolvedTermHopId ?? lastHop.hopId
    const reach = new Set<string>([finalTermHopId]), q = [finalTermHopId]
    for (let i = 0; i < q.length; i++) for (const e of edges) if (e.toHopId === q[i] && !reach.has(e.fromHopId)) { reach.add(e.fromHopId); q.push(e.fromHopId) }
    const pruned = pruneDangling && reach.size >= 2 && reach.size < keptHops.length
    const activeHops = pruned ? keptHops.filter(h => reach.has(h.receipt.hopId)) : keptHops, finalEdges = pruned ? edges.filter(e => reach.has(e.fromHopId) && reach.has(e.toHopId)) : edges
    const termHop = (resolvedTermHopId ? activeHops.find(h => h.receipt.hopId === resolvedTermHopId)?.receipt : undefined) ?? activeHops[activeHops.length - 1]!.receipt, preControl: string[] = [], postReadback: string[] = []
    for (const id of [...this.controlIds, ...this.baselineReadbackIds, ...demotedCtrlIds]) pushUnique(preControl, id)
    this.recordRefs(preControl, opts.control); this.recordRefs(preControl, opts.controlExchanges); for (const id of opts.preChainControlExchangeIds ?? []) pushUnique(preControl, id)
    for (const id of this.readbackIds) pushUnique(postReadback, id); this.recordRefs(postReadback, opts.readback); for (const id of opts.postChainReadbackExchangeIds ?? []) pushUnique(postReadback, id)
    const terminalExchangeId = opts.terminalExchangeId ?? extractExchangeIds(opts.terminalExchange)[0], modeAFailureExchangeId = opts.modeAFailureExchangeId ?? extractExchangeIds(opts.modeAFailureExchange)[0]
    const lastExIds = termHop.exchangeIds ?? [], resolvedTermEx = terminalExchangeId ?? lastExIds[lastExIds.length - 1], normCls = this.terminalVulnClass
    const effFamily: OracleFamily | undefined = opts.oracleFamily ?? (/^(?:economic_conservation|conserved_balance|ledger_overcredit|over_refund|double_spend|race_condition)$/.test(normCls) ? 'economic_conservation' : /^(?:dual_tenant_abac|cross_tenant_(?:export|read|write|idor))$/.test(normCls) ? 'dual_tenant_abac' : /^(?:parser_cache_differential|cache_bleed|cache_poisoning|cache_deception|web_cache_deception|web_cache_poisoning|path_confusion|request_smuggling)$/.test(normCls) ? 'parser_cache_differential' : undefined)
    const oracleInput = effFamily ? this.synthOracleInput(effFamily, opts.oracleInput, activeHops, finalEdges, preControl, postReadback, resolvedTermEx, Boolean(opts.oracleFamily) || normCls === 'dual_tenant_abac') : (opts.oracleInput ? { ...opts.oracleInput } : undefined)
    return {
      chainId: this.chainId, terminalVulnClass: this.terminalVulnClass, replayMode: opts.replayMode ?? this.replayMode,
      ...(opts.benchmarkMode ?? this.benchmarkMode !== undefined ? { benchmarkMode: opts.benchmarkMode ?? this.benchmarkMode } : {}),
      hops: activeHops.map(h => h.receipt), causalEdges: finalEdges,
      terminalImpact: {
        terminalHopId: finalTermHopId, claimedImpact: opts.claimedImpact ?? opts.summary ?? termHop.claimedDelta,
        ...(terminalExchangeId ? { terminalExchangeId } : {}), ...(preControl.length ? { preChainControlExchangeIds: preControl } : {}),
        ...(postReadback.length ? { postChainReadbackExchangeIds: postReadback } : {}), ...(modeAFailureExchangeId ? { modeAFailureExchangeId } : {}),
        ...(opts.oracleFamily ? { oracleFamily: opts.oracleFamily } : {}), ...(oracleInput ? { oracleInput } : {}), ...(opts.proofReceipt ? { proofReceipt: opts.proofReceipt } : {}),
      },
    }
  }
  prove(opts: ChainProveOptions = {}): Promise<CompositeVerificationResult> { return this.ctx.prove_composite(this.build(opts, true)) }
}
export class VerifyContext {
  readonly nonce: string; readonly runId: string; readonly targetOrigins: string[]; readonly targetOrigin: string; readonly sdkVersion: string
  readonly claims: VerifyClaim[] = []; readonly expect: Expectations; readonly assert: Expectations
  private readonly defaultOrigin: string | undefined; private readonly transport: RpcTransport
  private _lastRpcOp: string | null = null; private _lastFailedClaims: VerifyClaim[] = []
  private readonly _hopStack: HopRecorder[] = []; private readonly _capOrigins = new Map<string, string>(); private readonly _exMeta = new Map<string, ExSealDiag>()

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
  /** @internal */ _exStatusOf(id: string): number | undefined { return this._exMeta.get(id)?.status }
  private activeHop(): HopRecorder | undefined { return this._hopStack[this._hopStack.length - 1] }
  private recordExCaps(hop: HopRecorder, ex: HttpExchange, explicitCap?: unknown): void {
    for (const c of [resolveCapHandle(explicitCap), ex.consumedCapabilityId, ...(ex.consumedCapabilities ?? [])]) if (typeof c === 'string' && c.trim()) { pushUnique(hop.consumedCapabilities, c); hop.capConsumeExchange.set(c, ex.exchangeId) }
    for (const src of ex.derivedFromCapabilityIds ?? []) if (src && !hop.cryptoConsumptions.some(c => c.sourceCapabilityId === src)) { pushUnique(hop.consumedCapabilities, src); hop.cryptoConsumptions.push({ sourceCapabilityId: src }) }
  }
  private callRpc(op: string, args: Record<string, unknown>, timeoutMs = 60_000): Promise<unknown> { this._lastRpcOp = op; return sendRpc(this.transport, op, args, timeoutMs) }
  hello(sdkVersion: string = KOVO_VERIFY_SDK_VERSION): Promise<{ sdkVersion: string; nonce: string; runId: string }> { return this.callRpc('hello', { sdkVersion }) as Promise<{ sdkVersion: string; nonce: string; runId: string }> }

  chain(opts: ChainBuilderOptions): ChainBuilder
  chain(chainId: string, terminalVulnClass: string, opts?: Omit<ChainBuilderOptions, 'chainId' | 'terminalVulnClass'>): ChainBuilder
  chain(optsOrId: ChainBuilderOptions | string, terminalVulnClass?: string, extra?: Omit<ChainBuilderOptions, 'chainId' | 'terminalVulnClass'>): ChainBuilder {
    return new ChainBuilder(this, typeof optsOrId === 'string' ? { chainId: optsOrId, terminalVulnClass: terminalVulnClass ?? '', ...(extra ?? {}) } : optsOrId)
  }

  private buildHttpRpcArgs(input: HttpTarget, options: HttpOptions = {}): { args: Record<string, unknown>; timeoutMs: number } {
    const target = splitTarget(input, this.defaultOrigin), merged: HttpOptions = { ...extractInlineHttpOptions(input), ...options }
    const rawBody = merged.body !== undefined ? merged.body : (merged.jsonBody !== undefined ? merged.jsonBody : merged.textBody)
    const { body, headers } = normalizeBodyAndHeaders(rawBody, merged.headers), persona = merged.as ?? merged.persona, capability = normalizeCapabilityInjection(merged.capability)
    const arm = merged.arm ?? (merged.role === 'control' || merged.isControl === true || merged.control === true ? 'control' : undefined), sessionGroupRole = merged.role ?? arm
    return { args: { ...(target.origin ? { origin: target.origin } : {}), path: target.path, method: (merged.method ?? target.method ?? 'GET').toUpperCase(), ...(headers ? { headers } : {}), ...(body !== undefined ? { body } : {}), ...(persona ? { persona } : {}), ...(sessionGroupRole ? { sessionGroupRole } : {}), ...(arm ? { arm } : {}), ...(capability !== undefined && capability !== '' ? { capability } : {}), ...pickDefined(merged as Record<string, unknown>, ['session', 'followRedirects', 'capabilityTarget', 'capabilityHeaderName', 'capabilityCookieName', 'capabilityQueryParam', 'authMutation', 'entityId', 'evidenceRole', 'replayAttempt']), ...(merged.correlationIds?.length ? { correlationIds: merged.correlationIds } : {}) }, timeoutMs: (merged.timeoutMs ?? 60_000) + 10_000 }
  }

  private extractExDiag(raw: { status?: unknown; mediaType?: unknown; headers?: unknown; json?: unknown; body?: unknown }): ExSealDiag {
    const status = typeof raw.status === 'number' ? raw.status : 0, sanitizeKey = (k: string): string => k.replace(/[^\w.-]/g, '').slice(0, 32)
    const keysOf = (v: unknown): string[] => { if (!v || typeof v !== 'object') return []; const src = Array.isArray(v) ? (v[0] && typeof v[0] === 'object' && !Array.isArray(v[0]) ? Object.keys(v[0] as Record<string, unknown>).map(k => `[0].${k}`) : ['<array>']) : Object.keys(v as Record<string, unknown>); const out = src.slice(0, 12).map(sanitizeKey).filter(k => Boolean(k) && !/redacted/i.test(k)); if (src.length > 12) out.push('...'); return out }
    let isJson = false, parsedJson: unknown = null
    if (raw.json !== undefined && raw.json !== null) { isJson = true; parsedJson = raw.json } else if (typeof raw.body === 'string') { const c = raw.body.replace(/^\uFEFF/, '').trim(); if (c) try { parsedJson = JSON.parse(c); isJson = true } catch { isJson = false } }
    const hdrs: Record<string, string> = {}; if (raw.headers && typeof raw.headers === 'object' && !Array.isArray(raw.headers)) for (const [k, v] of Object.entries(raw.headers as Record<string, unknown>)) if (typeof v === 'string') hdrs[k.toLowerCase()] = v
    const mediaType = (hdrs['content-type'] ?? (typeof raw.mediaType === 'string' ? raw.mediaType : '')).split(';')[0]!.trim().replace(/[^\w./+-]/g, '').slice(0, 64), loc = (hdrs.location ?? '').trim(), locParams: string[] = []
    if (loc) try { const u = new URL(loc, 'http://kovo-local.invalid'); for (const k of u.searchParams.keys()) pushUnique(locParams, sanitizeKey(k)); if (u.hash.length > 1) for (const k of new URLSearchParams(u.hash.slice(1)).keys()) pushUnique(locParams, sanitizeKey(k)) } catch { /* ignore */ }
    return { status, mediaType, isJson, parsedJson, topKeys: isJson ? keysOf(parsedJson) : [], headerNames: Object.keys(hdrs).slice(0, 16), hasLocation: loc.length > 0, locationParamNames: locParams.slice(0, 12), hasSetCookie: 'set-cookie' in hdrs }
  }
  private resolveVisibleJsonPath(root: unknown, rawPath: string): { found: boolean; value?: unknown } {
    let s = rawPath.trim(); if (s.startsWith('$')) s = s.slice(1); if (s.startsWith('.')) s = s.slice(1); if (!s) return { found: true, value: root }
    const segs: string[] = []
    for (let i = 0; i < s.length;) {
      if (s[i] === '.') { i++; continue }
      if (s[i] === '[') { const close = s.indexOf(']', i + 1); if (close < 0) return { found: false }; let inner = s.slice(i + 1, close).trim(); if ((inner.startsWith("'") && inner.endsWith("'")) || (inner.startsWith('"') && inner.endsWith('"'))) inner = inner.slice(1, -1); segs.push(inner); i = close + 1 }
      else { let j = i; while (j < s.length && s[j] !== '.' && s[j] !== '[') j++; segs.push(s.slice(i, j)); i = j }
    }
    let cur: unknown = root
    for (const seg of segs) { if (cur === null || cur === undefined || typeof cur !== 'object') return { found: false }; if (Array.isArray(cur)) { if (!/^\d+$/.test(seg)) return { found: false }; const idx = Number(seg); if (idx < 0 || idx >= cur.length) return { found: false }; cur = cur[idx] } else if (Object.prototype.hasOwnProperty.call(cur, seg)) cur = (cur as Record<string, unknown>)[seg]; else return { found: false } }
    return { found: true, value: cur }
  }
  private diagnoseSealFailure(msg: string, raw: Record<string, unknown>, diag: ExSealDiag | undefined): string {
    const str = (v: unknown): string => typeof v === 'string' && v.trim() ? v.trim() : '', jp = str(raw.jsonPath), lq = str(raw.locationQuery) || str(raw.queryParam), hdr = str(raw.header), ck = str(raw.setCookie) || str(raw.cookie), hasVal = (typeof raw.value === 'string' && raw.value.length > 0) || (typeof raw.rawValue === 'string' && raw.rawValue.length > 0)
    const cleanKeys = (o: Record<string, unknown>) => Object.keys(o).slice(0, 12).map(k => k.replace(/[^\w.-]/g, '').slice(0, 32)).filter(k => Boolean(k) && !/redacted/i.test(k))
    if (jp && diag) {
      if (!diag.isJson) return `capability.seal: jsonPath "${jp}" requested on non-JSON response (HTTP ${diag.status}, content-type: ${diag.mediaType || 'unknown'}). Verify response status/content-type or use header/setCookie/locationQuery selector.`
      const hit = this.resolveVisibleJsonPath(diag.parsedJson, jp)
      if (hit.found && hit.value !== null && typeof hit.value === 'object') { if (Array.isArray(hit.value)) { const k0 = hit.value[0] && typeof hit.value[0] === 'object' && !Array.isArray(hit.value[0]) ? cleanKeys(hit.value[0] as Record<string, unknown>) : []; return `capability.seal: jsonPath "${jp}" resolved to array (length=${hit.value.length}${k0.length ? `, [0] subkeys=[${k0.join(', ')}]` : ''}), not a scalar string/number — select a leaf element/field. [status=${diag.status}]` } return `capability.seal: jsonPath "${jp}" resolved to object (subkeys=[${cleanKeys(hit.value as Record<string, unknown>).join(', ')}]), not a scalar string/number — select a leaf field. [status=${diag.status}]` }
      if (hit.found && hit.value !== null && hit.value !== undefined) return `capability.seal: jsonPath "${jp}" extracted value too short (<6 chars) or low entropy; seal an opaque token/id/signature instead [status=${diag.status}]`
      return `${msg} [status=${diag.status}, topKeys=[${diag.topKeys.join(', ')}]]`
    }
    if (lq && diag) return !diag.hasLocation ? `capability.seal: locationQuery "${lq}" requested on HTTP ${diag.status} response with no Location header. Pass followRedirects: false to capture Location header.` : diag.locationParamNames.includes(lq) ? `capability.seal: locationQuery "${lq}" extracted value too short (<6 chars) or low entropy; seal an opaque token/id/signature instead [status=${diag.status}]` : `capability.seal: locationQuery "${lq}" not found in Location header (HTTP ${diag.status}, available params=[${diag.locationParamNames.join(', ')}]).`
    if (hdr && diag) return !diag.headerNames.includes(hdr.toLowerCase()) ? `capability.seal: header "${hdr}" not present on HTTP ${diag.status} response (available headers=[${diag.headerNames.join(', ')}]).` : `capability.seal: header "${hdr}" extracted value too short (<6 chars) or low entropy; seal an opaque token/id/signature instead [status=${diag.status}]`
    if (ck && diag) return !diag.hasSetCookie ? `capability.seal: setCookie "${ck}" requested on HTTP ${diag.status} response with no Set-Cookie header.` : `capability.seal: setCookie "${ck}" not found in Set-Cookie or extracted value too short (<6 chars) or low entropy; seal an opaque token/id/signature instead [status=${diag.status}]`
    if (hasVal) return `capability.seal: value selector not found in host-visible/unredacted transcript (or failed min-length/entropy validation). Use jsonPath / header / setCookie / locationQuery selector on the exchange that minted the value.${diag ? ` [status=${diag.status}, topKeys=[${diag.topKeys.join(', ')}]]` : ''}`
    return diag ? `${msg} [status=${diag.status}, topKeys=[${diag.topKeys.join(', ')}]]` : msg
  }
  private rememberEx(ex: HttpExchange | null | undefined): void { if (!ex?.exchangeId) return; if (this._exMeta.size >= 256) { const first = this._exMeta.keys().next().value; if (first) this._exMeta.delete(first) } this._exMeta.set(ex.exchangeId, this.extractExDiag(ex)) }
  private async sendHttp(op: 'http' | 'http.send', input: HttpTarget, options: HttpOptions = {}, recordHop = true): Promise<HttpExchange> {
    const { args, timeoutMs } = this.buildHttpRpcArgs(input, options), ex = hydrateExchange(await this.callRpc(op, args, timeoutMs) as HttpExchange); this.rememberEx(ex)
    const hop = recordHop ? this.activeHop() : undefined
    if (hop) {
      hop.onExchange(ex.exchangeId, args.sessionGroupRole === 'control' || args.arm === 'control')
      if (!hop.target) hop.target = { origin: typeof args.origin === 'string' ? args.origin : this.targetOrigin, method: typeof args.method === 'string' ? args.method : ex.method, pathAndQuery: ex.pathAndQuery || (typeof args.path === 'string' ? args.path : '/') }
      this.recordExCaps(hop, ex, args.capability); if (!hop.entityId && typeof args.entityId === 'string' && args.entityId.trim()) hop.entityId = args.entityId.trim()
      if (Array.isArray(args.correlationIds)) for (const cid of args.correlationIds) if (typeof cid === 'string') hop.onCorrelation(cid)
    }
    return ex
  }
  /** @internal */ _httpSendDetached(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> { return this.sendHttp('http.send', input, options, false) }
  http(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> { return this.sendHttp('http', input, options) }
  http_send(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> { return this.sendHttp('http.send', input, options) }
  request(input: HttpTarget, options: HttpOptions = {}): Promise<HttpExchange> { return this.sendHttp('http.send', input, options) }

  async race_burst(requests: Array<RaceRequestInput | HttpTarget>, opts: { barrier?: 'auto' | 'h2' | 'http1'; session?: string; entityId?: string; correlationIds?: string[] } = {}): Promise<RaceBurstHopResult> {
    if (!Array.isArray(requests) || requests.length < 2 || requests.length > 10) throw new Error('race_burst requires between 2 and 10 requests.')
    const built = requests.map((req, i) => this.buildHttpRpcArgs(req as HttpTarget, { role: 'probe', session: opts.session ? `${opts.session}-${i}` : `race-${i}`, ...(opts.entityId ? { entityId: opts.entityId } : {}), ...(opts.correlationIds?.length ? { correlationIds: opts.correlationIds } : {}) }))
    const raw = await this.callRpc('race.burst', { requests: built.map(b => b.args), ...(opts.barrier ? { barrier: opts.barrier } : {}) }, Math.max(40_000, built[0]!.timeoutMs)) as { mode?: 'h2-single-packet' | 'http1-fallback'; fallbackReason?: string | null; raceBatchId?: string; summary?: Record<string, unknown>; results?: HttpExchange[] }
    const raceBatchId = raw.raceBatchId ?? '', results = (raw.results ?? []).map(r => { const ex = hydrateExchange({ ...r, ...(raceBatchId && !r.raceBatchId ? { raceBatchId } : {}) }); this.rememberEx(ex); return ex })
    const hop = this.activeHop()
    if (hop) {
      results.forEach((ex, i) => { hop.onExchange(ex.exchangeId); this.recordExCaps(hop, ex, built[i]?.args.capability) })
      if (!hop.target && built[0]) hop.target = { origin: typeof built[0].args.origin === 'string' ? built[0].args.origin : this.targetOrigin, method: typeof built[0].args.method === 'string' ? built[0].args.method : 'POST', pathAndQuery: results[0]?.pathAndQuery || (typeof built[0].args.path === 'string' ? built[0].args.path : '/') }
      if (!hop.entityId && opts.entityId?.trim()) hop.entityId = opts.entityId.trim(); if (opts.correlationIds) for (const cid of opts.correlationIds) hop.onCorrelation(cid)
    }
    return { mode: raw.mode ?? 'http1-fallback', fallbackReason: raw.fallbackReason ?? null, raceBatchId, summary: raw.summary ?? {}, results, exchanges: results }
  }
  raceBurst(requests: Array<RaceRequestInput | HttpTarget>, opts?: { barrier?: 'auto' | 'h2' | 'http1'; session?: string; entityId?: string; correlationIds?: string[] }): Promise<RaceBurstHopResult> { return this.race_burst(requests, opts) }
  async seal_capability(input: SealCapabilityInput): Promise<SealedCapabilityResult> {
    const raw = (input && typeof input === 'object' ? input : {}) as unknown as Record<string, unknown>, exchangeId = extractExchangeIds((raw.exchangeId ?? raw.exchange ?? raw.exchange_id ?? raw.sourceExchangeId ?? raw.response) as ExchangeRef | undefined)[0]
    if (!exchangeId) throw new Error('seal_capability requires exchangeId (string) or exchange ({ exchangeId }).')
    const activeHop = this.activeHop(), hopReceiptId = (typeof raw.hopReceiptId === 'string' && raw.hopReceiptId.trim()) ? raw.hopReceiptId.trim() : (typeof raw.hopId === 'string' && raw.hopId.trim()) ? raw.hopId.trim() : activeHop?.hopId
    const cookieSel = typeof raw.cookie === 'string' && raw.cookie.trim() ? raw.cookie : typeof raw.setCookie === 'string' && raw.setCookie.trim() ? raw.setCookie : undefined
    const jsonPathSel = typeof raw.jsonPath === 'string' && raw.jsonPath.trim() ? raw.jsonPath : typeof raw.path === 'string' && raw.path.trim() ? raw.path : undefined
    let res: SealedCapabilityResult
    try {
      res = await this.callRpc('capability.seal', { exchangeId, slot: input.slot, ...(hopReceiptId ? { hopReceiptId } : {}), ...(cookieSel ? { cookie: cookieSel } : {}), ...(jsonPathSel ? { jsonPath: jsonPathSel } : {}), ...pickDefined(raw, ['header', 'setCookie', 'locationQuery', 'queryParam', 'regex', 'kind', 'defaultHeaderName', 'defaultCookieName']), ...(input.value !== undefined ? { value: input.value } : {}), ...(input.ttlMs !== undefined ? { ttlMs: input.ttlMs } : {}), ...(input.allowedOrigins?.length ? { allowedOrigins: input.allowedOrigins } : {}) }, 30_000) as SealedCapabilityResult
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      if (/structured field not found/i.test(msg)) throw new Error(this.diagnoseSealFailure(msg, raw, this._exMeta.get(exchangeId) ?? (raw.exchange && typeof raw.exchange === 'object' ? this.extractExDiag(raw.exchange as Record<string, unknown>) : undefined)))
      throw err
    }
    const srcEx = res.exchangeId || exchangeId; if (res.handle && srcEx && !this._capOrigins.has(res.handle)) this._capOrigins.set(res.handle, srcEx); activeHop?.onProduce(res.handle, srcEx); return res
  }
  sealCapability(input: SealCapabilityInput): Promise<SealedCapabilityResult> { return this.seal_capability(input) }
  private recordCrypto(secretHandle: string, exchangeId: string | undefined, derivedHandle: string, alg?: string): void {
    const hop = this.activeHop(); if (!hop) return; if (exchangeId) hop.onExchange(exchangeId)
    if (secretHandle) { pushUnique(hop.consumedCapabilities, secretHandle); hop.cryptoConsumptions.push({ sourceCapabilityId: secretHandle, derivedCapabilityId: derivedHandle, alg }) }
    if (/^cap:/.test(derivedHandle)) hop.onProduce(derivedHandle, exchangeId)
  }
  async hmac_sign(inputOrSecret: HmacSignInput | Record<string, unknown> | string, payloadArg?: string | Record<string, unknown> | unknown[], opts?: { alg?: string; encoding?: string } | string, encodingArg?: string): Promise<HmacSignResult> {
    const isPos = typeof inputOrSecret === 'string' || (payloadArg !== undefined && inputOrSecret && typeof inputOrSecret === 'object' && !('secretHandle' in inputOrSecret))
    const r = !isPos && inputOrSecret && typeof inputOrSecret === 'object' ? (inputOrSecret as Partial<HmacSignInput>) : {}, posOpts = isPos ? (typeof opts === 'string' ? { alg: opts } : (opts ?? {})) : {}
    const secretHandle = resolveCapHandle(isPos ? inputOrSecret : (r.secretHandle ?? '')), alg = isPos ? posOpts.alg : r.alg, encoding = isPos ? (encodingArg ?? posOpts.encoding) : r.encoding
    const res = await this.callRpc('crypto.hmacSign', { secretHandle, payload: normalizePayloadStr(isPos ? payloadArg : r.payload), ...(alg ? { alg } : {}), ...(encoding ? { encoding } : {}) }, 30_000) as HmacSignResult
    const handle = res.handle ?? res.derivedHandle ?? res.signature, out = { ...res, signature: res.signature ?? handle, handle, derivedHandle: res.derivedHandle ?? handle }
    if (out.derivedHandle && /^cap:/.test(out.derivedHandle) && out.exchangeId) this._capOrigins.set(out.derivedHandle, out.exchangeId)
    this.recordCrypto(secretHandle, out.exchangeId, out.derivedHandle, out.attestation?.alg ?? alg); return out
  }
  hmacSign(...args: Parameters<VerifyContext['hmac_sign']>): Promise<HmacSignResult> { return this.hmac_sign(...args) }
  async jwt_sign(inputOrSecret: JwtSignInput | Record<string, unknown> | string, claimsArg?: Record<string, unknown>, opts?: Omit<JwtSignInput, 'secretHandle' | 'claims'> | string): Promise<JwtSignResult> {
    const isPos = typeof inputOrSecret === 'string' || (claimsArg !== undefined && inputOrSecret && typeof inputOrSecret === 'object' && !('secretHandle' in inputOrSecret))
    const r: Partial<JwtSignInput> = isPos ? (typeof opts === 'string' ? { alg: opts as JwtSignInput['alg'] } : { ...(opts ?? {}) }) : ((inputOrSecret && typeof inputOrSecret === 'object' ? inputOrSecret : {}) as Partial<JwtSignInput>)
    const secretHandle = resolveCapHandle(isPos ? inputOrSecret : (r.secretHandle ?? ''))
    const res = await this.callRpc('crypto.jwtSign', { secretHandle, claims: (isPos ? claimsArg : r.claims) ?? {}, ...pickDefined(r as Record<string, unknown>, ['alg', 'header', 'hopReceiptId', 'slot']), ...(r.ttlMs !== undefined ? { ttlMs: r.ttlMs } : {}), ...(r.allowedOrigins?.length ? { allowedOrigins: r.allowedOrigins } : {}) }, 30_000) as JwtSignResult
    const out = { ...res, handle: res.handle ?? res.derivedHandle, token: res.token ?? res.derivedHandle }
    if (out.derivedHandle && out.exchangeId) this._capOrigins.set(out.derivedHandle, out.exchangeId)
    this.recordCrypto(secretHandle, out.exchangeId, out.derivedHandle, out.attestation?.alg ?? r.alg); return out
  }
  jwtSign(...args: Parameters<VerifyContext['jwt_sign']>): Promise<JwtSignResult> { return this.jwt_sign(...args) }
  async await_async(input: AsyncAwaitInput | Record<string, unknown>): Promise<AsyncAwaitResult> {
    const r = (input && typeof input === 'object' ? input : {}) as AsyncAwaitInput
    const { args: pollRequest } = r.pollRequest !== undefined ? this.buildHttpRpcArgs(r.pollRequest, typeof r.pollRequest === 'string' ? extractInlineHttpOptions(r) : {}) : this.buildHttpRpcArgs(r as HttpTarget)
    const matchPredicate = normalizeAsyncPredicate(r.matchPredicate, r.expectStatus), triggerExchangeId = typeof r.triggerExchangeId === 'string' ? r.triggerExchangeId : (r.triggerExchangeId && typeof r.triggerExchangeId === 'object' ? r.triggerExchangeId.exchangeId : undefined), timeoutMs = r.timeoutMs !== undefined ? Number(r.timeoutMs) : undefined
    const res = await this.callRpc('async.awaitResult', { pollRequest, ...(matchPredicate ? { matchPredicate } : {}), ...(r.profile ? { profile: r.profile } : {}), ...(timeoutMs !== undefined ? { timeoutMs } : {}), ...(r.intervalMs !== undefined ? { intervalMs: Number(r.intervalMs) } : {}), ...(r.maxAttempts !== undefined ? { maxAttempts: Number(r.maxAttempts) } : {}), ...(triggerExchangeId ? { triggerExchangeId } : {}), ...(r.tTriggerMs !== undefined ? { tTriggerMs: Number(r.tTriggerMs) } : {}), ...(r.correlationId ? { correlationId: String(r.correlationId) } : {}), ...(r.correlationIds?.length ? { correlationIds: r.correlationIds } : {}), ...(r.entityId ? { entityId: String(r.entityId) } : {}) }, Math.max((timeoutMs ?? 30_000) + 10_000, 15_000)) as AsyncAwaitResult
    const out = res && res.exchange ? { ...res, exchange: hydrateExchange(res.exchange) } : res; if (out?.exchange) this.rememberEx(out.exchange)
    const hop = this.activeHop()
    if (hop) {
      if (out.exchangeId) hop.onExchange(out.exchangeId); if (out.exchange) this.recordExCaps(hop, out.exchange, pollRequest.capability)
      if (!hop.target) hop.target = { origin: typeof pollRequest.origin === 'string' ? pollRequest.origin : this.targetOrigin, method: typeof pollRequest.method === 'string' ? pollRequest.method : 'GET', pathAndQuery: out.exchange?.pathAndQuery || (typeof pollRequest.path === 'string' ? pollRequest.path : '/') }
      const cid = r.correlationId ? String(r.correlationId) : (r.correlationIds?.[0] ? String(r.correlationIds[0]) : undefined); if (cid) hop.onCorrelation(cid); if (!hop.entityId && r.entityId) hop.entityId = String(r.entityId)
      if (out.pollRecordId) hop.asyncPolls.push({ pollRecordId: out.pollRecordId, ...(cid ? { correlationId: cid } : {}), ...(triggerExchangeId ? { triggerExchangeId } : {}) })
    }
    return out
  }
  awaitAsync(input: AsyncAwaitInput | Record<string, unknown>): Promise<AsyncAwaitResult> { return this.await_async(input) }
  private recordProofClaims(ok: boolean, claims: readonly VerifyClaim[]): void { if (claims.length) { if (ok) { this._lastFailedClaims = []; this.claims.push(...claims) } else { this._lastFailedClaims = [...claims] } } }
  async prove_composite(receipt: CompositeProofReceiptInput): Promise<CompositeVerificationResult> {
    const res = await this.callRpc('composite.verify', normalizeCompositeReceipt(receipt, this.defaultOrigin, this._capOrigins), 30_000) as CompositeVerificationResult
    const confirmed = res.confirmed === true || res.ok === true || res.verified === true; if (res.claim) this.recordProofClaims(confirmed, [res.claim])
    return { ...res, confirmed, ok: confirmed, verified: confirmed }
  }
  proveComposite(receipt: CompositeProofReceiptInput): Promise<CompositeVerificationResult> { return this.prove_composite(receipt) }
  effectiveClaims(): VerifyClaim[] { return this.claims.length > 0 ? [...this.claims] : [...this._lastFailedClaims] }
  async browser(input: HttpTarget, options: { as?: string; waitForSelector?: string; timeoutMs?: number } = {}): Promise<BrowserExchange> {
    const target = splitTarget(input, this.defaultOrigin), res = await this.callRpc('browser', { ...(target.origin ? { origin: target.origin } : {}), path: target.path, ...(options.as ? { persona: options.as } : {}), ...(options.waitForSelector ? { waitForSelector: options.waitForSelector } : {}) }, (options.timeoutMs ?? 60_000) + 10_000) as BrowserExchange
    const hop = this.activeHop(); if (hop) { pushUnique(hop.browserTraceIds, res.exchangeId); if (!hop.target) hop.target = { origin: target.origin ?? this.targetOrigin, method: 'GET', pathAndQuery: target.path } }; return res
  }
  readonly oob = {
    mint: async (label = 'oob', origin?: string): Promise<OobHandle> => { const res = await this.callRpc('oob', { action: 'mint', label, ...(origin ? { origin } : {}) }, 30_000) as OobHandle; pushUnique(this.activeHop()?.oobEventIds ?? [], res.exchangeId); return res },
    check: async (handle: OobHandle | string): Promise<OobCheck> => { const h = typeof handle === 'string' ? { token: handle, exchangeId: '', url: '', dnsHost: '' } : handle, res = { ...h, ...(await this.callRpc('oob', { action: 'check', token: h.token, ...(h.exchangeId ? { exchangeId: h.exchangeId } : {}) }, 30_000) as OobCheck) }; pushUnique(this.activeHop()?.oobEventIds ?? [], res.checkExchangeId ?? res.exchangeId); return res },
    wait: async (handle: OobHandle | string, opts?: number | { timeoutMs?: number; immediateMs?: number }): Promise<OobCheck> => { const h = typeof handle === 'string' ? { token: handle, exchangeId: '', url: '', dnsHost: '' } : handle, ms = typeof opts === 'number' ? opts : opts?.timeoutMs, im = typeof opts === 'object' ? opts?.immediateMs : undefined, res = { ...h, ...(await this.callRpc('oob', { action: 'wait', token: h.token, ...(ms !== undefined ? { timeoutMs: ms } : {}), ...(im !== undefined ? { immediateMs: im } : {}) }, Math.max(30_000, (ms ?? 3_000) + 10_000)) as OobCheck) }; pushUnique(this.activeHop()?.oobEventIds ?? [], res.checkExchangeId ?? res.exchangeId); return res },
  }
  oob_create(label = 'oob', origin?: string): Promise<OobHandle> { return this.oob.mint(label, origin) }; oob_mint(label = 'oob', origin?: string): Promise<OobHandle> { return this.oob.mint(label, origin) }
  oob_poll(handle: OobHandle | string, opts?: number | { timeoutMs?: number; immediateMs?: number }): Promise<OobCheck> { return this.oob.wait(handle, opts) }; oob_check(handle: OobHandle | string): Promise<OobCheck> { return this.oob.check(handle) }
  private async callProof<T extends { ok?: boolean; confirmed?: boolean; claim?: VerifyClaim; claims?: VerifyClaim[] }>(op: string, input: unknown, errMsg: string, timeoutMs: number, hydrateKeys?: readonly string[]): Promise<T> {
    if (!input || typeof input !== 'object') throw new Error(errMsg)
    const raw = await this.callRpc(op, normalizeProofCapabilities(input) as Record<string, unknown>, timeoutMs) as Record<string, unknown>, res = (hydrateKeys ? hydrateFields(raw, hydrateKeys) : raw) as unknown as T
    this.recordProofClaims(res.ok !== false && res.confirmed !== false, Array.isArray(res.claims) ? res.claims : res.claim ? [res.claim] : []); return res
  }
  prove_access_boundary(input: AccessBoundaryInput | Record<string, unknown>): Promise<AccessBoundaryProof> { return this.callProof<AccessBoundaryProof>('prove.accessBoundary', input, 'prove_access_boundary requires { controlPersona?, probePersona?, route, method?, boundaryClass?, vulnClass?, expectControlDenied? }.', 70_000, ['control', 'probe']) }
  async prove_persisted_mutation(input: PersistedMutationInput | Record<string, unknown>): Promise<PersistedMutationProof> {
    if (!input || typeof input !== 'object') throw new Error('prove_persisted_mutation requires { readRoute, mutation, fieldPath, expectDelta }.')
    const raw = input as Record<string, unknown>, expectFn = typeof raw.expectDelta === 'function' ? raw.expectDelta : null, payload: Record<string, unknown> = { ...raw }
    if (payload.mutation === undefined && payload.write === undefined) { const m = raw.mutate ?? raw.mutationRoute ?? raw.writeRoute ?? raw.mutationTarget; if (m !== undefined) payload.mutation = m }
    if (payload.readRoute === undefined && payload.read_route === undefined) { const rr = raw.read ?? raw.beforeRoute ?? raw.readTarget ?? (payload.mutation !== undefined || payload.write !== undefined ? raw.route : undefined); if (rr !== undefined) payload.readRoute = rr }
    if (expectFn) { delete payload.expectDelta; payload.hasCustomExpectFn = true }
    const res = hydrateFields(await this.callRpc('prove.persistedMutation', normalizeProofCapabilities(payload) as Record<string, unknown>, 70_000) as Record<string, unknown>, ['before', 'mutation', 'after']) as unknown as PersistedMutationProof
    if (expectFn && !Boolean(expectFn(res.delta.before, res.delta.after, res.delta))) { if (res.claim) this.recordProofClaims(false, [res.claim]); return { ...res, ok: false, confirmed: false, expectationMatched: false, rejectedBy: res.rejectedBy ?? 'impact', missingEvidence: [...new Set([...res.missingEvidence, 'expected_delta'])] } }
    if (res.claim) this.recordProofClaims(res.ok !== false && res.confirmed !== false, [res.claim]); return res
  }
  async prove_boolean_or_timing_diff(input: BooleanOrTimingDiffInput | Record<string, unknown>): Promise<DifferentialProof> {
    const res = await this.callProof<DifferentialProof>('prove.differential', input, 'prove_boolean_or_timing_diff requires { control, variant, mode: "boolean"|"timing", rounds? }.', 120_000)
    if (res.exchanges) res.exchanges = { control: res.exchanges.control.map(hydrateExchange), variant: res.exchanges.variant.map(hydrateExchange) }; return res
  }
  async prove_oob_callback(input: OobCallbackInput | Record<string, unknown>): Promise<OobCallbackProof> {
    const raw = input as Record<string, unknown>, timeoutMs = Number(raw.timeoutMs ?? 6_000); let res: OobCallbackProof
    if (typeof raw.inject === 'function') {
      const injectFn = raw.inject as (canary: OobHandle) => Promise<HttpExchange | void> | HttpExchange | void
      const started = await this.callRpc('prove.oob', { phase: 'start', ...(raw.token ? { token: raw.token } : {}), ...(raw.immediateMs !== undefined ? { immediateMs: Number(raw.immediateMs) } : {}), ...(raw.windowMs !== undefined ? { windowMs: Number(raw.windowMs) } : {}) }, 30_000) as { handle: OobHandle; subscription: Record<string, unknown> }
      let injection: HttpExchange | null = null, injectionError: string | null = null; try { injection = (await injectFn(started.handle)) ?? null } catch (err) { injectionError = err instanceof Error ? err.message : 'OOB injection failed.' }
      res = await this.callRpc('prove.oob', { phase: 'finish', handle: started.handle, subscription: started.subscription, ...(injection ? { injection } : {}), ...(injectionError ? { injectionError } : {}), ...(raw.immediateMs !== undefined ? { immediateMs: Number(raw.immediateMs) } : {}), timeoutMs, ...(raw.message ? { message: raw.message } : {}) }, timeoutMs + 15_000) as OobCallbackProof
    } else { res = await this.callRpc('prove.oob', normalizeProofCapabilities(raw) as Record<string, unknown>, timeoutMs + 20_000) as OobCallbackProof }
    if (res.claim) this.recordProofClaims(res.ok !== false && res.confirmed !== false, [res.claim]); return res
  }
  async prove_race_burst(input: RaceBurstInput | Record<string, unknown>): Promise<RaceBurstProof> {
    const raw = (input && typeof input === 'object' ? input : {}) as Record<string, unknown>, reqCount = Array.isArray(raw.requests) ? raw.requests.length : 0
    const res = hydrateFields(await this.callRpc('prove.race', normalizeProofCapabilities(raw) as Record<string, unknown>, Math.max(40_000, Math.min(80_000, 25_000 + reqCount * 2_000))) as Record<string, unknown>, ['baseline', 'post', 'serial', 'serialPost']) as unknown as RaceBurstProof
    if (res.claim && Array.isArray(res.claim.exchangeIds) && res.claim.exchangeIds.length >= 2) this.recordProofClaims(res.ok !== false && res.confirmed !== false, [res.claim])
    const hop = this.activeHop()
    if (hop) {
      for (const id of res.claim?.exchangeIds ?? res.exchanges?.map(e => e.exchangeId) ?? []) hop.onExchange(id)
      if (!hop.target && Array.isArray(raw.requests) && raw.requests.length > 0) { const first = raw.requests[0] as RaceRequestInput | HttpTarget; try { const t = splitTarget(first as HttpTarget, this.defaultOrigin); hop.target = { origin: t.origin ?? this.targetOrigin, method: typeof first === 'object' && first && 'method' in first && typeof first.method === 'string' ? first.method.toUpperCase() : (t.method ?? 'POST'), pathAndQuery: t.path } } catch { /* explicit target */ } }
    }
    return res
  }
  prove_injection_differential(input: InjectionDifferentialInput | Record<string, unknown>): Promise<InjectionDifferentialProof> { return this.callProof<InjectionDifferentialProof>('prove.injection', input, 'prove_injection_differential requires { control, probe, expectedOutput?, vulnClass? }.', 70_000, ['control', 'probe']) }
  prove_signed_url_mint(input: SignedUrlMintInput | Record<string, unknown>): Promise<SignedUrlMintProof> { return this.callProof<SignedUrlMintProof>('prove.signedUrlMint', input, 'prove_signed_url_mint requires { control, probe } (or route + controlBody/probeBody, or controlExchangeId/probeExchangeId).', 70_000, ['control', 'probe']) }
  proveAccessBoundary(i: AccessBoundaryInput | Record<string, unknown>) { return this.prove_access_boundary(i) }; provePersistedMutation(i: PersistedMutationInput | Record<string, unknown>) { return this.prove_persisted_mutation(i) }
  proveBooleanOrTimingDiff(i: BooleanOrTimingDiffInput | Record<string, unknown>) { return this.prove_boolean_or_timing_diff(i) }; proveInjectionDifferential(i: InjectionDifferentialInput | Record<string, unknown>) { return this.prove_injection_differential(i) }
  proveSignedUrlMint(i: SignedUrlMintInput | Record<string, unknown>) { return this.prove_signed_url_mint(i) }; proveOobCallback(i: OobCallbackInput | Record<string, unknown>) { return this.prove_oob_callback(i) }; proveRaceBurst(i: RaceBurstInput | Record<string, unknown>) { return this.prove_race_burst(i) }
  result(input: { title: string; severity?: string; description?: string }): ProofResult {
    if (!input.title || !input.title.trim()) throw new Error('Proof result requires a title.')
    return { sdk: 'kovo_verify.ts', nonce: this.nonce, title: input.title.slice(0, 300), severity: (input.severity ?? 'high').slice(0, 32), ...(input.description ? { description: input.description.slice(0, 4000) } : {}), claims: this.effectiveClaims() }
  }
}
export interface VerificationScript { setup?(ctx: VerifyContext): Promise<void> | void; verify(ctx: VerifyContext): Promise<ProofResult | unknown> | ProofResult | unknown; cleanup?(ctx: VerifyContext): Promise<void> | void }
export type VerificationEntrypoint = VerificationScript | ((ctx: VerifyContext) => Promise<ProofResult | unknown> | ProofResult | unknown)
export function defineVerification(script: VerificationScript): VerificationScript { return script }
function writeResult(value: unknown): void { writeFileSync(process.env.KOVO_PROOF_RESULT_FILE ?? join(dirname(process.env.KOVO_RPC_CONTEXT_FILE ?? '/kovo-rpc/context.json'), 'result.json'), JSON.stringify(value), { mode: 0o600 }) }
function normalizeProofResult(ctx: VerifyContext, returned: unknown, defaultTitle?: string): ProofResult {
  const fallbackTitle = (defaultTitle && defaultTitle.trim() ? defaultTitle.trim() : 'Verification script proof').slice(0, 300), fallbackClaims = ctx.effectiveClaims()
  if (returned && typeof returned === 'object' && !Array.isArray(returned) && Array.isArray((returned as Record<string, unknown>).claims)) {
    const rec = returned as Record<string, unknown>
    return { sdk: 'kovo_verify.ts', nonce: typeof rec.nonce === 'string' && rec.nonce ? rec.nonce : ctx.nonce, title: typeof rec.title === 'string' && rec.title.trim() ? rec.title.trim().slice(0, 300) : fallbackTitle, severity: typeof rec.severity === 'string' && rec.severity.trim() ? rec.severity.trim().slice(0, 32) : 'high', ...(typeof rec.description === 'string' && rec.description ? { description: rec.description.slice(0, 4000) } : {}), claims: (rec.claims as VerifyClaim[]).length > 0 ? (rec.claims as VerifyClaim[]) : fallbackClaims }
  }
  return { sdk: 'kovo_verify.ts', nonce: ctx.nonce, title: fallbackTitle, severity: 'high', claims: fallbackClaims }
}
function failScript(ctx: VerifyContext, message: string, claims: VerifyClaim[]): void { writeResult({ sdk: 'kovo_verify.ts', nonce: ctx.nonce, error: message.slice(0, 2000), ...(ctx.lastRpcOp ? { lastRpcOp: ctx.lastRpcOp } : {}), claims }); process.stderr.write(`kovo_verify: ${message}\n`); process.exitCode = 1 }
export async function runVerification(script: VerificationScript, defaultTitle?: string): Promise<void> {
  const ctx = new VerifyContext(); let result: unknown = null
  try { await script.setup?.(ctx); result = await script.verify(ctx); await script.cleanup?.(ctx) } catch (error) { failScript(ctx, error instanceof Error ? error.message : 'Verification script failed.', ctx.effectiveClaims()); return }
  const normalized = normalizeProofResult(ctx, result, defaultTitle); writeResult(normalized); process.stdout.write(`kovo_verify: ${normalized.claims.length} transcript-backed claim(s) recorded\n`)
}
export async function runEntrypoint(entry: VerificationEntrypoint, defaultTitle?: string): Promise<void> {
  if (typeof entry === 'function') return runVerification({ verify: entry }, defaultTitle)
  if (entry && typeof entry === 'object' && typeof entry.verify === 'function') return runVerification(entry, defaultTitle)
  failScript(new VerifyContext(), 'kovo_verify script must export a default async (ctx) => ... function, an object with verify(ctx), or execute ctx.prove_* directly.', [])
}
