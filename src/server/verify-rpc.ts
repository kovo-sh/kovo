/**
 * Layer-3 verification RPC bridge (v6 Phase 3 MVP).
 *
 * Workers run untrusted verification scripts inside a `--network none` sandbox. Those scripts
 * never speak to the target directly and never hold persona credentials. Instead every
 * `http` / `http2` / `browser` / `oob` call crosses a Unix-domain socket into this server, which
 * owns the Layer-1 grant:
 *
 *   - scope is the exact `Grant.canRead` predicate used by the broker,
 *   - credentials are injected host-side (`buildPersonaHeader`) and redacted before a response
 *     leaves this process,
 *   - every exchange is appended to a tamper-evident, HMAC-signed transcript.
 *
 * The script may only return *claims* that reference transcript exchange ids. The transcript
 * oracle re-evaluates those claims against the recorded exchanges, so a fabricated stdout line
 * or a hand-written "passed: true" can never confirm a finding. `verifyScript()` additionally
 * re-runs the candidate once in a fresh session with a fresh nonce and requires both oracles to
 * pass and both transcripts to agree on the causal artifact.
 *
 * This module intentionally does not import replay-verifier, execution, store or broker internals
 * beyond the public `RequestBroker` / `Grant` seam. Impact semantics are shared with the replay
 * path through the pure `oracle-invariants` module, so both paths dismiss the same over-claims.
 */
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { BrokerApprovalRequired, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker, WireCredentialProvenance } from './broker.ts'
import { EgressDeniedError } from './egress-gateway.ts'
import { buildPersonaHeader, personaSecrets } from './persona-vault.ts'
import type { ResolvedPersona } from './persona-vault.ts'
import { redact, type NamedSecret } from './redact.ts'
import {
  EgressSanitizer,
  checkSealRateLimit,
  extractRequestEntityIds,
  normalizeDerivedSecretKind,
  resolveSealJsonPath,
  toPublicCapabilityMeta,
  validateCapabilitySealValue,
} from './egress-sanitizer.ts'
import { defaultRequestAdmissionEngine, type RequestAdmissionEngine } from './request-admission.ts'
import {
  DerivedCapabilityVault,
  SEAL_FIELD_NOT_FOUND_ERROR,
  SEAL_REGEX_RETIRED_ERROR,
  awaitAsyncConvergence,
  computeNonSecretLiteralHmac,
  consumeRunCompositeVerifyBudget,
  consumeRunSealBudget,
  formatDerivedHandle,
  isDerivedCapabilityHandle,
  resolveVerifyRpcScratchRoot,
} from './derived-custody.ts'
import { resolveRunSafetyBudgets, type RunSafetyBudgets } from './run-safety-budgets.ts'
import type {
  AsyncPollProfile,
  CapabilityConsumptionAttestation,
  CapabilitySourceProvenance,
  HostHmacAlg,
  HostHmacEncoding,
  HostJwtAlg,
  InjectCapabilityTarget,
} from './derived-custody.ts'
import { signHostRecord, verifyHostRecordSignature } from './composite-receipt.ts'
import type {
  CompositeReceiptVerification,
  CompositeVerifyOptions,
  HostAsyncPollRecord,
  HostBrowserTrace,
  HostCryptoAttestation,
  HostOobEvent,
  HostSignableRecord,
  HostSignedTranscript,
  HostTranscriptEntry,
} from './composite-receipt.ts'
import { HostFactLog, deriveAmbientAuthFromHeaders } from './host-fact-log.ts'
import { defaultTerminalOracleRegistry } from './terminal-oracle-registry.ts'
import { isReadMethod, normalizeRole, parseRoleLabel } from './oracle-invariants.ts'
import type { ImpactStep } from './oracle-invariants.ts'
import {
  buildHostAuthPlacement,
  compileAsyncMatchPredicate,
  consumeRunAsyncPollAttemptBudget,
  consumeRunAsyncPollCallBudget,
  evaluateAsyncMatchPredicate,
  parseCapabilityArg,
  parseVerifyAuthMutation,
  resolvePersonaAuthKind,
  resolveScopedBrowserDriverForVerify,
  type HostAuthPlacement,
  type ParsedCapabilityArg,
} from './verify-support.ts'

declare module './verify-claims.ts' {
  interface VerifyTranscriptRequest {
    /** R3-H-5: Explicit host-derived wire credential placement stamped from injection + wire provenance. */
    credentialPlacement?: HostAuthPlacement
    /** H-14 / R3-H-5: Broker-observed non-secret wire credential provenance. */
    wireCredentialProvenance?: WireCredentialProvenance
  }
}
import {
  VERIFY_RPC_CONTAINER_DIR,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_HEADER,
  VERIFY_NONCE_HEADER,
  TranscriptStore,
  asRecord,
  evaluateJsonPath,
  sameSiteFromRecord,
} from './verify-claims.ts'
import type {
  VerifyTranscriptRequest,
  VerifyTranscriptRecord,
  VerifyClaim,
  VerifyCanaryBroker,
  VerifyOobPromotionView,
} from './verify-claims.ts'
import {
  handleProveAccessBoundary,
  handleProvePersistedMutation,
  handleProveDifferential,
  handleProveOob,
  handleProveRace,
  handleProveInjection,
  handleProveSignedUrlMint,
} from './verify-prove-handlers.ts'
import type { ProveHandlerHost, ProveHttpExchangeResult } from './verify-prove-handlers.ts'
import { buildLocalAttemptFactory } from './verify-runner.ts'
import type { LocalAttemptFactoryBaseOptions } from './verify-runner.ts'

export {
  VERIFY_RPC_CONTAINER_DIR,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_NONCE_ENV,
  VERIFY_RESULT_ENV,
  VERIFY_RPC_HEADER,
  VERIFY_NONCE_HEADER,
  VERIFY_RESULT_MARKER,
  TranscriptStore,
  normalizeDynamic,
  parseVerifyScriptResult,
  mannWhitneyU,
  describeMissingEvidence,
  evaluateClaims,
  causalFingerprints,
} from './verify-claims.ts'
export type {
  VerifyExchangeOp,
  VerifyTranscriptRequest,
  VerifyTranscriptResponse,
  VerifyTranscriptArtifact,
  VerifyTranscriptRecord,
  TranscriptSummary,
  TranscriptCompositeVerification,
  VerifyClaim,
  VerifyScriptResult,
  VerifyClaimCheck,
  VerifyOracleResult,
  VerifyClaimContext,
  VerifyCanaryCheck,
  VerifyOobSubscriptionView,
  VerifyOobAwaitView,
  VerifyOobPromotionView,
  VerifyCanaryBroker,
  MannWhitneyResult,
  CausalFingerprint,
} from './verify-claims.ts'
export {
  KOVO_VERIFY_STDERR_PREVIEW_MAX_CHARS,
  KOVO_VERIFY_USAGE_HINT,
  redactStderrPreview,
  prepareVerifyScript,
  verifyScript,
  runCandidateLocally,
} from './verify-runner.ts'
export type {
  VerificationCandidate,
  AttemptExecution,
  VerifyAttemptSession,
  VerifyReason,
  VerifyAttemptReport,
  VerifyVerdict,
  VerifyScriptOptions,
  RunCandidateLocallyOptions,
} from './verify-runner.ts'

const MAX_RPC_BODY_BYTES = 4 * 1024 * 1024
const MAX_PATH_LENGTH = 8192
const MAX_HEADERS = 64
const MAX_HEADER_VALUE = 4096

// ---------------------------------------------------------------------------
// RPC server
// ---------------------------------------------------------------------------

export interface VerifyBrowserRequest {
  url: string
  origin: string
  personaHandle: string | null
  /** Injected host-side; never echoed to the script. */
  headers: Record<string, string>
  waitForSelector?: string
  timeoutMs: number
}

export interface VerifyBrowserResult {
  status: number
  url: string
  html: string
  title?: string
  /** Sentinels the *host-controlled* browser observed (e.g. an executed `alert`). */
  executedSentinels?: string[]
}

export interface VerifyBrowserDriver {
  open(request: VerifyBrowserRequest, signal: AbortSignal): Promise<VerifyBrowserResult>
}

export interface VerifyRpcSessionOptions {
  /** RequestBroker is used for the HTTP path (scope, approvals, credentials, redaction). */
  broker: RequestBroker
  grant: Grant
  runId: string
  assignmentId: string
  /** Fresh per attempt; echoed by the SDK and required on every RPC call. */
  nonce?: string
  /** Origins advertised to the script (absolute URLs are still re-checked by the grant). */
  targetOrigins?: string[]
  browser?: VerifyBrowserDriver
  canary?: VerifyCanaryBroker
  /** Host directory holding the socket, token and context. Created when omitted. */
  hostDir?: string
  maxRpcBodyBytes?: number
  /** Optional timeout for a single HTTP/h2/browser call. */
  callTimeoutMs?: number
  /** Optional shared per-run DerivedCapabilityVault; a fresh run-scoped vault is created when omitted. */
  capabilityVault?: DerivedCapabilityVault
  /** Optional 0600 file path for DerivedCapabilityVault persistence when capabilityVault is omitted. */
  capabilityPersistPath?: string
  /** Host-enforced CompositeProofReceipt verification options (never overridable by RPC callers). */
  compositeVerifyOptions?: Omit<CompositeVerifyOptions, 'signingKey'>
  /** Maximum `capability.seal` attempts allowed per exchangeId (default 12, C-3 anti-oracle cap). */
  maxSealsPerExchange?: number
  /** Maximum `capability.seal` / crypto derivation calls allowed across the entire run (default 4096). */
  maxSealsPerRun?: number
  /** Maximum `capability.seal` calls allowed per (origin+path+persona) endpoint per run (default 256). */
  maxSealsPerEndpoint?: number
  /** Maximum `composite.verify` RPC calls allowed across the entire run (default from RunSafetyBudgets). */
  maxCompositeVerifiesPerRun?: number
  /** Maximum `async.awaitResult` RPC calls allowed across the entire run (R3-H-2). */
  maxAsyncPollCallsPerRun?: number
  /** Maximum `async.awaitResult` individual poll attempts allowed across the entire run (R3-H-2). */
  maxAsyncPollAttemptsPerRun?: number
  /** Optional unified RunSafetyBudgets policy overrides resolved via `resolveRunSafetyBudgets`. */
  safetyBudgets?: Partial<RunSafetyBudgets>
  /** Canonical request admission engine (defaults to the broker's engine). */
  admissionEngine?: RequestAdmissionEngine
}

interface RpcPayload {
  op?: string
  args?: Record<string, unknown>
}

interface AuthCapabilityActor {
  handle: string
  roleLabel: string | null
  role: string | null
  tenant: string | null
}

interface HostExchangeProvenance {
  timestampMs: number
  emittedCapabilities: Set<string>
  observedResponseDigests: Set<string>
  consumedCapabilities: Set<string>
  injectedRequestDigests: Set<string>
  cryptoAttestations: HostCryptoAttestation[]
  entityId?: string
  correlationIds: Set<string>
  evidenceRole?: string
  cleanSession?: boolean
  replayAttempt?: 'mode_a' | 'ablation_control' | 'primary'
  rawRequestBody?: string
  rawRequestOrigin?: string
  rawRequestParts?: string[]
  kernelPathAndQuery?: string
  kernelRequestHeaders?: Record<string, string>
  kernelRequestBody?: string
  authCapabilityActor?: AuthCapabilityActor
  wireCredentialProvenance?: WireCredentialProvenance
  authPlacement?: HostAuthPlacement
  carrierText?: string
}

const BROKER_FORBIDDEN_CALLER_HEADER_RE = /^(?:authorization|proxy-authorization|cookie)$/i
const AUTH_CAP_HEADER_RE = /^(?:authorization|proxy-authorization|cookie|x-api-key|x-auth-token|x-access-token|x-session-token|api-key|x-token|x-scim-token)$/i
const INLINE_CAP_RE = /(?<!\[redacted:)(?<![A-Za-z0-9_])cap(?::|%3[aA])hop_[A-Za-z0-9._-]+(?::|%3[aA])[A-Za-z0-9._-]+/g
const EXACT_BEARER_CAP_RE = /^\s*(?:Bearer\s+)*(cap:hop_[A-Za-z0-9._-]+:[A-Za-z0-9._-]+)\s*$/i
const EXACT_INLINE_CAP_RE = /^cap:hop_[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$/
const SAFE_RPC_OP_RE = /^[a-z0-9._-]{1,40}$/i

function setHeaderCI(map: Record<string, string>, name: string, value: string): void {
  const lower = name.toLowerCase()
  for (const key of Object.keys(map)) {
    if (key.toLowerCase() === lower) delete map[key]
  }
  map[name] = value
}

function hasInlineCapCandidate(text: string): boolean {
  return text.includes('cap:') || /cap%3a/i.test(text)
}

export class VerifyRpcServer {
  readonly nonce: string
  readonly transcript: TranscriptStore
  readonly capabilityVault: DerivedCapabilityVault
  readonly safetyBudgets: RunSafetyBudgets
  private readonly options: VerifyRpcSessionOptions
  private readonly admissionEngine: RequestAdmissionEngine
  private readonly compositeSigningKey: string
  private readonly egress: EgressSanitizer
  private readonly kernelSanitizer: EgressSanitizer
  private readonly rawBodies = new Map<string, string>()
  private readonly rawResponseHeaders = new Map<string, Record<string, string>>()
  private readonly exchangeProvenance = new Map<string, HostExchangeProvenance>()
  private readonly hmacDerivations = new Map<string, HostCryptoAttestation>()
  private readonly jwtDerivations = new Map<string, HostCryptoAttestation>()
  private readonly asyncPollRecords = new Map<string, HostAsyncPollRecord>()
  private readonly mutatedSessions = new Set<string>()
  private readonly mutatedSessionEntities = new Set<string>()
  private readonly mintedCanaries = new Map<string, { token: string; canaryId: string; runId: string; attemptId: string; mintedAtMs: number }>()
  private readonly sessionOobSubscriptions = new Map<string, { token: string; canaryId: string }>()
  private readonly bufferedOobPromotions: VerifyOobPromotionView[] = []
  private readonly sealAttemptsByExchange = new Map<string, number>()
  private readonly sessionSealedHandles = new Set<string>()
  private totalSealAttempts = 0
  private lastHostTsMs = 0
  private server: ReturnType<typeof createServer> | null = null
  private hostDirValue = ''
  private socketPathValue = ''
  private tokenValue = ''
  private started = false
  private closing = false

  constructor(options: VerifyRpcSessionOptions) {
    this.options = options
    this.admissionEngine = options.admissionEngine
      ?? (typeof options.broker?.getAdmissionEngine === 'function' ? options.broker.getAdmissionEngine() : defaultRequestAdmissionEngine)
    this.nonce = options.nonce ?? randomBytes(12).toString('hex')
    this.transcript = new TranscriptStore()
    this.compositeSigningKey = randomBytes(32).toString('hex')
    const safeRunId = /^[A-Za-z0-9._-]{1,128}$/.test(options.runId)
      ? options.runId
      : options.runId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 128) || 'run'
    this.safetyBudgets = resolveRunSafetyBudgets({
      overrides: {
        ...options.safetyBudgets,
        ...(options.maxSealsPerRun !== undefined ? { maxSealsPerRun: options.maxSealsPerRun } : {}),
        ...(options.maxSealsPerEndpoint !== undefined ? { maxSealsPerEndpoint: options.maxSealsPerEndpoint } : {}),
        ...(options.maxCompositeVerifiesPerRun !== undefined ? { maxCompositeVerifiesPerRun: options.maxCompositeVerifiesPerRun } : {}),
      },
    })
    this.capabilityVault = options.capabilityVault ?? new DerivedCapabilityVault({
      runId: safeRunId,
      maxEntries: this.safetyBudgets.maxVaultEntries,
      maxSealAttempts: this.safetyBudgets.maxSealAttempts,
      ...(options.capabilityPersistPath ? { persistPath: options.capabilityPersistPath } : {}),
    })
    const getKernelSecrets = (): NamedSecret[] => {
      const out: NamedSecret[] = []
      if (this.options.grant.personas) {
        for (const persona of this.options.grant.personas.values()) {
          const vals = [persona.secret, persona.session?.value, ...(persona.secretHistory ?? []), ...(persona.session?.scrubTokens ?? [])]
          for (const v of vals) if (typeof v === 'string' && v.length >= 4) out.push({ value: v, placeholder: `[redacted:${persona.handle}]` })
        }
        out.push(...personaSecrets(this.options.grant.personas))
      }
      if (this.options.grant.secrets) out.push(...this.options.grant.secrets)
      if (typeof this.options.broker.getRegisteredSecrets === 'function') out.push(...this.options.broker.getRegisteredSecrets())
      return out
    }
    this.kernelSanitizer = new EgressSanitizer({ secrets: getKernelSecrets })
    this.egress = new EgressSanitizer({ secrets: getKernelSecrets, capabilityVaults: [this.capabilityVault] })
  }

  private nextHostTimestampMs(): number {
    const now = Date.now()
    this.lastHostTsMs = now >= this.lastHostTsMs ? now : this.lastHostTsMs
    return this.lastHostTsMs
  }

  private getOrCreateProvenance(exchangeId: string, timestampMs?: number): HostExchangeProvenance {
    let prov = this.exchangeProvenance.get(exchangeId)
    if (!prov) {
      prov = {
        timestampMs: timestampMs ?? this.nextHostTimestampMs(),
        emittedCapabilities: new Set<string>(),
        observedResponseDigests: new Set<string>(),
        consumedCapabilities: new Set<string>(),
        injectedRequestDigests: new Set<string>(),
        cryptoAttestations: [],
        correlationIds: new Set<string>(),
      }
      this.exchangeProvenance.set(exchangeId, prov)
    }
    return prov
  }

  get hostDir(): string {
    return this.hostDirValue
  }

  get socketPath(): string {
    return this.socketPathValue
  }

  get token(): string {
    return this.tokenValue
  }

  /** Environment + mount descriptor handed to the worker container. */
  mount(): { hostDir: string; socketPath: string; containerDir: string; socketEnv: string; tokenEnv: string; contextEnv: string } {
    return {
      hostDir: this.hostDirValue,
      socketPath: this.socketPathValue,
      containerDir: VERIFY_RPC_CONTAINER_DIR,
      socketEnv: `${VERIFY_RPC_SOCKET_ENV}=${VERIFY_RPC_CONTAINER_DIR}/${VERIFY_RPC_SOCKET_NAME}`,
      tokenEnv: `${VERIFY_RPC_TOKEN_ENV}=${VERIFY_RPC_CONTAINER_DIR}/${VERIFY_RPC_TOKEN_NAME}`,
      contextEnv: `${VERIFY_RPC_CONTEXT_ENV}=${VERIFY_RPC_CONTAINER_DIR}/${VERIFY_RPC_CONTEXT_NAME}`,
    }
  }

  async start(): Promise<this> {
    if (this.started) return this
    const configured = this.options.hostDir
    if (configured) {
      mkdirSync(configured, { recursive: true, mode: 0o711 })
      this.hostDirValue = configured
    } else {
      const scratchRaw = resolveVerifyRpcScratchRoot()
      if (scratchRaw) {
        const scratchRoot = resolve(scratchRaw)
        if (scratchRoot === '/') throw new Error('KOVO_CONTAINER_SCRATCH_DIR must not be root "/".')
        mkdirSync(scratchRoot, { recursive: true, mode: 0o711 })
        this.hostDirValue = mkdtempSync(join(scratchRoot, 'kovo-verify-rpc-'))
      } else {
        const tmpfsBase = existsSync('/dev/shm') ? '/dev/shm' : tmpdir()
        try { this.hostDirValue = mkdtempSync(join(tmpfsBase, 'kovo-verify-rpc-')) } catch { this.hostDirValue = mkdtempSync(join(tmpdir(), 'kovo-verify-rpc-')) }
      }
    }
    // 0711: the sandbox uid can traverse to the mounted files without listing the host directory.
    // Explicit chmodSync on every file bypasses restrictive host umasks (e.g. 0077) so the
    // non-root worker container UID (10001) never hits EACCES reading /kovo-rpc/*.
    chmodSync(this.hostDirValue, 0o711)
    this.socketPathValue = join(this.hostDirValue, VERIFY_RPC_SOCKET_NAME)
    this.tokenValue = randomBytes(24).toString('hex')
    const tokenPath = join(this.hostDirValue, VERIFY_RPC_TOKEN_NAME)
    writeFileSync(tokenPath, this.tokenValue + '\n', { mode: 0o444 })
    chmodSync(tokenPath, 0o444)
    const context = {
      nonce: this.nonce,
      runId: this.options.runId,
      assignmentId: this.options.assignmentId,
      targetOrigins: this.options.targetOrigins ?? [],
      sdkVersion: 'kovo_verify/v6-mvp',
    }
    const contextPath = join(this.hostDirValue, VERIFY_RPC_CONTEXT_NAME)
    writeFileSync(contextPath, JSON.stringify(context, null, 2), { mode: 0o444 })
    chmodSync(contextPath, 0o444)

    const server = createServer((req, res) => { void this.handle(req, res) })
    server.on('clientError', (_err, socket) => {
      try { socket.destroy() } catch { /* ignore */ }
    })
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => { server.off('listening', onListening); reject(err) }
      const onListening = () => { server.off('error', onError); resolve() }
      server.once('error', onError)
      server.once('listening', onListening)
      server.listen(this.socketPathValue)
    })
    chmodSync(this.socketPathValue, 0o666)
    this.server = server
    this.started = true
    return this
  }

  async close(): Promise<void> {
    if (this.closing) return
    this.closing = true
    const server = this.server
    this.server = null
    if (server) {
      await new Promise<void>(resolve => server.close(() => resolve()))
    }
    try { rmSync(this.hostDirValue, { recursive: true, force: true }) } catch { /* ignore */ }
  }

  private async handle(req: IncomingMessage, res: ServerResponse) {
    const reply = (status: number, body: unknown) => {
      const text = JSON.stringify(body)
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) })
      res.end(text)
    }
    if (req.method !== 'POST' || (req.url ?? '') !== '/rpc') {
      return reply(404, { ok: false, error: 'Unknown verification RPC endpoint.' })
    }
    const expectedToken = Buffer.from(this.tokenValue)
    const provided = String(req.headers[VERIFY_RPC_HEADER] ?? '')
    const providedBuf = Buffer.from(provided)
    if (providedBuf.length !== expectedToken.length || !timingSafeEqual(providedBuf, expectedToken)) {
      return reply(403, { ok: false, error: 'Invalid verification RPC capability.' })
    }
    const nonce = String(req.headers[VERIFY_NONCE_HEADER] ?? '')
    if (nonce !== this.nonce) {
      return reply(403, { ok: false, error: 'Stale verification nonce; scripts must run inside a fresh attempt session.' })
    }
    const limit = this.options.maxRpcBodyBytes ?? MAX_RPC_BODY_BYTES
    let body = ''
    try {
      for await (const chunk of req) {
        body += chunk
        if (Buffer.byteLength(body) > limit) return reply(413, { ok: false, error: 'Verification RPC payload exceeds the limit.' })
      }
    } catch {
      return reply(400, { ok: false, error: 'Verification RPC payload could not be read.' })
    }
    let payload: RpcPayload
    try { payload = JSON.parse(body) as RpcPayload } catch { return reply(400, { ok: false, error: 'Invalid JSON RPC payload.' }) }
    try {
      const result = await this.dispatch(payload, nonce)
      return reply(200, { ok: true, result })
    } catch (error) {
      return reply(200, { ok: false, error: this.scrub(error instanceof Error ? error.message : 'Verification RPC failed.').slice(0, 600) })
    }
  }

  private async dispatch(payload: RpcPayload, nonce: string): Promise<unknown> {
    const op = payload.op
    const args = asRecord(payload.args) ?? {}
    if (op === 'transcript') return this.handleTranscript(args)
    if (op === 'http' || op === 'http.send') return this.handleHttp(args, nonce, 'http')
    if (op === 'http2') return this.handleHttp2(args, nonce)
    if (op === 'browser') return this.handleBrowser(args, nonce)
    if (op === 'oob') return this.handleOob(args)
    if (op === 'race') return this.handleRace(args, nonce)
    if (op === 'capability.seal') return this.handleCapabilitySeal(args, nonce)
    if (op === 'crypto.hmacSign') return this.handleCryptoHmacSign(args, nonce)
    if (op === 'crypto.jwtSign') return this.handleCryptoJwtSign(args, nonce)
    if (op === 'async.awaitResult') return this.handleAsyncAwaitResult(args, nonce)
    if (op === 'composite.verify') return this.handleCompositeVerify(args)
    if (op === 'prove.accessBoundary') return handleProveAccessBoundary(this.proveHost(), args, nonce)
    if (op === 'prove.persistedMutation') return handleProvePersistedMutation(this.proveHost(), args, nonce)
    if (op === 'prove.differential') return handleProveDifferential(this.proveHost(), args, nonce)
    if (op === 'prove.oob') return handleProveOob(this.proveHost(), args, nonce)
    if (op === 'prove.race') return handleProveRace(this.proveHost(), args, nonce)
    if (op === 'prove.injection') return handleProveInjection(this.proveHost(), args, nonce)
    if (op === 'prove.signedUrlMint') return handleProveSignedUrlMint(this.proveHost(), args, nonce)
    const safeOp = typeof op === 'string' && SAFE_RPC_OP_RE.test(op) ? op : '<invalid>'
    throw new Error(`Unsupported verification RPC operation: ${safeOp}`)
  }

  private handleTranscript(args: Record<string, unknown>): unknown {
    const action = typeof args.action === 'string' ? args.action : 'list'
    if (action === 'get') {
      const id = typeof args.exchangeId === 'string' ? args.exchangeId : ''
      const record = this.transcript.get(id)
      if (!record) throw new Error('Unknown exchange id.')
      const rawBody = this.transcript.body(id)
      const scrubbedBody = rawBody !== undefined ? redact(this.scrub(rawBody)) : null
      // R3-H-2: Worker-facing bodySha256/bodyBytes reflect ONLY the worker-visible scrubbed body.
      const safeRecord = record.response && scrubbedBody !== null
        ? { ...record, response: { ...record.response, bodySha256: createHash('sha256').update(scrubbedBody, 'utf8').digest('hex'), bodyBytes: Buffer.byteLength(scrubbedBody, 'utf8') } }
        : record
      return this.scrubRecord({
        record: safeRecord,
        body: scrubbedBody,
        digest: this.transcript.digest(),
        signaturesValid: this.transcript.verifySignatures(),
      })
    }
    if (action === 'digest') {
      return { digest: this.transcript.digest(), signaturesValid: this.transcript.verifySignatures(), count: this.transcript.size }
    }
    return this.scrubRecord({
      exchanges: this.transcript.summaries(),
      digest: this.transcript.digest(),
      signaturesValid: this.transcript.verifySignatures(),
      nonce: this.nonce,
      runId: this.options.runId,
    })
  }

  private scopeOrigin(raw: unknown): { origin: string; url: URL } {
    const requested = typeof raw === 'string' && raw.length > 0
      ? raw
      : this.options.targetOrigins?.[0]
    if (!requested) throw new Error('No target origin is configured for this verification session.')
    const decision = this.admissionEngine.admitOrigin(requested, this.options.grant)
    if (!decision.allowed || !decision.normalizedOrigin || !decision.parsedUrl) throw new Error(decision.reason)
    return { origin: decision.normalizedOrigin, url: decision.parsedUrl }
  }

  private parseHttpArgs(args: Record<string, unknown>): { brokerRequest: BrokerHttpRequest; requestMeta: VerifyTranscriptRequest } {
    let originArg = args.origin
    let rawPathInput = args.path ?? args.pathAndQuery ?? args.endpoint
    if (rawPathInput === undefined && typeof args.url === 'string' && args.url.trim()) {
      const trimmedUrl = args.url.trim()
      if (/^https?:\/\//i.test(trimmedUrl)) {
        let parsedUrl: URL
        try { parsedUrl = new URL(trimmedUrl) } catch { throw new Error('Request URL is malformed.') }
        originArg = originArg ?? parsedUrl.origin
        rawPathInput = parsedUrl.pathname + parsedUrl.search
      } else {
        rawPathInput = trimmedUrl
      }
    }
    const { origin } = this.scopeOrigin(originArg)
    if (originArg !== undefined && typeof originArg !== 'string') throw new Error('origin must be a string.')
    const rawPath = rawPathInput ?? '/'
    const isExactCapPath = typeof rawPath === 'string' && isDerivedCapabilityHandle(rawPath.trim())
    if (typeof rawPath !== 'string' || (!isExactCapPath && (!rawPath.startsWith('/') || rawPath.startsWith('//'))) || rawPath.length > MAX_PATH_LENGTH || /[\r\n\0]/.test(rawPath)) {
      throw new Error('Request path is invalid or exceeds the 8 KiB limit.')
    }
    const method = String(args.method ?? 'GET').toUpperCase()
    const allowedMethods = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    if (!allowedMethods.has(method)) throw new Error('Unsupported HTTP method.')
    const headers: Record<string, string> = {}
    const rawHeaders = asRecord(args.headers) ?? {}
    if (Object.keys(rawHeaders).length > MAX_HEADERS) throw new Error('Too many request headers.')
    for (const [k, v] of Object.entries(rawHeaders)) {
      if (typeof v !== 'string' || v.length > MAX_HEADER_VALUE || /[\r\n\0]/.test(k) || /[\r\n\0]/.test(v)) throw new Error('Invalid request header.')
      if (k.trimStart().startsWith(':')) continue
      headers[k] = v
    }
    const body = typeof args.body === 'string' ? args.body : undefined
    if (body !== undefined && Buffer.byteLength(body) > 2 * 1024 * 1024) throw new Error('Request body exceeds 2 MiB.')
    const rawPersona = typeof args.persona === 'string' ? args.persona.trim()
      : typeof args.as === 'string' ? args.as.trim() : undefined
    const isAnonSentinel = Boolean(
      rawPersona
      && ['anonymous', 'anon', 'unauthenticated', 'none'].includes(rawPersona.toLowerCase())
      && !this.options.grant.personas?.has(rawPersona),
    )
    const persona = rawPersona && !isAnonSentinel ? rawPersona : undefined
    const session = typeof args.session === 'string' ? args.session : undefined
    const role = typeof args.sessionGroupRole === 'string' ? args.sessionGroupRole : (typeof args.arm === 'string' ? args.arm : undefined)
    if (role !== undefined && !['setup', 'control', 'probe', 'cleanup'].includes(role)) {
      throw new Error(`Invalid session group role "${role}"; expected one of: setup|control|probe|cleanup.`)
    }
    const authMutation = parseVerifyAuthMutation(args.authMutation, persona)
    const brokerRequest: BrokerHttpRequest = {
      origin,
      method: method as BrokerHttpRequest['method'],
      pathAndQuery: rawPath,
      ...(Object.keys(headers).length ? { headers } : {}),
      ...(body !== undefined ? { body } : {}),
      ...(persona ? { persona } : {}),
      ...(session ? { session } : {}),
      ...(role ? { sessionGroupRole: role as BrokerHttpRequest['sessionGroupRole'] } : {}),
      ...(authMutation ? { authMutation: authMutation as BrokerHttpRequest['authMutation'] } : {}),
      ...(typeof args.followRedirects === 'boolean' ? { followRedirects: args.followRedirects } : {}),
      ...(typeof args.probeClass === 'string' ? { probeClass: args.probeClass } : {}),
      runId: this.options.runId,
      assignmentId: this.options.assignmentId,
    }
    return {
      brokerRequest,
      requestMeta: {
        origin,
        method,
        pathAndQuery: rawPath,
        headers,
        bodyBytes: body ? Buffer.byteLength(body) : 0,
        bodySha256: createHash('sha256').update(body ?? '').digest('hex'),
        personaHandle: persona ?? null,
        sessionRole: role ?? null,
        actorRoleLabel: (persona ? this.options.grant.personas?.get(persona)?.roleLabel ?? null : null),
        nonce: this.nonce,
      },
    }
  }

  private scrub(text: string): string {
    return this.egress.redactText(text, 'worker_rpc')
  }

  private scrubRecord<T>(value: T): T {
    return this.egress.sanitizeValue(value, 'worker_rpc')
  }

  private scrubKernel(text: string): string {
    // R3-C-3: Kernel request plane uses exact host/persona/grant secret scrubbing ONLY — zero
    // heuristic key-name redaction so secret-named query/body echoes cannot bypass anti-reflection.
    return this.kernelSanitizer.redactSecrets(text)
  }

  private scrubKernelHeaderMap(headers: Record<string, string>): Record<string, string> {
    const out: Record<string, string> = {}
    for (const [k, v] of Object.entries(headers)) out[k] = this.scrubKernel(v)
    return out
  }

  private resolveImmutableSlot(hopReceiptId: string, requestedSlot: string): string {
    const baseHandle = `cap:hop_${hopReceiptId}:${requestedSlot}`
    if (this.sessionSealedHandles.has(baseHandle)) {
      throw new Error(`Capability handle "${baseHandle}" is immutable and already sealed in this session; choose a distinct hopReceiptId or slot.`)
    }
    if (!this.capabilityVault.hasEverSealed(baseHandle)) return requestedSlot
    const suffix = this.nonce.replace(/[^A-Za-z0-9]/g, '').slice(0, 6) || randomBytes(3).toString('hex')
    let candidate = `${requestedSlot.slice(0, 56)}_${suffix}`
    let attempt = 2
    while (this.capabilityVault.hasEverSealed(`cap:hop_${hopReceiptId}:${candidate}`)) {
      candidate = `${requestedSlot.slice(0, 52)}_${suffix}_${attempt++}`
    }
    return candidate
  }

  private inferCapabilityTarget(cap: ParsedCapabilityArg): InjectCapabilityTarget {
    if (cap.target) return cap.target
    if (cap.headerName) return 'header'
    if (cap.cookieName) return 'cookie'
    if (cap.queryParam) return 'url'
    const meta = this.capabilityVault.getMeta(cap.handle)
    if (meta?.kind === 'cookie' || meta?.defaultCookieName) return 'cookie'
    if (meta?.kind === 'signed_url') return 'url'
    if (meta?.defaultHeaderName) return 'header'
    return 'bearer'
  }

  private resolveInlineHandle(
    handle: string, targetUrl: string, method: string, mode: 'url' | 'header' | 'bearer', headerName?: string,
  ): { rawValue: string; attestation: CapabilityConsumptionAttestation } {
    if (mode === 'bearer') {
      const injected = this.capabilityVault.injectCapabilityIntoRequest({ handle, target: 'bearer', runId: this.capabilityVault.runId, request: { url: targetUrl, method, headers: {} } })
      return { rawValue: (injected.request.headers?.Authorization ?? '').replace(/^Bearer\s+/i, ''), attestation: injected.attestation }
    }
    if (mode === 'header') {
      const hName = headerName ?? 'X-Kovo-Inline-Resolve'
      const injected = this.capabilityVault.injectCapabilityIntoRequest({ handle, target: 'header', headerName: hName, runId: this.capabilityVault.runId, request: { url: targetUrl, method, headers: {} } })
      return { rawValue: injected.request.headers?.[hName] ?? '', attestation: injected.attestation }
    }
    const injected = this.capabilityVault.injectCapabilityIntoRequest({ handle, target: 'url', queryParam: '__kovo_resolve__', runId: this.capabilityVault.runId, request: { url: targetUrl, method, headers: {} } })
    return { rawValue: new URL(injected.request.url).searchParams.get('__kovo_resolve__') ?? '', attestation: injected.attestation }
  }

  private applyCapabilityInjection(
    brokerRequest: BrokerHttpRequest, requestMeta: VerifyTranscriptRequest, cap: ParsedCapabilityArg | null,
  ): {
    brokerRequest: BrokerHttpRequest; grant: Grant; requestMeta: VerifyTranscriptRequest
    attestation: CapabilityConsumptionAttestation | null; attestations: CapabilityConsumptionAttestation[]
    injectedHeaders: Record<string, string>; authCapabilityActor: AuthCapabilityActor | null
    injectedAuthHeaders: Record<string, string>; capabilityTargets: Array<'cookie' | 'bearer' | 'header' | 'query' | 'body'>
    basePersonaAuthKind: 'cookie' | 'bearer' | 'header' | 'none' | null; basePersonaDropped: boolean
  } {
    const baseReq: BrokerHttpRequest = { ...brokerRequest }
    const basePersonaHandle = baseReq.persona ?? baseReq.personaHandle
    const basePersonaObj = basePersonaHandle ? this.options.grant.personas?.get(basePersonaHandle) : undefined
    const basePersonaAuthKind = resolvePersonaAuthKind(basePersonaObj)
    const basePersonaHeaderLower = basePersonaObj?.headerName?.toLowerCase() ?? null
    const isCapAuthHeader = (name: string): boolean =>
      AUTH_CAP_HEADER_RE.test(name) || (basePersonaHeaderLower !== null && name.toLowerCase() === basePersonaHeaderLower)
    const capTargets = new Set<'cookie' | 'bearer' | 'header' | 'query' | 'body'>()
    const attestationsById = new Map<string, CapabilityConsumptionAttestation>()
    const recordAtt = (att: CapabilityConsumptionAttestation) => { if (!attestationsById.has(att.consumedCapabilityId)) attestationsById.set(att.consumedCapabilityId, att) }
    const decodeCap = (m: string) => (/%3[aA]/.test(m) ? m.replace(/%3[aA]/g, ':') : m)
    const knownHandles = this.capabilityVault.list().map(m => m.handle).sort((a, b) => b.length - a.length)
    const splitCap = (raw: string): { handle: string; suffix: string } => {
      if (this.capabilityVault.getMeta(raw)) return { handle: raw, suffix: '' }
      const hit = knownHandles.find(h => raw.startsWith(h) && /^[._-]/.test(raw.slice(h.length)))
      return hit ? { handle: hit, suffix: raw.slice(hit.length) } : { handle: raw, suffix: '' }
    }
    const authPlaceholder = (headerName: string, resolvedValue: string): string => {
      if (/^authorization$/i.test(headerName)) return /^bearer\s+/i.test(resolvedValue) ? 'Bearer [injected]' : '[injected]'
      return '[injected]'
    }
    const replaceInline = (
      text: string, targetUrl: string, mode: 'url' | 'header' | 'bearer',
      opts?: { headerName?: string; rejectCrlf?: boolean; jsonEscape?: boolean; onHandle?: (h: string) => void },
    ): string => text.replace(new RegExp(INLINE_CAP_RE.source, 'g'), (match) => {
      const isEncoded = /%3[aA]/.test(match)
      const { handle, suffix } = splitCap(decodeCap(match))
      const { rawValue, attestation } = this.resolveInlineHandle(handle, targetUrl, baseReq.method, mode, opts?.headerName)
      if (opts?.rejectCrlf && /[\r\n\0]/.test(rawValue)) throw new Error('Inline capability value contains control characters.')
      recordAtt(attestation)
      opts?.onHandle?.(handle)
      const val = isEncoded ? encodeURIComponent(rawValue) : (opts?.jsonEscape && /["\\\r\n\t\x00-\x1f]/.test(rawValue) ? JSON.stringify(rawValue).slice(1, -1) : rawValue)
      return `${val}${suffix}`
    })

    let nextOrigin = baseReq.origin
    let nextPathAndQuery = baseReq.pathAndQuery
    let nextBody = baseReq.body
    const workingHeaders: Record<string, string> = { ...(baseReq.headers ?? {}) }
    const injectedByCapKeys = new Set<string>()
    const authHeaders: Record<string, string> = {}
    const metaHeaders: Record<string, string> = { ...requestMeta.headers }
    const injectedHeaders: Record<string, string> = {}
    let primaryAuthHandle: string | null = null

    // 1) Explicit capability argument injection
    if (cap) {
      const target = this.inferCapabilityTarget(cap)
      const baseUrl = new URL(nextPathAndQuery.startsWith('/') ? nextPathAndQuery : '/', nextOrigin).href
      const capInputHeaders: Record<string, string> = {}
      for (const [k, v] of Object.entries(workingHeaders)) {
        if (!BROKER_FORBIDDEN_CALLER_HEADER_RE.test(k) || (target === 'cookie' && /^cookie$/i.test(k) && !hasInlineCapCandidate(v))) {
          capInputHeaders[k] = v
        }
      }
      const injected = this.capabilityVault.injectCapabilityIntoRequest({
        handle: cap.handle, target, runId: this.capabilityVault.runId,
        ...(cap.headerName ? { headerName: cap.headerName } : {}),
        ...(cap.cookieName ? { cookieName: cap.cookieName } : {}),
        ...(cap.queryParam ? { queryParam: cap.queryParam } : {}),
        request: { url: baseUrl, method: baseReq.method, headers: capInputHeaders },
      })
      recordAtt(injected.attestation)
      if (target === 'url') capTargets.add('query')
      if (injected.request.url !== baseUrl) {
        const parsedUrl = new URL(injected.request.url)
        if (!this.admissionEngine.admitOrigin(parsedUrl.origin, this.options.grant).allowed) throw new Error('Derived capability destination is outside the current assignment scope.')
        nextOrigin = parsedUrl.origin
        nextPathAndQuery = parsedUrl.pathname + parsedUrl.search
      }
      for (const [k, v] of Object.entries(injected.request.headers ?? {})) {
        const isAuthHdr = isCapAuthHeader(k)
        if (!isAuthHdr && capInputHeaders[k] === v) continue
        const normVal = /^authorization$/i.test(k) ? v.replace(/^\s*(?:Bearer\s+)+/i, 'Bearer ') : v
        injectedHeaders[k] = normVal
        injectedByCapKeys.add(k.toLowerCase())
        if (isAuthHdr) {
          capTargets.add(/^cookie$/i.test(k) ? 'cookie' : (/^authorization$/i.test(k) && /^bearer\s+/i.test(normVal) ? 'bearer' : 'header'))
          setHeaderCI(authHeaders, k, normVal)
          setHeaderCI(metaHeaders, k, authPlaceholder(k, normVal))
          primaryAuthHandle = primaryAuthHandle ?? cap.handle
          for (const wk of Object.keys(workingHeaders)) if (wk.toLowerCase() === k.toLowerCase()) delete workingHeaders[wk]
        } else {
          setHeaderCI(workingHeaders, k, normVal)
          setHeaderCI(metaHeaders, k, this.scrubKernel(normVal))
        }
      }
    }

    // 2) Inline `cap:hop_...` placeholders in URL path/query
    const trimmedPath = nextPathAndQuery.trim()
    if (EXACT_INLINE_CAP_RE.test(trimmedPath)) {
      const urlBase = new URL('/', nextOrigin).href
      const resolved = this.resolveInlineHandle(trimmedPath, urlBase, baseReq.method, 'url')
      capTargets.add('query')
      if (/^https?:\/\//i.test(resolved.rawValue)) {
        const injected = this.capabilityVault.injectCapabilityIntoRequest({
          handle: trimmedPath, target: 'url', runId: this.capabilityVault.runId, request: { url: urlBase, method: baseReq.method, headers: {} },
        })
        const parsedUrl = new URL(injected.request.url)
        if (!this.admissionEngine.admitOrigin(parsedUrl.origin, this.options.grant).allowed) throw new Error('Derived capability destination is outside the current assignment scope.')
        nextOrigin = parsedUrl.origin
        nextPathAndQuery = parsedUrl.pathname + parsedUrl.search
        recordAtt(injected.attestation)
      } else if (resolved.rawValue.startsWith('/') && !resolved.rawValue.startsWith('//') && !/[\r\n\0]/.test(resolved.rawValue) && resolved.rawValue.length <= MAX_PATH_LENGTH) {
        nextPathAndQuery = resolved.rawValue
        recordAtt(resolved.attestation)
      } else {
        throw new Error('Request path is invalid or exceeds the 8 KiB limit.')
      }
    } else if (hasInlineCapCandidate(nextPathAndQuery)) {
      const urlBase = new URL(nextPathAndQuery, nextOrigin).href
      nextPathAndQuery = replaceInline(nextPathAndQuery, urlBase, 'url', { rejectCrlf: true })
      capTargets.add('query')
      if (!nextPathAndQuery.startsWith('/') || nextPathAndQuery.startsWith('//') || nextPathAndQuery.length > MAX_PATH_LENGTH) {
        throw new Error('Request path is invalid or exceeds the 8 KiB limit.')
      }
    }

    // 3) Inline `cap:hop_...` placeholders in headers (routing Authorization/Cookie/auth headers through auth targets)
    const targetUrl = new URL(nextPathAndQuery, nextOrigin).href
    const nextHeaders: Record<string, string> = {}
    for (const [k, v] of Object.entries(workingHeaders)) {
      if (injectedByCapKeys.has(k.toLowerCase()) || !hasInlineCapCandidate(v) || !new RegExp(INLINE_CAP_RE.source, 'g').test(v)) {
        nextHeaders[k] = v
        continue
      }
      if (/^authorization$/i.test(k)) {
        const exactBearer = EXACT_BEARER_CAP_RE.exec(v)
        if (exactBearer) {
          const handle = exactBearer[1]!
          const injected = this.capabilityVault.injectCapabilityIntoRequest({
            handle, target: 'bearer', runId: this.capabilityVault.runId, request: { url: targetUrl, method: baseReq.method, headers: {} },
          })
          const resolvedAuth = injected.request.headers!.Authorization!
          setHeaderCI(authHeaders, 'Authorization', resolvedAuth)
          injectedHeaders['Authorization'] = resolvedAuth
          setHeaderCI(metaHeaders, k, authPlaceholder(k, resolvedAuth))
          recordAtt(injected.attestation)
          primaryAuthHandle = primaryAuthHandle ?? handle
          capTargets.add('bearer')
        } else {
          const resolvedAuth = replaceInline(v, targetUrl, 'bearer', { onHandle: h => { primaryAuthHandle = primaryAuthHandle ?? h } }).replace(/^\s*Bearer(?:\s+Bearer)+\s+/i, 'Bearer ')
          setHeaderCI(authHeaders, 'Authorization', resolvedAuth)
          injectedHeaders['Authorization'] = resolvedAuth
          setHeaderCI(metaHeaders, k, authPlaceholder(k, resolvedAuth))
          capTargets.add(/^bearer\s+/i.test(resolvedAuth) ? 'bearer' : 'header')
        }
      } else if (/^cookie$/i.test(k)) {
        const existingAuthCookie = Object.entries(authHeaders).find(([ak]) => /^cookie$/i.test(ak))?.[1]
        const cookieHeaders: Record<string, string> = existingAuthCookie ? { Cookie: existingAuthCookie } : {}
        let firstHandle: string | null = null
        const metaSegs: string[] = []
        for (const rawSeg of v.split(';')) {
          const seg = rawSeg.trim()
          if (!seg) continue
          if (!new RegExp(INLINE_CAP_RE.source, 'g').test(seg)) {
            cookieHeaders.Cookie = cookieHeaders.Cookie ? `${cookieHeaders.Cookie}; ${seg}` : seg
            metaSegs.push(this.scrubKernel(seg))
            continue
          }
          const eq = seg.indexOf('=')
          const rhs = eq > 0 ? seg.slice(eq + 1).trim() : seg
          if ((eq > 0 && EXACT_INLINE_CAP_RE.test(rhs)) || (eq === -1 && EXACT_INLINE_CAP_RE.test(seg))) {
            const cookieName = eq > 0 ? seg.slice(0, eq).trim() : undefined
            const injected = this.capabilityVault.injectCapabilityIntoRequest({
              handle: rhs, target: 'cookie', ...(cookieName ? { cookieName } : {}),
              runId: this.capabilityVault.runId, request: { url: targetUrl, method: baseReq.method, headers: cookieHeaders },
            })
            cookieHeaders.Cookie = injected.request.headers!.Cookie!
            recordAtt(injected.attestation)
            firstHandle = firstHandle ?? rhs
            metaSegs.push(cookieName ? `${cookieName}=[injected]` : '[injected]')
          } else {
            const resolvedSeg = replaceInline(seg, targetUrl, 'header', { headerName: 'X-Kovo-Inline-Resolve', onHandle: h => { firstHandle = firstHandle ?? h } })
            cookieHeaders.Cookie = cookieHeaders.Cookie ? `${cookieHeaders.Cookie}; ${resolvedSeg}` : resolvedSeg
            metaSegs.push(eq > 0 ? `${seg.slice(0, eq).trim()}=[injected]` : '[injected]')
          }
        }
        if (firstHandle && cookieHeaders.Cookie) {
          setHeaderCI(authHeaders, 'Cookie', cookieHeaders.Cookie)
          injectedHeaders['Cookie'] = cookieHeaders.Cookie
          setHeaderCI(metaHeaders, k, metaSegs.join('; '))
          primaryAuthHandle = primaryAuthHandle ?? firstHandle
          capTargets.add('cookie')
        } else {
          nextHeaders[k] = v
        }
      } else if (/^proxy-authorization$/i.test(k) || isCapAuthHeader(k)) {
        const resolvedVal = replaceInline(v, targetUrl, /^proxy-authorization$/i.test(k) ? 'bearer' : 'header', { headerName: k, onHandle: h => { primaryAuthHandle = primaryAuthHandle ?? h } })
        setHeaderCI(authHeaders, k, resolvedVal)
        injectedHeaders[k] = resolvedVal
        setHeaderCI(metaHeaders, k, '[injected]')
        capTargets.add('header')
      } else {
        const resolvedVal = replaceInline(v, targetUrl, 'header', { headerName: k })
        nextHeaders[k] = resolvedVal
        injectedHeaders[k] = resolvedVal
        setHeaderCI(metaHeaders, k, this.scrubKernel(resolvedVal))
      }
    }

    // 4) Inline `cap:hop_...` placeholders in request body
    if (typeof nextBody === 'string' && hasInlineCapCandidate(nextBody)) {
      let isJsonBody = false
      const trimmedBody = nextBody.trimStart()
      if (trimmedBody.startsWith('{') || trimmedBody.startsWith('[')) {
        try { JSON.parse(nextBody); isJsonBody = true } catch { isJsonBody = false }
      }
      nextBody = replaceInline(nextBody, targetUrl, 'url', { jsonEscape: isJsonBody })
      capTargets.add('body')
    }

    // 4b) Encapsulated vault auto-detection for literal sealed values in path/query, headers, or body
    const autoParts = [nextPathAndQuery, ...Object.values(nextHeaders), ...Object.values(injectedHeaders), ...(typeof nextBody === 'string' && nextBody ? [nextBody] : [])]
    for (const hit of this.capabilityVault.matchSealedHandlesInRequest({ runId: this.capabilityVault.runId, targetOrigin: nextOrigin, parts: autoParts })) {
      if (!attestationsById.has(hit.handleId)) {
        attestationsById.set(hit.handleId, { consumedCapabilityId: hit.handleId, digest: hit.rawDigest, sha256Prefix: hit.rawDigest.slice(0, 12), target: 'url', runId: this.capabilityVault.runId, timestampMs: Date.now() })
      }
    }

    const attestations = [...attestationsById.values()]
    if (attestations.length === 0) {
      return {
        brokerRequest: baseReq, grant: this.options.grant, requestMeta, attestation: null, attestations: [],
        injectedHeaders: {}, authCapabilityActor: null, injectedAuthHeaders: {}, capabilityTargets: [],
        basePersonaAuthKind, basePersonaDropped: false,
      }
    }

    // 5) R2-H-8 / R3-H-4(a): Package capability-injected auth headers into an ephemeral persona
    //    carrying ONLY capability credentials (NEVER merging base-persona credential headers!).
    let effectiveGrant: Grant = this.options.grant
    let effectivePersona = baseReq.persona
    let authCapabilityActor: AuthCapabilityActor | null = null
    let basePersonaDropped = false
    if (Object.keys(authHeaders).length > 0) {
      const mergedBundleHeaders: Record<string, string> = {}
      if (basePersonaHandle) {
        if (!basePersonaObj) throw new Error(`Persona "${basePersonaHandle}" is not approved for this run.`)
        // R3-H-4(a): Drop EVERY base-persona credential header (Authorization, Cookie, X-API-Key,
        // custom auth headers) whenever a capability supplies any auth credential so a privileged
        // base persona can NEVER ride along on the wire under a lower-privileged capability label.
        basePersonaDropped = true
      }
      for (const [k, v] of Object.entries(authHeaders)) setHeaderCI(mergedBundleHeaders, k, v)
      const ephemeralHandle = primaryAuthHandle ?? attestations[0]!.consumedCapabilityId
      const srcProv = this.capabilityVault.getSourceProvenance(ephemeralHandle)
      const capRoleLabel = srcProv?.sourceActorRoleLabel ?? null
      const capRole = srcProv?.sourceActorRole ?? (capRoleLabel ? normalizeRole(capRoleLabel) : null)
      const capTenant = srcProv?.sourceActorTenant ?? (capRoleLabel ? parseRoleLabel(capRoleLabel).tenant : null)
      authCapabilityActor = { handle: ephemeralHandle, roleLabel: capRoleLabel, role: capRole, tenant: capTenant }
      const ephemeralPersona: ResolvedPersona = {
        id: ephemeralHandle, handle: ephemeralHandle, roleLabel: capRoleLabel ?? 'derived', originAllowlist: [nextOrigin],
        authKind: 'login', headerName: null, secret: '', canaryMarkers: [],
        session: { headerType: 'header', value: '', adapterUsed: 'derived-capability', bundle: { v: 2, headers: mergedBundleHeaders } },
      }
      const nextPersonas = new Map(this.options.grant.personas ?? [])
      nextPersonas.set(ephemeralHandle, ephemeralPersona)
      effectiveGrant = { ...this.options.grant, personas: nextPersonas }
      effectivePersona = ephemeralHandle
    }

    const nextBrokerReq: BrokerHttpRequest = {
      ...baseReq,
      origin: nextOrigin,
      pathAndQuery: nextPathAndQuery,
      ...(nextBody !== undefined ? { body: nextBody } : {}),
      ...(Object.keys(nextHeaders).length > 0 ? { headers: nextHeaders } : { headers: undefined }),
      ...(effectivePersona ? { persona: effectivePersona, personaHandle: undefined } : {}),
    }
    const nextMeta: VerifyTranscriptRequest = {
      ...requestMeta,
      origin: nextOrigin,
      pathAndQuery: this.scrubKernel(nextPathAndQuery),
      headers: this.scrubKernelHeaderMap(metaHeaders),
      ...(authCapabilityActor ? { personaHandle: authCapabilityActor.handle, actorRoleLabel: authCapabilityActor.roleLabel } : {}),
      ...(nextBody !== baseReq.body ? {
        bodyBytes: nextBody ? Buffer.byteLength(nextBody) : 0,
        bodySha256: createHash('sha256').update(this.scrubKernel(nextBody ?? '')).digest('hex'),
      } : {}),
      consumedCapabilityId: attestations[0]!.consumedCapabilityId,
    }
    return {
      brokerRequest: nextBrokerReq, grant: effectiveGrant, requestMeta: nextMeta,
      attestation: attestations[0] ?? null, attestations, injectedHeaders, authCapabilityActor,
      injectedAuthHeaders: authHeaders, capabilityTargets: [...capTargets], basePersonaAuthKind, basePersonaDropped,
    }
  }

  private detectCryptoAttestationsForRequest(
    brokerRequest: BrokerHttpRequest,
    consumedCapabilityIds: readonly string[],
    injectedHeaders: Record<string, string>,
  ): HostCryptoAttestation[] {
    const matched: HostCryptoAttestation[] = []
    const seen = new Set<string>()
    const add = (att: HostCryptoAttestation) => {
      const key = `${att.derivedFromCapabilityId}:${att.derivedCapabilityId ?? ''}:${att.artifactDigest}`
      if (seen.has(key)) return
      seen.add(key)
      matched.push({ ...att })
    }
    for (const capId of consumedCapabilityIds) {
      const jwtAtt = this.jwtDerivations.get(capId)
      if (jwtAtt) add(jwtAtt)
    }
    if (this.hmacDerivations.size > 0) {
      const searchParts: string[] = [
        brokerRequest.pathAndQuery,
        brokerRequest.body ?? '',
        ...Object.values(brokerRequest.headers ?? {}),
        ...Object.values(injectedHeaders),
      ]
      const hay = searchParts.join('\n')
      for (const [signature, att] of this.hmacDerivations.entries()) {
        if (signature.length >= 8 && (hay.includes(signature) || hay.includes(encodeURIComponent(signature)))) add(att)
      }
    }
    return matched
  }

  private recordRequestProvenance(
    exchangeId: string,
    startedAt: number,
    args: Record<string, unknown>,
    brokerRequest: BrokerHttpRequest,
    requestMeta: VerifyTranscriptRequest,
    result: { body: string; respHeaders: Record<string, string> },
    attestations: readonly CapabilityConsumptionAttestation[],
    cryptoAttestations: HostCryptoAttestation[],
    cleanSession: boolean,
    authCapabilityActor: AuthCapabilityActor | null = null,
    wireCredentialProvenance?: WireCredentialProvenance,
    authPlacement?: HostAuthPlacement,
  ): void {
    this.rawBodies.set(exchangeId, result.body)
    this.rawResponseHeaders.set(exchangeId, { ...result.respHeaders })
    const prov = this.getOrCreateProvenance(exchangeId, startedAt)
    prov.timestampMs = startedAt
    prov.cleanSession = cleanSession
    prov.rawRequestBody = brokerRequest.body
    prov.rawRequestOrigin = brokerRequest.origin
    prov.rawRequestParts = [brokerRequest.pathAndQuery, ...Object.values(brokerRequest.headers ?? {}), ...(brokerRequest.body ? [brokerRequest.body] : [])]
    // R2-C-9 / R3-C-3: Kernel request plane uses exact host-secret redaction only (zero heuristics, zero vault placeholders).
    const kernelPath = this.scrubKernel(brokerRequest.pathAndQuery)
    const kernelReqHeaders = this.scrubKernelHeaderMap(requestMeta.headers)
    const kernelReqBody = brokerRequest.body !== undefined ? this.scrubKernel(brokerRequest.body) : undefined
    prov.kernelPathAndQuery = kernelPath
    prov.kernelRequestHeaders = kernelReqHeaders
    prov.kernelRequestBody = kernelReqBody
    if (authCapabilityActor) prov.authCapabilityActor = authCapabilityActor
    if (wireCredentialProvenance) prov.wireCredentialProvenance = wireCredentialProvenance
    if (authPlacement) prov.authPlacement = authPlacement
    prov.carrierText = this.scrubKernel([kernelPath, ...Object.entries(kernelReqHeaders).map(([k, v]) => `${k}: ${v}`), kernelReqBody ?? ''].join('\n'))
    for (const attestation of attestations) {
      prov.consumedCapabilities.add(attestation.consumedCapabilityId)
      prov.injectedRequestDigests.add(attestation.digest)
    }
    for (const att of cryptoAttestations) {
      prov.cryptoAttestations.push(att)
      prov.injectedRequestDigests.add(att.artifactDigest)
    }
    if (typeof args.evidenceRole === 'string' && args.evidenceRole.trim()) {
      prov.evidenceRole = args.evidenceRole.trim().slice(0, 64)
    }
    if (args.replayAttempt === 'mode_a' || args.replayAttempt === 'ablation_control' || args.replayAttempt === 'primary') {
      if (args.replayAttempt !== 'ablation_control' || cleanSession) {
        prov.replayAttempt = args.replayAttempt
      }
    }
    // R2-C-3: Bind worker-supplied entityId / correlationIds ONLY against worker-visible scrubbed text (never raw hidden bytes).
    const visibleCombined = `${this.scrub(brokerRequest.pathAndQuery)}\n${this.scrub(brokerRequest.body ?? '')}\n${this.scrub(result.body)}`
    if (typeof args.entityId === 'string' && args.entityId.trim()) {
      const entity = args.entityId.trim().slice(0, 256)
      if (visibleCombined.toLowerCase().includes(entity.toLowerCase())) prov.entityId = entity
    }
    const rawCorr = Array.isArray(args.correlationIds)
      ? args.correlationIds
      : typeof args.correlationId === 'string'
        ? [args.correlationId]
        : []
    for (const item of rawCorr) {
      if (typeof item === 'string' && item.trim()) {
        const token = item.trim().slice(0, 256)
        const isMintedCanary = this.mintedCanaries.has(token.toLowerCase())
        if ((isMintedCanary || token.length >= 4) && visibleCombined.includes(token)) prov.correlationIds.add(token)
      }
    }
  }

  private exchangeView(record: VerifyTranscriptRecord, result: BrokerExchangeResult, extra?: {
    consumedCapabilityId?: string | null
    consumedCapabilities?: string[]
    derivedFromCapabilityIds?: string[]
    protocol?: 'h2'
  }) {
    // R2-H-4 / R3-H-2: Always redact FULL raw body before slicing, and hash ONLY the worker-visible scrubbed body.
    const scrubbedFullBody = redact(this.scrub(result.body))
    const workerBodySha256 = createHash('sha256').update(scrubbedFullBody, 'utf8').digest('hex')
    const workerBodyBytes = Buffer.byteLength(scrubbedFullBody, 'utf8')
    const previewLimit = Math.min(Math.max(result.bodyPreview.length || 512, 0), 4096)
    return this.scrubRecord({
      exchangeId: record.exchangeId,
      status: result.status,
      method: result.method,
      pathAndQuery: this.scrub(result.pathAndQuery),
      finalPathAndQuery: result.finalPathAndQuery ? this.scrub(result.finalPathAndQuery) : result.finalPathAndQuery,
      redirectOrigins: result.redirectOrigins,
      mediaType: result.mediaType,
      headers: this.egress.sanitizeHttpHeaders(result.respHeaders, 'worker_rpc'),
      body: scrubbedFullBody.slice(0, 512 * 1024),
      bodyPreview: result.body ? scrubbedFullBody.slice(0, previewLimit) : redact(this.scrub(result.bodyPreview)),
      bodyBytes: workerBodyBytes,
      bodySha256: workerBodySha256,
      durationMs: result.durationMs,
      personaHandle: record.request?.personaHandle ?? null,
      ...(extra?.protocol ? { protocol: extra.protocol } : {}),
      ...(extra?.consumedCapabilityId ? { consumedCapabilityId: extra.consumedCapabilityId } : {}),
      ...(extra?.consumedCapabilities?.length ? { consumedCapabilities: extra.consumedCapabilities } : {}),
      ...(extra?.derivedFromCapabilityIds?.length ? { derivedFromCapabilityIds: extra.derivedFromCapabilityIds } : {}),
    })
  }

  private computeControlCleanSession(sessionKey: string, args: Record<string, unknown>, req: BrokerHttpRequest, role?: string | null): { isControlOrAblation: boolean; cleanSession: boolean; entityIds: string[] } {
    const isControlOrAblation = args.replayAttempt === 'ablation_control' || role === 'control'
    const entityIds = extractRequestEntityIds(args, req.pathAndQuery, req.body)
    if (!isControlOrAblation) return { isControlOrAblation, cleanSession: true, entityIds }
    const cleanSession = entityIds.length > 0
      ? entityIds.every(eid => !this.mutatedSessionEntities.has(`${sessionKey}::${eid}`))
      : !this.mutatedSessions.has(sessionKey)
    return { isControlOrAblation, cleanSession, entityIds }
  }

  private recordSessionMutation(sessionKey: string, method: string, entityIds: readonly string[], isControlOrAblation: boolean, status: number): void {
    if (isReadMethod(method) || (isControlOrAblation && status >= 400)) return
    this.mutatedSessions.add(sessionKey)
    for (const eid of entityIds) this.mutatedSessionEntities.add(`${sessionKey}::${eid}`)
  }

  private stampPlacement(
    applied: ReturnType<VerifyRpcServer['applyCapabilityInjection']>,
    requestMeta: VerifyTranscriptRequest,
    wireProvenance?: WireCredentialProvenance,
  ): { authPlacement: HostAuthPlacement; stampedReqMeta: VerifyTranscriptRequest } {
    const authPlacement = buildHostAuthPlacement({
      wireProvenance, injectedAuthHeaders: applied.injectedAuthHeaders, capabilityTargets: applied.capabilityTargets,
      basePersonaAuthKind: applied.basePersonaAuthKind, basePersonaDropped: applied.basePersonaDropped, requestHeaders: requestMeta.headers,
    })
    return { authPlacement, stampedReqMeta: { ...requestMeta, credentialPlacement: authPlacement, ...(wireProvenance ? { wireCredentialProvenance: wireProvenance } : {}) } }
  }

  private prepareCapRequest(args: Record<string, unknown>, nonce: string) {
    const parsed = this.parseHttpArgs(args)
    const applied = this.applyCapabilityInjection(parsed.brokerRequest, parsed.requestMeta, parseCapabilityArg(args))
    const consumedIds = applied.attestations.map(a => a.consumedCapabilityId)
    const cryptoAttestations = this.detectCryptoAttestationsForRequest(applied.brokerRequest, consumedIds, applied.injectedHeaders)
    const derivedFromCapabilityIds = [...new Set(cryptoAttestations.map(a => a.derivedFromCapabilityId))]
    const requestMeta: VerifyTranscriptRequest = {
      ...applied.requestMeta,
      pathAndQuery: this.scrubKernel(applied.requestMeta.pathAndQuery),
      headers: this.scrubKernelHeaderMap(applied.requestMeta.headers),
      ...(cryptoAttestations.length > 0 ? { derivedFromCapabilityId: cryptoAttestations[0]!.derivedFromCapabilityId } : {}),
      nonce,
    }
    const sessionKey = applied.brokerRequest.session ?? '__default__'
    const control = this.computeControlCleanSession(sessionKey, args, applied.brokerRequest, requestMeta.sessionRole)
    return { applied, consumedIds, cryptoAttestations, derivedFromCapabilityIds, requestMeta, sessionKey, ...control }
  }

  private async handleHttp(args: Record<string, unknown>, nonce: string, proto: 'http' | 'http2'): Promise<unknown> {
    const prep = this.prepareCapRequest(args, nonce)
    const started = this.nextHostTimestampMs()
    const signal = AbortSignal.timeout(this.options.callTimeoutMs ?? 30_000)
    try {
      const rawBox: { value: { body: string; headers: Record<string, string> } | null } = { value: null }
      const reqWithRaw: BrokerHttpRequest = { ...prep.applied.brokerRequest, onRawResponse: raw => { rawBox.value = raw } }
      // C-1: Route both HTTP/1.1 and HTTP/2 strictly through RequestBroker (slot/audit/circuit-breaker/admission/H-14).
      const result = proto === 'http2'
        ? await this.options.broker.executeHttp2Exchange(reqWithRaw, prep.applied.grant, signal)
        : await this.options.broker.executeHttp(reqWithRaw, prep.applied.grant, signal)
      this.recordSessionMutation(prep.sessionKey, prep.applied.brokerRequest.method, prep.entityIds, prep.isControlOrAblation, result.status)
      // H-9 / R2-C-9 / R3-H-5: Stamp authoritative host auth placement from injection + wire provenance.
      const { authPlacement, stampedReqMeta } = this.stampPlacement(prep.applied, prep.requestMeta, result.wireCredentialProvenance)
      const kernelHeaders = this.kernelSanitizer.sanitizeHttpHeaders(result.respHeaders, 'storage_log')
      const record = this.transcript.record({
        op: proto, startedAt: started, durationMs: result.durationMs, request: stampedReqMeta, body: result.body,
        ...(prep.applied.brokerRequest.body !== undefined ? { rawRequestBody: this.scrubKernel(prep.applied.brokerRequest.body) } : {}),
        response: {
          status: result.status, headers: kernelHeaders, bodyBytes: result.bodyBytes,
          bodySha256: result.bodySha256, mediaType: result.mediaType, redirectOrigins: result.redirectOrigins,
          ...(result.finalPathAndQuery ? { finalPathAndQuery: this.scrubKernel(result.finalPathAndQuery) } : {}),
        },
      })
      const rawProv = rawBox.value ? { body: rawBox.value.body, respHeaders: rawBox.value.headers } : { body: result.body, respHeaders: result.respHeaders }
      this.recordRequestProvenance(
        record.exchangeId, started, args, prep.applied.brokerRequest, stampedReqMeta, rawProv,
        prep.applied.attestations, prep.cryptoAttestations, prep.cleanSession, prep.applied.authCapabilityActor,
        result.wireCredentialProvenance, authPlacement,
      )
      return this.exchangeView(record, result, {
        consumedCapabilityId: prep.applied.attestation?.consumedCapabilityId ?? null,
        consumedCapabilities: prep.consumedIds,
        derivedFromCapabilityIds: prep.derivedFromCapabilityIds,
        ...(proto === 'http2' ? { protocol: 'h2' as const } : {}),
      })
    } catch (error) {
      const msg = this.scrub(error instanceof Error ? error.message : (proto === 'http2' ? 'HTTP/2 exchange failed.' : 'HTTP exchange failed.'))
      const isPolicyDeny = error instanceof BrokerDenied
        || error instanceof BrokerApprovalRequired
        || (error instanceof EgressDeniedError && error.code !== 'response_too_large')
        || /scope|denied|approval|forbidden|outside|header|kill.?switch/i.test(msg)
      const record = this.transcript.record({ op: proto, startedAt: started, durationMs: Date.now() - started, request: prep.requestMeta, error: msg, errorCode: isPolicyDeny ? 'denied' : 'failed' })
      throw new Error(`${record.exchangeId}: ${msg}`)
    }
  }

  /** C-1: HTTP/2 RPC routes exclusively through RequestBroker.executeHttp2Exchange. */
  private handleHttp2(args: Record<string, unknown>, nonce: string): Promise<unknown> {
    return this.handleHttp(args, nonce, 'http2')
  }

  private resolvePersonaHeaders(grant: Grant, personaHandle: string, origin: string): Record<string, string> {
    const persona = grant.personas?.get(personaHandle)
    if (!persona) throw new Error(`Persona "${personaHandle}" is not approved for this run.`)
    const injected = buildPersonaHeader(persona, origin)
    if (!injected) throw new Error(`Persona "${personaHandle}" does not have an active authenticated session.`)
    return injected
  }

  get browserDriver(): VerifyBrowserDriver | undefined {
    return resolveScopedBrowserDriverForVerify({ explicitDriver: this.options.browser, grant: this.options.grant, runId: this.options.runId, assignmentId: this.options.assignmentId })
  }

  private async handleBrowser(args: Record<string, unknown>, nonce: string): Promise<unknown> {
    const requestedOrigin = typeof args.origin === 'string' && args.origin.length > 0 ? args.origin : this.options.targetOrigins?.[0]
    if (!requestedOrigin) throw new Error('No target origin is configured for this verification session.')
    const rawPath = typeof args.path === 'string' ? args.path : '/'
    const personaHandle = typeof args.persona === 'string' ? args.persona : typeof args.as === 'string' ? args.as : null
    const decision = this.admissionEngine.admit({ kind: 'browser', origin: requestedOrigin, method: 'GET', pathAndQuery: rawPath, personaHandle, surface: 'browser', checkCallerHeaders: false, runId: this.options.runId, assignmentId: this.options.assignmentId }, this.options.grant)
    if (!decision.allowed || !decision.normalizedOrigin || !decision.parsedUrl) throw new Error(decision.reason)
    const origin = decision.normalizedOrigin
    const url = decision.parsedUrl
    const driver = this.browserDriver
    if (!driver) throw new Error('Browser verification is not available for this run.')
    const headers: Record<string, string> = personaHandle ? { ...this.resolvePersonaHeaders(this.options.grant, personaHandle, url.origin) } : {}
    const started = Date.now()
    const recordedHeaders = Object.fromEntries(Object.keys(headers).map(key => [key, '[injected]']))
    const emptySha = createHash('sha256').update('').digest('hex')
    try {
      const timeoutMs = this.options.callTimeoutMs ?? 30_000
      const result = await driver.open({
        url: url.href, origin, personaHandle, headers, timeoutMs,
        ...(typeof args.waitForSelector === 'string' ? { waitForSelector: args.waitForSelector } : {}),
      }, AbortSignal.timeout(timeoutMs))
      const kernelHtml = this.scrubKernel(result.html)
      const htmlSha = createHash('sha256').update(kernelHtml).digest('hex')
      const record = this.transcript.record({
        op: 'browser', startedAt: started, durationMs: Date.now() - started,
        request: { origin, method: 'GET', pathAndQuery: this.scrubKernel(rawPath), headers: recordedHeaders, bodyBytes: 0, bodySha256: emptySha, personaHandle, nonce: this.nonce },
        response: { status: result.status, headers: {}, bodyBytes: Buffer.byteLength(kernelHtml), bodySha256: htmlSha, mediaType: 'text/html' },
        artifact: { kind: 'browser', ...(result.executedSentinels?.length ? { executedSentinels: this.kernelSanitizer.sanitizeValue(result.executedSentinels, 'storage_log') } : {}), domHtmlSha256: htmlSha },
        body: kernelHtml,
      })
      this.rawBodies.set(record.exchangeId, result.html)
      this.getOrCreateProvenance(record.exchangeId, started).timestampMs = started
      return this.egress.sanitizeBrowserResult({
        exchangeId: record.exchangeId, status: result.status, url: result.url, html: redact(this.scrub(result.html)).slice(0, 512 * 1024),
        title: result.title, executedSentinels: result.executedSentinels ?? [], durationMs: record.durationMs,
      })
    } catch (error) {
      const msg = this.scrub(error instanceof Error ? error.message : 'Browser verification failed.')
      const record = this.transcript.record({
        op: 'browser', startedAt: started, durationMs: Date.now() - started,
        request: { origin, method: 'GET', pathAndQuery: this.scrubKernel(rawPath), headers: recordedHeaders, bodyBytes: 0, bodySha256: emptySha, personaHandle, nonce },
        error: msg,
      })
      throw new Error(`${record.exchangeId}: ${msg}`)
    }
  }

  private async handleRace(args: Record<string, unknown>, nonce: string): Promise<unknown> {
    const rawRequests = args.requests
    if (!Array.isArray(rawRequests) || rawRequests.length < 2 || rawRequests.length > 10) {
      throw new Error('race requires between 2 and 10 request objects.')
    }
    const items = rawRequests.map((item, index) => {
      const record = asRecord(item)
      if (!record) throw new Error(`race request ${index + 1} must be an object.`)
      const itemArgs = { sessionGroupRole: 'probe', ...record }
      return { itemArgs, prep: this.prepareCapRequest(itemArgs, nonce) }
    })
    let burstGrant: Grant = this.options.grant
    if (items.some(i => i.prep.applied.grant !== this.options.grant)) {
      const mergedPersonas = new Map(this.options.grant.personas ?? [])
      for (const i of items) for (const [k, v] of i.prep.applied.grant.personas ?? []) mergedPersonas.set(k, v)
      burstGrant = { ...this.options.grant, personas: mergedPersonas }
    }
    const summary = this.options.broker.getTransportSummary()
    const mode = summary.http2 && !summary.proxy
      ? { mode: 'h2-single-packet' as const, fallbackReason: null as string | null }
      : { mode: 'http1-fallback' as const, fallbackReason: summary.proxy ? 'proxy transport disables the HTTP/2 single-packet barrier' : 'HTTP/2 transport is unavailable; the burst runs on the HTTP/1.1 fallback' }
    const started = this.nextHostTimestampMs()
    try {
      const rawCaptures: Array<{ body: string; headers: Record<string, string> } | null> = items.map(() => null)
      const burst = await this.options.broker.executeRaceBurst(
        items.map((i, idx) => ({ ...i.prep.applied.brokerRequest, onRawResponse: raw => { rawCaptures[idx] = raw } })),
        burstGrant,
        AbortSignal.timeout(this.options.callTimeoutMs ?? 30_000),
      )
      const results = burst.results.map((result, index) => {
        const { itemArgs, prep } = items[index]!
        this.recordSessionMutation(prep.sessionKey, prep.applied.brokerRequest.method, prep.entityIds, prep.isControlOrAblation, result.status)
        const { authPlacement, stampedReqMeta } = this.stampPlacement(prep.applied, prep.requestMeta, result.wireCredentialProvenance)
        const record = this.transcript.record({
          op: mode.mode === 'h2-single-packet' ? 'http2' : 'http',
          startedAt: started, durationMs: result.durationMs, request: stampedReqMeta, body: result.body,
          ...(prep.applied.brokerRequest.body !== undefined ? { rawRequestBody: this.scrubKernel(prep.applied.brokerRequest.body) } : {}),
          response: { status: result.status, headers: this.kernelSanitizer.sanitizeHttpHeaders(result.respHeaders, 'storage_log'), bodyBytes: result.bodyBytes, bodySha256: result.bodySha256, mediaType: result.mediaType },
        })
        const capRaw = rawCaptures[index]
        this.recordRequestProvenance(
          record.exchangeId, started, itemArgs, prep.applied.brokerRequest, stampedReqMeta,
          capRaw ? { body: capRaw.body, respHeaders: capRaw.headers } : { body: result.body, respHeaders: result.respHeaders },
          prep.applied.attestations, prep.cryptoAttestations, prep.cleanSession, prep.applied.authCapabilityActor,
          result.wireCredentialProvenance, authPlacement,
        )
        return this.exchangeView(record, result, {
          consumedCapabilityId: prep.applied.attestation?.consumedCapabilityId ?? null,
          consumedCapabilities: prep.consumedIds,
          derivedFromCapabilityIds: prep.derivedFromCapabilityIds,
        })
      })
      return this.scrubRecord({ mode: mode.mode, fallbackReason: mode.fallbackReason, summary: burst.summary, results })
    } catch (error) {
      const msg = this.scrub(error instanceof Error ? error.message : 'Race burst failed.')
      const record = this.transcript.record({
        op: 'race', startedAt: started, durationMs: Date.now() - started, request: items[0]!.prep.requestMeta,
        error: msg, errorCode: /scope|denied|approval|forbidden|outside|header|tier/i.test(msg) ? 'denied' : 'failed',
      })
      throw new Error(`${record.exchangeId}: ${msg}`)
    }
  }

  /** Fail-closed lookup ensuring OOB tokens/ids belong to this session, run, and attempt. */
  private requireSessionCanary(args: Record<string, unknown>, action: string) {
    const raw = typeof args.token === 'string' ? args.token.trim().toLowerCase() : ''
    if (!raw) throw new Error(`oob ${action} requires a canary token.`)
    const entry = this.mintedCanaries.get(raw)
    if (!entry) throw new Error(`oob ${action} rejected: canary token was not minted in this verification session.`)
    if (entry.runId !== this.options.runId || entry.attemptId !== this.nonce) {
      throw new Error(`oob ${action} rejected: canary token does not belong to this run/attempt.`)
    }
    for (const [field, expected] of [['runId', entry.runId], ['attemptId', entry.attemptId], ['canaryId', entry.canaryId]] as const) {
      const provided = typeof args[field] === 'string' ? args[field].trim() : ''
      if (provided && provided !== expected) throw new Error(`oob ${action} rejected: ${field} mismatch.`)
    }
    return entry
  }

  /** Consume only the requested canary's promotion; buffer sibling session promotions instead of discarding them. */
  private takeOobPromotion(canary: VerifyCanaryBroker, normalizedToken: string, subscriptionId: string | null, canPromote: boolean): VerifyOobPromotionView | undefined {
    const matches = (item: VerifyOobPromotionView): boolean => {
      const itemToken = typeof item.subscription.token === 'string' ? item.subscription.token.trim().toLowerCase() : ''
      if (itemToken) return itemToken === normalizedToken && (!subscriptionId || !item.subscription.id || item.subscription.id === subscriptionId)
      return Boolean(subscriptionId && item.subscription.id === subscriptionId)
    }
    const bufferedIdx = this.bufferedOobPromotions.findIndex(matches)
    if (bufferedIdx >= 0) return this.bufferedOobPromotions.splice(bufferedIdx, 1)[0]
    if (!canPromote || !canary.promoteLate) return undefined
    let promotions: VerifyOobPromotionView[] = []
    try { promotions = canary.promoteLate({ runId: this.options.runId }) ?? [] } catch { return undefined }
    let matched: VerifyOobPromotionView | undefined
    for (const item of promotions) {
      if (!matched && matches(item)) { matched = item; continue }
      const itemToken = typeof item.subscription.token === 'string' ? item.subscription.token.trim().toLowerCase() : ''
      const owned = itemToken ? this.mintedCanaries.has(itemToken) : Boolean(item.subscription.id && this.sessionOobSubscriptions.has(item.subscription.id))
      if (owned && !this.bufferedOobPromotions.some(p => p.subscription.id === item.subscription.id)) this.bufferedOobPromotions.push(item)
    }
    return matched
  }

  private async handleOob(args: Record<string, unknown>): Promise<unknown> {
    const canary = this.options.canary ?? (this.options.grant as Grant & { canaryBroker?: VerifyCanaryBroker }).canaryBroker
    if (!canary) throw new Error('OOB canaries are not available for this run.')
    const action = typeof args.action === 'string' ? args.action : 'mint'
    if (action === 'mint') {
      const label = typeof args.label === 'string' ? args.label.slice(0, 80) : 'verify'
      const origin = typeof args.origin === 'string' && args.origin ? args.origin : this.options.targetOrigins?.[0]
      const started = Date.now()
      const minted = canary.mintCanary(this.options.runId, label, origin, { assignmentId: this.options.assignmentId }) as ReturnType<VerifyCanaryBroker['mintCanary']> & { id?: string }
      const normalizedToken = minted.token.trim().toLowerCase()
      if (!normalizedToken) throw new Error('OOB canary broker returned an empty token.')
      const canaryId = typeof minted.id === 'string' && minted.id ? minted.id : normalizedToken
      this.mintedCanaries.set(normalizedToken, { token: minted.token, canaryId, runId: this.options.runId, attemptId: this.nonce, mintedAtMs: started })
      const record = this.transcript.record({
        op: 'oob',
        startedAt: started,
        durationMs: Date.now() - started,
        request: { origin: origin ?? '', method: 'MINT', pathAndQuery: '/', headers: {}, bodyBytes: 0, bodySha256: createHash('sha256').update('').digest('hex'), nonce: this.nonce },
        artifact: { kind: 'oob-mint', token: minted.token, url: minted.httpUrl, dnsHost: minted.dnsHost, hit: false },
      })
      return this.scrubRecord({ exchangeId: record.exchangeId, token: minted.token, url: minted.httpUrl, dnsHost: minted.dnsHost, ...(minted.id ? { canaryId: minted.id } : {}) })
    }
    if (action === 'subscribe') {
      const entry = this.requireSessionCanary(args, 'subscribe')
      const token = entry.token.trim().toLowerCase()
      if (!canary.subscribe) throw new Error('OOB relay does not expose durable pending_oob subscriptions; a late callback cannot be promoted.')
      const artifact = typeof args.artifact === 'string' ? args.artifact : ''
      const immediateMs = typeof args.immediateMs === 'number' ? Math.max(0, Math.min(args.immediateMs, 30_000)) : undefined
      const windowMs = typeof args.windowMs === 'number' ? Math.max(1_000, Math.min(args.windowMs, 30 * 60_000)) : undefined
      const started = Date.now()
      const subscription = canary.subscribe({
        runId: this.options.runId,
        assignmentId: this.options.assignmentId,
        canaryId: entry.canaryId,
        token: entry.token,
        artifact,
        ...(immediateMs !== undefined ? { immediateMs } : {}),
        ...(windowMs !== undefined ? { windowMs } : {}),
      })
      this.sessionOobSubscriptions.set(subscription.id, { token, canaryId: entry.canaryId })
      this.transcript.record({
        op: 'oob',
        startedAt: started,
        durationMs: Date.now() - started,
        request: { origin: '', method: 'SUBSCRIBE', pathAndQuery: `/oob/pending/${subscription.id}`, headers: {}, bodyBytes: 0, bodySha256: createHash('sha256').update(subscription.id).digest('hex'), nonce: this.nonce },
        artifact: { kind: 'oob-mint', token: entry.token, hit: false },
      })
      return this.scrubRecord({
        subscriptionId: subscription.id, token: entry.token, status: subscription.status ?? 'pending',
        createdAt: subscription.createdAt ?? started, expiresAt: subscription.expiresAt ?? null,
        immediateMs: subscription.immediateMs ?? immediateMs ?? null, windowMs: subscription.windowMs ?? windowMs ?? null,
      })
    }
    if (action === 'wait') {
      const entry = this.requireSessionCanary(args, 'wait')
      const token = entry.token.trim().toLowerCase()
      const subscriptionId = typeof args.subscriptionId === 'string' && args.subscriptionId.trim() ? args.subscriptionId.trim() : null
      if (subscriptionId && this.sessionOobSubscriptions.get(subscriptionId)?.token !== token) {
        throw new Error('oob wait rejected: subscriptionId does not belong to this session canary.')
      }
      const subscriptionCreatedAt = typeof args.subscriptionCreatedAt === 'number' ? args.subscriptionCreatedAt : null
      const immediateMs = typeof args.immediateMs === 'number' ? Math.max(0, Math.min(args.immediateMs, 30_000)) : 3_000
      const timeoutMs = typeof args.timeoutMs === 'number' ? Math.max(0, Math.min(args.timeoutMs, 60_000)) : immediateMs
      const immediateDeadline = (subscriptionCreatedAt ?? Date.now()) + immediateMs
      const t0 = Date.now()
      let check = canary.checkCanary(entry.token, { runId: this.options.runId })
      let callbackReceivedAt: number | null = null
      let promoted = false
      let matched = check.hit
      if (!matched && canary.awaitAny) {
        try {
          const awaited = await canary.awaitAny({ token: entry.token, runId: this.options.runId }, { timeoutMs, pollMs: 100 })
          matched = awaited.matched
          callbackReceivedAt = awaited.callback?.receivedAt ?? null
        } catch { /* fall through to the recorded in-memory check */ }
      }
      const promotion = this.takeOobPromotion(canary, token, subscriptionId, matched || !canary.awaitAny)
      if (promotion) {
        promoted = true
        matched = true
        callbackReceivedAt = callbackReceivedAt ?? promotion.callback.receivedAt ?? null
      }
      check = canary.checkCanary(entry.token, { runId: this.options.runId })
      const hit = Boolean(matched || check.hit)
      const receivedAt = callbackReceivedAt ?? (typeof check.detail?.timestamp === 'number' ? check.detail.timestamp : null)
      const stage: 'immediate' | 'late' | 'pending' | 'none' = hit
        ? (receivedAt !== null && receivedAt > immediateDeadline ? 'late' : 'immediate')
        : (subscriptionId ? 'pending' : 'none')
      const record = this.transcript.record({
        op: 'oob',
        startedAt: t0,
        durationMs: Date.now() - t0,
        request: { origin: '', method: 'WAIT', pathAndQuery: subscriptionId ? `/oob/pending/${subscriptionId}` : '/oob/wait', headers: {}, bodyBytes: 0, bodySha256: createHash('sha256').update(token).digest('hex'), nonce: this.nonce },
        artifact: { kind: 'oob-mint', token: entry.token, hit },
      })
      return this.scrubRecord({
        exchangeId: record.exchangeId, checkExchangeId: record.exchangeId,
        subscriptionId: promotion?.subscription.id ?? subscriptionId, token: entry.token,
        hit, stage, promoted, receivedAt, hits: check.hits.slice(-5),
      })
    }
    if (action === 'check') {
      const entry = this.requireSessionCanary(args, 'check')
      const token = entry.token
      const id = typeof args.exchangeId === 'string' ? args.exchangeId : ''
      const record = id ? this.transcript.get(id) : undefined
      const result = canary.checkCanary(token, { runId: this.options.runId })
      if (record && record.op === 'oob' && record.artifact?.token === token) {
        // The mint record is signed before the hit is known; a check appends a correlated
        // record so the transcript remains append-only and tamper-evident.
        const started = Date.now()
        const check = this.transcript.record({
          op: 'oob',
          startedAt: started,
          durationMs: 0,
          request: { origin: '', method: 'CHECK', pathAndQuery: '/', headers: {}, bodyBytes: 0, bodySha256: createHash('sha256').update('').digest('hex'), nonce: this.nonce },
          artifact: { kind: 'oob-mint', token, hit: result.hit },
        })
        return this.scrubRecord({ exchangeId: record.exchangeId, checkExchangeId: check.exchangeId, token, hit: result.hit, hits: result.hits.slice(-5) })
      }
      return this.scrubRecord({ token, hit: result.hit, hits: result.hits.slice(-5) })
    }
    throw new Error('Unsupported oob action.')
  }

  private extractSecretFromExchange(exchangeId: string, args: Record<string, unknown>): { rawValue: string; selector: 'jsonPath' | 'header' | 'cookie' | 'value'; defaultCookieName?: string; isLocationQuery?: boolean } {
    if (args.regex !== undefined) throw new Error(SEAL_REGEX_RETIRED_ERROR)
    const rawBody = this.rawBodies.get(exchangeId) ?? this.transcript.body(exchangeId) ?? ''
    const record = this.transcript.get(exchangeId)
    const rawHeaders = this.rawResponseHeaders.get(exchangeId) ?? record?.response?.headers ?? {}
    const artifactText = record?.artifact?.token ?? record?.artifact?.url ?? ''
    if (typeof args.jsonPath === 'string' && args.jsonPath.trim()) {
      let parsed: unknown
      try { parsed = JSON.parse(rawBody.replace(/^\uFEFF/, '')) } catch { throw new Error(SEAL_FIELD_NOT_FOUND_ERROR) }
      const evalRes = resolveSealJsonPath(parsed, args.jsonPath.trim(), evaluateJsonPath)
      if (!evalRes.found || evalRes.value === undefined || evalRes.value === null || typeof evalRes.value === 'object') throw new Error(SEAL_FIELD_NOT_FOUND_ERROR)
      const extracted = typeof evalRes.value === 'string' ? evalRes.value : String(evalRes.value)
      if (!extracted) throw new Error(SEAL_FIELD_NOT_FOUND_ERROR)
      return { rawValue: extracted, selector: 'jsonPath' }
    }
    const locParam = typeof args.locationQuery === 'string' && args.locationQuery.trim() ? args.locationQuery.trim() : (typeof args.queryParam === 'string' && args.queryParam.trim() ? args.queryParam.trim() : '')
    if (locParam) {
      const loc = Object.entries(rawHeaders).find(([k]) => k.toLowerCase() === 'location')?.[1]?.trim() ?? ''
      let parsedUrl: URL | null = null
      if (loc) { try { parsedUrl = new URL(loc, 'http://kovo-local.invalid') } catch { parsedUrl = null } }
      const val = parsedUrl?.searchParams.get(locParam) || (parsedUrl && parsedUrl.hash.length > 1 ? new URLSearchParams(parsedUrl.hash.slice(1)).get(locParam) : null)
      if (!val) throw new Error(SEAL_FIELD_NOT_FOUND_ERROR)
      return { rawValue: val, selector: 'header', isLocationQuery: true }
    }
    if (typeof args.header === 'string' && args.header.trim()) {
      const wanted = args.header.trim().toLowerCase()
      const entry = Object.entries(rawHeaders).find(([k]) => k.toLowerCase() === wanted)
      if (!entry || !entry[1] || !entry[1].trim()) throw new Error(SEAL_FIELD_NOT_FOUND_ERROR)
      return { rawValue: entry[1], selector: 'header' }
    }
    const cookieName = typeof args.setCookie === 'string' && args.setCookie.trim() ? args.setCookie.trim() : (typeof args.cookie === 'string' && args.cookie.trim() ? args.cookie.trim() : '')
    if (cookieName) {
      const setCookie = Object.entries(rawHeaders).find(([k]) => k.toLowerCase() === 'set-cookie')?.[1] ?? ''
      for (const rawEntry of setCookie.split(/\r?\n/).flatMap(line => line.split(/,\s*(?=[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)/))) {
        const firstPart = rawEntry.split(';', 1)[0]?.trim() ?? ''
        const eq = firstPart.indexOf('=')
        if (eq > 0 && firstPart.slice(0, eq).trim() === cookieName) {
          const val = firstPart.slice(eq + 1).trim()
          if (val) return { rawValue: val, selector: 'cookie', defaultCookieName: cookieName }
        }
      }
      throw new Error(SEAL_FIELD_NOT_FOUND_ERROR)
    }
    const candidateRaw = typeof args.value === 'string' ? args.value : typeof args.rawValue === 'string' ? args.rawValue : null
    if (candidateRaw !== null && candidateRaw.length > 0) {
      const visibleHeaders = Object.values(this.egress.sanitizeHttpHeaders(rawHeaders, 'worker_rpc'))
      if (![this.scrub(rawBody), ...visibleHeaders, artifactText].join('\n').includes(candidateRaw)) throw new Error(SEAL_FIELD_NOT_FOUND_ERROR)
      return { rawValue: candidateRaw, selector: 'value' }
    }
    throw new Error(SEAL_FIELD_NOT_FOUND_ERROR)
  }

  private handleCapabilitySeal(args: Record<string, unknown>, nonce: string): unknown {
    const exchangeId = typeof args.exchangeId === 'string' ? args.exchangeId.trim() : ''
    if (!exchangeId) throw new Error('capability.seal requires exchangeId referencing a host-recorded exchange.')
    const sourceRecord = this.transcript.get(exchangeId)
    if (!sourceRecord) throw new Error(`Unknown exchangeId "${exchangeId}" for capability.seal.`)

    // Validate arguments BEFORE consuming run/endpoint/exchange budget so malformed/retired calls never drain budget.
    const requestedSlot = typeof args.slot === 'string' ? args.slot.trim() : ''
    if (!requestedSlot) throw new Error('capability.seal requires a non-empty slot name.')
    const hopReceiptId = typeof args.hopReceiptId === 'string' && args.hopReceiptId.trim() ? args.hopReceiptId.trim() : typeof args.hopId === 'string' && args.hopId.trim() ? args.hopId.trim() : exchangeId
    const slot = this.resolveImmutableSlot(hopReceiptId, requestedSlot)
    formatDerivedHandle(hopReceiptId, slot)
    const kind = normalizeDerivedSecretKind(args.kind)
    const ttlMs = args.ttlMs === null ? null : typeof args.ttlMs === 'number' ? args.ttlMs : undefined
    if (ttlMs !== undefined && ttlMs !== null && (!Number.isFinite(ttlMs) || ttlMs < 0)) throw new Error('capability.seal ttlMs must be a non-negative finite number or null.')
    const allowedOrigins = Array.isArray(args.allowedOrigins) ? args.allowedOrigins.filter((v): v is string => typeof v === 'string' && v.trim().length > 0) : undefined
    if (args.regex !== undefined) throw new Error(SEAL_REGEX_RETIRED_ERROR)
    const hasStr = (v: unknown) => typeof v === 'string' && v.trim().length > 0
    const hasVal = (typeof args.value === 'string' && args.value.length > 0) || (typeof args.rawValue === 'string' && args.rawValue.length > 0)
    if (!hasStr(args.jsonPath) && !hasStr(args.header) && !hasStr(args.cookie) && !hasStr(args.setCookie) && !hasStr(args.locationQuery) && !hasStr(args.queryParam) && !hasVal) {
      throw new Error('capability.seal requires a selector: jsonPath, header, setCookie (or cookie), locationQuery (or queryParam), or value.')
    }

    const endpointPath = (sourceRecord.request?.pathAndQuery ?? '/').split('?')[0]
    const endpointKey = `${sourceRecord.request?.origin ?? ''}|${endpointPath}|${sourceRecord.request?.personaHandle ?? ''}`
    consumeRunSealBudget(this.options.runId, endpointKey, {
      maxPerRun: this.options.maxSealsPerRun ?? this.options.safetyBudgets?.maxSealsPerRun,
      maxPerEndpoint: this.options.maxSealsPerEndpoint ?? this.options.safetyBudgets?.maxSealsPerEndpoint,
    })
    this.totalSealAttempts = checkSealRateLimit(
      this.sealAttemptsByExchange, exchangeId, this.totalSealAttempts,
      { maxPerExchange: this.options.maxSealsPerExchange },
    )

    const { rawValue, selector, defaultCookieName: extractedCookie, isLocationQuery } = this.extractSecretFromExchange(exchangeId, args)
    try { validateCapabilitySealValue(rawValue, selector) } catch { throw new Error(SEAL_FIELD_NOT_FOUND_ERROR) }
    const defaultHeaderName = typeof args.defaultHeaderName === 'string' && args.defaultHeaderName.trim() ? args.defaultHeaderName.trim() : undefined
    const defaultCookieName = typeof args.defaultCookieName === 'string' && args.defaultCookieName.trim() ? args.defaultCookieName.trim() : extractedCookie
    // C-3: Derive `kind` strictly from validated structural args — NEVER inspect `rawValue`.
    const effectiveKind = kind ?? (selector === 'cookie' || defaultCookieName ? 'cookie' : ((selector === 'header' && !isLocationQuery) || defaultHeaderName ? 'header_secret' : 'generic_secret'))
    const srcRoleLabel = sourceRecord.request?.actorRoleLabel ?? null
    const srcPersona = sourceRecord.request?.personaHandle ?? null
    const srcParsed = parseRoleLabel(srcRoleLabel)
    const sourceProvenance: CapabilitySourceProvenance = {
      sourceExchangeId: exchangeId,
      sourcePersonaHandle: srcPersona,
      sourceActorRoleLabel: srcRoleLabel,
      sourceActorRole: srcRoleLabel !== null ? (normalizeRole(srcRoleLabel) ?? normalizeRole(srcPersona) ?? null) : (normalizeRole(srcPersona) ?? null),
      sourceActorTenant: srcParsed.tenant ?? parseRoleLabel(srcPersona).tenant ?? null,
    }
    const meta = this.capabilityVault.seal({
      hopReceiptId, slot, rawValue, kind: effectiveKind,
      ...(ttlMs !== undefined ? { ttlMs } : {}),
      ...(defaultHeaderName ? { defaultHeaderName } : {}), ...(defaultCookieName ? { defaultCookieName } : {}),
      ...(allowedOrigins?.length ? { allowedOrigins } : {}),
      sourceProvenance,
    })
    this.sessionSealedHandles.add(`cap:hop_${hopReceiptId}:${requestedSlot}`)
    this.sessionSealedHandles.add(meta.handle)

    // H-9: Attach host-side provenance & backfill later requests WITHOUT rewriting raw kernel TranscriptStore bodies.
    const sourceProv = this.getOrCreateProvenance(exchangeId, sourceRecord.startedAt)
    sourceProv.emittedCapabilities.add(meta.handle); sourceProv.observedResponseDigests.add(meta.sha256)
    for (const [exId, exProv] of this.exchangeProvenance.entries()) {
      if (exId === exchangeId || exProv.timestampMs < sourceRecord.startedAt || !exProv.rawRequestParts?.length) continue
      const hits = this.capabilityVault.matchSealedHandlesInRequest({ runId: this.capabilityVault.runId, targetOrigin: exProv.rawRequestOrigin, parts: exProv.rawRequestParts })
      if (hits.some(h => h.handleId === meta.handle)) { exProv.consumedCapabilities.add(meta.handle); exProv.injectedRequestDigests.add(meta.sha256) }
    }

    const started = this.nextHostTimestampMs()
    const opaqueHandleDigest = createHash('sha256').update(`${this.compositeSigningKey}:${meta.handle}`).digest('hex')
    const sealRecord = this.transcript.record({
      op: 'capability', startedAt: started, durationMs: 0,
      request: {
        origin: sourceRecord.request?.origin ?? '', method: 'SEAL', pathAndQuery: `/capability/seal/${encodeURIComponent(slot)}`,
        headers: {}, bodyBytes: 0, bodySha256: opaqueHandleDigest, personaHandle: sourceRecord.request?.personaHandle ?? null,
        sessionRole: sourceRecord.request?.sessionRole ?? 'probe', actorRoleLabel: sourceRecord.request?.actorRoleLabel ?? null, nonce,
      },
      artifact: { kind: 'capability', capabilityHandle: meta.handle, artifactDigest: opaqueHandleDigest },
    })
    const sealProv = this.getOrCreateProvenance(sealRecord.exchangeId, started)
    sealProv.emittedCapabilities.add(meta.handle); sealProv.observedResponseDigests.add(meta.sha256)
    // R2-H-4: Redact FULL raw text BEFORE slicing so secrets crossing byte 1024 never leak prefixes.
    const scrubbedPreview = redact(this.scrub(this.rawBodies.get(exchangeId) ?? '')).slice(0, 1024)
    return this.scrubRecord({ handle: meta.handle, meta: toPublicCapabilityMeta(meta), exchangeId, sealExchangeId: sealRecord.exchangeId, scrubbedPreview })
  }

  private handleCryptoHmacSign(args: Record<string, unknown>, nonce: string): unknown {
    const secretHandle = typeof args.secretHandle === 'string' ? args.secretHandle.trim() : ''
    const literalKey = typeof args.literalKey === 'string' ? args.literalKey : ''
    if (secretHandle && literalKey) throw new Error('crypto.hmacSign accepts either secretHandle or literalKey, not both.')
    if (!secretHandle && !literalKey) throw new Error('crypto.hmacSign requires secretHandle (or explicit non-secret literalKey).')
    const payload = typeof args.payload === 'string' ? args.payload : ''
    if (typeof args.payload !== 'string') throw new Error('crypto.hmacSign requires a string payload.')
    const alg = (typeof args.alg === 'string' ? args.alg.trim().toLowerCase() : 'sha256') as HostHmacAlg
    const encoding = (typeof args.encoding === 'string' ? args.encoding.trim().toLowerCase() : 'hex') as HostHmacEncoding
    if (alg !== 'sha256' && alg !== 'sha384' && alg !== 'sha512') throw new Error(`Unsupported HMAC alg "${String(alg)}".`)
    if (encoding !== 'hex' && encoding !== 'base64' && encoding !== 'base64url') throw new Error(`Unsupported HMAC encoding "${String(encoding)}".`)
    // R2-C-4: Charge run-scoped seal budget for every HMAC signing request.
    consumeRunSealBudget(this.options.runId, undefined, { maxPerRun: this.options.maxSealsPerRun ?? this.options.safetyBudgets?.maxSealsPerRun })

    if (!secretHandle) {
      const lit = computeNonSecretLiteralHmac({ literalKey, payload, alg, encoding, isRedacted: v => this.scrub(v) !== v, vault: this.capabilityVault })
      const ts = this.nextHostTimestampMs()
      const record = this.transcript.record({
        op: 'crypto', startedAt: ts, durationMs: 0,
        request: { origin: this.options.targetOrigins?.[0] ?? '', method: 'HMAC_SIGN', pathAndQuery: `/crypto/hmac/${alg}`, headers: {}, bodyBytes: Buffer.byteLength(payload), bodySha256: lit.payloadDigest, personaHandle: null, sessionRole: 'probe', actorRoleLabel: null, nonce },
        artifact: { kind: 'crypto', alg, artifactDigest: lit.signatureDigest },
      })
      return this.scrubRecord({
        exchangeId: record.exchangeId, signature: lit.signature, literalKeyUsed: true,
        attestation: { alg, encoding, payloadDigest: lit.payloadDigest, runId: this.capabilityVault.runId, timestampMs: ts },
      })
    }

    // R2-C-4: Sealed capability custody path — enforce key entropy floor and return ONLY an opaque derived handle (NEVER raw HMAC output!).
    const ttlMs = args.ttlMs === null ? null : typeof args.ttlMs === 'number' ? args.ttlMs : undefined
    const allowedOrigins = Array.isArray(args.allowedOrigins) ? args.allowedOrigins.filter((v): v is string => typeof v === 'string' && v.trim().length > 0) : undefined
    const requestedHopId = typeof args.hopReceiptId === 'string' && args.hopReceiptId.trim() ? args.hopReceiptId.trim() : undefined
    const requestedSlot = typeof args.slot === 'string' && args.slot.trim() ? args.slot.trim() : undefined
    const sourceMeta = this.capabilityVault.getMeta(secretHandle)
    const effectiveHopId = requestedHopId ?? sourceMeta?.hopReceiptId
    const effectiveSlot = requestedSlot && effectiveHopId
      ? this.resolveImmutableSlot(effectiveHopId, requestedSlot)
      : (requestedSlot ?? `hmac_${randomBytes(6).toString('hex')}`)

    const signed = this.capabilityVault.hostHmacSign({
      secretHandle, payload, alg, encoding, runId: this.capabilityVault.runId,
      ...(requestedHopId ? { hopReceiptId: requestedHopId } : {}), slot: effectiveSlot,
      ...(ttlMs !== undefined ? { ttlMs } : {}), ...(allowedOrigins?.length ? { allowedOrigins } : {}),
      sealOutput: true, enforceKeyEntropy: true,
    })
    const derivedHandle = signed.derivedHandle!
    if (requestedSlot && effectiveHopId) this.sessionSealedHandles.add(`cap:hop_${effectiveHopId}:${requestedSlot}`)
    this.sessionSealedHandles.add(derivedHandle)
    const ts = this.nextHostTimestampMs()
    const hostAttestation: HostCryptoAttestation = {
      derivedFromCapabilityId: signed.attestation.derivedFromCapabilityId,
      derivedCapabilityId: derivedHandle,
      alg: signed.attestation.alg,
      artifactDigest: signed.attestation.signatureDigest,
      timestampMs: ts,
    }
    this.jwtDerivations.set(derivedHandle, hostAttestation)
    this.hmacDerivations.set(signed.signature, hostAttestation)
    const opaqueHandleDigest = createHash('sha256').update(`${this.compositeSigningKey}:${derivedHandle}`).digest('hex')

    const record = this.transcript.record({
      op: 'crypto', startedAt: ts, durationMs: 0,
      request: {
        origin: this.options.targetOrigins?.[0] ?? '', method: 'HMAC_SIGN', pathAndQuery: `/crypto/hmac/${alg}`,
        headers: {}, bodyBytes: Buffer.byteLength(payload), bodySha256: signed.attestation.payloadDigest,
        personaHandle: null, sessionRole: 'probe', actorRoleLabel: null,
        derivedFromCapabilityId: signed.attestation.derivedFromCapabilityId, nonce,
      },
      artifact: {
        kind: 'crypto', derivedFromCapabilityId: signed.attestation.derivedFromCapabilityId,
        derivedCapabilityId: derivedHandle, alg: signed.attestation.alg, artifactDigest: opaqueHandleDigest,
      },
    })
    const prov = this.getOrCreateProvenance(record.exchangeId, ts)
    prov.emittedCapabilities.add(derivedHandle)
    prov.cryptoAttestations.push(hostAttestation)
    prov.observedResponseDigests.add(signed.attestation.signatureDigest)
    prov.cleanSession = true

    const { sourceSecretDigest: _omitSrc, signatureDigest: _omitSig, ...publicAtt } = signed.attestation
    return this.scrubRecord({
      exchangeId: record.exchangeId,
      derivedHandle,
      handle: derivedHandle,
      attestation: { ...publicAtt, derivedCapabilityId: derivedHandle, timestampMs: ts },
    })
  }

  private handleCryptoJwtSign(args: Record<string, unknown>, nonce: string): unknown {
    const secretHandle = typeof args.secretHandle === 'string' ? args.secretHandle.trim() : ''
    if (!secretHandle) throw new Error('crypto.jwtSign requires secretHandle.')
    const claims = asRecord(args.claims)
    if (!claims) throw new Error('crypto.jwtSign requires a plain claims object.')
    const header = args.header !== undefined ? asRecord(args.header) : undefined
    if (args.header !== undefined && !header) throw new Error('crypto.jwtSign header must be a plain object.')
    const alg = (typeof args.alg === 'string' ? args.alg.trim().toUpperCase() : 'HS256') as HostJwtAlg
    if (alg !== 'HS256' && alg !== 'HS384' && alg !== 'HS512') throw new Error(`Unsupported JWT HMAC alg "${String(alg)}".`)
    if (header?.alg !== undefined && header.alg !== alg) throw new Error('JWT header.alg must match options.alg.')
    const ttlMs = args.ttlMs === null ? null : typeof args.ttlMs === 'number' ? args.ttlMs : undefined
    const allowedOrigins = Array.isArray(args.allowedOrigins)
      ? args.allowedOrigins.filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
      : undefined
    const requestedHopId = typeof args.hopReceiptId === 'string' && args.hopReceiptId.trim() ? args.hopReceiptId.trim() : undefined
    const requestedSlot = typeof args.slot === 'string' && args.slot.trim() ? args.slot.trim() : undefined
    consumeRunSealBudget(this.options.runId, undefined, { maxPerRun: this.options.maxSealsPerRun ?? this.options.safetyBudgets?.maxSealsPerRun })
    const sourceMeta = this.capabilityVault.getMeta(secretHandle)
    const effectiveHopId = requestedHopId ?? sourceMeta?.hopReceiptId
    const effectiveSlot = requestedSlot && effectiveHopId
      ? this.resolveImmutableSlot(effectiveHopId, requestedSlot)
      : (requestedSlot ?? `jwt_${randomBytes(6).toString('hex')}`)

    const minted = this.capabilityVault.hostJwtSign({
      secretHandle, claims, ...(header ? { header } : {}), alg,
      ...(requestedHopId ? { hopReceiptId: requestedHopId } : {}), slot: effectiveSlot,
      ...(ttlMs !== undefined ? { ttlMs } : {}), ...(allowedOrigins?.length ? { allowedOrigins } : {}),
      runId: this.capabilityVault.runId, enforceKeyEntropy: true,
    })
    if (requestedSlot && effectiveHopId) this.sessionSealedHandles.add(`cap:hop_${effectiveHopId}:${requestedSlot}`)
    this.sessionSealedHandles.add(minted.derivedHandle)
    const ts = this.nextHostTimestampMs()
    const hostAttestation: HostCryptoAttestation = {
      derivedFromCapabilityId: minted.attestation.derivedFromCapabilityId,
      derivedCapabilityId: minted.derivedHandle,
      alg: minted.attestation.alg,
      artifactDigest: minted.attestation.tokenDigest,
      timestampMs: ts,
    }
    this.jwtDerivations.set(minted.derivedHandle, hostAttestation)
    const opaqueHandleDigest = createHash('sha256').update(`${this.compositeSigningKey}:${minted.derivedHandle}`).digest('hex')

    const record = this.transcript.record({
      op: 'crypto', startedAt: ts, durationMs: 0,
      request: {
        origin: this.options.targetOrigins?.[0] ?? '', method: 'JWT_SIGN', pathAndQuery: `/crypto/jwt/${alg}`,
        headers: {}, bodyBytes: 0, bodySha256: minted.attestation.claimsDigest,
        personaHandle: null, sessionRole: 'probe', actorRoleLabel: null,
        derivedFromCapabilityId: minted.attestation.derivedFromCapabilityId, nonce,
      },
      artifact: {
        kind: 'crypto', derivedFromCapabilityId: minted.attestation.derivedFromCapabilityId,
        derivedCapabilityId: minted.derivedHandle, alg: minted.attestation.alg, artifactDigest: opaqueHandleDigest,
      },
    })
    const prov = this.getOrCreateProvenance(record.exchangeId, ts)
    prov.emittedCapabilities.add(minted.derivedHandle)
    prov.observedResponseDigests.add(minted.attestation.tokenDigest)
    prov.cryptoAttestations.push(hostAttestation)
    prov.cleanSession = true

    const { sourceSecretDigest: _omitJwtSrc, tokenDigest: _omitJwtTok, ...publicJwtAttestation } = minted.attestation
    return this.scrubRecord({
      exchangeId: record.exchangeId,
      derivedHandle: minted.derivedHandle,
      attestation: { ...publicJwtAttestation, timestampMs: ts },
    })
  }

  private async handleAsyncAwaitResult(args: Record<string, unknown>, nonce: string): Promise<unknown> {
    const pollReqArgs = asRecord(args.pollRequest ?? args.request)
    if (!pollReqArgs) throw new Error('async.awaitResult requires a pollRequest object.')
    const matchPredicate = args.matchPredicate !== undefined ? asRecord(args.matchPredicate)
      : args.match !== undefined ? asRecord(args.match) : null
    // R3-H-2: Validate & compile regex predicates via safe-regex BEFORE consuming budget or issuing traffic.
    const compiledPredicate = compileAsyncMatchPredicate(matchPredicate)
    const profile: AsyncPollProfile | undefined = args.profile === 'fast_lab' || args.profile === 'wan' ? args.profile : undefined
    const timeoutMs = typeof args.timeoutMs === 'number' ? args.timeoutMs : undefined
    const intervalMs = typeof args.intervalMs === 'number' ? args.intervalMs : undefined
    const maxAttempts = typeof args.maxAttempts === 'number' ? args.maxAttempts : undefined

    const triggerExchangeId = typeof args.triggerExchangeId === 'string' && args.triggerExchangeId.trim()
      ? args.triggerExchangeId.trim()
      : undefined
    let tTriggerMs: number | undefined
    if (triggerExchangeId) {
      const triggerRec = this.transcript.get(triggerExchangeId)
      if (!triggerRec) throw new Error(`Unknown triggerExchangeId "${triggerExchangeId}" for async.awaitResult.`)
      tTriggerMs = triggerRec.startedAt
    } else if (typeof args.tTriggerMs === 'number' && Number.isFinite(args.tTriggerMs)) {
      tTriggerMs = args.tTriggerMs
    }

    const parsedPoll = this.parseHttpArgs(pollReqArgs)
    const capArg = parseCapabilityArg(pollReqArgs)
    consumeRunAsyncPollCallBudget(this.options.runId, this.options.maxAsyncPollCallsPerRun)
    type LastPoll = { result: BrokerExchangeResult; rawResp: { body: string; headers: Record<string, string> } | null; startedAt: number; applied: ReturnType<VerifyRpcServer['applyCapabilityInjection']>; cryptoAtts: HostCryptoAttestation[]; cleanSession: boolean }
    let lastBrokerResult: LastPoll | null = null
    let budgetError: Error | null = null
    const pollAbort = new AbortController()

    const convergence = await awaitAsyncConvergence({
      ...(profile ? { profile } : {}),
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      ...(intervalMs !== undefined ? { intervalMs } : {}),
      ...(maxAttempts !== undefined ? { maxAttempts } : {}),
      ...(tTriggerMs !== undefined ? { tTriggerMs } : {}),
      signal: pollAbort.signal,
      now: () => this.nextHostTimestampMs(),
      pollFn: async ({ signal }) => {
        try {
          consumeRunAsyncPollAttemptBudget(this.options.runId, this.options.maxAsyncPollAttemptsPerRun)
        } catch (err) {
          budgetError = err instanceof Error ? err : new Error(String(err))
          pollAbort.abort(budgetError)
          throw budgetError
        }
        const applied = this.applyCapabilityInjection(parsedPoll.brokerRequest, parsedPoll.requestMeta, capArg)
        const cryptoAtts = this.detectCryptoAttestationsForRequest(
          applied.brokerRequest,
          applied.attestations.map(a => a.consumedCapabilityId),
          applied.injectedHeaders,
        )
        const sessionKey = applied.brokerRequest.session ?? '__default__'
        const { isControlOrAblation, cleanSession, entityIds } = this.computeControlCleanSession(sessionKey, pollReqArgs, applied.brokerRequest, applied.requestMeta.sessionRole)
        const startedAt = this.nextHostTimestampMs()
        let rawResp: { body: string; headers: Record<string, string> } | null = null
        const result = await this.options.broker.executeHttp({ ...applied.brokerRequest, onRawResponse: raw => { rawResp = raw } }, applied.grant, signal)
        this.recordSessionMutation(sessionKey, applied.brokerRequest.method, entityIds, isControlOrAblation, result.status)
        lastBrokerResult = { result, rawResp, startedAt, applied, cryptoAtts, cleanSession }
        // R3-H-2: Evaluate worker predicates strictly on vault-scrubbed worker-visible body & headers.
        return {
          status: result.status,
          body: redact(this.scrub(result.body)),
          headers: this.egress.sanitizeHttpHeaders(result.respHeaders, 'worker_rpc'),
          observedAtMs: this.nextHostTimestampMs(),
        }
      },
      matchPredicate: (val) => evaluateAsyncMatchPredicate(compiledPredicate, val, evaluateJsonPath),
      extractObservedAtMs: (val) => val.observedAtMs,
    })
    if (budgetError) throw budgetError

    let finalRecord: VerifyTranscriptRecord | null = null
    let finalExchangeView: unknown = null
    if (lastBrokerResult) {
      const last = lastBrokerResult as LastPoll
      const { authPlacement, stampedReqMeta } = this.stampPlacement(last.applied, {
        ...last.applied.requestMeta,
        ...(last.cryptoAtts.length > 0 ? { derivedFromCapabilityId: last.cryptoAtts[0]!.derivedFromCapabilityId } : {}),
        nonce,
      }, last.result.wireCredentialProvenance)
      const reqMeta = stampedReqMeta
      finalRecord = this.transcript.record({
        op: 'http', startedAt: last.startedAt, durationMs: last.result.durationMs, request: reqMeta, body: last.result.body,
        ...(last.applied.brokerRequest.body !== undefined ? { rawRequestBody: this.scrubKernel(last.applied.brokerRequest.body) } : {}),
        response: {
          status: last.result.status, headers: this.kernelSanitizer.sanitizeHttpHeaders(last.result.respHeaders, 'storage_log'), bodyBytes: last.result.bodyBytes,
          bodySha256: last.result.bodySha256, mediaType: last.result.mediaType, redirectOrigins: last.result.redirectOrigins,
          ...(last.result.finalPathAndQuery ? { finalPathAndQuery: this.scrubKernel(last.result.finalPathAndQuery) } : {}),
        },
      })
      const mergedPollArgs = { ...pollReqArgs, ...(args.entityId !== undefined ? { entityId: args.entityId } : {}), ...(args.correlationId !== undefined ? { correlationId: args.correlationId } : {}), ...(args.correlationIds !== undefined ? { correlationIds: args.correlationIds } : {}) }
      const rawProv = last.rawResp ? { body: last.rawResp.body, respHeaders: last.rawResp.headers } : { body: last.result.body, respHeaders: last.result.respHeaders }
      this.recordRequestProvenance(
        finalRecord.exchangeId, last.startedAt, mergedPollArgs, last.applied.brokerRequest, reqMeta, rawProv,
        last.applied.attestations, last.cryptoAtts, last.cleanSession, last.applied.authCapabilityActor,
        last.result.wireCredentialProvenance, authPlacement,
      )
      finalExchangeView = this.exchangeView(finalRecord, last.result, {
        consumedCapabilityId: last.applied.attestation?.consumedCapabilityId ?? null,
        consumedCapabilities: last.applied.attestations.map(a => a.consumedCapabilityId),
        derivedFromCapabilityIds: [...new Set(last.cryptoAtts.map(a => a.derivedFromCapabilityId))],
      })
    }

    const pollRecordId = `poll-${randomUUID()}`
    const tObservedMs = convergence.evidence.tObservedMs ?? this.nextHostTimestampMs()
    const rawCorr = Array.isArray(args.correlationIds)
      ? args.correlationIds.filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
      : typeof args.correlationId === 'string' && args.correlationId.trim()
        ? [args.correlationId.trim()]
        : []
    const lastVisibleBody = this.scrub(lastBrokerResult ? (lastBrokerResult as { result: BrokerExchangeResult }).result.body : '')
    const lastVisiblePath = this.scrub(parsedPoll.brokerRequest.pathAndQuery)
    const verifiedCorr = rawCorr.filter(c => (this.mintedCanaries.has(c.toLowerCase()) || c.length >= 4) && (lastVisibleBody.includes(c) || lastVisiblePath.includes(c)))
    const entityId = typeof args.entityId === 'string' && args.entityId.trim()
      && (lastVisibleBody.includes(args.entityId.trim()) || lastVisiblePath.includes(args.entityId.trim()))
      ? args.entityId.trim()
      : undefined

    const pollRecord: HostAsyncPollRecord = {
      id: pollRecordId,
      ...(triggerExchangeId ? { triggerExchangeId } : {}),
      tTriggerMs: convergence.evidence.tTriggerMs,
      tObservedMs,
      converged: convergence.converged,
      ...(verifiedCorr.length > 0 ? { correlationIds: verifiedCorr } : {}),
      ...(entityId ? { entityId } : {}),
      ...(finalRecord ? { observedValueDigests: [finalRecord.response?.bodySha256].filter((v): v is string => Boolean(v)) } : {}),
    }
    this.asyncPollRecords.set(pollRecordId, pollRecord)

    this.transcript.record({
      op: 'async_poll',
      startedAt: convergence.evidence.tTriggerMs,
      durationMs: convergence.evidence.elapsedMs,
      request: {
        origin: parsedPoll.requestMeta.origin,
        method: 'POLL',
        pathAndQuery: this.scrubKernel(parsedPoll.requestMeta.pathAndQuery),
        headers: {},
        bodyBytes: 0,
        bodySha256: createHash('sha256').update(pollRecordId).digest('hex'),
        personaHandle: parsedPoll.requestMeta.personaHandle ?? null,
        sessionRole: parsedPoll.requestMeta.sessionRole ?? 'probe',
        actorRoleLabel: parsedPoll.requestMeta.actorRoleLabel ?? null,
        nonce,
      },
      artifact: {
        kind: 'async_poll',
        pollRecordId,
        converged: convergence.converged,
        tTriggerMs: convergence.evidence.tTriggerMs,
        tObservedMs,
      },
    })

    return this.scrubRecord({
      pollRecordId,
      converged: convergence.converged,
      status: convergence.status,
      exchangeId: finalRecord?.exchangeId ?? null,
      exchange: finalExchangeView,
      evidence: convergence.evidence,
    })
  }

  /** Construct a host-signed HostSignedTranscript over all recorded exchanges, OOB events, browser traces, and async polls. */
  buildHostSignedTranscript(): HostSignedTranscript {
    const entries: HostTranscriptEntry[] = []
    const oobEvents: HostOobEvent[] = []
    const browserTraces: HostBrowserTrace[] = []
    const asyncPollRecords: HostAsyncPollRecord[] = []

    const sign = <T extends HostTranscriptEntry | HostOobEvent | HostBrowserTrace | HostAsyncPollRecord>(rec: T): T => ({
      ...rec,
      hostSignature: signHostRecord(rec, this.compositeSigningKey),
    })

    for (const record of this.transcript.list()) {
      const prov = this.exchangeProvenance.get(record.exchangeId)
      const ts = prov?.timestampMs ?? record.startedAt

      if (record.op === 'oob') {
        const oobRec: HostOobEvent = {
          id: record.exchangeId,
          ...(record.artifact?.token ? { token: record.artifact.token } : {}),
          ...(record.request?.origin ? { targetOrigin: record.request.origin } : {}),
          delivered: Boolean(record.artifact?.hit),
          receivedAtMs: ts,
          ...(prov && prov.emittedCapabilities.size > 0 ? { emittedCapabilities: [...prov.emittedCapabilities] } : {}),
          ...(prov && prov.observedResponseDigests.size > 0 ? { observedValueDigests: [...prov.observedResponseDigests] } : {}),
          ...(prov && prov.correlationIds.size > 0 ? { correlationIds: [...prov.correlationIds] } : {}),
        }
        oobEvents.push(sign(oobRec))
        continue
      }

      if (record.op === 'browser') {
        const traceRec: HostBrowserTrace = {
          id: record.exchangeId,
          origin: record.request?.origin ?? '',
          sinks: record.artifact?.executedSentinels ?? [],
          timestampMs: ts,
          actorPersona: record.request?.personaHandle ?? null,
          ...(prov && prov.emittedCapabilities.size > 0 ? { emittedCapabilities: [...prov.emittedCapabilities] } : {}),
          ...(prov && prov.observedResponseDigests.size > 0 ? { observedValueDigests: [...prov.observedResponseDigests] } : {}),
          ...(prov && prov.correlationIds.size > 0 ? { correlationIds: [...prov.correlationIds] } : {}),
        }
        browserTraces.push(sign(traceRec))
        continue
      }

      if (record.op === 'async_poll') continue

      // H-9 / R2-C-9: Kernel plane uses unmodified response bytes and kernel-only sanitized request fields (never vault-scrubbed).
      const kernelBody = this.rawBodies.get(record.exchangeId) ?? this.transcript.body(record.exchangeId) ?? ''
      let parsedJson: unknown
      if (kernelBody.trim()) {
        try { parsedJson = JSON.parse(kernelBody) } catch { parsedJson = undefined }
      }
      const kernelReqBody = prov?.kernelRequestBody ?? prov?.rawRequestBody
      let parsedReqJson: unknown
      if (kernelReqBody?.trim()) {
        try { parsedReqJson = JSON.parse(kernelReqBody) } catch { parsedReqJson = undefined }
      }
      // R2-H-8: Prefer capability-injected actor provenance when Authorization/Cookie was supplied by a capability.
      const capActor = prov?.authCapabilityActor ?? null
      const handle = capActor ? capActor.handle : (record.request?.personaHandle ?? null)
      const signedLabel = capActor ? capActor.roleLabel : (record.request?.actorRoleLabel ?? null)
      const parsedLabel = parseRoleLabel(signedLabel)
      const role = capActor
        ? (normalizeRole(capActor.role ?? signedLabel) ?? null)
        : (signedLabel !== null ? (normalizeRole(signedLabel) ?? normalizeRole(handle) ?? null) : (normalizeRole(handle) ?? null))
      const tenant = capActor
        ? (capActor.tenant ?? parsedLabel.tenant ?? null)
        : (parsedLabel.tenant ?? parseRoleLabel(handle).tenant ?? null)
      const rawRole = record.request?.sessionRole
      const arm: ImpactStep['arm'] = rawRole === 'control' || rawRole === 'setup' || rawRole === 'cleanup' || rawRole === 'probe'
        ? rawRole
        : 'probe'
      const pathAndQuery = prov?.kernelPathAndQuery ?? this.scrubKernel(record.request?.pathAndQuery ?? '/')
      const kernelReqHeaders = prov?.kernelRequestHeaders ?? (record.request?.headers ? this.scrubKernelHeaderMap(record.request.headers) : null)
      const route = pathAndQuery.split('?')[0].replace(/\/+$/, '').toLowerCase() || '/'
      const status = record.response?.status != null && Number.isFinite(Number(record.response.status))
        ? Number(record.response.status)
        : (record.op === 'crypto' || record.op === 'capability' ? 200 : null)

      const wireProv = prov?.wireCredentialProvenance ?? record.request?.wireCredentialProvenance
      const explicitPlacement = prov?.authPlacement
        ?? record.request?.credentialPlacement
        ?? (wireProv ? buildHostAuthPlacement({ wireProvenance: wireProv, requestHeaders: kernelReqHeaders }) : undefined)
      const entry: HostTranscriptEntry = {
        exchangeId: record.exchangeId,
        durationMs: record.durationMs,
        ...(prov?.carrierText ? { carrierText: prov.carrierText } : {}),
        ...(prov?.evidenceRole ? { evidenceRole: prov.evidenceRole } : (record.op === 'crypto' || record.op === 'capability' ? { evidenceRole: `host_${record.op}_op` } : {})),
        ...(explicitPlacement ? { credentialPlacement: explicitPlacement } : {}),
        ...(wireProv ? { wireCredentialProvenance: wireProv } : {}),
        step: {
          id: record.exchangeId,
          arm,
          method: (record.request?.method ?? 'GET').toUpperCase(),
          route,
          pathAndQuery,
          status,
          actor: {
            handle,
            role,
            tenant,
            auth: deriveAmbientAuthFromHeaders(kernelReqHeaders, undefined, explicitPlacement),
            sameSite: sameSiteFromRecord(record),
          },
          ...(parsedJson !== undefined ? { json: parsedJson } : {}),
          body: kernelBody,
          ...(parsedReqJson !== undefined ? { requestJson: parsedReqJson } : {}),
          requestHeaders: kernelReqHeaders,
          responseHeaders: record.response?.headers ?? null,
          durationMs: record.durationMs,
          ...(prov?.evidenceRole ? { evidenceRole: prov.evidenceRole } : {}),
        },
        timestampMs: ts,
        actorPersona: handle,
        actorRoleLabel: signedLabel,
        ...(prov && prov.emittedCapabilities.size > 0 ? { emittedCapabilities: [...prov.emittedCapabilities] } : {}),
        ...(prov && prov.observedResponseDigests.size > 0 ? { observedResponseDigests: [...prov.observedResponseDigests] } : {}),
        ...(prov && prov.consumedCapabilities.size > 0 ? { consumedCapabilities: [...prov.consumedCapabilities] } : {}),
        ...(prov && prov.injectedRequestDigests.size > 0 ? { injectedRequestDigests: [...prov.injectedRequestDigests] } : {}),
        ...(prov && prov.cryptoAttestations.length > 0 ? { cryptoAttestations: prov.cryptoAttestations.map(a => ({ ...a })) } : {}),
        ...(prov?.entityId ? { entityId: prov.entityId } : {}),
        ...(prov && prov.correlationIds.size > 0 ? { correlationIds: [...prov.correlationIds] } : {}),
        ...(prov?.cleanSession !== undefined ? { cleanSession: prov.cleanSession } : {}),
        ...(prov?.replayAttempt ? { replayAttempt: prov.replayAttempt } : {}),
      }
      entries.push(sign(entry))
    }

    for (const poll of this.asyncPollRecords.values()) {
      asyncPollRecords.push(sign(poll))
    }

    return { entries, oobEvents, browserTraces, asyncPollRecords }
  }

  /** Verify a host-signed transcript record against this session's private HMAC key without exposing the key. */
  verifyHostSignature(record: HostSignableRecord): boolean {
    return verifyHostRecordSignature(record, this.compositeSigningKey)
  }

  /** Build a read-only kernel-plane HostFactLog from this session's host-signed transcript. */
  buildHostFactLog(): HostFactLog { return HostFactLog.fromTranscript(this.buildHostSignedTranscript()) }

  /** Host-side verification of a CompositeProofReceipt against this session's signed transcript & capability vault. */
  verifyComposite(rawReceipt: unknown, options?: Omit<CompositeVerifyOptions, 'signingKey'>): CompositeReceiptVerification {
    const factLog = HostFactLog.fromTranscript(this.buildHostSignedTranscript())
    const res = defaultTerminalOracleRegistry.evaluate(
      factLog, { kind: 'composite', receipt: rawReceipt },
      { compositeOptions: { ...this.options.compositeVerifyOptions, ...options }, signingKey: this.compositeSigningKey, strictHostDerivation: true },
    )
    return res.composite!
  }

  private handleCompositeVerify(args: Record<string, unknown>): unknown {
    const rawReceipt = args.receipt !== undefined ? args.receipt : args
    const rawObj = asRecord(rawReceipt)
    if (!rawObj || !Array.isArray(rawObj.hops) || rawObj.hops.length === 0) {
      throw new Error('composite.verify requires a receipt object with a non-empty hops array.')
    }
    consumeRunCompositeVerifyBudget(this.options.runId, this.options.maxCompositeVerifiesPerRun ?? this.options.safetyBudgets?.maxCompositeVerifiesPerRun)
    // Security invariant: RPC callers can never weaken host-configured attackerPersonas, forbiddenShortcutPersonas, benchmarkMode, requireCleanSessionFlag, or signingKey.
    const verdict = this.verifyComposite(rawReceipt)
    const hops = rawObj.hops, ti = asRecord(rawObj.terminalImpact)
    const terminalHopId = typeof ti?.terminalHopId === 'string' ? ti.terminalHopId : ''
    const termHopObj = asRecord(hops.find(h => asRecord(h)?.hopId === terminalHopId) ?? hops[hops.length - 1])
    const termTarget = asRecord(termHopObj?.target)
    const rawRoute = typeof termTarget?.pathAndQuery === 'string' && termTarget.pathAndQuery.trim() ? termTarget.pathAndQuery.trim() : null
    const route = rawRoute ?? verdict.terminalEndpoint ?? null
    const strIds = (v: unknown): string[] => Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.length > 0) : []
    const exchangeIds = [...new Set([
      ...hops.flatMap(h => strIds(asRecord(h)?.exchangeIds)), ...strIds(ti?.preChainControlExchangeIds), ...strIds(ti?.postChainReadbackExchangeIds),
      ...(typeof ti?.terminalExchangeId === 'string' && ti.terminalExchangeId.trim() ? [ti.terminalExchangeId.trim()] : []),
    ])].slice(0, 64)
    const termExIds = strIds(termHopObj?.exchangeIds)
    const terminalExchangeId = (typeof ti?.terminalExchangeId === 'string' && ti.terminalExchangeId.trim()) ? ti.terminalExchangeId.trim() : (termExIds[termExIds.length - 1] ?? null)
    const hostRejectedBy = verdict.confirmed ? null : (verdict.rejectedBy ?? (verdict.failedStage ? `composite_${verdict.failedStage}` : 'composite_receipt'))
    const hostMissingEvidence = verdict.confirmed ? [] : (verdict.missingEvidence?.length ? [...verdict.missingEvidence] : [hostRejectedBy ?? 'composite_receipt'])
    const chainId = this.scrub(verdict.chainId || (typeof rawObj?.chainId === 'string' ? rawObj.chainId : 'invalid'))
    const terminalVulnClass = this.scrub(verdict.terminalVulnClass || (typeof rawObj?.terminalVulnClass === 'string' ? rawObj.terminalVulnClass : 'unknown'))
    const scrubbedRoute = route ? this.scrub(route) : null
    const recorded = this.transcript.recordCompositeVerification({
      chainId, terminalVulnClass, replayMode: verdict.replayMode, hopCount: verdict.hopCount, confirmed: verdict.confirmed,
      verifiedEdgeCount: verdict.verifiedEdges.filter(e => e.verified).length, reason: this.scrub(verdict.reason),
      ...(verdict.failedStage ? { failedStage: verdict.failedStage } : {}),
      rejectedBy: hostRejectedBy, missingEvidence: this.scrubRecord(hostMissingEvidence), exchangeIds, terminalExchangeId, route: scrubbedRoute,
    })
    const cwe = /\bCWE-\d{1,4}\b/i.exec(`${String(rawObj?.cwe ?? '')} ${String(ti?.cwe ?? '')} ${String(rawObj?.terminalVulnClass ?? '')} ${String(ti?.summary ?? ti?.claimedImpact ?? '')}`)?.[0]?.toUpperCase()
    const hopCount = typeof verdict.hopCount === 'number' ? verdict.hopCount : hops.length
    // R2-C-3: Return coarse confirmed/rejected diagnostics to the worker (NEVER raw leaf/stage/edge oracle feedback).
    const workerReason = verdict.confirmed ? 'composite_verification_confirmed' : 'composite_verification_rejected'
    const workerRejectedBy = verdict.confirmed ? null : 'composite_receipt'
    const workerMissing = verdict.confirmed ? [] : ['composite_receipt']
    const claim: Extract<VerifyClaim, { kind: 'composite_receipt' }> = {
      kind: 'composite_receipt', verificationId: recorded.verificationId, chainId, terminalVulnClass,
      ...(cwe ? { cwe } : {}), ...(scrubbedRoute ? { route: scrubbedRoute } : {}), exchangeIds,
      ...(terminalExchangeId ? { terminalExchangeId } : {}), ...(verdict.replayMode ? { replayMode: verdict.replayMode } : {}),
      hopCount, ...(rawObj ? { compositeReceipt: rawObj } : {}),
      ...(!verdict.confirmed ? { rejectedBy: workerRejectedBy, missingEvidence: workerMissing, reason: workerReason } : {}),
    }
    return this.scrubRecord({
      confirmed: verdict.confirmed, ok: verdict.confirmed, verified: verdict.confirmed, status: verdict.confirmed ? 'confirmed' : 'rejected',
      chainId, terminalVulnClass, replayMode: verdict.replayMode, hopCount,
      ...(verdict.confirmed ? { modeBVerified: verdict.modeBVerified, verifiedEdgeCount: verdict.verifiedEdges.filter(e => e.verified).length } : {}),
      ...(scrubbedRoute ? { terminalEndpoint: scrubbedRoute } : {}),
      verificationId: recorded.verificationId, reason: workerReason, rejectedBy: workerRejectedBy, missingEvidence: workerMissing, claim,
    })
  }

  private proveHost(): ProveHandlerHost {
    return {
      transcript: this.transcript,
      defaultOrigin: this.options.targetOrigins?.[0],
      canaryBroker: this.options.canary ?? (this.options.grant as Grant & { canaryBroker?: VerifyCanaryBroker }).canaryBroker,
      diffDigestKey: this.compositeSigningKey,
      runHttpExchange: async (args, nonce) => await this.handleHttp(args, nonce, 'http') as ProveHttpExchangeResult,
      runOob: args => this.handleOob(args),
      runRace: (args, nonce) => this.handleRace(args, nonce),
      scrubRecord: value => this.scrubRecord(value),
    }
  }
}

export interface LocalAttemptFactoryOptions extends LocalAttemptFactoryBaseOptions {
  createRpcOptions: (nonce: string, attempt: 1 | 2) => Omit<VerifyRpcSessionOptions, 'nonce'>
}

export function createLocalAttemptFactory(options: LocalAttemptFactoryOptions) {
  return buildLocalAttemptFactory(
    options,
    (nonce, attempt) => new VerifyRpcServer({ ...options.createRpcOptions(nonce, attempt), nonce }),
  )
}
