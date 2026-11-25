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
import { connect as h2Connect, constants as h2constants } from 'node:http2'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { lookup } from 'node:dns/promises'
import ipaddr from 'ipaddr.js'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import { buildPersonaHeader } from './persona-vault.ts'
import type { ResolvedPersona } from './persona-vault.ts'
import { redact } from './redact.ts'
import {
  DerivedCapabilityVault,
  awaitAsyncConvergence,
  isDerivedCapabilityHandle,
  scrubDerivedSecrets,
  vaultScrubDescriptors,
} from './derived-custody.ts'
import type {
  AsyncPollProfile,
  CapabilityConsumptionAttestation,
  DerivedSecretKind,
  HostHmacAlg,
  HostHmacEncoding,
  HostJwtAlg,
  InjectCapabilityTarget,
} from './derived-custody.ts'
import { signHostRecord, verifyCompositeReceipt } from './composite-receipt.ts'
import type {
  CompositeReceiptVerification,
  CompositeVerifyOptions,
  HostAsyncPollRecord,
  HostBrowserTrace,
  HostCryptoAttestation,
  HostOobEvent,
  HostSignedTranscript,
  HostTranscriptEntry,
} from './composite-receipt.ts'
import { isReadMethod, normalizeRole, parseRoleLabel } from './oracle-invariants.ts'
import type { ImpactStep } from './oracle-invariants.ts'
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
} from './verify-claims.ts'
import {
  handleProveAccessBoundary,
  handleProvePersistedMutation,
  handleProveDifferential,
  handleProveOob,
  handleProveRace,
  handleProveInjection,
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
  GUARDIAN_VERIFY_STDERR_PREVIEW_MAX_CHARS,
  GUARDIAN_VERIFY_USAGE_HINT,
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
}

interface RpcPayload {
  op?: string
  args?: Record<string, unknown>
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
  carrierText?: string
}

interface ParsedCapabilityArg {
  handle: string
  target?: InjectCapabilityTarget
  headerName?: string
  cookieName?: string
  queryParam?: string
}

const DERIVED_SECRET_KINDS = new Set<DerivedSecretKind>([
  'bearer_token', 'api_token', 'cookie', 'signed_url', 'oidc_assertion',
  'signing_salt', 'hmac_key', 'jwt', 'header_secret', 'generic_secret',
])
const INJECT_CAPABILITY_TARGETS = new Set<InjectCapabilityTarget>(['bearer', 'header', 'cookie', 'url'])
const BROKER_FORBIDDEN_CALLER_HEADER_RE = /^(?:authorization|proxy-authorization|cookie)$/i
const INLINE_CAP_RE = /(?<!\[redacted:)(?<![A-Za-z0-9_])cap(?::|%3[aA])hop_[A-Za-z0-9._-]+(?::|%3[aA])[A-Za-z0-9._-]+/g
const EXACT_BEARER_CAP_RE = /^\s*(?:Bearer\s+)*(cap:hop_[A-Za-z0-9._-]+:[A-Za-z0-9._-]+)\s*$/i
const EXACT_INLINE_CAP_RE = /^cap:hop_[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$/
const COOKIE_PAIR_VALUE_RE = /^(?:__Host-|__Secure-)?[A-Za-z][A-Za-z0-9_.-]{0,63}=[^;=\s&]{4,}$/
const STATIC_PATH_SEG_RE = /^(?:api|rest|v\d+|read|public|admin|me|settings|login|logout|auth|token|refresh|verify|mfa|2fa|otp|session)$/i
const ENTITY_PATH_SEG_RE = /^\d+$|(?:^|[-_.])\d|^[0-9a-f]{8,}$|^[a-z]{2,10}_[A-Za-z0-9_-]{4,}$|^[A-Za-z0-9_-]*\d[A-Za-z0-9_-]*$/i
const BODY_ENTITY_KEY_RE = /^(?:id|entity_?id|[a-z]+_?id)$/i
const BODY_SCOPE_KEY_RE = /^(?:tenant|org|organization|workspace|project|user|actor|session|client)_?id$/i

function extractRequestEntityIds(args: Record<string, unknown>, pathAndQuery: string, rawBody?: string): string[] {
  const ids = new Set<string>()
  if (typeof args.entityId === 'string' && args.entityId.trim()) ids.add(args.entityId.trim().slice(0, 256))
  for (const rawSeg of (pathAndQuery.split(/[?#]/, 1)[0] ?? '').split('/')) {
    if (!rawSeg) continue
    let seg = rawSeg; try { seg = decodeURIComponent(rawSeg) } catch { /* keep raw */ }
    if (!STATIC_PATH_SEG_RE.test(seg) && ENTITY_PATH_SEG_RE.test(seg) && (/^\d+$/.test(seg) || seg.length >= 4 || /^[a-z]\d{1,3}$/i.test(seg))) ids.add(seg.slice(0, 256))
  }
  if (ids.size === 0 && rawBody && rawBody.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(rawBody) as Record<string, unknown>
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const [k, v] of Object.entries(parsed)) {
          if (!BODY_ENTITY_KEY_RE.test(k) || BODY_SCOPE_KEY_RE.test(k)) continue
          if (typeof v === 'string' && v.trim()) ids.add(v.trim().slice(0, 256))
          else if (typeof v === 'number' && Number.isFinite(v)) ids.add(String(v))
        }
      }
    } catch { /* non-JSON body */ }
  }
  return [...ids]
}

function resolveSealJsonPath(root: unknown, rawPath: string): { found: boolean; value?: unknown } {
  const cleaned = rawPath.trim().replace(/^\$/, '')
  if (!cleaned) return { found: root !== undefined, value: root }
  const tokens: Array<string | number> = []
  const re = /\.?([^.[\]]+)|\[(\d+|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\]/g
  let m: RegExpExecArray | null, consumed = 0
  while ((m = re.exec(cleaned)) !== null) {
    if (m.index !== consumed && cleaned.slice(consumed, m.index).replace(/^\.+/, '') !== '') return evaluateJsonPath(root, rawPath)
    consumed = re.lastIndex
    if (m[1] !== undefined) tokens.push(/^\d+$/.test(m[1]) ? Number(m[1]) : m[1])
    else if (m[2] !== undefined) tokens.push((m[2].startsWith("'") || m[2].startsWith('"')) ? m[2].slice(1, -1).replace(/\\(.)/g, '$1') : Number(m[2]))
  }
  if (consumed < cleaned.length) return evaluateJsonPath(root, rawPath)
  let cur: unknown = root
  for (const tok of tokens) {
    if (Array.isArray(cur)) { if (typeof tok !== 'number' || tok < 0 || tok >= cur.length) return { found: false }; cur = cur[tok] }
    else if (cur && typeof cur === 'object') { const rec = cur as Record<string, unknown>, k = String(tok); if (!Object.prototype.hasOwnProperty.call(rec, k)) return { found: false }; cur = rec[k] }
    else return { found: false }
    if (cur === undefined) return { found: false }
  }
  return { found: true, value: cur }
}

function describeJsonTopKeys(parsed: unknown): string {
  if (Array.isArray(parsed)) {
    const first = parsed[0]
    if (first && typeof first === 'object' && !Array.isArray(first)) {
      const keys = Object.keys(first as Record<string, unknown>).slice(0, 20)
      return `top-level array length=${parsed.length}, [0] keys: ${keys.join(', ') || 'none'}`
    }
    return `top-level array length=${parsed.length}`
  }
  if (parsed && typeof parsed === 'object') {
    const keys = Object.keys(parsed as Record<string, unknown>).slice(0, 20)
    return keys.length ? `top-level keys: ${keys.join(', ')}` : 'top-level object is empty'
  }
  return `top-level type: ${parsed === null ? 'null' : typeof parsed}`
}

function normalizeDerivedSecretKind(raw: unknown): DerivedSecretKind | undefined {
  if (raw === undefined || raw === null) return undefined
  if (typeof raw !== 'string') throw new Error(`Unsupported capability kind "${String(raw)}".`)
  const norm = raw.trim().toLowerCase().replace(/[\s-]+/g, '_')
  if (!norm) return undefined
  if (DERIVED_SECRET_KINDS.has(norm as DerivedSecretKind)) return norm as DerivedSecretKind
  if (/(?:^|_)jwt(?:$|_)/.test(norm)) return 'jwt'
  if (/oidc|assertion/.test(norm)) return 'oidc_assertion'
  if (/salt/.test(norm)) return 'signing_salt'
  if (/cookie/.test(norm)) return 'cookie'
  if (/signed.*url|presigned|url/.test(norm)) return 'signed_url'
  if (/header/.test(norm)) return 'header_secret'
  if (/bearer|access_token|session_token|identity_session/.test(norm)) return 'bearer_token'
  if (/signing|hmac|secret_key|private_key|mac_key|key_material/.test(norm)) return 'hmac_key'
  if (/api_key|token|pat/.test(norm)) return 'api_token'
  if (/secret|key/.test(norm)) return 'hmac_key'
  return 'generic_secret'
}

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
  private readonly options: VerifyRpcSessionOptions
  private readonly compositeSigningKey: string
  private readonly rawBodies = new Map<string, string>()
  private readonly rawResponseHeaders = new Map<string, Record<string, string>>()
  private readonly exchangeProvenance = new Map<string, HostExchangeProvenance>()
  private readonly hmacDerivations = new Map<string, HostCryptoAttestation>()
  private readonly jwtDerivations = new Map<string, HostCryptoAttestation>()
  private readonly asyncPollRecords = new Map<string, HostAsyncPollRecord>()
  private readonly mutatedSessions = new Set<string>()
  private readonly mutatedSessionEntities = new Set<string>()
  private lastHostTsMs = 0
  private server: ReturnType<typeof createServer> | null = null
  private hostDirValue = ''
  private socketPathValue = ''
  private tokenValue = ''
  private started = false
  private closing = false

  constructor(options: VerifyRpcSessionOptions) {
    this.options = options
    this.nonce = options.nonce ?? randomBytes(12).toString('hex')
    this.transcript = new TranscriptStore()
    this.compositeSigningKey = randomBytes(32).toString('hex')
    const safeRunId = /^[A-Za-z0-9._-]{1,128}$/.test(options.runId)
      ? options.runId
      : options.runId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 128) || 'run'
    this.capabilityVault = options.capabilityVault ?? new DerivedCapabilityVault({
      runId: safeRunId,
      ...(options.capabilityPersistPath ? { persistPath: options.capabilityPersistPath } : {}),
    })
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
      // Prefer a real tmpfs so the socket directory is memory-backed on the host too.
      const tmpfsBase = existsSync('/dev/shm') ? '/dev/shm' : tmpdir()
      try {
        this.hostDirValue = mkdtempSync(join(tmpfsBase, 'guardian-verify-rpc-'))
      } catch {
        this.hostDirValue = mkdtempSync(join(tmpdir(), 'guardian-verify-rpc-'))
      }
    }
    // 0711: the sandbox uid can traverse to the mounted files without listing the host directory.
    // Explicit chmodSync on every file bypasses restrictive host umasks (e.g. 0077) so the
    // non-root worker container UID (10001) never hits EACCES reading /guardian-rpc/*.
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
      sdkVersion: 'guardian_verify/v6-mvp',
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
      return reply(200, { ok: false, error: error instanceof Error ? error.message.slice(0, 600) : 'Verification RPC failed.' })
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
    throw new Error(`Unsupported verification RPC operation: ${String(op)}`)
  }

  private handleTranscript(args: Record<string, unknown>): unknown {
    const action = typeof args.action === 'string' ? args.action : 'list'
    if (action === 'get') {
      const id = typeof args.exchangeId === 'string' ? args.exchangeId : ''
      const record = this.transcript.get(id)
      if (!record) throw new Error('Unknown exchange id.')
      const rawBody = this.transcript.body(id)
      return this.scrubRecord({
        record,
        body: rawBody !== undefined ? this.scrub(rawBody) : null,
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
    let url: URL
    try { url = new URL(requested) } catch { throw new Error('Target origin is malformed.') }
    const origin = url.origin
    if (!this.options.grant.canRead(origin)) throw new Error('Destination is outside the current assignment scope.')
    return { origin, url }
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
    if (role !== undefined && !['setup', 'control', 'probe', 'cleanup'].includes(role)) throw new Error('Invalid session group role.')
    const brokerRequest: BrokerHttpRequest = {
      origin,
      method: method as BrokerHttpRequest['method'],
      pathAndQuery: rawPath,
      ...(Object.keys(headers).length ? { headers } : {}),
      ...(body !== undefined ? { body } : {}),
      ...(persona ? { persona } : {}),
      ...(session ? { session } : {}),
      ...(role ? { sessionGroupRole: role as BrokerHttpRequest['sessionGroupRole'] } : {}),
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
    let out = text
    for (const persona of this.options.grant.personas?.values() ?? []) {
      const values = [persona.secret, persona.session?.value, ...(persona.secretHistory ?? []), ...(persona.session?.scrubTokens ?? [])]
      for (const value of values) {
        if (typeof value === 'string' && value.length >= 4) out = out.split(value).join(`[redacted:${persona.handle}]`)
      }
    }
    // Normalize broker personaSecrets() placeholders emitted for ephemeral derived-capability personas.
    out = out.replace(/\[persona:(cap:hop_[A-Za-z0-9._-]+:[A-Za-z0-9._-]+):secret\]/g, '[redacted:$1]')
    return scrubDerivedSecrets(out, this.capabilityVault)
  }

  private scrubRecord<T>(value: T): T {
    if (typeof value === 'string') return this.scrub(value) as T
    if (Array.isArray(value)) return value.map(v => this.scrubRecord(v)) as T
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = this.scrubRecord(v)
      return out as T
    }
    return value
  }

  private parseCapabilityArg(args: Record<string, unknown>): ParsedCapabilityArg | null {
    const raw = args.capability
    if (raw === undefined || raw === null) return null
    let targetRaw = args.capabilityTarget ?? args.capability_target
    let headerNameRaw = args.capabilityHeaderName ?? args.capability_header_name
    let cookieNameRaw = args.capabilityCookieName ?? args.capability_cookie_name
    let queryParamRaw = args.capabilityQueryParam ?? args.capability_query_param
    let handle = ''
    if (typeof raw === 'string') {
      handle = raw.trim()
    } else {
      const obj = asRecord(raw)
      const rawHandle = obj ? (obj.handle ?? obj.derivedHandle ?? obj.cap_id) : undefined
      if (!obj || typeof rawHandle !== 'string') throw new Error('capability must be a handle string or { handle, target?, headerName?, cookieName?, queryParam? }.')
      handle = rawHandle.trim()
      targetRaw = obj.target ?? targetRaw
      headerNameRaw = obj.headerName ?? obj.header_name ?? headerNameRaw
      cookieNameRaw = obj.cookieName ?? obj.cookie_name ?? cookieNameRaw
      queryParamRaw = obj.queryParam ?? obj.query_param ?? queryParamRaw
    }
    if (!isDerivedCapabilityHandle(handle)) throw new Error(`Invalid derived capability handle "${handle}".`)
    let target: InjectCapabilityTarget | undefined
    if (targetRaw !== undefined) {
      if (typeof targetRaw !== 'string' || !INJECT_CAPABILITY_TARGETS.has(targetRaw as InjectCapabilityTarget)) throw new Error(`Unsupported capability target "${String(targetRaw)}".`)
      target = targetRaw as InjectCapabilityTarget
    }
    return {
      handle, ...(target ? { target } : {}),
      ...(typeof headerNameRaw === 'string' && headerNameRaw.trim() ? { headerName: headerNameRaw.trim() } : {}),
      ...(typeof cookieNameRaw === 'string' && cookieNameRaw.trim() ? { cookieName: cookieNameRaw.trim() } : {}),
      ...(typeof queryParamRaw === 'string' && queryParamRaw.trim() ? { queryParam: queryParamRaw.trim() } : {}),
    }
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
      const hName = headerName ?? 'X-Guardian-Inline-Resolve'
      const injected = this.capabilityVault.injectCapabilityIntoRequest({ handle, target: 'header', headerName: hName, runId: this.capabilityVault.runId, request: { url: targetUrl, method, headers: {} } })
      return { rawValue: injected.request.headers?.[hName] ?? '', attestation: injected.attestation }
    }
    const injected = this.capabilityVault.injectCapabilityIntoRequest({ handle, target: 'url', queryParam: '__guardian_resolve__', runId: this.capabilityVault.runId, request: { url: targetUrl, method, headers: {} } })
    return { rawValue: new URL(injected.request.url).searchParams.get('__guardian_resolve__') ?? '', attestation: injected.attestation }
  }

  private applyCapabilityInjection(
    brokerRequest: BrokerHttpRequest, requestMeta: VerifyTranscriptRequest, cap: ParsedCapabilityArg | null,
  ): {
    brokerRequest: BrokerHttpRequest; grant: Grant; requestMeta: VerifyTranscriptRequest
    attestation: CapabilityConsumptionAttestation | null; attestations: CapabilityConsumptionAttestation[]; injectedHeaders: Record<string, string>
  } {
    const vaultSecrets = vaultScrubDescriptors(this.capabilityVault)
    const baseReq: BrokerHttpRequest = { ...brokerRequest, ...(vaultSecrets.length > 0 ? { secrets: [...(brokerRequest.secrets ?? []), ...vaultSecrets] } : {}) }
    const attestationsById = new Map<string, CapabilityConsumptionAttestation>()
    const recordAtt = (att: CapabilityConsumptionAttestation) => { if (!attestationsById.has(att.consumedCapabilityId)) attestationsById.set(att.consumedCapabilityId, att) }
    const decodeCap = (m: string) => (/%3[aA]/.test(m) ? m.replace(/%3[aA]/g, ':') : m)
    const knownHandles = this.capabilityVault.list().map(m => m.handle).sort((a, b) => b.length - a.length)
    const splitCap = (raw: string): { handle: string; suffix: string } => {
      if (this.capabilityVault.getMeta(raw)) return { handle: raw, suffix: '' }
      const hit = knownHandles.find(h => raw.startsWith(h) && /^[._-]/.test(raw.slice(h.length)))
      return hit ? { handle: hit, suffix: raw.slice(hit.length) } : { handle: raw, suffix: '' }
    }
    const redactCaps = (s: string) => s.replace(new RegExp(INLINE_CAP_RE.source, 'g'), (m) => {
      const { handle, suffix } = splitCap(decodeCap(m))
      return `[redacted:${handle}]${suffix}`
    })
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
      if (injected.request.url !== baseUrl) {
        const parsedUrl = new URL(injected.request.url)
        if (!this.options.grant.canRead(parsedUrl.origin)) throw new Error('Derived capability destination is outside the current assignment scope.')
        nextOrigin = parsedUrl.origin
        nextPathAndQuery = parsedUrl.pathname + parsedUrl.search
      }
      for (const [k, v] of Object.entries(injected.request.headers ?? {})) {
        const isAuthHdr = BROKER_FORBIDDEN_CALLER_HEADER_RE.test(k)
        if (!isAuthHdr && capInputHeaders[k] === v) continue
        const normVal = /^authorization$/i.test(k) ? v.replace(/^\s*(?:Bearer\s+)+/i, 'Bearer ') : v
        injectedHeaders[k] = normVal
        injectedByCapKeys.add(k.toLowerCase())
        if (isAuthHdr) {
          setHeaderCI(authHeaders, k, normVal)
          setHeaderCI(metaHeaders, k, `[redacted:${cap.handle}]`)
          primaryAuthHandle = primaryAuthHandle ?? cap.handle
          for (const wk of Object.keys(workingHeaders)) if (wk.toLowerCase() === k.toLowerCase()) delete workingHeaders[wk]
        } else {
          setHeaderCI(workingHeaders, k, normVal)
          setHeaderCI(metaHeaders, k, `[redacted:${cap.handle}]`)
        }
      }
    }

    // 2) Inline `cap:hop_...` placeholders in URL path/query
    const trimmedPath = nextPathAndQuery.trim()
    if (EXACT_INLINE_CAP_RE.test(trimmedPath)) {
      const urlBase = new URL('/', nextOrigin).href
      const resolved = this.resolveInlineHandle(trimmedPath, urlBase, baseReq.method, 'url')
      if (/^https?:\/\//i.test(resolved.rawValue)) {
        const injected = this.capabilityVault.injectCapabilityIntoRequest({
          handle: trimmedPath, target: 'url', runId: this.capabilityVault.runId, request: { url: urlBase, method: baseReq.method, headers: {} },
        })
        const parsedUrl = new URL(injected.request.url)
        if (!this.options.grant.canRead(parsedUrl.origin)) throw new Error('Derived capability destination is outside the current assignment scope.')
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
      if (!nextPathAndQuery.startsWith('/') || nextPathAndQuery.startsWith('//') || nextPathAndQuery.length > MAX_PATH_LENGTH) {
        throw new Error('Request path is invalid or exceeds the 8 KiB limit.')
      }
    }

    // 3) Inline `cap:hop_...` placeholders in headers (routing Authorization/Cookie through auth targets)
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
          setHeaderCI(metaHeaders, k, `[redacted:${handle}]`)
          recordAtt(injected.attestation)
          primaryAuthHandle = primaryAuthHandle ?? handle
        } else {
          const resolvedAuth = replaceInline(v, targetUrl, 'bearer', { onHandle: h => { primaryAuthHandle = primaryAuthHandle ?? h } }).replace(/^\s*Bearer(?:\s+Bearer)+\s+/i, 'Bearer ')
          setHeaderCI(authHeaders, 'Authorization', resolvedAuth)
          injectedHeaders['Authorization'] = resolvedAuth
          setHeaderCI(metaHeaders, k, redactCaps(v))
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
            metaSegs.push(seg)
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
            metaSegs.push(cookieName ? `${cookieName}=[redacted:${rhs}]` : `[redacted:${rhs}]`)
          } else {
            const resolvedSeg = replaceInline(seg, targetUrl, 'header', { headerName: 'X-Guardian-Inline-Resolve', onHandle: h => { firstHandle = firstHandle ?? h } })
            cookieHeaders.Cookie = cookieHeaders.Cookie ? `${cookieHeaders.Cookie}; ${resolvedSeg}` : resolvedSeg
            metaSegs.push(redactCaps(seg))
          }
        }
        if (firstHandle && cookieHeaders.Cookie) {
          setHeaderCI(authHeaders, 'Cookie', cookieHeaders.Cookie)
          injectedHeaders['Cookie'] = cookieHeaders.Cookie
          setHeaderCI(metaHeaders, k, metaSegs.join('; '))
          primaryAuthHandle = primaryAuthHandle ?? firstHandle
        } else {
          nextHeaders[k] = v
        }
      } else if (/^proxy-authorization$/i.test(k)) {
        const resolvedVal = replaceInline(v, targetUrl, 'bearer', { onHandle: h => { primaryAuthHandle = primaryAuthHandle ?? h } })
        setHeaderCI(authHeaders, k, resolvedVal)
        injectedHeaders[k] = resolvedVal
        setHeaderCI(metaHeaders, k, redactCaps(v))
      } else {
        const resolvedVal = replaceInline(v, targetUrl, 'header', { headerName: k })
        nextHeaders[k] = resolvedVal
        injectedHeaders[k] = resolvedVal
        setHeaderCI(metaHeaders, k, redactCaps(v))
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
      return { brokerRequest: baseReq, grant: this.options.grant, requestMeta, attestation: null, attestations: [], injectedHeaders: {} }
    }

    // 5) Package capability-injected Authorization/Cookie headers into an ephemeral persona
    let effectiveGrant: Grant = this.options.grant
    let effectivePersona = baseReq.persona
    if (Object.keys(authHeaders).length > 0) {
      const mergedBundleHeaders: Record<string, string> = {}
      const basePersonaHandle = baseReq.persona ?? baseReq.personaHandle
      let baseRoleLabel = 'derived'
      const authHasBearer = Object.keys(authHeaders).some(k => /^authorization$/i.test(k))
      const authHasCookie = Object.keys(authHeaders).some(k => /^cookie$/i.test(k))
      if (basePersonaHandle) {
        const basePersona = this.options.grant.personas?.get(basePersonaHandle)
        if (!basePersona) throw new Error(`Persona "${basePersonaHandle}" is not approved for this run.`)
        const baseInjected = buildPersonaHeader(basePersona, nextOrigin)
        if (!baseInjected) throw new Error(`Persona "${basePersonaHandle}" does not have an active authenticated session.`)
        for (const [bk, bv] of Object.entries(baseInjected)) {
          if (authHasBearer && !authHasCookie && /^cookie$/i.test(bk)) continue
          mergedBundleHeaders[bk] = bv
        }
        baseRoleLabel = basePersona.roleLabel
      }
      for (const [k, v] of Object.entries(authHeaders)) setHeaderCI(mergedBundleHeaders, k, v)
      const ephemeralHandle = primaryAuthHandle ?? attestations[0]!.consumedCapabilityId
      const ephemeralPersona: ResolvedPersona = {
        id: ephemeralHandle, handle: ephemeralHandle, roleLabel: baseRoleLabel, originAllowlist: [nextOrigin],
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
      secrets: [...(baseReq.secrets ?? []), ...vaultScrubDescriptors(this.capabilityVault)],
    }
    const nextMeta: VerifyTranscriptRequest = {
      ...requestMeta,
      origin: nextOrigin,
      pathAndQuery: this.scrub(nextPathAndQuery),
      headers: this.scrubRecord(metaHeaders),
      ...(nextBody !== baseReq.body ? {
        bodyBytes: nextBody ? Buffer.byteLength(nextBody) : 0,
        bodySha256: createHash('sha256').update(this.scrub(nextBody ?? '')).digest('hex'),
      } : {}),
      consumedCapabilityId: attestations[0]!.consumedCapabilityId,
    }
    return { brokerRequest: nextBrokerReq, grant: effectiveGrant, requestMeta: nextMeta, attestation: attestations[0] ?? null, attestations, injectedHeaders }
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
  ): void {
    this.rawBodies.set(exchangeId, result.body)
    this.rawResponseHeaders.set(exchangeId, { ...result.respHeaders })
    const prov = this.getOrCreateProvenance(exchangeId, startedAt)
    prov.timestampMs = startedAt
    prov.cleanSession = cleanSession
    prov.rawRequestBody = brokerRequest.body
    prov.carrierText = this.scrub([
      brokerRequest.pathAndQuery,
      ...Object.entries(requestMeta.headers).map(([k, v]) => `${k}: ${v}`),
      brokerRequest.body ?? '',
    ].join('\n'))
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
    const combinedText = `${brokerRequest.pathAndQuery}\n${brokerRequest.body ?? ''}\n${result.body}`
    if (typeof args.entityId === 'string' && args.entityId.trim()) {
      const entity = args.entityId.trim().slice(0, 256)
      if (combinedText.toLowerCase().includes(entity.toLowerCase())) prov.entityId = entity // case-variant host binding (still requires host-observed presence)
    }
    const rawCorr = Array.isArray(args.correlationIds)
      ? args.correlationIds
      : typeof args.correlationId === 'string'
        ? [args.correlationId]
        : []
    for (const item of rawCorr) {
      if (typeof item === 'string' && item.trim()) {
        const token = item.trim().slice(0, 256)
        if (combinedText.includes(token)) prov.correlationIds.add(token)
      }
    }
  }

  private exchangeView(record: VerifyTranscriptRecord, result: BrokerExchangeResult, extra?: {
    consumedCapabilityId?: string | null
    consumedCapabilities?: string[]
    derivedFromCapabilityIds?: string[]
  }) {
    return this.scrubRecord({
      exchangeId: record.exchangeId,
      status: result.status,
      method: result.method,
      pathAndQuery: this.scrub(result.pathAndQuery),
      finalPathAndQuery: result.finalPathAndQuery ? this.scrub(result.finalPathAndQuery) : result.finalPathAndQuery,
      redirectOrigins: result.redirectOrigins,
      mediaType: result.mediaType,
      headers: result.respHeaders,
      body: result.body.slice(0, 512 * 1024),
      bodyPreview: this.scrub(result.bodyPreview),
      bodyBytes: result.bodyBytes,
      bodySha256: result.bodySha256,
      durationMs: result.durationMs,
      personaHandle: record.request?.personaHandle ?? null,
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

  private prepareCapRequest(args: Record<string, unknown>, nonce: string) {
    const parsed = this.parseHttpArgs(args)
    const applied = this.applyCapabilityInjection(parsed.brokerRequest, parsed.requestMeta, this.parseCapabilityArg(args))
    const consumedIds = applied.attestations.map(a => a.consumedCapabilityId)
    const cryptoAttestations = this.detectCryptoAttestationsForRequest(applied.brokerRequest, consumedIds, applied.injectedHeaders)
    const derivedFromCapabilityIds = [...new Set(cryptoAttestations.map(a => a.derivedFromCapabilityId))]
    const requestMeta: VerifyTranscriptRequest = {
      ...applied.requestMeta,
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
    try {
      const rawBox: { value: { body: string; headers: Record<string, string> } | null } = { value: null }
      const reqWithRaw: BrokerHttpRequest = { ...prep.applied.brokerRequest, onRawResponse: raw => { rawBox.value = raw } }
      const result = await this.options.broker.executeHttp(reqWithRaw, prep.applied.grant, AbortSignal.timeout(this.options.callTimeoutMs ?? 30_000))
      this.recordSessionMutation(prep.sessionKey, prep.applied.brokerRequest.method, prep.entityIds, prep.isControlOrAblation, result.status)
      const body = this.scrub(result.body)
      const record = this.transcript.record({
        op: proto, startedAt: started, durationMs: result.durationMs, request: prep.requestMeta, body,
        response: {
          status: result.status, headers: this.scrubRecord(result.respHeaders), bodyBytes: result.bodyBytes,
          bodySha256: result.bodySha256, mediaType: result.mediaType, redirectOrigins: result.redirectOrigins,
          ...(result.finalPathAndQuery ? { finalPathAndQuery: this.scrub(result.finalPathAndQuery) } : {}),
        },
      })
      const rawProv = rawBox.value ? { body: rawBox.value.body, respHeaders: rawBox.value.headers } : { body: result.body, respHeaders: result.respHeaders }
      this.recordRequestProvenance(record.exchangeId, started, args, prep.applied.brokerRequest, prep.requestMeta, rawProv, prep.applied.attestations, prep.cryptoAttestations, prep.cleanSession)
      return this.exchangeView(record, { ...result, body }, {
        consumedCapabilityId: prep.applied.attestation?.consumedCapabilityId ?? null,
        consumedCapabilities: prep.consumedIds,
        derivedFromCapabilityIds: prep.derivedFromCapabilityIds,
      })
    } catch (error) {
      const msg = this.scrub(error instanceof Error ? error.message : 'HTTP exchange failed.')
      const record = this.transcript.record({ op: proto, startedAt: started, durationMs: Date.now() - started, request: prep.requestMeta, error: msg, errorCode: /scope|denied|approval|forbidden|outside|header/i.test(msg) ? 'denied' : 'failed' })
      throw new Error(`${record.exchangeId}: ${msg}`)
    }
  }

  private async handleHttp2(args: Record<string, unknown>, nonce: string): Promise<unknown> {
    const prep = this.prepareCapRequest(args, nonce)
    const started = this.nextHostTimestampMs()
    const signal = AbortSignal.timeout(this.options.callTimeoutMs ?? 30_000)
    try {
      const h2 = await this.executeHttp2(prep.applied.brokerRequest, signal, prep.applied.grant)
      this.recordSessionMutation(prep.sessionKey, prep.applied.brokerRequest.method, prep.entityIds, prep.isControlOrAblation, h2.status)
      const body = this.scrub(h2.body)
      const record = this.transcript.record({
        op: 'http2', startedAt: started, durationMs: h2.durationMs, request: prep.requestMeta, body,
        response: {
          status: h2.status, headers: this.scrubRecord(h2.headers), bodyBytes: Buffer.byteLength(h2.body),
          bodySha256: createHash('sha256').update(body).digest('hex'), mediaType: h2.headers['content-type'] ?? 'application/octet-stream',
        },
      })
      this.recordRequestProvenance(record.exchangeId, started, args, prep.applied.brokerRequest, prep.requestMeta, { body: h2.body, respHeaders: h2.headers }, prep.applied.attestations, prep.cryptoAttestations, prep.cleanSession)
      return this.scrubRecord({
        exchangeId: record.exchangeId, status: h2.status, headers: h2.headers, body: body.slice(0, 512 * 1024),
        bodyBytes: Buffer.byteLength(h2.body), bodySha256: record.response?.bodySha256, durationMs: h2.durationMs,
        mediaType: record.response?.mediaType, protocol: 'h2',
        ...(prep.applied.attestation?.consumedCapabilityId ? { consumedCapabilityId: prep.applied.attestation.consumedCapabilityId } : {}),
        ...(prep.consumedIds.length ? { consumedCapabilities: prep.consumedIds } : {}),
        ...(prep.derivedFromCapabilityIds.length ? { derivedFromCapabilityIds: prep.derivedFromCapabilityIds } : {}),
      })
    } catch (error) {
      const msg = this.scrub(error instanceof Error ? error.message : 'HTTP/2 exchange failed.')
      const record = this.transcript.record({ op: 'http2', startedAt: started, durationMs: Date.now() - started, request: prep.requestMeta, error: msg, errorCode: /scope|denied|approval|forbidden|outside|header/i.test(msg) ? 'denied' : 'failed' })
      throw new Error(`${record.exchangeId}: ${msg}`)
    }
  }

  /** HTTP/2 stays on the same grant: scope, persona injection, method approval. */
  private async executeHttp2(req: BrokerHttpRequest, signal: AbortSignal, grant: Grant = this.options.grant): Promise<{ status: number; headers: Record<string, string>; body: string; durationMs: number }> {
    const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
    let url: URL
    try {
      url = new URL(req.pathAndQuery, req.origin)
    } catch { throw new Error('Request origin or path is malformed.') }
    if (url.origin !== new URL(req.origin).origin) throw new Error('Request path escaped the requested origin.')
    if (!grant.canRead(url.origin)) throw new Error('Destination is outside the current assignment scope.')
    const protocolOk = url.protocol === 'https:' || (localLab && url.protocol === 'http:')
    if (!protocolOk || url.username || url.password || url.hash) throw new Error('HTTP/2 destination is outside the current assignment scope.')
    if (!localLab && url.port && url.port !== '443') {
      const numeric = Number(url.port)
      if (!Number.isInteger(numeric) || !(grant.allowedPorts ?? []).includes(numeric)) throw new Error('HTTP/2 destination port is not approved for this run.')
    }
    const addresses = await lookup(url.hostname, { all: true, order: 'verbatim' })
    if (addresses.length === 0) throw new Error('Target hostname did not resolve.')
    for (const address of addresses) {
      const range = ipaddr.process(address.address).range()
      if (range === 'linkLocal') throw new Error('Link-local/metadata destinations are never permitted.')
      if (!localLab && range !== 'unicast') throw new Error('Target hostname did not resolve exclusively to public addresses.')
    }
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS') {
      const tier = grant.tier ?? 1
      if (tier < 2) throw new Error('HTTP/2 state changes require Tier 2 or higher.')
      const approved = grant.isStateChangeApproved?.(url.origin, req.method, req.pathAndQuery, {
        personaHandle: req.persona ?? req.personaHandle ?? null,
        body: req.body ?? null,
      })
      if (!approved) throw new Error('Tier 3 operator approval required for this HTTP/2 state change.')
    }
    const forwarded = new Set(['authorization', 'proxy-authorization', 'cookie', 'host', 'content-length', 'transfer-encoding', 'x-guardian-trace-id'])
    const headers: Record<string, string> = {}
    for (const [key, value] of Object.entries(req.headers ?? {})) {
      if (forwarded.has(key.toLowerCase())) throw new Error(`Header "${key}" cannot be set directly; reference an approved persona handle instead.`)
      headers[key] = value
    }
    const personaHandle = req.persona ?? req.personaHandle
    if (personaHandle) {
      const persona = grant.personas?.get(personaHandle)
      if (!persona) throw new Error(`Persona "${personaHandle}" is not approved for this run.`)
      const injected = buildPersonaHeader(persona, url.origin)
      if (!injected) throw new Error(`Persona "${personaHandle}" does not have an active authenticated session.`)
      Object.assign(headers, injected)
    }
    const started = Date.now()
    const authority = `${url.protocol}//${url.host}`
    const client = h2Connect(authority, { rejectUnauthorized: true })
    try {
      signal.throwIfAborted()
      const aborted = new Promise<never>((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('HTTP/2 request timed out.')), { once: true })
      })
      const responsePromise = new Promise<{ status: number; headers: Record<string, string>; body: string }>((resolve, reject) => {
        client.once('error', reject)
        const stream = client.request({
          ':method': req.method,
          ':path': req.pathAndQuery,
          ...(req.body ? { 'content-length': String(Buffer.byteLength(req.body)) } : {}),
          ...headers,
        })
        let status = 0
        let responseHeaders: Record<string, string> = {}
        const chunks: Buffer[] = []
        let captured = 0
        stream.on('response', value => {
          status = Number(value[':status'] ?? 0)
          responseHeaders = {}
          for (const [k, v] of Object.entries(value)) {
            if (k.startsWith(':') || v === undefined) continue
            responseHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v)
          }
        })
        stream.on('data', (chunk: Buffer) => {
          captured += chunk.length
          if (captured > 2 * 1024 * 1024) {
            stream.close(h2constants.NGHTTP2_CANCEL)
            reject(new Error('HTTP/2 response exceeded the 2 MiB verification limit.'))
            return
          }
          chunks.push(chunk)
        })
        stream.once('error', reject)
        stream.once('end', () => resolve({ status, headers: responseHeaders, body: Buffer.concat(chunks).toString('utf8') }))
        if (req.body) stream.end(req.body)
        else stream.end()
      })
      const response = await Promise.race([responsePromise, aborted])
      return { ...response, durationMs: Date.now() - started }
    } finally {
      client.close()
    }
  }

  private async handleBrowser(args: Record<string, unknown>, nonce: string): Promise<unknown> {
    const { origin } = this.scopeOrigin(args.origin)
    const rawPath = typeof args.path === 'string' ? args.path : '/'
    const url = new URL(rawPath, origin)
    if (url.origin !== origin || !this.options.grant.canRead(url.origin)) throw new Error('Destination is outside the current assignment scope.')
    const driver = this.options.browser
    if (!driver) throw new Error('Browser verification is not available for this run.')
    const personaHandle = typeof args.persona === 'string' ? args.persona : typeof args.as === 'string' ? args.as : null
    const headers: Record<string, string> = {}
    if (personaHandle) {
      const persona = this.options.grant.personas?.get(personaHandle)
      if (!persona) throw new Error(`Persona "${personaHandle}" is not approved for this run.`)
      const injected = buildPersonaHeader(persona, url.origin)
      if (!injected) throw new Error(`Persona "${personaHandle}" does not have an active authenticated session.`)
      Object.assign(headers, injected)
    }
    const started = Date.now()
    try {
      const result = await driver.open({
        url: url.href,
        origin,
        personaHandle,
        headers,
        ...(typeof args.waitForSelector === 'string' ? { waitForSelector: args.waitForSelector } : {}),
        timeoutMs: this.options.callTimeoutMs ?? 30_000,
      }, AbortSignal.timeout(this.options.callTimeoutMs ?? 30_000))
      const html = this.scrub(result.html)
      // Never persist injected persona headers: the transcript is readable by the script.
      const recordedHeaders = Object.fromEntries(Object.keys(headers).map(key => [key, '[injected]']))
      const record = this.transcript.record({
        op: 'browser',
        startedAt: started,
        durationMs: Date.now() - started,
        request: {
          origin,
          method: 'GET',
          pathAndQuery: rawPath,
          headers: recordedHeaders,
          bodyBytes: 0,
          bodySha256: createHash('sha256').update('').digest('hex'),
          personaHandle,
          nonce: this.nonce,
        },
        response: {
          status: result.status,
          headers: {},
          bodyBytes: Buffer.byteLength(html),
          bodySha256: createHash('sha256').update(html).digest('hex'),
          mediaType: 'text/html',
        },
        artifact: {
          kind: 'browser',
          ...(result.executedSentinels?.length ? { executedSentinels: this.scrubRecord(result.executedSentinels) } : {}),
          domHtmlSha256: createHash('sha256').update(html).digest('hex'),
        },
        body: html,
      })
      this.rawBodies.set(record.exchangeId, result.html)
      const prov = this.getOrCreateProvenance(record.exchangeId, started)
      prov.timestampMs = started
      return this.scrubRecord({
        exchangeId: record.exchangeId,
        status: result.status,
        url: result.url,
        html: html.slice(0, 512 * 1024),
        title: result.title,
        executedSentinels: result.executedSentinels ?? [],
        durationMs: record.durationMs,
      })
    } catch (error) {
      const record = this.transcript.record({
        op: 'browser',
        startedAt: started,
        durationMs: Date.now() - started,
        request: { origin, method: 'GET', pathAndQuery: rawPath, headers: Object.fromEntries(Object.keys(headers).map(key => [key, '[injected]'])), bodyBytes: 0, bodySha256: createHash('sha256').update('').digest('hex'), personaHandle, nonce },
        error: error instanceof Error ? error.message : 'Browser verification failed.',
      })
      throw new Error(`${record.exchangeId}: ${error instanceof Error ? error.message : 'Browser verification failed.'}`)
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
        const body = this.scrub(result.body)
        const record = this.transcript.record({
          op: mode.mode === 'h2-single-packet' ? 'http2' : 'http',
          startedAt: started, durationMs: result.durationMs, request: prep.requestMeta, body,
          response: { status: result.status, headers: this.scrubRecord(result.respHeaders), bodyBytes: result.bodyBytes, bodySha256: result.bodySha256, mediaType: result.mediaType },
        })
        const capRaw = rawCaptures[index]
        this.recordRequestProvenance(record.exchangeId, started, itemArgs, prep.applied.brokerRequest, prep.requestMeta, capRaw ? { body: capRaw.body, respHeaders: capRaw.headers } : { body: result.body, respHeaders: result.respHeaders }, prep.applied.attestations, prep.cryptoAttestations, prep.cleanSession)
        return this.exchangeView(record, { ...result, body }, {
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

  private async handleOob(args: Record<string, unknown>): Promise<unknown> {
    const canary = this.options.canary ?? (this.options.grant as Grant & { canaryBroker?: VerifyCanaryBroker }).canaryBroker
    if (!canary) throw new Error('OOB canaries are not available for this run.')
    const action = typeof args.action === 'string' ? args.action : 'mint'
    if (action === 'mint') {
      const label = typeof args.label === 'string' ? args.label.slice(0, 80) : 'verify'
      const origin = typeof args.origin === 'string' ? args.origin : undefined
      const started = Date.now()
      const minted = canary.mintCanary(this.options.runId, label, origin, { assignmentId: this.options.assignmentId })
      const record = this.transcript.record({
        op: 'oob',
        startedAt: started,
        durationMs: Date.now() - started,
        request: { origin: origin ?? '', method: 'MINT', pathAndQuery: '/', headers: {}, bodyBytes: 0, bodySha256: createHash('sha256').update('').digest('hex'), nonce: this.nonce },
        artifact: { kind: 'oob-mint', token: minted.token, url: minted.httpUrl, dnsHost: minted.dnsHost, hit: false },
      })
      return this.scrubRecord({ exchangeId: record.exchangeId, token: minted.token, url: minted.httpUrl, dnsHost: minted.dnsHost })
    }
    if (action === 'subscribe') {
      const token = typeof args.token === 'string' ? args.token.trim().toLowerCase() : ''
      if (!token) throw new Error('oob subscribe requires a canary token.')
      if (!canary.subscribe) {
        throw new Error('OOB relay does not expose durable pending_oob subscriptions; a late callback cannot be promoted.')
      }
      const exchangeId = typeof args.exchangeId === 'string' ? args.exchangeId : ''
      const immediateMs = typeof args.immediateMs === 'number' ? Math.max(0, Math.min(args.immediateMs, 30_000)) : undefined
      const windowMs = typeof args.windowMs === 'number' ? Math.max(1_000, Math.min(args.windowMs, 30 * 60_000)) : undefined
      const started = Date.now()
      const subscription = canary.subscribe({
        runId: this.options.runId,
        assignmentId: this.options.assignmentId,
        canaryId: typeof args.canaryId === 'string' && args.canaryId ? args.canaryId : token,
        token,
        artifact: exchangeId,
        ...(immediateMs !== undefined ? { immediateMs } : {}),
        ...(windowMs !== undefined ? { windowMs } : {}),
      })
      this.transcript.record({
        op: 'oob',
        startedAt: started,
        durationMs: Date.now() - started,
        request: { origin: '', method: 'SUBSCRIBE', pathAndQuery: `/oob/pending/${subscription.id}`, headers: {}, bodyBytes: 0, bodySha256: createHash('sha256').update(subscription.id).digest('hex'), nonce: this.nonce },
        artifact: { kind: 'oob-mint', token, hit: false },
      })
      return this.scrubRecord({
        subscriptionId: subscription.id,
        token,
        status: subscription.status ?? 'pending',
        createdAt: subscription.createdAt ?? started,
        expiresAt: subscription.expiresAt ?? null,
        immediateMs: subscription.immediateMs ?? immediateMs ?? null,
        windowMs: subscription.windowMs ?? windowMs ?? null,
      })
    }
    if (action === 'wait') {
      const token = typeof args.token === 'string' ? args.token.trim().toLowerCase() : ''
      if (!token) throw new Error('oob wait requires a canary token.')
      const subscriptionId = typeof args.subscriptionId === 'string' ? args.subscriptionId : null
      const subscriptionCreatedAt = typeof args.subscriptionCreatedAt === 'number' ? args.subscriptionCreatedAt : null
      const immediateMs = typeof args.immediateMs === 'number' ? Math.max(0, Math.min(args.immediateMs, 30_000)) : 3_000
      const timeoutMs = typeof args.timeoutMs === 'number' ? Math.max(0, Math.min(args.timeoutMs, 60_000)) : immediateMs
      const immediateDeadline = (subscriptionCreatedAt ?? Date.now()) + immediateMs
      const t0 = Date.now()
      let check = canary.checkCanary(token, { runId: this.options.runId })
      let callbackReceivedAt: number | null = null
      let promoted = false
      let matched = check.hit
      if (!matched && canary.awaitAny) {
        try {
          const awaited = await canary.awaitAny({ token, runId: this.options.runId }, { timeoutMs, pollMs: 100 })
          matched = awaited.matched
          callbackReceivedAt = awaited.callback?.receivedAt ?? null
        } catch { /* fall through to the recorded in-memory check */ }
      }
      const promotions = (() => {
        try { return canary.promoteLate?.({ runId: this.options.runId }) ?? [] } catch { return [] }
      })()
      const promotion = promotions.find(item => item.subscription.token === token || item.subscription.id === subscriptionId)
      if (promotion) {
        promoted = true
        matched = true
        callbackReceivedAt = callbackReceivedAt ?? promotion.callback.receivedAt ?? null
      }
      check = canary.checkCanary(token, { runId: this.options.runId })
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
        artifact: { kind: 'oob-mint', token, hit },
      })
      return this.scrubRecord({
        exchangeId: record.exchangeId,
        checkExchangeId: record.exchangeId,
        subscriptionId: promotion?.subscription.id ?? subscriptionId,
        token,
        hit,
        stage,
        promoted,
        receivedAt,
        hits: check.hits.slice(-5),
      })
    }
    if (action === 'check') {
      const token = typeof args.token === 'string' ? args.token : ''
      if (!token) throw new Error('oob check requires a canary token.')
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

  private extractSecretFromExchange(exchangeId: string, args: Record<string, unknown>): string {
    const rawBody = this.rawBodies.get(exchangeId) ?? this.transcript.body(exchangeId) ?? ''
    const rawHeaders = this.rawResponseHeaders.get(exchangeId) ?? this.transcript.get(exchangeId)?.response?.headers ?? {}
    const record = this.transcript.get(exchangeId)
    const artifactText = record?.artifact?.token ?? record?.artifact?.url ?? ''

    if (typeof args.jsonPath === 'string' && args.jsonPath.trim()) {
      let parsed: unknown, jsonOk = true
      try { parsed = JSON.parse(rawBody) } catch { jsonOk = false }
      if (!jsonOk) {
        if (!(typeof args.regex === 'string' && args.regex.trim())) {
          const st = record?.response?.status ?? 'unknown'
          const ct = Object.entries(rawHeaders).find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? record?.response?.mediaType ?? 'unknown'
          const preview = redact(this.scrub(rawBody)).replace(/\s+/g, ' ').trim().slice(0, 60)
          throw new Error(`Exchange "${exchangeId}" response body is not valid JSON for jsonPath extraction (HTTP ${st} ${ct}; preview: "${preview}"). Use regex/header/cookie for non-JSON bodies.`)
        }
      } else {
        const evalRes = resolveSealJsonPath(parsed, args.jsonPath.trim())
        if (!evalRes.found || evalRes.value === undefined || evalRes.value === null) throw new Error(`jsonPath "${args.jsonPath}" did not match exchange "${exchangeId}" (${this.scrub(describeJsonTopKeys(parsed))}).`)
        const extracted = typeof evalRes.value === 'string' ? evalRes.value : String(evalRes.value)
        if (!extracted) throw new Error(`jsonPath "${args.jsonPath}" resolved to an empty value.`)
        return extracted
      }
    }

    if (typeof args.header === 'string' && args.header.trim()) {
      const wanted = args.header.trim().toLowerCase()
      const entry = Object.entries(rawHeaders).find(([k]) => k.toLowerCase() === wanted)
      if (!entry || !entry[1]) throw new Error(`Header "${args.header}" not found in exchange "${exchangeId}".`)
      return entry[1]
    }

    if (typeof args.cookie === 'string' && args.cookie.trim()) {
      const cookieName = args.cookie.trim()
      const setCookie = Object.entries(rawHeaders).find(([k]) => k.toLowerCase() === 'set-cookie')?.[1] ?? ''
      const escaped = cookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      const match = new RegExp(`(?:^|[,;\\s])${escaped}=([^;\\r\\n]+)`).exec(setCookie)
      if (!match?.[1]) throw new Error(`Cookie "${cookieName}" not found in Set-Cookie headers of exchange "${exchangeId}".`)
      return match[1].trim()
    }

    if (typeof args.regex === 'string' && args.regex.trim()) {
      if (args.regex.length > 256) throw new Error('capability.seal regex exceeds maximum length (256).')
      let re: RegExp
      try { re = new RegExp(args.regex) } catch { throw new Error('capability.seal regex is invalid.') }
      const match = re.exec(rawBody)
      const extracted = match?.[1] ?? match?.[0]
      if (!extracted) throw new Error(`Regex did not match exchange "${exchangeId}" body.`)
      return extracted
    }

    const candidateRaw = typeof args.value === 'string' ? args.value : typeof args.rawValue === 'string' ? args.rawValue : null
    if (candidateRaw !== null && candidateRaw.length > 0) {
      const haystack = [rawBody, ...Object.values(rawHeaders), artifactText].join('\n')
      if (!haystack.includes(candidateRaw)) {
        throw new Error(`Refusing to seal unverified value not observed in host-recorded exchange "${exchangeId}".`)
      }
      return candidateRaw
    }

    throw new Error('capability.seal requires an extraction selector (jsonPath, header, cookie, regex, or host-verified value).')
  }

  private handleCapabilitySeal(args: Record<string, unknown>, nonce: string): unknown {
    const exchangeId = typeof args.exchangeId === 'string' ? args.exchangeId.trim() : ''
    if (!exchangeId) throw new Error('capability.seal requires exchangeId referencing a host-recorded exchange.')
    const sourceRecord = this.transcript.get(exchangeId)
    if (!sourceRecord) throw new Error(`Unknown exchangeId "${exchangeId}" for capability.seal.`)

    const slot = typeof args.slot === 'string' ? args.slot.trim() : ''
    if (!slot) throw new Error('capability.seal requires a non-empty slot name.')
    const hopReceiptId = typeof args.hopReceiptId === 'string' && args.hopReceiptId.trim() ? args.hopReceiptId.trim() : typeof args.hopId === 'string' && args.hopId.trim() ? args.hopId.trim() : exchangeId
    const kind = normalizeDerivedSecretKind(args.kind)
    const ttlMs = args.ttlMs === null ? null : typeof args.ttlMs === 'number' ? args.ttlMs : undefined
    const allowedOrigins = Array.isArray(args.allowedOrigins) ? args.allowedOrigins.filter((v): v is string => typeof v === 'string' && v.trim().length > 0) : undefined
    const rawValue = this.extractSecretFromExchange(exchangeId, args)
    const defaultHeaderName = typeof args.defaultHeaderName === 'string' && args.defaultHeaderName.trim() ? args.defaultHeaderName.trim() : undefined
    const defaultCookieName = typeof args.defaultCookieName === 'string' && args.defaultCookieName.trim() ? args.defaultCookieName.trim() : (typeof args.cookie === 'string' && args.cookie.trim() ? args.cookie.trim() : undefined)
    const effectiveKind = kind ?? (defaultCookieName || (!defaultHeaderName && COOKIE_PAIR_VALUE_RE.test(rawValue)) ? 'cookie' : undefined)
    const meta = this.capabilityVault.seal({
      hopReceiptId, slot, rawValue,
      ...(effectiveKind ? { kind: effectiveKind } : {}), ...(ttlMs !== undefined ? { ttlMs } : {}),
      ...(defaultHeaderName ? { defaultHeaderName } : {}), ...(defaultCookieName ? { defaultCookieName } : {}),
      ...(allowedOrigins?.length ? { allowedOrigins } : {}),
    })

    // Attach host-side provenance to the originating exchange and retroactively scrub transcript bodies.
    const sourceProv = this.getOrCreateProvenance(exchangeId, sourceRecord.startedAt)
    sourceProv.emittedCapabilities.add(meta.handle)
    sourceProv.observedResponseDigests.add(meta.sha256)
    this.transcript.rescrubBodies(text => this.scrub(text))

    const started = this.nextHostTimestampMs()
    const sealRecord = this.transcript.record({
      op: 'capability',
      startedAt: started,
      durationMs: 0,
      request: {
        origin: sourceRecord.request?.origin ?? '',
        method: 'SEAL',
        pathAndQuery: `/capability/seal/${encodeURIComponent(slot)}`,
        headers: {},
        bodyBytes: 0,
        bodySha256: meta.sha256,
        personaHandle: sourceRecord.request?.personaHandle ?? null,
        sessionRole: sourceRecord.request?.sessionRole ?? 'probe',
        actorRoleLabel: sourceRecord.request?.actorRoleLabel ?? null,
        nonce,
      },
      artifact: {
        kind: 'capability',
        capabilityHandle: meta.handle,
        artifactDigest: meta.sha256,
      },
    })
    const sealProv = this.getOrCreateProvenance(sealRecord.exchangeId, started)
    sealProv.emittedCapabilities.add(meta.handle)
    sealProv.observedResponseDigests.add(meta.sha256)

    const scrubbedPreview = redact(this.scrub((this.rawBodies.get(exchangeId) ?? '').slice(0, 1024)))
    return this.scrubRecord({
      handle: meta.handle,
      meta,
      exchangeId,
      sealExchangeId: sealRecord.exchangeId,
      scrubbedPreview,
    })
  }

  private handleCryptoHmacSign(args: Record<string, unknown>, nonce: string): unknown {
    const secretHandle = typeof args.secretHandle === 'string' ? args.secretHandle.trim() : ''
    if (!secretHandle) throw new Error('crypto.hmacSign requires secretHandle.')
    const payload = typeof args.payload === 'string' ? args.payload : ''
    if (typeof args.payload !== 'string') throw new Error('crypto.hmacSign requires a string payload.')
    const alg = (typeof args.alg === 'string' ? args.alg.trim().toLowerCase() : 'sha256') as HostHmacAlg
    const encoding = (typeof args.encoding === 'string' ? args.encoding.trim().toLowerCase() : 'hex') as HostHmacEncoding

    const signed = this.capabilityVault.hostHmacSign({
      secretHandle,
      payload,
      alg,
      encoding,
      runId: this.capabilityVault.runId,
    })
    const ts = this.nextHostTimestampMs()
    const hostAttestation: HostCryptoAttestation = {
      derivedFromCapabilityId: signed.attestation.derivedFromCapabilityId,
      alg: signed.attestation.alg,
      artifactDigest: signed.attestation.signatureDigest,
      timestampMs: ts,
    }
    this.hmacDerivations.set(signed.signature, hostAttestation)

    const record = this.transcript.record({
      op: 'crypto',
      startedAt: ts,
      durationMs: 0,
      request: {
        origin: this.options.targetOrigins?.[0] ?? '',
        method: 'HMAC_SIGN',
        pathAndQuery: `/crypto/hmac/${alg}`,
        headers: {},
        bodyBytes: Buffer.byteLength(payload),
        bodySha256: signed.attestation.payloadDigest,
        personaHandle: null,
        sessionRole: 'probe',
        actorRoleLabel: null,
        derivedFromCapabilityId: signed.attestation.derivedFromCapabilityId,
        nonce,
      },
      artifact: {
        kind: 'crypto',
        derivedFromCapabilityId: signed.attestation.derivedFromCapabilityId,
        alg: signed.attestation.alg,
        artifactDigest: signed.attestation.signatureDigest,
      },
    })
    const prov = this.getOrCreateProvenance(record.exchangeId, ts)
    prov.cryptoAttestations.push(hostAttestation)
    prov.observedResponseDigests.add(signed.attestation.signatureDigest)
    prov.cleanSession = true

    return this.scrubRecord({
      exchangeId: record.exchangeId,
      signature: signed.signature,
      attestation: { ...signed.attestation, timestampMs: ts },
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
    const ttlMs = args.ttlMs === null ? null : typeof args.ttlMs === 'number' ? args.ttlMs : undefined
    const allowedOrigins = Array.isArray(args.allowedOrigins)
      ? args.allowedOrigins.filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
      : undefined

    const minted = this.capabilityVault.hostJwtSign({
      secretHandle,
      claims,
      ...(header ? { header } : {}),
      alg,
      ...(typeof args.hopReceiptId === 'string' && args.hopReceiptId.trim() ? { hopReceiptId: args.hopReceiptId.trim() } : {}),
      ...(typeof args.slot === 'string' && args.slot.trim() ? { slot: args.slot.trim() } : {}),
      ...(ttlMs !== undefined ? { ttlMs } : {}),
      ...(allowedOrigins?.length ? { allowedOrigins } : {}),
      runId: this.capabilityVault.runId,
    })
    const ts = this.nextHostTimestampMs()
    const hostAttestation: HostCryptoAttestation = {
      derivedFromCapabilityId: minted.attestation.derivedFromCapabilityId,
      derivedCapabilityId: minted.derivedHandle,
      alg: minted.attestation.alg,
      artifactDigest: minted.attestation.tokenDigest,
      timestampMs: ts,
    }
    this.jwtDerivations.set(minted.derivedHandle, hostAttestation)

    const record = this.transcript.record({
      op: 'crypto',
      startedAt: ts,
      durationMs: 0,
      request: {
        origin: this.options.targetOrigins?.[0] ?? '',
        method: 'JWT_SIGN',
        pathAndQuery: `/crypto/jwt/${alg}`,
        headers: {},
        bodyBytes: 0,
        bodySha256: minted.attestation.claimsDigest,
        personaHandle: null,
        sessionRole: 'probe',
        actorRoleLabel: null,
        derivedFromCapabilityId: minted.attestation.derivedFromCapabilityId,
        nonce,
      },
      artifact: {
        kind: 'crypto',
        derivedFromCapabilityId: minted.attestation.derivedFromCapabilityId,
        derivedCapabilityId: minted.derivedHandle,
        alg: minted.attestation.alg,
        artifactDigest: minted.attestation.tokenDigest,
      },
    })
    const prov = this.getOrCreateProvenance(record.exchangeId, ts)
    prov.emittedCapabilities.add(minted.derivedHandle)
    prov.observedResponseDigests.add(minted.attestation.tokenDigest)
    prov.cryptoAttestations.push(hostAttestation)
    prov.cleanSession = true

    // Raw JWT is sealed host-side behind derivedHandle and never returned to the worker.
    return this.scrubRecord({
      exchangeId: record.exchangeId,
      derivedHandle: minted.derivedHandle,
      attestation: { ...minted.attestation, timestampMs: ts },
    })
  }

  private matchAsyncPredicate(
    predicate: Record<string, unknown> | null,
    pollOutcome: { status: number; body: string; headers: Record<string, string> },
  ): boolean {
    if (!predicate || Object.keys(predicate).length === 0) {
      return pollOutcome.status >= 200 && pollOutcome.status < 300 && pollOutcome.body.trim().length > 0
    }
    if (predicate.status !== undefined) {
      const expected = Array.isArray(predicate.status) ? predicate.status : [predicate.status]
      if (!expected.includes(pollOutcome.status)) return false
    }
    if (typeof predicate.bodyContains === 'string' && !pollOutcome.body.includes(predicate.bodyContains)) {
      return false
    }
    if (typeof predicate.bodyMatches === 'string') {
      if (predicate.bodyMatches.length > 256) throw new Error('async.awaitResult bodyMatches regex exceeds 256 chars.')
      let re: RegExp
      try { re = new RegExp(predicate.bodyMatches) } catch { throw new Error('async.awaitResult bodyMatches regex is invalid.') }
      if (!re.test(pollOutcome.body)) return false
    }
    if (typeof predicate.jsonPath === 'string' && predicate.jsonPath.trim()) {
      let parsed: unknown
      try { parsed = JSON.parse(pollOutcome.body) } catch { return false }
      const evalRes = evaluateJsonPath(parsed, predicate.jsonPath.trim())
      if (!evalRes.found) return false
      if (predicate.equals !== undefined && JSON.stringify(evalRes.value) !== JSON.stringify(predicate.equals)) return false
      if (Array.isArray(predicate.in) && !predicate.in.some(v => JSON.stringify(v) === JSON.stringify(evalRes.value))) return false
      if (typeof predicate.matches === 'string') {
        let re: RegExp
        try { re = new RegExp(predicate.matches) } catch { throw new Error('async.awaitResult jsonPath matches regex is invalid.') }
        if (!re.test(String(evalRes.value ?? ''))) return false
      }
    }
    const headerPred = asRecord(predicate.header)
    if (headerPred && typeof headerPred.name === 'string') {
      const wanted = headerPred.name.toLowerCase()
      const val = Object.entries(pollOutcome.headers).find(([k]) => k.toLowerCase() === wanted)?.[1]
      if (val === undefined) return false
      if (typeof headerPred.equals === 'string' && val !== headerPred.equals) return false
      if (typeof headerPred.matches === 'string') {
        let re: RegExp
        try { re = new RegExp(headerPred.matches) } catch { throw new Error('async.awaitResult header matches regex is invalid.') }
        if (!re.test(val)) return false
      }
    }
    return true
  }

  private async handleAsyncAwaitResult(args: Record<string, unknown>, nonce: string): Promise<unknown> {
    const pollReqArgs = asRecord(args.pollRequest ?? args.request)
    if (!pollReqArgs) throw new Error('async.awaitResult requires a pollRequest object.')
    const matchPredicate = args.matchPredicate !== undefined ? asRecord(args.matchPredicate)
      : args.match !== undefined ? asRecord(args.match) : null

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
    const capArg = this.parseCapabilityArg(pollReqArgs)
    type LastPoll = { result: BrokerExchangeResult; rawResp: { body: string; headers: Record<string, string> } | null; startedAt: number; applied: ReturnType<VerifyRpcServer['applyCapabilityInjection']>; cryptoAtts: HostCryptoAttestation[]; cleanSession: boolean }
    let lastBrokerResult: LastPoll | null = null

    const convergence = await awaitAsyncConvergence({
      ...(profile ? { profile } : {}),
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      ...(intervalMs !== undefined ? { intervalMs } : {}),
      ...(maxAttempts !== undefined ? { maxAttempts } : {}),
      ...(tTriggerMs !== undefined ? { tTriggerMs } : {}),
      now: () => this.nextHostTimestampMs(),
      pollFn: async ({ signal }) => {
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
        return { status: result.status, body: result.body, headers: result.respHeaders, observedAtMs: this.nextHostTimestampMs() }
      },
      matchPredicate: (val) => this.matchAsyncPredicate(matchPredicate, val),
      extractObservedAtMs: (val) => val.observedAtMs,
    })

    let finalRecord: VerifyTranscriptRecord | null = null
    let finalExchangeView: unknown = null
    if (lastBrokerResult) {
      const last = lastBrokerResult as LastPoll
      const reqMeta: VerifyTranscriptRequest = {
        ...last.applied.requestMeta,
        ...(last.cryptoAtts.length > 0 ? { derivedFromCapabilityId: last.cryptoAtts[0]!.derivedFromCapabilityId } : {}),
        nonce,
      }
      const scrubbedBody = this.scrub(last.result.body)
      finalRecord = this.transcript.record({
        op: 'http', startedAt: last.startedAt, durationMs: last.result.durationMs, request: reqMeta, body: scrubbedBody,
        response: {
          status: last.result.status, headers: this.scrubRecord(last.result.respHeaders), bodyBytes: last.result.bodyBytes,
          bodySha256: last.result.bodySha256, mediaType: last.result.mediaType, redirectOrigins: last.result.redirectOrigins,
          ...(last.result.finalPathAndQuery ? { finalPathAndQuery: this.scrub(last.result.finalPathAndQuery) } : {}),
        },
      })
      const mergedPollArgs = { ...pollReqArgs, ...(args.entityId !== undefined ? { entityId: args.entityId } : {}), ...(args.correlationId !== undefined ? { correlationId: args.correlationId } : {}), ...(args.correlationIds !== undefined ? { correlationIds: args.correlationIds } : {}) }
      const rawProv = last.rawResp ? { body: last.rawResp.body, respHeaders: last.rawResp.headers } : { body: last.result.body, respHeaders: last.result.respHeaders }
      this.recordRequestProvenance(finalRecord.exchangeId, last.startedAt, mergedPollArgs, last.applied.brokerRequest, reqMeta, rawProv, last.applied.attestations, last.cryptoAtts, last.cleanSession)
      finalExchangeView = this.exchangeView(finalRecord, { ...last.result, body: scrubbedBody }, {
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
    const lastBodyText = lastBrokerResult ? (lastBrokerResult as { result: BrokerExchangeResult }).result.body : ''
    const verifiedCorr = rawCorr.filter(c => lastBodyText.includes(c) || parsedPoll.brokerRequest.pathAndQuery.includes(c))
    const entityId = typeof args.entityId === 'string' && args.entityId.trim()
      && (lastBodyText.includes(args.entityId.trim()) || parsedPoll.brokerRequest.pathAndQuery.includes(args.entityId.trim()))
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
        pathAndQuery: this.scrub(parsedPoll.requestMeta.pathAndQuery),
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

      const scrubbedBody = this.scrub(this.transcript.body(record.exchangeId) ?? '')
      let parsedJson: unknown
      if (scrubbedBody.trim()) {
        try { parsedJson = JSON.parse(scrubbedBody) } catch { parsedJson = undefined }
      }
      let parsedReqJson: unknown
      if (prov?.rawRequestBody?.trim()) {
        try { parsedReqJson = JSON.parse(this.scrub(prov.rawRequestBody)) } catch { parsedReqJson = undefined }
      }
      const handle = record.request?.personaHandle ?? null
      const signedLabel = record.request?.actorRoleLabel ?? null
      const parsedLabel = parseRoleLabel(signedLabel)
      const role = signedLabel !== null
        ? (normalizeRole(signedLabel) ?? normalizeRole(handle) ?? null)
        : (normalizeRole(handle) ?? null)
      const tenant = parsedLabel.tenant ?? parseRoleLabel(handle).tenant ?? null
      const rawRole = record.request?.sessionRole
      const arm: ImpactStep['arm'] = rawRole === 'control' || rawRole === 'setup' || rawRole === 'cleanup' || rawRole === 'probe'
        ? rawRole
        : 'probe'
      const pathAndQuery = record.request?.pathAndQuery ?? '/'
      const route = pathAndQuery.split('?')[0].replace(/\/+$/, '').toLowerCase() || '/'
      const status = record.response?.status != null && Number.isFinite(Number(record.response.status))
        ? Number(record.response.status)
        : (record.op === 'crypto' || record.op === 'capability' ? 200 : null)

      const entry: HostTranscriptEntry = {
        exchangeId: record.exchangeId,
        durationMs: record.durationMs,
        ...(prov?.carrierText ? { carrierText: prov.carrierText } : {}),
        ...(prov?.evidenceRole ? { evidenceRole: prov.evidenceRole } : (record.op === 'crypto' || record.op === 'capability' ? { evidenceRole: `host_${record.op}_op` } : {})),
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
            auth: 'unknown',
            sameSite: sameSiteFromRecord(record),
          },
          ...(parsedJson !== undefined ? { json: parsedJson } : {}),
          body: scrubbedBody,
          ...(parsedReqJson !== undefined ? { requestJson: parsedReqJson } : {}),
          requestHeaders: record.request?.headers ?? null,
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

  /** Host-side verification of a CompositeProofReceipt against this session's signed transcript & capability vault. */
  verifyComposite(
    rawReceipt: unknown,
    options?: Omit<CompositeVerifyOptions, 'signingKey'>,
  ): CompositeReceiptVerification {
    const transcript = this.buildHostSignedTranscript()
    return verifyCompositeReceipt(rawReceipt, transcript, {
      ...this.options.compositeVerifyOptions,
      ...options,
      signingKey: this.compositeSigningKey,
    })
  }

  private handleCompositeVerify(args: Record<string, unknown>): unknown {
    const rawReceipt = args.receipt !== undefined ? args.receipt : args
    // Security invariant: RPC callers can never weaken host-configured attackerPersonas,
    // forbiddenShortcutPersonas, benchmarkMode, requireCleanSessionFlag, or signingKey.
    const verdict = this.verifyComposite(rawReceipt)
    const rawObj = asRecord(rawReceipt)
    const hops = Array.isArray(rawObj?.hops) ? rawObj.hops : []
    const ti = asRecord(rawObj?.terminalImpact)
    const terminalHopId = typeof ti?.terminalHopId === 'string' ? ti.terminalHopId : ''
    const termHop = hops.find(h => asRecord(h)?.hopId === terminalHopId) ?? hops[hops.length - 1]
    const termHopObj = asRecord(termHop)
    const termTarget = asRecord(termHopObj?.target)
    const rawRoute = typeof termTarget?.pathAndQuery === 'string' && termTarget.pathAndQuery.trim()
      ? termTarget.pathAndQuery.trim()
      : null
    const route = rawRoute ?? verdict.terminalEndpoint ?? null
    const strIds = (v: unknown): string[] => Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.length > 0) : []
    const exchangeIds = [...new Set([
      ...hops.flatMap(h => strIds(asRecord(h)?.exchangeIds)),
      ...strIds(ti?.preChainControlExchangeIds),
      ...strIds(ti?.postChainReadbackExchangeIds),
      ...(typeof ti?.terminalExchangeId === 'string' && ti.terminalExchangeId.trim() ? [ti.terminalExchangeId.trim()] : []),
    ])].slice(0, 64)
    const termExIds = strIds(termHopObj?.exchangeIds)
    const terminalExchangeId = (typeof ti?.terminalExchangeId === 'string' && ti.terminalExchangeId.trim())
      ? ti.terminalExchangeId.trim()
      : (termExIds[termExIds.length - 1] ?? null)
    const rejectedBy = verdict.confirmed
      ? null
      : (verdict.rejectedBy ?? (verdict.failedStage ? `composite_${verdict.failedStage}` : 'composite_receipt'))
    const missingEvidence = verdict.confirmed
      ? []
      : (verdict.missingEvidence?.length ? [...verdict.missingEvidence] : [rejectedBy ?? 'composite_receipt'])
    const recorded = this.transcript.recordCompositeVerification({
      chainId: verdict.chainId,
      terminalVulnClass: verdict.terminalVulnClass,
      replayMode: verdict.replayMode,
      hopCount: verdict.hopCount,
      confirmed: verdict.confirmed,
      verifiedEdgeCount: verdict.verifiedEdges.filter(e => e.verified).length,
      reason: verdict.reason,
      ...(verdict.failedStage ? { failedStage: verdict.failedStage } : {}),
      rejectedBy,
      missingEvidence,
      exchangeIds,
      terminalExchangeId,
      route,
    })
    const cweText = `${String(rawObj?.cwe ?? '')} ${String(ti?.cwe ?? '')} ${String(rawObj?.terminalVulnClass ?? '')} ${String(ti?.summary ?? ti?.claimedImpact ?? '')}`
    const cwe = /\bCWE-\d{1,4}\b/i.exec(cweText)?.[0]?.toUpperCase()
    const claim: Extract<VerifyClaim, { kind: 'composite_receipt' }> = {
      kind: 'composite_receipt',
      verificationId: recorded.verificationId,
      chainId: verdict.chainId || (typeof rawObj?.chainId === 'string' ? rawObj.chainId : 'invalid'),
      terminalVulnClass: verdict.terminalVulnClass || (typeof rawObj?.terminalVulnClass === 'string' ? rawObj.terminalVulnClass : 'unknown'),
      ...(cwe ? { cwe } : {}),
      ...(route ? { route } : {}),
      exchangeIds,
      ...(terminalExchangeId ? { terminalExchangeId } : {}),
      ...(verdict.replayMode ? { replayMode: verdict.replayMode } : {}),
      hopCount: typeof verdict.hopCount === 'number' ? verdict.hopCount : hops.length,
      ...(rawObj ? { compositeReceipt: rawObj } : {}),
      ...(!verdict.confirmed ? { rejectedBy, missingEvidence, reason: verdict.reason } : {}),
    }
    return this.scrubRecord({
      ...verdict,
      ...(route && !verdict.terminalEndpoint ? { terminalEndpoint: route } : {}),
      ok: verdict.confirmed,
      verified: verdict.confirmed,
      verificationId: recorded.verificationId,
      rejectedBy,
      missingEvidence,
      claim,
    })
  }

  private proveHost(): ProveHandlerHost {
    return {
      transcript: this.transcript,
      defaultOrigin: this.options.targetOrigins?.[0],
      canaryBroker: this.options.canary ?? (this.options.grant as Grant & { canaryBroker?: VerifyCanaryBroker }).canaryBroker,
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
