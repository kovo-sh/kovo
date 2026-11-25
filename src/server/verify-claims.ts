/**
 * Layer-3 verification transcript store, claim/evidence oracle, statistical
 * differential helpers, and causal fingerprinting (leaf module).
 *
 * Pure leaf of the `verify-*.ts` decomposition: imports no other `verify-*.ts`
 * module except the shared structural-diff helper `verify-support.ts`.
 */
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { structuralDiff, intersectStructuralDeltas } from './verify-support.ts'
import {
  assessBoundary,
  assessImpactEvidence,
  assessMarkupImpact,
  assessMfaBypass,
  assessStatusOnlyDivergence,
  flattenJson,
  isMutatingMethod,
  isReadMethod,
  matchInjectionFingerprint,
  normalizeRole,
  parseRoleLabel,
  assessReadDisclosure,
} from './oracle-invariants.ts'
import type { AmbientAuth, BoundaryClass, ImpactClass, ImpactStep, ActorIdentity } from './oracle-invariants.ts'
import { isJobOrHandleStub } from './v8-oracle-families.ts'
import { compileSafeClaimRegex, MAX_CLAIM_REGEX_HAYSTACK } from './safe-regex.ts'
export { compileSafeClaimRegex } from './safe-regex.ts'

// ---------------------------------------------------------------------------
// Constants shared with the container mount (worker-backend) and both SDKs.
// ---------------------------------------------------------------------------

export const VERIFY_RPC_CONTAINER_DIR = '/kovo-rpc'
export const VERIFY_RPC_SOCKET_NAME = 'verify.sock'
export const VERIFY_RPC_TOKEN_NAME = 'token'
export const VERIFY_RPC_CONTEXT_NAME = 'context.json'
export const VERIFY_RPC_SOCKET_ENV = 'KOVO_RPC_SOCKET'
export const VERIFY_RPC_TOKEN_ENV = 'KOVO_RPC_TOKEN_FILE'
export const VERIFY_RPC_CONTEXT_ENV = 'KOVO_RPC_CONTEXT_FILE'
export const VERIFY_NONCE_ENV = 'KOVO_VERIFY_NONCE'
export const VERIFY_RESULT_ENV = 'KOVO_PROOF_RESULT_FILE'
export const VERIFY_RPC_HEADER = 'x-kovo-rpc-token'
export const VERIFY_NONCE_HEADER = 'x-kovo-verify-nonce'
export const VERIFY_RESULT_MARKER = 'KOVO_PROOF_RESULT:'


const MAX_RECORDED_BODY_BYTES = 512 * 1024
const MAX_TRANSCRIPT_EXCHANGES = 512
const MAX_CLAIMS = 64

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

export type VerifyExchangeOp = 'http' | 'http2' | 'browser' | 'oob' | 'transcript' | 'race' | 'capability' | 'crypto' | 'async_poll'

export interface VerifyTranscriptRequest {
  origin: string
  method: string
  pathAndQuery: string
  /** Already redacted by Layer 1; never contains persona secrets. */
  headers: Record<string, string>
  bodyBytes: number
  bodySha256: string
  personaHandle?: string | null
  sessionRole?: string | null
  /** Host-resolved persona role label (e.g. "owner (acme)"); signed, never script-supplied. */
  actorRoleLabel?: string | null
  /** Host-stamped derived capability handle injected into this request. */
  consumedCapabilityId?: string | null
  /** Host-stamped source capability handle from which a cryptographic artifact in this request was derived. */
  derivedFromCapabilityId?: string | null
  nonce: string
}

export interface VerifyTranscriptResponse {
  status: number
  headers: Record<string, string>
  bodyBytes: number
  bodySha256: string
  mediaType: string
  redirectOrigins?: string[]
  finalPathAndQuery?: string
}

export interface VerifyTranscriptArtifact {
  kind: 'oob-mint' | 'browser' | 'timing' | 'capability' | 'crypto' | 'async_poll'
  token?: string
  url?: string
  dnsHost?: string
  hit?: boolean
  executedSentinels?: string[]
  domHtmlSha256?: string
  capabilityHandle?: string
  derivedFromCapabilityId?: string
  derivedCapabilityId?: string
  alg?: string
  artifactDigest?: string
  pollRecordId?: string
  converged?: boolean
  tTriggerMs?: number
  tObservedMs?: number
}

export interface VerifyTranscriptRecord {
  exchangeId: string
  seq: number
  op: VerifyExchangeOp
  startedAt: number
  durationMs: number
  request?: VerifyTranscriptRequest
  response?: VerifyTranscriptResponse
  artifact?: VerifyTranscriptArtifact
  error?: string
  errorCode?: 'denied' | 'failed' | 'approval_required'
  signature: string
}

export interface TranscriptSummary {
  exchangeId: string
  seq: number
  op: VerifyExchangeOp
  method: string | null
  pathAndQuery: string | null
  origin: string | null
  status: number | null
  durationMs: number
  error: string | null
  signature: string
  /** Session-group/proof role the oracle reads (`control`, `probe`, `setup`, `pending_oob`, ...). */
  role?: string
  personaHandle?: string | null
  /** OOB callbacks are the only artifact whose hit is known after the record is signed. */
  hit?: boolean
}

export interface TranscriptCompositeVerification {
  verificationId: string
  seq: number
  chainId: string
  terminalVulnClass: string
  replayMode: 'fresh_clean_replay' | 'one_shot_transcript'
  hopCount: number
  confirmed: boolean
  verifiedEdgeCount: number
  reason: string
  failedStage?: string
  rejectedBy: string | null
  missingEvidence: string[]
  exchangeIds: string[]
  terminalExchangeId?: string | null
  route?: string | null
  signature: string
}

export class TranscriptStore {
  private readonly secret: Buffer
  private readonly records = new Map<string, VerifyTranscriptRecord>()
  private readonly bodies = new Map<string, string>()
  private readonly compositeVerifications = new Map<string, TranscriptCompositeVerification>()
  private seq = 0

  constructor(secret?: Buffer) {
    this.secret = secret ?? randomBytes(32)
  }

  get size(): number {
    return this.records.size
  }

  private sign(record: Omit<VerifyTranscriptRecord, 'signature'>): string {
    return createHmac('sha256', this.secret)
      .update(JSON.stringify(record))
      .digest('hex')
  }

  private signComposite(record: Omit<TranscriptCompositeVerification, 'signature'>): string {
    return createHmac('sha256', this.secret)
      .update(`composite:${JSON.stringify(record)}`)
      .digest('hex')
  }

  recordCompositeVerification(
    input: Omit<TranscriptCompositeVerification, 'verificationId' | 'seq' | 'signature'>,
  ): TranscriptCompositeVerification {
    this.seq += 1
    const verificationId = `gc-${randomUUID()}`
    const unsigned: Omit<TranscriptCompositeVerification, 'signature'> = {
      verificationId,
      seq: this.seq,
      ...input,
    }
    const record: TranscriptCompositeVerification = { ...unsigned, signature: this.signComposite(unsigned) }
    this.compositeVerifications.set(verificationId, record)
    return record
  }

  getCompositeVerification(verificationId: string): TranscriptCompositeVerification | undefined {
    return this.compositeVerifications.get(verificationId)
  }

  latestCompositeVerification(): TranscriptCompositeVerification | undefined {
    let latest: TranscriptCompositeVerification | undefined
    for (const rec of this.compositeVerifications.values()) latest = rec
    return latest
  }

  record(input: {
    op: VerifyExchangeOp
    startedAt: number
    durationMs: number
    request?: VerifyTranscriptRequest
    response?: VerifyTranscriptResponse
    artifact?: VerifyTranscriptArtifact
    error?: string
    errorCode?: 'denied' | 'failed' | 'approval_required'
    body?: string
  }): VerifyTranscriptRecord {
    this.seq += 1
    const exchangeId = `gx-${randomUUID()}`
    const unsigned: Omit<VerifyTranscriptRecord, 'signature'> = {
      exchangeId,
      seq: this.seq,
      op: input.op,
      startedAt: input.startedAt,
      durationMs: Math.max(0, Math.round(input.durationMs)),
      ...(input.request ? { request: input.request } : {}),
      ...(input.response ? { response: input.response } : {}),
      ...(input.artifact ? { artifact: input.artifact } : {}),
      ...(input.error ? { error: input.error.slice(0, 1024) } : {}),
      ...(input.errorCode ? { errorCode: input.errorCode } : {}),
    }
    const record: VerifyTranscriptRecord = { ...unsigned, signature: this.sign(unsigned) }
    this.records.set(exchangeId, record)
    if (typeof input.body === 'string' && input.body.length > 0) {
      this.bodies.set(exchangeId, input.body.slice(0, MAX_RECORDED_BODY_BYTES))
    }
    // Bounded memory: oldest metadata is kept (it is tiny) but old bodies are evicted first.
    if (this.records.size > MAX_TRANSCRIPT_EXCHANGES) {
      const oldest = this.records.keys().next().value
      if (oldest !== undefined) {
        this.records.delete(oldest)
        this.bodies.delete(oldest)
      }
    }
    return record
  }

  get(exchangeId: string): VerifyTranscriptRecord | undefined {
    return this.records.get(exchangeId)
  }

  body(exchangeId: string): string | undefined {
    return this.bodies.get(exchangeId)
  }

  /** Retroactively scrub all stored bodies (e.g. after sealing a newly discovered derived secret). */
  rescrubBodies(scrubber: (body: string) => string): void {
    for (const [id, text] of this.bodies.entries()) {
      const scrubbed = scrubber(text)
      if (scrubbed !== text) this.bodies.set(id, scrubbed)
    }
  }

  list(): VerifyTranscriptRecord[] {
    return [...this.records.values()]
  }

  summaries(): TranscriptSummary[] {
    return this.list().map(record => {
      const method = record.request?.method ?? null
      const role = record.request?.sessionRole
        ?? (record.op === 'oob'
          ? (method === 'MINT' ? 'oob_mint' : method === 'SUBSCRIBE' ? 'pending_oob' : method === 'WAIT' ? 'oob_wait' : 'oob_check')
          : record.op === 'browser' ? 'browser' : record.op === 'race' ? 'race' : 'setup')
      return {
        exchangeId: record.exchangeId,
        seq: record.seq,
        op: record.op,
        method,
        pathAndQuery: record.request?.pathAndQuery ?? null,
        origin: record.request?.origin ?? null,
        status: recordStatus(record),
        durationMs: record.durationMs,
        error: record.error ?? null,
        signature: record.signature,
        role,
        personaHandle: record.request?.personaHandle ?? null,
        ...(record.artifact?.hit !== undefined ? { hit: record.artifact.hit } : {}),
      }
    })
  }

  /** HMAC over every signed record; stable for a fixed transcript, changes on tamper/append. */
  digest(): string {
    const h = createHmac('sha256', this.secret)
    for (const record of this.list()) {
      h.update(record.signature)
      h.update('\0')
    }
    for (const comp of this.compositeVerifications.values()) {
      h.update(comp.signature)
      h.update('\0')
    }
    return h.digest('hex')
  }

  /** Recompute every signature; any mismatch means the transcript was mutated. */
  verifySignatures(): boolean {
    for (const record of this.records.values()) {
      const { signature, ...unsigned } = record
      const expected = this.sign(unsigned)
      if (signature.length !== expected.length) return false
      if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false
    }
    for (const comp of this.compositeVerifications.values()) {
      const { signature, ...unsigned } = comp
      const expected = this.signComposite(unsigned)
      if (signature.length !== expected.length) return false
      if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false
    }
    return true
  }
}

// ---------------------------------------------------------------------------
// Claims + transcript oracle
// ---------------------------------------------------------------------------

export type VerifyClaim =
  | { kind: 'status'; exchangeId: string; expected: number | number[]; message?: string }
  | { kind: 'header'; exchangeId: string; name: string; equals?: string; matches?: string; absent?: boolean; message?: string }
  | {
      kind: 'body_contains'
      exchangeId: string
      text: string
      absent?: boolean
      vulnClass?: string
      controlRequestBody?: unknown
      probeRequestBody?: unknown
      message?: string
    }
  | { kind: 'jsonpath'; exchangeId: string; path: string; equals?: unknown; matches?: string; exists?: boolean; message?: string }
  | { kind: 'css'; exchangeId: string; selector: string; exists?: boolean; count?: number; textEquals?: string; textContains?: string; message?: string }
  | { kind: 'dom_sentinel'; exchangeId: string; sentinel: string; mode?: 'source' | 'executed'; message?: string }
  | { kind: 'oob'; exchangeId: string; expectHit?: boolean; message?: string }
  | { kind: 'timing'; controlIds: string[]; variantIds: string[]; minPairs?: number; maxPValue?: number; message?: string }
  /**
   * Boolean/content differential: two interleaved arms whose noise-normalized bodies are stable
   * within each arm and differ between arms by a stable token set. Per-request nonces, UUIDs,
   * timestamps and opaque ids are stripped first, so a rotating token cannot fake a differential.
   */
  | {
      kind: 'structural_diff'
      controlIds: string[]
      variantIds: string[]
      minRounds?: number
      minDeltaTokens?: number
      /** Minimum token-set similarity the two arms may share (0 disables the ceiling). */
      maxSimilarity?: number
      message?: string
    }
  /**
   * Race/TOCTOU burst evidence: a synchronized burst of the same operation produced divergent
   * outcomes. `mode` records whether the broker released the burst on its HTTP/2 single-packet
   * barrier or fell back to HTTP/1.1.
   */
  | {
      kind: 'race'
      exchangeIds: string[]
      burstExchangeIds?: string[]
      baselineExchangeId?: string
      postExchangeId?: string
      serialExchangeIds?: string[]
      serialPreExchangeId?: string
      serialPostExchangeId?: string
      balanceField?: string
      capField?: string
      unitDebit?: number
      vulnClass?: string
      requestBody?: unknown
      mode?: 'h2-single-packet' | 'http1-fallback'
      minDistinctOutcomes?: number
      expectAllSuccess?: boolean
      message?: string
    }
  /**
   * Impact-evidence claim: binds an impact class to the exchanges that prove it. Evaluated by the
   * same pure validators as the declarative replay path (`oracle-invariants.ts`), so a status-only
   * script cannot confirm an assertion the replay verifier would dismiss.
   */
  | {
      kind: 'impact'
      impactClass: ImpactClass
      vulnClass?: string
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
      ambient?: { kind: AmbientAuth; sameSite?: string }
      message?: string
    }
  /**
   * Universal default-deny boundary evidence: a denied/challenged control plus a variant that crosses
   * the same route family. Auth claims confirm only through this claim; access claims may instead
   * rely on a passing `impact`/disclosure differential.
   */
  | {
      kind: 'boundary'
      boundaryClass: BoundaryClass
      vulnClass?: string
      controlExchangeId: string
      probeExchangeId: string
      expectControlDenied?: boolean
      controlRequestBody?: unknown
      probeRequestBody?: unknown
      actorRoles?: Record<string, string>
      actorTenants?: Record<string, string>
      message?: string
    }
  /**
   * MFA/2FA gate evidence: an enrolled control read, a protected read denied/challenged before the
   * code check, and the same actor's granted read of the same resource after it.
   */
  | {
      kind: 'mfa'
      enrolledExchangeId: string
      preChallengeExchangeId: string
      postChallengeExchangeId: string
      challengeExchangeId?: string
      actorRoles?: Record<string, string>
      actorTenants?: Record<string, string>
      message?: string
    }
  /**
   * Host-verified multi-hop CompositeProofReceipt claim emitted by `ctx.proveComposite()` /
   * `ctx.prove_composite()`. Verified strictly against the host-signed TranscriptStore record.
   */
  | {
      kind: 'composite_receipt'
      verificationId?: string
      chainId: string
      terminalVulnClass: string
      cwe?: string
      route?: string
      exchangeIds: string[]
      terminalExchangeId?: string
      replayMode?: 'fresh_clean_replay' | 'one_shot_transcript'
      hopCount?: number
      compositeReceipt?: Record<string, unknown>
      rejectedBy?: string | null
      missingEvidence?: string[]
      reason?: string
      message?: string
    }

export interface VerifyScriptResult {
  sdk?: string
  nonce?: string
  title?: string
  severity?: string
  description?: string
  claims: VerifyClaim[]
}

export interface VerifyClaimCheck {
  claim: VerifyClaim
  passed: boolean
  detail: string
  observed?: Record<string, unknown>
}

export interface VerifyOracleResult {
  passed: boolean
  checks: VerifyClaimCheck[]
  failures: string[]
  transcriptDigest: string
  /** First validator/claim that rejected the proof (null when it passed). */
  rejectedBy?: string | null
  /** Exact transcript roles/preconditions a repair must add, e.g. `control_denied`. */
  missingEvidence?: string[]
  /** Compact role-labelled transcript so a repair can be made in one turn. */
  transcriptSummary?: TranscriptSummary[]
  /** Primary probe endpoint pathAndQuery derived from the cited exchanges, when available. */
  endpoint?: string | null
}

export interface VerifyClaimContext {
  /** Live canary broker; when absent the transcript's recorded hit flag is authoritative. */
  canary?: VerifyCanaryBroker
  /** Exchange ids recorded by a different attempt must never satisfy this attempt's claims. */
  allowedExchangeIds?: ReadonlySet<string>
  /**
   * Impact class declared by the proof title/description. Mutation-based classes (BFLA, mass
   * assignment, CSRF) confirm only with a passing `impact` claim; a read-based authorization claim
   * needs an owner-scoped disclosure in the probe exchange.
   */
  claimedImpact?: ImpactClass
  /** Boundary class declared by the proof title/description; auth claims need a `boundary` claim. */
  claimedBoundary?: BoundaryClass
}

export interface VerifyCanaryCheck {
  found: boolean
  hit: boolean
  triggered: boolean
  hits: Array<{ protocol: string; token: string; remoteIp?: string; timestamp?: number }>
  detail?: Record<string, unknown> | null
}

/** Structural subset of the durable OOB relay surface (CanaryBroker satisfies it). */
export interface VerifyOobSubscriptionView {
  id: string
  token?: string
  status?: string
  createdAt?: number
  expiresAt?: number
  windowMs?: number
  immediateMs?: number
}

export interface VerifyOobAwaitView {
  matched: boolean
  callback: { receivedAt?: number; token?: string; detail?: Record<string, unknown> | null } | null
}

export interface VerifyOobPromotionView {
  subscription: { id: string; token?: string }
  callback: { receivedAt?: number; token?: string; detail?: Record<string, unknown> | null }
}

export interface VerifyCanaryBroker {
  mintCanary(runId: string, label: string, origin?: string, options?: { assignmentId?: string }): {
    token: string
    httpUrl: string
    url: string
    dnsHost: string
    label?: string
  }
  checkCanary(token: string, options?: { runId?: string }): VerifyCanaryCheck
  /**
   * Durable OOB correlation. When present, `prove_oob_callback` registers a `pending_oob`
   * subscription *before* injecting, then waits/promotes so a late callback is not lost.
   */
  subscribe?(input: {
    runId: string
    assignmentId: string
    canaryId: string
    token: string
    artifact?: string
    immediateMs?: number
    windowMs?: number
  }): VerifyOobSubscriptionView
  awaitAny?(
    query: { token?: string; canaryId?: string; runId?: string; assignmentId?: string },
    options?: { timeoutMs?: number; pollMs?: number },
  ): Promise<VerifyOobAwaitView>
  promoteLate?(options?: { runId?: string; now?: number }): VerifyOobPromotionView[]
}

// ---------------------------------------------------------------------------
// Assertion primitives (shared semantics with `worker/kovo_verify`).
// ---------------------------------------------------------------------------

const GX_ID_RE = /\bgx-[0-9a-f-]{8,}\b/gi
const REDACTED_TOKEN_RE = /\[redacted(?::[^\]]+)?\]/gi
const CAP_HANDLE_RE = /\bcap:[A-Za-z0-9_.:-]+\b/g
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi
const LONG_HEX_RE = /\b[0-9a-f]{16,}\b/gi
const ISO_TS_RE = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?/g
const COMPOUND_ID_RE = /(?<![a-z0-9])(?!(?:cwe|cve|rfc|iso|sha|aes|rsa|hmac|http|https|utf|tls|jwt)[-_])[a-z]{2,12}[_-](?:\d+[a-z0-9]*[_-][a-z0-9]{2,}|[a-z0-9]*\d[a-z0-9]*[_-](?=[a-z0-9]*\d)[a-z0-9]{2,})(?![a-z0-9])/gi
const PREFIXED_ID_RE = /(?<![a-z0-9])(?!(?:cwe|cve|rfc|iso|sha|aes|rsa|hmac|http|https|utf|tls|jwt)[-_])[a-z]{2,12}[_-](?=[a-z0-9]*\d)[a-z0-9]{3,}(?![a-z0-9])/gi

/** Remove run-scoped nonces and standard dynamic tokens (for cross-attempt comparison). */
export function normalizeDynamic(input: string, nonce?: string): string {
  let out = input
  if (nonce) out = out.split(nonce).join('<nonce>')
  return out
    .replace(GX_ID_RE, '<gx>')
    .replace(REDACTED_TOKEN_RE, '<redacted>')
    .replace(CAP_HANDLE_RE, '<cap>')
    .replace(UUID_RE, '<uuid>')
    .replace(ISO_TS_RE, '<ts>')
    .replace(LONG_HEX_RE, '<hex>')
    .replace(COMPOUND_ID_RE, '<id>')
    .replace(PREFIXED_ID_RE, '<id>')
}

export function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null
}

function isClaim(value: unknown): value is VerifyClaim {
  const rec = asRecord(value)
  if (!rec) return false
  switch (rec.kind) {
    case 'status':
      return typeof rec.exchangeId === 'string' &&
        (typeof rec.expected === 'number' || (Array.isArray(rec.expected) && rec.expected.every(n => typeof n === 'number')))
    case 'header':
      return typeof rec.exchangeId === 'string' && typeof rec.name === 'string'
    case 'body_contains':
      return typeof rec.exchangeId === 'string' && typeof rec.text === 'string'
    case 'jsonpath':
      return typeof rec.exchangeId === 'string' && typeof rec.path === 'string'
    case 'css':
      return typeof rec.exchangeId === 'string' && typeof rec.selector === 'string'
    case 'dom_sentinel':
      return typeof rec.exchangeId === 'string' && typeof rec.sentinel === 'string'
    case 'oob':
      return typeof rec.exchangeId === 'string'
    case 'timing':
      return Array.isArray(rec.controlIds) && Array.isArray(rec.variantIds) &&
        rec.controlIds.every(v => typeof v === 'string') && rec.variantIds.every(v => typeof v === 'string')
    case 'structural_diff':
      return Array.isArray(rec.controlIds) && Array.isArray(rec.variantIds) &&
        rec.controlIds.every(v => typeof v === 'string') && rec.variantIds.every(v => typeof v === 'string')
    case 'race':
      return Array.isArray(rec.exchangeIds) && rec.exchangeIds.length >= 2 &&
        rec.exchangeIds.every(v => typeof v === 'string')
    case 'impact': {
      const knownClasses = new Set(['authorization', 'bfla', 'mass_assignment', 'csrf', 'business_logic', 'markup', 'disclosure', 'injection'])
      return typeof rec.probeExchangeId === 'string' &&
        typeof rec.impactClass === 'string' && knownClasses.has(rec.impactClass) &&
        (rec.controlExchangeIds === undefined || (Array.isArray(rec.controlExchangeIds) && rec.controlExchangeIds.every(v => typeof v === 'string'))) &&
        (rec.oracleEvents === undefined || (Array.isArray(rec.oracleEvents) && rec.oracleEvents.every(v => typeof v === 'string')))
    }
    case 'boundary': {
      const knownClasses = new Set(['auth', 'access'])
      return typeof rec.controlExchangeId === 'string' &&
        typeof rec.probeExchangeId === 'string' &&
        typeof rec.boundaryClass === 'string' && knownClasses.has(rec.boundaryClass)
    }
    case 'mfa':
      return typeof rec.enrolledExchangeId === 'string' &&
        typeof rec.preChallengeExchangeId === 'string' &&
        typeof rec.postChallengeExchangeId === 'string'
    case 'composite_receipt':
      return typeof rec.chainId === 'string' &&
        typeof rec.terminalVulnClass === 'string' &&
        Array.isArray(rec.exchangeIds) &&
        rec.exchangeIds.every(v => typeof v === 'string')

    default:
      return false
  }
}

export function parseVerifyScriptResult(value: unknown): VerifyScriptResult {
  const rec = asRecord(value)
  if (!rec) throw new Error('Verification script result must be a JSON object.')
  if (!Array.isArray(rec.claims)) throw new Error('Verification script result is missing a claims array.')
  if (rec.claims.length === 0) throw new Error('Verification script returned no claims; stdout alone can never confirm a finding.')
  if (rec.claims.length > MAX_CLAIMS) throw new Error(`Verification script returned more than ${MAX_CLAIMS} claims.`)
  const claims = rec.claims.filter(isClaim)
  if (claims.length !== rec.claims.length) throw new Error('Verification script returned an unsupported claim shape.')
  return {
    ...(typeof rec.sdk === 'string' ? { sdk: rec.sdk } : {}),
    ...(typeof rec.nonce === 'string' ? { nonce: rec.nonce } : {}),
    ...(typeof rec.title === 'string' ? { title: rec.title.slice(0, 300) } : {}),
    ...(typeof rec.severity === 'string' ? { severity: rec.severity.slice(0, 32) } : {}),
    ...(typeof rec.description === 'string' ? { description: rec.description.slice(0, 4000) } : {}),
    claims,
  }
}

function parseJsonPath(path: string): Array<string | number> {
  const trimmed = path.trim().replace(/^\$\.?/, '')
  if (!trimmed) return []
  const parts: Array<string | number> = []
  for (const raw of trimmed.split('.')) {
    if (!raw) continue
    let rest = raw
    const bracket = rest.indexOf('[')
    const head = bracket === -1 ? rest : rest.slice(0, bracket)
    if (head) parts.push(head)
    if (bracket !== -1) {
      rest = rest.slice(bracket)
      const re = /\[(\d+|\*)\]/g
      let match: RegExpExecArray | null
      while ((match = re.exec(rest))) {
        parts.push(match[1] === '*' ? '*' : Number(match[1]))
      }
    }
  }
  return parts
}

export function evaluateJsonPath(value: unknown, path: string): { found: boolean; value?: unknown; count?: number } {
  let current: unknown = value
  const parts = parseJsonPath(path)
  for (const part of parts) {
    if (part === '*') {
      if (Array.isArray(current)) return { found: current.length > 0, value: current, count: current.length }
      if (current && typeof current === 'object') {
        const values = Object.values(current as Record<string, unknown>)
        return { found: values.length > 0, value: values, count: values.length }
      }
      return { found: false }
    }
    if (typeof part === 'number') {
      if (!Array.isArray(current) || current.length <= part) return { found: false }
      current = current[part]
      continue
    }
    if (!current || typeof current !== 'object') return { found: false }
    current = (current as Record<string, unknown>)[part]
    if (current === undefined) return { found: false }
  }
  return { found: true, value: current }
}

interface ParsedElement {
  tag: string
  attrs: Record<string, string>
  id?: string
  classes: string[]
  text: string
}

/** Very small HTML element scanner; adequate for CSS-selector-lite assertions. */
function scanElements(html: string): ParsedElement[] {
  const out: ParsedElement[] = []
  const tagRe = /<([a-zA-Z][a-zA-Z0-9-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g
  let match: RegExpExecArray | null
  while ((match = tagRe.exec(html))) {
    const tag = match[1].toLowerCase()
    const rawAttrs = match[2]
    const attrs: Record<string, string> = {}
    const attrRe = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/g
    let attr: RegExpExecArray | null
    while ((attr = attrRe.exec(rawAttrs))) {
      attrs[attr[1].toLowerCase()] = attr[3] ?? attr[4] ?? attr[5] ?? ''
    }
    const close = html.indexOf(`</${tag}>`, tagRe.lastIndex)
    const innerText = close === -1 ? '' : html.slice(tagRe.lastIndex, close).replace(/<[^>]*>/g, '')
    out.push({
      tag,
      attrs,
      ...(attrs.id ? { id: attrs.id } : {}),
      classes: (attrs.class ?? '').split(/\s+/).filter(Boolean),
      text: decodeEntities(innerText).replace(/\s+/g, ' ').trim(),
    })
  }
  return out
}

function decodeEntities(text: string): string {
  return text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
}

type SimpleSelector = { tag?: string; id?: string; classes: string[]; attrs: Array<{ name: string; value?: string }> }

function parseSelector(selector: string): SimpleSelector | null {
  const s = selector.trim()
  if (!s || /\s[>+~]\s/.test(s)) return null
  const simple = /^([a-zA-Z][a-zA-Z0-9-]*)?((?:[#.][A-Za-z0-9_-]+)*)((?:\[[^\]]+\])*)$/.exec(s)
  if (!simple) return null
  const classes: string[] = []
  let id: string | undefined
  const tokenRe = /([#.])([A-Za-z0-9_-]+)/g
  let token: RegExpExecArray | null
  while ((token = tokenRe.exec(simple[2] ?? ''))) {
    if (token[1] === '#') id = token[2]
    else classes.push(token[2])
  }
  const attrs: Array<{ name: string; value?: string }> = []
  const attrRe = /\[([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:=(?:"([^"]*)"|'([^']*)'|([^\]]+)))?\]/g
  let attr: RegExpExecArray | null
  while ((attr = attrRe.exec(simple[3] ?? ''))) {
    attrs.push({ name: attr[1].toLowerCase(), ...(attr[2] ?? attr[3] ?? attr[4] ? { value: attr[2] ?? attr[3] ?? attr[4] } : {}) })
  }
  return {
    ...(simple[1] ? { tag: simple[1].toLowerCase() } : {}),
    ...(id ? { id } : {}),
    classes,
    attrs,
  }
}

function matchesSelector(element: ParsedElement, selector: SimpleSelector): boolean {
  if (selector.tag && element.tag !== selector.tag) return false
  if (selector.id && element.id !== selector.id) return false
  for (const cls of selector.classes) {
    if (!element.classes.includes(cls)) return false
  }
  for (const attr of selector.attrs) {
    const value = element.attrs[attr.name]
    if (value === undefined) return false
    if (attr.value !== undefined && value !== attr.value) return false
  }
  return true
}

function median(values: number[]): number {
  if (values.length === 0) return 0
  const sorted = [...values].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid]
}

function mad(values: number[]): number {
  if (values.length === 0) return 0
  const m = median(values)
  return median(values.map(v => Math.abs(v - m)))
}

function erf(x: number): number {
  const sign = x < 0 ? -1 : 1
  const ax = Math.abs(x)
  const a1 = 0.254829592
  const a2 = -0.284496736
  const a3 = 1.421413741
  const a4 = -1.453152027
  const a5 = 1.061405429
  const p = 0.3275911
  const t = 1 / (1 + p * ax)
  const y = 1 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-ax * ax)
  return sign * y
}

function normalCdf(z: number): number {
  return 0.5 * (1 + erf(z / Math.SQRT2))
}

export interface MannWhitneyResult {
  u: number
  pValue: number
  n1: number
  n2: number
  medianControl: number
  medianVariant: number
  madControl: number
  madVariant: number
  separation: number
}

/** Mann-Whitney U with tie-corrected normal approximation plus median/MAD separation. */
export function mannWhitneyU(control: number[], variant: number[]): MannWhitneyResult {
  const n1 = control.length
  const n2 = variant.length
  const tagged = [
    ...control.map(v => ({ v, g: 0 })),
    ...variant.map(v => ({ v, g: 1 })),
  ].sort((a, b) => a.v - b.v)
  const ranks = new Array<number>(tagged.length)
  const tieSizes: number[] = []
  let i = 0
  while (i < tagged.length) {
    let j = i
    while (j + 1 < tagged.length && tagged[j + 1].v === tagged[i].v) j += 1
    const rank = (i + j + 2) / 2
    for (let k = i; k <= j; k += 1) ranks[k] = rank
    if (j > i) tieSizes.push(j - i + 1)
    i = j + 1
  }
  let r1 = 0
  for (let k = 0; k < tagged.length; k += 1) if (tagged[k].g === 0) r1 += ranks[k]
  const u1 = r1 - (n1 * (n1 + 1)) / 2
  const u = Math.min(u1, n1 * n2 - u1)
  const mu = (n1 * n2) / 2
  const total = n1 + n2
  const tieTerm = tieSizes.reduce((sum, size) => sum + (size ** 3 - size), 0)
  const sigmaSq = (n1 * n2 / 12) * ((total + 1) - (total > 1 ? tieTerm / (total * (total - 1)) : 0))
  const sigma = Math.sqrt(Math.max(sigmaSq, 1e-9))
  const z = (u - mu + 0.5) / sigma
  const pValue = Math.max(0, Math.min(1, 2 * (1 - normalCdf(Math.abs(z)))))
  const medianControl = median(control)
  const medianVariant = median(variant)
  const madControl = mad(control)
  const madVariant = mad(variant)
  const denom = Math.max(((madControl + madVariant) / 2) * 1.4826, 1)
  return {
    u,
    pValue,
    n1,
    n2,
    medianControl,
    medianVariant,
    madControl,
    madVariant,
    separation: (medianVariant - medianControl) / denom,
  }
}

function observedHeader(record: VerifyTranscriptRecord, name: string): string | undefined {
  const wanted = name.toLowerCase()
  for (const [key, value] of Object.entries(record.response?.headers ?? {})) {
    if (key.toLowerCase() === wanted) return value
  }
  return undefined
}

export function sameSiteFromRecord(record: VerifyTranscriptRecord | undefined): string | null {
  if (!record) return null
  const raw = observedHeader(record, 'set-cookie')
  if (!raw) return null
  const match = /samesite\s*=\s*([a-z]+)/i.exec(raw)
  return match ? match[1] ?? null : null
}

/** Normalize a recorded exchange into the shared impact-evidence shape. */
function transcriptImpactStep(
  store: TranscriptStore,
  claim: Extract<VerifyClaim, { kind: 'impact' }>,
  id: string,
  arm: ImpactStep['arm'],
  defaultSameSite: string | null,
): ImpactStep | null {
  const record = store.get(id)
  if (!record) return null
  const body = store.body(id)
  const json = parseJsonBody(body)
  const handle = record.request?.personaHandle ?? null
  // Host-signed persona label wins; a script cannot manufacture a role or tenant differential.
  const signedLabel = record.request?.actorRoleLabel ?? null
  const role = signedLabel !== null
    ? normalizeRole(signedLabel) ?? normalizeRole(handle) ?? null
    : normalizeRole(handle) ?? normalizeRole(claim.actorRoles?.[handle ?? '']) ?? null
  const tenant = signedLabel !== null
    ? parseRoleLabel(signedLabel).tenant ?? parseRoleLabel(handle).tenant ?? null
    : parseRoleLabel(handle).tenant ?? claim.actorTenants?.[handle ?? ''] ?? null
  const actor: ActorIdentity = {
    handle,
    role,
    tenant,
    auth: (claim.ambient?.kind ?? 'unknown') as AmbientAuth,
    sameSite: claim.ambient?.sameSite ?? defaultSameSite,
  }
  return {
    id,
    arm,
    method: (record.request?.method ?? 'GET').toUpperCase(),
    route: (record.request?.pathAndQuery ?? '/').split('?')[0].replace(/\/+$/, '').toLowerCase() || '/',
    pathAndQuery: record.request?.pathAndQuery ?? '/',
    status: recordStatus(record),
    actor,
    json,
    body: body ?? '',
    requestJson: claim.requestBody,
    requestHeaders: record.request?.headers ?? null,
    responseHeaders: record.response?.headers ?? null,
    ...(record.seq !== undefined ? { seq: record.seq } : {}),
  } as ImpactStep & { seq: number }
}

function transcriptBoundaryStep(
  store: TranscriptStore,
  claim: Extract<VerifyClaim, { kind: 'boundary' | 'impact' | 'mfa' }>,
  id: string,
  arm: ImpactStep['arm'],
): ImpactStep | null {
  const record = store.get(id)
  if (!record) return null
  const body = store.body(id)
  const json = parseJsonBody(body)
  const handle = record.request?.personaHandle ?? null
  const roles = 'actorRoles' in claim ? claim.actorRoles : undefined
  const tenants = 'actorTenants' in claim ? claim.actorTenants : undefined
  // Host-signed persona label wins; a handle alone is not a tenant ("alice" is not a tenant).
  const signedLabel = record.request?.actorRoleLabel ?? null
  const role = signedLabel !== null
    ? normalizeRole(signedLabel) ?? normalizeRole(handle) ?? null
    : normalizeRole(handle) ?? normalizeRole(roles?.[handle ?? '']) ?? null
  const tenant = signedLabel !== null
    ? parseRoleLabel(signedLabel).tenant ?? tenants?.[handle ?? ''] ?? null
    : tenants?.[handle ?? ''] ?? parseRoleLabel(handle).tenant ?? null
  return {
    id,
    arm,
    method: (record.request?.method ?? 'GET').toUpperCase(),
    route: (record.request?.pathAndQuery ?? '/').split('?')[0].replace(/\/+$/, '').toLowerCase() || '/',
    pathAndQuery: record.request?.pathAndQuery ?? '/',
    status: recordStatus(record),
    actor: { handle, role, tenant, auth: 'unknown', sameSite: null },
    json,
    body: body ?? '',
    requestHeaders: record.request?.headers ?? null,
    responseHeaders: record.response?.headers ?? null,
  }
}

const LIFECYCLE_STATE_KEY_RE = /^(?:status|state|workflow[_-]?status|workflow[_-]?state|approval[_-]?status|approval[_-]?state|lifecycle[_-]?state|lifecycle[_-]?status|stage|phase)$/i
const INTERMEDIATE_STATE_VAL_RE = /^(?:draft|queued|pending(?:[_-](?:approval|review|verification|settlement|execution|processing))?|awaiting[_-](?:approval|review|verification|settlement|confirmation)|unapproved|unverified|scheduled|enqueued|staged|initiated|requested|submitted|processing|in[_-]progress|accepted|primed)$/i
const FINALIZED_STATE_VAL_RE = /^(?:approved|settled|paid|disbursed|released|completed|fulfilled|captured|executed|published|active|confirmed|verified|granted|promoted|revoked|deleted|voided|refunded)$/i
const UNAPPROVED_BOOL_KEY_RE = /^(?:requires[_-]?approval|needs[_-]?approval|pending[_-]?approval|is[_-]?draft)$/i
const TERMINAL_BOOL_KEY_RE = /^(?:approved|settled|disbursed|verified|finalized|published|executed)$/i
const COLLECTION_COUNT_KEY_RE = /^(?:count|total_?count|length|size|updated_?at|version)$/i
export const STANDALONE_TERMINAL_IMPACT_HINT =
  'terminal_impact_unproven: creating or fetching an intermediate draft/queued/pending object or handle stub is NOT terminal security impact — prove unauthorized cross-tenant data exposure, privileged state settlement/approval, economic conservation violation, or chain the intermediate capability via ctx.seal_capability + ctx.prove_composite.'

const parseJsonBody = (body: string | undefined): unknown => { if (!body?.trim()) return undefined; try { return JSON.parse(body) } catch { return undefined } }
const recordStatus = (r: VerifyTranscriptRecord | undefined): number | null => (r?.response?.status != null && Number.isFinite(Number(r.response.status)) ? Number(r.response.status) : null)
const stubRejection = (claim: VerifyClaim, state: string | null, base: Record<string, unknown> = {}): VerifyClaimCheck =>
  ({ claim, passed: false, detail: STANDALONE_TERMINAL_IMPACT_HINT, observed: { ...base, intermediateStub: true, stubState: state, rejectedBy: 'terminal_impact_unproven' } })

function intermediateLifecycleState(json: unknown, status?: number | null, beforeFlat?: Map<string, string>): { state: string | null; existingMutated: boolean } {
  if (!json || typeof json !== 'object') return { state: null, existingMutated: false }
  let state: string | null = null, existingMutated = false
  for (const [path, rawVal] of flattenJson(json)) {
    const existed = Boolean(beforeFlat?.has(path))
    if (existed && beforeFlat!.get(path) === rawVal) continue
    const leaf = (path.replace(/\[\d+\]/g, '').split('.').pop() ?? '').toLowerCase(), val = rawVal.trim()
    if (LIFECYCLE_STATE_KEY_RE.test(leaf)) {
      if (FINALIZED_STATE_VAL_RE.test(val)) return { state: null, existingMutated }
      if (!state && INTERMEDIATE_STATE_VAL_RE.test(val)) state = val.toLowerCase()
    } else if (!state && UNAPPROVED_BOOL_KEY_RE.test(leaf) && val.toLowerCase() === 'true') state = 'unapproved'
    else if (!state && (status === 201 || status === 202) && TERMINAL_BOOL_KEY_RE.test(leaf) && val.toLowerCase() === 'false') state = 'unapproved'
    else if (existed && !COLLECTION_COUNT_KEY_RE.test(leaf)) existingMutated = true
  }
  return { state, existingMutated }
}

export function detectIntermediateStub(record: VerifyTranscriptRecord | undefined, body: string | undefined): { isStub: boolean; pureJobStub: boolean; state: string | null } {
  const status = recordStatus(record)
  if (!record || status === null || status < 200 || status >= 300) return { isStub: false, pureJobStub: false, state: null }
  const json = parseJsonBody(body), method = (record.request?.method ?? 'GET').toUpperCase()
  if (isJobOrHandleStub(json, body, status, method, record.request?.pathAndQuery ?? '')) {
    return { isStub: true, pureJobStub: true, state: intermediateLifecycleState(json, status).state ?? 'handle_stub' }
  }
  if (method === 'POST' || method === 'PUT') {
    const { state } = intermediateLifecycleState(json, status)
    if (state) return { isStub: true, pureJobStub: false, state }
  }
  return { isStub: false, pureJobStub: false, state: null }
}

function afterReadbackIsIntermediateOnly(beforeBody: string | undefined, afterRec: VerifyTranscriptRecord | undefined, afterBody: string | undefined): { isStub: boolean; pureJobStub: boolean; state: string | null } {
  const status = recordStatus(afterRec)
  if (!afterRec || status === null || status < 200 || status >= 300) return { isStub: false, pureJobStub: false, state: null }
  const afterJson = parseJsonBody(afterBody)
  if (isJobOrHandleStub(afterJson, afterBody, status, afterRec.request?.method, afterRec.request?.pathAndQuery)) {
    return { isStub: true, pureJobStub: true, state: intermediateLifecycleState(afterJson, status).state ?? 'handle_stub' }
  }
  const beforeJson = parseJsonBody(beforeBody)
  const beforeFlat = beforeJson && typeof beforeJson === 'object' ? flattenJson(beforeJson) : new Map<string, string>()
  const { state, existingMutated } = intermediateLifecycleState(afterJson, status, beforeFlat)
  return state && !existingMutated ? { isStub: true, pureJobStub: false, state } : { isStub: false, pureJobStub: false, state: null }
}

function evaluateBoundaryClaim(store: TranscriptStore, claim: Extract<VerifyClaim, { kind: 'boundary' }>, context: VerifyClaimContext): VerifyClaimCheck {
  const okId = (id: string) => (!context.allowedExchangeIds || context.allowedExchangeIds.has(id)) && Boolean(store.get(id))
  if (!okId(claim.controlExchangeId)) return { claim, passed: false, detail: `Unknown control exchange ${claim.controlExchangeId} for a boundary claim.` }
  if (!okId(claim.probeExchangeId)) return { claim, passed: false, detail: `Unknown probe exchange ${claim.probeExchangeId} for a boundary claim.` }
  const control = transcriptBoundaryStep(store, claim, claim.controlExchangeId, 'control')
  const probe = transcriptBoundaryStep(store, claim, claim.probeExchangeId, 'probe')
  if (!control || !probe) return { claim, passed: false, detail: 'Boundary claim references an unreadable exchange.' }
  const assessment = assessBoundary({
    boundaryClass: claim.boundaryClass,
    impactClass: claim.boundaryClass === 'access' ? 'authorization' : 'other',
    steps: [control, probe],
    expectControlDenied: claim.expectControlDenied,
  })
  if (assessment.required && assessment.satisfied) {
    const stub = detectIntermediateStub(store.get(claim.probeExchangeId), store.body(claim.probeExchangeId))
    if (stub.isStub) return stubRejection(claim, stub.state, assessment.evidence)
  }
  return { claim, passed: assessment.required && assessment.satisfied, detail: assessment.reason, observed: assessment.evidence }
}

function evaluateMfaClaim(
  store: TranscriptStore,
  claim: Extract<VerifyClaim, { kind: 'mfa' }>,
  context: VerifyClaimContext,
): VerifyClaimCheck {
  const ids = [claim.enrolledExchangeId, claim.preChallengeExchangeId, claim.postChallengeExchangeId, ...(claim.challengeExchangeId ? [claim.challengeExchangeId] : [])]
  for (const id of ids) {
    if (context.allowedExchangeIds && !context.allowedExchangeIds.has(id)) {
      return { claim, passed: false, detail: `Unknown MFA exchange ${id}.` }
    }
    if (!store.get(id)) return { claim, passed: false, detail: `Unknown MFA exchange ${id}.` }
  }
  const steps: ImpactStep[] = []
  const add = (id: string | undefined, arm: ImpactStep['arm']) => {
    if (!id) return
    const step = transcriptBoundaryStep(store, claim, id, arm)
    if (step) steps.push(step)
  }
  add(claim.enrolledExchangeId, 'control')
  add(claim.preChallengeExchangeId, 'control')
  add(claim.challengeExchangeId, 'probe')
  add(claim.postChallengeExchangeId, 'probe')
  steps.sort((a, b) => ((a as unknown as { seq?: number }).seq ?? 0) - ((b as unknown as { seq?: number }).seq ?? 0))
  const assessment = assessMfaBypass({ impactClass: 'other', steps })
  return {
    claim,
    passed: assessment.required && assessment.satisfied,
    detail: assessment.reason,
    observed: assessment.evidence,
  }
}

function evaluateImpactClaim(
  store: TranscriptStore,
  claim: Extract<VerifyClaim, { kind: 'impact' }>,
  context: VerifyClaimContext,
): VerifyClaimCheck {
  const requireRecord = (id: string): VerifyTranscriptRecord | null => {
    if (context.allowedExchangeIds && !context.allowedExchangeIds.has(id)) return null
    return store.get(id) ?? null
  }
  if (!requireRecord(claim.probeExchangeId)) {
    return { claim, passed: false, detail: `Unknown probe exchange ${claim.probeExchangeId} for an impact claim.` }
  }
  const ids = [
    ...(claim.beforeExchangeId ? [claim.beforeExchangeId] : []),
    claim.probeExchangeId,
    ...(claim.controlExchangeIds ?? []),
    ...(claim.afterExchangeId ? [claim.afterExchangeId] : []),
  ]
  for (const id of ids) {
    if (!requireRecord(id)) return { claim, passed: false, detail: `Unknown exchange ${id} for an impact claim.` }
  }
  const defaultSameSite = ids.map(id => sameSiteFromRecord(store.get(id))).find(Boolean) ?? null
  const steps: ImpactStep[] = []
  const add = (id: string | undefined, arm: ImpactStep['arm']) => {
    if (!id) return
    const step = transcriptImpactStep(store, claim, id, arm, defaultSameSite)
    if (step) steps.push(step)
  }
  add(claim.beforeExchangeId, 'control')
  add(claim.probeExchangeId, 'probe')
  for (const id of claim.controlExchangeIds ?? []) add(id, 'control')
  add(claim.afterExchangeId, 'control')
  steps.sort((a, b) => ((a as unknown as { seq?: number }).seq ?? 0) - ((b as unknown as { seq?: number }).seq ?? 0))
  const probeRecord = store.get(claim.probeExchangeId)
  const assessment = assessImpactEvidence({
    impactClass: claim.impactClass,
    steps,
    requiredRole: claim.requiredRole ?? null,
    resourceTenant: claim.resourceTenant ?? null,
    expectControlDenied: claim.expectControlDenied,
    oracleEvents: claim.oracleEvents,
    targetOrigin: probeRecord?.request?.origin ?? null,
  })
  if (assessment.required && assessment.satisfied && claim.impactClass !== 'injection' && claim.impactClass !== 'markup' && claim.impactClass !== 'csrf') {
    const probeStub = detectIntermediateStub(probeRecord, store.body(claim.probeExchangeId))
    if (probeStub.isStub) {
      const obs = asRecord(assessment.evidence)
      const hasBoundaryCrossing = obs?.crossTenant === true || obs?.roleDifferential === true
      const afterStub = claim.afterExchangeId
        ? afterReadbackIsIntermediateOnly(claim.beforeExchangeId ? store.body(claim.beforeExchangeId) : undefined, store.get(claim.afterExchangeId), store.body(claim.afterExchangeId))
        : null
      if (afterStub ? afterStub.isStub && ((probeStub.pureJobStub && afterStub.pureJobStub) || !hasBoundaryCrossing) : (probeStub.pureJobStub || !hasBoundaryCrossing)) {
        return stubRejection(claim, afterStub?.state ?? probeStub.state, assessment.evidence ?? {})
      }
    }
  }
  return { claim, passed: assessment.required && assessment.satisfied, detail: assessment.reason, ...(assessment.evidence ? { observed: assessment.evidence } : {}) }
}

/** Active-markup evidence over the exchanges a proof already asserts (never a bare tag). */
function implicitMarkupEvidence(
  store: TranscriptStore,
  claims: readonly VerifyClaim[],
  context: VerifyClaimContext,
): { satisfied: boolean; reason: string } {
  const steps: ImpactStep[] = []
  for (const id of claimedExchangeIds(claims)) {
    if (context.allowedExchangeIds && !context.allowedExchangeIds.has(id)) continue
    const record = store.get(id)
    if (!record) continue
    const body = store.body(id) ?? ''
    steps.push({
      id,
      arm: (record.request?.sessionRole as ImpactStep['arm'] | null) ?? 'setup',
      method: (record.request?.method ?? 'GET').toUpperCase(),
      route: (record.request?.pathAndQuery ?? '/').split('?')[0],
      status: recordStatus(record),
      actor: { handle: record.request?.personaHandle ?? null, role: normalizeRole(record.request?.personaHandle ?? null), tenant: null, auth: 'unknown', sameSite: null },
      body,
    })
  }
  const assessment = assessMarkupImpact({ impactClass: 'markup', steps, oracleEvents: [] })
  return { satisfied: assessment.satisfied, reason: assessment.reason }
}

/** Claims that reference a recorded exchange id (used for implicit read-disclosure checks). */
function claimedExchangeIds(claims: readonly VerifyClaim[]): string[] {
  const ids = new Set<string>()
  for (const claim of claims) {
    if (claim.kind === 'timing' || claim.kind === 'impact') continue
    if (claim.kind === 'structural_diff') { for (const id of [...claim.controlIds, ...claim.variantIds]) ids.add(id); continue }
    if (claim.kind === 'race' || claim.kind === 'composite_receipt') { for (const id of claim.exchangeIds) ids.add(id); continue }
    if (claim.kind === 'boundary') { ids.add(claim.controlExchangeId); ids.add(claim.probeExchangeId); continue }
    if (claim.kind === 'mfa') {
      ids.add(claim.enrolledExchangeId); ids.add(claim.preChallengeExchangeId); ids.add(claim.postChallengeExchangeId)
      if (claim.challengeExchangeId) ids.add(claim.challengeExchangeId)
      continue
    }
    ids.add(claim.exchangeId)
  }
  return [...ids]
}

/**
 * An authorization-titled proof without an `impact` claim still has to expose an owner-scoped
 * non-public attribute in its probe exchange. Status and self-echoed fields are not disclosure.
 */
function implicitReadDisclosure(store: TranscriptStore, claims: readonly VerifyClaim[], context: VerifyClaimContext): { satisfied: boolean; reason: string } {
  const steps: ImpactStep[] = []
  for (const id of claimedExchangeIds(claims)) {
    if (context.allowedExchangeIds && !context.allowedExchangeIds.has(id)) continue
    const record = store.get(id)
    if (!record) continue
    const body = store.body(id), handle = record.request?.personaHandle ?? null
    steps.push({
      id,
      arm: (record.request?.sessionRole as ImpactStep['arm'] | null) ?? 'setup',
      method: (record.request?.method ?? 'GET').toUpperCase(),
      status: recordStatus(record),
      actor: { handle, role: normalizeRole(handle), tenant: parseRoleLabel(handle).tenant, auth: 'unknown', sameSite: null },
      json: parseJsonBody(body),
      body: body ?? '',
      ...(record.seq !== undefined ? { seq: record.seq } : {}),
    } as ImpactStep & { seq: number })
  }
  const probe = steps.find(step => step.arm === 'probe') ??
    [...steps].reverse().find(step => step.json !== undefined && step.json !== null)
  if (!probe) return { satisfied: false, reason: 'no probe exchange carries a JSON body to inspect for an owner-scoped disclosure' }
  if (!isReadMethod(probe.method)) {
    return { satisfied: false, reason: 'the probe exchange is a state-changing request; a write needs a persisted-impact claim, not a read disclosure' }
  }
  const disclosure = assessReadDisclosure({ steps, probe })
  return { satisfied: disclosure.satisfied, reason: disclosure.reason }
}

export function evaluateClaim(
  store: TranscriptStore,
  claim: VerifyClaim,
  context: VerifyClaimContext,
): VerifyClaimCheck {
  const requireRecord = (id: string): VerifyTranscriptRecord | null => {
    if (context.allowedExchangeIds && !context.allowedExchangeIds.has(id)) return null
    return store.get(id) ?? null
  }
  switch (claim.kind) {
    case 'impact':
      return evaluateImpactClaim(store, claim, context)
    case 'boundary':
      return evaluateBoundaryClaim(store, claim, context)
    case 'mfa':
      return evaluateMfaClaim(store, claim, context)
    case 'status': {
      const record = requireRecord(claim.exchangeId)
      if (!record) return { claim, passed: false, detail: `Unknown exchange id ${claim.exchangeId}; claims must reference recorded RPC exchanges.` }
      if (!record.response) return { claim, passed: false, detail: `Exchange ${claim.exchangeId} has no recorded response (${record.error ?? 'failed'}).` }
      const expected = Array.isArray(claim.expected) ? claim.expected : [claim.expected]
      const passed = expected.includes(record.response.status)
      return {
        claim,
        passed,
        detail: `status ${record.response.status} ${passed ? 'in' : 'not in'} [${expected.join(', ')}]`,
        observed: { status: record.response.status, exchangeId: claim.exchangeId },
      }
    }
    case 'header': {
      const record = requireRecord(claim.exchangeId)
      if (!record) return { claim, passed: false, detail: `Unknown exchange id ${claim.exchangeId}.` }
      const value = observedHeader(record, claim.name)
      if (claim.absent) {
        return { claim, passed: value === undefined, detail: value === undefined ? `header ${claim.name} absent` : `header ${claim.name} unexpectedly present`, observed: { value: value ?? null } }
      }
      if (value === undefined) return { claim, passed: false, detail: `header ${claim.name} missing`, observed: { value: null } }
      if (claim.equals !== undefined) {
        const passed = value === claim.equals
        return { claim, passed, detail: `header ${claim.name} ${passed ? 'equals' : 'differs from'} expected value`, observed: { value } }
      }
      if (claim.matches !== undefined) {
        const compiled = compileSafeClaimRegex(claim.matches)
        if (!compiled.ok) return { claim, passed: false, detail: `Unsafe or invalid header regex: ${compiled.reason}` }
        const passed = compiled.regex.test(value.slice(0, MAX_CLAIM_REGEX_HAYSTACK))
        return { claim, passed, detail: `header ${claim.name} ${passed ? 'matches' : 'does not match'} /${claim.matches}/`, observed: { value } }
      }
      return { claim, passed: value.length > 0, detail: `header ${claim.name} present`, observed: { value } }
    }
    case 'body_contains': {
      const record = requireRecord(claim.exchangeId)
      if (!record) return { claim, passed: false, detail: `Unknown exchange id ${claim.exchangeId}.` }
      const body = store.body(claim.exchangeId) ?? ''
      const present = body.includes(claim.text)
      const passed = claim.absent ? !present : present
      return { claim, passed, detail: claim.absent ? (passed ? 'text absent' : 'text unexpectedly present') : (passed ? 'text present' : 'text absent') }
    }
    case 'jsonpath': {
      const record = requireRecord(claim.exchangeId)
      if (!record) return { claim, passed: false, detail: `Unknown exchange id ${claim.exchangeId}.` }
      const body = store.body(claim.exchangeId)
      if (body === undefined) return { claim, passed: false, detail: `Exchange ${claim.exchangeId} has no recorded body.` }
      let parsed: unknown
      try { parsed = JSON.parse(body) } catch { return { claim, passed: false, detail: 'Recorded response body is not JSON.' } }
      const result = evaluateJsonPath(parsed, claim.path)
      const observed = result.value
      if (claim.exists !== undefined) {
        const passed = claim.exists ? result.found : !result.found
        return { claim, passed, detail: `${claim.path} ${result.found ? 'exists' : 'missing'}`, observed: { value: observed ?? null } }
      }
      if (claim.equals !== undefined) {
        const passed = JSON.stringify(observed) === JSON.stringify(claim.equals)
        return { claim, passed, detail: `${claim.path} ${passed ? 'matches' : 'differs from'} expected value`, observed: { value: observed ?? null } }
      }
      if (claim.matches !== undefined) {
        const compiled = compileSafeClaimRegex(claim.matches)
        if (!compiled.ok) return { claim, passed: false, detail: `Unsafe or invalid jsonpath regex: ${compiled.reason}` }
        const passed = compiled.regex.test(String(observed).slice(0, MAX_CLAIM_REGEX_HAYSTACK))
        return { claim, passed, detail: `${claim.path} ${passed ? 'matches' : 'does not match'} /${claim.matches}/`, observed: { value: observed ?? null } }
      }
      return { claim, passed: result.found, detail: `${claim.path} ${result.found ? 'present' : 'missing'}`, observed: { value: observed ?? null } }
    }
    case 'css': {
      const record = requireRecord(claim.exchangeId)
      if (!record) return { claim, passed: false, detail: `Unknown exchange id ${claim.exchangeId}.` }
      const html = store.body(claim.exchangeId)
      if (html === undefined) return { claim, passed: false, detail: `Exchange ${claim.exchangeId} has no recorded DOM.` }
      const selector = parseSelector(claim.selector)
      if (!selector) return { claim, passed: false, detail: `Unsupported selector-lite syntax: ${claim.selector}` }
      const matches = scanElements(html).filter(element => matchesSelector(element, selector))
      if (claim.exists !== undefined) {
        const passed = claim.exists ? matches.length > 0 : matches.length === 0
        return { claim, passed, detail: `selector ${claim.selector} matched ${matches.length} element(s)`, observed: { count: matches.length } }
      }
      if (claim.count !== undefined) {
        const passed = matches.length === claim.count
        return { claim, passed, detail: `selector ${claim.selector} matched ${matches.length}, expected ${claim.count}`, observed: { count: matches.length } }
      }
      if (claim.textContains !== undefined || claim.textEquals !== undefined) {
        const text = matches.map(m => m.text).join(' ')
        const passed = claim.textEquals !== undefined ? text === claim.textEquals : text.includes(claim.textContains ?? '')
        return { claim, passed, detail: `selector ${claim.selector} text ${passed ? 'matched' : 'did not match'}`, observed: { text: text.slice(0, 200) } }
      }
      return { claim, passed: matches.length > 0, detail: `selector ${claim.selector} matched ${matches.length} element(s)`, observed: { count: matches.length } }
    }
    case 'dom_sentinel': {
      const record = requireRecord(claim.exchangeId)
      if (!record) return { claim, passed: false, detail: `Unknown exchange id ${claim.exchangeId}.` }
      const mode = claim.mode ?? 'executed'
      if (mode === 'executed') {
        const executed = record.artifact?.executedSentinels ?? []
        const passed = executed.includes(claim.sentinel)
        return { claim, passed, detail: `execution sentinel ${passed ? 'observed' : 'not observed'}`, observed: { executed: executed.slice(0, 8) } }
      }
      const html = store.body(claim.exchangeId) ?? ''
      const passed = html.includes(claim.sentinel)
      return { claim, passed, detail: `DOM sentinel ${passed ? 'present' : 'absent'}`, observed: { present: passed } }
    }
    case 'oob': {
      const record = requireRecord(claim.exchangeId)
      if (!record) return { claim, passed: false, detail: `Unknown exchange id ${claim.exchangeId}.` }
      if (record.op !== 'oob' || !record.artifact?.token) {
        return { claim, passed: false, detail: `Exchange ${claim.exchangeId} is not an OOB mint.` }
      }
      const expectHit = claim.expectHit ?? true
      let liveHit: boolean | null = null
      if (context.canary) {
        try { liveHit = context.canary.checkCanary(record.artifact.token).hit } catch { liveHit = null }
      }
      // A signed `oob check` record for the same token is append-only evidence of the callback;
      // the mint record itself is signed before any hit is known.
      const checkRecord = store.list().find(candidate =>
        candidate.op === 'oob' &&
        candidate.artifact?.token === record.artifact?.token &&
        candidate.artifact?.hit === true,
      )
      const recordedHit = Boolean(record.artifact.hit) || Boolean(checkRecord)
      const hit = liveHit === null ? recordedHit : recordedHit && liveHit
      const passed = expectHit ? hit : !hit
      return {
        claim,
        passed,
        detail: `OOB canary ${hit ? 'triggered' : 'did not trigger'}${liveHit === null ? ' (recorded)' : ' (re-checked)'}`,
        observed: { token: record.artifact.token, hit, liveHit },
      }
    }
    case 'timing': {
      const minPairs = Math.max(3, Math.min(claim.minPairs ?? 5, 7))
      const controlIds = claim.controlIds
      const variantIds = claim.variantIds
      if (controlIds.length < minPairs || variantIds.length < minPairs) {
        return { claim, passed: false, detail: `timing needs ${minPairs} interleaved pairs; got ${controlIds.length}/${variantIds.length}.` }
      }
      const controlRecords: VerifyTranscriptRecord[] = []
      const variantRecords: VerifyTranscriptRecord[] = []
      for (const id of controlIds) {
        const r = requireRecord(id)
        if (!r?.response) return { claim, passed: false, detail: `Unknown or failed timing control exchange ${id}.` }
        controlRecords.push(r)
      }
      for (const id of variantIds) {
        const r = requireRecord(id)
        if (!r?.response) return { claim, passed: false, detail: `Unknown or failed timing variant exchange ${id}.` }
        variantRecords.push(r)
      }
      // Interleaving check: a stable slow endpoint cannot fake separation by batching all probes.
      const ordered = [...controlRecords.map(r => ({ seq: r.seq, g: 0 })), ...variantRecords.map(r => ({ seq: r.seq, g: 1 }))]
        .sort((a, b) => a.seq - b.seq)
      let run = 0
      let previous = -1
      for (const item of ordered) {
        if (item.g === previous) run += 1
        else { run = 1; previous = item.g }
        if (run > 2) return { claim, passed: false, detail: 'timing exchanges are not interleaved control/variant pairs.' }
      }
      const control = controlRecords.map(r => r.durationMs)
      const variant = variantRecords.map(r => r.durationMs)
      const stats = mannWhitneyU(control, variant)
      const maxP = Math.min(Math.max(claim.maxPValue ?? 0.05, 0.001), 0.05)
      const passed = stats.pValue <= maxP && stats.separation >= 3
      return {
        claim,
        passed,
        detail: `Mann-Whitney p=${stats.pValue.toFixed(4)} separation=${stats.separation.toFixed(2)} (medians ${stats.medianControl.toFixed(1)}ms -> ${stats.medianVariant.toFixed(1)}ms)`,
        observed: {
          pValue: Number(stats.pValue.toFixed(6)),
          separation: Number(stats.separation.toFixed(3)),
          medianControl: stats.medianControl,
          medianVariant: stats.medianVariant,
          madControl: stats.madControl,
          madVariant: stats.madVariant,
          pairs: control.length,
        },
      }
    }
    case 'structural_diff': {
      const minRounds = Math.max(2, Math.min(claim.minRounds ?? 3, 10))
      if (claim.controlIds.length < minRounds || claim.variantIds.length < minRounds) {
        return { claim, passed: false, detail: `structural_diff needs ${minRounds} control and ${minRounds} variant exchanges; got ${claim.controlIds.length}/${claim.variantIds.length}.` }
      }
      const bodyOf = (id: string): string | null => {
        if (context.allowedExchangeIds && !context.allowedExchangeIds.has(id)) return null
        const record = requireRecord(id)
        if (!record?.response) return null
        return store.body(id) ?? ''
      }
      const controlBodies = claim.controlIds.map(bodyOf)
      const variantBodies = claim.variantIds.map(bodyOf)
      if (controlBodies.some(body => body === null)) return { claim, passed: false, detail: 'structural_diff references an unknown or failed control exchange.' }
      if (variantBodies.some(body => body === null)) return { claim, passed: false, detail: 'structural_diff references an unknown or failed variant exchange.' }
      const controls = controlBodies as string[]
      const variants = variantBodies as string[]
      const unstableControl = controls.some(body => !structuralDiff(controls[0]!, body).normalizedEqual)
      const unstableVariant = variants.some(body => !structuralDiff(variants[0]!, body).normalizedEqual)
      if (unstableControl || unstableVariant) {
        return {
          claim,
          passed: false,
          detail: `structural_diff needs a stable response within each arm after token stripping; ${unstableControl ? 'control' : 'variant'} arm drifted between rounds.`,
          observed: { stableControl: !unstableControl, stableVariant: !unstableVariant },
        }
      }
      const roundDeltas = controls.map((body, index) => structuralDiff(body, variants[index] ?? variants[0]!).changedTokens)
      const stableDelta = intersectStructuralDeltas(roundDeltas)
      const cross = structuralDiff(controls[0]!, variants[0]!)
      const minDelta = Math.max(1, Math.min(claim.minDeltaTokens ?? 1, 32))
      const maxSimilarity = claim.maxSimilarity ?? 1
      const distinct = !cross.normalizedEqual && stableDelta.length >= minDelta && cross.similarity < maxSimilarity
      const diffObs = { stableDelta: stableDelta.slice(0, 16), similarity: Number(cross.similarity.toFixed(4)), rounds: controls.length, stableControl: !unstableControl, stableVariant: !unstableVariant }
      if (distinct) {
        const vStubs = claim.variantIds.map((id, i) => detectIntermediateStub(store.get(id), variants[i]))
        if (vStubs.every(s => s.isStub) && variants.every(b => matchInjectionFingerprint(b) === null) &&
            (vStubs.every(s => s.pureJobStub) || claim.controlIds.every(id => (recordStatus(store.get(id)) ?? 0) >= 400))) {
          return stubRejection(claim, vStubs[0]?.state ?? 'draft', diffObs)
        }
      }
      // A changed token must be present in the same direction in every round: intersect alone can
      // keep tokens that rotate between two unrelated arms, so require the first arm's delta.
      return {
        claim,
        passed: distinct,
        detail: distinct
          ? `Structural differential: ${stableDelta.length} stable token(s) changed between arms (similarity ${cross.similarity.toFixed(3)}).`
          : `No stable structural differential: ${stableDelta.length} stable changed token(s), similarity ${cross.similarity.toFixed(3)}; ${cross.normalizedEqual ? 'the arms are identical after token stripping' : 'the delta is not stable across rounds'}.`,
        observed: diffObs,
      }
    }
    case 'race': {
      const minDistinct = Math.max(2, Math.min(claim.minDistinctOutcomes ?? 2, claim.exchangeIds.length))
      if (claim.exchangeIds.length < 2 || claim.exchangeIds.length > 10) {
        return { claim, passed: false, detail: `race needs between 2 and 10 exchanges; got ${claim.exchangeIds.length}.` }
      }
      const records: VerifyTranscriptRecord[] = []
      for (const id of claim.exchangeIds) {
        const record = requireRecord(id)
        if (!record?.response) return { claim, passed: false, detail: `Unknown or failed race exchange ${id}.` }
        records.push(record)
      }
      if (claim.mode === 'h2-single-packet' && records.some(record => record.op !== 'http2')) {
        return { claim, passed: false, detail: 'race claims an HTTP/2 single-packet barrier but the transcript recorded an HTTP/1.1 fallback exchange.' }
      }
      if (claim.expectAllSuccess !== false && records.some(record => (record.response?.status ?? 0) < 200 || (record.response?.status ?? 0) >= 300)) {
        return {
          claim,
          passed: false,
          detail: 'race burst expected every participant to succeed; at least one exchange was denied or errored, so no duplicate effect is attributable to the burst.',
          observed: { statuses: records.map(record => record.response?.status ?? null) },
        }
      }
      const distinctBodies = new Set(records.map(record => record.response?.bodySha256 ?? '')).size
      const distinctStatuses = new Set(records.map(record => record.response?.status ?? 0)).size
      const distinctOutcomes = Math.max(distinctBodies, distinctStatuses)
      const passed = distinctOutcomes >= minDistinct
      return {
        claim,
        passed,
        detail: passed
          ? `Race burst produced ${distinctOutcomes} distinct outcome(s) across ${records.length} synchronized exchanges (${claim.mode ?? 'mode-unspecified'}); a serialized/idempotent handler would return one outcome.`
          : `Race burst produced one idempotent outcome across ${records.length} synchronized exchanges; duplicate-effect evidence is missing.`,
        observed: {
          distinctBodies,
          distinctStatuses,
          distinctOutcomes,
          statuses: records.map(record => record.response?.status ?? null),
          mode: claim.mode ?? null,
          ops: [...new Set(records.map(record => record.op))],
        },
      }
    }
    case 'composite_receipt': {
      const hostRec = claim.verificationId ? store.getCompositeVerification(claim.verificationId) : undefined
      if (!hostRec) {
        return {
          claim,
          passed: false,
          detail: 'composite_receipt claim must reference a host-verified composite.verify verificationId recorded in this session transcript.',
          observed: { confirmed: false, rejectedBy: 'composite_receipt', missingEvidence: ['host_composite_verification'] },
        }
      }
      if (hostRec.chainId !== claim.chainId || hostRec.terminalVulnClass !== claim.terminalVulnClass) {
        return {
          claim,
          passed: false,
          detail: 'composite_receipt claim identity does not match the host-signed composite verification record.',
          observed: { confirmed: false, rejectedBy: 'composite_receipt', missingEvidence: ['composite_identity_match'] },
        }
      }
      if (!hostRec.confirmed) {
        return {
          claim,
          passed: false,
          detail: `CompositeProofReceipt rejected at stage '${hostRec.failedStage ?? 'unknown'}': ${hostRec.reason}`,
          observed: {
            confirmed: false,
            chainId: hostRec.chainId,
            terminalVulnClass: hostRec.terminalVulnClass,
            hopCount: hostRec.hopCount,
            failedStage: hostRec.failedStage ?? null,
            rejectedBy: hostRec.rejectedBy ?? 'composite_receipt',
            missingEvidence: hostRec.missingEvidence,
            reason: hostRec.reason,
          },
        }
      }
      for (const id of hostRec.exchangeIds) {
        if (!requireRecord(id)) {
          return {
            claim,
            passed: false,
            detail: `composite_receipt cites exchange ${id} outside this attempt transcript.`,
            observed: { confirmed: false, rejectedBy: 'composite_transcript_integrity', missingEvidence: ['attempt_transcript_exchange'] },
          }
        }
      }
      return {
        claim,
        passed: true,
        detail: hostRec.reason,
        observed: {
          confirmed: true,
          chainId: hostRec.chainId,
          terminalVulnClass: hostRec.terminalVulnClass,
          replayMode: hostRec.replayMode,
          hopCount: hostRec.hopCount,
          verifiedEdgeCount: hostRec.verifiedEdgeCount,
        },
      }
    }
    default:
      return { claim, passed: false, detail: 'Unsupported claim.' }
  }
}

/**
 * Translate a failed claim into the exact missing transcript role/precondition. The strings are
 * stable tokens (not prose) so an agent can repair the script in one turn: add the named arm and
 * re-run, instead of inferring what an opaque boolean meant.
 */
export function describeMissingEvidence(check: VerifyClaimCheck): string[] {
  if (check.passed) return []
  const missing = new Set<string>()
  const observed = check.observed ?? {}
  if (observed.rejectedBy === 'terminal_impact_unproven') return ['terminal_impact_unproven']
  const detail = check.detail ?? ''
  const claim = check.claim
  const bool = (key: string): boolean | null => typeof observed[key] === 'boolean' ? observed[key] as boolean : null
  switch (claim.kind) {
    case 'boundary': {
      if (bool('controlDenied') === false) missing.add('control_denied')
      if (bool('crossed') === false) missing.add('variant_crossed')
      if (bool('actorDifferential') === false && bool('controlDenied') !== true) missing.add('actor_differential')
      break
    }
    case 'impact': {
      if (claim.impactClass === 'injection') {
        if (/fingerprint/i.test(detail)) missing.add('engine_error_fingerprint')
        if (/boolean/i.test(detail)) missing.add('boolean_round_differential')
        if (/timing|jitter/i.test(detail)) missing.add('timing_separation')
        if (/out-of-band|callback/i.test(detail)) missing.add('oob_callback_hit')
        if (/status-only|status divergence|semantic oracle/i.test(detail)) missing.add('injection_semantic_oracle')
      } else if (claim.impactClass === 'mass_assignment') {
        if (Array.isArray(observed.persisted) && observed.persisted.length === 0) missing.add('persisted_field_delta')
        if (Array.isArray(observed.protectedFields) && observed.protectedFields.length === 0) missing.add('protected_field_delta')
        if (!Array.isArray(observed.persisted)) {
          if (/pre-mutation readback/.test(detail)) missing.add('before_get')
          if (/separate post-mutation GET/.test(detail)) missing.add('after_get')
          if (/request body/.test(detail)) missing.add('mutation_request_body')
          if (/catalog/.test(detail)) missing.add('catalog_baseline')
          if (/echo|persistence/.test(detail) && !/request body/.test(detail)) missing.add('persisted_field_delta')
        }
      } else if (claim.impactClass === 'csrf') {
        if (bool('persisted') === false) missing.add('persisted_state_change')
        if (typeof observed.ambient === 'string' && observed.ambient !== 'cookie') missing.add('ambient_cookie_auth')
        if (typeof observed.sameSite === 'string' && observed.sameSite.toLowerCase() !== 'none') missing.add('samesite_none_cookie')
        if (bool('crossSite') === false) missing.add('cross_site_origin')
        if (bool('oracleDeclared') === false) missing.add('impact_oracle_event')
      } else {
        if (bool('persisted') === false) {
          if (/pre-mutation readback/.test(detail)) missing.add('before_get')
          else if (/separate post-mutation GET/.test(detail)) missing.add('after_get')
          else missing.add('persisted_field_delta')
        }
        if (bool('roleDifferential') === false && bool('crossTenant') === false) missing.add('role_or_tenant_differential')
        if (bool('boundaryControlDenied') === false && bool('roleDifferential') !== true && bool('crossTenant') !== true) missing.add('control_denied')
        if (Array.isArray(observed.disclosureFields) && observed.disclosureFields.length === 0 && /disclosure/.test(detail)) missing.add('owner_scoped_disclosure')
        if (Array.isArray(observed.changedFields) && observed.changedFields.length === 0 && /persisted impact/.test(detail)) missing.add('field_delta')
        if (/oracle event/.test(detail)) missing.add('impact_oracle_event')
        if (/control arm/.test(detail)) missing.add('control_arm')
      }
      if (/no probe step/.test(detail)) missing.add('probe_arm')
      break
    }
    case 'mfa': {
      if (bool('enrolled') === false) missing.add('enrolled_control')
      if (bool('preDenied') === false) missing.add('pre_challenge_denied')
      if (bool('postGranted') === false) missing.add('post_challenge_granted')
      if (bool('sameActor') === false) missing.add('same_actor')
      if (bool('sameRoute') === false) missing.add('same_route')
      if (bool('decorative') === true) missing.add('gated_control')
      break
    }
    case 'timing': {
      if (/interleav/.test(detail)) missing.add('interleaved_pairs')
      else if (/got \d+\/\d+/.test(detail)) missing.add('control_variant_pairs')
      else missing.add('timing_separation')
      break
    }
    case 'structural_diff': {
      if (bool('stableControl') === false) missing.add('stable_control_arm')
      if (bool('stableVariant') === false) missing.add('stable_variant_arm')
      if (Array.isArray(observed.stableDelta) && observed.stableDelta.length === 0) missing.add('stable_variant_delta')
      if (/identical after token stripping/.test(detail)) missing.add('arm_differential')
      if (/needs \d+ control/.test(detail)) missing.add('control_variant_rounds')
      break
    }
    case 'race': {
      if (typeof observed.distinctOutcomes === 'number' && observed.distinctOutcomes < (claim.minDistinctOutcomes ?? 2)) missing.add('duplicate_effect')
      if (/HTTP\/1\.1 fallback/.test(detail)) missing.add('h2_single_packet_barrier')
      if (/expected every participant to succeed/.test(detail)) missing.add('all_participants_success')
      if (/needs between 2 and 10/.test(detail)) missing.add('race_requests')
      break
    }
    case 'oob':
      missing.add('oob_callback_hit')
      break
    case 'composite_receipt': {
      if (Array.isArray(observed.missingEvidence)) {
        for (const item of observed.missingEvidence) {
          if (typeof item === 'string' && item.trim()) missing.add(item.trim())
        }
      }
      if (missing.size === 0 && typeof observed.rejectedBy === 'string' && observed.rejectedBy.trim()) {
        missing.add(observed.rejectedBy.trim())
      }
      break
    }
    case 'status':
    case 'header':
    case 'body_contains':
    case 'jsonpath':
    case 'css':
    case 'dom_sentinel':
      missing.add(`${claim.kind}_claim`)
      break
    default:
      break
  }
  if (missing.size === 0) missing.add('claim_evidence')
  return [...missing]
}

/** Materialize the signed transcript as the shared impact model (bodies included, bounded). */
function transcriptStatusSteps(store: TranscriptStore): ImpactStep[] {
  const out: ImpactStep[] = []
  for (const record of store.list()) {
    if (!record.request) continue
    if (record.op !== 'http' && record.op !== 'http2') continue
    const body = store.body(record.exchangeId) ?? ''
    const json = parseJsonBody(body)
    const role = record.request.sessionRole
    const arm: ImpactStep['arm'] = role === 'probe' || role === 'control' ? role : 'setup'
    const handle = record.request.personaHandle ?? null
    const label = record.request.actorRoleLabel ?? null
    out.push({
      id: record.exchangeId,
      arm,
      method: record.request.method.toUpperCase(),
      route: (record.request.pathAndQuery || '/').split('?')[0],
      pathAndQuery: record.request.pathAndQuery,
      status: recordStatus(record),
      actor: { handle, role: normalizeRole(label ?? handle), tenant: parseRoleLabel(label ?? handle ?? '').tenant ?? null, auth: 'unknown', sameSite: null },
      ...(json !== undefined ? { json } : {}),
      body,
      requestHeaders: record.request.headers,
      responseHeaders: record.response?.headers ?? null,
      durationMs: record.durationMs,
    })
  }
  return out
}

/** Text a claim's exchange actually produced (for fingerprint detection). */
function claimEvidenceText(store: TranscriptStore, check: VerifyClaimCheck): string {
  const claim = check.claim
  const ids: string[] = []
  if (claim.kind === 'status' || claim.kind === 'header' || claim.kind === 'body_contains' ||
      claim.kind === 'jsonpath' || claim.kind === 'css' || claim.kind === 'dom_sentinel') {
    ids.push(claim.exchangeId)
  } else if (claim.kind === 'structural_diff') {
    ids.push(...claim.controlIds, ...claim.variantIds)
  } else if (claim.kind === 'race') {
    ids.push(...claim.exchangeIds)
  } else if (claim.kind === 'impact') {
    ids.push(claim.probeExchangeId, ...(claim.controlExchangeIds ?? []), ...(claim.afterExchangeId ? [claim.afterExchangeId] : []))
  } else if (claim.kind === 'boundary') {
    ids.push(claim.controlExchangeId, claim.probeExchangeId)
  } else if (claim.kind === 'mfa') {
    ids.push(claim.enrolledExchangeId, claim.preChallengeExchangeId, claim.postChallengeExchangeId)
  } else if (claim.kind === 'composite_receipt') {
    ids.push(...claim.exchangeIds)
  }
  return ids.map(id => store.body(id) ?? '').join('\n').slice(0, 64 * 1024)
}

/**
 * True when a passing claim carries evidence that stands without the HTTP status. A body/header
 * claim is not enough on its own here: the *probe exchange* must carry an engine fingerprint, which
 * is checked separately from the signed transcript body.
 */
function hasStatusIndependentEvidence(check: VerifyClaimCheck): boolean {
  if (!check.passed) return false
  switch (check.claim.kind) {
    case 'structural_diff':
    case 'timing':
    case 'oob':
    case 'race':
    case 'impact':
    case 'boundary':
    case 'mfa':
    case 'dom_sentinel':
    case 'composite_receipt':
      return true
    default:
      return false
  }
}

export function evaluateClaims(
  store: TranscriptStore,
  claims: readonly VerifyClaim[],
  context: VerifyClaimContext = {},
): VerifyOracleResult {
  const checks = claims.map(claim => evaluateClaim(store, claim, context))
  const failures = checks.filter(c => !c.passed).map(c => `${c.claim.kind}: ${c.detail}`)
  const claimed = context.claimedImpact
  // Universal status-only guard: a failing probe is never confirmation by itself. A 2xx -> 4xx/5xx
  // transition must be backed by an engine/parser fingerprint, a structural differential, a timing
  // arm, a state delta or an OOB callback; otherwise the claim is a bare availability/error signal.
  const statusSteps = transcriptStatusSteps(store)
  const statusOnly = assessStatusOnlyDivergence(statusSteps)
  if (statusOnly.statusOnly) {
    const probeText = statusOnly.probeId ? store.body(statusOnly.probeId) ?? '' : ''
    const fingerprintBacked = matchInjectionFingerprint(probeText) !== null
    const backed = fingerprintBacked || checks.some(check => hasStatusIndependentEvidence(check))
    if (!backed) {
      failures.push(`confirmation: ${statusOnly.reason} A status-only divergence cannot confirm injection, XSS, SSRF, traversal or any other class; cite an engine/parser fingerprint, a stable structural differential, a timing separation, a persisted state delta or an OOB callback.`)
    }
  }
  const injectionEvidencePassed = checks.some(check =>
    check.passed && (
      check.claim.kind === 'impact' && check.claim.impactClass === 'injection' ||
      check.claim.kind === 'structural_diff' ||
      check.claim.kind === 'timing' ||
      check.claim.kind === 'oob' ||
      matchInjectionFingerprint(claimEvidenceText(store, check)) !== null))
  // A boundary claim substitutes for impact evidence only when it crossed an actual denial/challenge;
  // an actor/precondition differential alone is not object-level impact.
  const boundaryClaimPassed = checks.some(check =>
    check.passed && check.claim.kind === 'boundary' &&
    (check.observed as { arm?: unknown } | undefined)?.arm === 'control_denied')
  const compositePassed = checks.some(check => check.passed && check.claim.kind === 'composite_receipt')
  const compositeFailed = checks.some(check => !check.passed && check.claim.kind === 'composite_receipt')
  const impactBacked = compositePassed || checks.some(check =>
    check.passed && check.claim.kind === 'impact' &&
    (check.claim.impactClass === claimed ||
      ((claimed === 'bfla' || claimed === 'disclosure') && check.claim.impactClass === 'authorization')))
  if (claimed && claimed !== 'other' && !impactBacked && !compositeFailed) {
    if (claimed === 'authorization' || claimed === 'disclosure') {
      const disclosure = implicitReadDisclosure(store, claims, context)
      if (!disclosure.satisfied && !boundaryClaimPassed) {
        failures.push(`impact: ${claimed} claim dismissed — ${disclosure.reason}. A status/self-echo claim is not object-level disclosure.`)
      }
    } else if (claimed === 'markup') {
      const markup = implicitMarkupEvidence(store, claims, context)
      if (!markup.satisfied) {
        failures.push(`impact: markup claim dismissed — ${markup.reason}`)
      }
    } else if (claimed === 'injection') {
      if (!injectionEvidencePassed) {
        failures.push('impact: injection claim requires a positive semantic oracle — an engine/dialect error fingerprint, a paired boolean differential with a stable structural delta, a >3x timing arm, a verified OOB callback, or the paired status-boolean contrast. A status-only 2xx -> 4xx/5xx divergence is not proof.')
      }
    } else {
      failures.push(`impact: ${claimed} claim requires a passing impact-evidence claim for its class (boundary differential, repeated transition, protected-field readback or invariant event); status and echo claims are insufficient.`)
    }
  }
  // Universal default-deny: authentication/bypass claims confirm only with a signed, challenged
  // control that the variant crosses. No label can pass on a 2xx from an ungated request.
  const claimedBoundary = context.claimedBoundary
  const mfaClaimPassed = checks.some(check => check.passed && check.claim.kind === 'mfa')
  if (!compositePassed && !compositeFailed && claimedBoundary === 'mfa' && !mfaClaimPassed) {
    failures.push('boundary: MFA/2FA claim requires an `mfa` claim showing an enrolled account, a protected read denied/challenged before the code check, and the same actor granted the same resource after it; an OTP endpoint that returns {ok:true} without gating anything is advisory only.')
  }
  if (!compositePassed && !compositeFailed && claimedBoundary === 'auth' && !boundaryClaimPassed) {
    failures.push('boundary: authentication/bypass claim requires a `boundary` claim over a denied/challenged control (401/403, login redirect or MFA challenge) and a variant that crosses it; a 2xx from an ungated request is not a bypass.')
  }
  if (!compositePassed && !compositeFailed && claimedBoundary === 'access' && !boundaryClaimPassed && !impactBacked) {
    const disclosure = implicitReadDisclosure(store, claims, context)
    if (!disclosure.satisfied) {
      failures.push('boundary: access-control claim requires a denied/challenged control plus a crossing variant, or an actor/precondition differential backed by data/state evidence.')
    }
  }
  // Standalone intermediate-stub gate: reject non-composite proofs whose succeeding probes only
  // create or poll a draft/queued/pending object or handle stub with no terminal security impact.
  const hasTerminalOracle = checks.some(c => c.passed && ['composite_receipt', 'oob', 'dom_sentinel', 'timing', 'mfa', 'race', 'impact', 'boundary'].includes(c.claim.kind))
  const hasEvaluatedOrFp = checks.some(p => {
    if (!p.passed) return false
    if (matchInjectionFingerprint(claimEvidenceText(store, p)) !== null) return true
    const pc = p.claim
    if (pc.kind !== 'body_contains' || pc.absent === true || pc.text.length < 4) return false
    return checks.some(a => a.passed && a.claim.kind === 'body_contains' && a.claim.absent === true && a.claim.text === pc.text &&
      a.claim.exchangeId !== pc.exchangeId && ((s: number | null) => s !== null && s >= 200 && s < 300)(recordStatus(store.get(a.claim.exchangeId))))
  })
  const citedRecords = claimedExchangeIds(claims)
    .filter(id => !context.allowedExchangeIds || context.allowedExchangeIds.has(id))
    .map(id => store.get(id))
    .filter((rec): rec is VerifyTranscriptRecord => Boolean(rec?.request && rec.response && (rec.op === 'http' || rec.op === 'http2')))
  if (!hasTerminalOracle && !hasEvaluatedOrFp) {
    const ok2xx = citedRecords.filter(r => { const s = recordStatus(r); return s !== null && s >= 200 && s < 300 })
    const probe2xx = ok2xx.filter(r => r.request?.sessionRole === 'probe')
    const mut2xx = ok2xx.filter(r => isMutatingMethod(r.request?.method))
    const primary2xx = probe2xx.length > 0 ? probe2xx : (mut2xx.length > 0 ? mut2xx : ok2xx)
    if (primary2xx.length > 0 && primary2xx.every(r => detectIntermediateStub(r, store.body(r.exchangeId)).isStub)) {
      const minProbeSeq = Math.min(...primary2xx.map(r => r.seq))
      const beforeBody = [...ok2xx].reverse().find(r => r.seq < minProbeSeq && !isMutatingMethod(r.request?.method))
      const probeActors = new Set(primary2xx.map(r => r.request?.personaHandle ?? null))
      const hasNonStubAfter = ok2xx.some(r =>
        r.seq > minProbeSeq && !primary2xx.includes(r) && !detectIntermediateStub(r, store.body(r.exchangeId)).isStub &&
        !(probeActors.has(r.request?.personaHandle ?? null) && afterReadbackIsIntermediateOnly(beforeBody ? store.body(beforeBody.exchangeId) : undefined, r, store.body(r.exchangeId)).isStub))
      if (!hasNonStubAfter) failures.push(STANDALONE_TERMINAL_IMPACT_HINT)
    }
  }
  const failedCheck = checks.find(check => !check.passed) ?? null
  const missingEvidence = new Set<string>()
  for (const check of checks) for (const item of describeMissingEvidence(check)) missingEvidence.add(item)
  if (failures.some(f => f.startsWith('terminal_impact_unproven:'))) missingEvidence.add('terminal_impact_unproven')
  if (failures.some(f => /impact: (?:authorization|disclosure) claim dismissed/.test(f))) missingEvidence.add('owner_scoped_disclosure')
  if (failures.some(f => /markup claim dismissed/.test(f))) missingEvidence.add('executable_markup')
  if (failures.some(f => /impact: .* requires a passing impact-evidence claim/.test(f))) missingEvidence.add('impact_claim')
  if (failures.some(f => /^boundary: authentication/.test(f))) missingEvidence.add('boundary_claim')
  if (failures.some(f => /^boundary: MFA/.test(f))) missingEvidence.add('mfa_claim')
  if (failures.some(f => /^boundary: access-control/.test(f))) missingEvidence.add('boundary_or_disclosure')
  const rejectedBy = failedCheck
    ? (typeof failedCheck.observed?.rejectedBy === 'string' ? failedCheck.observed.rejectedBy : failedCheck.claim.kind)
    : failures.length > 0
      ? (failures.some(f => f.startsWith('terminal_impact_unproven:')) ? 'terminal_impact_unproven'
          : failures.some(f => f.startsWith('boundary:')) ? 'boundary_gate'
            : failures.some(f => f.startsWith('impact:')) ? 'impact_gate' : 'oracle')
      : null
  const impactProbeId = claims.find((c): c is Extract<VerifyClaim, { kind: 'impact' }> => c.kind === 'impact')?.probeExchangeId
  const endpoint = citedRecords.find(r => r.request?.sessionRole === 'probe')?.request?.pathAndQuery
    ?? (impactProbeId ? store.get(impactProbeId)?.request?.pathAndQuery : undefined)
    ?? citedRecords[citedRecords.length - 1]?.request?.pathAndQuery ?? null
  return {
    passed: checks.length > 0 && failures.length === 0,
    checks,
    failures,
    transcriptDigest: store.digest(),
    rejectedBy,
    missingEvidence: failures.length > 0 ? [...missingEvidence] : [],
    transcriptSummary: store.summaries(),
    endpoint,
  }
}

// ---------------------------------------------------------------------------
// Cross-attempt causal fingerprints
// ---------------------------------------------------------------------------

function normalizedValue(value: unknown, nonce: string): unknown {
  if (typeof value === 'string') return normalizeDynamic(value, nonce)
  if (Array.isArray(value)) return value.map(v => normalizedValue(v, nonce))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = normalizedValue(v, nonce)
    return out
  }
  return value
}

const STANDARD_PATH_PREFIX_RE = /^(?:cwe|cve|rfc|iso|sha|aes|rsa|hmac|http|https|utf|tls|jwt|oauth|v\d+)$/i
const STANDARD_ALGO_TOKEN_RE = /^(?:sha\d+|aes\d+|hs\d+|rs\d+|es\d+|utf\d+|base\d+|http\d+)$/i

function isDynamicPathSegment(decoded: string): boolean {
  if (
    /^\d+$/.test(decoded) ||
    /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(decoded) ||
    /^[0-9a-f]{16,}$/i.test(decoded) ||
    /^gx-[0-9a-f-]{4,}$/i.test(decoded) ||
    /^cap:[A-Za-z0-9_.:-]+$/.test(decoded) ||
    /\[redacted(?::[^\]]+)?\]/i.test(decoded) ||
    /^[a-z]{2,10}_[A-Za-z0-9]{8,}$/.test(decoded) ||
    (/^[a-z]{2,12}[-_][A-Za-z0-9]{3,}$/i.test(decoded) && /\d/.test(decoded) && !/^(?:cwe|cve|rfc|iso|sha|aes|rsa|hmac|http|https|utf|tls|jwt)[-_]/i.test(decoded))
  ) return true
  const parts = decoded.split(/[-_]/)
  if (parts.length >= 2 && /^[a-z][a-z0-9]*$/i.test(parts[0]!) && !STANDARD_PATH_PREFIX_RE.test(parts[0]!)) {
    const tail = parts.slice(1)
    const hasDigitAlnumChunk = tail.some(p => /^(?=[a-z0-9]*\d)[a-z0-9]{4,}$/i.test(p) && !STANDARD_ALGO_TOKEN_RE.test(p))
    const numericCount = tail.filter(p => /^\d+$/.test(p)).length
    const digitPartCount = tail.filter(p => /\d/.test(p)).length
    if (hasDigitAlnumChunk || (parts.length >= 3 && numericCount >= 1 && digitPartCount >= 2)) return true
  }
  return false
}

/** Path template so fresh-session ids do not break agreement. */
function pathFingerprint(path: string | undefined): string {
  if (!path) return ''
  const [pathname, search] = path.split('?')
  const templated = pathname.split('/').map((segment, index) => {
    if (index === 0 || segment === '') return segment
    let decoded = segment
    if (segment.includes('%')) {
      try { decoded = decodeURIComponent(segment) } catch { decoded = segment }
    }
    const extMatch = /^([^./]+)(\.[a-z0-9]{1,8})$/i.exec(decoded)
    if (extMatch && isDynamicPathSegment(extMatch[1]!)) return `*${extMatch[2]!.toLowerCase()}`
    if (isDynamicPathSegment(decoded)) return '*'
    return segment.toLowerCase()
  }).join('/')
  // Query parameter names are causal; values are usually nonces/ids.
  const params = (search ?? '').split('&').filter(Boolean).map(pair => pair.split('=')[0]).sort()
  return `${templated}${params.length ? '?' + params.join('&') : ''}`
}

function sortedUniqueStrings(value: unknown, nonce: string): string[] {
  if (!Array.isArray(value)) return []
  return [...new Set(value.filter((item): item is string => typeof item === 'string' && item.length > 0).map(item => normalizeDynamic(item, nonce)))].sort()
}

function impactDeltaKind(obs: Record<string, unknown> | null, hasPersistedDelta: boolean, hasProtectedDelta: boolean): string | null {
  if (typeof obs?.deltaKind === 'string' && obs.deltaKind.length > 0) return obs.deltaKind
  if (obs?.crossTenant === true) return 'cross_tenant'
  if (obs?.roleDifferential === true) return 'role_differential'
  if (obs?.repeatedTransition === true) return 'repeated_transition'
  if (hasProtectedDelta) return 'protected_field'
  if (Array.isArray(obs?.disclosureFields) && obs.disclosureFields.length > 0) return 'disclosure'
  if (obs?.activeMarkup === true) return 'active_markup'
  if (obs?.oobDelivered === true) return 'oob'
  if (obs?.fingerprint != null) return 'error_fingerprint'
  if (obs?.boolean != null || obs?.statusBoolean === true) return 'boolean_differential'
  if (obs?.timing != null) return 'timing'
  if (hasPersistedDelta) return 'persisted_delta'
  if (obs?.boundaryControlDenied === true || obs?.boundary === true) return 'boundary'
  return null
}

function compositeVerifiedEdgeKinds(
  obs: Record<string, unknown> | null,
  receipt: Record<string, unknown> | null,
  passed: boolean,
): string[] {
  if (Array.isArray(obs?.verifiedEdgeKinds)) {
    return obs.verifiedEdgeKinds.filter((k): k is string => typeof k === 'string' && k.length > 0).sort()
  }
  if (Array.isArray(obs?.verifiedEdges)) {
    return obs.verifiedEdges
      .map(asRecord)
      .filter((edge): edge is Record<string, unknown> => edge !== null && edge.verified !== false && typeof edge.kind === 'string' && edge.kind.length > 0)
      .map(edge => edge.kind as string)
      .sort()
  }
  if (passed && Array.isArray(receipt?.causalEdges)) {
    return receipt.causalEdges
      .map(asRecord)
      .filter((edge): edge is Record<string, unknown> => edge !== null && typeof edge.kind === 'string' && edge.kind.length > 0)
      .map(edge => edge.kind as string)
      .sort()
  }
  return []
}

export interface CausalFingerprint {
  kind: VerifyClaim['kind']
  method: string
  path: string
  status: number | null
  expectation: unknown
  observed: unknown
}

export function causalFingerprints(
  store: TranscriptStore,
  checks: readonly VerifyClaimCheck[],
  nonce: string,
): CausalFingerprint[] {
  return checks.map(check => {
    const claim = check.claim
    if (claim.kind === 'timing') {
      const first = store.get(claim.variantIds[0])
      return {
        kind: claim.kind,
        method: first?.request?.method ?? '',
        path: pathFingerprint(first?.request?.pathAndQuery),
        status: first?.response?.status ?? null,
        expectation: { maxPValue: claim.maxPValue ?? 0.05, minPairs: claim.minPairs ?? 5 },
        observed: normalizedValue({ separated: check.passed, separationBucket: Number((Number(check.observed?.separation ?? 0) >= 3)) }, nonce),
      }
    }
    if (claim.kind === 'impact') {
      const probe = store.get(claim.probeExchangeId)
      const obs = asRecord(check.observed)
      const statusCode = probe?.response?.status != null
        ? Number(probe.response.status)
        : (typeof obs?.statusCode === 'number' ? obs.statusCode : null)
      const changedFields = Array.isArray(obs?.changedFields)
        ? sortedUniqueStrings(obs.changedFields, nonce)
        : (Array.isArray(obs?.persisted) ? sortedUniqueStrings(obs.persisted, nonce) : [])
      const hasPersistedDelta = typeof obs?.hasPersistedDelta === 'boolean'
        ? obs.hasPersistedDelta
        : typeof obs?.persisted === 'boolean'
          ? obs.persisted
          : Array.isArray(obs?.persisted)
            ? obs.persisted.length > 0
            : changedFields.length > 0
      const hasProtectedDelta = typeof obs?.hasProtectedDelta === 'boolean'
        ? obs.hasProtectedDelta
        : (Array.isArray(obs?.protectedFields) ? obs.protectedFields.length > 0 : false)
      return {
        kind: claim.kind,
        method: probe?.request?.method ?? '',
        path: pathFingerprint(probe?.request?.pathAndQuery),
        status: statusCode,
        expectation: { impactClass: claim.impactClass, oracleEvents: [...(claim.oracleEvents ?? [])].sort() },
        observed: {
          passed: Boolean(check.passed),
          impactClass: claim.impactClass,
          changedFields,
          deltaKind: impactDeltaKind(obs, hasPersistedDelta, hasProtectedDelta),
          hasPersistedDelta,
          hasProtectedDelta,
          statusCode,
        },
      }
    }
    if (claim.kind === 'boundary') {
      const control = store.get(claim.controlExchangeId)
      const probe = store.get(claim.probeExchangeId)
      const obs = asRecord(check.observed)
      const controlStatus = control?.response?.status != null
        ? Number(control.response.status)
        : (typeof obs?.controlStatus === 'number' ? obs.controlStatus : null)
      const probeStatus = probe?.response?.status != null
        ? Number(probe.response.status)
        : (typeof obs?.probeStatus === 'number' ? obs.probeStatus : null)
      const actorRoleDiff = typeof obs?.actorRoleDiff === 'boolean'
        ? obs.actorRoleDiff
        : typeof obs?.actorDifferential === 'boolean'
          ? obs.actorDifferential
          : (control?.request?.personaHandle ?? null) !== (probe?.request?.personaHandle ?? null)
      return {
        kind: claim.kind,
        method: probe?.request?.method ?? '',
        path: pathFingerprint(probe?.request?.pathAndQuery),
        status: probeStatus,
        expectation: { boundaryClass: claim.boundaryClass },
        observed: {
          passed: Boolean(check.passed),
          boundaryClass: claim.boundaryClass,
          controlStatus,
          probeStatus,
          actorRoleDiff,
        },
      }
    }
    if (claim.kind === 'structural_diff') {
      const probe = store.get(claim.variantIds[0])
      return {
        kind: claim.kind,
        method: probe?.request?.method ?? '',
        path: pathFingerprint(probe?.request?.pathAndQuery),
        status: probe?.response?.status != null ? Number(probe.response.status) : null,
        expectation: { minRounds: claim.minRounds ?? 3, minDeltaTokens: claim.minDeltaTokens ?? 1 },
        observed: {
          passed: Boolean(check.passed),
          separated: Boolean(check.passed),
          minRounds: claim.minRounds ?? 3,
        },
      }
    }
    if (claim.kind === 'race') {
      const raceRecords = claim.exchangeIds
        .map(id => store.get(id))
        .filter((rec): rec is VerifyTranscriptRecord => rec !== undefined)
      const probe = raceRecords[0]
      const winningRecord = raceRecords.find(rec => {
        const s = rec.response?.status != null ? Number(rec.response.status) : null
        return s !== null && s >= 200 && s < 300
      }) ?? probe
      const obs = asRecord(check.observed)
      const succeededCount = typeof obs?.succeededCount === 'number'
        ? obs.succeededCount
        : Array.isArray(obs?.statuses)
          ? obs.statuses.filter(s => typeof s === 'number' && s >= 200 && s < 300).length
          : raceRecords.length > 0
            ? raceRecords.filter(rec => {
                const s = rec.response?.status != null ? Number(rec.response.status) : null
                return s !== null && s >= 200 && s < 300
              }).length
            : (typeof obs?.distinctOutcomes === 'number' ? obs.distinctOutcomes : 0)
      return {
        kind: claim.kind,
        method: winningRecord?.request?.method ?? '',
        path: pathFingerprint(winningRecord?.request?.pathAndQuery),
        status: winningRecord?.response?.status != null ? Number(winningRecord.response.status) : null,
        expectation: { mode: claim.mode ?? null, minDistinctOutcomes: claim.minDistinctOutcomes ?? 2 },
        observed: {
          passed: Boolean(check.passed),
          mode: claim.mode ?? (typeof obs?.mode === 'string' ? obs.mode : null),
          succeededCountBucket: succeededCount >= 2 ? '>=2' : succeededCount,
        },
      }
    }
    if (claim.kind === 'mfa') {
      const probe = store.get(claim.postChallengeExchangeId)
      return {
        kind: claim.kind,
        method: probe?.request?.method ?? '',
        path: pathFingerprint(probe?.request?.pathAndQuery),
        status: probe?.response?.status != null ? Number(probe.response.status) : null,
        expectation: { mfa: true },
        observed: normalizedValue(check.observed ?? { passed: check.passed }, nonce),
      }
    }
    if (claim.kind === 'composite_receipt') {
      const obs = asRecord(check.observed)
      const hostRec = claim.verificationId ? store.getCompositeVerification(claim.verificationId) : undefined
      const receipt = asRecord(claim.compositeReceipt)
      const terminalImpact = asRecord(receipt?.terminalImpact)
      const terminalHopId = typeof terminalImpact?.terminalHopId === 'string' ? terminalImpact.terminalHopId : null
      const hopsArr = Array.isArray(receipt?.hops) ? receipt.hops.map(asRecord).filter((h): h is Record<string, unknown> => h !== null) : []
      const termHopObj = (terminalHopId ? hopsArr.find(h => h.hopId === terminalHopId) : null) ?? hopsArr[hopsArr.length - 1] ?? null
      const termHopExIds = Array.isArray(termHopObj?.exchangeIds)
        ? termHopObj.exchangeIds.filter((id): id is string => typeof id === 'string' && id.length > 0)
        : []
      const termId = claim.terminalExchangeId ?? termHopExIds[termHopExIds.length - 1] ?? claim.exchangeIds[claim.exchangeIds.length - 1]
      const rawTerm = termId ? store.get(termId) : undefined
      const is2xxRec = (rec: VerifyTranscriptRecord | undefined): boolean => {
        const s = rec?.response?.status != null ? Number(rec.response.status) : null
        return s !== null && s >= 200 && s < 300
      }
      // For multi-exchange terminal hops (e.g., concurrent race bursts), the last exchange can be a
      // non-deterministic non-2xx loser on one run and a 2xx winner on the other; prefer the winning 2xx record.
      const term = (rawTerm && is2xxRec(rawTerm))
        ? rawTerm
        : (termHopExIds.map(id => store.get(id)).find(is2xxRec) ?? rawTerm)
      const terminalOracleFamily = typeof obs?.terminalOracleFamily === 'string'
        ? obs.terminalOracleFamily
        : (typeof terminalImpact?.oracleFamily === 'string' ? terminalImpact.oracleFamily : null)
      const hopCount = typeof obs?.hopCount === 'number'
        ? obs.hopCount
        : typeof hostRec?.hopCount === 'number'
          ? hostRec.hopCount
          : typeof claim.hopCount === 'number'
            ? claim.hopCount
            : (Array.isArray(receipt?.hops) ? receipt.hops.length : null)
      const verifiedEdgeKinds = compositeVerifiedEdgeKinds(obs, receipt, Boolean(check.passed))
      const modeBVerified = typeof obs?.modeBVerified === 'boolean'
        ? obs.modeBVerified
        : Boolean(check.passed && (hostRec?.replayMode ?? claim.replayMode ?? receipt?.replayMode) === 'one_shot_transcript')
      return {
        kind: claim.kind,
        method: term?.request?.method ?? '',
        path: pathFingerprint(claim.route ?? term?.request?.pathAndQuery),
        status: term?.response?.status != null ? Number(term.response.status) : null,
        expectation: {
          chainId: normalizeDynamic(claim.chainId, nonce),
          terminalVulnClass: claim.terminalVulnClass,
          hopCount: claim.hopCount ?? null,
          replayMode: claim.replayMode ?? 'fresh_clean_replay',
        },
        observed: {
          confirmed: Boolean(check.passed),
          terminalOracleFamily,
          hopCount,
          verifiedEdgeKinds,
          modeBVerified,
        },
      }
    }
    const record = store.get(claim.exchangeId)
    const expectation = (() => {
      switch (claim.kind) {
        case 'status': return claim.expected
        case 'header': return { name: claim.name.toLowerCase(), equals: claim.equals, matches: claim.matches, absent: claim.absent }
        case 'body_contains': return { absent: claim.absent, text: normalizeDynamic(claim.text, nonce) }
        case 'jsonpath': return { path: claim.path, equals: claim.equals, matches: claim.matches, exists: claim.exists }
        case 'css': return { selector: claim.selector, exists: claim.exists, count: claim.count, textEquals: claim.textEquals, textContains: claim.textContains }
        case 'dom_sentinel': return { sentinel: normalizeDynamic(claim.sentinel, nonce), mode: claim.mode ?? 'executed' }
        case 'oob': return { expectHit: claim.expectHit ?? true }
        default: return null
      }
    })()
    const observed = (() => {
      if (claim.kind === 'body_contains') {
        return { passed: Boolean(check.passed), absent: Boolean(claim.absent) }
      }
      if (claim.kind === 'jsonpath' && claim.equals === undefined) {
        const obs = asRecord(check.observed)
        const val = obs && 'value' in obs ? obs.value : check.observed
        return {
          passed: Boolean(check.passed),
          exists: val !== undefined && val !== null,
          valueType: val === null ? 'null' : Array.isArray(val) ? 'array' : typeof val,
        }
      }
      return normalizedValue(check.observed ?? null, nonce)
    })()
    return {
      kind: claim.kind,
      method: record?.request?.method ?? '',
      path: pathFingerprint(record?.request?.pathAndQuery),
      status: record?.response?.status ?? null,
      expectation: normalizedValue(expectation, nonce),
      observed,
    }
  })
}

