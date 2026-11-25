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
import { spawn } from 'node:child_process'
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { connect as h2Connect, constants as h2constants } from 'node:http2'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { lookup } from 'node:dns/promises'
import ipaddr from 'ipaddr.js'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import { buildPersonaHeader } from './persona-vault.ts'
import { redact } from './redact.ts'
import { structuralDiff, intersectStructuralDeltas } from './verify-support.ts'
import {
  assessBoundary,
  assessImpactEvidence,
  assessMarkupImpact,
  assessMfaBypass,
  assessStatusOnlyDivergence,
  classifyBoundaryClaim,
  classifyImpactDescriptor,
  isReadMethod,
  matchInjectionFingerprint,
  normalizeRole,
  parseRoleLabel,
  assessReadDisclosure,
} from './oracle-invariants.ts'
import type { AmbientAuth, BoundaryClass, ImpactClass, ImpactStep, ActorIdentity } from './oracle-invariants.ts'

// ---------------------------------------------------------------------------
// Constants shared with the container mount (worker-backend) and both SDKs.
// ---------------------------------------------------------------------------

export const VERIFY_RPC_CONTAINER_DIR = '/guardian-rpc'
export const VERIFY_RPC_SOCKET_NAME = 'verify.sock'
export const VERIFY_RPC_TOKEN_NAME = 'token'
export const VERIFY_RPC_CONTEXT_NAME = 'context.json'
export const VERIFY_RPC_SOCKET_ENV = 'GUARDIAN_RPC_SOCKET'
export const VERIFY_RPC_TOKEN_ENV = 'GUARDIAN_RPC_TOKEN_FILE'
export const VERIFY_RPC_CONTEXT_ENV = 'GUARDIAN_RPC_CONTEXT_FILE'
export const VERIFY_NONCE_ENV = 'GUARDIAN_VERIFY_NONCE'
export const VERIFY_RESULT_ENV = 'GUARDIAN_PROOF_RESULT_FILE'
export const VERIFY_RPC_HEADER = 'x-guardian-rpc-token'
export const VERIFY_NONCE_HEADER = 'x-guardian-verify-nonce'
export const VERIFY_RESULT_MARKER = 'GUARDIAN_PROOF_RESULT:'

const MAX_RPC_BODY_BYTES = 4 * 1024 * 1024
const MAX_RECORDED_BODY_BYTES = 512 * 1024
const MAX_TRANSCRIPT_EXCHANGES = 512
const MAX_CLAIMS = 64
const MAX_PATH_LENGTH = 8192
const MAX_HEADERS = 64
const MAX_HEADER_VALUE = 4096

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

export type VerifyExchangeOp = 'http' | 'http2' | 'browser' | 'oob' | 'transcript' | 'race'

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
  kind: 'oob-mint' | 'browser' | 'timing'
  token?: string
  url?: string
  dnsHost?: string
  hit?: boolean
  executedSentinels?: string[]
  domHtmlSha256?: string
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

export class TranscriptStore {
  private readonly secret: Buffer
  private readonly records = new Map<string, VerifyTranscriptRecord>()
  private readonly bodies = new Map<string, string>()
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
        status: record.response?.status != null && Number.isFinite(Number(record.response.status))
      ? Number(record.response.status)
      : null,
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
    return true
  }
}

// ---------------------------------------------------------------------------
// Claims + transcript oracle
// ---------------------------------------------------------------------------

export type VerifyClaim =
  | { kind: 'status'; exchangeId: string; expected: number | number[]; message?: string }
  | { kind: 'header'; exchangeId: string; name: string; equals?: string; matches?: string; absent?: boolean; message?: string }
  | { kind: 'body_contains'; exchangeId: string; text: string; absent?: boolean; message?: string }
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
      controlExchangeId: string
      probeExchangeId: string
      expectControlDenied?: boolean
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
// Assertion primitives (shared semantics with `worker/guardian_verify`).
// ---------------------------------------------------------------------------

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi
const LONG_HEX_RE = /\b[0-9a-f]{16,}\b/gi
const ISO_TS_RE = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?/g

/** Remove run-scoped nonces and standard dynamic tokens (for cross-attempt comparison). */
export function normalizeDynamic(input: string, nonce?: string): string {
  let out = input
  if (nonce) out = out.split(nonce).join('<nonce>')
  return out
    .replace(UUID_RE, '<uuid>')
    .replace(ISO_TS_RE, '<ts>')
    .replace(LONG_HEX_RE, '<hex>')
}

function asRecord(value: unknown): Record<string, unknown> | null {
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

function evaluateJsonPath(value: unknown, path: string): { found: boolean; value?: unknown; count?: number } {
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

function sameSiteFromRecord(record: VerifyTranscriptRecord | undefined): string | null {
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
  let json: unknown
  if (body !== undefined) {
    try { json = JSON.parse(body) } catch { json = undefined }
  }
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
    status: record.response?.status != null && Number.isFinite(Number(record.response.status))
      ? Number(record.response.status)
      : null,
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
  let json: unknown
  if (body !== undefined) {
    try { json = JSON.parse(body) } catch { json = undefined }
  }
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
    status: record.response?.status != null && Number.isFinite(Number(record.response.status))
      ? Number(record.response.status)
      : null,
    actor: {
      handle,
      role,
      tenant,
      auth: 'unknown',
      sameSite: null,
    },
    json,
    body: body ?? '',
    requestHeaders: record.request?.headers ?? null,
    responseHeaders: record.response?.headers ?? null,
  }
}

function evaluateBoundaryClaim(
  store: TranscriptStore,
  claim: Extract<VerifyClaim, { kind: 'boundary' }>,
  context: VerifyClaimContext,
): VerifyClaimCheck {
  const requireRecord = (id: string): VerifyTranscriptRecord | null => {
    if (context.allowedExchangeIds && !context.allowedExchangeIds.has(id)) return null
    return store.get(id) ?? null
  }
  if (!requireRecord(claim.controlExchangeId)) {
    return { claim, passed: false, detail: `Unknown control exchange ${claim.controlExchangeId} for a boundary claim.` }
  }
  if (!requireRecord(claim.probeExchangeId)) {
    return { claim, passed: false, detail: `Unknown probe exchange ${claim.probeExchangeId} for a boundary claim.` }
  }
  const control = transcriptBoundaryStep(store, claim, claim.controlExchangeId, 'control')
  const probe = transcriptBoundaryStep(store, claim, claim.probeExchangeId, 'probe')
  if (!control || !probe) {
    return { claim, passed: false, detail: 'Boundary claim references an unreadable exchange.' }
  }
  const assessment = assessBoundary({
    boundaryClass: claim.boundaryClass,
    impactClass: claim.boundaryClass === 'access' ? 'authorization' : 'other',
    steps: [control, probe],
    expectControlDenied: claim.expectControlDenied,
  })
  return {
    claim,
    passed: assessment.required && assessment.satisfied,
    detail: assessment.reason,
    observed: assessment.evidence,
  }
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
  return {
    claim,
    passed: assessment.required && assessment.satisfied,
    detail: assessment.reason,
    ...(assessment.evidence ? { observed: assessment.evidence } : {}),
  }
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
      status: record.response?.status != null && Number.isFinite(Number(record.response.status))
      ? Number(record.response.status)
      : null,
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
    if (claim.kind === 'timing') continue
    if (claim.kind === 'structural_diff') {
      for (const id of claim.controlIds) ids.add(id)
      for (const id of claim.variantIds) ids.add(id)
      continue
    }
    if (claim.kind === 'race') {
      for (const id of claim.exchangeIds) ids.add(id)
      continue
    }
    if (claim.kind === 'impact') continue
    if (claim.kind === 'boundary') {
      ids.add(claim.controlExchangeId)
      ids.add(claim.probeExchangeId)
      continue
    }
    if (claim.kind === 'mfa') {
      ids.add(claim.enrolledExchangeId)
      ids.add(claim.preChallengeExchangeId)
      ids.add(claim.postChallengeExchangeId)
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
function implicitReadDisclosure(
  store: TranscriptStore,
  claims: readonly VerifyClaim[],
  context: VerifyClaimContext,
): { satisfied: boolean; reason: string } {
  const steps: ImpactStep[] = []
  for (const id of claimedExchangeIds(claims)) {
    if (context.allowedExchangeIds && !context.allowedExchangeIds.has(id)) continue
    const record = store.get(id)
    if (!record) continue
    const body = store.body(id)
    let json: unknown
    if (body !== undefined) {
      try { json = JSON.parse(body) } catch { json = undefined }
    }
    const handle = record.request?.personaHandle ?? null
    steps.push({
      id,
      arm: (record.request?.sessionRole as ImpactStep['arm'] | null) ?? 'setup',
      method: (record.request?.method ?? 'GET').toUpperCase(),
      status: record.response?.status != null && Number.isFinite(Number(record.response.status))
      ? Number(record.response.status)
      : null,
      actor: {
        handle,
        role: normalizeRole(handle),
        tenant: parseRoleLabel(handle).tenant,
        auth: 'unknown',
        sameSite: null,
      },
      json,
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

function evaluateClaim(
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
        let re: RegExp
        try { re = new RegExp(claim.matches) } catch { return { claim, passed: false, detail: 'Invalid header regex.' } }
        const passed = re.test(value)
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
        let re: RegExp
        try { re = new RegExp(claim.matches) } catch { return { claim, passed: false, detail: 'Invalid jsonpath regex.' } }
        const passed = re.test(String(observed))
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
      // A changed token must be present in the same direction in every round: intersect alone can
      // keep tokens that rotate between two unrelated arms, so require the first arm's delta.
      return {
        claim,
        passed: distinct,
        detail: distinct
          ? `Structural differential: ${stableDelta.length} stable token(s) changed between arms (similarity ${cross.similarity.toFixed(3)}).`
          : `No stable structural differential: ${stableDelta.length} stable changed token(s), similarity ${cross.similarity.toFixed(3)}; ${cross.normalizedEqual ? 'the arms are identical after token stripping' : 'the delta is not stable across rounds'}.`,
        observed: {
          stableDelta: stableDelta.slice(0, 16),
          similarity: Number(cross.similarity.toFixed(4)),
          rounds: controls.length,
          stableControl: !unstableControl,
          stableVariant: !unstableVariant,
        },
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
    let json: unknown
    if (body) {
      try { json = JSON.parse(body) } catch { json = undefined }
    }
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
      status: record.response ? Number(record.response.status) : null,
      actor: {
        handle,
        role: normalizeRole(label ?? handle),
        tenant: parseRoleLabel(label ?? handle ?? '').tenant ?? null,
        auth: 'unknown',
        sameSite: null,
      },
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
  const impactBacked = checks.some(check =>
    check.passed && check.claim.kind === 'impact' &&
    (check.claim.impactClass === claimed ||
      ((claimed === 'bfla' || claimed === 'disclosure') && check.claim.impactClass === 'authorization')))
  if (claimed && claimed !== 'other' && !impactBacked) {
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
  if (claimedBoundary === 'mfa' && !mfaClaimPassed) {
    failures.push('boundary: MFA/2FA claim requires an `mfa` claim showing an enrolled account, a protected read denied/challenged before the code check, and the same actor granted the same resource after it; an OTP endpoint that returns {ok:true} without gating anything is advisory only.')
  }
  if (claimedBoundary === 'auth' && !boundaryClaimPassed) {
    failures.push('boundary: authentication/bypass claim requires a `boundary` claim over a denied/challenged control (401/403, login redirect or MFA challenge) and a variant that crosses it; a 2xx from an ungated request is not a bypass.')
  }
  if (claimedBoundary === 'access' && !boundaryClaimPassed && !impactBacked) {
    const disclosure = implicitReadDisclosure(store, claims, context)
    if (!disclosure.satisfied) {
      failures.push('boundary: access-control claim requires a denied/challenged control plus a crossing variant, or an actor/precondition differential backed by data/state evidence.')
    }
  }
  const failedCheck = checks.find(check => !check.passed) ?? null
  const missingEvidence = new Set<string>()
  for (const check of checks) for (const item of describeMissingEvidence(check)) missingEvidence.add(item)
  if (failures.some(failure => /impact: (?:authorization|disclosure) claim dismissed/.test(failure))) missingEvidence.add('owner_scoped_disclosure')
  if (failures.some(failure => /markup claim dismissed/.test(failure))) missingEvidence.add('executable_markup')
  if (failures.some(failure => /impact: .* requires a passing impact-evidence claim/.test(failure))) missingEvidence.add('impact_claim')
  if (failures.some(failure => /^boundary: authentication/.test(failure))) missingEvidence.add('boundary_claim')
  if (failures.some(failure => /^boundary: MFA/.test(failure))) missingEvidence.add('mfa_claim')
  if (failures.some(failure => /^boundary: access-control/.test(failure))) missingEvidence.add('boundary_or_disclosure')
  const rejectedBy = failedCheck
    ? failedCheck.claim.kind
    : failures.length > 0
      ? (failures.some(failure => failure.startsWith('boundary:')) ? 'boundary_gate' : failures.some(failure => failure.startsWith('impact:')) ? 'impact_gate' : 'oracle')
      : null
  return {
    passed: checks.length > 0 && failures.length === 0,
    checks,
    failures,
    transcriptDigest: store.digest(),
    rejectedBy,
    ...(failures.length > 0 ? { missingEvidence: [...missingEvidence] } : { missingEvidence: [] }),
    transcriptSummary: store.summaries(),
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

/** Path template so fresh-session ids do not break agreement. */
function pathFingerprint(path: string | undefined): string {
  if (!path) return ''
  const [pathname, search] = path.split('?')
  const templated = pathname.split('/').map((segment, index) => {
    if (index === 0 || segment === '') return segment
    if (/^\d+$/.test(segment) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(segment) || /^[a-z]{2,10}_[A-Za-z0-9]{8,}$/.test(segment)) return '*'
    return segment.toLowerCase()
  }).join('/')
  // Query parameter names are causal; values are usually nonces/ids.
  const params = (search ?? '').split('&').filter(Boolean).map(pair => pair.split('=')[0]).sort()
  return `${templated}${params.length ? '?' + params.join('&') : ''}`
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
      return {
        kind: claim.kind,
        method: probe?.request?.method ?? '',
        path: pathFingerprint(probe?.request?.pathAndQuery),
        status: probe?.response?.status != null ? Number(probe.response.status) : null,
        expectation: { impactClass: claim.impactClass, oracleEvents: [...(claim.oracleEvents ?? [])].sort() },
        observed: normalizedValue(check.observed ?? { passed: check.passed }, nonce),
      }
    }
    if (claim.kind === 'boundary') {
      const probe = store.get(claim.probeExchangeId)
      return {
        kind: claim.kind,
        method: probe?.request?.method ?? '',
        path: pathFingerprint(probe?.request?.pathAndQuery),
        status: probe?.response?.status != null ? Number(probe.response.status) : null,
        expectation: { boundaryClass: claim.boundaryClass },
        observed: normalizedValue(check.observed ?? { passed: check.passed }, nonce),
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
        observed: normalizedValue(check.observed ?? { passed: check.passed }, nonce),
      }
    }
    if (claim.kind === 'race') {
      const probe = store.get(claim.exchangeIds[0])
      return {
        kind: claim.kind,
        method: probe?.request?.method ?? '',
        path: pathFingerprint(probe?.request?.pathAndQuery),
        status: probe?.response?.status != null ? Number(probe.response.status) : null,
        expectation: { mode: claim.mode ?? null, minDistinctOutcomes: claim.minDistinctOutcomes ?? 2 },
        observed: normalizedValue(check.observed ?? { passed: check.passed }, nonce),
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
    return {
      kind: claim.kind,
      method: record?.request?.method ?? '',
      path: pathFingerprint(record?.request?.pathAndQuery),
      status: record?.response?.status ?? null,
      expectation: normalizedValue(expectation, nonce),
      observed: normalizedValue(check.observed ?? null, nonce),
    }
  })
}

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
}

interface RpcPayload {
  op?: string
  args?: Record<string, unknown>
}

export class VerifyRpcServer {
  readonly nonce: string
  readonly transcript: TranscriptStore
  private readonly options: VerifyRpcSessionOptions
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
    if (op === 'http') return this.handleHttp(args, nonce, 'http')
    if (op === 'http2') return this.handleHttp2(args, nonce)
    if (op === 'browser') return this.handleBrowser(args, nonce)
    if (op === 'oob') return this.handleOob(args)
    if (op === 'race') return this.handleRace(args, nonce)
    throw new Error(`Unsupported verification RPC operation: ${String(op)}`)
  }

  private handleTranscript(args: Record<string, unknown>): unknown {
    const action = typeof args.action === 'string' ? args.action : 'list'
    if (action === 'get') {
      const id = typeof args.exchangeId === 'string' ? args.exchangeId : ''
      const record = this.transcript.get(id)
      if (!record) throw new Error('Unknown exchange id.')
      return { record, body: this.transcript.body(id) ?? null, digest: this.transcript.digest(), signaturesValid: this.transcript.verifySignatures() }
    }
    if (action === 'digest') {
      return { digest: this.transcript.digest(), signaturesValid: this.transcript.verifySignatures(), count: this.transcript.size }
    }
    return {
      exchanges: this.transcript.summaries(),
      digest: this.transcript.digest(),
      signaturesValid: this.transcript.verifySignatures(),
      nonce: this.nonce,
      runId: this.options.runId,
    }
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
    if (typeof rawPath !== 'string' || !rawPath.startsWith('/') || rawPath.startsWith('//') || rawPath.length > MAX_PATH_LENGTH || /[\r\n\0]/.test(rawPath)) {
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
    const role = typeof args.sessionGroupRole === 'string' ? args.sessionGroupRole : undefined
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
    return out
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

  private exchangeView(record: VerifyTranscriptRecord, result: BrokerExchangeResult) {
    return this.scrubRecord({
      exchangeId: record.exchangeId,
      status: result.status,
      method: result.method,
      pathAndQuery: result.pathAndQuery,
      finalPathAndQuery: result.finalPathAndQuery,
      redirectOrigins: result.redirectOrigins,
      mediaType: result.mediaType,
      headers: result.respHeaders,
      body: result.body.slice(0, 512 * 1024),
      bodyPreview: result.bodyPreview,
      bodyBytes: result.bodyBytes,
      bodySha256: result.bodySha256,
      durationMs: result.durationMs,
      personaHandle: result.personaHandle,
    })
  }

  private async handleHttp(args: Record<string, unknown>, nonce: string, proto: 'http' | 'http2'): Promise<unknown> {
    const { brokerRequest, requestMeta } = this.parseHttpArgs(args)
    const started = Date.now()
    try {
      const result = await this.options.broker.executeHttp(brokerRequest, this.options.grant, AbortSignal.timeout(this.options.callTimeoutMs ?? 30_000))
      const body = this.scrub(result.body)
      const record = this.transcript.record({
        op: proto,
        startedAt: started,
        durationMs: result.durationMs,
        request: { ...requestMeta, nonce },
        response: {
          status: result.status,
          headers: this.scrubRecord(result.respHeaders),
          bodyBytes: result.bodyBytes,
          bodySha256: result.bodySha256,
          mediaType: result.mediaType,
          redirectOrigins: result.redirectOrigins,
          ...(result.finalPathAndQuery ? { finalPathAndQuery: result.finalPathAndQuery } : {}),
        },
        body,
      })
      return this.exchangeView(record, { ...result, body })
    } catch (error) {
      const record = this.transcript.record({
        op: proto,
        startedAt: started,
        durationMs: Date.now() - started,
        request: { ...requestMeta, nonce },
        error: error instanceof Error ? error.message : 'HTTP exchange failed.',
        errorCode: /scope|denied|approval|forbidden|outside|header/i.test(error instanceof Error ? error.message : '') ? 'denied' : 'failed',
      })
      throw new Error(`${record.exchangeId}: ${error instanceof Error ? error.message : 'HTTP exchange failed.'}`)
    }
  }

  private async handleHttp2(args: Record<string, unknown>, nonce: string): Promise<unknown> {
    const { brokerRequest, requestMeta } = this.parseHttpArgs(args)
    const started = Date.now()
    const signal = AbortSignal.timeout(this.options.callTimeoutMs ?? 30_000)
    try {
      const h2 = await this.executeHttp2(brokerRequest, signal)
      const body = this.scrub(h2.body)
      const record = this.transcript.record({
        op: 'http2',
        startedAt: started,
        durationMs: h2.durationMs,
        request: { ...requestMeta, nonce },
        response: {
          status: h2.status,
          headers: this.scrubRecord(h2.headers),
          bodyBytes: Buffer.byteLength(h2.body),
          bodySha256: createHash('sha256').update(body).digest('hex'),
          mediaType: h2.headers['content-type'] ?? 'application/octet-stream',
        },
        body,
      })
      return this.scrubRecord({
        exchangeId: record.exchangeId,
        status: h2.status,
        headers: h2.headers,
        body: body.slice(0, 512 * 1024),
        bodyBytes: Buffer.byteLength(h2.body),
        bodySha256: record.response?.bodySha256,
        durationMs: h2.durationMs,
        mediaType: record.response?.mediaType,
        protocol: 'h2',
      })
    } catch (error) {
      const record = this.transcript.record({
        op: 'http2',
        startedAt: started,
        durationMs: Date.now() - started,
        request: { ...requestMeta, nonce },
        error: error instanceof Error ? error.message : 'HTTP/2 exchange failed.',
        errorCode: /scope|denied|approval|forbidden|outside|header/i.test(error instanceof Error ? error.message : '') ? 'denied' : 'failed',
      })
      throw new Error(`${record.exchangeId}: ${error instanceof Error ? error.message : 'HTTP/2 exchange failed.'}`)
    }
  }

  /** HTTP/2 stays on the same grant: scope, persona injection, method approval. */
  private async executeHttp2(req: BrokerHttpRequest, signal: AbortSignal): Promise<{ status: number; headers: Record<string, string>; body: string; durationMs: number }> {
    const grant = this.options.grant
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
    const parsed = rawRequests.map((item, index) => {
      const record = asRecord(item)
      if (!record) throw new Error(`race request ${index + 1} must be an object.`)
      return this.parseHttpArgs({ sessionGroupRole: 'probe', ...record })
    })
    const mode = (() => {
      const summary = this.options.broker.getTransportSummary()
      return summary.http2 && !summary.proxy
        ? { mode: 'h2-single-packet' as const, fallbackReason: null as string | null }
        : { mode: 'http1-fallback' as const, fallbackReason: summary.proxy ? 'proxy transport disables the HTTP/2 single-packet barrier' : 'HTTP/2 transport is unavailable; the burst runs on the HTTP/1.1 fallback' }
    })()
    const started = Date.now()
    try {
      const burst = await this.options.broker.executeRaceBurst(
        parsed.map(item => item.brokerRequest),
        this.options.grant,
        AbortSignal.timeout(this.options.callTimeoutMs ?? 30_000),
      )
      const results = burst.results.map((result, index) => {
        const meta = parsed[index]!.requestMeta
        const body = this.scrub(result.body)
        const record = this.transcript.record({
          op: mode.mode === 'h2-single-packet' ? 'http2' : 'http',
          startedAt: started,
          durationMs: result.durationMs,
          request: { ...meta, nonce },
          response: {
            status: result.status,
            headers: this.scrubRecord(result.respHeaders),
            bodyBytes: result.bodyBytes,
            bodySha256: result.bodySha256,
            mediaType: result.mediaType,
          },
          body,
        })
        return this.exchangeView(record, { ...result, body })
      })
      return this.scrubRecord({
        mode: mode.mode,
        fallbackReason: mode.fallbackReason,
        summary: burst.summary,
        results,
      })
    } catch (error) {
      const record = this.transcript.record({
        op: 'race',
        startedAt: started,
        durationMs: Date.now() - started,
        request: { ...parsed[0]!.requestMeta, nonce },
        error: error instanceof Error ? error.message : 'Race burst failed.',
        errorCode: /scope|denied|approval|forbidden|outside|header|tier/i.test(error instanceof Error ? error.message : '') ? 'denied' : 'failed',
      })
      throw new Error(`${record.exchangeId}: ${error instanceof Error ? error.message : 'Race burst failed.'}`)
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
}

// ---------------------------------------------------------------------------
// Independent re-run: verifyScript()
// ---------------------------------------------------------------------------

export const GUARDIAN_VERIFY_STDERR_PREVIEW_MAX_CHARS = 400

export const GUARDIAN_VERIFY_USAGE_HINT =
  'Inline TS scripts receive `ctx` directly (no imports required): `await ctx.prove_access_boundary({ controlPersona, probePersona, route }); return ctx.result({ title: "..." })` (or `export default async (ctx) => { ... }`). Python `ctx.*` helpers are synchronous (no `await` needed).'

/** Strip accidental outer markdown code fences (```ts ... ``` / ```python ... ```) from LLM scripts. */
function stripCodeFences(rawCode: string): string {
  const trimmed = rawCode.trim()
  const match = /^```[a-zA-Z0-9_-]*[ \t]*\r?\n([\s\S]*?)\r?\n```$/.exec(trimmed)
  return match ? match[1]! : rawCode
}

/** Redact credential-shaped tokens and bound stderr preview to 400 chars for repair feedback. */
export function redactStderrPreview(raw: string, maxChars = GUARDIAN_VERIFY_STDERR_PREVIEW_MAX_CHARS): string {
  const cleaned = redact(raw ?? '').replace(/\u001b\[[0-9;]*m/g, '').trim()
  if (!cleaned) return ''
  return cleaned.length <= maxChars ? cleaned : `${cleaned.slice(0, Math.max(0, maxChars - 3))}...`
}

function normalizeTsSdkImports(code: string): string {
  return code
    .replace(/(\bfrom\s*)(['"])(?:\.\/)?guardian_verify(?:\.(?:ts|mts|js|mjs))?\2/g, "$1'./guardian_verify.ts'")
    .replace(/\bimport\(\s*(['"])(?:\.\/)?guardian_verify(?:\.(?:ts|mts|js|mjs))?\1\s*\)/g, "import('./guardian_verify.ts')")
}

function splitLeadingTsImports(code: string): { imports: string; body: string } {
  const lines = code.split(/\r?\n/)
  const importLines: string[] = []
  let i = 0
  let inBlockComment = false
  let inImport = false
  while (i < lines.length) {
    const line = lines[i]!
    const trimmed = line.trim()
    if (inImport) {
      importLines.push(line)
      if (/\bfrom\s*['"][^'"]+['"]\s*;?$/.test(trimmed) || /^import\s*['"][^'"]+['"]\s*;?$/.test(trimmed)) {
        inImport = false
      }
      i += 1
      continue
    }
    if (inBlockComment) {
      importLines.push(line)
      if (trimmed.includes('*/')) inBlockComment = false
      i += 1
      continue
    }
    if (!trimmed || trimmed.startsWith('//')) {
      importLines.push(line)
      i += 1
      continue
    }
    if (trimmed.startsWith('/*')) {
      importLines.push(line)
      if (!trimmed.includes('*/')) inBlockComment = true
      i += 1
      continue
    }
    if (/^import\s+(?!\()/.test(trimmed)) {
      importLines.push(line)
      const completeSingle = /\bfrom\s*['"][^'"]+['"]\s*;?$/.test(trimmed)
        || /^import\s*['"][^'"]+['"]\s*;?$/.test(trimmed)
        || /^import\s+\w+\s*=\s*require\(/.test(trimmed)
      if (!completeSingle) inImport = true
      i += 1
      continue
    }
    break
  }
  const hasRealImport = importLines.some(line => /^\s*import\s+(?!\()/.test(line))
  if (!hasRealImport) return { imports: '', body: code }
  return {
    imports: importLines.join('\n'),
    body: lines.slice(i).join('\n'),
  }
}

/**
 * Normalize an inline `guardian_verify` script so every documented authoring style works identically:
 *   1. Explicit `runVerification(...)` / `runEntrypoint(...)` / `GUARDIAN_PROOF_RESULT_FILE` -> run as-is (with SDK import paths normalized).
 *   2. `export default async (ctx) => ...` / `export default defineVerification(...)` / `export default { verify(ctx) {} }` -> invoke via `runEntrypoint`.
 *   3. Named `export async function verify(ctx)` / `async function verify(ctx)` -> invoke via `runEntrypoint`.
 *   4. Bare inline script body using `ctx` (`await ctx.prove_access_boundary(...)`) -> wrap in `runEntrypoint(async (ctx) => { ... })`.
 *   5. Standalone scripts without `ctx` (e.g. stdout-only or raw probes) -> run verbatim (fail closed as `claims_missing`).
 *
 * Idempotent: calling twice produces the exact same output. Never fabricates claims.
 */
export function prepareVerifyScript(rawCode: string, runtime: 'ts' | 'python', defaultTitle?: string): string {
  const unfenced = stripCodeFences(rawCode)
  const trimmed = unfenced.trim()
  if (!trimmed) return rawCode
  const titleLiteral = JSON.stringify(defaultTitle?.trim() || 'Verification script proof')

  if (runtime === 'python') {
    if (/\b(?:run|run_entrypoint|_guardian_run)\s*\(/.test(trimmed) || /\bGUARDIAN_PROOF_RESULT_FILE\b/.test(trimmed)) {
      return unfenced
    }
    if (/^[ \t]*(?:async\s+)?def\s+verify\s*\(/m.test(trimmed)) {
      return [
        unfenced,
        '',
        'from guardian_verify import run_entrypoint as _guardian_run',
        `_guardian_run(verify, setup=globals().get("setup"), cleanup=globals().get("cleanup"), default_title=${titleLiteral})`,
        '',
      ].join('\n')
    }
    if (/\bctx\b/.test(trimmed)) {
      const defPrefix = /\bawait\b/.test(trimmed) ? 'async def' : 'def'
      const indented = unfenced
        .split(/\r?\n/)
        .map(line => (line.trim() ? `    ${line}` : ''))
        .join('\n')
      return [
        'from guardian_verify import run_entrypoint as _guardian_run',
        '',
        `${defPrefix} _guardian_inline_verify(ctx):`,
        indented,
        '',
        `_guardian_run(_guardian_inline_verify, default_title=${titleLiteral})`,
        '',
      ].join('\n')
    }
    return unfenced
  }

  // TypeScript runtime
  const normalized = normalizeTsSdkImports(unfenced)
  if (
    /\b(?:runVerification|runEntrypoint|__guardian_run)\s*\(/.test(normalized)
    || /\bGUARDIAN_PROOF_RESULT_FILE\b/.test(normalized)
  ) {
    return normalized
  }

  const needsDefineAlias = /\bdefineVerification\s*\(/.test(normalized)
    && !/\bimport\b[^;]*\bdefineVerification\b/.test(normalized)
  const sdkImport = needsDefineAlias
    ? "import { defineVerification, runEntrypoint as __guardian_run } from './guardian_verify.ts'\n"
    : "import { runEntrypoint as __guardian_run } from './guardian_verify.ts'\n"

  const exportDefaultRe = /(^|;[ \t]*|\n[ \t]*)export\s+default\s+/
  if (exportDefaultRe.test(normalized)) {
    const rewritten = normalized.replace(exportDefaultRe, '$1const __guardian_default_export = ')
    return `${sdkImport}${rewritten}\n;\nawait __guardian_run(__guardian_default_export, ${titleLiteral})\n`
  }

  const hasExportVerify = /^[ \t]*export\s+(?:(?:async\s+)?function\s+verify\s*\(|(?:const|let|var)\s+verify\s*=)/m.test(normalized)
  const hasTopLevelVerify = /^[ \t]*(?:async\s+)?function\s+verify\s*\(/m.test(normalized)
  if (hasExportVerify || hasTopLevelVerify) {
    const hasSetup = /^[ \t]*(?:export\s+)?(?:(?:async\s+)?function\s+setup\s*\(|(?:const|let|var)\s+setup\s*=)/m.test(normalized)
    const hasCleanup = /^[ \t]*(?:export\s+)?(?:(?:async\s+)?function\s+cleanup\s*\(|(?:const|let|var)\s+cleanup\s*=)/m.test(normalized)
    const hooks = ['verify', ...(hasSetup ? ['setup'] : []), ...(hasCleanup ? ['cleanup'] : [])].join(', ')
    return `${sdkImport}${normalized}\n;\nawait __guardian_run({ ${hooks} }, ${titleLiteral})\n`
  }

  if (/\bctx\b/.test(normalized)) {
    const { imports, body } = splitLeadingTsImports(normalized)
    const prefix = imports ? `${sdkImport}${imports}\n` : sdkImport
    const bodyTrimmed = body.trim()
    // Standalone function expression (e.g. `async (ctx) => { ... }` or `async function(ctx) { ... }`)
    const isStandaloneFnExpr = /^(?:async\s+)?(?:\(\s*ctx\b[^)]*\)\s*=>|ctx\s*=>|function\s*(?:[A-Za-z_$][\w$]*)?\s*\(\s*ctx\b[^)]*\))/.test(bodyTrimmed)
    if (isStandaloneFnExpr) {
      const expr = bodyTrimmed.replace(/;\s*$/, '')
      return `${prefix}await __guardian_run((\n${expr}\n), ${titleLiteral})\n`
    }
    return `${prefix}await __guardian_run(async (ctx) => {\n${body}\n}, ${titleLiteral})\n`
  }

  return normalized
}

export interface VerificationCandidate {
  name: string
  runtime: 'ts' | 'python'
  code: string
  title?: string
}

export interface AttemptExecution {
  result: unknown
  stdout: string
  stderr: string
  exitCode: number
  durationMs: number
  timedOut?: boolean
}

export interface VerifyAttemptSession {
  nonce: string
  transcript: TranscriptStore
  execute(candidate: VerificationCandidate, signal: AbortSignal): Promise<AttemptExecution>
  close(): Promise<void>
}

export type VerifyReason =
  | 'confirmed'
  | 'execution_failed'
  | 'claims_missing'
  | 'claims_invalid'
  | 'oracle_failed'
  | 'transcript_mismatch'
  | 'nonce_reuse'
  | 'nonce_mismatch'

export interface VerifyAttemptReport {
  attempt: 1 | 2
  nonce: string
  exitCode: number
  durationMs: number
  oraclePassed: boolean
  failures: string[]
  claimCount: number
  exchangeCount: number
  transcriptDigest: string
  signaturesValid: boolean
  causal: CausalFingerprint[]
  title: string | null
  nonceMismatch: boolean
  /** First validator that rejected this attempt, so a repair can target it directly. */
  rejectedBy: string | null
  /** Exact missing transcript roles/preconditions. */
  missingEvidence: string[]
  /** Role-labelled transcript summary (control/probe/... ids, statuses, personas). */
  transcriptSummary: TranscriptSummary[]
  /** Last 2 KiB of redacted script stderr, useful when the helper throws before returning claims. */
  stderr?: string
}

export interface VerifyVerdict {
  confirmed: boolean
  reason: VerifyReason
  detail: string
  attempts: VerifyAttemptReport[]
  disagreements: string[]
  claimTitle: string | null
  rejectedBy: string | null
  missingEvidence: string[]
  transcriptSummary: TranscriptSummary[]
  /** Script exit code when the attempt failed or produced no valid proof document. */
  exitCode?: number
  /** Bounded, redacted first 400 chars of script stderr on execution/proof-document failure. */
  stderrPreview?: string
  /** Actionable 1-line usage hint surfaced on `claims_missing` / execution failure. */
  usageHint?: string
}

export interface VerifyScriptOptions {
  candidate: VerificationCandidate
  /** Must create a genuinely fresh session (new broker jars, new transcript) per attempt. */
  openAttempt: (input: { attempt: 1 | 2; nonce: string }) => Promise<VerifyAttemptSession>
  signal?: AbortSignal
  canary?: VerifyCanaryBroker
  timeoutMs?: number
}

function describeFingerprint(fingerprint: CausalFingerprint): string {
  return `${fingerprint.kind}|${fingerprint.method}|${fingerprint.path}|${fingerprint.status}|${JSON.stringify(fingerprint.expectation)}|${JSON.stringify(fingerprint.observed)}`
}

async function runAttempt(
  options: VerifyScriptOptions,
  attempt: 1 | 2,
  nonce: string,
): Promise<{ report: VerifyAttemptReport; fingerprints: string[] }> {
  const session = await options.openAttempt({ attempt, nonce })
  try {
    if (session.nonce !== nonce) {
      throw new Error('Attempt session did not adopt the freshly minted nonce.')
    }
    const timeout = AbortSignal.timeout(options.timeoutMs ?? 120_000)
    const deadline = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout
    const execution = await session.execute(options.candidate, deadline)
    const rawResultError = execution.result && typeof execution.result === 'object' && !Array.isArray(execution.result)
      && typeof (execution.result as { error?: unknown }).error === 'string'
      ? (execution.result as { error: string }).error
      : ''
    const rawStderr = execution.stderr.trim() ? execution.stderr : rawResultError
    const base = {
      attempt,
      nonce,
      exitCode: execution.exitCode,
      durationMs: execution.durationMs,
      exchangeCount: session.transcript.size,
      transcriptDigest: session.transcript.digest(),
      signaturesValid: session.transcript.verifySignatures(),
      title: null as string | null,
      causal: [] as CausalFingerprint[],
      oraclePassed: false,
      failures: [] as string[],
      claimCount: 0,
      nonceMismatch: false,
      rejectedBy: null as string | null,
      missingEvidence: [] as string[],
      transcriptSummary: session.transcript.summaries(),
      stderr: redact(rawStderr).slice(0, 2_000),
    }
    if (execution.timedOut) {
      return { report: { ...base, failures: ['Verification script timed out.'], rejectedBy: 'execution', missingEvidence: ['script_completion'] }, fingerprints: [] }
    }
    let parsed: VerifyScriptResult
    try {
      parsed = parseVerifyScriptResult(execution.result)
    } catch (error) {
      return { report: { ...base, failures: [error instanceof Error ? error.message : 'Invalid result.'], rejectedBy: 'claims', missingEvidence: ['valid_proof_document'] }, fingerprints: [] }
    }
    if (typeof parsed.nonce === 'string' && parsed.nonce !== nonce) {
      return {
        report: { ...base, title: parsed.title ?? null, claimCount: parsed.claims.length, nonceMismatch: true, failures: ['Proof document nonce does not match this attempt; a stale result was replayed.'], rejectedBy: 'nonce', missingEvidence: ['fresh_nonce'] },
        fingerprints: [],
      }
    }
    const descriptorText = `${parsed.title ?? ''} ${parsed.description ?? ''}`
    const declaredCwe = /\bCWE-\d{1,4}\b/i.exec(descriptorText)?.[0] ?? null
    const oracle = evaluateClaims(session.transcript, parsed.claims, {
      ...(options.canary ? { canary: options.canary } : {}),
      allowedExchangeIds: new Set(session.transcript.list().map(record => record.exchangeId)),
      claimedImpact: classifyImpactDescriptor({
        cwe: declaredCwe,
        title: parsed.title,
        description: parsed.description,
      }),
      claimedBoundary: classifyBoundaryClaim({ title: parsed.title }),
    })
    const causal = causalFingerprints(session.transcript, oracle.checks, nonce)
    const missingEvidence = oracle.missingEvidence ?? []
    const repairFeedback = oracle.passed ? [] : [
      `rejected-by: ${oracle.rejectedBy ?? 'unknown'}`,
      ...missingEvidence.map(item => `missing-evidence: ${item}`),
      ...session.transcript.summaries().slice(0, 16).map(entry =>
        `transcript-role: ${entry.role ?? 'setup'} ${entry.exchangeId} ${entry.method ?? '-'} ${entry.pathAndQuery ?? '-'} -> ${entry.status ?? 'error'}${entry.personaHandle ? ` persona=${entry.personaHandle}` : ''}`),
    ]
    return {
      report: {
        ...base,
        title: parsed.title ?? null,
        oraclePassed: oracle.passed,
        failures: [...oracle.failures, ...repairFeedback],
        claimCount: parsed.claims.length,
        causal,
        rejectedBy: oracle.rejectedBy ?? null,
        missingEvidence,
      },
      fingerprints: causal.map(describeFingerprint),
    }
  } finally {
    await session.close().catch(() => undefined)
  }
}

async function runAttemptSafe(
  options: VerifyScriptOptions,
  attempt: 1 | 2,
  nonce: string,
): Promise<{ report: VerifyAttemptReport; fingerprints: string[] }> {
  try {
    return await runAttempt(options, attempt, nonce)
  } catch (error) {
    return {
      report: {
        attempt,
        nonce,
        exitCode: 1,
        durationMs: 0,
        oraclePassed: false,
        failures: [error instanceof Error ? error.message : 'Verification attempt failed to start.'],
        claimCount: 0,
        exchangeCount: 0,
        transcriptDigest: '',
        signaturesValid: false,
        causal: [],
        title: null,
        nonceMismatch: false,
        rejectedBy: 'execution',
        missingEvidence: [error instanceof Error ? error.message.slice(0, 120) : 'attempt_start'],
        transcriptSummary: [],
      },
      fingerprints: [],
    }
  }
}

/**
 * Run the candidate twice from scratch with fresh nonces/sessions. Confirmation requires:
 *   1. both runs executed and returned claims,
 *   2. both transcript oracles passed (stdout is never evidence),
 *   3. both transcripts' signatures verify,
 *   4. the causal fingerprints agree across runs,
 *   5. the nonces differ and each proof document echoes its own attempt nonce.
 */
export async function verifyScript(options: VerifyScriptOptions): Promise<VerifyVerdict> {
  const nonces: [string, string] = [randomBytes(16).toString('hex'), randomBytes(16).toString('hex')]
  const first = await runAttemptSafe(options, 1, nonces[0])
  const second = await runAttemptSafe(options, 2, nonces[1])
  const attempts = [first.report, second.report]
  const detailBase = `first=${first.report.oraclePassed ? 'pass' : 'fail'} second=${second.report.oraclePassed ? 'pass' : 'fail'}`
  // The repair contract: name the rejecting validator, the exact missing evidence, and the
  // role-labelled transcript, so the agent can repair in one turn instead of guessing.
  const feedback = (includeScriptDiagnostics = false) => {
    const failed = attempts.filter(report => !report.oraclePassed)
    const source = failed.length > 0 ? failed : attempts
    const failingExit = source.find(report => report.exitCode !== 0)?.exitCode ?? source[0]?.exitCode
    const rawStderr = source.map(report => report.stderr ?? '').find(text => text.trim().length > 0) ?? ''
    const stderrPreview = redactStderrPreview(rawStderr)
    const showDiagnostics = includeScriptDiagnostics || (typeof failingExit === 'number' && failingExit !== 0) || stderrPreview.length > 0
    return {
      rejectedBy: source.find(report => report.rejectedBy !== null)?.rejectedBy ?? null,
      missingEvidence: [...new Set(source.flatMap(report => report.missingEvidence))],
      transcriptSummary: source[0]?.transcriptSummary ?? [],
      ...(showDiagnostics && typeof failingExit === 'number' ? { exitCode: failingExit } : {}),
      ...(showDiagnostics ? { stderrPreview } : {}),
      ...(includeScriptDiagnostics ? { usageHint: GUARDIAN_VERIFY_USAGE_HINT } : {}),
    }
  }
  const withFeedback = <T extends Omit<VerifyVerdict, 'rejectedBy' | 'missingEvidence' | 'transcriptSummary'>>(
    value: T,
    includeScriptDiagnostics = false,
  ): VerifyVerdict => ({ ...value, ...feedback(includeScriptDiagnostics) })

  if (first.report.nonce === second.report.nonce) {
    return withFeedback({ confirmed: false, reason: 'nonce_reuse', detail: 'Both attempts used the same nonce; sessions were not fresh.', attempts, disagreements: [], claimTitle: first.report.title })
  }
  if (attempts.some(a => a.nonceMismatch)) {
    return withFeedback({ confirmed: false, reason: 'nonce_mismatch', detail: 'A proof document did not match its fresh attempt nonce.', attempts, disagreements: [], claimTitle: first.report.title })
  }
  if (attempts.some(a => a.claimCount === 0)) {
    const diag = feedback(true)
    const suffix = diag.stderrPreview
      ? ` (exitCode=${diag.exitCode ?? 0}: ${diag.stderrPreview.slice(0, 200)})`
      : (typeof diag.exitCode === 'number' && diag.exitCode !== 0 ? ` (exitCode=${diag.exitCode})` : '')
    return withFeedback({
      confirmed: false,
      reason: 'claims_missing',
      detail: `At least one run returned no transcript-backed claims${suffix}.`,
      attempts,
      disagreements: [],
      claimTitle: first.report.title,
    }, true)
  }
  if (attempts.some(a => a.exitCode !== 0)) {
    const diag = feedback(true)
    const suffix = diag.stderrPreview ? `: ${diag.stderrPreview.slice(0, 200)}` : ''
    return withFeedback({
      confirmed: false,
      reason: 'execution_failed',
      detail: `A verification run exited non-zero (${detailBase}, exitCode=${diag.exitCode ?? 1}${suffix}).`,
      attempts,
      disagreements: [],
      claimTitle: first.report.title,
    }, true)
  }
  if (!attempts.every(a => a.signaturesValid)) {
    return withFeedback({ confirmed: false, reason: 'transcript_mismatch', detail: 'A transcript failed signature verification.', attempts, disagreements: [], claimTitle: first.report.title })
  }
  if (!attempts.every(a => a.oraclePassed)) {
    return withFeedback({
      confirmed: false,
      reason: 'oracle_failed',
      detail: `Claims did not survive transcript re-check (${detailBase}).`,
      attempts,
      disagreements: [],
      claimTitle: first.report.title,
    })
  }
  const disagreements: string[] = []
  if (first.fingerprints.length !== second.fingerprints.length) {
    disagreements.push(`claim count differs: ${first.fingerprints.length} vs ${second.fingerprints.length}`)
  }
  const max = Math.max(first.fingerprints.length, second.fingerprints.length)
  for (let i = 0; i < max; i += 1) {
    if (first.fingerprints[i] !== second.fingerprints[i]) {
      disagreements.push(`claim ${i + 1}: ${first.fingerprints[i] ?? '<missing>'} !== ${second.fingerprints[i] ?? '<missing>'}`)
    }
  }
  if (disagreements.length > 0) {
    return withFeedback({
      confirmed: false,
      reason: 'transcript_mismatch',
      detail: 'Both runs passed, but their transcripts disagree on the causal artifact.',
      attempts,
      disagreements,
      claimTitle: first.report.title,
    })
  }
  if (!first.report.title || !second.report.title || first.report.title !== second.report.title) {
    return withFeedback({
      confirmed: false,
      reason: 'transcript_mismatch',
      detail: 'Runs reported different proof titles.',
      attempts,
      disagreements: [`title: ${String(first.report.title)} vs ${String(second.report.title)}`],
      claimTitle: first.report.title,
    })
  }
  return withFeedback({
    confirmed: true,
    reason: 'confirmed',
    detail: `Both fresh runs passed the transcript oracle with identical causal artifacts (${detailBase}).`,
    attempts,
    disagreements: [],
    claimTitle: first.report.title,
  })
}

// ---------------------------------------------------------------------------
// Local (host-side) attempt factory + script runner
// ---------------------------------------------------------------------------

const RESULT_FILE_MAX_BYTES = 1024 * 1024
const SCRIPT_OUTPUT_MAX_BYTES = 512 * 1024

function copySdkFiles(sdkDir: string, targetDir: string) {
  if (!existsSync(sdkDir)) throw new Error('guardian_verify SDK directory is missing.')
  for (const file of ['guardian_verify.ts', 'guardian_verify.py']) {
    const source = join(sdkDir, file)
    if (!existsSync(source)) continue
    if (statSync(source).size > 256 * 1024) throw new Error('SDK file exceeds the size limit.')
    copyFileSync(source, join(targetDir, basename(file)))
    chmodSync(join(targetDir, basename(file)), 0o644)
  }
}

export interface LocalAttemptFactoryOptions {
  sdkDir: string
  createRpcOptions: (nonce: string, attempt: 1 | 2) => Omit<VerifyRpcSessionOptions, 'nonce'>
  nodePath?: string
  pythonPath?: string
  timeoutMs?: number
  /** Cap for stdout/stderr returned to the verifier (script stdout is never evidence anyway). */
  maxOutputBytes?: number
}

export function createLocalAttemptFactory(options: LocalAttemptFactoryOptions) {
  return async (input: { attempt: 1 | 2; nonce: string }): Promise<VerifyAttemptSession> => {
    const server = new VerifyRpcServer({ ...options.createRpcOptions(input.nonce, input.attempt), nonce: input.nonce })
    await server.start()
    return {
      nonce: input.nonce,
      transcript: server.transcript,
      async execute(candidate, signal) {
        return runCandidateLocally(candidate, {
          socketPath: server.socketPath,
          tokenPath: join(server.hostDir, VERIFY_RPC_TOKEN_NAME),
          contextPath: join(server.hostDir, VERIFY_RPC_CONTEXT_NAME),
          nonce: input.nonce,
          sdkDir: options.sdkDir,
          ...(options.nodePath ? { nodePath: options.nodePath } : {}),
          ...(options.pythonPath ? { pythonPath: options.pythonPath } : {}),
          ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}),
          ...(options.maxOutputBytes ? { maxOutputBytes: options.maxOutputBytes } : {}),
          signal,
        })
      },
      async close() {
        await server.close()
      },
    }
  }
}

export interface RunCandidateLocallyOptions {
  socketPath: string
  tokenPath: string
  contextPath: string
  nonce: string
  sdkDir: string
  nodePath?: string
  pythonPath?: string
  timeoutMs?: number
  maxOutputBytes?: number
  signal?: AbortSignal
}

export async function runCandidateLocally(
  candidate: VerificationCandidate,
  options: RunCandidateLocallyOptions,
): Promise<AttemptExecution> {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-verify-candidate-'))
  const resultPath = join(dir, 'result.json')
  try {
    copySdkFiles(options.sdkDir, dir)
    const extension = candidate.runtime === 'python' ? '.py' : '.ts'
    const scriptPath = join(dir, `candidate${extension}`)
    const preparedCode = prepareVerifyScript(candidate.code, candidate.runtime, candidate.title)
    writeFileSync(scriptPath, preparedCode, { mode: 0o600 })
    const command = candidate.runtime === 'python'
      ? (options.pythonPath ?? 'python3')
      : (options.nodePath ?? process.execPath)
    const args = candidate.runtime === 'python' ? ['-s', scriptPath] : [scriptPath]
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      [VERIFY_RPC_SOCKET_ENV]: options.socketPath,
      [VERIFY_RPC_TOKEN_ENV]: options.tokenPath,
      [VERIFY_RPC_CONTEXT_ENV]: options.contextPath,
      [VERIFY_NONCE_ENV]: options.nonce,
      [VERIFY_RESULT_ENV]: resultPath,
    }
    const started = Date.now()
    const outcome = await new Promise<{ code: number | null; stdout: string; stderr: string; timedOut: boolean }>((resolve, reject) => {
      const child = spawn(command, args, { cwd: dir, env, stdio: ['ignore', 'pipe', 'pipe'] })
      const maxBytes = options.maxOutputBytes ?? SCRIPT_OUTPUT_MAX_BYTES
      let stdout = ''
      let stderr = ''
      let timedOut = false
      const timer = setTimeout(() => {
        timedOut = true
        try { child.kill('SIGKILL') } catch { /* ignore */ }
      }, options.timeoutMs ?? 90_000)
      timer.unref()
      child.stdout?.on('data', (chunk: Buffer) => { if (stdout.length < maxBytes) stdout += chunk.toString('utf8').slice(0, maxBytes - stdout.length) })
      child.stderr?.on('data', (chunk: Buffer) => { if (stderr.length < maxBytes) stderr += chunk.toString('utf8').slice(0, maxBytes - stderr.length) })
      const abortHandler = () => { try { child.kill('SIGKILL') } catch { /* ignore */ } }
      options.signal?.addEventListener('abort', abortHandler, { once: true })
      child.once('error', error => { clearTimeout(timer); options.signal?.removeEventListener('abort', abortHandler); reject(error) })
      child.once('close', code => {
        clearTimeout(timer)
        options.signal?.removeEventListener('abort', abortHandler)
        resolve({ code, stdout, stderr, timedOut: timedOut || Boolean(options.signal?.aborted) })
      })
    })
    let result: unknown = null
    if (existsSync(resultPath)) {
      const raw = readFileSync(resultPath, 'utf8')
      if (Buffer.byteLength(raw) <= RESULT_FILE_MAX_BYTES) {
        try { result = JSON.parse(raw) } catch { result = null }
      }
    }
    return {
      result,
      stdout: outcome.stdout,
      stderr: outcome.stderr,
      exitCode: outcome.code ?? (outcome.timedOut ? 124 : 1),
      durationMs: Date.now() - started,
      ...(outcome.timedOut ? { timedOut: true } : {}),
    }
  } finally {
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
  }
}
