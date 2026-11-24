import { createHash, createHmac, randomBytes, randomInt, randomUUID } from 'node:crypto'
import { diffResponse, dnsTakeoverAnalyze } from '../../worker/analyzers.ts'
import { maxInlineVerifyRetries } from '../domain.ts'
import type { InlineVerifyFeedback, VerificationTier } from '../domain.ts'
import type { StateChangeApprovalContext } from './approval-judge.ts'
import {
  cacheBusterValueRegex,
  containsDestructivePayload,
  declarativeReplaySpecSchema,
  extractCacheBusterParam,
  floorRecipeEnvelopeSchema,
  replayAssertionOutcomeSchema,
  agentScriptProofEnvelopeSchema,
  replaySpecOrigins,
} from '../replay-spec.ts'
import type { AgentScriptProofEnvelope, AuthMutation, DeclarativeReplaySpec, FloorRecipeEnvelope, RaceBurstRequest, ReplayAssertionOutcome, ReplayStep } from '../replay-spec.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied, RequestBroker, websocketResultToExchange } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { personaSecrets } from './persona-vault.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import type { BrowserDomSinkTrace, BrowserInteractiveAction, BrowserSessionStep } from './scoped-browser.ts'
import { injectUniversalParam } from './surface-engine.ts'
import {
  awaitReplayCanary,
  intersectStructuralDeltas,
  openCanarySession,
  structuralDiff,
  structuralSimilarity,
} from './verify-support.ts'
import type { CanaryWaitOutcome, EphemeralCanarySession } from './verify-support.ts'
import type { Store } from './store.ts'
import type { WorkerBackend } from './worker-backend.ts'
import {
  actorFromPersona,
  assessAuthorizationImpact,
  assessBoundary,
  assessImpactEvidence,
  assessMassAssignmentImpact,
  assessMfaBypass,
  assessStatusOnlyDivergence,
  classifyBoundaryClaim,
  classifyImpactDescriptor,
  normalizeRole,
} from './oracle-invariants.ts'
import type { ActorIdentity, AmbientAuth, ImpactStep, PersonaCredentialSource } from './oracle-invariants.ts'
import { verifyReceipt } from './proof-receipt.ts'
import type { ProofReceipt, ReceiptTranscript, ReceiptTranscriptEntry, ReceiptVerification, ScriptProofExchange } from './proof-receipt.ts'
import { buildAgentScriptReceipt } from './proof-receipt.ts'
import { TranscriptStore, VerifyRpcServer, verifyScript } from './verify-rpc.ts'
import type { VerifyAttemptSession, VerifyVerdict } from './verify-rpc.ts'
import { wiredRecipeForSpecKind } from './floor-recipes.ts'
import { retestPersistedRecipe } from './floor-recipe-engine.ts'

// Re-exported for tests and callers that only import the verifier.
export {
  awaitReplayCanary,
  defaultReplayCanaryImmediateMs,
  intersectStructuralDeltas,
  normalizeStructuralTokens,
  structuralDiff,
  structuralSimilarity,
} from './verify-support.ts'
export type { CanaryWaitOutcome, ReplayCanaryWaitOptions, StructuralDiff } from './verify-support.ts'

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
  /**
   * v7 ProofReceipt check over the host-recorded transcript. Present whenever the replay could be
   * expressed as a receipt (impact or out-of-band). `mode` says whether the receipt was advisory
   * ('shadow') or gating ('strict'); see `proofReceiptMode`.
   */
  receipt?: ReplayReceiptCheck
}

export type ProofReceiptMode = 'off' | 'shadow' | 'strict'

/**
 * `GUARDIAN_PROOF_RECEIPT=off` restores the pure legacy DSL verdict, `shadow` (default) records the
 * receipt without changing a verdict, and `strict` makes `verifyReceipt` the final confirmation
 * gate. Strict is opt-in until parity across every suite is certified.
 */
export function proofReceiptMode(env: NodeJS.ProcessEnv = process.env): ProofReceiptMode {
  const raw = (env.GUARDIAN_PROOF_RECEIPT ?? '').trim().toLowerCase()
  if (raw === '0' || raw === 'off' || raw === 'false' || raw === 'no') return 'off'
  if (raw === 'strict' || raw === 'enforce' || raw === '1') return 'strict'
  return 'shadow'
}

export interface ReplayReceiptCheck {
  receipt: ProofReceipt
  verification: ReceiptVerification
  mode: Exclude<ProofReceiptMode, 'off'>
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
  evidence?: Record<string, unknown>
}

function normalizedReplayPath(value: string | undefined): string {
  if (!value) return ''
  return value.split('?')[0].split('#')[0].replace(/\/{2,}/g, '/').replace(/\/+$/, '').toLowerCase() || '/'
}

/**
 * Map recorded replay steps onto the shared evidence model. Role/tenant/auth metadata is enriched
 * into each step summary at record time (see `personaActorFields`), so the same validators can run
 * on a spec whose persona handles are opaque.
 */
export function impactStepsFromStepsOut(
  spec: DeclarativeReplaySpec,
  stepsOut: Record<string, unknown>,
): ImpactStep[] {
  if (spec.kind !== 'http_chain' && spec.kind !== 'auth_protocol_proof') return []
  return spec.steps.map(step => {
    const entry = stepsOut[step.id] as Record<string, unknown> | undefined
    const handle = (typeof entry?.personaHandle === 'string' ? entry.personaHandle : null) ?? step.request.persona ?? null
    const declaredRole = typeof entry?.actorRole === 'string' ? normalizeRole(entry.actorRole) : null
    let entryJson = entry?.json ?? null
    if (entryJson === null && typeof entry?.body === 'string') {
      // Unit-level callers may provide only the recorded body; parse it so the shared validators
      // see the same shape the wire recorder produces.
      try { entryJson = JSON.parse(entry.body) } catch { entryJson = null }
    }
    return {
      id: step.id,
      arm: step.role,
      method: step.request.method.toUpperCase(),
      route: normalizedReplayPath(step.request.pathAndQuery),
      pathAndQuery: step.request.pathAndQuery,
      status: typeof entry?.status === 'number' ? entry.status : null,
      actor: {
        handle,
        role: declaredRole ?? normalizeRole(step.request.persona),
        tenant: typeof entry?.actorTenant === 'string' ? entry.actorTenant : null,
        auth: (typeof entry?.ambientAuth === 'string' ? entry.ambientAuth : 'unknown') as AmbientAuth,
        sameSite: typeof entry?.sessionSameSite === 'string' ? entry.sessionSameSite : null,
      } satisfies ActorIdentity,
      json: entryJson,
      body: typeof entry?.body === 'string' ? entry.body : '',
      ...(Array.isArray(entry?.secretMatches)
        ? { secretMatches: (entry.secretMatches as Array<Record<string, unknown>>).map(match => String(match.sha256Prefix ?? '')).filter(Boolean) }
        : {}),
      requestJson: step.request.jsonBody,
      requestHeaders: step.request.headers ?? null,
      responseHeaders: (entry?.headers as Record<string, string> | undefined) ?? null,
    }
  })
}

/**
 * Vertical (function-level) BFLA needs *impact*, not just a 2xx from a lower-privileged actor.
 * A read-only route that every authenticated role may legitimately read must never confirm as
 * privilege escalation: the replay must show a role/tenant differential *and* a real side effect
 * (or an owner-scoped disclosure for reads). Object-level BOLA (CWE-639) is handled by the shared
 * impact gate, not here.
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
  const assessment = assessImpactEvidence({
    impactClass: 'bfla',
    steps: impactStepsFromStepsOut(spec, stepsOut),
    requiredRole: spec.requiredRole ?? null,
    resourceTenant: spec.resourceTenant ?? null,
    expectControlDenied: spec.expectControlDenied,
    oracleEvents: spec.expectedImpactEvents,
    targetOrigin: spec.origin,
  })
  return {
    required: true,
    satisfied: assessment.satisfied,
    reason: assessment.reason,
    ...(assessment.evidence ? { evidence: assessment.evidence } : {}),
  }
}

// ---------------------------------------------------------------------------
// v5.1 Slice 4 — proof-strength + endpoint-binding guards for LLM-authored
// http_chain specs. These guards are strictly additive: they can only turn a
// would-be confirmation into `inconclusive`, never the other way around.
// ---------------------------------------------------------------------------

type HttpChainSpec = Extract<DeclarativeReplaySpec, { kind: 'http_chain' }>

/** Vertical/horizontal authorization claims, identified by CWE or category only (never free text). */
const AUTHZ_CWE_RE = /^CWE-(?:269|284|285|566|639|862|863|1220)$/i
const AUTHZ_CATEGORY_RE = /(?:^|[-_\s])(?:broken[-_\s]?access[-_\s]?control|access[-_\s]?control|idor|bola|bfla|authori[sz]ation|privilege[-_\s]?escalation|tenant[-_\s]?isolation)(?:$|[-_\s])/i

function isAuthorizationClaim(spec: HttpChainSpec): boolean {
  return AUTHZ_CWE_RE.test(spec.cwe) || AUTHZ_CATEGORY_RE.test(spec.category)
}

export type HttpChainAssertionEvidence = 'status_only' | 'unbound_content' | 'content_bound'

/**
 * Classify what the jq assertion actually proves. `status_only` inspects nothing but status codes;
 * `unbound_content` reads a body/header without binding it to an identifier, extracted variable or
 * field comparison (a dynamic page differs on every request); `content_bound` compares structured
 * fields, extracted identifiers, canary/canary-fingerprint evidence or secret fingerprints.
 */
export function classifyHttpChainAssertion(program: string): HttpChainAssertionEvidence {
  const fields = new Set<string>()
  for (const match of program.matchAll(/\.steps\.[A-Za-z0-9_-]+\.([A-Za-z0-9_]+)/g)) {
    fields.add(match[1].toLowerCase())
  }
  const contentFields = [...fields].filter(field =>
    field !== 'status' && field !== 'statuses' && field !== 'id' && field !== 'role' && field !== 'batchcount')
  const topLevelProof = /\.(?:proofMatches|extractedVars|secretMatches|canary|cacheProof|uploadProof|cryptographicProofPassed)\b/.test(program)
  if (contentFields.length === 0) return topLevelProof ? 'content_bound' : 'status_only'
  if (fields.has('json') || fields.has('secretmatches')) return 'content_bound'
  const identifierBound = topLevelProof ||
    /\$[A-Za-z_][A-Za-z0-9_]*/.test(program) ||
    /\.(?:body|bodyPreview)\s*\|\s*(?:index|contains|startswith|endswith|test|match|capture|split|ltrimstr|rtrimstr)\s*\(/.test(program) ||
    /\b(?:index|contains|startswith|endswith)\s*\(\s*(?:"[^"]*"|\$[A-Za-z_])/.test(program)
  if (identifierBound) return 'content_bound'
  // A body/header byte-length differential is structural (a masked value cannot be longer than the
  // value it masks); any other unbound body/header read is only a "different body" observation.
  if (fields.has('bodybytes')) return 'content_bound'
  return 'unbound_content'
}

interface JsonFieldRef {
  stepId: string
  path: string[]
}

/** Extract `.steps.<id>.json.<field>` / `.json["field"]` references (bounded, no array indexes). */
function referencedJsonPaths(program: string): JsonFieldRef[] {
  const out: JsonFieldRef[] = []
  const seen = new Set<string>()
  const refPattern = /\.steps\.([A-Za-z0-9_-]+)\.json((?:\.[A-Za-z_][A-Za-z0-9_]*|\[(?:"[^"]{1,64}"|\d{1,3})\])+)/g
  for (const match of program.matchAll(refPattern)) {
    const segments = [...match[2].matchAll(/\[(?:"([^"]{1,64})"|\d{1,3})\]|\.([A-Za-z_][A-Za-z0-9_]*)/g)]
    if (segments.some(seg => seg[1] === undefined && seg[2] === undefined)) continue
    if (/\[\d{1,3}\]/.test(match[2])) continue
    const path = segments.map(seg => seg[1] ?? seg[2]).filter((seg): seg is string => Boolean(seg))
    if (path.length === 0) continue
    const key = `${match[1]}|${path.join('.')}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ stepId: match[1], path })
    if (out.length >= 24) break
  }
  return out
}

function readJsonField(json: unknown, path: readonly string[]): string | null {
  let cur: unknown = json
  for (const segment of path) {
    if (!cur || typeof cur !== 'object' || Array.isArray(cur)) return null
    cur = (cur as Record<string, unknown>)[segment]
  }
  if (cur === undefined || cur === null) return null
  return typeof cur === 'string' ? cur : JSON.stringify(cur)
}

/** Non-secret quoted literals used by the assertion, for identifier-bound marker disclosure checks. */
function jqStringLiterals(program: string): string[] {
  const out = new Set<string>()
  for (const match of program.matchAll(/"((?:[^"\\]|\\.){8,120})"/g)) {
    const value = match[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\')
    if (!value || /[\r\n\0]/.test(value)) continue
    if (/^(?:application\/json|content-type|content-security-policy)$/i.test(value)) continue
    out.add(value)
    if (out.size >= 8) break
  }
  return [...out]
}

function normalizeOriginValue(value: string | undefined): string {
  if (!value) return ''
  try {
    const url = new URL(value)
    return `${url.protocol}//${url.host.toLowerCase()}`
  } catch {
    return value.trim().toLowerCase().replace(/\/+$/, '')
  }
}

function originHost(value: string | undefined): string {
  try {
    return value ? new URL(value).host.toLowerCase() : ''
  } catch {
    return ''
  }
}

/** Route family: path only, lower-cased, trailing slash trimmed (query is compared separately). */
function routeKey(pathAndQuery: string | undefined): string {
  if (!pathAndQuery) return ''
  const pathOnly = pathAndQuery.split('?')[0].split('#')[0]
  const collapsed = pathOnly.replace(/\/{2,}/g, '/').replace(/\/+$/, '')
  return (collapsed || '/').toLowerCase()
}

interface HttpChainStepSnapshot {
  index: number
  id: string
  role: string
  method: string
  route: string
  pathAndQuery: string
  actor: string
  status: number | null
  body: string
  bodyBytes: number
  mediaType: string
  json: unknown
  secretMatches: number
}

function isSuccessStatus(status: number | null): boolean {
  return status !== null && status >= 200 && status < 300
}

function snapshotHttpChainSteps(
  spec: HttpChainSpec,
  stepsOut: Record<string, unknown>,
  stepExchanges: ReadonlyMap<string, BrokerExchangeResult[]>,
): HttpChainStepSnapshot[] {
  return spec.steps.map((step, index) => {
    const entry = (stepsOut[step.id] ?? {}) as Record<string, unknown>
    const exchange = stepExchanges.get(step.id)?.[0]
    const body = typeof entry.body === 'string' ? entry.body : ''
    const persona = step.request.persona ?? null
    const session = step.request.session ?? null
    return {
      index,
      id: step.id,
      role: step.role,
      method: step.request.method.toUpperCase(),
      route: routeKey(exchange?.pathAndQuery ?? step.request.pathAndQuery),
      pathAndQuery: exchange?.pathAndQuery ?? step.request.pathAndQuery,
      actor: persona ? `persona:${persona}` : session ? `session:${session}` : 'anonymous',
      status: typeof entry.status === 'number' ? entry.status : null,
      body,
      bodyBytes: typeof entry.bodyBytes === 'number' ? entry.bodyBytes : Buffer.byteLength(body, 'utf8'),
      mediaType: typeof entry.mediaType === 'string' ? entry.mediaType : '',
      json: entry.json ?? null,
      secretMatches: exchange?.secretMatches?.length ?? 0,
    }
  })
}

export type HttpChainDifferential =
  | 'denied_then_allowed'
  | 'cross_actor_access'
  | 'field_bound'
  | 'state_delta'
  | 'identifier_proof'
  | null

export interface HttpChainProofStrength {
  claim: 'authorization' | 'other'
  assertionEvidence: HttpChainAssertionEvidence
  differential: HttpChainDifferential
  satisfied: boolean
  reason: string
}

function detectHttpChainDifferential(
  spec: HttpChainSpec,
  snapshots: readonly HttpChainStepSnapshot[],
): HttpChainDifferential {
  const controls = snapshots.filter(step => step.role === 'control')
  const probes = snapshots.filter(step => step.role === 'probe')
  const dataBearing = (step: HttpChainStepSnapshot) => isSuccessStatus(step.status) && step.bodyBytes >= 8
  const sameRoute = (a: HttpChainStepSnapshot, b: HttpChainStepSnapshot) =>
    a.method === b.method && a.route === b.route && a.route !== ''
  const denied = (step: HttpChainStepSnapshot) => step.status === 401 || step.status === 403
  // A control that is bounced (login/SSO redirect) did not receive the resource either.
  const bounced = (step: HttpChainStepSnapshot) =>
    step.status !== null && step.status >= 300 && step.status < 400

  // 1. The same endpoint is denied to the control caller and served to the probe caller.
  if (probes.some(probe => dataBearing(probe) && controls.some(control => sameRoute(control, probe) && (denied(control) || bounced(control))))) {
    return 'denied_then_allowed'
  }

  // 2. A different actor reaches the exact endpoint the control actor reached.
  if (probes.some(probe => dataBearing(probe) && controls.some(control =>
    sameRoute(control, probe) && control.actor !== probe.actor && (isSuccessStatus(control.status) || denied(control))))) {
    return 'cross_actor_access'
  }

  // 3. A declared response field carries a different value for the probe than for the control.
  for (const ref of referencedJsonPaths(spec.assertionsJq)) {
    const probe = probes.find(step => step.id === ref.stepId && isSuccessStatus(step.status))
    if (!probe) continue
    const probeValue = readJsonField(probe.json, ref.path)
    if (probeValue === null) continue
    if (controls.some(control => control.status !== null && readJsonField(control.json, ref.path) !== probeValue)) {
      return 'field_bound'
    }
  }

  // 4. A privileged mutation succeeds and a later read observes the mutated state (or its removal).
  const mutatingProbe = probes.find(step => MUTATING_REPLAY_METHODS.has(step.method) && isSuccessStatus(step.status))
  if (mutatingProbe) {
    const reads = snapshots.filter(step => READ_ONLY_REPLAY_METHODS.has(step.method) && step.index !== mutatingProbe.index)
    const before = [...reads].reverse().find(step => step.index < mutatingProbe.index && isSuccessStatus(step.status) && step.bodyBytes > 0)
    const after = reads.find(step => step.index > mutatingProbe.index)
    if (before && after) {
      if ((after.status !== null && after.status >= 400) || (after.bodyBytes > 0 && after.body !== before.body)) {
        return 'state_delta'
      }
    }
  }

  // 5. Identifier-bound proof: pre-redaction secret fingerprints or an asserted marker observed only
  //    in the probe response.
  if (probes.some(step => isSuccessStatus(step.status) && step.secretMatches > 0)) return 'identifier_proof'
  const controlBodies = controls.map(step => step.body)
  for (const literal of jqStringLiterals(spec.assertionsJq)) {
    if (probes.some(step => step.body !== '' && step.body.includes(literal)) &&
        !controlBodies.some(body => body.includes(literal))) {
      return 'identifier_proof'
    }
  }

  return null
}

/**
 * Proof-strength gate for authorization `http_chain` specs. A status-only claim (or a bare
 * "the body differs" claim) is never a control-vs-probe differential, and a content assertion must
 * be backed by an observable differential in the recorded exchanges (denied-then-allowed,
 * cross-actor access, field-bound value change, state delta, or identifier-bound proof).
 */
export function assessHttpChainProofStrength(
  spec: HttpChainSpec,
  snapshots: readonly HttpChainStepSnapshot[],
): HttpChainProofStrength {
  const assertionEvidence = classifyHttpChainAssertion(spec.assertionsJq)
  // Universal status-only ban: a bare 2xx -> 4xx/5xx divergence can never confirm ANY class. The
  // injection/authz/redirect oracles still run afterwards; this is a floor, not a substitute.
  if (assertionEvidence === 'status_only') {
    const statusOnly = assessStatusOnlyDivergence(
      snapshots.map(snapshot => ({
        id: snapshot.id,
        arm: snapshot.role === 'probe'
          ? 'probe' as const
          : snapshot.role === 'control'
            ? 'control' as const
            : snapshot.role === 'cleanup'
              ? 'cleanup' as const
              : 'setup' as const,
        method: snapshot.method,
        route: snapshot.route,
        pathAndQuery: snapshot.pathAndQuery,
        status: snapshot.status,
        actor: actorFromPersona(snapshot.actor, []),
        json: snapshot.json,
        body: snapshot.body,
      })),
    )
    if (statusOnly.statusOnly) {
      return {
        claim: isAuthorizationClaim(spec) ? 'authorization' : 'other',
        assertionEvidence,
        differential: null,
        satisfied: false,
        reason: statusOnly.reason,
      }
    }
  }
  if (!isAuthorizationClaim(spec)) {
    return { claim: 'other', assertionEvidence, differential: null, satisfied: true, reason: 'Not an authorization claim.' }
  }
  if (assertionEvidence === 'status_only') {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential: null,
      satisfied: false,
      reason: 'Authorization claim is status-only: a 2xx status (or status equality) is not an access-control differential. Assert a cross-actor resource read, a field/identifier bound to the victim object, or a state delta.',
    }
  }
  // Canary / cryptographic proof is produced by the verifier itself (distinct control vs probe
  // tokens, non-destructive math), so it is already an identifier-bound execution differential.
  if (/\.(?:canary|proof)\b/.test(spec.assertionsJq)) {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential: 'identifier_proof',
      satisfied: true,
      reason: 'Authorization claim is bound to verifier-minted canary/cryptographic proof.',
    }
  }
  const differential = detectHttpChainDifferential(spec, snapshots)
  if (assertionEvidence === 'unbound_content' && differential !== 'state_delta' && differential !== 'field_bound') {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential,
      satisfied: false,
      reason: 'Authorization claim rests on a different-body observation without identifier binding; assert a field-bound value, extracted victim identifier, secret fingerprint, or state delta.',
    }
  }
  if (differential === null) {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential,
      satisfied: false,
      reason: 'Authorization claim has no genuine control-vs-probe differential in the recorded exchanges (no denied-then-allowed route, cross-actor access, field-bound change, or state delta).',
    }
  }
  return {
    claim: 'authorization',
    assertionEvidence,
    differential,
    satisfied: true,
    reason: `Authorization differential proven: ${differential}.`,
  }
}

export interface HttpChainEndpointBinding {
  bound: boolean
  verifiedEndpoint: { stepId: string; role: string; origin: string; method: string; pathAndQuery: string } | null
  declaredEndpoint: { stepId: string; origin: string; method: string; pathAndQuery: string } | null
  mismatches: Array<{ stepId: string; field: 'origin' | 'method' | 'redirectHost' | 'specOrigin'; declared: string; actual: string }>
  reason: string
}

/**
 * Mechanical endpoint/method binding: the verified endpoint is the *actual* probe exchange, not the
 * spec's claim. Any disagreement between the declared step request and the wire exchange, a redirect
 * that leaves the declared host, or a primary probe step targeting a different origin than the
 * finding origin, invalidates the confirmation.
 */
export function assessHttpChainEndpointBinding(
  spec: HttpChainSpec,
  stepRequests: ReadonlyMap<string, readonly BrokerHttpRequest[]>,
  stepExchanges: ReadonlyMap<string, readonly BrokerExchangeResult[]>,
): HttpChainEndpointBinding {
  const mismatches: HttpChainEndpointBinding['mismatches'] = []
  for (const step of spec.steps) {
    const requests = stepRequests.get(step.id) ?? []
    const exchanges = stepExchanges.get(step.id) ?? []
    for (const [idx, exchange] of exchanges.entries()) {
      const request = requests[Math.min(idx, Math.max(0, requests.length - 1))]
      if (!request) continue
      if (exchange.method.toUpperCase() !== request.method.toUpperCase()) {
        mismatches.push({ stepId: step.id, field: 'method', declared: request.method.toUpperCase(), actual: exchange.method.toUpperCase() })
      }
      if (normalizeOriginValue(exchange.origin) !== normalizeOriginValue(request.origin)) {
        mismatches.push({ stepId: step.id, field: 'origin', declared: normalizeOriginValue(request.origin), actual: normalizeOriginValue(exchange.origin) })
      }
    }
  }

  const primaryProbe = spec.steps.find(step => step.role === 'probe' && (stepExchanges.get(step.id)?.length ?? 0) > 0)
  const primaryExchange = primaryProbe ? stepExchanges.get(primaryProbe.id)?.[0] : undefined
  if (!primaryProbe || !primaryExchange) {
    return {
      bound: false,
      verifiedEndpoint: null,
      declaredEndpoint: null,
      mismatches,
      reason: 'No executed probe exchange is available to bind the finding endpoint.',
    }
  }

  const declaredEndpoint = {
    stepId: primaryProbe.id,
    origin: normalizeOriginValue(primaryProbe.request.origin),
    method: primaryProbe.request.method.toUpperCase(),
    pathAndQuery: primaryProbe.request.pathAndQuery,
  }
  const verifiedEndpoint = {
    stepId: primaryProbe.id,
    role: primaryProbe.role,
    origin: normalizeOriginValue(primaryExchange.origin),
    method: primaryExchange.method.toUpperCase(),
    pathAndQuery: primaryExchange.pathAndQuery,
  }

  if (normalizeOriginValue(spec.origin) !== declaredEndpoint.origin) {
    mismatches.push({ stepId: primaryProbe.id, field: 'specOrigin', declared: declaredEndpoint.origin, actual: normalizeOriginValue(spec.origin) })
  }
  const declaredHost = originHost(primaryProbe.request.origin)
  const finalHost = originHost(primaryExchange.finalOrigin)
  if (declaredHost && finalHost && declaredHost !== finalHost) {
    mismatches.push({ stepId: primaryProbe.id, field: 'redirectHost', declared: declaredHost, actual: finalHost })
  }

  if (mismatches.length > 0) {
    const first = mismatches[0]
    return {
      bound: false,
      verifiedEndpoint,
      declaredEndpoint,
      mismatches: mismatches.slice(0, 8),
      reason: first.field === 'specOrigin'
        ? `Finding origin ${normalizeOriginValue(spec.origin)} does not match the probe endpoint origin ${declaredEndpoint.origin} (step "${first.stepId}"); the verified exchange came from a different asset than the finding claims.`
        : first.field === 'redirectHost'
          ? `Probe step "${first.stepId}" redirected from ${first.declared} to ${first.actual}; the verified endpoint is not the declared asset.`
          : `Probe step "${first.stepId}" ${first.field} mismatch: declared ${first.declared}, exchanged ${first.actual}.`,
    }
  }

  return {
    bound: true,
    verifiedEndpoint,
    declaredEndpoint,
    mismatches: [],
    reason: `Verified ${verifiedEndpoint.method} ${verifiedEndpoint.origin}${verifiedEndpoint.pathAndQuery} from step "${verifiedEndpoint.stepId}".`,
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

/**
 * Map a replay spec onto a receipt class. Only classes whose evidence the receipt model can
 * re-derive in-process are returned; everything else stays on the legacy verdict (no invented
 * receipt rule keeps a confirmation alive).
 */
export function receiptVulnClassFor(spec: DeclarativeReplaySpec): string | null {
  const text = `${spec.cwe} ${spec.category} ${spec.title} ${spec.impact}`
  if (/CWE-918|\bssrf\b|server[- ]side request/i.test(text)) return 'ssrf'
  if (/CWE-611|\bxxe\b|external entit/i.test(text)) return 'xxe'
  if (spec.kind !== 'http_chain' && spec.kind !== 'auth_protocol_proof') return null
  return vulnClassForImpactClass(classifyImpactDescriptor({
    cwe: spec.cwe,
    category: spec.category,
    title: spec.title,
    impact: spec.impact,
  }))
}

function vulnClassForImpactClass(impactClass: string | null | undefined): string | null {
  switch (impactClass) {
    case 'authorization':
    case 'bola':
      return 'bola'
    case 'bfla': return 'bfla'
    case 'mass_assignment': return 'mass_assignment'
    case 'csrf': return 'csrf'
    case 'business_logic': return 'business_logic'
    case 'markup': return 'xss_stored'
    case 'disclosure': return 'info_disclosure'
    default: return null
  }
}

const replayCanaryTokenRe = /guardian-canary-[a-f0-9]{24}/i

/**
 * Build a ProofReceipt + transcript from a completed replay. The transcript is the host-recorded
 * evidence the verifier already produced (`stepsOut` + exchange ids); nothing is re-executed.
 * Returns null when the spec has no receipt representation.
 */
export function buildReplayReceipt(input: {
  spec: DeclarativeReplaySpec
  evidencePayload: Record<string, unknown>
  exchangeIds: readonly string[]
  exchanges: readonly BrokerExchangeResult[]
}): { receipt: ProofReceipt; transcript: ReceiptTranscript } | null {
  const impactGate = input.evidencePayload.impactGate as { required?: boolean } | undefined
  const evidenceClass = typeof input.evidencePayload.evidenceClass === 'string'
    ? input.evidencePayload.evidenceClass
    : null
  const vulnClass = vulnClassForImpactClass(evidenceClass) ?? receiptVulnClassFor(input.spec)
  if (!vulnClass) return null
  const isOob = vulnClass === 'ssrf' || vulnClass === 'xxe'
  // The DSL only confirms an impact claim when its shared oracle gate applies. Do not manufacture a
  // receipt for a class the replay never gated (auth-boundary, redirect, injection differentials):
  // those keep their existing evidence model instead of being downgraded by a rule they never had.
  if (!isOob && impactGate?.required !== true) return null
  const stepsOut = (input.evidencePayload.steps ?? {}) as Record<string, unknown>
  const steps = impactStepsFromStepsOut(input.spec, stepsOut)
  if (steps.length === 0 && vulnClass !== 'ssrf' && vulnClass !== 'xxe') return null
  const exchangeById = new Map<string, BrokerExchangeResult>()
  input.exchangeIds.forEach((id, index) => {
    const exchange = input.exchanges[index]
    if (exchange) exchangeById.set(id, exchange)
  })
  const entries: ReceiptTranscriptEntry[] = []
  const orderedIds: string[] = []
  for (const [index, step] of steps.entries()) {
    const recorded = stepsOut[step.id] as { exchangeId?: unknown } | undefined
    const id = typeof recorded?.exchangeId === 'string'
      ? recorded.exchangeId
      : input.exchangeIds[index] ?? `exchange-${index}`
    if (!id) continue
    const exchange = exchangeById.get(id)
    entries.push({
      exchangeId: id,
      step,
      ...(typeof (recorded as { durationMs?: unknown } | undefined)?.durationMs === 'number'
        ? { durationMs: (recorded as { durationMs: number }).durationMs }
        : {}),
      ...(exchange
        ? { carrierText: `${exchange.pathAndQuery}\n${JSON.stringify(exchange.reqHeaders ?? {})}\n${String(exchange.body ?? '').slice(0, 32 * 1024)}` }
        : {}),
    })
    orderedIds.push(id)
  }

  if (isOob) {
    const carrying = entries.find(entry => replayCanaryTokenRe.test(entry.carrierText ?? ''))
    if (!carrying) return null
    const token = replayCanaryTokenRe.exec(carrying.carrierText ?? '')![0]
    const receipt = {
      vulnClass,
      target: {
        origin: input.spec.origin,
        method: carrying.step.method.toUpperCase(),
        ...(carrying.step.pathAndQuery ? { pathAndQuery: carrying.step.pathAndQuery } : {}),
      },
      exchangeIds: [carrying.exchangeId],
      oobEventIds: ['replay-canary'],
      browserTraceIds: [],
      claimedDelta: `The target fetched the injected out-of-band canary after the ${vulnClass.toUpperCase()} probe.`,
    }
    const transcript: ReceiptTranscript = {
      entries: [carrying],
      oobEvents: [{
        id: 'replay-canary',
        callbackId: `replay:${carrying.exchangeId}`,
        token,
        targetOrigin: input.spec.origin,
        delivered: true,
        stage: 'immediate',
        receivedAtMs: Date.now(),
      }],
      browserTraces: [],
    }
    return { receipt: receipt as ProofReceipt, transcript }
  }

  if (orderedIds.length === 0) return null
  const targetExchangeStep = steps.find(step => step.arm === 'probe') ?? steps[0]
  const targetEntry = entries.find(entry => entry.step === targetExchangeStep) ?? entries[0]
  const receipt = {
    vulnClass,
    target: {
      origin: input.spec.origin,
      method: targetEntry.step.method.toUpperCase(),
      ...(targetEntry.step.pathAndQuery ? { pathAndQuery: targetEntry.step.pathAndQuery } : {}),
    },
    exchangeIds: orderedIds,
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: (input.spec.expectedImpactEvents ?? []).length
      ? `Replay observed the declared impact: ${(input.spec.expectedImpactEvents ?? []).join(', ')}.`
      : `Replay moved state across the ${vulnClass} boundary described by "${input.spec.title.slice(0, 120)}".`,
    ...(() => {
      const declared = ((input.spec as { expectedImpactEvents?: string[] }).expectedImpactEvents ?? []).slice()
      const csrfModelled = 'steps' in input.spec && Array.isArray(input.spec.steps) &&
        input.spec.steps.some(s => Boolean((s as { request?: { csrfBind?: unknown } }).request?.csrfBind))
      if (csrfModelled && !declared.includes('csrf_state_change')) declared.push('csrf_state_change')
      return declared.length ? { oracleEvents: declared } : {}
    })(),
    ...('proofPatterns' in input.spec && Array.isArray(input.spec.proofPatterns) && input.spec.proofPatterns.length
      ? { proofPatterns: input.spec.proofPatterns as string[] }
      : {}),
    ...('requiredRole' in input.spec && input.spec.requiredRole ? { requiredRole: input.spec.requiredRole } : {}),
    ...('resourceTenant' in input.spec && input.spec.resourceTenant ? { resourceTenant: input.spec.resourceTenant } : {}),
    ...('expectControlDenied' in input.spec && input.spec.expectControlDenied ? { expectControlDenied: true } : {}),
  }
  return { receipt: receipt as ProofReceipt, transcript: { entries } }
}

/**
 * Apply the receipt to a verdict. Shadow mode only annotates; strict mode can only downgrade a
 * confirmation (never promote one), so precision is monotonic.
 */
export function applyReceiptGate(input: {
  mode: ProofReceiptMode
  verdict: ReplayVerdict
  outcome: ReplayAssertionOutcome
  receipt: ProofReceipt
  verification: ReceiptVerification
}): { verdict: ReplayVerdict; outcome: ReplayAssertionOutcome; check?: ReplayReceiptCheck } {
  if (input.mode === 'off') return { verdict: input.verdict, outcome: input.outcome }
  const check: ReplayReceiptCheck = { receipt: input.receipt, verification: input.verification, mode: input.mode }
  if (input.mode === 'strict' && input.verdict === 'confirmed' && !input.verification.confirmed) {
    return {
      verdict: 'inconclusive',
      outcome: {
        ...input.outcome,
        confirmed: false,
        reason: `ProofReceipt rejected the confirmation: ${input.verification.reason}`.slice(0, 1200),
      },
      check,
    }
  }
  return { verdict: input.verdict, outcome: input.outcome, check }
}

function receiptCheckForResult(input: {
  mode: ProofReceiptMode
  verdict: ReplayVerdict
  outcome: ReplayAssertionOutcome
  spec: DeclarativeReplaySpec
  evidencePayload: Record<string, unknown>
  exchangeIds: readonly string[]
  exchanges: readonly BrokerExchangeResult[]
}): { verdict: ReplayVerdict; outcome: ReplayAssertionOutcome; check?: ReplayReceiptCheck } {
  if (input.mode === 'off' || input.verdict !== 'confirmed') return { verdict: input.verdict, outcome: input.outcome }
  const built = buildReplayReceipt({
    spec: input.spec,
    evidencePayload: input.evidencePayload,
    exchangeIds: input.exchangeIds,
    exchanges: input.exchanges,
  })
  if (!built) return { verdict: input.verdict, outcome: input.outcome }
  const verification = verifyReceipt(built.receipt, built.transcript)
  return applyReceiptGate({
    mode: input.mode,
    verdict: input.verdict,
    outcome: input.outcome,
    receipt: built.receipt,
    verification,
  })
}

async function verifyReplaySpecInner(params: VerifyReplaySpecParams): Promise<ReplayVerificationResult> {
  const { broker, backend, grant, signal } = params
  const assignmentId = params.assignmentId ?? randomUUID()
  const exchanges: BrokerExchangeResult[] = []
  const exchangeIds: string[] = []
  const recordExchange = (ex: BrokerExchangeResult): string | null => {
    exchanges.push(ex)
    const id = params.onExchange?.(ex)
    if (typeof id === 'string' && id) {
      exchangeIds.push(id)
      return id
    }
    return null
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
    // Reproduce the exact fingerprint a Tier-3 decision registers (origin/method/path/persona/body
    // hash + multipart/rce flags). Without context the one-shot ledger can never be consumed, and a
    // matching operator pattern would be the only way through — which must never authorize an
    // RCE/upload proof of execution, so both kinds are flagged `isRceProof`.
    //
    // Local-lab uploads short-circuit through the approval module's `local_lab` decision. A public
    // upload additionally needs the execution-side registration to carry `isRceProof: true` (the
    // multipart body is interpolated with a fresh nonce, so the broker must also key the grant to the
    // prepared parts); until then public uploads fail closed instead of accepting a pattern.
    const approvalContext: StateChangeApprovalContext = spec.kind === 'rce_proof'
      ? {
          personaHandle: spec.probeStep.request.persona ?? null,
          body: spec.probeStep.request.textBody ??
            (spec.probeStep.request.jsonBody !== undefined ? JSON.stringify(spec.probeStep.request.jsonBody) : null),
          hasMultipart: false,
          isRaceBurst: false,
          isRceProof: true,
        }
      : {
          personaHandle: spec.uploadStep.persona ?? null,
          body: spec.uploadStep.contentTemplate,
          hasMultipart: true,
          isRaceBurst: false,
          isRceProof: true,
        }
    const approved = approvalFn
      ? approvalFn(gateRequest.origin, gateRequest.method, gateRequest.pathAndQuery, approvalContext)
      : localLab
    if (!approved) {
      grant.audit('denied', gateRequest.origin)
      return inconclusiveResult(`${spec.kind} requires explicit Tier 3 HITL operator approval.`, exchanges, exchangeIds, { kind: spec.kind })
    }
  }
  const guardControlErrors = spec.requireControlNonError ?? defaultRequireControlNonError(spec)
  // Persona credential context for the shared impact validators (role label, tenant, ambient auth
  // and session-cookie SameSite). Built from the approved persona vault only; never from the spec.
  const personaSources: PersonaCredentialSource[] = [...(grant.personas?.values() ?? [])].map(persona => ({
    handle: persona.handle,
    roleLabel: persona.roleLabel,
    authKind: persona.authKind,
    headerType: persona.session?.headerType ?? null,
    cookies: (persona.session?.bundle?.cookies ?? []).map(cookie => ({ name: cookie.name, sameSite: cookie.sameSite ?? null })),
  }))
  const declaredActorRoles = spec.kind === 'http_chain' ? spec.actorRoles : undefined

  // 3. Fresh Replay Execution
  let evidencePayload: Record<string, unknown> = {
    kind: spec.kind,
    origin: spec.origin,
    replayedAt: new Date().toISOString(),
  }
  let forcedInconclusiveReason: string | null = null
  // Proof-strength / endpoint-binding failures are recorded separately: they only veto a spec that
  // WOULD confirm. A spec that already evaluates to confirmed=false must keep its dismissed/fixed
  // semantics (e.g. "Verify Fix" after a patch), so the guard never runs ahead of the assertion.
  let proofGuardFailure: string | null = null
  let deterministicProofPassed = true
  let proofFailureReason = ''

  try {
    if (spec.kind === 'http_chain') {
      const vars: Record<string, string> = {}
      const stepsOut: Record<string, unknown> = {}
      const probeStepExchanges: Array<{ id: string; exchange: BrokerExchangeResult }> = []
      // Mechanical endpoint binding: track the exact request that was sent per step (post-interpolation)
      // and every exchange it produced, then bind the finding to the wire evidence afterwards.
      const stepRequests = new Map<string, BrokerHttpRequest[]>()
      const stepExchanges = new Map<string, BrokerExchangeResult[]>()
      const rememberStep = (stepId: string, requests: BrokerHttpRequest[], produced: BrokerExchangeResult[]) => {
        stepRequests.set(stepId, requests)
        stepExchanges.set(stepId, produced)
      }
      const replayJarPrefix = randomUUID().slice(0, 8)
      let firstControlStep: Record<string, unknown> | undefined
      let firstProbeStep: Record<string, unknown> | undefined

      const actorContextFor = (step: ReplayStep): Record<string, unknown> => {
        const actor = actorFromPersona(step.request.persona ?? null, personaSources, { roles: declaredActorRoles ?? null })
        if (!actor.handle) return {}
        return {
          ...(actor.role ? { actorRole: actor.role } : {}),
          ...(actor.tenant ? { actorTenant: actor.tenant } : {}),
          ...(actor.auth !== 'unknown' ? { ambientAuth: actor.auth } : {}),
          ...(actor.sameSite ? { sessionSameSite: actor.sameSite } : {}),
        }
      }

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
            const batchExchangeIds = batchResults.map(ex => recordExchange(ex)).filter((id): id is string => Boolean(id))
            rememberStep(step.id, batchReqs, batchResults)
            const first = batchResults[0]
            if (first) extractVariables(step, first, vars)
            const stepEntry: Record<string, unknown> = {
              id: step.id,
              role: step.role,
              batchCount: batchResults.length,
              statuses: batchResults.map(r => r.status),
              responses: batchResults.map(summarizeExchange),
              ...(batchExchangeIds.length ? { exchangeIds: batchExchangeIds } : {}),
              ...(batchExchangeIds[0] ? { exchangeId: batchExchangeIds[0] } : {}),
              ...(first ? summarizeExchange(first) : {}),
              ...actorContextFor(step),
            }
            stepsOut[step.id] = stepEntry
            if (step.role === 'control' && !firstControlStep) firstControlStep = stepEntry
            if (step.role === 'probe') {
              if (!firstProbeStep) firstProbeStep = stepEntry
              if (first) probeStepExchanges.push({ id: step.id, exchange: first })
            }
          } else {
            const ex = await broker.executeHttp(brokerReq, grant, signal)
            const exchangeId = recordExchange(ex)
            rememberStep(step.id, [brokerReq], [ex])
            extractVariables(step, ex, vars)
            const stepEntry: Record<string, unknown> = {
              id: step.id,
              role: step.role,
              ...(exchangeId ? { exchangeId } : {}),
              ...summarizeExchange(ex),
              ...actorContextFor(step),
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
              // A control that is *supposed* to be denied (a cross-tenant boundary probe) is proof
              // of the boundary, not a spec error. Dropping it would leave the chain with only the
              // weaker arm, so it is tolerated when declared or when the probe arm on the same route
              // succeeded.
              if (step.role === 'control' && (status === 401 || status === 403 || status === 404)) {
                const probeSucceededOnRoute = spec.steps.some(other =>
                  other.role === 'probe' &&
                  routeKey(other.request.pathAndQuery) === routeKey(step.request.pathAndQuery) &&
                  isSuccessStatus(((stepsOut[other.id] as { status?: number } | undefined)?.status) ?? null))
                if (spec.expectControlDenied || probeSucceededOnRoute) continue
              }
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
          // Two-stage async correlation: durable pending_oob subscription, short immediate check,
          // then promoteLate/awaitAny up to the run deadline so worker callbacks still confirm.
          const probeWait = await canarySession.waitForCallback(prbCanary.token, signal)
          const controlCheck = canarySession.check(ctrlCanary.token)
          canaryEvidence = {
            proof: {
              canaryProbeTriggered: probeWait.triggered,
              canaryProbeStage: probeWait.stage,
              canaryProbePromoted: probeWait.promoted,
              ...(probeWait.subscriptionId ? { canarySubscriptionId: probeWait.subscriptionId } : {}),
              canaryControlTriggered: controlCheck.triggered,
              canaryProbeDetail: probeWait.detail,
              canaryControlDetail: controlCheck.detail,
            },
            canary: {
              triggered: probeWait.triggered && !controlCheck.triggered,
              probeTriggered: probeWait.triggered,
              controlTriggered: controlCheck.triggered,
              probeDetail: probeWait.detail,
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

        // Auto catch-all baseline: when the spec does not opt in to spaCatchallControl, a 2xx HTML
        // probe is still compared against a fresh unmatched-path baseline. If the probe is
        // indistinguishable from the catch-all, the claim is not tied to a real endpoint and the
        // verifier requires the explicit control (`spaCatchallControl: true`) to re-verify.
        let spaCatchallAuto: Record<string, unknown> | undefined
        if (!spec.spaCatchallControl) {
          const htmlProbes = probeStepExchanges.filter(probe =>
            probe.exchange.status >= 200 && probe.exchange.status < 300 && probe.exchange.mediaType.includes('html'))
          if (htmlProbes.length > 0) {
            const catchallPath = `/.guardian-nonexistent-${randomUUID()}`
            const catchallEx = await broker.executeHttp({
              origin: spec.origin,
              method: 'GET',
              pathAndQuery: catchallPath,
              followRedirects: true,
            }, grant, signal)
            recordExchange(catchallEx)
            const comparisons: Record<string, Record<string, unknown>> = {}
            let matchedProbes = 0
            for (const probe of htmlProbes) {
              const diff = diffResponse(
                { status: catchallEx.status, body: catchallEx.body, mediaType: catchallEx.mediaType },
                { status: probe.exchange.status, body: probe.exchange.body, mediaType: probe.exchange.mediaType },
              )
              comparisons[probe.id] = diff
              if (diff.likelySpaCatchall) matchedProbes += 1
            }
            spaCatchallAuto = {
              path: catchallPath,
              requiresControl: true,
              probeCount: htmlProbes.length,
              matchedProbes,
              ...summarizeExchange(catchallEx),
              comparisons,
            }
            if (matchedProbes === htmlProbes.length && !proofGuardFailure) {
              proofGuardFailure = 'Probe response is structurally indistinguishable from an HTTP 200 SPA catch-all route; set spaCatchallControl: true to verify against a real endpoint baseline.'
            }
          }
        }

        const bflaImpact = assessBflaImpact(spec, stepsOut)
        const stepSnapshots = snapshotHttpChainSteps(spec, stepsOut, stepExchanges)
        const proofStrength = assessHttpChainProofStrength(spec, stepSnapshots)
        const endpointBinding = assessHttpChainEndpointBinding(spec, stepRequests, stepExchanges)
        if (proofStrength.claim === 'authorization' && !proofStrength.satisfied && !proofGuardFailure) {
          proofGuardFailure = proofStrength.reason
        }
        if (!endpointBinding.bound && !proofGuardFailure) {
          proofGuardFailure = endpointBinding.reason
        }
        // Shared semantic impact gate for every class the differential machinery can over-claim:
        // horizontal authorization (read disclosure / persisted cross-tenant write), mass assignment,
        // CSRF, business-logic/workflow, markup/scripting and disclosure. Vertical BFLA is covered by
        // `assessBflaImpact` above (same validators). Unmodelled classes ('other') stay ungated; every
        // class the gate understands is gated regardless of actor count, so a single anonymous actor
        // cannot bypass the authorization read-disclosure check.
        const declaredImpactClass = classifyImpactDescriptor({
          cwe: spec.cwe,
          category: spec.category,
          title: spec.title,
          impact: spec.impact,
        })
        const impactSteps = impactStepsFromStepsOut(spec, stepsOut)
        // Evidence-first class: if the probe persisted a protected field from the request body, the
        // proof *is* mass assignment no matter how the model labelled it (the common K=6 case is a
        // `tenant_id` overpost reported as BOLA). This both gates and labels on what happened.
        const massAssignmentEvidence = declaredImpactClass === 'mass_assignment'
          ? null
          : assessMassAssignmentImpact({
              impactClass: 'mass_assignment',
              steps: impactSteps,
              oracleEvents: spec.expectedImpactEvents,
              targetOrigin: spec.origin,
            })
        const impactClass = massAssignmentEvidence?.required && massAssignmentEvidence.satisfied
          ? 'mass_assignment' as const
          : declaredImpactClass
        // Cross-tenant evidence is object-level authorization when the *probe* actor sits outside
        // the tenant that successfully read the same route (a victim control). A victim readback
        // after a mass-assignment write is not a cross-tenant probe.
        const probeStep = impactSteps.find(step => step.arm === 'probe') ?? null
        const controlReadTenants = new Set<string>()
        for (const step of impactSteps) {
          if (step.arm !== 'control') continue
          if (!/^(?:GET|HEAD|OPTIONS)$/i.test(step.method ?? '')) continue
          if (step.status === null || step.status < 200 || step.status >= 300) continue
          if (!probeStep || step.route !== probeStep.route) continue
          if (step.actor.tenant) controlReadTenants.add(step.actor.tenant)
        }
        const crossTenantEvidence = Boolean(probeStep?.actor.tenant && controlReadTenants.size > 0 &&
          !controlReadTenants.has(probeStep.actor.tenant))
        const evidenceClassLabel = crossTenantEvidence && (impactClass === 'authorization' || impactClass === 'business_logic')
          ? 'bola'
          : impactClass
        // A control arm that binds a CSRF token is the engine's declared anti-CSRF defence for the
        // route, equivalent to the route's `csrf_state_change` oracle. It is a requirement, not
        // evidence: the persisted readback is still demanded below.
        const declaredImpactEvents = spec.expectedImpactEvents ?? []
        const csrfModelled = impactClass === 'csrf' && spec.steps.some(step => Boolean(step.request.csrfBind))
        const oracleEvents = csrfModelled && !declaredImpactEvents.includes('csrf_state_change')
          ? [...declaredImpactEvents, 'csrf_state_change']
          : declaredImpactEvents
        const distinctActors = new Set(spec.steps.map(step => step.request.persona ?? step.request.session ?? 'anonymous'))
        const gateApplies = impactClass === 'mass_assignment' || impactClass === 'csrf' ||
          impactClass === 'business_logic' || impactClass === 'markup' || impactClass === 'disclosure' ||
          impactClass === 'injection' ||
          (impactClass === 'authorization' && (distinctActors.size > 1 || Boolean(spec.requiredRole) || Boolean(spec.resourceTenant)))
        const impactGate = !gateApplies
          ? null
          : assessImpactEvidence({
              impactClass,
              steps: impactSteps,
              requiredRole: spec.requiredRole ?? null,
              resourceTenant: spec.resourceTenant ?? null,
              expectControlDenied: spec.expectControlDenied,
              oracleEvents,
              targetOrigin: spec.origin,
              credentialPatterns: spec.proofPatterns ?? null,
            })
        // Universal default-deny boundary gate: auth/bypass claims always need a challenged control
        // (401/403, login redirect, MFA challenge, negative id) plus a crossing variant; access
        // claims may fall back to an explicit actor/precondition differential.
        const boundaryClass = classifyBoundaryClaim({
          cwe: spec.cwe,
          category: spec.category,
          title: spec.title,
          impact: spec.impact,
        })
        const boundaryGate = boundaryClass === 'other'
          ? null
          : boundaryClass === 'mfa'
            ? assessMfaBypass({
                impactClass,
                steps: impactSteps,
                requiredRole: spec.requiredRole ?? null,
                resourceTenant: spec.resourceTenant ?? null,
                oracleEvents,
                targetOrigin: spec.origin,
              })
            : assessBoundary({
                impactClass,
                steps: impactSteps,
                requiredRole: spec.requiredRole ?? null,
                resourceTenant: spec.resourceTenant ?? null,
                expectControlDenied: spec.expectControlDenied,
                oracleEvents,
                targetOrigin: spec.origin,
                boundaryClass,
              })
        if (impactGate?.required && !impactGate.satisfied && !proofGuardFailure) {
          proofGuardFailure = impactGate.reason
        }
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
          ...(spaCatchallAuto ? { spaCatchallAuto } : {}),
          bflaImpact,
          ...(impactGate ? { impactGate } : {}),
          // Verified evidence class: lets the host align a mislabelled finding (e.g. a tenant_id
          // overpost reported as BOLA is mass assignment) with what the proof actually showed.
          ...(impactGate?.required && impactGate.satisfied ? { evidenceClass: evidenceClassLabel } : {}),
          ...(boundaryGate ? { boundaryGate } : {}),
          proofStrength,
          endpointBinding,
        }
        if (bflaImpact.required && !bflaImpact.satisfied && !forcedInconclusiveReason) {
          forcedInconclusiveReason = bflaImpact.reason
        }
        if (impactGate?.required && !impactGate.satisfied && !proofGuardFailure) {
          // Vetoes only a would-be confirmation; a spec whose assertion already fails keeps its
          // dismissed/fixed semantics (Verify Fix must still report `fixed`).
          proofGuardFailure = impactGate.reason
        }
        if (boundaryGate?.required && !boundaryGate.satisfied && !proofGuardFailure) {
          proofGuardFailure = boundaryGate.reason
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
          // Durable pending_oob subscription + promotion instead of a fixed 1.5 s poll.
          const probeWait = await canarySession.waitForCallback(probeCanaryToken, signal)
          const controlCheck = canarySession.check(controlCanaryToken)
          deterministicProofPassed = probeWait.triggered && !controlCheck.triggered
          proofMeta.canaryProbeTriggered = probeWait.triggered
          proofMeta.canaryProbeStage = probeWait.stage
          proofMeta.canaryProbePromoted = probeWait.promoted
          proofMeta.canaryProbeDetail = probeWait.detail
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
      const roundDeltas: string[][] = []
      let firstBaseline: BrokerExchangeResult | undefined
      let firstTrue: BrokerExchangeResult | undefined
      let firstFalse: BrokerExchangeResult | undefined
      let allPass = true
      let baselineHeld = true
      let unstable = false
      let baselineDrift = false
      for (let r = 0; r < roundCount; r += 1) {
        signal.throwIfAborted()
        let k = randomInt(1000, 90_000)
        while (usedKs.has(k)) k = randomInt(1000, 90_000)
        usedKs.add(k)
        // Interleaved baseline / true / false triplet through RequestBroker.
        const trueValue = makeValue(k, 'true')
        const falseValue = makeValue(k, 'false')
        const baseEx = await broker.executeHttp(buildRequest(baseValue), grant, signal)
        recordExchange(baseEx)
        const trueEx = await broker.executeHttp(buildRequest(trueValue), grant, signal)
        recordExchange(trueEx)
        const falseEx = await broker.executeHttp(buildRequest(falseValue), grant, signal)
        recordExchange(falseEx)
        firstBaseline ??= baseEx
        firstTrue ??= trueEx
        firstFalse ??= falseEx
        // Compare noise-normalized structure: a rotating nonce never separates the arms, and a
        // single real field delta inside a large HTML shell remains observable. The echoed request
        // value is scrubbed from every side (same rule as the differential probe): a response that
        // reflects the query is not evidence that the returned rows changed.
        const diffBody = (body: string, values: string[]): string => {
          let out = body
          for (const value of values) {
            if (!value || value.length < 3) continue
            out = out.split(value).join('\u0000')
            const escaped = JSON.stringify(value).slice(1, -1)
            if (escaped && escaped !== value) out = out.split(escaped).join('\u0000')
          }
          return out
        }
        const baseDiffBody = diffBody(baseEx.body, [baseValue])
        const trueDiffBody = diffBody(trueEx.body, [trueValue, baseValue])
        const falseDiffBody = diffBody(falseEx.body, [falseValue, baseValue])
        const simBaselineTrue = structuralSimilarity(baseDiffBody, trueDiffBody)
        const simBaselineFalse = structuralSimilarity(baseDiffBody, falseDiffBody)
        const simTrueFalse = structuralSimilarity(trueDiffBody, falseDiffBody)
        const fieldDelta = structuralDiff(trueDiffBody, falseDiffBody).changedTokens.filter(token => token.length >= 2)
        roundDeltas.push(fieldDelta)
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
        if (structuralSimilarity(firstBaseline.body, baseEx.body) < 0.9) baselineDrift = true
        const baselineMatch = isOrBranch ? Math.max(simBaselineTrue, simBaselineFalse) >= 0.9 : simBaselineTrue >= 0.9
        if (!(!anyServerError && baselineMatch)) baselineHeld = false
        const pass = !anyServerError && baselineMatch && (simTrueFalse <= 0.75 || statusDivergence)
        if (!pass) allPass = false
        rounds.push({
          round: r + 1, k,
          trueExpression: `${k}=${k}`, falseExpression: `${k}=${k + 1}`,
          baseline: lightSummary(baseEx), true: lightSummary(trueEx), false: lightSummary(falseEx),
          similarityBaselineTrue: simBaselineTrue, similarityBaselineFalse: simBaselineFalse, similarityTrueFalse: simTrueFalse,
          statusDivergence, isOrBranch, structuralDelta: fieldDelta.length > 0, structuralChangedTokens: fieldDelta.length, pass,
        })
      }
      // A small set of non-dynamic tokens that differ in *every* round is a stable field delta,
      // not per-request jitter. This lets a one-field differential in a large shell confirm while
      // still requiring identical structural context.
      const stableFieldDelta = intersectStructuralDeltas(roundDeltas).filter(token => token.length >= 2)
      const structuralFieldDelta = stableFieldDelta.length > 0 && stableFieldDelta.length <= 8
      const controlPassed = controlHealthy && !unstable && !baselineDrift
      deterministicProofPassed = controlPassed && baselineHeld && (allPass || structuralFieldDelta)
      if (!deterministicProofPassed) {
        proofFailureReason = !controlPassed
          ? 'sql_boolean_diff control unstable (5xx, unexpected 404 or drifting baseline).'
          : 'Boolean differential did not hold across all 3 randomized rounds (no status divergence, content separation, or stable non-dynamic field delta).'
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
          thresholds: { trueVsBaselineMin: 0.9, trueVsFalseMax: 0.75, stableFieldDeltaMax: 8 },
          structuralFieldDelta,
          structuralChangedTokens: stableFieldDelta.length,
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
          const probeWait = await canarySession.waitForCallback(probeCanaryToken, signal)
          const controlCheck = canarySession.check(controlCanaryToken)
          deterministicProofPassed = probeWait.triggered && !controlCheck.triggered
          if (!deterministicProofPassed) {
            proofFailureReason = 'auth_protocol_proof OOB canary callback did not trigger exclusively on probe step.'
          }
          canaryProof = {
            probeTriggered: probeWait.triggered,
            probeStage: probeWait.stage,
            probePromoted: probeWait.promoted,
            controlTriggered: controlCheck.triggered,
            probeDetail: probeWait.detail,
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

        // Auth-protocol proofs are auth/bypass claims: they still need a denied/challenged control
        // (or, for MFA, the full enrolled + pre/post access differential).
        const authSteps = impactStepsFromStepsOut(spec, stepsOut)
        const authBoundaryClass = classifyBoundaryClaim({
          cwe: spec.cwe,
          category: spec.category,
          title: spec.title,
          impact: spec.impact,
        })
        const authBoundaryGate = authBoundaryClass === 'mfa'
          ? assessMfaBypass({ impactClass: 'other', steps: authSteps, targetOrigin: spec.origin })
          : authBoundaryClass === 'auth' || authBoundaryClass === 'access'
            ? assessBoundary({
                impactClass: 'other',
                steps: authSteps,
                boundaryClass: authBoundaryClass,
                expectControlDenied: spec.expectControlDenied,
                targetOrigin: spec.origin,
              })
            : null
        if (authBoundaryGate?.required && !authBoundaryGate.satisfied) {
          deterministicProofPassed = false
          proofFailureReason = authBoundaryGate.reason
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
          ...(authBoundaryGate ? { boundaryGate: authBoundaryGate } : {}),
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
      const simControlVsVerify = structuralSimilarity(controlEx.body, verifyEx.body)
      const simProbeVsVerify = structuralSimilarity(probeEx.body, verifyEx.body)

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
          ? grant.isStateChangeApproved(
              spec.targetOrigin,
              spec.method,
              spec.pathAndQuery,
              {
                personaHandle: spec.persona ?? null,
                // Spec-scoped approval: the pre-gate authorizes the declared request (the mutated
                // timing payloads are derived from it), so the fingerprint uses the declared body.
                body: spec.paramLocation === 'json' && spec.jsonBody !== undefined
                  ? JSON.stringify(spec.jsonBody)
                  : spec.paramLocation === 'xml'
                    ? spec.xmlTemplate ?? null
                    : null,
                hasMultipart: false,
                isRaceBurst: false,
                isRceProof: false,
              },
            )
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

  if (proofGuardFailure && outcome.controlPassed && outcome.confirmed) {
    return {
      verdict: 'inconclusive',
      outcome: {
        ...outcome,
        confirmed: false,
        reason: proofGuardFailure,
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

  // v7: one confirmation primitive. Shadow mode annotates the result for parity measurement;
  // strict mode lets the receipt veto a DSL confirmation (never widen it).
  const gated = receiptCheckForResult({
    mode: proofReceiptMode(),
    verdict,
    outcome,
    spec,
    evidencePayload,
    exchangeIds,
    exchanges,
  })

  return {
    verdict: gated.verdict,
    outcome: gated.outcome,
    exchangeIds,
    exchanges,
    evidencePayload,
    evidenceSha256,
    ...(gated.check ? { receipt: gated.check } : {}),
  }
}

export async function verifyReplaySpec(params: VerifyReplaySpecParams): Promise<ReplayVerificationResult> {
  const result = await verifyReplaySpecInner(params)
  return withVerificationTier(result)
}

/**
 * Cut 3a no-fallback invariant at the *product floor* boundary.
 *
 * The deterministic engine runs a wired family through its recipe; immediately before its legacy
 * verifier call it asserts the candidate was not recipe-wired. A future edit that bypasses planning
 * therefore throws (and warns) instead of silently evaluating the DSL for a family the floor is
 * supposed to confirm through a receipt.
 *
 * The legacy branch itself stays in `verifyReplaySpec` because, after the retest migration
 * (`retestReplaySpec` re-runs a persisted floor recipe and verifies a fresh receipt; the capability
 * harness retests through that same entrypoint), it still has reachable callers:
 *
 *   1. `Execution`'s agent-facing `verify_replay_spec` / `propose_chain_finding` path
 *      (`execution.ts` -> `verifyReplaySpec`), which accepts any of the 14 declarative kinds from the
 *      investigator. This is the dominant caller and the reason the DSL cannot be deleted yet:
 *      `guardian_verify` script confirmation is not wired into `AgentSession` in production.
 *   2. The deterministic engine's still-unwired kinds, recorded in `LEGACY_UNWIRED_SPECKINDS`.
 *   3. `retestReplaySpec`'s legacy fallback for a persisted spec with no recipe envelope (an
 *      agent-authored proof, or a row written before Cut 3).
 *
 * Deleting the VM therefore needs (1) to move to Layer-3 script proofs first.
 */
export class RecipeWiredLegacyCallError extends Error {
  readonly code = 'GUARDIAN_RECIPE_WIRED_LEGACY_CALL'
  readonly specKind: string
  readonly vulnClass: string

  constructor(specKind: string, vulnClass: string) {
    super(`verifyReplaySpec() received a recipe-wired spec kind ${specKind}/${vulnClass}; the floor must confirm it through its ProofReceipt recipe, not the legacy DSL verifier.`)
    this.name = 'RecipeWiredLegacyCallError'
    this.specKind = specKind
    this.vulnClass = vulnClass
  }
}

/** The class a spec claims, in the vocabulary the recipe table uses. */
export function recipeClassOfSpec(spec: DeclarativeReplaySpec): string | null {
  switch (spec.kind) {
    case 'sql_boolean_diff':
    case 'sql_time_diff':
      return 'sqli'
    case 'race_burst':
      return 'race_double_spend'
    case 'http_chain':
      return typeof spec.category === 'string' ? spec.category : null
    default:
      return null
  }
}

/** Throw (and warn) when a wired pair would be routed to the legacy verifier. */
export function assertNotRecipeWiredLegacyCall(spec: DeclarativeReplaySpec | unknown): void {
  if (!spec || typeof spec !== 'object') return
  const kind = (spec as { kind?: unknown }).kind
  if (typeof kind !== 'string') return
  const vulnClass = recipeClassOfSpec(spec as DeclarativeReplaySpec)
  const recipe = vulnClass ? wiredRecipeForSpecKind(kind, vulnClass) : null
  if (!recipe) return
  const error = new RecipeWiredLegacyCallError(kind, vulnClass ?? 'unknown')
  process.emitWarning(error.message, { code: error.code })
  throw error
}

function withVerificationTier(result: ReplayVerificationResult): ReplayVerificationResult {
  const verificationTier: VerificationTier | undefined = result.verdict === 'static_verified'
    ? 'static_verified'
    : result.verdict === 'confirmed' ? 'runtime_confirmed' : undefined
  return { ...result, ...(verificationTier ? { verificationTier } : {}) }
}

export async function retestReplaySpec(params: VerifyReplaySpecParams): Promise<RetestReplayResult> {
  // Cut 3 retest receipts: a spec confirmed by a typed floor recipe carries that recipe, so retest
  // re-runs the recipe and validates a fresh ProofReceipt. The legacy re-interpretation below is only
  // for proofs that were never recipe-owned (LLM-authored specs and still-unwired kinds).
  const persisted = persistedRecipeOf(params.spec)
  if (persisted) {
    const args = persisted.envelope.args as { vulnClass?: unknown; pathAndQuery?: unknown }
    const result = await retestPersistedRecipe({
      envelope: persisted.envelope,
      specKind: persisted.kind,
      vulnClass: typeof args.vulnClass === 'string' && args.vulnClass ? args.vulnClass : persisted.kind,
      endpoint: typeof args.pathAndQuery === 'string' ? args.pathAndQuery : persisted.origin,
      origin: persisted.origin,
      broker: params.broker,
      grant: params.grant,
      signal: params.signal,
      ...(params.runId ? { runId: params.runId } : {}),
      ...(params.assignmentId ? { assignmentId: params.assignmentId } : {}),
      ...(params.onExchange
        ? { recordExchange: (exchange: BrokerExchangeResult) => params.onExchange?.(exchange) }
        : {}),
    })
    return { verdict: result.verdict, replay: result.replay }
  }
  // v7 M5 agent script proofs: the persisted row carries the Layer-3 script, so retest re-runs that
  // script through the same fresh-session double-run and re-validates a fresh receipt. The
  // declarative shape on the row is attribution only and is never re-interpreted.
  const agentScript = persistedAgentScriptOf(params.spec)
  if (agentScript) {
    return retestPersistedAgentScript(agentScript.envelope, { ...params, origin: agentScript.origin } as VerifyReplaySpecParams & { origin?: string })
  }
  // Retest is a regression replay of an already-persisted proof (reproduced vs fixed), not a new
  // confirmation, so it re-evaluates the recorded spec through the same replay used today.
  const replay = await verifyReplaySpec(params)
  const verdict: RetestVerdict = replay.verdict === 'confirmed' || replay.verdict === 'static_verified'
    ? 'reproduced'
    : replay.verdict === 'dismissed'
      ? 'fixed'
      : 'inconclusive'
  return { verdict, replay }
}

/** Read the persisted agent-script envelope from a (not-yet-validated) spec. */
export function persistedAgentScriptOf(spec: unknown): { envelope: AgentScriptProofEnvelope; origin: string } | null {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return null
  const record = spec as Record<string, unknown>
  const parsed = agentScriptProofEnvelopeSchema.safeParse(record.agentScript)
  if (!parsed.success) return null
  return { envelope: parsed.data, origin: typeof record.origin === 'string' ? record.origin : '' }
}

// ---------------------------------------------------------------------------
// Agent script proof runner (v7 M5)
//
// One place that runs a Layer-3 `guardian_verify` script for production: every attempt opens a real
// worker session with the attempt's RPC directory mounted, so the script runs in the air-gapped
// sandbox and its HTTP/browser/OOB calls cross the Layer-1 grant. The transcript stays host-side.
// ---------------------------------------------------------------------------

export interface AgentScriptProofParams {
  script: string
  runtime: 'ts' | 'python'
  title?: string
  broker: RequestBroker
  grant: Grant
  backend: WorkerBackend
  runId: string
  assignmentId: string
  targetOrigins: readonly string[]
  signal: AbortSignal
  timeoutMs?: number
  canaryBroker?: CanaryBroker
}

export interface AgentScriptProofResult {
  verdict: VerifyVerdict
  /** Host-recorded exchanges of the last passing attempt (empty when no attempt passed). */
  exchanges: ScriptProofExchange[]
  /** Present only when the claims map onto a receipt rule AND `verifyReceipt` confirms it. */
  receipt: { receipt: ProofReceipt; verification: ReceiptVerification } | null
  vulnClass: string | null
  transcriptDigests: string[]
  /** Script-declared attribution (never evidence by itself). */
  claimTitle: string | null
  severity: string | null
  description: string | null
}

export async function runAgentScriptProof(params: AgentScriptProofParams): Promise<AgentScriptProofResult> {
  const code = params.script.trim()
  if (!code) throw new Error('An agent proof script is required.')
  if (Buffer.byteLength(code) > 64 * 1024) throw new Error('The agent proof script exceeds the 64 KiB limit.')
  const attempts = new Map<1 | 2, {
    claims: Record<string, unknown>[]
    transcript: TranscriptStore
    title: string | null
    severity: string | null
    description: string | null
  }>()
  const openAttempt = async (input: { attempt: 1 | 2; nonce: string }): Promise<VerifyAttemptSession> => {
    const server = new VerifyRpcServer({
      broker: params.broker,
      grant: params.grant,
      runId: params.runId,
      assignmentId: params.assignmentId,
      nonce: input.nonce,
      targetOrigins: [...params.targetOrigins],
      ...(params.canaryBroker ? { canary: params.canaryBroker } : {}),
    })
    await server.start()
    let session: Awaited<ReturnType<WorkerBackend['openSession']>>
    try {
      session = await params.backend.openSession(
        `${params.assignmentId}-verify-${input.attempt}`,
        params.signal,
        { rpcMountDir: server.hostDir },
      )
    } catch (error) {
      await server.close().catch(() => undefined)
      throw error
    }
    const verify = session.verifyScript
    if (!verify) {
      await session.close().catch(() => undefined)
      await server.close().catch(() => undefined)
      throw new Error('This worker backend cannot execute Layer-3 verification scripts.')
    }
    return {
      nonce: input.nonce,
      transcript: server.transcript,
      async execute(candidate, signal) {
        const execution = await verify({
          runtime: candidate.runtime,
          code: candidate.code,
          nonce: input.nonce,
          ...(params.timeoutMs ? { timeoutMs: params.timeoutMs } : {}),
        }, signal)
        const claims = execution.result && typeof execution.result === 'object'
          ? ((execution.result as { claims?: unknown }).claims)
          : undefined
        const declared = execution.result && typeof execution.result === 'object'
          ? execution.result as { title?: unknown; severity?: unknown; description?: unknown }
          : {}
        attempts.set(input.attempt, {
          claims: Array.isArray(claims)
            ? claims.filter((claim): claim is Record<string, unknown> => Boolean(claim) && typeof claim === 'object' && !Array.isArray(claim))
            : [],
          transcript: server.transcript,
          title: typeof declared.title === 'string' && declared.title.trim() ? declared.title.trim() : null,
          severity: typeof declared.severity === 'string' && declared.severity.trim() ? declared.severity.trim() : null,
          description: typeof declared.description === 'string' && declared.description.trim() ? declared.description.trim() : null,
        })
        return {
          result: execution.result,
          stdout: execution.stdout,
          stderr: execution.stderr,
          exitCode: execution.exitCode,
          durationMs: execution.durationMs,
          timedOut: execution.timedOut,
        }
      },
      async close() {
        await session.close().catch(() => undefined)
        await server.close().catch(() => undefined)
      },
    }
  }

  const verdict = await verifyScript({
    candidate: { name: `agent-proof-${params.runId}.${params.runtime === 'python' ? 'py' : 'ts'}`, runtime: params.runtime, code },
    openAttempt,
    signal: params.signal,
  })
  const transcriptDigests = verdict.attempts.map(attempt => attempt.transcriptDigest).filter(Boolean)
  const passing = verdict.confirmed
    ? [...attempts.entries()]
        .sort((a, b) => b[0] - a[0])
        .find(([, captured]) => captured.transcript.size > 0)
    : undefined
  if (!passing) {
    return { verdict, exchanges: [], receipt: null, vulnClass: null, transcriptDigests, claimTitle: null, severity: null, description: null }
  }
  const captured = passing[1]
  const attribution = {
    claimTitle: captured.title ?? verdict.claimTitle ?? null,
    severity: captured.severity,
    description: captured.description,
  }
  const exchanges: ScriptProofExchange[] = captured.transcript.list().flatMap(record => {
    if (record.op === 'oob' || record.op === 'browser') return []
    const request = record.request
    if (!request) return []
    const body = captured.transcript.body(record.exchangeId)
    return [{
      exchangeId: record.exchangeId,
      op: record.op,
      method: request.method,
      pathAndQuery: request.pathAndQuery,
      origin: request.origin,
      status: record.response?.status ?? null,
      durationMs: record.durationMs,
      personaHandle: request.personaHandle ?? null,
      sessionRole: request.sessionRole ?? null,
      actorRoleLabel: request.actorRoleLabel ?? null,
      ...(body !== undefined ? { body } : {}),
      requestHeaders: request.headers ?? null,
      responseHeaders: record.response?.headers ?? null,
    }]
  })
  const origin = exchanges.find(exchange => exchange.sessionRole === 'probe')?.origin
    ?? exchanges[0]?.origin
    ?? params.targetOrigins[0]
    ?? ''
  const built = buildAgentScriptReceipt({
    claims: captured.claims,
    exchanges,
    origin,
    title: params.title?.trim() || verdict.claimTitle || 'Agent script proof',
  })
  if (!built) {
    return { verdict, exchanges, receipt: null, vulnClass: null, transcriptDigests, ...attribution }
  }
  const verification = verifyReceipt(built.receipt, built.transcript)
  if (!verification.confirmed) {
    // Fail closed: if a script claim maps onto a ProofReceipt rule and `verifyReceipt()` rejects
    // it (status-only, missing readback, anon-401 control, ...), do not fall back to confirming
    // the script verdict without a receipt.
    return {
      verdict: {
        ...verdict,
        confirmed: false,
        reason: 'oracle_failed',
        detail: `ProofReceipt verification rejected the script claim (${verification.rule}): ${verification.reason}`,
        rejectedBy: 'receipt',
      },
      exchanges,
      receipt: null,
      vulnClass: null,
      transcriptDigests,
      ...attribution,
    }
  }
  return {
    verdict,
    exchanges,
    receipt: { receipt: built.receipt, verification },
    vulnClass: built.receipt.vulnClass,
    transcriptDigests,
    ...attribution,
  }
}

async function retestPersistedAgentScript(
  envelope: AgentScriptProofEnvelope,
  params: VerifyReplaySpecParams & { origin?: string },
): Promise<RetestReplayResult> {
  const origin = params.origin?.trim() ?? ''
  const result = await runAgentScriptProof({
    script: envelope.script,
    runtime: envelope.runtime,
    ...(envelope.vulnClass ? { title: `${envelope.vulnClass} agent proof retest` } : {}),
    broker: params.broker,
    grant: params.grant,
    backend: params.backend,
    runId: params.runId ?? 'retest',
    assignmentId: params.assignmentId ?? 'retest',
    targetOrigins: origin ? [origin] : [],
    signal: params.signal,
    ...(params.canaryBroker ? { canaryBroker: params.canaryBroker } : {}),
  })
  const exchangeIds: string[] = []
  const exchanges: BrokerExchangeResult[] = []
  for (const exchange of result.exchanges) {
    const status = exchange.status ?? 0
    const body = exchange.body ?? ''
    const bodyHash = createHash('sha256').update(body).digest('hex')
    const brokerExchange: BrokerExchangeResult = {
      origin: exchange.origin,
      finalOrigin: exchange.origin,
      redirectOrigins: [],
      method: exchange.method.toUpperCase(),
      pathAndQuery: exchange.pathAndQuery,
      personaHandle: exchange.personaHandle ?? null,
      status,
      mediaType: 'application/octet-stream',
      reqHeaders: exchange.requestHeaders ?? {},
      respHeaders: exchange.responseHeaders ?? {},
      setCookies: [],
      bodyPreview: body.slice(0, 4_096),
      body,
      bodySha256: bodyHash,
      bodyBytes: Buffer.byteLength(body),
      bodyTruncated: false,
      durationMs: exchange.durationMs ?? 0,
      secretMatches: [],
      observation: {
        origin: exchange.origin,
        finalOrigin: exchange.origin,
        status,
        mediaType: 'application/octet-stream',
        transportMaxAge: null,
        includeSubDomains: false,
        source: 'public response' as const,
      },
    }
    exchanges.push(brokerExchange)
    const saved = params.onExchange?.(brokerExchange)
    exchangeIds.push(typeof saved === 'string' && saved ? saved : exchange.exchangeId)
  }
  const confirmed = result.verdict.confirmed && (!envelope.vulnClass || result.receipt?.verification.confirmed === true)
  const replay: ReplayVerificationResult = {
    verdict: confirmed ? 'confirmed' : result.verdict.reason === 'oracle_failed' ? 'dismissed' : 'inconclusive',
    ...(confirmed ? { verificationTier: 'runtime_confirmed' as const } : {}),
    outcome: {
      confirmed,
      controlPassed: result.verdict.attempts.every(attempt => attempt.oraclePassed),
      observed: confirmed
        ? `Agent script ${envelope.runtime} proof reproduced (${result.verdict.attempts.length} fresh runs).`
        : `Agent script proof did not reproduce: ${result.verdict.reason}.`,
      expected: 'the persisted proof script reproduces its confirmation',
      ...(result.verdict.detail ? { reason: result.verdict.detail } : {}),
    },
    exchangeIds,
    exchanges,
    evidencePayload: {
      mode: 'agent_script',
      runtime: envelope.runtime,
      scriptSha256: envelope.scriptSha256,
      transcriptDigests: result.transcriptDigests,
      receipt: result.receipt?.verification ?? null,
    },
    evidenceSha256: createHash('sha256').update(JSON.stringify({
      script: envelope.scriptSha256,
      digests: result.transcriptDigests,
      verdict: result.verdict.reason,
    })).digest('hex'),
    ...(result.receipt
      ? { receipt: { mode: 'strict' as const, receipt: result.receipt.receipt, verification: result.receipt.verification } }
      : {}),
  }
  return {
    verdict: replay.verdict === 'confirmed' ? 'reproduced' : replay.verdict === 'dismissed' ? 'fixed' : 'inconclusive',
    replay,
  }
}

/** Read the persisted recipe envelope from a (not-yet-validated) spec. */
function persistedRecipeOf(spec: unknown): { envelope: FloorRecipeEnvelope; kind: string; origin: string } | null {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return null
  const record = spec as Record<string, unknown>
  const parsed = floorRecipeEnvelopeSchema.safeParse(record.recipe)
  if (!parsed.success) return null
  return {
    envelope: parsed.data,
    kind: typeof record.kind === 'string' ? record.kind : parsed.data.recipeId,
    origin: typeof record.origin === 'string' ? record.origin : '',
  }
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
  /** False when a status-only / unbound authorization claim was rejected for lacking a differential. */
  proofStrengthSatisfied?: boolean
  proofStrengthReason?: string
  /** True when the executed probe exchange did not match the spec's declared endpoint/method. */
  endpointBindingFailed?: boolean
  /** Method + origin + path of the endpoint the verifier actually observed. */
  verifiedEndpoint?: string
  /** True when a catch-all baseline matched and the spec must opt in to spaCatchallControl. */
  spaCatchallRequired?: boolean
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

  let spaCatchallRequired: boolean | undefined
  if (payload.spaCatchallAuto && typeof payload.spaCatchallAuto === 'object') {
    const auto = payload.spaCatchallAuto as { requiresControl?: unknown; matchedProbes?: unknown; probeCount?: unknown }
    if (auto.requiresControl === true && typeof auto.matchedProbes === 'number' &&
        typeof auto.probeCount === 'number' && auto.matchedProbes === auto.probeCount) {
      spaCatchallRequired = true
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
  const proofStrengthPayload = payload.proofStrength as { claim?: unknown; satisfied?: unknown; reason?: unknown } | undefined
  const proofStrengthSatisfied = proofStrengthPayload && typeof proofStrengthPayload.satisfied === 'boolean'
    ? proofStrengthPayload.satisfied
    : undefined
  const proofStrengthReason = proofStrengthPayload && proofStrengthPayload.satisfied === false && typeof proofStrengthPayload.reason === 'string'
    ? redact(proofStrengthPayload.reason, secrets).slice(0, 320)
    : undefined
  const endpointBindingPayload = payload.endpointBinding as {
    bound?: unknown
    reason?: unknown
    verifiedEndpoint?: { origin?: unknown; method?: unknown; pathAndQuery?: unknown } | null
  } | undefined
  const endpointBindingFailed = endpointBindingPayload && endpointBindingPayload.bound === false ? true : undefined
  const verifiedEndpoint = endpointBindingPayload?.verifiedEndpoint &&
    typeof endpointBindingPayload.verifiedEndpoint.method === 'string' &&
    typeof endpointBindingPayload.verifiedEndpoint.origin === 'string' &&
    typeof endpointBindingPayload.verifiedEndpoint.pathAndQuery === 'string'
    ? redact(`${endpointBindingPayload.verifiedEndpoint.method} ${endpointBindingPayload.verifiedEndpoint.origin}${endpointBindingPayload.verifiedEndpoint.pathAndQuery}`, secrets).slice(0, 320)
    : undefined

  const rawFeedback: EnrichedInlineVerifyFeedback = {
    verdict: replay.verdict,
    ...(replay.verificationTier ? { verificationTier: replay.verificationTier } : {}),
    ...(failedStepId ? { failedStepId: redact(failedStepId, secrets) } : {}),
    controlPassed: replay.outcome.controlPassed,
    ...(requireControlNonErrorTriggered ? { requireControlNonErrorTriggered } : {}),
    ...(spaCatchallMatched !== undefined ? { spaCatchallMatched } : {}),
    ...(spaCatchallRequired ? { spaCatchallRequired } : {}),
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
    ...(proofStrengthSatisfied !== undefined ? { proofStrengthSatisfied } : {}),
    ...(proofStrengthReason ? { proofStrengthReason } : {}),
    ...(endpointBindingFailed ? { endpointBindingFailed } : {}),
    ...(verifiedEndpoint ? { verifiedEndpoint } : {}),
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
