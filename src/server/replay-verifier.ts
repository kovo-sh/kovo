import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto'
import { diffResponse } from '../../worker/analyzers.ts'
import { maxInlineVerifyRetries } from '../domain.ts'
import type { InlineVerifyFeedback, VerificationTier } from '../domain.ts'
import {
  containsDestructivePayload,
  declarativeReplaySpecSchema,
  floorRecipeEnvelopeSchema,
  replayAssertionOutcomeSchema,
  agentScriptProofEnvelopeSchema,
  replaySpecOrigins,
} from '../replay-spec.ts'
import type { AgentScriptProofEnvelope, AuthMutation, DeclarativeReplaySpec, FloorRecipeEnvelope, ReplayAssertionOutcome, ReplayStep } from '../replay-spec.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied, RequestBroker } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { personaSecrets } from './persona-vault.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import { openCanarySession } from './verify-support.ts'
import type { EphemeralCanarySession } from './verify-support.ts'
import type { Store } from './store.ts'
import type { WorkerBackend } from './worker-backend.ts'
import {
  actorFromPersona,
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
import { isProtocolBrowserSpec, wiredRecipeForSpecKind } from './floor-recipes.ts'
import {
  browserSessionSeam,
  retestPersistedRecipe,
  runAuthProtocolProofRecipe,
  runCacheDifferentialRecipe,
  runRceProofRecipe,
  runStaticAstProofRecipe,
} from './floor-recipe-engine.ts'

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

export const RETIRED_LEGACY_SPEC_KINDS: ReadonlySet<string> = new Set([
  'dns_takeover', 'tls_audit', 'browser_dom', 'ws_chain', 'upload_probe',
  'sql_boolean_diff', 'sql_time_diff', 'race_burst', 'browser_chain',
])
export const RETIRED_LEGACY_SPEC_REASON = 'retired_legacy_spec_kind: use guardian_verify'

function retiredLegacyResult(
  kind: string,
  exchanges: BrokerExchangeResult[],
  exchangeIds: string[],
): ReplayVerificationResult {
  const evidencePayload = { kind, retired: true, reason: RETIRED_LEGACY_SPEC_REASON }
  const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')
  return {
    verdict: 'dismissed',
    outcome: {
      confirmed: false,
      controlPassed: false,
      observed: RETIRED_LEGACY_SPEC_REASON,
      expected: 'Proof submitted via guardian_verify or a wired floor recipe.',
      reason: RETIRED_LEGACY_SPEC_REASON,
    },
    exchangeIds,
    exchanges,
    evidencePayload,
    evidenceSha256,
  }
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

function requestShapeToBrokerRequest(
  req: ReplayStep['request'],
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

const postureCwes = new Set([
  'CWE-16', 'CWE-200', 'CWE-209', 'CWE-284', 'CWE-285', 'CWE-287', 'CWE-288', 'CWE-306', 'CWE-319', 'CWE-326',
  'CWE-346', 'CWE-523', 'CWE-538', 'CWE-540', 'CWE-614', 'CWE-639', 'CWE-693', 'CWE-862', 'CWE-863', 'CWE-942',
  'CWE-1004', 'CWE-1021',
])
const postureCategoryPattern = /access|auth|bypass|cors|header|posture|misconfig|exposure|session|cookie|transport|tls|csp|policy|idor|bola|bfla/i

/** requireControlNonError defaults to true for posture / auth-bypass style specs. */
function defaultRequireControlNonError(spec: DeclarativeReplaySpec): boolean {
  if (spec.kind === 'static_ast_proof') return false
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

  // Floor-recipe dispatch runs BEFORE retired legacy VM rejection so recipe-backed specs
  // (e.g. `sql_boolean_diff`/`sql_time_diff` with a `boolean_or_timing` floorRecipe envelope)
  // verify cleanly through ProofReceipt while bare legacy VM specs fail closed below.
  const persistedRecipe = persistedRecipeOf(params.spec)
  if (persistedRecipe) {
    const result = await runPersistedFloorRecipe(persistedRecipe, params, spec.origin)
    return result.replay
  }

  if (RETIRED_LEGACY_SPEC_KINDS.has(spec.kind)) {
    return retiredLegacyResult(spec.kind, exchanges, exchangeIds)
  }

  // Cut 3e: non-http_chain legacy VMs are retired onto typed runners in floor-recipe-engine.ts.
  const runnerCtx = {
    broker,
    canaryBroker: params.canaryBroker,
    backend,
    reposDir: params.reposDir,
    grant,
    signal,
    storage: params.storage,
    runId: params.runId,
    assignmentId,
    onExchange: params.onExchange,
  }
  if (spec.kind === 'static_ast_proof') return runStaticAstProofRecipe(spec, runnerCtx)
  if (spec.kind === 'rce_proof') return runRceProofRecipe(spec, runnerCtx)
  if (spec.kind === 'cache_differential') return runCacheDifferentialRecipe(spec, runnerCtx)
  if (spec.kind === 'auth_protocol_proof') return runAuthProtocolProofRecipe(spec, runnerCtx)

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
    verdict = 'confirmed'
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

/** Cut 3 no-fallback invariant at the product floor boundary. */
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
  // Only navigate/fill/click DOM-sink proofs are wired to `browser_sink`. A protocol browser proof
  // (postMessage/fetch/builtin) legitimately stays on the framework verifier and must not trip the
  // no-fallback guard.
  if (kind === 'browser_chain') {
    const steps = (spec as { steps?: unknown }).steps
    if (Array.isArray(steps) && isProtocolBrowserSpec(steps as Array<Record<string, unknown>>)) return
  }
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

async function runPersistedFloorRecipe(
  persisted: NonNullable<ReturnType<typeof persistedRecipeOf>>,
  params: VerifyReplaySpecParams,
  originFallback?: string,
) {
  const args = persisted.envelope.args as { vulnClass?: unknown; pathAndQuery?: unknown }
  const origin = persisted.origin || originFallback || ''
  return retestPersistedRecipe({
    envelope: persisted.envelope,
    specKind: persisted.kind,
    vulnClass: typeof args.vulnClass === 'string' && args.vulnClass ? args.vulnClass : persisted.kind,
    endpoint: typeof args.pathAndQuery === 'string' ? args.pathAndQuery : origin,
    origin,
    broker: params.broker,
    grant: params.grant,
    signal: params.signal,
    ...(params.runId ? { runId: params.runId } : {}),
    ...(params.assignmentId ? { assignmentId: params.assignmentId } : {}),
    ...(params.onExchange ? { recordExchange: (exchange: BrokerExchangeResult) => params.onExchange?.(exchange) } : {}),
    // Browser recipes run through the same scoped browser the framework verifier uses; the trace
    // returned to the receipt is host-recorded and only counts a canary that reached a sink.
    browserSession: browserSessionSeam({
      browser: params.browser ?? new ScopedBrowser(params.broker),
      grant: params.grant,
      signal: params.signal,
      origin,
      ...(params.runId ? { runId: params.runId } : {}),
      ...(params.assignmentId ? { assignmentId: params.assignmentId } : {}),
      ...(params.onExchange ? { recordExchange: (exchange: BrokerExchangeResult) => params.onExchange?.(exchange) } : {}),
    }),
  })
}

export async function retestReplaySpec(params: VerifyReplaySpecParams): Promise<RetestReplayResult> {
  // Cut 3 retest receipts: a spec confirmed by a typed floor recipe carries that recipe, so retest
  // re-runs the recipe and validates a fresh ProofReceipt.
  const persisted = persistedRecipeOf(params.spec)
  if (persisted) {
    const result = await runPersistedFloorRecipe(persisted, params)
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
    // Fail closed: every agent script confirmation MUST produce a verified ProofReceipt.
    // Never fall back to a receiptless script-only confirmation (e.g. mutating POST boundary claims
    // that lack persisted before/after readbacks).
    return {
      verdict: {
        ...verdict,
        confirmed: false,
        reason: 'oracle_failed',
        rejectedBy: 'receipt',
        missingEvidence: [...new Set([...(verdict.missingEvidence ?? []), 'verified_proof_receipt'])],
        detail: 'ProofReceipt could not be built from the script claims: mutating boundary claims require persisted before/after readbacks via ctx.prove_persisted_mutation; read-only boundaries require GET/HEAD.',
      },
      exchanges,
      receipt: null,
      vulnClass: null,
      transcriptDigests,
      ...attribution,
    }
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
  } else if (kind === 'rce_proof') {
    if (payload.control && typeof payload.control === 'object') {
      stepStatuses.push(toStepStatusItem('control', 'control', payload.control as Record<string, unknown>))
    }
    if (payload.probe && typeof payload.probe === 'object') {
      stepStatuses.push(toStepStatusItem('probe', 'probe', payload.probe as Record<string, unknown>))
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
  }

  const reason = replay.outcome.reason ?? ''
  const requireControlNonErrorTriggered = /requireControlNonError/i.test(reason) ? true : undefined

  let failedStepId: string | undefined
  if (replay.verdict === 'dismissed' || replay.verdict === 'inconclusive') {
    const stepMatch = /step\s+"([^"]+)"/i.exec(reason)
    if (stepMatch) {
      failedStepId = stepMatch[1]
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
