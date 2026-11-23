/**
 * In-product deterministic closed loop.
 *
 * The benchmark pipeline proved that risk-ranked differential probing plus declarative replay
 * verification can find real vulnerabilities without a model. This module moves that loop into the
 * product engine: it risk-ranks the discovered surface, enumerates generic hypotheses from route
 * and parameter shapes, harvests identifiers/fields from the target's own responses, runs the
 * benign differential probes from `surface-engine.ts`, synthesizes identifier-bound
 * `DeclarativeReplaySpec`s, and lets the normal `verifyReplaySpec` decide. Only
 * ReplayVerifier-confirmed findings are handed to the persistence callback; signals that do not
 * replay are emitted as leads (facts), never as findings.
 *
 * Everything is bounded by a request cap, a wall-clock cap (inside the run budget), the run's
 * capability tier, assignment scope and the broker's RPS/destructive guards.
 */
import type { BrokerExchangeResult, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { declarativeReplaySpecSchema } from '../replay-spec.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'
import { probeDifferential, responseSimilarity } from './surface-engine.ts'
import type { DifferentialProbeClass, DifferentialResult, ProbeDifferentialRequest, SurfaceParamLocation } from './surface-engine.ts'
import { verifyReplaySpec } from './replay-verifier.ts'
import type { ReplayVerificationResult } from './replay-verifier.ts'
import type { ScopedBrowser } from './scoped-browser.ts'
import { normalizeEndpointTemplate } from './dedupe.ts'
import type { Store } from './store.ts'
import type { WorkerBackend } from './worker-backend.ts'
import { synthesizeEngineSpecs, vulnClassOfSpec } from './deterministic-specs.ts'
import type { EngineEndpoint, EngineHypothesis, EngineParam, SynthesizedEngineSpec } from './deterministic-specs.ts'

export type { EngineEndpoint, EngineHypothesis, EngineParam } from './deterministic-specs.ts'

export const defaultEngineMaxRequests = 1800
export const defaultEngineMaxDurationMs = 240_000
export const defaultEngineMaxEndpoints = 120
export const defaultEngineMaxHypotheses = 120
export const defaultEnginePerProbeRequests = 28
/**
 * Fixed wall-clock margin over `maxDurationMs`. The engine terminates on requests first; time is an
 * emergency brake only, so a loaded or slow host cannot truncate a different queue tail. The margin
 * is deliberately generous (2 minutes): normal completion is request-count driven.
 */
export const deterministicWallMarginMs = 120_000

export const engineDisableEnv = 'GUARDIAN_DETERMINISTIC_ENGINE'

/**
 * Conventional noun/action route wordlists (e.g. `/api/tokens`, `/api/admin/users`) are a local-lab
 * convenience: they only match when the target happens to use the same English nouns as the list.
 * They stay ON by default for local-lab compatibility, but a run can turn them OFF so capability is
 * measured from discovered/declared surface only. The switch never changes what is probed on a route
 * the target itself exposed; it only drops endpoints whose sole source is that wordlist.
 */
export const conventionalWordlistEnv = 'GUARDIAN_CONVENTIONAL_WORDLIST'

export function conventionalWordlistEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env[conventionalWordlistEnv]
  if (raw === undefined) return true
  const value = raw.trim().toLowerCase()
  if (value === '') return true
  return !(value === '0' || value === 'off' || value === 'false' || value === 'no')
}

/** Endpoints the deterministic engine may triage, honouring the conventional-wordlist switch. */
export function engineWordlistSurface(
  endpoints: readonly EngineEndpoint[],
  enabled: boolean,
): EngineEndpoint[] {
  return enabled ? [...endpoints] : endpoints.filter(endpoint => endpoint.source !== 'conventional')
}

/** The engine is on by default; `GUARDIAN_DETERMINISTIC_ENGINE=0|false|off` disables it. */
export function deterministicEngineEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env[engineDisableEnv]
  return !(raw === '0' || raw === 'false' || raw === 'off' || raw === 'no')
}

export interface EnginePersona {
  handle: string
  roleLabel: string
  privilege: 'admin' | 'viewer' | 'member'
  tenant?: string
}

export interface EndpointHarvest {
  ownerIds: string[]
  otherIds: string[]
  fields: string[]
  values: Record<string, string[]>
  otherValues: Record<string, string[]>
  seedValues: string[]
  /** Query parameter names whose benign value demonstrably changed the response. */
  activeQueryParams: string[]
  /** Identifiers observed on the lower-privileged (viewer) persona's own identity route. */
  viewerIds?: string[]
  /** Runtime value shape per field (url/path/xml/jwt/uuid/number/email/text). */
  shapes?: Record<string, ParamValueShape>
  /** Structural response evidence: wire format and value shape, never a route-name assumption. */
  evidence?: HarvestEvidence
}

export interface HarvestEvidence {
  /** `Content-Disposition: attachment[; filename=...]` on a response. */
  contentDisposition?: boolean
  /** Response `Location` header (redirect or created resource). */
  location?: string
  /** Response `Content-Type` carries XML. */
  xml?: boolean
  /** Observed string values that are absolute URLs. */
  urlValues?: string[]
  /** Observed values that are three-segment base64url JWT-shaped tokens. */
  jwtValues?: string[]
  /** Field names whose values look like credentials (pre-redaction secret fingerprints). */
  sensitiveFields?: string[]
  /** Response header names (signature/HMAC/cache/set-cookie evidence). */
  headerNames?: string[]
}

export interface EngineConfirmed {
  hypothesis: EngineHypothesis
  spec: DeclarativeReplaySpec
  specRecord: SynthesizedEngineSpec
  vulnClass: string
  endpoint: string
  result: ReplayVerificationResult
  exchangeIds: string[]
}

export type LeadEvidenceKind = 'denied_control' | 'data_delta' | 'near_miss'

/**
 * Evidence that justifies promoting an unconfirmed observation into a `det_lead`.
 *
 * A bare anomaly ("a non-owner received a 2xx") is not enough: on idempotent routes every caller and
 * every nonexistent id receives the same acknowledgement, so the "signal" carries no contrast and a
 * dispatched upgrade assignment can only burn budget re-proving it false. Promotion therefore needs
 * at least one of:
 *  - `denied_control`: an actor/identifier differential observed on the same route (401/403 for one
 *    actor while the owner/another actor is served) — the app does enforce a boundary;
 *  - `data_delta`: an observed body/state delta that only spec synthesis/verification failed to bind
 *    (owner-equivalent cross-actor read, boolean/time differential, state mutation read-back, ...);
 *  - `near_miss`: a verifier rejection with a concrete, actionable missing-evidence code (not a
 *    failed/absent control, which is evidence *against* the lead).
 */
export interface LeadEvidence {
  kind: LeadEvidenceKind
  /**
   * Concrete verifier-side reason the replay was rejected, or null when no spec reached the
   * verifier. Bounded probe/verifier wording only — never a raw HTTP body.
   */
  verifyFailureReason: string | null
  /** Concrete missing-evidence code derived from the verifier reason (null when none applies). */
  verifyFailureCode: string | null
  /**
   * What the control leg observed on the same route: `actor_denied_401`, `bogus_id_denied_404`,
   * `owner_equivalent_2xx`, `state_delta`, `anomaly_boolean_differential`, ...
   */
  controlOutcome: string
  /** Bounded exchange ids holding the differential and control evidence. */
  evidenceExchangeIds: string[]
  /** Probe class the dispatcher should prioritize for the upgrade (the lead's own class). */
  candidateProbeClass: string
  /** Short machine-readable justification. Never contains payloads or response bodies. */
  detail: string
}

export interface EngineLead {
  hypothesis: EngineHypothesis
  probe: DifferentialResult
  summary: string
  /** Promotion evidence. Always present on engine-emitted leads; optional for direct callers. */
  evidence?: LeadEvidence
}

/** One rejected replay attempt, retained so a failed hypothesis can still carry actionable evidence. */
export interface RejectedSpecEvidence {
  kind: string
  verdict: string
  controlPassed: boolean
  observed: string
  reason: string | null
  exchangeIds: string[]
}

export interface DeterministicEngineInput {
  runId: string
  assignmentId: string
  signal: AbortSignal
  endpoints: readonly EngineEndpoint[]
  personas: readonly EnginePersona[]
  broker: RequestBroker
  grant: Grant
  backend: WorkerBackend
  canaryBroker?: CanaryBroker
  browser?: ScopedBrowser
  storage?: Store
  reposDir?: string
  tier: number
  maxRequests?: number
  maxDurationMs?: number
  maxEndpoints?: number
  maxHypotheses?: number
  /** Evidence-gated `det_lead` emission cap for this pass (default 6, severity-ranked). */
  maxLeads?: number
  /**
   * v6 Phase A: the floor always runs with the same deep per-class policy as `--no-llm`.
   * Breadth-first caps are opt-in only for callers whose remaining budget cannot fund a deep pass.
   */
  breadthFirst?: boolean
  /** v6: environment contract. `prod_readonly` generates no mutating hypotheses at all. */
  environmentMode?: 'prod_readonly' | 'staging_isolated' | 'ephemeral_lab'
  /** v6: mandatory run-scoped tag applied to benign entity values the floor creates. */
  entityTag?: string
  /**
   * v6 staging: full declared-surface rows used only to discover the run-scoped cleanup hook.
   * Probe selection may deliberately exclude a low-risk cleanup route from the probed subset.
   */
  cleanupEndpoints?: readonly StagingCleanupEndpoint[]
  classes?: ReadonlySet<string>
  /** Injection points for tests; production uses the surface-engine probe and ReplayVerifier. */
  probe?: typeof probeDifferential
  verify?: typeof verifyReplaySpec
  recordExchange?: (exchange: BrokerExchangeResult) => string | void
  /** Persist a verified finding. Must create the finding as confirmed; never call for a lead. */
  onConfirmed: (input: EngineConfirmed) => Promise<string | null> | string | null
  onLead?: (lead: EngineLead) => void
  log?: (kind: string, message: string, data?: Record<string, unknown>) => void
}

export interface EngineClassStats {
  hypotheses: number
  signals: number
  specs: number
  confirmed: number
  rejected: number
  requests: number
}

export interface DeterministicEngineReport {
  requestsUsed: number
  durationMs: number
  endpointsConsidered: number
  endpointsHarvested: number
  hypothesesFormed: number
  hypothesesRun: number
  signals: number
  specsSubmitted: number
  confirmed: number
  rejectedSpecs: number
  leads: number
  /** Signals rejected by the evidence gate (bare anomaly / 2xx-only / non-selective control). */
  leadsSuppressed: number
  stoppedReason: 'budget' | 'time' | 'aborted' | 'complete' | 'disabled'
  byClass: Record<string, EngineClassStats>
  confirmedPairs: Array<{ endpoint: string; vulnClass: string }>
  /** Normalized `<endpoint>|<family>` keys for every hypothesis the engine formed. */
  touchedPairs: string[]
  /** Reporting for the conventional-noun wordlist switch (expansion is ON unless disabled). */
  conventionalWordlist: boolean
  /** v6 staging: mutating hypotheses that carried the run tag (per-probe count). */
  stagingTaggedMutations: number
  /** v6 staging: mutating hypotheses refused locally because they cannot be tagged safely. */
  stagingUntaggedSkipped: number
  /** v6 staging: run-tagged entities removed by the fixture run-scoped cleanup hook. */
  stagingCleaned: number
  /** v6 staging: entity ids observed in tagged 2xx create responses (cleanup audit trail). */
  stagingCreatedEntityIds: string[]
  notes: string[]
}

// ---------------------------------------------------------------------------------------------
// Deterministic lead promotion
// ---------------------------------------------------------------------------------------------

/** Per-run lead emission cap. Six severity-ranked leads are enough for one dispatch window. */
export const defaultEngineLeadCap = 6
const maxLeadEvidenceExchanges = 6
const maxLeadEvidenceText = 200

/**
 * Anomaly types that already carry an observed delta (body/state/timing/callback), so a rejected
 * synthesis is the only thing standing between the observation and a proof. Bare status anomalies
 * (`unauthorized_access`) are handled by the stricter authz rules below.
 */
const leadDataDeltaAnomalyTypes = new Set([
  'boolean_differential',
  'sql_time_differential',
  'db_error_fingerprint',
  'canary_callback',
  'xxe_entity_resolved_inband',
  'xxe_canary_callback',
  'command_executed',
  'expression_evaluated',
  'path_traversal_escape',
  'path_normalization_differential',
  'ssrf_inband_differential',
  'open_redirect_differential',
  'oauth_redirect_differential',
  'web_cache_deception',
  'cache_poisoning',
  'webhook_signature_bypass',
  'csrf_state_change',
  'mass_assignment',
  'workflow_step_skip',
  'workflow_repeat_accepted',
  'workflow_quantity_invariant',
  'invariant_violation',
  'xss_context',
  'graphql_nested_bola',
  'graphql_cross_persona_access',
  'graphql_mutation_accessible',
  'secret_disclosed',
  'jwt_auth_mutation_bypass',
  'pkce_downgrade',
  'introspection_enabled',
  'field_suggestion_leak',
  'operator_type_divergence',
  'alias_batching_allowed',
  'write_path_bola',
])

/** Verifier reasons that name a concrete next evidence step (and therefore justify a lead). */
const promotableNearMissCodes = new Set([
  'missing_identifier_binding',
  'missing_state_delta',
  'missing_probe_binding',
])

/**
 * Classify a verifier rejection reason into a concrete missing-evidence code.
 * `status_only`, `missing_control_differential` and `control_failed` are negatives: they say the
 * observation never had a contrast to begin with, so they must not promote a lead.
 */
export function missingEvidenceCode(reason: string | null | undefined): string | null {
  const text = (reason ?? '').trim()
  if (!text) return null
  if (/status-only|status only|status equality|2xx status/i.test(text)) return 'status_only'
  if (/no genuine control-vs-probe differential|no genuine control versus probe differential/i.test(text)) {
    return 'missing_control_differential'
  }
  if (/different-body observation without identifier binding|without identifier binding/i.test(text)) {
    return 'missing_identifier_binding'
  }
  if (/state delta|persisted state|persisted mutation/i.test(text)) return 'missing_state_delta'
  if (/no executed probe|bind the finding endpoint|no bound exchange/i.test(text)) return 'missing_probe_binding'
  return null
}

/** Read the bogus/nonexistent-identifier control status out of a replay `observed` string. */
export function bogusIdControlOutcome(observed: string | null | undefined): { status: number; accepted: boolean } | null {
  const match = /bogus status=(\d{3})/.exec(observed ?? '')
  if (!match) return null
  const status = Number(match[1])
  if (!Number.isFinite(status) || status <= 0) return null
  return { status, accepted: status >= 200 && status < 300 }
}

interface LeadMatrixRow {
  resourceId: string
  actor: string
  status: number | null
  accessible: boolean | null
  similarityToOwner: number | null
  bodyBytes: number | null
  bodySha256: string | null
}

function leadMatrix(probe: DifferentialResult): LeadMatrixRow[] {
  const raw = probe.details?.matrix
  if (!Array.isArray(raw)) return []
  const rows: LeadMatrixRow[] = []
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue
    const row = entry as Record<string, unknown>
    rows.push({
      resourceId: typeof row.resourceId === 'string' ? row.resourceId : '',
      actor: typeof row.actor === 'string' ? row.actor : '',
      status: typeof row.status === 'number' ? row.status : null,
      accessible: typeof row.accessible === 'boolean' ? row.accessible : null,
      similarityToOwner: typeof row.similarityToOwner === 'number' ? row.similarityToOwner : null,
      bodyBytes: typeof row.bodyBytes === 'number' ? row.bodyBytes : null,
      bodySha256: typeof row.bodySha256 === 'string' ? row.bodySha256 : null,
    })
  }
  return rows
}

function isSuccessStatus(status: unknown): boolean {
  return typeof status === 'number' && status >= 200 && status < 300
}

function isDeniedStatus(status: number | null): boolean {
  return status === 401 || status === 403
}

function isCrossActorHit(anomaly: Record<string, unknown>): boolean {
  const type = String(anomaly.type ?? '')
  if (type !== 'unauthorized_access' && type !== 'graphql_nested_bola' && type !== 'graphql_cross_persona_access') {
    return false
  }
  if (anomaly.actor === 'owner') return false
  return isSuccessStatus(anomaly.status)
}

function uniqueExchangeIds(values: Iterable<string>): string[] {
  const out: string[] = []
  for (const value of values) {
    if (typeof value !== 'string' || !value) continue
    if (!out.includes(value)) out.push(value)
  }
  return out.slice(0, maxLeadEvidenceExchanges)
}

function leadFailureReason(rejections: readonly RejectedSpecEvidence[]): string | null {
  // Prefer a rejection that names a concrete next step; fall back to the first verifier wording.
  const scored = rejections
    .map((rejection, index) => {
      const text = (rejection.reason ?? rejection.observed ?? '').trim()
      const code = missingEvidenceCode(rejection.reason)
      const weight = code && promotableNearMissCodes.has(code) ? 2 : code ? 1 : 0
      return { text, weight, index }
    })
    .filter(entry => entry.text.length > 0)
    .sort((a, b) => b.weight - a.weight || a.index - b.index)
  const chosen = scored[0]
  return chosen ? chosen.text.slice(0, maxLeadEvidenceText) : null
}

export interface LeadEvidenceInput {
  hypothesis: EngineHypothesis
  probe: DifferentialResult
  rejections?: readonly RejectedSpecEvidence[]
}

/**
 * Decide whether an unconfirmed observation has enough evidence to become a lead.
 * Returns null when the observation is a bare anomaly/2xx-only signal that must not be promoted.
 */
export function deriveLeadEvidence(input: LeadEvidenceInput): LeadEvidence | null {
  const { hypothesis: hyp, probe } = input
  const rejections = input.rejections ?? []
  if (probe.verdict !== 'signal') return null
  const anomalies = probe.anomalies.filter(
    (anomaly): anomaly is Record<string, unknown> => Boolean(anomaly) && typeof anomaly === 'object',
  )
  if (anomalies.length === 0) return null

  const verifyFailureReason = leadFailureReason(rejections)
  const verifyFailureCode = missingEvidenceCode(verifyFailureReason)
  const evidenceExchangeIds = uniqueExchangeIds([
    ...probe.exchangeIds,
    ...rejections.flatMap(rejection => rejection.exchangeIds),
  ])
  const base = {
    verifyFailureReason,
    verifyFailureCode,
    evidenceExchangeIds,
    candidateProbeClass: hyp.probeClass,
  }
  const scope = `${hyp.endpoint.origin} ${hyp.method} ${hyp.endpoint.pathTemplate}`
  const method = (hyp.method ?? 'GET').toUpperCase()
  const mutating = method !== 'GET' && method !== 'HEAD'
  const authz = hyp.intent === 'authz' || hyp.intent === 'graphql' ||
    probe.probeClass === 'authz_matrix' || probe.probeClass === 'graphql_audit'

  if (authz) {
    const hits = anomalies.filter(isCrossActorHit)
    if (hits.length === 0) return null
    const matrix = leadMatrix(probe)
    const ownerAccessible = matrix.some(row => row.actor === 'owner' && (row.accessible === true || isSuccessStatus(row.status)))
    const deniedRows = matrix.filter(row => isDeniedStatus(row.status))
    const hitIds = new Set(hits.map(hit => String(hit.resourceId ?? '')).filter(Boolean))
    const deniedForHit = deniedRows.filter(row => hitIds.size === 0 || hitIds.has(row.resourceId))

    if (mutating) {
      // A mutating 2xx is only meaningful when the route discriminates. The replay's bogus-id
      // control is the decisive observation: if a nonexistent identifier is also accepted, every
      // caller sees the same acknowledgement and the "signal" is a false lead.
      for (const rejection of rejections) {
        const bogus = bogusIdControlOutcome(rejection.observed)
        if (bogus?.accepted) {
          return null
        }
      }
      for (const rejection of rejections) {
        const bogus = bogusIdControlOutcome(rejection.observed)
        if (bogus && !bogus.accepted && /probe status=2\d\d/.test(rejection.observed)) {
          return {
            ...base,
            kind: 'near_miss',
            controlOutcome: `bogus_id_denied_${bogus.status}`,
            detail: `mutating 2xx with a denied bogus-id control on ${scope}`,
          }
        }
      }
      const hitActors = new Set(hits.map(hit => String(hit.actor ?? '')).filter(Boolean))
      const sameActorDenied = deniedForHit.some(row => ownerAccessible && hitActors.has(row.actor))
      if (sameActorDenied) {
        const status = deniedForHit.find(row => hitActors.has(row.actor))?.status ?? 0
        return {
          ...base,
          kind: 'denied_control',
          controlOutcome: `actor_denied_${status}`,
          detail: `mutating 2xx with a same-actor denial on ${scope}`,
        }
      }
      const stateDelta = anomalies.find(anomaly =>
        anomaly.type === 'write_path_bola' || anomaly.stateDelta === true || anomaly.persisted === true)
      if (stateDelta) {
        return {
          ...base,
          kind: 'data_delta',
          controlOutcome: 'state_delta',
          detail: `mutating 2xx with an owner-read-back state delta on ${scope}`,
        }
      }
      return null
    }

    const deniedForRoute = deniedForHit.length > 0 || (hitIds.size === 0 && deniedRows.length > 0)
    if (deniedForRoute && ownerAccessible) {
      const status = (deniedForHit[0] ?? deniedRows[0])?.status ?? 0
      return {
        ...base,
        kind: 'denied_control',
        controlOutcome: `actor_denied_${status}`,
        detail: `cross-actor 2xx with a denied actor control on ${scope}`,
      }
    }
    const ownerEquivalent = hits.some(hit => Number(hit.similarityToOwner ?? 0) >= 0.7) ||
      matrix.some((row, index) => row.bodySha256 !== null &&
        matrix.some((other, otherIndex) => otherIndex !== index && other.actor === 'owner' &&
          other.bodySha256 === row.bodySha256))
    if (ownerEquivalent) {
      return {
        ...base,
        kind: 'data_delta',
        controlOutcome: 'owner_equivalent_2xx',
        detail: `cross-actor read returned owner-equivalent content on ${scope}`,
      }
    }
    const code = missingEvidenceCode(verifyFailureReason)
    if (code && promotableNearMissCodes.has(code)) {
      return {
        ...base,
        kind: 'near_miss',
        controlOutcome: `verifier_${code}`,
        detail: `cross-actor read rejected for ${code} on ${scope}`,
      }
    }
    return null
  }

  const delta = anomalies.find(anomaly => leadDataDeltaAnomalyTypes.has(String(anomaly.type ?? '')))
  if (delta) {
    return {
      ...base,
      kind: 'data_delta',
      controlOutcome: `anomaly_${String(delta.type)}`,
      detail: `observed ${String(delta.type)} delta on ${scope}`,
    }
  }
  const code = missingEvidenceCode(verifyFailureReason)
  if (code && promotableNearMissCodes.has(code)) {
    return {
      ...base,
      kind: 'near_miss',
      controlOutcome: `verifier_${code}`,
      detail: `verifier rejected the spec for ${code} on ${scope}`,
    }
  }
  return null
}

export interface EngineLeadCandidate {
  lead: EngineLead
  key: string
  score: number
}

const leadEvidenceSeverity: Record<LeadEvidenceKind, number> = {
  near_miss: 3,
  denied_control: 2,
  data_delta: 1,
}

/** Dedupe key required by the lead lane: origin, endpoint, method, mutated input, class. */
export function leadCandidateKey(hyp: EngineHypothesis): string {
  const param = hyp.param?.name ?? hyp.idParamName ?? ''
  const location = hyp.param?.location ?? hyp.location ?? ''
  const mutatedInput = param ? `${param}@${location}` : '-'
  return [
    hyp.endpoint.origin,
    normalizeEndpointTemplate(hyp.endpoint.pathTemplate),
    (hyp.method ?? 'GET').toUpperCase(),
    mutatedInput,
    hyp.probeClass,
  ].join('|')
}

/** Severity rank: evidence kind first, then the hypothesis risk score, then a total identity order. */
export function leadCandidateScore(hyp: EngineHypothesis, evidence: LeadEvidence): number {
  const risk = Number.isFinite(hyp.risk) ? Math.max(0, Math.min(100, hyp.risk)) : 0
  return leadEvidenceSeverity[evidence.kind] * 1_000 + risk
}

/**
 * Deduplicate by the lane key and keep the `cap` highest-severity leads.
 * Total order: score desc, then key, then first exchange id (stable on permuted input).
 */
export function selectEngineLeads(
  candidates: readonly EngineLeadCandidate[],
  cap: number = defaultEngineLeadCap,
): EngineLeadCandidate[] {
  const byKey = new Map<string, EngineLeadCandidate>()
  for (const candidate of candidates) {
    const current = byKey.get(candidate.key)
    if (!current) {
      byKey.set(candidate.key, candidate)
      continue
    }
    const candidateExchange = candidate.lead.evidence?.evidenceExchangeIds[0] ?? ''
    const currentExchange = current.lead.evidence?.evidenceExchangeIds[0] ?? ''
    if (candidate.score > current.score ||
        (candidate.score === current.score && candidateExchange < currentExchange)) {
      byKey.set(candidate.key, candidate)
    }
  }
  const limit = Math.max(0, Math.floor(cap))
  return [...byKey.values()]
    .sort((a, b) =>
      b.score - a.score ||
      a.key.localeCompare(b.key) ||
      (a.lead.evidence?.evidenceExchangeIds[0] ?? '').localeCompare(b.lead.evidence?.evidenceExchangeIds[0] ?? ''))
    .slice(0, limit)
}

// ---------------------------------------------------------------------------------------------
// Risk ranking
// ---------------------------------------------------------------------------------------------

const staticAssetPath = /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|pdf|zip|gz|tgz|tar|rar|7z|wasm|txt)$/i
const baselinePath = /^(?:\/|)\/?(?:health|healthz|readyz|livez|app-config\.json|robots\.txt|sitemap\.xml|favicon\.ico|manifest\.json|\.well-known\/.*)$/i

export function isStaticOrBaselinePath(path: string): boolean {
  const bare = path.split('?')[0] || '/'
  if (bare === '/' || bare === '') return true
  if (staticAssetPath.test(bare)) return true
  if (baselinePath.test(bare)) return true
  return /(?:^|\/)(?:logout|signout)(?:\/|$)/i.test(bare)
}

const idSegmentRe = /(?:\/:[A-Za-z_][A-Za-z0-9_]*|\/\{\{id\}\}|\/\{[A-Za-z0-9_]+\}|\/\[[^\]]+\])/

export function hasDynamicIdSegment(path: string): boolean {
  return idSegmentRe.test(path.split('?')[0])
}

export function pathHasFileHint(path: string): boolean {
  return /(?:^|[/_.-])(?:download|downloads|file|files|asset|assets|view|serve|log|logs|journal|journals|billing[-_]?docs?|document|documents|attachment|attachments|backup|backups|archive|archives)(?:$|[/_.-])/i.test(path)
}

export function pathHasUrlHint(path: string): boolean {
  return /(?:^|[/_.-])(?:avatar|avatars|image|images|photo|photos|logo|logos|media|thumbnail|webhook|webhooks|hook|hooks|callback|callbacks|integration|integrations|connector|connectors|proxy|proxies|fetch|remote|link|links|manifest|manifests)(?:$|[/_.-])/i.test(path)
}

export function pathHasXmlHint(path: string): boolean {
  return /(?:^|[/_.-])(?:xml|import|imports|soap|saml|sso|svg|rss|wsdl|manifest|manifests|feed|feeds|upload|uploads|parse|backup|backups|archive|archives)(?:$|[/_.-])/i.test(path)
}

export function pathHasTemplateHint(path: string): boolean {
  return /(?:^|[/_.-])(?:render|preview|template|templates|layout|layouts|report|reports|docs?|pages?|email|emails|snippet|snippets)(?:$|[/_.-])/i.test(path)
}

export function pathHasSearchHint(path: string): boolean {
  return /(?:^|[/_.-])(?:search|searches|lookup|find|filter|query|queries|browse|catalog)(?:$|[/_.-])/i.test(path)
}

/** A route whose shape says it runs an operator-supplied host/command probe. */
export function pathHasCommandHint(path: string): boolean {
  return /(?:^|[/_.-])(?:diag|diagnostics?|exec|execute|command|cmd|shell|ping|nslookup|lookup|resolve|whois|healthcheck|system)(?:$|[/_.-])/i.test(path)
}

export function pathHasPrivilegedHint(path: string): boolean {
  return /(?:^|[/_.-])(?:admin|internal|manage|management|staff|superuser|privileged|permission|permissions|role|roles|impersonate|grant|feature[-_]?flag|backoffice)(?:$|[/_.-])/i.test(path)
}

export function pathHasRedirectHint(path: string): boolean {
  return /(?:^|[/_.-])(?:redirect|return|callback|continue|resume|sso|oauth|authorize|checkout|download|export|next)(?:$|[/_.-])/i.test(path)
}

/** A ranking score for triage priority. Pure and stable; no network access. */
export function endpointRiskScore(endpoint: EngineEndpoint): number {
  const bare = endpoint.pathTemplate.split('?')[0] || '/'
  if (isStaticOrBaselinePath(bare)) return -100
  let score = typeof endpoint.riskScore === 'number' ? endpoint.riskScore : 30
  const method = endpoint.method.toUpperCase()
  const params = endpoint.params ?? []
  if (params.length > 0) score += Math.min(15, params.length * 5)
  if (hasDynamicIdSegment(bare)) score += 18
  if (method === 'POST') score += 12
  else if (method === 'PATCH' || method === 'PUT') score += 10
  if (pathHasSearchHint(bare)) score += 18
  if (pathHasFileHint(bare)) score += 16
  if (pathHasUrlHint(bare)) score += 16
  if (pathHasXmlHint(bare)) score += 20
  if (/graphql/i.test(bare)) score += 25
  if (pathHasTemplateHint(bare)) score += 14
  if (pathHasPrivilegedHint(bare)) score += 14
  if (pathHasRedirectHint(bare)) score += 10
  if (/(?:token|tokens|key|keys|secret|secrets|activity|audit|config|settings)/i.test(bare)) score += 10
  if (/(?:^|\/)(?:login|auth|token|sso|whoami|session)(?:\/|$)/i.test(bare)) score += 6
  if (endpoint.source === 'conventional') score -= 15
  if ((endpoint.sinkKinds ?? []).length > 0) score += 10
  const depth = bare.split('/').filter(Boolean).length
  if (depth > 5) score -= 5
  return score
}

/** Collapse `<collection>/:id`, `<collection>/{id}` and renamed-placeholder variants of one route. */
export function collapseRouteVariants(endpoints: readonly EngineEndpoint[]): EngineEndpoint[] {
  const shapeOf = (pathTemplate: string): string => (pathTemplate.split('?')[0] || '/')
    .replace(/\/(?::[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])/g, '/:id')
  const byShape = new Map<string, EngineEndpoint>()
  // Canonical iteration order: the store returns risk-ordered rows whose ties are broken by random
  // row ids, so variant merging must not depend on arrival order. Every key is a total order over
  // the fields a route is identified by.
  const ordered = [...endpoints].sort(compareEngineEndpoints)
  for (const endpoint of ordered) {
    const key = `${endpoint.origin}|${endpoint.method.toUpperCase()}|${shapeOf(endpoint.pathTemplate)}`
    const prior = byShape.get(key)
    if (!prior) {
      byShape.set(key, endpoint)
      continue
    }
    const preferCurrent = endpoint.params.length > prior.params.length ||
      (endpoint.params.length === prior.params.length && (endpoint.riskScore ?? 0) > (prior.riskScore ?? 0)) ||
      (endpoint.params.length === prior.params.length && (endpoint.riskScore ?? 0) === (prior.riskScore ?? 0) &&
        endpoint.pathTemplate < prior.pathTemplate)
    const keep = preferCurrent ? endpoint : prior
    const other = preferCurrent ? prior : endpoint
    const mergedParams = [...keep.params]
    for (const param of other.params) {
      if (!mergedParams.some(existing => existing.name === param.name && existing.location === param.location)) {
        mergedParams.push(param)
      }
    }
    byShape.set(key, { ...keep, params: mergedParams })
  }
  return [...byShape.values()]
}

/** Stable total order for engine endpoints: origin, method, path template, then id as last resort. */
function compareEngineEndpoints(a: EngineEndpoint, b: EngineEndpoint): number {
  return a.origin.localeCompare(b.origin) ||
    a.method.toUpperCase().localeCompare(b.method.toUpperCase()) ||
    a.pathTemplate.localeCompare(b.pathTemplate) ||
    String(a.id).localeCompare(String(b.id))
}

/** Rank-risk the surface: static assets/soft baselines sink, injectable/id-bearing routes rise. */
export function rankEndpoints(endpoints: readonly EngineEndpoint[]): EngineEndpoint[] {
  return endpoints
    .map(endpoint => ({ endpoint, score: endpointRiskScore(endpoint) }))
    .filter(item => item.score > -50)
    .sort((a, b) => b.score - a.score ||
      a.endpoint.pathTemplate.length - b.endpoint.pathTemplate.length ||
      a.endpoint.pathTemplate.localeCompare(b.endpoint.pathTemplate) ||
      a.endpoint.origin.localeCompare(b.endpoint.origin) ||
      a.endpoint.method.toUpperCase().localeCompare(b.endpoint.method.toUpperCase()) ||
      String(a.endpoint.id).localeCompare(String(b.endpoint.id)))
    .map(item => item.endpoint)
}

// ---------------------------------------------------------------------------------------------
// Generic parameter inference (route semantics only; every candidate is still probe-verified)
// ---------------------------------------------------------------------------------------------

const placeholderSeg = /^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/
const protocolParam = /^(?:client[_-]?id|client[_-]?secret|redirect[_-]?uri|response[_-]?type|grant[_-]?type|scope|state|nonce|code|code[_-]challenge|code[_-]challenge[_-]method|audience|prompt|login[_-]hint|access[_-]token|refresh[_-]token|id[_-]token|assertion|signature|sig|continue|return_to)$/i

export function searchParamNames(path: string): string[] {
  if (/(?:logs?|journals?|audit)/i.test(path)) return ['filter', 'q', 'query']
  if (/(?:graphql)/i.test(path)) return []
  return ['q', 'query', 'term', 'keyword']
}

/** A declared parameter that plausibly carries free text (not an identifier, paging or sort key). */
export function isTextualParam(name: string): boolean {
  if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(name)) return false
  return !/(?:^|_)(?:id|uuid|uid|key|token|secret|password|page|limit|offset|cursor|count|size|amount|price|qty|quantity|num|number|index|sort|order|dir|direction|since|until|from|to|date|time|timestamp|at|version)$/i.test(name)
}

// ---------------------------------------------------------------------------------------------
// Explicit parameter / risk ranking (v6 Phase 1)
// ---------------------------------------------------------------------------------------------
//
// Name heuristics are *scores*, never eligibility gates. The structural inputs are the declared
// schema type, the value shape the target itself returned, the parameter family (identifier,
// number, URL, path, XML, JWT), the HTTP method semantics and whether the route requires auth.

export type ParamValueShape = 'url' | 'path' | 'xml' | 'jwt' | 'uuid' | 'number' | 'email' | 'text' | 'unknown'

/** Classify a value the target returned. Pure and bounded (no network). */
export function classifyValueShape(value: string): ParamValueShape {
  const raw = value.trim()
  if (!raw) return 'unknown'
  if (/^https?:\/\/[^\s]{1,300}$/i.test(raw)) return 'url'
  if (/^(?:\.{0,2}\/|[A-Za-z]:\\|[^\s]{1,200}\.(?:pdf|txt|log|csv|json|xml|zip))$/i.test(raw) && /[/\\.]/.test(raw)) return 'path'
  if (/^<\??[\s\S]{1,400}>/.test(raw)) return 'xml'
  if (/^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/.test(raw)) return 'jwt'
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(raw)) return 'uuid'
  if (/^-?\d{1,18}$/.test(raw)) return 'number'
  if (/^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,}$/.test(raw)) return 'email'
  return 'text'
}

/** Name-shape family: id/number/url/path/xml/jwt. Used as one score input, never a gate. */
export function paramNameShape(name: string): ParamValueShape | 'id' {
  const lower = name.toLowerCase()
  const camelEnd = (suffixes: readonly string[]) => suffixes.some(suffix =>
    name.endsWith(suffix) || name.endsWith(suffix[0].toUpperCase() + suffix.slice(1)))
  if (/(?:^|[_-])(?:id|uuid|uid|ref|key|slug)$/.test(lower) || /^(?:id|uuid|uid|ref)$/.test(lower) || camelEnd(['id', 'uuid', 'uid', 'ref', 'key'])) return 'id'
  if (/(?:url|uri|href|callback|webhook|redirect|avatar|image|photo|logo|src|destination|return_to|returnto|next)$/.test(lower)) return 'url'
  if (/(?:path|file|filename|filepath|document|attachment|log|journal)$/.test(lower)) return 'path'
  if (/(?:xml|soap)/i.test(name) || /(?:payload|body|markup)$/.test(lower)) return 'xml'
  if (/(?:jwt|token|assertion|bearer|auth)$/.test(lower)) return 'jwt'
  if (/(?:page|limit|offset|cursor|count|size|qty|quantity|amount|price|total|num|number|index|since|until)$/.test(lower)) return 'number'
  return 'text'
}

export interface ParamRiskInput {
  /** HTTP method of the route the parameter belongs to. */
  method?: string
  /** Route is known to require authentication/privilege (from the surface graph). */
  authRequired?: boolean
  /** Route-level semantic hint. A soft +boost only, never an eligibility gate. */
  routeHint?: boolean
}

export interface RankedEngineParam {
  param: EngineParam
  score: number
  reasons: string[]
}

/**
 * Score one parameter as a probe target. Deterministic and inspectable:
 *  - declared type (schema) and observed value shape carry the most weight;
 *  - id/number/url/path/xml/jwt families are recognized structurally;
 *  - method semantics and auth requirement adjust priority;
 *  - English route/param hints are a small tie-breaker.
 */
export function scoreEngineParam(param: EngineParam, input: ParamRiskInput = {}): RankedEngineParam {
  const reasons: string[] = []
  let score = 0
  const bump = (value: number, reason: string) => { score += value; if (value !== 0) reasons.push(reason) }
  const declared = (param.declaredType ?? '').toLowerCase()
  if (declared) {
    if (['integer', 'number'].includes(declared)) bump(9, `declared:${declared}`)
    else if (declared === 'string') bump(6, 'declared:string')
    else if (declared === 'array' || declared === 'object') bump(4, `declared:${declared}`)
    else bump(3, `declared:${declared}`)
  }
  const shape = (param.observedShape ?? 'unknown') as ParamValueShape
  const shapeWeight: Record<string, number> = { url: 28, path: 24, xml: 26, jwt: 18, uuid: 14, email: 12, number: 10, text: 6, unknown: 0 }
  bump(shapeWeight[shape] ?? 0, `shape:${shape}`)
  const family = paramNameShape(param.name)
  const familyWeight: Record<string, number> = { id: 12, url: 16, path: 14, xml: 16, jwt: 10, number: 8, text: 4 }
  bump(familyWeight[family] ?? 0, `family:${family}`)
  bump(param.location === 'json' || param.location === 'form' ? 8 : param.location === 'query' ? 6 : 4, `location:${param.location}`)
  if (param.isObjectId || family === 'id' || shape === 'uuid') bump(6, 'identifier-shaped')
  const method = (input.method ?? '').toUpperCase()
  if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') bump(8, `method:${method}`)
  else if (method === 'GET') bump(4, 'method:GET')
  if (input.authRequired) bump(6, 'auth-required')
  if (input.routeHint) bump(5, 'route-hint')
  if (param.isCsrf) bump(-40, 'csrf-token')
  if (/(?:^|_)(?:csrf|xsrf|nonce|authenticity)/i.test(param.name)) bump(-40, 'csrf-token')
  return { param, score, reasons }
}

/** Rank parameters for probe priority (highest first, stable on name/location/declared type). */
export function rankEngineParams(params: readonly EngineParam[], input: ParamRiskInput = {}): RankedEngineParam[] {
  return params
    .map(param => scoreEngineParam(param, input))
    .sort((a, b) => b.score - a.score ||
      a.param.name.localeCompare(b.param.name) ||
      a.param.location.localeCompare(b.param.location) ||
      (a.param.declaredType ?? '').localeCompare(b.param.declaredType ?? '') ||
      (a.param.observedShape ?? '').localeCompare(b.param.observedShape ?? ''))
}

export function fileParamNames(path: string): string[] {
  if (/(?:logs?|journals?|audit|stream|view)/i.test(path)) return ['file', 'logFile', 'name', 'path']
  if (/(?:receipt|invoice|statement|label|manifest|export|report)/i.test(path)) return ['file', 'document', 'name', 'path']
  return ['file', 'path', 'name']
}

export function urlParamNames(path: string): string[] {
  if (/(?:avatar|image|photo|logo|picture|thumbnail|media)/i.test(path)) return ['src', 'avatarUrl', 'imageUrl', 'pictureUrl', 'source']
  if (/(?:webhook|hook|callback)/i.test(path)) return ['callbackUrl', 'url', 'endpoint']
  if (/(?:integration|connector|fetch|proxy|remote|link)/i.test(path)) return ['url', 'endpoint', 'target']
  return ['url', 'target', 'endpoint']
}

export function redirectParamNames(path: string): string[] {
  if (/(?:sso|oauth|authorize|openid|login)/i.test(path)) return ['next', 'returnTo', 'returnUrl', 'redirect', 'redirect_uri']
  if (/(?:checkout|return)/i.test(path)) return ['next', 'returnUrl', 'returnTo', 'redirect']
  if (/(?:download|export)/i.test(path)) return ['url', 'next', 'returnTo', 'redirect']
  return ['url', 'next', 'redirect', 'returnTo']
}

/** Body fields a render/evaluate route plausibly reads (route semantics, not a route wordlist). */
export function templateParamNames(path: string): string[] {
  if (/(?:email|mail|message)/i.test(path)) return ['body', 'content', 'template', 'text', 'source']
  if (/(?:snippet|page|docs?|report|preview|render|layout|template)/i.test(path)) {
    return ['template', 'templateSrc', 'content', 'layout', 'source', 'body', 'text']
  }
  return ['content', 'body', 'text', 'source']
}

/** Body fields a host/command diagnostic route plausibly reads. */
export function commandParamNames(path: string): string[] {
  if (/(?:ping|nslookup|lookup|resolve|whois|diag|diagnostics?)/i.test(path)) {
    return ['host', 'hostname', 'endpointHost', 'target', 'address', 'ip', 'domain', 'command']
  }
  return ['command', 'cmd', 'host', 'target', 'input', 'query', 'script']
}

function inferredParam(name: string, location: SurfaceParamLocation): EngineParam {
  return { name, location, isObjectId: /(?:^|[_-])(?:id|uuid|uid|ref|key)$/i.test(name) }
}

/** Fill in the parameter names the surface never exposed, from route semantics. */
export function inferEndpointParams(endpoint: EngineEndpoint): EngineParam[] {
  const out: EngineParam[] = []
  const seen = new Set<string>()
  const push = (param: EngineParam) => {
    const key = `${param.name}|${param.location}`
    if (seen.has(key)) return
    if (protocolParam.test(param.name)) return
    if (!/^[A-Za-z0-9_.\-[\]]{1,64}$/.test(param.name)) return
    seen.add(key)
    out.push(param)
  }
  for (const param of endpoint.params ?? []) push(param)
  const bare = endpoint.pathTemplate.split('?')[0] || '/'
  const method = endpoint.method.toUpperCase()
  if (method === 'GET') {
    if (pathHasSearchHint(bare)) for (const name of searchParamNames(bare)) push(inferredParam(name, 'query'))
    if (pathHasFileHint(bare)) for (const name of fileParamNames(bare)) push(inferredParam(name, 'query'))
    if (pathHasUrlHint(bare)) for (const name of urlParamNames(bare)) push(inferredParam(name, 'query'))
    if (pathHasRedirectHint(bare)) for (const name of redirectParamNames(bare)) push(inferredParam(name, 'query'))
    for (const match of endpoint.pathTemplate.matchAll(/[?&]([A-Za-z0-9_.\-[\]]{1,64})=/g)) push(inferredParam(match[1], 'query'))
  } else if (method !== 'DELETE') {
    if (pathHasSearchHint(bare)) for (const name of searchParamNames(bare)) push(inferredParam(name, 'json'))
    if (pathHasUrlHint(bare)) for (const name of urlParamNames(bare)) push(inferredParam(name, 'json'))
  }
  return out
}

function collectionPathOf(pathTemplate: string): string | null {
  const bare = pathTemplate.split('?')[0] || '/'
  const segs = bare.split('/').filter(Boolean)
  const idx = segs.findIndex(seg => placeholderSeg.test(seg))
  if (idx > 0) return `/${segs.slice(0, idx).join('/')}`
  if (idx < 0 && !hasDynamicIdSegment(bare)) return bare
  return null
}

// ---------------------------------------------------------------------------------------------
// Authz readback inference
//
// A mutating authorization proof only proves impact when a *separate* GET shows the state change;
// the mutation's own acknowledgement is an echo (see deterministic-specs synthAuthz). The engine
// owns the harvest and the discovered route map, so it names that reading route here. Everything is
// derived from routes and identifiers the target itself exposed: no app or route literals.
// ---------------------------------------------------------------------------------------------

/** A discovered GET route that can read state back, normalized to a single `{{id}}` placeholder. */
interface ReadRoute {
  /** Path with every dynamic segment collapsed to `{{id}}` (at most one placeholder per route). */
  path: string
  segments: string[]
  /** Index of the `{{id}}` segment; -1 for a collection (no identifier) read. */
  placeholderIndex: number
  paramName?: string
}

/** Routes whose name marks the caller's own identity, read back with the mutating actor's persona. */
const identityReadRe = /(?:^|\/)(?:profile|me|whoami|session|account|self)(?:\/|$)/i

function readRouteParamName(segment: string): string | undefined {
  return segment.match(/^:([A-Za-z0-9_]+)$/)?.[1] ?? segment.match(/^\{([A-Za-z0-9_]+)\}$/)?.[1]
}

/**
 * Index every discovered GET route by origin. Built from the full surface (including baseline-ish
 * routes, which can still be the only readable detail for an object) and independent of iteration
 * order, so hypothesis output stays deterministic.
 */
function buildReadRouteIndex(endpoints: readonly EngineEndpoint[]): Map<string, ReadRoute[]> {
  const index = new Map<string, ReadRoute[]>()
  for (const endpoint of endpoints) {
    if (endpoint.method.toUpperCase() !== 'GET') continue
    const bare = endpoint.pathTemplate.split('?')[0] || '/'
    if (bare === '' || bare === '/') continue
    const raw = bare.split('/').filter(Boolean)
    const placeholders = raw.filter(segment => placeholderSeg.test(segment))
    // A readback the synthesizer cannot fill (`fillId` resolves `{{id}}` only) is not a readback.
    if (placeholders.length > 1) continue
    if (raw.length === 0) continue
    const placeholderIndex = raw.findIndex(segment => placeholderSeg.test(segment))
    const segments = raw.map(segment => (placeholderSeg.test(segment) ? '{{id}}' : segment))
    const path = `/${segments.join('/')}`
    const list = index.get(endpoint.origin) ?? []
    const paramName = placeholderIndex >= 0 ? readRouteParamName(raw[placeholderIndex]!) : undefined
    const existing = list.find(route => route.path === path)
    if (existing) {
      // Same shape discovered with different identifier spellings (`:id` / `:invoiceId`): keep a
      // canonical name so the index does not depend on arrival order.
      if (paramName && (!existing.paramName || paramName.localeCompare(existing.paramName) < 0)) existing.paramName = paramName
      continue
    }
    list.push({ path, segments, placeholderIndex, ...(paramName ? { paramName } : {}) })
    index.set(endpoint.origin, list)
  }
  for (const list of index.values()) list.sort((a, b) => a.path.localeCompare(b.path))
  return index
}

/** Specificity of a GET route as the readback of one mutated object (0 = not a reader). */
function scoreObjectReadback(
  mutation: { segments: string[]; placeholderIndex: number },
  route: ReadRoute,
  idParamName: string | undefined,
): number {
  const mutationPathLength = mutation.placeholderIndex + 1
  // Same REST shape: `PATCH /api/invoices/{{id}}` -> `GET /api/invoices/{{id}}`.
  if (route.placeholderIndex === mutation.placeholderIndex && route.segments.length === mutation.segments.length) {
    const same = route.segments.every((segment, i) => i === mutation.placeholderIndex || segment === mutation.segments[i])
    if (same) return 100
  }
  // Detail of the same object with a trailing action verb dropped: `/members/{{id}}/avatar`.
  if (route.placeholderIndex === mutation.placeholderIndex && route.segments.length === mutationPathLength) {
    const same = route.segments.every((segment, i) => segment === mutation.segments[i])
    if (same) return 90
  }
  if (route.placeholderIndex >= 0 && route.placeholderIndex === route.segments.length - 1 && route.segments.length > 1) {
    const routeNoun = route.segments[route.placeholderIndex - 1]!.toLowerCase()
    const mutationNoun = mutation.segments[mutation.placeholderIndex - 1]?.toLowerCase()
    // A sibling listing of the same record family: `DELETE /api/admin/people/{{id}}` -> `GET /api/people/{{id}}`.
    if (routeNoun && routeNoun === mutationNoun) return 70
    // Same identifier contract on a different prefix (`/api/v1/...` legacy aliases).
    if (idParamName && route.paramName && route.paramName.toLowerCase() === idParamName.toLowerCase()) return 60
  }
  // A collection that contains the object: proves a delete by disappearance.
  if (route.placeholderIndex < 0 && route.segments.length === mutation.placeholderIndex) {
    const same = route.segments.every((segment, i) => segment === mutation.segments[i])
    if (same) return 50
  }
  return 0
}

interface AuthzReadbackHint {
  path: string
  persona?: string
}

/**
 * Pick the GET route that can observe a mutating authz hypothesis:
 *  - object routes prefer the object's own detail readback (dropping action verbs), then a sibling
 *    detail of the same record family, then the containing collection;
 *  - function routes prefer a discovered observable GET (status route or sibling collection sharing
 *    the action's noun) and never reuse a path whose only response is the mutation echo;
 *  - the mutating actor's own identity route is the last resort for self-service account mutations.
 */
function inferAuthzReadback(input: {
  bare: string
  method: string
  functionLevel: boolean
  idParamName?: string
  queryIdParam?: string
  readRoutes: readonly ReadRoute[]
  selfIds: readonly string[]
  probePersona?: string
}): AuthzReadbackHint | null {
  if (input.functionLevel) {
    const segments = input.bare.split('/').filter(Boolean)
    if (segments.length === 0) return null
    const samePath = input.readRoutes.find(route => route.placeholderIndex < 0 && route.segments.length === segments.length &&
      route.segments.every((segment, i) => segment === segments[i]))
    if (samePath) return { path: samePath.path }
    // Action noun -> the collection/detail the function's state shows up in
    // (`/api/admin/feature-flags` -> `GET /api/feature-flags`).
    const tokens = new Set(segments[segments.length - 1]!
      .split(/[-_.]+/)
      .flatMap(token => token.split(/(?=[A-Z])/))
      .map(token => token.toLowerCase())
      .filter(token => token.length >= 3))
    if (tokens.size === 0) return null
    const scored = input.readRoutes
      .filter(route => route.placeholderIndex < 0 && route.path !== input.bare)
      .map(route => {
        const routeTokens = new Set(route.segments.flatMap(segment => segment
          .split(/[-_.]+/)
          .flatMap(token => token.split(/(?=[A-Z])/))
          .map(token => token.toLowerCase())))
        let score = 0
        for (const routeToken of routeTokens) {
          const singular = routeToken.replace(/s$/, '')
          for (const token of tokens) if (token === routeToken || token.replace(/s$/, '') === singular) score += 1
        }
        return { route, score }
      })
      .filter(item => item.score > 0)
      .sort((a, b) => b.score - a.score || a.route.segments.length - b.route.segments.length ||
        a.route.path.length - b.route.path.length || a.route.path.localeCompare(b.route.path))
    return scored[0] ? { path: scored[0].route.path } : null
  }
  if (input.method === 'GET') return null

  const rawSegments = input.bare.split('/').filter(Boolean)
  // Query-string object references keep their identifier in the read too.
  if (input.queryIdParam) {
    const collection = input.readRoutes.find(route => route.placeholderIndex < 0 &&
      route.segments.length === rawSegments.length && route.segments.every((segment, i) => segment === rawSegments[i]))
    if (collection) return { path: `${collection.path}?${encodeURIComponent(input.queryIdParam)}={{id}}` }
  }
  const placeholderIndex = rawSegments.findIndex(segment => placeholderSeg.test(segment))
  if (placeholderIndex <= 0) return null
  // Normalize the mutation's own placeholder so it compares against the read index (`{{id}}`).
  const segments = rawSegments.map(segment => (placeholderSeg.test(segment) ? '{{id}}' : segment))
  const mutation = { segments, placeholderIndex }
  const ranked = input.readRoutes
    .map(route => ({ route, score: scoreObjectReadback(mutation, route, input.idParamName) }))
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score || a.route.segments.length - b.route.segments.length ||
      a.route.path.length - b.route.path.length || a.route.path.localeCompare(b.route.path))
  if (ranked[0]) return { path: ranked[0].route.path }
  // Self-service: the mutating actor's own identity route is the only observable state.
  if (input.selfIds.length > 0 && input.probePersona) {
    const identity = input.readRoutes.find(route => route.placeholderIndex < 0 && identityReadRe.test(route.path))
    if (identity) return { path: identity.path, persona: input.probePersona }
  }
  return null
}

/**
 * Role a privileged function needs, when the route shape is role-exclusive and the control persona
 * outranks the probe persona. This is what makes a function-level mutation a vertical (BFLA) claim:
 * the replay has no bogus-id negative control, so the role differential has to be declared.
 */
function authzRequiredRoleFor(
  privileged: boolean,
  control?: EnginePersona,
  probe?: EnginePersona,
): 'viewer' | 'member' | 'admin' | 'owner' | undefined {
  if (!privileged || !control || !probe || control.handle === probe.handle) return undefined
  const rank: Record<EnginePersona['privilege'], number> = { viewer: 0, member: 1, admin: 2 }
  if (rank[control.privilege] <= rank[probe.privilege]) return undefined
  return control.privilege
}

export interface EnumerateOptions {
  tier: number
  personas: readonly EnginePersona[]
  maxHypotheses?: number
  /** Request budget the probe loop may spend; used to size class quotas fairly. */
  maxRequests?: number
  classes?: ReadonlySet<string>
}

function personaPicks(personas: readonly EnginePersona[]): {
  owner?: EnginePersona
  crossTenant?: EnginePersona
  lower?: EnginePersona
  admin?: EnginePersona
} {
  const members = personas.filter(p => p.privilege !== 'admin')
  const owner = members.find(p => p.privilege === 'member') ?? members[0] ?? personas[0]
  const crossTenant = owner
    ? personas.find(p => p.handle !== owner.handle && p.privilege !== 'admin' && p.tenant && owner.tenant && p.tenant !== owner.tenant)
    : undefined
  const lower = owner
    ? personas.find(p => p.privilege === 'viewer' && p.tenant === owner.tenant)
    : undefined
  const admin = personas.find(p => p.privilege === 'admin')
  return { owner, crossTenant: crossTenant ?? (owner ? personas.find(p => p.handle !== owner.handle) : undefined), lower, admin }
}

function semanticValue(name: string, observed?: string): string | number | boolean {
  if (observed !== undefined && observed !== '') return observed
  const lower = name.toLowerCase()
  if (/(?:^|_)(?:is|has)_|enabled|active|verified|admin|paid|approved|marketing|optin|boolean|visibility/.test(lower)) return true
  if (/(qty|quantity|count|limit|amount|price|total|number|num|page|size|offset|age)/.test(lower)) return 1
  if (/email/.test(lower)) return 'guardian@example.test'
  if (/(url|uri|link|callback|webhook|redirect|avatar|image|src)/.test(lower)) return 'http://guardian-control.invalid/'
  if (/(date|time|timestamp|at)$/.test(lower)) return '2026-01-01T00:00:00Z'
  if (/(id|ref|key|code|token)$/.test(lower)) return '1'
  return 'guardian'
}

function siblingBody(fields: readonly string[], values: Record<string, string[]>, exclude?: string): Record<string, unknown> {
  const body: Record<string, unknown> = {}
  for (const field of fields.slice(0, 8)) {
    if (field === exclude) continue
    if (!/^[A-Za-z0-9_.\-[\]]{1,64}$/.test(field)) continue
    body[field] = semanticValue(field, values[field]?.[0])
  }
  return body
}

function isObjectIdParam(param: EngineParam): boolean {
  return param.isObjectId === true || /(?:^|[_-])(?:id|uuid|uid|ref|key)$/i.test(param.name)
}

/**
 * Enumerate generic, bounded hypotheses for the ranked surface. Pure: callers pass the harvesting
 * profile observed on the target; nothing here is app-specific and nothing is submitted directly.
 */
export function enumerateHypotheses(
  endpoints: readonly EngineEndpoint[],
  harvests: ReadonlyMap<string, EndpointHarvest>,
  options: EnumerateOptions,
): EngineHypothesis[] {
  const all = new Map<string, EngineHypothesis>()
  const picks = personaPicks(options.personas)
  const add = (hyp: EngineHypothesis) => {
    if (options.classes && !options.classes.has(hyp.intent)) return
    if (all.has(hyp.key)) return
    all.set(hyp.key, hyp)
  }
  // A route's own collection is authoritative, but object parameters often point at a sibling
  // resource (assets?projectId -> /api/spaces). Keep a bounded per-origin pool as a fallback.
  const originIdPool = new Map<string, string[]>()
  const readRoutesByOrigin = buildReadRouteIndex(endpoints)
  // Destructive authz proofs must leave at least one live object for the replay: the probe matrix
  // exercises identifiers, so a probe that deletes the very id the replay needs produces a
  // "control read 404" rejection. Reserve one record-family identifier up front and keep it out of
  // every destructive matrix (see `reservedVictimId`).
  const reservedDestructiveIds = new Set<string>()
  for (const endpoint of endpoints) {
    const harvest = harvests.get(endpoint.id)
    const pool = originIdPool.get(endpoint.origin) ?? []
    for (const id of [...(harvest?.ownerIds ?? []), ...(harvest?.otherIds ?? [])]) {
      if (/^[A-Za-z0-9_.:-]{1,128}$/.test(id) && !pool.includes(id)) pool.push(id)
    }
    originIdPool.set(endpoint.origin, pool.slice(0, 24))
  }
  const globalIds = (harvest: EndpointHarvest | undefined, origin: string): string[] => {
    const ids = [
      ...(harvest?.ownerIds ?? []),
      ...(harvest?.otherIds ?? []),
      ...(originIdPool.get(origin) ?? []),
    ].filter(id => /^[A-Za-z0-9_.:-]{1,128}$/.test(id))
    return [...new Set(ids)].slice(0, 5)
  }
  // Field names observed anywhere on the origin (route maps and config documents publish the real
  // body-field spelling as a scalar value). Bounded and evidence-derived: it never invents a name
  // the target did not itself expose; the route-semantic fallbacks stay last.
  const originSchemaPool = new Map<string, string[]>()
  const originViewerIds = new Map<string, string[]>()
  for (const endpoint of endpoints) {
    const harvest = harvests.get(endpoint.id)
    if (!harvest) continue
    if (harvest.viewerIds?.length) {
      const ids = originViewerIds.get(endpoint.origin) ?? []
      for (const id of harvest.viewerIds) if (!ids.includes(id)) ids.push(id)
      originViewerIds.set(endpoint.origin, ids.slice(0, 4))
    }
    const pool = originSchemaPool.get(endpoint.origin) ?? []
    for (const value of [...harvest.fields, ...Object.values(harvest.values).flat(), ...harvest.seedValues]) {
      if (value.length < 2 || value.length > 40) continue
      if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(value)) continue
      if (!pool.includes(value)) pool.push(value)
    }
    originSchemaPool.set(endpoint.origin, pool.slice(0, 120))
  }

  // Collection-level evidence: a detail PATCH often exposes its writable schema only on the
  // collection/detail GET. Key by (origin, collection) — never by a route noun.
  const collectionEvidence = new Map<string, { fields: string[]; values: Record<string, string[]>; evidence: HarvestEvidence }>()
  for (const endpoint of endpoints) {
    const harvest = harvests.get(endpoint.id)
    if (!harvest) continue
    const bare = endpoint.pathTemplate.split('?')[0] || '/'
    const collection = collectionPathOf(bare) ?? (hasDynamicIdSegment(bare) ? null : bare)
    if (!collection || collection === '/') continue
    const key = `${endpoint.origin}|${collection}`
    const entry = collectionEvidence.get(key) ?? { fields: [], values: {}, evidence: {} }
    for (const field of [...harvest.fields, ...Object.keys(harvest.values)]) {
      if (!entry.fields.includes(field)) entry.fields.push(field)
    }
    for (const [field, values] of Object.entries(harvest.values)) {
      const bucket = entry.values[field] ?? []
      for (const value of values) if (!bucket.includes(value)) bucket.push(value)
      entry.values[field] = bucket.slice(0, 4)
    }
    const evidence = entry.evidence
    evidence.contentDisposition = evidence.contentDisposition || harvest.evidence?.contentDisposition
    evidence.xml = evidence.xml || harvest.evidence?.xml
    if (harvest.evidence?.location && !evidence.location) evidence.location = harvest.evidence.location
    for (const evidenceKey of ['urlValues', 'jwtValues', 'sensitiveFields', 'headerNames'] as const) {
      const incoming = harvest.evidence?.[evidenceKey]
      if (!incoming?.length) continue
      const bucket = evidence[evidenceKey] ?? []
      for (const value of incoming) if (bucket.length < 8 && !bucket.includes(value)) bucket.push(value)
      evidence[evidenceKey] = bucket
    }
    collectionEvidence.set(key, entry)
  }

  for (const endpoint of endpoints) {
    const bare = endpoint.pathTemplate.split('?')[0] || '/'
    if (isStaticOrBaselinePath(bare)) continue
    const method = endpoint.method.toUpperCase() as EngineHypothesis['method']
    const harvest = harvests.get(endpoint.id)
    const inferred = inferEndpointParams(endpoint)
    const hasIdPath = hasDynamicIdSegment(bare)
    const objectIdParam = inferred.find(p => p.location === 'query' && isObjectIdParam(p))
    const privileged = pathHasPrivilegedHint(bare)
    const siblingEvidence = collectionEvidence.get(
      `${endpoint.origin}|${collectionPathOf(bare) ?? (hasIdPath ? '' : bare)}`,
    )
    const observedFields = [...new Set([...(harvest?.fields ?? []), ...(siblingEvidence?.fields ?? [])])]
    const observedValues: Record<string, string[]> = {
      ...(siblingEvidence?.values ?? {}),
      ...(harvest?.values ?? {}),
    }
    const observedEvidence: HarvestEvidence = {
      ...(siblingEvidence?.evidence ?? {}),
      ...(harvest?.evidence ?? {}),
    }
    // Explicit, inspectable parameter/risk ranking. Declared schema type, observed value shape,
    // parameter family, method semantics and auth requirement drive priority; route nouns only
    // add a small tie-break boost.
    const shapeOf = (name: string): ParamValueShape =>
      harvest?.shapes?.[name] ?? (observedValues[name]?.[0] ? classifyValueShape(observedValues[name][0]) : 'unknown')
    const rankedParams = rankEngineParams(
      inferred.map(param => ({ ...param, observedShape: param.observedShape ?? shapeOf(param.name) })),
      {
        method,
        authRequired: privileged,
        routeHint: pathHasSearchHint(bare) || pathHasUrlHint(bare) || pathHasXmlHint(bare) ||
          pathHasFileHint(bare) || pathHasTemplateHint(bare) || pathHasCommandHint(bare) ||
          pathHasRedirectHint(bare) || pathHasPrivilegedHint(bare),
      },
    )
    const rankedFor = (predicate: (param: EngineParam) => boolean, bonus = 0): RankedEngineParam[] =>
      rankedParams
        .filter(item => predicate(item.param))
        .map(item => ({ ...item, score: item.score + bonus }))
        .sort((a, b) => b.score - a.score || a.param.name.localeCompare(b.param.name))
    const pathSegments = bare.split('/').filter(Boolean)
    const lastSegment = pathSegments[pathSegments.length - 1] ?? ''
    const idIsLast = hasIdPath && placeholderSeg.test(lastSegment)
    const mutating = method === 'POST' || method === 'PUT' || method === 'PATCH'
    const sensitiveRead = /(?:^|[/_.-])(?:tokens?|keys?|secrets?|audit|auditlog|activity|logs?|config|export|apikeys?)(?:$|[/_.-])/i.test(bare)
    const activeQuery = new Set(harvest?.activeQueryParams ?? [])
    const ownerId = harvest?.ownerIds[0] ?? harvest?.otherIds[0] ?? '1'
    /** Concrete path for non-authz probes: resolve a dynamic segment with a harvested owner id. */
    const resolvedPath = hasIdPath
      ? bare.replace(idSegmentRe, `/${encodeURIComponent(ownerId)}`)
      : bare

    // --- Authorization / BOLA / IDOR / BFLA ------------------------------------------------
    if (options.tier >= 2 && picks.owner && picks.crossTenant &&
        (options.tier >= 3 || method === 'GET' || method === 'POST' || method === 'DELETE')) {
      const authzOwner = privileged ? (picks.admin ?? picks.owner) : picks.owner
      const authzOther = privileged
        ? (sensitiveRead && !mutating ? (picks.crossTenant ?? picks.lower) : (picks.lower ?? picks.owner ?? picks.crossTenant))
        : picks.crossTenant
      let ids = globalIds(harvest, endpoint.origin)
      const functionLevel = !hasIdPath && !objectIdParam
      // A destructive matrix consumes the objects it addresses. Exclude ids already reserved by a
      // sibling destructive hypothesis, then reserve one live record-family victim for this chain.
      if (method === 'DELETE') ids = ids.filter(id => !reservedDestructiveIds.has(id))
      let reservedVictimId: string | undefined
      if (method === 'DELETE' && privileged && idIsLast) {
        const placeholderIdx = pathSegments.findIndex(segment => placeholderSeg.test(segment))
        const noun = placeholderIdx > 0 ? pathSegments[placeholderIdx - 1] : undefined
        const family: string[] = []
        if (noun) {
          const singular = noun.replace(/s$/i, '')
          for (const candidate of endpoints) {
            if (candidate.origin !== endpoint.origin || candidate.method.toUpperCase() !== 'GET') continue
            const candidatePath = candidate.pathTemplate.split('?')[0] || '/'
            if (hasDynamicIdSegment(candidatePath)) continue
            const candidateSegments = candidatePath.split('/').filter(Boolean)
            const last = (candidateSegments[candidateSegments.length - 1] ?? '').replace(/s$/i, '')
            if (last !== singular) continue
            for (const id of harvests.get(candidate.id)?.ownerIds ?? []) {
              if (/^[A-Za-z0-9_.:-]{1,128}$/.test(id) && !family.includes(id)) family.push(id)
            }
          }
        }
        const viewerOwned = originViewerIds.get(endpoint.origin) ?? []
        const pool = family.filter(id => !viewerOwned.includes(id))
        // Skip the first record (usually the tenant principal, which a role-scoped delete refuses)
        // and any id the lower actor owns, so the reserved victim is a genuinely deletable colleague.
        const pick = pool[1] ?? pool[0] ?? family[1] ?? family[0]
        // Keep at least one other id so the matrix can still establish the route signal.
        if (pick && ids.length > 1) {
          reservedVictimId = pick
          reservedDestructiveIds.add(pick)
          ids = ids.filter(id => id !== pick)
        }
      }
      // Object-authorization on a stable resource route: the identifier must be the last path
      // segment, a query filter, or (for a mutating privileged action) an id followed by a
      // role/grant verb. Rendered "view/card/public" subroutes are shared surfaces, and running a
      // cross-actor matrix there produces genuine-but-unreported noise.
      const objectRunnable = !functionLevel && ids.length > 0 && (
        idIsLast || Boolean(objectIdParam) || (mutating && privileged)
      )
      // Function-level authorization: mutating privileged actions (BFLA), or a read of a
      // token/secret/audit surface (the disclosure targets). A generic admin listing read is
      // deliberately left to the agentic pass.
      // Function-level authorization: mutating privileged actions (BFLA). Read-only privileged
      // collections are handled by the credential-exposure intent, which requires unmasked-value
      // evidence; a viewer merely reading a feed is not a confirmed impact on its own.
      const functionRunnable = functionLevel && mutating && privileged
      const runnable = objectRunnable || functionRunnable
      if (runnable && authzOwner && authzOther && authzOwner.handle !== authzOther.handle) {
        let pathAndQuery = endpoint.pathTemplate.split('?')[0]
        if (hasIdPath) pathAndQuery = bare.replace(idSegmentRe, '/{{id}}')
        else if (objectIdParam) {
          pathAndQuery = `${bare}?${encodeURIComponent(objectIdParam.name)}={{id}}`
        }
        const idParamName = objectIdParam?.name ?? (hasIdPath ? bare.match(/:([A-Za-z0-9_]+)/)?.[1] : undefined)
        // Mutating authz proofs need a separate read of the mutated state; name it from the route
        // map the harvest already produced, and declare the role a privileged function requires.
        const readback = method === 'GET' ? null : inferAuthzReadback({
          bare,
          method,
          functionLevel,
          ...(idParamName ? { idParamName } : {}),
          ...(objectIdParam ? { queryIdParam: objectIdParam.name } : {}),
          readRoutes: readRoutesByOrigin.get(endpoint.origin) ?? [],
          selfIds: harvest?.otherIds ?? [],
          ...(authzOther ? { probePersona: authzOther.handle } : {}),
        })
        const requiredRole = method === 'GET' ? undefined : authzRequiredRoleFor(privileged, authzOwner, authzOther)
        const score = endpointRiskScore(endpoint) + (hasIdPath || objectIdParam ? 20 : 0) + (privileged ? 15 : 0)
        add({
          key: `authz|${endpoint.id}|${objectIdParam?.name ?? (hasIdPath ? 'path' : 'fn')}`,
          endpoint,
          probeClass: 'authz_matrix',
          intent: 'authz',
          method: method === 'POST' || method === 'DELETE' ? method : (method === 'PUT' || method === 'PATCH' ? method : 'GET'),
          pathAndQuery,
          ownerPersona: authzOwner.handle,
          otherPersona: authzOther.handle,
          resourceIds: ids,
          functionLevel,
          idParamName,
          ...(readback ? { readbackPath: readback.path } : {}),
          ...(readback?.persona ? { readbackPersona: readback.persona } : {}),
          ...(requiredRole ? { authzRequiredRole: requiredRole } : {}),
          ...(reservedVictimId ? { reservedVictimId } : {}),
          jsonBody: mutating && /(?:role|grant|permission|privilege|promote|assign)(?:\/|$)/i.test(bare)
            ? { ...siblingBody(harvest?.fields ?? [], harvest?.values ?? {}), role: 'admin', grant: 'admin', level: 'admin' }
            : siblingBody(harvest?.fields ?? [], harvest?.values ?? {}),
          ...(sensitiveRead && !mutating
            ? { secretScan: true, viewerPersona: picks.lower?.handle ?? authzOther.handle }
            : {}),
          ...(mutating ? { csrfBind: true } : {}),
          risk: score + (sensitiveRead ? 25 : 0),
        })
      }
    }

    // Query-parameter object references (`/api/assets?projectId=`): the surface rarely exposes the
    // filter name, but the collection's own records carry the owning id field. Try the observed
    // snake_case/camelCase spellings with the values that field took in the owner's response.
    if (options.tier >= 2 && method === 'GET' && !hasIdPath && picks.owner && picks.crossTenant && harvest && /(?:file|asset|document|attachment|list|archive|links?)/i.test(bare)) {
      const idFields = harvest.fields
        .filter(field => /(?:^|[_-])(?:project|owner|tenant|team|org|account|user|parent|customer|space|invoice|order|file|asset|ticket|issue|report|job|group|member)_?id$|^iid$/i.test(field))
        .filter(field => !/^(?:id|uuid|uid)$/i.test(field))
        .slice(0, 2)
      const conventionalIdFields = /(?:^|\/)(?:links?|integrations?)(?:\/|$)/i.test(bare)
        ? ['iid']
        : /(?:^|\/)(?:assets?|files?|documents?)(?:\/|$)/i.test(bare) ? ['projectId', 'project_id'] : []
      for (const field of [...new Set([...idFields, ...conventionalIdFields])]) {
        const snake = field.replace(/Id$/, '_id')
        const camel = snake.replace(/_([a-z])/g, (_m, ch: string) => ch.toUpperCase())
        const names = [...new Set([field, snake, camel])].slice(0, 2)
        const fieldValues = (harvest.values[field] ?? []).filter(value => /^[A-Za-z0-9_.:-]{1,128}$/.test(value))
        const resourceIds = [...new Set([...fieldValues, ...globalIds(harvest, endpoint.origin)])].slice(0, 4)
        if (resourceIds.length === 0) continue
        for (const name of names) {
          add({
            key: `authz|${endpoint.id}|${name}`,
            endpoint,
            probeClass: 'authz_matrix',
            intent: 'authz',
            method: 'GET',
            pathAndQuery: `${bare}?${encodeURIComponent(name)}={{id}}`,
            ownerPersona: picks.owner.handle,
            otherPersona: picks.crossTenant.handle,
            resourceIds,
            functionLevel: false,
            idParamName: name,
            risk: endpointRiskScore(endpoint) + 12 + (/(?:tokens?|keys?|secrets?|audit|activity|logs?|links?|integrations?)/i.test(bare) ? 25 : 0),
          })
        }
      }
    }

    // --- SQL injection ----------------------------------------------------------------------
    // Eligibility is structural: a declared or observed query/body parameter the target reads.
    // Textual/identifier/number families rank first; route search hints only boost priority.
    if (method === 'GET' || method === 'POST') {
      const sqlCandidates = rankedFor(param =>
        ((param.location === 'query' && method === 'GET') || (param.location === 'json' && method !== 'GET')) &&
        !param.isCsrf &&
        !['url', 'path', 'xml', 'jwt'].includes(paramNameShape(param.name)) &&
        param.observedShape !== 'url' && param.observedShape !== 'xml',
      )
        .map(item => ({
          ...item,
          score: item.score +
            (['text', 'id', 'number'].includes(paramNameShape(item.param.name)) ? 10 : 0) +
            (activeQuery.has(item.param.name) ? 8 : 0) +
            (method === 'GET' && pathHasSearchHint(bare) ? 6 : 0),
        }))
        .sort((a, b) => b.score - a.score || a.param.name.localeCompare(b.param.name))
      const params = sqlCandidates.slice(0, 2).map(item => item.param)
      for (const param of params) {
        const numeric = /^(?:id|page|limit|offset|qty|quantity|amount|price|count|num|index)$/i.test(param.name)
        const observed = harvest?.values[param.name]?.[0] ?? harvest?.seedValues.find(v => v.length >= 3 && v.length <= 40)
        const baselineValue = numeric ? '1' : (observed && !/[<>{}\\]/.test(observed) ? observed.slice(0, 48) : 'guardian')
        add({
          key: `sqli_boolean|${endpoint.id}|${param.name}`,
          endpoint,
          probeClass: 'sqli_boolean',
          intent: 'sqli',
          method: method === 'GET' ? 'GET' : 'POST',
          pathAndQuery: resolvedPath,
          param,
          location: param.location,
          ownerPersona: picks.owner?.handle,
          jsonBody: method === 'GET' ? undefined : siblingBody(harvest?.fields ?? [], harvest?.values ?? {}, param.name),
          baselineValue,
          risk: endpointRiskScore(endpoint) + 12 + (pathHasSearchHint(bare) ? 12 : 0),
        })
      }
    }

    // --- Path traversal ---------------------------------------------------------------------
    // Structural evidence: a file-shaped declared parameter, an attachment response, or a route
    // that already published a filename value. Route nouns are only a priority tie-breaker.
    const fileishParams = rankedFor(param => param.location === 'query' &&
      (paramNameShape(param.name) === 'path' || param.observedShape === 'path' ||
        /^(?:file|filepath|filename|path|name|document|doc|attachment|download|src|source|template)$/i.test(param.name)))
    const fileEvidence = pathHasFileHint(bare) ||
      fileishParams.length > 0 ||
      observedEvidence.contentDisposition === true ||
      (observedValues.filename?.length ?? 0) > 0 ||
      Object.values(observedValues).some(values => values.some(value => classifyValueShape(value) === 'path'))
    if (method === 'GET' && fileEvidence) {
      // Preserve the surface's own parameter order among file-shaped candidates: the declared name
      // (`logFile`) beats a generic inferred fallback (`file`) when both are plausible.
      const params = inferred
        .filter(param => param.location === 'query')
        .filter(param => paramNameShape(param.name) === 'path' || param.observedShape === 'path' ||
          /^(?:file|filepath|filename|path|name|document|doc|attachment|download|logfile|src|source|template)$/i.test(param.name))
        .filter(param => activeQuery.size === 0 || activeQuery.has(param.name))
        .slice(0, 1)
      for (const param of params) {
        const observed = harvest?.values[param.name]?.find(v => v.length >= 2 && v.length <= 60 && !/[<>{}\\]/.test(v))
        add({
          key: `path_traversal_benign|${endpoint.id}|${param.name}`,
          endpoint,
          probeClass: 'path_traversal_benign',
          intent: 'traversal',
          method: 'GET',
          pathAndQuery: resolvedPath,
          param,
          location: 'query',
          ownerPersona: picks.owner?.handle,
          baselineValue: observed,
          risk: endpointRiskScore(endpoint) + (/(?:^|\/)(?:download|downloads|file|files|export|exports)(?:\/|$)/i.test(bare) ? 44 : pathHasFileHint(bare) ? 26 : 12) + (/^(?:filepath|path|document|file|name)$/i.test(param.name) ? 8 : 0),
        })
      }
    }

    // --- SSRF -------------------------------------------------------------------------------
    // A URL-consuming *write* is the SSRF source. Eligibility is structural: a declared body
    // parameter whose family or observed value is URL-shaped, or a collection response that
    // already publishes URL values (the target itself fetches them). Trigger routes are paired as
    // the second-order fetch step, never probed as if they accepted a URL body.
    const triggerShaped = hasDynamicIdSegment(bare) && /(?:ping|test|trigger|fetch|replay|send|deliver|run|execute|verify)$/i.test(lastSegment)
    const urlBodyParams = rankedFor(param =>
      (param.location === 'json' || param.location === 'form') &&
      (paramNameShape(param.name) === 'url' || param.observedShape === 'url'))
    const collectionPublishesUrls = (observedEvidence.urlValues?.length ?? 0) > 0
    if ((method === 'POST' || method === 'PUT') && !triggerShaped &&
        (urlBodyParams.length > 0 || collectionPublishesUrls)) {
      const declared = urlBodyParams.slice(0, 3).map(item => item.param)
      const params = declared.length > 0
        ? declared
        : [inferredParam(urlParamNames(bare)[0] ?? 'url', 'json')]
      // Second-order: a sibling trigger route for the same resource collection.
      const trigger = endpoints.find(candidate => {
        const candidateBare = candidate.pathTemplate.split('?')[0] || '/'
        if (candidate.method.toUpperCase() !== 'POST') return false
        const parts = candidateBare.split('/').filter(Boolean)
        const parent = `/${parts.slice(0, -1).join('/')}`
        return parts.length >= 2 && /(?:ping|test|trigger|fetch|replay|send|deliver|run)/i.test(parts[parts.length - 1] ?? '') &&
          (parent === bare || parent.startsWith(`${bare}/`) || bare.startsWith(`${parent}/`))
      })
      for (const param of params) {
        add({
          key: `ssrf_canary|${endpoint.id}|${param.name}`,
          endpoint,
          probeClass: 'ssrf_canary',
          intent: 'ssrf',
          method: method === 'PUT' ? 'PUT' : 'POST',
          pathAndQuery: resolvedPath,
          param,
          location: param.location,
          ownerPersona: picks.owner?.handle,
          jsonBody: siblingBody(harvest?.fields ?? [], harvest?.values ?? {}, param.name),
          ssrfParams: [param.name],
          ...(trigger && method === 'POST'
            ? { triggerPath: (trigger.pathTemplate.split('?')[0] || '/').replace(idSegmentRe, '/{{id}}') }
            : {}),
          risk: endpointRiskScore(endpoint) + 12,
        })
      }
    }

    // --- XXE --------------------------------------------------------------------------------
    // Eligibility is wire-format evidence: the route serves XML, or a declared/observed body value
    // is XML-shaped. The route noun is only a priority tie-breaker.
    const xmlBodyEvidence = Object.values(observedValues)
      .some(values => values.some(value => classifyValueShape(value) === 'xml'))
    const declaredXmlParam = inferred.some(param =>
      (param.location === 'json' || param.location === 'form') &&
      (paramNameShape(param.name) === 'xml' || param.observedShape === 'xml'))
    if (method === 'POST' && (observedEvidence.xml === true || xmlBodyEvidence || declaredXmlParam)) {
      add({
        key: `xxe_canary|${endpoint.id}`,
        endpoint,
        probeClass: 'xxe_canary',
        intent: 'xxe',
        method: 'POST',
        pathAndQuery: resolvedPath,
        ownerPersona: picks.owner?.handle,
        risk: endpointRiskScore(endpoint) + 15,
      })
    }

    // --- Template evaluation and shell-command sinks -----------------------------------------
    // Both families only make sense on a route whose own shape consumes renderable text or an
    // operator-supplied host/command. Candidate field names come from what the target published
    // (route map/config document) first, then the route's semantic vocabulary. URL/file-consuming
    // routes are excluded structurally (a declared URL/path body field), not by route noun.
    const hasUrlOrFilePathBody = urlBodyParams.length > 0 || fileishParams.length > 0
    if (mutating && !hasUrlOrFilePathBody) {
      const declaredBody = inferred.filter(p => p.location === 'json' || p.location === 'form')
      const published = originSchemaPool.get(endpoint.origin) ?? []
      const candidatesFor = (pattern: RegExp, fallbacks: string[]): EngineParam[] => {
        const names = [...new Set([
          ...declaredBody.map(p => p.name),
          ...published.filter(value => pattern.test(value)),
          ...fallbacks,
        ])].slice(0, 3)
        return names.map(name => declaredBody.find(p => p.name === name) ?? inferredParam(name, 'json'))
      }
      const templateShaped = Object.values(observedValues).some(values =>
        values.some(value => /\{\{|\$\{|<%|\{%/.test(value)))
      if (pathHasTemplateHint(bare) || templateShaped) {
        for (const param of candidatesFor(/template|layout|markup|content|snippet|source|body|text|render/i, templateParamNames(bare)).slice(0, 2)) {
          add({
            key: `ssti_math|${endpoint.id}|${param.name}`,
            endpoint,
            probeClass: 'ssti_math',
            intent: 'ssti',
            method,
            pathAndQuery: resolvedPath,
            param,
            location: 'json',
            ownerPersona: picks.owner?.handle,
            baselineValue: 'guardian',
            jsonBody: siblingBody(harvest?.fields ?? [], harvest?.values ?? {}, param.name),
            risk: endpointRiskScore(endpoint) + 14,
          })
        }
      }
      if (pathHasCommandHint(bare)) {
        for (const param of candidatesFor(/host|hostname|target|address|domain|command|cmd|script|input|endpoint/i, commandParamNames(bare)).slice(0, 2)) {
          add({
            key: `command_injection|${endpoint.id}|${param.name}`,
            endpoint,
            probeClass: 'command_injection',
            intent: 'command_injection',
            method,
            pathAndQuery: resolvedPath,
            param,
            location: 'json',
            ownerPersona: picks.owner?.handle,
            baselineValue: '127.0.0.1',
            jsonBody: siblingBody(harvest?.fields ?? [], harvest?.values ?? {}, param.name),
            risk: endpointRiskScore(endpoint) + 14,
          })
        }
      }
    }

    // --- Workflow step skip ------------------------------------------------------------------
    // A POST transition on an identified resource whose sibling read exposes workflow state, or
    // whose terminal-verb shape is a soft hint. The repeat-transition probe is the discriminator.
    const statusLike = observedFields.some(field => /^(?:status|state|stage|phase|workflow_state|step)$/i.test(field)) ||
      (siblingEvidence?.fields ?? []).some(field => /^(?:status|state|stage|phase|workflow_state|step)$/i.test(field))
    const actionVerb = /(?:confirm|approve|complete|finalize|fulfil|ship|activate|publish|accept|settle)$/i
    if (method === 'POST' && hasIdPath && actionVerb.test(lastSegment)) {
      const collection = collectionPathOf(bare)
      const barePath = (candidate: EngineEndpoint) => candidate.pathTemplate.split('?')[0] || '/'
      const list = collection
        ? endpoints.find(candidate => candidate.method.toUpperCase() === 'GET' && barePath(candidate) === collection)
        : undefined
      const detail = collection
        ? endpoints.find(candidate => {
            const candidatePath = barePath(candidate)
            return candidate.method.toUpperCase() === 'GET' && candidatePath.startsWith(`${collection}/`) &&
              hasDynamicIdSegment(candidatePath) &&
              candidatePath.split('/').filter(Boolean).length === collection.split('/').filter(Boolean).length + 1
          })
        : undefined
      const creator = collection
        ? endpoints.find(candidate => candidate.method.toUpperCase() === 'POST' && barePath(candidate) === collection)
        : undefined
      if (list || detail || creator) {
        add({
          key: `workflow_invariant|${endpoint.id}`,
          endpoint,
          probeClass: 'workflow_invariant',
          intent: 'workflow',
          method: 'POST',
          pathAndQuery: bare.replace(idSegmentRe, '/{{id}}'),
          ownerPersona: picks.owner?.handle,
          repeatTransition: true,
          ...(list ? { workflowListPath: barePath(list) } : {}),
          ...(detail ? { workflowReadPath: barePath(detail) } : {}),
          workflowTargetTemplate: bare,
          jsonBody: siblingBody(harvest?.fields ?? [], harvest?.values ?? {}),
          risk: endpointRiskScore(endpoint) + 8 + (statusLike ? 10 : 0),
        })
      }
    }

    // --- Open redirect ----------------------------------------------------------------------
    // URL/redirect-shaped declared or observed parameter, independent of the route noun.
    const redirectShapedParams = inferred.filter(p => p.location === 'query' &&
      /^(?:next|redirect|redirect_uri|redirecturl|return|returnurl|returnto|return_to|dest|destination|continue|continueurl)$/i.test(p.name))
    if (method === 'GET' && (pathHasRedirectHint(bare) || redirectShapedParams.length > 0)) {
      const candidates = new Set(redirectParamNames(bare))
      const declared = inferred.filter(p => p.location === 'query' && (candidates.has(p.name) || /^(?:next|url|uri|redirect|return\w*|callback\w*|dest|target|continue)$/i.test(p.name)))
      const active = declared.filter(p => activeQuery.size === 0 || activeQuery.has(p.name))
      const params = (active.length > 0 ? active : declared).slice(0, 2)
      if (params.length === 0) params.push(inferredParam(redirectParamNames(bare)[0] ?? 'url', 'query'))
      for (const param of params) {
        add({
          key: `open_redirect_differential|${endpoint.id}|${param.name}`,
          endpoint,
          probeClass: 'open_redirect_differential',
          intent: 'redirect',
          method: 'GET',
          pathAndQuery: resolvedPath,
          param,
          location: 'query',
          ownerPersona: picks.owner?.handle,
          risk: endpointRiskScore(endpoint) + (pathHasRedirectHint(bare) ? 26 : 10),
        })
      }
    }

    // --- Reflected XSS ----------------------------------------------------------------------
    // Any string query parameter the target actually reads is a reflection candidate; the probe
    // itself is the benign canary, so a parameter that is not reflected simply costs one request.
    const xssCandidates = inferred.filter(p => p.location === 'query' &&
      (pathHasSearchHint(bare) || activeQuery.has(p.name) ||
        (isTextualParam(p.name) &&
          ((observedValues[p.name]?.length ?? 0) > 0 || (p.declaredType ?? '').toLowerCase() === 'string'))))
    if (method === 'GET' && xssCandidates.length > 0) {
      const rank = (name: string): number => {
        if (activeQuery.has(name)) return 0
        if (/^(?:q|query|search)$/i.test(name)) return 1
        if (/^(?:term|keyword|s)$/i.test(name)) return 2
        return 3
      }
      const ordered = [...xssCandidates].sort((a, b) => rank(a.name) - rank(b.name))
      for (const param of ordered.slice(0, pathHasSearchHint(bare) ? 3 : 1)) {
        add({
          key: `xss_context|${endpoint.id}|${param.name}`,
          endpoint,
          probeClass: 'xss_context',
          intent: 'xss',
          method: 'GET',
          pathAndQuery: resolvedPath,
          param,
          location: 'query',
          ownerPersona: picks.owner?.handle,
          risk: endpointRiskScore(endpoint) + (pathHasSearchHint(bare) || activeQuery.has(param.name) ? 30 : 8) + (pathHasSearchHint(bare) && !hasIdPath ? 12 : 0),
        })
      }
    }

    // --- CSRF -------------------------------------------------------------------------------
    // Structural: a cookie-authenticated state mutation is any POST whose sibling GET exposes a
    // mutable state field (or whose creation has a readable detail route). The probe binds the
    // session jar and compares with/without CSRF material, so a non-cookie route stays silent.
    if (method === 'POST' && urlBodyParams.length === 0) {
      const detailReadPath = hasIdPath
        ? bare.replace(`/${lastSegment}`, '')
        : null
      const getSibling = endpoints.find(candidate => {
        if (candidate.origin !== endpoint.origin || candidate.method.toUpperCase() !== 'GET') return false
        const candidatePath = candidate.pathTemplate.split('?')[0] || '/'
        return candidatePath === bare || (detailReadPath !== null && candidatePath === detailReadPath)
      })
      const siblingHarvest = getSibling ? harvests.get(getSibling.id) : undefined
      const createDetail = !hasIdPath
        ? endpoints.find(candidate => {
            if (candidate.origin !== endpoint.origin || candidate.method.toUpperCase() !== 'GET') return false
            const candidatePath = candidate.pathTemplate.split('?')[0] || '/'
            return candidatePath.startsWith(`${bare}/`) && hasDynamicIdSegment(candidatePath)
          })
        : undefined
      const csrfFields = [...new Set([...observedFields, ...(siblingHarvest?.fields ?? [])])]
      const csrfValues: Record<string, string[]> = { ...(siblingHarvest?.values ?? {}), ...observedValues }
      const stateField = csrfFields.find(field => /^(?:name|title|label|company|timezone|email|status|state|plan|tier|enabled|active|value|notifications|digest|locale|language|amount|total|price)$/i.test(field))
        ?? csrfFields.find(field => typeof csrfValues[field]?.[0] === 'string' && !/(?:^|_)id$/i.test(field))
      const createReadTemplate = createDetail ? (createDetail.pathTemplate.split('?')[0] || '') : undefined
      if ((getSibling && stateField) || createReadTemplate) {
        const bodyField = stateField ?? (/refund|payment|credit|transfer|amount|price/i.test(bare) ? 'amount' : 'value')
        add({
          key: `csrf_state_change|${endpoint.id}|${stateField}`,
          endpoint,
          probeClass: 'csrf_state_change',
          intent: 'csrf',
          method: 'POST',
          pathAndQuery: resolvedPath,
          readPath: getSibling
            ? (getSibling.pathTemplate.split('?')[0] || '/').replace(idSegmentRe, `/${encodeURIComponent(ownerId)}`)
            : resolvedPath,
          stateField: stateField ?? bodyField,
          bodyField,
          ...(createReadTemplate ? { createReadTemplate } : {}),
          session: 'csrf',
          ownerPersona: picks.owner?.handle,
          jsonBody: siblingBody(csrfFields, csrfValues, bodyField),
          risk: endpointRiskScore(endpoint) + 8,
        })
      }
    }

    // --- Credential exposure on a read surface ----------------------------------------------
    // A read that the target itself publishes credential-shaped values from is scanned with a
    // non-entitled viewer actor; the anonymous denial in the same matrix is the control. The
    // selection is response-evidence driven (secret fingerprints) or a credential-surface route.
    const credentialSurface = /(?:^|\/)(?:tokens?|keys?|apikeys?|links?|integrations?|audit|auditlog|activity|logs?|config|settings|credentials?|secrets?|exports?)(?:\/|$)/i.test(bare)
    const secretEvidence = (observedEvidence.sensitiveFields?.length ?? 0) > 0 ||
      (observedEvidence.headerNames ?? []).some(name => /^(?:set-cookie|authorization|x-api-key)$/i.test(name))
    if (method === 'GET' && (credentialSurface || secretEvidence)) {
      add({
        key: `secret_disclosure|${endpoint.id}`,
        endpoint,
        probeClass: 'authz_matrix',
        intent: 'secret_disclosure',
        method: 'GET',
        pathAndQuery: resolvedPath,
        ownerPersona: picks.owner?.handle,
        functionLevel: !hasIdPath && !objectIdParam,
        secretScan: true,
        ...((picks.lower?.handle ?? picks.crossTenant?.handle)
          ? { viewerPersona: (picks.lower?.handle ?? picks.crossTenant?.handle)! }
          : {}),
        risk: endpointRiskScore(endpoint) + (credentialSurface ? 34 : 18),
      })
    }

    // --- GraphQL ----------------------------------------------------------------------------
    // Body shape `{query, variables}` identifies a GraphQL endpoint even without a `/graphql` noun.
    const graphqlShaped = method === 'POST' && (
      /graphql/i.test(bare) ||
      (inferred.some(p => p.location === 'json' && /^query$/i.test(p.name)) &&
        inferred.some(p => p.location === 'json' && /^(?:variables|operationName)$/i.test(p.name)))
    )
    if (graphqlShaped && picks.owner && picks.crossTenant) {
      // Introspection is often disabled. Derive candidate root fields from the discovered
      // collection nouns and pair each root with ids read from that collection for both actors.
      const graphqlRoots = new Set<string>()
      const graphqlSeedsByRoot: Record<string, string[]> = {}
      for (const candidate of endpoints) {
        if (candidate.method.toUpperCase() !== 'GET') continue
        const candidatePath = candidate.pathTemplate.split('?')[0] || '/'
        const segments = candidatePath.split('/').filter(segment => segment && !placeholderSeg.test(segment))
        const last = segments[segments.length - 1] ?? ''
        if (!/^[a-z][a-z0-9_-]{2,30}s?$/i.test(last)) continue
        if (/^(?:api|v1|v2|me|session|health|config|settings|admin|search|logs?|audit|csrf|login|logout|tokens?|keys?|hooks?|links?|jobs?|docs?)$/i.test(last)) continue
        const singular = last.replace(/s$/i, '')
        const ids = globalIds(harvests.get(candidate.id), candidate.origin)
        if (ids.length === 0) continue
        for (const root of [singular, last]) {
          graphqlRoots.add(root)
          graphqlSeedsByRoot[root] = ids
        }
      }
      add({
        key: `graphql_audit|${endpoint.id}`,
        endpoint,
        probeClass: 'graphql_audit',
        intent: 'graphql',
        method: 'POST',
        pathAndQuery: bare,
        ownerPersona: picks.owner.handle,
        otherPersona: picks.crossTenant.handle,
        resourceIds: globalIds(harvest, endpoint.origin),
        graphqlRoots: [...graphqlRoots]
          .sort((a, b) => {
            const priority = ['account', 'user', 'organization', 'org', 'team', 'workspace', 'project', 'invoice', 'order', 'customer', 'member', 'ticket', 'issue', 'document', 'file', 'report', 'product']
            const rank = (name: string): number => {
              const idx = priority.findIndex(entry => name.toLowerCase() === entry || name.toLowerCase().replace(/s$/, '') === entry)
              return idx === -1 ? priority.length : idx
            }
            return rank(a) - rank(b) || a.localeCompare(b)
          })
          .slice(0, 12),
        graphqlSeedsByRoot,
        jsonBody: {},
        risk: endpointRiskScore(endpoint) + 25,
      })
    }

    // --- Auth-protocol / JWT ----------------------------------------------------------------
    // Evidence: the target returned 3-segment base64url values (or a session/token surface whose
    // response carries them). The probe mutates the persona's own token; when the persona session
    // is not a JWT, the broker refuses the mutation, so this cannot manufacture a finding.
    const identityClaims: Record<string, string> = {}
    for (const field of ['email', 'mail', 'sub', 'userId', 'id', 'tenant', 'org', 'store', 'workspace', 'team', 'role']) {
      const value = observedValues[field]?.[0]
      if (value && value.length <= 120) identityClaims[field] = value
    }
    const jwtEvidence = options.tier >= 2 && method === 'GET' && picks.owner &&
      ((observedEvidence.jwtValues?.length ?? 0) > 0 || credentialSurface)
    if (jwtEvidence) {
      add({
        key: `auth_protocol|${endpoint.id}`,
        endpoint,
        probeClass: 'auth_protocol_audit',
        intent: 'auth_protocol',
        method: 'GET',
        pathAndQuery: resolvedPath,
        ownerPersona: picks.owner?.handle,
        tokenFields: Object.keys(observedValues).filter(field => /(?:token|jwt|auth|credential)/i.test(field)).slice(0, 3),
        ...(Object.keys(identityClaims).length > 0 ? { identityClaims } : {}),
        risk: endpointRiskScore(endpoint) + 18 +
          ((observedEvidence.jwtValues?.length ?? 0) > 0 ? 40 : 0) +
          (/(?:^|\/)(?:session|tokens?|auth|whoami|me)(?:\/|$)/i.test(bare) ? 16 : 0),
      })
    }

    // --- Webhook signature bypass -----------------------------------------------------------
    // Evidence: a mutating route that declares a signature/HMAC header, or a receiver-shaped write
    // route with a readable detail/collection sibling. Delivery bodies are built from observed
    // fields; the probe itself requires an accepted unsigned delivery plus a read-back/ack.
    const signatureHeader = inferred.find(p => p.location === 'header' && /signature|hmac|^x-.*sig/i.test(p.name))?.name
    const receiverShaped = method === 'POST' && !hasIdPath && !graphqlShaped && !pathHasUrlHint(bare) &&
      (Boolean(signatureHeader) || /(?:webhook|hooks?|receive|deliver|callback|events?)/i.test(bare))
    if (receiverShaped && picks.owner) {
      const delivery: Record<string, unknown> = {}
      for (const field of observedFields.slice(0, 8)) delivery[field] = semanticValue(field, observedValues[field]?.[0])
      if (Object.keys(delivery).length === 0) {
        delivery.event = 'guardian.verification'
        delivery.type = 'guardian.verification'
      }
      const detail = endpoints.find(candidate => {
        const candidatePath = candidate.pathTemplate.split('?')[0] || '/'
        return candidate.origin === endpoint.origin && candidate.method.toUpperCase() === 'GET' &&
          candidatePath.startsWith(`${bare}/`) && hasDynamicIdSegment(candidatePath)
      })
      const stateField = observedFields.find(field => /^(?:status|state|processed|received|ok|count|total|events?)$/i.test(field))
      add({
        key: `webhook_signature_bypass|${endpoint.id}`,
        endpoint,
        probeClass: 'webhook_signature_bypass',
        intent: 'webhook',
        method: 'POST',
        pathAndQuery: resolvedPath,
        ownerPersona: picks.owner?.handle,
        webhookBody: delivery,
        ...(signatureHeader ? { webhookHeader: signatureHeader } : {}),
        ...(detail ? { readPath: (detail.pathTemplate.split('?')[0] || '/').replace(idSegmentRe, `/${encodeURIComponent(ownerId)}`) } : {}),
        ...(stateField ? { stateField } : {}),
        risk: endpointRiskScore(endpoint) + 16 + (/(?:webhook|hooks?|receive|deliver|callback)(?:\/|$)/i.test(bare) ? 34 : 0),
      })
    }

    // --- Mass assignment: create-shaped POST or an identified PATCH/PUT write -----------------
    // A privileged/ownership field written through an ordinary update body is the same overpost
    // class as on create. The route's real method is kept; the object id must be concrete.
    const massPath = method === 'POST' && !hasIdPath
      ? bare
      : (method === 'PATCH' || method === 'PUT')
        ? (idIsLast ? resolvedPath
          : objectIdParam ? `${bare}?${encodeURIComponent(objectIdParam.name)}=${encodeURIComponent(ownerId)}`
            : null)
        : null
    if (massPath) {
      const massFields = observedFields
      const privilegeField = /(role|roles|admin|permission|privilege|grant|level|tenant|tenant_id|owner|owner_id|team|team_id|org|org_id|plan|tier|verified|email_verified|is_admin|visibility|amount|total|price|payment_state|status|state)/i
      const fieldRank = (field: string): number =>
        /role|roles|permission|privilege|grant|admin|tenant|owner|org|team/i.test(field) ? 0
          : /amount|total|price|payment_state|status|state/i.test(field) ? 1 : 2
      const observedPrivilege = massFields.filter(f => privilegeField.test(f))
        .sort((a, b) => fieldRank(a) - fieldRank(b))
      // On an update route, ordinary editable columns (name, amount, status) are not evidence of
      // overposting by themselves. Restrict the PATCH/PUT candidate set to ownership/privilege and
      // settlement fields that are never a normal client-editable property.
      const updateSensitive = /role|roles|permission|permissions|privilege|grant|level|admin|is_admin|isAdmin|tenant|tenant_id|owner|owner_id|team|team_id|org|org_id|plan|tier|verified|email_verified|visibility|payment_state|return_url/i
      const isUpdate = method === 'PATCH' || method === 'PUT'
      const candidateSource = isUpdate
        ? [...massFields.filter(f => updateSensitive.test(f)), 'role', 'permission', 'tenant_id', 'owner_id', 'plan', 'verified']
        : [...observedPrivilege, ...['role', 'permission', 'tenant_id', 'owner_id', 'plan', 'verified']]
      const candidates = [...new Set(candidateSource)]
        .filter(f => /^[A-Za-z0-9_.-]{1,64}$/.test(f)).slice(0, 10)
      const eligible = isUpdate
        ? massFields.some(f => updateSensitive.test(f)) || pathHasPrivilegedHint(bare)
        : observedPrivilege.length > 0 || pathHasPrivilegedHint(bare)
      if (candidates.length > 0 && eligible) {
        const values: Record<string, string | boolean | number> = {}
        for (const field of candidates) {
          const observed = harvest?.otherValues[field]?.[0]
          if (observed !== undefined && observed.length <= 64) values[field] = observed
        }
        // The cross-tenant persona's tenant label is itself a legitimate overpost value even when
        // the collection response does not expose the owning tenant id field.
        if (picks.crossTenant?.tenant && values.tenant_id === undefined) values.tenant_id = picks.crossTenant.tenant
        // A role/privilege write must be performed by a genuinely lower-privileged actor on that
        // actor's own record: an owner editing its own row cannot demonstrate escalation.
        const roleField = candidates.find(f => /^(?:role|roles|permission|permissions|privilege|grant|level|is_admin|isAdmin|admin)$/i.test(f))
        const viewerIds = originViewerIds.get(endpoint.origin) ?? []
        const viewerTarget = isUpdate && roleField && picks.lower && viewerIds.length > 0
          ? viewerIds[0]
          : null
        // The impact monitor evaluates the writer's role after the mutation, so a self-escalation
        // cannot demonstrate an escalation. Choose a colleague from the same collection, skipping
        // the first (owning) record and the viewer's own id.
        const listIds = (harvest?.ownerIds ?? []).filter(id => /^[A-Za-z0-9_.:-]{1,128}$/.test(id))
        const colleagueTarget = viewerTarget
          ? (listIds.filter(id => id !== viewerTarget && id !== listIds[0])[0]
            ?? listIds.find(id => id !== viewerTarget)
            ?? viewerTarget)
          : null
        const roleTarget = colleagueTarget ?? viewerTarget
        const writer = viewerTarget ? picks.lower!.handle : picks.owner?.handle
        const targetPath = roleTarget && hasIdPath
          ? bare.replace(idSegmentRe, `/${encodeURIComponent(roleTarget)}`)
          : massPath
        add({
          key: `mass_assignment|${endpoint.id}`,
          endpoint,
          probeClass: 'mass_assignment',
          intent: 'mass_assignment',
          method: method === 'PATCH' ? 'PATCH' : method === 'PUT' ? 'PUT' : 'POST',
          pathAndQuery: targetPath,
          ownerPersona: writer,
          otherPersona: picks.crossTenant?.handle,
          candidateFields: candidates,
          candidateValues: values,
          jsonBody: siblingBody(massFields, observedValues),
          risk: endpointRiskScore(endpoint) + 10,
        })
      }
    }
  }

  const intentPriority: Record<string, number> = {
    // SQLi is deliberately last: error-based payloads legitimately return 5xx and can trip the
    // broker's defensive circuit, which pauses the run. Every non-5xx class gets its pass first.
    authz: 100, secret_disclosure: 98, graphql: 95, ssti: 94, command_injection: 93, workflow: 92,
    xxe: 90, ssrf: 88, traversal: 85,
    redirect: 75, xss: 65, mass_assignment: 60, stored_xss: 55, cache: 50, csrf: 45, sqli: 10,
  }
  // Quota selection, not a pure global slice: late classes (SQLi in particular) must not be
  // starved when a richer surface forms more authz/xxe/ssrf hypotheses than the cap.
  const baseQuotas: Record<string, number> = {
    // Quotas reserve breadth: an authz-heavy surface must not starve the other classes when the
    // global hypothesis cap is reached.
    authz: 26, secret_disclosure: 5, graphql: 2, xxe: 5, ssrf: 7, traversal: 6, redirect: 6,
    xss: 6, mass_assignment: 6, csrf: 4, cache: 2, stored_xss: 2, workflow: 3, webhook: 2,
    auth_protocol: 2, ssti: 3, command_injection: 3, sqli: 10,
  }
  const baseMax = options.maxHypotheses ?? defaultEngineMaxHypotheses
  // A probe costs ~11 requests (control/probe variants + read-back). Spend the request budget
  // instead of starving late classes behind a fixed hypothesis count.
  const slots = Math.min(150, Math.max(baseMax, Math.floor((options.maxRequests ?? defaultEngineMaxRequests) / 11)))
  const scale = Math.max(1, slots / baseMax)
  const quotas: Record<string, number> = Object.fromEntries(
    Object.entries(baseQuotas).map(([intent, quota]) => [intent, Math.max(quota, Math.ceil(quota * scale))]),
  )
  const max = slots
  const used: Record<string, number> = {}
  const selected: EngineHypothesis[] = []
  for (const hyp of [...all.values()].sort((a, b) =>
    (intentPriority[b.intent] ?? 0) - (intentPriority[a.intent] ?? 0) ||
    b.risk - a.risk ||
    a.key.localeCompare(b.key))) {
    if ((used[hyp.intent] ?? 0) >= (quotas[hyp.intent] ?? 4)) continue
    used[hyp.intent] = (used[hyp.intent] ?? 0) + 1
    selected.push(hyp)
    if (selected.length >= max) break
  }
  return selected
}

// ---------------------------------------------------------------------------------------------
// Harvesting
// ---------------------------------------------------------------------------------------------

interface JsonHarvest {
  ids: string[]
  fields: string[]
  values: Record<string, string[]>
  /** Runtime value shape per field (url/path/xml/jwt/uuid/number/email/text). */
  shapes: Record<string, ParamValueShape>
  textValues: string[]
  body: string
  evidence: HarvestEvidence
}

const credentialFieldRe = /(?:^|[_-])(?:access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|secret|secret[_-]?key|client[_-]?secret|password|passwd|private[_-]?key|signing[_-]?key|webhook[_-]?secret|credential|authorization)$/i
const jwtValueRe = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/

function harvestJson(body: string): JsonHarvest {
  const ids: string[] = []
  const values: Record<string, string[]> = {}
  const shapes: Record<string, ParamValueShape> = {}
  const textValues: string[] = []
  const evidence: HarvestEvidence = {}
  let parsed: unknown
  try { parsed = JSON.parse(body) } catch { return { ids, fields: [], values, shapes, textValues, body, evidence } }
  const walk = (node: unknown, depth: number): void => {
    if (depth > 5 || node === null || node === undefined) return
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 30)) walk(item, depth + 1)
      return
    }
    if (typeof node !== 'object') return
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (typeof value === 'string' || typeof value === 'number') {
        const stringValue = String(value)
        const idKey = /(?:^|_)(?:id|uuid|uid|sku|slug|key|ref|code|token)$/i.test(key)
        const ownerKey = /(?:^|_)(?:project|owner|tenant|team|org|account|parent|user|member|invoice|order|customer|ticket|issue)$/i.test(key)
        if (idKey && stringValue.length <= 128 && stringValue.length > 0) ids.push(stringValue)
        else if (ownerKey && /^(?:[A-Za-z]{1,8}[-_])?[A-Za-z0-9_.:-]*\d[A-Za-z0-9_.:-]*$/.test(stringValue) && stringValue.length <= 128) ids.push(stringValue)
        const bucket = values[key] ?? []
        if (bucket.length < 4) bucket.push(stringValue)
        values[key] = bucket
        if (!shapes[key] || shapes[key] === 'unknown' || shapes[key] === 'text') {
          const classified = classifyValueShape(stringValue)
          if (classified !== 'unknown') shapes[key] = classified
        }
        if (/^(?:name|title|label|slug|subject|description|text|term|query|filename|file)$/i.test(key) &&
            stringValue.length >= 3 && stringValue.length <= 48 && !/[<>{}\\]/.test(stringValue)) {
          textValues.push(stringValue)
        }
        // Wire-format and value-shape evidence: a URL value, a JWT-shaped token, a credential field.
        if (/^https?:\/\/[^\s]{1,300}$/i.test(stringValue)) {
          const urls = evidence.urlValues ?? []
          if (urls.length < 4 && !urls.includes(stringValue)) urls.push(stringValue.slice(0, 300))
          evidence.urlValues = urls
        }
        if (jwtValueRe.test(stringValue)) {
          const tokens = evidence.jwtValues ?? []
          if (tokens.length < 2) tokens.push(stringValue)
          evidence.jwtValues = tokens
        }
        if (credentialFieldRe.test(key) && stringValue.length >= 8 && stringValue.length <= 2048 &&
            !/^(?:redacted|\*+|null|undefined|none|false|true)$/i.test(stringValue)) {
          const fields = evidence.sensitiveFields ?? []
          if (fields.length < 6 && !fields.includes(key)) fields.push(key)
          evidence.sensitiveFields = fields
        }
      } else if (value && typeof value === 'object') {
        walk(value, depth + 1)
      }
    }
  }
  walk(parsed, 0)
  return {
    ids: [...new Set(ids)].filter(id => /^[A-Za-z0-9_.:-]{1,128}$/.test(id)),
    fields: [...new Set(Object.keys(values))],
    values,
    shapes,
    textValues: [...new Set(textValues)],
    body,
    evidence,
  }
}

/** Bounded GET harvest of the target's own responses; every exchange is recorded by the caller. */
class SurfaceHarvester {
  private readonly cache = new Map<string, Promise<JsonHarvest>>()
  private readonly inflight = new Set<string>()
  private readonly deps: Pick<DeterministicEngineInput, 'broker' | 'grant' | 'signal' | 'storage' | 'recordExchange'>
  private readonly log: (kind: string, message: string, data?: Record<string, unknown>) => void
  private readonly origin: string

  constructor(
    deps: Pick<DeterministicEngineInput, 'broker' | 'grant' | 'signal' | 'storage' | 'recordExchange'>,
    log: (kind: string, message: string, data?: Record<string, unknown>) => void,
    origin: string,
  ) {
    this.deps = deps
    this.log = log
    this.origin = origin
  }

  get(persona: string | undefined, pathAndQuery: string): Promise<JsonHarvest> {
    const key = `${persona ?? ''}|${pathAndQuery}`
    const cached = this.cache.get(key)
    if (cached) return cached
    const promise = this.fetch(persona, pathAndQuery)
    this.cache.set(key, promise)
    return promise
  }

  private async fetch(persona: string | undefined, pathAndQuery: string): Promise<JsonHarvest> {
    this.inflight.add(pathAndQuery)
    try {
      const exchange = await this.deps.broker.executeHttp({
        origin: this.origin,
        method: 'GET',
        pathAndQuery,
        ...(persona ? { persona } : {}),
        followRedirects: false,
        timeoutMs: 8_000,
      }, this.deps.grant, this.deps.signal)
      if (exchange.status >= 200 && exchange.status < 300) {
        try { this.deps.recordExchange?.(exchange) } catch { /* persistence is best-effort */ }
        const harvested = harvestJson(exchange.body)
        const headers = exchange.respHeaders ?? {}
        const evidence: HarvestEvidence = { ...harvested.evidence }
        if (/attachment|filename=/i.test(headers['content-disposition'] ?? '')) evidence.contentDisposition = true
        if (headers.location) evidence.location = headers.location.slice(0, 300)
        if (/xml/i.test(exchange.mediaType ?? '')) evidence.xml = true
        const headerNames = Object.keys(headers).map(name => name.toLowerCase())
        if (headerNames.length > 0) evidence.headerNames = headerNames.slice(0, 32)
        return { ...harvested, evidence }
      }
      return { ids: [], fields: [], values: {}, shapes: {}, textValues: [], body: '', evidence: {} }
    } catch {
      return { ids: [], fields: [], values: {}, shapes: {}, textValues: [], body: '', evidence: {} }
    } finally {
      this.inflight.delete(pathAndQuery)
    }
  }
}

function emptyHarvest(): EndpointHarvest {
  return { ownerIds: [], otherIds: [], fields: [], values: {}, otherValues: {}, seedValues: [], activeQueryParams: [], viewerIds: [] }
}

function mergeEvidence(target: EndpointHarvest, next: HarvestEvidence): void {
  if (!next || Object.keys(next).length === 0) return
  const evidence = target.evidence ?? {}
  evidence.contentDisposition = evidence.contentDisposition || next.contentDisposition
  evidence.xml = evidence.xml || next.xml
  if (next.location && !evidence.location) evidence.location = next.location
  for (const key of ['urlValues', 'jwtValues', 'sensitiveFields', 'headerNames'] as const) {
    const incoming = next[key]
    if (!incoming?.length) continue
    const bucket = evidence[key] ?? []
    for (const value of incoming) if (bucket.length < 8 && !bucket.includes(value)) bucket.push(value)
    evidence[key] = bucket
  }
  target.evidence = evidence
}

function mergeHarvest(target: EndpointHarvest, next: JsonHarvest): void {
  for (const id of next.ids) {
    if (!target.ownerIds.includes(id)) target.ownerIds.push(id)
  }
  for (const field of next.fields) if (!target.fields.includes(field)) target.fields.push(field)
  for (const [field, values] of Object.entries(next.values)) {
    const bucket = target.values[field] ?? []
    for (const value of values) if (!bucket.includes(value)) bucket.push(value)
    target.values[field] = bucket.slice(0, 4)
  }
  target.shapes = target.shapes ?? {}
  for (const [field, shape] of Object.entries(next.shapes)) {
    if (shape !== 'unknown' && !target.shapes[field]) target.shapes[field] = shape
  }
  for (const value of next.textValues) if (!target.seedValues.includes(value)) target.seedValues.push(value)
  mergeEvidence(target, next.evidence)
}

function mergeOtherHarvest(target: EndpointHarvest, next: JsonHarvest): void {
  for (const id of next.ids) {
    if (!target.otherIds.includes(id)) target.otherIds.push(id)
  }
  for (const [field, values] of Object.entries(next.values)) {
    const bucket = target.otherValues[field] ?? []
    for (const value of values) if (!bucket.includes(value)) bucket.push(value)
    target.otherValues[field] = bucket.slice(0, 4)
  }
  mergeEvidence(target, next.evidence)
}

function mergeViewerHarvest(target: EndpointHarvest, next: JsonHarvest): void {
  const ids = target.viewerIds ?? []
  for (const id of next.ids) if (!ids.includes(id)) ids.push(id)
  target.viewerIds = ids.slice(0, 4)
}

async function harvestSurface(
  input: DeterministicEngineInput,
  ranked: readonly EngineEndpoint[],
  harvester: SurfaceHarvester,
  picks: ReturnType<typeof personaPicks>,
  budget: { requestsUsed: number; maxRequests: number },
  log: (kind: string, message: string, data?: Record<string, unknown>) => void,
): Promise<{ harvests: Map<string, EndpointHarvest>; endpointsHarvested: number }> {
  const harvests = new Map<string, EndpointHarvest>()
  let endpointsHarvested = 0
  const owner = picks.owner?.handle
  const other = picks.crossTenant?.handle
  const lower = picks.lower?.handle

  const take = (endpoint: EngineEndpoint): EndpointHarvest => {
    const existing = harvests.get(endpoint.id)
    if (existing) return existing
    const created = emptyHarvest()
    harvests.set(endpoint.id, created)
    endpointsHarvested += 1
    return created
  }

  for (const endpoint of ranked) {
    if (budget.requestsUsed >= budget.maxRequests || input.signal.aborted) break
    if (isStaticOrBaselinePath(endpoint.pathTemplate)) continue
    const bare = endpoint.pathTemplate.split('?')[0] || '/'
    const method = endpoint.method.toUpperCase()
    const collection = collectionPathOf(bare)
    const target = take(endpoint)
    let baseline: JsonHarvest | null = null
    if (method === 'GET' && !hasDynamicIdSegment(bare)) {
      // The route itself is a readable collection/detail page.
      const own = await harvester.get(owner, bare)
      budget.requestsUsed += 1
      mergeHarvest(target, own)
      baseline = own
    }
    if (collection && collection !== '/' && (hasDynamicIdSegment(bare) || method !== 'GET')) {
      const own = await harvester.get(owner, collection)
      budget.requestsUsed += 1
      mergeHarvest(target, own)
      if (other) {
        const theirs = await harvester.get(other, collection)
        budget.requestsUsed += 1
        mergeOtherHarvest(target, theirs)
      }
    }
    // Query-name discovery: a benign value that changes the response identifies the real filter
    // parameter, so later SQLi/traversal/SSRF/XSS probes do not burn their budget on ignored names.
    if (method === 'GET' && baseline && target.activeQueryParams.length === 0) {
      const candidates = inferEndpointParams(endpoint)
        .filter(param => param.location === 'query')
        .filter(param => !hasDynamicIdSegment(param.name))
        .filter(param => pathHasSearchHint(bare) || pathHasFileHint(bare) || pathHasUrlHint(bare) || pathHasRedirectHint(bare))
        .slice(0, 5)
      const sampleFor = (name: string): string => {
        if (pathHasFileHint(bare) || /(?:file|path|name|log|doc)/i.test(name)) return 'guardian.txt'
        if (pathHasUrlHint(bare) || /(?:url|uri|callback|avatar|image|src)/i.test(name)) return 'http://guardian-control.invalid/'
        if (pathHasRedirectHint(bare)) return '/guardian-return'
        return target.seedValues[0] ?? 'guardian'
      }
      for (const candidate of candidates) {
        const separator = bare.includes('?') ? '&' : '?'
        const probePath = `${bare}${separator}${encodeURIComponent(candidate.name)}=${encodeURIComponent(sampleFor(candidate.name))}`
        const probed = await harvester.get(owner, probePath)
        budget.requestsUsed += 1
        mergeHarvest(target, probed)
        const changed = probed.body.length > 0 && (
          baseline.body.length === 0 ||
          responseSimilarity(baseline.body, probed.body) < 0.98
        )
        if (changed && !target.activeQueryParams.includes(candidate.name)) {
          target.activeQueryParams.push(candidate.name)
        }
      }
    }
    // Detail read with a harvested owner id, so field names (body schema) are observable.
    if (hasDynamicIdSegment(bare) && target.fields.length === 0) {
      const detailPath = bare.replace(idSegmentRe, `/${encodeURIComponent(target.ownerIds[0] ?? '1')}`)
      const detail = await harvester.get(owner, detailPath)
      budget.requestsUsed += 1
      mergeHarvest(target, detail)
    }
  }

  // Persona identity endpoints give user ids for object-level routes whose collection is self-only.
  const identityPaths = ranked
    .filter(endpoint => endpoint.method.toUpperCase() === 'GET' && /(?:^|\/)(?:me|session|whoami)(?:\/|$)/i.test(endpoint.pathTemplate))
    .map(endpoint => endpoint.pathTemplate.split('?')[0])
  for (const path of identityPaths.slice(0, 2)) {
    for (const persona of [owner, other, lower]) {
      if (!persona) continue
      const identity = await harvester.get(persona, path)
      budget.requestsUsed += 1
      const target = ranked.find(e => (e.pathTemplate.split('?')[0] || '/') === path)
      if (!target) continue
      const profile = take(target)
      if (persona === owner) mergeHarvest(profile, identity)
      else if (persona === other) mergeOtherHarvest(profile, identity)
      else mergeViewerHarvest(profile, identity)
    }
  }
  log('deterministic_engine.harvest', `Harvested ${endpointsHarvested} endpoint profile(s) with ${budget.requestsUsed} request(s).`)
  return { harvests, endpointsHarvested }
}

// ---------------------------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------------------------

/** Run-scoped synthetic-tenant marker carried on every staging mutation (scope-policy contract). */
export const STAGING_TENANT_HEADER = 'x-guardian-tenant-tag'
/** Fixture/run journal key: lets the target attribute created rows to this run for teardown. */
export const STAGING_RUN_HEADER = 'x-guardian-run-id'

/**
 * Benign, human-visible fields the floor creates in a staging/isolated environment. Injecting the
 * run tag into these values keeps every test entity attributable and cleanable. Entity identifiers
 * of pre-existing owner rows are never rewritten: only values that create things are tagged.
 */
const stagingEntityFieldPattern =
  /^(?:name|title|label|slug|subject|description|notes?|body|text|company|email|memos?|message|comment|display[_-]?name|first[_-]?name|last[_-]?name|full[_-]?name|username|handle)$/i

/**
 * Routes where injecting a tag would corrupt a pre-existing identity (login/session/token flows).
 * A mutation there cannot be tagged safely, so a staging probe must skip it instead of letting it
 * reach the scope policy and be refused as an untagged mutation.
 */
const stagingUntaggablePathPattern =
  /(?:^|\/)(?:login|logout|signin|sign-in|signup|sign-up|register|session|sessions|auth|oauth|token|tokens|password|passwords|reset|forgot|otp|mfa|verify|verification)(?:\/|$)/i

/** Apply the mandatory run-scoped tag to benign string fields that create entities. */
export function tagStagingEntityBody(
  body: Record<string, unknown>,
  tag?: string | null,
): Record<string, unknown> {
  const prefix = (tag ?? '').trim()
  if (!prefix) return body
  const out: Record<string, unknown> = { ...body }
  for (const key of Object.keys(out)) {
    if (!stagingEntityFieldPattern.test(key)) continue
    const value = out[key]
    if (typeof value !== 'string' || value.startsWith(prefix)) continue
    out[key] = `${prefix}${value}`.slice(0, 160)
  }
  return out
}

/** Matching form-encoded tagger for probes that send `application/x-www-form-urlencoded`. */
export function tagStagingEntityForm(
  form: Record<string, string>,
  tag?: string | null,
): Record<string, string> {
  const prefix = (tag ?? '').trim()
  if (!prefix) return form
  const out: Record<string, string> = { ...form }
  for (const key of Object.keys(out)) {
    if (!stagingEntityFieldPattern.test(key)) continue
    const value = out[key]
    if (typeof value !== 'string' || value.startsWith(prefix)) continue
    out[key] = `${prefix}${value}`.slice(0, 160)
  }
  return out
}

/** Probe classes that can write even when the base hypothesis method is a read. */
const stagingMutatingProbeClasses = new Set<DifferentialProbeClass>([
  'csrf_state_change',
  'mass_assignment',
  'workflow_invariant',
  'xxe_canary',
  'webhook_signature_bypass',
  'ssrf_canary',
])

/** Probe classes that can rewrite state on their control/restore legs regardless of the base verb. */
const stagingConditionallyMutatingClasses = new Set<DifferentialProbeClass>([
  'authz_matrix',
  'graphql_audit',
])

/** Whether this hypothesis can issue a state-changing request (base verb or probe family semantics). */
export function probeHypothesisMutates(hyp: Pick<EngineHypothesis, 'probeClass'> & {
  method?: string
  intent?: EngineHypothesis['intent']
  functionLevel?: boolean
  csrfBind?: boolean
}): boolean {
  const method = (hyp.method ?? 'GET').toUpperCase()
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') return true
  if (stagingMutatingProbeClasses.has(hyp.probeClass)) return true
  if (hyp.intent === 'ssrf' || hyp.intent === 'xxe' || hyp.intent === 'webhook' ||
      hyp.intent === 'csrf' || hyp.intent === 'mass_assignment' || hyp.intent === 'workflow') return true
  if (stagingConditionallyMutatingClasses.has(hyp.probeClass)) {
    return hyp.functionLevel === true || hyp.csrfBind === true
  }
  return false
}

export interface StagingProbeTag {
  action: 'tag' | 'skip' | 'none'
  reason: 'tagged' | 'read_only' | 'not_staging' | 'missing_tag' | 'pre_existing_identity'
  headers?: Record<string, string>
  jsonBody?: Record<string, unknown>
  formBody?: Record<string, string>
}

/**
 * Decide how a probe request satisfies the `staging_isolated` tenant-tag contract.
 *
 * - `none`: not staging, or a genuinely read-only probe (never tagged).
 * - `tag`: mutating probe; headers carry the run tag and entity-creating string fields are tagged.
 * - `skip`: mutating probe that cannot carry the tag without corrupting a pre-existing identity
 *   (login/session/token routes); the caller must refuse to send it and count the skip.
 */
export function stagingProbeTag(input: {
  environmentMode?: 'prod_readonly' | 'staging_isolated' | 'ephemeral_lab'
  entityTag?: string | null
  runId?: string | null
  method?: string
  probeClass: DifferentialProbeClass
  pathAndQuery: string
  mutates?: boolean
  jsonBody?: Record<string, unknown>
  formBody?: Record<string, string>
}): StagingProbeTag {
  const entityTag = (input.entityTag ?? '').trim()
  const runId = (input.runId ?? '').trim()
  const mutating = input.mutates ??
    probeHypothesisMutates({ method: input.method ?? 'GET', probeClass: input.probeClass })
  if (input.environmentMode !== 'staging_isolated') {
    return { action: 'none', reason: 'not_staging' }
  }
  if (!mutating) return { action: 'none', reason: 'read_only' }
  if (!entityTag || !runId) return { action: 'skip', reason: 'missing_tag' }
  const path = (input.pathAndQuery.split('?')[0] || '/')
  if (stagingUntaggablePathPattern.test(path)) return { action: 'skip', reason: 'pre_existing_identity' }
  return {
    action: 'tag',
    reason: 'tagged',
    headers: { [STAGING_RUN_HEADER]: runId, [STAGING_TENANT_HEADER]: entityTag },
    ...(input.jsonBody ? { jsonBody: tagStagingEntityBody(input.jsonBody, entityTag) } : {}),
    ...(input.formBody ? { formBody: tagStagingEntityForm(input.formBody, entityTag) } : {}),
  }
}

/** Build the probe request for a hypothesis, applying the staging tag decision when present. */
export function buildProbeRequest(
  hyp: EngineHypothesis,
  maxRequests: number,
  context: Pick<DeterministicEngineInput, 'runId' | 'assignmentId' | 'storage' | 'entityTag'>,
  staging: StagingProbeTag = stagingProbeTag({
    environmentMode: context.entityTag ? 'staging_isolated' : 'ephemeral_lab',
    entityTag: context.entityTag,
    runId: context.runId,
    method: hyp.method,
    probeClass: hyp.probeClass,
    pathAndQuery: hyp.pathAndQuery,
    mutates: probeHypothesisMutates(hyp),
    ...(hyp.jsonBody ? { jsonBody: hyp.jsonBody } : {}),
    ...(hyp.formBody ? { formBody: hyp.formBody } : {}),
  }),
): ProbeDifferentialRequest {
  const tagged = staging.action === 'tag'
  const jsonBody = tagged ? staging.jsonBody : hyp.jsonBody
  const formBody = tagged ? staging.formBody : hyp.formBody
  const base: ProbeDifferentialRequest = {
    probeClass: hyp.probeClass,
    origin: hyp.endpoint.origin,
    pathAndQuery: hyp.pathAndQuery,
    method: hyp.method,
    maxRequests,
    runId: context.runId,
    assignmentId: context.assignmentId,
    ...(context.storage ? { storage: context.storage } : {}),
    ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
    ...(hyp.session ? { session: hyp.session } : {}),
    ...(tagged && staging.headers ? { headers: staging.headers } : {}),
    ...(jsonBody ? { jsonBody } : {}),
    ...(formBody ? { formBody } : {}),
    ...(hyp.xmlTemplate ? { xmlTemplate: hyp.xmlTemplate } : {}),
    ...(hyp.graphqlQuery ? { graphqlQuery: hyp.graphqlQuery } : {}),
  }
  switch (hyp.probeClass) {
    case 'authz_matrix': {
      // Tenant/owner-scoped resources are never legitimately public. Keeping an anonymous row on
      // such a route mostly records a public-cache or middleware fallback and would make the spec
      // synthesizer reject a real cross-tenant read as "public data".
      const path = hyp.endpoint.pathTemplate.split('?')[0] || '/'
      const scoped = /(?:orders?|purchases?|customers?|invoices?|billing|files?|assets?|documents?|accounts?|tickets?|alerts?|notifications?|members?|users?|shipments?|payments?|refunds?|jobs?|logs?|audit|reports?|issues?|links?|groups?|docs?)/i.test(path)
      const publicSurface = /(?:public|shared|preview|storefront|catalog|embed|community|landing|products?|wares?|ratings?|testimonials?|listings?)/i.test(path)
      const includeAnonymous = hyp.functionLevel ? true : !(scoped && !publicSurface)
      return {
        ...base,
        ownerPersona: hyp.ownerPersona,
        otherPersona: hyp.otherPersona,
        resourceIds: hyp.resourceIds ?? [],
        includeAnonymous,
        includeHeaderBypass: false,
        ...(hyp.functionLevel && hyp.jsonBody ? { functionBody: hyp.jsonBody } : {}),
        ...(hyp.secretScan ? { secretScan: true, ...(hyp.viewerPersona ? { viewerPersona: hyp.viewerPersona } : {}) } : {}),
        ...(hyp.csrfBind ? { csrfBind: true } : {}),
      }
    }
    case 'sqli_boolean':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location,
        baselineValue: hyp.baselineValue,
        ...(hyp.location === 'json' ? { jsonBody: hyp.jsonBody ?? {} } : {}),
      }
    case 'ssti_math':
    case 'command_injection':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location ?? 'json',
        ...(hyp.baselineValue ? { baselineValue: hyp.baselineValue } : {}),
        ...(hyp.location === 'json' ? { jsonBody: hyp.jsonBody ?? {} } : {}),
      }
    case 'workflow_invariant':
      return {
        ...base,
        ...(hyp.workflowListPath ? { workflowListPath: hyp.workflowListPath } : {}),
        ...(hyp.workflowReadPath ? { workflowReadPath: hyp.workflowReadPath } : {}),
        ...(hyp.workflowTargetTemplate ? { workflowTargetTemplate: hyp.workflowTargetTemplate } : {}),
        ...(hyp.repeatTransition ? { repeatTransition: true } : {}),
        ...(hyp.quantityField ? { quantityField: hyp.quantityField } : {}),
        jsonBody: hyp.jsonBody ?? {},
      }
    case 'path_traversal_benign':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location ?? 'query',
        ...(hyp.baselineValue ? { baselineValue: hyp.baselineValue } : {}),
      }
    case 'ssrf_canary':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location,
        ssrfParams: hyp.ssrfParams ?? (hyp.param ? [hyp.param.name] : []),
        ...(hyp.param?.location === 'json' || hyp.jsonBody ? { jsonBody: hyp.jsonBody ?? {} } : {}),
        waitMs: 2_500,
      }
    case 'xxe_canary':
      return { ...base, method: 'POST', waitMs: 2_500 }
    case 'graphql_audit':
      return {
        ...base,
        ownerPersona: hyp.ownerPersona,
        otherPersona: hyp.otherPersona,
        resourceIds: hyp.resourceIds ?? [],
        ...(hyp.graphqlRoots ? { graphqlRoots: hyp.graphqlRoots } : {}),
        ...(hyp.graphqlSeedsByRoot ? { graphqlSeedsByRoot: hyp.graphqlSeedsByRoot } : {}),
        maxDepth: 4,
        maxAliases: 3,
      }
    case 'open_redirect_differential':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location ?? 'query',
      }
    case 'xss_context':
      return {
        ...base,
        ...(hyp.param ? { param: hyp.param.name } : {}),
        paramLocation: hyp.location ?? 'query',
      }
    case 'csrf_state_change':
      return {
        ...base,
        method: 'POST',
        ...(hyp.readPath ? { readPath: hyp.readPath, readPathCandidates: [hyp.readPath] } : {}),
        ...(hyp.createReadTemplate ? { createReadTemplate: hyp.createReadTemplate } : {}),
        ...(hyp.stateField ? { stateField: hyp.stateField } : {}),
        ...(hyp.bodyField ? { bodyField: hyp.bodyField } : {}),
        bodyEncodings: ['form', 'json'],
        ...(hyp.session ? { session: hyp.session } : {}),
      }
    case 'csrf_state_change':
      return {
        ...base,
        method: 'POST',
        ...(hyp.readPath ? { readPath: hyp.readPath, readPathCandidates: [hyp.readPath] } : {}),
        ...(hyp.createReadTemplate ? { createReadTemplate: hyp.createReadTemplate } : {}),
        ...(hyp.stateField ? { stateField: hyp.stateField } : {}),
        ...(hyp.bodyField ? { bodyField: hyp.bodyField } : {}),
        bodyEncodings: ['form', 'json'],
        ...(hyp.session ? { session: hyp.session } : {}),
      }
    case 'mass_assignment':
      return {
        ...base,
        method: hyp.method === 'PATCH' || hyp.method === 'PUT' ? hyp.method : 'POST',
        paramLocation: 'json',
        candidateFields: hyp.candidateFields ?? [],
        jsonBody: hyp.jsonBody ?? {},
      }
    case 'auth_protocol_audit':
      return {
        ...base,
        ...(hyp.tokenFields?.length ? { tokenFields: hyp.tokenFields } : {}),
        ...(hyp.identityClaims ? { identityClaims: hyp.identityClaims } : {}),
      }
    case 'webhook_signature_bypass':
      return {
        ...base,
        method: 'POST',
        webhookBody: hyp.webhookBody ?? {},
        ...(hyp.webhookHeader ? { webhookHeader: hyp.webhookHeader } : {}),
        ...(hyp.readPath ? { readPath: hyp.readPath } : {}),
        ...(hyp.stateField ? { readStateField: hyp.stateField } : {}),
      }
    default:
      return base
  }
}


export function extractCreatedId(body: string): string | null {
  let parsed: unknown
  try { parsed = JSON.parse(body) } catch { return null }
  let fallback: string | null = null
  const walk = (node: unknown, depth: number): string | null => {
    if (depth > 4 || !node || typeof node !== 'object') return null
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 5)) {
        const found = walk(item, depth + 1)
        if (found) return found
      }
      return null
    }
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if ((typeof value === 'string' || typeof value === 'number') &&
          /^(?:id|webhookId|hookId|resourceId|uid|uuid)$/i.test(key)) return String(value)
      if (typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value) && !fallback) fallback = value
      if (value && typeof value === 'object') {
        const found = walk(value, depth + 1)
        if (found) return found
      }
    }
    return null
  }
  return walk(parsed, 0) ?? fallback
}

/**
 * Find the fixture/application run-scoped cleanup hook. Only a declared `POST …/cleanup` route is
 * used, and the run id is passed as a query parameter so teardown can never address a broad sweep.
 */
export interface StagingCleanupEndpoint { origin: string; method: string; pathTemplate: string }

export function stagingCleanupTarget(
  endpoints: readonly StagingCleanupEndpoint[],
  runId: string,
): { origin: string; pathAndQuery: string } | null {
  if (!runId) return null
  for (const endpoint of endpoints) {
    if ((endpoint.method || '').toUpperCase() !== 'POST') continue
    const bare = (endpoint.pathTemplate.split('?')[0] || '/')
    if (!/(?:^|\/)cleanup$/i.test(bare)) continue
    return {
      origin: endpoint.origin,
      pathAndQuery: `${bare}?runId=${encodeURIComponent(runId)}`,
    }
  }
  return null
}

/**
 * Every in-scope origin that can host the declared run-scoped cleanup hook. Declared-surface label
 * mapping can associate the hook with any approved target origin (e.g. an app origin that was
 * discovered alongside an h2 origin), so teardown tries each until one acknowledges the run id.
 */
export function stagingCleanupTargets(
  endpoints: readonly StagingCleanupEndpoint[],
  runId: string,
): Array<{ origin: string; pathAndQuery: string }> {
  const target = stagingCleanupTarget(endpoints, runId)
  if (!target) return []
  const origins = [...new Set([target.origin, ...endpoints.map(endpoint => endpoint.origin)])]
    .filter((origin, index, all) => Boolean(origin) && all.indexOf(origin) === index)
  return origins.map(origin => ({ origin, pathAndQuery: target.pathAndQuery }))
}

/**
 * Invoke the run-scoped cleanup hook with an explicit `cleanup` scope context (allowed by the
 * staging contract without weakening it). Returns the number of tagged entities the target removed.
 */
export async function cleanupStagedEntities(input: {
  endpoints: readonly StagingCleanupEndpoint[]
  runId: string
  broker: RequestBroker
  grant: Grant
  signal: AbortSignal
  assignmentId?: string
  log?: (kind: string, message: string, data?: Record<string, unknown>) => void
}): Promise<number> {
  const targets = stagingCleanupTargets(input.endpoints, input.runId)
  if (!targets.length) return 0
  let lastStatus: number | null = null
  for (const target of targets) {
    try {
      const exchange = await input.broker.executeHttp({
        origin: target.origin,
        method: 'POST',
        pathAndQuery: target.pathAndQuery,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ runId: input.runId }),
        scopeHook: 'cleanup',
        runId: input.runId,
        ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
        followRedirects: false,
        timeoutMs: 10_000,
      }, input.grant, input.signal)
      if (exchange.status < 200 || exchange.status >= 300) {
        lastStatus = exchange.status
        continue
      }
      let removed = 0
      try {
        const parsed = JSON.parse(exchange.body) as { removed?: unknown }
        if (typeof parsed.removed === 'number' && Number.isFinite(parsed.removed)) removed = Math.max(0, parsed.removed)
      } catch { /* non-JSON cleanup ack: nothing countable */ }
      input.log?.('staging.cleanup', `Run-scoped cleanup removed ${removed} tagged entit${removed === 1 ? 'y' : 'ies'}.`, {
        hook: target.pathAndQuery.split('?')[0],
        origin: target.origin,
        removed,
      })
      return removed
    } catch (error) {
      input.log?.('staging.cleanup_error', `Run-scoped cleanup hook failed: ${error instanceof Error ? error.message.slice(0, 160) : String(error).slice(0, 160)}`, {
        hook: target.pathAndQuery.split('?')[0],
        origin: target.origin,
      })
    }
  }
  if (lastStatus !== null) {
    input.log?.('staging.cleanup_error', `Run-scoped cleanup hook returned HTTP ${lastStatus} on every candidate origin.`, {
      hook: targets[0].pathAndQuery.split('?')[0],
      status: lastStatus,
      origins: targets.length,
    })
  }
  return 0
}

/**
 * Second-order SSRF: register a canary URL through the write route, then trigger the application's
 * own fetch step. The probe layer (`surface-engine`) only covers first-order sinks, so the engine
 * performs this bounded two-step lifecycle itself and hands the same `canary_callback` anomaly to
 * the normal spec synthesizer.
 */
async function probeSecondOrderSsrf(
  hyp: EngineHypothesis,
  input: DeterministicEngineInput,
  track: (exchange: BrokerExchangeResult) => string | void,
): Promise<DifferentialResult> {
  const started = Date.now()
  const base: DifferentialResult = {
    probeClass: 'ssrf_canary',
    origin: hyp.endpoint.origin,
    pathAndQuery: hyp.endpoint.pathTemplate,
    verdict: 'no_signal',
    summary: 'No out-of-band callback was observed from the stored URL.',
    anomalies: [],
    details: {},
    requestsSent: 0,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 0,
  }
  const canaryBroker = input.canaryBroker
  const param = hyp.param
  const trigger = hyp.triggerPath
  if (!canaryBroker || !param || !trigger) return { ...base, durationMs: Date.now() - started }
  // The two-step lifecycle posts create-shaped bodies itself, so it must carry the same run tag as
  // the generic probe path or the scope policy would (correctly) refuse the write.
  const staging = stagingProbeTag({
    environmentMode: input.environmentMode,
    entityTag: input.entityTag,
    runId: input.runId,
    method: 'POST',
    probeClass: 'ssrf_canary',
    pathAndQuery: hyp.pathAndQuery,
    mutates: true,
    ...(hyp.jsonBody ? { jsonBody: hyp.jsonBody } : {}),
  })
  if (staging.action === 'skip') {
    return { ...base, notes: ['staging_untagged_skipped'], durationMs: Date.now() - started }
  }
  const stagingHeaders = staging.action === 'tag' ? (staging.headers ?? {}) : {}
  const stagingBody = staging.action === 'tag' ? (staging.jsonBody ?? {}) : (hyp.jsonBody ?? {})
  let info = canaryBroker.listenerInfo()
  if (!info.running) info = await canaryBroker.startListener()
  const exchangeIds: string[] = []
  let requests = 0
  const send = async (pathAndQuery: string, value: string): Promise<BrokerExchangeResult | null> => {
    const body = { ...stagingBody, [param.name]: value }
    try {
      const exchange = await input.broker.executeHttp({
        origin: hyp.endpoint.origin,
        method: 'POST',
        pathAndQuery,
        headers: { 'Content-Type': 'application/json', ...stagingHeaders },
        body: JSON.stringify(body),
        ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
        runId: input.runId,
        assignmentId: input.assignmentId,
        followRedirects: false,
        timeoutMs: 8_000,
      }, input.grant, input.signal)
      requests += 1
      const id = track(exchange)
      if (typeof id === 'string') exchangeIds.push(id)
      return exchange
    } catch {
      requests += 1
      return null
    }
  }
  const triggerFetch = async (resourceId: string): Promise<void> => {
    const path = trigger.replace('{{id}}', encodeURIComponent(resourceId))
    try {
      const exchange = await input.broker.executeHttp({
        origin: hyp.endpoint.origin,
        method: 'POST',
        pathAndQuery: path,
        headers: { 'Content-Type': 'application/json', ...stagingHeaders },
        body: '{}',
        ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
        runId: input.runId,
        assignmentId: input.assignmentId,
        followRedirects: false,
        timeoutMs: 8_000,
      }, input.grant, input.signal)
      requests += 1
      const id = track(exchange)
      if (typeof id === 'string') exchangeIds.push(id)
    } catch {
      requests += 1
    }
  }

  const control = await send(hyp.pathAndQuery, 'http://guardian-control.invalid/')
  const controlId = control ? extractCreatedId(control.body) : null
  if (controlId) await triggerFetch(controlId)

  const minted = canaryBroker.mintCanary(
    input.runId,
    `engine:ssrf:${param.name}`,
    hyp.endpoint.origin,
    input.storage ? { storage: input.storage, assignmentId: input.assignmentId } : undefined,
  )
  const probe = await send(hyp.pathAndQuery, minted.httpUrl)
  const probeId = probe ? extractCreatedId(probe.body) : null
  if (probeId) await triggerFetch(probeId)

  const deadline = Date.now() + 3_000
  let hit = false
  while (!input.signal.aborted) {
    const check = canaryBroker.checkCanary(minted.token, input.storage ? { storage: input.storage, runId: input.runId } : undefined)
    if (check.hit) { hit = true; break }
    if (Date.now() >= deadline) break
    await new Promise<void>(resolve => setTimeout(resolve, 200))
  }
  if (hit) {
    return {
      ...base,
      verdict: 'signal',
      summary: 'The stored URL was fetched by the target after the trigger step (second-order SSRF callback).',
      anomalies: [{ type: 'canary_callback', variant: 'http', param: param.name }],
      details: { secondOrder: true, requests },
      requestsSent: requests,
      exchangeIds,
      durationMs: Date.now() - started,
    }
  }
  return { ...base, requestsSent: requests, exchangeIds, details: { secondOrder: true, requests }, durationMs: Date.now() - started }
}


const credentialPatterns: ReadonlyArray<RegExp> = [
  // Vendor-format credentials only. No benchmark/harness token literals: the engine proves a
  // disclosure from the response shape and an access-control differential, not from a known prefix.
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/,
  /\bghp_[A-Za-z0-9]{20,}\b/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
]
const sensitiveFieldName = /^(?:secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|password|private[_-]?key|token|webhook[_-]?secret|provider[_-]?key)$/i
const maskedValue = /[*…]|\[redacted\]|^x{4,}$/i

interface SensitiveField { field: string; length: number }

function findSensitiveField(body: string): SensitiveField | null {
  let parsed: unknown
  try { parsed = JSON.parse(body) } catch { parsed = null }
  const visit = (node: unknown, depth: number): SensitiveField | null => {
    if (depth > 5 || !node || typeof node !== 'object') return null
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 20)) {
        const found = visit(item, depth + 1)
        if (found) return found
      }
      return null
    }
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (typeof value === 'string' && sensitiveFieldName.test(key) && value.length >= 10 && !maskedValue.test(value)) {
        return { field: key, length: value.length }
      }
      if (value && typeof value === 'object') {
        const found = visit(value, depth + 1)
        if (found) return found
      }
    }
    return null
  }
  return visit(parsed, 0)
}

/**
 * Credential-inventory disclosure. Two generic shapes:
 *  - integration/connector lists return a `secret` field for the caller's own team;
 *  - token/key inventories expose a raw secret while their compact/preview control masks it.
 * The latter requires a masked control before the spec is built, which keeps endpoints that always
 * return masked metadata from being reported.
 */
async function probeSecretExposure(
  hyp: EngineHypothesis,
  input: DeterministicEngineInput,
  track: (exchange: BrokerExchangeResult) => void | string,
): Promise<DifferentialResult> {
  const started = Date.now()
  const base: DifferentialResult = {
    probeClass: 'authz_matrix',
    origin: hyp.endpoint.origin,
    pathAndQuery: hyp.pathAndQuery,
    verdict: 'no_signal',
    summary: 'No unmasked credential-shaped value was returned.',
    anomalies: [],
    details: {},
    requestsSent: 0,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 0,
  }
  const exchangeIds: string[] = []
  let requests = 0
  const get = async (path: string): Promise<BrokerExchangeResult | null> => {
    try {
      const exchange = await input.broker.executeHttp({
        origin: hyp.endpoint.origin,
        method: 'GET',
        pathAndQuery: path,
        ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
        followRedirects: false,
        timeoutMs: 8_000,
      }, input.grant, input.signal)
      requests += 1
      const id = track(exchange)
      if (typeof id === 'string') exchangeIds.push(id)
      return exchange
    } catch { requests += 1; return null }
  }
  const getAnonymous = async (path: string): Promise<BrokerExchangeResult | null> => {
    try {
      const exchange = await input.broker.executeHttp({
        origin: hyp.endpoint.origin,
        method: 'GET',
        pathAndQuery: path,
        followRedirects: false,
        timeoutMs: 8_000,
      }, input.grant, input.signal)
      requests += 1
      const id = track(exchange)
      if (typeof id === 'string') exchangeIds.push(id)
      return exchange
    } catch { requests += 1; return null }
  }
  const integrationSurface = /(?:links?|integrations?|connectors?)/i.test(hyp.endpoint.pathTemplate)
  const probePaths: string[] = []
  if (hyp.param) {
    for (const id of (hyp.resourceIds ?? []).slice(0, 4)) {
      const separator = hyp.pathAndQuery.includes('?') ? '&' : '?'
      probePaths.push(`${hyp.pathAndQuery}${separator}${encodeURIComponent(hyp.param.name)}=${encodeURIComponent(id)}`)
    }
  }
  probePaths.push(hyp.pathAndQuery)
  for (const path of [...new Set(probePaths)]) {
    const probe = await get(path)
    if (!probe || probe.status < 200 || probe.status >= 300) continue
    const raw = findSensitiveField(probe.body)
    const literal = credentialPatterns.find(candidate => candidate.test(probe.body))
    if (!raw && !literal) continue
    const controlPath = path
    if (!integrationSurface) {
      // Structural control: the same resource read by an anonymous (no-persona) actor. A 401/403
      // proves the endpoint is access-controlled, so an unmasked credential returned to the reader
      // is a disclosure. A public/masked view proves nothing and is silently skipped.
      const anonymous = await getAnonymous(path)
      const denied = !anonymous || anonymous.status === 401 || anonymous.status === 403
      if (!denied) continue
      return {
        ...base,
        verdict: 'signal',
        summary: 'A credential-bearing response is restricted to an authenticated actor but returns an unmasked secret.',
        anomalies: [{ type: 'secret_disclosed', path, controlPath, controlActor: 'anonymous', ...(raw ? { field: raw.field } : { pattern: literal?.source }) }],
        details: { mode: 'anonymous_denial', field: raw?.field ?? null },
        requestsSent: requests,
        exchangeIds,
        durationMs: Date.now() - started,
      }
    }
    return {
      ...base,
      verdict: 'signal',
      summary: 'A connector/integration read returned an unmasked credential field.',
      anomalies: [{ type: 'secret_disclosed', path, controlPath, ...(raw ? { field: raw.field } : { pattern: literal?.source }) }],
      details: { mode: 'integration_secret', field: raw?.field ?? null },
      requestsSent: requests,
      exchangeIds,
      durationMs: Date.now() - started,
    }
  }
  return { ...base, requestsSent: requests, exchangeIds, durationMs: Date.now() - started }
}

function classStats(report: DeterministicEngineReport, intent: string): EngineClassStats {
  const existing = report.byClass[intent]
  if (existing) return existing
  const created: EngineClassStats = { hypotheses: 0, signals: 0, specs: 0, confirmed: 0, rejected: 0, requests: 0 }
  report.byClass[intent] = created
  return created
}

/**
 * v6 environment contract: which floor hypotheses may be formed under an engagement mode.
 * `prod_readonly` keeps read-only checks (read BOLA, reflected redirect/XSS, GraphQL query reads,
 * credential exposure) and drops every mutating class, so no write ever reaches the broker.
 */
export function floorHypothesesForEnvironment(
  hypotheses: readonly EngineHypothesis[],
  mode: 'prod_readonly' | 'staging_isolated' | 'ephemeral_lab',
): EngineHypothesis[] {
  if (mode !== 'prod_readonly') return [...hypotheses]
  const mutatingIntents = new Set(['csrf', 'mass_assignment', 'workflow', 'webhook', 'ssrf', 'xxe', 'ssti', 'command_injection'])
  return hypotheses.filter(hyp => {
    if (mutatingIntents.has(hyp.intent)) return false
    if (hyp.intent === 'graphql') return true // query-only audit
    return hyp.method === 'GET'
  })
}

export async function runDeterministicEngine(input: DeterministicEngineInput): Promise<DeterministicEngineReport> {
  const started = Date.now()
  const maxRequests = Math.max(0, input.maxRequests ?? defaultEngineMaxRequests)
  const maxDurationMs = Math.max(1_000, input.maxDurationMs ?? defaultEngineMaxDurationMs)
  const log = input.log ?? (() => {})
  const conventionalWordlist = conventionalWordlistEnabled()
  const report: DeterministicEngineReport = {
    requestsUsed: 0,
    durationMs: 0,
    endpointsConsidered: 0,
    endpointsHarvested: 0,
    hypothesesFormed: 0,
    hypothesesRun: 0,
    signals: 0,
    specsSubmitted: 0,
    confirmed: 0,
    rejectedSpecs: 0,
    leads: 0,
    leadsSuppressed: 0,
    stoppedReason: 'complete',
    byClass: {},
    confirmedPairs: [],
    touchedPairs: [],
    conventionalWordlist,
    stagingTaggedMutations: 0,
    stagingUntaggedSkipped: 0,
    stagingCleaned: 0,
    stagingCreatedEntityIds: [],
    notes: [],
  }

  if (!deterministicEngineEnabled() || input.tier < 1) {
    report.stoppedReason = 'disabled'
    report.durationMs = Date.now() - started
    return report
  }

  const candidateEndpoints = engineWordlistSurface(input.endpoints, conventionalWordlist)
  if (!conventionalWordlist && candidateEndpoints.length !== input.endpoints.length) {
    report.notes.push(`conventional wordlist OFF: ${input.endpoints.length - candidateEndpoints.length} wordlist-only endpoint(s) excluded`)
  }
  const ranked = rankEndpoints(collapseRouteVariants(candidateEndpoints)).slice(0, input.maxEndpoints ?? defaultEngineMaxEndpoints)
  report.endpointsConsidered = ranked.length
  if (ranked.length === 0) {
    report.durationMs = Date.now() - started
    return report
  }

  const picks = personaPicks(input.personas)
  const origins = [...new Set(ranked.map(endpoint => endpoint.origin))]
  const budget = { requestsUsed: 0, maxRequests }
  const createdEntityIds = new Set<string>()
  /** Evidence-gated leads collected during the pass; deduped/ranked/capped before emission. */
  const leadCandidates: EngineLeadCandidate[] = []
  const stagingTag = (input.entityTag ?? '').trim()
  /**
   * Every brokered request (harvest, probe, replay) counts against the engine's request cap. Tagged
   * create responses are recorded so teardown can attribute and audit what the floor created.
   */
  const trackExchange = (exchange: BrokerExchangeResult): string | void => {
    budget.requestsUsed += 1
    report.requestsUsed = budget.requestsUsed
    if (stagingTag && /^(?:POST|PUT|PATCH)$/i.test(exchange.method)) {
      const carriesTag = Object.values(exchange.reqHeaders ?? {})
        .some(value => typeof value === 'string' && value.toLowerCase().includes(stagingTag.toLowerCase()))
      if (carriesTag && exchange.status >= 200 && exchange.status < 300) {
        const id = extractCreatedId(exchange.body)
        if (id) createdEntityIds.add(id)
      }
    }
    return input.recordExchange?.(exchange)
  }

  // Harvest each origin independently (the engine is per-run but a run may carry several assets).
  const harvests = new Map<string, EndpointHarvest>()
  for (const origin of origins) {
    if (budget.requestsUsed >= maxRequests || input.signal.aborted) break
    const originEndpoints = ranked.filter(endpoint => endpoint.origin === origin)
    const harvester = new SurfaceHarvester({ ...input, recordExchange: trackExchange }, log, origin)
    const result = await harvestSurface(input, originEndpoints, harvester, picks, budget, log)
    report.endpointsHarvested += result.endpointsHarvested
    for (const [id, harvest] of result.harvests) harvests.set(id, harvest)
  }

  const hypotheses = enumerateHypotheses(ranked, harvests, {
    tier: input.tier,
    personas: input.personas,
    maxHypotheses: input.maxHypotheses ?? defaultEngineMaxHypotheses,
    maxRequests,
    ...(input.classes ? { classes: input.classes } : {}),
  })

  // v6 environment contract: a production read-only engagement never forms a mutating hypothesis,
  // so a write probe cannot burn budget or a dry-step counter only to be refused by the broker.
  const environmentMode = input.environmentMode ?? 'ephemeral_lab'
  const gatedHypotheses = floorHypothesesForEnvironment(hypotheses, environmentMode)
  report.hypothesesFormed = gatedHypotheses.length
  report.touchedPairs = [...new Set(gatedHypotheses.map(hyp =>
    `${normalizeEndpointTemplate(hyp.endpoint.pathTemplate)}|${intentFamily(hyp.intent)}`))]
  for (const hyp of gatedHypotheses) classStats(report, hyp.intent).hypotheses += 1

  const perProbeRequestFloor = 6
  const probeSlots = Math.min(150, Math.max(defaultEngineMaxHypotheses, Math.floor(maxRequests / 11)))
  const capScale = Math.max(1, probeSlots / defaultEngineMaxHypotheses)
  const capFor = (value: number): number => Math.max(value, Math.ceil(value * capScale))
  // Phase A runs the same deep per-class policy as `--no-llm`, so the agentic floor and the
  // standalone floor probe the same hypotheses in the same order. Breadth caps are only used when
  // the caller's remaining request budget cannot fund a deep pass (explicit `breadthFirst`).
  const breadthFirst = input.breadthFirst === true || maxRequests < 600
  const intentCaps: Record<string, number> = {
    authz: breadthFirst ? Math.min(capFor(26), 14) : capFor(26),
    secret_disclosure: breadthFirst ? Math.min(capFor(5), 3) : capFor(5),
    sqli: breadthFirst ? Math.min(capFor(10), 8) : capFor(10),
    traversal: capFor(6),
    ssrf: capFor(6),
    xxe: capFor(4),
    redirect: capFor(6),
    xss: capFor(6),
    graphql: capFor(2),
    mass_assignment: capFor(6),
    csrf: capFor(4),
    workflow: capFor(3),
    ssti: capFor(3),
    command_injection: capFor(3),
    webhook: capFor(2),
    auth_protocol: capFor(2),
  }
  const intentUsed: Record<string, number> = {}
  // Request-count termination is the deterministic contract; the wall clock is only a safety net
  // with a fixed margin, so a slow host cannot silently truncate a different tail of the queue.
  const hardDeadlineMs = maxDurationMs + deterministicWallMarginMs
  for (const hyp of gatedHypotheses) {
    if (input.signal.aborted) { report.stoppedReason = 'aborted'; break }
    if (Date.now() - started >= hardDeadlineMs) { report.stoppedReason = 'time'; break }
    if (budget.requestsUsed >= maxRequests) { report.stoppedReason = 'budget'; break }
    const remaining = maxRequests - budget.requestsUsed
    if (remaining < perProbeRequestFloor) { report.stoppedReason = 'budget'; break }
    const cap = intentCaps[hyp.intent] ?? 6
    if ((intentUsed[hyp.intent] ?? 0) >= cap) continue
    intentUsed[hyp.intent] = (intentUsed[hyp.intent] ?? 0) + 1

    const stats = classStats(report, hyp.intent)
    const maxProbeRequests = Math.max(perProbeRequestFloor, Math.min(defaultEnginePerProbeRequests, remaining))
    // v6 staging contract: mutating probes must carry the run tag on their created/updated values.
    // A mutation that cannot be tagged without corrupting a pre-existing identity is skipped here,
    // so the scope policy never sees an untagged write (safety stays exactly as strict).
    const staging = stagingProbeTag({
      environmentMode,
      entityTag: input.entityTag,
      runId: input.runId,
      method: hyp.method,
      probeClass: hyp.probeClass,
      pathAndQuery: hyp.pathAndQuery,
      mutates: probeHypothesisMutates(hyp),
      ...(hyp.jsonBody ? { jsonBody: hyp.jsonBody } : {}),
      ...(hyp.formBody ? { formBody: hyp.formBody } : {}),
    })
    if (staging.action === 'skip') {
      report.stagingUntaggedSkipped += 1
      log('staging.untagged_skipped', `${hyp.probeClass} ${hyp.method} ${hyp.endpoint.pathTemplate}: ${staging.reason}`, {
        intent: hyp.intent,
        probeClass: hyp.probeClass,
        endpoint: hyp.endpoint.pathTemplate,
        method: hyp.method,
        reason: staging.reason,
      })
      continue
    }
    if (staging.action === 'tag') report.stagingTaggedMutations += 1
    let probe: DifferentialResult
    try {
      probe = hyp.intent === 'secret_disclosure' && !hyp.secretScan && !input.probe
        ? await probeSecretExposure(hyp, input, trackExchange)
        : hyp.probeClass === 'ssrf_canary' && hyp.triggerPath && input.canaryBroker && !input.probe
          ? await probeSecondOrderSsrf(hyp, input, trackExchange)
          : await (input.probe ?? probeDifferential)(
              { ...buildProbeRequest(hyp, maxProbeRequests, input, staging), onExchange: trackExchange },
              input.broker, input.grant, input.canaryBroker, input.signal,
            )
    } catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 200) : String(error).slice(0, 200)
      report.notes.push(`${hyp.probeClass} ${hyp.endpoint.pathTemplate}: ${message}`)
      log('deterministic_engine.probe_error', `${hyp.probeClass} ${hyp.method} ${hyp.endpoint.pathTemplate}: ${message}`, {
        intent: hyp.intent, endpoint: hyp.endpoint.pathTemplate, method: hyp.method,
      })
      if (/outside the current assignment scope|run is paused|circuit is open/i.test(message)) {
        report.stoppedReason = 'aborted'
        break
      }
      continue
    }
    report.hypothesesRun += 1
    stats.requests += probe.requestsSent
    log('deterministic_engine.probe', `${hyp.probeClass} ${hyp.method} ${hyp.endpoint.pathTemplate}${hyp.param ? ` param=${hyp.param.name}` : ''} -> ${probe.verdict}`, {
      intent: hyp.intent,
      probeClass: hyp.probeClass,
      endpoint: hyp.endpoint.pathTemplate,
      method: hyp.method,
      param: hyp.param?.name ?? null,
      verdict: probe.verdict,
      requests: probe.requestsSent,
      anomalies: probe.anomalies.map(anomaly => String(anomaly.type)).slice(0, 6),
      stoppedReason: probe.stoppedReason,
      summary: probe.summary.slice(0, 200),
    })
    if (probe.verdict !== 'signal') continue
    report.signals += 1
    stats.signals += 1

    const candidates = synthesizeEngineSpecs(hyp, probe).slice(0, 3)
    if (candidates.length === 0) {
      log('deterministic_engine.spec_skipped', `${hyp.probeClass} ${hyp.endpoint.pathTemplate}: signal had no schema-valid replay shape (${probe.anomalies.map(a => String(a.type)).join(',') || 'no anomaly'})`, {
        intent: hyp.intent,
        endpoint: hyp.endpoint.pathTemplate,
      })
    }
    let confirmedThisHypothesis = false
    const rejections: RejectedSpecEvidence[] = []
    for (const candidate of candidates) {
      if (input.signal.aborted || budget.requestsUsed >= maxRequests) break
      const parsed = declarativeReplaySpecSchema.safeParse(candidate.spec)
      if (!parsed.success) {
        log('deterministic_engine.spec_invalid', `${hyp.probeClass} ${hyp.endpoint.pathTemplate}: ${parsed.error.issues[0]?.path.join('.') ?? 'schema'} ${parsed.error.issues[0]?.message ?? ''}`.slice(0, 300), {
          intent: hyp.intent, endpoint: hyp.endpoint.pathTemplate,
        })
        continue
      }
      report.specsSubmitted += 1
      stats.specs += 1
      let replay: ReplayVerificationResult
      try {
        replay = await (input.verify ?? verifyReplaySpec)({
          spec: parsed.data,
          broker: input.broker,
          ...(input.browser ? { browser: input.browser } : {}),
          ...(input.canaryBroker ? { canaryBroker: input.canaryBroker } : {}),
          backend: input.backend,
          ...(input.reposDir ? { reposDir: input.reposDir } : {}),
          grant: input.grant,
          signal: input.signal,
          ...(input.storage ? { storage: input.storage } : {}),
          runId: input.runId,
          assignmentId: input.assignmentId,
          onExchange: trackExchange,
        })
      } catch (error) {
        report.notes.push(`verify ${candidate.kind} ${hyp.endpoint.pathTemplate}: ${error instanceof Error ? error.message.slice(0, 160) : String(error).slice(0, 160)}`)
        continue
      }
      if (replay.verdict !== 'confirmed') {
        log('deterministic_engine.spec_rejected', `${candidate.kind} ${hyp.endpoint.pathTemplate} -> ${replay.verdict}: ${(replay.outcome.reason ?? replay.outcome.observed).slice(0, 200)}`, {
          intent: hyp.intent, endpoint: hyp.endpoint.pathTemplate, kind: candidate.kind,
          verdict: replay.verdict, controlPassed: replay.outcome.controlPassed,
        })
        report.rejectedSpecs += 1
        stats.rejected += 1
        rejections.push({
          kind: candidate.kind,
          verdict: replay.verdict,
          controlPassed: replay.outcome.controlPassed === true,
          observed: replay.outcome.observed,
          reason: replay.outcome.reason ?? null,
          exchangeIds: replay.exchangeIds,
        })
        continue
      }
      const vulnClass = candidate.vulnClass || vulnClassOfSpec(parsed.data as unknown as Record<string, unknown>)
      let persistedId: string | null = null
      try {
        persistedId = await input.onConfirmed({
          hypothesis: hyp,
          spec: parsed.data,
          specRecord: candidate,
          vulnClass,
          endpoint: hyp.endpoint.pathTemplate,
          result: replay,
          exchangeIds: [...new Set([...probe.exchangeIds, ...replay.exchangeIds])],
        })
      } catch (error) {
        report.notes.push(`persist ${candidate.kind} ${hyp.endpoint.pathTemplate}: ${error instanceof Error ? error.message.slice(0, 160) : String(error).slice(0, 160)}`)
        continue
      }
      // A null return means the persistence layer recognized a structural duplicate; do not count
      // it as a new confirmation (and stop trying lower-priority specs for this hypothesis).
      confirmedThisHypothesis = true
      if (!persistedId) continue
      report.confirmed += 1
      stats.confirmed += 1
      report.confirmedPairs.push({ endpoint: hyp.endpoint.pathTemplate, vulnClass })
      break
    }
    if (!confirmedThisHypothesis) {
      const evidence = deriveLeadEvidence({ hypothesis: hyp, probe, rejections })
      if (!evidence) {
        report.leadsSuppressed += 1
        log('deterministic_engine.lead_suppressed', `${hyp.probeClass} ${hyp.method} ${hyp.endpoint.pathTemplate}: observation lacks failed-control/near-miss evidence`, {
          intent: hyp.intent,
          probeClass: hyp.probeClass,
          endpoint: hyp.endpoint.pathTemplate,
          method: hyp.method,
          anomalies: probe.anomalies.map(anomaly => String(anomaly.type)).slice(0, 6),
          rejected: rejections.length,
          controlPassed: rejections.map(rejection => rejection.controlPassed),
        })
      } else {
        leadCandidates.push({
          lead: {
            hypothesis: hyp,
            probe,
            summary: probe.summary.slice(0, 240),
            evidence,
          },
          key: leadCandidateKey(hyp),
          score: leadCandidateScore(hyp, evidence),
        })
      }
    }
  }

  // Emit the deduplicated, severity-ranked, capped lead set only after the whole pass: a later
  // hypothesis on the same (origin, route, method, input, class) may carry stronger evidence.
  const emittedLeads = selectEngineLeads(leadCandidates, input.maxLeads ?? defaultEngineLeadCap)
  for (const candidate of emittedLeads) {
    report.leads += 1
    try {
      input.onLead?.(candidate.lead)
    } catch { /* lead emission is best-effort */ }
  }

  if (report.stoppedReason === 'complete' && (Date.now() - started >= hardDeadlineMs)) report.stoppedReason = 'time'
  report.stagingCreatedEntityIds = [...createdEntityIds]
  // v6 staging teardown: hand the run tag back to the target's declared cleanup hook so tagged
  // entities never outlive the floor pass. Best-effort and only when this pass actually wrote.
  if (environmentMode === 'staging_isolated' && stagingTag && report.stagingTaggedMutations > 0) {
    let cleanupEndpoints: readonly StagingCleanupEndpoint[] = input.cleanupEndpoints ?? input.endpoints
    if (!stagingCleanupTarget(cleanupEndpoints, input.runId)) {
      cleanupEndpoints = [...cleanupEndpoints, ...input.endpoints]
    }
    if (!stagingCleanupTarget(cleanupEndpoints, input.runId) && input.storage) {
      try { cleanupEndpoints = [...cleanupEndpoints, ...input.storage.listEndpoints(input.runId)] } catch { /* keep probe slice */ }
    }
    report.stagingCleaned = await cleanupStagedEntities({
      endpoints: cleanupEndpoints,
      runId: input.runId,
      broker: input.broker,
      grant: input.grant,
      signal: input.signal,
      ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
      log,
    })
  }
  report.durationMs = Date.now() - started
  return report
}

// ---------------------------------------------------------------------------------------------
// Hide-confirmed helpers (shared with the Execution specialist queue)
// ---------------------------------------------------------------------------------------------

export function endpointClassPairKey(endpoint: string, vulnClass: string): string {
  return `${endpoint}|${vulnClass}`
}

/** Class -> wording that specialist queue entries use. */
export function engineClassKeywords(vulnClass: string): string[] {
  switch (vulnClass) {
    case 'bola': case 'idor': case 'bfla': case 'authz':
      return ['access-control', 'authorization', 'authorisation', 'idor', 'bola', 'bfla', 'tenant', 'object-level', 'privilege escalation']
    case 'sqli': return ['sql', 'injection-input']
    case 'xxe': return ['xxe', 'xml external', 'xml entity']
    case 'ssrf': return ['ssrf', 'server-side request']
    case 'path_traversal': return ['traversal', 'path traversal', 'directory']
    case 'open_redirect': return ['redirect', 'open-redirect']
    case 'xss_reflected': case 'xss_stored': return ['xss', 'cross-site scripting', 'script injection']
    case 'graphql_bola': return ['graphql', 'resolver']
    case 'mass_assignment': return ['mass assignment', 'mass-assignment', 'overpost']
    case 'ssti': return ['ssti', 'template injection', 'template']
    case 'command_injection': return ['command injection', 'os command', 'rce', 'shell']
    case 'workflow_bypass': return ['workflow', 'step skip', 'business logic']
    case 'cache_poisoning': case 'cache_deception': return ['cache']
    case 'csrf': return ['csrf', 'state change']
    default: return [vulnClass]
  }
}

/** Normalise a path template to the static prefix a queue entry would mention. */
export function stableEndpointKey(endpoint: string): string {
  return endpoint.split('?')[0]
    .replace(/\/:[^/]+/g, '')
    .replace(/\/\{[^}]+\}/g, '')
    .toLowerCase()
}

/** True when a specialist step's text already covers a deterministic (endpoint, class) confirmation. */
export function stepCoveredByConfirmedPairs(stepText: string, pairs: Iterable<string>): boolean {
  const text = stepText.toLowerCase()
  for (const pair of pairs) {
    const idx = pair.lastIndexOf('|')
    if (idx <= 0) continue
    const endpoint = pair.slice(0, idx)
    const vulnClass = pair.slice(idx + 1)
    const endpointKey = stableEndpointKey(endpoint)
    if (!endpointKey || endpointKey === '/') continue
    if (!text.includes(endpointKey)) continue
    if (engineClassKeywords(vulnClass).some(keyword => text.includes(keyword))) return true
  }
  return false
}

// ---------------------------------------------------------------------------------------------
// Class-family helpers shared with the agentic scope guard
// ---------------------------------------------------------------------------------------------

export function intentFamily(intent: string): string {
  switch (intent) {
    case 'authz': case 'graphql': return 'authz'
    case 'sqli': return 'sqli'
    case 'xxe': return 'xxe'
    case 'ssrf': return 'ssrf'
    case 'traversal': return 'traversal'
    case 'redirect': return 'redirect'
    case 'xss': case 'stored_xss': return 'xss'
    case 'mass_assignment': return 'mass_assign'
    case 'csrf': return 'csrf'
    case 'cache': return 'cache'
    case 'secret_disclosure': return 'disclosure'
    case 'workflow': return 'logic'
    case 'ssti': return 'ssti'
    case 'command_injection': return 'cmdi'
    case 'webhook': return 'webhook'
    case 'auth_protocol': return 'auth'
    default: return intent
  }
}

export function specClassFamily(cwe: string | undefined, kind: string | undefined): string | null {
  if (kind === 'static_ast_proof') return null
  const n = Number(/(\d+)/.exec(cwe ?? '')?.[1] ?? NaN)
  if (!Number.isFinite(n)) return kind === 'http_chain' ? null : null
  if ([639, 284, 285, 862, 863, 566].includes(n)) return 'authz'
  if ([89, 564, 943].includes(n)) return 'sqli'
  if ([79, 80, 83].includes(n)) return 'xss'
  if (n === 918) return 'ssrf'
  if ([611, 776].includes(n)) return 'xxe'
  if ([22, 23, 35, 73].includes(n)) return 'traversal'
  if (n === 601) return 'redirect'
  if (n === 915) return 'mass_assign'
  if (n === 352) return 'csrf'
  if ([200, 359, 522, 532].includes(n)) return 'disclosure'
  if ([524, 525, 444, 349].includes(n)) return 'cache'
  if ([840, 841].includes(n)) return 'logic'
  if ([362, 367].includes(n)) return 'race'
  if ([345, 347, 327, 1270].includes(n)) return 'token'
  if ([287, 306, 288, 290].includes(n)) return 'auth'
  if ([77, 78, 88].includes(n)) return 'command'
  if ([1336, 94, 95].includes(n)) return 'ssti'
  return null
}
