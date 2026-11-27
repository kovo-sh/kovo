/**
 * Generic Capability-to-Consumer Frontier Matcher & Dynamic Wave Materializer.
 *
 * Bridges the Grey-Box / multi-hop visibility gap where workers seal concrete capabilities
 * (`signing_secret`, `credential_token`, `signed_or_download_url`, `entity_or_job_id`) in
 * `CapabilityLedger` without source code showing which discovered consumer endpoint accepts them.
 *
 * Invariants:
 *  - 100% generic structural matching (zero app, route, or persona hardcoding).
 *  - Operates ONLY on agentic sealed capabilities when `llmMode !== 'deterministic-no-llm'`
 *    (`--no-llm` and synthetic/floor-only runs strictly emit 0 steps).
 *  - Preserves each capability's owning non-elevated `actingPersona` (NEVER substitutes an
 *    elevated shortcut persona).
 *  - Prunes already-falsified `(capabilityKind/capId, origin, method, route)` negative edges and
 *    deduplicates against already-confirmed / existing steps.
 */
import { classifyPersonaPrivilege } from './assignment-brief.ts'
import {
  CAPABILITY_KINDS,
  DERIVED_CAPABILITY_HANDLE_RE,
  computeArtifactDigest,
  formatDerivedCapabilityHandle,
  sanitizeCheckpointText,
  type CapabilityKind,
  type CapabilityLedger,
  type CapabilityNode,
  type CapabilitySurface,
  type NegativeEdge,
} from './capability-ledger.ts'
import type { ChainHop } from './graph-coordinator.ts'
import { resolveRunPersonas } from './persona-vault.ts'
import { normalizeRouteTemplate } from './route-template.ts'
import type { ChainStep, Fact, Run, Store } from './store.ts'

export type CapabilityShapeKind =
  | 'credential_token'
  | 'signing_secret'
  | 'signed_or_download_url'
  | 'entity_or_job_id'

export type FrontierAffordanceKind =
  | 'derive_signature'
  | 'pivot_with_credential'
  | 'consume_entity_id'
  | 'redeem_signed_url'

export type FrontierLlmMode = 'agentic' | 'deterministic-no-llm'

export interface FrontierCapabilityInput {
  capId: string
  origin: string
  actingPersona: string
  producerEndpoint?: string | null
  producerMethod?: string | null
  ledgerKind?: CapabilityKind
  secretKind?: string | null
  fieldName?: string | null
  slot?: string | null
  label?: string | null
  sourceHopId?: string | null
  summary?: string | null
  valueHint?: string | null
  provenance?: string | null
  temporalState?: string | null
  targetOrigin?: string | null
  targetPath?: string | null
  derivedFromAttackerPersona?: string | null
  factId?: string | null
  runtimeObserved?: boolean
}

export interface FrontierEndpointInput {
  id?: string
  origin: string
  method: string
  pathTemplate: string
  authRequirement?: string | null
  riskScore?: number
  paramNames?: readonly string[]
  hasObjectIdParam?: boolean
  sinkKinds?: readonly string[]
}

export interface FrontierObservedResponseInput {
  origin: string
  method: string
  pathAndQuery: string
  status: number
  personaHandle?: string | null
  respHeaders?: Record<string, string> | string | null
  bodyPreview?: string | null
}

export interface FrontierNegativeEdgeInput {
  capId?: string
  preconditionCapIds?: readonly string[]
  capabilityKind?: CapabilityShapeKind | CapabilityKind | string
  affordance?: FrontierAffordanceKind | string
  hypothesisClass?: string
  origin?: string
  method?: string
  route?: string
  targetSurfaceKey?: string
  pruned?: boolean
  attemptCount?: number
}

export interface FrontierPersonaInput {
  handle: string
  roleLabel?: string | null
  configIndex?: number
}

export interface FrontierConfirmedRefInput {
  origin?: string | null
  method?: string | null
  path?: string | null
  probeClass?: string | null
  hasCompositeReceipt?: boolean
}

export interface RankCapabilityConsumerPairsInput {
  llmMode?: FrontierLlmMode
  approvedOrigins: readonly string[] | ReadonlySet<string>
  capabilities: readonly FrontierCapabilityInput[]
  endpoints: readonly FrontierEndpointInput[]
  observedResponses?: readonly FrontierObservedResponseInput[]
  negativeEdges?: readonly (FrontierNegativeEdgeInput | NegativeEdge)[]
  completedTargets?: ReadonlySet<string> | readonly string[]
  personas?: readonly FrontierPersonaInput[]
  maxPairs?: number
}

export interface RankedCapabilityConsumerPair {
  pairKey: string
  capability: {
    capId: string
    origin: string
    producerEndpoint: string | null
    producerMethod: string | null
    shapeKind: CapabilityShapeKind
    actingPersona: string
    label: string
    factId: string | null
    runtimeObserved?: boolean
  }
  consumer: {
    origin: string
    method: string
    pathTemplate: string
    normPath: string
    observedDeniedStatuses: number[]
    hasSignatureRejection: boolean
    deniedPersonas: string[]
  }
  affordance: FrontierAffordanceKind
  crossOrigin: boolean
  score: number
  reasons: string[]
  nextHopInstruction: string
}

export interface CapabilityFrontierStepDraft {
  pairKey: string
  title: string
  hypothesis: string
  category: string
  priority: number
  origins: string[]
  skills: string[]
  actingPersona: string
  affordance: FrontierAffordanceKind
  capabilityKind: CapabilityShapeKind
  capId: string
  consumerOrigin: string
  consumerMethod: string
  consumerRoute: string
  dependsOnFactIds: string[]
}

export interface MaterializeCapabilityFrontierOptions {
  activeOrigins?: ReadonlySet<string>
  llmMode?: FrontierLlmMode
  maxSteps?: number
  existingSteps?: readonly ChainStep[]
  existingFacts?: readonly Fact[]
  confirmedRefs?: readonly FrontierConfirmedRefInput[]
  extraNegativeEdges?: readonly FrontierNegativeEdgeInput[]
  routeStep?: (step: { title: string; hypothesis: string; category: string; skills: string[] }) => ChainStep['specialistProfile']
}

const DEFAULT_MAX_FRONTIER_STEPS = 6
const HARD_MAX_FRONTIER_STEPS = 12
const MAX_PAIRS_PER_CAP = 3
const MAX_PAIRS_PER_CONSUMER = 2
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const HEALTH_OR_STATIC_RE = /^\/(?:health|healthz|ready|readyz|live|livez|metrics|ping|favicon\.ico|robots\.txt|assets|static)(?:\/|$)/i
const SKIP_SEGMENTS = new Set(['api', 'v1', 'v2', 'v3', 'v4', 'rest', 'public', 'internal', 'service', 'services', 'app', 'oauth', 'oauth2', 'oidc', 'auth'])
const NON_AGENTIC_PROVENANCES = new Set(['static_analysis', 'attacker_seed', 'floor_observation'])
const NON_AGENTIC_FACT_SUBKINDS = new Set(['code_audit_suspect', 'det_lead', 'hop_checkpoint', 'floor_lead', 'static_suspect'])
const NON_AGENTIC_FACT_SOURCES = new Set(['static_analysis', 'code_audit', 'deterministic_floor', 'floor_observation', 'phase0', 'openapi', 'repo_ast', 'attacker_seed', 'synthetic', 'deterministic-no-llm'])
const LIVE_AGENTIC_FACT_KINDS = new Set(['secret', 'object_ref', 'auth', 'cookie', 'redirect', 'config', 'policy_gap', 'note', 'dom'])
const GENERIC_ACTOR_LABELS = new Set(['', 'worker', 'unknown', 'anonymous', 'system', 'host'])

const SIGNING_SECRET_RE = /(?:^|[^a-z0-9])(?:signing[_-]?(?:secret|key|salt|material)|hmac[_-]?(?:secret|key|salt)?|webhook[_-]?(?:secret|key|signing|salt)|(?:sig|signature|mac|digest|verify)[_-]?(?:secret|key|salt)|private[_-]?key|shared[_-]?secret|jwt[_-]?(?:secret|key)|client[_-]?secret|master[_-]?key|secret[_-]?key|signing|salt)(?:[^a-z0-9]|$)/i
const SPARSE_SECRET_IDENT_RE = /(?:^|[^a-z0-9])(?:secret|salt|hmac|signing|sig)(?:[^a-z0-9]|$)/i
const SIGNED_URL_FIELD_RE = /(?:^|[^a-z0-9])(?:signed[_-]?url|presigned[_-]?url|download[_-]?url|export[_-]?url|artifact[_-]?url|result[_-]?url|file[_-]?url|upload[_-]?url|callback[_-]?url|location[_-]?url|download[_-]?link)(?:[^a-z0-9]|$)/i
const SIGNED_URL_VALUE_RE = /(?:https?:\/\/|\/)[^\s]*(?:[?&](?:sig|signature|expires|exp|x-amz-signature|token|download)=|\/(?:download|export|result|artifact|presign|signed)\b)/i
const CREDENTIAL_TOKEN_RE = /(?:^|[^a-z0-9])(?:jwt|bearer|access[_-]?token|id[_-]?token|refresh[_-]?token|session[_-]?(?:token|id|cookie)|api[_-]?key|apikey|pat|invite[_-]?(?:token|code)|scim(?:[_-]?(?:token|key|secret))?|service[_-]?token|auth[_-]?token|exchange[_-]?token|delegation(?:[_-]?(?:token|key|grant|assertion))?|assertion|oauth[_-]?token|credential|token|cookie)(?:[^a-z0-9]|$)/i
const SIGNING_PRODUCER_ROUTE_RE = /\/(?:webhooks?|hooks?|signing|hmac|crypto)(?:\/|$)/i
const CRED_PRODUCER_ROUTE_RE = /\/(?:oauth|oauth2|oidc|sso|auth|login|tokens?|sessions?|scim|delegat\w*|invites?)(?:\/|$)/i
const DUAL_TENANT_FRONTIER_SIGNAL_RE = /(?:^|[^a-z0-9])(?:cache|cached|cache[_-]?bleed|cache[_-]?key|shared[_-]?(?:edge[_-]?)?cache|edge[_-]?cache|prime|primed[_-]?cache|warm|cdn|cross[_-]?tenant|dual[_-]?tenant|multi[_-]?tenant|abac|switch[_-]?(?:tenant|org|workspace)|(?:tenant|org|workspace)[_-]?switch)(?:[^a-z0-9]|$)/i
const ORG_SWITCH_ROUTE_RE = /\/(?:orgs?|tenants?|organizations?|workspaces?)(?:\/[^/]+)?\/switch(?:\/|$)/i
const CAP_HANDLE_PREFIX_RE = /^cap:/i
const SYNTHETIC_PRECONDITION_CAP_RE = /^(?:surface|branch):/i
const KNOWN_NEGATIVE_RULE_KINDS: ReadonlySet<string> = new Set<string>([
  'credential_token', 'signing_secret', 'signed_or_download_url', 'entity_or_job_id',
  'derive_signature', 'pivot_with_credential', 'consume_entity_id', 'redeem_signed_url',
  ...CAPABILITY_KINDS,
])
const CAP_NOISE_NOUNS = new Set(['hop', 'cap', 'val', 'value', 'raw', 'slot', 'data', 'item', 'secret', 'token', 'key', 'salt', 'url'])
const JWT_SHAPE_RE = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/
const UUID_OR_PREFIX_ID_RE = /\b(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z]{2,8}_[a-z0-9]{4,})\b/i

const SIG_REJECTION_RE = /(?:sig(?:nature)?|hmac|digest|mac\b|webhook|x-signature|x-hub-signature|timestamp|invalid[_ -]?(?:sig|hmac|auth|token|jwt)|missing[_ -]?sig|bad[_ -]?sig|verify|signed|unauthorized)/i
const SIG_CONSUMER_ROUTE_RE = /\/(?:webhooks?|hooks?|ingest|callback|callbacks|events?|notify|deliver|delivery|dispatch|verify|sign|signed|receive|receiver|inbound|push|sync)(?:\/|$)/i
const SIG_SINK_RE = /(?:hmac|webhook|sig|jwt|crypto)/i
const PRIVILEGED_ROUTE_RE = /\/(?:admin|internal|vault|secrets?|keys?|approve|approval|patch|sync|config|settings?|roles?|permissions?|users?|members?|scim|tenants?|orgs?|organizations?|workspaces?|payouts?|transfers?|settle|release|finalize|revoke|impersonate|delegate|assume|exports?|audit|billing)(?:\/|$)/i
const SIBLING_VERB_ROUTE_RE = /\/(?:rebind|approve|trace|result|results|deliveries|delivery|archive|content|settle|release|finalize|revoke|cancel|dispatch|execute|run|download|export|url|status|logs|artifacts?|members?|secrets?|tokens?|keys?|sync|verify|trigger|complete|confirm|transfer|patch|update)(?:\/|$)/i
const DOWNLOAD_ROUTE_RE = /\/(?:download|downloads|export|exports|file|files|artifact|artifacts|result|results|content|storage|media|presign|signed|fetch|proxy|redirect|archive|snapshot|report|reports)(?:\/|$)/i

const AFFORDANCE_TIEBREAK: Record<FrontierAffordanceKind, number> = {
  derive_signature: 0,
  pivot_with_credential: 1,
  consume_entity_id: 2,
  redeem_signed_url: 3,
}

const toSnake = (raw: string): string =>
  raw.trim().replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '').toLowerCase()

const singularizeNoun = (word: string): string => {
  if (word.length <= 2) return word
  if (word.endsWith('ies') && word.length > 4) return `${word.slice(0, -3)}y`
  if (/(?:ses|xes|zes|ches|shes)$/.test(word) && word.length > 4) return word.slice(0, -2)
  if (word.endsWith('s') && !/(?:ss|us|is)$/.test(word)) return word.slice(0, -1)
  return word
}

const hostLabelOf = (origin: string): string =>
  URL.canParse(origin) ? new URL(origin).host.toLowerCase() : origin.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase()

function extractPathNouns(normPath: string): string[] {
  const nouns: string[] = []
  for (const rawSeg of normPath.split('/')) {
    const seg = rawSeg.trim().toLowerCase()
    if (!seg || seg.startsWith(':') || SKIP_SEGMENTS.has(seg)) continue
    const tail = toSnake(seg.replace(/[^a-z0-9_-]/g, '')).split('_').pop() ?? ''
    const noun = singularizeNoun(tail)
    if (noun.length >= 2 && !SKIP_SEGMENTS.has(noun)) nouns.push(noun)
  }
  return [...new Set(nouns)]
}

function parseCapIdParts(capId: string): { hopId: string | null; slot: string | null } {
  const m = /^cap:hop_([^:]+):([^:]+)$/i.exec(capId.trim())
  return m ? { hopId: m[1] ?? null, slot: m[2] ?? null } : { hopId: null, slot: null }
}

function isInvalidActorHandle(handle: string): boolean {
  return !handle
    || GENERIC_ACTOR_LABELS.has(handle.toLowerCase())
    || CAP_HANDLE_PREFIX_RE.test(handle)
    || DERIVED_CAPABILITY_HANDLE_RE.test(handle)
}

function extractCapabilityNouns(cap: FrontierCapabilityInput): Set<string> {
  const out = new Set<string>()
  const capParts = parseCapIdParts(cap.capId)
  for (const raw of [cap.fieldName, cap.label, cap.slot, cap.sourceHopId, capParts.hopId, capParts.slot]) {
    if (!raw) continue
    const snake = toSnake(raw).replace(/_(?:id|ids|uuid|key|token|secret|salt|url|handle|ref)$/, '')
    for (const part of snake.split('_')) {
      const n = singularizeNoun(part)
      if (n.length >= 2 && !SKIP_SEGMENTS.has(n) && !CAP_NOISE_NOUNS.has(n) && !/^[hsv]\d+$/i.test(n)) out.add(n)
    }
  }
  if (cap.producerEndpoint) {
    const norm = normalizeRouteTemplate(cap.producerEndpoint, { preserveCase: false })
    for (const n of extractPathNouns(norm)) out.add(n)
  }
  return out
}

function hasBaseAgenticCapabilityEligibility(
  node: Pick<CapabilityNode, 'capId' | 'kind' | 'provenance' | 'temporalState' | 'metadata'>,
): boolean {
  if (!DERIVED_CAPABILITY_HANDLE_RE.test(node.capId)) return false
  if (node.capId.startsWith('cap:hop_synth:') || node.capId.startsWith('cap:hop_seed_')) return false
  if (NON_AGENTIC_PROVENANCES.has(node.provenance)) return false
  if (node.kind === 'policy_asymmetry') return false
  if (node.temporalState === 'expired') return false
  if (node.metadata && (
    typeof node.metadata.synthCapId === 'string'
    || typeof node.metadata.hypothesisId === 'string'
    || node.metadata.consumerTarget === true
    || node.metadata.source === 'deterministic-no-llm'
  )) return false
  return true
}

/** True iff a `CapabilityLedger` node is a live agentic runtime-observed capability hop (`metadata.runtimeObserved === true`). */
export function isAgenticRuntimeCapabilityNode(
  node: Pick<CapabilityNode, 'capId' | 'kind' | 'provenance' | 'temporalState' | 'metadata'> & { tenantScope?: string },
): boolean {
  if (!hasBaseAgenticCapabilityEligibility(node)) return false
  return node.metadata?.runtimeObserved === true
}

/** True iff a `CapabilityLedger` node represents an agentic runtime-sealed or live runtime-observed capability (never a pre-floor seed, static stub, or hypothetical projection). */
export function isAgenticSealedCapabilityNode(
  node: Pick<CapabilityNode, 'capId' | 'kind' | 'provenance' | 'temporalState' | 'metadata'> & { tenantScope?: string },
): boolean {
  if (!hasBaseAgenticCapabilityEligibility(node)) return false
  if (node.metadata?.runtimeObserved === true) return true
  if (node.tenantScope === 'unscoped_hypothesis') return false
  if (node.metadata && typeof node.metadata.hopId === 'string' && typeof node.metadata.roundNo === 'number') {
    return false
  }
  return true
}

/** Fast check for whether the run's `CapabilityLedger` contains at least one agentic sealed or live runtime-observed capability. */
export function hasAgenticSealedCapabilities(
  ledger: Pick<CapabilityLedger, 'listCapabilities'>,
  options?: { llmMode?: FrontierLlmMode },
): boolean {
  if (options?.llmMode === 'deterministic-no-llm') return false
  return ledger.listCapabilities().some(isAgenticSealedCapabilityNode)
}

function classifyHopSurface(hop: ChainHop): CapabilitySurface {
  if (hop.artifactKind === 'stored_write_handle') return 'browser'
  if (hop.artifactKind === 'ssrf_redirect_target') return 'webhook'
  if (hop.artifactKind === 'workflow_state_handle') return 'async_job'
  const ep = (hop.endpoint ?? '/').toLowerCase()
  if (/\/(?:graphql|gql)\b/.test(ep)) return 'graphql'
  if (/\/(?:webhooks?|hooks?|callback)\b/.test(ep)) return 'webhook'
  if (/\/(?:jobs?|exports?|tasks?|builds?|pipelines?|runs?|async)\b/.test(ep)) return 'async_job'
  if (/\/(?:storage|files?|artifacts?|downloads?|uploads?|media)\b/.test(ep)) return 'storage'
  return 'http'
}

function resolveHopCapabilityKind(hop: ChainHop, textCorpus: string): CapabilityKind {
  if (hop.artifactKind === 'token_ref') {
    return SIGNING_SECRET_RE.test(textCorpus) ? 'signing_material' : 'scoped_token'
  }
  if (hop.artifactKind === 'ssrf_redirect_target') {
    return SIGNED_URL_FIELD_RE.test(textCorpus) ? 'signed_artifact_or_url' : 'internal_reach_handle'
  }
  if (hop.artifactKind === 'workflow_state_handle') {
    return SIGNED_URL_FIELD_RE.test(textCorpus) ? 'signed_artifact_or_url' : 'state_handle'
  }
  if (hop.artifactKind === 'leaked_id') return 'opaque_object_ref'
  if (hop.artifactKind === 'role_transition') return 'identity_session'
  return 'write_sink_handle'
}

function extractSafeHopFactCue(
  hop: ChainHop,
  backingFacts: readonly Fact[],
  observed2xxIds: ReadonlySet<string>,
  observed2xxOrigins: ReadonlySet<string>,
): { runtimeObserved: boolean; exchangeId?: string; fieldName?: string; secretKind?: string; label?: string; textCorpus: string } {
  const textParts = [hop.summary, hop.endpoint ?? '', hop.artifactRef]
  if (hop.factIds.length === 0 || hop.artifactRef.startsWith('suspect:')) {
    return { runtimeObserved: false, textCorpus: textParts.join(' ') }
  }
  const sourceFacts = backingFacts.filter(f => !f.tainted && f.data?.subkind !== 'chain_hop' && f.data?.kind !== 'chain_hop')
  const inspectFacts = sourceFacts.length > 0 ? sourceFacts : backingFacts.filter(f => !f.tainted)
  let runtimeObserved = false
  let exchangeId: string | undefined
  let fieldName: string | undefined
  let secretKind: string | undefined
  let label: string | undefined

  for (const fact of inspectFacts) {
    const data = (fact.data ?? {}) as Record<string, unknown>
    const subkind = typeof data.subkind === 'string' ? data.subkind.trim().toLowerCase() : ''
    const source = typeof data.source === 'string' ? data.source.trim().toLowerCase() : ''
    if (
      (fact.kind as string) === 'code_audit_suspect'
      || NON_AGENTIC_FACT_SUBKINDS.has(subkind)
      || NON_AGENTIC_FACT_SOURCES.has(source)
      || data.hypothetical === true
      || data.synthetic === true
      || data.staticOnly === true
    ) continue

    textParts.push(fact.summary)
    for (const k of ['fieldName', 'slot', 'resourceKey', 'secretKind', 'label', 'tokenKind']) {
      if (typeof data[k] === 'string' && (data[k] as string).trim()) textParts.push(data[k] as string)
    }
    if (!fieldName) {
      const rawField = [data.fieldName, data.slot, data.resourceKey].find(v => typeof v === 'string' && v.trim()) as string | undefined
      if (rawField) fieldName = sanitizeCheckpointText(rawField, 48)
    }
    if (!secretKind && typeof data.secretKind === 'string' && data.secretKind.trim()) {
      secretKind = sanitizeCheckpointText(data.secretKind, 36)
    }
    if (!label && typeof data.label === 'string' && data.label.trim()) {
      label = sanitizeCheckpointText(data.label, 48)
    }

    const factExIds = [
      ...(Array.isArray(fact.exchangeIds) ? fact.exchangeIds : []),
      ...(typeof data.exchangeId === 'string' ? [data.exchangeId] : []),
      ...(Array.isArray(data.exchangeIds) ? data.exchangeIds.filter((v): v is string => typeof v === 'string') : []),
    ].map(s => s.trim()).filter(Boolean)
    const matchedExId = factExIds.find(id => observed2xxIds.size === 0 || observed2xxIds.has(id)) ?? factExIds[0]
    if (matchedExId && !exchangeId) exchangeId = matchedExId

    const hasConcreteArtifact = Boolean(
      matchedExId
      || hop.verified
      || data.verified === true
      || observed2xxOrigins.has(hop.origin)
      || fact.kind === 'secret'
      || fact.kind === 'object_ref'
      || typeof data.resourceId === 'string'
      || typeof data.workflowHandle === 'string'
      || typeof data.stateHandle === 'string'
      || typeof data.fieldName === 'string'
      || typeof data.secretKind === 'string'
      || typeof data.downloadUrl === 'string'
      || typeof data.signedUrl === 'string',
    )
    if (LIVE_AGENTIC_FACT_KINDS.has(fact.kind) && hasConcreteArtifact) {
      runtimeObserved = true
    }
  }
  return { runtimeObserved, exchangeId, fieldName, secretKind, label, textCorpus: textParts.join(' ') }
}

/** Preload 2xx broker exchanges and untainted facts once per `syncChainHopsToLedger` batch. */
export function buildHopRuntimeObservationIndex(
  storage: Store,
  runId: string,
  llmMode: FrontierLlmMode,
  existingFacts?: readonly Fact[],
): { factById: Map<string, Fact>; observed2xxIds: Set<string>; observed2xxOrigins: Set<string> } {
  const factById = new Map<string, Fact>()
  const observed2xxIds = new Set<string>()
  const observed2xxOrigins = new Set<string>()
  if (llmMode !== 'agentic') return { factById, observed2xxIds, observed2xxOrigins }
  const facts = existingFacts ?? storage.listFacts(runId, { includeTainted: false, limit: 300, offset: 0 })
  for (const f of facts) factById.set(f.id, f)
  try {
    const rows = storage.client.prepare(`
      SELECT id, origin FROM broker_exchanges
      WHERE run_id = ? AND status BETWEEN 200 AND 299
      ORDER BY created_at DESC LIMIT 300
    `).all(runId) as Array<{ id: string; origin: string }>
    for (const r of rows) {
      if (r.id) observed2xxIds.add(r.id)
      if (r.origin) observed2xxOrigins.add(r.origin)
    }
  } catch { /* best-effort runtime check */ }
  return { factById, observed2xxIds, observed2xxOrigins }
}

/** Sanitize a `ChainHop` identifier so opaque `secret:<factId>` refs never trip raw-secret metadata guards. */
export function sanitizeLedgerHopId(hopId: string): string {
  return sanitizeCheckpointText(
    hopId.replace(/(?:^|:)(?:secret|jwt|token|key|password|passwd|credential):/gi, ':ref_'),
    120,
  )
}

/** Classify whether a `ChainHop` is backed by a live agentic runtime observation (never static/hypothetical or `--no-llm`). */
export function inspectChainHopRuntimeObservation(
  hop: ChainHop,
  llmMode: FrontierLlmMode,
  index: { factById: ReadonlyMap<string, Fact>; observed2xxIds: ReadonlySet<string>; observed2xxOrigins: ReadonlySet<string> },
): { runtimeObserved: boolean; safeHopId: string; kindOverride?: CapabilityKind; exchangeId?: string; fieldName?: string; secretKind?: string; label?: string } {
  const safeHopId = sanitizeLedgerHopId(hop.hopId)
  if (llmMode !== 'agentic') return { runtimeObserved: false, safeHopId }
  const backingFacts = hop.factIds.map(id => index.factById.get(id)).filter((f): f is Fact => Boolean(f))
  const cue = extractSafeHopFactCue(hop, backingFacts, index.observed2xxIds, index.observed2xxOrigins)
  const kindOverride = cue.runtimeObserved ? resolveHopCapabilityKind(hop, cue.textCorpus) : undefined
  return {
    runtimeObserved: cue.runtimeObserved,
    safeHopId,
    ...(kindOverride ? { kindOverride } : {}),
    ...(cue.exchangeId ? { exchangeId: cue.exchangeId } : {}),
    ...(cue.fieldName ? { fieldName: cue.fieldName } : {}),
    ...(cue.secretKind ? { secretKind: cue.secretKind } : {}),
    ...(cue.label ? { label: cue.label } : {}),
  }
}

/**
 * Sync extracted typed `ChainHop`s into `CapabilityLedger` as quarantined `capability_only` nodes.
 * Strictly marks live agentic runtime-observed hops with `metadata.runtimeObserved = true` ONLY when
 * `llmMode === 'agentic'` and backed by a live non-static agentic fact / 2xx exchange, keeping
 * static/hypothetical projections and `--no-llm` runs isolated under `unscoped_hypothesis`.
 */
export function syncChainHopsToCapabilityLedger(
  storage: Store,
  run: Run,
  ledger: CapabilityLedger,
  hops: readonly ChainHop[],
  options: { llmMode?: FrontierLlmMode; existingFacts?: readonly Fact[] } = {},
): number {
  if (!hops.length) return 0
  const llmMode: FrontierLlmMode = options.llmMode ?? 'deterministic-no-llm'
  const index = buildHopRuntimeObservationIndex(storage, run.id, llmMode, options.existingFacts)

  let synced = 0
  for (const hop of hops.slice(0, 32)) {
    const slot = hop.hopId.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, '').slice(0, 56) || 'hop'
    const capId = formatDerivedCapabilityHandle(`r${hop.roundNo}`, slot)
    if (ledger.getCapability(capId)) continue
    const obs = inspectChainHopRuntimeObservation(hop, llmMode, index)
    try {
      ledger.addCapability({
        capId,
        kind: obs.kindOverride ?? resolveHopCapabilityKind(hop, `${hop.summary} ${hop.endpoint ?? ''}`),
        promotionStatus: 'capability_only',
        provenance: hop.verified ? 'derived_hop' : 'runtime_discovery',
        tenantScope: obs.runtimeObserved ? 'runtime_observed' : 'unscoped_hypothesis',
        actorPersona: hop.persona ?? 'attacker',
        serviceOrigin: hop.origin,
        surface: classifyHopSurface(hop),
        parentHopReceiptIds: hop.verified ? [obs.safeHopId] : [],
        artifactDigest: computeArtifactDigest(`${hop.hopId}|${hop.origin}|${hop.artifactRef}`),
        artifactSummary: sanitizeCheckpointText(hop.summary, 220),
        metadata: {
          hopId: obs.safeHopId,
          roundNo: hop.roundNo,
          ...(obs.runtimeObserved ? { runtimeObserved: true } : {}),
          ...(obs.exchangeId ? { exchangeId: obs.exchangeId } : {}),
          ...(hop.endpoint ? { endpoint: hop.endpoint } : {}),
          ...(hop.method ? { method: hop.method } : {}),
          ...(hop.factIds[0] ? { factId: hop.factIds[0] } : {}),
          ...(obs.fieldName ? { fieldName: obs.fieldName } : {}),
          ...(obs.secretKind ? { secretKind: obs.secretKind } : {}),
          ...(obs.label ? { label: obs.label } : {}),
        },
      })
      synced += 1
    } catch { /* ignore invalid/duplicate/secret-rejected hop mirrors */ }
  }
  return synced
}

/** Generically classify a capability into one of the four structural frontier shapes. */
export function classifyCapabilityShape(cap: FrontierCapabilityInput): CapabilityShapeKind {
  const capParts = parseCapIdParts(cap.capId)
  const identText = [cap.fieldName, cap.label, cap.slot, cap.sourceHopId, capParts.hopId, capParts.slot].filter(Boolean).join(' ')
  const text = [identText, cap.secretKind, cap.summary].filter(Boolean).join(' ')
  if (cap.ledgerKind === 'signing_material' || cap.secretKind === 'signing_salt' || cap.secretKind === 'hmac_key' || SIGNING_SECRET_RE.test(text)) {
    return 'signing_secret'
  }
  if (
    cap.ledgerKind === 'signed_artifact_or_url'
    || cap.secretKind === 'signed_url'
    || Boolean(cap.targetPath)
    || SIGNED_URL_FIELD_RE.test(text)
    || (typeof cap.valueHint === 'string' && SIGNED_URL_VALUE_RE.test(cap.valueHint))
  ) {
    return 'signed_or_download_url'
  }
  if (
    cap.ledgerKind === 'identity_session'
    || cap.ledgerKind === 'scoped_token'
    || (cap.secretKind && ['bearer_token', 'api_token', 'cookie', 'oidc_assertion', 'jwt', 'header_secret'].includes(cap.secretKind))
    || CREDENTIAL_TOKEN_RE.test(text)
    || (typeof cap.valueHint === 'string' && (JWT_SHAPE_RE.test(cap.valueHint) || /^Bearer\s+\S+/i.test(cap.valueHint)))
  ) {
    return 'credential_token'
  }
  const primarySlot = (cap.fieldName ?? cap.slot ?? capParts.slot ?? '').trim()
  const looksLikeEntityId = /(?:^|_)id$/i.test(primarySlot)
  if (!looksLikeEntityId) {
    const prodPath = cap.producerEndpoint ? normalizeRouteTemplate(cap.producerEndpoint, { preserveCase: false }) : ''
    if (prodPath && SIGNING_PRODUCER_ROUTE_RE.test(prodPath)) return 'signing_secret'
    if (prodPath && DOWNLOAD_ROUTE_RE.test(prodPath) && /(?:^|[^a-z0-9])(?:url|link|href|download|location)(?:[^a-z0-9]|$)/i.test(identText)) {
      return 'signed_or_download_url'
    }
    if (prodPath && CRED_PRODUCER_ROUTE_RE.test(prodPath)) return 'credential_token'
    if (SPARSE_SECRET_IDENT_RE.test(identText)) return 'signing_secret'
  }
  if (typeof cap.valueHint === 'string' && UUID_OR_PREFIX_ID_RE.test(cap.valueHint)) return 'entity_or_job_id'
  return 'entity_or_job_id'
}

interface PersonaContext {
  roleByHandle: Map<string, string | null | undefined>
  nonElevatedHandles: Set<string>
  basePersona: string | null
  multiTenantPersona: string | null
}

function buildPersonaContext(personas: readonly FrontierPersonaInput[] = []): PersonaContext {
  const roleByHandle = new Map<string, string | null | undefined>()
  const ranked: Array<{ handle: string; rank: number; idx: number; elevated: boolean; revoked: boolean; multiTenant: boolean }> = []
  personas.forEach((p, idx) => {
    const h = p.handle.trim()
    if (!h || isInvalidActorHandle(h)) return
    roleByHandle.set(h, p.roleLabel)
    const priv = classifyPersonaPrivilege(h, p.roleLabel)
    ranked.push({
      handle: h,
      rank: priv.rank,
      idx: typeof p.configIndex === 'number' && Number.isFinite(p.configIndex) ? p.configIndex : idx,
      elevated: priv.elevated,
      revoked: priv.revokedStale,
      multiTenant: priv.multiTenant,
    })
  })
  ranked.sort((a, b) => a.rank - b.rank || a.idx - b.idx)
  const nonElevatedHandles = new Set(ranked.filter(r => !r.elevated).map(r => r.handle))
  const basePersona = ranked.find(r => !r.elevated && !r.revoked && !r.multiTenant)?.handle
    ?? ranked.find(r => !r.elevated && !r.multiTenant)?.handle
    ?? null
  const multiTenantPersona = ranked.find(r => !r.elevated && r.multiTenant)?.handle ?? null
  return { roleByHandle, nonElevatedHandles, basePersona, multiTenantPersona }
}

function isDualTenantFrontierPair(
  cap: FrontierCapabilityInput,
  consumer?: Pick<IndexedConsumer, 'normPath' | 'paramNames'>,
): boolean {
  if (cap.temporalState === 'primed_cache' || cap.ledgerKind === 'parser_or_cache_primitive') return true
  if (cap.producerEndpoint && ORG_SWITCH_ROUTE_RE.test(normalizeRouteTemplate(cap.producerEndpoint, { preserveCase: false }))) return true
  if (consumer && ORG_SWITCH_ROUTE_RE.test(consumer.normPath)) return true
  const corpus = [
    cap.fieldName,
    cap.label,
    cap.slot,
    cap.sourceHopId,
    cap.summary,
    cap.producerEndpoint,
    cap.targetPath,
    consumer?.normPath,
    ...(consumer ? [...consumer.paramNames] : []),
  ].filter(Boolean).join(' ')
  return DUAL_TENANT_FRONTIER_SIGNAL_RE.test(corpus)
}

/**
 * Resolve the owning `actingPersona` for a capability without ever emitting a `cap:*` handle,
 * an unapproved/elevated persona, or a `multi_tenant` persona on non-dual-tenant steps.
 */
function resolveSafeActingPersona(
  cap: FrontierCapabilityInput,
  ctx: PersonaContext,
  options?: { allowMultiTenant?: boolean },
): string | null {
  const allowMultiTenant = Boolean(options?.allowMultiTenant)
  const hasConfigured = ctx.roleByHandle.size > 0
  const isApprovedNonElevated = (handle: string): boolean => {
    if (isInvalidActorHandle(handle)) return false
    if (hasConfigured) return ctx.nonElevatedHandles.has(handle)
    return !classifyPersonaPrivilege(handle, ctx.roleByHandle.get(handle)).elevated
  }
  const acceptCandidate = (handle: string): string | null => {
    if (!isApprovedNonElevated(handle)) return null
    const priv = classifyPersonaPrivilege(handle, ctx.roleByHandle.get(handle))
    if (priv.multiTenant && !allowMultiTenant) return ctx.basePersona
    return handle
  }

  const raw = (cap.actingPersona ?? '').trim()
  const rawAccepted = acceptCandidate(raw)
  if (rawAccepted) return rawAccepted

  const derived = (cap.derivedFromAttackerPersona ?? '').trim()
  const derivedAccepted = acceptCandidate(derived)
  if (derivedAccepted) return derivedAccepted

  if (allowMultiTenant && ctx.multiTenantPersona) return ctx.multiTenantPersona
  return ctx.basePersona ?? (hasConfigured ? null : 'attacker')
}

interface ParsedNegativeRule {
  capIds: Set<string>
  kinds: Set<string>
  origin: string | null
  method: string | null
  normRoute: string | null
}

function parseSurfaceKey(rawKey: string | undefined): { origin: string | null; method: string | null; normRoute: string | null } {
  const trimmed = (rawKey ?? '').trim()
  if (!trimmed) return { origin: null, method: null, normRoute: null }
  const pipes = trimmed.split('|').map(s => s.trim()).filter(Boolean)
  let origin: string | null = null
  let method: string | null = null
  let routeRaw = ''
  if (pipes.length >= 2) {
    if (/^https?:\/\//i.test(pipes[0]!)) origin = pipes[0]!
    const last = pipes[pipes.length - 1]!
    const mLast = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/\S*)$/i.exec(last)
    if (mLast) {
      method = mLast[1]!.toUpperCase()
      routeRaw = mLast[2]!
    } else {
      routeRaw = last.startsWith('/') ? last : ''
      const mid = pipes.length >= 3 ? pipes[1]!.toUpperCase() : ''
      if (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(mid)) method = mid
    }
  } else {
    const mUrl = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?:\/\/[^\s/]+)(\/\S*)$/i.exec(trimmed)
    const mSingle = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/\S*)$/i.exec(trimmed)
    if (mUrl) {
      method = mUrl[1]!.toUpperCase()
      origin = mUrl[2]!
      routeRaw = mUrl[3]!
    } else if (mSingle) {
      method = mSingle[1]!.toUpperCase()
      routeRaw = mSingle[2]!
    } else if (trimmed.startsWith('/')) {
      routeRaw = trimmed
    }
  }
  const routePathOnly = routeRaw ? (routeRaw.split(/[?#]/, 1)[0] ?? '') : ''
  const normRoute = routePathOnly ? normalizeRouteTemplate(routePathOnly, { preserveCase: false }) : null
  return { origin, method, normRoute: normRoute && normRoute !== '/' ? normRoute : null }
}

function buildNegativeRules(edges: readonly (FrontierNegativeEdgeInput | NegativeEdge)[] = []): ParsedNegativeRule[] {
  const rules: ParsedNegativeRule[] = []
  for (const raw of edges) {
    const edge = raw as FrontierNegativeEdgeInput
    if (edge.pruned === false && (edge.attemptCount ?? 1) < 2) continue
    const parsedSurface = parseSurfaceKey(edge.targetSurfaceKey)
    const origin = (edge.origin ?? parsedSurface.origin ?? '').trim() || null
    const methodRaw = (edge.method ?? parsedSurface.method ?? '').trim().toUpperCase()
    const method = methodRaw && methodRaw !== 'ANY' ? methodRaw : null
    const routeInput = (edge.route ?? '').trim()
    const normRoute = routeInput
      ? normalizeRouteTemplate(routeInput.split(/[?#]/, 1)[0] ?? routeInput, { preserveCase: false })
      : parsedSurface.normRoute
    if (!origin && !normRoute) continue
    const capIds = new Set<string>(
      [
        ...(edge.capId ? [edge.capId.trim()] : []),
        ...(edge.preconditionCapIds ?? []).map(s => s.trim()),
      ].filter(s => Boolean(s) && !SYNTHETIC_PRECONDITION_CAP_RE.test(s)),
    )
    const kinds = new Set<string>(
      [edge.capabilityKind, edge.affordance, edge.hypothesisClass]
        .map(v => (typeof v === 'string' ? v.trim().toLowerCase() : ''))
        .filter(v => Boolean(v) && KNOWN_NEGATIVE_RULE_KINDS.has(v)),
    )
    if (!normRoute && capIds.size === 0 && kinds.size === 0) continue
    rules.push({ capIds, kinds, origin, method, normRoute })
  }
  return rules
}

function isPrunedByNegativeEdge(
  rules: readonly ParsedNegativeRule[],
  capId: string,
  shapeKind: CapabilityShapeKind,
  ledgerKind: CapabilityKind | undefined,
  affordance: FrontierAffordanceKind,
  origin: string,
  method: string,
  normRoute: string,
): boolean {
  const kindTokens = new Set<string>([shapeKind, affordance, ...(ledgerKind ? [ledgerKind] : [])])
  for (const r of rules) {
    if (r.origin && r.origin !== origin) continue
    if (r.method && r.method !== method) continue
    if (r.normRoute && r.normRoute !== normRoute) continue
    const capMatch = r.capIds.size === 0 || r.capIds.has(capId)
    const kindMatch = r.kinds.size === 0 || [...r.kinds].some(k => kindTokens.has(k))
    if (capMatch && kindMatch) return true
  }
  return false
}

interface IndexedConsumer {
  key: string
  origin: string
  method: string
  pathTemplate: string
  normPath: string
  nouns: Set<string>
  paramNames: Set<string>
  hasIdParam: boolean
  isMutating: boolean
  authRequirement: string
  riskScore: number
  sinkKinds: string[]
  observedDeniedStatuses: Set<number>
  deniedPersonas: Set<string>
  hasSignatureRejection: boolean
}

function parseHeadersText(raw: Record<string, string> | string | null | undefined): string {
  if (!raw) return ''
  if (typeof raw === 'string') return raw
  return Object.entries(raw).map(([k, v]) => `${k}: ${v}`).join(' ')
}

function indexConsumers(
  endpoints: readonly FrontierEndpointInput[],
  observedResponses: readonly FrontierObservedResponseInput[],
  approved: ReadonlySet<string>,
): IndexedConsumer[] {
  const byKey = new Map<string, IndexedConsumer>()
  const upsert = (
    origin: string,
    method: string,
    rawPath: string,
    opts?: { authRequirement?: string | null; riskScore?: number; paramNames?: readonly string[]; hasObjectIdParam?: boolean; sinkKinds?: readonly string[] },
  ): IndexedConsumer | null => {
    const cleanOrigin = origin.trim()
    if (!approved.has(cleanOrigin)) return null
    const cleanMethod = (method || 'GET').trim().toUpperCase()
    const pathOnly = (rawPath.split(/[?#]/, 1)[0] ?? '').trim()
    const normPath = normalizeRouteTemplate(pathOnly, { preserveCase: false })
    if (!normPath || normPath === '/' || HEALTH_OR_STATIC_RE.test(normPath)) return null
    const key = `${cleanOrigin}|${cleanMethod}|${normPath}`
    let node = byKey.get(key)
    if (!node) {
      const paramNames = new Set<string>()
      for (const seg of pathOnly.split('/')) {
        const m = /^(?::([A-Za-z0-9_.-]+)|\{([A-Za-z0-9_.-]+)\}|\[([A-Za-z0-9_.-]+)\])$/.exec(seg.trim())
        const pName = m?.[1] ?? m?.[2] ?? m?.[3]
        if (pName) paramNames.add(toSnake(pName))
      }
      const nouns = new Set(extractPathNouns(normPath))
      node = {
        key,
        origin: cleanOrigin,
        method: cleanMethod,
        pathTemplate: pathOnly.includes(':') || pathOnly.includes('{') ? pathOnly : normPath,
        normPath,
        nouns,
        paramNames,
        hasIdParam: normPath.includes('/:id'),
        isMutating: MUTATING_METHODS.has(cleanMethod),
        authRequirement: (opts?.authRequirement ?? '').trim(),
        riskScore: opts?.riskScore ?? 60,
        sinkKinds: [...(opts?.sinkKinds ?? [])],
        observedDeniedStatuses: new Set(),
        deniedPersonas: new Set(),
        hasSignatureRejection: false,
      }
      byKey.set(key, node)
    }
    if (opts?.authRequirement && !node.authRequirement) node.authRequirement = opts.authRequirement.trim()
    if (typeof opts?.riskScore === 'number' && opts.riskScore > node.riskScore) node.riskScore = opts.riskScore
    if (opts?.hasObjectIdParam) node.hasIdParam = true
    for (const p of opts?.paramNames ?? []) {
      const sn = toSnake(p)
      if (!sn) continue
      node.paramNames.add(sn)
      if (sn === 'id' || sn.endsWith('_id')) node.hasIdParam = true
      if (sn.endsWith('_id') && sn.length > 3) {
        const n = singularizeNoun(sn.slice(0, -3).split('_').pop() ?? '')
        if (n.length >= 2) node.nouns.add(n)
      }
    }
    for (const sk of opts?.sinkKinds ?? []) if (!node.sinkKinds.includes(sk)) node.sinkKinds.push(sk)
    return node
  }

  for (const ep of endpoints) {
    upsert(ep.origin, ep.method, ep.pathTemplate, ep)
  }
  for (const ex of observedResponses) {
    const node = upsert(ex.origin, ex.method, ex.pathAndQuery)
    if (!node) continue
    if (ex.status === 401 || ex.status === 403) {
      node.observedDeniedStatuses.add(ex.status)
      const persona = (ex.personaHandle ?? '').trim()
      if (persona) node.deniedPersonas.add(persona)
      const diag = `${ex.bodyPreview ?? ''} ${parseHeadersText(ex.respHeaders)}`
      if (SIG_REJECTION_RE.test(diag) || (node.isMutating && SIG_CONSUMER_ROUTE_RE.test(node.normPath))) {
        node.hasSignatureRejection = true
      }
    }
  }
  return [...byKey.values()]
}

function buildNextHopInstruction(
  affordance: FrontierAffordanceKind,
  capId: string,
  actingPersona: string,
  consumer: IndexedConsumer,
  runtimeObserved = false,
  producerDesc?: string | null,
): string {
  const target = `${consumer.method} ${consumer.origin}${consumer.normPath}`
  const sealHint = runtimeObserved && producerDesc
    ? ` If unsealed, first capture via kovo_verify seal_capability on ${producerDesc}.`
    : ''
  switch (affordance) {
    case 'derive_signature':
      return `Use kovo_verify with hmac_sign / jwt_sign over sealed handle ${capId} as ${actingPersona} to test standard signing schemes (HMAC-SHA256 hex/base64 over raw JSON body, timestamp.body, or canonical params; HS256 JWT) against ${target}, and compare against a clean unsigned/invalid-signature denied control (401/403).${sealHint}`
    case 'pivot_with_credential':
      return `Use kovo_verify to inject sealed credential handle ${capId} (Bearer/header/cookie) as ${actingPersona} against denied endpoint ${target}, comparing the base persona's 401/403 control against the credential-bearing variant.${sealHint}`
    case 'consume_entity_id':
      return `Use kovo_verify to supply the discovered entity/job ID from ${capId} into sibling route ${target} as ${actingPersona}, verifying authorization and tenant isolation against a clean denied control.${sealHint}`
    case 'redeem_signed_url':
      return `Use kovo_verify to redeem/fetch the signed download/export URL from ${capId} at ${target} as ${actingPersona}, comparing unauthorized/cross-tenant access against a clean denied control.${sealHint}`
  }
}

interface ScoreOutcome {
  affordance: FrontierAffordanceKind
  score: number
  reasons: string[]
}

function scoreCapabilityConsumerMatch(
  cap: FrontierCapabilityInput,
  shapeKind: CapabilityShapeKind,
  capNouns: ReadonlySet<string>,
  actingPersona: string,
  consumer: IndexedConsumer,
  personaCtx: PersonaContext,
): ScoreOutcome | null {
  const crossOrigin = cap.origin !== consumer.origin
  const nounOverlap = [...capNouns].filter(n => consumer.nouns.has(n))
  const hasDenied = consumer.observedDeniedStatuses.size > 0
  const basePersonaDenied = consumer.deniedPersonas.has(actingPersona)
    || (personaCtx.basePersona !== null && consumer.deniedPersonas.has(personaCtx.basePersona))
    || [...consumer.deniedPersonas].some(p => personaCtx.nonElevatedHandles.has(p))
  const reasons: string[] = []

  if (shapeKind === 'signing_secret') {
    const isSigRoute = SIG_CONSUMER_ROUTE_RE.test(consumer.normPath)
    const hasSigSink = consumer.sinkKinds.some(sk => SIG_SINK_RE.test(sk))
    if (!consumer.hasSignatureRejection && !hasDenied && !(consumer.isMutating && isSigRoute) && !hasSigSink) return null
    let score = 82
    if (consumer.hasSignatureRejection) { score += 40; reasons.push('observed_401_403_signature_rejection') }
    else if (hasDenied) { score += 18; reasons.push('observed_401_403') }
    if (consumer.isMutating && isSigRoute) { score += 22; reasons.push('mutating_webhook_or_ingest_route') }
    else if (isSigRoute) { score += 12; reasons.push('webhook_or_ingest_route') }
    if (hasSigSink) { score += 18; reasons.push('signature_sink_hint') }
    if (consumer.isMutating) { score += 8; reasons.push('mutating_method') }
    if (nounOverlap.length) { score += 14; reasons.push(`noun_overlap:${nounOverlap[0]}`) }
    if (crossOrigin) { score += 12; reasons.push('cross_origin') }
    return { affordance: 'derive_signature', score, reasons }
  }

  if (shapeKind === 'credential_token') {
    const isPrivRoute = PRIVILEGED_ROUTE_RE.test(consumer.normPath)
    const requiresAuth = Boolean(consumer.authRequirement && consumer.authRequirement !== 'none')
    if (!hasDenied && !isPrivRoute && !(requiresAuth && consumer.isMutating)) return null
    let score = 74
    if (hasDenied && basePersonaDenied) { score += 34; reasons.push('base_persona_401_403') }
    else if (hasDenied) { score += 24; reasons.push('observed_401_403') }
    if (isPrivRoute) { score += 20; reasons.push('privileged_or_admin_route') }
    if (consumer.isMutating) { score += 10; reasons.push('mutating_method') }
    if (crossOrigin) { score += 16; reasons.push('cross_origin') }
    if (nounOverlap.length) { score += 10; reasons.push(`noun_overlap:${nounOverlap[0]}`) }
    return { affordance: 'pivot_with_credential', score, reasons }
  }

  if (shapeKind === 'signed_or_download_url') {
    const normTarget = cap.targetPath ? normalizeRouteTemplate(cap.targetPath, { preserveCase: false }) : ''
    const exactTarget = Boolean(
      normTarget && normTarget !== '/'
      && (!cap.targetOrigin || cap.targetOrigin === consumer.origin)
      && (consumer.normPath === normTarget || consumer.normPath.startsWith(normTarget)),
    )
    const isDownloadRoute = DOWNLOAD_ROUTE_RE.test(consumer.normPath)
    if (!exactTarget && !isDownloadRoute) return null
    let score = 76
    if (exactTarget) { score += 36; reasons.push('exact_signed_url_target') }
    if (isDownloadRoute) { score += 16; reasons.push('download_or_export_route') }
    if (nounOverlap.length) { score += 12; reasons.push(`noun_overlap:${nounOverlap[0]}`) }
    if (crossOrigin) { score += 14; reasons.push('cross_origin') }
    if (hasDenied) { score += 10; reasons.push('observed_401_403') }
    return { affordance: 'redeem_signed_url', score, reasons }
  }

  // shapeKind === 'entity_or_job_id'
  const isSiblingVerb = SIBLING_VERB_ROUTE_RE.test(consumer.normPath)
  const acceptsId = consumer.hasIdParam || [...consumer.paramNames].some(p => p === 'id' || p.endsWith('_id'))
  if (!acceptsId) return null
  if (!nounOverlap.length && !isSiblingVerb) return null
  let score = 68
  if (nounOverlap.length) { score += 28; reasons.push(`noun_overlap:${nounOverlap[0]}`) }
  if (isSiblingVerb) { score += 24; reasons.push('sibling_verb_route') }
  if (consumer.isMutating) { score += 10; reasons.push('mutating_method') }
  if (hasDenied) { score += 12; reasons.push('observed_401_403') }
  if (crossOrigin) { score += 14; reasons.push('cross_origin') }
  return { affordance: 'consume_entity_id', score, reasons }
}

/**
 * Pure typed capability-to-consumer matcher.
 * Ranks `(agentic sealed capability, discovered consumer endpoint)` pairs across ALL approved
 * origins, pruning falsified negative edges and completed targets.
 */
export function rankCapabilityConsumerPairs(input: RankCapabilityConsumerPairsInput): RankedCapabilityConsumerPair[] {
  if (input.llmMode === 'deterministic-no-llm') return []
  const approved = input.approvedOrigins instanceof Set ? input.approvedOrigins : new Set(input.approvedOrigins)
  const maxPairs = Math.max(0, Math.min(36, Math.floor(input.maxPairs ?? 12)))
  if (approved.size === 0 || maxPairs <= 0 || input.capabilities.length === 0) return []

  const personaCtx = buildPersonaContext(input.personas)
  const consumers = indexConsumers(input.endpoints, input.observedResponses ?? [], approved)
  if (consumers.length === 0) return []

  const negativeRules = buildNegativeRules(input.negativeEdges)
  const completedSet = input.completedTargets instanceof Set ? input.completedTargets : new Set(input.completedTargets ?? [])
  const scored: RankedCapabilityConsumerPair[] = []

  for (const cap of input.capabilities) {
    if (!approved.has(cap.origin)) continue
    if (cap.provenance && NON_AGENTIC_PROVENANCES.has(cap.provenance)) continue
    if (cap.capId.startsWith('cap:hop_synth:') || cap.capId.startsWith('cap:hop_seed_')) continue
    if (cap.temporalState === 'expired') continue

    const shapeKind = classifyCapabilityShape(cap)
    const capNouns = extractCapabilityNouns(cap)
    const prodNorm = cap.producerEndpoint ? normalizeRouteTemplate(cap.producerEndpoint, { preserveCase: false }) : null
    const prodMethod = cap.producerMethod ? cap.producerMethod.trim().toUpperCase() : null
    const label = sanitizeCheckpointText((cap.fieldName || cap.label || cap.slot || cap.sourceHopId || cap.capId).trim(), 48)

    for (const consumer of consumers) {
      if (prodNorm && cap.origin === consumer.origin && prodNorm === consumer.normPath && (!prodMethod || prodMethod === consumer.method)) {
        continue
      }
      const actingPersona = resolveSafeActingPersona(cap, personaCtx, {
        allowMultiTenant: isDualTenantFrontierPair(cap, consumer),
      })
      if (!actingPersona) continue
      const match = scoreCapabilityConsumerMatch(cap, shapeKind, capNouns, actingPersona, consumer, personaCtx)
      if (!match) continue

      const pairKey = `${cap.capId}|${match.affordance}|${consumer.origin}|${consumer.method}|${consumer.normPath}`
      const routeOnlyKey = `${consumer.origin}|${consumer.method}|${consumer.normPath}`
      const affordanceRouteKey = `${match.affordance}|${routeOnlyKey}`
      if (completedSet.has(pairKey) || completedSet.has(routeOnlyKey) || completedSet.has(affordanceRouteKey)) continue
      if (isPrunedByNegativeEdge(negativeRules, cap.capId, shapeKind, cap.ledgerKind, match.affordance, consumer.origin, consumer.method, consumer.normPath)) {
        continue
      }

      scored.push({
        pairKey,
        capability: {
          capId: cap.capId,
          origin: cap.origin,
          producerEndpoint: prodNorm,
          producerMethod: prodMethod,
          shapeKind,
          actingPersona,
          label,
          factId: cap.factId ?? null,
          ...(cap.runtimeObserved ? { runtimeObserved: true } : {}),
        },
        consumer: {
          origin: consumer.origin,
          method: consumer.method,
          pathTemplate: consumer.pathTemplate,
          normPath: consumer.normPath,
          observedDeniedStatuses: [...consumer.observedDeniedStatuses].sort((a, b) => a - b),
          hasSignatureRejection: consumer.hasSignatureRejection,
          deniedPersonas: [...consumer.deniedPersonas].sort(),
        },
        affordance: match.affordance,
        crossOrigin: cap.origin !== consumer.origin,
        score: match.score,
        reasons: match.reasons,
        nextHopInstruction: buildNextHopInstruction(
          match.affordance,
          cap.capId,
          actingPersona,
          consumer,
          Boolean(cap.runtimeObserved),
          prodNorm ? `${prodMethod ? `${prodMethod} ` : ''}${cap.origin}${prodNorm}` : null,
        ),
      })
    }
  }

  scored.sort((a, b) =>
    b.score - a.score
    || AFFORDANCE_TIEBREAK[a.affordance] - AFFORDANCE_TIEBREAK[b.affordance]
    || Number(b.crossOrigin) - Number(a.crossOrigin)
    || a.pairKey.localeCompare(b.pairKey),
  )

  const selected: RankedCapabilityConsumerPair[] = []
  const perCap = new Map<string, number>()
  const perConsumer = new Map<string, number>()
  const seenPairs = new Set<string>()
  for (const item of scored) {
    if (selected.length >= maxPairs) break
    if (seenPairs.has(item.pairKey)) continue
    const consumerKey = `${item.consumer.origin}|${item.consumer.method}|${item.consumer.normPath}`
    if ((perCap.get(item.capability.capId) ?? 0) >= MAX_PAIRS_PER_CAP) continue
    if ((perConsumer.get(consumerKey) ?? 0) >= MAX_PAIRS_PER_CONSUMER) continue
    seenPairs.add(item.pairKey)
    perCap.set(item.capability.capId, (perCap.get(item.capability.capId) ?? 0) + 1)
    perConsumer.set(consumerKey, (perConsumer.get(consumerKey) ?? 0) + 1)
    selected.push(item)
  }
  return selected
}

/** Build a dispatchable `ChainStep` draft from a ranked capability-consumer pair. */
export function buildCapabilityFrontierStepDraft(
  pair: RankedCapabilityConsumerPair,
  rankIdx: number,
  siblingConsumers: readonly RankedCapabilityConsumerPair['consumer'][] = [],
): CapabilityFrontierStepDraft {
  const { capability: cap, consumer, affordance, crossOrigin } = pair
  const host = hostLabelOf(consumer.origin)
  const title = `Capability frontier · ${affordance} · ${host} ${consumer.method} ${consumer.normPath} (${cap.label})`.slice(0, 180)
  const origins = [...new Set([consumer.origin, cap.origin])]
  const tags = [
    '[chain_hops=2]',
    '[lane=chain]',
    `[cap_frontier=${affordance}]`,
    `[cap=${cap.capId}]`,
    `[cap_kind=${cap.shapeKind}]`,
    `[acting_persona=${cap.actingPersona}]`,
    `[api_dependency:${cap.label}]`,
    ...(crossOrigin ? [`[cross_origin_edge:${cap.origin}->${consumer.origin}]`] : []),
    ...(consumer.observedDeniedStatuses.length ? [`[persona_diff:${consumer.method} ${consumer.normPath} denied=${consumer.observedDeniedStatuses.join('/')}]`] : []),
  ]
  const prodDesc = cap.producerEndpoint
    ? `${cap.producerMethod ? `${cap.producerMethod} ` : ''}${cap.origin}${cap.producerEndpoint}`
    : cap.origin
  const altDesc = siblingConsumers.length > 0
    ? ` Alternate consumer candidates: ${siblingConsumers.slice(0, 2).map(c => `${c.method} ${c.origin}${c.normPath}`).join(', ')}.`
    : ''
  const hypothesis = `${tags.join(' ')} Sealed capability ${cap.capId} (type=${cap.shapeKind}, producer=${prodDesc}, actingPersona=${cap.actingPersona}) -> consumer ${consumer.method} ${consumer.origin}${consumer.normPath} [${affordance}]. ${pair.nextHopInstruction}${altDesc}`.slice(0, 1400)

  const category = affordance === 'redeem_signed_url'
    ? 'upload-storage'
    : affordance === 'derive_signature' || affordance === 'pivot_with_credential'
      ? 'auth-identity'
      : 'broken-access-control'
  const basePriority = affordance === 'derive_signature'
    ? (consumer.hasSignatureRejection ? 98 : 95)
    : affordance === 'pivot_with_credential'
      ? (consumer.observedDeniedStatuses.length ? 97 : 93)
      : affordance === 'consume_entity_id' ? 94 : 93
  const priority = Math.max(88, Math.min(99, basePriority - Math.min(rankIdx, 5)))
  const affordanceSkills = affordance === 'derive_signature'
    ? ['crypto-signature-derivation', 'auth-identity']
    : affordance === 'pivot_with_credential'
      ? ['authz-differential', 'auth-identity']
      : affordance === 'consume_entity_id'
        ? ['bola-idor-race', 'authz-differential']
        : ['upload-storage', 'authz-differential']
  const skills = [...new Set([
    'multihop-chains',
    'chain-primitives',
    'capability-frontier',
    ...affordanceSkills,
    ...(crossOrigin ? ['cross-origin-chain'] : []),
    ...(DERIVED_CAPABILITY_HANDLE_RE.test(cap.capId) ? [`checkpoint_cap:${cap.capId}`] : []),
  ])]

  return {
    pairKey: pair.pairKey,
    title,
    hypothesis,
    category,
    priority,
    origins,
    skills,
    actingPersona: cap.actingPersona,
    affordance,
    capabilityKind: cap.shapeKind,
    capId: cap.capId,
    consumerOrigin: consumer.origin,
    consumerMethod: consumer.method,
    consumerRoute: consumer.normPath,
    dependsOnFactIds: cap.factId ? [cap.factId] : [],
  }
}

function collectLedgerFrontierCapabilities(
  ledger: CapabilityLedger,
  facts: readonly Fact[],
  personas: readonly FrontierPersonaInput[],
  llmMode: FrontierLlmMode = 'agentic',
): FrontierCapabilityInput[] {
  if (llmMode === 'deterministic-no-llm') return []
  const nodes = ledger.listCapabilities().filter(node =>
    isAgenticSealedCapabilityNode(node)
    && (!isAgenticRuntimeCapabilityNode(node) || llmMode === 'agentic'),
  )
  if (!nodes.length) return []

  const nonElevated = personas
    .filter(p => !classifyPersonaPrivilege(p.handle, p.roleLabel).elevated)
    .map(p => p.handle)
  const factMetaByCap = new Map<string, { endpoint?: string; method?: string; fieldName?: string; factId?: string }>()
  for (const fact of facts) {
    if (fact.tainted) continue
    const data = fact.data ?? {}
    const capIds = new Set<string>()
    for (const k of ['capId', 'checkpointCapId', 'handle']) {
      if (typeof data[k] === 'string' && DERIVED_CAPABILITY_HANDLE_RE.test(data[k] as string)) capIds.add(data[k] as string)
    }
    const text = `${fact.summary} ${JSON.stringify(data)}`
    for (const m of text.matchAll(/cap:hop_[A-Za-z0-9._-]+:[A-Za-z0-9._-]+/g)) capIds.add(m[0]!)
    for (const id of capIds) {
      if (factMetaByCap.has(id)) continue
      factMetaByCap.set(id, {
        endpoint: typeof data.endpoint === 'string' ? data.endpoint : typeof data.producerEndpoint === 'string' ? data.producerEndpoint : undefined,
        method: typeof data.method === 'string' ? data.method : undefined,
        fieldName: typeof data.fieldName === 'string' ? data.fieldName : typeof data.slot === 'string' ? data.slot : undefined,
        factId: fact.id,
      })
    }
  }

  return nodes.map(node => {
    const meta = node.metadata ?? {}
    const factMeta = factMetaByCap.get(node.capId)
    const capParts = parseCapIdParts(node.capId)
    let derivedFromAttackerPersona: string | null = null
    if (nonElevated.length > 0) {
      const prov = ledger.traceProvenanceToAttacker(node.capId, nonElevated)
      if (prov.valid && prov.attackerRootPersonas.length > 0) {
        const singleTenantRoot = prov.attackerRootPersonas.find(
          h => !classifyPersonaPrivilege(h, personas.find(p => p.handle === h)?.roleLabel).multiTenant,
        )
        derivedFromAttackerPersona = singleTenantRoot ?? prov.attackerRootPersonas[0]!
      }
    }
    const sourceHopId = (typeof meta.sourceHopId === 'string' ? meta.sourceHopId
      : typeof meta.hopReceiptId === 'string' ? meta.hopReceiptId
      : node.parentHopReceiptIds[0]
      ?? capParts.hopId) ?? null
    const producerEndpoint = (typeof meta.endpoint === 'string' ? meta.endpoint
      : typeof meta.producerEndpoint === 'string' ? meta.producerEndpoint
      : typeof meta.route === 'string' ? meta.route
      : factMeta?.endpoint) ?? null
    return {
      capId: node.capId,
      origin: node.serviceOrigin,
      actingPersona: node.actorPersona,
      producerEndpoint,
      producerMethod: (typeof meta.method === 'string' ? meta.method : factMeta?.method) ?? null,
      ledgerKind: node.kind,
      secretKind: typeof meta.secretKind === 'string' ? meta.secretKind : null,
      fieldName: (typeof meta.fieldName === 'string' ? meta.fieldName : factMeta?.fieldName) ?? null,
      slot: (typeof meta.slot === 'string' ? meta.slot : capParts.slot) ?? null,
      label: typeof meta.label === 'string' ? meta.label : null,
      sourceHopId,
      summary: node.artifactSummary,
      provenance: node.provenance,
      temporalState: node.temporalState,
      targetOrigin: typeof meta.targetOrigin === 'string' ? meta.targetOrigin : null,
      targetPath: typeof meta.targetPath === 'string' ? meta.targetPath : null,
      derivedFromAttackerPersona,
      factId: (typeof meta.factId === 'string' ? meta.factId : factMeta?.factId) ?? null,
      ...(meta.runtimeObserved === true ? { runtimeObserved: true } : {}),
    }
  })
}

function buildCompletedTargetKeys(
  existingSteps: readonly ChainStep[],
  confirmedRefs: readonly FrontierConfirmedRefInput[],
): Set<string> {
  const keys = new Set<string>()
  for (const ref of confirmedRefs) {
    const origin = (ref.origin ?? '').trim()
    const norm = ref.path ? normalizeRouteTemplate(ref.path, { preserveCase: false }) : ''
    if (!origin || !norm || norm === '/') continue
    const method = (ref.method ?? '').trim().toUpperCase()
    if (method && method !== 'ANY') keys.add(`${origin}|${method}|${norm}`)
    else {
      for (const m of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) keys.add(`${origin}|${m}|${norm}`)
    }
  }
  for (const step of existingSteps) {
    if (step.status === 'canceled' || step.status === 'tainted') continue
    const capM = /\[cap=([^\]]+)\]/.exec(step.hypothesis)
    const affM = /\[cap_frontier=([^\]]+)\]/.exec(step.hypothesis)
    const consM = /->\s*consumer\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?:\/\/[^\s/]+)(\/[^\s[\]]+)/i.exec(step.hypothesis)
    if (capM?.[1] && affM?.[1] && consM?.[1] && consM?.[2] && consM?.[3]) {
      const norm = normalizeRouteTemplate(consM[3], { preserveCase: false })
      keys.add(`${capM[1]}|${affM[1]}|${consM[2]}|${consM[1].toUpperCase()}|${norm}`)
    }
  }
  return keys
}

/**
 * Load agentic sealed capabilities, discovered endpoints, observed 401/403 responses, and pruned
 * negative edges from SQLite `Store`, rank next-hop pairs, and idempotently persist up to
 * `maxSteps` (default 6) frontier `ChainStep`s for the active wave.
 */
export function materializeCapabilityConsumerFrontierSteps(
  storage: Store,
  run: Run,
  options: MaterializeCapabilityFrontierOptions = {},
): ChainStep[] {
  if (options.llmMode === 'deterministic-no-llm' || run.capabilityTier <= 0) return []
  const approvedOrigins = options.activeOrigins
    ?? new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin))
  if (approvedOrigins.size === 0) return []

  const maxSteps = Math.max(0, Math.min(HARD_MAX_FRONTIER_STEPS, Math.floor(options.maxSteps ?? DEFAULT_MAX_FRONTIER_STEPS)))
  if (maxSteps <= 0) return []

  const ledger = storage.capabilityLedger(run.id)
  const effectiveLlmMode: FrontierLlmMode = options.llmMode ?? 'agentic'
  if (!hasAgenticSealedCapabilities(ledger, { llmMode: effectiveLlmMode })) return []

  const approvedOrder = new Map(run.approvedPersonaIds.map((id, idx) => [id, idx]))
  const personas: FrontierPersonaInput[] = [...resolveRunPersonas(storage, run.projectId, run.approvedPersonaIds).values()]
    .map((p, idx) => ({ handle: p.handle, roleLabel: p.roleLabel, configIndex: approvedOrder.get(p.id) ?? idx }))
  const facts = options.existingFacts ?? storage.listFacts(run.id, { includeTainted: false, limit: 250, offset: 0 })
  const capabilities = collectLedgerFrontierCapabilities(ledger, facts, personas, effectiveLlmMode)
  if (!capabilities.length) return []

  const paramsByEp = new Map<string, { names: string[]; hasObjId: boolean }>()
  for (const p of storage.listEndpointParams(run.id).slice(0, 600)) {
    const entry = paramsByEp.get(p.endpointId) ?? { names: [], hasObjId: false }
    entry.names.push(p.name)
    if (p.isObjectId) entry.hasObjId = true
    paramsByEp.set(p.endpointId, entry)
  }
  const endpoints: FrontierEndpointInput[] = storage.listEndpoints(run.id, { limit: 250 })
    .filter(ep => approvedOrigins.has(ep.origin))
    .map(ep => {
      const pInfo = paramsByEp.get(ep.id)
      return {
        id: ep.id,
        origin: ep.origin,
        method: ep.method,
        pathTemplate: ep.pathTemplate,
        authRequirement: ep.authRequirement,
        riskScore: ep.riskScore,
        paramNames: pInfo?.names,
        hasObjectIdParam: pInfo?.hasObjId,
        sinkKinds: ep.sinkKinds,
      }
    })

  let observedResponses: FrontierObservedResponseInput[] = []
  try {
    const deniedRows = storage.client.prepare(`
      SELECT origin, method, path_and_query AS pathAndQuery, status, persona_handle AS personaHandle, resp_headers AS respHeaders, body_preview AS bodyPreview
      FROM broker_exchanges
      WHERE run_id = ? AND status IN (401, 403)
      ORDER BY created_at DESC LIMIT 150
    `).all(run.id) as unknown as FrontierObservedResponseInput[]
    observedResponses = deniedRows.filter(r => approvedOrigins.has(r.origin))
  } catch (err) {
    void err
  }

  const existingSteps = options.existingSteps ?? storage.listChainSteps(run.id, run.goalRevision)
  const activeFrontierCount = existingSteps.filter(
    s => s.title.startsWith('Capability frontier ·') && (s.status === 'pending' || s.status === 'ready' || s.status === 'running'),
  ).length
  const waveSlots = Math.max(0, maxSteps - activeFrontierCount)
  if (waveSlots <= 0) return []

  const existingTitles = new Set(existingSteps.map(s => s.title.trim().toLowerCase()))
  const completedTargets = buildCompletedTargetKeys(existingSteps, options.confirmedRefs ?? [])
  const negativeEdges: Array<NegativeEdge | FrontierNegativeEdgeInput> = [
    ...ledger.listNegativeEdges({ prunedOnly: true }),
    ...(options.extraNegativeEdges ?? []),
  ]

  const ranked = rankCapabilityConsumerPairs({
    llmMode: options.llmMode ?? 'agentic',
    approvedOrigins,
    capabilities,
    endpoints,
    observedResponses,
    negativeEdges,
    completedTargets,
    personas,
    maxPairs: Math.max(waveSlots * 2, 12),
  })
  if (!ranked.length) return []

  const created: ChainStep[] = []
  const liveFactIds = new Set(facts.map(f => f.id))
  for (let i = 0; i < ranked.length && created.length < waveSlots; i += 1) {
    const pair = ranked[i]!
    const siblings = ranked
      .filter(other => other !== pair && other.capability.capId === pair.capability.capId && other.affordance === pair.affordance)
      .map(other => other.consumer)
    const draft = buildCapabilityFrontierStepDraft(pair, created.length, siblings)
    const normTitle = draft.title.trim().toLowerCase()
    if (existingTitles.has(normTitle)) continue
    const validOrigins = draft.origins.filter(o => approvedOrigins.has(o))
    const assetIds = run.candidates
      .filter(c => validOrigins.includes(c.origin) && run.approved.includes(c.id))
      .map(c => c.id)
    if (!validOrigins.length || !assetIds.length) continue

    existingTitles.add(normTitle)
    const parentFactIds = draft.dependsOnFactIds.filter(id => liveFactIds.has(id))
    const step = storage.addChainStep(run, {
      title: draft.title,
      hypothesis: draft.hypothesis,
      category: draft.category,
      priority: draft.priority,
      targetAssetIds: assetIds,
      skills: draft.skills,
      dependsOnFactIds: parentFactIds,
      sourceOrigins: validOrigins,
      ...(options.routeStep ? { specialistProfile: options.routeStep(draft) } : {}),
    })
    created.push(storage.updateChainStep(step.id, { status: 'ready' }))
  }

  if (created.length > 0) {
    try {
      storage.event(
        run.id,
        'planner.capability_frontier',
        `Materialized ${created.length} capability-consumer frontier step(s) from ${capabilities.length} agentic sealed capability(ies).`,
        {
          createdCount: created.length,
          sealedCapabilities: capabilities.length,
          affordances: [...new Set(ranked.slice(0, created.length).map(r => r.affordance))],
        },
      )
    } catch (err) {
      void err
    }
  }
  return created
}
