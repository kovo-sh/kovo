// Shared contracts for realistic-bench. Every module (lib/, generator/, grader/, apps/*) imports
// these types; change them only with a coordinated update across all consumers.
// Taxonomy + funnel names deliberately mirror src/domain.ts (checked by tests/contracts.test.ts)
// but are copied, not imported, so the benchmark stays self-contained and independent of Kovo Hunter.

export const appNames = ['acme-saas', 'shopflow', 'opsportal'] as const
export type AppName = typeof appNames[number]

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type SiteMode = 'vulnerable' | 'hardened'
export type BenchMode = 'black-box' | 'grey-box' | 'white-box'
export type SeedSet = 'dev' | 'held-out'
export const personaIds = ['persona_a', 'persona_b', 'admin', 'viewer'] as const
export type PersonaId = typeof personaIds[number]
export type Actor = PersonaId | 'anonymous' | 'unknown'
export type IdFormat = 'int' | 'uuid' | 'prefixed' | 'hashid'

export const vulnClasses = [
  'idor', 'bola', 'bfla', 'graphql_bola', 'mass_assignment', 'auth_bypass', 'jwt', 'oauth',
  'csrf', 'sqli', 'ssti', 'ssrf', 'xxe', 'xss_stored', 'xss_reflected', 'path_traversal',
  'command_injection', 'cache_poisoning', 'cache_deception', 'race_condition', 'business_logic',
  'workflow_bypass', 'open_redirect', 'webhook_forgery', 'info_disclosure', 'rate_limit_bypass',
] as const
export type VulnClass = typeof vulnClasses[number]

export const oracleEventKinds = [
  'cross_tenant_read', 'cross_tenant_write', 'privilege_escalation', 'mass_assignment',
  'sql_structure_change', 'ssrf_internal_fetch', 'xxe_entity_resolved', 'path_escape',
  'command_injection_simulated', 'template_code_exec', 'stored_xss_rendered',
  'reflected_xss_rendered', 'auth_bypass', 'token_forgery', 'cache_poisoned', 'secret_disclosed',
  'open_redirect', 'csrf_state_change', 'race_double_spend', 'workflow_skip', 'webhook_forgery',
  'invariant_violation',
] as const
export type OracleEventKind = typeof oracleEventKinds[number]

// Mirrors src/domain.ts failureTaxonomyBuckets exactly (same order).
export const failureTaxonomyBuckets = [
  'surface_miss', 'hypothesis_miss', 'form_encoding_missing', 'csrf_blocked', 'context_reset',
  'tier_blocked', 'trigger_miss', 'jq_assertion_bug', 'spa_catchall_fp', 'replay_spec_miss',
  'budget_exhausted',
] as const
export type FailureTaxonomyBucket = typeof failureTaxonomyBuckets[number]

// Mirrors src/domain.ts BenchmarkFunnel (6 monotonic stages).
export interface BenchmarkFunnel {
  targetVulns: number
  surfaceDiscovered: number
  hypothesisFormed: number
  signalObserved: number
  specSubmitted: number
  zeroLlmConfirmed: number
}

export const budgetThresholdsUsd = [1, 5, 20] as const

// ---------------------------------------------------------------------------------------------
// Impact oracle side-channel (lib/oracle.ts). Never exposed on the app's HTTP surface and never
// fed into Kovo Hunter's ReplayVerifier; only the grader consumes it.
// ---------------------------------------------------------------------------------------------
export interface OracleEvent {
  seq: number
  ts: number // epoch ms
  kind: OracleEventKind
  app: AppName
  routeKey: string | null // logical route key of the request in whose context the impact happened
  method: string
  path: string // runtime path actually requested
  actor: Actor
  sessionId?: string
  sink?: string // generic sink tag, e.g. 'db:invoices', 'egress:metadata', 'vfs:/exports'
  detail: Record<string, string | number | boolean>
}

export interface RequestLogEntry {
  seq: number
  ts: number
  method: string
  path: string
  routeKey: string | null // null => unmatched (SPA fallback or 404)
  status: number
  actor: Actor
  contentType?: string
  paramNames: string[] // query + body field names seen
  suspicious: boolean // any input contained injection metacharacters / payload markers
  csrfRejected?: boolean
  spaFallback?: boolean
  sessionLost?: boolean // request carried a session cookie/token that was expired/unknown
  expectedEncoding?: 'json' | 'form' | 'multipart' | 'xml'
  encodingMismatch?: boolean
}

export interface EgressLogEntry {
  seq: number
  ts: number
  url: string
  allowed: boolean
  reason: string
  routeKey: string | null
}

// ---------------------------------------------------------------------------------------------
// Seeded variants (generator/)
// ---------------------------------------------------------------------------------------------
export interface RouteSpec { method: string; path: string } // path may contain :param segments

export interface PersonaCredential {
  id: PersonaId
  email: string
  password: string
  tenant: string // tenant slug
  role: 'owner' | 'member' | 'admin' | 'viewer'
}

export interface VariantPlan {
  app: AppName
  seed: number
  seedSet: SeedSet
  apiPrefix: string // e.g. '/api/v1', '/rest', '/api'
  routes: Record<string, RouteSpec> // logical routeKey -> runtime route
  params: Record<string, string> // logical param key -> runtime param/field name
  idFormat: IdFormat
  sites: Record<string, SiteMode> // siteId -> mode
  personas: Record<PersonaId, PersonaCredential>
  canarySalt: string // per-seed salt for canary tokens; synthetic, never a real secret
}

// Logical app description consumed by the generator. Lives in apps/<app>/truth/ (never mounted
// for white-box agents).
export interface RouteTemplate {
  method: string
  // Path made of literal segments, `{noun:<vocabKey>}` segments substituted from vocab, and
  // `:param` segments whose runtime name comes from params.
  path: string
}

export interface AppBlueprint {
  app: AppName
  apiPrefixes: string[]
  vocab: Record<string, string[]> // vocabKey -> synonyms, e.g. invoices: ['invoices','billing-docs']
  paramVocab: Record<string, string[]> // logical param -> synonyms
  routes: Record<string, RouteTemplate>
  idFormats: IdFormat[]
  sites: SiteSpec[]
  decoyCount: { min: number; max: number } // number of sites forced to 'hardened'
}

export interface SiteSpec {
  id: string // stable logical id, e.g. 'acme.invoice-bola'
  title: string
  vulnClass: VulnClass
  cwe: string // e.g. 'CWE-639'
  severity: Severity // severity when vulnerable
  routeKeys: string[] // entry routes (where the attacker acts)
  triggerRouteKeys?: string[] // second-order: where the impact manifests (defaults to routeKeys)
  params: string[] // logical param keys involved
  oracle: {
    kinds: OracleEventKind[] // any of these, attributed to oracle.routeKeys, proves impact
    routeKeys: string[] // (kind, routeKey) pairs must be unique across all sites of an app
  }
  rootCause: { file: string; symbol: string } // path inside the materialized source tree
  chain?: { id: string; step: number } // chain members are always assigned the same mode
  lure: string // why the hardened variant looks vulnerable (decoy realism)
  formEncoding?: 'json' | 'form' | 'multipart' | 'xml'
  requiresCsrf?: boolean
  secondOrder?: boolean
  canBeDecoy?: boolean // default true
}

// ---------------------------------------------------------------------------------------------
// Ground truth (instantiated per seed, written OUTSIDE the materialized app tree)
// ---------------------------------------------------------------------------------------------
export interface Endpoint { method: string; path: string; routeKey: string }

export interface GroundTruthEntry {
  siteId: string
  title: string
  vulnClass: VulnClass
  cwe: string
  severity: Severity
  endpoints: Endpoint[] // runtime entry endpoints
  triggerEndpoints: Endpoint[] // runtime trigger endpoints (== endpoints unless second-order)
  params: string[] // runtime param names
  oracle: { kinds: OracleEventKind[]; routeKeys: string[] }
  rootCause: { file: string; symbol: string }
  chain?: { id: string; step: number }
  formEncoding?: 'json' | 'form' | 'multipart' | 'xml'
  requiresCsrf?: boolean
  secondOrder?: boolean
  lure?: string
}

export interface GroundTruth {
  schemaVersion: 1
  app: AppName
  seed: number
  seedSet: SeedSet
  vulns: GroundTruthEntry[]
  decoys: GroundTruthEntry[]
  chains: Array<{ id: string; siteIds: string[]; severity: Severity }>
}

// ---------------------------------------------------------------------------------------------
// Grader input (adapter target for Kovo Hunter output) and output
// ---------------------------------------------------------------------------------------------
export type FindingStatus =
  | 'runtime_confirmed' | 'confirmed' | 'static_verified' | 'proposed' | 'open_proof_gap' | 'ruled_out'

export interface SubmittedFinding {
  id: string
  title: string
  cwe?: string
  vulnClass?: VulnClass | string
  severity?: Severity
  endpoints: Array<{ method?: string; path: string }> // runtime paths (concrete or templated)
  params?: string[]
  status: FindingStatus
  submittedAtMs: number
  costUsdAtSubmit?: number
  codeLocations?: Array<{ file: string; startLine?: number; symbol?: string }>
}

export interface RunTelemetry {
  startedAtMs: number
  endedAtMs: number
  totalCostUsd: number
  budgetUsd?: number
  budgetExhausted?: boolean
  hypotheses?: Array<{ path: string; vulnClass?: string; method?: string }>
  tierBlocked?: Array<{ method: string; path: string }>
  assertionFailures?: Array<{ findingId?: string; path?: string }>
}

export interface GradeInput {
  groundTruth: GroundTruth
  findings: SubmittedFinding[]
  oracleEvents: OracleEvent[]
  requestLog: RequestLogEntry[]
  egressLog?: EgressLogEntry[]
  telemetry: RunTelemetry
  mode: BenchMode
}

export type VulnOutcome = 'confirmed' | 'claimed_without_impact' | 'static_only' | 'missed'

export interface VulnResult {
  siteId: string
  severity: Severity
  vulnClass: VulnClass
  outcome: VulnOutcome
  matchedFindingIds: string[]
  oracleEventSeqs: number[]
  failureBucket?: FailureTaxonomyBucket // set for every outcome other than 'confirmed'
  confirmedAtUsd?: number
}

export interface Scorecard {
  app: AppName
  seed: number
  seedSet: SeedSet
  mode: BenchMode
  targets: number
  confirmed: number
  recall: number // confirmed / targets
  recallBySeverity: Record<Severity, { targets: number; confirmed: number; recall: number }>
  recallByClass: Record<string, { targets: number; confirmed: number }>
  staticRecall: number // (confirmed + static_only) / targets — white-box informational metric
  precision: number | null // confirmedTP / (TP + decoyFP + unmatchedFP), null when no claims (never 1)
  /** Conservative precision that also charges every uncharged misclassification:
   *  TP / (TP + decoyFP + unmatchedFP + misclassified), null when no claims. Phase-1 gates use this. */
  strictPrecision: number | null
  /** Findings that hit a planted vulnerable entry's endpoint under an incompatible class, whatever
   *  their status or sibling-pair eligibility. Phase-1 requires 0. */
  incompatibleClassCount: number
  decoys: number
  decoyFalsePositives: number
  unmatchedFalsePositives: number
  /** Class-incompatible findings left uncharged by the documented sibling allowlist + runtime proof.
   *  Not a TP, but excluded from the standard precision denominator; strictPrecision charges them. */
  misclassifiedFindingIds?: string[]
  duplicateFindings: number
  chainsTotal: number
  chainsCompleted: number
  funnel: BenchmarkFunnel
  failureBuckets: Record<FailureTaxonomyBucket, number>
  budgetCurve: Array<{ usd: number; confirmed: number; recall: number }>
  egressBlocked: number
  totalCostUsd: number
  vulns: VulnResult[]
  decoyResults: Array<{ siteId: string; falsePositive: boolean; findingIds: string[] }>
  unmatchedFindingIds: string[]
}

// ---------------------------------------------------------------------------------------------
// App module contract (apps/<app>/index.ts default-exports an AppModule)
// ---------------------------------------------------------------------------------------------
export interface StartedApp {
  app: AppName
  origin: string // http://127.0.0.1:<port>
  plan: VariantPlan
  groundTruth: GroundTruth
  sourceDir: string // materialized source tree (white-box mount); contains NO truth/solver files
  oracle: OracleHandle
  stop(): Promise<void>
}

export interface OracleHandle {
  events(): OracleEvent[]
  requests(): RequestLogEntry[]
  egress(): EgressLogEntry[]
  reset(): void
}

export interface AppModule {
  name: AppName
  blueprint: AppBlueprint
  start(opts: { plan: VariantPlan; groundTruth: GroundTruth; oobCallbackPorts?: number[] }): Promise<StartedApp>
}

// What the scanner under test is allowed to see, per mode. Never includes ground truth / site modes.
export interface ApiRef { routeKey: string; method: string; path: string; params: string[] }
export interface Briefing {
  app: AppName
  mode: BenchMode
  origin: string
  personas: Array<Pick<PersonaCredential, 'id' | 'email' | 'password' | 'tenant' | 'role'>>
  apiReference?: ApiRef[] // grey-box and white-box only
  sourceDir?: string // white-box only
}
