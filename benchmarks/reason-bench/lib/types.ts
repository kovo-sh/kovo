// Shared contracts for reason-bench. This file is an additive extension of
// benchmarks/realistic-bench/lib/types.ts: every realistic-bench rule and shape is preserved, and
// the reasoning-specific domain, persona, causal-chain and oracle kinds are layered on top.
// Taxonomy + funnel names deliberately mirror src/domain.ts but are copied, not imported, so the
// benchmark stays self-contained and independent of Kovo.

export const appNames = ['ledgerflow', 'forgecloud'] as const
export type AppName = typeof appNames[number]

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type SiteMode = 'vulnerable' | 'hardened'
export type BenchMode = 'black-box' | 'grey-box' | 'white-box'
export type SeedSet = 'dev' | 'held-out'

// Six personas across two tenants (plan §3.3). Black-box sees only member_a + member_b; grey-box and
// white-box see all six.
export const personaIds = [
  'owner_a', 'member_a', 'viewer_a', 'dual_member', 'member_b', 'revoked_or_demoted',
] as const
export type PersonaId = typeof personaIds[number]
export type Actor = PersonaId | 'anonymous' | 'unknown'
export type IdFormat = 'int' | 'uuid' | 'prefixed' | 'hashid'

export type PersonaRole = 'owner' | 'admin' | 'member' | 'viewer'
export interface TenantMembership { tenant: string; role: PersonaRole }

export interface PersonaCredential {
  id: PersonaId
  email: string
  password: string
  tenant: string // primary tenant slug (kept for realistic-bench compatibility)
  role: PersonaRole // role in the primary tenant
  // Cross-tenant memberships. dual_member carries an admin membership in org_a and a viewer
  // membership in org_b; single-tenant personas carry exactly one entry.
  memberships?: TenantMembership[]
  // Temporal lifecycle for revoked_or_demoted: starts with `fromRole`, ends with `toRole`.
  lifecycle?: { fromRole: PersonaRole; toRole?: PersonaRole; revoked?: boolean }
}

export const vulnClasses = [
  'idor', 'bola', 'bfla', 'graphql_bola', 'mass_assignment', 'auth_bypass', 'jwt', 'oauth',
  'csrf', 'sqli', 'ssti', 'ssrf', 'xxe', 'xss_stored', 'xss_reflected', 'path_traversal',
  'command_injection', 'cache_poisoning', 'cache_deception', 'race_condition', 'business_logic',
  'workflow_bypass', 'open_redirect', 'webhook_forgery', 'info_disclosure', 'rate_limit_bypass',
  // reason-bench addition: multi-hop chains are graded as a composite class (see grader/match.ts).
  'chain',
] as const
export type VulnClass = typeof vulnClasses[number]

export type SiteFamily = 'A' | 'B' | 'C' | 'D' | 'E' | 'F'

// Base realistic-bench kinds. Kept verbatim so shared lib/tests stay source-compatible.
export const oracleEventKinds = [
  'cross_tenant_read', 'cross_tenant_write', 'privilege_escalation', 'mass_assignment',
  'sql_structure_change', 'ssrf_internal_fetch', 'xxe_entity_resolved', 'path_escape',
  'command_injection_simulated', 'template_code_exec', 'stored_xss_rendered',
  'reflected_xss_rendered', 'auth_bypass', 'token_forgery', 'cache_poisoned', 'secret_disclosed',
  'open_redirect', 'csrf_state_change', 'race_double_spend', 'workflow_skip', 'webhook_forgery',
  'invariant_violation',
] as const
export type OracleEventKind = typeof oracleEventKinds[number]

// Reasoning-specific impact kinds (plan §3.4). These prove implicit domain / economic / temporal /
// authorization invariant violations, not syntactic payload acceptance.
export const reasonOracleEventKinds = [
  'economic_invariant_violation', 'self_approval_bypass', 'revoked_token_used',
  'stale_privilege_use', 'cross_org_transfer', 'batch_partial_authz_bypass',
  'tenant_existence_oracle', 'hmac_scope_replay', 'signed_url_prefix_escape',
  'sso_tenant_confusion', 'parser_differential_bypass', 'cache_tenant_bleed',
  'causal_chain_completed',
] as const
export type ReasonEventKind = typeof reasonOracleEventKinds[number]

// Effective set = every realistic-bench kind plus every reasoning-specific kind.
export type ReasonOracleEventKind = OracleEventKind | ReasonEventKind
export const allOracleEventKinds = [...oracleEventKinds, ...reasonOracleEventKinds] as const

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
// fed into Kovo's ReplayVerifier; only the grader consumes it.
// ---------------------------------------------------------------------------------------------
export interface OracleEvent {
  seq: number
  ts: number // epoch ms
  kind: ReasonOracleEventKind
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

// ---------------------------------------------------------------------------------------------
// Semantic domain randomization (plan §3.2). Business vocabulary, state labels, economic
// parameters and tenant slugs are randomized per seed so a prompt cannot memorize literals.
// ---------------------------------------------------------------------------------------------
export interface DomainRoles {
  owner: string
  admin: string
  member: string
  viewer: string
  maker: string // creator role in a maker/checker workflow
  checker: string // approver role in a maker/checker workflow
}
export interface DomainStates {
  draft: string
  pending: string
  settled: string
  rejected: string
  archived: string
}
export interface DomainEconomics {
  couponMinSpendCents: number // $150..$300 in minor units
  couponPercent: number // 15..35
  currencies: [string, string] // e.g. ['USD', 'EUR']
  roundingStepCents: number // conversion rounding step
  transferFeeCents: number
  promoBonusCents: number
}
export interface DomainVariant {
  app: AppName
  seed: number
  roleVocab: DomainRoles
  stateLabels: DomainStates
  economics: DomainEconomics
  tenants: { orgA: string; orgB: string } // orgB always prefix-overlaps orgA at a '-' boundary
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
  domain: DomainVariant // semantic business-rule variant (app-visible, never site modes/truth)
}

// Logical app description consumed by the generator. Lives in apps/<app>/truth/ (never mounted
// for white-box agents).
export interface RouteTemplate {
  method: string
  // Path made of literal segments, `{noun:<vocabKey>}` segments substituted from vocab, and
  // `:param` segments whose runtime name comes from params.
  path: string
}

// Per-app blueprint overrides for semantic randomization. All fields optional; domain-variant.ts
// falls back to its built-in vocabularies.
export interface DomainVocab {
  roleSets?: DomainRoles[]
  stateSets?: DomainStates[]
  currencyPairs?: Array<[string, string]>
  tenantBases?: string[]
  tenantSuffixes?: string[]
}

export interface CausalHop {
  hopId: string
  routeKey: string
  kind: ReasonOracleEventKind
  requiresPrior?: string[] // hopIds that must already be observed for the same causal artifact
}
export interface CausalChainSpec {
  id: string
  hops: CausalHop[]
  finalImpactKind: ReasonOracleEventKind
  finalRouteKey: string
}

export interface SiteSpec {
  id: string // stable logical id, e.g. 'lf-01'
  title: string
  vulnClass: VulnClass
  cwe: string // e.g. 'CWE-639'
  severity: Severity // severity when vulnerable
  family?: SiteFamily // reason-bench family A..F (plan §4)
  routeKeys: string[] // entry routes (where the attacker acts)
  triggerRouteKeys?: string[] // second-order: where the impact manifests (defaults to routeKeys)
  params: string[] // logical param keys involved
  oracle: {
    kinds: ReasonOracleEventKind[] // any of these, attributed to oracle.routeKeys, proves impact
    routeKeys: string[] // (kind, routeKey) pairs must be unique across all sites of an app
  }
  rootCause: { file: string; symbol: string } // path inside the materialized source tree
  chain?: { id: string; step: number } // chain members are always assigned the same mode
  causalChainId?: string // links to AppBlueprint.chains
  lure: string // why the hardened variant looks vulnerable (decoy realism)
  formEncoding?: 'json' | 'form' | 'multipart' | 'xml'
  requiresCsrf?: boolean
  secondOrder?: boolean
  canBeDecoy?: boolean // default true
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
  chains?: CausalChainSpec[] // causal multi-hop specs (never materialized)
  domain?: DomainVocab // optional semantic-randomization overrides
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
  family?: SiteFamily
  endpoints: Endpoint[] // runtime entry endpoints
  triggerEndpoints: Endpoint[] // runtime trigger endpoints (== endpoints unless second-order)
  params: string[] // runtime param names
  oracle: { kinds: ReasonOracleEventKind[]; routeKeys: string[] }
  rootCause: { file: string; symbol: string }
  chain?: { id: string; step: number }
  causalChainId?: string
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
  // Causal multi-hop specs (chain ids + hop order + final impact). Never materialized.
  causalChains?: CausalChainSpec[]
}

// ---------------------------------------------------------------------------------------------
// Grader input (adapter target for Kovo output) and output
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
  // Measured deterministic floor (0..1) from a `--no-llm` run. When supplied, the scorecard reports
  // ΔReasoning = recall - heuristicFloor and whether the Anti-Heuristic Gate passed.
  heuristicFloor?: number
}

export type VulnOutcome = 'confirmed' | 'claimed_without_impact' | 'static_only' | 'missed'

export interface VulnResult {
  siteId: string
  severity: Severity
  vulnClass: VulnClass
  family?: SiteFamily
  outcome: VulnOutcome
  matchedFindingIds: string[]
  oracleEventSeqs: number[]
  failureBucket?: FailureTaxonomyBucket // set for every outcome other than 'confirmed'
  confirmedAtUsd?: number
}

export interface ChainResult {
  chainId: string
  completed: boolean
  hopsObserved: number
  hopsTotal: number
  finalObserved: boolean
  artifact?: string
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
  recallByFamily: Record<string, { targets: number; confirmed: number; recall: number }>
  staticRecall: number // (confirmed + static_only) / targets — white-box informational metric
  precision: number | null // confirmedTP / (TP + decoyFP + unmatchedFP), null when no claims (never 1)
  rawPrecision?: number | null // pre-adjudication precision, null when no claims (never 1)
  decoys: number
  decoyFalsePositives: number
  decoyFalsePositiveRate: number // decoyFP / decoys
  unmatchedFalsePositives: number
  duplicateFindings: number
  chainsTotal: number // causal chains when groundTruth.causalChains is present, else site chains
  chainsCompleted: number
  siteChainsTotal: number
  siteChainsCompleted: number
  chainResults: ChainResult[]
  funnel: BenchmarkFunnel
  failureBuckets: Record<FailureTaxonomyBucket, number>
  budgetCurve: Array<{ usd: number; confirmed: number; recall: number }>
  egressBlocked: number
  totalCostUsd: number
  heuristicFloor?: number
  deltaReasoning?: number // recall - heuristicFloor
  heuristicFloorPass?: boolean // true when heuristicFloor <= 0.15
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

export interface AppModuleStartOpts {
  plan: VariantPlan
  groundTruth: GroundTruth
  oobCallbackPorts?: number[]
  // Optional pre-materialized tree (run.ts/self-tests may pass one); apps materialize when omitted.
  sourceDir?: string
}

export interface AppModule {
  name: AppName
  blueprint: AppBlueprint
  reasonBench: true
  start(opts: AppModuleStartOpts): Promise<StartedApp>
}

// Self-test solver contract (sites/<id>/solver.ts). Solvers live outside the materialized tree.
export interface SolverResponse {
  status: number
  headers: Record<string, string>
  body: string
  json<T = unknown>(): T
}
export interface SolverCtx {
  origin: string
  plan: VariantPlan
  persona(id: PersonaId): PersonaCredential
  /** Log in as a seeded persona; resolves to request headers carrying the session cookie. */
  login(id: PersonaId): Promise<Record<string, string>>
  request(input: {
    method: string
    path: string
    headers?: Record<string, string>
    body?: unknown
  }): Promise<SolverResponse>
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
