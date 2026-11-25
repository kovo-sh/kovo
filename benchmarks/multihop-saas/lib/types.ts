// Shared contracts for the v8 multi-hop SaaS benchmark track. Every module and every archetype
// builds against these shapes; the app shells mirror the domain subset they need so a materialized
// white-box source tree stays self-contained.

export type AppName = 'paygrid'
export const appNames: readonly AppName[] = ['paygrid']

export type BenchMode = 'black-box' | 'grey-box' | 'white-box'
export type LabMode = 'vulnerable' | 'hardened'
export type SeedSet = 'dev' | 'held-out'

export type PersonaId =
  | 'owner_a'
  | 'member_a'
  | 'viewer_a'
  | 'dual_member'
  | 'member_b'
  | 'revoked_or_demoted'
  | 'admin_bot'

export const personaIds: readonly PersonaId[] = [
  'owner_a', 'member_a', 'viewer_a', 'dual_member', 'member_b', 'revoked_or_demoted', 'admin_bot',
]

export type TenantId = 'org_a' | 'org_b' | 'org_c'

export type ServiceId = 'edge' | 'api' | 'worker' | 'idp' | 'vault.internal'
export const serviceIds: readonly ServiceId[] = ['edge', 'api', 'worker', 'idp', 'vault.internal']

export type Role = 'owner' | 'admin' | 'member' | 'viewer' | 'finance' | 'bot'

export type CausalEdgeKind =
  | 'value_binding'
  | 'derived_crypto_binding'
  | 'state_transition_binding'
  | 'async_pivot_binding'

export const causalEdgeKinds: readonly CausalEdgeKind[] = [
  'value_binding', 'derived_crypto_binding', 'state_transition_binding', 'async_pivot_binding',
]

export type TerminalImpactKind =
  | 'self_approved_payout'
  | 'forged_settlement'
  | 'cross_tenant_export'
  | 'ledger_overcredit'

export type HopDropReason =
  | 'capability_not_extracted'
  | 'pivot_not_discovered'
  | 'edge_binding_rejected'
  | 'replay_failed'
  | 'budget_exhausted'
  | 'persona_shortcut_rejected'
  | 'terminal_not_observed'

// ---------------------------------------------------------------------------------------------
// Domain variation
// ---------------------------------------------------------------------------------------------

export interface DomainTenant {
  id: TenantId
  slug: string
  name: string
  treasuryFile: string
  prefixOverlapWith?: TenantId
}

export interface DomainPersona {
  id: PersonaId
  userId: string
  email: string
  password: string
  tenantId: TenantId
  rolesByTenant: Partial<Record<TenantId, Role>>
  bot: boolean
  verified: boolean
}

export interface DomainEconomics {
  payoutCapCents: number
  payoutAmountCents: number
  settlementAmountCents: number
  orderAmountCents: number
  raceCreditCents: number
  treasuryCanary: string
  invoiceAmountCents: number
}

export interface DomainSecrets {
  sessionSigningKey: string
  webhookSigningSalt: string
  signedUrlKey: string
  serviceToken: string
  patPepper: string
}

export interface DomainIds {
  templateId: string
  invoiceId: string
  payoutIds: string[]
  pendingFinanceEmail: string
  pendingFinanceEmailNormalized: string
}

export interface DomainVariant {
  app: AppName
  seed: number
  seedSet: SeedSet
  routePrefix: string
  tenants: { a: DomainTenant; b: DomainTenant; c: DomainTenant }
  personas: Record<PersonaId, DomainPersona>
  secrets: DomainSecrets
  economics: DomainEconomics
  ids: DomainIds
}

export interface ServiceTopology {
  id: ServiceId
  role: string
  internal: boolean
  origin?: string
}

export interface ApiRef {
  routeKey: string
  service: ServiceId
  method: string
  path: string
  params: string[]
  auth: 'none' | 'session' | 'service' | 'invite'
}

export interface Briefing {
  app: AppName
  mode: BenchMode
  seed: number
  seedSet: SeedSet
  runId: string
  entryOrigins: Partial<Record<ServiceId, string>>
  services?: ServiceTopology[]
  internalServiceNames?: ServiceId[]
  personas: Array<{
    id: PersonaId
    email: string
    password: string
    tenant: TenantId
    rolesByTenant: Partial<Record<TenantId, Role>>
  }>
  apiReference?: ApiRef[]
  sourceDir?: string
}

// ---------------------------------------------------------------------------------------------
// Chain specifications
// ---------------------------------------------------------------------------------------------

export interface ChainHopSpec {
  hopId: string
  service: ServiceId
  routeKey: string
  actor: PersonaId
  edgeFromPrevious?: CausalEdgeKind
}

export interface ChainTerminalSpec {
  service: ServiceId
  routeKey: string
  kind: TerminalImpactKind
}

export interface ChainSpec {
  id: string
  title: string
  vulnClass: string
  hops: ChainHopSpec[]
  terminal: ChainTerminalSpec
  attackerPersonaSet: PersonaId[]
  forbiddenShortcutPersonas: PersonaId[]
}

export interface TwinSpec {
  id: string
  baseChainId: string
  decoyHopIds: string[]
  enforcedAtHopId: string
  note: string
}

// ---------------------------------------------------------------------------------------------
// Oracle observations and receipts
// ---------------------------------------------------------------------------------------------

export interface HopObservation {
  seq: number
  ts: number
  chainId: string
  hopId: string
  service: ServiceId
  routeKey: string
  actor: PersonaId
  artifactDigest: string
  entityId?: string
  effectiveRole?: Role
  detail: Record<string, string | number | boolean>
}

export interface EdgeObservation {
  seq: number
  ts: number
  chainId: string
  fromHopId: string
  toHopId: string
  kind: CausalEdgeKind
  fromArtifactDigest: string
  toConsumedDigest: string
  derivedFromDigest?: string
  entityId?: string
  runId?: string
  pollObserved?: boolean
  detail: Record<string, string | number | boolean>
}

export interface ControlObservation {
  seq: number
  ts: number
  chainId: string
  fromHopId: string
  toHopId: string
  entityId: string
  result: 'failed_without_predecessor' | 'unexpected_success'
  detail: Record<string, string | number | boolean>
}

export interface TerminalObservation {
  seq: number
  ts: number
  chainId: string
  service: ServiceId
  routeKey: string
  kind: TerminalImpactKind
  actor: PersonaId
  entityId?: string
  detail: Record<string, string | number | boolean>
}

export interface ReceiptHop {
  hopId: string
  service: ServiceId
  routeKey: string
  actor: PersonaId
  ts: number
  artifactDigest: string
}

export interface ReceiptEdge {
  fromHopId: string
  toHopId: string
  kind: CausalEdgeKind
  evidenceDigest: string
}

export interface CompositeProofReceipt {
  chainId: string
  terminalVulnClass: string
  hops: ReceiptHop[]
  causalEdges: ReceiptEdge[]
  terminalImpact: {
    kind: TerminalImpactKind
    service: ServiceId
    routeKey: string
    ts: number
  }
  replayMode: 'fresh_clean_replay' | 'one_shot_transcript'
  signer: 'mh_host_runtime'
  signature: string
}

export interface ChainEvaluation {
  chainId: string
  completed: boolean
  confirmed: boolean
  hopsObserved: number
  hopsTotal: number
  missingHopIds: string[]
  terminalObserved: boolean
  terminalAt?: number
  failureReason?: string
  dropReason?: HopDropReason
  receiptVerified: boolean
}

export interface ConfirmedChain {
  chainId: string
  vulnClass: string
  terminalKind: TerminalImpactKind
  receipt: CompositeProofReceipt
  receiptVerified: boolean
}

export interface OracleEventExport {
  hops: HopObservation[]
  edges: EdgeObservation[]
  controls: ControlObservation[]
  terminals: TerminalObservation[]
}

export interface OracleExport {
  runId: string
  evaluations: ChainEvaluation[]
  confirmed: ConfirmedChain[]
  events: OracleEventExport
  receipts: CompositeProofReceipt[]
  receiptVerification: Array<{ chainId: string; verified: boolean; reason: string }>
}

// ---------------------------------------------------------------------------------------------
// Ground truth, findings, grading
// ---------------------------------------------------------------------------------------------

export interface ExpectedChain {
  chainId: string
  vulnClass: string
  hopIds: string[]
  edgeKinds: CausalEdgeKind[]
  terminalKind: TerminalImpactKind
}

export interface TwinDecoy {
  chainId: string
  benignHopIds: string[]
  enforcedAtHopId: string
  note: string
}

export interface GroundTruth {
  app: AppName
  seed: number
  seedSet: SeedSet
  labMode: LabMode
  twinId?: string
  expectedChains: ExpectedChain[]
  twinDecoys: TwinDecoy[]
  topology: ServiceTopology[]
  personas: Array<{ id: PersonaId; tenantId: TenantId; rolesByTenant: Partial<Record<TenantId, Role>> }>
}

export interface Finding {
  chainId: string
  terminalVulnClass: string
  hopIds?: string[]
  receipt?: CompositeProofReceipt
  reportedBy?: string
}

export type FpCategory =
  | 'hardened_counterpart'
  | 'decoy_twin'
  | 'unmatched'
  | 'unconfirmed'

export interface HopFunnel {
  h1: number
  h2: number
  h3: number
  h4plus: number
  finalOracle: number
  receiptConfirmed: number
}

export interface GradeInput {
  groundTruth: GroundTruth
  findings: Finding[]
  oracle: OracleExport
}

export interface Scorecard {
  app: AppName
  seed: number
  seedSet: SeedSet
  mode: LabMode
  twin?: string
  tp: number
  fp: number
  fn: number
  precision: number
  recall: number
  strictDecoyFps: number
  fpByCategory: Record<FpCategory, number>
  matchedChainIds: string[]
  missedChainIds: string[]
  hopFunnel: HopFunnel
  dropReasons: Record<string, number>
  gate: {
    precisionOk: boolean
    zeroDecoyFps: boolean
    pass: boolean
  }
}

export interface SelftestRow {
  scope: string
  seed: number
  ok: boolean
  detail: string
}

export interface SelftestResult {
  summary: string
  rows: SelftestRow[]
}

export function isAppName(value: string): value is AppName {
  return (appNames as readonly string[]).includes(value)
}
