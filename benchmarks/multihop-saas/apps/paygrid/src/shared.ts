// Domain types shared by the five paygrid services. This file is part of the white-box source tree,
// so it deliberately contains only application vocabulary.

export type PersonaKey =
  | 'owner_a'
  | 'member_a'
  | 'viewer_a'
  | 'dual_member'
  | 'member_b'
  | 'revoked_or_demoted'
  | 'admin_bot'

export type TenantKey = 'org_a' | 'org_b' | 'org_c'
export type ServiceName = 'edge' | 'api' | 'worker' | 'idp' | 'vault.internal'
export type LabRole = 'owner' | 'admin' | 'member' | 'viewer' | 'finance' | 'bot'
export type SeedKind = 'dev' | 'held-out'
export type Detail = Record<string, string | number | boolean>

export interface TenantDef {
  id: TenantKey
  slug: string
  name: string
  treasuryFile: string
  prefixOverlapWith?: TenantKey
}

export interface PersonaDef {
  id: PersonaKey
  userId: string
  email: string
  password: string
  tenantId: TenantKey
  rolesByTenant: Partial<Record<TenantKey, LabRole>>
  bot: boolean
  verified: boolean
}

export interface SecretsDef {
  sessionSigningKey: string
  webhookSigningSalt: string
  signedUrlKey: string
  serviceToken: string
  patPepper: string
}

export interface EconomicsDef {
  payoutCapCents: number
  payoutAmountCents: number
  settlementAmountCents: number
  orderAmountCents: number
  raceCreditCents: number
  treasuryCanary: string
  invoiceAmountCents: number
}

export interface IdsDef {
  templateId: string
  invoiceId: string
  payoutIds: string[]
  pendingFinanceEmail: string
  pendingFinanceEmailNormalized: string
}

export interface PaygridPlan {
  seed: number
  seedSet: SeedKind
  routePrefix: string
  tenants: { a: TenantDef; b: TenantDef; c: TenantDef }
  personas: Record<PersonaKey, PersonaDef>
  secrets: SecretsDef
  economics: EconomicsDef
  ids: IdsDef
}

/** Lab behaviour switches. Names describe policy, not evaluation state. */
export interface LabProfile {
  directoryShowsPendingEmail: boolean
  inviteNormalization: boolean
  requireVerifiedSession: boolean
  makerCheckerBypass: boolean
  storeRawTemplateFooter: boolean
  renderLogShowsSigningSalt: boolean
  acceptScopedSettlement: boolean
  tenantlessPermissionCache: boolean
  strictExportPath: boolean
  duplicateKeyCapRelaxed: boolean
  rebindAfterAuthorization: boolean
  concurrentSettlement: boolean
  asyncLatencyMs: number
}

export interface AuditEvent {
  seq: number
  ts: number
  kind: string
  runId: string
  actorPersona?: PersonaKey
  detail: Detail
}

export interface OrgRecord {
  id: TenantKey
  slug: string
  name: string
  treasuryFile: string
}

export interface UserRecord {
  id: string
  personaKey: PersonaKey
  email: string
  password: string
  tenantId: TenantKey
  rolesByTenant: Partial<Record<TenantKey, LabRole>>
  bot: boolean
  verified: boolean
}

export interface SessionRecord {
  token: string
  userId: string
  tenantId: TenantKey
  role: LabRole
  originPersona: PersonaKey
  runId: string
  revoked: boolean
  emailVerified: boolean
  tid: TenantKey
}

export interface InviteRecord {
  id: string
  tenantId: TenantKey
  emailRaw: string
  emailNormalized: string
  role: LabRole
  verified: boolean
  revoked: boolean
  token: string
  runId: string
}

export interface PatRecord {
  id: string
  token: string
  userId: string
  tenantId: TenantKey
  scopes: string[]
  revoked: boolean
  runId: string
}

export interface PayoutRecord {
  id: string
  tenantId: TenantKey
  amountCents: number
  beneficiary: string
  status: 'draft' | 'pending_approval' | 'settled' | 'rejected'
  createdBy: string
  approvedBy: string
  rebound: boolean
  runId: string
}

export interface OrderRecord {
  id: string
  tenantId: TenantKey
  amountCents: number
  beneficiary: string
  status: 'draft' | 'authorized' | 'settled'
  createdBy: string
  rebound: boolean
  settled: boolean
  captureSeq: number
  runId: string
}

export interface TemplateRecord {
  id: string
  tenantId: TenantKey
  name: string
  footer: string
  rawStored: boolean
  runId: string
}

export interface InvoiceRecord {
  id: string
  tenantId: TenantKey
  templateId: string
  amountCents: number
  status: string
  runId: string
}

export interface JobRecord {
  id: string
  kind: 'pdf' | 'export'
  tenantId: TenantKey
  status: 'queued' | 'ready' | 'failed' | 'cancelled'
  createdAt: number
  readyAt: number
  runId: string
  templateId?: string
  invoiceId?: string
  artifactKey?: string
  prefix?: string
  trace?: string
  processed: boolean
}

export interface CacheEntry {
  key: string
  userId: string
  tenantId: TenantKey
  permissions: LabRole[]
  scoped: boolean
  runId: string
}

export interface LedgerEntry {
  id: string
  tenantId: TenantKey
  amountCents: number
  memo: string
  runId: string
  ts: number
}

export interface LabState {
  plan: PaygridPlan
  profile: LabProfile
  runId: string
  orgs: Record<TenantKey, OrgRecord>
  distro: TenantDef[]
  users: UserRecord[]
  sessions: Map<string, SessionRecord>
  invites: InviteRecord[]
  pats: PatRecord[]
  payouts: PayoutRecord[]
  orders: OrderRecord[]
  templates: TemplateRecord[]
  invoices: InvoiceRecord[]
  jobs: JobRecord[]
  cache: Map<string, CacheEntry>
  ledger: LedgerEntry[]
  treasury: Map<string, string>
  audit: AuditEvent[]
  listeners: Array<(event: AuditEvent) => void>
  seq: number
  /** Per-instance secret the edge attaches when forwarding to api; never leaves the process. */
  edgeBridgeToken: string
  emit(kind: string, detail?: Detail, actorPersona?: PersonaKey): AuditEvent
}
