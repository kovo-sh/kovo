// Domain types shared by the five connecthub services. This file ships inside the white-box
// source snapshot, so it contains marketplace vocabulary only.

export type PersonaKey =
  | 'owner_a'
  | 'member_a'
  | 'viewer_a'
  | 'dual_member'
  | 'member_b'
  | 'revoked_or_demoted'
  | 'admin_bot'

export type TenantKey = 'org_a' | 'org_b' | 'org_c'
export type ServiceName = 'portal' | 'api' | 'oauth' | 'webhook-relay' | 'billing.internal'
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

export interface ConnecthubPlan {
  seed: number
  seedSet: SeedKind
  routePrefix: string
  tenants: { a: TenantDef; b: TenantDef; c: TenantDef }
  personas: Record<PersonaKey, PersonaDef>
  secrets: SecretsDef
  economics: EconomicsDef
  ids: IdsDef
}

/** Lab behaviour switches. Names describe product policy, not evaluation state. */
export interface LabProfile {
  consentScopeWidening: boolean
  enforceConsentIntersection: boolean
  rebateCapCents: number
  webhookSignatureScopeBound: boolean
  webhookRequireVerifiedEndpoint: boolean
  graphqlPerNodeAuthz: boolean
  staleCallbackTokenRetained: boolean
  acceptStaleCallback: boolean
  stripInternalHeaders: boolean
  trustInternalActorHeader: boolean
  acceptCaseActorHint: boolean
  signedPrefixTrailingSlash: boolean
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
  kind: 'session'
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

export interface DelegatedTokenRecord {
  token: string
  consentId: string
  appId: string
  userId: string
  tenantId: TenantKey
  originPersona: PersonaKey
  scopes: string[]
  revoked: boolean
  runId: string
}

export interface AppRecord {
  id: string
  name: string
  ownerTenant: TenantKey
  clientSecret: string
  scopes: string[]
  status: 'listed' | 'suspended'
  runId: string
}

export interface InstallationRecord {
  id: string
  appId: string
  tenantId: TenantKey
  status: 'installed' | 'uninstalled'
  callbackTokenId: string
  callbackToken: string
  installedBy: string
  staleTokenRetained: boolean
  handle?: string
  runId: string
}

export interface ConsentRecord {
  id: string
  code: string
  appId: string
  userId: string
  tenantId: TenantKey
  originPersona: PersonaKey
  displayedScopes: string[]
  grantedScopes: string[]
  used: boolean
  revoked: boolean
  runId: string
}

export interface InvoiceRecord {
  id: string
  tenantId: TenantKey
  amountCents: number
  status: 'open' | 'settled'
  runId: string
}

export interface RebateClaimRecord {
  id: string
  invoiceId: string
  tenantId: TenantKey
  appId: string
  amountCents: number
  runId: string
}

export interface RefundRecord {
  id: string
  caseId: string
  tenantId: TenantKey
  parts: number[]
  status: 'claimed' | 'settled'
  runId: string
}

export interface SupportCaseRecord {
  id: string
  tenantId: TenantKey
  subject: string
  headerHint: boolean
  forwarded: boolean
  runId: string
}

export interface LedgerEntry {
  id: string
  tenantId: TenantKey
  subjectId: string
  amountCents: number
  memo: string
  runId: string
  ts: number
}

export interface WebhookRecord {
  id: string
  appId: string
  tenantId: TenantKey
  url: string
  secret: string
  signatureScopeOmitted: boolean
  verified: boolean
  revoked: boolean
  runId: string
}

export interface DeliveryRecord {
  id: string
  kind: 'delivery' | 'callback'
  webhookId: string
  tenantId: TenantKey
  callbackTokenId?: string
  status: 'queued' | 'ready' | 'failed' | 'cancelled'
  createdAt: number
  readyAt: number
  body: string
  signature: string
  scope: string
  processed: boolean
  runId: string
}

export interface StorageSignatureRecord {
  id: string
  jobId: string
  tenantId: TenantKey
  prefix: string
  signature: string
  runId: string
}

export interface PartnerExportRecord {
  id: string
  tenantId: TenantKey
  signedPrefix: string
  fileName: string
  runId: string
}

export interface LabState {
  plan: ConnecthubPlan
  profile: LabProfile
  runId: string
  orgs: Record<TenantKey, OrgRecord>
  distro: TenantDef[]
  users: UserRecord[]
  sessions: Map<string, SessionRecord>
  pats: PatRecord[]
  delegated: Map<string, DelegatedTokenRecord>
  apps: AppRecord[]
  installations: InstallationRecord[]
  consents: ConsentRecord[]
  invoices: InvoiceRecord[]
  rebates: RebateClaimRecord[]
  refunds: RefundRecord[]
  cases: SupportCaseRecord[]
  ledger: LedgerEntry[]
  webhooks: WebhookRecord[]
  deliveries: DeliveryRecord[]
  signatures: StorageSignatureRecord[]
  exports: PartnerExportRecord[]
  files: Map<string, string>
  audit: AuditEvent[]
  listeners: Array<(event: AuditEvent) => void>
  seq: number
  emit(kind: string, detail?: Detail, actorPersona?: PersonaKey): AuditEvent
}
