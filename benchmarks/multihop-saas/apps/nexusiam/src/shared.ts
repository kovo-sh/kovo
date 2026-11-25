// Domain vocabulary shared by the five nexusiam services. This file is part of the white-box
// source snapshot, so it intentionally carries application language only.

export type PersonaKey =
  | 'owner_a'
  | 'member_a'
  | 'viewer_a'
  | 'dual_member'
  | 'member_b'
  | 'revoked_or_demoted'
  | 'admin_bot'

export type TenantKey = 'org_a' | 'org_b' | 'org_c'
export type ServiceName = 'cdn' | 'app' | 'api' | 'idp' | 'docs-worker'
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

export interface NexusIds {
  privateFolderName: string
  folderCandidates: string[]
  privateDocId: string
  privateDocTitle: string
  shareLinkId: string
  profileSlug: string
  staleInviteId: string
  staleInviteToken: string
  exportJobId: string
  exportHandle: string
  canary: string
}

export interface NexusPlan {
  seed: number
  seedSet: SeedKind
  routePrefix: string
  tenants: { a: TenantDef; b: TenantDef; c: TenantDef }
  personas: Record<PersonaKey, PersonaDef>
  secrets: SecretsDef
  economics: EconomicsDef
  ids: IdsDef
  nexus: NexusIds
}

/** Lab behaviour switches. Names describe product policy, not assessment state. */
export interface LabProfile {
  moderationPipeline: boolean
  moderationRendersRaw: boolean
  botSameOriginMint: boolean
  redirectSubpathAccepted: boolean
  inviteListLeaksToken: boolean
  staleInviteRedeem: boolean
  cacheIgnoresAuth: boolean
  emptyWorkspaceFallsBack: boolean
  privateDocScopeCheck: boolean
  facetsLeakCounts: boolean
  shareMetadataLeaksHandle: boolean
  exportJobExfiltrates: boolean
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
  stale: boolean
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

export interface ScimTokenRecord {
  id: string
  token: string
  tenantId: TenantKey
  userId: string
  scopes: string[]
  revoked: boolean
  botInitiated: boolean
  commentId?: string
  runId: string
}

export interface DelegationRecord {
  key: string
  userId: string
  tenantId: TenantKey
  runId: string
}

export interface CommentRecord {
  id: string
  tenantId: TenantKey
  authorUserId: string
  body: string
  rawStored: boolean
  runId: string
}

export interface CollectedToken {
  commentId: string
  token: string
  tokenDigest: string
  runId: string
}

export interface DocRecord {
  id: string
  tenantId: TenantKey
  folder: string
  title: string
  body: string
  isPrivate: boolean
  runId: string
}

export interface JobRecord {
  id: string
  kind: 'export'
  tenantId: TenantKey
  status: 'queued' | 'ready' | 'failed' | 'cancelled'
  createdAt: number
  readyAt: number
  runId: string
  createdBy: string
  handle: string
  preDemotion: boolean
  folderName: string
  artifactKey: string
  processed: boolean
}

export interface CacheEntry {
  path: string
  delegationKey: string
  userId: string
  tenantId: TenantKey
  runId: string
}

export interface LabState {
  plan: NexusPlan
  profile: LabProfile
  runId: string
  orgs: Record<TenantKey, OrgRecord>
  distro: TenantDef[]
  users: UserRecord[]
  sessions: Map<string, SessionRecord>
  invites: InviteRecord[]
  pats: PatRecord[]
  scimTokens: ScimTokenRecord[]
  delegations: Map<string, DelegationRecord>
  comments: CommentRecord[]
  collected: CollectedToken[]
  docs: DocRecord[]
  jobs: JobRecord[]
  cache: Map<string, CacheEntry>
  audit: AuditEvent[]
  listeners: Array<(event: AuditEvent) => void>
  seq: number
  emit(kind: string, detail?: Detail, actorPersona?: PersonaKey): AuditEvent
}
