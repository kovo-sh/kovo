// Domain types shared by the five shipforge services. This file is part of the white-box source
// tree, so it contains only application vocabulary: tenants, projects, builds, runners, hooks,
// deployments, automations and registry sync.

export type PersonaKey =
  | 'owner_a'
  | 'member_a'
  | 'viewer_a'
  | 'dual_member'
  | 'member_b'
  | 'revoked_or_demoted'
  | 'admin_bot'

export type TenantKey = 'org_a' | 'org_b' | 'org_c'
export type ServiceName = 'edge' | 'api' | 'runner' | 'scm' | 'registry.internal'
export type LabRole = 'owner' | 'admin' | 'member' | 'viewer' | 'bot'
export type SeedKind = 'dev' | 'held-out'
export type Detail = Record<string, string | number | boolean>

export interface TenantDef {
  id: TenantKey
  slug: string
  name: string
  artifactBucket: string
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
  devRunnerToken: string
  prodRunnerToken: string
  internalBearerToken: string
  prodSigningKey: string
  webhookSigningSalt: string
  artifactKey: string
}

export interface IdsDef {
  projectIdA: string
  projectIdB: string
  webhookTemplateIdA: string
  webhookTemplateIdB: string
  deploymentProdId: string
  deploymentAutoId: string
  ownSecretId: string
  victimSecretId: string
  revokedPatId: string
  revokedPatToken: string
  sharedBuildId: string
  sharedArtifactHandle: string
  repoSlugA: string
  repoSlugB: string
}

export interface ShipforgePlan {
  seed: number
  seedSet: SeedKind
  routePrefix: string
  tenants: { a: TenantDef; b: TenantDef; c: TenantDef }
  personas: Record<PersonaKey, PersonaDef>
  secrets: SecretsDef
  ids: IdsDef
}

/** Lab behaviour switches. Names describe policy, not evaluation state. */
export interface LabProfile {
  previewEnvLeak: boolean
  promoteEnvScope: boolean
  secretsBatchAllIds: boolean
  sseChecksRevocation: boolean
  transferDualAdmin: boolean
  transferRequiresLivePat: boolean
  searchFilterParenthesized: boolean
  deliveryLogRedacted: boolean
  internalDiagnosticLeak: boolean
  registryTokenScoped: boolean
  automationInheritAdmin: boolean
  disputeKeepsSchedule: boolean
  autoReleaseRequiresApproval: boolean
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
  artifactBucket: string
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
}

export interface InviteRecord {
  id: string
  tenantId: TenantKey
  email: string
  role: LabRole
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

export interface ProjectRecord {
  id: string
  tenantId: TenantKey
  slug: string
  name: string
  visibility: 'private' | 'shared'
  state: 'active' | 'archived'
  transferredToTenant?: TenantKey
  runId: string
}

export interface WebhookTemplateRecord {
  id: string
  tenantId: TenantKey
  name: string
  targetHost: string
  targetPath: string
  secret: string
  visibility: 'private' | 'shared'
  state: 'active' | 'archived'
  runId: string
}

export interface DeliveryRecord {
  id: string
  status: number
  log: string
  ts: number
}

export interface WebhookRecord {
  id: string
  projectId: string
  tenantId: TenantKey
  templateId: string
  targetHost: string
  targetPath: string
  deliveries: DeliveryRecord[]
  runId: string
}

export interface EnvPreview {
  env: string
  runnerToken: string
  note: string
}

export interface BuildRecord {
  id: string
  projectId: string
  tenantId: TenantKey
  commit: string
  status: 'queued' | 'ready' | 'failed' | 'cancelled'
  createdAt: number
  readyAt: number
  artifactHandle: string
  envPreview: EnvPreview
  runId: string
}

export interface DeploymentRecord {
  id: string
  projectId: string
  tenantId: TenantKey
  env: 'staging' | 'prod'
  status: 'pending' | 'approved' | 'disputed' | 'released'
  approved: boolean
  autoReleaseScheduled: boolean
  disputed: boolean
  releaseId: string
  runId: string
}

export interface AutomationRecord {
  id: string
  projectId: string
  tenantId: TenantKey
  roleTemplate: string
  autoRelease: boolean
  runId: string
}

export interface SecretRecord {
  id: string
  tenantId: TenantKey
  name: string
  scope: string
  value: string
  runId: string
}

export interface ServiceAccountRecord {
  token: string
  tenantId: TenantKey
  scope: string
  runId: string
}

export interface LabState {
  plan: ShipforgePlan
  profile: LabProfile
  runId: string
  orgs: Record<TenantKey, OrgRecord>
  distro: TenantDef[]
  users: UserRecord[]
  sessions: Map<string, SessionRecord>
  invites: InviteRecord[]
  pats: PatRecord[]
  projects: ProjectRecord[]
  webhookTemplates: WebhookTemplateRecord[]
  webhooks: WebhookRecord[]
  builds: BuildRecord[]
  deployments: DeploymentRecord[]
  automations: AutomationRecord[]
  secrets: SecretRecord[]
  serviceAccounts: ServiceAccountRecord[]
  audit: AuditEvent[]
  listeners: Array<(event: AuditEvent) => void>
  seq: number
  emit(kind: string, detail?: Detail, actorPersona?: PersonaKey): AuditEvent
}
