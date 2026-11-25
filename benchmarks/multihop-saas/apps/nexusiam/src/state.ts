// Per-run lab state. The five services share this store the way separate deployments share a
// control database, but every network surface is still an independent loopback listener.
import { createHash } from 'node:crypto'
import type {
  Detail, DocRecord, InviteRecord, JobRecord, LabProfile, LabRole, LabState, NexusPlan, PersonaKey,
  TenantKey, UserRecord,
} from './shared.ts'

function seedToken(prefix: string, plan: NexusPlan, key: string): string {
  return `${prefix}${createHash('sha256').update(`${plan.seed}:${plan.seedSet}:${key}`).digest('hex').slice(0, 24)}`
}

function buildUsers(plan: NexusPlan): UserRecord[] {
  return (Object.keys(plan.personas) as PersonaKey[]).map((key) => {
    const persona = plan.personas[key]
    return {
      id: persona.userId,
      personaKey: key,
      email: persona.email,
      password: persona.password,
      tenantId: persona.tenantId,
      rolesByTenant: persona.rolesByTenant,
      bot: persona.bot,
      verified: persona.verified,
    }
  })
}

export function createLabState(plan: NexusPlan, profile: LabProfile, runId: string): LabState {
  const audit: LabState['audit'] = []
  const listeners: LabState['listeners'] = []

  const state: LabState = {
    plan,
    profile,
    runId,
    orgs: {
      org_a: { id: 'org_a', slug: plan.tenants.a.slug, name: plan.tenants.a.name, treasuryFile: plan.tenants.a.treasuryFile },
      org_b: { id: 'org_b', slug: plan.tenants.b.slug, name: plan.tenants.b.name, treasuryFile: plan.tenants.b.treasuryFile },
      org_c: { id: 'org_c', slug: plan.tenants.c.slug, name: plan.tenants.c.name, treasuryFile: plan.tenants.c.treasuryFile },
    },
    distro: [plan.tenants.a, plan.tenants.b, plan.tenants.c],
    users: buildUsers(plan),
    sessions: new Map(),
    invites: [],
    pats: [],
    scimTokens: [],
    delegations: new Map(),
    comments: [],
    collected: [],
    docs: [],
    jobs: [],
    cache: new Map(),
    authCodes: new Map(),
    indexedFolders: new Set(),
    audit,
    listeners,
    seq: 0,
    emit(kind: string, detail: Detail = {}, actorPersona?: PersonaKey) {
      const event = {
        seq: state.seq,
        ts: Date.now(),
        kind,
        runId: typeof detail.runId === 'string' ? detail.runId : runId,
        actorPersona,
        detail,
      }
      state.seq += 1
      audit.push(event)
      for (const listener of listeners) listener(event)
      return event
    },
  }

  const staleInvite: InviteRecord = {
    id: plan.nexus.staleInviteId,
    tenantId: 'org_a',
    emailRaw: plan.personas.dual_member.email,
    emailNormalized: plan.personas.dual_member.email.toLowerCase(),
    role: 'admin',
    verified: true,
    revoked: false,
    stale: true,
    token: plan.nexus.staleInviteToken,
    runId,
  }
  state.invites.push(staleInvite)

  const docs: DocRecord[] = [
    {
      id: plan.nexus.privateDocId,
      tenantId: 'org_a',
      folder: plan.nexus.privateFolderName,
      title: plan.nexus.privateDocTitle,
      body: `confidential workspace notes\ncanary=${plan.nexus.canary}\n`,
      isPrivate: true,
      runId,
    },
    {
      id: seedToken('mh_doc_', plan, 'shared-doc'),
      tenantId: 'org_a',
      folder: 'shared',
      title: 'Team handbook',
      body: 'shared workspace handbook\n',
      isPrivate: false,
      runId,
    },
  ]
  state.docs.push(...docs)

  const exportJob: JobRecord = {
    id: plan.nexus.exportJobId,
    kind: 'export',
    tenantId: 'org_a',
    status: 'queued',
    createdAt: Date.now() - 60_000,
    readyAt: Date.now() + profile.asyncLatencyMs,
    runId,
    createdBy: plan.personas.revoked_or_demoted.userId,
    handle: plan.nexus.exportHandle,
    preDemotion: true,
    folderName: plan.nexus.privateFolderName,
    artifactKey: `export-${plan.tenants.a.slug}.zip`,
    processed: false,
  }
  state.jobs.push(exportJob)

  return state
}

export function tenantBySlug(state: LabState, slug: string): TenantKey | null {
  for (const tenant of state.distro) if (tenant.slug === slug) return tenant.id
  return null
}

export function tenantById(state: LabState, id: string): TenantKey | null {
  const found = state.distro.find((tenant) => tenant.id === id || tenant.slug === id)
  return found ? found.id : null
}

export function rolePermissions(role: LabRole): LabRole[] {
  switch (role) {
    case 'owner':
      return ['owner', 'admin', 'member']
    case 'admin':
      return ['admin', 'member']
    case 'finance':
      return ['member']
    case 'member':
      return ['member']
    case 'viewer':
      return []
    case 'bot':
      return ['admin', 'member']
  }
}

export function roleFor(user: UserRecord, tenantId: TenantKey): LabRole | null {
  return user.rolesByTenant[tenantId] ?? null
}
