// Per-run lab state. The five services share this store the way separate deployments share a
// control database, but every network surface is still an independent loopback listener.
import { createHash } from 'node:crypto'
import type {
  AuditEvent, LabProfile, LabRole, LabState, PersonaKey, ShipforgePlan, TenantKey, UserRecord,
} from './shared.ts'

function seedToken(prefix: string, plan: ShipforgePlan, key: string): string {
  return `${prefix}${createHash('sha256').update(`${plan.seed}:${plan.seedSet}:${key}`).digest('hex').slice(0, 20)}`
}

function buildUsers(plan: ShipforgePlan): UserRecord[] {
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

export function createLabState(plan: ShipforgePlan, profile: LabProfile, runId: string): LabState {
  const audit: AuditEvent[] = []
  const listeners: LabState['listeners'] = []
  const now = Date.now()

  const state: LabState = {
    plan,
    profile,
    runId,
    orgs: {
      org_a: {
        id: 'org_a', slug: plan.tenants.a.slug, name: plan.tenants.a.name,
        artifactBucket: plan.tenants.a.artifactBucket,
      },
      org_b: {
        id: 'org_b', slug: plan.tenants.b.slug, name: plan.tenants.b.name,
        artifactBucket: plan.tenants.b.artifactBucket,
      },
      org_c: {
        id: 'org_c', slug: plan.tenants.c.slug, name: plan.tenants.c.name,
        artifactBucket: plan.tenants.c.artifactBucket,
      },
    },
    distro: [plan.tenants.a, plan.tenants.b, plan.tenants.c],
    users: buildUsers(plan),
    sessions: new Map(),
    invites: [],
    pats: [{
      id: plan.ids.revokedPatId,
      token: plan.ids.revokedPatToken,
      userId: plan.personas.revoked_or_demoted.userId,
      tenantId: 'org_a',
      scopes: ['org:admin', 'repo:write', 'runner:stream'],
      revoked: true,
      runId,
    }],
    projects: [
      {
        id: plan.ids.projectIdA, tenantId: 'org_a', slug: plan.ids.repoSlugA,
        name: 'checkout-service', visibility: 'private', state: 'active', runId,
      },
      {
        id: plan.ids.projectIdB, tenantId: 'org_b', slug: plan.ids.repoSlugB,
        name: 'billing-pipeline', visibility: 'shared', state: 'archived', runId,
      },
      {
        id: seedToken('mh_prj_', plan, 'project-a-docs'), tenantId: 'org_a', slug: 'docs-site',
        name: 'docs-site', visibility: 'private', state: 'active', runId,
      },
      {
        id: seedToken('mh_prj_', plan, 'project-b-api'), tenantId: 'org_b', slug: 'edge-api',
        name: 'edge-api', visibility: 'private', state: 'active', runId,
      },
    ],
    webhookTemplates: [
      {
        id: plan.ids.webhookTemplateIdA, tenantId: 'org_a', name: 'deploy-notify',
        targetHost: 'registry.internal', targetPath: '/hooks/deploy',
        secret: plan.secrets.webhookSigningSalt, visibility: 'private', state: 'active', runId,
      },
      {
        id: plan.ids.webhookTemplateIdB, tenantId: 'org_b', name: 'release-archive',
        targetHost: 'registry.internal', targetPath: '/sync',
        secret: plan.secrets.webhookSigningSalt, visibility: 'shared', state: 'archived', runId,
      },
    ],
    webhooks: [],
    builds: [{
      id: plan.ids.sharedBuildId,
      projectId: plan.ids.projectIdB,
      tenantId: 'org_b',
      commit: 'shared-ref-01',
      status: 'ready',
      createdAt: now - 60_000,
      readyAt: now - 59_000,
      artifactHandle: plan.ids.sharedArtifactHandle,
      envPreview: { env: 'dev', runnerToken: plan.secrets.devRunnerToken, note: 'shared runner pool' },
      runId,
    }],
    deployments: [
      {
        id: plan.ids.deploymentProdId, projectId: plan.ids.projectIdA, tenantId: 'org_a',
        env: 'prod', status: 'pending', approved: false, autoReleaseScheduled: false,
        disputed: false, releaseId: '', runId,
      },
      {
        id: plan.ids.deploymentAutoId, projectId: plan.ids.projectIdA, tenantId: 'org_a',
        env: 'prod', status: 'pending', approved: false, autoReleaseScheduled: false,
        disputed: false, releaseId: '', runId,
      },
    ],
    automations: [],
    secrets: [
      {
        id: plan.ids.ownSecretId, tenantId: 'org_a', name: 'DEV_ARTIFACT_KEY', scope: 'dev',
        value: plan.secrets.artifactKey, runId,
      },
      {
        id: plan.ids.victimSecretId, tenantId: 'org_b', name: 'PROD_SIGNING_KEY', scope: 'prod',
        value: plan.secrets.prodSigningKey, runId,
      },
    ],
    serviceAccounts: [],
    audit,
    listeners,
    seq: 0,
    emit(kind: string, detail = {}, actorPersona?: PersonaKey) {
      const event: AuditEvent = {
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

export function roleFor(user: UserRecord, tenantId: TenantKey): LabRole | null {
  return user.rolesByTenant[tenantId] ?? null
}

export function projectById(state: LabState, id: string) {
  return state.projects.find((project) => project.id === id) ?? null
}

export function deploymentById(state: LabState, id: string) {
  return state.deployments.find((deployment) => deployment.id === id) ?? null
}

export function buildById(state: LabState, id: string) {
  return state.builds.find((build) => build.id === id) ?? null
}

export function webhookById(state: LabState, id: string) {
  return state.webhooks.find((webhook) => webhook.id === id) ?? null
}

/** Lazily converge a queued build once its configured latency has elapsed. */
export function convergeBuild(state: LabState, buildId: string): void {
  const build = buildById(state, buildId)
  if (!build || build.status !== 'queued') return
  if (Date.now() < build.readyAt) return
  build.status = 'ready'
}
