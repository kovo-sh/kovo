// Per-run lab state. The five services share this store the way separate deployments share a
// control database, but every network surface is still an independent loopback listener.
import { createHash, randomBytes } from 'node:crypto'
import type {
  Detail, InviteRecord, LabProfile, LabRole, LabState, PaygridPlan, PersonaKey, TenantKey, UserRecord,
} from './shared.ts'

function seedToken(prefix: string, plan: PaygridPlan, key: string): string {
  return `${prefix}${createHash('sha256').update(`${plan.seed}:${plan.seedSet}:${key}`).digest('hex').slice(0, 20)}`
}

function buildUsers(plan: PaygridPlan): UserRecord[] {
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

export function createLabState(plan: PaygridPlan, profile: LabProfile, runId: string): LabState {
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
    payouts: plan.ids.payoutIds.map((id, index) => ({
      id,
      tenantId: 'org_a',
      amountCents: plan.economics.payoutAmountCents + index * 1000,
      beneficiary: `acct_vendor_${index + 1}`,
      status: 'draft',
      createdBy: plan.personas.owner_a.userId,
      approvedBy: '',
      rebound: false,
      runId,
    })),
    orders: [],
    templates: [{
      id: plan.ids.templateId,
      tenantId: 'org_a',
      name: 'Invoice footer',
      footer: 'Thank you for your business.',
      rawStored: false,
      runId,
    }],
    invoices: [{
      id: plan.ids.invoiceId,
      tenantId: 'org_a',
      templateId: plan.ids.templateId,
      amountCents: plan.economics.invoiceAmountCents,
      status: 'open',
      runId,
    }],
    jobs: [],
    cache: new Map(),
    ledger: [],
    treasury: new Map(),
    audit,
    listeners,
    seq: 0,
    edgeBridgeToken: randomBytes(24).toString('hex'),
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

  state.users.push({
    id: seedToken('mh_usr_fin_', plan, 'finance-user'),
    personaKey: 'member_a',
    email: plan.ids.pendingFinanceEmailNormalized,
    password: seedToken('mh_fake_pw_', plan, 'finance-user'),
    tenantId: 'org_a',
    rolesByTenant: { org_a: 'finance' },
    bot: false,
    verified: false,
  })

  const financeInvite: InviteRecord = {
    id: seedToken('mh_inv_', plan, 'finance-invite'),
    tenantId: 'org_a',
    emailRaw: plan.ids.pendingFinanceEmail,
    emailNormalized: plan.ids.pendingFinanceEmailNormalized,
    role: 'finance',
    verified: false,
    revoked: false,
    token: seedToken('mh_fake_invite_', plan, 'finance-invite-token'),
    runId,
  }
  state.invites.push(financeInvite)

  for (const tenant of state.distro) {
    const rows = [
      `tenant,${tenant.slug}`,
      `canary,${plan.economics.treasuryCanary}`,
      `balance_cents,${plan.economics.payoutCapCents * 10}`,
      `payout_instruction,${seedToken('mh_fake_acct_', plan, `treasury-${tenant.id}`)}`,
    ]
    state.treasury.set(tenant.slug, `${rows.join('\n')}\n`)
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

// Export paths are exact unless the target declares a direct slug overlap.
export function exportPathPrefix(
  state: LabState, signedTenantId: TenantKey, pathTenantId: TenantKey,
): string | null {
  const signedSlug = state.orgs[signedTenantId].slug
  const pathTenant = state.distro.find((tenant) => tenant.id === pathTenantId)
  const base = `/files/export/${signedSlug}`
  if (signedTenantId === pathTenantId) return `${base}/`
  if (!pathTenant || pathTenant.prefixOverlapWith !== signedTenantId || !pathTenant.slug.startsWith(`${signedSlug}-`)) {
    return null
  }
  return `${base}-`
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
