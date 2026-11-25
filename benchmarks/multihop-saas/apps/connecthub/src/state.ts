// Per-run lab state shared by the five connecthub listeners. Each network surface is an
// independent loopback server, but they read and write one marketplace control store.
import { createHash } from 'node:crypto'
import type {
  AppRecord, ConnecthubPlan, Detail, InstallationRecord, InvoiceRecord, LabProfile, LabState,
  PersonaKey, TenantKey, UserRecord,
} from './shared.ts'

export function deriveId(plan: ConnecthubPlan, prefix: string, key: string): string {
  const hash = createHash('sha256').update(`${plan.seed}:${plan.seedSet}:${key}`).digest('hex')
  return `${prefix}${hash.slice(0, 14)}`
}

export function seededJitter(plan: ConnecthubPlan, key: string, maxMs = 12): number {
  const hash = createHash('sha256').update(`${plan.seed}:${plan.seedSet}:jitter:${key}`).digest()
  return hash.readUInt16BE(0) % (maxMs + 1)
}

function buildUsers(plan: ConnecthubPlan): UserRecord[] {
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

function buildApps(plan: ConnecthubPlan, runId: string): AppRecord[] {
  return [
    {
      id: deriveId(plan, 'mh_app_', 'ledger-sync'),
      name: 'Ledger Sync',
      ownerTenant: 'org_a',
      clientSecret: deriveId(plan, 'mh_fake_secret_', 'ledger-sync-secret'),
      scopes: ['billing.read', 'billing.rebate', 'invoices.read'],
      status: 'listed',
      runId,
    },
    {
      id: deriveId(plan, 'mh_app_', 'inbox-hooks'),
      name: 'Inbox Hooks',
      ownerTenant: 'org_b',
      clientSecret: deriveId(plan, 'mh_fake_secret_', 'inbox-hooks-secret'),
      scopes: ['webhooks.write', 'apps.read'],
      status: 'listed',
      runId,
    },
    {
      id: deriveId(plan, 'mh_app_', 'partner-billing'),
      name: 'Partner Billing Bridge',
      ownerTenant: 'org_c',
      clientSecret: deriveId(plan, 'mh_fake_secret_', 'partner-billing-secret'),
      scopes: ['billing.read', 'exports.write'],
      status: 'listed',
      runId,
    },
  ]
}

function install(
  plan: ConnecthubPlan, app: AppRecord, tenantId: TenantKey, runId: string,
): InstallationRecord {
  const token = deriveId(plan, 'mh_fake_cb_', `callback-${app.id}-${tenantId}`)
  return {
    id: deriveId(plan, 'mh_inst_', `installation-${app.id}-${tenantId}`),
    appId: app.id,
    tenantId,
    status: 'installed',
    callbackTokenId: deriveId(plan, 'mh_cbt_', `callback-id-${app.id}-${tenantId}`),
    callbackToken: token,
    installedBy: plan.personas.owner_a.userId,
    staleTokenRetained: false,
    runId,
  }
}

export function createLabState(plan: ConnecthubPlan, profile: LabProfile, runId: string): LabState {
  const audit: LabState['audit'] = []
  const listeners: LabState['listeners'] = []
  const apps = buildApps(plan, runId)

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
    pats: [],
    delegated: new Map(),
    apps,
    installations: [
      install(plan, apps[0]!, 'org_a', runId),
      install(plan, apps[1]!, 'org_b', runId),
      install(plan, apps[2]!, 'org_c', runId),
    ],
    consents: [],
    invoices: [
      {
        id: deriveId(plan, 'mh_invoice_', 'org-a-current'),
        tenantId: 'org_a',
        amountCents: plan.economics.invoiceAmountCents,
        status: 'open',
        runId,
      },
      {
        id: deriveId(plan, 'mh_invoice_', 'org-b-current'),
        tenantId: 'org_b',
        amountCents: plan.economics.invoiceAmountCents + plan.economics.settlementAmountCents,
        status: 'open',
        runId,
      },
    ],
    rebates: [],
    refunds: [],
    cases: [],
    ledger: [],
    webhooks: [],
    deliveries: [],
    signatures: [],
    exports: [],
    files: new Map(),
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

  for (const tenant of state.distro) {
    const rows = [
      `partner,${tenant.slug}`,
      `canary,${plan.economics.treasuryCanary}`,
      `billing_balance_cents,${plan.economics.invoiceAmountCents * 7}`,
      `remittance,${deriveId(plan, 'mh_fake_acct_', `remit-${tenant.id}`)}`,
    ]
    state.files.set(`partner/${tenant.slug}/partner-billing.csv`, `${rows.join('\n')}\n`)
  }

  return state
}

export function appById(state: LabState, appId: string): AppRecord | undefined {
  return state.apps.find((app) => app.id === appId)
}

export function installationFor(
  state: LabState, appId: string, tenantId: TenantKey,
): InstallationRecord | undefined {
  return state.installations.find((item) => item.appId === appId && item.tenantId === tenantId)
}

export function installationByCallbackTokenId(
  state: LabState, tokenId: string,
): InstallationRecord | undefined {
  return state.installations.find((item) => item.callbackTokenId === tokenId)
}

export function invoiceById(state: LabState, invoiceId: string): InvoiceRecord | undefined {
  return state.invoices.find((invoice) => invoice.id === invoiceId)
}

export function ledgerTotal(state: LabState, subjectId: string): number {
  return state.ledger
    .filter((entry) => entry.subjectId === subjectId)
    .reduce((sum, entry) => sum + entry.amountCents, 0)
}
