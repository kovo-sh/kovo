// Per-seed domain semantics. The generator randomizes business vocabulary (role names, workflow state
// labels, currencies, coupon/transfer economics and the overlapping tenant slug pair); routes and
// params arrive in the plan already. This module resolves those optional fields with neutral
// ledgerflow defaults so the app runs on a bare plan while still honouring a richly randomized one.
import type { VariantPlan, PersonaCredential, PersonaId } from '../../../lib/types.ts'

export interface DomainRules {
  roles: { owner: string; admin: string; member: string; viewer: string }
  states: { draft: string; pending: string; settled: string; open: string; paid: string; fulfilled: string }
  currencies: { base: string; quote: string; baseRateMicros: number; quoteRateMicros: number }
  coupon: { percent: number; minSpendCents: number }
  transfer: { feeMicros: number; rebateMicros: number }
  tenantSlugs: { a: string; b: string }
}

export interface LedgerLabels {
  appName: string
  org: string
  nav: Record<string, string>
  roles: Record<string, string>
  states: Record<string, string>
  currency: string
  quoteCurrency: string
}

type Bag = Record<string, unknown>

function bag(value: unknown): Bag {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Bag) : {}
}

function text(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : fallback
}

function num(value: unknown, fallback: number): number {
  const n = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(n) ? n : fallback
}

function orderedSlugPair(a: string, b: string): { a: string; b: string } {
  if (a === b) return { a, b: `${b}-corp` }
  return a.startsWith(b) || b.startsWith(a) ? { a, b } : { a, b: `${b}` }
}

/** Resolve the randomized domain vocabulary for this seed. */
export function domainOf(plan: VariantPlan): DomainRules {
  const p = plan as unknown as Bag
  const domain = bag(p.domain ?? p.rules ?? p.semantics)
  const roles = bag(domain.roles ?? domain.roleLabels)
  const states = bag(domain.states ?? domain.stateLabels)
  const cur = bag(domain.currencies ?? domain.currency ?? domain.economics)
  const coupon = bag(domain.coupon ?? domain.coupons ?? domain.economics)
  const transfer = bag(domain.transfer ?? domain.transfers ?? domain.economics)
  const slugs = bag(domain.tenantSlugs ?? domain.tenants ?? domain.slugPair ?? domain.slugs)
  const personaA = personaCredential(plan, 'owner_a', 'persona_a')
  const personaB = personaCredential(plan, 'member_b', 'persona_b')
  const pair = orderedSlugPair(
    text(slugs.a ?? slugs.orgA ?? slugs.primary, personaA?.tenant ?? 'acme'),
    text(slugs.b ?? slugs.orgB ?? slugs.secondary, personaB?.tenant ?? 'acme-corp'),
  )
  const base = text(cur.base, 'USD').toUpperCase()
  const quote = text(cur.quote, base === 'EUR' ? 'USD' : 'EUR').toUpperCase()
  return {
    roles: {
      owner: text(roles.owner, 'owner'),
      admin: text(roles.admin, 'admin'),
      member: text(roles.member, 'member'),
      viewer: text(roles.viewer, 'viewer'),
    },
    states: {
      draft: text(states.draft, 'draft'),
      pending: text(states.pending, 'pending'),
      settled: text(states.settled, 'settled'),
      open: text(states.open, 'open'),
      paid: text(states.paid, 'paid'),
      fulfilled: text(states.fulfilled, 'fulfilled'),
    },
    currencies: {
      base,
      quote,
      baseRateMicros: num(cur.baseRateMicros ?? cur.rateToBaseMicros, 1_000_000),
      quoteRateMicros: num(cur.quoteRateMicros ?? cur.quoteRate, 920_000),
    },
    coupon: {
      percent: Math.min(60, Math.max(5, num(coupon.percent ?? coupon.percentOff ?? domain.couponPercent, 20))),
      minSpendCents: Math.max(0, num(coupon.minSpendCents ?? coupon.min_spend_cents ?? domain.couponMinSpendCents, 20_000)),
    },
    transfer: {
      feeMicros: Math.max(0, num(transfer.feeMicros ?? transfer.fee, 250_000)),
      rebateMicros: Math.max(0, num(transfer.rebateMicros ?? transfer.rebate, 0)),
    },
    tenantSlugs: pair,
  }
}

export function labelsFor(plan: VariantPlan): LedgerLabels {
  const d = domainOf(plan)
  return {
    appName: 'LedgerFlow',
    org: text((plan as unknown as Bag).orgName, 'LedgerFlow Workspace'),
    nav: {
      dashboard: 'Overview',
      invoices: 'Invoices',
      cart: 'Billing cart',
      payouts: 'Payouts',
      invites: 'Team & invites',
      exports: 'Exports',
    },
    roles: d.roles,
    states: d.states,
    currency: d.currencies.base,
    quoteCurrency: d.currencies.quote,
  }
}

type CredentialBag = Record<string, PersonaCredential | undefined>

/** Look up a seeded persona credential, falling back through compatibility aliases. */
export function personaCredential(plan: VariantPlan, ...ids: string[]): PersonaCredential | undefined {
  const personas = plan.personas as unknown as CredentialBag
  for (const id of ids) {
    const found = personas[id]
    if (found) return found
  }
  return undefined
}

export function personaId(plan: VariantPlan, ...ids: string[]): PersonaId | null {
  const personas = plan.personas as unknown as CredentialBag
  for (const id of ids) if (personas[id]) return id as unknown as PersonaId
  return null
}

/** Deterministic synthetic signing secrets, derived only from the per-seed canary salt. */
export function deriveSecrets(plan: VariantPlan): { jwt: string; webhookSecretFor: (tenant: string) => string } {
  const tag = plan.canarySalt.replace(/[^a-z0-9]/gi, '').slice(0, 12).toLowerCase() || 'seed'
  return {
    jwt: `rb_fake_jwt_${tag}`,
    webhookSecretFor: (tenant: string) => `rb_fake_whk_${tenant.replace(/[^a-z0-9]/gi, '').slice(0, 10)}_${tag}`,
  }
}

export function roleRank(role: string): number {
  switch (role) {
    case 'owner': return 3
    case 'admin': return 2
    case 'member': return 1
    case 'viewer': return 0
    default: return -1
  }
}
