// Semantic domain randomization (plan §3.2). Routes/params/ids are randomized by variant.ts; this
// module randomizes the *business semantics* an LLM might otherwise memorize: maker/checker role
// vocabulary, state-machine labels, coupon/currency/rounding economics, and a tenant slug pair that
// always prefix-overlaps at a '-' boundary (so the fc-07 signed-URL prefix bug is reachable).
import type {
  AppName, DomainEconomics, DomainRoles, DomainStates, DomainVariant, DomainVocab,
} from '../lib/types.ts'
import type { Prng } from '../lib/prng.ts'

const DEFAULT_ROLE_SETS: DomainRoles[] = [
  { owner: 'owner', admin: 'admin', member: 'member', viewer: 'viewer', maker: 'maker', checker: 'checker' },
  { owner: 'owner', admin: 'admin', member: 'member', viewer: 'viewer', maker: 'requester', checker: 'approver' },
  { owner: 'owner', admin: 'admin', member: 'analyst', viewer: 'reader', maker: 'analyst', checker: 'controller' },
  { owner: 'owner', admin: 'admin', member: 'contributor', viewer: 'observer', maker: 'drafter', checker: 'reviewer' },
  { owner: 'owner', admin: 'admin', member: 'operator', viewer: 'auditor', maker: 'initiator', checker: 'authorizer' },
]

const DEFAULT_STATE_SETS: DomainStates[] = [
  { draft: 'draft', pending: 'pending_capture', settled: 'settled', rejected: 'rejected', archived: 'archived' },
  { draft: 'open', pending: 'awaiting_payment', settled: 'finalized', rejected: 'declined', archived: 'closed' },
  { draft: 'draft', pending: 'under_review', settled: 'confirmed', rejected: 'void', archived: 'cancelled' },
  { draft: 'new', pending: 'in_flight', settled: 'completed', rejected: 'failed', archived: 'retired' },
  { draft: 'proposed', pending: 'queued', settled: 'released', rejected: 'withdrawn', archived: 'expired' },
]

const DEFAULT_CURRENCY_PAIRS: Array<[string, string]> = [
  ['USD', 'EUR'], ['USD', 'GBP'], ['CAD', 'EUR'], ['EUR', 'GBP'], ['AUD', 'USD'],
]

const DEFAULT_BASES = [
  'acme', 'nova', 'orbit', 'lumen', 'vertex', 'harbor', 'atlas', 'pioneer', 'summit', 'quanta',
  'cedar', 'northwind', 'beacon', 'meridian', 'cobalt', 'juniper', 'aster', 'silverline',
]

const DEFAULT_SUFFIXES = ['-corp', '-labs', '-group', '-works', '-inc', '-systems']

/** True when `b` starts with `a` followed by a '-' boundary (the fc-07 prefix pair property). */
export function tenantPrefixOverlaps(a: string, b: string): boolean {
  return b.startsWith(`${a}-`) && b.length > a.length + 1
}

function economics(p: Prng): DomainEconomics {
  const couponMinSpendCents = p.int(150, 300) * 100 // $150..$300
  const couponPercent = p.int(15, 35)
  const currencies = p.pick(DEFAULT_CURRENCY_PAIRS)
  const roundingStepCents = p.pick([1, 5, 10, 25])
  const transferFeeCents = p.int(25, 150)
  // Promo must exceed the fee so the lf-06 two-account loop is economically meaningful.
  const promoBonusCents = transferFeeCents + p.int(150, 500)
  return { couponMinSpendCents, couponPercent, currencies, roundingStepCents, transferFeeCents, promoBonusCents }
}

function tenantPair(p: Prng, vocab?: DomainVocab): { orgA: string; orgB: string } {
  const bases = vocab?.tenantBases?.length ? vocab.tenantBases : DEFAULT_BASES
  const suffixes = vocab?.tenantSuffixes?.length ? vocab.tenantSuffixes : DEFAULT_SUFFIXES
  const base = p.pick(bases).toLowerCase().replace(/[^a-z0-9-]/g, '')
  const suffix = p.pick(suffixes)
  return { orgA: base, orgB: `${base}${suffix}` }
}

/**
 * Derive the semantic variant for a seed. Consumes its own `domain` fork so adding a route or a
 * site cannot reshuffle business vocabulary (and vice versa).
 */
export function generateDomainVariant(
  app: AppName, seed: number, prng: Prng, vocab?: DomainVocab,
): DomainVariant {
  const p = prng.fork('domain')
  const roleSets = vocab?.roleSets?.length ? vocab.roleSets : DEFAULT_ROLE_SETS
  const stateSets = vocab?.stateSets?.length ? vocab.stateSets : DEFAULT_STATE_SETS
  return {
    app,
    seed,
    roleVocab: { ...p.pick(roleSets) },
    stateLabels: { ...p.pick(stateSets) },
    economics: economics(p.fork('economics')),
    tenants: tenantPair(p.fork('tenants'), vocab),
  }
}
