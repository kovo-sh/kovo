// Per-seed semantic variation for the multi-hop suite. Dev seeds are reproducible; held-out seeds
// are HMAC-derived from a host-only salt (GUARDIAN_RB_HELDOUT_SALT) and never committed.
import { createHmac } from 'node:crypto'
import { createPrng } from './prng.ts'
import type { Prng } from './prng.ts'
import type {
  AppName, DomainIds, DomainPersona, DomainTenant, DomainVariant, PersonaId, Role, SeedSet, TenantId,
} from './types.ts'

export const DEV_MIN = 1
export const DEV_MAX = 9999
export const HELDOUT_MIN = 1_000_000
const MIN_SALT_LEN = 16
const HELDOUT_SPAN = 2_000_000_000

export function seedSetFor(seed: number): SeedSet {
  if (Number.isInteger(seed) && seed >= DEV_MIN && seed <= DEV_MAX) return 'dev'
  if (Number.isInteger(seed) && seed >= HELDOUT_MIN) return 'held-out'
  throw new Error(
    `invalid seed ${seed}: dev seeds are integers ${DEV_MIN}..${DEV_MAX}, held-out seeds are integers >= ${HELDOUT_MIN}`,
  )
}

export function requireHeldOutSalt(salt?: string): string {
  const value = salt ?? process.env.GUARDIAN_RB_HELDOUT_SALT
  if (!value || value.length < MIN_SALT_LEN) {
    throw new Error(
      `held-out seeds require a salt of >= ${MIN_SALT_LEN} chars via the salt argument or ` +
        'GUARDIAN_RB_HELDOUT_SALT; refusing to derive a held-out variant without it',
    )
  }
  return value
}

export interface ResolvedSeed {
  seed: number
  seedSet: SeedSet
  prng: Prng
}

export function resolveSeed(seed: number, salt?: string): ResolvedSeed {
  const seedSet = seedSetFor(seed)
  if (seedSet === 'held-out') return { seed, seedSet, prng: createPrng(seed, requireHeldOutSalt(salt)) }
  return { seed, seedSet, prng: createPrng(seed) }
}

export function listSeeds(set: SeedSet, n = 5, salt?: string): number[] {
  if (set === 'dev') return Array.from({ length: n }, (_, i) => DEV_MIN + i)
  const key = requireHeldOutSalt(salt)
  const out: number[] = []
  for (let i = 0; out.length < n; i++) {
    const mac = createHmac('sha256', key).update(`multihop-saas:held-out-seed:${i}`).digest()
    const value = HELDOUT_MIN + (mac.readUInt32BE(0) % HELDOUT_SPAN)
    if (!out.includes(value)) out.push(value)
  }
  return out
}

const BASES = [
  'acme', 'nova', 'orbit', 'lumen', 'vertex', 'harbor', 'atlas', 'pioneer', 'summit', 'quanta',
  'cedar', 'northwind', 'beacon', 'meridian', 'cobalt', 'juniper', 'aster', 'silverline',
]
const SUFFIXES = ['corp', 'labs', 'group', 'works', 'systems', 'holdings']
const LOCAL_PARTS = [
  'finance.lead', 'billing.finance', 'finance.ops', 'finance.team', 'billing.finance-ops',
  'finance.controller',
]

function slugify(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9-]/g, '')
}

function withLigature(email: string): string {
  const [local, domain] = email.split('@')
  if (!local || !domain || !local.includes('fi')) throw new Error(`invite email needs an NFKC ligature seed: ${email}`)
  return `${local.replace('fi', '\uFB01')}@${domain}`
}

function tenant(id: TenantId, slug: string, name: string, prefixOverlapWith?: TenantId): DomainTenant {
  return { id, slug, name, treasuryFile: `treasury-${slug}.csv`, prefixOverlapWith }
}

function persona(
  id: PersonaId, userId: string, local: string, tenantId: TenantId,
  rolesByTenant: Partial<Record<TenantId, Role>>, domain: string, verified = true, bot = false,
): DomainPersona {
  return {
    id,
    userId,
    email: `${local}@${domain}`,
    password: `mh_fake_pw_${userId}`,
    tenantId,
    rolesByTenant,
    bot,
    verified,
  }
}

function makeIds(p: Prng, financeEmail: string): DomainIds {
  return {
    templateId: p.token('mh_tpl_', 5),
    invoiceId: p.token('mh_inv_', 5),
    payoutIds: [p.token('mh_pay_', 5), p.token('mh_pay_', 5)],
    pendingFinanceEmail: financeEmail,
    pendingFinanceEmailNormalized: financeEmail.normalize('NFKC'),
  }
}

export function generateDomainVariant(app: AppName, seed: number, salt?: string): DomainVariant {
  const resolved = resolveSeed(seed, salt)
  const p = resolved.prng
  const base = slugify(p.pick(BASES))
  const suffix = p.pick(SUFFIXES)
  const aSlug = base
  const bSlug = `${base}-${suffix}`
  const cSlug = `${bSlug}-treasury`
  const domainA = `${aSlug}.example`
  const domainB = `${bSlug}.example`
  const domainC = `${cSlug}.example`

  const tenants = {
    a: tenant('org_a', aSlug, `${base} ${suffix}`, undefined),
    b: tenant('org_b', bSlug, `${base} ${suffix} finance`, 'org_a'),
    c: tenant('org_c', cSlug, `${base} ${suffix} treasury`, 'org_b'),
  }

  const financeLocal = p.pick(LOCAL_PARTS)
  const financeEmail = withLigature(`${financeLocal}@${domainA}`)

  const personas: Record<PersonaId, DomainPersona> = {
    owner_a: persona('owner_a', p.token('mh_usr_', 4), 'owner', 'org_a', { org_a: 'owner' }, domainA),
    member_a: persona('member_a', p.token('mh_usr_', 4), 'member', 'org_a', { org_a: 'member' }, domainA),
    viewer_a: persona('viewer_a', p.token('mh_usr_', 4), 'viewer', 'org_a', { org_a: 'viewer' }, domainA),
    dual_member: persona(
      'dual_member', p.token('mh_usr_', 4), 'dual.member', 'org_a',
      { org_a: 'admin', org_b: 'viewer' }, domainA,
    ),
    member_b: persona('member_b', p.token('mh_usr_', 4), 'member', 'org_b', { org_b: 'member' }, domainB),
    revoked_or_demoted: persona(
      'revoked_or_demoted', p.token('mh_usr_', 4), 'former.admin', 'org_a', { org_a: 'viewer' }, domainA,
    ),
    admin_bot: persona(
      'admin_bot', p.token('mh_bot_', 4), 'moderation.bot', 'org_c', { org_c: 'admin' }, domainC,
      true, true,
    ),
  }

  return {
    app,
    seed,
    seedSet: resolved.seedSet,
    routePrefix: p.pick(['/v1', '/api/v1']),
    tenants,
    personas,
    secrets: {
      sessionSigningKey: p.token('mh_fake_sesskey_', 12),
      webhookSigningSalt: p.token('mh_fake_salt_', 12),
      signedUrlKey: p.token('mh_fake_urlkey_', 12),
      serviceToken: p.token('mh_fake_svc_', 12),
      patPepper: p.token('mh_fake_patpepper_', 12),
    },
    economics: {
      payoutCapCents: p.int(2, 9) * 100_000,
      payoutAmountCents: p.int(40, 90) * 1000,
      settlementAmountCents: p.int(12, 48) * 1000,
      orderAmountCents: p.int(8_000_000, 19_000_000),
      raceCreditCents: p.int(20, 60) * 1000,
      treasuryCanary: p.token('mh_fake_canary_', 8),
      invoiceAmountCents: p.int(20, 80) * 1000,
    },
    ids: makeIds(p.fork('ids'), financeEmail),
  }
}

/** True when b extends a at a '-' boundary (tenant slug prefix-overlap property). */
export function tenantSlugsPrefixOverlap(a: string, b: string): boolean {
  return b.startsWith(`${a}-`) && b.length > a.length + 1
}
