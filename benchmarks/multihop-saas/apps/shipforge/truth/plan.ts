// Host-side per-seed domain variation for shipforge. Held-out variants are HMAC-derived from the
// host-only salt; nothing here is copied into a white-box snapshot.
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { resolveSeed } from '../../../lib/domain-variant.ts'
import type { Prng } from '../../../lib/prng.ts'
import type {
  IdsDef, PersonaKey, ShipforgePlan, TenantDef, TenantKey, SecretsDef,
} from '../src/shared.ts'

const BASES = [
  'northwind', 'orbital', 'quanta', 'cobalt', 'summit', 'meridian', 'atlas', 'juniper',
  'beacon', 'harbor', 'vertex', 'silverline', 'aster', 'lumen', 'cedar', 'pioneer',
]
const SUFFIXES = ['labs', 'systems', 'works', 'group', 'holdings', 'cloud']

function slugify(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9-]/g, '')
}

function tenant(id: TenantKey, slug: string, name: string, prefixOverlapWith?: TenantKey): TenantDef {
  return { id, slug, name, artifactBucket: `artifacts-${slug}`, prefixOverlapWith }
}

function uuid(p: Prng): string {
  return `${p.hex(4)}-${p.hex(2)}-${p.hex(2)}-${p.hex(2)}-${p.hex(6)}`
}

function persona(
  id: PersonaKey, userId: string, local: string, tenantId: TenantKey,
  rolesByTenant: Partial<Record<TenantKey, 'owner' | 'admin' | 'member' | 'viewer' | 'bot'>>,
  domain: string, bot = false,
) {
  return {
    id,
    userId,
    email: `${local}@${domain}`,
    password: `mh_fake_pw_${userId}`,
    tenantId,
    rolesByTenant,
    bot,
    verified: true,
  }
}

function secrets(p: Prng): SecretsDef {
  return {
    devRunnerToken: p.token('mh_fake_runner_dev_', 12),
    prodRunnerToken: p.token('mh_fake_runner_prod_', 12),
    internalBearerToken: p.token('mh_fake_internal_', 12),
    prodSigningKey: p.token('mh_fake_signing_', 12),
    webhookSigningSalt: p.token('mh_fake_salt_', 12),
    artifactKey: p.token('mh_fake_artifact_', 12),
  }
}

export function generateShipforgePlan(seed: number, salt?: string): ShipforgePlan {
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
    a: tenant('org_a', aSlug, `${base} ${suffix}`),
    b: tenant('org_b', bSlug, `${base} ${suffix} platform`, 'org_a'),
    c: tenant('org_c', cSlug, `${base} ${suffix} treasury`, 'org_b'),
  }

  const personas: ShipforgePlan['personas'] = {
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
    admin_bot: persona('admin_bot', p.token('mh_bot_', 4), 'release.bot', 'org_c', { org_c: 'admin' }, domainC, true),
  }

  const ids: IdsDef = {
    projectIdA: uuid(p.fork('project-a')),
    projectIdB: uuid(p.fork('project-b')),
    webhookTemplateIdA: p.token('mh_wh_tpl_', 5),
    webhookTemplateIdB: p.token('mh_wh_tpl_', 5),
    deploymentProdId: p.token('mh_dep_', 5),
    deploymentAutoId: p.token('mh_dep_', 5),
    ownSecretId: p.token('mh_sec_', 5),
    victimSecretId: p.token('mh_sec_', 5),
    revokedPatId: p.token('mh_pat_', 5),
    revokedPatToken: p.token('mh_fake_pat_', 12),
    sharedBuildId: p.token('mh_bld_shared_', 5),
    sharedArtifactHandle: p.token('mh_fake_artifact_handle_', 8),
    repoSlugA: `${base}-checkout`,
    repoSlugB: `${base}-billing`,
  }

  return {
    seed,
    seedSet: resolved.seedSet,
    routePrefix: p.pick(['/v1', '/api/v1']),
    tenants,
    personas,
    secrets: secrets(p.fork('secrets')),
    ids,
  }
}

/** Replace the neutral snapshot descriptor with shipforge's service list (still marker-free). */
export function writeSnapshotDescriptor(root: string, plan: ShipforgePlan): void {
  const descriptor = {
    seed: plan.seed,
    seedSet: plan.seedSet,
    routePrefix: plan.routePrefix,
    tenants: plan.tenants,
    services: ['edge', 'api', 'runner', 'scm', 'registry.internal'],
  }
  writeFileSync(join(root, 'variant.json'), `${JSON.stringify(descriptor, null, 2)}\n`)
  writeFileSync(join(root, 'README.md'), `# shipforge lab source snapshot\nseed ${plan.seed} (${plan.seedSet})\n`)
}
