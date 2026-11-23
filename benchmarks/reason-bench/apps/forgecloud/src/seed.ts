// Deterministic per-seed identity, membership and credential seed. Everything is derived from
// plan.canarySalt, so a given seed always yields the same orgs, personas, tokens and canaries.
// Tenant records carry data canaries; workspace secrets and runner tokens carry secret canaries.
import { createHash } from 'node:crypto'
import type { VariantPlan } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import { createPrng } from '../../../lib/prng.ts'
import { ROLE_TEMPLATES, permissionsForRole } from './roles.ts'
import { seedContent, type SeedOrg } from './seed-content.ts'

export interface SeedResult {
  files: Record<string, string>
  orgs: { a: SeedOrg; b: SeedOrg }
  signingSalt: string
  idpSecret: string
  startTs: number
}

export function hashPassword(pw: string, salt: string): string {
  return createHash('sha256').update(`${salt}:${pw}`).digest('hex')
}

interface PersonaSeed {
  key: string
  email: string
  password: string
  role: string
  name: string
  org: 'a' | 'b'
  extra?: Array<{ org: 'a' | 'b'; role: string }>
}

function titleCase(slug: string): string {
  return slug.split(/[-_]/).filter(Boolean).map((s) => s[0]!.toUpperCase() + s.slice(1)).join(' ')
}

export function seed(db: Db, deps: { plan: VariantPlan; ids: IdCodec; canaries: CanaryRegistry }): SeedResult {
  const { plan, ids, canaries } = deps
  const salt = plan.canarySalt
  const rng = createPrng(`forgecloud:${salt}`)
  const personas = (plan.personas ?? {}) as unknown as Record<string, {
    email?: string; password?: string; tenant?: string; role?: string; id?: string
  }>
  const cred = (key: string, fallbackEmail: string, fallbackRole: string) => {
    const c = personas[key]
    return {
      email: c?.email || fallbackEmail,
      password: c?.password || `rb_fake_${key}_${rng.hex(6)}`,
      tenant: c?.tenant || '',
      role: c?.role || fallbackRole,
    }
  }

  const ownerA = cred('owner_a', 'owner@nova.example', 'owner')
  const memberA = cred('member_a', 'dev@nova.example', 'member')
  const viewerA = cred('viewer_a', 'viewer@nova.example', 'viewer')
  const dual = cred('dual_member', 'dual@nova.example', 'admin')
  const memberB = cred('member_b', 'dev@nova-labs.example', 'member')
  const revoked = cred('revoked_demoted', 'revoked@nova.example', 'admin')

  const slugA = (ownerA.tenant || 'nova').replace(/[^a-z0-9-]/gi, '').toLowerCase() || 'nova'
  const planSlugB = (memberB.tenant || '').replace(/[^a-z0-9-]/gi, '').toLowerCase()
  // Ensure the seed's prefix pair exists and the attacker org is the *shorter* slug.
  const slugB = planSlugB && planSlugB !== slugA && planSlugB.startsWith(slugA) ? planSlugB : `${slugA}-corp`

  const startTs = 1_700_000_000_000 + parseInt(createHash('sha256').update(`ts:${salt}`).digest('hex').slice(0, 8), 16) % 10_000_000
  const signingSalt = canaries.secretToken('internal-signing', 'salt')
  const idpSecret = `rb_fake_idp_${rng.hex(8)}`

  for (const [code, tpl] of Object.entries(ROLE_TEMPLATES)) {
    db.run('INSERT INTO role_templates (code,label,permissions) VALUES (?,?,?)',
      [code, tpl.label, JSON.stringify(tpl.permissions)])
  }

  const orgA: SeedOrg = {
    code: 'org_a', slug: slugA, name: `${titleCase(slugA)} Systems`,
    externalId: ids.encode('org', 1), ssoTenant: `tid_${slugA}`,
  }
  const orgB: SeedOrg = {
    code: 'org_b', slug: slugB, name: `${titleCase(slugB)} Labs`,
    externalId: ids.encode('org', 2), ssoTenant: `tid_${slugB}`,
  }
  for (const org of [orgA, orgB]) {
    db.run('INSERT INTO orgs (external_id,code,slug,name,plan,sso_tenant,data_ref) VALUES (?,?,?,?,?,?,?)',
      [org.externalId, org.code, org.slug, org.name, 'team', org.ssoTenant,
        canaries.tenantToken(org.slug, 'org')])
  }

  const personaSeeds: PersonaSeed[] = [
    { key: 'owner_a', email: ownerA.email, password: ownerA.password, role: 'owner', name: 'Olive Owner', org: 'a' },
    { key: 'member_a', email: memberA.email, password: memberA.password, role: 'team_lead', name: 'Mika Member', org: 'a' },
    { key: 'viewer_a', email: viewerA.email, password: viewerA.password, role: 'viewer', name: 'Vic Viewer', org: 'a' },
    { key: 'dual_member', email: dual.email, password: dual.password, role: 'admin', name: 'Dana Dual', org: 'a', extra: [{ org: 'b', role: 'viewer' }] },
    { key: 'member_b', email: memberB.email, password: memberB.password, role: 'developer', name: 'Bo Member', org: 'b' },
    { key: 'revoked_demoted', email: revoked.email, password: revoked.password, role: 'viewer', name: 'Rae Demoted', org: 'a' },
  ]
  const supportSeeds: PersonaSeed[] = [
    { key: 'support_lead', email: `lead@${slugA}.example`, password: `rb_fake_${slugA}_lead`, role: 'team_lead', name: 'Lee Lead', org: 'a' },
    { key: 'support_admin_b', email: `admin@${slugB}.example`, password: `rb_fake_${slugB}_admin`, role: 'admin', name: 'Sam Site', org: 'b' },
    { key: 'support_auditor', email: `audit@${slugA}.example`, password: `rb_fake_${slugA}_audit`, role: 'viewer', name: 'Ada Audit', org: 'a' },
  ]

  const orgOf = (which: 'a' | 'b'): SeedOrg => (which === 'a' ? orgA : orgB)
  let userIdx = 100
  for (const p of [...personaSeeds, ...supportSeeds]) {
    userIdx += 1
    const primary = orgOf(p.org)
    const ext = ids.encode('user', userIdx)
    const persona = p.key.startsWith('support_') ? null : p.key
    db.run(
      'INSERT INTO users (external_id,primary_org,email,password_hash,role,persona,name,status) VALUES (?,?,?,?,?,?,?,?)',
      [ext, primary.slug, p.email, hashPassword(p.password, salt), p.role, persona, p.name, 'active'],
    )
    db.run(
      'INSERT INTO memberships (user_ext_id,org_slug,role,permissions,invited_by) VALUES (?,?,?,?,?)',
      [ext, primary.slug, p.role, JSON.stringify(permissionsForRole(p.role)), 'seed'],
    )
    for (const extra of p.extra ?? []) {
      const eo = orgOf(extra.org)
      db.run(
        'INSERT INTO memberships (user_ext_id,org_slug,role,permissions,invited_by) VALUES (?,?,?,?,?)',
        [ext, eo.slug, extra.role, JSON.stringify(permissionsForRole(extra.role)), 'seed'],
      )
    }
    if (p.key === 'revoked_demoted') {
      db.run('INSERT INTO role_grants (org_slug,user_ext_id,role,source,granted_by,active) VALUES (?,?,?,?,?,?)',
        [orgA.slug, ext, 'admin', 'invite', 'seed', 0])
      db.run('INSERT INTO audit_log (org_slug,actor,action,target,detail,created_at) VALUES (?,?,?,?,?,?)',
        [orgA.slug, 'system', 'role.demote', ext, 'admin -> viewer after access review', startTs - 86_400_000])
    }
  }

  const teams: Array<{ org: SeedOrg; name: string; role: string }> = [
    { org: orgA, name: 'platform', role: 'team_lead' },
    { org: orgB, name: 'release', role: 'developer' },
  ]
  let teamIdx = 0
  for (const t of teams) {
    teamIdx += 1
    const ext = ids.encode('team', teamIdx)
    db.run('INSERT INTO teams (external_id,org_slug,name,role_template) VALUES (?,?,?,?)',
      [ext, t.org.slug, t.name, t.role])
    const owner = db.get<{ external_id: string }>(
      "SELECT external_id FROM users WHERE primary_org = ? AND role IN ('owner','admin') ORDER BY id LIMIT 1",
      [t.org.slug])
    if (owner) {
      db.run('INSERT INTO team_members (team_ext_id,org_slug,user_ext_id,role) VALUES (?,?,?,?)',
        [ext, t.org.slug, owner.external_id, t.role])
    }
  }

  // Tokens: an org-scoped CI token, a per-persona PAT, and one already-revoked credential.
  let tokenIdx = 0
  const tokenOwners = db.all<{ external_id: string; persona: string | null; primary_org: string }>(
    'SELECT external_id, persona, primary_org FROM users ORDER BY id')
  for (const org of [orgA, orgB]) {
    tokenIdx += 1
    const token = canaries.secretToken(org.slug, 'ci')
    db.run(
      'INSERT INTO tokens (external_id,org_slug,user_ext_id,name,secret_hash,scopes,env_scope,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?)',
      [ids.encode('token', tokenIdx), org.slug, tokenOwners.find((u) => u.primary_org === org.slug)?.external_id ?? '',
        'CI runner', createHash('sha256').update(token).digest('hex'), 'build:run,artifact:read', 'ci',
        startTs - 3600_000, startTs + 90 * 86_400_000],
    )
  }
  for (const persona of ['owner_a', 'member_a', 'viewer_a', 'dual_member', 'member_b', 'revoked_demoted']) {
    const owner = tokenOwners.find((u) => u.persona === persona)
    if (!owner) continue
    tokenIdx += 1
    const org = owner.primary_org
    const token = canaries.secretToken(`${org}-${persona}`, 'pat')
    const ext = ids.encode('token', tokenIdx)
    const isRevoked = persona === 'revoked_demoted'
    db.run(
      'INSERT INTO tokens (external_id,org_slug,user_ext_id,name,secret_hash,scopes,env_scope,created_at,expires_at,revoked_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
      [ext, org, owner.external_id, `${persona} cli`, createHash('sha256').update(token).digest('hex'),
        'build:run,artifact:read,secret:read', 'dev', startTs - 7200_000, startTs + 30 * 86_400_000,
        isRevoked ? startTs - 1800_000 : null],
    )
    if (isRevoked) {
      db.run('INSERT INTO token_revocations (org_slug,token_ext_id,reason,revoked_at) VALUES (?,?,?,?)',
        [org, ext, 'access_review', startTs - 1800_000])
    }
  }

  for (const org of [orgA, orgB]) {
    const user = tokenOwners.find((u) => u.primary_org === org.slug && u.persona)
    db.run('INSERT INTO sso_identities (external_id,issuer,tid,email,user_ext_id,org_slug,state) VALUES (?,?,?,?,?,?,?)',
      [ids.encode('identity', org.code === 'org_a' ? 1 : 2), `${org.ssoTenant}.idp.example`, org.ssoTenant,
        user ? db.get<{ email: string }>('SELECT email FROM users WHERE external_id = ?', [user.external_id])?.email ?? '' : '',
        user?.external_id ?? '', org.slug, 'linked'])
    db.run('INSERT INTO invites (external_id,org_slug,email,role,state,token) VALUES (?,?,?,?,?,?)',
      [ids.encode('invite', org.code === 'org_a' ? 1 : 2), org.slug, `newhire@${org.slug}.example`, 'developer',
        'pending', `rb_fake_inv_${rng.hex(8)}`])
    db.run('INSERT INTO audit_log (org_slug,actor,action,target,detail,created_at) VALUES (?,?,?,?,?,?)',
      [org.slug, 'system', 'workspace.seed', org.slug, `provisioned ${org.name}`, startTs - 7 * 86_400_000])
  }
  // The attacker org's IdP also asserts the victim org's tenant id (a realistic shared IdP); a
  // correct callback compares the assertion tid with the requested org's configured tenant.
  db.run('INSERT INTO sso_identities (external_id,issuer,tid,email,user_ext_id,org_slug,state) VALUES (?,?,?,?,?,?,?)',
    [ids.encode('identity', 3), `${orgA.ssoTenant}.idp.example`, orgA.ssoTenant, ownerA.email,
      tokenOwners.find((u) => u.persona === 'owner_a')?.external_id ?? '', orgA.slug, 'linked'])

  const content = seedContent(db, { ids, canaries, rng, startTs, signingSalt }, { a: orgA, b: orgB })

  return {
    files: content.files,
    orgs: { a: orgA, b: orgB },
    signingSalt,
    idpSecret,
    startTs,
  }
}
