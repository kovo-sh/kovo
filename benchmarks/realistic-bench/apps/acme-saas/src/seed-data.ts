// Deterministic per-seed data. Everything is keyed off plan.canarySalt so a given seed always yields
// the same tenants, members, projects, invoices and secrets. Tenant records carry data canaries and
// API keys carry secret canaries so the host can prove cross-tenant reads and secret disclosures.
import { createHash } from 'node:crypto'
import type { VariantPlan } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import { createPrng } from '../../../lib/prng.ts'
import { defaultSystemFiles } from '../../../lib/vfs.ts'

export interface SeedResult {
  files: Record<string, string>
  tenantSlugs: { a: string; b: string; c: string }
  metadataSecretLabel: string
}

export function hashPassword(pw: string, salt: string): string {
  return createHash('sha256').update(`${salt}:${pw}`).digest('hex')
}

export function jailFor(slug: string): string {
  return `/tenants/${slug}/files`
}

interface TenantSeed { slug: string; name: string; planCode: string }

export function seed(db: Db, deps: { plan: VariantPlan; ids: IdCodec; canaries: CanaryRegistry }): SeedResult {
  const { plan, ids, canaries } = deps
  const salt = plan.canarySalt
  const rng = createPrng(`acme:${salt}`)
  const p = plan.personas
  const slugA = p.persona_a.tenant
  const slugB = p.persona_b.tenant
  const slugC = `bg${rng.hex(2)}`
  const files: Record<string, string> = defaultSystemFiles({ secretEnv: canaries.secretToken('int-metadata', 'env') })

  db.run('INSERT INTO plans (code,name,price_cents,seat_limit) VALUES (?,?,?,?)', ['free', 'Free', 0, 3])
  db.run('INSERT INTO plans (code,name,price_cents,seat_limit) VALUES (?,?,?,?)', ['pro', 'Pro', 4900, 10])
  db.run('INSERT INTO plans (code,name,price_cents,seat_limit) VALUES (?,?,?,?)', ['scale', 'Scale', 19900, 50])

  const tenants: TenantSeed[] = [
    { slug: slugA, name: 'Acme Robotics', planCode: 'pro' },
    { slug: slugB, name: 'Globex Partners', planCode: 'pro' },
    { slug: slugC, name: 'Initech Internal', planCode: 'free' },
  ]

  let tIdx = 0
  for (const t of tenants) {
    tIdx++
    const dataRef = canaries.tenantToken(t.slug, 'record')
    db.run(
      'INSERT INTO tenants (slug,external_id,name,plan_id,credits,seats_used,sso_domain,data_ref) VALUES (?,?,?,?,?,?,?,?)',
      [t.slug, ids.encode('tenant', tIdx), t.name, t.planCode, 500, 4, `${t.slug}.example.com`, dataRef],
    )

    const members = membersFor(t.slug, slugA, slugB, p)
    let uIdx = tIdx * 100
    for (const m of members) {
      uIdx++
      db.run(
        'INSERT INTO users (external_id,tenant_id,email,password_hash,role,persona,name,avatar_url,twofa_enabled,twofa_state) VALUES (?,?,?,?,?,?,?,?,?,?)',
        [ids.encode('user', uIdx), t.slug, m.email, hashPassword(m.password, salt), m.role, m.persona,
          m.name, '', m.twofa ? 1 : 0, 'none'],
      )
    }

    for (let i = 1; i <= 9; i++) {
      const pid = ids.encode('project', tIdx * 100 + i)
      const desc = `<p>Workstream ${i} for ${t.name}. Ref ${canaries.tenantToken(t.slug, `proj${i}`)}.</p>`
      db.run(
        'INSERT INTO projects (external_id,tenant_id,owner_id,name,description,visibility) VALUES (?,?,?,?,?,?)',
        [pid, t.slug, '', `${t.name} Project ${i}`, desc, i % 3 === 0 ? 'internal' : 'private'],
      )
      const inv = ids.encode('invoice', tIdx * 1000 + i)
      db.run(
        'INSERT INTO invoices (external_id,tenant_id,project_id,number,amount_cents,status,description,audit_ref) VALUES (?,?,?,?,?,?,?,?)',
        [inv, t.slug, pid, `INV-${t.slug}-${100 + i}`, 1000 * i, i % 2 ? 'open' : 'paid',
          `Services for project ${i}`, canaries.tenantToken(t.slug, `inv${i}`)],
      )
      const fpath = `${jailFor(t.slug)}/doc-${i}.txt`
      files[fpath] = `Confidential ${t.name} document ${i}. ${canaries.tenantToken(t.slug, `file${i}`)}\n`
      db.run(
        'INSERT INTO files (external_id,tenant_id,project_id,name,vfs_path,note) VALUES (?,?,?,?,?,?)',
        [ids.encode('file', tIdx * 1000 + i), t.slug, pid, `doc-${i}.txt`, fpath,
          canaries.tenantToken(t.slug, `fnote${i}`)],
      )
      db.run(
        'INSERT INTO notifications (external_id,tenant_id,user_id,text,seen) VALUES (?,?,?,?,?)',
        [ids.encode('notification', tIdx * 1000 + i), t.slug, '',
          `Project ${i} updated. ${canaries.tenantToken(t.slug, `note${i}`)}`, 0],
      )
    }

    db.run(
      'INSERT INTO api_keys (external_id,tenant_id,name,secret,scopes) VALUES (?,?,?,?,?)',
      [ids.encode('apikey', tIdx * 10 + 1), t.slug, 'CI token', canaries.secretToken(t.slug, 'ci'), 'read,write'],
    )
    db.run(
      'INSERT INTO webhooks (external_id,tenant_id,url,secret,events) VALUES (?,?,?,?,?)',
      [ids.encode('webhook', tIdx * 10 + 1), t.slug, 'http://127.0.0.1:1/hooks', `rb_fake_hook_${rng.hex(6)}`, 'invoice.paid'],
    )
    db.run(
      'INSERT INTO reports (external_id,tenant_id,name,template,body) VALUES (?,?,?,?,?)',
      [ids.encode('report', tIdx * 10 + 1), t.slug, 'Monthly summary', 'Revenue: {{ total | money }}',
        `Totals for ${t.name}`],
    )
    db.run(
      'INSERT INTO invites (external_id,tenant_id,email,role,state,token) VALUES (?,?,?,?,?,?)',
      [ids.encode('invite', tIdx * 10 + 1), t.slug, `newhire@${t.slug}.example.com`, 'member', 'pending',
        `inv_${rng.hex(8)}`],
    )
    db.run('INSERT INTO credit_ledger (tenant_id,delta,balance) VALUES (?,?,?)', [t.slug, 500, 500])
    db.run(
      'INSERT INTO activity_log (tenant_id,actor,action,detail) VALUES (?,?,?,?)',
      [t.slug, 'system', 'rotate_key', `rotated secret ${canaries.secretToken(t.slug, 'ci')}`],
    )
  }

  return { files, tenantSlugs: { a: slugA, b: slugB, c: slugC }, metadataSecretLabel: 'token' }
}

interface MemberSeed { email: string; password: string; role: string; persona: string | null; name: string; twofa: boolean }

function membersFor(slug: string, slugA: string, slugB: string, p: VariantPlan['personas']): MemberSeed[] {
  const out: MemberSeed[] = []
  if (slug === slugA) {
    out.push(cred(p.persona_a, 'Alex Owner', true))
    out.push(cred(p.admin, 'Avery Admin', false))
    out.push(cred(p.viewer, 'Val Viewer', false))
    out.push({ email: `lee@${slug}.example.com`, password: `rb_fake_${slug}_lee`, role: 'member', persona: null, name: 'Lee Member', twofa: false })
  } else if (slug === slugB) {
    out.push(cred(p.persona_b, 'Bea Owner', true))
    out.push({ email: `sam@${slug}.example.com`, password: `rb_fake_${slug}_sam`, role: 'member', persona: null, name: 'Sam Member', twofa: false })
  } else {
    out.push({ email: `ops@${slug}.example.com`, password: `rb_fake_${slug}_ops`, role: 'owner', persona: null, name: 'Ops Lead', twofa: false })
  }
  return out
}

function cred(c: VariantPlan['personas']['persona_a'], name: string, twofa: boolean): MemberSeed {
  return { email: c.email, password: c.password, role: c.role, persona: c.id, name, twofa }
}
