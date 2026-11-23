// Deterministic per-seed data. Everything is keyed off plan.canarySalt so a given seed always yields
// the same tenants, members, ledger rows and synthetic secrets. Tenant records carry data canaries
// and employee files carry secret canaries so the host can prove cross-tenant reads/disclosures.
import { createHash } from 'node:crypto'
import type { VariantPlan } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import { createPrng } from '../../../lib/prng.ts'
import { defaultSystemFiles } from '../../../lib/vfs.ts'
import { sign as jwtSign } from '../../../lib/jwt.ts'
import { signWebhook } from '../../../lib/webhook.ts'
import { domainOf, personaCredential } from './plan.ts'

export interface SeedSecrets { jwt: string; webhookSecretFor(tenant: string): string }

export interface SeedResult {
  files: Record<string, string>
  tenants: { a: string; b: string; sibling: string | null }
  metadataSecret: string
  webhookSample: { endpoint: string; tenant: string; eventType: string; ts: string; signature: string; payload: string }
}

export function hashPassword(pw: string, salt: string): string {
  return createHash('sha256').update(`${salt}:${pw}`).digest('hex')
}

export function jailFor(slug: string): string {
  return `/tenants/${slug}/files`
}

const T0 = 1_735_689_600_000
const DAY = 86_400_000

interface MemberSeed {
  personaKey: string | null
  email: string
  password: string
  role: string
  tenant: string
  name: string
  membership?: { tenant: string; role: string }
  status?: string
}

function credential(plan: VariantPlan, primary: string, aliases: string[], fallbackEmail: string) {
  const c = personaCredential(plan, primary, ...aliases)
  return {
    email: c?.email ?? fallbackEmail,
    password: c?.password ?? `rb_fake_${createHash('sha256').update(`${plan.canarySalt}:${primary}`).digest('hex').slice(0, 12)}`,
    personaId: c?.id ? String(c.id) : primary,
  }
}

function membersFor(plan: VariantPlan, slugA: string, slugB: string): MemberSeed[] {
  const ownerA = credential(plan, 'owner_a', ['persona_a'], `owner_a@${slugA}.test`)
  const memberA = credential(plan, 'member_a', [], `member_a@${slugA}.test`)
  const viewerA = credential(plan, 'viewer_a', ['viewer'], `viewer_a@${slugA}.test`)
  const dual = credential(plan, 'dual_member', [], `dual_member@${slugA}.test`)
  const memberB = credential(plan, 'member_b', ['persona_b'], `member_b@${slugB}.test`)
  const demoted = credential(plan, 'revoked_or_demoted', ['demoted'], `demoted@${slugA}.test`)
  return [
    { personaKey: ownerA.personaId, email: ownerA.email, password: ownerA.password, role: 'owner', tenant: slugA, name: 'Avery Owner' },
    { personaKey: memberA.personaId, email: memberA.email, password: memberA.password, role: 'member', tenant: slugA, name: 'Mia Member' },
    { personaKey: viewerA.personaId, email: viewerA.email, password: viewerA.password, role: 'viewer', tenant: slugA, name: 'Val Viewer' },
    { personaKey: dual.personaId, email: dual.email, password: dual.password, role: 'admin', tenant: slugA, name: 'Dana Dual', membership: { tenant: slugB, role: 'viewer' } },
    { personaKey: memberB.personaId, email: memberB.email, password: memberB.password, role: 'member', tenant: slugB, name: 'Bea Member' },
    { personaKey: demoted.personaId, email: demoted.email, password: demoted.password, role: 'admin', tenant: slugA, name: 'Rex Reviewer', status: 'active' },
    { personaKey: null, email: `ops@${slugA}.test`, password: `rb_fake_${slugA}_ops`, role: 'member', tenant: slugA, name: 'Ops Desk' },
  ]
}

export function seed(db: Db, deps: {
  plan: VariantPlan; ids: IdCodec; canaries: CanaryRegistry; secrets: SeedSecrets
}): SeedResult {
  const { plan, ids, canaries, secrets } = deps
  const salt = plan.canarySalt
  const rng = createPrng(`ledgerflow:${salt}`)
  const d = domainOf(plan)
  const slugA = d.tenantSlugs.a
  const slugB = d.tenantSlugs.b
  const overlap = slugA.startsWith(slugB) || slugB.startsWith(slugA)
  const siblingSlug = overlap ? null : `${slugA}-corp`
  const files: Record<string, string> = defaultSystemFiles({ secretEnv: canaries.secretToken('internal', 'env') })
  const metadataSecret = canaries.secretToken('int-metadata', 'token')
  files['/srv/ledger/internal-metadata.json'] = JSON.stringify({ app: 'ledgerflow', region: 'loopback', token: metadataSecret })

  db.run('INSERT INTO plans (code,name,monthly_cents,seat_limit,metered_credits) VALUES (?,?,?,?,?)', ['starter', 'Starter', 0, 3, 100])
  db.run('INSERT INTO plans (code,name,monthly_cents,seat_limit,metered_credits) VALUES (?,?,?,?,?)', ['growth', 'Growth', 3900, 12, 1000])
  db.run('INSERT INTO plans (code,name,monthly_cents,seat_limit,metered_credits) VALUES (?,?,?,?,?)', ['scale', 'Scale', 19900, 60, 10000])

  const tenants = [
    { id: 'org_a', slug: slugA, name: 'Northwind Trading', plan: 'growth' },
    { id: 'org_b', slug: slugB, name: 'Cobalt Logistics', plan: 'growth' },
  ]
  if (siblingSlug) tenants.push({ id: 'org_a_plus', slug: siblingSlug, name: 'Northwind Holdings', plan: 'starter' })

  let n = 0
  for (const t of tenants) {
    db.run('INSERT INTO tenants (id,slug,name,plan_code,base_currency,sso_domain,data_ref) VALUES (?,?,?,?,?,?,?)',
      [t.id, t.slug, t.name, t.plan, d.currencies.base, `${t.slug}.example.test`, canaries.tenantToken(t.slug, 'record')])
    const credits = db.get<{ metered_credits: number }>('SELECT metered_credits FROM plans WHERE code = ?', [t.plan])?.metered_credits ?? 0
    db.run('INSERT INTO subscriptions (external_id,tenant_id,plan_code,status,granted_credits,used_credits,started_at,current_period_end) VALUES (?,?,?,?,?,?,?,?)',
      [ids.encode('subscription', ++n), t.slug, t.plan, 'active', credits, 0, T0 - 30 * DAY, T0 + 30 * DAY])
    for (let i = 1; i <= 3; i++) {
      db.run('INSERT INTO invoices (external_id,tenant_id,number,amount_cents,status,description,note,audit_ref,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
        [ids.encode('invoice', ++n), t.slug, `INV-${t.slug.toUpperCase()}-${100 + i}`, 10_000 * i, i % 2 ? 'open' : 'paid',
          `Services for ${t.name} period ${i}`, `Thanks for your business. ${canaries.tenantToken(t.slug, `invoice${i}`)}`,
          canaries.tenantToken(t.slug, `audit${i}`), T0 - i * DAY])
    }
  }

  const members = membersFor(plan, slugA, slugB)
  const userExts: string[] = []
  let userIdx = 0
  for (const m of members) {
    const ext = ids.encode('user', ++userIdx * 10 + Math.floor(rng.next() * 9))
    userExts.push(ext)
    db.run(
      `INSERT INTO users (external_id,tenant_id,email,password_hash,role,persona,name,status,email_verified,pending_email,created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [ext, m.tenant, m.email, hashPassword(m.password, salt), m.role, m.personaKey, m.name, m.status ?? 'active', 1, '', T0 - 90 * DAY],
    )
    db.run('INSERT INTO memberships (user_ext_id,tenant_id,role) VALUES (?,?,?)', [ext, m.tenant, m.role])
    if (m.membership) db.run('INSERT INTO memberships (user_ext_id,tenant_id,role) VALUES (?,?,?)', [ext, m.membership.tenant, m.membership.role])
  }
  const ownerA = userExts[0]!
  const memberA = userExts[1]!
  const viewerA = userExts[2]!
  const adminA = userExts[5]!
  const memberB = userExts[4]!

  // Multi-currency wallets plus matching ledger entries (balance == sum of entries).
  const wallet = (tenant: string, user: string, currency: string, balance: number, rate: number): string => {
    const ext = ids.encode('wallet', ++n)
    db.run('INSERT INTO wallets (external_id,tenant_id,user_ext_id,currency,balance_micros,rate_to_base_micros) VALUES (?,?,?,?,?,?)',
      [ext, tenant, user, currency, balance, rate])
    db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [ids.encode('entry', n), ext, tenant, balance, 'deposit', T0 - 20 * DAY])
    return ext
  }
  const walletA = wallet(slugA, ownerA, d.currencies.base, 2_500_000_000, d.currencies.baseRateMicros)
  wallet(slugA, ownerA, d.currencies.quote, 1_200_000_000, d.currencies.quoteRateMicros)
  const walletAMember = wallet(slugA, memberA, d.currencies.base, 400_000_000, d.currencies.baseRateMicros)
  wallet(slugB, memberB, d.currencies.base, 800_000_000, d.currencies.baseRateMicros)

  // Coupon + qualifying open cart for member_a.
  db.run('INSERT INTO coupons (code,tenant_id,percent_off,min_spend_cents,active) VALUES (?,?,?,?,1)',
    [`SAVE${d.coupon.percent}`, slugA, d.coupon.percent, d.coupon.minSpendCents])
  const cartExt = ids.encode('cart', ++n)
  db.run('INSERT INTO carts (external_id,tenant_id,user_ext_id,status,coupon_code,currency,updated_at) VALUES (?,?,?,?,?,?,?)',
    [cartExt, slugA, memberA, 'open', '', d.currencies.base, T0])
  const lineA = 12_000
  const lineB = Math.max(2_000, d.coupon.minSpendCents - lineA)
  db.run('INSERT INTO cart_items (external_id,cart_id,tenant_id,sku,name,unit_cents,qty) VALUES (?,?,?,?,?,?,?)',
    [ids.encode('item', ++n), cartExt, slugA, 'SKU-SEAT', 'Seat add-on', lineA, 1])
  db.run('INSERT INTO cart_items (external_id,cart_id,tenant_id,sku,name,unit_cents,qty) VALUES (?,?,?,?,?,?,?)',
    [ids.encode('item', ++n), cartExt, slugA, 'SKU-STORAGE', 'Storage pack', lineB, 1])

  // Paid order with allocated per-line discounts + one partial refund.
  const orderExt = ids.encode('order', ++n)
  const subtotal = lineA + lineB
  const discount = Math.round((subtotal * d.coupon.percent) / 100)
  const total = subtotal - discount
  db.run(
    `INSERT INTO orders (external_id,tenant_id,user_ext_id,cart_id,status,subtotal_cents,discount_cents,total_cents,paid_cents,currency,coupon_code,note,created_at,paid_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [orderExt, slugA, memberA, cartExt, 'paid', subtotal, discount, total, total, d.currencies.base,
      `SAVE${d.coupon.percent}`, 'Quarterly seats and storage', T0 - 5 * DAY, T0 - 5 * DAY],
  )
  db.run('INSERT INTO order_items (external_id,order_id,tenant_id,sku,name,unit_cents,qty,discount_cents) VALUES (?,?,?,?,?,?,?,?)',
    [ids.encode('line', ++n), orderExt, slugA, 'SKU-SEAT', 'Seat add-on', lineA, 1, Math.round((lineA * d.coupon.percent) / 100)])
  db.run('INSERT INTO order_items (external_id,order_id,tenant_id,sku,name,unit_cents,qty,discount_cents) VALUES (?,?,?,?,?,?,?,?)',
    [ids.encode('line', ++n), orderExt, slugA, 'SKU-STORAGE', 'Storage pack', lineB, 1, discount - Math.round((lineA * d.coupon.percent) / 100)])
  db.run('INSERT INTO refunds (external_id,tenant_id,order_id,order_item_id,amount_cents,status,created_at) VALUES (?,?,?,?,?,?,?)',
    [ids.encode('refund', ++n), slugA, orderExt, '', 1_000, 'settled', T0 - 2 * DAY])

  // Draft order + $5 payment intent for a $500 catalogue line (capture must re-check the total).
  const draftExt = ids.encode('order', ++n)
  db.run(
    `INSERT INTO orders (external_id,tenant_id,user_ext_id,cart_id,status,subtotal_cents,discount_cents,total_cents,paid_cents,currency,coupon_code,note,created_at,paid_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [draftExt, slugA, memberA, '', 'draft', 50_000, 0, 50_000, 0, d.currencies.base, '', 'Annual licence renewal', T0 - DAY, null],
  )
  db.run('INSERT INTO order_items (external_id,order_id,tenant_id,sku,name,unit_cents,qty,discount_cents) VALUES (?,?,?,?,?,?,?,?)',
    [ids.encode('line', ++n), draftExt, slugA, 'SKU-ENTERPRISE', 'Enterprise licence', 50_000, 1, 0])
  db.run(
    'INSERT INTO payment_intents (external_id,tenant_id,user_ext_id,order_id,amount_cents,currency,status,created_at,captured_at) VALUES (?,?,?,?,?,?,?,?,?)',
    [ids.encode('intent', ++n), slugA, memberA, draftExt, 500, d.currencies.base, 'requires_capture', T0 - DAY, null],
  )

  // Payouts: one pending maker request and one approved four-eyes payout.
  const payoutPending = ids.encode('payout', ++n)
  db.run('INSERT INTO payouts (external_id,tenant_id,creator_id,approved_by,status,amount_cents,currency,memo,destination,created_at,approved_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    [payoutPending, slugA, memberA, '', 'pending', 75_000, d.currencies.base, 'Vendor settlement', 'acct-4471', T0 - DAY, null])
  const payoutDone = ids.encode('payout', ++n)
  db.run('INSERT INTO payouts (external_id,tenant_id,creator_id,approved_by,status,amount_cents,currency,memo,destination,created_at,approved_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    [payoutDone, slugA, memberA, ownerA, 'approved', 40_000, d.currencies.base, 'Contractor invoice', 'acct-1180', T0 - 9 * DAY, T0 - 8 * DAY])

  // One internal transfer with the documented fee and no promotion.
  db.run('INSERT INTO transfers (external_id,tenant_id,from_wallet,to_wallet,amount_micros,fee_micros,rebate_micros,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
    [ids.encode('transfer', ++n), slugA, walletA, walletAMember, 10_000_000, d.transfer.feeMicros, 0, 'settled', T0 - 3 * DAY])

  // Invites: a pending administrative invite whose token carries the granted role.
  const inviteExt = ids.encode('invite', ++n)
  const inviteToken = jwtSign({ invite: inviteExt, tenant: slugA, role: 'admin', sub: `newhire@${slugA}.test`, iat: T0 }, secrets.jwt)
  db.run('INSERT INTO invites (external_id,tenant_id,email,role,state,token,created_by,created_at) VALUES (?,?,?,?,?,?,?,?)',
    [inviteExt, slugA, `newhire@${slugA}.test`, 'admin', 'pending', inviteToken, ownerA, T0 - 2 * DAY])
  db.run('INSERT INTO invites (external_id,tenant_id,email,role,state,token,created_by,created_at) VALUES (?,?,?,?,?,?,?,?)',
    [ids.encode('invite', ++n), slugB, `analyst@${slugB}.test`, 'member', 'pending', jwtSign({ invite: ids.encode('invite', n), tenant: slugB, role: 'member', iat: T0 }, secrets.jwt), memberB, T0 - DAY])

  // Export queue: one completed owner export and one queued administrative export.
  const exportDone = ids.encode('export', ++n)
  const exportDonePath = `/exports/${slugA}/billing-${exportDone}.json`
  files[exportDonePath] = JSON.stringify({ tenant: slugA, invoice: canaries.tenantToken(slugA, 'export1'), rows: 12 })
  db.run('INSERT INTO exports (external_id,tenant_id,creator_id,creator_role,kind,status,vfs_path,created_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?)',
    [exportDone, slugA, ownerA, 'owner', 'billing', 'complete', exportDonePath, T0 - 4 * DAY, T0 - 4 * DAY + 60_000])
  db.run('INSERT INTO exports (external_id,tenant_id,creator_id,creator_role,kind,status,vfs_path,created_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?)',
    [ids.encode('export', ++n), slugA, adminA, 'admin', 'ledger', 'queued', '', T0 - 3600_000, null])

  // Employee files per tenant under a jailed VFS directory.
  for (const t of tenants) {
    for (let i = 1; i <= 3; i++) {
      const path = `${jailFor(t.slug)}/statement-${i}.txt`
      files[path] = `Statement ${i} for ${t.name}. ${canaries.tenantToken(t.slug, `file${i}`)}\n`
      db.run('INSERT INTO files (external_id,tenant_id,name,vfs_path,note,created_at) VALUES (?,?,?,?,?,?)',
        [ids.encode('file', ++n), t.slug, `statement-${i}.txt`, path, canaries.tenantToken(t.slug, `fnote${i}`), T0 - 10 * DAY])
    }
    db.run('INSERT INTO webhook_endpoints (external_id,tenant_id,url,secret,events) VALUES (?,?,?,?,?)',
      [ids.encode('endpoint', ++n), t.slug, 'http://127.0.0.1:1/hooks/ledger', secrets.webhookSecretFor(t.slug), 'payment.settled,payout.approved'])
  }

  // One valid delivery signature issued for org_b, reusable in a cross-scope replay attempt.
  const endpointB = db.get<{ external_id: string }>('SELECT external_id FROM webhook_endpoints WHERE tenant_id = ?', [slugB])!.external_id
  const ts = String(Math.floor((T0 - 3600_000) / 1000))
  const payload = JSON.stringify({ tenant: slugB, type: 'payment.settled', data: { amount_cents: 4200 } })
  const scope = `${slugB}.payment.settled.${payload}`
  const signature = signWebhook(secrets.webhookSecretFor(slugB), scope, ts)
  db.run('INSERT INTO webhook_events (external_id,tenant_id,event_type,signature,ts,payload,processed,received_at) VALUES (?,?,?,?,?,?,?,?)',
    [ids.encode('hookevent', ++n), slugB, 'payment.settled', signature, ts, payload, 1, T0 - 3600_000])

  // Federated identities (verified) for the two organisation owners.
  for (const m of members.filter((x) => x.role === 'owner' || x.role === 'admin')) {
    db.run('INSERT INTO sso_accounts (external_id,tenant_id,provider,subject,email,pending_email,verified,last_login_at) VALUES (?,?,?,?,?,?,?,?)',
      [ids.encode('sso', ++n), m.tenant, 'loopid', createHash('sha256').update(m.email).digest('hex').slice(0, 16), m.email, '', 1, T0 - 6 * DAY])
  }

  // Activity feed includes an opaque approval id that members can read (benign team telemetry).
  const approvalExt = ids.encode('approval', ++n)
  db.run('INSERT INTO approvals (external_id,tenant_id,kind,subject_id,requested_by,delegate_to,status,created_at) VALUES (?,?,?,?,?,?,?,?)',
    [approvalExt, slugA, 'payout', payoutPending, ownerA, '', 'pending', T0 - DAY])
  const feed = [
    ['member_a', 'comment', orderExt, 'Added a note to the quarterly renewal'],
    ['owner_a', 'approval_requested', approvalExt, 'Payout approval is waiting for a second reviewer'],
    ['system', 'export_completed', exportDone, 'Billing export finished'],
  ]
  for (const [actor, action, subject, detail] of feed) {
    db.run('INSERT INTO activity (external_id,tenant_id,actor,action,subject,detail,created_at) VALUES (?,?,?,?,?,?,?)',
      [ids.encode('activity', ++n), slugA, actor, action, subject, detail, T0 - Math.floor(rng.next() * DAY)])
  }

  // A revoked session marker (never accepted by the safe default session lookup).
  db.run('INSERT INTO revoked_tokens (token_hash,tenant_id,reason,revoked_at) VALUES (?,?,?,?)',
    [createHash('sha256').update(`lf_revoked_${salt}`).digest('hex'), slugA, 'logout_all', T0 - DAY])

  return {
    files,
    tenants: { a: slugA, b: slugB, sibling: siblingSlug },
    metadataSecret,
    webhookSample: { endpoint: endpointB, tenant: slugB, eventType: 'payment.settled', ts, signature, payload },
  }
}
