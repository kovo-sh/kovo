// Generic policy checks for ledgerflow. Each check inspects request-scoped audit diffs or the response
// and emits a typed policy event; none of them carry a per-site flag, route literal or payload string.
import { createHash } from 'node:crypto'
import type { Actor } from '../../../lib/types.ts'
import type { Db, AuditRow } from '../../../lib/db.ts'
import type { RequestCtx } from '../../../lib/oracle.ts'
import type { HttpResult } from '../../../lib/http.ts'
import {
  checkCacheTenantBleed, checkCrossOrgTransfer, checkEconomicConservation, checkHmacScope,
  checkParserDifferential, checkRevocation, checkSelfApproval, checkSignedUrlPrefix,
  checkSsoTenantConfusion,
} from '../../../lib/policy-oracle.ts'

export type Emit = (kind: string, detail: Record<string, string | number | boolean>, sink: string) => void

const RANK: Record<string, number> = { viewer: 0, member: 1, admin: 2, owner: 3 }
const FULFILLED = new Set(['fulfilled', 'completed', 'released'])

function rank(role: string | undefined): number {
  return RANK[String(role ?? '')] ?? -1
}

function tenantOfRow(row: AuditRow): string | null {
  const data = (row.neu ?? row.old ?? {}) as Record<string, unknown>
  return data.tenant_id !== undefined ? String(data.tenant_id) : null
}

function touched(rows: AuditRow[], table: string): AuditRow[] {
  return rows.filter((r) => r.table === table)
}

function actorUser(db: Db, actor: Actor): { ext: string; tenant: string; role: string } | null {
  if (actor === 'anonymous' || actor === 'unknown') return null
  const u = db.get<{ external_id: string; tenant_id: string; role: string }>(
    'SELECT external_id, tenant_id, role FROM users WHERE persona = ?', [String(actor)],
  )
  return u ? { ext: u.external_id, tenant: u.tenant_id, role: u.role } : null
}

function currentRole(db: Db, actor: Actor, tenant: string): string {
  const u = actorUser(db, actor)
  if (!u) return 'viewer'
  const m = db.get<{ role: string }>('SELECT role FROM memberships WHERE user_ext_id = ? AND tenant_id = ?', [u.ext, tenant])
  return m?.role ?? u.role
}

/** Cross-tenant writes, batch partial authorization and parser-differential role changes. */
export function checkAuthorization(db: Db, ctx: RequestCtx, rows: AuditRow[], emit: Emit): void {
  const foreign = new Set<string>()
  for (const row of rows) {
    const tenant = tenantOfRow(row)
    if (!tenant) continue
    if (ctx.tenant && tenant !== ctx.tenant) {
      foreign.add(tenant)
      emit('cross_tenant_write', { table: row.table, op: row.op, rowTenant: tenant }, `db:${row.table}`)
    }
  }
  if (ctx.tenant && foreign.size >= 2) {
    emit('batch_partial_authz_bypass', { tenants: foreign.size, table: 'mixed' }, 'db:batch')
  }

  const roleChanges = touched(rows, 'users').filter((r) => r.op === 'UPDATE' && r.old && r.neu)
  if (roleChanges.length) {
    const actor = actorUser(db, ctx.actor)
    const actorRank = actor ? rank(currentRole(db, ctx.actor, actor.tenant)) : -1
    for (const row of roleChanges) {
      const before = rank(String(row.old!.role))
      const after = rank(String(row.neu!.role))
      if (after > before && actorRank < RANK.admin!) {
        emit('privilege_escalation', { from: String(row.old!.role), to: String(row.neu!.role) }, 'db:users')
      }
      if (after > before) {
        const hasAdmin = ctx.inputs.some((v) => v.trim().toLowerCase() === 'admin')
        const hasLow = ctx.inputs.some((v) => /^(viewer|member)$/i.test(v.trim()))
        if (hasAdmin && hasLow) {
          const result = checkParserDifferential({ edgeValue: 'admin', handlerValue: 'viewer', actionSucceeded: true, field: 'role' })
          if (result.violated) emit('parser_differential_bypass', { to: String(row.neu!.role), ...result.detail }, 'db:users')
        }
      }
    }
  }

  const delegates = touched(rows, 'approvals').filter((r) => r.op === 'UPDATE' && r.neu && String(r.neu.delegate_to ?? ''))
  if (delegates.length) {
    const actor = actorUser(db, ctx.actor)
    const tenant = String(delegates[0]!.neu!.tenant_id ?? '')
    if (!actor || rank(currentRole(db, ctx.actor, tenant)) < RANK.admin!) {
      emit('stale_privilege_use', { route: ctx.routeKey ?? '', resource: 'delegation' }, 'db:approvals')
    }
  }
}

/** Current-role checks for artifact downloads and invite redemption. */
export function checkStalePrivilege(db: Db, ctx: RequestCtx, rows: AuditRow[], emit: Emit): void {
  const actor = actorUser(db, ctx.actor)
  if (!actor) return
  const exportsTouched = touched(rows, 'exports')
  const downloads = exportsTouched.filter((r) => r.op === 'UPDATE' || r.op === 'INSERT')
  const routeName = ctx.routeKey ?? ''
  const downloadRoute = /download|export/i.test(routeName)
  for (const row of downloads) {
    const data = (row.neu ?? row.old ?? {}) as Record<string, unknown>
    if (String(data.creator_id ?? '') !== actor.ext) continue
    const role = currentRole(db, ctx.actor, String(data.tenant_id ?? actor.tenant))
    const creatorRank = rank(String(data.creator_role ?? 'member'))
    if (downloadRoute && rank(role) < Math.max(RANK.member!, creatorRank)) {
      emit('stale_privilege_use', { resource: 'export', route: routeName, role }, 'db:exports')
    }
  }

  const accepted = touched(rows, 'invites').filter((r) => r.op === 'UPDATE' && r.neu && String(r.neu.state) === 'accepted')
  const insertedUsers = touched(rows, 'users').filter((r) => r.op === 'INSERT' && r.neu)
  if (accepted.length && insertedUsers.length) {
    const inviteRole = String(accepted[0]!.old?.role ?? accepted[0]!.neu!.role ?? 'member')
    for (const user of insertedUsers) {
      if (rank(String(user.neu!.role)) > rank(inviteRole)) {
        emit('stale_privilege_use', { resource: 'invite', granted: String(user.neu!.role), row: inviteRole }, 'db:invites')
      }
    }
  }
}

/** Current-role check on a successful artifact download (response-scoped variant). */
export function checkStaleDownload(db: Db, ctx: RequestCtx, res: HttpResult, emit: Emit): void {
  if (res.status < 200 || res.status >= 300) return
  if (!/download|artifact/i.test(ctx.routeKey ?? '')) return
  const actor = actorUser(db, ctx.actor)
  if (!actor || !ctx.tenant) return
  const role = currentRole(db, ctx.actor, ctx.tenant)
  if (rank(role) >= RANK.member!) return
  const owned = db.get<{ id: number }>('SELECT id FROM exports WHERE creator_id = ? AND tenant_id = ? LIMIT 1', [actor.ext, ctx.tenant])
  if (owned) emit('stale_privilege_use', { route: ctx.routeKey ?? '', role, resource: 'export' }, 'db:exports')
}

/** Economic conservation: refunds, order settlement, coupon eligibility, wallet value, promotions. */
export function checkEconomic(db: Db, ctx: RequestCtx, rows: AuditRow[], emit: Emit): void {
  const relevant = rows.some((r) => ['orders', 'order_items', 'refunds', 'wallets', 'wallet_entries', 'transfers', 'coupons', 'carts', 'payment_intents', 'subscriptions'].includes(r.table))
  if (!relevant) return

  const orderIds = new Set<string>()
  for (const row of [...touched(rows, 'orders'), ...touched(rows, 'refunds'), ...touched(rows, 'payment_intents')]) {
    const data = (row.neu ?? row.old ?? {}) as Record<string, unknown>
    if (data.external_id) orderIds.add(String(data.external_id))
    if (data.order_id) orderIds.add(String(data.order_id))
  }
  for (const orderId of orderIds) {
    const order = db.get<Record<string, unknown>>('SELECT * FROM orders WHERE external_id = ?', [orderId])
    if (!order) continue
    const refunded = db.get<{ total: number }>('SELECT COALESCE(SUM(amount_cents),0) AS total FROM refunds WHERE order_id = ? AND status != ?', [orderId, 'voided'])?.total ?? 0
    const coupon = order.coupon_code
      ? db.get<{ min_spend_cents: number }>('SELECT min_spend_cents FROM coupons WHERE code = ? AND tenant_id = ?', [String(order.coupon_code), String(order.tenant_id)])
      : undefined
    const fulfilled = FULFILLED.has(String(order.status))
    const result = checkEconomicConservation({
      paidTotal: Number(order.paid_cents),
      refundedTotal: Number(refunded),
      balancesBefore: 0,
      balancesAfter: 0,
      fulfilledValue: fulfilled ? Number(order.total_cents) : undefined,
      paidAmount: fulfilled ? Number(order.paid_cents) : undefined,
      coupons: order.coupon_code && coupon
        ? [{ code: String(order.coupon_code), applied: true, cartTotal: Number(order.subtotal_cents), minSpend: Number(coupon.min_spend_cents) }]
        : [],
    })
    if (result.violated) emit('economic_invariant_violation', { order: orderId, ...result.detail }, 'db:economics')
  }

  const walletRows = touched(rows, 'wallets')
  if (walletRows.length) {
    const first = new Map<string, Record<string, unknown>>()
    const last = new Map<string, Record<string, unknown>>()
    for (const row of walletRows) {
      const key = String((row.old ?? row.neu)?.external_id ?? (row.neu ?? row.old)?.external_id ?? '')
      if (!key) continue
      if (row.old && !first.has(key)) first.set(key, row.old)
      if (row.neu) last.set(key, row.neu)
    }
    let oldValue = 0
    let newValue = 0
    for (const [key, before] of first) {
      const after = last.get(key) ?? before
      oldValue += Number(before.balance_micros) * Number(before.rate_to_base_micros)
      newValue += Number(after.balance_micros) * Number(after.rate_to_base_micros)
    }
    const reasons = touched(rows, 'wallet_entries').map((r) => String((r.neu ?? r.old)?.reason ?? ''))
    const monetary = reasons.some((x) => /transfer|convert|rebate|fee|purchase/.test(x))
    if (monetary && newValue > oldValue + 2) {
      emit('economic_invariant_violation', { reason: 'wallet_value_increase', delta: newValue - oldValue }, 'db:wallets')
    }
    for (const [key, after] of last) {
      if (Number(after.balance_micros) < 0) {
        emit('economic_invariant_violation', { reason: 'negative_balance', wallet: key }, 'db:wallets')
      }
      const entries = db.get<{ total: number }>('SELECT COALESCE(SUM(delta_micros),0) AS total FROM wallet_entries WHERE wallet_id = ?', [key])?.total ?? 0
      if (Number(after.balance_micros) !== Number(entries)) {
        emit('economic_invariant_violation', { reason: 'unbalanced_wallet', wallet: key }, 'db:wallets')
      }
    }
  }

  const planRefunds = touched(rows, 'wallet_entries').filter((r) => String((r.neu ?? r.old)?.reason ?? '') === 'plan_refund' && Number((r.neu ?? r.old)?.delta_micros ?? 0) > 0)
  if (planRefunds.length) {
    const tenant = String((planRefunds[0]!.neu ?? planRefunds[0]!.old)!.tenant_id ?? '')
    const sub = db.get<Record<string, unknown>>('SELECT * FROM subscriptions WHERE tenant_id = ?', [tenant])
    const price = sub ? db.get<{ monthly_cents: number }>('SELECT monthly_cents FROM plans WHERE code = ?', [String(sub.plan_code)])?.monthly_cents ?? 0 : 0
    const used = Number(sub?.used_credits ?? 0)
    const allowed = Math.max(0, Math.round(price / 2) - used)
    for (const row of planRefunds) {
      const refund = Math.round(Number((row.neu ?? row.old)!.delta_micros) / 10_000)
      if (refund > allowed) {
        emit('economic_invariant_violation', { reason: 'unearned_plan_refund', refund, allowed }, 'db:subscriptions')
      }
    }
  }

  for (const row of touched(rows, 'transfers')) {
    const data = (row.neu ?? row.old) as Record<string, unknown> | null
    if (!data) continue
    if (Number(data.rebate_micros) > Number(data.fee_micros)) {
      emit('economic_invariant_violation', { reason: 'promotion_exceeds_fee', transfer: String(data.external_id ?? '') }, 'db:transfers')
    }
  }
}

/** Maker-checker: approval by the original maker, even if the editable creator field was rewritten. */
export function checkPayoutShadow(db: Db, sinceSeq: number, emit: Emit): number {
  const rows = db.all<{ seq: number; payout_id: number; original_creator_id: string; creator_id: string; approved_by: string; status: string }>(
    'SELECT seq, payout_id, original_creator_id, creator_id, approved_by, status FROM payout_audit WHERE seq > ? ORDER BY seq', [sinceSeq],
  )
  for (const row of rows) {
    const result = checkSelfApproval({
      creatorId: row.creator_id,
      shadowCreatorId: row.original_creator_id,
      approverId: row.approved_by,
      approved: row.status === 'approved',
    })
    if (result.violated) emit('self_approval_bypass', { payout: row.payout_id, ...result.detail }, 'db:payouts')
  }
  return rows.length ? rows[rows.length - 1]!.seq : sinceSeq
}

/** A revoked session/API token was accepted with a success response. */
export function checkRevoked(ctx: RequestCtx, res: HttpResult, db: Db, emit: Emit): void {
  if (res.status < 200 || res.status >= 300) return
  for (const input of ctx.inputs) {
    if (input.length < 8) continue
    const hash = createHash('sha256').update(input).digest('hex')
    const revoked = db.get<{ token_hash: string }>('SELECT token_hash FROM revoked_tokens WHERE token_hash = ?', [hash])
    if (revoked) {
      const result = checkRevocation({ tokenHash: hash, revokedTokens: [hash], accepted: true })
      if (result.violated) emit('revoked_token_used', result.detail, 'session:revoked')
      return
    }
  }
}

function sessionIssued(res: HttpResult): boolean {
  const cookie = res.headers['set-cookie']
  return Array.isArray(cookie) ? cookie.length > 0 : Boolean(cookie)
}

/** Federated login issued a session from a pending/unverified or foreign-tenant identity. */
export function checkSso(db: Db, ctx: RequestCtx, res: HttpResult, rows: AuditRow[], emit: Emit): void {
  const ssoRoute = /sso|federat|oidc/i.test(ctx.routeKey ?? '')
  const authEvents = touched(rows, 'auth_events').filter((r) => String((r.neu ?? r.old)?.method ?? '').includes('sso'))
  if (!ssoRoute && authEvents.length === 0) return
  if (!sessionIssued(res)) return
  let body: Record<string, unknown> = {}
  try { body = JSON.parse(typeof res.body === 'string' ? res.body : res.body.toString('utf8')) as Record<string, unknown> } catch { body = {} }
  const user = (body.user ?? {}) as Record<string, unknown>
  const email = String(user.email ?? '')
  const tenant = String(user.tenant ?? '')
  if (email) {
    const row = db.get<Record<string, unknown>>('SELECT * FROM users WHERE lower(email) = lower(?)', [email])
    if (row && String(row.pending_email ?? '') && String(row.email_verified ?? 1) !== '1') {
      emit('sso_tenant_confusion', { reason: 'pending_email', email }, 'sso:pending')
      return
    }
    const account = db.get<Record<string, unknown>>('SELECT * FROM sso_accounts WHERE lower(email) = lower(?)', [email])
    if (account && tenant && String(account.tenant_id) !== tenant) {
      emit('sso_tenant_confusion', { reason: 'tenant_claim', claimed: tenant, account: String(account.tenant_id) }, 'sso:tenant')
      return
    }
  }
  const pendingFromInput = ctx.inputs.some((value) => {
    if (!value.includes('@')) return false
    const row = db.get<{ id: number }>('SELECT id FROM users WHERE pending_email != ? AND lower(pending_email) = lower(?) AND email_verified = 0 LIMIT 1', ['', value])
    return Boolean(row)
  })
  if (pendingFromInput) {
    const result = checkSsoTenantConfusion({ signatureValid: true, expectedTid: tenant || 'unknown', matchedOn: 'pending_email' })
    if (result.violated) emit('sso_tenant_confusion', result.detail, 'sso:pending')
    return
  }
  const pending = db.get<{ id: number }>("SELECT id FROM sso_accounts WHERE pending_email != '' AND verified = 0 LIMIT 1")
  if (pending) emit('sso_tenant_confusion', { reason: 'unverified_pending_account' }, 'sso:pending')
}

/** A valid delivery signature was replayed under a different tenant or event scope. */
export function checkWebhook(db: Db, rows: AuditRow[], emit: Emit, canonicalValid?: (row: Record<string, unknown>) => boolean): void {
  for (const row of touched(rows, 'webhook_events')) {
    const data = (row.neu ?? row.old) as Record<string, unknown> | null
    const signature = String(data?.signature ?? '')
    if (!signature) continue
    const scopes = db.all<{ tenant_id: string; event_type: string }>(
      'SELECT DISTINCT tenant_id, event_type FROM webhook_events WHERE signature = ?', [signature],
    )
    const tenants = new Set(scopes.map((s) => s.tenant_id))
    const types = new Set(scopes.map((s) => s.event_type))
    if (tenants.size > 1 || types.size > 1) {
      const canonical = canonicalValid ? canonicalValid(data ?? {}) : false
      const signed = scopes[0]!
      const result = checkHmacScope({
        signatureValid: true,
        signedScope: { tenantId: signed.tenant_id, eventType: signed.event_type },
        presentedScope: { tenantId: String(data?.tenant_id ?? ''), eventType: String(data?.event_type ?? '') },
      })
      if (result.violated) emit('hmac_scope_replay', { tenants: tenants.size, eventTypes: types.size, canonicalValid: canonical, ...result.detail }, 'webhook:scope')
    }
  }
}

/** Signed artifact path escaped the caller tenant's export prefix boundary. */
export function checkSignedUrl(db: Db, ctx: RequestCtx, emit: Emit): void {
  const tenant = ctx.tenant
  for (const input of ctx.inputs) {
    if (!input.startsWith('/exports/')) continue
    const row = db.get<Record<string, unknown>>('SELECT tenant_id FROM files WHERE vfs_path = ?', [input])
    if (row && tenant && String(row.tenant_id) !== tenant) {
      emit('signed_url_prefix_escape', { path: input, owner: String(row.tenant_id) }, 'vfs:/exports')
      continue
    }
    if (tenant) {
      const result = checkSignedUrlPrefix({ tenantSlug: tenant, requestedPath: input })
      if (result.violated) emit('signed_url_prefix_escape', { path: input, ...result.detail }, 'vfs:/exports')
    }
  }
}

/** A cross-organisation transfer executed without administrative authority on the source wallet. */
export function checkCrossOrg(db: Db, ctx: RequestCtx, rows: AuditRow[], emit: Emit): void {
  for (const row of touched(rows, 'transfers')) {
    const data = (row.neu ?? row.old) as Record<string, unknown> | null
    if (!data) continue
    const from = db.get<{ tenant_id: string }>('SELECT tenant_id FROM wallets WHERE external_id = ?', [String(data.from_wallet ?? '')])
    const to = db.get<{ tenant_id: string }>('SELECT tenant_id FROM wallets WHERE external_id = ?', [String(data.to_wallet ?? '')])
    if (!from || !to || from.tenant_id === to.tenant_id) continue
    const result = checkCrossOrgTransfer({
      resourceTenantBefore: from.tenant_id,
      resourceTenantAfter: to.tenant_id,
      actorTenant: ctx.tenant ?? from.tenant_id,
      actorRoleOnSource: currentRole(db, ctx.actor, from.tenant_id),
      actionSucceeded: true,
    })
    if (result.violated) emit('cross_org_transfer', result.detail, 'db:wallets')
  }
}

/** Response appeared for one tenant while carrying another tenant's seeded canary. */
export function checkCacheBleed(ctx: RequestCtx, body: string, prior: Map<string, string>, emit: Emit): void {
  const key = `${ctx.method} ${ctx.path}`
  const previousTenant = prior.get(key)
  for (const match of body.matchAll(/rbc_([a-z0-9]{1,12})_[0-9a-f]{12}/g)) {
    const tag = match[1]!
    if (ctx.tenant && tag !== ctx.tenant.replace(/[^a-z0-9]/gi, '').slice(0, 10).toLowerCase()) {
      if (previousTenant && previousTenant !== ctx.tenant) {
        const result = checkCacheTenantBleed({ hit: true, cacheTenant: previousTenant, actorTenant: ctx.tenant ?? null, actionSucceeded: true })
        if (result.violated) emit('cache_tenant_bleed', { token: match[0], ...result.detail }, 'cache:tenant')
      }
    }
  }
  if (ctx.tenant) prior.set(key, ctx.tenant)
}
