// Impact monitors: authorization policy, business invariants and response inspectors. Created on the
// repo side and injected into the HTTP layer; the materialized app never imports this file. All impact
// is judged from runtime audit diffs + responses, never from per-site flags in the source tree.
import { installAuditTriggers, drainAudit } from '../../../lib/audit.ts'
import type { AuditSpec, AuditRow, Db } from '../../../lib/db.ts'
import type { MonitorSet, HttpResult } from '../../../lib/http.ts'
import type { Oracle, RequestCtx } from '../../../lib/oracle.ts'
import type { VariantPlan } from '../../../lib/types.ts'

const AUDIT_SPECS: AuditSpec[] = [
  { table: 'orders', columns: ['id', 'store_id', 'status', 'payment_state', 'total'] },
  { table: 'gift_cards', columns: ['id', 'store_id', 'balance', 'initial'] },
  { table: 'refunds', columns: ['id', 'store_id', 'order_id', 'payment_id', 'amount', 'status'] },
  { table: 'coupon_uses', columns: ['id', 'store_id', 'coupon_code', 'order_id'] },
  { table: 'reviews', columns: ['id', 'store_id', 'approved'] },
  { table: 'payments', columns: ['id', 'store_id', 'order_id', 'amount', 'captured'] },
  { table: 'shipments', columns: ['id', 'store_id', 'order_id', 'status'] },
  { table: 'customers', columns: ['id', 'store_id'] },
  { table: 'products', columns: ['id', 'store_id', 'stock'] },
  { table: 'carts', columns: ['id', 'store_id', 'status', 'locked', 'discount', 'subtotal'] },
]

const TENANT_TABLES = new Set(AUDIT_SPECS.map((s) => s.table))
const num = (v: unknown): number => Number(v ?? 0)
const str = (v: unknown): string => String(v ?? '')
const ACTIVE_MARKUP = /<script\b|<[a-z][^>]*\son\w+\s*=|(?:href|src)\s*=\s*["']?\s*javascript:/i
const SECRET_TOKEN = /rbs_([a-z0-9]{1,10})_[0-9a-f]{6,}/gi
const ORDER_PROTECTED = ['status', 'total', 'payment_state'] as const
const STATE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const LOOPBACK_ORIGIN = /^https?:\/\/(?:127\.0\.0\.1|localhost)(?::\d+)?(?:[/?#]|$)/i
const tagOf = (s: string): string => s.replace(/[^a-z0-9]/gi, '').slice(0, 10).toLowerCase() || 't'
const roleOf = (plan: VariantPlan, actor: string): string | undefined =>
  plan.personas[actor as keyof VariantPlan['personas']]?.role

function authz(ctx: RequestCtx, oracle: Oracle, row: AuditRow): void {
  if (ctx.actor === 'anonymous' || ctx.actor === 'admin') return
  if (!TENANT_TABLES.has(row.table)) return
  const neu = row.neu
  if (!neu || ctx.tenant == null) return
  if ('store_id' in neu && str(neu.store_id) !== ctx.tenant) {
    oracle.emit('cross_tenant_write', { table: row.table, owner: str(neu.store_id) }, `db:${row.table}`)
  }
}

function invariants(ctx: RequestCtx, oracle: Oracle, row: AuditRow, db: Db): void {
  if (row.table === 'gift_cards' && row.neu && num(row.neu.balance) < 0) {
    oracle.emit('race_double_spend', { table: 'gift_cards', balance: num(row.neu.balance) }, 'db:gift_cards')
  }
  if (row.table === 'orders' && row.op === 'UPDATE' && row.old && row.neu) {
    const became = str(row.old.status) !== 'confirmed' && str(row.neu.status) === 'confirmed'
    if (became && str(row.neu.payment_state) !== 'captured') {
      oracle.emit('workflow_skip', { table: 'orders', order: num(row.neu.id) }, 'db:orders')
    }
  }
  if (row.table === 'coupon_uses' && row.op === 'INSERT' && row.neu) {
    const n = db.get<{ n: number }>(
      'SELECT COUNT(*) AS n FROM coupon_uses WHERE store_id = ? AND coupon_code = ?',
      [str(row.neu.store_id), str(row.neu.coupon_code)],
    )
    if (n && n.n > 1) oracle.emit('invariant_violation', { reason: 'coupon_reuse', code: str(row.neu.coupon_code) }, 'db:coupon_uses')
  }
  if (row.table === 'products' && row.neu && num(row.neu.stock) < 0) {
    oracle.emit('race_double_spend', { table: 'products', stock: num(row.neu.stock) }, 'db:products')
  }
  if (row.table === 'carts' && row.op === 'UPDATE' && row.old && row.neu) {
    const wasLocked = num(row.old.locked) === 1
    const discountMoved = num(row.old.discount) !== num(row.neu.discount)
    if (wasLocked && discountMoved) {
      oracle.emit('workflow_skip', { table: 'carts', cart: num(row.neu.id) }, 'db:carts')
    }
  }
  if (row.table === 'carts' && row.neu && num(row.neu.subtotal) < 0) {
    oracle.emit('invariant_violation', { reason: 'negative_subtotal', cart: num(row.neu.id) }, 'db:carts')
  }
  if (row.table === 'refunds' && (row.op === 'INSERT' || row.op === 'UPDATE') && row.neu) {
    const orderId = num(row.neu.order_id)
    if (orderId > 0) {
      const paid = db.get<{ s: number }>('SELECT COALESCE(SUM(amount), 0) AS s FROM payments WHERE order_id = ? AND captured = 1', [orderId])
      const refunded = db.get<{ s: number }>("SELECT COALESCE(SUM(amount), 0) AS s FROM refunds WHERE order_id = ? AND status = 'approved'", [orderId])
      const paidAmt = paid ? num(paid.s) : 0
      if (paidAmt > 0 && refunded && num(refunded.s) > paidAmt) {
        oracle.emit('invariant_violation', { reason: 'refund_over_payment', order: orderId }, 'db:refunds')
      }
    }
  }
}

// Over-posting: an order update that persisted a protected lifecycle/amount column straight from a
// value the request supplied (whitelisted edits never echo a request value into these columns).
function massAssign(ctx: RequestCtx, oracle: Oracle, row: AuditRow): void {
  if (row.table !== 'orders' || row.op !== 'UPDATE' || !row.old || !row.neu) return
  for (const col of ORDER_PROTECTED) {
    if (str(row.old[col]) === str(row.neu[col])) continue
    if (ctx.inputSet.has(str(row.neu[col]))) {
      oracle.emit('mass_assignment', { table: 'orders', field: col }, 'db:orders')
      return
    }
  }
}

// Function-level authorization: a staff-only action completed for a non-staff signed-in principal.
function privEsc(ctx: RequestCtx, res: HttpResult, oracle: Oracle, plan: VariantPlan): void {
  if (ctx.routeKey !== 'adminImpersonate') return
  if (res.status < 200 || res.status >= 300) return
  if (ctx.actor === 'anonymous' || ctx.actor === 'unknown') return
  if (roleOf(plan, ctx.actor) === 'admin') return
  oracle.emit('privilege_escalation', { route: ctx.routeKey, actor: ctx.actor }, 'session')
}

// Secret disclosure: a config/API secret canary served to a principal not entitled to it (foreign
// store, or a non-owner role of its own store), unless the caller itself supplied that token.
function secretLeak(ctx: RequestCtx, res: HttpResult, oracle: Oracle, plan: VariantPlan): void {
  const body = typeof res.body === 'string' ? res.body : res.body.toString('utf8')
  if (!body || !body.includes('rbs_')) return
  const role = roleOf(plan, ctx.actor)
  const myTag = ctx.tenant ? tagOf(ctx.tenant) : null
  for (const m of body.matchAll(SECRET_TOKEN)) {
    const token = m[0]
    const ownerTag = (m[1] ?? '').toLowerCase()
    if (ownerTag === 'fake' || ctx.inputSet.has(token)) continue
    const entitled = myTag !== null && ownerTag === myTag && (role === 'owner' || role === 'admin')
    if (!entitled) { oracle.emit('secret_disclosed', { owner: ownerTag, actor: ctx.actor }, 'secret'); break }
  }
}

// Cross-site state change: a cookie-authenticated write whose Origin/Referer belongs to a foreign
// host still took effect. A handler that bound the session to its CSRF token would have rejected the
// cross-site request before any row changed, so a persisted change here proves the guard was absent.
function csrfStateChange(ctx: RequestCtx, oracle: Oracle, wrote: boolean): void {
  if (!wrote || !ctx.sessionId || !STATE_METHODS.has(ctx.method)) return
  const foreign = [...ctx.inputSet].some((v) => /^https?:\/\//i.test(v) && !LOOPBACK_ORIGIN.test(v))
  if (foreign) oracle.emit('csrf_state_change', { route: str(ctx.routeKey) }, 'csrf')
}

function inspectXss(res: HttpResult, oracle: Oracle): void {
  const ct = str(res.headers['content-type'])
  if (!ct.includes('text/html')) return
  const body = typeof res.body === 'string' ? res.body : res.body.toString('utf8')
  if (ACTIVE_MARKUP.test(body)) oracle.emit('stored_xss_rendered', {}, 'html')
}

export function createMonitors(deps: { plan: VariantPlan }): MonitorSet {
  const { plan } = deps
  return {
    install(_oracle, db) {
      installAuditTriggers(db, AUDIT_SPECS)
    },
    afterRequest(ctx, oracle, db) {
      if (!db) return
      let wrote = false
      for (const row of drainAudit(db)) {
        wrote = true
        authz(ctx, oracle, row)
        invariants(ctx, oracle, row, db)
        massAssign(ctx, oracle, row)
      }
      csrfStateChange(ctx, oracle, wrote)
    },
    inspectResponse(ctx, res, oracle) {
      inspectXss(res, oracle)
      privEsc(ctx, res, oracle, plan)
      secretLeak(ctx, res, oracle, plan)
    },
  }
}
