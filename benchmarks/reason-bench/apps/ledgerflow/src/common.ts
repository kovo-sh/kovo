// Shared helpers for the area route modules: identity extraction, tenant scoping, row views and
// small request parsing utilities. Authorization is always resolved from current database state.
import type { ReqCtx, HttpResult } from '../../../lib/http.ts'
import type { AppContext } from './context.ts'
import { currentRole, identity, type Identity } from './auth.ts'
import { roleRank } from './plan.ts'

export function body(req: ReqCtx): Record<string, unknown> {
  return req.body && typeof req.body === 'object' && !Array.isArray(req.body)
    ? (req.body as Record<string, unknown>)
    : {}
}

export function param(req: ReqCtx, ctx: AppContext, key: string): string {
  return req.params[ctx.field(key)] ?? String(body(req)[ctx.field(key)] ?? body(req)[key] ?? '')
}

export function unauthorized(req: ReqCtx): HttpResult { return req.json({ error: 'unauthorized' }, 401) }
export function forbidden(req: ReqCtx): HttpResult { return req.json({ error: 'forbidden' }, 403) }
export function notFound(req: ReqCtx): HttpResult { return req.json({ error: 'not_found' }, 404) }
export function conflict(req: ReqCtx, error: string): HttpResult { return req.json({ error }, 409) }

export function requireSession(req: ReqCtx): Identity | null {
  return identity(req)
}

export function requireRole(ctx: AppContext, req: ReqCtx, minimum: string): Identity | null {
  const id = identity(req)
  if (!id) return null
  return roleRank(currentRole(ctx, req)) >= roleRank(minimum) ? id : null
}

export function ownRows<T = Record<string, unknown>>(ctx: AppContext, tenant: string, table: string): T[] {
  return ctx.db.all<T>(`SELECT * FROM ${table} WHERE tenant_id = ? ORDER BY id`, [tenant])
}

export function money(cents: unknown): string {
  return (Number(cents ?? 0) / 100).toFixed(2)
}

function state(ctx: AppContext, value: unknown): { status: string; statusLabel: string } {
  const raw = String(value ?? '')
  return { status: raw, statusLabel: ctx.labels.states[raw] ?? raw }
}

export function memberView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, email: row.email, role: row.role, name: row.name, status: row.status,
    pendingEmail: row.pending_email || undefined,
  }
}

export function invoiceView(ctx: AppContext, row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, number: row.number, amount: row.amount_cents, amountLabel: money(row.amount_cents),
    ...state(ctx, row.status), description: row.description, note: row.note ?? '', auditRef: row.audit_ref ?? '',
  }
}

export function orderView(ctx: AppContext, row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, user: row.user_ext_id,
    subtotal: row.subtotal_cents, discount: row.discount_cents, total: row.total_cents,
    totalLabel: money(row.total_cents), paid: row.paid_cents, currency: row.currency,
    coupon: row.coupon_code, note: row.note, ...state(ctx, row.status),
    items: ctx.db.all<Record<string, unknown>>('SELECT * FROM order_items WHERE order_id = ? ORDER BY id', [row.external_id])
      .map((i) => ({ id: i.external_id, sku: i.sku, name: i.name, unit: i.unit_cents, qty: i.qty, discount: i.discount_cents })),
  }
}

export function cartView(ctx: AppContext, row: Record<string, unknown>): Record<string, unknown> {
  const items = ctx.db.all<Record<string, unknown>>('SELECT * FROM cart_items WHERE cart_id = ? ORDER BY id', [row.external_id])
    .map((i) => ({ id: i.external_id, sku: i.sku, name: i.name, unit: i.unit_cents, qty: i.qty }))
  const subtotal = items.reduce((sum, i) => sum + Number(i.unit) * Number(i.qty), 0)
  const coupon = row.coupon_code
    ? ctx.db.get<Record<string, unknown>>('SELECT * FROM coupons WHERE code = ? AND tenant_id = ?', [row.coupon_code, row.tenant_id])
    : undefined
  const discount = coupon ? Math.round((subtotal * Number(coupon.percent_off)) / 100) : 0
  return {
    id: row.external_id, currency: row.currency, coupon: row.coupon_code || null,
    subtotal, discount, total: subtotal - discount, ...state(ctx, row.status), items,
    couponMinSpend: coupon ? coupon.min_spend_cents : undefined,
  }
}

export function payoutView(ctx: AppContext, row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, creator: row.creator_id, approvedBy: row.approved_by || null,
    amount: row.amount_cents, amountLabel: money(row.amount_cents), currency: row.currency,
    memo: row.memo, destination: row.destination, ...state(ctx, row.status),
  }
}

export function walletView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, currency: row.currency, balanceMicros: row.balance_micros,
    balanceLabel: money(Math.round(Number(row.balance_micros) / 10_000)), rateToBase: row.rate_to_base_micros,
  }
}

export function inviteView(row: Record<string, unknown>): Record<string, unknown> {
  return { id: row.external_id, email: row.email, role: row.role, state: row.state, createdBy: row.created_by }
}

export function exportView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, kind: row.kind, creator: row.creator_id, creatorRole: row.creator_role,
    status: row.status, path: row.vfs_path || undefined,
  }
}

export function fileView(row: Record<string, unknown>): Record<string, unknown> {
  return { id: row.external_id, name: row.name, note: row.note, path: row.vfs_path }
}
