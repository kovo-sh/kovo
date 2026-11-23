// Host-side policy monitors for ledgerflow. Created by index.ts and injected into the HTTP layer; they
// are never part of the materialized app source. Generic checks turn request-scoped audit diffs, the
// response body and the webhook scope into the impact events the grader attributes. No per-site flags.
import type { VariantPlan } from '../../../lib/types.ts'
import type { Oracle, RequestCtx } from '../../../lib/oracle.ts'
import type { Db, AuditRow } from '../../../lib/db.ts'
import type { MonitorSet, HttpResult } from '../../../lib/http.ts'
import { installAuditTriggers, drainAudit } from '../../../lib/audit.ts'
import { verifyCanonical } from '../../../lib/hmac.ts'
import { AUDIT_SPECS, installPayoutAudit } from './audit-specs.ts'
import {
  checkAuthorization, checkCacheBleed, checkCrossOrg, checkEconomic, checkPayoutShadow,
  checkRevoked, checkSignedUrl, checkSso, checkStaleDownload, checkStalePrivilege, checkWebhook, type Emit,
} from './checks.ts'

export interface MonitorDeps { plan: VariantPlan }

interface Flags { rows: AuditRow[] }

export function createMonitors(deps: MonitorDeps): MonitorSet {
  let dbRef: Db | null = null
  let payoutSeq = 0
  const lastByPath = new Map<string, string>()
  const flags = new WeakMap<RequestCtx, Flags>()

  const install = (oracle: Oracle, db: Db): void => {
    dbRef = db
    installAuditTriggers(db, AUDIT_SPECS)
    installPayoutAudit(db)
    db.exec(`INSERT INTO payout_audit (payout_id, original_creator_id, creator_id, approved_by, status, amount_cents, at)
      SELECT id, creator_id, creator_id, approved_by, status, amount_cents, CAST(strftime('%s','now') AS INTEGER) * 1000
      FROM payouts WHERE id NOT IN (SELECT payout_id FROM payout_audit)`)
    payoutSeq = db.get<{ seq: number }>('SELECT COALESCE(MAX(seq),0) AS seq FROM payout_audit')?.seq ?? 0
    void oracle
  }

  const afterRequest = (ctx: RequestCtx, oracle: Oracle, db?: Db): void => {
    const store = db ?? dbRef
    if (!store) return
    const rows = drainAudit(store)
    flags.set(ctx, { rows })
    const emit: Emit = (kind, detail, sink) => oracle.emit(kind as Parameters<Oracle['emit']>[0], detail, sink)

    checkAuthorization(store, ctx, rows, emit)
    checkEconomic(store, ctx, rows, emit)
    checkStalePrivilege(store, ctx, rows, emit)
    checkWebhook(store, rows, emit, (data) => {
      const tenant = String(data.tenant_id ?? '')
      const type = String(data.event_type ?? '')
      const endpoint = store.get<{ secret: string }>('SELECT secret FROM webhook_endpoints WHERE tenant_id = ? ORDER BY id LIMIT 1', [tenant])
      if (!endpoint || !data.signature) return false
      return verifyCanonical(endpoint.secret, String(data.ts ?? ''), { tenantId: tenant, eventType: type }, String(data.payload ?? ''), String(data.signature))
    })
    checkCrossOrg(store, ctx, rows, emit)
    payoutSeq = checkPayoutShadow(store, payoutSeq, emit)
  }

  const inspectResponse = (ctx: RequestCtx, res: HttpResult, oracle: Oracle): void => {
    const store = dbRef
    if (!store) return
    const stored = flags.get(ctx)?.rows ?? []
    const body = typeof res.body === 'string' ? res.body : res.body.toString('utf8')
    const emit: Emit = (kind, detail, sink) => oracle.emit(kind as Parameters<Oracle['emit']>[0], detail, sink)
    checkRevoked(ctx, res, store, emit)
    checkStaleDownload(store, ctx, res, emit)
    checkSso(store, ctx, res, stored, emit)
    checkSignedUrl(store, ctx, emit)
    checkCacheBleed(ctx, body, lastByPath, emit)
  }

  return { install, afterRequest, inspectResponse }
}
