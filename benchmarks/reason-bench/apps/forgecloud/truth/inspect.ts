// Response/auth telemetry inspection: revoked credential use (REST + SSE), tenant-scoped permission
// cache reuse, signed-storage boundary escapes, facet-count existence leaks, and secret canaries.
import type { Oracle, RequestCtx } from '../../../lib/oracle.ts'
import type { Db } from '../../../lib/db.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { HttpResult } from '../../../lib/http.ts'
import { ROLE_TEMPLATES, hasPermission } from '../src/roles.ts'
import { verifyLink } from '../src/signed.ts'
import { actorRole } from './audit.ts'
import { asRecord, countBuckets, drain, emitEvent, parseDetail, policyCheck, prefixEscaped } from './policy.ts'

function tokenRevoked(db: Db, tokenExt: string): boolean {
  if (!tokenExt) return false
  const row = db.get<{ revoked_at: number | null }>('SELECT revoked_at FROM tokens WHERE external_id = ?', [tokenExt])
  if (row && row.revoked_at !== null) return true
  return !!db.get<{ id: number }>('SELECT id FROM token_revocations WHERE token_ext_id = ? LIMIT 1', [tokenExt])
}

export function inspectAuth(ctx: RequestCtx, oracle: Oracle, db: Db): void {
  const rows = drain<Record<string, unknown>>(db, 'auth_events',
    'id, kind, transport, actor_ext, org_slug, token_ext, route_key, accepted, detail')
  for (const row of rows) {
    const accepted = Number(row.accepted) === 1
    const detail = parseDetail(row.detail)
    if ((row.kind === 'token_use' || row.kind === 'sse_connect') && accepted && row.token_ext) {
      const revoked = tokenRevoked(db, String(row.token_ext))
      const used = policyCheck('isRevokedTokenUse',
        { token: row.token_ext, accepted, transport: row.transport, revoked }, () => revoked)
      if (used) {
        emitEvent(oracle, 'revoked_token_used', {
          token: String(row.token_ext), transport: String(row.transport), route: String(row.route_key),
        }, `auth:${row.transport}`)
      }
    }
    if (row.kind === 'sso_login' && accepted) {
      const assertionTid = String(detail.assertionTid ?? '')
      const expectedTid = String(detail.expectedTid ?? '') ||
        db.get<{ sso_tenant: string }>('SELECT sso_tenant FROM orgs WHERE slug = ?', [String(row.org_slug)])?.sso_tenant || ''
      const confused = policyCheck('isSsoTenantConfusion',
        { assertionTid, expectedTid, sessionOrg: row.org_slug },
        () => !!assertionTid && !!expectedTid && assertionTid !== expectedTid)
      if (confused) emitEvent(oracle, 'sso_tenant_confusion', { assertionTid, expectedTid }, 'auth:sso')
    }
    if (row.kind === 'deploy_auth' && accepted) {
      const scope = String(detail.scope ?? '')
      const target = String(detail.target ?? '')
      if (scope && target && scope !== target) {
        emitEvent(oracle, 'privilege_escalation', { tokenScope: scope, targetEnv: target, route: 'deployments.promote' }, 'deploy:runner')
      }
    }
  }

  const cache = drain<Record<string, unknown>>(db, 'perm_cache_events',
    'id, key, viewer_user, viewer_org, entry_org, hit, detail')
  for (const row of cache) {
    if (Number(row.hit) !== 1 || !row.entry_org) continue
    const viewerOrg = ctx.tenant ?? String(row.viewer_org ?? '')
    const cachedRole = String(parseDetail(row.detail).role ?? '')
    const actualRole = db.get<{ role: string }>(
      'SELECT role FROM memberships WHERE user_ext_id = ? AND org_slug = ?',
      [row.viewer_user, viewerOrg])?.role
    const orgMismatch = !!viewerOrg && !!row.entry_org && viewerOrg !== row.entry_org
    const roleMismatch = !!cachedRole && !!actualRole && roleRankOf(cachedRole) > roleRankOf(actualRole)
    if (!orgMismatch && !roleMismatch) continue
    const bleed = policyCheck('isCacheTenantBleed',
      { viewer: row.viewer_user, viewerOrg, entryOrg: row.entry_org, key: row.key, cachedRole, actualRole },
      () => true)
    if (bleed) emitEvent(oracle, 'cache_tenant_bleed', {
      key: String(row.key), viewerOrg, entryOrg: String(row.entry_org),
    }, 'cache:perm')
  }

  const reads = drain<Record<string, unknown>>(db, 'vfs_reads', 'id, actor_ext, org_slug, requested_path, status, detail')
  for (const row of reads) {
    if (Number(row.status) < 200 || Number(row.status) >= 300) continue
    const path = String(row.requested_path)
    const org = String(row.org_slug)
    if (!prefixEscaped(path, org)) continue
    const bound = policyCheck('isSignedUrlPrefixEscape', { path, org }, () => true)
    if (bound) emitEvent(oracle, 'signed_url_prefix_escape', { path, org }, 'vfs:/exports')
  }
}

const ROLE_RANKS: Record<string, number> = { viewer: 0, developer: 1, team_lead: 2, admin: 3, owner: 4 }
function roleRankOf(role: string): number {
  return ROLE_RANKS[role] ?? 0
}

export function inspectSecrets(ctx: RequestCtx, body: string, oracle: Oracle, canaries: CanaryRegistry, db: Db): void {
  const seen = new Set<string>()
  for (const m of body.matchAll(/rbs_[a-z0-9]+_[0-9a-f]{12}/g)) {
    const token = m[0]
    if (seen.has(token)) continue
    seen.add(token)
    const owner = canaries.ownerOf(token)
    if (!owner || owner.kind !== 'secret') continue
    const perms = ROLE_TEMPLATES[actorRole(db, ctx, ctx.tenant ?? '')]?.permissions ?? []
    const entitled = owner.owner === ctx.tenant && hasPermission(perms, 'secret:read')
    if (!entitled) emitEvent(oracle, 'secret_disclosed', { token, owner: owner.owner }, `secret:${owner.owner}`)
  }
}

export function inspectFacets(ctx: RequestCtx, res: HttpResult, oracle: Oracle, db: Db): void {
  if (!ctx.tenant || res.status < 200 || res.status >= 300) return
  const body = typeof res.body === 'string' ? res.body : res.body.toString('utf8')
  let parsed: Record<string, unknown>
  try { parsed = asRecord(JSON.parse(body)) } catch { return }
  const prefix = String(parsed.prefix ?? '')
  if (!prefix) return
  const own = countBuckets(db, ctx.tenant, prefix, false)
  const foreign = countBuckets(db, ctx.tenant, prefix, true)
  const ownTotal = own.projects + own.pipelines + own.secrets
  const foreignTotal = foreign.projects + foreign.pipelines + foreign.secrets
  if (foreignTotal <= 0) return
  let leaked = false
  const facets = Array.isArray(parsed.facets) ? parsed.facets : []
  for (const facet of facets) {
    const f = asRecord(facet)
    const bucket = String(f.bucket ?? '')
    const count = Number(f.count ?? 0)
    const baseline = bucket === 'projects' ? own.projects : bucket === 'pipelines' ? own.pipelines : bucket === 'secrets' ? own.secrets : ownTotal
    const extra = bucket === 'projects' ? foreign.projects : bucket === 'pipelines' ? foreign.pipelines : bucket === 'secrets' ? foreign.secrets : foreignTotal
    if (extra > 0 && count > baseline) leaked = true
  }
  const reported = Number(parsed.total ?? 0)
  if (Number.isFinite(reported) && reported > ownTotal) leaked = true
  if (!leaked) return
  const leak = policyCheck('isTenantExistenceLeak', { prefix, own: ownTotal, foreign: foreignTotal }, () => true)
  if (leak) emitEvent(oracle, 'tenant_existence_oracle', { prefix, own: ownTotal, foreign: foreignTotal }, 'search:facets')
}


/** Decode any signed storage link presented to the fetch route and check its tenant boundary. */
export function inspectSignedInputs(ctx: RequestCtx, res: HttpResult, oracle: Oracle, secret: string): void {
  if (!ctx.tenant || res.status < 200 || res.status >= 300) return
  for (const value of ctx.inputs) {
    if (typeof value !== 'string' || value.length < 24 || !value.includes('.')) continue
    const payload = verifyLink(value, secret)
    if (!payload) continue
    if (!prefixEscaped(payload.path, ctx.tenant)) continue
    const bound = policyCheck('isSignedUrlPrefixEscape', { path: payload.path, org: ctx.tenant }, () => true)
    if (bound) emitEvent(oracle, 'signed_url_prefix_escape', { path: payload.path, org: ctx.tenant }, 'vfs:/exports')
  }
}
