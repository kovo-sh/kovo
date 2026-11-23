// AppContext — the dependency surface every route module (common area modules and planted site
// modules alike) receives. The host wires the concrete collaborators (database, virtual filesystem,
// contained egress, id codec, token helpers) and injects them here so route code stays declarative.
//
// SITE MODULE CONTRACT: every planted site file (both twins) default-exports
//   export default function register(app: AppContext): void
// registering exactly its own route(s) via app.route(...) / app.stream(...). Both twins export the
// same `register` symbol with similar shape and size. Site modules mount before the shared area
// modules, so a mounted site owns its route key (first registration wins in both the HTTP router and
// the stream hub).
//
// IDENTITY: a session identity carries the primary org. Requests may select another org the user is
// a member of with the `x-org-id` header (the HTTP resolver binds it to `req.tenant`). Workspace
// scoping uses the `x-workspace-id` header; helpers here resolve it against the caller's org.
import { createHash } from 'node:crypto'
import type { VariantPlan, Actor, PersonaId } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { Vfs } from '../../../lib/vfs.ts'
import type { Egress, InternalServiceRef } from '../../../lib/egress.ts'
import type { IdCodec } from '../../../lib/ids.ts'
import type { CanaryRegistry } from '../../../lib/canary.ts'
import type { Handler, RouteOpts, HttpApp, ReqCtx } from '../../../lib/http.ts'
import type { XmlNode } from '../../../lib/xml.ts'
import type { StreamHandler, StreamHub } from './streams.ts'
import type { PermissionCache } from './perm-cache.ts'
import { permissionsForRole, hasPermission, roleRank } from './roles.ts'

export interface AppConfig {
  buildLogOrigin: string
  metadataOrigin: string
  idpOrigin: string
  jwtSecret: string
  webhookSecret: string
  signedUrlSecret: string
  internalSigningSalt: string
  idpSecret: string
}

// Host-provided, pre-bound collaborators. The factories close over the request-impact recorder so
// route code cannot reach it directly.
export interface Wiring {
  makeVfs(files: Record<string, string>): Vfs
  makeEgress(services: InternalServiceRef[], oob?: number[]): Egress
  render(source: string, data: Record<string, unknown>, inputDerived?: boolean): string
  signToken(payload: Record<string, unknown>): string
  verifyToken(token: string, acceptNone: boolean): { valid: boolean; payload?: unknown }
  signWebhook(secret: string, body: string, ts: number | string): string
  verifyWebhook(secret: string, body: string, ts: string, sig: string): boolean
  simulate(template: string, args: string[]): { output: string; commands: string[] }
  parseXml(source: string, external: boolean, vfs: Vfs, egress: Egress): XmlNode
}

export interface UserRow {
  id: number
  external_id: string
  primary_org: string
  email: string
  password_hash: string
  role: string
  persona: string | null
  name: string
  status: string
}

export interface MembershipRow {
  id: number
  user_ext_id: string
  org_slug: string
  role: string
  permissions: string
  invited_by: string
}

export interface TokenRow {
  id: number
  external_id: string
  org_slug: string
  user_ext_id: string
  name: string
  secret_hash: string
  scopes: string
  env_scope: string
  created_at: number
  expires_at: number
  revoked_at: number | null
}

export interface OrgRow {
  id: number
  external_id: string
  slug: string
  name: string
  plan: string
  sso_tenant: string
  data_ref: string
}

export interface WorkspaceRow {
  id: number
  external_id: string
  org_slug: string
  name: string
  is_default: number
  visibility: string
}

export interface AuthEvent {
  kind: string
  transport?: 'rest' | 'sse' | 'sso'
  actorExt?: string
  org?: string
  tokenExt?: string
  routeKey?: string
  accepted?: boolean
  detail?: Record<string, unknown>
}

export interface PatCheck {
  token: string
  signatureValid: boolean
  payload: Record<string, unknown> | null
  row: TokenRow | null
  revoked: boolean
  org: string | null
  userExt: string | null
  scopes: string[]
  envScope: string
}

export interface AppLabels {
  brand: string
  tagline: string
  nav: { projects: string; builds: string; secrets: string; deployments: string; webhooks: string; members: string; search: string }
  roleNames: Record<string, string>
}

export interface AppContext {
  plan: VariantPlan
  db: Db
  ids: IdCodec
  vfs: Vfs
  egress: Egress
  canaries: CanaryRegistry
  config: AppConfig
  wiring: Wiring
  labels: AppLabels
  permCache: PermissionCache
  /** Register a handler for a logical route key; a no-op if the plan omits the key. */
  route(routeKey: string, handler: Handler, opts?: RouteOpts): void
  /** Register an SSE handler for a logical route key; a no-op if the plan omits the key. */
  stream(routeKey: string, handler: StreamHandler): void
  /** Runtime field/param name for a logical param key (e.g. 'secretId' -> 'credId'). */
  field(key: string): string
  /** The seeded user row bound to a persona/actor, if any. */
  userForActor(actor: Actor | PersonaId | string): UserRow | undefined
  /** Fetch a tenant-scoped row by its external id from a table (undefined if absent). */
  byExternalId<T = Record<string, unknown>>(table: string, externalId: string): T | undefined
  /** Membership row binding a user to an org (undefined when not a member). */
  membershipFor(userExtId: string, org: string): MembershipRow | undefined
  /** Effective capability list for a user in an org (membership template, or primary role). */
  permissionsFor(userExtId: string, org: string): string[]
  /** True when the user holds the capability in that org. */
  can(userExtId: string, org: string, permission: string): boolean
  /** Role code for a user in an org. */
  roleFor(userExtId: string, org: string): string
  /** Rank of the user's role in an org (higher is more privileged). */
  roleRankFor(userExtId: string, org: string): number
  /** Default workspace for an org. */
  defaultWorkspace(org: string): WorkspaceRow | undefined
  /** Workspace row by external id. */
  workspaceByExt(ext: string): WorkspaceRow | undefined
  /** Resolve the request's workspace header against the caller org (neutral: empty == absent). */
  workspaceForRequest(req: ReqCtx, org: string): { workspace?: WorkspaceRow; status: number }
  /** Issue a signed personal access token and persist its hash + revocation record slot. */
  issuePat(input: { userExt: string; org: string; name: string; scopes?: string[]; envScope?: string; expiresAt?: number }): { token: string; row: TokenRow }
  /** Verify a PAT signature and look up its persisted row / revocation state. */
  verifyPat(token: string): PatCheck
  /** Persist an authentication/authorization telemetry record for the host monitors. */
  recordAuth(event: AuthEvent): void
  /** Parse an XML document; external entities resolve through the virtual filesystem/egress. */
  parseXml(source: string, external: boolean): XmlNode
}

export interface BuildContextDeps {
  app: HttpApp
  plan: VariantPlan
  db: Db
  ids: IdCodec
  canaries: CanaryRegistry
  config: AppConfig
  wiring: Wiring
  vfs: Vfs
  egress: Egress
  streams: StreamHub
  permCache: PermissionCache
  labels: AppLabels
}

export function hashSecret(secret: string): string {
  return createHash('sha256').update(secret).digest('hex')
}

export function parseJson<T>(raw: string, fallback: T): T {
  try { return JSON.parse(raw) as T } catch { return fallback }
}

export function buildContext(deps: BuildContextDeps): AppContext {
  const { app, plan, db, ids, canaries, config, wiring, vfs, egress, streams, permCache, labels } = deps

  const membershipFor = (userExtId: string, org: string): MembershipRow | undefined =>
    db.get<MembershipRow>('SELECT * FROM memberships WHERE user_ext_id = ? AND org_slug = ?', [userExtId, org])

  const roleFor = (userExtId: string, org: string): string => {
    const m = membershipFor(userExtId, org)
    if (m) return m.role
    const u = db.get<UserRow>('SELECT * FROM users WHERE external_id = ?', [userExtId])
    return u && u.primary_org === org ? u.role : 'viewer'
  }

  const permissionsFor = (userExtId: string, org: string): string[] => {
    const m = membershipFor(userExtId, org)
    if (m) return parseJson<string[]>(m.permissions, permissionsForRole(m.role))
    return permissionsForRole(roleFor(userExtId, org))
  }

  const defaultWorkspace = (org: string): WorkspaceRow | undefined =>
    db.get<WorkspaceRow>('SELECT * FROM workspaces WHERE org_slug = ? AND is_default = 1 LIMIT 1', [org])

  const workspaceByExt = (ext: string): WorkspaceRow | undefined =>
    db.get<WorkspaceRow>('SELECT * FROM workspaces WHERE external_id = ?', [ext])

  const ctx: AppContext = {
    plan, db, ids, vfs, egress, canaries, config, wiring, labels, permCache,
    route(routeKey, handler, opts) {
      if (!plan.routes[routeKey]) return
      app.route(routeKey, handler, opts)
    },
    stream(routeKey, handler) {
      if (!plan.routes[routeKey]) return
      streams.route(routeKey, handler)
    },
    field(key) {
      return plan.params[key] ?? key
    },
    userForActor(actor) {
      if (!actor || actor === 'anonymous' || actor === 'unknown') return undefined
      return db.get<UserRow>('SELECT * FROM users WHERE persona = ?', [String(actor)])
    },
    byExternalId(table, externalId) {
      return db.get(`SELECT * FROM ${table} WHERE external_id = ?`, [externalId]) as never
    },
    membershipFor,
    permissionsFor,
    can(userExtId, org, permission) {
      return hasPermission(permissionsFor(userExtId, org), permission)
    },
    roleFor,
    roleRankFor(userExtId, org) {
      return roleRank(roleFor(userExtId, org))
    },
    defaultWorkspace,
    workspaceByExt,
    workspaceForRequest(req, org) {
      const header = req.headers['x-workspace-id']
      if (header === undefined || header === '') {
        const ws = defaultWorkspace(org)
        return ws ? { workspace: ws, status: 200 } : { status: 404 }
      }
      const ws = workspaceByExt(header)
      if (!ws || ws.org_slug !== org) return { status: 403 }
      return { workspace: ws, status: 200 }
    },
    issuePat(input) {
      const seq = db.get<{ n: number }>('SELECT COALESCE(MAX(id), 0) + 1 AS n FROM tokens')?.n ?? 1
      const externalId = ids.encode('token', seq)
      const now = Date.now()
      const payload = {
        typ: 'pat', sub: input.userExt, org: input.org, scopes: input.scopes ?? ['read'],
        env: input.envScope ?? 'dev', jti: externalId,
      }
      const token = wiring.signToken(payload)
      db.run(
        'INSERT INTO tokens (external_id, org_slug, user_ext_id, name, secret_hash, scopes, env_scope, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)',
        [externalId, input.org, input.userExt, input.name, hashSecret(token),
          (input.scopes ?? ['read']).join(','), input.envScope ?? 'dev', now, input.expiresAt ?? now + 86_400_000],
      )
      const row = db.get<TokenRow>('SELECT * FROM tokens WHERE external_id = ?', [externalId])!
      return { token, row }
    },
    verifyPat(token) {
      const verified = wiring.verifyToken(token, false)
      const payload = verified.valid && verified.payload && typeof verified.payload === 'object'
        ? verified.payload as Record<string, unknown> : null
      const row = db.get<TokenRow>('SELECT * FROM tokens WHERE secret_hash = ?', [hashSecret(token)]) ?? null
      const revocation = row
        ? db.get<{ id: number }>('SELECT id FROM token_revocations WHERE token_ext_id = ? LIMIT 1', [row.external_id])
        : undefined
      const expired = !!row && row.expires_at > 0 && row.expires_at < Date.now()
      const revoked = !!row && (row.revoked_at !== null || !!revocation) || expired
      const scopes = row ? row.scopes.split(',').map((s) => s.trim()).filter(Boolean)
        : Array.isArray(payload?.scopes) ? payload!.scopes.map(String) : []
      return {
        token,
        signatureValid: verified.valid,
        payload,
        row,
        revoked,
        org: row?.org_slug ?? (typeof payload?.org === 'string' ? payload.org : null),
        userExt: row?.user_ext_id ?? (typeof payload?.sub === 'string' ? payload.sub : null),
        scopes,
        envScope: row?.env_scope ?? (typeof payload?.env === 'string' ? payload.env : 'dev'),
      }
    },
    recordAuth(event) {
      db.run(
        'INSERT INTO auth_events (kind, transport, actor_ext, org_slug, token_ext, route_key, accepted, detail) VALUES (?,?,?,?,?,?,?,?)',
        [event.kind, event.transport ?? 'rest', event.actorExt ?? '', event.org ?? '',
          event.tokenExt ?? '', event.routeKey ?? '', event.accepted ? 1 : 0,
          event.detail ? JSON.stringify(event.detail) : ''],
      )
    },
    parseXml(source, external) {
      return wiring.parseXml(source, external, vfs, egress)
    },
  }
  return ctx
}

export { permissionsForRole, hasPermission, roleRank }
