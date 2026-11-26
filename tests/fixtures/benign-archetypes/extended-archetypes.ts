/**
 * Extended benign-target archetype generators (R3-12):
 *   5. `benign_share_link`        — Two-folder benign presign + same-actor signed URL download
 *                                   with strict per-resource HMAC verification.
 *   6. `integer_coercion`         — Coercing query/body parameter via `parseInt` without SQL
 *                                   evaluation (identical numeric coercion across equal-prefix strings).
 *   7. `honest_rbac`              — Per-object owner RBAC returning 200 for own entity, 403 for
 *                                   foreign sibling entity (individually & in batch), and enforcing
 *                                   revocation consistently across primary & secondary surfaces.
 *   8. `cache_hit_and_pagination` — Public CDN cache hit (`X-Cache: HIT`, `Age: 42`) serving
 *                                   benign paginated/sorted catalog data and same-origin/fixed-IdP
 *                                   redirects.
 *
 * Defensive QA framing: pure in-memory benign target simulators, zero network.
 */
import {
  createBenignSession,
  headerCI,
  parseQueryParams,
  pathnameOf,
  sha256Hex,
  type BenignArchetypeDefinition,
  type SyntheticTargetRequest,
  type SyntheticTargetResponse,
} from './types.ts'

function hasInvalidBearer(req: SyntheticTargetRequest): boolean {
  const auth = headerCI(req.headers, 'authorization')
  if (!auth) return false
  return /^bearer\s+/i.test(auth) && !/^bearer\s+tok_[a-z0-9_]+_valid$/i.test(auth.trim())
}

/**
 * 5. `benign_share_link`:
 * Benign object-storage presign + download service:
 *   - Issues resource-scoped HMAC signatures bound strictly to `(tenant, folder, filename)`.
 *   - Rejects traversal (`..`), foreign-tenant keys, and tampered signatures with 403.
 *   - Allows the same tenant to presign two benign folders (`folder_a/report.pdf` and
 *     `folder_b/summary.pdf`) and download the exact resource that was signed.
 */
export const benignShareLinkArchetype: BenignArchetypeDefinition = {
  id: 'benign_share_link',
  title: 'Two-folder benign presign / same-actor signed URL download',
  description: 'Mints per-resource HMAC signed URLs restricted to caller tenant folders and enforces signature-to-path binding on download.',
  createSession(opts) {
    const origin = opts?.origin ?? 'https://benign-qa.example.invalid'
    const signResource = (tenant: string, folder: string, file: string): string =>
      sha256Hex(`benign-share-hmac:${tenant}:${folder}:${file}`).slice(0, 32)

    return createBenignSession({
      archetypeId: 'benign_share_link',
      origin,
      signingKey: opts?.signingKey,
      primaryRoute: '/api/files/presign',
      secondaryRoute: '/api/files/download',
      queryParam: 'folder',
      baseParamValue: 'folder_a',
      mutateRoute: '/api/files/presign',
      balanceRoute: '/api/files/presign',
      readEntityRoute: '/api/files/download?folder=folder_a&file=report.pdf',
      foreignEntityRoute: '/api/files/download?folder=folder_b&file=summary.pdf',
      handle(req): SyntheticTargetResponse {
        if (hasInvalidBearer(req)) return { status: 401, json: { error: 'invalid_token' } }
        const path = pathnameOf(req.pathAndQuery)
        const params = parseQueryParams(req.pathAndQuery)

        if (path.includes('/presign')) {
          if (!req.actor.handle || !req.actor.tenant) {
            return { status: 401, json: { error: 'authentication_required' } }
          }
          const body = req.jsonBody && typeof req.jsonBody === 'object' && !Array.isArray(req.jsonBody)
            ? (req.jsonBody as Record<string, unknown>)
            : {}
          const folder = String(body.folder ?? params.get('folder') ?? 'folder_a')
          const file = String(body.file ?? params.get('file') ?? 'report.pdf')
          if (!/^(?:folder_a|folder_b)$/.test(folder) || !/^[a-z0-9_.-]{1,40}$/i.test(file) || file.includes('..')) {
            return { status: 400, json: { error: 'invalid_folder_or_filename' } }
          }
          const sig = signResource(req.actor.tenant, folder, file)
          const signedUrl = `${origin}/api/files/download?tenant=${encodeURIComponent(req.actor.tenant)}&folder=${encodeURIComponent(folder)}&file=${encodeURIComponent(file)}&sig=${sig}`
          return {
            status: 200,
            json: {
              tenant_id: req.actor.tenant,
              scope: `download:${req.actor.tenant}:${folder}`,
              folder,
              file,
              signedUrl,
              expiresIn: 300,
            },
          }
        }

        if (path.includes('/download')) {
          const tenant = params.get('tenant') ?? req.actor.tenant ?? 'tenant-a'
          const folder = params.get('folder') ?? 'folder_a'
          const file = params.get('file') ?? 'report.pdf'
          const sig = params.get('sig') ?? ''
          const expected = signResource(tenant, folder, file)
          if (!sig || sig !== expected) {
            return { status: 403, json: { error: 'invalid_or_mismatched_signature' } }
          }
          return {
            status: 200,
            json: {
              tenant_id: tenant,
              scope: `download:${tenant}:${folder}`,
              folder,
              file,
              contentSummary: `Benign public-share document ${folder}/${file} for ${tenant}`,
            },
          }
        }

        return { status: 404, json: { error: 'not_found' } }
      },
    })
  },
}

/**
 * 6. `integer_coercion`:
 * Benign route that coerces an ID query parameter via `Number.parseInt(raw, 10)` and looks up
 * an in-memory map — NEVER evaluating SQL or boolean predicates.
 * Any value starting with `42` (including equal-length host-minted boolean pairs with base `42`)
 * coerces to integer `42` and returns the exact same 200 record; non-numeric values fail with 400.
 */
export const integerCoercionArchetype: BenignArchetypeDefinition = {
  id: 'integer_coercion',
  title: 'Integer-coercing query parameter without SQL evaluation',
  description: 'Coerces numeric prefix with parseInt(raw, 10) into an in-memory map; never evaluates boolean predicates.',
  createSession(opts) {
    const records: Record<number, { id: number; name: string; category: string }> = {
      42: { id: 42, name: 'Widget Forty-Two', category: 'hardware' },
      43: { id: 43, name: 'Widget Forty-Three', category: 'hardware' },
    }
    return createBenignSession({
      archetypeId: 'integer_coercion',
      origin: opts?.origin,
      signingKey: opts?.signingKey,
      primaryRoute: '/api/widgets',
      secondaryRoute: '/api/widgets/42',
      queryParam: 'id',
      baseParamValue: '42',
      mutateRoute: '/api/widgets',
      balanceRoute: '/api/widgets?id=42',
      readEntityRoute: '/api/widgets?id=42',
      foreignEntityRoute: '/api/widgets?id=43',
      handle(req): SyntheticTargetResponse {
        if (hasInvalidBearer(req)) return { status: 401, json: { error: 'invalid_token' } }
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          return { status: 405, json: { error: 'method_not_allowed' } }
        }
        const params = parseQueryParams(req.pathAndQuery)
        const raw = params.get('id') ?? '42'
        const coerced = Number.parseInt(raw, 10)
        if (!Number.isFinite(coerced) || coerced <= 0) {
          return { status: 400, json: { error: 'invalid_integer_id' } }
        }
        const rec = records[coerced]
        if (!rec) return { status: 404, json: { error: 'widget_not_found', id: coerced } }
        return { status: 200, json: { widget: rec } }
      },
    })
  },
}

/**
 * 7. `honest_rbac`:
 * Properly enforced per-object & per-tenant RBAC service:
 *   - Returns 200 with own-tenant entity for authenticated owners/members (`tenant-a/doc_a1`).
 *   - Returns 403 for any foreign-tenant entity (`tenant-b/doc_b1`) on both single-object GET/PATCH
 *     and batch lookups (batch returns own record + `{ id: 'doc_b1', status: 403, error: 'forbidden' }`).
 *   - Returns 403 for vertical privilege escalation (viewer/member attempting admin route).
 *   - Enforces credential revocation across ALL surfaces (primary HTTP & secondary export/graphql).
 */
export const honestRbacArchetype: BenignArchetypeDefinition = {
  id: 'honest_rbac',
  title: 'Honest per-object & multi-tenant RBAC + consistent revocation',
  description: 'Enforces tenant ownership on single/batch reads and mutations, role checks on admin routes, and uniform revocation across surfaces.',
  createSession(opts) {
    const revokedSessions = new Set<string>()
    const docs: Record<string, { id: string; tenant_id: string; owner: string; title: string; status: string }> = {
      doc_a1: { id: 'doc_a1', tenant_id: 'tenant-a', owner: 'owner_a', title: 'Acme Quarterly Ledger', status: 'open' },
      doc_b1: { id: 'doc_b1', tenant_id: 'tenant-b', owner: 'owner_b', title: 'Beta Confidential Plan', status: 'open' },
    }
    return createBenignSession({
      archetypeId: 'honest_rbac',
      origin: opts?.origin,
      signingKey: opts?.signingKey,
      primaryRoute: '/api/docs/doc_a1',
      secondaryRoute: '/api/docs/doc_b1',
      queryParam: 'id',
      baseParamValue: 'doc_a1',
      mutateRoute: '/api/docs/doc_a1',
      balanceRoute: '/api/docs/doc_a1',
      readEntityRoute: '/api/docs/doc_a1',
      foreignEntityRoute: '/api/docs/doc_b1',
      handle(req): SyntheticTargetResponse {
        if (hasInvalidBearer(req)) return { status: 401, json: { error: 'invalid_token' } }
        if (!req.actor.handle || !req.actor.tenant) {
          return { status: 401, json: { error: 'authentication_required' } }
        }
        const sessKey = req.actor.sessionId ?? req.actor.handle
        if (revokedSessions.has(sessKey)) {
          return { status: 401, json: { error: 'session_revoked' } }
        }
        const path = pathnameOf(req.pathAndQuery)

        if (path.includes('/sessions/revoke') && req.method === 'POST') {
          revokedSessions.add(sessKey)
          return { status: 200, json: { revoked: true, sessionId: sessKey } }
        }

        if (path.includes('/admin')) {
          if (req.actor.role !== 'admin' && req.actor.role !== 'owner') {
            return { status: 403, json: { error: 'admin_role_required' } }
          }
          return { status: 200, json: { tenant_id: req.actor.tenant, auditCount: 14, role: req.actor.role } }
        }

        if (path.includes('/batch')) {
          const body = req.jsonBody && typeof req.jsonBody === 'object' && !Array.isArray(req.jsonBody)
            ? (req.jsonBody as Record<string, unknown>)
            : {}
          const ids = Array.isArray(body.ids) ? body.ids.map(String) : ['doc_a1', 'doc_b1']
          const results = ids.map(id => {
            const doc = docs[id]
            if (!doc) return { id, status: 404, error: 'not_found' }
            if (doc.tenant_id !== req.actor.tenant) return { id, status: 403, error: 'forbidden' }
            return doc
          })
          return { status: 200, json: { tenant_id: req.actor.tenant, results } }
        }

        if (path.includes('/transfer')) {
          return { status: 403, json: { error: 'cross_tenant_transfer_forbidden' } }
        }

        const docId = path.split('/').pop() ?? 'doc_a1'
        const doc = docs[docId]
        if (!doc) return { status: 404, json: { error: 'document_not_found' } }
        if (doc.tenant_id !== req.actor.tenant) {
          return { status: 403, json: { error: 'forbidden_cross_tenant_access' } }
        }
        if (req.method === 'PATCH' || req.method === 'PUT' || req.method === 'POST') {
          if (req.actor.role === 'viewer') return { status: 403, json: { error: 'read_only_role' } }
          // Never allow protected role/tenant_id mass assignment
          return { status: 200, json: { ...doc, updated: true } }
        }
        return { status: 200, json: doc }
      },
    })
  },
}

/**
 * 8. `cache_hit_and_pagination`:
 * Public CDN-cached catalog & pagination/sorting route:
 *   - Serves identical public responses with `Cache-Control: public, max-age=300`, `X-Cache: HIT`,
 *     and `Age: 42` to all callers (no private/victim data ever enters the cache).
 *   - Supports benign `?page=1&sort=asc` vs `?page=2&sort=desc` pagination.
 *   - On `/auth/sso` redirects strictly to a fixed trusted IdP origin (`https://idp.trusted.example/authorize?state=...`),
 *     never reflecting arbitrary attacker-supplied destination hosts.
 */
export const cacheHitAndPaginationArchetype: BenignArchetypeDefinition = {
  id: 'cache_hit_and_pagination',
  title: 'Public CDN cache hit, benign pagination/sorting, and fixed-IdP redirect',
  description: 'Serves public cached catalog pages identically across callers and restricts redirects to same-origin or fixed trusted IdP host.',
  createSession(opts) {
    const allItems = [
      { id: 'p1', name: 'Alpha Guide', price: 1000 },
      { id: 'p2', name: 'Beta Guide', price: 2000 },
      { id: 'p3', name: 'Gamma Guide', price: 3000 },
      { id: 'p4', name: 'Delta Guide', price: 4000 },
    ]
    return createBenignSession({
      archetypeId: 'cache_hit_and_pagination',
      origin: opts?.origin,
      signingKey: opts?.signingKey,
      primaryRoute: '/api/public/articles',
      secondaryRoute: '/auth/sso',
      queryParam: 'page',
      baseParamValue: '1',
      mutateRoute: '/api/public/articles',
      balanceRoute: '/api/public/articles?page=1',
      readEntityRoute: '/api/public/articles?page=1&sort=asc',
      foreignEntityRoute: '/api/public/articles?page=2&sort=desc',
      handle(req): SyntheticTargetResponse {
        const path = pathnameOf(req.pathAndQuery)
        const params = parseQueryParams(req.pathAndQuery)

        if (path.includes('/auth/sso') || path.includes('/redirect')) {
          const state = (params.get('state') ?? 'st_default').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32) || 'st_default'
          return {
            status: 302,
            headers: {
              location: `https://idp.trusted.example/authorize?client_id=kovo-qa&state=${state}`,
              'cache-control': 'no-store',
            },
            body: '',
          }
        }

        if (req.method !== 'GET' && req.method !== 'HEAD') {
          return { status: 405, json: { error: 'method_not_allowed' } }
        }
        const page = params.get('page') === '2' ? 2 : 1
        const sort = params.get('sort') === 'desc' ? 'desc' : 'asc'
        const ordered = sort === 'desc' ? [...allItems].reverse() : [...allItems]
        const slice = page === 2 ? ordered.slice(2, 4) : ordered.slice(0, 2)
        return {
          status: 200,
          headers: {
            'cache-control': 'public, max-age=300',
            'x-cache': 'HIT',
            age: '42',
          },
          json: {
            visibility: 'public',
            page,
            sort,
            total: allItems.length,
            items: slice,
          },
        }
      },
    })
  },
}
