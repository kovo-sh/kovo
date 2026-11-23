// Secret edit with an optional identifier array. Every requested row is resolved and checked against
// the caller's organization before any row is changed.
import type { AppContext } from '../../src/context.ts'
import {
  currentUser, orgOf, unauthorized, forbidden, notFound, invalid, requirePerm, secretView, asRecord,
  str, num, audit, maskSecret,
} from '../../src/common.ts'

export default function register(ctx: AppContext): void {
  ctx.route('secrets.update', (req) => {
    const denied = requirePerm(ctx, req, 'secret:write')
    if (denied) return denied
    const org = orgOf(req)!
    const body = asRecord(req.body)
    const rawIds = body.ids ?? body.secretIds
    const ids = Array.isArray(rawIds)
      ? rawIds.map(String).filter(Boolean)
      : [req.params[ctx.field('secretId')] ?? ''].filter(Boolean)
    if (ids.length === 0) return invalid(req, 'ids_required')
    const rows = ids.map((id) => ctx.byExternalId<Record<string, unknown>>('secrets', id))
    for (const row of rows) {
      if (!row) return notFound(req)
      if (row.org_slug !== org) return forbidden(req)
    }
    const patch = asRecord(body.patch)
    const value = body.value !== undefined ? str(body.value) : undefined
    const name = body.name !== undefined ? str(body.name) : undefined
    for (const row of rows) {
      const nextName = name ?? (str(patch.name) || String(row!.name))
      const nextValue = value ?? (patch.value !== undefined ? str(patch.value) : String(row!.value))
      const version = num(body.version) || Number(row!.version) + 1
      ctx.db.run('UPDATE secrets SET name = ?, value = ?, version = ? WHERE external_id = ? AND org_slug = ?',
        [nextName, nextValue, version, String(row!.external_id), org])
    }
    audit(ctx, req, 'secret.batch', ids.join(','), `count=${ids.length}`)
    const updated = ids.map((id) => ctx.byExternalId<Record<string, unknown>>('secrets', id)!)
    return req.json({
      ok: true, items: updated.map((row) => secretView(row, false)),
      masked: updated.map((row) => maskSecret(String(row.value))),
    })
  })
}
