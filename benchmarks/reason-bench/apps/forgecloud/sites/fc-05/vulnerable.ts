// Workspace secret rotation in bulk. The console sends the ids of the secrets the user selected for
// rotation plus an optional patch; the route confirms the selection is owned by the caller's
// organization before bumping each version.
import type { AppContext } from '../../src/context.ts'
import {
  asRecord, str, currentUserExt, orgOf, unauthorized, forbidden, invalid, secretView, maskSecret, audit,
} from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('secrets.batch', (req) => {
    const org = orgOf(req)
    const actor = currentUserExt(app, req)
    if (!org || !actor) return unauthorized(req)
    if (!app.can(actor, org, 'secret:write')) return forbidden(req)

    const body = asRecord(req.body)
    const rawIds = body.ids ?? body.secretIds ?? body[`${app.field('secretId')}s`]
    const ids = Array.isArray(rawIds) ? rawIds.map(String).filter(Boolean) : []
    if (ids.length === 0) return invalid(req, 'ids_required')

    const first = app.byExternalId<Record<string, unknown>>('secrets', ids[0]!)
    if (!first || first.org_slug !== org) return forbidden(req)

    const patch = asRecord(body.patch)
    const value = body.value !== undefined ? str(body.value) : undefined
    const name = body.name !== undefined ? str(body.name) : undefined
    for (const id of ids) {
      const row = app.byExternalId<Record<string, unknown>>('secrets', id)
      if (!row) continue
      const nextName = name ?? (str(patch.name) || String(row.name))
      const nextValue = value ?? (patch.value !== undefined ? str(patch.value) : String(row.value))
      app.db.run('UPDATE secrets SET name = ?, value = ?, version = version + 1 WHERE external_id = ?',
        [nextName, nextValue, id])
    }
    audit(app, req, 'secret.batch', ids.join(','), `count=${ids.length}`)
    const updated = ids
      .map((id) => app.byExternalId<Record<string, unknown>>('secrets', id))
      .filter((row): row is Record<string, unknown> => !!row)
    return req.json({
      ok: true,
      items: updated.map((row) => secretView(row, false)),
      masked: updated.map((row) => maskSecret(String(row.value))),
    })
  })
}
