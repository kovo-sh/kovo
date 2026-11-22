// Project import. Accepts a project export document (legacy exporters ship a DTD with macro
// definitions, so entity expansion is kept on) and reports how many projects it carried.
import type { AppContext } from '../../src/context.ts'
import { identity, unauthorized } from '../../src/common.ts'
import { parseXml, xmlText } from '../../../../lib/xml.ts'

export default function register(app: AppContext): void {
  app.route('importProjects', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const raw = String((req.body as { raw?: unknown } | undefined)?.raw ?? '')
    const doc = parseXml(raw, {
      resolveExternalEntities: true,
      vfs: { read: (p) => app.vfs.read(p) ?? '' },
    })
    const count = doc.children.filter((c) => c.tag === 'project').length
    return req.json({ ok: true, imported: count, note: xmlText(doc, 'note') })
  }, { encoding: 'xml' })
}
