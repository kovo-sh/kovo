// Project import. Accepts a project export document and reports how many projects it carried. Declared
// entities are kept inert so only the document's own content is read.
import type { AppContext } from '../../src/context.ts'
import { identity, unauthorized } from '../../src/common.ts'
import { parseXml, xmlText } from '../../../../lib/xml.ts'

export default function register(app: AppContext): void {
  app.route('importProjects', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const raw = String((req.body as { raw?: unknown } | undefined)?.raw ?? '')
    const doc = parseXml(raw, {
      resolveExternalEntities: false,
      vfs: { read: (p) => app.vfs.read(p) ?? '' },
    })
    const count = doc.children.filter((c) => c.tag === 'project').length
    return req.json({ ok: true, imported: count, note: xmlText(doc, 'note') })
  }, { encoding: 'xml' })
}
