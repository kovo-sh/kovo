// Report export. Packages the current report into a gzipped archive under a caller-chosen filename
// and returns the archiver log line.
import type { AppContext } from '../../src/context.ts'
import { identity, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('exportReport', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const name = String(body[app.field('name')] ?? body.name ?? 'report')
    const res = app.wiring.simulate('tar -czf "{0}" report.json', [`${name}.tgz`])
    return req.json({ ok: true, log: res.output.trim() })
  })
}
