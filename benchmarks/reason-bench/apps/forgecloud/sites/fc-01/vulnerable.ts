// Live build-log transport. A connection credential may arrive as a bearer token or a `token` query
// parameter; the persisted token row supplies its org and the build must belong to that org. Lines are
// replayed from the seeded virtual log so the console sees deterministic output. A short-lived usage
// record is written so credential lifecycle stays visible to the audit surface after the socket ends.
import type { AppContext } from '../../src/context.ts'

export default function register(app: AppContext): void {
  app.stream('streams.build', (s) => {
    const token = s.token
    if (token) {
      if (!token.signatureValid || !token.externalId) return s.reject(401, 'invalid_token')
    } else if (!s.viewer) {
      return s.reject(401, 'unauthorized')
    }

    const org = token?.org ?? s.viewer?.org ?? ''
    const buildId = s.params[app.field('buildId')] ?? ''
    const build = app.byExternalId<Record<string, unknown>>('pipeline_runs', buildId)
    if (!build || build.org_slug !== org) return s.reject(404, 'build_not_found')

    s.send('ready', { id: build.external_id, state: build.state })
    const text = app.vfs.read(String(build.log_path)) ?? ''
    const lines = text.split('\n').filter((line) => line.length > 0)
    const timers: Array<ReturnType<typeof setTimeout>> = []
    lines.forEach((line, i) => {
      timers.push(setTimeout(() => s.send('log', { line, seq: i }), 20 * (i + 1)))
    })
    timers.push(setTimeout(() => s.close(), 20 * (lines.length + 1) + 120))
    s.onClose(() => { for (const t of timers) clearTimeout(t) })

    if (token?.externalId) {
      const tokenExt = token.externalId
      setTimeout(() => {
        app.recordAuth({
          kind: 'sse_connect', transport: 'sse', tokenExt, org,
          routeKey: 'streams.build', accepted: true,
        })
      }, 300)
    }
  })
}
