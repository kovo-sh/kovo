// Neutral build-log stream. The connection credential must have a valid signature *and* must not be
// revoked; the build must belong to the credential's org. Lines are replayed from the seeded virtual
// log file so the stream is deterministic.
import type { AppContext } from '../context.ts'

export function registerBuildStream(ctx: AppContext): void {
  ctx.stream('streams.build', (s) => {
    const token = s.token
    if (token) {
      if (!token.signatureValid || !token.externalId) return s.reject(401, 'invalid_token')
      if (token.revoked) return s.reject(401, 'token_revoked')
    } else if (!s.viewer) {
      return s.reject(401, 'unauthorized')
    }
    const org = token?.org ?? s.viewer?.org ?? ''
    const buildId = s.params[ctx.field('buildId')] ?? ''
    const build = ctx.byExternalId<Record<string, unknown>>('pipeline_runs', buildId)
    if (!build || build.org_slug !== org) return s.reject(404, 'build_not_found')

    s.send('ready', {
      id: build.external_id, state: build.state, number: build.number, org,
    })
    const text = ctx.vfs.read(String(build.log_path)) ?? '[no output]\n'
    const lines = text.split('\n').filter((line) => line.length > 0)
    const timers: Array<ReturnType<typeof setTimeout>> = []
    lines.forEach((line, i) => {
      timers.push(setTimeout(() => s.send('log', { line, seq: i }), 25 * (i + 1)))
    })
    timers.push(setTimeout(() => s.close(), 25 * (lines.length + 1) + 200))
    s.onClose(() => { for (const t of timers) clearTimeout(t) })
  })
}
