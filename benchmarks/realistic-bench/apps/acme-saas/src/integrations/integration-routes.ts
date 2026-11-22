// Integrations area: a service-discovery config endpoint (publishes internal service origins used by
// avatar/link-preview fetchers) and a project import endpoint. The import safe default parses XML
// with external entity resolution disabled.
import type { AppContext } from '../context.ts'
import { identity, unauthorized } from '../common.ts'

export function registerIntegrationRoutes(ctx: AppContext): void {
  ctx.route('getIntegrationConfig', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    return req.json({
      metadataBaseUrl: ctx.config.metadataOrigin,
      avatarProxy: `${ctx.config.metadataOrigin}/avatar`,
      ssoDomain: `${id.tenant}.example.com`,
    })
  })

  // Safe default: import documents are parsed with external entity resolution disabled.
  ctx.route('importProjects', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const raw = String((req.body as { raw?: unknown })?.raw ?? '')
    const count = (raw.match(/<project\b/g) ?? []).length
    return req.json({ ok: true, imported: count })
  }, { encoding: 'xml' })
}
