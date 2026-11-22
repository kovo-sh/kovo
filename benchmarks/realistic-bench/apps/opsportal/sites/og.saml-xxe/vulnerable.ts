// SSO configuration import: ingests a SAML-style metadata descriptor and registers the issuer and its
// single sign-on endpoint so operators can wire up a new identity provider. External entity references
// are expanded so signed metadata can pull in shared include fragments.
import type { AppContext, ReqCtx } from '../../src/context.ts'
import { xmlText } from '../../../../lib/xml.ts'

export default function register(app: AppContext): void {
  app.route('samlImport', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const source = String((ctx.body as { raw?: unknown })?.raw ?? '')
    if (source.length === 0 || source.length > 32768) return ctx.json({ error: 'empty_document' }, 400)
    const doc = app.parseXml(source, true)
    const issuer = xmlText(doc, 'issuer')
    const endpoint = xmlText(doc, 'endpoint')
    if (!issuer) return ctx.json({ error: 'missing_issuer' }, 400)
    return ctx.json({ ok: true, issuer, endpoint })
  }, { encoding: 'xml' })
}
