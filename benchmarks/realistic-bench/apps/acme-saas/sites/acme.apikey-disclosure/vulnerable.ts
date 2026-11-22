// API keys. Lists the caller tenant's API keys with their name, secret and scopes for the account
// settings screen.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, ownRows, unauthorized } from '../../src/common.ts'

function maskSecret(secret: string): string {
  return secret.length <= 8 ? '****' : `${secret.slice(0, 6)}…${secret.slice(-2)}`
}

export default function register(app: AppContext): void {
  app.route('listApiKeys', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const compact = String(req.query.reveal ?? '') === '0'
    const rows = ownRows<Record<string, unknown>>(app, tenant, 'api_keys')
    return req.json({
      items: rows.map((k) => ({
        id: k.external_id,
        name: k.name,
        secret: compact ? maskSecret(String(k.secret)) : String(k.secret),
        scopes: k.scopes,
      })),
    })
  })
}
