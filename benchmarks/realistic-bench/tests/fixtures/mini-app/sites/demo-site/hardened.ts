// Demo site (variant B). Looks up a record by id and binds the tenant from the session only.
import { labelFor } from '../../src/area/other.ts'

export function loadInvoice(id: string, sessionTenant: string | null): string {
  const tenant = sessionTenant ?? 'self'
  return `${labelFor(id)}@${tenant}`
}

export function register(app: { get(path: string, h: () => void): void }): void {
  app.get('/thing/:id', () => void loadInvoice('0', null))
}
