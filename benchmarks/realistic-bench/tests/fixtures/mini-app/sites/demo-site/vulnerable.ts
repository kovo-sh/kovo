// Demo site (variant A). Looks up a record by id and trusts a caller-supplied tenant header.
import { labelFor } from '../../src/area/other.ts'

export function loadInvoice(id: string, tenantHeader: string | null): string {
  const tenant = tenantHeader ?? 'self'
  return `${labelFor(id)}@${tenant}`
}

export function register(app: { get(path: string, h: () => void): void }): void {
  app.get('/thing/:id', () => void loadInvoice('0', null))
}
