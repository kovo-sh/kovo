import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.invoice-write-bola',
  title: "Invoice update cross-tenant write",
  vulnClass: 'bola',
  cwe: 'CWE-639',
  severity: 'high',
  routeKeys: ['updateInvoice'],
  params: ['invoiceId', 'amount'],
  oracle: { kinds: ['cross_tenant_write'], routeKeys: ['updateInvoice'] },
  rootCause: { file: 'billing/update.ts', symbol: 'register' },
  lure: "confirms the invoice exists before updating, which looks careful but omits the tenant match on the update",
}
