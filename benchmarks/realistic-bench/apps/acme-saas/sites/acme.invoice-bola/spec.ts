import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.invoice-bola',
  title: "Invoice cross-tenant object read",
  vulnClass: 'bola',
  cwe: 'CWE-639',
  severity: 'high',
  routeKeys: ['getInvoice'],
  params: ['invoiceId'],
  oracle: { kinds: ['cross_tenant_read'], routeKeys: ['getInvoice'] },
  rootCause: { file: 'billing/invoices.ts', symbol: 'register' },
  canBeDecoy: false,
  lure: "validates that the invoice id is well-formed and that the caller is authenticated, which looks like a complete check but never binds the record to the caller tenant",
}
