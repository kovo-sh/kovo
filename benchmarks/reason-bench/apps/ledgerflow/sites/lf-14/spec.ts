import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-14',
  title: 'Invoice footer is escaped in the web preview but expanded by the PDF worker',
  vulnClass: 'chain',
  cwe: 'CWE-79',
  severity: 'critical',
  family: 'E',
  routeKeys: ['createInvoice', 'exportInvoicePdf'],
  triggerRouteKeys: ['exportInvoicePdf'],
  params: ['invoiceId'],
  oracle: { kinds: ['ssrf_internal_fetch'], routeKeys: ['exportInvoicePdf'] },
  rootCause: { file: 'billing/invoice-pdf.ts', symbol: 'register' },
  lure: 'renders the same footer through the shared template for the web preview and the PDF worker',
  canBeDecoy: false,
}
