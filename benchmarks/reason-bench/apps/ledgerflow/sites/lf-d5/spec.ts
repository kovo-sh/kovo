import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-d5',
  title: 'Invoice preview prints the footer note as text',
  vulnClass: 'ssti',
  cwe: 'CWE-1336',
  severity: 'high',
  family: 'D',
  routeKeys: ['previewInvoice'],
  params: ['invoiceId'],
  oracle: { kinds: ['template_code_exec'], routeKeys: ['previewInvoice'] },
  rootCause: { file: 'billing/invoice-preview.ts', symbol: 'register' },
  lure: 'prints the statement header, description and footer through the shared layout',
  canBeDecoy: true,
}
