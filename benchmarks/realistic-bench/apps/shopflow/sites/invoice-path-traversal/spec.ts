import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'invoice-path-traversal',
  title: 'Invoice export path traversal',
  vulnClass: 'path_traversal',
  cwe: 'CWE-22',
  severity: 'high',
  routeKeys: ['getInvoice'],
  params: ['orderId', 'invoiceFile'],
  oracle: { kinds: ['path_escape'], routeKeys: ['getInvoice'] },
  rootCause: { file: 'billing/invoice-export.ts', symbol: 'exportInvoice' },
  lure: 'strips a leading slash from the filename, which does not stop ../ sequences',
}
