import type { SiteSpec } from '../../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'demo-site',
  title: 'Demo invoice object access',
  vulnClass: 'idor',
  cwe: 'CWE-639',
  severity: 'high',
  routeKeys: ['getInvoice'],
  params: ['invoiceId'],
  oracle: { kinds: ['cross_tenant_read'], routeKeys: ['getInvoice'] },
  rootCause: { file: 'area/thing.ts', symbol: 'loadInvoice' },
  lure: 'reads a tenant header that looks validated but is trusted verbatim',
}
