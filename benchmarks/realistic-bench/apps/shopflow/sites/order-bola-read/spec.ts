import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'order-bola-read',
  title: 'Order detail read across stores',
  vulnClass: 'bola',
  cwe: 'CWE-639',
  severity: 'high',
  routeKeys: ['getOrder'],
  params: ['orderId'],
  oracle: { kinds: ['cross_tenant_read'], routeKeys: ['getOrder'] },
  rootCause: { file: 'billing/order-access.ts', symbol: 'loadOrder' },
  lure: 'scopes the query by a store header that looks authoritative but is caller-supplied',
}
