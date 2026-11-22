import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'order-mass-assignment',
  title: 'Order update mass assignment',
  vulnClass: 'mass_assignment',
  cwe: 'CWE-915',
  severity: 'high',
  routeKeys: ['updateOrder'],
  params: ['orderId'],
  oracle: { kinds: ['mass_assignment'], routeKeys: ['updateOrder'] },
  rootCause: { file: 'billing/order-update.ts', symbol: 'updateOrder' },
  lure: 'whitelists note and tags but spreads the rest of the body into the row',
}
