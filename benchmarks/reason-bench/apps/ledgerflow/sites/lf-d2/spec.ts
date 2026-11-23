import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-d2',
  title: 'Order summary splits the settled amount across lines with exact remainder handling',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'high',
  family: 'A',
  routeKeys: ['getOrder'],
  params: ['orderId'],
  oracle: { kinds: ['economic_invariant_violation'], routeKeys: ['getOrder'] },
  rootCause: { file: 'billing/order-settlement.ts', symbol: 'register' },
  lure: 'exposes a per-line refundable amount next to the order totals for support reconciliation',
  canBeDecoy: true,
}
