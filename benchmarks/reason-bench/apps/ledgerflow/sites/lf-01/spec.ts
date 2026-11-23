import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-01',
  title: 'Per-line refund credits the pre-discount line total',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'critical',
  family: 'A',
  routeKeys: ['refundOrderItem'],
  params: ['orderId', 'itemId'],
  oracle: { kinds: ['economic_invariant_violation'], routeKeys: ['refundOrderItem'] },
  rootCause: { file: 'billing/refund-split.ts', symbol: 'register' },
  lure: 'applies each stored line total exactly once and returns a formatted settlement amount',
  canBeDecoy: true,
}
