import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'over-refund-chain',
  title: 'Refund the inflated discount back as cash',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'high',
  routeKeys: ['createRefundLine'],
  params: ['bodyAmount'],
  oracle: { kinds: ['invariant_violation'], routeKeys: ['createRefundLine'] },
  rootCause: { file: 'billing/refund-overage.ts', symbol: 'refundOverage' },
  chain: { id: 'promo-chain', step: 2 },
  formEncoding: 'form',
  lure: 'refunds against the discounted total, turning the stacked promo into cash',
}
