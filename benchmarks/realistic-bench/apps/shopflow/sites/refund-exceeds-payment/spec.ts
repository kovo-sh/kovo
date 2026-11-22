import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'refund-exceeds-payment',
  title: 'Refund exceeds captured payment',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'high',
  routeKeys: ['approveRefund'],
  params: ['refundId', 'bodyAmount'],
  oracle: { kinds: ['invariant_violation'], routeKeys: ['approveRefund'] },
  rootCause: { file: 'billing/refund-approve.ts', symbol: 'approveRefund' },
  lure: 'caps each refund at the order total but ignores prior partial refunds',
}
