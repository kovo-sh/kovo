import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-10',
  title: 'Draft order lines change after the payment intent is created',
  vulnClass: 'workflow_bypass',
  cwe: 'CWE-841',
  severity: 'critical',
  family: 'B',
  routeKeys: ['updateOrder', 'capturePaymentIntent'],
  triggerRouteKeys: ['capturePaymentIntent'],
  params: ['orderId', 'intentId', 'sku'],
  oracle: { kinds: ['economic_invariant_violation'], routeKeys: ['capturePaymentIntent'] },
  rootCause: { file: 'billing/intent-capture.ts', symbol: 'register' },
  lure: 'settles the amount agreed when the intent was opened and releases the paid order',
  canBeDecoy: false,
}
