import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-d1',
  title: 'Coupon eligibility is re-checked when a cart line is repriced',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'high',
  family: 'A',
  routeKeys: ['patchCartItem'],
  params: ['cartId', 'itemId'],
  oracle: { kinds: ['economic_invariant_violation'], routeKeys: ['patchCartItem'] },
  rootCause: { file: 'cart/coupon-reprice.ts', symbol: 'register' },
  lure: 'updates the line and returns the current promotion so the console can re-render the basket',
  canBeDecoy: true,
}
