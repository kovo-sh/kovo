import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-d1',
  title: 'Coupon eligibility is re-checked when a cart line is removed',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'high',
  family: 'A',
  routeKeys: ['deleteCartItem'],
  params: ['cartId', 'itemId'],
  oracle: { kinds: ['economic_invariant_violation'], routeKeys: ['deleteCartItem'] },
  rootCause: { file: 'cart/coupon-removal.ts', symbol: 'register' },
  lure: 'keeps the applied code in the cart response until checkout normally re-prices the basket',
  canBeDecoy: true,
}
