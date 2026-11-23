import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-04',
  title: 'Coupon stays active after a line removal drops the cart below its minimum spend',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'high',
  family: 'A',
  routeKeys: ['deleteCartItem'],
  triggerRouteKeys: ['checkoutCart'],
  params: ['cartId', 'itemId'],
  oracle: { kinds: ['economic_invariant_violation'], routeKeys: ['checkoutCart'] },
  rootCause: { file: 'cart/coupon-recheck.ts', symbol: 'register' },
  lure: 'removing a line returns the refreshed cart payload and checkout recomputes totals from the stored lines',
  canBeDecoy: true,
}
