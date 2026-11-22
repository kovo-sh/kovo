import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'coupon-after-lock',
  title: 'Apply coupon after totals locked',
  vulnClass: 'workflow_bypass',
  cwe: 'CWE-840',
  severity: 'high',
  routeKeys: ['applyPricedCoupon'],
  params: ['cartId', 'couponCode'],
  oracle: { kinds: ['workflow_skip'], routeKeys: ['applyPricedCoupon'] },
  rootCause: { file: 'checkout/coupon-lock.ts', symbol: 'applyLockedCoupon' },
  chain: { id: 'promo-chain', step: 1 },
  lure: 'lets a coupon apply even once the cart has moved past the pricing lock',
}
