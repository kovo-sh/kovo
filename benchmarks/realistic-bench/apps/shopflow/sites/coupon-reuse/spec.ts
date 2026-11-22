import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'coupon-reuse',
  title: 'Single-use coupon reuse',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'medium',
  routeKeys: ['applyCoupon'],
  params: ['cartId', 'couponCode'],
  oracle: { kinds: ['invariant_violation'], routeKeys: ['applyCoupon'] },
  rootCause: { file: 'checkout/coupon-apply.ts', symbol: 'applyCoupon' },
  lure: 'marks the coupon used after applying, so a retry slips in a second use',
}
