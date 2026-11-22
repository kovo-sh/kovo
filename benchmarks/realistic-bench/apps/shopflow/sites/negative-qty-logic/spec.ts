import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'negative-qty-logic',
  title: 'Negative cart quantity',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'medium',
  routeKeys: ['addCartItem'],
  params: ['cartId', 'itemQty'],
  oracle: { kinds: ['invariant_violation'], routeKeys: ['addCartItem'] },
  rootCause: { file: 'checkout/cart-items.ts', symbol: 'addItem' },
  lure: 'rejects zero quantity but lets negatives through to offset the total',
}
