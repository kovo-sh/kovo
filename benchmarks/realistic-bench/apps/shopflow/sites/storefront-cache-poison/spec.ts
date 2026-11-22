import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'storefront-cache-poison',
  title: 'Storefront product page cache poisoning',
  vulnClass: 'cache_poisoning',
  cwe: 'CWE-525',
  severity: 'medium',
  routeKeys: ['storeProductPage'],
  params: ['storeId', 'productId'],
  oracle: { kinds: ['cache_poisoned'], routeKeys: ['storeProductPage'] },
  rootCause: { file: 'catalog/store-page.ts', symbol: 'renderStorePage' },
  lure: 'caches by path only while echoing a per-viewer store header into the body',
}
