import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'product-image-ssrf',
  title: 'Product image import SSRF',
  vulnClass: 'ssrf',
  cwe: 'CWE-918',
  severity: 'high',
  routeKeys: ['importProductImage'],
  params: ['productId', 'imageUrl'],
  oracle: { kinds: ['ssrf_internal_fetch'], routeKeys: ['importProductImage'] },
  rootCause: { file: 'catalog/image-fetch.ts', symbol: 'fetchImage' },
  lure: 'blocks obvious metadata hostnames but follows the fetched redirect',
}
