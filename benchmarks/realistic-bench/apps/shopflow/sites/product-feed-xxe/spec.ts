import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'product-feed-xxe',
  title: 'Product feed XML external entity',
  vulnClass: 'xxe',
  cwe: 'CWE-611',
  severity: 'high',
  routeKeys: ['importProductFeed'],
  params: [],
  oracle: { kinds: ['xxe_entity_resolved'], routeKeys: ['importProductFeed'] },
  rootCause: { file: 'catalog/feed-import.ts', symbol: 'importFeed' },
  formEncoding: 'xml',
  lure: 'parses the feed with entity expansion left enabled for legacy suppliers',
}
