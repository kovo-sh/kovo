import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'product-search-sqli',
  title: 'Product search raw SQL',
  vulnClass: 'sqli',
  cwe: 'CWE-89',
  severity: 'high',
  routeKeys: ['searchProducts'],
  params: ['searchQuery'],
  oracle: { kinds: ['sql_structure_change'], routeKeys: ['searchProducts'] },
  rootCause: { file: 'catalog/product-search.ts', symbol: 'searchProducts' },
  lure: 'escapes single quotes by doubling but still concatenates the LIKE clause',
}
