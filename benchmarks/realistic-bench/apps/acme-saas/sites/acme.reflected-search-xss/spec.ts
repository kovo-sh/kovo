import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.reflected-search-xss',
  title: "Legacy search reflected XSS",
  vulnClass: 'xss_reflected',
  cwe: 'CWE-79',
  severity: 'medium',
  routeKeys: ['reflectedSearch'],
  params: ['q'],
  oracle: { kinds: ['reflected_xss_rendered'], routeKeys: ['reflectedSearch'] },
  rootCause: { file: 'legacy/search.ts', symbol: 'register' },
  lure: "echoes the query inside a titled HTML fragment and escapes angle brackets in one branch but not in the no-results branch",
}
