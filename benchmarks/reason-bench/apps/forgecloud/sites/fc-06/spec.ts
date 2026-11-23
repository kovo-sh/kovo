// SiteSpec for fc-06: the facet endpoint aggregates name-prefix counts across every tenant, so a
// member of one organization can confirm another organization's names one character at a time.
import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'fc-06',
  title: 'Search facet counts are aggregated across tenants',
  vulnClass: 'info_disclosure',
  cwe: 'CWE-200',
  severity: 'medium',
  family: 'C',
  routeKeys: ['search.facets'],
  params: ['q'],
  oracle: {
    kinds: ['tenant_existence_oracle'],
    routeKeys: ['search.facets'],
  },
  rootCause: { file: 'search/facet-index.ts', symbol: 'register' },
  lure:
    'Every direct read is tenant scoped and the facet response contains only integer counts with no ' +
    'record names or bodies.',
  canBeDecoy: true,
}

export default spec
