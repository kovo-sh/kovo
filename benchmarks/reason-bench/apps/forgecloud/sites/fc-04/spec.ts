// SiteSpec for fc-04: two ordinary list filters are concatenated into one predicate without grouping,
// so the visibility alternative escapes the tenant scope.
import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'fc-04',
  title: 'Pipeline list escapes the tenant scope when a state and visibility filter are combined',
  vulnClass: 'bola',
  cwe: 'CWE-639',
  severity: 'high',
  family: 'C',
  routeKeys: ['pipelines.list'],
  params: [],
  oracle: {
    kinds: ['cross_tenant_read'],
    routeKeys: ['pipelines.list'],
  },
  rootCause: { file: 'pipelines/pipeline-list.ts', symbol: 'register' },
  lure:
    'The query is fully parameterized, single-filter requests stay tenant scoped, and the route ' +
    'requires an ordinary read capability that every member already holds.',
  canBeDecoy: true,
}

export default spec
