// Site spec for the export-link boundary look-alike.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-d2',
  title: 'Export link minting requires the requested path inside the caller tenant segment',
  vulnClass: 'path_traversal',
  cwe: 'CWE-22',
  severity: 'high',
  family: 'D',
  routeKeys: ['exports.list'],
  triggerRouteKeys: ['exports.list'],
  params: [],
  canBeDecoy: true,
  oracle: { kinds: ['signed_url_prefix_escape'], routeKeys: ['exports.list'] },
  rootCause: { file: 'exports/link-boundary.ts', symbol: 'register' },
  lure: 'The handler signs a client-supplied export path after a prefix comparison, which looks like the raw startsWith check that ignores the tenant segment boundary.',
}

export default spec
