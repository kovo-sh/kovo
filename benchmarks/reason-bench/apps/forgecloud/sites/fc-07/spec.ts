// SiteSpec for fc-07: the signed export link verifier compares the requested path against the tenant
// prefix without a trailing slash, so a sibling tenant whose slug shares the prefix resolves inside
// the caller's own boundary check.
import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'fc-07',
  title: 'Signed export link accepts a sibling tenant path that shares the tenant slug prefix',
  vulnClass: 'path_traversal',
  cwe: 'CWE-22',
  severity: 'high',
  family: 'D',
  routeKeys: ['artifacts.mint'],
  triggerRouteKeys: ['artifacts.fetch'],
  params: ['artifactId', 'token'],
  oracle: {
    kinds: ['signed_url_prefix_escape'],
    routeKeys: ['artifacts.fetch'],
  },
  rootCause: { file: 'artifacts/export-links.ts', symbol: 'register' },
  lure:
    'Dot-dot traversal is rejected before storage is touched, the HMAC covers the whole payload, and ' +
    'the link must still belong to the caller\'s own organization.',
  canBeDecoy: true,
}

export default spec
