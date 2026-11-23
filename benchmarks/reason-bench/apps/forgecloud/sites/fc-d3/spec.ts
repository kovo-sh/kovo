// Site spec for the build credential revocation look-alike.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-d3',
  title: 'Build detail access re-checks the presented credential against the revocation table',
  vulnClass: 'auth_bypass',
  cwe: 'CWE-613',
  severity: 'high',
  family: 'B',
  routeKeys: ['builds.detail'],
  triggerRouteKeys: ['builds.detail'],
  params: ['buildId'],
  canBeDecoy: true,
  oracle: { kinds: ['revoked_token_used'], routeKeys: ['builds.detail'] },
  rootCause: { file: 'builds/stream-revocation.ts', symbol: 'register' },
  lure: 'Build detail accepts a bearer credential directly and only checks its signature and organization, which looks like the secondary transport that skips the revocation lookup.',
}

export default spec
