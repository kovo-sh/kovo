// Site spec for the log stream revocation look-alike.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-d3',
  title: 'Build log access re-checks the presented credential against the revocation table',
  vulnClass: 'auth_bypass',
  cwe: 'CWE-613',
  severity: 'high',
  family: 'B',
  routeKeys: ['builds.logs'],
  triggerRouteKeys: ['builds.logs'],
  params: ['buildId'],
  canBeDecoy: true,
  oracle: { kinds: ['revoked_token_used'], routeKeys: ['builds.logs'] },
  rootCause: { file: 'builds/stream-revocation.ts', symbol: 'register' },
  lure: 'Log access accepts a bearer credential directly and only checks its signature and organization, which looks like the secondary transport that skips the revocation lookup.',
}

export default spec
