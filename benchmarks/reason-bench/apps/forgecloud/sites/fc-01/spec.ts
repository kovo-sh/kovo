// SiteSpec for fc-01: the live build-log transport keeps a credential alive after the REST surface
// has already started rejecting it.
import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'fc-01',
  title: 'Build-log stream keeps serving after the personal access token is revoked',
  vulnClass: 'auth_bypass',
  cwe: 'CWE-613',
  severity: 'high',
  family: 'B',
  routeKeys: ['streams.build'],
  triggerRouteKeys: ['builds.logs'],
  params: ['buildId', 'token'],
  oracle: {
    kinds: ['revoked_token_used'],
    routeKeys: ['builds.logs', 'streams.build'],
  },
  rootCause: { file: 'streams/build-log-stream.ts', symbol: 'register' },
  lure:
    'The REST resolver rejects a revoked token with 401 and the stream still validates the token ' +
    'signature, expiry and build ownership, so the transport looks like a thin replay of the same checks.',
  canBeDecoy: true,
}

export default spec
