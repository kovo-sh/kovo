// Site spec for the bulk secret ownership look-alike.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-d1',
  title: 'Bulk secret edit validates ownership on every requested identifier',
  vulnClass: 'bola',
  cwe: 'CWE-639',
  severity: 'high',
  family: 'C',
  routeKeys: ['secrets.update'],
  triggerRouteKeys: ['secrets.update'],
  params: ['secretId', 'name'],
  canBeDecoy: true,
  oracle: { kinds: ['batch_partial_authz_bypass'], routeKeys: ['secrets.update'] },
  rootCause: { file: 'secrets/bulk-owner-check.ts', symbol: 'register' },
  lure: 'The handler accepts an identifier array and applies one patch to all of them, which looks like the batch path that skips later elements.',
}

export default spec
