import type { SiteSpec } from '../../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'demo-site-2',
  title: 'Demo member object access',
  vulnClass: 'bola',
  cwe: 'CWE-639',
  severity: 'medium',
  routeKeys: ['getUser'],
  params: ['userId'],
  oracle: { kinds: ['cross_tenant_read'], routeKeys: ['getUser'] },
  rootCause: { file: 'area/widget.ts', symbol: 'loadUser' },
  lure: 'scopes by a session value that can be widened via a query flag',
}
