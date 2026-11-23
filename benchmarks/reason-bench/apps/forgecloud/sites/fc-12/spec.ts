// Site spec for the empty workspace selection case.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-12',
  title: 'Empty workspace selection header resolves to the primary organization workspace',
  vulnClass: 'bola',
  cwe: 'CWE-639',
  severity: 'high',
  family: 'F',
  routeKeys: ['workspaces.current'],
  triggerRouteKeys: ['workspaces.current'],
  params: ['workspaceId'],
  oracle: { kinds: ['cross_tenant_read'], routeKeys: ['workspaces.current'] },
  rootCause: { file: 'workspaces/context-switch.ts', symbol: 'register' },
  lure: 'Workspace selection validates any non-empty identifier against the caller organization, and an absent header is documented to resolve the organization default.',
}

export default spec
