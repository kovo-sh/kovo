// Site spec for the organization relocation look-alike.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-d5',
  title: 'Project relocation requires administrative authority in source and destination organizations',
  vulnClass: 'bola',
  cwe: 'CWE-863',
  severity: 'critical',
  family: 'C',
  routeKeys: ['projects.update'],
  triggerRouteKeys: ['projects.update'],
  params: ['projectId', 'orgId'],
  canBeDecoy: true,
  oracle: { kinds: ['cross_org_transfer'], routeKeys: ['projects.update'] },
  rootCause: { file: 'projects/org-relocation.ts', symbol: 'register' },
  lure: 'The update handler accepts a destination organization and relocates the row, which looks like the transfer path that authorizes only the destination side.',
}

export default spec
