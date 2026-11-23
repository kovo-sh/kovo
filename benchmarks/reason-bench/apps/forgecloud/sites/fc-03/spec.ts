// SiteSpec for fc-03: a dual-org administrator moves another tenant's project into the org where they
// are an administrator because the transfer only authorizes the destination side.
import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'fc-03',
  title: 'Project transfer authorizes the destination org and only membership on the source org',
  vulnClass: 'bola',
  cwe: 'CWE-863',
  severity: 'critical',
  family: 'C',
  routeKeys: ['projects.transfer'],
  params: ['projectId', 'orgId'],
  oracle: {
    kinds: ['cross_org_transfer'],
    routeKeys: ['projects.transfer'],
  },
  rootCause: { file: 'projects/project-transfer.ts', symbol: 'register' },
  lure:
    'A viewer in the source organization cannot list, edit or delete foreign projects, and the ' +
    'transfer does require administrative authority on the destination organization.',
  canBeDecoy: true,
}

export default spec
