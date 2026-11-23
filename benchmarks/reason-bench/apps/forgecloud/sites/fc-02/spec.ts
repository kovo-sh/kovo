// SiteSpec for fc-02: automation creation is a capability-gated surface that can hand out an
// organization-administration template without ever calling the direct role-change endpoint.
import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'fc-02',
  title: 'Workspace automation creation grants an organization-admin role template',
  vulnClass: 'bfla',
  cwe: 'CWE-269',
  severity: 'critical',
  family: 'C',
  routeKeys: ['automations.create'],
  params: ['role', 'name'],
  oracle: {
    kinds: ['privilege_escalation'],
    routeKeys: ['automations.create'],
  },
  rootCause: { file: 'automations/automation-grants.ts', symbol: 'register' },
  lure:
    'The direct membership role-change endpoint rejects an admin request from a team lead with 403, ' +
    'and automation creation only asks for the automation capability every team lead already has.',
  canBeDecoy: true,
}

export default spec
