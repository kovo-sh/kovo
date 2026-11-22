import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'admin-impersonate-privesc',
  title: 'Staff impersonation privilege escalation',
  vulnClass: 'bfla',
  cwe: 'CWE-269',
  severity: 'critical',
  routeKeys: ['adminImpersonate'],
  params: [],
  oracle: { kinds: ['privilege_escalation'], routeKeys: ['adminImpersonate'] },
  rootCause: { file: 'identity/impersonation.ts', symbol: 'impersonate' },
  canBeDecoy: false,
  lure: 'guards the route by login but not by the staff role it assumes',
}
