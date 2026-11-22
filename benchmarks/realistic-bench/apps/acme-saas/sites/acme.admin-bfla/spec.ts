import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.admin-bfla',
  title: "Admin user delete function-level authz bypass",
  vulnClass: 'bfla',
  cwe: 'CWE-285',
  severity: 'critical',
  routeKeys: ['adminDeleteUser'],
  params: ['memberId'],
  oracle: { kinds: ['privilege_escalation'], routeKeys: ['adminDeleteUser'] },
  rootCause: { file: 'admin/users.ts', symbol: 'register' },
  canBeDecoy: false,
  lure: "lives under an /admin path and checks authentication, which looks gated, but never checks the admin role",
}
