import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.member-role-privesc',
  title: "Member update role privilege escalation",
  vulnClass: 'mass_assignment',
  cwe: 'CWE-269',
  severity: 'high',
  routeKeys: ['updateMember'],
  params: ['memberId', 'role'],
  oracle: { kinds: ['privilege_escalation'], routeKeys: ['updateMember'] },
  rootCause: { file: 'members/roles.ts', symbol: 'register' },
  lure: "copies an allowlist of profile fields but leaves role in the same object spread so a crafted body still reaches it",
}
