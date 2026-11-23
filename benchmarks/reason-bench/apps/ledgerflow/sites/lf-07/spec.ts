import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-07',
  title: 'Invite acceptance grants the role signed into the token rather than the current invite row',
  vulnClass: 'auth_bypass',
  cwe: 'CWE-613',
  severity: 'critical',
  family: 'B',
  routeKeys: ['acceptInvite'],
  params: ['token', 'email', 'role'],
  oracle: { kinds: ['stale_privilege_use'], routeKeys: ['acceptInvite'] },
  rootCause: { file: 'team/invite-token.ts', symbol: 'register' },
  lure: 'checks the invite signature and matches the invite and tenant claims before creating the membership',
  canBeDecoy: true,
}
