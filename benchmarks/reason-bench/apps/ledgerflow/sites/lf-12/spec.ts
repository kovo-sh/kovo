import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-12',
  title: 'Recovery lookup folds an address the ownership check compared verbatim',
  vulnClass: 'auth_bypass',
  cwe: 'CWE-287',
  severity: 'high',
  family: 'D',
  routeKeys: ['requestPasswordReset'],
  params: ['email'],
  oracle: { kinds: ['cross_tenant_write'], routeKeys: ['requestPasswordReset'] },
  rootCause: { file: 'auth/recovery-lookup.ts', symbol: 'register' },
  lure: 'confirms nothing about the address and always answers with the same delivery message',
  canBeDecoy: false,
}
