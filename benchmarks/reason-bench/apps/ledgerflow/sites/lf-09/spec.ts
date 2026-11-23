import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-09',
  title: 'Federated sign-in accepts an unverified pending address',
  vulnClass: 'auth_bypass',
  cwe: 'CWE-287',
  severity: 'critical',
  family: 'B',
  routeKeys: ['changeEmail', 'ssoStart', 'ssoCallback'],
  params: ['email'],
  oracle: { kinds: ['sso_tenant_confusion'], routeKeys: ['ssoCallback'] },
  rootCause: { file: 'auth/sso-email-link.ts', symbol: 'register' },
  lure: 'issues a signed hand-off state and resolves the federated identity from the profile address',
  canBeDecoy: false,
}
