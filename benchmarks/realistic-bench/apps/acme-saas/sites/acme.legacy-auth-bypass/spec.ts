import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.legacy-auth-bypass',
  title: "Legacy login authentication bypass",
  vulnClass: 'auth_bypass',
  cwe: 'CWE-287',
  severity: 'high',
  routeKeys: ['legacyLogin'],
  params: ['email'],
  oracle: { kinds: ['auth_bypass'], routeKeys: ['legacyLogin'] },
  rootCause: { file: 'auth/legacy.ts', symbol: 'register' },
  lure: "supports a legacy password-less SSO hand-off for one domain but the domain check is a suffix match any email can satisfy",
}
