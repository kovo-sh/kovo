import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.sso-open-redirect',
  title: "SSO callback open redirect",
  vulnClass: 'oauth',
  cwe: 'CWE-601',
  severity: 'high',
  routeKeys: ['ssoCallback'],
  params: ['url'],
  oracle: { kinds: ['open_redirect'], routeKeys: ['ssoCallback'] },
  rootCause: { file: 'auth/sso.ts', symbol: 'register' },
  chain: { id: 'acme.takeover', step: 1 },
  lure: "checks that the return target starts with a slash OR matches a known prefix, but the prefix test is a substring match that a foreign host can satisfy",
}
