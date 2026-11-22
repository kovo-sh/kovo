import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.jwt-none',
  title: "API token alg:none forgery",
  vulnClass: 'jwt',
  cwe: 'CWE-347',
  severity: 'high',
  routeKeys: ['refreshToken'],
  params: ['token'],
  oracle: { kinds: ['token_forgery'], routeKeys: ['refreshToken'] },
  rootCause: { file: 'auth/token.ts', symbol: 'register' },
  chain: { id: 'acme.takeover', step: 2 },
  lure: "checks the token signature and expiry but leaves alg:none in the accepted algorithm list",
}
