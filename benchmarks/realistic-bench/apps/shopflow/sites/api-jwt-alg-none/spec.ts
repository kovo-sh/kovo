import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'api-jwt-alg-none',
  title: 'Sales report JWT alg confusion',
  vulnClass: 'jwt',
  cwe: 'CWE-347',
  severity: 'high',
  routeKeys: ['salesReport'],
  params: [],
  oracle: { kinds: ['token_forgery'], routeKeys: ['salesReport'] },
  rootCause: { file: 'identity/api-auth.ts', symbol: 'authorizeReport' },
  lure: 'verifies the signature but leaves the alg list open to unsigned tokens',
}
