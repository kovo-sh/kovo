import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'token-secret-disclosure',
  title: 'API token list secret disclosure',
  vulnClass: 'info_disclosure',
  cwe: 'CWE-200',
  severity: 'high',
  routeKeys: ['listTokens'],
  params: [],
  oracle: { kinds: ['secret_disclosed'], routeKeys: ['listTokens'] },
  rootCause: { file: 'identity/token-list.ts', symbol: 'listTokens' },
  lure: 'returns a masked preview that still includes the full secret in a sibling field',
}
