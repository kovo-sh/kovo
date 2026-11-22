import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.apikey-disclosure',
  title: "API key secret disclosure to viewer",
  vulnClass: 'info_disclosure',
  cwe: 'CWE-200',
  severity: 'high',
  routeKeys: ['listApiKeys'],
  params: [],
  oracle: { kinds: ['secret_disclosed'], routeKeys: ['listApiKeys'] },
  rootCause: { file: 'members/keys.ts', symbol: 'register' },
  lure: "masks the secret in the list view for most roles but returns the full secret when a verbose flag is set",
}
