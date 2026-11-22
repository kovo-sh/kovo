import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.export-open-redirect',
  title: "Export download open redirect",
  vulnClass: 'open_redirect',
  cwe: 'CWE-601',
  severity: 'low',
  routeKeys: ['exportRedirect'],
  params: ['url'],
  oracle: { kinds: ['open_redirect'], routeKeys: ['exportRedirect'] },
  rootCause: { file: 'legacy/redirect.ts', symbol: 'register' },
  lure: "redirects to a signed download URL but falls back to a caller-supplied next parameter when the signature is absent",
}
