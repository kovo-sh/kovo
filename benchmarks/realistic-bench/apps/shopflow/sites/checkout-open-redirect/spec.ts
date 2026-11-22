import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'checkout-open-redirect',
  title: 'Checkout return open redirect',
  vulnClass: 'open_redirect',
  cwe: 'CWE-601',
  severity: 'medium',
  routeKeys: ['checkoutReturn'],
  params: ['returnUrl'],
  oracle: { kinds: ['open_redirect'], routeKeys: ['checkoutReturn'] },
  rootCause: { file: 'checkout/return-handler.ts', symbol: 'handleReturn' },
  lure: 'allowlists a prefix match that a foreign host can spoof as a subdomain',
}
