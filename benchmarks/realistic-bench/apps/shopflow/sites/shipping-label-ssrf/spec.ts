import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'shipping-label-ssrf',
  title: 'Shipping label import SSRF',
  vulnClass: 'ssrf',
  cwe: 'CWE-918',
  severity: 'medium',
  routeKeys: ['importShippingLabel'],
  params: [],
  oracle: { kinds: ['ssrf_internal_fetch'], routeKeys: ['importShippingLabel'] },
  rootCause: { file: 'fulfillment/label-import.ts', symbol: 'importLabel' },
  formEncoding: 'xml',
  lure: 'fetches a label template URL from the manifest without host checks',
}
