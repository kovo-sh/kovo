import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'checkout-workflow-skip',
  title: 'Confirm order before payment capture',
  vulnClass: 'workflow_bypass',
  cwe: 'CWE-840',
  severity: 'critical',
  routeKeys: ['confirmOrder'],
  params: ['orderId'],
  oracle: { kinds: ['workflow_skip'], routeKeys: ['confirmOrder'] },
  rootCause: { file: 'checkout/confirm.ts', symbol: 'confirmOrder' },
  formEncoding: 'json',
  canBeDecoy: false,
  lure: 'confirms the order and only then kicks off an async capture that may never run',
}
