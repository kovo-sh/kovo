import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'refund-csrf',
  title: 'Refund creation CSRF',
  vulnClass: 'csrf',
  cwe: 'CWE-352',
  severity: 'medium',
  routeKeys: ['createRefund'],
  params: ['bodyAmount'],
  oracle: { kinds: ['csrf_state_change'], routeKeys: ['createRefund'] },
  rootCause: { file: 'billing/refund-create.ts', symbol: 'createRefund' },
  formEncoding: 'form',
  requiresCsrf: true,
  lure: 'accepts a token field but never compares it to the session token',
}
