import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-06',
  title: 'Transfer promotion pays more than the fee it is meant to offset',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'medium',
  family: 'A',
  routeKeys: ['transferFunds'],
  params: ['amount'],
  oracle: { kinds: ['economic_invariant_violation'], routeKeys: ['transferFunds'] },
  rootCause: { file: 'wallet/transfer-promo.ts', symbol: 'register' },
  lure: 'debits the documented fee, credits the recipient in full and labels the promotion separately',
  canBeDecoy: true,
}
