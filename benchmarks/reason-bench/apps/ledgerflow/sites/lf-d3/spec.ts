import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-d3',
  title: 'Payout requests record their maker and ignore settlement fields from the client',
  vulnClass: 'workflow_bypass',
  cwe: 'CWE-841',
  severity: 'critical',
  family: 'A',
  routeKeys: ['createPayout'],
  params: ['payoutId', 'amount', 'memberId'],
  oracle: { kinds: ['self_approval_bypass'], routeKeys: ['createPayout'] },
  rootCause: { file: 'payouts/payout-request.ts', symbol: 'register' },
  lure: 'accepts the payout form fields and opens a checking step for the amount',
  canBeDecoy: true,
}
