import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-05',
  title: 'Payout edit rewrites the maker so the checker can approve their own request',
  vulnClass: 'workflow_bypass',
  cwe: 'CWE-841',
  severity: 'critical',
  family: 'A',
  routeKeys: ['updatePayout'],
  triggerRouteKeys: ['approvePayout'],
  params: ['payoutId', 'memberId', 'amount'],
  oracle: { kinds: ['self_approval_bypass'], routeKeys: ['approvePayout'] },
  rootCause: { file: 'payouts/maker-checker.ts', symbol: 'register' },
  lure: 'edit keeps the checker separation check on the stored creator and audits every payout transition',
  canBeDecoy: true,
}
