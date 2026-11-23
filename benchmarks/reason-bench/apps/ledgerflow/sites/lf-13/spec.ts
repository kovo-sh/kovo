import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-13',
  title: 'Team feed approval id unlocks self-delegation and approval of a pending payout',
  vulnClass: 'chain',
  cwe: 'CWE-863',
  severity: 'critical',
  family: 'E',
  routeKeys: ['activityFeed', 'delegateApproval'],
  triggerRouteKeys: ['delegateApproval'],
  params: ['approvalId'],
  oracle: { kinds: ['stale_privilege_use', 'self_approval_bypass'], routeKeys: ['delegateApproval'] },
  rootCause: { file: 'approvals/delegated-approval.ts', symbol: 'register' },
  lure: 'reads the team feed for a signing reference and records the delegated reviewer on the request',
  canBeDecoy: false,
}
