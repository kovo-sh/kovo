import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-03',
  title: 'Downgrade refunds the prorated price without withholding granted credits',
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'high',
  family: 'A',
  routeKeys: ['upgradePlan', 'downgradePlan'],
  triggerRouteKeys: ['downgradePlan'],
  params: ['plan'],
  oracle: { kinds: ['economic_invariant_violation'], routeKeys: ['downgradePlan'] },
  rootCause: { file: 'billing/plan-cycle.ts', symbol: 'register' },
  lure: 'upgrade grants metered credits and downgrade reports a prorated settlement with a labelled refund',
  canBeDecoy: true,
}
