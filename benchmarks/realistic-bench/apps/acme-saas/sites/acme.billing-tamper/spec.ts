import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.billing-tamper',
  title: "Plan change price tampering",
  vulnClass: 'business_logic',
  cwe: 'CWE-472',
  severity: 'high',
  routeKeys: ['updatePlan'],
  params: ['planId'],
  oracle: { kinds: ['invariant_violation'], routeKeys: ['updatePlan'] },
  rootCause: { file: 'billing/plan.ts', symbol: 'register' },
  lure: "reads the target plan by id but trusts a price field in the body instead of the catalog price",
}
