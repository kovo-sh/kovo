import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.credit-double-spend',
  title: "Credit application double spend",
  vulnClass: 'race_condition',
  cwe: 'CWE-362',
  severity: 'high',
  routeKeys: ['applyCredit'],
  params: ['amount'],
  oracle: { kinds: ['race_double_spend'], routeKeys: ['applyCredit'] },
  rootCause: { file: 'billing/credits.ts', symbol: 'register' },
  lure: "reads the balance, checks it, then writes the new balance in separate steps so concurrent applies both pass the check",
}
