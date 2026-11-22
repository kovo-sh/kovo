import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'inventory-oversell',
  title: 'Inventory oversell race',
  vulnClass: 'race_condition',
  cwe: 'CWE-362',
  severity: 'high',
  routeKeys: ['checkout'],
  params: ['cartId'],
  oracle: { kinds: ['race_double_spend'], routeKeys: ['checkout'] },
  rootCause: { file: 'checkout/inventory.ts', symbol: 'reserveInventory' },
  lure: 'reserves stock with a read then write that interleaves under concurrency',
}
