import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'customer-bola-read',
  title: 'Customer record read across stores',
  vulnClass: 'bola',
  cwe: 'CWE-639',
  severity: 'medium',
  routeKeys: ['getCustomer'],
  params: ['customerId'],
  oracle: { kinds: ['cross_tenant_read'], routeKeys: ['getCustomer'] },
  rootCause: { file: 'crm/customer-access.ts', symbol: 'loadCustomer' },
  lure: 'filters the list endpoint by store but not the single-record endpoint',
}
