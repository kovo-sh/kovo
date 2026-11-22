import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.project-mass-assign',
  title: "Project create mass assignment",
  vulnClass: 'mass_assignment',
  cwe: 'CWE-915',
  severity: 'medium',
  routeKeys: ['createProject'],
  params: ['name'],
  oracle: { kinds: ['mass_assignment'], routeKeys: ['createProject'] },
  rootCause: { file: 'catalog/create.ts', symbol: 'register' },
  lure: "defaults tenant_id from the session but still merges the request body afterward, so a supplied tenant_id wins",
}
