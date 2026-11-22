import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.file-list-bola',
  title: "File listing cross-tenant exposure",
  vulnClass: 'bola',
  cwe: 'CWE-639',
  severity: 'medium',
  routeKeys: ['listFiles'],
  params: ['projectId'],
  oracle: { kinds: ['cross_tenant_read'], routeKeys: ['listFiles'] },
  rootCause: { file: 'files/list.ts', symbol: 'register' },
  lure: "filters files by the project id query param and looks scoped, but trusts the project id without checking project ownership",
}
