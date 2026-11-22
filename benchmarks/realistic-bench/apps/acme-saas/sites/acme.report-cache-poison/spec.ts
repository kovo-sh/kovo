import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.report-cache-poison',
  title: "Public report cache poisoning",
  vulnClass: 'cache_poisoning',
  cwe: 'CWE-524',
  severity: 'medium',
  routeKeys: ['publicReport'],
  params: ['reportId'],
  oracle: { kinds: ['cache_poisoned'], routeKeys: ['publicReport'] },
  rootCause: { file: 'reports/public.ts', symbol: 'register' },
  lure: "caches the public report keyed only by id and includes tenant-scoped figures, so a warm entry can be served across tenants",
}
