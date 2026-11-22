import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.report-ssti',
  title: "Report template server-side template injection",
  vulnClass: 'ssti',
  cwe: 'CWE-1336',
  severity: 'high',
  routeKeys: ['createReport'],
  triggerRouteKeys: ['renderReport'],
  params: ['name'],
  oracle: { kinds: ['template_code_exec'], routeKeys: ['renderReport'] },
  rootCause: { file: 'reports/render.ts', symbol: 'register' },
  secondOrder: true,
  lure: "offers a small set of placeholder tokens and escapes output, so it looks like a data-only templating feature while rendering the stored source as a live template",
}
