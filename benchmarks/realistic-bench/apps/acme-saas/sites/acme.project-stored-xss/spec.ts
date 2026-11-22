import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.project-stored-xss',
  title: "Project description stored XSS",
  vulnClass: 'xss_stored',
  cwe: 'CWE-79',
  severity: 'high',
  routeKeys: ['updateProject'],
  triggerRouteKeys: ['renderProjectCard'],
  params: ['projectId'],
  oracle: { kinds: ['stored_xss_rendered'], routeKeys: ['renderProjectCard'] },
  rootCause: { file: 'catalog/card.ts', symbol: 'register' },
  secondOrder: true,
  lure: "renders a rich-HTML description and runs a naive tag filter that removes <script> but misses event-handler attributes",
}
