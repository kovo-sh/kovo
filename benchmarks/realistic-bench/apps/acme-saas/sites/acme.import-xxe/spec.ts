import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.import-xxe',
  title: "Project import XML external entity",
  vulnClass: 'xxe',
  cwe: 'CWE-611',
  severity: 'high',
  routeKeys: ['importProjects'],
  params: [],
  oracle: { kinds: ['xxe_entity_resolved'], routeKeys: ['importProjects'] },
  rootCause: { file: 'integrations/import.ts', symbol: 'register' },
  formEncoding: 'xml',
  lure: "parses the uploaded XML with entity support enabled to support legacy exports, which looks like a compatibility feature",
}
