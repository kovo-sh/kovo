import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.project-search-sqli',
  title: "Project search SQL injection",
  vulnClass: 'sqli',
  cwe: 'CWE-89',
  severity: 'critical',
  routeKeys: ['searchProjects'],
  params: ['q'],
  oracle: { kinds: ['sql_structure_change'], routeKeys: ['searchProjects'] },
  rootCause: { file: 'catalog/search.ts', symbol: 'register' },
  canBeDecoy: false,
  lure: "escapes a few characters and wraps the term in LIKE wildcards so it reads like it sanitizes, but still concatenates the raw term into the SQL text",
}
