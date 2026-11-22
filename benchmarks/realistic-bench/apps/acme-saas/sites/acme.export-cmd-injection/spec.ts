import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.export-cmd-injection',
  title: "Report export command injection",
  vulnClass: 'command_injection',
  cwe: 'CWE-78',
  severity: 'critical',
  routeKeys: ['exportReport'],
  params: ['name'],
  oracle: { kinds: ['command_injection_simulated'], routeKeys: ['exportReport'] },
  rootCause: { file: 'reports/export.ts', symbol: 'register' },
  lure: "quotes the export filename in the archive command but the quoting is single-pass so an embedded quote re-opens the argument",
}
