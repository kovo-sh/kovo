import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'settings-secret-disclosure',
  title: 'Store settings secret disclosure',
  vulnClass: 'info_disclosure',
  cwe: 'CWE-200',
  severity: 'medium',
  routeKeys: ['getSettings'],
  params: [],
  oracle: { kinds: ['secret_disclosed'], routeKeys: ['getSettings'] },
  rootCause: { file: 'identity/settings-read.ts', symbol: 'readSettings' },
  lure: 'returns provider keys to any signed-in role rather than owners only',
}
