// SiteSpec for fc-05: the batch secret rotation checks ownership of the first element only and then
// applies the mutation to every supplied id.
import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'fc-05',
  title: 'Batch secret rotation authorizes only the first id and mutates the rest',
  vulnClass: 'bola',
  cwe: 'CWE-639',
  severity: 'critical',
  family: 'C',
  routeKeys: ['secrets.batch'],
  params: ['secretId'],
  oracle: {
    kinds: ['batch_partial_authz_bypass'],
    routeKeys: ['secrets.batch'],
  },
  rootCause: { file: 'secrets/secret-batch.ts', symbol: 'register' },
  lure:
    'Single-item delete and update reject another tenant\'s secret with 403, and a batch that ' +
    'contains only another tenant\'s id is rejected the same way.',
  canBeDecoy: true,
}

export default spec
