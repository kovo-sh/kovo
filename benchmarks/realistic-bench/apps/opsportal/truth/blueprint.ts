// AppBlueprint for opsportal: an internal operations/admin portal for a SaaS company. Assembled from
// the route templates (routes.ts) and the 24 planted sites (sites.ts). Validate with validateBlueprint.
import type { AppBlueprint } from '../../../lib/types.ts'
import { routes, vocab, paramVocab } from './routes.ts'
import { sites } from './sites.ts'

export const blueprint: AppBlueprint = {
  app: 'opsportal',
  apiPrefixes: ['/api', '/api/v1', '/rest'],
  vocab,
  paramVocab,
  routes,
  idFormats: ['int', 'uuid', 'prefixed', 'hashid'],
  sites,
  decoyCount: { min: 6, max: 8 },
}
