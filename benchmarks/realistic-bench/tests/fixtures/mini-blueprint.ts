// Minimal AppBlueprint fixture: ~6 routes, two sites (incl. the demo-site), vocab/paramVocab and a
// decoyCount. `app` is cast because the fixture name is not one of the real AppName values.
import type { AppBlueprint, AppName } from '../../lib/types.ts'
import { spec as demoSite } from './mini-app/sites/demo-site/spec.ts'
import { spec as demoSite2 } from './mini-app/sites/demo-site-2/spec.ts'

export const miniBlueprint: AppBlueprint = {
  app: 'mini-app' as AppName,
  apiPrefixes: ['/api/v1', '/rest', '/api'],
  vocab: {
    invoices: ['invoices', 'billing-docs', 'statements'],
    users: ['users', 'members', 'accounts'],
  },
  paramVocab: {
    invoiceId: ['invoiceId', 'invId', 'docId'],
    userId: ['userId', 'memberId', 'accountId'],
  },
  routes: {
    login: { method: 'POST', path: '/login' },
    listInvoices: { method: 'GET', path: '/api/{noun:invoices}' },
    getInvoice: { method: 'GET', path: '/api/{noun:invoices}/:invoiceId' },
    createInvoice: { method: 'POST', path: '/api/{noun:invoices}' },
    listUsers: { method: 'GET', path: '/api/{noun:users}' },
    getUser: { method: 'GET', path: '/api/{noun:users}/:userId' },
  },
  idFormats: ['int', 'uuid', 'prefixed'],
  sites: [demoSite, demoSite2],
  decoyCount: { min: 0, max: 2 },
}
