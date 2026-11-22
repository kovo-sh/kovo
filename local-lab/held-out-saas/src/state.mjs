import { createDb } from './db.mjs'
import { marker } from './markers.mjs'

export const USERS = [
  { id: 'u_acme_1', handle: 'persona_a', tenantId: 'acme', role: 'member', name: 'Alice Anders', email: 'alice@acme.example' },
  { id: 'u_acme_admin', handle: 'admin', tenantId: 'acme', role: 'admin', name: 'Ada Admin', email: 'ada@acme.example' },
  { id: 'u_acme_viewer', handle: 'viewer', tenantId: 'acme', role: 'viewer', name: 'Vic Viewer', email: 'vic@acme.example' },
  { id: 'u_globex_1', handle: 'persona_b', tenantId: 'globex', role: 'member', name: 'Gus Globex', email: 'gus@globex.example' },
]

/** Fresh, fully in-memory application state (rebuilt by `resetState()`). */
export function createState() {
  const users = new Map(USERS.map(u => [u.id, { ...u, displayName: u.name, creditLimit: 1000 }]))
  const tenants = new Map([
    ['acme', { id: 'acme', name: 'Acme Robotics', plan: 'team' }],
    ['globex', { id: 'globex', name: 'Globex Retail', plan: 'starter' }],
  ])
  const projects = new Map([
    ['p_acme_1', { id: 'p_acme_1', tenantId: 'acme', name: 'Apollo rollout', status: 'active', ownerId: 'u_acme_1' }],
    ['p_acme_2', { id: 'p_acme_2', tenantId: 'acme', name: 'Borealis migration', status: 'planning', ownerId: 'u_acme_admin' }],
    ['p_globex_1', { id: 'p_globex_1', tenantId: 'globex', name: 'Cygnus launch', status: 'active', ownerId: 'u_globex_1' }],
  ])
  const invoices = new Map([
    ['1001', { id: '1001', tenantId: 'acme', ownerId: 'u_acme_1', number: 'INV-1001', total: 1200.0, memo: 'Annual platform fee' }],
    ['1002', { id: '1002', tenantId: 'acme', ownerId: 'u_acme_admin', number: 'INV-1002', total: 340.5, memo: 'Support add-on' }],
    ['2001', { id: '2001', tenantId: 'globex', ownerId: 'u_globex_1', number: 'INV-2001', total: 8800.0, memo: `Enterprise renewal ${marker('hos-01')}` }],
    ['2002', { id: '2002', tenantId: 'globex', ownerId: 'u_globex_1', number: 'INV-2002', total: 150.0, memo: `Overage ${marker('hos-02')}` }],
  ])
  return {
    db: createDb(),
    users,
    tenants,
    projects,
    invoices,
    flags: { beta_exports: false, ai_assistant: false, sso_enforced: true },
    comments: [{ id: 'c_1', projectId: 'p_acme_1', author: 'u_acme_admin', body: `Release notes ${marker('hos-15')}` }],
    notes: [],
    checkoutOrders: new Map(),
    vouchers: new Map(),
    credits: new Map([['acme', 100], ['globex', 100]]),
    webhooks: new Map(),
    deliveries: [],
    csrfTokens: new Set(),
    cache: new Map(),
    counters: { order: 1000, webhook: 0, comment: 1, note: 0 },
  }
}
