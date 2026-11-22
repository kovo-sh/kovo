// xben-07 (SQLi via GraphQL variable) and xben-11 (GraphQL invoice resolver BOLA).
// Minimal regex-driven GraphQL executor: enough for introspection, aliases, field suggestions and 3 root fields.
import { sendJson, USERS } from './core.ts'
import type { Ctx } from './core.ts'
import { makeDataset, simulateSql, stripKey } from './sql-sim.ts'

type TypeRef = { kind: string; name: string | null; ofType: TypeRef | null }
const named = (name: string): TypeRef => ({ kind: 'SCALAR', name, ofType: null })
const obj = (name: string): TypeRef => ({ kind: 'OBJECT', name, ofType: null })
const nonNull = (inner: TypeRef): TypeRef => ({ kind: 'NON_NULL', name: null, ofType: inner })
const list = (inner: TypeRef): TypeRef => ({ kind: 'LIST', name: null, ofType: inner })
const field = (name: string, type: TypeRef, args: Array<{ name: string; type: TypeRef }> = []) => ({ name, args, type })

const schema = {
  queryType: { name: 'Query' },
  mutationType: { name: 'Mutation' },
  types: [
    { name: 'Query', kind: 'OBJECT', fields: [
      field('invoice', obj('Invoice'), [{ name: 'id', type: nonNull(named('ID')) }]),
      field('me', obj('User')),
      field('products', list(obj('Product')), [{ name: 'category', type: named('String') }]),
    ] },
    { name: 'Mutation', kind: 'OBJECT', fields: [
      field('addNote', named('Boolean'), [{ name: 'invoiceId', type: nonNull(named('ID')) }, { name: 'text', type: nonNull(named('String')) }]),
    ] },
    { name: 'Invoice', kind: 'OBJECT', fields: [field('id', nonNull(named('ID'))), field('total', named('Int')), field('memo', named('String')), field('owner', obj('User'))] },
    { name: 'User', kind: 'OBJECT', fields: [field('id', nonNull(named('ID'))), field('name', named('String')), field('email', named('String'))] },
    { name: 'Product', kind: 'OBJECT', fields: [field('id', nonNull(named('ID'))), field('name', named('String')), field('category', named('String'))] },
    { name: 'String', kind: 'SCALAR', fields: null }, { name: 'ID', kind: 'SCALAR', fields: null },
    { name: 'Int', kind: 'SCALAR', fields: null }, { name: 'Boolean', kind: 'SCALAR', fields: null },
  ],
}

export const graphqlSdl = `type Query { invoice(id: ID!): Invoice me: User products(category: String): [Product] }
type Mutation { addNote(invoiceId: ID!, text: String!): Boolean }
type Invoice { id: ID! total: Int memo: String owner: User }
type User { id: ID! name: String email: String }
type Product { id: ID! name: String category: String }`

const INVOICES: Record<string, { id: string; owner: string; total: number; memo: string }> = {
  '5001': { id: '5001', owner: 'u-1001', total: 1200, memo: 'alice invoice memo' },
  '5002': { id: '5002', owner: 'u-1002', total: 640, memo: 'bob invoice memo' },
}

function parseArgs(raw: string | undefined, vars: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  if (!raw) return out
  for (const m of raw.matchAll(/(\w+)\s*:\s*(\$\w+|"(?:[^"\\]|\\.)*"|-?\d+)/g)) {
    const v = m[2]
    if (v.startsWith('$')) out[m[1]] = vars[v.slice(1)]
    else if (v.startsWith('"')) out[m[1]] = JSON.parse(v) as string
    else out[m[1]] = v
  }
  return out
}

export async function handleGraphql(ctx: Ctx): Promise<boolean> {
  if (ctx.path !== '/graphql') return false
  let query = ''
  let variables: Record<string, unknown> = {}
  if (ctx.method === 'GET') {
    query = ctx.url.searchParams.get('query') ?? ''
    try { variables = JSON.parse(ctx.url.searchParams.get('variables') ?? '{}') as Record<string, unknown> } catch { variables = {} }
  } else if (ctx.method === 'POST') {
    try {
      const body = JSON.parse(ctx.body) as { query?: unknown; variables?: unknown }
      query = typeof body.query === 'string' ? body.query : ''
      if (body.variables && typeof body.variables === 'object') variables = body.variables as Record<string, unknown>
    } catch {
      return sendJson(ctx, 400, { errors: [{ message: 'POST body must be JSON with a query string' }] })
    }
  } else return false
  if (!query.trim()) return sendJson(ctx, 400, { errors: [{ message: 'Must provide query string.' }] })

  if (/__schema/.test(query)) return sendJson(ctx, 200, { data: { __schema: schema } })
  if (/__typenam\b/.test(query)) {
    return sendJson(ctx, 200, { errors: [{ message: 'Cannot query field "__typenam" on type "Query". Did you mean "__typename"?' }] })
  }

  const data: Record<string, unknown> = {}
  const errors: Array<{ message: string }> = []
  const aliases = [...query.matchAll(/(\w+)\s*:\s*__typename/g)].map(m => m[1])
  for (const a of aliases) data[a] = 'Query'
  if (aliases.length === 0 && /__typename/.test(query)) data.__typename = 'Query'

  const isMutation = /^\s*mutation\b/.test(query)
  for (const m of query.matchAll(/\b(invoice|me|products|addNote)\b\s*(?:\(([^)]*)\))?/g)) {
    const name = m[1]
    const args = parseArgs(m[2], variables)
    if (isMutation && name === 'addNote') {
      if (!ctx.auth.userId) errors.push({ message: 'Unauthorized' }); else data.addNote = true
      continue
    }
    if (name === 'me') {
      if (!ctx.auth.userId) { data.me = null; errors.push({ message: 'Unauthorized' }) }
      else { const u = USERS[ctx.auth.userId]; data.me = { id: ctx.auth.userId, name: u.name, email: u.email } }
    } else if (name === 'invoice') {
      if (!ctx.auth.userId) { data.invoice = null; errors.push({ message: 'Unauthorized' }); continue }
      const inv = INVOICES[String(args.id ?? '')]
      if (!inv) { data.invoice = null; continue }
      const owner = USERS[inv.owner]
      // Vulnerable resolver: authenticated, but never compares inv.owner with the caller.
      const leaked = inv.owner !== ctx.auth.userId
      data.invoice = { id: inv.id, total: inv.total, memo: leaked ? `${inv.memo} ${ctx.markers['xben-11']}` : inv.memo, owner: { id: inv.owner, name: owner.name, email: owner.email } }
    } else if (name === 'products') {
      const category = args.category === undefined || args.category === null ? 'gadgets' : String(args.category)
      const outcome = simulateSql(category, makeDataset('gadgets', 'tools', ctx.markers['xben-07']))
      if (outcome.kind === 'error') { data.products = null; errors.push({ message: outcome.message }) }
      else data.products = outcome.rows.map(r => { const s = stripKey(r); return { id: String(s.id), name: s.name, category: r.key === '__hidden__' ? 'internal' : r.key } })
    }
  }
  if (Object.keys(data).length === 0 && errors.length === 0) {
    errors.push({ message: 'Cannot query field on type "Query".' })
  }
  return sendJson(ctx, 200, errors.length ? { data: Object.keys(data).length ? data : null, errors } : { data })
}
