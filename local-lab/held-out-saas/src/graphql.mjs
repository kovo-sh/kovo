// Minimal GraphQL engine (parser + executor + introspection), pure stdlib.
import { sendJson } from './http-util.mjs'

const TYPES = {
  Query: { me: 'User', user: 'User', project: 'Project', products: '[Product]' },
  User: { id: 'ID', name: 'String', email: 'String', tenantId: 'ID', invoices: '[Invoice]' },
  Project: { id: 'ID', name: 'String', status: 'String', owner: 'User' },
  Invoice: { id: 'ID', number: 'String', total: 'Float', memo: 'String' },
  Product: { id: 'ID', sku: 'String', name: 'String', price: 'Float' },
}
const ARGS = {
  'Query.user': [{ name: 'id', type: 'ID!' }],
  'Query.project': [{ name: 'id', type: 'ID!' }],
  'Query.products': [{ name: 'sku', type: 'String' }],
}
const SCALARS = new Set(['ID', 'String', 'Float', 'Int', 'Boolean'])

// ---- tokenizer / parser ---------------------------------------------------------------------------------
const TOKEN_RE = /(?:\s+|,|#[^\n]*)|(\.\.\.)|([!$&():=@[\]{|}])|("""[\s\S]*?"""|"(?:[^"\\]|\\.)*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([_A-Za-z][_0-9A-Za-z]*)/y

function tokenize(src) {
  const tokens = []
  TOKEN_RE.lastIndex = 0
  while (TOKEN_RE.lastIndex < src.length) {
    const m = TOKEN_RE.exec(src)
    if (!m) throw new Error(`Syntax Error: Unexpected character at offset ${TOKEN_RE.lastIndex}`)
    if (m[1]) tokens.push({ t: 'p', v: '...' })
    else if (m[2]) tokens.push({ t: 'p', v: m[2] })
    else if (m[3]) tokens.push({ t: 's', v: m[3].startsWith('"""') ? m[3].slice(3, -3) : JSON.parse(m[3]) })
    else if (m[4]) tokens.push({ t: 'n', v: Number(m[4]) })
    else if (m[5]) tokens.push({ t: 'name', v: m[5] })
  }
  return tokens
}

function parseDocument(src) {
  const tokens = tokenize(src)
  let i = 0
  const peek = () => tokens[i]
  const next = () => tokens[i++]
  const isP = v => peek()?.t === 'p' && peek().v === v
  const expectP = v => {
    if (!isP(v)) throw new Error(`Syntax Error: Expected "${v}"`)
    i++
  }
  const name = () => {
    const tk = next()
    if (!tk || tk.t !== 'name') throw new Error('Syntax Error: Expected Name')
    return tk.v
  }

  function value() {
    const tk = next()
    if (!tk) throw new Error('Syntax Error: Unexpected end of document')
    if (tk.t === 'p' && tk.v === '$') return { k: 'var', name: name() }
    if (tk.t === 'p' && tk.v === '[') {
      const items = []
      while (!isP(']')) items.push(value())
      i++
      return { k: 'list', items }
    }
    if (tk.t === 'p' && tk.v === '{') {
      const fields = {}
      while (!isP('}')) {
        const key = name()
        expectP(':')
        fields[key] = value()
      }
      i++
      return { k: 'object', fields }
    }
    if (tk.t === 's' || tk.t === 'n') return { k: 'lit', v: tk.v }
    if (tk.t === 'name') {
      if (tk.v === 'true') return { k: 'lit', v: true }
      if (tk.v === 'false') return { k: 'lit', v: false }
      if (tk.v === 'null') return { k: 'lit', v: null }
      return { k: 'lit', v: tk.v }
    }
    throw new Error('Syntax Error: Unexpected token in value')
  }

  function skipDirectives() {
    while (isP('@')) {
      i++
      name()
      if (isP('(')) {
        i++
        while (!isP(')')) {
          name()
          expectP(':')
          value()
        }
        i++
      }
    }
  }

  function typeRef() {
    if (isP('[')) {
      i++
      typeRef()
      expectP(']')
    } else name()
    if (isP('!')) i++
  }

  function selectionSet() {
    expectP('{')
    const sels = []
    while (!isP('}')) {
      if (!peek()) throw new Error('Syntax Error: Unexpected end of document')
      if (isP('...')) {
        i++
        if (peek()?.t === 'name' && peek().v !== 'on') {
          sels.push({ kind: 'spread', name: name() })
          skipDirectives()
        } else {
          if (peek()?.t === 'name' && peek().v === 'on') { i++; name() }
          skipDirectives()
          sels.push({ kind: 'inline', selection: selectionSet() })
        }
        continue
      }
      let alias = null
      let fname = name()
      if (isP(':')) {
        i++
        alias = fname
        fname = name()
      }
      const args = {}
      if (isP('(')) {
        i++
        while (!isP(')')) {
          const an = name()
          expectP(':')
          args[an] = value()
        }
        i++
      }
      skipDirectives()
      const selection = isP('{') ? selectionSet() : null
      sels.push({ kind: 'field', alias, name: fname, args, selection })
    }
    i++
    return sels
  }

  const doc = { operations: [], fragments: {} }
  while (peek()) {
    if (isP('{')) {
      doc.operations.push({ name: null, op: 'query', varDefaults: {}, selection: selectionSet() })
      continue
    }
    const kw = name()
    if (kw === 'fragment') {
      const fname = name()
      if (name() !== 'on') throw new Error('Syntax Error: Expected "on"')
      name()
      skipDirectives()
      doc.fragments[fname] = selectionSet()
    } else if (kw === 'query' || kw === 'mutation' || kw === 'subscription') {
      const opName = peek()?.t === 'name' ? name() : null
      const varDefaults = {}
      if (isP('(')) {
        i++
        while (!isP(')')) {
          expectP('$')
          const vn = name()
          expectP(':')
          typeRef()
          if (isP('=')) {
            i++
            varDefaults[vn] = value()
          }
        }
        i++
      }
      skipDirectives()
      doc.operations.push({ name: opName, op: kw, varDefaults, selection: selectionSet() })
    } else {
      throw new Error(`Syntax Error: Unexpected Name "${kw}"`)
    }
  }
  if (!doc.operations.length) throw new Error('Syntax Error: Unexpected <EOF>')
  return doc
}

function literal(node, vars) {
  switch (node.k) {
    case 'var': return vars[node.name]
    case 'lit': return node.v
    case 'list': return node.items.map(n => literal(n, vars))
    case 'object': return Object.fromEntries(Object.entries(node.fields).map(([k, n]) => [k, literal(n, vars)]))
    default: return null
  }
}

// ---- introspection --------------------------------------------------------------------------------------
function typeRefOf(str) {
  const nonNull = str.endsWith('!')
  const core = nonNull ? str.slice(0, -1) : str
  let ref
  if (core.startsWith('[')) ref = { kind: 'LIST', name: null, ofType: typeRefOf(core.slice(1, -1)) }
  else ref = { kind: SCALARS.has(core) ? 'SCALAR' : 'OBJECT', name: core, ofType: null }
  return nonNull ? { kind: 'NON_NULL', name: null, ofType: ref } : ref
}

function introspectionSchema() {
  const types = Object.entries(TYPES).map(([tname, fields]) => ({
    kind: 'OBJECT',
    name: tname,
    fields: Object.entries(fields).map(([fname, ftype]) => ({
      name: fname,
      args: (ARGS[`${tname}.${fname}`] ?? []).map(a => ({ name: a.name, type: typeRefOf(a.type) })),
      type: typeRefOf(ftype),
    })),
  }))
  for (const s of SCALARS) types.push({ kind: 'SCALAR', name: s, fields: null })
  return { queryType: { name: 'Query' }, mutationType: null, types }
}

function project(value, selection, fragments) {
  if (!selection) return value
  if (Array.isArray(value)) return value.map(v => project(v, selection, fragments))
  if (value === null || typeof value !== 'object') return value
  const out = {}
  for (const f of flatten(selection, fragments)) out[f.alias ?? f.name] = project(value[f.name] ?? null, f.selection, fragments)
  return out
}

function flatten(selection, fragments) {
  const out = []
  for (const s of selection) {
    if (s.kind === 'field') out.push(s)
    else if (s.kind === 'spread') out.push(...flatten(fragments[s.name] ?? [], fragments))
    else if (s.kind === 'inline') out.push(...flatten(s.selection, fragments))
  }
  return out
}

// ---- executor -------------------------------------------------------------------------------------------
async function complete(value, typeStr, selection, run) {
  if (value === null || value === undefined) return null
  const core = typeStr.replace(/!$/, '')
  if (core.startsWith('[')) {
    const arr = Array.isArray(value) ? value : [value]
    return Promise.all(arr.map(v => complete(v, core.slice(1, -1), selection, run)))
  }
  if (SCALARS.has(core) || !selection) return value
  return execSelection(core, value, selection, run)
}

async function execSelection(typeName, parent, selection, run) {
  const out = {}
  for (const f of flatten(selection, run.fragments)) {
    const key = f.alias ?? f.name
    if (f.name === '__typename') { out[key] = typeName; continue }
    if (typeName === 'Query' && f.name === '__schema') { out[key] = project(introspectionSchema(), f.selection, run.fragments); continue }
    if (typeName === 'Query' && f.name === '__type') {
      const wanted = literal(f.args.name ?? { k: 'lit', v: '' }, run.vars)
      const found = introspectionSchema().types.find(t => t.name === wanted) ?? null
      out[key] = project(found, f.selection, run.fragments)
      continue
    }
    const fieldType = TYPES[typeName]?.[f.name]
    if (!fieldType) {
      run.errors.push({ message: `Cannot query field "${f.name}" on type "${typeName}".`, path: [key] })
      out[key] = null
      continue
    }
    try {
      const args = Object.fromEntries(Object.entries(f.args).map(([k, n]) => [k, literal(n, run.vars)]))
      const resolver = run.resolvers[typeName]?.[f.name]
      const value = resolver ? await resolver(parent, args, run.gctx) : parent?.[f.name]
      out[key] = await complete(value, fieldType, f.selection, run)
    } catch (err) {
      run.errors.push({ message: String(err?.message ?? err), path: [key] })
      out[key] = null
    }
  }
  return out
}

export async function executeGraphql({ query, variables, operationName }, resolvers, gctx) {
  let doc
  try {
    doc = parseDocument(String(query ?? ''))
  } catch (err) {
    return { errors: [{ message: String(err.message) }] }
  }
  const op = doc.operations.find(o => !operationName || o.name === operationName) ?? doc.operations[0]
  if (op.op !== 'query') return { errors: [{ message: `Operation "${op.op}" is not supported.` }] }
  const vars = { ...Object.fromEntries(Object.entries(op.varDefaults).map(([k, n]) => [k, literal(n, {})])), ...(variables && typeof variables === 'object' ? variables : {}) }
  const run = { vars, resolvers, gctx, fragments: doc.fragments, errors: [] }
  const data = await execSelection('Query', {}, op.selection, run)
  return run.errors.length ? { data, errors: run.errors } : { data }
}

// ---- resolvers & HTTP binding ---------------------------------------------------------------------------
export function register(router, ctx) {
  const requireAuth = g => {
    if (!g.user) throw new Error('Unauthorized: bearer token required')
    return g.user
  }
  const publicUser = (u, viewer) => ({
    id: u.id,
    name: u.displayName ?? u.name,
    email: u.tenantId === viewer.tenant ? u.email : null,
    tenantId: u.tenantId,
  })

  const resolvers = {
    Query: {
      me: (_p, _a, g) => {
        const viewer = requireAuth(g)
        const u = ctx.s.users.get(viewer.userId)
        return u ? publicUser(u, viewer) : null
      },
      // The user directory is intentionally public inside the product: any signed-in user can resolve a user node.
      user: (_p, a, g) => {
        const viewer = requireAuth(g)
        const u = ctx.s.users.get(String(a.id))
        return u ? publicUser(u, viewer) : null
      },
      project: (_p, a, g) => {
        const viewer = requireAuth(g)
        const p = ctx.s.projects.get(String(a.id))
        if (!p) return null
        if (p.tenantId !== viewer.tenant) throw new Error('Forbidden')
        return p
      },
      // hos-09: GraphQL scalar argument concatenated into SQL.
      products: (_p, a, g) => {
        requireAuth(g)
        try {
          if (ctx.fixed('hos-09')) {
            return a.sku === undefined || a.sku === null
              ? ctx.s.db.prepare('SELECT id, sku, name, price FROM products WHERE active = 1').all()
              : ctx.s.db.prepare('SELECT id, sku, name, price FROM products WHERE sku = ? AND active = 1').all(String(a.sku))
          }
          const sql = a.sku === undefined || a.sku === null
            ? 'SELECT id, sku, name, price FROM products WHERE active = 1'
            : `SELECT id, sku, name, price FROM products WHERE sku = '${a.sku}' AND active = 1`
          return ctx.s.db.prepare(sql).all()
        } catch (err) {
          throw new Error(`SQLITE_ERROR: ${String(err?.message ?? err)}`)
        }
      },
    },
    User: {
      // hos-02: nested resolver trusts the parent node and never re-checks tenant ownership of the invoices.
      invoices: (parent, _a, g) => {
        const viewer = requireAuth(g)
        if (ctx.fixed('hos-02') && parent.tenantId !== viewer.tenant) throw new Error('Forbidden')
        return [...ctx.s.invoices.values()].filter(i => i.ownerId === parent.id)
      },
    },
    Project: {
      owner: (parent, _a, g) => {
        const viewer = requireAuth(g)
        const u = ctx.s.users.get(parent.ownerId)
        return u ? publicUser(u, viewer) : null
      },
    },
  }

  const handler = async c => {
    let payload
    if (c.req.method === 'GET') {
      payload = {
        query: c.query.query,
        variables: c.query.variables ? safeJson(c.query.variables) : undefined,
        operationName: c.query.operationName,
      }
      if (!payload.query) {
        return sendJson(c.res, 200, { errors: [{ message: 'Must provide query string. POST {"query": "..."} to this endpoint.' }] })
      }
    } else {
      const raw = await c.text()
      const ctype = String(c.req.headers['content-type'] ?? '')
      payload = ctype.includes('application/graphql') ? { query: raw } : safeJson(raw)
      if (!payload || typeof payload !== 'object') return sendJson(c.res, 400, { errors: [{ message: 'Invalid JSON body.' }] })
    }
    const result = await executeGraphql(payload, resolvers, { user: c.user() })
    sendJson(c.res, 200, result)
  }

  router.get('/graphql', handler)
  router.post('/graphql', handler)
}

function safeJson(raw) {
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}
