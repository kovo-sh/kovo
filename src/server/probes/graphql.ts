// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import { matchesApprovedEndpointPattern } from '.././approval-judge.ts'
import type { BrokerExchangeResult, Grant } from '.././broker.ts'
import { responseSimilarity, setQueryParam } from './context.ts'
import type { DiffContext, DiffOutcome, InjectedRequest, ProbeDifferentialRequest } from './context.ts'
import type { ProbeModule } from './registry.ts'



export interface GraphqlFieldArg {
  name: string
  typeName: string
  isNonNull: boolean
  isList: boolean
  rawType: string
}



export interface GraphqlFieldDef {
  name: string
  args: GraphqlFieldArg[]
  returnTypeName: string
  isList: boolean
}



export interface GraphqlParsedSchema {
  queryType: string
  mutationType: string | null
  types: Record<string, GraphqlFieldDef[]>
}



export const GQL_BUILTIN_SCALARS = new Set(['ID', 'Int', 'Float', 'String', 'Boolean'])



export function parseSdlTypeString(raw: string): { typeName: string; isNonNull: boolean; isList: boolean; rawType: string } {
  const clean = raw.trim()
  const isNonNull = clean.endsWith('!')
  const isList = clean.includes('[')
  const typeName = clean.replace(/[\[\]!\s]/g, '') || 'String'
  return { typeName, isNonNull, isList, rawType: clean }
}



/** Deterministic GraphQL SDL parser (no external parser dependency; safe against malformed input). */
export function parseGraphqlSdl(sdl: string): GraphqlParsedSchema {
  const types: Record<string, GraphqlFieldDef[]> = {}
  const stripped = sdl
    .replace(/#[^\r\n]*/g, ' ')
    .replace(/"""[\s\S]*?"""/g, ' ')
    .replace(/"(?:\\.|[^"\\])*"/g, ' ')

  const typeRe = /\btype\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+implements\s+[^{]+)?\s*\{([^}]*)\}/g
  for (const m of stripped.matchAll(typeRe)) {
    const typeName = m[1]
    const body = m[2]
    const fields: GraphqlFieldDef[] = []
    const fieldRe = /([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?\s*:\s*([\[\]!A-Za-z0-9_]+)/g
    for (const fm of body.matchAll(fieldRe)) {
      const fieldName = fm[1]
      const argsRaw = fm[2] ?? ''
      const retRaw = fm[3]
      const args: GraphqlFieldArg[] = []
      if (argsRaw.trim()) {
        for (const piece of argsRaw.split(',')) {
          const am = /([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([\[\]!A-Za-z0-9_]+)/.exec(piece)
          if (!am) continue
          const parsedArgType = parseSdlTypeString(am[2])
          args.push({ name: am[1], ...parsedArgType })
        }
      }
      const parsedRet = parseSdlTypeString(retRaw)
      fields.push({ name: fieldName, args, returnTypeName: parsedRet.typeName, isList: parsedRet.isList })
    }
    if (fields.length > 0) types[typeName] = fields
  }

  return {
    queryType: types.Query ? 'Query' : (Object.keys(types).find(k => /query/i.test(k)) ?? 'Query'),
    mutationType: types.Mutation ? 'Mutation' : (Object.keys(types).find(k => /mutation/i.test(k)) ?? null),
    types,
  }
}



export function unwrapIntrospectionType(t: unknown): { typeName: string; isNonNull: boolean; isList: boolean; rawType: string } {
  const rec = (t && typeof t === 'object' ? t : {}) as { kind?: string; name?: string | null; ofType?: unknown }
  if (rec.kind === 'NON_NULL' && rec.ofType) {
    const inner = unwrapIntrospectionType(rec.ofType)
    return { ...inner, isNonNull: true, rawType: `${inner.rawType}!` }
  }
  if (rec.kind === 'LIST' && rec.ofType) {
    const inner = unwrapIntrospectionType(rec.ofType)
    return { ...inner, isList: true, rawType: `[${inner.rawType}]` }
  }
  const name = typeof rec.name === 'string' && rec.name ? rec.name : 'String'
  return { typeName: name, isNonNull: false, isList: false, rawType: name }
}



export function parseGraphqlIntrospection(schemaObj: Record<string, unknown>): GraphqlParsedSchema {
  const queryType = ((schemaObj.queryType as { name?: string } | undefined)?.name) ?? 'Query'
  const mutationType = ((schemaObj.mutationType as { name?: string } | undefined)?.name) ?? null
  const types: Record<string, GraphqlFieldDef[]> = {}
  const rawTypes = Array.isArray(schemaObj.types) ? schemaObj.types : []
  for (const rt of rawTypes) {
    if (!rt || typeof rt !== 'object') continue
    const tr = rt as { name?: string; kind?: string; fields?: unknown[] }
    if (!tr.name || tr.name.startsWith('__') || !Array.isArray(tr.fields)) continue
    if (tr.kind && tr.kind !== 'OBJECT' && tr.kind !== 'INTERFACE') continue
    const fields: GraphqlFieldDef[] = []
    for (const rf of tr.fields) {
      if (!rf || typeof rf !== 'object') continue
      const fr = rf as { name?: string; args?: unknown[]; type?: unknown }
      if (!fr.name) continue
      const args: GraphqlFieldArg[] = []
      for (const ra of Array.isArray(fr.args) ? fr.args : []) {
        if (!ra || typeof ra !== 'object') continue
        const ar = ra as { name?: string; type?: unknown }
        if (!ar.name) continue
        args.push({ name: ar.name, ...unwrapIntrospectionType(ar.type) })
      }
      const ret = unwrapIntrospectionType(fr.type)
      fields.push({ name: fr.name, args, returnTypeName: ret.typeName, isList: ret.isList })
    }
    if (fields.length > 0) types[tr.name] = fields
  }
  return { queryType, mutationType, types }
}



export function synthesizeGraphqlArgValue(arg: GraphqlFieldArg): unknown {
  let base: unknown
  switch (arg.typeName) {
    case 'ID': base = '1'; break
    case 'Int': base = 1; break
    case 'Float': base = 1.5; break
    case 'Boolean': base = true; break
    default: base = 'test'; break
  }
  return arg.isList ? [base] : base
}



export function buildSelectionSet(
  schema: GraphqlParsedSchema,
  typeName: string,
  depth: number,
  maxDepth: number,
  visited: Set<string>,
): { selection: string; nestedPath: string[] } {
  if (GQL_BUILTIN_SCALARS.has(typeName) || depth > maxDepth) {
    return { selection: '', nestedPath: [] }
  }
  const fields = schema.types[typeName]
  if (!fields || fields.length === 0) return { selection: '', nestedPath: [] }
  const scalarFields = fields.filter(f => GQL_BUILTIN_SCALARS.has(f.returnTypeName) || !schema.types[f.returnTypeName]).slice(0, 4)
  const objectFields = fields.filter(f => !GQL_BUILTIN_SCALARS.has(f.returnTypeName) && Boolean(schema.types[f.returnTypeName]))
  const parts: string[] = scalarFields.map(f => f.name)
  const nestedPath: string[] = []
  if (depth < maxDepth) {
    for (const objField of objectFields.slice(0, 3)) {
      if (visited.has(objField.returnTypeName)) continue
      const nextVisited = new Set(visited)
      nextVisited.add(objField.returnTypeName)
      const sub = buildSelectionSet(schema, objField.returnTypeName, depth + 1, maxDepth, nextVisited)
      if (sub.selection) {
        parts.push(`${objField.name} ${sub.selection}`)
        nestedPath.push(objField.name, ...sub.nestedPath)
      }
    }
  }
  if (parts.length === 0) parts.push('__typename')
  return { selection: `{ ${parts.join(' ')} }`, nestedPath }
}



export function buildGraphqlOperation(
  schema: GraphqlParsedSchema,
  opKind: 'query' | 'mutation',
  field: GraphqlFieldDef,
  maxDepth: number,
): { query: string; variables: Record<string, unknown>; nestedPath: string[] } {
  const variables: Record<string, unknown> = {}
  const varDecls: string[] = []
  const callArgs: string[] = []
  for (const arg of field.args) {
    const varName = arg.name.replace(/[^A-Za-z0-9_]/g, '') || 'arg'
    varDecls.push(`$${varName}: ${arg.rawType}`)
    callArgs.push(`${arg.name}: $${varName}`)
    variables[varName] = synthesizeGraphqlArgValue(arg)
  }
  const visited = new Set<string>([field.returnTypeName])
  const { selection, nestedPath } = buildSelectionSet(schema, field.returnTypeName, 1, maxDepth, visited)
  const opHeader = varDecls.length > 0 ? `${opKind}(${varDecls.join(', ')})` : opKind
  const callExpr = callArgs.length > 0 ? `${field.name}(${callArgs.join(', ')})` : field.name
  const query = `${opHeader} { ${callExpr}${selection ? ` ${selection}` : ''} }`
  return { query, variables, nestedPath }
}



/**
 * Resolve a GraphQL variable probe into a concrete operation: introspect the endpoint, find a root
 * field that accepts the parameter under test, and synthesize a typed query/mutation for it.
 * Only used when the caller did not supply an explicit `graphqlQuery`.
 */
export async function resolveGraphqlArgQuery(
  req: ProbeDifferentialRequest,
  send: (r: InjectedRequest & { persona?: string }) => Promise<BrokerExchangeResult | null>,
): Promise<void> {
  if (!req.param) return
  const introQuery = '{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{kind name ofType{kind name}}}}}}}'
  const intro = await send({
    method: 'POST',
    pathAndQuery: req.pathAndQuery,
    body: JSON.stringify({ query: introQuery }),
    headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
    persona: req.persona,
  })
  if (!intro) return
  let schemaObj: Record<string, unknown> | undefined
  try {
    const parsed = JSON.parse(intro.body) as { data?: { __schema?: Record<string, unknown> } }
    schemaObj = parsed.data?.__schema
  } catch {
    return
  }
  if (!schemaObj || !Array.isArray((schemaObj as { types?: unknown[] }).types)) return
  const schema = parseGraphqlIntrospection(schemaObj)
  const roots: Array<{ kind: 'query' | 'mutation'; typeName: string | null }> = [
    { kind: 'query', typeName: schema.queryType },
    { kind: 'mutation', typeName: schema.mutationType },
  ]
  for (const root of roots) {
    if (!root.typeName) continue
    const field = (schema.types[root.typeName] ?? []).find(f => f.args.some(a => a.name === req.param))
    if (!field) continue
    const op = buildGraphqlOperation(schema, root.kind, field, 3)
    req.graphqlQuery = op.query
    req.jsonBody = { ...(req.jsonBody ?? {}), variables: op.variables }
    return
  }
}



export async function diffGraphqlSurface(ctx: DiffContext, grant: Grant): Promise<DiffOutcome> {
  const { req, send, notes, anomalies } = ctx
  const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
  const tier = grant.tier ?? 1
  const useGet = req.method === 'GET'
  const gql = (
    query: string,
    variables?: Record<string, unknown>,
    persona: string | undefined = req.persona,
  ): InjectedRequest & { persona?: string } => {
    if (!useGet) {
      const payload: Record<string, unknown> = { query }
      if (variables && Object.keys(variables).length > 0) payload.variables = variables
      return {
        method: 'POST',
        pathAndQuery: req.pathAndQuery,
        body: JSON.stringify(payload),
        headers: { 'Content-Type': 'application/json', ...(req.headers ?? {}) },
        persona,
      }
    }
    let pq = setQueryParam(req.pathAndQuery, 'query', query)
    if (variables && Object.keys(variables).length > 0) {
      pq = setQueryParam(pq, 'variables', JSON.stringify(variables))
    }
    return { method: 'GET', pathAndQuery: pq, headers: req.headers, persona }
  }
  const parse = (body: string): { data?: Record<string, unknown>; errors?: Array<{ message?: string }> } | null => {
    try { return JSON.parse(body) as { data?: Record<string, unknown>; errors?: Array<{ message?: string }> } } catch { return null }
  }

  // Strictly bounded non-DoS limits (depth <= 6, aliases <= 8)
  const safeMaxDepth = Math.max(2, Math.min(req.maxDepth ?? 4, 6))
  const safeMaxAliases = Math.max(3, Math.min(req.maxAliases ?? 3, 8))

  const typename = await send(gql('{__typename}'))
  const fullIntroQuery = '{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{kind name ofType{kind name}}} type{kind name ofType{kind name ofType{kind name}}}}}}}'
  const introspection = await send(gql(fullIntroQuery))
  const introParsed = introspection ? parse(introspection.body) : null
  const introSchemaObj = introParsed?.data?.__schema as Record<string, unknown> | undefined
  const introspectionEnabled = Boolean(introSchemaObj && Array.isArray((introSchemaObj as { types?: unknown[] }).types))

  // Resolve schema: prefer live introspection, fall back to provided SDL (or merge SDL when introspection lacks nested types)
  let schema: GraphqlParsedSchema | null = null
  if (introspectionEnabled && introSchemaObj) {
    schema = parseGraphqlIntrospection(introSchemaObj)
  }
  if (req.sdl) {
    const sdlSchema = parseGraphqlSdl(req.sdl)
    if (!schema || Object.keys(schema.types).length <= 1) {
      schema = sdlSchema
    } else {
      schema = {
        queryType: schema.queryType || sdlSchema.queryType,
        mutationType: schema.mutationType ?? sdlSchema.mutationType,
        types: { ...sdlSchema.types, ...schema.types },
      }
    }
  }

  if (!typename && !schema) {
    return { verdict: 'inconclusive', summary: 'Endpoint did not return GraphQL JSON.', details: { status: null } }
  }

  const suggestion = await send(gql('{__typenam}'))
  const aliasBody = Array.from({ length: safeMaxAliases }, (_, i) => `a${i}:__typename`).join(' ')
  const alias = await send(gql(`{${aliasBody}}`))
  const suggestionLeak = Boolean(suggestion && /did you mean/i.test(suggestion.body))
  const aliasKeys = alias ? Object.keys((parse(alias.body)?.data ?? {})).length : 0

  const fuzzedQueries: Array<Record<string, unknown>> = []
  const fuzzedMutations: Array<Record<string, unknown>> = []

  if (schema) {
    const rootQueryFields = (schema.types[schema.queryType] ?? []).slice(0, 6)
    const idCandidates = [...new Set((req.resourceIds ?? []).filter(i => /^[A-Za-z0-9_.:-]{1,128}$/.test(i)))].slice(0, 2)
    const walkNested = (node: unknown, path: string[]): unknown => {
      let cur = node
      for (const key of path) {
        if (!cur || typeof cur !== 'object') return undefined
        cur = (cur as Record<string, unknown>)[key]
      }
      return cur
    }
    const nonEmpty = (v: unknown): boolean => (Array.isArray(v) ? v.length > 0 : Boolean(v && typeof v === 'object' && Object.keys(v as object).length > 0))
    for (const field of rootQueryFields) {
      const op = buildGraphqlOperation(schema, 'query', field, safeMaxDepth)
      if (req.ownerPersona && req.otherPersona) {
        const idArg = field.args.find(a => /^(?:ID|String)$/.test(a.typeName))
        const triedIds = idArg ? (idCandidates.length > 0 ? idCandidates : ['1']) : [undefined]
        for (const idValue of triedIds) {
          const variables = { ...op.variables }
          if (idArg && idValue !== undefined) variables[idArg.name] = idValue
          const ownerEx = await send(gql(op.query, variables, req.ownerPersona))
          const otherEx = await send(gql(op.query, variables, req.otherPersona))
          const ownerParsed = ownerEx ? parse(ownerEx.body) : null
          const otherParsed = otherEx ? parse(otherEx.body) : null
          const otherData = otherParsed?.data?.[field.name]
          const ownerData = ownerParsed?.data?.[field.name]
          const otherHasData = Boolean(
            otherEx && otherEx.status >= 200 && otherEx.status < 300 && otherData !== null && otherData !== undefined,
          )
          fuzzedQueries.push({
            field: field.name,
            resourceId: idValue ?? null,
            nestedPath: op.nestedPath,
            ownerStatus: ownerEx?.status ?? null,
            otherStatus: otherEx?.status ?? null,
            otherHasData,
          })
          if (!otherHasData || ownerData === null || ownerData === undefined) continue
          // Both actors must be reading the *same* root object. `me`-style resolvers return a
          // different node per caller, so identical nested shapes there are not object-level BOLA.
          if (ownerData && otherData && typeof ownerData === 'object' && typeof otherData === 'object') {
            const ownerRootId = (ownerData as Record<string, unknown>).id
            const otherRootId = (otherData as Record<string, unknown>).id
            if (ownerRootId !== undefined && otherRootId !== undefined && String(ownerRootId) !== String(otherRootId)) continue
          }
          // Nested-resource BOLA: both actors receive the same owned sub-collection/data.
          if (op.nestedPath.length > 0) {
            const ownerNested = walkNested(ownerData, op.nestedPath)
            const otherNested = walkNested(otherData, op.nestedPath)
            if (nonEmpty(ownerNested) && nonEmpty(otherNested) && JSON.stringify(ownerNested) === JSON.stringify(otherNested)) {
              anomalies.push({
                type: 'graphql_nested_bola', field: field.name, nestedPath: op.nestedPath,
                resourceId: idValue ?? null, otherPersona: req.otherPersona, status: otherEx!.status,
                query: op.query, variables,
              })
              break
            }
          }
          // Single-object BOLA: the other actor receives an object that names a different owner.
          if (idArg && otherData && typeof otherData === 'object') {
            const ownerRef = (otherData as Record<string, unknown>).owner ?? (otherData as Record<string, unknown>).ownerId
            const ownerId = ownerRef && typeof ownerRef === 'object' ? (ownerRef as Record<string, unknown>).id : ownerRef
            if (typeof ownerId === 'string' && req.otherUserId && ownerId !== req.otherUserId) {
              anomalies.push({
                type: 'graphql_cross_persona_access', field: field.name, resourceId: idValue ?? null,
                ownerField: ownerId, otherPersona: req.otherPersona, status: otherEx!.status,
                query: op.query, variables,
              })
              break
            }
          }
          if (!idArg || !idValue) break
        }
      } else {
        const ex = await send(gql(op.query, op.variables, req.persona))
        fuzzedQueries.push({
          field: field.name,
          nestedPath: op.nestedPath,
          status: ex?.status ?? null,
        })
      }
    }

    // Mutation fuzzing gate: strictly blocked on public Tier 2 without matching sandboxWriteAllowlist
    if (req.testMutations) {
      const hasSandboxAllowlist = Boolean(
        grant.sandboxWriteAllowlist?.length &&
        matchesApprovedEndpointPattern({ origin: ctx.origin, method: 'POST', pathAndQuery: req.pathAndQuery }, grant.sandboxWriteAllowlist),
      )
      const mutationsAllowed = localLab || tier >= 3 || hasSandboxAllowlist
      if (!mutationsAllowed) {
        notes.push('GraphQL mutation fuzzing skipped: requires Tier 3, local-lab, or matching sandboxWriteAllowlist.')
      } else if (schema.mutationType && schema.types[schema.mutationType]) {
        const mutFields = schema.types[schema.mutationType].slice(0, 4)
        for (const mf of mutFields) {
          const op = buildGraphqlOperation(schema, 'mutation', mf, Math.min(3, safeMaxDepth))
          const ex = await send(gql(op.query, op.variables, req.otherPersona ?? req.persona))
          const parsedMut = ex ? parse(ex.body) : null
          const succeeded = Boolean(ex && ex.status >= 200 && ex.status < 300 && parsedMut?.data && !parsedMut.errors?.length)
          fuzzedMutations.push({ field: mf.name, status: ex?.status ?? null, succeeded })
          if (succeeded) {
            anomalies.push({ type: 'graphql_mutation_accessible', field: mf.name, status: ex!.status })
          }
        }
      }
    }
  }

  // No SDL / introspection disabled: derive a nested object-level hypothesis from the target's own
  // field vocabulary. Root names come from discovered collection nouns; ids are other-actor objects.
  // A root that resolves for both actors with identical nested owned data is a resolver BOLA.
  if (!schema && req.ownerPersona && req.otherPersona) {
    const allRoots = [...new Set((req.graphqlRoots ?? []).filter(r => /^[A-Za-z_][A-Za-z0-9_]*$/.test(r)))]
    const rootPriority = ['account', 'user', 'organization', 'org', 'team', 'workspace', 'project', 'invoice', 'order', 'customer', 'member', 'ticket', 'issue', 'document', 'file', 'report', 'product']
    const rank = (name: string): number => {
      const idx = rootPriority.findIndex(p => name.toLowerCase() === p || name.toLowerCase().replace(/s$/, '') === p)
      return idx === -1 ? rootPriority.length : idx
    }
    const roots = allRoots
      .filter(r => (req.graphqlSeedsByRoot?.[r]?.length ?? 0) > 0)
      .sort((a, b) => rank(a) - rank(b) || a.length - b.length)
      .slice(0, 3)
    const fallbackIds = [...new Set((req.resourceIds ?? []).filter(id => /^[A-Za-z0-9_.:-]{1,128}$/.test(id)))].slice(0, 1)
    const nestedFields = ['tickets', 'invoices', 'orders', 'members', 'projects', 'accounts', 'files', 'documents', 'notes', 'comments', 'items', 'reports']
    for (const root of roots) {
      const rootIds = (req.graphqlSeedsByRoot?.[root]?.length ? req.graphqlSeedsByRoot[root]! : fallbackIds).slice(0, 1)
      const argNames = ['id', `${root.replace(/s$/i, '')}Id`, `${root}Id`].filter((v, i, a) => a.indexOf(v) === i)
      let rootFound = false
      for (const id of rootIds) {
        for (const argName of argNames) {
          const probe = `{ ${root}(${argName}: ${JSON.stringify(id)}) { id name } }`
          const ownerRoot = parse((await send(gql(probe, undefined, req.ownerPersona)))?.body ?? '')
          const otherRoot = parse((await send(gql(probe, undefined, req.otherPersona)))?.body ?? '')
          const ownerObj = ownerRoot?.data?.[root]
          const otherObj = otherRoot?.data?.[root]
          if (!ownerObj || !otherObj || typeof ownerObj !== 'object' || typeof otherObj !== 'object' || Array.isArray(ownerObj) || Array.isArray(otherObj)) continue
          rootFound = true
          fuzzedQueries.push({ field: root, argName, resourceId: id, discovery: 'no_sdl', status: otherRoot ? 200 : null })
          for (const nested of nestedFields.slice(0, 3)) {
            const q = `{ ${root}(${argName}: ${JSON.stringify(id)}) { id ${nested} { id name subject body title status } } }`
            const ownerEx = await send(gql(q, undefined, req.ownerPersona))
            const otherEx = await send(gql(q, undefined, req.otherPersona))
            const ownerData = parse(ownerEx?.body ?? '')?.data?.[root]
            const otherData = parse(otherEx?.body ?? '')?.data?.[root]
            const ownerNested = ownerData && typeof ownerData === 'object' ? (ownerData as Record<string, unknown>)[nested] : undefined
            const otherNested = otherData && typeof otherData === 'object' ? (otherData as Record<string, unknown>)[nested] : undefined
            const nonEmpty = (v: unknown): boolean => (Array.isArray(v) ? v.length > 0 : Boolean(v && typeof v === 'object' && Object.keys(v as object).length > 0))
            if (nonEmpty(ownerNested) && nonEmpty(otherNested) && JSON.stringify(ownerNested) === JSON.stringify(otherNested)) {
              anomalies.push({
                type: 'graphql_nested_bola', field: root, nestedPath: [nested], resourceId: id,
                otherPersona: req.otherPersona, status: otherEx?.status ?? null,
                query: q, variables: {}, discovery: 'no_sdl',
              })
              break
            }
          }
          break
        }
        if (anomalies.some(a => a.type === 'graphql_nested_bola')) break
        if (rootFound) break
      }
      if (anomalies.some(a => a.type === 'graphql_nested_bola')) break
    }
  }

  const details: Record<string, unknown> = {
    introspectionEnabled,
    typeCount: schema ? Object.keys(schema.types).length : null,
    fieldSuggestionLeak: suggestionLeak,
    aliasBatchingAllowed: aliasKeys >= 3,
    fuzzedQueries,
    fuzzedMutations,
  }
  if (req.persona) {
    const anon = await send(gql('{__schema{queryType{name}}}'))
    const authed = await send(gql('{__schema{queryType{name}}}', undefined, req.persona))
    if (anon && authed) {
      details.authDiff = {
        anonymousStatus: anon.status, personaStatus: authed.status,
        similarity: responseSimilarity(anon.body, authed.body),
        anonymousIntrospection: Boolean(parse(anon.body)?.data),
        personaIntrospection: Boolean(parse(authed.body)?.data),
      }
    }
  }
  if (introspectionEnabled) anomalies.push({ type: 'introspection_enabled' })
  if (suggestionLeak && !req.persona) anomalies.push({ type: 'field_suggestion_leak' })
  // Alias batching on an authenticated business API is expected GraphQL behaviour; only report it as
  // an unauthenticated schema-exposure signal.
  if (aliasKeys >= 3 && !req.persona) anomalies.push({ type: 'alias_batching_allowed', aliases: aliasKeys })
  return {
    verdict: anomalies.length > 0 ? 'signal' : 'no_signal',
    summary: anomalies.length > 0 ? 'GraphQL surface exposure or resolver authz indicators observed.' : 'No GraphQL exposure indicators observed.',
    details,
  }
}

export const graphqlProbe: ProbeModule = {
  family: 'graphql',
  classes: ['graphql_audit'],
  run: (ctx, deps) => diffGraphqlSurface(ctx, deps.grant),
}
