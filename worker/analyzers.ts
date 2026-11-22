import { createRequire } from 'node:module'

export type AnalyzerName =
  | 'js-harvest'
  | 'jwt-inspect'
  | 'graphql-parse'
  | 'openapi-parse'
  | 'diff-response'
  | 'dns-takeover'
  | 'secret-scan'
  | 'tech-fingerprint'
  | 'call-graph'

const require = createRequire(import.meta.url)

// ============================================================================
// Secret Masking Helper (self-contained so host & worker share protection)
// ============================================================================

function maskToken(raw: string): string {
  const trimmed = raw.trim()
  if (!trimmed) return '[masked]'
  if (trimmed.length <= 10) return `[masked:${trimmed.length}]`
  return `${trimmed.slice(0, 4)}…[masked:${trimmed.length}]…${trimmed.slice(-4)}`
}

const ANALYZER_SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^\n]*/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\b(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}\b/g,
  /\bsk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{20,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g,
  /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
]

function maskSecretsInText(input: string): string {
  if (!input) return input
  let out = input
  for (const re of ANALYZER_SECRET_PATTERNS) {
    out = out.replace(re, match => (match.startsWith('-----BEGIN') ? '[masked:private-key]' : maskToken(match)))
  }
  out = out.replace(
    /(\b(?:SERVICE_ROLE_KEY|SUPABASE_SERVICE_ROLE|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL|POSTGRES_URL|JWT_SECRET|NEXTAUTH_SECRET|API_KEY|API_SECRET|SECRET_KEY|PRIVATE_KEY|STRIPE_SECRET|WEBHOOK_SECRET)\s*[:=]\s*["'`])([^"'`\r\n]{6,})(["'`])/gi,
    (_m, pre: string, val: string, q: string) => `${pre}${maskToken(val)}${q}`,
  )
  return out
}

function uniq(items: string[], limit = 200): string[] {
  return [...new Set(items.filter(Boolean))].slice(0, limit)
}

// ============================================================================
// Optional Synchronous AST Parsers (@swc/core -> acorn -> typescript -> null)
// ============================================================================

interface SwcSpan { start?: number; end?: number }
interface SwcModule { type: string; body?: unknown[]; span?: SwcSpan }

interface SwcModuleApi {
  parseSync: (code: string, opts: Record<string, unknown>) => SwcModule
}

interface AcornApi {
  parse: (code: string, opts: Record<string, unknown>) => unknown
}

let cachedSwc: SwcModuleApi | null | undefined
let cachedAcorn: AcornApi | null | undefined

function loadSwc(): SwcModuleApi | null {
  if (cachedSwc !== undefined) return cachedSwc
  try {
    const mod = require('@swc/core') as SwcModuleApi
    cachedSwc = typeof mod?.parseSync === 'function' ? mod : null
  } catch {
    cachedSwc = null
  }
  return cachedSwc
}

function loadAcorn(): AcornApi | null {
  if (cachedAcorn !== undefined) return cachedAcorn
  try {
    const mod = require('acorn') as AcornApi
    cachedAcorn = typeof mod?.parse === 'function' ? mod : null
  } catch {
    cachedAcorn = null
  }
  return cachedAcorn
}

type AstParserKind = 'swc' | 'acorn' | 'regex'

function parseJsTsAst(content: string): { ast: unknown; kind: AstParserKind } {
  // Skip AST parsing on massive (> 2 MiB) or HTML-only documents
  if (content.length > 2 * 1024 * 1024 || /^\s*<!doctype\s+html|^\s*<html/i.test(content)) {
    return { ast: null, kind: 'regex' }
  }
  const swc = loadSwc()
  if (swc) {
    try {
      const ast = swc.parseSync(content, {
        syntax: 'typescript',
        tsx: true,
        decorators: true,
        dynamicImport: true,
        target: 'es2022',
      })
      return { ast, kind: 'swc' }
    } catch {
      try {
        const ast = swc.parseSync(content, {
          syntax: 'ecmascript',
          jsx: true,
          dynamicImport: true,
          target: 'es2022',
        })
        return { ast, kind: 'swc' }
      } catch {
        // try acorn next
      }
    }
  }
  const acorn = loadAcorn()
  if (acorn) {
    try {
      const ast = acorn.parse(content, {
        ecmaVersion: 'latest',
        sourceType: 'module',
        allowReturnOutsideFunction: true,
        allowImportExportEverywhere: true,
        locations: true,
      })
      return { ast, kind: 'acorn' }
    } catch {
      try {
        const ast = acorn.parse(content, {
          ecmaVersion: 'latest',
          sourceType: 'script',
          allowReturnOutsideFunction: true,
          locations: true,
        })
        return { ast, kind: 'acorn' }
      } catch {
        // malformed JS -> regex fallback
      }
    }
  }
  return { ast: null, kind: 'regex' }
}

// ============================================================================
// Generic AST Walking & Expression Resolution Utilities (handles SWC & Acorn)
// ============================================================================

type AstNode = Record<string, unknown>

function isAstNode(v: unknown): v is AstNode {
  return Boolean(v && typeof v === 'object' && !Array.isArray(v) && typeof (v as AstNode).type === 'string')
}

function walkAst(node: unknown, visit: (n: AstNode, ancestors: AstNode[]) => void, ancestors: AstNode[] = []): void {
  if (!node || typeof node !== 'object') return
  if (Array.isArray(node)) {
    for (const item of node) walkAst(item, visit, ancestors)
    return
  }
  const rec = node as AstNode
  if (typeof rec.type === 'string') {
    visit(rec, ancestors)
    ancestors.push(rec)
    for (const [k, v] of Object.entries(rec)) {
      if (k === 'span' || k === 'loc' || k === 'type') continue
      if (v && typeof v === 'object') walkAst(v, visit, ancestors)
    }
    ancestors.pop()
  } else {
    for (const v of Object.values(rec)) {
      if (v && typeof v === 'object') walkAst(v, visit, ancestors)
    }
  }
}

function getPropName(node: unknown): string | null {
  if (!isAstNode(node)) return null
  if (node.type === 'Identifier' && typeof node.value === 'string') return node.value // SWC
  if (node.type === 'Identifier' && typeof node.name === 'string') return node.name // Acorn
  if (node.type === 'StringLiteral' && typeof node.value === 'string') return node.value
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value
  return null
}

function getCalleeParts(callee: unknown): string[] {
  if (!isAstNode(callee)) return []
  if (callee.type === 'Identifier') {
    const n = getPropName(callee)
    return n ? [n] : []
  }
  if (callee.type === 'MemberExpression') {
    const obj = getCalleeParts(callee.object)
    const prop = getPropName(callee.property)
    return prop ? [...obj, prop] : obj
  }
  if (callee.type === 'ChainExpression' && callee.expression) {
    return getCalleeParts(callee.expression)
  }
  return []
}

function unwrapExpr(node: unknown): unknown {
  if (!isAstNode(node)) return node
  if (node.type === 'ParenthesisExpression' || node.type === 'ChainExpression' || node.type === 'TsAsExpression' || node.type === 'TsTypeAssertion' || node.type === 'TsNonNullExpression') {
    return unwrapExpr(node.expression)
  }
  return node
}

function resolveStringValue(rawNode: unknown, envConsts?: Map<string, string>, depth = 0): string | null {
  if (depth > 6) return null
  const node = unwrapExpr(rawNode)
  if (!isAstNode(node)) return null
  if (node.type === 'StringLiteral' && typeof node.value === 'string') return node.value
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value
  if (node.type === 'Identifier') {
    const name = getPropName(node)
    if (name && envConsts?.has(name)) return envConsts.get(name)!
    return null
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = resolveStringValue(node.left, envConsts, depth + 1)
    const right = resolveStringValue(node.right, envConsts, depth + 1)
    if (left !== null && right !== null) return left + right
    if (left !== null && isAstNode(node.right)) return left + ':param'
    return null
  }
  if (node.type === 'TemplateLiteral' && Array.isArray(node.quasis)) {
    const quasis = node.quasis as AstNode[]
    const exprs = Array.isArray(node.expressions) ? node.expressions : []
    let out = ''
    for (let i = 0; i < quasis.length; i += 1) {
      const q = quasis[i]
      const raw = typeof q.cooked === 'string'
        ? q.cooked
        : typeof q.raw === 'string'
          ? q.raw
          : isAstNode(q.value) && typeof q.value.cooked === 'string'
            ? q.value.cooked
            : isAstNode(q.value) && typeof q.value.raw === 'string'
              ? q.value.raw
              : ''
      out += raw
      if (i < exprs.length) {
        const resolved = resolveStringValue(exprs[i], envConsts, depth + 1)
        out += resolved !== null ? resolved : ':param'
      }
    }
    return out
  }
  return null
}

function getCallArgs(node: AstNode): unknown[] {
  if (!Array.isArray(node.arguments)) return []
  return node.arguments.map(a => (a && typeof a === 'object' && (a as AstNode).expression !== undefined ? (a as AstNode).expression : a))
}

function getObjectProps(objNode: unknown): Array<{ key: string; value: unknown }> {
  const unwrapped = unwrapExpr(objNode)
  if (!isAstNode(unwrapped) || unwrapped.type !== 'ObjectExpression' || !Array.isArray(unwrapped.properties)) {
    return []
  }
  const out: Array<{ key: string; value: unknown }> = []
  for (const prop of unwrapped.properties) {
    if (!isAstNode(prop)) continue
    if (prop.type === 'KeyValueProperty' || prop.type === 'Property') {
      const key = getPropName(prop.key)
      if (key) out.push({ key, value: prop.value })
    } else if (prop.type === 'Identifier') {
      const key = getPropName(prop)
      if (key) out.push({ key, value: prop })
    }
  }
  return out
}

function extractBodyKeysFromExpr(expr: unknown): string[] {
  const unwrapped = unwrapExpr(expr)
  if (!isAstNode(unwrapped)) return []
  if (unwrapped.type === 'ObjectExpression') {
    return getObjectProps(unwrapped).map(p => p.key).slice(0, 30)
  }
  if (unwrapped.type === 'CallExpression') {
    const parts = getCalleeParts(unwrapped.callee)
    if (parts.join('.') === 'JSON.stringify') {
      const first = getCallArgs(unwrapped)[0]
      return extractBodyKeysFromExpr(first)
    }
  }
  if (unwrapped.type === 'NewExpression') {
    const parts = getCalleeParts(unwrapped.callee)
    if (parts[0] === 'URLSearchParams' || parts[0] === 'FormData') {
      const first = getCallArgs(unwrapped)[0]
      return extractBodyKeysFromExpr(first)
    }
  }
  return []
}

function extractJsxStringAttr(attr: unknown): string | null {
  if (!isAstNode(attr)) return null
  if (attr.type === 'StringLiteral' && typeof attr.value === 'string') return attr.value
  if (attr.type === 'Literal' && typeof attr.value === 'string') return attr.value
  if (attr.type === 'JSXExpressionContainer' && attr.expression) {
    return resolveStringValue(attr.expression)
  }
  return null
}

function lineNumberAtOffset(content: string, offset?: number): number | undefined {
  if (typeof offset !== 'number' || offset < 0) return undefined
  let line = 1
  const end = Math.min(offset, content.length)
  for (let i = 0; i < end; i += 1) {
    if (content.charCodeAt(i) === 10) line += 1
  }
  return line
}

function nodeLine(node: AstNode, content: string): number | undefined {
  const loc = node.loc as { start?: { line?: number } } | undefined
  if (typeof loc?.start?.line === 'number') return loc.start.line
  const span = node.span as SwcSpan | undefined
  if (typeof span?.start === 'number') return lineNumberAtOffset(content, span.start)
  return undefined
}

function subtreeHasOriginCheck(fnNode: unknown): boolean {
  let hasOriginAccess = false
  walkAst(fnNode, n => {
    if (hasOriginAccess) return
    if (n.type === 'MemberExpression') {
      const prop = getPropName(n.property)
      if (prop === 'origin') hasOriginAccess = true
    } else if (n.type === 'Identifier') {
      const name = getPropName(n)
      if (name === 'allowedOrigins' || name === 'trustedOrigin') hasOriginAccess = true
    }
  })
  return hasOriginAccess
}

function parseGraphqlDocText(raw: string): { kind: 'query' | 'mutation' | 'subscription' | 'fragment'; name: string; fields: string[]; preview: string } | null {
  const m = raw.match(/\b(query|mutation|subscription|fragment)\s+([A-Za-z0-9_]{1,64})/)
  if (!m) return null
  const kind = m[1] as 'query' | 'mutation' | 'subscription' | 'fragment'
  const name = m[2]
  const bodyStart = raw.indexOf('{', m.index ?? 0)
  const fields: string[] = []
  if (bodyStart >= 0) {
    const snippet = raw.slice(bodyStart + 1, bodyStart + 400)
    for (const fm of snippet.matchAll(/\b([a-zA-Z_][a-zA-Z0-9_]{1,40})\s*(?:\(|\{|$)/g)) {
      if (!fields.includes(fm[1]) && fields.length < 12) fields.push(fm[1])
    }
  }
  return {
    kind,
    name,
    fields,
    preview: maskSecretsInText(raw.replace(/\s+/g, ' ').trim().slice(0, 180)),
  }
}

// ============================================================================
// AST-Based jsHarvest + Source-Map Recovery
// ============================================================================

const ADMIN_PATH_RE = /^\/.*(?:admin|internal|debug|ops|backoffice|impersonat|billing|export|graphql|trpc|audit)/i
const PATH_LIKE_RE = /^\/[a-zA-Z0-9_.:/${}?=&%-]{1,200}$/
const API_PATH_PREFIX_RE = /^\/(?:api|v[1-9]\d*|graphql|trpc|auth|oauth|sso|admin|internal|debug|upload|webhook|billing|account|user|session|_next\/data|health|metrics)/i
const NEXT_ACTION_HEX_RE = /^[a-f0-9]{40,64}$/i
const FEATURE_FLAG_IDENT_RE = /^(?:FEATURE_|NEXT_PUBLIC_ENABLE_|ENABLE_)[A-Z0-9_]{2,}$/

export interface JsHarvestOptions {
  sourceMapContent?: string
  maxMapBytes?: number
  maxMapSources?: number
  maxSourceBytes?: number
}

interface JsHarvestRoute {
  path: string
  kind: 'router' | 'jsx' | 'nav'
  line?: number
}

interface JsHarvestHttpCall {
  client: 'fetch' | 'axios' | 'trpc' | 'xhr'
  url: string
  method: string
  bodyKeys: string[]
  line?: number
}

interface JsHarvestDomSinkDetail {
  kind: string
  line?: number
  missingOriginCheck?: boolean
  snippet?: string
}

export function jsHarvest(content: string, sourceName = '', options?: JsHarvestOptions): Record<string, unknown> {
  const routes: JsHarvestRoute[] = []
  const httpCalls: JsHarvestHttpCall[] = []
  const graphqlDocs: Array<{ kind: 'query' | 'mutation' | 'subscription' | 'fragment'; name: string; fields: string[]; preview: string }> = []
  const nextActions: Array<{ id: string; source: 'header' | 'reference' | 'literal'; preview: string }> = []
  const featureFlags: string[] = []
  const domSinkDetails: JsHarvestDomSinkDetail[] = []
  const astPaths: string[] = []
  const astDomSinks: string[] = []

  const { ast, kind: parserUsed } = parseJsTsAst(content)

  if (ast) {
    // Pass 0: collect simple top-level/local string variable assignments for `fetch(e, ...)` resolution
    const stringConsts = new Map<string, string>()
    walkAst(ast, node => {
      if (node.type === 'VariableDeclarator') {
        const name = getPropName(node.id)
        if (name && node.init) {
          const val = resolveStringValue(node.init, stringConsts)
          if (val !== null && val.length <= 240) stringConsts.set(name, val)
        }
      }
    })

    // Pass 1: single AST walk for routes, HTTP/RPC calls, GraphQL, Next-Action, feature flags, DOM sinks
    walkAst(ast, node => {
      const line = nodeLine(node, content)

      // 1. Router config objects: { path: '...' }
      if (node.type === 'KeyValueProperty' || node.type === 'Property') {
        const key = getPropName(node.key)
        if (key === 'path' || key === 'route' || key === 'endpoint') {
          const val = resolveStringValue(node.value, stringConsts)
          if (val && val.startsWith('/') && val.length <= 200) {
            routes.push({ path: maskSecretsInText(val), kind: 'router', line })
            astPaths.push(val)
          }
        }
        if (key && key.toLowerCase() === 'next-action') {
          const val = resolveStringValue(node.value, stringConsts)
          if (val && val.length >= 8) {
            nextActions.push({ id: maskSecretsInText(val.slice(0, 80)), source: 'header', preview: `Next-Action: ${val.slice(0, 48)}` })
          }
        }
        if (key && FEATURE_FLAG_IDENT_RE.test(key)) {
          featureFlags.push(key)
        }
      }

      // 2. JSX Route/Link & dangerouslySetInnerHTML
      if (node.type === 'JSXAttribute') {
        const attrName = getPropName(node.name)
        if (attrName === 'dangerouslySetInnerHTML') {
          astDomSinks.push('dangerouslySetInnerHTML')
          domSinkDetails.push({ kind: 'dangerouslySetInnerHTML', line })
        } else if (attrName === 'path' || attrName === 'to' || attrName === 'href') {
          const val = extractJsxStringAttr(node.value)
          if (val && val.startsWith('/') && val.length <= 200) {
            routes.push({ path: maskSecretsInText(val), kind: 'jsx', line })
            astPaths.push(val)
          }
        }
      }

      // 3. Call expressions: fetch, axios, router nav, trpc, addEventListener('message'), feature flags, createServerReference
      if (node.type === 'CallExpression') {
        const parts = getCalleeParts(node.callee)
        const joined = parts.join('.')
        const last = parts[parts.length - 1] ?? ''
        const args = getCallArgs(node)

        // Navigation calls: router.push, history.push, navigate, redirect
        if (['push', 'replace', 'navigate', 'redirect'].includes(last) &&
          (parts.length === 1 || /^(?:router|history|navigation|Router|NextResponse)$/i.test(parts[0] ?? ''))) {
          const dest = resolveStringValue(args[0], stringConsts)
          if (dest && dest.startsWith('/')) {
            routes.push({ path: maskSecretsInText(dest), kind: 'nav', line })
            astPaths.push(dest)
          }
        }

        // fetch(url, init)
        if (last === 'fetch' && parts.length <= 2 && args.length >= 1) {
          const url = resolveStringValue(args[0], stringConsts)
          let method = 'GET'
          let bodyKeys: string[] = []
          if (args[1]) {
            for (const p of getObjectProps(args[1])) {
              if (p.key === 'method') {
                const m = resolveStringValue(p.value, stringConsts)
                if (m) method = m.toUpperCase()
              } else if (p.key === 'body') {
                bodyKeys = extractBodyKeysFromExpr(p.value)
              }
            }
          }
          if (url) {
            httpCalls.push({ client: 'fetch', url: maskSecretsInText(url), method, bodyKeys, line })
            if (url.startsWith('/')) astPaths.push(url)
          }
        }

        // axios.get/post/... or axios({ url, method, data })
        if (parts[0] === 'axios') {
          if (parts.length === 2 && ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(last)) {
            const url = resolveStringValue(args[0], stringConsts)
            const method = last.toUpperCase()
            const bodyKeys = ['POST', 'PUT', 'PATCH'].includes(method) ? extractBodyKeysFromExpr(args[1]) : []
            if (url) {
              httpCalls.push({ client: 'axios', url: maskSecretsInText(url), method, bodyKeys, line })
              if (url.startsWith('/')) astPaths.push(url)
            }
          } else if (parts.length === 1 && args[0]) {
            let url = ''
            let method = 'GET'
            let bodyKeys: string[] = []
            for (const p of getObjectProps(args[0])) {
              if (p.key === 'url') url = resolveStringValue(p.value, stringConsts) ?? ''
              if (p.key === 'method') method = (resolveStringValue(p.value, stringConsts) ?? 'GET').toUpperCase()
              if (p.key === 'data' || p.key === 'params') bodyKeys = extractBodyKeysFromExpr(p.value)
            }
            if (url) {
              httpCalls.push({ client: 'axios', url: maskSecretsInText(url), method, bodyKeys, line })
              if (url.startsWith('/')) astPaths.push(url)
            }
          }
        }

        // trpc.<router>.<proc>.query|mutate|useQuery|useMutation(input)
        if ((parts[0] === 'trpc' || parts.includes('trpc')) && parts.length >= 3 &&
          ['query', 'mutate', 'useQuery', 'useMutation'].includes(last)) {
          const procPath = parts.slice(parts.indexOf('trpc') + 1, -1).join('.')
          if (procPath) {
            const url = `/trpc/${procPath}`
            const method = last.toLowerCase().includes('mutat') ? 'POST' : 'GET'
            const bodyKeys = extractBodyKeysFromExpr(args[0])
            httpCalls.push({ client: 'trpc', url, method, bodyKeys, line })
            astPaths.push(url)
          }
        }

        // Feature flag calls
        if (['useFeatureFlag', 'isFeatureEnabled', 'getFeatureFlag', 'variation', 'hasFlag'].includes(last)) {
          const flagName = resolveStringValue(args[0], stringConsts)
          if (flagName && flagName.length <= 100) featureFlags.push(flagName)
        }

        // Next.js createServerReference(actionId, ...)
        if (last === 'createServerReference') {
          const actionId = resolveStringValue(args[0], stringConsts)
          if (actionId) {
            nextActions.push({ id: maskSecretsInText(actionId), source: 'reference', preview: `createServerReference(${actionId.slice(0, 48)})` })
          }
        }

        // DOM sinks: addEventListener('message', fn), postMessage, eval, document.write, window.open
        if (last === 'addEventListener' && resolveStringValue(args[0], stringConsts) === 'message') {
          astDomSinks.push('message-listener')
          const missingOrigin = args[1] ? !subtreeHasOriginCheck(args[1]) : false
          if (missingOrigin) astDomSinks.push('message-listener-missing-origin')
          domSinkDetails.push({ kind: 'message-listener', line, missingOriginCheck: missingOrigin })
        }
        if (last === 'postMessage') {
          astDomSinks.push('postMessage')
          domSinkDetails.push({ kind: 'postMessage', line })
        }
        if (joined === 'eval' || joined === 'document.write' || joined === 'document.writeln' || joined === 'window.open') {
          astDomSinks.push(joined)
          domSinkDetails.push({ kind: joined, line })
        }
      }

      // 4. Tagged templates: gql`...` / graphql`...`
      if (node.type === 'TaggedTemplateExpression') {
        const tagParts = getCalleeParts(node.tag)
        const tagName = tagParts[tagParts.length - 1] ?? ''
        if (/^(?:gql|graphql)$/i.test(tagName) && isAstNode(node.quasi) && Array.isArray(node.quasi.quasis)) {
          const text = (node.quasi.quasis as AstNode[])
            .map(q => (typeof q.raw === 'string' ? q.raw : isAstNode(q.value) && typeof q.value.raw === 'string' ? q.value.raw : ''))
            .join(' ')
          const doc = parseGraphqlDocText(text)
          if (doc) graphqlDocs.push(doc)
        }
      }

      // 5. Assignments: *.innerHTML = ..., *.outerHTML = ..., *.onmessage = fn, document.domain = ...
      if (node.type === 'AssignmentExpression' && isAstNode(node.left)) {
        const leftParts = getCalleeParts(node.left)
        const prop = leftParts[leftParts.length - 1] ?? ''
        if (prop === 'innerHTML' || prop === 'outerHTML') {
          astDomSinks.push(prop)
          domSinkDetails.push({ kind: prop, line })
        } else if (prop === 'onmessage') {
          astDomSinks.push('message-listener')
          const missingOrigin = node.right ? !subtreeHasOriginCheck(node.right) : false
          if (missingOrigin) astDomSinks.push('message-listener-missing-origin')
          domSinkDetails.push({ kind: 'message-listener', line, missingOriginCheck: missingOrigin })
        } else if (leftParts.join('.') === 'document.domain') {
          astDomSinks.push('document.domain')
          domSinkDetails.push({ kind: 'document.domain', line })
        }
      }

      // 6. String/Template literals & feature flag identifiers
      if (node.type === 'StringLiteral' || node.type === 'Literal') {
        const val = typeof node.value === 'string' ? node.value : null
        if (val) {
          if (API_PATH_PREFIX_RE.test(val) && PATH_LIKE_RE.test(val)) {
            astPaths.push(val)
          }
          if (/\b(?:query|mutation|subscription|fragment)\s+[A-Za-z0-9_]+\s*[({]/.test(val)) {
            const doc = parseGraphqlDocText(val)
            if (doc) graphqlDocs.push(doc)
          }
          if (NEXT_ACTION_HEX_RE.test(val) && content.includes('Next-Action')) {
            nextActions.push({ id: val, source: 'literal', preview: val.slice(0, 48) })
          }
        }
      }

      if (node.type === 'Identifier') {
        const name = getPropName(node)
        if (name && FEATURE_FLAG_IDENT_RE.test(name)) featureFlags.push(name)
      }
    })
  }

  // Hardened regex supplement (ensures resilience on malformed JS / HTML / inline scripts)
  const regexApiPaths = [
    ...[...content.matchAll(/["'`](\/(?:api|v[1-9]\d*|graphql|trpc|auth|oauth|sso|admin|internal|debug|upload|webhook|billing|account|user|session|_next\/data)[a-zA-Z0-9_./:${}-]{0,140})["'`]/g)].map(m => m[1]),
    ...[...content.matchAll(/(?:fetch|axios\.(?:get|post|put|patch|delete)|url\s*:\s*)\(\s*["'`](\/[a-zA-Z0-9_./:${}?=&-]{1,160})["'`]/g)].map(m => m[1]),
  ]
  const apiPaths = uniq([...astPaths, ...regexApiPaths].map(maskSecretsInText), 200)
  const adminPaths = uniq(
    [...apiPaths, ...routes.map(r => r.path)].filter(p => ADMIN_PATH_RE.test(p)),
    80,
  )

  const scriptChunks = uniq([
    ...[...content.matchAll(/["'`](\/_next\/static\/[a-zA-Z0-9_./-]+\.(?:js|mjs|json))["'`]/g)].map(m => maskSecretsInText(m[1])),
    ...[...content.matchAll(/src=["'](\/[^"']+\.(?:js|mjs)(?:\?[^"']*)?)["']/gi)].map(m => maskSecretsInText(m[1])),
  ], 120)

  const sourceMaps = uniq([
    ...[...content.matchAll(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/g)].map(m => m[1]),
  ], 40)

  const externalUrls = uniq([
    ...[...content.matchAll(/(?:https?|wss?):\/\/[a-zA-Z0-9.-]+(?::\d+)?(?:\/[a-zA-Z0-9_./?=&%+-]{0,120})?/g)].map(m => maskSecretsInText(m[0])),
  ].filter(u => !/w3\.org|schema\.org|googleapis\.com\/css|fonts\.gstatic|mozilla\.org/.test(u)), 120)

  const regexDomSinks = [
    ...(content.includes('postMessage') ? ['postMessage'] : []),
    ...(content.includes("addEventListener('message'") || content.includes('addEventListener("message"') ? ['message-listener'] : []),
    ...(content.includes('dangerouslySetInnerHTML') ? ['dangerouslySetInnerHTML'] : []),
    ...(/\binnerHTML\b/.test(content) ? ['innerHTML'] : []),
    ...(/\beval\s*\(/.test(content) ? ['eval'] : []),
    ...(/\bdocument\.domain\b/.test(content) ? ['document.domain'] : []),
    ...(/window\.open\s*\(/.test(content) ? ['window.open'] : []),
  ]
  const domSinks = uniq([...astDomSinks, ...regexDomSinks], 30)

  if (nextActions.length === 0) {
    for (const m of content.matchAll(/["']Next-Action["']\s*:\s*["']([a-f0-9]{16,64})["']/gi)) {
      nextActions.push({ id: m[1], source: 'header', preview: `Next-Action: ${m[1].slice(0, 48)}` })
    }
  }
  if (graphqlDocs.length === 0) {
    for (const m of content.matchAll(/\b(?:query|mutation|subscription|fragment)\s+([A-Za-z0-9_]{2,64})\b[^`"'{}]*\{[^}]{1,300}\}/g)) {
      const doc = parseGraphqlDocText(m[0])
      if (doc) graphqlDocs.push(doc)
    }
  }

  const nextDataMatch = content.match(/<script[^>]+id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i)
  let nextMeta: Record<string, unknown> | undefined
  if (nextDataMatch) {
    try {
      const parsed = JSON.parse(nextDataMatch[1]) as Record<string, unknown>
      nextMeta = {
        page: parsed.page,
        buildId: parsed.buildId,
        runtimeConfigKeys: parsed.runtimeConfig && typeof parsed.runtimeConfig === 'object' ? Object.keys(parsed.runtimeConfig) : [],
        propKeys: parsed.props && typeof parsed.props === 'object' ? Object.keys(parsed.props) : [],
      }
    } catch {
      nextMeta = { parseError: true }
    }
  }

  const secretFindings = secretScan(content, sourceName)
  const baseResult: Record<string, unknown> = {
    sourceName,
    bytes: content.length,
    parserUsed,
    apiPaths,
    adminPaths,
    routes: routes.slice(0, 120),
    httpCalls: httpCalls.slice(0, 120),
    graphqlDocs: graphqlDocs.slice(0, 40),
    nextActions: nextActions.slice(0, 40),
    featureFlags: uniq(featureFlags, 60),
    scriptChunks,
    sourceMaps,
    externalUrls,
    domSinks,
    domSinkDetails: domSinkDetails.slice(0, 40),
    ...(nextMeta ? { nextMeta } : {}),
    secretMatches: secretFindings.matches,
  }

  if (options?.sourceMapContent) {
    const mapSummary = analyzeSourceMapContent(options.sourceMapContent, sourceName, options)
    mergeHarvestResults(baseResult, mapSummary.aggregated)
    baseResult.sourceMapAnalysis = mapSummary.meta
  }

  return baseResult
}

const DEFAULT_MAX_MAP_BYTES = 4 * 1024 * 1024
const DEFAULT_MAX_MAP_SOURCES = 60
const DEFAULT_MAX_SOURCE_BYTES = 512 * 1024

function analyzeSourceMapContent(
  rawMap: string,
  sourceName: string,
  options?: JsHarvestOptions,
): {
  meta: Record<string, unknown>
  aggregated: {
    apiPaths: string[]
    adminPaths: string[]
    routes: JsHarvestRoute[]
    httpCalls: JsHarvestHttpCall[]
    graphqlDocs: Array<{ kind: string; name: string; fields: string[]; preview: string }>
    nextActions: Array<{ id: string; source: string; preview: string }>
    featureFlags: string[]
    domSinks: string[]
    domSinkDetails: JsHarvestDomSinkDetail[]
    secretMatches: Array<{ kind: string; preview: string; index: number }>
  }
} {
  const maxMapBytes = options?.maxMapBytes ?? DEFAULT_MAX_MAP_BYTES
  const maxMapSources = options?.maxMapSources ?? DEFAULT_MAX_MAP_SOURCES
  const maxSourceBytes = options?.maxSourceBytes ?? DEFAULT_MAX_SOURCE_BYTES

  const aggregated = {
    apiPaths: [] as string[],
    adminPaths: [] as string[],
    routes: [] as JsHarvestRoute[],
    httpCalls: [] as JsHarvestHttpCall[],
    graphqlDocs: [] as Array<{ kind: string; name: string; fields: string[]; preview: string }>,
    nextActions: [] as Array<{ id: string; source: string; preview: string }>,
    featureFlags: [] as string[],
    domSinks: [] as string[],
    domSinkDetails: [] as JsHarvestDomSinkDetail[],
    secretMatches: [] as Array<{ kind: string; preview: string; index: number }>,
  }

  if (Buffer.byteLength(rawMap, 'utf8') > maxMapBytes) {
    return {
      meta: { parsed: false, truncated: true, reason: `Source map exceeded ${maxMapBytes} byte cap`, sourcesTotal: 0, sourcesAnalyzed: 0, recoveredFiles: [] },
      aggregated,
    }
  }

  try {
    const mapObj = JSON.parse(rawMap) as { version?: number; sources?: unknown[]; sourcesContent?: unknown[] }
    const sources = Array.isArray(mapObj.sources) ? mapObj.sources.map(s => String(s ?? '')) : []
    const contents = Array.isArray(mapObj.sourcesContent) ? mapObj.sourcesContent : []
    const recoveredFiles: string[] = []
    let analyzed = 0
    let truncated = sources.length > maxMapSources

    for (let i = 0; i < Math.min(sources.length, maxMapSources); i += 1) {
      const srcPath = sources[i] || `source-${i}.js`
      const rawEntry = contents[i]
      if (typeof rawEntry !== 'string' || !rawEntry) continue
      const srcCode: string = rawEntry
      if (srcPath.includes('node_modules/')) continue
      recoveredFiles.push(srcPath)
      const bounded = srcCode.length > maxSourceBytes ? srcCode.slice(0, maxSourceBytes) : srcCode
      if (srcCode.length > maxSourceBytes) truncated = true
      analyzed += 1
      const sub = jsHarvest(bounded, `${sourceName}#${srcPath}`)
      aggregated.apiPaths.push(...((sub.apiPaths as string[]) ?? []))
      aggregated.adminPaths.push(...((sub.adminPaths as string[]) ?? []))
      aggregated.routes.push(...((sub.routes as JsHarvestRoute[]) ?? []))
      aggregated.httpCalls.push(...((sub.httpCalls as JsHarvestHttpCall[]) ?? []))
      aggregated.graphqlDocs.push(...((sub.graphqlDocs as Array<{ kind: string; name: string; fields: string[]; preview: string }>) ?? []))
      aggregated.nextActions.push(...((sub.nextActions as Array<{ id: string; source: string; preview: string }>) ?? []))
      aggregated.featureFlags.push(...((sub.featureFlags as string[]) ?? []))
      aggregated.domSinks.push(...((sub.domSinks as string[]) ?? []))
      aggregated.domSinkDetails.push(...((sub.domSinkDetails as JsHarvestDomSinkDetail[]) ?? []))
      aggregated.secretMatches.push(...((sub.secretMatches as Array<{ kind: string; preview: string; index: number }>) ?? []))
    }

    return {
      meta: {
        parsed: true,
        version: mapObj.version ?? 3,
        sourcesTotal: sources.length,
        sourcesAnalyzed: analyzed,
        truncated,
        recoveredFiles: recoveredFiles.slice(0, maxMapSources),
      },
      aggregated,
    }
  } catch {
    return {
      meta: { parsed: false, truncated: false, reason: 'Invalid JSON source map', sourcesTotal: 0, sourcesAnalyzed: 0, recoveredFiles: [] },
      aggregated,
    }
  }
}

function mergeHarvestResults(
  target: Record<string, unknown>,
  extra: ReturnType<typeof analyzeSourceMapContent>['aggregated'],
): void {
  target.apiPaths = uniq([...((target.apiPaths as string[]) ?? []), ...extra.apiPaths], 250)
  target.adminPaths = uniq([...((target.adminPaths as string[]) ?? []), ...extra.adminPaths], 100)
  target.routes = [...((target.routes as unknown[]) ?? []), ...extra.routes].slice(0, 150)
  target.httpCalls = [...((target.httpCalls as unknown[]) ?? []), ...extra.httpCalls].slice(0, 150)
  target.graphqlDocs = [...((target.graphqlDocs as unknown[]) ?? []), ...extra.graphqlDocs].slice(0, 50)
  target.nextActions = [...((target.nextActions as unknown[]) ?? []), ...extra.nextActions].slice(0, 50)
  target.featureFlags = uniq([...((target.featureFlags as string[]) ?? []), ...extra.featureFlags], 80)
  target.domSinks = uniq([...((target.domSinks as string[]) ?? []), ...extra.domSinks], 40)
  target.domSinkDetails = [...((target.domSinkDetails as unknown[]) ?? []), ...extra.domSinkDetails].slice(0, 50)
  target.secretMatches = [...((target.secretMatches as unknown[]) ?? []), ...extra.secretMatches].slice(0, 60)
}

// ============================================================================
// Offline Symbol & Call-Graph / Interprocedural Data-Flow Indexer
// ============================================================================

export type CallGraphSinkKind =
  | 'api_route'
  | 'server_action'
  | 'webhook'
  | 'db_query'
  | 'outbound_fetch'
  | 'redirect'
  | 'postmessage_iframe'
  | 'upload_storage'
  | 'auth_config'
  | 'other'

export interface CallGraphFileInput {
  file: string
  content: string
}

export interface CallGraphBuildOptions {
  maxDepth?: number
  customGuardPatterns?: readonly string[]
  customSanitizerPatterns?: readonly string[]
  customSinkPatterns?: ReadonlyArray<{ pattern: string; sinkKind: CallGraphSinkKind }>
}

export interface CallGraphNodeOut {
  id: string
  file: string
  line: number
  endLine?: number
  symbol: string
  kind: 'entrypoint' | 'function' | 'middleware' | 'sink' | 'guard' | 'sanitizer'
  httpMethod?: string
  routePath?: string
  sinkKind?: CallGraphSinkKind
  guards: string[]
  sanitizers: string[]
  calls: string[]
}

export interface CallGraphEdgeOut {
  fromId: string
  toId: string
  file: string
  line: number
}

export interface CallGraphTaintPathOut {
  entrypointId: string
  entrypointSymbol: string
  entrypointFile: string
  entrypointLine: number
  routeOrAction: string
  httpMethod?: string
  sinkId: string
  sinkSymbol: string
  sinkFile: string
  sinkLine: number
  sinkKind: CallGraphSinkKind
  callChain: Array<{ file: string; line: number; symbol: string; role: 'entrypoint' | 'intermediate' | 'guard' | 'sanitizer' | 'sink' }>
  dominatingGuards: string[]
  partialGuards: string[]
  dominatingSanitizers: string[]
  isUnguardedPath: boolean
  authCheck: string
  ownershipCheck: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  maskedSnippet: string
}

export interface CallGraphBuildResult {
  filesScanned: number
  nodes: CallGraphNodeOut[]
  edges: CallGraphEdgeOut[]
  taintPaths: CallGraphTaintPathOut[]
}

const DEFAULT_GUARD_RE = /\b(?:require(?:Auth|Session|User|Admin|Role|Tenant|Org|OrgMembership|Permission|Ownership|Csrf)|verify(?:Token|Jwt|Session|Signature|Webhook)|check(?:Auth|Ownership|Permission|Tenant)|assert(?:Authorized|Tenant|Owner)|isAuthenticated|authenticate|authorize|withAuth|authMiddleware)\b/
const DEFAULT_OWNERSHIP_GUARD_RE = /\b(?:require(?:Tenant|Org|OrgMembership|Ownership)|checkOwnership|assert(?:Tenant|Owner)|orgId|tenantId|userId\s*===|ownerId\s*===)\b/
const DEFAULT_SANITIZER_RE = /\b(?:parseInt|Number|Boolean|DOMPurify\.sanitize|escapeHtml|sanitizeHtml|path\.basename|encodeURIComponent|zod|safeParse|parameterize)\b/

const BUILTIN_SINK_PATTERNS: Array<{ re: RegExp; sinkKind: CallGraphSinkKind; label: string }> = [
  { re: /\b(?:db|pool|client|knex|prisma|sql|sequelize|conn|cursor|stmt)\s*\.\s*(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|executeQuery|executeUpdate)\b/i, sinkKind: 'db_query', label: 'sql_query' },
  { re: /\b(?:exec|execSync|spawn|spawnSync|os\.system|subprocess\.(?:run|Popen|call|check_output))\b/, sinkKind: 'other', label: 'cmd_exec' },
  { re: /\b(?:fetch|axios\.(?:get|post|put|patch|delete)|requests\.(?:get|post)|http\.(?:Get|NewRequest)|got)\s*\(/, sinkKind: 'outbound_fetch', label: 'outbound_fetch' },
  { re: /\b(?:res\.redirect|NextResponse\.redirect|redirect)\s*\(/, sinkKind: 'redirect', label: 'http_redirect' },
  { re: /\b(?:fs\.readFile(?:Sync)?|fs\.writeFile(?:Sync)?|res\.sendFile|send_from_directory)\s*\(/, sinkKind: 'upload_storage', label: 'fs_path' },
  { re: /\b(?:render_template_string|ejs\.render|pug\.render|nunjucks\.renderString|innerHTML|dangerouslySetInnerHTML)\b/, sinkKind: 'postmessage_iframe', label: 'template_or_dom' },
]

function resolveRelativeImportPath(fromFile: string, spec: string, allFiles: Set<string>): string | null {
  if (!spec.startsWith('.')) return null
  const dirParts = fromFile.split('/').slice(0, -1)
  for (const seg of spec.split('/')) {
    if (!seg || seg === '.') continue
    if (seg === '..') dirParts.pop()
    else dirParts.push(seg)
  }
  const base = dirParts.join('/')
  const candidates = [
    base,
    `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.jsx`, `${base}.mjs`, `${base}.cjs`,
    `${base}/index.ts`, `${base}/index.tsx`, `${base}/index.js`,
  ]
  for (const c of candidates) {
    if (allFiles.has(c)) return c
  }
  return null
}

function detectSinksInText(
  text: string,
  customSinks?: ReadonlyArray<{ pattern: string; sinkKind: CallGraphSinkKind }>,
): Array<{ sinkKind: CallGraphSinkKind; label: string }> {
  const hits: Array<{ sinkKind: CallGraphSinkKind; label: string }> = []
  for (const b of BUILTIN_SINK_PATTERNS) {
    if (b.re.test(text)) hits.push({ sinkKind: b.sinkKind, label: b.label })
  }
  for (const cs of customSinks ?? []) {
    if (cs.pattern && text.includes(cs.pattern)) {
      hits.push({ sinkKind: cs.sinkKind, label: cs.pattern })
    }
  }
  return hits
}

function detectGuardsAndSanitizers(
  text: string,
  customGuards?: readonly string[],
  customSanitizers?: readonly string[],
): { guards: string[]; sanitizers: string[] } {
  const guards: string[] = []
  const sanitizers: string[] = []
  const gm = text.match(new RegExp(DEFAULT_GUARD_RE.source, 'g'))
  if (gm) guards.push(...gm)
  for (const cg of customGuards ?? []) {
    if (cg && text.includes(cg)) guards.push(cg)
  }
  const sm = text.match(new RegExp(DEFAULT_SANITIZER_RE.source, 'g'))
  if (sm) sanitizers.push(...sm)
  for (const cs of customSanitizers ?? []) {
    if (cs && text.includes(cs)) sanitizers.push(cs)
  }
  return { guards: uniq(guards, 20), sanitizers: uniq(sanitizers, 20) }
}

function extractBodyRange(node: AstNode, content: string): { startLine: number; endLine: number; text: string } {
  const loc = node.loc as { start?: { line?: number }; end?: { line?: number } } | undefined
  const span = node.span as SwcSpan | undefined
  const startLine = loc?.start?.line ?? lineNumberAtOffset(content, span?.start) ?? 1
  const endLine = loc?.end?.line ?? lineNumberAtOffset(content, span?.end) ?? startLine
  const lines = content.split('\n')
  const text = lines.slice(Math.max(0, startLine - 1), Math.min(lines.length, endLine)).join('\n')
  return { startLine, endLine, text }
}

export function buildCallGraphFromFiles(
  files: readonly CallGraphFileInput[],
  options: CallGraphBuildOptions = {},
): CallGraphBuildResult {
  const maxDepth = Math.max(2, Math.min(options.maxDepth ?? 6, 12))
  const allFilePaths = new Set(files.map(f => f.file))
  const nodes: CallGraphNodeOut[] = []
  const edges: CallGraphEdgeOut[] = []
  const fileImports = new Map<string, Map<string, string>>() // file -> localName -> targetFile
  const nodesByFileAndSymbol = new Map<string, CallGraphNodeOut>()
  const nodesBySymbol = new Map<string, CallGraphNodeOut[]>()
  const fileLineTexts = new Map<string, string[]>()

  const registerNode = (n: CallGraphNodeOut) => {
    nodes.push(n)
    nodesByFileAndSymbol.set(`${n.file}::${n.symbol}`, n)
    const list = nodesBySymbol.get(n.symbol) ?? []
    list.push(n)
    nodesBySymbol.set(n.symbol, list)
  }

  for (const f of files) {
    const lines = f.content.split('\n')
    fileLineTexts.set(f.file, lines)
    const importMap = new Map<string, string>()
    fileImports.set(f.file, importMap)

    const isJsTs = /\.(?:[cm]?[jt]sx?)$/i.test(f.file)
    if (isJsTs) {
      const { ast } = parseJsTsAst(f.content)
      if (ast) {
        // Collect imports
        walkAst(ast, node => {
          if (node.type === 'ImportDeclaration' && isAstNode(node.source)) {
            const spec = resolveStringValue(node.source)
            const resolved = spec ? resolveRelativeImportPath(f.file, spec, allFilePaths) : null
            if (resolved && Array.isArray(node.specifiers)) {
              for (const sp of node.specifiers) {
                if (!isAstNode(sp)) continue
                const local = getPropName(sp.local)
                if (local) importMap.set(local, resolved)
              }
            }
          }
        })

        // Extract functions & route entrypoints
        const seenRanges = new Set<string>()
        walkAst(ast, (node, ancestors) => {
          // Express/Fastify route calls: app.get('/api/...', handler)
          if (node.type === 'CallExpression') {
            const parts = getCalleeParts(node.callee)
            const last = parts[parts.length - 1] ?? ''
            if (parts.length === 2 && ['get', 'post', 'put', 'patch', 'delete', 'all', 'use'].includes(last)) {
              const args = getCallArgs(node)
              const routePath = resolveStringValue(args[0])
              if (routePath && routePath.startsWith('/')) {
                const { startLine, endLine, text } = extractBodyRange(node, f.content)
                const calls: string[] = []
                walkAst(args.slice(1), inner => {
                  if (inner.type === 'CallExpression') {
                    const cp = getCalleeParts(inner.callee)
                    if (cp.length) calls.push(cp[cp.length - 1])
                  } else if (inner.type === 'Identifier') {
                    const nm = getPropName(inner)
                    if (nm && !['req', 'res', 'next'].includes(nm)) calls.push(nm)
                  }
                })
                const gs = detectGuardsAndSanitizers(text, options.customGuardPatterns, options.customSanitizerPatterns)
                const sinks = detectSinksInText(text, options.customSinkPatterns)
                const sym = `${last.toUpperCase()} ${routePath}`
                const epNode: CallGraphNodeOut = {
                  id: `${f.file}:${startLine}:${sym}`,
                  file: f.file,
                  line: startLine,
                  endLine,
                  symbol: sym,
                  kind: 'entrypoint',
                  httpMethod: last.toUpperCase(),
                  routePath,
                  ...(sinks[0] ? { sinkKind: sinks[0].sinkKind } : {}),
                  guards: gs.guards,
                  sanitizers: gs.sanitizers,
                  calls: uniq(calls, 40),
                }
                registerNode(epNode)
                if (sinks.length > 0) {
                  registerNode({
                    id: `${f.file}:${startLine}:sink:${sinks[0].label}`,
                    file: f.file,
                    line: startLine,
                    endLine,
                    symbol: sinks[0].label,
                    kind: 'sink',
                    sinkKind: sinks[0].sinkKind,
                    guards: gs.guards,
                    sanitizers: gs.sanitizers,
                    calls: [],
                  })
                  edges.push({ fromId: epNode.id, toId: `${f.file}:${startLine}:sink:${sinks[0].label}`, file: f.file, line: startLine })
                }
              }
            }
          }

          // Named function declarations / exported arrow functions
          let fnName: string | null = null
          let fnNode: AstNode | null = null
          if (node.type === 'FunctionDeclaration') {
            fnName = getPropName(node.identifier ?? node.id)
            fnNode = node
          } else if (node.type === 'VariableDeclarator' && isAstNode(node.init) &&
            (node.init.type === 'ArrowFunctionExpression' || node.init.type === 'FunctionExpression')) {
            fnName = getPropName(node.id)
            fnNode = node.init
          }
          if (fnName && fnNode) {
            const { startLine, endLine, text } = extractBodyRange(fnNode, f.content)
            const rangeKey = `${f.file}:${startLine}:${fnName}`
            if (seenRanges.has(rangeKey)) return
            seenRanges.add(rangeKey)

            const isExported = ancestors.some(a => a.type === 'ExportDeclaration' || a.type === 'ExportNamedDeclaration' || a.type === 'ExportDefaultDeclaration')
            const isNextRouteMethod = isExported && /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(fnName)
            const isServerAction = isExported && f.content.includes('use server')
            const calls: string[] = []
            walkAst(fnNode.body ?? fnNode, inner => {
              if (inner.type === 'CallExpression') {
                const cp = getCalleeParts(inner.callee)
                if (cp.length) {
                  calls.push(cp[cp.length - 1])
                  if (cp.length >= 2) calls.push(cp.join('.'))
                }
              }
            })
            const gs = detectGuardsAndSanitizers(text, options.customGuardPatterns, options.customSanitizerPatterns)
            const sinks = detectSinksInText(text, options.customSinkPatterns)
            const kind: CallGraphNodeOut['kind'] = (isNextRouteMethod || isServerAction)
              ? 'entrypoint'
              : sinks.length > 0
                ? 'sink'
                : gs.guards.length > 0 && fnName.toLowerCase().includes('require')
                  ? 'guard'
                  : 'function'
            registerNode({
              id: rangeKey,
              file: f.file,
              line: startLine,
              endLine,
              symbol: fnName,
              kind,
              ...(isNextRouteMethod ? { httpMethod: fnName, routePath: `/${f.file.replace(/^src\/app\/|\/route\.[jt]sx?$/g, '')}` } : {}),
              ...(isServerAction ? { routePath: `action:${fnName}`, sinkKind: 'server_action' } : {}),
              ...(sinks[0] ? { sinkKind: sinks[0].sinkKind } : {}),
              guards: gs.guards,
              sanitizers: gs.sanitizers,
              calls: uniq(calls, 40),
            })
          }
        })
        continue
      }
    }

    // Structural fallback for Python / Go / Java / PHP / Ruby / malformed JS
    lines.forEach((lineText, idx) => {
      const lineNo = idx + 1
      const pyMatch = lineText.match(/^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/)
      const goMatch = lineText.match(/^\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(/)
      const routeMatch = lineText.match(/\.(?:get|post|put|patch|delete|route)\s*\(\s*["']([^"']+)["']/)
      const sym = pyMatch?.[1] ?? goMatch?.[1] ?? (routeMatch ? `ROUTE ${routeMatch[1]}` : null)
      if (sym) {
        const block = lines.slice(idx, Math.min(lines.length, idx + 25)).join('\n')
        const gs = detectGuardsAndSanitizers(block, options.customGuardPatterns, options.customSanitizerPatterns)
        const sinks = detectSinksInText(block, options.customSinkPatterns)
        const calls = [...block.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)].map(m => m[1]).filter(c => c !== sym)
        registerNode({
          id: `${f.file}:${lineNo}:${sym}`,
          file: f.file,
          line: lineNo,
          symbol: sym,
          kind: routeMatch ? 'entrypoint' : sinks.length > 0 ? 'sink' : 'function',
          ...(routeMatch ? { routePath: routeMatch[1] } : {}),
          ...(sinks[0] ? { sinkKind: sinks[0].sinkKind } : {}),
          guards: gs.guards,
          sanitizers: gs.sanitizers,
          calls: uniq(calls, 30),
        })
      }
    })
  }

  // Link callEdges across files
  const edgeKeys = new Set<string>()
  for (const caller of nodes) {
    const imps = fileImports.get(caller.file)
    for (const calleeSym of caller.calls) {
      if (calleeSym === caller.symbol) continue
      const targetFile = imps?.get(calleeSym)
      const candidates: CallGraphNodeOut[] = []
      if (targetFile) {
        const exact = nodesByFileAndSymbol.get(`${targetFile}::${calleeSym}`)
        if (exact) candidates.push(exact)
      }
      const sameFile = nodesByFileAndSymbol.get(`${caller.file}::${calleeSym}`)
      if (sameFile) candidates.push(sameFile)
      if (candidates.length === 0) {
        for (const globalHit of nodesBySymbol.get(calleeSym) ?? []) {
          candidates.push(globalHit)
        }
      }
      for (const callee of candidates.slice(0, 4)) {
        if (callee.id === caller.id) continue
        const key = `${caller.id}->${callee.id}`
        if (edgeKeys.has(key)) continue
        edgeKeys.add(key)
        edges.push({ fromId: caller.id, toId: callee.id, file: caller.file, line: caller.line })
      }
    }
  }

  // Build reverse adjacency map (callee -> callers) for sinkpoint-backward traversal
  const nodeById = new Map(nodes.map(n => [n.id, n]))
  const callersOf = new Map<string, CallGraphNodeOut[]>()
  for (const edge of edges) {
    const caller = nodeById.get(edge.fromId)
    if (!caller) continue
    const list = callersOf.get(edge.toId) ?? []
    list.push(caller)
    callersOf.set(edge.toId, list)
  }

  // Backward traversal from every sink node
  const rawPaths: Array<{ ep: CallGraphNodeOut; sink: CallGraphNodeOut; chain: CallGraphNodeOut[] }> = []
  const sinkNodes = nodes.filter(n => n.kind === 'sink' || n.sinkKind !== undefined)

  for (const sink of sinkNodes) {
    const dfs = (cur: CallGraphNodeOut, visited: Set<string>, chainRev: CallGraphNodeOut[]) => {
      if (rawPaths.length >= 250) return
      const callers = callersOf.get(cur.id) ?? []
      if (cur.kind === 'entrypoint' || (callers.length === 0 && chainRev.length > 1)) {
        const ep = cur
        rawPaths.push({ ep, sink, chain: [...chainRev].reverse() })
        if (cur.kind === 'entrypoint') return
      }
      if (chainRev.length >= maxDepth) return
      for (const caller of callers) {
        if (visited.has(caller.id)) continue
        visited.add(caller.id)
        chainRev.push(caller)
        dfs(caller, visited, chainRev)
        chainRev.pop()
        visited.delete(caller.id)
      }
    }
    const vis = new Set<string>([sink.id])
    dfs(sink, vis, [sink])
  }

  // Group by (ep.id, sink.id) to compute path dominance intersection
  const grouped = new Map<string, Array<{ ep: CallGraphNodeOut; sink: CallGraphNodeOut; chain: CallGraphNodeOut[] }>>()
  for (const p of rawPaths) {
    const key = `${p.ep.id}::${p.sink.id}`
    const arr = grouped.get(key) ?? []
    arr.push(p)
    grouped.set(key, arr)
  }

  const taintPaths: CallGraphTaintPathOut[] = []
  for (const group of grouped.values()) {
    const { ep, sink, chain } = group[0]
    const guardSets = group.map(g => new Set(g.chain.flatMap(n => n.guards)))
    const sanSets = group.map(g => new Set(g.chain.flatMap(n => n.sanitizers)))
    const allGuards = uniq(guardSets.flatMap(s => [...s]), 20)
    const dominatingGuards = allGuards.filter(g => guardSets.every(s => s.has(g)))
    const partialGuards = allGuards.filter(g => !dominatingGuards.includes(g))
    const allSans = uniq(sanSets.flatMap(s => [...s]), 20)
    const dominatingSanitizers = allSans.filter(sn => sanSets.every(s => s.has(sn)))

    const sinkKind = sink.sinkKind ?? 'other'
    const isAuthSensitive = ['api_route', 'server_action', 'webhook', 'auth_config', 'db_query'].includes(sinkKind)
    const isInjectionSink = ['db_query', 'outbound_fetch', 'redirect', 'postmessage_iframe', 'upload_storage', 'other'].includes(sinkKind)
    const hasDomGuard = dominatingGuards.length > 0
    const hasDomSanitizer = dominatingSanitizers.length > 0
    const isUnguardedPath = (isAuthSensitive && !hasDomGuard && !hasDomSanitizer) || (isInjectionSink && !hasDomSanitizer && !hasDomGuard)

    const hasOwnershipGuard = dominatingGuards.some(g => DEFAULT_OWNERSHIP_GUARD_RE.test(g))
    const authCheck = hasDomGuard ? `present (${dominatingGuards.join(', ')})` : partialGuards.length > 0 ? `partial (${partialGuards.join(', ')})` : 'missing'
    const ownershipCheck = hasOwnershipGuard ? `present (${dominatingGuards.filter(g => DEFAULT_OWNERSHIP_GUARD_RE.test(g)).join(', ')})` : 'missing'
    const severity: 'critical' | 'high' | 'medium' | 'low' = isUnguardedPath
      ? (sinkKind === 'db_query' || sinkKind === 'other' ? 'critical' : 'high')
      : partialGuards.length > 0
        ? 'medium'
        : 'low'

    const lines = fileLineTexts.get(sink.file) ?? []
    const snippet = maskSecretsInText(lines.slice(Math.max(0, sink.line - 1), sink.line + 2).join(' ').replace(/\s+/g, ' ').trim().slice(0, 240))

    taintPaths.push({
      entrypointId: ep.id,
      entrypointSymbol: ep.symbol,
      entrypointFile: ep.file,
      entrypointLine: ep.line,
      routeOrAction: ep.routePath ?? ep.symbol,
      ...(ep.httpMethod ? { httpMethod: ep.httpMethod } : {}),
      sinkId: sink.id,
      sinkSymbol: sink.symbol,
      sinkFile: sink.file,
      sinkLine: sink.line,
      sinkKind,
      callChain: chain.map((n, i) => ({
        file: n.file,
        line: n.line,
        symbol: n.symbol,
        role: i === 0 ? 'entrypoint' : i === chain.length - 1 ? 'sink' : n.guards.length > 0 ? 'guard' : n.sanitizers.length > 0 ? 'sanitizer' : 'intermediate',
      })),
      dominatingGuards,
      partialGuards,
      dominatingSanitizers,
      isUnguardedPath,
      authCheck,
      ownershipCheck,
      severity,
      maskedSnippet: snippet,
    })
  }

  return {
    filesScanned: files.length,
    nodes,
    edges,
    taintPaths,
  }
}

// ============================================================================
// Preserved v3 Analyzers (secret-scan, jwt-inspect, graphql-parse, etc.)
// ============================================================================

export function secretScan(content: string, sourceName = ''): { sourceName: string; matches: Array<{ kind: string; preview: string; index: number }> } {
  const rules: Array<{ kind: string; regex: RegExp }> = [
    { kind: 'aws-access-key', regex: /\bAKIA[0-9A-Z]{16}\b/g },
    { kind: 'stripe-live-key', regex: /\bsk_live_[0-9a-zA-Z]{16,}\b/g },
    { kind: 'stripe-pub-key', regex: /\bpk_(?:live|test)_[0-9a-zA-Z]{16,}\b/g },
    { kind: 'clerk-pub-key', regex: /\bpk_(?:live|test)_[A-Za-z0-9+/=]{20,}\b/g },
    { kind: 'supabase-url', regex: /https:\/\/[a-z0-9]{12,32}\.supabase\.co\b/g },
    { kind: 'jwt-literal', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g },
    { kind: 'private-key', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
    { kind: 'google-api-key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { kind: 'slack-webhook', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9/]+/g },
    { kind: 'generic-secret-var', regex: /\b(?:SERVICE_ROLE_KEY|SUPABASE_SERVICE_ROLE|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL|POSTGRES_URL|JWT_SECRET|NEXTAUTH_SECRET)\s*[:=]\s*["'`][^"'`]{6,120}["'`]/gi },
  ]
  const matches: Array<{ kind: string; preview: string; index: number }> = []
  for (const rule of rules) {
    for (const match of content.matchAll(rule.regex)) {
      if (matches.length >= 60) break
      const raw = match[0]
      const preview = raw.length > 16 && !rule.kind.endsWith('-url')
        ? raw.slice(0, 8) + '…[masked:' + raw.length + ']…' + raw.slice(-4)
        : raw.slice(0, 120)
      matches.push({ kind: rule.kind, preview, index: match.index ?? 0 })
    }
  }
  return { sourceName, matches }
}

export function jwtInspect(token: string): Record<string, unknown> {
  const parts = token.trim().split('.')
  if (parts.length < 2 || parts.length > 3) return { valid: false, error: 'Not a JWT structure.' }
  const decode = (part: string) => JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')) as Record<string, unknown>
  try {
    const header = decode(parts[0])
    const payload = decode(parts[1])
    const warnings: string[] = []
    if (String(header.alg ?? '').toLowerCase() === 'none') warnings.push('alg=none accepted/present')
    if (header.jku || header.x5u) warnings.push('External key URL header (jku/x5u) present')
    if (header.kid) warnings.push('kid header present (check for path traversal/SQLi in key lookup)')
    if (payload.exp === undefined) warnings.push('Missing exp claim')
    if (payload.aud === undefined) warnings.push('Missing aud claim')
    if (String(payload.role ?? '').includes('service_role') || payload.role === 'admin') {
      warnings.push(`Privileged role claim detected: ${String(payload.role)}`)
    }
    return {
      valid: true,
      header,
      claimKeys: Object.keys(payload),
      safeClaims: {
        iss: payload.iss, sub: payload.sub ? '[present]' : undefined, aud: payload.aud,
        role: payload.role, exp: payload.exp, iat: payload.iat,
      },
      hasSignature: Boolean(parts[2] && parts[2].length > 0),
      warnings,
    }
  } catch {
    return { valid: false, error: 'Could not base64url-decode JWT JSON segments.' }
  }
}

export function graphqlParse(content: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(content) as { data?: { __schema?: { queryType?: { name?: string }; mutationType?: { name?: string }; types?: Array<{ name: string; kind: string; fields?: Array<{ name: string }> }> } } }
    const schema = parsed.data?.__schema
    if (schema?.types) {
      const queries = schema.types.find(t => t.name === schema.queryType?.name)?.fields?.map(f => f.name) ?? []
      const mutations = schema.types.find(t => t.name === schema.mutationType?.name)?.fields?.map(f => f.name) ?? []
      const userTypes = schema.types.filter(t => !t.name.startsWith('__') && t.kind === 'OBJECT').map(t => ({
        name: t.name, fields: (t.fields ?? []).map(f => f.name).slice(0, 30),
      })).slice(0, 60)
      return { introspectionEnabled: true, queries: queries.slice(0, 100), mutations: mutations.slice(0, 100), userTypes }
    }
  } catch {
    // Fall back to regex extraction from JS bundles.
  }
  const operations = uniq([
    ...[...content.matchAll(/\b(?:query|mutation|subscription)\s+([A-Za-z0-9_]{2,64})\b/g)].map(m => `${m[0]}`),
  ], 100)
  return { introspectionEnabled: false, operations }
}

export function openapiParse(content: string): Record<string, unknown> {
  try {
    const doc = JSON.parse(content) as {
      openapi?: string; swagger?: string; info?: { title?: string; version?: string }
      paths?: Record<string, Record<string, { summary?: string; security?: unknown[]; parameters?: Array<{ name: string; in: string }> }>>
    }
    const endpoints: Array<{ method: string; path: string; summary?: string; unauthenticated?: boolean; params: string[] }> = []
    for (const [path, methods] of Object.entries(doc.paths ?? {})) {
      for (const [method, op] of Object.entries(methods ?? {})) {
        if (!['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(method.toLowerCase())) continue
        endpoints.push({
          method: method.toUpperCase(),
          path,
          summary: op?.summary?.slice(0, 100),
          unauthenticated: Array.isArray(op?.security) && op.security.length === 0,
          params: (op?.parameters ?? []).map(p => `${p.in}:${p.name}`).slice(0, 20),
        })
      }
    }
    return { specVersion: doc.openapi ?? doc.swagger ?? 'unknown', title: doc.info?.title, endpointCount: endpoints.length, endpoints: endpoints.slice(0, 200) }
  } catch {
    return { error: 'OpenAPI input must be valid JSON.' }
  }
}

export function diffResponse(control: { status?: number; body?: string; mediaType?: string },
  probe: { status?: number; body?: string; mediaType?: string }): Record<string, unknown> {
  const cBody = control.body ?? ''
  const pBody = probe.body ?? ''
  const tokenize = (s: string) => new Set(s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().split(/\s+/).filter(t => t.length > 2).slice(0, 1500))
  const a = tokenize(cBody)
  const b = tokenize(pBody)
  let intersect = 0
  for (const token of a) if (b.has(token)) intersect += 1
  const union = a.size + b.size - intersect
  const jaccard = union === 0 ? 1 : Number((intersect / union).toFixed(4))
  const likelySpaCatchall = control.status === 200 && probe.status === 200 &&
    (control.mediaType ?? '').includes('html') && (probe.mediaType ?? '').includes('html') && jaccard >= 0.85
  return {
    statusChanged: control.status !== probe.status,
    controlStatus: control.status,
    probeStatus: probe.status,
    mediaTypeChanged: control.mediaType !== probe.mediaType,
    lengthDelta: pBody.length - cBody.length,
    tokenSimilarity: jaccard,
    likelySpaCatchall,
  }
}

const takeoverSignatures: Array<{ provider: string; cname: RegExp; body: RegExp }> = [
  { provider: 'GitHub Pages', cname: /\.github\.io\.?$/i, body: /There isn't a GitHub Pages site here/i },
  { provider: 'Vercel', cname: /\.(?:vercel-dns\.com|now\.sh)\.?$/i, body: /DEPLOYMENT_NOT_FOUND|The deployment could not be found on Vercel/i },
  { provider: 'Netlify', cname: /\.netlify\.(?:app|com)\.?$/i, body: /Not Found - Request ID:/i },
  { provider: 'AWS S3', cname: /\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\.?$/i, body: /NoSuchBucket|The specified bucket does not exist/i },
  { provider: 'AWS CloudFront', cname: /\.cloudfront\.net\.?$/i, body: /Bad request|ERROR: The request could not be satisfied/i },
  { provider: 'Heroku', cname: /\.herokudns\.com\.?$|\.herokuapp\.com\.?$/i, body: /No such app|herokucdn\.com\/error-pages\/no-such-app/i },
  { provider: 'Fastly', cname: /\.fastly\.net\.?$/i, body: /Fastly error: unknown domain/i },
  { provider: 'Fly.io', cname: /\.fly\.dev\.?$/i, body: /404 Not Found|Could not find App/i },
  { provider: 'Cloudflare Pages', cname: /\.pages\.dev\.?$/i, body: /Project not found|Nothing here yet/i },
  { provider: 'Azure', cname: /\.(?:azurewebsites\.net|cloudapp\.net|blob\.core\.windows\.net)\.?$/i, body: /404 Web Site not found|InvalidUri/i },
  { provider: 'Shopify', cname: /\.myshopify\.com\.?$/i, body: /Sorry, this shop is currently unavailable/i },
  { provider: 'Ghost', cname: /\.ghost\.io\.?$/i, body: /The thing you were looking for is no longer here/i },
  { provider: 'Surge', cname: /\.surge\.sh\.?$/i, body: /project not found/i },
  { provider: 'Render', cname: /\.onrender\.com\.?$/i, body: /Not Found|This service has been suspended/i },
  { provider: 'Railway', cname: /\.up\.railway\.app\.?$/i, body: /Application not found/i },
  { provider: 'Webflow', cname: /\.webflow\.io\.?$|proxy-ssl\.webflow\.com\.?$/i, body: /The page you are looking for doesn't exist or has been moved/i },
]

export function dnsTakeoverAnalyze(input: {
  hostname?: string; cnames?: string[]; a?: string[]; aaaa?: string[]; status?: number; body?: string; nxdomain?: boolean
}): Record<string, unknown> {
  const cnames = input.cnames ?? []
  const body = input.body ?? ''
  const matchedProviders: Array<{ provider: string; cname: string; bodyMatched: boolean; nxdomain: boolean }> = []
  for (const cname of cnames) {
    for (const sig of takeoverSignatures) {
      if (sig.cname.test(cname)) {
        matchedProviders.push({
          provider: sig.provider,
          cname,
          bodyMatched: sig.body.test(body),
          nxdomain: Boolean(input.nxdomain),
        })
      }
    }
  }
  const danglingNoIp = cnames.length > 0 && (input.a?.length ?? 0) === 0 && (input.aaaa?.length ?? 0) === 0
  return {
    hostname: input.hostname,
    cnames,
    danglingNoIp,
    nxdomain: Boolean(input.nxdomain),
    matchedProviders,
    likelyTakeover: matchedProviders.some(m => m.bodyMatched || m.nxdomain),
  }
}

export function techFingerprint(input: {
  headers?: Record<string, string>
  body?: string
  url?: string
  packageJson?: string
}): Record<string, unknown> {
  const headers = Object.fromEntries(Object.entries(input.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]))
  const body = input.body ?? ''
  const detected: Array<{ ecosystem: string; package: string; version?: string; confidence: 'high' | 'medium' | 'low'; signal: string }> = []
  const add = (ecosystem: string, pkg: string, version: string | undefined, confidence: 'high' | 'medium' | 'low', signal: string) => {
    if (!detected.some(item => item.ecosystem === ecosystem && item.package === pkg && item.version === version)) {
      detected.push({ ecosystem, package: pkg, ...(version ? { version } : {}), confidence, signal })
    }
  }

  const powered = headers['x-powered-by'] ?? ''
  const server = headers['server'] ?? ''
  if (/next\.js/i.test(powered) || headers['x-nextjs-cache'] || headers['x-nextjs-prerender'] || body.includes('/_next/static/') || body.includes('__NEXT_DATA__')) {
    const ver = powered.match(/next\.js\s+([\d.]+)/i)?.[1] ?? body.match(/next(?:\/dist)?@?([\d]+\.[\d]+\.[\d]+)/i)?.[1]
    add('npm', 'next', ver, ver ? 'high' : 'medium', ver ? `Next.js version signal (${ver})` : 'Next.js runtime headers/chunks')
  }
  if (/express/i.test(powered)) add('npm', 'express', powered.match(/express\/?([\d.]+)/i)?.[1], 'medium', `X-Powered-By: ${powered}`)
  if (/nginx\/([\d.]+)/i.test(server)) add('Debian', 'nginx', server.match(/nginx\/([\d.]+)/i)?.[1], 'high', `Server: ${server}`)
  if (/apache\/([\d.]+)/i.test(server)) add('Debian', 'apache2', server.match(/apache\/([\d.]+)/i)?.[1], 'high', `Server: ${server}`)
  if (/cloudflare/i.test(server) || headers['cf-ray']) add('infra', 'cloudflare', undefined, 'high', 'Cloudflare edge headers')
  if (/vercel/i.test(server) || headers['x-vercel-id']) add('infra', 'vercel', undefined, 'high', 'Vercel edge headers')
  if (headers['x-clerk-auth-status'] || body.includes('clerk.accounts') || /pk_(?:live|test)_[A-Za-z0-9]{15,}/.test(body)) {
    add('npm', '@clerk/nextjs', undefined, 'medium', 'Clerk auth headers/SDK markers')
  }
  if (body.includes('.supabase.co') || headers['x-supabase-api-version']) {
    add('npm', '@supabase/supabase-js', undefined, 'medium', 'Supabase client/API markers')
  }
  if (body.includes('react-dom') || body.includes('__REACT_DEVTOOLS') || /react@([\d.]+)/i.test(body)) {
    add('npm', 'react', body.match(/react(?:-dom)?@([\d]+\.[\d]+\.[\d]+)/i)?.[1], 'medium', 'React runtime markers')
  }
  if (body.includes('/@vite/client') || body.includes('__vite_plugin')) {
    add('npm', 'vite', body.match(/vite@([\d]+\.[\d]+\.[\d]+)/i)?.[1], 'high', 'Vite dev/client markers')
  }
  if (body.includes('graphql') || body.includes('__typename')) {
    add('npm', 'graphql', undefined, 'low', 'GraphQL client/schema markers')
  }
  if (input.packageJson) {
    try {
      const pkg = JSON.parse(input.packageJson) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
      for (const [name, rawVer] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
        const clean = rawVer.replace(/^[^\d]*/, '')
        if (/^\d+\.\d+/.test(clean)) add('npm', name, clean, 'high', `package.json dependency ${name}@${rawVer}`)
      }
    } catch {
      // ignore invalid packageJson
    }
  }
  return { url: input.url, count: detected.length, technologies: detected.slice(0, 100) }
}

export function runAnalyzer(tool: AnalyzerName, args: Record<string, unknown>, readEvidence: (name: string) => string): Record<string, unknown> {
  const file = typeof args.file === 'string' ? args.file : undefined
  const content = file ? readEvidence(file) : typeof args.text === 'string' ? args.text : ''
  const sourceName = typeof args.sourceName === 'string' ? args.sourceName : (file ?? 'inline')
  switch (tool) {
    case 'js-harvest': {
      let sourceMapContent = typeof args.sourceMapContent === 'string' ? args.sourceMapContent : undefined
      if (!sourceMapContent && typeof args.sourceMapFile === 'string') {
        try { sourceMapContent = readEvidence(args.sourceMapFile) } catch { /* ignore */ }
      }
      if (!sourceMapContent) {
        const inlineMatch = content.match(/\/\/[#@]\s*sourceMappingURL=data:application\/json[^,]*;base64,([A-Za-z0-9+/=]+)/)
        if (inlineMatch) {
          try { sourceMapContent = Buffer.from(inlineMatch[1], 'base64').toString('utf8') } catch { /* ignore */ }
        }
      }
      return jsHarvest(content, sourceName, sourceMapContent ? { sourceMapContent } : undefined)
    }
    case 'secret-scan':
      return secretScan(content, sourceName)
    case 'jwt-inspect':
      return jwtInspect(content)
    case 'graphql-parse':
      return graphqlParse(content)
    case 'openapi-parse':
      return openapiParse(content)
    case 'tech-fingerprint': {
      const payload = file ? JSON.parse(content) as Parameters<typeof techFingerprint>[0] : args as Parameters<typeof techFingerprint>[0]
      return techFingerprint(payload)
    }
    case 'diff-response': {
      const control = typeof args.controlFile === 'string'
        ? JSON.parse(readEvidence(args.controlFile)) as { status?: number; body?: string; mediaType?: string }
        : (args.control as { status?: number; body?: string; mediaType?: string }) ?? {}
      const probe = typeof args.probeFile === 'string'
        ? JSON.parse(readEvidence(args.probeFile)) as { status?: number; body?: string; mediaType?: string }
        : (args.probe as { status?: number; body?: string; mediaType?: string }) ?? {}
      return diffResponse(control, probe)
    }
    case 'dns-takeover': {
      const payload = file ? JSON.parse(content) as Parameters<typeof dnsTakeoverAnalyze>[0] : args as Parameters<typeof dnsTakeoverAnalyze>[0]
      return dnsTakeoverAnalyze(payload)
    }
    case 'call-graph': {
      const files = Array.isArray(args.files) ? (args.files as CallGraphFileInput[]) : []
      return buildCallGraphFromFiles(files, args as CallGraphBuildOptions) as unknown as Record<string, unknown>
    }
  }
}
