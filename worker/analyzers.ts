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
    for (let i = 0; i < node.length; i += 1) walkAst(node[i], visit, ancestors)
    return
  }
  const rec = node as AstNode
  if (typeof rec.type === 'string') {
    visit(rec, ancestors)
    ancestors.push(rec)
    for (const k in rec) {
      if (k === 'span' || k === 'loc' || k === 'type') continue
      const v = rec[k]
      if (v && typeof v === 'object') walkAst(v, visit, ancestors)
    }
    ancestors.pop()
  } else {
    for (const k in rec) {
      const v = rec[k]
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

function buildLineOffsets(content: string): number[] {
  const offsets: number[] = []
  let idx = content.indexOf('\n')
  while (idx !== -1) {
    offsets.push(idx)
    idx = content.indexOf('\n', idx + 1)
  }
  return offsets
}

function lineNumberAtOffset(content: string, offset?: number, lineOffsets?: readonly number[]): number | undefined {
  if (typeof offset !== 'number' || offset < 0) return undefined
  const end = Math.min(offset, content.length)
  if (lineOffsets) {
    let lo = 0
    let hi = lineOffsets.length
    while (lo < hi) {
      const mid = (lo + hi) >>> 1
      if (lineOffsets[mid] < end) lo = mid + 1
      else hi = mid
    }
    return lo + 1
  }
  let line = 1
  for (let i = 0; i < end; i += 1) {
    if (content.charCodeAt(i) === 10) line += 1
  }
  return line
}

function nodeLine(node: AstNode, content: string, lineOffsets?: readonly number[]): number | undefined {
  const loc = node.loc as { start?: { line?: number } } | undefined
  if (typeof loc?.start?.line === 'number') return loc.start.line
  const span = node.span as SwcSpan | undefined
  if (typeof span?.start === 'number') return lineNumberAtOffset(content, span.start, lineOffsets)
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
    const lineOffsets = buildLineOffsets(content)
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
      let cachedLine: number | undefined
      let lineResolved = false
      const getLine = (): number | undefined => {
        if (!lineResolved) {
          cachedLine = nodeLine(node, content, lineOffsets)
          lineResolved = true
        }
        return cachedLine
      }

      // 1. Router config objects: { path: '...' }
      if (node.type === 'KeyValueProperty' || node.type === 'Property') {
        const key = getPropName(node.key)
        if (key === 'path' || key === 'route' || key === 'endpoint') {
          const val = resolveStringValue(node.value, stringConsts)
          if (val && val.startsWith('/') && val.length <= 200) {
            routes.push({ path: maskSecretsInText(val), kind: 'router', line: getLine() })
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
          domSinkDetails.push({ kind: 'dangerouslySetInnerHTML', line: getLine() })
        } else if (attrName === 'path' || attrName === 'to' || attrName === 'href') {
          const val = extractJsxStringAttr(node.value)
          if (val && val.startsWith('/') && val.length <= 200) {
            routes.push({ path: maskSecretsInText(val), kind: 'jsx', line: getLine() })
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
            routes.push({ path: maskSecretsInText(dest), kind: 'nav', line: getLine() })
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
            httpCalls.push({ client: 'fetch', url: maskSecretsInText(url), method, bodyKeys, line: getLine() })
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
              httpCalls.push({ client: 'axios', url: maskSecretsInText(url), method, bodyKeys, line: getLine() })
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
              httpCalls.push({ client: 'axios', url: maskSecretsInText(url), method, bodyKeys, line: getLine() })
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
            httpCalls.push({ client: 'trpc', url, method, bodyKeys, line: getLine() })
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
          domSinkDetails.push({ kind: 'message-listener', line: getLine(), missingOriginCheck: missingOrigin })
        }
        if (last === 'postMessage') {
          astDomSinks.push('postMessage')
          domSinkDetails.push({ kind: 'postMessage', line: getLine() })
        }
        if (joined === 'eval' || joined === 'document.write' || joined === 'document.writeln' || joined === 'window.open') {
          astDomSinks.push(joined)
          domSinkDetails.push({ kind: joined, line: getLine() })
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
          domSinkDetails.push({ kind: prop, line: getLine() })
        } else if (prop === 'onmessage') {
          astDomSinks.push('message-listener')
          const missingOrigin = node.right ? !subtreeHasOriginCheck(node.right) : false
          if (missingOrigin) astDomSinks.push('message-listener-missing-origin')
          domSinkDetails.push({ kind: 'message-listener', line: getLine(), missingOriginCheck: missingOrigin })
        } else if (leftParts.join('.') === 'document.domain') {
          astDomSinks.push('document.domain')
          domSinkDetails.push({ kind: 'document.domain', line: getLine() })
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
  const apiPaths = uniq([...astPaths, ...regexApiPaths], 200).map(maskSecretsInText)
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
  /** Missing authorization/tenant guard on an auth-sensitive route. */
  isAuthUnguarded: boolean
  /** Missing input sanitizer on an injection-capable sink. */
  isInjectionUnsanitized: boolean
  /** Either of the two independent findings above (backwards-compatible aggregate). */
  isUnguardedPath: boolean
  /** Data-layer sink lacks a tenant/org/user ownership predicate (cross-tenant exposure candidate). */
  missingTenantScope?: boolean
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
  { re: /\b(?:db|pool|client|knex|prisma|sql|sequelize|conn|cursor|stmt|repository|repo|manager)\s*\.\s*(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|\$queryRaw|\$executeRaw|executeQuery|executeUpdate|whereRaw|havingRaw|createQueryBuilder)\b/i, sinkKind: 'db_query', label: 'sql_query' },
  // SQLAlchemy `text(...)` / `from_statement(...)` and Drizzle `sql.raw(...)` templates.
  { re: /\b(?:sql\s*\.\s*raw|text|from_statement)\s*\(/, sinkKind: 'db_query', label: 'sql_text_raw' },
  { re: /\b(?:exec|execSync|spawn|spawnSync|os\.system|subprocess\.(?:run|Popen|call|check_output))\b/, sinkKind: 'other', label: 'cmd_exec' },
  { re: /\b(?:fetch|axios\.(?:get|post|put|patch|delete)|requests\.(?:get|post)|http\.(?:Get|NewRequest)|got)\s*\(/, sinkKind: 'outbound_fetch', label: 'outbound_fetch' },
  { re: /\b(?:res\.redirect|NextResponse\.redirect|redirect)\s*\(/, sinkKind: 'redirect', label: 'http_redirect' },
  { re: /\b(?:fs\.readFile(?:Sync)?|fs\.writeFile(?:Sync)?|res\.sendFile|send_from_directory|readFile|writeFile)\s*\(/, sinkKind: 'upload_storage', label: 'fs_path' },
  { re: /\b(?:render_template_string|ejs\.render|pug\.render|nunjucks\.renderString|innerHTML|dangerouslySetInnerHTML)\b/, sinkKind: 'postmessage_iframe', label: 'template_or_dom' },
]

/** Sink kinds where a missing tenant/org/user predicate indicates cross-tenant data exposure. */
const TENANT_SCOPE_RE = /\b(?:tenantId|tenant_id|orgId|org_id|organizationId|accountId|account_id|ownerId|owner_id|userId|user_id|workspaceId|workspace_id|membership)\b/i

function resolveRelativeImportPath(fromFile: string, spec: string, allFiles: Set<string>): string | null {
  if (!spec.startsWith('.')) return null
  const dirParts = fromFile.split('/').slice(0, -1)
  for (const seg of spec.split('/')) {
    if (!seg || seg === '.') continue
    if (seg === '..') dirParts.pop()
    else dirParts.push(seg)
  }
  const base = dirParts.join('/')
  // TypeScript ESM convention: source imports use `./x.js` but the file on disk is `x.ts`.
  const stem = base.replace(/\.(?:jsx?|mjs|cjs)$/i, '')
  const candidates = [
    base,
    `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.jsx`, `${base}.mjs`, `${base}.cjs`,
    `${stem}.ts`, `${stem}.tsx`, `${stem}.js`, `${stem}.jsx`, `${stem}.mjs`, `${stem}.cjs`,
    `${base}/index.ts`, `${base}/index.tsx`, `${base}/index.js`, `${base}/index.jsx`,
    `${stem}/index.ts`, `${stem}/index.tsx`, `${stem}/index.js`,
  ]
  for (const c of candidates) {
    if (allFiles.has(c)) return c
  }
  return null
}

interface TsPathConfig {
  baseUrl: string
  aliases: Array<{ prefix: string; suffix: string; targets: string[] }>
}

function parseTsconfigPaths(files: ReadonlyArray<CallGraphFileInput>): TsPathConfig {
  const config = files.find(f => /(?:^|\/)tsconfig(?:\.[a-z]+)?\.json$/i.test(f.file))
  if (!config) return { baseUrl: '', aliases: [] }
  let json: { compilerOptions?: { baseUrl?: string; paths?: Record<string, string[]> } } = {}
  try {
    const stripped = config.content.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
    json = JSON.parse(stripped) as typeof json
  } catch {
    return { baseUrl: '', aliases: [] }
  }
  const baseUrl = (json.compilerOptions?.baseUrl ?? '.').replace(/^\.\/?/, '').replace(/\/$/, '')
  const aliases = Object.entries(json.compilerOptions?.paths ?? {})
    .filter(([pattern]) => pattern.includes('*'))
    .map(([pattern, targets]) => {
      const [prefix, suffix] = pattern.split('*')
      return { prefix, suffix: suffix ?? '', targets: targets.map(t => t.replace('*', '')) }
    })
  return { baseUrl, aliases }
}

function resolveImportSpec(
  fromFile: string,
  spec: string,
  allFiles: Set<string>,
  tsPaths: TsPathConfig,
): string | null {
  if (spec.startsWith('.')) return resolveRelativeImportPath(fromFile, spec, allFiles)
  for (const alias of tsPaths.aliases) {
    if (!spec.startsWith(alias.prefix) || !spec.endsWith(alias.suffix)) continue
    const middle = spec.slice(alias.prefix.length, spec.length - alias.suffix.length)
    for (const target of alias.targets) {
      const raw = [tsPaths.baseUrl, `${target}${middle}`].filter(Boolean).join('/').replace(/\/+/g, '/')
      const base = raw.replace(/^\.?\//, '')
      const candidates = [
        base,
        `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.jsx`, `${base}.mjs`, `${base}.cjs`,
        `${base}/index.ts`, `${base}/index.tsx`, `${base}/index.js`, `${base}/index.jsx`,
      ]
      for (const candidate of candidates) {
        if (allFiles.has(candidate)) return candidate
      }
    }
  }
  return null
}

function joinRoutePath(prefix: string, routePath: string): string {
  const left = prefix.trim() === '/' ? '' : prefix.trim().replace(/\/+$/, '')
  const right = routePath.trim()
  if (!right || right === '/') return left || '/'
  const joined = `${left}/${right.replace(/^\/+/, '')}`
  return joined.startsWith('/') ? joined : `/${joined}`
}

const GUARD_NAME_RE = /(?:auth(?:oriz|entic)?|guard|middleware|session|permission|ownership|csrf|xsrf|jwt|oauth|rbac|acl|passport|protected|depends|isAdmin|isAuthed|^(?:require|verify|check|assert)[A-Z_]|(?:require|verify|check|assert)(?:Auth|User|Admin|Role|Tenant|Org|Permission|Owner|Session|Csrf|Jwt|Signature|Token|Login))/i

function isGuardLikeName(name: string): boolean {
  return GUARD_NAME_RE.test(name) || DEFAULT_GUARD_RE.test(name)
}

function collectRouteGuardNames(args: ReadonlyArray<unknown>): string[] {
  const guards: string[] = []
  const visit = (node: unknown, depth = 0): void => {
    if (depth > 6) return
    if (Array.isArray(node)) { for (const item of node) visit(item, depth + 1); return }
    if (!isAstNode(node)) return
    if (node.type === 'Identifier' || node.type === 'MemberExpression') {
      const parts = getCalleeParts(node)
      const last = parts[parts.length - 1] ?? ''
      if (last && isGuardLikeName(last) && !guards.includes(last)) guards.push(last)
      return
    }
    if (node.type === 'CallExpression') {
      const parts = getCalleeParts(node.callee)
      const name = parts[parts.length - 1] ?? ''
      if (name && (isGuardLikeName(name) || /^with[A-Z]/.test(name)) && !guards.includes(name)) guards.push(name)
      for (const arg of getCallArgs(node)) visit(arg, depth + 1)
      return
    }
    for (const [key, value] of Object.entries(node)) {
      if (key === 'loc' || key === 'span' || key === 'start' || key === 'end') continue
      visit(value, depth + 1)
    }
  }
  for (const arg of args) visit(arg)
  return guards.slice(0, 12)
}

function decoratorNodes(node: AstNode): AstNode[] {
  const direct = Array.isArray(node.decorators) ? node.decorators as unknown[] : []
  const fn = node.function && typeof node.function === 'object' ? node.function as Record<string, unknown> : null
  const fnDecorators = fn && Array.isArray(fn.decorators) ? fn.decorators as unknown[] : []
  return [...direct, ...fnDecorators].filter(isAstNode)
}

function decoratorInfo(node: AstNode): Array<{ name: string; args: unknown[]; argStrings: string[] }> {
  const out: Array<{ name: string; args: unknown[]; argStrings: string[] }> = []
  for (const dec of decoratorNodes(node)) {
    const expr = dec.expression ?? dec.callee ?? dec
    if (!isAstNode(expr)) continue
    if (expr.type === 'CallExpression') {
      const parts = getCalleeParts(expr.callee)
      const args = getCallArgs(expr)
      const argStrings = args.map(a => resolveStringValue(a)).filter((s): s is string => Boolean(s))
      out.push({ name: parts[parts.length - 1] ?? '', args, argStrings })
    } else {
      const parts = getCalleeParts(expr)
      out.push({ name: parts[parts.length - 1] ?? '', args: [], argStrings: [] })
    }
  }
  return out
}

const NEST_ROUTE_DECORATORS: Record<string, string> = {
  Get: 'GET', Post: 'POST', Put: 'PUT', Patch: 'PATCH', Delete: 'DELETE',
  Options: 'OPTIONS', Head: 'HEAD', All: 'ALL', RequestMapping: 'GET',
}

function nextRoutePathFromFile(file: string): { routePath: string; kind: 'app' | 'pages' } | null {
  const normalized = file.replaceAll('\\', '/')
  const appIdx = normalized.search(/(?:^|\/)app\//)
  if (appIdx >= 0 && /\/(?:route|page)\.[jt]sx?$/i.test(normalized)) {
    const rel = normalized.slice(appIdx).replace(/^\/?app\//, '')
    const withoutFile = rel.replace(/\/(?:route|page)\.[jt]sx?$/i, '')
    const cleaned = withoutFile
      .split('/')
      .filter(seg => seg && !/^\(.*\)$/.test(seg))
      .map(seg => seg.replace(/^\[\[?(?:\.\.\.)?([^\]]+)\]\]?$/, ':$1'))
      .join('/')
    return { routePath: cleaned ? `/${cleaned}` : '/', kind: 'app' }
  }
  const pagesIdx = normalized.search(/(?:^|\/)pages\//)
  if (pagesIdx >= 0) {
    const rel = normalized.slice(pagesIdx).replace(/^\/?pages\//, '').replace(/\.[jt]sx?$/i, '')
    if (!rel.startsWith('api/')) return null
    const routePath = '/' + rel.split('/').map(seg => seg.replace(/^\[\[?(?:\.\.\.)?([^\]]+)\]\]?$/, ':$1')).join('/')
    return { routePath, kind: 'pages' }
  }
  return null
}

interface ExtractedRoute {
  file: string
  line: number
  endLine?: number
  text: string
  method?: string
  routePath: string
  symbol: string
  kind: 'entrypoint' | 'function' | 'sink' | 'middleware'
  guards: string[]
  sinks: Array<{ label: string; sinkKind: CallGraphSinkKind }>
  calls: string[]
  paramNames?: string[]
  owner?: string
}


/**
 * Blank out comments and string/template literals while preserving offsets and
 * newlines, so guard/sanitizer matches only come from executable code.
 */
function maskCommentsAndStrings(text: string): string {
  const out = text.split('')
  let mode: 'code' | 'line' | 'block' | 'single' | 'double' | 'template' = 'code'
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    const next = text[i + 1]
    if (mode === 'code') {
      if (ch === '/' && next === '/') {
        out[i] = ' '
        out[i + 1] = ' '
        mode = 'line'
        i += 1
        continue
      }
      if (ch === '/' && next === '*') {
        out[i] = ' '
        out[i + 1] = ' '
        mode = 'block'
        i += 1
        continue
      }
      if (ch === "'") { out[i] = ' '; mode = 'single'; continue }
      if (ch === '"') { out[i] = ' '; mode = 'double'; continue }
      if (ch === '`') { out[i] = ' '; mode = 'template'; continue }
      continue
    }
    if (mode === 'line') {
      if (ch === '\n') { mode = 'code'; continue }
      out[i] = ' '
      continue
    }
    if (mode === 'block') {
      if (ch === '*' && next === '/') {
        out[i] = ' '
        out[i + 1] = ' '
        mode = 'code'
        i += 1
        continue
      }
      if (ch !== '\n') out[i] = ' '
      continue
    }
    // String / template literal body.
    if (ch === '\\') {
      out[i] = ' '
      if (i + 1 < text.length) {
        if (text[i + 1] !== '\n') out[i + 1] = ' '
        i += 1
      }
      continue
    }
    const closer = mode === 'single' ? "'" : mode === 'double' ? '"' : '`'
    if (ch === closer) {
      out[i] = ' '
      mode = 'code'
      continue
    }
    if (ch !== '\n') out[i] = ' '
  }
  return out.join('')
}

interface PatternOccurrence {
  name: string
  offset: number
}

function findOccurrences(
  text: string,
  source: string,
  customPatterns?: readonly string[],
): PatternOccurrence[] {
  const masked = maskCommentsAndStrings(text)
  const found: PatternOccurrence[] = []
  for (const match of masked.matchAll(new RegExp(source, 'g'))) {
    if (typeof match.index === 'number' && match[0]) {
      found.push({ name: match[0], offset: match.index })
    }
  }
  for (const pattern of customPatterns ?? []) {
    if (!pattern) continue
    let index = masked.indexOf(pattern)
    while (index >= 0) {
      found.push({ name: pattern, offset: index })
      index = masked.indexOf(pattern, index + pattern.length)
    }
  }
  return found
}

function findSinkOccurrences(
  text: string,
  customSinks?: ReadonlyArray<{ pattern: string; sinkKind: CallGraphSinkKind }>,
): Array<{ sinkKind: CallGraphSinkKind; label: string; offset: number }> {
  const masked = maskCommentsAndStrings(text)
  const hits: Array<{ sinkKind: CallGraphSinkKind; label: string; offset: number }> = []
  for (const builtin of BUILTIN_SINK_PATTERNS) {
    const re = new RegExp(builtin.re.source, builtin.re.flags.includes('g') ? builtin.re.flags : `${builtin.re.flags}g`)
    for (const match of masked.matchAll(re)) {
      if (typeof match.index === 'number') {
        hits.push({ sinkKind: builtin.sinkKind, label: builtin.label, offset: match.index })
      }
    }
  }
  for (const custom of customSinks ?? []) {
    if (!custom.pattern) continue
    let index = masked.indexOf(custom.pattern)
    while (index >= 0) {
      hits.push({ sinkKind: custom.sinkKind, label: custom.pattern, offset: index })
      index = masked.indexOf(custom.pattern, index + custom.pattern.length)
    }
  }
  return hits.sort((a, b) => a.offset - b.offset)
}

function detectSinksInText(
  text: string,
  customSinks?: ReadonlyArray<{ pattern: string; sinkKind: CallGraphSinkKind }>,
): Array<{ sinkKind: CallGraphSinkKind; label: string }> {
  const hits = findSinkOccurrences(text, customSinks)
  const seen = new Set<string>()
  const out: Array<{ sinkKind: CallGraphSinkKind; label: string }> = []
  for (const hit of hits) {
    const key = `${hit.sinkKind}:${hit.label}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ sinkKind: hit.sinkKind, label: hit.label })
  }
  return out
}

function detectGuardsAndSanitizers(
  text: string,
  customGuards?: readonly string[],
  customSanitizers?: readonly string[],
): { guards: string[]; sanitizers: string[] } {
  const guards = uniq(findOccurrences(text, DEFAULT_GUARD_RE.source, customGuards).map(o => o.name), 20)
  const sanitizers = uniq(findOccurrences(text, DEFAULT_SANITIZER_RE.source, customSanitizers).map(o => o.name), 20)
  return { guards, sanitizers }
}

function extractBodyRange(
  node: AstNode,
  content: string,
  lineOffsets?: readonly number[],
  preSplitLines?: readonly string[],
): { startLine: number; endLine: number; text: string } {
  const loc = node.loc as { start?: { line?: number }; end?: { line?: number } } | undefined
  const span = node.span as SwcSpan | undefined
  const startLine = loc?.start?.line ?? lineNumberAtOffset(content, span?.start, lineOffsets) ?? 1
  const endLine = loc?.end?.line ?? lineNumberAtOffset(content, span?.end, lineOffsets) ?? startLine
  const lines = preSplitLines ?? content.split('\n')
  const text = lines.slice(Math.max(0, startLine - 1), Math.min(lines.length, endLine)).join('\n')
  return { startLine, endLine, text }
}

function extractJsFallbackRoutes(
  file: string,
  content: string,
  options: CallGraphBuildOptions,
): ExtractedRoute[] {
  const routes: ExtractedRoute[] = []
  const lines = content.split('\n')
  const localPrefix = new Map<string, { prefix: string; guards: string[] }>()
  const globals: string[] = []
  const blockFrom = (index: number, limit = 26): { endLine: number; text: string } => {
    const text = lines.slice(index, Math.min(lines.length, index + limit)).join('\n')
    return { endLine: Math.min(lines.length, index + limit), text }
  }
  const push = (r: ExtractedRoute) => routes.push(r)

  // Mounts must be known before routes are emitted.
  for (const [index, line] of lines.entries()) {
    const use = line.match(/\b([A-Za-z_$][A-Za-z0-9_$]*)\.use\s*\(\s*(["'])([^"']+)\2\s*,?\s*([^)]*)/)
    if (use) {
      const guards = collectTextGuardNames(use[4])
      const routerVar = use[4].match(/([A-Za-z_$][A-Za-z0-9_$]*)\s*$/)?.[1]
      if (routerVar) localPrefix.set(routerVar, { prefix: use[3], guards })
      continue
    }
    const pathless = line.match(/\b[A-Za-z_$][A-Za-z0-9_$]*\.use\s*\(\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*(?:,\s*([A-Za-z_$][A-Za-z0-9_$.]*))?\s*\)/)
    if (pathless) globals.push(...collectTextGuardNames(pathless[1]))
    void index
  }

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]
    const call = line.match(/\b([A-Za-z_$][A-Za-z0-9_$]*)\.(get|post|put|patch|delete|all)\s*\(\s*(["'])([^"']+)\3\s*,?\s*(.*)$/)
    if (call) {
      const owner = call[1]
      const method = call[2].toUpperCase()
      const mount = localPrefix.get(owner)
      const routePath = mount ? joinRoutePath(mount.prefix, call[4]) : call[4]
      const block = blockFrom(i)
      const guards = uniq([...(mount?.guards ?? []), ...globals, ...collectTextGuardNames(call[5])], 20)
      push({
        file, line: i + 1, endLine: block.endLine, text: block.text,
        method, routePath, symbol: `${method} ${routePath}`, kind: 'entrypoint',
        guards,
        sinks: detectSinksInText(block.text, options.customSinkPatterns),
        calls: textCalls(block.text),
        owner,
      })
      continue
    }

    // NestJS-style decorated controllers.
    const controller = line.match(/@Controller\s*\(\s*["']?([^"')]*)["']?\s*\)/)
    if (controller) {
      const prefix = controller[1] ?? ''
      for (let j = i + 1; j < Math.min(lines.length, i + 80); j += 1) {
        const deco = lines[j].match(/@(Get|Post|Put|Patch|Delete|Options|Head|All|RequestMapping)\s*\(\s*["']?([^"')]*)["']?\s*\)/)
        if (!deco) continue
        const method = NEST_ROUTE_DECORATORS[deco[1]] ?? 'GET'
        const routePath = joinRoutePath(prefix, deco[2] ?? '')
        const guardText = lines.slice(Math.max(0, i - 2), Math.min(lines.length, j + 6)).join('\n')
        const block = blockFrom(j, 22)
        push({
          file, line: j + 1, endLine: block.endLine, text: `${guardText}\n${block.text}`,
          method, routePath, symbol: `${method} ${routePath}`, kind: 'entrypoint',
          guards: collectTextGuardNames(guardText),
          sinks: detectSinksInText(block.text, options.customSinkPatterns),
          calls: textCalls(block.text),
        })
      }
    }

    const fn = line.match(/^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)/)
      ?? line.match(/^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(?[^=]*?\)?\s*=>/)
    if (fn) {
      const block = blockFrom(i, 30)
      const gs = detectGuardsAndSanitizers(block.text, options.customGuardPatterns, options.customSanitizerPatterns)
      const sinks = detectSinksInText(block.text, options.customSinkPatterns)
      push({
        file, line: i + 1, endLine: block.endLine, text: block.text,
        routePath: fn[1], symbol: fn[1],
        kind: sinks.length > 0 ? 'sink' : 'function',
        guards: gs.guards,
        sinks,
        calls: textCalls(block.text),
      })
    }
  }
  return routes
}

function textCalls(text: string): string[] {
  const calls: string[] = []
  for (const match of text.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)) calls.push(match[1])
  return uniq(calls, 40)
}

function pythonIndent(line: string): number {
  return line.length - line.trimStart().length
}

function pythonBlock(lines: string[], defIndex: number, maxLines = 60): string {
  const defIndent = pythonIndent(lines[defIndex] ?? '')
  const out: string[] = []
  for (let i = defIndex; i < Math.min(lines.length, defIndex + maxLines); i += 1) {
    const line = lines[i]
    if (i > defIndex && line.trim() !== '' && pythonIndent(line) <= defIndent && !/^\s*[)\]}]/.test(line)) break
    out.push(line)
  }
  return out.join('\n')
}

function quotedStrings(text: string): string[] {
  return [...text.matchAll(/["']([^"']{1,256})["']/g)].map(m => m[1])
}

/**
 * Structural, language-aware route extraction for non-JS/TS stacks. This replaces
 * the v4 25-line regex fallback which only recognised literal `.get('/x')` calls.
 */
function extractNonJsRoutes(
  file: string,
  content: string,
  options: CallGraphBuildOptions,
): ExtractedRoute[] {
  const routes: ExtractedRoute[] = []
  const lines = content.split('\n')
  const ext = file.split('.').pop()?.toLowerCase() ?? ''
  const base = file.split('/').pop() ?? ''
  const push = (input: {
    line: number
    method?: string
    routePath: string
    symbol: string
    text: string
    guards?: string[]
    sinkText?: string
  }) => {
    const text = input.text
    const gs = detectGuardsAndSanitizers(text, options.customGuardPatterns, options.customSanitizerPatterns)
    const calls: string[] = []
    for (const match of text.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)) calls.push(match[1])
    routes.push({
      file,
      line: input.line,
      text,
      ...(input.method ? { method: input.method } : {}),
      routePath: input.routePath,
      symbol: input.symbol,
      kind: 'entrypoint',
      guards: uniq([...(input.guards ?? []), ...gs.guards], 20),
      sinks: detectSinksInText(input.sinkText ?? text, options.customSinkPatterns),
      calls: uniq(calls, 40),
    })
  }

  if (['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs'].includes(ext)) {
    return extractJsFallbackRoutes(file, content, options)
  }

  if (ext === 'py') {
    const prefixes = new Map<string, string>()
    for (const line of lines) {
      const m = line.match(/([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:APIRouter|Blueprint)\s*\(([\s\S]*)/)
      if (m) {
        const prefix = m[2].match(/(?:prefix|url_prefix)\s*=\s*["']([^"']+)["']/)?.[1]
        if (prefix) prefixes.set(m[1], prefix.startsWith('/') ? prefix : `/${prefix}`)
      }
    }
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i]
      const deco = line.match(/^\s*@([A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|patch|delete|route|api_route)\s*\((.*)$/)
      if (deco) {
        let argText = deco[3]
        let lookahead = 1
        while (!argText.includes(')') && i + lookahead < lines.length && lookahead < 4) {
          argText += ' ' + lines[i + lookahead]
          lookahead += 1
        }
        const path = quotedStrings(argText)[0]
        if (!path) continue
        let defIndex = -1
        for (let j = i + 1; j < Math.min(lines.length, i + 8); j += 1) {
          if (/^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.test(lines[j])) { defIndex = j; break }
        }
        if (defIndex < 0) continue
        const fnName = lines[defIndex].match(/def\s+([A-Za-z_][A-Za-z0-9_]*)/)?.[1] ?? `handler_${i}`
        const block = pythonBlock(lines, defIndex)
        const prefix = prefixes.get(deco[1]) ?? ''
        const methods = deco[2].toLowerCase() === 'route'
          ? (argText.match(/methods\s*=\s*\[([^\]]+)\]/)?.[1].match(/["']([A-Za-z]+)["']/g) ?? ['GET'])
            .map(s => s.replace(/["']/g, '').toUpperCase())
          : [deco[2].toUpperCase()]
        const guardNames = [
          ...(argText.match(/Depends\(\s*([A-Za-z_][A-Za-z0-9_.]*)/g) ?? []).map(s => s.replace(/Depends\(\s*/, '')),
          ...(block.match(/Depends\(\s*([A-Za-z_][A-Za-z0-9_.]*)/g) ?? []).map(s => s.replace(/Depends\(\s*/, '')),
          ...(/login_required|permission_required|requires_auth|authenticated/i.test(argText + block) ? ['auth-decorator'] : []),
        ]
        const fullPath = joinRoutePath(prefix, path)
        for (const method of methods) {
          push({
            line: defIndex + 1,
            method,
            routePath: fullPath,
            symbol: `${method} ${fullPath}`,
            text: `${lines[i]}\n${block}`,
            guards: guardNames,
          })
        }
        continue
      }
      if (base === 'urls.py' || /urlpatterns/.test(line)) {
        const dj = line.match(/(?:path|re_path)\s*\(\s*r?["']([^"']+)["']\s*,\s*([A-Za-z_][A-Za-z0-9_.]*)/)
        if (dj) {
          const routePath = dj[1].startsWith('/') ? dj[1] : `/${dj[1]}`
          push({ line: i + 1, routePath, symbol: `ANY ${routePath}`, text: lines.slice(i, i + 8).join('\n'), guards: [] })
        }
      }
      const drf = line.match(/router\.register\s*\(\s*r?["']([^"']+)["']\s*,\s*([A-Za-z_][A-Za-z0-9_]*)/)
      if (drf) {
        const collection = `/${drf[1].replace(/^\/+/, '')}`
        push({ line: i + 1, method: 'GET', routePath: collection, symbol: `GET ${collection}`, text: line, guards: [] })
        push({ line: i + 1, method: 'POST', routePath: collection, symbol: `POST ${collection}`, text: line, guards: [] })
        push({ line: i + 1, method: 'GET', routePath: `${collection}/:id`, symbol: `GET ${collection}/:id`, text: line, guards: [] })
        push({ line: i + 1, method: 'PATCH', routePath: `${collection}/:id`, symbol: `PATCH ${collection}/:id`, text: line, guards: [] })
      }
      const djRest = line.match(/(?:path|re_path)\s*\(\s*r?["']([^"']+)["'][\s\S]*?\.as_view\s*\(\s*\{([^}]*)\}/)
      if (djRest) {
        const routePath = djRest[1].startsWith('/') ? djRest[1] : `/${djRest[1]}`
        for (const m of djRest[2].matchAll(/["'](get|post|put|patch|delete)["']/g)) {
          push({ line: i + 1, method: m[1].toUpperCase(), routePath, symbol: `${m[1].toUpperCase()} ${routePath}`, text: lines.slice(i, i + 6).join('\n') })
        }
      }
    }
    return routes
  }

  if (ext === 'java' || ext === 'kt') {
    const classPrefix = content.match(/@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/)?.[1] ?? ''
    const classGuards = [
      ...(content.match(/@PreAuthorize\s*\(([^)]*)\)/g) ?? []).map(s => s),
      ...(content.match(/@(?:Secured|RolesAllowed)\s*\(([^)]*)\)/g) ?? []).map(s => s.replace(/@(?:Secured|RolesAllowed)\s*\(/, '')),
    ]
    const mappingMethods: Record<string, string> = {
      GetMapping: 'GET', PostMapping: 'POST', PutMapping: 'PUT', PatchMapping: 'PATCH',
      DeleteMapping: 'DELETE', RequestMapping: 'ANY',
    }
    for (let i = 0; i < lines.length; i += 1) {
      const deco = lines[i].match(/@(Get|Post|Put|Patch|Delete|Request)Mapping\s*(?:\(([^)]*)\))?/)
      if (!deco) continue
      const argText = deco[2] ?? ''
      const path = quotedStrings(argText)[0] ?? ''
      let methodIndex = -1
      for (let j = i + 1; j < Math.min(lines.length, i + 8); j += 1) {
        if (/\b(?:public|private|protected)\b[\w<>\[\], .?]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.test(lines[j])) { methodIndex = j; break }
      }
      if (methodIndex < 0) continue
      const methodName = lines[methodIndex].match(/\s([A-Za-z_][A-Za-z0-9_]*)\s*\(/)?.[1] ?? `handler_${i}`
      const text = lines.slice(Math.max(0, i - 3), Math.min(lines.length, methodIndex + 30)).join('\n')
      const methodGuards = [
        ...(lines.slice(Math.max(0, i - 3), i).join('\n').match(/@(?:PreAuthorize|Secured|RolesAllowed)\s*\(([^)]*)\)/g) ?? []),
        ...classGuards,
      ]
      const methods = deco[1] === 'Request' ? ['ANY'] : [mappingMethods[`${deco[1]}Mapping`]]
      for (const method of methods) {
        const fullPath = joinRoutePath(classPrefix, path)
        push({ line: methodIndex + 1, method, routePath: fullPath, symbol: `${method} ${fullPath}`, text, guards: methodGuards })
      }
    }
    return routes
  }

  if (ext === 'go') {
    const groups = new Map<string, { prefix: string; guards: string[] }>()
    for (const line of lines) {
      const g = line.match(/([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*([A-Za-z_][A-Za-z0-9_]*)\.(?:Group|Route)\s*\(\s*["']([^"']+)["']\s*,?\s*([^)]*)/)
      if (g) groups.set(g[1], { prefix: g[3], guards: collectTextGuardNames(g[4]) })
    }
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i]
      const httpRoute = line.match(/http\.(?:HandleFunc|Handle)\s*\(\s*["']([^"']+)["']\s*,\s*([A-Za-z_][A-Za-z0-9_.]*)/)
      if (httpRoute) {
        const routePath = httpRoute[1]
        push({ line: i + 1, routePath, symbol: `ANY ${routePath}`, text: lines.slice(i, Math.min(lines.length, i + 12)).join('\n'), guards: [] })
        continue
      }
      const call = line.match(/\b([A-Za-z_][A-Za-z0-9_]*)\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Get|Post|Put|Patch|Delete|HandleFunc|Handle)\s*\(\s*["']([^"']+)["']\s*,?\s*([^)]*)/)
      if (!call) continue
      const group = groups.get(call[1])
      const prefix = group?.prefix ?? ''
      const routePath = joinRoutePath(prefix, call[3])
      const methodRaw = call[2].toUpperCase()
      const method = methodRaw === 'HANDLEFUNC' || methodRaw === 'HANDLE' ? undefined : methodRaw
      impactGuardScan: {
        // Inline middleware arguments (gin/chi/echo) inherit as guards when they look auth-related.
      }
      const guards = uniq([...(group?.guards ?? []), ...collectTextGuardNames(call[4])], 12)
      push({
        line: i + 1,
        ...(method ? { method } : {}),
        routePath,
        symbol: `${method ?? 'ANY'} ${routePath}`,
        text: lines.slice(i, Math.min(lines.length, i + 14)).join('\n'),
        guards,
      })
    }
    return routes
  }

  if (ext === 'rb' || base === 'routes.rb') {
    // routes.rb -> controller#action lookup table
    const routeTable = new Map<string, { path: string; method: string }>()
    for (const line of lines) {
      const r = line.match(/^\s*(get|post|put|patch|delete)\s+["']([^"']+)["'](?:[\s\S]*?to:\s*["']([A-Za-z0-9_]+)#([A-Za-z0-9_]+)["'])?/)
      if (r) {
        const path = r[2].startsWith('/') ? r[2] : `/${r[2]}`
        if (r[3] && r[4]) routeTable.set(`${r[3]}#${r[4]}`, { path, method: r[1].toUpperCase() })
        routes.push({
          file, line: 1, text: line, method: r[1].toUpperCase(), routePath: path,
          symbol: `${r[1].toUpperCase()} ${path}`, kind: 'entrypoint', guards: [],
          sinks: detectSinksInText(line, options.customSinkPatterns), calls: textCalls(line),
        })
      }
      const res = line.match(/^\s*resources?\s+:([A-Za-z0-9_]+)/)
      if (res) {
        const collection = `/${res[1]}`
        for (const [method, p] of [['GET', collection], ['POST', collection], ['GET', `${collection}/:id`], ['PATCH', `${collection}/:id`], ['DELETE', `${collection}/:id`]] as Array<[string, string]>) {
          routes.push({
            file, line: 1, text: line, method, routePath: p, symbol: `${method} ${p}`,
            kind: 'entrypoint', guards: [], sinks: [], calls: [],
          })
        }
      }
    }
    const controllerName = base.replace(/_controller\.rb$/i, '')
    if (controllerName !== base) {
      const beforeActions = [...content.matchAll(/before_action\s+:([A-Za-z0-9_!?]+)/g)].map(m => m[1])
      for (let i = 0; i < lines.length; i += 1) {
        const def = lines[i].match(/^\s*def\s+([A-Za-z0-9_!?]+)/)
        if (!def) continue
        const action = def[1]
        const mapped = routeTable.get(`${controllerName}#${action}`)
        const routePath = mapped?.path ?? `/${controllerName}/${action}`
        const method = mapped?.method ?? 'ANY'
        const text = lines.slice(i, Math.min(lines.length, i + 25)).join('\n')
        routes.push({
          file, line: i + 1, text, ...(method !== 'ANY' ? { method } : {}), routePath,
          symbol: `${method} ${routePath}`, kind: 'entrypoint',
          guards: uniq([...beforeActions, ...detectGuardsAndSanitizers(text, options.customGuardPatterns, options.customSanitizerPatterns).guards], 12),
          sinks: detectSinksInText(text, options.customSinkPatterns),
          calls: uniq([...text.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)].map(m => m[1]), 40),
        })
      }
      return routes
    }
    return routes
  }

  if (ext === 'php') {
    for (let i = 0; i < lines.length; i += 1) {
      const r = lines[i].match(/Route::(get|post|put|patch|delete|any)\s*\(\s*["']([^"']+)["']\s*,\s*([^)]*)/)
      if (!r) continue
      const routePath = r[2].startsWith('/') ? r[2] : `/${r[2]}`
      push({ line: i + 1, method: r[1].toUpperCase(), routePath, symbol: `${r[1].toUpperCase()} ${routePath}`, text: lines.slice(i, i + 15).join('\n'), guards: collectTextGuardNames(r[3]) })
    }
    return routes
  }

  return routes
}

function collectTextGuardNames(text: string): string[] {
  const out: string[] = []
  for (const match of text.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\b/g)) {
    if (isGuardLikeName(match[1]) && !out.includes(match[1])) out.push(match[1])
  }
  return out.slice(0, 8)
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

  const tsPaths = parseTsconfigPaths(files)
  const fileMounts = new Map<string, Array<{ prefix: string; guards: string[] }>>()
  const localMounts = new Map<string, { prefix: string; guards: string[] }>()
  const fileGlobals = new Map<string, string[]>()
  const pendingRoutes: Array<ExtractedRoute & { owner?: string }> = []
  const registeredRouteKeys = new Set<string>()
  const contentByFile = new Map(files.map(f => [f.file, f.content]))

  const sanitizersFor = (text: string): string[] =>
    detectGuardsAndSanitizers(text, options.customGuardPatterns, options.customSanitizerPatterns).sanitizers

  const registerExtractedRoute = (r: ExtractedRoute & { owner?: string }) => {
    const dedupeKey = `${r.file}:${r.line}:${r.method ?? 'ANY'}:${r.routePath}:${r.symbol}`
    if (registeredRouteKeys.has(dedupeKey)) return
    registeredRouteKeys.add(dedupeKey)
    let routePath = r.routePath || r.symbol
    let guards = [...r.guards]
    if (r.owner) {
      const local = localMounts.get(`${r.file}::${r.owner}`)
      const targetFile = fileImports.get(r.file)?.get(r.owner)
      const mounts = [
        ...(local ? [local] : []),
        ...(fileMounts.get(r.file) ?? []),
        ...(targetFile ? (fileMounts.get(targetFile) ?? []) : []),
      ]
      const best = mounts
        .filter(m => m.prefix)
        .sort((a, b) => b.prefix.length - a.prefix.length)[0]
      if (best && !routePath.startsWith(best.prefix)) routePath = joinRoutePath(best.prefix, routePath)
      for (const mount of mounts) guards.push(...mount.guards)
      guards.push(...(fileGlobals.get(r.file) ?? []))
      if (targetFile) guards.push(...(fileGlobals.get(targetFile) ?? []))
    }
    guards = uniq(guards, 20)
    const sinks = r.sinks.length > 0 ? r.sinks : detectSinksInText(r.text, options.customSinkPatterns)
    const node: CallGraphNodeOut = {
      id: `${r.file}:${r.line}:${r.symbol}`,
      file: r.file,
      line: r.line,
      ...(r.endLine ? { endLine: r.endLine } : {}),
      symbol: r.symbol,
      kind: r.kind,
      ...(r.method && r.method !== 'ANY' ? { httpMethod: r.method } : {}),
      routePath,
      ...(sinks[0] ? { sinkKind: sinks[0].sinkKind } : {}),
      guards,
      sanitizers: sanitizersFor(r.text),
      calls: uniq(r.calls, 40),
    }
    registerNode(node)
    if (sinks.length > 0 && node.kind === 'entrypoint') {
      const sinkNode: CallGraphNodeOut = {
        id: `${r.file}:${r.line}:sink:${sinks[0].label}`,
        file: r.file,
        line: r.line,
        ...(r.endLine ? { endLine: r.endLine } : {}),
        symbol: sinks[0].label,
        kind: 'sink',
        sinkKind: sinks[0].sinkKind,
        guards,
        sanitizers: sanitizersFor(r.text),
        calls: [],
      }
      registerNode(sinkNode)
      edges.push({ fromId: node.id, toId: sinkNode.id, file: r.file, line: r.line })
    }
  }

  const callsInText = (text: string): string[] => {
    const calls: string[] = []
    for (const match of text.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:\.\s*([A-Za-z_$][A-Za-z0-9_$]*))?\s*\(/g)) {
      calls.push(match[2] ?? match[1])
      if (match[2]) calls.push(`${match[1]}.${match[2]}`)
    }
    return uniq(calls, 40)
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
        const lineOffsets = buildLineOffsets(f.content)
        const fileLines = f.content.split('\n')
        // Imports, require() bindings and env string constants.
        walkAst(ast, node => {
          if (node.type === 'ImportDeclaration' && isAstNode(node.source)) {
            const spec = resolveStringValue(node.source)
            const resolved = spec ? resolveImportSpec(f.file, spec, allFilePaths, tsPaths) : null
            if (resolved && Array.isArray(node.specifiers)) {
              for (const sp of node.specifiers) {
                if (!isAstNode(sp)) continue
                const local = getPropName(sp.local)
                if (local) importMap.set(local, resolved)
              }
            }
          }
          if (node.type === 'VariableDeclarator' && isAstNode(node.init) && node.init.type === 'CallExpression') {
            const callee = getCalleeParts(node.init.callee)
            if (callee[callee.length - 1] === 'require') {
              const spec = resolveStringValue(getCallArgs(node.init)[0])
              const resolved = spec ? resolveImportSpec(f.file, spec, allFilePaths, tsPaths) : null
              const local = getPropName(node.id)
              if (resolved && local) importMap.set(local, resolved)
            }
          }
        })

        walkAst(ast, (node, ancestors) => {
          // Express/Fastify-style route registration: app.get('/x', mw, handler)
          if (node.type === 'CallExpression') {
            const parts = getCalleeParts(node.callee)
            const last = parts[parts.length - 1] ?? ''
            const owner = parts.length === 2 ? parts[0] : undefined
            const routeMethods = ['get', 'post', 'put', 'patch', 'delete', 'all', 'options', 'head']
            if (owner && routeMethods.includes(last.toLowerCase())) {
              const args = getCallArgs(node)
              const routePath = resolveStringValue(args[0])
              if (routePath && routePath.startsWith('/')) {
                const { startLine, endLine, text } = extractBodyRange(node, f.content, lineOffsets, fileLines)
                pendingRoutes.push({
                  file: f.file,
                  line: startLine,
                  endLine,
                  text,
                  method: last.toUpperCase(),
                  routePath,
                  symbol: `${last.toUpperCase()} ${routePath}`,
                  kind: 'entrypoint',
                  guards: collectRouteGuardNames(args.slice(1)),
                  sinks: detectSinksInText(text, options.customSinkPatterns),
                  calls: callsInText(text),
                  owner,
                })
              }
            } else if (owner && last === 'use') {
              const args = getCallArgs(node)
              const prefix = resolveStringValue(args[0])
              const middlewareArgs = prefix && prefix.startsWith('/') ? args.slice(1) : args
              const guards = collectRouteGuardNames(middlewareArgs)
              const lastArg = middlewareArgs[middlewareArgs.length - 1]
              const routerVar = isAstNode(lastArg) && (lastArg.type === 'Identifier' || lastArg.type === 'MemberExpression')
                ? getCalleeParts(lastArg).pop()
                : undefined
              const isPathful = Boolean(prefix && prefix.startsWith('/'))
              if (routerVar) {
                if (!isPathful) {
                  const globals = fileGlobals.get(f.file) ?? []
                  fileGlobals.set(f.file, uniq([...globals, ...guards], 12))
                }
                const existingLocal = localMounts.get(`${f.file}::${routerVar}`)
                const localMount = {
                  prefix: isPathful ? prefix! : (existingLocal?.prefix ?? ''),
                  guards: uniq([...(existingLocal?.guards ?? []), ...guards], 12),
                }
                if (localMount.prefix || localMount.guards.length) localMounts.set(`${f.file}::${routerVar}`, localMount)
                const targetFile = importMap.get(routerVar)
                if (targetFile && (localMount.prefix || localMount.guards.length)) {
                  const list = fileMounts.get(targetFile) ?? []
                  list.push({ prefix: localMount.prefix, guards: localMount.guards })
                  fileMounts.set(targetFile, list)
                }
              } else if (!isPathful) {
                const globals = fileGlobals.get(f.file) ?? []
                fileGlobals.set(f.file, uniq([...globals, ...guards], 12))
              }
            }

            // tRPC router procedures: router({ orders: protectedProcedure.input(...).query(...) })
            if (['router', 'createTRPCRouter'].includes(last)) {
              const obj = getCallArgs(node)[0]
              if (isAstNode(obj) && obj.type === 'ObjectExpression') {
                const parent = ancestors[ancestors.length - 1]
                const routerName = parent && parent.type === 'VariableDeclarator' ? (getPropName(parent.id) ?? 'router') : 'router'
                for (const prop of getObjectProps(obj)) {
                  let op = 'query'
                  let protectedProc = false
                  const paramNames: string[] = []
                  walkAst(prop.value, inner => {
                    if (inner.type !== 'CallExpression') return
                    const cp = getCalleeParts(inner.callee)
                    const name = cp[cp.length - 1] ?? ''
                    if (['query', 'mutation', 'subscription'].includes(name)) op = name
                    if (cp.some(p => /protectedProcedure|authedProcedure|privateProcedure|isAuthed/i.test(p))) protectedProc = true
                    if (name === 'input') {
                      for (const arg of getCallArgs(inner)) {
                        if (isAstNode(arg) && (arg.type === 'ObjectExpression' || arg.type === 'CallExpression')) {
                          walkAst(arg, a => {
                            if (a.type === 'ObjectExpression') {
                              for (const p2 of getObjectProps(a)) paramNames.push(p2.key)
                            }
                          })
                        }
                      }
                    }
                  })
                  if (protectedProc) importMap.set('__trpcProtected', '__trpcProtected')
                  const trpcLine = nodeLine(node, f.content, lineOffsets) ?? 1
                  pendingRoutes.push({
                    file: f.file,
                    line: trpcLine,
                    text: fileLines.slice(trpcLine - 1, trpcLine + 24).join('\n'),
                    method: 'POST',
                    routePath: `/trpc/${routerName}.${prop.key}`,
                    symbol: `TRPC ${routerName}.${prop.key}`,
                    kind: 'entrypoint',
                    guards: protectedProc ? ['protectedProcedure'] : [],
                    sinks: detectSinksInText(prop.value && isAstNode(prop.value) ? f.content : '', options.customSinkPatterns),
                    calls: paramNames.length ? [] : [],
                    owner: undefined,
                  })
                }
              }
            }
          }

          // NestJS controllers: @Controller('users') class UserController { @Get(':id') ... }
          if (node.type === 'ClassDeclaration' || node.type === 'ClassExpression') {
            const classDecs = decoratorInfo(node)
            const controller = classDecs.find(d => d.name === 'Controller')
            const classPrefix = controller?.argStrings[0] ?? ''
            const classGuards = classDecs
              .filter(d => /Guard|Roles|Secured|PreAuthorize|UseGuards/i.test(d.name))
              .flatMap(d => [d.name, ...d.argStrings, ...collectRouteGuardNames(d.args)])
            const className = getPropName(node.identifier ?? node.id) ?? 'AnonymousClass'
            const bodyNode = isAstNode(node.body) ? node.body : undefined
            const membersRaw: unknown[] = Array.isArray(node.body)
              ? node.body as unknown[]
              : bodyNode && Array.isArray(bodyNode.body)
                ? bodyNode.body as unknown[]
                : bodyNode
                  ? Object.values(bodyNode).filter(v => isAstNode(v) && String((v as AstNode).type).startsWith('Class'))
                  : []
            for (const rawMember of membersRaw) {
              if (!isAstNode(rawMember)) continue
              if (!['ClassMethod', 'ClassProperty', 'MethodDefinition', 'PropertyDefinition'].includes(String(rawMember.type))) continue
              const methodName = getPropName(rawMember.key ?? rawMember.id) ?? 'method'
              const mDecs = decoratorInfo(rawMember)
              const routeDec = mDecs.find(d => NEST_ROUTE_DECORATORS[d.name])
              const { startLine, endLine, text } = extractBodyRange(rawMember, f.content, lineOffsets, fileLines)
              const methodGuards = mDecs
                .filter(d => /Guard|Roles|Secured|PreAuthorize|UseGuards|Auth/i.test(d.name))
                .flatMap(d => [d.name, ...d.argStrings, ...collectRouteGuardNames(d.args)])
              const gs = detectGuardsAndSanitizers(text, options.customGuardPatterns, options.customSanitizerPatterns)
              const guards = uniq([...classGuards, ...methodGuards, ...gs.guards], 20)
              if (routeDec) {
                pendingRoutes.push({
                  file: f.file,
                  line: startLine,
                  endLine,
                  text,
                  method: NEST_ROUTE_DECORATORS[routeDec.name],
                  routePath: joinRoutePath(classPrefix, routeDec.argStrings[0] ?? ''),
                  symbol: `${routeDec.name.toUpperCase()} ${joinRoutePath(classPrefix, routeDec.argStrings[0] ?? '')}`,
                  kind: 'entrypoint',
                  guards,
                  sinks: detectSinksInText(text, options.customSinkPatterns),
                  calls: callsInText(text),
                })
              } else {
                const sinks = detectSinksInText(text, options.customSinkPatterns)
                if (!registeredRouteKeys.has(`${f.file}:${startLine}:${methodName}`)) {
                  registeredRouteKeys.add(`${f.file}:${startLine}:${methodName}`)
                  registerNode({
                    id: `${f.file}:${startLine}:${className}.${methodName}`,
                    file: f.file,
                    line: startLine,
                    endLine,
                    symbol: methodName,
                    kind: sinks.length > 0 ? 'sink' : 'function',
                    ...(sinks[0] ? { sinkKind: sinks[0].sinkKind } : {}),
                    guards,
                    sanitizers: gs.sanitizers,
                    calls: callsInText(text),
                  })
                }
              }
            }
          }

          // GraphQL resolvers: { Query: { order: (...) => ... }, Mutation: {...} }
          if (node.type === 'ObjectExpression') {
            for (const prop of getObjectProps(node)) {
              if (!['Query', 'Mutation', 'Subscription', 'Resolver'].includes(prop.key)) continue
              if (!isAstNode(prop.value) || prop.value.type !== 'ObjectExpression') continue
              for (const resolver of getObjectProps(prop.value)) {
                const resolverValue = isAstNode(resolver.value) ? resolver.value : node
                const line = nodeLine(resolverValue, f.content, lineOffsets) ?? nodeLine(node, f.content, lineOffsets) ?? 1
                const text = fileLines.slice(line - 1, line + 24).join('\n')
                pendingRoutes.push({
                  file: f.file,
                  line,
                  text,
                  method: prop.key === 'Mutation' ? 'POST' : 'POST',
                  routePath: `/graphql#${prop.key}.${resolver.key}`,
                  symbol: `GraphQL ${prop.key}.${resolver.key}`,
                  kind: 'entrypoint',
                  guards: detectGuardsAndSanitizers(text, options.customGuardPatterns, options.customSanitizerPatterns).guards,
                  sinks: detectSinksInText(text, options.customSinkPatterns),
                  calls: callsInText(text),
                })
              }
            }
          }

          // Named functions / exported arrow functions / Next.js route handlers.
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
            const { startLine, endLine, text } = extractBodyRange(fnNode, f.content, lineOffsets, fileLines)
            const rangeKey = `${f.file}:${startLine}:${fnName}`
            if (registeredRouteKeys.has(rangeKey)) return
            registeredRouteKeys.add(rangeKey)

            const isExported = ancestors.some(a => a.type === 'ExportDeclaration' || a.type === 'ExportNamedDeclaration' || a.type === 'ExportDefaultDeclaration')
            const nextRoute = nextRoutePathFromFile(f.file)
            const isHttpVerb = /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(fnName)
            const isNextRouteMethod = isExported && isHttpVerb && Boolean(nextRoute)
            const isNextPagesDefault = Boolean(nextRoute) && nextRoute?.kind === 'pages' && isExported && /^(?:default|handler)$/i.test(fnName)
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
            if (isNextRouteMethod || isNextPagesDefault) {
              pendingRoutes.push({
                file: f.file,
                line: startLine,
                endLine,
                text,
                method: isNextRouteMethod ? fnName : 'ANY',
                routePath: nextRoute!.routePath,
                symbol: `${isNextRouteMethod ? fnName : 'ANY'} ${nextRoute!.routePath}`,
                kind: 'entrypoint',
                guards: gs.guards,
                sinks,
                calls: uniq(calls, 40),
              })
            } else {
              const kind: CallGraphNodeOut['kind'] = isServerAction
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
                ...(isServerAction ? { routePath: `action:${fnName}`, sinkKind: 'server_action' } : {}),
                ...(sinks[0] ? { sinkKind: sinks[0].sinkKind } : {}),
                guards: gs.guards,
                sanitizers: gs.sanitizers,
                calls: uniq(calls, 40),
              })
            }
          }
        })

        // Next.js middleware matcher -> protect matching routes.
        if (/(?:^|\/)middleware\.[jt]sx?$/i.test(f.file)) {
          const matchers = [...f.content.matchAll(/matcher\s*:\s*\[([^\]]+)\]/g)]
            .flatMap(m => [...m[1].matchAll(/['"]([^'"]+)['"]/g)].map(x => x[1]))
          const prefixGuards = matchers.map(m => m.replace(/\/:path\*?$/, '').replace(/\/\(\.\*\)$/, ''))
          for (const route of pendingRoutes) {
            if (prefixGuards.some(prefix => prefix === '/' || route.routePath.startsWith(prefix))) {
              route.guards = uniq([...route.guards, 'next-middleware'], 20)
            }
          }
          registerNode({
            id: `${f.file}:1:MIDDLEWARE`,
            file: f.file,
            line: 1,
            symbol: 'MIDDLEWARE',
            kind: 'middleware',
            routePath: '/*',
            guards: ['next-middleware'],
            sanitizers: [],
            calls: callsInText(f.content),
          })
        }
        continue
      }
      // Malformed/minified JS or worker deps unavailable: regex fallback still resolves
      // imports, aliases and router mounts so the graph stays useful.
      for (const match of f.content.matchAll(/(?:import\s+[^'"]*?from\s*|import\s*|require\s*\(\s*)["']([^"']+)["']/g)) {
        const spec = match[1]
        const resolved = resolveImportSpec(f.file, spec, allFilePaths, tsPaths)
        if (!resolved) continue
        const localName = match[0].match(/\bas\s+([A-Za-z_$][A-Za-z0-9_$]*)/)?.[1]
          ?? match[0].match(/^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from/)?.[1]
        if (localName) importMap.set(localName, resolved)
        const named = match[0].match(/\{([^}]*)\}/)?.[1]
        if (named) {
          for (const part of named.split(',')) {
            const [imported, alias] = part.trim().split(/\s+as\s+/)
            const name = (alias ?? imported)?.trim()
            if (name && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)) importMap.set(name, resolved)
          }
        }
        const requireBinding = match[0].match(/^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=/)
        if (requireBinding) importMap.set(requireBinding[1], resolved)
      }
      for (const use of f.content.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\.use\s*\(\s*["']([^"']+)["']\s*,?\s*([^)]*)/g)) {
        const guards = collectTextGuardNames(use[3])
        const routerVar = use[3].match(/([A-Za-z_$][A-Za-z0-9_$]*)\s*$/)?.[1]
        if (!routerVar) continue
        localMounts.set(`${f.file}::${routerVar}`, { prefix: use[2], guards })
        const targetFile = importMap.get(routerVar)
        if (targetFile) {
          const list = fileMounts.get(targetFile) ?? []
          list.push({ prefix: use[2], guards })
          fileMounts.set(targetFile, list)
        }
      }
    }

    // Language-aware structural extraction for Python / Java / Go / Ruby / PHP.
    for (const route of extractNonJsRoutes(f.file, f.content, options)) {
      pendingRoutes.push(route)
    }
  }

  for (const route of pendingRoutes) registerExtractedRoute(route)

  // Link callEdges across files
  const edgeKeys = new Set<string>()
  const resolveBarrelExports = (file: string, symbol: string, depth = 0): string[] => {
    if (depth > 2) return []
    const content = contentByFile.get(file)
    if (!content) return []
    const targets: string[] = []
    for (const match of content.matchAll(/export\s*(?:\{[^}]*\}|(?:\*|\w+)\s+as\s+\w+[^;]*?)\s*from\s*["']([^"']+)["']/g)) {
      const resolved = resolveImportSpec(file, match[1], allFilePaths, tsPaths)
      if (resolved && !targets.includes(resolved)) targets.push(resolved)
    }
    for (const match of content.matchAll(/export\s*\*\s*from\s*["']([^"']+)["']/g)) {
      const resolved = resolveImportSpec(file, match[1], allFilePaths, tsPaths)
      if (resolved && !targets.includes(resolved)) targets.push(resolved)
    }
    const out: string[] = []
    for (const target of targets) {
      if (nodesByFileAndSymbol.has(`${target}::${symbol}`)) out.push(target)
      else out.push(...resolveBarrelExports(target, symbol, depth + 1))
    }
    return out
  }
  for (const caller of nodes) {
    const imps = fileImports.get(caller.file)
    for (const calleeSym of caller.calls) {
      if (calleeSym === caller.symbol) continue
      const targetFile = imps?.get(calleeSym)
      const candidates: CallGraphNodeOut[] = []
      if (targetFile) {
        const exact = nodesByFileAndSymbol.get(`${targetFile}::${calleeSym}`)
        if (exact) candidates.push(exact)
        else {
          for (const viaBarrel of resolveBarrelExports(targetFile, calleeSym)) {
            const hit = nodesByFileAndSymbol.get(`${viaBarrel}::${calleeSym}`)
            if (hit) candidates.push(hit)
          }
        }
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

  const nodeTextCache = new Map<string, string>()
  const guardOccurrenceCache = new Map<string, PatternOccurrence[]>()
  const sanitizerOccurrenceCache = new Map<string, PatternOccurrence[]>()
  const nodeTextFor = (node: CallGraphNodeOut): string => {
    const cached = nodeTextCache.get(node.id)
    if (cached !== undefined) return cached
    const lines = fileLineTexts.get(node.file) ?? []
    const startIndex = Math.max(0, node.line - 1)
    const endIndex = typeof node.endLine === 'number'
      ? Math.min(lines.length, node.endLine)
      : Math.min(lines.length, startIndex + 25)
    const text = lines.slice(startIndex, endIndex).join('\n')
    nodeTextCache.set(node.id, text)
    return text
  }
  const guardOccurrencesFor = (node: CallGraphNodeOut): PatternOccurrence[] => {
    const cached = guardOccurrenceCache.get(node.id)
    if (cached) return cached
    const occurrences = findOccurrences(nodeTextFor(node), DEFAULT_GUARD_RE.source, options.customGuardPatterns)
    guardOccurrenceCache.set(node.id, occurrences)
    return occurrences
  }
  const sanitizerOccurrencesFor = (node: CallGraphNodeOut): PatternOccurrence[] => {
    const cached = sanitizerOccurrenceCache.get(node.id)
    if (cached) return cached
    const occurrences = findOccurrences(nodeTextFor(node), DEFAULT_SANITIZER_RE.source, options.customSanitizerPatterns)
    sanitizerOccurrenceCache.set(node.id, occurrences)
    return occurrences
  }
  const escapeRegExp = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const offsetOfSymbol = (text: string, symbol: string): number | null => {
    if (!symbol) return null
    const masked = maskCommentsAndStrings(text)
    const match = new RegExp(`\\b${escapeRegExp(symbol)}\\b`).exec(masked)
    return match ? match.index : null
  }
  const firstSinkOffset = (node: CallGraphNodeOut, sinkKind: CallGraphSinkKind): number | null => {
    const hits = findSinkOccurrences(nodeTextFor(node), options.customSinkPatterns)
    const hit = hits.find(h => h.sinkKind === sinkKind) ?? hits[0]
    return hit ? hit.offset : null
  }
  /**
   * Statement-order dominance: a guard/sanitizer only counts when it appears
   * before the call into the next chain node (or before the sink itself).
   * Comments, string literals and post-sink checks are excluded.
   */
  const dominanceLimitOffset = (
    chain: CallGraphNodeOut[],
    index: number,
    sink: CallGraphNodeOut,
    sinkKind: CallGraphSinkKind,
  ): number | null => {
    const node = chain[index]
    if (index === chain.length - 1) return firstSinkOffset(node, sinkKind)
    const next = chain[index + 1]
    const endLine = node.endLine ?? node.line + 25
    const nested = next.file === node.file && next.line >= node.line && next.line <= endLine
    if (nested) {
      if (next.id === sink.id) return firstSinkOffset(node, sinkKind)
      const nestedSymbol = offsetOfSymbol(nodeTextFor(node), next.symbol)
      if (nestedSymbol !== null) return nestedSymbol
      return firstSinkOffset(node, next.sinkKind ?? sinkKind)
    }
    return offsetOfSymbol(nodeTextFor(node), next.symbol)
  }

  for (const group of grouped.values()) {
    const { ep, sink, chain } = group[0]
    const sinkKind = sink.sinkKind ?? 'other'
    const dominatingSetFor = (
      occurrencesFor: (node: CallGraphNodeOut) => PatternOccurrence[],
      includeInheritedGuards: boolean,
    ): Array<Set<string>> => group.map(g => {
      const set = new Set<string>()
      for (let i = 0; i < g.chain.length; i += 1) {
        const node = g.chain[i]
        // Framework-inherited guards (Express mount middleware, NestJS @UseGuards,
        // FastAPI Depends, middleware.ts matchers) are pre-handler by construction,
        // so they dominate the sink even though their text lives in another file.
        if (includeInheritedGuards && (node.kind === 'entrypoint' || node.kind === 'middleware')) {
          // Guards recorded as framework metadata (mount middleware, decorators, Depends) have no
          // textual occurrence in this node and dominate by construction. Textual guards still go
          // through the statement-order check below, so a post-sink check cannot count.
          const textual = occurrencesFor(node)
          for (const guard of node.guards) {
            if (!textual.some(occurrence => occurrence.name === guard)) set.add(guard)
          }
        }
        if (!includeInheritedGuards) {
          for (const sanitizer of node.sanitizers) set.add(sanitizer)
        }
        const limit = dominanceLimitOffset(g.chain, i, g.sink, sinkKind)
        for (const occurrence of occurrencesFor(node)) {
          if (limit === null || occurrence.offset < limit) set.add(occurrence.name)
        }
      }
      return set
    })
    const guardSets = dominatingSetFor(guardOccurrencesFor, true)
    const sanSets = dominatingSetFor(sanitizerOccurrencesFor, false)
    const allGuards = uniq(guardSets.flatMap(s => [...s]), 20)
    const dominatingGuards = allGuards.filter(g => guardSets.every(s => s.has(g)))
    const partialGuards = allGuards.filter(g => !dominatingGuards.includes(g))
    const allSans = uniq(sanSets.flatMap(s => [...s]), 20)
    const dominatingSanitizers = allSans.filter(sn => sanSets.every(s => s.has(sn)))

    const isAuthSensitive = ['api_route', 'server_action', 'webhook', 'auth_config', 'db_query'].includes(sinkKind)
    const isInjectionSink = ['db_query', 'outbound_fetch', 'redirect', 'postmessage_iframe', 'upload_storage', 'other'].includes(sinkKind)
    const hasDomGuard = dominatingGuards.length > 0
    const hasDomSanitizer = dominatingSanitizers.length > 0
    // Guards and sanitizers are distinct controls: a sanitizer never satisfies
    // an authorization check, and an auth guard never sanitizes a sink.
    const isAuthUnguarded = isAuthSensitive && !hasDomGuard
    const isInjectionUnsanitized = isInjectionSink && !hasDomSanitizer
    const isUnguardedPath = isAuthUnguarded || isInjectionUnsanitized

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
      isAuthUnguarded,
      isInjectionUnsanitized,
      isUnguardedPath,
      ...(sinkKind === 'db_query'
        ? { missingTenantScope: !TENANT_SCOPE_RE.test(nodeTextFor(sink)) }
        : {}),
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

const TECH_TAG_PACKAGE_RULES: Array<{ re: RegExp; tags: string[] }> = [
  { re: /^(?:next|@next\/)/i, tags: ['nextjs', 'react', 'node'] },
  { re: /^react/i, tags: ['react'] },
  { re: /^@nestjs\//i, tags: ['nestjs', 'node'] },
  { re: /^(?:express|fastify|koa)$/i, tags: ['express', 'node'] },
  { re: /^vite$/i, tags: ['vite'] },
  { re: /^(?:vue|nuxt|@nuxt\/)/i, tags: ['vue', 'nuxt'] },
  { re: /^@angular\//i, tags: ['angular'] },
  { re: /^(?:graphql|@apollo\/|apollo-server)/i, tags: ['graphql'] },
  { re: /^@clerk\//i, tags: ['clerk'] },
  { re: /^@supabase\//i, tags: ['supabase'] },
  { re: /^(?:django|djangorestframework)$/i, tags: ['django', 'python'] },
  { re: /^(?:fastapi|starlette)$/i, tags: ['fastapi', 'python'] },
  { re: /^(?:flask|flask-)/i, tags: ['flask', 'python'] },
  { re: /^spring-|^org\.springframework/i, tags: ['springboot', 'java'] },
  { re: /^(?:rails|railties|actionpack)$/i, tags: ['rails'] },
  { re: /^(?:laravel\/|symfony\/)/i, tags: ['laravel', 'php'] },
  { re: /^(?:gin-gonic|go-chi|gorm\.io)/i, tags: ['go'] },
]

function techTagsForPackage(packageName: string): string[] {
  const tags: string[] = []
  for (const rule of TECH_TAG_PACKAGE_RULES) {
    if (rule.re.test(packageName)) tags.push(...rule.tags)
  }
  return [...new Set(tags)]
}

function manifestDeps(fileName: string, content: string): Array<{ ecosystem: string; package: string; version?: string }> {
  const base = fileName.split('/').pop()?.toLowerCase() ?? ''
  const deps: Array<{ ecosystem: string; package: string; version?: string }> = []
  if (base === 'package.json') {
    try {
      const pkg = JSON.parse(content) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
      for (const [name, ver] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
        deps.push({ ecosystem: 'npm', package: name, version: ver.replace(/^[^\d]*/, '') || undefined })
      }
    } catch { /* ignore */ }
  } else if (base === 'requirements.txt') {
    for (const line of content.split('\n')) {
      const clean = line.split('#')[0].trim()
      const m = clean.match(/^([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|<=)?\s*([0-9][\w.+-]*)?/)
      if (m) deps.push({ ecosystem: 'pypi', package: m[1], ...(m[2] ? { version: m[2] } : {}) })
    }
  } else if (base === 'pyproject.toml' || base === 'pipfile') {
    for (const m of content.matchAll(/([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|\^|<=)\s*["']?([0-9][\w.+-]*)/g)) {
      deps.push({ ecosystem: 'pypi', package: m[1], version: m[2] })
    }
  } else if (base === 'go.mod') {
    for (const m of content.matchAll(/^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}\/[^\s]+)\s+v([\d.]+)/gim)) {
      deps.push({ ecosystem: 'go', package: m[1], version: m[2] })
    }
  } else if (base === 'pom.xml') {
    const artifacts = [...content.matchAll(/<artifactId>\s*([A-Za-z0-9_.-]+)\s*<\/artifactId>/g)].map(m => m[1])
    const versions = [...content.matchAll(/<version>\s*([0-9][\w.-]*)\s*<\/version>/g)].map(m => m[1])
    artifacts.forEach((name, i) => deps.push({ ecosystem: 'java', package: name, ...(versions[i] ? { version: versions[i] } : {}) }))
  } else if (base === 'build.gradle' || base === 'build.gradle.kts') {
    for (const m of content.matchAll(/["']([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+):([0-9][\w.+-]*)["']/g)) {
      deps.push({ ecosystem: 'java', package: m[2], version: m[3] })
    }
  } else if (base === 'gemfile' || base === 'gemfile.lock') {
    for (const m of content.matchAll(/^\s*gem\s+["']([A-Za-z0-9_.-]+)["']\s*,?\s*["']?([0-9][\w.+-]*)?/gm)) {
      deps.push({ ecosystem: 'rubygems', package: m[1], ...(m[2] ? { version: m[2] } : {}) })
    }
  }
  return deps
}

export function techFingerprint(input: {
  headers?: Record<string, string>
  body?: string
  url?: string
  packageJson?: string
  manifests?: ReadonlyArray<{ name: string; content: string }>
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
  if (input.manifests) {
    for (const manifest of input.manifests) {
      for (const dep of manifestDeps(manifest.name, manifest.content)) {
        add(dep.ecosystem, dep.package, dep.version, 'high', `${manifest.name} dependency ${dep.package}${dep.version ? `@${dep.version}` : ''}`)
      }
    }
  }
  const techTags = [...new Set(detected.flatMap(item => [
    ...techTagsForPackage(item.package),
    ...(item.ecosystem === 'npm' && item.package === 'express' ? ['express', 'node'] : []),
  ]))]
  return { url: input.url, count: detected.length, technologies: detected.slice(0, 100), techTags }
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
