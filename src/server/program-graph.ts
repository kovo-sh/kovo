/**
 * Program Graph — code-first structural analysis for v6 Phase 4.
 *
 * This module is deliberately dependency-free: it parses JavaScript/TypeScript,
 * Python, Java, Go and Ruby source with a delimiter-balanced structural scanner
 * (strings/comments/nesting aware) rather than line regexes. The resulting
 * graph keeps file:line for every route, handler, call edge and sink so live
 * findings can be reconciled back to exact code locations.
 *
 * Regexes are only used as an explicit last-resort fallback for constructs the
 * structural scanner cannot attribute to a handler; those routes are marked
 * with `extraction: 'regex'` and recorded in `warnings`.
 */
import type { StaticWorkspaceSnapshot } from './static-workspace-snapshot.ts'

export type ProgramFramework =
  | 'express'
  | 'fastify'
  | 'nestjs'
  | 'nextjs'
  | 'fastapi'
  | 'django'
  | 'flask'
  | 'spring'
  | 'gin'
  | 'chi'
  | 'rails'
  | 'unknown'

export type ProgramSinkKind =
  | 'db_query'
  | 'outbound_fetch'
  | 'template'
  | 'file'
  | 'command'
  | 'redirect'
  | 'other'

export type ProgramExtractionMode = 'ast' | 'regex'

export interface ProgramRouteInput {
  /** Path-template parameter names (`:id`, `<int:pk>`, `{id}`). */
  params: string[]
  query: string[]
  body: string[]
  /** Framework-specific schema/validation references detected on the route. */
  schemas: string[]
}

export interface ProgramRoute {
  id: string
  framework: ProgramFramework
  method: string
  /** Fully mounted path (prefixes resolved, `{id}`/`<int:id>` normalised to `:id`). */
  path: string
  file: string
  line: number
  handler: string
  handlerFile?: string
  handlerLine?: number
  input: ProgramRouteInput
  /** Effective middleware chain in declaration order (router global -> mount -> route). */
  middleware: string[]
  /** Subset of middleware that looks like auth/RBAC/tenant enforcement. */
  guards: string[]
  /** Mount prefixes applied while resolving this route. */
  mountedFrom: string[]
  extraction: ProgramExtractionMode
}

export interface ProgramNode {
  id: string
  kind: 'route' | 'function' | 'middleware' | 'sink'
  symbol: string
  file: string
  line: number
  endLine?: number
  routePath?: string
  httpMethod?: string
  sinkKind?: ProgramSinkKind
  guards: string[]
  calls: string[]
}

export interface ProgramEdge {
  fromId: string
  toId: string
  file: string
  line: number
}

export interface ProgramGraph {
  repo?: string
  filesScanned: number
  frameworks: ProgramFramework[]
  routes: ProgramRoute[]
  nodes: ProgramNode[]
  edges: ProgramEdge[]
  globalMiddleware: string[]
  warnings: string[]
  /** Bounded, value-free secret/IaC hints per route module (v7 white-box evidence). */
  codeHints?: Record<string, CodeSliceHint[]>
  /** Bounded, value-free repository-wide secret & IaC static leads (v7 M2). */
  staticLeads?: StaticCodeLead[]
}

export interface RouteSinkPath {
  routeId: string
  route: ProgramRoute
  sinkId: string
  sinkKind: ProgramSinkKind
  sinkFile: string
  sinkLine: number
  /** route -> handler -> ... -> sink, each hop with exact file:line. */
  chain: Array<{ id: string; kind: ProgramNode['kind']; symbol: string; file: string; line: number }>
  hops: number
  dominatingGuards: string[]
}

export type CodeHypothesisKind =
  | 'admin_route_missing_admin_guard'
  | 'tenant_param_without_scope'
  | 'unauthenticated_sink'
  | 'recent_diff_touches_sink'
  | 'middleware_policy_diff'
  | 'static_secret_or_iac'

export interface CodeToRuntimeHypothesis {
  id: string
  kind: CodeHypothesisKind
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence: number
  framework: ProgramFramework
  method?: string
  path?: string
  file: string
  line: number
  sinkKind?: ProgramSinkKind
  routeId?: string
  rationale: string
  evidence: string[]
  /** Suggested deterministic probe family (consumed by the Layer-2 floor). */
  probeClass: 'bola_bfla' | 'auth_bypass' | 'injection' | 'ssrf' | 'code_review'
}

// ============================================================================
// Structural scanner helpers
// ============================================================================

function lineNumberAt(text: string, index: number): number {
  let line = 1
  const end = Math.min(Math.max(0, index), text.length)
  for (let i = 0; i < end; i += 1) if (text.charCodeAt(i) === 10) line += 1
  return line
}

function buildNewlineOffsets(text: string): number[] {
  const offsets: number[] = []
  let idx = text.indexOf('\n')
  while (idx !== -1) {
    offsets.push(idx)
    idx = text.indexOf('\n', idx + 1)
  }
  return offsets
}

function lineAtFromOffsets(offsets: readonly number[], index: number, textLength: number): number {
  const end = Math.min(Math.max(0, index), textLength)
  let lo = 0
  let hi = offsets.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (offsets[mid] < end) lo = mid + 1
    else hi = mid
  }
  return lo + 1
}

interface DelimiterIndex {
  braceOpens: number[]
  braceClose: Map<number, number>
  parenClose: Map<number, number>
}

/** Single-pass O(n) delimiter matcher for `{}` and `()`, skipping strings and comments. */
function buildDelimiterIndex(text: string): DelimiterIndex {
  const braceOpens: number[] = []
  const braceClose = new Map<number, number>()
  const parenClose = new Map<number, number>()
  const braceStack: number[] = []
  const parenStack: number[] = []
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (ch === '"' || ch === "'" || ch === '`') {
      i = skipQuoted(text, i) - 1
      continue
    }
    if (ch === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i)
      i = nl < 0 ? text.length : nl
      continue
    }
    if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2)
      i = end < 0 ? text.length : end + 1
      continue
    }
    if (ch === '{') {
      braceOpens.push(i)
      braceStack.push(i)
    } else if (ch === '}') {
      const open = braceStack.pop()
      if (open !== undefined) braceClose.set(open, i)
    } else if (ch === '(') {
      parenStack.push(i)
    } else if (ch === ')') {
      const open = parenStack.pop()
      if (open !== undefined) parenClose.set(open, i)
    }
  }
  return { braceOpens, braceClose, parenClose }
}

/** First `{` index at or after `fromIndex` in O(log n). */
function nextBraceOpen(braceOpens: readonly number[], fromIndex: number): number {
  let lo = 0
  let hi = braceOpens.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (braceOpens[mid] < fromIndex) lo = mid + 1
    else hi = mid
  }
  return lo < braceOpens.length ? braceOpens[lo] : -1
}

function skipQuoted(text: string, start: number): number {
  const quote = text[start]
  let i = start + 1
  while (i < text.length) {
    if (text[i] === '\\') {
      i += 2
      continue
    }
    if (text[i] === quote) return i + 1
    i += 1
  }
  return i
}

/** Find the matching close delimiter, skipping strings and comments. */
function findMatching(
  text: string,
  openIndex: number,
  options: { open?: string; close?: string; hashComments?: boolean; comments?: boolean } = {},
): number {
  const open = options.open ?? '{'
  const close = options.close ?? '}'
  const comments = options.comments !== false
  let depth = 0
  for (let i = openIndex; i < text.length; i += 1) {
    const ch = text[i]
    if (ch === '"' || ch === "'" || ch === '`') {
      i = skipQuoted(text, i) - 1
      continue
    }
    if (comments && ch === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i)
      i = nl < 0 ? text.length : nl
      continue
    }
    if (comments && ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2)
      i = end < 0 ? text.length : end + 1
      continue
    }
    if (options.hashComments && ch === '#') {
      const nl = text.indexOf('\n', i)
      i = nl < 0 ? text.length : nl
      continue
    }
    if (ch === open) depth += 1
    else if (ch === close) {
      depth -= 1
      if (depth === 0) return i
    }
  }
  return -1
}

/** Split a comma-separated argument list at top-level depth. */
function splitTopLevel(text: string, start: number, end: number, separator = ','): string[] {
  const out: string[] = []
  let depth = 0
  let last = start
  for (let i = start; i < end; i += 1) {
    const ch = text[i]
    if (ch === '"' || ch === "'" || ch === '`') {
      i = skipQuoted(text, i) - 1
      continue
    }
    if (ch === '(' || ch === '[' || ch === '{') depth += 1
    else if (ch === ')' || ch === ']' || ch === '}') depth -= 1
    else if (ch === separator && depth === 0) {
      out.push(text.slice(last, i).trim())
      last = i + 1
    }
  }
  const tail = text.slice(last, end).trim()
  if (tail) out.push(tail)
  return out
}

function argsAtCall(text: string, openParenIndex: number): { args: string[]; closeIndex: number } {
  const close = findMatching(text, openParenIndex, { open: '(', close: ')' })
  if (close < 0) return { args: [], closeIndex: close }
  return { args: splitTopLevel(text, openParenIndex + 1, close), closeIndex: close }
}

function stringLiteralValue(token: string | undefined): string | null {
  if (!token) return null
  const trimmed = token.trim()
  if (trimmed.length < 2) return null
  const quote = trimmed[0]
  if (quote !== "'" && quote !== '"' && quote !== '`') return null
  const end = trimmed.length - 1
  if (trimmed[end] !== quote) return null
  for (let i = 1; i < end; i += 1) {
    const ch = trimmed[i]
    if (ch === '\\') {
      if (i + 1 >= end) return null
      i += 1
      continue
    }
    if (ch === quote) return null
  }
  const raw = trimmed.slice(1, end)
  if (quote === '`' && raw.includes('${')) return null
  return raw.replace(/\\(['"`\\])/g, '$1')
}

function stringListValue(token: string | undefined): string[] {
  if (!token) return []
  const trimmed = token.trim()
  const single = stringLiteralValue(trimmed)
  if (single !== null) return [single]
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    return splitTopLevel(trimmed, 1, trimmed.length - 1)
      .map(part => stringLiteralValue(part))
      .filter((value): value is string => value !== null)
  }
  return []
}

function normalizePathTemplate(path: string): string {
  return path
    .replace(/[{<](?:int:|str:|uuid:|slug:|path:)?([A-Za-z_][A-Za-z0-9_]*)[}>]/g, ':$1')
    .replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, ':$1')
}

function joinPaths(prefix: string, path: string): string {
  const raw = `${prefix}/${path}`.replace(/\/{2,}/g, '/')
  const normalized = normalizePathTemplate(raw)
  if (!normalized.startsWith('/')) return `/${normalized}`
  return normalized.length > 1 ? normalized.replace(/\/$/, '') : '/'
}

function routeParamNames(path: string): string[] {
  const names: string[] = []
  for (const match of path.matchAll(/:([A-Za-z_][A-Za-z0-9_]*)/g)) {
    if (match[1] && !names.includes(match[1])) names.push(match[1])
  }
  return names
}

const AUTH_GUARD_RE = /\b(?:auth\w*|require\w*(?:Auth|User|Login|Token|Session|Admin|Role|Permission|Tenant|Org|Scope)\w*|isAuthenticated|ensure(?:Auth|LoggedIn)\w*|verify(?:Token|Jwt|Session)\w*|passport\w*|jwt\w*|session\w*|csrf\w*|xsrf\w*|rbac|acl|permission\w*|privilege\w*|guard\w*|currentUser|getCurrentUser|get_user|getUser|principal|identity|loginRequired)\b/i
const ADMIN_GUARD_RE = /\b(?:admin\w*|isAdmin|requireAdmin\w*|superuser\w*|staff\w*|role\w*|rbac|permission\w*|privilege\w*|policy\w*|hasRole|hasAuthority)/i
const TENANT_GUARD_RE = /(?:tenant|organization|organisation|orgId|org_id|account|workspace|membership|ownership|ownerId|owner_id|scopeCheck|belongsTo)/i

function looksLikeGuard(name: string): boolean {
  return AUTH_GUARD_RE.test(name) || ADMIN_GUARD_RE.test(name) || TENANT_GUARD_RE.test(name)
}

function flattenMiddlewareTokens(tokens: readonly string[]): string[] {
  const out: string[] = []
  for (const token of tokens) {
    const trimmed = token.trim()
    if (!trimmed) continue
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      out.push(...flattenMiddlewareTokens(splitTopLevel(trimmed, 1, trimmed.length - 1)))
      continue
    }
    if (/^(?:async\s+)?(?:function\b|\(|[\w$,\s]*(?:\)\s*)?=>)/.test(trimmed)) continue
    const normalized = trimmed.replace(/\s+/g, ' ')
    if (!out.includes(normalized)) out.push(normalized)
  }
  return out
}

function guardsFromMiddleware(middleware: readonly string[]): string[] {
  return middleware.filter(looksLikeGuard)
}

function handlerNameFromToken(token: string): string {
  const trimmed = token.trim()
  if (/=>|\bfunction\b/.test(trimmed)) return 'anonymous'
  const direct = /^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)$/.exec(trimmed)
  if (direct) return direct[1]
  const identifiers = [...trimmed.matchAll(/[A-Za-z_$][\w$]*/g)].map(m => m[0])
  const keywords = new Set(['async', 'await', 'function', 'return', 'new', 'const', 'let', 'var', 'this'])
  const filtered = identifiers.filter(name => !keywords.has(name))
  return filtered[filtered.length - 1] ?? 'anonymous'
}

function resolveImportTarget(fromFile: string, specifier: string): string | undefined {
  if (!specifier.startsWith('.')) return undefined
  const base = fromFile.replaceAll('\\', '/').split('/').slice(0, -1)
  for (const segment of specifier.split('/')) {
    if (segment === '..') base.pop()
    else if (segment !== '.') base.push(segment)
  }
  return base.join('/').replace(/\.(?:[cm]?[jt]sx?|py|go|java|rb)$/, '')
}

function inputFromSignature(signature: string): ProgramRouteInput {
  const input: ProgramRouteInput = { params: [], query: [], body: [], schemas: [] }
  const parts = splitTopLevel(signature, 0, signature.length)
  for (const part of parts) {
    const nameMatch = /(?:^|[,(\s])(?:\.\.\.)?([A-Za-z_$][\w$]*)\s*(?::|$|=)/.exec(part.trim())
    if (nameMatch) {
      if (/\bQuery\s*\(/.test(part) || /=\s*(?:None|null|undefined)/.test(part) || /=/.test(part)) input.query.push(nameMatch[1])
      else if (/\bBody\s*\(/.test(part) || /\b(?:dto|payload|body|input|request)\b/i.test(nameMatch[1])) input.body.push(nameMatch[1])
      else input.params.push(nameMatch[1])
    }
    const typeMatch = /:\s*([A-Z][A-Za-z0-9_]*)/.exec(part)
    if (typeMatch && !input.schemas.includes(typeMatch[1])) input.schemas.push(typeMatch[1])
    const annotationBody = /@RequestBody\s+(?:[\w<>[\],.]+\s+)?([A-Za-z_$][\w$]*)/.exec(part)
    if (annotationBody) input.body.push(annotationBody[1])
    const annotationParam = /@(?:PathVariable|RequestParam)\s*(?:\([^)]*\))?\s*(?:[\w<>[\],.]+\s+)?([A-Za-z_$][\w$]*)/.exec(part)
    if (annotationParam) input.params.push(annotationParam[1])
  }
  input.params = [...new Set(input.params)]
  input.query = [...new Set(input.query.filter(x => !input.params.includes(x)))]
  input.body = [...new Set(input.body.filter(x => !input.params.includes(x)))]
  return input
}

// ============================================================================
// Function / sink extraction
// ============================================================================

interface ProgramFunction {
  name: string
  file: string
  line: number
  endLine: number
  startIndex: number
  endIndex: number
  calls: string[]
  guardNames: string[]
}

const CALL_KEYWORDS = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'return', 'function', 'typeof', 'new', 'await', 'async',
  'with', 'match', 'else', 'do', 'try', 'case', 'throw', 'delete', 'void', 'in', 'of', 'yield',
  'print', 'super', 'this', 'self', 'lambda', 'def', 'end', 'begin', 'rescue', 'ensure',
])

function maskCode(body: string, hashComments: boolean): string {
  let out = ''
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i]
    if (ch === '"' || ch === "'" || ch === '`') {
      const end = skipQuoted(body, i)
      out += ch + ' '.repeat(Math.max(0, end - i - 2)) + (end - 1 < body.length ? body[end - 1] : ch)
      i = end - 1
      continue
    }
    if (ch === '/' && body[i + 1] === '/') {
      const nl = body.indexOf('\n', i)
      const end = nl < 0 ? body.length : nl
      out += ' '.repeat(end - i)
      i = end - 1
      continue
    }
    if (ch === '/' && body[i + 1] === '*') {
      const end = body.indexOf('*/', i + 2)
      const stop = end < 0 ? body.length : end + 2
      out += body.slice(i, stop).replace(/[^\n]/g, ' ')
      i = stop - 1
      continue
    }
    if (hashComments && ch === '#') {
      const nl = body.indexOf('\n', i)
      const end = nl < 0 ? body.length : nl
      out += ' '.repeat(end - i)
      i = end - 1
      continue
    }
    out += ch
  }
  return out
}

function collectCalls(maskedBody: string): string[] {
  const calls: string[] = []
  for (const match of maskedBody.matchAll(/(?:\b|\.)([A-Za-z_$][\w$]*)\s*\(/g)) {
    const name = match[1]
    if (!name || CALL_KEYWORDS.has(name) || calls.includes(name)) continue
    calls.push(name)
  }
  return calls
}

interface SinkPattern {
  kind: ProgramSinkKind
  re: RegExp
}

const SINK_PATTERNS: readonly SinkPattern[] = [
  { kind: 'db_query', re: /(?:\.\s*(?:query|execute|raw|exec|prepare)|queryRaw|executeRaw|createQuery|createNativeQuery|findBySql|whereRaw|sequelize\.query|knex\.raw)\s*\(/i },
  { kind: 'db_query', re: /\b(?:select\s+.+\s+from\s+|insert\s+into\s+|update\s+\w+\s+set\s+|delete\s+from\s+)/i },
  { kind: 'outbound_fetch', re: /\b(?:fetch|axios(?:\.[A-Za-z]+)?|got|superagent|http\.(?:get|request)|https\.(?:get|request)|requests\.(?:get|post|put|delete|request)|urllib\.request|session\.(?:get|post)|RestTemplate|WebClient|http\.(?:Get|Post)|NewRequest)\s*\(/ },
  { kind: 'template', re: /\b(?:render|render_template|renderTemplate|renderToString|ejs\.render|pug\.render|TemplateEngine|processTemplate|res\.render|sendFile)\s*\(/ },
  { kind: 'file', re: /\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|FileInputStream|Files\.(?:read|write|newInputStream)|os\.(?:Open|ReadFile|WriteFile)|fs\.(?:read|write))\b/ },
  { kind: 'command', re: /\b(?:exec|execSync|spawn|spawnSync|execFile|child_process|Runtime\.getRuntime|ProcessBuilder|os\.system|subprocess\.(?:run|call|Popen)|Open3|system)\s*\(/ },
  { kind: 'redirect', re: /\b(?:redirect|res\.redirect|location\.href|sendRedirect|Redirect)\s*\(/ },
]

function detectSinks(body: string): Array<{ kind: ProgramSinkKind; index: number }> {
  const hits: Array<{ kind: ProgramSinkKind; index: number }> = []
  const seenKinds = new Set<ProgramSinkKind>()
  for (const pattern of SINK_PATTERNS) {
    const match = pattern.re.exec(body)
    if (!match || seenKinds.has(pattern.kind)) continue
    seenKinds.add(pattern.kind)
    hits.push({ kind: pattern.kind, index: match.index })
  }
  return hits
}

const JS_METHOD_MODIFIERS = new Set(['public', 'private', 'protected', 'static', 'async', 'readonly'])
const JAVA_VISIBILITY_MODIFIERS = new Set(['public', 'protected', 'private'])

function isJsIdentStart(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code === 36
}

function isJsIdentPart(code: number): boolean {
  return isJsIdentStart(code) || (code >= 48 && code <= 57)
}

function isJavaIdentStart(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95
}

function isJavaIdentPart(code: number): boolean {
  return isJavaIdentStart(code) || (code >= 48 && code <= 57)
}

function isJavaTypePrefixChar(code: number): boolean {
  return isJavaIdentPart(code)
    || code === 32 || code === 9 // space, tab
    || code === 60 || code === 62 // < >
    || code === 91 || code === 93 // [ ]
    || code === 44 || code === 46 || code === 63 // , . ?
}

function isWsChar(code: number): boolean {
  return code === 32 || code === 9 || code === 10 || code === 13 || code === 12 || code === 11
}

/** Linear-time O(n) Java/Kotlin method header scanner (no backtracking regexes). */
function scanJavaMethodHeaders(
  content: string,
  requireVisibility = false,
): Array<{ name: string; index: number; openParen: number }> {
  const matches: Array<{ name: string; index: number; openParen: number }> = []
  const len = content.length
  let lineStart = 0
  while (lineStart < len) {
    const nl = content.indexOf('\n', lineStart)
    const lineEnd = nl < 0 ? len : nl
    let p = lineStart
    while (p < lineEnd && (content.charCodeAt(p) === 32 || content.charCodeAt(p) === 9 || content.charCodeAt(p) === 13)) p += 1
    const nextLineStart = nl < 0 ? len : nl + 1

    if (p < lineEnd) {
      const c0 = content.charCodeAt(p)
      const c1 = p + 1 < lineEnd ? content.charCodeAt(p + 1) : 0
      const isCommentOrAnnotation = c0 === 64 || c0 === 42 || (c0 === 47 && (c1 === 47 || c1 === 42))
      if (!isCommentOrAnnotation) {
        const openParen = content.indexOf('(', p)
        if (openParen > p && openParen < lineEnd) {
          let nameEnd = openParen - 1
          while (nameEnd >= p && (content.charCodeAt(nameEnd) === 32 || content.charCodeAt(nameEnd) === 9)) nameEnd -= 1
          nameEnd += 1
          let nameStart = nameEnd
          while (nameStart > p && isJavaIdentPart(content.charCodeAt(nameStart - 1))) nameStart -= 1
          if (nameStart < nameEnd && isJavaIdentStart(content.charCodeAt(nameStart))) {
            let prefixEnd = nameStart
            while (prefixEnd > p && (content.charCodeAt(prefixEnd - 1) === 32 || content.charCodeAt(prefixEnd - 1) === 9)) prefixEnd -= 1
            if (prefixEnd < nameStart && prefixEnd > p) {
              let validPrefix = true
              let hasWord = false
              for (let k = p; k < prefixEnd; k += 1) {
                const ck = content.charCodeAt(k)
                if (!isJavaTypePrefixChar(ck)) {
                  validPrefix = false
                  break
                }
                if (isJavaIdentPart(ck)) hasWord = true
              }
              if (validPrefix && hasWord) {
                let visOk = true
                if (requireVisibility) {
                  let wEnd = p
                  while (wEnd < prefixEnd && isJavaIdentPart(content.charCodeAt(wEnd))) wEnd += 1
                  visOk = JAVA_VISIBILITY_MODIFIERS.has(content.slice(p, wEnd))
                }
                if (visOk) {
                  const name = content.slice(nameStart, nameEnd)
                  if (!CALL_KEYWORDS.has(name)) {
                    matches.push({ name, index: p, openParen })
                  }
                }
              }
            }
          }
        }
      }
    }
    lineStart = nextLineStart
  }
  return matches
}

function extractJsFunctions(file: string, content: string): ProgramFunction[] {
  const out: ProgramFunction[] = []
  const seen = new Set<number>()
  const newlineOffsets = buildNewlineOffsets(content)
  const { braceOpens, braceClose, parenClose } = buildDelimiterIndex(content)

  const push = (name: string | undefined, startIndex: number, bodyOpen: number, bodyClose: number) => {
    if (!name || bodyOpen < 0 || bodyClose < 0 || seen.has(startIndex)) return
    seen.add(startIndex)
    const body = content.slice(bodyOpen, bodyClose + 1)
    out.push({
      name,
      file,
      line: lineAtFromOffsets(newlineOffsets, startIndex, content.length),
      endLine: lineAtFromOffsets(newlineOffsets, bodyClose, content.length),
      startIndex,
      endIndex: bodyClose,
      calls: collectCalls(maskCode(body, false)),
      guardNames: guardIdentifiers(body),
    })
  }

  for (const match of content.matchAll(/(?:export[ \t]+)?(?:async[ \t]+)?function[ \t]+([A-Za-z_$][\w$]*)[ \t]*\(/g)) {
    const name = match[1]
    const openParen = match.index + match[0].length - 1
    const closeParen = parenClose.get(openParen)
    const open = nextBraceOpen(braceOpens, closeParen !== undefined ? closeParen + 1 : openParen + 1)
    const close = open >= 0 ? (braceClose.get(open) ?? -1) : -1
    push(name, match.index, open, close)
  }
  for (const match of content.matchAll(/(?:export[ \t]+)?(?:const|let|var)[ \t]+([A-Za-z_$][\w$]*)[ \t]*=[ \t]*(?:async[ \t]*)?/g)) {
    const name = match[1]
    let pos = match.index + match[0].length
    if (pos >= content.length) continue
    const ch = content.charCodeAt(pos)
    if (ch === 40) { // '('
      const cp = parenClose.get(pos)
      if (cp === undefined) continue
      pos = cp + 1
    } else if (isJsIdentStart(ch)) {
      pos += 1
      while (pos < content.length && isJsIdentPart(content.charCodeAt(pos))) pos += 1
    } else {
      continue
    }
    while (pos < content.length && isWsChar(content.charCodeAt(pos))) pos += 1
    if (!content.startsWith('=>', pos)) continue
    const afterArrow = pos + 2
    const open = nextBraceOpen(braceOpens, afterArrow)
    if (open >= 0 && open - afterArrow < 200) {
      const close = braceClose.get(open) ?? -1
      push(name, match.index, open, close)
    }
  }

  // Linear-time line scanner for class/object method declarations (replaces backtracking regex).
  let noReturnBraceUntil = -1
  let lineStart = 0
  const len = content.length
  while (lineStart < len) {
    const nl = content.indexOf('\n', lineStart)
    const lineEnd = nl < 0 ? len : nl
    const nextLineStart = nl < 0 ? len : nl + 1

    let p = lineStart
    while (p < lineEnd && (content.charCodeAt(p) === 32 || content.charCodeAt(p) === 9 || content.charCodeAt(p) === 13)) p += 1
    const declStart = p

    let name: string | undefined
    while (p < lineEnd && isJsIdentStart(content.charCodeAt(p))) {
      const tokStart = p
      p += 1
      while (p < lineEnd && isJsIdentPart(content.charCodeAt(p))) p += 1
      const tok = content.slice(tokStart, p)
      const wsStart = p
      while (p < lineEnd && (content.charCodeAt(p) === 32 || content.charCodeAt(p) === 9)) p += 1
      if (p < lineEnd && content.charCodeAt(p) === 40) { // '('
        name = tok
        break
      }
      if (p > wsStart && JS_METHOD_MODIFIERS.has(tok)) continue
      break
    }

    if (name && !CALL_KEYWORDS.has(name) && p < lineEnd && content.charCodeAt(p) === 40) {
      const openParen = p
      const closeParen = parenClose.get(openParen)
      if (closeParen !== undefined && closeParen > openParen && closeParen - openParen <= 4096) {
        let k = closeParen + 1
        while (k < len && isWsChar(content.charCodeAt(k))) k += 1
        let ok = true
        if (k < len && content.charCodeAt(k) === 58) { // ':' return type annotation
          k += 1
          while (k < len && isWsChar(content.charCodeAt(k))) k += 1
          if (k < noReturnBraceUntil) {
            ok = false
          } else {
            const rtStart = k
            while (k < len) {
              const ck = content.charCodeAt(k)
              if (ck === 123) break // '{'
              if (ck === 125 || ck === 59) { // '}' or ';'
                noReturnBraceUntil = k
                ok = false
                break
              }
              k += 1
            }
            if (k >= len) {
              noReturnBraceUntil = len
              ok = false
            } else if (k === rtStart) {
              ok = false
            }
          }
        }
        if (ok && k < len && content.charCodeAt(k) === 123) { // '{'
          const paramSlice = content.slice(openParen + 1, closeParen)
          if (!paramSlice.includes(';')) {
            const close = braceClose.get(k) ?? -1
            push(name, declStart, k, close)
          }
        }
      }
    }

    lineStart = nextLineStart
  }
  return out
}

function guardIdentifiers(body: string): string[] {
  const found: string[] = []
  for (const match of body.matchAll(/\b([A-Za-z_$][\w$]{2,})\s*(?:\(|\.)/g)) {
    const name = match[1]
    if (AUTH_GUARD_RE.test(name) || TENANT_GUARD_RE.test(name)) {
      if (!found.includes(name)) found.push(name)
    }
  }
  return found.slice(0, 12)
}

function extractPythonFunctions(file: string, content: string): ProgramFunction[] {
  const out: ProgramFunction[] = []
  const lines = content.split('\n')
  for (let i = 0; i < lines.length; i += 1) {
    const match = /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/.exec(lines[i])
    if (!match) continue
    const indent = match[1].length
    let endLine = i
    for (let j = i + 1; j < lines.length; j += 1) {
      const line = lines[j]
      if (!line.trim()) continue
      const lineIndent = line.length - line.trimStart().length
      if (lineIndent <= indent) break
      endLine = j
    }
    const startIndex = lines.slice(0, i).join('\n').length
    const endIndex = lines.slice(0, endLine + 1).join('\n').length
    const body = content.slice(startIndex, endIndex)
    out.push({
      name: match[2], file, line: i + 1, endLine: endLine + 1, startIndex, endIndex,
      calls: collectCalls(maskCode(body, true)), guardNames: guardIdentifiers(body),
    })
  }
  return out
}

function extractBraceFunctions(file: string, content: string, language: 'java' | 'go'): ProgramFunction[] {
  const out: ProgramFunction[] = []
  const newlineOffsets = buildNewlineOffsets(content)
  const { braceOpens, braceClose, parenClose } = buildDelimiterIndex(content)

  const emit = (name: string, startIndex: number, openParen: number) => {
    if (!name || CALL_KEYWORDS.has(name)) return
    const closeParen = parenClose.get(openParen)
    const open = nextBraceOpen(braceOpens, closeParen !== undefined ? closeParen + 1 : openParen + 1)
    if (open < 0) return
    const close = braceClose.get(open) ?? -1
    if (close < 0) return
    const body = content.slice(open, close + 1)
    out.push({
      name,
      file,
      line: lineAtFromOffsets(newlineOffsets, startIndex, content.length),
      endLine: lineAtFromOffsets(newlineOffsets, close, content.length),
      startIndex,
      endIndex: close,
      calls: collectCalls(maskCode(body, false)),
      guardNames: guardIdentifiers(body),
    })
  }

  if (language === 'go') {
    for (const match of content.matchAll(/func[ \t]+(?:\([^)\n]{0,200}\)[ \t]*)?([A-Za-z_]\w*)[ \t]*\(/g)) {
      emit(match[1], match.index, match.index + match[0].length - 1)
    }
    return out
  }

  for (const header of scanJavaMethodHeaders(content, false)) {
    emit(header.name, header.index, header.openParen)
  }
  return out
}

function extractRubyFunctions(file: string, content: string): ProgramFunction[] {
  const out: ProgramFunction[] = []
  const lines = content.split('\n')
  for (let i = 0; i < lines.length; i += 1) {
    const match = /^(\s*)def\s+([A-Za-z_]\w*[?!=]?)/.exec(lines[i])
    if (!match) continue
    const indent = match[1].length
    let endLine = i
    for (let j = i + 1; j < lines.length; j += 1) {
      const line = lines[j]
      if (/^\s*end\b/.test(line) && line.length - line.trimStart().length <= indent) break
      endLine = j
    }
    const startIndex = lines.slice(0, i).join('\n').length
    const endIndex = lines.slice(0, endLine + 1).join('\n').length
    const body = content.slice(startIndex, endIndex)
    out.push({
      name: match[2], file, line: i + 1, endLine: endLine + 1, startIndex, endIndex,
      calls: collectCalls(maskCode(body, true)), guardNames: guardIdentifiers(body),
    })
  }
  return out
}

function languageOfFile(file: string): 'js' | 'python' | 'java' | 'go' | 'ruby' | 'unknown' {
  const lower = file.toLowerCase()
  if (/\.(?:[cm]?[jt]sx?)$/.test(lower)) return 'js'
  if (lower.endsWith('.py')) return 'python'
  if (lower.endsWith('.java') || lower.endsWith('.kt')) return 'java'
  if (lower.endsWith('.go')) return 'go'
  if (lower.endsWith('.rb')) return 'ruby'
  return 'unknown'
}

function extractFunctions(file: string, content: string): ProgramFunction[] {
  switch (languageOfFile(file)) {
    case 'js': return extractJsFunctions(file, content)
    case 'python': return extractPythonFunctions(file, content)
    case 'java': return extractBraceFunctions(file, content, 'java')
    case 'go': return extractBraceFunctions(file, content, 'go')
    case 'ruby': return extractRubyFunctions(file, content)
    default: return []
  }
}

// ============================================================================
// Route extractors
// ============================================================================

interface RawRoute {
  framework: ProgramFramework
  method: string
  path: string
  file: string
  line: number
  handler: string
  routerKey?: string
  middleware: string[]
  guards: string[]
  input: ProgramRouteInput
  extraction: ProgramExtractionMode
}

interface RouterDef {
  key: string
  name: string
  file: string
  prefix: string
  middleware: string[]
  exported?: boolean
}

interface MountSpec {
  parentKey?: string
  parentFile: string
  parentName: string
  childKey?: string
  childName: string
  childFile?: string
  prefix: string
  middleware: string[]
  file: string
  line: number
}

interface Extraction {
  routes: RawRoute[]
  routers: RouterDef[]
  mounts: MountSpec[]
  functions: ProgramFunction[]
  globalMiddleware: string[]
  warnings: string[]
}

const EXPRESS_METHOD_RE = /([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|options|head|all|route)\s*\(/g
const EXPRESS_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'all'])

function valueOrFallback(value: string): ProgramRouteInput {
  return { params: routeParamNames(value), query: [], body: [], schemas: [] }
}

function extractExpressLike(file: string, content: string, out: Extraction): void {
  const routers = new Map<string, RouterDef>()
  const framework: ProgramFramework = /\bfastify\b/i.test(content) ? 'fastify' : 'express'
  const routerKey = (name: string) => `${file}#${name}`
  const exportNames = new Set<string>()
  for (const exportMatch of content.matchAll(/(?:module\.exports\s*=|export\s+default\s+|export\s*\{[^}]*\b)([A-Za-z_$][\w$]*)/g)) exportNames.add(exportMatch[1])
  const importTargets = new Map<string, string>()
  for (const importMatch of content.matchAll(/import\s+([A-Za-z_$][\w$]*)\s+from\s+(['"])([^'"]+)\2/g)) {
    const target = resolveImportTarget(file, importMatch[3])
    if (target) importTargets.set(importMatch[1], target)
  }
  for (const importMatch of content.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*(['"])([^'"]+)\2\s*\)/g)) {
    const target = resolveImportTarget(file, importMatch[3])
    if (target) importTargets.set(importMatch[1], target)
  }

  for (const match of content.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:express\s*\.\s*)?(?:Router|router)\s*\(/g)) {
    const router: RouterDef = { key: routerKey(match[1]), name: match[1], file, prefix: '', middleware: [], exported: exportNames.has(match[1]) }
    routers.set(match[1], router)
    out.routers.push(router)
  }
  for (const match of content.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:express|Fastify|fastify)\s*\(/g)) {
    const router: RouterDef = { key: routerKey(match[1]), name: match[1], file, prefix: '', middleware: [], exported: exportNames.has(match[1]) }
    routers.set(match[1], router)
    out.routers.push(router)
  }
  if (!routers.size) return

  // Mounts and router-level middleware.
  for (const match of content.matchAll(/([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(/g)) {
    const parent = routers.get(match[1])
    if (!parent) continue
    const open = content.indexOf('(', match.index)
    const { args } = argsAtCall(content, open)
    if (!args.length) continue
    const childToken = args[args.length - 1]?.trim() ?? ''
    const childName = /^([A-Za-z_$][\w$]*)$/.exec(childToken)?.[1]
    const child = childName ? routers.get(childName) : undefined
    if (args.length >= 2 && (child || childName)) {
      const mountPaths = stringListValue(args[0])
      const middleware = flattenMiddlewareTokens(args.slice(1, -1))
      for (const mountPath of mountPaths.length ? mountPaths : ['']) {
        out.mounts.push({
          parentKey: parent.key, parentFile: file, parentName: match[1],
          ...(child ? { childKey: child.key } : {}),
          childName: childName ?? childToken,
          childFile: childName && importTargets.has(childName) ? importTargets.get(childName) : file,
          prefix: mountPath,
          middleware,
          file,
          line: lineNumberAt(content, match.index),
        })
      }
    } else {
      const middleware = flattenMiddlewareTokens(args)
      parent.middleware.push(...middleware.filter(name => !parent.middleware.includes(name)))
    }
  }

  // Fastify object routes.
  for (const match of content.matchAll(/([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(\s*\{/g)) {
    const parent = routers.get(match[1])
    if (!parent) continue
    const open = content.indexOf('{', match.index)
    const close = findMatching(content, open)
    if (close < 0) continue
    const object = content.slice(open, close + 1)
    const url = /url\s*:\s*(['"`])([^'"`]+)\1/.exec(object)?.[2]
    if (!url) continue
    const methodRaw = /method\s*:\s*(?:\[([^\]]*)\]|(['"`])([A-Za-z]+)\2)/.exec(object)
    const methods = methodRaw
      ? methodRaw[1]
        ? stringListValue(`[${methodRaw[1]}]`).map(m => m.toUpperCase())
        : [methodRaw[3].toUpperCase()]
      : ['ANY']
    const preHandler = /preHandler\s*:\s*(\[[^\]]*\]|[A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)/.exec(object)?.[1]
    const middleware = preHandler ? flattenMiddlewareTokens(splitTopLevel(preHandler, 0, preHandler.length)) : []
    const handler = /handler\s*:\s*([^,}]+)/.exec(object)?.[1]?.trim() ?? 'anonymous'
    for (const method of methods) {
      out.routes.push({
        framework: 'fastify', method, path: url, file,
        line: lineNumberAt(content, match.index), handler,
        routerKey: parent.key, middleware: [...parent.middleware, ...middleware],
        guards: guardsFromMiddleware([...parent.middleware, ...middleware]),
        input: valueOrFallback(url), extraction: 'ast',
      })
    }
  }

  // Method routes (including `.route('/x').get(...)` chains).
  for (const match of content.matchAll(EXPRESS_METHOD_RE)) {
    const parent = routers.get(match[1])
    if (!parent) continue
    const method = match[2].toLowerCase()
    if (method === 'route') continue
    const open = content.indexOf('(', match.index)
    const { args } = argsAtCall(content, open)
    if (!args.length) continue
    const routePaths = stringListValue(args[0])
    if (!routePaths.length) {
      out.warnings.push(`Skipped non-literal Express/Fastify route at ${file}:${lineNumberAt(content, match.index)}`)
      continue
    }
    const middleware = flattenMiddlewareTokens(args.slice(1, -1))
    const handlerToken = args[args.length - 1] ?? 'anonymous'
    let handler = handlerNameFromToken(handlerToken)
    const routeLine = lineNumberAt(content, match.index)
    if (handler === 'anonymous' && /=>|\bfunction\b/.test(handlerToken)) {
      const syntheticName = `inline_${method}_${routeLine}`
      const tokenOffset = content.indexOf(handlerToken, open)
      const bodyStart = tokenOffset >= 0 ? tokenOffset : open
      const bodyEnd = bodyStart + handlerToken.length
      out.functions.push({
        name: syntheticName,
        file,
        line: routeLine,
        endLine: lineNumberAt(content, Math.min(content.length - 1, bodyEnd)),
        startIndex: bodyStart,
        endIndex: Math.min(content.length, bodyEnd),
        calls: collectCalls(maskCode(handlerToken, false)),
        guardNames: guardIdentifiers(handlerToken),
      })
      handler = syntheticName
    }
    for (const routePath of routePaths) {
      out.routes.push({
        framework,
        method: method === 'all' ? 'ANY' : method.toUpperCase(),
        path: routePath, file, line: routeLine, handler,
        routerKey: parent.key,
        middleware: [...parent.middleware, ...middleware],
        guards: guardsFromMiddleware([...parent.middleware, ...middleware]),
        input: valueOrFallback(routePath),
        extraction: 'ast',
      })
    }
  }

  // `.route('/x').get(auth, handler).post(handler)` chains.
  for (const match of content.matchAll(/([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(\s*(['"`])([^'"`]+)\2\s*\)/g)) {
    const parent = routers.get(match[1])
    if (!parent) continue
    const basePath = match[3]
    let pos = match.index + match[0].length
    while (pos < content.length) {
      const rest = content.slice(pos)
      const chain = /^\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/.exec(rest)
      if (!chain) break
      const chainMethod = chain[1].toLowerCase()
      if (!EXPRESS_METHODS.has(chainMethod) && chainMethod !== 'route') break
      const chainOpen = pos + chain[0].length - 1
      const { args, closeIndex } = argsAtCall(content, chainOpen)
      if (closeIndex < 0) break
      if (chainMethod !== 'route' && args.length) {
        const middleware = flattenMiddlewareTokens(args.slice(0, -1))
        const handler = handlerNameFromToken(args[args.length - 1])
        out.routes.push({
          framework: 'express', method: chainMethod === 'all' ? 'ANY' : chainMethod.toUpperCase(),
          path: basePath, file, line: lineNumberAt(content, match.index), handler,
          routerKey: parent.key,
          middleware: [...parent.middleware, ...middleware],
          guards: guardsFromMiddleware([...parent.middleware, ...middleware]),
          input: valueOrFallback(basePath),
          extraction: 'ast',
        })
      }
      pos = closeIndex + 1
    }
  }
}

function extractNest(file: string, content: string, out: Extraction): boolean {
  const controllerMatches = [...content.matchAll(/@Controller\s*\(([^)]*)\)/g)]
  if (!controllerMatches.length) return false
  for (const match of controllerMatches) {
    const classIndex = content.indexOf('class', match.index + match[0].length)
    if (classIndex < 0) continue
    const bodyOpen = content.indexOf('{', classIndex)
    if (bodyOpen < 0) continue
    const bodyClose = findMatching(content, bodyOpen)
    if (bodyClose < 0) continue
    const classPrefix = stringListValue(splitTopLevel(match[1], 0, match[1].length)[0])[0] ?? ''
    const header = content.slice(match.index, classIndex)
    const classGuards = decoratorGuards(header)
    const body = content.slice(bodyOpen + 1, bodyClose)

    for (const routeMatch of body.matchAll(/@(Get|Post|Put|Patch|Delete|Options|Head|All)\s*\(([^)]*)\)/g)) {
      const decoratorStart = bodyOpen + 1 + routeMatch.index
      const routeArgs = splitTopLevel(routeMatch[2], 0, routeMatch[2].length)
      const routePath = stringListValue(routeArgs[0])[0] ?? ''
      const decoratorRegion = content.slice(decoratorStart, Math.min(content.length, decoratorStart + 700))
      const handlerMatch = /(?:^|\n)\s*(?:(?:public|private|protected|static|async|readonly)\s+)*([A-Za-z_$][\w$]*)\s*\(/g
      let handler = 'anonymous'
      let handlerLine: number | undefined
      let methodDecorators = ''
      let handlerSignature = ''
      for (const hm of decoratorRegion.matchAll(handlerMatch)) {
        if (['if', 'for', 'while', 'switch', 'catch'].includes(hm[1])) continue
        handler = hm[1]
        const signatureOpen = decoratorStart + (hm.index ?? 0) + hm[0].length - 1
        handlerSignature = argsAtCall(content, signatureOpen).args.join(', ')
        handlerLine = lineNumberAt(content, decoratorStart + (hm.index ?? 0))
        methodDecorators = decoratorRegion.slice(0, hm.index)
        break
      }
      const methodGuards = decoratorGuards(methodDecorators)
      const method = routeMatch[1].toUpperCase() === 'ALL' ? 'ANY' : routeMatch[1].toUpperCase()
      const fullPath = joinPaths(joinPaths('', classPrefix), routePath)
      out.routes.push({
        framework: 'nestjs', method, path: fullPath, file,
        line: lineNumberAt(content, decoratorStart), handler,
        ...(handlerLine ? { handlerLine } : {}),
        middleware: [...classGuards, ...methodGuards],
        guards: [...classGuards, ...methodGuards],
        input: inputFromSignature(handlerSignature),
        extraction: 'ast',
      })
    }
  }
  return true
}

function decoratorGuards(text: string): string[] {
  const guards: string[] = []
  for (const match of text.matchAll(/@(UseGuards|Roles|Permissions|PreAuthorize|Secured|RolesAllowed|Authorize)\s*\(((?:[^()]|\([^()]*\))*)\)/g)) {
    guards.push(`${match[1]}(${match[2].replace(/\s+/g, '')})`)
  }
  return [...new Set(guards)]
}

function extractNext(file: string, content: string, out: Extraction): boolean {
  const normalized = file.replaceAll('\\', '/')
  const appRoute = /(?:^|\/)(?:src\/)?app\/(.+)\/route\.(?:[jt]sx?)$/.exec(normalized)
  const pagesRoute = /(?:^|\/)(?:src\/)?pages\/(api\/.+)\.(?:[jt]sx?)$/.exec(normalized)
  if (!appRoute && !pagesRoute) return false

  const routePath = `/${(appRoute?.[1] ?? pagesRoute?.[1] ?? '').replace(/\[\[?\.\.\.([^\]]+)\]\]?/g, ':$1').replace(/\[([^\]]+)\]/g, ':$1')}`
  const methods = new Map<string, number>()
  if (appRoute) {
    for (const match of content.matchAll(/export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b/g)) {
      methods.set(match[1], lineNumberAt(content, match.index))
    }
    if (!methods.size) methods.set('ANY', 1)
  } else {
    for (const match of content.matchAll(/req\.method\s*===?\s*['"](\w+)['"]/g)) {
      methods.set(match[1].toUpperCase(), lineNumberAt(content, match.index))
    }
    if (!methods.size) methods.set('ANY', 1)
  }
  const middleware: string[] = []
  for (const match of content.matchAll(/with(?:Auth|Admin|User|Role|Permission)\s*\(/g)) middleware.push(match[0].replace('(', ''))
  for (const [method, line] of methods) {
    out.routes.push({
      framework: 'nextjs', method, path: routePath, file, line,
      handler: appRoute ? method : 'default',
      middleware: [...middleware], guards: guardsFromMiddleware(middleware),
      input: valueOrFallback(routePath), extraction: 'ast',
    })
  }
  return true
}

function extractPythonRoutes(file: string, content: string, out: Extraction): boolean {
  const hasFastApi = /(?:FastAPI|APIRouter)\s*\(/.test(content)
  const hasFlask = /(?:Flask|Blueprint)\s*\(/.test(content)
  if (!hasFastApi && !hasFlask) return false

  const routerVars = new Map<string, RouterDef>()
  const addRouter = (name: string, prefix: string, middleware: string[], framework: 'fastapi' | 'flask') => {
    const key = `${file}#${framework}:${name}`
    const router: RouterDef = { key, name, file, prefix, middleware }
    routerVars.set(name, router)
    out.routers.push(router)
  }

  if (hasFastApi) {
    for (const match of content.matchAll(/([A-Za-z_]\w*)\s*=\s*(?:fastapi\s*\.\s*)?(?:FastAPI|APIRouter)\s*\(/g)) {
      const open = content.indexOf('(', match.index)
      const { args } = argsAtCall(content, open)
      const prefix = args.map(a => /prefix\s*=\s*(['"])(.*?)\1/.exec(a)?.[2]).find(Boolean) ?? ''
      const deps = args.map(a => /dependencies\s*=\s*\[([^\]]*)\]/.exec(a)?.[1]).find(Boolean)
      const middleware = deps ? [...deps.matchAll(/Depends\s*\(\s*([\w.]+)/g)].map(m => `Depends(${m[1]})`) : []
      addRouter(match[1], prefix, middleware, 'fastapi')
    }
    for (const match of content.matchAll(/@\s*([A-Za-z_]\w*)\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(/g)) {
      const router = routerVars.get(match[1])
      if (!router) continue
      const open = content.indexOf('(', match.index)
      const { args } = argsAtCall(content, open)
      const routePath = stringListValue(args[0])[0]
      if (routePath === null) continue
      const deps = args.map(a => /dependencies\s*=\s*\[([^\]]*)\]/.exec(a)?.[1]).find(Boolean)
      const routeMiddleware = deps ? [...deps.matchAll(/Depends\s*\(\s*([\w.]+)/g)].map(m => `Depends(${m[1]})`) : []
      const afterStart = open
      const defMatch = /(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/.exec(content.slice(afterStart, afterStart + 1200))
      const defOpen = defMatch ? afterStart + (defMatch.index ?? 0) + defMatch[0].length - 1 : -1
      const signature = defMatch && defOpen >= 0 ? argsAtCall(content, defOpen).args.join(', ') : ''
      out.routes.push({
        framework: 'fastapi', method: match[2].toUpperCase(), path: routePath, file,
        line: lineNumberAt(content, match.index), handler: defMatch?.[1] ?? 'anonymous',
        routerKey: router.key,
        middleware: [...router.middleware, ...routeMiddleware],
        guards: guardsFromMiddleware([...router.middleware, ...routeMiddleware]),
        input: defMatch ? inputFromSignature(signature) : valueOrFallback(routePath),
        extraction: 'ast',
      })
    }
    for (const match of content.matchAll(/include_router\s*\(/g)) {
      const open = content.indexOf('(', match.index)
      const { args } = argsAtCall(content, open)
      const childToken = args[0]?.trim() ?? ''
      const childName = childToken.split('.').pop() ?? childToken
      const prefix = args.map(a => /prefix\s*=\s*(['"])(.*?)\1/.exec(a)?.[2]).find(Boolean) ?? ''
      const parent = routerVars.get('app') ?? routerVars.get('application') ?? [...routerVars.values()].find(r => r.name === 'app')
      out.mounts.push({
        ...(parent ? { parentKey: parent.key } : {}),
        parentFile: file, parentName: parent?.name ?? 'app',
        ...(routerVars.get(childName) ? { childKey: routerVars.get(childName)!.key } : {}),
        childName, childFile: file, prefix, middleware: [],
        file, line: lineNumberAt(content, match.index),
      })
    }
  }

  if (hasFlask) {
    for (const match of content.matchAll(/([A-Za-z_]\w*)\s*=\s*(?:flask\s*\.\s*)?(?:Flask|Blueprint)\s*\(/g)) {
      const open = content.indexOf('(', match.index)
      const { args } = argsAtCall(content, open)
      const prefix = args.map(a => /url_prefix\s*=\s*(['"])(.*?)\1/.exec(a)?.[2]).find(Boolean) ?? ''
      addRouter(match[1], prefix, [], 'flask')
    }
    for (const match of content.matchAll(/@\s*([A-Za-z_]\w*)\s*\.\s*(get|post|put|patch|delete|head|options|route)\s*\(/g)) {
      const router = routerVars.get(match[1])
      if (!router) continue
      const open = content.indexOf('(', match.index)
      const { args } = argsAtCall(content, open)
      const routePath = stringListValue(args[0])[0]
      if (routePath === null) continue
      const methodsArg = args.map(a => /methods\s*=\s*\[([^\]]*)\]/.exec(a)?.[1]).find(Boolean)
      const methods = methodsArg ? stringListValue(`[${methodsArg}]`).map(m => m.toUpperCase()) : [match[2].toUpperCase()]
      const defMatch = /(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/.exec(content.slice(open, open + 800))
      const defOpen = defMatch ? open + (defMatch.index ?? 0) + defMatch[0].length - 1 : -1
      const signature = defMatch && defOpen >= 0 ? argsAtCall(content, defOpen).args.join(', ') : ''
      for (const method of methods) {
        out.routes.push({
          framework: 'flask', method: method === 'ROUTE' ? 'ANY' : method, path: routePath, file,
          line: lineNumberAt(content, match.index), handler: defMatch?.[1] ?? 'anonymous',
          routerKey: router.key, middleware: [...router.middleware],
          guards: guardsFromMiddleware(router.middleware),
          input: defMatch ? inputFromSignature(signature) : valueOrFallback(routePath),
          extraction: 'ast',
        })
      }
    }
    for (const match of content.matchAll(/register_blueprint\s*\(/g)) {
      const open = content.indexOf('(', match.index)
      const { args } = argsAtCall(content, open)
      const childName = (args[0] ?? '').trim().split('.').pop() ?? ''
      const prefix = args.map(a => /url_prefix\s*=\s*(['"])(.*?)\1/.exec(a)?.[2]).find(Boolean) ?? ''
      const parent = [...routerVars.values()].find(r => r.name === 'app')
      out.mounts.push({
        ...(parent ? { parentKey: parent.key } : {}),
        parentFile: file, parentName: parent?.name ?? 'app',
        ...(routerVars.get(childName) ? { childKey: routerVars.get(childName)!.key } : {}),
        childName, childFile: file, prefix, middleware: [],
        file, line: lineNumberAt(content, match.index),
      })
    }
  }
  return true
}

function extractDjango(file: string, content: string, out: Extraction): boolean {
  if (!/urlpatterns\s*=/.test(content)) return false
  const moduleName = file.replaceAll('\\', '/').replace(/\.py$/, '').replaceAll('/', '.')
  const moduleKey = `${file}#django:${moduleName}`
  out.routers.push({ key: moduleKey, name: moduleName, file, prefix: '', middleware: [] })

  const viewGuards = new Map<string, string[]>()
  for (const match of content.matchAll(/((?:^|\n)\s*@[^\n]+\n)+\s*def\s+([A-Za-z_]\w*)/g)) {
    const guards = [...match[1].matchAll(/@(\w+)\s*(?:\(([^)]*)\))?/g)].map(m => `${m[1]}(${m[2] ?? ''})`)
    viewGuards.set(match[2], guards.filter(g => AUTH_GUARD_RE.test(g) || ADMIN_GUARD_RE.test(g) || TENANT_GUARD_RE.test(g)))
  }

  for (const match of content.matchAll(/\b(?:path|re_path)\s*\(/g)) {
    const open = content.indexOf('(', match.index)
    const { args } = argsAtCall(content, open)
    const routePath = stringLiteralValue(args[0])
    if (routePath === null) continue
    const viewToken = args[1] ?? ''
    const line = lineNumberAt(content, match.index)
    const includeMatch = /include\s*\(\s*['"]([^'"]+)['"]/.exec(viewToken)
    if (includeMatch) {
      const target = includeMatch[1]
      out.mounts.push({
        parentKey: moduleKey, parentFile: file, parentName: moduleName,
        childName: target,
        childFile: target.includes('.') ? `${target.replaceAll('.', '/')}.py` : `${target.replace(/\/$/, '')}/urls.py`,
        prefix: routePath, middleware: [], file, line,
      })
      continue
    }
    const viewName = handlerNameFromToken(viewToken.replace(/\.as_view\s*\([^)]*\)/, ''))
    const guards = viewGuards.get(viewName) ?? []
    const methods = [...viewToken.matchAll(/['"](GET|POST|PUT|PATCH|DELETE)['"]/g)].map(m => m[1])
    const djangoPath = routePath.replace(/<(?:\w+:)?(\w+)>/g, ':$1').replace(/\(\?P<(\w+)>[^)]+\)/g, ':$1')
    out.routes.push({
      framework: 'django', method: methods[0] ?? 'ANY', path: djangoPath, file, line,
      handler: viewName, routerKey: moduleKey, middleware: [], guards,
      input: valueOrFallback(djangoPath), extraction: 'ast',
    })
  }
  for (const match of content.matchAll(/router\s*\.\s*register\s*\(\s*(['"])([^'"]+)\1/g)) {
    const base = match[2].startsWith('/') ? match[2] : `/${match[2]}`
    const line = lineNumberAt(content, match.index)
    const crud: Array<[string, string, string]> = [
      ['GET', base, 'list'], ['POST', base, 'create'],
      ['GET', `${base}/:pk`, 'retrieve'], ['PUT', `${base}/:pk`, 'update'],
      ['PATCH', `${base}/:pk`, 'partial_update'], ['DELETE', `${base}/:pk`, 'destroy'],
    ]
    for (const [method, routePath, action] of crud) {
      out.routes.push({
        framework: 'django', method, path: routePath, file, line, handler: `${base.slice(1)}_${action}`,
        routerKey: moduleKey, middleware: [], guards: [],
        input: valueOrFallback(routePath), extraction: 'ast',
      })
    }
  }
  return true
}

function extractSpring(file: string, content: string, out: Extraction): boolean {
  if (!/@(?:RestController|Controller|RequestMapping|GetMapping|PostMapping)\b/.test(content)) return false
  for (const match of content.matchAll(/((?:@[\w.]+(?:\s*\((?:[^()]|\([^()]*\))*\))?\s*)+)(?:public\s+)?(?:final\s+)?class\s+([A-Za-z_]\w*)/g)) {
    const classDecorators = match[1]
    const classBase = /@RequestMapping\s*\(([^)]*)\)/.exec(classDecorators)?.[1] ?? ''
    const basePath = stringListValue(splitTopLevel(classBase, 0, classBase.length).find(a => !/method\s*=/.test(a)) ?? '')[0] ?? ''
    const classGuards = decoratorGuards(classDecorators)
    const bodyOpen = content.indexOf('{', match.index + match[0].length)
    if (bodyOpen < 0) continue
    const bodyClose = findMatching(content, bodyOpen)
    if (bodyClose < 0) continue
    const body = content.slice(bodyOpen + 1, bodyClose)

    for (const routeMatch of body.matchAll(/@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(([^)]*)\)/g)) {
      const routeArgs = splitTopLevel(routeMatch[2], 0, routeMatch[2].length)
      const pathToken = routeArgs.find(a => !/method\s*=/.test(a)) ?? ''
      const routePath = stringListValue(pathToken)[0] ?? ''
      let methods: string[] = []
      const explicit = /RequestMethod\.(\w+)/.exec(routeMatch[2])?.[1]
      if (explicit) methods = [explicit.toUpperCase()]
      else if (routeMatch[1] !== 'Request') methods = [routeMatch[1].toUpperCase()]
      else methods = ['ANY']
      const decoratorStart = bodyOpen + 1 + routeMatch.index
      const region = content.slice(decoratorStart, Math.min(content.length, decoratorStart + 1500))
      const javaHandlers = scanJavaMethodHeaders(region, true)
      let handler = 'anonymous'
      let signature = ''
      let methodDecorators = ''
      if (javaHandlers.length > 0) {
        const hm = javaHandlers[0]
        handler = hm.name
        const signatureOpen = decoratorStart + hm.openParen
        signature = argsAtCall(content, signatureOpen).args.join(', ')
        methodDecorators = region.slice(0, hm.index)
      }
      const methodGuards = decoratorGuards(methodDecorators)
      const input = inputFromSignature(signature)
      input.params.push(...routeParamNames(routePath))
      for (const method of methods) {
        out.routes.push({
          framework: 'spring', method, path: joinPaths(joinPaths('', basePath), routePath), file,
          line: lineNumberAt(content, decoratorStart), handler,
          middleware: [...classGuards, ...methodGuards],
          guards: [...classGuards, ...methodGuards],
          input: { ...input, params: [...new Set(input.params)] },
          extraction: 'ast',
        })
      }
    }
  }
  return true
}

function extractGin(file: string, content: string, out: Extraction): boolean {
  if (!/\bgin\.(?:Default|New)\s*\(/.test(content)) return false
  interface Event { index: number; kind: 'group' | 'route'; name: string; method?: string; path?: string; args?: string[] }
  const events: Event[] = []
  for (const match of content.matchAll(/([A-Za-z_]\w*)\s*:?=\s*([A-Za-z_]\w*)\s*\.\s*Group\s*\(\s*(['"])([^'"]+)\3/g)) {
    events.push({ index: match.index, kind: 'group', name: match[1], path: match[4], args: [match[2]] })
  }
  for (const match of content.matchAll(/([A-Za-z_]\w*)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|Any)\s*\(\s*(['"])([^'"]+)\3\s*,/g)) {
    const open = content.indexOf('(', match.index)
    const { args } = argsAtCall(content, open)
    events.push({ index: match.index, kind: 'route', name: match[1], method: match[2], path: match[4], args })
  }
  events.sort((a, b) => a.index - b.index)
  const prefixes = new Map<string, string>()
  for (const event of events) {
    if (event.kind === 'group') {
      const parent = event.args?.[0] ?? ''
      prefixes.set(event.name, joinPaths(prefixes.get(parent) ?? '', event.path ?? ''))
      continue
    }
    const routeArgs = event.args ?? []
    const middleware = flattenMiddlewareTokens(routeArgs.slice(1, -1))
    const handler = handlerNameFromToken(routeArgs[routeArgs.length - 1] ?? 'anonymous')
    const method = event.method === 'Any' ? 'ANY' : (event.method ?? 'ANY')
    const fullPath = joinPaths(prefixes.get(event.name) ?? '', event.path ?? '')
    out.routes.push({
      framework: 'gin', method, path: fullPath, file, line: lineNumberAt(content, event.index), handler,
      middleware, guards: guardsFromMiddleware(middleware),
      input: valueOrFallback(fullPath), extraction: 'ast',
    })
  }
  return true
}

function extractChi(file: string, content: string, out: Extraction): boolean {
  if (!/chi\.(?:NewRouter|Router)/.test(content)) return false
  const prefixes = new Map<string, string>()

  const parseBlock = (start: number, end: number, prefix: string, depth: number) => {
    if (depth > 12) return
    for (let i = start; i < end; i += 1) {
      const rest = content.slice(i, end)
      const event = /^\s*([A-Za-z_]\w*)\s*\.\s*(Route|Mount|Group|With|Get|Post|Put|Patch|Delete|Head|Options|Handle|Any)\s*\(/.exec(rest)
      if (!event) continue
      const callIndex = i + event[0].length - 1
      const { args, closeIndex } = argsAtCall(content, callIndex)
      if (closeIndex < 0) break
      const verb = event[2]
      if (verb === 'Route' || verb === 'Mount' || verb === 'Group') {
        const routePath = verb === 'Group' ? '' : stringListValue(args[0])[0]
        if (verb === 'Mount') {
          const child = (args[1] ?? '').trim()
          if (routePath !== null && child) prefixes.set(child, joinPaths(prefix, routePath))
        } else if (routePath !== null) {
          const bodyOpen = content.indexOf('{', callIndex)
          if (bodyOpen > 0) {
            const bodyClose = findMatching(content, bodyOpen)
            if (bodyClose > 0) {
              parseBlock(bodyOpen + 1, bodyClose, joinPaths(prefix, routePath), depth + 1)
              i = bodyClose
              continue
            }
          }
        }
      } else if (verb === 'With') {
        const middleware = flattenMiddlewareTokens(args)
        let pos = closeIndex + 1
        while (pos < end) {
          const chain = /^\s*\.\s*(Get|Post|Put|Patch|Delete|Head|Options|Handle|Any)\s*\(/.exec(content.slice(pos, end))
          if (!chain) break
          const chainOpen = pos + chain[0].length - 1
          const chainArgs = argsAtCall(content, chainOpen)
          if (chainArgs.closeIndex < 0) break
          const routePath = stringListValue(chainArgs.args[0])[0]
          if (routePath !== null) {
            const handler = handlerNameFromToken(chainArgs.args[chainArgs.args.length - 1] ?? 'anonymous')
            const fullPath = joinPaths(prefix, routePath)
            out.routes.push({
              framework: 'chi', method: chain[1] === 'Any' || chain[1] === 'Handle' ? 'ANY' : chain[1].toUpperCase(),
              path: fullPath, file, line: lineNumberAt(content, i), handler,
              middleware, guards: guardsFromMiddleware(middleware),
              input: valueOrFallback(fullPath), extraction: 'ast',
            })
          }
          pos = chainArgs.closeIndex + 1
        }
        i = pos
        continue
      } else {
        const routePath = stringListValue(args[0])[0]
        if (routePath !== null) {
          const middleware = flattenMiddlewareTokens(args.slice(1, -1))
          const handler = handlerNameFromToken(args[args.length - 1] ?? 'anonymous')
          const fullPath = joinPaths(prefix, routePath)
          out.routes.push({
            framework: 'chi', method: verb === 'Handle' || verb === 'Any' ? 'ANY' : verb.toUpperCase(),
            path: fullPath, file, line: lineNumberAt(content, i), handler,
            middleware, guards: guardsFromMiddleware(middleware),
            input: valueOrFallback(fullPath), extraction: 'ast',
          })
        }
      }
      i = closeIndex
    }
  }
  parseBlock(0, content.length, '', 0)
  return true
}

function extractRails(file: string, content: string, out: Extraction): boolean {
  if (!/Rails\.application\.routes\.draw/.test(content)) return false
  const lines = content.split('\n')
  const routeDefinitions: RawRoute[] = []

  const addRoute = (method: string, routePath: string, handler: string, line: number) => {
    const normalized = routePath.startsWith('/') ? routePath : `/${routePath}`
    routeDefinitions.push({
      framework: 'rails', method, path: normalizePathTemplate(normalized), file, line, handler,
      middleware: [], guards: [], input: valueOrFallback(normalized), extraction: 'ast',
    })
  }

  const expandResources = (resourcePath: string, line: number, only?: Set<string>, prefix = '') => {
    const base = joinPaths(prefix, `/${resourcePath}`)
    const singular = resourcePath.split('/').pop() ?? resourcePath
    const actions: Array<[string, string, string, string]> = [
      ['index', 'GET', base, `${singular}#index`],
      ['create', 'POST', base, `${singular}#create`],
      ['show', 'GET', `${base}/:id`, `${singular}#show`],
      ['update', 'PATCH', `${base}/:id`, `${singular}#update`],
      ['destroy', 'DELETE', `${base}/:id`, `${singular}#destroy`],
    ]
    for (const [action, method, routePath, handler] of actions) {
      if (only && !only.has(action)) continue
      addRoute(method, routePath, handler, line)
    }
    if (!only) {
      addRoute('GET', `${base}/new`, `${singular}#new`, line)
      addRoute('GET', `${base}/:id/edit`, `${singular}#edit`, line)
    }
  }

  const walk = (start: number, end: number, prefix: string) => {
    for (let i = start; i < end; i += 1) {
      const line = lines[i]
      const indent = line.length - line.trimStart().length
      const ns = /^\s*(namespace|scope)\s+(?::([A-Za-z_]\w*)|(['"])([^'"]+)\3)(?:\s*,\s*[^d]+)?\s+do\b/.exec(line)
      if (ns) {
        const segment = ns[2] ?? ns[4]
        let blockEnd = end
        for (let j = i + 1; j < end; j += 1) {
          const l = lines[j]
          if (/^\s*end\b/.test(l) && l.length - l.trimStart().length <= indent) {
            blockEnd = j
            break
          }
        }
        const isModuleScope = /scope\s+module:/.test(line)
        walk(i + 1, blockEnd, isModuleScope ? prefix : joinPaths(prefix, segment))
        i = blockEnd
        continue
      }
      const resources = /^\s*resources\s+:(\w+)(?:.*only:\s*\[([^\]]*)\])?/.exec(line)
      if (resources) {
        const only = resources[2]
          ? new Set([...resources[2].matchAll(/:(\w+)/g)].map(m => m[1]))
          : undefined
        expandResources(resources[1], i + 1, only, prefix)
        continue
      }
      const resource = /^\s*resource\s+:(\w+)/.exec(line)
      if (resource) {
        const base = joinPaths(prefix, `/${resource[1]}`)
        addRoute('GET', base, `${resource[1]}#show`, i + 1)
        addRoute('POST', base, `${resource[1]}#create`, i + 1)
        addRoute('PATCH', base, `${resource[1]}#update`, i + 1)
        addRoute('DELETE', base, `${resource[1]}#destroy`, i + 1)
        continue
      }
      const verb = /^\s*(get|post|put|patch|delete|match)\s+(['"])([^'"]+)\2(.*)$/.exec(line)
      if (verb) {
        const method = verb[1] === 'match'
          ? (/via:\s*:(\w+)/.exec(verb[4])?.[1] ?? 'ANY').toUpperCase()
          : verb[1].toUpperCase()
        const to = /to:\s*['"]([^'"]+)['"]/.exec(verb[4])?.[1] ?? 'anonymous'
        addRoute(method, joinPaths(prefix, verb[3]), to, i + 1)
      }
    }
  }
  walk(0, lines.length, '')
  out.routes.push(...routeDefinitions)
  return true
}

function extractFile(file: string, content: string): Extraction {
  const out: Extraction = { routes: [], routers: [], mounts: [], functions: [], globalMiddleware: [], warnings: [] }
  const lang = languageOfFile(file)
  const normalized = file.replaceAll('\\', '/')
  out.functions = extractFunctions(file, content)

  if (lang === 'js') {
    if (extractNext(normalized, content, out)) return out
    if (extractNest(file, content, out)) return out
    extractExpressLike(file, content, out)
    if (/(?:^|\/)middleware\.[jt]sx?$/.test(normalized)) out.globalMiddleware.push('middleware')
    return out
  }
  if (lang === 'python') {
    extractPythonRoutes(file, content, out)
    extractDjango(file, content, out)
    return out
  }
  if (lang === 'java') {
    extractSpring(file, content, out)
    return out
  }
  if (lang === 'go') {
    extractGin(file, content, out)
    extractChi(file, content, out)
    return out
  }
  if (lang === 'ruby') {
    extractRails(file, content, out)
    return out
  }
  return out
}

// ============================================================================
// Mount resolution + graph assembly
// ============================================================================

const MAX_ROUTER_MOUNT_DEPTH = 12
const MAX_ROUTER_MOUNT_STEPS = 10_000
const MAX_MOUNT_PATH_LENGTH = 2048
const MAX_MOUNTED_ROUTES = 5000

function resolveMountedRoutes(extractions: readonly Extraction[]): { routes: ProgramRoute[]; warnings: string[] } {
  const routers = new Map<string, RouterDef>()
  const mounts: MountSpec[] = []
  const warnings: string[] = []
  for (const extraction of extractions) {
    for (const router of extraction.routers) routers.set(router.key, router)
    mounts.push(...extraction.mounts)
  }

  const byName = new Map<string, RouterDef[]>()
  const routerStems: Array<{ router: RouterDef; stem: string }> = []
  for (const router of routers.values()) {
    const list = byName.get(router.name) ?? []
    list.push(router)
    byName.set(router.name, list)
    routerStems.push({
      router,
      stem: router.file.replaceAll('\\', '/').replace(/\.(?:[cm]?[jt]sx?)$/, ''),
    })
  }
  const resolveChild = (mount: MountSpec): RouterDef | undefined => {
    if (mount.childKey && routers.has(mount.childKey)) return routers.get(mount.childKey)
    const candidates = byName.get(mount.childName) ?? []
    if (candidates.length === 1) return candidates[0]
    if (mount.childFile) {
      const target = mount.childFile.replaceAll('\\', '/')
      const inTarget = routerStems.filter(c => c.stem.endsWith(target)).map(c => c.router)
      if (inTarget.length === 1) return inTarget[0]
      const exported = inTarget.filter(c => c.exported)
      if (exported.length === 1) return exported[0]
    }
    return undefined
  }

  const mountsByParent = new Map<string, Array<{ mount: MountSpec; child: RouterDef }>>()
  const hasParent = new Set<string>()
  let cycleWarnings = 0
  let depthWarned = false
  let stepsWarned = false
  let pathWarned = false

  for (const mount of mounts) {
    const child = resolveChild(mount)
    if (!child || !mount.parentKey || !routers.has(mount.parentKey)) continue
    if (child.key === mount.parentKey) {
      if (cycleWarnings < 10) {
        warnings.push(`Skipped self-mounting router cycle on ${child.key} at ${mount.file}:${mount.line}`)
        cycleWarnings += 1
      }
      continue
    }
    const list = mountsByParent.get(mount.parentKey) ?? []
    list.push({ mount, child })
    mountsByParent.set(mount.parentKey, list)
    hasParent.add(child.key)
  }

  const bases = new Map<string, string>()
  for (const router of routers.values()) bases.set(router.key, router.prefix)
  const mountChain = new Map<string, MountSpec[]>()
  const settled = new Set<string>()
  let steps = 0

  const walk = (
    routerKey: string,
    currentBase: string,
    chain: MountSpec[],
    pathVisited: Set<string>,
    depth: number,
  ): void => {
    if (steps >= MAX_ROUTER_MOUNT_STEPS) {
      if (!stepsWarned) {
        warnings.push(`Router mount expansion capped at ${MAX_ROUTER_MOUNT_STEPS} steps`)
        stepsWarned = true
      }
      return
    }
    steps += 1
    settled.add(routerKey)
    bases.set(routerKey, currentBase)
    mountChain.set(routerKey, chain)

    if (depth >= MAX_ROUTER_MOUNT_DEPTH) {
      if (!depthWarned && (mountsByParent.get(routerKey)?.length ?? 0) > 0) {
        warnings.push(`Router mount depth capped at ${MAX_ROUTER_MOUNT_DEPTH} levels`)
        depthWarned = true
      }
      return
    }

    const children = mountsByParent.get(routerKey)
    if (!children) return
    for (const { mount, child } of children) {
      if (pathVisited.has(child.key)) {
        if (cycleWarnings < 10) {
          warnings.push(`Skipped cyclic router mount ${routerKey} -> ${child.key} at ${mount.file}:${mount.line}`)
          cycleWarnings += 1
        }
        continue
      }
      if (settled.has(child.key)) continue
      const nextBase = joinPaths(joinPaths(currentBase, mount.prefix), child.prefix)
      if (nextBase.length > MAX_MOUNT_PATH_LENGTH) {
        if (!pathWarned) {
          warnings.push(`Skipped mounted path exceeding ${MAX_MOUNT_PATH_LENGTH} chars on ${child.key}`)
          pathWarned = true
        }
        continue
      }
      pathVisited.add(child.key)
      walk(child.key, nextBase, [...chain, mount], pathVisited, depth + 1)
      pathVisited.delete(child.key)
    }
  }

  // First traverse from zero-in-degree root routers (normal apps & lassos).
  for (const router of routers.values()) {
    if (hasParent.has(router.key) || settled.has(router.key)) continue
    walk(router.key, router.prefix, [], new Set([router.key]), 0)
  }
  // Then traverse any remaining pure-cycle components without an external root.
  for (const router of routers.values()) {
    if (settled.has(router.key)) continue
    walk(router.key, router.prefix, [], new Set([router.key]), 0)
  }

  const routes: ProgramRoute[] = []
  const seen = new Set<string>()
  let routeCapWarned = false
  for (const extraction of extractions) {
    for (const raw of extraction.routes) {
      if (routes.length >= MAX_MOUNTED_ROUTES) {
        if (!routeCapWarned) {
          warnings.push(`Mounted routes capped at ${MAX_MOUNTED_ROUTES}`)
          routeCapWarned = true
        }
        break
      }
      const base = raw.routerKey ? bases.get(raw.routerKey) ?? '' : ''
      const path = raw.routerKey ? joinPaths(base, raw.path) : raw.path
      const chain = raw.routerKey ? mountChain.get(raw.routerKey) ?? [] : []
      const mountedFrom = chain.map(m => m.prefix).filter(Boolean)
      const router = raw.routerKey ? routers.get(raw.routerKey) : undefined
      const middleware = [...new Set([...(router?.middleware ?? []), ...chain.flatMap(m => m.middleware), ...raw.middleware])]
      const id = `route:${raw.method}:${path}:${raw.file}:${raw.line}`
      if (seen.has(id)) continue
      seen.add(id)
      routes.push({
        id,
        framework: raw.framework,
        method: raw.method,
        path,
        file: raw.file,
        line: raw.line,
        handler: raw.handler,
        input: { ...raw.input, params: [...new Set([...raw.input.params, ...routeParamNames(path)])] },
        middleware,
        guards: [...new Set([...raw.guards, ...guardsFromMiddleware(middleware)])],
        mountedFrom,
        extraction: raw.extraction,
      })
    }
    if (routes.length >= MAX_MOUNTED_ROUTES) break
  }
  return { routes, warnings }
}

function buildGraph(
  repo: string | undefined,
  files: ReadonlyArray<{ path: string; content: string }>,
  extractions: readonly Extraction[],
  globalMiddleware: string[],
  warnings: string[],
): ProgramGraph {
  const { routes, warnings: mountWarnings } = resolveMountedRoutes(extractions)
  const functions = extractions.flatMap(e => e.functions)
  const nodes: ProgramNode[] = []
  const edges: ProgramEdge[] = []
  const warningsOut = [...warnings, ...mountWarnings]

  const fnByFile = new Map<string, Map<string, ProgramFunction>>()
  const fnByName = new Map<string, ProgramFunction[]>()
  for (const fn of functions) {
    const perFile = fnByFile.get(fn.file) ?? new Map<string, ProgramFunction>()
    if (!perFile.has(fn.name)) perFile.set(fn.name, fn)
    fnByFile.set(fn.file, perFile)
    const list = fnByName.get(fn.name) ?? []
    list.push(fn)
    fnByName.set(fn.name, list)
  }
  const fnId = (fn: ProgramFunction) => `fn:${fn.file}:${fn.name}:${fn.line}`
  const functionNodes = new Map<ProgramFunction, ProgramNode>()
  for (const fn of functions) {
    const node: ProgramNode = {
      id: fnId(fn), kind: 'function', symbol: fn.name, file: fn.file, line: fn.line,
      endLine: fn.endLine, guards: fn.guardNames, calls: fn.calls,
    }
    functionNodes.set(fn, node)
    nodes.push(node)
  }

  const findFunction = (name: string, file: string, line?: number): ProgramFunction | undefined => {
    const sameFile = fnByFile.get(file)?.get(name)
    if (sameFile) return sameFile
    const candidates = fnByName.get(name) ?? []
    if (candidates.length === 1) return candidates[0]
    if (line !== undefined) {
      return candidates
        .filter(c => line >= c.line && line <= c.endLine)
        .sort((a, b) => a.line - b.line)[0]
    }
    return candidates.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line)[0]
  }

  for (const route of routes) {
    const handlerFn = findFunction(route.handler, route.file, route.line)
    const node: ProgramNode = {
      id: route.id, kind: 'route', symbol: route.handler, file: route.file, line: route.line,
      routePath: route.path, httpMethod: route.method, guards: route.guards, calls: [],
    }
    nodes.push(node)
    if (handlerFn) {
      edges.push({ fromId: route.id, toId: fnId(handlerFn), file: route.file, line: route.line })
    }
  }

  const contentByFile = new Map(files.map(file => [file.path, file.content]))
  const sinkNodes: ProgramNode[] = []
  for (const fn of functions) {
    const content = contentByFile.get(fn.file)
    if (content === undefined) continue
    const body = content.slice(fn.startIndex, fn.endIndex)
    for (const hit of detectSinks(body)) {
      const line = lineNumberAt(content, fn.startIndex + hit.index)
      const sink: ProgramNode = {
        id: `sink:${fn.file}:${line}:${hit.kind}:${fn.name}`, kind: 'sink', symbol: `${fn.name}:${hit.kind}`,
        file: fn.file, line, sinkKind: hit.kind, guards: [], calls: [],
      }
      sinkNodes.push(sink)
      nodes.push(sink)
      edges.push({ fromId: fnId(fn), toId: sink.id, file: fn.file, line })
    }
  }

  // Build per-file import maps so cross-file calls resolve deterministically even when
  // multiple modules export helpers with identical names (e.g., `findById`, `execute`, `save`).
  const normalizedFileByStem = new Map<string, string>()
  for (const file of files) {
    const norm = file.path.replaceAll('\\', '/')
    const stem = norm.replace(/\.(?:[cm]?[jt]sx?|py|go|java|rb)$/, '')
    normalizedFileByStem.set(stem, file.path)
    if (stem.endsWith('/index')) normalizedFileByStem.set(stem.slice(0, -6), file.path)
  }
  const importsByFile = new Map<string, Map<string, { targetFile: string; exportedName: string }>>()
  const namespaceImportsByFile = new Map<string, string[]>()
  for (const file of files) {
    const symbolMap = new Map<string, { targetFile: string; exportedName: string }>()
    const nsFiles: string[] = []
    const lang = languageOfFile(file.path)
    if (lang === 'js') {
      for (const m of file.content.matchAll(/import\s+\{([^}]+)\}\s+from\s+(['"])([^'"]+)\2/g)) {
        const stem = resolveImportTarget(file.path, m[3])
        const targetFile = stem ? normalizedFileByStem.get(stem) : undefined
        if (!targetFile) continue
        for (const spec of m[1].split(',')) {
          const clean = spec.replace(/\btype\s+/, '').trim()
          if (!clean) continue
          const [orig, alias] = clean.split(/\s+as\s+/).map(s => s.trim())
          if (orig) symbolMap.set(alias || orig, { targetFile, exportedName: orig })
        }
      }
      for (const m of file.content.matchAll(/import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+(['"])([^'"]+)\2/g)) {
        const stem = resolveImportTarget(file.path, m[3])
        const targetFile = stem ? normalizedFileByStem.get(stem) : undefined
        if (!targetFile) continue
        nsFiles.push(targetFile)
        symbolMap.set(m[1], { targetFile, exportedName: m[1] })
      }
      for (const m of file.content.matchAll(/(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\s*\(\s*(['"])([^'"]+)\2\s*\)/g)) {
        const stem = resolveImportTarget(file.path, m[3])
        const targetFile = stem ? normalizedFileByStem.get(stem) : undefined
        if (!targetFile) continue
        for (const spec of m[1].split(',')) {
          const [orig, alias] = spec.trim().split(/\s*:\s*/).map(s => s.trim())
          if (orig) symbolMap.set(alias || orig, { targetFile, exportedName: orig })
        }
      }
    } else if (lang === 'python') {
      for (const m of file.content.matchAll(/from\s+(\.{1,3}[A-Za-z0-9_.]*)\s+import\s+([^\n#]+)/g)) {
        const dots = /^\.+/.exec(m[1])?.[0].length ?? 1
        const modPath = m[1].slice(dots).replaceAll('.', '/')
        const prefix = dots === 1 ? './' : '../'.repeat(dots - 1)
        const stem = resolveImportTarget(file.path, `${prefix}${modPath}`)
        const targetFile = stem ? normalizedFileByStem.get(stem) : undefined
        if (!targetFile) continue
        for (const spec of m[2].split(',')) {
          const [orig, alias] = spec.trim().split(/\s+as\s+/).map(s => s.trim())
          if (orig) symbolMap.set(alias || orig, { targetFile, exportedName: orig })
        }
      }
    }
    if (symbolMap.size) importsByFile.set(file.path, symbolMap)
    if (nsFiles.length) namespaceImportsByFile.set(file.path, [...new Set(nsFiles)])
  }

  // Call graph edges: same-file first, then explicit import target, then namespace imports,
  // then unambiguous repo-wide matches.
  let edgeCount = 0
  for (const fn of functions) {
    const fileImports = importsByFile.get(fn.file)
    const nsFiles = namespaceImportsByFile.get(fn.file)
    for (const call of fn.calls) {
      if (edgeCount >= 8000) break
      let target = fnByFile.get(fn.file)?.get(call)
      if (!target && fileImports) {
        const imported = fileImports.get(call)
        if (imported) target = fnByFile.get(imported.targetFile)?.get(imported.exportedName)
      }
      if (!target && nsFiles) {
        for (const nsFile of nsFiles) {
          const candidate = fnByFile.get(nsFile)?.get(call)
          if (candidate) { target = candidate; break }
        }
      }
      if (!target && fnByName.get(call)?.length === 1) {
        target = fnByName.get(call)![0]
      }
      if (!target || (target.name === fn.name && target.file === fn.file)) continue
      edges.push({ fromId: fnId(fn), toId: fnId(target), file: fn.file, line: fn.line })
      edgeCount += 1
    }
  }

  const frameworks = [...new Set(routes.map(r => r.framework))]
  if (routes.some(r => r.framework === 'unknown')) warningsOut.push('Some routes were extracted with unknown framework.')
  const codeHints = deriveGraphCodeHints(files, routes)
  const staticLeads = extractStaticSecretsAndIacLeads(files, routes)
  return {
    repo,
    filesScanned: files.length,
    frameworks,
    routes,
    nodes,
    edges,
    globalMiddleware,
    warnings: warningsOut,
    ...(Object.keys(codeHints).length ? { codeHints } : {}),
    ...(staticLeads.length ? { staticLeads } : {}),
  }
}

/** Extract the cross-framework Program Graph from a set of repository sources or a StaticWorkspaceSnapshot. */
export function extractProgramGraph(input: {
  files?: ReadonlyArray<{ path: string; content: string }>
  repo?: string
  maxFileBytes?: number
  staticSnapshot?: StaticWorkspaceSnapshot
}): ProgramGraph {
  if (input.staticSnapshot && (!input.files || input.files.length === 0)) {
    const snap = input.staticSnapshot
    const repoPrefix = input.repo && snap.files.some(f => f.startsWith(`${input.repo}/`))
      ? `${input.repo}/`
      : ''
    if (input.maxFileBytes === undefined && !repoPrefix) {
      if (!input.repo || input.repo === snap.programGraph.repo) {
        return snap.programGraph
      }
      return { ...snap.programGraph, repo: input.repo }
    }
    const maxBytes = Math.max(4096, input.maxFileBytes ?? 1024 * 1024)
    const files: Array<{ path: string; content: string }> = []
    for (const [path, content] of snap.sourceByPath.entries()) {
      if (repoPrefix && !path.startsWith(repoPrefix)) continue
      if (!/\.(?:[cm]?[jt]sx?|py|java|kt|go|rb)$/i.test(path)) continue
      if (content.length <= maxBytes) files.push({ path, content })
    }
    const warnings: string[] = []
    const extractions: Extraction[] = []
    const globalMiddleware: string[] = []
    for (const file of files) {
      const extraction = extractFile(file.path, file.content)
      extractions.push(extraction)
      globalMiddleware.push(...extraction.globalMiddleware)
      warnings.push(...extraction.warnings)
    }
    return buildGraph(input.repo, files, extractions, [...new Set(globalMiddleware)], warnings)
  }
  const maxBytes = Math.max(4096, input.maxFileBytes ?? 1024 * 1024)
  const files = (input.files ?? []).filter(file => file.content.length <= maxBytes)
  const warnings: string[] = []
  const extractions: Extraction[] = []
  const globalMiddleware: string[] = []
  for (const file of files) {
    const extraction = extractFile(file.path, file.content)
    extractions.push(extraction)
    globalMiddleware.push(...extraction.globalMiddleware)
    warnings.push(...extraction.warnings)
  }
  return buildGraph(input.repo, files, extractions, [...new Set(globalMiddleware)], warnings)
}

// ============================================================================
// Reverse call graph, route/sink paths, code-to-runtime hypotheses
// ============================================================================

export interface ReversePathOptions {
  /** Hop budget for route -> controller -> service -> repository chains (default 7). */
  maxDepth?: number
  maxPaths?: number
}

export function resolveRouteSinkPaths(graph: ProgramGraph, options: ReversePathOptions = {}): RouteSinkPath[] {
  const maxDepth = Math.max(1, Math.min(options.maxDepth ?? 7, 16))
  const maxPaths = Math.max(1, Math.min(options.maxPaths ?? 500, 5000))
  const nodeById = new Map(graph.nodes.map(n => [n.id, n]))
  const incoming = new Map<string, ProgramEdge[]>()
  for (const edge of graph.edges) {
    const list = incoming.get(edge.toId) ?? []
    list.push(edge)
    incoming.set(edge.toId, list)
  }
  const results: RouteSinkPath[] = []
  for (const sink of graph.nodes.filter(n => n.kind === 'sink')) {
    const walk = (current: ProgramNode, chain: ProgramNode[], visited: Set<string>) => {
      if (results.length >= maxPaths) return
      if (current.kind === 'route') {
        const route = graph.routes.find(r => r.id === current.id)
        if (!route) return
        const ordered = [...chain].reverse()
        const key = `${route.id}:${sink.id}`
        if (results.some(existing => `${existing.routeId}:${existing.sinkId}` === key)) return
        results.push({
          routeId: route.id,
          route,
          sinkId: sink.id,
          sinkKind: sink.sinkKind ?? 'other',
          sinkFile: sink.file,
          sinkLine: sink.line,
          chain: ordered.map(node => ({ id: node.id, kind: node.kind, symbol: node.symbol, file: node.file, line: node.line })),
          hops: ordered.length - 1,
          dominatingGuards: route.guards,
        })
        return
      }
      if (chain.length > maxDepth + 1) return
      for (const edge of incoming.get(current.id) ?? []) {
        const caller = nodeById.get(edge.fromId)
        if (!caller || visited.has(caller.id)) continue
        visited.add(caller.id)
        chain.push(caller)
        walk(caller, chain, visited)
        chain.pop()
        visited.delete(caller.id)
      }
    }
    walk(sink, [sink], new Set([sink.id]))
  }
  return results
}

export interface ResolvedRouteLocation {
  route: ProgramRoute
  chain: Array<{ symbol: string; file: string; line: number }>
  depth: number
  matchedBy: 'range' | 'nearest' | 'reverse'
}

/** Map a `file:line` sink/function location back to its HTTP route through up to maxDepth hops. */
export function resolveRouteForLocation(
  graph: ProgramGraph,
  location: { file: string; line: number },
  options: ReversePathOptions = {},
): ResolvedRouteLocation | null {
  const maxDepth = Math.max(1, Math.min(options.maxDepth ?? 7, 16))
  const candidates = graph.nodes.filter(node =>
    node.file === location.file &&
    node.kind !== 'route' &&
    location.line >= node.line &&
    location.line <= (node.endLine ?? node.line),
  )
  const start = candidates.sort((a, b) => (a.kind === 'sink' ? -1 : 1) - (b.kind === 'sink' ? -1 : 1) || b.line - a.line)[0]
    ?? graph.nodes.filter(node => node.file === location.file && node.line <= location.line).sort((a, b) => b.line - a.line)[0]
  if (!start) return null
  const nodeById = new Map(graph.nodes.map(n => [n.id, n]))
  const incoming = new Map<string, ProgramEdge[]>()
  for (const edge of graph.edges) {
    const list = incoming.get(edge.toId) ?? []
    list.push(edge)
    incoming.set(edge.toId, list)
  }
  let best: ResolvedRouteLocation | null = null
  const walk = (current: ProgramNode, chain: ProgramNode[], visited: Set<string>) => {
    if (best && chain.length >= best.depth) return
    if (current.kind === 'route') {
      const route = graph.routes.find(r => r.id === current.id)
      if (!route) return
      const ordered = [...chain, current].reverse()
      best = {
        route,
        chain: ordered.map(node => ({ symbol: node.symbol, file: node.file, line: node.line })),
        depth: Math.max(0, chain.length - 1),
        matchedBy: start.kind === 'route' ? 'range' : 'reverse',
      }
      return
    }
    if (chain.length > maxDepth) return
    for (const edge of incoming.get(current.id) ?? []) {
      const caller = nodeById.get(edge.fromId)
      if (!caller || visited.has(caller.id)) continue
      visited.add(caller.id)
      walk(caller, [...chain, caller], visited)
      visited.delete(caller.id)
    }
  }
  walk(start, [start], new Set([start.id]))
  if (best) return best
  // Nearest preceding route in the same file is the documented fallback.
  const sameFile = graph.routes.filter(r => r.file === location.file && r.line <= location.line).sort((a, b) => b.line - a.line)
  return sameFile[0] ? { route: sameFile[0], chain: [{ symbol: sameFile[0].handler, file: sameFile[0].file, line: sameFile[0].line }], depth: 0, matchedBy: 'nearest' } : null
}

// ----------------------------------------------------------------------------
// Commit-diff mining (pure parser over pre-fetched `git show` output)
// ----------------------------------------------------------------------------

export interface CommitDiffLine {
  line: number
  change: 'added' | 'removed'
  snippet: string
  sinkKinds: ProgramSinkKind[]
}

export interface CommitDiffSignal {
  sha: string
  subject: string
  committedAt?: string
  file: string
  change: 'added' | 'removed' | 'modified'
  sinkKinds: ProgramSinkKind[]
  routeTouched: boolean
  authMiddlewareTouched: boolean
  securityRelevant: boolean
  reasons: string[]
  lines: CommitDiffLine[]
}

export interface CommitDiffInput {
  sha: string
  subject: string
  committedAt?: string
  diff: string
}

const ROUTE_DIFF_RE = /(?:\.\s*(?:get|post|put|patch|delete|route|use)\s*\(|@(?:Get|Post|Put|Patch|Delete|Request)Mapping|@(?:Router|app)\.(?:get|post|route)|\b(?:path|re_path)\s*\(|\bresources\s+:|(?:GET|POST|PUT|PATCH|DELETE)\s+["'`]\/)/i

export function mineSecurityRelevantCommitDiffs(
  commits: readonly CommitDiffInput[],
  options: { maxSignals?: number; maxLinesPerFile?: number } = {},
): CommitDiffSignal[] {
  const maxSignals = Math.max(1, Math.min(options.maxSignals ?? 200, 2000))
  const maxLines = Math.max(1, Math.min(options.maxLinesPerFile ?? 20, 200))
  const out: CommitDiffSignal[] = []
  const seen = new Set<string>()

  for (const commit of commits) {
    let currentFile: string | null = null
    let newLine = 0
    let removedLine = 0
    let signal: CommitDiffSignal | null = null
    const flush = () => {
      if (!signal) return
      const key = `${signal.sha}:${signal.file}`
      if (!seen.has(key)) {
        seen.add(key)
        out.push(signal)
      }
      signal = null
    }
    for (const raw of commit.diff.split('\n')) {
      if (raw.startsWith('diff --git ')) {
        flush()
        currentFile = null
        continue
      }
      if (raw.startsWith('+++ b/')) {
        currentFile = raw.slice(6).trim()
        continue
      }
      if (raw.startsWith('--- a/')) continue
      const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw)
      if (hunk) {
        removedLine = Number(hunk[1])
        newLine = Number(hunk[2])
        continue
      }
      if (!currentFile) continue
      if (raw.startsWith('+') && !raw.startsWith('+++')) {
        if (!signal) {
          signal = {
            sha: commit.sha, subject: commit.subject, ...(commit.committedAt ? { committedAt: commit.committedAt } : {}),
            file: currentFile, change: 'added', sinkKinds: [], routeTouched: false,
            authMiddlewareTouched: false, securityRelevant: false, reasons: [], lines: [],
          }
        }
        const body = raw.slice(1)
        const sinks = detectSinks(body).map(hit => hit.kind)
        if (sinks.length && signal.lines.length < maxLines) {
          signal.lines.push({ line: newLine, change: 'added', snippet: body.trim().slice(0, 240), sinkKinds: sinks })
        }
        for (const kind of sinks) if (!signal.sinkKinds.includes(kind)) signal.sinkKinds.push(kind)
        if (ROUTE_DIFF_RE.test(body)) signal.routeTouched = true
        if (AUTH_GUARD_RE.test(body) || ADMIN_GUARD_RE.test(body) || TENANT_GUARD_RE.test(body)) signal.authMiddlewareTouched = true
        newLine += 1
        continue
      }
      if (raw.startsWith('-') && !raw.startsWith('---')) {
        if (!signal) {
          signal = {
            sha: commit.sha, subject: commit.subject, ...(commit.committedAt ? { committedAt: commit.committedAt } : {}),
            file: currentFile, change: 'removed', sinkKinds: [], routeTouched: false,
            authMiddlewareTouched: false, securityRelevant: false, reasons: [], lines: [],
          }
        }
        const body = raw.slice(1)
        const sinks = detectSinks(body).map(hit => hit.kind)
        if (sinks.length && signal.lines.length < maxLines) {
          signal.lines.push({ line: removedLine, change: 'removed', snippet: body.trim().slice(0, 240), sinkKinds: sinks })
        }
        for (const kind of sinks) if (!signal.sinkKinds.includes(kind)) signal.sinkKinds.push(kind)
        if (ROUTE_DIFF_RE.test(body)) signal.routeTouched = true
        if (AUTH_GUARD_RE.test(body) || ADMIN_GUARD_RE.test(body) || TENANT_GUARD_RE.test(body)) signal.authMiddlewareTouched = true
        removedLine += 1
        continue
      }
      if (raw.startsWith(' ')) {
        newLine += 1
        removedLine += 1
      }
    }
    flush()
    if (out.length >= maxSignals) break
  }

  for (const signal of out) {
    const reasons: string[] = []
    if (signal.sinkKinds.length) reasons.push(`touches sink(s): ${signal.sinkKinds.join(', ')}`)
    if (signal.routeTouched) reasons.push('touches route declaration')
    if (signal.authMiddlewareTouched) reasons.push('touches auth/RBAC/tenant guard')
    signal.reasons = reasons
    signal.securityRelevant = reasons.length > 0 && (signal.sinkKinds.length > 0 || signal.authMiddlewareTouched)
    if (signal.lines.some(line => line.change === 'removed') && signal.lines.every(line => line.change === 'removed')) signal.change = 'removed'
    else if (signal.lines.some(line => line.change === 'added') && signal.lines.some(line => line.change === 'removed')) signal.change = 'modified'
  }
  return out.filter(signal => signal.securityRelevant)
}

export function deriveCodeToRuntimeHypotheses(
  graph: ProgramGraph,
  options: ReversePathOptions & { recentDiffSignals?: readonly CommitDiffSignal[] } = {},
): CodeToRuntimeHypothesis[] {
  const maxDepth = options.maxDepth ?? 7
  const hypotheses: CodeToRuntimeHypothesis[] = []
  const seen = new Set<string>()
  const push = (hypothesis: CodeToRuntimeHypothesis) => {
    if (seen.has(hypothesis.id)) return
    seen.add(hypothesis.id)
    hypotheses.push(hypothesis)
  }
  const guardIndex = buildSiblingGuardIndex(graph)

  for (const route of graph.routes) {
    const adminPath = /\/(?:admin|internal|manage|management|backoffice|staff|console|superuser)(?:\/|$)/i.test(route.path)
    const adminHandler = /(?:admin|backoffice|superuser|staff)/i.test(route.handler)
    const hasAdminGuard = route.guards.some(guard => ADMIN_GUARD_RE.test(guard))
    const guardDiffEvidence = guardDiffsForRoute(route, guardIndex)
      .map(diff => `missing_guard=${diff.guard} ${diff.symbol}@${diff.at} (sibling ${diff.sibling})`)
    if ((adminPath || adminHandler) && !hasAdminGuard) {
      push({
        id: `hyp:admin:${route.id}`, kind: 'admin_route_missing_admin_guard', severity: 'high', confidence: adminPath ? 0.82 : 0.68,
        framework: route.framework, method: route.method, path: route.path, file: route.file, line: route.line,
        routeId: route.id, rationale: `Privileged route ${route.method} ${route.path} has no admin/RBAC middleware in its mounted chain.`,
        evidence: [`guards=[${route.guards.join(', ')}]`, `middleware=[${route.middleware.join(', ')}]`, ...guardDiffEvidence],
        probeClass: 'auth_bypass',
      })
    }
    const tenantParam = route.input.params.some(name => /^(?:id|pk|.*_id|.*Id)$/.test(name))
    const mutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(route.method)
    const hasTenantGuard = route.guards.some(guard => TENANT_GUARD_RE.test(guard))
    if (tenantParam && mutating && !hasTenantGuard) {
      push({
        id: `hyp:tenant:${route.id}`, kind: 'tenant_param_without_scope', severity: 'high', confidence: 0.7,
        framework: route.framework, method: route.method, path: route.path, file: route.file, line: route.line,
        routeId: route.id, rationale: `Mutating ${route.method} ${route.path} reads an object identifier (${route.input.params.join(', ')}) without a tenant/ownership guard.`,
        evidence: [`params=[${route.input.params.join(', ')}]`, `guards=[${route.guards.join(', ')}]`, ...guardDiffEvidence],
        probeClass: 'bola_bfla',
      })
    }
  }

  for (const path of resolveRouteSinkPaths(graph, { maxDepth, maxPaths: options.maxPaths ?? 500 })) {
    const noAuth = path.dominatingGuards.length === 0
    if (!noAuth) continue
    const severity = path.sinkKind === 'db_query' || path.sinkKind === 'command' ? 'critical'
      : path.sinkKind === 'outbound_fetch' || path.sinkKind === 'template' || path.sinkKind === 'file' ? 'high' : 'medium'
    push({
      id: `hyp:sink:${path.routeId}:${path.sinkId}`, kind: 'unauthenticated_sink', severity,
      confidence: 0.62, framework: path.route.framework, method: path.route.method, path: path.route.path,
      file: path.sinkFile, line: path.sinkLine, sinkKind: path.sinkKind, routeId: path.routeId,
      rationale: `${path.sinkKind} sink at ${path.sinkFile}:${path.sinkLine} is reachable from ${path.route.method} ${path.route.path} (${path.hops} hops) with no dominating auth guard.`,
      evidence: path.chain.map(hop => `${hop.symbol} @ ${hop.file}:${hop.line}`),
      probeClass: path.sinkKind === 'db_query' || path.sinkKind === 'command' ? 'injection'
        : path.sinkKind === 'outbound_fetch' ? 'ssrf' : 'code_review',
    })
  }

  for (const signal of options.recentDiffSignals ?? []) {
    if (!signal.securityRelevant) continue
    const resolved = resolveRouteForLocation(graph, { file: signal.file, line: signal.lines[0]?.line ?? 1 }, { maxDepth })
    const sinkKind = signal.sinkKinds[0]
    push({
      id: `hyp:diff:${signal.sha}:${signal.file}`,
      kind: 'recent_diff_touches_sink',
      severity: sinkKind === 'db_query' || sinkKind === 'command' ? 'high' : 'medium',
      confidence: 0.58,
      framework: resolved?.route.framework ?? 'unknown',
      ...(resolved ? { method: resolved.route.method, path: resolved.route.path, routeId: resolved.route.id } : {}),
      file: signal.file,
      line: signal.lines[0]?.line ?? 1,
      ...(sinkKind ? { sinkKind } : {}),
      rationale: `Recent commit ${signal.sha.slice(0, 12)} (${signal.subject}) ${signal.change} ${signal.file} touching ${signal.reasons.join('; ')}.`,
      evidence: signal.lines.slice(0, 5).map(line => `${line.change} ${line.line}: ${line.snippet}`),
      probeClass: sinkKind === 'db_query' || sinkKind === 'command' ? 'injection'
        : sinkKind === 'outbound_fetch' ? 'ssrf' : 'auth_bypass',
    })
  }

  // v7 M2: Middleware / RBAC policy diffs across sibling routes in the same module.
  for (const diff of diffMiddlewarePolicies(graph)) {
    if (diff.missingFamily === 'admin' && seen.has(`hyp:admin:${diff.routeId}`)) continue
    if (diff.missingFamily === 'tenant' && seen.has(`hyp:tenant:${diff.routeId}`)) continue
    const route = graph.routes.find(candidate => candidate.id === diff.routeId)
    if (!route) continue
    push({
      id: `hyp:policy:${diff.missingFamily}:${diff.routeId}`,
      kind: 'middleware_policy_diff',
      severity: diff.severity,
      confidence: diff.guardedSiblings >= 2 ? 0.84 : 0.72,
      framework: route.framework,
      method: route.method,
      path: route.path,
      file: route.file,
      line: route.line,
      routeId: route.id,
      rationale: `Middleware/RBAC policy diff on ${route.method} ${route.path}: missing ${diff.missingFamily} guard (${diff.siblingGuard}) enforced on ${diff.guardedSiblings}/${diff.totalSiblings} sibling route(s) in module "${diff.module}".`,
      evidence: [
        `missing_guard=${diff.missingFamily} ${diff.siblingGuard}@${diff.siblingAt} (sibling ${diff.siblingRoute})`,
        `sibling_coverage=${diff.guardedSiblings}/${diff.totalSiblings}`,
        `guards=[${route.guards.join(', ')}]`,
      ],
      probeClass: diff.missingFamily === 'tenant' ? 'bola_bfla' : 'auth_bypass',
    })
  }

  // v7 M2: Value-free static secrets & IaC exposure leads.
  for (const lead of (graph.staticLeads ?? []).slice(0, 20)) {
    const route = lead.routeId ? graph.routes.find(candidate => candidate.id === lead.routeId) : undefined
    push({
      id: `hyp:static:${lead.kind}:${lead.file}:${lead.line}`,
      kind: 'static_secret_or_iac',
      severity: lead.severity,
      confidence: lead.kind === 'secret' ? 0.78 : 0.72,
      framework: route?.framework ?? 'unknown',
      ...(route ? { method: route.method, path: route.path, routeId: route.id } : {}),
      file: lead.file,
      line: lead.line,
      rationale: `Static ${lead.kind} exposure at ${lead.at}: ${lead.note} (value withheld).`,
      evidence: [
        `kind=${lead.kind}`,
        `at=${lead.at}`,
        `note=${lead.note}`,
        ...(lead.module ? [`module=${lead.module}`] : []),
      ],
      probeClass: /jwt|signing|token|auth/i.test(lead.note) ? 'auth_bypass' : 'code_review',
    })
  }
  return hypotheses
}

// ============================================================================
// White-box dataflow slices (v7 M1/M2): bounded code evidence for briefs
// ============================================================================

/** Hard cap for a single rendered dataflow slice (bytes of compact JSON). */
export const CODE_DATAFLOW_SLICE_MAX_BYTES = 600
/** Expanded budget a coordinator may request when it wants the full hop chain. */
export const CODE_DATAFLOW_SLICE_EXPANDED_BYTES = 1600

export interface CodeSliceHop {
  /** Exact `file:line`, relative to {@link CodeDataflowSlice.root} when present. */
  at: string
  /** Omitted means `function` (kept implicit to fit the byte cap). */
  kind?: 'route' | 'function' | 'middleware' | 'sink'
  /** Guard identifiers that dominate this hop (function-level checks included). */
  guards?: string[]
}

export interface CodeSliceGuardDiff {
  kind: 'missing_guard'
  /** Guard family the target route lacks (`admin` / `tenant`). */
  guard: string
  /** Concrete sibling guard identifier, e.g. `requireAdmin`. */
  symbol: string
  /** `METHOD /path` of the sibling route that carries the guard. */
  sibling: string
  /** Sibling `file:line` where the guard is applied/declared. */
  at: string
}

export interface CodeSliceHint {
  /** `secret` = secret-shaped literal; `iac` = infrastructure exposure. */
  kind: 'secret' | 'iac'
  at: string
  /** Bounded, value-free description (never the secret itself). */
  note: string
}

export interface CodeDataflowSlice {
  /** `METHOD /mounted/:path`. */
  route: string
  mounts: string[]
  methods: string[]
  input?: { params?: string[]; query?: string[]; body?: string[]; schemas?: string[] }
  /** `guarded` when the mounted chain carries auth/RBAC/tenant middleware. */
  auth: 'guarded' | 'unguarded'
  guards: string[]
  /** Shared directory prefix for hop/sink `at` paths (kept explicit to save bytes). */
  root?: string
  /** route -> controller -> ... -> sink, 1..8 hops with exact file:line. */
  hops: CodeSliceHop[]
  sink?: { at: string; kind: ProgramSinkKind }
  guardDiff?: CodeSliceGuardDiff[]
  hints?: CodeSliceHint[]
  /** Set when the byte ladder dropped hops/fields; the graph retains the full chain. */
  truncated?: boolean
}

export interface CodeSliceBuildOptions {
  maxBytes?: number
  /** Hop budget for the sink path (default 8, clamped 1..8). */
  maxHops?: number
  /** Repository sources used for secrets/IaC hints (read-only). */
  files?: ReadonlyArray<{ path: string; content: string }>
  /** Reuse a precomputed sink-path set (avoids re-walking a large graph). */
  sinkPaths?: readonly RouteSinkPath[]
}

export interface RenderedCodeDataflowSlice {
  slice: CodeDataflowSlice
  text: string
  bytes: number
  truncated: boolean
}

const VERSION_SEGMENT_RE = /^(?:api|rest|internal|public|v\d+)$/i

/**
 * Module key used for sibling guard diffs and module-scoped hints. Enterprise monorepos mount
 * services under versioned prefixes (`/v2`, `/v3`, `/v4`), so the first non-version static
 * segment is the service/module identity (`/v2/billing/...` and `/v4/billing/...` both → billing).
 */
export function routeModuleKey(routePath: string): string {
  const segments = routePath
    .split('/')
    .map(segment => segment.trim())
    .filter(segment => segment && !/^[:{<]/.test(segment))
  for (const segment of segments) {
    if (VERSION_SEGMENT_RE.test(segment)) continue
    const clean = segment.toLowerCase().replace(/[^a-z0-9_-]/g, '')
    if (clean) return clean
  }
  return ''
}

export interface MiddlewarePolicyDiff {
  routeId: string
  method: string
  path: string
  file: string
  line: number
  module: string
  missingFamily: 'admin' | 'tenant' | 'auth'
  siblingGuard: string
  siblingRoute: string
  siblingAt: string
  guardedSiblings: number
  totalSiblings: number
  severity: 'high' | 'medium'
}

export interface StaticCodeLead {
  id: string
  kind: 'secret' | 'iac'
  file: string
  line: number
  at: string
  /** Bounded, value-free description; matched literal text is never copied. */
  note: string
  severity: 'high' | 'medium'
  module?: string
  routeId?: string
  method?: string
  path?: string
}

const PUBLIC_AUTH_EXEMPT_ROUTE_RE = /\/(?:login|signin|sign-in|register|signup|sign-up|logout|health|healthz|ready|readyz|livez|metrics|public|status|ping|jwks|openid-configuration)(?:\/|$)/i

function guardsByFamily(guards: readonly string[]): Map<'admin' | 'tenant' | 'auth', string> {
  const found = new Map<'admin' | 'tenant' | 'auth', string>()
  for (const guard of guards) {
    if (!found.has('admin') && ADMIN_GUARD_RE.test(guard)) found.set('admin', guard)
    if (!found.has('tenant') && TENANT_GUARD_RE.test(guard)) found.set('tenant', guard)
    if (!found.has('auth') && AUTH_GUARD_RE.test(guard)) found.set('auth', guard)
  }
  return found
}

interface SiblingGuardIndex {
  byModule: Map<string, Map<'admin' | 'tenant' | 'auth', { route: ProgramRoute; guard: string; guardedCount: number }>>
  moduleRouteCount: Map<string, number>
}

const SIBLING_GUARD_INDEX_CACHE = new WeakMap<ProgramGraph, SiblingGuardIndex>()

/** Precompute sibling guard coverage per (module, guard family) once per graph pass. */
function buildSiblingGuardIndex(graph: ProgramGraph): SiblingGuardIndex {
  const cached = SIBLING_GUARD_INDEX_CACHE.get(graph)
  if (cached) return cached
  const byModule = new Map<string, Map<'admin' | 'tenant' | 'auth', { route: ProgramRoute; guard: string; guardedCount: number }>>()
  const moduleRouteCount = new Map<string, number>()
  const routes = [...graph.routes].sort((a, b) =>
    a.path.localeCompare(b.path) || a.method.localeCompare(b.method) || a.file.localeCompare(b.file) || a.line - b.line)
  for (const route of routes) {
    const module = routeModuleKey(route.path)
    if (!module) continue
    moduleRouteCount.set(module, (moduleRouteCount.get(module) ?? 0) + 1)
    const families = guardsByFamily(route.guards)
    if (!families.size) continue
    const perModule = byModule.get(module) ?? new Map<'admin' | 'tenant' | 'auth', { route: ProgramRoute; guard: string; guardedCount: number }>()
    for (const [family, guard] of families) {
      const existing = perModule.get(family)
      if (!existing) perModule.set(family, { route, guard, guardedCount: 1 })
      else existing.guardedCount += 1
    }
    byModule.set(module, perModule)
  }
  const index = { byModule, moduleRouteCount }
  SIBLING_GUARD_INDEX_CACHE.set(graph, index)
  return index
}

function guardDiffsForRoute(
  route: ProgramRoute,
  index: SiblingGuardIndex,
  options: { limit?: number; excludeRouteId?: string; includeAuthFamily?: boolean } = {},
): CodeSliceGuardDiff[] {
  const module = routeModuleKey(route.path)
  if (!module) return []
  const siblings = index.byModule.get(module)
  if (!siblings) return []
  const owned = guardsByFamily(route.guards)
  const out: CodeSliceGuardDiff[] = []
  const reportedSymbols = new Set<string>()
  const limit = Math.max(1, Math.min(options.limit ?? 2, 4))
  const families: Array<'admin' | 'tenant' | 'auth'> = options.includeAuthFamily === false
    ? ['admin', 'tenant']
    : ['admin', 'tenant', 'auth']
  for (const family of families) {
    if (out.length >= limit) break
    if (owned.has(family)) continue
    if (family === 'auth' && PUBLIC_AUTH_EXEMPT_ROUTE_RE.test(route.path)) continue
    const entry = siblings.get(family)
    if (!entry || entry.route.id === route.id || entry.route.id === options.excludeRouteId) continue
    // Avoid emitting a duplicate `auth` diff when the exact same sibling guard symbol (e.g.
    // `requireAdmin`) was already reported under `admin` or `tenant`.
    if (family === 'auth' && reportedSymbols.has(entry.guard)) continue
    reportedSymbols.add(entry.guard)
    out.push({
      kind: 'missing_guard',
      guard: family,
      symbol: entry.guard.slice(0, 48),
      sibling: `${entry.route.method} ${entry.route.path}`.slice(0, 120),
      at: `${entry.route.file}:${entry.route.line}`.slice(0, 160),
    })
  }
  return out
}

/**
 * Compare middleware/RBAC enforcement across sibling routes in every module and return
 * deterministic `MiddlewarePolicyDiff` entries for routes missing a guard enforced by siblings.
 */
export function diffMiddlewarePolicies(graph: ProgramGraph): MiddlewarePolicyDiff[] {
  const index = buildSiblingGuardIndex(graph)
  const diffs: MiddlewarePolicyDiff[] = []
  const orderedRoutes = [...graph.routes].sort((a, b) =>
    a.path.localeCompare(b.path) || a.method.localeCompare(b.method) || a.file.localeCompare(b.file) || a.line - b.line)
  for (const route of orderedRoutes) {
    const module = routeModuleKey(route.path)
    if (!module) continue
    const siblings = index.byModule.get(module)
    if (!siblings) continue
    const totalSiblings = index.moduleRouteCount.get(module) ?? 1
    if (totalSiblings < 2) continue
    const owned = guardsByFamily(route.guards)
    const reportedSymbols = new Set<string>()
    for (const family of ['admin', 'tenant', 'auth'] as const) {
      if (owned.has(family)) continue
      if (family === 'auth' && PUBLIC_AUTH_EXEMPT_ROUTE_RE.test(route.path)) continue
      const entry = siblings.get(family)
      if (!entry || entry.route.id === route.id) continue
      if (family === 'auth' && reportedSymbols.has(entry.guard)) continue
      reportedSymbols.add(entry.guard)
      const mutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(route.method.toUpperCase())
      const severity: 'high' | 'medium' = family === 'admin' || family === 'tenant' || mutating || entry.guardedCount >= 2 ? 'high' : 'medium'
      diffs.push({
        routeId: route.id,
        method: route.method,
        path: route.path,
        file: route.file,
        line: route.line,
        module,
        missingFamily: family,
        siblingGuard: entry.guard.slice(0, 48),
        siblingRoute: `${entry.route.method} ${entry.route.path}`.slice(0, 120),
        siblingAt: `${entry.route.file}:${entry.route.line}`.slice(0, 160),
        guardedSiblings: entry.guardedCount,
        totalSiblings,
        severity,
      })
    }
  }
  return diffs.sort((a, b) =>
    (a.severity === b.severity ? 0 : a.severity === 'high' ? -1 : 1)
    || b.guardedSiblings - a.guardedSiblings
    || a.path.localeCompare(b.path)
    || a.method.localeCompare(b.method)
    || a.missingFamily.localeCompare(b.missingFamily))
}

const SECRET_HINT_PATTERNS: ReadonlyArray<{ re: RegExp; note: string }> = [
  { re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, note: 'cloud access key' },
  { re: /\bsk_(?:live|test)_[A-Za-z0-9]{8,}\b/, note: 'payment secret key' },
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, note: 'private key block' },
  { re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s'"`:@/]{0,128}:[^\s'"`@]{1,256}@/i, note: 'credentialed conn-string' },
  { re: /\b(?:jwt[_-]?secret|signing[_-]?secret|webhook[_-]?secret|hmac[_-]?secret)\b\s*[:=]\s*['"][^'"\n]{6,}['"]/i, note: 'hardcoded JWT/signing secret' },
  { re: /\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|password|passwd|private[_-]?key)\b\s*[:=]\s*['"][^'"\n]{8,}['"]/i, note: 'secret-shaped assignment' },
  { re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/, note: 'forge access token' },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, note: 'chat app token' },
]

const IAC_FILE_RE = /(?:^|\/)(?:\.?env(?:\.[\w.-]+)?|infra|deploy(?:ment)?s?|k8s|kubernetes|helm|terraform|ops|docker-compose[\w.-]*\.ya?ml|Dockerfile[\w.-]*|[\w.-]+\.tf|[\w.-]+\.ya?ml)$/i
const IAC_HINT_PATTERNS: ReadonlyArray<{ re: RegExp; note: string }> = [
  { re: /\b0\.0\.0\.0\/0\b|\b::\/0\b/, note: 'open ingress CIDR' },
  { re: /\bprivileged\s*:\s*true\b/, note: 'privileged container' },
  { re: /\bhostNetwork\s*:\s*true\b/, note: 'host network namespace' },
  { re: /\brunAsUser\s*:\s*0\b/, note: 'container runs as root' },
  { re: /\b(?:allow_privilege_escalation|allowPrivilegeEscalation)\s*:\s*true\b/, note: 'privilege escalation allowed' },
  { re: /\b(?:CAP_)?SYS_ADMIN\b/, note: 'dangerous SYS_ADMIN Linux capability' },
  { re: /"(?:Action|Principal)"\s*:\s*"\*"|(?:\bactions?\s*=\s*\[\s*"\*"|\bprincipals?\s*=\s*\[\s*"\*")/i, note: 'wildcard IAM policy' },
  { re: /\bNODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0['"]?/, note: 'TLS certificate verification disabled' },
]

function fileInModule(file: string, module: string): boolean {
  if (!module) return false
  const normalized = file.replaceAll('\\', '/').toLowerCase()
  return normalized.split('/').includes(module) || normalized.startsWith(`${module}/`)
}

/** Single fast prefilter so a repository-wide hint pass stays cheap on generated trees. */
const HINT_PREFILTER_RE = /(?:AKIA|ASIA)[0-9A-Z]{16}|sk_(?:live|test)_[A-Za-z0-9]{8,}|-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|:\/\/[^\s'"`:@/]{0,128}:[^\s'"`@]{1,256}@|(?:jwt[_-]?secret|signing[_-]?secret|webhook[_-]?secret|hmac[_-]?secret|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|password|passwd|private[_-]?key)[ \t]{0,32}[:=][ \t]{0,32}['"]|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|0\.0\.0\.0\/0|::\/0|privileged[ \t]{0,32}:[ \t]{0,32}true|hostNetwork[ \t]{0,32}:[ \t]{0,32}true|runAsUser[ \t]{0,32}:[ \t]{0,32}0|allow[_]?[Pp]rivilege[_]?[Ee]scalation[ \t]{0,32}:[ \t]{0,32}true|(?:CAP_)?SYS_ADMIN|"(?:Action|Principal)"[ \t]{0,32}:[ \t]{0,32}"\*"|NODE_TLS_REJECT_UNAUTHORIZED[ \t]{0,32}[:=][ \t]{0,32}['"]?0/i

/**
 * Scan repository sources (including root/infra/k8s/terraform/docker/.env files outside route
 * directories) for value-free secret and IaC static leads. Matched text is never copied.
 */
export function extractStaticSecretsAndIacLeads(
  files: ReadonlyArray<{ path: string; content: string }>,
  routes: readonly ProgramRoute[] = [],
  options: { limit?: number; maxFileBytes?: number } = {},
): StaticCodeLead[] {
  const limit = Math.max(1, Math.min(options.limit ?? 40, 200))
  const maxFileBytes = Math.max(4096, options.maxFileBytes ?? 512 * 1024)
  const routeByModule = new Map<string, ProgramRoute>()
  for (const route of [...routes].sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method))) {
    const mod = routeModuleKey(route.path)
    if (mod && !routeByModule.has(mod)) routeByModule.set(mod, route)
  }
  const modules = [...routeByModule.keys()].sort()
  const ordered = [...files]
    .filter(file => file.content.length <= maxFileBytes && HINT_PREFILTER_RE.test(file.content))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))

  const leads: StaticCodeLead[] = []
  const seen = new Set<string>()
  for (const file of ordered) {
    if (leads.length >= limit) break
    const matchedModule = modules.find(mod => fileInModule(file.path, mod))
    const relatedRoute = matchedModule ? routeByModule.get(matchedModule) : undefined
    const looksIac = IAC_FILE_RE.test(file.path)
      || /\b(?:resource|module)\s+["']/.test(file.content.slice(0, 2048))
      || /\b(?:apiVersion|kind\s*:\s*(?:Deployment|Pod|DaemonSet|StatefulSet|Role|ClusterRole)|services\s*:)\b/.test(file.content.slice(0, 2048))
    const lines = file.content.split('\n')
    for (let i = 0; i < lines.length; i += 1) {
      if (leads.length >= limit) break
      const line = lines[i]
      if (!line || line.length > 4096) continue
      const trimmed = line.trim()
      if (trimmed.startsWith('//') || trimmed.startsWith('#') && !/\.env/i.test(file.path)) continue
      for (const pattern of SECRET_HINT_PATTERNS) {
        if (!pattern.re.test(line)) continue
        const at = `${file.path}:${i + 1}`.slice(0, 160)
        const key = `secret|${at}|${pattern.note}`
        if (!seen.has(key)) {
          seen.add(key)
          leads.push({
            id: `static:secret:${file.path}:${i + 1}`,
            kind: 'secret',
            file: file.path,
            line: i + 1,
            at,
            note: pattern.note,
            severity: 'high',
            ...(matchedModule ? { module: matchedModule } : {}),
            ...(relatedRoute ? { routeId: relatedRoute.id, method: relatedRoute.method, path: relatedRoute.path } : {}),
          })
        }
        break
      }
      if (!looksIac || leads.length >= limit) continue
      for (const pattern of IAC_HINT_PATTERNS) {
        if (!pattern.re.test(line)) continue
        const at = `${file.path}:${i + 1}`.slice(0, 160)
        const key = `iac|${at}|${pattern.note}`
        if (!seen.has(key)) {
          seen.add(key)
          leads.push({
            id: `static:iac:${file.path}:${i + 1}`,
            kind: 'iac',
            file: file.path,
            line: i + 1,
            at,
            note: pattern.note,
            severity: /privileged|root|wildcard|SYS_ADMIN|TLS/i.test(pattern.note) ? 'high' : 'medium',
            ...(matchedModule ? { module: matchedModule } : {}),
            ...(relatedRoute ? { routeId: relatedRoute.id, method: relatedRoute.method, path: relatedRoute.path } : {}),
          })
        }
        break
      }
    }
  }
  return leads
}

/**
 * Build per-module hint blocks once per extraction. Files are prefilted, so generated route
 * trees (thousands of files) cost one regex per file and no line scan unless a hint is present.
 * Hints contain only `file:line` and a fixed note; matched text is never copied.
 */
export function deriveGraphCodeHints(
  files: ReadonlyArray<{ path: string; content: string }>,
  routes: readonly ProgramRoute[],
  options: { maxModules?: number; maxHintsPerModule?: number } = {},
): Record<string, CodeSliceHint[]> {
  const modules = [...new Set(routes.map(route => routeModuleKey(route.path)).filter(Boolean))]
    .sort()
    .slice(0, Math.max(1, Math.min(options.maxModules ?? 200, 2000)))
  if (!modules.length) return {}
  const moduleSet = new Set(modules)
  const byModule = new Map<string, Array<{ path: string; content: string }>>()
  for (const file of files) {
    const normalized = file.path.replaceAll('\\', '/').toLowerCase()
    const segments = normalized.split('/')
    for (const module of moduleSet) {
      if (segments.includes(module) || normalized.startsWith(`${module}/`)) {
        const list = byModule.get(module) ?? []
        list.push(file)
        byModule.set(module, list)
      }
    }
  }
  const out: Record<string, CodeSliceHint[]> = {}
  const maxHints = Math.max(1, Math.min(options.maxHintsPerModule ?? 3, 8))
  for (const module of modules) {
    const candidates = byModule.get(module)
    if (!candidates) continue
    const scoped = candidates.filter(file => file.content.length <= 512 * 1024 && HINT_PREFILTER_RE.test(file.content))
    if (!scoped.length) continue
    const hints = collectModuleCodeHints(scoped, module, { limit: maxHints })
    if (hints.length) out[module] = hints
  }
  return out
}

/**
 * Scan module sources for secret-shaped literals and IaC exposures on the route's module.
 * The returned hints carry a file:line and a value-free note: the matched text is never copied.
 */
export function collectModuleCodeHints(
  files: ReadonlyArray<{ path: string; content: string }>,
  module: string,
  options: { limit?: number; maxFileBytes?: number } = {},
): CodeSliceHint[] {
  const limit = Math.max(1, Math.min(options.limit ?? 3, 8))
  const maxFileBytes = Math.max(4096, options.maxFileBytes ?? 512 * 1024)
  const hints: CodeSliceHint[] = []
  const ordered = [...files]
    .filter(file => file.content.length <= maxFileBytes)
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  for (const file of ordered) {
    if (hints.length >= limit) break
    if (module && !fileInModule(file.path, module)) continue
    const lines = file.content.split('\n')
    const looksIac = IAC_FILE_RE.test(file.path) || /\b(?:resource|module)\s+["']/.test(file.content.slice(0, 2048))
    for (let i = 0; i < lines.length; i += 1) {
      if (hints.length >= limit) break
      const line = lines[i]
      if (!line || line.length > 4096) continue
      for (const pattern of SECRET_HINT_PATTERNS) {
        if (!pattern.re.test(line)) continue
        hints.push({ kind: 'secret', at: `${file.path}:${i + 1}`.slice(0, 160), note: pattern.note })
        break
      }
      if (!looksIac || hints.length >= limit) continue
      for (const pattern of IAC_HINT_PATTERNS) {
        if (!pattern.re.test(line)) continue
        hints.push({ kind: 'iac', at: `${file.path}:${i + 1}`.slice(0, 160), note: pattern.note })
        break
      }
    }
  }
  return hints
}

function sinkKindRank(kind: ProgramSinkKind): number {
  if (kind === 'db_query' || kind === 'command') return 3
  if (kind === 'outbound_fetch' || kind === 'template' || kind === 'file') return 2
  if (kind === 'redirect') return 1
  return 0
}

function boundedStringList(values: readonly string[] | undefined, max: number): string[] {
  return [...new Set((values ?? []).map(value => value.trim()).filter(Boolean))].slice(0, max)
}

/** Longest shared directory prefix across hop/sink files (min 1 segment, trailing slash). */
function commonDirPrefix(files: readonly string[]): string {
  const split = files.filter(Boolean).map(file => file.split('/').slice(0, -1))
  if (!split.length || !split[0].length) return ''
  const first = split[0]
  let length = first.length
  for (const segments of split.slice(1)) {
    let i = 0
    while (i < length && i < segments.length && segments[i] === first[i]) i += 1
    length = i
  }
  return length ? `${first.slice(0, length).join('/')}/` : ''
}

function relativeAt(file: string, line: number, root: string): string {
  const relative = root && file.startsWith(root) ? file.slice(root.length) : file
  return `${relative}:${line}`.slice(0, 160)
}

function buildSliceFromRoute(
  graph: ProgramGraph,
  route: ProgramRoute,
  sinkPath: RouteSinkPath | null,
  options: CodeSliceBuildOptions,
): CodeDataflowSlice {
  const maxHops = Math.max(1, Math.min(options.maxHops ?? 8, 8))
  const nodeGuardsById = new Map(graph.nodes.map(node => [node.id, node.guards]))
  const rawHops: Array<{ file: string; line: number; kind: CodeSliceHop['kind']; guards: string[] }> = []
  if (sinkPath) {
    for (const hop of sinkPath.chain.slice(0, maxHops + 1)) {
      const nodeGuards = hop.kind === 'sink' ? [] : boundedStringList(nodeGuardsById.get(hop.id), 3)
      rawHops.push({
        file: hop.file,
        line: hop.line,
        kind: hop.kind === 'route' || hop.kind === 'sink' || hop.kind === 'middleware' ? hop.kind : 'function',
        guards: nodeGuards,
      })
    }
  } else {
    rawHops.push({ file: route.file, line: route.line, kind: 'route', guards: [] })
    const handlerNode = graph.nodes.find(node =>
      node.kind === 'function' && node.symbol === route.handler && node.file === (route.handlerFile ?? route.file))
    if (handlerNode) rawHops.push({ file: handlerNode.file, line: handlerNode.line, kind: 'function', guards: [] })
  }

  const root = commonDirPrefix([...rawHops.map(hop => hop.file), ...(sinkPath ? [sinkPath.sinkFile] : [])])
  const hops: CodeSliceHop[] = rawHops.map(hop => ({
    at: relativeAt(hop.file, hop.line, root),
    ...(hop.kind !== 'function' ? { kind: hop.kind } : {}),
    ...(hop.guards.length ? { guards: hop.guards } : {}),
  }))

  const input = route.input
  const pathParams = new Set(routeParamNames(route.path))
  const params = boundedStringList(input.params, 4).filter(name => !pathParams.has(name))
  const query = boundedStringList(input.query, 4)
  const body = boundedStringList(input.body, 3)
  const schemas = boundedStringList(input.schemas, 3)

  const index = buildSiblingGuardIndex(graph)
  const guardDiff = guardDiffsForRoute(route, index)
  const module = routeModuleKey(route.path)
  const hints = options.files?.length
    ? collectModuleCodeHints(options.files, module, { limit: 2 })
    : (graph.codeHints?.[module] ?? []).slice(0, 2)

  return {
    route: `${route.method} ${route.path}`.slice(0, 180),
    mounts: boundedStringList(route.mountedFrom, 4).map(mount => mount.slice(0, 40)),
    methods: [route.method],
    ...(params.length || query.length || body.length || schemas.length
      ? {
          input: {
            ...(params.length ? { params } : {}),
            ...(query.length ? { query } : {}),
            ...(body.length ? { body } : {}),
            ...(schemas.length ? { schemas } : {}),
          },
        }
      : {}),
    auth: route.guards.length ? 'guarded' : 'unguarded',
    guards: boundedStringList(route.guards, 6).map(guard => guard.slice(0, 48)),
    ...(root ? { root: root.slice(0, 120) } : {}),
    hops,
    ...(sinkPath ? { sink: { at: relativeAt(sinkPath.sinkFile, sinkPath.sinkLine, root), kind: sinkPath.sinkKind } } : {}),
    ...(guardDiff.length ? { guardDiff } : {}),
    ...(hints.length ? { hints } : {}),
  }
}

/** Pick the strongest sink path per route (db/command > network/template/file > rest, then depth). */
function bestSinkPath(paths: readonly RouteSinkPath[]): RouteSinkPath | null {
  if (!paths.length) return null
  return [...paths].sort((a, b) =>
    sinkKindRank(b.sinkKind) - sinkKindRank(a.sinkKind) ||
    b.hops - a.hops ||
    a.sinkId.localeCompare(b.sinkId) ||
    a.routeId.localeCompare(b.routeId))[0]
}

/**
 * Build a compact, deterministic dataflow slice for one hypothesis route.
 *
 * Accepts a route id (`PROGRAM_ROUTE` id), a `METHOD /path` string, a `ProgramRoute`, or a
 * code-to-runtime hypothesis carrying `routeId`/`method`/`path`. Returns `null` when the route is
 * not in the graph. The returned slice is always <= `maxBytes` (default 600).
 */
export function buildCodeDataflowSlice(
  graph: ProgramGraph,
  routeRef: string | Pick<ProgramRoute, 'id' | 'method' | 'path'> | { routeId?: string; method?: string; path?: string },
  options: CodeSliceBuildOptions = {},
): CodeDataflowSlice | null {
  const route = resolveSliceRoute(graph, routeRef)
  if (!route) return null
  const maxHops = Math.max(1, Math.min(options.maxHops ?? 8, 8))
  const sinkPaths = options.sinkPaths
    ?? resolveRouteSinkPaths(graph, { maxDepth: maxHops, maxPaths: 500 })
  const path = bestSinkPath(sinkPaths.filter(candidate => candidate.routeId === route.id))
  const slice = buildSliceFromRoute(graph, route, path, options)
  return renderCodeDataflowSlice(slice, options.maxBytes ?? CODE_DATAFLOW_SLICE_MAX_BYTES).slice
}

function resolveSliceRoute(
  graph: ProgramGraph,
  routeRef: string | Pick<ProgramRoute, 'id' | 'method' | 'path'> | { routeId?: string; method?: string; path?: string },
): ProgramRoute | null {
  if (typeof routeRef === 'string') {
    const direct = graph.routes.find(route => route.id === routeRef)
    if (direct) return direct
    const trimmed = routeRef.trim()
    const methodMatch = /^([A-Za-z]+)\s+(.+)$/.exec(trimmed)
    const method = methodMatch ? methodMatch[1].toUpperCase() : undefined
    const path = (methodMatch ? methodMatch[2] : trimmed).trim()
    return graph.routes.find(route =>
      route.path === path && (!method || route.method.toUpperCase() === method)) ?? null
  }
  const candidate = routeRef as { id?: string; routeId?: string; method?: string; path?: string }
  const id = candidate.id ?? candidate.routeId
  if (id) {
    const byId = graph.routes.find(route => route.id === id)
    if (byId) return byId
  }
  if (!candidate.path) return null
  const method = candidate.method?.toUpperCase()
  return graph.routes.find(route =>
    route.path === candidate.path && (!method || route.method.toUpperCase() === method)) ?? null
}

/**
 * Reduce a slice to a byte budget with a fixed ladder: hints → guard diffs → input detail →
 * middle hops (keeping the route and sink) → mounts. Deterministic and pure.
 */
export function renderCodeDataflowSlice(
  input: CodeDataflowSlice,
  maxBytes = CODE_DATAFLOW_SLICE_MAX_BYTES,
): RenderedCodeDataflowSlice {
  const cap = Math.max(64, Math.floor(maxBytes))
  let slice: CodeDataflowSlice = cloneSlice(input)
  let truncated = Boolean(input.truncated)
  const render = () => {
    const candidate: CodeDataflowSlice = truncated ? { ...slice, truncated: true } : slice
    const text = JSON.stringify(candidate)
    return { candidate, text, bytes: Buffer.byteLength(text, 'utf8') }
  }
  const finish = (rendered: { candidate: CodeDataflowSlice; text: string; bytes: number }) => ({
    slice: rendered.candidate,
    text: rendered.text,
    bytes: rendered.bytes,
    truncated,
  })

  for (let guard = 0; guard < 200; guard += 1) {
    const rendered = render()
    if (rendered.bytes <= cap) return finish(rendered)
    truncated = true
    if (slice.hints?.length) {
      const hints = slice.hints.slice(0, -1)
      slice = hints.length ? { ...slice, hints } : omit(slice, 'hints')
      continue
    }
    if (slice.guardDiff?.length) {
      const guardDiff = slice.guardDiff.slice(0, -1)
      slice = guardDiff.length ? { ...slice, guardDiff } : omit(slice, 'guardDiff')
      continue
    }
    if (slice.input && (slice.input.query?.length || slice.input.body?.length || slice.input.schemas?.length)) {
      slice = { ...slice, input: slice.input.params?.length ? { params: slice.input.params } : undefined }
      if (!slice.input) slice = omit(slice, 'input')
      continue
    }
    if (slice.hops.length > 2) {
      const hops = [...slice.hops]
      hops.splice(1, 1)
      slice = { ...slice, hops }
      continue
    }
    if (slice.hops.some(hop => hop.guards?.length)) {
      slice = { ...slice, hops: slice.hops.map(hop => (hop.guards ? { at: hop.at, kind: hop.kind } : hop)) }
      continue
    }
    if (slice.input) {
      slice = omit(slice, 'input')
      continue
    }
    if (slice.mounts?.length) {
      const mounts = slice.mounts.slice(0, -1)
      slice = mounts.length ? { ...slice, mounts } : omit(slice, 'mounts')
      continue
    }
    if (slice.guards?.length) {
      slice = { ...slice, guards: [] }
      continue
    }
    // Guaranteed-under-cap fallback: route + sink only.
    slice = {
      route: slice.route.slice(0, 120),
      mounts: [],
      methods: slice.methods.slice(0, 2),
      auth: slice.auth,
      guards: [],
      ...(slice.root ? { root: slice.root } : {}),
      hops: slice.hops.slice(0, 2),
      ...(slice.sink ? { sink: slice.sink } : {}),
      truncated: true,
    }
    const fallback = render()
    if (fallback.bytes <= cap) return finish(fallback)
    slice = {
      route: slice.route.slice(0, 80),
      mounts: [],
      methods: slice.methods.slice(0, 1),
      auth: slice.auth,
      guards: [],
      hops: [],
      truncated: true,
    }
    return finish(render())
  }

  slice = {
    route: input.route.slice(0, 80),
    mounts: [],
    methods: input.methods.slice(0, 1),
    auth: input.auth,
    guards: [],
    hops: [],
    truncated: true,
  }
  truncated = true
  return finish(render())
}

function cloneSlice(slice: CodeDataflowSlice): CodeDataflowSlice {
  return {
    ...slice,
    mounts: [...slice.mounts],
    methods: [...slice.methods],
    guards: [...slice.guards],
    hops: slice.hops.map(hop => ({ ...hop, ...(hop.guards ? { guards: [...hop.guards] } : {}) })),
    ...(slice.input
      ? {
          input: {
            ...(slice.input.params ? { params: [...slice.input.params] } : {}),
            ...(slice.input.query ? { query: [...slice.input.query] } : {}),
            ...(slice.input.body ? { body: [...slice.input.body] } : {}),
            ...(slice.input.schemas ? { schemas: [...slice.input.schemas] } : {}),
          },
        }
      : {}),
    ...(slice.sink ? { sink: { ...slice.sink } } : {}),
    ...(slice.guardDiff ? { guardDiff: slice.guardDiff.map(diff => ({ ...diff })) } : {}),
    ...(slice.hints ? { hints: slice.hints.map(hint => ({ ...hint })) } : {}),
  }
}

function omit<K extends keyof CodeDataflowSlice>(slice: CodeDataflowSlice, key: K): CodeDataflowSlice {
  const next = { ...slice }
  delete next[key]
  return next
}

/** Render a slice as compact JSON text, hard-truncated to the budget. */
export function renderCodeDataflowSliceText(input: CodeDataflowSlice, maxBytes = CODE_DATAFLOW_SLICE_MAX_BYTES): string {
  return renderCodeDataflowSlice(input, maxBytes).text
}

/**
 * Resolve a hop/sink `at` value back to its repo path. Hop and sink `at` values are relative to
 * `slice.root` (a shared directory prefix kept explicit to fit the byte cap); guard-diff and hint
 * `at` values are already repo-relative.
 */
export function expandCodeSlicePath(slice: CodeDataflowSlice, at: string): string {
  if (!slice.root || !at || at.startsWith(slice.root)) return at
  return `${slice.root}${at}`
}

/**
 * Explicit `missing_guard` evidence lines for hypothesis evidence arrays.
 * Format: `missing_guard=<family> <symbol>@<sibling file:line> (sibling <METHOD /path>)`.
 */
export function describeGuardDiffs(graph: ProgramGraph, route: ProgramRoute, limit = 2): string[] {
  return guardDiffsForRoute(route, buildSiblingGuardIndex(graph), { limit })
    .map(diff => `missing_guard=${diff.guard} ${diff.symbol}@${diff.at} (sibling ${diff.sibling})`)
}

/** Attach bounded slices to hypotheses so a planner can hand code evidence to specialists. */
export function attachCodeSlicesToHypotheses(
  graph: ProgramGraph,
  hypotheses: readonly CodeToRuntimeHypothesis[],
  options: CodeSliceBuildOptions = {},
): Array<CodeToRuntimeHypothesis & { codeSlice?: CodeDataflowSlice }> {
  const sinkPaths = options.sinkPaths ?? resolveRouteSinkPaths(graph, { maxDepth: options.maxHops ?? 8, maxPaths: 500 })
  return hypotheses.map(hypothesis => {
    if (!hypothesis.routeId && !hypothesis.path) return hypothesis
    const slice = buildCodeDataflowSlice(
      graph,
      hypothesis.routeId ?? { method: hypothesis.method, path: hypothesis.path as string },
      { ...options, sinkPaths },
    )
    return slice ? { ...hypothesis, codeSlice: slice } : hypothesis
  })
}

// ============================================================================
// Monorepo service -> origin mapping
// ============================================================================

export interface MonorepoService {
  name: string
  root?: string
  /** Host aliases harvested from compose/ingress/annotations. */
  hosts?: string[]
  ports?: number[]
}

export interface ServiceOriginMapping {
  service: string
  root?: string
  origin?: string
  confidence: 'exact' | 'host' | 'port' | 'path' | 'fallback' | 'unmapped'
  evidence: string[]
}

export interface MonorepoOriginInput {
  services: readonly MonorepoService[]
  origins: readonly string[]
  compose?: string
  ingress?: string
  dockerfiles?: ReadonlyArray<{ path: string; content: string }>
  manifests?: ReadonlyArray<{ path: string; content: string }>
}

function parseComposeServices(compose: string): Map<string, { hosts: string[]; ports: number[] }> {
  const services = new Map<string, { hosts: string[]; ports: number[] }>()
  const lines = compose.split('\n')
  let inServices = false
  let servicesIndent = -1
  let current: string | null = null
  let serviceIndent = -1
  let inPorts = false
  let portsIndent = -1
  for (const raw of lines) {
    if (/^\s*services\s*:/.test(raw)) {
      inServices = true
      servicesIndent = raw.length - raw.trimStart().length
      continue
    }
    if (!inServices) continue
    const indent = raw.length - raw.trimStart().length
    if (raw.trim() && indent <= servicesIndent && !/^\s*services\s*:/.test(raw)) break
    const serviceMatch = /^(\s+)([A-Za-z0-9_.-]+)\s*:\s*$/.exec(raw)
    if (serviceMatch && indent <= servicesIndent + 2) {
      current = serviceMatch[2]
      serviceIndent = indent
      inPorts = false
      services.set(current, { hosts: [], ports: [] })
      continue
    }
    if (!current) continue
    const entry = services.get(current)!
    if (raw.trim() && indent <= serviceIndent && !raw.trim().startsWith('#')) {
      current = null
      inPorts = false
      continue
    }
    if (/^\s*ports\s*:/.test(raw)) {
      inPorts = true
      portsIndent = indent
      const inline = /ports\s*:\s*\[([^\]]*)\]/.exec(raw)?.[1]
      if (inline) {
        for (const port of inline.matchAll(/(?:^|,)\s*['"]?(?:\d+:)?(\d{2,5})(?::\d+)?['"]?/g)) entry.ports.push(Number(port[1]))
        inPorts = false
      }
      continue
    }
    if (inPorts && indent <= portsIndent && raw.trim() && !/^\s*-/.test(raw)) {
      inPorts = false
    }
    if (inPorts) {
      const singlePort = /^\s*-\s*['"]?(?:\d+:)?(\d{2,5})(?::\d+)?['"]?\s*$/.exec(raw)
      if (singlePort) entry.ports.push(Number(singlePort[1]))
    }
    for (const host of raw.matchAll(/Host\s*\(\s*`?([^`')]+)`?\s*\)/g)) entry.hosts.push(host[1])
    const containerName = /container_name\s*:\s*['"]?([A-Za-z0-9_.-]+)/.exec(raw)?.[1]
    if (containerName) entry.hosts.push(containerName)
  }
  return services
}

function parseIngressRules(ingress: string): Array<{ host: string; service: string; path?: string }> {
  const rules: Array<{ host: string; service: string; path?: string }> = []
  const lines = ingress.split('\n')
  let host = ''
  let path: string | undefined
  let pendingService = false
  for (const raw of lines) {
    const hostMatch = /^\s*-\s*host\s*:\s*['"]?([^'"\s]+)/.exec(raw)
    if (hostMatch) host = hostMatch[1]
    const quotedHost = /host\s*:\s*['"]([^'"]+)['"]/.exec(raw)
    if (quotedHost && !hostMatch) host = quotedHost[1]
    const pathMatch = /path\s*:\s*['"]?([^'"\s]+)/.exec(raw)
    if (pathMatch) path = pathMatch[1]
    if (/service\s*:\s*$/.test(raw)) {
      pendingService = true
      continue
    }
    const nameMatch = /^\s*name\s*:\s*['"]?([A-Za-z0-9_.-]+)/.exec(raw)
    if (pendingService && nameMatch) {
      rules.push({ host, service: nameMatch[1], ...(path ? { path } : {}) })
      pendingService = false
    }
  }
  return rules
}

/**
 * Map monorepo services to concrete target origins using compose labels/ports,
 * Dockerfile EXPOSE, k8s ingress host/path backends and manifest names.
 * `origins[0]` is only used as an explicit, low-confidence last resort.
 */
export function mapServicesToOrigins(input: MonorepoOriginInput): ServiceOriginMapping[] {
  const composeServices = input.compose ? parseComposeServices(input.compose) : new Map<string, { hosts: string[]; ports: number[] }>()
  const ingressRules = input.ingress ? parseIngressRules(input.ingress) : []
  const dockerPorts = new Map<string, number[]>()
  for (const dockerfile of input.dockerfiles ?? []) {
    const root = dockerfile.path.replace(/(?:\/)?Dockerfile(?:\..*)?$/i, '').replace(/\/$/, '')
    const ports = [...dockerfile.content.matchAll(/^\s*EXPOSE\s+(\d{2,5})/gim)].map(m => Number(m[1]))
    if (ports.length) dockerPorts.set(root || '/', ports)
  }
  const manifestNames = new Map<string, string>()
  for (const manifest of input.manifests ?? []) {
    try {
      const parsed = JSON.parse(manifest.content) as { name?: string }
      if (parsed.name) manifestNames.set(manifest.path.replace(/(?:\/)?package\.json$/, '').replace(/\/$/, ''), parsed.name.split('/').pop() ?? parsed.name)
    } catch { /* ignore non-json manifests */ }
  }

  const results: ServiceOriginMapping[] = []
  for (const service of input.services) {
    const aliases = new Set<string>([service.name.toLowerCase()])
    const composeEntry = composeServices.get(service.name)
    const evidence: string[] = []
    for (const host of service.hosts ?? []) aliases.add(host.toLowerCase())
    for (const host of composeEntry?.hosts ?? []) aliases.add(host.toLowerCase())
    const root = service.root?.replace(/\/$/, '')
    if (root && manifestNames.has(root)) aliases.add(manifestNames.get(root)!.toLowerCase())
    const ports = new Set<number>([...(service.ports ?? []), ...(composeEntry?.ports ?? [])])
    if (root) for (const port of dockerPorts.get(root) ?? []) ports.add(port)

    let best: ServiceOriginMapping | null = null
    for (const origin of input.origins) {
      let host = ''
      let originPort = 0
      try {
        const url = new URL(origin)
        host = url.hostname.toLowerCase()
        originPort = Number(url.port || (url.protocol === 'https:' ? 443 : 80))
      } catch { continue }
      const hostMatch = [...aliases].find(alias => host === alias || host.startsWith(`${alias}.`) || host.includes(`-${alias}.`) || host.includes(`.${alias}.`))
      const ingressMatch = ingressRules.find(rule => rule.service.toLowerCase() === service.name.toLowerCase() && rule.host.toLowerCase() === host)
      const portMatch = ports.has(originPort)
      if (hostMatch) {
        const candidate: ServiceOriginMapping = { service: service.name, ...(root ? { root } : {}), origin, confidence: 'exact', evidence: [`host ${host} matches alias ${hostMatch}`] }
        if (!best || best.confidence !== 'exact') best = candidate
      } else if (ingressMatch) {
        const candidate: ServiceOriginMapping = {
          service: service.name, ...(root ? { root } : {}), origin,
          confidence: ingressMatch.path ? 'path' : 'host',
          evidence: [`ingress host ${ingressMatch.host}${ingressMatch.path ? ` path ${ingressMatch.path}` : ''} -> service ${service.name}`],
        }
        if (!best || ['path', 'host'].includes(best.confidence)) best = candidate
      } else if (portMatch && !best) {
        best = { service: service.name, ...(root ? { root } : {}), origin, confidence: 'port', evidence: [`port ${originPort} exposed by service`] }
      }
    }
    if (best) {
      results.push({ ...best, evidence: [...best.evidence, ...evidence] })
    } else if (input.origins.length) {
      results.push({
        service: service.name, ...(root ? { root } : {}), origin: input.origins[0], confidence: 'fallback',
        evidence: ['no host/port/ingress match; using origins[0] as documented fallback'],
      })
    } else {
      results.push({ service: service.name, ...(root ? { root } : {}), confidence: 'unmapped', evidence: ['no target origins configured'] })
    }
  }
  return results
}
