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
import { normalizeRouteTemplate } from './route-template.ts'
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

export type ProgramNodeKind = 'route' | 'function' | 'middleware' | 'sink' | 'service_endpoint' | 'async_channel'

export interface ProgramNode {
  id: string
  kind: ProgramNodeKind
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

export type ProgramEdgeKind = 'route_handler' | 'call' | 'sink' | 'client_call' | 'async_dispatch'

export interface ProgramEdge {
  fromId: string
  toId: string
  file: string
  line: number
  /** Structural edge kind (`client_call` and `async_dispatch` connect cross-service/async chains). */
  kind?: ProgramEdgeKind
  /** Transport/channel protocol for cross-service and async edges. */
  protocol?: 'http' | 'rpc' | 'grpc' | 'queue' | 'webhook' | 'job' | 'event'
  /** Target service hint for cross-service calls (hostname, env var, RPC client). */
  targetService?: string
  /** Target route/endpoint path for cross-service calls. */
  targetPath?: string
  /** Queue, topic, event, job, or webhook channel name for async dispatches. */
  channel?: string
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

export interface LineIndex {
  readonly newlineOffsets: readonly number[]
  readonly length: number
}

/** Single-pass O(n) newline-offset index for O(log L) offset-to-line lookup and O(window) slicing. */
export function buildLineIndex(text: string): LineIndex {
  const newlineOffsets: number[] = []
  let idx = text.indexOf('\n')
  while (idx !== -1) {
    newlineOffsets.push(idx)
    idx = text.indexOf('\n', idx + 1)
  }
  return { newlineOffsets, length: text.length }
}

/** O(log L) binary-search 1-based line number lookup for a character offset using a prebuilt `LineIndex`. */
export function lineAtOffset(index: LineIndex, offset: number): number {
  const end = Math.min(Math.max(0, offset), index.length)
  const offsets = index.newlineOffsets
  let lo = 0
  let hi = offsets.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (offsets[mid]! < end) lo = mid + 1
    else hi = mid
  }
  return lo + 1
}

/**
 * O(window) slice of 1-based lines `[startLine, endLineExclusive)` using a prebuilt `LineIndex`,
 * bounded to `maxChars` so adversarial single-line/minified files cannot trigger quadratic slicing.
 */
export function extractLineRange(
  text: string,
  index: LineIndex,
  startLine: number,
  endLineExclusive: number,
  maxChars = 4_096,
  anchorOffset?: number,
): string {
  const totalLines = index.newlineOffsets.length + 1
  const clampedStart = Math.max(1, Math.min(Math.trunc(startLine), totalLines + 1))
  const clampedEnd = Math.max(clampedStart, Math.min(Math.trunc(endLineExclusive), totalLines + 1))
  if (clampedStart >= clampedEnd || text.length === 0) return ''
  const startChar = clampedStart <= 1 ? 0 : index.newlineOffsets[clampedStart - 2]! + 1
  const endChar = clampedEnd > totalLines ? text.length : index.newlineOffsets[clampedEnd - 2]!
  if (endChar <= startChar) return ''
  const safeMax = Math.max(64, Math.trunc(maxChars))
  if (endChar - startChar <= safeMax) return text.slice(startChar, endChar)
  if (anchorOffset !== undefined && anchorOffset >= startChar && anchorOffset <= endChar) {
    const halfBefore = Math.floor(safeMax / 4)
    const winStart = Math.max(startChar, Math.min(anchorOffset - halfBefore, endChar - safeMax))
    return text.slice(winStart, Math.min(endChar, winStart + safeMax))
  }
  return text.slice(startChar, startChar + safeMax)
}

function buildNewlineOffsets(text: string): number[] {
  return buildLineIndex(text).newlineOffsets as number[]
}

function lineAtFromOffsets(offsets: readonly number[], index: number, textLength: number): number {
  return lineAtOffset({ newlineOffsets: offsets, length: textLength }, index)
}

interface DelimiterIndex {
  braceOpens: number[]
  braceClose: Map<number, number>
  parenClose: Map<number, number>
  bracketClose: Map<number, number>
}

/** Single-pass O(n) delimiter matcher for `{}`, `()`, and `[]`, skipping strings and comments. */
function buildDelimiterIndex(
  text: string,
  options: { hashComments?: boolean; cComments?: boolean } = {},
): DelimiterIndex {
  const braceOpens: number[] = []
  const braceClose = new Map<number, number>()
  const parenClose = new Map<number, number>()
  const bracketClose = new Map<number, number>()
  const braceStack: number[] = []
  const parenStack: number[] = []
  const bracketStack: number[] = []
  const cComments = options.cComments !== false
  const hashComments = options.hashComments === true
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (ch === '"' || ch === "'" || (ch === '`' && !hashComments)) {
      i = skipQuoted(text, i) - 1
      continue
    }
    if (cComments && ch === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i)
      i = nl < 0 ? text.length : nl
      continue
    }
    if (cComments && ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2)
      i = end < 0 ? text.length : end + 1
      continue
    }
    if (hashComments && ch === '#') {
      const nl = text.indexOf('\n', i)
      i = nl < 0 ? text.length : nl
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
    } else if (ch === '[') {
      bracketStack.push(i)
    } else if (ch === ']') {
      const open = bracketStack.pop()
      if (open !== undefined) bracketClose.set(open, i)
    }
  }
  return { braceOpens, braceClose, parenClose, bracketClose }
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

function skipQuoted(text: string, start: number, limit = text.length): number {
  const quote = text[start]
  const end = Math.min(limit, text.length)
  let i = start + 1
  while (i < end) {
    if (text[i] === '\\') {
      i += 2
      continue
    }
    if (text[i] === quote) return i + 1
    i += 1
  }
  return end
}

/**
 * Find the matching close delimiter, skipping strings and comments.
 * Uses O(1) lookup when a precomputed `DelimiterIndex` is provided, and caps fallback lookahead
 * at `maxScan` (default `MAX_FIND_MATCHING_SCAN_BYTES` = 4 KiB) so unclosed openers never cause
 * O(matches × fileSize) EOF scans (`R3-H-12`).
 */
function findMatching(
  text: string,
  openIndex: number,
  options: {
    open?: string
    close?: string
    hashComments?: boolean
    comments?: boolean
    maxScan?: number
    delimiters?: DelimiterIndex
  } = {},
): number {
  const open = options.open ?? '{'
  const close = options.close ?? '}'
  if (options.delimiters) {
    if (open === '(' && close === ')') return options.delimiters.parenClose.get(openIndex) ?? -1
    if (open === '{' && close === '}') return options.delimiters.braceClose.get(openIndex) ?? -1
    if (open === '[' && close === ']') return options.delimiters.bracketClose.get(openIndex) ?? -1
  }
  const comments = options.comments !== false
  const maxScan = Math.max(1, options.maxScan ?? MAX_FIND_MATCHING_SCAN_BYTES)
  const scanEnd = Math.min(text.length, openIndex + maxScan)
  let depth = 0
  for (let i = openIndex; i < scanEnd; i += 1) {
    const ch = text[i]
    if (ch === '"' || ch === "'" || ch === '`') {
      i = skipQuoted(text, i, scanEnd) - 1
      continue
    }
    if (comments && ch === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i)
      i = nl < 0 || nl >= scanEnd ? scanEnd : nl
      continue
    }
    if (comments && ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2)
      i = end < 0 || end + 1 >= scanEnd ? scanEnd : end + 1
      continue
    }
    if (options.hashComments && ch === '#') {
      const nl = text.indexOf('\n', i)
      i = nl < 0 || nl >= scanEnd ? scanEnd : nl
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

/** Split a comma-separated argument list at top-level depth (bounded args & quote window). */
function splitTopLevel(text: string, start: number, end: number, separator = ','): string[] {
  const out: string[] = []
  const clampedEnd = Math.min(end, text.length)
  let depth = 0
  let last = start
  for (let i = start; i < clampedEnd; i += 1) {
    const ch = text[i]
    if (ch === '"' || ch === "'" || ch === '`') {
      i = skipQuoted(text, i, clampedEnd) - 1
      continue
    }
    if (ch === '(' || ch === '[' || ch === '{') depth += 1
    else if (ch === ')' || ch === ']' || ch === '}') depth -= 1
    else if (ch === separator && depth === 0) {
      out.push(text.slice(last, i).trim())
      last = i + 1
      if (out.length >= MAX_CALL_ARGS) return out
    }
  }
  if (out.length < MAX_CALL_ARGS) {
    const tail = text.slice(last, clampedEnd).trim()
    if (tail) out.push(tail)
  }
  return out
}

function argsAtCall(
  text: string,
  openParenIndex: number,
  options: {
    delimiters?: DelimiterIndex
    maxSpan?: number
    consumeScanBytes?: (bytes: number) => boolean
  } = {},
): { args: string[]; closeIndex: number } {
  const maxSpan = Math.max(64, options.maxSpan ?? MAX_CALL_ARGS_SCAN_BYTES)
  const close = findMatching(text, openParenIndex, {
    open: '(',
    close: ')',
    delimiters: options.delimiters,
    maxScan: maxSpan,
  })
  if (close < 0) return { args: [], closeIndex: -1 }
  const span = close - openParenIndex
  if (span > maxSpan) return { args: [], closeIndex: close }
  if (options.consumeScanBytes && !options.consumeScanBytes(span)) {
    return { args: [], closeIndex: close }
  }
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

const MAX_ROUTER_MOUNT_DEPTH = 12
const MAX_ROUTER_MOUNT_STEPS = 10_000
const MAX_MOUNTS_PER_ROUTER = 64
const MAX_MOUNT_PATH_LENGTH = 2048
const MAX_MOUNTED_ROUTES = 5000
const MAX_CROSS_SERVICE_EDGES = 2000
const MAX_RAW_ROUTES_PER_FILE = 1000
const MAX_ROUTE_MATCH_ATTEMPTS_PER_FILE = MAX_RAW_ROUTES_PER_FILE * 4
const MAX_FIND_MATCHING_SCAN_BYTES = 4096
const MAX_CALL_ARGS_SCAN_BYTES = 4096
const MAX_CALL_ARG_SCAN_BYTES_PER_FILE = 256 * 1024
const MAX_CALL_ARGS = 128
const MAX_RAW_ROUTE_BYTES_PER_FILE = 512 * 1024
const MAX_MOUNTS_PER_FILE = 500
const MAX_FUNCTIONS_PER_FILE = 1000
const MAX_FUNCTION_BODY_SCAN_BYTES = 64 * 1024
const MAX_MIDDLEWARE_PER_ROUTER = 64
const MAX_MIDDLEWARE_PER_ROUTE = 64
const MAX_MIDDLEWARE_TOKEN_LENGTH = 128
const MAX_SCAN_LINE_LENGTH = 4096
const MAX_RAILS_LINES = 20_000
const MAX_COMPOSE_LINES = 8_000
const MAX_COMPOSE_SERVICES = 256
const MAX_COMPOSE_HOSTS_PER_SERVICE = 32
const MAX_COMPOSE_PREFIXES_PER_SERVICE = 32
const MAX_COMPOSE_PORTS_PER_SERVICE = 32
const MAX_INGRESS_RULES = 512
const MAX_FILE_WARNINGS = 64
const MAX_TOTAL_WARNINGS = 200
const EMPTY_STRINGS: string[] = []

function joinPaths(prefix: string, path: string): string {
  if (prefix.length > MAX_MOUNT_PATH_LENGTH * 2 || path.length > MAX_MOUNT_PATH_LENGTH * 2 || prefix.length + path.length > MAX_MOUNT_PATH_LENGTH * 2) {
    const bounded = `${prefix.slice(0, MAX_MOUNT_PATH_LENGTH)}/${path.slice(0, MAX_MOUNT_PATH_LENGTH)}`
    return normalizeRouteTemplate(bounded, {
      preserveParamNames: true,
      collapseConcreteIds: false,
    }).slice(0, MAX_MOUNT_PATH_LENGTH)
  }
  const joined = normalizeRouteTemplate(`${prefix}/${path}`, {
    preserveParamNames: true,
    collapseConcreteIds: false,
  })
  return joined.length > MAX_MOUNT_PATH_LENGTH ? joined.slice(0, MAX_MOUNT_PATH_LENGTH) : joined
}

function joinPathsBounded(
  prefix: string,
  path: string,
  warnings?: string[],
  context?: string,
): string | null {
  if (
    prefix.length > MAX_MOUNT_PATH_LENGTH
    || path.length > MAX_MOUNT_PATH_LENGTH
    || prefix.length + path.length + 1 > MAX_MOUNT_PATH_LENGTH * 2
  ) {
    if (warnings && warnings.length < MAX_FILE_WARNINGS) {
      warnings.push(`Skipped route path exceeding ${MAX_MOUNT_PATH_LENGTH} chars${context ? ` (${context})` : ''}`)
    }
    return null
  }
  const joined = normalizeRouteTemplate(`${prefix}/${path}`, {
    preserveParamNames: true,
    collapseConcreteIds: false,
  })
  if (joined.length > MAX_MOUNT_PATH_LENGTH) {
    if (warnings && warnings.length < MAX_FILE_WARNINGS) {
      warnings.push(`Skipped route path exceeding ${MAX_MOUNT_PATH_LENGTH} chars${context ? ` (${context})` : ''}`)
    }
    return null
  }
  return joined
}

function routeParamNames(path: string): string[] {
  const names: string[] = []
  const seen = new Set<string>()
  for (const match of path.matchAll(/:([A-Za-z_][A-Za-z0-9_]{0,63})/g)) {
    const param = match[1]
    if (param && !seen.has(param)) {
      seen.add(param)
      names.push(param)
      if (names.length >= 32) break
    }
  }
  return names
}

const AUTH_GUARD_RE = /\b(?:auth\w*|require\w*(?:Auth|User|Login|Token|Session|Admin|Role|Permission|Tenant|Org|Scope)\w*|isAuthenticated|ensure(?:Auth|LoggedIn)\w*|verify(?:Token|Jwt|Session)\w*|passport\w*|jwt\w*|session\w*|csrf\w*|xsrf\w*|rbac|acl|permission\w*|privilege\w*|guard\w*|currentUser|getCurrentUser|get_user|getUser|principal|identity|loginRequired)\b/i
const ADMIN_GUARD_RE = /\b(?:admin\w*|isAdmin|requireAdmin\w*|superuser\w*|staff\w*|role\w*|rbac|permission\w*|privilege\w*|policy\w*|hasRole|hasAuthority)/i
const TENANT_GUARD_RE = /(?:tenant|organization|organisation|orgId|org_id|account|workspace|membership|ownership|ownerId|owner_id|scopeCheck|belongsTo)/i

function looksLikeGuard(name: string): boolean {
  return AUTH_GUARD_RE.test(name) || ADMIN_GUARD_RE.test(name) || TENANT_GUARD_RE.test(name)
}

function flattenMiddlewareTokens(
  tokens: readonly string[],
  maxCount = MAX_MIDDLEWARE_PER_ROUTE,
  depth = 0,
  seen = new Set<string>(),
  out: string[] = [],
): string[] {
  if (depth > 4 || out.length >= maxCount) return out
  for (const token of tokens) {
    if (out.length >= maxCount) break
    const trimmed = token.trim()
    if (!trimmed) continue
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      if (depth < 4) {
        flattenMiddlewareTokens(splitTopLevel(trimmed, 1, trimmed.length - 1), maxCount, depth + 1, seen, out)
      }
      continue
    }
    const probe = trimmed.slice(0, 96)
    if (/^(?:async[ \t]+)?(?:function\b|\(|[\w$, \t]{0,64}(?:\)[ \t]*)?=>)/.test(probe)) continue
    const normalized = trimmed.slice(0, MAX_MIDDLEWARE_TOKEN_LENGTH).replace(/\s+/g, ' ')
    if (!seen.has(normalized)) {
      seen.add(normalized)
      out.push(normalized)
    }
  }
  return out
}

function guardsFromMiddleware(middleware: readonly string[]): string[] {
  if (middleware.length === 0) return EMPTY_STRINGS
  const out: string[] = []
  for (const mw of middleware) {
    if (looksLikeGuard(mw)) out.push(mw)
  }
  return out.length > 0 ? out : EMPTY_STRINGS
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
  const bounded = maskedBody.length > MAX_FUNCTION_BODY_SCAN_BYTES
    ? maskedBody.slice(0, MAX_FUNCTION_BODY_SCAN_BYTES)
    : maskedBody
  const calls: string[] = []
  const seen = new Set<string>()
  for (const match of bounded.matchAll(/(?<![\w$])([A-Za-z_$][\w$]{0,127})[ \t\r\n]{0,16}\(/g)) {
    const name = match[1]
    if (!name || CALL_KEYWORDS.has(name) || seen.has(name)) continue
    seen.add(name)
    calls.push(name)
    if (calls.length >= 256) break
  }
  return calls
}

interface SinkPattern {
  kind: ProgramSinkKind
  re: RegExp
}

const SINK_PATTERNS: readonly SinkPattern[] = [
  { kind: 'db_query', re: /(?:\.[ \t]{0,8}(?:query|execute|raw|exec|prepare)|queryRaw|executeRaw|createQuery|createNativeQuery|findBySql|whereRaw|sequelize\.query|knex\.raw)[ \t]{0,8}\(/i },
  { kind: 'db_query', re: /\b(?:select[ \t]+[^\r\n]{1,200}?[ \t]+from[ \t]+|insert[ \t]+into[ \t]+|update[ \t]+\w{1,64}[ \t]+set[ \t]+|delete[ \t]+from[ \t]+)/i },
  { kind: 'outbound_fetch', re: /\b(?:fetch|axios(?:\.[A-Za-z]{1,16})?|got|superagent|http\.(?:get|request)|https\.(?:get|request)|requests\.(?:get|post|put|delete|request)|urllib\.request|session\.(?:get|post)|RestTemplate|WebClient|http\.(?:Get|Post)|NewRequest)[ \t]{0,8}\(/ },
  { kind: 'template', re: /\b(?:render|render_template|renderTemplate|renderToString|ejs\.render|pug\.render|TemplateEngine|processTemplate|res\.render|sendFile)[ \t]{0,8}\(/ },
  { kind: 'file', re: /\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|FileInputStream|Files\.(?:read|write|newInputStream)|os\.(?:Open|ReadFile|WriteFile)|fs\.(?:read|write))\b/ },
  { kind: 'command', re: /\b(?:exec|execSync|spawn|spawnSync|execFile|child_process|Runtime\.getRuntime|ProcessBuilder|os\.system|subprocess\.(?:run|call|Popen)|Open3|system)[ \t]{0,8}\(/ },
  { kind: 'redirect', re: /\b(?:redirect|res\.redirect|location\.href|sendRedirect|Redirect)[ \t]{0,8}\(/ },
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

function extractJsFunctions(
  file: string,
  content: string,
  sharedDelimiters?: DelimiterIndex,
  sharedNewlineOffsets?: readonly number[],
): ProgramFunction[] {
  const out: ProgramFunction[] = []
  const seen = new Set<number>()
  const newlineOffsets = sharedNewlineOffsets ?? buildNewlineOffsets(content)
  const { braceOpens, braceClose, parenClose } = sharedDelimiters ?? buildDelimiterIndex(content)

  const push = (name: string | undefined, startIndex: number, bodyOpen: number, bodyClose: number) => {
    if (out.length >= MAX_FUNCTIONS_PER_FILE || !name || bodyOpen < 0 || bodyClose < 0 || seen.has(startIndex)) return
    seen.add(startIndex)
    const bodyEnd = Math.min(bodyClose + 1, bodyOpen + MAX_FUNCTION_BODY_SCAN_BYTES)
    const body = content.slice(bodyOpen, bodyEnd)
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

  for (const match of content.matchAll(/(?<![\w$])(?:export[ \t]{1,16})?(?:async[ \t]{1,16})?function[ \t]{1,16}([A-Za-z_$][\w$]{0,127})[ \t]{0,16}\(/g)) {
    if (out.length >= MAX_FUNCTIONS_PER_FILE) break
    const name = match[1]
    const openParen = match.index + match[0].length - 1
    const closeParen = parenClose.get(openParen)
    const open = nextBraceOpen(braceOpens, closeParen !== undefined ? closeParen + 1 : openParen + 1)
    const close = open >= 0 ? (braceClose.get(open) ?? -1) : -1
    push(name, match.index, open, close)
  }
  for (const match of content.matchAll(/(?<![\w$])(?:export[ \t]{1,16})?(?:const|let|var)[ \t]{1,16}([A-Za-z_$][\w$]{0,127})[ \t]{0,16}=[ \t]{0,16}(?:async[ \t]{0,16})?/g)) {
    if (out.length >= MAX_FUNCTIONS_PER_FILE) break
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
  const bounded = body.length > MAX_FUNCTION_BODY_SCAN_BYTES
    ? body.slice(0, MAX_FUNCTION_BODY_SCAN_BYTES)
    : body
  const found: string[] = []
  const seen = new Set<string>()
  for (const match of bounded.matchAll(/(?<![\w$])([A-Za-z_$][\w$]{2,127})[ \t\r\n]{0,16}(?:\(|\.)/g)) {
    const name = match[1]
    if (!seen.has(name) && (AUTH_GUARD_RE.test(name) || TENANT_GUARD_RE.test(name))) {
      seen.add(name)
      found.push(name)
      if (found.length >= 12) break
    }
  }
  return found
}

function buildLineStartOffsets(lines: readonly string[]): number[] {
  const starts: number[] = new Array(lines.length + 1)
  let offset = 0
  for (let i = 0; i < lines.length; i += 1) {
    starts[i] = offset
    offset += lines[i].length + 1
  }
  starts[lines.length] = offset
  return starts
}

function extractPythonFunctions(file: string, content: string): ProgramFunction[] {
  const out: ProgramFunction[] = []
  const lines = content.split('\n')
  const lineStarts = buildLineStartOffsets(lines)
  for (let i = 0; i < lines.length && out.length < MAX_FUNCTIONS_PER_FILE; i += 1) {
    const lineText = lines[i]
    if (lineText.length > MAX_SCAN_LINE_LENGTH) continue
    const match = /^([ \t]{0,128})(?:async[ \t]{1,16})?def[ \t]{1,16}([A-Za-z_]\w{0,63})[ \t]{0,16}\(/.exec(lineText)
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
    const startIndex = lineStarts[i]
    const endIndex = Math.min(content.length, lineStarts[endLine + 1] - 1)
    const body = content.slice(startIndex, Math.min(endIndex, startIndex + MAX_FUNCTION_BODY_SCAN_BYTES))
    out.push({
      name: match[2], file, line: i + 1, endLine: endLine + 1, startIndex, endIndex,
      calls: collectCalls(maskCode(body, true)), guardNames: guardIdentifiers(body),
    })
  }
  return out
}

function extractBraceFunctions(
  file: string,
  content: string,
  language: 'java' | 'go',
  sharedDelimiters?: DelimiterIndex,
  sharedNewlineOffsets?: readonly number[],
): ProgramFunction[] {
  const out: ProgramFunction[] = []
  const newlineOffsets = sharedNewlineOffsets ?? buildNewlineOffsets(content)
  const { braceOpens, braceClose, parenClose } = sharedDelimiters ?? buildDelimiterIndex(content)

  const emit = (name: string, startIndex: number, openParen: number) => {
    if (out.length >= MAX_FUNCTIONS_PER_FILE || !name || CALL_KEYWORDS.has(name)) return
    const closeParen = parenClose.get(openParen)
    const open = nextBraceOpen(braceOpens, closeParen !== undefined ? closeParen + 1 : openParen + 1)
    if (open < 0) return
    const close = braceClose.get(open) ?? -1
    if (close < 0) return
    const body = content.slice(open, Math.min(close + 1, open + MAX_FUNCTION_BODY_SCAN_BYTES))
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
    for (const match of content.matchAll(/(?<![\w$])func[ \t]{1,16}(?:\([^)\n]{0,200}\)[ \t]{0,16})?([A-Za-z_]\w{0,63})[ \t]{0,16}\(/g)) {
      if (out.length >= MAX_FUNCTIONS_PER_FILE) break
      emit(match[1], match.index, match.index + match[0].length - 1)
    }
    return out
  }

  for (const header of scanJavaMethodHeaders(content, false)) {
    if (out.length >= MAX_FUNCTIONS_PER_FILE) break
    emit(header.name, header.index, header.openParen)
  }
  return out
}

function extractRubyFunctions(file: string, content: string): ProgramFunction[] {
  const out: ProgramFunction[] = []
  const lines = content.split('\n')
  const lineStarts = buildLineStartOffsets(lines)
  for (let i = 0; i < lines.length && out.length < MAX_FUNCTIONS_PER_FILE; i += 1) {
    const lineText = lines[i]
    if (lineText.length > MAX_SCAN_LINE_LENGTH) continue
    const match = /^([ \t]{0,128})def[ \t]{1,16}([A-Za-z_]\w{0,63}[?!=]?)/.exec(lineText)
    if (!match) continue
    const indent = match[1].length
    let endLine = i
    for (let j = i + 1; j < lines.length; j += 1) {
      const line = lines[j]
      if (/^[ \t]{0,128}end\b/.test(line) && line.length - line.trimStart().length <= indent) break
      endLine = j
    }
    const startIndex = lineStarts[i]
    const endIndex = Math.min(content.length, lineStarts[endLine + 1] - 1)
    const body = content.slice(startIndex, Math.min(endIndex, startIndex + MAX_FUNCTION_BODY_SCAN_BYTES))
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

function extractFunctions(
  file: string,
  content: string,
  sharedDelimiters?: DelimiterIndex,
  sharedNewlineOffsets?: readonly number[],
): ProgramFunction[] {
  switch (languageOfFile(file)) {
    case 'js': return extractJsFunctions(file, content, sharedDelimiters, sharedNewlineOffsets)
    case 'python': return extractPythonFunctions(file, content)
    case 'java': return extractBraceFunctions(file, content, 'java', sharedDelimiters, sharedNewlineOffsets)
    case 'go': return extractBraceFunctions(file, content, 'go', sharedDelimiters, sharedNewlineOffsets)
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

interface FileExtractCtx {
  file: string
  delimiters: DelimiterIndex
  lineAt: (index: number) => number
  addWarning: (msg: string) => void
  addRoute: (route: RawRoute) => boolean
  addMount: (mount: MountSpec) => boolean
  routesRemaining: () => boolean
  /** Charge every call-site match attempt (including failed/unclosed openers) against the per-file budget. */
  consumeMatchAttempt: () => boolean
  /** O(1)-indexed, scan-budgeted call argument extractor for the current file. */
  argsAtCall: (openParenIndex: number, maxSpan?: number) => { args: string[]; closeIndex: number }
  /** O(1) brace-close lookup from the precomputed file delimiter index. */
  findBraceClose: (openBraceIndex: number) => number
}

const EXPRESS_METHOD_RE = /(?<![\w$])([A-Za-z_$][\w$]{0,127})[ \t\r\n]{0,16}\.[ \t\r\n]{0,16}(get|post|put|patch|delete|options|head|all|route)[ \t\r\n]{0,16}\(/g
const EXPRESS_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'all'])

function valueOrFallback(value: string): ProgramRouteInput {
  return { params: routeParamNames(value), query: EMPTY_STRINGS, body: EMPTY_STRINGS, schemas: EMPTY_STRINGS }
}

function extractExpressLike(file: string, content: string, out: Extraction, ctx: FileExtractCtx): void {
  const routers = new Map<string, RouterDef>()
  const routerMwSets = new Map<string, Set<string>>()
  let mwCapWarned = false
  const framework: ProgramFramework = /\bfastify\b/i.test(content) ? 'fastify' : 'express'
  const routerKey = (name: string) => `${file}#${name}`
  const exportNames = new Set<string>()
  for (const exportMatch of content.matchAll(/(?:module\.exports[ \t]{0,16}=|export[ \t]{1,16}default[ \t]{1,16}|export[ \t]{0,16}\{[^}]{0,512}\b)[ \t]{0,16}([A-Za-z_$][\w$]{0,127})/g)) {
    exportNames.add(exportMatch[1])
  }
  const importTargets = new Map<string, string>()
  for (const importMatch of content.matchAll(/(?<![\w$])import[ \t]{1,16}([A-Za-z_$][\w$]{0,127})[ \t]{1,16}from[ \t]{1,16}(['"])([^'"\r\n]{1,256})\2/g)) {
    const target = resolveImportTarget(file, importMatch[3])
    if (target) importTargets.set(importMatch[1], target)
  }
  for (const importMatch of content.matchAll(/(?<![\w$])(?:const|let|var)[ \t]{1,16}([A-Za-z_$][\w$]{0,127})[ \t]{0,16}=[ \t]{0,16}require[ \t]{0,16}\([ \t]{0,16}(['"])([^'"\r\n]{1,256})\2[ \t]{0,16}\)/g)) {
    const target = resolveImportTarget(file, importMatch[3])
    if (target) importTargets.set(importMatch[1], target)
  }

  const registerRouter = (name: string) => {
    if (routers.has(name) || routers.size >= 256) return
    const router: RouterDef = { key: routerKey(name), name, file, prefix: '', middleware: [], exported: exportNames.has(name) }
    routers.set(name, router)
    routerMwSets.set(name, new Set())
    out.routers.push(router)
  }
  for (const match of content.matchAll(/(?<![\w$])(?:const|let|var)[ \t]{1,16}([A-Za-z_$][\w$]{0,127})[ \t]{0,16}=[ \t]{0,16}(?:express[ \t]{0,16}\.[ \t]{0,16})?(?:Router|router)[ \t]{0,16}\(/g)) {
    registerRouter(match[1])
  }
  for (const match of content.matchAll(/(?<![\w$])(?:const|let|var)[ \t]{1,16}([A-Za-z_$][\w$]{0,127})[ \t]{0,16}=[ \t]{0,16}(?:express|Fastify|fastify)[ \t]{0,16}\(/g)) {
    registerRouter(match[1])
  }
  if (!routers.size) return

  // Mounts and router-level middleware.
  for (const match of content.matchAll(/(?<![\w$])([A-Za-z_$][\w$]{0,127})[ \t\r\n]{0,16}\.[ \t\r\n]{0,16}use[ \t\r\n]{0,16}\(/g)) {
    const parent = routers.get(match[1])
    if (!parent) continue
    if (!ctx.consumeMatchAttempt()) break
    const open = match.index + match[0].length - 1
    const { args } = ctx.argsAtCall(open, MAX_CALL_ARGS_SCAN_BYTES)
    if (!args.length) continue
    const childToken = args[args.length - 1]?.trim() ?? ''
    const childName = /^([A-Za-z_$][\w$]{0,127})$/.exec(childToken)?.[1]
    const child = childName ? routers.get(childName) : undefined
    if (args.length >= 2 && (child || childName)) {
      const mountPaths = stringListValue(args[0])
      const middleware = flattenMiddlewareTokens(args.slice(1, -1), MAX_MIDDLEWARE_PER_ROUTE)
      const line = ctx.lineAt(match.index)
      for (const mountPath of mountPaths.length ? mountPaths : ['']) {
        if (!ctx.addMount({
          parentKey: parent.key, parentFile: file, parentName: match[1],
          ...(child ? { childKey: child.key } : {}),
          childName: childName ?? childToken,
          childFile: childName && importTargets.has(childName) ? importTargets.get(childName) : file,
          prefix: mountPath.slice(0, MAX_MOUNT_PATH_LENGTH),
          middleware,
          file,
          line,
        })) break
      }
    } else {
      const mwSet = routerMwSets.get(match[1])!
      if (parent.middleware.length >= MAX_MIDDLEWARE_PER_ROUTER) {
        if (!mwCapWarned) {
          ctx.addWarning(`Router middleware capped at ${MAX_MIDDLEWARE_PER_ROUTER} entries in ${file}`)
          mwCapWarned = true
        }
        continue
      }
      const remaining = MAX_MIDDLEWARE_PER_ROUTER - parent.middleware.length
      const middleware = flattenMiddlewareTokens(args, remaining + 1)
      for (const name of middleware) {
        if (parent.middleware.length >= MAX_MIDDLEWARE_PER_ROUTER) {
          if (!mwCapWarned) {
            ctx.addWarning(`Router middleware capped at ${MAX_MIDDLEWARE_PER_ROUTER} entries in ${file}`)
            mwCapWarned = true
          }
          break
        }
        if (!mwSet.has(name)) {
          mwSet.add(name)
          parent.middleware.push(name)
        }
      }
    }
  }

  // Fastify object routes.
  for (const match of content.matchAll(/(?<![\w$])([A-Za-z_$][\w$]{0,127})[ \t\r\n]{0,16}\.[ \t\r\n]{0,16}route[ \t\r\n]{0,16}\([ \t\r\n]{0,16}\{/g)) {
    if (!ctx.routesRemaining()) break
    const parent = routers.get(match[1])
    if (!parent) continue
    if (!ctx.consumeMatchAttempt()) break
    const open = match.index + match[0].length - 1
    const close = ctx.findBraceClose(open)
    if (close < 0 || close - open > 16_384) continue
    const object = content.slice(open, close + 1)
    const url = /(?<![\w$])url[ \t]{0,16}:[ \t]{0,16}(['"`])([^'"`\r\n]{1,512})\1/.exec(object)?.[2]
    if (!url) continue
    const methodRaw = /(?<![\w$])method[ \t]{0,16}:[ \t]{0,16}(?:\[([^\]]{0,256})\]|(['"`])([A-Za-z]{1,16})\2)/.exec(object)
    const methods = methodRaw
      ? methodRaw[1]
        ? stringListValue(`[${methodRaw[1]}]`).map(m => m.toUpperCase()).slice(0, 12)
        : [methodRaw[3].toUpperCase()]
      : ['ANY']
    const preHandler = /(?<![\w$])preHandler[ \t]{0,16}:[ \t]{0,16}(\[[^\]]{0,1024}\]|[A-Za-z_$][\w$]{0,63}(?:[ \t]{0,8},[ \t]{0,8}[A-Za-z_$][\w$]{0,63}){0,16})/.exec(object)?.[1]
    const middleware = preHandler ? flattenMiddlewareTokens(splitTopLevel(preHandler, 0, preHandler.length), MAX_MIDDLEWARE_PER_ROUTE) : EMPTY_STRINGS
    const guards = guardsFromMiddleware(middleware)
    const handler = /(?<![\w$])handler[ \t]{0,16}:[ \t]{0,16}([^,}\r\n]{1,128})/.exec(object)?.[1]?.trim() ?? 'anonymous'
    const line = ctx.lineAt(match.index)
    for (const method of methods) {
      if (!ctx.addRoute({
        framework: 'fastify', method, path: url, file,
        line, handler,
        routerKey: parent.key,
        middleware,
        guards,
        input: valueOrFallback(url), extraction: 'ast',
      })) break
    }
  }

  // Method routes (including `.route('/x').get(...)` chains).
  for (const match of content.matchAll(EXPRESS_METHOD_RE)) {
    if (!ctx.routesRemaining()) break
    const parent = routers.get(match[1])
    if (!parent) continue
    const method = match[2].toLowerCase()
    if (method === 'route') continue
    if (!ctx.consumeMatchAttempt()) break
    const open = match.index + match[0].length - 1
    const { args } = ctx.argsAtCall(open, MAX_FUNCTION_BODY_SCAN_BYTES)
    if (!args.length) continue
    const routePaths = stringListValue(args[0])
    const routeLine = ctx.lineAt(match.index)
    if (!routePaths.length) {
      ctx.addWarning(`Skipped non-literal Express/Fastify route at ${file}:${routeLine}`)
      continue
    }
    const middleware = args.length > 2 ? flattenMiddlewareTokens(args.slice(1, -1), MAX_MIDDLEWARE_PER_ROUTE) : EMPTY_STRINGS
    const guards = guardsFromMiddleware(middleware)
    const handlerToken = args[args.length - 1] ?? 'anonymous'
    let handler = handlerNameFromToken(handlerToken)
    if (handler === 'anonymous' && /=>|\bfunction\b/.test(handlerToken.slice(0, 256)) && out.functions.length < MAX_FUNCTIONS_PER_FILE) {
      const syntheticName = `inline_${method}_${routeLine}`
      const tokenOffset = handlerToken.length <= 4096 ? content.indexOf(handlerToken, open) : open
      const bodyStart = tokenOffset >= 0 ? tokenOffset : open
      const bodyEnd = bodyStart + handlerToken.length
      const boundedToken = handlerToken.length > MAX_FUNCTION_BODY_SCAN_BYTES
        ? handlerToken.slice(0, MAX_FUNCTION_BODY_SCAN_BYTES)
        : handlerToken
      out.functions.push({
        name: syntheticName,
        file,
        line: routeLine,
        endLine: ctx.lineAt(Math.min(content.length - 1, bodyEnd)),
        startIndex: bodyStart,
        endIndex: Math.min(content.length, bodyEnd),
        calls: collectCalls(maskCode(boundedToken, false)),
        guardNames: guardIdentifiers(boundedToken),
      })
      handler = syntheticName
    }
    for (const routePath of routePaths) {
      if (!ctx.addRoute({
        framework,
        method: method === 'all' ? 'ANY' : method.toUpperCase(),
        path: routePath, file, line: routeLine, handler,
        routerKey: parent.key,
        middleware,
        guards,
        input: valueOrFallback(routePath),
        extraction: 'ast',
      })) break
    }
  }

  // `.route('/x').get(auth, handler).post(handler)` chains.
  const chainStickyRe = /[ \t\r\n]{0,32}\.[ \t\r\n]{0,16}([A-Za-z_$][\w$]{0,127})[ \t\r\n]{0,16}\(/y
  for (const match of content.matchAll(/(?<![\w$])([A-Za-z_$][\w$]{0,127})[ \t\r\n]{0,16}\.[ \t\r\n]{0,16}route[ \t\r\n]{0,16}\([ \t\r\n]{0,16}(['"`])([^'"`\r\n]{1,512})\2[ \t\r\n]{0,16}\)/g)) {
    if (!ctx.routesRemaining()) break
    const parent = routers.get(match[1])
    if (!parent) continue
    if (!ctx.consumeMatchAttempt()) break
    const basePath = match[3]
    const routeLine = ctx.lineAt(match.index)
    let pos = match.index + match[0].length
    let chainSteps = 0
    while (pos < content.length && chainSteps < 32 && ctx.routesRemaining()) {
      chainSteps += 1
      chainStickyRe.lastIndex = pos
      const chain = chainStickyRe.exec(content)
      if (!chain) break
      const chainMethod = chain[1].toLowerCase()
      if (!EXPRESS_METHODS.has(chainMethod) && chainMethod !== 'route') break
      if (!ctx.consumeMatchAttempt()) break
      const chainOpen = pos + chain[0].length - 1
      const { args, closeIndex } = ctx.argsAtCall(chainOpen, MAX_FUNCTION_BODY_SCAN_BYTES)
      if (closeIndex < 0) break
      if (chainMethod !== 'route' && args.length) {
        const middleware = args.length > 1 ? flattenMiddlewareTokens(args.slice(0, -1), MAX_MIDDLEWARE_PER_ROUTE) : EMPTY_STRINGS
        const guards = guardsFromMiddleware(middleware)
        const handler = handlerNameFromToken(args[args.length - 1])
        if (!ctx.addRoute({
          framework: 'express', method: chainMethod === 'all' ? 'ANY' : chainMethod.toUpperCase(),
          path: basePath, file, line: routeLine, handler,
          routerKey: parent.key,
          middleware,
          guards,
          input: valueOrFallback(basePath),
          extraction: 'ast',
        })) break
      }
      pos = closeIndex + 1
    }
  }
}

function extractNest(file: string, content: string, out: Extraction, ctx: FileExtractCtx): boolean {
  let matchedAnyController = false
  for (const match of content.matchAll(/@Controller[ \t]{0,16}\(([^)]{0,512})\)/g)) {
    matchedAnyController = true
    if (!ctx.routesRemaining() || !ctx.consumeMatchAttempt()) break
    const classIndex = content.indexOf('class', match.index + match[0].length)
    if (classIndex < 0) break
    const bodyOpen = nextBraceOpen(ctx.delimiters.braceOpens, classIndex)
    if (bodyOpen < 0) break
    const bodyClose = ctx.findBraceClose(bodyOpen)
    if (bodyClose < 0) continue
    const classPrefix = stringListValue(splitTopLevel(match[1], 0, match[1].length)[0])[0] ?? ''
    const header = content.slice(match.index, Math.min(classIndex, match.index + 2048))
    const classGuards = decoratorGuards(header)
    const body = content.slice(bodyOpen + 1, bodyClose)

    for (const routeMatch of body.matchAll(/@(Get|Post|Put|Patch|Delete|Options|Head|All)[ \t]{0,16}\(([^)]{0,512})\)/g)) {
      if (!ctx.routesRemaining() || !ctx.consumeMatchAttempt()) break
      const decoratorStart = bodyOpen + 1 + routeMatch.index
      const routeArgs = splitTopLevel(routeMatch[2], 0, routeMatch[2].length)
      const routePath = stringListValue(routeArgs[0])[0] ?? ''
      const decoratorRegion = content.slice(decoratorStart, Math.min(content.length, decoratorStart + 700))
      const handlerMatch = /(?:^|\n)[ \t]{0,64}(?:(?:public|private|protected|static|async|readonly)[ \t]{1,16}){0,6}([A-Za-z_$][\w$]{0,127})[ \t]{0,16}\(/g
      let handler = 'anonymous'
      let handlerLine: number | undefined
      let methodDecorators = ''
      let handlerSignature = ''
      for (const hm of decoratorRegion.matchAll(handlerMatch)) {
        if (['if', 'for', 'while', 'switch', 'catch'].includes(hm[1])) continue
        handler = hm[1]
        const signatureOpen = decoratorStart + (hm.index ?? 0) + hm[0].length - 1
        handlerSignature = ctx.argsAtCall(signatureOpen, MAX_CALL_ARGS_SCAN_BYTES).args.join(', ')
        handlerLine = ctx.lineAt(decoratorStart + (hm.index ?? 0))
        methodDecorators = decoratorRegion.slice(0, hm.index)
        break
      }
      const methodGuards = decoratorGuards(methodDecorators)
      const method = routeMatch[1].toUpperCase() === 'ALL' ? 'ANY' : routeMatch[1].toUpperCase()
      const basePrefix = joinPathsBounded('', classPrefix, out.warnings, file)
      const fullPath = basePrefix !== null ? joinPathsBounded(basePrefix, routePath, out.warnings, file) : null
      if (fullPath === null) continue
      const combinedGuards = [...new Set([...classGuards, ...methodGuards])].slice(0, MAX_MIDDLEWARE_PER_ROUTE)
      if (!ctx.addRoute({
        framework: 'nestjs', method, path: fullPath, file,
        line: ctx.lineAt(decoratorStart), handler,
        ...(handlerLine ? { handlerLine } : {}),
        middleware: combinedGuards,
        guards: combinedGuards,
        input: inputFromSignature(handlerSignature),
        extraction: 'ast',
      })) break
    }
  }
  return matchedAnyController
}

const DECORATOR_GUARD_NAMES = new Set([
  'UseGuards', 'Roles', 'Permissions', 'PreAuthorize', 'Secured', 'RolesAllowed', 'Authorize',
])

/** Strictly linear O(n) decorator guard extractor (replaces nested-quantifier regex). */
function decoratorGuards(text: string): string[] {
  const guards: string[] = []
  const seen = new Set<string>()
  const len = Math.min(text.length, 8192)
  let pos = 0
  while (pos < len && guards.length < MAX_MIDDLEWARE_PER_ROUTE) {
    const at = text.indexOf('@', pos)
    if (at < 0 || at >= len) break
    let nameEnd = at + 1
    while (nameEnd < len && isJavaIdentPart(text.charCodeAt(nameEnd))) nameEnd += 1
    const name = text.slice(at + 1, nameEnd)
    pos = nameEnd
    if (!DECORATOR_GUARD_NAMES.has(name)) continue
    let p = nameEnd
    while (p < len && (text.charCodeAt(p) === 32 || text.charCodeAt(p) === 9)) p += 1
    if (p >= len || text.charCodeAt(p) !== 40) continue
    const close = findMatching(text, p, { open: '(', close: ')', maxScan: 512 })
    if (close < 0 || close - p > 512) {
      pos = p + 1
      continue
    }
    const inner = text.slice(p + 1, close).replace(/\s+/g, '').slice(0, MAX_MIDDLEWARE_TOKEN_LENGTH)
    const formatted = `${name}(${inner})`
    if (!seen.has(formatted)) {
      seen.add(formatted)
      guards.push(formatted)
    }
    pos = close + 1
  }
  return guards
}

function extractNext(file: string, content: string, _out: Extraction, ctx: FileExtractCtx): boolean {
  const normalized = file.replaceAll('\\', '/')
  const appRoute = /(?:^|\/)(?:src\/)?app\/(.+)\/route\.(?:[jt]sx?)$/.exec(normalized)
  const pagesRoute = /(?:^|\/)(?:src\/)?pages\/(api\/.+)\.(?:[jt]sx?)$/.exec(normalized)
  if (!appRoute && !pagesRoute) return false

  const routePath = `/${(appRoute?.[1] ?? pagesRoute?.[1] ?? '').replace(/\[\[?\.\.\.([^\]]+)\]\]?/g, ':$1').replace(/\[([^\]]+)\]/g, ':$1')}`
  const methods = new Map<string, number>()
  if (appRoute) {
    for (const match of content.matchAll(/(?<![\w$])export[ \t]{1,16}(?:async[ \t]{1,16})?(?:function|const)[ \t]{1,16}(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b/g)) {
      methods.set(match[1], ctx.lineAt(match.index))
    }
    if (!methods.size) methods.set('ANY', 1)
  } else {
    for (const match of content.matchAll(/(?<![\w$])req\.method[ \t]{0,16}===?[ \t]{0,16}['"](\w{1,16})['"]/g)) {
      methods.set(match[1].toUpperCase(), ctx.lineAt(match.index))
    }
    if (!methods.size) methods.set('ANY', 1)
  }
  const middleware: string[] = []
  const mwSeen = new Set<string>()
  for (const match of content.matchAll(/(?<![\w$])with(?:Auth|Admin|User|Role|Permission)[ \t]{0,16}\(/g)) {
    const tok = match[0].replace(/[ \t]*\($/, '')
    if (!mwSeen.has(tok) && middleware.length < MAX_MIDDLEWARE_PER_ROUTE) {
      mwSeen.add(tok)
      middleware.push(tok)
    }
  }
  const guards = guardsFromMiddleware(middleware)
  for (const [method, line] of methods) {
    if (!ctx.addRoute({
      framework: 'nextjs', method, path: routePath, file, line,
      handler: appRoute ? method : 'default',
      middleware, guards,
      input: valueOrFallback(routePath), extraction: 'ast',
    })) break
  }
  return true
}

function extractPythonRoutes(file: string, content: string, out: Extraction, ctx: FileExtractCtx): boolean {
  const hasFastApi = /(?:FastAPI|APIRouter)[ \t]{0,16}\(/.test(content)
  const hasFlask = /(?:Flask|Blueprint)[ \t]{0,16}\(/.test(content)
  if (!hasFastApi && !hasFlask) return false

  const routerVars = new Map<string, RouterDef>()
  const addRouter = (name: string, prefix: string, middleware: string[], framework: 'fastapi' | 'flask') => {
    if (routerVars.size >= 256) return
    const key = `${file}#${framework}:${name}`
    const router: RouterDef = { key, name, file, prefix: prefix.slice(0, MAX_MOUNT_PATH_LENGTH), middleware: middleware.slice(0, MAX_MIDDLEWARE_PER_ROUTER) }
    routerVars.set(name, router)
    out.routers.push(router)
  }

  if (hasFastApi) {
    for (const match of content.matchAll(/(?<![\w$])([A-Za-z_]\w{0,63})[ \t]{0,16}=[ \t]{0,16}(?:fastapi[ \t]{0,8}\.[ \t]{0,8})?(?:FastAPI|APIRouter)[ \t]{0,16}\(/g)) {
      if (!ctx.consumeMatchAttempt()) break
      const open = match.index + match[0].length - 1
      const { args } = ctx.argsAtCall(open, MAX_CALL_ARGS_SCAN_BYTES)
      const prefix = args.map(a => /prefix[ \t]{0,8}=[ \t]{0,8}(['"])([^'"\r\n]{0,256})\1/.exec(a)?.[2]).find(Boolean) ?? ''
      const deps = args.map(a => /dependencies[ \t]{0,8}=[ \t]{0,8}\[([^\]]{0,1024})\]/.exec(a)?.[1]).find(Boolean)
      const middleware = deps ? [...deps.matchAll(/Depends[ \t]{0,8}\([ \t]{0,8}([\w.]{1,64})/g)].map(m => `Depends(${m[1]})`).slice(0, MAX_MIDDLEWARE_PER_ROUTER) : []
      addRouter(match[1], prefix, middleware, 'fastapi')
    }
    for (const match of content.matchAll(/@[ \t]{0,16}([A-Za-z_]\w{0,63})[ \t]{0,8}\.[ \t]{0,8}(get|post|put|patch|delete|head|options)[ \t]{0,16}\(/g)) {
      if (!ctx.routesRemaining()) break
      const router = routerVars.get(match[1])
      if (!router) continue
      if (!ctx.consumeMatchAttempt()) break
      const open = match.index + match[0].length - 1
      const { args } = ctx.argsAtCall(open, MAX_CALL_ARGS_SCAN_BYTES)
      const routePath = stringListValue(args[0])[0]
      if (routePath === undefined) continue
      const deps = args.map(a => /dependencies[ \t]{0,8}=[ \t]{0,8}\[([^\]]{0,1024})\]/.exec(a)?.[1]).find(Boolean)
      const routeMiddleware = deps ? [...deps.matchAll(/Depends[ \t]{0,8}\([ \t]{0,8}([\w.]{1,64})/g)].map(m => `Depends(${m[1]})`).slice(0, MAX_MIDDLEWARE_PER_ROUTE) : EMPTY_STRINGS
      const afterStart = open
      const defMatch = /(?:async[ \t]{1,16})?def[ \t]{1,16}([A-Za-z_]\w{0,63})[ \t]{0,16}\(/.exec(content.slice(afterStart, afterStart + 1200))
      const defOpen = defMatch ? afterStart + (defMatch.index ?? 0) + defMatch[0].length - 1 : -1
      const signature = defMatch && defOpen >= 0 ? ctx.argsAtCall(defOpen, MAX_CALL_ARGS_SCAN_BYTES).args.join(', ') : ''
      if (!ctx.addRoute({
        framework: 'fastapi', method: match[2].toUpperCase(), path: routePath, file,
        line: ctx.lineAt(match.index), handler: defMatch?.[1] ?? 'anonymous',
        routerKey: router.key,
        middleware: routeMiddleware,
        guards: guardsFromMiddleware(routeMiddleware),
        input: defMatch ? inputFromSignature(signature) : valueOrFallback(routePath),
        extraction: 'ast',
      })) break
    }
    for (const match of content.matchAll(/(?<![\w$])include_router[ \t]{0,16}\(/g)) {
      if (!ctx.consumeMatchAttempt()) break
      const open = match.index + match[0].length - 1
      const { args } = ctx.argsAtCall(open, MAX_CALL_ARGS_SCAN_BYTES)
      const childToken = args[0]?.trim() ?? ''
      const childName = childToken.split('.').pop() ?? childToken
      const prefix = args.map(a => /prefix[ \t]{0,8}=[ \t]{0,8}(['"])([^'"\r\n]{0,256})\1/.exec(a)?.[2]).find(Boolean) ?? ''
      const parent = routerVars.get('app') ?? routerVars.get('application') ?? [...routerVars.values()].find(r => r.name === 'app')
      if (!ctx.addMount({
        ...(parent ? { parentKey: parent.key } : {}),
        parentFile: file, parentName: parent?.name ?? 'app',
        ...(routerVars.get(childName) ? { childKey: routerVars.get(childName)!.key } : {}),
        childName, childFile: file, prefix, middleware: EMPTY_STRINGS,
        file, line: ctx.lineAt(match.index),
      })) break
    }
  }

  if (hasFlask) {
    for (const match of content.matchAll(/(?<![\w$])([A-Za-z_]\w{0,63})[ \t]{0,16}=[ \t]{0,16}(?:flask[ \t]{0,8}\.[ \t]{0,8})?(?:Flask|Blueprint)[ \t]{0,16}\(/g)) {
      if (!ctx.consumeMatchAttempt()) break
      const open = match.index + match[0].length - 1
      const { args } = ctx.argsAtCall(open, MAX_CALL_ARGS_SCAN_BYTES)
      const prefix = args.map(a => /url_prefix[ \t]{0,8}=[ \t]{0,8}(['"])([^'"\r\n]{0,256})\1/.exec(a)?.[2]).find(Boolean) ?? ''
      addRouter(match[1], prefix, [], 'flask')
    }
    for (const match of content.matchAll(/@[ \t]{0,16}([A-Za-z_]\w{0,63})[ \t]{0,8}\.[ \t]{0,8}(get|post|put|patch|delete|head|options|route)[ \t]{0,16}\(/g)) {
      if (!ctx.routesRemaining()) break
      const router = routerVars.get(match[1])
      if (!router) continue
      if (!ctx.consumeMatchAttempt()) break
      const open = match.index + match[0].length - 1
      const { args } = ctx.argsAtCall(open, MAX_CALL_ARGS_SCAN_BYTES)
      const routePath = stringListValue(args[0])[0]
      if (routePath === undefined) continue
      const methodsArg = args.map(a => /methods[ \t]{0,8}=[ \t]{0,8}\[([^\]]{0,256})\]/.exec(a)?.[1]).find(Boolean)
      const methods = methodsArg ? stringListValue(`[${methodsArg}]`).map(m => m.toUpperCase()).slice(0, 12) : [match[2].toUpperCase()]
      const defMatch = /(?:async[ \t]{1,16})?def[ \t]{1,16}([A-Za-z_]\w{0,63})[ \t]{0,16}\(/.exec(content.slice(open, open + 800))
      const defOpen = defMatch ? open + (defMatch.index ?? 0) + defMatch[0].length - 1 : -1
      const signature = defMatch && defOpen >= 0 ? ctx.argsAtCall(defOpen, MAX_CALL_ARGS_SCAN_BYTES).args.join(', ') : ''
      const line = ctx.lineAt(match.index)
      for (const method of methods) {
        if (!ctx.addRoute({
          framework: 'flask', method: method === 'ROUTE' ? 'ANY' : method, path: routePath, file,
          line, handler: defMatch?.[1] ?? 'anonymous',
          routerKey: router.key, middleware: EMPTY_STRINGS,
          guards: EMPTY_STRINGS,
          input: defMatch ? inputFromSignature(signature) : valueOrFallback(routePath),
          extraction: 'ast',
        })) break
      }
    }
    for (const match of content.matchAll(/(?<![\w$])register_blueprint[ \t]{0,16}\(/g)) {
      if (!ctx.consumeMatchAttempt()) break
      const open = match.index + match[0].length - 1
      const { args } = ctx.argsAtCall(open, MAX_CALL_ARGS_SCAN_BYTES)
      const childName = (args[0] ?? '').trim().split('.').pop() ?? ''
      const prefix = args.map(a => /url_prefix[ \t]{0,8}=[ \t]{0,8}(['"])([^'"\r\n]{0,256})\1/.exec(a)?.[2]).find(Boolean) ?? ''
      const parent = [...routerVars.values()].find(r => r.name === 'app')
      if (!ctx.addMount({
        ...(parent ? { parentKey: parent.key } : {}),
        parentFile: file, parentName: parent?.name ?? 'app',
        ...(routerVars.get(childName) ? { childKey: routerVars.get(childName)!.key } : {}),
        childName, childFile: file, prefix, middleware: EMPTY_STRINGS,
        file, line: ctx.lineAt(match.index),
      })) break
    }
  }
  return true
}

function extractDjango(file: string, content: string, out: Extraction, ctx: FileExtractCtx): boolean {
  if (!/(?<![\w$])urlpatterns[ \t]{0,16}=/.test(content)) return false
  const moduleName = file.replaceAll('\\', '/').replace(/\.py$/, '').replaceAll('/', '.')
  const moduleKey = `${file}#django:${moduleName}`
  out.routers.push({ key: moduleKey, name: moduleName, file, prefix: '', middleware: [] })

  // Linear O(n) line-by-line decorator collector (replaces nested-quantifier multiline regex).
  const viewGuards = new Map<string, string[]>()
  const lines = content.split('\n')
  let pendingDecorators: string[] = []
  for (let i = 0; i < lines.length; i += 1) {
    const rawLine = lines[i]
    if (rawLine.length > MAX_SCAN_LINE_LENGTH) {
      pendingDecorators = []
      continue
    }
    const trimmed = rawLine.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    if (trimmed.startsWith('@')) {
      if (pendingDecorators.length < 16) pendingDecorators.push(trimmed.slice(0, 256))
      continue
    }
    const defMatch = /^(?:async[ \t]{1,16})?def[ \t]{1,16}([A-Za-z_]\w{0,63})\b/.exec(trimmed)
    if (defMatch && pendingDecorators.length > 0) {
      const guards: string[] = []
      for (const dec of pendingDecorators) {
        const dm = /^@(\w{1,64})[ \t]{0,8}(?:\(([^)]{0,160})\))?/.exec(dec)
        if (!dm) continue
        const label = `${dm[1]}(${dm[2] ?? ''})`
        if (AUTH_GUARD_RE.test(label) || ADMIN_GUARD_RE.test(label) || TENANT_GUARD_RE.test(label)) {
          guards.push(label)
        }
      }
      if (guards.length > 0) viewGuards.set(defMatch[1], guards)
    }
    pendingDecorators = []
  }

  for (const match of content.matchAll(/(?<![\w$])(?:path|re_path)[ \t]{0,16}\(/g)) {
    if (!ctx.routesRemaining() || !ctx.consumeMatchAttempt()) break
    const open = match.index + match[0].length - 1
    const { args } = ctx.argsAtCall(open, MAX_CALL_ARGS_SCAN_BYTES)
    const routePath = stringLiteralValue(args[0])
    if (routePath === null) continue
    const viewToken = args[1] ?? ''
    const line = ctx.lineAt(match.index)
    const includeMatch = /(?<![\w$])include[ \t]{0,8}\([ \t]{0,8}['"]([^'"\r\n]{1,256})['"]/.exec(viewToken)
    if (includeMatch) {
      const target = includeMatch[1]
      if (!ctx.addMount({
        parentKey: moduleKey, parentFile: file, parentName: moduleName,
        childName: target,
        childFile: target.includes('.') ? `${target.replaceAll('.', '/')}.py` : `${target.replace(/\/$/, '')}/urls.py`,
        prefix: routePath.slice(0, MAX_MOUNT_PATH_LENGTH), middleware: EMPTY_STRINGS, file, line,
      })) break
      continue
    }
    const viewName = handlerNameFromToken(viewToken.replace(/\.as_view[ \t]{0,8}\([^)]{0,128}\)/, ''))
    const guards = viewGuards.get(viewName) ?? EMPTY_STRINGS
    const methods = [...viewToken.matchAll(/['"](GET|POST|PUT|PATCH|DELETE)['"]/g)].map(m => m[1])
    const djangoPath = routePath
      .slice(0, MAX_MOUNT_PATH_LENGTH)
      .replace(/<(?:\w{1,32}:)?(\w{1,64})>/g, ':$1')
      .replace(/\(\?P<(\w{1,64})>[^)]{1,128}\)/g, ':$1')
    if (!ctx.addRoute({
      framework: 'django', method: methods[0] ?? 'ANY', path: djangoPath, file, line,
      handler: viewName, routerKey: moduleKey, middleware: EMPTY_STRINGS, guards,
      input: valueOrFallback(djangoPath), extraction: 'ast',
    })) break
  }
  for (const match of content.matchAll(/(?<![\w$])router[ \t]{0,16}\.[ \t]{0,16}register[ \t]{0,16}\([ \t]{0,16}(['"])([^'"\r\n]{1,256})\1/g)) {
    if (!ctx.routesRemaining() || !ctx.consumeMatchAttempt()) break
    const base = match[2].startsWith('/') ? match[2] : `/${match[2]}`
    const line = ctx.lineAt(match.index)
    const crud: Array<[string, string, string]> = [
      ['GET', base, 'list'], ['POST', base, 'create'],
      ['GET', `${base}/:pk`, 'retrieve'], ['PUT', `${base}/:pk`, 'update'],
      ['PATCH', `${base}/:pk`, 'partial_update'], ['DELETE', `${base}/:pk`, 'destroy'],
    ]
    for (const [method, routePath, action] of crud) {
      if (!ctx.addRoute({
        framework: 'django', method, path: routePath, file, line, handler: `${base.slice(1)}_${action}`,
        routerKey: moduleKey, middleware: EMPTY_STRINGS, guards: EMPTY_STRINGS,
        input: valueOrFallback(routePath), extraction: 'ast',
      })) break
    }
  }
  return true
}

function extractSpring(file: string, content: string, out: Extraction, ctx: FileExtractCtx): boolean {
  if (!/@(?:RestController|Controller|RequestMapping|GetMapping|PostMapping)\b/.test(content)) return false
  const { braceOpens, braceClose, parenClose } = ctx.delimiters

  // Linear O(n) class scanner + bounded lookback for class-level annotations (no nested quantifier regex).
  for (const match of content.matchAll(/(?<![\w$])class[ \t]{1,16}([A-Za-z_]\w{0,63})\b/g)) {
    if (!ctx.routesRemaining()) break
    const classPos = match.index
    const lookbackStart = Math.max(0, classPos - 2048)
    let headerStart = lookbackStart
    for (let k = classPos - 1; k >= lookbackStart; k -= 1) {
      const ch = content.charCodeAt(k)
      if (ch === 125 || ch === 59) { // '}' or ';' ends previous declaration
        headerStart = k + 1
        break
      }
    }
    const classDecorators = content.slice(headerStart, classPos)
    if (!classDecorators.includes('@')) continue

    let basePath = ''
    const reqMapIdx = classDecorators.indexOf('@RequestMapping')
    if (reqMapIdx >= 0) {
      const openRel = classDecorators.indexOf('(', reqMapIdx + 15)
      if (openRel >= 0 && openRel - (reqMapIdx + 15) <= 16) {
        const closeRel = findMatching(classDecorators, openRel, { open: '(', close: ')', maxScan: 512 })
        if (closeRel > openRel && closeRel - openRel <= 512) {
          const classBase = classDecorators.slice(openRel + 1, closeRel)
          basePath = stringListValue(splitTopLevel(classBase, 0, classBase.length).find(a => !/method[ \t]{0,8}=/.test(a)) ?? '')[0] ?? ''
        }
      }
    }
    const classGuards = decoratorGuards(classDecorators)
    const bodyOpen = nextBraceOpen(braceOpens, classPos + match[0].length)
    if (bodyOpen < 0) continue
    const bodyClose = braceClose.get(bodyOpen) ?? -1
    if (bodyClose < 0) continue

    const mappingRe = /@(Get|Post|Put|Patch|Delete|Request)Mapping[ \t]{0,16}\(/g
    mappingRe.lastIndex = bodyOpen + 1
    let routeMatch: RegExpExecArray | null
    while ((routeMatch = mappingRe.exec(content)) !== null && routeMatch.index < bodyClose) {
      if (!ctx.routesRemaining() || !ctx.consumeMatchAttempt()) break
      const decoratorStart = routeMatch.index
      const openParen = routeMatch.index + routeMatch[0].length - 1
      const closeParen = parenClose.get(openParen)
      if (closeParen === undefined || closeParen > bodyClose || closeParen - openParen > 1024) continue
      const argSlice = content.slice(openParen + 1, closeParen)
      const routeArgs = splitTopLevel(argSlice, 0, argSlice.length)
      const pathToken = routeArgs.find(a => !/method[ \t]{0,8}=/.test(a)) ?? ''
      const routePath = stringListValue(pathToken)[0] ?? ''
      let methods: string[] = []
      const explicit = /RequestMethod\.(\w{1,16})/.exec(argSlice)?.[1]
      if (explicit) methods = [explicit.toUpperCase()]
      else if (routeMatch[1] !== 'Request') methods = [routeMatch[1].toUpperCase()]
      else methods = ['ANY']
      const region = content.slice(decoratorStart, Math.min(bodyClose, decoratorStart + 1500))
      const javaHandlers = scanJavaMethodHeaders(region, true)
      let handler = 'anonymous'
      let signature = ''
      let methodDecorators = ''
      if (javaHandlers.length > 0) {
        const hm = javaHandlers[0]
        handler = hm.name
        const signatureOpen = decoratorStart + hm.openParen
        signature = ctx.argsAtCall(signatureOpen, MAX_CALL_ARGS_SCAN_BYTES).args.join(', ')
        methodDecorators = region.slice(0, hm.index)
      }
      const methodGuards = decoratorGuards(methodDecorators)
      const input = inputFromSignature(signature)
      input.params.push(...routeParamNames(routePath))
      const baseNormalized = joinPathsBounded('', basePath, out.warnings, file)
      const fullPath = baseNormalized !== null ? joinPathsBounded(baseNormalized, routePath, out.warnings, file) : null
      if (fullPath === null) continue
      const combinedGuards = [...new Set([...classGuards, ...methodGuards])].slice(0, MAX_MIDDLEWARE_PER_ROUTE)
      const line = ctx.lineAt(decoratorStart)
      for (const method of methods) {
        if (!ctx.addRoute({
          framework: 'spring', method, path: fullPath, file,
          line, handler,
          middleware: combinedGuards,
          guards: combinedGuards,
          input: { ...input, params: [...new Set(input.params)] },
          extraction: 'ast',
        })) break
      }
    }
  }
  return true
}

function extractGin(file: string, content: string, out: Extraction, ctx: FileExtractCtx): boolean {
  if (!/\bgin\.(?:Default|New)[ \t]{0,16}\(/.test(content)) return false
  interface Event { index: number; kind: 'group' | 'route'; name: string; method?: string; path?: string; args?: string[] }
  const events: Event[] = []
  const MAX_GIN_EVENTS = MAX_RAW_ROUTES_PER_FILE * 2 + 256

  for (const match of content.matchAll(/(?<![\w$])([A-Za-z_]\w{0,63})[ \t]{0,16}:?=[ \t]{0,16}([A-Za-z_]\w{0,63})[ \t]{0,16}\.[ \t]{0,16}Group[ \t]{0,16}\([ \t]{0,16}(['"])([^'"\r\n]{0,512})\3/g)) {
    if (events.length >= MAX_GIN_EVENTS) break
    events.push({ index: match.index, kind: 'group', name: match[1], path: match[4], args: [match[2]] })
  }
  for (const match of content.matchAll(/(?<![\w$])([A-Za-z_]\w{0,63})[ \t]{0,16}\.[ \t]{0,16}(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|Any)[ \t]{0,16}\([ \t]{0,16}(['"])([^'"\r\n]{0,512})\3[ \t]{0,16},/g)) {
    if (events.length >= MAX_GIN_EVENTS || !ctx.consumeMatchAttempt()) break
    const open = content.indexOf('(', match.index)
    const { args } = ctx.argsAtCall(open, MAX_CALL_ARGS_SCAN_BYTES)
    events.push({ index: match.index, kind: 'route', name: match[1], method: match[2], path: match[4], args })
  }
  events.sort((a, b) => a.index - b.index)

  const prefixes = new Map<string, string>()
  const groupDepth = new Map<string, number>()
  const groupAncestors = new Map<string, Set<string>>()
  let selfGroupWarned = 0
  let depthWarned = false

  for (const event of events) {
    if (!ctx.routesRemaining()) break
    if (event.kind === 'group') {
      const parent = event.args?.[0] ?? ''
      if (event.name === parent) {
        if (selfGroupWarned < 5) {
          ctx.addWarning(`Skipped self-referential Gin group "${event.name}" at ${file}:${ctx.lineAt(event.index)}`)
          selfGroupWarned += 1
        }
        continue
      }
      const parentAncestors = groupAncestors.get(parent)
      if (parentAncestors?.has(event.name)) {
        if (selfGroupWarned < 5) {
          ctx.addWarning(`Skipped cyclic Gin group "${event.name}" <- "${parent}" at ${file}:${ctx.lineAt(event.index)}`)
          selfGroupWarned += 1
        }
        continue
      }
      const nextDepth = (groupDepth.get(parent) ?? 0) + 1
      if (nextDepth > MAX_ROUTER_MOUNT_DEPTH) {
        if (!depthWarned) {
          ctx.addWarning(`Gin group nesting depth capped at ${MAX_ROUTER_MOUNT_DEPTH} in ${file}`)
          depthWarned = true
        }
        continue
      }
      const nextPrefix = joinPathsBounded(prefixes.get(parent) ?? '', event.path ?? '', out.warnings, `${file}:${ctx.lineAt(event.index)}`)
      if (nextPrefix === null) continue
      prefixes.set(event.name, nextPrefix)
      groupDepth.set(event.name, nextDepth)
      const nextAncestors = new Set<string>(parentAncestors)
      nextAncestors.add(parent)
      groupAncestors.set(event.name, nextAncestors)
      continue
    }
    const routeArgs = event.args ?? []
    const middleware = routeArgs.length > 2 ? flattenMiddlewareTokens(routeArgs.slice(1, -1), MAX_MIDDLEWARE_PER_ROUTE) : EMPTY_STRINGS
    const handler = handlerNameFromToken(routeArgs[routeArgs.length - 1] ?? 'anonymous')
    const method = event.method === 'Any' ? 'ANY' : (event.method ?? 'ANY')
    const fullPath = joinPathsBounded(prefixes.get(event.name) ?? '', event.path ?? '', out.warnings, `${file}:${ctx.lineAt(event.index)}`)
    if (fullPath === null) continue
    if (!ctx.addRoute({
      framework: 'gin', method, path: fullPath, file, line: ctx.lineAt(event.index), handler,
      middleware, guards: guardsFromMiddleware(middleware),
      input: valueOrFallback(fullPath), extraction: 'ast',
    })) break
  }
  return true
}

function extractChi(file: string, content: string, out: Extraction, ctx: FileExtractCtx): boolean {
  if (!/chi\.(?:NewRouter|Router)/.test(content)) return false
  const prefixes = new Map<string, string>()
  const { braceOpens, braceClose } = ctx.delimiters
  const chiEventRe = /(?<![\w$])([A-Za-z_]\w{0,63})[ \t]{0,16}\.[ \t]{0,16}(Route|Mount|Group|With|Get|Post|Put|Patch|Delete|Head|Options|Handle|Any)[ \t]{0,16}\(/g
  const chiWithChainRe = /[ \t\r\n]{0,32}\.[ \t\r\n]{0,16}(Get|Post|Put|Patch|Delete|Head|Options|Handle|Any)[ \t\r\n]{0,16}\(/y

  const parseBlock = (start: number, end: number, prefix: string, depth: number) => {
    if (depth > MAX_ROUTER_MOUNT_DEPTH || !ctx.routesRemaining()) return
    let cursor = start
    while (cursor < end && ctx.routesRemaining()) {
      chiEventRe.lastIndex = cursor
      const event = chiEventRe.exec(content)
      if (!event || event.index >= end) break
      if (!ctx.consumeMatchAttempt()) break
      const callIndex = event.index + event[0].length - 1
      const { args, closeIndex } = ctx.argsAtCall(callIndex, MAX_CALL_ARGS_SCAN_BYTES)
      if (closeIndex < 0 || closeIndex > end) break
      const verb = event[2]
      if (verb === 'Route' || verb === 'Mount' || verb === 'Group') {
        const routePath = verb === 'Group' ? '' : stringListValue(args[0])[0]
        if (verb === 'Mount') {
          const child = (args[1] ?? '').trim()
          if (routePath !== undefined && child) {
            const joined = joinPathsBounded(prefix, routePath, out.warnings, file)
            if (joined !== null) prefixes.set(child, joined)
          }
        } else if (routePath !== undefined) {
          const bodyOpen = nextBraceOpen(braceOpens, callIndex)
          if (bodyOpen > 0 && bodyOpen < end) {
            const bodyClose = braceClose.get(bodyOpen) ?? -1
            if (bodyClose > bodyOpen && bodyClose <= end) {
              const nextPrefix = joinPathsBounded(prefix, routePath, out.warnings, file)
              if (nextPrefix !== null) {
                parseBlock(bodyOpen + 1, bodyClose, nextPrefix, depth + 1)
              }
              cursor = bodyClose + 1
              continue
            }
          }
        }
      } else if (verb === 'With') {
        const middleware = flattenMiddlewareTokens(args, MAX_MIDDLEWARE_PER_ROUTE)
        const guards = guardsFromMiddleware(middleware)
        let pos = closeIndex + 1
        let chainSteps = 0
        while (pos < end && chainSteps < 32 && ctx.routesRemaining()) {
          chainSteps += 1
          chiWithChainRe.lastIndex = pos
          const chain = chiWithChainRe.exec(content)
          if (!chain || chain.index >= end) break
          if (!ctx.consumeMatchAttempt()) break
          const chainOpen = pos + chain[0].length - 1
          const chainArgs = ctx.argsAtCall(chainOpen, MAX_CALL_ARGS_SCAN_BYTES)
          if (chainArgs.closeIndex < 0 || chainArgs.closeIndex > end) break
          const routePath = stringListValue(chainArgs.args[0])[0]
          if (routePath !== undefined) {
            const handler = handlerNameFromToken(chainArgs.args[chainArgs.args.length - 1] ?? 'anonymous')
            const fullPath = joinPathsBounded(prefix, routePath, out.warnings, file)
            if (fullPath !== null) {
              if (!ctx.addRoute({
                framework: 'chi', method: chain[1] === 'Any' || chain[1] === 'Handle' ? 'ANY' : chain[1].toUpperCase(),
                path: fullPath, file, line: ctx.lineAt(event.index), handler,
                middleware, guards,
                input: valueOrFallback(fullPath), extraction: 'ast',
              })) break
            }
          }
          pos = chainArgs.closeIndex + 1
        }
        cursor = pos
        continue
      } else {
        const routePath = stringListValue(args[0])[0]
        if (routePath !== undefined) {
          const middleware = args.length > 2 ? flattenMiddlewareTokens(args.slice(1, -1), MAX_MIDDLEWARE_PER_ROUTE) : EMPTY_STRINGS
          const handler = handlerNameFromToken(args[args.length - 1] ?? 'anonymous')
          const fullPath = joinPathsBounded(prefix, routePath, out.warnings, file)
          if (fullPath !== null) {
            if (!ctx.addRoute({
              framework: 'chi', method: verb === 'Handle' || verb === 'Any' ? 'ANY' : verb.toUpperCase(),
              path: fullPath, file, line: ctx.lineAt(event.index), handler,
              middleware, guards: guardsFromMiddleware(middleware),
              input: valueOrFallback(fullPath), extraction: 'ast',
            })) break
          }
        }
      }
      cursor = closeIndex + 1
    }
  }
  parseBlock(0, content.length, '', 0)
  return true
}

/** Parse Rails `only: [:index, :show]` linearly without backtracking regexes. */
function parseRailsOnlyActions(line: string): Set<string> | undefined {
  const onlyIdx = line.indexOf('only:')
  if (onlyIdx < 0) return undefined
  const bracketOpen = line.indexOf('[', onlyIdx + 5)
  if (bracketOpen < 0 || bracketOpen - (onlyIdx + 5) > 32) return undefined
  const bracketClose = line.indexOf(']', bracketOpen + 1)
  if (bracketClose < 0 || bracketClose - bracketOpen > 256) return undefined
  const slice = line.slice(bracketOpen + 1, bracketClose)
  const set = new Set<string>()
  for (const m of slice.matchAll(/:(\w{1,32})/g)) {
    set.add(m[1])
    if (set.size >= 16) break
  }
  return set
}

/** Parse a Rails `namespace`/`scope ... do` line in strictly linear O(line.length) time. */
function parseRailsNamespaceLine(trimmed: string): { segment: string; isModuleScope: boolean } | null {
  // Fast end-of-line check for `do` (optionally followed by block params `|...|` or `# comment`).
  const hashIdx = trimmed.indexOf('#')
  const codePart = (hashIdx >= 0 ? trimmed.slice(0, hashIdx) : trimmed).trimEnd()
  if (!/(?:^|[ \t])do(?:[ \t]*\|[^|]{0,64}\|)?$/.test(codePart)) return null
  const head = /^(namespace|scope)[ \t]+(?::([A-Za-z_]\w{0,63})|(['"])([^'"\r\n]{1,128})\3)/.exec(codePart)
  if (!head) return null
  const segment = head[2] ?? head[4] ?? ''
  const isModuleScope = head[1] === 'scope' && /\bmodule:/.test(codePart)
  return { segment, isModuleScope }
}

function extractRails(file: string, content: string, out: Extraction, ctx: FileExtractCtx): boolean {
  if (!/Rails\.application\.routes\.draw/.test(content)) return false
  const allLines = content.split('\n')
  const lineCount = Math.min(allLines.length, MAX_RAILS_LINES)
  if (allLines.length > MAX_RAILS_LINES) {
    ctx.addWarning(`Rails routes file truncated at ${MAX_RAILS_LINES} lines in ${file}`)
  }

  // Pass 1 (O(n)): Match every `do` block to its closing `end` so unterminated namespace/scope
  // blocks are detected and rejected instead of nesting all the way to EOF (`R2-H-24`, `R2-H-25`).
  interface OpenBlock { lineIdx: number; indent: number; isNs: boolean }
  const openBlocks: OpenBlock[] = []
  const matchedBlockEnd = new Map<number, number>()
  const parsedNsByLine = new Map<number, { segment: string; isModuleScope: boolean }>()
  let longLineWarned = false

  for (let i = 0; i < lineCount; i += 1) {
    const line = allLines[i]
    if (line.length > MAX_SCAN_LINE_LENGTH) {
      if (!longLineWarned) {
        ctx.addWarning(`Skipped oversized Rails line (>${MAX_SCAN_LINE_LENGTH} chars) at ${file}:${i + 1}`)
        longLineWarned = true
      }
      continue
    }
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const indent = line.length - line.trimStart().length

    if (/^end(?:\b|$)/.test(trimmed)) {
      while (openBlocks.length > 0 && openBlocks[openBlocks.length - 1].indent >= indent) {
        const closed = openBlocks.pop()!
        if (closed.isNs) matchedBlockEnd.set(closed.lineIdx, i)
        if (closed.indent === indent) break
      }
      continue
    }

    const ns = parseRailsNamespaceLine(trimmed)
    if (ns) {
      parsedNsByLine.set(i, ns)
      openBlocks.push({ lineIdx: i, indent, isNs: true })
      continue
    }
    // Track non-namespace `do` blocks (e.g. `draw do`, `resources :x do`, `member do`) so their
    // matching `end` closes them rather than prematurely closing an enclosing namespace.
    const hashIdx = trimmed.indexOf('#')
    const codePart = (hashIdx >= 0 ? trimmed.slice(0, hashIdx) : trimmed).trimEnd()
    if (/(?:^|[ \t])do(?:[ \t]*\|[^|]{0,64}\|)?$/.test(codePart)) {
      openBlocks.push({ lineIdx: i, indent, isNs: false })
    }
  }

  const addRoute = (method: string, routePath: string, handler: string, line: number): boolean => {
    if (routePath.length > MAX_MOUNT_PATH_LENGTH) return true
    const normalized = routePath.startsWith('/') ? routePath : `/${routePath}`
    const finalPath = normalizeRouteTemplate(normalized, { preserveParamNames: true, collapseConcreteIds: false })
    if (finalPath.length > MAX_MOUNT_PATH_LENGTH) return true
    return ctx.addRoute({
      framework: 'rails', method, path: finalPath, file, line, handler,
      middleware: EMPTY_STRINGS, guards: EMPTY_STRINGS, input: valueOrFallback(finalPath), extraction: 'ast',
    })
  }

  const expandResources = (resourcePath: string, line: number, only?: Set<string>, prefix = ''): boolean => {
    const base = joinPathsBounded(prefix, `/${resourcePath}`, out.warnings, `${file}:${line}`)
    if (base === null) return true
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
      if (!addRoute(method, routePath, handler, line)) return false
    }
    if (!only) {
      if (!addRoute('GET', `${base}/new`, `${singular}#new`, line)) return false
      if (!addRoute('GET', `${base}/:id/edit`, `${singular}#edit`, line)) return false
    }
    return true
  }

  // Pass 2 (O(n)): Walk lines with bounded namespace stack (max depth 12).
  interface NsFrame { endLine: number; prefix: string }
  const nsStack: NsFrame[] = []
  let unterminatedWarned = false
  let depthWarned = false

  for (let i = 0; i < lineCount && ctx.routesRemaining(); i += 1) {
    while (nsStack.length > 0 && i >= nsStack[nsStack.length - 1].endLine) {
      nsStack.pop()
    }
    const line = allLines[i]
    if (line.length > MAX_SCAN_LINE_LENGTH) continue
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const prefix = nsStack.length > 0 ? nsStack[nsStack.length - 1].prefix : ''

    const ns = parsedNsByLine.get(i)
    if (ns) {
      const endLine = matchedBlockEnd.get(i)
      if (endLine === undefined) {
        if (!unterminatedWarned) {
          ctx.addWarning(`Rejected unterminated Rails namespace/scope block at ${file}:${i + 1}`)
          unterminatedWarned = true
        }
        continue
      }
      if (nsStack.length >= MAX_ROUTER_MOUNT_DEPTH) {
        if (!depthWarned) {
          ctx.addWarning(`Rails namespace nesting depth capped at ${MAX_ROUTER_MOUNT_DEPTH} in ${file}`)
          depthWarned = true
        }
        i = endLine
        continue
      }
      const nextPrefix = ns.isModuleScope
        ? prefix
        : joinPathsBounded(prefix, ns.segment, out.warnings, `${file}:${i + 1}`)
      if (nextPrefix === null) {
        i = endLine
        continue
      }
      nsStack.push({ endLine, prefix: nextPrefix })
      continue
    }

    const resources = /^resources[ \t]+:(\w{1,64})\b/.exec(trimmed)
    if (resources) {
      const only = parseRailsOnlyActions(trimmed)
      if (!expandResources(resources[1], i + 1, only, prefix)) break
      continue
    }
    const resource = /^resource[ \t]+:(\w{1,64})\b/.exec(trimmed)
    if (resource) {
      const base = joinPathsBounded(prefix, `/${resource[1]}`, out.warnings, `${file}:${i + 1}`)
      if (base === null) continue
      if (!addRoute('GET', base, `${resource[1]}#show`, i + 1)) break
      if (!addRoute('POST', base, `${resource[1]}#create`, i + 1)) break
      if (!addRoute('PATCH', base, `${resource[1]}#update`, i + 1)) break
      if (!addRoute('DELETE', base, `${resource[1]}#destroy`, i + 1)) break
      continue
    }
    const verb = /^(get|post|put|patch|delete|match)[ \t]+(['"])([^'"\r\n]{1,512})\2(.*)$/.exec(trimmed)
    if (verb) {
      const tail = verb[4]
      const method = verb[1] === 'match'
        ? (/via:[ \t]{0,8}:(\w{1,16})/.exec(tail)?.[1] ?? 'ANY').toUpperCase()
        : verb[1].toUpperCase()
      const to = /to:[ \t]{0,8}['"]([^'"\r\n]{1,128})['"]/.exec(tail)?.[1] ?? 'anonymous'
      const fullPath = joinPathsBounded(prefix, verb[3], out.warnings, `${file}:${i + 1}`)
      if (fullPath !== null) {
        if (!addRoute(method, fullPath, to, i + 1)) break
      }
    }
  }
  return true
}

function extractFile(file: string, content: string, remainingRouteBudget = MAX_RAW_ROUTES_PER_FILE): Extraction {
  const out: Extraction = { routes: [], routers: [], mounts: [], functions: [], globalMiddleware: [], warnings: [] }
  const lang = languageOfFile(file)
  const normalized = file.replaceAll('\\', '/')
  const newlineOffsets = buildNewlineOffsets(content)
  const delimiters: DelimiterIndex = lang === 'js' || lang === 'python' || lang === 'java' || lang === 'go'
    ? buildDelimiterIndex(content, { hashComments: lang === 'python', cComments: lang !== 'python' })
    : { braceOpens: [], braceClose: new Map(), parenClose: new Map(), bracketClose: new Map() }
  const routeLimit = Math.max(0, Math.min(MAX_RAW_ROUTES_PER_FILE, remainingRouteBudget))
  let rawRouteBytes = 0
  let matchAttempts = 0
  let argScanBytes = 0
  let routeBudgetExhausted = routeLimit <= 0
  let matchBudgetWarned = false
  let argScanBudgetWarned = false
  let routeCapWarned = false
  let byteCapWarned = false
  let pathCapWarned = false
  let mountCapWarned = false

  const consumeArgScanBytes = (bytes: number): boolean => {
    argScanBytes += Math.max(1, bytes)
    if (argScanBytes > MAX_CALL_ARG_SCAN_BYTES_PER_FILE) {
      if (!argScanBudgetWarned) {
        if (out.warnings.length < MAX_FILE_WARNINGS) {
          out.warnings.push(`Call argument scan budget (${MAX_CALL_ARG_SCAN_BYTES_PER_FILE} bytes) exceeded in ${file}`)
        }
        argScanBudgetWarned = true
      }
      return false
    }
    return true
  }

  const ctx: FileExtractCtx = {
    file,
    delimiters,
    lineAt: (index: number) => lineAtFromOffsets(newlineOffsets, index, content.length),
    addWarning: (msg: string) => {
      if (out.warnings.length < MAX_FILE_WARNINGS) out.warnings.push(msg)
    },
    routesRemaining: () => !routeBudgetExhausted,
    consumeMatchAttempt: () => {
      matchAttempts += 1
      if (matchAttempts > MAX_ROUTE_MATCH_ATTEMPTS_PER_FILE) {
        routeBudgetExhausted = true
        if (!matchBudgetWarned) {
          ctx.addWarning(`Route match attempt budget capped at ${MAX_ROUTE_MATCH_ATTEMPTS_PER_FILE} in ${file}`)
          matchBudgetWarned = true
        }
        return false
      }
      return true
    },
    argsAtCall: (openParenIndex: number, maxSpan = MAX_CALL_ARGS_SCAN_BYTES) =>
      argsAtCall(content, openParenIndex, {
        delimiters,
        maxSpan,
        consumeScanBytes: consumeArgScanBytes,
      }),
    findBraceClose: (openBraceIndex: number) => delimiters.braceClose.get(openBraceIndex) ?? -1,
    addRoute: (route: RawRoute) => {
      if (routeBudgetExhausted) return false
      if (out.routes.length >= routeLimit) {
        routeBudgetExhausted = true
        if (!routeCapWarned) {
          ctx.addWarning(`Raw routes capped at ${routeLimit} in ${file}`)
          routeCapWarned = true
        }
        return false
      }
      if (route.path.length > MAX_MOUNT_PATH_LENGTH) {
        if (!pathCapWarned) {
          ctx.addWarning(`Skipped route path exceeding ${MAX_MOUNT_PATH_LENGTH} chars in ${file}`)
          pathCapWarned = true
        }
        return true
      }
      let mwBytes = 0
      for (const m of route.middleware) mwBytes += m.length
      rawRouteBytes += route.path.length + route.handler.length + mwBytes + 64
      if (rawRouteBytes > MAX_RAW_ROUTE_BYTES_PER_FILE) {
        routeBudgetExhausted = true
        if (!byteCapWarned) {
          ctx.addWarning(`Raw route byte budget (${MAX_RAW_ROUTE_BYTES_PER_FILE} bytes) exceeded in ${file}`)
          byteCapWarned = true
        }
        return false
      }
      out.routes.push(route)
      return true
    },
    addMount: (mount: MountSpec) => {
      if (out.mounts.length >= MAX_MOUNTS_PER_FILE) {
        if (!mountCapWarned) {
          ctx.addWarning(`Router mounts capped at ${MAX_MOUNTS_PER_FILE} in ${file}`)
          mountCapWarned = true
        }
        return false
      }
      out.mounts.push(mount)
      return true
    },
  }

  out.functions = extractFunctions(file, content, delimiters, newlineOffsets)

  if (lang === 'js') {
    if (extractNext(normalized, content, out, ctx)) return out
    if (extractNest(file, content, out, ctx)) return out
    extractExpressLike(file, content, out, ctx)
    if (/(?:^|\/)middleware\.[jt]sx?$/.test(normalized)) out.globalMiddleware.push('middleware')
    return out
  }
  if (lang === 'python') {
    extractPythonRoutes(file, content, out, ctx)
    extractDjango(file, content, out, ctx)
    return out
  }
  if (lang === 'java') {
    extractSpring(file, content, out, ctx)
    return out
  }
  if (lang === 'go') {
    extractGin(file, content, out, ctx)
    extractChi(file, content, out, ctx)
    return out
  }
  if (lang === 'ruby') {
    extractRails(file, content, out, ctx)
    return out
  }
  return out
}

// ============================================================================
// Mount resolution + graph assembly
// ============================================================================

function mergeBoundedUnique(base: readonly string[], extra: readonly string[], max = MAX_MIDDLEWARE_PER_ROUTE): string[] {
  if (extra.length === 0) return base as string[]
  if (base.length === 0) {
    if (extra.length <= max) return extra as string[]
    return extra.slice(0, max)
  }
  const seen = new Set<string>(base)
  const out: string[] = [...base]
  for (const item of extra) {
    if (out.length >= max) break
    if (!seen.has(item)) {
      seen.add(item)
      out.push(item)
    }
  }
  return out
}

function resolveMountedRoutes(extractions: readonly Extraction[]): { routes: ProgramRoute[]; warnings: string[] } {
  const routers = new Map<string, RouterDef>()
  const mounts: MountSpec[] = []
  const warnings: string[] = []
  const pushWarn = (msg: string) => {
    if (warnings.length < MAX_TOTAL_WARNINGS) warnings.push(msg)
  }
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
  let unresolvedWarnings = 0
  let mountFanoutWarned = false
  let depthWarned = false
  let stepsWarned = false
  let pathWarned = false

  const looksLikeRouterMountTarget = (mount: MountSpec): boolean =>
    Boolean(mount.childKey)
    || Boolean(mount.childFile && mount.childFile !== mount.file)
    || /(?:router|routes|controller|subapp|blueprint|urls|api|v\d+)/i.test(mount.childName)

  for (const mount of mounts) {
    const child = resolveChild(mount)
    if (!mount.parentKey || !routers.has(mount.parentKey)) {
      if (unresolvedWarnings < 20) {
        pushWarn(`Unresolved router mount parent "${mount.parentName}" -> "${mount.childName}" (${mount.prefix || '/'}) at ${mount.file}:${mount.line}`)
        unresolvedWarnings += 1
      }
      continue
    }
    if (!child) {
      if (looksLikeRouterMountTarget(mount) && unresolvedWarnings < 20) {
        pushWarn(`Unresolved router mount target "${mount.childName}" (${mount.prefix || '/'}) at ${mount.file}:${mount.line}`)
        unresolvedWarnings += 1
      }
      continue
    }
    if (child.key === mount.parentKey) {
      if (cycleWarnings < 10) {
        pushWarn(`Skipped self-mounting router cycle on ${child.key} at ${mount.file}:${mount.line}`)
        cycleWarnings += 1
      }
      continue
    }
    const list = mountsByParent.get(mount.parentKey) ?? []
    list.push({ mount, child })
    mountsByParent.set(mount.parentKey, list)
    hasParent.add(child.key)
  }

  // Key mount expansion by `(mountPath, childKey)` rather than global `settled.has(childKey)` so a
  // shared sub-router mounted at multiple prefixes (e.g., `/v1` + `/v2`, `/org` + `/admin`) retains
  // every mounted prefix & guard chain. Cycles are blocked strictly along `pathVisited`.
  const mountsByRouter = new Map<string, Array<{ base: string; chain: MountSpec[] }>>()
  const visitedMounts = new Set<string>()
  const reachedRouters = new Set<string>()
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
        pushWarn(`Router mount expansion capped at ${MAX_ROUTER_MOUNT_STEPS} steps`)
        stepsWarned = true
      }
      return
    }
    const mountInstanceKey = `${currentBase}\0${routerKey}`
    if (visitedMounts.has(mountInstanceKey)) return
    visitedMounts.add(mountInstanceKey)
    reachedRouters.add(routerKey)
    steps += 1

    const existingInstances = mountsByRouter.get(routerKey) ?? []
    if (existingInstances.length >= MAX_MOUNTS_PER_ROUTER) {
      if (!mountFanoutWarned) {
        pushWarn(`Router mount fan-out capped at ${MAX_MOUNTS_PER_ROUTER} prefixes for ${routerKey}`)
        mountFanoutWarned = true
      }
      return
    }
    existingInstances.push({ base: currentBase, chain })
    mountsByRouter.set(routerKey, existingInstances)

    if (depth >= MAX_ROUTER_MOUNT_DEPTH) {
      if (!depthWarned && (mountsByParent.get(routerKey)?.length ?? 0) > 0) {
        pushWarn(`Router mount depth capped at ${MAX_ROUTER_MOUNT_DEPTH} levels`)
        depthWarned = true
      }
      return
    }

    const children = mountsByParent.get(routerKey)
    if (!children) return
    for (const { mount, child } of children) {
      if (pathVisited.has(child.key)) {
        if (cycleWarnings < 10) {
          pushWarn(`Skipped cyclic router mount ${routerKey} -> ${child.key} at ${mount.file}:${mount.line}`)
          cycleWarnings += 1
        }
        continue
      }
      const stepBase = joinPathsBounded(currentBase, mount.prefix)
      const nextBase = stepBase !== null ? joinPathsBounded(stepBase, child.prefix) : null
      if (nextBase === null) {
        if (!pathWarned) {
          pushWarn(`Skipped mounted path exceeding ${MAX_MOUNT_PATH_LENGTH} chars on ${child.key}`)
          pathWarned = true
        }
        continue
      }
      if (visitedMounts.has(`${nextBase}\0${child.key}`)) continue
      pathVisited.add(child.key)
      walk(child.key, nextBase, [...chain, mount], pathVisited, depth + 1)
      pathVisited.delete(child.key)
    }
  }

  // First traverse from zero-in-degree root routers (normal apps & lassos).
  for (const router of routers.values()) {
    if (hasParent.has(router.key) || reachedRouters.has(router.key)) continue
    walk(router.key, router.prefix, [], new Set([router.key]), 0)
  }
  // Then traverse any remaining pure-cycle components without an external root.
  for (const router of routers.values()) {
    if (reachedRouters.has(router.key)) continue
    walk(router.key, router.prefix, [], new Set([router.key]), 0)
  }

  // Share precomputed router+mount middleware/guards/mountedFrom arrays by reference across routes
  // within each `(routerKey, mountInstanceIdx)` instead of cloning them per route (`R2-H-25`).
  const routerSharedCache = new Map<string, { middleware: string[]; guards: string[]; mountedFrom: string[] }>()
  const getRouterShared = (routerKey: string, instanceIdx: number, chain: MountSpec[]) => {
    const cacheKey = `${routerKey}\0${instanceIdx}`
    let cached = routerSharedCache.get(cacheKey)
    if (cached) return cached
    const router = routers.get(routerKey)
    const mwSeen = new Set<string>()
    const mw: string[] = []
    const pushMw = (list: readonly string[]) => {
      for (const item of list) {
        if (mw.length >= MAX_MIDDLEWARE_PER_ROUTE) break
        if (!mwSeen.has(item)) {
          mwSeen.add(item)
          mw.push(item)
        }
      }
    }
    if (router?.middleware.length) pushMw(router.middleware)
    for (const m of chain) {
      if (mw.length >= MAX_MIDDLEWARE_PER_ROUTE) break
      if (m.middleware.length) pushMw(m.middleware)
    }
    const middleware = mw.length > 0 ? mw : EMPTY_STRINGS
    const guards = guardsFromMiddleware(middleware)
    const mountedFrom = chain.map(m => m.prefix).filter(Boolean)
    cached = {
      middleware,
      guards,
      mountedFrom: mountedFrom.length > 0 ? mountedFrom : EMPTY_STRINGS,
    }
    routerSharedCache.set(cacheKey, cached)
    return cached
  }

  const routes: ProgramRoute[] = []
  const seen = new Set<string>()
  let routeCapWarned = false
  for (const extraction of extractions) {
    for (const raw of extraction.routes) {
      if (routes.length >= MAX_MOUNTED_ROUTES) {
        if (!routeCapWarned) {
          pushWarn(`Mounted routes capped at ${MAX_MOUNTED_ROUTES}`)
          routeCapWarned = true
        }
        break
      }
      const mountInstances = raw.routerKey
        ? (mountsByRouter.get(raw.routerKey) ?? [{ base: routers.get(raw.routerKey)?.prefix ?? '', chain: [] }])
        : [{ base: '', chain: [] }]
      for (let instanceIdx = 0; instanceIdx < mountInstances.length; instanceIdx += 1) {
        if (routes.length >= MAX_MOUNTED_ROUTES) {
          if (!routeCapWarned) {
            pushWarn(`Mounted routes capped at ${MAX_MOUNTED_ROUTES}`)
            routeCapWarned = true
          }
          break
        }
        const instance = mountInstances[instanceIdx]!
        const path = raw.routerKey
          ? joinPathsBounded(instance.base, raw.path)
          : (raw.path.length <= MAX_MOUNT_PATH_LENGTH ? raw.path : null)
        if (path === null) {
          if (!pathWarned) {
            pushWarn(`Skipped mounted path exceeding ${MAX_MOUNT_PATH_LENGTH} chars at ${raw.file}:${raw.line}`)
            pathWarned = true
          }
          continue
        }
        const shared = raw.routerKey ? getRouterShared(raw.routerKey, instanceIdx, instance.chain) : undefined
        const mountedFrom = shared ? shared.mountedFrom : EMPTY_STRINGS
        const middleware = shared
          ? mergeBoundedUnique(shared.middleware, raw.middleware, MAX_MIDDLEWARE_PER_ROUTE)
          : (raw.middleware.length > MAX_MIDDLEWARE_PER_ROUTE ? raw.middleware.slice(0, MAX_MIDDLEWARE_PER_ROUTE) : raw.middleware)
        const rawGuards = raw.guards.length > 0 ? raw.guards : guardsFromMiddleware(raw.middleware)
        const guards = shared
          ? mergeBoundedUnique(shared.guards, rawGuards, MAX_MIDDLEWARE_PER_ROUTE)
          : (rawGuards.length > MAX_MIDDLEWARE_PER_ROUTE ? rawGuards.slice(0, MAX_MIDDLEWARE_PER_ROUTE) : rawGuards)
        const id = `route:${raw.method}:${path}:${raw.file}:${raw.line}`
        if (seen.has(id)) continue
        seen.add(id)
        const pathParams = routeParamNames(path)
        const mergedParams = raw.input.params.length === 0
          ? pathParams
          : pathParams.length === 0
            ? raw.input.params
            : mergeBoundedUnique(raw.input.params, pathParams, 32)
        routes.push({
          id,
          framework: raw.framework,
          method: raw.method,
          path,
          file: raw.file,
          line: raw.line,
          handler: raw.handler,
          input: mergedParams === raw.input.params ? raw.input : { ...raw.input, params: mergedParams },
          middleware,
          guards,
          mountedFrom,
          extraction: raw.extraction,
        })
      }
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
      edges.push({ fromId: route.id, toId: fnId(handlerFn), file: route.file, line: route.line, kind: 'route_handler' })
    }
  }

  const contentByFile = new Map(files.map(file => [file.path, file.content]))
  const newlineOffsetsByFile = new Map<string, number[]>()
  const sinkNodes: ProgramNode[] = []
  for (const fn of functions) {
    const content = contentByFile.get(fn.file)
    if (content === undefined) continue
    const body = content.slice(fn.startIndex, Math.min(fn.endIndex, fn.startIndex + MAX_FUNCTION_BODY_SCAN_BYTES))
    let offsets = newlineOffsetsByFile.get(fn.file)
    for (const hit of detectSinks(body)) {
      if (!offsets) {
        offsets = buildNewlineOffsets(content)
        newlineOffsetsByFile.set(fn.file, offsets)
      }
      const line = lineAtFromOffsets(offsets, fn.startIndex + hit.index, content.length)
      const sink: ProgramNode = {
        id: `sink:${fn.file}:${line}:${hit.kind}:${fn.name}`, kind: 'sink', symbol: `${fn.name}:${hit.kind}`,
        file: fn.file, line, sinkKind: hit.kind, guards: [], calls: [],
      }
      sinkNodes.push(sink)
      nodes.push(sink)
      edges.push({ fromId: fnId(fn), toId: sink.id, file: fn.file, line, kind: 'sink' })
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
      for (const m of file.content.matchAll(/(?<![\w$])import[ \t]{1,16}\{([^}]{1,1024})\}[ \t]{1,16}from[ \t]{1,16}(['"])([^'"\r\n]{1,256})\2/g)) {
        const stem = resolveImportTarget(file.path, m[3])
        const targetFile = stem ? normalizedFileByStem.get(stem) : undefined
        if (!targetFile) continue
        for (const spec of m[1].split(',')) {
          const clean = spec.replace(/\btype[ \t]+/, '').trim()
          if (!clean) continue
          const [orig, alias] = clean.split(/[ \t]+as[ \t]+/).map(s => s.trim())
          if (orig) symbolMap.set(alias || orig, { targetFile, exportedName: orig })
        }
      }
      for (const m of file.content.matchAll(/(?<![\w$])import[ \t]{1,16}(?:\*[ \t]{1,16}as[ \t]{1,16})?([A-Za-z_$][\w$]{0,127})[ \t]{1,16}from[ \t]{1,16}(['"])([^'"\r\n]{1,256})\2/g)) {
        const stem = resolveImportTarget(file.path, m[3])
        const targetFile = stem ? normalizedFileByStem.get(stem) : undefined
        if (!targetFile) continue
        nsFiles.push(targetFile)
        symbolMap.set(m[1], { targetFile, exportedName: m[1] })
      }
      for (const m of file.content.matchAll(/(?<![\w$])(?:const|let|var)[ \t]{1,16}\{([^}]{1,1024})\}[ \t]{0,16}=[ \t]{0,16}require[ \t]{0,16}\([ \t]{0,16}(['"])([^'"\r\n]{1,256})\2[ \t]{0,16}\)/g)) {
        const stem = resolveImportTarget(file.path, m[3])
        const targetFile = stem ? normalizedFileByStem.get(stem) : undefined
        if (!targetFile) continue
        for (const spec of m[1].split(',')) {
          const [orig, alias] = spec.trim().split(/[ \t]*:[ \t]*/).map(s => s.trim())
          if (orig) symbolMap.set(alias || orig, { targetFile, exportedName: orig })
        }
      }
    } else if (lang === 'python') {
      for (const m of file.content.matchAll(/(?<![\w$])from[ \t]{1,16}(\.{1,3}[A-Za-z0-9_.]{0,128})[ \t]{1,16}import[ \t]{1,16}([^\n#]{1,512})/g)) {
        const dots = /^\.+/.exec(m[1])?.[0].length ?? 1
        const modPath = m[1].slice(dots).replaceAll('.', '/')
        const prefix = dots === 1 ? './' : '../'.repeat(dots - 1)
        const stem = resolveImportTarget(file.path, `${prefix}${modPath}`)
        const targetFile = stem ? normalizedFileByStem.get(stem) : undefined
        if (!targetFile) continue
        for (const spec of m[2].split(',')) {
          const [orig, alias] = spec.trim().split(/[ \t]+as[ \t]+/).map(s => s.trim())
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
      edges.push({ fromId: fnId(fn), toId: fnId(target), file: fn.file, line: fn.line, kind: 'call' })
      edgeCount += 1
    }
  }

  // First-class cross-service HTTP/RPC (`client_call`) and async queue/webhook/job (`async_dispatch`) edges.
  extractCrossServiceAndAsyncEdges({
    files,
    functions,
    routes,
    nodes,
    edges,
    fnByFile,
    fnByName,
    fnId,
    contentByFile,
    newlineOffsetsByFile,
    warningsOut,
  })

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

// ============================================================================
// Cross-service HTTP/RPC (`client_call`) & async (`async_dispatch`) edges
// ============================================================================

interface CrossServiceExtractContext {
  files: ReadonlyArray<{ path: string; content: string }>
  functions: readonly ProgramFunction[]
  routes: readonly ProgramRoute[]
  nodes: ProgramNode[]
  edges: ProgramEdge[]
  fnByFile: ReadonlyMap<string, ReadonlyMap<string, ProgramFunction>>
  fnByName: ReadonlyMap<string, readonly ProgramFunction[]>
  fnId: (fn: ProgramFunction) => string
  contentByFile: ReadonlyMap<string, string>
  newlineOffsetsByFile: Map<string, number[]>
  warningsOut: string[]
}

const CLIENT_HTTP_URL_RE = /\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|got(?:\.(?:get|post|put|patch|delete))?|superagent(?:\.(?:get|post|put|patch|delete))?|http\.(?:get|request|Get|Post|NewRequest)|https\.(?:get|request)|requests\.(?:get|post|put|patch|delete|request)|session\.(?:get|post|put|patch|delete)|RestTemplate\.\w{1,24}|WebClient\.\w{1,24})[ \t]{0,8}\([ \t]{0,8}(['"`])([^'"`\r\n]{1,320})\1/g
const CLIENT_RPC_CALL_RE = /\b([A-Za-z_$][\w$]{0,63}(?:Client|Stub|Rpc|Service|Proxy))[ \t]{0,4}\.[ \t]{0,4}([A-Za-z_$][\w$]{1,63})[ \t]{0,4}\(/g
const CLIENT_TRPC_CALL_RE = /\btrpc[ \t]{0,4}\.[ \t]{0,4}([A-Za-z_$][\w$]{0,63})[ \t]{0,4}\.[ \t]{0,4}([A-Za-z_$][\w$]{0,63})[ \t]{0,4}\.[ \t]{0,4}(?:mutate|query)[ \t]{0,4}\(/g
const ASYNC_PRODUCER_CHANNEL_RE = /\b(?:[A-Za-z_$][\w$]{0,63}\.)?(?:sendToQueue|publish|basic_publish|enqueue|add_task|send_task|convertAndSend|emit|dispatchWebhook|sendWebhook|triggerWebhook|deliverWebhook|NewTask)[ \t]{0,8}\([ \t]{0,8}(['"`])([^'"`\r\n]{1,160})\1/g
const ASYNC_QUEUE_ADD_RE = /\b([A-Za-z_$][\w$]{0,63}(?:Queue|Bus|Broker|Topic|Producer|Publisher|Events?|Jobs?|Tasks?|Worker|Sqs|Kafka|Rabbit|Nats|Amqp|Redis))[ \t]{0,4}\.[ \t]{0,4}(?:add|send|publish|emit|enqueue|sendMessage|putEvents)[ \t]{0,8}\([ \t]{0,8}(?:(['"`])([^'"`\r\n]{1,160})\2|\{[^{}\r\n]{0,200}\b(?:topic|queue|channel|event|name|QueueUrl)[ \t]{0,4}:[ \t]{0,4}(['"`])([^'"`\r\n]{1,160})\3)/gi
const ASYNC_CELERY_DELAY_RE = /\b([A-Za-z_][\w]{1,63})\.(?:delay|apply_async|perform_async|perform_later)[ \t]{0,4}\(/g
const ASYNC_WEBHOOK_CALL_RE = /\b(?:dispatchWebhook|sendWebhook|triggerWebhook|deliverWebhook|postWebhook|fireWebhook)[ \t]{0,8}\(/g

const ASYNC_CONSUMER_CALL_RE = /\b(?:[A-Za-z_$][\w$]{0,63}\.)?(?:process|consume|subscribe|on|handle|registerHandler|registerTask|listen)[ \t]{0,8}\([ \t]{0,8}(?:(['"`])([^'"`\r\n]{1,160})\1|\{[^{}\r\n]{0,160}\b(?:topic|queue|channel|event|name)[ \t]{0,4}:[ \t]{0,4}(['"`])([^'"`\r\n]{1,160})\2)[ \t]{0,8},[ \t]{0,8}([A-Za-z_$][\w$]{0,127})/g
const ASYNC_DECORATOR_CONSUMER_RE = /@(?:KafkaListener|RabbitListener|SqsListener|EventPattern|MessagePattern|Cron|Task|shared_task|celery\.task)[ \t]{0,8}\(([^)\r\n]{0,200})\)/g

function serviceRootOfFile(filePath: string): string {
  const parts = filePath.replaceAll('\\', '/').split('/').filter(Boolean)
  if (parts.length >= 2 && /^(?:services|apps|packages|microservices|workers)$/i.test(parts[0]!)) {
    return `${parts[0]}/${parts[1]}`.toLowerCase()
  }
  return (parts[0] ?? '').toLowerCase()
}

function parseClientTarget(rawUrl: string): { targetService?: string; targetPath?: string; isWebhook?: boolean } | null {
  const trimmed = rawUrl.trim()
  if (!trimmed || trimmed.length > 320) return null
  let targetService: string | undefined
  let rawPath = ''

  if (/^https?:\/\//i.test(trimmed)) {
    // Strip template interpolations inside host/path cleanly without dynamic regex.
    const cleanForUrl = trimmed.replace(/\$\{[^}]{1,80}\}/g, ':param')
    try {
      const parsed = new URL(cleanForUrl)
      targetService = parsed.hostname.toLowerCase()
      rawPath = parsed.pathname || '/'
    } catch {
      return null
    }
  } else if (trimmed.startsWith('${')) {
    const closeBrace = trimmed.indexOf('}')
    if (closeBrace < 0) return null
    const envHint = trimmed.slice(2, closeBrace).trim()
    const svcHint = envHint
      .replace(/^process\.env\./, '')
      .replace(/(?:_URL|_BASE_URL|_ORIGIN|_HOST|_ENDPOINT|_SERVICE)$/i, '')
      .replace(/[^A-Za-z0-9_-]+/g, '')
      .toLowerCase()
    if (svcHint) targetService = svcHint
    rawPath = trimmed.slice(closeBrace + 1).replace(/\$\{[^}]{1,80}\}/g, ':param')
  } else if (trimmed.startsWith('/')) {
    rawPath = trimmed.replace(/\$\{[^}]{1,80}\}/g, ':param')
  } else {
    return null
  }

  const barePath = rawPath.split('?')[0] ?? ''
  if (!barePath.startsWith('/')) return null
  const normalizedPath = normalizeRouteTemplate(barePath, { preserveParamNames: true, collapseConcreteIds: false })
  const isWebhook = /\/webhooks?(?:\/|$)/i.test(normalizedPath) || (targetService ? /webhook|callback/i.test(targetService) : false)
  return { ...(targetService ? { targetService } : {}), targetPath: normalizedPath, isWebhook }
}

function routeMatchesTargetPath(routePath: string, targetPath: string): boolean {
  if (routePath === targetPath) return true
  const rSegs = routePath.split('/').filter(Boolean)
  const tSegs = targetPath.split('/').filter(Boolean)
  if (rSegs.length !== tSegs.length || rSegs.length === 0) return false
  for (let i = 0; i < rSegs.length; i += 1) {
    const rs = rSegs[i]!
    const ts = tSegs[i]!
    if (rs === ts) continue
    if (rs.startsWith(':') || ts.startsWith(':')) continue
    return false
  }
  return true
}

function extractCrossServiceAndAsyncEdges(ctx: CrossServiceExtractContext): void {
  const {
    files, functions, routes, nodes, edges,
    fnByFile, fnByName, fnId, contentByFile, newlineOffsetsByFile, warningsOut,
  } = ctx

  const syntheticNodes = new Map<string, ProgramNode>()
  const ensureSyntheticNode = (
    id: string,
    kind: 'service_endpoint' | 'async_channel',
    symbol: string,
    file: string,
    line: number,
  ): ProgramNode => {
    const existing = syntheticNodes.get(id)
    if (existing) return existing
    const node: ProgramNode = { id, kind, symbol, file, line, guards: [], calls: [] }
    syntheticNodes.set(id, node)
    nodes.push(node)
    return node
  }

  // 1. Index async consumers across files (queue/event/job/listener handlers -> nodeId).
  const consumersByChannel = new Map<string, string[]>()
  const addConsumer = (rawChannel: string, targetNodeId: string) => {
    const key = rawChannel.trim().toLowerCase()
    if (!key || key.length > 160) return
    const list = consumersByChannel.get(key) ?? []
    if (!list.includes(targetNodeId)) list.push(targetNodeId)
    consumersByChannel.set(key, list)
  }

  for (const file of files) {
    const content = file.content.length > 512 * 1024 ? file.content.slice(0, 512 * 1024) : file.content
    const fileFns = fnByFile.get(file.path)
    // Match `queue.process('job', handler)` / `eventBus.on('topic', handler)`
    for (const m of content.matchAll(ASYNC_CONSUMER_CALL_RE)) {
      const channel = (m[2] ?? m[4] ?? '').trim()
      const handlerName = (m[5] ?? '').trim()
      if (!channel || !handlerName) continue
      const targetFn = fileFns?.get(handlerName) ?? (fnByName.get(handlerName)?.length === 1 ? fnByName.get(handlerName)![0] : undefined)
      if (targetFn) addConsumer(channel, fnId(targetFn))
    }
    // Match `@KafkaListener(topics = "orders")` / `@EventPattern('order.created')` / `@shared_task`
    for (const m of content.matchAll(ASYNC_DECORATOR_CONSUMER_RE)) {
      const inner = m[1] ?? ''
      const lit = /['"]([^'"\r\n]{1,120})['"]/.exec(inner)?.[1]
      const after = content.slice((m.index ?? 0) + m[0].length, Math.min(content.length, (m.index ?? 0) + m[0].length + 240))
      const fnMatch = /(?:def|async[ \t]+def|public|private|protected|async|function)[ \t]+(?:[A-Za-z0-9_<>,[\]? \t]{1,64}[ \t]+)?([A-Za-z_$][\w$]{0,127})[ \t]*\(/.exec(after)
      const handlerName = fnMatch?.[1]
      const targetFn = handlerName ? fileFns?.get(handlerName) : undefined
      if (targetFn) {
        if (lit) addConsumer(lit, fnId(targetFn))
        addConsumer(targetFn.name, fnId(targetFn))
      }
    }
  }
  // Index webhook routes as consumers too (e.g. POST /webhooks/stripe).
  for (const route of routes) {
    if (/\/webhooks?(?:\/|$)/i.test(route.path)) {
      addConsumer(route.path, route.id)
      const tail = route.path.split('/').filter(Boolean).pop()
      if (tail && !tail.startsWith(':')) addConsumer(`webhook:${tail}`, route.id)
    }
  }

  // Helper to resolve a client HTTP call to an extracted ProgramRoute when present in the graph.
  const findMatchingRoute = (callerFile: string, targetPath: string, targetService?: string): ProgramRoute | undefined => {
    const callerRoot = serviceRootOfFile(callerFile)
    const matching = routes.filter(r => routeMatchesTargetPath(r.path, targetPath))
    if (matching.length === 0) return undefined
    if (targetService) {
      const svcClean = targetService.replace(/[^a-z0-9_-]/g, '')
      const byService = matching.find(r => {
        const lowerFile = r.file.toLowerCase()
        return svcClean.length > 0 && (
          lowerFile.includes(`/${svcClean}/`)
          || lowerFile.startsWith(`${svcClean}/`)
          || serviceRootOfFile(r.file).includes(svcClean)
        )
      })
      if (byService) return byService
    }
    const crossService = matching.find(r => serviceRootOfFile(r.file) !== callerRoot)
    return crossService ?? matching[0]
  }

  const seenEdges = new Set<string>()
  let crossEdgeCount = 0
  let capWarned = false

  const pushCrossEdge = (edge: ProgramEdge): boolean => {
    if (crossEdgeCount >= MAX_CROSS_SERVICE_EDGES) {
      if (!capWarned && warningsOut.length < MAX_TOTAL_WARNINGS) {
        warningsOut.push(`Cross-service/async edges capped at ${MAX_CROSS_SERVICE_EDGES}`)
        capWarned = true
      }
      return false
    }
    const key = `${edge.fromId}|${edge.toId}|${edge.kind}|${edge.channel ?? edge.targetPath ?? ''}`
    if (seenEdges.has(key)) return true
    seenEdges.add(key)
    edges.push(edge)
    crossEdgeCount += 1
    return true
  }

  const lineFor = (file: string, content: string, absIndex: number): number => {
    let offsets = newlineOffsetsByFile.get(file)
    if (!offsets) {
      offsets = buildNewlineOffsets(content)
      newlineOffsetsByFile.set(file, offsets)
    }
    return lineAtFromOffsets(offsets, absIndex, content.length)
  }

  for (const fn of functions) {
    if (crossEdgeCount >= MAX_CROSS_SERVICE_EDGES) break
    const content = contentByFile.get(fn.file)
    if (content === undefined) continue
    const body = content.slice(fn.startIndex, Math.min(fn.endIndex, fn.startIndex + MAX_FUNCTION_BODY_SCAN_BYTES))
    const sourceId = fnId(fn)

    // 2a. Cross-service HTTP calls (`fetch`, `axios.*`, `requests.*`, `http.Post`, `RestTemplate`, etc.)
    for (const m of body.matchAll(CLIENT_HTTP_URL_RE)) {
      const target = parseClientTarget(m[2] ?? '')
      if (!target || !target.targetPath) continue
      const line = lineFor(fn.file, content, fn.startIndex + (m.index ?? 0))
      const matchedRoute = findMatchingRoute(fn.file, target.targetPath, target.targetService)
      // Avoid creating a self-loop from a handler to its own route in the same file.
      if (matchedRoute && matchedRoute.file === fn.file && matchedRoute.handler === fn.name) continue
      const toId = matchedRoute
        ? matchedRoute.id
        : ensureSyntheticNode(
            `svc:${target.targetService ?? 'http'}:${target.targetPath}`,
            target.isWebhook ? 'async_channel' : 'service_endpoint',
            target.targetService ? `${target.targetService}${target.targetPath}` : target.targetPath,
            fn.file,
            line,
          ).id
      if (target.isWebhook) {
        if (!pushCrossEdge({
          fromId: sourceId,
          toId,
          file: fn.file,
          line,
          kind: 'async_dispatch',
          protocol: 'webhook',
          ...(target.targetService ? { targetService: target.targetService } : {}),
          targetPath: target.targetPath,
          channel: target.targetPath,
        })) break
      } else {
        if (!pushCrossEdge({
          fromId: sourceId,
          toId,
          file: fn.file,
          line,
          kind: 'client_call',
          protocol: 'http',
          ...(target.targetService ? { targetService: target.targetService } : {}),
          targetPath: target.targetPath,
        })) break
      }
    }

    // 2b. Cross-service RPC / gRPC client calls (`billingClient.charge(...)`, `trpc.billing.settle.mutate(...)`)
    for (const m of body.matchAll(CLIENT_RPC_CALL_RE)) {
      const clientVar = m[1]!
      const rpcMethod = m[2]!
      if (/^(?:get|set|on|off|once|close|connect|disconnect|use|then|catch|finally|toString|valueOf)$/i.test(rpcMethod)) continue
      const line = lineFor(fn.file, content, fn.startIndex + (m.index ?? 0))
      const svcName = clientVar.replace(/(?:Client|Stub|Rpc|Service|Proxy)$/i, '').toLowerCase() || clientVar.toLowerCase()
      const candidates = fnByName.get(rpcMethod) ?? []
      const remoteFn = candidates.find(c => c.file !== fn.file && (serviceRootOfFile(c.file).includes(svcName) || c.file.toLowerCase().includes(svcName)))
        ?? candidates.find(c => serviceRootOfFile(c.file) !== serviceRootOfFile(fn.file))
      const toId = remoteFn
        ? fnId(remoteFn)
        : ensureSyntheticNode(`rpc:${svcName}:${rpcMethod}`, 'service_endpoint', `${svcName}.${rpcMethod}`, fn.file, line).id
      if (!pushCrossEdge({
        fromId: sourceId,
        toId,
        file: fn.file,
        line,
        kind: 'client_call',
        protocol: /stub|grpc/i.test(clientVar) ? 'grpc' : 'rpc',
        targetService: svcName,
        targetPath: `/${svcName}/${rpcMethod}`,
      })) break
    }
    for (const m of body.matchAll(CLIENT_TRPC_CALL_RE)) {
      const routerName = m[1]!
      const procName = m[2]!
      const line = lineFor(fn.file, content, fn.startIndex + (m.index ?? 0))
      const trpcPath = `/trpc/${routerName}.${procName}`
      const matchedRoute = findMatchingRoute(fn.file, trpcPath, routerName)
      const toId = matchedRoute
        ? matchedRoute.id
        : ensureSyntheticNode(`rpc:trpc:${routerName}.${procName}`, 'service_endpoint', `trpc.${routerName}.${procName}`, fn.file, line).id
      if (!pushCrossEdge({
        fromId: sourceId,
        toId,
        file: fn.file,
        line,
        kind: 'client_call',
        protocol: 'rpc',
        targetService: routerName.toLowerCase(),
        targetPath: trpcPath,
      })) break
    }

    // 2c. Async queue / event / job / webhook dispatches
    const recordAsync = (channel: string, protocol: 'queue' | 'webhook' | 'job' | 'event', matchIndex: number): boolean => {
      const cleanChannel = channel.trim()
      if (!cleanChannel || cleanChannel.length > 160) return true
      const line = lineFor(fn.file, content, fn.startIndex + matchIndex)
      const consumers = consumersByChannel.get(cleanChannel.toLowerCase()) ?? []
      if (consumers.length > 0) {
        for (const consumerId of consumers) {
          if (consumerId === sourceId) continue
          if (!pushCrossEdge({
            fromId: sourceId,
            toId: consumerId,
            file: fn.file,
            line,
            kind: 'async_dispatch',
            protocol,
            channel: cleanChannel,
          })) return false
        }
        return true
      }
      const chNode = ensureSyntheticNode(`async:${protocol}:${cleanChannel.toLowerCase()}`, 'async_channel', cleanChannel, fn.file, line)
      return pushCrossEdge({
        fromId: sourceId,
        toId: chNode.id,
        file: fn.file,
        line,
        kind: 'async_dispatch',
        protocol,
        channel: cleanChannel,
      })
    }

    for (const m of body.matchAll(ASYNC_PRODUCER_CHANNEL_RE)) {
      const raw = m[0]
      const channel = m[2] ?? ''
      const protocol: 'queue' | 'webhook' | 'job' | 'event' = /webhook/i.test(raw)
        ? 'webhook'
        : /emit/i.test(raw)
          ? 'event'
          : /task|enqueue/i.test(raw)
            ? 'job'
            : 'queue'
      if (!recordAsync(channel, protocol, m.index ?? 0)) break
    }
    for (const m of body.matchAll(ASYNC_QUEUE_ADD_RE)) {
      const objName = m[1] ?? ''
      const channel = (m[3] ?? m[4] ?? '').trim() || objName
      const protocol: 'queue' | 'job' | 'event' = /event|bus/i.test(objName)
        ? 'event'
        : /job|task|worker/i.test(objName)
          ? 'job'
          : 'queue'
      if (!recordAsync(channel, protocol, m.index ?? 0)) break
    }
    for (const m of body.matchAll(ASYNC_CELERY_DELAY_RE)) {
      const taskName = m[1]!
      const line = lineFor(fn.file, content, fn.startIndex + (m.index ?? 0))
      const taskFn = fnByFile.get(fn.file)?.get(taskName)
        ?? (fnByName.get(taskName)?.length === 1 ? fnByName.get(taskName)![0] : undefined)
      if (taskFn && fnId(taskFn) !== sourceId) {
        if (!pushCrossEdge({
          fromId: sourceId,
          toId: fnId(taskFn),
          file: fn.file,
          line,
          kind: 'async_dispatch',
          protocol: 'job',
          channel: taskName,
        })) break
      } else {
        if (!recordAsync(taskName, 'job', m.index ?? 0)) break
      }
    }
    for (const m of body.matchAll(ASYNC_WEBHOOK_CALL_RE)) {
      // Only emit generic webhook channel if not already matched with a literal channel by ASYNC_PRODUCER_CHANNEL_RE.
      const after = body.slice((m.index ?? 0) + m[0].length, (m.index ?? 0) + m[0].length + 80).trimStart()
      if (after.startsWith("'") || after.startsWith('"') || after.startsWith('`')) continue
      if (!recordAsync('webhook', 'webhook', m.index ?? 0)) break
    }
  }
}

function extractFilesBounded(
  repo: string | undefined,
  files: ReadonlyArray<{ path: string; content: string }>,
): ProgramGraph {
  const warnings: string[] = []
  const extractions: Extraction[] = []
  const globalMiddleware: string[] = []
  let totalRawRoutes = 0
  let totalBudgetWarned = false

  for (const file of files) {
    const remaining = Math.max(0, MAX_MOUNTED_ROUTES - totalRawRoutes)
    const extraction = extractFile(file.path, file.content, remaining)
    totalRawRoutes += extraction.routes.length
    extractions.push(extraction)
    globalMiddleware.push(...extraction.globalMiddleware)
    for (const w of extraction.warnings) {
      if (warnings.length < MAX_TOTAL_WARNINGS) warnings.push(w)
    }
    if (totalRawRoutes >= MAX_MOUNTED_ROUTES && !totalBudgetWarned) {
      if (warnings.length < MAX_TOTAL_WARNINGS) {
        warnings.push(`Cross-file raw route budget capped at ${MAX_MOUNTED_ROUTES}`)
      }
      totalBudgetWarned = true
    }
  }
  return buildGraph(repo, files, extractions, [...new Set(globalMiddleware)], warnings)
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
    return extractFilesBounded(input.repo, files)
  }
  const maxBytes = Math.max(4096, input.maxFileBytes ?? 1024 * 1024)
  const files = (input.files ?? []).filter(file => file.content.length <= maxBytes)
  return extractFilesBounded(input.repo, files)
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
        if (route) {
          const ordered = [...chain].reverse()
          const key = `${route.id}:${sink.id}`
          if (!results.some(existing => `${existing.routeId}:${existing.sinkId}` === key)) {
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
          }
        }
        // Also continue walking backward across cross-service (`client_call`) and async
        // (`async_dispatch`) edges so upstream entry routes that trigger downstream sinks are visible.
        if (chain.length > maxDepth + 1) return
        for (const edge of incoming.get(current.id) ?? []) {
          if (edge.kind !== 'client_call' && edge.kind !== 'async_dispatch') continue
          const caller = nodeById.get(edge.fromId)
          if (!caller || visited.has(caller.id)) continue
          visited.add(caller.id)
          chain.push(caller)
          walk(caller, chain, visited)
          chain.pop()
          visited.delete(caller.id)
        }
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
  /** Optional path prefix (e.g. `/api`, `/billing`) retained from ingress or reverse-proxy rules. */
  pathPrefix?: string
  confidence: 'exact' | 'host' | 'port' | 'path' | 'fallback' | 'unmapped'
  evidence: string[]
}

export interface MonorepoOriginInput {
  services: readonly MonorepoService[]
  origins: readonly string[]
  compose?: string
  /** All discovered compose files with relative paths (replaces single-file drop). */
  composeFiles?: ReadonlyArray<{ path: string; content: string }>
  ingress?: string
  /** All discovered ingress YAML files with relative paths (replaces single-file drop). */
  ingressFiles?: ReadonlyArray<{ path: string; content: string }>
  dockerfiles?: ReadonlyArray<{ path: string; content: string }>
  manifests?: ReadonlyArray<{ path: string; content: string }>
}

interface ParsedComposeService {
  name: string
  hosts: string[]
  ports: number[]
  pathPrefixes: string[]
  /** Resolved build context / compose directory prefixes for accurate multi-file attribution. */
  rootHints: string[]
  sourceFiles: string[]
}

function dirOfRelativePath(filePath: string): string {
  const norm = filePath.replaceAll('\\', '/').replace(/^\/+|\/+$/g, '')
  const idx = norm.lastIndexOf('/')
  return idx >= 0 ? norm.slice(0, idx) : ''
}

function joinRelativeDir(baseDir: string, rel: string): string {
  const cleanRel = rel.trim().replace(/^['"]|['"]$/g, '').replaceAll('\\', '/')
  if (!cleanRel || cleanRel === '.') return baseDir
  const parts = baseDir ? baseDir.split('/').filter(Boolean) : []
  for (const seg of cleanRel.split('/')) {
    if (!seg || seg === '.') continue
    if (seg === '..') parts.pop()
    else parts.push(seg)
  }
  return parts.join('/')
}

const TRAEFIK_HOST_OPEN_RE = /\bHost[ \t]{0,8}\(/g
const TRAEFIK_PATH_PREFIX_OPEN_RE = /\bPathPrefix[ \t]{0,8}\(/g
const MAX_TRAEFIK_RULE_SPAN = 512
const MAX_TRAEFIK_MATCHES_PER_LINE = 16
const MAX_TRAEFIK_HOST_LENGTH = 253
const MAX_TRAEFIK_PREFIX_LENGTH = 256

/**
 * Strictly linear, bounded Traefik rule extractor for `Host(...)` and `PathPrefix(...)`.
 * Avoids backtracking and unbounded captures on adversarial compose labels (`R3-H-12`).
 */
function extractTraefikRuleArgs(
  line: string,
  openRe: RegExp,
  mode: 'host' | 'pathPrefix',
  out: string[],
  maxOut: number,
): void {
  if (out.length >= maxOut) return
  openRe.lastIndex = 0
  let match: RegExpExecArray | null
  let attempts = 0
  while ((match = openRe.exec(line)) !== null) {
    if (out.length >= maxOut || attempts >= MAX_TRAEFIK_MATCHES_PER_LINE) break
    attempts += 1
    const open = match.index + match[0].length - 1
    const windowSlice = line.slice(open + 1, Math.min(line.length, open + 1 + MAX_TRAEFIK_RULE_SPAN))
    const relClose = windowSlice.indexOf(')')
    if (relClose < 0) continue
    const inner = windowSlice.slice(0, relClose)
    for (const part of inner.split(',')) {
      if (out.length >= maxOut) break
      const cleaned = part.trim().replace(/^[`'"]+|[`'"]+$/g, '').trim()
      if (!cleaned) continue
      if (mode === 'host') {
        if (cleaned.length > MAX_TRAEFIK_HOST_LENGTH || /[\s`'")(]/.test(cleaned)) continue
      } else {
        if (cleaned.length > MAX_TRAEFIK_PREFIX_LENGTH || /[\s`'")(]/.test(cleaned)) continue
      }
      if (!out.includes(cleaned)) out.push(cleaned)
    }
    openRe.lastIndex = open + 1 + relClose + 1
  }
}

function parseComposeServicesFromFiles(
  files: ReadonlyArray<{ path: string; content: string }>,
): ParsedComposeService[] {
  const byKey = new Map<string, ParsedComposeService>()
  for (const file of files) {
    const dirPrefix = dirOfRelativePath(file.path)
    const lines = file.content.split('\n')
    const lineCount = Math.min(lines.length, MAX_COMPOSE_LINES)
    let inServices = false
    let servicesIndent = -1
    let current: ParsedComposeService | null = null
    let serviceIndent = -1
    let inPorts = false
    let portsIndent = -1
    let inBuild = false
    let buildIndent = -1
    for (let li = 0; li < lineCount; li += 1) {
      const rawLine = lines[li]
      const raw = rawLine.length > MAX_SCAN_LINE_LENGTH ? rawLine.slice(0, MAX_SCAN_LINE_LENGTH) : rawLine
      if (/^[ \t]{0,64}services[ \t]{0,16}:/.test(raw)) {
        inServices = true
        servicesIndent = raw.length - raw.trimStart().length
        current = null
        inPorts = false
        inBuild = false
        continue
      }
      if (!inServices) continue
      const indent = raw.length - raw.trimStart().length
      if (raw.trim() && !raw.trim().startsWith('#') && indent <= servicesIndent && !/^[ \t]{0,64}services[ \t]{0,16}:/.test(raw)) {
        inServices = false
        current = null
        inPorts = false
        inBuild = false
        continue
      }
      const serviceMatch = /^([ \t]{1,64})([A-Za-z0-9_.-]{1,128})[ \t]{0,16}:[ \t]{0,16}$/.exec(raw)
      if (serviceMatch && indent <= servicesIndent + 2) {
        const svcName = serviceMatch[2]
        const key = `${dirPrefix}\0${svcName.toLowerCase()}`
        let entry = byKey.get(key)
        if (!entry) {
          if (byKey.size >= MAX_COMPOSE_SERVICES) {
            current = null
            continue
          }
          entry = {
            name: svcName,
            hosts: [],
            ports: [],
            pathPrefixes: [],
            rootHints: dirPrefix ? [dirPrefix] : [],
            sourceFiles: [file.path],
          }
          byKey.set(key, entry)
        } else if (!entry.sourceFiles.includes(file.path)) {
          entry.sourceFiles.push(file.path)
        }
        current = entry
        serviceIndent = indent
        inPorts = false
        inBuild = false
        continue
      }
      if (!current) continue
      if (raw.trim() && indent <= serviceIndent && !raw.trim().startsWith('#')) {
        current = null
        inPorts = false
        inBuild = false
        continue
      }
      if (/^[ \t]{0,64}build[ \t]{0,16}:/.test(raw)) {
        const inlineBuild = /^[ \t]{0,64}build[ \t]{0,16}:[ \t]{0,16}['"]?([^\s'"#]{1,256})['"]?[ \t]{0,16}$/.exec(raw)?.[1]
        if (inlineBuild) {
          const resolved = joinRelativeDir(dirPrefix, inlineBuild)
          if (resolved && !current.rootHints.includes(resolved) && current.rootHints.length < 16) current.rootHints.push(resolved)
          inBuild = false
        } else {
          inBuild = true
          buildIndent = indent
        }
        continue
      }
      if (inBuild && indent <= buildIndent && raw.trim() && !raw.trim().startsWith('#')) {
        inBuild = false
      }
      if (inBuild) {
        const ctxMatch = /^[ \t]{0,64}context[ \t]{0,16}:[ \t]{0,16}['"]?([^\s'"#]{1,256})['"]?/.exec(raw)?.[1]
        if (ctxMatch) {
          const resolved = joinRelativeDir(dirPrefix, ctxMatch)
          if (resolved && !current.rootHints.includes(resolved) && current.rootHints.length < 16) current.rootHints.push(resolved)
        }
      }
      if (/^[ \t]{0,64}ports[ \t]{0,16}:/.test(raw)) {
        inPorts = true
        portsIndent = indent
        const inline = /ports[ \t]{0,16}:[ \t]{0,16}\[([^\]]{0,512})\]/.exec(raw)?.[1]
        if (inline) {
          for (const port of inline.matchAll(/(?:^|,)[ \t]{0,16}['"]?(?:[\d.]{1,32}:)?(\d{2,5})(?::(\d{2,5}))?(?:\/(?:tcp|udp))?['"]?/g)) {
            if (current.ports.length >= MAX_COMPOSE_PORTS_PER_SERVICE) break
            const p1 = Number(port[1])
            if (p1 > 0 && p1 <= 65535 && !current.ports.includes(p1)) current.ports.push(p1)
            if (port[2] && current.ports.length < MAX_COMPOSE_PORTS_PER_SERVICE) {
              const p2 = Number(port[2])
              if (p2 > 0 && p2 <= 65535 && !current.ports.includes(p2)) current.ports.push(p2)
            }
          }
          inPorts = false
        }
        continue
      }
      if (inPorts && indent <= portsIndent && raw.trim() && !/^[ \t]{0,64}-/.test(raw)) {
        inPorts = false
      }
      if (inPorts && current.ports.length < MAX_COMPOSE_PORTS_PER_SERVICE) {
        const singlePort = /^[ \t]{0,64}-[ \t]{0,16}['"]?(?:[\d.]{1,32}:)?(\d{2,5})(?::(\d{2,5}))?(?:\/(?:tcp|udp))?['"]?[ \t]{0,16}$/.exec(raw)
        if (singlePort) {
          const p1 = Number(singlePort[1])
          if (p1 > 0 && p1 <= 65535 && !current.ports.includes(p1)) current.ports.push(p1)
          if (singlePort[2] && current.ports.length < MAX_COMPOSE_PORTS_PER_SERVICE) {
            const p2 = Number(singlePort[2])
            if (p2 > 0 && p2 <= 65535 && !current.ports.includes(p2)) current.ports.push(p2)
          }
        }
      }
      if (raw.includes('Host')) {
        extractTraefikRuleArgs(raw, TRAEFIK_HOST_OPEN_RE, 'host', current.hosts, MAX_COMPOSE_HOSTS_PER_SERVICE)
      }
      if (raw.includes('PathPrefix')) {
        extractTraefikRuleArgs(raw, TRAEFIK_PATH_PREFIX_OPEN_RE, 'pathPrefix', current.pathPrefixes, MAX_COMPOSE_PREFIXES_PER_SERVICE)
      }
      if (current.hosts.length < MAX_COMPOSE_HOSTS_PER_SERVICE) {
        const containerName = /container_name[ \t]{0,16}:[ \t]{0,16}['"]?([A-Za-z0-9_.-]{1,128})/.exec(raw)?.[1]
        if (containerName && !current.hosts.includes(containerName)) current.hosts.push(containerName)
      }
    }
  }
  return [...byKey.values()]
}

function parseIngressRulesFromFiles(
  files: ReadonlyArray<{ path: string; content: string }>,
): Array<{ host: string; service: string; path?: string; sourceFile: string; dirPrefix: string }> {
  const rules: Array<{ host: string; service: string; path?: string; sourceFile: string; dirPrefix: string }> = []
  for (const file of files) {
    if (rules.length >= MAX_INGRESS_RULES) break
    const dirPrefix = dirOfRelativePath(file.path)
    // Support multi-document YAML separated by `---`.
    const docs = file.content.split(/^[ \t]{0,64}---[ \t]{0,64}$/m)
    let totalLinesScanned = 0
    for (const doc of docs) {
      if (rules.length >= MAX_INGRESS_RULES || totalLinesScanned >= MAX_COMPOSE_LINES) break
      const lines = doc.split('\n')
      let host = ''
      let path: string | undefined
      let pendingService = false
      for (const rawLine of lines) {
        if (rules.length >= MAX_INGRESS_RULES || totalLinesScanned >= MAX_COMPOSE_LINES) break
        totalLinesScanned += 1
        const raw = rawLine.length > MAX_SCAN_LINE_LENGTH ? rawLine.slice(0, MAX_SCAN_LINE_LENGTH) : rawLine
        const hostMatch = /^[ \t]{0,64}-[ \t]{0,16}host[ \t]{0,16}:[ \t]{0,16}['"]?([^'"\s]{1,253})/.exec(raw)
        if (hostMatch) {
          host = hostMatch[1]
          path = undefined
        }
        const quotedHost = /host[ \t]{0,16}:[ \t]{0,16}['"]([^'"]{1,253})['"]/.exec(raw)
        if (quotedHost && !hostMatch) {
          host = quotedHost[1]
          path = undefined
        }
        const pathMatch = /path[ \t]{0,16}:[ \t]{0,16}['"]?([^'"\s]{1,256})/.exec(raw)
        if (pathMatch) path = pathMatch[1]
        if (/service[ \t]{0,16}:[ \t]{0,16}$/.test(raw)) {
          pendingService = true
          continue
        }
        const serviceNameInline = /^[ \t]{0,64}serviceName[ \t]{0,16}:[ \t]{0,16}['"]?([A-Za-z0-9_.-]{1,128})/.exec(raw)
        if (serviceNameInline) {
          rules.push({ host, service: serviceNameInline[1], ...(path ? { path } : {}), sourceFile: file.path, dirPrefix })
          pendingService = false
          continue
        }
        const nameMatch = /^[ \t]{0,64}name[ \t]{0,16}:[ \t]{0,16}['"]?([A-Za-z0-9_.-]{1,128})/.exec(raw)
        if (pendingService && nameMatch) {
          rules.push({ host, service: nameMatch[1], ...(path ? { path } : {}), sourceFile: file.path, dirPrefix })
          pendingService = false
        }
      }
    }
  }
  return rules
}

/**
 * Map monorepo services to concrete target origins using ALL parsed compose files (with build
 * contexts, ports, labels, and path prefixes), Dockerfile EXPOSE, ALL k8s ingress host/path
 * backends, and manifest names. Genuinely unmapped services are marked `unmapped` instead of
 * silently misattributing their routes to `origins[0]`.
 */
/**
 * Strictly linear O(n) line-wise Dockerfile `EXPOSE` port scanner (R4-H-16).
 * Uses only horizontal `[ \t]*` whitespace skipping per line so multiline whitespace
 * Dockerfiles can never trigger regex backtracking.
 */
function extractDockerfileExposePorts(content: string): number[] {
  const ports: number[] = []
  const len = content.length
  let pos = 0
  while (pos < len) {
    let nl = content.indexOf('\n', pos)
    if (nl === -1) nl = len
    const lineEnd = nl > pos && content.charCodeAt(nl - 1) === 13 ? nl - 1 : nl
    let i = pos
    while (i < lineEnd && (content.charCodeAt(i) === 32 || content.charCodeAt(i) === 9)) i += 1
    if (lineEnd - i >= 8) {
      const kw = content.slice(i, i + 6)
      if (kw === 'EXPOSE' || kw.toUpperCase() === 'EXPOSE') {
        let j = i + 6
        if (j < lineEnd && (content.charCodeAt(j) === 32 || content.charCodeAt(j) === 9)) {
          let linePorts = 0
          while (j < lineEnd && linePorts < 16) {
            while (j < lineEnd && (content.charCodeAt(j) === 32 || content.charCodeAt(j) === 9)) j += 1
            if (j >= lineEnd || content.charCodeAt(j) === 35 /* '#' */) break
            const tokenStart = j
            while (j < lineEnd && content.charCodeAt(j) !== 32 && content.charCodeAt(j) !== 9) j += 1
            let digitEnd = tokenStart
            while (
              digitEnd < j
              && content.charCodeAt(digitEnd) >= 48
              && content.charCodeAt(digitEnd) <= 57
              && digitEnd - tokenStart < 5
            ) {
              digitEnd += 1
            }
            const digitCount = digitEnd - tokenStart
            if (digitCount >= 2 && (digitEnd === j || content.charCodeAt(digitEnd) === 47 /* '/' */)) {
              const port = Number(content.slice(tokenStart, digitEnd))
              if (Number.isInteger(port) && port >= 1 && port <= 65535) {
                ports.push(port)
                linePorts += 1
              }
            }
          }
        }
      }
    }
    pos = nl + 1
  }
  return ports
}

export function mapServicesToOrigins(input: MonorepoOriginInput): ServiceOriginMapping[] {
  const composeFileList: Array<{ path: string; content: string }> = [
    ...(input.composeFiles ?? []),
    ...(input.compose && !(input.composeFiles ?? []).some(f => f.content === input.compose)
      ? [{ path: 'docker-compose.yml', content: input.compose }]
      : []),
  ]
  const ingressFileList: Array<{ path: string; content: string }> = [
    ...(input.ingressFiles ?? []),
    ...(input.ingress && !(input.ingressFiles ?? []).some(f => f.content === input.ingress)
      ? [{ path: 'ingress.yaml', content: input.ingress }]
      : []),
  ]

  const composeEntries = parseComposeServicesFromFiles(composeFileList)
  const ingressRules = parseIngressRulesFromFiles(ingressFileList)
  const dockerPorts = new Map<string, number[]>()
  for (const dockerfile of input.dockerfiles ?? []) {
    const root = dockerfile.path.replace(/(?:\/)?Dockerfile(?:\..*)?$/i, '').replace(/\/$/, '')
    const ports = extractDockerfileExposePorts(dockerfile.content)
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
    const root = service.root?.replace(/\/$/, '')
    const aliases = new Set<string>([service.name.toLowerCase()])
    // Match all compose entries belonging to this service (preferring build-context/dir-prefix matches).
    const matchingCompose = composeEntries.filter(entry => {
      if (root && entry.rootHints.some(hint => hint === root || root.endsWith(`/${hint}`) || hint.endsWith(`/${root}`))) {
        return entry.name.toLowerCase() === service.name.toLowerCase() || entry.rootHints.includes(root)
      }
      return entry.name.toLowerCase() === service.name.toLowerCase()
    })
    const evidence: string[] = []
    for (const host of service.hosts ?? []) aliases.add(host.toLowerCase())
    const composePathPrefixes: string[] = []
    const ports = new Set<number>([...(service.ports ?? [])])
    for (const composeEntry of matchingCompose) {
      for (const host of composeEntry.hosts) aliases.add(host.toLowerCase())
      for (const port of composeEntry.ports) ports.add(port)
      for (const prefix of composeEntry.pathPrefixes) {
        if (!composePathPrefixes.includes(prefix)) composePathPrefixes.push(prefix)
      }
    }
    if (root && manifestNames.has(root)) aliases.add(manifestNames.get(root)!.toLowerCase())
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
      const ingressMatch = ingressRules.find(rule =>
        (rule.service.toLowerCase() === service.name.toLowerCase() || aliases.has(rule.service.toLowerCase()))
        && (!rule.host || rule.host.toLowerCase() === host),
      )
      const portMatch = ports.has(originPort)
      const retainedPathPrefix = ingressMatch?.path ?? composePathPrefixes[0]
      if (hostMatch) {
        const candidate: ServiceOriginMapping = {
          service: service.name,
          ...(root ? { root } : {}),
          origin,
          ...(retainedPathPrefix ? { pathPrefix: retainedPathPrefix } : {}),
          confidence: 'exact',
          evidence: [
            `host ${host} matches alias ${hostMatch}`,
            ...(retainedPathPrefix ? [`path prefix ${retainedPathPrefix}`] : []),
          ],
        }
        if (!best || best.confidence !== 'exact') best = candidate
      } else if (ingressMatch) {
        const candidate: ServiceOriginMapping = {
          service: service.name,
          ...(root ? { root } : {}),
          origin,
          ...(ingressMatch.path ? { pathPrefix: ingressMatch.path } : {}),
          confidence: ingressMatch.path ? 'path' : 'host',
          evidence: [`ingress ${ingressMatch.sourceFile} host ${ingressMatch.host || host}${ingressMatch.path ? ` path ${ingressMatch.path}` : ''} -> service ${ingressMatch.service}`],
        }
        if (!best || best.confidence === 'port' || (best.confidence === 'host' && candidate.confidence === 'path')) best = candidate
      } else if (portMatch && !best) {
        best = {
          service: service.name,
          ...(root ? { root } : {}),
          origin,
          ...(composePathPrefixes[0] ? { pathPrefix: composePathPrefixes[0] } : {}),
          confidence: 'port',
          evidence: [`port ${originPort} exposed by service`],
        }
      }
    }
    if (best) {
      results.push({ ...best, evidence: [...best.evidence, ...evidence] })
    } else if (input.origins.length === 1 && input.services.length === 1) {
      results.push({
        service: service.name,
        ...(root ? { root } : {}),
        origin: input.origins[0],
        confidence: 'exact',
        evidence: ['single service mapped to single approved origin'],
      })
    } else {
      results.push({
        service: service.name,
        ...(root ? { root } : {}),
        confidence: 'unmapped',
        evidence: [
          input.origins.length
            ? 'no host/port/ingress/compose match; service marked unmapped instead of misattributing to origins[0]'
            : 'no target origins configured',
        ],
      })
    }
  }
  return results
}
