import { createHash, randomUUID } from 'node:crypto'
import { closeSync, constants as fsConstants, existsSync, lstatSync, openSync, readdirSync, readFileSync, realpathSync } from 'node:fs'
import { extname, isAbsolute, join, relative, sep } from 'node:path'
import { jsHarvest } from '../../worker/analyzers.ts'
import type { CapabilityTier, CodeLocation, EndpointSource, ParamLocation } from '../domain.ts'
import { mergeTechTags, techTagsFromManifests, techTagsFromResponse } from '../templates/tech-tags.ts'
import type { ManifestFile } from '../templates/tech-tags.ts'
import { BrokerCircuitOpen, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { normalizeEndpointTemplate } from './dedupe.ts'
import { listMountedRepos } from './github-connector.ts'
import {
  buildCodeDataflowSlice,
  deriveCodeToRuntimeHypotheses,
  extractProgramGraph,
  mapServicesToOrigins,
  resolveRouteSinkPaths,
} from './program-graph.ts'
import type {
  CodeDataflowSlice,
  CodeToRuntimeHypothesis,
  CommitDiffSignal,
  MonorepoService,
  ProgramGraph,
  ProgramRoute,
  RouteSinkPath,
  ServiceOriginMapping,
} from './program-graph.ts'
import { buildSoft404ProbePaths } from './scoped-browser.ts'
import type { ScopedBrowser } from './scoped-browser.ts'
import type { EndpointRow, Store } from './store.ts'
import { parseGraphqlIntrospection, probeSurface, runSafeTemplates } from './surface-engine.ts'

export interface Phase0ReconParams {
  storage: Store
  runId: string
  scopeRevision: number
  tier: CapabilityTier
  origins: readonly string[]
  budgetRequests?: number
  reposDir?: string
  personas?: readonly string[]
  broker: RequestBroker
  browser?: ScopedBrowser
  canaryBroker?: CanaryBroker
  grant: Grant
  signal: AbortSignal
  assignmentId?: string
  onExchange?: (ex: BrokerExchangeResult) => string | void
  /** Passive CDN/static origins for browser asset hydration (never actively probed). */
  assetOrigins?: readonly string[]
  /** Exercise non-destructive SPA navigation during the crawl. Defaults to true. */
  interactiveTraversal?: boolean
  /** Read-only traversal mode (no form submits). Defaults to true. */
  readOnlyMode?: boolean
  /** Lower the per-run code-slice cap for tests/tight budgets (hard-capped at 200). */
  maxCodeSlices?: number
}

export interface Phase0ReconResult {
  requestsUsed: number
  perOriginCap: number
  endpointsDiscovered: number
  paramsDiscovered: number
  frameworksDetected: string[]
  techFingerprint: string[]
  /** Per-endpoint provenance totals for persisted `endpoint_params` (observed vs inferred). */
  paramDiscovery?: ParamDiscoverySummary
  dynamicWordlist: {
    paths: string[]
    params: string[]
  }
  stoppedReason: string | null
  /** Endpoints expanded from served route-map/config artifacts. */
  routeMapEndpoints?: number
  /** Client router-table literals harvested from bundles. */
  jsRouterRoutes?: number
  /** JSON navigation fetches performed during discovery. */
  navigationRequests?: number
  navigationEndpoints?: number
  /** Discovery fetches that carried approved-persona session material. */
  authRequests?: number
  /** Candidate routes rejected by soft-404 / SPA catch-all calibration. */
  soft404Rejected?: number
  /** Declared operations ingested offline from the imported OpenAPI/API reference. */
  declaredSurface?: DeclaredSurfaceSummary
  /** Sibling detail routes derived from observed collections / Location headers (passive, no probe). */
  siblingEndpoints?: number
  /** Allowed methods learned from OPTIONS/405 `Allow` headers and validation 400/422 bodies. */
  methodHints?: number
  /** Endpoint union visibility: `METHOD pathTemplate` -> persona handles (or `anonymous`). */
  visibleToPersonas?: Record<string, string[]>
  /** Admin/privileged or role-restricted routes surfaced immediately from the persona union. */
  privilegedEndpoints?: Array<{ method: string; pathTemplate: string; personas: string[]; reason: string }>
  /** Code-to-runtime hypotheses derived from the mounted Program Graph (planner/engine input). */
  codeToRuntimeHypotheses?: CodeSliceHypothesis[]
  /**
   * Bounded attachment accounting for white-box dataflow slices stored on the hypotheses above.
   * `codeSlice: 'unavailable'` means no graph/source was available (nothing was fabricated).
   */
  codeSlices?: Phase0CodeSliceSummary
  /** Mounted-repo Program Graph extraction summary (AST primary, regex fallback). */
  repoStaticExtraction?: RepoStaticExtractionSummary
  /**
   * Ranked probe plan over the losslessly stored AST surface. Every route stays in the store;
   * this only reports the prioritized/sampled subset a consumer may probe first.
   */
  probePlan?: {
    totalRoutes: number
    priority: number
    schemaTyped: number
    longTail: number
    clusters: number
    representatives: number
    probeSubset: number
    /** First probe-subset keys (`METHOD pathTemplate`), bounded for artifact size. */
    sample: string[]
  }
  /** Set when speculative sibling derivation was disabled because declared/AST routes exist. */
  siblingDerivationSuppressed?: 'declared_surface'
}

export interface RepoStaticExtractionSummary {
  astRoutes: number
  regexFallbackRoutes: number
  mergedRoutes: number
  duplicateRoutes: number
  frameworks: string[]
  /** Service -> origin resolution reused for AST route attribution. */
  originMappings: ServiceOriginMapping[]
  /** `METHOD pathTemplate` -> origin provenance for AST routes (multi-origin targets). */
  routeOrigins: Record<string, { origin: string; confidence: ServiceOriginMapping['confidence']; service?: string; evidence: string[] }>
  warnings: string[]
}

export interface CrawlStateGraphParams {
  storage: Store
  runId: string
  scopeRevision: number
  origin: string
  personas?: readonly string[]
  maxPages?: number
  maxDepth?: number
  budgetRemaining?: number
  browser: ScopedBrowser
  grant: Grant
  signal: AbortSignal
  assignmentId?: string
  onExchange?: (ex: BrokerExchangeResult) => string | void
  assetOrigins?: readonly string[]
  interactiveTraversal?: boolean
  readOnlyMode?: boolean
}

export interface CrawlStateGraphResult {
  origin: string
  pagesVisited: number
  endpointsDiscovered: number
  paramsDiscovered: number
  storageKeys: string[]
  hasPostMessageListener: boolean
  personasCrawled: string[]
  stoppedReason?: string
  /** Endpoints expanded from route-map/config documents captured in XHR/fetch response bodies. */
  routeMapEndpoints?: number
  /** Endpoint union visibility across every crawled persona (`METHOD pathTemplate` -> handles). */
  visibleToPersonas?: Record<string, string[]>
  /** Privileged/admin routes discovered through the persona union, surfaced immediately. */
  privilegedEndpoints?: Array<{ method: string; pathTemplate: string; personas: string[]; reason: string }>
  /** Full-surface paged read the crawl's route lookups ran against (see `phase0.crawl_paged`). */
  crawlPaged?: PagedReadMetric
}

export interface StaticExtractedRoute {
  method: string
  pathTemplate: string
  framework: string
  authRequirement: string | null
  ownershipGuard: string | null
  sinkKinds: string[]
  riskScore: number
  params: Array<{ name: string; location: ParamLocation; isObjectId: boolean }>
  codeLocation: CodeLocation
  /** AST (Program Graph) extraction is authoritative; regex stays an explicit fallback. */
  extraction?: 'ast' | 'regex'
  /** Resolved auth/RBAC/tenant class for this route. */
  authClass?: 'admin' | 'tenant' | 'auth' | 'unguarded'
  /** Effective guard chain (router global -> mount -> route). */
  guards?: string[]
  /** Full middleware chain in declaration order. */
  middleware?: string[]
  /** Mount prefixes resolved by the AST. */
  mountedFrom?: string[]
  /** Monorepo service root that owns this route file. */
  service?: string
  /** Target origin this route was attributed to (multi-origin targets). */
  origin?: string
  /** How the origin attribution was established. */
  originConfidence?: ServiceOriginMapping['confidence']
  /** Program Graph route id (links code-to-runtime hypotheses back to the route). */
  routeId?: string
}

const CSRF_PARAM_RE = /^(?:_csrf|csrf[_-]?token|xsrf[_-]?token|csrfmiddlewaretoken|__requestverificationtoken|authenticity_token|_token)$/i
const OBJECT_ID_PARAM_RE = /^(?:id|uuid|[a-z0-9_]*_?id)$/i
const STATIC_ASSET_RE = /\.(?:css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|mp3|zip|tar|gz|pdf)(?:\?|$)/i
// SQL/query fragments that surface as quoted literals in source (for example DB helpers named like
// HTTP verbs). They are never route paths, so structural route extraction must reject them.
const SQL_ROUTE_FRAGMENT_RE = /\b(?:select|insert|update|delete|from|where|join|having|union|values|into|pragma|drop|alter|truncate|limit|offset|order\s+by|group\s+by|create\s+(?:table|index|view))\b/i

/**
 * True when a quoted source literal can plausibly be an HTTP route path. Rejects SQL/query fragments,
 * prose, and other non-path literals while keeping framework token shapes (`:id`, `{id}`, `[id]`).
 */
export function isPathLikeRouteLiteral(raw: string): boolean {
  const literal = raw.trim()
  if (!literal || literal.length > 300) return false
  if (/\s/.test(literal)) return false
  if (/[<>\\"'`]/.test(literal)) return false
  if (/[?#=;,()]/.test(literal)) return false
  if (literal.startsWith('//')) return false
  if (!/^\/?[A-Za-z0-9._~:/@{}\[\]-]+$/.test(literal)) return false
  if (SQL_ROUTE_FRAGMENT_RE.test(literal)) return false
  return true
}
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', 'out', 'coverage',
  'vendor', '__pycache__', '.venv', 'venv', 'target', '.gradle', '.idea',
])

const PHASE0_SEED_PATHS: readonly string[] = [
  '/',
  '/robots.txt',
  '/sitemap.xml',
  '/.well-known/openid-configuration',
  '/.well-known/jwks.json',
  '/.well-known/security.txt',
  '/openapi.json',
  '/graphql',
  '/swagger.json',
  // Common servable route-map/config artifacts (SPA route tables, endpoint manifests).
  '/config.json',
  '/routes.json',
  '/manifest.json',
  '/api/routes',
  // Framework API-description conventions.
  '/api-docs',
  '/v3/api-docs',
  '/api/openapi.json',
  '/api/swagger.json',
  '/api/graphql',
  '/trpc',
]

function sanitizePathCandidate(raw: string, baseOrigin: string): string | null {
  const trimmed = raw.trim()
  if (!trimmed || trimmed.startsWith('javascript:') || trimmed.startsWith('mailto:') || trimmed.startsWith('data:') || trimmed.startsWith('#')) {
    return null
  }
  try {
    const expectedOrigin = new URL(baseOrigin).origin
    const parsed = new URL(trimmed, baseOrigin)
    if (parsed.origin !== expectedOrigin) return null
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
    if (/[\r\n\0\\]/.test(parsed.pathname + parsed.search)) return null
    return parsed.pathname + parsed.search
  } catch {
    return null
  }
}

function normalizeRouteTemplate(rawPath: string): string {
  const bare = rawPath.split('?')[0] || '/'
  // Convert framework dynamic segments ([id], {id}, <int:id>, <id>) to :id while preserving named placeholders
  const cleaned = bare
    .replace(/\/\[\.\.\.([a-zA-Z0-9_-]+)\]/g, '/:$1')
    .replace(/\/\[([a-zA-Z0-9_-]+)\]/g, '/:$1')
    .replace(/\/\{([a-zA-Z0-9_-]+)\}/g, '/:$1')
    .replace(/\/<(?:[a-zA-Z0-9_]+:)?([a-zA-Z0-9_-]+)>/g, '/:$1')
  // Request paths are case-sensitive: preserve literal segment case (only built-in token shapes
  // are collapsed to `:id`). Fingerprinting/dedupe opts back into lowercasing separately.
  const normalized = normalizeEndpointTemplate(cleaned, { preserveCase: true })
  return normalized.startsWith('/') ? normalized : `/${normalized}`
}

/**
 * Discovery-facing route normalizer: preserves named parameter identifiers (`:orgId`, `:invoiceId`)
 * and literal segment casing (`/trpc/user.getById`, `/api/getInvoice`), normalizing only framework
 * token forms (`[id]`, `{id}`, `<int:id>`) to `:id`. Aggressive folding stays in `dedupe.ts`.
 */
export function normalizeDiscoveryTemplate(rawPath: string): string {
  const bare = (rawPath.split('?')[0] || '/').split('#')[0] || '/'
  const segments = bare.split('/').map(seg => {
    if (!seg) return ''
    if (/^:[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(seg)) return seg
    if (/^\[[^\]]{1,64}\]$/.test(seg) || /^\{[^}]{1,64}\}$/.test(seg) || /^<[^>]{1,64}>$/.test(seg)) return ':id'
    return seg
  })
  const joined = segments.join('/').replace(/\/{2,}/g, '/')
  const trimmed = joined.length > 1 && joined.endsWith('/') ? joined.slice(0, -1) : joined
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`
}

/**
 * Paths that conventionally expose administrative or privileged surface. Used only to surface
 * persona-union discoveries immediately (risk prioritization), never to skip coverage.
 */
export function isPrivilegedPathTemplate(pathTemplate: string): boolean {
  return /(?:^|\/)(?:admin|administrator|internal|debug|audit|staff|manage|management|console|superuser|settings|billing|roles?|permissions?|security|orgs?|tenants?)(?:\/|$)/i.test(pathTemplate)
}

function scoreEndpointRisk(method: string, pathTemplate: string, sinkKinds: readonly string[] = [], authReq?: string | null): number {
  let score = 45
  const lower = pathTemplate.toLowerCase()
  if (/(?:admin|internal|debug|billing|invoice|payment|webhook|secret|export|upload|token|auth|oauth|graphql|transfer|refund|role|permission|config|user|org|tenant|order)/.test(lower)) {
    score += 30
  }
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) score += 12
  if (/:[a-zA-Z0-9_]+|\{[a-zA-Z0-9_]+\}/.test(pathTemplate)) score += 8
  if (sinkKinds.length > 0) score += Math.min(20, sinkKinds.length * 7)
  if (authReq === 'none') score += 5
  return Math.max(10, Math.min(100, score))
}

function extractDynamicPathParams(pathTemplate: string): Array<{ name: string; location: ParamLocation; isObjectId: boolean }> {
  const out: Array<{ name: string; location: ParamLocation; isObjectId: boolean }> = []
  const seen = new Set<string>()
  for (const m of pathTemplate.matchAll(/(?::|\{)([a-zA-Z_][a-zA-Z0-9_-]{0,63})\}?/g)) {
    const name = m[1]
    if (!name || seen.has(name)) continue
    seen.add(name)
    out.push({ name, location: 'path', isObjectId: OBJECT_ID_PARAM_RE.test(name) })
  }
  return out
}

function detectSinksAndGuards(code: string): {
  authRequirement: string | null
  ownershipGuard: string | null
  sinkKinds: string[]
} {
  const authMatch = /\b(requireAuth|authMiddleware|authMw|isAuthenticated|verifyJwt|authenticate|getServerSession|currentUser|@login_required|@PreAuthorize|Depends\([^)]*auth)\b/i.exec(code)
  const ownerMatch = /\b(orgId|tenantId|ownerId|userId\s*===|checkOwnership|authorizeResource|canAccess)\b/.exec(code)
  const sinks: string[] = []
  if (/\b(?:query|execute|rawQuery|\$queryRaw|SELECT\s+.+\s+FROM)\b/i.test(code)) sinks.push('db_query')
  if (/\b(?:fetch|axios|http\.get|requests\.get|urllib|RestTemplate)\b/.test(code)) sinks.push('outbound_fetch')
  if (/\b(?:exec|execSync|spawn|system|popen|subprocess)\b/.test(code)) sinks.push('command_exec')
  if (/\b(?:readFile|writeFile|createReadStream|open\(|send_file|os\.Open)\b/.test(code)) sinks.push('file_io')
  if (/\b(?:redirect|sendRedirect|RedirectResponse)\b/.test(code)) sinks.push('redirect')
  return {
    authRequirement: authMatch ? authMatch[1] : null,
    ownershipGuard: ownerMatch ? ownerMatch[1] : null,
    sinkKinds: [...new Set(sinks)],
  }
}

function lineNumberAt(text: string, index: number): number {
  let line = 1
  for (let i = 0; i < index && i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1
  }
  return line
}

const NO_FOLLOW = (fsConstants as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0

/**
 * True when `candidate` resolves inside `rootReal`. Repo trees may contain directories replaced
 * by links between the lstat and the read; canonicalising each directory keeps the walker contained.
 */
function isRealPathUnder(rootReal: string, candidate: string): boolean {
  try {
    const real = realpathSync(candidate)
    const rel = relative(rootReal, real)
    return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel))
  } catch {
    return false
  }
}

/**
 * Read a repo file only when it is a regular file that is not a symlink. `O_NOFOLLOW` closes the
 * lstat/read race, so a manifest-shaped link to /etc/passwd is never dereferenced.
 */
function readRepoRegularFile(path: string, maxBytes = 256 * 1024): string | null {
  let fd: number | undefined
  try {
    const st = lstatSync(path)
    if (!st.isFile() || st.size > maxBytes) return null
    fd = openSync(path, fsConstants.O_RDONLY | NO_FOLLOW)
    return readFileSync(fd, 'utf8')
  } catch {
    return null
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd) } catch { /* already closed */ }
    }
  }
}

function walkRepoFiles(rootDir: string, maxFiles = 1500): string[] {
  const out: string[] = []
  let rootReal: string
  try {
    rootReal = realpathSync(rootDir)
  } catch {
    return out
  }
  const stack: string[] = [rootReal]
  while (stack.length > 0 && out.length < maxFiles) {
    const dir = stack.pop()!
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      continue
    }
    for (const name of entries) {
      if (out.length >= maxFiles) break
      if (SKIP_DIRS.has(name) || name.startsWith('.git')) continue
      const full = join(dir, name)
      let st
      try {
        st = lstatSync(full)
      } catch {
        continue
      }
      // Never traverse or read through a symlink: it can point at host files outside /repos.
      if (st.isSymbolicLink()) continue
      if (st.isDirectory()) {
        if (isRealPathUnder(rootReal, full)) stack.push(full)
      } else if (st.isFile() && st.size <= 256 * 1024) {
        const ext = extname(name).toLowerCase()
        if (['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.java', '.kt', '.go', '.rb', '.graphql', '.gql'].includes(ext)) {
          out.push(full)
        }
      }
    }
  }
  return out
}

/**
 * Deterministic 11-framework static route & sink extractor over mounted `/repos`.
 * Covers: Next.js (App/Pages/Server Actions), Express, Fastify, NestJS, Django/DRF,
 * FastAPI, Flask, Spring Boot, Rails, Go (net/http, gin, echo, chi), and GraphQL SDL.
 */
export function extractStaticFrameworkRoutes(reposDir: string): {
  routes: StaticExtractedRoute[]
  frameworks: string[]
} {
  if (!reposDir || !existsSync(reposDir)) return { routes: [], frameworks: [] }
  const files = walkRepoFiles(reposDir)
  let rootReal: string
  try {
    rootReal = realpathSync(reposDir)
  } catch {
    return { routes: [], frameworks: [] }
  }
  const routes: StaticExtractedRoute[] = []
  const frameworks = new Set<string>()
  const seen = new Set<string>()

  const pushRoute = (r: StaticExtractedRoute) => {
    const key = `${r.method.toUpperCase()} ${r.pathTemplate}`
    if (seen.has(key)) return
    seen.add(key)
    frameworks.add(r.framework)
    routes.push({ ...r, extraction: r.extraction ?? 'regex' })
  }

  for (const fullPath of files) {
    const code = readRepoRegularFile(fullPath)
    if (code === null) continue
    const rel = relative(rootReal, fullPath).split(sep).join('/')
    const repoName = rel.split('/')[0] || 'repo'
    const ext = extname(fullPath).toLowerCase()
    const meta = detectSinksAndGuards(code)

    // 1. Next.js App Router: .../app/<route>/route.{ts,tsx,js,jsx}
    const appRouteMatch = /(?:^|\/)app(\/[^?#]*)\/route\.(?:ts|tsx|js|jsx|mjs)$/i.exec(rel)
    if (appRouteMatch) {
      const rawRoute = appRouteMatch[1].replace(/\/\([^)]+\)/g, '') || '/'
      const pathTemplate = normalizeRouteTemplate(rawRoute)
      const methods = [...code.matchAll(/export\s+(?:async\s+)?(?:function|const|let)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g)].map(m => m[1])
      for (const method of methods.length ? methods : ['GET']) {
        pushRoute({
          method,
          pathTemplate,
          framework: 'nextjs',
          ...meta,
          riskScore: scoreEndpointRisk(method, pathTemplate, meta.sinkKinds, meta.authRequirement),
          params: extractDynamicPathParams(pathTemplate),
          codeLocation: { repo: repoName, file: rel, startLine: 1, endLine: Math.min(40, code.split('\n').length) },
        })
      }
    }

    // 1b. Next.js Pages API Router: .../pages/api/<route>.{ts,js}
    const pagesApiMatch = /(?:^|\/)pages(\/api\/.+)\.(?:ts|tsx|js|jsx)$/i.exec(rel)
    if (pagesApiMatch) {
      const rawRoute = pagesApiMatch[1].replace(/\/index$/, '') || '/api'
      const pathTemplate = normalizeRouteTemplate(rawRoute)
      pushRoute({
        method: 'POST',
        pathTemplate,
        framework: 'nextjs',
        ...meta,
        riskScore: scoreEndpointRisk('POST', pathTemplate, meta.sinkKinds, meta.authRequirement),
        params: extractDynamicPathParams(pathTemplate),
        codeLocation: { repo: repoName, file: rel, startLine: 1, endLine: Math.min(40, code.split('\n').length) },
      })
    }

    // 1c. Next.js "use server" Server Actions
    if (/['"]use server['"]/.test(code)) {
      for (const m of code.matchAll(/export\s+(?:async\s+)?function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g)) {
        const line = lineNumberAt(code, m.index ?? 0)
        const pathTemplate = `/_actions/${m[1]}`
        pushRoute({
          method: 'POST',
          pathTemplate,
          framework: 'nextjs',
          ...meta,
          sinkKinds: [...new Set([...meta.sinkKinds, 'server_action'])],
          riskScore: scoreEndpointRisk('POST', pathTemplate, ['server_action', ...meta.sinkKinds], meta.authRequirement),
          params: [],
          codeLocation: { repo: repoName, file: rel, startLine: line, endLine: line + 5 },
        })
      }
    }

    // 2 & 3. Express / Fastify / Hono JS/TS routes
    if (['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].includes(ext)) {
      const isFastify = /\bfastify\b/i.test(code)
      for (const m of code.matchAll(/\b(?:app|router|fastify|server|api)\.(get|post|put|patch|delete|options|head|all)\s*\(\s*['"`]([^'"`\r\n]+)['"`]/gi)) {
        if (!isPathLikeRouteLiteral(m[2])) continue
        const method = m[1].toUpperCase() === 'ALL' ? 'GET' : m[1].toUpperCase()
        const pathTemplate = normalizeRouteTemplate(m[2])
        const line = lineNumberAt(code, m.index ?? 0)
        pushRoute({
          method,
          pathTemplate,
          framework: isFastify ? 'fastify' : 'express',
          ...meta,
          riskScore: scoreEndpointRisk(method, pathTemplate, meta.sinkKinds, meta.authRequirement),
          params: extractDynamicPathParams(pathTemplate),
          codeLocation: { repo: repoName, file: rel, startLine: line, endLine: line + 3 },
        })
      }

      // 4. NestJS decorators (@Controller + @Get/@Post/...)
      const ctrlMatch = /@Controller\s*\(\s*['"`]([^'"`]*)['"`]\s*\)/.exec(code)
      if (ctrlMatch || /@(?:Get|Post|Put|Patch|Delete)\s*\(/.test(code)) {
        const base = ctrlMatch ? `/${ctrlMatch[1].replace(/^\/|\/$/g, '')}` : ''
        for (const m of code.matchAll(/@(Get|Post|Put|Patch|Delete)\s*\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)/g)) {
          const method = m[1].toUpperCase()
          const sub = m[2] ? `/${m[2].replace(/^\//, '')}` : ''
          const pathTemplate = normalizeRouteTemplate(`${base}${sub}` || '/')
          const line = lineNumberAt(code, m.index ?? 0)
          pushRoute({
            method,
            pathTemplate,
            framework: 'nestjs',
            ...meta,
            riskScore: scoreEndpointRisk(method, pathTemplate, meta.sinkKinds, meta.authRequirement),
            params: extractDynamicPathParams(pathTemplate),
            codeLocation: { repo: repoName, file: rel, startLine: line, endLine: line + 3 },
          })
        }
      }

      // Generic Node http.createServer pathname checks (e.g. lab fixtures)
      for (const m of code.matchAll(/pathname\s*===?\s*['"`](\/[a-zA-Z0-9_/:.-]+)['"`]/g)) {
        const pathTemplate = normalizeRouteTemplate(m[1])
        const line = lineNumberAt(code, m.index ?? 0)
        pushRoute({
          method: 'GET',
          pathTemplate,
          framework: 'express',
          ...meta,
          riskScore: scoreEndpointRisk('GET', pathTemplate, meta.sinkKinds, meta.authRequirement),
          params: extractDynamicPathParams(pathTemplate),
          codeLocation: { repo: repoName, file: rel, startLine: line, endLine: line + 3 },
        })
      }
    }

    // 5, 6, 7. Python: FastAPI, Flask, Django/DRF
    if (ext === '.py') {
      // FastAPI / Flask method decorators: @app.get("/items/{item_id}")
      for (const m of code.matchAll(/@[a-zA-Z0-9_]+\.(get|post|put|patch|delete|options|head)\s*\(\s*[rf]?['"]([^'"\r\n]+)['"]/gi)) {
        const method = m[1].toUpperCase()
        const pathTemplate = normalizeRouteTemplate(m[2])
        const line = lineNumberAt(code, m.index ?? 0)
        const fw = /\bflask\b/i.test(code) ? 'flask' : 'fastapi'
        pushRoute({
          method,
          pathTemplate,
          framework: fw,
          ...meta,
          riskScore: scoreEndpointRisk(method, pathTemplate, meta.sinkKinds, meta.authRequirement),
          params: extractDynamicPathParams(pathTemplate),
          codeLocation: { repo: repoName, file: rel, startLine: line, endLine: line + 3 },
        })
      }
      // Flask @app.route('/path', methods=['GET', 'POST'])
      for (const m of code.matchAll(/@[a-zA-Z0-9_]+\.route\s*\(\s*['"]([^'"\r\n]+)['"]([^)]*)\)/g)) {
        const pathTemplate = normalizeRouteTemplate(m[1])
        const line = lineNumberAt(code, m.index ?? 0)
        const methodsMatch = /methods\s*=\s*\[([^\]]+)\]/.exec(m[2])
        const methods = methodsMatch
          ? [...methodsMatch[1].matchAll(/['"]([A-Za-z]+)['"]/g)].map(x => x[1].toUpperCase())
          : ['GET']
        for (const method of methods) {
          pushRoute({
            method,
            pathTemplate,
            framework: 'flask',
            ...meta,
            riskScore: scoreEndpointRisk(method, pathTemplate, meta.sinkKinds, meta.authRequirement),
            params: extractDynamicPathParams(pathTemplate),
            codeLocation: { repo: repoName, file: rel, startLine: line, endLine: line + 3 },
          })
        }
      }
      // Django / DRF: path('api/orders/<int:id>/', view) / re_path / url
      for (const m of code.matchAll(/\b(?:re_path|path|url)\s*\(\s*r?['"]([^'"\r\n]+)['"]/g)) {
        const raw = m[1].replace(/^\^/, '').replace(/\$$/, '')
        if (!raw || raw.startsWith('http')) continue
        const pathTemplate = normalizeRouteTemplate(raw.startsWith('/') ? raw : `/${raw}`)
        const line = lineNumberAt(code, m.index ?? 0)
        pushRoute({
          method: 'GET',
          pathTemplate,
          framework: 'django',
          ...meta,
          riskScore: scoreEndpointRisk('GET', pathTemplate, meta.sinkKinds, meta.authRequirement),
          params: extractDynamicPathParams(pathTemplate),
          codeLocation: { repo: repoName, file: rel, startLine: line, endLine: line + 2 },
        })
      }
    }

    // 8. Spring Boot (Java / Kotlin)
    if (ext === '.java' || ext === '.kt') {
      const classReqMatch = /@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/.exec(code)
      const base = classReqMatch ? `/${classReqMatch[1].replace(/^\/|\/$/g, '')}` : ''
      for (const m of code.matchAll(/@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["']/g)) {
        const method = m[1] === 'Request' ? 'GET' : m[1].toUpperCase()
        const sub = m[2].startsWith('/') ? m[2] : `/${m[2]}`
        const pathTemplate = normalizeRouteTemplate(base && !sub.startsWith(base) ? `${base}${sub}` : sub)
        const line = lineNumberAt(code, m.index ?? 0)
        pushRoute({
          method,
          pathTemplate,
          framework: 'spring',
          ...meta,
          riskScore: scoreEndpointRisk(method, pathTemplate, meta.sinkKinds, meta.authRequirement),
          params: extractDynamicPathParams(pathTemplate),
          codeLocation: { repo: repoName, file: rel, startLine: line, endLine: line + 3 },
        })
      }
    }

    // 9. Ruby on Rails (config/routes.rb & controllers)
    if (ext === '.rb') {
      for (const m of code.matchAll(/^\s*(get|post|put|patch|delete)\s+['"]([^'"\r\n]+)['"]/gim)) {
        const method = m[1].toUpperCase()
        const pathTemplate = normalizeRouteTemplate(m[2].startsWith('/') ? m[2] : `/${m[2]}`)
        const line = lineNumberAt(code, m.index ?? 0)
        pushRoute({
          method,
          pathTemplate,
          framework: 'rails',
          ...meta,
          riskScore: scoreEndpointRisk(method, pathTemplate, meta.sinkKinds, meta.authRequirement),
          params: extractDynamicPathParams(pathTemplate),
          codeLocation: { repo: repoName, file: rel, startLine: line, endLine: line + 2 },
        })
      }
      for (const m of code.matchAll(/^\s*resources?\s+:([a-zA-Z0-9_]+)/gm)) {
        const res = m[1]
        const line = lineNumberAt(code, m.index ?? 0)
        for (const [method, path] of [['GET', `/${res}`], ['POST', `/${res}`], ['GET', `/${res}/:id`]] as const) {
          pushRoute({
            method,
            pathTemplate: path,
            framework: 'rails',
            ...meta,
            riskScore: scoreEndpointRisk(method, path, meta.sinkKinds, meta.authRequirement),
            params: extractDynamicPathParams(path),
            codeLocation: { repo: repoName, file: rel, startLine: line, endLine: line + 1 },
          })
        }
      }
    }

    // 10. Go (net/http, gin, echo, chi)
    if (ext === '.go') {
      for (const m of code.matchAll(/\.\s*(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|HandleFunc|Handle)\s*\(\s*"([^"\r\n]+)"/g)) {
        const rawMethod = m[1].toUpperCase()
        const method = (rawMethod === 'HANDLEFUNC' || rawMethod === 'HANDLE') ? 'GET' : rawMethod
        const pathTemplate = normalizeRouteTemplate(m[2])
        const line = lineNumberAt(code, m.index ?? 0)
        pushRoute({
          method,
          pathTemplate,
          framework: 'go',
          ...meta,
          riskScore: scoreEndpointRisk(method, pathTemplate, meta.sinkKinds, meta.authRequirement),
          params: extractDynamicPathParams(pathTemplate),
          codeLocation: { repo: repoName, file: rel, startLine: line, endLine: line + 3 },
        })
      }
    }

    // 11. GraphQL SDL files
    if (ext === '.graphql' || ext === '.gql') {
      pushRoute({
        method: 'POST',
        pathTemplate: '/graphql',
        framework: 'graphql',
        ...meta,
        riskScore: 85,
        params: [],
        codeLocation: { repo: repoName, file: rel, startLine: 1, endLine: Math.min(40, code.split('\n').length) },
      })
    }
  }

  return { routes, frameworks: [...frameworks] }
}

// ============================================================================
// Program Graph ingestion (AST-primary routes, guard chains, hypotheses, origins)
// ============================================================================

const GRAPH_SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.java', '.kt', '.go', '.rb'])

/** Guard-chain classifiers mirroring the Program Graph's middleware taxonomy. */
const ADMIN_CHAIN_RE = /\b(?:admin\w*|isAdmin|requireAdmin\w*|superuser\w*|staff\w*|role\w*|rbac|permission\w*|privilege\w*|policy\w*|hasRole|hasAuthority)/i
const TENANT_CHAIN_RE = /(?:tenant|organization|organisation|orgId|org_id|account|workspace|membership|ownership|ownerId|owner_id|scopeCheck|belongsTo)/i

interface RepoGraphInputs {
  sourceFiles: Array<{ path: string; content: string }>
  dockerfiles: Array<{ path: string; content: string }>
  manifests: Array<{ path: string; content: string }>
  compose?: string
  ingress?: string
  mountedRepos: string[]
}

/**
 * Bounded walk of the mounted `/repos` tree collecting Program Graph inputs. Symlinks are never
 * followed and file sizes are capped, so graph extraction can run on an untrusted mount.
 */
function collectRepoGraphInputs(reposDir: string, maxFiles = 2500): RepoGraphInputs | null {
  const inputs: RepoGraphInputs = { sourceFiles: [], dockerfiles: [], manifests: [], mountedRepos: [] }
  if (!reposDir || !existsSync(reposDir)) return null
  let rootReal: string
  try {
    rootReal = realpathSync(reposDir)
  } catch {
    return null
  }
  inputs.mountedRepos = listMountedRepos(reposDir)
    .map(mounted => mounted.replace(/^\/repos\//, ''))
    .filter(mounted => mounted && (existsSync(join(rootReal, mounted)) || !mounted.includes('/')))
  const stack: string[] = [rootReal]
  let visited = 0
  while (stack.length > 0 && visited < maxFiles) {
    const dir = stack.pop()!
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      continue
    }
    for (const name of entries) {
      if (visited >= maxFiles) break
      if (SKIP_DIRS.has(name) || name.startsWith('.git')) continue
      const full = join(dir, name)
      let st
      try {
        st = lstatSync(full)
      } catch {
        continue
      }
      if (st.isSymbolicLink()) continue
      if (st.isDirectory()) {
        if (isRealPathUnder(rootReal, full)) stack.push(full)
        continue
      }
      if (!st.isFile() || st.size > 256 * 1024) continue
      visited += 1
      const rel = relative(rootReal, full).split(sep).join('/')
      const base = name.toLowerCase()
      const ext = extname(name).toLowerCase()
      const isCompose = /^(?:docker-)?compose(?:[._-][^/]*)?\.ya?ml$/i.test(name)
      const isDockerfile = /^dockerfile(?:\.[^/]*)?$/i.test(name)
      const isManifest = base === 'package.json'
      const looksIngress = /^ingress[^/]*\.ya?ml$/i.test(name)
      if (!GRAPH_SOURCE_EXTENSIONS.has(ext) && !isCompose && !isDockerfile && !isManifest && !looksIngress) continue
      const content = readRepoRegularFile(full)
      if (content === null) continue
      if (GRAPH_SOURCE_EXTENSIONS.has(ext)) inputs.sourceFiles.push({ path: rel, content })
      if (isDockerfile && inputs.dockerfiles.length < 40) inputs.dockerfiles.push({ path: rel, content })
      if (isManifest && inputs.manifests.length < 80) inputs.manifests.push({ path: rel, content })
      if (isCompose && inputs.compose === undefined) inputs.compose = content
      if ((looksIngress || (!inputs.ingress && content.slice(0, 4000).includes('kind: Ingress'))) && inputs.ingress === undefined) {
        inputs.ingress = content
      }
    }
  }
  return inputs.sourceFiles.length > 0 || inputs.dockerfiles.length > 0 ? inputs : null
}

function repoBasename(path: string): string {
  const parts = path.split('/').filter(Boolean)
  return parts[parts.length - 1] ?? path
}

/** Candidate monorepo service roots from mounted repos, Dockerfiles and top-level manifests. */
function discoverGraphServices(inputs: RepoGraphInputs): MonorepoService[] {
  const services = new Map<string, MonorepoService>()
  const add = (root: string, name: string) => {
    const cleanRoot = root.replace(/\/$/, '')
    if (services.has(cleanRoot)) return
    services.set(cleanRoot, { name, ...(cleanRoot ? { root: cleanRoot } : {}) })
  }
  for (const mounted of inputs.mountedRepos) add(mounted, repoBasename(mounted))
  for (const dockerfile of inputs.dockerfiles) {
    const root = dockerfile.path.replace(/\/Dockerfile(?:\..*)?$/i, '')
    add(root, repoBasename(root) || 'app')
  }
  // Manifests only contribute roots at the mounted-repo root or one level below (avoid exposing
  // every workspace package as a distinct origin candidate).
  for (const manifest of inputs.manifests) {
    const root = manifest.path.replace(/\/package\.json$/, '')
    const ownerRepoDepth = inputs.mountedRepos.find(mounted => root === mounted || root.startsWith(`${mounted}/`))
      ? (inputs.mountedRepos.find(mounted => root === mounted || root.startsWith(`${mounted}/`))!.split('/').length)
      : 0
    const depth = root ? root.split('/').length : 0
    if (ownerRepoDepth === 0 || depth > ownerRepoDepth + 1) continue
    add(root, repoBasename(root) || 'app')
  }
  return [...services.values()].slice(0, 32)
}

function authClassFromGuards(guards: readonly string[]): StaticExtractedRoute['authClass'] {
  if (guards.some(guard => ADMIN_CHAIN_RE.test(guard))) return 'admin'
  if (guards.some(guard => TENANT_CHAIN_RE.test(guard))) return 'tenant'
  if (guards.length > 0) return 'auth'
  return 'unguarded'
}

function authRequirementFromGuards(guards: readonly string[], authClass: StaticExtractedRoute['authClass']): string | null {
  if (!guards.length) return null
  return `${authClass}:${guards.join(',')}`
}

function routeParamsFromGraph(route: ProgramRoute): StaticExtractedRoute['params'] {
  const out: StaticExtractedRoute['params'] = []
  const seen = new Set<string>()
  const push = (name: string, location: ParamLocation) => {
    const clean = name.trim()
    if (!clean || seen.has(`${location}:${clean}`)) return
    seen.add(`${location}:${clean}`)
    out.push({ name: clean, location, isObjectId: location === 'path' || OBJECT_ID_PARAM_RE.test(clean) })
  }
  for (const name of route.input.params) push(name, 'path')
  for (const name of extractDynamicPathParams(route.path)) push(name.name, 'path')
  for (const name of route.input.query) push(name, 'query')
  for (const name of route.input.body) push(name, 'json')
  return out
}

/** Longest mounted-repo prefix that owns a route file. */
function repoForRouteFile(file: string, mountedRepos: readonly string[]): string {
  const owner = [...mountedRepos].sort((a, b) => b.length - a.length).find(mounted => file === mounted || file.startsWith(`${mounted}/`))
  return owner ?? file.split('/')[0] ?? 'repo'
}

interface RouteOriginResolution {
  origin: string
  confidence: ServiceOriginMapping['confidence']
  service?: string
  evidence: string[]
}

/**
 * Attribute a route file to a target origin. Monorepo service roots are matched longest-first;
 * `origins[0]` is only used as a documented fallback (recorded in provenance) when no service
 * root/ingress/port evidence matches.
 */
function resolveRouteOrigin(
  file: string,
  mappings: readonly ServiceOriginMapping[],
  origins: readonly string[],
): RouteOriginResolution {
  const candidates = mappings
    .filter(mapping => mapping.root && mapping.origin && (file === mapping.root || file.startsWith(`${mapping.root}/`)))
    .sort((a, b) => (b.root?.length ?? 0) - (a.root?.length ?? 0))
  const strong = candidates.find(mapping => mapping.confidence !== 'fallback' && mapping.confidence !== 'unmapped')
  if (strong && strong.origin) {
    return {
      origin: strong.origin,
      confidence: strong.confidence,
      ...(strong.root ? { service: strong.service } : {}),
      evidence: strong.evidence.length ? strong.evidence : [`service root ${strong.root} matched ${file}`],
    }
  }
  if (origins.length === 1) {
    return { origin: origins[0]!, confidence: 'exact', evidence: ['single approved origin for the run'] }
  }
  const fallback = candidates[0]
  if (fallback && fallback.origin) {
    return {
      origin: fallback.origin,
      confidence: fallback.confidence,
      ...(fallback.root ? { service: fallback.service } : {}),
      evidence: fallback.evidence.length ? fallback.evidence : [`service root ${fallback.root} matched ${file}`],
    }
  }
  return {
    origin: origins[0]!,
    confidence: 'fallback',
    evidence: ['no service root/ingress/port evidence; using origins[0] as documented fallback'],
  }
}

export interface RepoProgramGraphExtraction {
  graph: ProgramGraph
  /** AST-derived routes tagged with guard chain, service and origin provenance. */
  routes: StaticExtractedRoute[]
  frameworks: string[]
  hypotheses: CodeToRuntimeHypothesis[]
  originMappings: ServiceOriginMapping[]
  routeOrigins: Record<string, RouteOriginResolution>
  warnings: string[]
}

/**
 * AST-primary route extraction for a mounted/synced repo. Returns `null` when no repository
 * source is present so callers fall back to the regex scanner unchanged.
 */
export function extractRepoProgramGraph(input: {
  reposDir?: string
  origins: readonly string[]
  maxFiles?: number
  /** Security-relevant commit signals (from the graph producer) folded into hypotheses. */
  recentDiffSignals?: readonly CommitDiffSignal[]
}): RepoProgramGraphExtraction | null {
  if (!input.reposDir) return null
  const inputs = collectRepoGraphInputs(input.reposDir, input.maxFiles)
  if (!inputs) return null
  const graph = extractProgramGraph({ files: inputs.sourceFiles, repo: inputs.mountedRepos.join(',') || undefined })
  const services = discoverGraphServices(inputs)
  const originMappings = services.length
    ? mapServicesToOrigins({
        services,
        origins: input.origins,
        ...(inputs.compose ? { compose: inputs.compose } : {}),
        ...(inputs.ingress ? { ingress: inputs.ingress } : {}),
        dockerfiles: inputs.dockerfiles,
        manifests: inputs.manifests,
      })
    : []
  const filesByPath = new Map(inputs.sourceFiles.map(file => [file.path, file.content]))
  const globalGuards = graph.globalMiddleware.filter(name => ADMIN_CHAIN_RE.test(name) || TENANT_CHAIN_RE.test(name) || /\b(?:auth|session|jwt|guard|login|authorize)/i.test(name))
  const routeOrigins: Record<string, RouteOriginResolution> = {}
  const routes: StaticExtractedRoute[] = []
  for (const route of graph.routes) {
    const pathTemplate = normalizeDiscoveryTemplate(route.path)
    const guards = route.guards.length ? route.guards : globalGuards
    const authClass = authClassFromGuards(guards)
    const authRequirement = authRequirementFromGuards(guards, authClass)
    const tenantGuards = guards.filter(guard => TENANT_CHAIN_RE.test(guard))
    const ownershipGuard = tenantGuards.length ? tenantGuards.join(',') : null
    const fileCode = filesByPath.get(route.file) ?? ''
    const sinkMeta = detectSinksAndGuards(fileCode)
    const resolved = resolveRouteOrigin(route.file, originMappings, input.origins)
    const key = `${route.method.toUpperCase()} ${pathTemplate}`
    if (!routeOrigins[key] || routeOrigins[key]!.confidence === 'fallback') routeOrigins[key] = resolved
    routes.push({
      method: route.method.toUpperCase(),
      pathTemplate,
      framework: route.framework,
      authRequirement,
      ownershipGuard,
      sinkKinds: sinkMeta.sinkKinds,
      riskScore: scoreEndpointRisk(route.method, pathTemplate, sinkMeta.sinkKinds, authClass === 'unguarded' ? 'none' : null),
      params: routeParamsFromGraph(route),
      codeLocation: {
        repo: repoForRouteFile(route.file, inputs.mountedRepos),
        file: route.file,
        startLine: Math.max(1, route.handlerLine ?? route.line),
        endLine: Math.max(1, route.handlerLine ?? route.line) + 3,
      },
      extraction: 'ast',
      authClass,
      guards: [...guards],
      middleware: [...route.middleware],
      mountedFrom: [...route.mountedFrom],
      ...(resolved.service ? { service: resolved.service } : {}),
      origin: resolved.origin,
      originConfidence: resolved.confidence,
      routeId: route.id,
    })
  }
  return {
    graph,
    routes,
    frameworks: [...new Set(graph.routes.map(route => route.framework))],
    hypotheses: deriveCodeToRuntimeHypotheses(graph, {
      ...(input.recentDiffSignals?.length ? { recentDiffSignals: input.recentDiffSignals } : {}),
    }),
    originMappings,
    routeOrigins,
    warnings: [...graph.warnings],
  }
}

/**
 * Merge AST routes with regex fallback routes, deduped by `(origin, METHOD, pathTemplate)`.
 * AST wins on collision; regex-only routes are retained and marked `extraction: 'regex'`.
 */
export function mergeStaticRouteExtractions(input: {
  astRoutes: readonly StaticExtractedRoute[]
  regexRoutes: readonly StaticExtractedRoute[]
  defaultOrigin: string
}): { routes: StaticExtractedRoute[]; duplicates: number } {
  const merged: StaticExtractedRoute[] = []
  const seen = new Set<string>()
  let duplicates = 0
  const keyOf = (route: StaticExtractedRoute) =>
    `${(route.origin ?? input.defaultOrigin).toLowerCase()}|${route.method.toUpperCase()}|${route.pathTemplate}`
  for (const route of input.astRoutes) {
    const key = keyOf(route)
    if (seen.has(key)) { duplicates += 1; continue }
    seen.add(key)
    merged.push(route)
  }
  for (const route of input.regexRoutes) {
    const key = keyOf(route)
    if (seen.has(key)) { duplicates += 1; continue }
    seen.add(key)
    merged.push({ ...route, extraction: route.extraction ?? 'regex' })
  }
  return { routes: merged, duplicates }
}

// ----------------------------------------------------------------------------
// Ranked probe plan: lossless storage, prioritized/sampled probing
// ----------------------------------------------------------------------------

export interface AstRouteCluster {
  /** Structural CRUD signature: framework|method|path-shape|guard-chain. */
  signature: string
  method: string
  framework: string
  routes: number
  representatives: Array<{ method: string; pathTemplate: string }>
}

export interface RankedAstProbePlan {
  totalRoutes: number
  /** Tier A: linked to an AST sink/recent-diff/admin-guard hypothesis. */
  priority: StaticExtractedRoute[]
  /** Tier B: mutating ID-bearing/schema-typed routes and role-exclusive admin routes. */
  schemaTyped: StaticExtractedRoute[]
  /** Tier C: structural long tail, probed by cluster representatives. */
  longTail: StaticExtractedRoute[]
  clusters: AstRouteCluster[]
  representatives: StaticExtractedRoute[]
  /** Tier A + Tier B + Tier C representatives, deduped. */
  probeSubset: StaticExtractedRoute[]
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

/**
 * Structural clustering signature. The first path segment (API root) is preserved; deeper
 * literal segments collapse to `{lit}` and parameters to `:p`, so CRUD boilerplate across
 * resources (`/rest/projects/:id`, `/rest/billing-docs/:docId`) shares one cluster. Guard
 * chains are part of the signature: an unguarded sibling must never be sampled away by a
 * guarded representative.
 */
export function astRouteClusterSignature(route: StaticExtractedRoute): string {
  const segments = route.pathTemplate.split('?')[0]!.split('/').filter(Boolean)
  const shape = segments.map((segment, index) => {
    if (/^[:{<]/.test(segment) || segment.startsWith('[')) return ':p'
    return index === 0 ? segment.toLowerCase() : '{lit}'
  }).join('/')
  const guards = [...(route.guards ?? [])].sort().join('>')
  return `${route.framework}|${route.method.toUpperCase()}|/${shape}|${guards}`
}

function routeKey(route: StaticExtractedRoute): string {
  return `${route.method.toUpperCase()} ${route.pathTemplate}`
}

/**
 * Rank AST routes for probing and sample CRUD boilerplate by structural cluster.
 * The caller stores every route losslessly; this plan only decides probe order/breadth.
 */
export function rankAndClusterAstRoutes(input: {
  routes: readonly StaticExtractedRoute[]
  hypotheses?: readonly CodeToRuntimeHypothesis[]
  /** Representatives sampled per long-tail cluster (default 1). */
  maxRepresentativesPerCluster?: number
  /** Upper bound on sampled long-tail clusters (default 24). */
  maxLongTailClusters?: number
}): RankedAstProbePlan {
  const perCluster = Math.max(1, Math.min(input.maxRepresentativesPerCluster ?? 1, 8))
  const maxClusters = Math.max(1, Math.min(input.maxLongTailClusters ?? 24, 200))
  const hypothesisKeys = new Set<string>()
  for (const hypothesis of input.hypotheses ?? []) {
    if (hypothesis.routeId) hypothesisKeys.add(`id:${hypothesis.routeId}`)
    if (hypothesis.method && hypothesis.path) hypothesisKeys.add(`${hypothesis.method.toUpperCase()} ${hypothesis.path}`)
  }
  const isPriority = (route: StaticExtractedRoute) =>
    (route.routeId ? hypothesisKeys.has(`id:${route.routeId}`) : false) || hypothesisKeys.has(routeKey(route))

  const priority: StaticExtractedRoute[] = []
  const schemaTyped: StaticExtractedRoute[] = []
  const longTail: StaticExtractedRoute[] = []
  const clusters = new Map<string, { meta: AstRouteCluster; members: StaticExtractedRoute[] }>()
  for (const route of input.routes) {
    const signature = astRouteClusterSignature(route)
    const entry = clusters.get(signature) ?? {
      meta: { signature, method: route.method.toUpperCase(), framework: route.framework, routes: 0, representatives: [] },
      members: [],
    }
    entry.members.push(route)
    entry.meta.routes += 1
    clusters.set(signature, entry)

    if (isPriority(route)) {
      priority.push(route)
      continue
    }
    const mutating = MUTATING_METHODS.has(route.method.toUpperCase())
    const idBearing = route.params.some(param => param.location === 'path')
    const schemaTypedInput = route.params.some(param => param.location === 'json' || param.location === 'query')
    if ((mutating && (idBearing || schemaTypedInput)) || route.authClass === 'admin') {
      schemaTyped.push(route)
      continue
    }
    longTail.push(route)
  }

  const representatives: StaticExtractedRoute[] = []
  const longTailKeys = new Set(longTail.map(routeKey))
  let usedClusters = 0
  const clusterList = [...clusters.values()].sort((a, b) => b.meta.routes - a.meta.routes)
  for (const cluster of clusterList) {
    const candidates = cluster.members
      .filter(route => longTailKeys.has(routeKey(route)))
      .sort((a, b) => b.riskScore - a.riskScore)
    if (candidates.length === 0) continue
    if (usedClusters >= maxClusters) break
    usedClusters += 1
    const sampled = candidates.slice(0, perCluster)
    representatives.push(...sampled)
    cluster.meta.representatives = sampled.map(route => ({ method: route.method.toUpperCase(), pathTemplate: route.pathTemplate }))
  }

  const seen = new Set<string>()
  const probeSubset: StaticExtractedRoute[] = []
  for (const route of [...priority, ...schemaTyped, ...representatives]) {
    const key = routeKey(route)
    if (seen.has(key)) continue
    seen.add(key)
    probeSubset.push(route)
  }
  return {
    totalRoutes: input.routes.length,
    priority,
    schemaTyped,
    longTail,
    clusters: [...clusters.values()].map(cluster => cluster.meta),
    representatives,
    probeSubset,
  }
}

/** Hard per-run cap on distinct code-dataflow slices built during Phase-0. */
export const PHASE0_MAX_CODE_SLICES = 200

/** Bounded accounting for Phase-0 code-slice attachment (metrics + result payload). */
export interface Phase0CodeSliceSummary {
  /** Route-bound hypotheses considered for a slice. */
  candidates: number
  /** Hypotheses that received a rendered slice. */
  attached: number
  /** Route-bound candidates that produced no slice (route absent from the graph). */
  unavailable: number
  /** Candidates left without a slice because the per-run cap was reached. */
  capped: number
  /** Distinct routes that produced a slice. */
  routes: number
  /** Mean rendered JSON size across the distinct attached slices. */
  avgBytes: number
  /** `missing_guard` entries carried by the distinct attached slices. */
  guardDiffs: number
  maxSlices: number
  /** `attached` when at least one slice was attached, else `unavailable` (no graph/source). */
  codeSlice: 'attached' | 'unavailable'
}

export type CodeSliceHypothesis = CodeToRuntimeHypothesis & { codeSlice?: CodeDataflowSlice }

const CODE_SLICE_SEVERITY_RANK: Record<CodeToRuntimeHypothesis['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

export function emptyCodeSliceSummary(maxSlices = PHASE0_MAX_CODE_SLICES): Phase0CodeSliceSummary {
  return {
    candidates: 0,
    attached: 0,
    unavailable: 0,
    capped: 0,
    routes: 0,
    avgBytes: 0,
    guardDiffs: 0,
    maxSlices,
    codeSlice: 'unavailable',
  }
}

/**
 * Attach compact (`<= 600 B`) dataflow slices to code-to-runtime hypotheses.
 *
 * Selection is deterministic and layer-first: Tier-A routes (hypothesis-linked probe-plan
 * priorities) first, then Tier-B schema/admin routes, then the long tail; ties break on severity,
 * confidence and hypothesis id. At most `maxSlices` distinct routes are built per run (`200` hard
 * cap), and the sink-path walk is shared across every slice. Hypotheses whose route is not in the
 * graph stay untouched — no slice is fabricated.
 */
export function attachCodeSlicesToPhase0Hypotheses(input: {
  graph?: ProgramGraph | null
  hypotheses: readonly CodeToRuntimeHypothesis[]
  /** Tier-A probe-plan route ids/keys (`METHOD path`). */
  priorityRouteIds?: ReadonlySet<string>
  priorityRouteKeys?: ReadonlySet<string>
  /** Tier-B probe-plan route ids/keys (`METHOD path`). */
  schemaTypedRouteIds?: ReadonlySet<string>
  schemaTypedRouteKeys?: ReadonlySet<string>
  maxSlices?: number
  /** Reuse a precomputed sink-path set (avoids re-walking a large graph). */
  sinkPaths?: readonly RouteSinkPath[]
}): { hypotheses: CodeSliceHypothesis[]; summary: Phase0CodeSliceSummary } {
  const maxSlices = Math.max(0, Math.min(input.maxSlices ?? PHASE0_MAX_CODE_SLICES, PHASE0_MAX_CODE_SLICES))
  const summary = emptyCodeSliceSummary(maxSlices)
  const keyOf = (hypothesis: CodeToRuntimeHypothesis): { key: string; ref: { routeId?: string; method?: string; path?: string } } | null => {
    const routeId = typeof hypothesis.routeId === 'string' && hypothesis.routeId ? hypothesis.routeId : undefined
    const method = typeof hypothesis.method === 'string' && hypothesis.method ? hypothesis.method.toUpperCase() : undefined
    const path = typeof hypothesis.path === 'string' && hypothesis.path ? hypothesis.path : undefined
    if (!routeId && !path) return null
    return {
      key: routeId ?? `${method ?? ''} ${path ?? ''}`,
      ref: { ...(routeId ? { routeId } : {}), ...(method ? { method } : {}), ...(path ? { path } : {}) },
    }
  }
  const candidates: Array<{ index: number; key: string; ref: { routeId?: string; method?: string; path?: string } }> = []
  for (let index = 0; index < input.hypotheses.length; index += 1) {
    const bound = keyOf(input.hypotheses[index]!)
    if (bound) candidates.push({ index, ...bound })
  }
  summary.candidates = candidates.length
  if (!input.graph || candidates.length === 0) {
    summary.unavailable = candidates.length
    return { hypotheses: input.hypotheses.map(hypothesis => hypothesis), summary }
  }

  const routeKey = (method?: string, path?: string) => `${(method ?? '').toUpperCase()} ${path ?? ''}`
  const tierOf = (hypothesis: CodeToRuntimeHypothesis): number => {
    const id = hypothesis.routeId
    const key = routeKey(hypothesis.method, hypothesis.path)
    if ((id && input.priorityRouteIds?.has(id)) || (hypothesis.path && input.priorityRouteKeys?.has(key))) return 0
    if ((id && input.schemaTypedRouteIds?.has(id)) || (hypothesis.path && input.schemaTypedRouteKeys?.has(key))) return 1
    return 2
  }
  const ordered = [...candidates].sort((a, b) => {
    const ha = input.hypotheses[a.index]!
    const hb = input.hypotheses[b.index]!
    return tierOf(ha) - tierOf(hb)
      || CODE_SLICE_SEVERITY_RANK[ha.severity] - CODE_SLICE_SEVERITY_RANK[hb.severity]
      || hb.confidence - ha.confidence
      || (ha.id < hb.id ? -1 : ha.id > hb.id ? 1 : 0)
  })

  const sinkPaths = input.sinkPaths ?? resolveRouteSinkPaths(input.graph, { maxDepth: 8, maxPaths: 500 })
  const built = new Map<string, CodeDataflowSlice | null>()
  const assigned = new Map<number, CodeDataflowSlice>()
  const bytesByKey = new Map<string, number>()
  let attempted = 0
  for (const candidate of ordered) {
    let slice = built.get(candidate.key)
    if (slice === undefined) {
      if (attempted >= maxSlices) {
        summary.capped += 1
        continue
      }
      attempted += 1
      slice = buildCodeDataflowSlice(input.graph, candidate.ref, { sinkPaths, maxHops: 8 }) ?? null
      built.set(candidate.key, slice)
      if (slice) bytesByKey.set(candidate.key, Buffer.byteLength(JSON.stringify(slice), 'utf8'))
    }
    if (!slice) {
      summary.unavailable += 1
      continue
    }
    assigned.set(candidate.index, slice)
    summary.attached += 1
  }

  summary.routes = bytesByKey.size
  if (bytesByKey.size > 0) {
    let total = 0
    for (const bytes of bytesByKey.values()) total += bytes
    summary.avgBytes = Math.round(total / bytesByKey.size)
  }
  for (const slice of built.values()) {
    const diff = slice?.guardDiff?.length ?? 0
    if (diff > 0) summary.guardDiffs += diff
  }
  summary.codeSlice = summary.attached > 0 ? 'attached' : 'unavailable'

  return {
    hypotheses: input.hypotheses.map((hypothesis, index) => {
      const slice = assigned.get(index)
      return slice ? { ...hypothesis, codeSlice: slice } : hypothesis
    }),
    summary,
  }
}

const MANIFEST_BASENAMES = new Set([
  'package.json', 'requirements.txt', 'pyproject.toml', 'pipfile',
  'go.mod', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'gemfile',
])

function isManifestBasename(name: string): boolean {
  const base = name.toLowerCase()
  return MANIFEST_BASENAMES.has(base) || /^requirements[-.].*\.txt$/.test(base)
}

/** Read dependency manifests from the mounted repo tree (bounded; never executes a package manager). */
export function readRepoManifests(reposDir: string, maxFiles = 60): ManifestFile[] {
  if (!reposDir || !existsSync(reposDir)) return []
  let rootReal: string
  try {
    rootReal = realpathSync(reposDir)
  } catch {
    return []
  }
  const out: ManifestFile[] = []
  const stack: string[] = [rootReal]
  while (stack.length > 0 && out.length < maxFiles) {
    const dir = stack.pop()!
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      continue
    }
    for (const name of entries) {
      if (out.length >= maxFiles) break
      if (SKIP_DIRS.has(name) || name.startsWith('.git')) continue
      const full = join(dir, name)
      let st
      try {
        st = lstatSync(full)
      } catch {
        continue
      }
      // Symlinked directories/files are never traversed or read: a link named like a manifest
      // must not make the host parse files outside the mounted repo.
      if (st.isSymbolicLink()) continue
      if (st.isDirectory()) {
        if (isRealPathUnder(rootReal, full)) stack.push(full)
        continue
      }
      if (!st.isFile() || st.size > 256 * 1024 || !isManifestBasename(name)) continue
      const content = readRepoRegularFile(full)
      if (content === null) continue
      out.push({
        name: relative(rootReal, full).split(sep).join('/'),
        content,
      })
    }
  }
  return out
}

export function extractHtmlLinksAndScripts(html: string, origin: string): {
  links: string[]
  scripts: string[]
  forms: Array<{ action: string; method: string; inputs: string[]; enctype: string }>
  inputs: Array<{ name: string; id: string | null; type: string | null }>
} {
  const links = new Set<string>()
  const scripts = new Set<string>()
  const forms: Array<{ action: string; method: string; inputs: string[]; enctype: string }> = []
  const inputs: Array<{ name: string; id: string | null; type: string | null }> = []
  const seenInputs = new Set<string>()

  for (const m of html.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi)) {
    const clean = sanitizePathCandidate(m[1], origin)
    if (clean && !STATIC_ASSET_RE.test(clean)) links.add(clean)
  }
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) {
    const clean = sanitizePathCandidate(m[1], origin)
    if (clean) scripts.add(clean)
  }
  for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = m[1]
    const inner = m[2]
    const actionMatch = /\baction\s*=\s*["']([^"']+)["']/i.exec(attrs)
    const methodMatch = /\bmethod\s*=\s*["']([a-zA-Z]+)["']/i.exec(attrs)
    const enctypeMatch = /\benctype\s*=\s*["']([^"']+)["']/i.exec(attrs)
    const action = sanitizePathCandidate(actionMatch?.[1] ?? '/', origin) ?? '/'
    const method = (methodMatch?.[1] ?? 'GET').toUpperCase()
    const inputsInForm: string[] = []
    for (const im of inner.matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi)) {
      if (im[1]) inputsInForm.push(im[1])
    }
    forms.push({ action, method, inputs: inputsInForm, enctype: (enctypeMatch?.[1] ?? 'application/x-www-form-urlencoded').toLowerCase() })
  }
  // Standalone controls outside a <form> (common in SPA/wizard pages). Both name and id are
  // recorded because scripted pages frequently drive inputs by id.
  for (const tm of html.matchAll(/<(?:input|select|textarea)\b([^>]*)>/gi)) {
    const attrs = tm[1]
    const nameMatch = /\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs)
    const idMatch = /\bid\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs)
    const typeMatch = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs)
    const name = (nameMatch?.[1] ?? nameMatch?.[2] ?? nameMatch?.[3] ?? idMatch?.[1] ?? idMatch?.[2] ?? idMatch?.[3] ?? '').trim()
    if (!name) continue
    const id = (idMatch?.[1] ?? idMatch?.[2] ?? idMatch?.[3] ?? null)
    const type = (typeMatch?.[1] ?? typeMatch?.[2] ?? typeMatch?.[3] ?? null)
    const key = `${name}|${id ?? ''}`
    if (seenInputs.has(key)) continue
    seenInputs.add(key)
    inputs.push({ name, id: id ? id.trim() : null, type: type ? type.toLowerCase() : null })
  }
  return { links: [...links], scripts: [...scripts], forms, inputs }
}

/** Pull XML element names out of an error/echo response (e.g. "expected &lt;lookup&gt;&lt;name&gt;"). */
export function extractXmlHintTags(body: string): string[] {
  const decoded = body
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&apos;/g, "'")
  const expectedIdx = decoded.search(/\b(?:expected|required|missing|invalid)\b/i)
  const scope = expectedIdx >= 0 ? decoded.slice(expectedIdx, expectedIdx + 512) : decoded.slice(0, 512)
  const tags: string[] = []
  for (const m of scope.matchAll(/<\s*\/?\s*([A-Za-z_][A-Za-z0-9_.-]{0,31})\b[^>]*>/g)) {
    const tag = m[1]
    if (!tag) continue
    if (/^(?:error|errors|html|body|head|request|response|root|result|results|message|status|code|detail|details)$/i.test(tag)) continue
    if (!tags.includes(tag)) tags.push(tag)
  }
  return tags
}

/** Return the balanced `( ... )` slice starting at openParenIndex (quote-aware, bounded). */
function sliceBalancedCall(code: string, openParenIndex: number, max = 1400): string {
  let depth = 0
  let quote: string | null = null
  let escaped = false
  for (let i = openParenIndex; i < code.length && i - openParenIndex < max; i += 1) {
    const ch = code[i]
    if (quote) {
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === quote) quote = null
      continue
    }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue }
    if (ch === '(') depth += 1
    else if (ch === ')') {
      depth -= 1
      if (depth === 0) return code.slice(openParenIndex, i + 1)
    }
  }
  return code.slice(openParenIndex, openParenIndex + max)
}

export interface JsRequestParam {
  name: string
  location: 'query' | 'json' | 'form' | 'xml'
}

export interface JsRequestSpec {
  method: string
  path: string
  params: JsRequestParam[]
}

const JS_RESERVED_BODY_KEYS = /^(?:query|variables|operationName|method|headers|body|mode|credentials|cache|redirect|referrer|integrity|keepalive|signal|url|data|params)$/i

/**
 * Bounded regex scan of client bundles for request literals: fetch()/axios()/XHR URLs, HTTP methods,
 * JSON/urlencoded body keys, and XML element names adjacent to a concatenation. Deterministic and
 * dependency-free (works when the AST parser is unavailable).
 */
export function harvestJsRequestParams(code: string): JsRequestSpec[] {
  const out: JsRequestSpec[] = []
  const seen = new Set<string>()
  const pushSpec = (method: string, rawPath: string, params: JsRequestParam[]) => {
    const path = rawPath.trim()
    if (!path.startsWith('/') || path.startsWith('//') || path.length > 200 || /[\r\n\0\\]/.test(path)) return
    const cleanPath = path.split('?')[0] ?? path
    const deduped: JsRequestParam[] = []
    const keys = new Set<string>()
    for (const p of params) {
      if (!p.name || !/^[A-Za-z_][A-Za-z0-9_.[-]{0,63}$/.test(p.name)) continue
      const key = `${p.name}|${p.location}`
      if (keys.has(key)) continue
      keys.add(key)
      deduped.push(p)
    }
    // Preserve query parameters that were already present in the URL literal.
    const qIdx = path.indexOf('?')
    if (qIdx >= 0) {
      try {
        for (const name of new URL(path, 'http://guardian.invalid').searchParams.keys()) {
          if (!/^[A-Za-z_][A-Za-z0-9_.[-]{0,63}$/.test(name)) continue
          const key = `${name}|query`
          if (keys.has(key)) continue
          keys.add(key)
          deduped.push({ name, location: 'query' })
        }
      } catch { /* ignore malformed query */ }
    }
    const methodUpper = method.toUpperCase()
    const key = `${methodUpper} ${cleanPath}`
    if (seen.has(`${key}|${JSON.stringify(deduped)}`)) return
    seen.add(`${key}|${JSON.stringify(deduped)}`)
    if (out.length < 40) out.push({ method: methodUpper, path: cleanPath, params: deduped.slice(0, 20) })
  }

  /**
   * Dotted paths for keys in a JS object literal (`{ filter: { name } }` -> filter, filter.name).
   * Bounded to `maxDepth` and only used to name request parameters, never to execute code.
   */
  const objectLiteralPaths = (source: string, maxDepth = 2): string[] => {
    const out: string[] = []
    const skipValue = (i: number): number => {
      let depth = 0
      while (i < source.length) {
        const ch = source[i]
        if (ch === '"' || ch === "'" || ch === '`') {
          const q = ch
          i += 1
          while (i < source.length && source[i] !== q) i += source[i] === '\\' ? 2 : 1
        } else if (ch === '{' || ch === '[' || ch === '(') depth += 1
        else if (ch === '}' || ch === ']' || ch === ')') {
          if (depth === 0) return i
          depth -= 1
        } else if ((ch === ',' || ch === '\n') && depth === 0) return i
        i += 1
      }
      return i
    }
    const parseObject = (start: number, prefix: string, depth: number): number => {
      let i = start + 1
      while (i < source.length) {
        while (i < source.length && /[\s,]/.test(source[i])) i += 1
        if (i >= source.length || source[i] === '}') return i + 1
        const keyMatch = /^[A-Za-z_$][\w$]*/.exec(source.slice(i))
        if (!keyMatch) return skipValue(i) + 1
        const key = keyMatch[0]
        i += key.length
        while (i < source.length && /\s/.test(source[i])) i += 1
        if (source[i] !== ':') {
          // Object shorthand (`{ filter: { name } }`): the identifier itself is the value.
          if (source[i] === ',' || source[i] === '}' || i >= source.length) {
            const full = prefix ? `${prefix}.${key}` : key
            if (depth <= maxDepth) out.push(full)
            continue
          }
          return i + 1
        }
        i += 1
        while (i < source.length && /\s/.test(source[i])) i += 1
        const full = prefix ? `${prefix}.${key}` : key
        if (source[i] === '{' && depth < maxDepth) {
          i = parseObject(i, full, depth + 1)
        } else {
          if (depth <= maxDepth) out.push(full)
          i = skipValue(i) + 1
        }
      }
      return i
    }
    // The balanced-call slice includes the wrapping parentheses; start at the first object brace.
    const objStart = source.indexOf('{')
    if (objStart >= 0) parseObject(objStart, '', 0)
    return out
  }

  const scanInit = (defaultMethod: string, path: string, initText: string) => {
    const methodMatch = /\bmethod\s*:\s*['"`]([A-Za-z]+)['"`]/i.exec(initText)
    const method = (methodMatch?.[1] ?? defaultMethod).toUpperCase()
    const contentType = /content-type['"]?\s*:\s*['"]([^'"]+)['"]/i.exec(initText)?.[1]?.toLowerCase() ?? ''
    if (contentType.includes('xml') || /\bapplication\/xml\b/i.test(initText)) {
      const concatTag = /<([A-Za-z_][\w.-]{0,31})>\s*['"`]\s*\+/.exec(initText)?.[1]
      const literalTags = [...initText.matchAll(/<([A-Za-z_][\w.-]{0,31})[^>]*>/g)]
        .map(m => m[1])
        .filter(t => !/^(?:request|root|guardian|envelope|body)$/i.test(t))
      const name = concatTag ?? literalTags[literalTags.length - 1]
      pushSpec(method, path, name ? [{ name, location: 'xml' }] : [])
      return
    }
    const params: JsRequestParam[] = []
    const collect = (block: string, location: 'json' | 'form', skipInitOptions: boolean, target: JsRequestParam[] = params) => {
      for (const m of block.matchAll(/([A-Za-z_$][\w$]*)\s*:/g)) {
        const name = m[1]
        if (skipInitOptions && JS_RESERVED_BODY_KEYS.test(name)) continue
        if (!skipInitOptions && /^(?:query|variables|operationName)$/i.test(name)) continue
        target.push({ name, location })
      }
    }
    // Keys inside an explicit serialize call are body fields (a field may legitimately be named "body").
    // Nested objects become dotted paths (`filter.name`) so probes can reach the real sink.
    const dotted: string[] = []
    for (const m of initText.matchAll(/JSON\.stringify\s*\(/g)) {
      const openIdx = (m.index ?? 0) + m[0].length - 1
      const arg = sliceBalancedCall(initText, openIdx)
      dotted.push(...objectLiteralPaths(arg))
    }
    for (const name of dotted) params.push({ name, location: 'json' })
    // Other object-literal keys in the call init (direct axios data object, etc.); skip request options.
    const nestedLeaf = new Set(dotted.filter(p => p.includes('.')).map(p => p.split('.').at(-1)!))
    const flatParams: JsRequestParam[] = []
    collect(initText, 'json', true, flatParams)
    for (const p of flatParams) if (!nestedLeaf.has(p.name)) params.push(p)
    for (const m of initText.matchAll(/URLSearchParams\s*\(\s*\{([^{}]{0,500})\}/g)) collect(m[1], 'form', false)
    for (const m of initText.matchAll(/\b(new\s+FormData|FormData)\s*\(/g)) {
      const tail = initText.slice((m.index ?? 0) + m[0].length, (m.index ?? 0) + m[0].length + 400)
      for (const am of tail.matchAll(/\.append\s*\(\s*['"]([^'"]+)['"]/g)) params.push({ name: am[1], location: 'form' })
    }
    pushSpec(method, path, params)
  }

  for (const m of code.matchAll(/fetch\s*\(\s*(['"`])([^'"`]{1,200})\1\s*(?:,\s*)?/g)) {
    if (!m[2].startsWith('/')) continue
    const openIdx = (m.index ?? 0) + m[0].indexOf('(')
    scanInit('GET', m[2], sliceBalancedCall(code, openIdx))
  }
  for (const m of code.matchAll(/axios\.(?:get|post|put|patch|delete)\s*\(\s*(['"`])([^'"`]{1,200})\1\s*,?\s*/g)) {
    if (!m[2].startsWith('/')) continue
    const openIdx = (m.index ?? 0) + m[0].indexOf('(')
    const method = /axios\.([a-z]+)/i.exec(m[0])?.[1] ?? 'GET'
    scanInit(method, m[2], sliceBalancedCall(code, openIdx))
  }
  for (const m of code.matchAll(/\.open\s*\(\s*(['"`])([A-Za-z]+)\1\s*,\s*(['"`])([^'"`]{1,200})\3/g)) {
    if (!m[4].startsWith('/')) continue
    const callEnd = (m.index ?? 0) + m[0].length
    const tail = code.slice(callEnd, Math.min(code.length, callEnd + 700))
    const sendIdx = tail.search(/\.send\s*\(/)
    scanInit(m[2], m[4], sendIdx >= 0 ? sliceBalancedCall(tail, sendIdx + tail.slice(sendIdx).indexOf('(')) : '')
  }
  return out
}

/** Record every query-string parameter of a discovered URL onto its endpoint. */
// ---------------------------------------------------------------------------------------------
// v5 M2 discovery helpers: config bindings, JSON navigation, XHR shapes, JS manifests, YAML.
// ---------------------------------------------------------------------------------------------

export interface RouteMapParamBinding {
  routeKey: string
  name: string
  location: 'json' | 'form' | 'query'
}

const PARAM_NAME_RE = /^[A-Za-z_][A-Za-z0-9_.[-]{0,63}$/

/** Extract runtime parameter names that the SPA binds to a named API client call. */
export function harvestConfigParamBindings(code: string): RouteMapParamBinding[] {
  const out: RouteMapParamBinding[] = []
  const seen = new Set<string>()
  const aliasRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\(?\s*[A-Za-z_$][\w$.]*\.params\s*&&\s*[A-Za-z_$][\w$.]*\.params(?:\.([A-Za-z_$][\w$]*)|\[\s*(['"])([^'"]+)\3\s*\])/g
  for (const match of code.matchAll(aliasRe)) {
    const alias = match[1] ?? ''
    const paramName = (match[2] ?? match[4] ?? '').trim()
    if (!alias || !PARAM_NAME_RE.test(paramName)) continue
    const start = match.index ?? 0
    const declarationWindow = code.slice(start, Math.min(code.length, start + 1600))
    const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const usage = new RegExp(`\\[\\s*${escaped}\\s*\\]\\s*=`).exec(declarationWindow)
    if (!usage) continue
    const window = declarationWindow.slice(usage.index, Math.min(declarationWindow.length, usage.index + 900))
    const call = /(?:api|call|routePath|request|mutate|send)\s*\(\s*(['"])([A-Za-z0-9_.:-]{1,80})\1/.exec(window)
    if (!call) continue
    const routeKey = call[2]
    const probes = window.slice(0, 500)
    const location: RouteMapParamBinding['location'] =
      /URLSearchParams|FormData\s*\(/.test(probes) ? 'form'
        : /JSON\.stringify\s*\(/.test(probes) ? 'json'
          : 'form'
    const dedupe = `${routeKey}|${paramName}|${location}`
    if (seen.has(dedupe)) continue
    seen.add(dedupe)
    out.push({ routeKey, name: paramName, location })
    if (out.length >= 20) break
  }
  return out
}

/**
 * Same-origin ES module specifiers referenced by a bundle (static import/export-from and dynamic
 * import). SPA bootstrap bundles usually keep their API client in an imported chunk, so following
 * these is required before request-literal scanning can see config fetches.
 */
export function extractJsModuleImports(code: string): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  const push = (specifier: string | undefined) => {
    if (!specifier || out.length >= 24) return
    const clean = specifier.trim()
    if (!clean || /[\r\n\0\\]/.test(clean)) return
    if (!clean.startsWith('/') && !clean.startsWith('./') && !clean.startsWith('../')) return
    if (seen.has(clean)) return
    seen.add(clean)
    out.push(clean)
  }
  for (const match of code.matchAll(/\bimport\s+(?:[^'";]{0,200}?\s+from\s+)?(['"])([^'"]{1,200})\1/g)) push(match[2])
  for (const match of code.matchAll(/\bexport\s+[^'";]{0,200}?\s+from\s+(['"])([^'"]{1,200})\1/g)) push(match[2])
  for (const match of code.matchAll(/\bimport\s*\(\s*(['"`])([^'"`]{1,200})\1\s*\)/g)) push(match[2])
  return out
}

/**
 * Same-origin build-asset references (JS chunks, source maps, manifest JSON) found in HTML,
 * bundles or webpack chunk maps. Used to drain the JS queue breadth-first beyond entry scripts.
 */
export function extractAssetReferences(code: string, max = 32): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  const push = (raw: string) => {
    if (out.length >= max) return
    const clean = raw.trim()
    if (!clean || clean.length > 200 || /[\r\n\0\\]/.test(clean)) return
    if (!/\.(?:m?js|json)(?:$|[?#])/i.test(clean)) return
    if (!clean.startsWith('/') && !clean.startsWith('./') && !clean.startsWith('../')) return
    if (seen.has(clean)) return
    seen.add(clean)
    out.push(clean)
  }
  for (const match of code.matchAll(/["'`]((?:\/|\.{1,2}\/)[^"'`\s]{1,180}?\.(?:m?js|json))(?:\?[^"'`]*)?["'`]/g)) push(match[1])
  for (const match of code.matchAll(/\b(?:chunk|asset|file|src|url)\s*[:=]\s*["'`]([^"'`\s]{1,180})["'`]/g)) push(match[1])
  return out
}

export interface TrpcProcedure {
  router: string
  procedure: string
}

/** Bounded scan for tRPC procedure references (`trpc.<router>.<proc>.useQuery`, literal paths). */
export function harvestTrpcProcedures(code: string): TrpcProcedure[] {
  const out: TrpcProcedure[] = []
  const seen = new Set<string>()
  const push = (router: string | undefined, procedure: string | undefined) => {
    const r = (router ?? '').trim()
    const p = (procedure ?? '').trim()
    if (!r || !p || !/^[A-Za-z_$][\w$]{0,63}$/.test(r) || !/^[A-Za-z_$][\w$]{0,63}$/.test(p)) return
    const key = `${r}.${p}`
    if (seen.has(key) || out.length >= 40) return
    seen.add(key)
    out.push({ router: r, procedure: p })
  }
  for (const match of code.matchAll(/\btrpc\s*\.\s*([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\.\s*(?:useQuery|useMutation|useInfiniteQuery|query|mutation|fetch|mutate)\b/g)) {
    push(match[1], match[2])
  }
  for (const match of code.matchAll(/\btrpc\s*\[\s*['"]([\w$]+)['"]\s*\]\s*\[\s*['"]([\w$]+)['"]\s*\]/g)) push(match[1], match[2])
  for (const match of code.matchAll(/["'`]\/trpc\/([A-Za-z0-9_$]+)\.([A-Za-z0-9_$]+)/g)) push(match[1], match[2])
  return out
}

const JSON_LINK_KEYS = /^(?:href|url|uri|link|links|self|next|prev|first|last|path|endpoint|action|resource|target|location|canonical|_links|@id)$/i

/**
 * Bounded walk of an authenticated JSON document collecting same-origin navigation targets
 * (HATEOAS `_links`/`href`, `next`, API paths) without treating arbitrary response fields as routes.
 */
export function extractJsonLinkTargets(rawBody: string, origin: string): string[] {
  let doc: unknown
  try {
    doc = JSON.parse(rawBody) as unknown
  } catch {
    return []
  }
  const out = new Set<string>()
  let visited = 0
  const consider = (value: string) => {
    if (out.size >= 40 || value.length > 240) return
    if (!value.startsWith('/') && !value.startsWith(origin)) return
    const clean = sanitizePathCandidate(value, origin)
    if (!clean || clean === '/' || STATIC_ASSET_RE.test(clean)) return
    out.add(clean)
  }
  const walk = (node: unknown, key: string, depth: number): void => {
    if (visited > 700 || depth > 6 || out.size >= 40) return
    visited += 1
    if (typeof node === 'string') {
      if (JSON_LINK_KEYS.test(key) || /^\/(?:api|rest|v\d|graphql|trpc)\//i.test(node)) consider(node)
      return
    }
    if (!node || typeof node !== 'object') return
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 80)) walk(item, key, depth + 1)
      return
    }
    for (const [childKey, value] of Object.entries(node as Record<string, unknown>)) walk(value, childKey, depth + 1)
  }
  walk(doc, '', 0)
  return [...out]
}

/**
 * Field names visible in an authenticated JSON response. Used to seed request-body parameter
 * names for sibling write routes on the same resource (schema-observed, never invented).
 */
export function extractJsonFieldNames(rawBody: string, max = 24): string[] {
  let doc: unknown
  try {
    doc = JSON.parse(rawBody) as unknown
  } catch {
    return []
  }
  const names: string[] = []
  const seen = new Set<string>()
  const responseOnly = /^(?:html|output|error|errors|message|messages|ok|success|detail|error_description|authenticated)$/i
  const push = (key: string) => {
    if (names.length >= max) return
    if (!PARAM_NAME_RE.test(key) || responseOnly.test(key) || /^(?:__proto__|constructor|prototype)$/.test(key)) return
    if (seen.has(key)) return
    seen.add(key)
    names.push(key)
  }
  const isScalar = (value: unknown): boolean =>
    typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
  const collectObject = (obj: Record<string, unknown>, depth: number) => {
    for (const [key, value] of Object.entries(obj)) {
      if (isScalar(value)) push(key)
      else if (depth < 1 && value && typeof value === 'object' && !Array.isArray(value)) {
        const nested = value as Record<string, unknown>
        // A resource wrapper such as {settings:{...}} contributes its leaf fields directly.
        for (const [nestedKey, nestedValue] of Object.entries(nested)) if (isScalar(nestedValue)) push(nestedKey)
      }
    }
  }
  const collectItems = (value: unknown, depth: number) => {
    if (Array.isArray(value)) {
      for (const item of value.slice(0, 3)) {
        if (item && typeof item === 'object' && !Array.isArray(item)) collectObject(item as Record<string, unknown>, depth)
      }
      return
    }
    if (value && typeof value === 'object') collectObject(value as Record<string, unknown>, depth)
  }
  if (Array.isArray(doc)) collectItems(doc, 0)
  else if (doc && typeof doc === 'object') {
    const root = doc as Record<string, unknown>
    for (const envelope of ['items', 'data', 'results', 'rows', 'records']) {
      if (envelope in root) collectItems(root[envelope], 0)
    }
    collectObject(root, 0)
  }
  return names
}

/** Collect stable record identifiers from an API listing so sibling detail routes can be walked. */
export function extractJsonRecordIds(rawBody: string, max = 4): string[] {
  let doc: unknown
  try {
    doc = JSON.parse(rawBody) as unknown
  } catch {
    return []
  }
  const rows: Array<Record<string, unknown>> = []
  const collect = (value: unknown) => {
    if (Array.isArray(value)) {
      for (const item of value.slice(0, 3)) {
        if (item && typeof item === 'object' && !Array.isArray(item)) rows.push(item as Record<string, unknown>)
      }
    }
  }
  if (Array.isArray(doc)) collect(doc)
  else if (doc && typeof doc === 'object') {
    const root = doc as Record<string, unknown>
    for (const envelope of ['items', 'data', 'results', 'rows', 'records', 'list', 'values']) {
      if (envelope in root) collect(root[envelope])
    }
  }
  const preferred = ['ext_id', 'id', 'uuid', 'uid', 'key', 'ref', 'slug', 'name']
  const out: string[] = []
  const seen = new Set<string>()
  const pushValue = (value: unknown) => {
    if (out.length >= max) return
    if (typeof value !== 'string' && typeof value !== 'number') return
    const clean = String(value).trim()
    if (!clean || clean.length > 80 || !/^[A-Za-z0-9_.:@-]+$/.test(clean)) return
    if (seen.has(clean)) return
    seen.add(clean)
    out.push(clean)
  }
  for (const key of preferred) for (const row of rows) if (key in row) pushValue(row[key])
  for (const row of rows) {
    for (const [key, value] of Object.entries(row)) {
      if (/(?:^|_)(?:id|key|ref|slug)$/i.test(key)) pushValue(value)
    }
  }
  return out.slice(0, max)
}

/** Normalise a concrete request URL/body into endpoint + parameter shape (query/json/form/xml). */
export function inferXhrRequestShape(input: {
  url: string
  method?: string | null
  body?: string | null
  contentType?: string | null
}): JsRequestSpec | null {
  const trimmedUrl = input.url.trim()
  if (!trimmedUrl) return null
  let parsed: URL
  try {
    parsed = new URL(trimmedUrl, 'http://guardian.invalid')
  } catch {
    return null
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
  const path = parsed.pathname
  if (!path.startsWith('/') || path.length > 240) return null
  const params: JsRequestParam[] = []
  const seen = new Set<string>()
  const push = (name: string, location: JsRequestParam['location']) => {
    if (!PARAM_NAME_RE.test(name)) return
    const dedupe = `${name}|${location}`
    if (seen.has(dedupe)) return
    seen.add(dedupe)
    params.push({ name, location })
  }
  for (const name of parsed.searchParams.keys()) push(name, 'query')
  const body = typeof input.body === 'string' ? input.body.trim() : ''
  if (body) {
    const contentType = (input.contentType ?? '').toLowerCase()
    if (body.startsWith('{') || body.startsWith('[') || contentType.includes('json')) {
      try {
        const parsedBody = JSON.parse(body) as unknown
        if (parsedBody && typeof parsedBody === 'object' && !Array.isArray(parsedBody)) {
          for (const [key, value] of Object.entries(parsedBody as Record<string, unknown>)) {
            if (value && typeof value === 'object' && !Array.isArray(value)) {
              for (const [nestedKey, nestedValue] of Object.entries(value as Record<string, unknown>)) {
                if (nestedValue === null || typeof nestedValue !== 'object') push(`${key}.${nestedKey}`, 'json')
              }
            } else {
              push(key, 'json')
            }
          }
        }
      } catch { /* not JSON */ }
    } else if (body.startsWith('<')) {
      const tags = [...body.matchAll(/<([A-Za-z_][\w.:-]{0,63})[^>]*>/g)]
        .map(match => match[1])
        .filter(tag => !/^(?:\?xml|request|root|envelope|body|guardian)$/i.test(tag))
      const last = tags[tags.length - 1]
      if (last) push(last, 'xml')
    } else if (/^[\w.-]+=[\s\S]*$/.test(body)) {
      try {
        for (const name of new URLSearchParams(body).keys()) push(name, 'form')
      } catch { /* ignore */ }
    }
    if (contentType.includes('multipart/form-data')) {
      for (const match of body.matchAll(/name="([^"]{1,64})"/g)) push(match[1], 'form')
    }
  }
  const method = HTTP_METHOD_SET.has((input.method ?? '').toUpperCase()) ? (input.method ?? 'GET').toUpperCase() : 'GET'
  return { method, path, params: params.slice(0, 24) }
}

const HTTP_METHOD_SET = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])

// ---------------------------------------------------------------------------------------------
// YAML subset parser (OpenAPI/route-map documents; JSON remains the fast path)
// ---------------------------------------------------------------------------------------------

function stripYamlComment(line: string): string {
  let quote: string | null = null
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]
    if (quote) {
      if (ch === quote && line[i - 1] !== '\\') quote = null
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; continue }
    if (ch === '#' && (i === 0 || /\s/.test(line[i - 1] ?? ''))) return line.slice(0, i)
  }
  return line
}

function splitYamlKeyValue(text: string): { key: string; rest: string } | null {
  let quote: string | null = null
  let depth = 0
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (quote) {
      if (ch === quote && text[i - 1] !== '\\') quote = null
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; continue }
    if (ch === '{' || ch === '[') depth += 1
    else if (ch === '}' || ch === ']') depth -= 1
    else if (ch === ':' && depth === 0 && (i + 1 >= text.length || /\s/.test(text[i + 1] ?? ''))) {
      const rawKey = text.slice(0, i).trim()
      const key = rawKey.replace(/^['"]|['"]$/g, '')
      if (!key) return null
      return { key, rest: text.slice(i + 1).trim() }
    }
  }
  return null
}

function parseYamlScalar(raw: string): unknown {
  const text = raw.trim()
  if (!text) return null
  if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) {
    return text.slice(1, -1)
  }
  if (/^(?:true|false)$/i.test(text)) return text.toLowerCase() === 'true'
  if (/^(?:null|~)$/i.test(text)) return null
  if (/^-?\d+(?:\.\d+)?$/.test(text)) return Number(text)
  if ((text.startsWith('{') && text.endsWith('}')) || (text.startsWith('[') && text.endsWith(']'))) {
    try { return JSON.parse(text) } catch { return text }
  }
  return text
}

/** Bounded YAML parser for mapping/sequence documents (OpenAPI, route maps). Not a full YAML engine. */
export function parseYamlLikeDocument(text: string): unknown {
  interface Line { indent: number; text: string; raw: string }
  const lines: Line[] = []
  for (const rawLine of text.replace(/\r\n?/g, '\n').split('\n')) {
    if (lines.length > 6000) break
    const stripped = stripYamlComment(rawLine)
    const body = stripped.trimEnd()
    const trimmed = body.trim()
    if (!trimmed || trimmed === '---' || trimmed === '...') continue
    const indent = body.length - body.trimStart().length
    lines.push({ indent, text: trimmed, raw: body })
  }
  if (lines.length === 0) return null
  let index = 0
  const blockScalar = (indent: number): string => {
    const parts: string[] = []
    while (index < lines.length && lines[index]!.indent > indent) {
      parts.push(lines[index]!.text)
      index += 1
    }
    return parts.join('\n')
  }
  const parseNode = (indent: number): unknown => {
    const first = lines[index]
    if (!first) return null
    return first.text === '-' || first.text.startsWith('- ') ? parseSequence(indent) : parseMapping(indent)
  }
  const parseSequence = (indent: number): unknown[] => {
    const out: unknown[] = []
    while (index < lines.length) {
      const line = lines[index]!
      if (line.indent < indent) break
      if (line.indent > indent) { index += 1; continue }
      if (!(line.text === '-' || line.text.startsWith('- '))) break
      const afterDash = line.text.slice(1)
      if (!afterDash.trim()) {
        index += 1
        const next = lines[index]
        out.push(next && next.indent > indent ? parseNode(next.indent) : null)
        continue
      }
      if (splitYamlKeyValue(afterDash.trim())) {
        // `- key: value` starts a mapping item; re-align the remainder and parse it as a map.
        const dashes = /^(\s*)-(\s*)/.exec(line.raw)
        const childIndent = (dashes?.[1]?.length ?? indent) + 1 + (dashes?.[2]?.length ?? 1)
        lines[index] = { indent: childIndent, text: afterDash.trim(), raw: ' '.repeat(childIndent) + afterDash.trim() }
        out.push(parseMapping(childIndent))
        continue
      }
      out.push(parseYamlScalar(afterDash))
      index += 1
    }
    return out
  }
  const parseMapping = (indent: number): Record<string, unknown> => {
    const out: Record<string, unknown> = {}
    while (index < lines.length) {
      const line = lines[index]!
      if (line.indent < indent) break
      if (line.indent > indent) { index += 1; continue }
      if (line.text === '-' || line.text.startsWith('- ')) break
      const kv = splitYamlKeyValue(line.text)
      if (!kv) { index += 1; continue }
      index += 1
      if (kv.rest) {
        if (/^[|>][+-]?$/.test(kv.rest)) { out[kv.key] = blockScalar(indent); continue }
        out[kv.key] = parseYamlScalar(kv.rest)
        continue
      }
      const next = lines[index]
      out[kv.key] = next && next.indent > indent ? parseNode(next.indent) : null
    }
    return out
  }
  return parseNode(lines[0]!.indent)
}

/** Parse a JSON or YAML document body into an object (null when neither parses). */
export function parseJsonOrYaml(rawBody: string): unknown {
  const text = rawBody.replace(/^\uFEFF/, '').trim()
  if (!text) return null
  if (text.startsWith('{') || text.startsWith('[')) {
    try { return JSON.parse(text) as unknown } catch { /* fall through to YAML */ }
  }
  const parsed = parseYamlLikeDocument(text)
  if (parsed !== null && typeof parsed === 'object') return parsed
  try { return JSON.parse(text) as unknown } catch { return null }
}

// ---------------------------------------------------------------------------------------------
// Soft-404 / SPA catch-all calibration
// ---------------------------------------------------------------------------------------------

export interface SoftNotFoundCalibration {
  statuses: number[]
  mediaTypes: string[]
  lengths: number[]
  signatures: string[]
}

/** Structural hash of a response body: strips volatile ids/digits and collapses whitespace. */
export function bodyStructuralSignature(body: string): string {
  const normalized = body
    .slice(0, 64 * 1024)
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '<uuid>')
    .replace(/\b[0-9a-f]{16,}\b/gi, '<hex>')
    .replace(/\d+/g, '<n>')
    .replace(/\s+/g, ' ')
    .trim()
  return createHash('sha256').update(normalized).digest('hex').slice(0, 16)
}

/**
 * Allowed methods advertised by an OPTIONS response or a 405 rejection (`Allow: GET, POST`).
 * Passive: the header is read from a response recon already received.
 */
export function harvestAllowMethods(respHeaders: Record<string, string> | undefined | null): string[] {
  if (!respHeaders) return []
  const raw = respHeaders.allow ?? respHeaders.Allow ?? ''
  if (!raw) return []
  return [...new Set(raw.split(',').map(part => part.trim().toUpperCase())
    .filter(method => HTTP_METHOD_SET.has(method) && method !== 'OPTIONS' && method !== 'HEAD'))].slice(0, 6)
}

/**
 * Field names named by a JSON RFC7807 / express-validator / class-validator style 400/422 body.
 * Used to learn a declared write/query schema from a validation error instead of guessing nouns.
 */
export function harvestValidationFieldHints(body: string): string[] {
  const out = new Set<string>()
  const push = (raw: unknown) => {
    if (typeof raw !== 'string') return
    const name = raw.split('.').pop()?.trim() ?? ''
    if (/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(name)) out.add(name)
  }
  let parsed: unknown
  try { parsed = JSON.parse(body) } catch { parsed = undefined }
  if (parsed && typeof parsed === 'object') {
    const walk = (node: unknown, depth: number): void => {
      if (depth > 3 || !node || typeof node !== 'object') return
      if (Array.isArray(node)) { for (const item of node.slice(0, 12)) walk(item, depth + 1); return }
      const record = node as Record<string, unknown>
      for (const key of ['field', 'property', 'param', 'name', 'path']) {
        if (typeof record[key] === 'string') push(record[key])
      }
      for (const key of ['errors', 'issues', 'details', 'violations', 'required', 'missing']) {
        if (Array.isArray(record[key])) walk(record[key], depth + 1)
      }
    }
    walk(parsed, 0)
  }
  for (const match of body.matchAll(/([A-Za-z_][A-Za-z0-9_-]{0,63})\s+(?:is required|required|must be provided|is missing|missing)/gi)) {
    push(match[1])
  }
  return [...out].slice(0, 8)
}

/** True when a response structurally matches a calibrated soft-404 / SPA catch-all probe. */
export function isSoftNotFound(calibration: SoftNotFoundCalibration, ex: Pick<BrokerExchangeResult, 'status' | 'mediaType' | 'body'>): boolean {
  if (calibration.statuses.length === 0) return false
  const ranked = calibration.statuses
    .map((status, i) => ({ status, media: calibration.mediaTypes[i] ?? '', len: calibration.lengths[i] ?? 0, sig: calibration.signatures[i] ?? '' }))
    .filter(entry => entry.status === ex.status && entry.media === ex.mediaType)
  if (ranked.length === 0) return false
  const signature = bodyStructuralSignature(ex.body)
  for (const entry of ranked) {
    if (entry.sig && entry.sig === signature) return true
    const tolerance = Math.max(32, Math.round(entry.len * 0.02))
    if (Math.abs(entry.len - ex.body.length) <= tolerance) return true
  }
  return false
}

/** Record every query-string parameter of a discovered URL onto its endpoint. */
function recordQueryParamsForEndpoint(input: {
  rawPathAndQuery: string
  origin: string
  endpointId: string
  source: string
  storage: Store
  runId: string
  dynamicParams: Set<string>
}): number {
  const { rawPathAndQuery, endpointId, source, storage, runId, dynamicParams } = input
  const qIdx = rawPathAndQuery.indexOf('?')
  if (qIdx < 0) return 0
  let names: string[] = []
  try {
    names = [...new URL(rawPathAndQuery, input.origin).searchParams.keys()]
  } catch {
    return 0
  }
  let count = 0
  const observedSource = source.startsWith('observed') ? source : 'observed:url_query'
  // Sort keys so identical crawl input produces an identical insertion (and read) order.
  for (const name of [...new Set(names)].sort().slice(0, 12)) {
    if (!name || !isUsefulParamForLocation(name, 'query')) continue
    storage.upsertEndpointParam({
      runId,
      endpointId,
      name,
      location: 'query',
      isCsrf: CSRF_PARAM_RE.test(name),
      isObjectId: OBJECT_ID_PARAM_RE.test(name),
      source: observedSource,
    })
    dynamicParams.add(name)
    count += 1
  }
  return count
}

// ---------------------------------------------------------------------------------------------
// Parameter discovery: provenance, confidence and generic candidate derivation
// ---------------------------------------------------------------------------------------------
//
// Layer-2 surfaces are randomized: a held-out app may rename a search/filter parameter that the
// crawler never sees verbatim. Recon therefore records *where a name came from* and how much the
// evidence supports it. Only an `observed` name (seen on the wire, declared by the target, or
// verified by a response differential) is treated as surface truth. An `inferred` name exists to
// let the deterministic floor form a hypothesis; the floor still has to prove the differential, so
// a wrong inferred name ends as `inconclusive`/`hypothesis_miss`, never as a finding.

export type ParamProvenance = 'observed' | 'inferred_bundle' | 'inferred_html' | 'inferred_ast'

export interface DiscoveredParamCandidate {
  name: string
  location: ParamLocation
  /**
   * Explicit, preserved provenance tag:
   *  - `observed[:detail]` — seen on the wire or declared by the target (link query key, form
   *    field, redirect query key, OpenAPI/route-map declaration, validation body hint);
   *  - `inferred_bundle[:sensitive]` — visible in shipped client JS;
   *  - `inferred_html[:sensitive]` — inferred from an HTML/JSON document field or route semantics;
   *  - `inferred_ast[:sensitive]` — harvested from a parsed request/AST shape.
   * The optional `:sensitive` suffix means a bounded control-vs-probe differential showed the
   * target reads the name. It is still not a confirmation: `verifyReceipt`/oracle invariants must
   * prove the value crossed a security boundary.
   */
  source: string
}

/** Provenance rank for deterministic ordering (observed first, then inferred families). */
const PROVENANCE_RANK: Record<ParamProvenance, number> = {
  observed: 0,
  inferred_bundle: 1,
  inferred_html: 2,
  inferred_ast: 3,
}

function legacyInferredProvenance(raw: string): ParamProvenance {
  if (raw.includes('bundle') || raw.includes('xhr') || raw.includes('graphql')) return 'inferred_bundle'
  if (raw.includes('response_field') || raw.includes('route_vocabulary') || raw.includes('html')) return 'inferred_html'
  return 'inferred_ast'
}

/** True when a bounded sensitivity differential showed the target reads this name. */
export function paramSourceSensitivityPassed(source: string): boolean {
  return /:sensitive\b/i.test(source)
}

/**
 * Confidence in a discovered parameter name (0-100), derived deterministically from its source.
 * A sensitivity-checked inference is strong evidence for hypothesis priority but is *not* an
 * observation and can never, on its own, produce a finding.
 */
export function paramDiscoveryConfidence(source: string): number {
  const raw = source.toLowerCase()
  if (raw.startsWith('observed:')) {
    if (raw.includes('url_query') || raw.includes('form_field')) return 95
    if (raw.includes('redirect_query')) return 90
    if (raw.includes('openapi') || raw.includes('route_map')) return 85
    return 85
  }
  if (raw.startsWith('inferred_')) {
    const sensitive = paramSourceSensitivityPassed(raw)
    if (raw.startsWith('inferred_bundle')) return sensitive ? 88 : 65
    if (raw.startsWith('inferred_html')) return sensitive ? 85 : 55
    if (raw.startsWith('inferred_ast')) return sensitive ? 85 : 65
    return sensitive ? 80 : 50
  }
  // Legacy source strings predate explicit provenance prefixes.
  if (raw === 'js_ast') return 65
  if (raw === 'openapi' || raw === 'route_map' || raw === 'graphql' || raw === 'phase0_xml' || raw === 'phase0_validation') return 85
  if (raw === 'surface_probe' || raw === 'spa_crawl' || raw === 'phase0_html' || raw === 'phase0_sibling') return 90
  return 70
}

/**
 * Observed vs inferred. Wire/declaration evidence is `observed`. Anything that only exists in
 * shipped client code, a document field, or a parsed shape is one of the explicit inferred tags,
 * even after it passes a sensitivity check.
 */
export function paramProvenanceOfSource(source: string): ParamProvenance {
  const raw = source.toLowerCase()
  if (raw.startsWith('observed:') || raw === 'observed') return 'observed'
  if (raw.startsWith('js_ast') || raw.startsWith('inferred_ast')) return 'inferred_ast'
  if (raw.startsWith('inferred_bundle')) return 'inferred_bundle'
  if (raw.startsWith('inferred_html')) return 'inferred_html'
  if (raw.startsWith('inferred:')) return legacyInferredProvenance(raw)
  // Legacy declaration/wire sources.
  return 'observed'
}

/** JS/UI noise literals that look like names but can never be request parameters. */
const PARAM_NOISE_RE = /^(?:undefined|null|true|false|nan|this|self|window|document|console|function|return|then|catch|finally|length|prototype|constructor|tostring|valueof|hasownproperty|appendchild|addeventlistener|preventdefault|stoppropagation|innerhtml|textcontent|classname|queryselector|queryselectorall|getelementbyid|setattribute|getattribute|removeattribute|classlist|dataset|style|children|props|component|render|mount|unmount|jsx|css)$/i

/** Whether a harvested literal is plausibly a request parameter (drops obvious JS/UI noise). */
export function isUsefulParamName(name: string): boolean {
  if (!PARAM_NAME_RE.test(name)) return false
  if (PARAM_NOISE_RE.test(name)) return false
  if (/^\d+$/.test(name)) return false
  if (/^(?:on[a-z]|aria-|data-)/i.test(name) && name.length > 2) return false
  // Dotted AST paths are legitimate JSON body fields (`filter.name`); callers reject them for
  // query locations, where a dot is never a wire key.
  return true
}

/** Location-aware usefulness: dotted names are body fields, not query keys. */
export function isUsefulParamForLocation(name: string, location: ParamLocation): boolean {
  if (!isUsefulParamName(name)) return false
  return !(location === 'query' && name.includes('.'))
}

/** Total order for discovered parameters: provenance rank, then name/location/source. */
export function compareDiscoveredParams(a: DiscoveredParamCandidate, b: DiscoveredParamCandidate): number {
  const rankA = PROVENANCE_RANK[paramProvenanceOfSource(a.source)]
  const rankB = PROVENANCE_RANK[paramProvenanceOfSource(b.source)]
  if (rankA !== rankB) return rankA - rankB
  return a.name.localeCompare(b.name) ||
    a.location.localeCompare(b.location) ||
    a.source.localeCompare(b.source)
}

export function orderDiscoveredParams<T extends DiscoveredParamCandidate>(candidates: readonly T[]): T[] {
  const seen = new Set<string>()
  const out: T[] = []
  for (const candidate of [...candidates].sort(compareDiscoveredParams)) {
    const key = `${candidate.name}|${candidate.location}`
    if (!candidate.name || seen.has(key) || !isUsefulParamForLocation(candidate.name, candidate.location)) continue
    seen.add(key)
    out.push(candidate)
  }
  return out
}

const SEARCH_ROUTE_HINT = /(?:^|[/_.-])(?:search|searches|lookup|find|filter|query|queries|browse|catalog)(?:$|[/_.-])/i
const FILE_ROUTE_HINT = /(?:^|[/_.-])(?:download|downloads|file|files|asset|assets|view|serve|log|logs|journal|journals|billing[-_]?docs?|document|documents|attachment|attachments|backup|backups|archive|archives)(?:$|[/_.-])/i
const URL_ROUTE_HINT = /(?:^|[/_.-])(?:avatar|avatars|image|images|photo|photos|logo|logos|media|thumbnail|webhook|webhooks|hook|hooks|callback|callbacks|integration|integrations|connector|connectors|proxy|proxies|fetch|remote|link|links|manifest|manifests)(?:$|[/_.-])/i
const REDIRECT_ROUTE_HINT = /(?:^|[/_.-])(?:redirect|return|callback|continue|resume|sso|oauth|authorize|checkout|download|export|next)(?:$|[/_.-])/i

/**
 * Candidate free-text parameter names implied by a route's semantics. These are *inferred* and are
 * only attached when independent evidence (a response field, a bundle literal, a form/link) already
 * points at the route; the name itself is never treated as observed.
 */
export function routeParamVocabulary(pathTemplate: string, method = 'GET'): DiscoveredParamCandidate[] {
  if (method.toUpperCase() !== 'GET') return []
  const bare = pathTemplate.split('?')[0] || '/'
  const names: string[] = []
  if (/(?:^|[/_.-])(?:logs?|journals?|audit)(?:$|[/_.-])/i.test(bare)) names.push('filter', 'q', 'query')
  else if (SEARCH_ROUTE_HINT.test(bare)) names.push('q', 'query', 'term', 'keyword')
  if (FILE_ROUTE_HINT.test(bare)) names.push('file', 'path', 'name')
  if (URL_ROUTE_HINT.test(bare)) names.push('url', 'src', 'target')
  if (REDIRECT_ROUTE_HINT.test(bare)) names.push('next', 'returnUrl', 'redirect')
  return [...new Set(names)].map(name => ({ name, location: 'query' as ParamLocation, source: 'inferred_html' }))
}

/**
 * Response field names that match the route's inferred vocabulary. A search route that publishes
 * `{"query": ...}` names its own reading parameter; the name is still only an inference until a
 * response differential verifies it.
 */
export function deriveResponseFieldParams(
  pathTemplate: string,
  responseFields: Iterable<string>,
  method = 'GET',
): DiscoveredParamCandidate[] {
  const fields = new Set<string>()
  for (const field of responseFields) fields.add(field.toLowerCase())
  return routeParamVocabulary(pathTemplate, method)
    .filter(candidate => fields.has(candidate.name.toLowerCase()))
    .map(candidate => ({ ...candidate, source: 'inferred_html' }))
}

/** Query keys carried by a same-origin redirect Location are wire-observed for the target route. */
export function paramCandidatesFromRedirect(searchParams: Iterable<string>): DiscoveredParamCandidate[] {
  const out: DiscoveredParamCandidate[] = []
  for (const name of searchParams) {
    if (!PARAM_NAME_RE.test(name)) continue
    out.push({ name, location: 'query', source: 'observed:redirect_query' })
  }
  return orderDiscoveredParams(out)
}

export interface ParamDiscoveryEndpointMetric {
  endpoint: string
  observed: number
  inferred: number
  sensitivityPassed: number
  byProvenance: Record<ParamProvenance, number>
  bySource: Record<string, number>
}

export interface ParamDiscoverySummary {
  endpoints: ParamDiscoveryEndpointMetric[]
  totals: {
    observed: number
    inferred: number
    sensitivityPassed: number
    byProvenance: Record<ParamProvenance, number>
    bySource: Record<string, number>
  }
}

const emptyProvenanceCounts = (): Record<ParamProvenance, number> => ({
  observed: 0, inferred_bundle: 0, inferred_html: 0, inferred_ast: 0,
})

/** Deterministic per-endpoint parameter-discovery metrics for persisted `endpoint_params`. */
export function summarizeParamDiscovery(storage: Store, runId: string, maxEndpoints = 200): ParamDiscoverySummary {
  const endpoints = storage.listEndpoints(runId, { limit: 20_000 })
  const byId = new Map(endpoints.map(endpoint => [endpoint.id, endpoint]))
  const metricsById = new Map<string, ParamDiscoveryEndpointMetric>()
  const totals: ParamDiscoverySummary['totals'] = {
    observed: 0, inferred: 0, sensitivityPassed: 0, byProvenance: emptyProvenanceCounts(), bySource: {},
  }
  for (const param of storage.listEndpointParams(runId)) {
    const endpoint = byId.get(param.endpointId)
    const key = endpoint ? `${endpoint.method.toUpperCase()} ${endpoint.pathTemplate}` : param.endpointId
    const provenance = paramProvenanceOfSource(param.source)
    const sensitive = paramSourceSensitivityPassed(param.source)
    const metric = metricsById.get(key) ?? {
      endpoint: key, observed: 0, inferred: 0, sensitivityPassed: 0,
      byProvenance: emptyProvenanceCounts(), bySource: {},
    }
    if (provenance === 'observed') metric.observed += 1
    else metric.inferred += 1
    if (sensitive) metric.sensitivityPassed += 1
    metric.byProvenance[provenance] += 1
    metric.bySource[param.source] = (metric.bySource[param.source] ?? 0) + 1
    metricsById.set(key, metric)
    if (provenance === 'observed') totals.observed += 1
    else totals.inferred += 1
    if (sensitive) totals.sensitivityPassed += 1
    totals.byProvenance[provenance] += 1
    totals.bySource[param.source] = (totals.bySource[param.source] ?? 0) + 1
  }
  const sortRecord = (record: Record<string, number>): Record<string, number> =>
    Object.fromEntries(Object.entries(record).sort(([a], [b]) => a.localeCompare(b)))
  const endpointsOut = [...metricsById.values()]
    .sort((a, b) => a.endpoint.localeCompare(b.endpoint))
    .slice(0, maxEndpoints)
  totals.bySource = sortRecord(totals.bySource)
  for (const metric of endpointsOut) metric.bySource = sortRecord(metric.bySource)
  return { endpoints: endpointsOut, totals }
}

const HTTP_VERBS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options'])
const ROUTE_COLLECTION_KEYS = /^(?:routes?|paths?|endpoints?|apis?|operations?|handlers?|resources?|navigation|nav|menu|screens?)$/i

export interface RouteMapEntry {
  method: string
  path: string
  params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' }>
  /** Logical route key from `{key: {method, path}}` map shapes (used for param bindings). */
  key?: string
}

/**
 * Expand configuration/route-map documents served by a single-page app into endpoint candidates.
 * Recognizes path-keyed method tables (`{"/api/x": {"get": {...}}}`), operation arrays
 * (`[{path, method, params}]`) and plain path arrays under route-ish keys. Bounded and shape-driven;
 * no application-specific literals.
 */
export function harvestRouteMapDocument(raw: unknown, maxEntries = 200): RouteMapEntry[] {
  const out: RouteMapEntry[] = []
  const seen = new Set<string>()
  const push = (method: string, rawPath: string, params: RouteMapEntry['params'] = [], routeKey?: string): void => {
    const path = rawPath.trim()
    if (!path.startsWith('/') || path.startsWith('//') || path.length > 200 || /[\r\n\0\\]/.test(path)) return
    const m = method.toUpperCase()
    if (!HTTP_VERBS.has(method.toLowerCase())) return
    const clean = path.split('?')[0] || '/'
    const key = `${m} ${clean}`
    if (seen.has(key) || out.length >= maxEntries) return
    seen.add(key)
    const entry: RouteMapEntry = { method: m, path: clean, params: params.slice(0, 20) }
    if (routeKey && !ROUTE_COLLECTION_KEYS.test(routeKey)) entry.key = routeKey
    out.push(entry)
  }
  const paramList = (node: unknown): RouteMapEntry['params'] => {
    const params: RouteMapEntry['params'] = []
    if (Array.isArray(node)) {
      for (const p of node) {
        if (typeof p === 'string' && /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(p)) params.push({ name: p, location: 'query' })
        else if (p && typeof p === 'object') {
          const rec = p as Record<string, unknown>
          const name = typeof rec.name === 'string' ? rec.name : typeof rec.key === 'string' ? rec.key : null
          if (!name || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(name)) continue
          const loc = String(rec.in ?? rec.location ?? rec.where ?? '').toLowerCase()
          params.push({ name, location: loc === 'path' ? 'path' : loc === 'body' ? 'json' : 'query' })
        }
      }
    } else if (node && typeof node === 'object') {
      for (const [name, value] of Object.entries(node as Record<string, unknown>)) {
        if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(name)) continue
        const type = String((value && typeof value === 'object' ? (value as Record<string, unknown>).type : value) ?? '').toLowerCase()
        params.push({ name, location: type === 'path' ? 'path' : 'json' })
      }
    }
    return params
  }
  const operationParams = (node: unknown): RouteMapEntry['params'] => {
    if (!node || typeof node !== 'object') return []
    const rec = node as Record<string, unknown>
    return [
      ...paramList(rec.parameters ?? rec.params ?? rec.query ?? rec.args ?? rec.fields),
      ...paramList(rec.body ?? rec.requestBody ?? rec.data ?? rec.payload),
    ]
  }
  const methodFrom = (value: unknown, fallbackKey?: string): string | null => {
    if (typeof value === 'string' && HTTP_VERBS.has(value.toLowerCase())) return value
    if (fallbackKey && HTTP_VERBS.has(fallbackKey.toLowerCase())) return fallbackKey
    return null
  }
  const walk = (node: unknown, depth: number, contextKey?: string): void => {
    if (depth > 6 || out.length >= maxEntries || !node) return
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 100)) {
        if (typeof item === 'string' && contextKey && ROUTE_COLLECTION_KEYS.test(contextKey) && item.startsWith('/')) {
          push('GET', item)
          continue
        }
        if (!item || typeof item !== 'object') continue
        const rec = item as Record<string, unknown>
        const rawPath = typeof rec.path === 'string' ? rec.path
          : typeof rec.route === 'string' ? rec.route
            : typeof rec.url === 'string' ? rec.url
              : typeof rec.endpoint === 'string' ? rec.endpoint : null
        if (rawPath) {
          const method = methodFrom(rec.method ?? rec.verb ?? rec.type) ?? 'GET'
          push(method, rawPath, operationParams(rec), contextKey)
          continue
        }
        walk(item, depth + 1, contextKey)
      }
      return
    }
    if (typeof node !== 'object') return
    const rec = node as Record<string, unknown>
    // Path-keyed method table.
    for (const [key, value] of Object.entries(rec)) {
      if (!key.startsWith('/') || key.startsWith('//')) continue
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        const methods = Object.entries(value as Record<string, unknown>).filter(([k]) => HTTP_VERBS.has(k.toLowerCase()))
        if (methods.length > 0) {
          for (const [verb, op] of methods) push(verb, key, operationParams(op))
          continue
        }
      }
      push('GET', key)
    }
    for (const [key, value] of Object.entries(rec)) {
      if (key.startsWith('/')) continue
      // A single operation object: { path|route, method, params }.
      if ((key === 'path' || key === 'route' || key === 'url' || key === 'endpoint') && typeof value === 'string' && value.startsWith('/')) {
        const method = methodFrom(rec.method ?? rec.verb ?? rec.type) ?? 'GET'
        push(method, value, operationParams(rec), contextKey)
        continue
      }
      walk(value, depth + 1, key)
    }
  }
  walk(raw, 0)
  return out
}

export interface RouteMapParamHints {
  paramHints: string[]
  /** logical parameter key -> concrete runtime field name */
  paramMap: Record<string, string>
}

/** Collect logical->actual parameter dictionaries from a route-map/config document. */
export function harvestRouteMapParamHints(raw: unknown): RouteMapParamHints {
  const paramHints: string[] = []
  const paramMap: Record<string, string> = {}
  let visited = 0
  const walk = (node: unknown, depth: number): void => {
    if (!node || typeof node !== 'object' || depth > 6 || visited > 600) return
    visited += 1
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 80)) walk(item, depth + 1)
      return
    }
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (/^(?:params|paramNames|paramMap|parameterNames)$/i.test(key)) {
        if (Array.isArray(value)) {
          for (const item of value.slice(0, 40)) {
            if (typeof item === 'string' && PARAM_NAME_RE.test(item)) paramHints.push(item)
          }
        } else if (value && typeof value === 'object') {
          for (const [logical, actual] of Object.entries(value as Record<string, unknown>)) {
            if (typeof actual !== 'string' || !PARAM_NAME_RE.test(actual.trim())) continue
            paramHints.push(actual.trim())
            if (PARAM_NAME_RE.test(logical.trim())) paramMap[logical.trim()] = actual.trim()
          }
        }
        continue
      }
      walk(value, depth + 1)
    }
  }
  walk(raw, 0)
  return { paramHints: [...new Set(paramHints)].slice(0, 60), paramMap }
}

function routeKeyTokens(raw: string): string[] {
  return raw
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .map(token => (token.length > 3 && token.endsWith('s') ? token.slice(0, -1) : token))
    .filter(token => token.length > 2 && !GENERIC_ROUTE_TOKENS.has(token))
}

const GENERIC_ROUTE_TOKENS = new Set([
  'api', 'get', 'list', 'view', 'create', 'update', 'delete', 'remove', 'patch', 'put', 'post', 'run',
  'new', 'all', 'set', 'the', 'and', 'for', 'with', 'by', 'to', 'from', 'item', 'data', 'field', 'body',
  'name', 'query', 'value', 'id', 'uuid', 'key', 'ref', 'src', 'page', 'type', 'current', 'accept',
])

export interface RouteMapParseOptions {
  bindings?: ReadonlyMap<string, readonly RouteMapParamBinding[]>
  /** Override the discovery template normalizer (defaults to normalizeDiscoveryTemplate). */
  normalizeTemplate?: (path: string) => string
}

/** Persist endpoints/params harvested from a served route-map/config document. */
export function parseRouteMapDoc(
  rawBody: string,
  origin: string,
  storage: Store,
  runId: string,
  scopeRevision: number,
  dynamicPaths: Set<string>,
  dynamicParams: Set<string>,
  options?: RouteMapParseOptions,
): { endpoints: number; params: number } {
  const doc = parseJsonOrYaml(rawBody)
  if (doc === null || typeof doc !== 'object') return { endpoints: 0, params: 0 }
  const root = doc as Record<string, unknown>
  if (typeof root.openapi === 'string' || typeof root.swagger === 'string') return { endpoints: 0, params: 0 }
  const entries = harvestRouteMapDocument(doc)
  const normalize = options?.normalizeTemplate ?? normalizeDiscoveryTemplate
  const hints = harvestRouteMapParamHints(doc)
  let endpoints = 0
  let params = 0
  const created: Array<{ id: string; key?: string; method: string; path: string }> = []
  const paramKeys = new Set<string>()
  const addParam = (endpointId: string, name: string, location: RouteMapEntry['params'][number]['location']) => {
    if (!PARAM_NAME_RE.test(name)) return
    const dedupe = `${endpointId}|${name}|${location}`
    if (paramKeys.has(dedupe)) return
    paramKeys.add(dedupe)
    storage.upsertEndpointParam({
      runId, endpointId, name, location,
      isCsrf: CSRF_PARAM_RE.test(name),
      isObjectId: location === 'path' || OBJECT_ID_PARAM_RE.test(name),
      source: 'route_map',
    })
    dynamicParams.add(name)
    params += 1
  }
  for (const entry of entries.slice(0, 120)) {
    const clean = sanitizePathCandidate(entry.path, origin)
    if (!clean || STATIC_ASSET_RE.test(clean)) continue
    const tmpl = normalize(clean)
    const ep = storage.upsertEndpoint({
      runId, scopeRevision, origin, method: entry.method, pathTemplate: tmpl,
      source: 'route_map', riskScore: scoreEndpointRisk(entry.method, tmpl),
    } as unknown as Parameters<Store['upsertEndpoint']>[0])
    endpoints += 1
    dynamicPaths.add(tmpl)
    created.push({ id: ep.id, ...(entry.key ? { key: entry.key } : {}), method: entry.method, path: tmpl })
    for (const pathParam of extractDynamicPathParams(entry.path)) addParam(ep.id, pathParam.name, 'path')
    for (const p of entry.params) addParam(ep.id, p.name, p.location)
    if (entry.key && options?.bindings) {
      for (const binding of options.bindings.get(entry.key) ?? []) {
        const actual = hints.paramMap[binding.name] ?? binding.name
        addParam(ep.id, actual, binding.location)
      }
    }
  }
  // Attach logical->actual parameter hints to same-resource write/read routes by shared name tokens.
  const attachedHints = new Set<string>()
  const attachHint = (matchKey: string, actualName: string) => {
    if (attachedHints.has(actualName) || !PARAM_NAME_RE.test(actualName)) return
    dynamicParams.add(actualName)
    const hintTokens = new Set(routeKeyTokens(matchKey))
    if (hintTokens.size === 0) return
    attachedHints.add(actualName)
    const ranked = created
      .filter(ep => ep.key)
      .map(ep => ({ ep, overlap: routeKeyTokens(ep.key ?? '').filter(token => hintTokens.has(token)).length }))
      .filter(candidate => candidate.overlap > 0)
      .sort((a, b) =>
        b.overlap - a.overlap
        || (a.ep.method === 'GET' ? 1 : 0) - (b.ep.method === 'GET' ? 1 : 0)
        || a.ep.path.length - b.ep.path.length)
      .slice(0, 4)
    for (const { ep } of ranked) addParam(ep.id, actualName, ep.method === 'GET' || ep.method === 'HEAD' ? 'query' : 'json')
  }
  const paramMapValues = new Set(Object.values(hints.paramMap))
  for (const [logical, actual] of Object.entries(hints.paramMap)) attachHint(logical, actual)
  for (const hint of hints.paramHints) if (!paramMapValues.has(hint)) attachHint(hint, hint)
  return { endpoints, params }
}

/** Bounded scan for client router tables / navigation literals in JS bundles. */
export function harvestJsRouteTable(code: string): string[] {
  const out = new Set<string>()
  const push = (p: string): void => {
    if (p.startsWith('/') && !p.startsWith('//') && p.length <= 160 && !/[\r\n\0\\]/.test(p) && out.size < 80) out.add(p.split('?')[0] || '/')
  }
  for (const m of code.matchAll(/["'`](\/[A-Za-z0-9_\-./:{}[\]]{1,140})["'`]\s*:\s*\{/g)) push(m[1])
  for (const m of code.matchAll(/\b(?:path|route|to|href)\s*:\s*["'`](\/[A-Za-z0-9_\-./:{}[\]]{1,140})["'`]/g)) push(m[1])
  for (const m of code.matchAll(/\b(?:navigate|router\.(?:push|replace)|redirect)\s*\(\s*["'`](\/[A-Za-z0-9_\-./:{}[\]]{1,140})["'`]/g)) push(m[1])
  // Express/Fastify/Koa-style router tables: `router.get('/api/x', handler)`.
  for (const m of code.matchAll(/\.(?:get|post|put|patch|delete|all|use)\s*\(\s*["'`](\/[A-Za-z0-9_\-./:{}[\]]{1,140})["'`]/g)) push(m[1])
  return [...out]
}

export function parseOpenApiDoc(
  rawBody: string,
  origin: string,
  storage: Store,
  runId: string,
  scopeRevision: number,
  dynamicPaths: Set<string>,
  dynamicParams: Set<string>,
): { endpoints: number; params: number; operations: Array<{ method: string; pathTemplate: string }> } {
  const parsed = parseJsonOrYaml(rawBody)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { endpoints: 0, params: 0, operations: [] }
  const doc = parsed as Record<string, unknown>
  const pathsObj = doc.paths
  if (!pathsObj || typeof pathsObj !== 'object' || Array.isArray(pathsObj)) return { endpoints: 0, params: 0, operations: [] }
  let endpoints = 0
  let params = 0
  const operations: Array<{ method: string; pathTemplate: string }> = []
  const validMethods = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options'])

  // OpenAPI `servers[].url` / Swagger 2 `basePath` may carry a deployment prefix.
  let basePrefix = ''
  if (Array.isArray(doc.servers) && doc.servers.length > 0) {
    const first = doc.servers[0]
    if (first && typeof first === 'object') {
      const rawUrl = (first as Record<string, unknown>).url
      if (typeof rawUrl === 'string' && !rawUrl.includes('{')) {
        try {
          const pathname = rawUrl.startsWith('/') ? rawUrl : new URL(rawUrl, origin).pathname
          basePrefix = pathname === '/' ? '' : pathname.replace(/\/+$/, '')
        } catch { /* ignore malformed server url */ }
      }
    }
  } else if (typeof doc.basePath === 'string' && doc.basePath.startsWith('/') && doc.basePath !== '/') {
    basePrefix = doc.basePath.replace(/\/+$/, '')
  }

  const isRecord = (value: unknown): value is Record<string, unknown> =>
    Boolean(value) && typeof value === 'object' && !Array.isArray(value)

  const resolvePointer = (ref: string): unknown => {
    if (!ref.startsWith('#/')) return undefined
    let cursor: unknown = doc
    for (const rawToken of ref.slice(2).split('/')) {
      const token = rawToken.replace(/~1/g, '/').replace(/~0/g, '~')
      if (!isRecord(cursor)) return undefined
      cursor = cursor[token]
    }
    return cursor
  }

  /** Dereference local `$ref` chains; sibling keys of a `$ref` override the target. */
  const resolveNode = (node: unknown, depth = 0): Record<string, unknown> | null => {
    if (depth > 8 || !isRecord(node)) return null
    const ref = typeof node.$ref === 'string' ? node.$ref : null
    if (!ref) return node
    const target = resolvePointer(ref)
    const resolved = resolveNode(target, depth + 1)
    const merged: Record<string, unknown> = { ...node }
    delete merged.$ref
    return resolved ? { ...resolved, ...merged } : (Object.keys(merged).length > 0 ? merged : null)
  }

  const addParam = (endpointId: string, name: string, location: ParamLocation, inferredType?: string | null) => {
    const clean = name.trim()
    if (!clean || !PARAM_NAME_RE.test(clean)) return
    storage.upsertEndpointParam({
      runId,
      endpointId,
      name: clean,
      location,
      inferredType: inferredType ?? null,
      isCsrf: CSRF_PARAM_RE.test(clean),
      isObjectId: location === 'path' || OBJECT_ID_PARAM_RE.test(clean),
      source: 'openapi',
    })
    dynamicParams.add(clean)
    params += 1
  }

  /** Flatten a schema (through $ref/allOf/oneOf/anyOf/items) into param names, bounded by depth. */
  const addSchemaParams = (
    schemaNode: unknown,
    location: ParamLocation,
    endpointId: string,
    prefix = '',
    level = 0,
    refStack: readonly string[] = [],
  ): void => {
    if (level > 2) return
    const ref = isRecord(schemaNode) && typeof schemaNode.$ref === 'string' ? schemaNode.$ref : null
    if (ref) {
      if (refStack.includes(ref)) return
      refStack = [...refStack, ref]
    }
    const schema = resolveNode(schemaNode)
    if (!schema) return
    const props: Record<string, unknown> = {}
    const collectProps = (node: Record<string, unknown>, depth: number) => {
      if (depth > 3) return
      if (isRecord(node.properties)) Object.assign(props, node.properties)
      for (const composite of ['allOf']) {
        const list = node[composite]
        if (Array.isArray(list)) {
          for (const branch of list) {
            const resolved = resolveNode(branch)
            if (resolved) collectProps(resolved, depth + 1)
          }
        }
      }
      for (const composite of ['oneOf', 'anyOf']) {
        const list = node[composite]
        if (Array.isArray(list) && list.length > 0) {
          const resolved = resolveNode(list[0])
          if (resolved) collectProps(resolved, depth + 1)
        }
      }
      const typeName = typeof node.type === 'string' ? node.type.toLowerCase() : ''
      if (typeName === 'array') {
        const items = resolveNode(node.items)
        if (items) collectProps(items, depth + 1)
      }
    }
    collectProps(schema, 0)

    for (const [propName, propNode] of Object.entries(props)) {
      if (!propName || params >= 800) continue
      const propSchema = resolveNode(propNode) ?? {}
      const inferredType = typeof propSchema.type === 'string' ? propSchema.type : null
      const xmlName = location === 'xml' && isRecord(propSchema.xml) && typeof propSchema.xml.name === 'string'
        ? String(propSchema.xml.name).trim()
        : ''
      const name = location === 'xml' ? (xmlName || propName) : `${prefix}${propName}`
      addParam(endpointId, name, location, inferredType)
      if (location === 'xml') continue
      const typeName = typeof propSchema.type === 'string' ? propSchema.type.toLowerCase() : ''
      if (typeName === 'array') {
        const items = resolveNode(propSchema.items)
        if (items && isRecord(items.properties)) {
          addSchemaParams(items, location, endpointId, `${prefix}${propName}.0.`, level + 1, refStack)
        }
        continue
      }
      if (isRecord(propSchema.properties)) {
        addSchemaParams(propSchema, location, endpointId, `${prefix}${propName}.`, level + 1, refStack)
      }
    }
  }

  const addParameterRecord = (rawParam: unknown, endpointId: string): string | null => {
    const rec = resolveNode(rawParam)
    if (!rec) return null
    const name = typeof rec.name === 'string' ? rec.name.trim() : ''
    const inRaw = typeof rec.in === 'string' ? rec.in.toLowerCase() : ''
    if (inRaw === 'body' || inRaw === 'formdata') {
      const location: ParamLocation = inRaw === 'body' ? 'json' : 'form'
      addSchemaParams(rec.schema ?? rec, location, endpointId)
      if (!rec.schema && name) addParam(endpointId, name, location, typeof rec.type === 'string' ? rec.type : null)
      return name || null
    }
    if (!name) return null
    const location: ParamLocation =
      inRaw === 'path' ? 'path'
        : inRaw === 'header' ? 'header'
          : inRaw === 'cookie' ? 'cookie'
            : inRaw === 'query' ? 'query'
              : 'query'
    const schemaObj = resolveNode(rec.schema) ?? {}
    addParam(endpointId, name, location, typeof schemaObj.type === 'string' ? schemaObj.type : null)
    return name
  }

  for (const [rawPath, rawPathItem] of Object.entries(pathsObj as Record<string, unknown>)) {
    const pathItem = resolveNode(rawPathItem)
    if (!pathItem) continue
    let leading = rawPath.startsWith('/') ? rawPath : `/${rawPath}`
    if (basePrefix && leading !== basePrefix && !leading.startsWith(`${basePrefix}/`)) {
      leading = `${basePrefix}${leading}`
    }
    // Preserve OpenAPI {param} placeholders while still collapsing raw literal IDs if any appear
    const pathTemplate = leading.includes('{')
      ? leading.split('?')[0].replace(/\/{2,}/g, '/')
      : normalizeDiscoveryTemplate(leading)
    dynamicPaths.add(pathTemplate)
    const pathLevelParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : []
    for (const [mKey, opVal] of Object.entries(pathItem)) {
      if (!validMethods.has(mKey.toLowerCase())) continue
      const method = mKey.toUpperCase()
      const ep = storage.upsertEndpoint({
        runId,
        scopeRevision,
        origin,
        method,
        pathTemplate,
        source: 'openapi',
        riskScore: scoreEndpointRisk(method, pathTemplate),
      })
      endpoints += 1
      operations.push({ method, pathTemplate })
      const op = resolveNode(opVal) ?? {}
      const opParams = [...pathLevelParams, ...(Array.isArray(op.parameters) ? op.parameters : [])]
      const declared = new Set<string>()
      for (const rawParam of opParams) {
        const name = addParameterRecord(rawParam, ep.id)
        if (name) declared.add(name)
      }
      // OpenAPI 3 requestBody (JSON/XML/form/multipart), resolving local $refs.
      const reqBody = resolveNode(op.requestBody)
      const content = isRecord(reqBody?.content) ? reqBody.content as Record<string, unknown> : {}
      for (const [mediaType, mediaNode] of Object.entries(content)) {
        const lower = mediaType.toLowerCase()
        const location: ParamLocation | null =
          lower.includes('json') ? 'json'
            : lower.includes('xml') ? 'xml'
              : lower.includes('x-www-form-urlencoded') || lower.includes('multipart/form-data') ? 'form'
                : null
        if (!location) continue
        const media = resolveNode(mediaNode)
        if (!media) continue
        addSchemaParams(media.schema, location, ep.id)
      }
      // OpenAPI path template placeholders that were not declared as parameters.
      for (const match of rawPath.matchAll(/\{([A-Za-z_][A-Za-z0-9_-]{0,63})\}/g)) {
        const name = match[1]
        if (!name || declared.has(name)) continue
        declared.add(name)
        addParam(ep.id, name, 'path')
      }
    }
  }
  return { endpoints, params, operations }
}

/**
 * Tolerant OpenAPI operation extraction for stored references whose text is truncated or carries a
 * redaction placeholder (JSON.parse then fails). Reads path keys, methods, declared parameters and
 * colon/brace path placeholders textually; no network and no semantics beyond the document itself.
 */
export interface TolerantOpenApiOperation {
  method: string
  pathTemplate: string
  params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' }>
}

/** Cap for malformed/truncated references only; the lossless JSON/YAML path stays uncapped. */
export const DEFAULT_TOLERANT_OP_CAP = 300

/**
 * Extract every operation a malformed/truncated reference textually exposes, without the ingestion
 * cap. A generous hard ceiling bounds pathological input; callers decide the real bound.
 */
function harvestTolerantOperationsUncapped(content: string, hardCeiling = 100_000): TolerantOpenApiOperation[] {
  const pathKeyRe = /"(\/[A-Za-z0-9_\-{}\/.:$\[\]]{0,300})"\s*:\s*\{/g
  const matches = [...content.matchAll(pathKeyRe)]
  if (matches.length === 0) return []
  const out: TolerantOpenApiOperation[] = []
  for (let idx = 0; idx < matches.length && out.length < hardCeiling; idx += 1) {
    const match = matches[idx]!
    const rawPath = match[1]!
    if (!rawPath.startsWith('/') || rawPath.length > 300) continue
    const start = (match.index ?? 0) + match[0].length
    const end = idx + 1 < matches.length ? (matches[idx + 1]!.index ?? content.length) : content.length
    const block = content.slice(start, Math.min(end, start + 20_000))
    const methods = [...new Set([...block.matchAll(/"(get|post|put|patch|delete|head|options)"\s*:\s*\{/g)].map(m => m[1]!.toUpperCase()))]
    if (methods.length === 0) continue
    const pathTemplate = normalizeDiscoveryTemplate(rawPath)
    const params: TolerantOpenApiOperation['params'] = []
    const pushParam = (name: string, location: TolerantOpenApiOperation['params'][number]['location']) => {
      if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(name)) return
      if (params.some(p => p.name === name)) return
      params.push({ name, location })
    }
    for (const rawParam of block.matchAll(/"name"\s*:\s*"([A-Za-z0-9_.\-\[\]]{1,64})"[\s\S]{0,240}?"in"\s*:\s*"(query|path|header|formData|form|body|cookie)"/g)) {
      const location = rawParam[2] === 'formData' || rawParam[2] === 'form' ? 'form'
        : rawParam[2] === 'body' ? 'json'
          : rawParam[2] === 'header' ? 'header'
            : rawParam[2] === 'path' ? 'path' : 'query'
      pushParam(rawParam[1]!, location)
    }
    for (const placeholder of rawPath.matchAll(/[/{:]([A-Za-z_][A-Za-z0-9_]{0,63})(?:[}/]|$)/g)) {
      if (rawPath.includes(`:${placeholder[1]}`) || rawPath.includes(`{${placeholder[1]}}`)) {
        pushParam(placeholder[1]!, 'path')
      }
    }
    for (const method of methods) out.push({ method, pathTemplate, params })
  }
  return out
}

/**
 * Bounded tolerant harvest for malformed references. The cap exists so a redacted/truncated blob
 * cannot balloon ingestion; when it binds the caller logs it and treats the result as incomplete.
 */
export function harvestTolerantOpenApiOperations(
  content: string,
  maxOps = DEFAULT_TOLERANT_OP_CAP,
): TolerantOpenApiOperation[] {
  const ops = harvestTolerantOperationsUncapped(content)
  const cap = Number.isFinite(maxOps) ? Math.max(0, Math.round(maxOps)) : ops.length
  return ops.slice(0, cap)
}

/** Declared operation count a malformed reference exposes, uncapped, so callers can detect cap binding. */
export function countTolerantOpenApiOperations(content: string): number {
  return harvestTolerantOperationsUncapped(content).length
}

/**
 * Page size for lossless full-store reads. `listEndpoints` falls back to 500 rows, which silently
 * truncates ingestion and probe-selection views on large surfaces; 1,000 keeps pages cheap.
 */
export const ENDPOINT_PAGE_SIZE = 1000

export type EndpointListFilter = NonNullable<Parameters<Store['listEndpoints']>[1]>

/**
 * One discovery phase's paged endpoint read. `considered` counts every stored row the phase saw,
 * `used` counts the rows that became planning input for that phase, and `truncated` is always false:
 * the read pages until a short page proves completeness, so no phase can be silently capped at the
 * store's default 500-row page.
 */
export type PagedReadMetric = {
  phase: string
  origin: string
  considered: number
  used: number
  truncated: boolean
  reads: number
  pages: number
}

/**
 * Read every endpoint matching `filter` through the store's stable (risk, coverage, id) ordering.
 * Pages until a short page proves the read is complete, so no fixed page cap can truncate a caller.
 */
export function listEndpointsPaged(
  storage: Pick<Store, 'listEndpoints'>,
  runId: string,
  filter?: EndpointListFilter,
  pageSize: number = ENDPOINT_PAGE_SIZE,
): EndpointRow[] {
  const limit = Math.max(1, Math.round(pageSize))
  const start = Math.max(0, Math.round(filter?.offset ?? 0))
  const out: EndpointRow[] = []
  for (let offset = start; ; offset += limit) {
    const rows = storage.listEndpoints(runId, { ...filter, limit, offset })
    out.push(...rows)
    if (rows.length < limit) break
  }
  return out
}

/**
 * Declared-surface ingestion metrics. `seen` counts distinct declared operations enumerated from
 * the references; `matched` counts those present in the store after ingestion. They must agree for
 * the lossless path — a gap means the ingestion view or the store dropped rows.
 */
export type DeclaredSurfaceSummary = {
  specs: number
  endpoints: number
  params: number
  methods: Record<string, number>
  declaredOpsSeen: number
  declaredOpsMatched: number
  /** Malformed references whose tolerant scan was truncated by the safety cap. */
  declaredTolerantCapped: number
}

/**
 * Offline ingestion of the grey-box API reference (OpenAPI/Swagger) that the harness imported for
 * this project. Every declared operation is kept with its declared method — including DELETE,
 * PATCH and body-only POST routes — without requiring an id segment or a known body field.
 * Deduped by (origin, METHOD, pathTemplate). No network request is made here.
 */
export function ingestDeclaredApiSurface(input: {
  storage: Store
  runId: string
  scopeRevision: number
  origin: string
  dynamicPaths?: Set<string>
  dynamicParams?: Set<string>
}): DeclaredSurfaceSummary {
  const result: DeclaredSurfaceSummary = {
    specs: 0, endpoints: 0, params: 0, methods: {},
    declaredOpsSeen: 0, declaredOpsMatched: 0, declaredTolerantCapped: 0,
  }
  const { storage, runId, scopeRevision, origin } = input
  let specs: Array<{ kind: string; content: string }> = []
  try {
    const run = storage.run(runId)
    const wanted = (() => { try { return new URL(origin).origin } catch { return origin } })()
    // A project reference can describe several origins (SPA shell, API, IdP, CDN). Parse only the
    // documents declared for this origin; otherwise every origin would claim every route.
    specs = storage.listProjectSpecsFull(run.projectId).filter(spec => {
      if (!spec.origin) return true
      try { return new URL(spec.origin).origin === wanted } catch { return false }
    })
  } catch {
    return result
  }
  // Full paged view: the dedupe baseline must include every stored row, not just the first page.
  const known = new Set<string>()
  try {
    for (const endpoint of listEndpointsPaged(storage, runId, { origin })) {
      known.add(`${origin}|${endpoint.method.toUpperCase()}|${endpoint.pathTemplate}`)
    }
  } catch { /* empty run: no known endpoints */ }
  const dynamicPaths = input.dynamicPaths ?? new Set<string>()
  const dynamicParams = input.dynamicParams ?? new Set<string>()
  const seen = new Set<string>()
  const noteDeclared = (method: string, pathTemplate: string) => {
    const normalized = method.trim().toUpperCase()
    const key = `${origin}|${normalized}|${pathTemplate}`
    seen.add(key)
    if (known.has(key)) return
    known.add(key)
    result.endpoints += 1
    result.methods[normalized] = (result.methods[normalized] ?? 0) + 1
  }

  for (const [specIndex, spec] of specs.slice(0, 6).entries()) {
    const head = spec.content.slice(0, 400)
    const looksOpenApi = /openapi|swagger/i.test(spec.kind)
      || /"(?:openapi|swagger)"\s*:/.test(head)
      || /^\s*openapi\s*:/m.test(head)
    if (!looksOpenApi) continue
    result.specs += 1
    const parsed = parseOpenApiDoc(spec.content, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams)
    result.params += parsed.params
    if (parsed.endpoints > 0) {
      // Lossless path: no operation cap. Enumerate exactly what the parser persisted.
      for (const op of parsed.operations) noteDeclared(op.method, op.pathTemplate)
      continue
    }
    // Stored references can be truncated or carry a redaction placeholder, so JSON/YAML parsing
    // fails. Fall back to the tolerant textual scan used by the route-derivation port; it keeps
    // every declared operation with its declared method, bounded by a safety cap that is logged.
    const tolerantOps = harvestTolerantOpenApiOperations(spec.content)
    const declaredTolerantOps = countTolerantOpenApiOperations(spec.content)
    if (declaredTolerantOps > tolerantOps.length) {
      result.declaredTolerantCapped += 1
      try {
        storage.event(
          runId,
          'phase0.declared_surface_capped',
          `Tolerant API-reference scan truncated at ${tolerantOps.length} of ${declaredTolerantOps} declared operation(s) (malformed/redacted reference).`,
          { specIndex, cap: tolerantOps.length, declaredTolerantOps, origin },
        )
      } catch { /* metrics only */ }
    }
    for (const op of tolerantOps) {
      const ep = storage.upsertEndpoint({
        runId,
        scopeRevision,
        origin,
        method: op.method,
        pathTemplate: op.pathTemplate,
        source: 'openapi',
        riskScore: scoreEndpointRisk(op.method, op.pathTemplate),
      })
      dynamicPaths.add(op.pathTemplate)
      for (const p of op.params) {
        storage.upsertEndpointParam({
          runId,
          endpointId: ep.id,
          name: p.name,
          location: p.location,
          isCsrf: CSRF_PARAM_RE.test(p.name),
          isObjectId: p.location === 'path' || OBJECT_ID_PARAM_RE.test(p.name),
          source: 'openapi',
        })
        dynamicParams.add(p.name)
        result.params += 1
      }
      noteDeclared(op.method, op.pathTemplate)
    }
  }

  // Integrity read: `seen` must be fully visible through the same paged ingestion view.
  // `endpoints` above stays incremental (idempotent re-ingestion reports 0), while these two
  // metrics describe the declared surface itself.
  result.declaredOpsSeen = seen.size
  if (seen.size > 0) {
    try {
      const persisted = new Set(listEndpointsPaged(storage, runId, { origin }).map(endpoint =>
        `${origin}|${endpoint.method.toUpperCase()}|${endpoint.pathTemplate}`))
      let matched = 0
      for (const key of seen) if (persisted.has(key)) matched += 1
      result.declaredOpsMatched = matched
    } catch { /* metrics only */ }
  }
  return result
}

/**
 * Zero-LLM Phase-0 deterministic surface mapper (SPEC-v4 §4.3A).
 * Strictly enforces per-origin request budget `min(floor(15% * budgetRequests), 250)`,
 * skips live HTTP at Tier 0, runs 11-framework static route extraction, harvests JS/OpenAPI/GraphQL,
 * synthesizes deduplicated dynamic wordlists, and populates SQLite `endpoints` + `endpoint_params`.
 */
export async function runPhase0Recon(params: Phase0ReconParams): Promise<Phase0ReconResult> {
  const { storage, runId, scopeRevision, tier, broker, grant, signal } = params
  const runBudget = (() => {
    if (typeof params.budgetRequests === 'number' && Number.isFinite(params.budgetRequests) && params.budgetRequests > 0) {
      return params.budgetRequests
    }
    try {
      const r = storage.run(runId)
      return r.budgetRequests > 0 ? r.budgetRequests : 1000
    } catch {
      return 1000
    }
  })()
  const perOriginCap = Math.max(1, Math.min(Math.floor(runBudget * 0.15), 250))
  // Navigation gets a small overflow lane, but only when the cap is large enough that 16 extra
  // requests cannot violate a deliberately tight budget.
  const navOverflow = perOriginCap >= 40 ? 16 : 0

  let requestsUsed = 0
  let endpointsDiscovered = 0
  let paramsDiscovered = 0
  let stoppedReason: string | null = null
  let routeMapEndpoints = 0
  let jsRouterRoutes = 0
  let navigationRequests = 0
  let navigationEndpoints = 0
  let authRequests = 0
  let soft404Rejected = 0
  // Sensitivity-check accounting for inferred parameters (checked / passed / dropped as dead).
  const paramSensitivity = { checked: 0, passed: 0, dropped: 0 }
  const visibleToPersonasUnion = new Map<string, Set<string>>()
  const privilegedSurface: Array<{ method: string; pathTemplate: string; personas: string[]; reason: string }> = []
  const frameworksDetected = new Set<string>()
  const techFingerprint = new Set<string>()
  const dynamicPaths = new Set<string>()
  const dynamicParams = new Set<string>()
  // Per-phase paged-read metrics for the discovery planning reads (nav, GraphQL, sibling derivation).
  const readPagedMetrics: PagedReadMetric[] = []

  const normalizedOrigins: string[] = []
  for (const raw of params.origins) {
    try {
      const o = new URL(raw).origin
      if (!normalizedOrigins.includes(o)) normalizedOrigins.push(o)
    } catch { /* skip malformed */ }
  }

  // Repo dependency manifests contribute tech tags even when live responses are uninformative
  // (or when Tier 0 sends no requests at all).
  for (const tag of mergeTechTags(techTagsFromManifests(readRepoManifests(params.reposDir ?? '')))) {
    techFingerprint.add(tag)
  }

  // 1. White-box static route extraction (runs at ALL tiers including Tier 0).
  //    AST Program Graph is authoritative when a mounted/synced repo is present: it resolves full
  //    mount prefixes, exact methods, input schemas and middleware/guard chains. Regex extraction
  //    stays as an explicitly-marked fallback for constructs the structural scanner cannot attribute.
  let repoStaticExtraction: RepoStaticExtractionSummary | undefined
  let codeToRuntimeHypotheses: CodeSliceHypothesis[] | undefined
  let codeSlices = emptyCodeSliceSummary(params.maxCodeSlices)
  let probePlan: Phase0ReconResult['probePlan']
  if (params.reposDir && normalizedOrigins.length > 0) {
    const primaryOrigin = normalizedOrigins[0]!
    const regexExtracted = extractStaticFrameworkRoutes(params.reposDir)
    let graphExtraction: RepoProgramGraphExtraction | null = null
    try {
      graphExtraction = extractRepoProgramGraph({ reposDir: params.reposDir, origins: normalizedOrigins })
    } catch {
      graphExtraction = null
    }
    const merged = mergeStaticRouteExtractions({
      astRoutes: graphExtraction?.routes ?? [],
      regexRoutes: regexExtracted.routes,
      defaultOrigin: primaryOrigin,
    })
    for (const fw of graphExtraction?.frameworks ?? []) frameworksDetected.add(fw)
    for (const fw of regexExtracted.frameworks) frameworksDetected.add(fw)
    for (const route of merged.routes) {
      const origin = route.origin ?? primaryOrigin
      const ep = storage.upsertEndpoint({
        runId,
        scopeRevision,
        origin,
        method: route.method,
        pathTemplate: route.pathTemplate,
        source: 'repo_ast',
        framework: route.framework,
        authRequirement: route.authRequirement,
        ownershipGuard: route.ownershipGuard,
        sinkKinds: route.sinkKinds,
        riskScore: route.riskScore,
        codeLocation: route.codeLocation,
      })
      endpointsDiscovered += 1
      dynamicPaths.add(route.pathTemplate)
      for (const p of route.params) {
        storage.upsertEndpointParam({
          runId,
          endpointId: ep.id,
          name: p.name,
          location: p.location,
          isCsrf: CSRF_PARAM_RE.test(p.name),
          isObjectId: p.isObjectId,
          source: 'repo_ast',
        })
        dynamicParams.add(p.name)
        paramsDiscovered += 1
      }
    }
    repoStaticExtraction = {
      astRoutes: graphExtraction?.routes.length ?? 0,
      regexFallbackRoutes: regexExtracted.routes.length,
      mergedRoutes: merged.routes.length,
      duplicateRoutes: merged.duplicates,
      frameworks: [...new Set([...(graphExtraction?.frameworks ?? []), ...regexExtracted.frameworks])],
      originMappings: graphExtraction?.originMappings ?? [],
      routeOrigins: graphExtraction?.routeOrigins ?? {},
      warnings: graphExtraction?.warnings ?? [],
    }
    if (graphExtraction) {
      // Lossless store, ranked probe: every AST route is persisted above; this plan only
      // prioritizes and clusters the probing/consumption order for downstream consumers.
      const plan = rankAndClusterAstRoutes({
        routes: graphExtraction.routes,
        hypotheses: graphExtraction.hypotheses,
      })
      // White-box slices ride on the hypothesis payload (bounded `codeSlice` field) so the brief
      // builder can hand exact file:line evidence to a specialist without re-reading the graph.
      // Tier-A (hypothesis-linked) routes are sliced first, then Tier-B, then the long tail.
      const attached = attachCodeSlicesToPhase0Hypotheses({
        graph: graphExtraction.graph,
        hypotheses: graphExtraction.hypotheses,
        priorityRouteIds: new Set(plan.priority.map(route => route.routeId).filter((id): id is string => Boolean(id))),
        priorityRouteKeys: new Set(plan.priority.map(route => routeKey(route))),
        schemaTypedRouteIds: new Set(plan.schemaTyped.map(route => route.routeId).filter((id): id is string => Boolean(id))),
        schemaTypedRouteKeys: new Set(plan.schemaTyped.map(route => routeKey(route))),
        ...(params.maxCodeSlices !== undefined ? { maxSlices: params.maxCodeSlices } : {}),
      })
      codeToRuntimeHypotheses = attached.hypotheses
      codeSlices = attached.summary
      probePlan = {
        totalRoutes: plan.totalRoutes,
        priority: plan.priority.length,
        schemaTyped: plan.schemaTyped.length,
        longTail: plan.longTail.length,
        clusters: plan.clusters.length,
        representatives: plan.representatives.length,
        probeSubset: plan.probeSubset.length,
        sample: plan.probeSubset.map(route => `${route.method.toUpperCase()} ${route.pathTemplate}`).slice(0, 40),
      }
      storage.event(runId, 'phase0.probe_plan', 'Ranked AST probe plan (lossless store, clustered sampling).', probePlan)
      // Middleware-aware authz hints: guard chains tag visibility without touching probe eligibility.
      for (const route of graphExtraction.routes) {
        const key = `${route.method.toUpperCase()} ${route.pathTemplate}`
        const label = route.authClass === 'admin' ? 'role:admin'
          : route.authClass === 'tenant' ? 'role:tenant'
          : route.authClass === 'auth' ? 'role:authenticated'
          : 'anonymous'
        const set = visibleToPersonasUnion.get(key) ?? new Set<string>()
        set.add(label)
        visibleToPersonasUnion.set(key, set)
        if (route.authClass === 'admin') {
          const entryKey = `${route.method.toUpperCase()} ${route.pathTemplate}`
          if (!privilegedSurface.some(entry => `${entry.method} ${entry.pathTemplate}` === entryKey)) {
            privilegedSurface.push({
              method: route.method.toUpperCase(),
              pathTemplate: route.pathTemplate,
              personas: [label],
              reason: 'code_admin_guard',
            })
          }
        }
      }
      for (const hypothesis of graphExtraction.hypotheses) {
        const method = hypothesis.method?.toUpperCase()
        if (!method || !hypothesis.path) continue
        const reason = hypothesis.kind === 'admin_route_missing_admin_guard' ? 'code_admin_route_unguarded'
          : hypothesis.kind === 'tenant_param_without_scope' ? 'code_tenant_unscoped'
          : undefined
        if (!reason) continue
        if (privilegedSurface.some(entry => `${entry.method} ${entry.pathTemplate}` === `${method} ${hypothesis.path}`)) continue
        privilegedSurface.push({ method, pathTemplate: hypothesis.path, personas: [], reason })
      }
      storage.event(runId, 'phase0.program_graph', 'Program Graph route extraction (AST primary, regex fallback).', {
        astRoutes: repoStaticExtraction.astRoutes,
        regexFallbackRoutes: repoStaticExtraction.regexFallbackRoutes,
        mergedRoutes: repoStaticExtraction.mergedRoutes,
        duplicateRoutes: repoStaticExtraction.duplicateRoutes,
        hypotheses: codeToRuntimeHypotheses.length,
        origins: repoStaticExtraction.originMappings,
        warnings: repoStaticExtraction.warnings.slice(0, 8),
      })
    }
  }

  // 1a. White-box dataflow slices (metrics for every tier). `codeSlice: 'unavailable'` records
  // that no graph/source existed; nothing is fabricated in that case.
  storage.event(
    runId,
    'phase0.code_slices',
    codeSlices.attached > 0
      ? `Attached ${codeSlices.attached} code dataflow slice(s) (${codeSlices.routes} route(s), avg ${codeSlices.avgBytes} B).`
      : 'No code dataflow slices available (no mounted graph/source); hypotheses stay slice-free.',
    {
      code_slices_attached: codeSlices.attached,
      code_slices_unavailable: codeSlices.unavailable,
      code_slices_capped: codeSlices.capped,
      code_slices_routes: codeSlices.routes,
      avg_slice_bytes: codeSlices.avgBytes,
      guard_diffs: codeSlices.guardDiffs,
      max_slices: codeSlices.maxSlices,
      codeSlice: codeSlices.codeSlice,
    },
  )

  // 1b. Lossless ingestion of the grey-box API reference. Offline: every declared operation is
  // recorded with its declared method (DELETE/PATCH/body-only POST included), so a variant that
  // renames resources still gets the full declared surface without any noun wordlist.
  let declaredSurface: Phase0ReconResult['declaredSurface']
  if (normalizedOrigins.length > 0) {
    // The project reference may describe several origins (SPA shell, API, IdP). Ingesting only
    // the primary origin silently dropped every declared operation of the others, so the engine
    // never saw body-only API routes or the IdP token/JWKS endpoints.
    const total: DeclaredSurfaceSummary = {
      specs: 0, endpoints: 0, params: 0, methods: {}, declaredOpsSeen: 0, declaredOpsMatched: 0, declaredTolerantCapped: 0,
    }
    // Declared references may cover origins the run never scopes as targets (external IdP, CDN).
    // Ingest them so the surface is complete, while the live crawl below stays target-only.
    const declaredOrigins = new Set(normalizedOrigins)
    try {
      for (const spec of storage.listProjectSpecsFull(storage.run(runId).projectId)) {
        if (!spec.origin) continue
        try { declaredOrigins.add(new URL(spec.origin).origin) } catch { /* malformed spec origin */ }
      }
    } catch { /* no project specs */ }
    for (const origin of declaredOrigins) {
      const part = ingestDeclaredApiSurface({ storage, runId, scopeRevision, origin, dynamicPaths, dynamicParams })
      total.specs += part.specs
      total.endpoints += part.endpoints
      total.params += part.params
      total.declaredOpsSeen += part.declaredOpsSeen
      total.declaredOpsMatched += part.declaredOpsMatched
      total.declaredTolerantCapped += part.declaredTolerantCapped
      for (const [method, count] of Object.entries(part.methods)) total.methods[method] = (total.methods[method] ?? 0) + count
    }
    declaredSurface = total
    endpointsDiscovered += total.endpoints
    paramsDiscovered += total.params
    if (total.declaredOpsSeen > 0) {
      storage.event(
        runId,
        'phase0.declared_surface',
        `Ingested ${total.endpoints} new declared operation(s); ${total.declaredOpsMatched}/${total.declaredOpsSeen} declared operation(s) are visible in the store.`,
        total,
      )
    }
  }
  let siblingEndpoints = 0
  let methodHints = 0
  // Sibling derivation and its OPTIONS probes are opt-in and stay a blind-target fallback: when
  // the mounted AST or the declared API reference already describes the surface, speculative
  // collection->item derivation is disabled (the declared truth is strictly better evidence).
  const siblingDerivationRequested = /^(?:1|true|on|yes)$/i.test((process.env.GUARDIAN_RECON_SIBLINGS ?? '').trim())
  const declaredOrAstSurfacePresent = (repoStaticExtraction?.mergedRoutes ?? 0) > 0 || (declaredSurface?.declaredOpsMatched ?? 0) > 0
  const siblingDerivationEnabled = siblingDerivationRequested && !declaredOrAstSurfacePresent
  const siblingDerivationSuppressed = siblingDerivationRequested && declaredOrAstSurfacePresent ? 'declared_surface' as const : undefined
  if (siblingDerivationSuppressed) {
    storage.event(runId, 'phase0.siblings_suppressed',
      'Speculative sibling derivation disabled: AST/declared surface is available for this origin.',
      { astRoutes: repoStaticExtraction?.mergedRoutes ?? 0, declared: declaredSurface?.declaredOpsMatched ?? declaredSurface?.endpoints ?? 0 })
  }

  // Tier 0: zero live HTTP requests
  if (tier === 0) {
    storage.event(runId, 'phase0.discovery', 'Phase-0 discovery counts (static only).', {
      requestsUsed: 0,
      perOriginCap,
      endpointsDiscovered,
      paramsDiscovered,
    })
    storage.updateRunPhase0Completed(runId, Date.now())
    const staticVisibility: Record<string, string[]> = {}
    for (const [key, set] of visibleToPersonasUnion) staticVisibility[key] = [...set].sort()
    return {
      requestsUsed: 0,
      perOriginCap,
      endpointsDiscovered,
      paramsDiscovered,
      frameworksDetected: [...frameworksDetected],
      techFingerprint: [...techFingerprint],
      dynamicWordlist: {
        paths: [...dynamicPaths].slice(0, 120),
        params: [...dynamicParams].slice(0, 80),
      },
      stoppedReason: null,
      routeMapEndpoints,
      jsRouterRoutes,
      navigationRequests,
      navigationEndpoints,
      authRequests,
      soft404Rejected,
      ...(declaredSurface ? { declaredSurface } : {}),
      ...(repoStaticExtraction ? { repoStaticExtraction } : {}),
      ...(codeToRuntimeHypotheses && codeToRuntimeHypotheses.length ? { codeToRuntimeHypotheses } : {}),
      codeSlices,
      ...(probePlan ? { probePlan } : {}),
      ...(siblingDerivationSuppressed ? { siblingDerivationSuppressed } : {}),
      visibleToPersonas: staticVisibility,
      ...(privilegedSurface.length > 0 ? { privilegedEndpoints: privilegedSurface } : {}),
    }
  }

  // 2. Live Black-Box / Grey-Box Pass (100% through RequestBroker)
  for (const origin of normalizedOrigins) {
    if (signal.aborted) {
      stoppedReason = 'aborted'
      break
    }
    if (!grant.canRead(origin)) {
      stoppedReason = 'scope_revoked'
      continue
    }

    let originUsed = 0
    const probedPaths = new Set<string>()
    const jsQueue: string[] = []
    const jsPageByScript = new Map<string, string>()
    const discoveredCandidatePaths: string[] = []
    const discoveredTemplates: string[] = []
    const idsByCollection = new Map<string, string[]>()
    const jsonDocCandidates: string[] = []
    const navSeeds: Array<{ path: string; depth: number }> = []
    const writeOnlyPaths = new Set<string>()
    const protectedPaths = new Set<string>()
    const configBindings = new Map<string, RouteMapParamBinding[]>()
    // Crawl-time parameter evidence, keyed by normalized route template. `fields` comes from a
    // served JSON response body; `redirectQuery` comes from a same-origin Location header.
    const paramEvidence = new Map<string, { fields: Set<string>; redirectQuery: Set<string> }>()
    const evidenceFor = (template: string) => {
      let evidence = paramEvidence.get(template)
      if (!evidence) {
        evidence = { fields: new Set<string>(), redirectQuery: new Set<string>() }
        paramEvidence.set(template, evidence)
      }
      return evidence
    }
    let observedFieldAttachments = 0
    let originHalted = false
    let personaRejected = false
    let softCalibration: SoftNotFoundCalibration | null = null

    // Surface-planning reads (nav targets, GraphQL, sibling derivation, dependency inference) must
    // see the whole stored surface. `storage.listEndpoints(runId, { origin })` pages at 500 rows by
    // default and silently truncates large apps, so every planning read goes through
    // `listEndpointsPaged` and contributes a `phase0.read_paged` metric for its phase.
    const readPaged = (phase: string, countUsed?: (rows: EndpointRow[]) => number): EndpointRow[] => {
      const rows = listEndpointsPaged(storage, runId, { origin })
      let metric = readPagedMetrics.find(entry => entry.phase === phase && entry.origin === origin)
      if (!metric) {
        metric = { phase, origin, considered: 0, used: 0, truncated: false, reads: 0, pages: 0 }
        readPagedMetrics.push(metric)
      }
      metric.considered += rows.length
      metric.used += countUsed ? countUsed(rows) : rows.length
      metric.reads += 1
      metric.pages += Math.max(1, Math.ceil(rows.length / ENDPOINT_PAGE_SIZE))
      return rows
    }

    const personaForOrigin = (handle: string | undefined): string | undefined => {
      if (!handle || personaRejected) return undefined
      const persona = grant.personas?.get(handle)
      if (!persona) return undefined
      return persona.originAllowlist.includes(origin) ? handle : undefined
    }
    // All discovery fetches carry the approved owner session when one is available, so the SPA
    // shell, API listings, config documents and OpenAPI specs behind login are visible.
    let discoveryPersona = personaForOrigin(params.personas?.find((handle): handle is string => Boolean(handle)))

    // Calibrated protected/API path hints for safe-template path variables (`{{discovered_*_path}}`).
    const noteDiscoveryResponse = (ex: BrokerExchangeResult): void => {
      const method = ex.method.toUpperCase()
      if (method !== 'GET' && method !== 'HEAD') return
      const bare = ex.pathAndQuery.split('?')[0] || '/'
      if (!bare.startsWith('/') || bare.startsWith('//')) return
      if (/[:{}[\]]/.test(bare) || /[\r\n\0]/.test(bare) || STATIC_ASSET_RE.test(bare)) return
      if ([301, 302, 303, 307, 308, 401, 403].includes(ex.status) && protectedPaths.size < 12) {
        protectedPaths.add(bare)
      }
      // Parameter evidence the crawler already holds. Bounded and passive: no extra requests.
      if (ex.status >= 200 && ex.status < 300 && /json/i.test(ex.mediaType) && ex.body.length <= 262_144) {
        const fields = extractJsonFieldNames(ex.body, 32)
        if (fields.length > 0) {
          const evidence = evidenceFor(normalizeDiscoveryTemplate(bare))
          for (const field of fields) evidence.fields.add(field)
        }
      }
      if ([301, 302, 303, 307, 308].includes(ex.status)) {
        const location = ex.respHeaders?.location ?? ex.respHeaders?.Location
        if (typeof location === 'string' && location.length <= 2048) {
          try {
            const target = new URL(location, origin)
            if (target.origin === origin && target.search) {
              const evidence = evidenceFor(normalizeDiscoveryTemplate(target.pathname))
              for (const name of target.searchParams.keys()) evidence.redirectQuery.add(name)
            }
          } catch { /* malformed Location */ }
        }
      }
    }

    const safeGet = async (
      pathAndQuery: string,
      opts?: {
        method?: 'GET' | 'POST'
        body?: string
        headers?: Record<string, string>
        persona?: string
        anonymous?: boolean
        followRedirects?: boolean
        /** Navigation seeds may use a small bounded overflow lane so earlier discovery probes
         *  cannot starve link-only HTML routes. */
        exceedCap?: boolean
      },
    ): Promise<BrokerExchangeResult | null> => {
      if (originHalted || signal.aborted) return null
      const effectiveCap = opts?.exceedCap ? perOriginCap + navOverflow : perOriginCap
      if (originUsed >= effectiveCap) return null
      if (!grant.canRead(origin)) {
        originHalted = true
        stoppedReason = 'scope_revoked'
        return null
      }
      const method = opts?.method ?? 'GET'
      const persona = opts?.anonymous ? undefined : (opts?.persona ?? discoveryPersona)
      const dedupeKey = `${method} ${persona ?? ''} ${pathAndQuery}`
      if (probedPaths.has(dedupeKey)) return null
      probedPaths.add(dedupeKey)
      originUsed += 1
      requestsUsed += 1
      try {
        const ex = await broker.executeHttp({
          origin,
          method,
          pathAndQuery,
          headers: opts?.headers,
          body: opts?.body,
          ...(persona ? { persona } : {}),
          followRedirects: opts?.followRedirects ?? (method === 'GET'),
          runId,
          assignmentId: params.assignmentId,
          timeoutMs: 8_000,
        }, grant, signal)
        if (persona) authRequests += 1
        noteDiscoveryResponse(ex)
        params.onExchange?.(ex)
        // Cross-persona object-ID harvesting runs for Phase-0 HTTP (authenticated and unauth alike).
        storage.trackExchangeResources({
          runId,
          scopeRevision,
          exchange: ex,
          source: 'surface_probe',
        })
        return ex
      } catch (err) {
        if (err instanceof BrokerCircuitOpen) {
          originHalted = true
          stoppedReason = 'circuit_open'
          return null
        }
        if (err instanceof BrokerDenied) {
          if (!grant.canRead(origin)) {
            originHalted = true
            stoppedReason = 'scope_revoked'
            return null
          }
          if (persona && /persona|session|credential/i.test(err.message)) {
            // Persona session unusable for this origin: drop it for the rest of the pass and retry
            // the same discovery request anonymously so recon never stalls on auth plumbing.
            personaRejected = true
            discoveryPersona = undefined
            return safeGet(pathAndQuery, { ...opts, anonymous: true })
          }
          return null
        }
        return null
      }
    }

    const recordEndpoint = (
      method: string,
      rawPath: string,
      source: EndpointSource,
      extra?: { framework?: string | null; riskScore?: number; authRequirement?: string | null },
    ) => {
      const pathTemplate = /(?:^|\/):[A-Za-z_][A-Za-z0-9_-]*/.test(rawPath)
        ? normalizeDiscoveryTemplate(rawPath)
        : normalizeRouteTemplate(rawPath)
      const ep = storage.upsertEndpoint({
        runId,
        scopeRevision,
        origin,
        method: method.toUpperCase(),
        pathTemplate,
        source,
        framework: extra?.framework ?? null,
        authRequirement: extra?.authRequirement ?? null,
        riskScore: extra?.riskScore ?? scoreEndpointRisk(method, pathTemplate),
      })
      endpointsDiscovered += 1
      dynamicPaths.add(pathTemplate)
      return ep
    }

    /** Track which role personas can reach an endpoint (merged after all passes). */
    const phase0Visibility = new Map<string, Set<string>>()
    const tagVisibility = (method: string, rawPath: string, who: string): void => {
      const bare = rawPath.split('?')[0] || '/'
      const tmpl = normalizeDiscoveryTemplate(bare)
      const key = `${method.toUpperCase()} ${tmpl}`
      const set = phase0Visibility.get(key) ?? new Set<string>()
      set.add(who)
      phase0Visibility.set(key, set)
    }

    const recordParams = (endpointId: string, paramList: readonly { name: string; location: ParamLocation }[], source: string): number => {
      let added = 0
      for (const p of paramList.slice(0, 24)) {
        if (!p.name || !isUsefulParamForLocation(p.name, p.location)) continue
        storage.upsertEndpointParam({
          runId,
          endpointId,
          name: p.name,
          location: p.location,
          isCsrf: CSRF_PARAM_RE.test(p.name),
          isObjectId: p.location === 'path' || OBJECT_ID_PARAM_RE.test(p.name),
          source,
        })
        dynamicParams.add(p.name)
        added += 1
      }
      paramsDiscovered += added
      return added
    }

    const queueJsonDoc = (cleanPath: string) => {
      if (jsonDocCandidates.length >= 8 || jsonDocCandidates.includes(cleanPath)) return
      jsonDocCandidates.push(cleanPath)
    }

    // Queue a read-only route harvested from a route map, OpenAPI document, JS bundle or navigation
    // payload for a bounded confirmation probe. Templated routes are kept apart so they are probed
    // with concrete ids harvested from their collection, never with a placeholder literal.
    const queueDiscoveredRoute = (method: string, rawPath: string): void => {
      const verb = method.toUpperCase()
      if (verb !== 'GET' && verb !== 'HEAD') return
      const bare = rawPath.trim()
      const clean = bare.startsWith('/') && !bare.startsWith('//') && !/[\r\n\0\\]/.test(bare)
        ? (bare.split('?')[0] || '/')
        : sanitizePathCandidate(rawPath, origin)
      if (!clean || STATIC_ASSET_RE.test(clean)) return
      if (/[:{}[\]]/.test(clean.split('?')[0] ?? '')) {
        const template = normalizeDiscoveryTemplate(clean)
        if (discoveredTemplates.length < 24 && !discoveredTemplates.includes(template)) {
          discoveredTemplates.push(template)
          // The collection that produces ids for the detail route is worth probing on its own.
          const base = template.replace(/\/:[A-Za-z_][A-Za-z0-9_-]*.*$/, '')
          if (base && base !== template && !/[:{}[\]]/.test(base)) queueDiscoveredRoute('GET', base)
        }
        return
      }
      if (discoveredCandidatePaths.length >= 40 || discoveredCandidatePaths.includes(clean)) return
      discoveredCandidatePaths.push(clean)
    }

    const queueJsChunk = (specifier: string, fromPath = '/') => {
      if (jsQueue.length >= 32) return
      const clean = sanitizePathCandidate(specifier, `${origin}${fromPath}`)
      if (!clean || STATIC_ASSET_RE.test(clean)) return
      if (!/\.(?:m?js|jsx|ts|tsx)(?:\?|$)/i.test(clean)) return
      if (!jsQueue.includes(clean)) jsQueue.push(clean)
    }

    const softNotFoundResponse = (ex: BrokerExchangeResult): boolean =>
      ex.status >= 200 && ex.status < 300 && Boolean(softCalibration && isSoftNotFound(softCalibration, ex))

    // 2a. Standard seed probes. Reserve a small slice of the per-origin cap for JS chunk
    // harvesting, otherwise a long seed list can starve the bundles that carry XHR/route evidence.
    const jsReserve = perOriginCap > 4 ? Math.min(4, Math.floor(perOriginCap / 3)) : 0
    const seedBudget = Math.max(1, perOriginCap - jsReserve)
    let seedFetches = 0

    // 2a-cal. Per-origin soft-404 / SPA catch-all calibration with several unmatched paths at
    // different depths (root-only calibration misses nested API catch-alls).
    if (!originHalted && !signal.aborted && originUsed + 1 < perOriginCap) {
      const cal: SoftNotFoundCalibration = { statuses: [], mediaTypes: [], lengths: [], signatures: [] }
      const probeCount = Math.min(3, Math.max(1, perOriginCap - originUsed - 1))
      for (const probePath of buildSoft404ProbePaths(probeCount)) {
        if (originHalted || signal.aborted || originUsed >= perOriginCap) break
        const ex = await safeGet(probePath)
        if (!ex) continue
        cal.statuses.push(ex.status)
        cal.mediaTypes.push(ex.mediaType)
        cal.lengths.push(ex.body.length)
        cal.signatures.push(bodyStructuralSignature(ex.body))
      }
      if (cal.statuses.length > 0) softCalibration = cal
    }

    for (const seedPath of PHASE0_SEED_PATHS) {
      if (seedFetches >= seedBudget) break
      seedFetches += 1
      if (originHalted || originUsed >= perOriginCap || signal.aborted) break
      if (seedPath === '/') {
        // On crash recovery, reuse any already-recorded GET / for this (runId, origin) so the
        // baseline is never duplicated across SIGKILL + resume. Scope revisions can advance while
        // paused, so the revision is intentionally not part of the reuse key; the live grant still
        // gates whether the origin may be read.
        try {
          const prior = storage.client.prepare(
            `SELECT status, media_type AS mediaType, resp_headers AS respHeadersJson, body_preview AS bodyPreview
             FROM broker_exchanges
             WHERE run_id = ? AND origin = ? AND method = 'GET' AND path_and_query = '/'
             ORDER BY created_at ASC LIMIT 1`,
          ).get(runId, origin) as {
            status: number
            mediaType: string
            respHeadersJson: string
            bodyPreview: string
          } | undefined
          if (prior) {
            // Match safeGet's dedupe key (`METHOD persona path`) so the navigation pass does not
            // re-fetch the recovered baseline route on resume. Keep the legacy key too.
            probedPaths.add(`GET ${discoveryPersona ?? ''} /`)
            probedPaths.add('GET /')
            let headersObj: Record<string, string> = {}
            try { headersObj = JSON.parse(prior.respHeadersJson) as Record<string, string> } catch { /* ignore */ }
            for (const t of mergeTechTags(techTagsFromResponse(headersObj, prior.bodyPreview ?? ''))) techFingerprint.add(t)
            if (prior.status < 400) {
              recordEndpoint('GET', '/', 'surface_probe')
              tagVisibility('GET', '/', 'anonymous')
              if (discoveryPersona) tagVisibility('GET', '/', discoveryPersona)
            }
            const html = extractHtmlLinksAndScripts(prior.bodyPreview ?? '', origin)
            for (const s of html.scripts) {
              queueJsChunk(s, '/')
              jsPageByScript.set(s, '/')
            }
            for (const asset of extractAssetReferences(prior.bodyPreview ?? '')) {
              if (/\.json(?:$|[?#])/i.test(asset)) queueJsonDoc(asset)
              else queueJsChunk(asset, '/')
            }
            for (const l of html.links.slice(0, 60)) {
              dynamicPaths.add(normalizeRouteTemplate(l))
              if (discoveredCandidatePaths.length < 40) discoveredCandidatePaths.push(l)
              if (/\.json(?:\?|$)/i.test(l)) queueJsonDoc(l)
              else navSeeds.push({ path: l, depth: 0 })
            }
            for (const form of html.forms) {
              const ep = recordEndpoint(form.method, form.action, 'surface_probe')
              for (const inp of form.inputs) {
                if (!isUsefulParamName(inp)) continue
                storage.upsertEndpointParam({
                  runId,
                  endpointId: ep.id,
                  name: inp,
                  location: form.method === 'GET' ? 'query' : 'form',
                  isCsrf: CSRF_PARAM_RE.test(inp),
                  isObjectId: OBJECT_ID_PARAM_RE.test(inp),
                  source: 'observed:form_field',
                })
                dynamicParams.add(inp)
                paramsDiscovered += 1
              }
            }
            continue
          }
        } catch { /* fall through to live GET / */ }
      }
      let ex = await safeGet(seedPath)
      // Config/route-map artifacts are often behind auth; retry with every approved persona (not
      // just the first) so role-scoped tables are visible to the persona union.
      if (ex && (ex.status === 401 || ex.status === 403) && params.personas?.length) {
        for (const handle of params.personas) {
          if (!personaForOrigin(handle)) continue
          if (originHalted || originUsed >= perOriginCap) break
          ex = await safeGet(seedPath, { persona: handle })
          if (ex && ex.status < 400) break
        }
      }
      if (!ex) continue

      if (seedPath === '/') {
        for (const t of mergeTechTags(techTagsFromResponse(ex.respHeaders, ex.body))) techFingerprint.add(t)
        if (ex.status < 400) {
          recordEndpoint('GET', '/', 'surface_probe')
          tagVisibility('GET', '/', discoveryPersona ?? 'anonymous')
        }
        const html = extractHtmlLinksAndScripts(ex.body, origin)
        for (const s of html.scripts) {
          queueJsChunk(s, '/')
          jsPageByScript.set(s, '/')
        }
        for (const asset of extractAssetReferences(ex.body)) {
          if (/\.json(?:$|[?#])/i.test(asset)) queueJsonDoc(asset)
          else queueJsChunk(asset, '/')
        }
        for (const l of html.links.slice(0, 60)) {
          dynamicPaths.add(normalizeRouteTemplate(l))
          if (discoveredCandidatePaths.length < 40) discoveredCandidatePaths.push(l)
          if (/\.json(?:\?|$)/i.test(l)) queueJsonDoc(l)
          else navSeeds.push({ path: l, depth: 0 })
        }
        for (const form of html.forms) {
          const ep = recordEndpoint(form.method, form.action, 'surface_probe')
          for (const inp of form.inputs) {
            if (!isUsefulParamName(inp)) continue
            storage.upsertEndpointParam({
              runId,
              endpointId: ep.id,
              name: inp,
              location: form.method === 'GET' ? 'query' : 'form',
              isCsrf: CSRF_PARAM_RE.test(inp),
              isObjectId: OBJECT_ID_PARAM_RE.test(inp),
              source: 'observed:form_field',
            })
            dynamicParams.add(inp)
            paramsDiscovered += 1
          }
        }
      } else if (seedPath === '/robots.txt' && ex.status < 400) {
        for (const m of ex.body.matchAll(/^(?:Allow|Disallow)\s*:\s*(\/\S+)/gim)) {
          const clean = sanitizePathCandidate(m[1].replace(/\*+$/, ''), origin)
          if (clean) {
            dynamicPaths.add(normalizeRouteTemplate(clean))
            if (discoveredCandidatePaths.length < 40) discoveredCandidatePaths.push(clean)
          }
        }
      } else if (seedPath === '/sitemap.xml' && ex.status < 400) {
        for (const m of ex.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
          const clean = sanitizePathCandidate(m[1], origin)
          if (clean) {
            dynamicPaths.add(normalizeRouteTemplate(clean))
            if (discoveredCandidatePaths.length < 40) discoveredCandidatePaths.push(clean)
          }
        }
      } else if (seedPath === '/.well-known/openid-configuration' && ex.status < 400) {
        recordEndpoint('GET', seedPath, 'surface_probe', { riskScore: 65 })
        try {
          const oidc = JSON.parse(ex.body) as Record<string, unknown>
          for (const k of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'registration_endpoint']) {
            if (typeof oidc[k] === 'string') {
              const clean = sanitizePathCandidate(oidc[k] as string, origin)
              if (clean) recordEndpoint('GET', clean, 'surface_probe', { riskScore: 80 })
            }
          }
        } catch { /* ignore invalid JSON */ }
      } else if (/(?:openapi|swagger|api-docs)/i.test(seedPath) && ex.status < 400 && !softNotFoundResponse(ex)) {
        const parsed = parseOpenApiDoc(ex.body, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams)
        endpointsDiscovered += parsed.endpoints
        paramsDiscovered += parsed.params
        if (parsed.endpoints > 0) {
          const specDoc = parseJsonOrYaml(ex.body)
          if (specDoc && typeof specDoc === 'object') {
            for (const entry of harvestRouteMapDocument(specDoc).slice(0, 120)) {
              queueDiscoveredRoute(entry.method, entry.path)
            }
          }
        }
        if (parsed.endpoints === 0) {
          // Swagger-less API index documents are handled by the structural route-map expander.
          const expanded = parseRouteMapDoc(ex.body, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams, { bindings: configBindings })
          endpointsDiscovered += expanded.endpoints
          paramsDiscovered += expanded.params
          routeMapEndpoints += expanded.endpoints
        }
      } else if ((seedPath === '/graphql' || seedPath === '/api/graphql') && ex.status < 400) {
        const gqlPath = seedPath.startsWith('/api/') ? seedPath : '/graphql'
        recordEndpoint('POST', gqlPath, 'graphql', { framework: 'graphql', riskScore: 85 })
        techFingerprint.add('graphql')
      } else if (ex.status >= 200 && ex.status < 300) {
        if (softNotFoundResponse(ex)) {
          soft404Rejected += 1
          continue
        }
        recordEndpoint('GET', seedPath, 'surface_probe')
        // Any served JSON/YAML document may be a route map or config with an endpoint table.
        if (/json|yaml/i.test(ex.mediaType) || /^\s*[{[]/.test(ex.body)) {
          try {
            const doc = parseJsonOrYaml(ex.body)
            const parsed = parseRouteMapDoc(ex.body, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams, { bindings: configBindings })
            endpointsDiscovered += parsed.endpoints
            paramsDiscovered += parsed.params
            routeMapEndpoints += parsed.endpoints
            if (doc && typeof doc === 'object') {
              for (const link of extractJsonLinkTargets(ex.body, origin)) navSeeds.push({ path: link, depth: 0 })
              const entries = harvestRouteMapDocument(doc).slice(0, 120)
              const docGetPaths = new Set(entries.filter(entry => entry.method === 'GET').map(entry => normalizeDiscoveryTemplate(entry.path)))
              for (const entry of entries) {
                const tmpl = normalizeDiscoveryTemplate(entry.path)
                if (entry.method !== 'GET' && entry.method !== 'HEAD' && !docGetPaths.has(tmpl)) writeOnlyPaths.add(tmpl)
                else if (entry.method === 'GET') {
                  queueDiscoveredRoute(entry.method, entry.path)
                  if (!/:/.test(entry.path)) navSeeds.push({ path: entry.path, depth: 0 })
                }
              }
            }
          } catch { /* not a route map */ }
        }
      }
    }

    // 2b. Fetch same-origin JS chunks. The queue is drained breadth-first (imports, manifests,
    // webpack/Vite chunk maps) within a bounded 32-bundle budget; seed probes reserved jsReserve.
    const maxJsChunks = Math.min(32, Math.max(0, perOriginCap - originUsed))
    let jsFetched = 0
    for (let jsIndex = 0; jsIndex < jsQueue.length && jsFetched < maxJsChunks; jsIndex += 1) {
      const jsPath = jsQueue[jsIndex]
      if (!jsPath) continue
      if (originHalted || originUsed >= perOriginCap || signal.aborted) break
      const ex = await safeGet(jsPath)
      if (!ex || ex.status >= 400 || !ex.body) continue
      jsFetched += 1

      const harvested = jsHarvest(ex.body, `${origin}${jsPath}`) as {
        apiPaths?: string[]
        adminPaths?: string[]
        routes?: Array<{ path?: string }>
        httpCalls?: Array<{ url?: string; method?: string; bodyKeys?: string[] }>
        graphqlDocs?: Array<{ kind?: string; name?: string }>
        nextActions?: Array<{ id?: string }>
        scriptChunks?: string[]
      }

      const seenJsRoutes = new Map<string, string>()
      const addJsEndpoint = (method: string, rawPath: string, bodyKeys: string[] = []): string | null => {
        if (seenJsRoutes.size >= 120) return null
        const clean = sanitizePathCandidate(rawPath, origin)
        if (!clean || STATIC_ASSET_RE.test(clean)) return null
        const tmpl = /(?:^|\/):[A-Za-z_][A-Za-z0-9_-]*/.test(clean)
          ? normalizeDiscoveryTemplate(clean)
          : normalizeRouteTemplate(clean)
        const key = `${method.toUpperCase()} ${tmpl}`
        const existingId = seenJsRoutes.get(key)
        // The same route is often referenced by several sources (harvested calls, regex literal scan,
        // OpenAPI-derived body keys). Merge parameters instead of dropping later evidence.
        if (existingId) return existingId
        const ep = recordEndpoint(method, tmpl, 'js_ast')
        seenJsRoutes.set(key, ep.id)
        if (method.toUpperCase() === 'GET' && (/\.json$/i.test(clean) || /(?:^|\/)(?:config|routes|route-map|manifest|endpoints|links|nav|menu|bootstrap)(?:\.|$)/i.test(clean))) {
          queueJsonDoc(clean)
        }
        for (const bk of bodyKeys.slice(0, 20)) {
          const bkLocation: ParamLocation = method.toUpperCase() === 'GET' ? 'query' : 'json'
          if (!bk || !isUsefulParamForLocation(bk, bkLocation)) continue
          storage.upsertEndpointParam({
            runId,
            endpointId: ep.id,
            name: bk,
            location: bkLocation,
            isCsrf: CSRF_PARAM_RE.test(bk),
            isObjectId: OBJECT_ID_PARAM_RE.test(bk),
            source: 'inferred_ast',
          })
          dynamicParams.add(bk)
          paramsDiscovered += 1
        }
        queueDiscoveredRoute(method, clean)
        return ep.id
      }

      for (const call of harvested.httpCalls ?? []) {
        if (call.url) addJsEndpoint(call.method || 'GET', call.url, call.bodyKeys ?? [])
      }
      for (const p of [...(harvested.apiPaths ?? []), ...(harvested.adminPaths ?? [])]) {
        addJsEndpoint('GET', p)
      }
      for (const r of harvested.routes ?? []) {
        if (r.path) addJsEndpoint('GET', r.path)
      }
      // Regex request-literal scan: fills in methods and body/XML parameter names even when the
      // bundle AST parser is unavailable (fetch/axios/XHR init object literals).
      for (const spec of harvestJsRequestParams(ex.body).slice(0, 24)) {
        const epId = addJsEndpoint(spec.method, spec.path)
        if (!epId) continue
        for (const p of spec.params) {
          if (!isUsefulParamForLocation(p.name, p.location)) continue
          storage.upsertEndpointParam({
            runId,
            endpointId: epId,
            name: p.name,
            location: p.location,
            isCsrf: CSRF_PARAM_RE.test(p.name),
            isObjectId: OBJECT_ID_PARAM_RE.test(p.name),
            source: 'inferred_bundle',
          })
          dynamicParams.add(p.name)
          paramsDiscovered += 1
        }
      }
      // SPA router tables: path literals in router config are navigable endpoints even without hrefs.
      for (const routePath of harvestJsRouteTable(ex.body).slice(0, 24)) {
        if (addJsEndpoint('GET', routePath)) jsRouterRoutes += 1
      }
      // tRPC procedures: batched GET uses a query `input`, mutations POST a JSON `input`.
      for (const proc of harvestTrpcProcedures(ex.body).slice(0, 24)) {
        const trpcPath = `/trpc/${proc.router}.${proc.procedure}`
        const getId = addJsEndpoint('GET', trpcPath)
        if (getId) recordParams(getId, [{ name: 'input', location: 'query' }], 'inferred_bundle')
        const postId = addJsEndpoint('POST', trpcPath)
        if (postId) recordParams(postId, [{ name: 'input', location: 'json' }], 'inferred_bundle')
      }
      // Runtime config-parameter -> API body-field bindings for route-map expansion.
      for (const binding of harvestConfigParamBindings(ex.body)) {
        const list = configBindings.get(binding.routeKey) ?? []
        if (!list.some(existing => existing.name === binding.name && existing.location === binding.location)) {
          list.push(binding)
          configBindings.set(binding.routeKey, list)
        }
      }
      // Module imports + build-asset references (manifest/chunk maps) extend the BFS queue.
      for (const specifier of extractJsModuleImports(ex.body)) queueJsChunk(specifier, jsPath)
      for (const chunk of harvested.scriptChunks ?? []) queueJsChunk(chunk, jsPath)
      for (const asset of extractAssetReferences(ex.body)) {
        if (/\.json(?:$|[?#])/i.test(asset)) queueJsonDoc(asset)
        else queueJsChunk(asset, jsPath)
      }
      if ((harvested.graphqlDocs?.length ?? 0) > 0) {
        recordEndpoint('POST', '/graphql', 'graphql', { framework: 'graphql', riskScore: 85 })
      }
      for (const act of (harvested.nextActions ?? []).slice(0, 10)) {
        if (!act.id) continue
        // Keep the executable synthetic action endpoint and represent the Next Server Action on its
        // page route with Next-Action metadata so probes can pair action ids with page paths.
        recordEndpoint('POST', `/_next/action/${act.id.slice(0, 40)}`, 'js_ast', { framework: 'nextjs', riskScore: 85 })
        const pagePath = jsPageByScript.get(jsPath)
        if (pagePath) {
          const pageEp = recordEndpoint('POST', pagePath, 'js_ast', { framework: 'nextjs', riskScore: 88 })
          recordParams(pageEp.id, [{ name: 'Next-Action', location: 'header' }], 'inferred_bundle')
        }
      }

      // Opportunistically fetch same-origin source map if budget permits
      const mapMatch = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/.exec(ex.body)
      if (mapMatch && originUsed < perOriginCap) {
        const mapPath = sanitizePathCandidate(mapMatch[1], `${origin}${jsPath}`)
        if (mapPath && mapPath.endsWith('.map')) {
          const mapEx = await safeGet(mapPath)
          if (mapEx && mapEx.status < 400 && mapEx.body) {
            const mapHarvest = jsHarvest(mapEx.body, `${origin}${mapPath}`, { sourceMapContent: mapEx.body }) as {
              apiPaths?: string[]
              httpCalls?: Array<{ url?: string; method?: string; bodyKeys?: string[] }>
            }
            for (const call of mapHarvest.httpCalls ?? []) {
              if (call.url) addJsEndpoint(call.method || 'GET', call.url, call.bodyKeys ?? [])
            }
            for (const p of mapHarvest.apiPaths ?? []) addJsEndpoint('GET', p)
          }
        }
      }
    }

    // 2b-bis. Fetch same-origin JSON/YAML route-map & config artifacts referenced by the SPA
    // (runtime config, API index, Vite/webpack manifests). This is the only way config tables that
    // are referenced solely from JS become visible before probes run.
    for (const docPath of [...new Set(jsonDocCandidates)].slice(0, 6)) {
      if (originHalted || originUsed >= perOriginCap - 4 || signal.aborted) break
      const ex = await safeGet(docPath)
      if (!ex || ex.status >= 400 || !ex.body) continue
      if (softNotFoundResponse(ex)) { soft404Rejected += 1; continue }
      const isStructured = /json|yaml/i.test(ex.mediaType) || /^\s*[{[]/.test(ex.body)
      if (!isStructured) {
        // A manifest-like JS body: follow the chunk references it lists.
        for (const asset of extractAssetReferences(ex.body)) queueJsChunk(asset, docPath)
        continue
      }
      const expanded = parseRouteMapDoc(ex.body, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams, { bindings: configBindings })
      endpointsDiscovered += expanded.endpoints
      paramsDiscovered += expanded.params
      routeMapEndpoints += expanded.endpoints
      const doc = parseJsonOrYaml(ex.body)
      if (doc && typeof doc === 'object') {
        // Declared-surface hydration: an OIDC discovery document and a CDN asset manifest both
        // name routes the origin actually serves. Absolute discovery URLs are accepted only when
        // they stay on the document's own origin; manifest entries resolve against the document.
        const docOrigin = (() => { try { return new URL(origin).origin } catch { return origin } })()
        const recordDeclared = (method: string, pathname: string): void => {
          if (!pathname.startsWith('/') || pathname.startsWith('//') || /[:{}\s]/.test(pathname)) return
          recordEndpoint(method, pathname, 'spa_crawl', { authRequirement: 'none' })
          queueDiscoveredRoute(method, pathname)
        }
        for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'end_session_endpoint', 'introspection_endpoint', 'revocation_endpoint', 'registration_endpoint']) {
          const value = (doc as Record<string, unknown>)[key]
          if (typeof value !== 'string') continue
          try {
            const parsed = new URL(value, docOrigin)
            if (parsed.origin !== docOrigin) continue
            recordDeclared(/token|introspection|revocation|registration/.test(key) ? 'POST' : 'GET', parsed.pathname)
          } catch { /* malformed declaration */ }
        }
        for (const key of ['chunks', 'files', 'assets', 'scripts', 'entrypoints']) {
          const list = (doc as Record<string, unknown>)[key]
          if (!Array.isArray(list)) continue
          for (const item of list.slice(0, 64)) {
            const raw = typeof item === 'string'
              ? item
              : item && typeof item === 'object'
                ? ((item as Record<string, unknown>).file ?? (item as Record<string, unknown>).src ?? (item as Record<string, unknown>).path)
                : null
            if (typeof raw !== 'string' || !raw.trim()) continue
            const clean = (raw.startsWith('/') ? raw : `/${raw.replace(/^\.?\//, '')}`).split('?')[0] ?? ''
            if (!clean || clean.startsWith('//') || !/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,512}$/.test(clean)) continue
            recordEndpoint('GET', clean, 'spa_crawl')
            if (/\.(?:js|mjs)$/i.test(clean)) queueJsChunk(clean, docPath)
          }
        }
        for (const link of extractJsonLinkTargets(ex.body, origin)) navSeeds.push({ path: link, depth: 0 })
        const entries = harvestRouteMapDocument(doc).slice(0, 120)
        const docGetPaths = new Set(entries.filter(entry => entry.method === 'GET').map(entry => normalizeDiscoveryTemplate(entry.path)))
        for (const entry of entries) {
          const tmpl = normalizeDiscoveryTemplate(entry.path)
          if (entry.method !== 'GET' && entry.method !== 'HEAD' && !docGetPaths.has(tmpl)) writeOnlyPaths.add(tmpl)
          else if (entry.method === 'GET') {
            queueDiscoveredRoute(entry.method, entry.path)
            if (!/:/.test(entry.path)) navSeeds.push({ path: entry.path, depth: 0 })
          }
        }
      }
      for (const asset of extractAssetReferences(ex.body)) {
        if (/\.json(?:$|[?#])/i.test(asset)) queueJsonDoc(asset)
        else queueJsChunk(asset, docPath)
      }
    }

    // 2c. Tech-matched safe templates (strictly bounded by remaining per-origin budget). Generic
    // exposure templates run even when no fingerprint matched, so they must not be gated on a
    // non-empty tag set.
    const remainingForTemplates = perOriginCap - originUsed
    if (!originHalted && !signal.aborted && remainingForTemplates >= 4 && grant.canRead(origin)) {
      const templateBudget = Math.min(20, remainingForTemplates)
      const templateApiPaths = new Set<string>()
      const considerApiPath = (rawPath: string): void => {
        const bare = rawPath.split('?')[0] || '/'
        if (!bare.startsWith('/') || /[:{}[\]]/.test(bare) || STATIC_ASSET_RE.test(bare)) return
        if (!/^\/(?:api|rest|graphql|trpc|v\d+)(?:\/|$)/i.test(bare)) return
        if (templateApiPaths.size < 6) templateApiPaths.add(bare)
      }
      for (const ep of readPaged('template_api_paths')) considerApiPath(ep.pathTemplate)
      for (const p of discoveredCandidatePaths) considerApiPath(p)
      let stagedTemplateExchanges = 0
      try {
        const tplRes = await runSafeTemplates({
          origin,
          techFingerprint: [...techFingerprint],
          discoveredPaths: {
            protectedPaths: [...protectedPaths].slice(0, 6),
            apiPaths: [...templateApiPaths].slice(0, 6),
          },
          maxTemplates: Math.max(1, Math.floor(templateBudget / 2)),
          maxRequests: templateBudget,
          ...(discoveryPersona ? { persona: discoveryPersona } : {}),
          runId,
          assignmentId: params.assignmentId,
          storage,
          onExchange: ex => {
            stagedTemplateExchanges += 1
            originUsed += 1
            requestsUsed += 1
            noteDiscoveryResponse(ex)
            return params.onExchange?.(ex)
          },
        }, broker, grant, params.canaryBroker, signal)
        const unaccounted = Math.max(0, tplRes.requestsSent - stagedTemplateExchanges)
        originUsed += unaccounted
        requestsUsed += unaccounted
        for (const m of tplRes.matches) {
          recordEndpoint(m.method, m.path, 'surface_probe', { riskScore: 85 })
        }
      } catch (err) {
        if (err instanceof BrokerCircuitOpen) {
          originHalted = true
          stoppedReason = 'circuit_open'
        }
      }
    }

    // 2c-bis. Parent-route derivation: a documented subresource (`/api/reports/summary`) implies its
    // parent resource (`/api/reports`). Bounded to a handful of read-only confirmation probes; the
    // soft-404 calibration below filters SPA catch-all responses.
    const parentProbes: string[] = []
    for (const candidatePath of [...discoveredCandidatePaths, ...discoveredTemplates]) {
      const bare = (candidatePath.split('?')[0] || '/').replace(/\/+$/, '')
      const segments = bare.split('/').filter(Boolean)
      if (segments.length < 3) continue
      const parent = `/${segments.slice(0, -1).join('/')}`
      if (/[:{}[\]]/.test(parent)) continue
      if (parentProbes.includes(parent) || discoveredCandidatePaths.includes(parent)) continue
      parentProbes.push(parent)
      if (parentProbes.length >= 6) break
    }

    // 2d-cal. Extend soft-404 calibration under the discovered API prefix: many SPAs answer unknown
    // `/api/*` paths with the same HTML shell (HTTP 200) as unknown top-level routes, while real API
    // routes answer JSON. Two extra probes keep this a cheap confirmation.
    if (softCalibration && !originHalted && !signal.aborted && originUsed + 2 <= perOriginCap - 8) {
      const prefixCounts = new Map<string, number>()
      for (const candidatePath of [...discoveredCandidatePaths, ...discoveredTemplates]) {
        const prefixMatch = /^\/((?:api|rest|graphql|internal|v\d+)(?:\/v\d+)?)\//i.exec(candidatePath)
        if (!prefixMatch) continue
        const prefix = `/${prefixMatch[1]}`
        prefixCounts.set(prefix, (prefixCounts.get(prefix) ?? 0) + 1)
      }
      const apiPrefix = [...prefixCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0]
      if (apiPrefix) {
        const token = randomUUID().replace(/-/g, '').slice(0, 12)
        const prefixProbes = [
          `${apiPrefix}/.guardian-cal-${token}`,
          `${apiPrefix}/.guardian-cal-${token}/missing`,
          `${apiPrefix}/.guardian-cal-${token}/detail/view`,
        ]
        for (const probePath of prefixProbes) {
          if (originHalted || signal.aborted || originUsed >= perOriginCap) break
          const ex = await safeGet(probePath)
          if (!ex) continue
          softCalibration.statuses.push(ex.status)
          softCalibration.mediaTypes.push(ex.mediaType)
          softCalibration.lengths.push(ex.body.length)
          softCalibration.signatures.push(bodyStructuralSignature(ex.body))
        }
      }
    }

    // 2d. Bounded probe of discovered route candidates (links, route maps, JS-AST/OpenAPI paths).
    // Strictly within perOriginCap; template routes are probed later with concrete ids.
    const siblingSeen = new Set<string>()
    const detailMethodsSeen = new Set<string>()
    for (const ep of readPaged('detail_methods')) {
      const template = ep.pathTemplate.split('?')[0] || '/'
      const detailBase = /^(.+)\/(?::[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/.exec(template)?.[1]
      if (detailBase) detailMethodsSeen.add(`${detailBase}|${ep.method.toUpperCase()}`)
    }
    let siblingOptionsProbes = 0
    const recordSiblingSurface = async (rawCollection: string, sampleId?: string): Promise<number> => {
      if (!siblingDerivationEnabled) return 0
      if (siblingSeen.size >= 8) return 0
      const bare = (rawCollection.split('?')[0] || '/').replace(/\/+$/, '')
      if (!bare || bare === '/' || STATIC_ASSET_RE.test(bare)) return 0
      if (/[:{}[\]]/.test(bare)) return 0
      const segments = bare.split('/').filter(Boolean)
      if (segments.length === 0 || segments.length > 5) return 0
      const template = `${bare}/:id`
      // Methods the target advertises for the object route (OPTIONS is a safe, read-only request).
      let allowed = new Set<string>(['GET'])
      if (sampleId && siblingOptionsProbes < 6 && originUsed < perOriginCap - 2 && !originHalted && !signal.aborted) {
        siblingOptionsProbes += 1
        try {
          const optionsEx = await broker.executeHttp({
            origin,
            method: 'OPTIONS',
            pathAndQuery: `${bare}/${encodeURIComponent(sampleId)}`,
            ...(discoveryPersona ? { persona: discoveryPersona } : {}),
            followRedirects: false,
            timeoutMs: 6_000,
            runId,
            assignmentId: params.assignmentId,
          }, grant, signal)
          originUsed += 1
          requestsUsed += 1
          params.onExchange?.(optionsEx)
          const advertised = harvestAllowMethods(optionsEx.respHeaders)
          if (advertised.length > 0) {
            allowed = new Set(['GET', ...advertised])
            methodHints += advertised.length
          }
        } catch { /* OPTIONS is optional; fall back to the safe GET sibling */ }
      }
      if (siblingSeen.has(template)) return 0
      siblingSeen.add(template)
      let added = 0
      for (const method of ['GET', 'PATCH', 'DELETE'] as const) {
        if (!allowed.has(method)) continue
        if (detailMethodsSeen.has(`${bare}|${method}`)) continue
        const ep = recordEndpoint(method, template, 'surface_probe', { riskScore: scoreEndpointRisk(method, template) })
        storage.upsertEndpointParam({
          runId,
          endpointId: ep.id,
          name: 'id',
          location: 'path',
          isObjectId: true,
          isCsrf: false,
          source: 'phase0_sibling',
        })
        dynamicParams.add('id')
        detailMethodsSeen.add(`${bare}|${method}`)
        siblingEndpoints += 1
        paramsDiscovered += 1
        added += 1
      }
      return added
    }
    /** A Location header that points below the requested path implies a created resource sibling. */
    const recordLocationSibling = async (requestPath: string, ex: BrokerExchangeResult): Promise<void> => {
      const rawLocation = ex.respHeaders?.location ?? ex.respHeaders?.Location
      if (!rawLocation) return
      const clean = sanitizePathCandidate(rawLocation, origin)
      if (!clean) return
      const requested = (requestPath.split('?')[0] || '/').replace(/\/+$/, '')
      const located = (clean.split('?')[0] || '/').replace(/\/+$/, '')
      if (!requested || requested === '/' || !located.startsWith(`${requested}/`)) return
      const sampleId = located.slice(requested.length + 1).split('/')[0]
      await recordSiblingSurface(requested, sampleId)
    }

    const probeDiscovered = async (candidate: string): Promise<void> => {
      if (originHalted || originUsed >= perOriginCap || signal.aborted) return
      if (candidate === '/' || STATIC_ASSET_RE.test(candidate)) return
      const ex = await safeGet(candidate)
      // 401/403/405 means the route exists but is gated or method-restricted: still part of the surface.
      if (ex && softNotFoundResponse(ex)) {
        soft404Rejected += 1
        return
      }
      if (!ex || !(ex.status < 400 || ex.status === 401 || ex.status === 403 || ex.status === 405)) return
      // A 405 response advertises the methods the route really accepts. Record those with their
      // declared method instead of inventing a GET, and never probe them from recon.
      const allow = harvestAllowMethods(ex.respHeaders)
      if (ex.status === 405 && allow.length > 0) {
        for (const method of allow) {
          recordEndpoint(method, candidate, 'surface_probe', { riskScore: scoreEndpointRisk(method, candidate) })
          methodHints += 1
        }
        return
      }
      const ep = recordEndpoint('GET', candidate, 'surface_probe')
      paramsDiscovered += recordQueryParamsForEndpoint({
        rawPathAndQuery: candidate, origin, endpointId: ep.id, source: 'phase0_html',
        storage, runId, dynamicParams,
      })
      await recordLocationSibling(candidate, ex)
      // A 400/422 validation body names the schema the route wants; learn it passively.
      if (ex.status === 400 || ex.status === 422) {
        for (const field of harvestValidationFieldHints(ex.body)) {
          storage.upsertEndpointParam({
            runId,
            endpointId: ep.id,
            name: field,
            location: 'query',
            isCsrf: CSRF_PARAM_RE.test(field),
            isObjectId: OBJECT_ID_PARAM_RE.test(field),
            source: 'phase0_validation',
          })
          dynamicParams.add(field)
          paramsDiscovered += 1
          methodHints += 1
        }
        return
      }
      if (ex.status >= 400) return
      if (/json/i.test(ex.mediaType) || /^\s*[{[]/.test(ex.body.slice(0, 64))) {
        // Collection listings seed concrete ids for templated detail routes.
        const ids = extractJsonRecordIds(ex.body)
        if (ids.length > 0) {
          idsByCollection.set(normalizeDiscoveryTemplate(candidate.split('?')[0] || '/'), ids)
          // Observed collection: derive the object siblings without assuming any noun.
          await recordSiblingSurface(candidate.split('?')[0] || '/', ids[0])
        }
        for (const link of extractJsonLinkTargets(ex.body, origin).slice(0, 8)) {
          queueDiscoveredRoute('GET', link)
        }
      }
      if (/<html\b|<input\b|<form\b/i.test(ex.body)) {
        const parsed = extractHtmlLinksAndScripts(ex.body, origin)
        for (const inp of parsed.inputs.slice(0, 8)) {
          if (inp.type && /^(?:hidden|submit|button|reset|checkbox|radio|file|image)$/i.test(inp.type)) continue
          if (!isUsefulParamName(inp.name)) continue
          storage.upsertEndpointParam({
            runId,
            endpointId: ep.id,
            name: inp.name,
            location: 'query',
            isCsrf: CSRF_PARAM_RE.test(inp.name),
            isObjectId: OBJECT_ID_PARAM_RE.test(inp.name),
            source: 'observed:form_field',
          })
          dynamicParams.add(inp.name)
          paramsDiscovered += 1
        }
        for (const s of parsed.scripts) {
          queueJsChunk(s, candidate)
          jsPageByScript.set(s, candidate)
        }
        for (const asset of extractAssetReferences(ex.body)) {
          if (/\.json(?:$|[?#])/i.test(asset)) queueJsonDoc(asset)
          else queueJsChunk(asset, candidate)
        }
      }
    }

    const navSeedPaths = new Set(navSeeds.slice(0, 32).map(seed => seed.path))
    for (const candidate of [...new Set(discoveredCandidatePaths)].slice(0, 20)) {
      if (originHalted || originUsed >= perOriginCap || signal.aborted) break
      // Route-map/HTML candidates are also navigation seeds; let the navigation pass probe them so
      // observed listing fields still seed sibling write endpoints.
      if (navSeedPaths.has(candidate)) continue
      await probeDiscovered(candidate)
    }
    for (const parent of parentProbes) {
      if (originHalted || originUsed >= perOriginCap || signal.aborted) break
      if (navSeedPaths.has(parent)) continue
      await probeDiscovered(parent)
    }

    // 2d-bis. Authenticated JSON navigation: follow HATEOAS links found in API responses and infer
    // collection->detail reads from ids observed in authenticated listings. Read-only, depth <= 2,
    // per-origin capped; only JSON/API responses become endpoints (SPA shell HTML is not recorded).
    const navVisited = new Set<string>()
    const navQueue = navSeeds.slice(0, 32)
    const navGetTemplates = [...new Set(readPaged('nav_targets',
      rows => rows.filter(ep => ep.method === 'GET' && ep.pathTemplate.split('/').filter(Boolean).length >= 2).length)
      .filter(ep => ep.method === 'GET' && ep.pathTemplate.split('/').filter(Boolean).length >= 2)
      .map(ep => ep.pathTemplate))]
    const navCap = Math.min(28, Math.max(0, perOriginCap + navOverflow - originUsed))
    const navOriginCap = perOriginCap + navOverflow
    const attachObservedFields = (baseTemplate: string, body: string) => {
      if (observedFieldAttachments >= 12) return
      const fields = extractJsonFieldNames(body)
        .filter(name => !/^(?:ext_)?id$/i.test(name) && !/(?:_id|Id|_at|_by|uuid|ref)$/.test(name))
      if (fields.length === 0) return
      const priority = (name: string): number =>
        /(url|uri|link|callback|redirect|endpoint|token|role|plan|price|amount|name|query|filter|template)/i.test(name) ? 0 : 1
      const ranked = [...fields].sort((a, b) => priority(a) - priority(b))
      // Paged surface read: a write target may sit far past the store's default 500-row page on a
      // large app, so read the whole origin surface and filter to the collection's write methods.
      const targets = readPaged('observed_fields', rows => rows.filter(ep =>
        ['POST', 'PUT', 'PATCH'].includes(ep.method)
        && (ep.pathTemplate === baseTemplate || ep.pathTemplate.startsWith(`${baseTemplate}/`))).length)
        .filter(ep =>
          ['POST', 'PUT', 'PATCH'].includes(ep.method)
          && (ep.pathTemplate === baseTemplate || ep.pathTemplate.startsWith(`${baseTemplate}/`)))
      let attached = 0
      for (const target of targets.slice(0, 24)) {
        if (observedFieldAttachments >= 12 || attached >= 4) break
        // Per-endpoint param lookup keeps the full-scan cost off the navigation hot path.
        if (storage.listEndpointParams(runId, target.id).length > 0) continue
        recordParams(target.id, ranked.slice(0, 4).map(name => ({ name, location: 'json' as const })), 'inferred_html')
        observedFieldAttachments += 1
        attached += 1
      }
    }
    for (let navIndex = 0; navIndex < navQueue.length && navigationRequests < navCap; navIndex += 1) {
      if (originHalted || originUsed >= navOriginCap || signal.aborted) break
      const item = navQueue[navIndex]
      if (!item) continue
      const clean = sanitizePathCandidate(item.path, origin)
      if (!clean || clean === '/' || STATIC_ASSET_RE.test(clean)) continue
      if (/[:{}]/.test(clean) || navVisited.has(clean)) continue
      if (writeOnlyPaths.has(normalizeDiscoveryTemplate(clean))) continue
      navVisited.add(clean)
      const ex = await safeGet(clean, { exceedCap: true })
      if (!ex) continue
      navigationRequests += 1
      if (softNotFoundResponse(ex)) { soft404Rejected += 1; continue }
      const isJson = /json/i.test(ex.mediaType) || /^\s*[{[]/.test(ex.body)
      const bare = clean.split('?')[0] || '/'
      const surfaceStatus = ex.status < 400 || ex.status === 401 || ex.status === 403 || ex.status === 405
      if (!surfaceStatus) continue
      if (!isJson && !/^\/(?:api|rest|v\d|graphql|trpc)\//i.test(bare) && !/\.json$/i.test(bare)) {
        // HTML pages reached only through links are real surface too (soft-404 already filtered the
        // SPA catch-all above). Record them instead of silently dropping every non-API navigation hit.
        if (!/html/i.test(ex.mediaType)) continue
      }
      const ep = recordEndpoint('GET', bare, 'spa_crawl', {
        authRequirement: discoveryPersona ? `persona:${discoveryPersona}` : null,
        riskScore: 60,
      })
      tagVisibility('GET', bare, discoveryPersona ?? 'anonymous')
      navigationEndpoints += 1
      paramsDiscovered += recordQueryParamsForEndpoint({
        rawPathAndQuery: clean, origin, endpointId: ep.id, source: 'spa_crawl',
        storage, runId, dynamicParams,
      })
      if (!isJson || ex.status >= 400) continue
      const template = normalizeDiscoveryTemplate(bare)
      const baseTemplate = template.replace(/\/:[A-Za-z_][A-Za-z0-9_-]*$/, '')
      attachObservedFields(baseTemplate, ex.body)
      if (item.depth < 2) {
        for (const link of extractJsonLinkTargets(ex.body, origin)) {
          if (navQueue.length >= 64) break
          if (writeOnlyPaths.has(normalizeDiscoveryTemplate(link))) continue
          navQueue.push({ path: link, depth: item.depth + 1 })
        }
      }
      const ids = extractJsonRecordIds(ex.body)
      if (ids.length > 0) {
        idsByCollection.set(normalizeDiscoveryTemplate(bare), ids)
        await recordSiblingSurface(bare, ids[0])
      }
      if (ids.length > 0 && item.depth === 0 && navQueue.length < 72 &&
          /"(?:items|data|results|rows|records|list|values)"\s*:\s*\[/.test(ex.body)) {
        // Collections without a documented detail template still imply `collection/:id` reads; probe
        // one concrete id (never a placeholder) so undocumented detail routes become visible.
        navQueue.push({ path: `${bare.replace(/\/+$/, '')}/${encodeURIComponent(ids[0]!)}`, depth: item.depth + 1 })
      }
      if (ids.length === 0 || item.depth >= 2) continue
      // Subresource templates (…/:id/view, …/:id/notes) imply the parent detail route; walk it too.
      const detailTemplates = new Set(navGetTemplates)
      for (const templatePath of navGetTemplates) {
        if (!templatePath.startsWith(`${baseTemplate}/:`)) continue
        const rest = templatePath.slice(baseTemplate.length + 1)
        const slash = rest.indexOf('/')
        if (slash > 0) detailTemplates.add(`${baseTemplate}/${rest.slice(0, slash)}`)
      }
      for (const candidateTemplate of detailTemplates) {
        if (navQueue.length >= 72) break
        if (!candidateTemplate.startsWith(`${baseTemplate}/`)) continue
        const placeholderHits = candidateTemplate.match(/(^|\/):[A-Za-z_][A-Za-z0-9_-]*/g) ?? []
        if (placeholderHits.length !== 1) continue
        for (const id of ids.slice(0, 2)) {
          navQueue.push({
            path: candidateTemplate.replace(/(^|\/):[A-Za-z_][A-Za-z0-9_-]*/, (_match, prefix: string) => `${prefix}${encodeURIComponent(id)}`),
            depth: item.depth + 1,
          })
        }
      }
    }

    // 2d-bis. Templated entry routes: probe with concrete ids harvested from their collection
    // listings (never with placeholder literals). This is what turns a route-map `…/:id` entry into a
    // confirmed live route; the remaining budget slice is reserved by the navigation cap above.
    let templateProbes = 0
    for (const template of [...new Set(discoveredTemplates)]) {
      if (templateProbes >= 8 || originHalted || originUsed >= perOriginCap || signal.aborted) break
      const templateMatch = /^(.*?)\/:[A-Za-z_][A-Za-z0-9_-]*(.*)$/.exec(template)
      if (!templateMatch) continue
      const [, base = '', rest = ''] = templateMatch
      const ids = idsByCollection.get(normalizeDiscoveryTemplate(base)) ?? []
      for (const id of ids.slice(0, 2)) {
        if (templateProbes >= 8 || originHalted || originUsed >= perOriginCap || signal.aborted) break
        templateProbes += 1
        await probeDiscovered(`${base}/${encodeURIComponent(id)}${rest}`)
      }
    }

    // 2d-ter. XML-accepting surface discovery: xml-ish routes frequently only reveal their element
    // schema in a parse-error response. Send a benign probe document and learn the expected element.
    const xmlish = /(?:xml|soap|wsdl|saml|rss|atom|svg|import|upload|feed|sitemap)/i
    if (!originHalted && !signal.aborted && grant.canRead(origin)) {
      const known = readPaged('xml_surface', rows =>
        rows.filter(e => xmlish.test(e.pathTemplate) && !/\{|\/:|\[/.test(e.pathTemplate)).length)
      const xmlCandidates = [...new Set(known.map(e => e.pathTemplate))]
        .filter(p => xmlish.test(p) && !/\{|\/:|\[/.test(p))
        .slice(0, 3)
      for (const xmlPath of xmlCandidates) {
        if (originUsed >= perOriginCap - 2) break
        const xmlEx = await safeGet(xmlPath, {
          method: 'POST',
          headers: { 'Content-Type': 'application/xml' },
          body: '<?xml version="1.0" encoding="UTF-8"?><guardian><probe>guardian-shape</probe></guardian>',
        })
        if (!xmlEx || xmlEx.status === 404 || xmlEx.status === 405 || xmlEx.status === 415 || xmlEx.status === 501) continue
        const xmlEp = recordEndpoint('POST', xmlPath, 'surface_probe')
        if (xmlEx.status >= 400) {
          const tags = extractXmlHintTags(xmlEx.body)
          const learned = tags[tags.length - 1]
          if (learned) {
            storage.upsertEndpointParam({
              runId,
              endpointId: xmlEp.id,
              name: learned,
              location: 'xml',
              isCsrf: CSRF_PARAM_RE.test(learned),
              isObjectId: OBJECT_ID_PARAM_RE.test(learned),
              source: 'phase0_xml',
            })
            dynamicParams.add(learned)
            paramsDiscovered += 1
          }
        }
      }
    }

    // 2d-ter. GraphQL argument discovery from live introspection so variable-level injection probes
    // can be formed for root fields that accept user arguments.
    if (!originHalted && !signal.aborted && grant.canRead(origin) && originUsed < perOriginCap - 1) {
      // Paged read: a GraphQL root can be recorded far past the default 500-row page, and the
      // introspection argument pass must still find it.
      const gqlEps = readPaged('graphql_args', rows => rows.filter(e => /graphql/i.test(e.pathTemplate)).length)
        .filter(e => /graphql/i.test(e.pathTemplate))
      if (gqlEps.length > 0) {
        const gqlPath = (gqlEps.find(e => e.method === 'POST') ?? gqlEps[0]).pathTemplate
        const introEx = await safeGet(gqlPath, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: '{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{kind name ofType{kind name}}}}}}}' }),
        })
        if (introEx && introEx.status < 400) {
          let schemaObj: Record<string, unknown> | undefined
          try {
            const parsed = JSON.parse(introEx.body) as { data?: { __schema?: Record<string, unknown> } }
            schemaObj = parsed.data?.__schema
          } catch { /* not JSON */ }
          if (schemaObj && Array.isArray((schemaObj as { types?: unknown[] }).types)) {
            const gqlEp = recordEndpoint('POST', gqlPath, 'graphql', { framework: 'graphql', riskScore: 85 })
            const schema = parseGraphqlIntrospection(schemaObj)
            const roots = [schema.queryType, schema.mutationType].filter((t): t is string => Boolean(t))
            const args = new Set<string>()
            for (const rootType of roots) {
              for (const field of schema.types[rootType] ?? []) {
                for (const arg of field.args) args.add(arg.name)
              }
            }
            for (const arg of [...args].slice(0, 24)) {
              if (!arg || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(arg)) continue
              storage.upsertEndpointParam({
                runId,
                endpointId: gqlEp.id,
                name: arg,
                location: 'graphql_var',
                isCsrf: CSRF_PARAM_RE.test(arg),
                isObjectId: OBJECT_ID_PARAM_RE.test(arg),
                source: 'graphql',
              })
              dynamicParams.add(arg)
              paramsDiscovered += 1
            }
          }
        }
      }
    }

    // 2d-ter. Multi-persona shell pass: every approved role persona gets its own root shell so
    // role-gated navigation (admin console) enters discovery instead of only persona[0]'s view.
    if (!originHalted && !signal.aborted && (params.personas?.length ?? 0) > 0 && originUsed < perOriginCap) {
      const handles = params.personas ?? []
      const personaCap = Math.min(handles.length, Math.max(1, Math.floor(perOriginCap * 0.12)))
      let personaFetches = 0
      for (const handle of handles) {
        if (personaFetches >= personaCap || originHalted || signal.aborted || originUsed >= perOriginCap) break
        if (!personaForOrigin(handle)) continue
        const ex = await safeGet('/', { persona: handle })
        if (!ex) continue
        personaFetches += 1
        tagVisibility('GET', '/', handle)
        if (ex.status >= 400) continue
        for (const t of mergeTechTags(techTagsFromResponse(ex.respHeaders, ex.body))) techFingerprint.add(t)
        const html = extractHtmlLinksAndScripts(ex.body, origin)
        for (const s of html.scripts) {
          queueJsChunk(s, '/')
          jsPageByScript.set(s, '/')
        }
        for (const asset of extractAssetReferences(ex.body)) {
          if (/\.json(?:$|[?#])/i.test(asset)) queueJsonDoc(asset)
          else queueJsChunk(asset, '/')
        }
        // Role-gated links are queued (soft-404 calibrated) rather than trusted blindly.
        for (const link of html.links.slice(0, 60)) {
          dynamicPaths.add(normalizeRouteTemplate(link))
          if (discoveredCandidatePaths.length < 40 && !discoveredCandidatePaths.includes(link)) {
            discoveredCandidatePaths.push(link)
          }
          if (!/\.json(?:\?|$)/i.test(link)) navSeeds.push({ path: link, depth: 0 })
        }
      }
    }

    // 2e. Optional browser SPA crawl when caller supplies ScopedBrowser and budget remains
    const remainingForCrawl = perOriginCap - originUsed
    if (params.browser && !originHalted && !signal.aborted && remainingForCrawl >= 2 && grant.canRead(origin)) {
      let browserExchanges = 0
      const crawlRes = await crawlStateGraph({
        storage,
        runId,
        scopeRevision,
        origin,
        personas: params.personas,
        maxPages: Math.min(10, Math.max(1, Math.floor(remainingForCrawl / 2))),
        maxDepth: 3,
        budgetRemaining: remainingForCrawl,
        browser: params.browser,
        grant,
        signal,
        assignmentId: params.assignmentId,
        ...(params.assetOrigins ? { assetOrigins: params.assetOrigins } : {}),
        ...(params.interactiveTraversal !== undefined ? { interactiveTraversal: params.interactiveTraversal } : {}),
        ...(params.readOnlyMode !== undefined ? { readOnlyMode: params.readOnlyMode } : {}),
        onExchange: ex => {
          browserExchanges += 1
          originUsed += 1
          requestsUsed += 1
          noteDiscoveryResponse(ex)
          return params.onExchange?.(ex)
        },
      })
      endpointsDiscovered += crawlRes.endpointsDiscovered
      paramsDiscovered += crawlRes.paramsDiscovered
      routeMapEndpoints += crawlRes.routeMapEndpoints ?? 0
      for (const [key, personas] of Object.entries(crawlRes.visibleToPersonas ?? {})) {
        const set = phase0Visibility.get(key) ?? new Set<string>()
        for (const handle of personas) set.add(handle)
        phase0Visibility.set(key, set)
      }
      // Browser traffic is accounted per accepted exchange above; page visits that produced no
      // recorded exchange still consumed a broker call.
      const unaccountedPages = Math.max(0, crawlRes.pagesVisited - browserExchanges)
      originUsed += unaccountedPages
      requestsUsed += unaccountedPages
    }
    // 2f. Infer producer-consumer api_dependencies edges from discovered collection -> item endpoints
    try {
      const originEndpoints = readPaged('api_dependencies')
      const byBase = new Map<string, typeof originEndpoints>()
      for (const ep of originEndpoints) {
        const clean = ep.pathTemplate.replace(/\/+$/, '') || '/'
        const parts = clean.split('/').filter(Boolean)
        if (parts.length === 0) continue
        const last = parts[parts.length - 1]
        const paramMatch = /^(?::([a-zA-Z0-9_-]+)|\{([a-zA-Z0-9_-]+)\})$/.exec(last)
        if (!paramMatch) {
          const list = byBase.get(clean) ?? []
          list.push(ep)
          byBase.set(clean, list)
        }
      }
      for (const ep of originEndpoints) {
        const clean = ep.pathTemplate.replace(/\/+$/, '') || '/'
        const parts = clean.split('/').filter(Boolean)
        if (parts.length < 2) continue
        // Look for any parameter segment in the path and check if its prefix is a known collection producer
        for (let idx = parts.length - 1; idx >= 1; idx -= 1) {
          const paramMatch = /^(?::([a-zA-Z0-9_-]+)|\{([a-zA-Z0-9_-]+)\})$/.exec(parts[idx])
          if (!paramMatch) continue
          const resourceKey = paramMatch[1] ?? paramMatch[2] ?? 'id'
          const prefix = '/' + parts.slice(0, idx).join('/')
          const producers = byBase.get(prefix)
          if (!producers || producers.length === 0) continue
          const producer = producers.find(p => p.method === 'POST') ?? producers.find(p => p.method === 'GET') ?? producers[0]
          if (!producer || producer.id === ep.id) continue
          const sampleHash = `sha256:${createHash('sha256').update(`${origin}:${prefix}:${resourceKey}`).digest('hex').slice(0, 16)}`
          storage.recordApiDependency({
            runId,
            producerEndpointId: producer.id,
            consumerEndpointId: ep.id,
            resourceKey,
            sampleResourceIdHash: sampleHash,
            personaHandle: params.personas?.[0] ?? null,
          })
          break
        }
      }
    } catch { /* best-effort static edge inference */ }

    // 2f-bis. Parameter discovery from crawl evidence. A held-out surface can randomize the search
    // parameter name so it never appears verbatim in a link or a declaration. Recon attaches the
    // names its own evidence supports (response field echo, same-origin redirect query, bundle/AST
    // literal, route vocabulary) with an explicit provenance tag, then runs a bounded paired
    // control-vs-probe sensitivity check on inferred names. A name the target demonstrably reads is
    // kept as `inferred_*:sensitive` (never `observed`, never a confirmation); a dead literal is
    // dropped so it cannot inflate probe queues.
    const PARAM_DISCOVERY_ACTIVE_CAP = 6
    const PARAM_DISCOVERY_RISK_BONUS = 15
    let activeParamProbes = 0
    for (const ep of readPaged('param_discovery', rows => rows.filter(row =>
      row.method.toUpperCase() === 'GET' && !/[:{}[\]]/.test(row.pathTemplate.split('?')[0] ?? '/')).length)) {
      if (originHalted || signal.aborted) break
      if (ep.method.toUpperCase() !== 'GET') continue
      const bare = ep.pathTemplate.split('?')[0] || '/'
      if (!bare.startsWith('/') || bare === '/' || /[:{}[\]]/.test(bare) || STATIC_ASSET_RE.test(bare)) continue
      const evidence = paramEvidence.get(ep.pathTemplate) ?? paramEvidence.get(normalizeDiscoveryTemplate(bare))
      const existingParams = storage.listEndpointParams(runId, ep.id)
      const existing = new Set(existingParams.map(param => `${param.name}|${param.location}`))
      const candidates = orderDiscoveredParams([
        ...(evidence ? deriveResponseFieldParams(bare, evidence.fields, 'GET') : []),
        ...(evidence ? paramCandidatesFromRedirect(evidence.redirectQuery) : []),
      ]).filter(candidate => !existing.has(`${candidate.name}|${candidate.location}`))
      const inferredExisting = existingParams.filter(param =>
        paramProvenanceOfSource(param.source) !== 'observed' && param.location === 'query')
      if (candidates.length === 0 && inferredExisting.length === 0) continue

      // Sensitivity check: one bounded paired differential decides which inferred names the target
      // actually reads. Limited to a handful of routes per origin and never a mutating request.
      const probeNames = [...new Set([
        ...candidates.filter(candidate => candidate.location === 'query').map(candidate => candidate.name),
        ...inferredExisting.map(param => param.name),
      ])].slice(0, 6)
      let checked = false
      let verified = new Set<string>()
      if (probeNames.length > 0 && activeParamProbes < PARAM_DISCOVERY_ACTIVE_CAP &&
          originUsed + 6 < perOriginCap && grant.canRead(origin)) {
        activeParamProbes += 1
        checked = true
        try {
          const discovery = await probeSurface({
            origin,
            mode: 'params',
            basePath: bare,
            params: probeNames,
            paramLocation: 'query',
            methods: ['GET'],
            ...(discoveryPersona ? { persona: discoveryPersona } : {}),
            maxRequests: Math.max(4, Math.min(12, perOriginCap - originUsed - 1)),
            onExchange: ex => {
              originUsed += 1
              requestsUsed += 1
              noteDiscoveryResponse(ex)
              return params.onExchange?.(ex)
            },
          }, broker, grant, signal)
          verified = new Set(discovery.anomalies
            .filter(anomaly => anomaly.kind === 'param' && typeof anomaly.param === 'string')
            .map(anomaly => String(anomaly.param)))
        } catch { /* differential discovery is best-effort */ }
      }
      if (checked) {
        paramSensitivity.checked += probeNames.length
        paramSensitivity.passed += probeNames.filter(name => verified.has(name)).length
        paramSensitivity.dropped += probeNames.filter(name => !verified.has(name)).length
      }

      let attached = 0
      for (const candidate of candidates) {
        if (checked && !verified.has(candidate.name)) continue // dead literal: do not queue it
        const provenance = paramProvenanceOfSource(candidate.source)
        const source = verified.has(candidate.name) && checked
          ? `${provenance}:sensitive`
          : candidate.source
        storage.upsertEndpointParam({
          runId,
          endpointId: ep.id,
          name: candidate.name,
          location: candidate.location,
          inferredType: candidate.location === 'query' ? 'string' : null,
          isCsrf: CSRF_PARAM_RE.test(candidate.name),
          isObjectId: OBJECT_ID_PARAM_RE.test(candidate.name),
          source,
        })
        dynamicParams.add(candidate.name)
        paramsDiscovered += 1
        attached += 1
      }
      for (const param of inferredExisting) {
        if (checked && !verified.has(param.name)) {
          // Dead inferred literal from the crawl: remove it rather than inflate the probe queue.
          storage.client.prepare(
            'DELETE FROM endpoint_params WHERE run_id = ? AND endpoint_id = ? AND name = ? AND location = ?',
          ).run(runId, ep.id, param.name, param.location)
          continue
        }
        if (checked && verified.has(param.name) && !paramSourceSensitivityPassed(param.source)) {
          const provenance = paramProvenanceOfSource(param.source)
          storage.upsertEndpointParam({
            runId,
            endpointId: ep.id,
            name: param.name,
            location: param.location,
            inferredType: param.inferredType,
            isCsrf: param.isCsrf,
            isObjectId: param.isObjectId,
            source: `${provenance}:sensitive`,
          })
          attached += 1
        }
      }
      const hasSensitive = checked
        ? verified.size > 0
        : existingParams.some(param => paramSourceSensitivityPassed(param.source))
      if (hasSensitive) {
        // A sensitivity-checked reading parameter is the strongest injectable-surface signal recon
        // can produce; rank the route accordingly (upsert keeps the maximum risk score). This is
        // still only a hypothesis seed: the floor's differential and verifyReceipt must confirm.
        storage.upsertEndpoint({
          runId,
          scopeRevision,
          origin,
          method: ep.method,
          pathTemplate: ep.pathTemplate,
          source: ep.source,
          riskScore: Math.min(100, ep.riskScore + PARAM_DISCOVERY_RISK_BONUS),
        })
      }
    }

    // 2g. Persona-union visibility: persist `visibleToPersonas` on discovered endpoints and surface
    // admin/privileged routes immediately instead of waiting for a later probe pass.
    // One paged snapshot instead of a full-store read per visibility key.
    const endpointsByRouteKey = new Map<string, EndpointRow>()
    for (const ep of readPaged('persona_visibility')) {
      const routeKey = `${ep.method.toUpperCase()} ${ep.pathTemplate}`
      if (!endpointsByRouteKey.has(routeKey)) endpointsByRouteKey.set(routeKey, ep)
    }
    for (const [key, set] of phase0Visibility) {
      const spaceAt = key.indexOf(' ')
      const method = key.slice(0, spaceAt)
      const pathTemplate = key.slice(spaceAt + 1)
      const personas = [...set].sort()
      const merged = visibleToPersonasUnion.get(key) ?? new Set<string>()
      for (const handle of personas) merged.add(handle)
      visibleToPersonasUnion.set(key, merged)
      const rolePersonas = personas.filter(handle => handle !== 'anonymous')
      const reasons: string[] = []
      if (isPrivilegedPathTemplate(pathTemplate)) reasons.push('privileged_path')
      if (rolePersonas.length > 0 && !personas.includes('anonymous') && personas.length > 1) reasons.push('role_restricted')
      if (reasons.length === 0) continue
      const entryKey = `${method} ${pathTemplate}`
      if (!privilegedSurface.some(entry => `${entry.method} ${entry.pathTemplate}` === entryKey)) {
        privilegedSurface.push({ method, pathTemplate, personas, reason: reasons.join('+') })
      }
      try {
        const existing = endpointsByRouteKey.get(entryKey)
        if (existing) {
          storage.upsertEndpoint({
            runId,
            scopeRevision,
            origin,
            method,
            pathTemplate,
            source: existing.source,
            authRequirement: rolePersonas.map(handle => `persona:${handle}`).join(',') || null,
          })
        }
      } catch { /* visibility tagging is best-effort */ }
    }
  }

  // Paged-read accounting: every phase reads to completion, so `truncated` is always false. A
  // non-zero `used` shortfall is a planning filter, never a dropped page.
  for (const metric of readPagedMetrics) {
    storage.event(runId, 'phase0.read_paged',
      `Phase-0 ${metric.phase} read ${metric.considered} endpoint row(s) across ${metric.pages} page(s); ${metric.used} used.`,
      metric)
  }

  const visibleToPersonas: Record<string, string[]> = {}
  for (const [key, set] of visibleToPersonasUnion) visibleToPersonas[key] = [...set].sort()
  if (privilegedSurface.length > 0) {
    storage.event(runId, 'phase0.privileged_surface',
      `Surfaced ${privilegedSurface.length} privileged/role-restricted route(s) from the persona union and mounted-source guard chains.`,
      { routes: privilegedSurface.slice(0, 20) })
  }

  // Per-endpoint param-discovery metrics: one event, deterministic ordering, no raw bodies.
  const paramDiscovery = summarizeParamDiscovery(storage, runId)
  if (paramDiscovery.endpoints.length > 0) {
    const provenance = paramDiscovery.totals.byProvenance
    storage.event(runId, 'phase0.param_discovery',
      `Parameter discovery: ${provenance.observed} observed / ${provenance.inferred_bundle} inferred_bundle / ${provenance.inferred_html} inferred_html / ${provenance.inferred_ast} inferred_ast across ${paramDiscovery.endpoints.length} endpoint(s); sensitivity ${paramSensitivity.checked} checked, ${paramSensitivity.passed} passed, ${paramSensitivity.dropped} dead dropped.`,
      { endpoints: paramDiscovery.endpoints, totals: paramDiscovery.totals, sensitivity: { ...paramSensitivity } })
  }

  storage.event(runId, 'phase0.discovery', 'Phase-0 discovery counts.', {
    requestsUsed,
    perOriginCap,
    endpointsDiscovered,
    paramsDiscovered,
    routeMapEndpoints,
    jsRouterRoutes,
    navigationRequests,
    navigationEndpoints,
    authRequests,
    soft404Rejected,
    stoppedReason,
    readPaged: readPagedMetrics,
  })
  storage.updateRunPhase0Completed(runId, Date.now())

  return {
    requestsUsed,
    perOriginCap,
    endpointsDiscovered,
    paramsDiscovered,
    frameworksDetected: [...frameworksDetected],
    techFingerprint: [...techFingerprint],
    ...(paramDiscovery.endpoints.length > 0 ? { paramDiscovery } : {}),
    dynamicWordlist: {
      paths: [...dynamicPaths].slice(0, 120),
      params: [...dynamicParams].slice(0, 80),
    },
    stoppedReason,
    routeMapEndpoints,
    jsRouterRoutes,
    navigationRequests,
    navigationEndpoints,
    authRequests,
    soft404Rejected,
    ...(declaredSurface ? { declaredSurface } : {}),
    siblingEndpoints,
    methodHints,
    visibleToPersonas,
    ...(repoStaticExtraction ? { repoStaticExtraction } : {}),
    ...(codeToRuntimeHypotheses && codeToRuntimeHypotheses.length ? { codeToRuntimeHypotheses } : {}),
    codeSlices,
    ...(probePlan ? { probePlan } : {}),
    ...(siblingDerivationSuppressed ? { siblingDerivationSuppressed } : {}),
    ...(privilegedSurface.length > 0 ? { privilegedEndpoints: privilegedSurface } : {}),
  }
}

/**
 * Stateful multi-persona SPA explorer (`crawl_state_graph`, SPEC-v4 §4.3A).
 * Crawls anonymous + approved personas through 100%-brokered ScopedBrowser,
 * enforcing maxPages, maxDepth, budgetRemaining, and strict origin scope,
 * and populates SQLite `endpoints` + `endpoint_params` (including CSRF flags,
 * XHR/fetch/GraphQL/Next-Action traffic, postMessage listeners, and key-only storage inventory).
 */
export async function crawlStateGraph(params: CrawlStateGraphParams): Promise<CrawlStateGraphResult> {
  const { storage, runId, scopeRevision, browser, grant, signal } = params
  const normalizedOrigin = new URL(params.origin).origin
  const requestedMaxPages = Math.max(1, Math.min(params.maxPages ?? 25, 60))
  const effectiveMaxPages = params.budgetRemaining !== undefined
    ? Math.max(0, Math.min(requestedMaxPages, Math.floor(params.budgetRemaining)))
    : requestedMaxPages
  const maxDepth = Math.max(0, Math.min(params.maxDepth ?? 3, 4))

  const personaList: Array<string | undefined> = [undefined]
  for (const p of params.personas ?? []) {
    if (p && !personaList.includes(p)) personaList.push(p)
  }
  const authenticatedPersonas = personaList.filter((p): p is string => Boolean(p))
  // Reserve most of the page budget for authenticated personas so anonymous pagination cannot
  // starve the views that render authenticated XHR traffic.
  const anonymousPageCap = authenticatedPersonas.length > 0
    ? Math.max(1, Math.floor(effectiveMaxPages * 0.4))
    : effectiveMaxPages

  let pagesVisited = 0
  let endpointsDiscovered = 0
  let paramsDiscovered = 0
  let routeMapEndpoints = 0
  const crawlDynamicPaths = new Set<string>()
  const crawlDynamicParams = new Set<string>()
  const idsByCollection = new Map<string, string[]>()
  const parsedXhrDocuments = new Set<string>()
  const crawlTemplates = new Set<string>()
  const storageKeySet = new Set<string>()
  let hasPostMessageListener = false
  const personasCrawled: string[] = []
  let stoppedReason: string | undefined
  const visibility = new Map<string, Set<string>>()
  const privilegedByKey = new Map<string, { method: string; pathTemplate: string; personas: string[]; reason: string }>()

  // Intercepted-query, Next-Action and persona-union lookups must see the whole stored surface.
  // `storage.listEndpoints(runId, { origin })` pages at the store default (500 rows) and silently
  // truncates large apps, so those lookups go through one paged index in the store's stable
  // (risk, coverage, id) order and report a `phase0.crawl_paged` metric.
  const crawlPagedMetric: PagedReadMetric = {
    phase: 'state_graph',
    origin: normalizedOrigin,
    considered: 0,
    used: 0,
    truncated: false,
    reads: 0,
    pages: 0,
  }
  const crawlRouteKey = (method: string, pathTemplate: string): string =>
    `${method.trim().toUpperCase()} ${pathTemplate.trim()}`
  let crawlSurfaceIndex: Map<string, EndpointRow> | null = null
  let crawlPagedKeys = new Set<string>()
  const crawlResolvedKeys = new Set<string>()
  /** Load the full-origin index once; later upserts are folded in by `noteCrawlEndpoint`. */
  const crawlSurface = (): Map<string, EndpointRow> => {
    if (crawlSurfaceIndex) return crawlSurfaceIndex
    const rows = listEndpointsPaged(storage, runId, { origin: normalizedOrigin })
    const index = new Map<string, EndpointRow>()
    const pagedKeys = new Set<string>()
    // Paged order is deterministic (risk desc, coverage asc, id asc); first row wins a duplicate
    // route key so the index keeps the store's priority order and never double-counts a route.
    for (const row of rows) {
      const key = crawlRouteKey(row.method, row.pathTemplate)
      if (!index.has(key)) index.set(key, row)
      pagedKeys.add(key)
    }
    crawlSurfaceIndex = index
    crawlPagedKeys = pagedKeys
    crawlPagedMetric.considered += rows.length
    crawlPagedMetric.reads += 1
    crawlPagedMetric.pages += Math.max(1, Math.ceil(rows.length / ENDPOINT_PAGE_SIZE))
    return index
  }
  /** Keep a freshly upserted row visible to later lookups without re-reading the whole surface. */
  const noteCrawlEndpoint = (row: EndpointRow): EndpointRow => {
    if (crawlSurfaceIndex) crawlSurfaceIndex.set(crawlRouteKey(row.method, row.pathTemplate), row)
    return row
  }
  const findCrawlEndpoint = (method: string, pathTemplate: string): EndpointRow | undefined => {
    const key = crawlRouteKey(method, pathTemplate)
    const hit = crawlSurface().get(key)
    if (hit && crawlPagedKeys.has(key)) crawlResolvedKeys.add(key)
    return hit
  }

  const tagVisibility = (method: string, rawPath: string, who: string): void => {
    const bare = rawPath.split('?')[0] || '/'
    const tmpl = normalizeDiscoveryTemplate(bare)
    const key = `${method.toUpperCase()} ${tmpl}`
    const set = visibility.get(key) ?? new Set<string>()
    set.add(who)
    visibility.set(key, set)
  }

  const recordFormAndParams = (
    actionRaw: string,
    methodRaw: string,
    inputNames: readonly string[],
    who: string,
  ) => {
    const cleanAction = sanitizePathCandidate(actionRaw || '/', normalizedOrigin)
    if (!cleanAction) return
    const method = (methodRaw || 'GET').toUpperCase()
    const pathTemplate = normalizeRouteTemplate(cleanAction)
    const ep = noteCrawlEndpoint(storage.upsertEndpoint({
      runId,
      scopeRevision,
      origin: normalizedOrigin,
      method,
      pathTemplate,
      source: 'spa_crawl',
      riskScore: scoreEndpointRisk(method, pathTemplate),
    }))
    tagVisibility(method, pathTemplate, who)
    endpointsDiscovered += 1
    for (const name of inputNames) {
      if (!name) continue
      storage.upsertEndpointParam({
        runId,
        endpointId: ep.id,
        name,
        location: method === 'GET' ? 'query' : 'form',
        isCsrf: CSRF_PARAM_RE.test(name),
        isObjectId: OBJECT_ID_PARAM_RE.test(name),
        source: 'spa_crawl',
      })
      paramsDiscovered += 1
    }
  }

  for (let personaIndex = 0; personaIndex < personaList.length; personaIndex += 1) {
    const persona = personaList[personaIndex]
    if (signal.aborted) {
      stoppedReason = 'aborted'
      break
    }
    if (effectiveMaxPages === 0) break
    if (!grant.canRead(normalizedOrigin)) {
      stoppedReason = 'scope_revoked'
      break
    }

    const queue: Array<{ pathAndQuery: string; depth: number }> = [{ pathAndQuery: '/', depth: 0 }]
    const visitedForPersona = new Set<string>()
    const templateVisits = new Map<string, number>()
    let personaPages = 0
    // Fair per-persona share: no single persona may consume the whole page budget, otherwise the
    // admin/privileged pass never runs and the persona union collapses to persona[0].
    const remainingPages = params.budgetRemaining !== undefined
      ? Math.max(1, effectiveMaxPages - pagesVisited)
      : requestedMaxPages
    const remainingSlots = Math.max(1, personaList.length - personaIndex)
    const fairShare = Math.max(1, Math.floor(remainingPages / remainingSlots))
    const personaPageCap = persona
      ? Math.max(1, Math.min(fairShare, Math.max(1, effectiveMaxPages - pagesVisited)))
      : Math.max(1, Math.min(anonymousPageCap, fairShare, Math.max(1, effectiveMaxPages - pagesVisited)))

    if (params.budgetRemaining !== undefined && pagesVisited >= effectiveMaxPages) break

    let personaTouched = false
    while (queue.length > 0 && personaPages < personaPageCap) {
      if (params.budgetRemaining !== undefined && pagesVisited >= effectiveMaxPages) break
      if (signal.aborted) {
        stoppedReason = 'aborted'
        break
      }
      if (!grant.canRead(normalizedOrigin)) {
        stoppedReason = 'scope_revoked'
        break
      }
      const next = queue.shift()!
      const dedupeKey = next.pathAndQuery
      if (visitedForPersona.has(dedupeKey)) continue
      visitedForPersona.add(dedupeKey)
      // Cap repeated instances of one normalized route template (pagination/item loops).
      const routeTemplateKey = normalizeRouteTemplate(next.pathAndQuery)
      const templateCount = templateVisits.get(routeTemplateKey) ?? 0
      if (templateCount >= 2) continue
      templateVisits.set(routeTemplateKey, templateCount + 1)

      const who = persona ?? 'anonymous'
      let visit
      try {
        const visitRequest = {
          origin: normalizedOrigin,
          pathAndQuery: next.pathAndQuery,
          persona,
          runId,
          assignmentId: params.assignmentId,
          waitAfterLoadMs: 120,
          interactiveTraversal: params.interactiveTraversal !== false,
          readOnlyMode: params.readOnlyMode !== false,
          ...(params.assetOrigins ? { assetOrigins: params.assetOrigins } : {}),
          ...(params.onExchange ? { onExchange: params.onExchange } : {}),
        }
        const pooledBrowser = browser as unknown as { visitPages?: ScopedBrowser['visitPages'] }
        if (typeof pooledBrowser.visitPages === 'function') {
          const visits = await pooledBrowser.visitPages([visitRequest], grant, signal)
          visit = visits[0]
        } else {
          visit = await browser.visitPage(visitRequest, grant, signal)
        }
        if (!visit) {
          stoppedReason = 'browser_unavailable'
          break
        }
      } catch (err) {
        if (err instanceof BrokerCircuitOpen) {
          stoppedReason = 'circuit_open'
          break
        }
        if (err instanceof BrokerDenied) {
          stoppedReason = 'denied'
          break
        }
        continue
      }

      personaTouched = true
      personaPages += 1
      pagesVisited += 1

      // Harvest object IDs from every intercepted XHR/fetch/page exchange for this persona
      // (including anonymous crawl passes) so cross-persona BOLA queues have concrete samples.
      for (const ex of visit.exchanges) {
        if (ex.origin !== normalizedOrigin) continue
        storage.trackExchangeResources({
          runId,
          scopeRevision,
          exchange: ex,
          source: 'spa_crawl',
        })
      }
      if (visit.domSnippet) {
        storage.trackExchangeResources({
          runId,
          scopeRevision,
          exchange: {
            origin: normalizedOrigin,
            method: 'GET',
            pathAndQuery: next.pathAndQuery,
            personaHandle: persona ?? null,
            status: 200,
            mediaType: 'text/html',
            body: visit.domSnippet,
          },
          source: 'spa_crawl',
        })
      }

      // Record visited route
      const routeTemplate = normalizeRouteTemplate(next.pathAndQuery)
      const routeEp = noteCrawlEndpoint(storage.upsertEndpoint({
        runId,
        scopeRevision,
        origin: normalizedOrigin,
        method: 'GET',
        pathTemplate: routeTemplate,
        source: 'spa_crawl',
        authRequirement: persona ? `persona:${persona}` : null,
        riskScore: scoreEndpointRisk('GET', routeTemplate),
      }))
      tagVisibility('GET', routeTemplate, who)
      endpointsDiscovered += 1

      // Record query params from URL
      try {
        const u = new URL(next.pathAndQuery, normalizedOrigin)
        for (const qk of u.searchParams.keys()) {
          storage.upsertEndpointParam({
            runId,
            endpointId: routeEp.id,
            name: qk,
            location: 'query',
            isCsrf: CSRF_PARAM_RE.test(qk),
            isObjectId: OBJECT_ID_PARAM_RE.test(qk),
            source: 'spa_crawl',
          })
          paramsDiscovered += 1
        }
      } catch { /* ignore */ }

      // Record storage key names ONLY (never values!)
      for (const key of [...visit.localStorageKeys, ...visit.sessionStorageKeys]) {
        if (key) storageKeySet.add(key)
      }
      if (visit.postMessageListeners.count > 0 || visit.postMessageListeners.hasOnMessage) {
        hasPostMessageListener = true
      }

      // Record HTML forms & inputs (including CSRF fields)
      for (const form of visit.forms) {
        recordFormAndParams(form.action, form.method, form.inputNames, who)
      }
      // Also parse raw domSnippet forms in case hidden inputs weren't captured
      if (visit.domSnippet && /<form\b/i.test(visit.domSnippet)) {
        const parsedHtml = extractHtmlLinksAndScripts(visit.domSnippet, normalizedOrigin)
        for (const f of parsedHtml.forms) {
          recordFormAndParams(f.action, f.method, f.inputs, who)
        }
      }

      // Record intercepted XHR / fetch / WebSocket / GraphQL / Next-Action calls, including query
      // parameters and (when the browser record exposes it) request-body shape.
      const intercepted = [...visit.xhrRequests, ...(visit.allRequests ?? [])]
      const pageDocs: Array<{ entries: RouteMapEntry[]; ids: string[]; links: string[]; detailPaths: string[] }> = []
      for (const req of intercepted) {
        if (req.origin !== normalizedOrigin) continue
        if (!['xhr', 'fetch', 'websocket'].includes(req.resourceType) && !/\/api\/|\/graphql|\/trpc/i.test(req.url)) {
          continue
        }
        const clean = sanitizePathCandidate(req.url, normalizedOrigin)
        if (!clean || STATIC_ASSET_RE.test(clean)) continue
        // Same-origin JSON bodies captured by the scoped browser may be route maps/config tables or
        // navigation listings: expand them structurally instead of only recording the call itself.
        const bodyPreview = (req as { bodyPreview?: string }).bodyPreview
        if (bodyPreview) {
          const docKey = `${clean.split('?')[0]}|${bodyPreview.length}|${bodyPreview.slice(0, 48)}`
          if (!parsedXhrDocuments.has(docKey) &&
              (/json|yaml/i.test(req.mediaType ?? '') || /^\s*[{[]/.test(bodyPreview.slice(0, 64)))) {
            parsedXhrDocuments.add(docKey)
            const doc = parseJsonOrYaml(bodyPreview)
            if (doc && typeof doc === 'object') {
              const expanded = parseRouteMapDoc(
                bodyPreview, normalizedOrigin, storage, runId, scopeRevision, crawlDynamicPaths, crawlDynamicParams,
              )
              endpointsDiscovered += expanded.endpoints
              paramsDiscovered += expanded.params
              routeMapEndpoints += expanded.endpoints
              const ids = extractJsonRecordIds(bodyPreview)
              const entries = harvestRouteMapDocument(doc).slice(0, 120)
              const isCollection = /"(?:items|data|results|rows|records|list|values)"\s*:\s*\[/.test(bodyPreview)
              pageDocs.push({
                entries,
                ids,
                links: extractJsonLinkTargets(bodyPreview, normalizedOrigin),
                detailPaths: isCollection && ids[0]
                  ? [`${(clean.split('?')[0] || '/').replace(/\/+$/, '')}/${encodeURIComponent(ids[0])}`]
                  : [],
              })
              for (const entry of entries) {
                if (entry.method !== 'GET' && entry.method !== 'HEAD') continue
                const tmpl = normalizeDiscoveryTemplate(entry.path)
                if (/:[A-Za-z_][A-Za-z0-9_-]*/.test(tmpl)) crawlTemplates.add(tmpl)
              }
              if (ids.length > 0) {
                idsByCollection.set(normalizeDiscoveryTemplate(clean.split('?')[0] || '/'), ids)
              }
            }
          }
        }
        const record = req as { body?: unknown; postData?: unknown }
        const rawBody = typeof record.body === 'string' ? record.body : typeof record.postData === 'string' ? record.postData : null
        const shape = inferXhrRequestShape({ url: req.url, method: req.method, body: rawBody })
        if (!shape) continue
        const tmpl = normalizeRouteTemplate(shape.path)
        const src: EndpointSource = /graphql|trpc/i.test(tmpl) ? 'graphql' : 'spa_crawl'
        const ep = noteCrawlEndpoint(storage.upsertEndpoint({
          runId,
          scopeRevision,
          origin: normalizedOrigin,
          method: shape.method,
          pathTemplate: tmpl,
          source: src,
          authRequirement: persona ? `persona:${persona}` : null,
          riskScore: scoreEndpointRisk(shape.method, tmpl),
        }))
        tagVisibility(shape.method, tmpl, who)
        endpointsDiscovered += 1
        for (const p of shape.params) {
          storage.upsertEndpointParam({
            runId,
            endpointId: ep.id,
            name: p.name,
            location: p.location,
            isCsrf: CSRF_PARAM_RE.test(p.name),
            isObjectId: OBJECT_ID_PARAM_RE.test(p.name),
            source: 'spa_crawl',
          })
          paramsDiscovered += 1
        }
      }
      // Broker exchanges expose the concrete query string of every intercepted call even when the
      // browser record only carries the URL; keep those parameter names too.
      for (const ex of visit.exchanges) {
        if (ex.origin !== normalizedOrigin) continue
        const tmpl = normalizeRouteTemplate(ex.pathAndQuery)
        const known = findCrawlEndpoint(ex.method, tmpl)
        if (known) {
          const shape = inferXhrRequestShape({ url: ex.pathAndQuery, method: ex.method })
          for (const p of shape?.params ?? []) {
            if (p.location !== 'query') continue
            storage.upsertEndpointParam({
              runId,
              endpointId: known.id,
              name: p.name,
              location: 'query',
              isCsrf: CSRF_PARAM_RE.test(p.name),
              isObjectId: OBJECT_ID_PARAM_RE.test(p.name),
              source: 'spa_crawl',
            })
            paramsDiscovered += 1
          }
        }
        const nextAction = ex.reqHeaders['next-action']
        if (nextAction) {
          noteCrawlEndpoint(storage.upsertEndpoint({
            runId,
            scopeRevision,
            origin: normalizedOrigin,
            method: ex.method.toUpperCase(),
            pathTemplate: tmpl,
            source: 'spa_crawl',
            framework: 'nextjs',
            sinkKinds: ['server_action'],
            riskScore: 88,
          }))
          endpointsDiscovered += 1
          const actionEp = findCrawlEndpoint(ex.method, tmpl)
          if (actionEp) {
            storage.upsertEndpointParam({
              runId,
              endpointId: actionEp.id,
              name: 'Next-Action',
              location: 'header',
              isCsrf: false,
              isObjectId: false,
              source: 'spa_crawl',
            })
          }
        }
      }

      // Enqueue same-origin links strictly within maxDepth
      if (next.depth < maxDepth) {
        const enqueuePath = (rawPath: string) => {
          const clean = sanitizePathCandidate(rawPath, normalizedOrigin)
          if (!clean || STATIC_ASSET_RE.test(clean)) return
          if (!visitedForPersona.has(clean)) queue.push({ pathAndQuery: clean, depth: next.depth + 1 })
        }
        for (const href of visit.links) enqueuePath(href)
        // JSON navigation/detail responses: follow HATEOAS links and walk collection ids into the
        // templated detail routes the same documents advertise.
        for (const doc of pageDocs) {
          for (const link of doc.links.slice(0, 8)) enqueuePath(link)
          for (const detailPath of doc.detailPaths) enqueuePath(detailPath)
          for (const entry of doc.entries) {
            if (entry.method !== 'GET' && entry.method !== 'HEAD') continue
            const tmpl = normalizeDiscoveryTemplate(entry.path)
            if (!/:|\{/.test(tmpl)) { enqueuePath(entry.path); continue }
          }
        }
        // Templates learned on an earlier page become probeable once a listing supplied record ids.
        for (const tmpl of crawlTemplates) {
          const templateMatch = /^(.*?)\/:[A-Za-z_][A-Za-z0-9_-]*(.*)$/.exec(tmpl)
          if (!templateMatch) continue
          const [, base = '', rest = ''] = templateMatch
          for (const id of (idsByCollection.get(normalizeDiscoveryTemplate(base)) ?? []).slice(0, 2)) {
            enqueuePath(`${base}/${encodeURIComponent(id)}${rest}`)
          }
        }
      }
    }

    if (personaTouched) personasCrawled.push(persona ?? 'anonymous')
    if (stoppedReason === 'circuit_open' || stoppedReason === 'scope_revoked' || stoppedReason === 'aborted') {
      break
    }
  }

  const visibleToPersonas: Record<string, string[]> = {}
  for (const [key, set] of visibility) {
    const spaceAt = key.indexOf(' ')
    const method = key.slice(0, spaceAt)
    const pathTemplate = key.slice(spaceAt + 1)
    const personas = [...set].sort()
    visibleToPersonas[key] = personas
    const rolePersonas = personas.filter(handle => handle !== 'anonymous')
    const reasons: string[] = []
    if (isPrivilegedPathTemplate(pathTemplate)) reasons.push('privileged_path')
    if (rolePersonas.length > 0 && !personas.includes('anonymous')) reasons.push('role_restricted')
    if (reasons.length === 0) continue
    privilegedByKey.set(key, { method, pathTemplate, personas, reason: reasons.join('+') })
    try {
      const existing = findCrawlEndpoint(method, pathTemplate)
      if (existing) {
        noteCrawlEndpoint(storage.upsertEndpoint({
          runId,
          scopeRevision,
          origin: normalizedOrigin,
          method,
          pathTemplate,
          source: existing.source,
          authRequirement: rolePersonas.map(handle => `persona:${handle}`).join(',') || null,
          riskScore: isPrivilegedPathTemplate(pathTemplate) ? Math.max(existing.riskScore, 85) : existing.riskScore,
        }))
      }
    } catch { /* visibility tagging is best-effort */ }
  }
  const privilegedEndpoints = [...privilegedByKey.values()]
  if (privilegedEndpoints.length > 0) {
    storage.event(runId, 'phase0.privileged_surface',
      `Persona union surfaced ${privilegedEndpoints.length} privileged/role-restricted route(s).`,
      { origin: normalizedOrigin, routes: privilegedEndpoints.slice(0, 20) })
  }
  // Crawl-read accounting: `considered` is every stored row the index paged through, `used` is the
  // distinct route keys a lookup resolved from it, and `truncated` is always false because the read
  // pages until a short page proves completeness. Routes inserted during the crawl are folded into
  // the index without re-paging, so they never inflate `used` beyond what the paged read supplied.
  crawlPagedMetric.used = crawlResolvedKeys.size
  if (crawlPagedMetric.reads > 0) {
    storage.event(runId, 'phase0.crawl_paged',
      `State-graph crawl read ${crawlPagedMetric.considered} endpoint row(s) across ${crawlPagedMetric.pages} page(s); ${crawlPagedMetric.used} route(s) resolved.`,
      crawlPagedMetric)
  }

  return {
    origin: normalizedOrigin,
    pagesVisited,
    endpointsDiscovered,
    paramsDiscovered,
    storageKeys: [...storageKeySet],
    hasPostMessageListener,
    personasCrawled,
    routeMapEndpoints,
    visibleToPersonas,
    ...(crawlPagedMetric.reads > 0 ? { crawlPaged: { ...crawlPagedMetric } } : {}),
    ...(privilegedEndpoints.length > 0 ? { privilegedEndpoints } : {}),
    ...(stoppedReason ? { stoppedReason } : {}),
  }
}
