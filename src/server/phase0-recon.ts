import { createHash, randomUUID } from 'node:crypto'
import { closeSync, constants as fsConstants, existsSync, lstatSync, openSync, readdirSync, readFileSync, realpathSync } from 'node:fs'
import { extname, isAbsolute, join, relative, sep } from 'node:path'
import type { CapabilityTier, CodeLocation, EndpointSource, ParamLocation } from '../domain.ts'
import { mergeTechTags, techTagsFromManifests, techTagsFromResponse } from '../templates/tech-tags.ts'
import type { ManifestFile } from '../templates/tech-tags.ts'
import { BrokerCircuitOpen, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
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
import { normalizeRouteTemplate } from './route-template.ts'
import { buildSoft404ProbePaths } from './scoped-browser.ts'
import type { ScopedBrowser } from './scoped-browser.ts'
import {
  getOrBuildStaticWorkspaceSnapshot,
  getOrBuildStaticWorkspaceSnapshotInWorker,
  SNAPSHOT_STATIC_ROUTE_EXTS,
  snapshotSourceFiles,
  type StaticWorkspaceSnapshot,
} from './static-workspace-snapshot.ts'
import {
  extractHtmlLinksAndScripts,
  extractHtmlLinksAndScriptsInWorker,
  extractProgramGraphInWorker,
  jsHarvestInWorker,
  mapServicesToOriginsInWorker,
  parseJsonOrYaml,
  parseJsonOrYamlInWorker,
  parseYamlLikeDocument,
  sanitizeSameOriginPath,
  UntrustedComputeAbortedError,
  type ExtractedHtmlSurface,
} from './untrusted-compute-pool.ts'

export { extractHtmlLinksAndScripts, parseJsonOrYaml, parseYamlLikeDocument }
import {
  classifySurface,
  type RuntimeApiDependency,
  type RuntimeGraphqlCatalog,
  type RuntimeGraphqlField,
  type RuntimeOpenApiOperation,
  type RuntimeSpaRoute,
} from './invariant-synthesizer.ts'
import {
  classifyStructuralFieldEdgeKind,
  extractResponseStructuralSignals,
  type ResponseSignalEdgeKind,
} from './resource-harvest.ts'
import type { EndpointRow, Store } from './store.ts'
import { parseGraphqlIntrospection, parseGraphqlSdl, probeSurface, runSafeTemplates, surfaceProbeTimeoutMs } from './surface-engine.ts'

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
  /** Optional Phase A StaticWorkspaceSnapshot (reused across manifest, route, and graph extraction). */
  staticSnapshot?: StaticWorkspaceSnapshot
  /** Optional explicit per-origin request cap override (bypasses adaptive multi-host scaling). */
  perOriginCap?: number
  /** Optional per-request HTTP timeout in ms for Phase-0 recon probes (default 8_000). */
  requestTimeoutMs?: number
}

export interface Phase0TruncationRecord {
  category: string
  cap: number
  observed: number
  dropped: number
  origin?: string
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
  /** Cached Phase A StaticWorkspaceSnapshot built or reused during Phase 0. */
  staticSnapshot?: StaticWorkspaceSnapshot
  /** Origins short-circuited early due to consecutive transport timeouts/errors or 520–526 responses. */
  skippedDeadHosts?: Array<{ origin: string; reason: string; requestsUsed: number }>
  /** Origins short-circuited early due to uniform edge-protection walls across initial probes. */
  edgeProtectedOrigins?: EdgeProtectedOriginRecord[]
  /** Structured SPA routes harvested from JS bundles and browser state-graph crawl for InvariantSynthesizer. */
  runtimeSpaRoutes?: RuntimeSpaRoute[]
  /** Structured GraphQL catalogs harvested from introspection, SDL specs, and JS bundles. */
  runtimeGraphqlCatalogs?: RuntimeGraphqlCatalog[]
  /** Structured OpenAPI operations (preserving `security`, `operationId`, and auth hints) parsed in Phase 0. */
  runtimeOpenApiOperations?: RuntimeOpenApiOperation[]
  /** Structured truncation telemetry whenever a finite Phase-0 discovery cap was reached. */
  truncations?: Phase0TruncationRecord[]
}

export type EdgeProtectionVendor = 'vercel_deployment_protection' | 'cloudflare_access' | 'edge_auth_wall'

export interface EdgeProtectedOriginRecord {
  origin: string
  vendor: EdgeProtectionVendor
  reason: string
  status: number
  probesObserved: number
  requestsUsed: number
  evidence: string[]
}

export interface StaticServerActionHint {
  actionName: string
  framework: 'nextjs'
  /** Inferred importing or sibling Next.js App Router page route (invoked via POST <page> + Next-Action header). */
  pageRoute?: string
  headerHint: 'Next-Action'
  authRequirement: string | null
  ownershipGuard: string | null
  sinkKinds: string[]
  codeLocation: CodeLocation
}

export interface RepoStaticExtractionSummary {
  astRoutes: number
  regexFallbackRoutes: number
  mergedRoutes: number
  duplicateRoutes: number
  /** Count of multi-origin AST routes left explicitly unmapped instead of misattributing to origins[0]. */
  unmappedRoutes?: number
  frameworks: string[]
  /** Next.js `"use server"` functions recorded as metadata/hints (invoked via page route + `Next-Action` header, never synthetic `/_actions/*` routes). */
  serverActions?: StaticServerActionHint[]
  /** Service -> origin resolution reused for AST route attribution. */
  originMappings: ServiceOriginMapping[]
  /** `METHOD pathTemplate` -> origin provenance for AST routes (multi-origin targets). */
  routeOrigins: Record<string, { origin?: string; pathPrefix?: string; confidence: ServiceOriginMapping['confidence']; service?: string; evidence: string[] }>
  warnings: string[]
  /** Truncation records from repo file/service discovery caps, if any were hit. */
  truncations?: Phase0TruncationRecord[]
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
  /** Structured SPA route summaries (route -> intercepted API calls + persona role gating). */
  spaRoutes?: RuntimeSpaRoute[]
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
  return sanitizeSameOriginPath(raw, baseOrigin)
}

/**
 * Discovery-facing route normalizer: preserves named parameter identifiers (`:orgId`, `:invoiceId`)
 * and literal segment casing (`/trpc/user.getById`, `/api/getInvoice`), normalizing only framework
 * token forms (`[id]`, `{id}`, `<int:id>`) to `:id`. Aggressive folding stays in `dedupe.ts`.
 */
export function normalizeDiscoveryTemplate(rawPath: string): string {
  return normalizeRouteTemplate(rawPath, { preserveColonParams: true, collapseConcreteIds: false })
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

function walkRepoFiles(rootDir: string, maxFiles = 10_000): string[] {
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
export function extractStaticFrameworkRoutes(
  reposDir: string,
  staticSnapshot?: StaticWorkspaceSnapshot,
): {
  routes: StaticExtractedRoute[]
  frameworks: string[]
  serverActions: StaticServerActionHint[]
} {
  const sourceEntries: Array<{ rel: string; code: string }> = []
  if (staticSnapshot) {
    for (const [rel, code] of staticSnapshot.sourceByPath.entries()) {
      const ext = extname(rel).toLowerCase()
      if (!SNAPSHOT_STATIC_ROUTE_EXTS.has(ext)) continue
      sourceEntries.push({ rel, code })
    }
  } else {
    if (!reposDir || !existsSync(reposDir)) return { routes: [], frameworks: [], serverActions: [] }
    const files = walkRepoFiles(reposDir)
    let rootReal: string
    try {
      rootReal = realpathSync(reposDir)
    } catch {
      return { routes: [], frameworks: [], serverActions: [] }
    }
    for (const fullPath of files) {
      const code = readRepoRegularFile(fullPath)
      if (code === null) continue
      sourceEntries.push({ rel: relative(rootReal, fullPath).split(sep).join('/'), code })
    }
  }
  const routes: StaticExtractedRoute[] = []
  const serverActions: StaticServerActionHint[] = []
  const frameworks = new Set<string>()
  const seen = new Set<string>()
  const seenServerActions = new Set<string>()

  // Index Next.js App Router pages ONCE in O(pageBytes) so "use server" functions can link to their
  // importing page route in O(1) average lookup without O(actions * pageBytes) `.includes()` scans (R4-H-16).
  interface IndexedNextAppPage {
    readonly rel: string
    readonly pageRoute: string
    readonly repoRoot: string
    readonly tokens: Set<string>
  }
  const indexPageTokens = (code: string): Set<string> => {
    const tokens = new Set<string>()
    const len = code.length
    let i = 0
    while (i < len) {
      const c = code.charCodeAt(i)
      const isTok = (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 95 || c === 45 || c === 46
      if (!isTok) {
        i += 1
        continue
      }
      const start = i
      let hasPunct = false
      while (i < len) {
        const ch = code.charCodeAt(i)
        if ((ch >= 65 && ch <= 90) || (ch >= 97 && ch <= 122) || (ch >= 48 && ch <= 57) || ch === 95) {
          i += 1
        } else if (ch === 45 || ch === 46) {
          hasPunct = true
          i += 1
        } else {
          break
        }
      }
      const raw = code.slice(start, i)
      const trimmed = raw.replace(/^\.+|\.+$/g, '')
      if (!trimmed || trimmed.length > 128) continue
      tokens.add(trimmed)
      if (hasPunct) {
        const stem = trimmed.replace(/\.(?:ts|tsx|js|jsx|mjs|cjs)$/i, '')
        if (stem && stem !== trimmed) tokens.add(stem)
        // Also index identifier sub-tokens so `actions.createOrder` or `order-actions` matches both
        // identifier action names and hyphen/dot-delimited file stems.
        let subStart = -1
        for (let k = 0; k <= trimmed.length; k += 1) {
          const sc = k < trimmed.length ? trimmed.charCodeAt(k) : 0
          const isIdent = (sc >= 65 && sc <= 90) || (sc >= 97 && sc <= 122) || (sc >= 48 && sc <= 57) || sc === 95
          if (isIdent) {
            if (subStart === -1) subStart = k
          } else if (subStart !== -1) {
            const sub = trimmed.slice(subStart, k)
            if (sub.length >= 2) tokens.add(sub)
            subStart = -1
          }
        }
      }
    }
    return tokens
  }
  const nextAppPages: IndexedNextAppPage[] = []
  const pagesByToken = new Map<string, number[]>()
  for (const entry of sourceEntries) {
    const pageMatch = /(?:^|\/)(?:src\/)?app((?:\/[^?#]*)?)\/page\.(?:ts|tsx|js|jsx|mjs)$/i.exec(entry.rel)
    if (!pageMatch) continue
    const rawPageRoute = (pageMatch[1] || '/').replace(/\/\([^)]+\)/g, '') || '/'
    const tokens = indexPageTokens(entry.code)
    const pageIdx = nextAppPages.length
    nextAppPages.push({
      rel: entry.rel,
      pageRoute: normalizeRouteTemplate(rawPageRoute),
      repoRoot: entry.rel.split('/')[0] ?? '',
      tokens,
    })
    for (const tok of tokens) {
      const list = pagesByToken.get(tok)
      if (list) list.push(pageIdx)
      else pagesByToken.set(tok, [pageIdx])
    }
  }
  const inferServerActionPageRoute = (actionRel: string, actionName: string): string | undefined => {
    const fileStem = (actionRel.split('/').pop() ?? '').replace(/\.(?:ts|tsx|js|jsx|mjs|cjs)$/i, '')
    const repoPrefix = actionRel.split('/').slice(0, 2).join('/')
    const actionRepoRoot = actionRel.split('/')[0] ?? ''
    const actionPages = pagesByToken.get(actionName)
    if (actionPages && actionPages.length > 0) {
      const stemPages = fileStem ? pagesByToken.get(fileStem) : undefined
      if (!fileStem || (stemPages && stemPages.length > 0)) {
        const candidates = stemPages && stemPages.length < actionPages.length ? stemPages : actionPages
        const checkAction = candidates === stemPages
        for (const idx of candidates) {
          const p = nextAppPages[idx]!
          if (
            (p.rel.startsWith(`${repoPrefix}/`) || actionRepoRoot === p.repoRoot)
            && (checkAction ? p.tokens.has(actionName) : (!fileStem || p.tokens.has(fileStem)))
          ) {
            return p.pageRoute
          }
        }
      }
    }
    const appDirMatch = /(?:^|\/)(?:src\/)?app((?:\/[^?#]*)?)\/[^/]+\.(?:ts|tsx|js|jsx|mjs)$/i.exec(actionRel)
    if (appDirMatch) {
      const rawRoute = (appDirMatch[1] || '/').replace(/\/\([^)]+\)/g, '') || '/'
      return normalizeRouteTemplate(rawRoute)
    }
    return undefined
  }

  const pushRoute = (r: StaticExtractedRoute) => {
    const key = `${r.method.toUpperCase()} ${r.pathTemplate}`
    if (seen.has(key)) return
    seen.add(key)
    frameworks.add(r.framework)
    routes.push({ ...r, extraction: r.extraction ?? 'regex' })
  }

  for (const { rel, code } of sourceEntries) {
    const repoName = rel.split('/')[0] || 'repo'
    const ext = extname(rel).toLowerCase()
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

    // 1c. Next.js "use server" Server Actions: NOT served at POST /_actions/<fn> (they invoke the
    // importing page route with a `Next-Action: <hash>` header). Record cleanly as metadata hints
    // instead of minting synthetic /_actions/* HTTP routes that only produce 404 probe spam.
    if (/['"]use server['"]/.test(code)) {
      for (const m of code.matchAll(/export\s+(?:async\s+)?function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g)) {
        const actionName = m[1]
        const actionKey = `${rel}:${actionName}`
        if (seenServerActions.has(actionKey)) continue
        seenServerActions.add(actionKey)
        const line = lineNumberAt(code, m.index ?? 0)
        const pageRoute = inferServerActionPageRoute(rel, actionName)
        frameworks.add('nextjs')
        serverActions.push({
          actionName,
          framework: 'nextjs',
          ...(pageRoute ? { pageRoute } : {}),
          headerHint: 'Next-Action',
          ...meta,
          sinkKinds: [...new Set([...meta.sinkKinds, 'server_action'])],
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

  return { routes, frameworks: [...frameworks], serverActions }
}

// ============================================================================
// Program Graph ingestion (AST-primary routes, guard chains, hypotheses, origins)
// ============================================================================

const GRAPH_SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.java', '.kt', '.go', '.rb'])

/** Guard-chain classifiers mirroring the Program Graph's middleware taxonomy. */
const ADMIN_CHAIN_RE = /\b(?:admin\w*|isAdmin|requireAdmin\w*|superuser\w*|staff\w*|role\w*|rbac|permission\w*|privilege\w*|policy\w*|hasRole|hasAuthority)/i
const TENANT_CHAIN_RE = /(?:tenant|organization|organisation|orgId|org_id|account|workspace|membership|ownership|ownerId|owner_id|scopeCheck|belongsTo)/i

const MAX_REPO_GRAPH_FILES = 10_000
const MAX_REPO_DOCKERFILES = 128
const MAX_REPO_MANIFESTS = 256
const MAX_REPO_COMPOSE_FILES = 64
const MAX_REPO_INGRESS_FILES = 64
const MAX_REPO_GRAPH_SERVICES = 128

interface RepoGraphInputs {
  sourceFiles: Array<{ path: string; content: string }>
  dockerfiles: Array<{ path: string; content: string }>
  manifests: Array<{ path: string; content: string }>
  compose?: string
  composeFiles: Array<{ path: string; content: string }>
  ingress?: string
  ingressFiles: Array<{ path: string; content: string }>
  mountedRepos: string[]
  truncations: Phase0TruncationRecord[]
}

function recordTruncationEntry(
  list: Phase0TruncationRecord[],
  category: string,
  cap: number,
  observed: number,
  origin?: string,
): void {
  if (observed <= cap) return
  const existing = list.find(entry => entry.category === category && entry.origin === origin)
  if (existing) {
    existing.observed = Math.max(existing.observed, observed)
    existing.dropped = Math.max(0, existing.observed - existing.cap)
    return
  }
  list.push({
    category,
    cap,
    observed,
    dropped: observed - cap,
    ...(origin ? { origin } : {}),
  })
}

const COMPOSE_BASENAME_RE = /^(?:docker-)?compose(?:[._-][^/]*)?\.ya?ml$/i
const INGRESS_BASENAME_RE = /^ingress[^/]*\.ya?ml$/i

/**
 * Bounded walk of the mounted `/repos` tree collecting Program Graph inputs. Symlinks are never
 * followed and file sizes are capped, so graph extraction can run on an untrusted mount.
 * Collects ALL compose and ingress files with path-prefix retention and reports truncation telemetry
 * whenever any finite DoS cap is reached.
 */
function collectRepoGraphInputs(reposDir: string, maxFiles = MAX_REPO_GRAPH_FILES): RepoGraphInputs | null {
  const inputs: RepoGraphInputs = {
    sourceFiles: [],
    dockerfiles: [],
    manifests: [],
    composeFiles: [],
    ingressFiles: [],
    mountedRepos: [],
    truncations: [],
  }
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
  let filesOverflowed = 0
  let dockerfilesObserved = 0
  let manifestsObserved = 0
  let composeObserved = 0
  let ingressObserved = 0
  while (stack.length > 0) {
    const dir = stack.pop()!
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      continue
    }
    for (const name of entries) {
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
        if (visited < maxFiles && isRealPathUnder(rootReal, full)) stack.push(full)
        continue
      }
      if (!st.isFile() || st.size > 256 * 1024) continue
      if (visited >= maxFiles) {
        filesOverflowed += 1
        continue
      }
      visited += 1
      const rel = relative(rootReal, full).split(sep).join('/')
      const base = name.toLowerCase()
      const ext = extname(name).toLowerCase()
      const isCompose = COMPOSE_BASENAME_RE.test(name)
      const isDockerfile = /^dockerfile(?:\.[^/]*)?$/i.test(name)
      const isManifest = base === 'package.json'
      const looksIngress = INGRESS_BASENAME_RE.test(name)
      const isYaml = ext === '.yaml' || ext === '.yml'
      if (!GRAPH_SOURCE_EXTENSIONS.has(ext) && !isCompose && !isDockerfile && !isManifest && !looksIngress && !isYaml) continue
      const content = readRepoRegularFile(full)
      if (content === null) continue
      if (GRAPH_SOURCE_EXTENSIONS.has(ext)) inputs.sourceFiles.push({ path: rel, content })
      if (isDockerfile) {
        dockerfilesObserved += 1
        if (inputs.dockerfiles.length < MAX_REPO_DOCKERFILES) inputs.dockerfiles.push({ path: rel, content })
      }
      if (isManifest) {
        manifestsObserved += 1
        if (inputs.manifests.length < MAX_REPO_MANIFESTS) inputs.manifests.push({ path: rel, content })
      }
      if (isCompose) {
        composeObserved += 1
        if (inputs.composeFiles.length < MAX_REPO_COMPOSE_FILES) inputs.composeFiles.push({ path: rel, content })
        if (inputs.compose === undefined) inputs.compose = content
      }
      const hasIngressKind = isYaml && content.slice(0, 8000).includes('kind: Ingress')
      if (looksIngress || hasIngressKind) {
        ingressObserved += 1
        if (inputs.ingressFiles.length < MAX_REPO_INGRESS_FILES) inputs.ingressFiles.push({ path: rel, content })
        if (inputs.ingress === undefined) inputs.ingress = content
      }
    }
  }
  if (filesOverflowed > 0) recordTruncationEntry(inputs.truncations, 'repo_graph_files', maxFiles, visited + filesOverflowed)
  recordTruncationEntry(inputs.truncations, 'repo_dockerfiles', MAX_REPO_DOCKERFILES, dockerfilesObserved)
  recordTruncationEntry(inputs.truncations, 'repo_manifests', MAX_REPO_MANIFESTS, manifestsObserved)
  recordTruncationEntry(inputs.truncations, 'repo_compose_files', MAX_REPO_COMPOSE_FILES, composeObserved)
  recordTruncationEntry(inputs.truncations, 'repo_ingress_files', MAX_REPO_INGRESS_FILES, ingressObserved)
  return inputs.sourceFiles.length > 0 || inputs.dockerfiles.length > 0 || inputs.composeFiles.length > 0 || inputs.ingressFiles.length > 0
    ? inputs
    : null
}

function repoBasename(path: string): string {
  const parts = path.split('/').filter(Boolean)
  return parts[parts.length - 1] ?? path
}

/** Candidate monorepo service roots from mounted repos, Dockerfiles and top-level manifests. */
function discoverGraphServices(inputs: RepoGraphInputs, maxServices = MAX_REPO_GRAPH_SERVICES): MonorepoService[] {
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
  const all = [...services.values()]
  recordTruncationEntry(inputs.truncations, 'repo_graph_services', maxServices, all.length)
  return all.slice(0, maxServices)
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
  origin?: string
  pathPrefix?: string
  confidence: ServiceOriginMapping['confidence']
  service?: string
  evidence: string[]
}

/**
 * Attribute a route file to a target origin. Monorepo service roots are matched longest-first;
 * genuinely unmapped services on multi-origin targets are marked `unmapped` instead of silently
 * misattributing their routes to `origins[0]`.
 */
function resolveRouteOrigin(
  file: string,
  mappings: readonly ServiceOriginMapping[],
  origins: readonly string[],
): RouteOriginResolution {
  const candidates = mappings
    .filter(mapping => mapping.root && (file === mapping.root || file.startsWith(`${mapping.root}/`)))
    .sort((a, b) => (b.root?.length ?? 0) - (a.root?.length ?? 0))
  const strong = candidates.find(mapping => mapping.origin && mapping.confidence !== 'fallback' && mapping.confidence !== 'unmapped')
  if (strong && strong.origin) {
    return {
      origin: strong.origin,
      ...(strong.pathPrefix ? { pathPrefix: strong.pathPrefix } : {}),
      confidence: strong.confidence,
      ...(strong.root ? { service: strong.service } : {}),
      evidence: strong.evidence.length ? strong.evidence : [`service root ${strong.root} matched ${file}`],
    }
  }
  if (origins.length === 1) {
    const matchedUnmapped = candidates[0]
    return {
      origin: origins[0]!,
      ...(matchedUnmapped?.pathPrefix ? { pathPrefix: matchedUnmapped.pathPrefix } : {}),
      confidence: 'exact',
      ...(matchedUnmapped?.root ? { service: matchedUnmapped.service } : {}),
      evidence: ['single approved origin for the run'],
    }
  }
  const matched = candidates[0]
  if (matched) {
    return {
      ...(matched.origin && matched.confidence !== 'unmapped' ? { origin: matched.origin } : {}),
      ...(matched.pathPrefix ? { pathPrefix: matched.pathPrefix } : {}),
      confidence: matched.origin ? matched.confidence : 'unmapped',
      ...(matched.root ? { service: matched.service } : {}),
      evidence: matched.evidence.length
        ? matched.evidence
        : [`service root ${matched.root} matched ${file} with no target origin mapping`],
    }
  }
  return {
    confidence: 'unmapped',
    evidence: ['no service root/ingress/port/compose evidence for multi-origin target; route left unmapped instead of misattributing to origins[0]'],
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
  truncations: Phase0TruncationRecord[]
}

function collectGraphExtractionInputs(input: {
  reposDir?: string
  maxFiles?: number
  staticSnapshot?: StaticWorkspaceSnapshot
}): { inputs: RepoGraphInputs; precomputedGraph?: ProgramGraph } | null {
  if (input.staticSnapshot) {
    const snap = input.staticSnapshot
    const sourceFiles = snapshotSourceFiles(snap)
    const dockerfiles = snap.dockerfiles.map(d => ({ path: d.path, content: d.content }))
    const truncations: Phase0TruncationRecord[] = []
    const composeFiles: Array<{ path: string; content: string }> = []
    const ingressFiles: Array<{ path: string; content: string }> = []
    let composeObserved = 0
    let ingressObserved = 0
    for (const [relPath, content] of snap.sourceByPath.entries()) {
      const base = relPath.split('/').pop() ?? relPath
      const ext = extname(base).toLowerCase()
      const isYaml = ext === '.yaml' || ext === '.yml'
      if (COMPOSE_BASENAME_RE.test(base)) {
        composeObserved += 1
        if (composeFiles.length < MAX_REPO_COMPOSE_FILES) composeFiles.push({ path: relPath, content })
      }
      if (INGRESS_BASENAME_RE.test(base) || (isYaml && content.slice(0, 8000).includes('kind: Ingress'))) {
        ingressObserved += 1
        if (ingressFiles.length < MAX_REPO_INGRESS_FILES) ingressFiles.push({ path: relPath, content })
      }
    }
    if (composeFiles.length === 0 && snap.compose !== undefined) {
      composeFiles.push({ path: 'docker-compose.yml', content: snap.compose })
    }
    if (ingressFiles.length === 0 && snap.ingress !== undefined) {
      ingressFiles.push({ path: 'ingress.yaml', content: snap.ingress })
    }
    const pkgManifests = snap.manifests
      .filter(m => m.name.toLowerCase() === 'package.json' || m.name.toLowerCase().endsWith('/package.json'))
    recordTruncationEntry(truncations, 'repo_manifests', MAX_REPO_MANIFESTS, pkgManifests.length)
    recordTruncationEntry(truncations, 'repo_compose_files', MAX_REPO_COMPOSE_FILES, composeObserved)
    recordTruncationEntry(truncations, 'repo_ingress_files', MAX_REPO_INGRESS_FILES, ingressObserved)
    if (sourceFiles.length === 0 && dockerfiles.length === 0 && composeFiles.length === 0 && ingressFiles.length === 0) return null
    return {
      inputs: {
        sourceFiles,
        dockerfiles,
        manifests: pkgManifests
          .slice(0, MAX_REPO_MANIFESTS)
          .map(m => ({ path: m.name, content: m.content })),
        ...(snap.compose !== undefined ? { compose: snap.compose } : {}),
        composeFiles,
        ...(snap.ingress !== undefined ? { ingress: snap.ingress } : {}),
        ingressFiles,
        mountedRepos: [...snap.mountedRepos],
        truncations,
      },
      precomputedGraph: snap.programGraph,
    }
  }
  if (!input.reposDir) return null
  const inputs = collectRepoGraphInputs(input.reposDir, input.maxFiles)
  if (!inputs) return null
  return { inputs }
}

function finalizeRepoProgramGraphExtraction(
  inputs: RepoGraphInputs,
  graph: ProgramGraph,
  origins: readonly string[],
  recentDiffSignals?: readonly CommitDiffSignal[],
  precomputedOriginMappings?: ServiceOriginMapping[],
): RepoProgramGraphExtraction {
  const services = discoverGraphServices(inputs)
  const originMappings = precomputedOriginMappings
    ?? (services.length
      ? mapServicesToOrigins({
          services,
          origins,
          ...(inputs.compose ? { compose: inputs.compose } : {}),
          ...(inputs.composeFiles.length ? { composeFiles: inputs.composeFiles } : {}),
          ...(inputs.ingress ? { ingress: inputs.ingress } : {}),
          ...(inputs.ingressFiles.length ? { ingressFiles: inputs.ingressFiles } : {}),
          dockerfiles: inputs.dockerfiles,
          manifests: inputs.manifests,
        })
      : [])
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
    const resolved = resolveRouteOrigin(route.file, originMappings, origins)
    const key = `${route.method.toUpperCase()} ${pathTemplate}`
    if (!routeOrigins[key] || routeOrigins[key]!.confidence === 'fallback' || routeOrigins[key]!.confidence === 'unmapped') {
      routeOrigins[key] = resolved
    }
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
      ...(resolved.origin ? { origin: resolved.origin } : {}),
      originConfidence: resolved.confidence,
      routeId: route.id,
    })
  }
  const baseHypotheses = deriveCodeToRuntimeHypotheses(graph, {
    ...(recentDiffSignals?.length ? { recentDiffSignals } : {}),
  })
  const hypotheses: CodeToRuntimeHypothesis[] = [...baseHypotheses]
  // When mounted repos have extracted AST routes that did not trigger the narrow intra-file sink
  // rules in `deriveCodeToRuntimeHypotheses` (common in multi-repo workspaces with external SDK
  // sinks or Next.js/Express route handlers), seed grounded route-bound hypotheses for unguarded
  // sink-bearing or high-risk routes so `phase0.code_slices` attaches real bounded slices.
  if (graph.routes.length > 0 && hypotheses.length === 0) {
    const coveredRouteIds = new Set(hypotheses.map(h => h.routeId).filter((id): id is string => Boolean(id)))
    const graphRouteById = new Map(graph.routes.map(r => [r.id, r]))
    const rankedRoutes = [...routes]
      .filter(r => r.routeId && graphRouteById.has(r.routeId) && !coveredRouteIds.has(r.routeId))
      .sort((a, b) =>
        (b.sinkKinds.length > 0 ? 1 : 0) - (a.sinkKinds.length > 0 ? 1 : 0)
        || (a.authClass === 'unguarded' ? 0 : 1) - (b.authClass === 'unguarded' ? 0 : 1)
        || b.riskScore - a.riskScore
        || a.pathTemplate.localeCompare(b.pathTemplate),
      )
      .slice(0, 24)
    for (const r of rankedRoutes) {
      const gr = graphRouteById.get(r.routeId!)!
      const primarySink = r.sinkKinds[0]
      const mappedSink = primarySink === 'db_query' ? 'db_query' as const
        : primarySink === 'command_exec' ? 'command' as const
        : primarySink === 'outbound_fetch' ? 'outbound_fetch' as const
        : primarySink === 'file_io' ? 'file' as const
        : primarySink === 'redirect' ? 'redirect' as const
        : undefined
      hypotheses.push({
        id: `hyp:route:${gr.id}`,
        kind: 'unauthenticated_sink',
        severity: mappedSink === 'db_query' || mappedSink === 'command' ? 'high' : 'medium',
        confidence: mappedSink ? 0.62 : 0.52,
        framework: gr.framework,
        method: gr.method,
        path: gr.path,
        file: gr.file,
        line: gr.line,
        ...(mappedSink ? { sinkKind: mappedSink } : {}),
        routeId: gr.id,
        rationale: mappedSink
          ? `Mounted route ${gr.method} ${gr.path} (${gr.file}:${gr.line}) contains ${mappedSink} sink evidence (${r.authClass ?? 'unguarded'}).`
          : `Mounted route ${gr.method} ${gr.path} (${gr.file}:${gr.line}) extracted from workspace Program Graph (${r.authClass ?? 'unguarded'}).`,
        evidence: [
          `repo=${r.codeLocation.repo}`,
          `guards=[${gr.guards.join(', ')}]`,
          ...(r.sinkKinds.length ? [`sinks=[${r.sinkKinds.join(', ')}]`] : []),
        ],
        probeClass: mappedSink === 'outbound_fetch' ? 'ssrf'
          : mappedSink === 'db_query' || mappedSink === 'command' ? 'injection'
          : r.authClass === 'unguarded' ? 'auth_bypass' : 'bola_bfla',
      })
    }
  }
  return {
    graph,
    routes,
    frameworks: [...new Set(graph.routes.map(route => route.framework))],
    hypotheses,
    originMappings,
    routeOrigins,
    warnings: [...graph.warnings],
    truncations: [...inputs.truncations],
  }
}

const MULTI_REPO_GRAPH_WORKER_TIMEOUT_MS = 25_000

/** Partition source files by mounted repo prefix (supports both `owner/repo/...` and top-level `<repo>/...`). */
function partitionSourceFilesByRepo(
  sourceFiles: ReadonlyArray<{ path: string; content: string }>,
  mountedRepos: readonly string[],
): Array<{ repo: string; files: Array<{ path: string; content: string }> }> {
  const sortedMounted = [...mountedRepos].filter(Boolean).sort((a, b) => b.length - a.length)
  const buckets = new Map<string, Array<{ path: string; content: string }>>()
  for (const file of sourceFiles) {
    const owner = sortedMounted.find(m => file.path === m || file.path.startsWith(`${m}/`))
      ?? file.path.split('/')[0]
      ?? 'repo'
    const list = buckets.get(owner)
    if (list) list.push(file)
    else buckets.set(owner, [file])
  }
  return [...buckets.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([repo, files]) => ({ repo, files }))
}

/** Merge multiple per-repo ProgramGraphs deterministically without losing routes, nodes, edges, or code hints. */
function mergeProgramGraphs(graphs: readonly ProgramGraph[], repoLabel?: string): ProgramGraph {
  const frameworks = new Set<ProgramGraph['frameworks'][number]>()
  const routes: ProgramGraph['routes'] = []
  const routeSeen = new Set<string>()
  const nodes: ProgramGraph['nodes'] = []
  const nodeSeen = new Set<string>()
  const edges: ProgramGraph['edges'] = []
  const edgeSeen = new Set<string>()
  const globalMiddleware = new Set<string>()
  const warnings: string[] = []
  const warningSeen = new Set<string>()
  const codeHints: NonNullable<ProgramGraph['codeHints']> = {}
  const staticLeads: NonNullable<ProgramGraph['staticLeads']> = []
  const leadSeen = new Set<string>()
  let filesScanned = 0

  for (const g of graphs) {
    filesScanned += g.filesScanned
    for (const fw of g.frameworks) frameworks.add(fw)
    for (const r of g.routes) {
      if (routeSeen.has(r.id)) continue
      routeSeen.add(r.id)
      routes.push(r)
    }
    for (const n of g.nodes) {
      if (nodeSeen.has(n.id)) continue
      nodeSeen.add(n.id)
      nodes.push(n)
    }
    for (const e of g.edges) {
      const ek = `${e.fromId}|${e.toId}|${e.kind ?? ''}|${e.file}:${e.line}`
      if (edgeSeen.has(ek)) continue
      edgeSeen.add(ek)
      edges.push(e)
    }
    for (const mw of g.globalMiddleware) globalMiddleware.add(mw)
    for (const w of g.warnings) {
      if (warningSeen.has(w)) continue
      warningSeen.add(w)
      warnings.push(w)
    }
    if (g.codeHints) {
      for (const [k, hints] of Object.entries(g.codeHints)) {
        const list = codeHints[k] ?? []
        for (const h of hints) list.push(h)
        codeHints[k] = list
      }
    }
    for (const lead of g.staticLeads ?? []) {
      const lk = `${lead.id}|${lead.kind}|${lead.file}:${lead.line}|${lead.note}`
      if (leadSeen.has(lk)) continue
      leadSeen.add(lk)
      staticLeads.push(lead)
    }
  }

  return {
    ...(repoLabel ? { repo: repoLabel } : {}),
    filesScanned,
    frameworks: [...frameworks],
    routes,
    nodes,
    edges,
    globalMiddleware: [...globalMiddleware],
    warnings,
    ...(Object.keys(codeHints).length > 0 ? { codeHints } : {}),
    ...(staticLeads.length > 0 ? { staticLeads } : {}),
  }
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
  /** Optional Phase A StaticWorkspaceSnapshot (reuses cached files + ProgramGraph without walking disk). */
  staticSnapshot?: StaticWorkspaceSnapshot
}): RepoProgramGraphExtraction | null {
  const prepared = collectGraphExtractionInputs(input)
  if (!prepared) return null
  const graph = prepared.precomputedGraph
    ?? extractProgramGraph({ files: prepared.inputs.sourceFiles, repo: prepared.inputs.mountedRepos.join(',') || undefined })
  return finalizeRepoProgramGraphExtraction(prepared.inputs, graph, input.origins, input.recentDiffSignals)
}

/**
 * Worker-isolated async variant of `extractRepoProgramGraph` offloading untrusted source
 * scanning into `UntrustedComputePool` so large/hostile repos cannot stall the event loop.
 * Uses a generous bounded worker timeout and falls back to per-repo partitioning if a giant
 * multi-repo workspace overflows a single worker isolate so `phase0.code_slices` stays populated.
 */
export async function extractRepoProgramGraphInWorker(input: {
  reposDir?: string
  origins: readonly string[]
  maxFiles?: number
  recentDiffSignals?: readonly CommitDiffSignal[]
  staticSnapshot?: StaticWorkspaceSnapshot
  signal?: AbortSignal
}): Promise<RepoProgramGraphExtraction | null> {
  const prepared = collectGraphExtractionInputs(input)
  if (!prepared) return null
  const usePrecomputed = prepared.precomputedGraph
    && (prepared.precomputedGraph.routes.length > 0 || prepared.inputs.sourceFiles.length === 0)
  let graph: ProgramGraph
  if (usePrecomputed) {
    graph = prepared.precomputedGraph!
  } else {
    const repoLabel = prepared.inputs.mountedRepos.join(',') || undefined
    let combined: ProgramGraph | null = null
    let combinedError: string | null = null
    try {
      combined = await extractProgramGraphInWorker(
        { files: prepared.inputs.sourceFiles, repo: repoLabel },
        { timeoutMs: MULTI_REPO_GRAPH_WORKER_TIMEOUT_MS, signal: input.signal },
      )
    } catch (err) {
      if (input.signal?.aborted || err instanceof UntrustedComputeAbortedError) throw err
      combinedError = err instanceof Error ? err.message : String(err)
    }
    const buckets = partitionSourceFilesByRepo(prepared.inputs.sourceFiles, prepared.inputs.mountedRepos)
    if (combined && (combined.routes.length > 0 || buckets.length <= 1)) {
      graph = combined
    } else if (buckets.length > 1) {
      const parts: ProgramGraph[] = []
      const bucketWarnings: string[] = combinedError ? [`Combined ProgramGraph worker failed (${combinedError}); partitioned across ${buckets.length} repos.`] : []
      await runBoundedPool(
        buckets,
        2,
        async bucket => {
          if (input.signal?.aborted) return
          try {
            const part = await extractProgramGraphInWorker(
              { files: bucket.files, repo: bucket.repo },
              { timeoutMs: MULTI_REPO_GRAPH_WORKER_TIMEOUT_MS, signal: input.signal },
            )
            parts.push(part)
          } catch (err) {
            if (input.signal?.aborted || err instanceof UntrustedComputeAbortedError) throw err
            const msg = err instanceof Error ? err.message : String(err)
            bucketWarnings.push(`ProgramGraph worker skipped repo "${bucket.repo}": ${msg}`)
          }
        },
        () => Boolean(input.signal?.aborted),
      )
      graph = mergeProgramGraphs(parts, repoLabel)
      if (bucketWarnings.length > 0) {
        graph = { ...graph, warnings: [...graph.warnings, ...bucketWarnings] }
      }
    } else if (combined) {
      graph = combined
    } else {
      throw new Error(combinedError ?? 'ProgramGraph worker extraction failed')
    }
  }
  const services = discoverGraphServices(prepared.inputs)
  const originMappings = services.length
    ? await mapServicesToOriginsInWorker(
        {
          services,
          origins: input.origins,
          ...(prepared.inputs.compose ? { compose: prepared.inputs.compose } : {}),
          ...(prepared.inputs.composeFiles.length ? { composeFiles: prepared.inputs.composeFiles } : {}),
          ...(prepared.inputs.ingress ? { ingress: prepared.inputs.ingress } : {}),
          ...(prepared.inputs.ingressFiles.length ? { ingressFiles: prepared.inputs.ingressFiles } : {}),
          dockerfiles: prepared.inputs.dockerfiles,
          manifests: prepared.inputs.manifests,
        },
        { timeoutMs: MULTI_REPO_GRAPH_WORKER_TIMEOUT_MS, signal: input.signal },
      )
    : []
  return finalizeRepoProgramGraphExtraction(prepared.inputs, graph, input.origins, input.recentDiffSignals, originMappings)
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
  const astFileRoutes = new Set<string>()
  let duplicates = 0
  const keyOf = (route: StaticExtractedRoute) =>
    `${(route.origin ?? (route.originConfidence === 'unmapped' ? 'unmapped' : input.defaultOrigin)).toLowerCase()}|${route.method.toUpperCase()}|${route.pathTemplate}`
  const fileRouteKeyOf = (route: StaticExtractedRoute) =>
    `${route.codeLocation.file}|${route.method.toUpperCase()}|${route.pathTemplate}`
  for (const route of input.astRoutes) {
    const key = keyOf(route)
    astFileRoutes.add(fileRouteKeyOf(route))
    if (seen.has(key)) { duplicates += 1; continue }
    seen.add(key)
    merged.push(route)
  }
  for (const route of input.regexRoutes) {
    // AST extraction is authoritative for the same (file, method, pathTemplate), including when
    // AST resolved a specific target origin or intentionally marked a microservice route `unmapped`.
    if (astFileRoutes.has(fileRouteKeyOf(route))) { duplicates += 1; continue }
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
export function readRepoManifests(
  reposDir: string,
  maxFiles = 200,
  staticSnapshot?: StaticWorkspaceSnapshot,
): ManifestFile[] {
  if (staticSnapshot) {
    return staticSnapshot.manifests.slice(0, maxFiles).map(m => ({ name: m.name, content: m.content }))
  }
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
const MAX_PHASE0_JS_SCAN_BYTES = 512 * 1024
const PROTO_POLLUTION_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype'])

/** Reject prototype-accessor segments in dotted/bracketed parameter paths (`R2-C-2`). */
export function hasPrototypePollutionSegment(name: string): boolean {
  if (!name) return false
  for (const rawSeg of name.split(/[.[\]]+/)) {
    const seg = rawSeg.trim()
    if (seg && PROTO_POLLUTION_SEGMENTS.has(seg)) return true
  }
  return false
}

const PARAM_NAME_RE = /^[A-Za-z_][A-Za-z0-9_.[-]{0,63}$/

function isSafeParamName(name: string): boolean {
  return PARAM_NAME_RE.test(name) && !hasPrototypePollutionSegment(name)
}

export function harvestJsRequestParams(rawCode: string): JsRequestSpec[] {
  const code = rawCode.length > MAX_PHASE0_JS_SCAN_BYTES ? rawCode.slice(0, MAX_PHASE0_JS_SCAN_BYTES) : rawCode
  const out: JsRequestSpec[] = []
  const seen = new Set<string>()
  const pushSpec = (method: string, rawPath: string, params: JsRequestParam[]) => {
    const path = rawPath.trim()
    if (!path.startsWith('/') || path.startsWith('//') || path.length > 200 || /[\r\n\0\\]/.test(path)) return
    const cleanPath = path.split('?')[0] ?? path
    const deduped: JsRequestParam[] = []
    const keys = new Set<string>()
    for (const p of params) {
      if (!p.name || !isSafeParamName(p.name)) continue
      const key = `${p.name}|${p.location}`
      if (keys.has(key)) continue
      keys.add(key)
      deduped.push(p)
    }
    // Preserve query parameters that were already present in the URL literal.
    const qIdx = path.indexOf('?')
    if (qIdx >= 0) {
      try {
        for (const name of new URL(path, 'http://kovo.invalid').searchParams.keys()) {
          if (!isSafeParamName(name)) continue
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
    if (out.length < 160) out.push({ method: methodUpper, path: cleanPath, params: deduped.slice(0, 40) })
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
        .filter(t => !/^(?:request|root|kovo|envelope|body)$/i.test(t))
      const name = concatTag ?? literalTags[literalTags.length - 1]
      pushSpec(method, path, name ? [{ name, location: 'xml' }] : [])
      return
    }
    const params: JsRequestParam[] = []
    const collect = (block: string, location: 'json' | 'form', skipInitOptions: boolean, target: JsRequestParam[] = params) => {
      for (const m of block.matchAll(/(?<![\w$])([A-Za-z_$][\w$]{0,63})[ \t]{0,16}:/g)) {
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

/** Extract runtime parameter names that the SPA binds to a named API client call. */
export function harvestConfigParamBindings(rawCode: string): RouteMapParamBinding[] {
  const code = rawCode.length > MAX_PHASE0_JS_SCAN_BYTES ? rawCode.slice(0, MAX_PHASE0_JS_SCAN_BYTES) : rawCode
  const out: RouteMapParamBinding[] = []
  const seen = new Set<string>()
  const aliasRe = /(?<![\w$])(?:const|let|var)[ \t]{1,16}([A-Za-z_$][\w$]{0,63})[ \t]{0,16}=[ \t]{0,16}\(?[ \t]{0,16}[A-Za-z_$][\w$.]{0,127}\.params[ \t]{0,16}&&[ \t]{0,16}[A-Za-z_$][\w$.]{0,127}\.params(?:\.([A-Za-z_$][\w$]{0,63})|\[[ \t]{0,16}(['"])([^'"\r\n]{1,64})\3[ \t]{0,16}\])/g
  for (const match of code.matchAll(aliasRe)) {
    const alias = match[1] ?? ''
    const paramName = (match[2] ?? match[4] ?? '').trim()
    if (!alias || !isSafeParamName(paramName)) continue
    const start = match.index ?? 0
    const declarationWindow = code.slice(start, Math.min(code.length, start + 1600))
    const escaped = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const usage = new RegExp(`\\[[ \\t]{0,16}${escaped}[ \\t]{0,16}\\][ \\t]{0,16}=`).exec(declarationWindow)
    if (!usage) continue
    const window = declarationWindow.slice(usage.index, Math.min(declarationWindow.length, usage.index + 900))
    const call = /(?:api|call|routePath|request|mutate|send)[ \t]{0,16}\([ \t]{0,16}(['"])([A-Za-z0-9_.:-]{1,80})\1/.exec(window)
    if (!call) continue
    const routeKey = call[2]
    const probes = window.slice(0, 500)
    const location: RouteMapParamBinding['location'] =
      /URLSearchParams|FormData[ \t]{0,8}\(/.test(probes) ? 'form'
        : /JSON\.stringify[ \t]{0,8}\(/.test(probes) ? 'json'
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
export function extractJsModuleImports(rawCode: string): string[] {
  const code = rawCode.length > MAX_PHASE0_JS_SCAN_BYTES ? rawCode.slice(0, MAX_PHASE0_JS_SCAN_BYTES) : rawCode
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
  for (const match of code.matchAll(/\bimport[ \t\r\n]{1,16}(?:[^'";]{0,200}?[ \t\r\n]{1,16}from[ \t\r\n]{1,16})?(['"])([^'"\r\n]{1,200})\1/g)) push(match[2])
  for (const match of code.matchAll(/\bexport[ \t\r\n]{1,16}[^'";]{0,200}?[ \t\r\n]{1,16}from[ \t\r\n]{1,16}(['"])([^'"\r\n]{1,200})\1/g)) push(match[2])
  for (const match of code.matchAll(/\bimport[ \t]{0,16}\([ \t]{0,16}(['"`])([^'"`\r\n]{1,200})\1[ \t]{0,16}\)/g)) push(match[2])
  return out
}

/**
 * Same-origin build-asset references (JS chunks, source maps, manifest JSON) found in HTML,
 * bundles or webpack chunk maps. Used to drain the JS queue breadth-first beyond entry scripts.
 */
export function extractAssetReferences(rawCode: string, max = 32): string[] {
  const code = rawCode.length > MAX_PHASE0_JS_SCAN_BYTES ? rawCode.slice(0, MAX_PHASE0_JS_SCAN_BYTES) : rawCode
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
  for (const match of code.matchAll(/["'`]((?:\/|\.{1,2}\/)[^"'`\s]{1,180}?\.(?:m?js|json))(?:\?[^"'`\s]{0,120})?["'`]/g)) push(match[1])
  for (const match of code.matchAll(/\b(?:chunk|asset|file|src|url)[ \t]{0,16}[:=][ \t]{0,16}["'`]([^"'`\s]{1,180})["'`]/g)) push(match[1])
  return out
}

export interface TrpcProcedure {
  router: string
  procedure: string
}

/** Bounded scan for tRPC procedure references (`trpc.<router>.<proc>.useQuery`, literal paths). */
export function harvestTrpcProcedures(rawCode: string): TrpcProcedure[] {
  const code = rawCode.length > MAX_PHASE0_JS_SCAN_BYTES ? rawCode.slice(0, MAX_PHASE0_JS_SCAN_BYTES) : rawCode
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
  for (const match of code.matchAll(/\btrpc[ \t]{0,8}\.[ \t]{0,8}([A-Za-z_$][\w$]{0,63})[ \t]{0,8}\.[ \t]{0,8}([A-Za-z_$][\w$]{0,63})[ \t]{0,8}\.[ \t]{0,8}(?:useQuery|useMutation|useInfiniteQuery|query|mutation|fetch|mutate)\b/g)) {
    push(match[1], match[2])
  }
  for (const match of code.matchAll(/\btrpc[ \t]{0,8}\[[ \t]{0,8}['"]([\w$]{1,64})['"][ \t]{0,8}\][ \t]{0,8}\[[ \t]{0,8}['"]([\w$]{1,64})['"][ \t]{0,8}\]/g)) push(match[1], match[2])
  for (const match of code.matchAll(/["'`]\/trpc\/([A-Za-z0-9_$]{1,64})\.([A-Za-z0-9_$]{1,64})/g)) push(match[1], match[2])
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
    if (!isSafeParamName(key) || responseOnly.test(key)) return
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
    parsed = new URL(trimmedUrl, 'http://kovo.invalid')
  } catch {
    return null
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
  const path = parsed.pathname
  if (!path.startsWith('/') || path.length > 240) return null
  const params: JsRequestParam[] = []
  const seen = new Set<string>()
  const push = (name: string, location: JsRequestParam['location']) => {
    if (!isSafeParamName(name)) return
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
        .filter(tag => !/^(?:\?xml|request|root|envelope|body|kovo)$/i.test(tag))
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
    if (hasPrototypePollutionSegment(raw)) return
    const name = raw.split('.').pop()?.trim() ?? ''
    if (/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(name) && !hasPrototypePollutionSegment(name)) out.add(name)
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
  if (!isSafeParamName(name)) return false
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
    if (!isSafeParamName(name)) continue
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
  const paramMap: Record<string, string> = Object.create(null) as Record<string, string>
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
            if (typeof item === 'string' && isSafeParamName(item)) paramHints.push(item)
          }
        } else if (value && typeof value === 'object') {
          for (const [logical, actual] of Object.entries(value as Record<string, unknown>)) {
            if (typeof actual !== 'string' || !isSafeParamName(actual.trim())) continue
            paramHints.push(actual.trim())
            if (isSafeParamName(logical.trim())) paramMap[logical.trim()] = actual.trim()
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
  /** Optional pre-parsed document produced inside `UntrustedComputePool`. */
  parsedDoc?: unknown
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
  const doc = options && 'parsedDoc' in options ? options.parsedDoc : parseJsonOrYaml(rawBody)
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
    if (!isSafeParamName(name)) return
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
    if (attachedHints.has(actualName) || !isSafeParamName(actualName)) return
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

export interface ParsedOpenApiOperation {
  method: string
  pathTemplate: string
  operationId?: string
  security?: Array<Record<string, string[]>>
  authRequirement?: string | null
  parameters?: string[]
  requestBodyKeys?: string[]
  tags?: string[]
}

const OPENAPI_AUTH_HEADER_RE = /^(?:authorization|x-api-key|api-key|x-auth-token|x-access-token)$/i
const SPA_LIFECYCLE_ACTION_RE = /\b(approve|reject|cancel|revoke|demote|promote|transfer|refund|credit|debit|payout|settle|release|publish|archive|export|download|invite|impersonate|grant|webhook|dispute|reopen|checkout|billing|quota|balance|roleUpdate|selfApprove)\b/gi
const SPA_ROLE_GUARD_PATTERNS: readonly RegExp[] = [
  /\b(?:requiredRoles?|allowedRoles?|roles?)\s*[:=]\s*\[\s*([^\]]{1,120})\]/g,
  /\b(?:requiredRole|minRole|roleGuard|allowRole)\s*[:=(]\s*["'`]([A-Za-z0-9_:-]{2,32})["'`]/g,
  /\b(?:hasRole|requireRole|checkRole|isRole)\s*\(\s*["'`]([A-Za-z0-9_:-]{2,32})["'`]/g,
  /\b(?:requiresAdmin|requireAdmin|adminOnly|isAdmin|isOwner|isStaff)\b/g,
]
const GQL_PRIVILEGED_FIELD_RE = /(?:admin|internal|role|grant|revoke|impersonat|secret|key|config|billing|export|audit|delete|mutat|transfer|approve)/i

function normalizeOpenApiSecurity(raw: unknown): Array<Record<string, string[]>> | undefined {
  if (!Array.isArray(raw)) return undefined
  const out: Array<Record<string, string[]>> = []
  for (const item of raw) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue
    const rec: Record<string, string[]> = {}
    for (const [scheme, scopes] of Object.entries(item as Record<string, unknown>)) {
      const cleanScheme = scheme.trim()
      if (!cleanScheme) continue
      rec[cleanScheme] = Array.isArray(scopes)
        ? scopes.filter((s): s is string => typeof s === 'string' && s.trim().length > 0).map(s => s.trim())
        : []
    }
    out.push(rec)
  }
  return out
}

function deriveOpenApiAuthRequirement(
  effectiveSecurity: Array<Record<string, string[]>> | undefined,
  op: Record<string, unknown>,
  opParams: readonly unknown[],
  resolveNode: (node: unknown) => Record<string, unknown> | null,
): string | null {
  if (effectiveSecurity !== undefined) {
    if (effectiveSecurity.length === 0) return 'none'
    const hasEmptyAlt = effectiveSecurity.some(entry => Object.keys(entry).length === 0)
    const parts: string[] = []
    for (const entry of effectiveSecurity) {
      for (const [scheme, scopes] of Object.entries(entry)) {
        const label = scopes.length > 0 ? `${scheme}:${scopes.slice(0, 4).join(',')}` : scheme
        if (!parts.includes(label)) parts.push(label)
      }
    }
    if (parts.length === 0 || hasEmptyAlt) return 'none'
    return parts.join(',').slice(0, 120)
  }

  // Secondary OpenAPI auth extension hints (x-auth-required / x-roles / x-required-roles / required auth header).
  if (op['x-auth-required'] === false || op['x-public'] === true) return 'none'
  const roleExt = op['x-required-roles'] ?? op['x-roles'] ?? op['x-permissions']
  if (Array.isArray(roleExt)) {
    const roles = roleExt.filter((r): r is string => typeof r === 'string' && r.trim().length > 0).map(r => r.trim())
    if (roles.length > 0) return `role:${roles.slice(0, 4).join(',')}`.slice(0, 120)
  } else if (typeof roleExt === 'string' && roleExt.trim()) {
    return `role:${roleExt.trim()}`.slice(0, 120)
  }
  if (op['x-auth-required'] === true) return 'auth_required'
  for (const rawParam of opParams) {
    const rec = resolveNode(rawParam)
    if (!rec) continue
    const inRaw = typeof rec.in === 'string' ? rec.in.toLowerCase() : ''
    const name = typeof rec.name === 'string' ? rec.name.trim() : ''
    if (inRaw === 'header' && OPENAPI_AUTH_HEADER_RE.test(name) && rec.required === true) {
      return `header:${name.toLowerCase()}`
    }
  }
  return null
}

/** Extract structured `RuntimeSpaRoute[]` summaries from a harvested JS bundle + router table. */
export function extractRuntimeSpaRoutesFromJs(
  code: string,
  harvested: {
    routes?: Array<{ path?: string }>
    adminPaths?: string[]
    apiPaths?: string[]
    httpCalls?: Array<{ url?: string; method?: string; bodyKeys?: string[] }>
  },
  origin: string,
  pagePath?: string,
): RuntimeSpaRoute[] {
  const apiCalls: Array<{ method: string; path: string; surface: ReturnType<typeof classifySurface>; serviceOrigin?: string }> = []
  const seenCall = new Set<string>()
  const pushCall = (method: string, rawUrl: string): void => {
    if (apiCalls.length >= 24) return
    let callOrigin: string | undefined
    let cleanPath: string | null = null
    if (/^https?:\/\//i.test(rawUrl.trim())) {
      try {
        const parsed = new URL(rawUrl.trim())
        callOrigin = parsed.origin
        cleanPath = normalizeDiscoveryTemplate(parsed.pathname || '/')
      } catch { /* ignore */ }
    } else {
      const clean = sanitizePathCandidate(rawUrl, origin)
      if (clean && !STATIC_ASSET_RE.test(clean)) cleanPath = normalizeDiscoveryTemplate(clean.split('?')[0] || '/')
    }
    if (!cleanPath || cleanPath === '/') return
    const upper = (method || 'GET').toUpperCase()
    const key = `${callOrigin ?? origin}|${upper}|${cleanPath}`
    if (seenCall.has(key)) return
    seenCall.add(key)
    apiCalls.push({
      method: upper,
      path: cleanPath,
      surface: classifySurface(cleanPath, upper),
      ...(callOrigin && callOrigin !== origin ? { serviceOrigin: callOrigin } : {}),
    })
  }

  for (const call of harvested.httpCalls ?? []) {
    if (call.url) pushCall(call.method || 'GET', call.url)
  }
  for (const p of harvested.apiPaths ?? []) {
    if (/^\/(?:api|rest|graphql|trpc|v\d+|internal|admin)\b/i.test(p)) pushCall('GET', p)
  }
  for (const spec of harvestJsRequestParams(code).slice(0, 24)) {
    pushCall(spec.method, spec.path)
  }

  const bundleRoles = new Set<string>()
  for (const re of SPA_ROLE_GUARD_PATTERNS) {
    re.lastIndex = 0
    for (const m of code.matchAll(re)) {
      if (m[1]) {
        for (const token of m[1].split(',')) {
          const clean = token.replace(/["'`\s]/g, '').trim()
          if (clean && clean.length <= 32) bundleRoles.add(clean)
        }
      } else if (m[0]) {
        const lower = m[0].toLowerCase()
        if (lower.includes('owner')) bundleRoles.add('owner')
        else if (lower.includes('staff')) bundleRoles.add('staff')
        else bundleRoles.add('admin')
      }
      if (bundleRoles.size >= 8) break
    }
  }

  const stateActions = new Set<string>()
  SPA_LIFECYCLE_ACTION_RE.lastIndex = 0
  for (const m of code.matchAll(SPA_LIFECYCLE_ACTION_RE)) {
    if (m[1]) stateActions.add(m[1].toLowerCase())
    if (stateActions.size >= 16) break
  }

  const candidateRoutes = new Set<string>()
  for (const r of harvested.routes ?? []) {
    if (r.path) candidateRoutes.add(r.path)
  }
  for (const p of harvested.adminPaths ?? []) candidateRoutes.add(p)
  for (const p of harvestJsRouteTable(code).slice(0, 24)) candidateRoutes.add(p)
  if (candidateRoutes.size === 0 && pagePath && (apiCalls.length > 0 || stateActions.size > 0 || bundleRoles.size > 0)) {
    candidateRoutes.add(pagePath)
  }

  const out: RuntimeSpaRoute[] = []
  const seenRoute = new Set<string>()
  for (const rawRoute of candidateRoutes) {
    if (out.length >= 24) break
    const clean = sanitizePathCandidate(rawRoute, origin)
    if (!clean || STATIC_ASSET_RE.test(clean)) continue
    const routePath = normalizeDiscoveryTemplate(clean.split('?')[0] || '/')
    if (seenRoute.has(routePath)) continue
    seenRoute.add(routePath)
    // Skip pure API routes when we have UI routes, unless they carry role/lifecycle cues.
    const isAdminOrPriv = isPrivilegedPathTemplate(routePath)
    const routeRoles = new Set<string>()
    if (isAdminOrPriv) {
      if (bundleRoles.size > 0) for (const role of bundleRoles) routeRoles.add(role)
      else routeRoles.add('admin')
    } else if (bundleRoles.size > 0 && apiCalls.length > 0) {
      for (const role of bundleRoles) routeRoles.add(role)
    }
    const matchingCalls = apiCalls.filter(c =>
      c.serviceOrigin
      || c.path === routePath
      || routePath === '/'
      || isAdminOrPriv
      || c.path.toLowerCase().includes((routePath.split('/').filter(Boolean)[0] ?? '').toLowerCase()),
    )
    const attachedCalls = (matchingCalls.length > 0 ? matchingCalls : apiCalls).slice(0, 6)
    const routeActions = [...stateActions].slice(0, 8)
    if (attachedCalls.length === 0 && routeActions.length === 0 && routeRoles.size === 0) continue
    out.push({
      path: routePath,
      serviceOrigin: origin,
      ...(attachedCalls.length > 0 ? { apiCalls: attachedCalls } : {}),
      ...(routeActions.length > 0 ? { stateActions: routeActions } : {}),
      ...(routeRoles.size > 0 ? { requiredRoles: [...routeRoles] } : {}),
    })
  }
  return out
}

/** Extract `RuntimeGraphqlField[]` summaries from JS-harvested GraphQL documents. */
export function extractRuntimeGraphqlFieldsFromJs(
  graphqlDocs: ReadonlyArray<{ kind?: string; name?: string; fields?: string[]; preview?: string }>,
): RuntimeGraphqlField[] {
  const out: RuntimeGraphqlField[] = []
  const seen = new Set<string>()
  for (const doc of graphqlDocs) {
    const rawKind = (doc.kind ?? '').toLowerCase()
    if (rawKind !== 'query' && rawKind !== 'mutation' && rawKind !== 'subscription') continue
    const kind = rawKind as RuntimeGraphqlField['kind']
    const args: string[] = []
    if (typeof doc.preview === 'string') {
      for (const m of doc.preview.matchAll(/\$([A-Za-z_][A-Za-z0-9_]{0,48})/g)) {
        if (m[1] && !args.includes(m[1])) args.push(m[1])
      }
    }
    const fieldNames = Array.isArray(doc.fields) && doc.fields.length > 0
      ? doc.fields
      : doc.name ? [doc.name] : []
    for (const rawName of fieldNames.slice(0, 12)) {
      const name = String(rawName).trim()
      if (!name || name.startsWith('__')) continue
      const key = `${kind}:${name}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push({
        name,
        kind,
        ...(args.length > 0 ? { args: args.slice(0, 12) } : {}),
      })
    }
  }
  return out
}

/** Convert parsed GraphQL introspection / SDL schema into a `RuntimeGraphqlCatalog`. */
export function buildRuntimeGraphqlCatalogFromSchema(
  schema: ReturnType<typeof parseGraphqlIntrospection>,
  endpoint: string,
  serviceOrigin: string,
  options: { defaultRequiresAuth?: boolean } = {},
): RuntimeGraphqlCatalog {
  const fields: RuntimeGraphqlField[] = []
  const seen = new Set<string>()
  const pushRoot = (typeName: string | null | undefined, kind: RuntimeGraphqlField['kind']) => {
    if (!typeName) return
    for (const field of (schema.types[typeName] ?? []).slice(0, 64)) {
      const key = `${kind}:${field.name}`
      if (seen.has(key)) continue
      seen.add(key)
      const privileged = GQL_PRIVILEGED_FIELD_RE.test(field.name)
      fields.push({
        name: field.name,
        kind,
        ...(field.args.length > 0 ? { args: field.args.map(a => a.name).slice(0, 16) } : {}),
        ...(field.returnTypeName ? { returnType: field.returnTypeName } : {}),
        ...(options.defaultRequiresAuth ? { requiresAuth: true } : {}),
        ...(privileged && kind === 'mutation' ? { requiredRole: 'admin' } : {}),
      })
    }
  }
  pushRoot(schema.queryType, 'query')
  pushRoot(schema.mutationType, 'mutation')
  if (schema.types.Subscription) pushRoot('Subscription', 'subscription')
  return {
    endpoint,
    serviceOrigin,
    fields,
  }
}

export function parseOpenApiDoc(
  rawBody: string,
  origin: string,
  storage: Store,
  runId: string,
  scopeRevision: number,
  dynamicPaths: Set<string>,
  dynamicParams: Set<string>,
  options?: { parsedDoc?: unknown },
): { endpoints: number; params: number; operations: ParsedOpenApiOperation[] } {
  const parsed = options && 'parsedDoc' in options ? options.parsedDoc : parseJsonOrYaml(rawBody)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { endpoints: 0, params: 0, operations: [] }
  const doc = parsed as Record<string, unknown>
  const pathsObj = doc.paths
  if (!pathsObj || typeof pathsObj !== 'object' || Array.isArray(pathsObj)) return { endpoints: 0, params: 0, operations: [] }
  let endpoints = 0
  let params = 0
  const operations: ParsedOpenApiOperation[] = []
  const validMethods = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options'])
  const docDefaultSecurity = normalizeOpenApiSecurity(doc.security)

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
    if (!clean || !isSafeParamName(clean)) return
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
    const props: Record<string, unknown> = Object.create(null) as Record<string, unknown>
    const collectProps = (node: Record<string, unknown>, depth: number) => {
      if (depth > 3) return
      if (isRecord(node.properties)) {
        for (const [k, v] of Object.entries(node.properties)) {
          if (!hasPrototypePollutionSegment(k)) props[k] = v
        }
      }
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
      if (!propName || hasPrototypePollutionSegment(propName) || params >= 800) continue
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
      const op = resolveNode(opVal) ?? {}
      const opParams = [...pathLevelParams, ...(Array.isArray(op.parameters) ? op.parameters : [])]
      const effectiveSecurity = op.security !== undefined
        ? normalizeOpenApiSecurity(op.security)
        : docDefaultSecurity
      const authRequirement = deriveOpenApiAuthRequirement(effectiveSecurity, op, opParams, resolveNode)
      const operationId = typeof op.operationId === 'string' && op.operationId.trim()
        ? op.operationId.trim().slice(0, 120)
        : undefined
      const tags = Array.isArray(op.tags)
        ? op.tags.filter((t): t is string => typeof t === 'string' && t.trim().length > 0).map(t => t.trim()).slice(0, 8)
        : undefined
      const ep = storage.upsertEndpoint({
        runId,
        scopeRevision,
        origin,
        method,
        pathTemplate,
        source: 'openapi',
        ...(authRequirement !== null ? { authRequirement } : {}),
        riskScore: scoreEndpointRisk(method, pathTemplate),
      })
      endpoints += 1
      const declared = new Set<string>()
      const requestBodyKeys: string[] = []
      const collectBodyKeys = (schemaNode: unknown, depth = 0): void => {
        if (depth > 2 || requestBodyKeys.length >= 24) return
        const schema = resolveNode(schemaNode)
        if (!schema) return
        if (isRecord(schema.properties)) {
          for (const key of Object.keys(schema.properties)) {
            if (key && !requestBodyKeys.includes(key) && requestBodyKeys.length < 24) requestBodyKeys.push(key)
          }
        }
        if (Array.isArray(schema.allOf)) {
          for (const branch of schema.allOf) collectBodyKeys(branch, depth + 1)
        }
      }
      for (const rawParam of opParams) {
        const rec = resolveNode(rawParam)
        const inRaw = typeof rec?.in === 'string' ? rec.in.toLowerCase() : ''
        if (inRaw === 'body' || inRaw === 'formdata') collectBodyKeys(rec?.schema ?? rec)
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
        collectBodyKeys(media.schema)
        addSchemaParams(media.schema, location, ep.id)
      }
      // OpenAPI path template placeholders that were not declared as parameters.
      for (const match of rawPath.matchAll(/\{([A-Za-z_][A-Za-z0-9_-]{0,63})\}/g)) {
        const name = match[1]
        if (!name || declared.has(name)) continue
        declared.add(name)
        addParam(ep.id, name, 'path')
      }
      operations.push({
        method,
        pathTemplate,
        ...(operationId ? { operationId } : {}),
        ...(effectiveSecurity !== undefined ? { security: effectiveSecurity } : {}),
        ...(authRequirement !== null ? { authRequirement } : {}),
        ...(declared.size > 0 ? { parameters: [...declared].slice(0, 24) } : {}),
        ...(requestBodyKeys.length > 0 ? { requestBodyKeys } : {}),
        ...(tags && tags.length > 0 ? { tags } : {}),
      })
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
/** Generous DoS ceiling on stored project API specs per origin (replaces hard 6-spec drop). */
const MAX_DECLARED_SPECS = 128

export type DeclaredSurfaceSummary = {
  specs: number
  endpoints: number
  params: number
  methods: Record<string, number>
  declaredOpsSeen: number
  declaredOpsMatched: number
  /** Malformed references whose tolerant scan was truncated by the safety cap. */
  declaredTolerantCapped: number
  /** Count of stored API specs dropped because `MAX_DECLARED_SPECS` was exceeded. */
  specsTruncated?: number
  /** Parsed OpenAPI operations (preserving `security` & `operationId`) for runtime invariant synthesis. */
  openApiOperations?: RuntimeOpenApiOperation[]
  /** Parsed GraphQL SDL catalogs from project specs. */
  graphqlCatalogs?: RuntimeGraphqlCatalog[]
}

/**
 * Offline ingestion of the grey-box API reference (OpenAPI/Swagger) that the harness imported for
 * this project. Every declared operation is kept with its declared method — including DELETE,
 * PATCH and body-only POST routes — without requiring an id segment or a known body field.
 * Deduped by (origin, METHOD, pathTemplate). No network request is made here.
 */
async function safeParseJsonOrYamlInWorker(rawBody: string, signal?: AbortSignal): Promise<unknown> {
  try {
    return await parseJsonOrYamlInWorker(rawBody, { signal })
  } catch (err) {
    if (signal?.aborted || err instanceof UntrustedComputeAbortedError) throw err
    return null
  }
}

async function safeExtractHtmlInWorker(html: string, origin: string, signal?: AbortSignal): Promise<ExtractedHtmlSurface> {
  try {
    return await extractHtmlLinksAndScriptsInWorker(html, origin, { signal })
  } catch (err) {
    if (signal?.aborted || err instanceof UntrustedComputeAbortedError) throw err
    return { links: [], scripts: [], forms: [], inputs: [] }
  }
}

async function safeJsHarvestInWorker(
  content: string,
  sourceName: string,
  options?: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  try {
    return await jsHarvestInWorker(content, sourceName, options, { signal })
  } catch (err) {
    if (signal?.aborted || err instanceof UntrustedComputeAbortedError) throw err
    return {}
  }
}

function ingestDeclaredApiSurfaceWithDocs(
  input: {
    storage: Store
    runId: string
    scopeRevision: number
    origin: string
    dynamicPaths?: Set<string>
    dynamicParams?: Set<string>
  },
  preParsedDocs?: ReadonlyMap<number, unknown>,
): DeclaredSurfaceSummary {
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

  if (specs.length > MAX_DECLARED_SPECS) {
    result.specsTruncated = specs.length - MAX_DECLARED_SPECS
    try {
      storage.event(
        runId,
        'phase0.truncation',
        `Declared API specs capped at ${MAX_DECLARED_SPECS} of ${specs.length} for ${origin}.`,
        { category: 'declared_specs', cap: MAX_DECLARED_SPECS, observed: specs.length, dropped: specs.length - MAX_DECLARED_SPECS, origin },
      )
    } catch { /* metrics only */ }
  }
  for (const [specIndex, spec] of specs.slice(0, MAX_DECLARED_SPECS).entries()) {
    const head = spec.content.slice(0, 400)
    if (spec.kind === 'graphql' || /\btype\s+(?:Query|Mutation|Subscription)\s*\{/.test(spec.content)) {
      try {
        const schema = parseGraphqlSdl(spec.content)
        const catalog = buildRuntimeGraphqlCatalogFromSchema(schema, '/graphql', origin)
        if (catalog.fields.length > 0) {
          result.graphqlCatalogs = [...(result.graphqlCatalogs ?? []), catalog]
          storage.upsertEndpoint({
            runId,
            scopeRevision,
            origin,
            method: 'POST',
            pathTemplate: '/graphql',
            source: 'graphql',
            framework: 'graphql',
            riskScore: 85,
          })
          noteDeclared('POST', '/graphql')
        }
      } catch { /* ignore malformed SDL */ }
      if (spec.kind === 'graphql') continue
    }
    const looksOpenApi = /openapi|swagger/i.test(spec.kind)
      || /"(?:openapi|swagger)"\s*:/.test(head)
      || /^\s*openapi\s*:/m.test(head)
    if (!looksOpenApi) continue
    result.specs += 1
    const parsed = preParsedDocs && preParsedDocs.has(specIndex)
      ? parseOpenApiDoc(spec.content, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams, {
          parsedDoc: preParsedDocs.get(specIndex),
        })
      : parseOpenApiDoc(spec.content, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams)
    result.params += parsed.params
    if (parsed.endpoints > 0) {
      // Lossless path: no operation cap. Enumerate exactly what the parser persisted.
      const collected = result.openApiOperations ?? []
      for (const op of parsed.operations) {
        noteDeclared(op.method, op.pathTemplate)
        collected.push({
          method: op.method,
          path: op.pathTemplate,
          serviceOrigin: origin,
          ...(op.operationId ? { operationId: op.operationId } : {}),
          ...(op.security !== undefined ? { security: op.security } : {}),
          ...(op.authRequirement !== undefined ? { authRequirement: op.authRequirement } : {}),
          ...(op.parameters ? { parameters: op.parameters } : {}),
          ...(op.requestBodyKeys ? { requestBodyKeys: op.requestBodyKeys } : {}),
          ...(op.tags ? { tags: op.tags } : {}),
        })
      }
      result.openApiOperations = collected
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
  return ingestDeclaredApiSurfaceWithDocs(input)
}

/** Worker-isolated async variant of `ingestDeclaredApiSurface` parsing OpenAPI docs inside `UntrustedComputePool`. */
export async function ingestDeclaredApiSurfaceAsync(input: {
  storage: Store
  runId: string
  scopeRevision: number
  origin: string
  dynamicPaths?: Set<string>
  dynamicParams?: Set<string>
  signal?: AbortSignal
}): Promise<DeclaredSurfaceSummary> {
  const preParsedDocs = new Map<number, unknown>()
  try {
    const run = input.storage.run(input.runId)
    const wanted = (() => { try { return new URL(input.origin).origin } catch { return input.origin } })()
    const specs = input.storage.listProjectSpecsFull(run.projectId).filter(spec => {
      if (!spec.origin) return true
      try { return new URL(spec.origin).origin === wanted } catch { return false }
    })
    for (const [specIndex, spec] of specs.slice(0, MAX_DECLARED_SPECS).entries()) {
      if (spec.kind === 'graphql') continue
      const head = spec.content.slice(0, 400)
      const looksOpenApi = /openapi|swagger/i.test(spec.kind)
        || /"(?:openapi|swagger)"\s*:/.test(head)
        || /^\s*openapi\s*:/m.test(head)
      if (!looksOpenApi) continue
      preParsedDocs.set(specIndex, await safeParseJsonOrYamlInWorker(spec.content, input.signal))
    }
  } catch (err) {
    if (input.signal?.aborted || err instanceof UntrustedComputeAbortedError) throw err
  }
  return ingestDeclaredApiSurfaceWithDocs(input, preParsedDocs)
}

const PHASE0_ORIGIN_CONCURRENCY = 6
const PHASE0_BROWSER_CONCURRENCY = 3
const PHASE0_INNER_CONCURRENCY = 3
const PHASE0_DEAD_HOST_THRESHOLD = 3
const PHASE0_EDGE_WALL_THRESHOLD = 3
const PHASE0_ORIGIN_DOWN_STATUSES = new Set([520, 521, 522, 523, 524, 525, 526])

const VERCEL_WALL_BODY_RE = /vercel\s+(?:authentication|deployment\s+protection|sso)|_vercel_sso_nonce|authentication\s+required[\s\S]{0,240}vercel|vercel\.com\/sso/i
const VERCEL_WALL_LOCATION_RE = /(?:vercel\.com\/sso|\/_vercel\/sso)/i
const CF_ACCESS_HOST_RE = /\.cloudflareaccess\.com(?:\/|$)/i
const CF_ACCESS_PATH_RE = /\/cdn-cgi\/access\/login/i
const CF_ACCESS_BODY_RE = /cloudflare\s+access|cdn-cgi\/access\/login|cf_authorization|access\s+denied[\s\S]{0,160}cloudflare/i

/**
 * Pure fingerprint for uniform edge-protection authentication walls (Vercel Deployment Protection,
 * Cloudflare Access, Cloud IAP / edge auth proxies). Used by Phase 0 to quarantine edge-walled
 * origins once `>= 3` distinct initial paths return only edge-wall responses with 0 non-wall hits.
 */
function classifyEdgeProtectionWallResponse(
  ex: Pick<BrokerExchangeResult, 'status' | 'respHeaders' | 'body' | 'mediaType' | 'finalOrigin' | 'finalPathAndQuery' | 'redirectOrigins' | 'redirectPaths'>,
): { vendor: EdgeProtectionVendor; reason: string; evidence: string[] } | null {
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries(ex.respHeaders ?? {})) {
    if (typeof v === 'string') headers[k.toLowerCase()] = v
  }
  const server = headers['server'] ?? ''
  const location = headers['location'] ?? ''
  const setCookie = headers['set-cookie'] ?? ''
  const wwwAuth = headers['www-authenticate'] ?? ''
  const bodyHead = (ex.body ?? '').slice(0, 4096)
  const isRedirect = ex.status === 301 || ex.status === 302 || ex.status === 303 || ex.status === 307 || ex.status === 308
  const redirectOrigins = Array.isArray(ex.redirectOrigins) ? ex.redirectOrigins : []
  const redirectPaths = Array.isArray(ex.redirectPaths) ? ex.redirectPaths : []

  // 1. Cloudflare Access (403 CF Access wall or 3xx/followed redirect to *.cloudflareaccess.com or /cdn-cgi/access/login)
  const hitCfAccessRedirect =
    CF_ACCESS_HOST_RE.test(location)
    || CF_ACCESS_PATH_RE.test(location)
    || (ex.finalOrigin ? CF_ACCESS_HOST_RE.test(ex.finalOrigin) : false)
    || (ex.finalPathAndQuery ? CF_ACCESS_PATH_RE.test(ex.finalPathAndQuery) : false)
    || redirectOrigins.some(ro => CF_ACCESS_HOST_RE.test(ro))
    || redirectPaths.some(rp => CF_ACCESS_HOST_RE.test(rp) || CF_ACCESS_PATH_RE.test(rp))
  if (hitCfAccessRedirect) {
    return {
      vendor: 'cloudflare_access',
      reason: `cloudflare_access_redirect_http_${ex.status}`,
      evidence: [
        `status=${ex.status}`,
        ...(location ? [`location=${location.slice(0, 120)}`] : []),
        ...(ex.finalOrigin && CF_ACCESS_HOST_RE.test(ex.finalOrigin) ? [`final_origin=${ex.finalOrigin}`] : []),
      ],
    }
  }
  if (ex.status === 403 && (Boolean(headers['cf-ray']) || /cloudflare/i.test(server)) && CF_ACCESS_BODY_RE.test(bodyHead)) {
    return {
      vendor: 'cloudflare_access',
      reason: 'cloudflare_access_403',
      evidence: [
        'status=403',
        ...(headers['cf-ray'] ? [`cf-ray=${headers['cf-ray'].slice(0, 48)}`] : []),
        ...(server ? [`server=${server.slice(0, 48)}`] : []),
      ],
    }
  }

  // 2. Vercel Deployment Protection (401/403 with x-vercel-id / Vercel SSO cookie / auth wall HTML)
  const hasVercelHeader = Boolean(headers['x-vercel-id'] || headers['x-vercel-error'] || headers['x-vercel-mitigated']) || /vercel/i.test(server)
  const hasVercelWallSignal =
    /_vercel_sso_nonce/i.test(setCookie)
    || /vercel/i.test(wwwAuth)
    || VERCEL_WALL_LOCATION_RE.test(location)
    || VERCEL_WALL_BODY_RE.test(bodyHead)
  if ((ex.status === 401 || ex.status === 403) && (hasVercelWallSignal || (ex.status === 401 && hasVercelHeader && !/json/i.test(ex.mediaType ?? headers['content-type'] ?? '')))) {
    return {
      vendor: 'vercel_deployment_protection',
      reason: `vercel_deployment_protection_${ex.status}`,
      evidence: [
        `status=${ex.status}`,
        ...(headers['x-vercel-id'] ? [`x-vercel-id=${headers['x-vercel-id'].slice(0, 48)}`] : []),
        ...(/_vercel_sso_nonce/i.test(setCookie) ? ['cookie=_vercel_sso_nonce'] : []),
        ...(VERCEL_WALL_BODY_RE.test(bodyHead) ? ['body=vercel_auth_wall'] : []),
      ],
    }
  }
  if (isRedirect && hasVercelHeader && VERCEL_WALL_LOCATION_RE.test(location)) {
    return {
      vendor: 'vercel_deployment_protection',
      reason: `vercel_sso_redirect_${ex.status}`,
      evidence: [`status=${ex.status}`, `location=${location.slice(0, 120)}`],
    }
  }

  // 3. Generic edge auth proxy walls (Google Cloud IAP / AWS WAF edge block)
  if ((ex.status === 401 || ex.status === 403) && (Boolean(headers['x-goog-iap-generated-response']) || Boolean(headers['x-amzn-waf-action']) || Boolean(headers['x-edge-auth']))) {
    return {
      vendor: 'edge_auth_wall',
      reason: `edge_auth_wall_${ex.status}`,
      evidence: [
        `status=${ex.status}`,
        ...(headers['x-goog-iap-generated-response'] ? ['header=x-goog-iap-generated-response'] : []),
        ...(headers['x-amzn-waf-action'] ? [`x-amzn-waf-action=${headers['x-amzn-waf-action'].slice(0, 48)}`] : []),
        ...(headers['x-edge-auth'] ? [`x-edge-auth=${headers['x-edge-auth'].slice(0, 48)}`] : []),
      ],
    }
  }

  return null
}

function resolvePhase0OriginConcurrency(envValue = process.env.KOVO_PHASE0_ORIGIN_CONCURRENCY): number {
  const parsed = Number.parseInt((envValue ?? '').trim(), 10)
  if (Number.isFinite(parsed) && parsed > 0) return Math.max(1, Math.min(parsed, 12))
  return PHASE0_ORIGIN_CONCURRENCY
}

function resolvePhase0BrowserConcurrency(envValue = process.env.KOVO_PHASE0_BROWSER_CONCURRENCY): number {
  const parsed = Number.parseInt((envValue ?? '').trim(), 10)
  if (Number.isFinite(parsed) && parsed > 0) return Math.max(1, Math.min(parsed, 4))
  return PHASE0_BROWSER_CONCURRENCY
}

export interface AdaptivePhase0CapInput {
  hostCount: number
  runBudget?: number
  explicitCap?: number
}

/**
 * Adaptive per-origin request cap for multi-host Phase-0 recon:
 * - 1–5 hosts: full depth (150 at default 1,000 budget, up to 250 when runBudget is large)
 * - 6–15 hosts: smooth taper from 120 down to 100 reqs/origin
 * - 16+ hosts: smooth taper from 80 down to 65 reqs/origin
 * Always honors an explicit positive caller override when provided.
 */
export function computeAdaptivePhase0PerOriginCap(input: AdaptivePhase0CapInput): number {
  if (typeof input.explicitCap === 'number' && Number.isFinite(input.explicitCap) && input.explicitCap > 0) {
    return Math.max(1, Math.floor(input.explicitCap))
  }
  const budget = typeof input.runBudget === 'number' && Number.isFinite(input.runBudget) && input.runBudget > 0
    ? input.runBudget
    : 1000
  const hosts = Math.max(1, Math.floor(Number.isFinite(input.hostCount) ? input.hostCount : 1))
  const baseCap = Math.max(1, Math.min(Math.floor(budget * 0.15), 250))
  if (hosts <= 5) return baseCap
  if (hosts <= 15) {
    const ceiling = Math.round(120 - ((hosts - 6) / 9) * 20)
    return Math.max(1, Math.min(baseCap, ceiling))
  }
  const ceiling = Math.round(80 - Math.min(1, (hosts - 16) / 24) * 15)
  return Math.max(1, Math.min(baseCap, ceiling))
}

function isHtmlLikeResponse(status: number, mediaType: string, body: string): boolean {
  if (status >= 400) return false
  if (/html|xhtml/i.test(mediaType)) return true
  const head = body.slice(0, 1024)
  return /<!doctype\s+html\b|<html\b|<head\b|<body\b|<script\b|<form\b/i.test(head)
}

async function runBoundedPool<T>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<void>,
  shouldStop?: () => boolean,
): Promise<void> {
  if (items.length === 0) return
  const lanes = Math.max(1, Math.min(Math.floor(concurrency), items.length))
  let cursor = 0
  const runLane = async (): Promise<void> => {
    while (true) {
      if (shouldStop?.()) return
      const idx = cursor
      cursor += 1
      if (idx >= items.length) return
      await worker(items[idx]!, idx)
    }
  }
  await Promise.all(Array.from({ length: lanes }, () => runLane()))
}

function createPhase0Semaphore(limit: number) {
  const max = Math.max(1, Math.floor(limit))
  let active = 0
  const waiters: Array<() => void> = []
  return {
    async withPermit<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
      if (signal?.aborted) throw new Error('aborted')
      if (active >= max) {
        await new Promise<void>((resolve, reject) => {
          const wake = () => {
            signal?.removeEventListener('abort', onAbort)
            resolve()
          }
          const onAbort = () => {
            const idx = waiters.indexOf(wake)
            if (idx >= 0) waiters.splice(idx, 1)
            reject(new Error('aborted'))
          }
          signal?.addEventListener('abort', onAbort, { once: true })
          waiters.push(wake)
        })
      }
      active += 1
      try {
        return await fn()
      } finally {
        active -= 1
        const next = waiters.shift()
        if (next) next()
      }
    },
  }
}

/**
 * Zero-LLM Phase-0 deterministic surface mapper (SPEC-v4 §4.3A).
 * Enforces adaptive per-origin request budget (`computeAdaptivePhase0PerOriginCap`),
 * skips live HTTP at Tier 0, runs 11-framework static route extraction, harvests JS/OpenAPI/GraphQL,
 * synthesizes deduplicated dynamic wordlists, and populates SQLite `endpoints` + `endpoint_params`.
 */
export async function runPhase0Recon(params: Phase0ReconParams): Promise<Phase0ReconResult> {
  const { storage, runId, scopeRevision, tier, broker, grant, signal } = params
  const normalizedOrigins: string[] = []
  for (const raw of params.origins) {
    try {
      const o = new URL(raw).origin
      if (!normalizedOrigins.includes(o)) normalizedOrigins.push(o)
    } catch { /* skip malformed */ }
  }
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
  const perOriginCap = computeAdaptivePhase0PerOriginCap({
    hostCount: Math.max(1, normalizedOrigins.length),
    runBudget,
    ...(params.perOriginCap !== undefined ? { explicitCap: params.perOriginCap } : {}),
  })
  // Navigation gets a small overflow lane, but only when the cap is large enough that 16 extra
  // requests cannot violate a deliberately tight budget.
  const navOverflow = perOriginCap >= 40 ? 16 : 0
  const requestTimeoutMs = typeof params.requestTimeoutMs === 'number'
    && Number.isFinite(params.requestTimeoutMs)
    && params.requestTimeoutMs > 0
    ? Math.max(250, Math.min(Math.floor(params.requestTimeoutMs), 30_000))
    : 8_000

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
  // Structured runtime catalogs for grey-box / black-box InvariantSynthesizer parity.
  const runtimeOpenApiMap = new Map<string, RuntimeOpenApiOperation>()
  const runtimeSpaMap = new Map<string, RuntimeSpaRoute>()
  const runtimeGraphqlMap = new Map<string, { endpoint: string; serviceOrigin: string; fields: Map<string, RuntimeGraphqlField> }>()
  const mergeRuntimeOpenApiOp = (op: RuntimeOpenApiOperation): void => {
    const key = `${op.serviceOrigin ?? ''}|${op.method.toUpperCase()}|${op.path}`
    const prev = runtimeOpenApiMap.get(key)
    if (!prev) {
      runtimeOpenApiMap.set(key, { ...op, method: op.method.toUpperCase() })
      return
    }
    runtimeOpenApiMap.set(key, {
      ...prev,
      ...op,
      method: op.method.toUpperCase(),
      operationId: op.operationId ?? prev.operationId,
      security: op.security !== undefined ? op.security : prev.security,
      authRequirement: op.authRequirement ?? prev.authRequirement,
      parameters: op.parameters?.length ? op.parameters : prev.parameters,
      requestBodyKeys: op.requestBodyKeys?.length ? op.requestBodyKeys : prev.requestBodyKeys,
      tags: op.tags?.length ? op.tags : prev.tags,
    })
  }
  const mergeRuntimeSpaRoute = (route: RuntimeSpaRoute): void => {
    if (runtimeSpaMap.size >= 120) return
    const key = `${route.serviceOrigin ?? ''}|${route.path}`
    const prev = runtimeSpaMap.get(key)
    if (!prev) {
      runtimeSpaMap.set(key, { ...route })
      return
    }
    const mergedCalls = [...(prev.apiCalls ?? [])]
    for (const c of route.apiCalls ?? []) {
      if (!mergedCalls.some(x => x.method === c.method && x.path === c.path && x.serviceOrigin === c.serviceOrigin) && mergedCalls.length < 12) {
        mergedCalls.push(c)
      }
    }
    const mergedActions = [...new Set([...(prev.stateActions ?? []), ...(route.stateActions ?? [])])].slice(0, 12)
    const mergedRoles = [...new Set([...(prev.requiredRoles ?? []), ...(route.requiredRoles ?? [])])].slice(0, 8)
    runtimeSpaMap.set(key, {
      path: prev.path,
      ...(prev.serviceOrigin ?? route.serviceOrigin ? { serviceOrigin: prev.serviceOrigin ?? route.serviceOrigin } : {}),
      ...(mergedCalls.length > 0 ? { apiCalls: mergedCalls } : {}),
      ...(mergedActions.length > 0 ? { stateActions: mergedActions } : {}),
      ...(mergedRoles.length > 0 ? { requiredRoles: mergedRoles } : {}),
    })
  }
  const mergeRuntimeGraphqlCatalog = (catalog: RuntimeGraphqlCatalog): void => {
    const endpoint = catalog.endpoint ?? '/graphql'
    const serviceOrigin = catalog.serviceOrigin ?? ''
    const key = `${serviceOrigin}|${endpoint}`
    let bucket = runtimeGraphqlMap.get(key)
    if (!bucket) {
      bucket = { endpoint, serviceOrigin, fields: new Map() }
      runtimeGraphqlMap.set(key, bucket)
    }
    for (const field of catalog.fields) {
      const fKey = `${field.kind}:${field.name}`
      const prev = bucket.fields.get(fKey)
      if (!prev) {
        bucket.fields.set(fKey, { ...field })
      } else {
        bucket.fields.set(fKey, {
          ...prev,
          ...field,
          args: [...new Set([...(prev.args ?? []), ...(field.args ?? [])])].slice(0, 16),
          returnType: field.returnType ?? prev.returnType,
          requiresAuth: prev.requiresAuth || field.requiresAuth,
          requiredRole: field.requiredRole ?? prev.requiredRole,
        })
      }
    }
  }
  // Per-phase paged-read metrics for the discovery planning reads (nav, GraphQL, sibling derivation).
  const readPagedMetrics: PagedReadMetric[] = []
  const skippedDeadHosts: Array<{ origin: string; reason: string; requestsUsed: number }> = []
  const edgeProtectedOrigins: EdgeProtectedOriginRecord[] = []
  let skippedBrowserNonHtml = 0

  // Build or reuse ONE StaticWorkspaceSnapshot per Phase 0 run so manifests, regex fallback routes,
  // and ProgramGraph extraction all read from memory without redundant repo filesystem walks.
  let staticSnapshot: StaticWorkspaceSnapshot | undefined = params.staticSnapshot
  if (!staticSnapshot && params.reposDir && existsSync(params.reposDir)) {
    try {
      staticSnapshot = await getOrBuildStaticWorkspaceSnapshotInWorker(params.reposDir, undefined, {
        maxFiles: 10_000,
        workerTimeoutMs: MULTI_REPO_GRAPH_WORKER_TIMEOUT_MS,
        signal,
      })
    } catch (err) {
      if (signal.aborted || err instanceof UntrustedComputeAbortedError) throw err
      staticSnapshot = undefined
    }
  }

  const truncations: Phase0TruncationRecord[] = []
  const noteTruncation = (category: string, cap: number, observed: number, origin?: string) => {
    recordTruncationEntry(truncations, category, cap, observed, origin)
  }

  type Phase0StageId =
    | 'static_ast'
    | 'host_fingerprint'
    | 'crawl_state_graph'
    | 'api_templates'
    | 'auth_privileged'
    | 'param_discovery'

  const stageRank: Record<Phase0StageId, number> = {
    static_ast: 0,
    host_fingerprint: 1,
    crawl_state_graph: 2,
    api_templates: 3,
    auth_privileged: 4,
    param_discovery: 5,
  }
  let maxStageRankSeen = -1
  let lastStageEmitAt = 0
  const emitPhase0Stage = (
    stage: Phase0StageId,
    label: string,
    opts?: {
      origin?: string
      hostsDone?: number
      hostsTotal?: number
      force?: boolean
      skippedDeadHost?: boolean
      deadHostReason?: string
    },
  ) => {
    const now = Date.now()
    const rank = stageRank[stage]
    const stageAdvanced = rank > maxStageRankSeen
    if (!opts?.force && !stageAdvanced && now - lastStageEmitAt < 1000) return
    if (stageAdvanced) maxStageRankSeen = rank
    lastStageEmitAt = now
    const frameworks = [...frameworksDetected].slice(0, 12)
    storage.event(runId, 'phase0.stage', label, {
      stage,
      label,
      ...(opts?.origin ? { origin: opts.origin } : {}),
      ...(opts?.hostsDone !== undefined ? { hostsDone: opts.hostsDone } : {}),
      ...(opts?.hostsTotal !== undefined ? { hostsTotal: opts.hostsTotal } : {}),
      ...(opts?.skippedDeadHost ? { skippedDeadHost: true } : {}),
      ...(opts?.deadHostReason ? { deadHostReason: opts.deadHostReason } : {}),
      endpointsDiscovered,
      paramsDiscovered,
      requestsUsed,
      ...(frameworks.length > 0 ? { frameworks } : {}),
    })
  }

  // Repo dependency manifests contribute tech tags even when live responses are uninformative
  // (or when Tier 0 sends no requests at all).
  for (const tag of mergeTechTags(techTagsFromManifests(readRepoManifests(params.reposDir ?? '', 200, staticSnapshot)))) {
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
  if ((params.reposDir || staticSnapshot) && normalizedOrigins.length > 0) {
    emitPhase0Stage('static_ast', 'Extracting static routes & workspace program graph.', {
      hostsDone: 0,
      hostsTotal: normalizedOrigins.length,
      force: true,
    })
    const primaryOrigin = normalizedOrigins[0]!
    const regexExtracted = extractStaticFrameworkRoutes(params.reposDir ?? '', staticSnapshot)
    let graphExtraction: RepoProgramGraphExtraction | null = null
    try {
      graphExtraction = await extractRepoProgramGraphInWorker({
        reposDir: params.reposDir,
        origins: normalizedOrigins,
        ...(staticSnapshot ? { staticSnapshot } : {}),
        signal,
      })
    } catch (err) {
      if (signal.aborted || err instanceof UntrustedComputeAbortedError) throw err
      graphExtraction = null
    }
    const regexRoutesWithOrigins = normalizedOrigins.length > 1 && graphExtraction?.originMappings.length
      ? regexExtracted.routes.map(route => {
          if (route.origin || route.originConfidence) return route
          const resolved = resolveRouteOrigin(route.codeLocation.file, graphExtraction.originMappings, normalizedOrigins)
          return {
            ...route,
            ...(resolved.service ? { service: resolved.service } : {}),
            ...(resolved.origin ? { origin: resolved.origin } : {}),
            originConfidence: resolved.confidence,
          }
        })
      : regexExtracted.routes
    const merged = mergeStaticRouteExtractions({
      astRoutes: graphExtraction?.routes ?? [],
      regexRoutes: regexRoutesWithOrigins,
      defaultOrigin: primaryOrigin,
    })
    for (const fw of graphExtraction?.frameworks ?? []) frameworksDetected.add(fw)
    for (const fw of regexExtracted.frameworks) frameworksDetected.add(fw)
    let unmappedRoutes = 0
    for (const route of merged.routes) {
      // Never silently misattribute genuinely unmapped multi-origin microservice routes to origins[0].
      if (normalizedOrigins.length > 1 && route.originConfidence === 'unmapped' && !route.origin) {
        unmappedRoutes += 1
        continue
      }
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
        if (!p.name || hasPrototypePollutionSegment(p.name)) continue
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
    for (const t of graphExtraction?.truncations ?? []) {
      noteTruncation(t.category, t.cap, t.observed, t.origin)
    }
    const extractionWarnings = [
      ...(graphExtraction?.warnings ?? []),
      ...(unmappedRoutes > 0
        ? [`Left ${unmappedRoutes} multi-origin AST route(s) unmapped instead of misattributing to ${primaryOrigin}.`]
        : []),
    ]
    repoStaticExtraction = {
      astRoutes: graphExtraction?.routes.length ?? 0,
      regexFallbackRoutes: regexExtracted.routes.length,
      mergedRoutes: merged.routes.length,
      duplicateRoutes: merged.duplicates,
      ...(unmappedRoutes > 0 ? { unmappedRoutes } : {}),
      frameworks: [...new Set([...(graphExtraction?.frameworks ?? []), ...regexExtracted.frameworks])],
      ...(regexExtracted.serverActions.length > 0 ? { serverActions: regexExtracted.serverActions } : {}),
      originMappings: graphExtraction?.originMappings ?? [],
      routeOrigins: graphExtraction?.routeOrigins ?? {},
      warnings: extractionWarnings,
      ...(graphExtraction?.truncations.length ? { truncations: [...graphExtraction.truncations] } : {}),
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
        ...(regexExtracted.serverActions.length > 0 ? { serverActionsCount: regexExtracted.serverActions.length } : {}),
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
      const part = await ingestDeclaredApiSurfaceAsync({ storage, runId, scopeRevision, origin, dynamicPaths, dynamicParams, signal })
      total.specs += part.specs
      total.endpoints += part.endpoints
      total.params += part.params
      total.declaredOpsSeen += part.declaredOpsSeen
      total.declaredOpsMatched += part.declaredOpsMatched
      total.declaredTolerantCapped += part.declaredTolerantCapped
      if (part.specsTruncated) {
        total.specsTruncated = (total.specsTruncated ?? 0) + part.specsTruncated
        noteTruncation('declared_specs', MAX_DECLARED_SPECS, MAX_DECLARED_SPECS + part.specsTruncated, origin)
      }
      for (const [method, count] of Object.entries(part.methods)) total.methods[method] = (total.methods[method] ?? 0) + count
      for (const op of part.openApiOperations ?? []) mergeRuntimeOpenApiOp(op)
      for (const cat of part.graphqlCatalogs ?? []) mergeRuntimeGraphqlCatalog(cat)
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
  const siblingDerivationRequested = /^(?:1|true|on|yes)$/i.test((process.env.KOVO_RECON_SIBLINGS ?? '').trim())
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
    noteTruncation('dynamic_wordlist_paths', 500, dynamicPaths.size)
    noteTruncation('dynamic_wordlist_params', 250, dynamicParams.size)
    if (truncations.length > 0) {
      storage.event(runId, 'phase0.truncation', `Phase-0 hit ${truncations.length} finite discovery cap(s).`, { truncations })
    }
    storage.event(runId, 'phase0.discovery', 'Phase-0 discovery counts (static only).', {
      requestsUsed: 0,
      perOriginCap,
      endpointsDiscovered,
      paramsDiscovered,
      frameworksDetected: [...frameworksDetected],
      ...(truncations.length > 0 ? { truncations } : {}),
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
        paths: [...dynamicPaths].slice(0, 500),
        params: [...dynamicParams].slice(0, 250),
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
      ...(truncations.length > 0 ? { truncations } : {}),
    }
  }

  // 2. Live Black-Box / Grey-Box Pass (100% through RequestBroker, bounded multi-host pool)
  const hostsTotal = normalizedOrigins.length
  const originConcurrency = resolvePhase0OriginConcurrency()
  const browserConcurrency = resolvePhase0BrowserConcurrency()
  const browserSemaphore = createPhase0Semaphore(browserConcurrency)
  let hostsDone = 0
  let hostsStarted = 0

  await runBoundedPool(normalizedOrigins, originConcurrency, async (origin, originIndex) => {
    if (signal.aborted) {
      stoppedReason = 'aborted'
      return
    }
    if (!grant.canRead(origin)) {
      stoppedReason = 'scope_revoked'
      hostsDone += 1
      return
    }

    hostsStarted += 1
    emitPhase0Stage(
      'host_fingerprint',
      `Fingerprinting ${origin} (${hostsStarted}/${hostsTotal}).`,
      {
        origin,
        hostsDone,
        hostsTotal,
        force: hostsStarted === 1,
      },
    )

    let originUsed = 0
    let consecutiveDeadResponses = 0
    let healthyResponses = 0
    let htmlResponsesObserved = 0
    let deadHostReason: string | null = null
    const edgeWallDistinctPaths = new Set<string>()
    let edgeWallMatch: { vendor: EdgeProtectionVendor; reason: string; status: number; evidence: string[] } | null = null
    let nonEdgeWallResponses = 0
    let edgeProtectedRecord: EdgeProtectedOriginRecord | null = null
    let originNavigationRequests = 0
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
    const rejectedPersonas = new Set<string>()
    let softCalibration: SoftNotFoundCalibration | null = null
    let protectedPathsObserved = 0
    let jsonDocsObserved = 0
    let candidatePathsObserved = 0
    let templatesObserved = 0
    let jsQueueObserved = 0
    let jsRoutesObserved = 0
    let jsReqParamsObserved = 0
    let jsRouteTableObserved = 0
    let trpcProcsObserved = 0
    const MAX_PROTECTED_PATHS = 48
    const MAX_JSON_DOCS = 24
    const MAX_CANDIDATE_PATHS = 160
    const MAX_DISCOVERED_TEMPLATES = 96
    const MAX_JS_QUEUE = 128
    const MAX_JS_CHUNKS_FETCH = 96
    const MAX_JS_ROUTES_PER_CHUNK = 400
    const MAX_JS_REQ_PARAMS_PER_CHUNK = 120
    const MAX_JS_ROUTE_TABLE_PER_CHUNK = 120
    const MAX_TRPC_PROCS_PER_CHUNK = 120

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

    const recordEndpoint = (
      method: string,
      rawPath: string,
      source: EndpointSource,
      extra?: { framework?: string | null; riskScore?: number; authRequirement?: string | null; targetOrigin?: string },
    ) => {
      const epOrigin = extra?.targetOrigin ?? origin
      const pathTemplate = /(?:^|\/):[A-Za-z_][A-Za-z0-9_-]*/.test(rawPath)
        ? normalizeDiscoveryTemplate(rawPath)
        : normalizeRouteTemplate(rawPath)
      const ep = storage.upsertEndpoint({
        runId,
        scopeRevision,
        origin: epOrigin,
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

    const personaForOrigin = (handle: string | undefined): string | undefined => {
      if (!handle || rejectedPersonas.has(handle)) return undefined
      const persona = grant.personas?.get(handle)
      if (!persona) return undefined
      return persona.originAllowlist.includes(origin) ? handle : undefined
    }
    const nextUsablePersona = (): string | undefined => {
      for (const handle of params.personas ?? []) {
        const candidate = personaForOrigin(handle)
        if (candidate) return candidate
      }
      return undefined
    }
    const isPersonaWideAuthInvalidation = (message: string): boolean =>
      /(?:unknown persona|persona\b[^.\n]{0,60}\b(?:not registered|revoked|invalid|not allowed for origin|not permitted for origin)|originAllowlist|session\b[^.\n]{0,60}\b(?:expired|revoked|invalidated|terminated|not found)|credential\b[^.\n]{0,60}\b(?:expired|revoked|invalidated|missing))/i.test(message)
    // All discovery fetches carry the approved owner session when one is available, so the SPA
    // shell, API listings, config documents and OpenAPI specs behind login are visible.
    let discoveryPersona = nextUsablePersona()

    const harvestRedirectHop = (hopOrigin: string, targetUrl: URL): void => {
      if (hopOrigin !== origin && !grant.canRead(hopOrigin)) return
      const targetPath = targetUrl.pathname || '/'
      if (!targetPath.startsWith('/') || targetPath.startsWith('//')) return
      if (/[\r\n\0]/.test(targetPath) || STATIC_ASSET_RE.test(targetPath)) return
      const targetTmpl = normalizeDiscoveryTemplate(targetPath)
      const queryNames = [...targetUrl.searchParams.keys()].filter(name => isSafeParamName(name))
      if (hopOrigin === origin) {
        const evidence = evidenceFor(targetTmpl)
        for (const name of queryNames) {
          evidence.redirectQuery.add(name)
          dynamicParams.add(name)
        }
      } else {
        for (const name of queryNames) dynamicParams.add(name)
      }
      if (targetPath !== '/' || queryNames.length > 0) {
        const ep = recordEndpoint('GET', targetPath, 'surface_probe', { targetOrigin: hopOrigin })
        for (const name of queryNames) {
          storage.upsertEndpointParam({
            runId,
            endpointId: ep.id,
            name,
            location: 'query',
            inferredType: 'string',
            isCsrf: CSRF_PARAM_RE.test(name),
            isObjectId: OBJECT_ID_PARAM_RE.test(name),
            source: 'observed:redirect_query',
          })
          paramsDiscovered += 1
        }
      }
    }

    // Bounded secret-free structural signals (JSON keys, workflow headers, 202 status) per route template.
    const producerResponseSignals = new Map<string, { method: string; template: string; signals: Map<string, ResponseSignalEdgeKind> }>()
    // Calibrated protected/API path hints for safe-template path variables (`{{discovered_*_path}}`)
    // plus wire-observed redirect query harvesting across BOTH 3xx Location headers and followed
    // `ex.redirectPaths` / `ex.redirectOrigins` hops.
    const noteDiscoveryResponse = (ex: BrokerExchangeResult): void => {
      const method = ex.method.toUpperCase()
      const bare = ex.pathAndQuery.split('?')[0] || '/'
      if (!bare.startsWith('/') || bare.startsWith('//')) return
      if (/[:{}[\]]/.test(bare) || /[\r\n\0]/.test(bare) || STATIC_ASSET_RE.test(bare)) return
      // Secret-free structural response harvesting across all 2xx/202 responses (JSON keys + headers).
      if (ex.status >= 200 && ex.status < 300 && producerResponseSignals.size < 120) {
        const extractedSignals = extractResponseStructuralSignals(ex, 24)
        if (extractedSignals.length > 0) {
          const tmpl = normalizeDiscoveryTemplate(bare)
          const sigKey = `${method} ${tmpl}`
          let bucket = producerResponseSignals.get(sigKey)
          if (!bucket) {
            bucket = { method, template: tmpl, signals: new Map() }
            producerResponseSignals.set(sigKey, bucket)
          }
          for (const sig of extractedSignals) {
            if (bucket.signals.size >= 24) break
            if (!bucket.signals.has(sig.field)) bucket.signals.set(sig.field, sig.edgeKind)
          }
        }
      }
      if (method !== 'GET' && method !== 'HEAD') return
      const is3xx = [301, 302, 303, 307, 308].includes(ex.status)
      const redirectPaths = Array.isArray(ex.redirectPaths) ? ex.redirectPaths : []
      const redirectOrigins = Array.isArray(ex.redirectOrigins) && ex.redirectOrigins.length > 0
        ? ex.redirectOrigins
        : [origin]
      const finalBare = (ex.finalPathAndQuery ?? ex.pathAndQuery).split('?')[0] || '/'
      const redirectedToDifferentPath = redirectPaths.length > 0
        && ((ex.finalOrigin && ex.finalOrigin !== origin)
          || (bare.replace(/\/+$/, '') || '/') !== (finalBare.replace(/\/+$/, '') || '/'))
      if (is3xx || ex.status === 401 || ex.status === 403 || redirectedToDifferentPath) {
        if (!protectedPaths.has(bare)) {
          protectedPathsObserved += 1
          if (protectedPaths.size < MAX_PROTECTED_PATHS) protectedPaths.add(bare)
        }
      }
      // Parameter evidence the crawler already holds. Bounded and passive: no extra requests.
      if (ex.status >= 200 && ex.status < 300 && /json/i.test(ex.mediaType) && ex.body.length <= 262_144) {
        const fields = extractJsonFieldNames(ex.body, 32)
        if (fields.length > 0) {
          const evidence = evidenceFor(normalizeDiscoveryTemplate(bare))
          for (const field of fields) evidence.fields.add(field)
        }
      }
      // Harvest redirect targets & query params across all followed in-scope redirect hops
      // (fixes dead 3xx harvesting when `safeGet` follows redirects to a final `200`).
      const allSameOrigin = redirectOrigins.every(ro => ro === origin)
      const allInScope = redirectOrigins.every(ro => ro === origin || grant.canRead(ro))
      for (let i = 0; i < redirectPaths.length; i += 1) {
        const hop = redirectPaths[i]
        if (typeof hop !== 'string' || hop.length > 2048) continue
        const isLastHop = i === redirectPaths.length - 1
        try {
          if (/^https?:\/\//i.test(hop)) {
            const target = new URL(hop)
            if (target.origin === origin || grant.canRead(target.origin)) {
              harvestRedirectHop(target.origin, target)
            }
          } else if (allSameOrigin) {
            const target = new URL(hop, origin)
            harvestRedirectHop(origin, target)
          } else if (isLastHop && ex.finalOrigin && (ex.finalOrigin === origin || grant.canRead(ex.finalOrigin))) {
            const target = new URL(hop, ex.finalOrigin)
            harvestRedirectHop(ex.finalOrigin, target)
          } else if (allInScope) {
            // Intermediate cross-origin hop within approved scope: attribute to the best matching
            // in-scope redirect origin (preferring secondary origin if present, else final/initial).
            const secondary = redirectOrigins.find(ro => ro !== origin && grant.canRead(ro))
            const hopOrigin = secondary ?? (ex.finalOrigin && grant.canRead(ex.finalOrigin) ? ex.finalOrigin : origin)
            const target = new URL(hop, hopOrigin)
            harvestRedirectHop(hopOrigin, target)
          }
        } catch { /* malformed redirect hop */ }
      }
      // Also capture a final 3xx Location header (when followRedirects is false or hop cap hit).
      if (is3xx) {
        const location = ex.respHeaders?.location ?? ex.respHeaders?.Location
        if (typeof location === 'string' && location.length <= 2048) {
          try {
            const target = new URL(location, ex.finalOrigin || origin)
            if (target.origin === origin || grant.canRead(target.origin)) {
              harvestRedirectHop(target.origin, target)
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
          timeoutMs: requestTimeoutMs,
        }, grant, signal)
        if (persona) authRequests += 1
        const edgeWall = classifyEdgeProtectionWallResponse(ex)
        if (edgeWall && nonEdgeWallResponses === 0) {
          const bareProbePath = (pathAndQuery.split('?')[0] || '/').replace(/\/+$/, '') || '/'
          edgeWallDistinctPaths.add(bareProbePath)
          edgeWallMatch ??= { ...edgeWall, status: ex.status }
          if (edgeWallDistinctPaths.size >= PHASE0_EDGE_WALL_THRESHOLD) {
            originHalted = true
            edgeProtectedRecord ??= {
              origin,
              vendor: edgeWallMatch.vendor,
              reason: edgeWallMatch.reason,
              status: edgeWallMatch.status,
              probesObserved: edgeWallDistinctPaths.size,
              requestsUsed: originUsed,
              evidence: edgeWallMatch.evidence,
            }
          }
        } else if (!edgeWall) {
          nonEdgeWallResponses += 1
        }
        if (ex.status < 500) {
          healthyResponses += 1
          consecutiveDeadResponses = 0
          if (!edgeWall && isHtmlLikeResponse(ex.status, ex.mediaType, ex.body)) {
            htmlResponsesObserved += 1
          }
        } else if (PHASE0_ORIGIN_DOWN_STATUSES.has(ex.status)) {
          consecutiveDeadResponses += 1
          if (healthyResponses === 0 && consecutiveDeadResponses >= PHASE0_DEAD_HOST_THRESHOLD) {
            originHalted = true
            deadHostReason ??= `origin_down_http_${ex.status}`
          }
        }
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
          if (!stoppedReason) stoppedReason = 'circuit_open'
          return null
        }
        if (err instanceof BrokerDenied) {
          if (!grant.canRead(origin)) {
            originHalted = true
            stoppedReason = 'scope_revoked'
            return null
          }
          if (persona) {
            // Only retire a persona for the origin on genuine persona-wide auth invalidation
            // (revoked/expired/not-registered/disallowed-for-origin). On any single-request denial
            // (e.g., route policy or single-endpoint session restriction), keep `discoveryPersona`
            // intact for subsequent requests and fall back to anonymous ONLY for this request.
            if (isPersonaWideAuthInvalidation(err.message)) {
              rejectedPersonas.add(persona)
              if (discoveryPersona === persona) {
                discoveryPersona = nextUsablePersona()
              }
            }
            return safeGet(pathAndQuery, { ...opts, anonymous: true })
          }
          return null
        }
        if (!signal.aborted) {
          consecutiveDeadResponses += 1
          if (healthyResponses === 0 && consecutiveDeadResponses >= PHASE0_DEAD_HOST_THRESHOLD) {
            originHalted = true
            const errMsg = err instanceof Error ? err.message : String(err)
            deadHostReason ??= /timeout|abort/i.test(errMsg) ? 'transport_timeout' : 'transport_error'
          }
        }
        return null
      }
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
      if (paramList.length > 64) noteTruncation('endpoint_params_batch', 64, paramList.length, origin)
      for (const p of paramList.slice(0, 64)) {
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
      if (jsonDocCandidates.includes(cleanPath)) return
      jsonDocsObserved += 1
      if (jsonDocCandidates.length >= MAX_JSON_DOCS) return
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
        if (!discoveredTemplates.includes(template)) {
          templatesObserved += 1
          if (discoveredTemplates.length < MAX_DISCOVERED_TEMPLATES) {
            discoveredTemplates.push(template)
            // The collection that produces ids for the detail route is worth probing on its own.
            const base = template.replace(/\/:[A-Za-z_][A-Za-z0-9_-]*.*$/, '')
            if (base && base !== template && !/[:{}[\]]/.test(base)) queueDiscoveredRoute('GET', base)
          }
        }
        return
      }
      if (discoveredCandidatePaths.includes(clean)) return
      candidatePathsObserved += 1
      if (discoveredCandidatePaths.length >= MAX_CANDIDATE_PATHS) return
      discoveredCandidatePaths.push(clean)
    }

    const queueJsChunk = (specifier: string, fromPath = '/') => {
      const clean = sanitizePathCandidate(specifier, `${origin}${fromPath}`)
      if (!clean || STATIC_ASSET_RE.test(clean)) return
      if (!/\.(?:m?js|jsx|ts|tsx)(?:\?|$)/i.test(clean)) return
      if (jsQueue.includes(clean)) return
      jsQueueObserved += 1
      if (jsQueue.length >= MAX_JS_QUEUE) return
      jsQueue.push(clean)
    }

    const softNotFoundResponse = (ex: BrokerExchangeResult): boolean =>
      ex.status >= 200 && ex.status < 300 && Boolean(softCalibration && isSoftNotFound(softCalibration, ex))

    // 2a. Standard seed probes. Reserve a small slice of the per-origin cap for JS chunk
    // harvesting, otherwise a long seed list can starve the bundles that carry XHR/route evidence.
    const jsReserve = perOriginCap > 4 ? Math.min(4, Math.floor(perOriginCap / 3)) : 0
    const seedBudget = Math.max(1, perOriginCap - jsReserve)

    const shortCircuitIfDeadHost = (): boolean => {
      if (!originHalted) return false
      if (edgeProtectedRecord) {
        const record: EdgeProtectedOriginRecord = { ...edgeProtectedRecord, requestsUsed: originUsed }
        edgeProtectedOrigins.push(record)
        storage.event(
          runId,
          'phase0.edge_protected',
          `Origin ${origin} returned uniform edge-protection wall (${record.vendor}; HTTP ${record.status} across ${record.probesObserved} distinct paths); quarantined.`,
          { ...record },
        )
        hostsDone += 1
        emitPhase0Stage(
          'host_fingerprint',
          `Quarantined edge-protected host ${origin} (${record.vendor}; ${originUsed} reqs) (${hostsDone}/${hostsTotal}).`,
          {
            origin,
            hostsDone,
            hostsTotal,
            force: true,
          },
        )
        return true
      }
      if (!deadHostReason) return false
      skippedDeadHosts.push({ origin, reason: deadHostReason, requestsUsed: originUsed })
      hostsDone += 1
      emitPhase0Stage(
        'host_fingerprint',
        `Skipped dead/unreachable host ${origin} (${deadHostReason}; ${originUsed} reqs) (${hostsDone}/${hostsTotal}).`,
        {
          origin,
          hostsDone,
          hostsTotal,
          force: true,
          skippedDeadHost: true,
          deadHostReason,
        },
      )
      return true
    }

    const processRootSurface = async (status: number, mediaType: string, respHeaders: Record<string, string>, body: string, fromRecovery: boolean): Promise<void> => {
      if (status < 500) {
        if (fromRecovery) {
          healthyResponses += 1
          consecutiveDeadResponses = 0
        }
        if (fromRecovery && isHtmlLikeResponse(status, mediaType, body)) {
          htmlResponsesObserved += 1
        }
      }
      for (const t of mergeTechTags(techTagsFromResponse(respHeaders, body))) techFingerprint.add(t)
      if (status < 400) {
        recordEndpoint('GET', '/', 'surface_probe')
        if (fromRecovery) {
          tagVisibility('GET', '/', 'anonymous')
          if (discoveryPersona) tagVisibility('GET', '/', discoveryPersona)
        } else {
          tagVisibility('GET', '/', discoveryPersona ?? 'anonymous')
        }
      }
      const html = await safeExtractHtmlInWorker(body, origin, signal)
      for (const s of html.scripts) {
        queueJsChunk(s, '/')
        jsPageByScript.set(s, '/')
      }
      for (const asset of extractAssetReferences(body)) {
        if (/\.json(?:$|[?#])/i.test(asset)) queueJsonDoc(asset)
        else queueJsChunk(asset, '/')
      }
      if (html.links.length > 160) noteTruncation('html_links', 160, html.links.length, origin)
      for (const l of html.links.slice(0, 160)) {
        dynamicPaths.add(normalizeRouteTemplate(l))
        if (discoveredCandidatePaths.length < MAX_CANDIDATE_PATHS) discoveredCandidatePaths.push(l)
        else candidatePathsObserved += 1
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
    }

    // 2a-root. Fetch or recover site root `GET /` first so dead/525 hosts are detected alongside
    // soft-404 calibration in <= 3 requests before spending seed, JS, template, or browser budget.
    if (!originHalted && originUsed < perOriginCap && !signal.aborted && seedBudget >= 1) {
      let recoveredRoot = false
      try {
        // On crash recovery, reuse any already-recorded GET / for this (runId, origin) so the
        // baseline is never duplicated across SIGKILL + resume. Scope revisions can advance while
        // paused, so the revision is intentionally not part of the reuse key; the live grant still
        // gates whether the origin may be read.
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
          await processRootSurface(prior.status, prior.mediaType ?? '', headersObj, prior.bodyPreview ?? '', true)
          recoveredRoot = true
        }
      } catch { /* fall through to live GET / */ }
      if (!recoveredRoot) {
        let rootEx = await safeGet('/')
        if (rootEx && (rootEx.status === 401 || rootEx.status === 403) && params.personas?.length) {
          for (const handle of params.personas) {
            if (!personaForOrigin(handle)) continue
            if (originHalted || originUsed >= perOriginCap) break
            rootEx = await safeGet('/', { persona: handle })
            if (rootEx && rootEx.status < 400) break
          }
        }
        if (rootEx && !(edgeWallMatch && nonEdgeWallResponses === 0)) {
          await processRootSurface(rootEx.status, rootEx.mediaType, rootEx.respHeaders, rootEx.body, false)
        }
      }
    }

    // 2a-cal. Per-origin soft-404 / SPA catch-all calibration with several unmatched paths at
    // different depths (root-only calibration misses nested API catch-alls). When the root already
    // answered healthily, run calibration probes concurrently; when root failed/timed out/525'd,
    // probe sequentially so dead hosts halt at exactly PHASE0_DEAD_HOST_THRESHOLD (3) requests.
    if (!originHalted && !signal.aborted && originUsed + 1 < perOriginCap) {
      const cal: SoftNotFoundCalibration = { statuses: [], mediaTypes: [], lengths: [], signatures: [] }
      const probeCount = Math.min(3, Math.max(1, perOriginCap - originUsed - 1))
      const calPaths = buildSoft404ProbePaths(probeCount)
      const calConcurrency = (healthyResponses > 0 && !(edgeWallMatch && nonEdgeWallResponses === 0))
        ? Math.min(PHASE0_INNER_CONCURRENCY, calPaths.length)
        : 1
      await runBoundedPool(
        calPaths,
        calConcurrency,
        async probePath => {
          if (originHalted || signal.aborted || originUsed >= perOriginCap) return
          const ex = await safeGet(probePath)
          if (!ex) return
          cal.statuses.push(ex.status)
          cal.mediaTypes.push(ex.mediaType)
          cal.lengths.push(ex.body.length)
          cal.signatures.push(bodyStructuralSignature(ex.body))
        },
        () => originHalted || signal.aborted || originUsed >= perOriginCap,
      )
      if (cal.statuses.length > 0) softCalibration = cal
    }

    if (shortCircuitIfDeadHost()) return

    // 2a-seeds. Probe remaining read-only seed paths in a bounded inner pool.
    const remainingSeeds = PHASE0_SEED_PATHS.slice(1, Math.max(1, seedBudget))
    const seedPoolConcurrency = healthyResponses > 0 ? PHASE0_INNER_CONCURRENCY : 1
    await runBoundedPool(
      remainingSeeds,
      seedPoolConcurrency,
      async seedPath => {
        if (originHalted || originUsed >= perOriginCap || signal.aborted) return
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
        if (!ex) return

        if (seedPath === '/robots.txt' && ex.status < 400) {
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
          const specDoc = await safeParseJsonOrYamlInWorker(ex.body, signal)
          const parsed = parseOpenApiDoc(ex.body, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams, { parsedDoc: specDoc })
          endpointsDiscovered += parsed.endpoints
          paramsDiscovered += parsed.params
          for (const op of parsed.operations) {
            mergeRuntimeOpenApiOp({
              method: op.method,
              path: op.pathTemplate,
              serviceOrigin: origin,
              ...(op.operationId ? { operationId: op.operationId } : {}),
              ...(op.security !== undefined ? { security: op.security } : {}),
              ...(op.authRequirement !== undefined ? { authRequirement: op.authRequirement } : {}),
              ...(op.parameters ? { parameters: op.parameters } : {}),
              ...(op.requestBodyKeys ? { requestBodyKeys: op.requestBodyKeys } : {}),
              ...(op.tags ? { tags: op.tags } : {}),
            })
          }
          if (parsed.endpoints > 0) {
            if (specDoc && typeof specDoc === 'object') {
              for (const entry of harvestRouteMapDocument(specDoc).slice(0, 120)) {
                queueDiscoveredRoute(entry.method, entry.path)
              }
            }
          }
          if (parsed.endpoints === 0) {
            // Swagger-less API index documents are handled by the structural route-map expander.
            const expanded = parseRouteMapDoc(ex.body, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams, { bindings: configBindings, parsedDoc: specDoc })
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
            return
          }
          recordEndpoint('GET', seedPath, 'surface_probe')
          // Any served JSON/YAML document may be a route map or config with an endpoint table.
          if (/json|yaml/i.test(ex.mediaType) || /^\s*[{[]/.test(ex.body)) {
            try {
              const doc = await safeParseJsonOrYamlInWorker(ex.body, signal)
              const parsed = parseRouteMapDoc(ex.body, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams, { bindings: configBindings, parsedDoc: doc })
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
      },
      () => originHalted || originUsed >= perOriginCap || signal.aborted,
    )

    if (shortCircuitIfDeadHost()) return

    // 2b. Fetch same-origin JS chunks in a bounded concurrent BFS pool. The queue is drained
    // breadth-first (imports, manifests, webpack/Vite chunk maps) within a scaled 96-bundle budget;
    // seed probes reserved jsReserve.
    const maxJsChunks = Math.min(MAX_JS_CHUNKS_FETCH, Math.max(0, perOriginCap - originUsed))
    if (!originHalted && !signal.aborted && jsQueue.length > 0 && maxJsChunks > 0) {
      emitPhase0Stage(
        'crawl_state_graph',
        `Harvesting client bundles & routes on ${origin} (${originIndex + 1}/${hostsTotal}).`,
        { origin, hostsDone, hostsTotal },
      )
    }
    let jsFetched = 0
    let jsCursor = 0
    let jsInFlight = 0
    const jsWaiters: Array<() => void> = []
    const wakeJsWaiters = () => {
      while (jsWaiters.length > 0) jsWaiters.shift()?.()
    }
    const processJsChunk = async (jsPath: string): Promise<void> => {
      if (originHalted || originUsed >= perOriginCap || signal.aborted || jsFetched >= maxJsChunks) return
      const ex = await safeGet(jsPath)
      if (!ex || ex.status >= 400 || !ex.body) return
      jsFetched += 1

      const harvested = await safeJsHarvestInWorker(ex.body, `${origin}${jsPath}`, undefined, signal) as {
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
        jsRoutesObserved += 1
        if (seenJsRoutes.size >= MAX_JS_ROUTES_PER_CHUNK) return null
        const ep = recordEndpoint(method, tmpl, 'js_ast')
        seenJsRoutes.set(key, ep.id)
        if (method.toUpperCase() === 'GET' && (/\.json$/i.test(clean) || /(?:^|\/)(?:config|routes|route-map|manifest|endpoints|links|nav|menu|bootstrap)(?:\.|$)/i.test(clean))) {
          queueJsonDoc(clean)
        }
        for (const bk of bodyKeys.slice(0, 48)) {
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
      const reqParamSpecs = harvestJsRequestParams(ex.body)
      jsReqParamsObserved = Math.max(jsReqParamsObserved, reqParamSpecs.length)
      for (const spec of reqParamSpecs.slice(0, MAX_JS_REQ_PARAMS_PER_CHUNK)) {
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
      const routeTablePaths = harvestJsRouteTable(ex.body)
      jsRouteTableObserved = Math.max(jsRouteTableObserved, routeTablePaths.length)
      for (const routePath of routeTablePaths.slice(0, MAX_JS_ROUTE_TABLE_PER_CHUNK)) {
        if (addJsEndpoint('GET', routePath)) jsRouterRoutes += 1
      }
      // Emit structured SPA route summaries (route -> API calls + client roles + lifecycle actions).
      for (const spaRoute of extractRuntimeSpaRoutesFromJs(ex.body, harvested, origin, jsPageByScript.get(jsPath))) {
        mergeRuntimeSpaRoute(spaRoute)
      }
      // tRPC procedures: batched GET uses a query `input`, mutations POST a JSON `input`.
      const trpcProcs = harvestTrpcProcedures(ex.body)
      trpcProcsObserved = Math.max(trpcProcsObserved, trpcProcs.length)
      for (const proc of trpcProcs.slice(0, MAX_TRPC_PROCS_PER_CHUNK)) {
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
        const jsGqlFields = extractRuntimeGraphqlFieldsFromJs(harvested.graphqlDocs ?? [])
        if (jsGqlFields.length > 0) {
          mergeRuntimeGraphqlCatalog({ endpoint: '/graphql', serviceOrigin: origin, fields: jsGqlFields })
        }
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
            const mapHarvest = await safeJsHarvestInWorker(mapEx.body, `${origin}${mapPath}`, { sourceMapContent: mapEx.body }, signal) as {
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
    if (!originHalted && !signal.aborted && jsQueue.length > 0 && maxJsChunks > 0) {
      const jsLanes = Math.min(PHASE0_INNER_CONCURRENCY, Math.max(1, maxJsChunks))
      const runJsLane = async (): Promise<void> => {
        while (true) {
          if (originHalted || originUsed >= perOriginCap || signal.aborted || jsFetched >= maxJsChunks) return
          if (jsCursor >= jsQueue.length) {
            if (jsInFlight === 0) return
            await new Promise<void>(resolve => jsWaiters.push(resolve))
            continue
          }
          const idx = jsCursor
          jsCursor += 1
          const jsPath = jsQueue[idx]
          if (!jsPath) continue
          jsInFlight += 1
          try {
            await processJsChunk(jsPath)
          } finally {
            jsInFlight -= 1
            wakeJsWaiters()
          }
        }
      }
      await Promise.all(Array.from({ length: jsLanes }, () => runJsLane()))
    }

    // 2b-bis. Fetch same-origin JSON/YAML route-map & config artifacts referenced by the SPA
    // (runtime config, API index, Vite/webpack manifests) in a bounded inner pool.
    const uniqueJsonDocs = [...new Set(jsonDocCandidates)]
    if (uniqueJsonDocs.length > 16) noteTruncation('json_doc_fetches', 16, uniqueJsonDocs.length, origin)
    await runBoundedPool(
      uniqueJsonDocs.slice(0, 16),
      PHASE0_INNER_CONCURRENCY,
      async docPath => {
        if (originHalted || originUsed >= perOriginCap - 4 || signal.aborted) return
        const ex = await safeGet(docPath)
        if (!ex || ex.status >= 400 || !ex.body) return
        if (softNotFoundResponse(ex)) { soft404Rejected += 1; return }
        const isStructured = /json|yaml/i.test(ex.mediaType) || /^\s*[{[]/.test(ex.body)
        if (!isStructured) {
          // A manifest-like JS body: follow the chunk references it lists.
          for (const asset of extractAssetReferences(ex.body)) queueJsChunk(asset, docPath)
          return
        }
        const doc = await safeParseJsonOrYamlInWorker(ex.body, signal)
        const expanded = parseRouteMapDoc(ex.body, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams, { bindings: configBindings, parsedDoc: doc })
        endpointsDiscovered += expanded.endpoints
        paramsDiscovered += expanded.params
        routeMapEndpoints += expanded.endpoints
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
      },
      () => originHalted || originUsed >= perOriginCap - 4 || signal.aborted,
    )

    // 2c. Tech-matched safe templates (strictly bounded by remaining per-origin budget). Generic
    // exposure templates run even when no fingerprint matched, so they must not be gated on a
    // non-empty tag set. Reserve a small slice for Playwright when a browser is attached to an HTML
    // origin so template probing cannot starve SPA state-graph discovery under adaptive caps.
    const browserReserve = params.browser && htmlResponsesObserved > 0 && perOriginCap >= 24
      ? Math.min(6, Math.floor(perOriginCap * 0.15))
      : 0
    const remainingForTemplates = perOriginCap - originUsed - browserReserve
    if (!originHalted && !signal.aborted && remainingForTemplates >= 4 && grant.canRead(origin)) {
      emitPhase0Stage(
        'api_templates',
        `Probing API templates & methods on ${origin} (${originIndex + 1}/${hostsTotal}).`,
        { origin, hostsDone, hostsTotal },
      )
      const templateBudget = Math.min(20, remainingForTemplates)
      const templateApiPaths = new Set<string>()
      const considerApiPath = (rawPath: string): void => {
        const bare = rawPath.split('?')[0] || '/'
        if (!bare.startsWith('/') || /[:{}[\]]/.test(bare) || STATIC_ASSET_RE.test(bare)) return
        if (!/^\/(?:api|rest|graphql|trpc|v\d+)(?:\/|$)/i.test(bare)) return
        if (templateApiPaths.size < 24) templateApiPaths.add(bare)
      }
      for (const ep of readPaged('template_api_paths')) considerApiPath(ep.pathTemplate)
      for (const p of discoveredCandidatePaths) considerApiPath(p)
      let stagedTemplateExchanges = 0
      try {
        const tplRes = await runSafeTemplates({
          origin,
          techFingerprint: [...techFingerprint],
          discoveredPaths: {
            protectedPaths: [...protectedPaths].slice(0, 24),
            apiPaths: [...templateApiPaths].slice(0, 24),
          },
          maxTemplates: Math.max(1, Math.floor(templateBudget / 2)),
          maxRequests: templateBudget,
          timeoutMs: Math.min(surfaceProbeTimeoutMs, requestTimeoutMs),
          ...(discoveryPersona ? { persona: discoveryPersona } : {}),
          runId,
          assignmentId: params.assignmentId,
          storage,
          onExchange: ex => {
            stagedTemplateExchanges += 1
            originUsed += 1
            requestsUsed += 1
            if (isHtmlLikeResponse(ex.status, ex.mediaType, ex.body)) htmlResponsesObserved += 1
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
          if (!stoppedReason) stoppedReason = 'circuit_open'
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
          `${apiPrefix}/.kovo-cal-${token}`,
          `${apiPrefix}/.kovo-cal-${token}/missing`,
          `${apiPrefix}/.kovo-cal-${token}/detail/view`,
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
    const siblingPending = new Set<string>()
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
      if (siblingSeen.has(template) || siblingPending.has(template)) return 0
      siblingPending.add(template)
      try {
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
              timeoutMs: Math.min(6_000, requestTimeoutMs),
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
        if (siblingSeen.has(template) || siblingSeen.size >= 8) return 0
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
      } finally {
        siblingPending.delete(template)
      }
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
        const parsed = await safeExtractHtmlInWorker(ex.body, origin, signal)
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

    const navSeedPaths = new Set(navSeeds.slice(0, 96).map(seed => seed.path))
    const uniqueCandidates = [...new Set(discoveredCandidatePaths)]
    if (uniqueCandidates.length > 64) noteTruncation('discovered_candidate_probes', 64, uniqueCandidates.length, origin)
    // Route-map/HTML candidates are also navigation seeds; let the navigation pass probe them so
    // observed listing fields still seed sibling write endpoints.
    const candidateTargets = uniqueCandidates.slice(0, 64).filter(candidate => !navSeedPaths.has(candidate))
    await runBoundedPool(
      candidateTargets,
      PHASE0_INNER_CONCURRENCY,
      async candidate => { await probeDiscovered(candidate) },
      () => originHalted || originUsed >= perOriginCap || signal.aborted,
    )
    const parentTargets = parentProbes.filter(parent => !navSeedPaths.has(parent))
    await runBoundedPool(
      parentTargets,
      PHASE0_INNER_CONCURRENCY,
      async parent => { await probeDiscovered(parent) },
      () => originHalted || originUsed >= perOriginCap || signal.aborted,
    )

    // 2d-bis. Authenticated JSON navigation: follow HATEOAS links found in API responses and infer
    // collection->detail reads from ids observed in authenticated listings. Read-only, depth <= 2,
    // per-origin capped; only JSON/API responses become endpoints (SPA shell HTML is not recorded).
    const navVisited = new Set<string>()
    if (navSeeds.length > 96) noteTruncation('nav_seeds', 96, navSeeds.length, origin)
    const navQueue = navSeeds.slice(0, 96)
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
    for (let navIndex = 0; navIndex < navQueue.length && originNavigationRequests < navCap; navIndex += 1) {
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
      originNavigationRequests += 1
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
          body: '<?xml version="1.0" encoding="UTF-8"?><kovo><probe>kovo-shape</probe></kovo>',
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
            const gqlCatalog = buildRuntimeGraphqlCatalogFromSchema(schema, gqlPath, origin)
            if (gqlCatalog.fields.length > 0) mergeRuntimeGraphqlCatalog(gqlCatalog)
            const roots = [schema.queryType, schema.mutationType].filter((t): t is string => Boolean(t))
            const args = new Set<string>()
            for (const rootType of roots) {
              for (const field of schema.types[rootType] ?? []) {
                for (const arg of field.args) args.add(arg.name)
              }
            }
            for (const arg of [...args].slice(0, 24)) {
              if (!arg || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(arg) || hasPrototypePollutionSegment(arg)) continue
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
        const html = await safeExtractHtmlInWorker(ex.body, origin, signal)
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

    // 2e. Optional browser SPA crawl when caller supplies ScopedBrowser, origin served HTML, and
    // budget remains. Bounded across live origins by `browserSemaphore` (`PHASE0_BROWSER_CONCURRENCY`)
    // and skipped automatically on dead/525/JSON-only/static origins with 0 HTML pages.
    const remainingForCrawl = perOriginCap - originUsed
    if (params.browser && !originHalted && !signal.aborted && remainingForCrawl >= 2 && grant.canRead(origin)) {
      if (htmlResponsesObserved === 0) {
        skippedBrowserNonHtml += 1
      } else {
        try {
          await browserSemaphore.withPermit(async () => {
            if (originHalted || signal.aborted || !grant.canRead(origin)) return
            const crawlBudget = Math.max(0, perOriginCap - originUsed)
            if (crawlBudget < 2) return
            emitPhase0Stage(
              'crawl_state_graph',
              `Crawling SPA state graph on ${origin} (${originIndex + 1}/${hostsTotal}).`,
              { origin, hostsDone, hostsTotal },
            )
            let browserExchanges = 0
            const crawlRes = await crawlStateGraph({
              storage,
              runId,
              scopeRevision,
              origin,
              personas: params.personas,
              maxPages: Math.min(10, Math.max(1, Math.floor(crawlBudget / 2))),
              maxDepth: 3,
              budgetRemaining: crawlBudget,
              browser: params.browser!,
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
            for (const spaRoute of crawlRes.spaRoutes ?? []) {
              mergeRuntimeSpaRoute(spaRoute)
            }
            // Browser traffic is accounted per accepted exchange above; page visits that produced no
            // recorded exchange still consumed a broker call.
            const unaccountedPages = Math.max(0, crawlRes.pagesVisited - browserExchanges)
            originUsed += unaccountedPages
            requestsUsed += unaccountedPages
          }, signal)
        } catch {
          if (signal.aborted) stoppedReason = 'aborted'
        }
      }
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
      // Cross-route produces -> consumes synthesis from harvested structural JSON/header/202 signals
      // matched against consumer endpoint_params + OpenAPI schemas (even without shared /collection prefix).
      const canonTok = (s: string): string => s.toLowerCase().replace(/^x-/, '').replace(/[^a-z0-9]/g, '')
      const consumerByTok = new Map<string, Array<{ ep: typeof originEndpoints[number]; param: string }>>()
      const asyncConsumers: typeof originEndpoints = [], webhookConsumers: typeof originEndpoints = [], storageConsumers: typeof originEndpoints = []
      for (const ep of originEndpoints) {
        const clean = ep.pathTemplate.replace(/\/+$/, '') || '/', surf = classifySurface(clean, ep.method)
        if (surf === 'async_job' || /\/(?:status|poll|result|progress|export|job|task)(?:\/|$)/i.test(clean)) asyncConsumers.push(ep)
        if (surf === 'webhook' || /\/(?:webhooks?|callbacks?|hooks?)(?:\/|$)/i.test(clean)) webhookConsumers.push(ep)
        if (surf === 'storage' || /\/(?:downloads?|files?|artifacts?|signed-url)(?:\/|$)/i.test(clean)) storageConsumers.push(ep)
        const oaOp = runtimeOpenApiMap.get(`${origin}|${ep.method.toUpperCase()}|${ep.pathTemplate}`)
        const pNames = new Set<string>([
          ...storage.listEndpointParams(runId, ep.id).map(p => p.name),
          ...(oaOp?.parameters ?? []), ...(oaOp?.requestBodyKeys ?? []),
        ])
        for (const m of clean.matchAll(/(?::([a-zA-Z0-9_-]+)|\{([a-zA-Z0-9_-]+)\})/g)) pNames.add(m[1] ?? m[2] ?? '')
        for (const pn of pNames) {
          const tok = canonTok(pn)
          if (tok.length < 3 || tok === 'id') continue
          const list = consumerByTok.get(tok) ?? []; list.push({ ep, param: pn }); consumerByTok.set(tok, list)
        }
      }
      let crossRouteEdges = 0
      const seenCross = new Set<string>()
      const emitCross = (prod: typeof originEndpoints[number], cons: typeof originEndpoints[number], rk: string, kind: string) => {
        if (crossRouteEdges >= 48 || prod.id === cons.id) return
        const k = `${prod.id}|${cons.id}|${rk}`
        if (seenCross.has(k)) return
        seenCross.add(k); crossRouteEdges += 1
        storage.recordApiDependency({
          runId, producerEndpointId: prod.id, consumerEndpointId: cons.id, resourceKey: rk,
          sampleResourceIdHash: `sha256:${createHash('sha256').update(`${origin}:${prod.pathTemplate}:${cons.pathTemplate}:${rk}`).digest('hex').slice(0, 16)}`,
          personaHandle: params.personas?.[0] ?? null, observedTransitions: [`edge_kind:${kind}`],
        })
      }
      for (const ep of originEndpoints) {
        const clean = ep.pathTemplate.replace(/\/+$/, '') || '/'
        const normTmpl = normalizeDiscoveryTemplate(clean)
        const sigMap = new Map<string, ResponseSignalEdgeKind>(
          producerResponseSignals.get(`${ep.method.toUpperCase()} ${normTmpl}`)?.signals
            ?? producerResponseSignals.get(`${ep.method.toUpperCase()} ${clean}`)?.signals
            ?? [],
        )
        const ev = paramEvidence.get(ep.pathTemplate) ?? paramEvidence.get(normTmpl)
        for (const f of ev?.fields ?? []) {
          const k = classifyStructuralFieldEdgeKind(f, 'json')
          if (k && !sigMap.has(f)) sigMap.set(f, k)
        }
        for (const [field, kind] of sigMap) {
          const tok = canonTok(field)
          for (const hit of consumerByTok.get(tok) ?? []) emitCross(ep, hit.ep, field, kind)
          if (kind === 'await_async') for (const c of asyncConsumers.slice(0, 4)) emitCross(ep, c, field, 'await_async')
          if (kind === 'hmac_sign') for (const c of webhookConsumers.slice(0, 4)) emitCross(ep, c, field, 'hmac_sign')
          if (kind === 'signed_url') for (const c of storageConsumers.slice(0, 4)) emitCross(ep, c, field, 'signed_url')
        }
      }
      // Synthesize create -> rebind -> finalize lifecycle chains on shared collection entities.
      const lifeByBase = new Map<string, { creates: typeof originEndpoints; rebinds: typeof originEndpoints; finalizes: typeof originEndpoints }>()
      for (const ep of originEndpoints) {
        const segs = ep.pathTemplate.split('/').filter(s => s && !/^[:{]/.test(s) && !/^(?:api|v\d+)$/i.test(s))
        const entitySeg = segs[0]?.toLowerCase()
        if (!entitySeg) continue
        const b = lifeByBase.get(entitySeg) ?? { creates: [], rebinds: [], finalizes: [] }
        const m = ep.method.toUpperCase()
        if (m === 'POST' && !/\/(?:rebind|update|approve|transfer|finalize|settle|release|export|complete|cancel)(?:\/|$)/i.test(ep.pathTemplate)) b.creates.push(ep)
        else if (m === 'PATCH' || m === 'PUT' || /\/(?:rebind|update|assign|delegate|transfer|approve)(?:\/|$)/i.test(ep.pathTemplate)) b.rebinds.push(ep)
        if (/\/(?:finalize|settle|release|complete|commit|publish|capture|export|dispatch|confirm|payout)(?:\/|$)/i.test(ep.pathTemplate)) b.finalizes.push(ep)
        lifeByBase.set(entitySeg, b)
      }
      for (const [entitySeg, b] of lifeByBase) {
        const cr = b.creates[0], rb = b.rebinds[0], fn = b.finalizes.find(f => f.id !== cr?.id && f.id !== rb?.id)
        if (cr && rb) emitCross(cr, rb, `${entitySeg}Id`, 'lifecycle_chain')
        if (rb && fn) emitCross(rb, fn, `${entitySeg}Id`, 'lifecycle_chain')
        else if (cr && fn) emitCross(cr, fn, `${entitySeg}Id`, 'lifecycle_chain')
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
        const provenance = paramProvenanceOfSource(candidate.source)
        // Wire-observed redirect query parameters (`observed:redirect_query`) are always retained;
        // sensitivity checking only prunes unverified inferred candidates.
        if (checked && provenance !== 'observed' && !verified.has(candidate.name)) continue // dead literal: do not queue it
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
    noteTruncation('protected_paths', MAX_PROTECTED_PATHS, protectedPathsObserved, origin)
    noteTruncation('json_doc_candidates', MAX_JSON_DOCS, jsonDocsObserved, origin)
    noteTruncation('discovered_candidate_paths', MAX_CANDIDATE_PATHS, candidatePathsObserved, origin)
    noteTruncation('discovered_templates', MAX_DISCOVERED_TEMPLATES, templatesObserved, origin)
    noteTruncation('js_chunk_queue', MAX_JS_QUEUE, jsQueueObserved, origin)
    noteTruncation('js_chunk_fetches', maxJsChunks, jsQueue.length, origin)
    noteTruncation('js_routes_per_chunk', MAX_JS_ROUTES_PER_CHUNK, jsRoutesObserved, origin)
    noteTruncation('js_request_params', MAX_JS_REQ_PARAMS_PER_CHUNK, jsReqParamsObserved, origin)
    noteTruncation('js_route_table', MAX_JS_ROUTE_TABLE_PER_CHUNK, jsRouteTableObserved, origin)
    noteTruncation('trpc_procedures', MAX_TRPC_PROCS_PER_CHUNK, trpcProcsObserved, origin)

    hostsDone += 1
    emitPhase0Stage(
      'auth_privileged',
      `Analyzing auth & privileged surface on ${origin} (${hostsDone}/${hostsTotal}).`,
      { origin, hostsDone, hostsTotal, force: hostsDone === hostsTotal },
    )
  }, () => signal.aborted)

  if (signal.aborted) stoppedReason = 'aborted'
  readPagedMetrics.sort((a, b) => a.origin.localeCompare(b.origin) || a.phase.localeCompare(b.phase))

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
  if (requestsUsed > 0 || endpointsDiscovered > 0) {
    emitPhase0Stage(
      'param_discovery',
      `Finalizing parameter discovery across ${hostsTotal} host(s).`,
      { hostsDone: hostsTotal, hostsTotal, force: true },
    )
  }
  const paramDiscovery = summarizeParamDiscovery(storage, runId)
  if (paramDiscovery.endpoints.length > 0) {
    const provenance = paramDiscovery.totals.byProvenance
    storage.event(runId, 'phase0.param_discovery',
      `Parameter discovery: ${provenance.observed} observed / ${provenance.inferred_bundle} inferred_bundle / ${provenance.inferred_html} inferred_html / ${provenance.inferred_ast} inferred_ast across ${paramDiscovery.endpoints.length} endpoint(s); sensitivity ${paramSensitivity.checked} checked, ${paramSensitivity.passed} passed, ${paramSensitivity.dropped} dead dropped.`,
      { endpoints: paramDiscovery.endpoints, totals: paramDiscovery.totals, sensitivity: { ...paramSensitivity } })
  }

  const allRuntimeSpaRoutes = [...runtimeSpaMap.values()]
  noteTruncation('runtime_spa_routes', 250, allRuntimeSpaRoutes.length)
  const runtimeSpaRoutes = allRuntimeSpaRoutes.slice(0, 250)
  const runtimeGraphqlCatalogs: RuntimeGraphqlCatalog[] = [...runtimeGraphqlMap.values()]
    .filter(entry => entry.fields.size > 0)
    .map(entry => {
      const allFields = [...entry.fields.values()]
      noteTruncation('runtime_graphql_fields', 250, allFields.length, entry.serviceOrigin)
      return {
        endpoint: entry.endpoint,
        ...(entry.serviceOrigin ? { serviceOrigin: entry.serviceOrigin } : {}),
        fields: allFields.slice(0, 250),
      }
    })
  const allRuntimeOpenApiOps = [...runtimeOpenApiMap.values()]
  noteTruncation('runtime_openapi_operations', 1000, allRuntimeOpenApiOps.length)
  const runtimeOpenApiOperations = allRuntimeOpenApiOps.slice(0, 1000)

  const persistedApiDeps = storage.listApiDependencies(runId)
  if (runtimeSpaRoutes.length > 0 || runtimeGraphqlCatalogs.length > 0 || runtimeOpenApiOperations.length > 0 || persistedApiDeps.length > 0) {
    storage.event(
      runId,
      'phase0.runtime_catalog',
      `Phase-0 runtime catalog: ${runtimeSpaRoutes.length} SPA route(s), ${runtimeGraphqlCatalogs.reduce((sum, c) => sum + c.fields.length, 0)} GraphQL field(s) across ${runtimeGraphqlCatalogs.length} catalog(s), ${runtimeOpenApiOperations.length} OpenAPI op(s), ${persistedApiDeps.length} API dependency edge(s).`,
      {
        spaRoutes: runtimeSpaRoutes.length,
        graphqlCatalogs: runtimeGraphqlCatalogs.length,
        graphqlFields: runtimeGraphqlCatalogs.reduce((sum, c) => sum + c.fields.length, 0),
        openApiOperations: runtimeOpenApiOperations.length,
        apiDependencies: persistedApiDeps.length,
      },
    )
    // Persist bounded summary facts so `collectRuntimeDiscoveryInput` / `extractRuntimeCatalogFromFacts`
    // can feed SPA routes, GraphQL catalogs, and OpenAPI security/operationId metadata directly into
    // `inferRuntimeInvariantHypotheses` both pre-floor and post-Phase-A-floor.
    try {
      const runRow = storage.run(runId)
      const assignmentRow = params.assignmentId
        ? storage.worker(params.assignmentId)
        : undefined
      if (runRow && assignmentRow) {
        const primaryOrigin = normalizedOrigins[0] ?? assignmentRow.sourceOrigins[0]
        if (runtimeSpaRoutes.length > 0 && primaryOrigin) {
          const spaByOrigin = new Map<string, RuntimeSpaRoute[]>()
          for (const route of runtimeSpaRoutes) {
            const routeOrigin = route.serviceOrigin ?? primaryOrigin
            const bucket = spaByOrigin.get(routeOrigin) ?? []
            bucket.push(route)
            spaByOrigin.set(routeOrigin, bucket)
          }
          for (const [routeOrigin, routes] of spaByOrigin) {
            storage.addFact(runRow, assignmentRow, {
              kind: 'note',
              origin: routeOrigin,
              summary: `Phase-0 runtime SPA route catalog (${routes.length} route(s)) on ${routeOrigin}.`,
              data: {
                subkind: 'runtime_spa_routes',
                origin: routeOrigin,
                spaRoutes: routes.slice(0, 40),
              },
              sourceOrigins: [routeOrigin],
            })
          }
        }
        for (const catalog of runtimeGraphqlCatalogs) {
          const gqlOrigin = catalog.serviceOrigin ?? primaryOrigin
          if (!gqlOrigin) continue
          storage.addFact(runRow, assignmentRow, {
            kind: 'note',
            origin: gqlOrigin,
            summary: `Phase-0 runtime GraphQL catalog (${catalog.fields.length} field(s) at ${catalog.endpoint ?? '/graphql'}) on ${gqlOrigin}.`,
            data: {
              subkind: 'runtime_graphql_catalog',
              origin: gqlOrigin,
              graphqlCatalog: catalog,
            },
            sourceOrigins: [gqlOrigin],
          })
        }
        const openApiWithMeta = runtimeOpenApiOperations.filter(op =>
          op.operationId || op.security !== undefined || op.authRequirement !== undefined,
        )
        if (openApiWithMeta.length > 0 && primaryOrigin) {
          const opsByOrigin = new Map<string, RuntimeOpenApiOperation[]>()
          for (const op of openApiWithMeta) {
            const opOrigin = op.serviceOrigin ?? primaryOrigin
            const bucket = opsByOrigin.get(opOrigin) ?? []
            bucket.push(op)
            opsByOrigin.set(opOrigin, bucket)
          }
          for (const [opOrigin, ops] of opsByOrigin) {
            storage.addFact(runRow, assignmentRow, {
              kind: 'note',
              origin: opOrigin,
              summary: `Phase-0 runtime OpenAPI catalog (${ops.length} operation(s) with security/operationId metadata) on ${opOrigin}.`,
              data: {
                subkind: 'runtime_openapi_catalog',
                origin: opOrigin,
                openApiOperations: ops.slice(0, 120),
              },
              sourceOrigins: [opOrigin],
            })
          }
        }
        if (persistedApiDeps.length > 0 && primaryOrigin) {
          const epById = new Map(storage.listEndpoints(runId, { limit: 500 }).map(e => [e.id, e]))
          const depsByOrigin = new Map<string, RuntimeApiDependency[]>()
          for (const d of persistedApiDeps) {
            const pEp = epById.get(d.producerEndpointId), cEp = epById.get(d.consumerEndpointId)
            if (!pEp || !cEp) continue
            const depOrigin = pEp.origin || primaryOrigin
            const list = depsByOrigin.get(depOrigin) ?? []
            if (list.length >= 60) continue
            list.push({
              producer: `${pEp.method.toUpperCase()} ${pEp.pathTemplate}`,
              consumer: `${cEp.method.toUpperCase()} ${cEp.pathTemplate}`,
              resourceKey: d.resourceKey,
              producerOrigin: pEp.origin,
              consumerOrigin: cEp.origin,
              ...(d.personaHandle !== undefined ? { personaHandle: d.personaHandle } : {}),
              ...(d.observedTransitions?.length ? { observedTransitions: d.observedTransitions } : {}),
              testedBola: d.testedBola,
            })
            depsByOrigin.set(depOrigin, list)
          }
          for (const [depOrigin, deps] of depsByOrigin) {
            storage.addFact(runRow, assignmentRow, {
              kind: 'note',
              origin: depOrigin,
              summary: `Phase-0 runtime API dependency graph (${deps.length} produces->consumes edge(s)) on ${depOrigin}.`,
              data: { subkind: 'runtime_api_dependencies', origin: depOrigin, apiDependencies: deps },
              sourceOrigins: [...new Set([depOrigin, ...deps.map(x => x.consumerOrigin).filter((o): o is string => Boolean(o))])],
            })
          }
        }
      }
    } catch { /* structured catalog fact persistence is best-effort */ }
  }

  noteTruncation('dynamic_wordlist_paths', 500, dynamicPaths.size)
  noteTruncation('dynamic_wordlist_params', 250, dynamicParams.size)
  if (truncations.length > 0) {
    storage.event(runId, 'phase0.truncation', `Phase-0 hit ${truncations.length} finite discovery cap(s).`, { truncations })
  }

  storage.event(runId, 'phase0.discovery', 'Phase-0 discovery counts.', {
    requestsUsed,
    perOriginCap,
    endpointsDiscovered,
    paramsDiscovered,
    frameworksDetected: [...frameworksDetected],
    routeMapEndpoints,
    jsRouterRoutes,
    navigationRequests,
    navigationEndpoints,
    authRequests,
    soft404Rejected,
    stoppedReason,
    readPaged: readPagedMetrics,
    ...(skippedDeadHosts.length > 0 ? { skippedDeadHosts } : {}),
    ...(edgeProtectedOrigins.length > 0 ? { edgeProtectedOrigins } : {}),
    ...(skippedBrowserNonHtml > 0 ? { skippedBrowserNonHtml } : {}),
    ...(truncations.length > 0 ? { truncations } : {}),
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
      paths: [...dynamicPaths].slice(0, 500),
      params: [...dynamicParams].slice(0, 250),
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
    ...(staticSnapshot ? { staticSnapshot } : {}),
    ...(runtimeSpaRoutes.length > 0 ? { runtimeSpaRoutes } : {}),
    ...(runtimeGraphqlCatalogs.length > 0 ? { runtimeGraphqlCatalogs } : {}),
    ...(runtimeOpenApiOperations.length > 0 ? { runtimeOpenApiOperations } : {}),
    ...(skippedDeadHosts.length > 0 ? { skippedDeadHosts } : {}),
    ...(edgeProtectedOrigins.length > 0 ? { edgeProtectedOrigins } : {}),
    ...(truncations.length > 0 ? { truncations } : {}),
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
  const crawlSpaMap = new Map<string, {
    apiCalls: Map<string, { method: string; path: string; surface: ReturnType<typeof classifySurface>; serviceOrigin?: string }>
    stateActions: Set<string>
    personas: Set<string>
  }>()
  const noteCrawlSpaPage = (
    pageTemplate: string,
    who: string,
    call?: { method: string; path: string; serviceOrigin?: string },
    actionText?: string,
  ): void => {
    let entry = crawlSpaMap.get(pageTemplate)
    if (!entry) {
      if (crawlSpaMap.size >= 48) return
      entry = { apiCalls: new Map(), stateActions: new Set(), personas: new Set() }
      crawlSpaMap.set(pageTemplate, entry)
    }
    entry.personas.add(who)
    if (call && entry.apiCalls.size < 10) {
      const key = `${call.serviceOrigin ?? normalizedOrigin}|${call.method}|${call.path}`
      if (!entry.apiCalls.has(key)) {
        entry.apiCalls.set(key, {
          method: call.method,
          path: call.path,
          surface: classifySurface(call.path, call.method),
          ...(call.serviceOrigin && call.serviceOrigin !== normalizedOrigin ? { serviceOrigin: call.serviceOrigin } : {}),
        })
      }
    }
    if (actionText) {
      SPA_LIFECYCLE_ACTION_RE.lastIndex = 0
      for (const m of actionText.matchAll(SPA_LIFECYCLE_ACTION_RE)) {
        if (m[1] && entry.stateActions.size < 10) entry.stateActions.add(m[1].toLowerCase())
      }
    }
  }

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
      noteCrawlSpaPage(routeTemplate, who, undefined, routeTemplate)
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
        const parsedHtml = await safeExtractHtmlInWorker(visit.domSnippet, normalizedOrigin, signal)
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
            const doc = await safeParseJsonOrYamlInWorker(bodyPreview, signal)
            if (doc && typeof doc === 'object') {
              const expanded = parseRouteMapDoc(
                bodyPreview, normalizedOrigin, storage, runId, scopeRevision, crawlDynamicPaths, crawlDynamicParams,
                { parsedDoc: doc },
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
        noteCrawlSpaPage(routeTemplate, who, { method: shape.method, path: tmpl }, tmpl)
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

  const spaRoutes: RuntimeSpaRoute[] = []
  for (const [pagePath, entry] of crawlSpaMap) {
    const apiCalls = [...entry.apiCalls.values()]
    const stateActions = [...entry.stateActions]
    const personas = [...entry.personas]
    const rolePersonas = personas.filter(p => p !== 'anonymous')
    const requiredRoles: string[] = []
    if (rolePersonas.length > 0 && !personas.includes('anonymous')) {
      for (const handle of rolePersonas) requiredRoles.push(handle)
    } else if (isPrivilegedPathTemplate(pagePath)) {
      requiredRoles.push('admin')
    }
    if (apiCalls.length === 0 && stateActions.length === 0 && requiredRoles.length === 0) continue
    spaRoutes.push({
      path: pagePath,
      serviceOrigin: normalizedOrigin,
      ...(apiCalls.length > 0 ? { apiCalls } : {}),
      ...(stateActions.length > 0 ? { stateActions } : {}),
      ...(requiredRoles.length > 0 ? { requiredRoles } : {}),
    })
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
    ...(spaRoutes.length > 0 ? { spaRoutes } : {}),
    ...(stoppedReason ? { stoppedReason } : {}),
  }
}
