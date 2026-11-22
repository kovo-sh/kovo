import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'
import { jsHarvest } from '../../worker/analyzers.ts'
import type { CapabilityTier, CodeLocation, EndpointSource, ParamLocation } from '../domain.ts'
import { BrokerCircuitOpen, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { normalizeEndpointTemplate } from './dedupe.ts'
import type { ScopedBrowser } from './scoped-browser.ts'
import type { Store } from './store.ts'
import { parseGraphqlIntrospection, runSafeTemplates } from './surface-engine.ts'

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
}

export interface Phase0ReconResult {
  requestsUsed: number
  perOriginCap: number
  endpointsDiscovered: number
  paramsDiscovered: number
  frameworksDetected: string[]
  techFingerprint: string[]
  dynamicWordlist: {
    paths: string[]
    params: string[]
  }
  stoppedReason: string | null
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
}

const CSRF_PARAM_RE = /^(?:_csrf|csrf[_-]?token|xsrf[_-]?token|csrfmiddlewaretoken|__requestverificationtoken|authenticity_token|_token)$/i
const OBJECT_ID_PARAM_RE = /^(?:id|uuid|[a-z0-9_]*_?id)$/i
const STATIC_ASSET_RE = /\.(?:css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|mp3|zip|tar|gz|pdf)(?:\?|$)/i
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

function walkRepoFiles(rootDir: string, maxFiles = 1500): string[] {
  const out: string[] = []
  const stack: string[] = [rootDir]
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
        st = statSync(full)
      } catch {
        continue
      }
      if (st.isDirectory()) {
        stack.push(full)
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
  const routes: StaticExtractedRoute[] = []
  const frameworks = new Set<string>()
  const seen = new Set<string>()

  const pushRoute = (r: StaticExtractedRoute) => {
    const key = `${r.method.toUpperCase()} ${r.pathTemplate}`
    if (seen.has(key)) return
    seen.add(key)
    frameworks.add(r.framework)
    routes.push(r)
  }

  for (const fullPath of files) {
    let code: string
    try {
      code = readFileSync(fullPath, 'utf8')
    } catch {
      continue
    }
    const rel = relative(reposDir, fullPath).split(sep).join('/')
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

function detectTechTags(respHeaders: Record<string, string>, body: string): string[] {
  const tags = new Set<string>()
  const poweredBy = (respHeaders['x-powered-by'] ?? '').toLowerCase()
  const server = (respHeaders['server'] ?? '').toLowerCase()
  const combined = `${poweredBy} ${server} ${body.slice(0, 16_000).toLowerCase()}`
  if (combined.includes('next.js') || combined.includes('__next') || combined.includes('/_next/')) tags.add('nextjs')
  if (combined.includes('express')) tags.add('express')
  if (combined.includes('django') || combined.includes('csrfmiddlewaretoken')) tags.add('django')
  if (combined.includes('spring') || combined.includes('whitelabel error page')) tags.add('spring')
  if (combined.includes('wordpress') || combined.includes('wp-content')) tags.add('wordpress')
  if (combined.includes('graphql')) tags.add('graphql')
  if (combined.includes('nginx')) tags.add('nginx')
  if (combined.includes('apache')) tags.add('apache')
  if (combined.includes('php')) tags.add('php')
  return [...tags]
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
  for (const name of names.slice(0, 12)) {
    if (!name) continue
    storage.upsertEndpointParam({
      runId,
      endpointId,
      name,
      location: 'query',
      isCsrf: CSRF_PARAM_RE.test(name),
      isObjectId: OBJECT_ID_PARAM_RE.test(name),
      source,
    })
    dynamicParams.add(name)
    count += 1
  }
  return count
}

const HTTP_VERBS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options'])
const ROUTE_COLLECTION_KEYS = /^(?:routes?|paths?|endpoints?|apis?|operations?|handlers?|resources?|navigation|nav|menu|screens?)$/i

export interface RouteMapEntry {
  method: string
  path: string
  params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' }>
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
  const push = (method: string, rawPath: string, params: RouteMapEntry['params'] = []): void => {
    const path = rawPath.trim()
    if (!path.startsWith('/') || path.startsWith('//') || path.length > 200 || /[\r\n\0\\]/.test(path)) return
    const m = method.toUpperCase()
    if (!HTTP_VERBS.has(method.toLowerCase())) return
    const clean = path.split('?')[0] || '/'
    const key = `${m} ${clean}`
    if (seen.has(key) || out.length >= maxEntries) return
    seen.add(key)
    out.push({ method: m, path: clean, params: params.slice(0, 20) })
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
          push(method, rawPath, operationParams(rec))
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
        push(method, value, operationParams(rec))
        continue
      }
      walk(value, depth + 1, key)
    }
  }
  walk(raw, 0)
  return out
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
): { endpoints: number; params: number } {
  let doc: unknown
  try { doc = JSON.parse(rawBody) } catch { return { endpoints: 0, params: 0 } }
  const entries = harvestRouteMapDocument(doc)
  let endpoints = 0
  let params = 0
  for (const entry of entries.slice(0, 120)) {
    const clean = sanitizePathCandidate(entry.path, origin)
    if (!clean || STATIC_ASSET_RE.test(clean)) continue
    const tmpl = normalizeRouteTemplate(clean)
    const ep = storage.upsertEndpoint({
      runId, scopeRevision, origin, method: entry.method, pathTemplate: tmpl,
      source: 'route_map', riskScore: scoreEndpointRisk(entry.method, tmpl),
    } as unknown as Parameters<Store['upsertEndpoint']>[0])
    endpoints += 1
    dynamicPaths.add(tmpl)
    for (const p of entry.params) {
      storage.upsertEndpointParam({
        runId, endpointId: ep.id, name: p.name, location: p.location,
        isCsrf: CSRF_PARAM_RE.test(p.name), isObjectId: OBJECT_ID_PARAM_RE.test(p.name), source: 'route_map',
      })
      dynamicParams.add(p.name)
      params += 1
    }
  }
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
): { endpoints: number; params: number } {
  let doc: Record<string, unknown>
  try {
    const parsed = JSON.parse(rawBody) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { endpoints: 0, params: 0 }
    doc = parsed as Record<string, unknown>
  } catch {
    return { endpoints: 0, params: 0 }
  }
  const pathsObj = doc.paths
  if (!pathsObj || typeof pathsObj !== 'object' || Array.isArray(pathsObj)) return { endpoints: 0, params: 0 }
  let endpoints = 0
  let params = 0
  const validMethods = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options'])

  for (const [rawPath, methodsObj] of Object.entries(pathsObj as Record<string, unknown>)) {
    if (!methodsObj || typeof methodsObj !== 'object' || Array.isArray(methodsObj)) continue
    const leading = rawPath.startsWith('/') ? rawPath : `/${rawPath}`
    // Preserve OpenAPI {param} placeholders while still collapsing raw literal IDs if any appear
    const pathTemplate = leading.includes('{')
      ? leading.split('?')[0].replace(/\/{2,}/g, '/')
      : normalizeRouteTemplate(leading)
    dynamicPaths.add(pathTemplate)
    for (const [mKey, opVal] of Object.entries(methodsObj as Record<string, unknown>)) {
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
      const op = (opVal && typeof opVal === 'object' ? opVal : {}) as Record<string, unknown>
      const opParams = Array.isArray(op.parameters) ? op.parameters : []
      for (const p of opParams) {
        if (!p || typeof p !== 'object') continue
        const rec = p as Record<string, unknown>
        const name = typeof rec.name === 'string' ? rec.name.trim() : ''
        if (!name) continue
        const locRaw = typeof rec.in === 'string' ? rec.in.toLowerCase() : 'query'
        const location: ParamLocation =
          locRaw === 'path' ? 'path'
            : locRaw === 'header' ? 'header'
              : locRaw === 'cookie' ? 'cookie'
                : 'query'
        const schemaObj = (rec.schema && typeof rec.schema === 'object' ? rec.schema : {}) as Record<string, unknown>
        storage.upsertEndpointParam({
          runId,
          endpointId: ep.id,
          name,
          location,
          inferredType: typeof schemaObj.type === 'string' ? schemaObj.type : null,
          isCsrf: CSRF_PARAM_RE.test(name),
          isObjectId: location === 'path' || OBJECT_ID_PARAM_RE.test(name),
          source: 'openapi',
        })
        dynamicParams.add(name)
        params += 1
      }
      // Extract requestBody properties for JSON, XML and form/multipart content types.
      type SchemaProp = { type?: string; xml?: { name?: string } }
      const reqBody = op.requestBody as { content?: Record<string, { schema?: { properties?: Record<string, SchemaProp> } }> } | undefined
      const addBodyProps = (props: Record<string, SchemaProp> | undefined, location: ParamLocation) => {
        if (!props || typeof props !== 'object') return
        for (const [propName, propSchema] of Object.entries(props)) {
          if (!propName) continue
          const xmlName = location === 'xml' && typeof propSchema?.xml?.name === 'string' && propSchema.xml.name.trim()
            ? propSchema.xml.name.trim()
            : propName
          storage.upsertEndpointParam({
            runId,
            endpointId: ep.id,
            name: xmlName,
            location,
            inferredType: typeof propSchema?.type === 'string' ? propSchema.type : null,
            isCsrf: CSRF_PARAM_RE.test(xmlName),
            isObjectId: OBJECT_ID_PARAM_RE.test(xmlName),
            source: 'openapi',
          })
          dynamicParams.add(xmlName)
          params += 1
        }
      }
      const content = reqBody?.content ?? {}
      for (const [mediaType, media] of Object.entries(content)) {
        const lower = mediaType.toLowerCase()
        const props = media?.schema?.properties
        if (lower.includes('json')) addBodyProps(props, 'json')
        else if (lower.includes('xml')) addBodyProps(props, 'xml')
        else if (lower.includes('x-www-form-urlencoded') || lower.includes('multipart/form-data')) addBodyProps(props, 'form')
      }
      // Swagger 2 style parameters: in: body / formData with a schema.
      for (const p of opParams) {
        if (!p || typeof p !== 'object') continue
        const rec = p as { in?: string; name?: string; schema?: { properties?: Record<string, SchemaProp> }; items?: unknown }
        const inLoc = typeof rec.in === 'string' ? rec.in.toLowerCase() : ''
        if (inLoc === 'body') addBodyProps(rec.schema?.properties, 'json')
        else if (inLoc === 'formdata') addBodyProps(rec.schema?.properties, 'form')
      }
    }
  }
  return { endpoints, params }
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

  let requestsUsed = 0
  let endpointsDiscovered = 0
  let paramsDiscovered = 0
  let stoppedReason: string | null = null
  const frameworksDetected = new Set<string>()
  const techFingerprint = new Set<string>()
  const dynamicPaths = new Set<string>()
  const dynamicParams = new Set<string>()

  const normalizedOrigins: string[] = []
  for (const raw of params.origins) {
    try {
      const o = new URL(raw).origin
      if (!normalizedOrigins.includes(o)) normalizedOrigins.push(o)
    } catch { /* skip malformed */ }
  }

  // 1. White-box static framework route extraction (runs at ALL tiers including Tier 0)
  if (params.reposDir && normalizedOrigins.length > 0) {
    const primaryOrigin = normalizedOrigins[0]
    const extracted = extractStaticFrameworkRoutes(params.reposDir)
    for (const fw of extracted.frameworks) frameworksDetected.add(fw)
    for (const route of extracted.routes) {
      const ep = storage.upsertEndpoint({
        runId,
        scopeRevision,
        origin: primaryOrigin,
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
  }

  // Tier 0: zero live HTTP requests
  if (tier === 0) {
    storage.updateRunPhase0Completed(runId, Date.now())
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
    const discoveredCandidatePaths: string[] = []
    let originHalted = false

    const safeGet = async (
      pathAndQuery: string,
      opts?: { method?: 'GET' | 'POST'; body?: string; headers?: Record<string, string>; persona?: string },
    ): Promise<BrokerExchangeResult | null> => {
      if (originHalted || signal.aborted) return null
      if (originUsed >= perOriginCap) return null
      if (!grant.canRead(origin)) {
        originHalted = true
        stoppedReason = 'scope_revoked'
        return null
      }
      const method = opts?.method ?? 'GET'
      const dedupeKey = `${method} ${opts?.persona ?? ''} ${pathAndQuery}`
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
          ...(opts?.persona ? { persona: opts.persona } : {}),
          followRedirects: false,
          runId,
          assignmentId: params.assignmentId,
          timeoutMs: 8_000,
        }, grant, signal)
        params.onExchange?.(ex)
        return ex
      } catch (err) {
        if (err instanceof BrokerCircuitOpen) {
          originHalted = true
          stoppedReason = 'circuit_open'
          return null
        }
        if (err instanceof BrokerDenied) {
          if (!grant.canRead(origin) || /scope|revoked/i.test(err.message)) {
            originHalted = true
            stoppedReason = 'scope_revoked'
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
      extra?: { framework?: string | null; riskScore?: number },
    ) => {
      const pathTemplate = normalizeRouteTemplate(rawPath)
      const ep = storage.upsertEndpoint({
        runId,
        scopeRevision,
        origin,
        method: method.toUpperCase(),
        pathTemplate,
        source,
        framework: extra?.framework ?? null,
        riskScore: extra?.riskScore ?? scoreEndpointRisk(method, pathTemplate),
      })
      endpointsDiscovered += 1
      dynamicPaths.add(pathTemplate)
      return ep
    }

    // 2a. Standard seed probes. Reserve a small slice of the per-origin cap for JS chunk
    // harvesting, otherwise a long seed list can starve the bundles that carry XHR/route evidence.
    const jsReserve = perOriginCap > 4 ? Math.min(4, Math.floor(perOriginCap / 3)) : 0
    const seedBudget = Math.max(1, perOriginCap - jsReserve)
    let seedFetches = 0
    for (const seedPath of PHASE0_SEED_PATHS) {
      if (seedFetches >= seedBudget) break
      seedFetches += 1
      if (originHalted || originUsed >= perOriginCap || signal.aborted) break
      if (seedPath === '/') {
        // On crash recovery, reuse any already-recorded GET / for this (runId, scopeRevision, origin)
        // so baseline GET / is never duplicated across SIGKILL + resume.
        try {
          const prior = storage.client.prepare(
            `SELECT status, media_type AS mediaType, resp_headers AS respHeadersJson, body_preview AS bodyPreview
             FROM broker_exchanges
             WHERE run_id = ? AND scope_revision = ? AND origin = ? AND method = 'GET' AND path_and_query = '/'
             ORDER BY created_at ASC LIMIT 1`,
          ).get(runId, scopeRevision, origin) as {
            status: number
            mediaType: string
            respHeadersJson: string
            bodyPreview: string
          } | undefined
          if (prior) {
            probedPaths.add('GET /')
            let headersObj: Record<string, string> = {}
            try { headersObj = JSON.parse(prior.respHeadersJson) as Record<string, string> } catch { /* ignore */ }
            for (const t of detectTechTags(headersObj, prior.bodyPreview ?? '')) techFingerprint.add(t)
            if (prior.status < 400) recordEndpoint('GET', '/', 'surface_probe')
            const html = extractHtmlLinksAndScripts(prior.bodyPreview ?? '', origin)
            for (const s of html.scripts) {
              if (!jsQueue.includes(s)) jsQueue.push(s)
            }
            for (const l of html.links.slice(0, 60)) {
              dynamicPaths.add(normalizeRouteTemplate(l))
              if (discoveredCandidatePaths.length < 40) discoveredCandidatePaths.push(l)
            }
            for (const form of html.forms) {
              const ep = recordEndpoint(form.method, form.action, 'surface_probe')
              for (const inp of form.inputs) {
                storage.upsertEndpointParam({
                  runId,
                  endpointId: ep.id,
                  name: inp,
                  location: form.method === 'GET' ? 'query' : 'form',
                  isCsrf: CSRF_PARAM_RE.test(inp),
                  isObjectId: OBJECT_ID_PARAM_RE.test(inp),
                  source: 'phase0_html',
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
      // Config/route-map artifacts are often behind auth; retry once with the first approved persona
      // so authenticated tables are not invisible to recon.
      if (ex && (ex.status === 401 || ex.status === 403) && params.personas?.[0]) {
        ex = await safeGet(seedPath, { persona: params.personas[0] })
      }
      if (!ex) continue

      if (seedPath === '/') {
        for (const t of detectTechTags(ex.respHeaders, ex.body)) techFingerprint.add(t)
        if (ex.status < 400) recordEndpoint('GET', '/', 'surface_probe')
        const html = extractHtmlLinksAndScripts(ex.body, origin)
        for (const s of html.scripts) {
          if (!jsQueue.includes(s)) jsQueue.push(s)
        }
        for (const l of html.links.slice(0, 60)) {
          dynamicPaths.add(normalizeRouteTemplate(l))
          if (discoveredCandidatePaths.length < 40) discoveredCandidatePaths.push(l)
        }
        for (const form of html.forms) {
          const ep = recordEndpoint(form.method, form.action, 'surface_probe')
          for (const inp of form.inputs) {
            storage.upsertEndpointParam({
              runId,
              endpointId: ep.id,
              name: inp,
              location: form.method === 'GET' ? 'query' : 'form',
              isCsrf: CSRF_PARAM_RE.test(inp),
              isObjectId: OBJECT_ID_PARAM_RE.test(inp),
              source: 'phase0_html',
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
      } else if ((seedPath === '/openapi.json' || seedPath === '/swagger.json') && ex.status < 400) {
        const parsed = parseOpenApiDoc(ex.body, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams)
        endpointsDiscovered += parsed.endpoints
        paramsDiscovered += parsed.params
      } else if (seedPath === '/graphql' && ex.status < 400) {
        recordEndpoint('POST', '/graphql', 'graphql', { framework: 'graphql', riskScore: 85 })
        techFingerprint.add('graphql')
      } else if (ex.status >= 200 && ex.status < 300) {
        recordEndpoint('GET', seedPath, 'surface_probe')
        // Any served JSON document may be a route map or config with an endpoint table.
        if (/json/i.test(ex.mediaType) || /^\s*[{[]/.test(ex.body)) {
          try {
            const parsed = parseRouteMapDoc(ex.body, origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams)
            endpointsDiscovered += parsed.endpoints
            paramsDiscovered += parsed.params
          } catch { /* not a route map */ }
        }
      }
    }

    // 2b. Fetch same-origin JS chunks & optional source maps and feed into AST jsHarvest
    const maxJsChunks = Math.min(12, Math.max(0, perOriginCap - originUsed))
    for (const jsPath of jsQueue.slice(0, maxJsChunks)) {
      if (originHalted || originUsed >= perOriginCap || signal.aborted) break
      const ex = await safeGet(jsPath)
      if (!ex || ex.status >= 400 || !ex.body) continue

      const harvested = jsHarvest(ex.body, `${origin}${jsPath}`) as {
        apiPaths?: string[]
        adminPaths?: string[]
        routes?: Array<{ path?: string }>
        httpCalls?: Array<{ url?: string; method?: string; bodyKeys?: string[] }>
        graphqlDocs?: Array<{ kind?: string; name?: string }>
        nextActions?: Array<{ id?: string }>
      }

      const seenJsRoutes = new Map<string, string>()
      const addJsEndpoint = (method: string, rawPath: string, bodyKeys: string[] = []): string | null => {
        if (seenJsRoutes.size >= 120) return null
        const clean = sanitizePathCandidate(rawPath, origin)
        if (!clean || STATIC_ASSET_RE.test(clean)) return null
        const tmpl = normalizeRouteTemplate(clean)
        const key = `${method.toUpperCase()} ${tmpl}`
        const existingId = seenJsRoutes.get(key)
        // The same route is often referenced by several sources (harvested calls, regex literal scan,
        // OpenAPI-derived body keys). Merge parameters instead of dropping later evidence.
        if (existingId) return existingId
        const ep = recordEndpoint(method, tmpl, 'js_ast')
        seenJsRoutes.set(key, ep.id)
        for (const bk of bodyKeys.slice(0, 20)) {
          if (!bk) continue
          storage.upsertEndpointParam({
            runId,
            endpointId: ep.id,
            name: bk,
            location: method.toUpperCase() === 'GET' ? 'query' : 'json',
            isCsrf: CSRF_PARAM_RE.test(bk),
            isObjectId: OBJECT_ID_PARAM_RE.test(bk),
            source: 'js_ast',
          })
          dynamicParams.add(bk)
          paramsDiscovered += 1
        }
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
          storage.upsertEndpointParam({
            runId,
            endpointId: epId,
            name: p.name,
            location: p.location,
            isCsrf: CSRF_PARAM_RE.test(p.name),
            isObjectId: OBJECT_ID_PARAM_RE.test(p.name),
            source: 'js_ast',
          })
          dynamicParams.add(p.name)
          paramsDiscovered += 1
        }
      }
      // SPA router tables: path literals in router config are navigable endpoints even without hrefs.
      for (const routePath of harvestJsRouteTable(ex.body).slice(0, 24)) {
        addJsEndpoint('GET', routePath)
      }
      if ((harvested.graphqlDocs?.length ?? 0) > 0) {
        recordEndpoint('POST', '/graphql', 'graphql', { framework: 'graphql', riskScore: 85 })
      }
      for (const act of (harvested.nextActions ?? []).slice(0, 10)) {
        if (act.id) recordEndpoint('POST', `/_next/action/${act.id.slice(0, 40)}`, 'js_ast', { framework: 'nextjs', riskScore: 85 })
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

    // 2c. Tech-matched safe templates (strictly bounded by remaining per-origin budget)
    const remainingForTemplates = perOriginCap - originUsed
    if (!originHalted && !signal.aborted && remainingForTemplates >= 4 && techFingerprint.size > 0 && grant.canRead(origin)) {
      const templateBudget = Math.min(20, remainingForTemplates)
      let stagedTemplateExchanges = 0
      try {
        const tplRes = await runSafeTemplates({
          origin,
          techFingerprint: [...techFingerprint],
          maxTemplates: Math.max(1, Math.floor(templateBudget / 2)),
          maxRequests: templateBudget,
          runId,
          assignmentId: params.assignmentId,
          storage,
          onExchange: ex => {
            stagedTemplateExchanges += 1
            originUsed += 1
            requestsUsed += 1
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

    // 2d. Bounded probe of top discovered high-signal links (strictly within perOriginCap)
    for (const candidate of discoveredCandidatePaths.slice(0, 12)) {
      if (originHalted || originUsed >= perOriginCap || signal.aborted) break
      if (candidate === '/' || STATIC_ASSET_RE.test(candidate)) continue
      const ex = await safeGet(candidate)
      // 401/403/405 means the route exists but is gated or method-restricted: still part of the surface.
      if (ex && (ex.status < 400 || ex.status === 401 || ex.status === 403 || ex.status === 405)) {
        const ep = recordEndpoint('GET', candidate, 'surface_probe')
        paramsDiscovered += recordQueryParamsForEndpoint({
          rawPathAndQuery: candidate, origin, endpointId: ep.id, source: 'phase0_html',
          storage, runId, dynamicParams,
        })
        if (ex.status < 400 && /<html\b|<input\b|<form\b/i.test(ex.body)) {
          const parsed = extractHtmlLinksAndScripts(ex.body, origin)
          for (const inp of parsed.inputs.slice(0, 8)) {
            if (inp.type && /^(?:hidden|submit|button|reset|checkbox|radio|file|image)$/i.test(inp.type)) continue
            storage.upsertEndpointParam({
              runId,
              endpointId: ep.id,
              name: inp.name,
              location: 'query',
              isCsrf: CSRF_PARAM_RE.test(inp.name),
              isObjectId: OBJECT_ID_PARAM_RE.test(inp.name),
              source: 'phase0_html',
            })
            dynamicParams.add(inp.name)
            paramsDiscovered += 1
          }
          for (const s of parsed.scripts) {
            if (!jsQueue.includes(s)) jsQueue.push(s)
          }
        }
      }
    }

    // 2d-bis. XML-accepting surface discovery: xml-ish routes frequently only reveal their element
    // schema in a parse-error response. Send a benign probe document and learn the expected element.
    const xmlish = /(?:xml|soap|wsdl|saml|rss|atom|svg|import|upload|feed|sitemap)/i
    if (!originHalted && !signal.aborted && grant.canRead(origin)) {
      const known = storage.listEndpoints(runId, { origin })
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
      const gqlEps = storage.listEndpoints(runId, { origin }).filter(e => /graphql/i.test(e.pathTemplate))
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

    // 2e. Optional browser SPA crawl when caller supplies ScopedBrowser and budget remains
    const remainingForCrawl = perOriginCap - originUsed
    if (params.browser && !originHalted && !signal.aborted && remainingForCrawl >= 2 && grant.canRead(origin)) {
      const crawlRes = await crawlStateGraph({
        storage,
        runId,
        scopeRevision,
        origin,
        personas: params.personas,
        maxPages: Math.min(25, remainingForCrawl),
        maxDepth: 3,
        budgetRemaining: remainingForCrawl,
        browser: params.browser,
        grant,
        signal,
        assignmentId: params.assignmentId,
      })
      endpointsDiscovered += crawlRes.endpointsDiscovered
      paramsDiscovered += crawlRes.paramsDiscovered
      requestsUsed += crawlRes.pagesVisited
    }
    // 2f. Infer producer-consumer api_dependencies edges from discovered collection -> item endpoints
    try {
      const originEndpoints = storage.listEndpoints(runId, { origin })
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
  }

  storage.updateRunPhase0Completed(runId, Date.now())

  return {
    requestsUsed,
    perOriginCap,
    endpointsDiscovered,
    paramsDiscovered,
    frameworksDetected: [...frameworksDetected],
    techFingerprint: [...techFingerprint],
    dynamicWordlist: {
      paths: [...dynamicPaths].slice(0, 120),
      params: [...dynamicParams].slice(0, 80),
    },
    stoppedReason,
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

  let pagesVisited = 0
  let endpointsDiscovered = 0
  let paramsDiscovered = 0
  const storageKeySet = new Set<string>()
  let hasPostMessageListener = false
  const personasCrawled: string[] = []
  let stoppedReason: string | undefined

  const recordFormAndParams = (
    actionRaw: string,
    methodRaw: string,
    inputNames: readonly string[],
  ) => {
    const cleanAction = sanitizePathCandidate(actionRaw || '/', normalizedOrigin)
    if (!cleanAction) return
    const method = (methodRaw || 'GET').toUpperCase()
    const pathTemplate = normalizeRouteTemplate(cleanAction)
    const ep = storage.upsertEndpoint({
      runId,
      scopeRevision,
      origin: normalizedOrigin,
      method,
      pathTemplate,
      source: 'spa_crawl',
      riskScore: scoreEndpointRisk(method, pathTemplate),
    })
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

  for (const persona of personaList) {
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
    let personaPages = 0
    // Per-persona budget share when crawling multiple personas while respecting total budgetRemaining if specified
    const personaPageCap = params.budgetRemaining !== undefined
      ? Math.max(1, effectiveMaxPages - pagesVisited)
      : requestedMaxPages

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

      let visit
      try {
        visit = await browser.visitPage({
          origin: normalizedOrigin,
          pathAndQuery: next.pathAndQuery,
          persona,
          runId,
          assignmentId: params.assignmentId,
          waitAfterLoadMs: 120,
        }, grant, signal)
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

      // Record visited route
      const routeTemplate = normalizeRouteTemplate(next.pathAndQuery)
      const routeEp = storage.upsertEndpoint({
        runId,
        scopeRevision,
        origin: normalizedOrigin,
        method: 'GET',
        pathTemplate: routeTemplate,
        source: 'spa_crawl',
        authRequirement: persona ? `persona:${persona}` : null,
        riskScore: scoreEndpointRisk('GET', routeTemplate),
      })
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
        recordFormAndParams(form.action, form.method, form.inputNames)
      }
      // Also parse raw domSnippet forms in case hidden inputs weren't captured
      if (visit.domSnippet && /<form\b/i.test(visit.domSnippet)) {
        const parsedHtml = extractHtmlLinksAndScripts(visit.domSnippet, normalizedOrigin)
        for (const f of parsedHtml.forms) {
          recordFormAndParams(f.action, f.method, f.inputs)
        }
      }

      // Record intercepted XHR / fetch / WebSocket / GraphQL / Next-Action calls
      const intercepted = [...visit.xhrRequests, ...(visit.allRequests ?? [])]
      for (const req of intercepted) {
        if (req.origin !== normalizedOrigin) continue
        if (!['xhr', 'fetch', 'websocket'].includes(req.resourceType) && !/\/api\/|\/graphql|\/trpc/i.test(req.url)) {
          continue
        }
        const clean = sanitizePathCandidate(req.url, normalizedOrigin)
        if (!clean || STATIC_ASSET_RE.test(clean)) continue
        const tmpl = normalizeRouteTemplate(clean)
        const src: EndpointSource = /graphql/i.test(tmpl) ? 'graphql' : 'spa_crawl'
        storage.upsertEndpoint({
          runId,
          scopeRevision,
          origin: normalizedOrigin,
          method: (req.method || 'GET').toUpperCase(),
          pathTemplate: tmpl,
          source: src,
          authRequirement: persona ? `persona:${persona}` : null,
          riskScore: scoreEndpointRisk(req.method || 'GET', tmpl),
        })
        endpointsDiscovered += 1
      }
      // Also inspect broker exchanges for Next-Action headers
      for (const ex of visit.exchanges) {
        if (ex.origin !== normalizedOrigin) continue
        const nextAction = ex.reqHeaders['next-action']
        if (nextAction) {
          const tmpl = normalizeRouteTemplate(ex.pathAndQuery)
          storage.upsertEndpoint({
            runId,
            scopeRevision,
            origin: normalizedOrigin,
            method: ex.method.toUpperCase(),
            pathTemplate: tmpl,
            source: 'spa_crawl',
            framework: 'nextjs',
            sinkKinds: ['server_action'],
            riskScore: 88,
          })
          endpointsDiscovered += 1
        }
      }

      // Enqueue same-origin links strictly within maxDepth
      if (next.depth < maxDepth) {
        for (const href of visit.links) {
          const clean = sanitizePathCandidate(href, normalizedOrigin)
          if (!clean || STATIC_ASSET_RE.test(clean)) continue
          if (!visitedForPersona.has(clean)) {
            queue.push({ pathAndQuery: clean, depth: next.depth + 1 })
          }
        }
      }
    }

    if (personaTouched) personasCrawled.push(persona ?? 'anonymous')
    if (stoppedReason === 'circuit_open' || stoppedReason === 'scope_revoked' || stoppedReason === 'aborted') {
      break
    }
  }

  return {
    origin: normalizedOrigin,
    pagesVisited,
    endpointsDiscovered,
    paramsDiscovered,
    storageKeys: [...storageKeySet],
    hasPostMessageListener,
    personasCrawled,
    ...(stoppedReason ? { stoppedReason } : {}),
  }
}
