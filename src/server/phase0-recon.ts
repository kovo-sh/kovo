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
import { runSafeTemplates } from './surface-engine.ts'

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
]

function sanitizePathCandidate(raw: string, baseOrigin: string): string | null {
  const trimmed = raw.trim()
  if (!trimmed || trimmed.startsWith('javascript:') || trimmed.startsWith('mailto:') || trimmed.startsWith('data:') || trimmed.startsWith('#')) {
    return null
  }
  try {
    const parsed = new URL(trimmed, baseOrigin)
    if (parsed.origin !== baseOrigin) return null
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
  const normalized = normalizeEndpointTemplate(cleaned)
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

function extractHtmlLinksAndScripts(html: string, origin: string): {
  links: string[]
  scripts: string[]
  forms: Array<{ action: string; method: string; inputs: string[] }>
} {
  const links = new Set<string>()
  const scripts = new Set<string>()
  const forms: Array<{ action: string; method: string; inputs: string[] }> = []

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
    const action = sanitizePathCandidate(actionMatch?.[1] ?? '/', origin) ?? '/'
    const method = (methodMatch?.[1] ?? 'GET').toUpperCase()
    const inputs: string[] = []
    for (const im of inner.matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi)) {
      if (im[1]) inputs.push(im[1])
    }
    forms.push({ action, method, inputs })
  }
  return { links: [...links], scripts: [...scripts], forms }
}

function parseOpenApiDoc(
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
      // Extract JSON requestBody properties if present
      const reqBody = op.requestBody as { content?: Record<string, { schema?: { properties?: Record<string, { type?: string }> } }> } | undefined
      const jsonProps = reqBody?.content?.['application/json']?.schema?.properties
      if (jsonProps && typeof jsonProps === 'object') {
        for (const [propName, propSchema] of Object.entries(jsonProps)) {
          storage.upsertEndpointParam({
            runId,
            endpointId: ep.id,
            name: propName,
            location: 'json',
            inferredType: typeof propSchema?.type === 'string' ? propSchema.type : null,
            isCsrf: CSRF_PARAM_RE.test(propName),
            isObjectId: OBJECT_ID_PARAM_RE.test(propName),
            source: 'openapi',
          })
          dynamicParams.add(propName)
          params += 1
        }
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
      opts?: { method?: 'GET' | 'POST'; body?: string; headers?: Record<string, string> },
    ): Promise<BrokerExchangeResult | null> => {
      if (originHalted || signal.aborted) return null
      if (originUsed >= perOriginCap) return null
      if (!grant.canRead(origin)) {
        originHalted = true
        stoppedReason = 'scope_revoked'
        return null
      }
      const method = opts?.method ?? 'GET'
      const dedupeKey = `${method} ${pathAndQuery}`
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

    // 2a. Standard seed probes
    for (const seedPath of PHASE0_SEED_PATHS) {
      if (originHalted || originUsed >= perOriginCap || signal.aborted) break
      const ex = await safeGet(seedPath)
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

      const seenJsRoutes = new Set<string>()
      const addJsEndpoint = (method: string, rawPath: string, bodyKeys: string[] = []) => {
        if (seenJsRoutes.size >= 120) return
        const clean = sanitizePathCandidate(rawPath, origin)
        if (!clean || STATIC_ASSET_RE.test(clean)) return
        const tmpl = normalizeRouteTemplate(clean)
        const key = `${method.toUpperCase()} ${tmpl}`
        if (seenJsRoutes.has(key)) return
        seenJsRoutes.add(key)
        const ep = recordEndpoint(method, tmpl, 'js_ast')
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
      if (ex && ex.status < 400) {
        recordEndpoint('GET', candidate, 'surface_probe')
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
