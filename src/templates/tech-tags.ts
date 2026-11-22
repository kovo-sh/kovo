/**
 * Canonical technology-tag detection shared by Phase-0 recon, the offline worker
 * analyzer (`worker/analyzers.ts:techFingerprint`) and template selection.
 *
 * Keeping one mapping avoids the v4 failure mode where Phase-0 emitted `spring`
 * while templates expected `springboot`, or where a mounted repo knew it used
 * FastAPI but the live fingerprint stayed empty.
 */
import { normalizeTechTagSet, templateTechTags } from './loader.ts'

export interface ManifestFile {
  /** File name or repo-relative path (e.g. `package.json`, `backend/requirements.txt`). */
  name: string
  content: string
}

const KNOWN_TAGS = new Set<string>(templateTechTags)

/** Dependency/package name -> template tech tag(s). */
const PACKAGE_TECH_MAP: ReadonlyArray<{ re: RegExp; tags: string[] }> = [
  { re: /^(?:next|@next\/(?:[a-z-]+))$/i, tags: ['nextjs', 'react', 'node'] },
  { re: /^react(?:-dom|-router[^/]*)?$/i, tags: ['react'] },
  { re: /^(?:express|fastify|koa|@nestjs\/core)$/i, tags: ['node', 'express'] },
  { re: /^@nestjs\//i, tags: ['nestjs', 'node'] },
  { re: /^vite$/i, tags: ['vite'] },
  { re: /^(?:vue|nuxt|@nuxt\/core)$/i, tags: ['vue', 'nuxt'] },
  { re: /^@angular\//i, tags: ['angular'] },
  { re: /^graphql(?:-yoga|-http)?$/i, tags: ['graphql'] },
  { re: /^(?:apollo-server(?:-express)?|@apollo\/server)$/i, tags: ['graphql'] },
  { re: /^@clerk\//i, tags: ['clerk'] },
  { re: /^@supabase\//i, tags: ['supabase'] },
  { re: /^@trpc\//i, tags: ['node'] },
  { re: /^(?:django|djangorestframework)$/i, tags: ['django', 'python'] },
  { re: /^(?:fastapi|starlette)$/i, tags: ['fastapi', 'python'] },
  { re: /^(?:flask|flask-[a-z-]+)$/i, tags: ['flask', 'python'] },
  { re: /^(?:sqlalchemy|alembic|psycopg2|asyncpg|pydantic)$/i, tags: ['python'] },
  { re: /^(?:spring-boot[^:]*|org\.springframework[^:]*)$/i, tags: ['springboot', 'java'] },
  { re: /^(?:spring-security[^:]*|thymeleaf)$/i, tags: ['springboot', 'java', 'actuator'] },
  { re: /^(?:rails|railties|actionpack|activerecord)$/i, tags: ['rails'] },
  { re: /^(?:laravel\/framework|symfony\/[a-z-]+)$/i, tags: ['laravel', 'php'] },
  { re: /^(?:gin|github\.com\/gin-gonic\/gin)$/i, tags: ['go'] },
  { re: /^(?:github\.com\/go-chi\/chi[^ ]*|net\/http)$/i, tags: ['go'] },
  { re: /^(?:gorm\.io\/gorm|github\.com\/jmoiron\/sqlx)$/i, tags: ['go'] },
  { re: /^(?:wordpress|wp-|drupal|joomla)/i, tags: ['wordpress', 'php'] },
]

function addKnown(out: Set<string>, tags: readonly string[]): void {
  for (const tag of tags) {
    if (KNOWN_TAGS.has(tag)) out.add(tag)
  }
}

/** Map an ecosystem package name (as produced by `techFingerprint`) to tech tags. */
export function techTagsFromPackage(packageName: string): string[] {
  const name = packageName.trim()
  if (!name) return []
  const tags: string[] = []
  for (const entry of PACKAGE_TECH_MAP) {
    if (entry.re.test(name)) tags.push(...entry.tags)
  }
  if (tags.length === 0 && /^[a-z0-9@._/-]+$/i.test(name)) {
    // Package may itself be a known tag (e.g. `express`, `django`).
    const normalized = normalizeTechTagSet([name.split('/').pop() ?? name])
    for (const tag of normalized) if (KNOWN_TAGS.has(tag)) tags.push(tag)
  }
  return [...new Set(tags)]
}

/** Convert `techFingerprint` `technologies[]` output into template tags. */
export function techTagsFromFingerprint(fingerprint: { technologies?: ReadonlyArray<{ package?: string }> } | null | undefined): string[] {
  const out = new Set<string>()
  for (const item of fingerprint?.technologies ?? []) {
    if (item.package) addKnown(out, techTagsFromPackage(item.package))
  }
  return [...out]
}

function parseJsonDeps(content: string): string[] {
  try {
    const pkg = JSON.parse(content) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
    return [...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})]
  } catch {
    return []
  }
}

function parseRequirements(content: string): string[] {
  const deps: string[] = []
  for (const rawLine of content.split('\n')) {
    const line = rawLine.split('#')[0].trim()
    if (!line || line.startsWith('-')) continue
    const name = line.match(/^([A-Za-z0-9_.-]+)/)?.[1]
    if (name) deps.push(name)
  }
  return deps
}

function parsePyproject(content: string): string[] {
  const deps = new Set<string>()
  for (const match of content.matchAll(/(?:^|["'\s])([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|\^|<=|>|<)/g)) {
    deps.add(match[1])
  }
  for (const match of content.matchAll(/^\s*([A-Za-z0-9_.-]+)\s*=\s*["'][\^~>=<\d]/gm)) {
    deps.add(match[1])
  }
  return [...deps]
}

function parseGoMod(content: string): string[] {
  const deps = new Set<string>()
  for (const match of content.matchAll(/^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}\/[^\s]+)\s+v[\d.]+/gim)) {
    deps.add(match[1])
  }
  return [...deps]
}

function parsePom(content: string): string[] {
  const deps = new Set<string>()
  for (const match of content.matchAll(/<artifactId>\s*([A-Za-z0-9_.-]+)\s*<\/artifactId>/g)) {
    deps.add(match[1])
  }
  for (const match of content.matchAll(/<groupId>\s*([A-Za-z0-9_.-]+)\s*<\/groupId>/g)) {
    deps.add(match[1])
  }
  return [...deps]
}

function parseGemfile(content: string): string[] {
  const deps = new Set<string>()
  for (const match of content.matchAll(/^\s*gem\s+["']([A-Za-z0-9_.-]+)["']/gm)) deps.add(match[1])
  return [...deps]
}

function parseBuildGradle(content: string): string[] {
  const deps = new Set<string>()
  for (const match of content.matchAll(/["']([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+)(?::[^"']+)?["']/g)) {
    deps.add(match[1])
    deps.add(match[2])
  }
  return [...deps]
}

/** Detect tech tags from mounted repo manifests without executing any package manager. */
export function techTagsFromManifests(manifests: readonly ManifestFile[]): string[] {
  const out = new Set<string>()
  for (const file of manifests) {
    const base = file.name.split('/').pop()?.toLowerCase() ?? ''
    let deps: string[] = []
    if (base === 'package.json') deps = parseJsonDeps(file.content)
    else if (base === 'requirements.txt' || /^requirements[-.].*\.txt$/.test(base)) deps = parseRequirements(file.content)
    else if (base === 'pyproject.toml' || base === 'pipfile') deps = parsePyproject(file.content)
    else if (base === 'go.mod') deps = parseGoMod(file.content)
    else if (base === 'pom.xml') deps = parsePom(file.content)
    else if (base === 'build.gradle' || base === 'build.gradle.kts') deps = parseBuildGradle(file.content)
    else if (base === 'gemfile') deps = parseGemfile(file.content)
    for (const dep of deps) addKnown(out, techTagsFromPackage(dep))
  }
  return [...out]
}

/** Detect tech tags from live HTTP response headers/body (superset of v4 phase0 detectTechTags). */
export function techTagsFromResponse(headers: Record<string, string>, body: string): string[] {
  const lowerHeaders = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)]))
  const powered = (lowerHeaders['x-powered-by'] ?? '').toLowerCase()
  const server = (lowerHeaders['server'] ?? '').toLowerCase()
  const bodyLower = body.slice(0, 32_000).toLowerCase()
  const combined = `${powered} ${server} ${bodyLower}`
  const out = new Set<string>()
  const add = (...tags: string[]) => addKnown(out, tags)

  if (/next\.js/.test(combined) || combined.includes('__next') || combined.includes('/_next/') ||
    lowerHeaders['x-nextjs-cache'] || lowerHeaders['x-nextjs-prerender']) add('nextjs', 'react', 'node')
  if (/express/.test(combined)) add('express', 'node')
  if (/fastify/.test(combined)) add('node')
  if (lowerHeaders['x-powered-by']?.includes('PHP') || combined.includes('.php') || combined.includes('phpsessid')) add('php')
  if (combined.includes('laravel') || combined.includes('laravel_session')) add('laravel', 'php')
  if (combined.includes('symfony')) add('symfony', 'php')
  if (combined.includes('wordpress') || combined.includes('wp-content') || combined.includes('/wp-')) add('wordpress', 'php')
  if (combined.includes('drupal')) add('drupal', 'php')
  if (combined.includes('django') || combined.includes('csrfmiddlewaretoken')) add('django', 'python')
  if (combined.includes('fastapi') || combined.includes('"detail":"not found"') && bodyLower.includes('fastapi')) add('fastapi', 'python')
  if (combined.includes('flask') || lowerHeaders['server']?.includes('werkzeug')) add('flask', 'python')
  if (combined.includes('spring') || combined.includes('whitelabel error page')) add('springboot', 'java')
  if (combined.includes('/actuator')) add('actuator', 'springboot', 'java')
  if (combined.includes('graphql') || combined.includes('__typename') || combined.includes('"__schema"')) add('graphql')
  if (combined.includes('/@vite') || combined.includes('__vite_plugin')) add('vite', 'react')
  if (combined.includes('/_nuxt') || combined.includes('__nuxt')) add('nuxt', 'vue')
  if (combined.includes('ng-version') || combined.includes('angular')) add('angular')
  if (combined.includes('jsessionid') || combined.includes('tomcat')) add('tomcat', 'java')
  if (combined.includes('x-aspnet') || combined.includes('asp.net') || combined.includes('.aspx')) add('dotnet', 'iis')
  if (combined.includes('swagger') || combined.includes('openapi')) add('swagger')
  if (/nginx\/[\d.]*/.test(server)) add('nginx')
  if (/apache\/[\d.]*/.test(server) || server.includes('httpd')) add('apache')
  if (lowerHeaders['cf-ray'] || server.includes('cloudflare')) add('cloudflare')
  if (lowerHeaders['x-vercel-id'] || server.includes('vercel')) add('vercel')
  if (lowerHeaders['x-clerk-auth-status'] || combined.includes('clerk.accounts')) add('clerk')
  if (combined.includes('.supabase.co') || lowerHeaders['x-supabase-api-version']) add('supabase')
  if (combined.includes('jenkins')) add('jenkins')
  if (combined.includes('grafana')) add('grafana')
  if (combined.includes('prometheus')) add('prometheus')
  if (combined.includes('kibana')) add('kibana')
  if (combined.includes('elasticsearch')) add('elasticsearch')
  if (combined.includes('gitlab')) add('gitlab')
  if (combined.includes('keycloak')) add('keycloak')
  if (combined.includes('traefik')) add('traefik')
  if (combined.includes('s3.amazonaws.com')) add('s3')
  return [...out]
}

/** Union of live + repo fingerprints, normalized through loader aliases. */
export function mergeTechTags(...groups: ReadonlyArray<readonly string[] | undefined>): string[] {
  const merged = new Set<string>()
  for (const group of groups) {
    for (const tag of normalizeTechTagSet(group)) {
      if (KNOWN_TAGS.has(tag)) merged.add(tag)
    }
  }
  return [...merged]
}
