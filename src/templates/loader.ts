import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'
import { containsDestructivePayload, containsWebshellSignature } from '../replay-spec.ts'
import { parseMiniYaml } from './yaml.ts'

export const templateTechTags = [
  'generic', 'generic-web-exposure', 'nextjs', 'vite', 'express', 'django', 'fastapi', 'springboot', 'nestjs', 'graphql',
  'clerk', 'supabase', 'wordpress', 'nginx', 'apache', 'php', 'swagger', 'cloudflare', 'react', 'node',
  'rails', 'flask', 'laravel', 'symfony', 'drupal', 'jenkins', 'gitlab', 'grafana', 'prometheus',
  'kibana', 'elasticsearch', 'tomcat', 'iis', 'traefik', 'keycloak', 'auth0', 'oidc',
  'java', 'go', 'python', 'dotnet', 'actuator', 'nuxt', 'vue', 'angular', 'vercel', 's3', 'kubernetes', 'docker',
  // Vendor / appliance families: never selected unless the live target or mounted repo
  // fingerprint matches the vendor explicitly. This keeps consumer web stacks (Express,
  // Next.js, FastAPI) from burning the template cap on camera/NAS/appliance probes.
  'cisco', 'aem', 'adobe', '3cx', 'avtech', 'hikvision', 'dahua', 'axis', 'fortinet', 'citrix',
  'vmware', 'sonicwall', 'juniper', 'mikrotik', 'zyxel', 'synology', 'qnap', 'dlink', 'tplink',
  'netgear', 'draytek', 'grandstream', 'polycom', 'f5', 'paloalto', 'sophos', 'zywave',
] as const
export type TemplateTechTag = typeof templateTechTags[number]

/** Appliance/vendor families that only run when the target explicitly fingerprints them. */
export const vendorApplianceTechTags: ReadonlySet<string> = new Set([
  'cisco', 'aem', 'adobe', '3cx', 'avtech', 'hikvision', 'dahua', 'axis', 'fortinet', 'citrix',
  'vmware', 'sonicwall', 'juniper', 'mikrotik', 'zyxel', 'synology', 'qnap', 'dlink', 'tplink',
  'netgear', 'draytek', 'grandstream', 'polycom', 'f5', 'paloalto', 'sophos', 'zywave',
])

/** Universal exposure checks that are safe/meaningful on any web origin. */
export const genericWebExposureTag = 'generic-web-exposure' as const

/** Dynamic, discovery-derived path placeholders resolved per origin at runtime. */
export const dynamicTemplatePathPlaceholders = [
  'discovered_protected_path',
  'discovered_api_path',
] as const
export type DynamicTemplatePathPlaceholder = typeof dynamicTemplatePathPlaceholders[number]

export const defaultCompiledTemplateLimit = 150
export const compiledTemplateLimitCeiling = 400

const readOnlyMethods = ['GET', 'HEAD', 'OPTIONS'] as const
const tier3Methods = ['POST', 'PUT', 'PATCH'] as const

const templateRequestSchema = z.object({
  method: z.enum([...readOnlyMethods, ...tier3Methods]).default('GET'),
  path: z.string().min(1).max(2048),
  headers: z.record(z.string().min(1).max(64), z.string().max(1024)).default({}),
  body: z.string().max(4096).optional(),
}).strict()

const templateControlSchema = z.object({
  method: z.enum([...readOnlyMethods, ...tier3Methods]).optional(),
  path: z.string().min(1).max(2048).optional(),
  headers: z.record(z.string().min(1).max(64), z.string().max(1024)).optional(),
  body: z.string().max(4096).optional(),
}).strict()

const matcherPart = z.enum(['body', 'header', 'all']).default('body')

export const templateMatcherSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('status'), status: z.array(z.number().int().min(100).max(599)).min(1).max(8) }).strict(),
  z.object({
    type: z.literal('word'),
    part: matcherPart,
    words: z.array(z.string().min(1).max(256)).min(1).max(10),
    condition: z.enum(['and', 'or']).default('or'),
    negative: z.boolean().default(false),
  }).strict(),
  z.object({
    type: z.literal('regex'),
    part: matcherPart,
    regex: z.array(z.string().min(1).max(512)).min(1).max(6),
    condition: z.enum(['and', 'or']).default('or'),
    negative: z.boolean().default(false),
  }).strict(),
  z.object({ type: z.literal('canary'), protocol: z.enum(['any', 'http', 'dns']).default('any') }).strict(),
])
export type TemplateMatcher = z.output<typeof templateMatcherSchema>

export const safeTemplateSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]{2,63}$/),
  name: z.string().trim().min(3).max(160),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  description: z.string().trim().min(5).max(600),
  tech: z.array(z.enum(templateTechTags)).min(1).max(6),
  tags: z.array(z.string().regex(/^[a-z0-9-]{2,32}$/)).max(8).default([]),
  cve: z.string().regex(/^CVE-\d{4}-\d{4,7}$/).optional(),
  cwe: z.string().regex(/^CWE-\d{1,5}$/).optional(),
  reference: z.string().max(300).optional(),
  requiresTier3: z.boolean().default(false),
  spaExclusion: z.boolean().default(false),
  request: templateRequestSchema,
  control: templateControlSchema.optional(),
  'matchers-condition': z.enum(['and', 'or']).default('and'),
  matchers: z.array(templateMatcherSchema).min(1).max(8),
}).strict()

export type SafeTemplate = Omit<z.output<typeof safeTemplateSchema>, 'matchers-condition'> & {
  matchersCondition: 'and' | 'or'
  sourceFile?: string
}

export class TemplateValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TemplateValidationError'
  }
}

const thirdPartyOastPattern = /(?:interact\.sh|interactsh|oast\.(?:pro|live|site|online|fun|me)|oast\.[a-z]{2,10}\b|burpcollaborator|requestbin|pipedream|webhook\.site|ngrok|canarytokens|dnslog|ceye\.io|oastify|beeceptor|requestcatcher|dnsbin\.|bxss\.me|xss\.ht)/i
const privateHostPattern = /(?:\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b|\b169\.254\.\d{1,3}\.\d{1,3}\b|\b0\.0\.0\.0\b|\blocalhost\b|\[::1?\]|::ffff:|metadata\.google\.internal|metadata\.azure\.internal|100\.100\.100\.200|\b2852039166\b|\b0xa9fea9fe\b|\bfd[0-9a-f]{2}:)/i
const allowedPlaceholders = /\{\{(?:rand|kovo_canary_http|kovo_canary_dns|discovered_protected_path|discovered_api_path)\}\}/g
const originLikeHeaders = /^(?:origin|referer)$/i

function decodeLoose(text: string): string {
  try { return decodeURIComponent(text) } catch { return text }
}

function assertRequestFieldSafe(label: string, value: string, headerName?: string) {
  const stripped = value.replace(allowedPlaceholders, 'X')
  if (/\{\{[^}]*\}\}/.test(stripped)) {
    throw new TemplateValidationError(`${label} uses an unknown {{placeholder}}; only rand, kovo_canary_http, kovo_canary_dns, discovered_protected_path and discovered_api_path are allowed.`)
  }
  const decoded = decodeLoose(decodeLoose(stripped))
  if (/[\r\n\0]/.test(decoded)) throw new TemplateValidationError(`${label} contains control characters.`)
  if (privateHostPattern.test(decoded)) {
    throw new TemplateValidationError(`${label} references an internal/loopback/metadata address.`)
  }
  if (thirdPartyOastPattern.test(decoded)) {
    throw new TemplateValidationError(`${label} references a third-party OAST service; use {{kovo_canary_http}}/{{kovo_canary_dns}}.`)
  }
  if (decoded.includes('://')) {
    const allowedOriginHeader = headerName && originLikeHeaders.test(headerName) &&
      /^https?:\/\/[a-z0-9.-]+\.invalid(?::\d+)?\/?$/i.test(decoded.trim())
    if (!allowedOriginHeader) {
      throw new TemplateValidationError(`${label} contains an absolute URL; templates may only target the approved origin.`)
    }
  }
}

export function assertTemplateSafety(t: SafeTemplate): void {
  const serialized = JSON.stringify({ request: t.request, control: t.control, matchers: t.matchers, name: t.name, description: t.description })
  const decodedOnce = decodeLoose(serialized)
  const decodedTwice = decodeLoose(decodedOnce)
  const plusDecoded = decodeLoose(decodedTwice.replace(/\+/g, ' '))
  if (
    containsDestructivePayload(serialized) ||
    containsDestructivePayload(decodedOnce) ||
    containsDestructivePayload(decodedTwice) ||
    containsDestructivePayload(plusDecoded)
  ) {
    throw new TemplateValidationError('Template matches the destructive-payload denylist.')
  }
  if (
    containsWebshellSignature(serialized) ||
    containsWebshellSignature(decodedOnce) ||
    containsWebshellSignature(decodedTwice) ||
    containsWebshellSignature(plusDecoded)
  ) {
    throw new TemplateValidationError('Template contains a webshell/code-execution signature.')
  }
  const requests = [t.request, ...(t.control ? [t.control] : [])]
  for (const request of requests) {
    const method = request.method ?? t.request.method
    const mutating = !(readOnlyMethods as readonly string[]).includes(method)
    if (mutating && !t.requiresTier3) {
      throw new TemplateValidationError(`Method ${method} is only allowed in templates marked requiresTier3: true.`)
    }
    if (request.path !== undefined) {
      const startsWithDynamic = /^\{\{discovered_[a-z_]+\}\}/.test(request.path)
      if (!request.path.startsWith('/') && !startsWithDynamic) {
        throw new TemplateValidationError('Template request paths must start with a single "/" (or a discovered_* placeholder).')
      }
      if (request.path.startsWith('//')) {
        throw new TemplateValidationError('Template request paths must start with a single "/".')
      }
      assertRequestFieldSafe('path', request.path)
    }
    for (const [name, value] of Object.entries(request.headers ?? {})) {
      if (/^(?:authorization|proxy-authorization|cookie|host|content-length|transfer-encoding)$/i.test(name)) {
        throw new TemplateValidationError(`Template header "${name}" is forbidden.`)
      }
      assertRequestFieldSafe(`header ${name}`, value, name)
    }
    if (request.body !== undefined) assertRequestFieldSafe('body', request.body)
  }
  if (t.requiresTier3 && (readOnlyMethods as readonly string[]).includes(t.request.method) && !t.control) {
    // Tier-3 flag is harmless on read-only templates, but they must still carry a control.
  }
  if (!t.control && !t.spaExclusion) {
    throw new TemplateValidationError('Template must declare a `control` request or `spaExclusion: true`.')
  }
  if (!t.matchers.some(m => m.type !== 'status')) {
    throw new TemplateValidationError('Template needs at least one content matcher (word/regex/canary); status-only matchers are not allowed.')
  }
  for (const m of t.matchers) {
    if (m.type === 'regex') {
      for (const pattern of m.regex) {
        try { new RegExp(pattern, 'im') } catch { throw new TemplateValidationError(`Invalid regex "${pattern}".`) }
        if (/\((?:[^()]*[+*])\)[+*{]/.test(pattern)) {
          throw new TemplateValidationError(`Regex "${pattern}" risks catastrophic backtracking.`)
        }
      }
    }
    if (m.type === 'word') {
      for (const word of m.words) {
        if (thirdPartyOastPattern.test(word)) throw new TemplateValidationError('Matcher references third-party OAST.')
      }
    }
  }
  const usesCanary = JSON.stringify(t.request).includes('kovo_canary_')
  if (usesCanary !== t.matchers.some(m => m.type === 'canary')) {
    throw new TemplateValidationError('Canary placeholders and a `canary` matcher must be used together.')
  }
  if (t.control && JSON.stringify(t.control).includes('kovo_canary_')) {
    throw new TemplateValidationError('Control requests must not use canary placeholders.')
  }
}

export function validateSafeTemplate(raw: unknown, sourceFile?: string): SafeTemplate {
  const parsed = safeTemplateSchema.safeParse(raw)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    throw new TemplateValidationError(`${issue?.path.join('.') || 'template'}: ${issue?.message ?? 'invalid'}`)
  }
  const { 'matchers-condition': matchersCondition, ...rest } = parsed.data
  // Backwards-compatible tag alias: legacy tooling/tests look for the `generic` bucket,
  // while v5 splits universal exposure checks into `generic-web-exposure`.
  const tech = [...rest.tech]
  if (tech.includes(genericWebExposureTag) && !tech.includes('generic') && tech.length < 6) tech.push('generic')
  const template: SafeTemplate = { ...rest, tech, matchersCondition, ...(sourceFile ? { sourceFile } : {}) }
  assertTemplateSafety(template)
  return template
}

export function parseSafeTemplateYaml(source: string, sourceFile?: string): SafeTemplate {
  return validateSafeTemplate(parseMiniYaml(source), sourceFile)
}

export interface LoadedTemplates {
  templates: SafeTemplate[]
  errors: Array<{ file: string; error: string }>
  dir: string | null
}

const cache = new Map<string, LoadedTemplates>()

function candidateDirs(explicit?: string): string[] {
  const dirs: string[] = []
  if (explicit) dirs.push(resolve(explicit))
  if (process.env.KOVO_TEMPLATES_DIR) dirs.push(resolve(process.env.KOVO_TEMPLATES_DIR))
  try { dirs.push(fileURLToPath(new URL('./', import.meta.url))) } catch { /* bundled */ }
  try { dirs.push(fileURLToPath(new URL('../templates/', import.meta.url))) } catch { /* bundled */ }
  dirs.push(resolve(process.cwd(), 'src/templates'))
  return [...new Set(dirs)]
}

function walkYaml(dir: string, out: string[] = [], depth = 0): string[] {
  if (depth > 4) return out
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry)
    const st = statSync(full)
    if (st.isDirectory()) walkYaml(full, out, depth + 1)
    else if (/\.ya?ml$/i.test(entry) && st.size < 32 * 1024) out.push(full)
  }
  return out
}

export function loadSafeTemplates(options: { dir?: string; refresh?: boolean } = {}): LoadedTemplates {
  const dir = candidateDirs(options.dir).find(d => {
    try { return existsSync(d) && statSync(d).isDirectory() && walkYaml(d).length > 0 } catch { return false }
  })
  if (!dir) return { templates: [], errors: [{ file: '(none)', error: 'No template directory found.' }], dir: null }
  if (!options.refresh) {
    const hit = cache.get(dir)
    if (hit) return hit
  }
  const templates: SafeTemplate[] = []
  const errors: LoadedTemplates['errors'] = []
  const seen = new Set<string>()
  for (const file of walkYaml(dir)) {
    try {
      const template = parseSafeTemplateYaml(readFileSync(file, 'utf8'), file)
      if (seen.has(template.id)) throw new TemplateValidationError(`Duplicate template id "${template.id}".`)
      seen.add(template.id)
      templates.push(template)
    } catch (err) {
      errors.push({ file, error: err instanceof Error ? err.message : String(err) })
    }
  }
  const loaded = { templates, errors, dir }
  cache.set(dir, loaded)
  return loaded
}

export interface TemplateSelection {
  selected: SafeTemplate[]
  skipped: Array<{ id: string; reason: string }>
}

/**
 * Score/rank a template for a concrete fingerprint. Lower is better.
 *   0  curated custom + explicit tech match
 *   1  explicit tech match + modern CVE (>= 2021)
 *   2  curated custom generic
 *   3  explicit tech match (legacy / no CVE)
 *   4  generic-web-exposure (universal)
 *   5  plain generic
 *   6  legacy CVE (< 2021)
 */
function templateGroupRank(t: SafeTemplate, tags: ReadonlySet<string>): number {
  const curated = Boolean(t.sourceFile && !/(?:^|\/)compiled\//.test(t.sourceFile.replaceAll('\\', '/')))
  const explicitTech = t.tech.some(x => x !== 'generic' && x !== genericWebExposureTag && tags.has(x))
  const cveYear = Number(t.cve?.split('-')[1] ?? 0)
  if (curated) return explicitTech ? 0 : 2
  if (explicitTech && cveYear >= 2021) return 1
  if (explicitTech) return 3
  if (t.tech.includes(genericWebExposureTag)) return 4
  if (cveYear > 0 && cveYear < 2021) return 6
  return 5
}

export function isVendorApplianceTemplate(t: SafeTemplate): boolean {
  return t.tech.some(x => vendorApplianceTechTags.has(x))
}

export function selectSafeTemplates(
  templates: readonly SafeTemplate[],
  options: {
    techTags?: readonly string[]
    templateIds?: readonly string[]
    cveIds?: readonly string[]
    tier: number
    maxTemplates: number
  },
): TemplateSelection {
  const tags = normalizeTechTagSet(options.techTags)
  const wantIds = options.templateIds?.length ? new Set(options.templateIds) : null
  const wantCves = options.cveIds?.length ? new Set(options.cveIds.map(c => c.toUpperCase())) : null
  const selected: SafeTemplate[] = []
  const skipped: Array<{ id: string; reason: string }> = []
  for (const t of templates) {
    if (wantIds && !wantIds.has(t.id)) continue
    if (wantCves && !(t.cve && wantCves.has(t.cve.toUpperCase())) && !wantIds) continue
    if (t.requiresTier3 && options.tier < 3) { skipped.push({ id: t.id, reason: 'requires Tier 3' }); continue }
    // Vendor appliances are excluded unless the fingerprint names the vendor explicitly.
    const vendorTags = t.tech.filter(x => vendorApplianceTechTags.has(x))
    if (vendorTags.length > 0 && !vendorTags.some(x => tags.has(x))) {
      skipped.push({ id: t.id, reason: 'vendor appliance not fingerprinted' })
      continue
    }
    const techMatch = t.tech.includes('generic') || t.tech.includes(genericWebExposureTag) || t.tech.some(x => tags.has(x))
    if (!wantIds && !techMatch) { skipped.push({ id: t.id, reason: 'tech mismatch' }); continue }
    selected.push(t)
  }
  const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  selected.sort((a, b) =>
    templateGroupRank(a, tags) - templateGroupRank(b, tags) ||
    severityRank[a.severity] - severityRank[b.severity] ||
    Number(b.cve?.split('-')[1] ?? 0) - Number(a.cve?.split('-')[1] ?? 0) ||
    (a.cve ? 0 : 1) - (b.cve ? 0 : 1) ||
    a.id.localeCompare(b.id))
  if (selected.length > options.maxTemplates) {
    for (const t of selected.splice(options.maxTemplates)) skipped.push({ id: t.id, reason: 'template cap' })
  }
  return { selected, skipped }
}

export function selectTemplatesForTech(
  templates: readonly SafeTemplate[],
  options: { techTags?: readonly string[]; templateIds?: readonly string[]; cveIds?: readonly string[]; tier: number; maxTemplates?: number },
): TemplateSelection {
  const rawMax = options.maxTemplates ?? defaultCompiledTemplateLimit
  const clampedMax = Number.isFinite(rawMax)
    ? Math.max(1, Math.min(Math.round(rawMax), compiledTemplateLimitCeiling))
    : defaultCompiledTemplateLimit
  return selectSafeTemplates(templates, { ...options, maxTemplates: clampedMax })
}

/** Map known CVE ids to compiled/curated template ids for targeted template runs. */
export function selectTemplateIdsForCves(
  templates: readonly SafeTemplate[],
  cveIds: readonly string[],
): string[] {
  const wanted = new Set(cveIds.map(c => c.toUpperCase()))
  const ids: string[] = []
  for (const t of templates) {
    if (t.cve && wanted.has(t.cve.toUpperCase()) && !ids.includes(t.id)) ids.push(t.id)
  }
  return ids.slice(0, 40)
}

const techAliases: Record<string, TemplateTechTag> = {
  next: 'nextjs', nextjs: 'nextjs',
  spring: 'springboot', springboot: 'springboot',
  nest: 'nestjs', nestjs: 'nestjs',
  wp: 'wordpress', wordpress: 'wordpress',
  openapi: 'swagger', swagger: 'swagger',
  httpd: 'apache', apache2: 'apache',
  k8s: 'kubernetes', kubernetes: 'kubernetes',
  nodejs: 'node', node: 'node',
  reactjs: 'react', react: 'react',
  vuejs: 'vue', vue: 'vue',
  nuxtjs: 'nuxt', nuxt: 'nuxt',
  angularjs: 'angular', angular: 'angular',
  py: 'python', python3: 'python',
  golang: 'go', go: 'go',
  rubyonrails: 'rails', rails: 'rails',
  springactuator: 'actuator', actuator: 'actuator',
  aspnet: 'dotnet', csharp: 'dotnet',
  exposure: 'generic-web-exposure', exposures: 'generic-web-exposure',
  discovery: 'generic-web-exposure',
  'adobe-experience-manager': 'aem', experiencemanager: 'aem', aem: 'aem',
  '3cx': '3cx', threesixty: '3cx', avtech: 'avtech', cisco: 'cisco',
  'adobe-coldfusion': 'adobe', coldfusion: 'adobe',
}

export function normalizeTechTagSet(techTags?: readonly string[]): Set<string> {
  const tags = new Set((techTags ?? []).map(t => t.toLowerCase().replace(/[^a-z0-9]/g, '')).filter(Boolean))
  for (const t of [...tags]) {
    if (techAliases[t]) tags.add(techAliases[t])
  }
  return tags
}
