// Blueprint + seed -> VariantPlan, plus dynamic site/app discovery for the app shells. Each
// randomized dimension draws from an independently forked PRNG stream so adding a site later
// cannot reshuffle unrelated choices. Semantic business vocabulary lives in domain-variant.ts.
import { existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import type {
  AppBlueprint, AppName, PersonaCredential, PersonaId, PersonaRole, RouteSpec, SiteMode,
  SiteSpec, VariantPlan, DomainVariant,
} from '../lib/types.ts'
import type { Prng } from '../lib/prng.ts'
import { resolveSeed } from './seeds.ts'
import { generateDomainVariant } from './domain-variant.ts'
import { validateBlueprint } from './validate.ts'
import { groupUnits, reachableSubsets } from './subset.ts'

const NOUN_REF = /\{noun:([a-zA-Z0-9_-]+)\}/g

function pickVocab(p: Prng, vocab: Record<string, string[]>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const key of Object.keys(vocab)) out[key] = p.pick(vocab[key]!)
  return out
}

function pickParams(p: Prng, paramVocab: Record<string, string[]>): Record<string, string> {
  const out: Record<string, string> = {}
  const used = new Set<string>()
  for (const key of Object.keys(paramVocab)) {
    const options = p.shuffle(paramVocab[key]!)
    const name = options.find((o) => !used.has(o)) ?? `${options[0]}_${key}`
    used.add(name)
    out[key] = name
  }
  return out
}

function runtimePath(templatePath: string, apiPrefix: string, vocab: Record<string, string>, params: Record<string, string>): string {
  let path = templatePath.replace(NOUN_REF, (_, k: string) => vocab[k] ?? k)
  path = path
    .split('/')
    .map((seg) => (seg.startsWith(':') ? `:${params[seg.slice(1)] ?? seg.slice(1)}` : seg))
    .join('/')
  if (templatePath === '/api' || templatePath.startsWith('/api/')) path = apiPrefix + path.slice(4)
  return path
}

/** Build runtime routes; returns null if any (method,path) collides (caller re-picks vocab). */
function buildRoutes(bp: AppBlueprint, apiPrefix: string, vocab: Record<string, string>, params: Record<string, string>): Record<string, RouteSpec> | null {
  const routes: Record<string, RouteSpec> = {}
  const seen = new Set<string>()
  for (const [key, tmpl] of Object.entries(bp.routes)) {
    const path = runtimePath(tmpl.path, apiPrefix, vocab, params)
    const sig = `${tmpl.method} ${path}`
    if (seen.has(sig)) return null
    seen.add(sig)
    routes[key] = { method: tmpl.method, path }
  }
  return routes
}

function buildPersonas(p: Prng, bp: AppBlueprint, domain: DomainVariant): Record<PersonaId, PersonaCredential> {
  const brand = bp.app
  const mailDomain = `${brand}-${p.hex(3)}.test`
  const orgA = domain.tenants.orgA
  const orgB = domain.tenants.orgB
  const defs: Array<{
    id: PersonaId; tenant: string; role: PersonaRole; memberships?: Array<{ tenant: string; role: PersonaRole }>
    lifecycle?: PersonaCredential['lifecycle']
  }> = [
    { id: 'owner_a', tenant: orgA, role: 'owner', memberships: [{ tenant: orgA, role: 'owner' }] },
    { id: 'member_a', tenant: orgA, role: 'member', memberships: [{ tenant: orgA, role: 'member' }] },
    { id: 'viewer_a', tenant: orgA, role: 'viewer', memberships: [{ tenant: orgA, role: 'viewer' }] },
    {
      id: 'dual_member', tenant: orgA, role: 'admin',
      memberships: [{ tenant: orgA, role: 'admin' }, { tenant: orgB, role: 'viewer' }],
    },
    { id: 'member_b', tenant: orgB, role: 'member', memberships: [{ tenant: orgB, role: 'member' }] },
    {
      id: 'revoked_or_demoted', tenant: orgA, role: 'admin',
      memberships: [{ tenant: orgA, role: 'admin' }],
      lifecycle: { fromRole: 'admin', toRole: 'viewer' },
    },
  ]
  const out = {} as Record<PersonaId, PersonaCredential>
  for (const d of defs) {
    out[d.id] = {
      id: d.id,
      email: `${d.id.replace(/_/g, '.')}@${mailDomain}`,
      password: `rb_fake_${p.hex(12)}`,
      tenant: d.tenant,
      role: d.role,
      memberships: d.memberships,
      lifecycle: d.lifecycle,
    }
  }
  return out
}

function assignModes(p: Prng, bp: AppBlueprint): Record<string, SiteMode> {
  const sites: Record<string, SiteMode> = {}
  const units = groupUnits(bp.sites)
  for (const u of units) if (!u.decoyable) for (const id of u.siteIds) sites[id] = 'vulnerable'
  const decoyable = p.shuffle(units.filter((u) => u.decoyable))
  // A shell with in-progress (or zero) site directories is a valid intermediate state: it
  // simply has nothing to harden yet. Full-app blueprints still enforce the declared range.
  if (decoyable.length === 0) return sites
  const reach = reachableSubsets(decoyable.map((u) => u.size))
  const targets = [...reach.keys()].filter((t) => t >= bp.decoyCount.min && t <= bp.decoyCount.max).sort((a, b) => a - b)
  if (targets.length === 0) {
    if (bp.sites.length === 0) return sites
    throw new Error(`decoyCount [${bp.decoyCount.min},${bp.decoyCount.max}] is infeasible`)
  }
  const chosen = new Set(reach.get(p.pick(targets))!)
  decoyable.forEach((u, i) => {
    const mode: SiteMode = chosen.has(i) ? 'hardened' : 'vulnerable'
    for (const id of u.siteIds) sites[id] = mode
  })
  return sites
}

/** Deterministically derive a VariantPlan from a blueprint + seed (+ held-out salt). */
export function generateVariant(bp: AppBlueprint, seed: number, opts?: { salt?: string }): VariantPlan {
  validateBlueprint(bp)
  const { seedSet, prng } = resolveSeed(seed, opts?.salt)

  const apiPrefix = prng.fork('apiPrefix').pick(bp.apiPrefixes)
  const params = pickParams(prng.fork('params'), bp.paramVocab)
  const idFormat = prng.fork('idFormat').pick(bp.idFormats)
  const domain = generateDomainVariant(bp.app, seed, prng.fork('domainVariant'), bp.domain)

  let routes: Record<string, RouteSpec> | null = null
  for (let attempt = 0; attempt < 16 && !routes; attempt++) {
    const vocab = pickVocab(prng.fork(attempt === 0 ? 'vocab' : `vocab:${attempt}`), bp.vocab)
    routes = buildRoutes(bp, apiPrefix, vocab, params)
  }
  if (!routes) throw new Error(`could not build collision-free routes for ${bp.app}`)

  const personas = buildPersonas(prng.fork('personas'), bp, domain)
  const canarySalt = prng.fork('canary').hex(16)
  const sites = assignModes(prng.fork('sites'), bp)

  return {
    app: bp.app, seed, seedSet, apiPrefix, routes, params, idFormat, sites, personas, canarySalt, domain,
  }
}

// ---------------------------------------------------------------------------------------------
// Dynamic discovery. App shells must enumerate sites/*/spec.ts (never a hardcoded list) so a new
// site is picked up by the harness as soon as its spec + twins exist. Apps may be absent during M0;
// callers handle an empty result.
// ---------------------------------------------------------------------------------------------
export async function discoverSiteSpecs(appDir: string): Promise<SiteSpec[]> {
  const sitesDir = join(appDir, 'sites')
  if (!existsSync(sitesDir)) return []
  const out: SiteSpec[] = []
  const seen = new Set<string>()
  for (const entry of readdirSync(sitesDir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isDirectory()) continue
    const specPath = join(sitesDir, entry.name, 'spec.ts')
    if (!existsSync(specPath)) continue
    const mod = (await import(pathToFileURL(specPath).href)) as { default?: SiteSpec; spec?: SiteSpec }
    const spec = mod.default ?? mod.spec
    if (!spec) throw new Error(`${specPath} must default-export (or named-export) a SiteSpec`)
    if (seen.has(spec.id)) throw new Error(`duplicate discovered site id '${spec.id}' under ${sitesDir}`)
    seen.add(spec.id)
    out.push(spec)
  }
  return out
}

/** Discover app names by enumerating immediate subdirectories that contain an index.ts. */
export function discoverAppNames(appsRoot: string): string[] {
  if (!existsSync(appsRoot)) return []
  return readdirSync(appsRoot, { withFileTypes: true })
    .filter((e) => e.isDirectory() && existsSync(join(appsRoot, e.name, 'index.ts')))
    .map((e) => e.name)
    .sort()
}

/** Resolve an app directory by name under appsRoot, or null when the app shell is not built yet. */
export function appDirFor(appsRoot: string, app: AppName): string | null {
  const dir = join(appsRoot, app)
  return existsSync(join(dir, 'index.ts')) ? dir : null
}

/** Clone a blueprint with dynamically discovered sites (used by app shells/tests). */
export async function withDiscoveredSites(bp: AppBlueprint, appDir: string): Promise<AppBlueprint> {
  const sites = await discoverSiteSpecs(appDir)
  return sites.length > 0 ? { ...bp, sites } : bp
}
