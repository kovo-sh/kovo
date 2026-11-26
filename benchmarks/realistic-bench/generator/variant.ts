// Blueprint + seed -> VariantPlan. Each randomized dimension draws from an independently forked
// PRNG stream so adding a site later cannot reshuffle unrelated choices.
import type {
  AppBlueprint,
  PersonaCredential,
  PersonaId,
  RouteSpec,
  SiteMode,
  VariantPlan,
} from '../lib/types.ts'
import type { Prng } from '../lib/prng.ts'
import { resolveSeed } from './seeds.ts'
import { validateBlueprint } from './validate.ts'
import { groupUnits, reachableSubsets } from './subset.ts'

const NOUN_REF = /\{noun:([a-zA-Z0-9_-]+)\}/g

/**
 * Neutral out-of-distribution roots used by `novelVocab` mode. Chosen to avoid generic REST/API
 * domain vocabulary and scanner route/param heuristics so novel-vocabulary generalization is
 * measured honestly against unseen entity, route, and parameter identifiers.
 */
const NOVEL_ROOTS: readonly string[] = [
  'acorn', 'alder', 'amber', 'aspen', 'basalt', 'birch', 'breeze', 'cairn', 'cedar', 'chert',
  'clover', 'coral', 'cove', 'creek', 'dune', 'elm', 'ember', 'fern', 'fjord', 'flint',
  'glade', 'gneiss', 'granite', 'grove', 'hazel', 'heath', 'indigo', 'islet', 'ivory', 'jasper',
  'juniper', 'kelp', 'kestrel', 'knoll', 'larch', 'lichen', 'linen', 'marble', 'meadow', 'moss',
  'nectar', 'nimbus', 'ochre', 'opal', 'osier', 'pebble', 'pine', 'plume', 'quartz', 'quill',
  'reed', 'ridge', 'sedge', 'shale', 'slate', 'spruce', 'tarn', 'thistle', 'timber', 'umber',
  'upland', 'vale', 'vetch', 'weir', 'willow', 'wren', 'yarrow', 'yucca', 'zenith', 'zephyr',
]

export interface GenerateVariantOptions {
  salt?: string
  /**
   * When true, deterministically substitutes non-pool, out-of-distribution API prefix, route
   * entity nouns, and parameter names derived from the seed PRNG.
   * When false or omitted, default blueprint pool generation is preserved bit-for-bit.
   */
  novelVocab?: boolean
}

function collectBlueprintPoolTokens(bp: AppBlueprint): Set<string> {
  const pool = new Set<string>()
  for (const prefix of bp.apiPrefixes) {
    pool.add(prefix.toLowerCase())
    for (const seg of prefix.split('/').filter(Boolean)) pool.add(seg.toLowerCase())
  }
  for (const [key, values] of Object.entries(bp.vocab)) {
    pool.add(key.toLowerCase())
    for (const v of values) pool.add(v.toLowerCase())
  }
  for (const [key, values] of Object.entries(bp.paramVocab)) {
    pool.add(key.toLowerCase())
    for (const v of values) pool.add(v.toLowerCase())
  }
  for (const tmpl of Object.values(bp.routes)) {
    for (const seg of tmpl.path.split('/').filter(Boolean)) {
      if (!seg.startsWith(':') && !seg.startsWith('{noun:')) pool.add(seg.toLowerCase())
    }
  }
  return pool
}

function pickNovelApiPrefix(p: Prng, forbidden: ReadonlySet<string>): string {
  const roots = p.shuffle(NOVEL_ROOTS)
  for (const root of roots) {
    const candidate = `/nv-${root}-${p.hex(2)}`
    if (!forbidden.has(candidate) && !forbidden.has(candidate.slice(1))) return candidate
  }
  return `/nv-${p.hex(4)}`
}

function pickNovelVocab(
  p: Prng,
  vocab: Record<string, string[]>,
  forbidden: ReadonlySet<string>,
): Record<string, string> {
  const roots = p.shuffle(NOVEL_ROOTS)
  const out: Record<string, string> = {}
  const used = new Set<string>()
  let idx = 0
  for (const key of Object.keys(vocab)) {
    let candidate = ''
    for (let tries = 0; tries < 32; tries++) {
      const root = roots[(idx + tries) % roots.length]!
      const next = `${root}-${p.hex(2)}`
      if (!used.has(next) && !forbidden.has(next)) {
        candidate = next
        break
      }
    }
    if (!candidate) candidate = `nv-${p.hex(4)}`
    used.add(candidate)
    out[key] = candidate
    idx += 1
  }
  return out
}

function pickNovelParams(
  p: Prng,
  paramVocab: Record<string, string[]>,
  forbidden: ReadonlySet<string>,
): Record<string, string> {
  const roots = p.shuffle(NOVEL_ROOTS)
  const out: Record<string, string> = {}
  const used = new Set<string>()
  let idx = 0
  for (const key of Object.keys(paramVocab)) {
    let candidate = ''
    for (let tries = 0; tries < 32; tries++) {
      const root = roots[(idx + tries) % roots.length]!
      // Valid JS / route-param identifier matching /^[a-z][a-zA-Z0-9_]*$/ without heuristic suffixes.
      const next = `${root}X${p.hex(2)}`
      if (!used.has(next) && !forbidden.has(next.toLowerCase())) {
        candidate = next
        break
      }
    }
    if (!candidate) candidate = `nvX${p.hex(4)}`
    used.add(candidate)
    out[key] = candidate
    idx += 1
  }
  return out
}

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

function buildPersonas(p: Prng, bp: AppBlueprint): Record<PersonaId, PersonaCredential> {
  const brand = bp.app.split('-')[0] || 'tenant'
  const slugA = p.hex(3)
  const slugB = p.hex(3)
  const defs: Array<{ id: PersonaId; slug: string; role: PersonaCredential['role'] }> = [
    { id: 'persona_a', slug: slugA, role: 'owner' },
    { id: 'persona_b', slug: slugB, role: 'owner' },
    { id: 'admin', slug: slugA, role: 'admin' },
    { id: 'viewer', slug: slugA, role: 'viewer' },
  ]
  const out = {} as Record<PersonaId, PersonaCredential>
  for (const d of defs) {
    out[d.id] = {
      id: d.id,
      email: `${d.id}@${brand}-${d.slug}.test`,
      password: `rb_fake_${p.hex(12)}`,
      tenant: d.slug,
      role: d.role,
    }
  }
  return out
}

function assignModes(p: Prng, bp: AppBlueprint): Record<string, SiteMode> {
  const sites: Record<string, SiteMode> = {}
  const units = groupUnits(bp.sites)
  for (const u of units) if (!u.decoyable) for (const id of u.siteIds) sites[id] = 'vulnerable'
  const decoyable = p.shuffle(units.filter((u) => u.decoyable))
  const reach = reachableSubsets(decoyable.map((u) => u.size))
  const targets = [...reach.keys()].filter((t) => t >= bp.decoyCount.min && t <= bp.decoyCount.max).sort((a, b) => a - b)
  if (targets.length === 0) throw new Error(`decoyCount [${bp.decoyCount.min},${bp.decoyCount.max}] is infeasible`)
  const chosen = new Set(reach.get(p.pick(targets))!)
  decoyable.forEach((u, i) => {
    const mode: SiteMode = chosen.has(i) ? 'hardened' : 'vulnerable'
    for (const id of u.siteIds) sites[id] = mode
  })
  return sites
}

/** Deterministically derive a VariantPlan from a blueprint + seed (+ held-out salt). */
export function generateVariant(bp: AppBlueprint, seed: number, opts?: GenerateVariantOptions): VariantPlan {
  validateBlueprint(bp)
  const { seedSet, prng } = resolveSeed(seed, opts?.salt)

  let apiPrefix: string
  let params: Record<string, string>
  const idFormat = prng.fork('idFormat').pick(bp.idFormats)
  let routes: Record<string, RouteSpec> | null = null

  if (opts?.novelVocab) {
    const forbidden = collectBlueprintPoolTokens(bp)
    apiPrefix = pickNovelApiPrefix(prng.fork('novelApiPrefix'), forbidden)
    params = pickNovelParams(prng.fork('novelParams'), bp.paramVocab, forbidden)
    for (let attempt = 0; attempt < 16 && !routes; attempt++) {
      const vocab = pickNovelVocab(prng.fork(attempt === 0 ? 'novelVocab' : `novelVocab:${attempt}`), bp.vocab, forbidden)
      routes = buildRoutes(bp, apiPrefix, vocab, params)
    }
  } else {
    apiPrefix = prng.fork('apiPrefix').pick(bp.apiPrefixes)
    params = pickParams(prng.fork('params'), bp.paramVocab)
    for (let attempt = 0; attempt < 16 && !routes; attempt++) {
      const vocab = pickVocab(prng.fork(attempt === 0 ? 'vocab' : `vocab:${attempt}`), bp.vocab)
      routes = buildRoutes(bp, apiPrefix, vocab, params)
    }
  }
  if (!routes) throw new Error(`could not build collision-free routes for ${bp.app}`)

  const personas = buildPersonas(prng.fork('personas'), bp)
  const canarySalt = prng.fork('canary').hex(16)
  const sites = assignModes(prng.fork('sites'), bp)

  return { app: bp.app, seed, seedSet, apiPrefix, routes, params, idFormat, sites, personas, canarySalt }
}
