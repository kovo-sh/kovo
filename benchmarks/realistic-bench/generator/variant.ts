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
export function generateVariant(bp: AppBlueprint, seed: number, opts?: { salt?: string }): VariantPlan {
  validateBlueprint(bp)
  const { seedSet, prng } = resolveSeed(seed, opts?.salt)

  const apiPrefix = prng.fork('apiPrefix').pick(bp.apiPrefixes)
  const params = pickParams(prng.fork('params'), bp.paramVocab)
  const idFormat = prng.fork('idFormat').pick(bp.idFormats)

  let routes: Record<string, RouteSpec> | null = null
  for (let attempt = 0; attempt < 16 && !routes; attempt++) {
    const vocab = pickVocab(prng.fork(attempt === 0 ? 'vocab' : `vocab:${attempt}`), bp.vocab)
    routes = buildRoutes(bp, apiPrefix, vocab, params)
  }
  if (!routes) throw new Error(`could not build collision-free routes for ${bp.app}`)

  const personas = buildPersonas(prng.fork('personas'), bp)
  const canarySalt = prng.fork('canary').hex(16)
  const sites = assignModes(prng.fork('sites'), bp)

  return { app: bp.app, seed, seedSet, apiPrefix, routes, params, idFormat, sites, personas, canarySalt }
}
