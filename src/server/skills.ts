import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export interface SkillSummary {
  name: string
  title: string
  summary: string
  tags: string[]
}

export interface LoadedSkill extends SkillSummary {
  content: string
}

export const MULTIHOP_CHAINS_SKILL = 'multihop-chains' as const

const safeSkillName = /^[a-z0-9][a-z0-9-]{0,63}$/

const SKILL_ALIASES: Record<string, string> = {
  'multi-hop': MULTIHOP_CHAINS_SKILL,
  multihop: MULTIHOP_CHAINS_SKILL,
  'multihop-chain': MULTIHOP_CHAINS_SKILL,
  'hop-checkpoint': MULTIHOP_CHAINS_SKILL,
  'composite-receipt': MULTIHOP_CHAINS_SKILL,
  'composite-proof': MULTIHOP_CHAINS_SKILL,
}

export function resolveSkillName(name: string): string | null {
  const normalized = name.trim().toLowerCase().replace(/\.md$/, '')
  if (!safeSkillName.test(normalized)) return null
  return SKILL_ALIASES[normalized] ?? normalized
}

function resolveSkillsDir(): string {
  const fromHere = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'skills')
  if (existsSync(fromHere)) return fromHere
  const fromCwd = resolve(process.cwd(), 'src', 'skills')
  if (existsSync(fromCwd)) return fromCwd
  return fromHere
}

function parseMeta(name: string, content: string): SkillSummary {
  const lines = content.split(/\r?\n/)
  const heading = lines.find(line => line.startsWith('# '))?.slice(2).trim() ?? name
  const tagsLine = lines.find(line => /^tags\s*:/i.test(line))
  const tags = tagsLine
    ? tagsLine.replace(/^tags\s*:/i, '').split(',').map(t => t.trim()).filter(Boolean)
    : []
  const summaryLine = lines.find(line => /^summary\s*:/i.test(line))
  const summary = summaryLine
    ? summaryLine.replace(/^summary\s*:/i, '').trim()
    : (lines.find(line => line.trim() && !line.startsWith('#') && !/^tags\s*:/i.test(line)) ?? '').trim().slice(0, 220)
  return { name, title: heading, summary, tags }
}

let cachedSkills: Map<string, LoadedSkill> | undefined

function loadAll(): Map<string, LoadedSkill> {
  if (cachedSkills) return cachedSkills
  const dir = resolveSkillsDir()
  const map = new Map<string, LoadedSkill>()
  if (!existsSync(dir)) return map
  for (const entry of readdirSync(dir).sort()) {
    if (!entry.endsWith('.md')) continue
    const name = entry.slice(0, -3)
    if (!safeSkillName.test(name)) continue
    const content = readFileSync(join(dir, entry), 'utf8').trim()
    map.set(name, { ...parseMeta(name, content), content })
  }
  cachedSkills = map
  return map
}

export function clearSkillsCache(): void {
  cachedSkills = undefined
}

export function listSkills(): SkillSummary[] {
  return [...loadAll().values()].map(({ content: _omit, ...meta }) => meta)
}

export function skillsByTag(tag: string): SkillSummary[] {
  const needle = tag.trim().toLowerCase()
  if (!needle) return []
  return listSkills().filter(skill => skill.tags.some(t => t.toLowerCase() === needle))
}

export function listSkillTags(): string[] {
  const tags = new Set<string>()
  for (const skill of loadAll().values()) {
    for (const tag of skill.tags) tags.add(tag.toLowerCase())
  }
  return [...tags].sort()
}

export function searchSkills(query: string): SkillSummary[] {
  const needle = query.trim().toLowerCase()
  if (!needle) return listSkills()
  return listSkills().filter(skill =>
    skill.name.toLowerCase().includes(needle) ||
    skill.title.toLowerCase().includes(needle) ||
    skill.summary.toLowerCase().includes(needle) ||
    skill.tags.some(t => t.toLowerCase().includes(needle)),
  )
}

export function loadSkill(name: string): LoadedSkill | null {
  const resolved = resolveSkillName(name)
  if (!resolved) return null
  return loadAll().get(resolved) ?? null
}

export interface PreInjectedSkill extends SkillSummary {
  excerpt: string
  score: number
}

export interface SelectPreInjectionSkillsInput {
  profileSkills?: readonly string[]
  /** Optional step-level skill slugs (e.g. 'multihop-chains', 'chain-primitives', 'chain:*'). */
  stepSkills?: readonly string[]
  techTags?: readonly string[]
  sinkKind?: string
  category?: string
  title?: string
  hypothesis?: string
  /** Optional dispatch lane (e.g. 'chain' | 'multihop' | 'frontier'). */
  lane?: string
  /** Optional mission kind (e.g. 'chain', 'chain_step_2', 'multihop_chain', 'second_order'). */
  missionKind?: string
  /** Explicit signal that this assignment is a multi-hop chain or frontier continuation. */
  multiHop?: boolean
  /** True when the assignment brief embeds a v8 hopCheckpoint or depends on verified parent hops. */
  hasHopCheckpoint?: boolean
  /** Chain hop depth (>= 2 indicates a multi-hop continuation). */
  hopDepth?: number
  limit?: number
}

const maxPreInjectedSkillChars = 1200

const MULTIHOP_MISSION_KINDS = new Set(['chain', 'chain_step', 'chain_step_2', 'multihop_chain', 'second_order'])
const MULTIHOP_MISSION_KIND_RE = /^(?:chain(?:[-_]?step(?:[-_]?\d+)?)?|multi[-_]?hop(?:[-_]?chain)?|second[-_]?order)$/i
const MULTIHOP_LANE_RE = /^(?:chain|multi[-_]?hop|frontier(?:[-_]?chain)?)$/i
const MULTIHOP_CATEGORY_RE = /^(?:chain|chain[-_]?step(?:[-_]?\d+)?|multi[-_]?hop(?:[-_]?chain)?|chain[-_]?pivot|cross[-_]?service[-_]?chain|cross[-_]?tenant[-_]?chain|composite[-_]?chain)$/i
const MULTIHOP_TEXT_RE =
  /\b(?:multi[- ]?hop|[2-8][- ]?hops?|hop[- ]?checkpoint|hop[-_ ]?[2-8]\b|chain[-_ ]?step(?:[-_ ]?[2-8])?\b|composite\s*(?:proof|receipt)|prove_composite|seal_capability|hmac_sign|jwt_sign|await_async|value_binding|derived_crypto_binding|state_transition_binding|async_pivot_binding|derived\s+capability|(?:cross[- ](?:service|tenant|surface)|capability)\s+(?:pivot|chain)|sub[- ]?chain\s+fus(?:e|ion)|cap:hop_)\b/i

/** Map a sinkKind to the skill tags that document how to audit it. */
const SINK_SKILL_TAGS: Record<string, readonly string[]> = {
  db_query: ['sqli', 'sql', 'database'],
  outbound_fetch: ['ssrf', 'oob', 'canary'],
  redirect: ['open-redirect', 'redirect', 'ssrf'],
  upload_storage: ['upload', 'storage', 'path-traversal'],
  postmessage_iframe: ['postmessage', 'dom', 'client-side'],
  auth_config: ['jwt', 'auth', 'oauth'],
  webhook: ['webhook', 'auth', 'business-logic'],
  server_action: ['bola', 'business-logic', 'authz'],
  api_route: ['api', 'bola', 'authz'],
  async_job: ['async-pivot', 'multihop'],
  cross_surface: ['multihop', 'chaining'],
}

/**
 * Determine whether an assignment is a v8 multi-hop chain continuation or pivot.
 * Deliberately ignores generic single-hop prose (such as a `det_lead` merely mentioning "chain")
 * so single-hop specialist pre-injection rankings remain deterministic and unchanged.
 */
export function isMultiHopChainAssignment(input: Omit<SelectPreInjectionSkillsInput, 'limit'>): boolean {
  if (input.multiHop === true || input.hasHopCheckpoint === true) return true
  if (typeof input.hopDepth === 'number' && Number.isFinite(input.hopDepth) && input.hopDepth >= 2) return true
  if (input.lane && MULTIHOP_LANE_RE.test(input.lane.trim())) return true
  if (input.missionKind) {
    const normalized = input.missionKind.trim().toLowerCase()
    if (MULTIHOP_MISSION_KINDS.has(normalized) || MULTIHOP_MISSION_KIND_RE.test(normalized)) return true
  }
  if ((input.profileSkills ?? []).some(name => resolveSkillName(name) === MULTIHOP_CHAINS_SKILL)) return true
  if ((input.stepSkills ?? []).some(name => {
    const trimmed = name.trim().toLowerCase()
    return resolveSkillName(trimmed) === MULTIHOP_CHAINS_SKILL || trimmed === 'chain-primitives' || trimmed.startsWith('chain:')
  })) return true
  if (input.category && MULTIHOP_CATEGORY_RE.test(input.category.trim())) return true
  if (input.sinkKind && ['async_job', 'cross_surface'].includes(input.sinkKind.trim().toLowerCase())) return true
  const text = `${input.title ?? ''} ${input.hypothesis ?? ''}`
  return text.trim().length > 0 && MULTIHOP_TEXT_RE.test(text)
}

/**
 * Return a deduplicated list of resolved skill slugs for a specialist profile, appending
 * `multihop-chains` when dispatching a multi-hop chain assignment.
 */
export function resolveSkillsForProfile(
  profileSkills: readonly string[],
  options?: { multiHop?: boolean },
): string[] {
  const loaded = loadAll()
  const out: string[] = []
  const seen = new Set<string>()
  const push = (raw: string) => {
    const resolved = resolveSkillName(raw)
    if (!resolved || seen.has(resolved) || !loaded.has(resolved)) return
    seen.add(resolved)
    out.push(resolved)
  }
  for (const skill of profileSkills) push(skill)
  if (options?.multiHop) push(MULTIHOP_CHAINS_SKILL)
  return out
}

/**
 * Deterministically pick the top 1-2 curated playbooks for a worker prompt from
 * `specialistProfile` skills, detected tech tags, sink kind, and multi-hop chain signals.
 * This exists so the curated skill catalog does not rely on pull-only `load_skill` discovery.
 */
export function selectPreInjectionSkills(input: SelectPreInjectionSkillsInput): PreInjectedSkill[] {
  const limit = Math.max(0, Math.min(2, input.limit ?? 2))
  if (limit === 0) return []
  const loaded = loadAll()
  const scores = new Map<string, number>()
  const bump = (name: string, weight: number) => {
    const resolved = resolveSkillName(name)
    if (!resolved || !loaded.has(resolved)) return
    scores.set(resolved, (scores.get(resolved) ?? 0) + weight)
  }

  for (const name of input.profileSkills ?? []) bump(name, 10)
  for (const tag of input.techTags ?? []) {
    for (const skill of skillsByTag(tag)) bump(skill.name, 4)
  }
  const sinkTags = input.sinkKind ? SINK_SKILL_TAGS[input.sinkKind.toLowerCase()] ?? [] : []
  for (const tag of sinkTags) {
    for (const skill of skillsByTag(tag)) bump(skill.name, 3)
  }
  const text = `${input.title ?? ''} ${input.hypothesis ?? ''}`.toLowerCase()
  if (text.trim()) {
    for (const token of new Set(text.replace(/[^a-z0-9]+/g, ' ').split(/\s+/))) {
      if (token.length < 4) continue
      for (const skill of searchSkills(token)) bump(skill.name, 1)
    }
  }

  const isMultiHop = isMultiHopChainAssignment(input)
  if (isMultiHop && loaded.has(MULTIHOP_CHAINS_SKILL)) {
    bump(MULTIHOP_CHAINS_SKILL, 15)
  }

  const ranked = [...scores.entries()]
    .sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0]))
    .slice(0, limit)

  // Guarantee multi-hop chain assignments always receive the multi-hop playbook while keeping
  // the top domain-specific playbook when limit >= 2.
  if (isMultiHop && loaded.has(MULTIHOP_CHAINS_SKILL) && !ranked.some(([name]) => name === MULTIHOP_CHAINS_SKILL)) {
    const multihopEntry: [string, number] = [MULTIHOP_CHAINS_SKILL, scores.get(MULTIHOP_CHAINS_SKILL) ?? 15]
    if (ranked.length < limit) ranked.push(multihopEntry)
    else ranked[ranked.length - 1] = multihopEntry
  }

  return ranked.flatMap(([name, score]) => {
    const skill = loaded.get(name)
    if (!skill) return []
    return [{
      name: skill.name,
      title: skill.title,
      summary: skill.summary,
      tags: skill.tags,
      excerpt: skill.content.slice(0, maxPreInjectedSkillChars),
      score,
    }]
  })
}
