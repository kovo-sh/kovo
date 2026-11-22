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

const safeSkillName = /^[a-z0-9][a-z0-9-]{0,63}$/

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
  const normalized = name.trim().toLowerCase().replace(/\.md$/, '')
  if (!safeSkillName.test(normalized)) return null
  return loadAll().get(normalized) ?? null
}

export interface PreInjectedSkill extends SkillSummary {
  excerpt: string
  score: number
}

const maxPreInjectedSkillChars = 1200

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
}

/**
 * Deterministically pick the top 1-2 curated playbooks for a worker prompt from
 * `specialistProfile` skills, detected tech tags, and the sink kind. This exists so the
 * 41-skill catalog does not rely on pull-only `load_skill` discovery.
 */
export function selectPreInjectionSkills(input: {
  profileSkills?: readonly string[]
  techTags?: readonly string[]
  sinkKind?: string
  category?: string
  title?: string
  hypothesis?: string
  limit?: number
}): PreInjectedSkill[] {
  const limit = Math.max(0, Math.min(2, input.limit ?? 2))
  if (limit === 0) return []
  const scores = new Map<string, number>()
  const bump = (name: string, weight: number) => {
    const normalized = name.trim().toLowerCase().replace(/\.md$/, '')
    if (!safeSkillName.test(normalized)) return
    if (!loadAll().has(normalized)) return
    scores.set(normalized, (scores.get(normalized) ?? 0) + weight)
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

  const ranked = [...scores.entries()]
    .sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0]))
    .slice(0, limit)

  const loaded = loadAll()
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
