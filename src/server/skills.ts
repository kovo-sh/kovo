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
