#!/usr/bin/env node
/**
 * Blueprint-Derived Fixture-Contamination Ratchet Lint (R2-20 / plans/claude_quality_2.md §20).
 *
 * Generalizes `check-v8-contamination.ts` by deriving fixture signatures directly from the
 * benchmark blueprints and runtime libraries under:
 *   - `benchmarks/realistic-bench/`
 *   - `benchmarks/reason-bench/`
 *   - `benchmarks/multihop-saas/`
 *
 * Three contamination categories are derived (minus a curated generic HTTP/OS lexicon so
 * ordinary REST nouns like `users`/`orders` and standard OS paths like `/etc/passwd` never
 * false-positive):
 *   1. `canary_grammar`  — synthetic canary / fake-secret grammars from `lib/canary.ts`,
 *                          `lib/vfs.ts`, `generator/variant.ts`, and `lib/domain-variant.ts`
 *                          (e.g. `rbc_`/`rbs_`/`rb[cs]_`/`rb[s]_`, `rb_fake_`, `mh_fake_`).
 *   2. `vfs_path`        — distinctive virtual-filesystem paths seeded by benchmark VFS libs
 *                          and app seeders (e.g. `/app/config/secrets.env`, `/app/.env`,
 *                          `/var/log/system/audit.log`, `/etc/opsportal/secrets.env`,
 *                          `/srv/ledger/internal-metadata.json`).
 *   3. `blueprint_route` — distinctive multi-segment or benchmark-specific full-route strings
 *                          derived from `truth/blueprint.ts` / `truth/routes.ts` across all
 *                          three benchmark suites (with `{noun:*}` expansion and `:param`
 *                          normalization), minus `GENERIC_HTTP_ROUTES`.
 *
 * Scans all of `src/server/**\/*.ts` (excluding `*.test.*` / `*.spec.*`) and enforces a
 * **monotone-shrinking baseline** stored in `scripts/fixture-contamination-baseline.json`:
 *   - Fails (exit 1) if ANY new hit appears (new `(file, category, token)` or count increase).
 *   - Fails (exit 1) if ANY baselined hit was removed/reduced without pruning the baseline
 *     (`prune-fail` discipline matching `scripts/check-unwired.ts`).
 *   - `--write-baseline` is strictly removal-only (monotone-shrinking) when a baseline already
 *     exists; it refuses to add new entries or raise existing counts.
 *
 * Usage:
 *   node scripts/check-fixture-contamination.ts                    # enforce ratchet
 *   node scripts/check-fixture-contamination.ts --json             # JSON report
 *   node scripts/check-fixture-contamination.ts --write-baseline   # monotone prune of baseline
 *   node scripts/check-fixture-contamination.ts --root <dir> [--baseline <path>]
 */
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, posix, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export type FixtureContaminationCategory = 'canary_grammar' | 'vfs_path' | 'blueprint_route'

export interface FixtureContaminationHit {
  /** Repo-relative POSIX path. */
  file: string
  /** 1-based line number. */
  line: number
  /** 1-based column number. */
  column: number
  /** Matched token / normalized route / VFS path. */
  token: string
  /** Canonical key used for line-number-independent monotone baseline accounting. */
  key: string
  category: FixtureContaminationCategory
  ruleId: string
}

export interface FixtureBaselineEntry {
  key: string
  file: string
  category: FixtureContaminationCategory
  token: string
  count: number
}

export interface FixtureContaminationBaseline {
  version: 1
  entries: FixtureBaselineEntry[]
}

export interface DerivedFixtureRules {
  canaryRegexes: Array<{ id: string; pattern: RegExp; description: string }>
  vfsPaths: string[]
  /** Exact distinctive lowercase routes (no :param segments). */
  exactRoutes: Set<string>
  /** Parameter-normalized distinctive lowercase route templates (`:param` placeholder). */
  templateRoutes: Set<string>
  /** Normalized route suffix map for prefix-normalized lookup (`/api/...`). */
  canonicalExactRoutes: Set<string>
  canonicalTemplateRoutes: Set<string>
  sources: {
    canaryFiles: string[]
    vfsFiles: string[]
    blueprintFiles: string[]
  }
}

export interface FixtureContaminationDiffEntry {
  key: string
  file: string
  category: FixtureContaminationCategory
  token: string
  expectedCount: number
  actualCount: number
}

export interface FixtureContaminationResult {
  ok: boolean
  rootDir: string
  benchmarksRoot: string
  filesScanned: number
  derivedCounts: {
    canaryRules: number
    vfsPaths: number
    blueprintRoutes: number
  }
  hits: FixtureContaminationHit[]
  totalHits: number
  baselineTotal: number
  newEntries: FixtureContaminationDiffEntry[]
  resolvedEntries: FixtureContaminationDiffEntry[]
  durationMs: number
}

export const DEFAULT_SCAN_DIRS = ['src/server'] as const
export const DEFAULT_BASELINE_REL = 'scripts/fixture-contamination-baseline.json'

const EXCLUDED_DIR_NAMES = new Set([
  'node_modules',
  '.git',
  'tests',
  '__tests__',
  'benchmarks',
  'dist',
])
const EXCLUDED_FILE_RE = /(?:\.test|\.spec)\.[^./\\]+$/i
const TS_FILE_RE = /\.(?:ts|tsx|mts|cts)$/i

/**
 * Curated generic OS paths that legitimate traversal / XXE oracles check on real targets.
 * Excluded when deriving benchmark-specific VFS paths.
 */
export const GENERIC_VFS_PATHS: ReadonlySet<string> = new Set([
  '/etc/passwd',
  '/etc/hosts',
  '/etc/shadow',
  '/etc/group',
  '/etc/hostname',
  '/etc/os-release',
])

/**
 * Curated generic HTTP/API route lexicon (common across real-world web apps).
 * Excluded when deriving distinctive benchmark blueprint routes so standard endpoints and
 * generic pool nouns like `users`/`orders`/`invoices` never false-positive.
 */
export const GENERIC_HTTP_ROUTES: ReadonlySet<string> = new Set([
  '/',
  '/health',
  '/login',
  '/logout',
  '/status',
  '/manifest.json',
  '/robots.txt',
  '/sitemap.xml',
  '/favicon.ico',
  '/openapi.json',
  '/swagger.json',
  '/assets/app.css',
  '/assets/app.js',
  '/oauth/authorize',
  '/oauth/token',
  '/api',
  '/api/health',
  '/api/me',
  '/api/me/email',
  '/api/user',
  '/api/users',
  '/api/users/:param',
  '/api/session',
  '/api/csrf',
  '/api/graphql',
  '/api/graphql/batch',
  '/api/search',
  '/api/settings',
  '/api/dashboard',
  '/api/docs',
  '/api/auth/login',
  '/api/auth/logout',
  '/api/auth/me',
  '/api/auth/token',
  '/api/auth/2fa',
  '/api/auth/sso',
  '/api/auth/sso/start',
  '/api/auth/sso/callback',
  '/api/auth/password/reset',
  '/api/admin/users',
  '/api/admin/users/:param',
  '/api/admin/config',
  '/api/admin/metrics',
  '/api/admin/flags',
  '/api/admin/settings',
  '/api/webhooks/receive',
  '/webhooks/receive',
  '/sso/start',
  '/sso/callback',
])

/**
 * Curated generic REST single-segment resource nouns. Single-segment `/api/<noun>` or
 * `/api/<noun>/:param` routes are ignored unless the noun is benchmark-distinctive (e.g.
 * `product-import`, `invoice-templates`, `webhook-events`).
 */
const DISTINCTIVE_SINGLE_RESOURCE_SLUGS: ReadonlySet<string> = new Set([
  'product-import',
  'invoice-templates',
  'webhook-events',
  'payment-intents',
  'exchange-rates',
  'billing-docs',
  'sales-orders',
  'catalog-feed',
  'shipping-labels',
  'service-accounts',
  'saved-views',
  'store-credit',
])

const API_PREFIX_RE = /^\/(?:api\/(?:v\d+|2)|api|rest|v\d+)(?=\/|$)/i
const PARAM_SEG_RE = /^:[A-Za-z_][A-Za-z0-9_]*$/
const BRACE_PARAM_SEG_RE = /^(?:\{\{[A-Za-z0-9_]+\}\}|\{[A-Za-z0-9_]+\})$/
const NOUN_REF_RE = /\{noun:([a-zA-Z0-9_-]+)\}/g
const PATH_CANDIDATE_RE = /(?<![A-Za-z0-9_.-])(\/(?:[A-Za-z0-9_.:{}-]+\/)*[A-Za-z0-9_.:{}-]+)/g

function toPosixRelative(rootDir: string, absPath: string): string {
  const rel = relative(rootDir, absPath)
  return sep === '/' ? rel : rel.split(sep).join(posix.sep)
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function collectFilesMatching(
  dirPath: string,
  predicate: (relName: string, absPath: string) => boolean,
  out: string[],
): void {
  if (!existsSync(dirPath)) return
  const entries = readdirSync(dirPath, { withFileTypes: true })
  entries.sort((a, b) => a.name.localeCompare(b.name))
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue
    const fullPath = join(dirPath, entry.name)
    if (entry.isDirectory()) {
      if (EXCLUDED_DIR_NAMES.has(entry.name)) continue
      collectFilesMatching(fullPath, predicate, out)
    } else if (entry.isFile() && predicate(entry.name, fullPath)) {
      out.push(fullPath)
    }
  }
}

function collectBenchmarkFiles(
  benchDir: string,
  predicate: (absPath: string) => boolean,
  out: string[],
): void {
  if (!existsSync(benchDir)) return
  const walk = (dir: string) => {
    const entries = readdirSync(dir, { withFileTypes: true })
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === 'tests' || entry.name === '.git') continue
        walk(full)
      } else if (entry.isFile() && entry.name.endsWith('.ts') && !EXCLUDED_FILE_RE.test(entry.name)) {
        if (predicate(full)) out.push(full)
      }
    }
  }
  walk(benchDir)
}

function normalizePathParams(rawPath: string): { normalized: string; hasParam: boolean } {
  const withoutQuery = rawPath.split('?')[0]!
  const segs = withoutQuery.split('/').filter(Boolean)
  let hasParam = false
  const mapped = segs.map((seg) => {
    if (PARAM_SEG_RE.test(seg) || BRACE_PARAM_SEG_RE.test(seg)) {
      hasParam = true
      return ':param'
    }
    return seg.toLowerCase()
  })
  return { normalized: `/${mapped.join('/')}`, hasParam }
}

function canonicalizeApiPrefix(normalizedPath: string): string {
  if (API_PREFIX_RE.test(normalizedPath)) {
    const rest = normalizedPath.replace(API_PREFIX_RE, '')
    return rest ? `/api${rest}` : '/api'
  }
  return normalizedPath
}

function isDistinctiveRoute(normalizedPath: string): boolean {
  const canonical = canonicalizeApiPrefix(normalizedPath)
  if (GENERIC_HTTP_ROUTES.has(normalizedPath) || GENERIC_HTTP_ROUTES.has(canonical)) return false
  if (normalizedPath.endsWith('.json')) return true

  const hasApiPrefix = API_PREFIX_RE.test(normalizedPath)
  const rest = hasApiPrefix ? normalizedPath.replace(API_PREFIX_RE, '') : normalizedPath
  const segs = rest.split('/').filter(Boolean)
  if (segs.length === 0) return false

  // Single-segment non-API route (e.g. `/orders`, `/plans`, `/audit`) is too generic.
  if (!hasApiPrefix && segs.length < 2) return false

  const literalSegs = segs.filter(s => s !== ':param')
  if (literalSegs.length === 0) return false

  // Single-resource REST endpoint (`/api/<noun>` or `/api/<noun>/:param`): only distinctive if
  // the slug itself is a benchmark-specific compound noun (not a generic REST pool noun).
  if (segs.length === 1 || (segs.length === 2 && segs[1] === ':param')) {
    return DISTINCTIVE_SINGLE_RESOURCE_SLUGS.has(literalSegs[0]!)
  }

  // Multi-segment route (>= 2 non-prefix segments, e.g. `/api/checkout/return`,
  // `/api/hooks/:param/ping`, `/api/orders/:param/confirm`, `/files/export/:param/:param`):
  // distinctive unless explicitly listed in GENERIC_HTTP_ROUTES.
  return literalSegs.length >= 2 || (segs.length >= 3 && literalSegs.length >= 1)
}

/** Extract `key: ['syn1', 'syn2', ...]` vocab dictionary from a blueprint/routes source file. */
function parseBlueprintVocab(text: string): Record<string, string[]> {
  const vocab: Record<string, string[]> = {}
  const vocabStartRe = /\b(?:vocab|VOCAB)\s*(?::\s*Record<[^>]+>\s*=\s*|=|:)\s*\{/g
  for (const startMatch of text.matchAll(vocabStartRe)) {
    const openIdx = startMatch.index! + startMatch[0]!.length - 1
    let depth = 0
    let closeIdx = -1
    for (let i = openIdx; i < text.length; i += 1) {
      const ch = text[i]
      if (ch === '{') depth += 1
      else if (ch === '}') {
        depth -= 1
        if (depth === 0) { closeIdx = i; break }
      }
    }
    if (closeIdx < 0) continue
    const body = text.slice(openIdx + 1, closeIdx)
    const entryRe = /['"]?([a-zA-Z0-9_-]+)['"]?\s*:\s*\[([^\]]+)\]/g
    for (const entryMatch of body.matchAll(entryRe)) {
      const key = entryMatch[1]!
      const items: string[] = []
      for (const itemMatch of entryMatch[2]!.matchAll(/['"]([^'"]+)['"]/g)) {
        items.push(itemMatch[1]!)
      }
      if (items.length > 0) vocab[key] = items
    }
  }
  return vocab
}

/** Expand `{noun:X}` placeholders in a blueprint route template using `vocab`. */
function expandRouteTemplate(template: string, vocab: Record<string, string[]>): string[] {
  const refs = [...template.matchAll(NOUN_REF_RE)]
  if (refs.length === 0) return [template]
  let acc = [template]
  for (const m of refs) {
    const nounKey = m[1]!
    const synonyms = vocab[nounKey] ?? [nounKey]
    const next: string[] = []
    for (const cur of acc) {
      for (const syn of synonyms) {
        next.push(cur.replace(m[0]!, syn))
      }
    }
    acc = next
    if (acc.length > 64) break
  }
  return acc
}

/**
 * Derive canary grammar rules, VFS paths, and distinctive blueprint routes directly from the
 * benchmark trees under `benchmarksRoot/benchmarks/{realistic-bench,reason-bench,multihop-saas}`.
 */
export function deriveFixtureRules(benchmarksRoot: string): DerivedFixtureRules {
  const resolvedRoot = resolve(benchmarksRoot)
  const suites = ['realistic-bench', 'reason-bench', 'multihop-saas']

  // 1. Canary grammar rules derived from canary.ts, vfs.ts, variant.ts, domain-variant.ts
  const canaryFiles: string[] = []
  const canaryKinds = new Set<string>()
  const fakePrefixes = new Set<string>()
  for (const suite of suites) {
    const suiteDir = join(resolvedRoot, 'benchmarks', suite)
    const candidates = [
      join(suiteDir, 'lib', 'canary.ts'),
      join(suiteDir, 'lib', 'vfs.ts'),
      join(suiteDir, 'generator', 'variant.ts'),
      join(suiteDir, 'lib', 'domain-variant.ts'),
    ]
    for (const abs of candidates) {
      if (!existsSync(abs)) continue
      canaryFiles.push(toPosixRelative(resolvedRoot, abs))
      const txt = readFileSync(abs, 'utf8')
      for (const m of txt.matchAll(/mk\s*\(\s*['"]([a-z]{2,4})['"]/g)) {
        canaryKinds.add(m[1]!)
      }
      for (const m of txt.matchAll(/\b((?:rb|mh)_fake)_/g)) {
        fakePrefixes.add(`${m[1]!}_`)
      }
    }
  }

  const canaryRegexes: Array<{ id: string; pattern: RegExp; description: string }> = []
  if (canaryKinds.size > 0) {
    // Group 3-letter canary kinds sharing a 2-letter prefix (e.g. `rbc`, `rbs` -> stem `rb`, chars `cs`)
    // so both concrete tokens (`rbc_`, `rbs_`) and regex-class literals (`rb[cs]_`, `rb[s]_`) match.
    const byStem = new Map<string, Set<string>>()
    const standalone: string[] = []
    for (const kind of [...canaryKinds].sort()) {
      if (kind.length === 3) {
        const stem = kind.slice(0, 2)
        const ch = kind.slice(2)
        let set = byStem.get(stem)
        if (!set) { set = new Set(); byStem.set(stem, set) }
        set.add(ch)
      } else {
        standalone.push(`${escapeRegex(kind)}_`)
      }
    }
    const alts: string[] = [...standalone]
    for (const [stem, chars] of byStem) {
      const sortedChars = [...chars].sort()
      const charUnion = sortedChars.map(escapeRegex).join('|')
      const charClass = sortedChars.map(escapeRegex).join('')
      alts.push(`${escapeRegex(stem)}(?:${charUnion}|\\[[${charClass}]{1,${sortedChars.length}}\\])_`)
    }
    canaryRegexes.push({
      id: 'derived-canary-grammar',
      pattern: new RegExp(`(?<![A-Za-z0-9_])(?:${alts.join('|')})`, 'gi'),
      description: `Blueprint-derived canary grammar (${[...canaryKinds].sort().join(', ')})`,
    })
  }
  if (fakePrefixes.size > 0) {
    const alts = [...fakePrefixes].sort().map(escapeRegex)
    canaryRegexes.push({
      id: 'derived-fake-secret-prefix',
      pattern: new RegExp(`(?<![A-Za-z0-9_])(?:${alts.join('|')})`, 'gi'),
      description: `Blueprint-derived synthetic secret prefix (${[...fakePrefixes].sort().join(', ')})`,
    })
  }

  // 2. VFS paths derived from lib/vfs.ts and app seed/context files
  const vfsFiles: string[] = []
  const vfsPathSet = new Set<string>()
  for (const suite of suites) {
    const suiteDir = join(resolvedRoot, 'benchmarks', suite)
    collectBenchmarkFiles(
      suiteDir,
      (abs) => {
        const rel = toPosixRelative(resolvedRoot, abs)
        return (
          rel.endsWith('/lib/vfs.ts')
          || /\/apps\/[^/]+\/src\/(?:seed(?:-data)?|context)\.ts$/.test(rel)
        )
      },
      vfsFiles,
    )
  }
  const vfsRelFiles: string[] = []
  for (const abs of vfsFiles) {
    vfsRelFiles.push(toPosixRelative(resolvedRoot, abs))
    const txt = readFileSync(abs, 'utf8')
    if (!/vfs|defaultSystemFiles/i.test(txt)) continue
    for (const m of txt.matchAll(/['"](\/(?:etc|app|var|srv|opt)\/[a-zA-Z0-9._/-]+)['"]/g)) {
      const p = m[1]!
      if (p.split('/').filter(Boolean).length < 2) continue
      if (GENERIC_VFS_PATHS.has(p)) continue
      vfsPathSet.add(p)
    }
  }
  const vfsPaths = [...vfsPathSet].sort()

  // 3. Distinctive full-route strings derived from all blueprint/routes files
  const blueprintAbsFiles: string[] = []
  for (const suite of suites) {
    const appsDir = join(resolvedRoot, 'benchmarks', suite, 'apps')
    collectBenchmarkFiles(
      appsDir,
      (abs) => {
        const rel = toPosixRelative(resolvedRoot, abs)
        return /\/truth\/(?:blueprint|routes)\.ts$/.test(rel)
      },
      blueprintAbsFiles,
    )
  }

  const exactRoutes = new Set<string>()
  const templateRoutes = new Set<string>()
  const canonicalExactRoutes = new Set<string>()
  const canonicalTemplateRoutes = new Set<string>()
  const blueprintRelFiles: string[] = []

  for (const abs of blueprintAbsFiles) {
    blueprintRelFiles.push(toPosixRelative(resolvedRoot, abs))
    const txt = readFileSync(abs, 'utf8')
    const vocab = parseBlueprintVocab(txt)

    const rawTemplates: string[] = []
    // realistic-bench & reason-bench: r('GET', '/api/...')
    for (const m of txt.matchAll(/\br\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]\s*\)/g)) {
      rawTemplates.push(m[1]!)
    }
    // multihop-saas apiCatalog tuples: ['routeKey', 'svc', 'METHOD', `${p}/...` | '/...', ...]
    for (const m of txt.matchAll(/['"](?:GET|POST|PUT|PATCH|DELETE)['"]\s*,\s*(?:`\$\{p\}([^`]+)`|['"]([^'"]+)['"])/g)) {
      const route = m[1] ? `/api${m[1]}` : m[2]!
      rawTemplates.push(route)
    }

    for (const rawTmpl of rawTemplates) {
      const expanded = expandRouteTemplate(rawTmpl, vocab)
      for (const route of expanded) {
        const { normalized, hasParam } = normalizePathParams(route)
        if (!isDistinctiveRoute(normalized)) continue
        const canonical = canonicalizeApiPrefix(normalized)
        if (hasParam) {
          templateRoutes.add(normalized)
          canonicalTemplateRoutes.add(canonical)
        } else {
          exactRoutes.add(normalized)
          canonicalExactRoutes.add(canonical)
        }
      }
    }
  }

  return {
    canaryRegexes,
    vfsPaths,
    exactRoutes,
    templateRoutes,
    canonicalExactRoutes,
    canonicalTemplateRoutes,
    sources: {
      canaryFiles,
      vfsFiles: vfsRelFiles,
      blueprintFiles: blueprintRelFiles,
    },
  }
}

function buildVfsRegex(vfsPaths: readonly string[]): RegExp | null {
  if (vfsPaths.length === 0) return null
  // Sort longest first so `/app/config/secrets.env` matches before any shorter prefix.
  const sorted = [...vfsPaths].sort((a, b) => b.length - a.length)
  const alts = sorted.map((p) => {
    const bare = p.replace(/^\/+/, '')
    return `(?:\\/|%2f)?${escapeRegex(bare)}`
  })
  return new RegExp(`(?<![A-Za-z0-9_.-])(?:${alts.join('|')})(?![A-Za-z0-9_.-])`, 'gi')
}

function makeHitKey(file: string, category: FixtureContaminationCategory, token: string): string {
  return `${file}::${category}::${token}`
}

/** Scan a single file's text against derived fixture-contamination rules. */
export function scanTextForFixtureContamination(
  file: string,
  content: string,
  rules: DerivedFixtureRules,
): FixtureContaminationHit[] {
  const hits: FixtureContaminationHit[] = []
  const lines = content.split(/\r?\n/)
  const vfsRe = buildVfsRegex(rules.vfsPaths)

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx += 1) {
    const lineText = lines[lineIdx]!

    // 1. Canary grammar rules
    for (const rule of rules.canaryRegexes) {
      const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`
      const re = new RegExp(rule.pattern.source, flags)
      let match: RegExpExecArray | null
      while ((match = re.exec(lineText)) !== null) {
        const token = match[0]!.toLowerCase()
        hits.push({
          file,
          line: lineIdx + 1,
          column: match.index + 1,
          token,
          key: makeHitKey(file, 'canary_grammar', token),
          category: 'canary_grammar',
          ruleId: rule.id,
        })
        if (match[0]!.length === 0) re.lastIndex += 1
      }
    }

    // 2. Derived VFS path rules
    if (vfsRe) {
      vfsRe.lastIndex = 0
      let match: RegExpExecArray | null
      while ((match = vfsRe.exec(lineText)) !== null) {
        const normalizedVfs = `/${match[0]!.replace(/^(?:\/|%2f)+/i, '').toLowerCase()}`
        hits.push({
          file,
          line: lineIdx + 1,
          column: match.index + 1,
          token: normalizedVfs,
          key: makeHitKey(file, 'vfs_path', normalizedVfs),
          category: 'vfs_path',
          ruleId: 'derived-vfs-path',
        })
        if (match[0]!.length === 0) vfsRe.lastIndex += 1
      }
    }

    // 3. Derived distinctive blueprint route rules (O(1) lookup per path candidate)
    if (lineText.includes('/')) {
      PATH_CANDIDATE_RE.lastIndex = 0
      let match: RegExpExecArray | null
      while ((match = PATH_CANDIDATE_RE.exec(lineText)) !== null) {
        const rawCandidate = match[1]!
        // Skip URL scheme tails (e.g. `//example.com/...`) and comment dividers (`//...`).
        if (match.index > 0 && lineText[match.index - 1] === '/') continue
        const { normalized, hasParam } = normalizePathParams(rawCandidate)
        const canonical = canonicalizeApiPrefix(normalized)
        let matchedToken: string | null = null
        if (hasParam) {
          if (rules.templateRoutes.has(normalized)) matchedToken = normalized
          else if (rules.canonicalTemplateRoutes.has(canonical)) matchedToken = canonical
        } else {
          if (rules.exactRoutes.has(normalized)) matchedToken = normalized
          else if (rules.canonicalExactRoutes.has(canonical)) matchedToken = canonical
        }
        if (matchedToken) {
          hits.push({
            file,
            line: lineIdx + 1,
            column: match.index + 1,
            token: matchedToken,
            key: makeHitKey(file, 'blueprint_route', matchedToken),
            category: 'blueprint_route',
            ruleId: 'derived-blueprint-route',
          })
        }
        if (match[0]!.length === 0) PATH_CANDIDATE_RE.lastIndex += 1
      }
    }
  }

  return hits
}

function aggregateHitCounts(hits: readonly FixtureContaminationHit[]): Map<string, FixtureBaselineEntry> {
  const counts = new Map<string, FixtureBaselineEntry>()
  for (const h of hits) {
    const prev = counts.get(h.key)
    if (prev) {
      prev.count += 1
    } else {
      counts.set(h.key, {
        key: h.key,
        file: h.file,
        category: h.category,
        token: h.token,
        count: 1,
      })
    }
  }
  return counts
}

export function loadFixtureBaseline(baselinePath: string): FixtureContaminationBaseline {
  if (!existsSync(baselinePath)) {
    return { version: 1, entries: [] }
  }
  return JSON.parse(readFileSync(baselinePath, 'utf8')) as FixtureContaminationBaseline
}

export function buildBaselineFromHits(hits: readonly FixtureContaminationHit[]): FixtureContaminationBaseline {
  const entries = [...aggregateHitCounts(hits).values()].sort((a, b) => a.key.localeCompare(b.key))
  return { version: 1, entries }
}

export interface RunFixtureContaminationOptions {
  rootDir?: string
  benchmarksRoot?: string
  dirs?: readonly string[]
  baselinePath?: string
  baseline?: FixtureContaminationBaseline
  rules?: DerivedFixtureRules
}

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

/**
 * Scan `src/server/**\/*.ts` against blueprint-derived fixture rules and compare against
 * the monotone-shrinking baseline.
 */
export function runFixtureContaminationCheck(
  options: RunFixtureContaminationOptions = {},
): FixtureContaminationResult {
  const startedAt = performance.now()
  const rootDir = resolve(options.rootDir ?? REPO_ROOT)
  const benchmarksRoot = resolve(
    options.benchmarksRoot
      ?? (existsSync(join(rootDir, 'benchmarks')) ? rootDir : REPO_ROOT),
  )
  const dirs = options.dirs ?? DEFAULT_SCAN_DIRS
  const rules = options.rules ?? deriveFixtureRules(benchmarksRoot)
  const baselinePath = options.baselinePath ?? join(rootDir, DEFAULT_BASELINE_REL)
  const baseline = options.baseline ?? loadFixtureBaseline(baselinePath)

  const absFiles: string[] = []
  for (const relDir of dirs) {
    const absDir = resolve(rootDir, relDir)
    collectFilesMatching(
      absDir,
      (name) => TS_FILE_RE.test(name) && !name.endsWith('.d.ts') && !EXCLUDED_FILE_RE.test(name),
      absFiles,
    )
  }

  const hits: FixtureContaminationHit[] = []
  let filesScanned = 0
  for (const absFile of absFiles) {
    const raw = readFileSync(absFile)
    if (raw.includes(0)) continue
    filesScanned += 1
    const relFile = toPosixRelative(rootDir, absFile)
    const fileHits = scanTextForFixtureContamination(relFile, raw.toString('utf8'), rules)
    for (const h of fileHits) hits.push(h)
  }

  const actualMap = aggregateHitCounts(hits)
  const baselineMap = new Map<string, FixtureBaselineEntry>()
  for (const entry of baseline.entries) {
    baselineMap.set(entry.key, entry)
  }

  const newEntries: FixtureContaminationDiffEntry[] = []
  const resolvedEntries: FixtureContaminationDiffEntry[] = []

  for (const [key, actual] of [...actualMap.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const expected = baselineMap.get(key)
    const expectedCount = expected?.count ?? 0
    if (actual.count > expectedCount) {
      newEntries.push({
        key,
        file: actual.file,
        category: actual.category,
        token: actual.token,
        expectedCount,
        actualCount: actual.count,
      })
    }
  }

  for (const [key, expected] of [...baselineMap.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const actualCount = actualMap.get(key)?.count ?? 0
    if (actualCount < expected.count) {
      resolvedEntries.push({
        key,
        file: expected.file,
        category: expected.category,
        token: expected.token,
        expectedCount: expected.count,
        actualCount,
      })
    }
  }

  const baselineTotal = baseline.entries.reduce((sum, e) => sum + e.count, 0)
  const durationMs = Math.max(0, Math.round(performance.now() - startedAt))

  return {
    ok: newEntries.length === 0 && resolvedEntries.length === 0,
    rootDir,
    benchmarksRoot,
    filesScanned,
    derivedCounts: {
      canaryRules: rules.canaryRegexes.length,
      vfsPaths: rules.vfsPaths.length,
      blueprintRoutes: rules.exactRoutes.size + rules.templateRoutes.size,
    },
    hits,
    totalHits: hits.length,
    baselineTotal,
    newEntries,
    resolvedEntries,
    durationMs,
  }
}

export interface UpdateFixtureBaselineResult {
  ok: boolean
  wrote: boolean
  addedEntries: FixtureContaminationDiffEntry[]
  prunedEntries: FixtureContaminationDiffEntry[]
  previousTotal: number
  nextTotal: number
  baseline: FixtureContaminationBaseline | null
  error?: string
}

/**
 * Monotone-shrinking baseline writer:
 * - When a baseline file already exists, strictly REMOVAL-ONLY (prunes resolved entries / reduces
 *   counts and REFUSES to add new entries or raise existing counts).
 * - When no baseline file exists yet (initial bootstrap), writes the initial snapshot.
 */
export function updateFixtureBaselineMonotone(opts: {
  rootDir: string
  benchmarksRoot?: string
  baselinePath: string
  allowBootstrap?: boolean
}): UpdateFixtureBaselineResult {
  const baselineExists = existsSync(opts.baselinePath)
  const existing = baselineExists ? loadFixtureBaseline(opts.baselinePath) : { version: 1 as const, entries: [] }
  const scan = runFixtureContaminationCheck({
    rootDir: opts.rootDir,
    benchmarksRoot: opts.benchmarksRoot,
    baseline: existing,
  })
  const candidate = buildBaselineFromHits(scan.hits)
  const previousTotal = existing.entries.reduce((sum, e) => sum + e.count, 0)
  const nextTotal = candidate.entries.reduce((sum, e) => sum + e.count, 0)

  if (baselineExists && scan.newEntries.length > 0) {
    return {
      ok: false,
      wrote: false,
      addedEntries: scan.newEntries,
      prunedEntries: scan.resolvedEntries,
      previousTotal,
      nextTotal,
      baseline: null,
      error:
        `--write-baseline is strictly monotone-shrinking (removal-only); refusing to add/increase `
        + `${scan.newEntries.length} fixture-contamination entry/entries: `
        + scan.newEntries.slice(0, 6).map(e => `${e.key} (${e.expectedCount}->${e.actualCount})`).join(', '),
    }
  }
  if (!baselineExists && !opts.allowBootstrap) {
    return {
      ok: false,
      wrote: false,
      addedEntries: scan.newEntries,
      prunedEntries: [],
      previousTotal: 0,
      nextTotal,
      baseline: null,
      error: `Baseline file does not exist at ${opts.baselinePath}; pass --bootstrap to create initial baseline.`,
    }
  }

  writeFileSync(opts.baselinePath, `${JSON.stringify(candidate, null, 2)}\n`, 'utf8')
  return {
    ok: true,
    wrote: true,
    addedEntries: baselineExists ? [] : scan.newEntries,
    prunedEntries: scan.resolvedEntries,
    previousTotal,
    nextTotal,
    baseline: candidate,
  }
}

export function formatFixtureContaminationReport(res: FixtureContaminationResult): string {
  const header =
    `fixture-contamination: ${res.ok ? 'PASS' : 'FAIL'} `
    + `(files=${res.filesScanned}, hits=${res.totalHits}, baseline=${res.baselineTotal}, `
    + `new=${res.newEntries.length}, resolved=${res.resolvedEntries.length}, `
    + `derived=[canary:${res.derivedCounts.canaryRules}, vfs:${res.derivedCounts.vfsPaths}, routes:${res.derivedCounts.blueprintRoutes}], `
    + `${res.durationMs}ms)`
  if (res.ok) return header

  const lines = [header]
  for (const e of res.newEntries) {
    lines.push(
      `  FAIL [new-contamination]: ${e.file} [${e.category}] "${e.token}" `
      + `(expected=${e.expectedCount}, actual=${e.actualCount})`,
    )
  }
  for (const e of res.resolvedEntries) {
    lines.push(
      `  FAIL [resolved-baseline]: ${e.file} [${e.category}] "${e.token}" `
      + `(baseline=${e.expectedCount}, actual=${e.actualCount}) — prune via: node scripts/check-fixture-contamination.ts --write-baseline`,
    )
  }
  return lines.join('\n')
}

const usage = `Kovo Hunter Blueprint-Derived Fixture-Contamination Ratchet Lint (R2-20)

Usage:
  node scripts/check-fixture-contamination.ts [--root <dir>] [--baseline <path>] [--json] [--write-baseline] [--bootstrap] [--help]

Derives canary grammars, VFS paths, and distinctive blueprint routes from benchmarks/{realistic-bench,reason-bench,multihop-saas}
and enforces a monotone-shrinking baseline over src/server/**/*.ts.
`

export function main(argv: string[] = process.argv.slice(2)): number {
  let rootDir = REPO_ROOT
  let baselinePath: string | null = null
  let json = false
  let writeBaseline = false
  let bootstrap = false

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--help' || arg === '-h') {
      process.stdout.write(usage)
      return 0
    }
    if (arg === '--json') { json = true; continue }
    if (arg === '--write-baseline') { writeBaseline = true; continue }
    if (arg === '--bootstrap') { bootstrap = true; continue }
    if (arg === '--root') {
      const next = argv[++i]
      if (!next) { process.stderr.write('error: --root requires a directory\n'); return 2 }
      rootDir = resolve(next)
      continue
    }
    if (arg === '--baseline') {
      const next = argv[++i]
      if (!next) { process.stderr.write('error: --baseline requires a path\n'); return 2 }
      baselinePath = resolve(next)
      continue
    }
    process.stderr.write(`error: unknown argument '${arg}'\n`)
    return 2
  }

  const resolvedBaseline = baselinePath ?? join(rootDir, DEFAULT_BASELINE_REL)

  if (writeBaseline) {
    const upd = updateFixtureBaselineMonotone({
      rootDir,
      baselinePath: resolvedBaseline,
      allowBootstrap: bootstrap,
    })
    if (json) {
      process.stdout.write(`${JSON.stringify(upd, null, 2)}\n`)
    } else if (!upd.ok) {
      process.stderr.write(`fixture-contamination --write-baseline: FAIL — ${upd.error}\n`)
    } else {
      process.stdout.write(
        `wrote ${toPosixRelative(rootDir, resolvedBaseline)}: entries=${upd.baseline!.entries.length}, `
        + `totalHits=${upd.nextTotal} (previous=${upd.previousTotal}, pruned=${upd.prunedEntries.length})\n`,
      )
    }
    return upd.ok ? 0 : 1
  }

  const res = runFixtureContaminationCheck({ rootDir, baselinePath: resolvedBaseline })
  if (json) {
    process.stdout.write(`${JSON.stringify(res, null, 2)}\n`)
  } else {
    const report = `${formatFixtureContaminationReport(res)}\n`
    if (res.ok) process.stdout.write(report)
    else process.stderr.write(report)
  }
  return res.ok ? 0 : 1
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  process.exit(main())
}
