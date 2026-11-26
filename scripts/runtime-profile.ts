/**
 * Canonical production Node runtime profile & hermetic fast-test environment builder
 * (`R2-02`, `plans/claude_quality_2.md` §2).
 *
 * Single source of truth for:
 *   - `PRODUCTION_NODE_FLAGS`: matches `package.json` (`start`/`scan`) and `scripts/cli.ts`.
 *   - `buildHermeticTestEnv(tmpDir)`: allowlisted child process environment with isolated
 *     per-file `KOVO_DATA_DIR`, `TMPDIR`, and XDG data/config dirs, stripping ambient
 *     `KOVO_*`, `OPENROUTER_*`, proxy vars, and other host leaks unless explicitly allowlisted.
 */
import { existsSync, mkdirSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

export const PRODUCTION_NODE_FLAGS: readonly string[] = Object.freeze([
  '--disable-proto=delete',
  '--enable-experimental-regexp-engine-on-excessive-backtracks',
  '--regexp-backtracks-before-fallback=10000',
])

export const DEFAULT_TEST_NODE_OPTIONS = '--max-old-space-size=2048'

export const HERMETIC_ENV_ALLOWLIST: readonly string[] = Object.freeze([
  'PATH',
  'HOME',
  'USER',
  'LOGNAME',
  'SHELL',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TERM',
  'TZ',
  'CI',
  'XDG_CACHE_HOME',
  'PLAYWRIGHT_BROWSERS_PATH',
  'SYSTEMROOT',
  'COMSPEC',
  'PATHEXT',
  'WINDIR',
])

export interface HermeticTestEnvOptions {
  /** Ambient source environment (defaults to `process.env`). */
  baseEnv?: NodeJS.ProcessEnv
  /** Additional ambient variable names explicitly allowed through. */
  allowlist?: readonly string[]
  /** Explicit key/value overrides injected after isolation (undefined deletes). */
  extraEnv?: Record<string, string | undefined>
  /** Override NODE_OPTIONS for the child process (defaults to `--max-old-space-size=2048`). */
  nodeOptions?: string
}

export function buildHermeticTestEnv(
  tmpDir: string,
  options: HermeticTestEnvOptions = {},
): NodeJS.ProcessEnv {
  const resolvedTmp = resolve(tmpDir)
  const baseEnv = options.baseEnv ?? process.env
  const allowed = new Set<string>(HERMETIC_ENV_ALLOWLIST)
  if (options.allowlist) {
    for (const key of options.allowlist) allowed.add(key)
  }

  const env: NodeJS.ProcessEnv = {}
  for (const key of allowed) {
    const val = baseEnv[key]
    if (val !== undefined) {
      env[key] = val
    }
  }

  // Short subdirectory names ('d' / 't') keep child TMPDIR paths well below the
  // Linux 108-byte Unix domain socket sun_path limit.
  const childTmp = join(resolvedTmp, 't')
  env.KOVO_DATA_DIR = join(resolvedTmp, 'd')
  env.TMPDIR = childTmp
  env.TMP = childTmp
  env.TEMP = childTmp
  env.XDG_DATA_HOME = join(resolvedTmp, 'xdg-d')
  env.XDG_CONFIG_HOME = join(resolvedTmp, 'xdg-c')
  env.NODE_OPTIONS = options.nodeOptions ?? DEFAULT_TEST_NODE_OPTIONS

  if (options.extraEnv) {
    for (const [key, val] of Object.entries(options.extraEnv)) {
      if (val === undefined) {
        delete env[key]
      } else {
        env[key] = val
      }
    }
  }

  return env
}

/**
 * Resolve a short writable temp root for per-file hermetic test sandboxes.
 * Linux Unix domain sockets (`sun_path` max 108 bytes) fail with `EINVAL` when `TMPDIR`
 * is nested deeply, so when the requested root exceeds 24 bytes we prefer `/tmp` if available.
 */
export function resolveShortHermeticTmpRoot(preferredRoot: string = tmpdir()): string {
  const resolved = resolve(preferredRoot)
  if (resolved.length <= 24) return resolved
  if (process.platform !== 'win32' && existsSync('/tmp')) return '/tmp'
  return resolved
}

export function prepareHermeticTestDir(rootTmpDir: string = tmpdir(), prefix = 'kf-'): string {
  const effectiveRoot = resolveShortHermeticTmpRoot(rootTmpDir)
  mkdirSync(effectiveRoot, { recursive: true })
  const dir = mkdtempSync(join(effectiveRoot, prefix))
  mkdirSync(join(dir, 'd'), { recursive: true, mode: 0o700 })
  mkdirSync(join(dir, 't'), { recursive: true, mode: 0o700 })
  mkdirSync(join(dir, 'xdg-d'), { recursive: true, mode: 0o700 })
  mkdirSync(join(dir, 'xdg-c'), { recursive: true, mode: 0o700 })
  return dir
}

export function buildHermeticNodeTestArgs(
  testFile: string,
  extraTestArgs: readonly string[] = [],
): string[] {
  return [
    ...PRODUCTION_NODE_FLAGS,
    '--test',
    '--test-isolation=none',
    '--test-reporter=tap',
    ...extraTestArgs,
    testFile,
  ]
}

export interface ParsedTapCase {
  name: string
  status: 'pass' | 'fail' | 'skipped' | 'todo'
  failureType: string
  location: string
  error: string
}

export interface ParsedTapSummary {
  tests: number
  suites: number
  pass: number
  fail: number
  cancelled: number
  skipped: number
  todo: number
}

export interface ParsedTapResult {
  cases: ParsedTapCase[]
  summary: ParsedTapSummary
}

/**
 * Parse Node `--test-reporter=tap` output into canonical leaf test cases.
 *
 * Nested `describe()` / `t.test()` hierarchies are joined with ` > ` (matching TAP
 * 4-space indentation depth). Container rollups (`type: 'suite'` or parent tests whose
 * only failure is `failureType: 'subtestsFailed'`) are omitted so each failure maps
 * 1:1 to its actual failing leaf case.
 */
export function parseTapOutput(tapText: string, repoRoot?: string): ParsedTapResult {
  const lines = tapText.split(/\r?\n/)
  const stack: Array<{ depth: number; name: string; hadChildren: boolean }> = []
  const cases: ParsedTapCase[] = []
  const summary: ParsedTapSummary = {
    tests: 0,
    suites: 0,
    pass: 0,
    fail: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0,
  }
  const normRoot = repoRoot ? resolve(repoRoot).replace(/\\/g, '/').replace(/\/$/, '') : ''

  let i = 0
  while (i < lines.length) {
    const line = lines[i]!
    const sumM = /^# (tests|suites|pass|fail|cancelled|skipped|todo) (\d+)$/.exec(line)
    if (sumM) {
      summary[sumM[1] as keyof ParsedTapSummary] = Number(sumM[2])
      i += 1
      continue
    }

    const subM = /^((?:    )*)# Subtest: (.*)$/.exec(line)
    if (subM) {
      const depth = subM[1]!.length / 4
      while (stack.length > depth) stack.pop()
      if (stack.length > 0) stack[stack.length - 1]!.hadChildren = true
      stack.push({ depth, name: subM[2]!.replace(/\\#/g, '#'), hadChildren: false })
      i += 1
      continue
    }

    const resM = /^((?:    )*)(ok|not ok) (\d+)(?: - (.*))?$/.exec(line)
    if (resM) {
      const depth = resM[1]!.length / 4
      const ok = resM[2] === 'ok'
      let rawDesc = resM[4] ?? ''
      let directive: 'SKIP' | 'TODO' | null = null
      const dirM = /^(.*?)\s+#\s*(SKIP|TODO)(?:\s+(.*))?$/i.exec(rawDesc)
      if (dirM) {
        rawDesc = dirM[1]!
        directive = dirM[2]!.toUpperCase() as 'SKIP' | 'TODO'
      }
      while (stack.length > depth + 1) stack.pop()
      const top = stack.length === depth + 1 ? stack.pop()! : null
      const leafName = top ? top.name : rawDesc.replace(/\\#/g, '#')
      const fullName = [...stack.map(s => s.name), leafName].join(' > ')
      const hadChildren = top ? top.hadChildren : false

      let type = 'test'
      let failureType = ''
      let location = ''
      let error = ''
      if (i + 1 < lines.length && /^(\s+)---$/.test(lines[i + 1]!)) {
        const yamlIndent = /^(\s+)---$/.exec(lines[i + 1]!)![1]!
        i += 2
        while (i < lines.length && lines[i] !== `${yamlIndent}...`) {
          const yLine = lines[i]!
          if (yLine.startsWith(yamlIndent)) {
            const trimmed = yLine.slice(yamlIndent.length)
            const tm = /^type:\s*'?([^']+)'?$/.exec(trimmed)
            if (tm) type = tm[1]!.trim()
            const fm = /^failureType:\s*'?([^']+)'?$/.exec(trimmed)
            if (fm) failureType = fm[1]!.trim()
            const lm = /^location:\s*'?([^']+)'?$/.exec(trimmed)
            if (lm) {
              const rawLoc = lm[1]!.trim().replace(/\\/g, '/')
              location = normRoot && rawLoc.startsWith(`${normRoot}/`)
                ? rawLoc.slice(normRoot.length + 1)
                : rawLoc
            }
            const em = /^error:\s*(.+)$/.exec(trimmed)
            if (em && !error && em[1] !== '|-' && em[1] !== '|') {
              error = em[1]!.replace(/^['"]|['"]$/g, '').trim()
            }
          } else if (!error && yLine.trim() && yLine.startsWith(`${yamlIndent}  `)) {
            error = yLine.trim()
          }
          i += 1
        }
      }

      const isContainerRollup = (type === 'suite' || hadChildren) && (ok || failureType === 'subtestsFailed')
      if (!isContainerRollup) {
        const status: ParsedTapCase['status'] =
          directive === 'SKIP' ? 'skipped' : directive === 'TODO' ? 'todo' : ok ? 'pass' : 'fail'
        cases.push({ name: fullName, status, failureType, location, error })
      }
      i += 1
      continue
    }

    i += 1
  }

  return { cases, summary }
}
