#!/usr/bin/env node
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { cpSync, existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { pathToFileURL } from 'node:url'
import { assetOriginForEnvironment, personaHandle } from '../src/domain.ts'
import type { CapabilityTier, Finding } from '../src/domain.ts'
import { Execution } from '../src/server/execution.ts'
import { projectReposDir } from '../src/server/github-connector.ts'
import { assertLocalLabAllowed, LabRunner } from '../src/server/lab-runner.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import { exportReportMarkdown } from '../src/server/report-export.ts'
import { exportReportSarif } from '../src/server/sarif-export.ts'
import { Store } from '../src/server/store.ts'

export type FailOnSeverity = 'critical' | 'high' | 'medium' | 'low'

export interface CliOptions {
  command: 'scan' | 'help'
  repos: string[]
  diffBase?: string
  origins: string[]
  tier?: CapabilityTier
  personas: string[]
  maxRps: number
  budgetUsd: number
  budgetRequests?: number
  sarifPath?: string
  failOn: FailOnSeverity
  localLab: boolean
  outputDir: string
  goal?: string
  timeoutSec: number
  help: boolean
}

export interface ParsedPersonaConfig {
  handle: string
  roleLabel: string
  authKind: 'cookie' | 'bearer' | 'header'
  headerName?: string
  originAllowlist: string[]
  secret: string
  canaryMarkers: string[]
}

const SEVERITY_ORDER: Record<string, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

export function formatCliHelp(): string {
  return [
    'Guardian v3 Headless Security Scanner CLI',
    '',
    'Usage:',
    '  guardian scan [options]',
    '',
    'Options:',
    '  --repo <path>              Local repository path to mount read-only into /repos (repeatable)',
    '  --diff-base <ref>          PR-diff CI mode: scope audit to `git diff --name-only <ref>...HEAD`',
    '  --origin <url>             Approved target origin URL (repeatable)',
    '  --tier <0-3>               Capability tier (0=offline/static, 1=read-only, 2=auth, 3=active/HITL)',
    '  --persona <handle:file>    Persona credential file (repeatable; file MUST be mode 0600)',
    '  --max-rps <n>              Max requests per second per origin (default: 5)',
    '  --budget-usd <n>           Max LLM spend budget in USD (default: 15)',
    '  --budget-requests <n>      Max brokered requests (default: 4000 public / 10000 local-lab)',
    '  --sarif <path>             Write OASIS SARIF 2.1.0 report JSON to path',
    '  --fail-on <severity>       Exit code 2 threshold: critical|high|medium|low (default: high)',
    '  --local-lab                Enable local-lab HTTP/port target mode (requires GUARDIAN_ALLOW_LOCAL_LAB=1)',
    '  --output-dir <dir>         Output directory for SQLite state, Markdown & JSON reports',
    '  --goal <text>              Custom assessment goal prompt',
    '  --timeout-sec <n>          Maximum run duration in seconds (default: 900)',
    '  -h, --help                 Show this help message',
    '',
    'Exit Codes:',
    '  0  Completed cleanly with zero confirmed/static_verified findings >= --fail-on',
    '  1  Fatal error, invalid arguments, policy violation, or incomplete/failed run',
    '  2  One or more confirmed/static_verified findings >= --fail-on threshold',
  ].join('\n')
}

function validateOriginForCli(raw: string, localLab: boolean): string {
  if (localLab) {
    assertLocalLabAllowed('local-lab')
  }
  return assetOriginForEnvironment(localLab ? 'local-lab' : 'public').parse(raw)
}

export function parseCliArgs(argv: readonly string[]): CliOptions {
  const args = [...argv]
  let command: 'scan' | 'help' = 'scan'
  if (args[0] === 'scan') {
    args.shift()
  } else if (args[0] === 'help' || args[0] === '--help' || args[0] === '-h') {
    return {
      command: 'help',
      repos: [],
      origins: [],
      personas: [],
      maxRps: 5,
      budgetUsd: 15,
      failOn: 'high',
      localLab: false,
      outputDir: resolve('.guardian', 'cli-run'),
      timeoutSec: 900,
      help: true,
    }
  } else if (args[0] && !args[0].startsWith('-')) {
    throw new Error(`Unknown Guardian CLI command: "${args[0]}". Expected "guardian scan".`)
  }

  const opts: CliOptions = {
    command,
    repos: [],
    origins: [],
    personas: [],
    maxRps: 5,
    budgetUsd: 15,
    failOn: 'high',
    localLab: false,
    outputDir: resolve('.guardian', `cli-run-${Date.now()}`),
    timeoutSec: 900,
    help: false,
  }

  const nextValue = (flag: string, i: number): string => {
    const val = args[i + 1]
    if (val === undefined || val.startsWith('--')) {
      throw new Error(`Missing value for ${flag}.`)
    }
    return val
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    switch (arg) {
      case '-h':
      case '--help':
        opts.help = true
        opts.command = 'help'
        return opts
      case '--repo':
        opts.repos.push(resolve(nextValue(arg, i)))
        i++
        break
      case '--diff-base':
        opts.diffBase = nextValue(arg, i).trim()
        i++
        break
      case '--origin':
        opts.origins.push(nextValue(arg, i).trim())
        i++
        break
      case '--tier': {
        const raw = Number(nextValue(arg, i))
        if (!Number.isInteger(raw) || raw < 0 || raw > 3) {
          throw new Error(`Invalid --tier value "${args[i + 1]}": expected integer 0, 1, 2, or 3.`)
        }
        opts.tier = raw as CapabilityTier
        i++
        break
      }
      case '--persona':
        opts.personas.push(nextValue(arg, i))
        i++
        break
      case '--max-rps': {
        const n = Number(nextValue(arg, i))
        if (!Number.isInteger(n) || n < 1 || n > 20) {
          throw new Error(`Invalid --max-rps value "${args[i + 1]}": expected integer 1..20.`)
        }
        opts.maxRps = n
        i++
        break
      }
      case '--budget-usd': {
        const n = Number(nextValue(arg, i))
        if (!Number.isFinite(n) || n < 0.1 || n > 500) {
          throw new Error(`Invalid --budget-usd value "${args[i + 1]}": expected 0.1..500.`)
        }
        opts.budgetUsd = n
        i++
        break
      }
      case '--budget-requests': {
        const n = Number(nextValue(arg, i))
        if (!Number.isInteger(n) || n < 0 || n > 25_000) {
          throw new Error(`Invalid --budget-requests value "${args[i + 1]}": expected 0..25000.`)
        }
        opts.budgetRequests = n
        i++
        break
      }
      case '--sarif':
        opts.sarifPath = resolve(nextValue(arg, i))
        i++
        break
      case '--fail-on': {
        const val = nextValue(arg, i).toLowerCase()
        if (!['critical', 'high', 'medium', 'low'].includes(val)) {
          throw new Error(`Invalid --fail-on value "${val}": expected critical|high|medium|low.`)
        }
        opts.failOn = val as FailOnSeverity
        i++
        break
      }
      case '--local-lab':
        opts.localLab = true
        break
      case '--output-dir':
        opts.outputDir = resolve(nextValue(arg, i))
        i++
        break
      case '--goal':
        opts.goal = nextValue(arg, i).trim()
        i++
        break
      case '--timeout-sec': {
        const n = Number(nextValue(arg, i))
        if (!Number.isFinite(n) || n < 5 || n > 14_400) {
          throw new Error(`Invalid --timeout-sec value "${args[i + 1]}".`)
        }
        opts.timeoutSec = Math.floor(n)
        i++
        break
      }
      default:
        throw new Error(`Unknown CLI flag: "${arg}". Run "guardian scan --help" for usage.`)
    }
  }

  return opts
}

export function computeGitDiffScope(repoPath: string, diffBase: string): { diffBase: string; changedFiles: string[] } {
  if (!/^[a-zA-Z0-9._/@^~-]+$/.test(diffBase) || diffBase.startsWith('-')) {
    throw new Error(`Invalid --diff-base git ref: "${diffBase}"`)
  }
  if (!existsSync(repoPath) || !statSync(repoPath).isDirectory()) {
    throw new Error(`Repository path does not exist: ${repoPath}`)
  }
  const stdout = execFileSync('git', ['diff', '--name-only', `${diffBase}...HEAD`], {
    cwd: repoPath,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 15_000,
  })
  const changedFiles = stdout
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
  return { diffBase, changedFiles }
}

export function loadPersonaFile(
  spec: string,
  defaultOrigins: readonly string[],
  localLab = false,
): ParsedPersonaConfig {
  const colonIdx = spec.indexOf(':')
  if (colonIdx <= 0 || colonIdx === spec.length - 1) {
    throw new Error(`Invalid --persona "${spec}": expected "<handle>:<file>".`)
  }
  const handle = personaHandle.parse(spec.slice(0, colonIdx))
  const filePath = resolve(spec.slice(colonIdx + 1))
  if (!existsSync(filePath)) {
    throw new Error(`Persona credential file not found: ${filePath}`)
  }
  const st = statSync(filePath)
  if (!st.isFile()) {
    throw new Error(`Persona credential path is not a regular file: ${filePath}`)
  }
  // Non-negotiable Invariant #2: Persona credential files MUST have 0600 owner-only permissions.
  if ((st.mode & 0o077) !== 0) {
    throw new Error(
      `Persona credential file "${filePath}" has unsafe permissions (${(st.mode & 0o777).toString(8)}); must be owner-only (0600).`,
    )
  }

  const raw = readFileSync(filePath, 'utf8').trim()
  if (!raw) {
    throw new Error(`Persona credential file "${filePath}" is empty.`)
  }

  if (raw.startsWith('{')) {
    const parsed = JSON.parse(raw) as Record<string, unknown>
    const secret = typeof parsed.secret === 'string' ? parsed.secret.trim() : ''
    if (!secret) throw new Error(`Persona JSON file "${filePath}" missing non-empty "secret" field.`)
    const authKind = (parsed.authKind === 'cookie' || parsed.authKind === 'bearer' || parsed.authKind === 'header')
      ? parsed.authKind
      : 'bearer'
    const rawAllowlist = Array.isArray(parsed.originAllowlist) && parsed.originAllowlist.length > 0
      ? parsed.originAllowlist.map(o => validateOriginForCli(String(o), localLab))
      : [...defaultOrigins]
    if (!rawAllowlist.length) {
      throw new Error(`Persona "${handle}" requires at least one allowed origin (--origin or originAllowlist).`)
    }
    return {
      handle,
      roleLabel: typeof parsed.roleLabel === 'string' && parsed.roleLabel.trim() ? parsed.roleLabel.trim() : handle,
      authKind,
      headerName: typeof parsed.headerName === 'string' ? parsed.headerName : undefined,
      originAllowlist: rawAllowlist,
      secret,
      canaryMarkers: Array.isArray(parsed.canaryMarkers) ? parsed.canaryMarkers.map(String).slice(0, 16) : [],
    }
  }

  if (!defaultOrigins.length) {
    throw new Error(`Persona "${handle}" requires at least one --origin.`)
  }
  return {
    handle,
    roleLabel: handle,
    authKind: raw.includes('=') && raw.includes(';') ? 'cookie' : 'bearer',
    originAllowlist: [...defaultOrigins],
    secret: raw,
    canaryMarkers: [],
  }
}

export function determineExitCode(
  findings: ReadonlyArray<{ status: string; severity: Finding['severity']; verificationTier?: string }>,
  failOn: FailOnSeverity,
  runStatus?: string,
): 0 | 1 | 2 {
  const threshold = SEVERITY_ORDER[failOn] ?? SEVERITY_ORDER.high
  const triggered = findings.some(f => {
    const verified = f.status === 'confirmed' || f.status === 'static_verified' || f.verificationTier === 'static_verified'
    if (!verified) return false
    return (SEVERITY_ORDER[f.severity] ?? 0) >= threshold
  })
  if (triggered) return 2
  // Per SPEC-v3 §4.7A: exit 0 ONLY on complete runs; incomplete/stopped/paused/budget_paused/failed runs exit 1.
  if (runStatus && runStatus !== 'complete') {
    return 1
  }
  return 0
}

function mountLocalReposReadOnlyCopy(repos: readonly string[], destReposDir: string): string[] {
  mkdirSync(destReposDir, { recursive: true, mode: 0o700 })
  const mountedNames: string[] = []
  for (const repoPath of repos) {
    if (!existsSync(repoPath) || !statSync(repoPath).isDirectory()) {
      throw new Error(`Repository directory does not exist: ${repoPath}`)
    }
    const repoReal = realpathSync(repoPath)
    const name = basename(repoReal).replace(/[^a-zA-Z0-9._-]/g, '_') || 'repo'
    const target = join(destReposDir, name)
    cpSync(repoReal, target, {
      recursive: true,
      filter: src => {
        const base = basename(src)
        if (base === '.git' || base === 'node_modules' || /^\.env(?:\..+)?$/i.test(base)) return false
        return true
      },
    })
    mountedNames.push(name)
  }
  return mountedNames
}

export async function runCli(argv: readonly string[]): Promise<0 | 1 | 2> {
  let opts: CliOptions
  try {
    opts = parseCliArgs(argv)
  } catch (err) {
    console.error(`[guardian] ${err instanceof Error ? err.message : String(err)}`)
    return 1
  }

  if (opts.help || opts.command === 'help') {
    console.log(formatCliHelp())
    return 0
  }

  if (opts.localLab) {
    try {
      assertLocalLabAllowed('local-lab')
    } catch (err) {
      console.error(`[guardian] ${err instanceof Error ? err.message : String(err)}`)
      return 1
    }
  }

  if (opts.origins.length === 0 && opts.repos.length === 0) {
    console.error('[guardian] Provide at least one --origin <url> or --repo <path>. Run "guardian scan --help".')
    return 1
  }

  let validatedOrigins: string[]
  try {
    validatedOrigins = opts.origins.map(o => validateOriginForCli(o, opts.localLab))
  } catch (err) {
    console.error(`[guardian] ${err instanceof Error ? err.message : String(err)}`)
    return 1
  }

  // Compute offline PR-diff scoping before launching engine.
  const diffScopes: Array<{ repo: string; diffBase: string; changedFiles: string[] }> = []
  if (opts.diffBase) {
    if (opts.repos.length === 0) {
      console.error('[guardian] --diff-base requires at least one --repo <path>.')
      return 1
    }
    try {
      for (const repoPath of opts.repos) {
        const diff = computeGitDiffScope(repoPath, opts.diffBase)
        diffScopes.push({ repo: basename(repoPath), ...diff })
      }
    } catch (err) {
      console.error(`[guardian] Offline git diff scoping failed: ${err instanceof Error ? err.message : String(err)}`)
      return 1
    }
  }

  // Validate personas upfront (strict 0600 check before touching SQLite).
  let parsedPersonas: ParsedPersonaConfig[]
  try {
    parsedPersonas = opts.personas.map(p => loadPersonaFile(p, validatedOrigins, opts.localLab))
  } catch (err) {
    console.error(`[guardian] ${err instanceof Error ? err.message : String(err)}`)
    return 1
  }

  mkdirSync(opts.outputDir, { recursive: true, mode: 0o700 })
  const dataDir = join(opts.outputDir, 'data')
  mkdirSync(dataDir, { recursive: true, mode: 0o700 })

  const labRunner = new LabRunner()
  const storage = new Store(dataDir)
  const engine = new Execution(storage)

  try {
    const environment: 'public' | 'local-lab' = opts.localLab ? 'local-lab' : 'public'
    const tier: CapabilityTier = opts.tier ?? (validatedOrigins.length > 0 ? 1 : 0)
    const budgetRequests = opts.budgetRequests ?? (opts.localLab ? 10_000 : 4_000)

    // For repo-only Tier 0 offline scans without an explicit origin, use a synthetic static-only placeholder seed.
    const effectiveOrigins = validatedOrigins.length > 0
      ? validatedOrigins
      : (opts.localLab ? ['http://127.0.0.1:8080'] : ['https://static-audit.invalid'])

    const { id: projectId } = storage.createProject({
      requestId: randomUUID(),
      name: `CLI Scan (${basename(opts.outputDir)})`,
      seeds: effectiveOrigins,
      environment,
    })

    const mountedRepos = opts.repos.length > 0
      ? mountLocalReposReadOnlyCopy(opts.repos, projectReposDir(dataDir, projectId))
      : []

    if (diffScopes.length > 0) {
      storage.upsertProjectSpecRaw(projectId, {
        name: `pr-diff-${opts.diffBase}`,
        kind: 'notes',
        content: diffScopes
          .map(d => `Repository: ${d.repo}\nDiff base: ${d.diffBase}...HEAD\nChanged files (${d.changedFiles.length}):\n${d.changedFiles.map(f => `- ${f}`).join('\n')}`)
          .join('\n\n'),
      })
    }

    const approvedPersonaIds: string[] = []
    for (const p of parsedPersonas) {
      const created = createProjectPersona(storage, {
        requestId: randomUUID(),
        projectId,
        handle: p.handle,
        roleLabel: p.roleLabel,
        originAllowlist: p.originAllowlist,
        authKind: p.authKind,
        headerName: p.headerName,
        secret: p.secret,
        canaryMarkers: p.canaryMarkers,
      })
      approvedPersonaIds.push(created.id)
    }

    const defaultGoalParts = [
      `Perform a Tier ${tier} defensive security assessment`,
      validatedOrigins.length ? `of ${validatedOrigins.join(', ')}` : 'over mounted source repositories',
      mountedRepos.length ? `with mounted repos: ${mountedRepos.join(', ')}.` : '.',
      diffScopes.length
        ? `PR-diff mode (${opts.diffBase}...HEAD): prioritize changed files and their callers: ${diffScopes.flatMap(d => d.changedFiles).slice(0, 40).join(', ')}.`
        : '',
    ]
    const goal = opts.goal || defaultGoalParts.filter(Boolean).join(' ')

    const { id: runId } = storage.createRun({
      requestId: randomUUID(),
      projectId,
      goal,
      sourceMode: 'public',
      capabilityTier: tier,
      budgetUsd: opts.budgetUsd,
      budgetRequests: Math.min(budgetRequests, 10_000),
      maxRpsPerOrigin: opts.maxRps,
      workerConcurrency: 4,
      workerMaxTurns: 50,
    })

    storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
    const allAssetIds = storage.run(runId).candidates.map(c => c.id)

    storage.command({
      requestId: randomUUID(),
      runId,
      action: 'scope',
      expectedScopeRevision: 0,
      assetIds: allAssetIds,
      consent: true,
      capabilityTier: tier,
      approvedPersonaIds,
      budgetUsd: opts.budgetUsd,
      budgetRequests: Math.min(budgetRequests, 10_000),
      maxRpsPerOrigin: opts.maxRps,
    })

    engine.start()
    engine.wake()

    const deadline = Date.now() + opts.timeoutSec * 1000
    while (Date.now() < deadline) {
      const current = storage.run(runId)
      if (['complete', 'failed', 'stopped', 'paused', 'budget_paused'].includes(current.status)) {
        break
      }
      await delay(1_000)
    }

    let finalRun = storage.run(runId)
    if (finalRun.status === 'running') {
      storage.command({ requestId: randomUUID(), runId, action: 'stop' })
      finalRun = storage.run(runId)
    }

    await engine.stop()

    const detail = storage.runDetail(runId)
    const latestReport = detail.reports[0]
    if (latestReport) {
      const md = exportReportMarkdown(storage, runId, latestReport.id)
      writeFileSync(join(opts.outputDir, md.filename), md.content, { mode: 0o600 })
    }

    const sarif = exportReportSarif(storage, runId, latestReport?.id)
    const sarifOut = opts.sarifPath ?? join(opts.outputDir, sarif.filename)
    mkdirSync(resolve(sarifOut, '..'), { recursive: true })
    writeFileSync(sarifOut, sarif.content, { mode: 0o600 })

    const exitCode = determineExitCode(detail.findings, opts.failOn, finalRun.status)
    const summary = {
      runId,
      status: finalRun.status,
      phase: finalRun.phase,
      failOn: opts.failOn,
      exitCode,
      findingsTotal: detail.findings.length,
      confirmedCount: detail.findings.filter(f => f.status === 'confirmed').length,
      sarifPath: sarifOut,
      diffScopes,
    }
    writeFileSync(join(opts.outputDir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n', { mode: 0o600 })
    console.log(JSON.stringify(summary))
    return exitCode
  } catch (err) {
    console.error(`[guardian] Scan failed: ${err instanceof Error ? err.message : String(err)}`)
    return 1
  } finally {
    await engine.stop().catch(() => undefined)
    await labRunner.stopAll().catch(() => undefined)
    storage.close()
  }
}

const isMain = Boolean(
  process.argv[1] &&
  (import.meta.url === pathToFileURL(process.argv[1]).href
    || (existsSync(process.argv[1]) && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href)),
)

if (isMain) {
  runCli(process.argv.slice(2))
    .then(code => {
      process.exitCode = code
    })
    .catch(err => {
      console.error(`[guardian] Fatal CLI error: ${err instanceof Error ? err.message : String(err)}`)
      process.exitCode = 1
    })
}
