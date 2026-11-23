#!/usr/bin/env node
// CLI + programmatic API for the realism suite.
//   node benchmarks/realism-suite/run.ts list
//   node benchmarks/realism-suite/run.ts brief --fixture enterprise-spa
//   node benchmarks/realism-suite/run.ts serve --fixture wan-oob
//   node benchmarks/realism-suite/run.ts grade --fixture enterprise-spa --findings findings.json
//   node benchmarks/realism-suite/run.ts selftest --fixture all
import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { start as startEnterpriseSpa } from './fixtures/enterprise-spa/index.ts'
import { start as startWanOob } from './fixtures/wan-oob/index.ts'
import { start as startStaging } from './fixtures/staging-concurrency/index.ts'
import { start as startMonorepo } from './fixtures/monorepo-whitebox/index.ts'
import { gradeFindings, loadTruth, renderGrade } from './lib/grade.ts'
import type {
  ApiRefEntry,
  FixtureModule,
  FixtureStartOptions,
  GradeResult,
  Persona,
  RouteRef,
  StartedFixture,
  SubmittedFinding,
} from './lib/types.ts'

export const FIXTURES: Record<string, FixtureModule> = {
  'enterprise-spa': {
    name: 'enterprise-spa',
    title: 'Modern enterprise SPA (CDN + split app/api hosts + external OIDC IdP)',
    start: startEnterpriseSpa,
  },
  'wan-oob': {
    name: 'wan-oob',
    title: 'WAN latency jitter + async out-of-band callbacks',
    start: startWanOob,
  },
  'staging-concurrency': {
    name: 'staging-concurrency',
    title: 'Staging isolated safety: write-BOLA, checkout workflow, HTTP/2 race, orphan-free cleanup',
    start: startStaging,
  },
  'monorepo-whitebox': {
    name: 'monorepo-whitebox',
    title: 'Enterprise monorepo white-box: git history, nested mounts, 4-hop sinks, 2,560 routes',
    start: startMonorepo,
  },
}

export interface Briefing {
  fixture: string
  title: string
  safety: { loopbackOnly: true; envGate: 'GUARDIAN_ALLOW_LOCAL_LAB=1'; syntheticSecrets: true }
  origins: Record<string, string>
  hosts: Record<string, string>
  personas: Array<Omit<Persona, 'password'> & { password: string }>
  api: ApiRefEntry[]
  routes?: { count: number; sample: RouteRef[] }
  source?: { dir: string; gitCommits?: Array<{ sha: string; message: string }> }
  notes: string[]
}

export function listFixtures(): Array<{ name: string; title: string }> {
  return Object.values(FIXTURES).map(({ name, title }) => ({ name, title }))
}

export async function startFixture(name: string, options: FixtureStartOptions = {}): Promise<StartedFixture> {
  const fixture = FIXTURES[name]
  if (!fixture) throw new Error(`unknown realism fixture "${name}" (have: ${Object.keys(FIXTURES).join(', ')})`)
  return fixture.start(options)
}

export function briefingFor(fixture: StartedFixture): Briefing {
  const notes = [
    'All hosts are loopback aliases over 127.0.0.1 with OS-assigned ports; use the origins map directly.',
    'Personas carry synthetic credentials only. Bearer tokens, when present, are per-run and fake.',
    'truth.json is never served by any fixture; grading compares submitted findings against it offline.',
  ]
  const briefing: Briefing = {
    fixture: fixture.name,
    title: fixture.title,
    safety: { loopbackOnly: true, envGate: 'GUARDIAN_ALLOW_LOCAL_LAB=1', syntheticSecrets: true },
    origins: fixture.origins,
    hosts: fixture.hosts,
    personas: fixture.personas,
    api: fixture.api,
    notes,
  }
  if (fixture.routes) {
    briefing.routes = {
      count: fixture.routes.length,
      sample: fixture.routes.slice(0, 16),
    }
  }
  if (fixture.sourceDir) {
    let gitCommits: Array<{ sha: string; message: string }> | undefined
    const candidate = fixture as unknown as { git?: { log: () => Array<{ sha: string; message: string }> } }
    try {
      gitCommits = candidate.git?.log().map(({ sha, message }) => ({ sha, message }))
    } catch {
      gitCommits = undefined
    }
    briefing.source = { dir: fixture.sourceDir, gitCommits }
  }
  return briefing
}

export function gradeFixture(name: string, findings: SubmittedFinding[]): GradeResult {
  return gradeFindings(loadTruth(name), findings)
}

export function gradeFixtureFile(name: string, path: string): GradeResult {
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as SubmittedFinding[] | { findings: SubmittedFinding[] }
  const findings = Array.isArray(parsed) ? parsed : parsed.findings
  if (!Array.isArray(findings)) throw new Error('findings file must be an array or { "findings": [...] }')
  return gradeFixture(name, findings)
}

function parseArgs(argv: string[]): { command: string; flags: Map<string, string> } {
  const [command = 'list', ...rest] = argv
  const flags = new Map<string, string>()
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i]
    if (!token.startsWith('--')) continue
    const key = token.slice(2)
    const next = rest[i + 1]
    if (next && !next.startsWith('--')) {
      flags.set(key, next)
      i++
    } else {
      flags.set(key, 'true')
    }
  }
  return { command, flags }
}

async function runCli(argv: string[]): Promise<void> {
  const { command, flags } = parseArgs(argv)
  const fixtureName = flags.get('fixture') ?? ''

  if (command === 'list') {
    for (const entry of listFixtures()) console.log(`${entry.name}\t${entry.title}`)
    return
  }

  if (command === 'brief') {
    const fixture = await startFixture(fixtureName)
    try {
      const briefing = briefingFor(fixture)
      console.log(JSON.stringify(briefing, null, 2))
    } finally {
      await fixture.stop()
    }
    return
  }

  if (command === 'serve') {
    const fixture = await startFixture(fixtureName)
    process.stdout.write(`${JSON.stringify(briefingFor(fixture), null, 2)}\n`)
    await new Promise<void>((resolve) => {
      process.once('SIGINT', resolve)
      process.once('SIGTERM', resolve)
    })
    await fixture.stop()
    return
  }

  if (command === 'grade') {
    const findingsPath = flags.get('findings')
    if (!findingsPath) throw new Error('grade requires --findings <path>')
    const result = gradeFixtureFile(fixtureName, findingsPath)
    if (flags.get('json') === 'true') console.log(JSON.stringify(result, null, 2))
    else console.log(renderGrade(result))
    return
  }

  if (command === 'selftest') {
    const names = fixtureName === 'all' || !fixtureName ? Object.keys(FIXTURES) : [fixtureName]
    let failed = 0
    for (const name of names) {
      const module = await import(`./fixtures/${name}/selftest.ts`)
      try {
        const checks = (await module.runSelfTest()) as string[]
        console.log(`PASS ${name}: ${checks.length} checks`)
        for (const check of checks) console.log(`  - ${check}`)
      } catch (err) {
        failed++
        console.error(`FAIL ${name}: ${err instanceof Error ? err.message : String(err)}`)
      }
    }
    if (failed > 0) process.exitCode = 1
    return
  }

  throw new Error(`unknown command "${command}" (list|brief|serve|grade|selftest)`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli(process.argv.slice(2)).catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err))
    process.exitCode = 1
  })
}
