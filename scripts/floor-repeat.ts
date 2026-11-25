#!/usr/bin/env node
// Deterministic-floor repeat harness (not a production entry point).
//
// Runs the SAME `Execution --no-llm` cell N times in isolated out-dirs and fails when the
// confirmed site-id set differs between runs. This is the measurement the v6 determinism gate
// uses: a >1-target spread is a bug, never sampling noise.
//
// Usage:
//   KOVO_ALLOW_LOCAL_LAB=1 node scripts/floor-repeat.ts \
//     --apps acme-saas,shopflow,opsportal --seed 1 --repeat 3 --out-dir /tmp/floor-repeat
//
// Options mirror `scripts/benchmark-realistic.ts` for the floor: `--seed`, `--apps`, `--repeat`,
// `--out-dir`, `--mode` (default grey-box), `--concurrency` (child-process parallelism, default 1),
// and `--wordlist-on` (default OFF so the measurement is the discovered surface).
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

interface Args {
  apps: string[]
  seed: number
  repeat: number
  outDir: string
  mode: string
  concurrency: number
  wordlist: boolean
  timeoutMs: number
}

function parse(): Args {
  const argv = process.argv.slice(2)
  const args: Args = {
    apps: ['acme-saas', 'shopflow', 'opsportal'],
    seed: 1,
    repeat: 3,
    outDir: '/tmp/kovo-floor-repeat',
    mode: 'grey-box',
    concurrency: 1,
    wordlist: false,
    timeoutMs: 900_000,
  }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    const value = argv[i + 1]
    const take = (): string => {
      if (value === undefined) throw new Error(`${arg} requires a value`)
      i += 1
      return value
    }
    switch (arg) {
      case '--apps': args.apps = take().split(',').map(s => s.trim()).filter(Boolean); break
      case '--seed': args.seed = Number(take()); break
      case '--repeat': args.repeat = Math.max(2, Number(take())); break
      case '--out-dir': args.outDir = take(); break
      case '--mode': args.mode = take(); break
      case '--concurrency': args.concurrency = Math.max(1, Number(take())); break
      case '--wordlist-on': args.wordlist = true; break
      case '--timeout-ms': args.timeoutMs = Math.max(10_000, Number(take())); break
      case '--help': case '-h':
        console.log('Usage: node scripts/floor-repeat.ts [--apps a,b] [--seed N] [--repeat N] [--out-dir DIR] [--mode grey-box] [--concurrency N] [--wordlist-on]')
        process.exit(0)
        break
      default: throw new Error(`unknown option: ${arg}`)
    }
  }
  if (!Number.isInteger(args.seed) || args.seed <= 0) throw new Error('--seed must be a positive integer')
  return args
}

interface CellRun {
  app: string
  repeat: number
  ok: boolean
  confirmed: number
  targets: number
  sites: string[]
  error?: string
}

function runCell(args: Args, app: string, repeat: number): Promise<CellRun> {
  const dir = resolve(args.outDir, `r${repeat}`, app)
  mkdirSync(dir, { recursive: true })
  const json = resolve(dir, `${app}-seed${args.seed}-${args.mode}.json`)
  const childArgs = [
    resolve(import.meta.dirname, 'benchmark-realistic.ts'),
    '--app', app, '--seed', String(args.seed), '--mode', args.mode,
    '--no-llm', '--concurrency', '1', '--out-dir', dir,
    ...(args.wordlist ? [] : ['--no-conventional-wordlist']),
  ]
  return new Promise(resolvePromise => {
    const child = spawn(process.execPath, childArgs, {
      cwd: resolve(import.meta.dirname, '..'),
      env: { ...process.env, KOVO_ALLOW_LOCAL_LAB: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let log = ''
    const cap = (chunk: Buffer) => { if (log.length < 8_000) log += chunk.toString() }
    child.stdout.on('data', cap)
    child.stderr.on('data', cap)
    const timer = setTimeout(() => child.kill('SIGKILL'), args.timeoutMs)
    // Some apps leave a listener/child shutting down well after the scorecard is written. The
    // artifact is the measurement, so kill the cell shortly after it appears instead of waiting
    // for process teardown (which is unrelated to the confirmed set).
    let grace: NodeJS.Timeout | undefined
    const artifactWatch = setInterval(() => {
      if (!existsSync(json) || grace) return
      grace = setTimeout(() => child.kill('SIGKILL'), 30_000)
      grace.unref?.()
    }, 1_000)
    artifactWatch.unref?.()
    child.on('close', code => {
      clearTimeout(timer)
      clearInterval(artifactWatch)
      if (grace) clearTimeout(grace)
      if (!existsSync(json)) {
        const firstError = log.split('\n').find(line => /^error:/i.test(line.trim()))?.slice(0, 200)
        resolvePromise({ app, repeat, ok: false, confirmed: 0, targets: 0, sites: [], error: firstError ?? `exit ${code}` })
        return
      }
      try {
        const score = JSON.parse(readFileSync(json, 'utf8')) as {
          confirmed?: number; targets?: number; vulns?: Array<{ siteId?: string; outcome?: string }>
        }
        const sites = (score.vulns ?? [])
          .filter(v => v.outcome === 'confirmed' && typeof v.siteId === 'string')
          .map(v => v.siteId!)
          .sort()
        resolvePromise({ app, repeat, ok: true, confirmed: Number(score.confirmed ?? sites.length), targets: Number(score.targets ?? 0), sites })
      } catch (error) {
        resolvePromise({ app, repeat, ok: false, confirmed: 0, targets: 0, sites: [], error: String(error).slice(0, 200) })
      }
    })
  })
}

async function main(): Promise<number> {
  const args = parse()
  mkdirSync(args.outDir, { recursive: true })
  const cells: Array<{ app: string; repeat: number }> = []
  for (let repeat = 1; repeat <= args.repeat; repeat += 1) for (const app of args.apps) cells.push({ app, repeat })

  const runs: CellRun[] = []
  let next = 0
  await Promise.all(Array.from({ length: Math.min(args.concurrency, cells.length) }, async () => {
    while (next < cells.length) {
      const cell = cells[next]!
      next += 1
      const result = await runCell(args, cell.app, cell.repeat)
      runs.push(result)
      console.log(`[floor-repeat] ${cell.app} run${cell.repeat}: ${result.ok ? `${result.confirmed}/${result.targets}` : `ERROR ${result.error}`}`)
    }
  }))

  let drift = 0
  for (const app of args.apps) {
    const perApp = runs.filter(run => run.app === app).sort((a, b) => a.repeat - b.repeat)
    if (perApp.length < 2) continue
    const baseline = perApp[0]!
    const counts = perApp.map(run => run.confirmed)
    const spread = Math.max(...counts) - Math.min(...counts)
    const siteSets = perApp.map(run => run.sites.join(','))
    const identical = siteSets.every(set => set === siteSets[0])
    if (spread !== 0 || !identical) drift += 1
    console.log(`[floor-repeat] ${app}: counts=[${counts.join(', ')}] spread=${spread} identicalSites=${identical}`)
    for (const run of perApp) console.log(`[floor-repeat]   run${run.repeat}: ${run.sites.join(',') || '(none)'}`)
    if (!baseline.ok) console.log(`[floor-repeat]   warning: run1 did not exit cleanly (${baseline.error})`)
  }
  console.log(`[floor-repeat] apps=${args.apps.length} repeats=${args.repeat} seed=${args.seed} wordlist=${args.wordlist ? 'on' : 'off'} driftApps=${drift}`)
  return drift === 0 ? 0 : 1
}

main().then(code => process.exit(code)).catch(error => {
  console.error(`floor-repeat: ${error instanceof Error ? error.message : String(error)}`)
  process.exit(2)
})
