// Anti-Heuristic Gate acceptance (M4): the real `Execution --no-llm` runner must stay at or below
// 10% overall confirmed recall on dev and salted held-out seeds, and the CLI must exit 0.
//
// The gate is exercised through its real process boundary (the CLI's exit code is the assertion),
// never mocked or called in-process. Held-out is skipped cleanly when KOVO_RB_HELDOUT_SALT is
// absent; the value is forwarded to the child and never printed or written.
//
// Note: reason-bench app/runtime source may not statically import child_process (safety.test.ts
// enforces that). This test loads the builtin lazily and uses it only to run the sanctioned
// `scripts/benchmark-reason.ts` harness.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = resolve(HERE, '..', '..', '..')
const SCRIPT = join(REPO_ROOT, 'scripts', 'benchmark-reason.ts')
const FLOOR_CEILING = 0.10
const TIMEOUT_MS = 15 * 60 * 1000
const KEEP = process.env.REASON_KEEP_ARTIFACTS === '1'

interface GateReport {
  gate?: { ceiling: number; recall: number; confirmed: number; targets: number; passed: boolean }
  cells?: Array<{ llm?: string; confirmed?: number; targets?: number }>
}

interface GateResult {
  code: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
  report: GateReport
  dir: string
}

function tail(text: string, limit = 2000): string {
  return text.slice(-limit)
}

async function runGate(label: string, args: string[], withSalt: boolean): Promise<GateResult> {
  const dir = mkdtempSync(join(tmpdir(), `reason-anti-heuristic-${label}-`))
  const jsonPath = join(dir, 'reason-report.json')
  const mdPath = join(dir, 'reason-report.md')
  const fullArgs = [
    SCRIPT, ...args,
    '--mode', 'grey-box',
    '--no-llm',
    '--concurrency', '2',
    '--out-dir', dir,
    '--json', jsonPath,
    '--md', mdPath,
  ]
  const env: NodeJS.ProcessEnv = { ...process.env, KOVO_ALLOW_LOCAL_LAB: '1' }
  if (withSalt) env.KOVO_RB_HELDOUT_SALT = process.env.KOVO_RB_HELDOUT_SALT
  else delete env.KOVO_RB_HELDOUT_SALT

  // Lazy builtin load: the benchmark tree forbids a static child_process import.
  const { spawn } = await import('node:child_process')
  const child = spawn(process.execPath, fullArgs, {
    cwd: REPO_ROOT,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const cap = 256 * 1024
  let stdout = ''
  let stderr = ''
  child.stdout!.on('data', (chunk: Buffer) => {
    if (stdout.length < cap) stdout += chunk.toString('utf8')
  })
  child.stderr!.on('data', (chunk: Buffer) => {
    if (stderr.length < cap) stderr += chunk.toString('utf8')
  })

  const timer = setTimeout(() => child.kill('SIGKILL'), TIMEOUT_MS)
  const code = await new Promise<number | null>((resolveCode, reject) => {
    child.once('error', reject)
    child.once('close', resolveCode)
  })
  clearTimeout(timer)

  let report: GateReport = {}
  try {
    report = JSON.parse(readFileSync(jsonPath, 'utf8')) as GateReport
  } catch {
    // Left empty so the assertion below reports the missing artifact with the CLI tail.
  }
  const signal = child.signalCode
  if (!KEEP) rmSync(dir, { recursive: true, force: true })
  return { code, signal, stdout, stderr, report, dir }
}

function assertFloor(label: string, result: GateResult, expectedTargets: number): void {
  const context = `\nstdout:\n${tail(result.stdout)}\nstderr:\n${tail(result.stderr)}\nartifacts: ${result.dir}`
  assert.equal(result.signal, null, `${label} gate was killed by ${result.signal}${context}`)
  assert.equal(result.code, 0, `${label} gate exited ${result.code}${context}`)
  const gate = result.report.gate
  assert.ok(gate, `${label} report has no gate block${context}`)
  assert.equal(gate.passed, true, `${label} gate verdict was FAIL${context}`)
  assert.ok(
    gate.recall <= FLOOR_CEILING,
    `${label} deterministic floor ${(gate.recall * 100).toFixed(1)}% exceeds ${(FLOOR_CEILING * 100).toFixed(0)}%${context}`,
  )
  assert.ok(
    gate.targets >= expectedTargets,
    `${label} gate scored ${gate.targets} targets, expected >= ${expectedTargets}${context}`,
  )
  assert.ok(
    (result.report.cells ?? []).every((cell) => cell.llm === 'deterministic-no-llm'),
    `${label} mixed an agentic cell into the floor run${context}`,
  )
}

test('anti-heuristic gate: dev seed 1 floor <= 10% and exit 0', { timeout: TIMEOUT_MS }, async () => {
  const result = await runGate('dev', ['--app', 'all', '--seed', '1'], false)
  assertFloor('dev seed 1', result, 28)
})

const salt = process.env.KOVO_RB_HELDOUT_SALT ?? ''
test('anti-heuristic gate: held-out seed 1000042 floor <= 10% and exit 0', {
  timeout: TIMEOUT_MS,
  skip: salt.length < 16 ? 'KOVO_RB_HELDOUT_SALT is not set' : false,
}, async () => {
  const result = await runGate('heldout', ['--app', 'all', '--held-out', '--seeds', '1000042'], true)
  assertFloor('held-out seed 1000042', result, 28)
})
