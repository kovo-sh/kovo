import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { PassThrough, Writable } from 'node:stream'
import { fileURLToPath, pathToFileURL } from 'node:url'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SCRIPT = join(REPO_ROOT, 'scripts', 'dispatch-worker.mjs')
const EXPECTED = 'claude-opus-5-5'
const OPENCODE_ARGS_PREFIX = ['run', '-m', 'opencode-go/deepseek-v4.1-flash', '--auto', '--archived']
const KILL_SWITCHES = {
  CLAUDE_CODE_NO_MODEL_FALLBACK: '1',
  CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK: '1',
  CLAUDE_CODE_DISABLE_MODEL_ACCESS_FALLBACK: '1',
} as const

// ---------- typed view of the untyped ESM module ----------

type Tier = 'standard' | 'security-adjacent'
type Mode = 'implement' | 'review'
type Fallback = 'handoff' | 'opencode'

interface DispatchOptions {
  tier: Tier
  worktree?: string
  prompt?: string
  promptFile?: string
  expectedModel: string
  mode: Mode
  fallback: Fallback
  dryRun: boolean
  help: boolean
}

interface Invocation {
  command: string
  args: string[]
  env: Record<string, string | undefined>
  envOverrides: Record<string, string>
  cwd: string
  stdin?: string
}

interface InspectorState {
  frames: number
  detectedModels: string[]
  safetyStops: number
  fallbackCredit: unknown
  sawResult: boolean
  sawCleanResult: boolean
  violation: { reason: string } | null
}

interface SpawnOpts {
  cwd?: string
  env?: Record<string, string | undefined>
}

type SpawnImpl = (command: string, args: string[], opts: SpawnOpts) => MockChild

interface DispatchDeps {
  claudeBin?: string
  opencodeBin?: string
  spawnImpl?: SpawnImpl
  stdout?: Writable
  stderr?: Writable
  env?: Record<string, string | undefined>
  killGraceMs?: number
}

interface DispatchResult {
  exitCode: number
  action: string
  reason?: string
  handoffPath?: string
}

interface HandoffRecord {
  reason: string
  detectedModels: string[]
  safetyStops: number
  fallbackCredit: unknown
  tier: Tier
  worktree: string
  nextTier: string
  tertiaryTier: string
  mode: Mode
  expectedModel: string
  fallback: Fallback
}

interface DispatchModule {
  HANDOFF_EXIT_CODE: number
  HANDOFF_FILENAME: string
  DispatchUsageError: new (message: string) => Error
  parseArgs(argv: string[]): DispatchOptions
  resolvePrompt(opts: Partial<DispatchOptions>, readFile?: (p: string) => string): string
  isExpectedModel(modelId: unknown, expectedModel: string): boolean
  buildClaudeInvocation(input: {
    mode?: Mode
    worktree: string
    prompt: string
    baseEnv?: Record<string, string | undefined>
    claudeBin?: string
  }): Invocation
  buildOpencodeInvocation(input: { worktree: string; prompt: string; opencodeBin?: string }): Invocation
  parseFrames(text: string, expectedModel?: string): InspectorState
  runDispatch(options: string[] | Partial<DispatchOptions>, deps?: DispatchDeps): Promise<DispatchResult>
}

const mod = (await import(pathToFileURL(SCRIPT).href)) as DispatchModule

// ---------- helpers ----------

const tmpRoots: string[] = []
after(() => {
  for (const d of tmpRoots) rmSync(d, { recursive: true, force: true })
})

function makeWorktree(): string {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-dispatch-wt-'))
  tmpRoots.push(dir)
  writeFileSync(join(dir, 'uncommitted.ts'), 'export const wip = 1\n')
  return dir
}

function sink(): Writable & { text: () => string } {
  const chunks: string[] = []
  const w = new Writable({
    write(chunk: Buffer | string, _enc, cb) {
      chunks.push(String(chunk))
      cb()
    },
  }) as Writable & { text: () => string }
  w.text = () => chunks.join('')
  return w
}

const line = (frame: unknown): string => `${JSON.stringify(frame)}\n`
const init = (model = EXPECTED) => ({ type: 'system', subtype: 'init', model, session_id: 's' })
const assistant = (model: string) => ({
  type: 'assistant',
  message: { model, role: 'assistant', content: [{ type: 'text', text: 'ok' }] },
})
const result = (overrides: Record<string, unknown> = {}) => ({
  type: 'result',
  subtype: 'success',
  is_error: false,
  safety_stops: 0,
  usage: { input_tokens: 1, output_tokens: 1, fallback_credit: null },
  modelUsage: { [EXPECTED]: { inputTokens: 1, outputTokens: 1 } },
  ...overrides,
})

class MockChild extends EventEmitter {
  stdin = new PassThrough()
  stdout = new PassThrough()
  stderr = new PassThrough()
  exitCode: number | null = null
  signalCode: string | null = null
  killSignals: string[] = []
  framesWritten = 0
  stdinText = ''

  constructor() {
    super()
    this.stdin.on('data', (c: Buffer) => {
      this.stdinText += String(c)
    })
  }

  get closed(): boolean {
    return this.exitCode !== null || this.signalCode !== null
  }

  kill(signal: string): boolean {
    this.killSignals.push(signal)
    setImmediate(() => this.finish(null, signal))
    return true
  }

  finish(code: number | null, signal: string | null): void {
    if (this.closed) return
    this.exitCode = code
    this.signalCode = signal
    this.stdout.end()
    this.stderr.end()
    setImmediate(() => this.emit('close', code, signal))
  }
}

interface Script {
  frames?: unknown[]
  raw?: string
  chunks?: string[]
  exitCode?: number
  hang?: boolean
}

interface SpawnCall {
  command: string
  args: string[]
  cwd?: string
  env?: Record<string, string | undefined>
  child: MockChild
}

/** spawnImpl that plays scripted frames for `claude` and exits with a code for `opencode`. */
function mockSpawn(script: Script, opencodeExit = 0): { spawnImpl: SpawnImpl; calls: SpawnCall[] } {
  const calls: SpawnCall[] = []
  const spawnImpl: SpawnImpl = (command, args, opts) => {
    const child = new MockChild()
    calls.push({ command, args, cwd: opts.cwd, env: opts.env, child })
    if (command === 'mock-opencode') {
      setImmediate(() => child.finish(opencodeExit, null))
      return child
    }
    const chunks = script.chunks ?? (script.raw !== undefined ? [script.raw] : (script.frames ?? []).map(line))
    let i = 0
    const tick = () => {
      if (child.closed) return
      if (i < chunks.length) {
        child.stdout.write(chunks[i++])
        child.framesWritten = i
        setTimeout(tick, 2)
      } else if (!script.hang) {
        child.finish(script.exitCode ?? 0, null)
      }
    }
    setImmediate(tick)
    return child
  }
  return { spawnImpl, calls }
}

async function dispatch(
  opts: Partial<DispatchOptions>,
  script: Script,
  opencodeExit = 0,
): Promise<{ res: DispatchResult; calls: SpawnCall[]; worktree: string; stderr: string; stdout: string }> {
  const worktree = opts.worktree ?? makeWorktree()
  const { spawnImpl, calls } = mockSpawn(script, opencodeExit)
  const out = sink()
  const err = sink()
  const res = await mod.runDispatch(
    { prompt: 'Implement the stream.', ...opts, worktree },
    { spawnImpl, claudeBin: 'mock-claude', opencodeBin: 'mock-opencode', stdout: out, stderr: err, env: { PATH: '/usr/bin' }, killGraceMs: 50 },
  )
  return { res, calls, worktree, stderr: err.text(), stdout: out.text() }
}

function readHandoff(worktree: string): HandoffRecord {
  return JSON.parse(readFileSync(join(worktree, mod.HANDOFF_FILENAME), 'utf8')) as HandoffRecord
}

function assertWorktreePreserved(worktree: string, expectHandoff: boolean): void {
  assert.equal(readFileSync(join(worktree, 'uncommitted.ts'), 'utf8'), 'export const wip = 1\n')
  const expected = expectHandoff ? [mod.HANDOFF_FILENAME, 'uncommitted.ts'] : ['uncommitted.ts']
  assert.deepEqual(readdirSync(worktree).sort(), expected.sort())
}

// ---------- 1. CLI argument parsing ----------

describe('dispatch-worker: argument parsing', () => {
  it('applies defaults', () => {
    const o = mod.parseArgs(['--prompt', 'do it'])
    assert.equal(o.tier, 'standard')
    assert.equal(o.mode, 'implement')
    assert.equal(o.fallback, 'handoff')
    assert.equal(o.expectedModel, EXPECTED)
    assert.equal(o.worktree, undefined)
    assert.equal(o.dryRun, false)
  })

  it('parses every flag in both "--flag value" and "--flag=value" forms', () => {
    const o = mod.parseArgs([
      '--tier', 'security-adjacent', '--worktree=/tmp/wt', '--prompt', 'p',
      '--expected-model=claude-opus-5-5', '--mode', 'review', '--fallback=opencode', '--dry-run',
    ])
    assert.deepEqual(
      { tier: o.tier, worktree: o.worktree, prompt: o.prompt, model: o.expectedModel, mode: o.mode, fb: o.fallback, dry: o.dryRun },
      { tier: 'security-adjacent', worktree: '/tmp/wt', prompt: 'p', model: EXPECTED, mode: 'review', fb: 'opencode', dry: true },
    )
    assert.equal(mod.parseArgs(['--prompt-file', 'x.md']).promptFile, 'x.md')
  })

  it('allows --help without a prompt', () => {
    assert.equal(mod.parseArgs(['-h']).help, true)
    assert.equal(mod.parseArgs(['--help']).help, true)
  })

  it('rejects invalid values cleanly with DispatchUsageError', () => {
    const bad: string[][] = [
      ['--prompt', 'p', '--tier', 'yolo'],
      ['--prompt', 'p', '--mode', 'write'],
      ['--prompt', 'p', '--fallback', 'sonnet'],
      ['--prompt', 'p', '--expected-model', ''],
      ['--prompt', 'p', '--prompt-file', 'f'],
      [],
      ['--prompt'],
      ['--prompt', 'p', '--fallback-model', 'claude-opus-4-8'],
      ['--prompt', 'p', 'stray'],
      ['--prompt', 'a', '--prompt', 'b'],
      ['--prompt', '   '],
    ]
    for (const argv of bad) {
      assert.throws(() => mod.parseArgs(argv), mod.DispatchUsageError, `argv ${JSON.stringify(argv)}`)
    }
  })

  it('reads --prompt-file as UTF-8 and rejects missing/empty files', () => {
    const dir = makeWorktree()
    const f = join(dir, 'prompt.md')
    writeFileSync(f, 'Task: überprüfen ✓\n', 'utf8')
    assert.equal(mod.resolvePrompt({ promptFile: f }), 'Task: überprüfen ✓\n')
    assert.throws(() => mod.resolvePrompt({ promptFile: join(dir, 'missing.md') }), mod.DispatchUsageError)
    writeFileSync(join(dir, 'empty.md'), '\n')
    assert.throws(() => mod.resolvePrompt({ promptFile: join(dir, 'empty.md') }), mod.DispatchUsageError)
  })

  it('returns usage exit code 2 for a non-existent worktree without spawning', async () => {
    const { spawnImpl, calls } = mockSpawn({})
    const res = await mod.runDispatch(
      { prompt: 'x', worktree: join(tmpdir(), 'kovo-dispatch-does-not-exist-xyz') },
      { spawnImpl, stdout: sink(), stderr: sink() },
    )
    assert.equal(res.exitCode, 2)
    assert.equal(calls.length, 0)
  })
})

// ---------- 2. Claude command & env builder ----------

describe('dispatch-worker: claude invocation builder', () => {
  const wt = '/tmp/some-wt'

  it('always injects the 3 fallback kill-switches, even over a hostile base env', () => {
    for (const mode of ['implement', 'review'] as const) {
      const inv = mod.buildClaudeInvocation({
        mode,
        worktree: wt,
        prompt: 'p',
        baseEnv: { PATH: '/bin', CLAUDE_CODE_NO_MODEL_FALLBACK: '0', CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK: '' },
      })
      for (const [k, v] of Object.entries(KILL_SWITCHES)) {
        assert.equal(inv.env[k], v, `${mode}: ${k}`)
        assert.equal(inv.envOverrides[k], v)
      }
      assert.equal(inv.env.PATH, '/bin')
      assert.equal(inv.cwd, wt)
      assert.equal(inv.stdin, 'p')
    }
  })

  it('never passes --fallback-model', () => {
    for (const mode of ['implement', 'review'] as const) {
      const { args } = mod.buildClaudeInvocation({ mode, worktree: wt, prompt: 'p' })
      assert.ok(!args.some((a) => a.startsWith('--fallback-model')), `${mode}: ${args.join(' ')}`)
    }
  })

  it('implement mode: bypassPermissions + pinned opus stream-json', () => {
    const { command, args } = mod.buildClaudeInvocation({ mode: 'implement', worktree: wt, prompt: 'p', claudeBin: 'claude' })
    assert.equal(command, 'claude')
    assert.deepEqual(args, [
      '-p', '--permission-mode', 'bypassPermissions', '--no-session-persistence',
      '--model', 'opus', '--output-format', 'stream-json', '--verbose',
    ])
    assert.ok(!args.includes('--safe-mode'))
  })

  it('review mode: --safe-mode + read-only tools, no bypassPermissions', () => {
    const { args } = mod.buildClaudeInvocation({ mode: 'review', worktree: wt, prompt: 'p' })
    assert.deepEqual(args, [
      '-p', '--safe-mode', '--tools', 'Read,Grep,Glob', '--no-session-persistence',
      '--model', 'opus', '--output-format', 'stream-json', '--verbose',
    ])
    assert.ok(!args.includes('bypassPermissions'))
    assert.ok(!args.includes('--permission-mode'))
  })

  it('opencode invocation is pinned to deepseek-v4.1-flash on the same worktree', () => {
    const inv = mod.buildOpencodeInvocation({ worktree: wt, prompt: 'the task' })
    assert.equal(inv.command, 'opencode')
    assert.deepEqual(inv.args, [...OPENCODE_ARGS_PREFIX, 'the task'])
    assert.equal(inv.cwd, wt)
  })
})

// ---------- 3. model matching & frame parser ----------

describe('dispatch-worker: model matching and frame parser', () => {
  it('isExpectedModel accepts exact + dated/variant suffixes, rejects other versions and families', () => {
    for (const ok of [EXPECTED, `${EXPECTED}-20261101`, `${EXPECTED}[1m]`]) {
      assert.equal(mod.isExpectedModel(ok, EXPECTED), true, ok)
    }
    for (const bad of [
      'claude-opus-4-8', 'claude-opus-5', 'claude-opus-5-50', 'claude-opus-5-4', 'claude-sonnet-5-5',
      'claude-haiku-5-5', 'opus', '', '<synthetic>', `x-${EXPECTED}`, undefined, 42,
    ]) {
      assert.equal(mod.isExpectedModel(bad, EXPECTED), false, String(bad))
    }
  })

  it('clean stream-json session passes', () => {
    const st = mod.parseFrames([init(), assistant(EXPECTED), assistant(`${EXPECTED}-20261101`), result()].map(line).join(''))
    assert.equal(st.violation, null)
    assert.equal(st.sawCleanResult, true)
    assert.deepEqual(st.detectedModels, [EXPECTED, `${EXPECTED}-20261101`])
  })

  it('clean single-object json (compact and pretty-printed) passes', () => {
    assert.equal(mod.parseFrames(JSON.stringify(result())).sawCleanResult, true)
    const pretty = mod.parseFrames(JSON.stringify(result(), null, 2))
    assert.equal(pretty.violation, null)
    assert.equal(pretty.sawCleanResult, true)
    assert.equal(mod.parseFrames(JSON.stringify([init(), assistant(EXPECTED), result()])).sawCleanResult, true)
  })

  it('flags assistant downgrades to older opus, sonnet, and haiku', () => {
    for (const m of ['claude-opus-4-8', 'claude-sonnet-5-5', 'claude-haiku-5-5-20261001']) {
      const st = mod.parseFrames([init(), assistant(m), result()].map(line).join(''))
      assert.ok(st.violation, m)
      assert.match(st.violation.reason, /model-mismatch:assistant/)
      assert.ok(st.detectedModels.includes(m))
      assert.equal(st.sawResult, false, 'stops at first violation')
    }
  })

  it('flags result frames: safety_stops, fallback_credit, is_error, modelUsage, canonicalModel', () => {
    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ safety_stops: 2 }, /safety_stops:2/],
      [{ usage: { fallback_credit: { amount: 3 } } }, /fallback_credit/],
      [{ is_error: true, subtype: 'error_during_execution' }, /is_error:error_during_execution/],
      [{ subtype: 'error_refusal', status: 'error' }, /result-error/],
      [{ stop_reason: 'refusal' }, /refusal/],
      [{ modelUsage: { [EXPECTED]: {}, 'claude-opus-4-8': {} } }, /modelUsage:claude-opus-4-8/],
      [{ modelUsage: { [EXPECTED]: { canonicalModel: 'claude-sonnet-5-5' } } }, /modelUsage\.canonicalModel/],
      [{ canonicalModel: 'claude-haiku-5-5' }, /canonicalModel:claude-haiku-5-5/],
    ]
    for (const [over, re] of cases) {
      const st = mod.parseFrames(line(result(over)))
      assert.ok(st.violation, JSON.stringify(over))
      assert.match(st.violation.reason, re)
      assert.equal(st.sawCleanResult, false)
    }
    assert.equal(mod.parseFrames(line(result({ safety_stops: 2 }))).safetyStops, 2)
    assert.deepEqual(mod.parseFrames(line(result({ usage: { fallback_credit: { amount: 3 } } }))).fallbackCredit, { amount: 3 })
  })

  it('flags an init frame that already reports a different model', () => {
    const st = mod.parseFrames(line(init('claude-opus-4-8')))
    assert.match(st.violation?.reason ?? '', /model-mismatch:init:claude-opus-4-8/)
  })

  it('handles frames split across arbitrary chunk boundaries', async () => {
    const text = [init(), assistant('claude-opus-4-8')].map(line).join('')
    const mid = Math.floor(text.length / 2)
    const { res, calls } = await dispatch({}, { chunks: [text.slice(0, 7), text.slice(7, mid), text.slice(mid)], hang: true })
    assert.equal(res.exitCode, 42)
    assert.deepEqual(calls[0].child.killSignals, ['SIGTERM'])
  })
})

// ---------- runner: standard tier ----------

describe('dispatch-worker: standard tier runner', () => {
  it('clean claude-opus-5-5 session -> exit 0, no handoff, prompt on stdin, cwd = worktree', async () => {
    const { res, calls, worktree, stdout } = await dispatch({}, { frames: [init(), assistant(EXPECTED), result()], exitCode: 0 })
    assert.equal(res.exitCode, 0)
    assert.equal(calls.length, 1)
    const c = calls[0]
    assert.equal(c.command, 'mock-claude')
    assert.equal(c.cwd, worktree)
    for (const [k, v] of Object.entries(KILL_SWITCHES)) assert.equal(c.env?.[k], v)
    assert.ok(!c.args.some((a) => a.startsWith('--fallback-model')))
    assert.equal(c.child.stdinText, 'Implement the stream.')
    assert.deepEqual(c.child.killSignals, [])
    assert.ok(stdout.includes('"type":"result"'), 'stream is passed through')
    assertWorktreePreserved(worktree, false)
  })

  it('silent mid-stream downgrade to claude-opus-4-8 -> kills immediately, preserves worktree, writes handoff, exits 42', async () => {
    const frames = [init(), assistant(EXPECTED), assistant('claude-opus-4-8'), assistant(EXPECTED), assistant(EXPECTED), result()]
    const { res, calls, worktree } = await dispatch({}, { frames, hang: true })
    assert.equal(res.exitCode, mod.HANDOFF_EXIT_CODE)
    assert.equal(res.exitCode, 42)
    const child = calls[0].child
    assert.deepEqual(child.killSignals, ['SIGTERM'])
    assert.ok(child.framesWritten < frames.length, `killed before stream finished (${child.framesWritten}/${frames.length})`)
    assert.equal(calls.length, 1, 'no opencode in handoff mode')
    const h = readHandoff(worktree)
    assert.ok(h.detectedModels.includes('claude-opus-4-8'))
    assert.match(h.reason, /claude-opus-4-8/)
    assert.equal(h.nextTier, 'gemini-neon')
    assert.equal(h.tertiaryTier, 'opencode-go/deepseek-v4.1-flash')
    assert.equal(h.tier, 'standard')
    assert.equal(h.worktree, worktree)
    assert.equal(h.safetyStops, 0)
    assert.equal(h.fallbackCredit, null)
    assertWorktreePreserved(worktree, true)
  })

  it('escalates SIGKILL when the child ignores SIGTERM', async () => {
    const worktree = makeWorktree()
    let child: MockChild | undefined
    const spawnImpl: SpawnImpl = () => {
      const c = new MockChild()
      child = c
      c.kill = (signal: string) => {
        c.killSignals.push(signal)
        if (signal === 'SIGKILL') setImmediate(() => c.finish(null, 'SIGKILL'))
        return true
      }
      setImmediate(() => c.stdout.write(line(assistant('claude-sonnet-5-5'))))
      return c
    }
    const res = await mod.runDispatch({ prompt: 'p', worktree }, { spawnImpl, stdout: sink(), stderr: sink(), killGraceMs: 10 })
    assert.equal(res.exitCode, 42)
    assert.deepEqual(child?.killSignals, ['SIGTERM', 'SIGKILL'])
  })

  it('result safety_stops > 0 -> handoff records safetyStops', async () => {
    const { res, worktree } = await dispatch({}, { frames: [init(), assistant(EXPECTED), result({ safety_stops: 3 })], hang: true })
    assert.equal(res.exitCode, 42)
    const h = readHandoff(worktree)
    assert.equal(h.safetyStops, 3)
    assert.match(h.reason, /safety_stops:3/)
  })

  it('result usage.fallback_credit != null -> handoff records fallbackCredit', async () => {
    const { res, worktree } = await dispatch({}, { frames: [result({ usage: { fallback_credit: 0.25 } })], exitCode: 0 })
    assert.equal(res.exitCode, 42)
    assert.equal(readHandoff(worktree).fallbackCredit, 0.25)
  })

  it('result is_error: true -> handoff', async () => {
    const { res, worktree } = await dispatch({}, { frames: [result({ is_error: true, subtype: 'error_during_execution' })], exitCode: 1 })
    assert.equal(res.exitCode, 42)
    assert.match(readHandoff(worktree).reason, /is_error/)
  })

  it('unexpected modelUsage key / canonicalModel -> handoff', async () => {
    const a = await dispatch({}, { frames: [result({ modelUsage: { 'claude-haiku-5-5': {} } })] })
    assert.equal(a.res.exitCode, 42)
    assert.ok(readHandoff(a.worktree).detectedModels.includes('claude-haiku-5-5'))
    const b = await dispatch({}, { frames: [result({ modelUsage: { [EXPECTED]: { canonicalModel: 'claude-opus-4-8' } } })] })
    assert.equal(b.res.exitCode, 42)
    assert.ok(readHandoff(b.worktree).detectedModels.includes('claude-opus-4-8'))
  })

  it('non-zero exit without a clean result -> handoff; missing result frame -> handoff', async () => {
    const a = await dispatch({}, { frames: [init(), assistant(EXPECTED)], exitCode: 1 })
    assert.equal(a.res.exitCode, 42)
    assert.match(readHandoff(a.worktree).reason, /claude-exit:1/)
    const b = await dispatch({}, { frames: [init(), assistant(EXPECTED)], exitCode: 0 })
    assert.equal(b.res.exitCode, 42)
    assert.match(readHandoff(b.worktree).reason, /no-result/)
  })

  it('accepts a single-object json result on stdout', async () => {
    const { res, worktree } = await dispatch({}, { raw: JSON.stringify(result(), null, 2), exitCode: 0 })
    assert.equal(res.exitCode, 0)
    assertWorktreePreserved(worktree, false)
  })

  it('--fallback opencode on opus-4-8 downgrade -> kills claude, writes handoff, runs opencode on the same worktree', async () => {
    const frames = [init(), assistant('claude-opus-4-8'), assistant(EXPECTED), result()]
    const { res, calls, worktree } = await dispatch({ fallback: 'opencode', prompt: 'Fix the gate.' }, { frames, hang: true }, 7)
    assert.equal(calls.length, 2)
    assert.deepEqual(calls[0].child.killSignals, ['SIGTERM'])
    assert.equal(calls[1].command, 'mock-opencode')
    assert.deepEqual(calls[1].args, [...OPENCODE_ARGS_PREFIX, 'Fix the gate.'])
    assert.equal(calls[1].cwd, worktree)
    assert.equal(res.exitCode, 7, "propagates opencode's exit code")
    assert.ok(readHandoff(worktree).detectedModels.includes('claude-opus-4-8'))
    assertWorktreePreserved(worktree, true)
  })
})

// ---------- 4. security-adjacent pre-routing ----------

describe('dispatch-worker: security-adjacent pre-router', () => {
  it('handoff mode: never spawns claude, writes pre-routed handoff, exits 42', async () => {
    const { res, calls, worktree } = await dispatch({ tier: 'security-adjacent' }, {})
    assert.equal(res.exitCode, 42)
    assert.equal(calls.length, 0)
    const h = readHandoff(worktree)
    assert.deepEqual(
      { reason: h.reason, tier: h.tier, detectedModels: h.detectedModels, safetyStops: h.safetyStops, fallbackCredit: h.fallbackCredit, worktree: h.worktree, nextTier: h.nextTier, tertiaryTier: h.tertiaryTier },
      { reason: 'pre-routed:security-adjacent', tier: 'security-adjacent', detectedModels: [], safetyStops: 0, fallbackCredit: null, worktree, nextTier: 'gemini-neon', tertiaryTier: 'opencode-go/deepseek-v4.1-flash' },
    )
    assertWorktreePreserved(worktree, true)
  })

  it('opencode mode: never spawns claude, writes handoff, runs opencode with the exact args in the worktree', async () => {
    const { res, calls, worktree } = await dispatch({ tier: 'security-adjacent', fallback: 'opencode', prompt: 'Audit oracle.' }, {}, 0)
    assert.equal(res.exitCode, 0)
    assert.equal(calls.length, 1)
    assert.ok(calls.every((c) => c.command !== 'mock-claude'))
    assert.equal(calls[0].command, 'mock-opencode')
    assert.deepEqual(calls[0].args, ['run', '-m', 'opencode-go/deepseek-v4.1-flash', '--auto', '--archived', 'Audit oracle.'])
    assert.equal(calls[0].cwd, worktree)
    assert.equal(readHandoff(worktree).reason, 'pre-routed:security-adjacent')
  })
})

// ---------- 5/6. CLI subprocess tests (mock bins via env) ----------

interface MockBins {
  dir: string
  claudeBin: string
  opencodeBin: string
  logPath: string
}

function makeMockBins(): MockBins {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-dispatch-bin-'))
  tmpRoots.push(dir)
  const logPath = join(dir, 'calls.jsonl')
  const logger = `
import { appendFileSync } from 'node:fs'
const log = (who) => appendFileSync(process.env.MOCK_LOG, JSON.stringify({
  who, argv: process.argv.slice(2), cwd: process.cwd(),
  killSwitches: [process.env.CLAUDE_CODE_NO_MODEL_FALLBACK, process.env.CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK, process.env.CLAUDE_CODE_DISABLE_MODEL_ACCESS_FALLBACK],
}) + '\\n')
`
  const claudeBin = join(dir, 'mock-claude.mjs')
  writeFileSync(
    claudeBin,
    `#!/usr/bin/env node
${logger}
log('claude')
for (const f of JSON.parse(process.env.MOCK_FRAMES || '[]')) process.stdout.write(JSON.stringify(f) + '\\n')
if (process.env.MOCK_HANG === '1') setInterval(() => {}, 1000)
`,
  )
  const opencodeBin = join(dir, 'mock-opencode.mjs')
  writeFileSync(
    opencodeBin,
    `#!/usr/bin/env node
${logger}
log('opencode')
process.exitCode = Number(process.env.MOCK_OPENCODE_EXIT || 0)
`,
  )
  chmodSync(claudeBin, 0o755)
  chmodSync(opencodeBin, 0o755)
  return { dir, claudeBin, opencodeBin, logPath }
}

function runCli(args: string[], bins: MockBins, extraEnv: Record<string, string> = {}) {
  const env: Record<string, string> = {}
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !k.startsWith('CLAUDE_CODE_')) env[k] = v
  Object.assign(env, {
    KOVO_DISPATCH_CLAUDE_BIN: bins.claudeBin,
    KOVO_DISPATCH_OPENCODE_BIN: bins.opencodeBin,
    MOCK_LOG: bins.logPath,
    ...extraEnv,
  })
  return spawnSync(process.execPath, [SCRIPT, ...args], { env, encoding: 'utf8', timeout: 10_000 })
}

interface CallLog {
  who: string
  argv: string[]
  cwd: string
  killSwitches: Array<string | undefined>
}

function readCalls(bins: MockBins): CallLog[] {
  if (!existsSync(bins.logPath)) return []
  return readFileSync(bins.logPath, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l) as CallLog)
}

describe('dispatch-worker: CLI', () => {
  it('--help prints usage and exits 0', () => {
    const bins = makeMockBins()
    const r = runCli(['--help'], bins)
    assert.equal(r.status, 0)
    assert.match(r.stdout, /--tier <standard\|security-adjacent>/)
  })

  it('invalid flag values exit 2 without spawning anything', () => {
    const bins = makeMockBins()
    const r = runCli(['--prompt', 'x', '--mode', 'yolo'], bins)
    assert.equal(r.status, 2)
    assert.match(r.stderr, /invalid --mode/)
    assert.deepEqual(readCalls(bins), [])
  })

  it('--dry-run prints a valid JSON plan for every tier/mode and writes nothing', () => {
    const bins = makeMockBins()
    for (const tier of ['standard', 'security-adjacent'] as const) {
      for (const mode of ['implement', 'review'] as const) {
        for (const fallback of ['handoff', 'opencode'] as const) {
          const wt = makeWorktree()
          const r = runCli(['--dry-run', '--tier', tier, '--mode', mode, '--fallback', fallback, '--worktree', wt, '--prompt', 'Plan only.'], bins)
          assert.equal(r.status, 0, r.stderr)
          const plan = JSON.parse(r.stdout) as Record<string, unknown> & { args: string[]; envOverrides: Record<string, string>; handoffPreview: HandoffRecord }
          for (const k of ['tier', 'mode', 'worktree', 'expectedModel', 'fallback', 'action', 'command', 'args', 'envOverrides', 'handoffPreview']) {
            assert.ok(k in plan, `${tier}/${mode}/${fallback}: missing ${k}`)
          }
          assert.equal(plan.tier, tier)
          assert.equal(plan.mode, mode)
          assert.equal(plan.worktree, wt)
          assert.equal(plan.expectedModel, EXPECTED)
          assert.equal(plan.handoffPreview.nextTier, 'gemini-neon')
          if (tier === 'standard') {
            assert.equal(plan.action, 'spawn-claude')
            assert.deepEqual(plan.envOverrides, KILL_SWITCHES)
            assert.equal(plan.args.includes('--safe-mode'), mode === 'review')
            assert.equal(plan.args.includes('bypassPermissions'), mode === 'implement')
            assert.ok(!plan.args.includes('--fallback-model'))
          } else {
            assert.equal(plan.action, fallback === 'opencode' ? 'handoff+opencode' : 'handoff')
            assert.equal(plan.handoffPreview.reason, 'pre-routed:security-adjacent')
          }
          assertWorktreePreserved(wt, false)
        }
      }
    }
    assert.deepEqual(readCalls(bins), [], 'dry-run never spawns')
  })

  it('end-to-end: opus-4-8 downgrade with --fallback opencode kills claude and runs opencode in the worktree', () => {
    const bins = makeMockBins()
    const wt = makeWorktree()
    const promptFile = join(bins.dir, 'task.md')
    writeFileSync(promptFile, 'CLI task.')
    const frames = [init(), assistant('claude-opus-4-8')]
    const r = runCli(['--worktree', wt, '--prompt-file', promptFile, '--fallback', 'opencode'], bins, {
      MOCK_FRAMES: JSON.stringify(frames),
      MOCK_HANG: '1',
      MOCK_OPENCODE_EXIT: '5',
    })
    assert.equal(r.status, 5, r.stderr)
    const calls = readCalls(bins)
    assert.deepEqual(calls.map((c) => c.who), ['claude', 'opencode'])
    assert.deepEqual(calls[0].killSwitches, ['1', '1', '1'])
    assert.equal(calls[0].cwd, wt)
    assert.deepEqual(calls[1].argv, [...OPENCODE_ARGS_PREFIX, 'CLI task.'])
    assert.equal(calls[1].cwd, wt)
    assert.ok(readHandoff(wt).detectedModels.includes('claude-opus-4-8'))
    assertWorktreePreserved(wt, true)
  })

  it('end-to-end: security-adjacent handoff exits 42 and never invokes claude', () => {
    const bins = makeMockBins()
    const wt = makeWorktree()
    const r = runCli(['--tier', 'security-adjacent', '--worktree', wt, '--prompt', 'x'], bins)
    assert.equal(r.status, 42)
    assert.deepEqual(readCalls(bins), [])
    assert.equal(readHandoff(wt).reason, 'pre-routed:security-adjacent')
  })
})
