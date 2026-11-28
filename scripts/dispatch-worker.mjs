#!/usr/bin/env node
/**
 * Claude Code worker dispatch bridge (coordinator Option 1 + 2 + 3).
 *
 * Hard no-silent-fallback bridge between the Antigravity coordinator and a
 * local Claude Code (`claude -p --model opus`) implementation worker:
 *
 *  - Option 2 (risk-tiered pre-router): `--tier security-adjacent` never
 *    spawns `claude`; it writes `<worktree>/.kovo-handoff.json` immediately and
 *    either exits 42 (Gemini Neon handoff) or runs OpenCode on the worktree.
 *  - Option 3 (pinned-model watchdog): `--tier standard` spawns `claude` with
 *    the three fallback kill-switch env vars, never passes `--fallback-model`,
 *    and inspects every `stream-json` / `json` frame live. Any model downgrade
 *    (assistant/init/modelUsage/canonicalModel not matching
 *    `--expected-model`), `safety_stops > 0`, `is_error`, a refusal stop,
 *    `usage.fallback_credit != null`, or a non-clean exit kills the child,
 *    preserves the worktree untouched, writes `.kovo-handoff.json`, and
 *    escalates (`--fallback handoff` -> exit 42; `--fallback opencode` ->
 *    `opencode run -m opencode-go/deepseek-v4.1-flash --auto --archived`).
 *
 * Zero dependencies. Pure helpers and `runDispatch(options, deps)` are exported
 * for hermetic tests; the CLI only runs when executed directly.
 *
 * Exit codes: 0 clean (or dry-run/help), 2 usage error, 42 handoff to Gemini
 * Neon, otherwise the propagated OpenCode exit code.
 */

import { spawn as nodeSpawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { StringDecoder } from 'node:string_decoder'
import { pathToFileURL } from 'node:url'

export const HANDOFF_EXIT_CODE = 42
export const USAGE_EXIT_CODE = 2
export const HANDOFF_FILENAME = '.kovo-handoff.json'
export const DEFAULT_EXPECTED_MODEL = 'claude-opus-5-5'
export const OPENCODE_MODEL = 'opencode-go/deepseek-v4.1-flash'
export const NEXT_TIER = 'gemini-neon'
export const TERTIARY_TIER = OPENCODE_MODEL
export const SECURITY_ADJACENT_REASON = 'pre-routed:security-adjacent'
export const REVIEW_TOOLS = 'Read,Grep,Glob'
export const DEFAULT_KILL_GRACE_MS = 3000

export const TIERS = Object.freeze(['standard', 'security-adjacent'])
export const MODES = Object.freeze(['implement', 'review'])
export const FALLBACKS = Object.freeze(['handoff', 'opencode'])

/** Env vars always injected into the Claude Code child (never overridable). */
export const CLAUDE_KILL_SWITCH_ENV = Object.freeze({
  CLAUDE_CODE_NO_MODEL_FALLBACK: '1',
  CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK: '1',
  CLAUDE_CODE_DISABLE_MODEL_ACCESS_FALLBACK: '1',
})

export const USAGE = `Usage: node scripts/dispatch-worker.mjs [options]

Dispatch a Claude Code worker pinned to one model, with a hard no-fallback
watchdog and a Gemini Neon / OpenCode escalation ladder on a preserved worktree.

Options:
  --tier <standard|security-adjacent>  Risk tier (default: standard). security-adjacent
                                       never spawns claude (pre-routed handoff).
  --worktree <dir>                     Worker git worktree (default: cwd).
  --prompt <str>                       Task prompt (sent to claude on stdin).
  --prompt-file <path>                 Read the task prompt from a UTF-8 file.
  --expected-model <id>                Pinned model id (default: ${DEFAULT_EXPECTED_MODEL}).
  --mode <implement|review>            implement: --permission-mode bypassPermissions;
                                       review: --safe-mode --tools "${REVIEW_TOOLS}" (default: implement).
  --fallback <handoff|opencode>        On violation: handoff -> write ${HANDOFF_FILENAME}, exit ${HANDOFF_EXIT_CODE};
                                       opencode -> write ${HANDOFF_FILENAME}, run
                                       opencode run -m ${OPENCODE_MODEL} --auto --archived <prompt>
                                       (default: handoff).
  --dry-run                            Print the JSON plan; spawn nothing, write nothing.
  -h, --help                           Show this help.

Env overrides: KOVO_DISPATCH_CLAUDE_BIN, KOVO_DISPATCH_OPENCODE_BIN.
Exit codes: 0 clean, ${USAGE_EXIT_CODE} usage error, ${HANDOFF_EXIT_CODE} handoff to Gemini Neon, else OpenCode's exit code.
`

export class DispatchUsageError extends Error {
  constructor(message) {
    super(message)
    this.name = 'DispatchUsageError'
  }
}

export const DEFAULT_OPTIONS = Object.freeze({
  tier: 'standard',
  worktree: undefined,
  prompt: undefined,
  promptFile: undefined,
  expectedModel: DEFAULT_EXPECTED_MODEL,
  mode: 'implement',
  fallback: 'handoff',
  dryRun: false,
  help: false,
})

const VALUE_FLAGS = new Map([
  ['--tier', 'tier'],
  ['--worktree', 'worktree'],
  ['--prompt', 'prompt'],
  ['--prompt-file', 'promptFile'],
  ['--expected-model', 'expectedModel'],
  ['--mode', 'mode'],
  ['--fallback', 'fallback'],
])

function assertChoice(flag, value, choices) {
  if (!choices.includes(value)) {
    throw new DispatchUsageError(`invalid ${flag} "${value}" (expected one of: ${choices.join(', ')})`)
  }
}

/**
 * Parse CLI argv (without node/script) into validated options. Pure: never
 * touches the filesystem (prompt files are read by `resolvePrompt`).
 */
export function parseArgs(argv) {
  const opts = { ...DEFAULT_OPTIONS }
  const seen = new Set()
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i]
    if (raw === '-h' || raw === '--help') {
      opts.help = true
      continue
    }
    if (raw === '--dry-run') {
      opts.dryRun = true
      continue
    }
    const eq = raw.startsWith('--') ? raw.indexOf('=') : -1
    const flag = eq > 0 ? raw.slice(0, eq) : raw
    const key = VALUE_FLAGS.get(flag)
    if (!key) {
      throw new DispatchUsageError(
        raw.startsWith('-') ? `unknown option ${flag}` : `unexpected positional argument "${raw}"`,
      )
    }
    let value
    if (eq > 0) {
      value = raw.slice(eq + 1)
    } else {
      if (i + 1 >= argv.length) throw new DispatchUsageError(`${flag} requires a value`)
      value = argv[++i]
    }
    if (seen.has(key)) throw new DispatchUsageError(`${flag} given more than once`)
    seen.add(key)
    opts[key] = value
  }
  return opts.help ? opts : validateOptions(opts)
}

/** Validate a (possibly programmatic) options object; returns it with defaults applied. */
export function validateOptions(input) {
  const opts = { ...DEFAULT_OPTIONS, ...input }
  if (opts.help) return opts
  assertChoice('--tier', opts.tier, TIERS)
  assertChoice('--mode', opts.mode, MODES)
  assertChoice('--fallback', opts.fallback, FALLBACKS)
  if (typeof opts.expectedModel !== 'string' || !opts.expectedModel.trim()) {
    throw new DispatchUsageError('--expected-model must be a non-empty model id')
  }
  if (opts.worktree !== undefined && (typeof opts.worktree !== 'string' || !opts.worktree.trim())) {
    throw new DispatchUsageError('--worktree must be a non-empty path')
  }
  if (opts.prompt !== undefined && opts.promptFile !== undefined) {
    throw new DispatchUsageError('--prompt and --prompt-file are mutually exclusive')
  }
  if (opts.prompt === undefined && opts.promptFile === undefined) {
    throw new DispatchUsageError('one of --prompt or --prompt-file is required')
  }
  if (opts.prompt !== undefined && (typeof opts.prompt !== 'string' || !opts.prompt.trim())) {
    throw new DispatchUsageError('--prompt must be non-empty')
  }
  return opts
}

/** Resolve the prompt text (reads `--prompt-file` as UTF-8). */
export function resolvePrompt(opts, readFile = (p) => readFileSync(p, 'utf8')) {
  if (opts.prompt !== undefined) return opts.prompt
  let text
  try {
    text = readFile(resolve(opts.promptFile))
  } catch (err) {
    throw new DispatchUsageError(`cannot read --prompt-file ${opts.promptFile}: ${err?.code ?? err?.message ?? err}`)
  }
  if (!text.trim()) throw new DispatchUsageError(`--prompt-file ${opts.promptFile} is empty`)
  return text
}

/**
 * True when `modelId` is the pinned model or a dated/variant suffix of it
 * (`claude-opus-5-5-20261101`, `claude-opus-5-5[1m]`). Any other version
 * (`claude-opus-4-8`) or family (`sonnet`, `haiku`) is rejected.
 */
export function isExpectedModel(modelId, expectedModel) {
  if (typeof modelId !== 'string' || typeof expectedModel !== 'string' || !expectedModel) return false
  return (
    modelId === expectedModel ||
    modelId.startsWith(`${expectedModel}-`) ||
    modelId.startsWith(`${expectedModel}[`)
  )
}

/** Build the `claude -p` invocation. The prompt is written to stdin. */
export function buildClaudeInvocation({ mode = 'implement', worktree, prompt, baseEnv = process.env, claudeBin = 'claude' }) {
  assertChoice('--mode', mode, MODES)
  const modeArgs =
    mode === 'review'
      ? ['--safe-mode', '--tools', REVIEW_TOOLS]
      : ['--permission-mode', 'bypassPermissions']
  const args = ['-p', ...modeArgs, '--no-session-persistence', '--model', 'opus', '--output-format', 'stream-json', '--verbose']
  const envOverrides = { ...CLAUDE_KILL_SWITCH_ENV }
  const env = { ...baseEnv, ...envOverrides }
  return { command: claudeBin, args, env, envOverrides, cwd: worktree, stdin: prompt }
}

/** Build the tertiary OpenCode invocation on the exact same worktree. */
export function buildOpencodeInvocation({ worktree, prompt, baseEnv = process.env, opencodeBin = 'opencode' }) {
  return {
    command: opencodeBin,
    args: ['run', '-m', OPENCODE_MODEL, '--auto', '--archived', prompt],
    env: { ...baseEnv },
    envOverrides: {},
    cwd: worktree,
  }
}

/** Build the `.kovo-handoff.json` record. */
export function buildHandoffRecord({
  reason,
  detectedModels = [],
  safetyStops = 0,
  fallbackCredit = null,
  tier,
  worktree,
  mode,
  expectedModel,
  fallback,
  claudeExitCode = null,
  prompt,
  promptFile,
  now = new Date(),
}) {
  const record = {
    reason,
    detectedModels: [...detectedModels],
    safetyStops,
    fallbackCredit: fallbackCredit ?? null,
    tier,
    worktree,
    nextTier: NEXT_TIER,
    tertiaryTier: TERTIARY_TIER,
    mode,
    expectedModel,
    fallback,
    claudeExitCode,
    createdAt: now.toISOString(),
  }
  if (promptFile !== undefined) record.promptFile = resolve(promptFile)
  if (typeof prompt === 'string') record.promptSha256 = createHash('sha256').update(prompt).digest('hex')
  return record
}

/** Atomically write `<worktree>/.kovo-handoff.json`; never touches other files. */
export function writeHandoff(worktree, record) {
  const target = join(worktree, HANDOFF_FILENAME)
  const tmp = `${target}.${process.pid}.tmp`
  writeFileSync(tmp, `${JSON.stringify(record, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 })
  renameSync(tmp, target)
  return target
}

function finiteNumber(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined
}

/**
 * Stateful frame inspector for Claude Code `stream-json` (NDJSON) and
 * single-object / array `json` output. `inspect(frame)` returns the first
 * violation (sticky) or null.
 */
export function createFrameInspector(expectedModel = DEFAULT_EXPECTED_MODEL) {
  const state = {
    frames: 0,
    detectedModels: [],
    safetyStops: 0,
    fallbackCredit: null,
    sawResult: false,
    sawCleanResult: false,
    violation: null,
  }

  const noteModel = (m) => {
    if (typeof m === 'string' && m && !state.detectedModels.includes(m)) state.detectedModels.push(m)
  }
  const checkModel = (m, where, reasons) => {
    if (typeof m !== 'string' || !m) return
    noteModel(m)
    if (!isExpectedModel(m, expectedModel)) reasons.push(`model-mismatch:${where}:${m}`)
  }

  function inspectOne(frame) {
    if (!frame || typeof frame !== 'object') return
    state.frames++
    const reasons = []
    const type = frame.type

    if (type === 'system' && frame.subtype === 'init') checkModel(frame.model, 'init', reasons)
    if (type === 'assistant') checkModel(frame.message?.model, 'assistant', reasons)
    if (type === 'stream_event' && frame.event?.type === 'message_start') {
      checkModel(frame.event.message?.model, 'stream_event', reasons)
    }
    checkModel(frame.canonicalModel, `${type ?? 'frame'}.canonicalModel`, reasons)

    if (type === 'result') {
      state.sawResult = true
      const stops = finiteNumber(frame.safety_stops) ?? finiteNumber(frame.usage?.safety_stops) ?? 0
      if (stops > 0) {
        state.safetyStops = stops
        reasons.push(`safety_stops:${stops}`)
      }
      const credit = frame.usage?.fallback_credit ?? frame.fallback_credit
      if (credit != null) {
        state.fallbackCredit = credit
        reasons.push('fallback_credit')
      }
      const subtype = typeof frame.subtype === 'string' ? frame.subtype : ''
      if (frame.is_error === true) {
        reasons.push(`is_error:${subtype || 'unknown'}`)
      } else if (/error|refus/i.test(subtype) && (frame.status === 'error' || frame.error != null)) {
        reasons.push(`result-error:${subtype}`)
      }
      if (frame.stop_reason === 'refusal') reasons.push('stop_reason:refusal')
      if (frame.modelUsage && typeof frame.modelUsage === 'object') {
        for (const [key, entry] of Object.entries(frame.modelUsage)) {
          checkModel(key, 'modelUsage', reasons)
          checkModel(entry?.canonicalModel, 'modelUsage.canonicalModel', reasons)
        }
      }
      if (reasons.length === 0) state.sawCleanResult = true
    }

    if (reasons.length > 0 && !state.violation) state.violation = { reason: reasons.join(', ') }
  }

  function inspect(frame) {
    if (state.violation) return state.violation
    if (Array.isArray(frame)) {
      for (const f of frame) {
        inspectOne(f)
        if (state.violation) break
      }
    } else {
      inspectOne(frame)
    }
    return state.violation
  }

  return { state, inspect }
}

/**
 * Line-buffered stdout parser feeding a frame inspector. `push(chunk)` and
 * `end()` return the sticky violation or null. Non-JSON lines are kept so a
 * pretty-printed single `json` object can still be parsed at end of stream.
 */
export function createStreamParser(expectedModel = DEFAULT_EXPECTED_MODEL) {
  const inspector = createFrameInspector(expectedModel)
  const decoder = new StringDecoder('utf8')
  let buffer = ''
  const unparsed = []

  const handleLine = (line) => {
    const trimmed = line.trim()
    if (!trimmed) return
    let frame
    try {
      frame = JSON.parse(trimmed)
    } catch {
      unparsed.push(line)
      return
    }
    inspector.inspect(frame)
  }

  function push(chunk) {
    buffer += typeof chunk === 'string' ? chunk : decoder.write(chunk)
    let nl
    while ((nl = buffer.indexOf('\n')) !== -1) {
      handleLine(buffer.slice(0, nl))
      buffer = buffer.slice(nl + 1)
      if (inspector.state.violation) break
    }
    return inspector.state.violation
  }

  function end() {
    buffer += decoder.end()
    if (buffer) handleLine(buffer)
    buffer = ''
    if (!inspector.state.violation && unparsed.length > 0) {
      try {
        inspector.inspect(JSON.parse(unparsed.join('\n')))
        unparsed.length = 0
      } catch {
        // not a multi-line JSON document; leave as unparsed diagnostics
      }
    }
    return inspector.state.violation
  }

  return { push, end, state: inspector.state, unparsedLineCount: () => unparsed.length }
}

/** Parse a full stdout capture (NDJSON or single JSON) into its final state. */
export function parseFrames(text, expectedModel = DEFAULT_EXPECTED_MODEL) {
  const parser = createStreamParser(expectedModel)
  parser.push(text)
  parser.end()
  return parser.state
}

/** SIGTERM now, SIGKILL after `graceMs` if the child has not exited. */
export function terminateChild(child, graceMs = DEFAULT_KILL_GRACE_MS) {
  if (!child || child.exitCode != null || child.signalCode != null) return
  try {
    child.kill('SIGTERM')
  } catch {
    return
  }
  const timer = setTimeout(() => {
    if (child.exitCode == null && child.signalCode == null) {
      try {
        child.kill('SIGKILL')
      } catch {
        // already gone
      }
    }
  }, graceMs)
  timer.unref?.()
  child.once?.('close', () => clearTimeout(timer))
}

/** Build the structured `--dry-run` plan (pure). */
export function buildPlan(opts, { worktree, prompt, claudeBin = 'claude', opencodeBin = 'opencode', baseEnv = process.env } = {}) {
  const common = { tier: opts.tier, mode: opts.mode, worktree, expectedModel: opts.expectedModel, fallback: opts.fallback }
  const opencode = buildOpencodeInvocation({ worktree, prompt, baseEnv, opencodeBin })
  const handoffBase = {
    tier: opts.tier,
    worktree,
    mode: opts.mode,
    expectedModel: opts.expectedModel,
    fallback: opts.fallback,
    prompt,
    promptFile: opts.promptFile,
  }
  if (opts.tier === 'security-adjacent') {
    const handoffPreview = buildHandoffRecord({ ...handoffBase, reason: SECURITY_ADJACENT_REASON })
    if (opts.fallback === 'opencode') {
      return { ...common, action: 'handoff+opencode', command: opencode.command, args: opencode.args, envOverrides: {}, handoffPreview, exitCode: 'opencode' }
    }
    return { ...common, action: 'handoff', command: null, args: [], envOverrides: {}, handoffPreview, exitCode: HANDOFF_EXIT_CODE }
  }
  const claude = buildClaudeInvocation({ mode: opts.mode, worktree, prompt, baseEnv, claudeBin })
  return {
    ...common,
    action: 'spawn-claude',
    command: claude.command,
    args: claude.args,
    envOverrides: claude.envOverrides,
    promptVia: 'stdin',
    promptChars: prompt.length,
    handoffPreview: buildHandoffRecord({ ...handoffBase, reason: '<violation reason>' }),
    onViolation:
      opts.fallback === 'opencode'
        ? { action: 'handoff+opencode', command: opencode.command, args: opencode.args }
        : { action: 'handoff', exitCode: HANDOFF_EXIT_CODE },
  }
}

function resolveWorktree(dir) {
  const worktree = resolve(dir ?? process.cwd())
  if (!existsSync(worktree) || !statSync(worktree).isDirectory()) {
    throw new DispatchUsageError(`--worktree ${worktree} is not a directory`)
  }
  return worktree
}

function writeLine(stream, text) {
  stream?.write?.(text.endsWith('\n') ? text : `${text}\n`)
}

function runOpencode({ worktree, prompt, env, opencodeBin, spawnImpl, stdout, stderr, signal }) {
  const inv = buildOpencodeInvocation({ worktree, prompt, baseEnv: env, opencodeBin })
  writeLine(stderr, `[dispatch-worker] tertiary: ${inv.command} run -m ${OPENCODE_MODEL} --auto --archived <prompt> (cwd ${worktree})`)
  return new Promise((resolvePromise) => {
    let settled = false
    const done = (code) => {
      if (!settled) {
        settled = true
        resolvePromise(code)
      }
    }
    let child
    try {
      child = spawnImpl(inv.command, inv.args, { cwd: inv.cwd, env: inv.env, stdio: ['ignore', 'pipe', 'pipe'] })
    } catch (err) {
      writeLine(stderr, `[dispatch-worker] opencode spawn failed (${err?.code ?? err?.message}); falling back to Gemini Neon handoff`)
      done(HANDOFF_EXIT_CODE)
      return
    }
    const onAbort = () => terminateChild(child)
    signal?.addEventListener?.('abort', onAbort, { once: true })
    child.stdout?.on('data', (c) => stdout?.write?.(c))
    child.stderr?.on('data', (c) => stderr?.write?.(c))
    child.on('error', (err) => {
      writeLine(stderr, `[dispatch-worker] opencode spawn failed (${err?.code ?? err?.message}); falling back to Gemini Neon handoff`)
      done(HANDOFF_EXIT_CODE)
    })
    child.on('close', (code, sig) => {
      signal?.removeEventListener?.('abort', onAbort)
      done(typeof code === 'number' ? code : sig ? 1 : 0)
    })
  })
}

function runClaude({ worktree, prompt, opts, env, claudeBin, spawnImpl, stdout, stderr, killGraceMs, signal }) {
  const inv = buildClaudeInvocation({ mode: opts.mode, worktree, prompt, baseEnv: env, claudeBin })
  const parser = createStreamParser(opts.expectedModel)
  return new Promise((resolvePromise) => {
    let settled = false
    let killed = false
    const finish = (result) => {
      if (!settled) {
        settled = true
        resolvePromise({ ...result, state: parser.state })
      }
    }
    let child
    try {
      child = spawnImpl(inv.command, inv.args, { cwd: inv.cwd, env: inv.env, stdio: ['pipe', 'pipe', 'pipe'] })
    } catch (err) {
      finish({ violation: { reason: `claude-spawn-error:${err?.code ?? err?.message}` }, exitCode: null })
      return
    }
    let violation = null
    const kill = () => {
      if (!killed) {
        killed = true
        terminateChild(child, killGraceMs)
      }
    }
    const onAbort = () => {
      violation ??= { reason: 'dispatcher-aborted' }
      kill()
    }
    signal?.addEventListener?.('abort', onAbort, { once: true })

    child.stdin?.on?.('error', () => {})
    child.stdin?.end?.(prompt)
    child.stdout?.on('data', (chunk) => {
      if (killed) return
      stdout?.write?.(chunk)
      const v = parser.push(chunk)
      if (v) {
        violation ??= v
        writeLine(stderr, `[dispatch-worker] violation: ${v.reason} — killing claude`)
        kill()
      }
    })
    child.stderr?.on('data', (chunk) => stderr?.write?.(chunk))
    child.on('error', (err) => {
      violation ??= { reason: `claude-spawn-error:${err?.code ?? err?.message}` }
      finish({ violation, exitCode: null })
    })
    child.on('close', (code, sig) => {
      signal?.removeEventListener?.('abort', onAbort)
      if (!killed) violation ??= parser.end()
      const st = parser.state
      if (!violation) {
        if (typeof code === 'number' && code !== 0 && !st.sawCleanResult) {
          violation = { reason: `claude-exit:${code}` }
        } else if (code == null && sig) {
          violation = { reason: `claude-signal:${sig}` }
        } else if (!st.sawResult) {
          violation = { reason: 'claude-no-result-frame' }
        }
      }
      finish({ violation, exitCode: typeof code === 'number' ? code : null })
    })
  })
}

/**
 * Run a dispatch. Returns `{ exitCode, action, reason?, handoffPath? }`.
 * deps: { claudeBin, opencodeBin, spawnImpl, stdout, stderr, env, killGraceMs, signal }
 */
export async function runDispatch(options, deps = {}) {
  const env = deps.env ?? process.env
  const stdout = deps.stdout ?? process.stdout
  const stderr = deps.stderr ?? process.stderr
  const spawnImpl = deps.spawnImpl ?? nodeSpawn
  const claudeBin = deps.claudeBin ?? env.KOVO_DISPATCH_CLAUDE_BIN ?? 'claude'
  const opencodeBin = deps.opencodeBin ?? env.KOVO_DISPATCH_OPENCODE_BIN ?? 'opencode'
  const killGraceMs = deps.killGraceMs ?? DEFAULT_KILL_GRACE_MS

  let opts
  let worktree
  let prompt
  try {
    opts = Array.isArray(options) ? parseArgs(options) : validateOptions(options)
    if (opts.help) {
      stdout.write(USAGE)
      return { exitCode: 0, action: 'help' }
    }
    worktree = resolveWorktree(opts.worktree)
    prompt = resolvePrompt(opts)
  } catch (err) {
    if (err instanceof DispatchUsageError) {
      writeLine(stderr, `[dispatch-worker] error: ${err.message}\n\n${USAGE}`)
      return { exitCode: USAGE_EXIT_CODE, action: 'usage-error', reason: err.message }
    }
    throw err
  }

  if (opts.dryRun) {
    const plan = buildPlan(opts, { worktree, prompt, claudeBin, opencodeBin, baseEnv: env })
    stdout.write(`${JSON.stringify(plan, null, 2)}\n`)
    return { exitCode: 0, action: 'dry-run', plan }
  }

  const handoffBase = {
    tier: opts.tier,
    worktree,
    mode: opts.mode,
    expectedModel: opts.expectedModel,
    fallback: opts.fallback,
    prompt,
    promptFile: opts.promptFile,
  }
  const escalate = async (record) => {
    const handoffPath = writeHandoff(worktree, record)
    writeLine(stderr, `[dispatch-worker] handoff written: ${handoffPath} (reason: ${record.reason})`)
    if (opts.fallback === 'opencode') {
      const exitCode = await runOpencode({ worktree, prompt, env, opencodeBin, spawnImpl, stdout, stderr, signal: deps.signal })
      return { exitCode, action: 'handoff+opencode', reason: record.reason, handoffPath }
    }
    writeLine(stderr, `[dispatch-worker] exit ${HANDOFF_EXIT_CODE}: coordinator should spawn a ${NEXT_TIER} worker on the preserved worktree`)
    return { exitCode: HANDOFF_EXIT_CODE, action: 'handoff', reason: record.reason, handoffPath }
  }

  if (opts.tier === 'security-adjacent') {
    return escalate(buildHandoffRecord({ ...handoffBase, reason: SECURITY_ADJACENT_REASON }))
  }

  const { violation, exitCode, state } = await runClaude({
    worktree,
    prompt,
    opts,
    env,
    claudeBin,
    spawnImpl,
    stdout,
    stderr,
    killGraceMs,
    signal: deps.signal,
  })
  if (!violation) {
    writeLine(stderr, `[dispatch-worker] clean ${opts.expectedModel} session (models: ${state.detectedModels.join(', ') || 'none'})`)
    return { exitCode: 0, action: 'claude' }
  }
  if (violation.reason === 'dispatcher-aborted') {
    writeLine(stderr, '[dispatch-worker] aborted; worktree preserved, no handoff written')
    return { exitCode: 130, action: 'aborted', reason: violation.reason }
  }
  return escalate(
    buildHandoffRecord({
      ...handoffBase,
      reason: violation.reason,
      detectedModels: state.detectedModels,
      safetyStops: state.safetyStops,
      fallbackCredit: state.fallbackCredit,
      claudeExitCode: exitCode,
    }),
  )
}

async function main() {
  const controller = new AbortController()
  const onSignal = () => controller.abort()
  process.once('SIGINT', onSignal)
  process.once('SIGTERM', onSignal)
  const { exitCode } = await runDispatch(process.argv.slice(2), { signal: controller.signal })
  process.exitCode = exitCode
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch((err) => {
    process.stderr.write(`[dispatch-worker] fatal: ${err?.stack ?? err}\n`)
    process.exitCode = 1
  })
}
