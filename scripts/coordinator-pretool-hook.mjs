#!/usr/bin/env node
/**
 * Antigravity PreToolUse Coordinator Delegation Guard (A4 #1).
 *
 * Mechanically enforces the Coordinator 1-Call Budget & Subagent Routing Table
 * (`.agents/skills/coordinator/SKILL.md`) when running in coordinator mode:
 *
 *  - Hard-blocks inline coordinator `run_command` invocations containing
 *    `ssh`, `docker exec`, `sqlite3`, and inline `read_file`/`view_file`
 *    targeting `src/`, `worker/`, or `benchmarks/`.
 *  - Allows `grep`/`rg`/`git grep`/`grep_search` and whitelisted coordinator
 *    orchestration commands (`git`, `scripts/merge-stream.sh`,
 *    `scripts/certify-v8.ts`, `scripts/benchmark-multihop.ts`,
 *    `scripts/parallel-pulse.sh`, `scripts/worker-source-hash.sh`,
 *    `npm run worker:build`, `uptime`, `df`, `ls`).
 *  - Safety-critical: NEVER blocks swarm workers (worktrees/`*`/swarm-`*` or
 *    `inherit` workers) or subagents (`research`/`self`). Fails open on
 *    malformed/incomplete payloads so the hook can never wedge a session.
 *  - Escape hatch: set `KOVO_COORDINATOR_HOOK_BYPASS=1` for emergencies.
 *
 * Antigravity PreToolUse contract (`.agents/hooks.json`):
 *   stdin:  camelCase protojson PreToolUse payload
 *   stdout: {"decision":"allow"} | {"decision":"deny","reason":"..."}
 */

import { existsSync, openSync, readFileSync, readSync, closeSync } from 'node:fs'
import { basename, dirname, isAbsolute, join, posix, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const WORKER_WORKTREE_RE =
  /(?:^|[\\/])(?:worktrees[\\/][^\\/]+[\\/]swarm-[^\\/]+|opencode-wt[\\/][^\\/]+)(?:[\\/]|$)/i

const BLOCKED_READ_PREFIXES = ['src', 'worker', 'benchmarks']

const WHITELISTED_SCRIPT_PATHS = new Set([
  'scripts/merge-stream.sh',
  'scripts/certify-v8.ts',
  'scripts/benchmark-multihop.ts',
  'scripts/parallel-pulse.sh',
  'scripts/worker-source-hash.sh',
])

const WHITELISTED_DIRECT_CMDS = new Set(['uptime', 'df', 'ls'])

const WRAPPER_CMDS_NO_ARG = new Set(['sudo', 'nohup', 'command', 'time', 'exec'])
const SHELL_CMDS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh'])
const SCRIPT_RUNNERS = new Set(['bash', 'sh', 'zsh', 'node', 'tsx', 'npx'])
const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/

function isTruthyEnv(value) {
  if (typeof value !== 'string') return false
  const v = value.trim().toLowerCase()
  return v === '1' || v === 'true' || v === 'yes'
}

/**
 * Normalize a path into POSIX slash form for cross-platform prefix checks.
 */
function toPosixPath(p) {
  return String(p).replace(/\\/g, '/')
}

/**
 * Returns true if any candidate workspace/cwd path belongs to a swarm worker or
 * OpenCode isolated worktree. Workers MUST NEVER be blocked by this hook.
 */
export function isWorkerWorktree(payload) {
  if (!payload || typeof payload !== 'object') return false
  const candidates = []
  if (typeof payload.cwd === 'string' && payload.cwd.trim()) {
    candidates.push(payload.cwd)
  }
  if (Array.isArray(payload.workspacePaths)) {
    for (const wp of payload.workspacePaths) {
      if (typeof wp === 'string' && wp.trim()) candidates.push(wp)
    }
  }
  return candidates.some((p) => WORKER_WORKTREE_RE.test(p))
}

/**
 * Resolve the conversation brain directory from PreToolUse common fields or env.
 */
function resolveBrainDir(payload, env) {
  if (typeof payload?.artifactDirectoryPath === 'string' && payload.artifactDirectoryPath.trim()) {
    return payload.artifactDirectoryPath.trim()
  }
  if (typeof payload?.transcriptPath === 'string' && payload.transcriptPath.trim()) {
    const tp = payload.transcriptPath.trim()
    const norm = toPosixPath(tp)
    const marker = '/.system_generated/logs/'
    const idx = norm.lastIndexOf(marker)
    if (idx > 0) {
      return tp.slice(0, idx)
    }
  }
  const convId =
    (typeof payload?.conversationId === 'string' && payload.conversationId.trim()) ||
    (typeof env?.ANTIGRAVITY_CONVERSATION_ID === 'string' && env.ANTIGRAVITY_CONVERSATION_ID.trim()) ||
    ''
  const appDataDir =
    typeof env?.ANTIGRAVITY_APP_DATA_DIR === 'string' ? env.ANTIGRAVITY_APP_DATA_DIR.trim() : ''
  if (convId && appDataDir) {
    return join(appDataDir, 'brain', convId)
  }
  return null
}

/**
 * Inspect only the first JSON line (<=4KB) of a transcript to detect whether
 * the session was spawned as a subagent or swarm worker (step 0 has
 * source === "SYSTEM" and type === "SYSTEM_MESSAGE").
 */
function isTranscriptSubagentOrWorker(transcriptPath) {
  if (typeof transcriptPath !== 'string' || !transcriptPath.trim()) return false
  if (!existsSync(transcriptPath)) return false
  let fd
  try {
    fd = openSync(transcriptPath, 'r')
    const buf = Buffer.alloc(4096)
    const bytesRead = readSync(fd, buf, 0, buf.length, 0)
    if (bytesRead <= 0) return false
    const chunk = buf.toString('utf8', 0, bytesRead)
    const newlineIdx = chunk.indexOf('\n')
    const firstLine = (newlineIdx >= 0 ? chunk.slice(0, newlineIdx) : chunk).trim()
    if (!firstLine) return false
    const entry = JSON.parse(firstLine)
    return entry?.source === 'SYSTEM' && entry?.type === 'SYSTEM_MESSAGE'
  } catch {
    return false
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd)
      } catch {
        // ignore close errors
      }
    }
  }
}

/**
 * Authoritatively check whether the current conversation is the swarm
 * coordinator by reading `<brainDir>/.system_generated/swarm/swarm.json`.
 *
 * In Antigravity:
 *  - Coordinator conversations own `.system_generated/swarm/swarm.json` with
 *    `swarm_id === conversationId`.
 *  - Swarm workers (`share`, `branch`, `inherit`) and subagents (`research`,
 *    `self`) have their own `conversationId` and `brain/<id>` directory with
 *    NO `.system_generated/swarm/swarm.json`.
 */
function hasAuthoritativeCoordinatorSwarmJson(payload, env) {
  const brainDir = resolveBrainDir(payload, env)
  if (!brainDir) return false
  const swarmJsonPath = join(brainDir, '.system_generated', 'swarm', 'swarm.json')
  if (!existsSync(swarmJsonPath)) return false
  try {
    const parsed = JSON.parse(readFileSync(swarmJsonPath, 'utf8'))
    const swarmId = typeof parsed?.swarm_id === 'string' ? parsed.swarm_id.trim() : ''
    if (!swarmId) return false
    const convId =
      (typeof payload?.conversationId === 'string' && payload.conversationId.trim()) || ''
    if (convId) {
      return swarmId === convId
    }
    return basename(brainDir) === swarmId
  } catch {
    return false
  }
}

/**
 * Determine whether coordinator enforcement is active for this PreToolUse event.
 */
export function isCoordinatorMode(payload, env = process.env) {
  if (isTruthyEnv(env?.KOVO_COORDINATOR_HOOK_BYPASS)) {
    return false
  }
  if (isWorkerWorktree(payload)) {
    return false
  }
  if (hasAuthoritativeCoordinatorSwarmJson(payload, env)) {
    return true
  }
  if (isTruthyEnv(env?.KOVO_COORDINATOR_MODE)) {
    // Even if KOVO_COORDINATOR_MODE=1 is inherited in env, never enforce on
    // subagents or swarm workers whose transcript starts with a SYSTEM spawn step.
    if (isTranscriptSubagentOrWorker(payload?.transcriptPath)) {
      return false
    }
    return true
  }
  return false
}

/**
 * Tokenize a shell command line into segments split by control/pipe operators
 * (`&&`, `||`, `;`, `|`, `&`, newline), while also extracting any nested
 * command substitutions (`$(...)` and backticks) as additional segments.
 */
function parseShellSegments(input) {
  const segments = []
  let currentTokens = []
  let currentBuf = ''
  let hasToken = false
  let inSingle = false
  let inDouble = false

  const flushToken = () => {
    if (hasToken || currentBuf.length > 0) {
      currentTokens.push(currentBuf)
      currentBuf = ''
      hasToken = false
    }
  }

  const flushSegment = () => {
    flushToken()
    if (currentTokens.length > 0) {
      segments.push(currentTokens)
      currentTokens = []
    }
  }

  for (let i = 0; i < input.length; i++) {
    const ch = input[i]
    const next = input[i + 1]

    if (inSingle) {
      if (ch === "'") {
        inSingle = false
      } else {
        currentBuf += ch
      }
      continue
    }

    if (ch === '\\' && i + 1 < input.length) {
      hasToken = true
      currentBuf += input[i + 1]
      i++
      continue
    }

    if (inDouble) {
      if (ch === '"') {
        inDouble = false
        continue
      }
      if (ch === '$' && next === '(') {
        const end = findMatchingParen(input, i + 2)
        if (end !== -1) {
          const inner = input.slice(i + 2, end)
          segments.push(...parseShellSegments(inner))
          i = end
          continue
        }
      }
      if (ch === '`') {
        const end = findMatchingBacktick(input, i + 1)
        if (end !== -1) {
          const inner = input.slice(i + 1, end)
          segments.push(...parseShellSegments(inner))
          i = end
          continue
        }
      }
      currentBuf += ch
      continue
    }

    if (ch === "'") {
      inSingle = true
      hasToken = true
      continue
    }
    if (ch === '"') {
      inDouble = true
      hasToken = true
      continue
    }

    // Command substitutions outside quotes
    if (ch === '$' && next === '(') {
      const end = findMatchingParen(input, i + 2)
      if (end !== -1) {
        const inner = input.slice(i + 2, end)
        segments.push(...parseShellSegments(inner))
        i = end
        continue
      }
    }
    if (ch === '`') {
      const end = findMatchingBacktick(input, i + 1)
      if (end !== -1) {
        const inner = input.slice(i + 1, end)
        segments.push(...parseShellSegments(inner))
        i = end
        continue
      }
    }

    // Comments (unquoted `#` at token boundary)
    if (ch === '#' && !hasToken && currentBuf.length === 0) {
      while (i < input.length && input[i] !== '\n') i++
      flushSegment()
      continue
    }

    // Separators: &&, ||, ;, |, &, \n
    if (ch === '\n' || ch === ';') {
      flushSegment()
      continue
    }
    if ((ch === '&' && next === '&') || (ch === '|' && next === '|')) {
      flushSegment()
      i++
      continue
    }
    if (ch === '|') {
      flushSegment()
      continue
    }
    if (ch === '&' && currentBuf.slice(-1) !== '>' && next !== '>') {
      flushSegment()
      continue
    }

    // Subshell grouping parentheses
    if (ch === '(' || ch === ')') {
      flushSegment()
      continue
    }

    // Whitespace
    if (/\s/.test(ch)) {
      flushToken()
      continue
    }

    hasToken = true
    currentBuf += ch
  }

  flushSegment()
  return segments
}

function findMatchingParen(str, startIdx) {
  let depth = 1
  let inSingle = false
  let inDouble = false
  for (let i = startIdx; i < str.length; i++) {
    const ch = str[i]
    if (inSingle) {
      if (ch === "'") inSingle = false
      continue
    }
    if (ch === '\\') {
      i++
      continue
    }
    if (inDouble) {
      if (ch === '"') inDouble = false
      continue
    }
    if (ch === "'") inSingle = true
    else if (ch === '"') inDouble = true
    else if (ch === '(') depth++
    else if (ch === ')') {
      depth--
      if (depth === 0) return i
    }
  }
  return -1
}

function findMatchingBacktick(str, startIdx) {
  for (let i = startIdx; i < str.length; i++) {
    if (str[i] === '\\') {
      i++
      continue
    }
    if (str[i] === '`') return i
  }
  return -1
}

/**
 * Strip leading redirections, env assignments, and wrapper commands
 * (`env`, `timeout`, `sudo`, `nohup`, `nice`, `command`, `time`) and also
 * extract nested `-c <script>` invocations (e.g. `bash -c '...'`,
 * `newgrp docker -c '...'`).
 */
function expandSegmentInvocations(tokens, depth = 0) {
  if (!Array.isArray(tokens) || tokens.length === 0 || depth > 4) return []

  // Strip shell redirections while keeping positional words
  const words = []
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]
    if (/^(?:\d+)?(?:>>?|<<?|<&|>&|&>|&>>)$/.test(tok)) {
      i++ // skip redirection target
      continue
    }
    if (/^(?:\d+)?(?:>>?|<<?|<&|>&|&>|&>>)/.test(tok)) {
      continue
    }
    words.push(tok)
  }

  let idx = 0
  while (idx < words.length && ENV_ASSIGN_RE.test(words[idx])) {
    idx++
  }
  if (idx >= words.length) return []

  const cmd = basename(words[idx])
  const rest = words.slice(idx + 1)

  if (WRAPPER_CMDS_NO_ARG.has(cmd)) {
    // Skip flags like `sudo -u root` or `nohup`
    let j = 0
    while (j < rest.length && rest[j].startsWith('-')) {
      if ((rest[j] === '-u' || rest[j] === '-g') && j + 1 < rest.length) j += 2
      else j++
    }
    return expandSegmentInvocations(rest.slice(j), depth + 1)
  }

  if (cmd === 'env') {
    let j = 0
    while (j < rest.length) {
      if (rest[j] === '-u' && j + 1 < rest.length) {
        j += 2
      } else if (rest[j].startsWith('-') || ENV_ASSIGN_RE.test(rest[j])) {
        j++
      } else {
        break
      }
    }
    return expandSegmentInvocations(rest.slice(j), depth + 1)
  }

  if (cmd === 'timeout') {
    let j = 0
    while (j < rest.length && rest[j].startsWith('-')) {
      if (/^-(?:k|s)$/.test(rest[j]) && j + 1 < rest.length) j += 2
      else j++
    }
    // Skip duration argument
    if (j < rest.length) j++
    return expandSegmentInvocations(rest.slice(j), depth + 1)
  }

  if (cmd === 'nice') {
    let j = 0
    while (j < rest.length && rest[j].startsWith('-')) {
      if (rest[j] === '-n' && j + 1 < rest.length) j += 2
      else j++
    }
    return expandSegmentInvocations(rest.slice(j), depth + 1)
  }

  // Unwrap `sh -c '...'`, `bash -lc '...'`, `newgrp docker -c '...'`
  if (SHELL_CMDS.has(cmd) || cmd === 'newgrp') {
    for (let j = 0; j < rest.length; j++) {
      const arg = rest[j]
      if (arg === '-c' || (SHELL_CMDS.has(cmd) && /^-[a-zA-Z]*c$/.test(arg))) {
        const script = rest[j + 1]
        if (typeof script === 'string' && script.trim()) {
          const nested = parseShellSegments(script)
          return nested.flatMap((seg) => expandSegmentInvocations(seg, depth + 1))
        }
      }
    }
  }

  return [{ rawCmd: words[idx], cmd, args: rest }]
}

/**
 * Normalize a script path argument (e.g., `./scripts/merge-stream.sh` or
 * `/repo/scripts/certify-v8.ts`) to its `scripts/<name>` form if applicable.
 */
function normalizeWhitelistedScript(token) {
  if (typeof token !== 'string') return null
  const p = toPosixPath(token).replace(/^\.\//, '')
  if (WHITELISTED_SCRIPT_PATHS.has(p)) return p
  for (const scriptRel of WHITELISTED_SCRIPT_PATHS) {
    if (p.endsWith('/' + scriptRel)) return scriptRel
  }
  return null
}

/**
 * Returns true if a single parsed invocation matches an explicitly whitelisted
 * coordinator orchestration command.
 */
function isWhitelistedInvocation({ rawCmd, cmd, args }) {
  // Direct whitelisted script (`scripts/merge-stream.sh`, `./scripts/parallel-pulse.sh`, etc.)
  if (normalizeWhitelistedScript(rawCmd)) return true

  // Direct whitelisted host/status commands (`uptime`, `df`, `ls`)
  if (WHITELISTED_DIRECT_CMDS.has(cmd)) return true

  // `git ...` (all git orchestration commands including `git grep`)
  if (cmd === 'git') {
    return true
  }

  // `npm run worker:build`
  if (cmd === 'npm') {
    const nonFlags = args.filter((a) => !a.startsWith('-'))
    if (nonFlags[0] === 'run' && nonFlags[1] === 'worker:build') return true
  }

  // Script runners executing whitelisted scripts (`bash scripts/merge-stream.sh`,
  // `npx tsx scripts/certify-v8.ts`, `node scripts/benchmark-multihop.ts`, etc.)
  if (SCRIPT_RUNNERS.has(cmd)) {
    for (const arg of args) {
      if (arg.startsWith('-')) continue
      if (arg === 'tsx' || arg === 'ts-node') continue
      return normalizeWhitelistedScript(arg) !== null
    }
  }

  return false
}

function findDockerSubcommand(args) {
  for (let i = 0; i < args.length; i++) {
    const a = args[i]
    if (a === '-H' || a === '--host' || a === '--context' || a === '--config' || a === '-l' || a === '--log-level') {
      i++
      continue
    }
    if (a.startsWith('-')) continue
    return a
  }
  return ''
}

/**
 * Evaluate a `run_command` CommandLine in coordinator mode.
 */
export function evaluateRunCommand(commandLine) {
  if (typeof commandLine !== 'string' || !commandLine.trim()) {
    return { decision: 'allow' }
  }

  const segments = parseShellSegments(commandLine)
  const invocations = segments.flatMap((seg) => expandSegmentInvocations(seg))

  for (const inv of invocations) {
    const { cmd, args } = inv

    if (cmd === 'ssh') {
      return {
        decision: 'deny',
        reason:
          "Coordinator PreToolUse guard: inline `ssh` is blocked in coordinator mode. Delegate live VM / SSH debugging to `invoke_subagent(typeName: 'self')` (isolated shell/SSH, return a <=10-line summary). Emergency override: KOVO_COORDINATOR_HOOK_BYPASS=1.",
      }
    }

    if (cmd === 'docker' && findDockerSubcommand(args) === 'exec') {
      return {
        decision: 'deny',
        reason:
          "Coordinator PreToolUse guard: inline `docker exec` is blocked in coordinator mode. Delegate live container debugging to `invoke_subagent(typeName: 'self')` (isolated Docker/shell check, return a <=10-line summary). Emergency override: KOVO_COORDINATOR_HOOK_BYPASS=1.",
      }
    }

    if (cmd === 'sqlite3') {
      return {
        decision: 'deny',
        reason:
          "Coordinator PreToolUse guard: inline `sqlite3` is blocked in coordinator mode. Delegate live DB inspection to `invoke_subagent(typeName: 'self')` (return a <=10-line summary) or read-only forensics to `invoke_subagent(typeName: 'research')`. Emergency override: KOVO_COORDINATOR_HOOK_BYPASS=1.",
      }
    }

    // Explicitly recognize whitelisted orchestration commands (and allow other non-blocked commands).
    if (isWhitelistedInvocation(inv)) {
      continue
    }
  }

  return { decision: 'allow' }
}

/**
 * Evaluate a `read_file` / `view_file` path in coordinator mode.
 */
export function evaluateReadFile(targetPath, payload) {
  if (typeof targetPath !== 'string' || !targetPath.trim()) {
    return { decision: 'allow' }
  }

  const rawPath = targetPath.trim()
  const roots = []
  if (typeof payload?.cwd === 'string' && payload.cwd.trim()) {
    roots.push(payload.cwd.trim())
  }
  if (Array.isArray(payload?.workspacePaths)) {
    for (const wp of payload.workspacePaths) {
      if (typeof wp === 'string' && wp.trim() && !roots.includes(wp.trim())) {
        roots.push(wp.trim())
      }
    }
  }

  const relCandidates = []
  if (isAbsolute(rawPath)) {
    for (const root of roots) {
      const rel = toPosixPath(relative(resolve(root), resolve(rawPath)))
      if (rel && !rel.startsWith('..') && !isAbsolute(rel)) {
        relCandidates.push(rel)
      }
    }
    // If no workspace roots were supplied in payload, inspect normalized path segments conservatively.
    if (roots.length === 0) {
      const norm = toPosixPath(posix.normalize(toPosixPath(rawPath)))
      for (const prefix of BLOCKED_READ_PREFIXES) {
        const idx = norm.indexOf('/' + prefix + '/')
        if (idx !== -1) {
          relCandidates.push(norm.slice(idx + 1))
        } else if (norm.endsWith('/' + prefix)) {
          relCandidates.push(prefix)
        }
      }
    }
  } else {
    const norm = toPosixPath(posix.normalize(toPosixPath(rawPath))).replace(/^\.\//, '')
    relCandidates.push(norm)
    if (roots.length > 0) {
      const absFromCwd = resolve(roots[0], rawPath)
      for (const root of roots) {
        const rel = toPosixPath(relative(resolve(root), absFromCwd))
        if (rel && !rel.startsWith('..') && !isAbsolute(rel)) {
          relCandidates.push(rel)
        }
      }
    }
  }

  for (const rel of relCandidates) {
    const clean = rel.replace(/^\.\//, '')
    for (const prefix of BLOCKED_READ_PREFIXES) {
      if (clean === prefix || clean.startsWith(prefix + '/')) {
        return {
          decision: 'deny',
          reason: `Coordinator PreToolUse guard: inline \`read_file\` on \`${prefix}/\` (\`${clean}\`) is blocked in coordinator mode. Delegate local codebase or benchmark inspection to \`invoke_subagent(typeName: 'research')\` (or OpenCode fallback for \`truth/blueprint.ts\`), and delegate edits to \`swarm(action='add', workspace='share')\`. Emergency override: KOVO_COORDINATOR_HOOK_BYPASS=1.`,
        }
      }
    }
  }

  return { decision: 'allow' }
}

/**
 * Evaluate a full Antigravity PreToolUse hook payload.
 */
export function evaluatePreToolUse(payload, env = process.env) {
  try {
    if (!payload || typeof payload !== 'object') {
      return { decision: 'allow' }
    }
    if (!isCoordinatorMode(payload, env)) {
      return { decision: 'allow' }
    }

    const toolCall = payload.toolCall
    if (!toolCall || typeof toolCall !== 'object') {
      return { decision: 'allow' }
    }

    const toolName = typeof toolCall.name === 'string' ? toolCall.name.trim().toLowerCase() : ''
    const args = toolCall.args && typeof toolCall.args === 'object' ? toolCall.args : {}

    if (toolName === 'run_command') {
      const cmdLine =
        typeof args.CommandLine === 'string'
          ? args.CommandLine
          : typeof args.commandLine === 'string'
            ? args.commandLine
            : typeof args.command === 'string'
              ? args.command
              : ''
      return evaluateRunCommand(cmdLine)
    }

    if (toolName === 'read_file' || toolName === 'view_file') {
      const targetPath =
        typeof args.Path === 'string'
          ? args.Path
          : typeof args.path === 'string'
            ? args.path
            : typeof args.AbsolutePath === 'string'
              ? args.AbsolutePath
              : typeof args.filePath === 'string'
                ? args.filePath
                : typeof args.file_path === 'string'
                  ? args.file_path
                  : ''
      return evaluateReadFile(targetPath, payload)
    }

    return { decision: 'allow' }
  } catch {
    // Fail-safe: never wedge an agent session on unexpected hook errors.
    return { decision: 'allow' }
  }
}

function runCli() {
  try {
    const raw = readFileSync(0, 'utf8')
    if (!raw || !raw.trim()) {
      process.stdout.write(JSON.stringify({ decision: 'allow' }) + '\n')
      return
    }
    const payload = JSON.parse(raw)
    const result = evaluatePreToolUse(payload, process.env)
    process.stdout.write(JSON.stringify(result) + '\n')
  } catch {
    // Malformed JSON or unreadable stdin -> fail open.
    process.stdout.write(JSON.stringify({ decision: 'allow' }) + '\n')
  }
}

const isMain =
  typeof process.argv[1] === 'string' &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))

if (isMain) {
  runCli()
}
