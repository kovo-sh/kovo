import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { createInterface } from 'node:readline'
import { Bash, InMemoryFs, MountableFs, OverlayFs } from 'just-bash'
import { runAnalyzer } from './analyzers.ts'
import type { AnalyzerName } from './analyzers.ts'

type OneShotInput = {
  files: Array<{ name: string; content: string }>
  command: string
  outputs: string[]
  timeoutMs?: number
}

type SessionMessage =
  | { id: string; op: 'stage'; name: string; content: string }
  | { id: string; op: 'exec'; command: string; outputs: string[]; timeoutMs?: number }
  | { id: string; op: 'analyze'; tool: AnalyzerName; args: Record<string, unknown> }
  | { id: string; op: 'shutdown' }

const maxInputBytes = 16 * 1024 * 1024
const maxOutputBytes = 256 * 1024
const maxFileBytes = 2 * 1024 * 1024
const maxScratchBytes = 16 * 1024 * 1024
const cleanPath = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}(?:\/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}){0,3}$/
const cleanOutputName = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/

async function stageFile(root: string, name: string, content: string) {
  if (!cleanPath.test(name) || name.includes('..')) throw new Error('Invalid input path.')
  if (Buffer.byteLength(content) > maxFileBytes) throw new Error('Staged file exceeds limit.')
  const full = join(root, name)
  await mkdir(dirname(full), { recursive: true, mode: 0o700 })
  await writeFile(full, content, { mode: 0o400 })
}

async function execCommand(
  shell: Bash,
  scratch: InMemoryFs,
  command: string,
  outputNames: string[],
  timeoutMs = 60_000,
) {
  const capped = Math.max(1_000, Math.min(timeoutMs, 120_000))
  const timer = setTimeout(() => {
    process.stderr.write('Worker command exceeded its deadline.\n')
    process.exit(124)
  }, capped)
  timer.unref()
  try {
    const result = await shell.exec(command)
    const outputs: Record<string, string> = {}
    for (const name of outputNames) {
      const path = '/work/' + name
      if (!cleanOutputName.test(name) || !(await scratch.exists(path))) continue
      const info = await scratch.lstat(path)
      if (info.isFile && !info.isSymbolicLink && info.size <= maxOutputBytes) {
        outputs[name] = await scratch.readFile(path)
      }
    }
    return {
      exitCode: result.exitCode,
      stdout: result.stdout.slice(0, maxOutputBytes),
      stderr: result.stderr.slice(0, maxOutputBytes),
      outputs,
    }
  } finally {
    clearTimeout(timer)
  }
}

async function createSandbox() {
  const inputDirectory = await mkdtemp(join(tmpdir(), 'guardian-inputs-'))
  const scratch = new InMemoryFs({}, { maxTotalBytes: maxScratchBytes })
  scratch.mkdirSync('/work')
  const fs = new MountableFs({
    base: scratch,
    mounts: [{
      mountPoint: '/evidence',
      filesystem: new OverlayFs({
        root: inputDirectory,
        mountPoint: '/',
        readOnly: true,
        allowSymlinks: false,
        maxFileReadSize: maxFileBytes,
      }),
    }],
  })
  const shell = new Bash({
    cwd: '/work',
    fs,
    executionLimitProfile: 'hardened',
    python: false,
    javascript: false,
  })
  return { inputDirectory, scratch, shell }
}

async function runOneShot() {
  const source = readFileSync(0, 'utf8')
  if (Buffer.byteLength(source) > maxInputBytes) throw new Error('Assignment inputs exceed the worker limit.')
  const job = JSON.parse(source) as OneShotInput
  const { inputDirectory, scratch, shell } = await createSandbox()
  for (const input of job.files) {
    await stageFile(inputDirectory, input.name, input.content)
  }
  const result = await execCommand(shell, scratch, job.command, job.outputs, job.timeoutMs ?? 60_000)
  process.stdout.write(JSON.stringify(result))
}

async function runSession() {
  const { inputDirectory, scratch, shell } = await createSandbox()
  const stagedContents = new Map<string, string>()
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity })
  const respond = (payload: Record<string, unknown>) => {
    process.stdout.write(JSON.stringify(payload) + '\n')
  }
  for await (const line of rl) {
    const trimmed = line.trim()
    if (!trimmed) continue
    let msg: SessionMessage
    try {
      msg = JSON.parse(trimmed) as SessionMessage
    } catch {
      respond({ id: 'parse', ok: false, error: 'Invalid NDJSON command.' })
      continue
    }
    try {
      if (msg.op === 'shutdown') {
        respond({ id: msg.id, ok: true })
        break
      }
      if (msg.op === 'stage') {
        await stageFile(inputDirectory, msg.name, msg.content)
        stagedContents.set(msg.name, msg.content)
        respond({ id: msg.id, ok: true, path: '/evidence/' + msg.name })
      } else if (msg.op === 'exec') {
        const result = await execCommand(shell, scratch, msg.command, msg.outputs, msg.timeoutMs ?? 60_000)
        respond({ id: msg.id, ok: true, result })
      } else if (msg.op === 'analyze') {
        const result = runAnalyzer(msg.tool, msg.args, (name: string) => {
          const clean = name.replace(/^\/evidence\//, '')
          const cached = stagedContents.get(clean)
          if (cached !== undefined) return cached
          throw new Error('Staged evidence file not found: ' + clean)
        })
        respond({ id: msg.id, ok: true, result })
      }
    } catch (error) {
      respond({ id: msg.id, ok: false, error: error instanceof Error ? error.message : 'Worker operation failed.' })
    }
  }
  // Keep reference to readFile used if needed later
  void readFile
}

const sessionMode = process.argv.includes('--session')
;(sessionMode ? runSession() : runOneShot()).catch(() => {
  process.stderr.write('The evidence worker could not execute the operation.\n')
  process.exitCode = 1
})
