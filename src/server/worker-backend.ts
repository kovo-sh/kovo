import { spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { existsSync, realpathSync, statSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { z } from 'zod'
import type { AnalyzerName } from '../../worker/analyzers.ts'

const pathSchema = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}(?:\/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}){0,3}$/)
const outputNameSchema = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/)
const workerNamespace = 'dev.guardian.workspace'
const workerName = /^guardian-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/

const jobSchema = z.object({
  assignmentId: z.uuid(),
  files: z.array(z.object({ name: pathSchema, content: z.string().max(2 * 1024 * 1024) })).max(128),
  command: z.string().min(1).max(16 * 1024),
  outputs: z.array(outputNameSchema).max(16),
  timeoutMs: z.number().int().min(1_000).max(120_000).optional(),
})

const resultSchema = z.object({
  exitCode: z.number().int(),
  stdout: z.string().max(256 * 1024),
  stderr: z.string().max(256 * 1024),
  outputs: z.record(outputNameSchema, z.string().max(256 * 1024)),
})

export type WorkerJob = z.input<typeof jobSchema>
export type WorkerResult = z.output<typeof resultSchema>

export interface WorkerSession {
  stage(name: string, content: string, signal: AbortSignal): Promise<string>
  exec(command: string, outputs: string[], signal: AbortSignal, timeoutMs?: number): Promise<WorkerResult>
  analyze(tool: AnalyzerName, args: Record<string, unknown>, signal: AbortSignal): Promise<Record<string, unknown>>
  close(): Promise<void>
}

export interface WorkerSessionOptions {
  reposDir?: string
}

export interface WorkerBackend {
  run(job: WorkerJob, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerResult>
  openSession(assignmentId: string, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession>
}

function dockerHost() {
  const host = process.env.DOCKER_HOST || 'unix:///var/run/docker.sock'
  if (!/^unix:\/\/\/[^/?#\r\n][^?#\r\n]*$/.test(host)) {
    throw new Error('Guardian requires a local Docker Unix socket.')
  }
  return host
}

function dockerEnv() {
  return {
    PATH: process.env.PATH,
    DOCKER_HOST: dockerHost(),
    XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
  }
}

function docker(args: string[], signal: AbortSignal, input?: string) {
  signal.throwIfAborted()
  return new Promise<string>((resolve, reject) => {
    const cli = spawn('docker', args, {
      signal,
      env: dockerEnv(),
      stdio: ['pipe', 'pipe', 'ignore'],
    })
    const chunks: Buffer[] = []
    let size = 0
    const limit = 16 * 1024 * 1024
    cli.stdout.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > limit) {
        cli.kill()
        reject(new Error('Worker output exceeded its limit.'))
      } else chunks.push(chunk)
    })
    cli.stdin.on('error', () => { /* Early exit closes stdin. */ })
    cli.stdin.end(input)
    cli.once('error', error => reject(signal.aborted ? signal.reason : error))
    cli.once('close', code => {
      if (code === 0) resolve(Buffer.concat(chunks).toString('utf8'))
      else reject(new Error('The isolated worker failed. Build the local worker image and check Docker availability.'))
    })
  })
}

export class LinuxWorkerBackend implements WorkerBackend {
  private readonly image: string
  private readonly owner?: string
  private readonly activeContainers = new Set<string>()
  private reclaiming?: Promise<void>

  constructor({ image = 'guardian-worker:local', workspace }: {
    image?: string
    workspace?: { id: string; directory: string }
  } = {}) {
    this.image = image
    if (workspace) {
      this.owner = createHash('sha256').update(workspace.id).update('\0').update(realpathSync(workspace.directory)).digest('hex')
    }
  }

  reclaimInactive() {
    if (!this.owner) return Promise.resolve()
    return this.reclaiming ??= this.removeInactive(this.owner).finally(() => {
      this.reclaiming = undefined
    })
  }

  private async removeInactive(owner: string) {
    const signal = AbortSignal.timeout(5_000)
    const list = async () => {
      const rows = await docker([
        'container', 'ls', '--all', '--no-trunc', '--filter', `label=${workerNamespace}=${owner}`,
        '--format', '{{.ID}}\t{{.Names}}',
      ], signal)
      return rows.trim().split('\n').flatMap(row => {
        const [id, name] = row.split('\t')
        return /^[a-f0-9]{64}$/.test(id) && workerName.test(name) && !this.activeContainers.has(name) ? [id] : []
      })
    }
    const inactive = await list()
    if (!inactive.length) return
    try {
      await docker(['container', 'rm', '--force', ...inactive], signal)
    } catch (error) {
      if ((await list()).length) throw error
    }
  }

  private resolveReposMountArgs(reposDir?: string): string[] {
    if (!reposDir) return []
    if (/[\0,\r\n]/.test(reposDir)) {
      throw new Error('Invalid repository mount path.')
    }
    if (!existsSync(reposDir)) return []
    const st = statSync(reposDir)
    if (!st.isDirectory()) {
      throw new Error('Repository mount path must be an existing directory.')
    }
    const resolved = realpathSync(reposDir)
    if (/[\0,\r\n]/.test(resolved)) {
      throw new Error('Invalid resolved repository mount path.')
    }
    return ['--mount', `type=bind,source=${resolved},target=/repos,readonly`]
  }

  private containerCreateArgs(name: string, assignmentId: string, extraArgs: string[] = [], options?: WorkerSessionOptions) {
    return [
      'container', 'create', '--name', name, '--interactive', '--rm', '--pull', 'never',
      '--network', 'none', '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges', '--pids-limit', '96', '--cpus', '1.0',
      '--memory', '512m', '--memory-swap', '512m',
      '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777',
      ...this.resolveReposMountArgs(options?.reposDir),
      '--label', 'dev.guardian.assignment=' + assignmentId,
      ...(this.owner ? ['--label', `${workerNamespace}=${this.owner}`] : []),
      this.image,
      ...extraArgs,
    ]
  }

  async run(rawJob: WorkerJob, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerResult> {
    signal.throwIfAborted()
    const job = jobSchema.parse(rawJob)
    const payload = JSON.stringify(job)
    if (Buffer.byteLength(payload) > 16 * 1024 * 1024) throw new Error('Worker inputs exceeded their limit.')
    await this.reclaimInactive()
    signal.throwIfAborted()
    const name = 'guardian-' + randomUUID()
    const timeoutMs = (job.timeoutMs ?? 60_000) + 10_000
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
    this.activeContainers.add(name)
    try {
      await docker(this.containerCreateArgs(name, job.assignmentId, [], options), deadline)
      const result = await docker(['container', 'start', '--attach', '--interactive', name], deadline, payload)
      return resultSchema.parse(JSON.parse(result))
    } finally {
      await docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000)).catch(() => undefined)
      this.activeContainers.delete(name)
    }
  }

  async openSession(assignmentId: string, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession> {
    signal.throwIfAborted()
    await this.reclaimInactive()
    signal.throwIfAborted()
    const name = 'guardian-' + randomUUID()
    this.activeContainers.add(name)
    try {
      await docker(this.containerCreateArgs(name, assignmentId, ['--session'], options), AbortSignal.any([signal, AbortSignal.timeout(15_000)]))
    } catch (error) {
      await docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000)).catch(() => undefined)
      this.activeContainers.delete(name)
      throw error
    }

    const cli: ChildProcess = spawn('docker', ['container', 'start', '--attach', '--interactive', name], {
      env: dockerEnv(),
      stdio: ['pipe', 'pipe', 'ignore'],
    })
    cli.stdin?.on('error', () => { /* Ignore EPIPE or write-after-end during shutdown. */ })
    const pending = new Map<string, { resolve: (value: Record<string, unknown>) => void; reject: (err: Error) => void }>()
    let closed = false
    let closing: Promise<void> | undefined

    const failAll = (err: Error) => {
      for (const [, waiter] of pending) waiter.reject(err)
      pending.clear()
    }

    const rl = createInterface({ input: cli.stdout!, crlfDelay: Infinity })
    rl.on('line', line => {
      const trimmed = line.trim()
      if (!trimmed) return
      try {
        const msg = JSON.parse(trimmed) as { id?: string; ok?: boolean; error?: string } & Record<string, unknown>
        const waiter = msg.id ? pending.get(msg.id) : undefined
        if (!waiter) return
        pending.delete(msg.id!)
        if (msg.ok) waiter.resolve(msg)
        else waiter.reject(new Error(msg.error ?? 'Worker session operation failed.'))
      } catch {
        // Ignore malformed noise
      }
    })
    cli.once('close', () => {
      closed = true
      failAll(new Error('Isolated worker session exited unexpectedly.'))
    })
    cli.once('error', error => {
      closed = true
      failAll(error)
    })

    const close = () => {
      if (closing) return closing
      closing = (async () => {
        closed = true
        try {
          if (cli.stdin && !cli.stdin.writableEnded && !cli.stdin.destroyed) {
            cli.stdin.end(JSON.stringify({ id: 'shutdown', op: 'shutdown' }) + '\n')
          }
        } catch { /* ignore */ }
        try { cli.kill() } catch { /* ignore */ }
        failAll(new Error('Isolated worker session closed.'))
        rl.close()
        await docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000)).catch(() => undefined)
        this.activeContainers.delete(name)
      })()
      return closing
    }

    const onAbort = () => { void close() }
    signal.addEventListener('abort', onAbort, { once: true })
    if (signal.aborted) void close()

    let chain: Promise<unknown> = Promise.resolve()
    const request = (payload: Record<string, unknown>, opSignal: AbortSignal, timeoutMs = 70_000) => {
      const run = () => new Promise<Record<string, unknown>>((resolve, reject) => {
        if (closed || !cli.stdin || cli.stdin.writableEnded || cli.stdin.destroyed) {
          return reject(new Error('Worker session is closed.'))
        }
        if (opSignal.aborted) return reject(opSignal.reason instanceof Error ? opSignal.reason : new Error('Aborted'))
        const id = randomUUID()
        const timer = setTimeout(() => {
          pending.delete(id)
          void close()
          reject(new Error('Worker session operation timed out.'))
        }, timeoutMs)
        const abortHandler = () => {
          clearTimeout(timer)
          pending.delete(id)
          void close()
          reject(opSignal.reason instanceof Error ? opSignal.reason : new Error('Aborted'))
        }
        opSignal.addEventListener('abort', abortHandler, { once: true })
        pending.set(id, {
          resolve: value => {
            clearTimeout(timer)
            opSignal.removeEventListener('abort', abortHandler)
            resolve(value)
          },
          reject: err => {
            clearTimeout(timer)
            opSignal.removeEventListener('abort', abortHandler)
            reject(err)
          },
        })
        cli.stdin.write(JSON.stringify({ ...payload, id }) + '\n')
      })
      const next = chain.then(run, run)
      chain = next.catch(() => undefined)
      return next
    }

    return {
      async stage(fileName, content, opSignal) {
        const clean = pathSchema.parse(fileName)
        const res = await request({ op: 'stage', name: clean, content }, opSignal, 15_000)
        return String(res.path ?? '/evidence/' + clean)
      },
      async exec(command, outputs, opSignal, timeoutMs = 60_000) {
        const validOutputs = z.array(outputNameSchema).max(16).parse(outputs)
        const res = await request({ op: 'exec', command: command.slice(0, 16 * 1024), outputs: validOutputs, timeoutMs }, opSignal, timeoutMs + 10_000)
        return resultSchema.parse(res.result)
      },
      async analyze(tool, args, opSignal) {
        const res = await request({ op: 'analyze', tool, args }, opSignal, 30_000)
        return (res.result as Record<string, unknown>) ?? {}
      },
      async close() {
        signal.removeEventListener('abort', onAbort)
        await close()
      },
    }
  }
}
