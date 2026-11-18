import { spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { realpathSync } from 'node:fs'
import { z } from 'zod'

const nameSchema = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/)
const workerNamespace = 'dev.guardian.workspace'
const workerName = /^guardian-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/
const jobSchema = z.object({
  assignmentId: z.uuid(),
  files: z.array(z.object({ name: nameSchema, content: z.string().max(64 * 1024) })).max(16),
  command: z.string().min(1).max(4 * 1024),
  outputs: z.array(nameSchema).max(4),
})
const resultSchema = z.object({
  exitCode: z.number().int(),
  stdout: z.string().max(32_768),
  stderr: z.string().max(32_768),
  outputs: z.record(nameSchema, z.string().max(32_768)),
})

export type WorkerJob = z.input<typeof jobSchema>
export type WorkerResult = z.output<typeof resultSchema>

export interface WorkerBackend {
  // The backend stages files, runs one bounded operation, and collects the
  // declared scratch outputs. Aborting the signal cancels the operation.
  run(job: WorkerJob, signal: AbortSignal): Promise<WorkerResult>
}

function docker(args: string[], signal: AbortSignal, input?: string) {
  signal.throwIfAborted()
  const host = process.env.DOCKER_HOST || 'unix:///var/run/docker.sock'
  return new Promise<string>((resolve, reject) => {
    if (!/^unix:\/\/\/[^/?#\r\n][^?#\r\n]*$/.test(host)) {
      throw new Error('Guardian requires a local Docker Unix socket.')
    }
    const cli = spawn('docker', args, {
      signal,
      env: {
        PATH: process.env.PATH,
        DOCKER_HOST: host,
        XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
      },
      stdio: ['pipe', 'pipe', 'ignore'],
    })
    const chunks: Buffer[] = []
    let size = 0
    const limit = 512 * 1024
    cli.stdout.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > limit) {
        cli.kill()
        reject(new Error('Worker output exceeded its limit.'))
      } else chunks.push(chunk)
    })
    cli.stdin.on('error', () => { /* An early container exit closes stdin. */ })
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
      // Docker can auto-remove a worker between listing it and removing it.
      if ((await list()).length) throw error
    }
  }

  async run(rawJob: WorkerJob, signal: AbortSignal): Promise<WorkerResult> {
    signal.throwIfAborted()
    const job = jobSchema.parse(rawJob)
    const payload = JSON.stringify(job)
    if (Buffer.byteLength(payload) > 512 * 1024) throw new Error('Worker inputs exceeded their limit.')
    await this.reclaimInactive()
    signal.throwIfAborted()
    const name = 'guardian-' + randomUUID()
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(15_000)])
    this.activeContainers.add(name)
    try {
      await docker([
        'container', 'create', '--name', name, '--interactive', '--rm', '--pull', 'never',
        '--network', 'none', '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--pids-limit', '48', '--cpus', '0.5',
        '--memory', '256m', '--memory-swap', '256m',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=8m,mode=1777',
        '--label', 'dev.guardian.assignment=' + job.assignmentId,
        ...(this.owner ? ['--label', `${workerNamespace}=${this.owner}`] : []),
        this.image,
      ], deadline)
      const result = await docker(['container', 'start', '--attach', '--interactive', name], deadline, payload)
      return resultSchema.parse(JSON.parse(result))
    } finally {
      // A disconnected CLI does not guarantee the container has stopped.
      await docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000)).catch(() => undefined)
      this.activeContainers.delete(name)
    }
  }
}
