/**
 * Zero-LLM verifier backends for the recall benchmark.
 *
 * `ReplayVerifier` evaluates its jq assertion through a WorkerBackend. The default is the
 * air-gapped Docker worker (`LinuxWorkerBackend`). When Docker (or the worker image) is not
 * usable on the host, `auto` falls back to `LocalJqBackend`, which runs ONLY the exact
 * `jq '<filter>' /evidence/replay-results.json > /work/outcome.json` command shape that the
 * verifier emits, via execFile (no shell), on a temp copy of the evidence. The chosen backend
 * is recorded in every report as `verifierBackend`.
 */
import { execFile } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'

export type VerifierBackendKind = 'docker' | 'local-jq'
type RunFn = WorkerBackend['run']

const jqCommandShape = /^jq '([\s\S]*)' \/evidence\/replay-results\.json > \/work\/outcome\.json$/

function execFileText(file: string, args: string[], timeoutMs: number): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise(resolve => {
    execFile(file, args, { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, env: { PATH: process.env.PATH } }, (err, stdout, stderr) => {
      const code = err ? (typeof (err as { code?: unknown }).code === 'number' ? (err as { code: number }).code : 1) : 0
      resolve({ code, stdout: String(stdout), stderr: String(stderr) })
    })
  })
}

export class LocalJqBackend implements WorkerBackend {
  run: RunFn = async (job, signal) => {
    signal.throwIfAborted()
    const match = jqCommandShape.exec(job.command)
    if (!match) {
      return { exitCode: 2, stdout: '', stderr: 'LocalJqBackend only evaluates the verifier jq assertion command.', outputs: {} }
    }
    const filter = match[1].replaceAll(`'\\''`, `'`)
    const file = job.files.find(f => f.name === 'replay-results.json')
    if (!file) return { exitCode: 2, stdout: '', stderr: 'missing replay-results.json evidence file', outputs: {} }
    const dir = mkdtempSync(join(tmpdir(), 'kovo-bench-jq-'))
    try {
      const evidencePath = join(dir, 'replay-results.json')
      writeFileSync(evidencePath, file.content, { mode: 0o600 })
      const res = await execFileText('jq', [filter, evidencePath], Math.min(job.timeoutMs ?? 30_000, 30_000))
      const outputs: Record<string, string> = res.code === 0 ? { 'outcome.json': res.stdout } : {}
      return { exitCode: res.code, stdout: res.stdout, stderr: res.stderr.slice(0, 2000), outputs }
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }

  async openSession(): Promise<WorkerSession> {
    throw new Error('LocalJqBackend does not support worker sessions.')
  }

  async verifyStaticAst(): Promise<never> {
    throw new Error('LocalJqBackend does not support static AST verification.')
  }
}

export const DEFAULT_WORKER_IMAGE = 'kovo-worker:v4'

export interface WorkerImageIdentity {
  imageRef: string
  imageId: string | null
  sourceHash: string | null
  sdkVersion: string | null
}

/** Resolve the exact Docker worker image ref that `LinuxWorkerBackend` honors (`KOVO_WORKER_IMAGE` or default). */
export function resolveWorkerImageRef(
  env: NodeJS.ProcessEnv = process.env,
  explicitImage?: string,
): string {
  return explicitImage?.trim() || env.KOVO_WORKER_IMAGE?.trim() || DEFAULT_WORKER_IMAGE
}

type ExecTextFn = (file: string, args: string[], timeoutMs: number) => Promise<{ code: number; stdout: string; stderr: string }>

/** Inspect the resolved worker image via `docker image inspect` for immutable image ID and build LABELs. */
export async function inspectDockerWorkerImage(
  imageRef: string = resolveWorkerImageRef(),
  execFn: ExecTextFn = execFileText,
): Promise<WorkerImageIdentity | null> {
  const info = await execFn('docker', ['info', '--format', '{{.ServerVersion}}'], 8_000)
  if (info.code !== 0) return null
  const format = '{{.Id}}\t{{index .Config.Labels "kovo.worker.source_hash"}}\t{{index .Config.Labels "kovo.worker.sdk_version"}}'
  const res = await execFn('docker', ['image', 'inspect', '--format', format, imageRef], 8_000)
  if (res.code !== 0) return null
  const line = res.stdout.trim().split(/\r?\n/)[0] ?? ''
  const [rawId = '', rawHash = '', rawSdk = ''] = line.split('\t')
  const clean = (v: string): string | null => {
    const trimmed = v.trim()
    return trimmed && trimmed !== '<no value>' ? trimmed : null
  }
  return {
    imageRef,
    imageId: clean(rawId),
    sourceHash: clean(rawHash),
    sdkVersion: clean(rawSdk),
  }
}

export async function selectVerifierBackend(
  choice: 'auto' | 'docker' | 'local-jq',
  opts: { env?: NodeJS.ProcessEnv; image?: string } = {},
): Promise<{ kind: VerifierBackendKind; backend: WorkerBackend; workerImage: WorkerImageIdentity | null }> {
  if (choice === 'local-jq') {
    const probe = await execFileText('jq', ['--version'], 5_000)
    if (probe.code !== 0) throw new Error('--verifier-backend local-jq requires jq on PATH.')
    return { kind: 'local-jq', backend: new LocalJqBackend(), workerImage: null }
  }
  const imageRef = resolveWorkerImageRef(opts.env, opts.image)
  const workerImage = await inspectDockerWorkerImage(imageRef)
  if (choice === 'docker') {
    if (!workerImage) {
      throw new Error(`Docker worker backend requested but Docker or the ${imageRef} image is unavailable.`)
    }
    return {
      kind: 'docker',
      backend: new LinuxWorkerBackend({
        image: imageRef,
        imageId: workerImage.imageId,
        sourceHash: workerImage.sourceHash,
      }),
      workerImage,
    }
  }
  if (workerImage) {
    return {
      kind: 'docker',
      backend: new LinuxWorkerBackend({
        image: imageRef,
        imageId: workerImage.imageId,
        sourceHash: workerImage.sourceHash,
      }),
      workerImage,
    }
  }
  const probe = await execFileText('jq', ['--version'], 5_000)
  if (probe.code !== 0) throw new Error('No usable verifier backend: Docker worker unavailable and jq not found on PATH.')
  return { kind: 'local-jq', backend: new LocalJqBackend(), workerImage: null }
}
