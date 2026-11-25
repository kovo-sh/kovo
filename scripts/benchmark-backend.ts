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

async function dockerWorkerUsable(): Promise<boolean> {
  const info = await execFileText('docker', ['info', '--format', '{{.ServerVersion}}'], 8_000)
  if (info.code !== 0) return false
  const image = await execFileText('docker', ['image', 'inspect', 'kovo-worker:v4'], 8_000)
  return image.code === 0
}

export async function selectVerifierBackend(choice: 'auto' | 'docker' | 'local-jq'): Promise<{ kind: VerifierBackendKind; backend: WorkerBackend }> {
  if (choice === 'local-jq') {
    const probe = await execFileText('jq', ['--version'], 5_000)
    if (probe.code !== 0) throw new Error('--verifier-backend local-jq requires jq on PATH.')
    return { kind: 'local-jq', backend: new LocalJqBackend() }
  }
  const dockerOk = await dockerWorkerUsable()
  if (choice === 'docker') {
    if (!dockerOk) throw new Error('Docker worker backend requested but Docker or the kovo-worker:v4 image is unavailable.')
    return { kind: 'docker', backend: new LinuxWorkerBackend() }
  }
  if (dockerOk) return { kind: 'docker', backend: new LinuxWorkerBackend() }
  const probe = await execFileText('jq', ['--version'], 5_000)
  if (probe.code !== 0) throw new Error('No usable verifier backend: Docker worker unavailable and jq not found on PATH.')
  return { kind: 'local-jq', backend: new LocalJqBackend() }
}
