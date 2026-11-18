import { spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

async function availablePort() {
  const server = createServer().listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Could not allocate a test port.')
  await new Promise<void>(resolve => server.close(() => resolve()))
  return address.port
}

export async function createApp(env: NodeJS.ProcessEnv = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'guardian-e2e-'))
  const port = await availablePort()
  const url = `http://127.0.0.1:${port}`
  let processHandle: ChildProcess | undefined
  let output = ''

  return {
    directory,
    url,
    async start() {
      output = ''
      const child = spawn(process.execPath, ['scripts/serve.ts'], {
        cwd: process.cwd(),
        env: { ...process.env, GUARDIAN_PUBLIC_ORIGIN: '', ...env, PORT: String(port), GUARDIAN_DATA_DIR: directory },
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      processHandle = child
      child.stdout.on('data', chunk => { output += String(chunk) })
      child.stderr.on('data', chunk => { output += String(chunk) })
      for (let attempt = 0; attempt < 130; attempt += 1) {
        if (child.exitCode !== null) break
        try {
          const response = await fetch(url + '/health', { signal: AbortSignal.timeout(300) })
          if (response.ok) return
        } catch {
          // The production server has not bound the test port yet.
        }
        await delay(70)
      }
      throw new Error('Guardian startup failed.\n' + output)
    },
    async stop(signal: NodeJS.Signals = 'SIGTERM') {
      const child = processHandle
      if (child && child.exitCode === null && child.signalCode === null) {
        const exited = once(child, 'exit')
        child.kill(signal)
        await exited
      }
    },
    async dispose() {
      await this.stop()
      await rm(directory, { recursive: true, force: true })
    },
  }
}
