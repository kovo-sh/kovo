import { spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import type { Page } from '@playwright/test'

async function availablePort() {
  const server = createServer().listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Could not allocate a test port.')
  await new Promise<void>(resolve => server.close(() => resolve()))
  return address.port
}

export async function createApp(env: NodeJS.ProcessEnv = {}, existingDirectory?: string) {
  const directory = existingDirectory ?? await mkdtemp(join(tmpdir(), 'guardian-e2e-'))
  const port = await availablePort()
  const url = `http://127.0.0.1:${port}`
  let processHandle: ChildProcess | undefined
  let output = ''
  let bootstrapSecret = ''

  return {
    directory,
    url,
    async start() {
      output = ''
      bootstrapSecret = ''
      const child = spawn(process.execPath, ['scripts/serve.ts'], {
        cwd: process.cwd(),
        env: { ...process.env, GUARDIAN_OFFLINE: '1', GUARDIAN_PUBLIC_ORIGIN: '', ...env, PORT: String(port), GUARDIAN_DATA_DIR: directory },
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      processHandle = child
      child.stdout.on('data', chunk => { output += String(chunk) })
      child.stderr.on('data', chunk => { output += String(chunk) })
      for (let attempt = 0; attempt < 130; attempt += 1) {
        if (child.exitCode !== null) break
        try {
          const response = await fetch(url + '/health', { signal: AbortSignal.timeout(300) })
          if (response.ok) {
            // The server issues a single-use bootstrap secret for the local session; read it
            // before it is consumed so specs can open the app exactly as an operator would.
            for (let read = 0; read < 20 && !bootstrapSecret; read += 1) {
              try { bootstrapSecret = (await readFile(join(directory, 'bootstrap'), 'utf8')).trim() } catch { await delay(50) }
            }
            return
          }
        } catch {
          // The production server has not bound the test port yet.
        }
        await delay(70)
      }
      throw new Error('Guardian startup failed.\n' + output)
    },
    /** Open the app through the single-use local bootstrap (sets the session cookie). */
    async open(page: Page) {
      const secret = bootstrapSecret.trim()
      if (!secret) return page.goto(url)
      bootstrapSecret = ''
      return page.goto(`${url}/?bootstrap=${encodeURIComponent(secret)}`)
    },
    async stop(signal: NodeJS.Signals = 'SIGTERM') {
      const child = processHandle
      if (!child || child.exitCode !== null || child.signalCode !== null) return
      const exited = once(child, 'exit')
      child.kill(signal)
      const timedOut = await Promise.race([
        exited.then(() => false),
        delay(3_000).then(() => true),
      ])
      if (timedOut && child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL')
        await once(child, 'exit')
      }
    },
    async dispose() {
      await this.stop()
      if (!existingDirectory) await rm(directory, { recursive: true, force: true })
    },
  }
}
