import { createHmac, randomBytes, randomUUID } from 'node:crypto'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import { once } from 'node:events'
import { and, eq } from 'drizzle-orm'
import { canaries } from './schema.ts'
import type { Store } from './store.ts'

export class CanaryBroker {
  private readonly secret = randomBytes(32)
  private server?: Server
  private baseUrl?: string

  async startLocalListener(): Promise<string> {
    if (this.baseUrl) return this.baseUrl
    const configured = process.env.GUARDIAN_CANARY_BASE_URL
    if (configured) {
      this.baseUrl = configured.replace(/\/+$/, '')
      return this.baseUrl
    }
    const server = createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      const match = /^\/c\/(guardian-canary-[a-f0-9]{24})$/.exec(url.pathname)
      if (match) {
        this.recordCallback(match[1], {
          method: req.method ?? 'GET',
          path: url.pathname,
          userAgent: String(req.headers['user-agent'] ?? '').slice(0, 120),
          receivedAt: new Date().toISOString(),
        })
      }
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end('guardian-canary-ok')
    })
    server.listen(0, '127.0.0.1')
    await once(server, 'listening')
    const addr = server.address()
    if (!addr || typeof addr === 'string') throw new Error('Could not bind local canary listener.')
    this.server = server
    this.baseUrl = `http://127.0.0.1:${addr.port}`
    return this.baseUrl
  }

  async stop() {
    if (!this.server) return
    this.server.closeAllConnections()
    await new Promise<void>(resolve => this.server!.close(() => resolve()))
    this.server = undefined
    this.baseUrl = undefined
  }

  private callbacks = new Map<string, Record<string, unknown>>()

  recordCallback(token: string, detail: Record<string, unknown>) {
    this.callbacks.set(token, detail)
  }

  mint(storage: Store, runId: string, assignmentId: string, purpose: string): { id: string; token: string; url: string | null } {
    const id = randomUUID()
    const digest = createHmac('sha256', this.secret).update(runId).update(id).update(randomBytes(8)).digest('hex').slice(0, 24)
    const token = `guardian-canary-${digest}`
    storage.db.insert(canaries).values({
      id, runId, assignmentId, token, purpose: purpose.slice(0, 200), triggered: false, createdAt: Date.now(),
    }).run()
    return { id, token, url: this.baseUrl ? `${this.baseUrl}/c/${token}` : null }
  }

  check(storage: Store, runId: string, token: string): { found: boolean; triggered: boolean; detail: Record<string, unknown> | null } {
    const row = storage.db.select().from(canaries).where(and(eq(canaries.runId, runId), eq(canaries.token, token))).get()
    if (!row) return { found: false, triggered: false, detail: null }
    const mem = this.callbacks.get(token)
    if (mem && !row.triggered) {
      storage.db.update(canaries).set({ triggered: true, triggerDetail: mem, triggeredAt: Date.now() })
        .where(eq(canaries.id, row.id)).run()
      return { found: true, triggered: true, detail: mem }
    }
    return { found: true, triggered: row.triggered, detail: row.triggerDetail ?? null }
  }
}
