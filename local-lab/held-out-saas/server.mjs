// Held-Out Modern SaaS Lab ("Orbit Workspace") entrypoint.
//
//   node server.mjs                      -> listens on HOST:PORT (Docker: 0.0.0.0:3000 under GUARDIAN_LAB=1)
//   import { startHeldOutSaasServer }    -> in-process loopback server for benchmark-recall (127.0.0.1:0)
//
// Pure Node.js stdlib (node:http, node:crypto, node:sqlite). No npm install, no network, no disk writes.
import { createServer } from 'node:http'
import { pathToFileURL } from 'node:url'
import { createApp, PATCH_IDS } from './src/app.mjs'
import { manifest } from './src/markers.mjs'

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1'])

export function loadHeldOutSaasManifest() {
  return manifest
}

export const heldOutSaasPatchIds = [...PATCH_IDS]

/**
 * @param {{ host?: string, port?: number, patchedIds?: string[] }} [opts]
 */
export async function startHeldOutSaasServer(opts = {}) {
  const host = opts.host ?? '127.0.0.1'
  if (!LOOPBACK.has(host) && process.env.GUARDIAN_LAB !== '1') {
    throw new Error(`Held-out SaaS lab refuses to bind ${host}: only loopback is allowed outside a Guardian lab container.`)
  }
  for (const id of opts.patchedIds ?? []) {
    if (!PATCH_IDS.includes(id)) throw new Error(`Unknown held-out SaaS patch id "${id}".`)
  }

  const app = createApp({ patchedIds: opts.patchedIds ?? [] })
  const server = createServer((req, res) => {
    app.handle(req, res).catch(() => {
      try { res.writeHead(500).end() } catch { /* socket already closed */ }
    })
  })
  server.keepAliveTimeout = 2000
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(opts.port ?? 0, host, resolve)
  })
  const addr = server.address()
  const port = typeof addr === 'object' && addr ? addr.port : Number(opts.port ?? 0)
  const origin = `http://${host === '0.0.0.0' ? '127.0.0.1' : (host === '::1' ? '[::1]' : host)}:${port}`

  return {
    origin,
    port,
    host,
    personas: app.personas(),
    /** Rebuild all in-memory state (DB, stores, caches). Patch toggles are preserved. */
    resetState() {
      app.ctx.reset()
    },
    /** Hot-swap the applied patch set (empty array == fully vulnerable build). */
    setPatchedIds(ids) {
      for (const id of ids) {
        if (!PATCH_IDS.includes(id)) throw new Error(`Unknown held-out SaaS patch id "${id}".`)
      }
      app.ctx.patched = new Set(ids)
      app.ctx.reset()
    },
    getPatchedIds() {
      return [...app.ctx.patched]
    },
    async close() {
      server.closeAllConnections?.()
      await new Promise(resolve => server.close(() => resolve()))
      try { app.ctx.s.db.close() } catch { /* already closed */ }
    },
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const host = process.env.HOST ?? '127.0.0.1'
  const port = Number(process.env.PORT ?? 3000)
  const lab = await startHeldOutSaasServer({ host, port })
  process.stderr.write(`[held-out-saas] listening on ${host}:${lab.port}\n`)
  const stop = () => lab.close().finally(() => process.exit(0))
  process.on('SIGTERM', stop)
  process.on('SIGINT', stop)
}
