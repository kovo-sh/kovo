// XBEN-25 dev benchmark server: 25 simulated challenges on an ephemeral loopback port.
// Safety: binds to loopback only, never spawns processes, never reads host files, and only ever issues
// loopback http fetches (SSRF / XXE / jku / curl simulation) via safeLoopbackFetch.
import { readFileSync } from 'node:fs'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import type { AddressInfo, Socket } from 'node:net'
import { randomBytes } from 'node:crypto'
import { authenticate, createPersonas, freshState, isLoopbackHost, readBody, sendJson } from './core.ts'
import type { Ctx, PersonaInfo, ServerState } from './core.ts'
import { handleSqli } from './routes-sqli.ts'
import { handleAuthz } from './routes-authz.ts'
import { handleGraphql } from './routes-graphql.ts'
import { handleInject } from './routes-inject.ts'
import { handleWeb } from './routes-web.ts'

export interface Xben25Challenge {
  id: string
  name: string
  vulnClass: string
  cwe: string
  endpoint: string
  method: 'GET' | 'POST' | 'PUT' | 'PATCH'
  param?: string
  encoding: string
  flagMarker: string
  expectedReplayKind: string
  tierRequired: 1 | 2 | 3
  requiresAuth: boolean
  requiresCsrf: boolean
  requiresBrowser: boolean
  requiresV4Feature: string
  v3BaselineDetectable: boolean
  discoverableVia: string[]
  [extra: string]: unknown
}

export interface Xben25Manifest {
  suite: string
  version: number
  challenges: Xben25Challenge[]
  [extra: string]: unknown
}

export interface Xben25ServerHandle {
  origin: string
  port: number
  personas: Record<string, PersonaInfo>
  /** challenge id -> flag marker (only ever emitted in exploited responses). */
  markers: Record<string, string>
  resetState: () => void
  close: () => Promise<void>
}

export function loadXben25Manifest(): Xben25Manifest {
  const raw = readFileSync(new URL('./manifest.json', import.meta.url), 'utf8')
  return JSON.parse(raw) as Xben25Manifest
}

const handlers = [handleWeb, handleGraphql, handleSqli, handleAuthz, handleInject]

export async function startXben25Server(opts: { host?: string; port?: number } = {}): Promise<Xben25ServerHandle> {
  const host = opts.host ?? '127.0.0.1'
  if (!isLoopbackHost(host)) throw new Error(`XBEN-25 server refuses to bind to non-loopback host: ${host}`)
  const manifest = loadXben25Manifest()
  const markers: Record<string, string> = {}
  for (const c of manifest.challenges) markers[c.id] = c.flagMarker
  const jwtSecret = randomBytes(32).toString('hex')
  const personas = createPersonas(jwtSecret)
  let state: ServerState = freshState()
  let origin = ''
  const sockets = new Set<Socket>()

  const server: Server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://xben25.local')
      const body = req.method === 'GET' || req.method === 'HEAD' ? '' : await readBody(req)
      const ctx: Ctx = {
        req, res, url, method: (req.method ?? 'GET').toUpperCase(), path: url.pathname, body, headers: req.headers,
        markers, state, auth: authenticate(req.headers, jwtSecret), jwtSecret, origin,
      }
      for (const handler of handlers) {
        if (await handler(ctx)) return
      }
      sendJson(ctx, 404, { error: 'not found' })
    } catch {
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'internal error' }))
    }
  })
  server.on('connection', socket => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
  })
  server.listen(opts.port ?? 0, host)
  await once(server, 'listening')
  const port = (server.address() as AddressInfo).port
  const displayHost = host === '::1' ? '[::1]' : host
  origin = `http://${displayHost}:${port}`

  return {
    origin,
    port,
    personas,
    markers,
    resetState: () => { state = freshState() },
    close: async () => {
      for (const s of sockets) s.destroy()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}
