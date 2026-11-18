import { randomBytes, timingSafeEqual } from 'node:crypto'
import { createReadStream, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { join, resolve } from 'node:path'
import { Readable, Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'

const directory = resolve(process.env.GUARDIAN_DATA_DIR ?? '.guardian')
const port = Number(process.env.PORT ?? 8000)
const clientRoot = resolve('build/client')
const serverEntry = new URL('../build/server/server.js', import.meta.url).href
const { default: app, initialize } = await import(serverEntry) as {
  default: { fetch(request: Request): Promise<Response> | Response }
  initialize: () => void
}

const origins = new Map([
  [`127.0.0.1:${port}`, `http://127.0.0.1:${port}`],
  [`localhost:${port}`, `http://localhost:${port}`],
])
// A deliberately configured local reverse proxy can present one additional origin.
if (process.env.GUARDIAN_PUBLIC_ORIGIN) {
  const proxy = new URL(process.env.GUARDIAN_PUBLIC_ORIGIN)
  if (proxy.protocol !== 'https:' || proxy.origin !== process.env.GUARDIAN_PUBLIC_ORIGIN) {
    throw new Error('GUARDIAN_PUBLIC_ORIGIN must be a single HTTPS origin.')
  }
  origins.set(proxy.host, proxy.origin)
}

function sessionToken() {
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  const file = join(directory, 'local-session')
  try {
    writeFileSync(file, randomBytes(32).toString('hex'), { flag: 'wx', mode: 0o600 })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
  if ((statSync(file).mode & 0o077) !== 0) throw new Error('The local session file must have owner-only permissions.')
  const value = readFileSync(file, 'utf8')
  if (!/^[a-f0-9]{64}$/.test(value)) throw new Error('Invalid local session file.')
  return value
}

const token = sessionToken()
const maxBody = 1024 * 1024

function authorized(req: IncomingMessage): boolean {
  const cookies = req.headers.cookie?.split(';').map(cookie => cookie.trim()) ?? []
  const value = cookies.find(cookie => cookie.startsWith('guardian_local='))?.slice('guardian_local='.length)
  return value?.length === token.length && /^[0-9a-f]+$/.test(value)
    && timingSafeEqual(Buffer.from(value), Buffer.from(token))
}

function reject(res: ServerResponse, status: number, message: string) {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8' }).end(message)
}

const mime: Record<string, string> = {
  js: 'text/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8',
  woff2: 'font/woff2',
  svg: 'image/svg+xml',
  png: 'image/png',
}

initialize()

async function serve(req: IncomingMessage, res: ServerResponse) {
  const origin = origins.get(req.headers.host ?? '')
  const method = req.method ?? 'GET'
  const readOnly = method === 'GET' || method === 'HEAD'
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Cache-Control', 'no-store')
  if (!origin) return reject(res, 421, 'Unexpected host.')
  const path = new URL(req.url ?? '/', origin)
  if (path.origin !== origin) return reject(res, 421, 'Unexpected request URL.')
  if (!readOnly && req.headers.origin !== origin) return reject(res, 403, 'Unexpected origin.')
  if (readOnly && path.pathname === '/health') return reject(res, 200, 'ok')

  if (readOnly && /^\/assets\/[A-Za-z0-9._-]+\.(?:js|css|woff2|svg|png)$/.test(path.pathname)) {
    const file = join(clientRoot, 'assets', path.pathname.split('/').at(-1)!)
    let size: number
    try {
      size = statSync(file).size
    } catch {
      return reject(res, 404, 'Asset not found.')
    }
    const extension = file.split('.').at(-1)!
    res.writeHead(200, {
      'Content-Type': mime[extension], 'Content-Length': size, 'Cache-Control': 'public, max-age=31536000, immutable',
    })
    if (method === 'HEAD') return res.end()
    await pipeline(createReadStream(file), res)
    return
  }

  const api = path.pathname.startsWith('/_serverFn/') || path.pathname.startsWith('/api/')
  const session = authorized(req)
  if ((api || !readOnly) && !session) return reject(res, 401, 'Open Guardian to start a local session.')
  if (req.headers['sec-fetch-site'] === 'cross-site') return reject(res, 403, 'Open Guardian directly.')
  if (Number(req.headers['content-length'] ?? 0) > maxBody) return reject(res, 413, 'Request body is too large.')

  const headers = new Headers()
  for (const [name, value] of Object.entries(req.headers)) {
    if (value !== undefined && !name.startsWith('x-forwarded-') && name !== 'forwarded') {
      for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item)
    }
  }

  const abort = new AbortController()
  res.once('close', () => abort.abort())
  let received = 0
  const limiter = new Transform({
    transform(chunk, _encoding, done) {
      received += chunk.length
      if (received > maxBody) done(new Error('Request body is too large.'))
      else done(null, chunk)
    },
  })
  if (!readOnly) req.pipe(limiter)
  const body = readOnly ? undefined : Readable.toWeb(limiter) as ReadableStream<Uint8Array>
  const request = new Request(path, {
    method, headers, body, signal: abort.signal, ...(body ? { duplex: 'half' } : {}),
  } as RequestInit)
  const response = await app.fetch(request)
  for (const [name, value] of response.headers) {
    if (name !== 'set-cookie') res.setHeader(name, value)
  }
  const cookies = response.headers.getSetCookie()
  if (!session && !api && /^text\/html\b/i.test(response.headers.get('content-type') ?? '')) {
    cookies.push(`guardian_local=${token}; Path=/; HttpOnly; SameSite=Strict${origin.startsWith('https:') ? '; Secure' : ''}`)
  }
  if (cookies.length) res.setHeader('set-cookie', cookies)
  res.writeHead(response.status)
  if (!response.body || method === 'HEAD') return res.end()
  await pipeline(Readable.fromWeb(response.body as import('node:stream/web').ReadableStream), res)
}

const server = createServer((req, res) => {
  void serve(req, res).catch(() => {
    if (res.destroyed) return
    if (!res.headersSent) reject(res, 500, 'Guardian could not complete the request.')
    else res.end()
  })
})
server.listen(port, '127.0.0.1', () => console.log(`Guardian listening on http://127.0.0.1:${port}`))
