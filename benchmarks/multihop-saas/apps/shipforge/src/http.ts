// Minimal HTTP helpers for the lab services (no framework, no dependency).
import type { IncomingMessage, ServerResponse } from 'node:http'

const MAX_BODY = 96 * 1024

export async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    size += buf.length
    if (size > MAX_BODY) throw new Error('request body too large')
    chunks.push(buf)
  }
  return Buffer.concat(chunks).toString('utf8')
}

export function parseJson<T>(raw: string): T | null {
  if (!raw) return null
  try {
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

export function sendJson(
  res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {},
): void {
  const text = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(text)),
    ...headers,
  })
  res.end(text)
}

export function sendText(
  res: ServerResponse, status: number, body: string, headers: Record<string, string> = {},
): void {
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': String(Buffer.byteLength(body)),
    ...headers,
  })
  res.end(body)
}

/** Bounded event-stream response: a finite sequence of `data:` frames, then end of stream. */
export function sendEventStream(res: ServerResponse, frames: unknown[]): void {
  const body = frames.map((frame) => `data: ${JSON.stringify(frame)}\n\n`).join('') +
    'event: close\ndata: {}\n\n'
  res.writeHead(200, {
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': String(Buffer.byteLength(body)),
  })
  res.end(body)
}

export function header(req: IncomingMessage, name: string): string {
  const value = req.headers[name.toLowerCase()]
  if (Array.isArray(value)) return value[0] ?? ''
  return value ?? ''
}

export function bearer(req: IncomingMessage): string {
  const raw = header(req, 'authorization')
  return raw.startsWith('Bearer ') ? raw.slice(7).trim() : ''
}

export function runIdOf(req: IncomingMessage, fallback: string): string {
  return header(req, 'x-kovo-run-id') || fallback
}

export interface Match {
  params: string[]
  pathname: string
  search: URLSearchParams
}

export function parseUrl(req: IncomingMessage): Match {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  return { params: [], pathname: url.pathname, search: url.searchParams }
}

/** Match `/v1/projects/:id` style patterns. Returns positional params or null. */
export function match(matchInfo: Match, reqMethod: string, pattern: string): string[] | null {
  const want = pattern.split('/').filter(Boolean)
  const got = matchInfo.pathname.split('/').filter(Boolean)
  if (want.length !== got.length) return null
  const params: string[] = []
  for (let i = 0; i < want.length; i++) {
    const w = want[i]!
    const g = got[i]!
    if (w.startsWith(':')) params.push(decodeURIComponent(g))
    else if (w !== g) return null
  }
  return params
}
