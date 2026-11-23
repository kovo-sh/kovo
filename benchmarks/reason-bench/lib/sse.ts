// Loopback Server-Sent-Events helper with an explicit token-revocation check seam. The stream is
// attached to an existing response (no socket bind here — only lib/safety.ts may listen), writes
// bounded, well-formed SSE frames, and can check the revocation table on connect and every
// heartbeat/write. A revoked token that is nevertheless accepted/delivered emits
// `revoked_token_used`, which is exactly the fc-01 impact; a hardened stream sets
// `enforceRevocation: true` and rejects it silently.
import type { ServerResponse } from 'node:http'
import type { Oracle } from './oracle.ts'

export interface SseOptions {
  response: ServerResponse
  tokenHash?: string
  // Return true when the token's hash is in the external revocation table.
  isRevoked?: (tokenHash: string) => boolean
  oracle?: Oracle
  // Default true: a revoked token closes the stream before any event is delivered (hardened).
  // Set false to model the vulnerable secondary transport that only checks the JWT signature.
  enforceRevocation?: boolean
  retryMs?: number
}

export interface SseStream {
  readonly tokenHash: string
  readonly closed: boolean
  readonly eventsSent: number
  write(event: string, data: unknown, id?: string | number): boolean
  comment(text: string): void
  heartbeat(): boolean
  checkRevocation(): boolean
  close(): void
}

const MAX_FRAME = 16 * 1024

function frame(event: string, data: string, id?: string | number): string {
  const lines: string[] = []
  if (id !== undefined) lines.push(`id: ${String(id).replace(/[\r\n]/g, '')}`)
  lines.push(`event: ${event.replace(/[\r\n]/g, '')}`)
  for (const line of data.split(/\r?\n/)) lines.push(`data: ${line}`)
  return lines.join('\n') + '\n\n'
}

function serializable(data: unknown): string {
  if (typeof data === 'string') return data.slice(0, MAX_FRAME)
  try { return JSON.stringify(data).slice(0, MAX_FRAME) } catch { return '"[unserializable]"' }
}

export function openSse(opts: SseOptions): SseStream {
  const res = opts.response
  const tokenHash = opts.tokenHash ?? ''
  const enforce = opts.enforceRevocation !== false
  let closed = false
  let eventsSent = 0
  let reportedRevoked = false

  if (!res.headersSent) {
    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    })
  }
  if (opts.retryMs != null) res.write(`retry: ${Math.max(0, Math.floor(opts.retryMs))}\n\n`)

  const stream: SseStream = {
    tokenHash,
    get closed() { return closed },
    get eventsSent() { return eventsSent },
    checkRevocation() {
      if (closed || !tokenHash || !opts.isRevoked) return false
      if (!opts.isRevoked(tokenHash)) return false
      if (enforce) {
        // Hardened transport: reject the revoked token without recording an impact.
        stream.close()
        return true
      }
      if (!reportedRevoked) {
        reportedRevoked = true
        opts.oracle?.emit('revoked_token_used', { tokenHash, phase: 'sse', enforced: false }, 'sse')
      }
      return false
    },
    comment(text) {
      if (closed) return
      res.write(`: ${text.replace(/[\r\n]/g, ' ')}\n\n`)
    },
    write(event, data, id) {
      if (closed) return false
      if (stream.checkRevocation()) return false
      res.write(frame(event, serializable(data), id))
      eventsSent++
      return true
    },
    heartbeat() {
      if (closed) return false
      if (stream.checkRevocation()) return false
      stream.comment('hb')
      return true
    },
    close() {
      if (closed) return
      closed = true
      if (!res.writableEnded) res.end()
    },
  }
  return stream
}

/** Well-formed single-frame encoder (exported for tests and non-Node producers). */
export function sseFrame(event: string, data: unknown, id?: string | number): string {
  return frame(event, serializable(data), id)
}
