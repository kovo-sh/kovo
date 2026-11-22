// Minimal JWT helper (HS256 + 'none') used as a generic token-forgery sink. Every token produced by
// sign() is remembered by its sha256 hash; if verify() ACCEPTS a token that was never issued here
// (e.g. an alg:none forgery or a tampered token that still validates), a `token_forgery` impact event
// is recorded. Uses only node:crypto.
import { createHmac, createHash, timingSafeEqual } from 'node:crypto'
import type { Oracle } from './oracle.ts'

export function base64urlEncode(data: string | Buffer): string {
  return Buffer.from(data).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
export function base64urlDecode(s: string): string {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
}

export interface JwtHeader { alg: string; typ?: string; kid?: string;[k: string]: unknown }
export interface SignOpts { alg?: 'HS256' | 'none'; kid?: string; header?: Record<string, unknown> }
export interface VerifyOpts {
  secret?: string
  keyResolver?: (header: JwtHeader) => string | undefined
  algorithms: string[]
  acceptNone?: boolean
  oracle?: Oracle
}
export interface VerifyResult { valid: boolean; payload?: unknown; header?: JwtHeader }

// Set of sha256 hashes of tokens legitimately produced by sign().
const issued = new Set<string>()
const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex')
const hmac = (input: string, secret: string): string => base64urlEncode(createHmac('sha256', secret).update(input).digest())

export function sign(payload: Record<string, unknown>, secret: string, opts: SignOpts = {}): string {
  const alg = opts.alg ?? 'HS256'
  const header: JwtHeader = { alg, typ: 'JWT', ...opts.header, ...(opts.kid ? { kid: opts.kid } : {}) }
  const signingInput = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}`
  const sig = alg === 'HS256' ? hmac(signingInput, secret) : ''
  const token = `${signingInput}.${sig}`
  issued.add(hashToken(token))
  return token
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a); const bb = Buffer.from(b)
  if (ab.length !== bb.length) return false
  return timingSafeEqual(ab, bb)
}

export function verify(token: string, opts: VerifyOpts): VerifyResult {
  const parts = token.split('.')
  if (parts.length !== 3) return { valid: false }
  let header: JwtHeader
  let payload: unknown
  try { header = JSON.parse(base64urlDecode(parts[0]!)) as JwtHeader; payload = JSON.parse(base64urlDecode(parts[1]!)) }
  catch { return { valid: false } }
  const alg = header.alg
  if (!opts.algorithms.includes(alg)) return { valid: false }

  let ok = false
  if (alg === 'none') {
    ok = opts.acceptNone === true && parts[2] === ''
  } else if (alg === 'HS256') {
    const secret = opts.keyResolver ? opts.keyResolver(header) : opts.secret
    if (secret == null) return { valid: false }
    ok = constantTimeEqual(hmac(`${parts[0]}.${parts[1]}`, secret), parts[2]!)
  }
  if (!ok) return { valid: false }

  if (!issued.has(hashToken(token))) opts.oracle?.emit('token_forgery', { alg }, 'jwt')
  return { valid: true, payload, header }
}
