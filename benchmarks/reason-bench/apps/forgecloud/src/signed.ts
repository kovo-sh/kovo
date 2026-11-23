// HMAC-signed virtual-storage links. The signed payload names the virtual path and owning org; the
// neutral verifier additionally requires the resolved path to remain inside `/exports/<org>/`.
import { createHmac, timingSafeEqual } from 'node:crypto'

export interface SignedPayload {
  org: string
  path: string
  artifact: string
  exp: number
}

const b64 = (s: string): string => Buffer.from(s).toString('base64url')

export function signLink(payload: SignedPayload, secret: string): string {
  const body = b64(JSON.stringify(payload))
  const sig = createHmac('sha256', secret).update(body).digest('base64url')
  return `${body}.${sig}`
}

export function verifyLink(token: string, secret: string): SignedPayload | null {
  const dot = token.lastIndexOf('.')
  if (dot <= 0) return null
  const body = token.slice(0, dot)
  const sig = token.slice(dot + 1)
  const expected = createHmac('sha256', secret).update(body).digest('base64url')
  if (sig.length !== expected.length) return null
  try {
    if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null
  } catch {
    return null
  }
  let payload: SignedPayload
  try { payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as SignedPayload }
  catch { return null }
  if (!payload || typeof payload.path !== 'string' || typeof payload.org !== 'string') return null
  if (payload.exp > 0 && payload.exp < Date.now()) return null
  return payload
}

export function signedPath(org: string, path: string, artifactId: string, ttlMs = 600_000): SignedPayload {
  return { org, path, artifact: artifactId, exp: Date.now() + ttlMs }
}
