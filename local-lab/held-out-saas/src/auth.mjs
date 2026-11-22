// JWT handling. `verifyStrict` is the hardened verifier; `verifyLenient` / `verifyJku` model the planted flaws.
import { createHmac, generateKeyPairSync, timingSafeEqual } from 'node:crypto'
import { JWT_FAR_FUTURE_EXP, JWT_ISSUER, JWT_SECRET } from './config.mjs'
import { fetchLoopback, parseCookies } from './http-util.mjs'

export function decodeSegment(segment) {
  try {
    return JSON.parse(Buffer.from(String(segment), 'base64url').toString('utf8'))
  } catch {
    return null
  }
}

const encode = obj => Buffer.from(JSON.stringify(obj)).toString('base64url')
const mac = (input, secret) => createHmac('sha256', secret).update(input).digest('base64url')

function safeEqual(a, b) {
  const x = Buffer.from(String(a))
  const y = Buffer.from(String(b))
  return x.length === y.length && timingSafeEqual(x, y)
}

export function signHs256(payload, header = { alg: 'HS256', typ: 'JWT', kid: 'orbit-1' }, secret = JWT_SECRET) {
  const input = `${encode(header)}.${encode(payload)}`
  return `${input}.${mac(input, secret)}`
}

export function personaToken(user) {
  return signHs256({
    sub: user.id,
    tenant: user.tenantId,
    role: user.role,
    email: user.email,
    iss: JWT_ISSUER,
    iat: 1_700_000_000,
    exp: JWT_FAR_FUTURE_EXP,
  })
}

function toPrincipal(payload) {
  if (!payload || typeof payload !== 'object' || typeof payload.sub !== 'string') return null
  if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) return null
  return {
    sub: payload.sub,
    userId: payload.sub,
    tenant: String(payload.tenant ?? ''),
    role: String(payload.role ?? 'viewer'),
    email: payload.email ?? null,
  }
}

export function tokenFromRequest(req) {
  const auth = String(req.headers.authorization ?? '')
  const m = /^Bearer\s+(\S+)$/i.exec(auth)
  if (m) return m[1]
  return parseCookies(req.headers.cookie ?? '').hos_session ?? ''
}

/** Hardened verifier: exact alg === HS256, mandatory signature, issuer + expiry enforced. */
export function verifyStrict(token) {
  const parts = String(token ?? '').split('.')
  if (parts.length !== 3 || !parts[2]) return null
  const header = decodeSegment(parts[0])
  const payload = decodeSegment(parts[1])
  if (!header || !payload || header.alg !== 'HS256') return null
  if (!safeEqual(parts[2], mac(`${parts[0]}.${parts[1]}`, JWT_SECRET))) return null
  if (payload.iss !== JWT_ISSUER) return null
  return toPrincipal(payload)
}

/** PLANTED FLAW (hos-11): accepts `alg: none` and empty-signature tokens. */
export function verifyLenient(token) {
  const parts = String(token ?? '').split('.')
  if (parts.length < 2) return null
  const header = decodeSegment(parts[0])
  const payload = decodeSegment(parts[1])
  if (!header || !payload) return null
  if (String(header.alg ?? '').toLowerCase() === 'none' || !parts[2]) return toPrincipal(payload)
  return verifyStrict(token)
}

/**
 * PLANTED FLAW (hos-12): honours the attacker-controlled `jku` header — the key set is fetched from the URL
 * inside the token (lab egress policy: loopback only) and an `oct` key found there is trusted.
 */
export async function verifyJku(token) {
  const parts = String(token ?? '').split('.')
  if (parts.length !== 3) return null
  const header = decodeSegment(parts[0])
  const payload = decodeSegment(parts[1])
  if (!header || !payload) return null
  if (typeof header.jku !== 'string' || !header.jku) return verifyStrict(token)
  const fetched = await fetchLoopback(header.jku, { timeoutMs: 1500, maxBytes: 8192 })
  if (!fetched.ok) return null
  let keys = []
  try {
    keys = JSON.parse(fetched.body).keys ?? []
  } catch {
    return null
  }
  const oct = keys.find(k => k?.kty === 'oct' && typeof k.k === 'string')
  if (!oct) return null
  const secret = Buffer.from(oct.k, 'base64url')
  if (!safeEqual(parts[2], mac(`${parts[0]}.${parts[1]}`, secret))) return null
  return toPrincipal(payload)
}

// Public JWKS (RSA, for OIDC discovery realism). The RSA key is never used to verify anything.
let jwksCache = null
export function publicJwks() {
  if (!jwksCache) {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const jwk = publicKey.export({ format: 'jwk' })
    jwksCache = { keys: [{ ...jwk, kid: 'orbit-rsa-1', use: 'sig', alg: 'RS256' }] }
  }
  return jwksCache
}
