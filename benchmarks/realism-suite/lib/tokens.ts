// Token helpers: HS256 JWTs for app sessions and RS256 JWTs for the synthetic OIDC IdP.
import {
  createHmac,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject,
} from 'node:crypto'

export interface JwtParts {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
  signedPart: string
}

export function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

export function fromB64url(input: string): Buffer {
  return Buffer.from(input, 'base64url')
}

export function randomSecret(prefix = 'rbs_fake_'): string {
  return `${prefix}${randomBytes(24).toString('hex')}`
}

export function hmacHex(secret: string, data: string): string {
  return createHmac('sha256', secret).update(data).digest('hex')
}

export function hmacEquals(secret: string, data: string, expectedHex: string): boolean {
  const actual = Buffer.from(hmacHex(secret, data), 'hex')
  let want: Buffer
  try {
    want = Buffer.from(expectedHex, 'hex')
  } catch {
    return false
  }
  return actual.length === want.length && timingSafeEqual(actual, want)
}

export function signJwt(claims: Record<string, unknown>, secret: string, kid = 'hs-1'): string {
  const header = { alg: 'HS256', typ: 'JWT', kid }
  const signedPart = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`
  return `${signedPart}.${createHmac('sha256', secret).update(signedPart).digest('base64url')}`
}

/** Parse without verifying. Never call on untrusted input outside a fixture's intentionally weak path. */
export function decodeJwt(token: string): JwtParts | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const header = JSON.parse(fromB64url(parts[0]).toString('utf8')) as Record<string, unknown>
    const payload = JSON.parse(fromB64url(parts[1]).toString('utf8')) as Record<string, unknown>
    return { header, payload, signature: parts[2], signedPart: `${parts[0]}.${parts[1]}` }
  } catch {
    return null
  }
}

export function verifyJwt(token: string, secret: string): Record<string, unknown> | null {
  const parts = decodeJwt(token)
  if (!parts || parts.header.alg !== 'HS256') return null
  const expected = createHmac('sha256', secret).update(parts.signedPart).digest()
  const actual = fromB64url(parts.signature)
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return null
  return parts.payload
}

export interface OidcKeys {
  privateKey: KeyObject
  publicKey: KeyObject
  kid: string
  jwk: Record<string, unknown>
}

export function createOidcKeys(): OidcKeys {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const kid = 'realism-fake-kid-1'
  const jwk = { ...(publicKey.export({ format: 'jwk' }) as Record<string, unknown>), kid, use: 'sig', alg: 'RS256' }
  return { privateKey, publicKey, kid, jwk }
}

export function signRs256(claims: Record<string, unknown>, keys: OidcKeys): string {
  const header = { alg: 'RS256', typ: 'JWT', kid: keys.kid }
  const signedPart = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`
  const signature = sign('RSA-SHA256', Buffer.from(signedPart), keys.privateKey).toString('base64url')
  return `${signedPart}.${signature}`
}

export function verifyRs256(token: string, keys: OidcKeys): Record<string, unknown> | null {
  const parts = decodeJwt(token)
  if (!parts || parts.header.alg !== 'RS256') return null
  const ok = verify('RSA-SHA256', Buffer.from(parts.signedPart), keys.publicKey, fromB64url(parts.signature))
  return ok ? parts.payload : null
}

/** Rebuild a public key object from a JWK (used by the IdP's /jwks self-check). */
export function publicKeyFromJwk(jwk: Record<string, unknown>): KeyObject {
  return createPublicKey({ key: jwk as JsonWebKey, format: 'jwk' })
}
