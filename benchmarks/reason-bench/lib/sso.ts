// Simulated multi-tenant OIDC identity provider + assertion verifier. Tokens are HMAC-SHA256
// assertions (zero deps). The verifier exposes the exact seam behind lf-09 / fc-08: `enforceTid`
// controls whether the assertion's `tid` must equal the target tenant, and `matchPendingEmail`
// controls whether an unverified profile email may satisfy the login. Both violations emit
// `sso_tenant_confusion`; hardened callers enforce `tid` and match only the verified email.
import { createHmac, timingSafeEqual } from 'node:crypto'
import type { Oracle } from './oracle.ts'
import { base64urlDecode, base64urlEncode } from './jwt.ts'

export interface IdpUser {
  sub: string
  email: string
  tid: string
  name?: string
}

export interface OidcAssertion {
  iss: string
  sub: string
  email: string
  tid?: string
  iat: number
  exp: number
  nonce?: string
}

export interface OidcIdp {
  readonly issuer: string
  issue(user: IdpUser, opts?: { nowMs?: number; ttlSec?: number; omitTid?: boolean; nonce?: string }): string
}

export interface VerifyOidcOpts {
  issuer: string
  secret: string
  expectedTid: string
  // Default true. Set false to model a verifier that checks signature + email but omits `tid`.
  enforceTid?: boolean
  verifiedEmail?: string
  pendingEmail?: string
  // Default false. Set true to model matching an unverified pendingEmail as well.
  matchPendingEmail?: boolean
  nowMs?: number
  oracle?: Oracle
}

export interface OidcVerifyResult {
  valid: boolean
  assertion?: OidcAssertion
  tenantMismatch: boolean
  pendingEmailMatch: boolean
  reason: string
}

const HEADER = base64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'reason-idp' }))

function sign(secret: string, input: string): string {
  return base64urlEncode(createHmac('sha256', secret).update(input).digest())
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ab.length !== bb.length || ab.length === 0) return false
  return timingSafeEqual(ab, bb)
}

export function createIdp(opts: { issuer: string; secret: string }): OidcIdp {
  if (!opts.issuer || !opts.secret) throw new Error('createIdp: issuer and secret are required')
  return {
    issuer: opts.issuer,
    issue(user, issueOpts = {}) {
      const now = issueOpts.nowMs ?? Date.now()
      const iat = Math.floor(now / 1000)
      const payload: OidcAssertion = {
        iss: opts.issuer,
        sub: user.sub,
        email: user.email,
        iat,
        exp: iat + (issueOpts.ttlSec ?? 600),
      }
      if (!issueOpts.omitTid) payload.tid = user.tid
      if (issueOpts.nonce) payload.nonce = issueOpts.nonce
      const body = base64urlEncode(JSON.stringify(payload))
      return `${HEADER}.${body}.${sign(opts.secret, `${HEADER}.${body}`)}`
    },
  }
}

export function decodeAssertion(token: string): OidcAssertion | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const payload = JSON.parse(base64urlDecode(parts[1]!)) as OidcAssertion
    if (typeof payload.iss !== 'string' || typeof payload.sub !== 'string') return null
    return payload
  } catch {
    return null
  }
}

/**
 * Verify an assertion. Returns valid=true only for a correctly signed, unexpired assertion from the
 * expected issuer whose email matches. Tenant/email-binding defects are reported even when the
 * caller's policy is lax, so the oracle can attribute a real cross-tenant login.
 */
export function verifyOidcAssertion(token: string, opts: VerifyOidcOpts): OidcVerifyResult {
  const parts = token.split('.')
  if (parts.length !== 3) return { valid: false, tenantMismatch: false, pendingEmailMatch: false, reason: 'malformed' }
  if (!safeEqual(sign(opts.secret, `${parts[0]}.${parts[1]}`), parts[2]!)) {
    return { valid: false, tenantMismatch: false, pendingEmailMatch: false, reason: 'bad_signature' }
  }
  const assertion = decodeAssertion(token)
  if (!assertion) return { valid: false, tenantMismatch: false, pendingEmailMatch: false, reason: 'malformed_payload' }
  if (assertion.iss !== opts.issuer) {
    return { valid: false, assertion, tenantMismatch: false, pendingEmailMatch: false, reason: 'issuer_mismatch' }
  }
  const nowSec = Math.floor((opts.nowMs ?? Date.now()) / 1000)
  if (typeof assertion.exp !== 'number' || assertion.exp < nowSec) {
    return { valid: false, assertion, tenantMismatch: false, pendingEmailMatch: false, reason: 'expired' }
  }

  const enforceTid = opts.enforceTid !== false
  const tenantMismatch = assertion.tid !== opts.expectedTid
  const pendingEmailMatch = !!opts.matchPendingEmail && !!opts.pendingEmail && assertion.email === opts.pendingEmail

  if (enforceTid && tenantMismatch) {
    return { valid: false, assertion, tenantMismatch, pendingEmailMatch, reason: 'tenant_mismatch' }
  }
  if (tenantMismatch) {
    opts.oracle?.emit('sso_tenant_confusion', {
      reason: 'tenant_mismatch', assertionTid: assertion.tid ?? 'omitted', expectedTid: opts.expectedTid,
    }, 'sso')
  }
  if (pendingEmailMatch) {
    opts.oracle?.emit('sso_tenant_confusion', {
      reason: 'pending_email_trusted', pendingEmail: opts.pendingEmail ?? '',
      verifiedEmail: opts.verifiedEmail ?? '',
    }, 'sso')
  }

  const email = assertion.email
  const verifiedOk = !opts.verifiedEmail || email === opts.verifiedEmail
  if (!verifiedOk && !pendingEmailMatch) {
    return { valid: false, assertion, tenantMismatch, pendingEmailMatch, reason: 'email_mismatch' }
  }
  return {
    valid: true, assertion, tenantMismatch, pendingEmailMatch,
    reason: tenantMismatch || pendingEmailMatch ? 'accepted_with_confusion' : 'ok',
  }
}
