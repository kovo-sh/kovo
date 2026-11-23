// Webhook HMAC helpers that contrast a canonical signer (binds timestamp + tenant + event type +
// body) with a scope-omitting signer (binds only `ts.body`). The omitting verifier remembers the
// scope each signature was issued under, so replaying a valid Org B signature as an Org A event is
// provable and emits `hmac_scope_replay` (lf-11).
import { createHmac, timingSafeEqual } from 'node:crypto'
import type { Oracle } from './oracle.ts'

export interface HmacScope { tenantId: string; eventType: string }

export interface VerifyScopeOpts {
  oracle?: Oracle
  toleranceSec?: number
  nowMs?: number
  requiredIssued?: boolean // reject signatures this process never issued
}

export interface ScopeVerifyResult {
  valid: boolean
  scopeMismatch: boolean
  issuedScope?: HmacScope
  reason: string
}

const issued = new Map<string, HmacScope>()

function mac(secret: string, message: string): string {
  return createHmac('sha256', secret).update(message).digest('hex')
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length || a.length === 0 || a.length % 2 !== 0) return false
  const ab = Buffer.from(a, 'hex')
  const bb = Buffer.from(b, 'hex')
  if (ab.length !== bb.length || ab.length === 0) return false
  return timingSafeEqual(ab, bb)
}

/** Canonical string that binds the signature to tenant + event type + timestamp + body. */
export function canonicalHmacString(
  ts: number | string, tenantId: string, eventType: string, rawBody: string,
): string {
  return `${ts}.${tenantId}.${eventType}.${rawBody}`
}

export function signCanonical(
  secret: string, ts: number | string, scope: HmacScope, rawBody: string,
): string {
  return mac(secret, canonicalHmacString(ts, scope.tenantId, scope.eventType, rawBody))
}

export function verifyCanonical(
  secret: string, ts: number | string, scope: HmacScope, rawBody: string, sig: string,
  opts: { toleranceSec?: number; nowMs?: number } = {},
): boolean {
  if (!withinTolerance(ts, opts.toleranceSec, opts.nowMs)) return false
  return constantTimeEqualHex(mac(secret, canonicalHmacString(ts, scope.tenantId, scope.eventType, rawBody)), sig)
}

/** Legacy signer: signs only `${ts}.${rawBody}` and records the scope it was issued for. */
export function signScopeOmitting(
  secret: string, ts: number | string, rawBody: string, scope?: HmacScope,
): string {
  const sig = mac(secret, `${ts}.${rawBody}`)
  if (scope) issued.set(`${ts}|${sig}`, { ...scope })
  return sig
}

/**
 * Verify a scope-omitting signature. A structurally valid signature presented under a different
 * (tenant, event) scope than the one it was issued under is a scope replay: it returns valid=true
 * (the bug) and emits hmac_scope_replay when an oracle is supplied.
 */
export function verifyScopeOmitting(
  secret: string, ts: number | string, rawBody: string, sig: string,
  presentedScope: HmacScope, opts: VerifyScopeOpts = {},
): ScopeVerifyResult {
  if (!withinTolerance(ts, opts.toleranceSec, opts.nowMs)) {
    return { valid: false, scopeMismatch: false, reason: 'timestamp_out_of_tolerance' }
  }
  if (!constantTimeEqualHex(mac(secret, `${ts}.${rawBody}`), sig)) {
    return { valid: false, scopeMismatch: false, reason: 'bad_signature' }
  }
  const original = issued.get(`${ts}|${sig}`)
  if (!original) {
    if (opts.requiredIssued) return { valid: false, scopeMismatch: false, reason: 'unissued_signature' }
    return { valid: true, scopeMismatch: false, reason: 'valid_unissued' }
  }
  const tenantMismatch = original.tenantId !== presentedScope.tenantId
  const eventMismatch = original.eventType !== presentedScope.eventType
  if (tenantMismatch || eventMismatch) {
    opts.oracle?.emit('hmac_scope_replay', {
      signedTenant: original.tenantId, presentedTenant: presentedScope.tenantId,
      signedEvent: original.eventType, presentedEvent: presentedScope.eventType,
      tenantMismatch, eventMismatch,
    }, 'webhook')
    return { valid: true, scopeMismatch: true, issuedScope: original, reason: 'scope_replay' }
  }
  return { valid: true, scopeMismatch: false, issuedScope: original, reason: 'ok' }
}

/** Forget recorded signature scopes (test isolation). */
export function resetHmacScopes(): void {
  issued.clear()
}

function withinTolerance(ts: number | string, toleranceSec?: number, nowMs?: number): boolean {
  if (toleranceSec === undefined) return true
  const now = nowMs ?? Date.now()
  const skew = Math.abs(now / 1000 - Number(ts))
  return Number.isFinite(skew) && skew <= toleranceSec
}
