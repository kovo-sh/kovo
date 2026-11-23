// Webhook HMAC signing/verification used as a generic forgery sink. signWebhook() records every
// signature it produces; if verifyWebhook() ACCEPTS a (body, sig) pair whose signature was not issued
// by signWebhook() with the real secret (a forged, altered, or out-of-band-computed signature), a
// `webhook_forgery` impact event is recorded. Comparison is constant-time. Uses only node:crypto.
import { createHmac, timingSafeEqual } from 'node:crypto'
import type { Oracle } from './oracle.ts'

export interface VerifyWebhookOpts { toleranceSec?: number; oracle?: Oracle; nowMs?: number }

// Signatures legitimately produced by signWebhook().
const issued = new Set<string>()

export function signWebhook(secret: string, body: string, ts: number | string): string {
  const sig = createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex')
  issued.add(sig)
  return sig
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  const ab = Buffer.from(a, 'hex'); const bb = Buffer.from(b, 'hex')
  if (ab.length !== bb.length || ab.length === 0) return false
  return timingSafeEqual(ab, bb)
}

export function verifyWebhook(
  secret: string, body: string, ts: number | string, sig: string, opts: VerifyWebhookOpts = {},
): boolean {
  if (opts.toleranceSec !== undefined) {
    const now = opts.nowMs ?? Date.now()
    const skew = Math.abs(now / 1000 - Number(ts))
    if (!Number.isFinite(skew) || skew > opts.toleranceSec) return false
  }
  const expected = createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex')
  if (!constantTimeEqualHex(expected, sig)) return false
  // Accepted. If this signature never came out of signWebhook(), it is a forgery/replay-from-elsewhere.
  if (!issued.has(sig)) opts.oracle?.emit('webhook_forgery', {}, 'webhook')
  return true
}
