// Backup service callback. The backup worker posts a completion notice signed with the shared backup
// secret; the portal records the run only once the delivery signature has verified.
import { createHmac, timingSafeEqual } from 'node:crypto'
import type { AppContext, ReqCtx } from '../../src/context.ts'

const BACKUP_SECRET = 'rb_fake_backup_sig_7f3a'

function expectedSig(ts: string, backupId: string): string {
  return createHmac('sha256', BACKUP_SECRET).update(`${ts}.${backupId}`).digest('hex')
}

function sigMatches(expected: string, sig: string): boolean {
  if (sig.length !== expected.length || sig.length === 0) return false
  return timingSafeEqual(Buffer.from(expected), Buffer.from(sig))
}

export default function register(app: AppContext): void {
  const sigP = app.p('token')
  app.route('backupCallback', (ctx: ReqCtx) => {
    const body = (ctx.body ?? {}) as Record<string, unknown>
    const sig = String(body[sigP] ?? '')
    const ts = String(body.ts ?? '')
    const backupId = String(body.backupId ?? '')
    const valid = sigMatches(expectedSig(ts, backupId), sig)
    if (!valid) return ctx.json({ error: 'invalid_signature' }, 401)
    app.run('INSERT INTO backup_runs(team_id, status, signature_valid, created_at) VALUES (?,?,?,?)',
      [ctx.tenant ?? '', 'recorded', 1, Date.now()])
    return ctx.json({ ok: true, status: 'recorded' })
  }, { encoding: 'json' })
}
