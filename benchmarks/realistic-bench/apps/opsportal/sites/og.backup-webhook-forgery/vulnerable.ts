// Backup service callback. The backup worker posts a completion notice signed with the shared backup
// secret; the portal records the run and notes whether the delivery signature matched.
import { createHmac } from 'node:crypto'
import type { AppContext, ReqCtx } from '../../src/context.ts'

const BACKUP_SECRET = 'rb_fake_backup_sig_7f3a'

function expectedSig(ts: string, backupId: string): string {
  return createHmac('sha256', BACKUP_SECRET).update(`${ts}.${backupId}`).digest('hex')
}

export default function register(app: AppContext): void {
  const sigP = app.p('token')
  app.route('backupCallback', (ctx: ReqCtx) => {
    const body = (ctx.body ?? {}) as Record<string, unknown>
    const sig = String(body[sigP] ?? '')
    const ts = String(body.ts ?? '')
    const backupId = String(body.backupId ?? '')
    const valid = sig.length > 0 && sig === expectedSig(ts, backupId)
    app.run('INSERT INTO backup_runs(team_id, status, signature_valid, created_at) VALUES (?,?,?,?)',
      [ctx.tenant ?? '', 'recorded', valid ? 1 : 0, Date.now()])
    return ctx.json({ ok: true, status: 'recorded' })
  }, { encoding: 'json' })
}
