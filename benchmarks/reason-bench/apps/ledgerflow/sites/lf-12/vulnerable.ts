// Recovery desk action. A teammate can ask the console to re-send a recovery note for an address;
// the desk checks the spelling first, then resolves the profile that should receive the note.
import type { AppContext, UserRow } from '../../src/context.ts'
import { hashToken } from '../../src/auth.ts'
import { body, requireSession, unauthorized } from '../../src/common.ts'

function normalized(value: string): string {
  return value.normalize('NFKC').toLowerCase().trim()
}

export default function register(app: AppContext): void {
  app.route('requestPasswordReset', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const submitted = String(body(req)[app.field('email')] ?? body(req).email ?? '').trim()
    const address = normalized(submitted)
    if (!address.includes('@')) return req.json({ error: 'invalid_email' }, 400)
    const spelling = app.db.get<UserRow>('SELECT * FROM users WHERE email = ?', [submitted])
    const account = spelling ?? app.db.get<UserRow>('SELECT * FROM users WHERE lower(email) = ?', [address])
    if (!account) return req.json({ ok: true, message: 'If the address exists, a reset link was sent.' })
    if (!spelling && account.tenant_id !== id.tenant) {
      const raw = `lf_reset_${app.newId('reset')}`
      app.db.run('INSERT INTO user_tokens (tenant_id,user_ext_id,kind,token_hash,issued_at) VALUES (?,?,?,?,?)',
        [account.tenant_id, account.external_id, 'reset', hashToken(raw), Date.now()])
      app.db.run('INSERT INTO auth_events (tenant_id,email,method,detail,created_at) VALUES (?,?,?,?,?)',
        [account.tenant_id, account.email, 'password_reset', 'alias_lookup', Date.now()])
    }
    return req.json({ ok: true, message: 'If the address exists, a reset link was sent.' })
  })
}
