// Admin console: remove a user from a tenant by external id. Reached under the administration path
// for signed-in operators.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('adminDeleteUser', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[app.field('memberId')] ?? ''
    app.db.run('DELETE FROM users WHERE external_id = ? AND tenant_id = ? AND role != ?', [ext, tenant, 'owner'])
    return req.json({ ok: true })
  })
}
