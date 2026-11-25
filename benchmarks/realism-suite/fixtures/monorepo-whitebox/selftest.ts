// Self-test for Fixture #4 — proves git history, nested mounts, 4-hop sinks, and scale.
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { start } from './index.ts'

export async function runSelfTest(): Promise<string[]> {
  const checks: string[] = []
  const fixture = await start()
  const app = fixture.origins.app
  const alice = fixture.personas.find((p) => p.id === 'mono-alice')!
  const headers = { authorization: `Bearer ${alice.token}`, 'content-type': 'application/json' }

  try {
    // 1. Scale + nested mounts
    assert.ok(fixture.routeCount >= 2500, `expected >= 2500 routes, got ${fixture.routeCount}`)
    assert.equal(fixture.routes?.filter((r) => r.path.startsWith('/v4/')).length, 2560)
    const resolved = fixture.resolve('/v2/billing/invoices/inv-beta-1')
    assert.ok(resolved)
    assert.deepEqual(resolved.mounts, ['/v2', '/billing'])
    assert.equal(resolved.hopCount, 4)
    assert.equal(resolved.chain.length, 4)
    assert.match(resolved.chain[3], /invoice-repo\.ts#findById/)
    checks.push('2,560 generated routes + nested mounts + 4-hop chain')

    // 2. Git history is real and contains the authz regression
    const log = fixture.git.log()
    assert.equal(log.length, 5)
    assert.ok(log.some((entry) => /drop tenant predicate/i.test(entry.message)))
    const regression = log.find((entry) => entry.sha === fixture.git.regressionCommit)
    assert.ok(regression)
    const repoPath = 'services/billing/src/repos/invoice-repo.ts'
    const beforeRegression = fixture.git.fileAt(log[3].sha, repoPath)
    const afterRegression = fixture.git.fileAt(fixture.git.regressionCommit, repoPath)
    assert.ok(beforeRegression?.includes('AND tenant_id = ?'), 'pre-regression repo scopes the lookup')
    assert.ok(afterRegression?.includes('WHERE id = ?'))
    assert.ok(!afterRegression?.includes('tenant_id = ?'))
    checks.push('preserved .git history with authz regression commit')

    // 3. Billing invoice cross-tenant read through all four hops
    const invoice = await fetch(`${app}/v2/billing/invoices/inv-beta-1`, { headers })
    assert.equal(invoice.status, 200)
    const invoiceBody = (await invoice.json()) as { invoice: { tenant: string; canary: string } }
    assert.equal(invoiceBody.invoice.tenant, 'tenant-beta')
    assert.equal(invoiceBody.invoice.canary, 'rbs_fake_mono_beta_invoice_canary')

    // 4. Reports SQLi at the repo layer
    const safe = await fetch(`${app}/v2/reports/export?sort=total`, { headers })
    assert.equal(safe.status, 200)
    assert.match(await safe.text(), /^id,total,created_at/)
    const injected = await fetch(`${app}/v2/reports/export?sort=${encodeURIComponent('total,(select 1)')}`, { headers })
    assert.equal(injected.status, 500)
    const injectedBody = (await injected.json()) as { error: string }
    assert.match(injectedBody.error, /SQLITE_ERROR/)

    // 5. Admin role update without an admin check (middleware ordering)
    const promote = await fetch(`${app}/v3/admin/users/mono-bob`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ role: 'admin' }),
    })
    assert.equal(promote.status, 200)
    const promoted = (await promote.json()) as { user: { role: string } }
    assert.equal(promoted.user.role, 'admin')

    // 5b. Legitimate admin readback: a member is refused, an admin observes the persisted change.
    const refusedRead = await fetch(`${app}/v3/admin/users/mono-bob`, { headers })
    assert.equal(refusedRead.status, 403)
    const admin = fixture.personas.find((p) => p.id === 'mono-admin')!
    const adminHeaders = { authorization: `Bearer ${admin.token}` }
    const directory = await fetch(`${app}/v3/admin/users`, { headers: adminHeaders })
    assert.equal(directory.status, 200)
    const directoryBody = (await directory.json()) as { users: Array<{ id: string }> }
    assert.ok(directoryBody.users.some((user) => user.id === 'mono-bob'))
    const record = await fetch(`${app}/v3/admin/users/mono-bob`, { headers: adminHeaders })
    assert.equal(record.status, 200)
    assert.equal(((await record.json()) as { role: string }).role, 'admin')
    const unknown = await fetch(`${app}/v3/admin/users/kovo-none-selftest`, { headers: adminHeaders })
    assert.equal(unknown.status, 404)
    checks.push('admin read surface exposes the persisted role change to admins only')
    checks.push('authz + sqli sinks reachable through nested mounts')

    // 6. Scoped profile decoy + generated route reachability
    const profile = await fetch(`${app}/v1/profile`, { headers })
    assert.equal(profile.status, 200)
    assert.equal(((await profile.json()) as { tenant: string }).tenant, 'tenant-alpha')
    const generated = await fetch(`${app}/v4/search/resource-318/abc`, { headers })
    assert.equal(generated.status, 200)
    assert.equal(((await generated.json()) as { service: string }).service, 'search')
    const generatedPost = await fetch(`${app}/v4/billing/resource-319/xyz`, { method: 'POST', headers, body: '{}' })
    assert.equal(generatedPost.status, 200)
    assert.equal(((await generatedPost.json()) as { service: string }).service, 'billing')
    checks.push('decoy profile + generated route reachability')
  } finally {
    const dir = fixture.sourceDir!
    await fixture.stop()
    assert.equal(existsSync(dir), false, 'source tree removed on stop')
    await fixture.stop()
  }
  checks.push('stop removes the materialized tree')
  return checks
}
