import { expect, test } from '@playwright/test'
import { createApp } from './app.ts'
import { configureModel, downloadReport, openScopeReview, saveScope } from './browser-flows.ts'
import { createV2FixtureServer, E2E_COOKIE_SECRET, E2E_CREDENTIAL } from './v2-fixture-server.ts'

test.setTimeout(90_000)

test('end-to-end multi-step chain discovery, CVE-2025-29927 Zero-LLM replay verification, Verify Fix retest, Persona Vault, and portable Markdown export', async ({ page }) => {
  const fixture = await createV2FixtureServer({ scenario: 'chain_cve' })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  const personaSecret = 'opaque-e2e-persona-bearer-secret-44109'

  try {
    await app.start()
    await page.goto(app.url)

    // 1. Multi-profile LLM Settings UI
    await configureModel(page, fixture.origin + '/api/v1', E2E_CREDENTIAL)
    await page.getByRole('link', { name: 'Model settings' }).click()
    await expect(page.getByRole('region', { name: 'Configured model profiles' }).or(page.locator('[aria-label="Configured model profiles"]'))).toContainText('Healthy')
    await page.getByRole('link', { name: 'Projects', exact: true }).click()

    // 2. Create project, register Persona Vault secret, import lockfile spec
    await page.getByLabel('Project name').fill('Northstar v2 E2E')
    await page.getByLabel('Seed hosts').fill('https://northstar.example')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()

    // Persona Vault: save secret, confirm secret is NEVER displayed in DOM
    await page.getByRole('button', { name: 'Add persona', exact: true }).click()
    await page.getByLabel(/Handle/).fill('tenant_a')
    await page.getByLabel('Role label').fill('Standard Tenant A')
    await page.getByLabel('Credential secret').fill(personaSecret)
    await page.getByRole('button', { name: 'Save persona', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'Saved persona "tenant_a"' })).toBeVisible()
    await expect(page.locator('body')).not.toContainText(personaSecret)

    // Import package.json lockfile spec for CVE-2025-29927 grey-box correlation
    await page.getByRole('button', { name: 'Import spec / lockfile', exact: true }).click()
    await page.getByLabel('Name', { exact: true }).fill('package.json')
    await page.getByRole('combobox', { name: 'Kind', exact: true }).selectOption('notes')
    await page.getByLabel('Content', { exact: true }).fill(JSON.stringify({ dependencies: { next: '14.2.20' } }))
    await page.getByRole('button', { name: 'Import spec', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: 'Imported spec "package.json"' })).toBeVisible()

    // 3. Create Tier 1 run, authorize discovery, approve scope
    await openScopeReview(page, 'Discover hidden endpoints and verify CVE-2025-29927 middleware auth bypass.', 1)
    await saveScope(page)

    // 4. Inspect Report once Zero-LLM Replay Verifier confirms the chain finding
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toBeVisible({ timeout: 45_000 })
    await expect(report).toContainText('Next.js Middleware Auth Bypass (CVE-2025-29927)')
    await expect(report).toContainText('Multi-step chain')
    await expect(report).toContainText('Threat model ranking')
    await expect(report).toContainText('OWASP / API Top 10 coverage')

    // 5. One-click Verify Fix retest: first Reproduced (vulnerable), then Fixed (patched)!
    const verifyBtn = report.getByRole('button', { name: 'Verify Fix', exact: true })
    await expect(verifyBtn).toBeVisible()
    await verifyBtn.click()
    await expect(report).toContainText('Still reproducible', { timeout: 25_000 })

    fixture.setPatched(true)
    await verifyBtn.click()
    await expect(report).toContainText('Verified fixed', { timeout: 25_000 })

    // 6. Inspect Workflow Trace DAG view
    await page.getByRole('link', { name: 'Workflow', exact: true }).click()
    await page.getByRole('link', { name: /^Trace/ }).click()
    await expect(page.locator('.trace-canvas')).toBeVisible()

    // 7. Export portable Markdown with evidence & verify zero secret leaks
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const exported = await downloadReport(page, 'Markdown with evidence')
    expect(exported.content).toContain('Next.js Middleware Auth Bypass (CVE-2025-29927)')
    expect(exported.content).toContain('## Executive summary')
    expect(exported.content).not.toContain(E2E_CREDENTIAL)
    expect(exported.content).not.toContain(E2E_COOKIE_SECRET)
    expect(exported.content).not.toContain(personaSecret)
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('surfaces Tier 3 HITL approval card and blocks state-changing probe until operator clicks Approve probe', async ({ page }) => {
  const fixture = await createV2FixtureServer({ scenario: 'tier3_approval' })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })

  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', E2E_CREDENTIAL)

    await page.getByLabel('Project name').fill('Northstar Tier 3 HITL')
    await page.getByLabel('Seed hosts').fill('https://northstar.example')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()

    await openScopeReview(page, 'Validate benign Tier 3 state probe with explicit operator approval.', 3)
    await saveScope(page)

    // Wait for inline Tier 3 Approval Card in Overview
    const approveBtn = page.getByRole('button', { name: 'Approve probe', exact: true })
    await expect(approveBtn).toBeVisible({ timeout: 30_000 })
    await expect(page.getByText('POST https://northstar.example/api/state-eval', { exact: true })).toBeVisible()

    // Hard security invariant: POST /api/state-eval MUST NOT have fired before approval!
    expect(fixture.targetRequests.filter(r => r.method === 'POST')).toHaveLength(0)

    await approveBtn.click()
    await expect(approveBtn).toBeHidden({ timeout: 15_000 })

    // Run completes cleanly after operator approves probe
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    await expect(page.getByRole('article', { name: 'Complete report' })).toBeVisible({ timeout: 40_000 })
    expect(fixture.targetRequests.filter(r => r.method === 'POST' && r.target.includes('/api/state-eval'))).toHaveLength(1)
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('recovers cleanly from SIGKILL crash into paused and resumes without duplicating baseline requests', async ({ page }) => {
  const fixture = await createV2FixtureServer({ scenario: 'chain_cve', holdTargetPath: '/app.js' })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })

  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', E2E_CREDENTIAL)

    await page.getByLabel('Project name').fill('Northstar Crash Recovery')
    await page.getByLabel('Seed hosts').fill('https://northstar.example')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()

    await openScopeReview(page, 'Verify crash recovery without duplicate baseline requests.', 1)
    await saveScope(page)

    // Wait until worker hits held /app.js (baseline GET / is already persisted!)
    await fixture.targetHeld
    const rootReadsBeforeCrash = fixture.targetRequests.filter(r => r.target === 'https://northstar.example/').length
    expect(rootReadsBeforeCrash).toBe(1)

    // Kill the production server abruptly with SIGKILL
    await app.stop('SIGKILL')
    fixture.dropTargetHold()

    // Restart production server on same SQLite directory
    await app.start()
    await page.reload()

    // Must recover into paused and wait for explicit Resume (zero new requests before Resume!)
    const resumeBtn = page.getByRole('button', { name: 'Resume', exact: true })
    await expect(resumeBtn).toBeVisible({ timeout: 20_000 })
    expect(fixture.targetRequests.filter(r => r.target === 'https://northstar.example/').length).toBe(1)

    await resumeBtn.click()
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    await expect(page.getByRole('article', { name: 'Complete report' })).toBeVisible({ timeout: 45_000 })

    // Baseline GET / was never duplicated across crash + resume!
    expect(fixture.targetRequests.filter(r => r.target === 'https://northstar.example/').length).toBe(1)
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('enforces mid-chain scope revocation and omits revoked host from subsequent report export', async ({ page }) => {
  const fixture = await createV2FixtureServer({ scenario: 'two_host_revoke', holdTargetPath: '/app.js' })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })

  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', E2E_CREDENTIAL)

    await page.getByLabel('Project name').fill('Northstar Scope Revocation')
    await page.getByLabel('Seed hosts').fill('https://northstar.example\nhttps://api.northstar.example')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()

    await openScopeReview(page, 'Test mid-chain scope revocation across two hosts.', 1)
    await saveScope(page)

    await fixture.targetHeld

    // Open Review scope while run is active and revoke northstar.example
    await page.getByRole('button', { name: 'Review scope', exact: true }).click()
    await page.getByRole('checkbox', { name: 'Include northstar.example', exact: true }).uncheck()
    await saveScope(page, 'Save scope revision')
    await expect(page.getByText(/1 approved host · Revision 2/)).toBeVisible({ timeout: 15_000 })

    // Release hold so remaining approved host finishes cleanly
    fixture.releaseTargetHold()

    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toBeVisible({ timeout: 45_000 })
    await expect(report).toContainText('api.northstar.example')

    const exported = await downloadReport(page, 'Markdown with evidence')
    expect(exported.content).toContain('api.northstar.example')
    expect(exported.content).not.toContain('Next.js Middleware Auth Bypass (CVE-2025-29927)')
    expect(exported.content).not.toContain('https://northstar.example')
  } finally {
    await app.dispose()
    await fixture.close()
  }
})
