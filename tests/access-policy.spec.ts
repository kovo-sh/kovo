import { expect, test } from '@playwright/test'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { createApp } from './app.ts'
import { configureModel, downloadReport, openScopeReview, saveScope } from './browser-flows.ts'
import { collectReportBenchmark } from './collect-report-benchmark.ts'
import { fixtureServer } from './fixture-server.ts'
import {
  accessPolicy, accessPolicyGoal, combinedGoal, fixtureCredential, primaryOrigin, secondaryAccessPolicy, unavailableOrigin,
} from './scenarios.ts'

test('imports and verifies access policy cases alone and alongside response checks', { tag: '@report-benchmark' }, async ({ page }) => {
  const fixture = await fixtureServer({ scenes: ['connection', 'plan-access-policy', 'plan-combined', 'response-primary'] })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  const privateValue = 'inert-access-record-secret-6409'
  const posted: string[] = []
  page.on('request', request => { if (request.method() === 'POST') posted.push(request.postData() ?? '') })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await page.getByLabel('Project name').fill('Northstar')
    await page.getByLabel('Seed hosts').fill([primaryOrigin, unavailableOrigin].join('\n'))
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await page.getByRole('button', { name: 'Import access records' }).click()

    const file = page.getByLabel('Access policy JSON')
    const selectFile = (document: object) => file.setInputFiles({
      name: 'authorization-decisions.json', mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(document)),
    })
    await selectFile({ ...accessPolicy, origin: 'https://outside.example' })
    await page.getByRole('button', { name: 'Review records' }).click()
    await expect(page.getByRole('alert')).toContainText('existing project host')

    await selectFile({
      ...accessPolicy,
      credentials: { apiKey: privateValue },
      observed: accessPolicy.observed.map(item => ({ ...item, rawAuditDetail: privateValue })),
    })
    await page.getByRole('button', { name: 'Review records' }).click()
    const preview = page.getByRole('region', { name: 'Access policy import preview' })
    await expect(preview).toContainText('4 expected cases · 3 recorded decisions')
    await preview.getByRole('button', { name: 'Import records' }).click()
    await expect(page.getByRole('status')).toContainText('Imported 4 access cases for northstar.example.')
    expect(posted.join('')).not.toContain(privateValue)

    await openScopeReview(page, accessPolicyGoal, true)
    await page.getByRole('checkbox', { name: 'Include docs.northstar.example' }).uncheck()
    expect(fixture.requested).toEqual([])
    expect(fixture.accepted).not.toContain('plan-access-policy:responses:0')
    await saveScope(page)
    const firstRunPath = new URL(page.url()).pathname
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('2 confirmed findings', { timeout: 18_000 })
    await expect(report).toContainText('1 check met baseline · 2 verified gaps · 1 check inconclusive')
    await expect(report).toContainText('Supplied access policy records')
    await expect(report).not.toContainText('Approved HTTPS root responses')
    await expect(report).not.toContainText('docs.northstar.example')
    const excess = report.locator('.finding').filter({ has: page.getByRole('heading', { name: 'Recorded access exceeds policy for billing-export' }) })
    const priority = report.getByRole('region', { name: 'Fix first' })
    await expect(priority).toContainText('northstar.example · medium')
    await expect(priority).toContainText('server-side authorization policy')
    await priority.getByRole('link', { name: 'Recorded access exceeds policy for billing-export' }).press('Enter')
    await expect(excess).toBeFocused()
    await expect(excess).toContainText('medium')
    await expect(excess).toContainText('Allowed')
    await expect(excess).toContainText('Deny export-statements for billing-viewer.')
    await expect(excess).toContainText('Rerun the owner’s authorization test for this case')
    await expect(report).toContainText('Recorded access falls short of policy for audit-summary')
    await report.getByText('Checks for northstar.example', { exact: true }).click()
    await expect(report.getByText('Meets baseline', { exact: true })).toHaveCount(1)
    await expect(report.getByText('Inconclusive', { exact: true })).toHaveCount(1)
    await expect(report).toContainText('The supplied records omit a decision for modify-schedule.')
    await expect(report.locator('time[datetime]')).toHaveAttribute('datetime', accessPolicy.recordedAt)

    await excess.getByRole('button', { name: 'Supplied access policy records' }).click()
    const input = page.getByRole('dialog', { name: 'Supplied access policy records' })
    await expect(input).toContainText('2026-11-17T15:45:00Z')
    await expect(input).not.toContainText(privateValue)
    await input.getByRole('button', { name: 'Close', exact: true }).click()
    await excess.getByRole('button', { name: 'Access policy verification' }).click()
    const receipt = page.getByRole('dialog', { name: 'Access policy verification' })
    await expect(receipt).toContainText('"id": "access-policy:billing-export"')
    await expect(receipt).toContainText('"exitStatus": 0')
    await receipt.getByRole('link', { name: /Open worker thread/ }).click()
    await expect(page.getByRole('region', { name: 'Worker thread' })).toContainText('Verify northstar.example')
    expect(fixture.requested).toEqual([])

    await page.getByRole('link', { name: 'Northstar', exact: true }).click()
    await page.getByRole('heading', { name: 'Northstar', exact: true }).waitFor()
    const laterCapture = '2026-11-18T08:00:00Z'
    await page.getByRole('button', { name: 'Import access records' }).click()
    await selectFile({ ...accessPolicy, recordedAt: laterCapture })
    await page.getByRole('button', { name: 'Review records' }).click()
    await preview.getByRole('button', { name: 'Replace access records' }).click()
    await expect(page.getByRole('status')).toContainText('Imported 4 access cases')
    const newRun = page.getByRole('button', { name: 'New run', exact: true })
    if (await newRun.isVisible()) await newRun.click()
    await openScopeReview(page, combinedGoal, true)
    await page.getByRole('checkbox', { name: 'Include docs.northstar.example' }).uncheck()
    await saveScope(page)
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    await expect(report).toContainText('5 confirmed findings', { timeout: 18_000 })
    await expect(report).toContainText('Approved HTTPS root responses · Supplied access policy records')
    await expect(report).toContainText('HSTS max-age missing or disabled')
    expect(fixture.requested).toEqual([primaryOrigin + '/'])
    expect(fixture.accepted).toContain('plan-access-policy:responses:0')
    expect(fixture.accepted).toContain('plan-combined:responses:0')
    expect(fixture.unexpected).toEqual([])

    const { content: exported } = await downloadReport(page, 'Plain text')
    expect(exported).toContain('Fix first\nRecorded access exceeds policy for billing-export\n' + primaryOrigin)
    expect(exported).toContain('Deny export-statements for billing-viewer.')
    expect(exported).toContain('Recorded ' + laterCapture)
    expect(exported).not.toContain(privateValue)

    const { name, content: markdown } = await downloadReport(page, 'Markdown with evidence')
    expect(name).toMatch(/^guardian-report-[a-f0-9]{8}-v1\.md$/)
    expect(markdown).toContain('# Guardian complete report')
    expect(markdown).toContain('## Fix first\n\n**Recorded access exceeds policy for billing-export** · ' + primaryOrigin)
    expect(markdown).toContain('Deny export-statements for billing-viewer.')
    expect(markdown).toContain('The supplied records omit a decision for modify-schedule.')
    expect(markdown).toContain(laterCapture)
    expect(markdown).not.toContain(accessPolicy.recordedAt)
    expect(markdown).not.toContain('docs.northstar.example')
    expect(markdown).not.toContain(privateValue)
    expect(markdown).not.toContain(fixtureCredential)
    expect(markdown).not.toMatch(/"(?:command|stdout|stderr|rawAuditDetail|credentials)"/)
    const linked = [...markdown.matchAll(/\]\(#evidence-(\d+)\)/g)].map(match => match[1])
    const sections = [...markdown.matchAll(/^### Evidence (\d+)$/gm)].map(match => match[1])
    expect([...new Set(linked)].sort()).toEqual(sections.sort())
    const attachments = [...markdown.matchAll(/\*\*SHA-256 of the JSON below\*\* `([a-f0-9]{64})`\n\n~~~json\n([\s\S]*?)\n~~~/g)]
      .map(([, digest, json]) => {
        expect(createHash('sha256').update(json).digest('hex')).toBe(digest)
        return JSON.parse(json)
      })
    expect(attachments).toHaveLength(sections.length)
    const access = attachments.find(record => record.kind === 'access-policy')
    const response = attachments.find(record => record.kind === 'observation')
    const verificationRecord = attachments.find(record => record.kind === 'verification')
    expect(access.snapshot.recordedAt).toBe(laterCapture)
    expect(response.observation.origin).toBe(primaryOrigin)
    expect(verificationRecord).toMatchObject({
      interpreter: 'just-bash 3.6.1', exitStatus: 0, inputEvidence: [response.artifactId, access.artifactId],
    })
    expect(verificationRecord.comparisons).toContainEqual({
      id: 'access-policy:billing-export', observed: 'allow', baseline: { allowed: ['deny'] },
    })

    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    try {
      const rows = db.prepare(`SELECT check_id, case_id, json_extract(finding, '$.evidenceIds[0]') AS source
        FROM findings WHERE json_extract(finding, '$.status') = 'confirmed'`).all()
      expect(rows.filter(row => row.check_id === 'access-policy').map(row => row.case_id).sort())
        .toEqual(['audit-summary', 'audit-summary', 'billing-export', 'billing-export'])
      expect(rows).toHaveLength(7)
      for (const row of rows) {
        const evidence = db.prepare('SELECT kind FROM evidence WHERE id = ?').get(String(row.source))
        expect(evidence?.kind).toBe(row.check_id === 'access-policy' ? 'access-policy' : 'observation')
      }
    } finally {
      db.close()
    }
    await page.goto(app.url + firstRunPath + '?view=report')
    await expect(report).toContainText('2 confirmed findings')
    await expect(report.locator('time[datetime]')).toHaveAttribute('datetime', accessPolicy.recordedAt)
    await page.setViewportSize({ width: 390, height: 844 })
    await page.emulateMedia({ colorScheme: 'dark' })
    const layout = await report.locator('.finding .state').first().evaluate(status => ({
      width: document.documentElement.scrollWidth,
      lines: Math.round(status.getBoundingClientRect().height / Number.parseFloat(getComputedStyle(status).lineHeight)),
    }))
    expect(layout).toEqual({ width: 390, lines: 1 })
    const historical = await downloadReport(page, 'Markdown with evidence')
    expect(historical.content).toContain('2 confirmed findings')
    expect(historical.content).toContain(accessPolicy.recordedAt)
    expect(historical.content).not.toContain(laterCapture)
    expect(historical.content).not.toContain('Supporting record unavailable')
    await collectReportBenchmark('access-policy', app.directory, page.url(), historical)
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('keeps overlapping access findings and verification tied to each approved host', { tag: '@report-benchmark' }, async ({ page }) => {
  const fixture = await fixtureServer({ scenes: ['connection', 'plan-access-policy'] })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await page.getByLabel('Project name').fill('Northstar policy overlap')
    await page.getByLabel('Seed hosts').fill([primaryOrigin, unavailableOrigin].join('\n'))
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    for (const policy of [accessPolicy, secondaryAccessPolicy]) {
      await page.getByRole('button', { name: 'Import access records' }).click()
      await page.getByLabel('Access policy JSON').setInputFiles({
        name: 'authorization-decisions.json',
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify(policy)),
      })
      await page.getByRole('button', { name: 'Review records' }).click()
      const review = page.getByRole('region', { name: 'Access policy import preview' })
      await review.getByRole('button', { name: 'Import records' }).click()
      await expect(page.getByRole('status')).toContainText('Imported 4 access cases for ' + new URL(policy.origin).hostname)
    }

    await openScopeReview(page, accessPolicyGoal, true)
    await saveScope(page)
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('3 confirmed findings', { timeout: 18_000 })
    await expect(report).toContainText('3 checks met baseline · 3 verified gaps · 2 checks inconclusive')
    await expect(report.getByRole('region', { name: 'Fix first' })).toContainText('2 medium-severity findings share top priority.')
    await expect(report.getByRole('heading', { name: 'Recorded access exceeds policy for billing-export' })).toHaveCount(2)
    const exported = await downloadReport(page, 'Markdown with evidence')
    await collectReportBenchmark('policy-multi-host', app.directory, page.url(), exported)
    expect(fixture.requested).toEqual([])
    expect(fixture.accepted).toContain('plan-access-policy:responses:0')
    expect(fixture.unexpected).toEqual([])
  } finally {
    await app.dispose()
    await fixture.close()
  }
})
