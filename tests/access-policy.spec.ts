import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { delimiter, join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import type { AccessPolicySnapshot } from '../src/access-policy.ts'
import { createApp } from './app.ts'
import { configureModel, downloadReport, openScopeReview, saveScope } from './browser-flows.ts'
import { collectReportBenchmark } from './collect-report-benchmark.ts'
import { fixtureServer } from './fixture-server.ts'
import {
  accessPolicy, accessPolicyGoal, combinedGoal, fixtureCredential, healthyOrigin, primary, primaryOrigin, secondaryAccessPolicy,
  severeAccessPolicy, unavailableOrigin,
} from './scenarios.ts'

function markdownEvidence(markdown: string) {
  return [...markdown.matchAll(/\*\*SHA-256 of the JSON below\*\* `([a-f0-9]{64})`\n\n~~~json\n([\s\S]*?)\n~~~/g)]
    .map(([, digest, json]) => {
      expect(createHash('sha256').update(json).digest('hex')).toBe(digest)
      return JSON.parse(json)
    })
}

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
    const attachments = markdownEvidence(markdown)
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

async function importAccessRecords(page: Page, policy: AccessPolicySnapshot) {
  await page.getByRole('button', { name: 'Import access records' }).click()
  await page.getByLabel('Access policy JSON').setInputFiles({
    name: 'authorization-decisions.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(policy)),
  })
  await page.getByRole('button', { name: 'Review records' }).click()
  const review = page.getByRole('region', { name: 'Access policy import preview' })
  await review.getByRole('button', { name: 'Import records' }).click()
  await expect(page.getByRole('status')).toContainText('Imported ' + policy.expected.length + ' access cases for ' +
    new URL(policy.origin).hostname)
}

test('retains independently verified access findings after a redirect host is removed', async ({ page }) => {
  const gate = await mkdtemp(join(tmpdir(), 'guardian-redirect-verification-'))
  const docker = execFileSync('which', ['docker'], { encoding: 'utf8' }).trim()
  // Hold the relay's response-only verification so the operator can stop after the primary host finishes.
  await writeFile(join(gate, 'docker'), `#!/usr/bin/env node
const { readFileSync } = require('node:fs')
const { spawnSync } = require('node:child_process')
const args = process.argv.slice(2)
const startsWorker = args[0] === 'container' && args[1] === 'start'
const input = startsWorker ? readFileSync(0, 'utf8') : undefined
const verification = input && JSON.parse(input).files.find(file => file.name === 'verification-input.json')
if (verification && JSON.parse(verification.content).access === null) {
  setTimeout(() => process.exit(1), 15_000)
} else {
  const options = input === undefined ? { stdio: 'inherit' } : { input, stdio: ['pipe', 'inherit', 'inherit'] }
  process.exit(spawnSync(${JSON.stringify(docker)}, args, options).status ?? 1)
}
`, { mode: 0o700 })
  const requested = [primaryOrigin + '/', healthyOrigin + '/relay', primaryOrigin + '/headers', healthyOrigin + '/']
  const fixture = await fixtureServer({
    scenes: ['connection', 'plan-combined', 'response-primary', 'response-healthy'],
    pages: {
      [primaryOrigin + '/']: healthyOrigin + '/relay',
      [healthyOrigin + '/relay']: primaryOrigin + '/headers',
      [primaryOrigin + '/headers']: primary,
    },
  })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin, PATH: gate + delimiter + process.env.PATH })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await page.getByLabel('Project name').fill('Northstar redirected response')
    await page.getByLabel('Seed hosts').fill([primaryOrigin, healthyOrigin].join('\n'))
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await importAccessRecords(page, severeAccessPolicy)
    await openScopeReview(page, combinedGoal, true)
    await saveScope(page)
    await page.getByRole('link', { name: /^Trace/ }).click()
    await expect(page.getByRole('link', { name: 'Verify northstar.example, complete', exact: true }))
      .toBeVisible({ timeout: 15_000 })
    await page.getByRole('button', { name: 'Run actions' }).click()
    await page.getByRole('menuitem', { name: 'Stop run' }).click()
    await expect(page.getByRole('article', { name: 'Partial report' })).toContainText('5 confirmed findings')
    const original = await downloadReport(page, 'Markdown with evidence')
    const originalRecords = markdownEvidence(original.content)
    const oldProof = originalRecords.find(record => record.kind === 'verification')
    const oldResponse = originalRecords.find(record => record.kind === 'observation' && record.origin === primaryOrigin)
    const access = originalRecords.find(record => record.kind === 'access-policy' && record.origin === primaryOrigin)
    expect(oldProof.inputEvidence).toEqual([oldResponse.artifactId, access.artifactId])

    await page.getByRole('link', { name: 'Workflow', exact: true }).click()
    await page.getByRole('button', { name: 'Review scope' }).click()
    await page.getByRole('checkbox', { name: 'Include healthy.northstar.example' }).uncheck()
    await saveScope(page, 'Save scope revision')
    await expect(page.getByText('1 approved host · Revision 2', { exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'Resume', exact: true }).click()
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('2 confirmed findings')
    await expect(report).toContainText('1 check met baseline · 2 verified gaps · 4 checks inconclusive')
    const priority = report.getByRole('region', { name: 'Fix first' })
    await expect(priority).toContainText('workspace-ownership')
    await expect(priority).toContainText('northstar.example · critical')
    await expect(report.locator('.finding').nth(1)).toContainText('northstar.example · high')
    await report.getByText('Checks for northstar.example', { exact: true }).click()
    await expect(report).toContainText('The supplied records omit a decision for payroll-records.')
    await report.locator('.finding').first().getByRole('button', { name: 'Access policy verification' }).click()
    const proofDialog = page.getByRole('dialog', { name: 'Access policy verification' })
    await expect(proofDialog.locator('pre')).not.toContainText(oldResponse.artifactId)
    await expect(proofDialog.locator('pre')).toContainText(access.artifactId)
    await proofDialog.getByRole('button', { name: 'Close', exact: true }).click()

    const narrowed = await downloadReport(page, 'Markdown with evidence')
    const currentRecords = markdownEvidence(narrowed.content)
    expect(currentRecords.map(({ kind }) => kind)).toEqual(['access-policy', 'verification'])
    expect(currentRecords[1]).toMatchObject({
      inputEvidence: [access.artifactId], verifiedAt: oldProof.capturedAt, exitStatus: 0,
      comparisons: expect.arrayContaining([{ id: 'access-policy:workspace-ownership', observed: 'allow', baseline: { allowed: ['deny'] } }]),
    })
    expect(currentRecords[1].checks.map(({ id }: { id: string }) => id)).toEqual(Array(4).fill('access-policy'))
    for (const excluded of [healthyOrigin, oldResponse.artifactId, oldProof.artifactId, 'Supporting record unavailable']) {
      expect(narrowed.content).not.toContain(excluded)
    }
    await report.getByLabel('Version').selectOption('1')
    expect(await downloadReport(page, 'Markdown with evidence')).toEqual(original)
    expect(fixture.requested.slice().sort()).toEqual(requested.slice().sort())
    expect(fixture.unexpected).toEqual([])
  } finally {
    await app.dispose()
    await fixture.close()
    await rm(gate, { recursive: true, force: true })
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
    await importAccessRecords(page, accessPolicy)
    await importAccessRecords(page, secondaryAccessPolicy)

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

test('prioritizes verified serious access grants and attributes their impact', { tag: '@report-benchmark' }, async ({ page }) => {
  const fixture = await fixtureServer({ scenes: ['connection', 'plan-access-policy'] })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await page.getByLabel('Project name').fill('Northstar administration')
    await page.getByLabel('Seed hosts').fill(primaryOrigin)
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await importAccessRecords(page, severeAccessPolicy)

    await openScopeReview(page, accessPolicyGoal, true)
    await saveScope(page)
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('2 confirmed findings', { timeout: 18_000 })
    await expect(report).toContainText('1 check met baseline · 2 verified gaps · 1 check inconclusive')
    const priority = report.getByRole('region', { name: 'Fix first' })
    await expect(priority).toContainText('northstar.example · critical')
    await expect(priority).toContainText('Deny manage-organization-owners for team-viewer')
    const title = 'Recorded access exceeds policy for workspace-ownership'
    await priority.getByRole('link', { name: title }).press('Enter')
    const findings = report.locator('.finding')
    await expect(findings).toHaveCount(2)
    await expect(findings.first()).toBeFocused()
    await expect(findings.first()).toContainText('The supplied policy identifies this capability as organization-wide administration.')
    await expect(findings.first()).toContainText('The expected decision is deny.')
    await expect(findings.nth(1)).toContainText('northstar.example · high')
    await expect(findings.nth(1)).toContainText('The supplied policy identifies this capability as access to sensitive records.')

    const exported = await downloadReport(page, 'Markdown with evidence')
    await collectReportBenchmark('policy-serious-impact', app.directory, page.url(), exported)
    expect(fixture.requested).toEqual([])
    expect(fixture.accepted).toContain('plan-access-policy:responses:0')
    expect(fixture.unexpected).toEqual([])
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('plans again with the remaining approved inputs when scope changes during planning', async ({ page }) => {
  const fixture = await fixtureServer({
    scenes: ['connection', 'plan-combined', 'plan-combined-narrowed', 'response-healthy'],
    holdModel: 'plan-combined:responses:0',
  })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await page.getByLabel('Project name').fill('Northstar scope revision')
    await page.getByLabel('Seed hosts').fill([primaryOrigin, healthyOrigin].join('\n'))
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await importAccessRecords(page, accessPolicy)
    await openScopeReview(page, combinedGoal, true)
    await saveScope(page)
    await fixture.modelWithheld
    await expect(page.getByText('Preparing review plan', { exact: true })).toBeVisible()
    expect(fixture.requested).toEqual([])

    await page.getByRole('button', { name: 'Review scope' }).click()
    await page.getByRole('checkbox', { name: 'Include northstar.example' }).uncheck()
    await saveScope(page, 'Save scope revision')
    await expect(page.getByText('1 approved host · Revision 2')).toBeVisible()
    await expect.poll(() => fixture.heldModelClosed).toBe(true)

    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('3 checks met baseline', { timeout: 18_000 })
    await expect(report).toContainText('Standard checks · HSTS policy, MIME sniffing protection, Referrer policy')
    await expect(report).toContainText('Scope revision 2 · Goal revision 0')
    await expect(report).not.toContainText('Access policy decisions')
    expect(fixture.requested).toEqual([healthyOrigin + '/'])
    expect(fixture.accepted.filter(name => name.startsWith('plan-'))).toEqual(['plan-combined-narrowed:responses:0'])
    expect(fixture.unexpected).toEqual([])

    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    try {
      const planned = db.prepare("SELECT detail FROM events WHERE kind = 'review.planned'").all()
      expect(planned.map(row => JSON.parse(String(row.detail)))).toEqual([
        { goalRevision: 0, scopeRevision: 2, source: 'standard', checks: ['hsts', 'nosniff', 'referrer-policy'] },
      ])
      expect(db.prepare("SELECT phase, scope_revision FROM assignments WHERE phase != 'discovery' ORDER BY phase").all())
        .toEqual([{ phase: 'analysis', scope_revision: 2 }, { phase: 'verification', scope_revision: 2 }])
    } finally {
      db.close()
    }
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('replans an active run when a newly approved host supplies access records', async ({ page }) => {
  const fixture = await fixtureServer({
    scenes: ['connection', 'plan-combined-narrowed', 'plan-combined', 'response-primary', 'response-unavailable'],
    holdModel: 'response-primary:responses:0',
  })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await page.getByLabel('Project name').fill('Northstar expanded scope')
    await page.getByLabel('Seed hosts').fill([primaryOrigin, unavailableOrigin].join('\n'))
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await importAccessRecords(page, secondaryAccessPolicy)
    await openScopeReview(page, combinedGoal, true)
    const docs = page.getByRole('checkbox', { name: 'Include docs.northstar.example' })
    await docs.uncheck()
    await saveScope(page)
    await fixture.modelWithheld
    expect(fixture.requested).toEqual([primaryOrigin + '/'])
    expect(fixture.accepted).toContain('plan-combined-narrowed:responses:0')

    const expandedPlan = fixture.holdNextModel('plan-combined:responses:0')
    await page.getByRole('button', { name: 'Review scope' }).click()
    await docs.check()
    await saveScope(page, 'Save scope revision')
    await expect(page.getByText('2 approved hosts · Revision 2')).toBeVisible()
    await expandedPlan
    await expect(page.getByText('Preparing review plan', { exact: true })).toBeVisible()
    expect(fixture.requested).toEqual([primaryOrigin + '/'])
    let earlierId: string
    let originalCapture: { artifactId: string; capturedAt: string; scopeRevision: number }
    const before = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    try {
      const worker = before.prepare("SELECT id, status, scope_revision FROM assignments WHERE phase = 'analysis'").all()
      expect(worker).toHaveLength(1)
      expect(worker[0]).toMatchObject({ status: 'running', scope_revision: 1 })
      earlierId = String(worker[0].id)
      const observation = before.prepare("SELECT id, created_at, scope_revision FROM evidence WHERE assignment_id = ? AND kind = 'observation'")
        .get(earlierId)
      expect(observation).toBeDefined()
      originalCapture = {
        artifactId: String(observation?.id), capturedAt: new Date(Number(observation?.created_at)).toISOString(),
        scopeRevision: Number(observation?.scope_revision),
      }
    } finally {
      before.close()
    }

    await app.stop('SIGKILL')
    fixture.dropHeldModel()
    await app.start()
    const resume = page.getByRole('button', { name: 'Resume', exact: true })
    await expect(resume).toBeVisible()
    expect(fixture.requested).toEqual([primaryOrigin + '/'])
    await resume.click()
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('4 confirmed findings', { timeout: 18_000 })
    await expect(report).toContainText('Scope revision 2 · Goal revision 0')
    await expect(report).toContainText('Planned checks · HSTS policy, MIME sniffing protection, Referrer policy, Access policy decisions')
    const policy = page.getByRole('heading', { name: 'Recorded access exceeds policy for billing-export', exact: true })
    await expect(report.locator('.finding').filter({ has: policy })).toContainText('docs.northstar.example')
    const { content } = await downloadReport(page, 'Markdown with evidence')
    expect(content).toContain(secondaryAccessPolicy.recordedAt)
    const retained = [...content.matchAll(/~~~json\n([\s\S]*?)\n~~~/g)].map(([, json]) => JSON.parse(json))
      .find(record => record.kind === 'observation' && record.observation?.origin === primaryOrigin)
    expect(retained).toMatchObject({ capturedAt: originalCapture.capturedAt, reusedFrom: originalCapture })
    expect(fixture.requested).toEqual([primaryOrigin + '/', unavailableOrigin + '/'])
    expect(fixture.accepted.filter(name => name.startsWith('plan-'))).toEqual([
      'plan-combined-narrowed:responses:0', 'plan-combined:responses:0',
    ])
    expect(fixture.unexpected).toEqual([])

    const after = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    try {
      const attempt = after.prepare('SELECT status, outcome FROM assignments WHERE id = ?').get(earlierId)
      expect(attempt).toEqual({ status: 'canceled', outcome: 'Superseded by the revised check plan.' })
      expect(after.prepare("SELECT id FROM evidence WHERE assignment_id = ? AND kind = 'observation'").get(earlierId)?.id)
        .toBe(originalCapture.artifactId)
      const reuse = after.prepare("SELECT detail FROM events WHERE kind = 'evidence.reused'").all()
      expect(reuse).toHaveLength(1)
      expect(JSON.parse(String(reuse[0].detail))).toMatchObject({
        sourceArtifactId: originalCapture.artifactId, origins: [primaryOrigin],
      })
      const fresh = after.prepare("SELECT count(*) AS n FROM assignments WHERE scope_revision = 2 AND status = 'complete'").get()
      expect(fresh?.n).toBe(4)
    } finally {
      after.close()
    }
  } finally {
    if (test.info().status !== test.info().expectedStatus) await test.info().attach('fixture activity', {
      body: JSON.stringify({ requested: fixture.requested, accepted: fixture.accepted, unexpected: fixture.unexpected }),
      contentType: 'application/json',
    })
    await app.dispose()
    await fixture.close()
  }
})
