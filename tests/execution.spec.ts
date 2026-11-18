import { expect, test } from '@playwright/test'
import { readdirSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { createApp } from './app.ts'
import { configureModel, downloadReport, reviewScope, saveScope } from './browser-flows.ts'
import { collectReportBenchmark } from './collect-report-benchmark.ts'
import { fixtureServer } from './fixture-server.ts'
import {
  allChecksGoal, excludedOrigin, fixtureCredential, healthyOrigin, primaryOrigin, referrerGoal, statusQuestion, unavailableOrigin,
} from './scenarios.ts'

const mainScenes = ['connection', 'plan-all', 'response-primary', 'response-unavailable']
const healthyScenes = ['connection', 'plan-all', 'response-healthy']
const seeds = [primaryOrigin, unavailableOrigin]

test('replays real provider streams through analysis, restart, explicit resume, and the final report', { tag: '@report-benchmark' }, async ({ page }) => {
  const fixture = await fixtureServer({
    scenes: mainScenes, hold: unavailableOrigin + '/', holdModel: 'plan-all:responses:0',
  })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await reviewScope(page, { project: 'Northstar', seeds, goal: allChecksGoal, thirdParty: excludedOrigin, live: true })
    await expect(page.getByRole('checkbox', { name: 'Include help.vendor.example' })).not.toBeChecked()
    expect(fixture.requested).toEqual([])
    await saveScope(page)
    await fixture.modelWithheld
    await app.stop('SIGKILL')
    fixture.dropHeldModel()
    await app.start()
    const resume = page.getByRole('button', { name: 'Resume', exact: true })
    await expect(resume).toBeVisible()
    expect(fixture.requested).toEqual([])
    await resume.click()
    await page.getByRole('link', { name: /^Trace/ }).click()
    await page.getByRole('link', { name: 'Review northstar.example, complete' }).click()
    await expect(page.getByRole('button', { name: /Derived evidence/ })).toBeVisible()
    const link = page.url()
    await fixture.withheld

    await app.stop('SIGKILL')
    fixture.release()
    await app.start()
    await expect(page.getByRole('button', { name: 'Resume', exact: true })).toBeVisible()
    expect(fixture.requested).toEqual(expect.arrayContaining([primaryOrigin + '/', unavailableOrigin + '/']))
    await page.goto(link)
    await expect(page.getByRole('region', { name: 'Worker thread' })).toContainText('Derived evidence')
    await page.getByRole('button', { name: 'Run actions', exact: true }).click()
    await page.getByRole('menuitem', { name: 'Stop run' }).click()
    const partial = page.getByRole('article', { name: 'Partial report' })
    await expect(partial).toContainText('No confirmed findings')
    await expect(partial).toContainText('6 checks untested')
    await expect(partial.getByRole('region', { name: 'Fix first' })).toHaveCount(0)
    await expect(partial).toContainText('Verification pending')
    await expect(partial).toContainText('Planned checks · HSTS policy, MIME sniffing protection, Referrer policy')
    for (const origin of seeds) {
      await partial.getByText('Checks for ' + new URL(origin).hostname, { exact: true }).click()
    }
    const untested = partial.getByText('Untested', { exact: true })
    await expect(untested).toHaveCount(6)
    await expect(untested.last()).toBeVisible()
    await page.getByRole('button', { name: 'Resume', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Complete report' })).toBeVisible({ timeout: 18_000 })
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('3 confirmed findings')
    await expect(report).toContainText('3 verified gaps · 3 checks inconclusive')
    await expect(report.getByRole('region', { name: 'Fix first' })).toContainText('2 low-severity findings share top priority.')
    await expect(report).toContainText('Inconclusive')
    await expect(report).toContainText('Coverage gaps')
    await expect(report).toContainText('HSTS max-age missing or disabled')
    await expect(report).toContainText('MIME sniffing protection missing')
    await expect(report).toContainText('Referrer policy permits full cross-origin URLs')
    await expect(report).toContainText('Check the fix')
    const referrer = report.locator('.finding').filter({ has: page.getByRole('heading', { name: 'Referrer policy permits full cross-origin URLs' }) })
    await expect(referrer).toContainText('unsafe-url')
    await expect(referrer).toContainText('strict-origin-when-cross-origin')
    await referrer.getByRole('button', { name: 'Observed public response' }).click()
    await expect(page.getByRole('dialog')).toContainText('Observed public response')
    await expect(page.getByRole('dialog')).not.toContainText(fixture.sensitiveFixtureValue)
    await page.getByRole('button', { name: 'Close', exact: true }).click()
    await referrer.getByRole('button', { name: 'Response policy verification' }).click()
    const verification = page.getByRole('dialog', { name: 'Response policy verification' })
    await expect(verification).toContainText('just-bash 3.6.1')
    await expect(verification).toContainText('"exitStatus": 0')
    await expect(verification).not.toContainText(fixture.sensitiveFixtureValue)
    await verification.getByRole('link', { name: /Open worker thread/ }).click()
    const verificationWorker = page.getByRole('region', { name: 'Worker thread' })
    await expect(verificationWorker).toContainText('Verify northstar.example')
    await expect(verificationWorker.locator('[data-role=worker]').getByRole('group', { name: 'Turn evidence' })
      .getByRole('button', { name: 'Response policy verification' })).toBeVisible()
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const { content: mark } = await downloadReport(page, 'Plain text')
    expect(mark).not.toContain(fixtureCredential)
    expect(mark).not.toContain(fixture.sensitiveFixtureValue)
    expect(mark).toContain('Guardian complete report')
    expect(mark).toContain('Fix first\n2 low-severity findings share top priority.')
    expect(mark).toContain('Referrer policy · Gap found')
    expect(mark).toContain('Observed: unsafe-url')
    expect(mark).toContain('Check the fix:')

    const completeExport = await downloadReport(page, 'Markdown with evidence')
    expect(completeExport.name).toMatch(/-v2\.md$/)
    expect(completeExport.content).toContain('# Guardian complete report')
    expect(completeExport.content).toContain('## Fix first\n\n2 low-severity findings share top priority.')
    expect(completeExport.content).toContain('## Coverage gaps')
    expect(completeExport.content).toContain('"kind": "verification"')
    expect(completeExport.content).toContain('"status": 503')
    expect(completeExport.content).toContain('The recorded response returned HTTP 503.')
    expect(completeExport.content).not.toContain(fixture.sensitiveFixtureValue)
    expect(completeExport.content).not.toContain('Supporting record unavailable')
    await collectReportBenchmark('response-multi-host', app.directory, page.url(), completeExport)
    await report.getByLabel('Version').selectOption('1')
    await expect(partial).toContainText('Verification pending')
    await expect(partial).toContainText('6 checks untested')
    const partialText = await downloadReport(page, 'Plain text')
    expect(partialText.content.match(/ · Untested$/gm)).toHaveLength(6)
    expect(partialText.content).not.toContain('Gap found')
    const partialExport = await downloadReport(page, 'Markdown with evidence')
    expect(partialExport.name).toMatch(/-v1\.md$/)
    expect(partialExport.content).toContain('# Guardian partial report')
    expect(partialExport.content.match(/ · Untested$/gm)).toHaveLength(6)
    expect(partialExport.content).not.toContain('## Fix first')
    expect(partialExport.content).toContain('Verification pending')
    expect(partialExport.content).toContain('"kind": "observation"')
    expect(partialExport.content).not.toContain('"kind": "verification"')
    await collectReportBenchmark('response-interrupted', app.directory, page.url(), partialExport)

    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    let planningSession: string
    try {
      planningSession = String(db.prepare("SELECT json_extract(review_plan, '$.goalMessageId') AS id FROM runs").get()?.id)
      expect(db.prepare("SELECT count(*) AS n FROM assignments WHERE phase = 'analysis' AND status = 'complete'").get()?.n).toBe(2)
      expect(db.prepare("SELECT count(*) AS n FROM reports").get()?.n).toBe(2)
      const confirmed = db.prepare(`SELECT check_id, json_extract(finding, '$.evidenceIds') AS evidence
        FROM findings WHERE json_extract(finding, '$.status') = 'confirmed' ORDER BY check_id`).all()
      expect(confirmed.map(row => row.check_id)).toEqual(['hsts', 'nosniff', 'referrer-policy'])
      expect(new Set(confirmed.map(row => row.evidence)).size).toBe(1)
      const receipts = JSON.parse(String(confirmed[0].evidence)) as string[]
      expect(receipts).toHaveLength(2)
      for (const [index, kind] of ['observation', 'verification'].entries()) {
        expect(db.prepare('SELECT kind FROM evidence WHERE id = ?').get(receipts[index])?.kind).toBe(kind)
      }
      const transcript = JSON.stringify(db.prepare('SELECT content FROM messages').all())
      expect(transcript).not.toContain(fixtureCredential)
      expect(transcript).not.toContain(fixture.sensitiveFixtureValue)
    } finally {
      db.close()
    }
    const plan = new DatabaseSync(join(app.directory, 'agent-sessions', planningSession + '.sqlite'), { readOnly: true })
    try {
      expect(plan.prepare("SELECT count(*) AS n FROM entries WHERE json_extract(record, '$.kind') = 'pi.user'").get()?.n).toBe(1)
    } finally {
      plan.close()
    }
    expect(readdirSync(join(app.directory, 'agent-sessions')).filter(file => file.endsWith('.sqlite')).length).toBe(3)
    expect(fixture.requested.filter(url => url === primaryOrigin + '/')).toHaveLength(1)
    expect(fixture.requested.filter(url => url === unavailableOrigin + '/')).toHaveLength(2)
    expect(fixture.requested).not.toContain(excludedOrigin + '/')
    expect(fixture.accepted.filter(name => name.startsWith('plan-all:'))).toEqual(['plan-all:responses:0'])
    expect(fixture.unexpected).toEqual([])
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('revokes a host while its real fixture connection is pending and discards the result', async ({ page }) => {
  const fixture = await fixtureServer({ scenes: mainScenes, hold: unavailableOrigin + '/' })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await reviewScope(page, { project: 'Northstar', seeds, goal: allChecksGoal, live: true })
    await saveScope(page)
    await fixture.withheld
    await page.getByRole('button', { name: 'Review scope' }).click()
    await page.getByRole('checkbox', { name: 'Include docs.northstar.example' }).uncheck()
    await saveScope(page, 'Save scope revision')
    await expect(page.getByText('1 approved host · Revision 2')).toBeVisible()
    fixture.release()
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Complete report' })).toBeVisible({ timeout: 18_000 })
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).not.toContainText('docs.northstar.example')
    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    try {
      expect(db.prepare(`SELECT count(*) AS n FROM evidence JOIN assignments ON evidence.assignment_id = assignments.id
        WHERE assignments.title = 'Review docs.northstar.example' AND evidence.kind = 'observation'`).get()?.n).toBe(0)
    } finally {
      db.close()
    }
    expect(fixture.requested.filter(url => url === unavailableOrigin + '/')).toHaveLength(1)
    expect(fixture.unexpected).toEqual([])
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('keeps candidate evidence with its host and starts its review after explicit approval', async ({ page }) => {
  const fixture = await fixtureServer({
    scenes: ['connection', 'plan-all', 'response-primary', 'response-healthy'], hold: primaryOrigin + '/',
  })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await reviewScope(page, { project: 'Northstar', seeds: [primaryOrigin], goal: allChecksGoal, live: true })
    await saveScope(page)
    await fixture.withheld

    await page.getByRole('button', { name: 'Add candidate' }).click()
    await page.getByLabel('Host', { exact: true }).fill(healthyOrigin)
    await page.getByLabel('Source', { exact: true }).fill('Reviewed service inventory')
    await page.getByRole('button', { name: 'Add for review' }).click()
    const candidate = page.getByRole('row', { name: /healthy\.northstar\.example/ })
    await expect(candidate).toContainText('excluded')
    await page.reload()
    await candidate.getByRole('button', { name: 'Reviewed service inventory ↗' }).click()
    const source = page.getByRole('dialog')
    await expect(source).toContainText(healthyOrigin)
    await expect(source).toContainText('Reviewed service inventory')
    await expect(source).toContainText('Scope revision 1')
    await expect(source).not.toContainText(primaryOrigin)
    await source.getByRole('button', { name: 'Close', exact: true }).click()

    await page.getByRole('button', { name: 'Review scope' }).click()
    const include = page.getByRole('checkbox', { name: 'Include healthy.northstar.example' })
    await expect(include).not.toBeChecked()
    await include.check()
    await page.getByRole('button', { name: 'Save scope revision', exact: true }).click()
    await expect(page.getByText('1 approved host · Revision 1')).toBeVisible()
    expect(fixture.requested).toEqual([primaryOrigin + '/'])
    await saveScope(page, 'Save scope revision')
    await expect(page.getByText('2 approved hosts · Revision 2')).toBeVisible()
    const requested = [primaryOrigin + '/', healthyOrigin + '/']
    await expect.poll(() => fixture.requested).toEqual(requested)
    fixture.release()

    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('3 confirmed findings', { timeout: 18_000 })
    await expect(report).toContainText('2 approved hosts · Scope revision 2')
    await report.getByText('Checks for healthy.northstar.example', { exact: true }).click()
    await expect(report.getByText('Meets baseline', { exact: true })).toHaveCount(3)
    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    try {
      const approvals = db.prepare("SELECT detail FROM events WHERE kind = 'scope.approved' ORDER BY id").all()
        .map(row => JSON.parse(String(row.detail)).approved)
      expect(approvals).toEqual([[primaryOrigin], [primaryOrigin, healthyOrigin]])
    } finally {
      db.close()
    }
    expect(fixture.requested).toEqual(requested)
    expect(fixture.unexpected).toEqual([])
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('resumes a saved observation after narrowing scope for an unrelated host', async ({ page }) => {
  const fixture = await fixtureServer({
    scenes: [...mainScenes, 'coordinator-status'], holdModel: 'response-primary:responses:0', hold: unavailableOrigin + '/',
  })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await reviewScope(page, { project: 'Northstar', seeds, goal: allChecksGoal, live: true })
    await saveScope(page)
    await fixture.modelWithheld
    await fixture.withheld
    const chat = page.getByRole('region', { name: 'Coordinator chat' })
    const question = chat.getByRole('textbox', { name: 'Message coordinator' })
    await question.fill(statusQuestion)
    await question.press('Enter')
    await expect(chat.locator('[data-role=coordinator]')).toHaveCount(2)
    expect(fixture.accepted).toContain('coordinator-status:responses:0')
    const stale = await page.context().newPage()
    try {
      await stale.route('**/api/runs/*/events?*', route => route.abort())
      await stale.goto(page.url())
      await stale.getByRole('button', { name: 'Review scope' }).click()
      await expect(stale.getByRole('checkbox', { name: 'Include docs.northstar.example' })).toBeChecked()
      const consent = stale.getByRole('checkbox', { name: 'I authorize read-only review of the selected hosts.' })
      await consent.check()

      await page.getByRole('button', { name: 'Review scope' }).click()
      await page.getByRole('checkbox', { name: 'Include docs.northstar.example' }).uncheck()
      await saveScope(page, 'Save scope revision')
      await expect(page.getByText('1 approved host · Revision 2')).toBeVisible()
      await expect(stale.getByText('2 approved hosts · Revision 1')).toBeVisible()
      await stale.getByRole('button', { name: 'Save scope revision' }).click()
      await expect(stale.getByRole('alert')).toContainText('Scope changed since you opened this review.')
      await expect(stale.getByText('1 approved host · Revision 2')).toBeVisible()
      await stale.getByRole('button', { name: 'Review latest scope' }).click()
      await expect(stale.getByRole('checkbox', { name: 'Include northstar.example' })).toBeChecked()
      await expect(stale.getByRole('checkbox', { name: 'Include docs.northstar.example' })).not.toBeChecked()
      await expect(consent).not.toBeChecked()
    } finally {
      await stale.close()
    }

    await app.stop('SIGKILL')
    fixture.dropHeldModel()
    await app.start()
    const resume = page.getByRole('button', { name: 'Resume', exact: true })
    await expect(resume).toBeVisible()
    expect(fixture.requested.filter(url => url === primaryOrigin + '/')).toHaveLength(1)
    await resume.click()
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('3 confirmed findings', { timeout: 18_000 })
    await expect(report).not.toContainText('docs.northstar.example')
    expect(fixture.requested.filter(url => url === primaryOrigin + '/')).toHaveLength(1)
    expect(fixture.requested.filter(url => url === unavailableOrigin + '/')).toHaveLength(1)
    expect(fixture.unexpected).toEqual([])
    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    let sessionId: string
    try {
      expect(db.prepare(`SELECT evidence.scope_revision FROM evidence JOIN assignments ON evidence.assignment_id = assignments.id
        WHERE assignments.title = 'Review northstar.example' AND evidence.kind = 'observation'`).all())
        .toMatchObject([{ scope_revision: 1 }])
      sessionId = String(db.prepare("SELECT session_id FROM assignments WHERE title = 'Review northstar.example'").get()?.session_id)
    } finally {
      db.close()
    }
    const session = new DatabaseSync(join(app.directory, 'agent-sessions', sessionId + '.sqlite'), { readOnly: true })
    try {
      expect(session.prepare("SELECT count(*) AS n FROM entries WHERE json_extract(record, '$.kind') = 'pi.user'").get()?.n).toBe(1)
    } finally {
      session.close()
    }
  } finally {
    if (test.info().status !== test.info().expectedStatus) await test.info().attach('fixture activity', {
      body: JSON.stringify({ requested: fixture.requested, accepted: fixture.accepted, unexpected: fixture.unexpected }, null, 2),
      contentType: 'application/json',
    })
    await app.dispose()
    await fixture.close()
  }
})

test('returns from first-run model setup to the approved run and waits for explicit resume', async ({ page }) => {
  const fixture = await fixtureServer({ scenes: ['connection', 'plan-referrer', 'response-referrer'] })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await reviewScope(page, { project: 'Northstar', seeds: [primaryOrigin], goal: referrerGoal, live: true })
    await saveScope(page)
    const runPath = new URL(page.url()).pathname
    await expect(page.getByText('Waiting for model', { exact: true })).toBeVisible()
    await expect(page.getByText('1 approved host · Revision 1')).toBeVisible()
    await expect(page.getByText('Review plan pending', { exact: true })).toBeVisible()
    const coordinator = page.getByRole('region', { name: 'Coordinator chat' })
    const question = coordinator.getByRole('textbox', { name: 'Message coordinator' })
    await question.fill(statusQuestion)
    await question.press('Enter')
    await expect(coordinator).toContainText('This run needs a workspace model.')
    expect(fixture.requested).toEqual([])
    expect(fixture.accepted).toEqual([])
    await page.getByRole('button', { name: 'Pause', exact: true }).click()
    const resume = page.getByRole('button', { name: 'Resume', exact: true })
    await expect(resume).toBeVisible()

    await page.getByRole('link', { name: 'Set up model', exact: true }).click()
    await expect(page.getByRole('link', { name: /Back to run/ })).toHaveAttribute('href', runPath)
    await page.getByLabel('API key').fill('invalid-fixture-key')
    await page.getByText('Advanced provider settings', { exact: true }).click()
    await page.getByLabel('Base URL').fill(fixture.origin + '/api/v1')
    await page.getByRole('button', { name: 'Test connection', exact: true }).click()
    await expect(page.getByRole('alert')).toContainText('The provider rejected the API key.')
    await page.getByLabel('API key').fill(fixtureCredential)
    await page.getByRole('button', { name: 'Save model', exact: true }).click()
    await expect(page).toHaveURL(app.url + runPath)
    await expect(page.getByText('1 approved host · Revision 1')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Set up model', exact: true })).toHaveCount(0)
    expect(fixture.requested).toEqual([])
    expect(fixture.accepted.filter(name => name.startsWith('plan-'))).toEqual([])
    await resume.click()
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('1 confirmed finding', { timeout: 18_000 })
    await expect(report).toContainText('Planned checks · Referrer policy')
    await expect(report).toContainText('Referrer policy permits full cross-origin URLs')
    expect(fixture.requested).toEqual([primaryOrigin + '/'])
    expect(fixture.accepted.filter(name => name.startsWith('plan-'))).toEqual(['plan-referrer:responses:0'])
    expect(fixture.unexpected).toEqual([])
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('validates both model connections and produces a zero-finding Responses report', { tag: '@report-benchmark' }, async ({ page }) => {
  const fixture = await fixtureServer({ scenes: healthyScenes })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await page.getByRole('link', { name: 'Model settings' }).click()
    await page.getByLabel('API key').fill('invalid-fixture-key')
    await page.getByText('Advanced provider settings', { exact: true }).click()
    await page.getByLabel('Base URL').fill(fixture.origin + '/api/v1')
    await page.getByRole('button', { name: 'Test connection' }).click()
    await expect(page.getByRole('alert')).toContainText('The provider rejected the API key.')
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential, 'messages')
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential, 'responses')
    await reviewScope(page, { project: 'Healthy Northstar', seeds: [healthyOrigin], goal: allChecksGoal, live: true })
    await saveScope(page)
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Complete report' })).toBeVisible({ timeout: 18_000 })
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('No confirmed findings')
    await expect(report).toContainText('3 checks met baseline')
    await expect(report.getByRole('region', { name: 'Fix first' })).toHaveCount(0)
    await expect(report).toContainText('healthy.northstar.example')
    await expect(report.getByRole('button', { name: 'Open evidence' })).toBeVisible()
    await report.getByText('Checks for healthy.northstar.example', { exact: true }).click()
    await expect(report.getByText('Meets baseline', { exact: true })).toHaveCount(3)
    await expect(report).toContainText('31536000 seconds')
    await expect(report).toContainText('nosniff')
    await expect(report).toContainText('strict-origin-when-cross-origin')
    await expect(report).not.toContainText('Coverage gaps')
    const exported = await downloadReport(page, 'Markdown with evidence')
    const { content } = exported
    expect(content).toContain('No findings recorded.')
    expect(content).toContain('3 checks met baseline')
    expect(content).not.toContain('## Fix first')
    expect(content).toContain('"kind": "verification"')
    expect(content).toContain('"kind": "observation"')
    expect(content).toContain('"transportMaxAge": 31536000')
    expect(content).not.toContain('Supporting record unavailable')
    await collectReportBenchmark('response-healthy', app.directory, page.url(), exported)
    expect(fixture.unexpected).toEqual([])
    expect(fixture.accepted).toContain('connection:messages:0')
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('resumes a Messages analysis from its saved tool result and verifies the report', async ({ page }) => {
  const fixture = await fixtureServer({
    scenes: ['connection', 'plan-referrer', 'response-referrer'], holdModel: 'response-referrer:messages:1',
  })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  const beforeResume = ['connection:messages:0', 'plan-referrer:messages:0', 'response-referrer:messages:0']
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential, 'messages')
    await reviewScope(page, { project: 'Northstar Messages', seeds: [primaryOrigin], goal: referrerGoal, live: true })
    await saveScope(page)
    await fixture.modelWithheld
    expect(fixture.accepted).toEqual(beforeResume)
    expect(fixture.requested).toEqual([primaryOrigin + '/'])
    await page.getByRole('link', { name: /^Trace/ }).click()
    await page.getByRole('link', { name: 'Review northstar.example, running' }).click()
    const worker = page.getByRole('region', { name: 'Worker thread' })
    const derived = worker.locator('[data-role=worker]').filter({ hasText: 'Recorded the evidence command result.' })
      .getByRole('group', { name: 'Turn evidence' }).getByRole('button', { name: 'Derived evidence', exact: true })
    await expect(derived).toBeVisible()

    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    try {
      const analysisReceipts = db.prepare("SELECT id FROM evidence WHERE kind = 'analysis'")
      const originalReceipt = analysisReceipts.all()
      expect(originalReceipt).toHaveLength(1)
      const analysisTurns = db.prepare(`SELECT messages.id FROM messages JOIN json_each(messages.evidence_ids) AS attachment
        JOIN evidence ON evidence.id = attachment.value AND evidence.assignment_id = messages.thread_id
        WHERE evidence.kind = 'analysis'`)
      const originalTurn = analysisTurns.all()
      expect(originalTurn).toHaveLength(1)
      const assignment = db.prepare("SELECT session_id FROM assignments WHERE phase = 'analysis'").get()
      expect(typeof assignment?.session_id).toBe('string')
      await app.stop('SIGKILL')
      fixture.dropHeldModel()
      await app.start()

      const resume = page.getByRole('button', { name: 'Resume', exact: true })
      await expect(resume).toBeVisible()
      await expect(derived).toBeVisible()
      expect(fixture.accepted).toEqual(beforeResume)
      expect(fixture.requested).toEqual([primaryOrigin + '/'])
      await resume.click()
      await page.getByRole('link', { name: 'Report', exact: true }).click()
      const report = page.getByRole('article', { name: 'Complete report' })
      await expect(report).toContainText('1 confirmed finding', { timeout: 18_000 })
      await expect(report).toContainText('Planned checks · Referrer policy')
      await expect(report).toContainText('Referrer policy permits full cross-origin URLs')
      await expect(report).toContainText('unsafe-url')
      await report.getByRole('button', { name: 'Response policy verification' }).click()
      const verification = page.getByRole('dialog', { name: 'Response policy verification' })
      await expect(verification).toContainText('just-bash 3.6.1')
      await expect(verification).toContainText('"exitStatus": 0')
      expect(analysisReceipts.all()).toEqual(originalReceipt)
      expect(analysisTurns.all()).toEqual(originalTurn)
      expect(db.prepare("SELECT check_id FROM findings WHERE json_extract(finding, '$.status') = 'confirmed'").all())
        .toEqual([{ check_id: 'referrer-policy' }])

      const session = new DatabaseSync(join(app.directory, 'agent-sessions', String(assignment?.session_id) + '.sqlite'), { readOnly: true })
      try {
        const entries = session.prepare('SELECT count(*) AS n FROM entries WHERE json_extract(record, \'$.kind\') = ?')
        expect(entries.get('pi.user')?.n).toBe(1)
        expect(entries.get('pi.tool-result')?.n).toBe(1)
      } finally {
        session.close()
      }
    } finally {
      db.close()
    }
    expect(fixture.accepted).toEqual([...beforeResume, 'response-referrer:messages:1'])
    expect(fixture.requested).toEqual([primaryOrigin + '/'])
    expect(fixture.unexpected).toEqual([])
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('uses standard checks after planning fails and continues through an output-limited analysis', async ({ page }) => {
  const fixture = await fixtureServer({ scenes: healthyScenes, failModel: 'plan-all:responses:0' })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await reviewScope(page, { project: 'Healthy Northstar', seeds: [healthyOrigin], goal: allChecksGoal, live: true })
    await saveScope(page)
    await page.getByRole('link', { name: /^Trace/ }).click()
    const node = page.getByRole('link', { name: 'Review healthy.northstar.example, complete' })
    await expect(node).toBeVisible({ timeout: 12_000 })
    await node.click()
    const worker = page.getByRole('region', { name: 'Worker thread' })
    await expect(worker).toContainText('The model reached its output limit.')
    await worker.getByRole('button', { name: 'Derived evidence', exact: true }).click()
    await expect(page.getByRole('dialog', { name: 'Derived evidence' })).toContainText('transportMaxAge')
    await page.getByRole('button', { name: 'Close', exact: true }).click()
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('No confirmed findings')
    await expect(report).toContainText('Standard checks · HSTS policy, MIME sniffing protection, Referrer policy')
    expect(fixture.accepted.filter(name => name.startsWith('response-healthy:'))).toEqual(['response-healthy:responses:0'])
    expect(fixture.unexpected).toEqual([])
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('replaces an in-flight plan after a goal revision and delegates only the selected checks', async ({ page }) => {
  const fixture = await fixtureServer({
    scenes: ['connection', 'plan-all', 'plan-referrer', 'response-referrer'],
    holdModel: 'plan-all:responses:0',
  })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await reviewScope(page, { project: 'Northstar', seeds: [primaryOrigin], goal: allChecksGoal, thirdParty: excludedOrigin, live: true })
    await saveScope(page)
    await fixture.modelWithheld
    await expect(page.getByText('Preparing review plan', { exact: true })).toBeVisible()
    expect(fixture.requested).toEqual([])
    await page.getByRole('button', { name: 'Run actions', exact: true }).click()
    await page.getByRole('menuitem', { name: 'Revise goal' }).click()
    await page.getByRole('textbox', { name: 'Revise goal' }).fill(referrerGoal)
    await page.getByRole('button', { name: 'Save goal' }).click()

    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('1 confirmed finding', { timeout: 18_000 })
    await expect(report).toContainText('Planned checks · Referrer policy')
    await expect(report).toContainText('Scope revision 1 · Goal revision 1')
    await expect(report).toContainText('Referrer policy permits full cross-origin URLs')
    await expect(report).not.toContainText('HSTS max-age missing or disabled')
    await expect(report).not.toContainText('MIME sniffing protection missing')
    expect(fixture.requested).toEqual([primaryOrigin + '/'])
    expect(fixture.accepted.filter(name => name.startsWith('plan-'))).toEqual(['plan-referrer:responses:0'])
    expect(fixture.unexpected).toEqual([])

    await report.getByRole('button', { name: 'Response policy verification' }).click()
    const receipt = page.getByRole('dialog', { name: 'Response policy verification' })
    await expect(receipt).toContainText('"id": "referrer-policy"')
    await expect(receipt).not.toContainText('"id": "hsts"')
    await receipt.getByRole('link', { name: /Open worker thread/ }).click()
    const worker = page.getByRole('region', { name: 'Worker thread' })
    await worker.getByRole('button', { name: 'assignment.md', exact: true }).click()
    await expect(page.getByRole('dialog', { name: 'assignment.md' })).toContainText('Checks: Referrer policy')

    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    try {
      const planned = db.prepare("SELECT detail FROM events WHERE kind = 'review.planned'").all()
      expect(planned.map(row => JSON.parse(String(row.detail)))).toEqual([
        { goalRevision: 1, scopeRevision: 1, source: 'coordinator', checks: ['referrer-policy'] },
      ])
      expect(db.prepare('SELECT phase, goal_revision FROM assignments WHERE phase != ? ORDER BY phase').all('discovery'))
        .toMatchObject([{ phase: 'analysis', goal_revision: 1 }, { phase: 'verification', goal_revision: 1 }])
    } finally {
      db.close()
    }
  } finally {
    await app.dispose()
    await fixture.close()
  }
})
