import { expect, test } from '@playwright/test'
import { readdirSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { createApp } from './app.ts'
import { configureModel, reviewScope, saveScope } from './browser-flows.ts'
import { fixtureServer } from './fixture-server.ts'
import {
  allChecksGoal, excludedOrigin, fixtureCredential, healthyOrigin, primaryOrigin, referrerGoal, statusQuestion, unavailableOrigin,
} from './scenarios.ts'

const mainScenes = ['connection', 'plan-all', 'response-primary', 'response-unavailable']
const healthyScenes = ['connection', 'plan-all', 'response-healthy']
const seeds = [primaryOrigin, unavailableOrigin]

test('replays real provider streams through analysis, restart, explicit resume, and the final report', async ({ page }) => {
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
    await expect(partial).toContainText('Verification pending')
    await expect(partial).toContainText('Planned checks · HSTS policy, MIME sniffing protection, Referrer policy')
    await page.getByRole('button', { name: 'Resume', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Complete report' })).toBeVisible({ timeout: 18_000 })
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('3 confirmed findings')
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
    await expect(page.getByRole('region', { name: 'Worker thread' })).toContainText('Verify northstar.example')
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    const download = page.waitForEvent('download')
    await report.getByRole('button', { name: 'Export text' }).click()
    const exported = await (await download).createReadStream()
    let mark = ''
    for await (const chunk of exported) mark += String(chunk)
    expect(mark).not.toContain(fixtureCredential)
    expect(mark).not.toContain(fixture.sensitiveFixtureValue)
    expect(mark).toContain('Guardian complete report')
    expect(mark).toContain('Referrer policy · Gap found')
    expect(mark).toContain('Observed: unsafe-url')
    expect(mark).toContain('Check the fix:')

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
    await expect(page.getByText('1 approved hosts · Revision 2')).toBeVisible()
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
    await page.getByRole('button', { name: 'Review scope' }).click()
    await page.getByRole('checkbox', { name: 'Include docs.northstar.example' }).uncheck()
    await saveScope(page, 'Save scope revision')
    await expect(page.getByText('1 approved hosts · Revision 2')).toBeVisible()

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
    expect(fixture.requested.filter(url => url === primaryOrigin + '/')).toHaveLength(1)
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

test('verifies both model protocols and produces a zero-finding report with coverage', async ({ page }) => {
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
    await expect(report).toContainText('healthy.northstar.example')
    await expect(report.getByRole('button', { name: 'Open evidence' })).toBeVisible()
    await report.getByText('Checks for healthy.northstar.example', { exact: true }).click()
    await expect(report.getByText('Meets baseline', { exact: true })).toHaveCount(3)
    await expect(report).toContainText('31536000 seconds')
    await expect(report).toContainText('nosniff')
    await expect(report).toContainText('strict-origin-when-cross-origin')
    await expect(report).not.toContainText('Coverage gaps')
    expect(fixture.unexpected).toEqual([])
    expect(fixture.accepted).toContain('connection:messages:0')
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
