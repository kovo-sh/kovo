import { expect, test } from '@playwright/test'
import { readdirSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { createApp } from './app.ts'
import { configureModel, reviewScope, saveScope } from './browser-flows.ts'
import { fixtureServer } from './fixture-server.ts'
import { excludedOrigin, fixtureCredential, healthyGoal, healthyOrigin, mainGoal, primaryOrigin, unavailableOrigin } from './scenarios.ts'

const mainScenes = ['connection', 'coordinator-main', 'primary', 'unavailable']
const seeds = [primaryOrigin, unavailableOrigin]

test('replays real provider streams through analysis, restart, explicit resume, and the final report', async ({ page }) => {
  const fixture = await fixtureServer({ scenes: mainScenes, hold: unavailableOrigin + '/' })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await reviewScope(page, { project: 'Northstar', seeds, goal: mainGoal, thirdParty: excludedOrigin, live: true })
    await expect(page.getByLabel('Include help.vendor.example')).not.toBeChecked()
    await saveScope(page)
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
    await page.getByLabel('Run actions', { exact: true }).click()
    await page.getByRole('button', { name: 'Stop run' }).click()
    await expect(page.getByRole('heading', { name: 'Partial report' })).toBeVisible()
    await page.getByRole('button', { name: 'Resume', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Complete report' })).toBeVisible({ timeout: 18_000 })
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('1 confirmed finding')
    await expect(report).toContainText('Inconclusive')
    await expect(report).toContainText('Coverage gaps')
    await report.getByRole('button', { name: 'Open finding evidence' }).first().click()
    await expect(page.getByRole('dialog')).toContainText('Observed public response')
    await expect(page.getByRole('dialog')).not.toContainText(fixture.sensitiveFixtureValue)
    await page.getByRole('button', { name: 'Close', exact: true }).click()
    const download = page.waitForEvent('download')
    await report.getByRole('button', { name: 'Export text' }).click()
    const exported = await (await download).createReadStream()
    let mark = ''
    for await (const chunk of exported) mark += String(chunk)
    expect(mark).not.toContain(fixtureCredential)
    expect(mark).not.toContain(fixture.sensitiveFixtureValue)
    expect(mark).toContain('Guardian complete report')

    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    try {
      expect(db.prepare("SELECT count(*) AS n FROM assignments WHERE phase = 'analysis' AND status = 'complete'").get()?.n).toBe(2)
      expect(db.prepare("SELECT count(*) AS n FROM reports").get()?.n).toBe(2)
      expect(db.prepare("SELECT count(*) AS n FROM findings").get()?.n).toBe(2)
    } finally {
      db.close()
    }
    expect(readdirSync(join(app.directory, 'agent-sessions')).filter(file => file.endsWith('.sqlite')).length).toBe(3)
    expect(fixture.requested.filter(url => url === primaryOrigin + '/')).toHaveLength(1)
    expect(fixture.requested.filter(url => url === unavailableOrigin + '/')).toHaveLength(2)
    expect(fixture.requested).not.toContain(excludedOrigin + '/')
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
    await reviewScope(page, { project: 'Northstar', seeds, goal: mainGoal, live: true })
    await saveScope(page)
    await fixture.withheld
    await page.getByRole('button', { name: 'Review scope' }).click()
    await page.getByLabel('Include docs.northstar.example').uncheck()
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

test('verifies both model protocols and produces a zero-finding report with coverage', async ({ page }) => {
  const fixture = await fixtureServer({ scenes: ['connection', 'coordinator-healthy', 'healthy'] })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential, 'messages')
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential, 'responses')
    await reviewScope(page, { project: 'Healthy Northstar', seeds: [healthyOrigin], goal: healthyGoal, live: true })
    await saveScope(page)
    await page.getByRole('link', { name: 'Report', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Complete report' })).toBeVisible({ timeout: 18_000 })
    const report = page.getByRole('article', { name: 'Complete report' })
    await expect(report).toContainText('No confirmed findings')
    await expect(report).toContainText('healthy.northstar.example')
    await expect(report.getByRole('button', { name: 'Open evidence' })).toBeVisible()
    expect(fixture.unexpected).toEqual([])
    expect(fixture.accepted).toContain('connection:messages:0')
  } finally {
    await app.dispose()
    await fixture.close()
  }
})
