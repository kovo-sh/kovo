import assert from 'node:assert/strict'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { chromium } from '@playwright/test'
import { DEFAULT_PROVIDER } from '../src/domain.ts'
import { createApp } from '../tests/app.ts'
import { reviewScope, saveScope } from '../tests/browser-flows.ts'

const args = process.argv.slice(2)
const resume = args.length === 3 && args[1] === '--resume' ? resolve(args[2]) : undefined
if (args[0] !== '--live' || (args.length !== 1 && !resume)) {
  throw new Error('Pass --live to run the approved smoke check, or --live --resume <data-directory> to finish the same run.')
}

const seeds = ['https://dyad.sh', 'https://www.dyad.sh']
const hosts = seeds.map(seed => new URL(seed).hostname)
const app = await createApp({ GUARDIAN_OFFLINE: '0', GUARDIAN_NETWORK_FIXTURE: '' }, resume)
let stage = 'production startup'
let runPath: string | undefined

function savedRun(directory: string) {
  const db = new DatabaseSync(join(directory, 'guardian.sqlite'), { readOnly: true })
  try {
    const runs = db.prepare('SELECT id, status, source_mode, candidates, approved FROM runs').all()
    assert.equal(runs.length, 1)
    const run = runs[0]
    assert.equal(run.source_mode, 'public')
    const candidates = JSON.parse(String(run.candidates)) as { id: string; origin: string }[]
    const approved = JSON.parse(String(run.approved)) as string[]
    assert.deepEqual(candidates.filter(candidate => approved.includes(candidate.id)).map(candidate => candidate.origin).sort(), [...seeds].sort())
    const config = db.prepare('SELECT endpoint, model, protocol FROM model_config').get()
    assert.equal(config?.endpoint, DEFAULT_PROVIDER.endpoint)
    assert.equal(config?.model, DEFAULT_PROVIDER.model)
    assert.equal(config?.protocol, 'responses')
    return { path: `/runs/${run.id}`, status: run.status }
  } finally {
    db.close()
  }
}

try {
  const existing = resume && savedRun(resume)
  await app.start()
  const browser = await chromium.launch()
  try {
    const page = await browser.newPage({ colorScheme: 'light', reducedMotion: 'reduce' })
    page.setDefaultTimeout(12_000)
    const resumeButton = page.getByRole('button', { name: 'Resume', exact: true })
    if (existing) {
      runPath = existing.path
      stage = 'explicit resume of the same run'
      await page.goto(app.url + runPath + '?view=report')
      if (existing.status !== 'complete') {
        await resumeButton.click()
        await resumeButton.waitFor({ state: 'hidden' })
      }
    } else {
      await page.goto(app.url)
      stage = 'OpenRouter connection and workspace save'
      const credentialPath = join(homedir(), '.config', 'guardian-fixtures', 'openrouter.key')
      if (statSync(credentialPath).mode & 0o077) throw new Error('The smoke credential must have owner-only permissions.')
      await page.getByRole('link', { name: 'Model settings' }).click()
      await page.getByLabel('API key').fill(readFileSync(credentialPath, 'utf8').trim())
      await page.getByRole('button', { name: 'Test connection' }).click()
      await page.getByRole('status').filter({ hasText: 'Connection verified' }).waitFor({ timeout: 40_000 })
      await page.getByRole('button', { name: 'Save model' }).click()
      await page.getByRole('status').filter({ hasText: 'Model saved' }).waitFor()
      await page.getByRole('link', { name: 'Projects', exact: true }).click()

      stage = 'individual host approvals'
      await reviewScope(page, {
        project: 'Dyad public website', seeds, live: true,
        goal: 'Record the HTTPS transport policy shown by the approved public home pages.',
      })
      runPath = new URL(page.url()).pathname
      for (const host of hosts) await page.getByRole('checkbox', { name: `Include ${host}`, exact: true }).check()
      await saveScope(page)
      await page.getByRole('link', { name: 'Report', exact: true }).click()
    }

    stage = 'live analysis and complete report'
    const report = page.getByRole('article', { name: 'Complete report' })
    await report.or(resumeButton).first().waitFor({ timeout: 100_000 })
    assert.ok(await report.isVisible())
    for (const host of hosts) await report.getByText(host, { exact: true }).first().waitFor()
    await report.getByRole('button', { name: 'Open evidence', exact: true }).first().click()
    const verificationTitle = /^(Transport|Response) policy verification$/
    const evidence = page.getByRole('dialog', { name: verificationTitle })
    await evidence.waitFor()
    await evidence.getByRole('link', { name: /Open worker thread/ }).click()
    const worker = page.getByRole('region', { name: 'Worker thread' })
    await worker.getByRole('button', { name: verificationTitle }).waitFor()
    assert.equal(await worker.getByRole('textbox').count(), 0)

    stage = 'durable approval, request audit, and evidence'
    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    try {
      const runId = runPath.split('/')[2]
      const config = db.prepare('SELECT model, protocol FROM model_config').get()
      assert.equal(config?.model, DEFAULT_PROVIDER.model)
      assert.equal(config?.protocol, 'responses')
      const approval = db.prepare("SELECT detail FROM events WHERE run_id = ? AND kind = 'scope.approved'").get(runId)
      const approved = JSON.parse(String(approval?.detail)).approved as string[]
      assert.deepEqual([...approved].sort(), [...seeds].sort())
      const reads = db.prepare("SELECT detail FROM events WHERE run_id = ? AND kind = 'broker.allowed'").all(runId)
      assert.ok(reads.length > 0 && reads.length <= 8)
      for (const row of reads) assert.ok(seeds.includes(JSON.parse(String(row.detail)).origin))
      const observed = db.prepare("SELECT detail FROM events WHERE run_id = ? AND kind = 'broker.observed' ORDER BY id").all(runId)
        .map(row => JSON.parse(String(row.detail)) as { origin: string; status: number })
      assert.ok(observed.some(({ status }) => status >= 200 && status < 300))
      const captures = db.prepare("SELECT id FROM evidence WHERE run_id = ? AND kind = 'observation'").all(runId)
        .map(({ id }) => {
          const flat = join(app.directory, 'artifacts', `${id}.txt`)
          if (existsSync(flat)) return JSON.parse(readFileSync(flat, 'utf8'))
          // v6 sharded layout: artifacts/<runId>/<bucket>/<id>.txt
          const runArtifacts = join(app.directory, 'artifacts', runId)
          const bucket = readdirSync(runArtifacts).find(name => existsSync(join(runArtifacts, name, `${id}.txt`)))
          assert.ok(bucket, `missing artifact ${id}`)
          return JSON.parse(readFileSync(join(runArtifacts, bucket, `${id}.txt`), 'utf8'))
        })
      assert.ok(captures.some(({ observation }) => observation?.source === 'public response'))
      const sessions = readdirSync(join(app.directory, 'agent-sessions')).filter(file => file.endsWith('.sqlite'))
      assert.ok(sessions.length >= 2)
      const savedReport = db.prepare('SELECT version, partial, body FROM reports WHERE run_id = ? ORDER BY version DESC LIMIT 1').get(runId)
      assert.equal(savedReport?.partial, 0)
      const body = JSON.parse(String(savedReport?.body))
      assert.ok(body.coverage.every((item: { evidenceId: string }) => item.evidenceId))
      const derivedCount = db.prepare("SELECT count(*) AS n FROM evidence WHERE run_id = ? AND kind = 'analysis'").get(runId)?.n
      assert.ok(Number(derivedCount) > 0)
      console.log(JSON.stringify({
        result: 'passed', model: config.model, observed, approved, requests: reads.length, version: savedReport?.version,
        coverage: body.coverage.length, findings: body.findings.length, derivedCount, sessions: sessions.length,
        dataDirectory: app.directory, reportPath: runPath + '?view=report',
      }, null, 2))
    } finally {
      db.close()
    }
  } finally {
    await browser.close()
  }
} catch {
  // Browser errors can contain form values. Print only the failed step and local storage location.
  console.error(`Live smoke stopped at ${stage}. Data directory ${app.directory}${runPath ? `, run ${runPath}` : ''}.`)
  process.exitCode = 1
} finally {
  await app.stop()
}
