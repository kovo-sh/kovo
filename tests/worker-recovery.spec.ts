import { expect, test } from '@playwright/test'
import { execFile, execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { delimiter, join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { promisify } from 'node:util'
import { createApp } from './app.ts'
import { configureModel, openScopeReview, saveScope } from './browser-flows.ts'
import { fixtureServer } from './fixture-server.ts'
import { accessPolicy, accessPolicyGoal, fixtureCredential, primaryOrigin } from './scenarios.ts'

const exec = promisify(execFile)

async function containerState(name: string) {
  const { stdout } = await exec('docker', ['container', 'ls', '--all', '--filter', 'name=' + name,
    '--format', '{{.Names}}\t{{.State}}'])
  return stdout.split('\n').find(row => row.startsWith(name + '\t'))?.split('\t')[1]
}

test('cleans up a created worker after a server crash and waits for explicit resume', async ({ page }) => {
  const gate = await mkdtemp(join(tmpdir(), 'guardian-worker-gate-'))
  const marker = join(gate, 'created')
  const realDocker = execFileSync('which', ['docker'], { encoding: 'utf8' }).trim()
  // Hold only the first start. Docker still creates the real container and handles every other command.
  await writeFile(join(gate, 'docker'), `#!/usr/bin/env node
const { existsSync, writeFileSync } = require('node:fs')
const { spawnSync } = require('node:child_process')
const args = process.argv.slice(2)
const marker = ${JSON.stringify(marker)}
if (args[0] === 'container' && args[1] === 'start' && !existsSync(marker)) {
  const parent = process.ppid
  writeFileSync(marker, args.at(-1), { flag: 'wx' })
  setInterval(() => {
    try { process.kill(parent, 0) } catch { process.exit(1) }
  }, 30)
  setTimeout(() => process.exit(1), 15_000)
} else {
  process.exit(spawnSync(${JSON.stringify(realDocker)}, args, { stdio: 'inherit' }).status ?? 1)
}
`, { mode: 0o700 })
  const fixture = await fixtureServer({ scenes: ['connection', 'plan-access-policy'] })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin, PATH: gate + delimiter + process.env.PATH })
  const other = 'guardian-' + randomUUID()
  const readMarker = () => readFile(marker, 'utf8').catch(() => '')
  try {
    await app.start()
    await page.goto(app.url)
    await configureModel(page, fixture.origin + '/api/v1', fixtureCredential)
    await page.getByLabel('Project name').fill('Northstar')
    await page.getByLabel('Seed hosts').fill(primaryOrigin)
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await page.getByRole('button', { name: 'Import access records' }).click()
    await page.getByLabel('Access policy JSON').setInputFiles({
      name: 'authorization-decisions.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(accessPolicy)),
    })
    await page.getByRole('button', { name: 'Review records' }).click()
    await page.getByRole('button', { name: 'Import records' }).click()
    await expect(page.getByRole('status')).toContainText('Imported 4 access cases')
    await openScopeReview(page, accessPolicyGoal, true)
    await saveScope(page)

    await expect.poll(readMarker).toMatch(/^guardian-[0-9a-f-]{36}$/)
    const orphan = await readMarker()
    expect(await containerState(orphan)).toBe('created')
    const { stdout: label } = await exec('docker', ['container', 'inspect', '--format',
      '{{index .Config.Labels "dev.guardian.assignment"}}', orphan])
    const assignmentId = label.trim()
    expect(assignmentId).toMatch(/^[0-9a-f-]{36}$/)
    await exec('docker', ['container', 'create', '--rm', '--network', 'none', '--pull', 'never', '--name', other,
      '--label', 'dev.guardian.assignment=' + assignmentId, '--label', 'dev.guardian.workspace=' + 'b'.repeat(64),
      'guardian-worker:local'])
    await app.stop('SIGKILL')
    expect(await containerState(orphan)).toBe('created')

    await app.start()
    const resume = page.getByRole('button', { name: 'Resume', exact: true })
    await expect(resume).toBeVisible()
    await expect.poll(() => containerState(orphan)).toBeUndefined()
    expect(await containerState(other)).toBe('created')
    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    try {
      expect(db.prepare('SELECT status, lease FROM assignments WHERE id = ?').get(assignmentId))
        .toMatchObject({ status: 'paused', lease: null })
      expect(db.prepare('SELECT count(*) AS n FROM reports').get()?.n).toBe(0)
      await resume.click()
      await page.getByRole('link', { name: 'Report', exact: true }).click()
      await expect(page.getByRole('article', { name: 'Complete report' })).toContainText('2 confirmed findings', { timeout: 18_000 })
      expect(db.prepare("SELECT id FROM assignments WHERE phase = 'verification'").all()).toEqual([{ id: assignmentId }])
      expect(db.prepare("SELECT assignment_id FROM evidence WHERE kind = 'verification'").all()).toEqual([{ assignment_id: assignmentId }])
    } finally {
      db.close()
    }
    expect(fixture.requested).toEqual([])
    expect(fixture.accepted.filter(call => call.startsWith('plan-access-policy:'))).toEqual(['plan-access-policy:responses:0'])
    expect(fixture.unexpected).toEqual([])
    expect(await containerState(other)).toBe('created')
  } finally {
    await app.dispose()
    await fixture.close()
    const orphan = await readMarker()
    for (const name of [orphan, other].filter(name => /^guardian-[0-9a-f-]{36}$/.test(name))) {
      await exec('docker', ['container', 'rm', '--force', name]).catch(() => undefined)
    }
    await rm(gate, { recursive: true, force: true })
  }
})
