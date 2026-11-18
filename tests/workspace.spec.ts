import { expect, test } from '@playwright/test'
import { request } from 'node:http'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { createApp } from './app.ts'

test('persists project, approval, and worker context across production restarts', async ({ page }) => {
  const app = await createApp()
  const pageErrors: string[] = []
  page.on('pageerror', error => pageErrors.push(error.message))
  try {
    await app.start()
    await page.goto(app.url)
    await page.getByLabel('Project name').fill('Northstar')
    await page.getByLabel('Seed hosts').fill('northstar.example\ndocs.northstar.example')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Northstar' })).toBeVisible()
    await page.getByRole('button', { name: 'Add candidate' }).click()
    await page.getByLabel('Host', { exact: true }).fill('help.vendor.example')
    await page.getByLabel('Source', { exact: true }).fill('Supplier inventory <em>untrusted</em>')
    await page.getByRole('checkbox', { name: 'Third-party service' }).check()
    await page.getByRole('button', { name: 'Add to project' }).click()
    await expect(page.getByText('help.vendor.example')).toBeVisible()
    await page.getByLabel('Run goal').fill('Review the public site evidence.')
    await page.getByRole('button', { name: 'Create run', exact: true }).click()
    await expect(page.getByText('Discovery consent', { exact: true }).first()).toBeVisible()
    await expect(page.getByRole('button', { name: 'Approve scope' })).toHaveCount(0)
    await page.getByRole('button', { name: 'Start discovery' }).click()
    await expect(page.getByRole('button', { name: 'Review scope' })).toHaveCount(0)
    await page.getByRole('checkbox', { name: 'I authorize discovery for these assets.' }).check()
    await page.getByRole('button', { name: 'Start discovery' }).click()
    await page.getByRole('button', { name: 'Review scope' }).click()
    await expect(page.getByRole('checkbox', { name: 'Include help.vendor.example' })).not.toBeChecked()
    await page.getByRole('checkbox', { name: 'Include docs.northstar.example' }).uncheck()
    await page.getByRole('button', { name: 'Project seed ↗' }).first().click()
    const inventory = page.getByRole('dialog', { name: 'Supplied asset inventory' })
    await expect(inventory).toContainText('Supplier inventory <em>untrusted</em>')
    await expect(inventory.locator('em')).toHaveCount(0)
    await page.getByRole('button', { name: 'Close', exact: true }).click()
    await expect(page.getByRole('checkbox', { name: 'Include docs.northstar.example' })).not.toBeChecked()
    await page.getByRole('checkbox', { name: 'I authorize read-only review of the selected hosts.' }).check()
    await page.getByRole('button', { name: 'Approve scope' }).click()
    await expect(page.getByText('1 approved hosts · Revision 1')).toBeVisible()
    await page.getByRole('button', { name: 'Run actions', exact: true }).click()
    await page.getByRole('menuitem', { name: 'Revise goal' }).click()
    await page.getByRole('textbox', { name: 'Revise goal' }).fill('Review only the public transport policy.')
    await page.getByRole('button', { name: 'Save goal' }).click()
    await expect(page.getByRole('region', { name: 'Coordinator chat' })).toContainText('Revised goal: Review only the public transport policy.')
    await page.getByRole('button', { name: 'Add candidate' }).click()
    await page.getByLabel('Host', { exact: true }).fill('blog.northstar.example')
    await page.getByLabel('Source', { exact: true }).fill('New service inventory record')
    await page.getByRole('button', { name: 'Add for review' }).click()
    await expect(page.getByRole('row', { name: /blog\.northstar\.example/ })).toContainText('excluded')
    await page.getByRole('button', { name: 'Review scope' }).click()
    await expect(page.getByRole('checkbox', { name: 'Include blog.northstar.example' })).not.toBeChecked()
    await page.getByRole('link', { name: /^Trace/ }).click()
    await expect(page.getByRole('link', { name: 'Review northstar.example, canceled' })).toHaveCount(1)
    await expect(page.getByRole('link', { name: 'Review northstar.example, queued' })).toHaveCount(1)
    await expect(page.getByRole('link', { name: /Review blog\.northstar\.example/ })).toHaveCount(0)
    await page.getByRole('link', { name: 'Asset inventory, complete' }).click()
    await expect(page.getByRole('region', { name: 'Worker thread' })).toContainText('Supplied asset inventory')
    const deepLink = page.url()
    const runId = new URL(deepLink).pathname.split('/')[2]
    const db = new DatabaseSync(join(app.directory, 'guardian.sqlite'), { readOnly: true })
    const lastEvent = db.prepare('SELECT max(id) AS id FROM events WHERE run_id = ?').get(runId)?.id as number
    db.close()
    await app.stop('SIGKILL')
    await app.start()
    await expect(page.getByRole('button', { name: 'Resume', exact: true })).toBeVisible()
    const localSession = (await page.context().cookies(app.url)).find(cookie => cookie.name === 'guardian_local')!
    const replay = await fetch(`${app.url}/api/runs/${runId}/events?since=0`, {
      headers: { cookie: `guardian_local=${localSession.value}`, 'Last-Event-ID': String(lastEvent) },
      signal: AbortSignal.timeout(4_000),
    })
    expect(replay.status).toBe(200)
    const reader = replay.body!.getReader()
    let stream = ''
    try {
      const decode = new TextDecoder()
      while (!stream.includes('"kind":"interrupted"')) {
        const { done, value } = await reader.read()
        if (done) break
        stream += decode.decode(value, { stream: true })
      }
    } finally {
      await reader.cancel()
    }
    expect([...stream.matchAll(/^id: (\d+)$/gm)].map(match => Number(match[1]))).toEqual([lastEvent + 1])
    await page.goto(deepLink)
    await expect(page.getByRole('region', { name: 'Worker thread' })).toContainText('Asset inventory')
    await expect(page.getByRole('button', { name: 'Resume', exact: true })).toBeVisible()
    expect(pageErrors).toEqual([])
  } finally {
    await app.dispose()
  }
})

test('guards host, origin, and unauthenticated event streams', async ({ request: client }) => {
  const app = await createApp()
  try {
    await app.start()
    const response = await new Promise<number | undefined>((resolve, reject) => {
      const req = request(app.url + '/health', { headers: { host: 'unexpected.example' } }, value => {
        value.resume()
        resolve(value.statusCode)
      })
      req.on('error', reject).end()
    })
    expect(response).toBe(421)
    expect((await client.post(app.url + '/_serverFn/test', { headers: { origin: 'https://outside.example' } })).status()).toBe(403)
    expect((await client.get(app.url + '/api/runs/abc/events')).status()).toBe(401)
  } finally {
    await app.dispose()
  }
})
