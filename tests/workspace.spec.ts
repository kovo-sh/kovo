import { expect, test } from '@playwright/test'
import { existsSync } from 'node:fs'
import { request } from 'node:http'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { createApp } from './app.ts'
import { enterModelSettings } from './browser-flows.ts'
import { fixtureServer } from './fixture-server.ts'
import { fixtureCredential } from './scenarios.ts'

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
    await expect(page.getByText('1 approved host · Revision 1')).toBeVisible()
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
    await expect(page.getByRole('link', { name: /Review northstar\.example/ })).toHaveCount(0)
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

test('rechecks credentials on save after the provider rejects a previously verified key', async ({ page }) => {
  const fixture = await fixtureServer({ scenes: ['connection'] })
  const app = await createApp()
  try {
    await app.start()
    await page.goto(app.url)
    await enterModelSettings(page, fixture.origin + '/api/v1', fixtureCredential)
    const check = page.getByRole('button', { name: 'Test connection' })
    const verified = page.getByRole('status').filter({ hasText: 'Connection verified' })
    await check.click()
    await expect(verified).toBeVisible()

    fixture.revokeKey()
    await check.click()
    const alert = page.getByRole('alert')
    await expect(alert).toContainText('The provider rejected the API key.')
    await expect(verified).toHaveCount(0)
    expect(fixture.authorizationFailures).toBe(1)
    await page.getByRole('button', { name: 'Save model' }).click()
    await expect.poll(() => fixture.authorizationFailures).toBe(2)
    await expect(alert).toContainText('The provider rejected the API key.')
    expect(existsSync(join(app.directory, 'credentials'))).toBe(false)
    expect(fixture.unexpected).toEqual([])
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

test('imports attributed DNS candidates and requires their own scope selection', async ({ page }) => {
  const app = await createApp()
  try {
    await app.start()
    await page.goto(app.url)
    await page.getByLabel('Project name').fill('Northstar')
    await page.getByLabel('Seed hosts').fill('northstar.example')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await page.getByRole('button', { name: 'Import DNS export' }).click()
    const file = page.getByLabel('DNS export', { exact: true })
    await file.setInputFiles({ name: 'invalid.zone', mimeType: 'text/plain', buffer: Buffer.from('$INCLUDE other.zone') })
    await page.getByRole('button', { name: 'Review import' }).click()
    await expect(page.getByRole('alert')).toContainText('Use a self-contained DNS export')
    const privateValue = 'inert-private-asset-inventory-value'
    await file.setInputFiles({ name: 'northstar.zone', mimeType: 'text/plain', buffer: Buffer.from([
      '$ORIGIN northstar.example.',
      '$TTL 1h',
      '@ IN SOA ns admin (',
      '  100 1h 1h 1d 60 )',
      '@ IN A 192.0.2.10',
      'api 300 IN A 192.0.2.20',
      '    IN AAAA 2001:db8::20',
      'partner IN CNAME www.vendor.example.',
      `tracking IN TXT "${privateValue}; ignored"`,
      '* IN A 192.0.2.42',
      'outside.example. IN A 192.0.2.90',
    ].join('\n')) })
    await page.getByRole('button', { name: 'Review import' }).click()
    const preview = page.getByRole('region', { name: 'DNS import preview' })
    await expect(preview).toContainText('3 hosts in northstar.example')
    await expect(preview).toContainText('A, AAAA')
    await expect(preview).toContainText('Third-party alias · www.vendor.example')
    await expect(preview).not.toContainText('outside.example')
    await expect(preview).not.toContainText(privateValue)
    await preview.getByRole('button', { name: 'Import hosts' }).click()
    await expect(page.getByRole('status')).toContainText('Added 2 hosts. Skipped 1 existing.')
    await expect(page.getByText('Project seed', { exact: true })).toBeVisible()

    await page.getByLabel('Run goal').fill('Review the declared public web inventory.')
    await page.getByRole('button', { name: 'Create run', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Discovery consent' })).toBeVisible()
    await page.getByRole('checkbox', { name: 'I authorize discovery for these assets.' }).check()
    await page.getByRole('button', { name: 'Start discovery' }).click()
    await page.getByRole('button', { name: 'Review scope' }).click()
    const api = page.getByRole('checkbox', { name: 'Include api.northstar.example' })
    await expect(api).not.toBeChecked()
    await expect(page.getByRole('checkbox', { name: 'Include partner.northstar.example' })).not.toBeChecked()
    await expect(page.getByRole('checkbox', { name: 'Include www.vendor.example' })).toHaveCount(0)
    await page.getByRole('button', { name: 'DNS export · A, AAAA ↗' }).click()
    const evidence = page.getByRole('dialog', { name: 'Supplied asset inventory' })
    await expect(evidence).toContainText('externalAliases')
    await expect(evidence).toContainText('www.vendor.example')
    await expect(evidence).not.toContainText(privateValue)
    await expect(evidence).not.toContainText('192.0.2.20')
    await page.getByRole('button', { name: 'Close', exact: true }).click()
    await api.check()
    await page.getByRole('checkbox', { name: 'I authorize read-only review of the selected hosts.' }).check()
    await page.getByRole('button', { name: 'Approve scope' }).click()
    await expect(page.getByText('2 approved hosts · Revision 1')).toBeVisible()
    await expect(page.getByRole('row', { name: /api\.northstar\.example/ })).toContainText('approved')
    await expect(page.getByRole('row', { name: /partner\.northstar\.example/ })).toContainText('excluded')
    await page.getByRole('link', { name: /^Trace/ }).click()
    await expect(page.getByRole('link', { name: 'Set up model', exact: true })).toBeVisible()
    await expect(page.getByLabel('Worker graph').getByRole('link', { name: /^Review / })).toHaveCount(0)
  } finally {
    await app.dispose()
  }
})
