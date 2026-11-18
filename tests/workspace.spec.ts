import { expect, test } from '@playwright/test'
import { request } from 'node:http'
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
    await page.getByLabel('Source', { exact: true }).fill('Supplier inventory')
    await page.getByLabel('Third-party service').check()
    await page.getByRole('button', { name: 'Add to project' }).click()
    await expect(page.getByText('help.vendor.example')).toBeVisible()
    await page.getByLabel('Run goal').fill('Review the public site evidence.')
    await page.getByRole('button', { name: 'Create run', exact: true }).click()
    await expect(page.getByText('Discovery consent', { exact: true }).first()).toBeVisible()
    await expect(page.getByRole('button', { name: 'Approve scope' })).toHaveCount(0)
    await page.getByLabel('I authorize discovery for these assets.').check()
    await page.getByRole('button', { name: 'Start discovery' }).click()
    await page.getByRole('button', { name: 'Review scope' }).click()
    await expect(page.getByLabel('Include help.vendor.example')).not.toBeChecked()
    await page.getByLabel('Include docs.northstar.example').uncheck()
    await page.getByRole('button', { name: 'Project seed ↗' }).first().click()
    await expect(page.getByRole('dialog')).toContainText('Supplied asset inventory')
    await page.getByRole('button', { name: 'Close', exact: true }).click()
    await expect(page.getByLabel('Include docs.northstar.example')).not.toBeChecked()
    await page.getByLabel('I authorize read-only review of the selected hosts.').check()
    await page.getByRole('button', { name: 'Approve scope' }).click()
    await expect(page.getByText('1 approved hosts · Revision 1')).toBeVisible()
    await page.getByRole('link', { name: /^Trace/ }).click()
    await page.getByRole('link', { name: 'Asset inventory, complete' }).click()
    await expect(page.getByRole('region', { name: 'Worker thread' })).toContainText('Supplied asset inventory')
    const deepLink = page.url()
    await app.stop('SIGKILL')
    await app.start()
    await expect(page.getByRole('button', { name: 'Resume', exact: true })).toBeVisible()
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
