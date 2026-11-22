import { expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import { DEFAULT_PROVIDER } from '../src/domain.ts'

export async function enterModelSettings(
  page: Page,
  base: string,
  key: string,
  protocol: 'messages' | 'responses' = 'responses',
  model = DEFAULT_PROVIDER.model,
) {
  await page.getByRole('link', { name: 'Model settings' }).click()
  await page.getByLabel('API key').fill(key)
  await page.getByText('Advanced provider settings', { exact: true }).click()
  await page.getByLabel('Base URL').fill(base)
  await page.getByLabel('Model ID').fill(model)
  await page.getByLabel('Protocol').selectOption(protocol)
}

export async function configureModel(
  page: Page,
  base: string,
  key: string,
  protocol: 'messages' | 'responses' = 'responses',
  model = DEFAULT_PROVIDER.model,
) {
  await enterModelSettings(page, base, key, protocol, model)
  await page.getByRole('button', { name: 'Test connection' }).click()
  await page.getByRole('status').filter({ hasText: 'Connection verified' }).waitFor({ timeout: 20_000 })
  await page.getByRole('button', { name: 'Save model' }).click()
  await page.getByRole('status').filter({ hasText: /Model profile (added|updated)/ }).waitFor({ timeout: 20_000 })
  await page.getByRole('link', { name: 'Projects', exact: true }).click()
}

export async function reviewScope(page: Page, options: {
  project: string
  seeds: string[]
  goal: string
  thirdParty?: string
  live?: boolean
}) {
  await page.getByLabel('Project name').fill(options.project)
  await page.getByLabel('Seed hosts').fill(options.seeds.join('\n'))
  await page.getByRole('button', { name: 'Create project', exact: true }).click()
  if (options.thirdParty) {
    await page.getByRole('button', { name: 'Add candidate' }).click()
    await page.getByLabel('Host', { exact: true }).fill(options.thirdParty)
    await page.getByLabel('Source', { exact: true }).fill('Supplier inventory')
    await page.getByRole('checkbox', { name: 'Third-party service' }).check()
    await page.getByRole('button', { name: 'Add to project' }).click()
    await page.getByRole('button', { name: 'Add to project' }).waitFor({ state: 'hidden' })
  }
  await openScopeReview(page, options.goal, options.live ? 1 : 0)
}

export async function openScopeReview(page: Page, goal: string, tier: 0 | 1 | 2 | 3 = 1) {
  await page.getByLabel('Run goal').fill(goal)
  await page.getByLabel('Capability tier').selectOption(String(tier))
  await page.getByRole('button', { name: 'Create run', exact: true }).click()
  // The run page opens on the consent sheet: approving discovery sends after the undo window.
  await expect(page.getByText('Waiting on your consent')).toBeVisible({ timeout: 20_000 })
  await page.getByRole('button', { name: /^Approve & start/ }).click()
  // Discovery finishes on the project seeds and the same sheet asks for the scope review.
  await expect(page.getByText('Waiting on your scope approval')).toBeVisible({ timeout: 30_000 })
}

/**
 * Approve the reviewed scope on the consent sheet, or save a scope revision in the
 * "Edit scope" dialog. Both send when the 6 s undo window closes.
 */
export async function saveScope(page: Page, label: 'Approve scope' | 'Save scope revision' = 'Approve scope') {
  if (label === 'Approve scope') {
    await page.getByRole('button', { name: /^Approve & start/ }).click()
    await expect(page.getByText('Approved · ', { exact: false })).toBeVisible()
  } else {
    await page.getByRole('dialog', { name: 'Edit scope' }).getByRole('button', { name: label, exact: true }).click()
  }
}

/** Switch the run workspace to a view through the rail ("Report", "Workflow", "Surface", …). */
export async function openView(page: Page, view: string) {
  await page.getByRole('navigation', { name: 'Run views' }).getByRole('button', { name: new RegExp('^' + view) }).click()
}

export async function downloadReport(page: Page, format: 'Markdown with evidence' | 'Plain text') {
  await page.getByRole('button', { name: 'Export', exact: true }).click()
  const pending = page.waitForEvent('download')
  await page.getByRole('menuitem', { name: format, exact: true }).click()
  const download = await pending
  let content = ''
  for await (const chunk of await download.createReadStream()) content += String(chunk)
  return { name: download.suggestedFilename(), content }
}
