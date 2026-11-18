import type { Page } from '@playwright/test'
import { DEFAULT_PROVIDER } from '../src/domain.ts'

export async function configureModel(page: Page, base: string, key: string, protocol: 'messages' | 'responses' = 'responses') {
  await page.getByRole('link', { name: 'Model settings' }).click()
  await page.getByLabel('API key').fill(key)
  await page.getByText('Advanced provider settings', { exact: true }).click()
  await page.getByLabel('Base URL').fill(base)
  await page.getByLabel('Model ID').fill(DEFAULT_PROVIDER.model)
  await page.getByLabel('Protocol').selectOption(protocol)
  await page.getByRole('button', { name: 'Test connection' }).click()
  await page.getByRole('status').filter({ hasText: 'Connection verified' }).waitFor()
  await page.getByRole('button', { name: 'Save model' }).click()
  await page.getByRole('status').filter({ hasText: 'Model saved' }).waitFor()
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
    await page.getByLabel('Third-party service').check()
    await page.getByRole('button', { name: 'Add to project' }).click()
    await page.getByRole('button', { name: 'Add to project' }).waitFor({ state: 'hidden' })
  }
  await page.getByLabel('Run goal').fill(options.goal)
  if (options.live) await page.getByLabel('Read approved public pages during this run').check()
  await page.getByRole('button', { name: 'Create run', exact: true }).click()
  await page.getByLabel('I authorize discovery for these assets.').check()
  await page.getByRole('button', { name: 'Start discovery' }).click()
  await page.getByRole('button', { name: 'Review scope' }).click()
}

export async function saveScope(page: Page, label = 'Approve scope') {
  await page.getByLabel('I authorize read-only review of the selected hosts.').check()
  await page.getByRole('button', { name: label, exact: true }).click()
}
