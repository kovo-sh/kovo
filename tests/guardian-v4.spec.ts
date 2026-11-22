import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { DEFAULT_PROVIDER } from '../src/domain.ts'
import { createApp } from './app.ts'
import { openScopeReview, openView, saveScope } from './browser-flows.ts'
import { createV2FixtureServer, E2E_CREDENTIAL } from './v2-fixture-server.ts'

test.setTimeout(90_000)

function readDb<T>(directory: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(join(directory, 'guardian.sqlite'), { readOnly: true })
  try {
    return fn(db)
  } finally {
    db.close()
  }
}

async function createModelProfile(
  page: Page,
  opts: {
    name: string
    endpoint: string
    key: string
    model: string
    priority: number
    roleAffinity?: 'reasoning' | 'tactical' | 'fast' | 'any'
    protocol?: 'responses' | 'messages'
  },
) {
  await page.getByLabel('Profile name').fill(opts.name)
  await page.getByLabel(/Priority/).fill(String(opts.priority))
  await page.getByLabel(/API key/).fill(opts.key)

  const roleSelect = page.getByLabel(/Role affinity/i)
  await expect(roleSelect).toBeVisible()
  if (opts.roleAffinity) {
    await roleSelect.selectOption(opts.roleAffinity)
  }

  const advTrigger = page.getByText('Advanced provider settings', { exact: true })
  const modelInput = page.getByLabel('Model ID')
  if (!(await modelInput.isVisible())) {
    await advTrigger.click()
  }
  await modelInput.fill(opts.model)
  await page.getByLabel('Protocol').selectOption(opts.protocol ?? 'responses')
  await page.getByLabel('Base URL').fill(opts.endpoint)

  await page.getByRole('button', { name: 'Test connection' }).click()
  await page.getByRole('status').filter({ hasText: 'Connection verified' }).waitFor({ timeout: 20_000 })
  await page.getByRole('button', { name: /Save model|Update profile/ }).click()
  await page.getByRole('status').filter({ hasText: /Model profile (added|updated)/ }).waitFor({ timeout: 20_000 })
}

/**
 * 1. roleAffinity Model Settings UI & SQLite persistence + edit round-trip
 */
test('configures, displays across reload, and edits roleAffinity across multiple model profiles with SQLite persistence', async ({ page }) => {
  const fixture = await createV2FixtureServer({ scenario: 'chain_cve' })
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })

  try {
    await app.start()
    await page.goto(app.url)
    await page.getByRole('link', { name: 'Model settings' }).click()

    const roleSelect = page.getByLabel(/Role affinity/i)
    await expect(roleSelect).toBeVisible()
    await expect(roleSelect).toHaveValue('any')
    const optionValues = await roleSelect.locator('option').evaluateAll(opts =>
      opts.map(opt => (opt as HTMLOptionElement).value),
    )
    expect(optionValues).toEqual(expect.arrayContaining(['any', 'reasoning', 'tactical', 'fast']))

    await createModelProfile(page, {
      name: 'Profile Alpha',
      endpoint: fixture.origin + '/api/v1',
      key: E2E_CREDENTIAL,
      model: 'mock/model-alpha',
      priority: 70,
    })
    await createModelProfile(page, {
      name: 'Profile Bravo',
      endpoint: fixture.origin + '/api/v1',
      key: E2E_CREDENTIAL,
      model: 'mock/model-bravo',
      priority: 100,
      roleAffinity: 'reasoning',
    })
    await createModelProfile(page, {
      name: 'Profile Charlie',
      endpoint: fixture.origin + '/api/v1',
      key: E2E_CREDENTIAL,
      model: 'mock/model-charlie',
      priority: 90,
      roleAffinity: 'tactical',
    })
    await createModelProfile(page, {
      name: 'Profile Delta',
      endpoint: fixture.origin + '/api/v1',
      key: E2E_CREDENTIAL,
      model: 'mock/model-delta',
      priority: 80,
      roleAffinity: 'fast',
    })

    const profilesRegion = page.getByRole('region', { name: 'Configured model profiles' })

    const alphaCard = profilesRegion.locator('article').filter({ hasText: 'Profile Alpha' })
    const bravoCard = profilesRegion.locator('article').filter({ hasText: 'Profile Bravo' })
    const charlieCard = profilesRegion.locator('article').filter({ hasText: 'Profile Charlie' })
    const deltaCard = profilesRegion.locator('article').filter({ hasText: 'Profile Delta' })

    await expect(alphaCard).toContainText(/Role\s+.*\bany\b/i)
    await expect(bravoCard).toContainText(/Role\s+.*\breasoning\b/i)
    await expect(charlieCard).toContainText(/Role\s+.*\btactical\b/i)
    await expect(deltaCard).toContainText(/Role\s+.*\bfast\b/i)

    // Reload to verify DB round-trip in UI
    await page.reload()
    await expect(alphaCard).toContainText(/Role\s+.*\bany\b/i)
    await expect(bravoCard).toContainText(/Role\s+.*\breasoning\b/i)
    await expect(charlieCard).toContainText(/Role\s+.*\btactical\b/i)
    await expect(deltaCard).toContainText(/Role\s+.*\bfast\b/i)

    // Edit Profile Delta -> any
    await deltaCard.getByRole('button', { name: 'Edit', exact: true }).click()
    await expect(page.getByLabel(/Role affinity/i)).toHaveValue('fast')
    await page.getByLabel(/Role affinity/i).selectOption('any')
    await page.getByRole('button', { name: 'Update profile', exact: true }).click()
    await expect(page.getByRole('status').filter({ hasText: /Model profile updated/ })).toBeVisible()

    // Reload again to confirm edited affinity persisted cleanly and old 'fast' badge is removed
    await page.reload()
    await expect(deltaCard).toContainText(/Role\s+.*\bany\b/i)
    await expect(deltaCard).not.toContainText(/\bfast\b/i)

    // Verify SQLite model_profiles.role_affinity values
    const rows = readDb(app.directory, db =>
      db.prepare('SELECT name, role_affinity AS roleAffinity, priority, enabled FROM model_profiles').all() as Array<{
        name: string
        roleAffinity: string
        priority: number
        enabled: number
      }>,
    )
    expect(rows.find(r => r.name === 'Profile Alpha')?.roleAffinity).toBe('any')
    expect(rows.find(r => r.name === 'Profile Bravo')?.roleAffinity).toBe('reasoning')
    expect(rows.find(r => r.name === 'Profile Charlie')?.roleAffinity).toBe('tactical')
    expect(rows.find(r => r.name === 'Profile Delta')?.roleAffinity).toBe('any')
    expect(rows.every(r => r.enabled === 1)).toBe(true)
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

/**
 * 2. Fail-closed public & unset GUARDIAN_ALLOW_LOCAL_LAB gating + default sandbox_write_allowlist = []
 */
test('enforces fail-closed public gating when GUARDIAN_ALLOW_LOCAL_LAB is unset and defaults sandbox_write_allowlist to []', async ({ page }) => {
  const fixture = await createV2FixtureServer({ scenario: 'chain_cve' })
  const publicApp = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })

  try {
    await publicApp.start()
    await page.goto(publicApp.url)
    await page.getByLabel('Project name').fill('Public Fail-Closed Project')
    await page.getByLabel('Seed hosts').fill('https://northstar.example')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Public Fail-Closed Project' })).toBeVisible()
    await expect(page.getByText('Public HTTPS', { exact: true })).toBeVisible()

    const labEnable = page.getByLabel(/Enable local lab/i)
    await expect(labEnable).toBeDisabled()

    const publicRow = readDb(publicApp.directory, db =>
      db.prepare('SELECT environment, lab_config AS labConfig, sandbox_write_allowlist AS allowlist FROM projects WHERE name = ?')
        .get('Public Fail-Closed Project') as { environment: string; labConfig: string | null; allowlist: string } | undefined,
    )
    expect(publicRow?.environment).toBe('public')
    expect(publicRow?.labConfig).toBeNull()
    expect(JSON.parse(publicRow?.allowlist ?? '[]')).toEqual([])

    // Attempting to configure a local-lab project without GUARDIAN_ALLOW_LOCAL_LAB=1 must fail closed in both layers
    await page.getByRole('link', { name: 'Projects', exact: true }).click()
    const newProjectBtn = page.getByRole('button', { name: 'New project', exact: true })
    await expect(newProjectBtn).toBeVisible()
    await newProjectBtn.click()

    // Check A: loopback seed rejected at creation by labAssetOrigin
    await page.getByLabel('Target environment').selectOption('local-lab')
    await page.getByLabel('Project name').fill('Blocked Local Lab')
    await page.getByLabel('Seed hosts').fill('http://127.0.0.1:8080')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()

    await expect(page.getByRole('alert')).toContainText(/GUARDIAN_ALLOW_LOCAL_LAB=1/i, { timeout: 15_000 })
    await expect(page.getByRole('heading', { name: 'Blocked Local Lab' })).toHaveCount(0)
    const rejectedRow = readDb(publicApp.directory, db =>
      db.prepare('SELECT id FROM projects WHERE name = ?').get('Blocked Local Lab') as { id: string } | undefined,
    )
    expect(rejectedRow).toBeUndefined()

    // Check B: local-lab project with public HTTPS seed created, but Enable local lab remains disabled and labConfig.enabled === false
    await page.getByLabel('Seed hosts').fill('https://northstar-lab.example')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Blocked Local Lab' })).toBeVisible()

    const localEnable = page.getByLabel(/Enable local lab/i)
    await expect(localEnable).toBeDisabled()

    const blockedRow = readDb(publicApp.directory, db =>
      db.prepare('SELECT environment, lab_config AS labConfig FROM projects WHERE name = ?')
        .get('Blocked Local Lab') as { environment: string; labConfig: string | null } | undefined,
    )
    expect(blockedRow?.environment).toBe('local-lab')
    const parsedBlockedLab = blockedRow?.labConfig ? JSON.parse(blockedRow.labConfig) as Record<string, unknown> : null
    expect(Boolean(parsedBlockedLab?.enabled)).toBe(false)
  } finally {
    await publicApp.dispose()
    await fixture.close()
  }
})

/**
 * 3. LabRunner Project Settings (services, seedCommand, iastEnabled, healthPath, internalPort)
 *    + Tier-2 sandboxWriteAllowlist + Run Overview LabRunner status & controls
 */
test('persists local-lab LabRunner config and sandboxWriteAllowlist across reload and renders LabRunner controls on Run Overview', async ({ page }) => {
  const fixture = await createV2FixtureServer({ scenario: 'chain_cve' })
  const labApp = await createApp({
    GUARDIAN_NETWORK_FIXTURE: fixture.origin,
    GUARDIAN_ALLOW_LOCAL_LAB: '1',
  })

  try {
    await labApp.start()
    await page.goto(labApp.url)

    await page.getByLabel('Target environment').selectOption('local-lab')
    await page.getByLabel('Project name').fill('Northstar Local SaaS Lab')
    await page.getByLabel('Seed hosts').fill('http://127.0.0.1:8080')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Northstar Local SaaS Lab' })).toBeVisible()
    await expect(page.getByText('Local lab', { exact: true })).toBeVisible()

    // Configure LabRunner settings: dockerComposeFile, services, seedCommand, iastEnabled, healthPath, internalPort
    const labSection = page.getByRole('region', { name: /Local lab|Lab runner|Lab & sandbox/i })
    await expect(labSection).toBeVisible()

    const enableLabCheckbox = labSection.getByLabel(/Enable local lab/i)
    await expect(enableLabCheckbox).toBeEnabled()
    await enableLabCheckbox.check()

    const composeInput = labSection.getByLabel(/Compose file|Docker Compose/i)
    await expect(composeInput).toBeVisible()
    await composeInput.fill('docker-compose.lab.yml')

    const servicesInput = labSection.getByLabel(/Services/i)
    await expect(servicesInput).toBeVisible()
    await servicesInput.fill(JSON.stringify([{ name: 'app', internalPort: 8080 }, { name: 'postgres' }]))

    const seedInput = labSection.getByLabel(/Seed command/i)
    await expect(seedInput).toBeVisible()
    await seedInput.fill('node scripts/seed-personas.mjs')

    const iastCheckbox = labSection.getByLabel(/IAST|Telemetry/i)
    await expect(iastCheckbox).toBeVisible()
    await iastCheckbox.check()

    const healthInput = labSection.getByLabel(/Health path/i)
    await expect(healthInput).toBeVisible()
    await healthInput.fill('/health')

    const portInput = labSection.getByLabel(/Internal port/i)
    await expect(portInput).toBeVisible()
    await portInput.fill('8080')

    await labSection.getByRole('button', { name: /Save lab/i }).click()
    await expect(page.getByRole('status').filter({ hasText: /Lab/i })).toBeVisible()

    // Configure Tier-2 sandboxWriteAllowlist
    const originField = page.getByLabel(/Allowlist origin|Pattern origin|Endpoint origin/i)
    await expect(originField).toBeVisible()
    await originField.fill('http://127.0.0.1:8080')

    const methodField = page.getByLabel(/Allowlist method|HTTP method|^Method$/i)
    await expect(methodField).toBeVisible()
    await methodField.selectOption('POST')

    const pathField = page.getByLabel(/Path pattern/i)
    await expect(pathField).toBeVisible()
    await pathField.fill('/api/search')

    await page.getByRole('button', { name: /Add allowlist|Save allowlist/i }).click()
    await expect(page.locator('body')).toContainText('http://127.0.0.1:8080')
    await expect(page.locator('body')).toContainText('POST')
    await expect(page.locator('body')).toContainText('/api/search')

    // Reload and verify UI + SQLite persistence unconditionally
    await page.reload()
    await expect(labSection.getByLabel(/Enable local lab/i)).toBeChecked()
    await expect(labSection.getByLabel(/Seed command/i)).toHaveValue('node scripts/seed-personas.mjs')
    await expect(labSection.getByLabel(/IAST|Telemetry/i)).toBeChecked()
    await expect(labSection.getByLabel(/Compose file|Docker Compose/i)).toHaveValue('docker-compose.lab.yml')
    await expect(labSection.getByLabel(/Health path/i)).toHaveValue('/health')
    await expect(labSection.getByLabel(/Internal port/i)).toHaveValue('8080')
    const reloadedServicesRaw = await labSection.getByLabel(/Services/i).inputValue()
    expect(JSON.parse(reloadedServicesRaw)).toEqual([
      expect.objectContaining({ name: 'app', internalPort: 8080 }),
      expect.objectContaining({ name: 'postgres' }),
    ])
    await expect(page.locator('body')).toContainText('http://127.0.0.1:8080')
    await expect(page.locator('body')).toContainText('POST')
    await expect(page.locator('body')).toContainText('/api/search')

    const projectRow = readDb(labApp.directory, db =>
      db.prepare('SELECT environment, lab_config AS labConfig, sandbox_write_allowlist AS allowlist FROM projects WHERE name = ?')
        .get('Northstar Local SaaS Lab') as { environment: string; labConfig: string | null; allowlist: string } | undefined,
    )
    expect(projectRow?.environment).toBe('local-lab')
    const parsedLab = JSON.parse(projectRow?.labConfig ?? '{}') as Record<string, unknown>
    expect(parsedLab.enabled).toBe(true)
    expect(parsedLab.seedCommand).toBe('node scripts/seed-personas.mjs')
    expect(parsedLab.iastEnabled).toBe(true)
    expect(parsedLab.dockerComposeFile).toBe('docker-compose.lab.yml')
    expect(parsedLab.healthPath).toBe('/health')
    expect(parsedLab.internalPort).toBe(8080)
    expect(parsedLab.services).toEqual([
      expect.objectContaining({ name: 'app', internalPort: 8080 }),
      expect.objectContaining({ name: 'postgres' }),
    ])

    const parsedAllowlist = JSON.parse(projectRow?.allowlist ?? '[]') as Array<Record<string, unknown>>
    expect(parsedAllowlist).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          origin: 'http://127.0.0.1:8080',
          method: 'POST',
          pathPattern: '/api/search',
        }),
      ]),
    )

    // Create a Tier 2 run and verify LabRunner status/controls panel appears on Run Overview
    await page.getByLabel('Run goal').fill('Verify LabRunner controls and Surface Graph in local-lab mode.')
    await page.getByLabel('Capability tier').selectOption('2')
    await page.getByRole('button', { name: 'Create run', exact: true }).click()

    const runLabPanel = page.getByRole('region', { name: /Lab runner|Local lab/i })
    await expect(runLabPanel).toBeVisible({ timeout: 20_000 })
    await expect(runLabPanel).toContainText(/IAST\s*(enabled|on|active)/i)
    await expect(runLabPanel).toContainText(/\bapp\b/)
    await expect(runLabPanel).toContainText(/\bpostgres\b/)
    await expect(runLabPanel).toContainText(/8080/)
    await expect(runLabPanel).toContainText(/seed-personas\.mjs/)
    await expect(
      runLabPanel.getByRole('button', { name: /Start lab|Stop lab|Reseed|Health|Refresh/i }).first(),
    ).toBeVisible()
  } finally {
    await labApp.dispose()
    await fixture.close()
  }
})

/**
 * 4. Surface Graph E2E: Phase-0 + Worker discovery populates endpoints, endpoint_params,
 *    api_dependencies in SQLite and renders them cleanly in Run Workspace Surface Graph UI
 */
test('populates endpoints, endpoint_params, and api_dependencies and renders Surface Graph in the run workspace', async ({ page }) => {
  const requests: string[] = []
  const fixture = await createV4SurfaceFixture(requests)
  const app = await createApp({ GUARDIAN_NETWORK_FIXTURE: fixture.origin })

  try {
    await app.start()
    await page.goto(app.url)
    await page.getByRole('link', { name: 'Model settings' }).click()
    await createModelProfile(page, {
      name: 'Surface Primary',
      endpoint: fixture.origin + '/api/v1',
      key: E2E_CREDENTIAL,
      model: DEFAULT_PROVIDER.model,
      priority: 100,
      roleAffinity: 'any',
    })
    await page.getByRole('link', { name: 'Projects', exact: true }).click()

    await page.getByLabel('Project name').fill('Northstar Surface Graph E2E')
    await page.getByLabel('Seed hosts').fill('https://northstar.example')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()

    // Register Persona Vault user_a so Tier-2 authenticated SPA crawl & producer-consumer inference execute
    const personaSection = page.getByRole('region', { name: 'Persona vault' })
    await personaSection.getByRole('button', { name: 'Add persona', exact: true }).click()
    await personaSection.getByLabel(/Handle/i).fill('user_a')
    await personaSection.getByLabel(/Role label/i).fill('Standard User A')
    await personaSection.getByLabel(/Origin allowlist/i).fill('https://northstar.example')
    await personaSection.getByLabel(/Authentication kind/i).selectOption('bearer')
    await personaSection.getByLabel(/Credential secret/i).fill('e2e-user-a-bearer-token')
    await personaSection.getByRole('button', { name: 'Save persona', exact: true }).click()
    await expect(personaSection.getByRole('status')).toContainText('user_a')

    // Allowlist benign POST /api/orders on Tier-2 public project so POST -> GET /api/orders/{orderId} producer-consumer runs cleanly
    const allowOrigin = page.getByLabel(/Allowlist origin|Pattern origin|Endpoint origin/i)
    await expect(allowOrigin).toBeVisible()
    await allowOrigin.fill('https://northstar.example')

    const allowMethod = page.getByLabel(/Allowlist method|HTTP method|^Method$/i)
    await expect(allowMethod).toBeVisible()
    await allowMethod.selectOption('POST')

    const allowPath = page.getByLabel(/Path pattern/i)
    await expect(allowPath).toBeVisible()
    await allowPath.fill('/api/orders')

    await page.getByRole('button', { name: /Add allowlist|Save allowlist/i }).click()
    await expect(page.locator('body')).toContainText('/api/orders')

    await openScopeReview(page, 'Map Phase-0 endpoints, parameters, and producer-consumer API dependencies.', 2)
    await saveScope(page)

    // Poll until all 3 Surface Graph tables in SQLite contain discovered rows
    await expect.poll(() =>
      readDb(app.directory, db => {
        const ep = (db.prepare('SELECT COUNT(*) AS c FROM endpoints').get() as { c: number }).c
        const pr = (db.prepare('SELECT COUNT(*) AS c FROM endpoint_params').get() as { c: number }).c
        const dep = (db.prepare('SELECT COUNT(*) AS c FROM api_dependencies').get() as { c: number }).c
        return { ready: ep > 0 && pr > 0 && dep > 0, ep, pr, dep }
      }),
    { timeout: 45_000 },
    ).toEqual(expect.objectContaining({ ready: true }))

    // Inspect SQLite rows across endpoints, endpoint_params, and api_dependencies
    const surfaceDb = readDb(app.directory, db => {
      const endpoints = db.prepare('SELECT method, path_template AS pathTemplate, source FROM endpoints').all() as Array<{
        method: string
        pathTemplate: string
        source: string
      }>
      const params = db.prepare('SELECT name, location, is_csrf AS isCsrf, is_object_id AS isObjectId FROM endpoint_params').all() as Array<{
        name: string
        location: string
        isCsrf: number
        isObjectId: number
      }>
      const deps = db.prepare('SELECT resource_key AS resourceKey, tested_bola AS testedBola FROM api_dependencies').all() as Array<{
        resourceKey: string
        testedBola: number
      }>
      return { endpoints, params, deps }
    })

    expect(surfaceDb.endpoints.some(e => e.pathTemplate === '/api/orders')).toBe(true)
    expect(surfaceDb.endpoints.some(e => e.pathTemplate === '/api/orders/{orderId}')).toBe(true)
    expect(surfaceDb.params.some(p => p.name === 'orderId' && p.location === 'path')).toBe(true)
    expect(surfaceDb.params.some(p => p.name === 'include' && p.location === 'query')).toBe(true)
    expect(surfaceDb.deps.some(d => /orderId/i.test(d.resourceKey))).toBe(true)

    // Navigate to Surface unconditionally and assert the rendered endpoint inventory (Surface → Endpoints)
    await openView(page, 'Surface')
    await page.getByRole('radio', { name: 'Endpoints', exact: true }).click({ timeout: 20_000 })
    const surfaceRegion = page.getByRole('region', { name: 'Endpoint inventory' })
    await expect(surfaceRegion).toBeVisible({ timeout: 20_000 })
    await expect(surfaceRegion).toContainText('/api/orders')
    await expect(surfaceRegion).toContainText('/api/orders/{orderId}')
    await expect(surfaceRegion).toContainText(/producer → consumer dependencies/i)
    // Parameters and producer → consumer edges live in the endpoint inspector
    await surfaceRegion.getByText('/api/orders/{orderId}', { exact: true }).first().click()
    const inspector = page.getByRole('complementary', { name: 'Inspector' })
    await expect(inspector).toContainText(/\borderId\b/)
    await expect(inspector).toContainText(/\binclude\b/)
    await expect(inspector).toContainText(/\b(?:query|path)\b/i)
    await expect(inspector).toContainText(/API dependencies/i)
    await expect(inspector).toContainText(/Consumes from (?:GET|POST) \/api\/orders\b/)
  } finally {
    await app.dispose()
    await fixture.close()
  }
})

// Local lightweight HTTP fixture helper extending v2-fixture-server patterns for Surface Graph
async function createV4SurfaceFixture(requests: string[]) {
  const base = await createV2FixtureServer({ scenario: 'chain_cve' })
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method === 'POST' && (req.url ?? '').startsWith('/api/v1/')) {
      const chunks: Buffer[] = []
      for await (const c of req) chunks.push(Buffer.from(c))
      const upstream = await fetch(base.origin + req.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: String(req.headers.authorization ?? ''),
          'x-api-key': String(req.headers['x-api-key'] ?? ''),
        },
        body: Buffer.concat(chunks),
      })
      res.writeHead(upstream.status, { 'Content-Type': upstream.headers.get('content-type') ?? 'text/event-stream' })
      res.end(await upstream.text())
      return
    }
    const targetHref = String(req.headers['x-guardian-fixture-target'] ?? '')
    if (!targetHref) {
      res.writeHead(400).end('Missing x-guardian-fixture-target')
      return
    }
    requests.push(`${req.method ?? 'GET'} ${targetHref}`)
    const url = new URL(targetHref)
    if (url.pathname === '/openapi.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({
        openapi: '3.0.3',
        paths: {
          '/api/orders': {
            get: {
              responses: { '200': { description: 'Order list' } },
            },
            post: {
              requestBody: { content: { 'application/json': { schema: { properties: { itemId: { type: 'string' } } } } } },
              responses: { '201': { description: 'Created' } },
            },
          },
          '/api/orders/{orderId}': {
            get: {
              parameters: [
                { name: 'orderId', in: 'path', required: true },
                { name: 'include', in: 'query' },
              ],
            },
          },
        },
      }))
      return
    }
    if (url.pathname === '/api/orders' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ orders: [{ orderId: 'ord_9001', status: 'draft' }] }))
      return
    }
    if (url.pathname === '/api/orders' && req.method === 'POST') {
      res.writeHead(201, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ orderId: 'ord_9001', status: 'draft' }))
      return
    }
    if (url.pathname.startsWith('/api/orders/')) {
      res.writeHead(200, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ orderId: 'ord_9001', items: ['sku_1'], status: 'draft' }))
      return
    }
    if (url.pathname === '/api/admin/bypass') {
      const hasSubreq = Boolean(req.headers['x-middleware-subrequest'])
      if (hasSubreq) {
        res.writeHead(200, { 'Content-Type': 'application/json' })
          .end(JSON.stringify({ ok: true, marker: 'admin_bypass_confirmed' }))
      } else {
        res.writeHead(401, { 'Content-Type': 'application/json' })
          .end(JSON.stringify({ error: 'unauthorized' }))
      }
      return
    }
    if (url.pathname === '/app.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' })
        .end('fetch("/api/orders").then(r => r.json());\nfetch("/api/orders/ord_9001?include=items").then(r => r.json());\nfetch("/api/admin/bypass").then(r => r.json());\n')
      return
    }
    if (url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
        .end('<!doctype html><html><body><a href="/api/orders">Orders</a><form action="/api/orders" method="POST"><input type="hidden" name="_csrf" value="t1"><input name="itemId"></form><script src="/app.js"></script></body></html>')
      return
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not Found')
  }).listen(0, '127.0.0.1')

  await once(server, 'listening')
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('Failed to bind v4 surface fixture')
  return {
    origin: `http://127.0.0.1:${addr.port}`,
    async close() {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
      await base.close()
    },
  }
}
