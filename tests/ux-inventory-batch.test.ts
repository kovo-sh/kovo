import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser, BrowserContext, Page } from '@playwright/test'
import { Store } from '../src/server/store.ts'
import { HARDENED_NODE_FLAGS } from './app.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

const SYSTEM_CHROMIUM_CANDIDATES = [
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
]

interface PlaywrightModule {
  chromium: {
    executablePath(): string
    launch(options?: { headless?: boolean; executablePath?: string; args?: string[] }): Promise<Browser>
  }
}

async function loadPlaywright(): Promise<{ pw: PlaywrightModule; executablePath: string } | null> {
  let pw: PlaywrightModule | null = null
  for (const modName of ['@playwright/test', 'playwright-core', 'playwright'] as const) {
    try {
      const loaded = (await import(modName)) as Partial<PlaywrightModule>
      if (loaded.chromium && typeof loaded.chromium.launch === 'function') {
        pw = loaded as PlaywrightModule
        break
      }
    } catch {
      // Try next candidate package.
    }
  }
  if (!pw) return null

  const bundled = (() => {
    try {
      return pw.chromium.executablePath()
    } catch {
      return ''
    }
  })()
  if (bundled && existsSync(bundled)) return { pw, executablePath: bundled }
  for (const candidate of SYSTEM_CHROMIUM_CANDIDATES) {
    if (existsSync(candidate)) return { pw, executablePath: candidate }
  }
  return null
}

async function findFreePort(): Promise<number> {
  const srv = createNetServer().listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const addr = srv.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not allocate an ephemeral port.')
  await new Promise<void>(done => srv.close(() => done()))
  return addr.port
}

function ensureBuilt(): void {
  const serverEntry = resolve(REPO_ROOT, 'build/server/server.js')
  const clientDir = resolve(REPO_ROOT, 'build/client')
  if (existsSync(serverEntry) && existsSync(clientDir)) return
  execFileSync('npm', ['run', 'build'], { cwd: REPO_ROOT, stdio: 'pipe' })
}

interface SpawnedKovoServer {
  origin: string
  dataDir: string
  bootstrapSecret: string
  stop(): Promise<void>
}

async function startKovoServer(): Promise<SpawnedKovoServer> {
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-inventory-batch-'))
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''

  const child: ChildProcess = spawn(process.execPath, [...HARDENED_NODE_FLAGS, 'scripts/serve.ts'], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      PORT: String(port),
      KOVO_DATA_DIR: dataDir,
      KOVO_ALLOW_LOCAL_LAB: '1',
      KOVO_ALLOW_LOCAL_MODEL: '1',
      KOVO_OFFLINE: '',
      KOVO_PUBLIC_ORIGIN: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout?.on('data', chunk => { output += String(chunk) })
  child.stderr?.on('data', chunk => { output += String(chunk) })

  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit')
      child.kill('SIGTERM')
      const timedOut = await Promise.race([
        exited.then(() => false),
        delay(3_000).then(() => true),
      ])
      if (timedOut && child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL')
        await once(child, 'exit')
      }
    }
    await rm(dataDir, { recursive: true, force: true })
  }

  let healthy = false
  for (let attempt = 0; attempt < 250; attempt += 1) {
    if (child.exitCode !== null) break
    try {
      const res = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(300) })
      if (res.ok) {
        healthy = true
        break
      }
    } catch {
      // Server not bound yet.
    }
    await delay(70)
  }
  if (!healthy) {
    await stop()
    throw new Error(`scripts/serve.ts failed to start on ${origin}.\n${output}`)
  }

  let bootstrapSecret = ''
  for (let read = 0; read < 30 && !bootstrapSecret; read += 1) {
    try {
      bootstrapSecret = (await readFile(join(dataDir, 'bootstrap'), 'utf8')).trim()
    } catch {
      await delay(50)
    }
  }
  if (!bootstrapSecret) {
    await stop()
    throw new Error(`Bootstrap secret file was not written in ${dataDir}.\n${output}`)
  }

  return { origin, dataDir, bootstrapSecret, stop }
}

function withSqlite<T>(dataDir: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(join(dataDir, 'kovo.sqlite'))
  try {
    db.exec('PRAGMA busy_timeout = 5000;')
    return fn(db)
  } finally {
    db.close()
  }
}

describe('Option 3 — Inventory Multi-Select Batch Actions + Scope Review Default Sync', { timeout: 120_000 }, () => {
  describe('Store transactional bulk inventory operations', () => {
    it('bulkUpdateProjectAssetScope approves/unapproves 20 hosts in 1 transaction with 1 audit event and ignores cross-project IDs', t => {
      const dir = mkdtempSync(join(tmpdir(), 'kovo-bulk-store-'))
      t.after(() => rmSync(dir, { recursive: true, force: true }))
      const store = new Store(dir, { ftsMode: 'preview' })
      t.after(() => store.close())

      const projA = store.createProject({
        requestId: randomUUID(),
        name: 'Bulk Project A',
        seeds: ['https://app.alpha.example'],
        environment: 'public',
        includeSubdomains: false,
      })
      const projB = store.createProject({
        requestId: randomUUID(),
        name: 'Bulk Project B',
        seeds: ['https://app.beta.example'],
        environment: 'public',
        includeSubdomains: false,
      })

      const addedIdsA: string[] = []
      for (let i = 1; i <= 20; i += 1) {
        const res = store.addProjectAsset({
          requestId: randomUUID(),
          projectId: projA.id,
          origin: `https://svc-${i}.alpha.example`,
          source: 'phase0_subdomain_discovery',
          thirdParty: i > 18,
          includeSubdomains: false,
        })
        addedIdsA.push(res.id)
      }
      const foreignAssetB = store.addProjectAsset({
        requestId: randomUUID(),
        projectId: projB.id,
        origin: 'https://secret.beta.example',
        source: 'Manual entry',
        thirdParty: false,
        includeSubdomains: false,
      })

      // 1. Bulk approve 20 hosts + 1 foreign ID in a single transaction
      const approveReqId = randomUUID()
      const approved = store.projectsRepo.bulkUpdateProjectAssetScope({
        requestId: approveReqId,
        projectId: projA.id,
        assetIds: [...addedIdsA, foreignAssetB.id, 'non-existent-id'],
        approveInDefaultScope: true,
        includeSubdomains: true,
      })
      assert.equal(approved.updatedCount, 20)
      assert.deepEqual(approved.ignoredIds.sort(), [foreignAssetB.id, 'non-existent-id'].sort())
      assert.equal(approved.defaultScope.length, 21, '1 seed + 20 newly approved hosts')

      // Verify idempotent replay returns identical payload without emitting another audit event
      const approvedReplay = store.projectsRepo.bulkUpdateProjectAssetScope({
        requestId: approveReqId,
        projectId: projA.id,
        assetIds: [...addedIdsA, foreignAssetB.id, 'non-existent-id'],
        approveInDefaultScope: true,
        includeSubdomains: true,
      })
      assert.deepEqual(approvedReplay, approved)

      // Verify third-party assets did NOT get includeSubdomains=true while first-party assets did
      const detailA = store.projectDetail(projA.id)
      const firstPartyEnabled = detailA.assets.filter(a => addedIdsA.includes(a.id) && !a.thirdParty && a.includeSubdomains)
      const thirdPartyEnabled = detailA.assets.filter(a => addedIdsA.includes(a.id) && a.thirdParty && a.includeSubdomains)
      assert.equal(firstPartyEnabled.length, 18)
      assert.equal(thirdPartyEnabled.length, 0)

      // Verify Project B was completely untouched
      const detailB = store.projectDetail(projB.id)
      assert.deepEqual(detailB.project.defaultScope, ['https://app.beta.example'])
      assert.equal(detailB.assets.length, 2)

      // Verify exactly 1 bulk audit event emitted for the 20-host approval
      const bulkEventsAfterApprove = store.client.prepare(
        `SELECT kind, message, detail FROM events WHERE kind = 'inventory.assets_scope_bulk_updated'`,
      ).all() as Array<{ kind: string; message: string; detail: string }>
      assert.equal(bulkEventsAfterApprove.length, 1, '20 hosts must emit exactly 1 summary audit event')
      assert.match(bulkEventsAfterApprove[0]!.message, /Approved 20 hosts/)

      // 2. Bulk unapprove all 20 hosts in 1 transaction
      const unapproved = store.projectsRepo.bulkUpdateProjectAssetScope({
        requestId: randomUUID(),
        projectId: projA.id,
        assetIds: addedIdsA,
        approveInDefaultScope: false,
      })
      assert.equal(unapproved.updatedCount, 20)
      assert.deepEqual(unapproved.defaultScope, ['https://app.alpha.example'])

      // 3. Bulk remove 10 hosts + foreign ID safely in 1 transaction
      const toRemove = addedIdsA.slice(0, 10)
      const removed = store.projectsRepo.bulkRemoveProjectAssets({
        requestId: randomUUID(),
        projectId: projA.id,
        assetIds: [...toRemove, foreignAssetB.id],
      })
      assert.equal(removed.removedCount, 10)
      assert.deepEqual(removed.ignoredIds, [foreignAssetB.id])
      assert.equal(store.projectDetail(projA.id).assets.length, 11, '1 seed + 10 remaining hosts')
      assert.equal(store.projectDetail(projB.id).assets.length, 2, 'Foreign project asset must NOT be deleted')

      const deleteEvents = store.client.prepare(
        `SELECT kind, message FROM events WHERE kind = 'inventory.assets_bulk_deleted'`,
      ).all() as Array<{ kind: string; message: string }>
      assert.equal(deleteEvents.length, 1, 'Bulk removal must emit 1 summary audit event')
      assert.match(deleteEvents[0]!.message, /Removed 10 hosts/)
    })
  })

  describe('Playwright E2E: filter pills, multi-select sticky batch bar, geometry, and Scope Review default sync', () => {
    let skipReason: string | null = null
    let kovo: SpawnedKovoServer | undefined
    let browser: Browser | undefined
    let context: BrowserContext | undefined
    let page: Page | undefined
    const pageErrors: string[] = []
    let projectId = ''
    const firstPartyIds: string[] = []
    const thirdPartyIds: string[] = []

    before(async () => {
      const pwEnv = await loadPlaywright()
      if (!pwEnv) {
        skipReason = 'Playwright or Chromium binary unavailable in this environment'
        return
      }
      ensureBuilt()
      kovo = await startKovoServer()
      browser = await pwEnv.pw.chromium.launch({
        headless: true,
        executablePath: pwEnv.executablePath,
        args: ['--no-sandbox'],
      })
      context = await browser.newContext({ viewport: { width: 1280, height: 720 } })
      page = await context.newPage()
      page.on('pageerror', err => {
        pageErrors.push(err instanceof Error ? err.message : String(err))
      })

      // 1. Bootstrap auth & create a project with 3 seed hosts
      await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, {
        waitUntil: 'domcontentloaded',
      })
      await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })
      await page.getByLabel('Project name').fill('Acme Batch Inventory')
      await page.getByLabel('Sites').fill('https://acme-batch.example\nhttps://api.acme-batch.example\nhttps://auth.acme-batch.example')
      await page.getByRole('button', { name: 'Create project', exact: true }).click()
      await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 15_000 })
      const projectMatch = /\/projects\/([a-f0-9-]+)/.exec(page.url())
      assert.ok(projectMatch?.[1], `Expected project URL, got ${page.url()}`)
      projectId = projectMatch[1]

      // 2. Seed 25 additional hosts (20 unapproved first-party + 5 unapproved third-party) => 28 hosts total
      const firstPartySubs = [
        'accounts', 'admin', 'beta', 'billing', 'cdn', 'console', 'dashboard', 'docs', 'files', 'gateway',
        'graphql', 'media', 'metrics', 'portal', 'sandbox', 'sso', 'staging', 'status', 'support', 'webhooks',
      ]
      const thirdPartyEntries = [
        { sub: 'blog', cname: 'acme.ghost.io' },
        { sub: 'help', cname: 'acme.zendesk.com' },
        { sub: 'mail', cname: 'sendgrid.net' },
        { sub: 'shop', cname: 'shops.myshopify.com' },
        { sub: 'track', cname: 'edge.segment.io' },
      ]
      withSqlite(kovo.dataDir, db => {
        const stmt = db.prepare(
          `INSERT INTO project_assets (id, project_id, origin, source, third_party, include_subdomains, prepared, dns_source, access_policy)
           VALUES (?, ?, ?, ?, ?, 0, NULL, ?, NULL)`,
        )
        firstPartySubs.forEach(sub => {
          const assetId = randomUUID()
          firstPartyIds.push(assetId)
          stmt.run(
            assetId,
            projectId,
            `https://${sub}.acme-batch.example`,
            'phase0_subdomain_discovery',
            0,
            JSON.stringify({ zone: 'acme-batch.example' }),
          )
        })
        thirdPartyEntries.forEach(entry => {
          const assetId = randomUUID()
          thirdPartyIds.push(assetId)
          stmt.run(
            assetId,
            projectId,
            `https://${entry.sub}.acme-batch.example`,
            'phase0_subdomain_discovery',
            1,
            JSON.stringify({ zone: 'acme-batch.example', externalAliases: [entry.cname] }),
          )
        })
      })
    })

    after(async () => {
      if (context) await context.close().catch(() => {})
      if (browser) await browser.close().catch(() => {})
      if (kovo) await kovo.stop().catch(() => {})
    })

    it('renders filter pills, sticky batch bar, Approve all first-party, and satisfies zero overflow/overlap at 1280x720 & 1440x900', async t => {
      if (skipReason || !page || !kovo) {
        t.skip(skipReason ?? 'Browser setup unavailable')
        return
      }

      const captureDir = process.env.KOVO_CAPTURE_INVENTORY_SHOTS_DIR
      if (captureDir) mkdirSync(captureDir, { recursive: true })

      // Check geometry & capture screenshots across 1280x720 and 1440x900 with 28 hosts & 4 selected
      const viewports = [
        { width: 1280, height: 720, shotName: 'inventory-batch-after-1280x720.png' },
        { width: 1440, height: 900, shotName: 'inventory-batch-after-1440x900.png' },
      ] as const

      for (const vp of viewports) {
        await page.setViewportSize({ width: vp.width, height: vp.height })
        await page.goto(`${kovo.origin}/projects/${projectId}?tab=inventory`, { waitUntil: 'networkidle' })
        await page.getByTestId('inventory-filter-bar').waitFor({ state: 'visible', timeout: 10_000 })

        // Verify filter pill counts
        assert.match(await page.getByTestId('inventory-filter-all').innerText(), /All\s*28/)
        assert.match(await page.getByTestId('inventory-filter-needs_approval').innerText(), /Needs approval\s*25/)
        assert.match(await page.getByTestId('inventory-filter-approved').innerText(), /Approved\s*3/)
        assert.match(await page.getByTestId('inventory-filter-first_party').innerText(), /First-party\s*23/)
        assert.match(await page.getByTestId('inventory-filter-third_party').innerText(), /Third-party\s*5/)

        // Verify Approve all first-party (20) button is present in Needs approval section header
        const approveAll1p = page.getByTestId('approve-all-first-party')
        await approveAll1p.waitFor({ state: 'visible', timeout: 5_000 })
        assert.equal((await approveAll1p.innerText()).trim(), 'Approve all first-party (20)')

        // Select 4 unapproved hosts near the top of Needs approval (instant local state, no server write yet)
        for (const id of firstPartyIds.slice(0, 4)) {
          await page.getByTestId(`select-asset-${id}`).click()
        }
        // Scroll back to top of the scrollable pane so header, filter pills, Approve all first-party, selected rows, and sticky batch bar are all visible together
        await page.evaluate(() => {
          const doc = (globalThis as unknown as { document: { querySelector(s: string): { parentElement: unknown; scrollTop?: number } | null } }).document
          let cur = doc.querySelector('[data-testid="inventory-filter-bar"]') as { parentElement: unknown; scrollTop?: number } | null
          while (cur) {
            if (typeof cur.scrollTop === 'number' && cur.scrollTop > 0) cur.scrollTop = 0
            cur = cur.parentElement as { parentElement: unknown; scrollTop?: number } | null
          }
          ;(globalThis as unknown as { scrollTo(x: number, y: number): void }).scrollTo(0, 0)
        })
        await delay(150)

        const batchBar = page.getByTestId('inventory-batch-bar')
        await batchBar.waitFor({ state: 'visible', timeout: 5_000 })
        assert.equal((await page.getByTestId('inventory-batch-count').innerText()).trim(), '4 selected')

        // Geometry invariants: sticky bar visible inside viewport, zero horizontal overflow, zero button clipping/overlap
        const barPosition = await batchBar.evaluate(el => getComputedStyle(el).position)
        assert.equal(barPosition, 'sticky', 'Batch action bar must use position: sticky')

        const barBox = await batchBar.boundingBox()
        const approveBtnBox = await page.getByTestId('batch-approve-selected').boundingBox()
        const unapproveBtnBox = await page.getByTestId('batch-unapprove-selected').boundingBox()
        const removeBtnBox = await page.getByTestId('batch-remove-selected').boundingBox()
        assert.ok(barBox && approveBtnBox && unapproveBtnBox && removeBtnBox, `Expected batch bar boxes at ${vp.width}x${vp.height}`)
        assert.ok(barBox.y >= 0 && barBox.y + barBox.height <= vp.height + 1, `Sticky batch bar must stay inside viewport at ${vp.width}x${vp.height}`)
        assert.ok(approveBtnBox.x + approveBtnBox.width < unapproveBtnBox.x, 'Approve and Unapprove buttons must not overlap')
        assert.ok(unapproveBtnBox.x + unapproveBtnBox.width < removeBtnBox.x, 'Unapprove and Remove buttons must not overlap')

        const overflowCheck: {
          docScrollWidth: number
          docClientWidth: number
          filterOverflow: boolean
          batchOverflow: boolean
          clippedButtons: string[]
        } = await page.evaluate(() => {
          const doc = (globalThis as unknown as { document: { documentElement: { scrollWidth: number; clientWidth: number }; querySelector(s: string): { scrollWidth: number; clientWidth: number } | null; querySelectorAll(s: string): Array<{ scrollHeight: number; clientHeight: number; textContent: string | null }> } }).document
          const filterBar = doc.querySelector('[data-testid="inventory-filter-bar"]')
          const batchBarEl = doc.querySelector('[data-testid="inventory-batch-bar"]')
          const buttons = [...doc.querySelectorAll('[data-testid="inventory-filter-bar"] button, [data-testid="inventory-batch-bar"] button')]
          const clippedButtons = buttons
            .filter(btn => btn.scrollHeight > btn.clientHeight + 2)
            .map(btn => btn.textContent?.trim() ?? '')
          return {
            docScrollWidth: doc.documentElement.scrollWidth,
            docClientWidth: doc.documentElement.clientWidth,
            filterOverflow: filterBar ? filterBar.scrollWidth > filterBar.clientWidth + 1 : false,
            batchOverflow: batchBarEl ? batchBarEl.scrollWidth > batchBarEl.clientWidth + 1 : false,
            clippedButtons,
          }
        })
        assert.ok(
          overflowCheck.docScrollWidth <= overflowCheck.docClientWidth + 1,
          `Zero horizontal document overflow at ${vp.width}x${vp.height}: ${JSON.stringify(overflowCheck)}`,
        )
        assert.equal(overflowCheck.filterOverflow, false, `Filter bar must not overflow at ${vp.width}x${vp.height}`)
        assert.equal(overflowCheck.batchOverflow, false, `Batch bar must not overflow at ${vp.width}x${vp.height}`)
        assert.deepEqual(overflowCheck.clippedButtons, [], `Buttons must not clip text at ${vp.width}x${vp.height}`)

        if (captureDir) {
          await page.screenshot({ path: join(captureDir, vp.shotName), fullPage: false })
          if (vp.width === 1280) {
            await page.evaluate(() => {
              const root = (globalThis as unknown as { document: { documentElement: { setAttribute(k: string, v: string): void } } }).document.documentElement
              root.setAttribute('data-appearance', 'dark')
              root.setAttribute('data-theme', 'dark')
            })
            await delay(100)
            await page.screenshot({ path: join(captureDir, 'inventory-batch-after-1280x720-dark.png'), fullPage: false })
            await page.evaluate(() => {
              const root = (globalThis as unknown as { document: { documentElement: { setAttribute(k: string, v: string): void } } }).document.documentElement
              root.setAttribute('data-appearance', 'light')
              root.setAttribute('data-theme', 'light')
            })
          }
        }
      }

      // Functional E2E flows at 1280x720
      await page.setViewportSize({ width: 1280, height: 720 })
      await page.goto(`${kovo.origin}/projects/${projectId}?tab=inventory`, { waitUntil: 'networkidle' })

      // 1. Filter pills filter the displayed rows accurately
      await page.getByTestId('inventory-filter-third_party').click()
      assert.equal(await page.locator('[data-testid^="inventory-row-"]').count(), 5)
      await page.getByTestId('inventory-filter-approved').click()
      assert.equal(await page.locator('[data-testid^="inventory-row-"]').count(), 3)
      await page.getByTestId('inventory-filter-needs_approval').click()
      assert.equal(await page.locator('[data-testid^="inventory-row-"]').count(), 25)
      await page.getByTestId('inventory-filter-all').click()
      assert.equal(await page.locator('[data-testid^="inventory-row-"]').count(), 28)

      // 2. Multi-select 4 unapproved hosts & click Approve selected (4)
      for (const id of firstPartyIds.slice(0, 4)) {
        await page.getByTestId(`select-asset-${id}`).click()
      }
      await page.getByTestId('batch-approve-selected').click()
      await page.getByText('Approved 4 hosts in project scope.').waitFor({ state: 'visible', timeout: 10_000 })
      assert.equal(await page.getByTestId('inventory-batch-bar').count(), 0, 'Batch bar clears after approval')
      assert.match(await page.getByTestId('inventory-filter-approved').innerText(), /Approved\s*7/)
      assert.equal((await page.getByTestId('approve-all-first-party').innerText()).trim(), 'Approve all first-party (16)')

      // 3. Click Approve all first-party (16) -> 1 transaction approves all remaining first-party hosts
      await page.getByTestId('approve-all-first-party').click()
      await page.getByText('Approved 16 first-party hosts in project scope.').waitFor({ state: 'visible', timeout: 10_000 })
      assert.match(await page.getByTestId('inventory-filter-approved').innerText(), /Approved\s*23/)
      assert.match(await page.getByTestId('inventory-filter-needs_approval').innerText(), /Needs approval\s*5/)
      assert.equal(await page.getByTestId('approve-all-first-party').count(), 0, 'Approve all first-party hides when 0 unapproved 1P remain')

      // 3b. Multi-select 2 approved hosts & click Unapprove selected
      for (const id of firstPartyIds.slice(0, 2)) {
        await page.getByTestId(`select-asset-${id}`).click()
      }
      await page.getByTestId('batch-unapprove-selected').click()
      await page.getByText('Unapproved 2 hosts from project scope.').waitFor({ state: 'visible', timeout: 10_000 })
      assert.match(await page.getByTestId('inventory-filter-approved').innerText(), /Approved\s*21/)
      assert.match(await page.getByTestId('inventory-filter-needs_approval').innerText(), /Needs approval\s*7/)

      // 4. Filter to Third-party, Select all visible (5), Remove selected via confirm dialog
      await page.getByTestId('inventory-filter-third_party').click()
      assert.equal(thirdPartyIds.length, 5)
      await page.getByTestId('inventory-select-all').click()
      assert.equal((await page.getByTestId('inventory-batch-count').innerText()).trim(), '5 selected')
      await page.getByTestId('batch-remove-selected').click()
      await page.getByTestId('confirm-bulk-remove').waitFor({ state: 'visible', timeout: 5_000 })
      await page.getByTestId('confirm-bulk-remove').click()
      await page.getByText('Removed 5 hosts from project inventory.').waitFor({ state: 'visible', timeout: 10_000 })
      assert.match(await page.getByTestId('inventory-filter-all').innerText(), /All\s*23/)
      assert.match(await page.getByTestId('inventory-filter-third_party').innerText(), /Third-party\s*0/)

      assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
    })

    it('Scope Review "Save as project default" checkbox syncs approved hosts back to projects.defaultScope', async t => {
      if (skipReason || !page || !kovo) {
        t.skip(skipReason ?? 'Browser setup unavailable')
        return
      }

      // Start a new run from the project page
      await page.setViewportSize({ width: 1280, height: 720 })
      await page.goto(`${kovo.origin}/projects/${projectId}`, { waitUntil: 'networkidle' })
      await page.getByRole('button', { name: 'New run', exact: true }).click()
      const dialog = page.getByRole('dialog')
      await dialog.waitFor({ state: 'visible', timeout: 10_000 })
      await dialog.getByRole('button', { name: 'Start run', exact: true }).click()
      await page.waitForURL(/\/runs\/[a-f0-9-]+/, { timeout: 15_000 })
      const runMatch = /\/runs\/([a-f0-9-]+)/.exec(page.url())
      assert.ok(runMatch?.[1], `Expected run URL, got ${page.url()}`)
      const runId = runMatch[1]

      // Put the run in review/waiting with a brand-new candidate not currently in projects.defaultScope
      const candidates = [
        { id: randomUUID(), origin: 'https://acme-batch.example', source: 'Project seed', thirdParty: false },
        { id: randomUUID(), origin: 'https://new-api.acme-batch.example', source: 'phase0_subdomain_discovery', thirdParty: false },
      ]
      withSqlite(kovo.dataDir, db => {
        db.prepare('UPDATE projects SET default_scope = ? WHERE id = ?').run(JSON.stringify(['https://acme-batch.example']), projectId)
        db.prepare(
          `UPDATE runs
             SET phase = 'review',
                 status = 'waiting',
                 scope_revision = 0,
                 candidates = ?,
                 approved = '[]',
                 capability_tier = 1,
                 approval_policy = 'auto_review'
           WHERE id = ?`,
        ).run(JSON.stringify(candidates), runId)
      })

      await page.goto(`${kovo.origin}/runs/${runId}`, { waitUntil: 'networkidle' })
      await page.getByRole('heading', { name: 'Review scope', level: 1 }).waitFor({ state: 'visible', timeout: 10_000 })

      const saveDefaultCheckbox = page.getByTestId('consent-save-default')
      await saveDefaultCheckbox.waitFor({ state: 'visible', timeout: 5_000 })
      assert.equal(await saveDefaultCheckbox.isChecked(), false, 'Save as project default must default to false')

      // Check the new host + check "Save as project default" + Approve & start
      const newHostCheckbox = page.getByRole('checkbox', { name: 'Include new-api.acme-batch.example' })
      if (!(await newHostCheckbox.isChecked())) {
        await newHostCheckbox.check()
      }
      await saveDefaultCheckbox.check()
      assert.equal(await saveDefaultCheckbox.isChecked(), true)

      await page.getByRole('button', { name: /^Approve & start/ }).click()

      // Wait for SQLite to reflect updated projects.default_scope
      let syncedScope: string[] = []
      for (let attempt = 0; attempt < 40; attempt += 1) {
        syncedScope = withSqlite(kovo.dataDir, db => {
          const row = db.prepare('SELECT default_scope FROM projects WHERE id = ?').get(projectId) as { default_scope: string } | undefined
          return row ? (JSON.parse(row.default_scope) as string[]) : []
        })
        if (syncedScope.includes('https://new-api.acme-batch.example')) break
        await delay(100)
      }
      assert.deepEqual(
        syncedScope.sort(),
        ['https://acme-batch.example', 'https://new-api.acme-batch.example'].sort(),
        'Checking "Save as project default" on Scope Review must sync approved hosts back to projects.defaultScope',
      )

      assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
    })
  })
})
