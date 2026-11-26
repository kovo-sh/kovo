import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser, BrowserContext, Page } from '@playwright/test'
import { HARDENED_NODE_FLAGS } from './app.ts'

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
  if (bundled && existsSync(bundled)) {
    return { pw, executablePath: bundled }
  }
  for (const candidate of SYSTEM_CHROMIUM_CANDIDATES) {
    if (existsSync(candidate)) {
      return { pw, executablePath: candidate }
    }
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
  const serverEntry = resolve('build/server/server.js')
  const clientDir = resolve('build/client')
  if (existsSync(serverEntry) && existsSync(clientDir)) return
  execFileSync('npm', ['run', 'build'], { cwd: process.cwd(), stdio: 'pipe' })
}

interface SpawnedKovoServer {
  origin: string
  port: number
  dataDir: string
  bootstrapSecret: string
  stop(): Promise<void>
}

async function startKovoServer(): Promise<SpawnedKovoServer> {
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-tabs-ui-'))
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''

  const child: ChildProcess = spawn(process.execPath, [...HARDENED_NODE_FLAGS, 'scripts/serve.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      KOVO_DATA_DIR: dataDir,
      KOVO_ALLOW_LOCAL_LAB: '1',
      KOVO_ALLOW_LOCAL_MODEL: '1',
      KOVO_OFFLINE: '1',
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
  for (let attempt = 0; attempt < 150; attempt += 1) {
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

  return { origin, port, dataDir, bootstrapSecret, stop }
}

function seedProjectWithAssetsAndModels(dataDir: string, assetCount = 30, profileCount = 15): { projectId: string } {
  const db = new DatabaseSync(join(dataDir, 'kovo.sqlite'))
  try {
    db.exec('PRAGMA busy_timeout = 5000;')
    const ws = db.prepare('SELECT id FROM workspaces LIMIT 1').get() as { id: string } | undefined
    assert.ok(ws?.id, 'Expected default workspace to exist in kovo.sqlite')

    const projectId = randomUUID()
    const now = Date.now()
    const origins: string[] = []
    for (let i = 1; i <= assetCount; i += 1) {
      origins.push(`https://svc-${String(i).padStart(2, '0')}.tall-inventory.example`)
    }
    const approvedOrigins = origins.slice(0, Math.min(20, assetCount))

    db.prepare(`
      INSERT INTO projects (
        id, workspace_id, tenant_id, name, environment, seeds, default_scope,
        lab_config, sandbox_write_allowlist, created_at
      ) VALUES (?, ?, 'default', ?, 'public', ?, ?, NULL, '[]', ?)
    `).run(
      projectId,
      ws.id,
      'Tall Inventory Flex Verification',
      JSON.stringify([origins[0]]),
      JSON.stringify(approvedOrigins),
      now,
    )

    const insertAsset = db.prepare(`
      INSERT INTO project_assets (
        id, project_id, origin, source, third_party, include_subdomains,
        prepared, dns_source, access_policy
      ) VALUES (?, ?, ?, ?, ?, 0, NULL, NULL, NULL)
    `)
    for (let i = 0; i < origins.length; i += 1) {
      insertAsset.run(
        randomUUID(),
        projectId,
        origins[i],
        i === 0 ? 'Seed host' : 'DNS zone import',
        i >= 25 ? 1 : 0,
      )
    }

    const insertProfile = db.prepare(`
      INSERT INTO model_profiles (
        id, workspace_id, name, endpoint, model, protocol, credential_id,
        priority, enabled, context_window, max_tokens, thinking_level,
        role_affinity, input_cost_per_mtok, cached_input_cost_per_mtok,
        output_cost_per_mtok, health_state, cooldown_until, last_error, updated_at
      ) VALUES (?, ?, ?, ?, ?, 'responses', ?, ?, 1, 1048576, 16384, 'medium', 'any', 0.15, 0.003, 0.6, 'closed', NULL, NULL, ?)
    `)
    for (let i = 1; i <= profileCount; i += 1) {
      insertProfile.run(
        randomUUID(),
        ws.id,
        `Pool Profile ${String(i).padStart(2, '0')}`,
        `https://provider-${i}.example/v1`,
        `vendor/model-v${i}`,
        `cred-synthetic-${i}`,
        100 - i,
        now - i * 60_000,
      )
    }

    return { projectId }
  } finally {
    db.close()
  }
}

const VIEWPORTS = [
  { name: '1280x720', width: 1280, height: 720 },
  { name: '1440x900', width: 1440, height: 900 },
] as const

describe('Project tab bar flex-collapse & Settings sticky-header regression guards', { timeout: 90_000 }, () => {
  let skipReason: string | null = null
  let kovo: SpawnedKovoServer | undefined
  let browser: Browser | undefined
  let context: BrowserContext | undefined
  let page: Page | undefined
  let projectId = ''
  const pageErrors: string[] = []
  const screenshotDir = process.env.KOVO_TAB_SCREENSHOT_DIR?.trim() || ''

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

    // Authenticate session via single-use bootstrap secret (triggers store initialization too).
    await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, {
      waitUntil: 'domcontentloaded',
    })
    await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })

    // Seed 30 assets and 15 model profiles directly in SQLite.
    const seeded = seedProjectWithAssetsAndModels(kovo.dataDir, 30, 15)
    projectId = seeded.projectId

    if (screenshotDir) {
      await mkdir(screenshotDir, { recursive: true })
    }
  })

  after(async () => {
    if (context) await context.close().catch(() => {})
    if (browser) await browser.close().catch(() => {})
    if (kovo) await kovo.stop().catch(() => {})
  })

  for (const vp of VIEWPORTS) {
    it(`keeps project header & tablist pinned and clickable with 30 inventory hosts at ${vp.name}`, async t => {
      if (skipReason || !page || !kovo) {
        t.skip(skipReason ?? 'Browser setup unavailable')
        return
      }

      await page.setViewportSize({ width: vp.width, height: vp.height })
      await page.goto(`${kovo.origin}/projects/${projectId}?tab=inventory`, {
        waitUntil: 'domcontentloaded',
      })

      const tablist = page.getByRole('tablist', { name: 'Project sections' })
      await tablist.waitFor({ state: 'visible', timeout: 10_000 })
      await page.getByText('svc-30.tall-inventory.example').waitFor({ state: 'attached', timeout: 10_000 })

      async function measureProjectLayout(stage: string) {
        return page!.evaluate(() => {
          const main = document.querySelector('main') as HTMLElement | null
          const header = main?.querySelector(':scope > header') as HTMLElement | null
          const tabNav = document.querySelector('[role="tablist"]') as HTMLElement | null
          const tabStrip = tabNav?.parentElement as HTMLElement | null
          const scrollPane = Array.from(main?.children ?? []).find(
            el => el instanceof HTMLElement && el !== tabStrip && getComputedStyle(el).overflowY === 'auto',
          ) as HTMLElement | undefined

          const tabs = Array.from(document.querySelectorAll('[role="tab"]')).map(el => {
            const r = el.getBoundingClientRect()
            const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2)
            return {
              label: el.textContent?.trim() ?? '',
              top: r.top,
              bottom: r.bottom,
              height: r.height,
              width: r.width,
              scrollHeight: el.scrollHeight,
              clientHeight: el.clientHeight,
              clickable: Boolean(hit && (hit === el || el.contains(hit))),
            }
          })

          const rectOf = (el: HTMLElement | null | undefined) => {
            if (!el) return null
            const r = el.getBoundingClientRect()
            return {
              top: r.top,
              bottom: r.bottom,
              left: r.left,
              right: r.right,
              height: r.height,
              width: r.width,
              clientHeight: el.clientHeight,
              scrollHeight: el.scrollHeight,
              clientWidth: el.clientWidth,
              scrollWidth: el.scrollWidth,
              scrollTop: el.scrollTop,
            }
          }

          return {
            viewport: { width: window.innerWidth, height: window.innerHeight },
            docOverflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth,
            main: rectOf(main),
            header: rectOf(header),
            tabStrip: rectOf(tabStrip),
            tabNav: rectOf(tabNav),
            scrollPane: rectOf(scrollPane),
            tabs,
          }
        }).then(res => ({ stage, ...res }))
      }

      const topMetrics = await measureProjectLayout(`${vp.name} scrollTop=0`)
      assert.equal(topMetrics.docOverflowX, 0, `${vp.name}: document horizontal overflow must be 0`)
      assert.ok(topMetrics.header, `${vp.name}: project <header> must exist`)
      assert.ok(topMetrics.header.height >= 40, `${vp.name}: <header> height must be >= 40, got ${topMetrics.header.height}`)
      assert.ok(topMetrics.header.top >= 0 && topMetrics.header.top <= 2, `${vp.name}: <header> must be pinned at top, got ${topMetrics.header.top}`)

      assert.ok(topMetrics.tabStrip, `${vp.name}: tab strip container must exist`)
      assert.ok(topMetrics.tabStrip.height >= 36, `${vp.name}: tab strip height must be >= 36, got ${topMetrics.tabStrip.height}`)
      assert.ok(topMetrics.tabStrip.clientHeight >= 36, `${vp.name}: tab strip clientHeight must be >= 36, got ${topMetrics.tabStrip.clientHeight}`)
      assert.ok(topMetrics.tabStrip.top >= 0 && topMetrics.tabStrip.bottom <= vp.height, `${vp.name}: tab strip must be inside viewport`)
      assert.ok(topMetrics.tabStrip.scrollWidth <= topMetrics.tabStrip.clientWidth, `${vp.name}: tab strip must have zero horizontal overflow`)

      assert.ok(topMetrics.tabNav, `${vp.name}: [role="tablist"] must exist`)
      assert.ok(topMetrics.tabNav.height >= 36, `${vp.name}: [role="tablist"] height must be >= 36, got ${topMetrics.tabNav.height}`)
      assert.ok(topMetrics.tabNav.clientHeight >= 36, `${vp.name}: [role="tablist"] clientHeight must be >= 36, got ${topMetrics.tabNav.clientHeight}`)
      assert.ok(topMetrics.tabNav.top >= 0 && topMetrics.tabNav.bottom <= Math.min(vp.height, 720), `${vp.name}: [role="tablist"] must be visible in viewport`)

      assert.equal(topMetrics.tabs.length, 6, `${vp.name}: expected 6 project tabs`)
      for (const tab of topMetrics.tabs) {
        assert.ok(tab.height >= 24, `${vp.name}: tab "${tab.label}" collapsed to height ${tab.height}`)
        assert.ok(tab.scrollHeight <= tab.clientHeight + 2, `${vp.name}: tab "${tab.label}" clipped vertically`)
        assert.equal(tab.clickable, true, `${vp.name}: tab "${tab.label}" must be clickable at scrollTop=0`)
      }

      assert.ok(topMetrics.scrollPane, `${vp.name}: tab body must have an inner vertical scroll pane`)
      assert.ok(
        topMetrics.scrollPane.scrollHeight > topMetrics.scrollPane.clientHeight + 400,
        `${vp.name}: 30 hosts must overflow scroll pane (${topMetrics.scrollPane.scrollHeight} vs ${topMetrics.scrollPane.clientHeight})`,
      )
      assert.ok(
        topMetrics.scrollPane.scrollWidth <= topMetrics.scrollPane.clientWidth,
        `${vp.name}: scroll pane must have zero horizontal overflow (${topMetrics.scrollPane.scrollWidth} vs ${topMetrics.scrollPane.clientWidth})`,
      )

      if (screenshotDir) {
        await page.screenshot({ path: join(screenshotDir, `project-tabs-after-${vp.name}.png`) })
      }

      // Scroll the tab body down by 600px and re-verify header + tab bar remain permanently pinned.
      const actualScrollTop = await page.evaluate(() => {
        const main = document.querySelector('main')
        const tabStrip = document.querySelector('[role="tablist"]')?.parentElement ?? null
        const scrollPane = Array.from(main?.children ?? []).find(
          el => el instanceof HTMLElement && el !== tabStrip && getComputedStyle(el).overflowY === 'auto',
        ) as HTMLElement | undefined
        if (!scrollPane) return -1
        scrollPane.scrollTop = 600
        return scrollPane.scrollTop
      })
      assert.ok(actualScrollTop >= 500, `${vp.name}: expected scroll pane to scroll down >= 500px, got ${actualScrollTop}`)

      if (screenshotDir) {
        await page.screenshot({ path: join(screenshotDir, `project-tabs-after-${vp.name}-scrolled.png`) })
      }

      const scrolledMetrics = await measureProjectLayout(`${vp.name} scrollTop=600`)
      assert.ok(scrolledMetrics.header, `${vp.name} (scrolled): <header> missing`)
      assert.ok(scrolledMetrics.header.top >= 0 && scrolledMetrics.header.top <= 2, `${vp.name} (scrolled): <header> detached (top=${scrolledMetrics.header.top})`)
      assert.ok(scrolledMetrics.header.height >= 40, `${vp.name} (scrolled): <header> shrunk (${scrolledMetrics.header.height})`)

      assert.ok(scrolledMetrics.tabStrip, `${vp.name} (scrolled): tab strip missing`)
      assert.ok(scrolledMetrics.tabStrip.height >= 36, `${vp.name} (scrolled): tab strip height collapsed (${scrolledMetrics.tabStrip.height})`)
      assert.ok(scrolledMetrics.tabStrip.clientHeight >= 36, `${vp.name} (scrolled): tab strip clientHeight collapsed (${scrolledMetrics.tabStrip.clientHeight})`)
      assert.ok(scrolledMetrics.tabNav, `${vp.name} (scrolled): [role="tablist"] missing`)
      assert.ok(scrolledMetrics.tabNav.height >= 36, `${vp.name} (scrolled): [role="tablist"] height collapsed (${scrolledMetrics.tabNav.height})`)
      assert.ok(scrolledMetrics.tabNav.clientHeight >= 36, `${vp.name} (scrolled): [role="tablist"] clientHeight collapsed (${scrolledMetrics.tabNav.clientHeight})`)
      assert.ok(
        scrolledMetrics.tabNav.top >= 40 && scrolledMetrics.tabNav.bottom <= Math.min(vp.height, 720),
        `${vp.name} (scrolled): [role="tablist"] moved out of pinned position (top=${scrolledMetrics.tabNav.top}, bottom=${scrolledMetrics.tabNav.bottom})`,
      )
      for (const tab of scrolledMetrics.tabs) {
        assert.equal(tab.clickable, true, `${vp.name} (scrolled): tab "${tab.label}" must remain clickable after scrolling 600px`)
      }

      // Clicking "Test Accounts" tab while scrolled down must navigate cleanly to ?tab=personas.
      await page.getByRole('tab', { name: /^Test Accounts/ }).click()
      await page.waitForURL(url => url.searchParams.get('tab') === 'personas', { timeout: 10_000 })
      const personasTab = page.getByRole('tab', { name: /^Test Accounts/ })
      assert.equal(await personasTab.getAttribute('aria-selected'), 'true')
      assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
    })
  }

  it('keeps Settings header pinned on tall model-profile list at 1280x720 and 1440x900', async t => {
    if (skipReason || !page || !kovo) {
      t.skip(skipReason ?? 'Browser setup unavailable')
      return
    }

    const activePage = page
    const activeKovo = kovo

    for (const vp of VIEWPORTS) {
      await activePage.setViewportSize({ width: vp.width, height: vp.height })
      await activePage.goto(`${activeKovo.origin}/settings`, { waitUntil: 'domcontentloaded' })
      await activePage.getByRole('heading', { name: 'Settings', level: 1 }).waitFor({ state: 'visible', timeout: 10_000 })
      await activePage.getByText('Pool Profile 15').waitFor({ state: 'attached', timeout: 10_000 })

      const beforeScroll: {
        docOverflowX: number
        headerTop: number
        headerHeight: number
        scrollPaneOverflowY: number
        scrollPaneOverflowX: number
      } = await activePage.evaluate(() => {
        const main = document.querySelector('main') as HTMLElement | null
        const header = main?.querySelector(':scope > header') as HTMLElement | null
        const scrollPane = Array.from(main?.children ?? []).find(
          el => el instanceof HTMLElement && getComputedStyle(el).overflowY === 'auto',
        ) as HTMLElement | undefined
        const hr = header?.getBoundingClientRect()
        return {
          docOverflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth,
          headerTop: hr?.top ?? -1,
          headerHeight: hr?.height ?? 0,
          scrollPaneOverflowY: scrollPane ? scrollPane.scrollHeight - scrollPane.clientHeight : 0,
          scrollPaneOverflowX: scrollPane ? scrollPane.scrollWidth - scrollPane.clientWidth : 0,
        }
      })

      assert.equal(beforeScroll.docOverflowX, 0, `Settings ${vp.name}: document horizontal overflow must be 0`)
      assert.ok(beforeScroll.headerTop >= 0 && beforeScroll.headerTop <= 2, `Settings ${vp.name}: header top=${beforeScroll.headerTop}`)
      assert.ok(beforeScroll.headerHeight >= 40, `Settings ${vp.name}: header height=${beforeScroll.headerHeight}`)
      assert.ok(beforeScroll.scrollPaneOverflowY > 200, `Settings ${vp.name}: expected tall scrollable content, got overflowY=${beforeScroll.scrollPaneOverflowY}`)
      assert.equal(beforeScroll.scrollPaneOverflowX, 0, `Settings ${vp.name}: scroll pane horizontal overflow must be 0`)

      const afterScroll: {
        scrollTop: number
        headerTop: number
        headerHeight: number
      } = await activePage.evaluate(() => {
        const main = document.querySelector('main') as HTMLElement | null
        const header = main?.querySelector(':scope > header') as HTMLElement | null
        const scrollPane = Array.from(main?.children ?? []).find(
          el => el instanceof HTMLElement && getComputedStyle(el).overflowY === 'auto',
        ) as HTMLElement | undefined
        if (scrollPane) scrollPane.scrollTop = 500
        const hr = header?.getBoundingClientRect()
        return {
          scrollTop: scrollPane?.scrollTop ?? -1,
          headerTop: hr?.top ?? -1,
          headerHeight: hr?.height ?? 0,
        }
      })

      assert.ok(afterScroll.scrollTop >= 400, `Settings ${vp.name}: expected scrollTop >= 400, got ${afterScroll.scrollTop}`)
      assert.ok(afterScroll.headerTop >= 0 && afterScroll.headerTop <= 2, `Settings ${vp.name} (scrolled): header detached (top=${afterScroll.headerTop})`)
      assert.ok(afterScroll.headerHeight >= 40, `Settings ${vp.name} (scrolled): header height=${afterScroll.headerHeight}`)
    }

    assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
  })
})
