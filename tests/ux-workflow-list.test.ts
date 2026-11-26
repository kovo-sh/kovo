import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdirSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser, BrowserContext, Page } from '@playwright/test'
import { newProject, newRun, runCommand } from '../src/domain.ts'
import { VIEWS } from '../src/components/run/meta.ts'
import { Store } from '../src/server/store.ts'
import { HARDENED_NODE_FLAGS } from './app.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const CI_TIMEOUT_MULT = process.env.CI ? 2 : 1
const E2E_HOOK_TIMEOUT_MS = process.env.CI ? 45_000 : 25_000

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
      // Try next package
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
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-workflow-list-'))
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
  const healthAttempts = process.env.CI ? 250 : 150
  const healthReqTimeoutMs = process.env.CI ? 1_000 : 300
  for (let attempt = 0; attempt < healthAttempts; attempt += 1) {
    if (child.exitCode !== null) break
    try {
      const res = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(healthReqTimeoutMs) })
      if (res.ok) {
        healthy = true
        break
      }
    } catch {
      // Server not bound yet
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

async function waitForHydrated(page: Page, selector: string, timeoutMs: number): Promise<void> {
  await page.waitForFunction(
    (sel: string) => {
      if (document.readyState !== 'complete') return false
      const el = document.querySelector(sel)
      if (!el) return false
      return Object.keys(el).some(k => k.startsWith('__reactProps$') || k.startsWith('__reactFiber$'))
    },
    selector,
    { timeout: timeoutMs },
  )
}

async function waitForLayoutSettled(page: Page): Promise<void> {
  await page.evaluate(async () => {
    if (document.fonts?.ready) {
      try {
        await document.fonts.ready
      } catch {
        // Ignore font-ready failures in offline headless environments
      }
    }
    await new Promise<void>(r => requestAnimationFrame(() => requestAnimationFrame(() => r())))
  })
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

async function createStoreWithApprovedRun() {
  const dir = await mkdtemp(join(tmpdir(), 'kovo-store-wf-'))
  const store = new Store(dir)
  const project = store.createProject(newProject.parse({
    name: 'Workflow Terminal Guard Project',
    seeds: ['https://app.workflow-test.example'],
    environment: 'public',
    requestId: randomUUID(),
  }))
  const created = store.createRun(newRun.parse({
    projectId: project.id,
    goal: 'Verify terminal assignment settlement',
    capabilityTier: 2,
    approvalPolicy: 'auto_review',
    requestId: randomUUID(),
  }))
  store.command(runCommand.parse({ requestId: randomUUID(), runId: created.id, action: 'discover', consent: true }))
  const afterDiscover = store.run(created.id)
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId: created.id,
    action: 'scope',
    assetIds: afterDiscover.candidates.map(c => c.id),
    expectedScopeRevision: afterDiscover.scopeRevision,
    capabilityTier: 2,
    approvalPolicy: 'auto_review',
    consent: true,
    saveProject: false,
  }))
  const run = store.run(created.id)
  return {
    store,
    run,
    cleanup: async () => {
      store.close()
      await rm(dir, { recursive: true, force: true })
    },
  }
}

describe('Workflow UX upgrades & terminal assignment settlement', () => {
  it('places Workflow inside Investigation nav group (not Telemetry)', () => {
    const wf = VIEWS.find(v => v.id === 'workflow')
    assert.ok(wf, 'Workflow view must exist in VIEWS')
    assert.equal(wf.group, 'investigation')
    const investigationIds = VIEWS.filter(v => v.group === 'investigation').map(v => v.id)
    const telemetryIds = VIEWS.filter(v => v.group === 'telemetry').map(v => v.id)
    assert.deepEqual(investigationIds, ['overview', 'workflow', 'queue', 'findings', 'report'])
    assert.equal(telemetryIds.includes('workflow'), false)
  })

  it('atomically settles dangling running/queued/paused assignments on run complete, stop, and fail', async () => {
    // 1. Complete transition (same chokepoint as oob-drain.ts updateRun({ phase: 'complete', status: 'complete' }))
    {
      const { store, run, cleanup } = await createStoreWithApprovedRun()
      try {
        const asset = run.candidates[0]!
        const runningCodeAudit = store.makeWorker(run, 'threat_model', asset, 'Source-First Code Audit', 'Audit routes')
        store.updateWorker(runningCodeAudit.id, {
          status: 'running',
          lease: randomUUID(),
          leaseExpiresAt: Date.now() + 60_000,
        })
        const queuedRound0 = store.makeWorker(run, 'threat_model', asset, 'Round-0 Threat Model', 'Rank hosts')
        const pausedWorker = store.makeWorker(run, 'investigation', asset, 'Paused check', 'Check auth')
        store.updateWorker(pausedWorker.id, { status: 'paused', outcome: 'Paused mid-check' })
        const waitingApproval = store.makeWorker(run, 'investigation', asset, 'Approval waiter', 'Tier 3 probe')
        store.updateWorker(waitingApproval.id, { status: 'waiting_approval', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 })
        const doneWorker = store.makeWorker(run, 'investigation', asset, 'Completed probe', 'Done')
        store.updateWorker(doneWorker.id, { status: 'complete', outcome: 'Confirmed clean.' })
        const failedWorker = store.makeWorker(run, 'verification', asset, 'Failed probe', 'Err')
        store.updateWorker(failedWorker.id, { status: 'failed', outcome: 'Timed out.' })

        assert.equal(store.isRunActive(run.id), true)
        store.updateRun(run.id, { phase: 'complete', status: 'complete' })

        const workers = store.workerList(run.id)
        const byId = new Map(workers.map(w => [w.id, w]))
        for (const id of [runningCodeAudit.id, queuedRound0.id, pausedWorker.id, waitingApproval.id]) {
          const w = byId.get(id)!
          assert.equal(w.status, 'canceled', `Worker ${w.title} must transition to canceled on run completion`)
          assert.equal(w.lease, null, `Worker ${w.title} lease must be cleared`)
          assert.equal(w.leaseExpiresAt, null, `Worker ${w.title} leaseExpiresAt must be cleared`)
          assert.ok(w.outcome && w.outcome.length > 0, `Worker ${w.title} must have a clean outcome`)
        }
        assert.equal(byId.get(runningCodeAudit.id)!.outcome, 'Stopped when run completed.')
        assert.equal(byId.get(queuedRound0.id)!.outcome, 'Stopped when run completed.')
        assert.equal(byId.get(pausedWorker.id)!.outcome, 'Paused mid-check', 'Existing non-empty outcome must be preserved')
        assert.equal(byId.get(doneWorker.id)!.status, 'complete')
        assert.equal(byId.get(failedWorker.id)!.status, 'failed')
        assert.equal(
          workers.filter(w => ['running', 'queued', 'paused', 'waiting_approval'].includes(w.status)).length,
          0,
          'Zero dangling non-terminal assignments may remain after completion',
        )
        assert.equal(store.isRunActive(run.id), false)

        // Legacy DB safety net in runDetail: even if an older DB already had a stuck running assignment on a completed run,
        // runDetail never surfaces it as running/queued (while preserving an explicit Verify Fix retest worker).
        store.updateWorker(runningCodeAudit.id, { status: 'running', lease: 'stale-lease', outcome: null })
        const retest = store.makeWorker(store.run(run.id), 'retest', asset, 'Verify Fix · SQLi', 'Retest fix')
        const detail = store.runDetail(run.id)
        const detailById = new Map(detail.assignments.map(w => [w.id, w]))
        assert.equal(detailById.get(runningCodeAudit.id)!.status, 'canceled')
        assert.equal(detailById.get(runningCodeAudit.id)!.lease, null)
        assert.equal(detailById.get(runningCodeAudit.id)!.outcome, 'Stopped when run completed.')
        assert.equal(detailById.get(retest.id)!.status, 'queued', 'Explicit retest worker on completed run must remain runnable')
      } finally {
        await cleanup()
      }
    }

    // 2. Stop transition (command action: 'stop')
    {
      const { store, run, cleanup } = await createStoreWithApprovedRun()
      try {
        const asset = run.candidates[0]!
        const active = store.makeWorker(run, 'investigation', asset, 'Active probe', 'Run probe')
        store.updateWorker(active.id, { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 })
        const queued = store.makeWorker(run, 'investigation', asset, 'Queued probe', 'Queued')

        store.command(runCommand.parse({ requestId: randomUUID(), runId: run.id, action: 'stop' }))

        assert.equal(store.worker(active.id).status, 'canceled')
        assert.equal(store.worker(active.id).lease, null)
        assert.equal(store.worker(queued.id).status, 'canceled')
        assert.equal(store.isRunActive(run.id), false)
      } finally {
        await cleanup()
      }
    }

    // 3. Fail transition (setStatus(run, 'failed'))
    {
      const { store, run, cleanup } = await createStoreWithApprovedRun()
      try {
        const asset = run.candidates[0]!
        const active = store.makeWorker(run, 'investigation', asset, 'Running before failure', 'Run probe')
        store.updateWorker(active.id, { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 })
        const paused = store.makeWorker(run, 'investigation', asset, 'Paused before failure', 'Paused')
        store.updateWorker(paused.id, { status: 'paused' })

        store.setStatus(store.run(run.id), 'failed')

        assert.equal(store.worker(active.id).status, 'canceled')
        assert.equal(store.worker(active.id).lease, null)
        assert.equal(store.worker(active.id).outcome, 'Interrupted before run finished.')
        assert.equal(store.worker(paused.id).status, 'canceled')
        assert.equal(store.isRunActive(run.id), false)
      } finally {
        await cleanup()
      }
    }
  })

  describe('Playwright E2E & visual geometry QA', () => {
    let skipReason: string | null = null
    let kovo: SpawnedKovoServer | undefined
    let browser: Browser | undefined
    let context: BrowserContext | undefined
    let page: Page | undefined
    const pageErrors: string[] = []
    let runId = ''

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
      page.setDefaultTimeout(30_000 * CI_TIMEOUT_MULT)
      page.setDefaultNavigationTimeout(30_000 * CI_TIMEOUT_MULT)
      page.on('pageerror', err => {
        pageErrors.push(err instanceof Error ? err.message : String(err))
      })

      await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, {
        waitUntil: 'load',
      })
      await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 * CI_TIMEOUT_MULT })
      await waitForHydrated(page, 'button', 15_000 * CI_TIMEOUT_MULT)
      await page.getByLabel('Project name').fill('Acme Cloud Workflow QA')
      await page.getByLabel('Sites').fill('https://app.acme-cloud.example\nhttps://api.acme-cloud.example\nhttps://admin.acme-cloud.example')
      await page.getByRole('button', { name: 'Create project', exact: true }).click()
      await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 15_000 * CI_TIMEOUT_MULT })

      await waitForHydrated(page, 'button', 15_000 * CI_TIMEOUT_MULT)
      await page.getByRole('button', { name: 'New run', exact: true }).click()
      const dialog = page.getByRole('dialog')
      await dialog.waitFor({ state: 'visible', timeout: 10_000 * CI_TIMEOUT_MULT })
      await dialog.getByRole('button', { name: 'Start run', exact: true }).click()
      await page.waitForURL(/\/runs\/[a-f0-9-]+/, { timeout: 15_000 * CI_TIMEOUT_MULT })
      const runMatch = /\/runs\/([a-f0-9-]+)/.exec(page.url())
      assert.ok(runMatch?.[1], `Expected run URL, got ${page.url()}`)
      runId = runMatch[1]

      const now = Date.now()
      const origins = [
        'https://app.acme-cloud.example',
        'https://api.acme-cloud.example',
        'https://admin.acme-cloud.example',
      ]
      const candidates = origins.map((origin, i) => ({
        id: `cand-${i + 1}`,
        origin,
        source: 'Project seed',
        thirdParty: false,
      }))

      withSqlite(kovo.dataDir, db => {
        const meta = db.prepare('SELECT workspace_id, goal_revision FROM runs WHERE id = ?').get(runId) as
          | { workspace_id: string; goal_revision: number }
          | undefined
        assert.ok(meta?.workspace_id)
        const goalRev = meta.goal_revision ?? 1

        // Keep run status='paused' (non-terminal) so scripts/serve.ts's live Execution loop
        // does not pick up the synthetic fixture via Store.runnable() and spawn a duplicate
        // Round-0 Threat Model worker while Playwright inspects the 3 seeded active rows.
        db.prepare(
          `UPDATE runs
             SET phase = 'threat_model',
                 status = 'paused',
                 scope_revision = 1,
                 candidates = ?,
                 approved = ?,
                 spent_requests = 248,
                 created_at = ?
           WHERE id = ?`,
        ).run(JSON.stringify(candidates), JSON.stringify(candidates.map(c => c.id)), now - 3_700_000, runId)

        db.prepare(`DELETE FROM assignments WHERE run_id = ?`).run(runId)
        const insertWorker = db.prepare(
          `INSERT INTO assignments (
             id, run_id, asset_id, step_id, input_assignment_id, phase, status,
             scope_revision, goal_revision, session_id, attempt, max_turns, turns_used, requests_used,
             parent_fact_ids, source_origins, title, objective, outcome, created_at
           ) VALUES (?, ?, ?, NULL, NULL, ?, ?, 1, ?, ?, 0, ?, ?, ?, '[]', ?, ?, ?, ?, ?)`,
        )

        // Completed earlier workers
        insertWorker.run(
          'w-disc-1', runId, 'cand-1', 'discovery', 'complete', goalRev, 's-disc-1',
          10, 2, 12, JSON.stringify([origins[0]]),
          'Asset inventory', 'Review supplied seeds', 'Recorded 3 approved origins.', now - 180_000,
        )
        insertWorker.run(
          'w-tm-done', runId, 'cand-1', 'threat_model', 'complete', goalRev, 's-tm-done',
          20, 6, 44, JSON.stringify(origins),
          'Baseline capture · app.acme-cloud.example', 'Capture baseline headers and cookies', 'Captured baseline.', now - 150_000,
        )
        insertWorker.run(
          'w-inv-done-1', runId, 'cand-2', 'investigation', 'complete', goalRev, 's-inv-done-1',
          25, 11, 63, JSON.stringify([origins[1]]),
          'GraphQL introspection & schema exposure', 'Inspect GraphQL schema exposure on api host', 'No issue found.', now - 110_000,
        )
        insertWorker.run(
          'w-inv-done-2', runId, 'cand-3', 'investigation', 'complete', goalRev, 's-inv-done-2',
          25, 9, 41, JSON.stringify([origins[2]]),
          'Admin export CSRF boundary check', 'Test CSRF enforcement on admin CSV export', 'Enforcing SameSite + CSRF token.', now - 90_000,
        )

        // Active tasks (must be pinned in "Active now (3)" at the top)
        insertWorker.run(
          'w-r0-live', runId, 'cand-1', 'threat_model', 'running', goalRev, 's-r0-live',
          150, 0, 52, JSON.stringify(origins),
          'Round-0 Threat Model & Surface Ranking', 'Rank approved hosts and map attack surface.', null, now - 60_000,
        )
        insertWorker.run(
          'w-inv-live', runId, 'cand-2', 'investigation', 'running', goalRev, 's-inv-live',
          30, 8, 27, JSON.stringify([origins[1]]),
          'Cross-tenant invoice IDOR differential check', 'Compare member vs. sibling tenant invoice reads.', null, now - 35_000,
        )
        insertWorker.run(
          'w-ver-paused', runId, 'cand-3', 'verification', 'paused', goalRev, 's-ver-paused',
          15, 3, 9, JSON.stringify([origins[2]]),
          'Replay confirmation · Admin role escalation', 'Verify admin role mutation replay spec.', null, now - 20_000,
        )

        db.prepare(
          `INSERT INTO events (workspace_id, run_id, kind, message, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
        ).run(
          meta.workspace_id,
          runId,
          'phase0.stage',
          'Crawling SPA state graph on https://api.acme-cloud.example (2/3).',
          JSON.stringify({
            stage: 'crawl_state_graph',
            origin: origins[1],
            hostsDone: 2,
            hostsTotal: 3,
            endpointsDiscovered: 42,
            paramsDiscovered: 11,
            requestsUsed: 52,
            frameworks: ['Next.js', 'Express'],
          }),
          now - 10_000,
        )
      })
    }, { timeout: E2E_HOOK_TIMEOUT_MS })

    after(async () => {
      await context?.close()
      await browser?.close()
      await kovo?.stop()
    })

    it(
      'elevates Workflow into Investigation, defaults to List view with Active now pinned at top, and keeps geometry clean at 1280x720 & 1440x900',
      { timeout: E2E_HOOK_TIMEOUT_MS },
      async t => {
      if (skipReason || !page || !kovo) {
        t.skip(skipReason ?? 'Playwright unavailable')
        return
      }

      await page.setViewportSize({ width: 1280, height: 720 })
      await page.goto(`${kovo.origin}/runs/${runId}?view=workflow`, { waitUntil: 'load' })

      // 1. Sidebar: Workflow is inside Investigation (NOT Telemetry)
      const invNav = page.getByRole('navigation', { name: 'Investigation views' })
      await invNav.waitFor({ state: 'visible', timeout: 15_000 * CI_TIMEOUT_MULT })
      const invWfBtn = invNav.getByRole('button', { name: /^Workflow/ })
      await invWfBtn.waitFor({ state: 'visible', timeout: 10_000 * CI_TIMEOUT_MULT })
      assert.equal(await invWfBtn.getAttribute('aria-current'), 'page')

      // Wait for TanStack Start client bundle to hydrate React click handlers on the run workspace
      await waitForHydrated(page, 'button[aria-controls="rail-telemetry-nav"]', 15_000 * CI_TIMEOUT_MULT)
      await waitForHydrated(page, '[role="radio"][aria-label="Graph"]', 15_000 * CI_TIMEOUT_MULT)

      const telemetryToggle = page.getByRole('button', { name: /^Telemetry/ })
      if ((await telemetryToggle.getAttribute('aria-expanded')) !== 'true') {
        await telemetryToggle.click()
        await page.waitForFunction(
          () => document.querySelector('button[aria-controls="rail-telemetry-nav"]')?.getAttribute('aria-expanded') === 'true',
          undefined,
          { timeout: 10_000 * CI_TIMEOUT_MULT },
        )
      }
      const telemetryNav = page.getByRole('navigation', { name: 'Telemetry views' })
      await telemetryNav.waitFor({ state: 'visible', timeout: 5_000 * CI_TIMEOUT_MULT })
      assert.equal(await telemetryNav.getByRole('button', { name: /^Workflow/ }).count(), 0, 'Workflow must not appear inside Telemetry')
      // Collapse Telemetry back so screenshots show clean default rail
      await telemetryToggle.click()
      await page.waitForFunction(
        () => document.querySelector('button[aria-controls="rail-telemetry-nav"]')?.getAttribute('aria-expanded') === 'false',
        undefined,
        { timeout: 10_000 * CI_TIMEOUT_MULT },
      )

      // 2. Default mode is List (with Graph toggle working)
      const listRadio = page.getByRole('radio', { name: 'List' })
      const graphRadio = page.getByRole('radio', { name: 'Graph' })
      assert.equal(await listRadio.getAttribute('aria-checked'), 'true')
      assert.equal(await graphRadio.getAttribute('aria-checked'), 'false')
      await page.getByRole('region', { name: 'Worker list' }).waitFor({ state: 'visible', timeout: 10_000 * CI_TIMEOUT_MULT })

      // 3. Active now (3) section is pinned at top above completed phase groups
      const activeSection = page.getByTestId('workflow-active-section')
      await activeSection.waitFor({ state: 'visible', timeout: 10_000 * CI_TIMEOUT_MULT })
      await page.waitForFunction(
        () => {
          const el = document.querySelector('[data-testid="workflow-active-section"]')
          return Boolean(el && el.textContent && el.textContent.includes('2/5 Crawl'))
        },
        undefined,
        { timeout: 10_000 * CI_TIMEOUT_MULT },
      )
      const activeText = await activeSection.innerText()
      assert.match(activeText, /Active now \(3\)/)
      assert.match(activeText, /Round-0 Threat Model & Surface Ranking/)
      assert.match(activeText, /2\/5 Crawl/)
      assert.match(activeText, /Cross-tenant invoice IDOR differential check/)
      assert.match(activeText, /Running/)
      assert.match(activeText, /Replay confirmation · Admin role escalation/)
      assert.match(activeText, /Paused/)

      const verifyViewportGeometry = async (width: number, height: number, shotName?: string) => {
        await page!.setViewportSize({ width, height })
        await waitForLayoutSettled(page!)
        const geo = await page!.evaluate(() => {
          const docOverflow = document.documentElement.scrollWidth > document.documentElement.clientWidth
          const list = document.querySelector<HTMLElement>('[role="region"][aria-label="Worker list"]')
          const listOverflow = list ? list.scrollWidth > list.clientWidth + 1 : true
          const active = document.querySelector<HTMLElement>('[data-testid="workflow-active-section"]')
          const activeRect = active?.getBoundingClientRect()
          const firstGroupHead = list?.querySelector<HTMLElement>('[role="button"][aria-expanded]')
          const groupRect = firstGroupHead?.getBoundingClientRect()
          const activeRows = [...(active?.querySelectorAll<HTMLElement>('[data-id]') ?? [])]
          let overlap = false
          for (let i = 0; i + 1 < activeRows.length; i += 1) {
            const a = activeRows[i]!.getBoundingClientRect()
            const b = activeRows[i + 1]!.getBoundingClientRect()
            if (a.bottom > b.top + 1) overlap = true
          }
          const activeAboveGroups = Boolean(activeRect && groupRect && activeRect.bottom <= groupRect.top + 2)
          const activeVisibleAboveFold = Boolean(activeRect && activeRect.top >= 0 && activeRect.bottom <= window.innerHeight)
          return {
            docOverflow,
            docScrollW: document.documentElement.scrollWidth,
            docClientW: document.documentElement.clientWidth,
            listOverflow,
            listScrollW: list?.scrollWidth ?? -1,
            listClientW: list?.clientWidth ?? -1,
            overlap,
            activeAboveGroups,
            activeVisibleAboveFold,
            activeTop: activeRect?.top ?? -1,
            activeBottom: activeRect?.bottom ?? -1,
            groupTop: groupRect?.top ?? -1,
            innerHeight: window.innerHeight,
            activeRowCount: activeRows.length,
          }
        })
        const diag = JSON.stringify(geo)
        assert.equal(geo.docOverflow, false, `Zero document overflow at ${width}x${height}: ${diag}`)
        assert.equal(geo.listOverflow, false, `Zero worker list horizontal overflow at ${width}x${height}: ${diag}`)
        assert.equal(geo.overlap, false, `Zero overlapping active rows at ${width}x${height}: ${diag}`)
        assert.equal(geo.activeAboveGroups, true, `Active now section must sit above phase groups at ${width}x${height}: ${diag}`)
        assert.equal(geo.activeVisibleAboveFold, true, `Active now section must be visible above the fold at ${width}x${height}: ${diag}`)
        assert.equal(geo.activeRowCount, 3, `Expected 3 active rows at ${width}x${height}: ${diag}`)

        const shotDir = process.env.WORKFLOW_LIST_SCREENSHOT_DIR
        if (shotDir && shotName) {
          mkdirSync(shotDir, { recursive: true })
          await page!.screenshot({ path: join(shotDir, shotName) })
        }
      }

      await verifyViewportGeometry(1280, 720, 'workflow-list-after-1280x720.png')
      await verifyViewportGeometry(1440, 900, 'workflow-list-after-1440x900.png')

      // 4. Graph toggle & explicit ?mode=graph still work 100%
      await graphRadio.click()
      await page.waitForFunction(
        () =>
          document.querySelector('[role="radio"][aria-label="Graph"]')?.getAttribute('aria-checked') === 'true'
          && new URLSearchParams(window.location.search).get('mode') === 'graph',
        undefined,
        { timeout: 10_000 * CI_TIMEOUT_MULT },
      )
      assert.equal(await graphRadio.getAttribute('aria-checked'), 'true')
      assert.match(page.url(), /mode=graph/)
      await page.locator('[data-wf-kind="worker"][data-n="w-inv-live"]').waitFor({ state: 'visible', timeout: 10_000 * CI_TIMEOUT_MULT })

      await listRadio.click()
      await page.waitForFunction(
        () =>
          document.querySelector('[role="radio"][aria-label="List"]')?.getAttribute('aria-checked') === 'true'
          && !new URLSearchParams(window.location.search).has('mode'),
        undefined,
        { timeout: 10_000 * CI_TIMEOUT_MULT },
      )
      assert.equal(await listRadio.getAttribute('aria-checked'), 'true')
      assert.equal(page.url().includes('mode=graph'), false)
      await activeSection.waitFor({ state: 'visible', timeout: 10_000 * CI_TIMEOUT_MULT })

      await page.goto(`${kovo.origin}/runs/${runId}?view=workflow&mode=graph`, { waitUntil: 'load' })
      await page.getByLabel(/Workflow graph/).waitFor({ state: 'visible', timeout: 10_000 * CI_TIMEOUT_MULT })
      await page.locator('[data-wf-kind="worker"][data-n="w-inv-live"]').waitFor({ state: 'visible', timeout: 10_000 * CI_TIMEOUT_MULT })
      await page.waitForFunction(
        () => document.querySelector('[role="radio"][aria-label="Graph"]')?.getAttribute('aria-checked') === 'true',
        undefined,
        { timeout: 10_000 * CI_TIMEOUT_MULT },
      )
      assert.equal(await page.getByRole('radio', { name: 'Graph' }).getAttribute('aria-checked'), 'true')

      // 5. Terminal run never displays "Active now" or stale pulsing spinners (even if a legacy row was running in SQLite)
      withSqlite(kovo.dataDir, db => {
        db.prepare(`UPDATE runs SET status = 'complete', phase = 'complete' WHERE id = ?`).run(runId)
      })
      await page.goto(`${kovo.origin}/runs/${runId}?view=workflow`, { waitUntil: 'load' })
      await page.getByRole('region', { name: 'Worker list' }).waitFor({ state: 'visible', timeout: 10_000 * CI_TIMEOUT_MULT })
      await waitForHydrated(page, '[role="region"][aria-label="Worker list"]', 10_000 * CI_TIMEOUT_MULT)
      assert.equal(await page.getByTestId('workflow-active-section').count(), 0, 'Completed run must never show Active now section')
      const liveDots = await page.locator('[role="region"][aria-label="Worker list"] .animate-ping').count()
      assert.equal(liveDots, 0, 'Completed run must never show pulsing live spinners')
      assert.deepEqual(pageErrors, [], `Unexpected browser page errors: ${pageErrors.join('; ')}`)
      },
    )
  })
})
