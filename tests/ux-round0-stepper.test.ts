import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser, BrowserContext, Page } from '@playwright/test'
import {
  deriveRound0PipelineState,
  fmtEventKind,
  isRound0ThreatModelWorker,
} from '../src/components/run/format.ts'
import type { Round0DerivationInput } from '../src/components/run/format.ts'

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
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-round0-stepper-'))
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''

  const child: ChildProcess = spawn(process.execPath, ['scripts/serve.ts'], {
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
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (child.exitCode !== null) break
    try {
      const res = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(300) })
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

function withSqlite<T>(dataDir: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(join(dataDir, 'kovo.sqlite'))
  try {
    db.exec('PRAGMA busy_timeout = 5000;')
    return fn(db)
  } finally {
    db.close()
  }
}

const SAMPLE_27_ORIGINS = [
  'https://app.acme-cloud.example',
  'https://api.acme-cloud.example',
  'https://auth.acme-cloud.example',
  'https://admin.acme-cloud.example',
  'https://billing.acme-cloud.example',
  'https://portal.acme-cloud.example',
  'https://console.acme-cloud.example',
  'https://graphql.acme-cloud.example',
  'https://gateway.acme-cloud.example',
  'https://accounts.acme-cloud.example',
  'https://sso.acme-cloud.example',
  'https://docs.acme-cloud.example',
  'https://status.acme-cloud.example',
  'https://dashboard.acme-cloud.example',
  'https://webhooks.acme-cloud.example',
  'https://files.acme-cloud.example',
  'https://media.acme-cloud.example',
  'https://cdn.acme-cloud.example',
  'https://staging.acme-cloud.example',
  'https://beta.acme-cloud.example',
  'https://sandbox.acme-cloud.example',
  'https://internal.acme-cloud.example',
  'https://metrics.acme-cloud.example',
  'https://support.acme-cloud.example',
  'https://mail.acme-cloud.example',
  'https://help.acme-cloud.example',
  'https://blog.acme-cloud.example',
]

function makeRound0Input(overrides?: {
  assignment?: Partial<Round0DerivationInput['assignment']>
  run?: Partial<Round0DerivationInput['detail']['run']>
  detail?: Partial<Omit<Round0DerivationInput['detail'], 'run'>>
  events?: Round0DerivationInput['events']
}): Round0DerivationInput {
  return {
    assignment: {
      id: 'worker-round0',
      phase: 'threat_model',
      status: 'running',
      stepId: null,
      title: 'Round-0 Threat Model & Surface Ranking',
      turnsUsed: 0,
      requestsUsed: 0,
      sourceOrigins: SAMPLE_27_ORIGINS,
      ...overrides?.assignment,
    },
    detail: {
      run: {
        phase: 'threat_model',
        status: 'running',
        phase0CompletedAt: null,
        candidates: SAMPLE_27_ORIGINS.map((origin, idx) => ({ id: `cand-${idx + 1}`, origin })),
        approved: SAMPLE_27_ORIGINS.map((_, idx) => `cand-${idx + 1}`),
        ...overrides?.run,
      },
      endpoints: [],
      endpointParams: [],
      exchangesSummary: [],
      threatModel: null,
      chainSteps: [],
      projection: { totals: { endpoints: 0, endpointParams: 0, exchanges: 0 } },
      ...overrides?.detail,
    },
    events: overrides?.events ?? [],
  }
}

describe('Round-0 stage stepper, live telemetry, and collapsed traffic drawer', () => {
  it('formats all phase0.* event kinds into human-readable labels', () => {
    const requiredKinds = [
      'phase0.stage',
      'phase0.discovery',
      'phase0.completed',
      'phase0.crawl_paged',
      'phase0.read_paged',
      'phase0.privileged_surface',
      'phase0.code_slices',
      'phase0.program_graph',
      'phase0.param_discovery',
      'phase0.runtime_catalog',
    ]
    for (const kind of requiredKinds) {
      const label = fmtEventKind(kind)
      assert.ok(label.length > 0, `Expected label for ${kind}`)
      assert.equal(label.includes('phase0'), false, `Label for ${kind} should be plain English, got "${label}"`)
    }
  })

  it('detects Round-0 orchestrator worker without misclassifying per-host baseline or step workers', () => {
    assert.equal(isRound0ThreatModelWorker({
      phase: 'threat_model',
      stepId: null,
      title: 'Round-0 Threat Model & Surface Ranking',
    }), true)
    assert.equal(isRound0ThreatModelWorker({
      phase: 'threat_model',
      stepId: null,
      title: 'Baseline capture · app.acme-cloud.example',
    }), false)
    assert.equal(isRound0ThreatModelWorker({
      phase: 'investigation',
      stepId: 'step-1',
      title: 'Round-0 follow-up check',
    }), false)
  })

  it('derives empty start state cleanly (Step 1 active, Steps 2-5 pending)', () => {
    const state = deriveRound0PipelineState(makeRound0Input())
    assert.equal(state.isComplete, false)
    assert.equal(state.doneSteps, 0)
    assert.equal(state.activeStepIndex, 0)
    assert.equal(state.stageBadge, 'Stage 1/5 · Fingerprint')
    assert.equal(state.stageShort, '1/5 Fingerprint')
    assert.deepEqual(state.steps.map(s => s.status), ['active', 'pending', 'pending', 'pending', 'pending'])
    assert.equal(state.counts.totalHosts, 27)
    assert.equal(state.counts.mappedHosts, 0)
    assert.equal(state.counts.endpoints, 0)
    assert.equal(state.counts.requests, 0)
    assert.equal(state.hosts.length, 27)
  })

  it('derives mid-crawl state with 27 hosts & 251 endpoints (both historical crawl_paged and live phase0.stage)', () => {
    const mapped14 = SAMPLE_27_ORIGINS.slice(0, 14)
    const sampleEndpoints = [
      ...Array.from({ length: 12 }, (_, i) => ({
        origin: 'https://api.acme-cloud.example',
        method: 'GET',
        pathTemplate: `/api/v1/projects/:id/items-${i}`,
        source: 'openapi',
        framework: 'Express',
        authRequirement: null,
      })),
      {
        origin: 'https://admin.acme-cloud.example',
        method: 'GET',
        pathTemplate: '/admin/users',
        source: 'spa_crawl',
        framework: 'Next.js',
        authRequirement: 'persona:admin',
      },
      {
        origin: 'https://admin.acme-cloud.example',
        method: 'POST',
        pathTemplate: '/admin/audit-export',
        source: 'spa_crawl',
        framework: 'Next.js',
        authRequirement: 'persona:admin',
      },
      ...mapped14.slice(2).map((origin, idx) => ({
        origin,
        method: 'GET',
        pathTemplate: `/route-${idx}`,
        source: 'surface_probe',
        framework: null,
        authRequirement: null,
      })),
    ]
    const exchangesSummary = [
      { id: 'ex-1', assignmentId: 'worker-round0', origin: 'https://api.acme-cloud.example', method: 'GET', pathAndQuery: '/api/v1/me', status: 401 },
      { id: 'ex-2', assignmentId: 'worker-round0', origin: 'https://admin.acme-cloud.example', method: 'GET', pathAndQuery: '/admin/users', status: 403 },
      { id: 'ex-3', assignmentId: 'worker-round0', origin: 'https://admin.acme-cloud.example', method: 'GET', pathAndQuery: '/admin/health', status: 500 },
      { id: 'ex-4', assignmentId: 'worker-round0', origin: 'https://app.acme-cloud.example', method: 'GET', pathAndQuery: '/', status: 200 },
    ]

    // 1. Historical / already-running run WITHOUT phase0.stage (only phase0.crawl_paged)
    const historical = deriveRound0PipelineState(makeRound0Input({
      assignment: { requestsUsed: 148 },
      detail: {
        endpoints: sampleEndpoints,
        exchangesSummary,
        projection: { totals: { endpoints: 251, endpointParams: 44, exchanges: 148 } },
      },
      events: [
        {
          kind: 'phase0.crawl_paged',
          message: 'State-graph crawl read 251 endpoint rows.',
          detail: { origin: 'https://api.acme-cloud.example', considered: 251, used: 180, pages: 1 },
        },
      ],
    }))
    assert.equal(historical.activeStepIndex, 1)
    assert.deepEqual(historical.steps.map(s => s.status), ['done', 'active', 'pending', 'pending', 'pending'])
    assert.equal(historical.counts.endpoints, 251)
    assert.equal(historical.counts.params, 44)
    assert.equal(historical.counts.totalHosts, 27)
    assert.equal(historical.counts.mappedHosts, 14)
    assert.equal(historical.counts.authGated, 2)
    assert.equal(historical.counts.privileged, 2)
    assert.equal(historical.counts.requests, 148)
    assert.deepEqual(historical.frameworks, ['Express', 'Next.js'])
    assert.match(historical.steps[1]!.metric ?? '', /14\/27 hosts · 251 endpoints/)
    assert.equal(historical.hosts[0]?.origin, 'https://api.acme-cloud.example')
    assert.equal(historical.hosts[1]?.origin, 'https://admin.acme-cloud.example')
    assert.equal(historical.hosts[1]?.status403, 1)
    assert.equal(historical.hosts[1]?.status5xx, 1)

    // 2. Live run WITH phase0.stage telemetry advancing through crawl -> templates -> auth -> ranking
    const liveCrawl = deriveRound0PipelineState(makeRound0Input({
      assignment: { requestsUsed: 148 },
      detail: {
        endpoints: sampleEndpoints,
        exchangesSummary,
        projection: { totals: { endpoints: 251, endpointParams: 44, exchanges: 148 } },
      },
      events: [
        {
          kind: 'phase0.stage',
          message: 'Crawling SPA state graph on https://api.acme-cloud.example (14/27).',
          detail: {
            stage: 'crawl_state_graph',
            label: 'Crawling SPA state graph on https://api.acme-cloud.example (14/27).',
            origin: 'https://api.acme-cloud.example',
            hostsDone: 14,
            hostsTotal: 27,
            endpointsDiscovered: 251,
            paramsDiscovered: 44,
            requestsUsed: 148,
            frameworks: ['Express', 'Next.js'],
          },
        },
      ],
    }))
    assert.equal(liveCrawl.activeStepIndex, 1)
    assert.equal(liveCrawl.stageBadge, 'Stage 2/5 · Crawl')
    assert.equal(liveCrawl.currentOrigin, 'https://api.acme-cloud.example')

    const liveTemplates = deriveRound0PipelineState(makeRound0Input({
      assignment: { requestsUsed: 220 },
      detail: { endpoints: sampleEndpoints, exchangesSummary, projection: { totals: { endpoints: 251, endpointParams: 44, exchanges: 220 } } },
      events: [
        { kind: 'phase0.stage', detail: { stage: 'api_templates', hostsDone: 18, hostsTotal: 27, requestsUsed: 220 } },
      ],
    }))
    assert.equal(liveTemplates.activeStepIndex, 2)
    assert.deepEqual(liveTemplates.steps.map(s => s.status), ['done', 'done', 'active', 'pending', 'pending'])

    const liveAuth = deriveRound0PipelineState(makeRound0Input({
      assignment: { requestsUsed: 290 },
      detail: { endpoints: sampleEndpoints, exchangesSummary, projection: { totals: { endpoints: 251, endpointParams: 44, exchanges: 290 } } },
      events: [
        { kind: 'phase0.stage', detail: { stage: 'auth_privileged', hostsDone: 27, hostsTotal: 27, requestsUsed: 290 } },
        {
          kind: 'phase0.privileged_surface',
          detail: {
            origin: 'https://admin.acme-cloud.example',
            routes: [{ method: 'DELETE', pathTemplate: '/admin/tenants/:id' }],
          },
        },
      ],
    }))
    assert.equal(liveAuth.activeStepIndex, 3)
    assert.deepEqual(liveAuth.steps.map(s => s.status), ['done', 'done', 'done', 'active', 'pending'])
    assert.equal(liveAuth.counts.privileged, 3)
    assert.match(liveAuth.steps[3]!.metric ?? '', /3 priv · 2 401\/403/)

    const liveRanking = deriveRound0PipelineState(makeRound0Input({
      assignment: { requestsUsed: 312 },
      run: { phase0CompletedAt: Date.now() },
      detail: { endpoints: sampleEndpoints, exchangesSummary, projection: { totals: { endpoints: 251, endpointParams: 44, exchanges: 312 } } },
      events: [
        { kind: 'phase0.discovery', detail: { requestsUsed: 312, endpointsDiscovered: 251, paramsDiscovered: 44, frameworksDetected: ['Express', 'Next.js', 'GraphQL'] } },
      ],
    }))
    assert.equal(liveRanking.activeStepIndex, 4)
    assert.deepEqual(liveRanking.steps.map(s => s.status), ['done', 'done', 'done', 'done', 'active'])
    assert.deepEqual(liveRanking.frameworks, ['Express', 'GraphQL', 'Next.js'])
  })

  it('derives post-threat_model.saved completed state (all 5 steps done + ranked/steps metric)', () => {
    const state = deriveRound0PipelineState(makeRound0Input({
      assignment: { status: 'complete', requestsUsed: 340 },
      run: { phase: 'investigation', status: 'running', phase0CompletedAt: 1_700_000_050_000 },
      detail: {
        threatModel: {
          entries: SAMPLE_27_ORIGINS.map(origin => ({ origin, riskTier: 'high' })),
        },
        chainSteps: Array.from({ length: 8 }, (_, i) => ({ id: `step-${i + 1}` })),
        projection: { totals: { endpoints: 251, endpointParams: 63, exchanges: 340 } },
      },
      events: [
        { kind: 'phase0.discovery', detail: { requestsUsed: 340, endpointsDiscovered: 251, paramsDiscovered: 63, frameworksDetected: ['Next.js'] } },
        { kind: 'threat_model.saved', detail: {} },
      ],
    }))
    assert.equal(state.isComplete, true)
    assert.equal(state.doneSteps, 5)
    assert.equal(state.stageBadge, '5/5 · Ranked')
    assert.equal(state.stageShort, '5/5 Ranked')
    assert.deepEqual(state.steps.map(s => s.status), ['done', 'done', 'done', 'done', 'done'])
    assert.equal(state.steps[4]!.metric, '27 ranked · 8 steps')
    assert.equal(state.counts.mappedHosts, 27)
  })

  it('preserves browser-safety and source invariants across leased files', () => {
    const phase0Src = readFileSync(join(REPO_ROOT, 'src/server/phase0-recon.ts'), 'utf8')
    const inspectorSrc = readFileSync(join(REPO_ROOT, 'src/components/run/views/workflow-inspector.tsx'), 'utf8')
    const graphSrc = readFileSync(join(REPO_ROOT, 'src/components/run/views/workflow-graph.tsx'), 'utf8')
    const formatSrc = readFileSync(join(REPO_ROOT, 'src/components/run/format.ts'), 'utf8')

    assert.match(phase0Src, /storage\.event\(runId,\s*'phase0\.stage'/)
    assert.match(phase0Src, /'phase0\.discovery'[\s\S]{0,400}frameworksDetected:\s*\[\.\.\.frameworksDetected\]/)

    for (const [name, src] of [
      ['workflow-inspector.tsx', inspectorSrc],
      ['workflow-graph.tsx', graphSrc],
      ['format.ts', formatSrc],
    ] as const) {
      assert.equal(/\bfrom\s+['"]node:/.test(src), false, `${name} must not import node:* builtins`)
    }
    assert.match(inspectorSrc, /h-auto[^\n]*whitespace-normal[^\n]*shadow-none/)
  })

  describe('Playwright E2E & visual geometry verification in Workflow view', () => {
    let skipReason: string | null = null
    let kovo: SpawnedKovoServer | undefined
    let browser: Browser | undefined
    let context: BrowserContext | undefined
    let page: Page | undefined
    const pageErrors: string[] = []
    let runId = ''
    const round0WorkerId = 'worker-round0-stepper-test'

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

      // 1. Bootstrap auth & create project + run via UI
      await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, {
        waitUntil: 'domcontentloaded',
      })
      await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })
      await page.getByLabel('Project name').fill('Acme Cloud Round-0')
      await page.getByLabel('Sites').fill('https://app.acme-cloud.example\nhttps://api.acme-cloud.example\nhttps://admin.acme-cloud.example')
      await page.getByRole('button', { name: 'Create project', exact: true }).click()
      await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 15_000 })

      await page.getByRole('button', { name: 'New run', exact: true }).click()
      const dialog = page.getByRole('dialog')
      await dialog.waitFor({ state: 'visible', timeout: 10_000 })
      await dialog.getByRole('button', { name: 'Start run', exact: true }).click()
      await page.waitForURL(/\/runs\/[a-f0-9-]+/, { timeout: 15_000 })
      const runMatch = /\/runs\/([a-f0-9-]+)/.exec(page.url())
      assert.ok(runMatch?.[1], `Expected run URL, got ${page.url()}`)
      runId = runMatch[1]

      // 2. Seed realistic live Round-0 recon state (27 hosts, 14 mapped, 251 endpoints, 28 exchanges, phase0.stage + phase0.crawl_paged)
      const now = Date.now()
      const candidates = SAMPLE_27_ORIGINS.map((origin, idx) => ({
        id: `cand-${idx + 1}`,
        origin,
        source: idx < 3 ? 'Project seed' : 'phase0_subdomain_discovery',
        thirdParty: false,
      }))
      const approved = candidates.map(c => c.id)

      withSqlite(kovo.dataDir, db => {
        const metaRow = db.prepare('SELECT workspace_id, goal_revision FROM runs WHERE id = ?').get(runId) as
          | { workspace_id: string; goal_revision: number }
          | undefined
        assert.ok(metaRow?.workspace_id, 'Expected workspace_id on seeded run')
        const goalRev = metaRow.goal_revision ?? 1

        db.prepare(
          `UPDATE runs
             SET phase = 'threat_model',
                 status = 'running',
                 scope_revision = 1,
                 candidates = ?,
                 approved = ?,
                 spent_requests = 148
           WHERE id = ?`,
        ).run(JSON.stringify(candidates), JSON.stringify(approved), runId)

        db.prepare(`DELETE FROM assignments WHERE run_id = ? AND phase = 'threat_model'`).run(runId)

        db.prepare(
          `INSERT INTO assignments (
             id, run_id, asset_id, step_id, input_assignment_id, phase, status,
             scope_revision, goal_revision, session_id, attempt, max_turns, turns_used, requests_used,
             parent_fact_ids, source_origins, title, objective, outcome, created_at
           ) VALUES (?, ?, ?, NULL, NULL, 'threat_model', 'running', 1, ?, ?, 0, 150, 0, 148, '[]', ?, ?, ?, NULL, ?)`,
        ).run(
          round0WorkerId,
          runId,
          'cand-1',
          goalRev,
          `sess-${round0WorkerId}`,
          JSON.stringify(SAMPLE_27_ORIGINS),
          'Round-0 Threat Model & Surface Ranking',
          'Rank 27 approved hosts by attack-surface richness and seed prioritized chain investigation steps.',
          now - 95_000,
        )

        const insertEp = db.prepare(
          `INSERT INTO endpoints (
             id, run_id, scope_revision, origin, method, path_template, source, framework,
             auth_requirement, risk_score, created_at, updated_at
           ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )

        // 251 endpoints distributed across the first 14 mapped hosts
        const hostWeights = [58, 42, 31, 24, 19, 16, 13, 11, 9, 8, 7, 5, 4, 4]
        assert.equal(hostWeights.reduce((a, b) => a + b, 0), 251)
        let epSeq = 0
        for (let h = 0; h < hostWeights.length; h += 1) {
          const origin = SAMPLE_27_ORIGINS[h]!
          const count = hostWeights[h]!
          const fw = h === 0 ? 'Next.js' : h === 1 ? 'Express' : h === 7 ? 'GraphQL' : null
          for (let k = 0; k < count; k += 1) {
            epSeq += 1
            const isPriv = h === 3 && k < 5
            const path = isPriv
              ? `/admin/controls/${k + 1}`
              : h === 1
                ? `/api/v1/resource-${k + 1}/:id`
                : `/app/section-${k + 1}`
            insertEp.run(
              `ep-${epSeq}`,
              runId,
              origin,
              k % 5 === 0 ? 'POST' : 'GET',
              path,
              h === 1 ? 'openapi' : 'spa_crawl',
              fw,
              isPriv ? 'persona:admin' : null,
              isPriv ? 90 : 60,
              now - 80_000 + epSeq * 50,
              now - 80_000 + epSeq * 50,
            )
          }
        }

        // Seed 28 broker exchanges on Round-0 worker (triggers >20 collapse on Evidence tab too)
        const insertEx = db.prepare(
          `INSERT INTO broker_exchanges (
             id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins,
             method, path_and_query, persona_handle, status, media_type, req_headers, resp_headers,
             body_preview, body_sha256, secret_matches, duration_ms, created_at
           ) VALUES (?, ?, ?, 1, ?, ?, '[]', ?, ?, NULL, ?, 'application/json', '{}', '{}', '{}', ?, '[]', 42, ?)`,
        )
        for (let i = 0; i < 28; i += 1) {
          const origin = SAMPLE_27_ORIGINS[i % 10]!
          const status = i === 1 || i === 5 || i === 11
            ? 401
            : i === 3 || i === 13
              ? 403
              : i === 7
                ? 500
                : 200
          const path = i % 3 === 0 ? `/api/v1/items/${i}` : i % 3 === 1 ? `/admin/panel/${i}` : `/page/${i}`
          insertEx.run(
            `ex-r0-${i + 1}`,
            runId,
            round0WorkerId,
            origin,
            origin,
            i % 4 === 0 ? 'POST' : 'GET',
            path,
            status,
            `sha-${i + 1}`,
            now - 70_000 + i * 1_000,
          )
        }

        const runRow = db.prepare('SELECT workspace_id FROM runs WHERE id = ?').get(runId) as { workspace_id: string } | undefined
        assert.ok(runRow?.workspace_id, 'Expected workspace_id on seeded run')
        const insertEv = db.prepare(
          `INSERT INTO events (workspace_id, run_id, kind, message, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
        )
        insertEv.run(
          runRow.workspace_id,
          runId,
          'phase0.stage',
          'Fingerprinting https://app.acme-cloud.example (1/27).',
          JSON.stringify({
            stage: 'host_fingerprint',
            label: 'Fingerprinting https://app.acme-cloud.example (1/27).',
            origin: 'https://app.acme-cloud.example',
            hostsDone: 1,
            hostsTotal: 27,
            endpointsDiscovered: 18,
            paramsDiscovered: 6,
            requestsUsed: 12,
            frameworks: ['Next.js'],
          }),
          now - 85_000,
        )
        insertEv.run(
          runRow.workspace_id,
          runId,
          'phase0.crawl_paged',
          'State-graph crawl read 251 endpoint row(s) across 1 page(s); 180 route(s) resolved.',
          JSON.stringify({
            phase: 'state_graph',
            origin: 'https://api.acme-cloud.example',
            considered: 251,
            used: 180,
            truncated: false,
            reads: 1,
            pages: 1,
          }),
          now - 30_000,
        )
        insertEv.run(
          runRow.workspace_id,
          runId,
          'phase0.stage',
          'Crawling SPA state graph on https://api.acme-cloud.example (14/27).',
          JSON.stringify({
            stage: 'crawl_state_graph',
            label: 'Crawling SPA state graph on https://api.acme-cloud.example (14/27).',
            origin: 'https://api.acme-cloud.example',
            hostsDone: 14,
            hostsTotal: 27,
            endpointsDiscovered: 251,
            paramsDiscovered: 44,
            requestsUsed: 148,
            frameworks: ['Next.js', 'Express', 'GraphQL'],
          }),
          now - 10_000,
        )
      })
    })

    after(async () => {
      await context?.close()
      await browser?.close()
      await kovo?.stop()
    })

    it('renders the 5-step stepper, discovery counters, top hosts, collapsed network log, and hides 0/150 turns at 1280x720 and 1440x900', async t => {
      if (skipReason || !page || !kovo) {
        t.skip(skipReason ?? 'Playwright unavailable')
        return
      }

      const url = `${kovo.origin}/runs/${runId}?view=workflow&sel=worker:${round0WorkerId}`
      await page.setViewportSize({ width: 1280, height: 720 })
      await page.goto(url, { waitUntil: 'domcontentloaded' })

      const stepper = page.getByTestId('round0-stage-stepper')
      await stepper.waitFor({ state: 'visible', timeout: 15_000 })

      // 1. Verify 5-step stepper states (Step 1 done, Step 2 active, Steps 3-5 pending)
      assert.equal(await page.getByTestId('round0-stage-fingerprint').getAttribute('data-stage-status'), 'done')
      assert.equal(await page.getByTestId('round0-stage-crawl').getAttribute('data-stage-status'), 'active')
      assert.equal(await page.getByTestId('round0-stage-templates').getAttribute('data-stage-status'), 'pending')
      assert.equal(await page.getByTestId('round0-stage-auth').getAttribute('data-stage-status'), 'pending')
      assert.equal(await page.getByTestId('round0-stage-ranking').getAttribute('data-stage-status'), 'pending')

      // 2. Verify discovery counters + frameworks pills
      const countersText = await page.getByTestId('round0-discovery-counters').innerText()
      assert.match(countersText, /Endpoints\s+251/)
      assert.match(countersText, /Active hosts\s+14\s*\/\s*27/)
      assert.match(countersText, /Auth-gated[\s\S]*5/)
      assert.match(countersText, /Privileged\s+5/)
      assert.match(countersText, /Requests\s+148/)

      const fwText = await page.getByTestId('round0-frameworks').innerText()
      assert.match(fwText, /Express/)
      assert.match(fwText, /Next\.js/)

      // 3. Verify "0 of 150" / "0/150 turns" is NOT shown in the Round-0 WorkerInspector or Round-0 NodeCard
      const inspectorPane = page.locator('aside').filter({ has: stepper }).first()
      const inspectorText = (await inspectorPane.count()) > 0
        ? await inspectorPane.innerText()
        : await page.locator('body').innerText()
      assert.equal(/0\s+of\s+150/.test(inspectorText), false, 'Inspector must not show "0 of 150" turns for Round-0')
      assert.equal(/0\/150\s+turns/i.test(inspectorText), false, 'Inspector must not show "0/150 turns" for Round-0')
      const round0Card = page.locator(`[data-n="${round0WorkerId}"]`)
      await round0Card.waitFor({ state: 'visible', timeout: 10_000 })
      const cardText = await round0Card.innerText()
      assert.equal(/0\/150\s+turns/i.test(cardText), false, 'NodeCard must not show "0/150 turns" for Round-0')
      assert.match(cardText, /2\/5 Crawl/)
      assert.match(cardText, /14\/27 hosts/)
      assert.match(cardText, /148 req/)

      // 4. Verify Top Hosts preview shows 6 rows and expands to all 27 on click
      const hostRows = page.getByTestId('round0-host-row')
      assert.equal(await hostRows.count(), 6)
      const hostsToggle = page.getByTestId('round0-hosts-toggle')
      assert.match(await hostsToggle.innerText(), /Show all 27 hosts/)

      // 5. Verify raw network log is collapsed by default and expands on click
      const netToggle = page.getByTestId('round0-network-log-toggle')
      assert.equal(await netToggle.getAttribute('aria-expanded'), 'false')
      assert.equal(await page.getByTestId('round0-network-log-panel').count(), 0)

      // Wait briefly for workflow graph camera easing to settle before screenshot
      await delay(400)

      // Capture 1280x720 screenshot in default collapsed state (if requested)
      const shotDir = process.env.ROUND0_SCREENSHOT_DIR
      if (shotDir) {
        mkdirSync(shotDir, { recursive: true })
        await page.screenshot({ path: join(shotDir, 'round0-workflow-1280x720.png') })
      }

      // Check zero horizontal overflow, zero label truncation in counters, and zero overlapping controls at 1280x720
      const geo1280 = await page.evaluate(() => {
        const docOverflow = document.documentElement.scrollWidth > document.documentElement.clientWidth
        const stepperRect = document.querySelector('[data-testid="round0-stage-stepper"]')?.getBoundingClientRect()
        const countersRect = document.querySelector('[data-testid="round0-discovery-counters"]')?.getBoundingClientRect()
        const hostsRect = document.querySelector('[data-testid="round0-top-hosts"]')?.getBoundingClientRect()
        const netRect = document.querySelector('[data-testid="round0-network-drawer"]')?.getBoundingClientRect()
        const statLabels = [...document.querySelectorAll<HTMLElement>('[data-round0-stat-label]')]
        const truncatedLabels = statLabels.filter(el => el.scrollWidth > el.clientWidth + 1).map(el => el.textContent)
        const ordered = Boolean(
          stepperRect && countersRect && hostsRect && netRect
          && stepperRect.bottom <= countersRect.top + 2
          && countersRect.bottom <= hostsRect.top + 2
          && hostsRect.bottom <= netRect.top + 2,
        )
        return { docOverflow, ordered, truncatedLabels }
      })
      assert.equal(geo1280.docOverflow, false, 'Zero horizontal overflow at 1280x720')
      assert.equal(geo1280.ordered, true, 'Round-0 stepper, counters, hosts, and network drawer must not overlap')
      assert.deepEqual(geo1280.truncatedLabels, [], 'Discovery counter labels must not truncate')

      // Expand network log and verify rows appear
      await netToggle.click()
      assert.equal(await netToggle.getAttribute('aria-expanded'), 'true')
      await page.getByTestId('round0-network-log-panel').waitFor({ state: 'visible', timeout: 5_000 })
      const panelText = await page.getByTestId('round0-network-log-panel').innerText()
      assert.match(panelText, /\/api\/v1\/items\/0/)
      await netToggle.click()
      assert.equal(await netToggle.getAttribute('aria-expanded'), 'false')

      // Expand hosts toggle and verify 27 rows render, then collapse back
      await hostsToggle.click()
      assert.equal(await hostRows.count(), 27)
      await hostsToggle.click()
      assert.equal(await hostRows.count(), 6)

      // Check Evidence tab keeps Exchanges collapsed when > 20 exchanges on Round-0
      await page.getByRole('tab', { name: /Evidence/ }).click()
      const evExchangesTrigger = page.getByRole('button', { name: /Exchanges/ })
      await evExchangesTrigger.waitFor({ state: 'visible', timeout: 5_000 })
      assert.equal(await evExchangesTrigger.getAttribute('aria-expanded'), 'false')
      await evExchangesTrigger.click()
      assert.equal(await evExchangesTrigger.getAttribute('aria-expanded'), 'true')
      await page.getByRole('tab', { name: /Summary/ }).click()
      await stepper.waitFor({ state: 'visible', timeout: 5_000 })

      // 6. Verify 1440x900 viewport geometry + capture screenshot
      await page.setViewportSize({ width: 1440, height: 900 })
      await delay(250)
      if (shotDir) {
        await page.screenshot({ path: join(shotDir, 'round0-workflow-1440x900.png') })
      }
      const overflow1440 = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)
      assert.equal(overflow1440, false, 'Zero horizontal overflow at 1440x900')
      assert.deepEqual(pageErrors, [], `Unexpected page errors: ${pageErrors.join('; ')}`)
    })
  })
})
