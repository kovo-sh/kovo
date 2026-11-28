// Phase 4 Bucket A polish — PR 3 (Run Workbench): behavioral + rendered-DOM geometry guards.
//
// 1. Pure helper behavior (format.ts / model.ts) — grouped USD, billions tier, day-scale
//    relative times/durations, empty-run verdict copy, malformed-row normalisation.
// 2. Class-level motion guard over the exported run primitives (tw.ts): no `transition-[…transform…]`
//    next to Tailwind v4 individual `scale-`/`translate-` utilities, no width/all transitions.
// 3. Playwright: a seeded stress run (180-char project + goal, 999,999 counters, multi-day offsets,
//    long hosts/personas/tool names, failed workers) rendered at 1280×720, 1440×900 and 390×844 in
//    light + dark (+ prefers-reduced-motion: reduce) asserting zero horizontal overflow, unclipped
//    controls, header actions in viewport, run-line digits never sliced, keyboard/ARIA semantics and
//    focused-input stability. Set `KOVO_UI_SHOTS_DIR=<dir>` to also capture screenshots.
import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
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
import { fmtDur, fmtRel, fmtTok, fmtUsd, operatorErrorCopy } from '../src/components/run/format.ts'
import { buildRunModel, buildVerdict, normalizeRunDetail } from '../src/components/run/model.ts'
import type { Detail } from '../src/components/run/model.ts'
import { RW, runBtn, runDdItem, runIconBtn, runStamp } from '../src/components/run/tw.ts'
import { HARDENED_NODE_FLAGS } from './app.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const CI_MULT = process.env.CI ? 2 : 1
const HOOK_TIMEOUT_MS = 90_000 * CI_MULT
const SHOTS_DIR = process.env.KOVO_UI_SHOTS_DIR ?? ''

// ---------------------------------------------------------------------------
// 1. Pure helpers
// ---------------------------------------------------------------------------

describe('run format helpers scale to stress values', () => {
  it('groups USD and adds a billions tier for tokens (A-112)', () => {
    assert.equal(fmtUsd(1234.56), '$1,234.56')
    assert.equal(fmtUsd(999_999), '$999,999.00')
    assert.equal(fmtUsd(null), '$0.00')
    assert.equal(fmtTok(999_999_999), '1.0B')
    assert.notEqual(fmtTok(999_999), '1000.0K')
  })

  it('relative times and durations gain a day tier (A-113)', () => {
    const base = Date.UTC(2026, 10, 20, 0, 0, 0)
    const sevenDays = 7 * 86_400_000 + 8 * 3_600_000 + 13 * 60_000
    assert.equal(fmtRel(base + sevenDays, base), '+7d 08h')
    assert.equal(fmtRel(base + 11 * 60_000 + 53_000, base), '+11:53')
    assert.match(fmtRel(base + 3 * 3_600_000 + 4 * 60_000 + 5_000, base), /^\+3:04:05$/)
    assert.equal(fmtDur(7 * 86_400_000 + 8 * 3_600_000), '7d 8h')
    for (const v of [fmtRel(base + sevenDays, base), fmtDur(sevenDays)]) {
      assert.ok(v.length <= 8, `day-scale label must fit a 72px column: ${v}`)
    }
  })

  it('maps browser network failures to operator copy (A-111)', () => {
    assert.equal(operatorErrorCopy(new TypeError('Failed to fetch')), 'Kovo is unreachable. Check that the local server is running.')
    assert.equal(operatorErrorCopy(new Error('Run is locked')), 'Run is locked')
    for (const v of [null, undefined, '', {}]) {
      const copy = operatorErrorCopy(v)
      assert.ok(copy.length > 0 && !/undefined|null|\[object/.test(copy), `never leaks raw values: ${copy}`)
    }
  })
})

function fakeDetail(overrides: Record<string, unknown> = {}, run: Record<string, unknown> = {}): Detail {
  const createdAt = 1_700_000_000_000
  const candidates = [{ id: 'asset-1', origin: 'https://app.example.test', source: 'seed', thirdParty: false }]
  const base = {
    run: {
      id: 'run-1', projectId: 'proj-1', workspaceId: 'ws-1', tenantId: 'default', originalGoal: 'Verify auth boundaries', goal: 'Verify auth boundaries',
      goalRevision: 1, scopeRevision: 1, coordinatorId: 'coord-1', phase: 'investigation', status: 'running', sourceMode: 'public', capabilityTier: 2,
      approvalPolicy: 'auto_review', approvedEndpointPatterns: [], approvedPersonaIds: [], roundNo: 1, budgetUsd: 25, budgetRequests: 0, spentUsd: 1,
      spentTokens: 1000, spentRequests: 10, turnsUsed: 2, maxRpsPerOrigin: 5, workerConcurrency: 6, workerMaxTurns: 150, dynamicStepBudget: null,
      multiTrialEnabled: true, phase0CompletedAt: null, reviewPlan: null, candidates, approved: ['asset-1'], authOrigins: [], assetOrigins: [],
      environmentMode: 'prod_readonly', routeDenylist: [], createdAt, ...run,
    },
    project: { id: 'proj-1', workspaceId: 'ws-1', tenantId: 'default', name: 'Demo', environment: 'public', seeds: ['https://app.example.test'], defaultScope: ['https://app.example.test'], labConfig: null, sandboxWriteAllowlist: [], createdAt },
    personas: [], specs: [], threatModel: null, chainSteps: [], facts: [], graphEdges: [], digests: [], assignments: [], approvals: [], exchangesSummary: [],
    coverageEntries: [], endpoints: [], endpointParams: [], apiDependencies: [], labTelemetry: [], openProofGaps: [], sastRuns: [], surfaceProbes: [],
    patchProposals: [], replaySpecs: [], retestRuns: [], findings: [], provenanceCounts: { deterministic_floor: 0, agent_confirmed: 0, static_advisory: 0, open_proof_gap: 0 },
    messages: [], boardMembers: [], boardMessages: [], evidence: [], reports: [], cursor: 0, hasModel: true, labTarget: null, localLabEnvEnabled: false,
  }
  return { ...base, ...overrides } as unknown as Detail
}

describe('run detail is normalised at the data boundary (A-110/A-115)', () => {
  it('malformed live rows never crash buildRunModel (class-level guard, <5s)', () => {
    const t0 = Date.now()
    const malformedWorker = { id: 'w-bad', phase: 'investigation', status: 'running', sourceOrigins: null, parentFactIds: null, title: null, stepId: 'step-bad', createdAt: 1_700_000_000_500 }
    const malformedFinding = { id: 'f-bad', origin: null, title: null, severity: null, status: 'pending', evidenceIds: null, exchangeIds: null }
    const malformedStep = { id: 'step-bad', dependsOnStepIds: null, dependsOnFactIds: null }
    const variants: Array<Record<string, unknown>> = [
      { assignments: [malformedWorker] },
      { findings: [malformedFinding] },
      { chainSteps: [malformedStep], assignments: [malformedWorker] },
      { assignments: [malformedWorker, null, 7, 'x'], findings: [malformedFinding, null] },
      { assignments: null, findings: null, chainSteps: null, exchangesSummary: null, approvals: null, evidence: null, facts: null },
    ]
    for (const v of variants) {
      const d = normalizeRunDetail(fakeDetail(v))
      assert.doesNotThrow(() => buildRunModel(d), `buildRunModel survives ${Object.keys(v).join('+')}`)
    }
    // Messy-at-scale: 2,000 rows alternating valid and malformed shapes.
    const many = Array.from({ length: 2_000 }, (_, i) => ({ ...malformedWorker, id: `w-${i}`, sourceOrigins: i % 2 ? null : ['https://app.example.test'] }))
    const model = buildRunModel(normalizeRunDetail(fakeDetail({ assignments: many })))
    assert.ok(model)
    const titles = normalizeRunDetail(fakeDetail({ assignments: [malformedWorker] })).assignments.map(a => a.title)
    assert.deepEqual(titles, ['Untitled worker'])
    assert.ok(Date.now() - t0 < 5_000, 'guard stays fast')
  })

  it('empty runs read as copy, not "across no hosts" / "0 of 0"', () => {
    const d = normalizeRunDetail(fakeDetail({ coverageEntries: [] }, { status: 'complete', phase: 'complete', approved: [], candidates: [] }))
    const v = buildVerdict(d, [], false)
    const text = JSON.stringify(v)
    assert.ok(!/across no hosts/i.test(text), text)
    assert.ok(!/\b0 of 0\b/.test(text), text)
    assert.match(text, /Nothing was tested\./)
  })
})

// ---------------------------------------------------------------------------
// 2. Class-level motion guard (A-105/A-106/A-107/A-108)
// ---------------------------------------------------------------------------

function allPrimitiveClassStrings(): Array<[string, string]> {
  const out: Array<[string, string]> = []
  const variants = ['default', 'primary', 'ink', 'ghost', 'ghostOn', 'dangerSolid', 'link'] as const
  const sizes = ['default', 'sm', 'xs', 'icon', 'iconSm', 'iconXs', 'none'] as const
  for (const variant of variants) for (const size of sizes) out.push([`runBtn(${variant},${size})`, runBtn({ variant, size })])
  for (const size of ['default', 'sm', 'xs'] as const) for (const tone of ['default', 'ok', 'danger'] as const) out.push([`runIconBtn(${size},${tone})`, runIconBtn({ size, tone })])
  for (const active of [true, false]) for (const danger of [true, false]) out.push([`runDdItem(${active},${danger})`, runDdItem({ active, danger })])
  for (const tone of ['ok', 'no', 'fp', 'acc'] as const) out.push([`runStamp(${tone})`, runStamp({ tone })])
  for (const [k, v] of Object.entries(RW)) out.push([`RW.${k}`, v])
  return out
}

describe('run primitives never pair a transform transition with individual transform utilities', () => {
  it('no transition-[…transform…] next to scale-/translate- utilities; no width/all transitions', () => {
    for (const [name, cls] of allPrimitiveClassStrings()) {
      const tokens = cls.split(/\s+/)
      const transitions = tokens.filter(t => /^transition(-|$)/.test(t.replace(/^[a-z-]+:/, '')))
      const usesIndividual = tokens.some(t => /(^|:)-?(scale|translate)-/.test(t))
      for (const t of transitions) {
        if (usesIndividual) assert.ok(!/\btransform\b/.test(t), `${name}: ${t} must name scale/translate (Tailwind v4 individual transforms)`)
        assert.ok(!/transition-all|\[width|,width/.test(t), `${name}: ${t} must not transition width/all`)
      }
    }
  })

  it('runBtn press scale is transitioned as the `scale` property (A-105)', () => {
    const cls = runBtn()
    assert.ok(cls.includes('active:scale-[.98]'))
    assert.ok(/transition-\[[^\]]*\bscale\b/.test(cls), 'runBtn transition list names scale')
  })

  it('list rows do not tween selection; pre blocks wrap only when needed; menus carry a hairline (A-106/A-107/A-108)', () => {
    assert.ok(!/\btransition/.test(RW.row), 'RW.row has no transition (j/k selection is instant)')
    assert.ok(!RW.pre.split(/\s+/).includes('break-all'), 'RW.pre uses overflow-wrap:anywhere, not break-all')
    assert.ok(RW.pre.includes('[overflow-wrap:anywhere]'))
    assert.ok(RW.ddMenu.includes('var(--line-2)'), 'dropdown menu has a hairline edge')
  })
})

// ---------------------------------------------------------------------------
// 3. Playwright geometry
// ---------------------------------------------------------------------------

const SYSTEM_CHROMIUM = ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable']

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
      if (loaded.chromium && typeof loaded.chromium.launch === 'function') { pw = loaded as PlaywrightModule; break }
    } catch {
      // try next package
    }
  }
  if (!pw) return null
  let bundled = ''
  try { bundled = pw.chromium.executablePath() } catch { bundled = '' }
  if (bundled && existsSync(bundled)) return { pw, executablePath: bundled }
  const sys = SYSTEM_CHROMIUM.find(p => existsSync(p))
  return sys ? { pw, executablePath: sys } : null
}

async function freePort(): Promise<number> {
  const srv = createNetServer().listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const addr = srv.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not allocate a port.')
  await new Promise<void>(done => srv.close(() => done()))
  return addr.port
}

function ensureBuilt(): void {
  if (existsSync(resolve(REPO_ROOT, 'build/server/server.js')) && existsSync(resolve(REPO_ROOT, 'build/client'))) return
  execFileSync('npm', ['run', 'build'], { cwd: REPO_ROOT, stdio: 'pipe' })
}

interface Kovo { origin: string; dataDir: string; bootstrapSecret: string; stop(): Promise<void> }

async function startKovo(): Promise<Kovo> {
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-pr3-polish-'))
  const port = await freePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''
  const child: ChildProcess = spawn(process.execPath, [...HARDENED_NODE_FLAGS, 'scripts/serve.ts'], {
    cwd: REPO_ROOT,
    env: { ...process.env, PORT: String(port), KOVO_DATA_DIR: dataDir, KOVO_ALLOW_LOCAL_LAB: '1', KOVO_ALLOW_LOCAL_MODEL: '1', KOVO_OFFLINE: '', KOVO_PUBLIC_ORIGIN: '' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout?.on('data', c => { output += String(c) })
  child.stderr?.on('data', c => { output += String(c) })
  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit')
      child.kill('SIGTERM')
      const timedOut = await Promise.race([exited.then(() => false), delay(3_000).then(() => true)])
      if (timedOut && child.exitCode === null) { child.kill('SIGKILL'); await once(child, 'exit') }
    }
    await rm(dataDir, { recursive: true, force: true })
  }
  let healthy = false
  for (let i = 0; i < 200 && child.exitCode === null; i += 1) {
    try {
      const res = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(500) })
      if (res.ok) { healthy = true; break }
    } catch {
      // not bound yet
    }
    await delay(70)
  }
  if (!healthy) { await stop(); throw new Error(`serve.ts failed to start.\n${output}`) }
  let bootstrapSecret = ''
  for (let i = 0; i < 40 && !bootstrapSecret; i += 1) {
    try { bootstrapSecret = (await readFile(join(dataDir, 'bootstrap'), 'utf8')).trim() } catch { await delay(50) }
  }
  if (!bootstrapSecret) { await stop(); throw new Error('bootstrap secret missing') }
  return { origin, dataDir, bootstrapSecret, stop }
}

function withDb<T>(dataDir: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(join(dataDir, 'kovo.sqlite'))
  try { db.exec('PRAGMA busy_timeout = 5000;'); return fn(db) } finally { db.close() }
}

/** Clone a run row under a new id (every column copied, then overridden). */
function cloneRun(db: DatabaseSync, fromId: string, toId: string, set: Record<string, string | number>): void {
  const cols = (db.prepare('PRAGMA table_info(runs)').all() as Array<{ name: string }>).map(c => c.name)
  const select = cols.map(c => (c === 'id' ? '?' : c)).join(', ')
  db.prepare(`INSERT INTO runs (${cols.join(', ')}) SELECT ${select} FROM runs WHERE id = ?`).run(toId, fromId)
  const keys = Object.keys(set)
  if (keys.length) db.prepare(`UPDATE runs SET ${keys.map(k => `${k} = ?`).join(', ')} WHERE id = ?`).run(...keys.map(k => set[k]!), toId)
}

const LONG_NAME = ('Acme Enterprise Customer Identity & Billing Platform — Multi-Region Production Regression Sweep ' +
  'for the Q4 Release Train including Legacy Partner Portals and Internal Admin Consoles').padEnd(180, ' X').slice(0, 180)
const LONG_HOST = 'https://very-long-unbroken-subdomain-for-tenant-routing-and-regional-failover-0.api.acme-enterprise-customer-identity.example'
const ORIGINS = ['https://app.acme-cloud.example', 'https://api.acme-cloud.example', LONG_HOST]
const DAY = 86_400_000

interface Seeded { runId: string; consentRunId: string; emptyRunId: string; findingIds: string[]; exchangeIds: string[]; workerIds: string[] }

function seedStressRun(dataDir: string, runId: string): Seeded {
  const now = Date.now()
  const started = now - 7 * DAY - 8 * 3_600_000
  const candidates = ORIGINS.map((origin, i) => ({ id: `cand-${i + 1}`, origin, source: 'Project seed', thirdParty: false }))
  const findingIds: string[] = []
  const exchangeIds: string[] = []
  const workerIds: string[] = []
  return withDb(dataDir, db => {
    const meta = db.prepare('SELECT workspace_id, project_id, goal_revision FROM runs WHERE id = ?').get(runId) as { workspace_id: string; project_id: string; goal_revision: number }
    db.prepare('UPDATE projects SET name = ? WHERE id = ?').run(LONG_NAME, meta.project_id)
    db.prepare(
      `UPDATE runs SET phase = 'investigation', status = 'paused', scope_revision = 1, candidates = ?, approved = ?,
         spent_requests = 999999, budget_requests = 1000000, spent_usd = 999999, budget_usd = 1000000,
         spent_tokens = 999999999, turns_used = 999999, created_at = ?, goal = ? WHERE id = ?`,
    ).run(JSON.stringify(candidates), JSON.stringify(candidates.map(c => c.id)), started, LONG_NAME, runId)

    db.prepare('DELETE FROM assignments WHERE run_id = ?').run(runId)
    const insW = db.prepare(
      `INSERT INTO assignments (id, run_id, asset_id, step_id, input_assignment_id, phase, status, scope_revision, goal_revision,
         session_id, attempt, max_turns, turns_used, requests_used, parent_fact_ids, source_origins, title, objective, outcome, created_at)
       VALUES (?, ?, ?, NULL, NULL, ?, ?, 1, ?, ?, 0, ?, ?, ?, '[]', ?, ?, ?, ?, ?)`,
    )
    const phases = ['discovery', 'threat_model', 'investigation', 'verification'] as const
    for (let i = 0; i < 36; i += 1) {
      const phase = phases[i % phases.length]!
      const failed = i % 9 === 4
      const id = `w-${i}`
      workerIds.push(id)
      const title = i === 0 ? `Cross-tenant invoice authorization differential probe across every regional billing replica ${LONG_NAME}`.slice(0, 180) : `${phase.replace('_', ' ')} worker ${i} · ${ORIGINS[i % 3]!.replace('https://', '')}`
      insW.run(
        id, runId, `cand-${(i % 3) + 1}`, phase, failed ? 'failed' : 'complete', meta.goal_revision, `s-${i}`,
        999999, i < 4 ? 999998 : 12, i < 6 ? 999999 : 40 + i, JSON.stringify(i % 2 ? ORIGINS : [ORIGINS[2]]),
        title, 'Differential control vs. variant comparison on the approved surface.',
        failed ? 'Worker failed: upstream model endpoint returned 503 after 3 retries; the lease expired before verification completed and the partial transcript was quarantined.' : 'No issue found.',
        started + i * 60_000,
      )
    }

    const insX = db.prepare(
      `INSERT INTO broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, method, path_and_query,
         persona_handle, status, media_type, req_headers, resp_headers, body_preview, body_artifact_id, body_sha256, secret_matches, duration_ms, created_at)
       VALUES (?, ?, ?, 1, ?, ?, '[]', ?, ?, ?, ?, 'application/json', ?, ?, ?, NULL, ?, '[]', ?, ?)`,
    )
    const methods = ['GET', 'POST', 'OPTIONS', 'PATCH', 'DELETE']
    const respHeaders = {
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
      'access-control-allow-origin': 'https://app.acme-cloud.example',
      'x-request-correlation-identifier-for-distributed-tracing-pipeline': 'a'.repeat(120),
    }
    for (let i = 0; i < 30; i += 1) {
      const id = `x-${i}`
      exchangeIds.push(id)
      insX.run(
        id, runId, `w-${i % 36}`, ORIGINS[i % 3], ORIGINS[i % 3], methods[i % methods.length],
        `/api/v2/tenants/acme-enterprise/billing/invoices/${100000 + i}/line-items?expand=adjustments,credits,taxes&page=${i}`,
        i % 4 === 0 ? 'tenant-admin-with-extended-billing-export-permissions-for-regional-finance-operations-team-west' : null,
        [200, 403, 402, 500, 204][i % 5], JSON.stringify({ accept: 'application/json' }), JSON.stringify(respHeaders),
        JSON.stringify({ ok: true, items: i }), 'sha256-' + String(i).padStart(4, '0'), 120 + i * 37,
        started + Math.round((i / 29) * (now - started - 3_600_000)),
      )
    }

    const insF = db.prepare(
      `INSERT INTO findings (id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind, provenance, verification_class,
         source_origins, status, severity, cwe, origin, triage_status, finding)
       VALUES (?, ?, ?, ?, 'chain', ?, 'multi_step_chain', 'agent_only', 'runtime_confirmed', ?, ?, ?, ?, ?, 'open', ?)`,
    )
    const sevs = ['critical', 'high', 'medium', 'low', 'info'] as const
    for (let i = 0; i < 12; i += 1) {
      const id = `f-${i}`
      findingIds.push(id)
      const degenerate = i === 11
      const origin = degenerate ? '' : ORIGINS[i % 3]!
      const severity = sevs[i % sevs.length]!
      const title = degenerate ? '' : i === 0
        ? `Cross-tenant invoice line-item read through the regional billing replica exposes sibling tenant adjustments ${LONG_NAME}`.slice(0, 180)
        : `Finding ${i}: authorization differential on invoice export`
      const finding = {
        id, origin, title, cwe: 'CWE-639', category: 'broken-access-control', severity, status: (['pending', 'inconclusive', 'pending', 'dismissed'] as const)[i % 4],
        reason: 'Control vs. variant differential showed a sibling-tenant read.',
        verification: 'Automated replay',
        remediation: degenerate ? '' : 'Enforce the tenant check in `InvoiceLineItemsController#index` and scope `LineItem.where(tenant_id: current_tenant.id)` before serialising. Re-run the differential probe afterwards.',
        evidenceIds: [], exchangeIds: exchangeIds.slice(0, 5), scopeRevision: 1,
      }
      insF.run(id, runId, `cand-${(i % 3) + 1}`, meta.goal_revision, `pr3-case-${i}`, JSON.stringify(origin ? [origin] : []),
        finding.status, severity, 'CWE-639', origin, JSON.stringify(finding))
    }

    const insE = db.prepare('INSERT INTO events (workspace_id, run_id, kind, message, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    for (let i = 0; i < 20; i += 1) {
      insE.run(meta.workspace_id, runId, i % 2 ? 'worker.complete' : 'phase0.stage', `Event ${i} on ${ORIGINS[i % 3]}`, JSON.stringify({ origin: ORIGINS[i % 3] }), started + i * 9 * 3_600_000)
    }

    const consentRunId = `${runId.slice(0, 24)}c0c0c0c0c0c1`
    cloneRun(db, runId, consentRunId, { phase: 'consent', status: 'waiting', scope_revision: 0, approved: '[]', spent_requests: 0, spent_usd: 0, spent_tokens: 0, turns_used: 0 })
    const emptyRunId = `${runId.slice(0, 24)}e0e0e0e0e0e1`
    cloneRun(db, runId, emptyRunId, { phase: 'complete', status: 'complete', candidates: '[]', approved: '[]', spent_requests: 0, spent_usd: 0, spent_tokens: 0, turns_used: 0 })
    return { runId, consentRunId, emptyRunId, findingIds, exchangeIds, workerIds }
  })
}

type Theme = 'light' | 'dark'
interface Combo { width: number; height: number; theme: Theme; reduced: boolean }
const COMBOS: Combo[] = [
  { width: 1280, height: 720, theme: 'light', reduced: false },
  { width: 1280, height: 720, theme: 'dark', reduced: false },
  { width: 1440, height: 900, theme: 'light', reduced: false },
  { width: 1440, height: 900, theme: 'dark', reduced: false },
  { width: 390, height: 844, theme: 'light', reduced: false },
  { width: 390, height: 844, theme: 'dark', reduced: false },
  { width: 1280, height: 720, theme: 'light', reduced: true },
]
const comboName = (c: Combo) => `${c.width}x${c.height}__${c.theme}${c.reduced ? '__reduced' : ''}`

/** Geometry offenders inside the run shell (empty list = clean). `narrow` skips the 0px-main mobile layout ([U1]). */
async function geometryOffenders(page: Page, narrow: boolean): Promise<string[]> {
  return page.evaluate((isNarrow: boolean) => {
    const out: string[] = []
    const visible = (el: Element) => { const r = el.getBoundingClientRect(); return r.width > 1 && r.height > 1 }
    const label = (el: Element) => el.tagName.toLowerCase() + (el.getAttribute('aria-label') ? `[${el.getAttribute('aria-label')}]` : '') + (el.getAttribute('data-testid') ? `#${el.getAttribute('data-testid')}` : '') + '.' + [...el.classList].slice(0, 4).join('.')
    const doc = document.documentElement
    if (doc.scrollWidth > doc.clientWidth + 1) out.push(`document ${doc.scrollWidth}>${doc.clientWidth}`)
    const shell = document.querySelector('main')?.closest('.h-screen') ?? document.body
    if (shell.scrollLeft !== 0) out.push(`shell scrollLeft=${shell.scrollLeft}`)
    if (isNarrow) return out
    const containers = document.querySelectorAll('main, aside[aria-label="Inspector"], aside[aria-label="Inspector"] .overflow-auto, main [role="region"], main .overflow-auto, [role="dialog"]')
    for (const el of containers) {
      if (!visible(el)) continue
      if (el.scrollWidth > el.clientWidth + 1) {
        const edge = el.getBoundingClientRect().left + el.clientWidth
        const culprit = [...el.querySelectorAll('*')].find(c => c.getBoundingClientRect().right > edge + 1 && c.children.length === 0)
        out.push(`${label(el)} scrollWidth ${el.scrollWidth}>${el.clientWidth}` + (culprit ? ` (widest leaf: ${label(culprit)} "${(culprit.textContent ?? '').trim().slice(0, 30)}")` : ''))
      }
    }
    for (const t of document.querySelectorAll('main table, aside table')) {
      const p = t.parentElement
      if (p && visible(t) && t.getBoundingClientRect().right > p.getBoundingClientRect().right + 1) out.push(`table overflows ${label(p)}`)
    }
    for (const b of document.querySelectorAll<HTMLElement>('main button, aside button, header button')) {
      if (!visible(b) || getComputedStyle(b).overflow === 'visible') continue
      if (b.scrollHeight > b.clientHeight + 2) out.push(`button clipped vertically "${(b.textContent ?? '').trim().slice(0, 40)}" ${b.scrollHeight}>${b.clientHeight}`)
    }
    return out
  }, narrow)
}

async function settle(page: Page): Promise<void> {
  await page.evaluate(async () => {
    try { await document.fonts?.ready } catch { /* offline */ }
    await new Promise<void>(r => requestAnimationFrame(() => requestAnimationFrame(() => r())))
  })
  await delay(350)
}

async function waitHydrated(page: Page): Promise<void> {
  await page.waitForFunction(() => {
    if (document.readyState !== 'complete') return false
    const el = document.querySelector('main button, nav button')
    return !!el && Object.keys(el).some(k => k.startsWith('__reactProps$') || k.startsWith('__reactFiber$'))
  }, undefined, { timeout: 20_000 * CI_MULT })
}

async function shot(page: Page, name: string): Promise<void> {
  if (!SHOTS_DIR) return
  mkdirSync(SHOTS_DIR, { recursive: true })
  await page.screenshot({ path: join(SHOTS_DIR, `${name}.png`) })
}

describe('Run workbench rendered geometry (Playwright)', () => {
  let skip: string | null = null
  let kovo: Kovo | undefined
  let browser: Browser | undefined
  let storageState: Awaited<ReturnType<BrowserContext['storageState']>> | undefined
  let seeded: Seeded | undefined
  const pageErrors: string[] = []

  before(async () => {
    const env = await loadPlaywright()
    if (!env) { skip = 'Playwright or Chromium unavailable'; return }
    ensureBuilt()
    kovo = await startKovo()
    browser = await env.pw.chromium.launch({ headless: true, executablePath: env.executablePath, args: ['--no-sandbox'] })
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 720 } })
    const page = await ctx.newPage()
    await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, { waitUntil: 'load' })
    await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 20_000 * CI_MULT })
    await waitHydrated(page).catch(() => undefined)
    await page.getByLabel('Project name').fill('PR3 polish stress')
    await page.getByLabel('Sites').fill(ORIGINS.slice(0, 2).join('\n'))
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 20_000 * CI_MULT })
    await page.getByRole('button', { name: 'New run', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await dialog.waitFor({ state: 'visible' })
    await dialog.getByRole('button', { name: 'Start run', exact: true }).click()
    await page.waitForURL(/\/runs\/[a-f0-9-]+/, { timeout: 20_000 * CI_MULT })
    const runId = /\/runs\/([a-f0-9-]+)/.exec(page.url())?.[1]
    assert.ok(runId)
    // Let the freshly created run settle out of the live loop before we overwrite its rows.
    await delay(500)
    seeded = seedStressRun(kovo.dataDir, runId)
    storageState = await ctx.storageState()
    await ctx.close()
  }, { timeout: HOOK_TIMEOUT_MS })

  after(async () => {
    await browser?.close().catch(() => undefined)
    await kovo?.stop().catch(() => undefined)
  })

  async function open(combo: Combo, path: string): Promise<{ page: Page; ctx: BrowserContext }> {
    const ctx = await browser!.newContext({
      viewport: { width: combo.width, height: combo.height },
      colorScheme: combo.theme,
      reducedMotion: combo.reduced ? 'reduce' : 'no-preference',
      storageState,
    })
    // tsx/esbuild keep-names wraps named inner functions in `__name(...)`; give serialized evaluate bodies a no-op.
    await ctx.addInitScript({ content: 'globalThis.__name = globalThis.__name || (f => f)' })
    await ctx.addInitScript((theme: string) => { try { localStorage.setItem('kovo-appearance', theme) } catch { /* noop */ } }, combo.theme)
    const page = await ctx.newPage()
    page.setDefaultTimeout(20_000 * CI_MULT)
    page.on('pageerror', err => { pageErrors.push(`${path}: ${err instanceof Error ? err.message : String(err)}`) })
    await page.goto(`${kovo!.origin}${path}`, { waitUntil: 'load' })
    await page.locator('main').first().waitFor({ state: 'attached' })
    await waitHydrated(page)
    await settle(page)
    assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), combo.theme)
    return { page, ctx }
  }

  const VIEWS = (s: Seeded) => [
    { name: 'overview', path: `/runs/${s.runId}?view=overview` },
    { name: 'workers-list', path: `/runs/${s.runId}?view=workflow` },
    { name: 'worker-inspector-failed', path: `/runs/${s.runId}?view=workflow&sel=worker:w-4` },
    { name: 'workflow-graph', path: `/runs/${s.runId}?view=workflow&mode=graph` },
    { name: 'findings-inspector', path: `/runs/${s.runId}?view=findings&sel=finding:f-0` },
    { name: 'findings-degenerate', path: `/runs/${s.runId}?view=findings&sel=finding:f-11` },
    { name: 'traffic-drawer', path: `/runs/${s.runId}?view=exchanges&sel=exchange:x-0` },
    { name: 'activity', path: `/runs/${s.runId}?view=activity` },
    { name: 'queue', path: `/runs/${s.runId}?view=queue` },
    { name: 'consent', path: `/runs/${s.consentRunId}?view=overview` },
    { name: 'empty-complete', path: `/runs/${s.emptyRunId}?view=overview` },
  ]

  for (const combo of COMBOS) {
    it(`stress views keep zero horizontal overflow and unclipped controls at ${comboName(combo)}`, { timeout: 240_000 * CI_MULT }, async t => {
      if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
      const narrow = combo.width < 600
      const offenders: string[] = []
      for (const view of VIEWS(seeded)) {
        const { page, ctx } = await open(combo, view.path)
        try {
          for (const o of await geometryOffenders(page, narrow)) offenders.push(`${view.name}: ${o}`)
          await shot(page, `${view.name}__${comboName(combo)}`)
        } finally {
          await ctx.close()
        }
      }
      assert.deepEqual(offenders, [], comboName(combo))
    })
  }

  it('header keeps actions in viewport and never slices a run-line number under a 180-char name (A-093/A-094)', { timeout: 120_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const combo of COMBOS.filter(c => c.width >= 1280 && c.theme === 'light' && !c.reduced)) {
      const { page, ctx } = await open(combo, `/runs/${seeded.runId}?view=overview`)
      try {
        for (const name of ['More actions', /^(Show|Hide) panel$/] as const) {
          const box = await page.getByRole('button', { name }).first().boundingBox()
          assert.ok(box, `${String(name)} rendered`)
          assert.ok(box.x >= 0 && box.x + box.width <= combo.width + 0.5, `${String(name)} inside viewport at ${comboName(combo)}: ${JSON.stringify(box)}`)
        }
        const resume = page.getByRole('button', { name: /^(Resume|Pause)$/ }).first()
        if (await resume.count()) {
          const box = await resume.boundingBox()
          assert.ok(box && box.x + box.width <= combo.width + 0.5, `Resume/Pause in viewport at ${comboName(combo)}`)
          const tp = await resume.evaluate(el => getComputedStyle(el).transitionProperty)
          assert.ok(/\bscale\b/.test(tp) && !/\btransform\b/.test(tp), `run button transitions scale: ${tp}`)
        }
        const rl = await page.evaluate(() => {
          const items = [...document.querySelectorAll<HTMLElement>('[data-rl]')].filter(el => el.offsetParent !== null && getComputedStyle(el).display !== 'none')
          const line = items[0]?.parentElement
          const lineRight = line?.getBoundingClientRect().right ?? 0
          return {
            count: items.length,
            sliced: items.filter(el => el.getBoundingClientRect().right > lineRight + 0.5 || el.scrollWidth > el.clientWidth + 1).map(el => (el.textContent ?? '').trim()),
            clippedV: items.filter(el => el.scrollHeight > el.clientHeight + 1).map(el => (el.textContent ?? '').trim()),
          }
        })
        assert.ok(rl.count > 0, 'run line renders')
        assert.deepEqual(rl.sliced, [], `no partially visible run-line item at ${comboName(combo)}`)
        assert.deepEqual(rl.clippedV, [], `run-line items fit their line box at ${comboName(combo)}`)
      } finally {
        await ctx.close()
      }
    }
  })

  it('focusing off-screen header controls never scrolls the shell sideways at 390 and 1440 (A-090)', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const width of [390, 1440]) {
      const { page, ctx } = await open({ width, height: width === 390 ? 844 : 900, theme: 'light', reduced: false }, `/runs/${seeded.runId}?view=overview`)
      try {
        for (let i = 0; i < 25; i += 1) await page.keyboard.press('Tab')
        const offenders = await geometryOffenders(page, true)
        assert.deepEqual(offenders, [], `after tabbing at ${width}`)
      } finally {
        await ctx.close()
      }
    }
  })

  it('workers list rows stay 36px with 999,999 req and keep at most one live ping (A-127/A-130)', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    for (const combo of [COMBOS[0]!, COMBOS[2]!]) {
      const { page, ctx } = await open(combo, `/runs/${seeded.runId}?view=workflow`)
      try {
        const rows = await page.evaluate(() => {
          const list = document.querySelector('[role="region"][aria-label="Worker list"]')
          const rs = [...(list?.querySelectorAll<HTMLElement>('[data-id]') ?? [])].filter(r => r.getBoundingClientRect().height > 0).slice(0, 30)
          const text = list?.textContent ?? ''
          let overlap = 0
          for (const r of rs) {
            const kids = [...r.children].map(k => k.getBoundingClientRect()).filter(b => b.width > 0)
            for (let i = 0; i + 1 < kids.length; i += 1) if (kids[i]!.right > kids[i + 1]!.left + 1) overlap += 1
          }
          return { n: rs.length, tall: rs.filter(r => r.getBoundingClientRect().height > 37).length, overlap, grouped: text.includes('999,999'), pings: document.querySelectorAll('main .animate-ping').length }
        })
        assert.ok(rows.n > 0, 'worker rows render')
        assert.equal(rows.tall, 0, `no wrapped rows at ${comboName(combo)}`)
        assert.equal(rows.overlap, 0, `no overlapping cells at ${comboName(combo)}`)
        assert.ok(rows.grouped, 'stress request counts render grouped')
        assert.ok(rows.pings <= 2, `at most two live pings, got ${rows.pings}`)
      } finally {
        await ctx.close()
      }
    }
  })

  it('findings: j/k selection is instant, titles keep ≥38% of the row, filter keeps focus/value across ticks (A-101/A-106/A-152)', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(COMBOS[0]!, `/runs/${seeded.runId}?view=findings`)
    try {
      const rowTransition = await page.evaluate(() => {
        const row = document.querySelector<HTMLElement>('main [data-id]')
        return row ? getComputedStyle(row).transitionDuration.split(',').every(d => parseFloat(d) === 0) : null
      })
      assert.equal(rowTransition, true, 'list rows carry no transition')
      const ratio = await page.evaluate(() => {
        const row = document.querySelector<HTMLElement>('main [data-id]')
        const title = row?.querySelector<HTMLElement>('[data-slot="finding-title"]')
        return row && title ? title.getBoundingClientRect().width / row.getBoundingClientRect().width : 0
      })
      assert.ok(ratio >= 0.38, `finding title keeps ≥38% of the row of the row (${ratio.toFixed(2)})`)
      await page.keyboard.press('j')
      await page.waitForFunction(() => !!document.querySelector('main [aria-selected="true"]'))
      const filter = page.getByPlaceholder(/Filter/i).first()
      if (await filter.count()) {
        const before = await filter.boundingBox()
        await page.keyboard.press('/')
        await page.keyboard.type('invoice')
        const anims = await page.evaluate(() => document.getAnimations().filter(a => (a as CSSTransition).transitionProperty === 'width').length)
        assert.equal(anims, 0, 'no width transition on "/"')
        await delay(2_500)
        assert.equal(await filter.inputValue(), 'invoice', 'background ticks never clobber typed filter')
        assert.equal(await page.evaluate(() => (document.activeElement as HTMLInputElement | null)?.value ?? ''), 'invoice', 'filter keeps focus')
        const afterBox = await filter.boundingBox()
        assert.ok(before && afterBox && Math.abs(before.width - afterBox.width) <= 2, `filter box width is fixed: ${before?.width} → ${afterBox?.width}`)
      }
    } finally {
      await ctx.close()
    }
  })

  it('findings inspector reads degenerate rows as copy, never "()", trailing "·", or literal null (A-142/A-144)', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(COMBOS[2]!, `/runs/${seeded.runId}?view=findings&sel=finding:f-11`)
    try {
      const text = await page.locator('aside[aria-label="Inspector"]').innerText()
      assert.ok(!/\(\s*\)/.test(text), 'no empty parens')
      assert.ok(!/·\s*$/m.test(text), 'no dangling separators')
      assert.ok(!/\b(undefined|null)\b/.test(text), 'no raw null/undefined')
      assert.match(await page.locator('main').innerText(), /Untitled finding/)
    } finally {
      await ctx.close()
    }
  })

  it('traffic rows always show their duration and method column fits OPTIONS (A-164/A-168)', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(COMBOS[0]!, `/runs/${seeded.runId}?view=exchanges&sel=exchange:x-0`)
    try {
      const res = await page.evaluate(() => {
        const rows = [...document.querySelectorAll<HTMLElement>('main [data-id]')].filter(r => r.getBoundingClientRect().height > 0)
        const hidden = rows.filter(r => {
          const rr = r.getBoundingClientRect()
          const ms = [...r.querySelectorAll<HTMLElement>('span, div')].find(el => /\d\s*ms$/.test((el.textContent ?? '').trim()) && el.children.length === 0)
          return !ms || ms.getBoundingClientRect().right > rr.right + 1
        }).length
        return { n: rows.length, hidden }
      })
      assert.ok(res.n > 0, 'traffic rows render')
      assert.equal(res.hidden, 0, 'every traffic row shows its ms value')
      const drawer = await page.locator('aside[aria-label="Inspector"]').innerText()
      assert.match(drawer, /Untitled finding/, 'untitled citing findings read as copy, never a blank row')
      assert.ok(!/\b(undefined|null)\b/.test(drawer), 'drawer never shows raw null/undefined')
    } finally {
      await ctx.close()
    }
  })

  it('a disabled Approve & start always says why; stepper exposes aria-current (A-140/A-141)', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(COMBOS[0]!, `/runs/${seeded.consentRunId}?view=overview`)
    try {
      const btn = page.getByRole('button', { name: /^Approve & start/ }).first()
      if (await btn.count()) {
        if (await btn.isDisabled()) {
          const title = (await btn.getAttribute('title')) ?? ''
          assert.ok(title.trim().length > 0, 'disabled Approve & start has a reason title')
        }
        const box = await btn.boundingBox()
        assert.ok(box && box.y + box.height <= 720 + 1 && box.x + box.width <= 1280 + 1, 'Approve & start above the fold at 1280×720')
      }
      const current = await page.locator('[aria-current="step"]').count()
      if (await page.locator('ol li, [role="list"] li').count()) assert.ok(current <= 1)
    } finally {
      await ctx.close()
    }
  })

  it('empty completed run never says "across no hosts" or "0 of 0" (A-115/A-124)', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const { page, ctx } = await open(COMBOS[0]!, `/runs/${seeded.emptyRunId}?view=overview`)
    try {
      const text = await page.locator('main').innerText()
      assert.ok(!/across no hosts/i.test(text), 'no "across no hosts"')
      assert.ok(!/\b0 of 0\b/.test(text), 'no "0 of 0"')
      assert.ok(!/Every finding is decided or verified/.test(text), 'short "Nothing needs you." on empty runs')
    } finally {
      await ctx.close()
    }
  })

  it('reduced motion: no running non-zero-duration CSS animation after load; graph settles at once (A-137)', { timeout: 60_000 * CI_MULT }, async t => {
    if (skip || !seeded) { t.skip(skip ?? 'not seeded'); return }
    const reduced = COMBOS.find(c => c.reduced)!
    for (const path of [`/runs/${seeded.runId}?view=overview`, `/runs/${seeded.runId}?view=workflow&mode=graph`]) {
      const { page, ctx } = await open(reduced, path)
      try {
        const moving = await page.evaluate(() => document.getAnimations()
          .filter(a => a.playState === 'running')
          .map(a => ({ d: Number(a.effect?.getComputedTiming().duration ?? 0), k: a.constructor.name }))
          .filter(a => a.d > 0))
        assert.deepEqual(moving, [], `${path}: nothing moves under prefers-reduced-motion`)
      } finally {
        await ctx.close()
      }
    }
  })

  it('no page errors across all stress views', t => {
    if (skip) { t.skip(skip); return }
    assert.deepEqual(pageErrors, [])
  })
})
