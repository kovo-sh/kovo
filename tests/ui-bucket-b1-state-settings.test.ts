// Desktop Bucket B — PR B1: unified StatePanel, malformed-SSE / malformed-row quarantine,
// model pool failover order + presets, draft-safe settings forms.
//
// Part 1 is hermetic and fast (<5s): shared preset contract (UI ↔ CLI parity through a real
// configureModelPool run), the reorder server primitive against a temp Store, the run data
// boundary fed malformed frames/rows, and the useServerDraft reconciliation contract.
//
// Part 2 boots the built app on an isolated KOVO_DATA_DIR and drives headless Chromium:
// every assertion is a DOM geometry, computed-style or interaction check — never source text.
//
// Set KOVO_UI_SHOTS_DIR=<dir> to also write the visual-QA screenshots.
import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser, BrowserContext, Locator, Page } from '@playwright/test'
import { and, eq } from 'drizzle-orm'
import { configureModelPool, POOL_TIER_PRESETS } from '../scripts/configure-model-pool.ts'
import { setModelProfilePrioritiesInStore } from '../src/actions.ts'
import {
  EMPTY_QUARANTINE,
  hydrateHistoricalEvents,
  MAX_QUARANTINE_SAMPLES,
  parseRunEventFrame,
  parseSseEventsChunk,
  quarantineDiagnostics,
  quarantineHeadline,
  quarantineRunDetail,
  quarantineRunEvents,
  recordRowQuarantine,
  recordStreamQuarantine,
} from '../src/components/run/data.tsx'
import { buildRunModel, normalizeRunDetail } from '../src/components/run/model.ts'
import type { Detail } from '../src/components/run/model.ts'
import {
  editServerDraft,
  initialServerDraft,
  reconcileServerDraft,
  serverDraftFlags,
} from '../src/components/settings/useServerDraft.ts'
import { describeStateError, stateErrorDetails } from '../src/components/ui/state-panel.tsx'
import { DEFAULT_PROVIDER } from '../src/domain.ts'
import {
  failoverPriorities,
  failoverRoleLabel,
  MODEL_POOL_PRESETS,
  modelPoolPreset,
  presetProfileFields,
} from '../src/model-pool-presets.ts'
import { listModelProfiles, saveModelProfile } from '../src/server/model-settings.ts'
import { modelProfiles } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { HARDENED_NODE_FLAGS } from './app.ts'

// ===========================================================================
// Part 1 — hermetic behavioural contracts
// ===========================================================================

const ORDER_DEPS = { modelProfiles, and, eq }

function writeKeyFile(dir: string, name: string, key: string): string {
  const path = join(dir, name)
  writeFileSync(path, `${key}\n`, { mode: 0o600 })
  return path
}

describe('B1 shared model pool presets (UI ↔ CLI single source of truth)', () => {
  it('presets are unique, ranked Primary → Fallback in descending priority, and keyless', () => {
    const ids = MODEL_POOL_PRESETS.map(p => p.id)
    assert.equal(new Set(ids).size, ids.length, 'preset ids are unique')
    assert.deepEqual(MODEL_POOL_PRESETS.map(p => p.tier), ['Primary', 'Fallback 1', 'Fallback 2'])
    const priorities = MODEL_POOL_PRESETS.map(p => p.priority)
    assert.deepEqual([...priorities].sort((a, b) => b - a), priorities, 'highest priority (tried first) leads')
    for (const preset of MODEL_POOL_PRESETS) {
      assert.match(preset.endpoint, /^https:\/\//, `${preset.id}: HTTPS endpoint`)
      assert.ok(preset.contextWindow >= 32_000 && preset.maxTokens >= 512, `${preset.id}: limits inside the schema`)
      const fields = presetProfileFields(preset)
      assert.equal('key' in fields, false, `${preset.id}: a preset never carries a key`)
      assert.equal(fields.priority, preset.priority)
      assert.equal(fields.protocol, preset.protocol)
    }
    const openrouter = modelPoolPreset('openrouter')
    assert.equal(openrouter.endpoint, DEFAULT_PROVIDER.endpoint)
    assert.equal(openrouter.model, DEFAULT_PROVIDER.model)
    assert.equal(openrouter.protocol, DEFAULT_PROVIDER.protocol)
    assert.throws(() => modelPoolPreset('nope' as never), /Unknown model pool preset/)
  })

  it('CLI tiers are the shared presets, and a real configureModelPool run writes exactly those values', async () => {
    assert.deepEqual(POOL_TIER_PRESETS.map(t => t.idKey), ['morph', 'opencode'])
    for (const tier of POOL_TIER_PRESETS) {
      const preset = modelPoolPreset(tier.idKey)
      assert.deepEqual(
        { name: tier.name, endpoint: tier.endpoint, model: tier.model, protocol: tier.protocol, priority: tier.priority, contextWindow: tier.contextWindow },
        { name: preset.name, endpoint: preset.endpoint, model: preset.model, protocol: preset.protocol, priority: preset.priority, contextWindow: preset.contextWindow },
      )
    }
    const dataDir = mkdtempSync(join(tmpdir(), 'kovo-b1-pool-'))
    try {
      const keys = mkdtempSync(join(tmpdir(), 'kovo-b1-keys-'))
      const result = await configureModelPool({
        dataDir,
        morphKeyFile: writeKeyFile(keys, 'morph.key', 'morph-test-key-0001'),
        opencodeKeyFile: writeKeyFile(keys, 'opencode.key', 'opencode-test-key-0002'),
      })
      rmSync(keys, { recursive: true, force: true })
      assert.deepEqual(result.upserted.map(u => u.action), ['created', 'created'])
      for (const preset of [modelPoolPreset('morph'), modelPoolPreset('opencode')]) {
        const saved = result.profiles.find(p => p.name === preset.name)
        assert.ok(saved, `${preset.id} profile saved`)
        assert.deepEqual(
          { endpoint: saved.endpoint, model: saved.model, protocol: saved.protocol, priority: saved.priority, contextWindow: saved.contextWindow, thinkingLevel: saved.thinkingLevel },
          { endpoint: preset.endpoint, model: preset.model, protocol: preset.protocol, priority: preset.priority, contextWindow: preset.contextWindow, thinkingLevel: preset.thinkingLevel },
        )
      }
    } finally {
      rmSync(dataDir, { recursive: true, force: true })
    }
  })

  it('failover ranks: rank 1 = Primary, priorities persist in steps of 10 (descending), stale orders are refused', async () => {
    assert.deepEqual(failoverPriorities(3), [30, 20, 10])
    assert.deepEqual([1, 2, 3, 4].map(failoverRoleLabel), ['Primary', 'Fallback 1', 'Fallback 2', 'Fallback 3'])

    const dataDir = mkdtempSync(join(tmpdir(), 'kovo-b1-reorder-'))
    const storage = new Store(dataDir, { autoRecover: false })
    try {
      for (const [name, priority] of [['Alpha', 300], ['Bravo', 200], ['Charlie', 100]] as const) {
        await saveModelProfile({ name, endpoint: 'https://example.test/v1', model: `vendor/${name.toLowerCase()}`, protocol: 'responses', key: `sk-test-${name}-0001`, priority }, storage, { skipConnectionCheck: true })
      }
      const before = listModelProfiles(storage)
      assert.deepEqual(before.map(p => p.name), ['Alpha', 'Bravo', 'Charlie'])
      const reordered = [before[1]!.id, before[2]!.id, before[0]!.id]
      const result = setModelProfilePrioritiesInStore(reordered, storage, ORDER_DEPS)
      assert.deepEqual(result.priorities.map(p => p.priority), [30, 20, 10])
      const after = listModelProfiles(storage)
      assert.deepEqual(after.map(p => [p.name, p.priority]), [['Bravo', 30], ['Charlie', 20], ['Alpha', 10]])
      assert.throws(() => setModelProfilePrioritiesInStore(reordered.slice(0, 2), storage, ORDER_DEPS), /model pool changed/)
      assert.throws(() => setModelProfilePrioritiesInStore([...reordered.slice(0, 2), randomUUID()], storage, ORDER_DEPS), /model pool changed/)
      assert.deepEqual(listModelProfiles(storage).map(p => p.priority), [30, 20, 10], 'refused orders write nothing')
    } finally {
      storage.close()
      rmSync(dataDir, { recursive: true, force: true })
    }
  })
})

function minimalDetail(overrides: Record<string, unknown> = {}): Detail {
  return {
    run: { id: 'run-b1', projectId: 'proj-b1', status: 'running', phase: 'investigation', approved: [], candidates: [] },
    project: { id: 'proj-b1', name: 'B1 project', seeds: [] },
    cursor: 10,
    assignments: [],
    findings: [],
    exchangesSummary: [],
    approvals: [],
    evidence: [],
    facts: [],
    chainSteps: [],
    ...overrides,
  } as unknown as Detail
}

describe('B1 run data boundary: malformed SSE frames and rows are quarantined, never thrown', () => {
  it('SSE chunks: valid events pass, bad JSON / shapeless events are quarantined with exact counts', () => {
    const chunk = [
      'id: 11\ndata: {"id":11,"runId":"run-b1","kind":"note","message":"ok","detail":{},"createdAt":1}\n\n',
      'id: 12\ndata: {"id":12,"kind":\n\n',
      'id: 13\ndata: {"id":13,"message":"no kind"}\n\n',
      'id: 14\ndata: [1,2,3]\n\n',
      ': keepalive\n\n',
      'id: 15\ndata: {"id":15,"kind":"note","detail":"not-an-object"}\n\n',
      'id: 16\ndata: {"id":16,"kind":"partial',
    ].join('')
    const parsed = parseSseEventsChunk('', chunk)
    assert.deepEqual(parsed.events.map(e => e.id), [11, 15])
    assert.deepEqual(parsed.events[1]!.detail, {}, 'non-object detail coerced, not thrown')
    assert.deepEqual(parsed.quarantined.map(q => [q.kind, q.eventId]), [['sse-frame', 12], ['event', 13], ['event', 14]])
    assert.ok(parsed.carry.startsWith('id: 16'), 'partial frame carried, not quarantined')

    let state = recordStreamQuarantine(EMPTY_QUARANTINE, parsed.quarantined)
    // The same frames re-delivered (EventSource reconnect / history backfill) are never double counted.
    state = recordStreamQuarantine(state, parseSseEventsChunk('', chunk).quarantined)
    assert.equal(state.total, 3)
    assert.deepEqual(state.byKind, { 'sse-frame': 1, event: 2 })
    assert.equal(quarantineHeadline(state), '3 malformed stream events quarantined')

    const frame = parseRunEventFrame('{oops', 99)
    assert.ok('quarantined' in frame && frame.quarantined.kind === 'sse-frame' && frame.quarantined.size === 5)
  })

  it('snapshot rows: malformed worker/finding/exchange rows are set aside and the model still builds', () => {
    const detail = minimalDetail({
      assignments: [{ id: 'w1', title: 'Recon', status: 'running', phase: 'discovery' }, null, { title: 'no id' }, { id: 7 }],
      findings: [{ id: 'f1', title: 'Finding', origin: 'https://a.test', category: 'xss' }, 'junk'],
      exchangesSummary: { not: 'a list' },
    })
    const boundary = quarantineRunDetail(detail)
    assert.deepEqual(boundary.quarantined.map(q => [q.kind, q.index ?? null]), [
      ['worker', 1], ['worker', 2], ['worker', 3], ['finding', 1], ['exchange', null],
    ])
    const normalized = normalizeRunDetail(boundary.detail)
    assert.deepEqual(normalized.assignments.map(a => a.id), ['w1'])
    assert.deepEqual(normalized.findings.map(f => f.id), ['f1'])
    const model = buildRunModel(normalized, Date.now())
    assert.ok(model.workerById.has('w1'))

    const rows = recordRowQuarantine(EMPTY_QUARANTINE, boundary.quarantined)
    assert.equal(rows.total, 5)
    assert.equal(quarantineHeadline(rows), '5 malformed records quarantined')
    // Refreshing with the same malformed snapshot replaces (never accumulates) the row counts.
    assert.equal(recordRowQuarantine(rows, quarantineRunDetail(detail).quarantined).total, 5)
    const oneWorker = recordRowQuarantine(EMPTY_QUARANTINE, quarantineRunDetail(minimalDetail({ assignments: [{ title: 'x' }] })).quarantined)
    assert.equal(quarantineHeadline(oneWorker), '1 worker row could not be displayed')
    assert.equal(recordRowQuarantine(oneWorker, []).total, 0, 'a clean refresh clears row quarantine')

    const clean = minimalDetail({ assignments: [{ id: 'w1' }] })
    assert.equal(quarantineRunDetail(clean).detail, clean, 'a clean snapshot passes through untouched')
  })

  it('diagnostics are structural only and samples stay bounded; 20k-row refresh stays fast', () => {
    const secret = 'raw-payload-marker-should-never-be-copied'
    const frames = Array.from({ length: 50 }, (_, i) => `id: ${100 + i}\ndata: {"broken":"${secret}"\n\n`).join('')
    const state = recordStreamQuarantine(EMPTY_QUARANTINE, parseSseEventsChunk('', frames).quarantined)
    assert.equal(state.total, 50)
    assert.equal(state.samples.length, MAX_QUARANTINE_SAMPLES)
    const text = quarantineDiagnostics(state, 'run-b1')
    assert.match(text, /quarantined: 50 \(stream 50, rows 0\)/)
    assert.match(text, /event #149/)
    assert.equal(text.includes(secret), false, 'raw payloads never reach diagnostics')

    const big = Array.from({ length: 20_000 }, (_, i) => (i % 100 === 0 ? { title: 'missing id' } : { id: `w${i}`, title: 'Worker' }))
    const started = performance.now()
    const boundary = quarantineRunDetail(minimalDetail({ assignments: big }))
    const again = quarantineRunDetail(minimalDetail({ assignments: big }))
    const elapsed = performance.now() - started
    assert.equal(boundary.quarantined.length, 200)
    assert.equal(again.quarantined.length, 200)
    assert.ok(elapsed < 250, `boundary over 2×20k rows took ${elapsed.toFixed(1)}ms`)

    const page = quarantineRunEvents([{ id: 1, kind: 'a' }, { id: 'x', kind: 'b' }, null, { id: 4, kind: '' }])
    assert.deepEqual(page.events.map(e => e.id), [1])
    assert.equal(page.quarantined.length, 3)
  })

  it('history backfill reports malformed historical frames once and keeps hydrating good ones', async () => {
    const body = [
      'id: 1\ndata: {"id":1,"kind":"run.started","message":"","detail":{},"createdAt":1}\n\n',
      'id: 2\ndata: {nope\n\n',
      'id: 3\ndata: {"id":3,"kind":"note","message":"","detail":{},"createdAt":3}\n\n',
      'id: 9\ndata: {bad-live\n\n',
    ].join('')
    const fetchImpl = (async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(body))
        controller.close()
      },
    }), { status: 200 })) as unknown as typeof fetch
    const batches: number[][] = []
    const bad: number[] = []
    await hydrateHistoricalEvents('run-b1', 3, {
      signal: new AbortController().signal,
      fetchImpl,
      idleMs: 50,
      onBatch: batch => batches.push(batch.map(e => e.id)),
      onQuarantine: samples => bad.push(...samples.map(s => s.eventId ?? -1)),
    })
    assert.deepEqual(batches.flat(), [1, 3])
    assert.deepEqual(bad, [2], 'frames after the cursor are left to the live stream')
  })
})

describe('B1 useServerDraft contract (pristine follows, dirty/held never clobbered)', () => {
  it('pristine drafts follow the server; dirty drafts are protected and flag serverChanged', () => {
    let s = initialServerDraft('Acme')
    s = reconcileServerDraft(s, 'Acme v2')
    assert.deepEqual(s, { draft: 'Acme v2', base: 'Acme v2', server: 'Acme v2', pinned: false }, 'pristine syncs')
    assert.equal(reconcileServerDraft(s, 'Acme v2'), s, 'no-op reconcile returns the same object (safe in render)')

    s = editServerDraft(s, 'My draft')
    assert.deepEqual(serverDraftFlags(s), { dirty: true, serverChanged: false })
    s = reconcileServerDraft(s, 'Renamed elsewhere')
    assert.equal(s.draft, 'My draft', 'background refresh never overwrites a dirty draft')
    assert.deepEqual(serverDraftFlags(s), { dirty: true, serverChanged: true })

    // Accept / reset: load the latest server value and end pristine.
    const accepted = initialServerDraft(s.server)
    assert.deepEqual(serverDraftFlags(accepted), { dirty: false, serverChanged: false })
    assert.equal(accepted.draft, 'Renamed elsewhere')

    // Our own save landing (server === draft) converges without touching the draft.
    const converged = reconcileServerDraft(s, 'My draft')
    assert.deepEqual(converged, { draft: 'My draft', base: 'My draft', server: 'My draft', pinned: false })
    assert.equal(editServerDraft(converged, prev => `${prev}!`).draft, 'My draft!')
  })

  it('a held (focused) pristine field is not overwritten until it is released', () => {
    let s = initialServerDraft('Acme')
    s = reconcileServerDraft(s, 'Changed', { hold: true })
    assert.equal(s.draft, 'Acme', 'focused input keeps its value')
    assert.deepEqual(serverDraftFlags(s), { dirty: false, serverChanged: true })
    s = reconcileServerDraft(s, 'Changed', { hold: false })
    assert.deepEqual(s, { draft: 'Changed', base: 'Changed', server: 'Changed', pinned: false }, 'released field follows')

    // Regression: while "Updated elsewhere" shows, re-typing the old value is an explicit choice —
    // releasing focus (clicking Save) must not snap the field to the server value.
    let held = reconcileServerDraft(initialServerDraft('Original'), 'Renamed', { hold: true })
    held = editServerDraft(held, 'Typo')
    held = editServerDraft(held, 'Original')
    held = reconcileServerDraft(held, 'Renamed', { hold: false })
    assert.equal(held.draft, 'Original', 'pinned draft survives blur')
    assert.deepEqual(serverDraftFlags(held), { dirty: true, serverChanged: true })
    assert.equal(reconcileServerDraft(held, 'Original').pinned, false, 'saving it converges and unpins')

    const eq = (a: { v: number }, b: { v: number }) => a.v === b.v
    const obj = initialServerDraft({ v: 1 })
    assert.equal(reconcileServerDraft(obj, { v: 1 }, { equals: eq }), obj, 'custom equality avoids churn on new objects')
  })
})

describe('B1 StatePanel error-code mapping', () => {
  it('maps HTTP statuses, Zod/JSON/timeout errors and messages to human copy; raw text stays in details', () => {
    const cases: Array<[unknown, string, string]> = [
      [{ status: 401 }, 'unauthorized', 'error'],
      [{ statusCode: 403 }, 'forbidden', 'error'],
      [{ response: { status: 404 } }, 'not-found', 'not-found'],
      [{ status: 503 }, 'unavailable', 'degraded'],
      [{ status: 502 }, 'unavailable', 'degraded'],
      [{ status: 500 }, 'server', 'error'],
      [Object.assign(new Error('signal timed out'), { name: 'TimeoutError' }), 'timeout', 'degraded'],
      [new SyntaxError('Unexpected token < in JSON at position 0'), 'malformed', 'error'],
      [new Error('[{"code":"invalid_format","path":["projectId"]}]'), 'invalid', 'error'],
      ['Request failed with status 504', 'timeout', 'degraded'],
      [new Error('weird'), 'unknown', 'error'],
    ]
    for (const [error, code, kind] of cases) {
      const copy = describeStateError(error)
      assert.equal(copy.code, code, `code for ${JSON.stringify(error)}`)
      assert.equal(copy.kind, kind)
      assert.doesNotMatch(copy.title + copy.description, /invalid_format|Unexpected token|\{|\[/, 'human copy carries no raw text')
    }
    const details = stateErrorDetails(new Error('[{"code":"invalid_format"}]'), ['path: /projects/x'])
    assert.match(details, /^code: invalid\ntype: Error\npath: \/projects\/x\nmessage: \[/)
  })
})

// ===========================================================================
// Part 2 — built app in headless Chromium
// ===========================================================================

type Theme = 'light' | 'dark'
interface Viewport { width: number; height: number }

const DESKTOP: Viewport = { width: 1280, height: 720 }
const WIDE: Viewport = { width: 1440, height: 900 }
const VIEWPORTS = [DESKTOP, WIDE]
const THEMES: Theme[] = ['light', 'dark']
const SHOTS_DIR = process.env.KOVO_UI_SHOTS_DIR ?? ''

interface PlaywrightModule {
  chromium: {
    executablePath(): string
    launch(options?: { headless?: boolean; executablePath?: string; args?: string[] }): Promise<Browser>
  }
}

async function loadPlaywright(): Promise<{ pw: PlaywrightModule; executablePath: string } | null> {
  for (const modName of ['@playwright/test', 'playwright-core', 'playwright'] as const) {
    try {
      const pw = (await import(modName)) as Partial<PlaywrightModule>
      if (!pw.chromium?.launch) continue
      const candidates = [
        (() => { try { return pw.chromium!.executablePath() } catch { return '' } })(),
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
      ]
      const executablePath = candidates.find(p => p && existsSync(p))
      if (executablePath) return { pw: pw as PlaywrightModule, executablePath }
    } catch {
      // Try the next package name.
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
  if (existsSync(resolve('build/server/server.js')) && existsSync(resolve('build/client'))) return
  execFileSync('npm', ['run', 'build'], { cwd: process.cwd(), stdio: 'pipe' })
}

interface KovoServer {
  origin: string
  dataDir: string
  bootstrapSecret: string
  stop(): Promise<void>
}

async function startKovoServer(): Promise<KovoServer> {
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-ui-b1-'))
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
      if (await Promise.race([exited.then(() => false), delay(3_000).then(() => true)])) {
        child.kill('SIGKILL')
        await once(child, 'exit')
      }
    }
    await rm(dataDir, { recursive: true, force: true })
  }
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (child.exitCode !== null) break
    try {
      if ((await fetch(`${origin}/health`, { signal: AbortSignal.timeout(300) })).ok) {
        let bootstrapSecret = ''
        for (let read = 0; read < 40 && !bootstrapSecret; read += 1) {
          try { bootstrapSecret = (await readFile(join(dataDir, 'bootstrap'), 'utf8')).trim() } catch { await delay(50) }
        }
        if (!bootstrapSecret) break
        return { origin, dataDir, bootstrapSecret, stop }
      }
    } catch {
      // Not bound yet.
    }
    await delay(70)
  }
  await stop()
  throw new Error(`scripts/serve.ts failed to start on ${origin}.\n${output}`)
}

async function startTargetServer(): Promise<{ origin: string; server: Server }> {
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end('<!doctype html><title>QA target</title><p>ok</p>')
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  assert.ok(addr && typeof addr !== 'string')
  return { origin: `http://127.0.0.1:${addr.port}`, server }
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

const POOL = ['Pool Alpha', 'Pool Bravo', 'Pool Charlie'] as const

/** Three-profile pool: Bravo sits in an open circuit with a live cooldown. */
function seedPool(dataDir: string): void {
  withSqlite(dataDir, db => {
    const workspace = db.prepare('SELECT id FROM workspaces LIMIT 1').get() as { id: string } | undefined
    assert.ok(workspace, 'workspace row must exist after bootstrap')
    const insert = db.prepare(`INSERT INTO model_profiles
      (id, workspace_id, name, endpoint, model, protocol, credential_id, priority, enabled, context_window, max_tokens,
       thinking_level, role_affinity, input_cost_per_mtok, cached_input_cost_per_mtok, output_cost_per_mtok,
       health_state, cooldown_until, last_error, updated_at)
      VALUES (?, ?, ?, 'https://openrouter.ai/api/v1', ?, 'responses', ?, ?, 1, 1048576, 16384, 'medium', 'any', 0.15, 0.003, 0.6, ?, ?, NULL, ?)`)
    const now = Date.now()
    insert.run(randomUUID(), workspace.id, POOL[0], 'vendor/alpha', 'model-' + randomUUID(), 300, 'closed', null, now)
    insert.run(randomUUID(), workspace.id, POOL[1], 'vendor/bravo', 'model-' + randomUUID(), 200, 'open', now + 600_000, now)
    insert.run(randomUUID(), workspace.id, POOL[2], 'vendor/charlie', 'model-' + randomUUID(), 100, 'closed', null, now)
  })
}

function poolPriorities(dataDir: string): Array<[string, number]> {
  return withSqlite(dataDir, db => (db.prepare('SELECT name, priority FROM model_profiles ORDER BY priority DESC').all() as Array<{ name: string; priority: number }>)
    .map(row => [row.name, row.priority]))
}

const QA_HELPERS_SCRIPT = String.raw`(() => {
  window.__b1qa = {
    isRendered: el => {
      const r = el.getBoundingClientRect()
      if (r.width < 1 || r.height < 1) return false
      for (let node = el; node; node = node.parentElement) {
        const cs = getComputedStyle(node)
        if (cs.visibility === 'hidden' || cs.display === 'none' || Number(cs.opacity) < 0.05) return false
      }
      return true
    },
    // CSS colour (hex/rgb/oklch/color-mix…) → sRGB bytes via a 1×1 canvas.
    rgb: css => {
      const ctx = (window.__b1qaCtx ||= document.createElement('canvas').getContext('2d', { willReadFrequently: true }))
      ctx.clearRect(0, 0, 1, 1)
      ctx.fillStyle = '#000'
      ctx.fillStyle = css
      ctx.fillRect(0, 0, 1, 1)
      const d = ctx.getImageData(0, 0, 1, 1).data
      return [d[0], d[1], d[2]]
    },
    // Resolve a token such as var(--accent-fg) in the context of an element.
    token: (el, prop, value) => {
      const probe = document.createElement('span')
      probe.style[prop] = value
      el.append(probe)
      const out = getComputedStyle(probe)[prop]
      probe.remove()
      return out
    },
    // WCAG 2.x relative-luminance contrast ratio of two sRGB triples.
    contrast: (a, b) => {
      const lum = c => c.map(v => { const s = v / 255; return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4 })
        .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0)
      const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x)
      return (hi + 0.05) / (lo + 0.05)
    },
  }
})()`

type Rgb = [number, number, number]
declare global {
  interface Window {
    __b1qa: {
      isRendered(el: Element): boolean
      rgb(css: string): Rgb
      token(el: Element, prop: 'color' | 'backgroundColor', value: string): string
      contrast(a: Rgb, b: Rgb): number
    }
  }
}

let skipReason: string | null = null
let browser: Browser | undefined
let kovo: KovoServer | undefined
let target: { origin: string; server: Server } | undefined
let authCookies: Awaited<ReturnType<BrowserContext['cookies']>> = []
let runPath = ''
const openContexts = new Set<BrowserContext>()
const pageErrors: string[] = []

async function openPage(opts: { viewport?: Viewport; theme?: Theme; clipboard?: boolean } = {}): Promise<{ page: Page; context: BrowserContext }> {
  assert.ok(browser && kovo)
  const theme = opts.theme ?? 'light'
  const context = await browser.newContext({
    viewport: opts.viewport ?? DESKTOP,
    colorScheme: theme,
    deviceScaleFactor: 1,
    ...(opts.clipboard ? { permissions: ['clipboard-read', 'clipboard-write'] } : {}),
  })
  openContexts.add(context)
  await context.addCookies(authCookies)
  await context.addInitScript({ content: QA_HELPERS_SCRIPT })
  await context.addInitScript(mode => {
    try { localStorage.setItem('kovo-appearance', mode) } catch { /* storage unavailable */ }
  }, theme)
  const page = await context.newPage()
  page.on('pageerror', err => { pageErrors.push(`${new URL(page.url()).pathname}: ${err instanceof Error ? err.message : String(err)}`) })
  return { page, context }
}

async function closePage(context: BrowserContext) {
  openContexts.delete(context)
  await context.close().catch(() => {})
}

async function shot(page: Page, name: string, el?: Locator) {
  if (!SHOTS_DIR) return
  mkdirSync(SHOTS_DIR, { recursive: true })
  const path = join(SHOTS_DIR, `${name}.png`)
  if (el) await el.screenshot({ path, animations: 'disabled' })
  else await page.screenshot({ path, animations: 'disabled' })
}

const tag = (state: string, viewport: Viewport, theme: Theme) => `${state}-${viewport.width}x${viewport.height}-${theme}`

async function gotoApp(page: Page, path: string, ready: () => Promise<unknown>) {
  assert.ok(kovo)
  await page.goto(`${kovo.origin}${path}`, { waitUntil: 'domcontentloaded' })
  await ready()
  await page.waitForFunction(() => Boolean(window.__TSR_ROUTER__))
  await page.evaluate(() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))))
}

async function settle(page: Page) {
  await page.waitForFunction(() => document.getAnimations().every(a => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity), undefined, { timeout: 5_000 })
}

/** Zero horizontal overflow, zero clipped controls/cards, zero overlapping sibling controls, no null/undefined copy. */
async function assertGeometry(page: Page, scope: string, label: string) {
  const report = await page.evaluate(sel => {
    const overflow: string[] = []
    const clipped: string[] = []
    const overlaps: string[] = []
    const roots = [...document.querySelectorAll<HTMLElement>(sel)].filter(el => window.__b1qa.isRendered(el))
    if (document.documentElement.scrollWidth > document.documentElement.clientWidth) overflow.push('document')
    for (const root of roots) {
      for (const el of [root, ...root.querySelectorAll<HTMLElement>('main, header, form, [data-slot=card], [data-slot=dialog-content], [data-slot=state-panel], [data-slot=empty-state], table')]) {
        if (!window.__b1qa.isRendered(el)) continue
        const sideScroller = el.matches('[data-slot=card]') && getComputedStyle(el).overflowX === 'auto' && el.querySelector('table')
        if (!sideScroller && el.scrollWidth > el.clientWidth + 1) overflow.push(`${el.tagName}.${el.dataset.slot ?? ''} ${el.scrollWidth}>${el.clientWidth}`)
      }
      for (const el of root.querySelectorAll<HTMLElement>('button, a[data-slot=button], [role=radio], [data-slot=badge]')) {
        if (window.__b1qa.isRendered(el) && el.scrollHeight > el.clientHeight + 2) clipped.push(`${(el.textContent ?? '').trim().slice(0, 30)} ${el.scrollHeight}>${el.clientHeight}`)
      }
      const controls = [...root.querySelectorAll<HTMLElement>('button, input:not([type=hidden]), select, textarea, a[href]')].filter(el => window.__b1qa.isRendered(el))
      for (let i = 0; i < controls.length; i += 1) {
        for (let j = i + 1; j < controls.length; j += 1) {
          const a = controls[i]!
          const b = controls[j]!
          if (a.contains(b) || b.contains(a) || a.parentElement !== b.parentElement) continue
          const ra = a.getBoundingClientRect()
          const rb = b.getBoundingClientRect()
          if (Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left) > 1 && Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top) > 1) {
            overlaps.push(`${(a.textContent ?? a.getAttribute('aria-label') ?? '').trim().slice(0, 20)} × ${(b.textContent ?? b.getAttribute('aria-label') ?? '').trim().slice(0, 20)}`)
          }
        }
      }
    }
    const text = roots.map(r => r.innerText).join('\n')
    return { found: roots.length, overflow, clipped, overlaps, nullish: /\b(?:null|undefined|NaN)\b/.test(text) }
  }, scope)
  assert.ok(report.found > 0, `${label}: ${scope} rendered`)
  assert.deepEqual(report.overflow, [], `${label}: horizontal overflow`)
  assert.deepEqual(report.clipped, [], `${label}: clipped text`)
  assert.deepEqual(report.overlaps, [], `${label}: overlapping sibling controls`)
  assert.equal(report.nullish, false, `${label}: raw null/undefined/NaN in visible copy`)
}

async function assertInViewport(locator: Locator, viewport: Viewport, label: string) {
  const box = await locator.boundingBox()
  assert.ok(box, `${label}: not rendered`)
  assert.ok(box.x >= 0 && box.y >= 0 && box.x + box.width <= viewport.width + 0.5 && box.y + box.height <= viewport.height + 0.5,
    `${label}: outside the ${viewport.width}x${viewport.height} viewport (${JSON.stringify(box)})`)
}

/**
 * A link styled as a Button must paint the same label colour as a real Button of that
 * variant (app.css's unlayered `a { color: inherit }` silently beats layered `text-*`
 * utilities) and clear WCAG AA (4.5:1) on its own fill. Colours are resolved to sRGB
 * through a 1×1 canvas so oklch/color-mix tokens compare like-for-like.
 */
async function assertButtonLinkContrast(link: Locator, tokens: { fg: string; bg: string }, label: string) {
  const report = await link.evaluate((el, t) => {
    const qa = window.__b1qa
    const style = getComputedStyle(el)
    const fg = qa.rgb(style.color)
    const bg = qa.rgb(style.backgroundColor)
    const host = el.parentElement ?? el
    return { fg, bg, expectedFg: qa.rgb(qa.token(host, 'color', t.fg)), expectedBg: qa.rgb(qa.token(host, 'backgroundColor', t.bg)), ratio: qa.contrast(fg, bg) }
  }, tokens)
  const near = (a: number[], b: number[]) => a.every((v, i) => Math.abs(v - b[i]!) <= 2)
  assert.ok(near(report.fg, report.expectedFg), `${label}: label colour ${report.fg} ≠ ${tokens.fg} ${report.expectedFg}`)
  assert.ok(near(report.bg, report.expectedBg), `${label}: fill ${report.bg} ≠ ${tokens.bg} ${report.expectedBg}`)
  assert.ok(report.ratio >= 4.5, `${label}: contrast ${report.ratio.toFixed(2)}:1 < 4.5:1 AA`)
}

const waitForPool = (page: Page) => page.getByRole('table', { name: 'Configured model profiles' }).waitFor({ state: 'visible', timeout: 15_000 })

async function poolOrder(page: Page): Promise<Array<{ name: string; rank: string; role: string }>> {
  return page.locator('tr[data-profile-id]').evaluateAll(rows => rows.map(row => ({
    name: row.querySelector('[title] .line-clamp-2, span.line-clamp-2')?.textContent ?? '',
    rank: row.querySelector('[data-testid=failover-rank]')?.textContent ?? '',
    role: row.querySelector('[data-testid=failover-role]')?.textContent ?? '',
  })))
}

function requireEnv(t: { skip(msg?: string): void }): boolean {
  if (skipReason || !browser || !kovo) {
    t.skip(skipReason ?? 'Browser setup unavailable')
    return false
  }
  return true
}

const SSE_MARK = 900_000_000
/** Live stream with one valid event, one non-JSON frame and one event without a kind. */
const MALFORMED_STREAM = [
  `retry: 60000\n\n`,
  `id: ${SSE_MARK + 1}\ndata: {"id":${SSE_MARK + 1},"runId":null,"kind":"qa.note","message":"valid","detail":{},"createdAt":1}\n\n`,
  `id: ${SSE_MARK + 2}\ndata: {"id":${SSE_MARK + 2},"kind":\n\n`,
  `id: ${SSE_MARK + 3}\ndata: {"id":${SSE_MARK + 3},"message":"missing kind"}\n\n`,
].join('')

describe('B1 built app — StatePanel states, run quarantine banner, model pool failover & draft-safe settings', { timeout: 300_000 }, () => {
  before(async () => {
    const pwEnv = await loadPlaywright()
    if (!pwEnv) {
      skipReason = 'Playwright or Chromium binary unavailable in this environment'
      return
    }
    ensureBuilt()
    target = await startTargetServer()
    kovo = await startKovoServer()
    browser = await pwEnv.pw.chromium.launch({ headless: true, executablePath: pwEnv.executablePath, args: ['--no-sandbox'] })

    const context = await browser.newContext({ viewport: DESKTOP })
    const page = await context.newPage()
    await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, { waitUntil: 'domcontentloaded' })
    await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 20_000 })
    authCookies = await context.cookies()

    await page.getByLabel('Project name').fill('B1 QA target')
    await page.getByLabel('Sites').fill(target.origin)
    await page.getByRole('button', { name: /Advanced configuration/ }).click()
    await page.getByLabel('Target environment').selectOption('local-lab')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()
    await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 20_000 })
    await page.getByRole('button', { name: 'New run', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await dialog.waitFor({ state: 'visible', timeout: 10_000 })
    await dialog.getByRole('button', { name: 'Start run', exact: true }).click()
    await page.waitForURL(/\/runs\/[a-f0-9-]+/, { timeout: 20_000 })
    runPath = new URL(page.url()).pathname
    await context.close()
  })

  after(async () => {
    for (const context of openContexts) await context.close().catch(() => {})
    await browser?.close().catch(() => {})
    await kovo?.stop().catch(() => {})
    if (target) {
      target.server.closeAllConnections()
      await new Promise<void>(done => target!.server.close(() => done()))
    }
  })

  it('empty state: EmptyState renders through StatePanel with its CTA above the fold', async t => {
    if (!requireEnv(t)) return
    for (const theme of THEMES) {
      const { page, context } = await openPage({ viewport: DESKTOP, theme })
      await gotoApp(page, '/settings', () => page.getByRole('heading', { name: 'No model profiles configured' }).waitFor({ state: 'visible', timeout: 15_000 }))
      const panel = page.locator('[data-slot=empty-state]')
      assert.equal(await panel.getAttribute('data-kind'), 'empty')
      assert.equal(await panel.locator('[data-slot=empty-state-icon] svg').count(), 1, 'caller illustration kept in the icon slot')
      await assertInViewport(panel.getByRole('button', { name: 'Add model profile' }), DESKTOP, `${theme}: empty-state CTA`)
      await assertGeometry(page, 'main', `empty-state ${theme}`)
      await shot(page, tag('state-empty', DESKTOP, theme))
      await closePage(context)
    }
    seedPool(kovo!.dataDir)
  })

  it('404 + route error: in-shell StatePanel with recovery CTAs and collapsed mono diagnostics', async t => {
    if (!requireEnv(t)) return
    for (const viewport of VIEWPORTS) {
      for (const theme of THEMES) {
        const label = tag('state-404', viewport, theme)
        const { page, context } = await openPage({ viewport, theme, clipboard: true })
        const res = await page.goto(`${kovo!.origin}/no-such-page`, { waitUntil: 'domcontentloaded' })
        assert.equal(res?.status(), 404)
        await page.getByRole('heading', { name: 'Page not found' }).waitFor({ state: 'visible', timeout: 15_000 })
        await page.getByRole('navigation', { name: 'Workspace' }).waitFor({ state: 'visible' })
        await page.waitForFunction(() => Boolean(window.__TSR_ROUTER__))
        const panel = page.getByTestId('state-not-found')
        assert.equal(await panel.getAttribute('data-kind'), 'not-found')
        await assertInViewport(panel.getByRole('link', { name: 'Go to Projects' }), viewport, `${label}: primary CTA`)
        await assertButtonLinkContrast(panel.getByRole('link', { name: 'Go to Projects' }), { fg: 'var(--accent-fg)', bg: 'var(--accent)' }, `${label}: primary CTA`)
        await assertInViewport(panel.getByRole('button', { name: 'Go back' }), viewport, `${label}: secondary CTA`)
        const details = panel.locator('details')
        assert.equal(await details.evaluate(el => (el as HTMLDetailsElement).open), false, 'diagnostics start collapsed')
        assert.equal(await details.locator('pre').evaluate(el => getComputedStyle(el).fontFamily.includes('mono')), true, 'diagnostics are monospace')
        await assertGeometry(page, 'main', label)
        await shot(page, label)
        if (viewport === DESKTOP && theme === 'light') {
          await details.locator('summary').click()
          assert.match(await details.locator('pre').innerText(), /status: 404\npath: \/no-such-page/)
          await details.getByRole('button', { name: 'Copy diagnostics' }).click()
          await details.getByRole('button', { name: 'Copied' }).waitFor({ state: 'visible', timeout: 3_000 })
          await panel.getByRole('link', { name: 'Go to Projects' }).click()
          await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 10_000 })
        }

        await gotoApp(page, '/projects/not-a-valid-project-id', () => page.getByRole('heading', { name: 'Kovo couldn’t open this view' }).waitFor({ state: 'visible', timeout: 15_000 }))
        const error = page.getByTestId('state-route-error')
        assert.equal(await error.getAttribute('data-kind'), 'error')
        await page.getByRole('navigation', { name: 'Workspace' }).waitFor({ state: 'visible' })
        const visible = await error.evaluate(el => {
          const clone = el.cloneNode(true) as HTMLElement
          clone.querySelector('details')?.remove()
          return clone.textContent ?? ''
        })
        assert.doesNotMatch(visible, /invalid_|"code"|Zod|\[\s*\{/, 'no raw error text outside the details block')
        await assertInViewport(error.getByRole('button', { name: 'Try again' }), viewport, `${label}: Try again`)
        await assertButtonLinkContrast(error.getByRole('button', { name: 'Try again' }), { fg: 'var(--accent-fg)', bg: 'var(--accent)' }, `${label}: Try again`)
        await assertButtonLinkContrast(error.getByRole('link', { name: 'Go to Projects' }), { fg: 'var(--fg)', bg: 'var(--raise)' }, `${label}: route-error Go to Projects`)
        await assertGeometry(page, 'main', `${label} route-error`)
        await shot(page, tag('state-route-error', viewport, theme))
        await closePage(context)
      }
    }
    assert.deepEqual(pageErrors, [], `page errors: ${pageErrors.join('; ')}`)
  })

  it('run page: malformed SSE frames are quarantined; the page stays interactive with a dismissible recovery banner', async t => {
    if (!requireEnv(t)) return
    assert.ok(runPath, 'setup created a run')
    for (const viewport of VIEWPORTS) {
      for (const theme of THEMES) {
        const label = tag('run-sse-quarantine', viewport, theme)
        const { page, context } = await openPage({ viewport, theme, clipboard: true })
        const errorsBefore = pageErrors.length
        let streamHits = 0
        await page.route('**/api/runs/*/events**', route => {
          streamHits += 1
          return route.fulfill({ status: 200, headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-store' }, body: MALFORMED_STREAM })
        })
        await gotoApp(page, runPath, () => page.getByTestId('run-quarantine-banner').waitFor({ state: 'visible', timeout: 20_000 }))
        const banner = page.getByTestId('run-quarantine-banner')
        assert.equal(await banner.getByRole('heading').innerText(), '2 malformed stream events quarantined')
        assert.equal(await page.getByTestId('run-error-boundary').count(), 0, 'run page never fell into the error boundary')
        assert.ok(streamHits >= 1)
        await assertInViewport(banner.getByRole('button', { name: 'Copy diagnostics' }), viewport, `${label}: Copy diagnostics`)
        await assertInViewport(banner.getByRole('button', { name: 'Dismiss' }), viewport, `${label}: Dismiss`)
        await assertGeometry(page, '[data-testid=run-quarantine-banner]', label)
        const covered = await banner.evaluate(el => {
          const b = el.getBoundingClientRect()
          return [...document.querySelectorAll<HTMLElement>('button, a[href], input, select')]
            .filter(c => !el.contains(c) && window.__b1qa.isRendered(c))
            .filter(c => {
              const r = c.getBoundingClientRect()
              return Math.min(r.right, b.right) - Math.max(r.left, b.left) > 1 && Math.min(r.bottom, b.bottom) - Math.max(r.top, b.top) > 1
            })
            .map(c => (c.textContent ?? c.getAttribute('aria-label') ?? c.tagName).trim().slice(0, 30))
        })
        assert.deepEqual(covered, [], `${label}: the banner never covers run-page controls`)
        await settle(page)
        await shot(page, label)

        if (viewport === DESKTOP && theme === 'light') {
          // The rest of the workspace stays interactive under the banner.
          await page.getByRole('button', { name: 'Keyboard shortcuts' }).click()
          const help = page.locator('[data-slot=dialog-content]').filter({ hasText: 'Keyboard shortcuts' })
          await help.waitFor({ state: 'visible', timeout: 5_000 })
          await page.keyboard.press('Escape')
          await help.waitFor({ state: 'detached', timeout: 5_000 })

          await banner.getByRole('button', { name: 'Copy diagnostics' }).click()
          await banner.getByRole('button', { name: 'Copied' }).waitFor({ state: 'visible', timeout: 3_000 })
          const copied = await page.evaluate(() => navigator.clipboard.readText())
          assert.match(copied, /quarantined: 2 \(stream 2, rows 0\)/)
          assert.match(copied, new RegExp(`sse-frame: frame is not valid JSON · event #${SSE_MARK + 2}`))
          assert.match(copied, new RegExp(`event: event kind is missing · event #${SSE_MARK + 3}`))
          assert.equal(copied.includes('missing kind'), false, 'raw frame payloads are never copied')

          await banner.getByRole('button', { name: 'Dismiss' }).click()
          await banner.waitFor({ state: 'detached', timeout: 3_000 })
          // Reconnects replay the same frames: deduplicated by event id, the banner stays dismissed.
          await delay(600)
          assert.equal(await page.getByTestId('run-quarantine-banner').count(), 0)
        }
        assert.deepEqual(pageErrors.slice(errorsBefore), [], `${label}: page errors`)
        await closePage(context)
      }
    }
  })

  it('settings main: explicit failover ranks, live cooldown countdown, geometry at 1280×720 / 1440×900 in light & dark', async t => {
    if (!requireEnv(t)) return
    for (const viewport of VIEWPORTS) {
      for (const theme of THEMES) {
        const label = tag('settings-main', viewport, theme)
        const { page, context } = await openPage({ viewport, theme })
        await gotoApp(page, '/settings', () => waitForPool(page))
        assert.deepEqual(await poolOrder(page), [
          { name: POOL[0], rank: '1', role: 'Primary' },
          { name: POOL[1], rank: '2', role: 'Fallback 1' },
          { name: POOL[2], rank: '3', role: 'Fallback 2' },
        ])
        const rows = page.locator('tr[data-profile-id]')
        assert.equal(await rows.nth(0).getByRole('button', { name: /^Move up/ }).isDisabled(), true, 'first row cannot move up')
        assert.equal(await rows.nth(2).getByRole('button', { name: /^Move down/ }).isDisabled(), true, 'last row cannot move down')
        assert.equal(await rows.nth(1).getByRole('button', { name: /^Move up/ }).isEnabled(), true)
        if (viewport === DESKTOP) await assertInViewport(page.getByRole('button', { name: 'Add model profile' }), viewport, `${label}: primary CTA`)
        const fit = await page.getByRole('table', { name: 'Configured model profiles' }).evaluate(el => ({ table: el.scrollWidth, card: el.parentElement!.clientWidth }))
        assert.ok(fit.table <= fit.card, `${label}: table ${fit.table}px fits its card ${fit.card}px`)
        await assertGeometry(page, 'main', label)
        await shot(page, label)
        await closePage(context)
      }
    }

    // Cooldown ticks every second in tabular figures; the status never animates its colour swap.
    const { page, context } = await openPage({ viewport: DESKTOP })
    await gotoApp(page, '/settings', () => waitForPool(page))
    const countdown = page.locator('tr', { hasText: POOL[1] }).getByTestId('cooldown-remaining')
    const readSecs = async () => {
      const text = await countdown.innerText()
      const m = /^(?:(\d+)m )?(\d+)s$/.exec(text.trim())
      assert.ok(m, `countdown format (${text})`)
      return Number(m[1] ?? 0) * 60 + Number(m[2])
    }
    const style = await countdown.evaluate(el => ({
      numeric: getComputedStyle(el).fontVariantNumeric,
      transition: getComputedStyle(el.closest('[data-testid=profile-status]')!).transitionDuration,
    }))
    assert.match(style.numeric, /tabular-nums/)
    assert.equal(style.transition, '0s', 'status colour swaps instantly')
    const first = await readSecs()
    await delay(2_300)
    const second = await readSecs()
    assert.ok(first - second >= 2 && first - second <= 3, `countdown ticks each second (${first}s → ${second}s)`)
    await closePage(context)
  })

  it('settings: Move up / Move down reorder optimistically, keep focus, and persist priorities in steps of 10 across reload', async t => {
    if (!requireEnv(t)) return
    const { page, context } = await openPage({ viewport: WIDE })
    await gotoApp(page, '/settings', () => waitForPool(page))
    const firstDown = page.locator('tr[data-profile-id]').nth(0).getByRole('button', { name: /^Move down/ })
    await firstDown.focus()
    await page.keyboard.press('Enter')
    await page.waitForFunction(() => document.querySelector('tr[data-profile-id] [data-testid=failover-role]')?.closest('tr')?.textContent?.includes('Pool Bravo'))
    assert.deepEqual((await poolOrder(page)).map(r => [r.name, r.role]), [[POOL[1], 'Primary'], [POOL[0], 'Fallback 1'], [POOL[2], 'Fallback 2']])
    await page.getByText(`${POOL[0]} moved down in the failover order.`).waitFor({ state: 'visible', timeout: 10_000 })
    const focused = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null
      return { move: el?.dataset.move, row: el?.closest('tr')?.querySelector('span.line-clamp-2')?.textContent }
    })
    assert.deepEqual(focused, { move: 'down', row: POOL[0] }, 'keyboard focus follows the moved profile')
    assert.deepEqual(poolPriorities(kovo!.dataDir), [[POOL[1], 30], [POOL[0], 20], [POOL[2], 10]])

    await page.reload({ waitUntil: 'domcontentloaded' })
    await waitForPool(page)
    assert.deepEqual((await poolOrder(page)).map(r => [r.name, r.rank, r.role]), [[POOL[1], '1', 'Primary'], [POOL[0], '2', 'Fallback 1'], [POOL[2], '3', 'Fallback 2']])

    // Move it back so later tests see the seeded order (Alpha, Bravo, Charlie).
    await page.locator('tr[data-profile-id]').nth(1).getByRole('button', { name: /^Move up/ }).click()
    await page.getByText(`${POOL[0]} moved up in the failover order.`).waitFor({ state: 'visible', timeout: 10_000 })
    assert.deepEqual(poolPriorities(kovo!.dataDir), [[POOL[0], 30], [POOL[1], 20], [POOL[2], 10]])
    await closePage(context)
  })

  it('ModelProfileSheet: preset cards pre-fill endpoint/model/protocol/priority/limits; CTA above the fold; no overflow', async t => {
    if (!requireEnv(t)) return
    for (const viewport of VIEWPORTS) {
      for (const theme of THEMES) {
        const label = tag('settings-preset-sheet', viewport, theme)
        const { page, context } = await openPage({ viewport, theme })
        await gotoApp(page, '/settings', () => waitForPool(page))
        await page.getByRole('button', { name: 'Add model profile' }).click()
        const sheet = page.locator('[data-slot=dialog-content]')
        await sheet.waitFor({ state: 'visible' })
        const presets = sheet.getByRole('group', { name: 'Failover presets' })
        await presets.waitFor({ state: 'visible' })
        const preset = modelPoolPreset('opencode')
        const card = presets.locator(`[data-preset=${preset.id}]`)
        assert.equal(await card.getAttribute('aria-pressed'), 'false')
        assert.deepEqual(await card.evaluate(el => {
          const cs = getComputedStyle(el)
          const layers = cs.boxShadow === 'none' ? [] : cs.boxShadow.split(/,(?![^(]*\))/)
          return [cs.whiteSpace, cs.height === '26px', layers.every(layer => layer.includes('rgba(0, 0, 0, 0)'))]
        }), ['normal', false, true], 'preset cards opt out of the bare button height/nowrap/shadow')
        await card.click()
        assert.equal(await card.getAttribute('aria-pressed'), 'true')
        const values = await sheet.evaluate(el => Object.fromEntries(
          ['name', 'endpoint', 'model', 'protocol', 'priority', 'contextWindow', 'maxTokens', 'thinkingLevel', 'key']
            .map(name => [name, (el.querySelector(`[name="${name}"]`) as HTMLInputElement | HTMLSelectElement | null)?.value ?? null]),
        ))
        assert.deepEqual(values, {
          name: preset.name,
          endpoint: preset.endpoint,
          model: preset.model,
          protocol: preset.protocol,
          priority: String(preset.priority),
          contextWindow: String(preset.contextWindow),
          maxTokens: String(preset.maxTokens),
          thinkingLevel: preset.thinkingLevel,
          key: '',
        })
        assert.equal(await page.evaluate(() => (document.activeElement as HTMLInputElement | null)?.name), 'key', 'only the API key is left: it gets focus')
        await settle(page)
        if (viewport === DESKTOP) await assertInViewport(sheet.getByRole('button', { name: 'Save model' }), viewport, `${label}: primary CTA`)
        await assertGeometry(page, '[data-slot=dialog-content]', label)
        await shot(page, label)
        await page.keyboard.press('Escape')
        await sheet.waitFor({ state: 'detached', timeout: 5_000 })
        await closePage(context)
      }
    }
  })

  it('draft safety: workspace name and an open edit sheet survive revalidation and the 10s health poll', async t => {
    if (!requireEnv(t)) return
    const { page, context } = await openPage({ viewport: DESKTOP })
    await gotoApp(page, '/settings', () => waitForPool(page))
    const field = page.locator('input[name="workspaceName"]')
    const original = await field.inputValue()

    const other = await openPage({ viewport: DESKTOP })
    await gotoApp(other.page, '/settings', () => waitForPool(other.page))
    const renameElsewhere = async (name: string) => {
      await other.page.locator('input[name="workspaceName"]').fill(name)
      await other.page.getByRole('button', { name: 'Save', exact: true }).click()
      await other.page.getByText('Workspace name updated.').waitFor({ state: 'visible', timeout: 10_000 })
    }

    // Focused but untouched: a background rename is held (no value swap under the caret).
    await field.focus()
    await renameElsewhere('Renamed While Focused')
    await page.evaluate(() => window.__TSR_ROUTER__!.invalidate())
    await page.getByTestId('updated-elsewhere').waitFor({ state: 'visible', timeout: 5_000 })
    assert.equal(await field.inputValue(), original, 'focused pristine input not swapped')
    await field.evaluate(el => (el as HTMLInputElement).blur())
    await page.waitForFunction(() => (document.querySelector('input[name="workspaceName"]') as HTMLInputElement).value === 'Renamed While Focused')

    // Dirty: typing survives revalidation, keeps focus, and offers "Updated elsewhere · Reload".
    await field.click()
    await field.fill('Draft in progress')
    await renameElsewhere('Renamed Elsewhere')
    await closePage(other.context)
    await page.evaluate(() => window.__TSR_ROUTER__!.invalidate())
    const hint = page.getByTestId('updated-elsewhere')
    await hint.waitFor({ state: 'visible', timeout: 5_000 })
    assert.equal(await field.inputValue(), 'Draft in progress')
    assert.ok(await field.evaluate(el => document.activeElement === el), 'focus retained')
    assert.match(await hint.innerText(), /Updated elsewhere\s*·\s*Reload/)
    await assertGeometry(page, 'main', 'draft hint')
    await shot(page, tag('settings-updated-elsewhere', DESKTOP, 'light'))
    await hint.getByRole('button', { name: 'Reload' }).click()
    assert.equal(await field.inputValue(), 'Renamed Elsewhere')
    await hint.waitFor({ state: 'detached', timeout: 3_000 })

    // Open edit sheet + 10s poll (Bravo's open circuit keeps polling on): the poll refreshes the
    // table underneath while the typed draft and the sheet's form stay untouched.
    const marker = `poll-marker-${Date.now()}`
    const navs = await page.evaluate(() => performance.getEntriesByType('navigation').length)
    await page.locator('tr', { hasText: POOL[2] }).getByRole('button', { name: 'Edit', exact: true }).click()
    const sheet = page.locator('[data-slot=dialog-content]')
    await sheet.waitFor({ state: 'visible' })
    const nameField = sheet.locator('input[name="name"]')
    await nameField.fill('Charlie draft name')
    withSqlite(kovo!.dataDir, db => db.prepare('UPDATE model_profiles SET last_error = ?, model = ? WHERE name = ?').run(marker, 'vendor/charlie-v2', POOL[2]))
    await page.locator('tr', { hasText: marker }).waitFor({ state: 'attached', timeout: 13_000 })
    assert.equal(await nameField.inputValue(), 'Charlie draft name', 'poll never clobbers the open sheet')
    assert.equal(await sheet.locator('input[name="model"]').inputValue(), 'vendor/charlie', 'form keeps the values it was opened with')
    await sheet.getByTestId('updated-elsewhere').waitFor({ state: 'visible', timeout: 3_000 })
    await sheet.getByTestId('updated-elsewhere').getByRole('button', { name: 'Reload' }).click()
    assert.equal(await sheet.locator('input[name="model"]').inputValue(), 'vendor/charlie-v2', 'Reload adopts the newer server profile')
    assert.equal(await page.evaluate(() => performance.getEntriesByType('navigation').length), navs, 'polling never reloads the page')
    await page.keyboard.press('Escape')
    await sheet.waitFor({ state: 'detached', timeout: 5_000 })
    await closePage(context)
  })

  it('GitHub band: PAT / Enterprise options start collapsed under "Other ways to connect" and expand cleanly', async t => {
    if (!requireEnv(t)) return
    for (const theme of THEMES) {
      const { page, context } = await openPage({ viewport: DESKTOP, theme })
      await gotoApp(page, '/settings', () => waitForPool(page))
      const band = page.locator('section[aria-labelledby=github-integration-heading]')
      await band.scrollIntoViewIfNeeded()
      const trigger = band.getByRole('button', { name: /Other ways to connect/ })
      assert.equal(await trigger.getAttribute('aria-expanded'), 'false')
      assert.equal(await band.getByRole('button', { name: /Other ways to connect/ }).count(), 1, 'one disclosure for all secondary paths')
      assert.equal(await band.getByLabel('Read-only GitHub access token').isVisible(), false)
      assert.equal(await band.getByRole('button', { name: 'Sign in with GitHub' }).isVisible(), true, 'GitHub App sign-in stays primary')
      await trigger.click()
      assert.equal(await trigger.getAttribute('aria-expanded'), 'true')
      await band.getByLabel('Read-only GitHub access token').waitFor({ state: 'visible' })
      await band.getByLabel('Custom GitHub App Client ID').waitFor({ state: 'visible' })
      await settle(page)
      await assertGeometry(page, 'section[aria-labelledby=github-integration-heading]', `github ${theme}`)
      await shot(page, tag('settings-github-other-ways', DESKTOP, theme), band)
      await closePage(context)
    }
    assert.deepEqual(pageErrors, [], `page errors: ${pageErrors.join('; ')}`)
  })
})
