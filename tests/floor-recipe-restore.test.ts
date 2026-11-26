process.env.KOVO_ALLOW_LOCAL_LAB ??= '1'
/**
 * R2-08 (`r2-08-restore-disp`) verification suite:
 *  1. `finally`-guarded mutating floor-recipe restore via `ctx.registerRestore(...)` and
 *     `RequestBroker.executeCleanupHttp(...)` with an independent short timeout signal.
 *  2. Target-safety invariant: broker cleanup allowance NEVER bypasses `ScopePolicy` or
 *     Tier-3 approval/lease gates; denied/failed restores invalidate + re-mint persona sessions
 *     and emit structured degradation telemetry.
 *  3. Non-`selfState` `baselineWrite` captures and restores the owner's original field value
 *     both on success and on post-mutation abort/throw.
 *  4. Fail-closed async-poll safety budget (`RunAsyncPollBudgetLedger`): requires explicit `runId`
 *     (no `'__default__'`), denies with counters at cap, and NEVER FIFO-evicts/resets active runs.
 *  5. `registerRunDisposer` + `runAllRunDisposers(runId)` (wired from `Execution.cleanupRunState`)
 *     deterministically purges `verify-runner` alias counters, `token-telemetry`, and `verify-support`
 *     async-poll state without touching sibling runs.
 *  6. `scripts/check-run-scoped-state.ts` ratchet passes on the repo and catches new unregistered
 *     top-level per-run Maps/Sets.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  BrokerApprovalRequired,
  BrokerDenied,
  RequestBroker,
} from '../src/server/broker.ts'
import type { Grant, PublicAddress, RawHttpResponse } from '../src/server/broker.ts'
import type { SecondOrderStore } from '../src/server/canary-broker.ts'
import { Execution } from '../src/server/execution.ts'
import {
  brokerFloorRecipeDeps,
  floorRecipe,
  runFloorRecipe,
} from '../src/server/floor-recipes.ts'
import type {
  FloorRestoreDegradationEvent,
  PersistedMutationArgs,
} from '../src/server/floor-recipes.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { registerRunDisposer, runAllRunDisposers } from '../src/server/run-disposers.ts'
import { RunAsyncPollBudgetLedger } from '../src/server/run-safety-budgets.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'
import { Store } from '../src/server/store.ts'
import {
  getRunTokenTelemetrySummary,
  hasRunTokenTelemetry,
  recordProviderUsageTelemetry,
} from '../src/server/token-telemetry.ts'
import {
  getKovoVerifyAliasUsage,
  recordKovoVerifyAliasUsage,
} from '../src/server/verify-runner.ts'
import {
  consumeRunAsyncPollAttemptBudget,
  consumeRunAsyncPollCallBudget,
  getRunAsyncPollBudgetUsage,
  resetRunAsyncPollBudgets,
} from '../src/server/verify-support.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { scanRunScopedState } from '../scripts/check-run-scoped-state.ts'
import { setupApprovedRun, stopExecution } from './v4-tier-helpers.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const APP_ORIGIN = 'https://app.example.test'
const PUBLIC_ADDR: PublicAddress = { address: '93.184.216.34', family: 4 }

function makePersona(handle: string, cookieSecret: string): ResolvedPersona {
  return {
    id: `id-${handle}`,
    handle,
    roleLabel: handle,
    originAllowlist: [APP_ORIGIN],
    authKind: 'cookie',
    headerName: null,
    secret: `sid=${cookieSecret}`,
    canaryMarkers: [],
  }
}

function makeRecordingEventStore() {
  const events: Array<{ runId: string | null; kind: string; message: string; detail?: Record<string, unknown> }> = []
  const store: SecondOrderStore = {
    insertSecondOrderCanary: () => { throw new Error('unused') },
    markSecondOrderCanarySurfaced: () => { throw new Error('unused') },
    listSecondOrderCanaries: () => [],
    event: (runId, kind, message, detail) => {
      events.push({ runId, kind, message, detail })
    },
  }
  return { store, events }
}

function makeGrant(options: {
  runId: string
  mode?: ScopePolicy['mode']
  tier?: 1 | 2 | 3
  personas?: ReadonlyArray<ResolvedPersona>
  storage?: SecondOrderStore
  approvalLeases?: Grant['approvalLeases']
  isStateChangeApproved?: Grant['isStateChangeApproved']
}): Grant {
  return {
    origin: APP_ORIGIN,
    tier: options.tier ?? 3,
    maxRpsPerOrigin: 50,
    canRead: (o: string) => o === APP_ORIGIN,
    audit: () => {},
    scopePolicy: {
      runId: options.runId,
      mode: options.mode ?? 'staging_isolated',
      targetOrigins: [APP_ORIGIN],
    },
    ...(options.personas ? { personas: new Map(options.personas.map(p => [p.handle, p])) } : {}),
    ...(options.storage ? { storage: options.storage } : {}),
    ...(options.approvalLeases ? { approvalLeases: options.approvalLeases } : {}),
    ...(options.isStateChangeApproved ? { isStateChangeApproved: options.isStateChangeApproved } : {}),
  }
}

function makeStore(t: { after: (fn: () => void) => void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r2-08-'))
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return storage
}

function stubBackend(): WorkerBackend {
  return {
    openSession: async () => ({
      stage: async (name: string) => `/work/${name}`,
      exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
      analyze: async () => ({ ok: true }),
      sast: async () => ({ repo: 'app', enginesRun: [], engineStatus: {}, findings: [], durationMs: 1 }),
      runScript: async () => ({ runtime: 'python', exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 1 }),
      close: async () => undefined,
    }),
  } as unknown as WorkerBackend
}

// ============================================================================
// 1. Finally-guarded restore on abort / throw during post_mutation_read
// ============================================================================

test('R2-08.1a: aborting caller signal after mutation_probe still restores state via broker cleanup allowance', async () => {
  const runId = 'run-r2-08-abort-restore'
  const viewer = makePersona('viewer', 'viewer_cookie_1111')
  const { store, events } = makeRecordingEventStore()

  let actingStore = 'store-own'
  const abortController = new AbortController()
  const requestsSeen: Array<{ method: string; path: string; body?: string }> = []

  const transport = async (url: URL, _addr: PublicAddress, _signal: AbortSignal, opts?: { method?: string; body?: string }): Promise<RawHttpResponse> => {
    const method = (opts?.method ?? 'GET').toUpperCase()
    requestsSeen.push({ method, path: url.pathname, body: opts?.body })
    if (url.pathname === '/api/v1/admin/impersonate' && method === 'POST') {
      const parsed = JSON.parse(opts?.body ?? '{}') as { store?: string }
      if (parsed.store) actingStore = parsed.store
      // Simulate deadline abort firing right after mutation_probe succeeded, before post_mutation_read!
      if (parsed.store === 'store-victim') {
        abortController.abort(new Error('recipe deadline expired after mutation_probe'))
      }
      const body = JSON.stringify({ ok: true, actingAs: actingStore })
      return { status: 200, headers: { 'content-type': 'application/json' }, body, bodyBytes: Buffer.byteLength(body) }
    }
    const body = JSON.stringify({ actor: 'viewer', store: actingStore })
    return { status: 200, headers: { 'content-type': 'application/json' }, body, bodyBytes: Buffer.byteLength(body) }
  }

  const broker = new RequestBroker({ resolve: async () => [PUBLIC_ADDR], transport, storage: store })
  const grant: Grant = {
    origin: APP_ORIGIN,
    tier: 3,
    maxRpsPerOrigin: 50,
    canRead: o => o === APP_ORIGIN,
    audit: () => {},
    personas: new Map([[viewer.handle, viewer]]),
    storage: store,
    isStateChangeApproved: () => true,
  }
  const deps = brokerFloorRecipeDeps({
    broker,
    grant,
    signal: abortController.signal,
    origin: APP_ORIGIN,
    runId,
    cleanupTimeoutMs: 2_000,
  })

  const args: PersistedMutationArgs = {
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/v1/admin/impersonate',
    vulnClass: 'bfla',
    actor: { handle: 'viewer', role: 'viewer', tenant: 'tenant-a', auth: 'cookie' },
    body: { store: 'store-victim' },
    reset: { body: { store: 'store-own' } },
    baselineMethod: 'GET',
    baselinePathAndQuery: '/api/v1/session',
    readbackMethod: 'GET',
    readbackPathAndQuery: '/api/v1/session',
  }

  const execution = await runFloorRecipe(floorRecipe('persisted_mutation', args), deps)

  assert.equal(execution.result.confirmed, false, 'aborted recipe must not confirm')
  assert.equal(execution.failure?.code, 'recipe_error')
  assert.equal(actingStore, 'store-own', 'finally restore must revert target state even when caller signal aborted')
  assert.ok(
    execution.result.transcript.entries?.some(e => e.evidenceRole === 'state_restore'),
    'reset state_restore cleanup exchange must be recorded',
  )
  assert.equal(execution.result.restoreDegradations, undefined, 'successful restore emits no degradation')
  assert.equal(events.length, 0)
  const postBodies = requestsSeen.filter(r => r.method === 'POST').map(r => JSON.parse(r.body ?? '{}').store)
  assert.deepEqual(postBodies, ['store-own', 'store-victim', 'store-own'])
})

test('R2-08.1b: throw injected during post_mutation_read (BrokerDenied) triggers restore in finally', async () => {
  let state = 'initial-own'
  let restoreSent = false
  const execution = await runFloorRecipe(
    floorRecipe('persisted_mutation', {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/v1/session/switch',
      vulnClass: 'bfla',
      actor: { handle: 'viewer', role: 'viewer', tenant: 'tenant-a', auth: 'cookie' },
      body: { tenant: 'tenant-victim' },
      reset: { body: { tenant: 'initial-own' } },
      baselineMethod: 'GET',
      baselinePathAndQuery: '/api/v1/session',
      readbackMethod: 'GET',
      readbackPathAndQuery: '/api/v1/session',
    }),
    {
      request: spec => {
        if (spec.role === 'post_mutation_read') {
          throw new BrokerDenied('Injected BrokerDenied during post_mutation_read')
        }
        if (spec.method === 'POST') {
          state = String((spec.jsonBody as { tenant?: string })?.tenant ?? state)
          return { status: 200, json: { tenant: state } }
        }
        return { status: 200, json: { tenant: state } }
      },
      cleanupRequest: spec => {
        restoreSent = true
        state = String((spec.jsonBody as { tenant?: string })?.tenant ?? state)
        return { status: 200, json: { tenant: state } }
      },
    },
  )

  assert.equal(execution.result.confirmed, false)
  assert.equal(restoreSent, true, 'cleanupRequest must be invoked in finally after post_mutation_read throw')
  assert.equal(state, 'initial-own', 'target state must be restored back to initial-own')
})

// ============================================================================
// 2. Target-safety invariant: cleanup allowance respects ScopePolicy & approvals,
//    invalidates/re-mints persona session, and emits structured degradation event
// ============================================================================

test('R2-08.2: broker cleanup allowance NEVER bypasses ScopePolicy or approval gates; denied restore invalidates/re-mints session and emits degradation telemetry', async () => {
  const runId = 'run-r2-08-scope-invariant'
  const viewer = makePersona('viewer', 'viewer_cookie_2222')
  const { store, events } = makeRecordingEventStore()

  // Allow initial setup/mutation POSTs, then revoke approval before cleanup so cleanup MUST be denied!
  let allowMutations = true
  let wirePostCount = 0
  let reauthCalls = 0
  let remintedPersona = ''

  const transport = async (url: URL, _addr: PublicAddress, _signal: AbortSignal, opts?: { method?: string; body?: string }): Promise<RawHttpResponse> => {
    const method = (opts?.method ?? 'GET').toUpperCase()
    if (method === 'POST') {
      wirePostCount += 1
      const parsed = JSON.parse(opts?.body ?? '{}') as { store?: string }
      if (parsed.store === 'store-victim') {
        // Revoke approval right after mutation_probe lands so the finally restore is NOT approved!
        allowMutations = false
      }
      const body = JSON.stringify({ ok: true, store: parsed.store })
      return {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'set-cookie': ['app_sess=rotated_viewer_session_99; Path=/'],
        },
        body,
        bodyBytes: Buffer.byteLength(body),
      }
    }
    const body = JSON.stringify({ store: 'store-own' })
    return { status: 200, headers: { 'content-type': 'application/json' }, body, bodyBytes: Buffer.byteLength(body) }
  }

  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport,
    storage: store,
    reauth: async (personaHandle, rId, orig) => {
      reauthCalls += 1
      remintedPersona = `${personaHandle}@${rId}@${orig}`
      return true
    },
  })

  // Explicitly use a grant WITHOUT staging_isolated auto-approval so Tier-3 approval gates are active!
  const grant: Grant = {
    origin: APP_ORIGIN,
    tier: 3,
    maxRpsPerOrigin: 50,
    canRead: o => o === APP_ORIGIN,
    audit: () => {},
    personas: new Map([[viewer.handle, viewer]]),
    storage: store,
    isStateChangeApproved: () => allowMutations,
  }

  // First seed a session jar cookie for `viewer` in this run to verify jar invalidation.
  await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/v1/session', persona: 'viewer', runId, session: 's1' },
    grant,
    AbortSignal.timeout(5_000),
  )
  // Trigger a jar cookie via POST state_reset / mutation_probe and check jar count before restore fails
  const observedDegradations: FloorRestoreDegradationEvent[] = []
  const deps = brokerFloorRecipeDeps({
    broker,
    grant,
    signal: AbortSignal.timeout(5_000),
    origin: APP_ORIGIN,
    runId,
    onRestoreDegradation: ev => { observedDegradations.push(ev) },
  })

  // Also directly prove executeCleanupHttp fails closed on prod_readonly ScopePolicy
  const prodReadonlyGrant = makeGrant({ runId: 'run-prod-ro', mode: 'prod_readonly', personas: [viewer], storage: store })
  await assert.rejects(
    () => broker.executeCleanupHttp(
      { origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/v1/admin/impersonate', persona: 'viewer', runId: 'run-prod-ro', body: '{}' },
      prodReadonlyGrant,
    ),
    BrokerDenied,
    'executeCleanupHttp must NEVER bypass prod_readonly ScopePolicy',
  )
  assert.equal(wirePostCount, 0, 'prod_readonly cleanup denial must send zero wire requests')

  // Now run the persisted_mutation recipe where approval is revoked right after mutation_probe
  const args: PersistedMutationArgs = {
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/v1/admin/impersonate',
    vulnClass: 'bfla',
    actor: { handle: 'viewer', role: 'viewer', tenant: 'tenant-a', auth: 'cookie' },
    body: { store: 'store-victim' },
    reset: { body: { store: 'store-own' } },
    baselineMethod: 'GET',
    baselinePathAndQuery: '/api/v1/session',
    readbackMethod: 'GET',
    readbackPathAndQuery: '/api/v1/session',
  }

  const execution = await runFloorRecipe(floorRecipe('persisted_mutation', args), deps)

  // Only state_reset + mutation_probe reached the wire; the unapproved restore MUST be blocked!
  assert.equal(wirePostCount, 2, 'unapproved cleanup restore must NEVER bypass approval gate to hit the wire')
  assert.equal(reauthCalls, 1, 'failed/denied restore must trigger persona session re-mint via broker reauth')
  assert.equal(remintedPersona, `viewer@${runId}@${APP_ORIGIN}`)
  assert.equal(broker.getRunStateCounts(runId).sessionJars, 0, 'viewer session jar must be invalidated on restore failure')

  // Structured degradation event emitted both on result and on broker storage event sink
  assert.equal(observedDegradations.length, 1)
  assert.equal(execution.result.restoreDegradations?.length, 1)
  const deg = execution.result.restoreDegradations![0]!
  assert.equal(deg.actorHandle, 'viewer')
  assert.equal(deg.sessionInvalidated, true)
  assert.equal(deg.sessionReminted, true)
  assert.match(deg.reason, /approval|denied/i)

  const storedEvent = events.find(e => e.kind === 'floor_recipe.restore_degraded')
  assert.ok(storedEvent, 'structured floor_recipe.restore_degraded event must be persisted to storage')
  assert.equal(storedEvent.runId, runId)
  assert.equal(storedEvent.detail?.degradation, 'floor_recipe_restore_failed')
  assert.equal(storedEvent.detail?.sessionInvalidated, true)
  assert.equal(storedEvent.detail?.sessionReminted, true)

  // Also verify direct executeCleanupHttp throws BrokerApprovalRequired when approval is missing
  await assert.rejects(
    () => broker.executeCleanupHttp(
      { origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/v1/admin/impersonate', persona: 'viewer', runId, body: '{}' },
      grant,
    ),
    BrokerApprovalRequired,
    'executeCleanupHttp must fail closed with BrokerApprovalRequired when approval is absent',
  )
})

// ============================================================================
// 3. Non-selfState baselineWrite owner-value restore (success + post-mutation throw)
// ============================================================================

test('R2-08.3a: non-selfState baselineWrite restores owner original value on success AND preserves proof transcript', async () => {
  let invoiceTitle = 'Original Owner Title'
  const writeActors: Array<{ role: string; actor: string; title: string }> = []

  const args: PersistedMutationArgs = {
    origin: APP_ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/v1/invoices/inv-42',
    vulnClass: 'bola',
    actor: { handle: 'attacker', role: 'member', tenant: 'tenant-b', auth: 'cookie' },
    body: { title: 'attacker-tampered', amount: 100 },
    baselineWrite: {
      body: { title: 'kovo-baseline-deadbeef', amount: 100 },
      actor: { handle: 'owner', role: 'member', tenant: 'tenant-a', auth: 'cookie' },
      method: 'PATCH',
      field: 'title',
      restoreOriginal: true,
    },
    baselineMethod: 'GET',
    baselinePathAndQuery: '/api/v1/invoices/inv-42',
    readbackMethod: 'GET',
    readbackPathAndQuery: '/api/v1/invoices/inv-42',
    readbackActor: { handle: 'owner', role: 'member', tenant: 'tenant-a', auth: 'cookie' },
  }

  const execution = await runFloorRecipe(floorRecipe('persisted_mutation', args), {
    request: spec => {
      if (spec.method === 'GET') {
        const doc = { id: 'inv-42', title: invoiceTitle, amount: 100 }
        return { status: 200, json: doc, body: JSON.stringify(doc) }
      }
      const nextTitle = String((spec.jsonBody as { title?: string })?.title ?? invoiceTitle)
      writeActors.push({ role: spec.role, actor: spec.actor.handle, title: nextTitle })
      invoiceTitle = nextTitle
      const doc = { id: 'inv-42', title: invoiceTitle, amount: 100 }
      return { status: 200, json: doc, body: JSON.stringify(doc) }
    },
  })

  assert.equal(execution.result.confirmed, true, execution.failure?.message ?? execution.result.verification.reason)
  assert.equal(invoiceTitle, 'Original Owner Title', 'owner original title must be restored in finally (not left as baseline sentinel or probe value)')
  assert.deepEqual(writeActors, [
    { role: 'baseline_write', actor: 'owner', title: 'kovo-baseline-deadbeef' },
    { role: 'mutation_probe', actor: 'attacker', title: 'attacker-tampered' },
    { role: 'state_restore', actor: 'owner', title: 'Original Owner Title' },
  ])
  assert.deepEqual(
    execution.result.transcript.entries?.map(e => e.evidenceRole),
    ['baseline_write', 'baseline_read', 'mutation_probe', 'post_mutation_read'],
    'non-selfState baselineWrite snapshot & restore must not distort proof receipt transcript entries',
  )
})

test('R2-08.3b: non-selfState baselineWrite restores owner original value on collection readback even when post_mutation_read throws', async () => {
  let shipmentStatus = 'delivered'

  const args: PersistedMutationArgs = {
    origin: APP_ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/v1/shipments/ship-9',
    vulnClass: 'cross_tenant_write',
    actor: { handle: 'persona_b', role: 'member', tenant: 'tenant-b', auth: 'cookie' },
    body: { status: 'canceled', external_id: 'ext-9' },
    baselineWrite: {
      body: { status: 'kovo-baseline-9999', external_id: 'ext-9' },
      actor: { handle: 'persona_a', role: 'member', tenant: 'tenant-a', auth: 'cookie' },
      method: 'PATCH',
      field: 'status',
      restoreOriginal: true,
    },
    baselineMethod: 'GET',
    baselinePathAndQuery: '/api/v1/shipments',
    readbackMethod: 'GET',
    readbackPathAndQuery: '/api/v1/shipments',
    readbackActor: { handle: 'persona_a', role: 'member', tenant: 'tenant-a', auth: 'cookie' },
  }

  const execution = await runFloorRecipe(floorRecipe('persisted_mutation', args), {
    request: spec => {
      if (spec.role === 'post_mutation_read') {
        throw new Error('simulated transport timeout during post_mutation_read')
      }
      if (spec.method === 'GET') {
        const doc = { shipments: [{ id: 'ship-1', status: 'open' }, { id: 'ship-9', status: shipmentStatus, external_id: 'ext-9' }] }
        return { status: 200, json: doc, body: JSON.stringify(doc) }
      }
      shipmentStatus = String((spec.jsonBody as { status?: string })?.status ?? shipmentStatus)
      return { status: 204, body: '' }
    },
  })

  assert.equal(execution.result.confirmed, false)
  assert.equal(shipmentStatus, 'delivered', 'owner original collection item status must be restored in finally after throw')
})

// ============================================================================
// 4. Fail-closed async-poll safety budget (no '__default__', no FIFO reset)
// ============================================================================

test('R2-08.4: async-poll safety budget requires explicit runId, denies fail-closed with counters at cap, and NEVER FIFO-evicts active runs', () => {
  const ledger = new RunAsyncPollBudgetLedger({ maxTrackedRuns: 2 })

  // Empty / whitespace runId fails closed (no '__default__' bucket!)
  assert.throws(() => ledger.consumeCall(''), /explicit non-empty runId/i)
  assert.throws(() => ledger.consumeCall('   '), /explicit non-empty runId/i)
  assert.throws(() => ledger.consumeAttempt(''), /explicit non-empty runId/i)
  assert.throws(() => consumeRunAsyncPollCallBudget(''), /explicit non-empty runId/i)
  assert.throws(() => consumeRunAsyncPollAttemptBudget('  '), /explicit non-empty runId/i)

  // Per-run call & attempt caps deny fail-closed, increment denial counters, and never reset
  assert.equal(ledger.consumeCall('run-1', 2), 1)
  assert.equal(ledger.consumeCall('run-1', 2), 2)
  assert.throws(() => ledger.consumeCall('run-1', 2), /run call budget exceeded/)
  assert.throws(() => ledger.consumeCall('run-1', 2), /run call budget exceeded/)

  assert.equal(ledger.consumeAttempt('run-1', 1), 1)
  assert.throws(() => ledger.consumeAttempt('run-1', 1), /run poll-attempt budget exceeded/)
  assert.deepEqual(ledger.getUsage('run-1'), {
    calls: 2,
    attempts: 1,
    deniedCalls: 2,
    deniedAttempts: 1,
  })

  // Fill tracked-runs capacity cap (2 active runs)
  assert.equal(ledger.consumeCall('run-2', 5), 1)
  assert.deepEqual(ledger.getCapacityStats(), { trackedRuns: 2, capacityDenials: 0 })

  // 3rd run MUST fail closed at tracked-runs cap — NEVER FIFO-evict run-1!
  assert.throws(() => ledger.consumeCall('run-3', 5), /tracked-run safety budget capacity reached/)
  assert.throws(() => ledger.consumeAttempt('run-3', 5), /tracked-run safety budget capacity reached/)
  assert.deepEqual(ledger.getCapacityStats(), { trackedRuns: 2, capacityDenials: 2 })
  assert.equal(ledger.has('run-1'), true, 'oldest live run-1 must NEVER be FIFO-evicted')
  assert.equal(ledger.getUsage('run-1').calls, 2, 'run-1 budget counter must NEVER silently reset')
  assert.throws(() => ledger.consumeCall('run-1', 2), /run call budget exceeded/, 'run-1 must still deny at cap')

  // Only explicit run disposal frees capacity for run-3
  ledger.delete('run-1')
  assert.equal(ledger.has('run-1'), false)
  assert.equal(ledger.consumeCall('run-3', 5), 1)
  assert.equal(ledger.getUsage('run-3').calls, 1)
  assert.equal(ledger.getUsage('run-2').calls, 1, 'sibling run-2 unaffected')
})

// ============================================================================
// 5. Run-disposer registry + Execution.cleanupRunState end-to-end disposal
// ============================================================================

test('R2-08.5: runAllRunDisposers and Execution.disposeRun deterministically purge alias counters, token telemetry, and async-poll budgets without affecting sibling runs', async t => {
  const storage = makeStore(t)
  const { runId: runA } = await setupApprovedRun(storage, { budgetRequests: 100 })
  const { runId: runB } = await setupApprovedRun(storage, { budgetRequests: 100 })
  t.after(() => {
    runAllRunDisposers(runA)
    runAllRunDisposers(runB)
  })

  // Verify custom disposer error isolation + unregister handle
  let customDisposed: string[] = []
  const unregThrow = registerRunDisposer('test:r2-08-thrower', () => { throw new Error('boom') })
  const unregOk = registerRunDisposer('test:r2-08-recorder', id => { customDisposed.push(id) })
  t.after(() => {
    unregThrow()
    unregOk()
  })

  // Populate all three registered per-run stores for runA and runB
  recordKovoVerifyAliasUsage(runA, ['tool_arg:code'])
  recordKovoVerifyAliasUsage(runB, ['tool_arg:code'])
  recordProviderUsageTelemetry({ runId: runA, inputTokens: 100, outputTokens: 20, costUsd: 0.01 })
  recordProviderUsageTelemetry({ runId: runB, inputTokens: 200, outputTokens: 40, costUsd: 0.02 })
  consumeRunAsyncPollCallBudget(runA, 10)
  consumeRunAsyncPollAttemptBudget(runA, 10)
  consumeRunAsyncPollCallBudget(runB, 10)
  consumeRunAsyncPollAttemptBudget(runB, 10)

  assert.equal(getKovoVerifyAliasUsage(runA).totalCalls, 1)
  assert.equal(hasRunTokenTelemetry(runA), true)
  assert.equal(getRunAsyncPollBudgetUsage(runA).calls, 1)

  // Direct runAllRunDisposers drains all registered disposers even if one throws
  const drain = runAllRunDisposers(runA)
  assert.ok(drain.invoked >= 5)
  assert.equal(drain.errors.length, 1)
  assert.equal(drain.errors[0]?.name, 'test:r2-08-thrower')
  assert.deepEqual(customDisposed, [runA])

  // All three registered per-run stores are purged for runA while runB stays intact
  assert.equal(getKovoVerifyAliasUsage(runA).totalCalls, 0)
  assert.equal(hasRunTokenTelemetry(runA), false)
  assert.equal(getRunTokenTelemetrySummary(runA).inputTokens, 0)
  assert.deepEqual(getRunAsyncPollBudgetUsage(runA), { calls: 0, attempts: 0, deniedCalls: 0, deniedAttempts: 0 })

  assert.equal(getKovoVerifyAliasUsage(runB).totalCalls, 1, 'sibling runB alias counters preserved')
  assert.equal(hasRunTokenTelemetry(runB), true, 'sibling runB token telemetry preserved')
  assert.equal(getRunAsyncPollBudgetUsage(runB).calls, 1, 'sibling runB async-poll budget preserved')

  // Unregister test hooks before running Execution.disposeRun on runB
  unregThrow()
  unregOk()
  customDisposed = []

  const engine = new Execution(storage, { backend: stubBackend(), broker: new RequestBroker(), deterministicSweep: false })
  t.after(() => stopExecution(engine as never))

  await engine.disposeRun(runB, { terminalState: 'completed', reason: 'r2-08 disposal test' })
  assert.equal(getKovoVerifyAliasUsage(runB).totalCalls, 0, 'Execution.disposeRun must purge alias counters via runAllRunDisposers')
  assert.equal(hasRunTokenTelemetry(runB), false, 'Execution.disposeRun must purge token telemetry via runAllRunDisposers')
  assert.deepEqual(
    getRunAsyncPollBudgetUsage(runB),
    { calls: 0, attempts: 0, deniedCalls: 0, deniedAttempts: 0 },
    'Execution.disposeRun must purge async-poll budget via runAllRunDisposers',
  )
  resetRunAsyncPollBudgets(runA)
})

// ============================================================================
// 6. Per-run module-Map ratchet lint (`scripts/check-run-scoped-state.ts`)
// ============================================================================

test('R2-08.6: check-run-scoped-state ratchet passes on live repo and rejects new unregistered per-run Maps', t => {
  const repoResult = scanRunScopedState(REPO_ROOT)
  assert.equal(repoResult.ok, true, `Expected clean repo ratchet, got violations: ${JSON.stringify(repoResult.newViolations)}`)
  assert.equal(repoResult.newViolations.length, 0)
  assert.ok(repoResult.unregisteredCount <= repoResult.baselineMax)
  const registeredKeys = repoResult.registered.map(r => r.key)
  assert.ok(registeredKeys.includes('src/server/token-telemetry.ts::runTelemetryStore'))
  assert.ok(registeredKeys.includes('src/server/verify-runner.ts::runAliasCounters'))

  // Synthetic negative + positive ratchet test on a temp root
  const tmpRoot = mkdtempSync(join(tmpdir(), 'kovo-r2-08-lint-'))
  t.after(() => rmSync(tmpRoot, { recursive: true, force: true }))
  mkdirSync(join(tmpRoot, 'src/server'), { recursive: true })

  // 1) Unregistered per-run Map -> MUST FAIL
  writeFileSync(
    join(tmpRoot, 'src/server/leaky.ts'),
    `const runLeakedSessions = new Map<string, string>()\nexport function track(id: string) { runLeakedSessions.set(id, 'x') }\n`,
  )
  const failed = scanRunScopedState(tmpRoot, { baselinedKeys: [], baselineMax: 0 })
  assert.equal(failed.ok, false)
  assert.equal(failed.newViolations.length, 1)
  assert.equal(failed.newViolations[0]?.key, 'src/server/leaky.ts::runLeakedSessions')

  // 2) Registered via registerRunDisposer -> MUST PASS
  writeFileSync(
    join(tmpRoot, 'src/server/leaky.ts'),
    `import { registerRunDisposer } from './run-disposers.ts'\nconst runLeakedSessions = new Map<string, string>()\nregisterRunDisposer('leaky', runId => { runLeakedSessions.delete(runId) })\n`,
  )
  const passed = scanRunScopedState(tmpRoot, { baselinedKeys: [], baselineMax: 0 })
  assert.equal(passed.ok, true)
  assert.equal(passed.registeredCount, 1)
  assert.equal(passed.unregisteredCount, 0)
})
