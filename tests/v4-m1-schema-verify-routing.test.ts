import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'
import { eq } from 'drizzle-orm'
import {
  DEFAULT_PROVIDER,
  maxInlineVerifyRetries,
  providerSettings,
} from '../src/domain.ts'
import type { Finding, InlineVerifyFeedback } from '../src/domain.ts'
import {
  browserChainReplaySpecSchema,
} from '../src/replay-spec.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  defaultThinkingForRole,
  roleAffinityForScenario,
  runAgentSession,
} from '../src/server/agent-session.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant, PublicAddress } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import {
  listModelProfiles,
  privateModelProfiles,
  recordProfileFailure,
  resolveProfilePoolForRole,
  saveModelProfile,
} from '../src/server/model-settings.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { orderProfiles, providerPool } from '../src/server/provider.ts'
import { redact, redactJsonValue } from '../src/server/redact.ts'
import { verifyReplaySpec, verifyReplaySpecInline } from '../src/server/replay-verifier.ts'
import { exportReportMarkdown } from '../src/server/report-export.ts'
import type { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { findings as findingsTable, messages as messagesTable } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

const exec = promisify(execFile)
const repoRootDir = new URL('..', import.meta.url).pathname
const publicAddr: PublicAddress = { address: '93.184.216.34', family: 4 }
const appOrigin = 'https://app.m1test.example'

async function httpFixture(handler: (req: IncomingMessage, res: ServerResponse) => void, host = '127.0.0.1') {
  const server = createServer(handler).listen(0, host)
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Fixture has no address.')
  return {
    port: address.port,
    url: `http://${host}:${address.port}`,
    close() {
      server.closeAllConnections()
      return new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

function makeGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    origin: appOrigin,
    tier: 2,
    maxRpsPerOrigin: 50,
    canRead: origin => origin === appOrigin,
    audit: () => {},
    ...overrides,
  }
}

function makeFixtureBroker(fixturePort: number, resolveHost = appOrigin): RequestBroker {
  const host = new URL(resolveHost).hostname
  return new RequestBroker({
    resolve: async h => (h === host ? [publicAddr] : []),
    transport: async (url, _addr, signal, opts) => {
      const target = `http://127.0.0.1:${fixturePort}${url.pathname}${url.search}`
      const res = await fetch(target, {
        method: opts?.method ?? 'GET',
        headers: opts?.headers,
        body: opts?.body,
        signal,
        redirect: 'manual',
      })
      const body = opts?.readBody === false ? '' : await res.text()
      return {
        status: res.status,
        headers: Object.fromEntries(res.headers),
        body,
        bodyBytes: Buffer.byteLength(body, 'utf8'),
        bodyTruncated: false,
      }
    },
  })
}

/** Genuine host-/bin/jq WorkerBackend for fast deterministic unit/execution tests (zero mocked assertions). */
function createJqBackend(onRun?: () => void): WorkerBackend {
  return {
    async run(job, signal) {
      onRun?.()
      const dir = mkdtempSync(join(tmpdir(), 'kovo-jq-unit-'))
      try {
        for (const f of job.files) {
          writeFileSync(join(dir, f.name.replace(/\//g, '_')), f.content, 'utf8')
        }
        const match = /^jq\s+'([\s\S]*)'\s+\/evidence\/replay-results\.json\s+>\s+\/work\/outcome\.json$/.exec(job.command.trim())
        if (!match) {
          return { exitCode: 1, stdout: '', stderr: `Unsupported command: ${job.command}`, outputs: {} as Record<string, string> }
        }
        const jqFilter = match[1].replaceAll("'\\''", "'")
        const inputPath = join(dir, 'replay-results.json')
        try {
          const { stdout, stderr } = await exec('jq', [jqFilter, inputPath], { signal, timeout: job.timeoutMs ?? 15_000 })
          return { exitCode: 0, stdout, stderr, outputs: { 'outcome.json': stdout } as Record<string, string> }
        } catch (err) {
          const e = err as { code?: number; stdout?: string; stderr?: string; message?: string }
          return {
            exitCode: typeof e.code === 'number' ? e.code : 2,
            stdout: e.stdout ?? '',
            stderr: e.stderr ?? e.message ?? 'jq failed',
            outputs: {} as Record<string, string>,
          }
        }
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    },
    async verifyStaticAst(_assignmentId, req) {
      const missing = req.ruleOrPattern.includes('MISSING_PATTERN')
      return {
        verified: !missing,
        engine: req.engine,
        repo: req.repo,
        file: req.file,
        startLine: req.startLine,
        endLine: req.endLine,
        matchedLines: missing ? [] : [req.startLine],
        codeExcerpt: '',
        matchCount: missing ? 0 : 1,
        durationMs: 1,
        reason: missing ? 'Pattern not matched' : undefined,
      }
    },
    async openSession() {
      return {
        async stage(name) { return `/evidence/${name}` },
        async exec() { return { exitCode: 0, stdout: '', stderr: '', outputs: {} as Record<string, string> } },
        async analyze() { return {} },
        async sast() {
          return { repo: 'repo', enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }
        },
        async runScript() {
          return { runtime: 'node', exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }
        },
        async verifyStaticAst(req) {
          return {
            verified: true,
            engine: req.engine,
            repo: req.repo,
            file: req.file,
            startLine: req.startLine,
            endLine: req.endLine,
            matchedLines: [req.startLine],
            codeExcerpt: '',
            matchCount: 1,
            durationMs: 1,
          }
        },
        async close() {},
      }
    },
  }
}

function replayBase(origin = appOrigin) {
  return {
    version: 1 as const,
    origin,
    title: 'M1 Test Finding',
    category: 'broken-access-control' as const,
    cwe: 'CWE-639',
    severity: 'high' as const,
    severityRationale: 'Deterministic replay proof without LLM judgment.',
    impact: 'Unauthorized access across tenant boundary.',
    remediation: 'Enforce strict tenant authorization check on handler.',
    recheckInstructions: 'Replay the control and probe steps.',
  }
}

function sseResponsesPayload(text: string, toolCalls: Array<{ name: string; args: Record<string, unknown> }> = []): string {
  const responseId = 'resp_' + randomUUID().slice(0, 12)
  const events: Record<string, unknown>[] = [
    { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } },
  ]
  const output: Record<string, unknown>[] = []
  let idx = 0

  if (text) {
    const msgId = 'msg_' + randomUUID().slice(0, 8)
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: msgId, type: 'message', status: 'in_progress', role: 'assistant', content: [] } },
      { type: 'response.output_text.delta', output_index: idx, item_id: msgId, content_index: 0, delta: text },
      { type: 'response.output_text.done', output_index: idx, item_id: msgId, content_index: 0, text },
      { type: 'response.output_item.done', output_index: idx, item: { id: msgId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] } },
    )
    output.push({ id: msgId, type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text }] })
    idx += 1
  }

  for (const call of toolCalls) {
    const fcId = 'fc_' + randomUUID().slice(0, 8)
    const callId = 'call_' + randomUUID().slice(0, 8)
    const serialized = JSON.stringify(call.args)
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: fcId, type: 'function_call', status: 'in_progress', call_id: callId, name: call.name, arguments: '' } },
      { type: 'response.function_call_arguments.delta', output_index: idx, item_id: fcId, delta: serialized },
      { type: 'response.function_call_arguments.done', output_index: idx, item_id: fcId, name: call.name, arguments: serialized },
      { type: 'response.output_item.done', output_index: idx, item: { id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized } },
    )
    output.push({ id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: call.name, arguments: serialized })
    idx += 1
  }

  events.push({
    type: 'response.completed',
    response: {
      id: responseId,
      status: 'completed',
      output,
      usage: { input_tokens: 180, output_tokens: 70, total_tokens: 250 },
    },
  })
  return events.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('') + 'data: [DONE]\n\n'
}

// ============================================================================
// 1. Lossless v2/v3 -> v4 Auto-Migration, Idempotency & 19 Store Methods
// ============================================================================

test('M1.1 Lossless v3->v4 (and v2->v4) SQLite auto-migration, idempotency, indexes, and all 19 Store methods', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m1-store-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  // A. If v2 smoke DB exists, verify lossless v2 -> v4 auto-migration on a temp copy
  const v2SmokeDb = join(repoRootDir, '.kovo', 'dyad-v2-smoke', 'data', 'kovo.sqlite')
  if (existsSync(v2SmokeDb)) {
    const v2CopyDir = join(dir, 'v2-copy')
    mkdirSync(v2CopyDir, { recursive: true })
    copyFileSync(v2SmokeDb, join(v2CopyDir, 'kovo.sqlite'))
    const migratedV2 = new Store(v2CopyDir)
    assert.ok(migratedV2.listWorkspace().projects.length > 0, 'v2->v4 migration must preserve existing projects')
    migratedV2.close()
  }

  // B. Construct an explicit pre-v4 (v3) SQLite DB (migrated through Drizzle + v3 schema, then stripped of v4 columns/tables)
  const v3Dir = join(dir, 'v3-migrated')
  mkdirSync(v3Dir, { recursive: true })
  const preStore = new Store(v3Dir)
  const now = Date.now()
  preStore.client.exec(`
    INSERT INTO model_profiles (id, workspace_id, name, endpoint, model, protocol, credential_id, updated_at)
      VALUES ('mp-1', '${preStore.workspace.id}', 'Legacy Profile', 'https://api.example/v1', 'm1', 'responses', 'cred-1', ${now});
    INSERT INTO projects (id, workspace_id, name, seeds, default_scope, created_at)
      VALUES ('proj-1', '${preStore.workspace.id}', 'Legacy Project', '["${appOrigin}"]', '[]', ${now});
    INSERT INTO runs (id, project_id, workspace_id, original_goal, goal, goal_revision, scope_revision, coordinator_id, phase, status, approved_persona_ids, candidates, approved, created_at)
      VALUES ('run-1', 'proj-1', '${preStore.workspace.id}', 'Audit', 'Audit', 1, 1, 'coord-1', 'investigation', 'running', '[]', '[]', '[]', ${now});
    INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at)
      VALUES ('assign-1', 'run-1', 'investigation', 'running', 1, 1, 'sess-1', '[]', '[]', 'Step', 'Obj', ${now});
    INSERT INTO chain_steps (id, run_id, goal_revision, scope_revision, seq, title, hypothesis, target_asset_ids, skills, depends_on_fact_ids, depends_on_step_ids, status, source_origins, created_at, updated_at)
      VALUES ('step-1', 'run-1', 1, 1, 1, 'Legacy step', 'Hyp', '[]', '[]', '[]', '[]', 'ready', '[]', ${now}, ${now});
    INSERT INTO replay_specs (id, run_id, finding_id, assignment_id, scope_revision, goal_revision, spec, spec_sha256, source_origins, created_at)
      VALUES ('spec-1', 'run-1', 'find-1', 'assign-1', 1, 1, '{"version":1,"kind":"http_chain"}', 'sha', '["${appOrigin}"]', ${now});
  `)
  preStore.close()

  const preDb = new DatabaseSync(join(v3Dir, 'kovo.sqlite'))
  for (const tbl of ['benchmark_runs', 'lab_telemetry', 'second_order_canaries', 'api_dependencies', 'endpoint_params', 'endpoints']) {
    preDb.exec(`DROP TABLE IF EXISTS ${tbl};`)
  }
  preDb.exec(`
    ALTER TABLE model_profiles DROP COLUMN role_affinity;
    ALTER TABLE projects DROP COLUMN sandbox_write_allowlist;
    ALTER TABLE runs DROP COLUMN dynamic_step_budget;
    ALTER TABLE runs DROP COLUMN multi_trial_enabled;
    ALTER TABLE runs DROP COLUMN phase0_completed_at;
    ALTER TABLE chain_steps DROP COLUMN specialist_profile;
    ALTER TABLE chain_steps DROP COLUMN trial_group_id;
    ALTER TABLE chain_steps DROP COLUMN trial_index;
    ALTER TABLE replay_specs DROP COLUMN attempt_count;
    ALTER TABLE replay_specs DROP COLUMN verified_inline;
    ALTER TABLE replay_specs DROP COLUMN last_verification_diff;
  `)
  preDb.close()

  // Open Store twice to verify idempotent initV4Schema()
  const store1 = new Store(v3Dir)
  store1.close()
  const storage = new Store(v3Dir)
  t.after(() => storage.close())

  // Check all 5 extended tables have v4 columns + preserved rows + defaults
  const colsOf = (table: string) =>
    new Set((storage.client.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map(r => r.name))

  assert.ok(colsOf('model_profiles').has('role_affinity'))
  assert.ok(colsOf('projects').has('sandbox_write_allowlist'))
  assert.ok(colsOf('runs').has('dynamic_step_budget'))
  assert.ok(colsOf('runs').has('multi_trial_enabled'))
  assert.ok(colsOf('runs').has('phase0_completed_at'))
  assert.ok(colsOf('chain_steps').has('specialist_profile'))
  assert.ok(colsOf('chain_steps').has('trial_group_id'))
  assert.ok(colsOf('chain_steps').has('trial_index'))
  assert.ok(colsOf('replay_specs').has('attempt_count'))
  assert.ok(colsOf('replay_specs').has('verified_inline'))
  assert.ok(colsOf('replay_specs').has('last_verification_diff'))

  const migratedMp = storage.client.prepare(`SELECT role_affinity FROM model_profiles WHERE id = 'mp-1'`).get() as { role_affinity: string }
  assert.equal(migratedMp.role_affinity, 'any')
  const migratedProj = storage.client.prepare(`SELECT sandbox_write_allowlist FROM projects WHERE id = 'proj-1'`).get() as { sandbox_write_allowlist: string }
  assert.equal(migratedProj.sandbox_write_allowlist, '[]')
  const migratedRun = storage.run('run-1')
  assert.equal(migratedRun.multiTrialEnabled, true)
  assert.equal(migratedRun.dynamicStepBudget, null)
  assert.equal(migratedRun.phase0CompletedAt, null)
  const migratedStep = storage.listChainSteps('run-1')[0]
  assert.equal(migratedStep.trialIndex, 0)
  assert.equal(migratedStep.specialistProfile, null)
  const migratedSpec = storage.getReplaySpec('run-1', 'spec-1')
  assert.equal(migratedSpec.attemptCount, 1)
  assert.equal(migratedSpec.verifiedInline, false)

  // Check all 6 new tables & unique index exist
  const tablesSet = new Set(
    (storage.client.prepare(`SELECT name FROM sqlite_master WHERE type='table'`).all() as Array<{ name: string }>).map(r => r.name),
  )
  for (const tbl of ['endpoints', 'endpoint_params', 'api_dependencies', 'second_order_canaries', 'lab_telemetry', 'benchmark_runs']) {
    assert.ok(tablesSet.has(tbl), `missing v4 table ${tbl}`)
  }
  const indexSet = new Set(
    (storage.client.prepare(`SELECT name FROM sqlite_master WHERE type='index'`).all() as Array<{ name: string }>).map(r => r.name),
  )
  assert.ok(indexSet.has('endpoints_run_route'))

  // Exercise all 19 Store CRUD/query helpers
  // 1-3: upsertEndpoint, listEndpoints, updateEndpointCoverage
  const ep1 = storage.upsertEndpoint({
    runId: 'run-1', scopeRevision: 1, origin: appOrigin, method: 'get', pathTemplate: '/api/orders/{orderId}',
    source: 'openapi', framework: 'nextjs', sinkKinds: ['db_query'], testedClasses: ['sqli_boolean'], riskScore: 70,
  })
  const ep1Upsert = storage.upsertEndpoint({
    runId: 'run-1', scopeRevision: 2, origin: appOrigin, method: 'GET', pathTemplate: '/api/orders/{orderId}',
    source: 'spa_crawl', authRequirement: 'bearer', sinkKinds: ['authz'], testedClasses: ['authz_matrix'], riskScore: 90,
  })
  assert.equal(ep1Upsert.id, ep1.id, 'unique (runId, origin, method, pathTemplate) must upsert in place')
  assert.deepEqual(ep1Upsert.sinkKinds.sort(), ['authz', 'db_query'])
  assert.deepEqual(ep1Upsert.testedClasses.sort(), ['authz_matrix', 'sqli_boolean'])
  assert.equal(ep1Upsert.riskScore, 90)
  assert.equal(ep1Upsert.framework, 'nextjs')
  assert.equal(ep1Upsert.authRequirement, 'bearer')

  const ep2 = storage.upsertEndpoint({
    runId: 'run-1', scopeRevision: 1, origin: appOrigin, method: 'POST', pathTemplate: '/api/orders',
    source: 'js_ast', riskScore: 65,
  })
  assert.equal(storage.listEndpoints('run-1', { untestedClass: 'authz_matrix' }).length, 1)
  assert.equal(storage.listEndpoints('run-1', { minRiskScore: 80 })[0].id, ep1.id)

  const ep1Cov = storage.updateEndpointCoverage(ep1.id, 87.5, ['xss_context'])
  assert.equal(ep1Cov.coveragePct, 87.5)
  assert.ok(ep1Cov.testedClasses.includes('xss_context'))

  // 4-5: upsertEndpointParam, listEndpointParams
  const p1 = storage.upsertEndpointParam({
    runId: 'run-1', endpointId: ep1.id, name: 'orderId', location: 'path', inferredType: 'uuid', isObjectId: true, source: 'openapi',
  })
  const p1Updated = storage.upsertEndpointParam({
    runId: 'run-1', endpointId: ep1.id, name: 'orderId', location: 'path', isCsrf: true, source: 'spa_crawl',
  })
  assert.equal(p1Updated.id, p1.id)
  assert.equal(p1Updated.isObjectId, true)
  assert.equal(p1Updated.isCsrf, true)
  assert.equal(storage.listEndpointParams('run-1', ep1.id).length, 1)

  // 6-8: recordApiDependency, listApiDependencies, markApiDependencyTestedBola
  const dep = storage.recordApiDependency({
    runId: 'run-1',
    producerEndpointId: ep2.id,
    consumerEndpointId: ep1.id,
    resourceKey: 'orderId',
    sampleResourceIdHash: 'Bearer secret-token-should-redact-1234',
    personaHandle: 'persona_a',
    observedTransitions: ['draft->paid'],
  })
  assert.ok(!dep.sampleResourceIdHash?.includes('secret-token-should-redact'))
  const dep2 = storage.recordApiDependency({
    runId: 'run-1',
    producerEndpointId: ep2.id,
    consumerEndpointId: ep1.id,
    resourceKey: 'orderId',
    observedTransitions: ['paid->refunded'],
  })
  assert.equal(dep2.id, dep.id)
  assert.deepEqual(dep2.observedTransitions.sort(), ['draft->paid', 'paid->refunded'])
  assert.equal(storage.listApiDependencies('run-1').length, 1)
  const testedDep = storage.markApiDependencyTestedBola(dep.id)
  assert.equal(testedDep.testedBola, true)

  // 9-11: insertSecondOrderCanary, markSecondOrderCanarySurfaced, listSecondOrderCanaries
  const canary = storage.insertSecondOrderCanary({
    runId: 'run-1', assignmentId: 'assign-1', marker: 'gn2o_deadbeef',
    injectedOrigin: appOrigin, injectedEndpoint: '/profile', injectedParam: 'bio', injectedPersona: 'persona_a',
  })
  assert.equal(canary.status, 'planted')
  const surfaced = storage.markSecondOrderCanarySurfaced(canary.id, {
    surfacedOrigin: appOrigin, surfacedEndpoint: '/admin/users', surfacedPersona: 'admin', surfacedExchangeId: 'ex-99',
  })
  assert.equal(surfaced.status, 'surfaced')
  assert.equal(storage.listSecondOrderCanaries('run-1', 'surfaced').length, 1)

  // 12-13: insertLabTelemetry, listLabTelemetry
  const tel = storage.insertLabTelemetry({
    runId: 'run-1',
    exchangeId: 'ex-1',
    traceId: 'trace-1',
    routesHit: ['/api/orders?token=Bearer super-secret-jwt-12345678'],
    newLinesCovered: 14,
    sinkEventsCount: 2,
    hasUnhandledException: true,
    artifactId: 'art-tel-1',
  })
  assert.ok(!JSON.stringify(tel.routesHit).includes('super-secret-jwt-12345678'))
  assert.equal(storage.listLabTelemetry('run-1').length, 1)

  // 14-16: insertBenchmarkRun, listBenchmarkRuns, getLatestBenchmarkRun
  storage.insertBenchmarkRun({
    suite: 'xben-25',
    gitSha: 'abc111',
    modelRoutingConfig: { reasoning: 'm1', apiKey: 'sk-ant-secret1234567890' },
    targetsTotal: 25,
    confirmedCount: 20,
    falsePositiveCount: 0,
    funnelCounts: { targetVulns: 25, surfaceDiscovered: 24, hypothesisFormed: 23, signalObserved: 22, specSubmitted: 21, zeroLlmConfirmed: 20 },
    failureTaxonomy: {
      surface_miss: 1, hypothesis_miss: 1, form_encoding_missing: 0, csrf_blocked: 0, context_reset: 0,
      tier_blocked: 0, trigger_miss: 1, jq_assertion_bug: 1, spa_catchall_fp: 0, replay_spec_miss: 1, budget_exhausted: 0,
    },
    totalCostUsd: 1.5,
    durationMs: 12_000,
  })
  const b2 = storage.insertBenchmarkRun({
    suite: 'xben-25',
    gitSha: 'abc222',
    targetsTotal: 25,
    confirmedCount: 23,
    falsePositiveCount: 0,
    funnelCounts: { targetVulns: 25, surfaceDiscovered: 25, hypothesisFormed: 24, signalObserved: 24, specSubmitted: 23, zeroLlmConfirmed: 23 },
    failureTaxonomy: {
      surface_miss: 0, hypothesis_miss: 1, form_encoding_missing: 0, csrf_blocked: 0, context_reset: 0,
      tier_blocked: 0, trigger_miss: 0, jq_assertion_bug: 0, spa_catchall_fp: 0, replay_spec_miss: 1, budget_exhausted: 0,
    },
  })
  assert.equal(storage.listBenchmarkRuns('xben-25', 10).length, 2)
  assert.equal(storage.getLatestBenchmarkRun('xben-25')?.id, b2.id)

  // 17-18: updateRunPhase0Completed, updateRunDynamicStepBudget
  const rP0 = storage.updateRunPhase0Completed('run-1', 1_700_000_000_000)
  assert.equal(rP0.phase0CompletedAt, 1_700_000_000_000)
  const rBudget = storage.updateRunDynamicStepBudget('run-1', 500)
  assert.equal(rBudget.dynamicStepBudget, 300, 'dynamicStepBudget must clamp to 300 ceiling')

  // 19: incrementReplaySpecAttempt with secret scrubbing
  const rawSecret = 'ULTRA_SECRET_COOKIE_TOKEN_VALUE_999'
  const feedback: InlineVerifyFeedback = {
    verdict: 'inconclusive',
    failedStepId: 'probe',
    controlPassed: true,
    jqError: `Cookie: sid=${rawSecret} failed`,
    assertionSummary: { observed: `Bearer ${rawSecret}`, expected: 'true' },
    stepStatuses: [{ id: 'probe', role: 'probe', status: 403, bodyLen: 12 }],
    retriesRemaining: 1,
  }
  const incSpec = storage.incrementReplaySpecAttempt('spec-1', feedback, {
    secrets: [{ value: rawSecret, placeholder: '[persona:a:secret]' }],
  })
  assert.equal(incSpec.attemptCount, 2)
  assert.equal(incSpec.verifiedInline, false)
  assert.ok(!JSON.stringify(incSpec.lastVerificationDiff).includes(rawSecret))
})

// ============================================================================
// 2. roleAffinity Tiered Model Routing & Thinking Defaults
// ============================================================================

test('M1.2 roleAffinity tiered routing: priority vs role precedence, single-profile & open-circuit fallback, and thinking defaults', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m1-routing-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  // Default roleAffinity when omitted from providerSettings
  const parsedDefault = providerSettings.parse({
    endpoint: 'https://api.example/v1',
    model: 'default-model',
    protocol: 'responses',
    key: 'sk-test-key-12345',
  })
  assert.equal(parsedDefault.roleAffinity, 'any')
  assert.equal(DEFAULT_PROVIDER.roleAffinity, 'any')

  // Single-profile fallback: 1 reasoning profile handles all roles
  const { id: reasoningId } = await saveModelProfile({
    name: 'Reasoning Only',
    endpoint: 'http://127.0.0.1:9001/v1',
    model: 'reason-1',
    protocol: 'messages',
    key: 'reason-key-12345',
    priority: 200,
    roleAffinity: 'reasoning',
  }, storage, { skipConnectionCheck: true })

  assert.equal(listModelProfiles(storage)[0].roleAffinity, 'reasoning')
  assert.equal(resolveProfilePoolForRole('fast', storage)[0].id, reasoningId)
  assert.equal(resolveProfilePoolForRole('tactical', storage)[0].id, reasoningId)
  assert.equal(resolveProfilePoolForRole('reasoning', storage)[0].id, reasoningId)

  // Multi-profile pool: reasoning (prio 200), any (prio 150), fast (prio 50)
  const hitLog: Array<{ target: string; headers: Record<string, string | string[] | undefined>; body: Record<string, unknown> }> = []
  let failFastWith500 = false

  const reasoningServer = await httpFixture(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(Buffer.from(c))
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>
    hitLog.push({ target: 'reasoning', headers: req.headers, body })
    res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
      'event: message_start\ndata: {"type":"message_start","message":{"id":"m1","type":"message","role":"assistant","content":[],"model":"reason-1","usage":{"input_tokens":10,"output_tokens":5}}}\n\n' +
      'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n' +
      'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok-reasoning"}}\n\n' +
      'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n' +
      'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":5}}\n\n' +
      'event: message_stop\ndata: {"type":"message_stop"}\n\n',
    )
  })
  t.after(() => reasoningServer.close())

  const anyServer = await httpFixture(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(Buffer.from(c))
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>
    hitLog.push({ target: 'any', headers: req.headers, body })
    res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sseResponsesPayload('ok-any'))
  })
  t.after(() => anyServer.close())

  const fastServer = await httpFixture(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(Buffer.from(c))
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>
    hitLog.push({ target: 'fast', headers: req.headers, body })
    if (failFastWith500) {
      res.writeHead(500, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: { message: 'boom' } }))
      return
    }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sseResponsesPayload('ok-fast'))
  })
  t.after(() => fastServer.close())

  // Update reasoning profile to point at reasoningServer
  await saveModelProfile({
    id: reasoningId,
    name: 'Reasoning Only',
    endpoint: reasoningServer.url,
    model: 'reason-1',
    protocol: 'messages',
    key: '',
    priority: 200,
    roleAffinity: 'reasoning',
  }, storage, { skipConnectionCheck: true })

  const { id: anyId } = await saveModelProfile({
    name: 'Any Fallback',
    endpoint: anyServer.url,
    model: 'any-1',
    protocol: 'responses',
    key: 'any-key-12345',
    priority: 150,
    roleAffinity: 'any',
  }, storage, { skipConnectionCheck: true })

  const { id: fastId } = await saveModelProfile({
    name: 'Fast Low Cost',
    endpoint: fastServer.url,
    model: 'fast-1',
    protocol: 'responses',
    key: 'fast-key-12345',
    priority: 50,
    roleAffinity: 'fast',
  }, storage, { skipConnectionCheck: true })

  // Verify resolveProfilePoolForRole('fast') excludes reasoning and puts fast before any (despite lower priority!)
  const fastPool = resolveProfilePoolForRole('fast', storage)
  assert.deepEqual(fastPool.map(p => p.id), [fastId, anyId])

  // Verify orderProfiles respects preferredRole over raw priority while preserving legacy priority when omitted
  const allProfiles = privateModelProfiles(storage)
  assert.deepEqual(orderProfiles(allProfiles, 1000).map(p => p.id), [reasoningId, anyId, fastId])
  assert.deepEqual(orderProfiles(allProfiles, 1000, 'fast').map(p => p.id), [fastId, anyId, reasoningId])

  // Verify providerPool with roleAffinity: 'fast' hits fast first (NOT any/reasoning), and fails over to any
  const { models, model } = providerPool(allProfiles, 'compactor', { roleAffinity: 'fast' })
  const s1 = models.stream(model, {
    systemPrompt: 'sys',
    messages: [{ role: 'user', content: 'hi', timestamp: Date.now() }],
    tools: [],
  })
  await s1.result()
  assert.equal(hitLog.at(-1)?.target, 'fast')

  failFastWith500 = true
  const s2 = models.stream(model, {
    systemPrompt: 'sys',
    messages: [{ role: 'user', content: 'hi', timestamp: Date.now() }],
    tools: [],
  })
  await s2.result()
  assert.equal(hitLog.at(-1)?.target, 'any', 'must failover from fast to any, never hitting reasoning')

  // Verify scenario role & thinking defaults (reasoning -> high effort on Anthropic messages)
  assert.equal(roleAffinityForScenario('code-auditor'), 'reasoning')
  assert.equal(roleAffinityForScenario('cross-host-synthesizer'), 'reasoning')
  assert.equal(roleAffinityForScenario('patch-author'), 'reasoning')
  assert.equal(roleAffinityForScenario('patch-reviewer'), 'reasoning')
  assert.equal(roleAffinityForScenario('worker-investigation'), 'tactical')
  assert.equal(roleAffinityForScenario('chain-planner'), 'tactical')
  assert.equal(roleAffinityForScenario('compactor'), 'fast')
  assert.equal(defaultThinkingForRole('reasoning', 'medium'), 'high')
  assert.equal(defaultThinkingForRole('reasoning', 'off'), 'off')
  assert.equal(defaultThinkingForRole('tactical', 'medium'), 'medium')
  assert.equal(defaultThinkingForRole('fast', 'medium'), 'low')

  const hitCountBeforeCodeAudit = hitLog.length
  const sessionRes = await runAgentSession({
    directory: dir,
    sessionId: 'route-reason-test',
    requestId: randomUUID(),
    profiles: allProfiles,
    scenario: 'code-auditor',
    prompt: 'Analyze repo.',
    signal: AbortSignal.timeout(10_000),
    maxTurns: 1,
    requireCompleteIntent: false,
  })
  assert.equal(sessionRes.answer, 'ok-reasoning')
  assert.equal(hitLog[hitCountBeforeCodeAudit].target, 'reasoning')
  const sentBody = hitLog[hitCountBeforeCodeAudit].body as { output_config?: { effort?: string }; thinking?: unknown }
  assert.ok(sentBody.thinking, 'reasoning scenario must enable Anthropic thinking')
  if (sentBody.output_config) {
    assert.equal(sentBody.output_config.effort, 'high')
  }

  // Open-circuit cross-role fallback: if fast & any are both open in cooldown, fall back to healthy reasoning first
  recordProfileFailure(fastId, '401 invalid', true, storage)
  recordProfileFailure(anyId, '402 quota', true, storage)
  const fallbackPool = resolveProfilePoolForRole('fast', storage)
  assert.ok(fallbackPool.some(p => p.id === reasoningId), 'healthy cross-role fallback must be included when all primary profiles are open')
  assert.equal(fallbackPool[0]?.id, reasoningId, 'healthy cross-role fallback must come BEFORE open-tripped profiles')
  // Keep unused ResolvedModelProfile import type-referenced cleanly
  const _: ResolvedModelProfile[] = fallbackPool
  assert.ok(_.length >= 1)
})

// ============================================================================
// 3. browser_chain Optional pathAndQuery After Step 1
// ============================================================================

test('M1.3 browser_chain optional pathAndQuery after step 1 enforces session-continuity rules cleanly', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m1-bchain-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())
  const base = {
    ...replayBase(),
    kind: 'browser_chain' as const,
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
  }

  // Step 1 omitting pathAndQuery must fail
  const step1Missing = browserChainReplaySpecSchema.safeParse({
    ...base,
    steps: [
      { id: 'c1', role: 'control', description: 'Control step', origin: appOrigin },
      { id: 'p1', role: 'probe', description: 'Probe step', origin: appOrigin, pathAndQuery: '/probe' },
    ],
  })
  assert.equal(step1Missing.success, false)

  // Step 2 omitting pathAndQuery with same origin + persona + role (e.g. control->control or probe->probe or setup->probe) passes
  const validReuse = browserChainReplaySpecSchema.safeParse({
    ...base,
    steps: [
      { id: 'c1', role: 'control', description: 'Control page', origin: appOrigin, pathAndQuery: '/login', persona: 'user_a' },
      { id: 's1', role: 'probe', description: 'Navigate to form', origin: appOrigin, pathAndQuery: '/form', persona: 'user_a', action: 'navigate' },
      { id: 's2', role: 'probe', description: 'Fill input in live DOM', origin: appOrigin, persona: 'user_a', action: 'fill', selector: '#name', value: 'alice', reusePage: true },
      { id: 's3', role: 'probe', description: 'Click submit', origin: appOrigin, persona: 'user_a', action: 'click', selector: '#submit' },
    ],
  })
  assert.equal(validReuse.success, true)

  // Report markdown export must handle optional pathAndQuery safely
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'P', seeds: [appOrigin], environment: 'public',
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'g', sourceMode: 'public',
    capabilityTier: 2, budgetUsd: 10, budgetRequests: 100, maxRpsPerOrigin: 5, workerConcurrency: 2, workerMaxTurns: 20,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })
  const run = storage.run(runId)
  const w = storage.makeWorker(run, 'investigation', asset, 'T', 'O')
  const ev = storage.addArtifact(run, w, 'replay', 'Spec', '{}')
  const fId = randomUUID()
  const specRow = storage.createReplaySpec(run, w, fId, validReuse.data as DeclarativeReplaySpec, [appOrigin])
  storage.upsertChainFinding(run, asset.id, {
    id: fId, origin: appOrigin, title: 'XSS', status: 'confirmed', severity: 'high',
    reason: 'DOM sink triggered', remediation: 'Escape', evidenceIds: [ev.id], scopeRevision: run.scopeRevision,
    findingKind: 'multi_step_chain', replaySpecId: specRow.id,
  }, specRow.id, [appOrigin])
  const reportId = storage.writeReport(storage.run(runId), false)
  const { content: markdown } = exportReportMarkdown(storage, runId, reportId)
  assert.ok(markdown.includes('reusePage'))

  // Crossing control -> probe boundary without pathAndQuery fails
  const crossControlProbe = browserChainReplaySpecSchema.safeParse({
    ...base,
    steps: [
      { id: 'c1', role: 'control', description: 'Control', origin: appOrigin, pathAndQuery: '/app' },
      { id: 'p1', role: 'probe', description: 'Probe missing path', origin: appOrigin, action: 'click', selector: '#btn' },
    ],
  })
  assert.equal(crossControlProbe.success, false)

  // Different persona without pathAndQuery fails
  const diffPersona = browserChainReplaySpecSchema.safeParse({
    ...base,
    steps: [
      { id: 'c1', role: 'control', description: 'Control', origin: appOrigin, pathAndQuery: '/app' },
      { id: 'p1', role: 'probe', description: 'Probe', origin: appOrigin, pathAndQuery: '/app', persona: 'user_a' },
      { id: 'p2', role: 'probe', description: 'Probe 2', origin: appOrigin, persona: 'user_b', action: 'click', selector: '#btn' },
    ],
  })
  assert.equal(diffPersona.success, false)

  // Different origin without pathAndQuery fails
  const diffOrigin = browserChainReplaySpecSchema.safeParse({
    ...base,
    steps: [
      { id: 'c1', role: 'control', description: 'Control', origin: appOrigin, pathAndQuery: '/app' },
      { id: 'p1', role: 'probe', description: 'Probe', origin: appOrigin, pathAndQuery: '/app' },
      { id: 'p2', role: 'probe', description: 'Probe 2', origin: 'https://other.m1test.example', action: 'click', selector: '#btn' },
    ],
  })
  assert.equal(diffOrigin.success, false)

  // resetContext: true or reusePage: false without pathAndQuery fails
  const resetTrue = browserChainReplaySpecSchema.safeParse({
    ...base,
    steps: [
      { id: 'c1', role: 'control', description: 'Control', origin: appOrigin, pathAndQuery: '/app' },
      { id: 'p1', role: 'probe', description: 'Probe', origin: appOrigin, pathAndQuery: '/app' },
      { id: 'p2', role: 'probe', description: 'Probe 2', origin: appOrigin, resetContext: true, action: 'click', selector: '#btn' },
    ],
  })
  assert.equal(resetTrue.success, false)

  const reuseFalse = browserChainReplaySpecSchema.safeParse({
    ...base,
    steps: [
      { id: 'c1', role: 'control', description: 'Control', origin: appOrigin, pathAndQuery: '/app' },
      { id: 'p1', role: 'probe', description: 'Probe', origin: appOrigin, pathAndQuery: '/app' },
      { id: 'p2', role: 'probe', description: 'Probe 2', origin: appOrigin, reusePage: false, action: 'click', selector: '#btn' },
    ],
  })
  assert.equal(reuseFalse.success, false)
})

// ============================================================================
// 4. verifyReplaySpecInline Diagnostics, Redaction, Retry Cap & Zero-LLM Lock
// ============================================================================

test('M1.4 verifyReplaySpecInline diagnostics (jqError, requireControlNonError, SPA catchall, canaryTriggered), secret redaction, 3-attempt cap & static_ast_proof tier lock', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m1-inline-diag-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const bearerSecret = 'PERSONA_A_RAW_BEARER_SECRET_XYZ123'
  const cookieSecret = 'SESSION_COOKIE_RAW_SECRET_ABC789'

  const fx = await httpFixture((req, res) => {
    if (req.url?.startsWith('/control-ok')) {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }))
      return
    }
    if (req.url?.startsWith('/missing')) {
      res.writeHead(404, { 'Content-Type': 'text/plain' }).end(`missing Cookie: sid=${cookieSecret}`)
      return
    }
    if (req.url?.startsWith('/spa') || req.url?.startsWith('/.kovo-nonexistent-')) {
      const html = '<!doctype html><html><head><title>App</title></head><body><div id="root">Welcome to the SPA shell application dashboard content</div></body></html>'
      res.writeHead(200, { 'Content-Type': 'text/html' }).end(html)
      return
    }
    if (req.url?.startsWith('/echo-secret')) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': `sid=${cookieSecret}` }).end(
        JSON.stringify({ auth: `Bearer ${bearerSecret}`, cookie: cookieSecret }),
      )
      return
    }
    if (req.url?.startsWith('/oob-rce')) {
      const u = new URL(req.url, 'http://127.0.0.1')
      const cb = u.searchParams.get('cb')
      if (cb && cb.startsWith('http://127.0.0.1:')) {
        void fetch(cb).catch(() => undefined)
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' }).end('dispatched')
      return
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' }).end('ok')
  })
  t.after(() => fx.close())

  const broker = makeFixtureBroker(fx.port)
  let backendCalls = 0
  const backend = createJqBackend(() => { backendCalls += 1 })
  const personaMap = new Map<string, ResolvedPersona>([
    ['user_a', {
      id: 'p-a', handle: 'user_a', roleLabel: 'Member', originAllowlist: [appOrigin],
      authKind: 'bearer', headerName: null, secret: bearerSecret, canaryMarkers: [],
    }],
  ])
  const grant = makeGrant({
    tier: 3,
    personas: personaMap,
    secrets: [{ value: cookieSecret, placeholder: '[redacted-cookie]' }],
    isStateChangeApproved: () => true,
  })

  // A. jqError diagnostic + secret scrubbing
  const badJqSpec = {
    ...replayBase(),
    kind: 'http_chain' as const,
    steps: [
      { id: 'c1', role: 'control' as const, description: 'Control', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/control-ok', persona: 'user_a' } },
      { id: 'p1', role: 'probe' as const, description: 'Probe', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/echo-secret', persona: 'user_a' } },
    ],
    assertionsJq: 'invalid jq syntax (((',
  }
  const jqRes = await verifyReplaySpecInline({
    spec: badJqSpec, broker, backend, grant, signal: AbortSignal.timeout(10_000), attemptCount: 1,
  })
  assert.equal(jqRes.feedback.verdict, 'inconclusive')
  assert.ok(jqRes.feedback.jqError && jqRes.feedback.jqError.includes('jq'))
  assert.equal(jqRes.feedback.retriesRemaining, 2)
  assert.equal(jqRes.feedback.stepStatuses.length, 2)
  assert.ok(!JSON.stringify(jqRes.feedback).includes(bearerSecret))
  assert.ok(!JSON.stringify(jqRes.feedback).includes(cookieSecret))

  // B. requireControlNonErrorTriggered + failedStepId on unexpected 404
  const reqNonErrRes = await verifyReplaySpecInline({
    spec: {
      ...replayBase(),
      kind: 'http_chain' as const,
      requireControlNonError: true,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'Control 404', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/missing' } },
        { id: 'p1', role: 'probe' as const, description: 'Probe', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/control-ok' } },
      ],
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    },
    broker, backend, grant, signal: AbortSignal.timeout(10_000), attemptCount: 1,
  })
  assert.equal(reqNonErrRes.feedback.verdict, 'inconclusive')
  assert.equal(reqNonErrRes.feedback.requireControlNonErrorTriggered, true)
  assert.equal(reqNonErrRes.feedback.failedStepId, 'c1')
  assert.ok(!JSON.stringify(reqNonErrRes.feedback).includes(cookieSecret))

  // C. spaCatchallMatched + spaSimilarityScore >= 0.85
  const spaRes = await verifyReplaySpecInline({
    spec: {
      ...replayBase(),
      kind: 'http_chain' as const,
      spaCatchallControl: true,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'Control', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/control-ok' } },
        { id: 'p1', role: 'probe' as const, description: 'Probe SPA', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/spa/admin' } },
      ],
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    },
    broker, backend, grant, signal: AbortSignal.timeout(10_000), attemptCount: 1,
  })
  assert.equal(spaRes.feedback.verdict, 'inconclusive')
  assert.equal(spaRes.feedback.spaCatchallMatched, true)
  assert.ok((spaRes.feedback.spaSimilarityScore ?? 0) >= 0.85)

  // D. canaryTriggered for rce_proof oob_canary
  const canaryRes = await verifyReplaySpecInline({
    spec: {
      ...replayBase(),
      kind: 'rce_proof' as const,
      proofMode: 'oob_canary' as const,
      requiresTier3Approval: true as const,
      controlStep: { id: 'c1', role: 'control' as const, description: 'Control', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/control-ok' } },
      probeStep: { id: 'p1', role: 'probe' as const, description: 'Probe OOB', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/oob-rce?cb={{canary_url}}' } },
      assertionsJq: '{ controlPassed: (.control.status == 200), confirmed: (.proof.cryptographicProofPassed == true), observed: "oob", expected: "oob" }',
    },
    broker, backend, grant, signal: AbortSignal.timeout(10_000), attemptCount: 1,
  })
  assert.equal(canaryRes.feedback.verdict, 'confirmed')
  assert.equal(canaryRes.feedback.canaryTriggered, true)

  // E. Retry cap enforcement: attemptCount > 1 + maxInlineVerifyRetries (4 > 3) does NOT invoke broker/backend
  const callsBeforeLimit = backendCalls
  const limitRes = await verifyReplaySpecInline({
    spec: badJqSpec, broker, backend, grant, signal: AbortSignal.timeout(5_000),
    attemptCount: 1 + maxInlineVerifyRetries + 1,
  })
  assert.equal(backendCalls, callsBeforeLimit, 'must not execute backend once retry limit is exceeded')
  assert.equal(limitRes.feedback.verdict, 'inconclusive')
  assert.equal(limitRes.feedback.retriesRemaining, 0)

  // F. static_ast_proof stays strictly static_verified (NEVER confirmed)
  const staticRes = await verifyReplaySpecInline({
    spec: {
      ...replayBase(),
      kind: 'static_ast_proof' as const,
      repo: 'acme/app',
      file: 'src/handler.ts',
      startLine: 10,
      endLine: 20,
      engine: 'opengrep' as const,
      ruleOrPattern: 'db.query(req.body)',
      runtimeProofGap: 'No live lab container configured.',
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ast matched", expected: "ast matched" }',
    },
    broker, backend, grant, reposDir: dir, signal: AbortSignal.timeout(10_000), attemptCount: 1,
  })
  assert.equal(staticRes.feedback.verdict, 'static_verified')
  assert.equal(staticRes.feedback.verificationTier, 'static_verified')
})

// ============================================================================
// 5. Worker Inline Repair Loop & Bounded 1x 8-Turn Phase-3 Refinement Turn
// ============================================================================

test('M1.5 Worker inline repair loop: propose_chain_finding(verifyNow=true) -> jqError feedback -> verify_replay_spec -> confirmed (and static_ast_proof stays static_verified)', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m1-inline-loop-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const targetFx = await httpFixture((req, res) => {
    if (req.url === '/public') {
      res.writeHead(401, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'unauthorized' }))
      return
    }
    if (req.url === '/admin/leak') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ leaked: true, users: 42 }))
      return
    }
    res.writeHead(404).end('not found')
  })
  t.after(() => targetFx.close())

  const turnsByPrompt = new Map<string, number>()
  const observedFeedbacks: Array<Record<string, unknown>> = []
  let targetStepId = ''
  const llmServer = await httpFixture(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(Buffer.from(c))
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
      input?: Array<{ type?: string; role?: string; content?: unknown; output?: string }>
      tools?: unknown[]
    }
    const toolsStr = JSON.stringify(body.tools ?? [])
    const isInvestigationWorker = toolsStr.includes('verify_replay_spec')
    if (!isInvestigationWorker) {
      if (toolsStr.includes('complete_intent')) {
        res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
          sseResponsesPayload('', [{ name: 'complete_intent', args: { status: 'ruled_out', summary: 'skip non-worker' } }]),
        )
        return
      }
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
        sseResponsesPayload(JSON.stringify({ summary: 'done', newSteps: [], cancelStepIds: [], done: true })),
      )
      return
    }

    const promptKey = JSON.stringify(body.input?.[1] ?? body.input?.[0] ?? '')
    if (!targetStepId || !promptKey.includes(targetStepId)) {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
        sseResponsesPayload('', [{ name: 'complete_intent', args: { status: 'ruled_out', summary: 'skip auto-seeded step' } }]),
      )
      return
    }
    const workerTurnIdx = (turnsByPrompt.get(targetStepId) ?? 0) + 1
    turnsByPrompt.set(targetStepId, workerTurnIdx)

    let latestFindingId: string | undefined
    for (const item of body.input ?? []) {
      if (item.type === 'function_call_output' && typeof item.output === 'string') {
        try {
          const parsedOut = JSON.parse(item.output) as { findingId?: string; inlineVerifyFeedback?: Record<string, unknown> }
          if (parsedOut.findingId) latestFindingId = parsedOut.findingId
          if (parsedOut.inlineVerifyFeedback) observedFeedbacks.push(parsedOut.inlineVerifyFeedback)
        } catch { /* ignore */ }
      }
    }

    const baseHttpSpec = {
      ...replayBase(),
      kind: 'http_chain',
      steps: [
        { id: 'c1', role: 'control', description: 'Control unauth', expectedStatus: 401, request: { origin: appOrigin, method: 'GET', pathAndQuery: '/public' } },
        { id: 'p1', role: 'probe', description: 'Probe leak', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/admin/leak' } },
      ],
    }

    let sse = ''
    if (workerTurnIdx === 1) {
      // Turn 1: broken assertionsJq -> triggers inline verification failure feedback
      sse = sseResponsesPayload('', [{
        name: 'propose_chain_finding',
        args: {
          replaySpec: { ...baseHttpSpec, assertionsJq: 'broken jq (((' },
          counterevidence: 'Route might require session cookie in production.',
          confidenceRationale: 'Directly observed 200 JSON response with leaked users.',
          verifyNow: true,
        },
      }])
    } else if (workerTurnIdx === 2) {
      sse = sseResponsesPayload('', [{
        name: 'verify_replay_spec',
        args: {
          findingId: latestFindingId,
          spec: {
            ...baseHttpSpec,
            assertionsJq: '{ controlPassed: (.steps.c1.status == 401), confirmed: (.steps.p1.status == 200 and .steps.p1.json.leaked == true), observed: "leaked=true", expected: "401" }',
          },
        },
      }])
    } else if (workerTurnIdx === 3) {
      // Also submit static_ast_proof with verifyNow=true -> must stay strictly static_verified
      sse = sseResponsesPayload('', [{
        name: 'propose_chain_finding',
        args: {
          replaySpec: {
            ...replayBase(),
            title: 'Static AST Finding',
            cwe: 'CWE-89',
            kind: 'static_ast_proof',
            repo: 'acme/app',
            file: 'src/db.ts',
            startLine: 5,
            endLine: 12,
            engine: 'opengrep',
            ruleOrPattern: 'sql.raw(input)',
            runtimeProofGap: 'No live route mapped.',
            assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ast", expected: "ast" }',
          },
          counterevidence: 'Input might be validated in upstream middleware.',
          confidenceRationale: 'Opengrep matched raw SQL interpolation directly.',
          verifyNow: true,
        },
      }])
    } else {
      sse = sseResponsesPayload('', [{
        name: 'complete_intent',
        args: { status: 'proved', summary: 'Repaired inline spec and verified finding.' },
      }])
    }

    res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sse)
  })
  t.after(() => llmServer.close())

  await saveModelProfile({
    name: 'M1 Test LLM',
    endpoint: llmServer.url,
    model: 'm1-test-model',
    protocol: 'responses',
    key: 'm1-test-key-12345',
    priority: 100,
  }, storage, { skipConnectionCheck: true })

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Inline Repair Proj', seeds: [appOrigin], environment: 'public',
  })
  const reposDir = join(dir, 'repos', projectId, 'acme', 'app', 'src')
  mkdirSync(reposDir, { recursive: true })
  writeFileSync(join(reposDir, 'db.ts'), 'export function q(input: string) { return sql.raw(input) }\n')

  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Test inline repair', sourceMode: 'public',
    capabilityTier: 2, budgetUsd: 5, budgetRequests: 100, maxRpsPerOrigin: 30, workerConcurrency: 2, workerMaxTurns: 10,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })
  const run = storage.run(runId)
  const step = storage.addChainStep(run, {
    title: 'Check admin leak', hypothesis: 'GET /admin/leak bypasses auth', targetAssetIds: [asset.id], sourceOrigins: [appOrigin],
  })
  targetStepId = step.id

  const execution = new Execution(storage, {
    broker: makeFixtureBroker(targetFx.port),
    backend: createJqBackend(),
  })
  t.after(() => execution.stop())
  execution.start()

  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    const r = storage.run(runId)
    if (r.phase === 'complete' || r.status === 'complete' || r.status === 'failed') break
    await delay(100)
  }
  await execution.stop()

  assert.ok(observedFeedbacks.length >= 1, 'LLM must receive InlineVerifyFeedback after broken propose_chain_finding')
  assert.equal(observedFeedbacks[0].verdict, 'inconclusive', `feedbacks=${JSON.stringify(observedFeedbacks)}`)
  assert.ok(typeof observedFeedbacks[0].jqError === 'string')

  const detail = storage.runDetail(runId)
  const httpFinding = detail.findings.find(f => f.title === 'M1 Test Finding')
  assert.ok(httpFinding, 'HTTP chain finding must exist')
  assert.equal(httpFinding.status, 'confirmed', `Expected confirmed, got ${httpFinding.status}; feedbacks=${JSON.stringify(observedFeedbacks)}; reason=${httpFinding.reason}`)
  assert.equal(httpFinding.verificationTier, 'runtime_confirmed')

  const specRow = storage.getReplaySpec(runId, httpFinding.replaySpecId!)
  assert.equal(specRow.attemptCount, 2)
  assert.equal(specRow.verifiedInline, true)

  const staticFinding = detail.findings.find(f => f.title === 'Static AST Finding')
  assert.ok(staticFinding, 'static_ast_proof finding must exist')
  assert.equal(staticFinding.status, 'static_verified')
  assert.equal(staticFinding.verificationTier, 'static_verified')
  assert.equal(step.id.length > 0, true)
})

test('M1.6 Phase-3 Focused Refinement Turn: positive 8-turn repair confirms AND negative closure stays unconfirmed with max 1 refinement worker', async t => {
  for (const mode of ['positive', 'negative'] as const) {
    const dir = mkdtempSync(join(tmpdir(), `kovo-m1-refine-${mode}-`))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const storage = new Store(dir)
    t.after(() => storage.close())

    const targetFx = await httpFixture((req, res) => {
      if (req.url === '/control') {
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ admin: false }))
        return
      }
      if (req.url === '/probe') {
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(
          JSON.stringify(mode === 'positive' ? { admin: true } : { admin: false }),
        )
        return
      }
      res.writeHead(404).end('not found')
    })
    t.after(() => targetFx.close())

    let llmCalls = 0
    const llmServer = await httpFixture(async (req, res) => {
      const chunks: Buffer[] = []
      for await (const c of req) chunks.push(Buffer.from(c))
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { model?: string; input?: Array<Record<string, unknown>> }
      const serialized = JSON.stringify(body.input ?? [])
      llmCalls += 1
      assert.equal(body.model, 'reason-model', 'Phase-3 refinement must route to reasoning profile')

      let sse = ''
      if (llmCalls === 1) {
        if (mode === 'positive') {
          sse = sseResponsesPayload('', [{
            name: 'verify_replay_spec',
            args: {
              spec: {
                ...replayBase(),
                kind: 'http_chain',
                steps: [
                  { id: 'c1', role: 'control', description: 'Control', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/control' } },
                  { id: 'p1', role: 'probe', description: 'Probe', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/probe' } },
                ],
                assertionsJq: '{ controlPassed: (.steps.c1.json.admin == false), confirmed: (.steps.p1.json.admin == true), observed: "admin=true", expected: "admin=false" }',
              },
            },
          }])
        } else {
          // Negative mode: try verifying, still returns dismissed (admin == false), do NOT confirm
          sse = sseResponsesPayload('', [{
            name: 'verify_replay_spec',
            args: {
              spec: {
                ...replayBase(),
                kind: 'http_chain',
                steps: [
                  { id: 'c1', role: 'control', description: 'Control', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/control' } },
                  { id: 'p1', role: 'probe', description: 'Probe', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/probe' } },
                ],
                assertionsJq: '{ controlPassed: (.steps.c1.json.admin == false), confirmed: (.steps.p1.json.admin == true), observed: "admin=false", expected: "admin=true" }',
              },
            },
          }])
        }
      } else {
        assert.ok(serialized.includes('inlineVerifyFeedback') || llmCalls > 1)
        sse = sseResponsesPayload('', [{
          name: 'complete_intent',
          args: { status: mode === 'positive' ? 'proved' : 'ruled_out', summary: `Refinement ${mode} complete.` },
        }])
      }
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sse)
    })
    t.after(() => llmServer.close())

    await saveModelProfile({
      name: 'Tactical Profile',
      endpoint: llmServer.url,
      model: 'tactical-model',
      protocol: 'responses',
      key: 'tactical-key-12345',
      priority: 200,
      roleAffinity: 'tactical',
    }, storage, { skipConnectionCheck: true })

    await saveModelProfile({
      name: 'Reasoning Profile',
      endpoint: llmServer.url,
      model: 'reason-model',
      protocol: 'responses',
      key: 'reason-key-12345',
      priority: 50,
      roleAffinity: 'reasoning',
    }, storage, { skipConnectionCheck: true })

    const { id: projectId } = storage.createProject({
      requestId: randomUUID(), name: `Refine ${mode}`, seeds: [appOrigin], environment: 'public',
    })
    const { id: runId } = storage.createRun({
      requestId: randomUUID(), projectId, goal: `Phase-3 refinement ${mode}`, sourceMode: 'public',
      capabilityTier: 2, budgetUsd: 5, budgetRequests: 100, maxRpsPerOrigin: 30, workerConcurrency: 2, workerMaxTurns: 20,
    })
    storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
    const asset = storage.run(runId).candidates[0]
    storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })

    // Seed a pending finding with a failing replay_specs row (attemptCount: 1) and transition directly to verification
    const run = storage.run(runId)
    const invWorker = storage.makeWorker(run, 'investigation', asset, 'Seeded', 'Seeded')
    storage.updateWorker(invWorker.id, { status: 'complete' })
    const findingId = randomUUID()
    const failingSpec: DeclarativeReplaySpec = {
      ...replayBase(),
      kind: 'http_chain',
      spaCatchallControl: false,
      steps: [
        { id: 'c1', role: 'control', description: 'Control', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/control', followRedirects: false } },
        { id: 'p1', role: 'probe', description: 'Probe', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/probe', followRedirects: false } },
      ],
      assertionsJq: 'broken jq ((',
    }
    const specRow = storage.createReplaySpec(run, invWorker, findingId, failingSpec, [appOrigin], { initialAttemptCount: 1 })
    const seededFinding: Finding = {
      id: findingId,
      origin: appOrigin,
      title: failingSpec.title,
      status: 'pending',
      severity: 'high',
      reason: 'Seeded pending finding',
      remediation: failingSpec.remediation,
      category: failingSpec.category,
      cwe: failingSpec.cwe,
      findingKind: 'multi_step_chain',
      replaySpecId: specRow.id,
      evidenceIds: [],
      scopeRevision: run.scopeRevision,
    }
    storage.upsertChainFinding(run, asset.id, seededFinding, specRow.id, [appOrigin])
    // Also mark baseline verify complete so driveVerification finishes promptly after replay + refinement
    const baseWorker = storage.makeWorker(run, 'verification', asset, 'Baseline', 'Baseline')
    storage.updateWorker(baseWorker.id, { status: 'complete' })
    storage.updateRun(runId, { phase: 'verification', status: 'running' })

    const execution = new Execution(storage, {
      broker: makeFixtureBroker(targetFx.port),
      backend: createJqBackend(),
    })
    t.after(() => execution.stop())
    execution.start()

    const deadline = Date.now() + 20_000
    while (Date.now() < deadline) {
      const r = storage.run(runId)
      if (r.phase === 'complete' || r.status === 'complete' || r.status === 'failed') break
      await delay(100)
    }
    await execution.stop()

    const workers = storage.workerList(runId)
    const refineWorkers = workers.filter(w => w.stepId === `refine:${specRow.id}`)
    assert.equal(refineWorkers.length, 1, 'must spawn at most 1 Phase-3 refinement worker per spec')
    assert.equal(refineWorkers[0].maxTurns, 8)
    assert.equal(refineWorkers[0].status, 'complete')

    const finalFindingRow = storage.db.select().from(findingsTable).where(eq(findingsTable.id, findingId)).get()
    assert.ok(finalFindingRow)
    if (mode === 'positive') {
      assert.equal(finalFindingRow.finding.status, 'confirmed')
      assert.equal(finalFindingRow.verificationTier, 'runtime_confirmed')
    } else {
      assert.notEqual(finalFindingRow.finding.status, 'confirmed')
      assert.equal(finalFindingRow.finding.status, 'dismissed')
      const cov = storage.listCoverageEntries(runId, run.goalRevision).find(c => c.origin === appOrigin && c.category === 'broken-access-control')
      assert.ok(cov && (cov.status === 'ruled_out' || cov.status === 'needs_follow_up'), 'negative refinement must close coverage deterministically')
    }
  }
})

test('M1.7 Real --network none LinuxWorkerBackend end-to-end verification with verifyReplaySpecInline', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m1-docker-inline-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const fx = await httpFixture((req, res) => {
    if (req.url === '/c') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ role: 'user' }))
      return
    }
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ role: 'admin' }))
  })
  t.after(() => fx.close())

  const broker = makeFixtureBroker(fx.port)
  const backend = new LinuxWorkerBackend({ workspace: { id: 'm1-docker-ws', directory: dir } })
  const res = await verifyReplaySpecInline({
    spec: {
      ...replayBase(),
      kind: 'http_chain',
      steps: [
        { id: 'c1', role: 'control', description: 'Control', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/c' } },
        { id: 'p1', role: 'probe', description: 'Probe', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/p' } },
      ],
      assertionsJq: '{ controlPassed: (.steps.c1.json.role == "user"), confirmed: (.steps.p1.json.role == "admin"), observed: .steps.p1.json.role, expected: "user" }',
    },
    broker,
    backend,
    grant: makeGrant(),
    signal: AbortSignal.timeout(30_000),
    attemptCount: 1,
  })
  assert.equal(res.feedback.verdict, 'confirmed')
  assert.equal(res.feedback.verificationTier, 'runtime_confirmed')
  assert.equal(res.feedback.retriesRemaining, 2)
})

// ============================================================================
// 8. Iteration 2 Regression Tests (Challenger 1, Challenger 2, Reviewer 2)
// ============================================================================

test('M1.8 Regression: openai-responses reasoningEffort wire forwarding & open-circuit healthy primarySettings', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m1-reg-routing-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const capturedBodies: Array<Record<string, unknown>> = []
  const llmServer = await httpFixture(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(Buffer.from(c))
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>
    capturedBodies.push(body)
    if (req.url?.includes('/v1/messages')) {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
        'event: message_start\ndata: {"type":"message_start","message":{"id":"m1","type":"message","role":"assistant","content":[],"model":"reason-healthy","usage":{"input_tokens":10,"output_tokens":5}}}\n\n' +
        'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n' +
        'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok-msg"}}\n\n' +
        'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n' +
        'event: message_delta\ndata: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":5}}\n\n' +
        'event: message_stop\ndata: {"type":"message_stop"}\n\n',
      )
      return
    }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sseResponsesPayload('ok-resp'))
  })
  t.after(() => llmServer.close())

  // 1. Verify openai-responses forwards reasoning.effort = high | medium | low and omits when thinkingLevel = off
  for (const [role, expectedEffort] of [['reasoning', 'high'], ['tactical', 'medium'], ['fast', 'low']] as const) {
    const profile: ResolvedModelProfile = {
      id: `p-${role}`,
      name: `Resp ${role}`,
      endpoint: llmServer.url,
      model: `resp-${role}`,
      protocol: 'responses',
      key: 'test-key-12345',
      priority: 100,
      enabled: true,
      contextWindow: 128_000,
      maxTokens: 16_384,
      thinkingLevel: 'medium',
      roleAffinity: role,
      inputCostPerMtok: 0.15,
      cachedInputCostPerMtok: 0.003,
      outputCostPerMtok: 0.6,
      healthState: 'closed',
      cooldownUntil: null,
      lastError: null,
    }
    await runAgentSession({
      directory: dir,
      sessionId: `resp-effort-${role}`,
      requestId: randomUUID(),
      profiles: [profile],
      scenario: role === 'reasoning' ? 'code-auditor' : role === 'tactical' ? 'chain-planner' : 'compactor',
      roleAffinity: role,
      prompt: 'Check reasoning wire forwarding.',
      signal: AbortSignal.timeout(10_000),
      maxTurns: 1,
      requireCompleteIntent: false,
    })
    const sent = capturedBodies.at(-1) as { reasoning?: { effort?: string } }
    assert.equal(sent.reasoning?.effort, expectedEffort, `responses role=${role} must send reasoning.effort=${expectedEffort}`)
  }

  // When thinkingLevel is explicitly 'off', reasoning must NOT be forwarded
  const offProfile: ResolvedModelProfile = {
    id: 'p-off',
    name: 'Resp Off',
    endpoint: llmServer.url,
    model: 'resp-off',
    protocol: 'responses',
    key: 'test-key-12345',
    priority: 100,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 16_384,
    thinkingLevel: 'off',
    roleAffinity: 'reasoning',
    inputCostPerMtok: 0.15,
    cachedInputCostPerMtok: 0.003,
    outputCostPerMtok: 0.6,
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
  }
  await runAgentSession({
    directory: dir,
    sessionId: 'resp-effort-off',
    requestId: randomUUID(),
    profiles: [offProfile],
    scenario: 'code-auditor',
    roleAffinity: 'reasoning',
    prompt: 'Check off thinking.',
    signal: AbortSignal.timeout(10_000),
    maxTurns: 1,
    requireCompleteIntent: false,
  })
  assert.equal((capturedBodies.at(-1) as { reasoning?: unknown }).reasoning, undefined)

  // 2. Open-tripped fast profile (thinkingLevel: 'off', contextWindow: 32_000, responses) must NOT poison healthy reasoning fallback
  const openFast: ResolvedModelProfile = {
    id: 'p-fast-open',
    name: 'Open Fast',
    endpoint: llmServer.url,
    model: 'fast-dead',
    protocol: 'responses',
    key: 'fast-key-12345',
    priority: 300,
    enabled: true,
    contextWindow: 32_000,
    maxTokens: 4096,
    thinkingLevel: 'off',
    roleAffinity: 'fast',
    inputCostPerMtok: 0.1,
    cachedInputCostPerMtok: 0.01,
    outputCostPerMtok: 0.2,
    healthState: 'open',
    cooldownUntil: Date.now() + 120_000,
    lastError: '401 invalid',
  }
  const healthyReason: ResolvedModelProfile = {
    id: 'p-reason-ok',
    name: 'Healthy Reason',
    endpoint: llmServer.url,
    model: 'reason-healthy',
    protocol: 'messages',
    key: 'reason-key-12345',
    priority: 100,
    enabled: true,
    contextWindow: 200_000,
    maxTokens: 16_384,
    thinkingLevel: 'high',
    roleAffinity: 'reasoning',
    inputCostPerMtok: 1.0,
    cachedInputCostPerMtok: 0.1,
    outputCostPerMtok: 2.0,
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
  }
  const resolvedPool = resolveProfilePoolForRole('fast', [openFast, healthyReason])
  assert.equal(resolvedPool[0].id, 'p-reason-ok')
  const { model: poolModel } = providerPool(resolvedPool, 'compactor', { roleAffinity: 'fast' })
  assert.equal(poolModel.id, 'reason-healthy')
  assert.equal(poolModel.contextWindow, 200_000)

  const beforeFallbackIdx = capturedBodies.length
  await runAgentSession({
    directory: dir,
    sessionId: 'open-fallback-thinking',
    requestId: randomUUID(),
    profiles: [openFast, healthyReason],
    scenario: 'compactor',
    roleAffinity: 'fast',
    prompt: 'Compact findings.',
    signal: AbortSignal.timeout(10_000),
    maxTurns: 1,
    requireCompleteIntent: false,
  })
  const fallbackBody = capturedBodies[beforeFallbackIdx] as { model?: string; thinking?: unknown }
  assert.equal(fallbackBody.model, 'reason-healthy')
  assert.ok(fallbackBody.thinking, 'healthy fallback must retain thinking instead of inheriting off from open-tripped profile')
})

test('M1.9 Regression: base64/base64url secret scrubbing, credentialPatterns secret=..., redactJsonValue keys, and NaN store guards', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m1-reg-redact-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const rawPersonaToken = 'pA_RawSecretToken_998877'
  const shortSecret = 's3cr'
  const secrets = [
    { value: rawPersonaToken, placeholder: '[persona:user_a:secret]' },
    { value: shortSecret, placeholder: '[persona:user_short:secret]' },
  ]
  const b64Persona = Buffer.from(rawPersonaToken, 'utf8').toString('base64')
  const b64urlPersona = Buffer.from(rawPersonaToken, 'utf8').toString('base64url')
  const b64Short = Buffer.from(shortSecret, 'utf8').toString('base64')
  const b64urlShort = Buffer.from(shortSecret, 'utf8').toString('base64url')

  const scrubbed = redact(
    `raw=${rawPersonaToken} b64=${b64Persona} b64url=${b64urlPersona} shortB64=${b64Short} shortB64url=${b64urlShort} secret=MY_TOP_SECRET_VALUE_42`,
    secrets,
  )
  assert.ok(!scrubbed.includes(rawPersonaToken))
  assert.ok(!scrubbed.includes(b64Persona))
  assert.ok(!scrubbed.includes(b64urlPersona))
  assert.ok(!scrubbed.includes(b64Short))
  assert.ok(!scrubbed.includes(b64urlShort))
  assert.ok(!scrubbed.includes('MY_TOP_SECRET_VALUE_42'))

  // redactJsonValue & insertBenchmarkRun expanded sensitiveKey checks
  const bm = storage.insertBenchmarkRun({
    suite: 'redact-probe',
    gitSha: 'deadbeef',
    modelRoutingConfig: {
      headers: {
        'x-api-key': 'opaque-header-api-key-value',
        'X-Auth-Token': 'opaque-header-auth-token-value',
        'X-Csrf-Token': 'opaque-csrf-token-value',
      },
      access_token: 'opaque-access-token-value',
      refreshToken: 'opaque-refresh-token-value',
      id_token: 'opaque-id-token-value',
      bearer_token: 'opaque-bearer-token-value',
      privateKey: 'opaque-private-key-value',
      session_id: 'opaque-session-id-value',
      credentials: 'opaque-credentials-value',
    },
    targetsTotal: 1,
    confirmedCount: 1,
    falsePositiveCount: 0,
    funnelCounts: { targetVulns: 1, surfaceDiscovered: 1, hypothesisFormed: 1, signalObserved: 1, specSubmitted: 1, zeroLlmConfirmed: 1 },
    failureTaxonomy: {
      surface_miss: 0, hypothesis_miss: 0, form_encoding_missing: 0, csrf_blocked: 0, context_reset: 0,
      tier_blocked: 0, trigger_miss: 0, jq_assertion_bug: 0, spa_catchall_fp: 0, replay_spec_miss: 0, budget_exhausted: 0,
    },
  })
  const latestBm = storage.getLatestBenchmarkRun('redact-probe')!
  const cfgStr = JSON.stringify(latestBm.modelRoutingConfig)
  for (const leaked of [
    'opaque-header-api-key-value',
    'opaque-header-auth-token-value',
    'opaque-csrf-token-value',
    'opaque-access-token-value',
    'opaque-refresh-token-value',
    'opaque-id-token-value',
    'opaque-bearer-token-value',
    'opaque-private-key-value',
    'opaque-session-id-value',
    'opaque-credentials-value',
  ]) {
    assert.ok(!cfgStr.includes(leaked), `sensitive key value leaked: ${leaked}`)
  }
  assert.ok(bm.id)
  const cleanJson = redactJsonValue({ sessionKey: 'opaque-session-key-val' })
  assert.equal(cleanJson.sessionKey, '[redacted]')

  // verifyReplaySpecInline redaction of base64 persona secret + secret=... in jqError & assertionSummary
  const fx = await httpFixture((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }))
  })
  t.after(() => fx.close())
  const broker = makeFixtureBroker(fx.port)
  const backend = createJqBackend()
  const grant = makeGrant({
    personas: new Map<string, ResolvedPersona>([
      ['user_a', {
        id: 'pa', handle: 'user_a', roleLabel: 'User', originAllowlist: [appOrigin],
        authKind: 'bearer', headerName: null, secret: rawPersonaToken, canaryMarkers: [],
      }],
    ]),
  })
  const inlineRes = await verifyReplaySpecInline({
    spec: {
      ...replayBase(),
      kind: 'http_chain',
      steps: [
        { id: 'c1', role: 'control', description: 'C', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/c' } },
        { id: 'p1', role: 'probe', description: 'P', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/p' } },
      ],
      assertionsJq: `{ controlPassed: true, confirmed: false, observed: "b64=${b64Persona}", expected: "secret=MY_TOP_SECRET_VALUE_42" }`,
    },
    broker, backend, grant, signal: AbortSignal.timeout(10_000), attemptCount: 1,
  })
  const inlineStr = JSON.stringify(inlineRes.feedback)
  assert.ok(!inlineStr.includes(b64Persona))
  assert.ok(!inlineStr.includes('MY_TOP_SECRET_VALUE_42'))

  // NaN numeric guards on upsertEndpoint & insertLabTelemetry
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'NaN Guard', seeds: [appOrigin], environment: 'public',
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'NaN check', sourceMode: 'public',
    capabilityTier: 2, budgetUsd: 5, budgetRequests: 50, maxRpsPerOrigin: 10, workerConcurrency: 1, workerMaxTurns: 10,
  })
  const ep = storage.upsertEndpoint({
    runId, scopeRevision: 1, origin: appOrigin, method: 'GET', pathTemplate: '/nan-test',
    source: 'openapi', riskScore: Number.NaN, coveragePct: Number.NaN,
  })
  assert.equal(ep.riskScore, 50)
  assert.equal(ep.coveragePct, null)
  const tel = storage.insertLabTelemetry({
    runId, exchangeId: 'ex-nan', traceId: 'trace-nan',
    routesHit: ['/nan-test'], newLinesCovered: Number.NaN, sinkEventsCount: Number.NaN,
    hasUnhandledException: false, artifactId: 'art-nan',
  })
  assert.equal(tel.newLinesCovered, 0)
  assert.equal(tel.sinkEventsCount, 0)
})

test('M1.10 Regression: browser_chain control -> setup/cleanup -> probe rejects omitted pathAndQuery in Zod', async t => {
  const base = {
    ...replayBase(),
    kind: 'browser_chain' as const,
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
  }

  for (const middleRole of ['setup', 'cleanup'] as const) {
    const parsed = browserChainReplaySpecSchema.safeParse({
      ...base,
      steps: [
        { id: 'c1', role: 'control', description: 'Control', origin: appOrigin, pathAndQuery: '/control' },
        { id: 'm1', role: middleRole, description: 'Middle', origin: appOrigin, action: 'fill', selector: '#x', value: '1' },
        { id: 'p1', role: 'probe', description: 'Probe missing path', origin: appOrigin, action: 'click', selector: '#btn' },
      ],
    })
    assert.equal(parsed.success, false, `control -> ${middleRole} -> probe omitting pathAndQuery must be rejected`)
  }

  const probeToControl = browserChainReplaySpecSchema.safeParse({
    ...base,
    steps: [
      { id: 'p1', role: 'probe', description: 'Probe', origin: appOrigin, pathAndQuery: '/probe' },
      { id: 'm1', role: 'cleanup', description: 'Cleanup', origin: appOrigin, action: 'click', selector: '#x' },
      { id: 'c1', role: 'control', description: 'Control missing path', origin: appOrigin, action: 'click', selector: '#btn' },
    ],
  })
  assert.equal(probeToControl.success, false, 'probe -> cleanup -> control omitting pathAndQuery must be rejected')

})

test('M1.11 Regression: update_proposed_finding does not reset exhausted findings to pending & finding.reason/verification redact secrets', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m1-reg-exhaust-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const rawLeak = 'SECRET_LEAK_TOKEN_987654'
  const targetFx = await httpFixture((req, res) => {
    if (req.url === '/control') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }))
      return
    }
    if (req.url === '/probe') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ leaked: rawLeak }))
      return
    }
    res.writeHead(404).end('not found')
  })
  t.after(() => targetFx.close())

  const toolOutputs: Array<Record<string, unknown>> = []
  let targetStepId = ''
  let turnCount = 0
  const llmServer = await httpFixture(async (req, res) => {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(Buffer.from(c))
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
      input?: Array<{ type?: string; output?: string }>
      tools?: unknown[]
    }
    const toolsStr = JSON.stringify(body.tools ?? [])
    if (!toolsStr.includes('verify_replay_spec')) {
      if (toolsStr.includes('complete_intent')) {
        res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
          sseResponsesPayload('', [{ name: 'complete_intent', args: { status: 'ruled_out', summary: 'skip' } }]),
        )
        return
      }
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
        sseResponsesPayload(JSON.stringify({ summary: 'done', newSteps: [], cancelStepIds: [], done: true })),
      )
      return
    }
    const promptKey = JSON.stringify(body.input?.[1] ?? body.input?.[0] ?? '')
    if (!targetStepId || !promptKey.includes(targetStepId)) {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
        sseResponsesPayload('', [{ name: 'complete_intent', args: { status: 'ruled_out', summary: 'skip' } }]),
      )
      return
    }
    let latestFindingId = ''
    for (const item of body.input ?? []) {
      if (item.type === 'function_call_output' && typeof item.output === 'string') {
        try {
          const parsed = JSON.parse(item.output) as Record<string, unknown>
          toolOutputs.push(parsed)
          if (typeof parsed.findingId === 'string') latestFindingId = parsed.findingId
        } catch { /* ignore */ }
      }
    }
    turnCount += 1

    const failingSpec = {
      ...replayBase(),
      kind: 'http_chain',
      spaCatchallControl: false,
      steps: [
        { id: 'c1', role: 'control', description: 'C', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/control' } },
        { id: 'p1', role: 'probe', description: 'P', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/probe' } },
      ],
      assertionsJq: '{ controlPassed: true, confirmed: false, observed: (.steps.p1.json.leaked // .steps.p1.body), expected: "safe", reason: (.steps.p1.json.leaked // .steps.p1.body) }',
    }
    const workingSpec = {
      ...failingSpec,
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    }

    let sse = ''
    if (turnCount === 1) {
      sse = sseResponsesPayload('', [{
        name: 'propose_chain_finding',
        args: {
          replaySpec: failingSpec,
          counterevidence: 'Control might block sensitive fields.',
          confidenceRationale: 'Testing inline retry exhaustion.',
          verifyNow: true,
        },
      }])
    } else if (turnCount === 2 || turnCount === 3) {
      sse = sseResponsesPayload('', [{
        name: 'verify_replay_spec',
        args: { findingId: latestFindingId, spec: failingSpec },
      }])
    } else if (turnCount === 4) {
      // Attempt 4 via update_proposed_finding after 3 failed attempts -> must NOT reset to pending or create new spec
      sse = sseResponsesPayload('', [{
        name: 'update_proposed_finding',
        args: { findingId: latestFindingId, replaySpec: workingSpec, verifyNow: true },
      }])
    } else {
      sse = sseResponsesPayload('', [{
        name: 'complete_intent',
        args: { status: 'ruled_out', summary: 'Exhausted retries.' },
      }])
    }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sse)
  })
  t.after(() => llmServer.close())

  await saveModelProfile({
    name: 'M11 LLM',
    endpoint: llmServer.url,
    model: 'm11-model',
    protocol: 'responses',
    key: 'm11-key-12345',
    priority: 100,
  }, storage, { skipConnectionCheck: true })

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Exhaust Proj', seeds: [appOrigin], environment: 'public',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(), projectId, handle: 'user_a', roleLabel: 'Member',
    originAllowlist: [appOrigin], authKind: 'bearer', secret: rawLeak, canaryMarkers: [],
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Test exhausted update_proposed_finding', sourceMode: 'public',
    capabilityTier: 2, budgetUsd: 5, budgetRequests: 100, maxRpsPerOrigin: 30, workerConcurrency: 1, workerMaxTurns: 10,
    approvedPersonaIds: [persona.id],
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })
  const run = storage.run(runId)
  const step = storage.addChainStep(run, {
    title: 'Exhaust test', hypothesis: 'h', targetAssetIds: [asset.id], sourceOrigins: [appOrigin],
  })
  targetStepId = step.id

  const execution = new Execution(storage, {
    broker: makeFixtureBroker(targetFx.port),
    backend: createJqBackend(),
  })
  t.after(() => execution.stop())
  execution.start()
  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    const r = storage.run(runId)
    if (r.phase === 'complete' || r.status === 'complete' || r.status === 'failed') break
    await delay(100)
  }
  await execution.stop()

  const targetFindingId = toolOutputs[0]?.findingId as string
  assert.ok(targetFindingId, 'expected findingId from propose_chain_finding')
  const findingRow = storage.db.select().from(findingsTable).where(eq(findingsTable.id, targetFindingId)).get()
  assert.ok(findingRow)
  assert.equal(
    findingRow.finding.status,
    'dismissed',
    `exhausted finding must remain dismissed, never reset to pending (reason=${findingRow.finding.reason}, outputs=${JSON.stringify(toolOutputs)})`,
  )
  assert.ok(!findingRow.finding.reason.includes(rawLeak), 'finding.reason must redact secrets')
  assert.ok(!(findingRow.finding.verification ?? '').includes(rawLeak), 'finding.verification must redact secrets')
  assert.equal(storage.listReplaySpecsForFinding(runId, findingRow.id).length, 1, 'must NOT create a new replay_specs row when exhausted')

  const updateOut = toolOutputs.at(-1) as { updated?: boolean; status?: string; isError?: boolean; inlineVerifyFeedback?: InlineVerifyFeedback }
  assert.equal(updateOut.updated, false)
  assert.equal(updateOut.isError, true)
  assert.equal(updateOut.status, 'dismissed')
  assert.equal(updateOut.inlineVerifyFeedback?.retriesRemaining, 0)
  assert.equal(updateOut.inlineVerifyFeedback?.assertionSummary?.observed, 'retry_limit_exceeded')
})

test('M1.12 Regression: Phase-3 refinement gets independent verification allowance (even when attemptCount === 3), caps at 3 refinement attempts, and persists update_proposed_finding(verifyNow=false)', async t => {
  for (const scenario of ['exhausted-from-investigation', 'verify-now-false', 'refinement-own-retry-cap'] as const) {
    const dir = mkdtempSync(join(tmpdir(), `kovo-m1-reg-p3-${scenario}-`))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const storage = new Store(dir)
    t.after(() => storage.close())

    const targetFx = await httpFixture((req, res) => {
      if (req.url === '/control') {
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ admin: false }))
        return
      }
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ admin: true }))
    })
    t.after(() => targetFx.close())

    let llmCalls = 0
    let backendCalls = 0
    let findingId = ''
    const refineToolOutputs: Array<Record<string, unknown>> = []
    const workingSpec = {
      ...replayBase(),
      kind: 'http_chain' as const,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'C', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/control' } },
        { id: 'p1', role: 'probe' as const, description: 'P', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/probe' } },
      ],
      assertionsJq: '{ controlPassed: (.steps.c1.json.admin == false), confirmed: (.steps.p1.json.admin == true), observed: "admin=true", expected: "admin=false" }',
    }
    const stillFailingSpec = {
      ...workingSpec,
      assertionsJq: '{ controlPassed: (.steps.c1.json.admin == false), confirmed: false, observed: "admin=false", expected: "admin=true" }',
    }

    const llmServer = await httpFixture(async (req, res) => {
      const chunks: Buffer[] = []
      for await (const c of req) chunks.push(Buffer.from(c))
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
        input?: Array<{ type?: string; output?: string }>
      }
      for (const item of body.input ?? []) {
        if (item.type === 'function_call_output' && typeof item.output === 'string') {
          try {
            refineToolOutputs.push(JSON.parse(item.output) as Record<string, unknown>)
          } catch { /* ignore */ }
        }
      }
      llmCalls += 1
      let sse = ''
      if (scenario === 'refinement-own-retry-cap') {
        if (llmCalls <= 3) {
          sse = sseResponsesPayload('', [{ name: 'verify_replay_spec', args: { spec: stillFailingSpec } }])
        } else if (llmCalls === 4) {
          sse = sseResponsesPayload('', [{ name: 'verify_replay_spec', args: { spec: workingSpec } }])
        } else {
          sse = sseResponsesPayload('', [{ name: 'complete_intent', args: { status: 'ruled_out', summary: 'Refinement cap hit.' } }])
        }
      } else if (llmCalls === 1) {
        if (scenario === 'exhausted-from-investigation') {
          sse = sseResponsesPayload('', [{
            name: 'verify_replay_spec',
            args: { spec: workingSpec },
          }])
        } else {
          sse = sseResponsesPayload('', [{
            name: 'update_proposed_finding',
            args: { findingId, replaySpec: workingSpec, verifyNow: false },
          }])
        }
      } else {
        sse = sseResponsesPayload('', [{
          name: 'complete_intent',
          args: { status: 'proved', summary: `Scenario ${scenario} done.` },
        }])
      }
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sse)
    })
    t.after(() => llmServer.close())

    await saveModelProfile({
      name: 'Reason P3',
      endpoint: llmServer.url,
      model: 'reason-p3',
      protocol: 'responses',
      key: 'reason-p3-key-12345',
      priority: 100,
      roleAffinity: 'reasoning',
    }, storage, { skipConnectionCheck: true })

    const { id: projectId } = storage.createProject({
      requestId: randomUUID(), name: `P3 ${scenario}`, seeds: [appOrigin], environment: 'public',
    })
    const { id: runId } = storage.createRun({
      requestId: randomUUID(), projectId, goal: `P3 ${scenario}`, sourceMode: 'public',
      capabilityTier: 2, budgetUsd: 5, budgetRequests: 100, maxRpsPerOrigin: 30, workerConcurrency: 2, workerMaxTurns: 20,
    })
    storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
    const asset = storage.run(runId).candidates[0]
    storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })

    const run = storage.run(runId)
    const invWorker = storage.makeWorker(run, 'investigation', asset, 'Seeded', 'Seeded')
    storage.updateWorker(invWorker.id, { status: 'complete' })
    findingId = randomUUID()
    const brokenSpec: DeclarativeReplaySpec = {
      ...replayBase(),
      kind: 'http_chain',
      spaCatchallControl: false,
      steps: [
        { id: 'c1', role: 'control', description: 'C', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/control', followRedirects: false } },
        { id: 'p1', role: 'probe', description: 'P', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/probe', followRedirects: false } },
      ],
      assertionsJq: 'broken jq ((',
    }
    const specRow = storage.createReplaySpec(run, invWorker, findingId, brokenSpec, [appOrigin], { initialAttemptCount: 3 })
    storage.upsertChainFinding(run, asset.id, {
      id: findingId, origin: appOrigin, title: brokenSpec.title, status: 'pending', severity: 'high',
      reason: 'Seeded pending finding', remediation: brokenSpec.remediation, category: brokenSpec.category,
      cwe: brokenSpec.cwe, findingKind: 'multi_step_chain', replaySpecId: specRow.id, evidenceIds: [], scopeRevision: run.scopeRevision,
    }, specRow.id, [appOrigin])
    const baseWorker = storage.makeWorker(run, 'verification', asset, 'Baseline', 'Baseline')
    storage.updateWorker(baseWorker.id, { status: 'complete' })
    storage.updateRun(runId, { phase: 'verification', status: 'running' })

    const execution = new Execution(storage, {
      broker: makeFixtureBroker(targetFx.port),
      backend: createJqBackend(() => { backendCalls += 1 }),
    })
    t.after(() => execution.stop())
    execution.start()
    const deadline = Date.now() + 20_000
    while (Date.now() < deadline) {
      const r = storage.run(runId)
      if (r.phase === 'complete' || r.status === 'complete' || r.status === 'failed') break
      await delay(100)
    }
    await execution.stop()

    const finalFinding = storage.db.select().from(findingsTable).where(eq(findingsTable.id, findingId)).get()
    assert.ok(finalFinding)
    const activeSpec = storage.getReplaySpec(runId, finalFinding.replaySpecId!)
    if (scenario === 'refinement-own-retry-cap') {
      assert.equal(finalFinding.finding.status, 'dismissed')
      assert.equal(backendCalls, 4, '1 initial Phase-3 verify + 3 refinement attempts; 4th refinement verify must short-circuit')
      const fourthFeedback = (refineToolOutputs.at(-1) as { inlineVerifyFeedback?: InlineVerifyFeedback } | undefined)?.inlineVerifyFeedback
      assert.equal(fourthFeedback?.assertionSummary?.observed, 'retry_limit_exceeded')
      assert.equal(fourthFeedback?.retriesRemaining, 0)
    } else {
      assert.equal(finalFinding.finding.status, 'confirmed', `${scenario}: Phase-3 refinement must confirm finding`)
      assert.equal(finalFinding.verificationTier, 'runtime_confirmed')
      assert.equal(activeSpec.verifiedInline, true)
      if (scenario === 'exhausted-from-investigation') {
        assert.equal(activeSpec.attemptCount, 4, 'attemptCount must increment cleanly from 3 -> 4')
      } else {
        assert.notEqual(activeSpec.id, specRow.id, 'verifyNow=false must persist a new replay_specs row and update finding.replaySpecId')
        assert.equal(activeSpec.attemptCount, 1)
      }
    }
  }
})

test('M1.13 Regression: exhausted update_proposed_finding(verifyNow=false) & propose_chain_finding dedupe-merge preserve dismissed status without orphan specs', async t => {
  for (const mode of ['update-verify-now-false', 'dedupe-propose-after-exhaust'] as const) {
    const dir = mkdtempSync(join(tmpdir(), `kovo-m1-reg-m13-${mode}-`))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const storage = new Store(dir)
    t.after(() => storage.close())

    const targetFx = await httpFixture((req, res) => {
      if (req.url === '/control') {
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }))
        return
      }
      if (req.url === '/probe') {
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: false }))
        return
      }
      res.writeHead(404).end('not found')
    })
    t.after(() => targetFx.close())

    const toolOutputs: Array<Record<string, unknown>> = []
    let targetStepId = ''
    let turnCount = 0
    let backendCalls = 0
    const failingSpec = {
      ...replayBase(),
      kind: 'http_chain' as const,
      spaCatchallControl: false,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'C', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/control' } },
        { id: 'p1', role: 'probe' as const, description: 'P', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/probe' } },
      ],
      assertionsJq: '{ controlPassed: true, confirmed: false, observed: "blocked", expected: "bypass" }',
    }
    const workingSpec = {
      ...failingSpec,
      assertionsJq: '{ controlPassed: true, confirmed: true, observed: "bypass", expected: "bypass" }',
    }
    const workingHigherSeveritySpec = {
      ...workingSpec,
      severity: 'critical' as const,
    }

    const llmServer = await httpFixture(async (req, res) => {
      const chunks: Buffer[] = []
      for await (const c of req) chunks.push(Buffer.from(c))
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
        input?: Array<{ type?: string; output?: string }>
        tools?: unknown[]
      }
      const toolsStr = JSON.stringify(body.tools ?? [])
      if (!toolsStr.includes('verify_replay_spec')) {
        if (toolsStr.includes('complete_intent')) {
          res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
            sseResponsesPayload('', [{ name: 'complete_intent', args: { status: 'ruled_out', summary: 'skip' } }]),
          )
          return
        }
        res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
          sseResponsesPayload(JSON.stringify({ summary: 'done', newSteps: [], cancelStepIds: [], done: true })),
        )
        return
      }
      const promptKey = JSON.stringify(body.input?.[1] ?? body.input?.[0] ?? '')
      if (!targetStepId || !promptKey.includes(targetStepId)) {
        res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(
          sseResponsesPayload('', [{ name: 'complete_intent', args: { status: 'ruled_out', summary: 'skip' } }]),
        )
        return
      }
      let latestFindingId = ''
      for (const item of body.input ?? []) {
        if (item.type === 'function_call_output' && typeof item.output === 'string') {
          try {
            const parsed = JSON.parse(item.output) as Record<string, unknown>
            toolOutputs.push(parsed)
            if (typeof parsed.findingId === 'string') latestFindingId = parsed.findingId
          } catch { /* ignore */ }
        }
      }
      turnCount += 1

      let sse = ''
      if (turnCount === 1) {
        sse = sseResponsesPayload('', [{
          name: 'propose_chain_finding',
          args: {
            replaySpec: failingSpec,
            counterevidence: 'Control might reject request.',
            confidenceRationale: 'Testing retry exhaustion.',
            verifyNow: true,
          },
        }])
      } else if (turnCount === 2 || turnCount === 3) {
        sse = sseResponsesPayload('', [{
          name: 'verify_replay_spec',
          args: { findingId: latestFindingId, spec: failingSpec },
        }])
      } else if (turnCount === 4) {
        sse = sseResponsesPayload('', [
          mode === 'update-verify-now-false'
            ? {
                name: 'update_proposed_finding',
                args: { findingId: latestFindingId, replaySpec: workingSpec, verifyNow: false },
              }
            : {
                name: 'propose_chain_finding',
                args: {
                  replaySpec: workingHigherSeveritySpec,
                  counterevidence: 'Control might reject request.',
                  confidenceRationale: 'Testing dedupe-merge exhaustion.',
                  verifyNow: true,
                },
              },
        ])
      } else {
        sse = sseResponsesPayload('', [{
          name: 'complete_intent',
          args: { status: 'ruled_out', summary: 'Exhausted.' },
        }])
      }
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sse)
    })
    t.after(() => llmServer.close())

    await saveModelProfile({
      name: `M13 LLM ${mode}`,
      endpoint: llmServer.url,
      model: 'm13-model',
      protocol: 'responses',
      key: 'm13-key-12345',
      priority: 100,
    }, storage, { skipConnectionCheck: true })

    const { id: projectId } = storage.createProject({
      requestId: randomUUID(), name: `M13 ${mode}`, seeds: [appOrigin], environment: 'public',
    })
    const { id: runId } = storage.createRun({
      requestId: randomUUID(), projectId, goal: `M13 ${mode}`, sourceMode: 'public',
      capabilityTier: 2, budgetUsd: 5, budgetRequests: 100, maxRpsPerOrigin: 30, workerConcurrency: 1, workerMaxTurns: 10,
    })
    storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
    const asset = storage.run(runId).candidates[0]
    storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })
    const run = storage.run(runId)
    const step = storage.addChainStep(run, {
      title: 'M13 step', hypothesis: 'h', targetAssetIds: [asset.id], sourceOrigins: [appOrigin],
    })
    targetStepId = step.id

    const execution = new Execution(storage, {
      broker: makeFixtureBroker(targetFx.port),
      backend: createJqBackend(() => { backendCalls += 1 }),
    })
    t.after(() => execution.stop())
    execution.start()
    const deadline = Date.now() + 20_000
    while (Date.now() < deadline) {
      const r = storage.run(runId)
      if (r.phase === 'complete' || r.status === 'complete' || r.status === 'failed') break
      await delay(100)
    }
    await execution.stop()

    const finalRun = storage.run(runId)
    assert.equal(finalRun.phase, 'complete')
    const targetFindingId = toolOutputs[0]?.findingId as string
    assert.ok(targetFindingId)
    const findingRow = storage.db.select().from(findingsTable).where(eq(findingsTable.id, targetFindingId)).get()
    assert.ok(findingRow)
    assert.equal(findingRow.finding.status, 'dismissed')
    assert.equal(findingRow.finding.severity, 'high')
    assert.equal(backendCalls, 3, `${mode}: must execute exactly 3 replay verifications total`)
    assert.equal(storage.listReplaySpecs(runId).length, 1, `${mode}: must create zero extra/orphan replay_specs rows`)
    assert.equal(storage.listReplaySpecsForFinding(runId, findingRow.id).length, 1)

    const fourthOut = toolOutputs.at(-1) as {
      updated?: boolean
      rejected?: boolean
      deduplicated?: boolean
      isError?: boolean
      status?: string
      inlineVerifyFeedback?: InlineVerifyFeedback
    }
    assert.equal(fourthOut.isError, true)
    assert.equal(fourthOut.status, 'dismissed')
    assert.equal(fourthOut.inlineVerifyFeedback?.retriesRemaining, 0)
    assert.equal(fourthOut.inlineVerifyFeedback?.assertionSummary?.observed, 'retry_limit_exceeded')
    if (mode === 'update-verify-now-false') {
      assert.equal(fourthOut.updated, false)
    } else {
      assert.equal(fourthOut.rejected, true)
      assert.equal(fourthOut.deduplicated, true)
    }
  }
})

test('M1.14 Regression: Phase-3 refinement caps verify_replay_spec x3 + update_proposed_finding(verifyNow=false) and prevents driveVerification duplicate-worker race', async t => {
  for (const scenario of ['exhausted-verify-now-false', 'no-duplicate-worker-race'] as const) {
    const dir = mkdtempSync(join(tmpdir(), `kovo-m1-reg-m14-${scenario}-`))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const storage = new Store(dir)
    t.after(() => storage.close())

    const targetFx = await httpFixture((req, res) => {
      if (req.url === '/control') {
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ admin: false }))
        return
      }
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ admin: true }))
    })
    t.after(() => targetFx.close())

    let llmCalls = 0
    let backendCalls = 0
    let findingId = ''
    const refineToolOutputs: Array<Record<string, unknown>> = []
    const workingSpec = {
      ...replayBase(),
      kind: 'http_chain' as const,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'C', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/control' } },
        { id: 'p1', role: 'probe' as const, description: 'P', request: { origin: appOrigin, method: 'GET' as const, pathAndQuery: '/probe' } },
      ],
      assertionsJq: '{ controlPassed: (.steps.c1.json.admin == false), confirmed: (.steps.p1.json.admin == true), observed: "admin=true", expected: "admin=false" }',
    }
    const stillFailingSpec = {
      ...workingSpec,
      assertionsJq: '{ controlPassed: (.steps.c1.json.admin == false), confirmed: false, observed: "admin=false", expected: "admin=true" }',
    }

    const llmServer = await httpFixture(async (req, res) => {
      const chunks: Buffer[] = []
      for await (const c of req) chunks.push(Buffer.from(c))
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
        input?: Array<{ type?: string; output?: string }>
      }
      for (const item of body.input ?? []) {
        if (item.type === 'function_call_output' && typeof item.output === 'string') {
          try {
            refineToolOutputs.push(JSON.parse(item.output) as Record<string, unknown>)
          } catch { /* ignore */ }
        }
      }
      llmCalls += 1
      let sse = ''
      if (scenario === 'exhausted-verify-now-false') {
        if (llmCalls <= 3) {
          sse = sseResponsesPayload('', [{ name: 'verify_replay_spec', args: { spec: stillFailingSpec } }])
        } else if (llmCalls === 4) {
          sse = sseResponsesPayload('', [{ name: 'update_proposed_finding', args: { findingId, replaySpec: workingSpec, verifyNow: false } }])
        } else {
          sse = sseResponsesPayload('', [{ name: 'complete_intent', args: { status: 'ruled_out', summary: 'Exhausted Phase-3 refinement.' } }])
        }
      } else {
        if (llmCalls === 1) {
          sse = sseResponsesPayload('', [{ name: 'update_proposed_finding', args: { findingId, replaySpec: workingSpec, verifyNow: false } }])
        } else {
          // Give driveVerification ample opportunity to tick concurrently before Phase-3 refinement exits
          await delay(150)
          sse = sseResponsesPayload('', [{ name: 'complete_intent', args: { status: 'proved', summary: 'Refined without duplicate verify worker.' } }])
        }
      }
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }).end(sse)
    })
    t.after(() => llmServer.close())

    await saveModelProfile({
      name: `Reason M14 ${scenario}`,
      endpoint: llmServer.url,
      model: 'reason-m14',
      protocol: 'responses',
      key: 'reason-m14-key-12345',
      priority: 100,
      roleAffinity: 'reasoning',
    }, storage, { skipConnectionCheck: true })

    const { id: projectId } = storage.createProject({
      requestId: randomUUID(), name: `M14 ${scenario}`, seeds: [appOrigin], environment: 'public',
    })
    const { id: runId } = storage.createRun({
      requestId: randomUUID(), projectId, goal: `M14 ${scenario}`, sourceMode: 'public',
      capabilityTier: 2, budgetUsd: 5, budgetRequests: 100, maxRpsPerOrigin: 30, workerConcurrency: 2, workerMaxTurns: 20,
    })
    storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
    const asset = storage.run(runId).candidates[0]
    storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })

    const run = storage.run(runId)
    const invWorker = storage.makeWorker(run, 'investigation', asset, 'Seeded', 'Seeded')
    storage.updateWorker(invWorker.id, { status: 'complete' })
    findingId = randomUUID()
    const brokenSpec: DeclarativeReplaySpec = {
      ...replayBase(),
      kind: 'http_chain',
      spaCatchallControl: false,
      steps: [
        { id: 'c1', role: 'control', description: 'C', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/control', followRedirects: false } },
        { id: 'p1', role: 'probe', description: 'P', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/probe', followRedirects: false } },
      ],
      assertionsJq: 'broken jq ((',
    }
    const initialAttempts = scenario === 'exhausted-verify-now-false' ? 3 : 1
    const specRow = storage.createReplaySpec(run, invWorker, findingId, brokenSpec, [appOrigin], { initialAttemptCount: initialAttempts })
    storage.upsertChainFinding(run, asset.id, {
      id: findingId, origin: appOrigin, title: brokenSpec.title, status: 'pending', severity: 'high',
      reason: 'Seeded pending finding', remediation: brokenSpec.remediation, category: brokenSpec.category,
      cwe: brokenSpec.cwe, findingKind: 'multi_step_chain', replaySpecId: specRow.id, evidenceIds: [], scopeRevision: run.scopeRevision,
    }, specRow.id, [appOrigin])
    const baseWorker = storage.makeWorker(run, 'verification', asset, 'Baseline', 'Baseline')
    storage.updateWorker(baseWorker.id, { status: 'complete' })
    storage.updateRun(runId, { phase: 'verification', status: 'running' })

    const execution = new Execution(storage, {
      broker: makeFixtureBroker(targetFx.port),
      backend: createJqBackend(() => { backendCalls += 1 }),
    })
    t.after(() => execution.stop())
    execution.start()
    const deadline = Date.now() + 20_000
    while (Date.now() < deadline) {
      const r = storage.run(runId)
      if (r.phase === 'complete' || r.status === 'complete' || r.status === 'failed') break
      await delay(100)
    }
    await execution.stop()

    const finalFinding = storage.db.select().from(findingsTable).where(eq(findingsTable.id, findingId)).get()
    assert.ok(finalFinding)
    const activeSpec = storage.getReplaySpec(runId, finalFinding.replaySpecId!)
    if (scenario === 'exhausted-verify-now-false') {
      assert.equal(finalFinding.finding.status, 'dismissed')
      assert.equal(backendCalls, 4, 'must run only 1 initial Phase-3 + 3 refinement attempts (no 4th gate run)')
      const updateOut = refineToolOutputs.at(-1) as { updated?: boolean; isError?: boolean; inlineVerifyFeedback?: InlineVerifyFeedback }
      assert.equal(updateOut.updated, false)
      assert.equal(updateOut.isError, true)
      assert.equal(updateOut.inlineVerifyFeedback?.assertionSummary?.observed, 'retry_limit_exceeded')
      assert.equal(updateOut.inlineVerifyFeedback?.retriesRemaining, 0)
    } else {
      assert.equal(finalFinding.finding.status, 'confirmed')
      assert.equal(finalFinding.verificationTier, 'runtime_confirmed')
      assert.equal(backendCalls, 2, 'must run only 1 initial Phase-3 + 1 Post-Refinement Gate (no duplicate verifyReplaySpecJob)')
      assert.notEqual(activeSpec.id, specRow.id)
      assert.equal(activeSpec.attemptCount, 1)
      const dupVerifyWorkers = storage.workerList(runId).filter(
        w => w.phase === 'verification' && w.stepId === activeSpec.id,
      )
      assert.equal(dupVerifyWorkers.length, 0, 'driveVerification must not spawn a duplicate worker while refine:* owns the finding')
    }
  }
})

test('M1.15 Regression: completeWorker/redact.ts secret scrubbing (base64/base64url, *_secret=, sensitive subtrees) & store.ts Number.isFinite guards', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-m1-reg-m15-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  // 1. Direct redact() and redactJsonValue() assertions
  const scrubbedInline = redact('rsn_secret=TOP_42 app-secret="VAL_99" secretary=keep_public token_count=5')
  assert.ok(!scrubbedInline.includes('TOP_42'), 'underscore-prefixed *_secret= must be scrubbed')
  assert.ok(!scrubbedInline.includes('VAL_99'), 'hyphen-prefixed *-secret= must be scrubbed')
  assert.ok(scrubbedInline.includes('secretary=keep_public'), 'secretary= must not false-match secret')
  assert.ok(scrubbedInline.includes('token_count=5'), 'token_count= must not false-match token')

  const scrubbedJson = redactJsonValue({
    'x-api-key': ['s1', 's2'],
    credentials: { user: 'alice', rawSecretField: 's3', nested: ['s4'] },
    safeField: 'public-ok',
  })
  assert.deepEqual(scrubbedJson['x-api-key'], ['[redacted]', '[redacted]'])
  assert.deepEqual(scrubbedJson.credentials, { user: '[redacted]', rawSecretField: '[redacted]', nested: ['[redacted]'] })
  assert.equal(scrubbedJson.safeField, 'public-ok')

  // 2. Direct Store Number.isFinite assertions
  const { id: projId } = storage.createProject({
    requestId: randomUUID(), name: 'Finite Proj', seeds: [appOrigin], environment: 'public',
  })
  const { id: finiteRunId } = storage.createRun({
    requestId: randomUUID(), projectId: projId, goal: 'Finite guards', sourceMode: 'public',
    capabilityTier: 1, budgetUsd: 5, budgetRequests: 100, maxRpsPerOrigin: 30, workerConcurrency: 1, workerMaxTurns: 10,
  })
  const epInf = storage.upsertEndpoint({ runId: finiteRunId, scopeRevision: 0, origin: appOrigin, method: 'GET', pathTemplate: '/inf', source: 'spa_crawl', riskScore: Infinity })
  const epNegInf = storage.upsertEndpoint({ runId: finiteRunId, scopeRevision: 0, origin: appOrigin, method: 'GET', pathTemplate: '/neginf', source: 'spa_crawl', riskScore: -Infinity })
  const epNan = storage.upsertEndpoint({ runId: finiteRunId, scopeRevision: 0, origin: appOrigin, method: 'GET', pathTemplate: '/nan', source: 'spa_crawl', riskScore: Number.NaN })
  assert.equal(epInf.riskScore, 100)
  assert.equal(epNegInf.riskScore, 0)
  assert.equal(epNan.riskScore, 50)
  assert.equal(storage.listEndpoints(finiteRunId, { limit: Number.NaN }).length, 3)

  const bench = storage.insertBenchmarkRun({
    suite: 'm15-finite',
    gitSha: 'deadbeef',
    targetsTotal: Number.NaN,
    confirmedCount: Infinity,
    falsePositiveCount: -Infinity,
    funnelCounts: { targetVulns: 0, surfaceDiscovered: 0, hypothesisFormed: 0, signalObserved: 0, specSubmitted: 0, zeroLlmConfirmed: 0 },
    failureTaxonomy: {
      surface_miss: 0, hypothesis_miss: 0, form_encoding_missing: 0, csrf_blocked: 0,
      context_reset: 0, tier_blocked: 0, trigger_miss: 0, jq_assertion_bug: 0,
      spa_catchall_fp: 0, replay_spec_miss: 0, budget_exhausted: 0,
    },
    totalCostUsd: Number.NaN,
    durationMs: Number.NaN,
  })
  assert.equal(bench.targetsTotal, 0)
  assert.equal(bench.confirmedCount, 0)
  assert.equal(bench.falsePositiveCount, 0)
  assert.equal(bench.totalCostUsd, 0)
  assert.equal(bench.durationMs, 0)
  assert.equal(storage.listBenchmarkRuns('m15-finite', Number.NaN).length, 1)

  const setBudget = storage.updateRunDynamicStepBudget(finiteRunId, 77)
  assert.equal(setBudget.dynamicStepBudget, 77)
  const afterNanBudget = storage.updateRunDynamicStepBudget(finiteRunId, Number.NaN)
  assert.equal(afterNanBudget.dynamicStepBudget, 77, 'NaN budget must preserve existing dynamicStepBudget')

  // 3. End-to-end Phase-3 verifyReplaySpecJob redaction across outcome, result.md, messages, findings, and lastVerificationDiff
  const rawSecret = 'pA?Secret>99/88+'
  const b64 = Buffer.from(rawSecret, 'utf8').toString('base64')
  const b64url = Buffer.from(rawSecret, 'utf8').toString('base64url')
  assert.notEqual(b64, b64url)

  const targetFx = await httpFixture((req, res) => {
    if (req.url === '/control') {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ok: true }))
      return
    }
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({
      observed: `obs_${b64url}_${rawSecret}`,
      reason: `rsn_secret=TOP_42_${b64}`,
    }))
  })
  t.after(() => targetFx.close())

  const persona = createProjectPersona(storage, {
    requestId: randomUUID(), projectId: projId, handle: 'user_a', roleLabel: 'Member',
    originAllowlist: [appOrigin], authKind: 'bearer', secret: rawSecret, canaryMarkers: [],
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId: projId, goal: 'M15 redaction', sourceMode: 'public',
    capabilityTier: 2, budgetUsd: 5, budgetRequests: 100, maxRpsPerOrigin: 30, workerConcurrency: 1, workerMaxTurns: 10,
    approvedPersonaIds: [persona.id],
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })

  const run = storage.run(runId)
  const invWorker = storage.makeWorker(run, 'investigation', asset, 'Seeded', 'Seeded')
  storage.updateWorker(invWorker.id, { status: 'complete' })
  const findingId = randomUUID()
  const spec: DeclarativeReplaySpec = {
    ...replayBase(),
    kind: 'http_chain',
    spaCatchallControl: false,
    steps: [
      { id: 'c1', role: 'control', description: 'C', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/control', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'P', request: { origin: appOrigin, method: 'GET', pathAndQuery: '/probe', followRedirects: false } },
    ],
    assertionsJq: '{ controlPassed: true, confirmed: false, observed: .steps.p1.json.observed, expected: "safe", reason: .steps.p1.json.reason }',
  }
  const specRow = storage.createReplaySpec(run, invWorker, findingId, spec, [appOrigin], { initialAttemptCount: 0 })
  storage.upsertChainFinding(run, asset.id, {
    id: findingId, origin: appOrigin, title: spec.title, status: 'pending', severity: 'high',
    reason: 'Seeded pending finding', remediation: spec.remediation, category: spec.category,
    cwe: spec.cwe, findingKind: 'multi_step_chain', replaySpecId: specRow.id, evidenceIds: [], scopeRevision: run.scopeRevision,
  }, specRow.id, [appOrigin])
  const baseWorker = storage.makeWorker(run, 'verification', asset, 'Baseline', 'Baseline')
  storage.updateWorker(baseWorker.id, { status: 'complete' })
  storage.updateRun(runId, { phase: 'verification', status: 'running' })

  const execution = new Execution(storage, {
    broker: makeFixtureBroker(targetFx.port),
    backend: createJqBackend(),
  })
  t.after(() => execution.stop())
  execution.start()
  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    const r = storage.run(runId)
    if (r.phase === 'complete' || r.status === 'complete' || r.status === 'failed') break
    await delay(100)
  }
  await execution.stop()

  const verifyWorker = storage.workerList(runId).find(w => w.phase === 'verification' && w.stepId === specRow.id)
  assert.ok(verifyWorker)
  const resultArtifacts = storage.runDetail(runId).evidence
    .filter(a => a.kind === 'handoff' && a.title === 'result.md')
    .map(a => storage.artifact(runId, a.id))
  const runMessages = storage.db.select().from(messagesTable).where(eq(messagesTable.runId, runId)).all()
  const finalFinding = storage.db.select().from(findingsTable).where(eq(findingsTable.id, findingId)).get()
  const finalSpec = storage.getReplaySpec(runId, specRow.id)
  assert.ok(finalFinding)

  const checkNoSecret = (label: string, text: string | null | undefined) => {
    const s = text ?? ''
    assert.ok(!s.includes(rawSecret), `${label} leaked rawSecret`)
    assert.ok(!s.includes(b64), `${label} leaked b64`)
    assert.ok(!s.includes(b64url), `${label} leaked b64url`)
    assert.ok(!s.includes('TOP_42'), `${label} leaked TOP_42`)
  }
  checkNoSecret('assignments.outcome', verifyWorker.outcome)
  for (const art of resultArtifacts) checkNoSecret(`result.md(${art.id})`, art.content)
  for (const msg of runMessages) checkNoSecret(`message(${msg.id})`, msg.content)
  checkNoSecret('finding.reason', finalFinding.finding.reason)
  checkNoSecret('finding.verification', finalFinding.finding.verification)
  checkNoSecret('lastVerificationDiff', JSON.stringify(finalSpec.lastVerificationDiff))
})

