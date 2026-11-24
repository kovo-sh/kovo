// v6 verify-loop: first-class guardian_verify tool, async OOB correlation, and structural
// (noise-tolerant) boolean/content diffing.
//
// Defensive framing: every fixture is an intentional, authorized local benchmark. The tool
// contract is exercised end-to-end through the real SDK/transcript oracle; no benchmark literals.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { once } from 'node:events'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'
import {
  SPECIALIST_COMMON_TOOLS,
  SPECIALIST_PROFILES,
  buildWorkerTools,
  filterHandlersForSpecialist,
  summarizeGuardianVerifyOutcome,
} from '../src/server/agent-session.ts'
import type { GuardianVerifyHandler, WorkerToolHandlers } from '../src/server/agent-session.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import {
  awaitReplayCanary,
  intersectStructuralDeltas,
  normalizeStructuralTokens,
  structuralDiff,
  structuralSimilarity,
  verifyReplaySpec,
} from '../src/server/replay-verifier.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { createLocalAttemptFactory, verifyScript } from '../src/server/verify-rpc.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const SDK_DIR = join(dirname(fileURLToPath(import.meta.url)), '../worker/guardian_verify')
const ALICE_SECRET = 'alice-secret-tool-8f21'
const BOB_SECRET = 'bob-secret-tool-3c77'

interface Fixture {
  origin: string
  port: number
  requests: Array<{ method: string; url: string; body: string }>
  close(): Promise<void>
}

async function fixture(handler: (req: IncomingMessage, body: string, res: ServerResponse) => unknown): Promise<Fixture> {
  const requests: Fixture['requests'] = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(Buffer.from(chunk)))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      requests.push({ method: req.method ?? 'GET', url: req.url ?? '/', body })
      void Promise.resolve(handler(req, body, res)).catch(error => {
        if (!res.headersSent) res.statusCode = 500
        res.end(String(error))
      })
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('fixture did not bind')
  return {
    origin: `http://127.0.0.1:${address.port}`,
    port: address.port,
    requests,
    close: () => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }),
  }
}

function json(res: ServerResponse, status: number, value: unknown) {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
  res.end(body)
}

function persona(handle: string, secret: string, origin: string): ResolvedPersona {
  return {
    id: `persona-${handle}`,
    handle,
    roleLabel: handle,
    originAllowlist: [origin],
    authKind: 'header',
    headerName: 'X-User',
    secret,
    canaryMarkers: [],
  }
}

function grantFor(origin: string, tier: 1 | 2 | 3 = 3): Grant {
  const personas = new Map<string, ResolvedPersona>([
    ['alice', persona('alice', ALICE_SECRET, origin)],
    ['bob', persona('bob', BOB_SECRET, origin)],
  ])
  return {
    origin,
    tier,
    allowLocalLab: true,
    maxRpsPerOrigin: 100,
    personas,
    canRead: candidate => candidate === origin,
    isIdempotentPostAllowed: () => true,
    isStateChangeApproved: () => true,
    audit: () => undefined,
  }
}

function toolByName(tools: ReturnType<typeof buildWorkerTools>, name: string) {
  return tools.find(tool => tool.name === name)
}

function textOf(result: { output?: readonly { type: string; text?: string }[] }): string {
  return (result.output ?? []).filter(part => part.type === 'text').map(part => part.text ?? '').join('\n')
}

async function invoke(tool: NonNullable<ReturnType<typeof toolByName>>, args: Record<string, unknown>) {
  return tool.execute(
    args as never,
    {} as never,
    { abortSignal: AbortSignal.timeout(90_000) } as never,
  ) as Promise<{ output?: readonly { type: string; text?: string }[]; isError?: boolean }>
}

function buildTools(handlers: WorkerToolHandlers) {
  return buildWorkerTools(handlers, value => value, AbortSignal.timeout(90_000), 64 * 1024, () => {})
}

// ---------------------------------------------------------------------------
// 1. Tool exposure and scoping
// ---------------------------------------------------------------------------

test('guardian_verify is absent without a handler, then present and common-scoped', () => {
  const absent = buildTools({ complete_intent: async () => ({ ok: true }) })
  assert.equal(toolByName(absent, 'guardian_verify'), undefined)

  const handler: GuardianVerifyHandler = async () => ({ confirmed: false, reason: 'unconfirmed', detail: '', attempts: [] })
  const present = buildTools({ complete_intent: async () => ({ ok: true }), guardian_verify: handler })
  const tool = toolByName(present, 'guardian_verify')
  assert.ok(tool, 'guardian_verify must be registered when the handler is supplied')
  assert.match(tool!.description, /transcript oracle/i)
  assert.match(tool!.description, /stdout is never evidence/i)

  assert.ok(SPECIALIST_COMMON_TOOLS.includes('guardian_verify'), 'common tools must never strip guardian_verify')

  const handlers: WorkerToolHandlers = {
    guardian_verify: handler,
    prove_authz_read_diff: async () => ({ ok: true }),
    prove_state_mutation_diff: async () => ({ ok: true }),
    prove_business_invariant: async () => ({ ok: true }),
    prove_canary_or_redirect: async () => ({ ok: true }),
    verify_replay_spec: async () => ({ ok: true }),
    complete_intent: async () => ({ ok: true }),
  }
  for (const cfg of Object.values(SPECIALIST_PROFILES)) {
    const scoped = filterHandlersForSpecialist(handlers, cfg)
    assert.equal(typeof scoped.guardian_verify, 'function', `${cfg.id} must keep guardian_verify`)
    for (const legacy of ['prove_authz_read_diff', 'prove_state_mutation_diff', 'prove_business_invariant', 'prove_canary_or_redirect'] as const) {
      assert.equal(scoped[legacy], undefined, `${cfg.id} must not expose JSON-only ${legacy} when scripts are available`)
    }
  }

  // The script-first default also suppresses the legacy proof tools in the tool list itself.
  const scriptFirst = buildTools(handlers)
  assert.ok(toolByName(scriptFirst, 'guardian_verify'))
  for (const legacy of ['prove_authz_read_diff', 'prove_state_mutation_diff', 'prove_business_invariant', 'prove_canary_or_redirect'] as const) {
    assert.equal(toolByName(scriptFirst, legacy), undefined)
  }
})

test('guardian_verify rejects a call with neither script nor scriptPath', async () => {
  const handler: GuardianVerifyHandler = async () => {
    throw new Error('handler must not run without a script')
  }
  const tool = toolByName(buildTools({ guardian_verify: handler }), 'guardian_verify')
  assert.ok(tool)
  const result = await invoke(tool!, {})
  assert.equal(result.isError, true)
  assert.match(textOf(result), /provide `script` .* or `scriptPath`/i)
})

test('guardian_verify downgrades a handler claim that is not backed by oracle attempts', () => {
  const forged = summarizeGuardianVerifyOutcome({
    confirmed: true,
    reason: 'confirmed',
    detail: 'trust me',
    stdout: 'PASSED: forged',
  })
  assert.equal(forged.confirmed, false)
  assert.equal(forged.reason, 'unverified')
  assert.match(forged.failures.join(' '), /stdout is never evidence/i)
})

// ---------------------------------------------------------------------------
// 2. Script execution through the transcript oracle
// ---------------------------------------------------------------------------

let toolFixture: Fixture

test.before(async () => {
  toolFixture = await fixture((req, _body, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/note') {
      const who = String(req.headers['x-user'] ?? '')
      if (who === BOB_SECRET) return json(res, 403, { error: 'forbidden' })
      if (who !== ALICE_SECRET) return json(res, 401, { error: 'unauthenticated' })
      return json(res, 200, { owner: 'alice', note: 'private-note-42' })
    }
    return json(res, 404, { error: 'not found' })
  })
})

test.after(async () => {
  await toolFixture.close()
})

function attemptFactory(origin: string) {
  return createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions(nonce) {
      return {
        broker: new RequestBroker(),
        grant: grantFor(origin),
        runId: `run-v6-loop-${nonce.slice(0, 8)}`,
        assignmentId: 'assignment-v6-loop',
        targetOrigins: [origin],
      }
    },
  })
}

function scriptHandler(origin: string): GuardianVerifyHandler {
  const factory = attemptFactory(origin)
  return async args => {
    assert.ok(args.script, 'inline script expected')
    return verifyScript({
      candidate: { name: 'guardian-verify-tool.ts', runtime: args.runtime ?? 'ts', code: args.script },
      openAttempt: factory,
    })
  }
}

test('a real verification script flows through verifyScript and returns proof + transcript digest', async () => {
  const tool = toolByName(buildTools({ guardian_verify: scriptHandler(toolFixture.origin) }), 'guardian_verify')
  assert.ok(tool)
  const result = await invoke(tool!, {
    script: `
import { defineVerification, runVerification } from './guardian_verify.ts'

runVerification(defineVerification({
  async verify(ctx) {
    const denied = await ctx.http('/note', { as: 'bob' })
    const owner = await ctx.http('/note', { as: 'alice' })
    ctx.expect.status(denied, 403)
    ctx.expect.status(owner, 200)
    ctx.expect.jsonPath(owner, 'note', 'private-note-42')
    return ctx.result({ title: 'guardian_verify tool contract', severity: 'medium' })
  },
}))
`,
    runtime: 'ts',
    title: 'tool contract',
  })
  assert.equal(result.isError, undefined)
  const proof = JSON.parse(textOf(result)) as {
    confirmed: boolean
    reason: string
    transcriptDigest: string | null
    failures: string[]
    attempts: Array<{ oraclePassed: boolean; signaturesValid: boolean; exchangeCount: number; transcriptDigest: string }>
  }
  assert.equal(proof.confirmed, true, `${proof.reason}: ${proof.failures.join('; ')}`)
  assert.equal(proof.reason, 'confirmed')
  assert.match(proof.transcriptDigest ?? '', /^[a-f0-9]{64}$/)
  assert.equal(proof.failures.length, 0)
  assert.equal(proof.attempts.length, 2)
  assert.ok(proof.attempts.every(attempt => attempt.oraclePassed && attempt.signaturesValid && attempt.exchangeCount >= 2))
  assert.notEqual(proof.attempts[0].transcriptDigest, proof.attempts[1].transcriptDigest)
})

test('forged stdout and fabricated exchange ids never confirm through the tool', async () => {
  const tool = toolByName(buildTools({ guardian_verify: scriptHandler(toolFixture.origin) }), 'guardian_verify')
  assert.ok(tool)
  const result = await invoke(tool!, {
    script: `
import { writeFileSync } from 'node:fs'
console.log('{"confirmed":true,"claims":[]}')
writeFileSync(process.env.GUARDIAN_PROOF_RESULT_FILE!, JSON.stringify({
  title: 'forged note read',
  claims: [{ kind: 'status', exchangeId: 'gx-00000000-0000-0000-0000-000000000000', expected: 200 }],
}))
`,
    runtime: 'ts',
  })
  assert.equal(result.isError, undefined)
  const proof = JSON.parse(textOf(result)) as { confirmed: boolean; reason: string; failures: string[] }
  assert.equal(proof.confirmed, false)
  assert.equal(proof.reason, 'oracle_failed')
  assert.match(proof.failures.join(' '), /Unknown exchange|no recorded|not.*record/i)
})

// ---------------------------------------------------------------------------
// 3. Async OOB correlation
// ---------------------------------------------------------------------------

test('late OOB callback is promoted by the durable subscription (fake clock)', async () => {
  let clock = 1_700_000_000_000
  const broker = new CanaryBroker({ now: () => clock })
  const runId = 'run-late-oob'
  const assignmentId = 'assignment-late-oob'
  try {
    const minted = broker.mintCanary(runId, 'ssrf-late', toolFixture.origin, { assignmentId })
    const first = await awaitReplayCanary(broker, {
      runId, assignmentId, token: minted.token, canaryId: minted.id,
    }, { immediateMs: 1_000, budgetMs: 0, now: () => clock })
    assert.equal(first.triggered, false, 'no callback yet')
    assert.ok(first.subscriptionId, 'a durable pending_oob subscription must be registered')

    // Background worker fires 5 s after the immediate window.
    clock += 5_000
    broker.recordCallback({
      token: minted.token,
      runId,
      assignmentId,
      sourceIp: '127.0.0.1',
      method: 'GET',
      path: `/c/${minted.token}`,
      receivedAt: clock,
    })

    const second = await awaitReplayCanary(broker, {
      runId, assignmentId, token: minted.token, canaryId: minted.id,
    }, { immediateMs: 1_000, budgetMs: 0, now: () => clock })
    assert.equal(second.triggered, true)
    assert.equal(second.stage, 'late')
    assert.equal(second.promoted, true)
    assert.equal(broker.oob.subscription(second.subscriptionId!).status, 'promoted')
    assert.equal(broker.pending(runId).some(sub => sub.token === minted.token), false)
  } finally {
    await broker.stop()
  }
})

test('rce_proof oob_canary confirms through the subscription path (real relay)', async () => {
  const fx = await fixture(async (req, body, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/job' && req.method === 'POST') {
      const parsed = JSON.parse(body || '{}') as { mode?: string; url?: string }
      if (parsed.mode === 'exec' && parsed.url) {
        setTimeout(() => { void fetch(parsed.url!).catch(() => undefined) }, 250)
      }
      return json(res, 202, { queued: true })
    }
    return json(res, 404, { error: 'not found' })
  })
  const canaryBroker = new CanaryBroker()
  try {
    const origin = fx.origin
    const spec: Extract<DeclarativeReplaySpec, { kind: 'rce_proof' }> = {
      version: 1,
      kind: 'rce_proof',
      origin,
      title: 'Async OOB callback proof',
      category: 'injection-input',
      cwe: 'CWE-918',
      severity: 'high',
      severityRationale: 'Background worker performs an outbound fetch from a caller-controlled URL.',
      impact: 'Server-side request forgery with asynchronous callback.',
      remediation: 'Deny internal destinations and require an allowlist.',
      recheckInstructions: 'Replay control vs probe and observe the canary callback only on the probe.',
      proofMode: 'oob_canary',
      requiresTier3Approval: true,
      controlStep: {
        id: 'control', role: 'control', description: 'Inert job',
        request: { origin, method: 'POST', pathAndQuery: '/job', jsonBody: { mode: 'noop', url: '{{canary_url}}' }, followRedirects: false },
      },
      probeStep: {
        id: 'probe', role: 'probe', description: 'Callback job',
        request: { origin, method: 'POST', pathAndQuery: '/job', jsonBody: { mode: 'exec', url: '{{canary_url}}' }, followRedirects: false },
      },
      assertionsJq: `{
        controlPassed: (.control.status == 202 and (.proof.canaryControlTriggered == false)),
        confirmed: (.proof.canaryProbeTriggered == true),
        observed: ("probeCanary=" + (.proof.canaryProbeTriggered | tostring)),
        expected: "No outbound callback triggered"
      }`,
    }
    const result = await verifyReplaySpec({
      spec,
      broker: new RequestBroker(),
      canaryBroker,
      backend: new LocalJqBackend(),
      grant: grantFor(origin),
      signal: AbortSignal.timeout(30_000),
    })
    assert.equal(result.verdict, 'confirmed', result.outcome.reason ?? '')
    const proof = result.evidencePayload.proof as { canaryProbeTriggered?: boolean; canaryProbeStage?: string }
    assert.equal(proof.canaryProbeTriggered, true)
    assert.match(proof.canaryProbeStage ?? '', /immediate|late/)
  } finally {
    await canaryBroker.stop()
    await fx.close()
  }
})

test('no-relay path is unchanged: standalone canary listener still confirms', async () => {
  const fx = await fixture(async (req, body, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/job' && req.method === 'POST') {
      const parsed = JSON.parse(body || '{}') as { mode?: string; url?: string }
      if (parsed.mode === 'exec' && parsed.url) {
        void fetch(parsed.url).catch(() => undefined)
      }
      return json(res, 202, { queued: true })
    }
    return json(res, 404, { error: 'not found' })
  })
  try {
    const origin = fx.origin
    const spec: Extract<DeclarativeReplaySpec, { kind: 'rce_proof' }> = {
      version: 1,
      kind: 'rce_proof',
      origin,
      title: 'Standalone canary proof',
      category: 'injection-input',
      cwe: 'CWE-918',
      severity: 'high',
      severityRationale: 'Outbound fetch from caller-controlled URL.',
      impact: 'SSRF with callback.',
      remediation: 'Deny internal destinations.',
      recheckInstructions: 'Replay control vs probe.',
      proofMode: 'oob_canary',
      requiresTier3Approval: true,
      controlStep: {
        id: 'control', role: 'control', description: 'Inert job',
        request: { origin, method: 'POST', pathAndQuery: '/job', jsonBody: { mode: 'noop', url: '{{canary_url}}' }, followRedirects: false },
      },
      probeStep: {
        id: 'probe', role: 'probe', description: 'Callback job',
        request: { origin, method: 'POST', pathAndQuery: '/job', jsonBody: { mode: 'exec', url: '{{canary_url}}' }, followRedirects: false },
      },
      assertionsJq: `{
        controlPassed: (.control.status == 202),
        confirmed: (.proof.canaryProbeTriggered == true),
        observed: "standalone",
        expected: "no callback"
      }`,
    }
    const result = await verifyReplaySpec({
      spec,
      broker: new RequestBroker(),
      backend: new LocalJqBackend(),
      grant: grantFor(origin),
      signal: AbortSignal.timeout(30_000),
    })
    assert.equal(result.verdict, 'confirmed', result.outcome.reason ?? '')
    assert.equal((result.evidencePayload.proof as { canaryProbeTriggered?: boolean }).canaryProbeTriggered, true)
  } finally {
    await fx.close()
  }
})

// ---------------------------------------------------------------------------
// 4. Structural boolean/content diffing
// ---------------------------------------------------------------------------

function bigShell(nonce: string, role: string): string {
  const rows: string[] = []
  for (let i = 0; i < 220; i += 1) {
    rows.push(`<div class="row" data-field="field${i}"><span>value${i}</span><em>label${i}</em></div>`)
  }
  return `<!doctype html><html><head>
<meta name="csrf-token" content="${nonce}">
<meta name="build-signature" content="a1b2c3d4e5f60718">
<script>window.__STATE__={"role":"${role}","requestId":"${randomUUID()}","builtAt":"2026-01-02T03:04:05.678Z"}</script>
</head><body><main class="shell">${rows.join('')}</main></body></html>`
}

test('structural normalisation ignores rotating tokens but detects a real field delta', () => {
  const nonceA = randomUUID()
  const nonceB = randomUUID()
  const shellA = bigShell(nonceA, 'admin')
  const shellB = bigShell(nonceB, 'admin')
  const shellDelta = bigShell(nonceB, 'user')

  const normalized = normalizeStructuralTokens(shellA)
  assert.equal(normalized.includes(nonceA), false, 'CSRF nonce must be stripped')
  assert.equal(normalized.includes('2026-01-02T03:04:05.678Z'), false, 'ISO timestamp must be stripped')
  assert.equal(normalized.includes('<dynamic>'), true)
  assert.equal(normalizeStructuralTokens(`bare ${randomUUID()} id`).includes('<uuid>'), true)
  assert.equal(normalized.includes('<hex>'), true)

  assert.equal(structuralSimilarity(shellA, shellB), 1, 'rotating nonce/timestamp/uuid must not create a differential')
  const delta = structuralDiff(shellA, shellDelta)
  assert.ok(delta.similarity > 0.9, `large shells stay similar, got ${delta.similarity}`)
  assert.deepEqual(delta.changedTokens.sort(), ['admin', 'user'])
  assert.deepEqual(intersectStructuralDeltas([delta.changedTokens, delta.changedTokens]), ['admin', 'user'])
})

test('retired sql_boolean_diff without floorRecipe fails closed without executing legacy VM code', async () => {
  let hits = 0
  const fx = await fixture((_req, _body, res) => {
    hits += 1
    res.statusCode = 500
    res.end('should not be reached')
  })
  try {
    const origin = fx.origin
    const spec: Extract<DeclarativeReplaySpec, { kind: 'sql_boolean_diff' }> = {
      version: 1,
      kind: 'sql_boolean_diff',
      origin,
      targetOrigin: origin,
      title: 'Boolean differential in a large shell',
      category: 'injection-input',
      cwe: 'CWE-89',
      severity: 'high',
      severityRationale: 'True/false predicates change a stable response field while the shell is identical.',
      impact: 'Boolean-based SQL injection.',
      remediation: 'Use parameterized queries.',
      recheckInstructions: 'Replay the randomized triplets.',
      method: 'GET',
      pathAndQuery: '/shell',
      paramName: 'id',
      paramLocation: 'query',
      baselineValue: '1',
      quoteStyle: 'single',
      assertionsJq: `{
        controlPassed: (.sqlDiff.controlPassed == true),
        confirmed: (.sqlDiff.passed == true),
        observed: "stable field delta",
        expected: "no differential"
      }`,
    }
    const result = await verifyReplaySpec({
      spec,
      broker: new RequestBroker(),
      backend: new LocalJqBackend(),
      grant: grantFor(origin),
      signal: AbortSignal.timeout(30_000),
    })
    assert.equal(result.verdict, 'dismissed', result.outcome.reason ?? '')
    assert.equal(result.outcome.reason, 'retired_legacy_spec_kind: use guardian_verify')
    assert.equal(hits, 0)
  } finally {
    await fx.close()
  }
})
