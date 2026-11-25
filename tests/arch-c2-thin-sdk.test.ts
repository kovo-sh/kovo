/**
 * Architecture Wave 3 Proposal C2 — thin-client worker SDK.
 *
 * Defensive QA: differential probes against an intentional local loopback fixture. Verifies that
 *   1. the TS SDK stays within tight LOC budgets and carries zero duplicated statistics / structural
 *      normalization / oracle scoring (the host `verify-rpc.ts` is the single engine),
 *   2. every `ctx.prove_*` helper returns the authoritative host verdict (`prove.*` RPC), so the
 *      helper's `ok` can never diverge from the host transcript oracle, and
 *   3. TS helper calls flow end-to-end through `verifyScript()` fresh double runs.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
  createLocalAttemptFactory,
  evaluateClaims,
  verifyScript,
} from '../src/server/verify-rpc.ts'
import type { VerifyClaim } from '../src/server/verify-rpc.ts'
import { VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_DIR = join(REPO_ROOT, 'worker', 'kovo_verify')
const ALICE = 'alice-thin-sdk-secret-1'
const BOB = 'bob-thin-sdk-secret-2'

const state = { balance: 100, hardened: false, slot: 0 }

function json(res: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
  res.end(body)
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf8')
}

const fixture = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const who = req.headers['x-user'] === ALICE ? 'alice' : req.headers['x-user'] === BOB ? 'bob' : 'anon'
  if (url.pathname === '/items/1') {
    if (state.hardened || who !== 'alice') return json(res, who === 'anon' ? 401 : 403, { error: 'forbidden' })
    return json(res, 200, { owner: 'alice', item: 'item-1', private: 'alice-private-note-77' })
  }
  if (url.pathname === '/state/item') return json(res, 200, { owner: 'alice', balance: state.balance })
  if (url.pathname === '/state/mutate') {
    const parsed = JSON.parse(await readBody(req) || '{}') as { balance?: number }
    if (!state.hardened && typeof parsed.balance === 'number') state.balance = parsed.balance
    return json(res, 200, { ok: true })
  }
  if (url.pathname === '/diff') {
    const nonce = randomUUID()
    const admin = !state.hardened && url.searchParams.get('view') === 'admin'
    res.writeHead(200, { 'content-type': 'text/html' })
    return res.end(admin
      ? `<html><body data-request-id="${nonce}"><h1>Welcome administrator</h1><table id="panel"><tr><td>ledger</td></tr></table></body></html>`
      : `<html><body data-request-id="${nonce}"><p>Access denied</p></body></html>`)
  }
  if (url.pathname === '/race/redeem') {
    if (state.hardened) return json(res, 200, { ok: true })
    state.slot += 1
    return json(res, 200, { ok: true, slot: state.slot })
  }
  return json(res, 404, { error: 'not found' })
})

const port = await new Promise<number>((resolve, reject) => {
  fixture.once('error', reject)
  fixture.listen(0, '127.0.0.1', () => {
    const address = fixture.address()
    if (!address || typeof address === 'string') reject(new Error('no port'))
    else resolve(address.port)
  })
})
const origin = `http://127.0.0.1:${port}`
test.after(() => new Promise<void>(resolve => { fixture.closeAllConnections(); fixture.close(() => resolve()) }))

function persona(handle: string, secret: string): ResolvedPersona {
  return { id: `persona-${handle}`, handle, roleLabel: 'member (acme)', originAllowlist: [origin], authKind: 'header', headerName: 'X-User', secret, canaryMarkers: [] }
}

function makeGrant(): Grant {
  return {
    origin,
    tier: 2,
    allowLocalLab: true,
    allowedPorts: [port],
    maxRpsPerOrigin: 200,
    personas: new Map([['alice', persona('alice', ALICE)], ['bob', persona('bob', BOB)]]),
    canRead: candidate => candidate === origin,
    isStateChangeApproved: () => true,
    audit: () => {},
  }
}

const brokerFactory = () => new RequestBroker({ transportConfig: { http2: false } })

const factory = () => createLocalAttemptFactory({
  sdkDir: SDK_DIR,
  createRpcOptions: () => ({
    broker: brokerFactory(),
    grant: makeGrant(),
    runId: `run-thin-sdk-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assignment-thin-sdk',
    targetOrigins: [origin],
  }),
})

function reset(): void {
  state.balance = 100
  state.hardened = false
  state.slot = 0
}

const describeVerdict = (v: Awaited<ReturnType<typeof verifyScript>>) =>
  `${v.reason}: ${v.detail} | ${v.attempts.map(a => a.failures.join('; ') + ' | stderr=' + (a.stderr ?? '')).join(' || ')}`

// ---------------------------------------------------------------------------
// 1. Static budgets: thin SDKs, single host engine
// ---------------------------------------------------------------------------

test('thin SDK stays within LOC budget and carries zero duplicated stats/normalization/oracle scoring', () => {
  const ts = readFileSync(join(SDK_DIR, 'kovo_verify.ts'), 'utf8')
  const rpcSrc = readFileSync(join(REPO_ROOT, 'src/server/verify-rpc.ts'), 'utf8')
  const loc = (text: string) => text.trimEnd().split('\n').length
  assert.ok(loc(ts) <= 900, `kovo_verify.ts is ${loc(ts)} LOC (must be <= 900)`)

  for (const forbidden of [/\bmannWhitneyU\b/, /\bfunction erf\b/, /\bnormalCdf\b/, /\bfunction median\b/, /\bfunction mad\b/, /STRUCTURAL_[A-Z_]+_RE/, /normalizeStructuralTokens/, /\bchangedTokens\b/, /\btokenSet\b/]) {
    assert.equal(forbidden.test(ts), false, `kovo_verify.ts must not duplicate ${forbidden}`)
  }
  // TS SDK delegates every prove_* helper to the host `prove.*` RPCs.
  for (const op of ['prove.accessBoundary', 'prove.persistedMutation', 'prove.differential', 'prove.oob', 'prove.race', 'prove.injection']) {
    assert.ok(ts.includes(`'${op}'`), `kovo_verify.ts must call ${op}`)
    assert.ok(rpcSrc.includes(`op === '${op}'`), `verify-rpc.ts must dispatch ${op}`)
  }
  // Backward-compatible method names and aliases survive.
  for (const method of ['prove_access_boundary(', 'proveAccessBoundary(', 'prove_persisted_mutation(', 'prove_boolean_or_timing_diff(', 'prove_oob_callback(', 'prove_race_burst(', 'prove_injection_differential(', 'prove_composite(', 'proveComposite(', 'seal_capability(', 'hmac_sign(', 'jwt_sign(', 'await_async(']) {
    assert.ok(ts.includes(method), `kovo_verify.ts missing ${method}`)
  }
})

// ---------------------------------------------------------------------------
// 2. Helper verdict == host oracle verdict (no "SDK passed, host rejected")
// ---------------------------------------------------------------------------

function bindEnv(server: VerifyRpcServer): () => void {
  const keys = [VERIFY_RPC_SOCKET_ENV, VERIFY_RPC_TOKEN_ENV, VERIFY_RPC_CONTEXT_ENV, VERIFY_NONCE_ENV] as const
  const previous = keys.map(key => process.env[key])
  process.env[VERIFY_RPC_SOCKET_ENV] = server.socketPath
  process.env[VERIFY_RPC_TOKEN_ENV] = join(server.hostDir, 'token')
  process.env[VERIFY_RPC_CONTEXT_ENV] = join(server.hostDir, 'context.json')
  process.env[VERIFY_NONCE_ENV] = server.nonce
  return () => keys.forEach((key, i) => { if (previous[i] === undefined) delete process.env[key]; else process.env[key] = previous[i] })
}

test('every prove_* helper verdict matches the host transcript oracle on vulnerable and hardened fixtures', async () => {
  reset()
  const server = new VerifyRpcServer({
    broker: brokerFactory(),
    grant: makeGrant(),
    runId: 'run-thin-sdk-direct',
    assignmentId: 'assignment-thin-sdk-direct',
    nonce: randomUUID().replace(/-/g, ''),
    targetOrigins: [origin],
  })
  await server.start()
  const restore = bindEnv(server)
  try {
    const ctx = new VerifyContext()
    const agree = (ok: boolean, claims: VerifyClaim[] | VerifyClaim) => {
      const oracle = evaluateClaims(server.transcript, Array.isArray(claims) ? claims : [claims])
      assert.equal(ok, oracle.passed, `helper ok=${ok} must equal host oracle passed=${oracle.passed}: ${oracle.failures.join('; ')}`)
    }
    for (const hardened of [false, true]) {
      state.hardened = hardened
      const boundary = await ctx.prove_access_boundary({ controlPersona: 'bob', probePersona: 'alice', route: '/items/1' })
      assert.equal(boundary.ok, !hardened, boundary.missingEvidence.join(','))
      assert.equal(boundary.confirmed, boundary.ok)
      if (hardened) assert.deepEqual(boundary.missingEvidence, ['variant_crossed'])
      agree(boundary.ok, boundary.claim as unknown as VerifyClaim)

      const diff = await ctx.prove_boolean_or_timing_diff({ control: '/diff?view=user', variant: '/diff?view=admin', mode: 'boolean', rounds: 3 })
      assert.equal(diff.ok, !hardened, diff.missingEvidence.join(','))
      agree(diff.ok, diff.claim as unknown as VerifyClaim)

      state.slot = 0
      const race = await ctx.prove_race_burst({ requests: ['/race/redeem', '/race/redeem'] })
      assert.equal(race.mode, 'http1-fallback')
      assert.equal(race.ok, !hardened, race.missingEvidence.join(','))
      if (hardened) assert.ok(race.missingEvidence.includes('duplicate_effect'))
      agree(race.ok, race.claim as unknown as VerifyClaim)
    }

    state.hardened = false
    const mutation = await ctx.prove_persisted_mutation({
      readRoute: '/state/item',
      mutation: { target: '/state/mutate', method: 'POST', body: JSON.stringify({ balance: 999 }), as: 'alice' },
      fieldPath: 'balance',
      expectDelta: 999,
      readPersona: 'alice',
    })
    assert.equal(mutation.ok, true, mutation.missingEvidence.join(','))
    assert.equal(mutation.delta.before, 100)
    assert.equal(mutation.delta.after, 999)
    assert.deepEqual(mutation.transcriptSummary.map(e => e.role), ['before_get', 'mutation', 'after_get'])
    // A custom predicate stays client-side but can only downgrade the host verdict, never upgrade it.
    const strict = await ctx.prove_persisted_mutation({
      readRoute: '/state/item',
      mutation: { target: '/state/mutate', method: 'POST', body: { balance: 1234 }, as: 'alice' },
      fieldPath: 'balance',
      expectDelta: (_before: unknown, after: unknown) => after === -1,
      readPersona: 'alice',
    })
    assert.equal(strict.ok, false)
    assert.ok(strict.missingEvidence.includes('expected_delta'))

    // Malformed race input fails closed with the host's repair token (and records no claim).
    const before = ctx.claims.length
    const malformed = await ctx.prove_race_burst({ requests: ['/race/redeem'] })
    assert.equal(malformed.ok, false)
    assert.deepEqual(malformed.missingEvidence, ['race_requests'])
    assert.equal(ctx.claims.length, before)
  } finally {
    restore()
    await server.close()
  }
})

// ---------------------------------------------------------------------------
// 3. End-to-end verifyScript() fresh double runs: TS
// ---------------------------------------------------------------------------

test('TS SDK prove_access_boundary / prove_persisted_mutation / prove_boolean_or_timing_diff / prove_race_burst confirm through verifyScript()', async () => {
  const cases: Array<{ name: string; code: string }> = [
    {
      name: 'boundary.ts',
      code: `
const proof = await ctx.prove_access_boundary({ controlPersona: 'bob', probePersona: 'alice', route: '/items/1' })
if (!proof.ok || proof.confirmed !== true) throw new Error(proof.missingEvidence.join(','))
return ctx.result({ title: 'BOLA access-control boundary' })
`,
    },
    {
      name: 'mutation.ts',
      code: `
const value = Date.now() % 1000000
const proof = await ctx.prove_persisted_mutation({
  readRoute: '/state/item',
  mutation: { target: '/state/mutate', method: 'POST', body: { balance: value }, as: 'alice' },
  fieldPath: 'balance',
  expectDelta: value,
  read_persona: 'alice',
})
if (!proof.ok) throw new Error(proof.missingEvidence.join(','))
return ctx.result({ title: 'Mass assignment balance overwrite' })
`,
    },
    {
      name: 'diff.ts',
      code: `
const proof = await ctx.prove_boolean_or_timing_diff({ control: '/diff?view=user', variant: { path: '/diff?view=admin' }, mode: 'boolean', rounds: 3 })
if (!proof.ok) throw new Error(proof.missingEvidence.join(','))
return ctx.result({ title: 'Admin view boolean differential' })
`,
    },
    {
      name: 'race.ts',
      code: `
const proof = await ctx.prove_race_burst({ requests: [{ path: '/race/redeem', method: 'GET', as: 'alice' }, { path: '/race/redeem', method: 'GET', as: 'alice' }] })
if (!proof.ok) throw new Error(proof.missingEvidence.join(','))
return ctx.result({ title: 'Concurrent duplicate redemption burst' })
`,
    },
  ]
  for (const candidate of cases) {
    reset()
    const verdict = await verifyScript({ candidate: { ...candidate, runtime: 'ts' }, openAttempt: factory() })
    assert.equal(verdict.confirmed, true, `${candidate.name}: ${describeVerdict(verdict)}`)
    assert.equal(verdict.rejectedBy, null)
    assert.ok(verdict.attempts.every(a => a.claimCount >= 1))
  }
})

test('TS prove_composite returns the authoritative host verdict and auto-records the host-signed claim (never claims_missing)', async () => {
  const receipt = (exchangeVar: string, originVar: string) => `{
    chainId: 'chain-thin-sdk-single-hop',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [{ hopId: 'hop_1', surface: 'http', target: { origin: ${originVar}, method: 'GET', pathAndQuery: '/items/1' }, exchangeIds: [${exchangeVar}], claimedDelta: 'Read item as owner.' }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'hop_1', summary: 'Single-hop read without any denied control or pivot.', terminalExchangeId: ${exchangeVar} },
    replayMode: 'fresh_clean_replay',
  }`
  reset()
  const tsVerdict = await verifyScript({
    candidate: {
      name: 'composite.ts',
      runtime: 'ts',
      code: `
const h1 = await ctx.http_send('/items/1', { as: 'alice', role: 'probe' })
const verdict = await ctx.prove_composite(${receipt('h1.exchangeId', 'ctx.targetOrigin')})
if (verdict.ok !== false || verdict.confirmed !== false) throw new Error('expected host rejection')
if (!verdict.claim || !String(verdict.claim.verificationId).startsWith('gc-')) throw new Error('claim must come from host composite.verify')
if (!verdict.rejectedBy || !verdict.missingEvidence?.length) throw new Error('host must name rejectedBy + missingEvidence')
return ctx.result({ title: 'Single-hop composite (expected rejection)' })
`,
    },
    openAttempt: factory(),
  })
  assert.equal(tsVerdict.confirmed, false)
  assert.equal(tsVerdict.reason, 'oracle_failed', describeVerdict(tsVerdict))
  assert.ok(tsVerdict.rejectedBy && tsVerdict.rejectedBy !== 'claims')
  assert.ok(tsVerdict.attempts.every(a => a.claimCount === 1))
})
