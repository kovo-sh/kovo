/**
 * CLAUDE_AUDIT Tier 2 — Receipt Kernel & Verifier Hardening Tests:
 *  - C-5:  Conserved-balance / race receipt deterministic host ordering, host requestBody,
 *          temporal concurrency overlap, and host-derived/bounded unitDebit.
 *  - H-5:  Reject untrusted model-supplied recipe/agentScript envelopes & enforce scope/Tier-0/
 *          carrier boundaries on static_ast_proof.
 *  - H-13: Impact oracles derive requestBody, ambient auth, SameSite, and oracleEvents strictly
 *          from host-recorded exchanges/headers (never script-declared claims).
 *  - H-14: auth_bypass rejects sealed capabilities, session jars/cookies, admin/higher-role
 *          personas, login-issued tokens, and non-security header differentials.
 *  - H-15: Timing differential (`blind_sqli`) requires exact same normalized origin, method,
 *          route, and persona across control and probe arms.
 *  - H-18: Confirmed finding identity (cwe, origin, endpoint/fingerprint, title) is bound to the
 *          confirming spec/receipt and immutable against post-confirmation edits.
 *  - H-20: `buildAgentScriptReceipt` supports `claim.kind === 'oob'` via `buildOobReceipt` with
 *          host OOB events and mint/injection/wait exchange IDs.
 *  - H-32: Structural ReDoS guard rejects nested quantifiers, quantified alternations, >256-char
 *          patterns, and caps haystack length in `replay-verifier.ts`.
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { once } from 'node:events'
import { test } from 'node:test'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import type { Finding } from '../src/domain.ts'
import { RequestBroker } from '../src/server/broker.ts'
import {
  bindConfirmedFindingIdentity,
  guardConfirmedFindingMutation,
} from '../src/server/exec-verify.ts'
import {
  buildAgentScriptReceipt,
  buildProofReceipt,
  defaultHostMintedOracle,
  verifyReceipt,
  type ImpactStep,
  type ReceiptOobEvent,
  type ReceiptTranscript,
  type ReceiptTranscriptEntry,
  type ScriptProofExchange,
} from '../src/server/proof-receipt.ts'
import {
  MAX_REPLAY_REGEX_HAYSTACK_LENGTH,
  MAX_REPLAY_REGEX_PATTERN_LENGTH,
  isSafeRegexPattern,
  retestReplaySpec,
  safeRegexTest,
  verifyReplaySpec,
  type ReplayVerificationResult,
} from '../src/server/replay-verifier.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'https://app.example.invalid'
const OTHER_ORIGIN = 'https://other.example.invalid'

function mkStep(overrides: Partial<ImpactStep> & { id: string; arm: ImpactStep['arm']; method: string; status: number | null }): ImpactStep {
  return {
    route: '/api/v1/wallets/1/redeem',
    pathAndQuery: '/api/v1/wallets/1/redeem',
    actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null },
    ...overrides,
  }
}

// ============================================================================
// C-5: Conserved-balance / race receipt hardening
// ============================================================================

test('C-5: conserved_balance confirms genuine overlapping burst with host requestBody & serial debit, and rejects swapped order / non-overlapping burst / forged requestBody / inflated unitDebit / role reuse', () => {
  // Positive: overlapping burst windows, chronological host seq, host-stamped raceBatchId & requestBody
  const validExchanges: ScriptProofExchange[] = [
    { exchangeId: 'pre', seq: 1, startedAt: 1000, endedAt: 1015, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":100}' },
    { exchangeId: 'b1', seq: 2, op: 'race', raceBatchId: 'batch-c5-1', startedAt: 1050, endedAt: 1120, durationMs: 70, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'b2', seq: 3, op: 'race', raceBatchId: 'batch-c5-1', startedAt: 1052, endedAt: 1125, durationMs: 73, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'post', seq: 4, startedAt: 1150, endedAt: 1165, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":90}' },
    { exchangeId: 's1', seq: 5, startedAt: 1200, endedAt: 1230, durationMs: 30, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'spost', seq: 6, startedAt: 1250, endedAt: 1265, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":80}' },
  ]
  const validBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Concurrent wallet redeem under-debit',
    exchanges: validExchanges,
    claims: [{
      kind: 'race',
      vulnClass: 'race_double_spend',
      baselineExchangeId: 'pre',
      burstExchangeIds: ['b2', 'b1'], // worker supplies reverse order; kernel must sort by host seq
      postExchangeId: 'post',
      serialExchangeIds: ['s1'],
      serialPostExchangeId: 'spost',
      balanceField: 'balance',
    }],
  })
  assert.ok(validBuilt)
  assert.deepEqual(validBuilt.receipt.exchangeIds, ['pre', 'b1', 'b2', 'post', 's1', 'spost'])
  const validVerdict = verifyReceipt(validBuilt.receipt, validBuilt.transcript)
  assert.equal(validVerdict.confirmed, true, validVerdict.reason)
  assert.equal(validVerdict.evidence?.violationKind, 'under_debit')

  // Negative 1: Swapped baseline/post timestamps & host seq (worker claims later read is baseline and earlier read is post)
  const swappedExchanges: ScriptProofExchange[] = [
    { exchangeId: 'early', seq: 1, startedAt: 1000, endedAt: 1015, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":90}' },
    { exchangeId: 'b1', seq: 2, op: 'race', raceBatchId: 'batch-c5-swap', startedAt: 1050, endedAt: 1120, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'b2', seq: 3, op: 'race', raceBatchId: 'batch-c5-swap', startedAt: 1051, endedAt: 1122, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'late', seq: 4, startedAt: 1150, endedAt: 1165, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":100}' },
    { exchangeId: 's1', seq: 5, startedAt: 1200, endedAt: 1220, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'spost', seq: 6, startedAt: 1250, endedAt: 1265, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":90}' },
  ]
  const swappedBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Swapped baseline/post must fail',
    exchanges: swappedExchanges,
    claims: [{
      kind: 'race',
      baselineExchangeId: 'late',
      burstExchangeIds: ['b1', 'b2'],
      postExchangeId: 'early',
      serialExchangeIds: ['s1'],
      serialPostExchangeId: 'spost',
      balanceField: 'balance',
    }],
  })
  assert.ok(swappedBuilt)
  const swappedVerdict = verifyReceipt(swappedBuilt.receipt, swappedBuilt.transcript)
  assert.equal(swappedVerdict.confirmed, false, 'swapped baseline/post must be rejected by host ordering')
  assert.match(swappedVerdict.reason, /chronologically before|chronologically after/i)

  // Negative 2: Worker tries to override host requestBody and inflate unitDebit on a CONSERVED wallet
  const conservedExchanges: ScriptProofExchange[] = [
    { exchangeId: 'pre', seq: 1, startedAt: 1000, endedAt: 1015, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":100}' },
    { exchangeId: 'b1', seq: 2, op: 'race', raceBatchId: 'batch-c5-cons', startedAt: 1050, endedAt: 1110, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'b2', seq: 3, op: 'race', raceBatchId: 'batch-c5-cons', startedAt: 1052, endedAt: 1115, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'post', seq: 4, startedAt: 1150, endedAt: 1165, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":80}' },
    { exchangeId: 's1', seq: 5, startedAt: 1200, endedAt: 1220, method: 'POST', pathAndQuery: '/api/v1/wallet/redeem', origin: ORIGIN, status: 200, requestBody: '{"amount":10}', body: '{"ok":true}' },
    { exchangeId: 'spost', seq: 6, startedAt: 1250, endedAt: 1265, method: 'GET', pathAndQuery: '/api/v1/wallet', origin: ORIGIN, status: 200, body: '{"balance":70}' },
  ]
  const spoofDebitBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Spoofed requestBody and unitDebit on conserved wallet',
    exchanges: conservedExchanges,
    claims: [{
      kind: 'race',
      baselineExchangeId: 'pre',
      burstExchangeIds: ['b1', 'b2'],
      postExchangeId: 'post',
      serialExchangeIds: ['s1'],
      serialPostExchangeId: 'spost',
      balanceField: 'balance',
      requestBody: { amount: 50 },
      unitDebit: 50,
    }],
  })
  assert.ok(spoofDebitBuilt)
  const spoofDebitVerdict = verifyReceipt(spoofDebitBuilt.receipt, spoofDebitBuilt.transcript)
  assert.equal(spoofDebitVerdict.confirmed, false, 'worker requestBody/unitDebit must never override host exchanges')

  // Negative 3: Uncorroborated unitDebit inflation with 4xx serial rejection (no host requestBody debit)
  const inflatedUnitTranscript: ReceiptTranscript = {
    entries: [
      { exchangeId: 'pre', seq: 1, startedAt: 1000, endedAt: 1010, evidenceRole: 'baseline_read', step: mkStep({ id: 'pre', arm: 'setup', method: 'GET', status: 200, json: { balance: 100 } }) },
      { exchangeId: 'b1', seq: 2, startedAt: 1050, endedAt: 1100, evidenceRole: 'burst_1', step: mkStep({ id: 'b1', arm: 'probe', method: 'POST', status: 200, json: { ok: true } }) },
      { exchangeId: 'b2', seq: 3, startedAt: 1055, endedAt: 1105, evidenceRole: 'burst_2', step: mkStep({ id: 'b2', arm: 'probe', method: 'POST', status: 200, json: { ok: true } }) },
      { exchangeId: 'post', seq: 4, startedAt: 1150, endedAt: 1160, evidenceRole: 'post_read', step: mkStep({ id: 'post', arm: 'control', method: 'GET', status: 200, json: { balance: 80 } }) },
      { exchangeId: 's1', seq: 5, startedAt: 1200, endedAt: 1220, evidenceRole: 'serial_control_1', step: mkStep({ id: 's1', arm: 'control', method: 'POST', status: 409, json: { error: 'limit reached' } }) },
    ],
  }
  const inflatedUnitReceipt = buildProofReceipt({
    vulnClass: 'race_double_spend',
    target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/wallets/1/redeem' },
    exchangeIds: ['pre', 'b1', 'b2', 'post', 's1'],
    claimedDelta: 'Claimed 50 per debit with 409 serial rejection.',
    conservedBalance: { balanceField: 'balance', unitDebit: 50 },
  })
  const inflatedUnitVerdict = verifyReceipt(inflatedUnitReceipt, inflatedUnitTranscript)
  assert.equal(inflatedUnitVerdict.confirmed, false, 'uncorroborated unitDebit with 4xx serial rejection must not confirm under_debit')

  // Negative 4: Strictly non-overlapping (sequential) burst timestamps rejected
  const sequentialExchanges = validExchanges.map(ex =>
    ex.exchangeId === 'b1' ? { ...ex, startedAt: 1050, endedAt: 1080, durationMs: 30 }
      : ex.exchangeId === 'b2' ? { ...ex, startedAt: 1200, endedAt: 1230, durationMs: 30 }
        : ex.exchangeId === 'post' ? { ...ex, startedAt: 1300, endedAt: 1310 }
          : ex.exchangeId === 's1' ? { ...ex, startedAt: 1400, endedAt: 1420 }
            : ex.exchangeId === 'spost' ? { ...ex, startedAt: 1450, endedAt: 1460 }
              : ex,
  )
  const seqBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Sequential non-overlapping requests are not a race',
    exchanges: sequentialExchanges,
    claims: [{
      kind: 'race',
      baselineExchangeId: 'pre',
      burstExchangeIds: ['b1', 'b2'],
      postExchangeId: 'post',
      serialExchangeIds: ['s1'],
      serialPostExchangeId: 'spost',
      balanceField: 'balance',
    }],
  })
  assert.ok(seqBuilt)
  const seqVerdict = verifyReceipt(seqBuilt.receipt, seqBuilt.transcript)
  assert.equal(seqVerdict.confirmed, false, 'non-overlapping sequential burst must be rejected')
  assert.match(seqVerdict.reason, /did not overlap in time/i)

  // Negative 5: Role aliasing (reusing exchange ID across roles) rejected
  const aliasedBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Aliased exchange ID across baseline and post',
    exchanges: validExchanges,
    claims: [{
      kind: 'race',
      baselineExchangeId: 'pre',
      burstExchangeIds: ['b1', 'b2'],
      postExchangeId: 'pre',
      serialExchangeIds: ['s1'],
    }],
  })
  assert.equal(aliasedBuilt, null, 'reused exchange ID across roles must not build a race receipt')
})

// ============================================================================
// H-5: Untrusted recipe/agentScript envelopes & static_ast_proof boundaries
// ============================================================================

test('H-5: replay-verifier rejects untrusted recipe/agentScript envelopes and enforces scope/Tier-0/carrier checks on static_ast_proof', async (t) => {
  let requestsSent = 0
  const server = createServer((req, res) => {
    requestsSent += 1
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    res.setHeader('content-type', 'application/json')
    const q = url.searchParams.get('q') ?? ''
    const rows = /AND\s+1\s*=\s*2/i.test(q) ? [] : [{ id: 1 }]
    res.end(JSON.stringify({ rows }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`
  t.after(() => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) }))

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const backend = new LocalJqBackend()
  const grant = makeLabGrant(origin, { tier: 3 })
  const tier0Grant = makeLabGrant(origin, { tier: 0 })
  const outOfScopeGrant = makeLabGrant(OTHER_ORIGIN, { tier: 3 })
  const signal = AbortSignal.timeout(10_000)

  const boolRecipe = {
    recipeId: 'boolean_or_timing' as const,
    args: {
      origin,
      method: 'GET',
      pathAndQuery: '/search?q=ok',
      controlPathAndQuery: `/search?q=${encodeURIComponent("ok' AND 1=1-- -")}`,
      probePathAndQuery: `/search?q=${encodeURIComponent("ok' AND 1=2-- -")}`,
      param: 'q',
      vulnClass: 'sqli',
      mode: 'boolean',
      rounds: 2,
    },
  }

  const baseSpecFields = {
    version: 1 as const,
    origin,
    title: 'Boolean differential test',
    category: 'injection-input',
    cwe: 'CWE-89',
    severity: 'high' as const,
    severityRationale: 'SQL predicate changes response rows.',
    impact: 'Query logic altered.',
    remediation: 'Use parameterized queries.',
    recheckInstructions: 'Replay predicate differential.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
  }

  const sqlBoolSpec = {
    ...baseSpecFields,
    kind: 'sql_boolean_diff' as const,
    targetOrigin: origin,
    method: 'GET' as const,
    pathAndQuery: '/search?q=ok',
    paramName: 'q',
    recipe: boolRecipe,
  }

  // 1. Negative: Untrusted model-supplied recipe envelope is refused without sending live traffic
  const untrustedRes = await verifyReplaySpec({
    spec: sqlBoolSpec,
    broker,
    backend,
    grant,
    signal,
    envelopeTrust: 'untrusted',
  })
  assert.equal(untrustedRes.verdict, 'inconclusive')
  assert.match(untrustedRes.outcome.reason ?? '', /Untrusted model-supplied recipe/i)
  assert.equal(requestsSent, 0)

  const staticBase = {
    ...baseSpecFields,
    kind: 'static_ast_proof' as const,
    repo: 'demo-repo',
    file: 'src/app.ts',
    startLine: 1,
    endLine: 5,
    engine: 'opengrep' as const,
    ruleOrPattern: 'db.query($X)',
    sourceToSinkTrace: 'req.query.q -> db.query',
    runtimeProofGap: 'Offline static check.',
  }

  // 2. Negative: static_ast_proof carrying a live recipe envelope is refused
  const staticSmuggleRes = await verifyReplaySpec({
    spec: { ...staticBase, recipe: boolRecipe },
    broker,
    backend,
    grant,
    signal,
  })
  assert.equal(staticSmuggleRes.verdict, 'inconclusive')
  assert.match(staticSmuggleRes.outcome.reason ?? '', /static_ast_proof cannot carry/i)
  assert.equal(requestsSent, 0)

  // 3. Negative: static_ast_proof with out-of-scope origin is rejected by scope check
  const staticScopeRes = await verifyReplaySpec({
    spec: staticBase,
    broker,
    backend,
    grant: outOfScopeGrant,
    signal,
  })
  assert.equal(staticScopeRes.verdict, 'inconclusive')
  assert.match(staticScopeRes.outcome.reason ?? '', /not in approved scope/i)

  // 4. Negative: recipe envelope blocked in Tier 0
  const tier0Res = await verifyReplaySpec({
    spec: sqlBoolSpec,
    broker,
    backend,
    grant: tier0Grant,
    signal,
  })
  assert.equal(tier0Res.verdict, 'inconclusive')
  assert.match(tier0Res.outcome.reason ?? '', /Tier 0/i)
  assert.equal(requestsSent, 0)

  // 5. Negative: cross-route boolean_or_timing recipe args rejected
  const crossRouteRecipeRes = await verifyReplaySpec({
    spec: {
      ...sqlBoolSpec,
      recipe: {
        recipeId: 'boolean_or_timing',
        args: {
          ...boolRecipe.args,
          controlPathAndQuery: '/api/fast?q=ok',
          probePathAndQuery: '/api/slow-export?q=ok',
          mode: 'timing',
          vulnClass: 'blind_sqli',
        },
      },
    },
    broker,
    backend,
    grant,
    signal,
  })
  assert.equal(crossRouteRecipeRes.verdict, 'inconclusive')
  assert.match(crossRouteRecipeRes.outcome.reason ?? '', /control route.*does not match probe route/i)
  assert.equal(requestsSent, 0)

  // 6. Negative: retestReplaySpec rejects untrusted agentScript envelope (inconclusive, never 'fixed'!)
  const untrustedScriptRetest = await retestReplaySpec({
    spec: {
      ...baseSpecFields,
      kind: 'http_chain',
      steps: [
        { id: 'c', role: 'control', description: 'c', request: { origin, method: 'GET', pathAndQuery: '/search?q=ok', followRedirects: false } },
        { id: 'p', role: 'probe', description: 'p', request: { origin, method: 'GET', pathAndQuery: '/search?q=ok', followRedirects: false } },
      ],
      agentScript: {
        kind: 'agent_script',
        runtime: 'ts',
        script: 'return { ok: false, claims: [] }',
        scriptSha256: 'a'.repeat(64),
        verdict: 'confirmed',
        exchangeIds: [],
        transcriptDigests: [],
        confirmedAt: Date.now(),
      },
    },
    broker,
    backend,
    grant,
    signal,
    envelopeTrust: 'untrusted',
  })
  assert.equal(untrustedScriptRetest.verdict, 'inconclusive')
  assert.match(untrustedScriptRetest.replay.outcome.reason ?? '', /Untrusted model-supplied agentScript/i)

  // 7. Positive: host-persisted boolean_or_timing recipe on same route in Tier 3 confirms cleanly
  const trustedRes = await verifyReplaySpec({
    spec: sqlBoolSpec,
    broker,
    backend,
    grant,
    signal,
    envelopeTrust: 'host_persisted',
  })
  assert.equal(trustedRes.verdict, 'confirmed', trustedRes.outcome.reason ?? '')
  assert.ok(requestsSent >= 4)
})

// ============================================================================
// H-13: Host-derived requestBody, ambient auth, SameSite, and oracleEvents
// ============================================================================

test('H-13: impact receipts ignore script-declared requestBody, ambient, SameSite, and oracleEvents and derive them strictly from host exchanges', () => {
  // Negative 1: Bearer-token write with SameSite=Strict cookie in host headers cannot spoof CSRF via claim fields
  const bearerExchanges: ScriptProofExchange[] = [
    {
      exchangeId: 'pre', seq: 1, method: 'GET', pathAndQuery: '/api/v1/profile', origin: ORIGIN, status: 200,
      personaHandle: 'alice', actorRoleLabel: 'member (acme)',
      requestHeaders: { authorization: 'Bearer tok_alice_real' },
      responseHeaders: { 'set-cookie': 'sid=abc123; HttpOnly; SameSite=Strict' },
      body: '{"email":"alice@acme.example"}',
    },
    {
      exchangeId: 'prb', seq: 2, method: 'POST', pathAndQuery: '/api/v1/profile', origin: ORIGIN, status: 200,
      personaHandle: 'alice', actorRoleLabel: 'member (acme)',
      requestHeaders: { authorization: 'Bearer tok_alice_real', origin: 'https://evil.example.invalid' },
      requestBody: '{"email":"changed@acme.example"}',
      body: '{"email":"changed@acme.example"}',
    },
    {
      exchangeId: 'post', seq: 3, method: 'GET', pathAndQuery: '/api/v1/profile', origin: ORIGIN, status: 200,
      personaHandle: 'alice', actorRoleLabel: 'member (acme)',
      requestHeaders: { authorization: 'Bearer tok_alice_real' },
      body: '{"email":"changed@acme.example"}',
    },
  ]
  const spoofCsrf = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Spoofed CSRF over bearer auth',
    exchanges: bearerExchanges,
    claims: [{
      kind: 'impact',
      impactClass: 'csrf',
      vulnClass: 'csrf',
      beforeExchangeId: 'pre',
      probeExchangeId: 'prb',
      afterExchangeId: 'post',
      ambient: { kind: 'cookie', sameSite: 'None' },
      oracleEvents: ['csrf_state_change'],
      requestBody: { email: 'spoofed@evil.invalid' },
    }],
  })
  assert.ok(spoofCsrf)
  assert.equal(spoofCsrf.receipt.oracleEvents, undefined, 'script-declared oracleEvents must not be copied to receipt')
  const prbEntry = spoofCsrf.transcript.entries!.find(e => e.exchangeId === 'prb')!
  assert.equal(prbEntry.step.actor.auth, 'bearer', 'ambient auth must be derived from host headers, not claim.ambient')
  assert.equal(prbEntry.step.actor.sameSite, 'Strict', 'SameSite must be derived from host Set-Cookie, not claim.ambient')
  assert.deepEqual(prbEntry.step.requestJson, { email: 'changed@acme.example' }, 'requestJson must come from host requestBody')
  const spoofCsrfVerdict = verifyReceipt(spoofCsrf.receipt, spoofCsrf.transcript)
  assert.equal(spoofCsrfVerdict.confirmed, false, 'bearer-token write must not confirm CSRF even when claim spoofs cookie/None/oracleEvents')

  // Negative 2: Mass assignment cannot spoof requestBody to claim a protected field was injected
  const massExchanges: ScriptProofExchange[] = [
    {
      exchangeId: 'pre', seq: 1, method: 'GET', pathAndQuery: '/api/v1/users/1', origin: ORIGIN, status: 200,
      personaHandle: 'alice', actorRoleLabel: 'member (acme)', body: '{"id":"1","note":"old","role":"member"}',
    },
    {
      exchangeId: 'prb', seq: 2, method: 'PATCH', pathAndQuery: '/api/v1/users/1', origin: ORIGIN, status: 200,
      personaHandle: 'alice', actorRoleLabel: 'member (acme)',
      requestBody: '{"note":"new"}',
      body: '{"id":"1","note":"new","role":"admin"}',
    },
    {
      exchangeId: 'post', seq: 3, method: 'GET', pathAndQuery: '/api/v1/users/1', origin: ORIGIN, status: 200,
      personaHandle: 'alice', actorRoleLabel: 'member (acme)', body: '{"id":"1","note":"new","role":"admin"}',
    },
  ]
  const spoofMass = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Spoofed mass assignment requestBody',
    exchanges: massExchanges,
    claims: [{
      kind: 'impact',
      impactClass: 'mass_assignment',
      vulnClass: 'mass_assignment',
      beforeExchangeId: 'pre',
      probeExchangeId: 'prb',
      afterExchangeId: 'post',
      requestBody: { role: 'admin' },
      oracleEvents: ['mass_assignment'],
    }],
  })
  assert.ok(spoofMass)
  const massPrb = spoofMass.transcript.entries!.find(e => e.exchangeId === 'prb')!
  assert.deepEqual(massPrb.step.requestJson, { note: 'new' })
  const spoofMassVerdict = verifyReceipt(spoofMass.receipt, spoofMass.transcript)
  assert.equal(spoofMassVerdict.confirmed, false, 'mass_assignment must fail when host requestBody did not send the protected field')

  // Positive: Real cookie-authenticated CSRF with host Set-Cookie SameSite=None and foreign Origin confirms
  const realCsrfExchanges: ScriptProofExchange[] = [
    {
      exchangeId: 'pre', seq: 1, method: 'GET', pathAndQuery: '/api/v1/profile', origin: ORIGIN, status: 200,
      personaHandle: 'alice', actorRoleLabel: 'member (acme)',
      requestHeaders: { cookie: 'sid=sess_real_123' },
      responseHeaders: { 'set-cookie': 'sid=sess_real_123; Path=/; SameSite=None; Secure' },
      body: '{"email":"alice@acme.example"}',
    },
    {
      exchangeId: 'prb', seq: 2, method: 'POST', pathAndQuery: '/api/v1/profile', origin: ORIGIN, status: 200,
      personaHandle: 'alice', actorRoleLabel: 'member (acme)',
      requestHeaders: { cookie: 'sid=sess_real_123', origin: 'https://attacker.example.invalid' },
      requestBody: '{"email":"pwned@attacker.invalid"}',
      body: '{"email":"pwned@attacker.invalid"}',
    },
    {
      exchangeId: 'post', seq: 3, method: 'GET', pathAndQuery: '/api/v1/profile', origin: ORIGIN, status: 200,
      personaHandle: 'alice', actorRoleLabel: 'member (acme)',
      requestHeaders: { cookie: 'sid=sess_real_123' },
      body: '{"email":"pwned@attacker.invalid"}',
    },
  ]
  const realCsrf = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Real cookie CSRF with SameSite=None',
    exchanges: realCsrfExchanges,
    claims: [{
      kind: 'impact',
      impactClass: 'csrf',
      vulnClass: 'csrf',
      beforeExchangeId: 'pre',
      probeExchangeId: 'prb',
      afterExchangeId: 'post',
    }],
  })
  assert.ok(realCsrf)
  const realCsrfVerdict = verifyReceipt(realCsrf.receipt, realCsrf.transcript)
  assert.equal(realCsrfVerdict.confirmed, true, realCsrfVerdict.reason)
})

// ============================================================================
// H-14: auth_bypass hardening against sealed caps, session jars, admin personas
// ============================================================================

test('H-14: auth_bypass rejects sealed capabilities, session cookies/jars, admin personas, login-issued tokens, and non-security header diffs, while confirming genuine forged-token bypass', () => {
  const mkAuthStep = (overrides: Partial<ImpactStep> & { id: string; arm: ImpactStep['arm']; status: number }): ImpactStep => ({
    method: 'GET',
    route: '/api/v1/admin/settings',
    pathAndQuery: '/api/v1/admin/settings',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    ...overrides,
  })
  const receipt = buildProofReceipt({
    vulnClass: 'auth_bypass',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/admin/settings' },
    exchangeIds: ['ctl', 'prb'],
    claimedDelta: 'Protected route bypassed.',
  })
  const protectedBody = '{"admin":true,"email":"root@acme.example","apiKeys":["k_live_01"]}'

  // Positive: forged unsigned token with no sealed cap / no session jar / no vault persona
  const forgedOk = verifyReceipt(receipt, {
    entries: [
      { exchangeId: 'ctl', step: mkAuthStep({ id: 'ctl', arm: 'control', status: 401, body: '{"error":"unauthorized"}' }) },
      { exchangeId: 'prb', step: mkAuthStep({ id: 'prb', arm: 'probe', status: 200, requestHeaders: { authorization: 'Bearer forged.unsigned.jwt' }, body: protectedBody }) },
    ],
  })
  assert.equal(forgedOk.confirmed, true, forgedOk.reason)

  // Negative 1: Sealed capability injected with personaHandle: null
  const sealedCapRejected = verifyReceipt(receipt, {
    entries: [
      { exchangeId: 'ctl', step: mkAuthStep({ id: 'ctl', arm: 'control', status: 401, body: '{"error":"unauthorized"}' }) },
      {
        exchangeId: 'prb',
        consumedCapabilityId: 'cap:hop_login:bearer',
        step: mkAuthStep({ id: 'prb', arm: 'probe', status: 200, requestHeaders: { authorization: 'Bearer [redacted:cap:hop_login:bearer]' }, body: protectedBody }),
      },
    ],
  })
  assert.equal(sealedCapRejected.confirmed, false, 'sealed capability must never confirm auth_bypass')
  assert.match(sealedCapRejected.reason, /sealed capability/i)

  // Negative 2: Session cookie / session jar from anonymous login
  const cookieJarRejected = verifyReceipt(receipt, {
    entries: [
      { exchangeId: 'ctl', step: mkAuthStep({ id: 'ctl', arm: 'control', status: 401, body: '{"error":"unauthorized"}' }) },
      {
        exchangeId: 'prb',
        sessionId: 'jar-logged-in',
        step: mkAuthStep({ id: 'prb', arm: 'probe', status: 200, requestHeaders: { cookie: 'sid=valid_login_cookie', 'x-bypass': '1' }, body: protectedBody }),
      },
    ],
  })
  assert.equal(cookieJarRejected.confirmed, false, 'session cookie / jar must never confirm auth_bypass')
  assert.match(cookieJarRejected.reason, /cookie|session jar/i)

  // Negative 3: Member control (403) vs Admin persona probe (200) — normal RBAC, NOT auth bypass
  const adminRbacRejected = verifyReceipt(receipt, {
    entries: [
      {
        exchangeId: 'ctl',
        step: mkAuthStep({
          id: 'ctl', arm: 'control', status: 403,
          actor: { handle: 'member_a', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null },
          requestHeaders: { authorization: 'Bearer tok_member' },
          body: '{"error":"forbidden"}',
        }),
      },
      {
        exchangeId: 'prb',
        step: mkAuthStep({
          id: 'prb', arm: 'probe', status: 200,
          actor: { handle: 'admin_a', role: 'admin', tenant: 'acme', auth: 'bearer', sameSite: null },
          requestHeaders: { authorization: 'Bearer tok_admin' },
          body: protectedBody,
        }),
      },
    ],
  })
  assert.equal(adminRbacRejected.confirmed, false, 'admin persona crossing member 403 is normal RBAC, not auth bypass')

  // Negative 4: Token issued by an earlier 2xx login response in the transcript
  const loginIssuedRejected = verifyReceipt(receipt, {
    entries: [
      {
        exchangeId: 'login',
        step: mkAuthStep({
          id: 'login', arm: 'setup', method: 'POST', route: '/api/v1/login', pathAndQuery: '/api/v1/login', status: 200,
          body: '{"token":"real_session_token_987654321"}',
        }),
      },
      { exchangeId: 'ctl', step: mkAuthStep({ id: 'ctl', arm: 'control', status: 401, body: '{"error":"unauthorized"}' }) },
      {
        exchangeId: 'prb',
        step: mkAuthStep({ id: 'prb', arm: 'probe', status: 200, requestHeaders: { authorization: 'Bearer real_session_token_987654321' }, body: protectedBody }),
      },
    ],
  })
  assert.equal(loginIssuedRejected.confirmed, false, 'login-issued token from transcript must not confirm auth_bypass')
  assert.match(loginIssuedRejected.reason, /login\/token exchange/i)

  // Negative 5: Benign non-security header diff (`accept-language`) does not count as auth bypass differential
  const benignHeaderRejected = verifyReceipt(receipt, {
    entries: [
      { exchangeId: 'ctl', step: mkAuthStep({ id: 'ctl', arm: 'control', status: 401, body: '{"error":"unauthorized"}' }) },
      { exchangeId: 'prb', step: mkAuthStep({ id: 'prb', arm: 'probe', status: 200, requestHeaders: { 'accept-language': 'fr-FR' }, body: protectedBody }) },
    ],
  })
  assert.equal(benignHeaderRejected.confirmed, false, 'unrelated benign header differential must be rejected')
})

// ============================================================================
// H-15: Timing differential (`blind_sqli`) route / origin / method / persona lock
// ============================================================================

test('H-15: timing differential confirms same-origin/method/route/persona with host-minted delay >=5 interleaved arms and rejects mismatched route, persona, method, origin, or 1+1 arms', () => {
  const timingRunId = 'run-t2-timing'
  const challenge = defaultHostMintedOracle.mintTimingChallenge('sqli', 1_800, undefined, { runId: timingRunId, origin: ORIGIN, method: 'GET', route: '/api/search', param: 'q' })
  const mkTimingExchanges = (probeOverrides: Partial<ScriptProofExchange> = {}): ScriptProofExchange[] => [
    ...Array.from({ length: 5 }, (_, i) => ({
      exchangeId: `c${i}`, seq: i * 2, method: 'GET',
      pathAndQuery: `/api/search?q=${encodeURIComponent(challenge.controlToken)}`,
      origin: ORIGIN, status: 200, durationMs: 35, personaHandle: 'alice', body: '{"items":[]}',
      hostTimingChallenge: defaultHostMintedOracle.stampTimingChallengeArm(challenge, 'control', { exchangeId: `c${i}` }),
    })),
    ...Array.from({ length: 5 }, (_, i) => ({
      exchangeId: `p${i}`, seq: i * 2 + 1, method: 'GET',
      pathAndQuery: `/api/search?q=${encodeURIComponent(challenge.delayToken)}`,
      origin: ORIGIN, status: 200, durationMs: 1_800, personaHandle: 'alice', body: '{"items":[]}',
      hostTimingChallenge: defaultHostMintedOracle.stampTimingChallengeArm(challenge, 'probe', { exchangeId: `p${i}` }),
      ...probeOverrides,
    })),
  ]
  const timingClaim = {
    kind: 'timing',
    controlIds: ['c0', 'c1', 'c2', 'c3', 'c4'],
    variantIds: ['p0', 'p1', 'p2', 'p3', 'p4'],
    hostMintedTimingChallengeId: challenge.challengeId,
  }

  // Positive: identical origin, method, route, persona, >=5 interleaved arms, host-minted delay vs zero-delay control
  const okBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    runId: timingRunId,
    title: 'Blind timing on /api/search',
    exchanges: mkTimingExchanges(),
    claims: [timingClaim],
  })
  assert.ok(okBuilt)
  const okVerdict = verifyReceipt(okBuilt.receipt, okBuilt.transcript, { runId: timingRunId })
  assert.equal(okVerdict.confirmed, true, okVerdict.reason)

  // Negative 1 (buildAgentScriptReceipt): different routes (`/api/search` vs `/api/export`)
  assert.equal(
    buildAgentScriptReceipt({ origin: ORIGIN, runId: timingRunId, title: 'Cross-route timing', exchanges: mkTimingExchanges({ pathAndQuery: `/api/export?q=${encodeURIComponent(challenge.delayToken)}` }), claims: [timingClaim] }),
    null,
    'buildAgentScriptReceipt must reject cross-route timing',
  )

  // Negative 2 (buildAgentScriptReceipt): different personas (`alice` vs `admin`)
  assert.equal(
    buildAgentScriptReceipt({ origin: ORIGIN, runId: timingRunId, title: 'Cross-persona timing', exchanges: mkTimingExchanges({ personaHandle: 'admin' }), claims: [timingClaim] }),
    null,
    'buildAgentScriptReceipt must reject cross-persona timing',
  )

  // Negative 3 (verifyReceipt direct): 1+1 arms must be rejected; >=5 interleaved arms with host challenge confirms,
  // and mismatched route, persona, method, or origin all fail closed.
  const onePairReceipt = buildProofReceipt({
    vulnClass: 'blind_sqli',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/api/search?q=${encodeURIComponent(challenge.delayToken)}` },
    exchangeIds: ['c0', 'p0'],
    claimedDelta: 'Single pair timing claim must fail closed.',
  })
  assert.equal(verifyReceipt(onePairReceipt, {
    runId: timingRunId,
    hostTimingChallenge: challenge,
    entries: [
      { exchangeId: 'c0', seq: 1, origin: ORIGIN, durationMs: 40, step: mkStep({ id: 'c0', arm: 'control', method: 'GET', route: '/api/search', pathAndQuery: `/api/search?q=${encodeURIComponent(challenge.controlToken)}`, status: 200 }) },
      { exchangeId: 'p0', seq: 2, origin: ORIGIN, durationMs: 2_000, step: mkStep({ id: 'p0', arm: 'probe', method: 'GET', route: '/api/search', pathAndQuery: `/api/search?q=${encodeURIComponent(challenge.delayToken)}`, status: 200 }) },
    ],
  }, { runId: timingRunId }).confirmed, false, '1+1 timing arms must be rejected by R2 H-15')

  const timingReceipt = buildProofReceipt({
    vulnClass: 'blind_sqli',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/api/search?q=${encodeURIComponent(challenge.delayToken)}`, param: 'q' },
    exchangeIds: ['c0', 'p0', 'c1', 'p1', 'c2', 'p2', 'c3', 'p3', 'c4', 'p4'],
    claimedDelta: 'Timing separation claimed across 5 interleaved host-minted rounds.',
  })
  const makeDirect = (probePatch: Partial<ReceiptTranscriptEntry> & { stepPatch?: Partial<ImpactStep> }): ReceiptTranscript => ({
    runId: timingRunId,
    entries: Array.from({ length: 5 }, (_, i) => [
      {
        exchangeId: `c${i}`,
        seq: i * 2,
        origin: ORIGIN,
        durationMs: 40,
        hostTimingChallenge: defaultHostMintedOracle.stampTimingChallengeArm(challenge, 'control', { exchangeId: `c${i}` }),
        step: mkStep({ id: `c${i}`, arm: 'control', method: 'GET', route: '/api/search', pathAndQuery: `/api/search?q=${encodeURIComponent(challenge.controlToken)}`, status: 200 }),
      },
      {
        exchangeId: `p${i}`,
        seq: i * 2 + 1,
        origin: probePatch.origin ?? ORIGIN,
        durationMs: 2_000,
        hostTimingChallenge: defaultHostMintedOracle.stampTimingChallengeArm(challenge, 'probe', { exchangeId: `p${i}` }),
        step: mkStep({ id: `p${i}`, arm: 'probe', method: 'GET', route: '/api/search', pathAndQuery: `/api/search?q=${encodeURIComponent(challenge.delayToken)}`, status: 200, ...(probePatch.stepPatch ?? {}) }),
      },
    ]).flat(),
  })
  assert.equal(verifyReceipt(timingReceipt, makeDirect({}), { runId: timingRunId }).confirmed, true)
  assert.equal(verifyReceipt(timingReceipt, makeDirect({ stepPatch: { route: '/api/slow-export', pathAndQuery: `/api/slow-export?q=${encodeURIComponent(challenge.delayToken)}` } }), { runId: timingRunId }).confirmed, false)
  assert.equal(verifyReceipt(timingReceipt, makeDirect({ stepPatch: { actor: { handle: 'admin', role: 'admin', tenant: 'acme', auth: 'bearer', sameSite: null } } }), { runId: timingRunId }).confirmed, false)
  assert.equal(verifyReceipt(timingReceipt, makeDirect({ stepPatch: { method: 'POST' } }), { runId: timingRunId }).confirmed, false)
  assert.equal(verifyReceipt(timingReceipt, makeDirect({ origin: OTHER_ORIGIN }), { runId: timingRunId }).confirmed, false)
})

// ============================================================================
// H-18: Confirmed finding identity binding & post-confirmation immutability
// ============================================================================

test('H-18: bindConfirmedFindingIdentity binds CWE/origin/endpoint/title to confirming spec and guardConfirmedFindingMutation forbids post-confirmation identity edits', () => {
  const staleProposed: Finding = {
    id: 'finding-1',
    origin: OTHER_ORIGIN,
    title: 'Stale SQL Injection Proposal',
    status: 'pending',
    severity: 'critical',
    reason: 'Model proposed SQLi.',
    remediation: 'Fix it.',
    evidenceIds: [],
    scopeRevision: 1,
    cwe: 'CWE-89',
    category: 'injection-input',
  }
  const confirmingSpec: DeclarativeReplaySpec = {
    version: 1,
    kind: 'http_chain',
    spaCatchallControl: false,
    origin: ORIGIN,
    title: 'Cross-tenant BOLA read on GET /api/v1/invoices/42',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Foreign tenant invoice read.',
    impact: 'Cross-tenant data exposure.',
    remediation: 'Enforce tenant check.',
    recheckInstructions: 'Replay GET /api/v1/invoices/42.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "403" }',
    steps: [
      { id: 'c1', role: 'control', description: 'denied', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/invoices/42', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'read', request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/invoices/42', followRedirects: false } },
    ],
  }
  const replayStub: ReplayVerificationResult = {
    verdict: 'confirmed',
    verificationTier: 'runtime_confirmed',
    outcome: { confirmed: true, controlPassed: true, observed: 'ok', expected: '403' },
    exchangeIds: ['ex-1'],
    exchanges: [],
    evidencePayload: {},
    evidenceSha256: 'b'.repeat(64),
  }

  // Positive: identity binds cleanly to the confirming spec (NOT the stale CWE-89 proposal)
  const bound = bindConfirmedFindingIdentity(staleProposed, confirmingSpec, replayStub)
  assert.equal(bound.cwe, 'CWE-639')
  assert.equal(bound.origin, ORIGIN)
  assert.equal(bound.category, 'broken-access-control')
  assert.equal(bound.title, confirmingSpec.title)
  assert.ok(bound.fingerprintHash && bound.fingerprintHash.length >= 16, 'fingerprintHash must be bound to confirming endpoint')

  // Negative: post-confirmation mutation attempt on CWE, origin, title, category, fingerprintHash, endpoint is blocked
  const confirmedRow: Finding = { ...bound, status: 'confirmed', verificationTier: 'runtime_confirmed' }
  const blocked = guardConfirmedFindingMutation(confirmedRow, {
    cwe: 'CWE-89',
    origin: OTHER_ORIGIN,
    title: 'Tampered SQLi Title',
    category: 'injection-input',
    fingerprintHash: 'tampered-hash',
    endpoint: '/api/v1/other',
    reason: 'Additional non-identity note',
  })
  assert.equal(blocked.allowed, false)
  assert.deepEqual(new Set(blocked.blockedFields), new Set(['cwe', 'origin', 'title', 'category', 'fingerprintHash', 'endpoint']))
  assert.equal(blocked.sanitizedPatch.cwe, undefined)
  assert.equal(blocked.sanitizedPatch.origin, undefined)
  assert.equal(blocked.sanitizedPatch.title, undefined)
  assert.equal(blocked.sanitizedPatch.reason, 'Additional non-identity note')

  // Positive: pending (unconfirmed) findings remain editable
  const pendingEdit = guardConfirmedFindingMutation(staleProposed, { cwe: 'CWE-639', title: 'Updated Pending Title' })
  assert.equal(pendingEdit.allowed, true)
  assert.equal(pendingEdit.blockedFields.length, 0)
  assert.equal(pendingEdit.sanitizedPatch.cwe, 'CWE-639')
})

// ============================================================================
// H-20: `prove.oob` branch in `buildAgentScriptReceipt` via `buildOobReceipt`
// ============================================================================

test('H-20: buildAgentScriptReceipt builds and verifies OOB receipts via buildOobReceipt from host OOB events and op:oob transcript records, and fails closed when undelivered', () => {
  const token = 'kovo-canary-9876543210fedcba98765432'
  const mintEx: ScriptProofExchange = {
    exchangeId: 'ex-mint', seq: 1, op: 'oob', startedAt: 1000, endedAt: 1001,
    method: 'MINT', pathAndQuery: '/', origin: ORIGIN, status: null,
    artifact: { kind: 'oob-mint', token, url: `http://relay.invalid/c/${token}`, hit: false },
  }
  const injectEx: ScriptProofExchange = {
    exchangeId: 'ex-inject', seq: 2, op: 'http', startedAt: 1020, endedAt: 1050,
    method: 'POST', pathAndQuery: '/api/v1/webhooks/test', origin: ORIGIN, status: 202,
    requestBody: JSON.stringify({ targetUrl: `http://relay.invalid/c/${token}` }),
    body: '{"queued":true}',
  }
  const waitEx: ScriptProofExchange = {
    exchangeId: 'ex-wait', seq: 3, op: 'oob', startedAt: 1100, endedAt: 1200,
    method: 'WAIT', pathAndQuery: '/oob/pending/sub-oob-1', origin: '', status: null,
    artifact: { kind: 'oob-mint', token, hit: true, subscriptionId: 'sub-oob-1', canaryId: 'can-1', receivedAtMs: 1180 },
  }

  // Positive 1: via explicit host `oobEvents`
  const hostOob: ReceiptOobEvent = {
    id: 'sub-oob-1',
    canaryId: 'can-1',
    token,
    targetOrigin: ORIGIN,
    delivered: true,
    stage: 'immediate',
    receivedAtMs: 1180,
    injectedAtMs: 1020,
    latencyMs: 160,
  }
  const builtWithEvents = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Blind SSRF webhook callback',
    exchanges: [mintEx, injectEx, waitEx],
    oobEvents: [hostOob],
    claims: [{ kind: 'oob', exchangeId: 'ex-mint', expectHit: true }],
  })
  assert.ok(builtWithEvents, 'oob claim with delivered host OOB event must build a ProofReceipt')
  assert.equal(builtWithEvents.receipt.vulnClass, 'ssrf')
  assert.deepEqual(builtWithEvents.receipt.oobEventIds, ['sub-oob-1'])
  assert.deepEqual(builtWithEvents.receipt.exchangeIds, ['ex-mint', 'ex-inject'])
  const verEvents = verifyReceipt(builtWithEvents.receipt, builtWithEvents.transcript)
  assert.equal(verEvents.confirmed, true, verEvents.reason)
  assert.equal(verEvents.rule, 'oob')

  // Positive 2: via host `op: 'oob'` mint + wait transcript records (without separate oobEvents array)
  const builtFromTranscript = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Blind XXE external entity callback',
    exchanges: [mintEx, injectEx, waitEx],
    claims: [{ kind: 'oob', exchangeId: 'ex-mint', expectHit: true }],
  })
  assert.ok(builtFromTranscript)
  assert.equal(builtFromTranscript.receipt.vulnClass, 'xxe')
  assert.deepEqual(builtFromTranscript.receipt.oobEventIds, ['sub-oob-1'])
  assert.deepEqual(builtFromTranscript.receipt.exchangeIds, ['ex-mint', 'ex-inject', 'ex-wait'])
  const verTranscript = verifyReceipt(builtFromTranscript.receipt, builtFromTranscript.transcript)
  assert.equal(verTranscript.confirmed, true, verTranscript.reason)

  // Negative 1: Undelivered callback returns null (fails closed)
  const undeliveredWait: ScriptProofExchange = {
    ...waitEx,
    artifact: { kind: 'oob-mint', token, hit: false },
  }
  const builtUndelivered = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Undelivered SSRF callback',
    exchanges: [mintEx, injectEx, undeliveredWait],
    claims: [{ kind: 'oob', exchangeId: 'ex-mint', expectHit: true }],
  })
  assert.equal(builtUndelivered, null, 'undelivered OOB callback must not build a receipt')

  // Negative 2: Callback delivered for a token never carried by any HTTP exchange fails verifyReceipt
  const nonCarryingInject: ScriptProofExchange = {
    ...injectEx,
    requestBody: '{"targetUrl":"https://benign.invalid/"}',
  }
  const builtUncarried = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Uncarried SSRF callback',
    exchanges: [mintEx, nonCarryingInject, waitEx],
    claims: [{ kind: 'oob', exchangeId: 'ex-mint', expectHit: true }],
  })
  assert.ok(builtUncarried)
  const verUncarried = verifyReceipt(builtUncarried.receipt, builtUncarried.transcript)
  assert.equal(verUncarried.confirmed, false, 'OOB receipt without carrying exchange must fail closed')
})

// ============================================================================
// H-32: ReDoS guard in replay-verifier.ts
// ============================================================================

test('H-32: isSafeRegexPattern and safeRegexTest reject ReDoS patterns in <5ms, reject >256-char patterns, cap haystack, and allow safe patterns', () => {
  const evilPatterns = [
    '(a+)+$',
    '((a*))+b',
    '(a{1,5}){2,}b',
    '(?:a+b?)+$',
    '(a|aa)+$',
    '([a-z]|[a-z0-9])+!',
    '(a)\\1+',
    '(?<=foo)bar',
    'a++',
    'a{100}',
    '.*.*.*needle',
    '\\w+\\w+x',
    'a'.repeat(MAX_REPLAY_REGEX_PATTERN_LENGTH + 1),
  ]
  const evilHaystack = `${'a'.repeat(32)}!`
  const started = Date.now()
  for (const pattern of evilPatterns) {
    assert.equal(isSafeRegexPattern(pattern), false, `expected unsafe regex to be rejected: ${pattern.slice(0, 40)}`)
    assert.equal(safeRegexTest(pattern, evilHaystack), false, `safeRegexTest must reject unsafe regex: ${pattern.slice(0, 40)}`)
  }
  assert.ok(Date.now() - started < 100, 'ReDoS guard must reject all evil patterns immediately without backtracking')

  // Positive: safe linear patterns match cleanly
  assert.equal(isSafeRegexPattern('tok_[a-z0-9]{8,32}'), true)
  assert.equal(safeRegexTest('tok_[a-z0-9]{8,32}', 'prefix tok_abcdef123456 suffix'), true)
  assert.equal(safeRegexTest('tok_[a-z0-9]{8,32}', 'no match here'), false)

  // Haystack length cap enforced: needle placed beyond 16 KiB is not matched
  const farNeedle = `${'x'.repeat(MAX_REPLAY_REGEX_HAYSTACK_LENGTH + 128)}SECRET_MARKER_999`
  assert.equal(safeRegexTest('SECRET_MARKER_999', farNeedle), false, 'haystack beyond max length cap must not be scanned')
})
