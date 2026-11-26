/**
 * Move A Part 3a (`WS-5` + `verify-prove-handlers.ts`) — Comprehensive Proof-Receipt & Host-Custody Tests
 *
 * Covers:
 *  1. R2-C-6: HostMintedOracle evaluated-expression differential oracle (randomized per-attempt
 *             operands, worker-marker rejection, origin/persona/shape parity, body_contains lead downgrade)
 *  2. C-5:    State conservation / race oracle (host-stamped raceBatchId, reserved evidenceRole
 *             rejection, mandatory readRoute + identical serial control in prove.race, narrowed
 *             409/410/422 serial_rejection after serial 2xx, over_credit >= 2 * delta)
 *  3. H-15:   Timing differential oracle (strict timingArmIdentity tuple, single differing param,
 *             status parity, >= 5 interleaved arms, host-minted delay vs zero-delay control,
 *             host construct-family class derivation)
 *  4. R2-H-13: Redirect differential rule (same method/route/actor control, 3xx status, host-minted
 *              canary destination host in controlled param, host comparison vs raw Location)
 *  5. R2-H-11/H-6: OOB request-side-only carrier matching, unique carrier with startedAt <= receivedAtMs,
 *                  host-signed callback timestamp/id verification, no WAIT-time synthesis
 *  6. H-13 & R2-C-9: Host-only credentialPlacement, SameSite bound strictly to authenticating cookie
 *                    (defaulting unknown to Lax), CSRF cross-site sendability, clean kernel request
 *                    plane assertions (no [redacted:cap:...]), and TerminalOracleRegistry embedded
 *                    receipt custody sanitization & strict host derivation.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  HostFactLog,
  assertCleanKernelRequestPlane,
  deriveAmbientAuthFromHeaders,
  deriveCredentialPlacement,
  extractSameSiteFromHeaders,
  hasVaultScrubbedRequestPlane,
  isReservedEvidenceRole,
} from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import {
  HostMintedOracle,
  buildAgentScriptReceipt,
  buildOobReceipt,
  buildProofReceipt,
  defaultHostMintedOracle,
  isCrossSiteSendableCsrfRequest,
  signOobCallback,
  timingArmIdentityOf,
  verifyOobCallbackSignature,
  verifyReceipt,
  type ReceiptOobEvent,
  type ReceiptTranscript,
  type ReceiptTranscriptEntry,
  type ScriptProofExchange,
} from '../src/server/proof-receipt.ts'
import {
  TerminalOracleRegistry,
  sanitizeSingleHopReceiptForHostCustody,
} from '../src/server/terminal-oracle-registry.ts'
import { TranscriptStore } from '../src/server/verify-claims.ts'
import {
  handleProveDifferential,
  handleProveInjection,
  handleProveRace,
  type ProveHandlerHost,
  type ProveHttpExchangeResult,
} from '../src/server/verify-prove-handlers.ts'

const ORIGIN = 'https://app.example.invalid'
const OTHER_ORIGIN = 'https://other.example.invalid'
const SIGNING_KEY = 'movea-proof-receipt-test-signing-key-32b'

function mkStep(
  overrides: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>,
): ImpactStep {
  return {
    route: '/api/v1/items',
    pathAndQuery: '/api/v1/items',
    actor: { handle: 'alice', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null },
    ...overrides,
  }
}

function makeMockProveHost(
  responder: (args: Record<string, unknown>, callIndex: number) => {
    status: number
    body: string
    durationMs?: number
    headers?: Record<string, string>
  },
  raceResponder?: (args: Record<string, unknown>) => {
    mode?: 'h2-single-packet' | 'http1-fallback'
    raceBatchId?: string
    results: Array<{ status: number; body?: string; durationMs?: number }>
  },
): {
  host: ProveHandlerHost
  httpCalls: Record<string, unknown>[]
  raceCalls: Record<string, unknown>[]
} {
  const transcript = new TranscriptStore()
  const httpCalls: Record<string, unknown>[] = []
  const raceCalls: Record<string, unknown>[] = []
  let clock = 1_700_000_000_000

  const host: ProveHandlerHost = {
    transcript,
    defaultOrigin: ORIGIN,
    canaryBroker: undefined,
    scrubRecord: <T,>(v: T): T => v,
    async runOob(): Promise<unknown> {
      return {}
    },
    async runHttpExchange(args: Record<string, unknown>, nonce: string, stamps?: { hostExpressionChallenge?: unknown; hostBooleanPair?: unknown }): Promise<ProveHttpExchangeResult> {
      const idx = httpCalls.length
      httpCalls.push(args)
      const res = responder(args, idx)
      const durationMs = res.durationMs ?? 20
      const startedAt = clock
      clock += durationMs + 5
      const method = String(args.method ?? 'GET').toUpperCase()
      const pathAndQuery = String(args.path ?? '/')
      const origin = String(args.origin ?? ORIGIN)
      const reqHeaders = (args.headers as Record<string, string> | undefined) ?? {}
      const reqBody = typeof args.body === 'string' ? args.body : ''
      const rec = transcript.record({
        op: 'http',
        startedAt,
        durationMs,
        ...(stamps?.hostExpressionChallenge ? { hostExpressionChallenge: stamps.hostExpressionChallenge as never } : {}),
        ...(stamps?.hostBooleanPair ? { hostBooleanPair: stamps.hostBooleanPair as never } : {}),
        request: {
          origin,
          method,
          pathAndQuery,
          headers: reqHeaders,
          bodyBytes: Buffer.byteLength(reqBody),
          bodySha256: '0'.repeat(64),
          personaHandle: typeof args.persona === 'string' ? args.persona : null,
          sessionRole: typeof args.sessionGroupRole === 'string' ? args.sessionGroupRole : null,
          nonce,
        },
        response: {
          status: res.status,
          headers: res.headers ?? { 'content-type': 'application/json' },
          bodyBytes: Buffer.byteLength(res.body),
          bodySha256: '1'.repeat(64),
          mediaType: 'application/json',
        },
        body: res.body,
        rawRequestBody: reqBody || undefined,
      })
      return {
        exchangeId: rec.exchangeId,
        status: res.status,
        method,
        pathAndQuery,
        headers: res.headers ?? { 'content-type': 'application/json' },
        body: res.body,
        bodyPreview: res.body.slice(0, 200),
        bodyBytes: Buffer.byteLength(res.body),
        bodySha256: '1'.repeat(64),
        durationMs,
        personaHandle: typeof args.persona === 'string' ? args.persona : null,
      }
    },
    async runRace(args: Record<string, unknown>, nonce: string): Promise<unknown> {
      raceCalls.push(args)
      const reqs = (args.requests as Array<Record<string, unknown>>) ?? []
      const custom = raceResponder?.(args)
      const burstStart = clock
      const items = custom?.results ?? reqs.map(() => ({ status: 200, body: '{"ok":true}', durationMs: 40 }))
      const results = items.map((item, idx) => {
        const req = reqs[idx] ?? reqs[0] ?? {}
        const dur = item.durationMs ?? 40
        const body = item.body ?? '{"ok":true}'
        const reqBody = typeof req.body === 'string' ? req.body : ''
        const rec = transcript.record({
          op: 'race',
          startedAt: burstStart + idx,
          durationMs: dur,
          request: {
            origin: String(req.origin ?? ORIGIN),
            method: String(req.method ?? 'POST').toUpperCase(),
            pathAndQuery: String(req.path ?? '/'),
            headers: (req.headers as Record<string, string> | undefined) ?? {},
            bodyBytes: Buffer.byteLength(reqBody),
            bodySha256: '0'.repeat(64),
            personaHandle: typeof req.persona === 'string' ? req.persona : null,
            sessionRole: 'probe',
            nonce,
          },
          response: {
            status: item.status,
            headers: { 'content-type': 'application/json' },
            bodyBytes: Buffer.byteLength(body),
            bodySha256: '1'.repeat(64),
            mediaType: 'application/json',
          },
          body,
          rawRequestBody: reqBody || undefined,
        })
        return {
          exchangeId: rec.exchangeId,
          status: item.status,
          durationMs: dur,
          bodySha256: '1'.repeat(64),
        }
      })
      clock = burstStart + 60
      return {
        mode: custom?.mode ?? 'h2-single-packet',
        raceBatchId: custom?.raceBatchId ?? args.raceBatchId,
        results,
      }
    },
  }
  return { host, httpCalls, raceCalls }
}

// ============================================================================
// 1. R2-C-6: Host-minted evaluated-expression differential oracle
// ============================================================================

test('R2-C-6: evaluated-expression oracle requires host-minted randomized operands, rejects worker markers, and downgrades plain body_contains pairs to leads', async () => {
  const oracle = new HostMintedOracle()
  const ch1 = oracle.mintExpressionChallenge('ssti')
  const ch2 = oracle.mintExpressionChallenge('ssti')
  assert.notEqual(ch1.expectedOutput, ch2.expectedOutput, 'host-minted outputs must vary across attempts')
  assert.equal(String(ch1.operandA * ch1.operandB), ch1.expectedOutput)
  assert.equal(String(ch2.operandA * ch2.operandB), ch2.expectedOutput)

  // Negative 1: Worker-chosen marker on a normal filter endpoint (?category=books vs ?category=music) MUST fail closed
  const workerMarkerReceipt = buildProofReceipt({
    vulnClass: 'ssti',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/catalog?category=music' },
    exchangeIds: ['ctl-1', 'prb-1'],
    claimedDelta: 'Product title appeared only in music category.',
    proofPatterns: ['AcousticGuitarPro'],
  })
  const workerMarkerVerdict = verifyReceipt(workerMarkerReceipt, {
    entries: [
      { exchangeId: 'ctl-1', origin: ORIGIN, step: mkStep({ id: 'ctl-1', arm: 'control', method: 'GET', route: '/api/catalog', pathAndQuery: '/api/catalog?category=books', status: 200, body: '{"items":["NovelOne"]}' }) },
      { exchangeId: 'prb-1', origin: ORIGIN, step: mkStep({ id: 'prb-1', arm: 'probe', method: 'GET', route: '/api/catalog', pathAndQuery: '/api/catalog?category=music', status: 200, body: '{"items":["AcousticGuitarPro"]}' }) },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(workerMarkerVerdict.confirmed, false, 'worker-chosen marker must NEVER confirm SSTI/injection')

  // Negative 2: Plain body_contains pair in buildAgentScriptReceipt is downgraded to unconfirmed lead (returns null)
  const plainBodyContainsBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Plain body_contains filter diff',
    exchanges: [
      { exchangeId: 'ctl', seq: 1, method: 'GET', pathAndQuery: '/api/catalog?category=books', origin: ORIGIN, status: 200, body: '{"items":["NovelOne"]}' },
      { exchangeId: 'prb', seq: 2, method: 'GET', pathAndQuery: '/api/catalog?category=music', origin: ORIGIN, status: 200, body: '{"items":["AcousticGuitarPro"]}' },
    ],
    claims: [
      { kind: 'body_contains', exchangeId: 'ctl', text: 'AcousticGuitarPro', absent: true },
      { kind: 'body_contains', exchangeId: 'prb', text: 'AcousticGuitarPro', absent: false, vulnClass: 'ssti' },
    ],
  })
  assert.equal(plainBodyContainsBuilt, null, 'plain body_contains pair must downgrade to unconfirmed lead (no confirming receipt)')

  // Positive: Two randomized host-minted SSTI expression challenges confirm when evaluated non-reflected
  const validReceipt = buildProofReceipt({
    vulnClass: 'ssti',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/api/render?name={{${ch1.expressionSyntax}}}` },
    exchangeIds: ['c1', 'p1', 'c2', 'p2'],
    claimedDelta: 'Host-minted arithmetic template expressions evaluated on server.',
  })
  const validTranscript: ReceiptTranscript = {
    hostExpressionChallenges: [ch1, ch2],
    entries: [
      { exchangeId: 'c1', origin: ORIGIN, step: mkStep({ id: 'c1', arm: 'control', method: 'GET', route: '/api/render', pathAndQuery: '/api/render?name=benign', status: 200, body: 'Hello benign' }) },
      { exchangeId: 'p1', origin: ORIGIN, hostExpressionChallenge: ch1, step: mkStep({ id: 'p1', arm: 'probe', method: 'GET', route: '/api/render', pathAndQuery: `/api/render?name=${encodeURIComponent(`{{${ch1.expressionSyntax}}}`)}`, status: 200, body: `Hello ${ch1.expectedOutput}` }) },
      { exchangeId: 'c2', origin: ORIGIN, step: mkStep({ id: 'c2', arm: 'control', method: 'GET', route: '/api/render', pathAndQuery: '/api/render?name=benign', status: 200, body: 'Hello benign' }) },
      { exchangeId: 'p2', origin: ORIGIN, hostExpressionChallenge: ch2, step: mkStep({ id: 'p2', arm: 'probe', method: 'GET', route: '/api/render', pathAndQuery: `/api/render?name=${encodeURIComponent(`{{${ch2.expressionSyntax}}}`)}`, status: 200, body: `Hello ${ch2.expectedOutput}` }) },
    ],
  }
  const positiveVerdict = verifyReceipt(validReceipt, validTranscript, { hostMintedOracle: oracle })
  assert.equal(positiveVerdict.confirmed, true, positiveVerdict.reason)
  assert.equal(positiveVerdict.evidence?.hostMinted, true)

  // Negative 3: Persona mismatch, origin mismatch, or extra differing param (request shape mismatch) rejected
  const diffPersona = verifyReceipt(validReceipt, {
    ...validTranscript,
    entries: validTranscript.entries!.map(e => e.step.arm === 'probe'
      ? { ...e, step: { ...e.step, actor: { ...e.step.actor, handle: 'bob' } } }
      : e),
  }, { hostMintedOracle: oracle })
  assert.equal(diffPersona.confirmed, false, 'mismatched persona must reject evaluated-expression confirmation')

  const diffShape = verifyReceipt(validReceipt, {
    ...validTranscript,
    entries: validTranscript.entries!.map(e => e.step.arm === 'probe'
      ? { ...e, step: { ...e.step, pathAndQuery: `${e.step.pathAndQuery}&extra=1` } }
      : e),
  }, { hostMintedOracle: oracle })
  assert.equal(diffShape.confirmed, false, 'mismatched request shape must reject evaluated-expression confirmation')

  // Negative 4: Same static challenge reused across both attempts (does not vary across attempts) rejected
  const staticRepeat = verifyReceipt(validReceipt, {
    hostExpressionChallenges: [ch1],
    entries: [
      validTranscript.entries![0]!,
      validTranscript.entries![1]!,
      validTranscript.entries![2]!,
      { ...validTranscript.entries![3]!, hostExpressionChallenge: ch1, step: { ...validTranscript.entries![1]!.step, id: 'p2' } },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(staticRepeat.confirmed, false, 'identical outputs across 2 attempts must be rejected')

  // Handler tests (`handleProveInjection`):
  // (a) Worker-chosen expectedOutput is rejected and downgraded to lead
  const { host: workerMarkerHost } = makeMockProveHost((args) => {
    const p = String(args.path ?? '')
    return { status: 200, body: p.includes('music') ? '{"item":"AcousticGuitarPro"}' : '{"item":"NovelOne"}' }
  })
  const workerRes = await handleProveInjection(workerMarkerHost, {
    control: '/api/catalog?category=books',
    probe: '/api/catalog?category=music',
    expectedOutput: 'AcousticGuitarPro',
    vulnClass: 'ssti',
  }, 'n-1') as Record<string, unknown>
  assert.equal(workerRes.ok, false)
  assert.equal(workerRes.confirmed, false)
  assert.equal(workerRes.lead, true)
  assert.equal(workerRes.rejectedBy, 'worker_chosen_marker_rejected')

  // (b) Host-minted template evaluates two distinct randomized expressions and confirms
  const { host: evalHost } = makeMockProveHost((args) => {
    const p = decodeURIComponent(String(args.path ?? ''))
    const m = /\{\{(\d+)\*(\d+)\}\}/.exec(p)
    if (m) return { status: 200, body: `Rendered: ${Number(m[1]) * Number(m[2])}` }
    return { status: 200, body: 'Rendered: benign' }
  })
  const hostEvalRes = await handleProveInjection(evalHost, {
    control: '/api/render?name=benign',
    probe: '/api/render?name={{' + '{{expr}}' + '}}',
    expressionFamily: 'ssti',
  }, 'n-2') as Record<string, unknown>
  assert.equal(hostEvalRes.ok, true)
  assert.equal(hostEvalRes.confirmed, true)
  assert.equal(hostEvalRes.evaluated, true)
  const minted = hostEvalRes.hostMintedChallenges as Array<Record<string, unknown>>
  assert.equal(minted.length, 2)
  assert.notEqual(minted[0]!.challengeId, minted[1]!.challengeId)
  // R4-C-2: handleProveInjection must NEVER return expectedOutput or operands to the worker.
  assert.equal('expectedOutput' in minted[0]!, false)
  assert.equal('expectedOutput' in minted[1]!, false)
  assert.equal('operandA' in minted[0]!, false)
  assert.equal('operandB' in minted[0]!, false)
})

// ============================================================================
// 2. C-5: Conserved-balance / race oracle
// ============================================================================

test('C-5: conserved_balance enforces host raceBatchId, rejects reserved evidenceRoles, requires readRoute + identical serial control, narrows serial_rejection to 409/410/422 after serial 2xx, and requires over_credit >= 2*delta', async () => {
  assert.equal(isReservedEvidenceRole('baseline_read'), true)
  assert.equal(isReservedEvidenceRole('burst_1'), true)
  assert.equal(isReservedEvidenceRole('serial_control_1'), true)
  assert.equal(isReservedEvidenceRole('custom_note'), false)

  // Positive: over_credit >= 2 * delta with host-stamped raceBatchId and 409 serial rejection following a serial 2xx
  const overCreditTranscript: ReceiptTranscript = {
    entries: [
      { exchangeId: 'pre', seq: 1, startedAt: 1000, endedAt: 1010, evidenceRole: 'baseline_read', origin: ORIGIN, step: mkStep({ id: 'pre', arm: 'setup', method: 'GET', route: '/api/wallet', pathAndQuery: '/api/wallet', status: 200, json: { balance: 0 } }) },
      { exchangeId: 'b1', seq: 2, op: 'race', raceBatchId: 'race_batch_1', startedAt: 1050, endedAt: 1110, evidenceRole: 'burst_1', origin: ORIGIN, step: mkStep({ id: 'b1', arm: 'probe', method: 'POST', route: '/api/coupons/redeem', pathAndQuery: '/api/coupons/redeem', status: 200, requestJson: { amount: 50 }, json: { ok: true } }) },
      { exchangeId: 'b2', seq: 3, op: 'race', raceBatchId: 'race_batch_1', startedAt: 1055, endedAt: 1115, evidenceRole: 'burst_2', origin: ORIGIN, step: mkStep({ id: 'b2', arm: 'probe', method: 'POST', route: '/api/coupons/redeem', pathAndQuery: '/api/coupons/redeem', status: 200, requestJson: { amount: 50 }, json: { ok: true } }) },
      { exchangeId: 'post', seq: 4, startedAt: 1150, endedAt: 1160, evidenceRole: 'post_read', origin: ORIGIN, step: mkStep({ id: 'post', arm: 'control', method: 'GET', route: '/api/wallet', pathAndQuery: '/api/wallet', status: 200, json: { balance: 100 } }) },
      { exchangeId: 's1', seq: 5, startedAt: 1200, endedAt: 1220, evidenceRole: 'serial_control_1', origin: ORIGIN, step: mkStep({ id: 's1', arm: 'control', method: 'POST', route: '/api/coupons/redeem', pathAndQuery: '/api/coupons/redeem', status: 200, requestJson: { amount: 50 }, json: { ok: true } }) },
      { exchangeId: 's2', seq: 6, startedAt: 1240, endedAt: 1260, evidenceRole: 'serial_control_2', origin: ORIGIN, step: mkStep({ id: 's2', arm: 'control', method: 'POST', route: '/api/coupons/redeem', pathAndQuery: '/api/coupons/redeem', status: 409, requestJson: { amount: 50 }, json: { error: 'already redeemed' } }) },
    ],
  }
  const overCreditReceipt = buildProofReceipt({
    vulnClass: 'race_double_spend',
    target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/coupons/redeem' },
    exchangeIds: ['pre', 'b1', 'b2', 'post', 's1', 's2'],
    claimedDelta: 'Concurrent single-use coupon redemption credited 2x amount.',
    conservedBalance: { balanceField: 'balance' },
  })
  const okOverCredit = verifyReceipt(overCreditReceipt, overCreditTranscript)
  assert.equal(okOverCredit.confirmed, true, okOverCredit.reason)
  assert.equal(okOverCredit.evidence?.violationKind, 'over_credit')
  assert.equal(okOverCredit.evidence?.raceBatchId, 'race_batch_1')

  // Negative A: over_credit < 2 * delta (only credited 50 = 1 * delta, not >= 100) rejected
  const underTwoDelta = verifyReceipt(overCreditReceipt, {
    entries: overCreditTranscript.entries!.map(e => e.exchangeId === 'post'
      ? { ...e, step: { ...e.step, json: { balance: 50 } } }
      : e),
  })
  assert.equal(underTwoDelta.confirmed, false, 'over_credit < 2 * delta must be rejected')

  // Negative B: Unrelated 404 serial control (no serial 2xx, wrong status, wrong route) rejected
  const unrelated404 = verifyReceipt(
    buildProofReceipt({
      vulnClass: 'race_double_spend',
      target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/coupons/redeem' },
      exchangeIds: ['pre', 'b1', 'b2', 'post', 's404'],
      claimedDelta: 'Unrelated 404 serial control.',
    }),
    {
      entries: [
        ...overCreditTranscript.entries!.slice(0, 4),
        { exchangeId: 's404', seq: 5, startedAt: 1200, endedAt: 1210, evidenceRole: 'serial_control_1', origin: ORIGIN, step: mkStep({ id: 's404', arm: 'control', method: 'GET', route: '/api/missing', pathAndQuery: '/api/missing', status: 404, json: { error: 'not found' } }) },
      ],
    },
  )
  assert.equal(unrelated404.confirmed, false, 'unrelated 404 serial control must be rejected')

  // Negative C: Bare 409 without preceding serial 2xx rejected
  const bare409 = verifyReceipt(
    buildProofReceipt({
      vulnClass: 'race_double_spend',
      target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/coupons/redeem' },
      exchangeIds: ['pre', 'b1', 'b2', 'post', 's2'],
      claimedDelta: 'Bare 409 without serial 2xx.',
    }),
    { entries: [...overCreditTranscript.entries!.slice(0, 4), overCreditTranscript.entries![5]!] },
  )
  assert.equal(bare409.confirmed, false, 'bare 409 without preceding serial 2xx must be rejected')

  // Negative D: Missing or mismatched raceBatchId rejected
  const crossBatch = verifyReceipt(overCreditReceipt, {
    entries: overCreditTranscript.entries!.map(e => e.exchangeId === 'b2' ? { ...e, raceBatchId: 'race_batch_other' } : e),
  })
  assert.equal(crossBatch.confirmed, false, 'cross-batch race exchanges must be rejected')

  const noBatch = verifyReceipt(overCreditReceipt, {
    entries: overCreditTranscript.entries!.map(e => ({ ...e, raceBatchId: undefined })),
  })
  assert.equal(noBatch.confirmed, false, 'burst without host raceBatchId must be rejected')

  // Negative E: Missing timestamps rejected
  const noTimestamps = verifyReceipt(overCreditReceipt, {
    entries: overCreditTranscript.entries!.map(e => ({ ...e, startedAt: undefined, endedAt: undefined })),
  })
  assert.equal(noTimestamps.confirmed, false, 'burst without host timestamps must be rejected')

  // Negative F: GET burst or mismatched wallet read routes rejected
  const differentWallets = verifyReceipt(overCreditReceipt, {
    entries: overCreditTranscript.entries!.map(e => e.exchangeId === 'post'
      ? { ...e, step: { ...e.step, route: '/api/wallet-other', pathAndQuery: '/api/wallet-other' } }
      : e),
  })
  assert.equal(differentWallets.confirmed, false, 'mismatched baseline/post read routes must be rejected')

  // Handler tests (`handleProveRace`):
  // 1. Rejects worker-supplied reserved evidenceRole
  const { host: roleHost } = makeMockProveHost(() => ({ status: 200, body: '{"balance":100}' }))
  const reservedRoleRes = await handleProveRace(roleHost, {
    readRoute: '/api/wallet',
    requests: [
      { target: '/api/wallet/redeem', method: 'POST', body: { amount: 10 }, evidenceRole: 'burst_1' },
      { target: '/api/wallet/redeem', method: 'POST', body: { amount: 10 } },
    ],
  }, 'n-r1') as Record<string, unknown>
  assert.equal(reservedRoleRes.ok, false)
  assert.equal(reservedRoleRes.rejectedBy, 'reserved_evidence_role')

  // 2. Requires readRoute (ignores worker baselineExchangeId / postExchangeId / serialExchangeIds fallbacks)
  const { host: noReadHost } = makeMockProveHost(() => ({ status: 200, body: '{"balance":100}' }))
  const noReadRes = await handleProveRace(noReadHost, {
    requests: [
      { target: '/api/wallet/redeem', method: 'POST', body: { amount: 10 } },
      { target: '/api/wallet/redeem', method: 'POST', body: { amount: 10 } },
    ],
    baselineExchangeId: 'gx-fake-1',
    postExchangeId: 'gx-fake-2',
    serialExchangeIds: ['gx-fake-3'],
  }, 'n-r2') as Record<string, unknown>
  assert.equal(noReadRes.ok, false)
  assert.deepEqual(noReadRes.missingEvidence, ['read_route'])

  // 3. Stamps host raceBatchId and forces serial control to be identical to burst request (ignoring serialRequest override)
  const { host: raceHost, httpCalls, raceCalls } = makeMockProveHost((args, idx) => {
    if (String(args.path).includes('/wallet/redeem')) return { status: 200, body: '{"ok":true}' }
    return { status: 200, body: JSON.stringify({ balance: idx === 0 ? 100 : idx === 1 ? 90 : 80 }) }
  })
  const raceOut = await handleProveRace(raceHost, {
    readRoute: '/api/wallet',
    requests: [
      { target: '/api/wallet/redeem', method: 'POST', body: { amount: 10 } },
      { target: '/api/wallet/redeem', method: 'POST', body: { amount: 10 } },
    ],
    serialRequest: { target: '/api/unrelated-404', method: 'GET' },
  }, 'n-r3') as Record<string, unknown>
  assert.equal(typeof raceOut.raceBatchId, 'string')
  assert.ok((raceOut.raceBatchId as string).startsWith('race_'))
  assert.equal(raceCalls.length, 1)
  assert.equal(raceCalls[0]!.raceBatchId, raceOut.raceBatchId)
  // Serial call (httpCalls[2]: baseline=0, post=1, serial=2) MUST target /api/wallet/redeem POST, NOT /api/unrelated-404!
  assert.equal(httpCalls[2]!.path, '/api/wallet/redeem')
  assert.equal(httpCalls[2]!.method, 'POST')
})

// ============================================================================
// 3. H-15: Timing differential oracle
// ============================================================================

test('H-15: timing oracle enforces strict timingArmIdentity, single differing param, status parity, >=5 interleaved arms, host-minted delay vs zero-delay control, and construct-family class', async () => {
  const oracle = new HostMintedOracle()
  const cmdiChallenge = oracle.mintTimingChallenge('cmdi', 2_000)
  const buildEntries = (
    overrideProbe?: (i: number, base: ReceiptTranscriptEntry) => ReceiptTranscriptEntry,
    interleaved = true,
    count = 5,
  ): ReceiptTranscriptEntry[] => {
    const controls: ReceiptTranscriptEntry[] = Array.from({ length: count }, (_, i) => ({
      exchangeId: `c${i}`,
      seq: interleaved ? i * 2 : i,
      origin: ORIGIN,
      sessionId: 'sess-1',
      consumedCapabilities: ['cap:hop_1:a'],
      durationMs: 35,
      hostTimingChallenge: cmdiChallenge,
      step: mkStep({
        id: `c${i}`,
        arm: 'control',
        method: 'GET',
        route: '/api/Search',
        pathAndQuery: `/api/Search?q=${encodeURIComponent(cmdiChallenge.controlToken)}&page=1`,
        status: 200,
      }),
    }))
    const probes: ReceiptTranscriptEntry[] = Array.from({ length: count }, (_, i) => {
      const base: ReceiptTranscriptEntry = {
        exchangeId: `p${i}`,
        seq: interleaved ? i * 2 + 1 : count + i,
        origin: ORIGIN,
        sessionId: 'sess-1',
        consumedCapabilities: ['cap:hop_1:a'],
        durationMs: 2_100,
        hostTimingChallenge: cmdiChallenge,
        step: mkStep({
          id: `p${i}`,
          arm: 'probe',
          method: 'GET',
          route: '/api/Search',
          pathAndQuery: `/api/Search?q=${encodeURIComponent(cmdiChallenge.delayToken)}&page=1`,
          status: 200,
        }),
      }
      return overrideProbe ? overrideProbe(i, base) : base
    })
    return [...controls, ...probes]
  }
  const makeReceipt = (vulnClass: string, count = 5) => buildProofReceipt({
    vulnClass,
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/api/Search?q=${encodeURIComponent(cmdiChallenge.delayToken)}&page=1`, param: 'q' },
    exchangeIds: Array.from({ length: count }, (_, i) => [`c${i}`, `p${i}`]).flat(),
    claimedDelta: 'Host-minted timing delay separation.',
  })

  // Positive: >=5 interleaved arms with strict identity parity & host-minted cmdi challenge confirms as command_injection
  const positive = verifyReceipt(makeReceipt('timing'), {
    hostTimingChallenge: cmdiChallenge,
    entries: buildEntries(),
  }, { hostMintedOracle: oracle })
  assert.equal(positive.confirmed, true, positive.reason)
  assert.equal(positive.vulnClass, 'command_injection', 'class must be derived from host construct family')
  assert.equal(positive.evidence?.constructFamily, 'cmdi')

  // Verify timingArmIdentityOf matches identically across control & probe
  const sampleEntries = buildEntries()
  assert.deepEqual(timingArmIdentityOf(sampleEntries[0]!, 'q'), timingArmIdentityOf(sampleEntries[5]!, 'q'))

  // Negatives (A)-(J):
  // (A) Extra differing query param (`page=1` vs `page=100`)
  assert.equal(verifyReceipt(makeReceipt('timing'), {
    hostTimingChallenge: cmdiChallenge,
    entries: buildEntries((_, b) => ({ ...b, step: { ...b.step, pathAndQuery: `/api/Search?q=${encodeURIComponent(cmdiChallenge.delayToken)}&page=100` } })),
  }, { hostMintedOracle: oracle }).confirmed, false, 'extra differing query param must be rejected')

  // (B) Different capability set
  assert.equal(verifyReceipt(makeReceipt('timing'), {
    hostTimingChallenge: cmdiChallenge,
    entries: buildEntries((_, b) => ({ ...b, consumedCapabilities: ['cap:hop_1:admin'] })),
  }, { hostMintedOracle: oracle }).confirmed, false, 'mismatched capability set must be rejected')

  // (C) Different session jar
  assert.equal(verifyReceipt(makeReceipt('timing'), {
    hostTimingChallenge: cmdiChallenge,
    entries: buildEntries((_, b) => ({ ...b, sessionId: 'sess-other' })),
  }, { hostMintedOracle: oracle }).confirmed, false, 'mismatched sessionId must be rejected')

  // (D) Different POST body shape
  assert.equal(verifyReceipt(makeReceipt('timing'), {
    hostTimingChallenge: cmdiChallenge,
    entries: buildEntries((_, b) => ({ ...b, step: { ...b.step, requestJson: { extra: true } } })),
  }, { hostMintedOracle: oracle }).confirmed, false, 'mismatched body shape must be rejected')

  // (E) Status parity violation (400 vs 200)
  assert.equal(verifyReceipt(makeReceipt('timing'), {
    hostTimingChallenge: cmdiChallenge,
    entries: buildEntries((_, b) => ({ ...b, step: { ...b.step, status: 400 } })),
  }, { hostMintedOracle: oracle }).confirmed, false, 'status mismatch must be rejected')

  // (F) Identical requests (0 differing params)
  assert.equal(verifyReceipt(makeReceipt('timing'), {
    hostTimingChallenge: cmdiChallenge,
    entries: buildEntries((_, b) => ({ ...b, step: { ...b.step, pathAndQuery: `/api/Search?q=${encodeURIComponent(cmdiChallenge.controlToken)}&page=1` } })),
  }, { hostMintedOracle: oracle }).confirmed, false, 'identical requests must be rejected')

  // (G) Case-sensitive path difference (`/api/search` vs `/api/Search`)
  assert.equal(verifyReceipt(makeReceipt('timing'), {
    hostTimingChallenge: cmdiChallenge,
    entries: buildEntries((_, b) => ({ ...b, step: { ...b.step, route: '/api/search', pathAndQuery: `/api/search?q=${encodeURIComponent(cmdiChallenge.delayToken)}&page=1` } })),
  }, { hostMintedOracle: oracle }).confirmed, false, 'case-mismatched path must be rejected')

  // (H) < 5 arms (4+4 rejected)
  assert.equal(verifyReceipt(makeReceipt('timing', 4), {
    hostTimingChallenge: cmdiChallenge,
    entries: buildEntries(undefined, true, 4),
  }, { hostMintedOracle: oracle }).confirmed, false, '<5 arms must be rejected')

  // (I) Non-interleaved blocks (all controls then all probes)
  assert.equal(verifyReceipt(makeReceipt('timing'), {
    hostTimingChallenge: cmdiChallenge,
    entries: buildEntries(undefined, false, 5),
  }, { hostMintedOracle: oracle }).confirmed, false, 'non-interleaved timing arms must be rejected')

  // (J) Missing host-minted timing challenge OR class laundering (`cmdi` claiming `blind_sqli`)
  assert.equal(verifyReceipt(makeReceipt('timing'), {
    entries: buildEntries().map(({ hostTimingChallenge: _drop, ...e }) => e),
  }, { hostMintedOracle: oracle }).confirmed, false, 'timing without host-minted challenge must be rejected')
  assert.equal(verifyReceipt(makeReceipt('blind_sqli'), {
    hostTimingChallenge: cmdiChallenge,
    entries: buildEntries(),
  }, { hostMintedOracle: oracle }).confirmed, false, 'class mismatch with host construct family must be rejected')

  // Handler test (`handleProveDifferential`): rejects non-host-minted timing & persona mismatch
  const { host: diffHost } = makeMockProveHost(() => ({ status: 200, body: '{}', durationMs: 20 }))
  const noTemplate = await handleProveDifferential(diffHost, {
    mode: 'timing',
    control: '/api/search?q=1',
    variant: '/api/search?q=2',
  }, 'n-t1') as Record<string, unknown>
  assert.equal(noTemplate.ok, false)
  assert.deepEqual(noTemplate.missingEvidence, ['host_minted_timing_challenge'])

  const personaMismatch = await handleProveDifferential(diffHost, {
    mode: 'timing',
    timingFamily: 'sqli',
    control: { target: '/api/search?q={{delayToken}}', options: { as: 'alice' } },
    variant: { target: '/api/search?q={{delayToken}}', options: { as: 'admin' } },
  }, 'n-t2') as Record<string, unknown>
  assert.equal(personaMismatch.ok, false)
  assert.deepEqual(personaMismatch.missingEvidence, ['arm_identity_parity'])
})

// ============================================================================
// 4. R2-H-13: Redirect differential rule
// ============================================================================

test('R2-H-13: redirect rule requires same method/route/actor control, 3xx status, host-minted canary host in controlled param, and host-level comparison', () => {
  const oracle = new HostMintedOracle()
  const canary = oracle.mintRedirectCanary()

  const receipt = buildProofReceipt({
    vulnClass: 'open_redirect',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/login?next=https://${canary.host}/cb`, param: 'next' },
    exchangeIds: ['ctl', 'prb'],
    claimedDelta: 'Controlled next parameter redirected to host-minted canary host.',
  })

  // Positive: matching control (stays local) + 302 probe carrying host-minted canary host in `next`
  const positive = verifyReceipt(receipt, {
    entries: [
      { exchangeId: 'ctl', origin: ORIGIN, step: mkStep({ id: 'ctl', arm: 'control', method: 'GET', route: '/login', pathAndQuery: '/login?next=/dashboard', status: 302, responseHeaders: { location: '/dashboard' } }) },
      { exchangeId: 'prb', origin: ORIGIN, hostRedirectCanaryHost: canary.host, step: mkStep({ id: 'prb', arm: 'probe', method: 'GET', route: '/login', pathAndQuery: `/login?next=${encodeURIComponent(`https://${canary.host}/cb`)}`, status: 302, responseHeaders: { location: `https://${canary.host}/cb` } }) },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(positive.confirmed, true, positive.reason)
  assert.equal(positive.evidence?.locationHost, canary.host)

  // Negative 1: Lone probe without control arm rejected
  const loneProbe = verifyReceipt(
    buildProofReceipt({
      vulnClass: 'open_redirect',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/login' },
      exchangeIds: ['prb'],
      claimedDelta: 'Single SSO 302 redirect.',
    }),
    {
      entries: [
        { exchangeId: 'prb', origin: ORIGIN, step: mkStep({ id: 'prb', arm: 'probe', method: 'GET', route: '/login', pathAndQuery: '/login', status: 302, responseHeaders: { location: 'https://idp.example.invalid/authorize?state=abc' } }) },
      ],
    },
    { hostMintedOracle: oracle },
  )
  assert.equal(loneProbe.confirmed, false, 'lone probe redirect must be rejected')

  // Negative 2: SSO/IdP redirect where control and probe hit SAME external host with different `?state=` rejected
  const ssoStateDiff = verifyReceipt(receipt, {
    hostRedirectCanaryHost: canary.host,
    entries: [
      { exchangeId: 'ctl', origin: ORIGIN, step: mkStep({ id: 'ctl', arm: 'control', method: 'GET', route: '/login', pathAndQuery: '/login?next=/a', status: 302, responseHeaders: { location: `https://${canary.host}/authorize?state=ctl_nonce_1` } }) },
      { exchangeId: 'prb', origin: ORIGIN, step: mkStep({ id: 'prb', arm: 'probe', method: 'GET', route: '/login', pathAndQuery: `/login?next=https://${canary.host}/cb`, status: 302, responseHeaders: { location: `https://${canary.host}/authorize?state=prb_nonce_2` } }) },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(ssoStateDiff.confirmed, false, 'same redirect host with differing query/state must be rejected')

  // Negative 3: Off-origin host NOT minted by host oracle rejected
  const unminted = verifyReceipt(
    buildProofReceipt({
      vulnClass: 'open_redirect',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/login?next=https://evil.example.invalid/', param: 'next' },
      exchangeIds: ['ctl', 'prb'],
      claimedDelta: 'Worker-picked redirect host.',
    }),
    {
      entries: [
        { exchangeId: 'ctl', origin: ORIGIN, step: mkStep({ id: 'ctl', arm: 'control', method: 'GET', route: '/login', pathAndQuery: '/login?next=/home', status: 302, responseHeaders: { location: '/home' } }) },
        { exchangeId: 'prb', origin: ORIGIN, step: mkStep({ id: 'prb', arm: 'probe', method: 'GET', route: '/login', pathAndQuery: '/login?next=https://evil.example.invalid/', status: 302, responseHeaders: { location: 'https://evil.example.invalid/' } }) },
      ],
    },
    { hostMintedOracle: oracle },
  )
  assert.equal(unminted.confirmed, false, 'non-host-minted redirect destination must be rejected')

  // Negative 4: Non-3xx status rejected
  const non3xx = verifyReceipt(receipt, {
    hostRedirectCanaryHost: canary.host,
    entries: [
      { exchangeId: 'ctl', origin: ORIGIN, step: mkStep({ id: 'ctl', arm: 'control', method: 'GET', route: '/login', pathAndQuery: '/login?next=/home', status: 200 }) },
      { exchangeId: 'prb', origin: ORIGIN, step: mkStep({ id: 'prb', arm: 'probe', method: 'GET', route: '/login', pathAndQuery: `/login?next=https://${canary.host}/cb`, status: 200, responseHeaders: { location: `https://${canary.host}/cb` } }) },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(non3xx.confirmed, false, 'non-3xx status with Location header must be rejected')

  // Negative 5: Control with mismatched actor rejected
  const diffActor = verifyReceipt(receipt, {
    hostRedirectCanaryHost: canary.host,
    entries: [
      { exchangeId: 'ctl', origin: ORIGIN, step: mkStep({ id: 'ctl', arm: 'control', method: 'GET', route: '/login', pathAndQuery: '/login?next=/home', status: 302, actor: { handle: 'bob', role: 'member', tenant: 'acme', auth: 'bearer', sameSite: null }, responseHeaders: { location: '/home' } }) },
      { exchangeId: 'prb', origin: ORIGIN, step: mkStep({ id: 'prb', arm: 'probe', method: 'GET', route: '/login', pathAndQuery: `/login?next=https://${canary.host}/cb`, status: 302, responseHeaders: { location: `https://${canary.host}/cb` } }) },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(diffActor.confirmed, false, 'control with different actor must be rejected')
})

// ============================================================================
// 5. R2-H-11/H-6: OOB request-side-only carrier, unique carrier, ordering & signed callback
// ============================================================================

test('R2-H-11/H-6: OOB rejects response-only echoes, ambiguous carriers, pre-start callbacks, and tampered callback signatures', () => {
  const token = 'kovo-canary-abcdef0123456789abcdef01'
  const baseEvent: ReceiptOobEvent = {
    id: 'sub-1',
    callbackId: 'cb-1',
    canaryId: 'can-1',
    token,
    targetOrigin: ORIGIN,
    delivered: true,
    stage: 'immediate',
    receivedAtMs: 1_700_000_001_500,
  }
  const signedEvent: ReceiptOobEvent = {
    ...baseEvent,
    callbackSignature: signOobCallback(baseEvent, SIGNING_KEY),
  }
  assert.equal(verifyOobCallbackSignature(signedEvent, SIGNING_KEY), true)
  assert.equal(verifyOobCallbackSignature({ ...signedEvent, receivedAtMs: signedEvent.receivedAtMs + 1 }, SIGNING_KEY), false)

  const reqCarrier: ReceiptTranscriptEntry = {
    exchangeId: 'ex-req',
    op: 'http',
    seq: 1,
    startedAt: 1_700_000_001_000,
    origin: ORIGIN,
    step: mkStep({
      id: 'ex-req',
      arm: 'probe',
      method: 'POST',
      route: '/api/fetch',
      pathAndQuery: '/api/fetch',
      status: 202,
      requestJson: { url: `http://relay.invalid/c/${token}` },
      body: '{"queued":true}',
    }),
  }
  const echoOnly: ReceiptTranscriptEntry = {
    exchangeId: 'ex-echo',
    op: 'http',
    seq: 2,
    startedAt: 1_700_000_001_100,
    origin: ORIGIN,
    carrierText: `GET /api/logs\n{"echo":"${token}"}`,
    step: mkStep({
      id: 'ex-echo',
      arm: 'probe',
      method: 'GET',
      route: '/api/logs',
      pathAndQuery: '/api/logs',
      status: 200,
      body: `{"echo":"${token}"}`,
    }),
  }

  // Positive: unique request-side carrier with startedAt <= receivedAtMs and valid signature confirms
  const okReceipt = buildOobReceipt({
    vulnClass: 'ssrf',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/fetch',
    exchangeIds: ['ex-req'],
    oobEventId: 'sub-1',
    claimedDelta: 'SSRF callback received after POST /api/fetch.',
  })
  const okVerdict = verifyReceipt(okReceipt, { entries: [reqCarrier], oobEvents: [signedEvent] }, { signingKey: SIGNING_KEY })
  assert.equal(okVerdict.confirmed, true, okVerdict.reason)

  // Negative 1: Response-only echo exchange cited as carrier MUST fail closed
  const echoReceipt = buildOobReceipt({
    vulnClass: 'ssrf',
    origin: ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/logs',
    exchangeIds: ['ex-echo'],
    oobEventId: 'sub-1',
    claimedDelta: 'Misattributed echo-only carrier.',
  })
  const echoVerdict = verifyReceipt(echoReceipt, { entries: [echoOnly], oobEvents: [signedEvent] }, { signingKey: SIGNING_KEY })
  assert.equal(echoVerdict.confirmed, false, 'response-only echo must never confirm as an OOB carrier')

  // Negative 2: Ambiguous multiple request-side carriers MUST fail closed
  const secondCarrier: ReceiptTranscriptEntry = { ...reqCarrier, exchangeId: 'ex-req-2', seq: 3 }
  const multiReceipt = buildOobReceipt({
    vulnClass: 'ssrf',
    origin: ORIGIN,
    exchangeIds: ['ex-req', 'ex-req-2'],
    oobEventId: 'sub-1',
    claimedDelta: 'Ambiguous two carriers.',
  })
  const multiVerdict = verifyReceipt(multiReceipt, { entries: [reqCarrier, secondCarrier], oobEvents: [signedEvent] }, { signingKey: SIGNING_KEY })
  assert.equal(multiVerdict.confirmed, false, 'multiple carrying exchanges must be rejected')

  // Negative 3: Callback arrived BEFORE carrier started (startedAt > receivedAtMs) MUST fail closed
  const lateCarrier: ReceiptTranscriptEntry = { ...reqCarrier, startedAt: 1_700_000_009_000 }
  const preStartVerdict = verifyReceipt(okReceipt, { entries: [lateCarrier], oobEvents: [signedEvent] }, { signingKey: SIGNING_KEY })
  assert.equal(preStartVerdict.confirmed, false, 'callback before carrier startedAt must be rejected')

  // Negative 4: Tampered callback timestamp or callbackId fails signature verification
  const tamperedTs: ReceiptOobEvent = { ...signedEvent, receivedAtMs: signedEvent.receivedAtMs + 5000 }
  assert.equal(verifyReceipt(okReceipt, { entries: [reqCarrier], oobEvents: [tamperedTs] }, { signingKey: SIGNING_KEY }).confirmed, false)
  const tamperedId: ReceiptOobEvent = { ...signedEvent, callbackId: 'cb-forged' }
  assert.equal(verifyReceipt(okReceipt, { entries: [reqCarrier], oobEvents: [tamperedId] }, { signingKey: SIGNING_KEY }).confirmed, false)

  // Negative 5: buildAgentScriptReceipt refuses WAIT record missing artifact.receivedAtMs (no WAIT-time fallback)
  const noRelayTs = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Blind SSRF without relay timestamp',
    exchanges: [
      { exchangeId: 'm1', seq: 1, op: 'oob', startedAt: 1000, method: 'MINT', pathAndQuery: '/', origin: ORIGIN, status: null, artifact: { kind: 'oob-mint', token, hit: false } },
      { exchangeId: 'i1', seq: 2, op: 'http', startedAt: 1050, method: 'POST', pathAndQuery: '/api/fetch', origin: ORIGIN, status: 202, requestBody: JSON.stringify({ url: `http://relay.invalid/c/${token}` }), body: '{}' },
      { exchangeId: 'w1', seq: 3, op: 'oob', startedAt: 1100, endedAt: 1200, method: 'WAIT', pathAndQuery: '/oob/pending/sub-x', origin: '', status: null, artifact: { kind: 'oob-mint', token, hit: true, subscriptionId: 'sub-x' } },
    ],
    claims: [{ kind: 'oob', exchangeId: 'm1', expectHit: true }],
  })
  assert.equal(noRelayTs, null, 'WAIT artifact without host receivedAtMs must not synthesize callback time from WAIT endedAt')
})

// ============================================================================
// 6. H-13 & R2-C-9: credentialPlacement, SameSite binding, CSRF sendability,
//    clean kernel request plane, and TerminalOracleRegistry embedded custody
// ============================================================================

test('H-13: HostFactLog records host credentialPlacement, binds SameSite strictly to authenticating cookie (default Lax), and CSRF requires cross-site sendability', () => {
  // 1. Bearer persona + junk cookie capability => mixed=true, ambientAuth='bearer' (never 'cookie')
  const mixedPlacement = deriveCredentialPlacement(
    { authorization: 'Bearer real_api_tok', cookie: 'junk=1' },
    { personaAuthKind: 'bearer', capabilityTargets: ['cookie'] },
  )
  assert.equal(mixedPlacement.mixed, true)
  assert.equal(deriveAmbientAuthFromHeaders({ authorization: 'Bearer real_api_tok', cookie: 'junk=1' }, undefined, mixedPlacement), 'bearer')

  // 2. SameSite bound strictly to authenticating cookie; cosmetic cookie SameSite=None does NOT override sid; unknown defaults to Lax
  const setCookieHeader = 'theme=dark; Path=/; SameSite=None; Secure, sid=sess_auth_1; Path=/; HttpOnly'
  assert.equal(extractSameSiteFromHeaders({ 'set-cookie': setCookieHeader }, 'sid'), 'Lax')
  assert.equal(extractSameSiteFromHeaders({ 'set-cookie': setCookieHeader }, 'theme'), 'None')

  const laxLog = new HostFactLog()
  laxLog.recordExchange({
    seq: 1, exchangeId: 'pre', method: 'GET', origin: ORIGIN, pathAndQuery: '/api/profile', status: 200,
    requestHeaders: { cookie: 'sid=sess_auth_1; theme=dark' },
    responseHeaders: { 'set-cookie': setCookieHeader },
    rawResponseBody: '{"email":"old@acme.example"}',
    actor: 'alice', actorRoleLabel: 'member (acme)',
  })
  laxLog.recordExchange({
    seq: 2, exchangeId: 'prb', method: 'POST', origin: ORIGIN, pathAndQuery: '/api/profile', status: 200,
    requestHeaders: { cookie: 'sid=sess_auth_1; theme=dark', origin: 'https://attacker.invalid', 'content-type': 'application/x-www-form-urlencoded' },
    rawRequestBody: 'email=pwned@attacker.invalid',
    rawResponseBody: '{"email":"pwned@attacker.invalid"}',
    actor: 'alice', actorRoleLabel: 'member (acme)',
  })
  laxLog.recordExchange({
    seq: 3, exchangeId: 'post', method: 'GET', origin: ORIGIN, pathAndQuery: '/api/profile', status: 200,
    requestHeaders: { cookie: 'sid=sess_auth_1' },
    rawResponseBody: '{"email":"pwned@attacker.invalid"}',
    actor: 'alice', actorRoleLabel: 'member (acme)',
  })
  assert.equal(laxLog.resolveSameSite('prb'), 'Lax', 'unknown SameSite on authenticating cookie sid must default to Lax, ignoring cosmetic theme=SameSite=None')
  const laxBuilt = buildAgentScriptReceipt({
    origin: ORIGIN,
    title: 'Unknown SameSite CSRF attempt',
    exchanges: [],
    factLog: laxLog,
    claims: [{ kind: 'impact', impactClass: 'csrf', vulnClass: 'csrf', beforeExchangeId: 'pre', probeExchangeId: 'prb', afterExchangeId: 'post' }],
  })
  assert.ok(laxBuilt)
  assert.equal(verifyReceipt(laxBuilt.receipt, laxBuilt.transcript).confirmed, false, 'default-Lax authenticating cookie must NOT confirm CSRF')

  // 3. Cross-site sendability: SameSite=None with application/json OR custom header OR CSRF token is REJECTED; form-encoded with no token CONFIRMS
  const makeCsrfLog = (probeHeaders: Record<string, string>, probeBody: string) => {
    const log = new HostFactLog()
    log.recordExchange({
      seq: 1, exchangeId: 'pre', method: 'GET', origin: ORIGIN, pathAndQuery: '/api/profile', status: 200,
      requestHeaders: { cookie: 'sid=sess_none_1' },
      responseHeaders: { 'set-cookie': 'sid=sess_none_1; Path=/; SameSite=None; Secure' },
      rawResponseBody: '{"email":"old@acme.example"}',
      actor: 'alice', actorRoleLabel: 'member (acme)',
    })
    log.recordExchange({
      seq: 2, exchangeId: 'prb', method: 'POST', origin: ORIGIN, pathAndQuery: '/api/profile', status: 200,
      requestHeaders: { cookie: 'sid=sess_none_1', origin: 'https://attacker.invalid', ...probeHeaders },
      rawRequestBody: probeBody,
      rawResponseBody: '{"email":"new@attacker.invalid"}',
      actor: 'alice', actorRoleLabel: 'member (acme)',
    })
    log.recordExchange({
      seq: 3, exchangeId: 'post', method: 'GET', origin: ORIGIN, pathAndQuery: '/api/profile', status: 200,
      requestHeaders: { cookie: 'sid=sess_none_1' },
      rawResponseBody: '{"email":"new@attacker.invalid"}',
      actor: 'alice', actorRoleLabel: 'member (acme)',
    })
    return log
  }

  // JSON Content-Type => NOT cross-site sendable (requires CORS preflight)
  const jsonLog = makeCsrfLog({ 'content-type': 'application/json' }, '{"email":"new@attacker.invalid"}')
  assert.equal(isCrossSiteSendableCsrfRequest(jsonLog.toImpactStep('prb', { arm: 'probe' })!, ORIGIN).sendable, false)
  const jsonBuilt = buildAgentScriptReceipt({
    origin: ORIGIN, title: 'JSON CSRF', exchanges: [], factLog: jsonLog,
    claims: [{ kind: 'impact', impactClass: 'csrf', vulnClass: 'csrf', beforeExchangeId: 'pre', probeExchangeId: 'prb', afterExchangeId: 'post' }],
  })!
  assert.equal(verifyReceipt(jsonBuilt.receipt, jsonBuilt.transcript).confirmed, false, 'application/json CSRF must be rejected')

  // Custom X-CSRF-Token header => NOT cross-site sendable
  const customHdrLog = makeCsrfLog({ 'content-type': 'application/x-www-form-urlencoded', 'x-csrf-token': 'tok_123' }, 'email=new@attacker.invalid')
  assert.equal(isCrossSiteSendableCsrfRequest(customHdrLog.toImpactStep('prb', { arm: 'probe' })!, ORIGIN).sendable, false)

  // Form-encoded with SameSite=None and no custom header/token => CONFIRMS
  const formLog = makeCsrfLog({ 'content-type': 'application/x-www-form-urlencoded' }, 'email=new@attacker.invalid')
  assert.equal(isCrossSiteSendableCsrfRequest(formLog.toImpactStep('prb', { arm: 'probe' })!, ORIGIN).sendable, true)
  const formBuilt = buildAgentScriptReceipt({
    origin: ORIGIN, title: 'Form CSRF', exchanges: [], factLog: formLog,
    claims: [{ kind: 'impact', impactClass: 'csrf', vulnClass: 'csrf', beforeExchangeId: 'pre', probeExchangeId: 'prb', afterExchangeId: 'post' }],
  })!
  assert.equal(verifyReceipt(formBuilt.receipt, formBuilt.transcript).confirmed, true, 'form-encoded SameSite=None CSRF with no custom header/token must confirm')
})

test('R2-C-9 & R2-H-6: kernel request plane rejects vault-scrubbed [redacted:cap:...] tokens and TerminalOracleRegistry sanitizes embedded composite receipts strictly', () => {
  // R2-C-9: HostFactLog clean request plane assertion
  assert.equal(hasVaultScrubbedRequestPlane({ pathAndQuery: '/search?q=[redacted:cap:hop_1:tok]' }), true)
  assert.throws(() => assertCleanKernelRequestPlane({ exchangeId: 'ex-1', pathAndQuery: '/search?q=[redacted:cap:hop_1:tok]' }), /vault-scrubbed/i)

  const strictLog = new HostFactLog({ assertCleanRequestPlane: true })
  assert.throws(() => {
    strictLog.recordExchange({
      exchangeId: 'scrubbed-1', method: 'GET', origin: ORIGIN,
      pathAndQuery: '/search?q=[redacted:cap:hop_1:m]', status: 200, rawResponseBody: 'echoed',
    })
  }, /vault-scrubbed/i)

  // R2-C-9: verifyReceipt fails closed when kernel request plane contains `[redacted:cap:...]`
  const oracle = new HostMintedOracle()
  const ch = oracle.mintExpressionChallenge('ssti')
  const scrubbedReceipt = buildProofReceipt({
    vulnClass: 'ssti',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/render?q=test' },
    exchangeIds: ['c1', 'p1'],
    claimedDelta: 'Claimed evaluation with scrubbed request plane.',
  })
  const scrubbedVerdict = verifyReceipt(scrubbedReceipt, {
    hostExpressionChallenges: [ch],
    entries: [
      { exchangeId: 'c1', origin: ORIGIN, step: mkStep({ id: 'c1', arm: 'control', method: 'GET', route: '/render', pathAndQuery: '/render?q=benign', status: 200, body: 'benign' }) },
      { exchangeId: 'p1', origin: ORIGIN, hostExpressionChallenge: ch, step: mkStep({ id: 'p1', arm: 'probe', method: 'GET', route: '/render', pathAndQuery: '/render?q=[redacted:cap:hop_1:marker]', status: 200, body: `result ${ch.expectedOutput}` }) },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(scrubbedVerdict.confirmed, false, 'vault-scrubbed kernel request plane must fail closed in verifyReceipt')
  assert.match(scrubbedVerdict.reason, /vault-scrubbed/i)

  // R2-H-6: TerminalOracleRegistry enforces strict host derivation even if strictHostDerivation:false is passed,
  // and sanitizes/binds embedded terminal proofReceipts inside composite receipts.
  const massLog = new HostFactLog()
  massLog.recordExchange({ seq: 1, exchangeId: 'pre', arm: 'control', method: 'GET', origin: ORIGIN, pathAndQuery: '/api/users/1', status: 200, actor: 'alice', actorRoleLabel: 'member (acme)', rawResponseBody: '{"id":"1","note":"old","role":"member"}', timestampMs: 1000, cleanSession: true })
  massLog.recordExchange({ seq: 2, exchangeId: 'prb', arm: 'probe', method: 'PATCH', origin: ORIGIN, pathAndQuery: '/api/users/1', status: 200, actor: 'alice', actorRoleLabel: 'member (acme)', rawRequestBody: '{"note":"new"}', rawResponseBody: '{"id":"1","note":"new","role":"admin"}', timestampMs: 1100, cleanSession: true })
  massLog.recordExchange({ seq: 3, exchangeId: 'post', arm: 'control', method: 'GET', origin: ORIGIN, pathAndQuery: '/api/users/1', status: 200, actor: 'alice', actorRoleLabel: 'member (acme)', rawResponseBody: '{"id":"1","note":"new","role":"admin"}', timestampMs: 1200, cleanSession: true })

  const forgedMassReceipt = buildProofReceipt({
    vulnClass: 'mass_assignment',
    target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/api/users/1' },
    exchangeIds: ['pre', 'prb', 'post'],
    claimedDelta: 'Forged mass assignment via declared oracleEvents.',
    oracleEvents: ['mass_assignment'],
    requiredRole: 'admin',
    resourceTenant: 'globex',
  })

  // Direct sanitizer strips worker scalars even when policy.strictHostDerivation === false
  const cleaned = sanitizeSingleHopReceiptForHostCustody(forgedMassReceipt, massLog, { strictHostDerivation: false })
  assert.equal(cleaned.oracleEvents, undefined)
  assert.equal(cleaned.requiredRole, undefined)
  assert.equal(cleaned.resourceTenant, undefined)

  const registry = new TerminalOracleRegistry()
  const singleRes = registry.evaluate(massLog, { kind: 'single_hop', receipt: forgedMassReceipt }, { strictHostDerivation: false })
  assert.equal(singleRes.confirmed, false, 'strict host derivation must strip worker oracleEvents even when strictHostDerivation:false is passed')

  // Composite embedded proofReceipt with declared oracleEvents AND class laundering (mass_assignment -> bola) rejected
  const compositeWithSpoofedEmbedded = {
    chainId: 'movea-embedded-launder',
    terminalVulnClass: 'bola',
    hops: [{
      hopId: 'hop_1',
      surface: 'http',
      target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/api/users/1' },
      exchangeIds: ['pre', 'prb', 'post'],
      claimedDelta: 'Laundered mass_assignment under bola.',
      proofReceipt: forgedMassReceipt,
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      terminalExchangeId: 'prb',
      summary: 'Attempted class laundering and declared oracleEvents via embedded proofReceipt.',
      preChainControlExchangeIds: ['pre'],
      postChainReadbackExchangeIds: ['post'],
      proofReceipt: forgedMassReceipt,
    },
    replayMode: 'fresh_clean_replay',
  }
  const compRes = registry.evaluate(massLog, { kind: 'composite', receipt: compositeWithSpoofedEmbedded }, { strictHostDerivation: false })
  assert.equal(compRes.confirmed, false, 'embedded terminal proofReceipt class mismatch and declared events must be rejected')
  assert.match(compRes.reason, /does not match composite terminalVulnClass/i)
})
