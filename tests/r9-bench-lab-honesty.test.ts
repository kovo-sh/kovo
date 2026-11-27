/**
 * Regression suite for M2 R9 benchmark lab & grader honesty fixes (grounded in audit #1692):
 *   1. PayGrid domain-variant: org_b does NOT prefix-overlap org_a (closing the unintended
 *      org_a -> org_b signed-URL export leak), while org_c -> org_b remains intact for PG-C3.
 *   2. PayGrid billing: single capture credits order.amountCents (conserving balance), while
 *      a duplicate-key concurrent race credits >= 2 * order.amountCents and triggers PG-C4.
 *   3. Grader twin attribution: vulnerable-mode partial/unconfirmed base-chain Mode-A receipts
 *      (e.g. NX-C1 h1-h4 on PATCH /scim/users/:id, or PG-C3 terminal without oracle) are scored
 *      as strict unmatchedFalsePositives (precision penalized) rather than falsely attributed to
 *      an inactive hardened twin, while genuine decoy-hop-only FPs, unverified/self-declared
 *      findings, hardened mode, and twin mode STILL strictly fail with hardenedTwinDecoyFps >= 1.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import { generateDomainVariant } from '../benchmarks/multihop-saas/lib/domain-variant.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
import type { OracleExport } from '../benchmarks/multihop-saas/lib/types.ts'
import {
  gradeRun,
  startMultihopApp,
  type ProductSubmittedCompositeProof,
  type ProductSubmittedFinding,
  type StartedMultihopApp,
} from '../benchmarks/multihop-saas/run.ts'

function routePrefixOf(started: StartedMultihopApp): string {
  const meRef = started.briefing('grey-box').apiReference?.find((r) => r.routeKey === 'api.me')
  assert.ok(meRef, `${started.app}: expected api.me in grey-box apiReference`)
  return meRef.path.replace(/\/me$/, '')
}

function makeOracleExport(
  started: StartedMultihopApp,
  observedChainIds: readonly string[],
): OracleExport {
  const observed = new Set(observedChainIds)
  const evaluations = started.groundTruth.expectedChains.map((expected) => {
    const ok = observed.has(expected.chainId)
    return {
      chainId: expected.chainId,
      completed: ok,
      confirmed: ok,
      hopsObserved: ok ? expected.hopIds.length : 0,
      hopsTotal: expected.hopIds.length,
      missingHopIds: ok ? [] : [...expected.hopIds],
      terminalObserved: ok,
      receiptVerified: ok,
      ...(ok ? { terminalAt: 100 } : { dropReason: 'pivot_not_discovered' as const }),
    }
  })
  return {
    runId: started.runId,
    evaluations,
    confirmed: [],
    events: { hops: [], edges: [], controls: [], terminals: [] },
    receipts: [],
    receiptVerification: [],
  }
}

async function jsonRequest<T>(
  url: string,
  opts: { method?: string; token?: string; body?: unknown; rawBody?: string } = {},
): Promise<{ status: number; text: string; json: () => T }> {
  const headers: Record<string, string> = {}
  if (opts.token) headers.authorization = `Bearer ${opts.token}`
  let bodyStr: string | undefined
  if (opts.rawBody !== undefined) {
    headers['content-type'] = 'application/json'
    bodyStr = opts.rawBody
  } else if (opts.body !== undefined) {
    headers['content-type'] = 'application/json'
    bodyStr = JSON.stringify(opts.body)
  }
  const res = await fetch(url, {
    method: opts.method ?? (bodyStr !== undefined ? 'POST' : 'GET'),
    headers,
    body: bodyStr,
  })
  const text = await res.text()
  return {
    status: res.status,
    text,
    json: () => JSON.parse(text) as T,
  }
}

// ---------------------------------------------------------------------------
// 1. Domain variant prefix overlap: org_b must NOT overlap org_a; org_c -> org_b stays intact
// ---------------------------------------------------------------------------

test('domain-variant drops org_b -> org_a prefixOverlapWith while keeping org_c -> org_b for PG-C3', async () => {
  for (let seed = 1; seed <= 10; seed++) {
    const plan = generateDomainVariant('paygrid', seed)
    assert.equal(plan.tenants.a.prefixOverlapWith, undefined, `seed ${seed}: org_a has no overlap`)
    assert.equal(plan.tenants.b.prefixOverlapWith, undefined, `seed ${seed}: org_b must NOT overlap org_a`)
    assert.equal(plan.tenants.c.prefixOverlapWith, 'org_b', `seed ${seed}: org_c must still overlap org_b`)
  }

  // Live PayGrid verification: org_a signed URL cannot be replayed against org_b's path
  const started = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', fastLab: true })
  try {
    const plan = generateDomainVariant('paygrid', 1)
    const p = routePrefixOf(started)
    const api = started.origins.api!
    const edge = started.origins.edge!

    const loginA = await jsonRequest<{ token: string }>(`${api}${p}/auth/login`, {
      method: 'POST',
      body: { email: plan.personas.member_a.email, password: plan.personas.member_a.password },
    })
    assert.equal(loginA.status, 200)
    const tokenA = loginA.json().token

    const created = await jsonRequest<{ jobId: string }>(`${api}${p}/orgs/org_a/exports`, {
      method: 'POST',
      token: tokenA,
    })
    assert.equal(created.status, 202)
    const jobId = created.json().jobId

    let ready = false
    for (let i = 0; i < 60; i++) {
      const poll = await jsonRequest<{ job: { status: string } }>(`${api}${p}/exports/${jobId}`, {
        method: 'GET',
        token: tokenA,
      })
      if (poll.status === 200 && poll.json().job.status === 'ready') {
        ready = true
        break
      }
      await new Promise((r) => setTimeout(r, 10))
    }
    assert.equal(ready, true, 'org_a export job should complete')

    const urlRes = await jsonRequest<{ signedUrl: string }>(`${api}${p}/exports/${jobId}/url`, {
      method: 'GET',
      token: tokenA,
    })
    assert.equal(urlRes.status, 200)
    const signedUrl = new URL(urlRes.json().signedUrl)

    // Own-tenant download succeeds
    const ownDownload = await jsonRequest<unknown>(signedUrl.toString(), { method: 'GET', token: tokenA })
    assert.equal(ownDownload.status, 200)

    // Swapping path tenant org_a -> org_b MUST be denied (403)
    const swapped = new URL(signedUrl.toString())
    swapped.pathname = swapped.pathname.replace(
      `/files/export/${plan.tenants.a.slug}`,
      `/files/export/${plan.tenants.b.slug}`,
    )
    const crossDownload = await jsonRequest<{ error?: string }>(`${edge}${swapped.pathname}${swapped.search}`, {
      method: 'GET',
      token: tokenA,
    })
    assert.equal(crossDownload.status, 403, 'org_a signed URL must not download org_b treasury')
  } finally {
    await started.stop()
  }
})

// ---------------------------------------------------------------------------
// 2. PayGrid billing: single capture conserves order.amountCents; race overcredits >= 2x & triggers PG-C4
// ---------------------------------------------------------------------------

test('PayGrid billing single capture credits order.amountCents (conserves balance) while duplicate-key race credits >= 2x and triggers PG-C4', async () => {
  const started = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', fastLab: true })
  try {
    const plan = generateDomainVariant('paygrid', 1)
    const p = routePrefixOf(started)
    const api = started.origins.api!
    const edge = started.origins.edge!

    const login = await jsonRequest<{ token: string }>(`${api}${p}/auth/login`, {
      method: 'POST',
      body: { email: plan.personas.member_a.email, password: plan.personas.member_a.password },
    })
    assert.equal(login.status, 200)
    const token = login.json().token

    const balanceBefore = (await jsonRequest<{ balanceCents: number }>(`${api}${p}/balance`, {
      method: 'GET',
      token,
    })).json().balanceCents

    // (a) Benign 1x capture on a normal 5,000¢ order MUST credit exactly 5,000¢ (not fixed raceCreditCents)
    const benignOrderAmount = 5_000
    assert.notEqual(benignOrderAmount, plan.economics.raceCreditCents)
    const benignCreate = await jsonRequest<{ order: { id: string; amountCents: number } }>(`${edge}${p}/orders`, {
      method: 'POST',
      token,
      body: { amountCents: benignOrderAmount, beneficiary: 'acct_benign_vendor' },
    })
    assert.equal(benignCreate.status, 201)
    const benignOrderId = benignCreate.json().order.id
    assert.equal(benignCreate.json().order.amountCents, benignOrderAmount)

    const benignRebind = await jsonRequest(`${api}${p}/orders/${benignOrderId}/rebind`, {
      method: 'PATCH',
      token,
      body: { beneficiary: 'acct_benign_vendor' },
    })
    assert.equal(benignRebind.status, 200)

    const benignCapture = await jsonRequest(`${api}${p}/orders/${benignOrderId}/settle-race`, {
      method: 'POST',
      token,
    })
    assert.equal(benignCapture.status, 200)

    // Repeat capture on standard order is rejected (409 idempotent)
    const benignRepeat = await jsonRequest(`${api}${p}/orders/${benignOrderId}/settle-race`, {
      method: 'POST',
      token,
    })
    assert.equal(benignRepeat.status, 409)

    const balanceAfterBenign = (await jsonRequest<{ balanceCents: number }>(`${api}${p}/balance`, {
      method: 'GET',
      token,
    })).json().balanceCents
    assert.equal(
      balanceAfterBenign - balanceBefore,
      benignOrderAmount,
      'benign 1x capture must conserve balance (delta === order.amountCents)',
    )

    // (b) Duplicate-key race on high-value order credits >= 2 * order.amountCents and triggers PG-C4 oracle
    const inflatedAmount = plan.economics.payoutCapCents + plan.economics.orderAmountCents
    const rawDupBody = `{"amountCents":${inflatedAmount},"beneficiary":"acct_vendor_1","amountCents":100}`

    let raceCredits = 0
    let raceOrderId = ''
    for (let attempt = 0; attempt < 4; attempt++) {
      const created = await jsonRequest<{ order: { id: string } }>(`${edge}${p}/orders`, {
        method: 'POST',
        token,
        rawBody: rawDupBody,
      })
      assert.equal(created.status, 201)
      const orderId = created.json().order.id

      // Pre-rebind control capture denial (required by PG-C4 ablation control)
      const ctrl = await jsonRequest(`${api}${p}/orders/${orderId}/settle-race`, {
        method: 'POST',
        token,
      })
      assert.equal(ctrl.status, 409)

      const rebind = await jsonRequest(`${api}${p}/orders/${orderId}/rebind`, {
        method: 'PATCH',
        token,
        body: { beneficiary: 'acct_race_target' },
      })
      assert.equal(rebind.status, 200)

      const burst = await Promise.all(
        Array.from({ length: 4 }, () => jsonRequest(`${api}${p}/orders/${orderId}/settle-race`, {
          method: 'POST',
          token,
        })),
      )
      const okCount = burst.filter((r) => r.status === 200).length
      if (okCount >= 2) {
        raceCredits = okCount
        raceOrderId = orderId
        break
      }
    }
    assert.ok(raceCredits >= 2, `expected concurrent race to achieve >= 2 credits, got ${raceCredits}`)

    const ledgerRes = await jsonRequest<{ entries: Array<{ memo: string; amountCents: number }> }>(
      `${api}${p}/ledger`,
      { method: 'GET', token },
    )
    assert.equal(ledgerRes.status, 200)
    const raceEntries = ledgerRes.json().entries.filter((e) => e.memo === `capture:${raceOrderId}`)
    assert.equal(raceEntries.length, raceCredits)
    const totalRaceCredited = raceEntries.reduce((sum, e) => sum + e.amountCents, 0)
    assert.equal(totalRaceCredited, inflatedAmount * raceCredits)
    assert.ok(totalRaceCredited >= 2 * inflatedAmount, 'race must violate conservation (>= 2 * order.amountCents)')

    const pgC4Eval = started.export().evaluations.find((ev) => ev.chainId === 'PG-C4')
    assert.equal(pgC4Eval?.completed, true, 'PG-C4 oracle must confirm the duplicate-key race')
    assert.equal(pgC4Eval?.terminalObserved, true)
  } finally {
    await started.stop()
  }
})

// ---------------------------------------------------------------------------
// 3. Grader twin attribution: vulnerable-mode partial/unconfirmed base-chain receipts vs genuine decoys
// ---------------------------------------------------------------------------

test('grader does not misattribute vulnerable-mode NX-C1 h1-h4 partial receipt to inactive NX-D1, while decoy-only/hardened/twin still fail strictly', async () => {
  const vuln = await startMultihopApp({ app: 'nexusiam', seed: 1, mode: 'grey-box', fastLab: true })
  const hardened = await startMultihopApp({ app: 'nexusiam', seed: 1, mode: 'hardened', fastLab: true })
  const twinD1 = await startMultihopApp({ app: 'nexusiam', seed: 1, mode: 'grey-box', twin: 'NX-D1', fastLab: true })
  try {
    const p = routePrefixOf(vuln)

    // Shape of R8 WB e458fed3: 3-hop confirmed Mode-A receipt on NX-C1 h1-h4 (POST /comments ->
    // PATCH /scim/users/:id -> GET /me readback), missing h5 terminal (GET /audit/vault).
    const nxC1PartialReceipt: ProductSubmittedCompositeProof = {
      findingId: 'e458fed3',
      chainId: 'generic-nx-scim-escalation',
      terminalVulnClass: 'privilege_escalation',
      hopCount: 3,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'POST', pathAndQuery: `${p}/comments` } },
          { hopId: 'h2', target: { method: 'PATCH', pathAndQuery: `${p}/scim/users/mh_usr_target` } },
          { hopId: 'h3', target: { method: 'GET', pathAndQuery: `${p}/me` } },
        ],
        causalEdges: [{ kind: 'value_binding' }],
        terminalImpact: { terminalHopId: 'h3' },
      },
      verification: {
        terminalEndpoint: `${p}/me`,
        terminalOracleFamily: null,
      },
    }
    const nxC1PartialFindingWithEarlyHop: ProductSubmittedFinding = {
      id: 'e458fed3',
      findingId: 'e458fed3',
      vulnClass: 'privilege_escalation',
      endpoints: [
        { method: 'POST', path: `${p}/comments` },
        { method: 'PATCH', path: `${p}/scim/users/mh_usr_target` },
        { method: 'GET', path: `${p}/me` },
      ],
      status: 'confirmed',
    }
    const nxC1PartialFindingPostOnly: ProductSubmittedFinding = {
      id: 'e458fed3',
      findingId: 'e458fed3',
      vulnClass: 'privilege_escalation',
      endpoints: [
        { method: 'PATCH', path: `${p}/scim/users/mh_usr_target` },
        { method: 'GET', path: `${p}/me` },
      ],
      status: 'confirmed',
    }

    // (a) Vulnerable mode with early hop + post-enforcement hop (PATCH /scim/users/:id):
    //     NOT falsely blamed on inactive NX-D1, but remains a strict unmatched FP (precision = 0).
    const vulnWithEarly = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [nxC1PartialFindingWithEarlyHop],
      compositeReceipts: [nxC1PartialReceipt],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, []),
      mode: 'white-box',
    })
    assert.equal(vulnWithEarly.chainsConfirmed, 0)
    assert.equal(vulnWithEarly.hardenedTwins.find((t) => t.twinId === 'NX-D1')?.falsePositive, false)
    assert.equal(vulnWithEarly.hardenedTwinDecoyFps, 0)
    assert.equal(vulnWithEarly.unmatchedFalsePositives, 1)
    assert.equal(vulnWithEarly.precision, 0)

    // (b) Vulnerable mode with post-enforcement endpoints only (matching NX-D1 only via vulnClass):
    //     NOT falsely blamed on NX-D1, still strict unmatched FP.
    const vulnPostOnly = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [nxC1PartialFindingPostOnly],
      compositeReceipts: [nxC1PartialReceipt],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, []),
      mode: 'white-box',
    })
    assert.equal(vulnPostOnly.hardenedTwins.find((t) => t.twinId === 'NX-D1')?.falsePositive, false)
    assert.equal(vulnPostOnly.hardenedTwinDecoyFps, 0)
    assert.equal(vulnPostOnly.unmatchedFalsePositives, 1)
    assert.equal(vulnPostOnly.precision, 0)

    // (c) Genuine decoy-hop-only finding in vulnerable mode (stops at POST /scim/tokens, never reaches h4):
    //     MUST STILL fail with NX-D1 hardenedTwinDecoyFps >= 1!
    const decoyOnlyReceipt: ProductSubmittedCompositeProof = {
      findingId: 'nx-decoy-only',
      chainId: 'generic-nx-decoy-only',
      terminalVulnClass: 'privilege_escalation',
      hopCount: 2,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'POST', pathAndQuery: `${p}/comments` } },
          { hopId: 'h2', target: { method: 'POST', pathAndQuery: `${p}/scim/tokens` } },
        ],
        causalEdges: [{ kind: 'value_binding' }],
        terminalImpact: { terminalHopId: 'h2' },
      },
      verification: { terminalEndpoint: `${p}/scim/tokens` },
    }
    const decoyOnlyCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [{
        id: 'nx-decoy-only',
        vulnClass: 'privilege_escalation',
        endpoints: [
          { method: 'POST', path: `${p}/comments` },
          { method: 'POST', path: `${p}/scim/tokens` },
        ],
        status: 'confirmed',
      }],
      compositeReceipts: [decoyOnlyReceipt],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, []),
      mode: 'white-box',
    })
    assert.equal(decoyOnlyCard.hardenedTwins.find((t) => t.twinId === 'NX-D1')?.falsePositive, true)
    assert.ok(decoyOnlyCard.hardenedTwinDecoyFps >= 1)
    assert.equal(decoyOnlyCard.precision, 0)

    // (d) Unverified / self-declared finding listing early hop + h4 WITHOUT a confirmed Mode-A receipt:
    //     MUST STILL fail with NX-D1 hardenedTwinDecoyFps >= 1!
    const unverifiedCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [nxC1PartialFindingWithEarlyHop],
      compositeReceipts: [],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, []),
      mode: 'white-box',
    })
    assert.equal(unverifiedCard.hardenedTwins.find((t) => t.twinId === 'NX-D1')?.falsePositive, true)
    assert.ok(unverifiedCard.hardenedTwinDecoyFps >= 1)
    assert.equal(unverifiedCard.precision, 0)

    // (e) Hardened mode AND NX-D1 twin mode MUST STILL fail with hardenedTwinDecoyFps >= 1!
    const hardenedCard = gradeRun({
      groundTruth: hardened.groundTruth,
      findings: [nxC1PartialFindingWithEarlyHop],
      compositeReceipts: [nxC1PartialReceipt],
      oracleEvents: [],
      oracleExport: hardened.export(),
      mode: 'white-box',
    })
    assert.equal(hardenedCard.chainsConfirmed, 0)
    assert.ok(hardenedCard.hardenedTwinDecoyFps >= 1)
    assert.equal(hardenedCard.precision, 0)

    const twinCard = gradeRun({
      groundTruth: twinD1.groundTruth,
      findings: [nxC1PartialFindingWithEarlyHop],
      compositeReceipts: [nxC1PartialReceipt],
      oracleEvents: [],
      oracleExport: twinD1.export(),
      mode: 'white-box',
    })
    assert.equal(twinCard.chainsConfirmed, 0)
    assert.equal(twinCard.hardenedTwins.find((t) => t.twinId === 'NX-D1')?.falsePositive, true)
    assert.ok(twinCard.hardenedTwinDecoyFps >= 1)
    assert.equal(twinCard.precision, 0)
  } finally {
    await vuln.stop()
    await hardened.stop()
    await twinD1.stop()
  }
})

test('grader does not misattribute vulnerable-mode unconfirmed PG-C3 terminal receipt to inactive PG-D3, while PG-D3 twin & decoy-only still fail strictly', async () => {
  const vuln = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', fastLab: true })
  const hardened = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'hardened', fastLab: true })
  const twinD3 = await startMultihopApp({ app: 'paygrid', seed: 1, mode: 'grey-box', twin: 'PG-D3', fastLab: true })
  try {
    const p = routePrefixOf(vuln)
    const pgC3Receipt: ProductSubmittedCompositeProof = {
      findingId: '900e90fb',
      chainId: 'generic-pg-export-replay',
      terminalVulnClass: 'cross_tenant_export',
      hopCount: 2,
      replayMode: 'fresh_clean_replay',
      confirmed: true,
      attackerProvenanceValid: true,
      receipt: {
        hops: [
          { hopId: 'h1', target: { method: 'GET', pathAndQuery: `${p}/exports/exp_1/url` } },
          { hopId: 'h2', target: { method: 'GET', pathAndQuery: '/files/export/acme-corp/treasury-acme-corp.csv?sig=abc' } },
        ],
        causalEdges: [{ kind: 'value_binding' }],
        terminalImpact: { terminalHopId: 'h2' },
      },
      verification: {
        terminalEndpoint: '/files/export/acme-corp/treasury-acme-corp.csv?sig=abc',
        terminalOracleFamily: 'cryptographic_scope_replay',
      },
    }
    const pgC3Finding: ProductSubmittedFinding = {
      id: '900e90fb',
      findingId: '900e90fb',
      vulnClass: 'cross_tenant_export',
      endpoints: [
        { method: 'GET', path: `${p}/exports/exp_1/url` },
        { method: 'GET', path: '/files/export/acme-corp/treasury-acme-corp.csv' },
      ],
      status: 'confirmed',
    }

    // (a) Vulnerable mode with oracleObserved=false: unmatched FP (precision = 0), NOT PG-D3 twin FP
    const vulnCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [pgC3Finding],
      compositeReceipts: [pgC3Receipt],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, []),
      mode: 'white-box',
    })
    assert.equal(vulnCard.hardenedTwins.find((t) => t.twinId === 'PG-D3')?.falsePositive, false)
    assert.equal(vulnCard.hardenedTwinDecoyFps, 0)
    assert.equal(vulnCard.unmatchedFalsePositives, 1)
    assert.equal(vulnCard.precision, 0)

    // (b) Receipt-only submission in vulnerable mode still penalizes unmatchedFalsePositives (never precision=1)
    const receiptOnlyCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [],
      compositeReceipts: [pgC3Receipt],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, []),
      mode: 'white-box',
    })
    assert.equal(receiptOnlyCard.hardenedTwinDecoyFps, 0)
    assert.equal(receiptOnlyCard.unmatchedFalsePositives, 1)
    assert.equal(receiptOnlyCard.precision, 0)

    // (c) Decoy-hop-only finding stopping at GET /exports/:id/url MUST STILL fail PG-D3
    const decoyCard = gradeRun({
      groundTruth: vuln.groundTruth,
      findings: [{
        id: 'pg-d3-decoy-only',
        vulnClass: 'cross_tenant_export',
        endpoints: [
          { method: 'POST', path: `${p}/orgs/org_b/exports` },
          { method: 'GET', path: `${p}/exports/exp_1/url` },
        ],
        status: 'confirmed',
      }],
      compositeReceipts: [],
      oracleEvents: [],
      oracleExport: makeOracleExport(vuln, []),
      mode: 'white-box',
    })
    assert.equal(decoyCard.hardenedTwins.find((t) => t.twinId === 'PG-D3')?.falsePositive, true)
    assert.ok(decoyCard.hardenedTwinDecoyFps >= 1)

    // (d) Hardened mode & PG-D3 twin mode MUST STILL fail hardenedTwinDecoyFps >= 1
    const hardenedCard = gradeRun({
      groundTruth: hardened.groundTruth,
      findings: [pgC3Finding],
      compositeReceipts: [pgC3Receipt],
      oracleEvents: [],
      oracleExport: hardened.export(),
      mode: 'white-box',
    })
    assert.ok(hardenedCard.hardenedTwinDecoyFps >= 1)
    assert.equal(hardenedCard.precision, 0)

    const twinCard = gradeRun({
      groundTruth: twinD3.groundTruth,
      findings: [pgC3Finding],
      compositeReceipts: [pgC3Receipt],
      oracleEvents: [],
      oracleExport: twinD3.export(),
      mode: 'white-box',
    })
    assert.equal(twinCard.hardenedTwins.find((t) => t.twinId === 'PG-D3')?.falsePositive, true)
    assert.ok(twinCard.hardenedTwinDecoyFps >= 1)
    assert.equal(twinCard.precision, 0)
  } finally {
    await vuln.stop()
    await hardened.stop()
    await twinD3.stop()
  }
})
