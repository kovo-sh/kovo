/**
 * R3-12 — Executable Oracle × Benign-Archetype FP Matrix (`< 5s` in `worker-gate.sh`).
 *
 * Executable statement of what MUST NEVER confirm in the verification kernel:
 *   1. Drives EVERY registered rule in `SINGLE_HOP_ORACLE_RULES` (all 10 rules, including all 8
 *      `impact` sub-oracles + `signed_url_mint`) through BOTH `evaluateTerminalOracle` and
 *      `verifyReceipt` against all 8 parametric synthetic benign target archetypes.
 *   2. Drives EVERY registered family in `REGISTERED_V8_ORACLE_FAMILIES` (all 6 V8 families across
 *      every sub-mode/equation) through `evaluateTerminalOracle` against all 8 benign archetypes.
 *   3. Runs a lateral same-CWE label sweep across sibling `vulnClass` labels on each archetype's
 *      strongest-claim `HostFactLog` to ensure relabeling never flips a dismissal into a confirm.
 *   4. Replays all 12 Tier-0 traps from `benchmarks/realism-suite/traps/fp-archetypes.json` through
 *      `evaluateTerminalOracle` (closing direct assessor-only bypasses).
 *   5. Enforces 0 non-exempt confirmations, prints the full Oracle × Archetype coverage grid,
 *      pins a non-decreasing coverage floor, and enforces `< 5s` execution budget.
 *
 * Defensive QA framing: zero-network synthetic host-observed exchanges only.
 */
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import {
  buildProofReceipt,
  defaultHostMintedOracle,
  signOobCallback,
  verifyReceipt,
  type ProofReceipt,
} from '../src/server/proof-receipt.ts'
import {
  REGISTERED_V8_ORACLE_FAMILIES,
  SINGLE_HOP_ORACLE_RULES,
  evaluateTerminalOracle,
  type SingleHopOracleRule,
  type TerminalOracleResult,
} from '../src/server/terminal-oracle-registry.ts'
import type { V8OracleFamily } from '../src/server/v8-oracle-families.ts'
import {
  BENIGN_ARCHETYPES,
  BENIGN_ARCHETYPE_IDS,
  MATRIX_ACTORS,
  MATRIX_ORIGIN,
  MATRIX_SIGNING_KEY,
  type BenignArchetypeDefinition,
  type BenignArchetypeId,
  type BenignTargetSession,
} from './fixtures/benign-archetypes/index.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FP_ARCHETYPES_PATH = join(REPO_ROOT, 'benchmarks', 'realism-suite', 'traps', 'fp-archetypes.json')
const MAX_MATRIX_DURATION_MS = 5_000

export interface MatrixExemption {
  readonly oracle: string
  readonly archetype: BenignArchetypeId
  readonly ticket: string
  readonly reason: string
  readonly expires: string
}

/**
 * Ticketed, expiring exemption list for structurally-inapplicable `(oracle, archetype)` cells.
 * MUST remain empty unless a cell is genuinely structurally inapplicable and backed by a ticket +
 * ISO expiry date (`YYYY-MM-DD`). Unexpected confirmations are REAL FPs and must NEVER be exempted.
 */
export const MATRIX_EXEMPTIONS: ReadonlyArray<MatrixExemption> = []

interface CellRunOutcome {
  readonly oracle: string
  readonly archetype: BenignArchetypeId
  readonly subChecks: number
  readonly confirmed: boolean
  readonly confirmedDetails: readonly string[]
  readonly sampleReason: string
}

const POLICY = { signingKey: MATRIX_SIGNING_KEY } as const

function withQueryParam(basePath: string, param: string, value: string): string {
  const url = new URL(basePath, MATRIX_ORIGIN)
  url.searchParams.set(param, value)
  return `${url.pathname}${url.search}`
}

function evalSingleHopBoth(
  session: BenignTargetSession,
  receipt: ProofReceipt,
): { terminal: TerminalOracleResult; direct: ReturnType<typeof verifyReceipt> } {
  const terminal = evaluateTerminalOracle(
    session.log,
    { kind: 'single_hop', receipt },
    POLICY,
  )
  const transcript = session.log.toHostSignedTranscript({ signingKey: MATRIX_SIGNING_KEY })
  const direct = verifyReceipt(receipt, { ...transcript, oobSigningKey: MATRIX_SIGNING_KEY }, {
    signingKey: MATRIX_SIGNING_KEY,
    hostMintedOracle: defaultHostMintedOracle,
  })
  return { terminal, direct }
}

// ============================================================================
// 1. Hand-written strongest-claim builders for every SINGLE_HOP_ORACLE_RULE
// ============================================================================

type SingleHopBuilder = (arch: BenignArchetypeDefinition) => CellRunOutcome

function runImpactSubClasses(arch: BenignArchetypeDefinition): CellRunOutcome {
  const confirmedDetails: string[] = []
  let subChecks = 0
  let lastReason = ''

  const checkReceipt = (label: string, session: BenignTargetSession, receipt: ProofReceipt) => {
    subChecks += 1
    const { terminal, direct } = evalSingleHopBoth(session, receipt)
    lastReason = terminal.reason
    if (terminal.confirmed) confirmedDetails.push(`${label} [evaluateTerminalOracle]: ${terminal.reason}`)
    if (direct.confirmed) confirmedDetails.push(`${label} [verifyReceipt]: ${direct.reason}`)
  }

  // 1a. authorization (bola / idor / cross_tenant_read): owner control + foreign probe + anon probe
  {
    const s = arch.createSession()
    s.send('ctl_owner', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.ownerA, arm: 'control' })
    s.send('ctl_anon', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.anon, arm: 'control' })
    s.send('prb_foreign', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.ownerB, arm: 'probe' })
    s.send('prb_anon', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.anon, arm: 'probe' })
    checkReceipt(
      'impact:authorization',
      s,
      buildProofReceipt({
        vulnClass: 'bola',
        target: { origin: s.origin, method: 'GET', pathAndQuery: s.readEntityRoute },
        exchangeIds: ['ctl_owner', 'ctl_anon', 'prb_foreign', 'prb_anon'],
        claimedDelta: 'Cross-tenant or anonymous object read claim on benign archetype.',
      }),
    )
  }

  // 1b. bfla: higher-role control vs lower-role probe on admin/primary route
  {
    const s = arch.createSession()
    const adminRoute = arch.id === 'honest_rbac' ? '/api/admin/audit' : s.primaryRoute
    s.send('ctl_admin', { method: 'GET', pathAndQuery: adminRoute, actor: MATRIX_ACTORS.ownerA, arm: 'control' })
    s.send('prb_viewer', { method: 'GET', pathAndQuery: adminRoute, actor: MATRIX_ACTORS.viewerA, arm: 'probe' })
    checkReceipt(
      'impact:bfla',
      s,
      buildProofReceipt({
        vulnClass: 'bfla',
        target: { origin: s.origin, method: 'GET', pathAndQuery: adminRoute },
        exchangeIds: ['ctl_admin', 'prb_viewer'],
        claimedDelta: 'Lower role access claim on benign archetype.',
      }),
    )
  }

  // 1c. mass_assignment: before-read, PATCH protected field, after-read
  {
    const s = arch.createSession()
    s.send('before', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    s.send('patch_probe', {
      method: 'PATCH',
      pathAndQuery: s.readEntityRoute,
      actor: MATRIX_ACTORS.memberA,
      arm: 'probe',
      jsonBody: { role: 'admin', is_admin: true, tenant_id: 'tenant-b' },
    })
    s.send('after', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    checkReceipt(
      'impact:mass_assignment',
      s,
      buildProofReceipt({
        vulnClass: 'mass_assignment',
        target: { origin: s.origin, method: 'PATCH', pathAndQuery: s.readEntityRoute },
        exchangeIds: ['before', 'patch_probe', 'after'],
        claimedDelta: 'Protected field mass assignment claim on benign archetype.',
      }),
    )
  }

  // 1d. csrf: cross-origin state-change attempt with SameSite=Lax cookie or bearer
  {
    const s = arch.createSession()
    s.send('csrf_before', { method: 'GET', pathAndQuery: s.primaryRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    s.send('csrf_probe', {
      method: 'POST',
      pathAndQuery: s.mutateRoute,
      actor: MATRIX_ACTORS.memberA,
      arm: 'probe',
      headers: { origin: 'https://cross-origin.example.invalid' },
      jsonBody: { note: 'cross-site-test', amount: 10 },
    })
    s.send('csrf_after', { method: 'GET', pathAndQuery: s.primaryRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    checkReceipt(
      'impact:csrf',
      s,
      buildProofReceipt({
        vulnClass: 'csrf',
        target: { origin: s.origin, method: 'POST', pathAndQuery: s.mutateRoute },
        exchangeIds: ['csrf_before', 'csrf_probe', 'csrf_after'],
        claimedDelta: 'Cross-site request forgery claim on benign archetype.',
      }),
    )
  }

  // 1e. business_logic: honest repeated accumulation (deposit twice / add-to-cart twice) + idempotent PUT
  {
    const s = arch.createSession()
    const depositPath = s.mutateRoute
    s.send('bl_before', { method: 'GET', pathAndQuery: s.balanceRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    s.send('bl_act1', { method: 'POST', pathAndQuery: depositPath, actor: MATRIX_ACTORS.memberA, arm: 'probe', jsonBody: { amount: 25, qty: 1 } })
    s.send('bl_mid', { method: 'GET', pathAndQuery: s.balanceRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    s.send('bl_act2', { method: 'POST', pathAndQuery: depositPath, actor: MATRIX_ACTORS.memberA, arm: 'probe', jsonBody: { amount: 25, qty: 1 } })
    s.send('bl_after', { method: 'GET', pathAndQuery: s.balanceRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    checkReceipt(
      'impact:business_logic',
      s,
      buildProofReceipt({
        vulnClass: 'business_logic',
        target: { origin: s.origin, method: 'POST', pathAndQuery: depositPath },
        exchangeIds: ['bl_before', 'bl_act1', 'bl_mid', 'bl_act2', 'bl_after'],
        claimedDelta: 'Repeated state accumulation claim on benign archetype.',
      }),
    )
  }

  // 1f. markup (xss_reflected): benign sanitized/tag-stripped echo with angle-bracket/zero-width input
  {
    const s = arch.createSession()
    const ctlPath = withQueryParam(s.primaryRoute, s.queryParam, s.baseParamValue)
    const prbPath = withQueryParam(s.primaryRoute, s.queryParam, '<b>qa_benign_\u200Bmarker</b>')
    s.send('xss_ctl', { method: 'GET', pathAndQuery: ctlPath, actor: MATRIX_ACTORS.viewerA, arm: 'control' })
    s.send('xss_prb', { method: 'GET', pathAndQuery: prbPath, actor: MATRIX_ACTORS.viewerA, arm: 'probe' })
    checkReceipt(
      'impact:markup',
      s,
      buildProofReceipt({
        vulnClass: 'xss_reflected',
        target: { origin: s.origin, method: 'GET', pathAndQuery: prbPath, param: s.queryParam },
        exchangeIds: ['xss_ctl', 'xss_prb'],
        claimedDelta: 'Reflected markup claim on benign archetype.',
      }),
    )
  }

  // 1g. disclosure: normal read response with no secret material
  {
    const s = arch.createSession()
    s.send('disc_ctl', { method: 'GET', pathAndQuery: s.primaryRoute, actor: MATRIX_ACTORS.ownerA, arm: 'control' })
    s.send('disc_prb', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.anon, arm: 'probe' })
    checkReceipt(
      'impact:disclosure',
      s,
      buildProofReceipt({
        vulnClass: 'disclosure',
        target: { origin: s.origin, method: 'GET', pathAndQuery: s.readEntityRoute },
        exchangeIds: ['disc_ctl', 'disc_prb'],
        claimedDelta: 'Sensitive data disclosure claim on benign archetype.',
      }),
    )
  }

  // 1h. injection (sqli_error + host-minted expression challenge): benign validator/sanitizer/coercion response
  {
    const s = arch.createSession()
    const exprChallenge = defaultHostMintedOracle.mintExpressionChallenge('ssti', '*', { runId: `matrix_${arch.id}_expr` })
    const ctlPath = withQueryParam(s.primaryRoute, s.queryParam, s.baseParamValue)
    const prbPath = withQueryParam(s.primaryRoute, s.queryParam, `${s.baseParamValue}_${exprChallenge.expressionSyntax}_overlong_probe`)
    s.send('inj_ctl', { method: 'GET', pathAndQuery: ctlPath, actor: MATRIX_ACTORS.viewerA, arm: 'control' })
    s.send('inj_prb', {
      method: 'GET',
      pathAndQuery: prbPath,
      actor: MATRIX_ACTORS.viewerA,
      arm: 'probe',
      hostExpressionChallenge: exprChallenge,
    })
    checkReceipt(
      'impact:injection',
      s,
      buildProofReceipt({
        vulnClass: 'sqli_error',
        target: { origin: s.origin, method: 'GET', pathAndQuery: prbPath, param: s.queryParam },
        exchangeIds: ['inj_ctl', 'inj_prb'],
        claimedDelta: 'Injection fingerprint or expression evaluation claim on benign archetype.',
      }),
    )
  }

  // 1i. signed_url_mint (routes through rule:'impact' -> verifySignedUrlMintReceipt): two-folder benign presign
  {
    const s = arch.createSession()
    const presignPath = arch.id === 'benign_share_link' ? '/api/files/presign' : s.mutateRoute
    s.send('su_ctl', {
      method: 'POST',
      pathAndQuery: presignPath,
      actor: MATRIX_ACTORS.ownerA,
      arm: 'control',
      jsonBody: { folder: 'folder_a', file: 'report.pdf' },
    })
    s.send('su_prb', {
      method: 'POST',
      pathAndQuery: presignPath,
      actor: MATRIX_ACTORS.ownerA,
      arm: 'probe',
      jsonBody: { folder: 'folder_b', file: 'summary.pdf' },
    })
    checkReceipt(
      'impact:signed_url_mint',
      s,
      buildProofReceipt({
        vulnClass: 'signed_url_mint',
        target: { origin: s.origin, method: 'POST', pathAndQuery: presignPath },
        exchangeIds: ['su_ctl', 'su_prb'],
        claimedDelta: 'Signed URL minting scope escape claim on benign archetype.',
      }),
    )
  }

  return {
    oracle: 'impact',
    archetype: arch.id,
    subChecks,
    confirmed: confirmedDetails.length > 0,
    confirmedDetails,
    sampleReason: lastReason,
  }
}

function runBooleanRule(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  const baseVal = s.baseParamValue
  const exchangeIds: string[] = []
  for (const round of [1, 2]) {
    const pair = defaultHostMintedOracle.mintBooleanPair(baseVal, {
      param: s.queryParam,
      style: /^\d+$/.test(baseVal) ? 'numeric' : 'single_quote',
      binding: { runId: `matrix_${arch.id}_lateral` },
    })
    const bStamp = defaultHostMintedOracle.stampBooleanPairArm(pair, 'baseline')
    const tStamp = defaultHostMintedOracle.stampBooleanPairArm(pair, 'true')
    const fStamp = defaultHostMintedOracle.stampBooleanPairArm(pair, 'false')
    const bId = `bool_b${round}`
    const tId = `bool_t${round}`
    const fId = `bool_f${round}`
    s.send(bId, {
      method: 'GET',
      pathAndQuery: withQueryParam(s.primaryRoute, s.queryParam, bStamp.mintedValue),
      actor: MATRIX_ACTORS.viewerA,
      arm: 'control',
      evidenceRole: 'benign_baseline',
      hostBooleanPair: bStamp,
    })
    s.send(tId, {
      method: 'GET',
      pathAndQuery: withQueryParam(s.primaryRoute, s.queryParam, tStamp.mintedValue),
      actor: MATRIX_ACTORS.viewerA,
      arm: 'control',
      hostBooleanPair: tStamp,
    })
    s.send(fId, {
      method: 'GET',
      pathAndQuery: withQueryParam(s.primaryRoute, s.queryParam, fStamp.mintedValue),
      actor: MATRIX_ACTORS.viewerA,
      arm: 'probe',
      hostBooleanPair: fStamp,
    })
    exchangeIds.push(bId, tId, fId)
  }
  const receipt = buildProofReceipt({
    vulnClass: 'boolean_differential',
    target: { origin: s.origin, method: 'GET', pathAndQuery: s.primaryRoute, param: s.queryParam },
    exchangeIds,
    claimedDelta: 'Host-minted two-round boolean differential claim on benign archetype.',
  })
  const { terminal, direct } = evalSingleHopBoth(s, receipt)
  const confirmedDetails: string[] = []
  if (terminal.confirmed) confirmedDetails.push(`boolean [evaluateTerminalOracle]: ${terminal.reason}`)
  if (direct.confirmed) confirmedDetails.push(`boolean [verifyReceipt]: ${direct.reason}`)
  return { oracle: 'boolean', archetype: arch.id, subChecks: 1, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: terminal.reason }
}

function runStatusDifferentialRule(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  const baseVal = s.baseParamValue
  const exchangeIds: string[] = []
  for (const round of [1, 2]) {
    const pair = defaultHostMintedOracle.mintBooleanPair(baseVal, {
      param: s.queryParam,
      style: /^\d+$/.test(baseVal) ? 'numeric' : 'single_quote',
      binding: { runId: `matrix_${arch.id}_lateral` },
    })
    const bStamp = defaultHostMintedOracle.stampBooleanPairArm(pair, 'baseline')
    const tStamp = defaultHostMintedOracle.stampBooleanPairArm(pair, 'true')
    const fStamp = defaultHostMintedOracle.stampBooleanPairArm(pair, 'false')
    const bId = `sd_b${round}`
    const tId = `sd_t${round}`
    const fId = `sd_f${round}`
    s.send(bId, {
      method: 'GET',
      pathAndQuery: withQueryParam(s.primaryRoute, s.queryParam, bStamp.mintedValue),
      actor: MATRIX_ACTORS.viewerA,
      arm: 'control',
      evidenceRole: 'benign_baseline',
      hostBooleanPair: bStamp,
    })
    s.send(tId, {
      method: 'GET',
      pathAndQuery: withQueryParam(s.primaryRoute, s.queryParam, tStamp.mintedValue),
      actor: MATRIX_ACTORS.viewerA,
      arm: 'probe',
      hostBooleanPair: tStamp,
    })
    s.send(fId, {
      method: 'GET',
      pathAndQuery: withQueryParam(s.primaryRoute, s.queryParam, fStamp.mintedValue),
      actor: MATRIX_ACTORS.viewerA,
      arm: 'probe',
      hostBooleanPair: fStamp,
    })
    exchangeIds.push(bId, tId, fId)
  }
  const receipt = buildProofReceipt({
    vulnClass: 'sqli_status',
    target: { origin: s.origin, method: 'GET', pathAndQuery: s.primaryRoute, param: s.queryParam },
    exchangeIds,
    claimedDelta: 'Host-minted status-differential triangle claim on benign archetype.',
  })
  const { terminal, direct } = evalSingleHopBoth(s, receipt)
  const confirmedDetails: string[] = []
  if (terminal.confirmed) confirmedDetails.push(`status_differential [evaluateTerminalOracle]: ${terminal.reason}`)
  if (direct.confirmed) confirmedDetails.push(`status_differential [verifyReceipt]: ${direct.reason}`)
  return { oracle: 'status_differential', archetype: arch.id, subChecks: 1, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: terminal.reason }
}

function runTimingRule(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  const challenge = defaultHostMintedOracle.mintTimingChallenge('timing', 1500, undefined, { runId: `matrix_${arch.id}_timing` })
  const exchangeIds: string[] = []
  // 5 interleaved control + 5 probe arms with realistic benign constant latency (~12-16ms)
  for (let i = 1; i <= 5; i += 1) {
    const ctlId = `tm_ctl_${i}`
    const prbId = `tm_prb_${i}`
    s.send(ctlId, {
      method: 'GET',
      pathAndQuery: withQueryParam(s.primaryRoute, s.queryParam, s.baseParamValue),
      actor: MATRIX_ACTORS.viewerA,
      arm: 'control',
      hostTimingChallenge: challenge,
      durationMs: 12 + (i % 3),
    })
    s.send(prbId, {
      method: 'GET',
      pathAndQuery: withQueryParam(s.primaryRoute, s.queryParam, `${s.baseParamValue}_timing_probe_${i}`),
      actor: MATRIX_ACTORS.viewerA,
      arm: 'probe',
      hostTimingChallenge: challenge,
      durationMs: 13 + (i % 4),
    })
    exchangeIds.push(ctlId, prbId)
  }
  const receipt = buildProofReceipt({
    vulnClass: 'timing',
    target: { origin: s.origin, method: 'GET', pathAndQuery: s.primaryRoute, param: s.queryParam },
    exchangeIds,
    claimedDelta: 'Interleaved timing differential claim on benign archetype.',
  })
  const { terminal, direct } = evalSingleHopBoth(s, receipt)
  const confirmedDetails: string[] = []
  if (terminal.confirmed) confirmedDetails.push(`timing [evaluateTerminalOracle]: ${terminal.reason}`)
  if (direct.confirmed) confirmedDetails.push(`timing [verifyReceipt]: ${direct.reason}`)
  return { oracle: 'timing', archetype: arch.id, subChecks: 1, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: terminal.reason }
}

function runOobRule(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  const token = `kovo_qa_oob_benign_${arch.id}`
  const prbPath = withQueryParam(s.primaryRoute, s.queryParam, `https://${token}.oob.example.invalid/ping`)
  const prb = s.send('oob_prb', {
    method: 'GET',
    pathAndQuery: prbPath,
    actor: MATRIX_ACTORS.viewerA,
    arm: 'probe',
  })
  // Benign target never fires an OOB callback -> delivered: false
  const baseEvt = {
    id: 'oob_ev_1',
    canaryId: `canary_${arch.id}`,
    token,
    targetOrigin: s.origin,
    delivered: false,
    stage: 'immediate' as const,
    receivedAtMs: prb.timestampMs + 50,
    injectedAtMs: prb.timestampMs,
  }
  s.log.recordOobEvent({ ...baseEvt, callbackSignature: signOobCallback(baseEvt, MATRIX_SIGNING_KEY) })
  const receipt = buildProofReceipt({
    vulnClass: 'ssrf',
    target: { origin: s.origin, method: 'GET', pathAndQuery: prbPath },
    exchangeIds: ['oob_prb'],
    oobEventIds: ['oob_ev_1'],
    claimedDelta: 'Out-of-band callback claim on benign archetype with undelivered canary.',
  })
  const { terminal, direct } = evalSingleHopBoth(s, receipt)
  const confirmedDetails: string[] = []
  if (terminal.confirmed) confirmedDetails.push(`oob [evaluateTerminalOracle]: ${terminal.reason}`)
  if (direct.confirmed) confirmedDetails.push(`oob [verifyReceipt]: ${direct.reason}`)
  return { oracle: 'oob', archetype: arch.id, subChecks: 1, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: terminal.reason }
}

function runBrowserRule(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  const prbPath = withQueryParam(s.primaryRoute, s.queryParam, '<b>qa_browser_marker</b>')
  s.send('br_prb', { method: 'GET', pathAndQuery: prbPath, actor: MATRIX_ACTORS.viewerA, arm: 'probe' })
  // Benign target executes zero DOM sinks
  s.log.recordBrowserTrace({ id: 'br_trace_1', origin: s.origin, sinks: [] })
  const receipt = buildProofReceipt({
    vulnClass: 'browser_dom_xss',
    target: { origin: s.origin, method: 'GET', pathAndQuery: prbPath },
    exchangeIds: ['br_prb'],
    browserTraceIds: ['br_trace_1'],
    claimedDelta: 'Browser DOM sink claim on benign archetype with zero executed sinks.',
  })
  const { terminal, direct } = evalSingleHopBoth(s, receipt)
  const confirmedDetails: string[] = []
  if (terminal.confirmed) confirmedDetails.push(`browser [evaluateTerminalOracle]: ${terminal.reason}`)
  if (direct.confirmed) confirmedDetails.push(`browser [verifyReceipt]: ${direct.reason}`)
  return { oracle: 'browser', archetype: arch.id, subChecks: 1, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: terminal.reason }
}

function runRedirectRule(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  const canary = defaultHostMintedOracle.mintRedirectCanary('canary.kovo.invalid', { runId: `matrix_${arch.id}_redir` })
  const route = arch.id === 'cache_hit_and_pagination' ? '/auth/sso' : s.primaryRoute
  const ctlPath = withQueryParam(route, 'next', '/dashboard')
  const prbPath = withQueryParam(route, 'next', `https://${canary.host}/landing`)
  s.send('redir_ctl', {
    method: 'GET',
    pathAndQuery: ctlPath,
    actor: MATRIX_ACTORS.viewerA,
    arm: 'control',
    hostRedirectCanaryHost: canary.host,
  })
  s.send('redir_prb', {
    method: 'GET',
    pathAndQuery: prbPath,
    actor: MATRIX_ACTORS.viewerA,
    arm: 'probe',
    hostRedirectCanaryHost: canary.host,
  })
  const receipt = buildProofReceipt({
    vulnClass: 'open_redirect',
    target: { origin: s.origin, method: 'GET', pathAndQuery: route, param: 'next' },
    exchangeIds: ['redir_ctl', 'redir_prb'],
    claimedDelta: 'Open redirect claim with host-minted destination canary on benign archetype.',
  })
  const { terminal, direct } = evalSingleHopBoth(s, receipt)
  const confirmedDetails: string[] = []
  if (terminal.confirmed) confirmedDetails.push(`redirect [evaluateTerminalOracle]: ${terminal.reason}`)
  if (direct.confirmed) confirmedDetails.push(`redirect [verifyReceipt]: ${direct.reason}`)
  return { oracle: 'redirect', archetype: arch.id, subChecks: 1, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: terminal.reason }
}

function runConservedBalanceRule(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  const debitRoute = arch.id === 'honest_accumulator' ? '/api/wallets/acct_a/debit' : s.mutateRoute
  s.send('cb_pre', {
    method: 'GET',
    pathAndQuery: s.balanceRoute,
    actor: MATRIX_ACTORS.memberA,
    arm: 'control',
    evidenceRole: 'baseline_read',
    timestampMs: 1_700_000_001_000,
  })
  // Two genuinely overlapping burst debits against an honest target that conserves balance (second returns 409)
  s.send('cb_b1', {
    method: 'POST',
    pathAndQuery: debitRoute,
    actor: MATRIX_ACTORS.memberA,
    arm: 'probe',
    evidenceRole: 'burst_1',
    raceBatchId: 'batch_benign_1',
    jsonBody: { amount: 60 },
    timestampMs: 1_700_000_002_000,
    durationMs: 40,
  })
  s.send('cb_b2', {
    method: 'POST',
    pathAndQuery: debitRoute,
    actor: MATRIX_ACTORS.memberA,
    arm: 'probe',
    evidenceRole: 'burst_2',
    raceBatchId: 'batch_benign_1',
    jsonBody: { amount: 60 },
    timestampMs: 1_700_000_002_010,
    durationMs: 40,
  })
  s.send('cb_post', {
    method: 'GET',
    pathAndQuery: s.balanceRoute,
    actor: MATRIX_ACTORS.memberA,
    arm: 'control',
    evidenceRole: 'post_read',
    timestampMs: 1_700_000_003_000,
  })
  s.send('cb_serial', {
    method: 'POST',
    pathAndQuery: debitRoute,
    actor: MATRIX_ACTORS.memberA,
    arm: 'control',
    evidenceRole: 'serial_control',
    jsonBody: { amount: 60 },
    timestampMs: 1_700_000_004_000,
  })
  const receipt = buildProofReceipt({
    vulnClass: 'race_double_spend',
    target: { origin: s.origin, method: 'POST', pathAndQuery: debitRoute },
    exchangeIds: ['cb_pre', 'cb_b1', 'cb_b2', 'cb_post', 'cb_serial'],
    claimedDelta: 'Conserved balance double-spend claim on benign archetype.',
  })
  const { terminal, direct } = evalSingleHopBoth(s, receipt)
  const confirmedDetails: string[] = []
  if (terminal.confirmed) confirmedDetails.push(`conserved_balance [evaluateTerminalOracle]: ${terminal.reason}`)
  if (direct.confirmed) confirmedDetails.push(`conserved_balance [verifyReceipt]: ${direct.reason}`)
  return { oracle: 'conserved_balance', archetype: arch.id, subChecks: 1, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: terminal.reason }
}

function runAuthBypassRule(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  // Strongest adversarial FP shape (R4-H-7): invalid bearer control (401 on public_endpoint),
  // bare anonymous ablation, plus spoofed header probe.
  s.send('ab_ctl_invalid', {
    method: 'GET',
    pathAndQuery: s.readEntityRoute,
    actor: MATRIX_ACTORS.anon,
    arm: 'control',
    headers: { authorization: 'Bearer invalid.jwt.token' },
  })
  s.send('ab_ctl_bare', {
    method: 'GET',
    pathAndQuery: s.readEntityRoute,
    actor: MATRIX_ACTORS.anon,
    arm: 'control',
  })
  s.send('ab_prb_hdr', {
    method: 'GET',
    pathAndQuery: s.readEntityRoute,
    actor: MATRIX_ACTORS.anon,
    arm: 'probe',
    headers: { 'x-forwarded-user': 'admin', 'x-original-url': s.readEntityRoute },
  })
  const receipt = buildProofReceipt({
    vulnClass: 'auth_bypass',
    target: { origin: s.origin, method: 'GET', pathAndQuery: s.readEntityRoute },
    exchangeIds: ['ab_ctl_invalid', 'ab_ctl_bare', 'ab_prb_hdr'],
    claimedDelta: 'Authentication bypass claim on benign archetype.',
  })
  const { terminal, direct } = evalSingleHopBoth(s, receipt)
  const confirmedDetails: string[] = []
  if (terminal.confirmed) confirmedDetails.push(`auth_bypass [evaluateTerminalOracle]: ${terminal.reason}`)
  if (direct.confirmed) confirmedDetails.push(`auth_bypass [verifyReceipt]: ${direct.reason}`)
  return { oracle: 'auth_bypass', archetype: arch.id, subChecks: 1, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: terminal.reason }
}

function runWebhookRule(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  const payload = { event: 'invoice.paid', id: 'evt_benign_1', amount: 100 }
  const secret = 'qa_inline_test_key'
  const canonical = JSON.stringify(payload)
  const validSig = createHmac('sha256', secret).update(canonical, 'utf8').digest('hex')
  const badSig = '0'.repeat(64)
  s.send('wh_ctl', {
    method: 'POST',
    pathAndQuery: s.mutateRoute,
    actor: MATRIX_ACTORS.anon,
    arm: 'control',
    jsonBody: { ...payload, signing_key: secret, signature: badSig },
  })
  s.send('wh_prb', {
    method: 'POST',
    pathAndQuery: s.mutateRoute,
    actor: MATRIX_ACTORS.anon,
    arm: 'probe',
    jsonBody: { ...payload, signing_key: secret, signature: validSig },
  })
  const receipt = buildProofReceipt({
    vulnClass: 'webhook_forgery',
    target: { origin: s.origin, method: 'POST', pathAndQuery: s.mutateRoute },
    exchangeIds: ['wh_ctl', 'wh_prb'],
    claimedDelta: 'Inline-key webhook forgery claim on benign archetype.',
  })
  const { terminal, direct } = evalSingleHopBoth(s, receipt)
  const confirmedDetails: string[] = []
  if (terminal.confirmed) confirmedDetails.push(`webhook [evaluateTerminalOracle]: ${terminal.reason}`)
  if (direct.confirmed) confirmedDetails.push(`webhook [verifyReceipt]: ${direct.reason}`)
  return { oracle: 'webhook', archetype: arch.id, subChecks: 1, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: terminal.reason }
}

const SINGLE_HOP_BUILDERS: Readonly<Record<SingleHopOracleRule, SingleHopBuilder>> = {
  impact: runImpactSubClasses,
  oob: runOobRule,
  timing: runTimingRule,
  boolean: runBooleanRule,
  status_differential: runStatusDifferentialRule,
  browser: runBrowserRule,
  redirect: runRedirectRule,
  conserved_balance: runConservedBalanceRule,
  auth_bypass: runAuthBypassRule,
  webhook: runWebhookRule,
}

// ============================================================================
// 2. Hand-written strongest-claim builders for every REGISTERED_V8_ORACLE_FAMILY
// ============================================================================

type V8FamilyBuilder = (arch: BenignArchetypeDefinition) => CellRunOutcome

function runDualTenantAbacFamily(arch: BenignArchetypeDefinition): CellRunOutcome {
  const confirmedDetails: string[] = []
  let subChecks = 0
  let lastReason = ''

  // Mode A: cross_org_transfer
  {
    const s = arch.createSession()
    const xferRoute = arch.id === 'honest_rbac' ? '/api/docs/doc_b1/transfer' : s.mutateRoute
    s.send('dt_ctl', { method: 'GET', pathAndQuery: s.foreignEntityRoute, actor: MATRIX_ACTORS.dualOrgActor, arm: 'control' })
    s.send('dt_xfer', { method: 'POST', pathAndQuery: xferRoute, actor: MATRIX_ACTORS.dualOrgActor, arm: 'probe', jsonBody: { entityId: 'doc_b1', destTenantId: 'tenant-a' } })
    s.send('dt_rb', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.dualOrgActor, arm: 'control' })
    const res = evaluateTerminalOracle(
      s.log,
      {
        kind: 'v8_family',
        family: 'dual_tenant_abac',
        rawInput: {
          mode: 'cross_org_transfer',
          entityId: 'doc_b1',
          sourceControlExchangeId: 'dt_ctl',
          transferExchangeId: 'dt_xfer',
          postTransferReadback: 'dt_rb',
        },
      },
      POLICY,
    )
    subChecks += 1
    lastReason = res.reason
    if (res.confirmed) confirmedDetails.push(`dual_tenant_abac:cross_org_transfer: ${res.reason}`)
  }

  // Mode B: dual_org_cache_bleed
  {
    const s = arch.createSession()
    s.send('cb_base', { method: 'GET', pathAndQuery: s.foreignEntityRoute, actor: MATRIX_ACTORS.dualOrgActor, arm: 'control' })
    s.send('cb_prime', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.dualOrgActor, arm: 'probe' })
    s.send('cb_bled', { method: 'GET', pathAndQuery: s.foreignEntityRoute, actor: MATRIX_ACTORS.dualOrgActor, arm: 'probe' })
    const res = evaluateTerminalOracle(
      s.log,
      {
        kind: 'v8_family',
        family: 'dual_tenant_abac',
        rawInput: {
          mode: 'dual_org_cache_bleed',
          baselineControlExchangeId: 'cb_base',
          primeAction: 'cb_prime',
          bledAccess: 'cb_bled',
        },
      },
      POLICY,
    )
    subChecks += 1
    lastReason = res.reason
    if (res.confirmed) confirmedDetails.push(`dual_tenant_abac:dual_org_cache_bleed: ${res.reason}`)
  }

  // Mode C: batch_partial_authz
  {
    const s = arch.createSession()
    const batchRoute = arch.id === 'honest_rbac' ? '/api/docs/batch' : s.mutateRoute
    s.send('bp_ctl', { method: 'GET', pathAndQuery: s.foreignEntityRoute, actor: MATRIX_ACTORS.ownerA, arm: 'control' })
    s.send('bp_batch', { method: 'POST', pathAndQuery: batchRoute, actor: MATRIX_ACTORS.ownerA, arm: 'probe', jsonBody: { ids: ['doc_a1', 'doc_b1'] } })
    const res = evaluateTerminalOracle(
      s.log,
      {
        kind: 'v8_family',
        family: 'dual_tenant_abac',
        rawInput: {
          mode: 'batch_partial_authz',
          ownRecordId: 'doc_a1',
          foreignRecordId: 'doc_b1',
          foreignTenantId: 'tenant-b',
          requestedIds: ['doc_a1', 'doc_b1'],
          singleForeignControlExchangeId: 'bp_ctl',
          batchRequest: 'bp_batch',
        },
      },
      POLICY,
    )
    subChecks += 1
    lastReason = res.reason
    if (res.confirmed) confirmedDetails.push(`dual_tenant_abac:batch_partial_authz: ${res.reason}`)
  }

  return { oracle: 'v8:dual_tenant_abac', archetype: arch.id, subChecks, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: lastReason }
}

function runTemporalRevocationFamily(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  const revokeRoute = arch.id === 'honest_rbac' ? '/api/sessions/revoke' : s.mutateRoute
  s.send('tr_base', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.ownerA, arm: 'control' })
  s.send('tr_rev', { method: 'POST', pathAndQuery: revokeRoute, actor: MATRIX_ACTORS.ownerA, arm: 'probe', jsonBody: { revoke: true } })
  s.send('tr_pri', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.ownerA, arm: 'control' })
  s.send('tr_sec', { method: 'GET', pathAndQuery: s.secondaryRoute, actor: MATRIX_ACTORS.ownerA, arm: 'probe' })
  const res = evaluateTerminalOracle(
    s.log,
    {
      kind: 'v8_family',
      family: 'temporal_revocation',
      rawInput: {
        credentialKind: 'session',
        actorId: MATRIX_ACTORS.ownerA.handle,
        preRevocationBaseline: 'tr_base',
        revocationEvent: 'tr_rev',
        primaryDeniedCheck: 'tr_pri',
        secondarySuccess: 'tr_sec',
      },
    },
    POLICY,
  )
  return {
    oracle: 'v8:temporal_revocation',
    archetype: arch.id,
    subChecks: 1,
    confirmed: res.confirmed,
    confirmedDetails: res.confirmed ? [`temporal_revocation: ${res.reason}`] : [],
    sampleReason: res.reason,
  }
}

function runEconomicConservationFamily(arch: BenignArchetypeDefinition): CellRunOutcome {
  const confirmedDetails: string[] = []
  let subChecks = 0
  let lastReason = ''

  // Equation 1: over_refund
  {
    const s = arch.createSession()
    const ordRoute = arch.id === 'honest_accumulator' ? '/api/orders/ord_100' : s.balanceRoute
    const refRoute = arch.id === 'honest_accumulator' ? '/api/orders/ord_100/refund' : s.mutateRoute
    s.send('ec_base', { method: 'GET', pathAndQuery: ordRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    s.send('ec_a1', { method: 'POST', pathAndQuery: refRoute, actor: MATRIX_ACTORS.memberA, arm: 'probe', jsonBody: { amount: 2500 } })
    s.send('ec_a2', { method: 'POST', pathAndQuery: refRoute, actor: MATRIX_ACTORS.memberA, arm: 'probe', jsonBody: { amount: 2500 } })
    s.send('ec_a3', { method: 'POST', pathAndQuery: refRoute, actor: MATRIX_ACTORS.memberA, arm: 'probe', jsonBody: { amount: 2500 } })
    s.send('ec_fin', { method: 'GET', pathAndQuery: ordRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    const res = evaluateTerminalOracle(
      s.log,
      {
        kind: 'v8_family',
        family: 'economic_conservation',
        rawInput: {
          equation: 'over_refund',
          baselineExchangeId: 'ec_base',
          actionExchangeIds: ['ec_a1', 'ec_a2', 'ec_a3'],
          finalExchangeId: 'ec_fin',
        },
      },
      POLICY,
    )
    subChecks += 1
    lastReason = res.reason
    if (res.confirmed) confirmedDetails.push(`economic_conservation:over_refund: ${res.reason}`)
  }

  // Equation 2: balance_minting (honest deposits match balance increase)
  {
    const s = arch.createSession()
    const depRoute = s.mutateRoute
    s.send('bm_base', { method: 'GET', pathAndQuery: s.balanceRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    s.send('bm_a1', { method: 'POST', pathAndQuery: depRoute, actor: MATRIX_ACTORS.memberA, arm: 'probe', jsonBody: { amount: 25 } })
    s.send('bm_a2', { method: 'POST', pathAndQuery: depRoute, actor: MATRIX_ACTORS.memberA, arm: 'probe', jsonBody: { amount: 25 } })
    s.send('bm_fin', { method: 'GET', pathAndQuery: s.balanceRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    const res = evaluateTerminalOracle(
      s.log,
      {
        kind: 'v8_family',
        family: 'economic_conservation',
        rawInput: {
          equation: 'balance_minting',
          baselineExchangeId: 'bm_base',
          actionExchangeIds: ['bm_a1', 'bm_a2'],
          finalExchangeId: 'bm_fin',
        },
      },
      POLICY,
    )
    subChecks += 1
    lastReason = res.reason
    if (res.confirmed) confirmedDetails.push(`economic_conservation:balance_minting: ${res.reason}`)
  }

  // Equation 3: underpaid_fulfillment
  {
    const s = arch.createSession()
    const ordRoute = arch.id === 'honest_accumulator' ? '/api/orders/ord_100' : s.balanceRoute
    s.send('uf_base', { method: 'GET', pathAndQuery: ordRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    s.send('uf_act', { method: 'POST', pathAndQuery: s.mutateRoute, actor: MATRIX_ACTORS.memberA, arm: 'probe', jsonBody: { amount: 5000 } })
    s.send('uf_fin', { method: 'GET', pathAndQuery: ordRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    const res = evaluateTerminalOracle(
      s.log,
      {
        kind: 'v8_family',
        family: 'economic_conservation',
        rawInput: {
          equation: 'underpaid_fulfillment',
          baselineExchangeId: 'uf_base',
          actionExchangeIds: ['uf_act'],
          finalExchangeId: 'uf_fin',
        },
      },
      POLICY,
    )
    subChecks += 1
    lastReason = res.reason
    if (res.confirmed) confirmedDetails.push(`economic_conservation:underpaid_fulfillment: ${res.reason}`)
  }

  // Equation 4: ineligible_discount
  {
    const s = arch.createSession()
    s.send('id_base', { method: 'GET', pathAndQuery: s.balanceRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    s.send('id_act', { method: 'POST', pathAndQuery: s.mutateRoute, actor: MATRIX_ACTORS.memberA, arm: 'probe', jsonBody: { couponCode: 'WELCOME10' } })
    s.send('id_fin', { method: 'GET', pathAndQuery: s.balanceRoute, actor: MATRIX_ACTORS.memberA, arm: 'control' })
    const res = evaluateTerminalOracle(
      s.log,
      {
        kind: 'v8_family',
        family: 'economic_conservation',
        rawInput: {
          equation: 'ineligible_discount',
          baselineExchangeId: 'id_base',
          actionExchangeIds: ['id_act'],
          finalExchangeId: 'id_fin',
        },
      },
      POLICY,
    )
    subChecks += 1
    lastReason = res.reason
    if (res.confirmed) confirmedDetails.push(`economic_conservation:ineligible_discount: ${res.reason}`)
  }

  return { oracle: 'v8:economic_conservation', archetype: arch.id, subChecks, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: lastReason }
}

function runCryptographicScopeReplayFamily(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  if (arch.id === 'benign_share_link') {
    // Strongest benign test: mint a real signed URL for folder_a/report.pdf, verify tampered sig returns 403,
    // and replay exact same signed URL as same actor (same resource -> MUST dismiss as same_principal_not_replay!)
    const issued = s.send('csr_issue', {
      method: 'POST',
      pathAndQuery: '/api/files/presign',
      actor: MATRIX_ACTORS.ownerA,
      arm: 'control',
      jsonBody: { folder: 'folder_a', file: 'report.pdf' },
    })
    const signedUrl = String((issued.json as { signedUrl?: string } | undefined)?.signedUrl ?? '/api/files/download?tenant=tenant-a&folder=folder_a&file=report.pdf&sig=none')
    const parsed = new URL(signedUrl, s.origin)
    const validPathAndQuery = `${parsed.pathname}${parsed.search}`
    const tampered = new URL(signedUrl, s.origin)
    tampered.searchParams.set('sig', '0'.repeat(32))
    s.send('csr_tampered', {
      method: 'GET',
      pathAndQuery: `${tampered.pathname}${tampered.search}`,
      actor: MATRIX_ACTORS.ownerA,
      arm: 'control',
    })
    s.send('csr_replay', {
      method: 'GET',
      pathAndQuery: validPathAndQuery,
      actor: MATRIX_ACTORS.ownerA,
      arm: 'probe',
    })
  } else {
    s.send('csr_tampered', {
      method: 'GET',
      pathAndQuery: withQueryParam(s.readEntityRoute, 'sig', '0'.repeat(32)),
      actor: MATRIX_ACTORS.ownerA,
      arm: 'control',
    })
    s.send('csr_issue', {
      method: 'GET',
      pathAndQuery: withQueryParam(s.readEntityRoute, 'sig', 'a'.repeat(32)),
      actor: MATRIX_ACTORS.ownerA,
      arm: 'control',
    })
    s.send('csr_replay', {
      method: 'GET',
      pathAndQuery: withQueryParam(s.readEntityRoute, 'sig', 'a'.repeat(32)),
      actor: MATRIX_ACTORS.ownerB,
      arm: 'probe',
    })
  }
  const res = evaluateTerminalOracle(
    s.log,
    {
      kind: 'v8_family',
      family: 'cryptographic_scope_replay',
      rawInput: {
        tamperedControlExchangeId: 'csr_tampered',
        sourceIssuanceExchangeId: 'csr_issue',
        replayedExchangeId: 'csr_replay',
      },
    },
    POLICY,
  )
  return {
    oracle: 'v8:cryptographic_scope_replay',
    archetype: arch.id,
    subChecks: 1,
    confirmed: res.confirmed,
    confirmedDetails: res.confirmed ? [`cryptographic_scope_replay: ${res.reason}`] : [],
    sampleReason: res.reason,
  }
}

function runParserCacheDifferentialFamily(arch: BenignArchetypeDefinition): CellRunOutcome {
  const confirmedDetails: string[] = []
  let subChecks = 0
  let lastReason = ''

  // Mode 1: parser_differential (path_normalization + duplicate_json_key)
  {
    const s = arch.createSession()
    s.send('pd_ctl', { method: 'GET', pathAndQuery: s.foreignEntityRoute, actor: MATRIX_ACTORS.viewerA, arm: 'control' })
    s.send('pd_prb', { method: 'GET', pathAndQuery: `${s.foreignEntityRoute}${s.foreignEntityRoute.includes('?') ? '&' : '?'}sort=desc`, actor: MATRIX_ACTORS.viewerA, arm: 'probe' })
    const res = evaluateTerminalOracle(
      s.log,
      {
        kind: 'v8_family',
        family: 'parser_cache_differential',
        rawInput: {
          mode: 'parser_differential',
          differentialKind: 'path_normalization',
          differentialFeature: 'pagination_query_variant',
          impactKind: 'read',
          cleanControl: 'pd_ctl',
          differentialProbe: 'pd_prb',
        },
      },
      POLICY,
    )
    subChecks += 1
    lastReason = res.reason
    if (res.confirmed) confirmedDetails.push(`parser_cache_differential:parser_differential: ${res.reason}`)
  }

  // Mode 2: cache_primed (public CDN X-Cache: HIT served identically to cleanControl, prime, and attackerProbe)
  {
    const s = arch.createSession()
    s.send('cp_ctl', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.anon, arm: 'control' })
    s.send('cp_prime', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.ownerA, arm: 'control' })
    s.send('cp_probe', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.ownerB, arm: 'probe' })
    const res = evaluateTerminalOracle(
      s.log,
      {
        kind: 'v8_family',
        family: 'parser_cache_differential',
        rawInput: {
          mode: 'cache_primed',
          cacheKey: s.readEntityRoute,
          cleanControl: 'cp_ctl',
          victimPrimeExchangeId: 'cp_prime',
          attackerProbe: 'cp_probe',
        },
      },
      POLICY,
    )
    subChecks += 1
    lastReason = res.reason
    if (res.confirmed) confirmedDetails.push(`parser_cache_differential:cache_primed: ${res.reason}`)
  }

  return { oracle: 'v8:parser_cache_differential', archetype: arch.id, subChecks, confirmed: confirmedDetails.length > 0, confirmedDetails, sampleReason: lastReason }
}

function runCrossSurfacePivotFamily(arch: BenignArchetypeDefinition): CellRunOutcome {
  const s = arch.createSession()
  s.send('csp_ctl', { method: 'GET', pathAndQuery: s.foreignEntityRoute, actor: MATRIX_ACTORS.viewerA, arm: 'control' })
  s.send('csp_h0', { method: 'POST', pathAndQuery: s.mutateRoute, actor: MATRIX_ACTORS.viewerA, arm: 'probe', jsonBody: { text: 'benign-note' } })
  s.send('csp_h1', { method: 'GET', pathAndQuery: s.secondaryRoute, actor: MATRIX_ACTORS.viewerA, arm: 'probe' })
  const res = evaluateTerminalOracle(
    s.log,
    {
      kind: 'v8_family',
      family: 'cross_surface_pivot',
      rawInput: {
        preChainControlExchangeId: 'csp_ctl',
        controlKind: 'authz_denied',
        hops: [
          { surface: 'http', role: 'trigger_write', exchangeId: 'csp_h0' },
          { surface: 'browser', role: 'terminal_impact', exchangeId: 'csp_h1', bindingKind: 'value_binding' },
        ],
        terminalImpact: { kind: 'privileged_read' },
      },
    },
    POLICY,
  )
  return {
    oracle: 'v8:cross_surface_pivot',
    archetype: arch.id,
    subChecks: 1,
    confirmed: res.confirmed,
    confirmedDetails: res.confirmed ? [`cross_surface_pivot: ${res.reason}`] : [],
    sampleReason: res.reason,
  }
}

const V8_FAMILY_BUILDERS: Readonly<Record<V8OracleFamily, V8FamilyBuilder>> = {
  dual_tenant_abac: runDualTenantAbacFamily,
  temporal_revocation: runTemporalRevocationFamily,
  economic_conservation: runEconomicConservationFamily,
  cryptographic_scope_replay: runCryptographicScopeReplayFamily,
  parser_cache_differential: runParserCacheDifferentialFamily,
  cross_surface_pivot: runCrossSurfacePivotFamily,
}

// ============================================================================
// 3. Lateral same-CWE label sweep groups (sibling vulnClass labels per CWE)
// ============================================================================

const LATERAL_CWE_SWEEP_GROUPS: ReadonlyArray<{
  readonly cwe: string
  readonly siblingLabels: readonly string[]
}> = [
  { cwe: 'CWE-89', siblingLabels: ['sqli', 'boolean_differential', 'sqli_status', 'sqli_error', 'timing', 'injection'] },
  { cwe: 'CWE-639', siblingLabels: ['bola', 'idor', 'cross_tenant_read', 'cross_tenant_write', 'authorization', 'signed_url_mint'] },
  { cwe: 'CWE-862', siblingLabels: ['bfla', 'privilege_escalation', 'authorization', 'auth_bypass'] },
  { cwe: 'CWE-79', siblingLabels: ['xss', 'xss_reflected', 'xss_stored', 'markup', 'browser_dom_xss'] },
  { cwe: 'CWE-840', siblingLabels: ['business_logic', 'invariant_violation', 'race_double_spend', 'conserved_balance'] },
  { cwe: 'CWE-287', siblingLabels: ['auth_bypass', 'broken_auth', 'jwt_forgery', 'token_forgery'] },
  { cwe: 'CWE-918', siblingLabels: ['ssrf', 'oob', 'open_redirect', 'disclosure'] },
]

function printCoverageGrid(
  oracles: readonly string[],
  archetypes: readonly BenignArchetypeId[],
  grid: ReadonlyMap<string, CellRunOutcome>,
  exemptSet: ReadonlySet<string>,
  elapsedMs: number,
  lateralChecks: number,
): void {
  const colW = 10
  const rowW = 28
  const shortArch = (id: BenignArchetypeId): string => id.slice(0, colW - 1)
  const header = `${'Oracle'.padEnd(rowW)} | ${archetypes.map(a => shortArch(a).padEnd(colW)).join(' | ')}`
  const sep = '-'.repeat(header.length)
  const lines = [
    '',
    '=== R3-12 Executable Oracle x Benign-Archetype FP Matrix ===',
    header,
    sep,
  ]
  for (const oracle of oracles) {
    const cells = archetypes.map(arch => {
      const key = `${oracle}::${arch}`
      const cell = grid.get(key)
      if (!cell) return 'MISS'.padEnd(colW)
      if (cell.confirmed) return (exemptSet.has(key) ? 'EXEMPT' : 'FAIL-FP').padEnd(colW)
      return `PASS(${cell.subChecks})`.padEnd(colW)
    })
    lines.push(`${oracle.padEnd(rowW)} | ${cells.join(' | ')}`)
  }
  lines.push(sep)
  lines.push(
    `[R3-12 matrix] oracles=${oracles.length} (${SINGLE_HOP_ORACLE_RULES.length} single-hop + ${REGISTERED_V8_ORACLE_FAMILIES.length} v8), ` +
    `archetypes=${archetypes.length}, coreCells=${grid.size}, lateralChecks=${lateralChecks}, ` +
    `exemptions=${exemptSet.size}, runtimeMs=${elapsedMs}`,
  )
  console.log(lines.join('\n'))
}

// ============================================================================
// Tests
// ============================================================================

test('R3-12 matrix exemptions metadata: every exemption carries ticket, reason, and non-expired ISO date', () => {
  const today = new Date().toISOString().slice(0, 10)
  for (const ex of MATRIX_EXEMPTIONS) {
    assert.ok(ex.ticket.trim().length > 0, `exemption (${ex.oracle}, ${ex.archetype}) missing ticket`)
    assert.ok(ex.reason.trim().length > 0, `exemption (${ex.oracle}, ${ex.archetype}) missing reason`)
    assert.match(ex.expires, /^\d{4}-\d{2}-\d{2}$/, `exemption (${ex.oracle}, ${ex.archetype}) invalid ISO date`)
    assert.ok(ex.expires >= today, `exemption (${ex.oracle}, ${ex.archetype}) expired on ${ex.expires}`)
  }
})

test('R3-12 executable matrix: all SINGLE_HOP_ORACLE_RULES and REGISTERED_V8_ORACLE_FAMILIES dismiss across all benign archetypes (<5s, 0 non-exempt confirms)', () => {
  const t0 = performance.now()

  // Registry completeness: every registered rule and V8 family MUST have a builder in the matrix.
  for (const rule of SINGLE_HOP_ORACLE_RULES) {
    assert.equal(typeof SINGLE_HOP_BUILDERS[rule], 'function', `Missing matrix builder for single-hop rule "${rule}"`)
  }
  for (const family of REGISTERED_V8_ORACLE_FAMILIES) {
    assert.equal(typeof V8_FAMILY_BUILDERS[family], 'function', `Missing matrix builder for V8 oracle family "${family}"`)
  }

  const exemptSet = new Set(MATRIX_EXEMPTIONS.map(e => `${e.oracle}::${e.archetype}`))
  const allOracleNames = [
    ...SINGLE_HOP_ORACLE_RULES,
    ...REGISTERED_V8_ORACLE_FAMILIES.map(f => `v8:${f}`),
  ]
  const grid = new Map<string, CellRunOutcome>()
  const unexpectedFPs: string[] = []

  // 1. Core Oracle × Benign-Archetype Grid
  for (const arch of BENIGN_ARCHETYPES) {
    for (const rule of SINGLE_HOP_ORACLE_RULES) {
      const outcome = SINGLE_HOP_BUILDERS[rule](arch)
      const key = `${outcome.oracle}::${arch.id}`
      grid.set(key, outcome)
      if (outcome.confirmed && !exemptSet.has(key)) {
        unexpectedFPs.push(`${key} -> ${outcome.confirmedDetails.join(' | ')}`)
      }
    }
    for (const family of REGISTERED_V8_ORACLE_FAMILIES) {
      const outcome = V8_FAMILY_BUILDERS[family](arch)
      const key = `${outcome.oracle}::${arch.id}`
      grid.set(key, outcome)
      if (outcome.confirmed && !exemptSet.has(key)) {
        unexpectedFPs.push(`${key} -> ${outcome.confirmedDetails.join(' | ')}`)
      }
    }
  }

  // 2. Lateral same-CWE label sweep across every benign archetype
  let lateralChecks = 0
  for (const arch of BENIGN_ARCHETYPES) {
    const s = arch.createSession()
    const baseVal = s.baseParamValue
    const pair = defaultHostMintedOracle.mintBooleanPair(baseVal, {
      param: s.queryParam,
      style: /^\d+$/.test(baseVal) ? 'numeric' : 'single_quote',
      binding: { runId: `matrix_${arch.id}_lateral` },
    })
    const bStamp = defaultHostMintedOracle.stampBooleanPairArm(pair, 'baseline')
    const tStamp = defaultHostMintedOracle.stampBooleanPairArm(pair, 'true')
    const fStamp = defaultHostMintedOracle.stampBooleanPairArm(pair, 'false')
    s.send('lat_owner', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.ownerA, arm: 'control' })
    s.send('lat_anon', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.anon, arm: 'control' })
    s.send('lat_foreign', { method: 'GET', pathAndQuery: s.readEntityRoute, actor: MATRIX_ACTORS.ownerB, arm: 'probe' })
    s.send('lat_b', {
      method: 'GET',
      pathAndQuery: withQueryParam(s.primaryRoute, s.queryParam, bStamp.mintedValue),
      actor: MATRIX_ACTORS.viewerA,
      arm: 'control',
      evidenceRole: 'benign_baseline',
      hostBooleanPair: bStamp,
    })
    s.send('lat_t', {
      method: 'GET',
      pathAndQuery: withQueryParam(s.primaryRoute, s.queryParam, tStamp.mintedValue),
      actor: MATRIX_ACTORS.viewerA,
      arm: 'control',
      hostBooleanPair: tStamp,
    })
    s.send('lat_f', {
      method: 'GET',
      pathAndQuery: withQueryParam(s.primaryRoute, s.queryParam, fStamp.mintedValue),
      actor: MATRIX_ACTORS.viewerA,
      arm: 'probe',
      hostBooleanPair: fStamp,
    })
    const allIds = ['lat_owner', 'lat_anon', 'lat_foreign', 'lat_b', 'lat_t', 'lat_f']

    for (const group of LATERAL_CWE_SWEEP_GROUPS) {
      for (const sibling of group.siblingLabels) {
        lateralChecks += 1
        const receipt = buildProofReceipt({
          vulnClass: sibling,
          target: { origin: s.origin, method: 'GET', pathAndQuery: s.primaryRoute, param: s.queryParam },
          exchangeIds: allIds,
          claimedDelta: `Lateral ${group.cwe} sibling label (${sibling}) sweep on ${arch.id}.`,
        })
        const { terminal, direct } = evalSingleHopBoth(s, receipt)
        if (terminal.confirmed) {
          unexpectedFPs.push(`lateral:${group.cwe}:${sibling}::${arch.id} [evaluateTerminalOracle] -> ${terminal.reason}`)
        }
        if (direct.confirmed) {
          unexpectedFPs.push(`lateral:${group.cwe}:${sibling}::${arch.id} [verifyReceipt] -> ${direct.reason}`)
        }
      }
    }
  }

  const elapsedMs = Math.round(performance.now() - t0)
  printCoverageGrid(allOracleNames, BENIGN_ARCHETYPE_IDS, grid, exemptSet, elapsedMs, lateralChecks)

  // Non-decreasing coverage floor: 16 registered oracles (10 single-hop + 6 v8) × 8 benign archetypes = 128 cells
  const expectedCoreCells = allOracleNames.length * BENIGN_ARCHETYPES.length
  assert.equal(grid.size, expectedCoreCells, `Expected all ${expectedCoreCells} core matrix cells exercised, got ${grid.size}`)
  assert.ok(expectedCoreCells >= 128, `Grid coverage regressed below 128 core cells (got ${expectedCoreCells})`)
  assert.ok(lateralChecks >= 240, `Expected >= 240 lateral same-CWE label checks, got ${lateralChecks}`)
  assert.equal(
    unexpectedFPs.length,
    0,
    `REAL FP(s) detected in kernel archetype matrix (${unexpectedFPs.length}):\n  - ${unexpectedFPs.join('\n  - ')}`,
  )
  assert.ok(
    elapsedMs < MAX_MATRIX_DURATION_MS,
    `Kernel archetype matrix exceeded <5s budget: took ${elapsedMs}ms`,
  )
})

test('R3-12 Tier-0 fp-archetypes.json parity: all 12 past FP archetypes dismiss through evaluateTerminalOracle (no direct assessor bypass)', () => {
  interface RawTrapFile {
    archetypes: Array<{
      id: string
      title: string
      assessor: string
      expectedDismissal: string
      input: {
        impactClass: string
        requiredRole?: string
        targetOrigin?: string
        steps: ImpactStep[]
      }
    }>
  }
  const raw = JSON.parse(readFileSync(FP_ARCHETYPES_PATH, 'utf8')) as RawTrapFile
  assert.ok(raw.archetypes.length >= 12, `Expected >= 12 Tier-0 fp-archetypes, got ${raw.archetypes.length}`)

  const assessorToVulnClass: Record<string, string[]> = {
    authorization: ['bola', 'idor', 'cross_tenant_read', 'authorization'],
    bfla: ['bfla', 'privilege_escalation'],
    business_logic: ['business_logic', 'invariant_violation'],
    mass_assignment: ['mass_assignment'],
    csrf: ['csrf'],
    mfa: ['auth_bypass', 'broken_auth'],
  }

  for (const trap of raw.archetypes) {
    const origin = trap.input.targetOrigin ?? MATRIX_ORIGIN
    const log = new HostFactLog({ signingKey: MATRIX_SIGNING_KEY })
    const exchangeIds: string[] = []
    trap.input.steps.forEach((step, idx) => {
      const exId = `${trap.id}_${step.id || idx}`
      exchangeIds.push(exId)
      const body = step.body !== undefined
        ? step.body
        : step.json !== undefined
          ? JSON.stringify(step.json)
          : ''
      const rawReq = step.requestJson !== undefined
        ? (typeof step.requestJson === 'string' ? step.requestJson : JSON.stringify(step.requestJson))
        : (step.requestBody ?? null)
      log.recordExchange({
        exchangeId: exId,
        method: step.method,
        origin,
        pathAndQuery: step.pathAndQuery ?? step.route ?? '/',
        status: step.status,
        requestHeaders: step.requestHeaders ?? null,
        rawRequestBody: rawReq,
        responseHeaders: step.responseHeaders ?? null,
        rawResponseBody: body,
        actor: step.actor.handle,
        actorRole: step.actor.role,
        actorTenant: step.actor.tenant,
        ambientAuth: step.actor.auth,
        sameSite: step.actor.sameSite,
        arm: step.arm,
        timestampMs: 1_700_000_000_000 + (idx + 1) * 100,
        cleanSession: true,
      })
    })

    const targetStep = trap.input.steps.find(st => st.arm === 'probe') ?? trap.input.steps[0]!
    const labels = assessorToVulnClass[trap.assessor] ?? [trap.input.impactClass]
    for (const vulnClass of labels) {
      const receipt = buildProofReceipt({
        vulnClass,
        target: {
          origin,
          method: targetStep.method,
          pathAndQuery: targetStep.pathAndQuery ?? targetStep.route ?? '/',
        },
        exchangeIds,
        claimedDelta: `Tier-0 fp-archetype replay (${trap.id}) via evaluateTerminalOracle.`,
      })
      const res = evaluateTerminalOracle(log, { kind: 'single_hop', receipt }, POLICY)
      assert.equal(
        res.confirmed,
        false,
        `Tier-0 fp-archetype "${trap.id}" MUST dismiss under evaluateTerminalOracle (vulnClass=${vulnClass}), got confirmed=true: ${res.reason}`,
      )
    }
  }
})
