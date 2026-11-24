import { createHash, randomUUID } from 'node:crypto'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { join, sep } from 'node:path'
import { and, eq } from 'drizzle-orm'
import type { AccessPolicySnapshot } from '../access-policy.ts'
import {
  findingSeverities,
  httpMethods,
  maxInlineVerifyRetries,
  responseCheckIds,
  type AssessmentCheckId,
  type Candidate,
  type CheckCoverage,
  type CodeLocation,
  type Finding,
  type InlineVerifyFeedback,
  type OwaspCategory,
  type ResponseCheckId,
  type VerificationTier,
} from '../domain.ts'
import { declarativeReplaySpecSchema, replaySpecOrigins, type AgentScriptProofEnvelope, type DeclarativeReplaySpec } from '../replay-spec.ts'
import { accessPolicyReviews } from './access-policy-checks.ts'
import { BrokerDenied, type BrokerExchangeResult, type Grant, type RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { checkCoverage, readComparisons, verificationCommand, type EvidenceReview } from './evidence-checks.ts'
import type { ExecBoardManager } from './exec-board.ts'
import {
  createExchangeRecorder,
  recordReportedFindingCoverage,
  type ExecActiveJob,
  type ExecCapture,
  type ExecReviewInput,
  type ExecTier3ApprovalInput,
} from './exec-exchange.ts'
import { alignClaimClass } from './oracle-invariants.ts'
import { buildOobReceipt, verifyReceipt, type ReceiptOobEvent } from './proof-receipt.ts'
import { BudgetExceededError } from './provider.ts'
import { redact, redactJsonValue, type NamedSecret } from './redact.ts'
import {
  buildInlineVerifyFeedback,
  persistedAgentScriptOf,
  retestReplaySpec,
  runAgentScriptProof,
  verifyReplaySpec,
  verifyReplaySpecInline,
  type AgentScriptProofResult,
} from './replay-verifier.ts'
import { responseReview } from './response-checks.ts'
import { canaries, findings, type ReplayProofReceiptRow } from './schema.ts'
import type { ScopedBrowser } from './scoped-browser.ts'
import {
  assessmentAssignments,
  InvariantError,
  type AgentScriptProofRecord,
  type Assignment,
  type BoardMessageRow,
  type ReplaySpecRow,
  type Run,
  type Store,
} from './store.ts'
import { LinuxWorkerBackend, type WorkerBackend } from './worker-backend.ts'

type Active = ExecActiveJob
type Capture = ExecCapture
type ReviewInput = ExecReviewInput

export interface ExecVerifyHost {
  storage: Store
  broker: RequestBroker
  browser: ScopedBrowser
  canaryBroker: CanaryBroker
  backend: WorkerBackend
  approvedOriginsSet: (run: Run) => Set<string>
  permitted: (run: Run, origin: string) => boolean
  check: (job: Active) => Run
  buildGrant: (job: Active, run: Run, permittedAtAdmission: ReadonlySet<string>) => { grant: Grant; secrets: NamedSecret[]; currentSecrets: () => NamedSecret[] }
  projectReposMount: (projectId: string) => { reposDir?: string; mountedRepos: string[] }
  isCanaryDnsConfigured: () => boolean
  isCanaryListenerConfigured: () => boolean
  markEndpointCoverage: (run: Run, origin: string, method: string, pathAndQuery: string, probeClass: string) => void
  markReplaySpecCoverage: (run: Run, spec: DeclarativeReplaySpec, probeClass: string) => void
  waitForTier3Approval: (job: Active, input: ExecTier3ApprovalInput, signal: AbortSignal) => Promise<{ approved: boolean; deniedReason?: string }>
  postVerificationVerdict: (run: Run, opts: Parameters<ExecBoardManager["postVerificationVerdict"]>[1]) => BoardMessageRow | null
  cancelSiblingTrialsOnConfirmation: (run: Run, winningStepId: string | null, findingId?: string) => void
  scheduleVariantSweepForFinding: (run: Run, findingRow: typeof findings.$inferSelect) => void
  completeWorker: (worker: Assignment, run: Run, outcome: string, evidenceIds: string[], checks?: CheckCoverage[], secrets?: readonly NamedSecret[]) => void
  recordSpecVerification: (runId: string, specId: string, feedback: InlineVerifyFeedback, summary: string) => void
  resolveInlineVerdictRow: (runId: string, findingRow: typeof findings.$inferSelect | undefined) => typeof findings.$inferSelect | undefined
}



/**
 * A finding's declared class can disagree with what the proof actually showed (the common case:
 * a protected-field overpost reported as BOLA). The verifier records the verified `evidenceClass`;
 * align the persisted finding with it so the report and the benchmark see the class the evidence
 * supports. Authorization evidence never relabels a claim.
 */
function alignFindingForEvidence(
  finding: Finding,
  replay: { evidencePayload?: Record<string, unknown> | null },
): Finding {
  const payload = replay.evidencePayload
  const evidenceClass = payload && typeof payload.evidenceClass === 'string' ? payload.evidenceClass : null
  const label = alignClaimClass({ cwe: finding.cwe, category: finding.category }, evidenceClass)
  if (!label) return finding
  return { ...finding, cwe: label.cwe, category: label.category }
}


function buildTier3VerifyGateReq(spec: Extract<DeclarativeReplaySpec, { kind: 'rce_proof' | 'upload_probe' }>, label: string) {
  if (spec.kind === 'rce_proof') {
    return {
      origin: spec.probeStep.request.origin,
      method: spec.probeStep.request.method,
      pathAndQuery: spec.probeStep.request.pathAndQuery,
      personaHandle: spec.probeStep.request.persona ?? null,
      rationale: `[rce_proof:${spec.proofMode}] ${label} for "${spec.title}"`,
      requestPreview: JSON.stringify({ proofMode: spec.proofMode, controlStep: spec.controlStep, probeStep: spec.probeStep }, null, 2),
      bodyPreview: spec.probeStep.request.textBody
        ?? (spec.probeStep.request.jsonBody !== undefined ? JSON.stringify(spec.probeStep.request.jsonBody) : undefined),
      hasMultipart: false,
      isRceProof: true,
    }
  }
  return {
    origin: spec.uploadStep.origin,
    method: spec.uploadStep.method,
    pathAndQuery: spec.uploadStep.pathAndQuery,
    personaHandle: spec.uploadStep.persona ?? null,
    rationale: `[upload_probe] ${label} for "${spec.title}"`,
    requestPreview: JSON.stringify({
      filename: spec.uploadStep.filename,
      contentType: spec.uploadStep.contentType,
      uploadStep: spec.uploadStep.pathAndQuery,
      fetchStep: spec.fetchStep.request.pathAndQuery,
    }, null, 2),
    bodyPreview: spec.uploadStep.contentTemplate,
    hasMultipart: true,
    isRceProof: false,
  }
}


type ReplayVerificationResult = Awaited<ReturnType<typeof verifyReplaySpec>>


function deriveReplayOutcomeStatus(spec: DeclarativeReplaySpec, replay: ReplayVerificationResult) {
  const staticSpec = spec.kind === 'static_ast_proof' ? spec : null
  const isStaticAst = staticSpec !== null
  const rawVerdict = replay.verdict as Finding['status']
  const finalStatus: Finding['status'] = isStaticAst
    ? (rawVerdict === 'confirmed' || rawVerdict === 'static_verified' ? 'static_verified' : rawVerdict)
    : rawVerdict
  const verificationTier: VerificationTier | undefined = finalStatus === 'static_verified'
    ? 'static_verified'
    : finalStatus === 'confirmed'
      ? 'runtime_confirmed'
      : undefined
  return { staticSpec, isStaticAst, finalStatus, verificationTier }
}


function buildReplayFindingPatch(
  spec: DeclarativeReplaySpec,
  replay: ReplayVerificationResult,
  existingFinding: Finding,
  finalStatus: Finding['status'],
  verificationTier: VerificationTier | undefined,
  verificationVerb: string,
  secretsList: readonly NamedSecret[],
): { patch: Partial<Finding>; cleanObserved: string } {
  const staticSpec = spec.kind === 'static_ast_proof' ? spec : null
  const staticCodeLocations: CodeLocation[] | undefined = staticSpec
    ? [{
        repo: staticSpec.repo,
        file: staticSpec.file,
        startLine: staticSpec.startLine,
        endLine: staticSpec.endLine,
        label: staticSpec.sourceToSinkTrace?.slice(0, 180),
      }]
    : existingFinding.codeLocations
  const cleanReason = redact(replay.outcome.reason || replay.outcome.observed || existingFinding.reason, secretsList)
  const cleanObserved = redact(replay.outcome.observed, secretsList)
  const patch: Partial<Finding> = {
    status: finalStatus,
    verificationTier,
    reason: cleanReason,
    confidence: (finalStatus === 'confirmed' || finalStatus === 'static_verified')
      ? 'high'
      : finalStatus === 'dismissed'
        ? 'medium'
        : 'low',
    verification: `${staticSpec ? 'Deterministic offline static_ast_proof' : `Zero-LLM ${spec.kind} ${verificationVerb}`} verdict: ${finalStatus} (controlPassed=${replay.outcome.controlPassed}, observed: ${cleanObserved}).`,
    ...(staticSpec ? { runtimeProofGap: staticSpec.runtimeProofGap } : {}),
    ...(staticCodeLocations?.length ? { codeLocations: staticCodeLocations } : {}),
  }
  return { patch, cleanObserved }
}


/**
 * Confirmation attribution for an agent script proof: reporting vocabulary for a class whose
 * confirmation came from the script's receipt. Only labels/CWE/copy — never a verification input.
 */
export function agentProofAttribution(vulnClass: string): {
  label: string
  cwe: string
  category: OwaspCategory
  impact: string
  remediation: string
} {
  const key = vulnClass.toLowerCase()
  if (/^(?:bol[ai]|idor|cross_tenant|authorization|access_control|broken-access-control)$/.test(key)) {
    return {
      label: 'broken object-level authorization',
      cwe: 'CWE-639',
      category: 'broken-access-control',
      impact: 'An authenticated actor read or changed a resource owned by another tenant or user.',
      remediation: 'Enforce an object-level authorization check on every request that names a resource id.',
    }
  }
  if (/^(?:bfla|privilege_escalation)$/.test(key)) {
    return {
      label: 'broken function-level authorization',
      cwe: 'CWE-285',
      category: 'broken-access-control',
      impact: 'A lower-privileged actor invoked a privileged function that should be role-gated.',
      remediation: 'Gate the function server-side on the caller role, not on client-side visibility.',
    }
  }
  if (/^mass_assignment$/.test(key)) {
    return {
      label: 'mass assignment',
      cwe: 'CWE-915',
      category: 'broken-access-control',
      impact: 'An over-posted field persisted a value the actor was not allowed to set.',
      remediation: 'Allowlist assignable fields and bind them explicitly server-side.',
    }
  }
  if (/^csrf$/.test(key)) {
    return {
      label: 'cross-site request forgery',
      cwe: 'CWE-352',
      category: 'auth-identity',
      impact: 'A cross-site request performed a state change as the victim without a valid intent token.',
      remediation: 'Require a per-session anti-CSRF token (or SameSite=Lax cookies) on state-changing routes.',
    }
  }
  if (/^(?:sqli|sql_boolean|blind_sqli|injection|nosqli|ssti|template_injection|command_injection|cmdi|path_traversal|directory_traversal)$/.test(key)) {
    return {
      label: 'injection',
      cwe: 'CWE-74',
      category: 'injection-input',
      impact: 'Injected input changed the query/command structure or timing of the server-side operation.',
      remediation: 'Use parameterized queries and context-appropriate encoding; never concatenate input into a command.',
    }
  }
  if (/^(?:xss|xss_stored|xss_reflected|markup|html_injection)$/.test(key)) {
    return {
      label: 'cross-site scripting',
      cwe: 'CWE-79',
      category: 'injection-input',
      impact: 'Actor-supplied markup was stored or reflected and executed in another user’s browser context.',
      remediation: 'Encode output for the HTML context and apply a restrictive Content-Security-Policy.',
    }
  }
  if (/^(?:ssrf|blind_ssrf|xxe|blind_xxe|oob|webhook_forgery)$/.test(key)) {
    return {
      label: 'server-side request forgery',
      cwe: 'CWE-918',
      category: 'ssrf-redirects',
      impact: 'The target fetched an attacker-supplied destination or out-of-band canary.',
      remediation: 'Allowlist outbound destinations and disable external entity resolution for XML parsers.',
    }
  }
  if (/^(?:race|race_double_spend)$/.test(key)) {
    return {
      label: 'race condition',
      cwe: 'CWE-362',
      category: 'business-logic-race',
      impact: 'A synchronized burst of the same request produced divergent outcomes (over-spend or duplicate effect).',
      remediation: 'Serialize the state transition (unique constraint, lock, or idempotency key).',
    }
  }
  if (/^(?:business_logic|invariant_violation|workflow_skip)$/.test(key)) {
    return {
      label: 'business-logic invariant violation',
      cwe: 'CWE-840',
      category: 'business-logic-race',
      impact: 'A workflow invariant was violated by replaying or skipping a legitimate step.',
      remediation: 'Enforce the invariant server-side and re-validate workflow state on every transition.',
    }
  }
  return {
    label: 'information disclosure',
    cwe: 'CWE-200',
    category: 'misconfig-exposure',
    impact: 'The response exposed data the requesting actor was not entitled to read.',
    remediation: 'Filter responses server-side to the fields the caller is authorized to see.',
  }
}


/** v6 Phase 1: map a deterministic probe class to the specialist category it best belongs to. */
/**
 * Classify a probe-minted canary purpose (`engine:ssrf:<param> (origin)`, `ssrf:<param>:http
 * (origin)`, `xxe:general_entity (origin)`). Anything else (JWT/JKU, template, auth canaries) is
 * not an async-injection proof and must not be converted into a finding.
 */
export function probeCanaryClass(purpose: string): { vulnClass: 'ssrf' | 'xxe'; origin: string; param: string | null } | null {
  const origin = /\(([^()]+)\)\s*$/.exec(purpose)?.[1]?.trim()
  if (!origin) return null
  const match = /^(?:engine:)?(ssrf|xxe)(?::([^()\s]+))?/.exec(purpose)
  if (!match) return null
  const vulnClass = match[1] as 'ssrf' | 'xxe'
  const segment = match[2] ?? ''
  const variant = new Set(['http', 'dns', 'header', 'custom', 'general_entity', 'param_entity', 'svg_dtd'])
  const param = vulnClass === 'ssrf' && segment && !variant.has(segment)
    ? segment.split(':')[0] ?? null
    : null
  return { vulnClass, origin, param: param || null }
}


function receiptFindingTemplate(vulnClass: 'ssrf' | 'xxe', origin: string, param: string | null) {
  const host = (() => { try { return new URL(origin).hostname } catch { return origin } })()
  if (vulnClass === 'ssrf') {
    return {
      title: `Asynchronous server-side request forgery on ${host}${param ? ` (${param})` : ''}`,
      severity: 'high' as const,
      cwe: 'CWE-918',
      // `Finding.category` is the grader's vulnClass key. A generic OWASP bucket
      // (`ssrf-redirects`) would be scored as an unmatched FP despite the confirmed receipt.
      category: 'ssrf' as const,
      /** Coverage closure keeps the report's OWASP taxonomy. */
      coverageCategory: 'ssrf-redirects' as const,
      impact: 'A server-side fetch of an attacker-controlled URL completes after the HTTP response, so synchronous SSRF filtering and response-time evidence miss it.',
      remediation: 'Resolve and allowlist outbound destinations against a strict scheme/host policy, block metadata and loopback ranges, and perform the fetch inside the request scope so failures are observable.',
      recheck: 'Re-inject the same canary URL and confirm no callback is delivered to the Guardian relay after the response.',
    }
  }
  return {
    title: `Asynchronous XML external entity fetch on ${host}`,
    severity: 'high' as const,
    cwe: 'CWE-611',
    // Canonical vulnClass key (not the generic `injection-input` bucket).
    category: 'xxe' as const,
    coverageCategory: 'injection-input' as const,
    impact: 'An external entity is resolved by a background worker after the upload/preview response, enabling internal file or HTTP exfiltration.',
    remediation: 'Disable DTD and external entity resolution in the XML parser and process imports synchronously with a non-network resolver.',
    recheck: 'Re-submit the same DOCTYPE entity document and confirm the collector receives no request after the response.',
  }
}

function serializeProofReceiptRow(
  pair: { receipt: import('./proof-receipt.ts').ProofReceipt; verification: import('./proof-receipt.ts').ReceiptVerification },
): ReplayProofReceiptRow {
  const { receipt, verification } = pair
  return {
    receipt: {
      vulnClass: receipt.vulnClass,
      target: receipt.target,
      exchangeIds: receipt.exchangeIds,
      oobEventIds: receipt.oobEventIds,
      browserTraceIds: receipt.browserTraceIds,
      claimedDelta: receipt.claimedDelta,
      ...(receipt.oracleEvents ? { oracleEvents: receipt.oracleEvents } : {}),
      ...(receipt.requiredRole ? { requiredRole: receipt.requiredRole } : {}),
      ...(receipt.resourceTenant ? { resourceTenant: receipt.resourceTenant } : {}),
      ...(receipt.expectControlDenied !== undefined ? { expectControlDenied: receipt.expectControlDenied } : {}),
      ...(receipt.proofPatterns ? { proofPatterns: receipt.proofPatterns } : {}),
    } satisfies ReplayProofReceiptRow['receipt'],
    verification: {
      confirmed: verification.confirmed,
      vulnClass: verification.vulnClass,
      rule: verification.rule,
      reason: verification.reason,
      observed: verification.observed,
      expected: verification.expected,
    },
  }
}

export class ExecVerifier {
  private readonly host: ExecVerifyHost
  constructor(host: ExecVerifyHost) { this.host = host }
  private get storage(): Store { return this.host.storage }
  private get broker(): RequestBroker { return this.host.broker }
  private get browser(): ScopedBrowser { return this.host.browser }
  private get canaryBroker(): CanaryBroker { return this.host.canaryBroker }
  private get backend(): WorkerBackend { return this.host.backend }

  private async ensureCanaryListenerForSpec(spec: DeclarativeReplaySpec): Promise<void> {
    if ((spec.kind === 'rce_proof' && spec.proofMode === 'oob_canary') || this.host.isCanaryListenerConfigured()) {
      await this.canaryBroker.startListener({ enableDns: this.host.isCanaryDnsConfigured() }).catch(() => undefined)
    }
  }

  private baseReplayRunnerParams(
    spec: DeclarativeReplaySpec,
    runId: string,
    assignmentId: string,
    grant: Grant,
    signal: AbortSignal,
    reposDir: string | undefined,
    onExchange: (ex: BrokerExchangeResult) => string,
  ) {
    return {
      spec,
      broker: this.broker,
      browser: this.browser,
      canaryBroker: this.canaryBroker,
      backend: this.backend,
      reposDir,
      grant,
      signal,
      storage: this.storage,
      runId,
      assignmentId,
      onExchange,
    }
  }


  // --- Phase 3: Zero-LLM Verification (Replay Specs + Baseline Checks) ---

  /**
   * v6 Phase 3/4: bounded pre-report drain of durable `pending_oob` subscriptions.
   *
   * A background worker can trigger an SSRF/XXE/webhook callback long after the HTTP response.
   * Finalizing the report as soon as verification workers settle dropped exactly those callbacks.
   * This waits up to `GUARDIAN_OOB_DRAIN_MS` (default 45 s), promotes late callbacks on every poll,
   * and records `oobDrainMs` / `promotedLate` in run-event meta. It never waits when nothing is
   * pending, so local-lab benchmark runs keep their zero-latency behavior.
   */
  /**
   * v7 Realism #2: a callback that lands after the synchronous probe/verification window still
   * confirms an async SSRF/XXE. The durable `pending_oob` promotion is host-observed evidence, so it
   * becomes a ProofReceipt validated against the recorded injection exchange and only then a
   * `runtime_confirmed` finding (never a model assertion).
   */
  promoteReceiptOob(runId: string): number {
    let promotions: ReturnType<CanaryBroker['promoteLate']>
    try { promotions = this.canaryBroker.promoteLate({ runId }) } catch { return 0 }
    return this.convertOobPromotions(runId, promotions)
  }


  convertOobPromotions(runId: string, promotions: ReturnType<CanaryBroker['promoteLate']>): number {
    if (promotions.length === 0) return 0
    let run: Run
    try { run = this.storage.run(runId) } catch { return 0 }
    if (run.status !== 'running') return 0
    const approved = this.host.approvedOriginsSet(run)
    let converted = 0
    for (const promotion of promotions) {
      const subscription = promotion.subscription
      let canary: typeof canaries.$inferSelect | undefined
      try {
        canary = this.storage.db.select().from(canaries).where(eq(canaries.id, subscription.canaryId)).get()
      } catch { canary = undefined }
      if (!canary) continue
      const classified = probeCanaryClass(canary.purpose)
      if (!classified) continue
      if (!approved.has(classified.origin)) continue
      // The exact request that carried the canary is the causal binding; a callback alone does not
      // prove that this target reached the listener.
      let carrier: ReturnType<Store['searchExchanges']>[number] | undefined
      try {
        carrier = this.storage.searchExchanges(runId, subscription.token, { approvedOrigins: approved, limit: 10 })
          .find(ex => [ex.pathAndQuery, ex.bodyPreview, JSON.stringify(ex.reqHeaders ?? {})]
            .some(text => String(text).includes(subscription.token)))
      } catch { carrier = undefined }
      if (!carrier) continue
      const receipt = buildOobReceipt({
        vulnClass: classified.vulnClass,
        origin: classified.origin,
        method: carrier.method,
        pathAndQuery: carrier.pathAndQuery,
        ...(classified.param ? { param: classified.param } : {}),
        exchangeIds: [carrier.id],
        oobEventId: subscription.id,
        claimedDelta: `The target fetched the injected ${classified.vulnClass.toUpperCase()} canary after its HTTP response (durable ${promotion.stage} callback).`,
      })
      const oobEvent: ReceiptOobEvent = {
        id: subscription.id,
        callbackId: promotion.callback.callbackId,
        canaryId: subscription.canaryId,
        token: subscription.token,
        targetOrigin: classified.origin,
        delivered: true,
        stage: promotion.stage,
        receivedAtMs: promotion.callback.receivedAt,
        latencyMs: promotion.latencyMs,
      }
      let body = carrier.bodyPreview
      try { body = this.storage.getExchange(runId, carrier.id).body } catch { /* preview is enough */ }
      const verification = verifyReceipt(receipt, {
        entries: [{
          exchangeId: carrier.id,
          step: {
            id: carrier.id,
            arm: 'probe',
            method: carrier.method,
            route: carrier.pathAndQuery.split('?')[0],
            pathAndQuery: carrier.pathAndQuery,
            status: carrier.status,
            actor: { handle: carrier.personaHandle, role: null, tenant: null, auth: 'unknown', sameSite: null },
            body,
            requestHeaders: carrier.reqHeaders ?? null,
            responseHeaders: carrier.respHeaders ?? null,
          },
          carrierText: `${carrier.pathAndQuery}\n${JSON.stringify(carrier.reqHeaders ?? {})}\n${body}`,
        }],
        oobEvents: [oobEvent],
      })
      if (!verification.confirmed) {
        try {
          this.storage.event(runId, 'oob.receipt_rejected', `OOB promotion for canary ${subscription.canaryId} did not verify: ${verification.reason}`, {
            canaryId: subscription.canaryId,
            subscriptionId: subscription.id,
            reason: verification.reason,
          })
        } catch { /* store closed */ }
        continue
      }
      try {
        if (this.persistReceiptFinding(run, {
          vulnClass: classified.vulnClass,
          origin: classified.origin,
          param: classified.param,
          carrier,
          receipt,
          verification,
          subscriptionId: subscription.id,
        })) converted += 1
      } catch { /* persistence is best-effort; never fail the drain */ }
    }
    return converted
  }


  persistReceiptFinding(run: Run, input: {
    vulnClass: 'ssrf' | 'xxe'
    origin: string
    param: string | null
    carrier: ReturnType<Store['searchExchanges']>[number]
    receipt: ReturnType<typeof buildOobReceipt>
    verification: ReturnType<typeof verifyReceipt>
    subscriptionId: string
  }): boolean {
    const asset = run.candidates.find(candidate => candidate.origin === input.origin && run.approved.includes(candidate.id))
    if (!asset) return false
    const template = receiptFindingTemplate(input.vulnClass, input.origin, input.param)
    const rows = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id),
      eq(findings.goalRevision, run.goalRevision),
    )).all()
    // One async callback per (origin, class) target: never let a repeated poll inflate findings.
    const duplicate = rows.find(row => row.finding.origin === input.origin &&
      row.finding.cwe === template.cwe &&
      (row.finding.status === 'confirmed' || row.finding.status === 'static_verified'))
    if (duplicate) return false

    const assignment = this.storage.workerList(run.id).find(worker => worker.id === input.carrier.assignmentId)
      ?? this.storage.workerList(run.id)[0]
    if (!assignment) return false
    const evidence = this.storage.addArtifact(
      run,
      assignment,
      'replay',
      `ProofReceipt · async ${input.vulnClass.toUpperCase()} · ${new URL(input.origin).hostname}`,
      JSON.stringify({
        receipt: input.receipt,
        verification: input.verification,
        carrierExchangeId: input.carrier.id,
        oobSubscriptionId: input.subscriptionId,
      }, null, 2),
      `receipt:oob:${input.subscriptionId}`,
      [],
    )

    // Prefer the replay spec whose probe carried this canary (it has the chain context), else keep
    // `replay_spec_id` null for a receipt-only finding.
    let specRow: ReplaySpecRow | undefined
    try {
      specRow = this.storage.listReplaySpecs(run.id).find(row => {
        const text = JSON.stringify(row.spec)
        return text.includes(input.subscriptionId) || text.includes(input.carrier.id)
      })
    } catch { specRow = undefined }
    const existing = specRow
      ? rows.find(row => row.id === specRow!.findingId)
      : rows.find(row => row.finding.origin === input.origin && row.finding.cwe === template.cwe && row.finding.status !== 'confirmed')
    const findingId = existing?.id ?? randomUUID()
    const finding: Finding = {
      ...(existing?.finding ?? {}),
      id: findingId,
      origin: input.origin,
      title: template.title,
      status: 'confirmed',
      severity: template.severity,
      reason: input.verification.reason,
      remediation: template.remediation,
      impact: template.impact,
      recheck: template.recheck,
      category: template.category,
      cwe: template.cwe,
      confidence: 'high',
      verification: `ProofReceipt ${input.receipt.oobEventIds[0]} · ${input.verification.rule} rule · ${input.verification.reason}`,
      verificationTier: 'runtime_confirmed',
      findingKind: 'multi_step_chain',
      replaySpecId: specRow?.id,
      exchangeIds: [...new Set([...(existing?.finding.exchangeIds ?? []), input.carrier.id])],
      evidenceIds: [...new Set([...(existing?.finding.evidenceIds ?? []), evidence.id])],
      scopeRevision: run.scopeRevision,
    }
    if (specRow) {
      this.storage.upsertChainFinding(run, asset.id, finding, specRow.id, specRow.sourceOrigins)
    } else if (existing) {
      this.storage.db.update(findings).set({
        verificationTier: 'runtime_confirmed',
        verificationClass: 'runtime_confirmed',
        finding,
      }).where(and(eq(findings.runId, run.id), eq(findings.id, findingId))).run()
    } else {
      this.storage.db.insert(findings).values({
        id: findingId,
        runId: run.id,
        assetId: asset.id,
        goalRevision: run.goalRevision,
        checkId: 'chain',
        caseId: findingId,
        findingKind: 'multi_step_chain',
        replaySpecId: null,
        sourceOrigins: [input.origin],
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        verificationClass: 'runtime_confirmed',
        finding,
      }).run()
    }
    try {
      this.storage.upsertCoverageEntry(run, assignment.id, {
        origin: input.origin,
        category: template.coverageCategory,
        status: 'reported',
        summary: `Confirmed async ${input.vulnClass.toUpperCase()} via ProofReceipt ${input.subscriptionId}`,
        linkedFindingId: findingId,
      })
      this.storage.event(run.id, 'oob.receipt_confirmed',
        `Late ${input.vulnClass.toUpperCase()} callback promoted to a runtime_confirmed finding (${input.verification.reason.slice(0, 200)}).`, {
          findingId,
          oobSubscriptionId: input.subscriptionId,
          exchangeId: input.carrier.id,
          rule: input.verification.rule,
        })
    } catch { /* metrics/coverage are best-effort */ }
    return true
  }


  async verifyReplaySpecJob(job: Active, replaySpecId: string) {
    const run = this.host.check(job)
    const specRow = this.storage.getReplaySpec(run.id, replaySpecId)
    const findingRow = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.id, specRow.findingId),
    )).get()
    if (!findingRow) {
      this.host.completeWorker(job.assignment, run, 'Finding no longer exists.', [])
      return
    }

    const permittedAtAdmission = this.host.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.host.buildGrant(job, run, permittedAtAdmission)
    const { reposDir } = this.host.projectReposMount(run.projectId)

    await this.ensureCanaryListenerForSpec(specRow.spec)

    // Tier 3 HITL gate for rce_proof and upload_probe specs on non-local-lab targets
    if (specRow.spec.kind === 'rce_proof' || specRow.spec.kind === 'upload_probe') {
      const gateReq = buildTier3VerifyGateReq(
        specRow.spec,
        specRow.spec.kind === 'rce_proof'
          ? 'Zero-LLM non-destructive PoE verification'
          : 'Zero-LLM benign multipart upload verification',
      )
      const approval = await this.host.waitForTier3Approval(job, { ...gateReq, secrets }, job.controller.signal)
      if (!approval.approved) {
        const current = this.host.check(job)
        const updatedFinding: Finding = {
          ...findingRow.finding,
          status: 'inconclusive',
          reason: approval.deniedReason
            ? `Tier 3 Safety Judge denied ${specRow.spec.kind} verification: ${approval.deniedReason}`
            : `Tier 3 approval for ${specRow.spec.kind} verification was denied or expired.`,
          confidence: 'low',
        }
        this.storage.upsertChainFinding(current, findingRow.assetId, updatedFinding, specRow.id, specRow.sourceOrigins)
        this.host.completeWorker(job.assignment, current, 'Inconclusive: Tier 3 approval denied.', [], undefined, secrets)
        return
      }
    }

    const verifyParams = this.baseReplayRunnerParams(
      specRow.spec, run.id, job.assignment.id, grant, job.controller.signal, reposDir,
      createExchangeRecorder(this.storage, () => run, job.assignment.id, currentSecrets, {
        trackResources: true,
        markCoverage: (r, o, m, p) => this.host.markEndpointCoverage(r, o, m, p, `replay:${specRow.spec.kind}`),
      }),
    )
    const result = await verifyReplaySpec(verifyParams)
    this.host.markReplaySpecCoverage(run, specRow.spec, `replay:${specRow.spec.kind}`)
    if (result.receipt && !result.receipt.verification.confirmed) {
      // Parity telemetry only: shadow receipts never change this verdict.
      try {
        this.storage.event(run.id, 'proof_receipt.shadow_reject',
          `ProofReceipt did not substantiate spec ${specRow.id}: ${result.receipt.verification.reason}`.slice(0, 400), {
            replaySpecId: specRow.id,
            vulnClass: result.receipt.receipt.vulnClass,
            rule: result.receipt.verification.rule,
            mode: result.receipt.mode,
          })
      } catch { /* store closed */ }
    }

    const current = this.host.check(job)
    let phaseFeedback: InlineVerifyFeedback | undefined
    this.storage.transaction(() => {
      // Strict Tier Separation (Invariant #4): static_ast_proof NEVER promotes to 'confirmed' / 'runtime_confirmed'
      const { isStaticAst, finalStatus, verificationTier } = deriveReplayOutcomeStatus(specRow.spec, result)
      const receipt = this.storage.addArtifact(current, job.assignment, 'replay',
        `${isStaticAst ? 'Deterministic Static AST' : 'Zero-LLM replay'} · ${specRow.spec.title}`,
        JSON.stringify({
          replaySpecId: specRow.id,
          specSha256: specRow.specSha256,
          kind: specRow.spec.kind,
          origin: specRow.spec.origin,
          verdict: finalStatus,
          verificationTier: verificationTier ?? null,
          outcome: result.outcome,
          exchangeIds: result.exchangeIds,
          sourceOrigins: specRow.sourceOrigins,
          evidenceSha256: result.evidenceSha256,
          evidencePayload: result.evidencePayload,
          receipt: result.receipt?.verification ?? null,
          receiptArtifact: result.receipt?.receipt ?? null,
        }, null, 2), 'replay:' + specRow.id, currentSecrets())

      const secretsList = currentSecrets()
      const { patch, cleanObserved } = buildReplayFindingPatch(
        specRow.spec, result, findingRow.finding, finalStatus, verificationTier, 'replay', secretsList,
      )
      const updatedFinding: Finding = {
        ...findingRow.finding,
        ...patch,
        evidenceIds: [...new Set([...findingRow.finding.evidenceIds, receipt.id])],
        exchangeIds: [...new Set([...(findingRow.finding.exchangeIds ?? []), ...result.exchangeIds])],
        scopeRevision: current.scopeRevision,
      }
      const rawFeedback = buildInlineVerifyFeedback(
        specRow.spec,
        result,
        Math.max(1, specRow.attemptCount),
        maxInlineVerifyRetries,
        currentSecrets(),
      )
      phaseFeedback = rawFeedback
      // Route every diff through the store: confirmation writes persist the confirming verdict
      // before the finding write, and a non-confirming retest demotes an already-confirmed claim
      // (and is counted) instead of leaving it contradicted by its own evidence.
      this.host.recordSpecVerification(
        current.id,
        specRow.id,
        rawFeedback,
        `phase3 ${specRow.spec.kind} attempt ${specRow.attemptCount} returned ${finalStatus}`,
      )
      if (finalStatus === 'confirmed' || finalStatus === 'static_verified') {
        this.storage.upsertChainFinding(current, findingRow.assetId, alignFindingForEvidence(updatedFinding, result), specRow.id, specRow.sourceOrigins)
        recordReportedFindingCoverage(this.storage, current, job.assignment.id, specRow.spec.origin, specRow.spec.category, `${finalStatus === 'static_verified' ? 'Static verified' : 'Confirmed'}: ${specRow.spec.title}`, findingRow.id, (r, o) => this.host.permitted(r, o))
        const refreshedRow = this.storage.db.select().from(findings).where(and(
          eq(findings.runId, current.id), eq(findings.id, findingRow.id),
        )).get()
        if (refreshedRow) this.host.scheduleVariantSweepForFinding(current, refreshedRow)
      } else {
        this.storage.updateProposedFinding(current, findingRow.id, {
          verificationTier: null,
          finding: updatedFinding,
        })
      }
      this.host.completeWorker(
        job.assignment,
        current,
        `Replay verdict: ${finalStatus} (${cleanObserved.slice(0, 160)})`,
        [receipt.id],
        undefined,
        secretsList,
      )
    }, { behavior: 'immediate' })
    const refreshed = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, current.id), eq(findings.id, findingRow.id),
    )).get()
    if (refreshed) {
      this.host.postVerificationVerdict(current, {
        replaySpecId: specRow.id,
        findingId: refreshed.id,
        title: specRow.spec.title,
        status: refreshed.finding.status,
        verificationTier: refreshed.verificationTier ?? refreshed.finding.verificationTier ?? null,
        feedback: phaseFeedback ?? specRow.lastVerificationDiff ?? null,
        assignmentId: specRow.assignmentId,
        attempt: specRow.attemptCount,
      })
    }
  }


  // --- Phase 3b: agent script proofs (v7 M5) ---------------------------------

  /**
   * The Layer-3 script path needs a backend that can open an air-gapped session with the attempt's
   * verification RPC directory mounted. A replay-only backend (local-jq) must keep the declarative
   * compilers instead of exposing a script tool that can never run.
   */
  backendSupportsVerifyScript(): boolean {
    return this.backend instanceof LinuxWorkerBackend
  }


  /** Resolve a workspace-relative script path inside the read-only repo mount, bounded. */
  readAgentProofScript(reposDir: string | undefined, scriptPath: string): string {
    if (!reposDir) throw new Error('guardian_verify scriptPath requires a mounted workspace; pass `script` inline.')
    const clean = scriptPath.trim().replace(/^\/+/, '')
    if (!clean || clean.includes('\0') || clean.split(/[\\/]/).includes('..')) {
      throw new Error('guardian_verify scriptPath must stay inside the mounted workspace.')
    }
    const full = join(reposDir, clean)
    if (!full.startsWith(reposDir + sep) || !existsSync(full)) {
      throw new Error('guardian_verify scriptPath was not found in the mounted workspace; pass the script inline via `script` instead.')
    }
    const size = statSync(full).size
    if (size <= 0 || size > 64 * 1024) throw new Error('guardian_verify script must be between 1 byte and 64 KiB.')
    return readFileSync(full, 'utf8')
  }


  /**
   * Persist a confirmed Layer-3 proof: the script (redacted, owner-only artifact), the receipt row
   * (script hash, verdict, receipt + verification), and a finding that cites the receipt. The
   * declarative fields on the row are attribution for reporting/retest only; the receipt is what
   * confirms.
   */
  persistAgentScriptProof(input: {
    run: Run
    assignment: Assignment
    script: string
    runtime: 'ts' | 'python'
    title?: string
    proof: AgentScriptProofResult
    secrets: readonly NamedSecret[]
  }): { findingId: string; replaySpecId: string; receiptId: string | null } {
    const { run, assignment, proof } = input
    if (!proof.verdict.confirmed || (proof.receipt && !proof.receipt.verification.confirmed)) {
      throw new InvariantError(
        'invariant.confirmation_evidence',
        `Invariant: refusing to persist a non-confirming agent script proof (verdict=${proof.verdict.reason}).`,
      )
    }
    const receipt = proof.receipt?.receipt ?? null
    const verification = proof.receipt?.verification ?? null
    const claim = receipt?.vulnClass ?? 'disclosure'
    const attribution = agentProofAttribution(claim)
    const origin = receipt?.target.origin
      ?? proof.exchanges.find(exchange => exchange.sessionRole === 'probe')?.origin
      ?? proof.exchanges[0]?.origin
    if (!origin || !this.host.approvedOriginsSet(run).has(origin)) {
      throw new BrokerDenied('The proof exchanges name an origin outside the current approved scope.')
    }
    const asset = run.candidates.find(candidate => candidate.origin === origin && run.approved.includes(candidate.id))
    if (!asset) throw new BrokerDenied('The proof origin is not an approved asset of this run.')
    const title = (input.title ?? proof.claimTitle ?? `${attribution.label} confirmed by script proof`).slice(0, 200)
    const severity = (findingSeverities as readonly string[]).includes(proof.severity ?? '')
      ? proof.severity as Finding['severity']
      : 'high'
    const scriptSha256 = createHash('sha256').update(input.script).digest('hex')
    const scriptRedacted = redact(input.script, input.secrets)
    const cleanTitle = redact(title, input.secrets)

    const artifact = this.storage.addArtifact(
      run,
      assignment,
      'replay',
      `Agent proof script · ${cleanTitle}`,
      JSON.stringify({
        mode: 'agent_script',
        runtime: input.runtime,
        scriptSha256,
        script: scriptRedacted,
        receipt,
        verification,
        transcriptDigests: proof.transcriptDigests,
      }, null, 2),
      `agent-proof:${scriptSha256}`,
      input.secrets,
    )

    const envelope: AgentScriptProofEnvelope = {
      kind: 'agent_script',
      runtime: input.runtime,
      script: scriptRedacted,
      scriptSha256,
      verdict: 'confirmed',
      ...(receipt?.vulnClass ? { vulnClass: receipt.vulnClass } : {}),
      exchangeIds: [...new Set(proof.exchanges.map(exchange => exchange.exchangeId))].slice(0, 64),
      transcriptDigests: proof.transcriptDigests.slice(0, 4),
      receiptArtifactId: artifact.id,
      confirmedAt: Date.now(),
    }
    const feedback: InlineVerifyFeedback = {
      verdict: 'confirmed',
      verificationTier: 'runtime_confirmed',
      controlPassed: proof.verdict.attempts.every(attempt => attempt.oraclePassed),
      assertionSummary: {
        observed: verification?.observed ?? `${proof.verdict.attempts.length} signed script runs confirmed the claim.`,
        expected: verification?.expected ?? 'the claimed impact is re-derivable from the recorded transcript',
        ...(verification?.reason ? { reason: verification.reason } : {}),
      },
      stepStatuses: [],
      retriesRemaining: maxInlineVerifyRetries,
    }
    const findingId = this.storage.findDuplicateChainFinding(run.id, run.goalRevision, {
      origin,
      cwe: attribution.cwe,
      category: attribution.category,
      title: cleanTitle,
    })?.id ?? randomUUID()
    const spec = this.agentProofAttributionSpec({
      origin,
      title: cleanTitle,
      attribution,
      severity,
      envelope,
      proof,
      receipt,
    })
    const proofRecord: AgentScriptProofRecord = {
      replaySpecId: '',
      findingId,
      verdict: 'confirmed',
      runtime: input.runtime,
      scriptSha256,
      artifactId: artifact.id,
      receipt: receipt && verification ? serializeProofReceiptRow({ receipt, verification }) : null,
      createdAt: Date.now(),
    }
    const specRow = this.storage.createReplaySpec(
      run,
      assignment,
      findingId,
      spec,
      [origin],
      { initialAttemptCount: 1, verifiedInline: true, lastVerificationDiff: feedback, proof: proofRecord },
    )

    const finding: Finding = {
      id: findingId,
      origin,
      title: cleanTitle,
      status: 'confirmed',
      severity,
      reason: verification?.reason ?? proof.verdict.detail ?? 'Confirmed by a Layer-3 verification script.',
      remediation: attribution.remediation,
      impact: receipt?.claimedDelta ?? attribution.impact,
      recheck: `Re-run the persisted ${input.runtime} proof script and re-validate its receipt.`,
      category: attribution.category,
      cwe: attribution.cwe,
      confidence: 'high',
      verification: receipt
        ? `ProofReceipt ${receipt.exchangeIds[0] ?? scriptSha256.slice(0, 12)} · ${verification?.rule ?? 'receipt'} rule · ${verification?.reason ?? 'verified'}`
        : `Layer-3 script proof (${input.runtime}) · ${proof.verdict.attempts.length} signed runs · digest ${proof.transcriptDigests[0]?.slice(0, 12) ?? 'n/a'}`,
      verificationTier: 'runtime_confirmed',
      findingKind: 'multi_step_chain',
      replaySpecId: specRow.id,
      exchangeIds: receipt?.exchangeIds?.length ? [...receipt.exchangeIds] : envelope.exchangeIds,
      evidenceIds: [artifact.id],
      scopeRevision: run.scopeRevision,
    }
    this.storage.upsertChainFinding(run, asset.id, finding, specRow.id, [origin])
    recordReportedFindingCoverage(this.storage, run, assignment.id, origin, attribution.category, `Confirmed via agent script proof: ${cleanTitle}`, findingId, (r, o) => this.host.permitted(r, o))
    this.storage.event(run.id, 'agent.script_proof_confirmed', `Agent script proof confirmed a ${attribution.label} finding on ${origin}.`, {
      findingId,
      replaySpecId: specRow.id,
      artifactId: artifact.id,
      scriptSha256,
      receiptRule: verification?.rule ?? null,
      transcriptDigests: proof.transcriptDigests,
    })
    return { findingId, replaySpecId: specRow.id, receiptId: receipt?.exchangeIds[0] ?? null }
  }


  /** Attribution-only declarative row for a script proof (never interpreted as a DSL confirm). */
  agentProofAttributionSpec(input: {
    origin: string
    title: string
    attribution: ReturnType<typeof agentProofAttribution>
    severity: Finding['severity']
    envelope: AgentScriptProofEnvelope
    proof: AgentScriptProofResult
    receipt: import('./proof-receipt.ts').ProofReceipt | null
  }): DeclarativeReplaySpec {
    const cited = input.receipt?.exchangeIds ?? []
    const ordered = [
      ...input.proof.exchanges.filter(exchange => cited.includes(exchange.exchangeId)),
      ...input.proof.exchanges.filter(exchange => !cited.includes(exchange.exchangeId)),
    ].slice(0, 8)
    const steps = (ordered.length >= 2 ? ordered : [...ordered, ...ordered]).slice(0, 8).map((exchange, index) => ({
      id: `proof_${index + 1}`,
      role: index === 0 ? 'control' as const : 'probe' as const,
      description: `${exchange.method.toUpperCase()} ${exchange.pathAndQuery} (agent script proof)`.slice(0, 400),
      ...(exchange.status !== null ? { expectedStatus: exchange.status } : {}),
      request: {
        origin: exchange.origin,
        method: (httpMethods as readonly string[]).includes(exchange.method.toUpperCase())
          ? exchange.method.toUpperCase() as typeof httpMethods[number]
          : 'GET' as const,
        pathAndQuery: exchange.pathAndQuery.startsWith('/') ? exchange.pathAndQuery : `/${exchange.pathAndQuery}`,
        followRedirects: false,
        ...(exchange.personaHandle ? { persona: exchange.personaHandle } : {}),
      },
    }))
    return {
      version: 1,
      kind: 'http_chain',
      spaCatchallControl: false,
      origin: input.origin,
      title: input.title,
      category: input.attribution.category,
      cwe: input.attribution.cwe,
      severity: input.severity,
      severityRationale: `Confirmed by a Layer-3 verification script whose receipt was re-checked against the host transcript (${input.attribution.label}).`,
      impact: input.attribution.impact,
      remediation: input.attribution.remediation,
      recheckInstructions: 'Re-run the persisted guardian_verify script; the finding is confirmed only by its receipt.',
      assertionsJq: '[.[] | select(.status >= 200)]',
      agentScript: input.envelope,
      steps,
    }
  }


  /**
   * Receipt-first re-verification of a persisted agent script proof.
   *
   * The script is re-run through the same fresh-session double-run, and the fresh receipt is
   * re-validated with `verifyReceipt()`. Nothing here interprets the declarative attribution row.
   * Returns null only when the row carries no script envelope (legacy/agent-authored DSL proofs),
   * which keeps the old path available for kinds with no script form.
   */
  async reverifyAgentScriptProof(
    run: Run,
    params: {
      job: Active
      grant: Grant
      currentSecrets: () => readonly NamedSecret[]
      findingId?: string
      replaySpecId?: string
      onExchangeObserved?: (curRun: Run, ex: BrokerExchangeResult, exchangeId: string) => void
    },
    proof: AgentScriptProofRecord,
  ): Promise<{
    findingId?: string
    replaySpecId: string
    attemptCount: number
    status: Finding['status']
    verificationTier?: VerificationTier
    feedback: InlineVerifyFeedback
  } | null> {
    const specRow = this.storage.getReplaySpec(run.id, proof.replaySpecId)
    const persisted = persistedAgentScriptOf(specRow.spec)
    if (!persisted?.envelope) return null
    const envelope = persisted.envelope
    const findingRow = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.id, specRow.findingId),
    )).get()
    const origin = (persisted.origin || specRow.spec.origin || '').trim()
    const approved = this.host.approvedOriginsSet(run)
    if (!origin || !approved.has(origin)) return null

    const result = await runAgentScriptProof({
      script: envelope.script,
      runtime: envelope.runtime,
      ...(envelope.vulnClass ? { title: `${envelope.vulnClass} agent proof re-verification` } : {}),
      broker: this.broker,
      grant: params.grant,
      backend: this.backend,
      runId: run.id,
      assignmentId: params.job.assignment.id,
      targetOrigins: [origin],
      signal: params.job.controller.signal,
      canaryBroker: this.canaryBroker,
    })
    const receiptOk = !envelope.vulnClass || result.receipt?.verification.confirmed === true
    const confirmed = result.verdict.confirmed && receiptOk
    const status: Finding['status'] = confirmed
      ? 'confirmed'
      : result.verdict.reason === 'oracle_failed'
        ? 'dismissed'
        : 'inconclusive'
    const verificationTier: VerificationTier | undefined = confirmed ? 'runtime_confirmed' : undefined
    const feedback: InlineVerifyFeedback = {
      verdict: status === 'confirmed' ? 'confirmed' : status === 'dismissed' ? 'dismissed' : 'inconclusive',
      ...(verificationTier ? { verificationTier } : {}),
      controlPassed: result.verdict.attempts.every(attempt => attempt.oraclePassed),
      assertionSummary: {
        observed: confirmed
          ? `Agent script ${envelope.runtime} proof reproduced and its receipt re-validated.`
          : `Agent script proof did not re-confirm: ${result.verdict.reason}.`,
        expected: 'the persisted script reproduces the confirmation and its receipt re-validates',
        ...(result.verdict.detail ? { reason: result.verdict.detail } : {}),
      },
      stepStatuses: [],
      retriesRemaining: maxInlineVerifyRetries,
    }
    const updatedSpec = this.storage.incrementReplaySpecAttempt(specRow.id, feedback, {
      spec: specRow.spec,
      sourceOrigins: specRow.sourceOrigins,
      secrets: params.currentSecrets(),
    })
    const receiptRow = confirmed && result.receipt
      ? serializeProofReceiptRow(result.receipt)
      : confirmed
        ? proof.receipt ?? null
        : null
    this.storage.setReplaySpecProof(run.id, updatedSpec.id, {
      ...proof,
      replaySpecId: updatedSpec.id,
      verdict: status === 'confirmed' ? 'confirmed' : status === 'dismissed' ? 'dismissed' : 'inconclusive',
      receipt: receiptRow,
      createdAt: Date.now(),
    })

    if (findingRow) {
      const nextFinding: Finding = {
        ...findingRow.finding,
        status,
        verificationTier,
        reason: result.verdict.detail || result.verdict.reason,
        confidence: confirmed ? 'high' : 'low',
        verification: confirmed
          ? `ProofReceipt · ${result.receipt?.verification.rule ?? 'script'} rule · ${result.receipt?.verification.reason ?? result.verdict.reason}`
          : `Agent script proof re-verification returned ${status} (${result.verdict.reason}).`,
        exchangeIds: result.exchanges.map(exchange => exchange.exchangeId),
        replaySpecId: updatedSpec.id,
        scopeRevision: run.scopeRevision,
      }
      if (confirmed) {
        const assetId = findingRow.assetId
        this.storage.upsertChainFinding(run, assetId, nextFinding, updatedSpec.id, specRow.sourceOrigins)
      } else {
        this.storage.updateProposedFinding(run, findingRow.id, {
          replaySpecId: updatedSpec.id,
          verificationTier: null,
          finding: {
            status,
            verificationTier: undefined,
            reason: nextFinding.reason,
            confidence: 'low',
            verification: nextFinding.verification,
            exchangeIds: nextFinding.exchangeIds,
          },
        })
      }
    }
    this.host.postVerificationVerdict(run, {
      replaySpecId: updatedSpec.id,
      findingId: findingRow?.id ?? null,
      title: findingRow?.finding.title ?? 'Agent script proof',
      status,
      verificationTier,
      feedback,
      assignmentId: updatedSpec.assignmentId ?? params.job.assignment.id,
      refStepId: params.job.assignment.stepId,
      attempt: updatedSpec.attemptCount,
    })
    return {
      findingId: findingRow?.id ?? specRow.findingId,
      replaySpecId: updatedSpec.id,
      attemptCount: updatedSpec.attemptCount,
      status,
      ...(verificationTier ? { verificationTier } : {}),
      feedback,
    }
  }


  async executeInlineVerification(params: {
    job: Active
    grant: Grant
    currentSecrets: () => readonly NamedSecret[]
    reposDir?: string
    spec: DeclarativeReplaySpec
    findingId?: string
    replaySpecId?: string
    onExchangeObserved?: (curRun: Run, ex: BrokerExchangeResult, exchangeId: string) => void
  }): Promise<{
    findingId?: string
    replaySpecId: string
    attemptCount: number
    status: Finding['status']
    verificationTier?: VerificationTier
    feedback: InlineVerifyFeedback
    artifactId?: string
  }> {
    const curRun = this.host.check(params.job)
    if (this.storage.checkBudgetExceeded(curRun.id)) {
      throw new BudgetExceededError('Run spend or request budget exceeded.')
    }
    // Receipt-first: a finding that already carries a persisted agent script proof is judged by
    // re-running that script and re-validating its receipt. The declarative shape is attribution
    // only, so it is never parsed or interpreted for such a finding.
    const agentProof = (params.replaySpecId ? this.storage.replaySpecProof(curRun.id, params.replaySpecId) : null)
      ?? (params.findingId ? this.storage.agentProofForFinding(curRun.id, params.findingId) : null)
    if (agentProof) {
      const receiptFirst = await this.reverifyAgentScriptProof(curRun, params, agentProof)
      if (receiptFirst) return receiptFirst
    }
    const parsed = declarativeReplaySpecSchema.parse(params.spec)
    const specOrigins = replaySpecOrigins(parsed)
    const currentApproved = this.host.approvedOriginsSet(curRun)
    if (specOrigins.some(o => !currentApproved.has(o))) {
      throw new BrokerDenied('Replay spec references an origin outside current approved scope.')
    }

    const findingRow = params.findingId
      ? this.storage.db.select().from(findings).where(and(
          eq(findings.runId, curRun.id), eq(findings.id, params.findingId),
        )).get()
      : undefined
    const isAlreadyVerified = Boolean(
      findingRow && (findingRow.finding.status === 'confirmed' || findingRow.finding.status === 'static_verified'),
    )

    const standaloneKey = !params.findingId
      ? 'inline:' + params.job.assignment.id + ':' + createHash('sha256')
          .update(`${parsed.kind}|${parsed.origin}|${parsed.cwe}|${parsed.title.trim().toLowerCase()}`)
          .digest('hex').slice(0, 16)
      : undefined
    const trackingFindingId = findingRow?.id ?? params.findingId ?? standaloneKey!

    let specRow: ReplaySpecRow | undefined
    if (params.replaySpecId) {
      specRow = this.storage.getReplaySpec(curRun.id, params.replaySpecId)
    }
    const existingForFinding = this.storage.listReplaySpecsForFinding(curRun.id, trackingFindingId)
    if (!specRow) {
      specRow = existingForFinding[0]
    }
    if (!specRow) {
      specRow = this.storage.createReplaySpec(
        curRun,
        params.job.assignment,
        trackingFindingId,
        parsed,
        specOrigins.length ? specOrigins : [parsed.origin],
        { initialAttemptCount: 0 },
      )
    }

    const currentAttempts = Math.max(
      specRow.attemptCount,
      ...existingForFinding.map(r => r.attemptCount),
      0,
    )
    const nextAttempt = currentAttempts + 1
    const maxAttempts = 1 + maxInlineVerifyRetries

    if (nextAttempt <= maxAttempts) {
      await this.ensureCanaryListenerForSpec(parsed)
      if (parsed.kind === 'rce_proof' || parsed.kind === 'upload_probe') {
        const gateReq = buildTier3VerifyGateReq(parsed, 'Inline Zero-LLM verification')
        const approval = await this.host.waitForTier3Approval(params.job, {
          ...gateReq,
          secrets: params.currentSecrets(),
        }, params.job.controller.signal)
        if (!approval.approved) {
          const deniedReason = approval.deniedReason
            ? `Tier 3 Safety Judge denied ${parsed.kind} verification: ${approval.deniedReason}`
            : `Tier 3 approval for ${parsed.kind} verification was denied or expired.`
          const deniedFeedback = redactJsonValue({
            verdict: 'inconclusive',
            controlPassed: false,
            assertionSummary: {
              observed: 'tier3_approval_denied',
              expected: 'Tier 3 approval granted',
              reason: deniedReason,
            },
            stepStatuses: [],
            retriesRemaining: Math.max(0, maxAttempts - nextAttempt),
          } satisfies InlineVerifyFeedback, params.currentSecrets())
          const updatedSpec = this.storage.incrementReplaySpecAttempt(specRow.id, deniedFeedback, {
            spec: parsed,
            sourceOrigins: [...new Set([...specRow.sourceOrigins, ...specOrigins])],
            secrets: params.currentSecrets(),
          })
          if (findingRow && !isAlreadyVerified) {
            const latestRun = this.host.check(params.job)
            this.storage.updateProposedFinding(latestRun, findingRow.id, {
              replaySpecId: updatedSpec.id,
              verificationTier: null,
              finding: { status: 'inconclusive', verificationTier: undefined, reason: deniedReason, confidence: 'low' },
            })
          }
          const deniedRun = this.host.check(params.job)
          const deniedRow = findingRow
            ? this.storage.db.select().from(findings).where(and(
                eq(findings.runId, deniedRun.id), eq(findings.id, findingRow.id),
              )).get()
            : undefined
          return {
            findingId: findingRow?.id,
            replaySpecId: updatedSpec.id,
            attemptCount: updatedSpec.attemptCount,
            status: deniedRow?.finding.status ?? 'inconclusive',
            feedback: deniedFeedback,
          }
        }
      }
    }

    const { feedback, replay } = await verifyReplaySpecInline({
      ...this.baseReplayRunnerParams(
        parsed, curRun.id, params.job.assignment.id, params.grant, params.job.controller.signal, params.reposDir,
        createExchangeRecorder(
          this.storage,
          () => this.host.check(params.job),
          params.job.assignment.id,
          params.currentSecrets,
          {
            trackResources: true,
            markCoverage: (latest, o, m, p) => this.host.markEndpointCoverage(latest, o, m, p, `replay:${parsed.kind}`),
            onSaved: (latest, ex, id) => params.onExchangeObserved?.(latest, ex, id),
          },
        ),
      ),
      findingId: findingRow?.id,
      attemptCount: nextAttempt,
      maxRetries: maxInlineVerifyRetries,
      secrets: params.currentSecrets(),
    })
    const latestForCoverage = this.host.check(params.job)
    this.host.markReplaySpecCoverage(latestForCoverage, parsed, `replay:${parsed.kind}`)

    if (nextAttempt > maxAttempts) {
      return {
        findingId: findingRow?.id,
        replaySpecId: specRow.id,
        attemptCount: currentAttempts,
        status: findingRow?.finding.status ?? 'inconclusive',
        verificationTier: findingRow?.verificationTier ?? undefined,
        feedback,
      }
    }

    const { isStaticAst, finalStatus, verificationTier } = deriveReplayOutcomeStatus(parsed, replay)
    const normalizedFeedback: InlineVerifyFeedback = {
      ...feedback,
      verdict: finalStatus as InlineVerifyFeedback['verdict'],
      ...(verificationTier ? { verificationTier } : {}),
    }

    const latestRun = this.host.check(params.job)
    const updatedSpec = this.storage.incrementReplaySpecAttempt(specRow.id, normalizedFeedback, {
      spec: parsed,
      sourceOrigins: [...new Set([...specRow.sourceOrigins, ...specOrigins])],
      secrets: params.currentSecrets(),
    })

    const receipt = this.storage.addArtifact(
      latestRun,
      params.job.assignment,
      'replay',
      `Inline ${isStaticAst ? 'Static AST' : 'Zero-LLM replay'} attempt #${updatedSpec.attemptCount} · ${parsed.title}`,
      JSON.stringify({
        replaySpecId: updatedSpec.id,
        attemptCount: updatedSpec.attemptCount,
        specSha256: updatedSpec.specSha256,
        kind: parsed.kind,
        origin: parsed.origin,
        verdict: finalStatus,
        verificationTier: verificationTier ?? null,
        outcome: replay.outcome,
        feedback: normalizedFeedback,
        exchangeIds: replay.exchangeIds,
        evidenceSha256: replay.evidenceSha256,
        evidencePayload: replay.evidencePayload,
        receipt: replay.receipt?.verification ?? null,
        receiptArtifact: replay.receipt?.receipt ?? null,
      }, null, 2),
      undefined,
      params.currentSecrets(),
    )

    if (findingRow && !isAlreadyVerified) {
      const mergedOrigins = [...new Set([...findingRow.sourceOrigins, ...specOrigins])]
      const { patch } = buildReplayFindingPatch(
        parsed, replay, findingRow.finding, finalStatus, verificationTier, 'inline replay', params.currentSecrets(),
      )
      const nextFindingPatch: Partial<Finding> = {
        ...patch,
        evidenceIds: [receipt.id],
        exchangeIds: replay.exchangeIds,
      }
      if (finalStatus === 'confirmed' || finalStatus === 'static_verified') {
        this.storage.upsertChainFinding(
          latestRun,
          findingRow.assetId,
          alignFindingForEvidence(
            { ...findingRow.finding, ...nextFindingPatch, replaySpecId: updatedSpec.id, scopeRevision: latestRun.scopeRevision },
            replay,
          ),
          updatedSpec.id,
          mergedOrigins,
        )
        recordReportedFindingCoverage(this.storage, latestRun, params.job.assignment.id, parsed.origin, parsed.category, `${finalStatus === 'static_verified' ? 'Static verified' : 'Confirmed'}: ${parsed.title}`, findingRow.id, (r, o) => this.host.permitted(r, o))
        // Multi-Trial Early Stopping: cancel sibling trials immediately on first Zero-LLM confirmation
        this.host.cancelSiblingTrialsOnConfirmation(latestRun, params.job.assignment.stepId, findingRow.id)
        const refreshedRow = this.storage.db.select().from(findings).where(and(
          eq(findings.runId, latestRun.id), eq(findings.id, findingRow.id),
        )).get()
        if (refreshedRow) this.host.scheduleVariantSweepForFinding(latestRun, refreshedRow)
      } else {
        this.storage.updateProposedFinding(latestRun, findingRow.id, {
          replaySpecId: updatedSpec.id,
          sourceOrigins: mergedOrigins,
          verificationTier: null,
          finding: nextFindingPatch,
        })
      }
    }

    // The persisted row is the single source of truth: a non-confirming attempt may have just
    // demoted an already-confirmed finding (finding.confirmation_conflict). Never report the
    // pre-attempt status in that case.
    const verdictRun = this.storage.run(params.job.assignment.runId)
    const verdictRow = this.host.resolveInlineVerdictRow(verdictRun.id, findingRow)
    const verdictStatus = verdictRow?.finding.status ?? finalStatus
    const verdictTier = verdictRow?.verificationTier ?? (verdictStatus === 'confirmed' ? verificationTier : undefined)
    this.host.postVerificationVerdict(verdictRun, {
      replaySpecId: updatedSpec.id,
      findingId: findingRow?.id ?? params.findingId ?? null,
      title: parsed.title,
      status: verdictStatus,
      verificationTier: verdictTier,
      feedback: normalizedFeedback,
      assignmentId: specRow.assignmentId ?? params.job.assignment.id,
      refStepId: params.job.assignment.stepId,
      attempt: updatedSpec.attemptCount,
    })
    return {
      findingId: findingRow?.id,
      replaySpecId: updatedSpec.id,
      attemptCount: updatedSpec.attemptCount,
      status: verdictStatus,
      verificationTier: verdictTier,
      feedback: normalizedFeedback,
      artifactId: receipt.id,
    }
  }


  async verifyBaselineJob(job: Active) {
    const run = this.host.check(job)
    const asset = run.candidates.find(c => c.id === job.assignment.assetId)
    if (!asset) {
      this.host.completeWorker(job.assignment, run, 'Host is no longer in run inventory.', [])
      return
    }
    const { analysis } = assessmentAssignments(this.storage.workerList(run.id), asset.id, run.goalRevision)
    const ready = analysis?.status === 'complete' ? analysis : undefined
    const selected: readonly AssessmentCheckId[] = run.reviewPlan?.status === 'ready' ? run.reviewPlan.checks : responseCheckIds
    const responseChecks = selected.filter(id => id !== 'access-policy') as ResponseCheckId[]
    const includesAccess = selected.includes('access-policy')

    const response: ReviewInput | undefined = responseChecks.length ? (() => {
      const stored = ready ? this.storage.assignmentObservation(ready.id) : undefined
      const record = stored ? JSON.parse(this.storage.artifact(run.id, stored.id).content) as Capture : undefined
      const origins = ready && record?.observation ? [...new Set([record.observation.origin, record.observation.finalOrigin, ...this.storage.brokerOrigins(ready)])] : []
      const authorized = origins.every(origin => this.host.permitted(run, origin))
      const observation = authorized ? record?.observation : null
      const note = authorized ? record?.note : 'The saved observation includes a host outside the current approval.'
      if (authorized) for (const origin of origins) job.origins.add(origin)
      return { artifactId: authorized ? stored?.id : undefined, reviews: responseReview(observation, note, responseChecks) }
    })() : undefined

    const access: ReviewInput | undefined = includesAccess ? (() => {
      const stored = ready ? this.storage.assignmentEvidence(ready.id, 'access-policy') : undefined
      const record = stored ? JSON.parse(this.storage.artifact(run.id, stored.id).content) as {
        origin: string; snapshot: AccessPolicySnapshot | null
      } : undefined
      const snapshot = record?.origin === asset.origin && record.snapshot?.origin === asset.origin ? record.snapshot : undefined
      return { artifactId: record?.origin === asset.origin ? stored?.id : undefined, reviews: accessPolicyReviews(snapshot), policy: snapshot }
    })() : undefined

    const inputs = [response, access].filter((i): i is ReviewInput => i !== undefined)
    const responseComparisons = response?.reviews.flatMap(r => r.comparison ? [r.comparison] : []) ?? []
    const accessComparisons = access?.reviews.flatMap(r => r.comparison ? [r.comparison] : []) ?? []
    const comparisons = [...responseComparisons, ...accessComparisons]
    const payload = { response: responseComparisons, access: access?.policy ?? null }
    const { reposDir } = this.host.projectReposMount(run.projectId)
    const result = comparisons.length ? await this.backend.run({
      assignmentId: job.assignment.id,
      files: [{ name: 'verification-input.json', content: JSON.stringify(payload) }],
      command: verificationCommand,
      outputs: ['verification.json'],
    }, job.controller.signal, reposDir ? { reposDir } : undefined) : undefined

    const outcomes = readComparisons(result?.exitCode === 0 ? result.outputs['verification.json'] : undefined, comparisons)
    const verified = inputs.flatMap(({ artifactId, reviews }) =>
      reviews.map(review => ({ artifactId, review, coverage: checkCoverage(review, outcomes) })))
    const checks = verified.map(item => item.coverage)
    const current = this.host.check(job)
    const assessed = checks.filter(check => check.status === 'met' || check.status === 'gap').length
    const gaps = checks.filter(check => check.status === 'gap').length
    const outcome = assessed
      ? `${assessed} checks verified · ${gaps === 1 ? '1 gap' : gaps + ' gaps'}`
      : 'Inconclusive: ' + (checks[0]?.reason ?? 'No checks evaluated.')

    this.storage.transaction(() => {
      const title = includesAccess ? (responseChecks.length ? 'Evidence verification' : 'Access policy verification') : 'Response policy verification'
      const ev = this.storage.addArtifact(current, job.assignment, 'verification', title,
        JSON.stringify({
          origin: asset.origin,
          inputEvidence: inputs.flatMap(i => i.artifactId ? [i.artifactId] : []),
          checks,
          comparisons,
          accessRecord: access?.artifactId,
          command: result ? verificationCommand : undefined,
          exitStatus: result?.exitCode,
          interpreter: result ? 'just-bash 3.6.1' : undefined,
        }, null, 2), 'verification')
      for (const { artifactId, review, coverage } of verified) {
        const links = artifactId ? [artifactId, ev.id] : [ev.id]
        const earlier = this.baselineFinding(current, asset, review)
        if (coverage.status === 'gap') this.saveBaselineFinding(current, asset, review, 'confirmed', coverage.reason, links, earlier?.id)
        else if (coverage.status === 'inconclusive' && (earlier || review.rule.id === 'hsts')) {
          this.saveBaselineFinding(current, asset, review, 'inconclusive', coverage.reason, links, earlier?.id)
        } else if (earlier) this.saveBaselineFinding(current, asset, review, 'dismissed', coverage.reason, links, earlier.id)
      }
      this.host.completeWorker(job.assignment, current, outcome, [ev.id], checks)
    }, { behavior: 'immediate' })
  }


  async runRetestJob(job: Active) {
    const run = this.host.check(job)
    const findingId = job.assignment.stepId
    if (!findingId) throw new Error('Retest worker missing finding reference.')
    const findingRow = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.id, findingId),
    )).get()
    if (!findingRow?.replaySpecId) throw new Error('Finding has no Declarative Replay Spec.')
    const specRow: ReplaySpecRow = this.storage.getReplaySpec(run.id, findingRow.replaySpecId)
    const permittedAtAdmission = this.host.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.host.buildGrant(job, run, permittedAtAdmission)

    await this.ensureCanaryListenerForSpec(specRow.spec)

    const { reposDir } = this.host.projectReposMount(run.projectId)
    const retestRes = await retestReplaySpec(this.baseReplayRunnerParams(
      specRow.spec, run.id, job.assignment.id, grant, job.controller.signal, reposDir,
      createExchangeRecorder(this.storage, () => run, job.assignment.id, currentSecrets),
    ))

    const current = this.storage.run(run.id)
    this.storage.transaction(() => {
      const secretsList = currentSecrets()
      const cleanObserved = redact(retestRes.replay.outcome.observed, secretsList)
      const ev = this.storage.addArtifact(current, job.assignment, 'replay',
        `Verify Fix retest · ${findingRow.finding.title}`,
        JSON.stringify({
          findingId,
          replaySpecId: specRow.id,
          verdict: retestRes.verdict,
          outcome: retestRes.replay.outcome,
          exchangeIds: retestRes.replay.exchangeIds,
          evidenceSha256: retestRes.replay.evidenceSha256,
        }, null, 2), 'retest:' + job.assignment.id, secretsList)
      const summary = `${retestRes.verdict}: ${cleanObserved}`
      this.storage.recordRetestRun(current, findingId, specRow.id, retestRes.verdict, summary, [ev.id], retestRes.replay.exchangeIds)
      this.host.completeWorker(job.assignment, current, `Verify Fix verdict: ${retestRes.verdict}`, [ev.id], undefined, secretsList)
      this.storage.message(current.id, current.coordinatorId, 'guardian',
        `Verify Fix retest for "${findingRow.finding.title}": ${retestRes.verdict}. ${cleanObserved}`, undefined, undefined, secretsList)
    }, { behavior: 'immediate' })
  }


  // --- Shared Helpers ---

  baselineFinding(run: Run, asset: Candidate, review: EvidenceReview) {
    return this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id), eq(findings.assetId, asset.id), eq(findings.goalRevision, run.goalRevision),
      eq(findings.checkId, review.rule.id), eq(findings.caseId, review.coverage.caseId ?? ''),
    )).get()
  }


  saveBaselineFinding(
    run: Run,
    asset: Candidate,
    review: EvidenceReview,
    status: Finding['status'],
    reason: string,
    evidenceIds: string[],
    existingId?: string,
  ) {
    const { rule, coverage } = review
    const confirmed = status === 'confirmed'
    const record: Finding = {
      id: existingId ?? randomUUID(),
      origin: asset.origin,
      title: status === 'inconclusive' ? rule.title + ' could not be assessed' : rule.findingTitle,
      status,
      severity: confirmed ? rule.severity : 'informational',
      reason,
      remediation: confirmed ? rule.remediation : status === 'inconclusive'
        ? 'Supply a current record from the approved host and repeat the review.'
        : status === 'pending' ? 'Resume the run to verify the observation.' : 'Review the verification evidence.',
      impact: confirmed ? rule.impact : undefined,
      recheck: confirmed ? rule.recheck : undefined,
      category: rule.category,
      cwe: rule.cwe,
      confidence: confirmed ? 'high' : status === 'inconclusive' ? 'low' : 'medium',
      verification: confirmed ? rule.verification : undefined,
      verificationTier: confirmed ? 'baseline_confirmed' : undefined,
      findingKind: 'baseline_check',
      check: { id: rule.id, caseId: coverage.caseId, expected: coverage.expected, observed: coverage.observed },
      evidenceIds,
      scopeRevision: run.scopeRevision,
    }
    const verificationClass = confirmed
      ? 'runtime_confirmed'
      : status === 'dismissed'
        ? 'dismissed'
        : status === 'inconclusive' || status === 'pending'
          ? 'open_proof_gap'
          : 'static_advisory'
    const persistedRecord = {
      ...record,
      provenance: 'agent_only',
      verificationStatus: verificationClass,
    } as typeof record
    if (existingId) {
      this.storage.db.update(findings).set({
        verificationTier: confirmed ? 'baseline_confirmed' : null,
        verificationClass,
        finding: persistedRecord,
      }).where(eq(findings.id, record.id)).run()
    } else {
      this.storage.db.insert(findings).values({
        id: record.id,
        runId: run.id,
        assetId: asset.id,
        goalRevision: run.goalRevision,
        checkId: rule.id,
        caseId: coverage.caseId ?? '',
        findingKind: 'baseline_check',
        replaySpecId: null,
        sourceOrigins: [asset.origin],
        verificationTier: confirmed ? 'baseline_confirmed' : null,
        provenance: 'agent_only',
        verificationClass,
        finding: persistedRecord,
      }).run()
    }
  }

}
