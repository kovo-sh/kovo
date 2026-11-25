import { createHash, randomUUID } from 'node:crypto'
import { diffResponse } from '../../worker/analyzers.ts'
import type { VerificationTier } from '../domain.ts'
import {
  declarativeReplaySpecSchema,
  floorRecipeEnvelopeSchema,
  replayAssertionOutcomeSchema,
  replaySpecOrigins,
} from '../replay-spec.ts'
import type { DeclarativeReplaySpec, FloorRecipeEnvelope, ReplayAssertionOutcome, ReplayStep } from '../replay-spec.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { personaSecrets } from './persona-vault.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import { openCanarySession } from './verify-support.ts'
import type { EphemeralCanarySession } from './verify-support.ts'
import type { Store } from './store.ts'
import type { WorkerBackend } from './worker-backend.ts'
import {
  actorFromPersona,
  assessBoundary,
  assessImpactEvidence,
  assessMassAssignmentImpact,
  assessMfaBypass,
  classifyBoundaryClaim,
  classifyImpactDescriptor,
} from './oracle-invariants.ts'
import type { PersonaCredentialSource } from './oracle-invariants.ts'
import { proofReceiptMode } from './proof-receipt.ts'
import type { ProofReceipt, ProofReceiptMode, ReceiptVerification } from './proof-receipt.ts'
import { persistedAgentScriptOf, retestPersistedAgentScript } from './agent-script-proof.ts'
import {
  assessBflaImpact,
  assessHttpChainEndpointBinding,
  assessHttpChainProofStrength,
  defaultRequireControlNonError,
  extractVariables,
  hasDestructiveContent,
  impactStepsFromStepsOut,
  inconclusiveResult,
  isSuccessStatus,
  isUnexpectedErrorStatus,
  receiptCheckForResult,
  retiredLegacyResult,
  RETIRED_LEGACY_SPEC_KINDS,
  routeKey,
  singleQuoteEscape,
  snapshotHttpChainSteps,
  stepToBrokerRequest,
  summarizeExchange,
} from './floor-recipe-engine.ts'
import {
  browserSessionSeam,
  retestPersistedRecipe,
  runAuthProtocolProofRecipe,
  runCacheDifferentialRecipe,
  runRceProofRecipe,
  runStaticAstProofRecipe,
} from './floor-recipe-engine.ts'
import { isProtocolBrowserSpec, wiredRecipeForSpecKind } from './floor-recipes.ts'

// Cut 3f: the legacy VM's assessment/receipt helpers moved to the recipe engine; re-exported here
// so tests and callers keep importing them from the verifier.
export {
  RETIRED_LEGACY_SPEC_KINDS,
  RETIRED_LEGACY_SPEC_REASON,
  applyReceiptGate,
  assessBflaImpact,
  assessHttpChainEndpointBinding,
  assessHttpChainProofStrength,
  buildReplayReceipt,
  classifyHttpChainAssertion,
  impactStepsFromStepsOut,
  inconclusiveResult,
} from './floor-recipe-engine.ts'
export { proofReceiptMode } from './proof-receipt.ts'
export type { ProofReceiptMode } from './proof-receipt.ts'
export type {
  BflaImpactAssessment,
  HttpChainAssertionEvidence,
  HttpChainDifferential,
  HttpChainEndpointBinding,
  HttpChainProofStrength,
} from './floor-recipe-engine.ts'

// Cut 3f: inline verification feedback lives in its own module; re-exported here.
export { buildInlineVerifyFeedback, verifyReplaySpecInline } from './replay-feedback.ts'
export type {
  EnrichedInlineVerifyFeedback,
  InlineExchangeHeaderSummary,
  InlineReplayVerificationResult,
  InlineStepBodyPreview,
  VerifyReplaySpecInlineParams,
} from './replay-feedback.ts'

// Cut 3f: agent-script proof execution lives in its own module; re-exported here so callers and
// tests keep importing it from the verifier.
export { persistedAgentScriptOf, retestPersistedAgentScript, runAgentScriptProof } from './agent-script-proof.ts'
export type { AgentScriptProofParams, AgentScriptProofResult } from './agent-script-proof.ts'

// Re-exported for tests and callers that only import the verifier.
export {
  awaitReplayCanary,
  defaultReplayCanaryImmediateMs,
  intersectStructuralDeltas,
  normalizeStructuralTokens,
  structuralDiff,
  structuralSimilarity,
} from './verify-support.ts'
export type { CanaryWaitOutcome, ReplayCanaryWaitOptions, StructuralDiff } from './verify-support.ts'

export type ReplayVerdict = 'confirmed' | 'static_verified' | 'dismissed' | 'inconclusive'
export type RetestVerdict = 'reproduced' | 'fixed' | 'inconclusive'

export interface VerifyReplaySpecParams {
  spec: DeclarativeReplaySpec | unknown
  broker: RequestBroker
  browser?: ScopedBrowser
  canaryBroker?: CanaryBroker
  backend: WorkerBackend
  /** Host path of the read-only repo mount; required for static_ast_proof. */
  reposDir?: string
  grant: Grant
  signal: AbortSignal
  storage?: Store
  runId?: string
  assignmentId?: string
  onExchange?: (exchange: BrokerExchangeResult) => string | void
}

export interface ReplayVerificationResult {
  verdict: ReplayVerdict
  /** 'runtime_confirmed' only for runtime-confirmed verdicts; 'static_verified' for static_ast_proof; never both. */
  verificationTier?: VerificationTier
  outcome: ReplayAssertionOutcome
  exchangeIds: string[]
  exchanges: BrokerExchangeResult[]
  evidencePayload: Record<string, unknown>
  evidenceSha256: string
  /**
   * ProofReceipt check over the host-recorded transcript. Present whenever the replay could be
   * expressed as a receipt (impact or out-of-band). `mode` defaults to `'strict'` (gating), or
   * `'shadow'` when explicitly opted in via `KOVO_PROOF_RECEIPT=shadow`; see `proofReceiptMode`.
   */
  receipt?: ReplayReceiptCheck
}

export interface ReplayReceiptCheck {
  receipt: ProofReceipt
  verification: ReceiptVerification
  mode: Exclude<ProofReceiptMode, 'off'>
}

export interface RetestReplayResult {
  verdict: RetestVerdict
  replay: ReplayVerificationResult
}

async function verifyReplaySpecInner(params: VerifyReplaySpecParams): Promise<ReplayVerificationResult> {
  const { broker, backend, grant, signal } = params
  const assignmentId = params.assignmentId ?? randomUUID()
  const exchanges: BrokerExchangeResult[] = []
  const exchangeIds: string[] = []
  const recordExchange = (ex: BrokerExchangeResult): string | null => {
    exchanges.push(ex)
    const id = params.onExchange?.(ex)
    if (typeof id === 'string' && id) {
      exchangeIds.push(id)
      return id
    }
    return null
  }

  // 1. Structural validation
  const parsed = declarativeReplaySpecSchema.safeParse(params.spec)
  if (!parsed.success) {
    return inconclusiveResult(`Invalid DeclarativeReplaySpec: ${parsed.error.issues[0]?.message ?? 'schema mismatch'}`, exchanges, exchangeIds, {})
  }
  const spec = parsed.data

  // 2. Policy & scope validation
  const isStatic = spec.kind === 'static_ast_proof'
  const origins = replaySpecOrigins(spec)
  for (const origin of origins) {
    if (!grant.canRead(origin)) {
      grant.audit('denied', origin)
      return inconclusiveResult(`Replay spec origin ${origin} is not in approved scope.`, exchanges, exchangeIds, { kind: spec.kind, origins })
    }
  }
  if (!isStatic && hasDestructiveContent(JSON.stringify(spec))) {
    grant.audit('denied', spec.origin)
    return inconclusiveResult('Replay spec rejected by Kovo Hunter destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
  }
  const tier = grant.tier ?? 1
  if (tier === 0 && !isStatic) {
    return inconclusiveResult('Live replay verification is disabled in Tier 0.', exchanges, exchangeIds, { kind: spec.kind })
  }

  // Floor-recipe dispatch runs BEFORE retired legacy VM rejection so recipe-backed specs
  // (e.g. `sql_boolean_diff`/`sql_time_diff` with a `boolean_or_timing` floorRecipe envelope)
  // verify cleanly through ProofReceipt while bare legacy VM specs fail closed below.
  const persistedRecipe = persistedRecipeOf(params.spec)
  if (persistedRecipe) {
    const result = await runPersistedFloorRecipe(persistedRecipe, params, spec.origin)
    return result.replay
  }

  if (RETIRED_LEGACY_SPEC_KINDS.has(spec.kind)) {
    return retiredLegacyResult(spec.kind, exchanges, exchangeIds)
  }

  // Cut 3e: non-http_chain legacy VMs are retired onto typed runners in floor-recipe-engine.ts.
  const runnerCtx = {
    broker,
    canaryBroker: params.canaryBroker,
    backend,
    reposDir: params.reposDir,
    grant,
    signal,
    storage: params.storage,
    runId: params.runId,
    assignmentId,
    onExchange: params.onExchange,
  }
  if (spec.kind === 'static_ast_proof') return runStaticAstProofRecipe(spec, runnerCtx)
  if (spec.kind === 'rce_proof') return runRceProofRecipe(spec, runnerCtx)
  if (spec.kind === 'cache_differential') return runCacheDifferentialRecipe(spec, runnerCtx)
  if (spec.kind === 'auth_protocol_proof') return runAuthProtocolProofRecipe(spec, runnerCtx)

  const guardControlErrors = spec.requireControlNonError ?? defaultRequireControlNonError(spec)
  // Persona credential context for the shared impact validators (role label, tenant, ambient auth
  // and session-cookie SameSite). Built from the approved persona vault only; never from the spec.
  const personaSources: PersonaCredentialSource[] = [...(grant.personas?.values() ?? [])].map(persona => ({
    handle: persona.handle,
    roleLabel: persona.roleLabel,
    authKind: persona.authKind,
    headerType: persona.session?.headerType ?? null,
    cookies: (persona.session?.bundle?.cookies ?? []).map(cookie => ({ name: cookie.name, sameSite: cookie.sameSite ?? null })),
  }))
  const declaredActorRoles = spec.kind === 'http_chain' ? spec.actorRoles : undefined

  // 3. Fresh Replay Execution
  let evidencePayload: Record<string, unknown> = {
    kind: spec.kind,
    origin: spec.origin,
    replayedAt: new Date().toISOString(),
  }
  let forcedInconclusiveReason: string | null = null
  // Proof-strength / endpoint-binding failures are recorded separately: they only veto a spec that
  // WOULD confirm. A spec that already evaluates to confirmed=false must keep its dismissed/fixed
  // semantics (e.g. "Verify Fix" after a patch), so the guard never runs ahead of the assertion.
  let proofGuardFailure: string | null = null
  let deterministicProofPassed = true
  let proofFailureReason = ''

  try {
    if (spec.kind === 'http_chain') {
      const vars: Record<string, string> = {}
      const stepsOut: Record<string, unknown> = {}
      const probeStepExchanges: Array<{ id: string; exchange: BrokerExchangeResult }> = []
      // Mechanical endpoint binding: track the exact request that was sent per step (post-interpolation)
      // and every exchange it produced, then bind the finding to the wire evidence afterwards.
      const stepRequests = new Map<string, BrokerHttpRequest[]>()
      const stepExchanges = new Map<string, BrokerExchangeResult[]>()
      const rememberStep = (stepId: string, requests: BrokerHttpRequest[], produced: BrokerExchangeResult[]) => {
        stepRequests.set(stepId, requests)
        stepExchanges.set(stepId, produced)
      }
      const replayJarPrefix = randomUUID().slice(0, 8)
      let firstControlStep: Record<string, unknown> | undefined
      let firstProbeStep: Record<string, unknown> | undefined

      const actorContextFor = (step: ReplayStep): Record<string, unknown> => {
        const actor = actorFromPersona(step.request.persona ?? null, personaSources, { roles: declaredActorRoles ?? null })
        if (!actor.handle) return {}
        return {
          ...(actor.role ? { actorRole: actor.role } : {}),
          ...(actor.tenant ? { actorTenant: actor.tenant } : {}),
          ...(actor.auth !== 'unknown' ? { ambientAuth: actor.auth } : {}),
          ...(actor.sameSite ? { sessionSameSite: actor.sameSite } : {}),
        }
      }

      const serializedSteps = JSON.stringify(spec.steps)
      const needsCanary = /\{\{canary_(?:url|token|dns_host)\}\}/.test(serializedSteps) ||
        spec.steps.some(s => s.request.authMutation?.kind === 'jku_x5u_canary')
      let canarySession: EphemeralCanarySession | undefined
      let ctrlCanary: { url: string; token: string; dnsHost: string } | undefined
      let prbCanary: { url: string; token: string; dnsHost: string } | undefined
      if (needsCanary) {
        canarySession = await openCanarySession(params.canaryBroker, params.storage, params.runId, assignmentId, spec.origin)
        ctrlCanary = canarySession.mint(`http_chain:control:${spec.title}`)
        prbCanary = canarySession.mint(`http_chain:probe:${spec.title}`)
      }

      try {
        for (const step of spec.steps) {
          signal.throwIfAborted()
          const stepVars: Record<string, string> = { ...vars }
          if (ctrlCanary && prbCanary) {
            const activeCanary = step.role === 'control' ? ctrlCanary : prbCanary
            stepVars.canary_url = activeCanary.url
            stepVars.canary_token = activeCanary.token
            stepVars.canary_dns_host = activeCanary.dnsHost
          }
          const brokerReq = stepToBrokerRequest(step, stepVars, {
            replayJarPrefix,
            runId: params.runId,
            assignmentId,
          })
          if (brokerReq.authMutation?.kind === 'jku_x5u_canary' && !brokerReq.authMutation.url && !brokerReq.authMutation.value && ctrlCanary && prbCanary) {
            brokerReq.authMutation = {
              ...brokerReq.authMutation,
              url: step.role === 'control' ? ctrlCanary.url : prbCanary.url,
            }
          }
          if (step.request.batchCount) {
            const batchReqs = Array.from({ length: step.request.batchCount }, () => ({ ...brokerReq }))
            const batchResults = await broker.executeBatch(batchReqs, grant, signal)
            const batchExchangeIds = batchResults.map(ex => recordExchange(ex)).filter((id): id is string => Boolean(id))
            rememberStep(step.id, batchReqs, batchResults)
            const first = batchResults[0]
            if (first) extractVariables(step, first, vars)
            const stepEntry: Record<string, unknown> = {
              id: step.id,
              role: step.role,
              batchCount: batchResults.length,
              statuses: batchResults.map(r => r.status),
              responses: batchResults.map(summarizeExchange),
              ...(batchExchangeIds.length ? { exchangeIds: batchExchangeIds } : {}),
              ...(batchExchangeIds[0] ? { exchangeId: batchExchangeIds[0] } : {}),
              ...(first ? summarizeExchange(first) : {}),
              ...actorContextFor(step),
            }
            stepsOut[step.id] = stepEntry
            if (step.role === 'control' && !firstControlStep) firstControlStep = stepEntry
            if (step.role === 'probe') {
              if (!firstProbeStep) firstProbeStep = stepEntry
              if (first) probeStepExchanges.push({ id: step.id, exchange: first })
            }
          } else {
            const ex = await broker.executeHttp(brokerReq, grant, signal)
            const exchangeId = recordExchange(ex)
            rememberStep(step.id, [brokerReq], [ex])
            extractVariables(step, ex, vars)
            const stepEntry: Record<string, unknown> = {
              id: step.id,
              role: step.role,
              ...(exchangeId ? { exchangeId } : {}),
              ...summarizeExchange(ex),
              ...actorContextFor(step),
            }
            stepsOut[step.id] = stepEntry
            if (step.role === 'control' && !firstControlStep) firstControlStep = stepEntry
            if (step.role === 'probe') {
              if (!firstProbeStep) firstProbeStep = stepEntry
              probeStepExchanges.push({ id: step.id, exchange: ex })
            }
          }
        }

        if (guardControlErrors) {
          for (const step of spec.steps) {
            if (step.role !== 'control' && step.role !== 'probe') continue
            const status = (stepsOut[step.id] as { status?: number } | undefined)?.status
            if (typeof status === 'number' && isUnexpectedErrorStatus(status, step.expectedStatus, spec.expectedStatus)) {
              // A control that is *supposed* to be denied (a cross-tenant boundary probe) is proof
              // of the boundary, not a spec error. Dropping it would leave the chain with only the
              // weaker arm, so it is tolerated when declared or when the probe arm on the same route
              // succeeded.
              if (step.role === 'control' && (status === 401 || status === 403 || status === 404)) {
                const probeSucceededOnRoute = spec.steps.some(other =>
                  other.role === 'probe' &&
                  routeKey(other.request.pathAndQuery) === routeKey(step.request.pathAndQuery) &&
                  isSuccessStatus(((stepsOut[other.id] as { status?: number } | undefined)?.status) ?? null))
                if (spec.expectControlDenied || probeSucceededOnRoute) continue
              }
              // On probe steps, allow error status if assertionsJq explicitly asserts that error status
              // (e.g. error-based SQLi testing `.steps.p1.status == 500` while control step is 200).
              if (step.role === 'probe') {
                const statusAssertedInJq =
                  new RegExp(`status\\s*==\\s*${status}\\b|\\b${status}\\s*==\\s*[^;]*status`).test(spec.assertionsJq) ||
                  (status >= 500 && /status\s*>=\s*500\b/.test(spec.assertionsJq))
                if (statusAssertedInJq) continue
              }
              forcedInconclusiveReason = `Unexpected HTTP ${status} on ${step.role} step "${step.id}" (requireControlNonError); declare expectedStatus ${status} to test error behavior.`
              break
            }
          }
        }

        let canaryEvidence: Record<string, unknown> | undefined
        if (canarySession && prbCanary && ctrlCanary) {
          // Two-stage async correlation: durable pending_oob subscription, short immediate check,
          // then promoteLate/awaitAny up to the run deadline so worker callbacks still confirm.
          const probeWait = await canarySession.waitForCallback(prbCanary.token, signal)
          const controlCheck = canarySession.check(ctrlCanary.token)
          canaryEvidence = {
            proof: {
              canaryProbeTriggered: probeWait.triggered,
              canaryProbeStage: probeWait.stage,
              canaryProbePromoted: probeWait.promoted,
              ...(probeWait.subscriptionId ? { canarySubscriptionId: probeWait.subscriptionId } : {}),
              canaryControlTriggered: controlCheck.triggered,
              canaryProbeDetail: probeWait.detail,
              canaryControlDetail: controlCheck.detail,
            },
            canary: {
              triggered: probeWait.triggered && !controlCheck.triggered,
              probeTriggered: probeWait.triggered,
              controlTriggered: controlCheck.triggered,
              probeDetail: probeWait.detail,
              controlDetail: controlCheck.detail,
            },
          }
        }

        let spaCatchall: Record<string, unknown> | undefined
        if (spec.spaCatchallControl) {
          const catchallPath = `/.kovo-nonexistent-${randomUUID()}`
          const catchallEx = await broker.executeHttp({
            origin: spec.origin,
            method: 'GET',
            pathAndQuery: catchallPath,
            followRedirects: true,
          }, grant, signal)
          recordExchange(catchallEx)

          const comparisons: Record<string, Record<string, unknown>> = {}
          let allProbesMatchedCatchall = probeStepExchanges.length > 0
          for (const probe of probeStepExchanges) {
            const diff = diffResponse(
              { status: catchallEx.status, body: catchallEx.body, mediaType: catchallEx.mediaType },
              { status: probe.exchange.status, body: probe.exchange.body, mediaType: probe.exchange.mediaType },
            )
            comparisons[probe.id] = diff
            if (!diff.likelySpaCatchall) allProbesMatchedCatchall = false
          }
          spaCatchall = {
            path: catchallPath,
            ...summarizeExchange(catchallEx),
            comparisons,
            allProbesMatchedCatchall,
          }
          if (allProbesMatchedCatchall) {
            forcedInconclusiveReason = 'Probe response is structurally indistinguishable from an HTTP 200 SPA catch-all route.'
          }
        }

        // Auto catch-all baseline: when the spec does not opt in to spaCatchallControl, a 2xx HTML
        // probe is still compared against a fresh unmatched-path baseline. If the probe is
        // indistinguishable from the catch-all, the claim is not tied to a real endpoint and the
        // verifier requires the explicit control (`spaCatchallControl: true`) to re-verify.
        let spaCatchallAuto: Record<string, unknown> | undefined
        if (!spec.spaCatchallControl) {
          const htmlProbes = probeStepExchanges.filter(probe =>
            probe.exchange.status >= 200 && probe.exchange.status < 300 && probe.exchange.mediaType.includes('html'))
          if (htmlProbes.length > 0) {
            const catchallPath = `/.kovo-nonexistent-${randomUUID()}`
            const catchallEx = await broker.executeHttp({
              origin: spec.origin,
              method: 'GET',
              pathAndQuery: catchallPath,
              followRedirects: true,
            }, grant, signal)
            recordExchange(catchallEx)
            const comparisons: Record<string, Record<string, unknown>> = {}
            let matchedProbes = 0
            for (const probe of htmlProbes) {
              const diff = diffResponse(
                { status: catchallEx.status, body: catchallEx.body, mediaType: catchallEx.mediaType },
                { status: probe.exchange.status, body: probe.exchange.body, mediaType: probe.exchange.mediaType },
              )
              comparisons[probe.id] = diff
              if (diff.likelySpaCatchall) matchedProbes += 1
            }
            spaCatchallAuto = {
              path: catchallPath,
              requiresControl: true,
              probeCount: htmlProbes.length,
              matchedProbes,
              ...summarizeExchange(catchallEx),
              comparisons,
            }
            if (matchedProbes === htmlProbes.length && !proofGuardFailure) {
              proofGuardFailure = 'Probe response is structurally indistinguishable from an HTTP 200 SPA catch-all route; set spaCatchallControl: true to verify against a real endpoint baseline.'
            }
          }
        }

        const bflaImpact = assessBflaImpact(spec, stepsOut)
        const stepSnapshots = snapshotHttpChainSteps(spec, stepsOut, stepExchanges)
        const proofStrength = assessHttpChainProofStrength(spec, stepSnapshots)
        const endpointBinding = assessHttpChainEndpointBinding(spec, stepRequests, stepExchanges)
        if (proofStrength.claim === 'authorization' && !proofStrength.satisfied && !proofGuardFailure) {
          proofGuardFailure = proofStrength.reason
        }
        if (!endpointBinding.bound && !proofGuardFailure) {
          proofGuardFailure = endpointBinding.reason
        }
        // Shared semantic impact gate for every class the differential machinery can over-claim:
        // horizontal authorization (read disclosure / persisted cross-tenant write), mass assignment,
        // CSRF, business-logic/workflow, markup/scripting and disclosure. Vertical BFLA is covered by
        // `assessBflaImpact` above (same validators). Unmodelled classes ('other') stay ungated; every
        // class the gate understands is gated regardless of actor count, so a single anonymous actor
        // cannot bypass the authorization read-disclosure check.
        const declaredImpactClass = classifyImpactDescriptor({
          cwe: spec.cwe,
          category: spec.category,
          title: spec.title,
          impact: spec.impact,
        })
        const impactSteps = impactStepsFromStepsOut(spec, stepsOut)
        // Evidence-first class: if the probe persisted a protected field from the request body, the
        // proof *is* mass assignment no matter how the model labelled it (the common K=6 case is a
        // `tenant_id` overpost reported as BOLA). This both gates and labels on what happened.
        const massAssignmentEvidence = declaredImpactClass === 'mass_assignment'
          ? null
          : assessMassAssignmentImpact({
              impactClass: 'mass_assignment',
              steps: impactSteps,
              oracleEvents: spec.expectedImpactEvents,
              targetOrigin: spec.origin,
            })
        const impactClass = massAssignmentEvidence?.required && massAssignmentEvidence.satisfied
          ? 'mass_assignment' as const
          : declaredImpactClass
        // Cross-tenant evidence is object-level authorization when the *probe* actor sits outside
        // the tenant that successfully read the same route (a victim control). A victim readback
        // after a mass-assignment write is not a cross-tenant probe.
        const probeStep = impactSteps.find(step => step.arm === 'probe') ?? null
        const controlReadTenants = new Set<string>()
        for (const step of impactSteps) {
          if (step.arm !== 'control') continue
          if (!/^(?:GET|HEAD|OPTIONS)$/i.test(step.method ?? '')) continue
          if (step.status === null || step.status < 200 || step.status >= 300) continue
          if (!probeStep || step.route !== probeStep.route) continue
          if (step.actor.tenant) controlReadTenants.add(step.actor.tenant)
        }
        const crossTenantEvidence = Boolean(probeStep?.actor.tenant && controlReadTenants.size > 0 &&
          !controlReadTenants.has(probeStep.actor.tenant))
        const evidenceClassLabel = crossTenantEvidence && (impactClass === 'authorization' || impactClass === 'business_logic')
          ? 'bola'
          : impactClass
        // A control arm that binds a CSRF token is the engine's declared anti-CSRF defence for the
        // route, equivalent to the route's `csrf_state_change` oracle. It is a requirement, not
        // evidence: the persisted readback is still demanded below.
        const declaredImpactEvents = spec.expectedImpactEvents ?? []
        const csrfModelled = impactClass === 'csrf' && spec.steps.some(step => Boolean(step.request.csrfBind))
        const oracleEvents = csrfModelled && !declaredImpactEvents.includes('csrf_state_change')
          ? [...declaredImpactEvents, 'csrf_state_change']
          : declaredImpactEvents
        const distinctActors = new Set(spec.steps.map(step => step.request.persona ?? step.request.session ?? 'anonymous'))
        const gateApplies = impactClass === 'mass_assignment' || impactClass === 'csrf' ||
          impactClass === 'business_logic' || impactClass === 'markup' || impactClass === 'disclosure' ||
          impactClass === 'injection' ||
          (impactClass === 'authorization' && (distinctActors.size > 1 || Boolean(spec.requiredRole) || Boolean(spec.resourceTenant)))
        const impactGate = !gateApplies
          ? null
          : assessImpactEvidence({
              impactClass,
              steps: impactSteps,
              requiredRole: spec.requiredRole ?? null,
              resourceTenant: spec.resourceTenant ?? null,
              expectControlDenied: spec.expectControlDenied,
              oracleEvents,
              targetOrigin: spec.origin,
              credentialPatterns: spec.proofPatterns ?? null,
            })
        // Universal default-deny boundary gate: auth/bypass claims always need a challenged control
        // (401/403, login redirect, MFA challenge, negative id) plus a crossing variant; access
        // claims may fall back to an explicit actor/precondition differential.
        const boundaryClass = classifyBoundaryClaim({
          cwe: spec.cwe,
          category: spec.category,
          title: spec.title,
          impact: spec.impact,
        })
        const boundaryGate = boundaryClass === 'other'
          ? null
          : boundaryClass === 'mfa'
            ? assessMfaBypass({
                impactClass,
                steps: impactSteps,
                requiredRole: spec.requiredRole ?? null,
                resourceTenant: spec.resourceTenant ?? null,
                oracleEvents,
                targetOrigin: spec.origin,
              })
            : assessBoundary({
                impactClass,
                steps: impactSteps,
                requiredRole: spec.requiredRole ?? null,
                resourceTenant: spec.resourceTenant ?? null,
                expectControlDenied: spec.expectControlDenied,
                oracleEvents,
                targetOrigin: spec.origin,
                boundaryClass,
              })
        if (impactGate?.required && !impactGate.satisfied && !proofGuardFailure) {
          proofGuardFailure = impactGate.reason
        }
        let proofMatches: Record<string, boolean[]> | undefined
        if (spec.proofPatterns?.length) {
          proofMatches = {}
          for (const [id, entry] of Object.entries(stepsOut)) {
            const body = entry && typeof entry === 'object' && typeof (entry as { body?: unknown }).body === 'string'
              ? (entry as { body: string }).body
              : ''
            proofMatches[id] = spec.proofPatterns.map(pattern => {
              // Harden the in-process matcher against pathological regexes: bounded length (schema),
              // no nested quantifiers, and only the first 16 KiB of the body.
              if (/\((?:\?:)?[^)]*[+*][^)]*\)[+*?]/.test(pattern)) return false
              try {
                return new RegExp(pattern).test(body.slice(0, 16 * 1024))
              } catch {
                return false
              }
            })
          }
        }
        evidencePayload = {
          ...evidencePayload,
          steps: stepsOut,
          ...(firstControlStep ? { control: firstControlStep } : {}),
          ...(firstProbeStep ? { probe: firstProbeStep } : {}),
          extractedVars: vars,
          ...(proofMatches ? { proofMatches } : {}),
          ...(canaryEvidence ?? {}),
          ...(spaCatchall ? { spaCatchall } : {}),
          ...(spaCatchallAuto ? { spaCatchallAuto } : {}),
          bflaImpact,
          ...(impactGate ? { impactGate } : {}),
          // Verified evidence class: lets the host align a mislabelled finding (e.g. a tenant_id
          // overpost reported as BOLA is mass assignment) with what the proof actually showed.
          ...(impactGate?.required && impactGate.satisfied ? { evidenceClass: evidenceClassLabel } : {}),
          ...(boundaryGate ? { boundaryGate } : {}),
          proofStrength,
          endpointBinding,
        }
        if (bflaImpact.required && !bflaImpact.satisfied && !forcedInconclusiveReason) {
          forcedInconclusiveReason = bflaImpact.reason
        }
        if (impactGate?.required && !impactGate.satisfied && !proofGuardFailure) {
          // Vetoes only a would-be confirmation; a spec whose assertion already fails keeps its
          // dismissed/fixed semantics (Verify Fix must still report `fixed`).
          proofGuardFailure = impactGate.reason
        }
        if (boundaryGate?.required && !boundaryGate.satisfied && !proofGuardFailure) {
          proofGuardFailure = boundaryGate.reason
        }
      } finally {
        await canarySession?.close()
      }
    }
  } catch (err) {
    const catchSecrets: NamedSecret[] = [
      ...(params.grant.secrets ?? []),
      ...(params.grant.personas ? personaSecrets(params.grant.personas) : []),
      ...(broker.getRegisteredSecrets?.() ?? []),
    ]
    const safePayload = redactJsonValue(evidencePayload, catchSecrets)
    if (err instanceof BrokerDenied || err instanceof BrokerCircuitOpen || err instanceof BrokerApprovalRequired) {
      return inconclusiveResult(redact(err.message, catchSecrets), exchanges, exchangeIds, safePayload)
    }
    const message = redact(err instanceof Error ? err.message : String(err), catchSecrets)
    return inconclusiveResult(`Replay execution failed: ${message}`, exchanges, exchangeIds, safePayload)
  }

  // Scrub any dynamic broker-registered secrets (jar cookies, CSRF tokens, mutated JWTs) + grant/persona secrets
  const dynamicSecrets: NamedSecret[] = [
    ...(params.grant.secrets ?? []),
    ...(params.grant.personas ? personaSecrets(params.grant.personas) : []),
    ...(broker.getRegisteredSecrets?.() ?? []),
  ]
  evidencePayload = redactJsonValue(evidencePayload, dynamicSecrets)

  // 4. Air-Gapped Assertion Evaluation via one-shot --network none just-bash worker
  const serializedPayload = JSON.stringify(evidencePayload, null, 2)
  const evidenceSha256 = createHash('sha256').update(serializedPayload).digest('hex')
  const jqCommand = `jq '${singleQuoteEscape(spec.assertionsJq)}' /evidence/replay-results.json > /work/outcome.json`

  let workerResult
  try {
    workerResult = await backend.run({
      assignmentId,
      files: [{ name: 'replay-results.json', content: serializedPayload }],
      command: jqCommand,
      outputs: ['outcome.json'],
      timeoutMs: 30_000,
    }, signal)
  } catch (err) {
    return inconclusiveResult(
      `Verification container failed: ${redact(err instanceof Error ? err.message : String(err), dynamicSecrets)}`,
      exchanges,
      exchangeIds,
      evidencePayload,
    )
  }

  const rawOutcome = (workerResult.outputs['outcome.json'] || workerResult.stdout || '').trim()
  if (workerResult.exitCode !== 0 || !rawOutcome) {
    return inconclusiveResult(
      `Replay jq assertion failed (exit ${workerResult.exitCode}): ${workerResult.stderr.slice(0, 400)}`,
      exchanges,
      exchangeIds,
      evidencePayload,
    )
  }

  let parsedJson: unknown
  try {
    parsedJson = JSON.parse(rawOutcome)
  } catch {
    return inconclusiveResult('Replay jq assertion did not emit valid JSON.', exchanges, exchangeIds, evidencePayload)
  }

  // Coerce structured observed/expected/reason fields to bounded strings while keeping confirmed/controlPassed strictly boolean.
  const coerceOutcomeText = (value: unknown): string => {
    if (typeof value === 'string') return value.slice(0, 1200)
    try {
      return (JSON.stringify(value) ?? String(value)).slice(0, 1200)
    } catch {
      return String(value).slice(0, 1200)
    }
  }
  if (parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)) {
    const obj = { ...(parsedJson as Record<string, unknown>) }
    if ('observed' in obj && obj.observed !== undefined) obj.observed = coerceOutcomeText(obj.observed)
    if ('expected' in obj && obj.expected !== undefined) obj.expected = coerceOutcomeText(obj.expected)
    if ('reason' in obj) {
      if (obj.reason === undefined || obj.reason === null) delete obj.reason
      else obj.reason = coerceOutcomeText(obj.reason)
    }
    parsedJson = obj
  }

  const validatedOutcome = replayAssertionOutcomeSchema.safeParse(parsedJson)
  if (!validatedOutcome.success) {
    return inconclusiveResult(
      `Replay assertion output violated schema: ${validatedOutcome.error.issues[0]?.message ?? 'invalid shape'}`,
      exchanges,
      exchangeIds,
      evidencePayload,
    )
  }

  const outcome = validatedOutcome.data

  // 5. Verdict Promotion (enforcing deterministic anti-false-positive guards)
  if (forcedInconclusiveReason) {
    return {
      verdict: 'inconclusive',
      outcome: {
        ...outcome,
        confirmed: false,
        controlPassed: false,
        reason: forcedInconclusiveReason,
      },
      exchangeIds,
      exchanges,
      evidencePayload,
      evidenceSha256,
    }
  }

  if (proofGuardFailure && outcome.controlPassed && outcome.confirmed) {
    return {
      verdict: 'inconclusive',
      outcome: {
        ...outcome,
        confirmed: false,
        reason: proofGuardFailure,
      },
      exchangeIds,
      exchanges,
      evidencePayload,
      evidenceSha256,
    }
  }

  if (!deterministicProofPassed) {
    return {
      verdict: outcome.controlPassed ? 'dismissed' : 'inconclusive',
      outcome: {
        ...outcome,
        confirmed: false,
        reason: proofFailureReason || 'Cryptographic non-destructive proof-of-execution check did not pass (possible reflection or unexecuted payload).',
      },
      exchangeIds,
      exchanges,
      evidencePayload,
      evidenceSha256,
    }
  }

  let verdict: ReplayVerdict
  if (outcome.controlPassed && outcome.confirmed) {
    verdict = 'confirmed'
  } else if (outcome.controlPassed && !outcome.confirmed) {
    verdict = 'dismissed'
  } else {
    verdict = 'inconclusive'
  }

  // ProofReceipt confirmation gate: strict by default (vetoes unsubstantiated DSL confirmations,
  // never widens a non-confirming verdict); KOVO_PROOF_RECEIPT=shadow|off overrides for tests.
  const gated = receiptCheckForResult({
    mode: proofReceiptMode(),
    verdict,
    outcome,
    spec,
    evidencePayload,
    exchangeIds,
    exchanges,
  })

  return {
    verdict: gated.verdict,
    outcome: gated.outcome,
    exchangeIds,
    exchanges,
    evidencePayload,
    evidenceSha256,
    ...(gated.check ? { receipt: gated.check } : {}),
  }
}

export async function verifyReplaySpec(params: VerifyReplaySpecParams): Promise<ReplayVerificationResult> {
  const result = await verifyReplaySpecInner(params)
  return withVerificationTier(result)
}

/** Cut 3 no-fallback invariant at the product floor boundary. */
export class RecipeWiredLegacyCallError extends Error {
  readonly code = 'KOVO_RECIPE_WIRED_LEGACY_CALL'
  readonly specKind: string
  readonly vulnClass: string

  constructor(specKind: string, vulnClass: string) {
    super(`verifyReplaySpec() received a recipe-wired spec kind ${specKind}/${vulnClass}; the floor must confirm it through its ProofReceipt recipe, not the legacy DSL verifier.`)
    this.name = 'RecipeWiredLegacyCallError'
    this.specKind = specKind
    this.vulnClass = vulnClass
  }
}

/** The class a spec claims, in the vocabulary the recipe table uses. */
function recipeClassOfSpec(spec: DeclarativeReplaySpec): string | null {
  switch (spec.kind) {
    case 'sql_boolean_diff':
    case 'sql_time_diff':
      return 'sqli'
    case 'race_burst':
      return 'race_double_spend'
    case 'http_chain':
      return typeof spec.category === 'string' ? spec.category : null
    default:
      return null
  }
}

/** Throw (and warn) when a wired pair would be routed to the legacy verifier. */
export function assertNotRecipeWiredLegacyCall(spec: DeclarativeReplaySpec | unknown): void {
  if (!spec || typeof spec !== 'object') return
  const kind = (spec as { kind?: unknown }).kind
  if (typeof kind !== 'string') return
  // Only navigate/fill/click DOM-sink proofs are wired to `browser_sink`. A protocol browser proof
  // (postMessage/fetch/builtin) legitimately stays on the framework verifier and must not trip the
  // no-fallback guard.
  if (kind === 'browser_chain') {
    const steps = (spec as { steps?: unknown }).steps
    if (Array.isArray(steps) && isProtocolBrowserSpec(steps as Array<Record<string, unknown>>)) return
  }
  const vulnClass = recipeClassOfSpec(spec as DeclarativeReplaySpec)
  const recipe = vulnClass ? wiredRecipeForSpecKind(kind, vulnClass) : null
  if (!recipe) return
  const error = new RecipeWiredLegacyCallError(kind, vulnClass ?? 'unknown')
  process.emitWarning(error.message, { code: error.code })
  throw error
}

function withVerificationTier(result: ReplayVerificationResult): ReplayVerificationResult {
  const verificationTier: VerificationTier | undefined = result.verdict === 'static_verified'
    ? 'static_verified'
    : result.verdict === 'confirmed' ? 'runtime_confirmed' : undefined
  return { ...result, ...(verificationTier ? { verificationTier } : {}) }
}

async function runPersistedFloorRecipe(
  persisted: NonNullable<ReturnType<typeof persistedRecipeOf>>,
  params: VerifyReplaySpecParams,
  originFallback?: string,
) {
  const args = persisted.envelope.args as { vulnClass?: unknown; pathAndQuery?: unknown }
  const origin = persisted.origin || originFallback || ''
  return retestPersistedRecipe({
    envelope: persisted.envelope,
    specKind: persisted.kind,
    vulnClass: typeof args.vulnClass === 'string' && args.vulnClass ? args.vulnClass : persisted.kind,
    endpoint: typeof args.pathAndQuery === 'string' ? args.pathAndQuery : origin,
    origin,
    broker: params.broker,
    grant: params.grant,
    signal: params.signal,
    ...(params.runId ? { runId: params.runId } : {}),
    ...(params.assignmentId ? { assignmentId: params.assignmentId } : {}),
    ...(params.onExchange ? { recordExchange: (exchange: BrokerExchangeResult) => params.onExchange?.(exchange) } : {}),
    // Browser recipes run through the same scoped browser the framework verifier uses; the trace
    // returned to the receipt is host-recorded and only counts a canary that reached a sink.
    browserSession: browserSessionSeam({
      browser: params.browser ?? new ScopedBrowser(params.broker),
      grant: params.grant,
      signal: params.signal,
      origin,
      ...(params.runId ? { runId: params.runId } : {}),
      ...(params.assignmentId ? { assignmentId: params.assignmentId } : {}),
      ...(params.onExchange ? { recordExchange: (exchange: BrokerExchangeResult) => params.onExchange?.(exchange) } : {}),
    }),
  })
}

export async function retestReplaySpec(params: VerifyReplaySpecParams): Promise<RetestReplayResult> {
  // Cut 3 retest receipts: a spec confirmed by a typed floor recipe carries that recipe, so retest
  // re-runs the recipe and validates a fresh ProofReceipt.
  const persisted = persistedRecipeOf(params.spec)
  if (persisted) {
    const result = await runPersistedFloorRecipe(persisted, params)
    return { verdict: result.verdict, replay: result.replay }
  }
  // v7 M5 agent script proofs: the persisted row carries the Layer-3 script, so retest re-runs that
  // script through the same fresh-session double-run and re-validates a fresh receipt. The
  // declarative shape on the row is attribution only and is never re-interpreted.
  const agentScript = persistedAgentScriptOf(params.spec)
  if (agentScript) {
    return retestPersistedAgentScript(agentScript.envelope, { ...params, origin: agentScript.origin } as VerifyReplaySpecParams & { origin?: string })
  }
  // Retest is a regression replay of an already-persisted proof (reproduced vs fixed), not a new
  // confirmation, so it re-evaluates the recorded spec through the same replay used today.
  const replay = await verifyReplaySpec(params)
  const verdict: RetestVerdict = replay.verdict === 'confirmed' || replay.verdict === 'static_verified'
    ? 'reproduced'
    : replay.verdict === 'dismissed'
      ? 'fixed'
      : 'inconclusive'
  return { verdict, replay }
}

/** Read the persisted agent-script envelope from a (not-yet-validated) spec. */
/** Read the persisted recipe envelope from a (not-yet-validated) spec. */
function persistedRecipeOf(spec: unknown): { envelope: FloorRecipeEnvelope; kind: string; origin: string } | null {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return null
  const record = spec as Record<string, unknown>
  const parsed = floorRecipeEnvelopeSchema.safeParse(record.recipe)
  if (!parsed.success) return null
  return {
    envelope: parsed.data,
    kind: typeof record.kind === 'string' ? record.kind : parsed.data.recipeId,
    origin: typeof record.origin === 'string' ? record.origin : '',
  }
}

