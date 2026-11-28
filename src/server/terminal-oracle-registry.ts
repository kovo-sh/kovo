/**
 * TerminalOracleRegistry — Unified Typed Oracle Registry (Option 2, Move 1).
 *
 * Single host-side verification boundary taking `(factLog: HostFactLog, pointerRef, policyContext)`
 * that registers and dispatches BOTH:
 *   1. All 6 v8 multi-hop extended oracle families (delegating cleanly to `v8-oracle-families.ts`
 *      after host-only hydration via `v8-oracle-hydrate.ts`), AND
 *   2. All single-hop `ProofReceipt` / floor-recipe verification classes (`impact`, `oob`, `timing`,
 *      `boolean`, `status_differential`, `browser`, `redirect`, `conserved_balance`, `auth_bypass`),
 *      routing single-hop proofs through the exact same host-custody boundary as 1-hop
 *      `CompositeProofReceipt` and deriving request bodies, actor/tenant, ambient auth, SameSite,
 *      and exchange ordering strictly from `HostFactLog` — never from untrusted worker claim scalars.
 */
import {
  compositeProofReceiptSchema,
  registerDefaultCompositeOracleEvaluator,
  singleReceiptToComposite,
  verifyCompositeReceipt,
  verifyHostRecordSignature,
  type CompositeProofReceipt,
  type CompositeReceiptVerification,
  type CompositeVerifyOptions,
  type HostSignableRecord,
  type HostSignedTranscript,
  type ReplayMode,
} from './composite-receipt.ts'
import { evaluatePolicyJudge, type PolicyJudgeDecision, type PolicyJudgeOptions, type PolicyJudgeVerdict } from './policy-judge.ts'
import { compileVerifyFixPredicate, type CompiledVerifyFixPredicate } from './verify-fix-predicate.ts'
import type { HostFactLog } from './host-fact-log.ts'
import type { ImpactStep } from './oracle-invariants.ts'
import {
  constructHostEvidence,
  sanitizeReceiptByAllowlist,
} from './evidence-provenance.ts'
import {
  proofReceiptSchema,
  receiptRuleFor,
  verifyHostEvidence,
  type ProofReceipt,
  type ReceiptVerification,
} from './proof-receipt.ts'
import {
  evaluateV8OracleFamily,
  type HostSignedRecord as V8OracleRecord,
  type SignatureVerifier,
  type V8OracleDecision,
  type V8OracleFamily,
  type V8OracleInputMap,
} from './v8-oracle-families.ts'
import {
  hydrateV8OracleInput,
  isHydratedStub,
  matchesHydratedRecord,
  type EconomicAutoHydrateContext,
  type HydratableTranscriptIndex,
} from './v8-oracle-hydrate.ts'
import {
  assertLegitimateControl,
  extractV8KernelStageContext,
  specDeclaresDeniedControl,
  transcriptEntryToControlExchange,
} from './proof-kernel/control-legitimacy.ts'
import {
  PublicnessReplayBudgetLedger,
  evaluateMustBeNonPublicStage,
  specRequiresNonPublic,
  type PublicnessReplayEnvironmentMode,
} from './proof-kernel/publicness.ts'

import {
  DEFAULT_ORACLE_SPEC_REGISTRY,
  REGISTERED_SINGLE_HOP_RULES,
  REGISTERED_V8_FAMILIES,
  canonicalCweForOracle,
  getRegisteredClaimEvaluatorSpecs,
  labelToOracle,
  listRegisteredClaimEvaluatorKinds,
  resolveReceiptRule,
  type LabelToOracleQuery,
  type OracleClaimKind,
  type OracleSpec,
} from './oracle-spec.ts'

export type SingleHopOracleRule = Exclude<ReceiptVerification['rule'], 'none'>

export const SINGLE_HOP_ORACLE_RULES: readonly SingleHopOracleRule[] = REGISTERED_SINGLE_HOP_RULES

export const REGISTERED_V8_ORACLE_FAMILIES: readonly V8OracleFamily[] = REGISTERED_V8_FAMILIES

export type TerminalOraclePointerRef =
  | {
      kind: 'single_hop'
      receipt: ProofReceipt | unknown
      armOverrides?: ReadonlyMap<string, ImpactStep['arm']>
      evidenceRoleOverrides?: ReadonlyMap<string, string>
      /** Optional composite wrapper check (routes 1-hop receipt through 1-node CompositeProofReceipt custody checks). */
      enforceCompositeEnvelope?: boolean
    }
  | {
      kind: 'v8_family'
      family: V8OracleFamily
      rawInput?: Record<string, unknown>
      econCtx?: EconomicAutoHydrateContext
      fallbackSig?: string
      verifySignature?: SignatureVerifier
    }
  | {
      kind: 'composite'
      receipt: CompositeProofReceipt | unknown
    }

export interface TerminalOraclePolicyContext {
  signingKey?: string
  attackerPersonas?: readonly string[]
  forbiddenShortcutPersonas?: readonly string[]
  benchmarkMode?: boolean
  requireCleanSessionFlag?: boolean
  allowedExchangeIds?: ReadonlySet<string>
  replayMode?: ReplayMode
  /**
   * When `true` (default), untrusted worker-supplied claim scalars (`requiredRole`,
   * `resourceTenant`, `conservedBalance.unitDebit`, `oracleEvents`) are neutralized or
   * strictly bounded by host facts so mutating worker scalars can never flip a verdict.
   */
  strictHostDerivation?: boolean
  /** Explicitly host-trusted oracle events (e.g. from floor spec or host CSRF observation). */
  trustedOracleEvents?: readonly string[]
  /** Optional host run identifier for per-run HMAC nonce-ledger binding (`R3-16`). */
  runId?: string
  /** Explicitly host-trusted composite verification options. */
  compositeOptions?: Omit<CompositeVerifyOptions, 'signingKey'>
  /** Host-configured Tier-2 skeptic policy judge (fail-closed; only consulted when Tier-1 terminal impact is undecided). */
  policyJudge?: PolicyJudgeOptions
  /** R3-17: Environment mode enforced by budgeted publicness replay stage (defaults to `'prod_readonly'`). */
  environmentMode?: PublicnessReplayEnvironmentMode
  /** R3-17: Optional per-run finite budget ledger for active publicness replay checks. */
  publicnessReplayBudget?: PublicnessReplayBudgetLedger
  /** R3-17: Optional active unauthenticated replay probe executor gated by `publicnessReplayBudget`. */
  publicnessReplayProbe?: (target: { method: string; route: string }) => ImpactStep | null
  /** R3-17: Fail closed when active publicness replay is denied by budget or `prod_readonly` policy. */
  failClosedOnPublicnessReplayDenied?: boolean
  /** R3-17: Optional observer invoked whenever a spec-driven kernel stage executes. */
  onKernelStageExecuted?: (event: {
    stage: 'control_legitimacy' | 'must_be_non_public'
    specId: string
    ok: boolean
    reason: string
  }) => void
}

export interface TerminalOracleResult {
  readonly confirmed: boolean
  readonly kind: TerminalOraclePointerRef['kind']
  readonly familyOrRule: string
  readonly reason: string
  readonly singleHop?: ReceiptVerification
  readonly v8Decision?: V8OracleDecision
  readonly composite?: CompositeReceiptVerification
  readonly evidence?: Record<string, unknown>
  /** Three-way verdict when Tier-2 ran (`needs_review` is never confirmed). */
  readonly verdict?: PolicyJudgeVerdict
  readonly policyJudgeDecision?: PolicyJudgeDecision
  /** 0-LLM Verify Fix predicate compiled from the confirming host-signed transcript. */
  readonly compiledPredicate?: CompiledVerifyFixPredicate
}

export type SingleHopRuleHandler = (
  factLog: HostFactLog,
  receipt: ProofReceipt,
  transcript: HostSignedTranscript,
  policy: TerminalOraclePolicyContext,
) => ReceiptVerification

export type V8FamilyHandler = (
  factLog: HostFactLog,
  family: V8OracleFamily,
  rawInput: Record<string, unknown>,
  policy: TerminalOraclePolicyContext,
  opts?: { econCtx?: EconomicAutoHydrateContext; fallbackSig?: string; verifySignature?: SignatureVerifier },
) => V8OracleDecision

export function sanitizeSingleHopReceiptForHostCustody(
  receipt: ProofReceipt,
  factLog: HostFactLog,
  policy: TerminalOraclePolicyContext,
): ProofReceipt {
  const orderedIds = factLog
    .orderedExchanges(receipt.exchangeIds)
    .map(f => f.exchangeId)
  // Preserve missing IDs so verifyReceipt explicitly rejects absent citations rather than dropping them.
  const missingIds = receipt.exchangeIds.filter(id => !factLog.getExchange(id))
  const hostOrderedExchangeIds = missingIds.length > 0
    ? [...orderedIds, ...missingIds]
    : orderedIds

  // R3-16 strict allowlist host custody (ZERO spread of untrusted keys): preserves ONLY
  // allowlisted routing/citation fields + host-ordered exchangeIds + explicitly host-trusted
  // oracleEvents. Unconditionally strips requiredRole, resourceTenant, expectControlDenied,
  // proofPatterns, injectedAtMs, conservedBalance (balanceField/capField/unitDebit), worker
  // oracleEvents, and any unknown/future worker scalars.
  return sanitizeReceiptByAllowlist(receipt, hostOrderedExchangeIds, policy.trustedOracleEvents)
}

function sanitizeEmbeddedReceiptField(
  rawEmbedded: unknown,
  factLog: HostFactLog,
  policy: TerminalOraclePolicyContext,
): { sanitized: unknown; parsed?: ProofReceipt } {
  if (!rawEmbedded || typeof rawEmbedded !== 'object') return { sanitized: rawEmbedded }
  const parsed = proofReceiptSchema.safeParse(rawEmbedded)
  if (!parsed.success) return { sanitized: rawEmbedded }
  const clean = sanitizeSingleHopReceiptForHostCustody(parsed.data, factLog, {
    ...policy,
    strictHostDerivation: true,
    // Never pass untrusted worker oracleEvents into embedded composite receipts.
    trustedOracleEvents: undefined,
  })
  return { sanitized: clean, parsed: clean }
}

function sanitizeAndBindCompositeReceipt(
  rawReceipt: unknown,
  factLog: HostFactLog,
  policy: TerminalOraclePolicyContext,
): { receipt: unknown; bindingError?: string } {
  if (!rawReceipt || typeof rawReceipt !== 'object' || Array.isArray(rawReceipt)) {
    return { receipt: rawReceipt }
  }
  const rec = rawReceipt as Record<string, unknown>
  const rawHops = Array.isArray(rec.hops) ? rec.hops : null
  const sanitizedHops = rawHops
    ? rawHops.map(rawHop => {
        if (!rawHop || typeof rawHop !== 'object' || Array.isArray(rawHop)) return rawHop
        const hopObj = rawHop as Record<string, unknown>
        if (!hopObj.proofReceipt) return rawHop
        const { sanitized } = sanitizeEmbeddedReceiptField(hopObj.proofReceipt, factLog, policy)
        return { ...hopObj, proofReceipt: sanitized }
      })
    : undefined

  let sanitizedTerminalImpact = rec.terminalImpact
  let bindingError: string | undefined
  if (rec.terminalImpact && typeof rec.terminalImpact === 'object' && !Array.isArray(rec.terminalImpact)) {
    const ti = rec.terminalImpact as Record<string, unknown>
    if (ti.proofReceipt) {
      const { sanitized, parsed } = sanitizeEmbeddedReceiptField(ti.proofReceipt, factLog, policy)
      sanitizedTerminalImpact = { ...ti, proofReceipt: sanitized }
      if (parsed) {
        // R2-H-6: Bind embedded terminal proofReceipt class to terminalVulnClass and bind its
        // exchange/OOB/trace citations to the terminal hop (+ pre/post terminal controls).
        const terminalClass = typeof rec.terminalVulnClass === 'string' ? rec.terminalVulnClass.trim().toLowerCase() : ''
        const embeddedClass = parsed.vulnClass.trim().toLowerCase()
        if (terminalClass && embeddedClass && terminalClass !== embeddedClass) {
          const termRule = receiptRuleFor(terminalClass, parsed)
          const embRule = receiptRuleFor(embeddedClass, parsed)
          const sameImpactClass = Boolean(termRule.impactClass && embRule.impactClass && termRule.impactClass === embRule.impactClass)
          const sameRule = termRule.rule !== 'none' && termRule.rule === embRule.rule && termRule.rule !== 'impact'
          if (!sameImpactClass && !sameRule) {
            bindingError = `Embedded terminal proofReceipt vulnClass "${parsed.vulnClass}" does not match composite terminalVulnClass "${String(rec.terminalVulnClass)}".`
          }
        }
        if (!bindingError && sanitizedHops && typeof ti.terminalHopId === 'string') {
          const termHop = sanitizedHops.find(
            h => h && typeof h === 'object' && (h as Record<string, unknown>).hopId === ti.terminalHopId,
          ) as Record<string, unknown> | undefined
          if (termHop) {
            const allowedEx = new Set<string>([
              ...(Array.isArray(termHop.exchangeIds) ? termHop.exchangeIds.filter((x): x is string => typeof x === 'string') : []),
              ...(Array.isArray(ti.preChainControlExchangeIds) ? ti.preChainControlExchangeIds.filter((x): x is string => typeof x === 'string') : []),
              ...(Array.isArray(ti.postChainReadbackExchangeIds) ? ti.postChainReadbackExchangeIds.filter((x): x is string => typeof x === 'string') : []),
            ])
            const allowedOob = new Set<string>(
              Array.isArray(termHop.oobEventIds) ? termHop.oobEventIds.filter((x): x is string => typeof x === 'string') : [],
            )
            const allowedTrace = new Set<string>(
              Array.isArray(termHop.browserTraceIds) ? termHop.browserTraceIds.filter((x): x is string => typeof x === 'string') : [],
            )
            const unboundEx = parsed.exchangeIds.find(id => !allowedEx.has(id))
            const unboundOob = parsed.oobEventIds.find(id => !allowedOob.has(id))
            const unboundTrace = parsed.browserTraceIds.find(id => !allowedTrace.has(id))
            if (unboundEx) {
              bindingError = `Embedded terminal proofReceipt cites exchange "${unboundEx}" outside terminal hop "${ti.terminalHopId}".`
            } else if (unboundOob) {
              bindingError = `Embedded terminal proofReceipt cites OOB event "${unboundOob}" outside terminal hop "${ti.terminalHopId}".`
            } else if (unboundTrace) {
              bindingError = `Embedded terminal proofReceipt cites browser trace "${unboundTrace}" outside terminal hop "${ti.terminalHopId}".`
            }
          }
        }
      }
    }
  }

  return {
    receipt: {
      ...rec,
      ...(sanitizedHops ? { hops: sanitizedHops } : {}),
      ...(sanitizedTerminalImpact !== undefined ? { terminalImpact: sanitizedTerminalImpact } : {}),
    },
    ...(bindingError ? { bindingError } : {}),
  }
}

function checkHostCustodySignatures(
  receipt: ProofReceipt,
  transcript: HostSignedTranscript,
  policy: TerminalOraclePolicyContext,
): string | null {
  if (policy.allowedExchangeIds) {
    const disallowed = receipt.exchangeIds.find(id => !policy.allowedExchangeIds!.has(id))
    if (disallowed) {
      return `Receipt cites exchange "${disallowed}" outside the allowed host session transcript.`
    }
  }
  if (!policy.signingKey) return null
  const entriesById = new Map((transcript.entries ?? []).map(e => [e.exchangeId, e]))
  const oobById = new Map((transcript.oobEvents ?? []).map(o => [o.id, o]))
  const tracesById = new Map((transcript.browserTraces ?? []).map(t => [t.id, t]))
  const check = (ids: readonly string[], map: Map<string, HostSignableRecord>, label: string): string | null => {
    for (const id of ids) {
      const rec = map.get(id)
      if (!rec) return `Receipt cites ${label} "${id}" absent from HostFactLog.`
      if (!verifyHostRecordSignature(rec, policy.signingKey!)) {
        return `Host signature verification failed for ${label} "${id}".`
      }
    }
    return null
  }
  return check(receipt.exchangeIds, entriesById, 'exchange')
    ?? check(receipt.oobEventIds, oobById, 'OOB event')
    ?? check(receipt.browserTraceIds, tracesById, 'browser trace')
}

function runSingleHopPreOracleStages(
  spec: OracleSpec | undefined,
  receipt: ProofReceipt,
  transcript: HostSignedTranscript,
  policy: TerminalOraclePolicyContext,
  rule: SingleHopOracleRule,
): ReceiptVerification | null {
  if (!spec) return null
  const allEntries = transcript.entries ?? []
  const entriesById = new Map(allEntries.map(e => [e.exchangeId, e]))
  const cited = receipt.exchangeIds
    .map(id => entriesById.get(id))
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
  const probeEntry = cited.find(e => e.step.arm === 'probe' && typeof e.step.status === 'number' && e.step.status >= 200 && e.step.status < 300)
    ?? cited.find(e => e.step.arm === 'probe')
    ?? null
  const citedControls = cited.filter(e => e.step.arm === 'control')

  if (specDeclaresDeniedControl(spec)) {
    const allExchanges = allEntries.map(transcriptEntryToControlExchange)
    const probeEx = probeEntry ? transcriptEntryToControlExchange(probeEntry) : null
    if (citedControls.length === 0) {
      const reason = `Control legitimacy rejected (${spec.id}): receipt cites zero negative-control exchanges (fail-closed).`
      policy.onKernelStageExecuted?.({ stage: 'control_legitimacy', specId: spec.id, ok: false, reason })
      return {
        confirmed: false,
        vulnClass: receipt.vulnClass,
        rule,
        reason,
        observed: receipt.claimedDelta,
        expected: 'a legitimate negative control satisfying the spec control contract',
        evidence: { rejectedBy: 'missing_negative_control', specId: spec.id },
      }
    }
    for (const ctl of citedControls) {
      const res = assertLegitimateControl({
        spec,
        control: transcriptEntryToControlExchange(ctl),
        probe: probeEx,
        allEntries: allExchanges,
        requireAnonymousAblation: spec.id === 'auth_bypass',
      })
      policy.onKernelStageExecuted?.({ stage: 'control_legitimacy', specId: spec.id, ok: res.ok, reason: res.reason })
      if (!res.ok) {
        return {
          confirmed: false,
          vulnClass: receipt.vulnClass,
          rule,
          reason: res.reason,
          observed: receipt.claimedDelta,
          expected: 'a legitimate negative control satisfying the spec control contract',
          evidence: { rejectedBy: res.rejectedBy ?? 'control_legitimacy', specId: spec.id },
        }
      }
    }
  }

  if (specRequiresNonPublic(spec)) {
    const pub = evaluateMustBeNonPublicStage({
      spec,
      steps: allEntries.map(e => e.step),
      probe: probeEntry?.step ?? null,
      replayBudget: policy.publicnessReplayBudget,
      runId: policy.runId,
      environmentMode: policy.environmentMode,
      replayProbe: policy.publicnessReplayProbe,
      failClosedOnReplayDenied: policy.failClosedOnPublicnessReplayDenied,
    })
    policy.onKernelStageExecuted?.({ stage: 'must_be_non_public', specId: spec.id, ok: pub.passed, reason: pub.reason })
    if (!pub.passed) {
      return {
        confirmed: false,
        vulnClass: receipt.vulnClass,
        rule,
        reason: pub.reason,
        observed: receipt.claimedDelta,
        expected: 'a non-public protected resource',
        evidence: {
          rejectedBy: 'publicness',
          specId: spec.id,
          ...(pub.referenceId ? { publicnessReferenceId: pub.referenceId } : {}),
          ...(pub.replayTelemetry ? { publicnessReplayTelemetry: pub.replayTelemetry } : {}),
        },
      }
    }
  }
  return null
}

function defaultSingleHopHandler(
  factLog: HostFactLog,
  receipt: ProofReceipt,
  transcript: HostSignedTranscript,
  policy: TerminalOraclePolicyContext,
): ReceiptVerification {
  const { rule, spec } = resolveReceiptRule(receipt.vulnClass, receipt)
  const effectiveRule: ReceiptVerification['rule'] = rule
  const custodyErr = checkHostCustodySignatures(receipt, transcript, policy)
  if (custodyErr) {
    return {
      confirmed: false,
      vulnClass: receipt.vulnClass,
      rule: effectiveRule,
      reason: custodyErr,
      observed: receipt.claimedDelta,
      expected: 'host-custody verified transcript records',
    }
  }
  const canonicalReceipt = sanitizeSingleHopReceiptForHostCustody(receipt, factLog, {
    ...policy,
    strictHostDerivation: true,
  })
  if (effectiveRule !== 'none') {
    const stageRejection = runSingleHopPreOracleStages(spec, canonicalReceipt, transcript, policy, effectiveRule)
    if (stageRejection) return stageRejection
  }
  const hostEvidence = constructHostEvidence({
    receipt: canonicalReceipt,
    transcript,
    hostOrderedExchangeIds: canonicalReceipt.exchangeIds,
    trustedOracleEvents: policy.trustedOracleEvents,
    ...(policy.runId ? { runId: policy.runId } : {}),
  })
  return verifyHostEvidence(hostEvidence, {
    ...(policy.signingKey ? { signingKey: policy.signingKey } : {}),
    ...(policy.runId ? { runId: policy.runId } : {}),
  })
}

function defaultV8FamilyHandler(
  factLog: HostFactLog,
  family: V8OracleFamily,
  rawInput: Record<string, unknown>,
  policy: TerminalOraclePolicyContext,
  opts?: { econCtx?: EconomicAutoHydrateContext; fallbackSig?: string; verifySignature?: SignatureVerifier },
): V8OracleDecision {
  const transcript = factLog.toHostSignedTranscript()
  const signedEntriesById = new Map((transcript.entries ?? []).map(e => [e.exchangeId, e]))
  const entriesById = new Map([...signedEntriesById].map(([id, e]) => {
    const rawRequest = factLog.getExchange(id)?.rawRequestBody
    const entry = e.step.requestJson === undefined && rawRequest !== null && rawRequest !== undefined
      ? { ...e, step: { ...e.step, requestJson: rawRequest } }
      : e
    return [id, entry] as const
  }))
  const oobById = new Map((transcript.oobEvents ?? []).map(o => [o.id, o]))
  const tracesById = new Map((transcript.browserTraces ?? []).map(t => [t.id, t]))
  const pollsById = new Map((transcript.asyncPollRecords ?? []).map(p => [p.id, p]))
  const idx: HydratableTranscriptIndex = { entriesById, oobById, tracesById }
  const fallbackSig = opts?.fallbackSig ?? (policy.signingKey ? '' : 'host-verified-sig')
  const verifySignature: SignatureVerifier = opts?.verifySignature ?? ((rec: V8OracleRecord): boolean => {
    if (policy.allowedExchangeIds && entriesById.has(rec.id) && !policy.allowedExchangeIds.has(rec.id)) return false
    const e = entriesById.get(rec.id) ?? oobById.get(rec.id) ?? tracesById.get(rec.id) ?? pollsById.get(rec.id)
    if (!e) return false
    const signed = signedEntriesById.get(rec.id) ?? e
    if (policy.signingKey && (signed.hostSignature !== rec.hostSignature || !verifyHostRecordSignature(signed, policy.signingKey))) {
      return false
    }
    return pollsById.has(rec.id) || matchesHydratedRecord(rec, idx, fallbackSig)
  })
  const hydrated = hydrateV8OracleInput(family, rawInput, idx, fallbackSig, opts?.econCtx)
  if (family === 'economic_conservation' && isHydratedStub(hydrated.finalReadback)) {
    return {
      family,
      required: true,
      satisfied: false,
      reason: 'terminal_impact_unproven_intermediate_stub',
    }
  }
  const v8Spec = DEFAULT_ORACLE_SPEC_REGISTRY.get(`v8:${family}`)
  if (!v8Spec) {
    const reason = `Unregistered v8 oracle spec "v8:${family}" in DEFAULT_ORACLE_SPEC_REGISTRY (fail-closed).`
    policy.onKernelStageExecuted?.({ stage: 'control_legitimacy', specId: `v8:${family}`, ok: false, reason })
    return {
      family,
      required: true,
      satisfied: false,
      reason,
      evidence: { rejectedBy: 'unregistered_v8_spec', specId: `v8:${family}` },
    }
  }
  const stageCtx = extractV8KernelStageContext(family, hydrated, idx)
  if (specDeclaresDeniedControl(v8Spec)) {
    if (stageCtx.controls.length === 0) {
      const reason = `Control legitimacy rejected (${v8Spec.id}): zero resolvable negative-control exchanges for denied-control spec (fail-closed).`
      policy.onKernelStageExecuted?.({ stage: 'control_legitimacy', specId: v8Spec.id, ok: false, reason })
      return {
        family,
        required: true,
        satisfied: false,
        reason,
        evidence: { rejectedBy: 'missing_negative_control', specId: v8Spec.id },
      }
    }
    for (const ctl of stageCtx.controls) {
      const ctlRes = assertLegitimateControl({
        spec: v8Spec,
        control: ctl,
        probe: stageCtx.probe,
        allEntries: stageCtx.allExchanges,
        requireAnonymousAblation: false,
      })
      policy.onKernelStageExecuted?.({ stage: 'control_legitimacy', specId: v8Spec.id, ok: ctlRes.ok, reason: ctlRes.reason })
      if (!ctlRes.ok) {
        return {
          family,
          required: true,
          satisfied: false,
          reason: ctlRes.reason,
          evidence: { rejectedBy: ctlRes.rejectedBy ?? 'control_legitimacy', specId: v8Spec.id },
        }
      }
    }
  }
  if (specRequiresNonPublic(v8Spec)) {
    const pubRes = evaluateMustBeNonPublicStage({
      spec: v8Spec,
      steps: stageCtx.allSteps,
      probe: stageCtx.probeStep,
      replayBudget: policy.publicnessReplayBudget,
      runId: policy.runId,
      environmentMode: policy.environmentMode,
      replayProbe: policy.publicnessReplayProbe,
      failClosedOnReplayDenied: policy.failClosedOnPublicnessReplayDenied,
    })
    policy.onKernelStageExecuted?.({ stage: 'must_be_non_public', specId: v8Spec.id, ok: pubRes.passed, reason: pubRes.reason })
    if (!pubRes.passed) {
      return {
        family,
        required: true,
        satisfied: false,
        reason: pubRes.reason,
        evidence: {
          rejectedBy: 'publicness',
          specId: v8Spec.id,
          ...(pubRes.referenceId ? { publicnessReferenceId: pubRes.referenceId } : {}),
          ...(pubRes.replayTelemetry ? { publicnessReplayTelemetry: pubRes.replayTelemetry } : {}),
        },
      }
    }
  }
  return evaluateV8OracleFamily(family, { ...hydrated, verifySignature } as V8OracleInputMap[typeof family])
}

const tier2ResultFields = (c: CompositeReceiptVerification): Pick<TerminalOracleResult, 'verdict' | 'policyJudgeDecision' | 'compiledPredicate'> => ({
  ...(c.verdict ? { verdict: c.verdict } : {}), ...(c.policyJudgeDecision ? { policyJudgeDecision: c.policyJudgeDecision } : {}), ...(c.compiledPredicate ? { compiledPredicate: c.compiledPredicate } : {}),
})

/**
 * Tier-1 → Tier-2 hand-off for composite verdicts. A Tier-1 confirmation is never overridden: it
 * only gains a compiled 0-LLM Verify Fix predicate. The host-configured policy judge is consulted
 * ONLY when every integrity/edge/provenance/replay stage passed and terminal impact alone was
 * undecided; its fail-closed clamping (`needs_review`, never `confirmed` without repo or refusal
 * proof) is authoritative.
 */
function withTier2PolicyJudge(policy: TerminalOraclePolicyContext, transcript: HostSignedTranscript, rawReceipt: unknown, composite: CompositeReceiptVerification): CompositeReceiptVerification {
  const parsed = compositeProofReceiptSchema.safeParse(rawReceipt)
  if (!parsed.success) return composite
  const receipt = parsed.data, signingKey = policy.signingKey
  if (composite.confirmed) {
    const compiledPredicate = signingKey ? compileVerifyFixPredicate(receipt, transcript, { confirmed: true, signingKey, vulnClass: composite.terminalVulnClass, evidence: composite.terminalVerification?.evidence ?? composite.evidence }) : null
    return compiledPredicate ? { ...composite, compiledPredicate } : composite
  }
  const judge = policy.policyJudge ?? policy.compositeOptions?.policyJudge
  if (!judge || composite.failedStage !== 'terminal_impact') return composite
  const citedExchangeIds = [...receipt.hops.flatMap(h => h.exchangeIds), ...receipt.terminalImpact.preChainControlExchangeIds, ...receipt.terminalImpact.postChainReadbackExchangeIds]
  const decision = evaluatePolicyJudge({ ...judge, vulnClass: composite.terminalVulnClass, exchanges: transcript.entries ?? [], citedExchangeIds, ...(signingKey ? { signingKey } : {}) })
  const compiledPredicate = decision.confirmed && signingKey ? compileVerifyFixPredicate(receipt, transcript, { confirmed: true, signingKey, vulnClass: composite.terminalVulnClass, policyJudgeDecision: decision }) : null
  return {
    ...composite, confirmed: decision.confirmed, verdict: decision.verdict, policyJudgeDecision: decision,
    ...(decision.confirmed ? { failedStage: undefined, rejectedBy: null, missingEvidence: [] } : {}),
    reason: `Tier-2 policy judge ${decision.verdict}: ${decision.reason} (Tier-1: ${composite.reason})`.slice(0, 600),
    ...(compiledPredicate ? { compiledPredicate } : {}),
  }
}

export class UnregisteredTerminalOracleError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'UnregisteredTerminalOracleError'
  }
}

export class TerminalOracleRegistry {
  private readonly singleHopRules = new Map<SingleHopOracleRule, SingleHopRuleHandler>()
  private readonly v8Families = new Map<V8OracleFamily, V8FamilyHandler>()
  private readonly defaultPublicnessReplayBudget = new PublicnessReplayBudgetLedger()

  constructor(options: { registerDefaults?: boolean } = {}) {
    if (options.registerDefaults !== false) {
      for (const rule of SINGLE_HOP_ORACLE_RULES) {
        this.singleHopRules.set(rule, defaultSingleHopHandler)
      }
      for (const family of REGISTERED_V8_ORACLE_FAMILIES) {
        this.v8Families.set(family, defaultV8FamilyHandler)
      }
    }
  }

  registerSingleHopRule(rule: SingleHopOracleRule, handler: SingleHopRuleHandler): void {
    this.singleHopRules.set(rule, handler)
  }

  registerV8Family(family: V8OracleFamily, handler: V8FamilyHandler): void {
    this.v8Families.set(family, handler)
  }

  listRegisteredRules(): readonly SingleHopOracleRule[] {
    return [...this.singleHopRules.keys()]
  }

  listRegisteredV8Families(): readonly V8OracleFamily[] {
    return [...this.v8Families.keys()]
  }

  listOracleSpecs(): readonly OracleSpec[] {
    return DEFAULT_ORACLE_SPEC_REGISTRY.list()
  }

  resolveOracleSpec(input: string | LabelToOracleQuery): OracleSpec | null {
    return labelToOracle(input, DEFAULT_ORACLE_SPEC_REGISTRY)
  }

  canonicalCweFor(input: string | LabelToOracleQuery): string | null {
    return canonicalCweForOracle(input, DEFAULT_ORACLE_SPEC_REGISTRY)
  }

  listRegisteredClaimKinds(): readonly OracleClaimKind[] {
    return listRegisteredClaimEvaluatorKinds()
  }

  claimEvaluatorSpecsFor(kind: OracleClaimKind): readonly string[] {
    return getRegisteredClaimEvaluatorSpecs(kind)
  }

  /**
   * Unified typed dispatch over immutable `HostFactLog`.
   * Evaluates single-hop `ProofReceipt` (via the same host-custody boundary as 1-hop
   * `CompositeProofReceipt`), all 6 v8 extended oracle families, or full `CompositeProofReceipt` DAGs.
   */
  evaluate(
    factLog: HostFactLog,
    pointerRef: TerminalOraclePointerRef,
    policyContext: TerminalOraclePolicyContext = {},
  ): TerminalOracleResult {
    const effectivePolicy: TerminalOraclePolicyContext = policyContext.publicnessReplayBudget || (!policyContext.runId && !policyContext.publicnessReplayProbe) ? policyContext : { ...policyContext, publicnessReplayBudget: this.defaultPublicnessReplayBudget }
    if (pointerRef.kind === 'v8_family') {
      const handler = this.v8Families.get(pointerRef.family)
      if (!handler) throw new UnregisteredTerminalOracleError(`Unregistered v8 oracle family "${pointerRef.family}" in TerminalOracleRegistry (fail-closed; no fallback evaluator).`)
      const decision = handler(factLog, pointerRef.family, pointerRef.rawInput ?? {}, effectivePolicy, {
        ...(pointerRef.econCtx ? { econCtx: pointerRef.econCtx } : {}),
        ...(pointerRef.fallbackSig !== undefined ? { fallbackSig: pointerRef.fallbackSig } : {}),
        ...(pointerRef.verifySignature ? { verifySignature: pointerRef.verifySignature } : {}),
      })
      return {
        confirmed: decision.required && decision.satisfied,
        kind: 'v8_family',
        familyOrRule: pointerRef.family,
        reason: decision.reason,
        v8Decision: decision,
        ...(decision.evidence ? { evidence: decision.evidence } : {}),
      }
    }

    if (pointerRef.kind === 'composite') {
      const hostTranscript = factLog.toHostSignedTranscript()
      const sanitized = sanitizeAndBindCompositeReceipt(pointerRef.receipt, factLog, {
        ...policyContext,
        strictHostDerivation: true,
      })
      if (sanitized.bindingError) {
        return {
          confirmed: false,
          kind: 'composite',
          familyOrRule: String((pointerRef.receipt as { terminalVulnClass?: unknown } | null)?.terminalVulnClass ?? 'composite'),
          reason: sanitized.bindingError,
        }
      }
      const composite = withTier2PolicyJudge(policyContext, hostTranscript, sanitized.receipt, verifyCompositeReceipt(sanitized.receipt, hostTranscript, {
        oracleEvaluator: this,
        ...(policyContext.compositeOptions ?? {}),
        ...(policyContext.signingKey ? { signingKey: policyContext.signingKey } : {}),
        ...(policyContext.attackerPersonas ? { attackerPersonas: policyContext.attackerPersonas } : {}),
        ...(policyContext.forbiddenShortcutPersonas ? { forbiddenShortcutPersonas: policyContext.forbiddenShortcutPersonas } : {}),
        ...(policyContext.benchmarkMode !== undefined ? { benchmarkMode: policyContext.benchmarkMode } : {}),
        ...(policyContext.requireCleanSessionFlag !== undefined ? { requireCleanSessionFlag: policyContext.requireCleanSessionFlag } : {}),
        strictHostDerivation: true,
        factLog,
      }))
      return {
        confirmed: composite.confirmed, ...tier2ResultFields(composite),
        kind: 'composite',
        familyOrRule: String(composite.terminalOracleFamily ?? composite.terminalVulnClass),
        reason: composite.reason,
        composite,
        ...(composite.terminalVerification ? { singleHop: composite.terminalVerification } : {}),
        ...(composite.evidence ? { evidence: composite.evidence } : {}),
      }
    }

    // Single-hop ProofReceipt path: parse, enforce host custody, optionally validate 1-hop
    // CompositeProofReceipt envelope, and dispatch to the registered single-hop rule handler.
    const parsed = proofReceiptSchema.safeParse(pointerRef.receipt)
    if (!parsed.success) {
      const issue = parsed.error.issues[0]
      const singleHop: ReceiptVerification = {
        confirmed: false,
        vulnClass: 'invalid',
        rule: 'none',
        reason: `Receipt failed schema validation: ${issue?.path.join('.') || 'receipt'} ${issue?.message ?? ''}`.slice(0, 400),
        observed: 'invalid receipt',
        expected: 'a well-formed ProofReceipt',
      }
      return {
        confirmed: false,
        kind: 'single_hop',
        familyOrRule: 'none',
        reason: singleHop.reason,
        singleHop,
      }
    }
    const receipt = parsed.data
    const { rule } = receiptRuleFor(receipt.vulnClass, receipt)
    if (rule === 'none') {
      const singleHop: ReceiptVerification = {
        confirmed: false,
        vulnClass: receipt.vulnClass,
        rule: 'none',
        reason: `No confirmation rule for vulnerability class "${receipt.vulnClass}".`,
        observed: receipt.claimedDelta,
        expected: 'a registered single-hop confirmation rule',
      }
      return {
        confirmed: false,
        kind: 'single_hop',
        familyOrRule: 'none',
        reason: singleHop.reason,
        singleHop,
      }
    }

    const hostTranscript = factLog.toHostSignedTranscript({
      ...(pointerRef.armOverrides ? { armOverrides: pointerRef.armOverrides } : {}),
      ...(pointerRef.evidenceRoleOverrides ? { evidenceRoleOverrides: pointerRef.evidenceRoleOverrides } : {}),
    })
    const handler = this.singleHopRules.get(rule)
    if (!handler) {
      throw new UnregisteredTerminalOracleError(`Single-hop rule "${rule}" is not registered in TerminalOracleRegistry (fail-closed; no unsanitized fallback).`)
    }

    if (pointerRef.enforceCompositeEnvelope) {
      const canonical = sanitizeSingleHopReceiptForHostCustody(receipt, factLog, policyContext)
      const wrapped = singleReceiptToComposite(canonical, {
        ...(policyContext.replayMode ? { replayMode: policyContext.replayMode } : {}),
        ...(policyContext.benchmarkMode !== undefined ? { benchmarkMode: policyContext.benchmarkMode } : {}),
      })
      const compRes = verifyCompositeReceipt(wrapped, hostTranscript, {
        oracleEvaluator: this,
        ...(policyContext.compositeOptions ?? {}),
        ...(policyContext.signingKey ? { signingKey: policyContext.signingKey } : {}),
        ...(policyContext.attackerPersonas ? { attackerPersonas: policyContext.attackerPersonas } : {}),
        ...(policyContext.forbiddenShortcutPersonas ? { forbiddenShortcutPersonas: policyContext.forbiddenShortcutPersonas } : {}),
        ...(policyContext.benchmarkMode !== undefined ? { benchmarkMode: policyContext.benchmarkMode } : {}),
        ...(policyContext.requireCleanSessionFlag !== undefined ? { requireCleanSessionFlag: policyContext.requireCleanSessionFlag } : {}),
        strictHostDerivation: true,
        factLog,
      })
      const singleHop = compRes.terminalVerification ?? {
        confirmed: compRes.confirmed,
        vulnClass: canonical.vulnClass,
        rule,
        reason: compRes.reason,
        observed: canonical.claimedDelta,
        expected: 'host-custody verified single-hop composite envelope',
        ...(compRes.evidence ? { evidence: compRes.evidence } : {}),
      }
      return {
        confirmed: compRes.confirmed && singleHop.confirmed,
        kind: 'single_hop',
        familyOrRule: rule,
        reason: compRes.confirmed ? singleHop.reason : compRes.reason,
        singleHop,
        composite: compRes,
        ...(singleHop.evidence ? { evidence: singleHop.evidence } : {}),
      }
    }

    const singleHop = handler(factLog, receipt, hostTranscript, effectivePolicy)
    return {
      confirmed: singleHop.confirmed,
      kind: 'single_hop',
      familyOrRule: rule,
      reason: singleHop.reason,
      singleHop,
      ...(singleHop.evidence ? { evidence: singleHop.evidence } : {}),
    }
  }
}

export const defaultTerminalOracleRegistry = new TerminalOracleRegistry()
let activeDefaultTerminalOracleRegistry: TerminalOracleRegistry | null = null

export function registerDefaultTerminalOracleRegistry(registry: TerminalOracleRegistry | null): void {
  activeDefaultTerminalOracleRegistry = registry
  registerDefaultCompositeOracleEvaluator(registry)
}

registerDefaultTerminalOracleRegistry(defaultTerminalOracleRegistry)

export function evaluateTerminalOracle(
  factLog: HostFactLog,
  pointerRef: TerminalOraclePointerRef,
  policyContext: TerminalOraclePolicyContext = {},
): TerminalOracleResult {
  if (!activeDefaultTerminalOracleRegistry) {
    throw new UnregisteredTerminalOracleError('TerminalOracleRegistry is not registered (fail-closed; zero unsanitized fallback).')
  }
  return activeDefaultTerminalOracleRegistry.evaluate(factLog, pointerRef, policyContext)
}
