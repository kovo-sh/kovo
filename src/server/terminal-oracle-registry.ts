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
import type { HostFactLog } from './host-fact-log.ts'
import type { ImpactStep } from './oracle-invariants.ts'
import {
  proofReceiptSchema,
  receiptRuleFor,
  verifyReceipt,
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

export type SingleHopOracleRule = Exclude<ReceiptVerification['rule'], 'none'>

export const SINGLE_HOP_ORACLE_RULES: readonly SingleHopOracleRule[] = [
  'impact',
  'oob',
  'timing',
  'boolean',
  'status_differential',
  'browser',
  'redirect',
  'conserved_balance',
  'auth_bypass',
  'webhook',
]

export const REGISTERED_V8_ORACLE_FAMILIES: readonly V8OracleFamily[] = [
  'dual_tenant_abac',
  'temporal_revocation',
  'economic_conservation',
  'cryptographic_scope_replay',
  'parser_cache_differential',
  'cross_surface_pivot',
]

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
  /** Explicitly host-trusted composite verification options. */
  compositeOptions?: Omit<CompositeVerifyOptions, 'signingKey'>
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

  // Strict host custody (H-13 / R2-H-6): unconditionally neutralize untrusted worker-supplied
  // scalar hints so mutating them (or passing strictHostDerivation:false) can never flip an
  // oracle verdict; preserve only host-trusted oracleEvents if explicitly passed by host code.
  const { requiredRole: _dropRole, resourceTenant: _dropTenant, oracleEvents: _dropEvents, conservedBalance, ...rest } = receipt
  const cleanConserved = conservedBalance
    ? {
        ...(conservedBalance.balanceField ? { balanceField: conservedBalance.balanceField } : {}),
        ...(conservedBalance.capField ? { capField: conservedBalance.capField } : {}),
      }
    : undefined
  const trustedEvents = policy.trustedOracleEvents?.length ? [...policy.trustedOracleEvents] : undefined
  return {
    ...rest,
    exchangeIds: hostOrderedExchangeIds,
    ...(trustedEvents ? { oracleEvents: trustedEvents } : {}),
    ...(cleanConserved && Object.keys(cleanConserved).length > 0 ? { conservedBalance: cleanConserved } : {}),
  }
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

function defaultSingleHopHandler(
  factLog: HostFactLog,
  receipt: ProofReceipt,
  transcript: HostSignedTranscript,
  policy: TerminalOraclePolicyContext,
): ReceiptVerification {
  const { rule } = receiptRuleFor(receipt.vulnClass, receipt)
  const custodyErr = checkHostCustodySignatures(receipt, transcript, policy)
  if (custodyErr) {
    return {
      confirmed: false,
      vulnClass: receipt.vulnClass,
      rule,
      reason: custodyErr,
      observed: receipt.claimedDelta,
      expected: 'host-custody verified transcript records',
    }
  }
  const canonicalReceipt = sanitizeSingleHopReceiptForHostCustody(receipt, factLog, {
    ...policy,
    strictHostDerivation: true,
  })
  return verifyReceipt(canonicalReceipt, transcript, {
    ...(policy.signingKey ? { signingKey: policy.signingKey } : {}),
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
  return evaluateV8OracleFamily(family, { ...hydrated, verifySignature } as V8OracleInputMap[typeof family])
}

export class TerminalOracleRegistry {
  private readonly singleHopRules = new Map<SingleHopOracleRule, SingleHopRuleHandler>()
  private readonly v8Families = new Map<V8OracleFamily, V8FamilyHandler>()

  constructor() {
    for (const rule of SINGLE_HOP_ORACLE_RULES) {
      this.singleHopRules.set(rule, defaultSingleHopHandler)
    }
    for (const family of REGISTERED_V8_ORACLE_FAMILIES) {
      this.v8Families.set(family, defaultV8FamilyHandler)
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
    if (pointerRef.kind === 'v8_family') {
      const handler = this.v8Families.get(pointerRef.family)
      if (!handler) {
        return {
          confirmed: false,
          kind: 'v8_family',
          familyOrRule: pointerRef.family,
          reason: `Unregistered v8 oracle family "${pointerRef.family}".`,
        }
      }
      const decision = handler(factLog, pointerRef.family, pointerRef.rawInput ?? {}, policyContext, {
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
      const composite = verifyCompositeReceipt(sanitized.receipt, hostTranscript, {
        ...(policyContext.compositeOptions ?? {}),
        ...(policyContext.signingKey ? { signingKey: policyContext.signingKey } : {}),
        ...(policyContext.attackerPersonas ? { attackerPersonas: policyContext.attackerPersonas } : {}),
        ...(policyContext.forbiddenShortcutPersonas ? { forbiddenShortcutPersonas: policyContext.forbiddenShortcutPersonas } : {}),
        ...(policyContext.benchmarkMode !== undefined ? { benchmarkMode: policyContext.benchmarkMode } : {}),
        ...(policyContext.requireCleanSessionFlag !== undefined ? { requireCleanSessionFlag: policyContext.requireCleanSessionFlag } : {}),
        strictHostDerivation: true,
        factLog,
      })
      return {
        confirmed: composite.confirmed,
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
      const singleHop: ReceiptVerification = {
        confirmed: false,
        vulnClass: receipt.vulnClass,
        rule,
        reason: `Single-hop rule "${rule}" is not registered in TerminalOracleRegistry.`,
        observed: receipt.claimedDelta,
        expected: 'a registered single-hop oracle handler',
      }
      return {
        confirmed: false,
        kind: 'single_hop',
        familyOrRule: rule,
        reason: singleHop.reason,
        singleHop,
      }
    }

    if (pointerRef.enforceCompositeEnvelope) {
      const canonical = sanitizeSingleHopReceiptForHostCustody(receipt, factLog, policyContext)
      const wrapped = singleReceiptToComposite(canonical, {
        ...(policyContext.replayMode ? { replayMode: policyContext.replayMode } : {}),
        ...(policyContext.benchmarkMode !== undefined ? { benchmarkMode: policyContext.benchmarkMode } : {}),
      })
      const compRes = verifyCompositeReceipt(wrapped, hostTranscript, {
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

    const singleHop = handler(factLog, receipt, hostTranscript, policyContext)
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

export function evaluateTerminalOracle(
  factLog: HostFactLog,
  pointerRef: TerminalOraclePointerRef,
  policyContext: TerminalOraclePolicyContext = {},
): TerminalOracleResult {
  return defaultTerminalOracleRegistry.evaluate(factLog, pointerRef, policyContext)
}
