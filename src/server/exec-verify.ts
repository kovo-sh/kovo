import { createHash, randomUUID } from 'node:crypto'
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
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
import { attributionFromTaxonomy, cweFamilyFromTaxonomy, type TaxonomyCategory } from '../vuln-taxonomy.ts'
import { accessPolicyReviews } from './access-policy-checks.ts'
import { BrokerDenied, type BrokerExchangeResult, type Grant, type RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import {
  LEGACY_PYTHON_PROOF_REASON,
  runAgentScriptProof,
  safeVaultRunId,
  verifyPersistedScriptIntegrity,
  type AgentScriptProofParams,
  type AgentScriptProofResult,
  type V8CompositeProofBundle,
} from './agent-script-proof.ts'
import {
  ALWAYS_QUARANTINED_KINDS,
  DERIVED_CAPABILITY_HANDLE_RE,
  computeArtifactDigest,
  formatDerivedCapabilityHandle,
  type CapabilityKind,
  type CapabilityLedger,
  type CapabilitySurface,
  type CausalEdgeBindingKind,
} from './capability-ledger.ts'
import type {
  CompositeProofReceipt, CompositeReceiptVerification,
  HostTranscriptEntry,
} from './composite-receipt.ts'
import { resolveCompositeTerminalExchange as resolveCanonicalCompositeTerminalExchange } from './composite-terminal.ts'
import {
  DerivedCapabilityVault,
  scrubDerivedSecrets,
  vaultScrubDescriptors,
  type DerivedCapabilityMeta,
  type DerivedSecretKind,
} from './derived-custody.ts'
import { checkCoverage, readComparisons, verificationCommand, type EvidenceReview } from './evidence-checks.ts'
import { isFixedEligibleFailureReason } from './retest-health.ts'
import type { ExecBoardManager } from './exec-board.ts'
import {
  ExecServiceModule,
  createExchangeRecorder,
  findFindingRow,
  recordReportedFindingCoverage,
  type ExecActiveJob,
  type ExecCapture,
  type ExecCoreServices,
  type ExecReviewInput,
  type ExecTier3ApprovalInput,
} from './exec-exchange.ts'
import {
  computeFindingFingerprint,
  normalizeCwe,
  normalizeEndpointTemplate,
  normalizeOrigin,
} from './finding-fingerprint.ts'
import { CWE_TO_RECEIPT_CLASS, SEVERITY_BY_CLASS } from './floor-recipe-engine.ts'
import { alignClaimClass, resolvePersonaIdentity, type RoleName } from './oracle-invariants.ts'
import {
  buildOobReceipt,
  verifyReceipt,
  type ProofReceipt,
  type ReceiptOobEvent,
  type ReceiptVerification,
} from './proof-receipt.ts'
import { BudgetExceededError } from './provider.ts'
import { redact, redactExactValues, redactJsonValue, type NamedSecret } from './redact.ts'
import {
  buildInlineVerifyFeedback,
  persistedAgentScriptOf,
  retestReplaySpec,
  verifyReplaySpec,
  verifyReplaySpecInline,
} from './replay-verifier.ts'
import { responseReview } from './response-checks.ts'
import { isSensitiveRepoEntry, isSensitiveRepoRelativePath } from './safety-primitives.ts'
import { canaries, findings, type ReplayProofReceiptRow } from './schema.ts'

export { isSensitiveRepoEntry, isSensitiveRepoRelativePath }
import { classifyCompositeChainOverlap, compositeChainOriginsEquivalent, compositeChainRichnessScore, extractCompositeChainDedupSignature, extractRowCompositeSignature, isGenericSharedAuthOrUtilityEndpoint, sortChainDuplicateRows, type CompositeChainDedupSignature } from './store-findings.ts'
import { isAuthzPrivescClassSupersessionCompatible, resolveCompositeSupersessionMatch } from './composite-chain-dedup.ts'
export { isGenericSharedAuthOrUtilityEndpoint }
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
import type {
  VerifyTranscriptRecord,
} from './verify-rpc.ts'
import { LinuxWorkerBackend, type WorkerBackend } from './worker-backend.ts'

type Active = ExecActiveJob
type Capture = ExecCapture
type ReviewInput = ExecReviewInput

export interface ExecVerifyHost extends ExecCoreServices {
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
  /** Shared run-scoped Layer-1 DerivedCapabilityVault across all VerifyRpcServer worker sessions. */
  capabilityVaultFor?: (runId: string) => DerivedCapabilityVault
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


function buildTier3VerifyGateReq(spec: Extract<DeclarativeReplaySpec, { kind: 'rce_proof' }>, label: string) {
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


type ReplayVerificationResult = Awaited<ReturnType<typeof verifyReplaySpec>>

/**
 * Returns true when this run has live runtime verification available (`kovo_verify` supported by
 * the active worker backend AND the run is NOT an offline / static-repo-only Tier 0 or `prepared`
 * audit). On live-target runtime runs, static AST pattern matches cannot distinguish hardened/decoy
 * controls from runtime-exploitable vulnerabilities and must be recorded as `code_audit_suspect`
 * facts + proved with `kovo_verify` rather than persisted as findings.
 */
export function isLiveRuntimeVerificationRun(
  run: Pick<Run, 'capabilityTier' | 'sourceMode'>,
  supportsVerifyScript: boolean,
): boolean {
  return supportsVerifyScript && run.capabilityTier > 0 && run.sourceMode !== 'prepared'
}

export const STATIC_AST_LIVE_TARGET_REJECT_MESSAGE =
  "Live target is reachable — static_ast_proof cannot be submitted as a finding because static pattern matches cannot prove runtime exploitability or rule out runtime guards. Record static code observations with record_fact(kind='code_audit_suspect') and prove runtime exploitability with kovo_verify instead."

export interface InlineDeferredFindingCandidate {
  assetId: string
  finding: Finding
  sourceOrigins: string[]
  validFactIds: string[]
}


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


/**
 * Confirmed findings have immutable core identity fields once runtime_confirmed or static_verified.
 * Post-confirmation updates (`update_proposed_finding`, inline retries, etc.) must never mutate
 * these fields to disguise or swap the confirmed vulnerability class, origin, endpoint, or title.
 */
export const IMMUTABLE_CONFIRMED_FINDING_FIELDS = [
  'cwe',
  'origin',
  'title',
  'category',
  'severity',
  'fingerprintHash',
  'endpoint',
] as const

export function extractSpecEndpointAndMethod(
  spec: DeclarativeReplaySpec,
  replay: Pick<ReplayVerificationResult, 'receipt' | 'exchanges'>,
): { endpoint: string | null; method: string | null } {
  const receiptTarget = replay.receipt?.receipt.target
  if (receiptTarget?.pathAndQuery) {
    return {
      endpoint: receiptTarget.pathAndQuery,
      method: receiptTarget.method ? receiptTarget.method.toUpperCase() : null,
    }
  }
  if (spec.kind === 'http_chain') {
    const probe = spec.steps.find(s => s.role === 'probe') ?? spec.steps[spec.steps.length - 1]
    if (probe) {
      return {
        endpoint: probe.request.pathAndQuery,
        method: probe.request.method.toUpperCase(),
      }
    }
  } else if (spec.kind === 'rce_proof') {
    return {
      endpoint: spec.probeStep.request.pathAndQuery,
      method: spec.probeStep.request.method.toUpperCase(),
    }
  } else if (spec.kind === 'cache_differential') {
    const probeReq = (spec as { probeRequest?: { pathAndQuery?: string; method?: string }; pathAndQuery?: string; method?: string })
    const path = probeReq.probeRequest?.pathAndQuery ?? probeReq.pathAndQuery ?? null
    const method = probeReq.probeRequest?.method ?? probeReq.method ?? null
    if (path) return { endpoint: path, method: method ? method.toUpperCase() : null }
  } else if (spec.kind === 'auth_protocol_proof') {
    const authSpec = spec as { steps?: Array<{ role?: string; request?: { pathAndQuery?: string; method?: string } }>; targetPath?: string; pathAndQuery?: string }
    const probeStep = authSpec.steps?.find(s => s.role === 'probe') ?? authSpec.steps?.[authSpec.steps.length - 1]
    const path = probeStep?.request?.pathAndQuery ?? authSpec.targetPath ?? authSpec.pathAndQuery ?? null
    const method = probeStep?.request?.method ?? null
    if (path) return { endpoint: path, method: method ? method.toUpperCase() : null }
  } else if (spec.kind === 'static_ast_proof') {
    return {
      endpoint: `${spec.repo}/${spec.file}:${spec.startLine}`,
      method: null,
    }
  }
  const ex = replay.exchanges[replay.exchanges.length - 1]
  if (ex) {
    return {
      endpoint: ex.pathAndQuery,
      method: ex.method.toUpperCase(),
    }
  }
  return { endpoint: null, method: null }
}

/**
 * R2-H-14 / H-18 / R3-11: Canonical CWE + accepted CWE family for a verified ProofReceipt
 * `vulnClass`, derived directly from `src/vuln-taxonomy.ts`. Confirmed finding CWE/category must
 * bind to the verified receipt class rather than arbitrary model-declared `spec.cwe`; unknown
 * receipt classes map visibly to `'unclassified'` instead of silently falling through to `CWE-200`.
 */
export function cweFamilyForReceiptClass(vulnClass: string): {
  cwe: string
  family: readonly string[]
  category: TaxonomyCategory
  unclassified: boolean
} {
  return cweFamilyFromTaxonomy(vulnClass)
}

/** Check whether a finding CWE belongs to the accepted CWE family of a verified receipt class. */
export function isCweConsistentWithReceiptClass(
  cwe: string | null | undefined,
  receiptVulnClass: string,
): boolean {
  const normalized = cwe ? normalizeCwe(cwe) : ''
  if (!normalized) return false
  const family = cweFamilyForReceiptClass(receiptVulnClass)
  return family.family.includes(normalized)
}

const SEVERITY_BY_EXTRA_CLASS: Readonly<Record<string, Finding['severity']>> = {
  command_injection: 'critical',
  cmdi: 'critical',
  rce: 'critical',
  race: 'critical',
  race_condition: 'critical',
  double_spend: 'critical',
  auth_bypass: 'high',
  jwt: 'high',
  jwt_forgery: 'high',
  token_forgery: 'high',
  path_traversal: 'high',
  directory_traversal: 'high',
  lfi: 'high',
  ssti: 'high',
  template_injection: 'high',
  nosqli: 'high',
  nosql_injection: 'high',
  redirect: 'medium',
}

const SEVERITY_BY_EXTRA_CWE: Readonly<Record<number, Finding['severity']>> = {
  77: 'critical',
  78: 'critical',
  362: 'critical',
  367: 'critical',
  22: 'high',
  23: 'high',
  73: 'high',
  94: 'high',
  1336: 'high',
}

function lookupSeverityBand(rawKey: string | null | undefined): Finding['severity'] | null {
  if (!rawKey) return null
  const norm = rawKey.trim().toLowerCase().replace(/[\s-]+/g, '_')
  if (!norm) return null
  if (Object.prototype.hasOwnProperty.call(SEVERITY_BY_CLASS, norm)) {
    return SEVERITY_BY_CLASS[norm]!
  }
  if (Object.prototype.hasOwnProperty.call(SEVERITY_BY_EXTRA_CLASS, norm)) {
    return SEVERITY_BY_EXTRA_CLASS[norm]!
  }
  return null
}

/**
 * Derive a deterministic default severity band from the verified receipt class, evidence class,
 * normalized CWE, or category so confirmation severity never drifts by entry path (e.g.
 * `open_redirect` always derives `medium` rather than fluctuating between `low` and `medium`).
 */
export function deriveSeverityBandForClass(input: {
  receiptVulnClass?: string | null
  evidenceClass?: string | null
  cwe?: string | null
  category?: string | null
  fallback?: Finding['severity']
}): Finding['severity'] {
  const fromReceipt = lookupSeverityBand(input.receiptVulnClass)
  if (fromReceipt) return fromReceipt
  const fromEvidence = lookupSeverityBand(input.evidenceClass)
  if (fromEvidence) return fromEvidence
  const cweMatch = /^CWE-([1-9]\d*)$/i.exec((input.cwe ?? '').trim())
  if (cweMatch) {
    const cweNum = Number(cweMatch[1])
    if (Object.prototype.hasOwnProperty.call(SEVERITY_BY_EXTRA_CWE, cweNum)) {
      return SEVERITY_BY_EXTRA_CWE[cweNum]!
    }
    const receiptClass = Object.prototype.hasOwnProperty.call(CWE_TO_RECEIPT_CLASS, cweNum)
      ? CWE_TO_RECEIPT_CLASS[cweNum]!
      : null
    const fromCweClass = lookupSeverityBand(receiptClass)
    if (fromCweClass) return fromCweClass
  }
  const fromCategory = lookupSeverityBand(input.category)
  if (fromCategory) return fromCategory
  return input.fallback ?? 'high'
}

/**
 * H-18 / R2-H-14: Bind a confirmed/static_verified finding's identity (`cwe`, `category`, `origin`,
 * `title`, `severity`, and `fingerprintHash` derived from endpoint/method) strictly to the
 * confirming receipt class and spec so a stale or mislabelled spec can never persist a mismatched
 * CWE/origin/endpoint or path-dependent severity.
 */
export function bindConfirmedFindingIdentity(
  existingFinding: Finding,
  spec: DeclarativeReplaySpec,
  replay: ReplayVerificationResult,
  secretsList: readonly NamedSecret[] = [],
): Finding {
  const aligned = alignFindingForEvidence(existingFinding, replay)
  const payload = replay.evidencePayload
  const evidenceClass = payload && typeof payload.evidenceClass === 'string' ? payload.evidenceClass : null
  const evidenceAligned = alignClaimClass({ cwe: spec.cwe, category: spec.category }, evidenceClass)
  const confirmedReceipt = replay.receipt?.verification.confirmed ? replay.receipt.receipt : null
  const receiptFamily = confirmedReceipt?.vulnClass ? cweFamilyForReceiptClass(confirmedReceipt.vulnClass) : null
  const specCwe = spec.cwe ? normalizeCwe(spec.cwe) : null
  const boundOrigin = confirmedReceipt?.target.origin ?? spec.origin
  // R2-H-14 / H-18: When a confirmed ProofReceipt exists, strictly enforce its CWE family.
  // Keep spec.cwe only when it falls within the proven receipt class family; otherwise override
  // with the receipt's canonical CWE and category so model labels cannot relabel the proven class.
  let boundCwe: string | undefined
  let boundCategory: Finding['category']
  if (receiptFamily) {
    if (receiptFamily.unclassified) {
      // R3-11: Unknown receipt classes stay visible as 'unclassified' rather than silently
      // falling through to CWE-200 / misconfig-exposure or dropping the confirmed finding.
      boundCwe = receiptFamily.cwe
      boundCategory = receiptFamily.category
    } else {
      const specMatchesReceiptFamily = Boolean(specCwe && receiptFamily.family.includes(specCwe))
      const evidenceMatchesReceiptFamily = Boolean(
        evidenceAligned?.cwe && receiptFamily.family.includes(normalizeCwe(evidenceAligned.cwe)),
      )
      if (evidenceMatchesReceiptFamily && evidenceAligned) {
        boundCwe = normalizeCwe(evidenceAligned.cwe)
        boundCategory = evidenceAligned.category
      } else if (specMatchesReceiptFamily && specCwe) {
        boundCwe = specCwe
        boundCategory = spec.category ?? receiptFamily.category
      } else {
        boundCwe = receiptFamily.cwe
        boundCategory = receiptFamily.category
      }
    }
  } else {
    boundCwe = evidenceAligned?.cwe
      ?? specCwe
      ?? aligned.cwe
    boundCategory = evidenceAligned?.category
      ?? spec.category
      ?? aligned.category
  }
  const boundSeverity = deriveSeverityBandForClass({
    receiptVulnClass: confirmedReceipt?.vulnClass ?? null,
    evidenceClass,
    cwe: boundCwe ?? null,
    category: boundCategory ?? null,
    fallback: aligned.severity,
  })
  const boundTitle = redact(spec.title, secretsList).slice(0, 200) || aligned.title
  const { endpoint, method } = extractSpecEndpointAndMethod(spec, replay)
  const computedFp = endpoint
    ? computeFindingFingerprint({
        origin: boundOrigin,
        cwe: boundCwe,
        category: boundCategory,
        endpoint,
        method,
      })
    : null
  return {
    ...aligned,
    origin: boundOrigin,
    cwe: boundCwe,
    category: boundCategory,
    severity: boundSeverity,
    title: boundTitle,
    ...(computedFp ? { fingerprintHash: computedFp.hash } : {}),
  }
}

/**
 * H-18: Guard post-confirmation updates (`update_proposed_finding`, etc.) from mutating a
 * confirmed or static_verified finding's CWE, origin, endpoint, category, fingerprint, or title.
 */
export function guardConfirmedFindingMutation(
  existingFinding: Finding & { endpoint?: string },
  patch: Partial<Finding> & { endpoint?: string },
): { allowed: boolean; blockedFields: string[]; sanitizedPatch: Partial<Finding> } {
  const isVerified = existingFinding.status === 'confirmed' || existingFinding.status === 'static_verified'
  if (!isVerified) {
    const { endpoint: _ep, ...rest } = patch
    return { allowed: true, blockedFields: [], sanitizedPatch: rest }
  }
  const blockedFields: string[] = []
  const sanitizedPatch: Partial<Finding> = { ...patch }
  delete (sanitizedPatch as { endpoint?: string }).endpoint
  if (patch.cwe !== undefined && normalizeCwe(patch.cwe) !== normalizeCwe(existingFinding.cwe ?? '')) {
    blockedFields.push('cwe')
    delete sanitizedPatch.cwe
  }
  if (patch.origin !== undefined && normalizeOrigin(patch.origin) !== normalizeOrigin(existingFinding.origin)) {
    blockedFields.push('origin')
    delete sanitizedPatch.origin
  }
  if (patch.title !== undefined && patch.title.trim() !== existingFinding.title.trim()) {
    blockedFields.push('title')
    delete sanitizedPatch.title
  }
  if (patch.category !== undefined && patch.category !== existingFinding.category) {
    blockedFields.push('category')
    delete sanitizedPatch.category
  }
  if (patch.severity !== undefined && patch.severity !== existingFinding.severity) {
    blockedFields.push('severity')
    delete sanitizedPatch.severity
  }
  if (patch.fingerprintHash !== undefined && patch.fingerprintHash !== existingFinding.fingerprintHash) {
    blockedFields.push('fingerprintHash')
    delete sanitizedPatch.fingerprintHash
  }
  if (patch.endpoint !== undefined && patch.endpoint !== existingFinding.endpoint) {
    blockedFields.push('endpoint')
  }
  return { allowed: blockedFields.length === 0, blockedFields, sanitizedPatch }
}

export function buildReplayFindingPatch(
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
  const cleanReplayReason = redact(replay.outcome.reason || '', secretsList)
  const cleanObserved = redact(replay.outcome.observed, secretsList)
  const existingReason = existingFinding.reason?.trim() ? existingFinding.reason : ''
  // UX fix: when replay ends inconclusive (e.g. "Replay execution failed: ..."), preserve the
  // finding's vulnerability description (`existingFinding.reason`) under "What happened" and keep
  // the replay failure details in `verification` (and `last_verification_diff`).
  const cleanReason = finalStatus === 'inconclusive' && existingReason
    ? existingReason
    : redact(replay.outcome.reason || replay.outcome.observed || existingFinding.reason, secretsList)
  const verificationDetail = cleanReplayReason && cleanReplayReason !== cleanObserved
    ? `${cleanObserved}; ${cleanReplayReason}`
    : cleanObserved
  const isConfirming = finalStatus === 'confirmed' || finalStatus === 'static_verified'
  const bound = isConfirming
    ? bindConfirmedFindingIdentity(existingFinding, spec, replay, secretsList)
    : null
  const patch: Partial<Finding> = {
    status: finalStatus,
    verificationTier,
    reason: cleanReason,
    confidence: isConfirming
      ? 'high'
      : finalStatus === 'dismissed'
        ? 'medium'
        : 'low',
    verification: `${staticSpec ? 'Deterministic offline static_ast_proof' : `Zero-LLM ${spec.kind} ${verificationVerb}`} verdict: ${finalStatus} (controlPassed=${replay.outcome.controlPassed}, observed: ${verificationDetail}).`,
    ...(bound ? {
      origin: bound.origin,
      cwe: bound.cwe,
      category: bound.category,
      title: bound.title,
      ...(bound.fingerprintHash !== undefined ? { fingerprintHash: bound.fingerprintHash } : {}),
    } : {}),
    ...(staticSpec ? { runtimeProofGap: staticSpec.runtimeProofGap } : {}),
    ...(staticCodeLocations?.length ? { codeLocations: staticCodeLocations } : {}),
  }
  return { patch, cleanObserved }
}


const LEADING_HTTP_METHOD_RE = /^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE)\s+(.+)$/i

const CWE_ALIAS_GROUP_BY_CWE: Readonly<Record<string, string>> = {
  'CWE-362': 'conservation_race',
  'CWE-367': 'conservation_race',
  'CWE-840': 'conservation_race',
  'CWE-639': 'authorization',
  'CWE-285': 'authorization',
  'CWE-862': 'authorization',
  'CWE-863': 'authorization',
  'CWE-284': 'authorization',
  'CWE-347': 'auth_crypto',
  'CWE-287': 'auth_crypto',
  'CWE-345': 'auth_crypto',
  'CWE-613': 'session_revocation',
  'CWE-384': 'session_revocation',
  'CWE-444': 'parser_cache',
  'CWE-436': 'parser_cache',
  'CWE-918': 'cross_surface_ssrf',
}

const ORACLE_FAMILY_ALIAS_GROUP: Readonly<Record<string, string>> = {
  economic_conservation: 'conservation_race',
  dual_tenant_abac: 'authorization',
  cryptographic_scope_replay: 'auth_crypto',
  temporal_revocation: 'session_revocation',
  parser_cache_differential: 'parser_cache',
  cross_surface_pivot: 'cross_surface_ssrf',
}

const FINDING_STATUS_PRIORITY: Readonly<Record<Finding['status'], number>> = {
  confirmed: 0,
  static_verified: 1,
  pending: 2,
  inconclusive: 3,
  dismissed: 4,
}

export interface AgentProofTargetInfo {
  origin: string | null
  endpoint: string | null
  normalizedEndpoint: string | null
  method: string | null
  terminalOracleFamily: string | null
}

/** Host-recorded exchange view derived strictly from signed host transcripts / broker exchanges. */
export interface HostRecordedExchangeView {
  exchangeId: string
  origin: string
  method: string | null
  pathAndQuery: string
  status: number | null
  sessionRole: string | null
}

export function buildHostRecordedExchangeIndex(
  proof: Pick<AgentScriptProofResult, 'exchanges'> & { hostTranscript?: AgentScriptProofResult['hostTranscript'] },
): Map<string, HostRecordedExchangeView> {
  const byId = new Map<string, HostRecordedExchangeView>()
  const scriptById = new Map((proof.exchanges ?? []).map(ex => [ex.exchangeId, ex]))
  for (const entry of proof.hostTranscript?.entries ?? []) {
    const fallback = scriptById.get(entry.exchangeId)
    const origin = (entry.origin ?? fallback?.origin ?? '').trim()
    const method = normalizeMethodToken(entry.step.method) ?? normalizeMethodToken(fallback?.method)
    const pathAndQuery = (entry.step.pathAndQuery ?? entry.step.route ?? fallback?.pathAndQuery ?? '').trim()
    const status = typeof entry.step.status === 'number'
      ? entry.step.status
      : (typeof fallback?.status === 'number' ? fallback.status : null)
    const sessionRole: string | null = entry.step.arm === 'probe'
      ? 'probe'
      : entry.step.arm === 'control'
        ? 'control'
        : (fallback?.sessionRole ?? null)
    byId.set(entry.exchangeId, {
      exchangeId: entry.exchangeId,
      origin,
      method,
      pathAndQuery,
      status,
      sessionRole,
    })
  }
  for (const ex of proof.exchanges ?? []) {
    if (byId.has(ex.exchangeId)) continue
    byId.set(ex.exchangeId, {
      exchangeId: ex.exchangeId,
      origin: (ex.origin ?? '').trim(),
      method: normalizeMethodToken(ex.method),
      pathAndQuery: (ex.pathAndQuery ?? '').trim(),
      status: typeof ex.status === 'number' ? ex.status : null,
      sessionRole: ex.sessionRole ?? null,
    })
  }
  return byId
}

export function resolveCompositeTerminalExchange(
  receipt: CompositeProofReceipt,
  exchangeById: ReadonlyMap<string, HostRecordedExchangeView>,
): HostRecordedExchangeView | undefined {
  return resolveCanonicalCompositeTerminalExchange(receipt, exchangeById)
}

/**
 * R3-H-15: Derive a composite receipt's authoritative origin strictly from the terminal exchange's
 * host-signed `origin` in the transcript, rejecting any hop whose declared origin disagrees with
 * its cited host-signed exchanges.
 */
export function inspectCompositeHostOrigin(
  receipt: CompositeProofReceipt,
  exchangeById: ReadonlyMap<string, HostRecordedExchangeView>,
): { ok: true; origin: string; terminalExchange: HostRecordedExchangeView } | { ok: false; reason: string } {
  const terminalHop = receipt.hops.find(h => h.hopId === receipt.terminalImpact?.terminalHopId)
    ?? receipt.hops[receipt.hops.length - 1]
  const terminalExchange = resolveCompositeTerminalExchange(receipt, exchangeById)
  const signedOrigin = terminalExchange?.origin?.trim() ?? ''
  const normalizedSigned = signedOrigin ? normalizeOrigin(signedOrigin) : ''
  if (!terminalExchange || !normalizedSigned) {
    return {
      ok: false,
      reason: 'CompositeProofReceipt is missing a host-signed terminal exchange with a valid origin.',
    }
  }
  const declaredTerminalOrigin = terminalHop?.target?.origin?.trim() ?? ''
  if (declaredTerminalOrigin && normalizeOrigin(declaredTerminalOrigin) !== normalizedSigned) {
    return {
      ok: false,
      reason: `CompositeProofReceipt terminal hop "${terminalHop?.hopId ?? 'terminal'}" declared origin "${declaredTerminalOrigin}" disagrees with host-signed terminal exchange "${terminalExchange.exchangeId}" origin "${signedOrigin}".`,
    }
  }
  for (const hop of receipt.hops) {
    if (hop === terminalHop) continue
    const declaredHopOrigin = hop.target?.origin?.trim() ?? ''
    if (!declaredHopOrigin || !hop.exchangeIds.length) continue
    const cited = hop.exchangeIds
      .map(id => exchangeById.get(id))
      .filter((ex): ex is HostRecordedExchangeView => Boolean(ex && ex.origin.trim()))
    if (cited.length > 0 && !cited.some(ex => normalizeOrigin(ex.origin) === normalizeOrigin(declaredHopOrigin))) {
      return {
        ok: false,
        reason: `CompositeProofReceipt hop "${hop.hopId}" declared origin "${declaredHopOrigin}" disagrees with its cited host-signed exchanges.`,
      }
    }
  }
  return { ok: true, origin: signedOrigin, terminalExchange }
}

function parseEndpointAndMethodCandidate(raw: unknown): { endpoint: string; method: string | null } | null {
  if (typeof raw !== 'string') return null
  const trimmed = raw.trim()
  if (!trimmed) return null
  const verbMatch = LEADING_HTTP_METHOD_RE.exec(trimmed)
  if (verbMatch?.[1] && verbMatch[2]) {
    const path = verbMatch[2].trim()
    if (path) return { endpoint: path, method: verbMatch[1].toUpperCase() }
  }
  return { endpoint: trimmed, method: null }
}

function normalizeMethodToken(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const upper = raw.trim().toUpperCase()
  if (!upper || upper === 'ANY') return null
  return upper
}

function isLoopbackOrigin(origin: string): boolean {
  try {
    const host = new URL(origin).hostname.toLowerCase()
    return (
      host === 'localhost'
      || host === '127.0.0.1'
      || host === '::1'
      || host === '[::1]'
      || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
    )
  } catch {
    return false
  }
}

export function originsEquivalentForAgentProofDedupe(
  originA: string,
  originB: string,
  normalizedEndpoint: string,
): boolean {
  const a = normalizeOrigin(originA)
  const b = normalizeOrigin(originB)
  if (!a || !b) return false
  if (a === b) return true
  // Local test targets frequently expose the same route through both a proxy origin and a direct
  // API port on loopback; collapse only on matching non-root route templates.
  return normalizedEndpoint !== '/' && isLoopbackOrigin(a) && isLoopbackOrigin(b)
}

export function methodsCompatibleForAgentProofDedupe(
  methodA: string | null | undefined,
  methodB: string | null | undefined,
): boolean {
  const a = normalizeMethodToken(methodA)
  const b = normalizeMethodToken(methodB)
  if (!a || !b) return true
  return a === b
}

export function vulnClassesEquivalentForAgentProofDedupe(
  a: { cwe?: string | null; category?: string | null; terminalOracleFamily?: string | null },
  b: { cwe?: string | null; category?: string | null; terminalOracleFamily?: string | null },
): boolean {
  const famA = a.terminalOracleFamily?.trim().toLowerCase() || null
  const famB = b.terminalOracleFamily?.trim().toLowerCase() || null
  if (famA && famB) return famA === famB
  const cweA = normalizeCwe(a.cwe, a.category)
  const cweB = normalizeCwe(b.cwe, b.category)
  if (cweA === cweB) return true
  const groupA = (famA ? ORACLE_FAMILY_ALIAS_GROUP[famA] : undefined) ?? CWE_ALIAS_GROUP_BY_CWE[cweA]
  const groupB = (famB ? ORACLE_FAMILY_ALIAS_GROUP[famB] : undefined) ?? CWE_ALIAS_GROUP_BY_CWE[cweB]
  return Boolean(groupA && groupB && groupA === groupB)
}

export function extractAgentProofTarget(input: {
  cleanCompositeBundle: V8CompositeProofBundle | null
  receipt: ProofReceipt | null
  baseSpec: DeclarativeReplaySpec
  proof: Pick<AgentScriptProofResult, 'exchanges'> & { hostTranscript?: AgentScriptProofResult['hostTranscript'] }
  envelope?: AgentScriptProofEnvelope
}): AgentProofTargetInfo {
  const terminalHop = input.cleanCompositeBundle
    ? (input.cleanCompositeBundle.receipt.hops.find(
        h => h.hopId === input.cleanCompositeBundle!.receipt.terminalImpact.terminalHopId,
      ) ?? input.cleanCompositeBundle.receipt.hops[input.cleanCompositeBundle.receipt.hops.length - 1])
    : undefined
  const exchangeById = buildHostRecordedExchangeIndex(input.proof)
  const terminalExchange = input.cleanCompositeBundle
    ? resolveCompositeTerminalExchange(input.cleanCompositeBundle.receipt, exchangeById)
    : undefined
  const receiptExchange = (() => {
    const ids = input.receipt?.exchangeIds ?? []
    const matched = ids.map(id => exchangeById.get(id)).filter((ex): ex is HostRecordedExchangeView => Boolean(ex))
    return matched.find(ex => ex.sessionRole === 'probe') ?? matched[0]
  })()
  const baseSpecStep = input.baseSpec.kind === 'http_chain'
    ? (input.baseSpec.steps.find(step => step.role === 'probe') ?? input.baseSpec.steps[0])
    : undefined
  const receiptRecord = input.receipt as (ProofReceipt & { endpoint?: string | null }) | null
  const envelopeRecord = input.envelope as (AgentScriptProofEnvelope & { endpoint?: string; path?: string }) | undefined

  // R3-H-15: For composite proofs, derive origin strictly from the terminal exchange's host-signed
  // origin — never from worker-declared `hops[terminal].target.origin`.
  const origin = input.cleanCompositeBundle
    ? (terminalExchange?.origin?.trim() || null)
    : (receiptExchange?.origin?.trim()
        || input.receipt?.target.origin?.trim()
        || input.proof.exchanges.find(ex => ex.sessionRole === 'probe')?.origin?.trim()
        || input.proof.exchanges[0]?.origin?.trim()
        || null)

  const endpointCandidates: unknown[] = [
    input.cleanCompositeBundle?.verification.terminalEndpoint,
    terminalExchange?.pathAndQuery,
    ...(input.cleanCompositeBundle ? [] : [terminalHop?.target.pathAndQuery]),
    receiptExchange?.pathAndQuery,
    receiptRecord?.endpoint,
    input.receipt?.target.pathAndQuery,
    baseSpecStep?.request.pathAndQuery,
    envelopeRecord?.endpoint,
    envelopeRecord?.path,
    input.proof.exchanges.find(ex => ex.sessionRole === 'probe')?.pathAndQuery,
    input.proof.exchanges[0]?.pathAndQuery,
  ]
  let parsedEndpoint: { endpoint: string; method: string | null } | null = null
  for (const candidate of endpointCandidates) {
    parsedEndpoint = parseEndpointAndMethodCandidate(candidate)
    if (parsedEndpoint) break
  }
  const endpoint = parsedEndpoint?.endpoint ?? null
  const normalizedEndpoint = endpoint ? normalizeEndpointTemplate(endpoint) : null

  const matchingExchangeMethod = (() => {
    if (!normalizedEndpoint) return null
    const matching = [...input.proof.exchanges]
      .reverse()
      .filter(ex => normalizeEndpointTemplate(ex.pathAndQuery) === normalizedEndpoint)
    const chosen = matching.find(ex => ex.sessionRole === 'probe') ?? matching[0]
    return normalizeMethodToken(chosen?.method)
  })()
  const baseSpecMethod = baseSpecStep && (
    !normalizedEndpoint || normalizeEndpointTemplate(baseSpecStep.request.pathAndQuery) === normalizedEndpoint
  )
    ? normalizeMethodToken(baseSpecStep.request.method)
    : null

  const method = parsedEndpoint?.method
    ?? normalizeMethodToken(terminalExchange?.method)
    ?? (input.cleanCompositeBundle ? null : normalizeMethodToken(terminalHop?.target.method))
    ?? normalizeMethodToken(receiptExchange?.method)
    ?? normalizeMethodToken(input.receipt?.target.method)
    ?? matchingExchangeMethod
    ?? baseSpecMethod
    ?? null

  const rawFamily = input.cleanCompositeBundle?.verification.terminalOracleFamily
    ?? input.cleanCompositeBundle?.receipt.terminalImpact.oracleFamily
    ?? null
  const terminalOracleFamily = typeof rawFamily === 'string' && rawFamily.trim()
    ? rawFamily.trim().toLowerCase()
    : null

  return { origin, endpoint, normalizedEndpoint, method, terminalOracleFamily }
}

function extractExistingFindingTargetMeta(
  row: typeof findings.$inferSelect,
  specRow?: ReplaySpecRow,
): AgentProofTargetInfo {
  const findingObj = row.finding as Finding & { evidence?: Record<string, unknown> }
  const ev = findingObj.evidence && typeof findingObj.evidence === 'object' ? findingObj.evidence : undefined
  const proofReceiptObj = specRow?.proofReceipt && typeof specRow.proofReceipt === 'object'
    ? specRow.proofReceipt as unknown as Record<string, unknown>
    : undefined
  const compReceipt = (ev?.compositeReceipt ?? proofReceiptObj?.compositeReceipt) as CompositeProofReceipt | undefined
  const compVer = (ev?.compositeVerification ?? proofReceiptObj?.compositeVerification) as CompositeReceiptVerification | undefined
  const terminalHop = compReceipt && Array.isArray(compReceipt.hops)
    ? (compReceipt.hops.find(h => h.hopId === compReceipt.terminalImpact?.terminalHopId)
        ?? compReceipt.hops[compReceipt.hops.length - 1])
    : undefined
  const singleReceipt = specRow?.proofReceipt?.receipt
  const specStep = specRow?.spec && specRow.spec.kind === 'http_chain'
    ? (specRow.spec.steps.find(step => step.role === 'probe') ?? specRow.spec.steps[0])
    : undefined

  const endpointCandidates: unknown[] = [
    ev?.terminalEndpoint,
    compVer?.terminalEndpoint,
    terminalHop?.target?.pathAndQuery,
    singleReceipt?.target?.pathAndQuery,
    specStep?.request?.pathAndQuery,
  ]
  let parsedEndpoint: { endpoint: string; method: string | null } | null = null
  for (const candidate of endpointCandidates) {
    parsedEndpoint = parseEndpointAndMethodCandidate(candidate)
    if (parsedEndpoint) break
  }
  const endpoint = parsedEndpoint?.endpoint ?? null
  const normalizedEndpoint = endpoint ? normalizeEndpointTemplate(endpoint) : null

  const specMethod = specStep && (
    !normalizedEndpoint || normalizeEndpointTemplate(specStep.request.pathAndQuery) === normalizedEndpoint
  )
    ? normalizeMethodToken(specStep.request.method)
    : null
  const method = parsedEndpoint?.method
    ?? normalizeMethodToken(terminalHop?.target?.method)
    ?? normalizeMethodToken(singleReceipt?.target?.method)
    ?? specMethod
    ?? null

  const rawFamily = ev?.terminalOracleFamily
    ?? compVer?.terminalOracleFamily
    ?? compReceipt?.terminalImpact?.oracleFamily
    ?? null
  const terminalOracleFamily = typeof rawFamily === 'string' && rawFamily.trim()
    ? rawFamily.trim().toLowerCase()
    : null

  return { origin: row.finding.origin || null, endpoint, normalizedEndpoint, method, terminalOracleFamily }
}

function existingRowHasCompositeProof(
  row: typeof findings.$inferSelect,
  specRow?: ReplaySpecRow,
): boolean {
  const ev = (row.finding as Finding & { evidence?: Record<string, unknown> }).evidence
  if (ev && typeof ev === 'object' && ev.compositeReceipt) return true
  const pr = specRow?.proofReceipt as unknown as Record<string, unknown> | null | undefined
  return Boolean(pr && typeof pr === 'object' && pr.compositeReceipt)
}

export interface SupersessionEndpointSpec {
  origin: string
  method: string | null
  normalizedEndpoint: string
  /** Host-signed exchange ID backing this upstream endpoint (when derived from transcript). */
  exchangeId?: string
  /** Explicitly declared precondition vulnClass on the upstream hop (e.g. `hop.proofReceipt.vulnClass`). */
  preconditionVulnClass?: string | null
}

function parseSupersessionEndpoint(
  origin: unknown,
  rawMethod: unknown,
  rawPath: unknown,
  extra?: { exchangeId?: string; preconditionVulnClass?: string | null },
): SupersessionEndpointSpec | null {
  if (typeof origin !== 'string' || !origin.trim()) return null
  const parsed = parseEndpointAndMethodCandidate(rawPath)
  if (!parsed) return null
  return {
    origin: origin.trim(),
    method: parsed.method ?? normalizeMethodToken(rawMethod),
    normalizedEndpoint: normalizeEndpointTemplate(parsed.endpoint),
    ...(extra?.exchangeId ? { exchangeId: extra.exchangeId } : {}),
    ...(extra?.preconditionVulnClass ? { preconditionVulnClass: extra.preconditionVulnClass } : {}),
  }
}

function dedupeSupersessionEndpoints(endpoints: readonly SupersessionEndpointSpec[]): SupersessionEndpointSpec[] {
  const out: SupersessionEndpointSpec[] = []
  const seen = new Set<string>()
  for (const ep of endpoints) {
    const key = `${normalizeOrigin(ep.origin)}|${ep.method ?? '*'}|${ep.normalizedEndpoint}|${ep.exchangeId ?? ''}|${ep.preconditionVulnClass ?? ''}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(ep)
  }
  return out
}

/**
 * R3-H-13: Derive composite upstream endpoints strictly from non-terminal hops' cited host-signed
 * transcript exchanges (with exact origin and explicit HTTP method) — NEVER from unbound
 * worker-declared `hop.target` strings alone.
 */
export function extractCompositeUpstreamEndpoints(
  receipt: CompositeProofReceipt,
  hostExchanges: ReadonlyMap<string, HostRecordedExchangeView> | readonly HostRecordedExchangeView[] = [],
): SupersessionEndpointSpec[] {
  if (!Array.isArray(receipt.hops) || receipt.hops.length < 2) return []
  const exchangeById: ReadonlyMap<string, HostRecordedExchangeView> = hostExchanges instanceof Map
    ? hostExchanges
    : new Map((hostExchanges as readonly HostRecordedExchangeView[]).map(ex => [ex.exchangeId, ex]))
  if (exchangeById.size === 0) return []
  const terminalHop = receipt.hops.find(h => h.hopId === receipt.terminalImpact?.terminalHopId)
    ?? receipt.hops[receipt.hops.length - 1]
  const out: SupersessionEndpointSpec[] = []
  for (const hop of receipt.hops) {
    if (hop === terminalHop) continue
    const preconditionVulnClass = hop.proofReceipt?.vulnClass?.trim().toLowerCase() || null
    for (const exId of hop.exchangeIds ?? []) {
      const ex = exchangeById.get(exId)
      if (!ex) continue
      const exMethod = normalizeMethodToken(ex.method)
      if (!exMethod) continue
      const parsed = parseSupersessionEndpoint(ex.origin, exMethod, ex.pathAndQuery, {
        exchangeId: ex.exchangeId,
        preconditionVulnClass,
      })
      if (parsed && parsed.method) out.push(parsed)
    }
  }
  return dedupeSupersessionEndpoints(out)
}

function extractExistingFindingEndpointsForSupersession(
  row: typeof findings.$inferSelect,
  specRow?: ReplaySpecRow,
): SupersessionEndpointSpec[] {
  const findingObj = row.finding as Finding & { evidence?: Record<string, unknown> }
  const ev = findingObj.evidence && typeof findingObj.evidence === 'object' ? findingObj.evidence : undefined
  const proofReceiptObj = specRow?.proofReceipt && typeof specRow.proofReceipt === 'object'
    ? specRow.proofReceipt as unknown as Record<string, unknown>
    : undefined
  const specObj = specRow?.spec && typeof specRow.spec === 'object'
    ? specRow.spec as unknown as Record<string, unknown>
    : undefined
  const compReceipt = (ev?.compositeReceipt ?? proofReceiptObj?.compositeReceipt ?? specObj?.compositeReceipt) as CompositeProofReceipt | undefined
  if (compReceipt && Array.isArray(compReceipt.hops) && compReceipt.hops.length > 0) {
    const hopEndpoints: SupersessionEndpointSpec[] = []
    for (const hop of compReceipt.hops) {
      const parsed = parseSupersessionEndpoint(
        hop.target?.origin || row.finding.origin,
        hop.target?.method,
        hop.target?.pathAndQuery,
      )
      if (!parsed) return []
      hopEndpoints.push(parsed)
    }
    return dedupeSupersessionEndpoints(hopEndpoints)
  }

  const singleReceipt = specRow?.proofReceipt?.receipt
  if (singleReceipt?.target?.pathAndQuery) {
    const parsed = parseSupersessionEndpoint(
      singleReceipt.target.origin || row.finding.origin,
      singleReceipt.target.method,
      singleReceipt.target.pathAndQuery,
    )
    if (parsed) return [parsed]
  }

  const spec = specRow?.spec
  if (spec) {
    if (spec.kind === 'http_chain') {
      const probeSteps = spec.steps.filter(step => step.role === 'probe')
      const targetSteps = probeSteps.length > 0 ? probeSteps : spec.steps.slice(-1)
      const stepEndpoints = targetSteps
        .map(step => parseSupersessionEndpoint(step.request.origin || row.finding.origin, step.request.method, step.request.pathAndQuery))
        .filter((ep): ep is SupersessionEndpointSpec => Boolean(ep))
      if (stepEndpoints.length > 0) return dedupeSupersessionEndpoints(stepEndpoints)
    } else if (spec.kind === 'rce_proof') {
      const parsed = parseSupersessionEndpoint(
        spec.probeStep.request.origin || row.finding.origin,
        spec.probeStep.request.method,
        spec.probeStep.request.pathAndQuery,
      )
      if (parsed) return [parsed]
    } else {
      const extracted = extractSpecEndpointAndMethod(spec, { exchanges: [] })
      if (extracted.endpoint) {
        const parsed = parseSupersessionEndpoint(row.finding.origin, extracted.method, extracted.endpoint)
        if (parsed) return [parsed]
      }
    }
  }

  const compVer = (ev?.compositeVerification ?? proofReceiptObj?.compositeVerification) as CompositeReceiptVerification | undefined
  const fallback = parseSupersessionEndpoint(row.finding.origin, null, ev?.terminalEndpoint ?? compVer?.terminalEndpoint)
  return fallback ? [fallback] : []
}

function supersessionEndpointsMatchExact(
  earlier: SupersessionEndpointSpec,
  upstream: SupersessionEndpointSpec,
): boolean {
  const earlierMethod = normalizeMethodToken(earlier.method)
  const upstreamMethod = normalizeMethodToken(upstream.method)
  const earlierOrigin = normalizeOrigin(earlier.origin)
  const upstreamOrigin = normalizeOrigin(upstream.origin)
  if (!earlierMethod || !upstreamMethod || !earlierOrigin || !upstreamOrigin) return false
  return (
    earlier.normalizedEndpoint === upstream.normalizedEndpoint
    && earlierMethod === upstreamMethod
    && earlierOrigin === upstreamOrigin
  )
}

/**
 * R3-H-13: Strict subset check for composite supersession:
 *  - Exact origin match (no loopback cross-port/hostname equivalence)
 *  - Exact explicit HTTP method match (missing / ANY method never matches)
 *  - Excludes generic shared auth/utility endpoints from driving supersession
 */
export function isEndpointSubsetOfUpstream(
  earlierEndpoints: readonly SupersessionEndpointSpec[],
  upstreamEndpoints: readonly SupersessionEndpointSpec[],
): boolean {
  if (!earlierEndpoints.length || !upstreamEndpoints.length) return false
  const nonGenericUpstream = upstreamEndpoints.filter(up => !isGenericSharedAuthOrUtilityEndpoint(up.normalizedEndpoint))
  if (!nonGenericUpstream.length) return false
  const matchesUpstream = (ep: SupersessionEndpointSpec, candidates: readonly SupersessionEndpointSpec[]) =>
    candidates.some(up => supersessionEndpointsMatchExact(ep, up))
  const hasNonGenericMatch = earlierEndpoints.some(
    ep => !isGenericSharedAuthOrUtilityEndpoint(ep.normalizedEndpoint) && matchesUpstream(ep, nonGenericUpstream),
  )
  if (!hasNonGenericMatch) return false
  return earlierEndpoints.every(ep => matchesUpstream(ep, upstreamEndpoints))
}

/**
 * R3-H-13: Ensure an earlier confirmed finding's vulnerability class or CWE matches the composite
 * chain's terminal class or an explicitly declared precondition class on the matched upstream hop.
 * Unrelated classes (e.g. SQLi/XSS on a BOLA setup listing route) must NEVER be superseded.
 */
export function isFindingClassSupersessionCompatible(
  earlier: {
    cwe?: string | null
    vulnClass?: string | null
    terminalOracleFamily?: string | null
  },
  composite: {
    terminalVulnClass: string
    terminalOracleFamily?: string | null
    preconditionVulnClasses?: readonly string[]
  },
): boolean {
  const earlierCwe = earlier.cwe ? normalizeCwe(earlier.cwe) : ''
  const hasConcreteEarlierCwe = /^CWE-\d{1,5}$/.test(earlierCwe)
  const earlierVulnClass = earlier.vulnClass?.trim().toLowerCase() || ''
  const earlierFamily = earlier.terminalOracleFamily?.trim().toLowerCase() || ''
  if (!hasConcreteEarlierCwe && !earlierVulnClass && !earlierFamily) return false

  const allowedClasses = [
    composite.terminalVulnClass,
    ...(composite.preconditionVulnClasses ?? []),
  ]
    .map(c => c.trim().toLowerCase())
    .filter(Boolean)

  for (const allowedClass of allowedClasses) {
    if (earlierVulnClass && earlierVulnClass === allowedClass) return true
    if (hasConcreteEarlierCwe && isCweConsistentWithReceiptClass(earlierCwe, allowedClass)) return true
  }

  const compFamily = composite.terminalOracleFamily?.trim().toLowerCase() || ''
  if (earlierFamily && compFamily) {
    if (earlierFamily === compFamily) return true
    const g1 = ORACLE_FAMILY_ALIAS_GROUP[earlierFamily]
    const g2 = ORACLE_FAMILY_ALIAS_GROUP[compFamily]
    if (g1 && g2 && g1 === g2) return true
  }
  return isAuthzPrivescClassSupersessionCompatible({ cwe: earlierCwe, vulnClass: earlierVulnClass }, { vulnClasses: allowedClasses })
}

/**
 * Confirmation attribution for an agent script proof: reporting vocabulary derived directly from
 * `src/vuln-taxonomy.ts` (`R3-11`). Only labels/CWE/copy — never a verification input. Unknown
 * classes map visibly to `'unclassified'` instead of silently reporting `CWE-200`.
 */
export function agentProofAttribution(vulnClass: string): {
  label: string
  cwe: string
  category: TaxonomyCategory
  unclassified: boolean
  impact: string
  remediation: string
} {
  return attributionFromTaxonomy(vulnClass)
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
  const variant = new Set(['http', 'dns', 'header', 'custom', 'general_entity', 'param_entity', 'svg_dtd', 'prove_oob'])
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
      recheck: 'Re-inject the same canary URL and confirm no callback is delivered to the Kovo Hunter relay after the response.',
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
  pair: { receipt: ProofReceipt; verification: ReceiptVerification },
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

// --- v8 Layer-1 Vault, CompositeProofReceipt & CapabilityLedger Wiring ------

export type { V8CompositeProofBundle }
export type V8AgentScriptProofParams = AgentScriptProofParams
export type V8AgentScriptProofResult = AgentScriptProofResult
/** Unified agent-script proof runner (re-exported for backwards compatibility). */
export const runV8AgentScriptProof = runAgentScriptProof

export interface SyncVerifyArtifactsResult {
  sealedCapabilities: Array<{
    handle: string
    kind: string
    sha256Prefix: string
    derivedFromCapabilityId?: string
  }>
  verifiedHops: Array<{
    hopReceiptId: string
    edgeId: string
    binding: CausalEdgeBindingKind
    postconditionCapId: string | null
    terminalImpact: string | null
  }>
  newCapabilityCount: number
  newEdgeCount: number
}

function mapDerivedSecretKindToCapabilityKind(kind: DerivedSecretKind): CapabilityKind {
  switch (kind) {
    case 'cookie':
    case 'oidc_assertion':
      return 'identity_session'
    case 'signing_salt':
    case 'hmac_key':
      return 'signing_material'
    case 'signed_url':
      return 'signed_artifact_or_url'
    case 'bearer_token':
    case 'api_token':
    case 'jwt':
    case 'header_secret':
      return 'scoped_token'
    default:
      return 'state_handle'
  }
}

function mapTranscriptOpToSurface(op: VerifyTranscriptRecord['op']): CapabilitySurface {
  if (op === 'browser') return 'browser'
  if (op === 'async_poll') return 'async_job'
  return 'http'
}

function normalizeLedgerCapHandle(meta: Pick<DerivedCapabilityMeta, 'handle' | 'hopReceiptId' | 'slot'>): string {
  if (DERIVED_CAPABILITY_HANDLE_RE.test(meta.handle)) return meta.handle
  const safeHop = meta.hopReceiptId.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, 'h').slice(0, 40)
    || createHash('sha256').update(meta.hopReceiptId).digest('hex').slice(0, 16)
  const safeSlot = meta.slot.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, 's').slice(0, 40) || 'slot'
  return formatDerivedCapabilityHandle(safeHop, safeSlot)
}

export function serializeCompositeProofReceiptRow(
  bundle: V8CompositeProofBundle,
  singlePair?: { receipt: ProofReceipt; verification: ReceiptVerification } | null,
  hostTerminal?: Pick<HostRecordedExchangeView, 'origin' | 'method' | 'pathAndQuery'> | null,
): ReplayProofReceiptRow & {
  compositeReceipt: CompositeProofReceipt
  compositeVerification: CompositeReceiptVerification
  hopActors: Record<string, string | null>
} {
  const { receipt: rawComp, verification: rawVer, hopActors } = bundle
  const terminalHop = rawComp.hops.find(h => h.hopId === rawComp.terminalImpact.terminalHopId) ?? rawComp.hops[rawComp.hops.length - 1]!
  const signedOrigin = hostTerminal?.origin?.trim() || ''
  if (signedOrigin && terminalHop.target.origin && normalizeOrigin(terminalHop.target.origin) !== normalizeOrigin(signedOrigin)) {
    throw new InvariantError(
      'invariant.confirmation_evidence',
      `CompositeProofReceipt terminal hop "${terminalHop.hopId}" declared origin "${terminalHop.target.origin}" disagrees with host-signed terminal exchange origin "${signedOrigin}".`,
    )
  }
  const resolvedOrigin = signedOrigin || terminalHop.target.origin
  const terminalEndpoint = rawVer.terminalEndpoint ?? hostTerminal?.pathAndQuery ?? terminalHop.target.pathAndQuery ?? null
  const terminalMethod = normalizeMethodToken(hostTerminal?.method) ?? normalizeMethodToken(terminalHop.target.method) ?? undefined
  const summaryText = rawComp.terminalImpact.summary && rawComp.terminalImpact.summary.length > 0
    ? rawComp.terminalImpact.summary
    : rawComp.terminalImpact.claimedImpact
  const comp: CompositeProofReceipt = {
    ...rawComp,
    hops: rawComp.hops.map(h => {
      if (h.hopId !== terminalHop.hopId) return h
      return {
        ...h,
        target: {
          ...h.target,
          origin: resolvedOrigin,
          ...(terminalMethod ? { method: terminalMethod } : {}),
          ...(terminalEndpoint && !h.target.pathAndQuery ? { pathAndQuery: terminalEndpoint } : {}),
        },
      }
    }),
    terminalImpact: {
      ...rawComp.terminalImpact,
      claimedImpact: rawComp.terminalImpact.claimedImpact || summaryText,
      ...(summaryText ? { summary: summaryText } : {}),
    },
  }
  const compVer: CompositeReceiptVerification = {
    ...rawVer,
    confirmed: Boolean(rawVer.confirmed),
    chainId: rawVer.chainId || comp.chainId,
    terminalVulnClass: rawVer.terminalVulnClass || comp.terminalVulnClass,
    replayMode: rawVer.replayMode || comp.replayMode,
    modeBVerified: Boolean(rawVer.modeBVerified),
    hopCount: typeof rawVer.hopCount === 'number' && rawVer.hopCount > 0 ? rawVer.hopCount : comp.hops.length,
    verifiedEdges: Array.isArray(rawVer.verifiedEdges) ? rawVer.verifiedEdges : [],
    reason: rawVer.reason || `CompositeProofReceipt confirmed (${comp.hops.length} hop(s), mode=${comp.replayMode}).`,
    ...(rawVer.terminalOracleFamily !== undefined
      ? { terminalOracleFamily: rawVer.terminalOracleFamily }
      : comp.terminalImpact.oracleFamily
        ? { terminalOracleFamily: comp.terminalImpact.oracleFamily }
        : {}),
    ...(terminalEndpoint ? { terminalEndpoint } : {}),
  }
  const allExchangeIds = [...new Set([
    ...comp.hops.flatMap(h => h.exchangeIds),
    ...comp.terminalImpact.preChainControlExchangeIds,
    ...comp.terminalImpact.postChainReadbackExchangeIds,
  ])].slice(0, 64)
  const base: ReplayProofReceiptRow = singlePair
    ? serializeProofReceiptRow(singlePair)
    : {
        receipt: {
          vulnClass: comp.terminalVulnClass,
          target: {
            origin: resolvedOrigin,
            ...(terminalMethod ? { method: terminalMethod } : {}),
            ...(terminalEndpoint ? { pathAndQuery: terminalEndpoint } : {}),
            ...(terminalHop.target.param ? { param: terminalHop.target.param } : {}),
          },
          exchangeIds: allExchangeIds,
          oobEventIds: [...new Set(comp.hops.flatMap(h => h.oobEventIds))].slice(0, 16),
          browserTraceIds: [...new Set(comp.hops.flatMap(h => h.browserTraceIds))].slice(0, 16),
          claimedDelta: comp.terminalImpact.claimedImpact,
        },
        verification: {
          confirmed: compVer.confirmed,
          vulnClass: compVer.terminalVulnClass,
          rule: `composite:${compVer.replayMode}`,
          reason: compVer.reason,
          observed: `${compVer.hopCount}-hop CompositeProofReceipt (${compVer.verifiedEdges.length} verified causal edges)`,
          expected: 'every hop and causal edge verifies over host-signed transcripts with attacker-origin provenance',
        },
      }
  return {
    ...base,
    compositeReceipt: comp,
    compositeVerification: compVer,
    hopActors,
  }
}

function nextMonotonicEdgeTimestamps(
  ledger: CapabilityLedger,
  preconditionCapIds: readonly string[],
  rawSourceMs: number,
  rawTargetMs: number,
): { sourceTimestampMs: number; targetTimestampMs: number } {
  let minUpstreamMs = 0
  for (const preId of preconditionCapIds) {
    for (const edge of ledger.getIncomingEdges(preId)) {
      if (edge.targetTimestampMs > minUpstreamMs) minUpstreamMs = edge.targetTimestampMs
    }
  }
  const sourceTimestampMs = Math.max(0, Math.floor(Math.max(rawSourceMs, minUpstreamMs)))
  const targetTimestampMs = Math.max(sourceTimestampMs, Math.floor(rawTargetMs))
  return { sourceTimestampMs, targetTimestampMs }
}

/**
 * Persist newly sealed Layer-1 capabilities and host-verified hop edges into `CapabilityLedger`.
 *
 * Security invariants:
 *  - Intermediate capabilities are strictly quarantined (`promotionStatus: 'capability_only'`,
 *    `terminalImpactOracleVerified: false`).
 *  - Zero raw secrets ever touch the ledger (only opaque `cap:hop_<id>:<slot>` handles + SHA-256 digests).
 *  - Only a host-verified `CompositeProofReceipt` may mark a non-quarantined terminal capability
 *    `terminal_eligible` or record a `terminalImpact` edge.
 */
export function syncVerifyArtifactsToLedger(input: {
  ledger: CapabilityLedger
  proof: V8AgentScriptProofResult
  defaultOrigin: string
  defaultPersona?: string
}): SyncVerifyArtifactsResult {
  const { ledger, proof } = input
  const defaultOrigin = input.defaultOrigin.trim() || 'unknown'
  const defaultPersona = input.defaultPersona?.trim() || 'attacker'
  const unscopedTenant = 'unscoped_hypothesis'
  const sealedSummaries: SyncVerifyArtifactsResult['sealedCapabilities'] = []
  const verifiedHops: SyncVerifyArtifactsResult['verifiedHops'] = []
  let newCapabilityCount = 0
  let newEdgeCount = 0

  type PersonaMeta = { roleLabel: string | null; tenantRef: string | null; privilege: RoleName | null }
  const recordByCapHandle = new Map<string, VerifyTranscriptRecord>()
  const recordByExchangeId = new Map<string, VerifyTranscriptRecord>()
  const hostEntryByExchangeId = new Map<string, HostTranscriptEntry>()
  const metaByPersona = new Map<string, PersonaMeta>()
  const rememberMeta = (handle: string | null | undefined, meta: PersonaMeta): void => {
    const key = handle?.trim().toLowerCase()
    if (!key) return
    const prev = metaByPersona.get(key)
    metaByPersona.set(key, {
      roleLabel: prev?.roleLabel ?? meta.roleLabel,
      tenantRef: prev?.tenantRef ?? meta.tenantRef,
      privilege: prev?.privilege ?? meta.privilege,
    })
  }
  for (const rec of proof.transcriptRecords) {
    recordByExchangeId.set(rec.exchangeId, rec)
    if (rec.artifact?.capabilityHandle) recordByCapHandle.set(rec.artifact.capabilityHandle, rec)
    if (rec.artifact?.derivedCapabilityId) recordByCapHandle.set(rec.artifact.derivedCapabilityId, rec)
    if (rec.request?.personaHandle) {
      rememberMeta(rec.request.personaHandle, {
        roleLabel: rec.request.actorRoleLabel ?? null,
        tenantRef: rec.request.actorTenant ?? null,
        privilege: rec.request.actorPrivilege ?? null,
      })
    }
  }
  for (const entry of proof.hostTranscript?.entries ?? []) {
    hostEntryByExchangeId.set(entry.exchangeId, entry)
    rememberMeta(entry.actorPersona ?? entry.step.actor.handle, {
      roleLabel: entry.actorRoleLabel ?? null,
      tenantRef: entry.actorTenant ?? entry.step.actor.tenant ?? null,
      privilege: entry.actorPrivilege ?? entry.step.actor.role ?? null,
    })
  }
  const resolveActorTenant = (
    persona: string,
    rec?: VerifyTranscriptRecord,
    exchangeIds?: readonly string[],
  ): { tenant: string | null; roleLabel: string | undefined } => {
    let matchedRec = rec
    let hostEntry = matchedRec ? hostEntryByExchangeId.get(matchedRec.exchangeId) : undefined
    if (!matchedRec && !hostEntry && exchangeIds) {
      const target = persona.trim().toLowerCase()
      for (const exId of exchangeIds) {
        const candHost = hostEntryByExchangeId.get(exId)
        const candRec = recordByExchangeId.get(exId)
        const candActor = (candRec?.request?.personaHandle ?? candHost?.actorPersona ?? candHost?.step.actor.handle ?? '').trim().toLowerCase()
        if (candActor && candActor === target) { hostEntry = candHost; matchedRec = candRec; break }
      }
    }
    const pm = metaByPersona.get(persona.trim().toLowerCase())
    const tenantRef = matchedRec?.request?.actorTenant ?? hostEntry?.actorTenant ?? hostEntry?.step.actor.tenant ?? pm?.tenantRef ?? null
    const privilege = matchedRec?.request?.actorPrivilege ?? hostEntry?.actorPrivilege ?? hostEntry?.step.actor.role ?? pm?.privilege ?? null
    const roleLabel = matchedRec?.request?.actorRoleLabel ?? hostEntry?.actorRoleLabel ?? pm?.roleLabel ?? null
    const resolved = resolvePersonaIdentity({ roleLabel, tenantRef, privilege, handle: persona })
    return { tenant: resolved.tenant, roleLabel: roleLabel ?? undefined }
  }

  const ensureAttackerSeed = (persona: string, tenantScope: string, serviceOrigin: string, createdAtMs: number): string => {
    const safePersona = persona.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, 'a').slice(0, 32) || 'attacker'
    const seedCapId = formatDerivedCapabilityHandle(`seed_${safePersona}`, 'session')
    if (!ledger.getCapability(seedCapId)) {
      ledger.addCapability({
        capId: seedCapId, kind: 'identity_session', promotionStatus: 'capability_only',
        terminalImpactOracleVerified: false, provenance: 'attacker_seed', tenantScope,
        actorPersona: persona, serviceOrigin, surface: 'http',
        artifactDigest: computeArtifactDigest(`seed:${ledger.runId}:${persona}:${serviceOrigin}`),
        artifactSummary: `Attacker seed session for ${persona}`, createdAtMs: Math.max(0, Math.floor(createdAtMs)),
      })
      newCapabilityCount += 1
    }
    return seedCapId
  }

  // 1. Persist every newly sealed Layer-1 capability strictly as `capability_only`.
  for (const meta of proof.sealedCapabilities) {
    const capId = normalizeLedgerCapHandle(meta)
    const rec = recordByCapHandle.get(meta.handle)
    const actorPersona = rec?.request?.personaHandle?.trim() || defaultPersona
    const { tenant: resolvedTenant, roleLabel } = resolveActorTenant(actorPersona, rec)
    const tenantScope = resolvedTenant ?? unscopedTenant
    const serviceOrigin = rec?.request?.origin?.trim() || meta.allowedOrigins?.[0] || defaultOrigin
    const surface = rec ? mapTranscriptOpToSurface(rec.op) : 'http'
    const capKind = mapDerivedSecretKindToCapabilityKind(meta.kind)
    const nowMs = Math.max(0, Math.floor(meta.createdAtMs || Date.now()))

    if (!ledger.getCapability(capId)) {
      ledger.addCapability({
        capId, kind: capKind, promotionStatus: 'capability_only', terminalImpactOracleVerified: false,
        provenance: meta.derivedFromCapabilityId ? 'derived_hop' : 'runtime_discovery',
        tenantScope, actorPersona, serviceOrigin, surface,
        validityTtlMs: meta.expiresAtMs !== null ? Math.max(0, meta.expiresAtMs - meta.createdAtMs) : null,
        parentHopReceiptIds: [meta.hopReceiptId], artifactDigest: meta.sha256,
        artifactSummary: `Sealed ${meta.kind} slot ${meta.slot} (sha256:${meta.sha256Prefix})`,
        metadata: { slot: meta.slot, secretKind: meta.kind, ...(meta.derivedFromCapabilityId ? { parentHandle: meta.derivedFromCapabilityId } : {}) },
        createdAtMs: nowMs,
      })
      newCapabilityCount += 1
    }

    sealedSummaries.push({
      handle: meta.handle, kind: meta.kind, sha256Prefix: meta.sha256Prefix,
      ...(meta.derivedFromCapabilityId ? { derivedFromCapabilityId: meta.derivedFromCapabilityId } : {}),
    })

    // Record a verified causal hop edge for this newly sealed capability.
    const parentHandle = meta.derivedFromCapabilityId
      ? normalizeLedgerCapHandle({ handle: meta.derivedFromCapabilityId, hopReceiptId: meta.hopReceiptId, slot: 'parent' })
      : null
    const hasParentInLedger = Boolean(parentHandle && ledger.getCapability(parentHandle))
    const consumedFromTranscript = proof.transcriptRecords.find(r => r.request?.consumedCapabilityId)?.request?.consumedCapabilityId
    const hasConsumedInLedger = Boolean(consumedFromTranscript && ledger.getCapability(consumedFromTranscript))

    let preconditionCapIds: string[]
    let bindingKind: CausalEdgeBindingKind
    if (hasParentInLedger && parentHandle && parentHandle !== capId) {
      preconditionCapIds = [parentHandle]
      bindingKind = 'derived_crypto_binding'
    } else if (hasConsumedInLedger && consumedFromTranscript && consumedFromTranscript !== capId) {
      preconditionCapIds = [consumedFromTranscript]
      bindingKind = 'value_binding'
    } else {
      const seedId = ensureAttackerSeed(actorPersona, tenantScope, serviceOrigin, Math.max(0, nowMs - 1))
      preconditionCapIds = [seedId]
      bindingKind = 'value_binding'
    }

    const edgeId = `edge_cap_${createHash('sha256').update(`${ledger.runId}:${preconditionCapIds.join(',')}:${capId}:${bindingKind}`).digest('hex').slice(0, 20)}`
    if (!ledger.getCausalEdge(edgeId)) {
      const { sourceTimestampMs, targetTimestampMs } = nextMonotonicEdgeTimestamps(
        ledger, preconditionCapIds, rec?.startedAt ?? Math.max(0, nowMs - 1), nowMs,
      )
      try {
        const edge = ledger.addCausalEdge({
          edgeId, preconditionCapIds,
          actorContext: {
            persona: actorPersona,
            ...(resolvedTenant ? { tenantScope: resolvedTenant } : {}),
            ...(roleLabel ? { roleLabel } : {}),
            serviceOrigin,
          },
          hopReceiptId: meta.hopReceiptId, edgeBindingKind: bindingKind, postconditionCapId: capId,
          sourceTimestampMs, targetTimestampMs, bindingDigest: meta.sha256,
          metadata: { source: 'kovo_verify', slot: meta.slot },
        })
        newEdgeCount += 1
        verifiedHops.push({
          hopReceiptId: edge.hopReceiptId, edgeId: edge.edgeId, binding: edge.edgeBindingKind,
          postconditionCapId: edge.postconditionCapId, terminalImpact: edge.terminalImpact,
        })
      } catch {
        // Ignore cycle/duplicate edge races cleanly; capability node stays persisted.
      }
    }
  }

  // 2. If a CompositeProofReceipt was host-verified, persist its verified DAG causal edges.
  if (proof.compositeReceipt?.verification.confirmed) {
    const { receipt, hopActors } = proof.compositeReceipt
    const hopById = new Map(receipt.hops.map(hop => [hop.hopId, hop]))
    const hopRepCap = new Map<string, string>()

    for (let idx = 0; idx < receipt.hops.length; idx += 1) {
      const hop = receipt.hops[idx]!
      const persona = hopActors[hop.hopId] || defaultPersona
      const origin = hop.target.origin || defaultOrigin
      const { tenant: resolvedTenant } = resolveActorTenant(persona, undefined, hop.exchangeIds)
      const tenantScope = resolvedTenant ?? unscopedTenant
      const baseTs = Date.now() + idx

      for (const rawCap of [...hop.producedCapabilities, ...hop.consumedCapabilities]) {
        if (!DERIVED_CAPABILITY_HANDLE_RE.test(rawCap)) continue
        if (!ledger.getCapability(rawCap)) {
          ledger.addCapability({
            capId: rawCap, kind: 'scoped_token', promotionStatus: 'capability_only',
            terminalImpactOracleVerified: false, provenance: 'derived_hop', tenantScope,
            actorPersona: persona, serviceOrigin: origin, surface: hop.surface,
            parentHopReceiptIds: [hop.hopId],
            artifactDigest: computeArtifactDigest(`${receipt.chainId}:${hop.hopId}:${rawCap}`),
            artifactSummary: `Composite hop ${hop.hopId} capability`, createdAtMs: baseTs,
          })
          newCapabilityCount += 1
        }
      }
      const produced = hop.producedCapabilities.find(c => DERIVED_CAPABILITY_HANDLE_RE.test(c))
      if (produced) {
        hopRepCap.set(hop.hopId, produced)
      } else {
        const synthetic = formatDerivedCapabilityHandle(
          `${receipt.chainId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 24)}_${hop.hopId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 24)}`,
          'hop',
        )
        if (!ledger.getCapability(synthetic)) {
          ledger.addCapability({
            capId: synthetic, kind: 'state_handle', promotionStatus: 'capability_only',
            terminalImpactOracleVerified: false, provenance: idx === 0 ? 'attacker_seed' : 'derived_hop',
            tenantScope, actorPersona: persona, serviceOrigin: origin, surface: hop.surface,
            parentHopReceiptIds: [hop.hopId],
            artifactDigest: computeArtifactDigest(`${receipt.chainId}:${hop.hopId}:${hop.claimedDelta}`),
            artifactSummary: hop.claimedDelta.slice(0, 160), createdAtMs: baseTs,
          })
          newCapabilityCount += 1
        }
        hopRepCap.set(hop.hopId, synthetic)
      }
    }

    for (let i = 0; i < receipt.causalEdges.length; i += 1) {
      const edge = receipt.causalEdges[i]!
      const fromCap = (edge.kind === 'value_binding' && edge.capabilityHandle && ledger.getCapability(edge.capabilityHandle)
        ? edge.capabilityHandle
        : edge.kind === 'derived_crypto_binding' && ledger.getCapability(edge.sourceCapabilityId)
          ? edge.sourceCapabilityId
          : hopRepCap.get(edge.fromHopId))
      const toHop = hopById.get(edge.toHopId)
      const isTerminal = edge.toHopId === receipt.terminalImpact.terminalHopId
      const toCap = (edge.kind === 'derived_crypto_binding' && edge.derivedCapabilityId && ledger.getCapability(edge.derivedCapabilityId)
        ? edge.derivedCapabilityId
        : hopRepCap.get(edge.toHopId)) ?? null
      if (!fromCap || (!toCap && !isTerminal)) continue

      const edgeId = `edge_comp_${createHash('sha256').update(`${ledger.runId}:${receipt.chainId}:${i}:${edge.fromHopId}:${edge.toHopId}:${edge.kind}`).digest('hex').slice(0, 20)}`
      if (ledger.getCausalEdge(edgeId)) continue

      const persona = hopActors[edge.toHopId] || hopActors[edge.fromHopId] || defaultPersona
      const edgeActor = resolveActorTenant(persona, undefined, toHop?.exchangeIds)
      const nowMs = Date.now() + i
      const { sourceTimestampMs, targetTimestampMs } = nextMonotonicEdgeTimestamps(ledger, [fromCap], nowMs, nowMs + 1)
      try {
        const saved = ledger.addCausalEdge({
          edgeId, preconditionCapIds: [fromCap],
          actorContext: {
            persona,
            ...(edgeActor.tenant ? { tenantScope: edgeActor.tenant } : {}),
            ...(edgeActor.roleLabel ? { roleLabel: edgeActor.roleLabel } : {}),
            serviceOrigin: toHop?.target.origin || defaultOrigin,
          },
          hopReceiptId: edge.toHopId, edgeBindingKind: edge.kind,
          ...(toCap && toCap !== fromCap ? { postconditionCapId: toCap } : {}),
          ...(isTerminal ? { terminalImpact: receipt.terminalImpact.claimedImpact } : {}),
          sourceTimestampMs, targetTimestampMs,
          metadata: { chainId: receipt.chainId, terminalVulnClass: receipt.terminalVulnClass },
        })
        newEdgeCount += 1
        verifiedHops.push({
          hopReceiptId: saved.hopReceiptId, edgeId: saved.edgeId, binding: saved.edgeBindingKind,
          postconditionCapId: saved.postconditionCapId, terminalImpact: saved.terminalImpact,
        })
      } catch {
        // Ignore cycle/duplicate races; verified composite receipt remains authoritative.
      }
    }

    // Mark ONLY the terminal hop's non-quarantined capability (if any) terminal_eligible.
    const terminalCap = hopRepCap.get(receipt.terminalImpact.terminalHopId)
    if (terminalCap) {
      const terminalNode = ledger.getCapability(terminalCap)
      if (terminalNode && !ALWAYS_QUARANTINED_KINDS.has(terminalNode.kind)) {
        try { ledger.markTerminalEligible(terminalCap, receipt.chainId) } catch { /* stay quarantined if constrained */ }
      }
    }
  }

  return { sealedCapabilities: sealedSummaries, verifiedHops, newCapabilityCount, newEdgeCount }
}

/** H-20: Run-scoped request-side carrier recorded for late async OOB callback promotion. */
export interface OobCarrierRecord {
  exchangeId: string
  origin: string
  method: string
  pathAndQuery: string
  status: number
  personaHandle: string | null
  assignmentId: string | null
  reqHeaders: Record<string, string>
  respHeaders: Record<string, string>
  requestBody: string
  responseBody: string
}

/**
 * H-18 step 7: Select a replay spec for OOB promotion strictly by structured fields
 * (`origin`, `recipe.args.oobSubscriptionId`/`subscriptionId`, `agentScript.exchangeIds`,
 * or top-level `oobSubscriptionId`) rather than substring-scanning `JSON.stringify(row.spec)`.
 */
export function findOobMatchingReplaySpec(
  specs: readonly ReplaySpecRow[],
  input: { subscriptionId: string; carrierExchangeId: string; origin: string; cwe?: string },
): ReplaySpecRow | undefined {
  const targetOrigin = normalizeOrigin(input.origin)
  return specs.find(row => {
    const specRecord = row.spec as Record<string, unknown>
    const specOrigin = typeof row.spec.origin === 'string' ? normalizeOrigin(row.spec.origin) : ''
    if (specOrigin && specOrigin !== targetOrigin) return false
    if (typeof specRecord.oobSubscriptionId === 'string' && specRecord.oobSubscriptionId === input.subscriptionId) {
      return true
    }
    const recipe = specRecord.recipe as { args?: Record<string, unknown> } | undefined
    const recipeArgs = recipe && typeof recipe === 'object' ? recipe.args : undefined
    if (recipeArgs && typeof recipeArgs === 'object') {
      if (recipeArgs.oobSubscriptionId === input.subscriptionId || recipeArgs.subscriptionId === input.subscriptionId) {
        return true
      }
      if (recipeArgs.carrierExchangeId === input.carrierExchangeId) {
        return true
      }
    }
    const agentScript = persistedAgentScriptOf(row.spec)
    if (agentScript?.envelope.exchangeIds.includes(input.carrierExchangeId)) {
      return true
    }
    return false
  })
}

export class ExecVerifier extends ExecServiceModule<ExecVerifyHost> {
  private readonly fallbackVaults = new Map<string, DerivedCapabilityVault>()
  private readonly oobCarriersByRun = new Map<string, Map<string, OobCarrierRecord>>()

  /** H-20: Record a host-observed request-side carrier for a canary token so late OOB callbacks promote reliably. */
  recordOobCarrier(runId: string, token: string, carrier: OobCarrierRecord): void {
    const cleanToken = token.trim()
    if (!runId || !cleanToken) return
    const reqSide = `${carrier.pathAndQuery}\n${JSON.stringify(carrier.reqHeaders ?? {})}\n${carrier.requestBody ?? ''}`
    if (!reqSide.includes(cleanToken)) return
    let byToken = this.oobCarriersByRun.get(runId)
    if (!byToken) {
      byToken = new Map<string, OobCarrierRecord>()
      this.oobCarriersByRun.set(runId, byToken)
    }
    byToken.set(cleanToken, carrier)
  }

  getOobCarrier(runId: string, token: string): OobCarrierRecord | undefined {
    return this.oobCarriersByRun.get(runId)?.get(token.trim())
  }

  clearOobCarriers(runId: string): void {
    this.oobCarriersByRun.delete(runId)
  }

  /** Return the shared run-scoped Layer-1 DerivedCapabilityVault across worker sessions. */
  capabilityVaultFor(runId: string): DerivedCapabilityVault {
    if (this.host.capabilityVaultFor) return this.host.capabilityVaultFor(runId)
    let vault = this.fallbackVaults.get(runId)
    if (!vault) {
      vault = new DerivedCapabilityVault({ runId: safeVaultRunId(runId) })
      this.fallbackVaults.set(runId, vault)
    }
    return vault
  }

  /** Execute a `kovo_verify` script bound to this run's shared `DerivedCapabilityVault`. */
  async runAgentScriptProof(
    params: Omit<V8AgentScriptProofParams, 'broker' | 'backend' | 'canaryBroker' | 'capabilityVault'> & {
      capabilityVault?: DerivedCapabilityVault
    },
  ): Promise<V8AgentScriptProofResult> {
    const result = await runAgentScriptProof({
      ...params,
      broker: this.broker,
      backend: this.backend,
      canaryBroker: this.canaryBroker,
      capabilityVault: params.capabilityVault ?? this.capabilityVaultFor(params.runId),
    })
    // H-20: Index any request-side canary carriers from `prove.oob` / `kovo_verify` exchanges into
    // the run-scoped OOB carrier map so late callbacks promote even when exchanges are not in SQLite.
    const mintedTokens = new Set<string>()
    for (const rec of result.transcriptRecords ?? []) {
      const resp = rec.response && typeof rec.response === 'object' ? rec.response as unknown as Record<string, unknown> : null
      if (typeof resp?.token === 'string' && resp.token.trim().length >= 8) {
        mintedTokens.add(resp.token.trim())
      }
      const handle = resp?.handle && typeof resp.handle === 'object' ? resp.handle as Record<string, unknown> : null
      if (typeof handle?.token === 'string' && handle.token.trim().length >= 8) {
        mintedTokens.add(handle.token.trim())
      }
    }
    if (mintedTokens.size > 0) {
      for (const token of mintedTokens) {
        const carrierEx = result.exchanges.find(ex => {
          const reqSide = `${ex.pathAndQuery}\n${JSON.stringify(ex.requestHeaders ?? {})}\n${ex.requestBody ?? ''}`
          return reqSide.includes(token)
        })
        if (carrierEx) {
          this.recordOobCarrier(params.runId, token, {
            exchangeId: carrierEx.exchangeId,
            origin: carrierEx.origin,
            method: carrierEx.method.toUpperCase(),
            pathAndQuery: carrierEx.pathAndQuery,
            status: carrierEx.status ?? 0,
            personaHandle: carrierEx.personaHandle ?? null,
            assignmentId: params.assignmentId,
            reqHeaders: carrierEx.requestHeaders ?? {},
            respHeaders: carrierEx.responseHeaders ?? {},
            requestBody: carrierEx.requestBody ?? '',
            responseBody: carrierEx.body ?? '',
          })
        }
      }
    }
    return result
  }

  /** Persist sealed capabilities and verified hops from a `kovo_verify` run into `CapabilityLedger`. */
  syncVerifyArtifactsToLedger(input: {
    runId: string
    proof: V8AgentScriptProofResult
    defaultOrigin: string
    defaultPersona?: string
  }): SyncVerifyArtifactsResult {
    return syncVerifyArtifactsToLedger({
      ledger: this.storage.capabilityLedger(input.runId),
      proof: input.proof,
      defaultOrigin: input.defaultOrigin,
      ...(input.defaultPersona ? { defaultPersona: input.defaultPersona } : {}),
    })
  }

  private addReplayReceiptArtifact(
    run: Run,
    assignment: Assignment,
    title: string,
    specRow: ReplaySpecRow,
    spec: DeclarativeReplaySpec,
    finalStatus: string,
    verificationTier: VerificationTier | undefined,
    result: ReplayVerificationResult,
    secrets: readonly NamedSecret[],
    extra?: { tag?: string; attemptCount?: number; feedback?: InlineVerifyFeedback; sourceOrigins?: string[] },
  ) {
    return this.storage.addArtifact(
      run, assignment, 'replay', title,
      JSON.stringify({
        replaySpecId: specRow.id,
        ...(extra?.attemptCount !== undefined ? { attemptCount: extra.attemptCount } : {}),
        specSha256: specRow.specSha256,
        kind: spec.kind,
        origin: spec.origin,
        verdict: finalStatus,
        verificationTier: verificationTier ?? null,
        outcome: result.outcome,
        ...(extra?.feedback ? { feedback: extra.feedback } : {}),
        exchangeIds: result.exchangeIds,
        ...(extra?.sourceOrigins ? { sourceOrigins: extra.sourceOrigins } : {}),
        evidenceSha256: result.evidenceSha256,
        evidencePayload: result.evidencePayload,
        receipt: result.receipt?.verification ?? null,
        receiptArtifact: result.receipt?.receipt ?? null,
      }, null, 2),
      extra?.tag,
      secrets,
    )
  }

  private persistReplayConfirmation(
    run: Run,
    assignment: Assignment,
    findingRow: Pick<typeof findings.$inferSelect, 'id' | 'assetId' | 'finding'>,
    spec: DeclarativeReplaySpec,
    specRowId: string,
    origins: string[],
    updatedFinding: Finding,
    result: ReplayVerificationResult,
    finalStatus: Finding['status'],
    cancelSiblingStepId?: string | null,
  ): void {
    // H-18: If the finding is already runtime_confirmed, preserve its immutable core identity
    // (CWE, origin, title, category, fingerprintHash); otherwise bind identity strictly to the
    // confirming spec & receipt before persisting.
    const alreadyRuntimeConfirmed = findingRow.finding.status === 'confirmed'
    const boundFinding = alreadyRuntimeConfirmed
      ? {
          ...updatedFinding,
          cwe: findingRow.finding.cwe,
          origin: findingRow.finding.origin,
          title: findingRow.finding.title,
          category: findingRow.finding.category,
          fingerprintHash: findingRow.finding.fingerprintHash,
        }
      : bindConfirmedFindingIdentity(updatedFinding, spec, result)
    this.storage.upsertChainFinding(run, findingRow.assetId, boundFinding, specRowId, origins)
    recordReportedFindingCoverage(
      this.storage, run, assignment.id, boundFinding.origin, boundFinding.category ?? spec.category,
      `${finalStatus === 'static_verified' ? 'Static verified' : 'Confirmed'}: ${boundFinding.title}`,
      findingRow.id, (r, o) => this.host.permitted(r, o),
    )
    if (cancelSiblingStepId !== undefined) this.host.cancelSiblingTrialsOnConfirmation(run, cancelSiblingStepId, findingRow.id)
    const refreshedRow = findFindingRow(this.storage, run.id, findingRow.id)
    if (refreshedRow) this.host.scheduleVariantSweepForFinding(run, refreshedRow)
  }

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
   * This waits up to `KOVO_OOB_DRAIN_MS` (default 45 s), promotes late callbacks on every poll,
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
      // H-20: The exact request that carried the canary is the causal binding; consult the
      // run-scoped request-side carrier map first (captures `prove.oob` / `kovo_verify` injections
      // that bypass `broker_exchanges`), then fall back to stored exchanges using request-side
      // fields ONLY (never echo-only response bodies).
      const recordedCarrier = this.getOobCarrier(runId, subscription.token)
      let carrier: {
        id: string
        origin: string
        method: string
        pathAndQuery: string
        status: number
        personaHandle: string | null
        assignmentId: string | null
        reqHeaders: Record<string, string>
        respHeaders: Record<string, string>
        bodyPreview: string
        requestBody?: string
      } | undefined
      if (recordedCarrier && approved.has(recordedCarrier.origin)) {
        const reqSide = `${recordedCarrier.pathAndQuery}\n${JSON.stringify(recordedCarrier.reqHeaders ?? {})}\n${recordedCarrier.requestBody ?? ''}`
        if (reqSide.includes(subscription.token)) {
          carrier = {
            id: recordedCarrier.exchangeId,
            origin: recordedCarrier.origin,
            method: recordedCarrier.method,
            pathAndQuery: recordedCarrier.pathAndQuery,
            status: recordedCarrier.status,
            personaHandle: recordedCarrier.personaHandle,
            assignmentId: recordedCarrier.assignmentId,
            reqHeaders: recordedCarrier.reqHeaders,
            respHeaders: recordedCarrier.respHeaders,
            bodyPreview: recordedCarrier.responseBody.slice(0, 4_096),
            requestBody: recordedCarrier.requestBody,
          }
        }
      }
      if (!carrier) {
        try {
          const found = this.storage.searchExchanges(runId, subscription.token, { approvedOrigins: approved, limit: 10 })
            .find(ex => [ex.pathAndQuery, JSON.stringify(ex.reqHeaders ?? {})]
              .some(text => String(text).includes(subscription.token)))
          if (found) {
            carrier = {
              id: found.id,
              origin: found.origin,
              method: found.method,
              pathAndQuery: found.pathAndQuery,
              status: found.status,
              personaHandle: found.personaHandle,
              assignmentId: found.assignmentId,
              reqHeaders: found.reqHeaders ?? {},
              respHeaders: found.respHeaders ?? {},
              bodyPreview: found.bodyPreview,
            }
          }
        } catch { carrier = undefined }
      }
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
      if (carrier.requestBody === undefined) {
        try { body = this.storage.getExchange(runId, carrier.id).body } catch { /* preview is enough */ }
      }
      const carrierText = [
        carrier.pathAndQuery,
        JSON.stringify(carrier.reqHeaders ?? {}),
        carrier.requestBody ?? '',
      ].filter(Boolean).join('\n')
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
          carrierText,
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
    carrier: { id: string; assignmentId: string | null }
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

    // H-18 step 7: Select the replay spec strictly by structured fields (origin + oobSubscriptionId /
    // carrierExchangeId), never by substring-scanning `JSON.stringify(row.spec)`.
    let specRow: ReplaySpecRow | undefined
    try {
      specRow = findOobMatchingReplaySpec(this.storage.listReplaySpecs(run.id), {
        subscriptionId: input.subscriptionId,
        carrierExchangeId: input.carrier.id,
        origin: input.origin,
        cwe: template.cwe,
      })
    } catch { specRow = undefined }
    const specExisting = specRow ? rows.find(row => row.id === specRow!.findingId) : undefined
    const existing = specExisting && (specExisting.finding.status !== 'confirmed' || specExisting.finding.cwe === template.cwe)
      ? specExisting
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
    const emitOobReceiptConfirmed = () => {
      try {
        this.storage.event(run.id, 'oob.receipt_confirmed',
          `Late ${input.vulnClass.toUpperCase()} callback promoted to a runtime_confirmed finding (${input.verification.reason.slice(0, 200)}).`, {
            findingId,
            oobSubscriptionId: input.subscriptionId,
            exchangeId: input.carrier.id,
            rule: input.verification.rule,
          })
      } catch { /* metrics/coverage are best-effort */ }
    }
    emitOobReceiptConfirmed()
    if (specRow) {
      const existingProof = this.storage.replaySpecProof(run.id, specRow.id)
      const receiptRow = serializeProofReceiptRow({ receipt: input.receipt, verification: input.verification })
      if (existingProof) {
        this.storage.setReplaySpecProof(run.id, specRow.id, {
          ...existingProof,
          verdict: 'confirmed',
          receipt: receiptRow,
        })
      } else {
        this.storage.setReplaySpecProof(run.id, specRow.id, {
          replaySpecId: specRow.id,
          findingId,
          verdict: 'confirmed',
          runtime: 'ts',
          scriptSha256: specRow.specSha256,
          artifactId: evidence.id,
          receipt: receiptRow,
          createdAt: Date.now(),
        })
      }
      this.storage.upsertChainFinding(run, asset.id, finding, specRow.id, specRow.sourceOrigins)
    } else {
      this.storage.upsertFindingRecord({
        runId: run.id,
        assetId: asset.id,
        goalRevision: run.goalRevision,
        findingId,
        existingId: existing?.id ?? null,
        checkId: 'chain',
        caseId: findingId,
        findingKind: 'multi_step_chain',
        replaySpecId: null,
        sourceOrigins: [input.origin],
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        verificationClass: 'runtime_confirmed',
        finding,
      })
    }
    try {
      this.storage.upsertCoverageEntry(run, assignment.id, {
        origin: input.origin,
        category: template.coverageCategory,
        status: 'reported',
        summary: `Confirmed async ${input.vulnClass.toUpperCase()} via ProofReceipt ${input.subscriptionId}`,
        linkedFindingId: findingId,
      })
    } catch { /* metrics/coverage are best-effort */ }
    return true
  }


  async verifyReplaySpecJob(job: Active, replaySpecId: string) {
    const run = this.host.check(job)
    const specRow = this.storage.getReplaySpec(run.id, replaySpecId)
    const findingRow = findFindingRow(this.storage, run.id, specRow.findingId)
    if (!findingRow) {
      this.host.completeWorker(job.assignment, run, 'Finding no longer exists.', [])
      return
    }

    const permittedAtAdmission = this.host.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.host.buildGrant(job, run, permittedAtAdmission)
    const { reposDir } = this.host.projectReposMount(run.projectId)

    if (
      specRow.spec.kind === 'static_ast_proof'
      && isLiveRuntimeVerificationRun(run, this.backendSupportsVerifyScript())
    ) {
      const current = this.host.check(job)
      const updatedFinding: Finding = {
        ...findingRow.finding,
        status: 'dismissed',
        verificationTier: undefined,
        confidence: 'low',
        reason: STATIC_AST_LIVE_TARGET_REJECT_MESSAGE,
        verification: 'Dismissed: static_ast_proof is disallowed as a standalone finding on live-target runtime verification runs.',
      }
      this.demoteFindingToNonConfirmed(current, findingRow.id, { verificationTier: null, finding: updatedFinding })
      this.host.completeWorker(
        job.assignment,
        current,
        'Dismissed: static_ast_proof is disallowed on live-target runtime verification runs.',
        [],
        undefined,
        secrets,
      )
      return
    }

    await this.ensureCanaryListenerForSpec(specRow.spec)

    // Tier 3 HITL gate for rce_proof specs on non-local-lab targets (upload_probe is retired).
    if (specRow.spec.kind === 'rce_proof') {
      const gateReq = buildTier3VerifyGateReq(
        specRow.spec,
        'Zero-LLM non-destructive PoE verification',
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
        this.restoreSupersededDependents(current, findingRow.id)
        this.host.completeWorker(job.assignment, current, 'Inconclusive: Tier 3 approval denied.', [], undefined, secrets)
        return
      }
    }

    const verifyParams = {
      ...this.baseReplayRunnerParams(
        specRow.spec, run.id, job.assignment.id, grant, job.controller.signal, reposDir,
        createExchangeRecorder(this.storage, () => run, job.assignment.id, currentSecrets, {
          trackResources: true,
          markCoverage: (r, o, m, p) => this.host.markEndpointCoverage(r, o, m, p, `replay:${specRow.spec.kind}`),
        }),
      ),
      envelopeTrust: findingRow.provenance === 'floor' ? 'host_persisted' as const : 'untrusted' as const,
    }
    const result = await verifyReplaySpec(verifyParams)
    this.host.markReplaySpecCoverage(run, specRow.spec, `replay:${specRow.spec.kind}`)
    if (result.receipt && !result.receipt.verification.confirmed) {
      // Receipt rejection telemetry (strict mode vetoes confirmation; shadow mode is advisory).
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
      const secretsList = currentSecrets()
      const receipt = this.addReplayReceiptArtifact(
        current, job.assignment, `${isStaticAst ? 'Deterministic Static AST' : 'Zero-LLM replay'} · ${specRow.spec.title}`,
        specRow, specRow.spec, finalStatus, verificationTier, result, secretsList,
        { tag: 'replay:' + specRow.id, sourceOrigins: specRow.sourceOrigins },
      )
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
        specRow.spec, result, Math.max(1, specRow.attemptCount), maxInlineVerifyRetries, secretsList,
      )
      phaseFeedback = rawFeedback
      this.host.recordSpecVerification(
        current.id, specRow.id, rawFeedback,
        `phase3 ${specRow.spec.kind} attempt ${specRow.attemptCount} returned ${finalStatus}`,
      )
      if (finalStatus === 'confirmed' || finalStatus === 'static_verified') {
        this.persistReplayConfirmation(
          current, job.assignment, findingRow, specRow.spec, specRow.id, specRow.sourceOrigins, updatedFinding, result, finalStatus,
        )
      } else {
        this.demoteFindingToNonConfirmed(current, findingRow.id, { verificationTier: null, finding: updatedFinding })
      }
      this.host.completeWorker(
        job.assignment, current, `Replay verdict: ${finalStatus} (${cleanObserved.slice(0, 160)})`, [receipt.id], undefined, secretsList,
      )
    }, { behavior: 'immediate' })
    const refreshed = findFindingRow(this.storage, current.id, findingRow.id)
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


  /** Resolve a workspace-relative script path inside the read-only repo mount, bounded and H-39 filtered. */
  readAgentProofScript(reposDir: string | undefined, scriptPath: string): string {
    if (!reposDir) throw new Error('kovo_verify scriptPath requires a mounted workspace; pass `script` inline.')
    const clean = scriptPath.trim().replace(/^\/+/, '')
    if (!clean || clean.includes('\0') || clean.split(/[\\/]/).includes('..')) {
      throw new Error('kovo_verify scriptPath must stay inside the mounted workspace.')
    }
    if (isSensitiveRepoRelativePath(clean)) {
      throw new Error('kovo_verify scriptPath cannot read sensitive repository files.')
    }
    const full = join(reposDir, clean)
    if (!full.startsWith(reposDir + sep) || !existsSync(full)) {
      throw new Error('kovo_verify scriptPath was not found in the mounted workspace; pass the script inline via `script` instead.')
    }
    let realRoot: string
    let realFull: string
    try {
      realRoot = realpathSync(reposDir)
      realFull = realpathSync(full)
    } catch {
      throw new Error('kovo_verify scriptPath was not found in the mounted workspace; pass the script inline via `script` instead.')
    }
    if (!realFull.startsWith(realRoot + sep)) {
      throw new Error('kovo_verify scriptPath must stay inside the mounted workspace.')
    }
    const resolvedRelPosix = relative(realRoot, realFull).split(sep).join('/')
    if (isSensitiveRepoRelativePath(resolvedRelPosix)) {
      throw new Error('kovo_verify scriptPath cannot read sensitive repository files.')
    }
    const st = statSync(realFull)
    if (!st.isFile()) {
      throw new Error('kovo_verify scriptPath must reference a regular file.')
    }
    if (st.size <= 0 || st.size > 64 * 1024) throw new Error('kovo_verify script must be between 1 byte and 64 KiB.')
    return readFileSync(realFull, 'utf8')
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
    runtime: 'ts'
    title?: string
    proof: AgentScriptProofResult | V8AgentScriptProofResult
    secrets: readonly NamedSecret[]
  }): { findingId: string; replaySpecId: string; receiptId: string | null } {
    if (input.runtime !== 'ts') {
      throw new Error(`Unsupported kovo_verify runtime: ${String(input.runtime)}. kovo_verify supports TypeScript only (runtime='ts').`)
    }
    const { run, assignment, proof } = input
    const compositeBundle = 'compositeReceipt' in proof ? proof.compositeReceipt : null
    const singleConfirmed = Boolean(proof.receipt && proof.receipt.verification.confirmed)
    const compositeConfirmed = Boolean(compositeBundle && compositeBundle.verification.confirmed)
    if (!proof.verdict.confirmed || (!singleConfirmed && !compositeConfirmed)) {
      throw new InvariantError(
        'invariant.confirmation_evidence',
        `Invariant: refusing to persist an agent script proof without a verified ProofReceipt or CompositeProofReceipt (verdict=${proof.verdict.reason}, hasReceipt=${Boolean(proof.receipt)}, hasComposite=${Boolean(compositeBundle)}).`,
      )
    }
    const vault = this.capabilityVaultFor(run.id)
    const allSecrets: NamedSecret[] = [...input.secrets, ...vaultScrubDescriptors(vault)]
    const receipt = proof.receipt?.receipt ?? null
    const verification = proof.receipt?.verification ?? null
    const cleanCompositeBundle: V8CompositeProofBundle | null = compositeConfirmed && compositeBundle
      ? {
          receipt: redactJsonValue(compositeBundle.receipt, allSecrets),
          verification: redactJsonValue(compositeBundle.verification, allSecrets),
          hopActors: compositeBundle.hopActors,
        }
      : null
    const claim = cleanCompositeBundle?.receipt.terminalVulnClass ?? receipt?.vulnClass ?? 'disclosure'
    const attribution = agentProofAttribution(claim)
    // R3-H-15: Derive composite finding origin strictly from the terminal exchange's host-signed
    // `origin` in the transcript — NEVER from worker-declared `hops[terminal].target.origin`.
    // Reject/fail closed if the declared hop origin disagrees with its cited host-signed exchange.
    const hostExchangeById = buildHostRecordedExchangeIndex(proof)
    let compositeTerminalExchange: HostRecordedExchangeView | null = null
    let origin: string | undefined
    if (cleanCompositeBundle) {
      const originCheck = inspectCompositeHostOrigin(cleanCompositeBundle.receipt, hostExchangeById)
      if (!originCheck.ok) {
        throw new InvariantError('invariant.confirmation_evidence', originCheck.reason)
      }
      origin = originCheck.origin
      compositeTerminalExchange = originCheck.terminalExchange
    } else {
      const receiptExchange = (() => {
        const ids = receipt?.exchangeIds ?? []
        const matched = ids.map(id => hostExchangeById.get(id)).filter((ex): ex is HostRecordedExchangeView => Boolean(ex && ex.origin))
        return matched.find(ex => ex.sessionRole === 'probe') ?? matched[0]
      })()
      if (receiptExchange?.origin && receipt?.target.origin && normalizeOrigin(receipt.target.origin) !== normalizeOrigin(receiptExchange.origin)) {
        throw new InvariantError(
          'invariant.confirmation_evidence',
          `ProofReceipt declared origin "${receipt.target.origin}" disagrees with host-signed exchange "${receiptExchange.exchangeId}" origin "${receiptExchange.origin}".`,
        )
      }
      origin = receiptExchange?.origin
        ?? receipt?.target.origin
        ?? proof.exchanges.find(exchange => exchange.sessionRole === 'probe')?.origin
        ?? proof.exchanges[0]?.origin
    }
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
    // R2-H-16: Never heuristically redact the executable script persisted in `envelope.script`
    // (heuristic keyword regexes corrupt JWT/password/Bearer literals and turn live findings into
    // `fixed`/`dismissed` on retest). Apply exact-known-secret substitution at most; if any known
    // secret was scrubbed, the sha256 check on re-execution will safely return `inconclusive`.
    const executableScript = scrubDerivedSecrets(redactExactValues(input.script, allSecrets), vault)
    const scriptDisplay = scrubDerivedSecrets(redact(input.script, allSecrets), vault)
    const cleanTitle = scrubDerivedSecrets(redact(title, allSecrets), vault)

    const artifact = this.storage.addArtifact(
      run,
      assignment,
      'replay',
      `Agent proof script · ${cleanTitle}`,
      JSON.stringify({
        mode: cleanCompositeBundle ? 'agent_script_composite' : 'agent_script',
        runtime: input.runtime,
        scriptSha256,
        script: scriptDisplay,
        receipt,
        verification,
        ...(cleanCompositeBundle ? {
          compositeReceipt: cleanCompositeBundle.receipt,
          compositeVerification: cleanCompositeBundle.verification,
          hopActors: cleanCompositeBundle.hopActors,
        } : {}),
        transcriptDigests: proof.transcriptDigests,
      }, null, 2),
      `agent-proof:${scriptSha256}`,
      allSecrets,
    )

    const compositeExchangeIds = cleanCompositeBundle
      ? [...new Set([
          ...cleanCompositeBundle.receipt.hops.flatMap(h => h.exchangeIds),
          ...cleanCompositeBundle.receipt.terminalImpact.preChainControlExchangeIds,
          ...cleanCompositeBundle.receipt.terminalImpact.postChainReadbackExchangeIds,
        ])]
      : []
    const envelope: AgentScriptProofEnvelope = {
      kind: 'agent_script',
      runtime: input.runtime,
      script: executableScript,
      scriptSha256,
      verdict: 'confirmed',
      ...(claim ? { vulnClass: claim } : {}),
      exchangeIds: [...new Set([...compositeExchangeIds, ...proof.exchanges.map(exchange => exchange.exchangeId)])].slice(0, 64),
      transcriptDigests: proof.transcriptDigests.slice(0, 4),
      receiptArtifactId: artifact.id,
      confirmedAt: Date.now(),
    }
    const feedback: InlineVerifyFeedback = {
      verdict: 'confirmed',
      verificationTier: 'runtime_confirmed',
      controlPassed: proof.verdict.attempts.every(attempt => attempt.oraclePassed),
      assertionSummary: {
        observed: cleanCompositeBundle
          ? `${cleanCompositeBundle.verification.hopCount}-hop CompositeProofReceipt (${cleanCompositeBundle.receipt.chainId}) confirmed across ${proof.verdict.attempts.length} fresh runs.`
          : verification?.observed ?? `${proof.verdict.attempts.length} signed script runs confirmed the claim.`,
        expected: cleanCompositeBundle
          ? 'every hop, causal edge binding, and attacker-origin provenance verifies over host-signed transcripts'
          : verification?.expected ?? 'the claimed impact is re-derivable from the recorded transcript',
        ...(cleanCompositeBundle?.verification.reason
          ? { reason: cleanCompositeBundle.verification.reason }
          : verification?.reason
            ? { reason: verification.reason }
            : {}),
      },
      stepStatuses: [],
      retriesRemaining: maxInlineVerifyRetries,
    }
    const baseSpec = this.agentProofAttributionSpec({
      origin,
      title: cleanTitle,
      attribution,
      severity,
      envelope,
      proof,
      receipt,
    })
    const proofTarget = extractAgentProofTarget({
      cleanCompositeBundle,
      receipt,
      baseSpec,
      proof,
      envelope,
    })
    const computedFingerprint = proofTarget.endpoint
      ? computeFindingFingerprint({
          origin,
          cwe: attribution.cwe,
          category: attribution.category,
          endpoint: proofTarget.endpoint,
          method: proofTarget.method,
        })
      : null
    const fingerprintHash = computedFingerprint?.hash
    const incomingCompositeSig = cleanCompositeBundle ? extractCompositeChainDedupSignature({ origin, compositeReceipt: cleanCompositeBundle.receipt, compositeVerification: cleanCompositeBundle.verification, hostExchanges: hostExchangeById }) : null
    const primaryDup = this.storage.findDuplicateChainFinding(run.id, run.goalRevision, {
      origin,
      cwe: attribution.cwe,
      category: attribution.category,
      title: cleanTitle,
      ...(proofTarget.endpoint ? { endpoint: proofTarget.endpoint } : {}),
      ...(proofTarget.method ? { method: proofTarget.method } : {}),
      ...(fingerprintHash ? { fingerprintHash } : {}),
      ...(incomingCompositeSig ? { compositeSignature: incomingCompositeSig } : {}),
    })
    const existingDup = primaryDup ?? this.findCorroboratingAgentProofFinding(run, {
      origin,
      cwe: attribution.cwe,
      category: attribution.category,
      normalizedEndpoint: proofTarget.normalizedEndpoint,
      method: proofTarget.method,
      terminalOracleFamily: proofTarget.terminalOracleFamily,
      compositeSignature: incomingCompositeSig,
    })
    const findingId = existingDup?.id ?? randomUUID()
    const effectiveFingerprintHash = existingDup?.fingerprintHash ?? existingDup?.finding.fingerprintHash ?? fingerprintHash
    const existingCanonicalSpecId = existingDup?.replaySpecId ?? existingDup?.finding.replaySpecId ?? null
    const existingSpecRow = existingDup && existingCanonicalSpecId
      ? this.storage.listReplaySpecsForFinding(run.id, existingDup.id).find(s => s.id === existingCanonicalSpecId)
      : undefined
    const existingHasComposite = Boolean(existingDup && existingRowHasCompositeProof(existingDup, existingSpecRow))
    const incomingUpgradesComposite = Boolean(
      cleanCompositeBundle && existingDup && compositeChainRichnessScore(incomingCompositeSig) > compositeChainRichnessScore(extractRowCompositeSignature(existingDup, existingSpecRow)))
    const reuseExistingConfirmedSpec = Boolean(existingDup && existingDup.finding.status === 'confirmed' && existingCanonicalSpecId && (!cleanCompositeBundle || (existingHasComposite && !incomingUpgradesComposite)))

    let canonicalSpecId: string
    if (reuseExistingConfirmedSpec) {
      canonicalSpecId = existingCanonicalSpecId!
    } else {
      const spec: DeclarativeReplaySpec = cleanCompositeBundle
        ? ({
            ...baseSpec,
            compositeReceipt: cleanCompositeBundle.receipt,
            compositeVerification: cleanCompositeBundle.verification,
          } as unknown as DeclarativeReplaySpec)
        : baseSpec
      const proofReceiptRow: ReplayProofReceiptRow | null = cleanCompositeBundle
        ? serializeCompositeProofReceiptRow(
            cleanCompositeBundle,
            receipt && verification ? { receipt, verification } : null,
            compositeTerminalExchange,
          )
        : receipt && verification
          ? serializeProofReceiptRow({ receipt, verification })
          : null
      const proofRecord: AgentScriptProofRecord = {
        replaySpecId: '',
        findingId,
        verdict: 'confirmed',
        runtime: input.runtime,
        scriptSha256,
        artifactId: artifact.id,
        receipt: proofReceiptRow,
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
      canonicalSpecId = specRow.id
    }

    const incomingExchangeIds = compositeExchangeIds.length
      ? compositeExchangeIds
      : receipt?.exchangeIds?.length
        ? [...receipt.exchangeIds]
        : envelope.exchangeIds

    const finding: Finding & { evidence?: Record<string, unknown> } = reuseExistingConfirmedSpec && existingDup
      ? {
          ...existingDup.finding,
          id: existingDup.id,
          // H-18: Preserve immutable confirmed identity (cwe, origin, title, category, fingerprintHash, severity).
          ...(effectiveFingerprintHash && !existingDup.finding.fingerprintHash ? { fingerprintHash: effectiveFingerprintHash } : {}),
          replaySpecId: canonicalSpecId,
          exchangeIds: [...new Set([...(existingDup.finding.exchangeIds ?? []), ...incomingExchangeIds])],
          evidenceIds: [...new Set([...existingDup.finding.evidenceIds, artifact.id])],
          scopeRevision: run.scopeRevision,
        }
      : {
          id: findingId,
          origin,
          title: cleanTitle,
          status: 'confirmed',
          severity,
          reason: cleanCompositeBundle?.verification.reason ?? verification?.reason ?? proof.verdict.detail ?? 'Confirmed by a Layer-3 verification script.',
          remediation: attribution.remediation,
          impact: cleanCompositeBundle?.receipt.terminalImpact.claimedImpact ?? receipt?.claimedDelta ?? attribution.impact,
          recheck: `Re-run the persisted ${input.runtime} proof script and re-validate its receipt.`,
          category: attribution.category,
          cwe: attribution.cwe,
          confidence: 'high',
          verification: cleanCompositeBundle
            ? `ProofReceipt (Composite) ${cleanCompositeBundle.receipt.chainId} · ${cleanCompositeBundle.verification.hopCount} hops · ${cleanCompositeBundle.receipt.replayMode} · ${cleanCompositeBundle.verification.reason}`
            : receipt
              ? `ProofReceipt ${receipt.exchangeIds[0] ?? scriptSha256.slice(0, 12)} · ${verification?.rule ?? 'receipt'} rule · ${verification?.reason ?? 'verified'}`
              : `Layer-3 script proof (${input.runtime}) · ${proof.verdict.attempts.length} signed runs · digest ${proof.transcriptDigests[0]?.slice(0, 12) ?? 'n/a'}`,
          verificationTier: 'runtime_confirmed',
          findingKind: 'multi_step_chain',
          ...(effectiveFingerprintHash ? { fingerprintHash: effectiveFingerprintHash } : {}),
          replaySpecId: canonicalSpecId,
          exchangeIds: existingDup ? [...new Set([...(existingDup.finding.exchangeIds ?? []), ...incomingExchangeIds])] : incomingExchangeIds,
          evidenceIds: existingDup ? [...new Set([...existingDup.finding.evidenceIds, artifact.id])] : [artifact.id],
          ...(cleanCompositeBundle ? {
            evidence: {
              compositeReceipt: cleanCompositeBundle.receipt,
              compositeVerification: cleanCompositeBundle.verification,
              hopActors: cleanCompositeBundle.hopActors,
              ...(cleanCompositeBundle.verification.terminalOracleFamily ? { terminalOracleFamily: cleanCompositeBundle.verification.terminalOracleFamily } : {}),
              ...(cleanCompositeBundle.verification.terminalEndpoint ? { terminalEndpoint: cleanCompositeBundle.verification.terminalEndpoint } : {}),
            },
          } : {}),
          scopeRevision: run.scopeRevision,
        }
    const upsertAssetId = existingDup?.assetId ?? asset.id
    const upsertOrigins = existingDup
      ? [...new Set([...existingDup.sourceOrigins, origin])]
      : [origin]
    const savedFinding = this.storage.upsertChainFinding(run, upsertAssetId, finding, canonicalSpecId, upsertOrigins)
    if (cleanCompositeBundle) {
      this.supersedeUpstreamCompositeFindings(
        run,
        savedFinding.id,
        cleanCompositeBundle.receipt,
        hostExchangeById,
        cleanCompositeBundle.verification,
      )
    }
    recordReportedFindingCoverage(this.storage, run, assignment.id, origin, attribution.category, `Confirmed via agent script proof: ${cleanTitle}`, findingId, (r, o) => this.host.permitted(r, o))
    this.storage.event(run.id, 'agent.script_proof_confirmed', `Agent script proof confirmed a ${attribution.label} finding on ${origin}.`, {
      findingId,
      replaySpecId: canonicalSpecId,
      artifactId: artifact.id,
      scriptSha256,
      deduplicated: Boolean(existingDup),
      ...(effectiveFingerprintHash ? { fingerprintHash: effectiveFingerprintHash } : {}),
      ...(proofTarget.normalizedEndpoint ? { normalizedEndpoint: proofTarget.normalizedEndpoint } : {}),
      receiptRule: cleanCompositeBundle ? `composite:${cleanCompositeBundle.receipt.replayMode}` : (verification?.rule ?? null),
      ...(cleanCompositeBundle ? {
        chainId: cleanCompositeBundle.receipt.chainId,
        hopCount: cleanCompositeBundle.receipt.hops.length,
        ...(cleanCompositeBundle.verification.terminalOracleFamily ? { terminalOracleFamily: cleanCompositeBundle.verification.terminalOracleFamily } : {}),
        ...(cleanCompositeBundle.verification.terminalEndpoint ? { terminalEndpoint: cleanCompositeBundle.verification.terminalEndpoint } : {}),
      } : {}),
      transcriptDigests: proof.transcriptDigests,
    })
    return {
      findingId,
      replaySpecId: canonicalSpecId,
      receiptId: cleanCompositeBundle?.receipt.chainId ?? receipt?.exchangeIds[0] ?? null,
    }
  }

  /**
   * R3-H-13: Restore any findings previously superseded by `findingId` whenever `findingId`
   * transitions to a non-confirmed status.
   */
  private restoreSupersededDependents(run: Run, findingId: string): string[] {
    const dependentRows = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id),
      eq(findings.supersededByFindingId, findingId),
    )).all()
    const restoredIds: string[] = []
    for (const dep of dependentRows) {
      this.storage.updateProposedFinding(run, dep.id, {
        supersededByFindingId: null,
      })
      restoredIds.push(dep.id)
    }
    return restoredIds
  }

  /**
   * R3-H-13: Single authoritative path for transitioning a finding to a non-confirmed status
   * (`inconclusive` or `dismissed`) and unconditionally restoring any superseded dependents.
   */
  private demoteFindingToNonConfirmed(
    run: Run,
    findingId: string,
    patch: Parameters<Store['updateProposedFinding']>[2],
  ): string[] {
    this.storage.updateProposedFinding(run, findingId, patch)
    return this.restoreSupersededDependents(run, findingId)
  }

  private supersedeUpstreamCompositeFindings(
    run: Run,
    newFindingId: string,
    receipt: CompositeProofReceipt,
    hostExchanges: ReadonlyMap<string, HostRecordedExchangeView>,
    verification?: CompositeReceiptVerification | null,
  ): string[] {
    const upstreamEndpoints = extractCompositeUpstreamEndpoints(receipt, hostExchanges)
    if (!upstreamEndpoints.length) return []

    const upstreamNonGenericByExchangeId = new Map<string, SupersessionEndpointSpec>()
    for (const up of upstreamEndpoints) {
      if (up.exchangeId && !isGenericSharedAuthOrUtilityEndpoint(up.normalizedEndpoint)) {
        upstreamNonGenericByExchangeId.set(up.exchangeId, up)
      }
    }

    const rows = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id),
      eq(findings.goalRevision, run.goalRevision),
    )).all()
    if (!rows.length) return []

    const allSpecs = this.storage.listReplaySpecs(run.id)
    const specById = new Map(allSpecs.map(s => [s.id, s]))
    const specByFindingId = new Map<string, ReplaySpecRow>()
    for (const spec of allSpecs) if (!specByFindingId.has(spec.findingId)) specByFindingId.set(spec.findingId, spec)

    const compositeOracleFamily = verification?.terminalOracleFamily ?? receipt.terminalImpact?.oracleFamily ?? null
    const upstreamNonGeneric = upstreamEndpoints.filter(up => !isGenericSharedAuthOrUtilityEndpoint(up.normalizedEndpoint))
    const supersededIds: string[] = []
    for (const row of rows) {
      if (row.id === newFindingId) continue
      if (row.supersededByFindingId || row.finding.supersededByFindingId) continue
      if (row.finding.status !== 'confirmed') continue
      if (row.provenance === 'floor') continue

      const linkedSpec = (row.replaySpecId ? specById.get(row.replaySpecId) : undefined)
        ?? specByFindingId.get(row.id)
      const earlierEndpoints = extractExistingFindingEndpointsForSupersession(row, linkedSpec)
      const earlierExIds = row.finding.exchangeIds ?? []
      const directMatchedUpstream: SupersessionEndpointSpec[] = []
      const earlierRowOrigin = normalizeOrigin(row.finding.origin)
      for (const exId of earlierExIds) {
        const matched = upstreamNonGenericByExchangeId.get(exId)
        if (matched && earlierRowOrigin && normalizeOrigin(matched.origin) === earlierRowOrigin) {
          directMatchedUpstream.push(matched)
        }
      }

      const findingObj = row.finding as Finding & { evidence?: Record<string, unknown> }
      const ev = findingObj.evidence && typeof findingObj.evidence === 'object' ? findingObj.evidence : undefined
      const proofReceiptObj = linkedSpec?.proofReceipt && typeof linkedSpec.proofReceipt === 'object'
        ? linkedSpec.proofReceipt as unknown as Record<string, unknown>
        : undefined
      const earlierCompReceipt = (ev?.compositeReceipt ?? proofReceiptObj?.compositeReceipt) as CompositeProofReceipt | undefined

      // 1) Require verified signed upstream transcript match with exact origin & explicit HTTP method
      // (or direct signed exchangeId overlap when endpoint metadata is absent).
      const matchedUpstreamSpecs: SupersessionEndpointSpec[] = []
      let supersessionDir: 'incoming_supersedes_earlier' | 'earlier_supersedes_incoming' = 'incoming_supersedes_earlier'
      if (earlierEndpoints.length > 0 && isEndpointSubsetOfUpstream(earlierEndpoints, upstreamEndpoints)) {
        for (const ep of earlierEndpoints) {
          if (isGenericSharedAuthOrUtilityEndpoint(ep.normalizedEndpoint)) continue
          for (const up of upstreamEndpoints) {
            if (supersessionEndpointsMatchExact(ep, up)) matchedUpstreamSpecs.push(up)
          }
        }
      } else if (earlierEndpoints.length === 0 && directMatchedUpstream.length > 0) {
        matchedUpstreamSpecs.push(...directMatchedUpstream)
      } else {
        const resSup = resolveCompositeSupersessionMatch({
          incomingReceipt: receipt, incomingOrigin: upstreamEndpoints[0]?.origin ?? row.finding.origin,
          incomingTerminalEndpoint: verification?.terminalEndpoint ?? null, incomingUpstreamNonGeneric: upstreamNonGeneric,
          earlierCompReceipt, earlierOrigin: row.finding.origin, earlierEndpoints, endpointsMatchExact: supersessionEndpointsMatchExact,
        })
        if (resSup.direction !== 'none') { supersessionDir = resSup.direction; matchedUpstreamSpecs.push(...resSup.matched) }
      }
      if (!matchedUpstreamSpecs.length) continue

      const earlierVulnClass = earlierCompReceipt?.terminalVulnClass
        ?? linkedSpec?.proofReceipt?.receipt?.vulnClass
        ?? persistedAgentScriptOf(linkedSpec?.spec)?.envelope.vulnClass
        ?? null
      const earlierMeta = extractExistingFindingTargetMeta(row, linkedSpec)
      const preconditionVulnClasses = matchedUpstreamSpecs
        .map(up => up.preconditionVulnClass)
        .filter((cls): cls is string => Boolean(cls))
      if (!isFindingClassSupersessionCompatible(
        {
          cwe: row.finding.cwe,
          vulnClass: earlierVulnClass,
          terminalOracleFamily: earlierMeta.terminalOracleFamily,
        },
        {
          terminalVulnClass: receipt.terminalVulnClass,
          terminalOracleFamily: compositeOracleFamily,
          preconditionVulnClasses,
        },
      )) continue

      if (supersessionDir === 'earlier_supersedes_incoming') {
        this.storage.updateProposedFinding(run, newFindingId, { supersededByFindingId: row.id })
        return supersededIds
      }
      this.storage.updateProposedFinding(run, row.id, { supersededByFindingId: newFindingId })
      supersededIds.push(row.id)
    }
    return supersededIds
  }

  private findCorroboratingAgentProofFinding(
    run: Run,
    candidate: {
      origin: string; cwe: string; category: TaxonomyCategory
      normalizedEndpoint: string | null; method: string | null; terminalOracleFamily: string | null
      compositeSignature?: CompositeChainDedupSignature | null
    },
  ): typeof findings.$inferSelect | undefined {
    const hasCompositeSig = Boolean(candidate.compositeSignature && candidate.compositeSignature.hopCount >= 2)
    if (!candidate.normalizedEndpoint && !hasCompositeSig) return undefined
    const rows = this.storage.db.select().from(findings).where(and(
      eq(findings.runId, run.id),
      eq(findings.goalRevision, run.goalRevision),
      eq(findings.findingKind, 'multi_step_chain'),
    )).all()
    if (!rows.length) return undefined

    const allSpecs = this.storage.listReplaySpecs(run.id)
    const specById = new Map(allSpecs.map(s => [s.id, s]))
    const specByFindingId = new Map<string, ReplaySpecRow>()
    for (const spec of allSpecs) {
      if (!specByFindingId.has(spec.findingId)) specByFindingId.set(spec.findingId, spec)
    }

    const sigByRowId = new Map<string, CompositeChainDedupSignature | null>()
    const matches = rows.filter(row => {
      if (row.supersededByFindingId || row.finding.supersededByFindingId) return false
      const linkedSpec = (row.replaySpecId ? specById.get(row.replaySpecId) : undefined) ?? specByFindingId.get(row.id)
      const meta = extractExistingFindingTargetMeta(row, linkedSpec)
      const existingOrigins = [row.finding.origin, ...(row.sourceOrigins ?? [])]
      const vulnEquiv = vulnClassesEquivalentForAgentProofDedupe(candidate, { cwe: row.finding.cwe, category: row.finding.category, terminalOracleFamily: meta.terminalOracleFamily })
      const existingSig = hasCompositeSig ? extractRowCompositeSignature(row, linkedSpec) : null
      if (hasCompositeSig) sigByRowId.set(row.id, existingSig)
      const bothMultiHopComposite = Boolean(hasCompositeSig && existingSig && existingSig.hopCount >= 2)
      if (!bothMultiHopComposite && candidate.normalizedEndpoint && meta.normalizedEndpoint === candidate.normalizedEndpoint && methodsCompatibleForAgentProofDedupe(candidate.method, meta.method) && vulnEquiv) {
        return existingOrigins.some(existingOrigin => originsEquivalentForAgentProofDedupe(candidate.origin, existingOrigin, candidate.normalizedEndpoint!))
      }
      if (bothMultiHopComposite && candidate.compositeSignature && existingSig) {
        const originsEquivalent = existingOrigins.some(existingOrigin => compositeChainOriginsEquivalent(candidate.origin, existingOrigin))
        return classifyCompositeChainOverlap(candidate.compositeSignature, existingSig, { originsEquivalent, vulnClassesEquivalent: vulnEquiv }) === 'collapse_in_place'
      }
      return false
    })
    if (!matches.length) return undefined
    return sortChainDuplicateRows(matches, FINDING_STATUS_PRIORITY, r => sigByRowId.get(r.id) ?? extractRowCompositeSignature(r, (r.replaySpecId ? specById.get(r.replaySpecId) : undefined) ?? specByFindingId.get(r.id)))[0]
  }


  /** Attribution-only declarative row for a script proof (never interpreted as a DSL confirm). */
  agentProofAttributionSpec(input: {
    origin: string
    title: string
    attribution: Omit<ReturnType<typeof agentProofAttribution>, 'unclassified'> & { unclassified?: boolean }
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
      recheckInstructions: 'Re-run the persisted kovo_verify script; the finding is confirmed only by its receipt.',
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
    const findingRow = findFindingRow(this.storage, run.id, specRow.findingId)
    const origin = (persisted.origin || specRow.spec.origin || '').trim()
    const approved = this.host.approvedOriginsSet(run)
    if (!origin || !approved.has(origin)) return null

    if (envelope.runtime !== 'ts' || proof.runtime !== 'ts') {
      const status: Finding['status'] = 'inconclusive'
      const feedback: InlineVerifyFeedback = {
        verdict: 'inconclusive',
        controlPassed: false,
        assertionSummary: {
          observed: LEGACY_PYTHON_PROOF_REASON,
          expected: 'the persisted script reproduces the confirmation and its receipt re-validates',
          reason: LEGACY_PYTHON_PROOF_REASON,
        },
        stepStatuses: [],
        retriesRemaining: maxInlineVerifyRetries,
      }
      const updatedSpec = this.storage.incrementReplaySpecAttempt(specRow.id, feedback, {
        spec: specRow.spec,
        sourceOrigins: specRow.sourceOrigins,
        secrets: params.currentSecrets(),
      })
      this.storage.setReplaySpecProof(run.id, updatedSpec.id, {
        ...proof,
        replaySpecId: updatedSpec.id,
        verdict: 'inconclusive',
        receipt: null,
        createdAt: Date.now(),
      })
      if (findingRow) {
        this.demoteFindingToNonConfirmed(run, findingRow.id, {
          replaySpecId: updatedSpec.id,
          verificationTier: null,
          finding: {
            status,
            verificationTier: undefined,
            reason: findingRow.finding.reason?.trim() ? findingRow.finding.reason : LEGACY_PYTHON_PROOF_REASON,
            confidence: 'low',
            verification: `Agent script proof re-verification returned inconclusive (${LEGACY_PYTHON_PROOF_REASON}).`,
            exchangeIds: [],
          },
        })
      }
      this.host.postVerificationVerdict(run, {
        replaySpecId: updatedSpec.id,
        findingId: findingRow?.id ?? null,
        title: findingRow?.finding.title ?? 'Agent script proof',
        status,
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
        feedback,
      }
    }

    // R2-H-16: Assert sha256(envelope.script) === scriptSha256 BEFORE re-executing any persisted
    // proof script; on mismatch (e.g. legacy redacted/corrupted script), fail closed as
    // `inconclusive` — never `dismissed` or `fixed`.
    const integrity = verifyPersistedScriptIntegrity(envelope, proof.scriptSha256)
    if (!integrity.ok) {
      const status: Finding['status'] = 'inconclusive'
      const feedback: InlineVerifyFeedback = {
        verdict: 'inconclusive',
        controlPassed: false,
        assertionSummary: {
          observed: integrity.reason,
          expected: 'the persisted proof script SHA-256 matches its recorded confirmation digest',
          reason: integrity.reason,
        },
        stepStatuses: [],
        retriesRemaining: maxInlineVerifyRetries,
      }
      const updatedSpec = this.storage.incrementReplaySpecAttempt(specRow.id, feedback, {
        spec: specRow.spec,
        sourceOrigins: specRow.sourceOrigins,
        secrets: params.currentSecrets(),
      })
      this.storage.setReplaySpecProof(run.id, updatedSpec.id, {
        ...proof,
        replaySpecId: updatedSpec.id,
        verdict: 'inconclusive',
        receipt: null,
        createdAt: Date.now(),
      })
      if (findingRow) {
        this.demoteFindingToNonConfirmed(run, findingRow.id, {
          replaySpecId: updatedSpec.id,
          verificationTier: null,
          finding: {
            status,
            verificationTier: undefined,
            reason: findingRow.finding.reason?.trim() ? findingRow.finding.reason : integrity.reason,
            confidence: 'low',
            verification: `Agent script proof re-verification returned inconclusive (${integrity.reason}).`,
            exchangeIds: [],
          },
        })
      }
      this.host.postVerificationVerdict(run, {
        replaySpecId: updatedSpec.id,
        findingId: findingRow?.id ?? null,
        title: findingRow?.finding.title ?? 'Agent script proof',
        status,
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
        feedback,
      }
    }

    const result = await this.runAgentScriptProof({
      script: envelope.script,
      runtime: envelope.runtime,
      ...(envelope.vulnClass ? { title: `${envelope.vulnClass} agent proof re-verification` } : {}),
      grant: params.grant,
      runId: run.id,
      assignmentId: params.job.assignment.id,
      targetOrigins: [origin],
      signal: params.job.controller.signal,
    })
    const receiptOk = result.receipt?.verification.confirmed === true
      || result.compositeReceipt?.verification.confirmed === true
    const rawConfirmed = result.verdict.confirmed && receiptOk
    const reverifyExchangeById = buildHostRecordedExchangeIndex(result)
    const reverifyCompositeOrigin = rawConfirmed && result.compositeReceipt?.verification.confirmed
      ? inspectCompositeHostOrigin(result.compositeReceipt.receipt, reverifyExchangeById)
      : null
    const originDriftReason = reverifyCompositeOrigin && !reverifyCompositeOrigin.ok
      ? reverifyCompositeOrigin.reason
      : reverifyCompositeOrigin?.ok && findingRow?.finding.origin && normalizeOrigin(reverifyCompositeOrigin.origin) !== normalizeOrigin(findingRow.finding.origin)
        ? `Re-verification terminal exchange origin "${reverifyCompositeOrigin.origin}" drifted from confirmed finding origin "${findingRow.finding.origin}".`
        : null
    // H-18 step 6: Reject receipt class drift on reverify when the re-verified receipt class
    // disagrees with the confirmed finding's CWE family.
    const provenVulnClass = result.compositeReceipt?.receipt.terminalVulnClass
      ?? result.receipt?.receipt.vulnClass
      ?? null
    const classDriftReason = rawConfirmed && findingRow?.finding.cwe && provenVulnClass
      && !isCweConsistentWithReceiptClass(findingRow.finding.cwe, provenVulnClass)
      ? `Re-verification receipt class "${provenVulnClass}" (${cweFamilyForReceiptClass(provenVulnClass).cwe}) drifted from confirmed finding CWE ${normalizeCwe(findingRow.finding.cwe)}.`
      : null
    const identityDriftReason = originDriftReason ?? classDriftReason
    const confirmed = rawConfirmed && !identityDriftReason
    const status: Finding['status'] = confirmed
      ? 'confirmed'
      : identityDriftReason
        ? 'inconclusive'
        : result.verdict.reason === 'oracle_failed' || isFixedEligibleFailureReason(result.verdict.reason)
          ? 'dismissed'
          : 'inconclusive'
    const verificationTier: VerificationTier | undefined = confirmed ? 'runtime_confirmed' : undefined
    const feedback: InlineVerifyFeedback = {
      verdict: status === 'confirmed' ? 'confirmed' : status === 'dismissed' ? 'dismissed' : 'inconclusive',
      ...(verificationTier ? { verificationTier } : {}),
      controlPassed: !identityDriftReason && result.verdict.attempts.every(attempt => attempt.oraclePassed),
      assertionSummary: {
        observed: confirmed
          ? `Agent script ${envelope.runtime} proof reproduced and its receipt re-validated.`
          : identityDriftReason
            ? identityDriftReason
            : `Agent script proof did not re-confirm: ${result.verdict.reason}.`,
        expected: 'the persisted script reproduces the confirmation and its receipt re-validates',
        ...(identityDriftReason
          ? { reason: identityDriftReason }
          : result.verdict.detail
            ? { reason: result.verdict.detail }
            : {}),
      },
      stepStatuses: [],
      retriesRemaining: maxInlineVerifyRetries,
    }
    const updatedSpec = this.storage.incrementReplaySpecAttempt(specRow.id, feedback, {
      spec: specRow.spec,
      sourceOrigins: specRow.sourceOrigins,
      secrets: params.currentSecrets(),
    })
    const reverifySecrets: NamedSecret[] = [...params.currentSecrets(), ...vaultScrubDescriptors(this.capabilityVaultFor(run.id))]
    const cleanReverifyComposite: V8CompositeProofBundle | null = confirmed && result.compositeReceipt?.verification.confirmed
      ? {
          receipt: redactJsonValue(result.compositeReceipt.receipt, reverifySecrets),
          verification: redactJsonValue(result.compositeReceipt.verification, reverifySecrets),
          hopActors: result.compositeReceipt.hopActors,
        }
      : null
    const receiptRow = cleanReverifyComposite
      ? serializeCompositeProofReceiptRow(
          cleanReverifyComposite,
          result.receipt,
          reverifyCompositeOrigin?.ok ? reverifyCompositeOrigin.terminalExchange : null,
        )
      : confirmed && result.receipt
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
      const preservedReason = status === 'inconclusive' && findingRow.finding.reason?.trim()
        ? findingRow.finding.reason
        : null
      const nextFinding: Finding & { evidence?: Record<string, unknown> } = {
        ...findingRow.finding,
        status,
        verificationTier,
        reason: preservedReason
          ?? cleanReverifyComposite?.verification.reason
          ?? identityDriftReason
          ?? (result.verdict.detail || result.verdict.reason),
        confidence: confirmed ? 'high' : 'low',
        verification: confirmed
          ? cleanReverifyComposite
            ? `ProofReceipt (Composite) ${cleanReverifyComposite.receipt.chainId} · ${cleanReverifyComposite.verification.hopCount} hops · ${cleanReverifyComposite.receipt.replayMode} · ${cleanReverifyComposite.verification.reason}`
            : `ProofReceipt · ${result.receipt?.verification.rule ?? 'script'} rule · ${result.receipt?.verification.reason ?? result.verdict.reason}`
          : identityDriftReason
            ? `Agent script proof re-verification returned inconclusive (${identityDriftReason}).`
            : `Agent script proof re-verification returned ${status} (${result.verdict.reason}).`,
        exchangeIds: result.exchanges.map(exchange => exchange.exchangeId),
        replaySpecId: updatedSpec.id,
        ...(cleanReverifyComposite ? {
          evidence: {
            compositeReceipt: cleanReverifyComposite.receipt,
            compositeVerification: cleanReverifyComposite.verification,
            hopActors: cleanReverifyComposite.hopActors,
            ...(cleanReverifyComposite.verification.terminalOracleFamily ? { terminalOracleFamily: cleanReverifyComposite.verification.terminalOracleFamily } : {}),
            ...(cleanReverifyComposite.verification.terminalEndpoint ? { terminalEndpoint: cleanReverifyComposite.verification.terminalEndpoint } : {}),
          },
        } : {}),
        scopeRevision: run.scopeRevision,
      }
      if (confirmed) {
        const assetId = findingRow.assetId
        const savedFinding = this.storage.upsertChainFinding(run, assetId, nextFinding, updatedSpec.id, specRow.sourceOrigins)
        if (cleanReverifyComposite) {
          this.supersedeUpstreamCompositeFindings(
            run,
            savedFinding.id,
            cleanReverifyComposite.receipt,
            reverifyExchangeById,
            cleanReverifyComposite.verification,
          )
        }
      } else {
        this.demoteFindingToNonConfirmed(run, findingRow.id, {
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
    deferredCandidate?: InlineDeferredFindingCandidate
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
    // H-5: Strip untrusted model-supplied `recipe` / `agentScript` envelopes before parsing inline specs.
    const sanitizedSpecInput = params.spec && typeof params.spec === 'object' && !Array.isArray(params.spec)
      ? (() => {
          const copy = { ...(params.spec as Record<string, unknown>) }
          delete copy.recipe
          delete copy.agentScript
          return copy
        })()
      : params.spec
    const parsed = declarativeReplaySpecSchema.parse(sanitizedSpecInput)
    if (
      parsed.kind === 'static_ast_proof'
      && isLiveRuntimeVerificationRun(curRun, this.backendSupportsVerifyScript())
    ) {
      throw new Error(STATIC_AST_LIVE_TARGET_REJECT_MESSAGE)
    }
    const specOrigins = replaySpecOrigins(parsed)
    const currentApproved = this.host.approvedOriginsSet(curRun)
    if (specOrigins.some(o => !currentApproved.has(o))) {
      throw new BrokerDenied('Replay spec references an origin outside current approved scope.')
    }

    const findingRow = params.findingId ? findFindingRow(this.storage, curRun.id, params.findingId) : undefined
    const isAlreadyVerified = Boolean(
      findingRow && (findingRow.finding.status === 'confirmed' || findingRow.finding.status === 'static_verified'),
    )
    // H-18: Once a finding is confirmed or static_verified, forbid post-confirmation inline spec
    // swaps or identity edits (CWE, origin, endpoint, title). Return the immutable confirmed state.
    if (findingRow && isAlreadyVerified) {
      const immutableSpecId = findingRow.replaySpecId ?? params.replaySpecId ?? findingRow.id
      const immutableFeedback: InlineVerifyFeedback = {
        verdict: findingRow.finding.status === 'confirmed' ? 'confirmed' : 'static_verified',
        ...(findingRow.verificationTier ? { verificationTier: findingRow.verificationTier } : {}),
        controlPassed: true,
        assertionSummary: {
          observed: `Finding "${findingRow.finding.title}" is already ${findingRow.finding.status}; confirmed finding identity (CWE, origin, endpoint, title) is immutable.`,
          expected: 'confirmed findings cannot be mutated post-confirmation',
          reason: 'Confirmed finding is immutable; post-confirmation edits are rejected.',
        },
        stepStatuses: [],
        retriesRemaining: 0,
      }
      return {
        findingId: findingRow.id,
        replaySpecId: immutableSpecId,
        attemptCount: this.storage.listReplaySpecsForFinding(curRun.id, findingRow.id).reduce((m, r) => Math.max(m, r.attemptCount), 1),
        status: findingRow.finding.status,
        verificationTier: findingRow.verificationTier ?? undefined,
        feedback: immutableFeedback,
      }
    }

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
      if (parsed.kind === 'rce_proof') {
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
            this.demoteFindingToNonConfirmed(latestRun, findingRow.id, {
              replaySpecId: updatedSpec.id,
              verificationTier: null,
              finding: { status: 'inconclusive', verificationTier: undefined, reason: deniedReason, confidence: 'low' },
            })
          }
          const deniedRun = this.host.check(params.job)
          const deniedRow = findingRow ? findFindingRow(this.storage, deniedRun.id, findingRow.id) : undefined
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
      envelopeTrust: 'untrusted',
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

    const receipt = this.addReplayReceiptArtifact(
      latestRun, params.job.assignment,
      `Inline ${isStaticAst ? 'Static AST' : 'Zero-LLM replay'} attempt #${updatedSpec.attemptCount} · ${parsed.title}`,
      updatedSpec, parsed, finalStatus, verificationTier, replay, params.currentSecrets(),
      { attemptCount: updatedSpec.attemptCount, feedback: normalizedFeedback },
    )

    if (findingRow && !isAlreadyVerified) {
      const mergedOrigins = [...new Set([...findingRow.sourceOrigins, ...specOrigins])]
      const { patch } = buildReplayFindingPatch(
        parsed, replay, findingRow.finding, finalStatus, verificationTier, 'inline replay', params.currentSecrets(),
      )
      const nextFindingPatch: Partial<Finding> = { ...patch, evidenceIds: [receipt.id], exchangeIds: replay.exchangeIds }
      if (finalStatus === 'confirmed' || finalStatus === 'static_verified') {
        this.persistReplayConfirmation(
          latestRun, params.job.assignment, findingRow, parsed, updatedSpec.id, mergedOrigins,
          { ...findingRow.finding, ...nextFindingPatch, replaySpecId: updatedSpec.id, scopeRevision: latestRun.scopeRevision },
          replay, finalStatus, params.job.assignment.stepId,
        )
      } else {
        this.demoteFindingToNonConfirmed(latestRun, findingRow.id, {
          replaySpecId: updatedSpec.id, sourceOrigins: mergedOrigins, verificationTier: null, finding: nextFindingPatch,
        })
      }
    } else if (!findingRow && params.deferredCandidate && finalStatus === 'confirmed') {
      const cand = params.deferredCandidate
      const mergedOrigins = [...new Set([...cand.sourceOrigins, ...specOrigins])]
      const { patch } = buildReplayFindingPatch(
        parsed, replay, cand.finding, finalStatus, verificationTier, 'inline replay', params.currentSecrets(),
      )
      const nextFinding: Finding = {
        ...cand.finding,
        ...patch,
        replaySpecId: updatedSpec.id,
        evidenceIds: [...new Set([...cand.finding.evidenceIds, receipt.id])],
        exchangeIds: [...new Set([...(cand.finding.exchangeIds ?? []), ...replay.exchangeIds])],
        scopeRevision: latestRun.scopeRevision,
      }
      this.persistReplayConfirmation(
        latestRun, params.job.assignment,
        { id: cand.finding.id, assetId: cand.assetId, finding: cand.finding },
        parsed, updatedSpec.id, mergedOrigins,
        nextFinding, replay, finalStatus, params.job.assignment.stepId,
      )
      for (const fid of cand.validFactIds) {
        this.storage.addGraphEdge(latestRun.id, { fromKind: 'fact', fromId: fid, toKind: 'finding', toId: cand.finding.id, edgeKind: 'proves' })
      }
      this.storage.addGraphEdge(latestRun.id, { fromKind: 'assignment', fromId: params.job.assignment.id, toKind: 'finding', toId: cand.finding.id, edgeKind: 'proves' })
    }

    // The persisted row is the single source of truth: a non-confirming attempt may have just
    // demoted an already-confirmed finding (finding.confirmation_conflict). Never report the
    // pre-attempt status in that case.
    const verdictRun = this.storage.run(params.job.assignment.runId)
    const persistedFindingRow = findingRow
      ?? (params.deferredCandidate && finalStatus === 'confirmed'
        ? findFindingRow(this.storage, verdictRun.id, params.deferredCandidate.finding.id)
        : undefined)
    const verdictRow = this.host.resolveInlineVerdictRow(verdictRun.id, persistedFindingRow)
    const verdictStatus = verdictRow?.finding.status ?? finalStatus
    const verdictTier = verdictRow?.verificationTier ?? (verdictStatus === 'confirmed' ? verificationTier : undefined)
    this.host.postVerificationVerdict(verdictRun, {
      replaySpecId: updatedSpec.id,
      findingId: persistedFindingRow?.id ?? (params.deferredCandidate ? null : (params.findingId ?? null)),
      title: verdictRow?.finding.title ?? parsed.title,
      status: verdictStatus,
      verificationTier: verdictTier,
      feedback: normalizedFeedback,
      assignmentId: specRow.assignmentId ?? params.job.assignment.id,
      refStepId: params.job.assignment.stepId,
      attempt: updatedSpec.attemptCount,
    })
    return {
      findingId: persistedFindingRow?.id,
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
    }, job.controller.signal, reposDir ? { reposDir, runId: run.id } : { runId: run.id }) : undefined

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
    const findingRow = findFindingRow(this.storage, run.id, findingId)
    if (!findingRow?.replaySpecId) throw new Error('Finding has no Declarative Replay Spec.')
    const specRow: ReplaySpecRow = this.storage.getReplaySpec(run.id, findingRow.replaySpecId)
    const permittedAtAdmission = this.host.approvedOriginsSet(run)
    const { grant, secrets, currentSecrets } = this.host.buildGrant(job, run, permittedAtAdmission)

    await this.ensureCanaryListenerForSpec(specRow.spec)

    const { reposDir } = this.host.projectReposMount(run.projectId)
    const persistedProof = this.storage.replaySpecProof(run.id, specRow.id)
    const hasHostTrustedEnvelope = findingRow.provenance === 'floor'
      || Boolean(persistedProof && persistedProof.verdict === 'confirmed')
    const retestRes = await retestReplaySpec({
      ...this.baseReplayRunnerParams(
        specRow.spec, run.id, job.assignment.id, grant, job.controller.signal, reposDir,
        createExchangeRecorder(this.storage, () => run, job.assignment.id, currentSecrets),
      ),
      envelopeTrust: hasHostTrustedEnvelope ? 'host_persisted' : 'untrusted',
    })

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
      this.storage.message(current.id, current.coordinatorId, 'kovo',
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
    this.storage.upsertFindingRecord({
      runId: run.id,
      assetId: asset.id,
      goalRevision: run.goalRevision,
      findingId: record.id,
      existingId: existingId ?? null,
      checkId: rule.id,
      caseId: coverage.caseId ?? '',
      findingKind: 'baseline_check',
      replaySpecId: null,
      sourceOrigins: [asset.origin],
      verificationTier: confirmed ? 'baseline_confirmed' : null,
      provenance: 'agent_only',
      verificationClass,
      finding: persistedRecord,
    })
  }

}
