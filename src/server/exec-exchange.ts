import { and, eq } from 'drizzle-orm'
import type { AccessPolicySnapshot } from '../access-policy.ts'
import { owaspCategories, type InlineVerifyFeedback, type OwaspCategory } from '../domain.ts'
import type { BrokerExchangeResult, PublicObservation } from './broker.ts'
import { extractSpecDedupeFields, type ExistingFindingRef } from './dedupe.ts'
import type { EvidenceReview } from './evidence-checks.ts'
import type { NamedSecret } from './redact.ts'
import { findings } from './schema.ts'
import type { Assignment, Run, Store } from './store.ts'

export type ExecActiveJob = {
  assignment: Assignment
  origins: Set<string>
  controller: AbortController
  /** Set when the provider-stream watchdog aborted this assignment (retry once). */
  stallAbort?: boolean
}

export type ExecCapture = { observation: PublicObservation | null; note: string }
export type ExecReviewInput = { artifactId?: string; reviews: EvidenceReview[]; policy?: AccessPolicySnapshot }
export type ExecCoordinatorTask = { controller: AbortController; goalRevision: number; scopeRevision?: number }

export interface ExecTier3ApprovalInput {
  origin: string
  method: string
  pathAndQuery: string
  personaHandle?: string | null
  rationale: string
  requestPreview: string
  bodyPreview?: string | null
  bodyHash?: string | null
  headers?: Record<string, string>
  hasMultipart?: boolean
  isRceProof?: boolean
  isRaceBurst?: boolean
  approvalInstances?: number
  additionalApprovalTargets?: Array<{
    origin: string
    method: string
    pathAndQuery: string
    personaHandle?: string | null
    bodyHash?: string | null
    bodyPreview?: string | null
    headers?: Record<string, string>
    hasMultipart?: boolean
    isRaceBurst?: boolean
    isRceProof?: boolean
    instances?: number
  }>
  secrets: readonly NamedSecret[]
}

export interface RecordBrokerExchangeOptions {
  trackResources?: boolean
  markCoverage?: (run: Run, origin: string, method: string, pathAndQuery: string) => void
  onSaved?: (run: Run, ex: BrokerExchangeResult, exchangeId: string) => void
}

/**
 * Persist a brokered HTTP/WebSocket exchange with consistent redaction, optional resource
 * harvesting, endpoint coverage tracking, and caller-provided post-save hooks.
 */
export function recordBrokerExchange(
  storage: Store,
  run: Run,
  assignmentId: string,
  ex: BrokerExchangeResult,
  secrets: readonly NamedSecret[],
  options: RecordBrokerExchangeOptions = {},
): { id: string } {
  const saved = storage.recordExchange({
    runId: run.id,
    assignmentId,
    scopeRevision: run.scopeRevision,
    origin: ex.origin,
    finalOrigin: ex.finalOrigin,
    redirectOrigins: ex.redirectOrigins,
    method: ex.method,
    pathAndQuery: ex.pathAndQuery,
    personaHandle: ex.personaHandle,
    status: ex.status,
    mediaType: ex.mediaType,
    reqHeaders: ex.reqHeaders,
    respHeaders: ex.respHeaders,
    body: ex.body,
    durationMs: ex.durationMs,
    secretMatches: ex.secretMatches,
    secrets,
  })
  if (options.trackResources) {
    storage.trackExchangeResources({
      runId: run.id,
      scopeRevision: run.scopeRevision,
      exchange: ex,
      source: 'surface_probe',
    })
  }
  options.markCoverage?.(run, ex.origin, ex.method, ex.pathAndQuery)
  options.onSaved?.(run, ex, saved.id)
  return saved
}

/** Build an `onExchange` callback bound to a dynamic run/secrets supplier. */
export function createExchangeRecorder(
  storage: Store,
  resolveRun: () => Run,
  assignmentId: string,
  resolveSecrets: () => readonly NamedSecret[],
  options: RecordBrokerExchangeOptions = {},
): (ex: BrokerExchangeResult) => string {
  return (ex: BrokerExchangeResult) =>
    recordBrokerExchange(storage, resolveRun(), assignmentId, ex, resolveSecrets(), options).id
}

export function buildExistingFindingRefs(
  storage: Store,
  runId: string,
  goalRevision: number,
  options: { chainOnly?: boolean; includeDescriptions?: boolean } = {},
) {
  const rows = storage.db.select().from(findings).where(and(
    eq(findings.runId, runId),
    eq(findings.goalRevision, goalRevision),
    ...(options.chainOnly ? [eq(findings.findingKind, 'multi_step_chain')] : []),
  )).all()
  const specMap = options.chainOnly ? new Map(storage.listReplaySpecs(runId).map(s => [s.id, s])) : null
  const refs: ExistingFindingRef[] = rows.map(row => {
    const existingSpec = row.replaySpecId
      ? (specMap ? specMap.get(row.replaySpecId)?.spec : storage.getReplaySpec(runId, row.replaySpecId)?.spec)
      : undefined
    const existingFields = existingSpec ? extractSpecDedupeFields(existingSpec) : undefined
    return {
      id: row.id,
      origin: row.finding.origin,
      title: row.finding.title,
      status: row.finding.status,
      cwe: row.finding.cwe,
      category: row.finding.category,
      severity: row.finding.severity,
      endpoint: existingFields?.endpoint ?? null,
      authState: existingFields?.authState ?? null,
      specKind: existingFields?.specKind ?? null,
      method: existingFields?.method ?? null,
      param: existingFields?.param ?? null,
      graphqlField: existingFields?.graphqlField ?? null,
      mutated: existingFields?.mutated ?? null,
      ...(options.includeDescriptions
        ? {
            reason: row.finding.reason,
            impact: row.finding.impact,
            remediation: row.finding.remediation,
            sourceOrigins: row.sourceOrigins,
            fingerprintHash: row.fingerprintHash ?? row.finding.fingerprintHash ?? null,
          }
        : { fingerprintHash: row.fingerprintHash ?? null }),
    }
  })
  return { rows, refs }
}

export function retryLimitExceededFeedback(maxAttempts: number, reason: string): InlineVerifyFeedback {
  return {
    verdict: 'inconclusive',
    controlPassed: false,
    assertionSummary: { observed: 'retry_limit_exceeded', expected: `<= ${maxAttempts} verification attempts`, reason },
    stepStatuses: [],
    retriesRemaining: 0,
  }
}

export function recordReportedFindingCoverage(
  storage: Store,
  run: Run,
  assignmentId: string,
  origin: string,
  category: string,
  summary: string,
  linkedFindingId: string,
  permitted: (run: Run, origin: string) => boolean,
): void {
  if (owaspCategories.includes(category as OwaspCategory) && permitted(run, origin)) {
    storage.upsertCoverageEntry(run, assignmentId, {
      origin,
      category: category as OwaspCategory,
      status: 'reported',
      summary,
      linkedFindingId,
    })
  }
}
