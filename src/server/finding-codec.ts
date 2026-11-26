/**
 * Move S4 — Canonical `FindingCodec` & Promoted Indexed Finding Columns.
 *
 * Centralizes finding serialization/deserialization and relational projection across
 * `status`, `severity`, `cwe`, `origin`, and `triage_status` so SQL columns and the
 * `findings.finding` JSON blob never diverge, while keeping the exact existing TypeScript
 * `Finding` / `TriagedFinding` return interface for all UI and API consumers.
 */
import type { DatabaseSync } from 'node:sqlite'
import { findingStatuses } from '../domain.ts'
import type { CodeLocation, Finding, FindingStatus, VerificationTier } from '../domain.ts'
import { normalizeFindingSeverity, normalizeFindingSeverityOverride } from '../findings-view.ts'
import type {
  FindingProvenance,
  FindingProvenanceFields,
  FindingVerificationClass,
} from '../report-summary.ts'
import {
  assertConfirmedVerificationClass,
  resolvePageLimit,
  resolvePageOffset,
  safeJsonParse,
  verificationClassForFinding,
} from './store-session.ts'

export const operatorTriageStatuses = [
  'open',
  'confirmed_by_operator',
  'accepted_risk',
  'false_positive',
  'fixed',
] as const
export type OperatorTriageStatus = typeof operatorTriageStatuses[number]

/**
 * Accepted operator severity overrides: canonical severities matching `findingSeverities`
 * (`'informational'`), plus legacy `'info'` decode alias canonicalized to `'informational'`.
 */
export const operatorSeverityOverrides = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
  'info',
] as const
export type OperatorSeverityOverride = typeof operatorSeverityOverrides[number]

export interface OperatorTriage {
  status: OperatorTriageStatus
  severityOverride: OperatorSeverityOverride | null
  notes: string
  updatedAt: number
}

export type TriagedFinding = Finding & Partial<FindingProvenanceFields> & {
  operatorTriage?: OperatorTriage | null
}

/** First-class promoted columns indexed on `findings` and kept in lockstep with `finding` JSON. */
export const PROMOTED_FINDING_COLUMNS = [
  'status',
  'severity',
  'cwe',
  'origin',
  'triage_status',
] as const

/**
 * Single authoritative SQL predicate for runtime-confirmed findings.
 * Excludes static advisories (`static_verified`), pending/inconclusive/dismissed items, and
 * superseded duplicates. Reads only indexed relational columns (zero `json_extract`).
 */
export const CONFIRMED_FINDING_PREDICATE_SQL =
  "verification_class = 'runtime_confirmed' AND status = 'confirmed' AND superseded_by_finding_id IS NULL"

const findingStatusSet = new Set<string>(findingStatuses)
const operatorTriageStatusSet = new Set<string>(operatorTriageStatuses)

export interface PromotedFindingColumns {
  status: FindingStatus
  severity: Finding['severity']
  cwe: string | null
  origin: string
  triageStatus: OperatorTriageStatus
  verificationClass: FindingVerificationClass
}

export interface RawFindingRow {
  id: string
  run_id: string
  asset_id: string
  goal_revision: number
  check_id: string
  case_id: string
  finding_kind: 'baseline_check' | 'multi_step_chain'
  replay_spec_id: string | null
  provenance: FindingProvenance
  parent_finding_ids: string | string[] | null
  verification_class: FindingVerificationClass
  source_origins: string | string[]
  verification_tier: VerificationTier | null
  fingerprint_hash: string | null
  superseded_by_finding_id: string | null
  counterevidence: string | null
  confidence_rationale: string | null
  severity_change_conditions: string | null
  code_locations: string | CodeLocation[] | null
  status?: string | null
  severity?: string | null
  cwe?: string | null
  origin?: string | null
  triage_status?: string | null
  finding: string | TriagedFinding
}

export interface DrizzleFindingRow {
  id: string
  runId: string
  assetId: string
  goalRevision: number
  checkId: string
  caseId: string
  findingKind: 'baseline_check' | 'multi_step_chain'
  replaySpecId: string | null
  provenance: FindingProvenance
  parentFindingIds: string[] | null
  verificationClass: FindingVerificationClass
  sourceOrigins: string[]
  verificationTier: VerificationTier | null
  fingerprintHash: string | null
  supersededByFindingId: string | null
  counterevidence: string | null
  confidenceRationale: string | null
  severityChangeConditions: string | null
  codeLocations: CodeLocation[] | null
  status?: string | null
  severity?: string | null
  cwe?: string | null
  origin?: string | null
  triageStatus?: string | null
  finding: TriagedFinding
}

export interface FindingInsertInput {
  id?: string
  runId: string
  assetId: string
  goalRevision: number
  checkId: string
  caseId: string
  findingKind: 'baseline_check' | 'multi_step_chain'
  replaySpecId: string | null
  provenance: FindingProvenance
  parentFindingIds: string[] | null
  verificationClass?: FindingVerificationClass
  sourceOrigins: string[]
  verificationTier: VerificationTier | null
  fingerprintHash: string | null
  supersededByFindingId: string | null
  counterevidence: string | null
  confidenceRationale: string | null
  severityChangeConditions: string | null
  codeLocations: CodeLocation[] | null
  finding: TriagedFinding
}

export interface FindingUpdateInput {
  finding: TriagedFinding
  replaySpecId?: string | null
  provenance?: FindingProvenance
  parentFindingIds?: string[] | null
  verificationClass?: FindingVerificationClass
  sourceOrigins?: string[]
  verificationTier?: VerificationTier | null
  fingerprintHash?: string | null
  supersededByFindingId?: string | null
  counterevidence?: string | null
  confidenceRationale?: string | null
  severityChangeConditions?: string | null
  codeLocations?: CodeLocation[] | null
}

export interface EncodedFindingRow {
  id: string
  run_id: string
  asset_id: string
  goal_revision: number
  check_id: string
  case_id: string
  finding_kind: 'baseline_check' | 'multi_step_chain'
  replay_spec_id: string | null
  provenance: FindingProvenance
  parent_finding_ids: string | null
  verification_class: FindingVerificationClass
  source_origins: string
  verification_tier: VerificationTier | null
  fingerprint_hash: string | null
  superseded_by_finding_id: string | null
  counterevidence: string | null
  confidence_rationale: string | null
  severity_change_conditions: string | null
  code_locations: string | null
  status: FindingStatus
  severity: Finding['severity']
  cwe: string | null
  origin: string
  triage_status: OperatorTriageStatus
  finding: string
  canonical: TriagedFinding
}

export interface EncodedFindingUpdate {
  replay_spec_id?: string | null
  provenance?: FindingProvenance
  parent_finding_ids?: string | null
  verification_class: FindingVerificationClass
  source_origins?: string
  verification_tier?: VerificationTier | null
  fingerprint_hash?: string | null
  superseded_by_finding_id?: string | null
  counterevidence?: string | null
  confidence_rationale?: string | null
  severity_change_conditions?: string | null
  code_locations?: string | null
  status: FindingStatus
  severity: Finding['severity']
  cwe: string | null
  origin: string
  triage_status: OperatorTriageStatus
  finding: string
  canonical: TriagedFinding
}

export interface FindingQueryFilter {
  status?: FindingStatus | readonly FindingStatus[]
  severity?: Finding['severity'] | readonly Finding['severity'][]
  cwe?: string
  origin?: string
  triageStatus?: OperatorTriageStatus | readonly OperatorTriageStatus[]
  verificationClass?: FindingVerificationClass | readonly FindingVerificationClass[]
  includeSuperseded?: boolean
  limit?: number
  offset?: number
}

export interface RunFindingRollup {
  runId: string
  findingCount: number
  confirmedCount: number
}

function normalizeStatus(value: unknown): FindingStatus {
  if (typeof value === 'string' && findingStatusSet.has(value)) {
    return value as FindingStatus
  }
  return 'pending'
}

function normalizeSeverity(value: unknown): Finding['severity'] {
  return normalizeFindingSeverity(value, 'medium')
}

function normalizeSeverityOverride(value: unknown): Finding['severity'] | null {
  return normalizeFindingSeverityOverride(value)
}

function normalizeCwe(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function normalizeOrigin(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function normalizeTriageStatus(value: unknown): OperatorTriageStatus {
  if (typeof value === 'string' && operatorTriageStatusSet.has(value)) {
    return value as OperatorTriageStatus
  }
  return 'open'
}

function isRawFindingRow(row: RawFindingRow | DrizzleFindingRow): row is RawFindingRow {
  return 'run_id' in row
}

function parseJsonArray<T>(raw: string | T[] | null | undefined): T[] | null {
  if (raw == null) return null
  if (Array.isArray(raw)) return raw
  const parsed = safeJsonParse<unknown>(raw, null)
  return Array.isArray(parsed) ? (parsed as T[]) : null
}

export const FindingCodec = {
  /**
   * Derive canonical promoted column values from a Finding payload + optional explicit overrides,
   * enforcing the `confirmed => runtime_confirmed` verification invariant.
   */
  extractPromotedColumns(
    finding: Finding | TriagedFinding,
    overrides?: { verificationClass?: FindingVerificationClass; triageStatus?: OperatorTriageStatus },
  ): PromotedFindingColumns {
    const status = normalizeStatus(finding.status)
    const severity = normalizeSeverity(finding.severity)
    const cwe = normalizeCwe(finding.cwe)
    const origin = normalizeOrigin(finding.origin)
    const triage = (finding as TriagedFinding).operatorTriage
    const triageStatus = normalizeTriageStatus(overrides?.triageStatus ?? triage?.status ?? 'open')
    const verificationClass = verificationClassForFinding(
      { ...finding, status },
      overrides?.verificationClass,
    )
    assertConfirmedVerificationClass(status, verificationClass)
    return { status, severity, cwe, origin, triageStatus, verificationClass }
  },

  /**
   * Canonicalize a `TriagedFinding` object so embedded metadata matches its relational columns
   * 1:1 before JSON serialization.
   */
  canonicalize(
    finding: TriagedFinding,
    meta: {
      id?: string
      findingKind?: 'baseline_check' | 'multi_step_chain'
      replaySpecId?: string | null
      provenance?: FindingProvenance
      parentFindingIds?: string[] | null
      verificationClass?: FindingVerificationClass
      verificationTier?: VerificationTier | null
      fingerprintHash?: string | null
      supersededByFindingId?: string | null
      counterevidence?: string | null
      confidenceRationale?: string | null
      severityChangeConditions?: string | null
      codeLocations?: CodeLocation[] | null
    } = {},
  ): { canonical: TriagedFinding; promoted: PromotedFindingColumns } {
    const verificationTier = meta.verificationTier !== undefined
      ? meta.verificationTier
      : (finding.verificationTier ?? null)
    const normalizedFinding: TriagedFinding = {
      ...finding,
      ...(meta.id ? { id: meta.id } : {}),
      ...(meta.findingKind ? { findingKind: meta.findingKind } : {}),
      ...(meta.replaySpecId !== undefined
        ? (meta.replaySpecId ? { replaySpecId: meta.replaySpecId } : { replaySpecId: undefined })
        : {}),
      ...(verificationTier !== null
        ? { verificationTier }
        : meta.verificationTier === null
          ? { verificationTier: undefined }
          : {}),
      ...(meta.fingerprintHash !== undefined ? { fingerprintHash: meta.fingerprintHash } : {}),
      ...(meta.supersededByFindingId !== undefined ? { supersededByFindingId: meta.supersededByFindingId } : {}),
      ...(meta.counterevidence !== undefined ? { counterevidence: meta.counterevidence } : {}),
      ...(meta.confidenceRationale !== undefined ? { confidenceRationale: meta.confidenceRationale } : {}),
      ...(meta.severityChangeConditions !== undefined ? { severityChangeConditions: meta.severityChangeConditions } : {}),
      ...(meta.codeLocations !== undefined ? { codeLocations: meta.codeLocations ?? undefined } : {}),
    }
    const promoted = FindingCodec.extractPromotedColumns(normalizedFinding, {
      verificationClass: meta.verificationClass,
    })
    const canonical: TriagedFinding = {
      ...normalizedFinding,
      status: promoted.status,
      severity: promoted.severity,
      origin: promoted.origin,
      ...(promoted.cwe !== null ? { cwe: promoted.cwe } : {}),
      ...(meta.provenance !== undefined ? { provenance: meta.provenance } : {}),
      ...(meta.parentFindingIds?.length ? { parentFindingIds: meta.parentFindingIds } : {}),
      verificationStatus: promoted.verificationClass,
    }
    if (canonical.operatorTriage) {
      canonical.operatorTriage = {
        ...canonical.operatorTriage,
        status: promoted.triageStatus,
        severityOverride: normalizeSeverityOverride(canonical.operatorTriage.severityOverride),
      }
    }
    return { canonical, promoted }
  },

  /** Serialize a complete finding record for SQLite `INSERT INTO findings`. */
  toRow(input: FindingInsertInput): EncodedFindingRow {
    const id = input.id ?? input.finding.id
    const { canonical, promoted } = FindingCodec.canonicalize(input.finding, {
      id,
      findingKind: input.findingKind,
      replaySpecId: input.replaySpecId,
      provenance: input.provenance,
      parentFindingIds: input.parentFindingIds,
      verificationClass: input.verificationClass,
      verificationTier: input.verificationTier,
      fingerprintHash: input.fingerprintHash,
      supersededByFindingId: input.supersededByFindingId,
      counterevidence: input.counterevidence,
      confidenceRationale: input.confidenceRationale,
      severityChangeConditions: input.severityChangeConditions,
      codeLocations: input.codeLocations,
    })
    return {
      id,
      run_id: input.runId,
      asset_id: input.assetId,
      goal_revision: input.goalRevision,
      check_id: input.checkId,
      case_id: input.caseId,
      finding_kind: input.findingKind,
      replay_spec_id: input.replaySpecId ?? null,
      provenance: input.provenance,
      parent_finding_ids: input.parentFindingIds?.length ? JSON.stringify(input.parentFindingIds) : null,
      verification_class: promoted.verificationClass,
      source_origins: JSON.stringify(input.sourceOrigins),
      verification_tier: input.verificationTier ?? null,
      fingerprint_hash: input.fingerprintHash ?? null,
      superseded_by_finding_id: input.supersededByFindingId ?? null,
      counterevidence: input.counterevidence ?? null,
      confidence_rationale: input.confidenceRationale ?? null,
      severity_change_conditions: input.severityChangeConditions ?? null,
      code_locations: input.codeLocations?.length ? JSON.stringify(input.codeLocations) : null,
      status: promoted.status,
      severity: promoted.severity,
      cwe: promoted.cwe,
      origin: promoted.origin,
      triage_status: promoted.triageStatus,
      finding: JSON.stringify(canonical),
      canonical,
    }
  },

  /** Serialize a finding update for SQLite `UPDATE findings SET ...` keeping all promoted columns synced. */
  toUpdateColumns(input: FindingUpdateInput): EncodedFindingUpdate {
    const { canonical, promoted } = FindingCodec.canonicalize(input.finding, {
      replaySpecId: input.replaySpecId,
      provenance: input.provenance,
      parentFindingIds: input.parentFindingIds,
      verificationClass: input.verificationClass,
      verificationTier: input.verificationTier,
      fingerprintHash: input.fingerprintHash,
      supersededByFindingId: input.supersededByFindingId,
      counterevidence: input.counterevidence,
      confidenceRationale: input.confidenceRationale,
      severityChangeConditions: input.severityChangeConditions,
      codeLocations: input.codeLocations,
    })
    return {
      ...(input.replaySpecId !== undefined ? { replay_spec_id: input.replaySpecId } : {}),
      ...(input.provenance !== undefined ? { provenance: input.provenance } : {}),
      ...(input.parentFindingIds !== undefined
        ? { parent_finding_ids: input.parentFindingIds?.length ? JSON.stringify(input.parentFindingIds) : null }
        : {}),
      verification_class: promoted.verificationClass,
      ...(input.sourceOrigins !== undefined ? { source_origins: JSON.stringify(input.sourceOrigins) } : {}),
      ...(input.verificationTier !== undefined ? { verification_tier: input.verificationTier } : {}),
      ...(input.fingerprintHash !== undefined ? { fingerprint_hash: input.fingerprintHash } : {}),
      ...(input.supersededByFindingId !== undefined ? { superseded_by_finding_id: input.supersededByFindingId } : {}),
      ...(input.counterevidence !== undefined ? { counterevidence: input.counterevidence } : {}),
      ...(input.confidenceRationale !== undefined ? { confidence_rationale: input.confidenceRationale } : {}),
      ...(input.severityChangeConditions !== undefined ? { severity_change_conditions: input.severityChangeConditions } : {}),
      ...(input.codeLocations !== undefined
        ? { code_locations: input.codeLocations?.length ? JSON.stringify(input.codeLocations) : null }
        : {}),
      status: promoted.status,
      severity: promoted.severity,
      cwe: promoted.cwe,
      origin: promoted.origin,
      triage_status: promoted.triageStatus,
      finding: JSON.stringify(canonical),
      canonical,
    }
  },

  /**
   * Deserialize a SQLite `findings` row (raw snake_case or Drizzle camelCase) into the canonical
   * TypeScript `TriagedFinding` interface. Relational promoted columns are authoritative whenever present.
   */
  fromRow(row: RawFindingRow | DrizzleFindingRow): TriagedFinding {
    const rawFinding = typeof row.finding === 'string'
      ? safeJsonParse<TriagedFinding>(row.finding, {} as TriagedFinding)
      : row.finding

    if (isRawFindingRow(row)) {
      const parentFindingIds = parseJsonArray<string>(row.parent_finding_ids)
      const codeLocations = parseJsonArray<CodeLocation>(row.code_locations)
      const status = row.status && findingStatusSet.has(row.status)
        ? (row.status as FindingStatus)
        : normalizeStatus(rawFinding.status)
      const severity = row.severity
        ? normalizeSeverity(row.severity)
        : normalizeSeverity(rawFinding.severity)
      const origin = row.origin !== undefined && row.origin !== null && row.origin !== ''
        ? row.origin
        : normalizeOrigin(rawFinding.origin)
      const cwe = row.cwe !== undefined && row.cwe !== null && row.cwe !== ''
        ? row.cwe
        : rawFinding.cwe
      const colTriageStatus = row.triage_status && operatorTriageStatusSet.has(row.triage_status)
        ? (row.triage_status as OperatorTriageStatus)
        : undefined
      const operatorTriage = rawFinding.operatorTriage
        ? {
            ...rawFinding.operatorTriage,
            status: colTriageStatus ?? rawFinding.operatorTriage.status,
            severityOverride: normalizeSeverityOverride(rawFinding.operatorTriage.severityOverride),
          }
        : colTriageStatus && colTriageStatus !== 'open'
          ? { status: colTriageStatus, severityOverride: null, notes: '', updatedAt: 0 }
          : rawFinding.operatorTriage

      return {
        ...rawFinding,
        id: row.id,
        status,
        severity,
        origin,
        ...(cwe !== undefined ? { cwe } : {}),
        findingKind: row.finding_kind,
        replaySpecId: row.replay_spec_id ?? rawFinding.replaySpecId,
        verificationTier: row.verification_tier ?? rawFinding.verificationTier,
        fingerprintHash: row.fingerprint_hash ?? rawFinding.fingerprintHash,
        supersededByFindingId: row.superseded_by_finding_id ?? rawFinding.supersededByFindingId,
        counterevidence: row.counterevidence ?? rawFinding.counterevidence,
        confidenceRationale: row.confidence_rationale ?? rawFinding.confidenceRationale,
        severityChangeConditions: row.severity_change_conditions ?? rawFinding.severityChangeConditions,
        ...(codeLocations?.length
          ? { codeLocations }
          : rawFinding.codeLocations?.length
            ? { codeLocations: rawFinding.codeLocations }
            : {}),
        provenance: row.provenance,
        ...(parentFindingIds?.length ? { parentFindingIds } : {}),
        verificationStatus: row.verification_class,
        ...(operatorTriage !== undefined ? { operatorTriage } : {}),
      }
    }

    const status = row.status && findingStatusSet.has(row.status)
      ? (row.status as FindingStatus)
      : normalizeStatus(rawFinding.status)
    const severity = row.severity
      ? normalizeSeverity(row.severity)
      : normalizeSeverity(rawFinding.severity)
    const origin = row.origin !== undefined && row.origin !== null && row.origin !== ''
      ? row.origin
      : normalizeOrigin(rawFinding.origin)
    const cwe = row.cwe !== undefined && row.cwe !== null && row.cwe !== ''
      ? row.cwe
      : rawFinding.cwe
    const colTriageStatus = row.triageStatus && operatorTriageStatusSet.has(row.triageStatus)
      ? (row.triageStatus as OperatorTriageStatus)
      : undefined
    const operatorTriage = rawFinding.operatorTriage
      ? {
          ...rawFinding.operatorTriage,
          status: colTriageStatus ?? rawFinding.operatorTriage.status,
          severityOverride: normalizeSeverityOverride(rawFinding.operatorTriage.severityOverride),
        }
      : colTriageStatus && colTriageStatus !== 'open'
        ? { status: colTriageStatus, severityOverride: null, notes: '', updatedAt: 0 }
        : rawFinding.operatorTriage

    return {
      ...rawFinding,
      id: row.id,
      status,
      severity,
      origin,
      ...(cwe !== undefined ? { cwe } : {}),
      findingKind: row.findingKind,
      replaySpecId: row.replaySpecId ?? rawFinding.replaySpecId,
      verificationTier: row.verificationTier ?? rawFinding.verificationTier,
      fingerprintHash: row.fingerprintHash ?? rawFinding.fingerprintHash,
      supersededByFindingId: row.supersededByFindingId ?? rawFinding.supersededByFindingId,
      counterevidence: row.counterevidence ?? rawFinding.counterevidence,
      confidenceRationale: row.confidenceRationale ?? rawFinding.confidenceRationale,
      severityChangeConditions: row.severityChangeConditions ?? rawFinding.severityChangeConditions,
      ...(row.codeLocations?.length
        ? { codeLocations: row.codeLocations }
        : rawFinding.codeLocations?.length
          ? { codeLocations: rawFinding.codeLocations }
          : {}),
      provenance: row.provenance,
      ...(row.parentFindingIds?.length ? { parentFindingIds: row.parentFindingIds } : {}),
      verificationStatus: row.verificationClass,
      ...(operatorTriage !== undefined ? { operatorTriage } : {}),
    }
  },

  /**
   * Idempotent SQL backfill populating promoted columns (`status`, `severity`, `cwe`, `origin`,
   * `triage_status`) from `findings.finding` JSON for legacy pre-v10 databases.
   */
  backfillPromotedColumns(client: DatabaseSync): number {
    const info = client.prepare(`
      UPDATE findings
      SET
        status = CASE
          WHEN json_extract(finding, '$.status') IN ('pending', 'confirmed', 'static_verified', 'dismissed', 'inconclusive')
            THEN json_extract(finding, '$.status')
          ELSE 'pending'
        END,
        severity = CASE
          WHEN json_extract(finding, '$.severity') = 'info' THEN 'informational'
          WHEN json_extract(finding, '$.severity') IN ('critical', 'high', 'medium', 'low', 'informational')
            THEN json_extract(finding, '$.severity')
          ELSE 'medium'
        END,
        cwe = NULLIF(trim(coalesce(json_extract(finding, '$.cwe'), '')), ''),
        origin = trim(coalesce(json_extract(finding, '$.origin'), '')),
        triage_status = CASE
          WHEN json_extract(finding, '$.operatorTriage.status') IN ('open', 'confirmed_by_operator', 'accepted_risk', 'false_positive', 'fixed')
            THEN json_extract(finding, '$.operatorTriage.status')
          ELSE 'open'
        END
      WHERE
        status IS NULL
        OR status <> CASE
          WHEN json_extract(finding, '$.status') IN ('pending', 'confirmed', 'static_verified', 'dismissed', 'inconclusive')
            THEN json_extract(finding, '$.status')
          ELSE 'pending'
        END
        OR severity IS NULL
        OR severity <> CASE
          WHEN json_extract(finding, '$.severity') = 'info' THEN 'informational'
          WHEN json_extract(finding, '$.severity') IN ('critical', 'high', 'medium', 'low', 'informational')
            THEN json_extract(finding, '$.severity')
          ELSE 'medium'
        END
        OR coalesce(cwe, '') <> coalesce(NULLIF(trim(coalesce(json_extract(finding, '$.cwe'), '')), ''), '')
        OR origin IS NULL
        OR origin <> trim(coalesce(json_extract(finding, '$.origin'), ''))
        OR triage_status IS NULL
        OR triage_status <> CASE
          WHEN json_extract(finding, '$.operatorTriage.status') IN ('open', 'confirmed_by_operator', 'accepted_risk', 'false_positive', 'fixed')
            THEN json_extract(finding, '$.operatorTriage.status')
          ELSE 'open'
        END
    `).run()
    return Number(info.changes ?? 0)
  },

  /**
   * Indexed rollup of `(findingCount, confirmedCount)` per run ID using only promoted relational
   * columns (`verification_class`, `status`, `superseded_by_finding_id`). Zero `json_extract`.
   */
  rollupCountsByRunIds(
    client: DatabaseSync,
    runIds: readonly string[],
  ): Map<string, RunFindingRollup> {
    const out = new Map<string, RunFindingRollup>()
    const unique = [...new Set(runIds.filter(Boolean))]
    if (!unique.length) return out
    for (const runId of unique) {
      out.set(runId, { runId, findingCount: 0, confirmedCount: 0 })
    }
    const placeholders = unique.map(() => '?').join(', ')
    const rows = client.prepare(`
      SELECT
        run_id AS runId,
        count(*) AS findingCount,
        sum(CASE WHEN ${CONFIRMED_FINDING_PREDICATE_SQL} THEN 1 ELSE 0 END) AS confirmedCount
      FROM findings
      WHERE run_id IN (${placeholders})
        AND superseded_by_finding_id IS NULL
      GROUP BY run_id
    `).all(...unique) as Array<{ runId: string; findingCount: number; confirmedCount: number }>
    for (const row of rows) {
      out.set(row.runId, {
        runId: row.runId,
        findingCount: Number(row.findingCount ?? 0),
        confirmedCount: Number(row.confirmedCount ?? 0),
      })
    }
    return out
  },

  /** Indexed count of runtime-confirmed, non-superseded findings for a single run. */
  countConfirmedForRun(client: DatabaseSync, runId: string): number {
    const row = client.prepare(`
      SELECT count(*) AS c
      FROM findings
      WHERE run_id = ? AND ${CONFIRMED_FINDING_PREDICATE_SQL}
    `).get(runId) as { c?: number } | undefined
    return Number(row?.c ?? 0)
  },

  /** Indexed finding query over promoted columns returning canonical `TriagedFinding` objects. */
  queryFindings(
    client: DatabaseSync,
    runId: string,
    filter: FindingQueryFilter = {},
  ): TriagedFinding[] {
    const conditions: string[] = ['run_id = ?']
    const params: Array<string | number> = [runId]
    if (!filter.includeSuperseded) {
      conditions.push('superseded_by_finding_id IS NULL')
    }
    const pushIn = (column: string, value: string | readonly string[] | undefined) => {
      if (value === undefined) return
      const values = Array.isArray(value) ? value : [value]
      if (values.length === 0) {
        conditions.push('1 = 0')
        return
      }
      conditions.push(`${column} IN (${values.map(() => '?').join(', ')})`)
      params.push(...values)
    }
    pushIn('status', filter.status)
    pushIn('severity', filter.severity)
    pushIn('triage_status', filter.triageStatus)
    pushIn('verification_class', filter.verificationClass)
    if (filter.cwe !== undefined) {
      conditions.push('cwe = ?')
      params.push(filter.cwe.trim())
    }
    if (filter.origin !== undefined) {
      conditions.push('origin = ?')
      params.push(filter.origin.trim())
    }
    const limit = resolvePageLimit(filter.limit, 500)
    const offset = resolvePageOffset(filter.offset)
    const rows = client.prepare(`
      SELECT * FROM findings
      WHERE ${conditions.join(' AND ')}
      ORDER BY rowid ASC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset) as unknown as RawFindingRow[]
    return rows.map(row => FindingCodec.fromRow(row))
  },
}
