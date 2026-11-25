// Read-only external 0-FP clean negative-control oracle for oss-clean-vikunja-01 (db_query).
// Pure Node 24+ TypeScript, zero npm deps, zero shell execution, zero exploit payloads.

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  CleanControlGradeDetail,
  CleanNegativeControlSpec,
  DbQueryOracleSpec,
  ExternalOracleObservation,
  GuardianCompositeProofReceipt,
  ManifestBundle,
  OracleProbeInput,
} from '../../lib/types.ts'
import { evaluateOracleEvidence, validateExternalImpactOracle } from '../../lib/oracle-runner.ts'
import { gradeCleanControl } from '../../lib/grader.ts'

export const CONTROL_ID = 'oss-clean-vikunja-01'
export const PROJECT_NAME = 'vikunja'
export const MAX_ALLOWED_FINDINGS = 0 as const

const HERE = dirname(fileURLToPath(import.meta.url))
const CLEAN_CONTROLS_PATH = resolve(HERE, '../../manifests/clean-controls.json')

function loadVikunjaCleanSpec(): CleanNegativeControlSpec {
  const bundle = JSON.parse(readFileSync(CLEAN_CONTROLS_PATH, 'utf8')) as ManifestBundle
  const control = bundle.cleanControls?.find((entry) => entry.controlId === CONTROL_ID)
  if (!control) {
    throw new Error(`Missing clean-control entry '${CONTROL_ID}' in ${CLEAN_CONTROLS_PATH}`)
  }
  if (control.maxAllowedFindings !== 0) {
    throw new Error(`Clean control '${CONTROL_ID}' must enforce maxAllowedFindings: 0`)
  }
  const oracle = control.impactOracles[0]
  if (!oracle || oracle.kind !== 'db_query') {
    throw new Error(`Expected db_query oracle for '${CONTROL_ID}'`)
  }
  const serviceNames = new Set(Object.keys(control.composeTemplate.services))
  const issues = validateExternalImpactOracle(oracle, CONTROL_ID, serviceNames)
  if (issues.length > 0) {
    throw new Error(`Invalid clean-control oracle spec for '${CONTROL_ID}': ${JSON.stringify(issues)}`)
  }
  return control
}

export const CLEAN_CONTROL_SPEC: CleanNegativeControlSpec = loadVikunjaCleanSpec()
export const ORACLE_SPEC: DbQueryOracleSpec = CLEAN_CONTROL_SPEC.impactOracles[0] as DbQueryOracleSpec

export type VikunjaAuditRow = Record<string, string | number | boolean | null>

export interface VikunjaCleanDbEvidence {
  rows: readonly VikunjaAuditRow[]
  observedAtMs: number
  correlationId?: string
}

export interface CleanControlAssertionResult {
  passed: boolean
  controlId: string
  observation: ExternalOracleObservation
  grade: CleanControlGradeDetail
}

export function buildVikunjaProbeInput(
  evidence: VikunjaCleanDbEvidence,
): Extract<OracleProbeInput, { kind: 'db_query' }> {
  return {
    kind: 'db_query',
    observedAtMs: evidence.observedAtMs,
    correlationId: evidence.correlationId,
    rows: evidence.rows.map((row) => ({ ...row })),
  }
}

export function evaluateVikunjaCleanOracle(
  runId: string,
  evidence: VikunjaCleanDbEvidence,
): ExternalOracleObservation {
  return evaluateOracleEvidence(
    ORACLE_SPEC,
    CONTROL_ID,
    runId,
    'patched',
    buildVikunjaProbeInput(evidence),
  )
}

/**
 * Evaluates the hard 0-FP clean negative-control gate:
 * PASS iff the external DB oracle stays strictly silent (`observed === false`)
 * AND Guardian emits zero findings/receipts targeting `oss-clean-vikunja-01`.
 */
export function assertVikunjaZeroFalsePositives(
  runId: string,
  receipts: readonly GuardianCompositeProofReceipt[],
  evidence: VikunjaCleanDbEvidence,
): CleanControlAssertionResult {
  const observation = evaluateVikunjaCleanOracle(runId, evidence)
  const grade = gradeCleanControl(CLEAN_CONTROL_SPEC, receipts, [observation])
  return {
    passed: grade.passed && !observation.observed,
    controlId: CONTROL_ID,
    observation,
    grade,
  }
}
