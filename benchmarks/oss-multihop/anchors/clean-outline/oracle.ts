// Read-only external 0-FP clean negative-control oracle for oss-clean-outline-02 (container_log).
// Pure Node 24+ TypeScript, zero npm deps, zero shell execution, zero exploit payloads.

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  CleanControlGradeDetail,
  CleanNegativeControlSpec,
  ContainerLogOracleSpec,
  ExternalOracleObservation,
  KovoCompositeProofReceipt,
  ManifestBundle,
  OracleProbeInput,
} from '../../lib/types.ts'
import { evaluateOracleEvidence, validateExternalImpactOracle } from '../../lib/oracle-runner.ts'
import { gradeCleanControl } from '../../lib/grader.ts'

export const CONTROL_ID = 'oss-clean-outline-02'
export const PROJECT_NAME = 'outline'
export const MAX_ALLOWED_FINDINGS = 0 as const

const HERE = dirname(fileURLToPath(import.meta.url))
const CLEAN_CONTROLS_PATH = resolve(HERE, '../../manifests/clean-controls.json')

function loadOutlineCleanSpec(): CleanNegativeControlSpec {
  const bundle = JSON.parse(readFileSync(CLEAN_CONTROLS_PATH, 'utf8')) as ManifestBundle
  const control = bundle.cleanControls?.find((entry) => entry.controlId === CONTROL_ID)
  if (!control) {
    throw new Error(`Missing clean-control entry '${CONTROL_ID}' in ${CLEAN_CONTROLS_PATH}`)
  }
  if (control.maxAllowedFindings !== 0) {
    throw new Error(`Clean control '${CONTROL_ID}' must enforce maxAllowedFindings: 0`)
  }
  const oracle = control.impactOracles[0]
  if (!oracle || oracle.kind !== 'container_log') {
    throw new Error(`Expected container_log oracle for '${CONTROL_ID}'`)
  }
  const serviceNames = new Set(Object.keys(control.composeTemplate.services))
  const issues = validateExternalImpactOracle(oracle, CONTROL_ID, serviceNames)
  if (issues.length > 0) {
    throw new Error(`Invalid clean-control oracle spec for '${CONTROL_ID}': ${JSON.stringify(issues)}`)
  }
  return control
}

export const CLEAN_CONTROL_SPEC: CleanNegativeControlSpec = loadOutlineCleanSpec()
export const ORACLE_SPEC: ContainerLogOracleSpec = CLEAN_CONTROL_SPEC
  .impactOracles[0] as ContainerLogOracleSpec

export interface OutlineLogLine {
  stream: 'stdout' | 'stderr'
  text: string
  timestampMs?: number
}

export interface OutlineCleanLogEvidence {
  lines: readonly OutlineLogLine[]
  observedAtMs: number
  correlationId?: string
}

export interface CleanControlAssertionResult {
  passed: boolean
  controlId: string
  observation: ExternalOracleObservation
  grade: CleanControlGradeDetail
}

export function buildOutlineProbeInput(
  evidence: OutlineCleanLogEvidence,
): Extract<OracleProbeInput, { kind: 'container_log' }> {
  return {
    kind: 'container_log',
    observedAtMs: evidence.observedAtMs,
    correlationId: evidence.correlationId,
    lines: evidence.lines.map((line) => ({
      stream: line.stream,
      text: line.text,
      timestampMs: line.timestampMs,
    })),
  }
}

export function evaluateOutlineCleanOracle(
  runId: string,
  evidence: OutlineCleanLogEvidence,
): ExternalOracleObservation {
  return evaluateOracleEvidence(
    ORACLE_SPEC,
    CONTROL_ID,
    runId,
    'patched',
    buildOutlineProbeInput(evidence),
  )
}

/**
 * Evaluates the hard 0-FP clean negative-control gate:
 * PASS iff the external container-log oracle stays strictly silent (`observed === false`)
 * AND Kovo emits zero findings/receipts targeting `oss-clean-outline-02`.
 */
export function assertOutlineZeroFalsePositives(
  runId: string,
  receipts: readonly KovoCompositeProofReceipt[],
  evidence: OutlineCleanLogEvidence,
): CleanControlAssertionResult {
  const observation = evaluateOutlineCleanOracle(runId, evidence)
  const grade = gradeCleanControl(CLEAN_CONTROL_SPEC, receipts, [observation])
  return {
    passed: grade.passed && !observation.observed,
    controlId: CONTROL_ID,
    observation,
    grade,
  }
}
