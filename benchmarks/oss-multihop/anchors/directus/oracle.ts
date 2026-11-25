// Read-only external impact oracle for oss-dev-directus-01 (db_query).
// Pure Node 24+ TypeScript, zero npm deps, zero shell execution, zero exploit payloads.

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  DbQueryOracleSpec,
  ExternalOracleObservation,
  ManifestBundle,
  OracleProbeInput,
  OssAnchorManifest,
} from '../../lib/types.ts'
import { evaluateOracleEvidence, validateExternalImpactOracle } from '../../lib/oracle-runner.ts'

export const ANCHOR_ID = 'oss-dev-directus-01'
export const PROJECT_NAME = 'directus'

const HERE = dirname(fileURLToPath(import.meta.url))
const DEV_MANIFEST_PATH = resolve(HERE, '../../manifests/dev-anchors.json')

function loadDirectusManifest(): OssAnchorManifest {
  const bundle = JSON.parse(readFileSync(DEV_MANIFEST_PATH, 'utf8')) as ManifestBundle
  const anchor = bundle.anchors?.find((entry) => entry.anchorId === ANCHOR_ID)
  if (!anchor) {
    throw new Error(`Missing manifest entry '${ANCHOR_ID}' in ${DEV_MANIFEST_PATH}`)
  }
  if (anchor.impactOracle.kind !== 'db_query') {
    throw new Error(`Expected db_query oracle for '${ANCHOR_ID}', got '${anchor.impactOracle.kind}'`)
  }
  const serviceNames = new Set(Object.keys(anchor.composeTemplate.services))
  const issues = validateExternalImpactOracle(anchor.impactOracle, ANCHOR_ID, serviceNames)
  if (issues.length > 0) {
    throw new Error(`Invalid oracle spec for '${ANCHOR_ID}': ${JSON.stringify(issues)}`)
  }
  return anchor
}

export const ANCHOR_MANIFEST: OssAnchorManifest = loadDirectusManifest()
export const ORACLE_SPEC: DbQueryOracleSpec = ANCHOR_MANIFEST.impactOracle as DbQueryOracleSpec
export const EXPECTED_PATCH_BROKE_HOP_IDS: readonly string[] = ANCHOR_MANIFEST.expectedPatchBrokeHopIds

export type DirectusAuditRow = Record<string, string | number | boolean | null>

export interface DirectusDbEvidence {
  rows: readonly DirectusAuditRow[]
  observedAtMs: number
  correlationId?: string
}

export interface PairedBuildOracleReport {
  anchorId: string
  oracleId: string
  vulnerableObservation: ExternalOracleObservation
  patchedObservation: ExternalOracleObservation
  impactConfirmedOnVulnerable: boolean
  impactEliminatedOnPatched: boolean
  expectedPatchBrokeHopIds: readonly string[]
}

export function isRunScopedCanary(value: string | undefined): boolean {
  return typeof value === 'string' && value.startsWith(ORACLE_SPEC.runScopedCanaryPrefix)
}

export function getReadOnlyAuditQuery(): string {
  return ORACLE_SPEC.readOnlyQuery
}

export function buildDirectusProbeInput(
  evidence: DirectusDbEvidence,
): Extract<OracleProbeInput, { kind: 'db_query' }> {
  return {
    kind: 'db_query',
    observedAtMs: evidence.observedAtMs,
    correlationId: evidence.correlationId,
    rows: evidence.rows.map((row) => ({ ...row })),
  }
}

export function evaluateDirectusOracle(
  runId: string,
  buildTarget: 'vulnerable' | 'patched',
  evidence: DirectusDbEvidence,
): ExternalOracleObservation {
  return evaluateOracleEvidence(
    ORACLE_SPEC,
    ANCHOR_ID,
    runId,
    buildTarget,
    buildDirectusProbeInput(evidence),
  )
}

export function evaluatePairedBuilds(params: {
  runId: string
  vulnerableEvidence: DirectusDbEvidence
  patchedEvidence: DirectusDbEvidence
}): PairedBuildOracleReport {
  const vulnerableObservation = evaluateDirectusOracle(
    params.runId,
    'vulnerable',
    params.vulnerableEvidence,
  )
  const patchedObservation = evaluateDirectusOracle(
    params.runId,
    'patched',
    params.patchedEvidence,
  )
  return {
    anchorId: ANCHOR_ID,
    oracleId: ORACLE_SPEC.oracleId,
    vulnerableObservation,
    patchedObservation,
    impactConfirmedOnVulnerable: vulnerableObservation.observed === true,
    impactEliminatedOnPatched: patchedObservation.observed === false,
    expectedPatchBrokeHopIds: EXPECTED_PATCH_BROKE_HOP_IDS,
  }
}
