// Read-only external impact oracle for oss-sealed-keycloak-01 (db_query).
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

export const ANCHOR_ID = 'oss-sealed-keycloak-01'
export const PROJECT_NAME = 'keycloak'

const HERE = dirname(fileURLToPath(import.meta.url))
const SEALED_MANIFEST_PATH = resolve(HERE, '../../manifests/sealed-anchors.json')

function loadKeycloakManifest(): OssAnchorManifest {
  const bundle = JSON.parse(readFileSync(SEALED_MANIFEST_PATH, 'utf8')) as ManifestBundle
  const anchor = bundle.anchors?.find((entry) => entry.anchorId === ANCHOR_ID)
  if (!anchor) {
    throw new Error(`Missing manifest entry '${ANCHOR_ID}' in ${SEALED_MANIFEST_PATH}`)
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

export const ANCHOR_MANIFEST: OssAnchorManifest = loadKeycloakManifest()
export const ORACLE_SPEC: DbQueryOracleSpec = ANCHOR_MANIFEST.impactOracle as DbQueryOracleSpec
export const EXPECTED_PATCH_BROKE_HOP_IDS: readonly string[] = ANCHOR_MANIFEST.expectedPatchBrokeHopIds

export type KeycloakAuditRow = Record<string, string | number | boolean | null>

export interface KeycloakDbEvidence {
  rows: readonly KeycloakAuditRow[]
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

export function buildKeycloakProbeInput(
  evidence: KeycloakDbEvidence,
): Extract<OracleProbeInput, { kind: 'db_query' }> {
  return {
    kind: 'db_query',
    observedAtMs: evidence.observedAtMs,
    correlationId: evidence.correlationId,
    rows: evidence.rows.map((row) => ({ ...row })),
  }
}

export function evaluateKeycloakOracle(
  runId: string,
  buildTarget: 'vulnerable' | 'patched',
  evidence: KeycloakDbEvidence,
): ExternalOracleObservation {
  return evaluateOracleEvidence(
    ORACLE_SPEC,
    ANCHOR_ID,
    runId,
    buildTarget,
    buildKeycloakProbeInput(evidence),
  )
}

export function evaluatePairedBuilds(params: {
  runId: string
  vulnerableEvidence: KeycloakDbEvidence
  patchedEvidence: KeycloakDbEvidence
}): PairedBuildOracleReport {
  const vulnerableObservation = evaluateKeycloakOracle(
    params.runId,
    'vulnerable',
    params.vulnerableEvidence,
  )
  const patchedObservation = evaluateKeycloakOracle(
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
