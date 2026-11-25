// Read-only external impact oracle for oss-dev-ghost-01 (file_integrity).
// Pure Node 24+ TypeScript, zero npm deps, zero shell execution, zero exploit payloads.

import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  ExternalOracleObservation,
  FileIntegrityOracleSpec,
  ManifestBundle,
  OracleProbeInput,
  OssAnchorManifest,
} from '../../lib/types.ts'
import { evaluateOracleEvidence, validateExternalImpactOracle } from '../../lib/oracle-runner.ts'

export const ANCHOR_ID = 'oss-dev-ghost-01'
export const PROJECT_NAME = 'ghost'

const HERE = dirname(fileURLToPath(import.meta.url))
const DEV_MANIFEST_PATH = resolve(HERE, '../../manifests/dev-anchors.json')
const MAX_PREVIEW_BYTES = 4096

function loadGhostManifest(): OssAnchorManifest {
  const bundle = JSON.parse(readFileSync(DEV_MANIFEST_PATH, 'utf8')) as ManifestBundle
  const anchor = bundle.anchors?.find((entry) => entry.anchorId === ANCHOR_ID)
  if (!anchor) {
    throw new Error(`Missing manifest entry '${ANCHOR_ID}' in ${DEV_MANIFEST_PATH}`)
  }
  if (anchor.impactOracle.kind !== 'file_integrity') {
    throw new Error(`Expected file_integrity oracle for '${ANCHOR_ID}', got '${anchor.impactOracle.kind}'`)
  }
  const serviceNames = new Set(Object.keys(anchor.composeTemplate.services))
  const issues = validateExternalImpactOracle(anchor.impactOracle, ANCHOR_ID, serviceNames)
  if (issues.length > 0) {
    throw new Error(`Invalid oracle spec for '${ANCHOR_ID}': ${JSON.stringify(issues)}`)
  }
  return anchor
}

export const ANCHOR_MANIFEST: OssAnchorManifest = loadGhostManifest()
export const ORACLE_SPEC: FileIntegrityOracleSpec = ANCHOR_MANIFEST
  .impactOracle as FileIntegrityOracleSpec
export const EXPECTED_PATCH_BROKE_HOP_IDS: readonly string[] = ANCHOR_MANIFEST.expectedPatchBrokeHopIds

export interface GhostFileEvidence {
  exists: boolean
  sha256?: string
  contentPreview?: string
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

/**
 * Pure read-only helper for inspecting a bind-mounted or local export audit marker file
 * into a structured `GhostFileEvidence` payload without modifying the filesystem.
 */
export function readAuditMarkerEvidence(
  filePath: string,
  observedAtMs: number,
  correlationId?: string,
): GhostFileEvidence {
  if (!existsSync(filePath)) {
    return {
      exists: false,
      observedAtMs,
      correlationId,
    }
  }
  const raw = readFileSync(filePath)
  const sha256 = createHash('sha256').update(raw).digest('hex')
  const contentPreview = raw.subarray(0, MAX_PREVIEW_BYTES).toString('utf8')
  return {
    exists: true,
    sha256,
    contentPreview,
    observedAtMs,
    correlationId,
  }
}

export function buildGhostProbeInput(
  evidence: GhostFileEvidence,
): Extract<OracleProbeInput, { kind: 'file_integrity' }> {
  return {
    kind: 'file_integrity',
    exists: evidence.exists,
    sha256: evidence.sha256,
    contentPreview: evidence.contentPreview,
    observedAtMs: evidence.observedAtMs,
    correlationId: evidence.correlationId,
  }
}

export function evaluateGhostOracle(
  runId: string,
  buildTarget: 'vulnerable' | 'patched',
  evidence: GhostFileEvidence,
): ExternalOracleObservation {
  return evaluateOracleEvidence(
    ORACLE_SPEC,
    ANCHOR_ID,
    runId,
    buildTarget,
    buildGhostProbeInput(evidence),
  )
}

export function evaluatePairedBuilds(params: {
  runId: string
  vulnerableEvidence: GhostFileEvidence
  patchedEvidence: GhostFileEvidence
}): PairedBuildOracleReport {
  const vulnerableObservation = evaluateGhostOracle(
    params.runId,
    'vulnerable',
    params.vulnerableEvidence,
  )
  const patchedObservation = evaluateGhostOracle(
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
