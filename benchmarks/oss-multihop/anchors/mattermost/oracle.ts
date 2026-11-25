// Read-only external impact oracle for oss-dev-mattermost-01 (container_log).
// Pure Node 24+ TypeScript, zero npm deps, zero shell execution, zero exploit payloads.

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  ContainerLogOracleSpec,
  ExternalOracleObservation,
  ManifestBundle,
  OracleProbeInput,
  OssAnchorManifest,
} from '../../lib/types.ts'
import { evaluateOracleEvidence, validateExternalImpactOracle } from '../../lib/oracle-runner.ts'

export const ANCHOR_ID = 'oss-dev-mattermost-01'
export const PROJECT_NAME = 'mattermost'

const HERE = dirname(fileURLToPath(import.meta.url))
const DEV_MANIFEST_PATH = resolve(HERE, '../../manifests/dev-anchors.json')

function loadMattermostManifest(): OssAnchorManifest {
  const bundle = JSON.parse(readFileSync(DEV_MANIFEST_PATH, 'utf8')) as ManifestBundle
  const anchor = bundle.anchors?.find((entry) => entry.anchorId === ANCHOR_ID)
  if (!anchor) {
    throw new Error(`Missing manifest entry '${ANCHOR_ID}' in ${DEV_MANIFEST_PATH}`)
  }
  if (anchor.impactOracle.kind !== 'container_log') {
    throw new Error(`Expected container_log oracle for '${ANCHOR_ID}', got '${anchor.impactOracle.kind}'`)
  }
  const serviceNames = new Set(Object.keys(anchor.composeTemplate.services))
  const issues = validateExternalImpactOracle(anchor.impactOracle, ANCHOR_ID, serviceNames)
  if (issues.length > 0) {
    throw new Error(`Invalid oracle spec for '${ANCHOR_ID}': ${JSON.stringify(issues)}`)
  }
  return anchor
}

export const ANCHOR_MANIFEST: OssAnchorManifest = loadMattermostManifest()
export const ORACLE_SPEC: ContainerLogOracleSpec = ANCHOR_MANIFEST
  .impactOracle as ContainerLogOracleSpec
export const EXPECTED_PATCH_BROKE_HOP_IDS: readonly string[] = ANCHOR_MANIFEST.expectedPatchBrokeHopIds

export interface MattermostLogLine {
  stream: 'stdout' | 'stderr'
  text: string
  timestampMs?: number
}

export interface MattermostLogEvidence {
  lines: readonly MattermostLogLine[]
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

export function buildMattermostProbeInput(
  evidence: MattermostLogEvidence,
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

export function evaluateMattermostOracle(
  runId: string,
  buildTarget: 'vulnerable' | 'patched',
  evidence: MattermostLogEvidence,
): ExternalOracleObservation {
  return evaluateOracleEvidence(
    ORACLE_SPEC,
    ANCHOR_ID,
    runId,
    buildTarget,
    buildMattermostProbeInput(evidence),
  )
}

export function evaluatePairedBuilds(params: {
  runId: string
  vulnerableEvidence: MattermostLogEvidence
  patchedEvidence: MattermostLogEvidence
}): PairedBuildOracleReport {
  const vulnerableObservation = evaluateMattermostOracle(
    params.runId,
    'vulnerable',
    params.vulnerableEvidence,
  )
  const patchedObservation = evaluateMattermostOracle(
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
