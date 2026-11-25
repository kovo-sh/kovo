// Read-only external impact oracle for oss-sealed-woodpecker-01 (loopback_oob_collector).
// Pure Node 24+ TypeScript, zero npm deps, zero shell execution, zero exploit payloads.

import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  ExternalOracleObservation,
  LoopbackOobCollectorOracleSpec,
  ManifestBundle,
  OracleProbeInput,
  OssAnchorManifest,
} from '../../lib/types.ts'
import { evaluateOracleEvidence, validateExternalImpactOracle } from '../../lib/oracle-runner.ts'
import { isLoopbackUrl } from '../../lib/safety.ts'

export const ANCHOR_ID = 'oss-sealed-woodpecker-01'
export const PROJECT_NAME = 'woodpecker'

const HERE = dirname(fileURLToPath(import.meta.url))
const SEALED_MANIFEST_PATH = resolve(HERE, '../../manifests/sealed-anchors.json')

function loadWoodpeckerManifest(): OssAnchorManifest {
  const bundle = JSON.parse(readFileSync(SEALED_MANIFEST_PATH, 'utf8')) as ManifestBundle
  const anchor = bundle.anchors?.find((entry) => entry.anchorId === ANCHOR_ID)
  if (!anchor) {
    throw new Error(`Missing manifest entry '${ANCHOR_ID}' in ${SEALED_MANIFEST_PATH}`)
  }
  if (anchor.impactOracle.kind !== 'loopback_oob_collector') {
    throw new Error(
      `Expected loopback_oob_collector oracle for '${ANCHOR_ID}', got '${anchor.impactOracle.kind}'`,
    )
  }
  const serviceNames = new Set(Object.keys(anchor.composeTemplate.services))
  const issues = validateExternalImpactOracle(anchor.impactOracle, ANCHOR_ID, serviceNames)
  if (issues.length > 0) {
    throw new Error(`Invalid oracle spec for '${ANCHOR_ID}': ${JSON.stringify(issues)}`)
  }
  return anchor
}

export const ANCHOR_MANIFEST: OssAnchorManifest = loadWoodpeckerManifest()
export const ORACLE_SPEC: LoopbackOobCollectorOracleSpec = ANCHOR_MANIFEST
  .impactOracle as LoopbackOobCollectorOracleSpec
export const EXPECTED_PATCH_BROKE_HOP_IDS: readonly string[] = ANCHOR_MANIFEST.expectedPatchBrokeHopIds

export interface WoodpeckerOobEvent {
  method: string
  path: string
  canaryToken?: string
  correlationId?: string
  receivedAtMs: number
}

export interface WoodpeckerOracleEvidence {
  requests: readonly WoodpeckerOobEvent[]
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

export function isRunScopedCanary(token: string | undefined): boolean {
  return typeof token === 'string' && token.startsWith(ORACLE_SPEC.runScopedCanaryPrefix)
}

export function assertLoopbackCollectorUrl(): void {
  if (!isLoopbackUrl(ORACLE_SPEC.collectorUrl)) {
    throw new Error(`Woodpecker OOB collectorUrl '${ORACLE_SPEC.collectorUrl}' must be strictly loopback.`)
  }
}

export function buildWoodpeckerProbeInput(
  evidence: WoodpeckerOracleEvidence,
): Extract<OracleProbeInput, { kind: 'loopback_oob_collector' }> {
  return {
    kind: 'loopback_oob_collector',
    observedAtMs: evidence.observedAtMs,
    correlationId: evidence.correlationId,
    requests: evidence.requests.map((req) => ({
      method: req.method,
      path: req.path,
      canaryToken: req.canaryToken,
      correlationId: req.correlationId,
      receivedAtMs: req.receivedAtMs,
    })),
  }
}

export function evaluateWoodpeckerOracle(
  runId: string,
  buildTarget: 'vulnerable' | 'patched',
  evidence: WoodpeckerOracleEvidence,
): ExternalOracleObservation {
  assertLoopbackCollectorUrl()
  return evaluateOracleEvidence(
    ORACLE_SPEC,
    ANCHOR_ID,
    runId,
    buildTarget,
    buildWoodpeckerProbeInput(evidence),
  )
}

export function evaluatePairedBuilds(params: {
  runId: string
  vulnerableEvidence: WoodpeckerOracleEvidence
  patchedEvidence: WoodpeckerOracleEvidence
}): PairedBuildOracleReport {
  const vulnerableObservation = evaluateWoodpeckerOracle(
    params.runId,
    'vulnerable',
    params.vulnerableEvidence,
  )
  const patchedObservation = evaluateWoodpeckerOracle(
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
