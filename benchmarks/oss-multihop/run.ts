// CLI & programmatic entrypoint for benchmarks/oss-multihop/.
// Commands: list | validate | grade | selftest
// Zero npm dependencies (node:* only); Node 24+ native TypeScript.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  CleanNegativeControlSpec,
  ExternalOracleObservation,
  GuardianCompositeProofReceipt,
  ManifestBundle,
  OssAnchorManifest,
  OssGradeResult,
  PatchRetestRecord,
  RunTelemetry,
  ValidationIssue,
} from './lib/types.ts'
import { assertLocalLabAllowed } from './lib/safety.ts'
import { evaluateOracleEvidence, validateManifestBundle } from './lib/oracle-runner.ts'
import { gradeOssRun, renderOssScorecardMarkdown } from './lib/grader.ts'

export * from './lib/types.ts'
export * from './lib/safety.ts'
export * from './lib/oracle-runner.ts'
export * from './lib/grader.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
export const MANIFESTS_DIR = join(HERE, 'manifests')
export const DEV_MANIFEST_PATH = join(MANIFESTS_DIR, 'dev-anchors.json')
export const CLEAN_CONTROLS_PATH = join(MANIFESTS_DIR, 'clean-controls.json')
export const SEALED_EXAMPLE_PATH = join(MANIFESTS_DIR, 'sealed-manifest.example.json')

export function loadManifestBundle(filePath: string): ManifestBundle {
  const raw = readFileSync(filePath, 'utf8')
  return JSON.parse(raw) as ManifestBundle
}

export interface FileValidationReport {
  file: string
  valid: boolean
  issueCount: number
  issues: ValidationIssue[]
}

export function validateAllCommittedManifests(): {
  valid: boolean
  results: FileValidationReport[]
} {
  const files = [DEV_MANIFEST_PATH, CLEAN_CONTROLS_PATH, SEALED_EXAMPLE_PATH]
  const results: FileValidationReport[] = files.map((file) => {
    const bundle = loadManifestBundle(file)
    const res = validateManifestBundle(bundle)
    return {
      file,
      valid: res.valid,
      issueCount: res.issues.length,
      issues: res.issues,
    }
  })
  return {
    valid: results.every((r) => r.valid),
    results,
  }
}

export interface SelfTestReport {
  ok: boolean
  manifestsValid: boolean
  oracleKindsVerified: number
  passingGrade: OssGradeResult
  cleanControlFpGateRejected: boolean
}

/**
 * Pure offline self-test (no Docker): validates all committed manifests, exercises all 4
 * ExternalImpactOracleSpec evaluators, verifies two-side confirmation + patchBrokeHopId
 * closure, and verifies the clean-control 0-FP failure tripwire.
 */
export function runOfflineSelfTest(): SelfTestReport {
  assertLocalLabAllowed()

  const manifestReport = validateAllCommittedManifests()
  if (!manifestReport.valid) {
    throw new Error(
      `Manifest validation failed during selftest: ${JSON.stringify(manifestReport.results.filter((r) => !r.valid))}`,
    )
  }

  const devBundle = loadManifestBundle(DEV_MANIFEST_PATH)
  const cleanBundle = loadManifestBundle(CLEAN_CONTROLS_PATH)
  const anchors = devBundle.anchors ?? []
  const controls = cleanBundle.cleanControls ?? []

  const runId = 'oss_selftest_run_01'
  const baseTs = 1_732_500_000_000

  const gitea = anchors.find((a) => a.project === 'gitea')!
  const directus = anchors.find((a) => a.project === 'directus')!
  const ghost = anchors.find((a) => a.project === 'ghost')!
  const mattermost = anchors.find((a) => a.project === 'mattermost')!

  const obsGitea = evaluateOracleEvidence(gitea.impactOracle, gitea.anchorId, runId, 'vulnerable', {
    kind: 'loopback_oob_collector',
    observedAtMs: baseTs + 4_000,
    correlationId: 'corr-gitea-1',
    requests: [
      {
        method: 'POST',
        path: '/oob/gitea/callback',
        canaryToken: 'oss_canary_gitea_selftest',
        correlationId: 'corr-gitea-1',
        receivedAtMs: baseTs + 4_000,
      },
    ],
  })
  const obsDirectus = evaluateOracleEvidence(directus.impactOracle, directus.anchorId, runId, 'vulnerable', {
    kind: 'db_query',
    observedAtMs: baseTs + 4_500,
    correlationId: 'corr-directus-1',
    rows: [{ id: 1, role_name: 'admin', canary_marker: 'oss_canary_directus_selftest' }],
  })
  const obsGhost = evaluateOracleEvidence(ghost.impactOracle, ghost.anchorId, runId, 'vulnerable', {
    kind: 'file_integrity',
    observedAtMs: baseTs + 5_000,
    correlationId: 'corr-ghost-1',
    exists: true,
    contentPreview: 'marker=oss_canary_ghost_selftest',
  })
  const obsMattermost = evaluateOracleEvidence(mattermost.impactOracle, mattermost.anchorId, runId, 'vulnerable', {
    kind: 'container_log',
    observedAtMs: baseTs + 5_500,
    correlationId: 'corr-mm-1',
    lines: [
      {
        stream: 'stdout',
        text: 'level=info audit_event=compliance_export_complete token=oss_canary_mm_selftest',
        timestampMs: baseTs + 5_500,
      },
    ],
  })

  const observations: ExternalOracleObservation[] = [obsGitea, obsDirectus, obsGhost, obsMattermost]
  const oracleKindsVerified = new Set(observations.filter((o) => o.observed).map((o) => o.kind)).size
  if (oracleKindsVerified !== 4) {
    throw new Error(`Expected 4 observed oracle kinds in selftest, got ${oracleKindsVerified}`)
  }

  const makeReceipt = (anchor: OssAnchorManifest, obs: ExternalOracleObservation): GuardianCompositeProofReceipt => {
    const origin = anchor.personas.find((p) => p.allowedAsChainOrigin)!
    return {
      receiptId: `rcpt_${anchor.anchorId}`,
      chainId: `chain_${anchor.anchorId}`,
      targetId: anchor.anchorId,
      terminalVulnClass: anchor.terminalVulnClass,
      verified: true,
      attackerOriginVerified: true,
      originPersona: origin.personaId,
      replayMode: 'fresh_clean_replay',
      hops: anchor.hops.map((h, idx) => ({
        hopId: h.hopId,
        order: h.order,
        surface: h.surface,
        actorPersona: origin.personaId,
        observedAtMs: baseTs + idx * 500,
        exchangeIds: [`ex_${anchor.anchorId}_${h.hopId}`],
      })),
      causalEdges: anchor.hops.slice(1).map((h, idx) => ({
        fromHopId: anchor.hops[idx].hopId,
        toHopId: h.hopId,
        bindingKind: h.incomingEdgeKind ?? 'value_binding',
        verified: true,
      })),
      terminalImpact: {
        observed: true,
        oracleId: anchor.impactOracle.oracleId,
        correlationId: obs.correlationId,
        observedAtMs: obs.observedAtMs,
      },
      runId,
    }
  }

  // Confirm 3/4 anchors (75% recall >= 50%) and close all 3 on their paired patched commits.
  const confirmedPairs: Array<[OssAnchorManifest, ExternalOracleObservation]> = [
    [gitea, obsGitea],
    [directus, obsDirectus],
    [ghost, obsGhost],
  ]
  const receipts = confirmedPairs.map(([a, o]) => makeReceipt(a, o))
  const patchRetests: PatchRetestRecord[] = confirmedPairs.map(([a, o]) => ({
    targetId: a.anchorId,
    receiptId: `rcpt_${a.anchorId}`,
    patchedCommitSha: a.patchedBuild.commitSha,
    replayedFullDag: true,
    terminalImpactEliminated: true,
    patchBrokeHopId: a.expectedPatchBrokeHopIds[0],
    patchedOracleObservation: {
      ...o,
      observationId: `${o.observationId}_patched`,
      buildTarget: 'patched',
      observed: false,
      detail: 'Impact eliminated on paired patched commit.',
    },
  }))

  const telemetry: RunTelemetry = {
    runId,
    split: 'dev',
    mode: 'white-box',
    durationMs: 1_200_000,
    costUsd: 4.0,
  }

  const passingGrade = gradeOssRun({
    anchors,
    cleanControls: controls,
    receipts,
    oracleObservations: [obsGitea, obsDirectus, obsGhost],
    patchRetests,
    telemetry,
  })

  // Verify clean-control 0-FP failure tripwire
  const fpReceipt: GuardianCompositeProofReceipt = {
    ...receipts[0],
    receiptId: 'rcpt_clean_fp_tripwire',
    targetId: controls[0].controlId,
  }
  const fpGrade = gradeOssRun({
    anchors,
    cleanControls: controls,
    receipts: [...receipts, fpReceipt],
    oracleObservations: [obsGitea, obsDirectus, obsGhost],
    patchRetests,
    telemetry,
  })
  const cleanControlFpGateRejected =
    !fpGrade.gates.passed &&
    !fpGrade.gates.cleanControlGatePassed &&
    fpGrade.cleanControlFpCount === 1

  const ok = manifestReport.valid && passingGrade.gates.passed && cleanControlFpGateRejected
  return {
    ok,
    manifestsValid: manifestReport.valid,
    oracleKindsVerified,
    passingGrade,
    cleanControlFpGateRejected,
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseFlags(args: string[]): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {}
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i]
    if (!token.startsWith('--')) continue
    const key = token.slice(2)
    const next = args[i + 1]
    if (next !== undefined && !next.startsWith('--')) {
      flags[key] = next
      i += 1
    } else {
      flags[key] = true
    }
  }
  return flags
}

function printHelp(): void {
  console.log(`benchmarks/oss-multihop CLI (Node 24+ native TS, zero npm deps)

Usage:
  node benchmarks/oss-multihop/run.ts list [--split dev|clean_control|all] [--json]
  node benchmarks/oss-multihop/run.ts validate [--manifest <path>] [--all]
  node benchmarks/oss-multihop/run.ts grade --manifest <path> [--controls <path>] --input <path> [--json <out>] [--md <out>]
  GUARDIAN_ALLOW_LOCAL_LAB=1 node benchmarks/oss-multihop/run.ts selftest
`)
}

interface RawGradePayload {
  receipts: GuardianCompositeProofReceipt[]
  oracleObservations: ExternalOracleObservation[]
  patchRetests?: PatchRetestRecord[]
  telemetry: RunTelemetry
}

function cmdList(flags: Record<string, string | boolean>): number {
  const split = typeof flags.split === 'string' ? flags.split : 'all'
  const devBundle = loadManifestBundle(DEV_MANIFEST_PATH)
  const cleanBundle = loadManifestBundle(CLEAN_CONTROLS_PATH)
  const anchors: OssAnchorManifest[] = split === 'clean_control' ? [] : (devBundle.anchors ?? [])
  const controls: CleanNegativeControlSpec[] = split === 'dev' ? [] : (cleanBundle.cleanControls ?? [])

  if (flags.json === true) {
    console.log(
      JSON.stringify(
        {
          devAnchors: anchors.map((a) => ({
            anchorId: a.anchorId,
            project: a.project,
            language: a.language,
            hopCount: a.hopCount,
            oracleKind: a.impactOracle.kind,
            vulnerableTag: a.vulnerableBuild.versionTag,
            patchedTag: a.patchedBuild.versionTag,
            expectedPatchBrokeHopIds: a.expectedPatchBrokeHopIds,
          })),
          cleanControls: controls.map((c) => ({
            controlId: c.controlId,
            project: c.project,
            language: c.language,
            patchedTag: c.patchedBuild.versionTag,
            maxAllowedFindings: c.maxAllowedFindings,
          })),
        },
        null,
        2,
      ),
    )
    return 0
  }

  if (anchors.length > 0) {
    console.log(`Dev OSS Multi-Hop Anchors (${anchors.length}):`)
    for (const a of anchors) {
      console.log(
        `  - ${a.anchorId} [${a.project} / ${a.language}] ${a.hopCount} hops | oracle=${a.impactOracle.kind} | ${a.vulnerableBuild.versionTag} -> ${a.patchedBuild.versionTag} (breaks: ${a.expectedPatchBrokeHopIds.join(',')})`,
      )
    }
  }
  if (controls.length > 0) {
    console.log(`Clean Patched Negative Controls (${controls.length}, 0-FP gate):`)
    for (const c of controls) {
      console.log(
        `  - ${c.controlId} [${c.project} / ${c.language}] ${c.patchedBuild.versionTag} | maxAllowedFindings=${c.maxAllowedFindings}`,
      )
    }
  }
  return 0
}

function cmdValidate(flags: Record<string, string | boolean>): number {
  if (typeof flags.manifest === 'string') {
    const file = resolve(flags.manifest)
    const bundle = loadManifestBundle(file)
    const res = validateManifestBundle(bundle)
    console.log(JSON.stringify({ file, valid: res.valid, issueCount: res.issues.length, issues: res.issues }, null, 2))
    return res.valid ? 0 : 1
  }
  const report = validateAllCommittedManifests()
  console.log(JSON.stringify(report, null, 2))
  return report.valid ? 0 : 1
}

function cmdGrade(flags: Record<string, string | boolean>): number {
  const manifestPath =
    typeof flags.manifest === 'string' ? resolve(flags.manifest) : DEV_MANIFEST_PATH
  const controlsPath =
    typeof flags.controls === 'string' ? resolve(flags.controls) : CLEAN_CONTROLS_PATH
  if (typeof flags.input !== 'string') {
    console.error('grade requires --input <path-to-observations.json>')
    return 2
  }
  const inputPath = resolve(flags.input)
  const anchorBundle = loadManifestBundle(manifestPath)
  const anchorVal = validateManifestBundle(anchorBundle)
  if (!anchorVal.valid) {
    console.error('Manifest failed validation:', JSON.stringify(anchorVal.issues))
    return 1
  }
  const controlBundle = loadManifestBundle(controlsPath)
  const controlVal = validateManifestBundle(controlBundle)
  if (!controlVal.valid) {
    console.error('Clean-controls manifest failed validation:', JSON.stringify(controlVal.issues))
    return 1
  }

  const payload = JSON.parse(readFileSync(inputPath, 'utf8')) as RawGradePayload
  const result = gradeOssRun({
    anchors: anchorBundle.anchors ?? [],
    cleanControls: controlBundle.cleanControls ?? [],
    receipts: payload.receipts ?? [],
    oracleObservations: payload.oracleObservations ?? [],
    patchRetests: payload.patchRetests ?? [],
    telemetry: payload.telemetry,
  })

  if (typeof flags.json === 'string') {
    const outJson = resolve(flags.json)
    mkdirSync(dirname(outJson), { recursive: true })
    writeFileSync(outJson, `${JSON.stringify(result, null, 2)}\n`, 'utf8')
  }
  if (typeof flags.md === 'string') {
    const outMd = resolve(flags.md)
    mkdirSync(dirname(outMd), { recursive: true })
    writeFileSync(outMd, renderOssScorecardMarkdown(result), 'utf8')
  }

  console.log(JSON.stringify(result, null, 2))
  return result.gates.passed ? 0 : 2
}

function cmdSelfTest(): number {
  const report = runOfflineSelfTest()
  console.log(
    JSON.stringify(
      {
        ok: report.ok,
        manifestsValid: report.manifestsValid,
        oracleKindsVerified: report.oracleKindsVerified,
        passingRecall: report.passingGrade.recall,
        passingPrecision: report.passingGrade.precision,
        patchRetestClosureRate: report.passingGrade.patchRetestClosureRate,
        tpPerUsd: report.passingGrade.tpPerUsd,
        tpPer10m: report.passingGrade.tpPer10m,
        cleanControlFpGateRejected: report.cleanControlFpGateRejected,
      },
      null,
      2,
    ),
  )
  return report.ok ? 0 : 1
}

function main(argv: string[]): number {
  const [cmd, ...rest] = argv
  if (!cmd || cmd === '--help' || cmd === '-h') {
    printHelp()
    return 0
  }
  const flags = parseFlags(rest)
  switch (cmd) {
    case 'list':
      return cmdList(flags)
    case 'validate':
      return cmdValidate(flags)
    case 'grade':
      return cmdGrade(flags)
    case 'selftest':
      return cmdSelfTest()
    default:
      console.error(`Unknown command '${cmd}'. Run with --help.`)
      return 2
  }
}

const isMain =
  process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)

if (isMain) {
  process.exitCode = main(process.argv.slice(2))
}
