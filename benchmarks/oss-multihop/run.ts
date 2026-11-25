// CLI & programmatic entrypoint for benchmarks/oss-multihop/.
// Commands: list | validate | grade | selftest
// Zero npm dependencies (node:* only); Node 24+ native TypeScript.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  AnchorGradeDetail,
  AnchorOutcomeStatus,
  AnchorSplit,
  CleanControlGradeDetail,
  CleanNegativeControlSpec,
  ExternalOracleObservation,
  GuardianCompositeProofReceipt,
  ManifestBundle,
  OssAnchorManifest,
  OssGradeInput,
  OssGradeResult,
  PatchRetestRecord,
  RunTelemetry,
  ValidationIssue,
} from './lib/types.ts'
import { assertLocalLabAllowed } from './lib/safety.ts'
import { evaluateOracleEvidence, validateManifestBundle } from './lib/oracle-runner.ts'
import {
  OSS_MIN_PATCH_CLOSURE_GATE,
  OSS_MIN_RECALL_GATE,
  gradeOssRun as rawGradeOssRun,
  renderOssScorecardMarkdown,
} from './lib/grader.ts'

export * from './lib/types.ts'
export * from './lib/safety.ts'
export * from './lib/oracle-runner.ts'
export {
  OSS_MIN_RECALL_GATE,
  OSS_MIN_PATCH_CLOSURE_GATE,
  verifyTwoSideConfirmation,
  gradePatchRetest,
  gradeCleanControl,
  renderOssScorecardMarkdown,
} from './lib/grader.ts'
export type { TwoSideVerdict, PatchRetestVerdict } from './lib/grader.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
export const MANIFESTS_DIR = join(HERE, 'manifests')
export const DEV_MANIFEST_PATH = join(MANIFESTS_DIR, 'dev-anchors.json')
export const SEALED_MANIFEST_PATH = join(MANIFESTS_DIR, 'sealed-anchors.json')
export const CLEAN_CONTROLS_PATH = join(MANIFESTS_DIR, 'clean-controls.json')
export const SEALED_EXAMPLE_PATH = join(MANIFESTS_DIR, 'sealed-manifest.example.json')

const SPURIOUS_ANCHOR_FP_STATUSES = new Set<AnchorOutcomeStatus>([
  'unconfirmed_receipt_only',
  'rejected_shortcut',
  'rejected_edge_binding',
  'rejected_replay_mode',
  'rejected_correlation',
])

export interface CertifyOssAnchorResult extends AnchorGradeDetail {
  split: 'dev' | 'sealed'
  cleanControl: false
  patchRetestPassed: boolean
  falsePositives: number
}

export interface CertifyOssCleanControlResult extends CleanControlGradeDetail {
  split: 'clean_control'
  cleanControl: true
  falsePositives: number
}

export interface CertifyOssGradeReport
  extends Omit<OssGradeResult, 'anchorResults' | 'cleanControlResults'> {
  /** Direct alias of `totalFpCount` for M4 certification scorecards. */
  falsePositives: number
  /** Worst-run precision for this OSS run (1.0 when 0 FPs). */
  worstRunPrecision: number
  /** Count of sealed anchors included in this report. */
  sealedAnchors: number
  /** Count of two-side confirmed sealed anchors included in this report. */
  sealedTpCount: number
  /** Sealed recall (`sealedTpCount / sealedAnchors`), or `null` if no sealed anchors were graded. */
  sealedRecall: number | null
  anchorResults: CertifyOssAnchorResult[]
  cleanControlResults: CertifyOssCleanControlResult[]
}

/**
 * Aligns a raw `OssGradeResult` from `lib/grader.ts` so its JSON payload is 100% directly
 * consumable by `scripts/certify-v8.ts --oss <path>` (`normalizeOssInputs`) with zero manual
 * adaptation, while preserving full backwards compatibility with `OssGradeResult`.
 */
export function toCertifyOssGradeReport(raw: OssGradeResult): CertifyOssGradeReport {
  const anchorResults: CertifyOssAnchorResult[] = raw.anchorResults.map((a) => ({
    ...a,
    split: a.split,
    cleanControl: false,
    patchRetestPassed: a.patchRetestStatus === 'closed',
    falsePositives: SPURIOUS_ANCHOR_FP_STATUSES.has(a.status) ? 1 : 0,
  }))

  const cleanControlResults: CertifyOssCleanControlResult[] = raw.cleanControlResults.map((c) => ({
    ...c,
    split: 'clean_control',
    cleanControl: true,
    falsePositives: c.fpCount,
  }))

  const sealedAnchors = anchorResults.filter((a) => a.split === 'sealed').length
  const sealedTpCount = anchorResults.filter((a) => a.split === 'sealed' && a.twoSideConfirmed).length
  const sealedRecall = sealedAnchors > 0 ? sealedTpCount / sealedAnchors : null

  // `scripts/certify-v8.ts` computes `patchRetestClosureRate = patchRetestClosed / patchRetestAttempted`.
  // Per CONTRACTS.md §6, every confirmed TP requires patch-retest closure, so unrun TPs must count
  // in `patchRetestAttempted` (`>= tpCount`) rather than being silently omitted from the denominator.
  const patchRetestAttempted = Math.max(raw.patchRetestAttempted, raw.tpCount)
  const patchRetestClosureRate =
    patchRetestAttempted > 0 ? raw.patchRetestClosed / patchRetestAttempted : 1

  const sealedRecallGatePassed = sealedRecall === null ? true : sealedRecall >= OSS_MIN_RECALL_GATE
  const recallGatePassed = raw.gates.recallGatePassed && sealedRecallGatePassed
  const patchRetestGatePassed =
    raw.tpCount === 0 ? true : patchRetestClosureRate >= OSS_MIN_PATCH_CLOSURE_GATE

  const failures = [...raw.gates.failures]
  if (!sealedRecallGatePassed) {
    failures.push(
      `Sealed recall gate failed: ${((sealedRecall ?? 0) * 100).toFixed(1)}% < ${(OSS_MIN_RECALL_GATE * 100).toFixed(0)}%.`,
    )
  }

  const split: AnchorSplit = sealedAnchors > 0 ? 'sealed' : raw.split

  return {
    ...raw,
    split,
    falsePositives: raw.totalFpCount,
    worstRunPrecision: raw.precision,
    sealedAnchors,
    sealedTpCount,
    sealedRecall,
    patchRetestAttempted,
    patchRetestClosureRate,
    anchorResults,
    cleanControlResults,
    gates: {
      ...raw.gates,
      recallGatePassed,
      patchRetestGatePassed,
      passed: failures.length === 0,
      failures,
    },
  }
}

/**
 * Grades an OSS multi-hop run and emits a certification-aligned `CertifyOssGradeReport`
 * directly consumable by `scripts/certify-v8.ts --oss <path>`.
 */
export function gradeOssRun(input: OssGradeInput): CertifyOssGradeReport {
  return toCertifyOssGradeReport(rawGradeOssRun(input))
}

export function isSealedManifestPath(filePath: string): boolean {
  const abs = resolve(filePath)
  return abs === resolve(SEALED_MANIFEST_PATH) || basename(abs) === 'sealed-anchors.json'
}

export function assertSealedM4Allowed(allowSealedM4: boolean, context = 'sealed OSS M4 anchors'): void {
  if (!allowSealedM4) {
    throw new Error(
      `Refusing to load ${context} (${SEALED_MANIFEST_PATH}) during default/dev runs. Pass --allow-sealed-m4 (or an explicit --manifest path) for M4 certification only.`,
    )
  }
}

export function loadManifestBundle(filePath: string): ManifestBundle {
  const raw = readFileSync(filePath, 'utf8')
  return JSON.parse(raw) as ManifestBundle
}

export function loadSealedManifestBundle(options: { allowSealedM4: boolean }): ManifestBundle {
  assertSealedM4Allowed(options.allowSealedM4)
  return loadManifestBundle(SEALED_MANIFEST_PATH)
}

export interface CorpusLoadOptions {
  includeDev?: boolean
  includeSealed?: boolean
  includeCleanControls?: boolean
  allowSealedM4?: boolean
}

/**
 * Loads committed OSS manifests with strict dev/sealed separation.
 * Defaults to dev anchors + clean controls only; `includeSealed: true` requires `allowSealedM4: true`.
 */
export function loadCorpusManifests(options: CorpusLoadOptions = {}): {
  anchors: OssAnchorManifest[]
  cleanControls: CleanNegativeControlSpec[]
} {
  const includeDev = options.includeDev ?? true
  const includeSealed = options.includeSealed ?? false
  const includeCleanControls = options.includeCleanControls ?? true

  if (includeSealed) {
    assertSealedM4Allowed(options.allowSealedM4 === true)
  }

  const anchors: OssAnchorManifest[] = []
  if (includeDev) {
    const devBundle = loadManifestBundle(DEV_MANIFEST_PATH)
    anchors.push(...(devBundle.anchors ?? []))
  }
  if (includeSealed) {
    const sealedBundle = loadManifestBundle(SEALED_MANIFEST_PATH)
    anchors.push(...(sealedBundle.anchors ?? []))
  }

  const cleanControls: CleanNegativeControlSpec[] = includeCleanControls
    ? (loadManifestBundle(CLEAN_CONTROLS_PATH).cleanControls ?? [])
    : []

  return { anchors, cleanControls }
}

export interface FileValidationReport {
  file: string
  valid: boolean
  issueCount: number
  issues: ValidationIssue[]
}

export interface ValidateCommittedOptions {
  includeSealed?: boolean
  allowSealedM4?: boolean
}

export function validateAllCommittedManifests(options: ValidateCommittedOptions = {}): {
  valid: boolean
  results: FileValidationReport[]
} {
  const files = [DEV_MANIFEST_PATH, CLEAN_CONTROLS_PATH, SEALED_EXAMPLE_PATH]
  if (options.includeSealed) {
    assertSealedM4Allowed(options.allowSealedM4 === true, 'sealed-anchors.json validation')
    files.splice(1, 0, SEALED_MANIFEST_PATH)
  }
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
  passingGrade: CertifyOssGradeReport
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

interface ParsedCliFlags {
  flags: Record<string, string | boolean>
  manifests: string[]
}

function splitCsvPaths(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

function parseFlags(args: string[]): ParsedCliFlags {
  const flags: Record<string, string | boolean> = {}
  const manifests: string[] = []
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i]
    if (!token.startsWith('--')) continue
    const key = token.slice(2)
    const next = args[i + 1]
    if (next !== undefined && !next.startsWith('--')) {
      flags[key] = next
      if (key === 'manifest') {
        manifests.push(...splitCsvPaths(next))
      }
      i += 1
    } else {
      flags[key] = true
    }
  }
  return { flags, manifests }
}

function printHelp(): void {
  console.log(`benchmarks/oss-multihop CLI (Node 24+ native TS, zero npm deps)

Usage:
  node benchmarks/oss-multihop/run.ts list [--split dev|clean_control|sealed|all] [--allow-sealed-m4] [--json]
  node benchmarks/oss-multihop/run.ts validate [--manifest <path>...] [--all] [--allow-sealed-m4]
  node benchmarks/oss-multihop/run.ts grade [--manifest <path>...] [--split dev|sealed|all] [--allow-sealed-m4] [--controls <path>|none] --input <path> [--json <out>] [--md <out>] [--quiet]
  GUARDIAN_ALLOW_LOCAL_LAB=1 node benchmarks/oss-multihop/run.ts selftest
`)
}

interface RawGradePayload {
  receipts: GuardianCompositeProofReceipt[]
  oracleObservations: ExternalOracleObservation[]
  patchRetests?: PatchRetestRecord[]
  telemetry: Omit<RunTelemetry, 'split'> & { split?: AnchorSplit }
}

function cmdList(parsed: ParsedCliFlags): number {
  const { flags } = parsed
  const split = typeof flags.split === 'string' ? flags.split : 'all'
  const allowSealedM4 = flags['allow-sealed-m4'] === true
  const includeSealedFlag = flags['include-sealed'] === true

  if ((split === 'sealed' || includeSealedFlag) && !allowSealedM4) {
    console.error(
      `Refusing to list sealed OSS M4 anchors without --allow-sealed-m4 (never loaded during default dev runs).`,
    )
    return 2
  }

  const includeDev = split === 'dev' || split === 'all'
  const includeSealed = (split === 'sealed' || (split === 'all' && allowSealedM4) || includeSealedFlag) && allowSealedM4
  const includeCleanControls = split === 'clean_control' || split === 'all'

  const devAnchors: OssAnchorManifest[] = includeDev
    ? (loadManifestBundle(DEV_MANIFEST_PATH).anchors ?? [])
    : []
  const sealedAnchors: OssAnchorManifest[] = includeSealed
    ? (loadSealedManifestBundle({ allowSealedM4 }).anchors ?? [])
    : []
  const controls: CleanNegativeControlSpec[] = includeCleanControls
    ? (loadManifestBundle(CLEAN_CONTROLS_PATH).cleanControls ?? [])
    : []

  if (flags.json === true) {
    const out: Record<string, unknown> = {
      devAnchors: devAnchors.map((a) => ({
        anchorId: a.anchorId,
        project: a.project,
        split: a.split,
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
        split: 'clean_control',
        language: c.language,
        patchedTag: c.patchedBuild.versionTag,
        maxAllowedFindings: c.maxAllowedFindings,
      })),
    }
    if (includeSealed) {
      out.sealedAnchors = sealedAnchors.map((a) => ({
        anchorId: a.anchorId,
        project: a.project,
        split: a.split,
        language: a.language,
        hopCount: a.hopCount,
        oracleKind: a.impactOracle.kind,
        vulnerableTag: a.vulnerableBuild.versionTag,
        patchedTag: a.patchedBuild.versionTag,
        expectedPatchBrokeHopIds: a.expectedPatchBrokeHopIds,
      }))
    }
    console.log(JSON.stringify(out, null, 2))
    return 0
  }

  if (devAnchors.length > 0) {
    console.log(`Dev OSS Multi-Hop Anchors (${devAnchors.length}):`)
    for (const a of devAnchors) {
      console.log(
        `  - ${a.anchorId} [${a.project} / ${a.language}] ${a.hopCount} hops | oracle=${a.impactOracle.kind} | ${a.vulnerableBuild.versionTag} -> ${a.patchedBuild.versionTag} (breaks: ${a.expectedPatchBrokeHopIds.join(',')})`,
      )
    }
  }
  if (sealedAnchors.length > 0) {
    console.log(`Sealed OSS Multi-Hop Anchors (${sealedAnchors.length}, M4 certification):`)
    for (const a of sealedAnchors) {
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

function cmdValidate(parsed: ParsedCliFlags): number {
  const { flags, manifests } = parsed
  if (manifests.length > 0) {
    const results: FileValidationReport[] = manifests.map((rawPath) => {
      const file = resolve(rawPath)
      const bundle = loadManifestBundle(file)
      const res = validateManifestBundle(bundle)
      return { file, valid: res.valid, issueCount: res.issues.length, issues: res.issues }
    })
    const valid = results.every((r) => r.valid)
    const out = results.length === 1 ? results[0] : { valid, results }
    if (flags.quiet !== true) {
      console.log(JSON.stringify(out, null, 2))
    }
    return valid ? 0 : 1
  }

  const allowSealedM4 = flags['allow-sealed-m4'] === true
  const includeSealedFlag = flags['include-sealed'] === true
  if (includeSealedFlag && !allowSealedM4) {
    console.error('Refusing to validate sealed-anchors.json via --include-sealed without --allow-sealed-m4.')
    return 2
  }

  const report = validateAllCommittedManifests({
    includeSealed: allowSealedM4 || includeSealedFlag,
    allowSealedM4,
  })
  if (flags.quiet !== true) {
    console.log(JSON.stringify(report, null, 2))
  }
  return report.valid ? 0 : 1
}

function cmdGrade(parsed: ParsedCliFlags): number {
  const { flags, manifests } = parsed
  const allowSealedM4 = flags['allow-sealed-m4'] === true
  const includeSealedFlag = flags['include-sealed'] === true
  const splitFlag = typeof flags.split === 'string' ? flags.split : undefined

  const resolvedManifestPaths: string[] = []
  if (manifests.length > 0) {
    for (const m of manifests) {
      resolvedManifestPaths.push(resolve(m))
    }
    if (includeSealedFlag) {
      if (!allowSealedM4) {
        console.error(
          'Refusing to include sealed OSS M4 anchors via --include-sealed without --allow-sealed-m4.',
        )
        return 2
      }
      const sealedAbs = resolve(SEALED_MANIFEST_PATH)
      if (!resolvedManifestPaths.includes(sealedAbs)) {
        resolvedManifestPaths.push(sealedAbs)
      }
    }
  } else {
    const effectiveSplit = splitFlag ?? (includeSealedFlag ? 'all' : 'dev')
    if (effectiveSplit === 'dev') {
      resolvedManifestPaths.push(DEV_MANIFEST_PATH)
    } else if (effectiveSplit === 'sealed') {
      if (!allowSealedM4) {
        console.error(
          'Refusing to grade sealed OSS M4 anchors without --allow-sealed-m4 (or explicit --manifest path).',
        )
        return 2
      }
      resolvedManifestPaths.push(SEALED_MANIFEST_PATH)
    } else if (effectiveSplit === 'all' || effectiveSplit === 'combined' || effectiveSplit === 'm4') {
      if (!allowSealedM4) {
        console.error(
          `Refusing to grade combined dev+sealed OSS corpus (--split ${effectiveSplit}) without --allow-sealed-m4 (or explicit --manifest paths).`,
        )
        return 2
      }
      resolvedManifestPaths.push(DEV_MANIFEST_PATH, SEALED_MANIFEST_PATH)
    } else {
      console.error(`Unknown --split '${effectiveSplit}'; expected dev, sealed, or all.`)
      return 2
    }
  }

  if (typeof flags.input !== 'string') {
    console.error('grade requires --input <path-to-observations.json>')
    return 2
  }
  const inputPath = resolve(flags.input)

  const anchors: OssAnchorManifest[] = []
  const seenAnchorIds = new Set<string>()
  for (const manifestPath of resolvedManifestPaths) {
    const anchorBundle = loadManifestBundle(manifestPath)
    const anchorVal = validateManifestBundle(anchorBundle)
    if (!anchorVal.valid) {
      console.error(`Manifest '${manifestPath}' failed validation:`, JSON.stringify(anchorVal.issues))
      return 1
    }
    for (const a of anchorBundle.anchors ?? []) {
      if (seenAnchorIds.has(a.anchorId)) {
        console.error(`Duplicate anchorId '${a.anchorId}' across manifests.`)
        return 1
      }
      seenAnchorIds.add(a.anchorId)
      anchors.push(a)
    }
  }

  let cleanControls: CleanNegativeControlSpec[] = []
  if (flags.controls !== 'none') {
    const controlsPath =
      typeof flags.controls === 'string' ? resolve(flags.controls) : CLEAN_CONTROLS_PATH
    const controlBundle = loadManifestBundle(controlsPath)
    const controlVal = validateManifestBundle(controlBundle)
    if (!controlVal.valid) {
      console.error('Clean-controls manifest failed validation:', JSON.stringify(controlVal.issues))
      return 1
    }
    cleanControls = controlBundle.cleanControls ?? []
  }

  const payload = JSON.parse(readFileSync(inputPath, 'utf8')) as RawGradePayload
  const inferredSplit: AnchorSplit =
    payload.telemetry.split ?? (anchors.some((a) => a.split === 'sealed') ? 'sealed' : 'dev')
  const telemetry: RunTelemetry = {
    ...payload.telemetry,
    split: inferredSplit,
  }

  const result = gradeOssRun({
    anchors,
    cleanControls,
    receipts: payload.receipts ?? [],
    oracleObservations: payload.oracleObservations ?? [],
    patchRetests: payload.patchRetests ?? [],
    telemetry,
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

  if (flags.quiet !== true) {
    console.log(JSON.stringify(result, null, 2))
  }
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
        worstRunPrecision: report.passingGrade.worstRunPrecision,
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

export function main(argv: string[]): number {
  const [cmd, ...rest] = argv
  if (!cmd || cmd === '--help' || cmd === '-h') {
    printHelp()
    return 0
  }
  const parsed = parseFlags(rest)
  switch (cmd) {
    case 'list':
      return cmdList(parsed)
    case 'validate':
      return cmdValidate(parsed)
    case 'grade':
      return cmdGrade(parsed)
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
