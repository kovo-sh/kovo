// End-to-end M4 certification bridge & contract tests connecting all 10 OSS targets
// (4 dev anchors + 4 sealed anchors + 2 clean controls) from benchmarks/oss-multihop/run.ts
// directly into scripts/certify-v8.ts (`normalizeOssInputs`, `loadOssInputs`, `evaluateV8Certification`).
// Pure offline Node 24+ TypeScript, zero npm deps, zero Docker execution.

import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  CLEAN_CONTROLS_PATH,
  DEV_MANIFEST_PATH,
  SEALED_MANIFEST_PATH,
  assertLocalLabAllowed,
  gradeOssRun,
  isSealedManifestPath,
  loadCorpusManifests,
  loadSealedManifestBundle,
  main as ossRunMain,
  runOfflineSelfTest,
  validateAllCommittedManifests,
} from '../run.ts'
import type {
  ExternalOracleObservation,
  GuardianCompositeProofReceipt,
  OssAnchorManifest,
  PatchRetestRecord,
  RunTelemetry,
} from '../lib/types.ts'
import * as giteaOracle from '../anchors/gitea/oracle.ts'
import * as directusOracle from '../anchors/directus/oracle.ts'
import * as ghostOracle from '../anchors/ghost/oracle.ts'
import * as mattermostOracle from '../anchors/mattermost/oracle.ts'
import * as keycloakOracle from '../anchors/keycloak/oracle.ts'
import * as woodpeckerOracle from '../anchors/woodpecker/oracle.ts'
import * as metabaseOracle from '../anchors/metabase/oracle.ts'
import * as saleorOracle from '../anchors/saleor/oracle.ts'
import * as cleanVikunjaOracle from '../anchors/clean-vikunja/oracle.ts'
import * as cleanOutlineOracle from '../anchors/clean-outline/oracle.ts'

import {
  evaluateV8Certification,
  loadOssInputs,
  main as certifyV8Main,
  normalizeOssInputs,
  renderCalibrationMarkdown,
  type MultihopCellInput,
  type MultihopChainVerdictInput,
  type MultihopMode,
  type OssCorpusInput,
  type V7RegressionFloorInput,
} from '../../../scripts/certify-v8.ts'

const tempRoot = mkdtempSync(join(tmpdir(), 'guardian-v8-oss-cert-bridge-'))
process.on('exit', () => rmSync(tempRoot, { recursive: true, force: true }))

const DEV_APPS = ['paygrid', 'shipforge', 'nexusiam'] as const

// ---------------------------------------------------------------------------
// Synthetic M4 Multihop & v7 Regression Floor Baseline Fixtures
// ---------------------------------------------------------------------------

function makeChainVerdicts(
  app: string,
  confirmed34: number,
  confirmed56: number,
): MultihopChainVerdictInput[] {
  const verdicts: MultihopChainVerdictInput[] = []
  for (let i = 0; i < 2; i += 1) {
    const ok = i < confirmed34
    verdicts.push({
      chainId: `${app}-c34-${i + 1}`,
      expectedHops: 4,
      maxHopReached: ok ? 4 : 2,
      oracleObserved: ok,
      compositeReceiptConfirmed: ok,
      twoSideConfirmed: ok,
      dropReason: ok ? null : 'pivot_not_discovered',
    })
  }
  for (let i = 0; i < 2; i += 1) {
    const ok = i < confirmed56
    verdicts.push({
      chainId: `${app}-c56-${i + 1}`,
      expectedHops: 5,
      maxHopReached: ok ? 5 : 3,
      oracleObserved: ok,
      compositeReceiptConfirmed: ok,
      twoSideConfirmed: ok,
      dropReason: ok ? null : 'budget_exhausted',
    })
  }
  return verdicts
}

function makeSuiteCells(opts: {
  mode: MultihopMode
  budgetUsd: number
  maxDurationMs: number
  seed: number
  seedSet?: 'dev' | 'held-out'
  confirmedByApp: [number, number, number]
  costUsdPerApp: number
  durationMsPerApp: number
}): MultihopCellInput[] {
  return DEV_APPS.map((app, idx) => {
    const confirmed = opts.confirmedByApp[idx]!
    const c34 = Math.min(2, confirmed)
    const c56 = Math.max(0, confirmed - c34)
    return {
      schemaVersion: 1,
      app,
      sealed: false,
      seed: opts.seed,
      seedSet: opts.seedSet ?? (opts.seed >= 1_000_000 ? 'held-out' : 'dev'),
      mode: opts.mode,
      llm: 'agentic',
      budgetUsd: opts.budgetUsd,
      maxDurationMs: opts.maxDurationMs,
      costUsd: opts.costUsdPerApp,
      durationMs: opts.durationMsPerApp,
      chainsTotal: 4,
      chainsOracleObserved: confirmed,
      chainsCompositeConfirmed: confirmed,
      chainsConfirmed: confirmed,
      recall: confirmed / 4,
      precision: 1,
      hardenedTwinsTotal: 3,
      hardenedTwinDecoyFps: 0,
      unmatchedFalsePositives: 0,
      chains: makeChainVerdicts(app, c34, c56),
      phaseBAssignments: 40,
      deadEndReprobeCount: 1,
      gitSha: 'abc123def456',
    }
  })
}

function makePassingM4MultihopCells(): MultihopCellInput[] {
  const cells: MultihopCellInput[] = DEV_APPS.map((app) => ({
    schemaVersion: 1,
    app,
    sealed: false,
    seed: 1,
    seedSet: 'dev',
    mode: 'white-box',
    llm: 'deterministic-no-llm',
    budgetUsd: 0,
    maxDurationMs: 300_000,
    costUsd: 0,
    durationMs: 40_000,
    chainsTotal: 4,
    chainsConfirmed: 0,
    precision: 1,
    hardenedTwinsTotal: 3,
    hardenedTwinDecoyFps: 0,
    unmatchedFalsePositives: 0,
  }))

  for (const seed of [1, 2, 3]) {
    cells.push(
      ...makeSuiteCells({
        mode: 'white-box',
        budgetUsd: 2,
        maxDurationMs: 600_000,
        seed,
        confirmedByApp: [1, 1, 1],
        costUsdPerApp: 1.5,
        durationMsPerApp: 420_000,
      }),
      ...makeSuiteCells({
        mode: 'white-box',
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        seed,
        confirmedByApp: [3, 2, 2],
        costUsdPerApp: 3.5,
        durationMsPerApp: 1_000_000,
      }),
      ...makeSuiteCells({
        mode: 'white-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        seed,
        confirmedByApp: [3, 3, 2],
        costUsdPerApp: 11.0,
        durationMsPerApp: 2_400_000,
      }),
      ...makeSuiteCells({
        mode: 'grey-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        seed,
        confirmedByApp: [2, 2, 2],
        costUsdPerApp: 10.0,
        durationMsPerApp: 2_200_000,
      }),
    )
  }

  for (const seed of [1_000_001, 1_000_002, 1_000_003]) {
    cells.push(
      ...makeSuiteCells({
        mode: 'white-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        seed,
        seedSet: 'held-out',
        confirmedByApp: [3, 2, 2],
        costUsdPerApp: 11.0,
        durationMsPerApp: 2_500_000,
      }),
      ...makeSuiteCells({
        mode: 'grey-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        seed,
        seedSet: 'held-out',
        confirmedByApp: [2, 2, 1],
        costUsdPerApp: 10.0,
        durationMsPerApp: 2_300_000,
      }),
    )
  }

  // Sealed connecthub blind first run: 2/4 = 50.0% (gap = 16.7 pp <= 20 pp)
  cells.push({
    schemaVersion: 1,
    app: 'connecthub',
    sealed: true,
    seed: 9001,
    seedSet: 'dev',
    mode: 'white-box',
    llm: 'agentic',
    budgetUsd: 15,
    maxDurationMs: 3_600_000,
    startedAt: 1_750_000_000_000,
    costUsd: 11.0,
    durationMs: 2_400_000,
    chainsTotal: 4,
    chainsConfirmed: 2,
    precision: 1,
    hardenedTwinsTotal: 3,
    hardenedTwinDecoyFps: 0,
    unmatchedFalsePositives: 0,
    chains: makeChainVerdicts('connecthub', 2, 0),
    phaseBAssignments: 50,
    deadEndReprobeCount: 1,
  })

  return cells
}

function makePassingV7Floor(): V7RegressionFloorInput {
  return {
    xben: { confirmed: 25, targets: 25, falsePositives: 0 },
    heldOutSaas: { confirmed: 20, targets: 20, patchesClosed: 20, patchesTotal: 20, falsePositives: 0 },
    reasonBench: { noLlmRecall: 0.08, agenticRecall: 0.56, worstPrecision: 1 },
    realisticBench: { maxFloorSpread: 0 },
  }
}

// ---------------------------------------------------------------------------
// Real Anchor Oracle & Composite Receipt Builders (All 10 OSS Targets)
// ---------------------------------------------------------------------------

function makeValidReceipt(
  anchor: OssAnchorManifest,
  runId: string,
  baseTs: number,
  correlationId: string,
): GuardianCompositeProofReceipt {
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
      observedAtMs: baseTs + idx * 1_000,
      exchangeIds: [`ex_${anchor.anchorId}_${h.hopId}`],
    })),
    causalEdges: anchor.hops.slice(1).map((h, idx) => ({
      fromHopId: anchor.hops[idx]!.hopId,
      toHopId: h.hopId,
      bindingKind: h.incomingEdgeKind ?? 'value_binding',
      verified: true,
    })),
    terminalImpact: {
      observed: true,
      oracleId: anchor.impactOracle.oracleId,
      correlationId,
      observedAtMs: baseTs + 5_000,
    },
    runId,
  }
}

function evaluateAnchorVulnerableOracle(
  project: string,
  runId: string,
  observedAtMs: number,
  correlationId: string,
): ExternalOracleObservation {
  switch (project) {
    case 'gitea':
      return giteaOracle.evaluateGiteaOracle(runId, 'vulnerable', {
        observedAtMs,
        correlationId,
        requests: [
          {
            method: 'POST',
            path: '/oob/gitea/pivot',
            canaryToken: 'oss_canary_gitea_m4',
            correlationId,
            receivedAtMs: observedAtMs,
          },
        ],
      })
    case 'directus':
      return directusOracle.evaluateDirectusOracle(runId, 'vulnerable', {
        observedAtMs,
        correlationId,
        rows: [{ id: 1, role_name: 'tenant_a_admin', canary_marker: 'oss_canary_directus_m4' }],
      })
    case 'ghost':
      return ghostOracle.evaluateGhostOracle(runId, 'vulnerable', {
        observedAtMs,
        correlationId,
        exists: true,
        contentPreview: 'marker=oss_canary_ghost_m4',
      })
    case 'mattermost':
      return mattermostOracle.evaluateMattermostOracle(runId, 'vulnerable', {
        observedAtMs,
        correlationId,
        lines: [
          {
            stream: 'stdout',
            text: 'level=info audit_event=compliance_export_complete token=oss_canary_mm_m4',
            timestampMs: observedAtMs,
          },
        ],
      })
    case 'keycloak':
      return keycloakOracle.evaluateKeycloakOracle(runId, 'vulnerable', {
        observedAtMs,
        correlationId,
        rows: [
          {
            id: 1,
            realm_id: 'tenant_realm_a',
            role_name: 'realm-admin',
            canary_marker: 'oss_canary_keycloak_m4',
          },
        ],
      })
    case 'woodpecker':
      return woodpeckerOracle.evaluateWoodpeckerOracle(runId, 'vulnerable', {
        observedAtMs,
        correlationId,
        requests: [
          {
            method: 'POST',
            path: '/oob/woodpecker/runner-pivot',
            canaryToken: 'oss_canary_woodpecker_m4',
            correlationId,
            receivedAtMs: observedAtMs,
          },
        ],
      })
    case 'metabase':
      return metabaseOracle.evaluateMetabaseOracle(runId, 'vulnerable', {
        observedAtMs,
        correlationId,
        exists: true,
        contentPreview: 'scheduled_export=oss_canary_metabase_m4',
      })
    case 'saleor':
      return saleorOracle.evaluateSaleorOracle(runId, 'vulnerable', {
        observedAtMs,
        correlationId,
        lines: [
          {
            stream: 'stdout',
            text: 'level=info audit_event=delegated_billing_settlement_complete token=oss_canary_saleor_m4',
            timestampMs: observedAtMs,
          },
        ],
      })
    default:
      throw new Error(`Unknown OSS anchor project '${project}'`)
  }
}

function makeClosedPatchRetest(
  anchor: OssAnchorManifest,
  receipt: GuardianCompositeProofReceipt,
  vulnObs: ExternalOracleObservation,
  overrides: Partial<PatchRetestRecord> = {},
): PatchRetestRecord {
  return {
    targetId: anchor.anchorId,
    receiptId: receipt.receiptId,
    patchedCommitSha: anchor.patchedBuild.commitSha,
    replayedFullDag: true,
    terminalImpactEliminated: true,
    patchBrokeHopId: anchor.expectedPatchBrokeHopIds[0]!,
    patchedOracleObservation: {
      ...vulnObs,
      observationId: `${vulnObs.observationId}_patched`,
      buildTarget: 'patched',
      observed: false,
      detail: 'Impact eliminated on paired official patched release.',
    },
    ...overrides,
  }
}

function buildTenTargetScenario(opts: {
  runId: string
  confirmedProjects: readonly string[]
  closedPatchProjects?: readonly string[]
  omitPatchRetestProjects?: readonly string[]
  invalidPatchHopProjects?: readonly string[]
  cleanControlFpControlIds?: readonly string[]
  unexpectedOutlineOracle?: boolean
}) {
  const corpus = loadCorpusManifests({
    includeDev: true,
    includeSealed: true,
    includeCleanControls: true,
    allowSealedM4: true,
  })
  const baseTs = 1_732_700_000_000
  const confirmedSet = new Set(opts.confirmedProjects)
  const closedSet = new Set(opts.closedPatchProjects ?? opts.confirmedProjects)
  const omitPatchSet = new Set(opts.omitPatchRetestProjects ?? [])
  const invalidHopSet = new Set(opts.invalidPatchHopProjects ?? [])

  const receipts: GuardianCompositeProofReceipt[] = []
  const oracleObservations: ExternalOracleObservation[] = []
  const patchRetests: PatchRetestRecord[] = []

  for (const [idx, anchor] of corpus.anchors.entries()) {
    if (!confirmedSet.has(anchor.project)) continue
    const corr = `corr-${anchor.project}-${idx}`
    const obs = evaluateAnchorVulnerableOracle(anchor.project, opts.runId, baseTs + 5_000, corr)
    assert.equal(obs.observed, true, `Expected positive oracle observation for ${anchor.project}`)
    const rcpt = makeValidReceipt(anchor, opts.runId, baseTs, corr)
    oracleObservations.push(obs)
    receipts.push(rcpt)

    if (!omitPatchSet.has(anchor.project)) {
      if (invalidHopSet.has(anchor.project)) {
        patchRetests.push(makeClosedPatchRetest(anchor, rcpt, obs, { patchBrokeHopId: 'H99_INVALID' }))
      } else if (closedSet.has(anchor.project)) {
        patchRetests.push(makeClosedPatchRetest(anchor, rcpt, obs))
      } else {
        patchRetests.push(
          makeClosedPatchRetest(anchor, rcpt, obs, {
            terminalImpactEliminated: false,
            patchBrokeHopId: null,
            patchedOracleObservation: {
              ...obs,
              observationId: `${obs.observationId}_patched_open`,
              buildTarget: 'patched',
              observed: true,
              detail: 'Still reproduces on patched build.',
            },
          }),
        )
      }
    }
  }

  // Evaluate clean controls (normally silent; optionally inject an unexpected oracle or FP receipt)
  const vikunjaClean = cleanVikunjaOracle.evaluateVikunjaCleanOracle(opts.runId, {
    observedAtMs: baseTs + 6_000,
    rows: [],
  })
  const outlineClean = cleanOutlineOracle.evaluateOutlineCleanOracle(opts.runId, {
    observedAtMs: baseTs + 6_000,
    lines: opts.unexpectedOutlineOracle
      ? [
          {
            stream: 'stdout',
            text: 'level=warn audit_event=unauthorized_export canary=oss_canary_clean_outline_m4',
            timestampMs: baseTs + 6_000,
          },
        ]
      : [{ stream: 'stdout', text: 'level=info audit_event=collection_read_denied', timestampMs: baseTs + 6_000 }],
  })
  oracleObservations.push(vikunjaClean, outlineClean)

  for (const controlId of opts.cleanControlFpControlIds ?? []) {
    receipts.push({
      receiptId: `rcpt_fp_${controlId}`,
      chainId: `chain_fp_${controlId}`,
      targetId: controlId,
      terminalVulnClass: 'cross_tenant_rbac_privilege_escalation',
      verified: true,
      attackerOriginVerified: true,
      originPersona: 'clean_origin',
      replayMode: 'fresh_clean_replay',
      hops: [
        {
          hopId: 'H1',
          order: 1,
          surface: 'http',
          actorPersona: 'clean_origin',
          observedAtMs: baseTs,
          exchangeIds: ['ex_fp_1'],
        },
      ],
      causalEdges: [],
      terminalImpact: { observed: true, observedAtMs: baseTs + 1_000 },
      runId: opts.runId,
    })
  }

  const telemetry: RunTelemetry = {
    runId: opts.runId,
    split: 'sealed',
    mode: 'white-box',
    durationMs: 1_800_000, // 30m
    costUsd: 8.0,
  }

  return {
    anchors: corpus.anchors,
    cleanControls: corpus.cleanControls,
    receipts,
    oracleObservations,
    patchRetests,
    telemetry,
  }
}

function captureConsole<T>(fn: () => T): { result: T; stdout: string; stderr: string } {
  const out: string[] = []
  const err: string[] = []
  const origLog = console.log
  const origErr = console.error
  const origStdOutWrite = process.stdout.write.bind(process.stdout)
  const origStdErrWrite = process.stderr.write.bind(process.stderr)
  console.log = (...args: unknown[]) => out.push(args.map(String).join(' '))
  console.error = (...args: unknown[]) => err.push(args.map(String).join(' '))
  process.stdout.write = ((chunk: string | Uint8Array) => {
    out.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'))
    return true
  }) as typeof process.stdout.write
  process.stderr.write = ((chunk: string | Uint8Array) => {
    err.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'))
    return true
  }) as typeof process.stderr.write
  try {
    const result = fn()
    return { result, stdout: out.join('\n'), stderr: err.join('\n') }
  } finally {
    console.log = origLog
    console.error = origErr
    process.stdout.write = origStdOutWrite
    process.stderr.write = origStdErrWrite
  }
}

// ---------------------------------------------------------------------------
// 1. Sealed-Anchor Safety Guard & Manifest Loading Tests
// ---------------------------------------------------------------------------

test('sealed-anchors.json safety guard blocks default/dev runs and requires --allow-sealed-m4 or explicit --manifest', () => {
  assertLocalLabAllowed()
  assert.equal(isSealedManifestPath(SEALED_MANIFEST_PATH), true)
  assert.equal(isSealedManifestPath(DEV_MANIFEST_PATH), false)

  // Default corpus load returns ONLY 4 dev anchors + 2 clean controls (0 sealed)
  const devDefault = loadCorpusManifests()
  assert.equal(devDefault.anchors.length, 4)
  assert.equal(devDefault.anchors.every((a) => a.split === 'dev'), true)
  assert.equal(devDefault.cleanControls.length, 2)

  // Programmatic sealed loads MUST fail without explicit allowSealedM4: true
  assert.throws(() => loadSealedManifestBundle({ allowSealedM4: false }), /--allow-sealed-m4/)
  assert.throws(() => loadCorpusManifests({ includeSealed: true }), /--allow-sealed-m4/)

  // Default validateAllCommittedManifests validates 3 files and excludes sealed-anchors.json
  const defaultVal = validateAllCommittedManifests()
  assert.equal(defaultVal.valid, true)
  assert.equal(defaultVal.results.length, 3)
  assert.equal(defaultVal.results.some((r) => isSealedManifestPath(r.file)), false)

  // Including sealed in validateAllCommittedManifests requires allowSealedM4: true
  assert.throws(() => validateAllCommittedManifests({ includeSealed: true }), /--allow-sealed-m4/)
  const fullVal = validateAllCommittedManifests({ includeSealed: true, allowSealedM4: true })
  assert.equal(fullVal.valid, true)
  assert.equal(fullVal.results.length, 4)
  assert.equal(fullVal.results.some((r) => isSealedManifestPath(r.file)), true)

  // With allowSealedM4: true, all 10 OSS targets load cleanly (4 dev + 4 sealed + 2 clean controls)
  const fullCorpus = loadCorpusManifests({
    includeDev: true,
    includeSealed: true,
    includeCleanControls: true,
    allowSealedM4: true,
  })
  assert.equal(fullCorpus.anchors.length, 8)
  assert.equal(fullCorpus.anchors.filter((a) => a.split === 'dev').length, 4)
  assert.equal(fullCorpus.anchors.filter((a) => a.split === 'sealed').length, 4)
  assert.equal(fullCorpus.cleanControls.length, 2)

  // CLI list blocks --split sealed without --allow-sealed-m4, allows with --allow-sealed-m4
  const blockedList = captureConsole(() => ossRunMain(['list', '--split', 'sealed']))
  assert.equal(blockedList.result, 2)
  assert.match(blockedList.stderr, /--allow-sealed-m4/)

  const allowedList = captureConsole(() => ossRunMain(['list', '--split', 'all', '--allow-sealed-m4', '--json']))
  assert.equal(allowedList.result, 0)
  const parsedList = JSON.parse(allowedList.stdout) as {
    devAnchors: unknown[]
    sealedAnchors: unknown[]
    cleanControls: unknown[]
  }
  assert.equal(parsedList.devAnchors.length, 4)
  assert.equal(parsedList.sealedAnchors.length, 4)
  assert.equal(parsedList.cleanControls.length, 2)

  // CLI grade blocks --split sealed and --split all without --allow-sealed-m4
  const dummyInputPath = join(tempRoot, 'guard-dummy-input.json')
  writeFileSync(
    dummyInputPath,
    JSON.stringify({
      receipts: [],
      oracleObservations: [],
      patchRetests: [],
      telemetry: { runId: 'guard_check', mode: 'white-box', durationMs: 600_000, costUsd: 1 },
    }),
    'utf8',
  )
  const blockedGradeSealed = captureConsole(() =>
    ossRunMain(['grade', '--split', 'sealed', '--input', dummyInputPath, '--quiet']),
  )
  assert.equal(blockedGradeSealed.result, 2)
  assert.match(blockedGradeSealed.stderr, /--allow-sealed-m4/)

  const blockedGradeAll = captureConsole(() =>
    ossRunMain(['grade', '--split', 'all', '--input', dummyInputPath, '--quiet']),
  )
  assert.equal(blockedGradeAll.result, 2)
  assert.match(blockedGradeAll.stderr, /--allow-sealed-m4/)

  // Explicit --manifest pointing at sealed-anchors.json IS allowed (returns 2 due to 0% recall, not guard refusal)
  const explicitSealed = captureConsole(() =>
    ossRunMain(['grade', '--manifest', SEALED_MANIFEST_PATH, '--input', dummyInputPath, '--quiet']),
  )
  assert.equal(explicitSealed.stderr, '')
  assert.equal(explicitSealed.result, 2)
})

// ---------------------------------------------------------------------------
// 2. Full 10-Target M4 Certification Bridge (PASS)
// ---------------------------------------------------------------------------

test('M4 PASS bridge: all 10 OSS targets (4 dev + 4 sealed + 2 clean controls) flow directly from run.ts -> certify-v8.ts', () => {
  // Confirm 3/4 dev (gitea, directus, ghost) + 3/4 sealed (keycloak, woodpecker, saleor) = 6/8 total (75% sealed recall >= 50%),
  // close 5/6 on paired patched commits (83.3% >= 80%), 0 FPs on both clean controls.
  const scenario = buildTenTargetScenario({
    runId: 'run_m4_bridge_pass_01',
    confirmedProjects: ['gitea', 'directus', 'ghost', 'keycloak', 'woodpecker', 'saleor'],
    closedPatchProjects: ['gitea', 'directus', 'ghost', 'keycloak', 'woodpecker'],
  })

  const gradeReport = gradeOssRun(scenario)

  // Verify schema alignment fields on CertifyOssGradeReport (direct OssCorpusInput assignability without cast)
  const asOssInput: OssCorpusInput = gradeReport
  assert.equal(asOssInput.totalAnchors, 8)
  assert.equal(gradeReport.gates.passed, true, JSON.stringify(gradeReport.gates.failures))
  assert.equal(gradeReport.tpCount, 6)
  assert.equal(gradeReport.fnCount, 2)
  assert.equal(gradeReport.sealedAnchors, 4)
  assert.equal(gradeReport.sealedTpCount, 3)
  assert.equal(gradeReport.sealedRecall, 0.75)
  assert.equal(gradeReport.cleanControlCount, 2)
  assert.equal(gradeReport.cleanControlFpCount, 0)
  assert.equal(gradeReport.totalFpCount, 0)
  assert.equal(gradeReport.falsePositives, 0)
  assert.equal(gradeReport.precision, 1)
  assert.equal(gradeReport.worstRunPrecision, 1)
  assert.equal(gradeReport.patchRetestAttempted, 6)
  assert.equal(gradeReport.patchRetestClosed, 5)

  // Per-anchor & per-clean-control fields
  assert.equal(gradeReport.anchorResults.length, 8)
  assert.equal(gradeReport.anchorResults.filter((a) => a.split === 'dev').length, 4)
  assert.equal(gradeReport.anchorResults.filter((a) => a.split === 'sealed').length, 4)
  assert.equal(gradeReport.anchorResults.filter((a) => a.twoSideConfirmed).length, 6)
  assert.equal(gradeReport.anchorResults.filter((a) => a.patchRetestPassed).length, 5)
  assert.equal(
    gradeReport.anchorResults.filter((a) => a.patchRetestPassed && a.patchBrokeHopId !== null).length,
    5,
  )
  assert.equal(gradeReport.anchorResults.every((a) => a.falsePositives === 0 && a.cleanControl === false), true)

  assert.equal(gradeReport.cleanControlResults.length, 2)
  assert.equal(
    gradeReport.cleanControlResults.every(
      (c) =>
        c.split === 'clean_control' &&
        c.cleanControl === true &&
        c.passed === true &&
        c.fpCount === 0 &&
        c.falsePositives === 0 &&
        c.unexpectedOracleTriggers === 0,
    ),
    true,
  )

  // Direct zero-adaptation handoff to normalizeOssInputs
  const normalized = normalizeOssInputs(gradeReport)
  assert.ok(normalized)
  assert.equal(normalized.totalAnchors, 8)
  assert.equal(normalized.tpCount, 6)
  assert.equal(normalized.sealedAnchors, 4)
  assert.equal(normalized.sealedTpCount, 3)
  assert.equal(normalized.sealedRecall, 0.75)
  assert.equal(normalized.worstRunPrecision, 1)
  assert.equal(normalized.totalFpCount, 0)
  assert.equal(normalized.cleanControlCount, 2)
  assert.equal(normalized.cleanControlFpCount, 0)
  assert.equal(normalized.cleanControlUnexpectedOracles, 0)
  assert.equal(normalized.patchRetestAttempted, 6)
  assert.equal(normalized.patchRetestClosed, 5)
  assert.ok(Math.abs((normalized.patchRetestClosureRate ?? 0) - 5 / 6) < 1e-9)

  // Full M4 certification evaluation
  const certReport = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4MultihopCells(),
    oss: gradeReport,
    v7Floor: makePassingV7Floor(),
    options: { gitSha: 'deadbeef1234', generatedAt: '2026-11-25T00:00:00.000Z' },
  })
  assert.equal(certReport.verdict, 'PASS', JSON.stringify(certReport.failedChecks, null, 2))
  assert.equal(certReport.checks.find((c) => c.id === 'm4_oss_corpus_coverage')?.status, 'PASS')
  assert.equal(certReport.checks.find((c) => c.id === 'm4_oss_sealed_recall')?.status, 'PASS')
  assert.equal(certReport.checks.find((c) => c.id === 'm4_oss_patch_retest')?.status, 'PASS')
  assert.equal(certReport.checks.find((c) => c.id === 'm4_oss_clean_controls')?.status, 'PASS')
  assert.equal(certReport.checks.find((c) => c.id === 'precision_worst_run')?.status, 'PASS')

  const md = renderCalibrationMarkdown(certReport)
  assert.match(md, /## OSS Multi-Hop Corpus/)
  assert.match(md, /6\/8 \(75\.0%\)/)
  assert.match(md, /3\/4 \(75\.0%\)/)
  assert.match(md, /5\/6 \(83\.3%\)/)
  assert.match(md, /0 FPs across 2 controls/)
})

// ---------------------------------------------------------------------------
// 3. CLI Disk Round-Trip (Combined & Split Dev+Sealed Reports -> certify-v8)
// ---------------------------------------------------------------------------

test('CLI round-trip: run.ts grade --json feeds scripts/certify-v8.ts --gate m4 --oss (combined and split modes)', () => {
  const workDir = join(tempRoot, 'cli-bridge-e2e')
  const multihopDir = join(workDir, 'multihop')
  mkdirSync(multihopDir, { recursive: true })

  writeFileSync(
    join(multihopDir, 'multihop-report.json'),
    JSON.stringify({ schemaVersion: 1, cells: makePassingM4MultihopCells() }, null, 2),
    'utf8',
  )
  const v7Path = join(workDir, 'v7-floor.json')
  writeFileSync(v7Path, JSON.stringify(makePassingV7Floor(), null, 2), 'utf8')

  const scenario = buildTenTargetScenario({
    runId: 'run_m4_cli_roundtrip_01',
    confirmedProjects: ['gitea', 'directus', 'ghost', 'keycloak', 'woodpecker', 'metabase'],
  })

  // (a) Single combined M4 run via `--split all --allow-sealed-m4`
  const combinedInputPath = join(workDir, 'oss-combined-input.json')
  const combinedGradePath = join(workDir, 'oss-combined-grade.json')
  const certOutJson = join(workDir, 'cert-combined.json')
  const certOutMd = join(workDir, 'cert-combined.md')
  writeFileSync(
    combinedInputPath,
    JSON.stringify({
      receipts: scenario.receipts,
      oracleObservations: scenario.oracleObservations,
      patchRetests: scenario.patchRetests,
      telemetry: scenario.telemetry,
    }),
    'utf8',
  )

  const gradeCombined = captureConsole(() =>
    ossRunMain([
      'grade',
      '--split',
      'all',
      '--allow-sealed-m4',
      '--input',
      combinedInputPath,
      '--json',
      combinedGradePath,
      '--quiet',
    ]),
  )
  assert.equal(gradeCombined.result, 0, gradeCombined.stderr)
  assert.equal(existsSync(combinedGradePath), true)

  const loadedCombined = loadOssInputs([combinedGradePath])
  assert.equal(loadedCombined.length, 1)
  assert.equal(loadedCombined[0]!.totalAnchors, 8)
  assert.equal(loadedCombined[0]!.cleanControlCount, 2)

  const certCombined = captureConsole(() =>
    certifyV8Main([
      '--gate',
      'm4',
      '--inputs',
      multihopDir,
      '--oss',
      combinedGradePath,
      '--v7-floor',
      v7Path,
      '--out-json',
      certOutJson,
      '--out-md',
      certOutMd,
    ]),
  )
  assert.equal(certCombined.result, 0, certCombined.stdout + certCombined.stderr)
  const parsedCert = JSON.parse(readFileSync(certOutJson, 'utf8')) as {
    verdict: string
    oss: { totalAnchors: number; sealedAnchors: number; cleanControlCount: number; sealedRecall: number }
  }
  assert.equal(parsedCert.verdict, 'PASS')
  assert.equal(parsedCert.oss.totalAnchors, 8)
  assert.equal(parsedCert.oss.sealedAnchors, 4)
  assert.equal(parsedCert.oss.cleanControlCount, 2)
  assert.equal(parsedCert.oss.sealedRecall, 0.75)

  // (b) Split dev (`--controls none`) + sealed (`--controls CLEAN_CONTROLS_PATH`) two-file handoff
  const devIds = new Set(scenario.anchors.filter((a) => a.split === 'dev').map((a) => a.anchorId))
  const sealedIds = new Set(scenario.anchors.filter((a) => a.split === 'sealed').map((a) => a.anchorId))
  const controlIds = new Set(scenario.cleanControls.map((c) => c.controlId))

  const devInputPath = join(workDir, 'oss-dev-input.json')
  const sealedInputPath = join(workDir, 'oss-sealed-input.json')
  const devGradePath = join(workDir, 'oss-dev-grade.json')
  const sealedGradePath = join(workDir, 'oss-sealed-grade.json')

  writeFileSync(
    devInputPath,
    JSON.stringify({
      receipts: scenario.receipts.filter((r) => devIds.has(r.targetId)),
      oracleObservations: scenario.oracleObservations.filter((o) => devIds.has(o.targetId)),
      patchRetests: scenario.patchRetests.filter((p) => devIds.has(p.targetId)),
      telemetry: { ...scenario.telemetry, runId: 'run_oss_dev_split', split: 'dev' },
    }),
    'utf8',
  )
  writeFileSync(
    sealedInputPath,
    JSON.stringify({
      receipts: scenario.receipts.filter((r) => sealedIds.has(r.targetId) || controlIds.has(r.targetId)),
      oracleObservations: scenario.oracleObservations.filter(
        (o) => sealedIds.has(o.targetId) || controlIds.has(o.targetId),
      ),
      patchRetests: scenario.patchRetests.filter((p) => sealedIds.has(p.targetId)),
      telemetry: { ...scenario.telemetry, runId: 'run_oss_sealed_split', split: 'sealed' },
    }),
    'utf8',
  )

  assert.equal(
    captureConsole(() =>
      ossRunMain([
        'grade',
        '--manifest',
        DEV_MANIFEST_PATH,
        '--controls',
        'none',
        '--input',
        devInputPath,
        '--json',
        devGradePath,
        '--quiet',
      ]),
    ).result,
    0,
  )
  assert.equal(
    captureConsole(() =>
      ossRunMain([
        'grade',
        '--manifest',
        SEALED_MANIFEST_PATH,
        '--controls',
        CLEAN_CONTROLS_PATH,
        '--input',
        sealedInputPath,
        '--json',
        sealedGradePath,
        '--quiet',
      ]),
    ).result,
    0,
  )

  const certSplitJson = join(workDir, 'cert-split.json')
  const certSplit = captureConsole(() =>
    certifyV8Main([
      '--gate',
      'm4',
      '--inputs',
      multihopDir,
      '--oss',
      devGradePath,
      sealedGradePath,
      '--v7-floor',
      v7Path,
      '--out-json',
      certSplitJson,
    ]),
  )
  assert.equal(certSplit.result, 0, certSplit.stdout + certSplit.stderr)
  const parsedSplitCert = JSON.parse(readFileSync(certSplitJson, 'utf8')) as {
    verdict: string
    oss: { runs: number; totalAnchors: number; sealedAnchors: number; cleanControlCount: number }
  }
  assert.equal(parsedSplitCert.verdict, 'PASS')
  assert.equal(parsedSplitCert.oss.runs, 2)
  assert.equal(parsedSplitCert.oss.totalAnchors, 8)
  assert.equal(parsedSplitCert.oss.sealedAnchors, 4)
  assert.equal(parsedSplitCert.oss.cleanControlCount, 2)
})

// ---------------------------------------------------------------------------
// 4. M4 FAIL Scenarios (Clean-Control FP, Patch-Retest < 80%, Sealed Recall < 50%, Spurious FP)
// ---------------------------------------------------------------------------

test('M4 FAIL: clean-control FP or unexpected clean-control oracle trigger fails M4 immediately', () => {
  // 4a) 1 spurious receipt on clean Vikunja control
  const fpScenario = buildTenTargetScenario({
    runId: 'run_m4_fail_clean_fp',
    confirmedProjects: ['gitea', 'directus', 'ghost', 'keycloak', 'woodpecker', 'saleor'],
    cleanControlFpControlIds: [cleanVikunjaOracle.CONTROL_ID],
  })
  const fpGrade = gradeOssRun(fpScenario)
  assert.equal(fpGrade.gates.passed, false)
  assert.equal(fpGrade.gates.cleanControlGatePassed, false)
  assert.equal(fpGrade.cleanControlFpCount, 1)
  assert.equal(fpGrade.falsePositives, 1)
  assert.ok(fpGrade.worstRunPrecision < 1)
  assert.equal(fpGrade.cleanControlResults[0]!.split, 'clean_control')
  assert.equal(fpGrade.cleanControlResults[0]!.falsePositives, 1)

  const certFp = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4MultihopCells(),
    oss: fpGrade,
    v7Floor: makePassingV7Floor(),
  })
  assert.equal(certFp.verdict, 'FAIL')
  assert.equal(certFp.precision.passed, false)
  assert.equal(certFp.precision.totalOssFalsePositives, 1)
  assert.ok(certFp.failedChecks.some((c) => c.id === 'precision_worst_run'))
  assert.ok(certFp.failedChecks.some((c) => c.id === 'm4_oss_clean_controls'))
  assert.ok(certFp.failedChecks.some((c) => c.id === 'm4_oss_sealed_recall'))

  // 4b) 0 receipts, but 1 unexpected external oracle trigger on clean Outline control
  const unexpectedOracleScenario = buildTenTargetScenario({
    runId: 'run_m4_fail_clean_oracle',
    confirmedProjects: ['gitea', 'directus', 'ghost', 'keycloak', 'woodpecker', 'saleor'],
    unexpectedOutlineOracle: true,
  })
  const oracleGrade = gradeOssRun(unexpectedOracleScenario)
  assert.equal(oracleGrade.gates.passed, false)
  assert.equal(oracleGrade.gates.cleanControlGatePassed, false)
  assert.equal(oracleGrade.cleanControlResults[1]!.unexpectedOracleTriggers, 1)

  const certOracle = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4MultihopCells(),
    oss: oracleGrade,
    v7Floor: makePassingV7Floor(),
  })
  assert.equal(certOracle.verdict, 'FAIL')
  assert.equal(certOracle.oss?.cleanControlUnexpectedOracles, 1)
  assert.ok(certOracle.failedChecks.some((c) => c.id === 'm4_oss_clean_controls'))
})

test('M4 FAIL: < 80% patch-retest closure fails M4 (both explicit failure and omitted not_run records)', () => {
  // 5a) 6 confirmed TPs: 4 closed, 1 open_still_reproduces, 1 invalid_broke_hop => 4/6 = 66.7% < 80%
  const failedPatchScenario = buildTenTargetScenario({
    runId: 'run_m4_fail_patch_closure_explicit',
    confirmedProjects: ['gitea', 'directus', 'ghost', 'keycloak', 'woodpecker', 'saleor'],
    closedPatchProjects: ['gitea', 'directus', 'keycloak', 'woodpecker'],
    invalidPatchHopProjects: ['saleor'],
  })
  const failedPatchGrade = gradeOssRun(failedPatchScenario)
  assert.equal(failedPatchGrade.gates.passed, false)
  assert.equal(failedPatchGrade.gates.patchRetestGatePassed, false)
  assert.equal(failedPatchGrade.patchRetestAttempted, 6)
  assert.equal(failedPatchGrade.patchRetestClosed, 4)
  assert.equal(failedPatchGrade.anchorResults.filter((a) => a.patchRetestPassed).length, 4)

  const certFailedPatch = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4MultihopCells(),
    oss: failedPatchGrade,
    v7Floor: makePassingV7Floor(),
  })
  assert.equal(certFailedPatch.verdict, 'FAIL')
  assert.ok(certFailedPatch.failedChecks.some((c) => c.id === 'm4_oss_patch_retest'))
  assert.equal(certFailedPatch.checks.find((c) => c.id === 'm4_oss_sealed_recall')?.status, 'PASS')
  assert.equal(certFailedPatch.checks.find((c) => c.id === 'm4_oss_clean_controls')?.status, 'PASS')
  assert.equal(certFailedPatch.checks.find((c) => c.id === 'precision_worst_run')?.status, 'PASS')

  // 5b) 6 confirmed TPs: 4 closed, 2 omitted (not_run) => denominator MUST stay 6 (4/6 = 66.7% < 80%), never 4/4!
  const omittedPatchScenario = buildTenTargetScenario({
    runId: 'run_m4_fail_patch_closure_not_run',
    confirmedProjects: ['gitea', 'directus', 'ghost', 'keycloak', 'woodpecker', 'saleor'],
    closedPatchProjects: ['gitea', 'directus', 'keycloak', 'woodpecker'],
    omitPatchRetestProjects: ['ghost', 'saleor'],
  })
  const omittedPatchGrade = gradeOssRun(omittedPatchScenario)
  assert.equal(omittedPatchGrade.gates.passed, false)
  assert.equal(omittedPatchGrade.gates.patchRetestGatePassed, false)
  assert.equal(omittedPatchGrade.patchRetestAttempted, 6)
  assert.equal(omittedPatchGrade.patchRetestClosed, 4)

  const certOmittedPatch = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4MultihopCells(),
    oss: omittedPatchGrade,
    v7Floor: makePassingV7Floor(),
  })
  assert.equal(certOmittedPatch.verdict, 'FAIL')
  assert.ok(certOmittedPatch.failedChecks.some((c) => c.id === 'm4_oss_patch_retest'))
  assert.ok((certOmittedPatch.oss?.patchRetestClosureRate ?? 1) < 0.8)
})

test('M4 FAIL: < 50% sealed recall (1/4 sealed even with 4/4 dev = 62.5% overall) fails both run.ts and M4', () => {
  const lowSealedScenario = buildTenTargetScenario({
    runId: 'run_m4_fail_sealed_recall',
    confirmedProjects: ['gitea', 'directus', 'ghost', 'mattermost', 'keycloak'],
  })
  const lowSealedGrade = gradeOssRun(lowSealedScenario)
  assert.equal(lowSealedGrade.totalAnchors, 8)
  assert.equal(lowSealedGrade.tpCount, 5)
  assert.equal(lowSealedGrade.recall, 5 / 8)
  assert.equal(lowSealedGrade.sealedAnchors, 4)
  assert.equal(lowSealedGrade.sealedTpCount, 1)
  assert.equal(lowSealedGrade.sealedRecall, 0.25)
  assert.equal(lowSealedGrade.gates.recallGatePassed, false)
  assert.equal(lowSealedGrade.gates.passed, false)

  const certLowSealed = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4MultihopCells(),
    oss: lowSealedGrade,
    v7Floor: makePassingV7Floor(),
  })
  assert.equal(certLowSealed.verdict, 'FAIL')
  assert.equal(certLowSealed.oss?.sealedRecall, 0.25)
  assert.ok(certLowSealed.failedChecks.some((c) => c.id === 'm4_oss_sealed_recall'))
  assert.equal(certLowSealed.checks.find((c) => c.id === 'm4_oss_corpus_coverage')?.status, 'PASS')
  assert.equal(certLowSealed.checks.find((c) => c.id === 'm4_oss_patch_retest')?.status, 'PASS')
  assert.equal(certLowSealed.checks.find((c) => c.id === 'm4_oss_clean_controls')?.status, 'PASS')
  assert.equal(certLowSealed.checks.find((c) => c.id === 'precision_worst_run')?.status, 'PASS')
})

test('M4 FAIL: spurious anchor FP (victim_admin shortcut on sealed anchor) propagates per-anchor falsePositives and fails M4', () => {
  const scenario = buildTenTargetScenario({
    runId: 'run_m4_fail_shortcut_fp',
    confirmedProjects: ['gitea', 'directus', 'ghost', 'keycloak', 'woodpecker', 'saleor'],
  })
  // Corrupt keycloak receipt originPersona to victim_admin
  const kcReceipt = scenario.receipts.find((r) => r.targetId === 'oss-sealed-keycloak-01')!
  kcReceipt.originPersona = 'kc_realm_admin'

  const grade = gradeOssRun(scenario)
  const kcResult = grade.anchorResults.find((a) => a.anchorId === 'oss-sealed-keycloak-01')!
  assert.equal(kcResult.status, 'rejected_shortcut')
  assert.equal(kcResult.twoSideConfirmed, false)
  assert.equal(kcResult.falsePositives, 1)
  assert.equal(grade.spuriousAnchorFpCount, 1)
  assert.equal(grade.falsePositives, 1)
  assert.ok(grade.worstRunPrecision < 1)

  const cert = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4MultihopCells(),
    oss: grade,
    v7Floor: makePassingV7Floor(),
  })
  assert.equal(cert.verdict, 'FAIL')
  assert.equal(cert.precision.totalOssFalsePositives, 1)
  assert.ok(cert.failedChecks.some((c) => c.id === 'precision_worst_run'))
  assert.ok(cert.failedChecks.some((c) => c.id === 'm4_oss_sealed_recall'))
})

test('runOfflineSelfTest dev-only grade output is directly consumable by normalizeOssInputs', () => {
  const selfTest = runOfflineSelfTest()
  assert.equal(selfTest.ok, true)

  const normalized = normalizeOssInputs(selfTest.passingGrade)
  assert.ok(normalized)
  assert.equal(normalized.totalAnchors, 4)
  assert.equal(normalized.sealedAnchors, 0)
  assert.equal(normalized.sealedRecall, null)
  assert.equal(normalized.cleanControlCount, 2)
  assert.equal(normalized.cleanControlFpCount, 0)
  assert.equal(normalized.worstRunPrecision, 1)
  assert.equal(normalized.patchRetestClosureRate, 1)
})
