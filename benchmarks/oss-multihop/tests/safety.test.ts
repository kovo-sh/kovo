// Safety, manifest validation, external impact oracle, two-side grading,
// patch-retest `patchBrokeHopId`, and clean-control 0-FP gate tests.

import test from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  CLEAN_CONTROLS_PATH,
  DEV_MANIFEST_PATH,
  SEALED_EXAMPLE_PATH,
  assertLocalLabAllowed,
  evaluateOracleEvidence,
  gradeOssRun,
  isLoopbackBindSpec,
  isLoopbackUrl,
  loadManifestBundle,
  renderOssScorecardMarkdown,
  runOfflineSelfTest,
  validateAllCommittedManifests,
  validateCleanNegativeControl,
  validateComposeTemplate,
  validateExternalImpactOracle,
  validateOssAnchorManifest,
} from '../run.ts'
import type {
  CleanNegativeControlSpec,
  ExternalOracleObservation,
  KovoCompositeProofReceipt,
  OssAnchorManifest,
  PatchRetestRecord,
  RunTelemetry,
} from '../lib/types.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')

function walkTsFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    const st = statSync(full)
    if (st.isDirectory()) {
      out.push(...walkTsFiles(full))
    } else if (entry.endsWith('.ts')) {
      out.push(full)
    }
  }
  return out
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

function makeValidReceipt(
  anchor: OssAnchorManifest,
  runId: string,
  baseTs: number,
  correlationId: string,
): KovoCompositeProofReceipt {
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
      observedAtMs: baseTs + idx * 1000,
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
      correlationId,
      observedAtMs: baseTs + 5000,
    },
    runId,
  }
}

function makeVulnerableObservation(
  anchor: OssAnchorManifest,
  runId: string,
  observedAtMs: number,
  correlationId: string,
  observed = true,
): ExternalOracleObservation {
  return {
    observationId: `obs_${anchor.anchorId}_${observed ? 'hit' : 'miss'}`,
    targetId: anchor.anchorId,
    oracleId: anchor.impactOracle.oracleId,
    kind: anchor.impactOracle.kind,
    buildTarget: 'vulnerable',
    observed,
    observedAtMs,
    runId,
    correlationId,
    detail: observed ? 'External oracle observed impact.' : 'External oracle remained silent.',
  }
}

test('static safety: zero npm deps and no child_process/eval/vm in benchmarks/oss-multihop', () => {
  const tsFiles = walkTsFiles(ROOT)
  assert.ok(tsFiles.length >= 5)

  const importRe = /\bfrom\s+['"]([^'"]+)['"]/g
  const forbiddenCalls = [
    /\bnode:child_process\b/,
    /\bchild_process\b/,
    /\bnode:vm\b/,
    /\bnew\s+Function\s*\(/,
    /\beval\s*\(/,
  ]

  for (const file of tsFiles) {
    const src = readFileSync(file, 'utf8')
    let match: RegExpExecArray | null
    while ((match = importRe.exec(src)) !== null) {
      const spec = match[1]
      const allowed = spec.startsWith('node:') || spec.startsWith('./') || spec.startsWith('../')
      assert.ok(allowed, `Disallowed non-node/non-relative import '${spec}' in ${file}`)
    }
    if (!file.endsWith('safety.test.ts')) {
      for (const re of forbiddenCalls) {
        assert.equal(re.test(src), false, `Forbidden primitive ${re} found in ${file}`)
      }
    }
  }
})

test('local-lab gate enforces KOVO_ALLOW_LOCAL_LAB=1', () => {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  try {
    delete process.env.KOVO_ALLOW_LOCAL_LAB
    assert.throws(() => assertLocalLabAllowed(), /KOVO_ALLOW_LOCAL_LAB=1/)
    process.env.KOVO_ALLOW_LOCAL_LAB = '1'
    assert.doesNotThrow(() => assertLocalLabAllowed())
  } finally {
    if (prev === undefined) {
      delete process.env.KOVO_ALLOW_LOCAL_LAB
    } else {
      process.env.KOVO_ALLOW_LOCAL_LAB = prev
    }
  }
})

test('all committed manifests pass strict validation and satisfy split counts', () => {
  const report = validateAllCommittedManifests()
  assert.equal(report.valid, true, `Manifest validation issues: ${JSON.stringify(report.results)}`)

  const dev = loadManifestBundle(DEV_MANIFEST_PATH)
  assert.equal(dev.bundleKind, 'dev_anchors')
  assert.equal(dev.anchors?.length, 4)
  assert.deepEqual(
    dev.anchors?.map((a) => a.project),
    ['gitea', 'directus', 'ghost', 'mattermost'],
  )
  const oracleKinds = new Set(dev.anchors?.map((a) => a.impactOracle.kind))
  assert.deepEqual(
    [...oracleKinds].sort(),
    ['container_log', 'db_query', 'file_integrity', 'loopback_oob_collector'],
  )

  const clean = loadManifestBundle(CLEAN_CONTROLS_PATH)
  assert.equal(clean.bundleKind, 'clean_controls')
  assert.equal(clean.cleanControls?.length, 2)
  for (const ctrl of clean.cleanControls ?? []) {
    assert.equal(ctrl.maxAllowedFindings, 0)
  }

  const sealedRaw = readFileSync(SEALED_EXAMPLE_PATH, 'utf8')
  const sealed = loadManifestBundle(SEALED_EXAMPLE_PATH)
  assert.equal(sealed.bundleKind, 'sealed_anchors')
  assert.equal(sealed.anchors?.length, 4)
  // Ensure sealed template does not leak real M4 sealed OSS target names
  for (const forbidden of ['keycloak', 'authentik', 'gitlab', 'woodpecker', 'metabase', 'superset', 'saleor', 'medusa']) {
    assert.equal(
      sealedRaw.toLowerCase().includes(forbidden),
      false,
      `sealed-manifest.example.json must not leak sealed target '${forbidden}'`,
    )
  }
})

test('strict validator enforces --internal Docker networks, loopback-only binds, and pinned builds', () => {
  assert.equal(isLoopbackBindSpec('127.0.0.1:0:3000'), true)
  assert.equal(isLoopbackBindSpec('127.0.0.1:8080:3000'), true)
  assert.equal(isLoopbackBindSpec('0.0.0.0:3000:3000'), false)
  assert.equal(isLoopbackBindSpec('3000:3000'), false)
  assert.equal(isLoopbackBindSpec('[::]:3000:3000'), false)
  assert.equal(isLoopbackUrl('http://127.0.0.1:19401/oob/gitea'), true)
  assert.equal(isLoopbackUrl('https://evil.example.com/oob'), false)

  const dev = loadManifestBundle(DEV_MANIFEST_PATH)
  const baseAnchor = dev.anchors![0]

  // 1) Non-internal Docker network must be rejected
  const nonInternal = deepClone(baseAnchor)
  nonInternal.composeTemplate.networks.gitea_internal.internal = false
  const nonInternalRes = validateOssAnchorManifest(nonInternal)
  assert.equal(nonInternalRes.valid, false)
  assert.ok(nonInternalRes.issues.some((i) => i.code === 'NON_INTERNAL_NETWORK'))

  // 2) network_mode: host must be rejected
  const hostNet = deepClone(baseAnchor)
  hostNet.composeTemplate.services.gitea_app.networkMode = 'host'
  const hostNetRes = validateComposeTemplate(hostNet.composeTemplate, 'hostNet')
  assert.ok(hostNetRes.some((i) => i.code === 'FORBIDDEN_NETWORK_MODE'))

  // 3) Non-loopback port publication must be rejected
  const publicBind = deepClone(baseAnchor)
  publicBind.composeTemplate.services.gitea_app.ports = ['0.0.0.0:3000:3000']
  const publicBindRes = validateComposeTemplate(publicBind.composeTemplate, 'publicBind')
  assert.ok(publicBindRes.some((i) => i.code === 'NON_LOOPBACK_PORT_BIND'))

  // 4) Bare port publication (binds 0.0.0.0 in Docker) must be rejected
  const bareBind = deepClone(baseAnchor)
  bareBind.composeTemplate.services.gitea_app.ports = ['3000:3000']
  const bareBindRes = validateComposeTemplate(bareBind.composeTemplate, 'bareBind')
  assert.ok(bareBindRes.some((i) => i.code === 'NON_LOOPBACK_PORT_BIND'))

  // 5) Internal service (db/worker/internal_target) publishing even a loopback host port must be rejected
  const internalPort = deepClone(baseAnchor)
  internalPort.composeTemplate.services.gitea_db.ports = ['127.0.0.1:5432:5432']
  const internalPortRes = validateComposeTemplate(internalPort.composeTemplate, 'internalPort')
  assert.ok(internalPortRes.some((i) => i.code === 'INTERNAL_SERVICE_PORT_EXPOSED'))

  // 6) Privileged container and NET_ADMIN capability must be rejected
  const priv = deepClone(baseAnchor)
  priv.composeTemplate.services.gitea_app.privileged = true
  priv.composeTemplate.services.gitea_app.capAdd = ['NET_ADMIN']
  const privRes = validateComposeTemplate(priv.composeTemplate, 'priv')
  assert.ok(privRes.some((i) => i.code === 'PRIVILEGED_CONTAINER'))
  assert.ok(privRes.some((i) => i.code === 'FORBIDDEN_CAPABILITY'))

  // 7) Missing/floating pinned SHA or digest must be rejected
  const badPin = deepClone(baseAnchor)
  badPin.vulnerableBuild.versionTag = 'latest'
  badPin.vulnerableBuild.commitSha = 'not-a-sha'
  badPin.vulnerableBuild.imageDigest = 'sha256:short'
  const badPinRes = validateOssAnchorManifest(badPin)
  assert.equal(badPinRes.valid, false)
  assert.ok(badPinRes.issues.some((i) => i.code === 'FLOATING_OR_MISSING_TAG'))
  assert.ok(badPinRes.issues.some((i) => i.code === 'UNPINNED_COMMIT_SHA'))
  assert.ok(badPinRes.issues.some((i) => i.code === 'UNPINNED_IMAGE_DIGEST'))

  // 8) Missing paired patched commit or identical commit SHA must be rejected
  const sameCommit = deepClone(baseAnchor)
  sameCommit.patchedBuild.commitSha = sameCommit.vulnerableBuild.commitSha
  const sameCommitRes = validateOssAnchorManifest(sameCommit)
  assert.equal(sameCommitRes.valid, false)
  assert.ok(sameCommitRes.issues.some((i) => i.code === 'IDENTICAL_VULN_AND_PATCH_COMMIT'))

  // 9) Non-loopback OOB collector URL and mutating SQL query must be rejected
  const nonLoopbackOob = deepClone(baseAnchor.impactOracle)
  if (nonLoopbackOob.kind === 'loopback_oob_collector') {
    nonLoopbackOob.collectorUrl = 'https://collector.example.com/oob'
  }
  const oobRes = validateExternalImpactOracle(nonLoopbackOob, 'oob')
  assert.ok(oobRes.some((i) => i.code === 'NON_LOOPBACK_OOB_URL'))

  const directusAnchor = dev.anchors!.find((a) => a.project === 'directus')!
  const mutatingDb = deepClone(directusAnchor.impactOracle)
  if (mutatingDb.kind === 'db_query') {
    mutatingDb.readOnlyQuery = 'DELETE FROM directus_lab_audit'
  }
  const dbRes = validateExternalImpactOracle(mutatingDb, 'db')
  assert.ok(dbRes.some((i) => i.code === 'NON_READONLY_ORACLE_QUERY'))

  // 10) Clean negative control with non-zero maxAllowedFindings must be rejected
  const clean = loadManifestBundle(CLEAN_CONTROLS_PATH)
  const badClean = deepClone(clean.cleanControls![0]) as unknown as Omit<
    CleanNegativeControlSpec,
    'maxAllowedFindings'
  > & {
    maxAllowedFindings: number
  }
  badClean.maxAllowedFindings = 1
  const badCleanRes = validateCleanNegativeControl(badClean as unknown as CleanNegativeControlSpec)
  assert.equal(badCleanRes.valid, false)
  assert.ok(badCleanRes.issues.some((i) => i.code === 'NON_ZERO_CLEAN_CONTROL_LIMIT'))
})

test('external impact oracle evaluator handles all 4 oracle kinds (positive + silent)', () => {
  const dev = loadManifestBundle(DEV_MANIFEST_PATH)
  const anchors = dev.anchors!
  const runId = 'run_oracle_unit_01'
  const ts = 1_732_500_000_000

  const gitea = anchors.find((a) => a.project === 'gitea')!
  assert.equal(
    evaluateOracleEvidence(gitea.impactOracle, gitea.anchorId, runId, 'vulnerable', {
      kind: 'loopback_oob_collector',
      observedAtMs: ts,
      requests: [{ method: 'POST', path: '/oob/gitea/hit', canaryToken: 'oss_canary_gitea_abc', receivedAtMs: ts }],
    }).observed,
    true,
  )
  assert.equal(
    evaluateOracleEvidence(gitea.impactOracle, gitea.anchorId, runId, 'patched', {
      kind: 'loopback_oob_collector',
      observedAtMs: ts,
      requests: [{ method: 'POST', path: '/oob/gitea/hit', canaryToken: 'wrong_prefix', receivedAtMs: ts }],
    }).observed,
    false,
  )

  const directus = anchors.find((a) => a.project === 'directus')!
  assert.equal(
    evaluateOracleEvidence(directus.impactOracle, directus.anchorId, runId, 'vulnerable', {
      kind: 'db_query',
      observedAtMs: ts,
      rows: [{ id: 1, canary_marker: 'oss_canary_directus_123' }],
    }).observed,
    true,
  )
  assert.equal(
    evaluateOracleEvidence(directus.impactOracle, directus.anchorId, runId, 'patched', {
      kind: 'db_query',
      observedAtMs: ts,
      rows: [],
    }).observed,
    false,
  )

  const ghost = anchors.find((a) => a.project === 'ghost')!
  assert.equal(
    evaluateOracleEvidence(ghost.impactOracle, ghost.anchorId, runId, 'vulnerable', {
      kind: 'file_integrity',
      observedAtMs: ts,
      exists: true,
      contentPreview: 'audit=oss_canary_ghost_999',
    }).observed,
    true,
  )
  assert.equal(
    evaluateOracleEvidence(ghost.impactOracle, ghost.anchorId, runId, 'patched', {
      kind: 'file_integrity',
      observedAtMs: ts,
      exists: false,
    }).observed,
    false,
  )

  const mm = anchors.find((a) => a.project === 'mattermost')!
  assert.equal(
    evaluateOracleEvidence(mm.impactOracle, mm.anchorId, runId, 'vulnerable', {
      kind: 'container_log',
      observedAtMs: ts,
      lines: [{ stream: 'stdout', text: 'audit_event=compliance_export_complete id=oss_canary_mm_77', timestampMs: ts }],
    }).observed,
    true,
  )
  assert.equal(
    evaluateOracleEvidence(mm.impactOracle, mm.anchorId, runId, 'patched', {
      kind: 'container_log',
      observedAtMs: ts,
      lines: [{ stream: 'stdout', text: 'audit_event=compliance_export_denied id=oss_canary_mm_77', timestampMs: ts }],
    }).observed,
    false,
  )
})

test('two-side grading, patchBrokeHopId verification, and clean-control 0-FP failure gate', () => {
  const dev = loadManifestBundle(DEV_MANIFEST_PATH)
  const clean = loadManifestBundle(CLEAN_CONTROLS_PATH)
  const anchors = dev.anchors!
  const controls = clean.cleanControls!

  const runId = 'run_grade_test_01'
  const baseTs = 1_732_500_000_000
  const telemetry: RunTelemetry = {
    runId,
    split: 'dev',
    mode: 'white-box',
    durationMs: 1_800_000, // 30m
    costUsd: 5.0,
  }

  // Case 1: 3/4 two-side confirmed TPs with valid patchBrokeHopId closure, 0 clean-control FPs -> PASS
  const confirmedAnchors = anchors.slice(0, 3)
  const receipts = confirmedAnchors.map((a, i) => makeValidReceipt(a, runId, baseTs, `corr-${i}`))
  const observations = confirmedAnchors.map((a, i) => makeVulnerableObservation(a, runId, baseTs + 6000, `corr-${i}`, true))
  const patchRetests: PatchRetestRecord[] = confirmedAnchors.map((a, i) => ({
    targetId: a.anchorId,
    receiptId: receipts[i].receiptId,
    patchedCommitSha: a.patchedBuild.commitSha,
    replayedFullDag: true,
    terminalImpactEliminated: true,
    patchBrokeHopId: a.expectedPatchBrokeHopIds[0],
    patchedOracleObservation: {
      ...observations[i],
      observationId: `obs_patched_${i}`,
      buildTarget: 'patched',
      observed: false,
    },
  }))

  const passRes = gradeOssRun({
    anchors,
    cleanControls: controls,
    receipts,
    oracleObservations: observations,
    patchRetests,
    telemetry,
  })
  assert.equal(passRes.gates.passed, true)
  assert.equal(passRes.tpCount, 3)
  assert.equal(passRes.fnCount, 1)
  assert.equal(passRes.totalFpCount, 0)
  assert.equal(passRes.recall, 0.75)
  assert.equal(passRes.precision, 1)
  assert.equal(passRes.patchRetestClosureRate, 1)
  assert.equal(passRes.tpPerUsd, 0.6)
  assert.equal(passRes.tpPer10m, 1.0)
  assert.equal(passRes.hopDepthFunnel.twoSideConfirmed, 3)
  assert.ok(renderOssScorecardMarkdown(passRes).includes('patchBrokeHopId'))

  // Case 2: Any single FP on a clean negative control MUST fail the gate immediately
  const cleanFpReceipt: KovoCompositeProofReceipt = {
    ...receipts[0],
    receiptId: 'rcpt_clean_control_fp',
    targetId: controls[1].controlId,
  }
  const cleanFpRes = gradeOssRun({
    anchors,
    cleanControls: controls,
    receipts: [...receipts, cleanFpReceipt],
    oracleObservations: observations,
    patchRetests,
    telemetry,
  })
  assert.equal(cleanFpRes.gates.passed, false)
  assert.equal(cleanFpRes.gates.cleanControlGatePassed, false)
  assert.equal(cleanFpRes.gates.precisionGatePassed, false)
  assert.equal(cleanFpRes.cleanControlFpCount, 1)
  assert.equal(cleanFpRes.totalFpCount, 1)

  // Case 3: Missing or invalid patchBrokeHopId fails patch-retest closure gate
  const badPatchRetests = deepClone(patchRetests)
  badPatchRetests[0].patchBrokeHopId = null
  badPatchRetests[1].patchBrokeHopId = 'H99_NONEXISTENT'
  const badPatchRes = gradeOssRun({
    anchors,
    cleanControls: controls,
    receipts,
    oracleObservations: observations,
    patchRetests: badPatchRetests,
    telemetry,
  })
  assert.equal(badPatchRes.anchorResults[0].patchRetestStatus, 'missing_broke_hop')
  assert.equal(badPatchRes.anchorResults[1].patchRetestStatus, 'invalid_broke_hop')
  assert.equal(badPatchRes.patchRetestClosed, 1)
  assert.equal(badPatchRes.gates.patchRetestGatePassed, false)
  assert.equal(badPatchRes.gates.passed, false)

  // Case 4: Persona shortcutting (victim_admin origin) and Mode-B replay are rejected as spurious claims
  const shortcutReceipt = makeValidReceipt(anchors[0], runId, baseTs, 'corr-shortcut')
  shortcutReceipt.originPersona = 'gitea_org_admin' // victim_admin (allowedAsChainOrigin: false)
  const modeBReceipt = makeValidReceipt(anchors[1], runId, baseTs, 'corr-modeb')
  modeBReceipt.replayMode = 'one_shot_transcript'
  const receiptOnly = makeValidReceipt(anchors[2], runId, baseTs, 'corr-no-oracle')

  const rejectedRes = gradeOssRun({
    anchors,
    cleanControls: controls,
    receipts: [shortcutReceipt, modeBReceipt, receiptOnly],
    oracleObservations: [
      makeVulnerableObservation(anchors[0], runId, baseTs + 6000, 'corr-shortcut', true),
      makeVulnerableObservation(anchors[1], runId, baseTs + 6000, 'corr-modeb', true),
      // anchors[2] has NO oracle observation!
      makeVulnerableObservation(anchors[3], runId, baseTs + 6000, 'corr-oracle-only', true),
    ],
    patchRetests: [],
    telemetry,
  })
  assert.equal(rejectedRes.anchorResults[0].status, 'rejected_shortcut')
  assert.equal(rejectedRes.anchorResults[1].status, 'rejected_replay_mode')
  assert.equal(rejectedRes.anchorResults[2].status, 'unconfirmed_receipt_only')
  assert.equal(rejectedRes.anchorResults[3].status, 'unconfirmed_oracle_only')
  assert.equal(rejectedRes.tpCount, 0)
  assert.equal(rejectedRes.spuriousAnchorFpCount, 3)
  assert.equal(rejectedRes.gates.precisionGatePassed, false)
  assert.equal(rejectedRes.gates.passed, false)
})

test('runOfflineSelfTest passes end-to-end without Docker', () => {
  const report = runOfflineSelfTest()
  assert.equal(report.ok, true)
  assert.equal(report.manifestsValid, true)
  assert.equal(report.oracleKindsVerified, 4)
  assert.equal(report.passingGrade.gates.passed, true)
  assert.equal(report.cleanControlFpGateRejected, true)
})
