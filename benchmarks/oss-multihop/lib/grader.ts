// Pure two-side confirmation grader, patch-retest `patchBrokeHopId` verifier,
// clean negative-control 0-FP gate, and Markdown scorecard renderer for benchmarks/oss-multihop/.

import type {
  AnchorGradeDetail,
  AnchorOutcomeStatus,
  CleanControlGradeDetail,
  CleanNegativeControlSpec,
  ExternalOracleObservation,
  GuardianCompositeProofReceipt,
  HopDepthFunnel,
  OssAnchorManifest,
  OssGradeInput,
  OssGradeResult,
  PatchRetestRecord,
  PatchRetestStatus,
} from './types.ts'

export const OSS_MIN_RECALL_GATE = 0.5
export const OSS_MIN_PATCH_CLOSURE_GATE = 0.8

export interface TwoSideVerdict {
  confirmed: boolean
  status: AnchorOutcomeStatus
  oracleConfirmed: boolean
  receiptConfirmed: boolean
  matchedObservation?: ExternalOracleObservation
  reasons: string[]
}

export interface PatchRetestVerdict {
  status: PatchRetestStatus
  patchBrokeHopId: string | null
  reasons: string[]
}

function isMonotonicHops(receipt: GuardianCompositeProofReceipt): boolean {
  if (!Array.isArray(receipt.hops) || receipt.hops.length === 0) return false
  const sorted = [...receipt.hops].sort((a, b) => a.order - b.order)
  for (let i = 0; i < sorted.length; i += 1) {
    if (sorted[i].order !== i + 1) return false
    if (i > 0 && sorted[i].observedAtMs < sorted[i - 1].observedAtMs) return false
  }
  return true
}

function areCausalEdgesValid(receipt: GuardianCompositeProofReceipt): boolean {
  if (receipt.hops.length <= 1) return true
  if (!Array.isArray(receipt.causalEdges) || receipt.causalEdges.length < receipt.hops.length - 1) {
    return false
  }
  const hopIds = new Set(receipt.hops.map((h) => h.hopId))
  for (const edge of receipt.causalEdges) {
    if (!edge.verified) return false
    if (!hopIds.has(edge.fromHopId) || !hopIds.has(edge.toHopId)) return false
    if (edge.fromHopId === edge.toHopId) return false
  }
  return true
}

/**
 * Verifies two-side confirmation:
 * 1) External impact oracle observed the terminal impact on the vulnerable build, AND
 * 2) Guardian produced a host-verified Mode-A `CompositeProofReceipt` originating from an
 *    allowed attacker persona with verified causal edges and matching run/correlation.
 */
export function verifyTwoSideConfirmation(
  anchor: OssAnchorManifest,
  receipt: GuardianCompositeProofReceipt | undefined,
  observations: readonly ExternalOracleObservation[],
): TwoSideVerdict {
  const reasons: string[] = []
  const matchingObs = observations.find(
    (obs) =>
      obs.targetId === anchor.anchorId &&
      obs.oracleId === anchor.impactOracle.oracleId &&
      obs.buildTarget === 'vulnerable' &&
      obs.observed === true,
  )
  const oracleConfirmed = matchingObs !== undefined

  if (!receipt) {
    if (oracleConfirmed) {
      reasons.push('External oracle observed impact, but Guardian emitted no CompositeProofReceipt.')
      return {
        confirmed: false,
        status: 'unconfirmed_oracle_only',
        oracleConfirmed: true,
        receiptConfirmed: false,
        matchedObservation: matchingObs,
        reasons,
      }
    }
    reasons.push('Neither external oracle nor Guardian receipt confirmed this anchor.')
    return {
      confirmed: false,
      status: 'fn',
      oracleConfirmed: false,
      receiptConfirmed: false,
      reasons,
    }
  }

  if (!receipt.verified || !receipt.terminalImpact.observed) {
    reasons.push('Guardian CompositeProofReceipt is not host-verified or terminalImpact.observed is false.')
    return {
      confirmed: false,
      status: oracleConfirmed ? 'unconfirmed_oracle_only' : 'fn',
      oracleConfirmed,
      receiptConfirmed: false,
      matchedObservation: matchingObs,
      reasons,
    }
  }

  if (receipt.replayMode !== 'fresh_clean_replay') {
    reasons.push(`Replay mode '${receipt.replayMode}' is disallowed on benchmark anchors (Mode A fresh_clean_replay required).`)
    return {
      confirmed: false,
      status: 'rejected_replay_mode',
      oracleConfirmed,
      receiptConfirmed: false,
      matchedObservation: matchingObs,
      reasons,
    }
  }

  const allowedOrigins = new Set(
    anchor.personas.filter((p) => p.allowedAsChainOrigin).map((p) => p.personaId),
  )
  if (!receipt.attackerOriginVerified || !allowedOrigins.has(receipt.originPersona)) {
    reasons.push(
      `Origin persona '${receipt.originPersona}' failed attacker-origin provenance check (allowed: ${[...allowedOrigins].join(', ')}).`,
    )
    return {
      confirmed: false,
      status: 'rejected_shortcut',
      oracleConfirmed,
      receiptConfirmed: false,
      matchedObservation: matchingObs,
      reasons,
    }
  }

  if (receipt.hops.length < anchor.hopCount || !isMonotonicHops(receipt) || !areCausalEdgesValid(receipt)) {
    reasons.push(
      `Causal DAG incomplete or unverified (expected >= ${anchor.hopCount} monotonically ordered hops with verified causalEdges).`,
    )
    return {
      confirmed: false,
      status: 'rejected_edge_binding',
      oracleConfirmed,
      receiptConfirmed: false,
      matchedObservation: matchingObs,
      reasons,
    }
  }

  if (!oracleConfirmed || !matchingObs) {
    reasons.push('Guardian emitted a verified receipt, but the external impact oracle did not observe impact.')
    return {
      confirmed: false,
      status: 'unconfirmed_receipt_only',
      oracleConfirmed: false,
      receiptConfirmed: true,
      reasons,
    }
  }

  if (matchingObs.runId !== receipt.runId) {
    reasons.push(`Run ID mismatch: receipt runId='${receipt.runId}' vs oracle runId='${matchingObs.runId}'.`)
    return {
      confirmed: false,
      status: 'rejected_correlation',
      oracleConfirmed: true,
      receiptConfirmed: true,
      matchedObservation: matchingObs,
      reasons,
    }
  }

  if (
    receipt.terminalImpact.correlationId &&
    matchingObs.correlationId &&
    receipt.terminalImpact.correlationId !== matchingObs.correlationId
  ) {
    reasons.push(
      `Correlation ID mismatch: receipt='${receipt.terminalImpact.correlationId}' vs oracle='${matchingObs.correlationId}'.`,
    )
    return {
      confirmed: false,
      status: 'rejected_correlation',
      oracleConfirmed: true,
      receiptConfirmed: true,
      matchedObservation: matchingObs,
      reasons,
    }
  }

  const earliestHopMs = Math.min(...receipt.hops.map((h) => h.observedAtMs))
  if (matchingObs.observedAtMs < earliestHopMs) {
    reasons.push(
      `Non-causal timestamp ordering: external oracle (${matchingObs.observedAtMs}) preceded first hop (${earliestHopMs}).`,
    )
    return {
      confirmed: false,
      status: 'rejected_correlation',
      oracleConfirmed: true,
      receiptConfirmed: true,
      matchedObservation: matchingObs,
      reasons,
    }
  }

  return {
    confirmed: true,
    status: 'tp',
    oracleConfirmed: true,
    receiptConfirmed: true,
    matchedObservation: matchingObs,
    reasons: ['Two-side confirmed: external impact oracle and Mode-A CompositeProofReceipt agree.'],
  }
}

/**
 * Verifies full-DAG patch retest closure against the paired official patched commit,
 * requiring a valid `patchBrokeHopId` and external oracle silence on the patched build.
 */
export function gradePatchRetest(
  anchor: OssAnchorManifest,
  receipt: GuardianCompositeProofReceipt,
  patchRetests: readonly PatchRetestRecord[],
): PatchRetestVerdict {
  const record = patchRetests.find(
    (r) => r.targetId === anchor.anchorId && r.receiptId === receipt.receiptId,
  )
  if (!record) {
    return {
      status: 'not_run',
      patchBrokeHopId: null,
      reasons: ['No patch-retest record submitted for confirmed TP.'],
    }
  }

  if (record.patchedCommitSha !== anchor.patchedBuild.commitSha) {
    return {
      status: 'commit_mismatch',
      patchBrokeHopId: record.patchBrokeHopId,
      reasons: [
        `Patch retest ran against commit '${record.patchedCommitSha}', expected paired patched commit '${anchor.patchedBuild.commitSha}'.`,
      ],
    }
  }

  if (!record.replayedFullDag) {
    return {
      status: 'open_still_reproduces',
      patchBrokeHopId: record.patchBrokeHopId,
      reasons: ['Patch retest must replay the full CompositeProofReceipt DAG (replayedFullDag: true).'],
    }
  }

  const patchedObs = record.patchedOracleObservation
  if (!patchedObs || patchedObs.buildTarget !== 'patched' || patchedObs.observed !== false) {
    return {
      status: 'open_still_reproduces',
      patchBrokeHopId: record.patchBrokeHopId,
      reasons: [
        'External oracle did not confirm impact elimination on the patched build (requires patched build observation with observed: false).',
      ],
    }
  }

  if (!record.terminalImpactEliminated) {
    return {
      status: 'open_still_reproduces',
      patchBrokeHopId: record.patchBrokeHopId,
      reasons: ['Terminal impact was not eliminated on the paired patched build.'],
    }
  }

  if (!record.patchBrokeHopId || record.patchBrokeHopId.trim().length === 0) {
    return {
      status: 'missing_broke_hop',
      patchBrokeHopId: null,
      reasons: ['Patch retest must report a non-empty patchBrokeHopId identifying where the patch broke the chain.'],
    }
  }

  const validAnchorHopIds = new Set(anchor.hops.map((h) => h.hopId))
  const validReceiptHopIds = new Set(receipt.hops.map((h) => h.hopId))
  if (!validAnchorHopIds.has(record.patchBrokeHopId) && !validReceiptHopIds.has(record.patchBrokeHopId)) {
    return {
      status: 'invalid_broke_hop',
      patchBrokeHopId: record.patchBrokeHopId,
      reasons: [
        `Reported patchBrokeHopId '${record.patchBrokeHopId}' does not match any hop in anchor '${anchor.anchorId}' or its receipt.`,
      ],
    }
  }

  const matchesExpected = anchor.expectedPatchBrokeHopIds.includes(record.patchBrokeHopId)
  const note = matchesExpected
    ? `Patch retest closed cleanly at expected hop '${record.patchBrokeHopId}'.`
    : `Patch retest closed at valid chain hop '${record.patchBrokeHopId}' (expected: ${anchor.expectedPatchBrokeHopIds.join(', ')}).`

  return {
    status: 'closed',
    patchBrokeHopId: record.patchBrokeHopId,
    reasons: [note],
  }
}

export function gradeCleanControl(
  control: CleanNegativeControlSpec,
  receipts: readonly GuardianCompositeProofReceipt[],
  observations: readonly ExternalOracleObservation[],
): CleanControlGradeDetail {
  const controlReceipts = receipts.filter((r) => r.targetId === control.controlId)
  const unexpectedOracles = observations.filter(
    (o) => o.targetId === control.controlId && o.observed === true,
  )
  const fpCount = controlReceipts.length
  const passed = fpCount === 0 && unexpectedOracles.length === 0
  const reasons: string[] = []
  if (fpCount > 0) {
    reasons.push(
      `Clean negative control '${control.controlId}' failed 0-FP gate with ${fpCount} finding(s): ${controlReceipts.map((r) => r.receiptId).join(', ')}.`,
    )
  }
  if (unexpectedOracles.length > 0) {
    reasons.push(
      `Clean negative control '${control.controlId}' triggered ${unexpectedOracles.length} unexpected external oracle event(s).`,
    )
  }
  if (passed) {
    reasons.push('0 FPs and 0 unexpected oracle triggers on clean patched control.')
  }

  return {
    controlId: control.controlId,
    project: control.project,
    passed,
    fpCount,
    fpReceiptIds: controlReceipts.map((r) => r.receiptId),
    unexpectedOracleTriggers: unexpectedOracles.length,
    reasons,
  }
}

export function gradeOssRun(input: OssGradeInput): OssGradeResult {
  const anchorIds = new Set(input.anchors.map((a) => a.anchorId))
  const controlIds = new Set(input.cleanControls.map((c) => c.controlId))

  const anchorResults: AnchorGradeDetail[] = []
  let tpCount = 0
  let fnCount = 0
  let spuriousAnchorFpCount = 0
  let patchRetestAttempted = 0
  let patchRetestClosed = 0

  const funnel: HopDepthFunnel = {
    h1: 0,
    h2: 0,
    h3: 0,
    h4Plus: 0,
    oracleObserved: 0,
    twoSideConfirmed: 0,
  }

  for (const anchor of input.anchors) {
    const candidateReceipts = input.receipts.filter((r) => r.targetId === anchor.anchorId)
    const maxObservedHopDepth = candidateReceipts.reduce(
      (max, r) => Math.max(max, r.hops.length),
      0,
    )
    if (maxObservedHopDepth >= 1) funnel.h1 += 1
    if (maxObservedHopDepth >= 2) funnel.h2 += 1
    if (maxObservedHopDepth >= 3) funnel.h3 += 1
    if (maxObservedHopDepth >= 4) funnel.h4Plus += 1

    // Pick best matching receipt (prefer verified TP, else first verified claim, else first receipt).
    let chosenReceipt: GuardianCompositeProofReceipt | undefined
    let chosenVerdict: TwoSideVerdict | undefined

    if (candidateReceipts.length === 0) {
      chosenVerdict = verifyTwoSideConfirmation(anchor, undefined, input.oracleObservations)
    } else {
      for (const r of candidateReceipts) {
        const verdict = verifyTwoSideConfirmation(anchor, r, input.oracleObservations)
        if (verdict.confirmed) {
          chosenReceipt = r
          chosenVerdict = verdict
          break
        }
        if (!chosenVerdict || (r.verified && !chosenReceipt?.verified)) {
          chosenReceipt = r
          chosenVerdict = verdict
        }
      }
    }

    const verdict = chosenVerdict!
    if (verdict.oracleConfirmed) funnel.oracleObserved += 1

    let patchRetestStatus: PatchRetestStatus = 'not_applicable'
    let patchBrokeHopId: string | null = null
    const reasons = [...verdict.reasons]

    if (verdict.confirmed && chosenReceipt) {
      tpCount += 1
      funnel.twoSideConfirmed += 1
      const pr = gradePatchRetest(anchor, chosenReceipt, input.patchRetests)
      patchRetestStatus = pr.status
      patchBrokeHopId = pr.patchBrokeHopId
      reasons.push(...pr.reasons)
      if (pr.status !== 'not_run') {
        patchRetestAttempted += 1
      }
      if (pr.status === 'closed') {
        patchRetestClosed += 1
      }
    } else {
      fnCount += 1
      if (
        chosenReceipt?.verified &&
        (verdict.status === 'unconfirmed_receipt_only' ||
          verdict.status === 'rejected_shortcut' ||
          verdict.status === 'rejected_edge_binding' ||
          verdict.status === 'rejected_replay_mode' ||
          verdict.status === 'rejected_correlation')
      ) {
        spuriousAnchorFpCount += 1
      }
    }

    anchorResults.push({
      anchorId: anchor.anchorId,
      project: anchor.project,
      split: anchor.split,
      status: verdict.status,
      oracleConfirmed: verdict.oracleConfirmed,
      receiptConfirmed: verdict.receiptConfirmed,
      twoSideConfirmed: verdict.confirmed,
      matchedReceiptId: chosenReceipt?.receiptId,
      patchRetestStatus,
      patchBrokeHopId,
      maxObservedHopDepth,
      reasons,
    })
  }

  const cleanControlResults = input.cleanControls.map((ctrl) =>
    gradeCleanControl(ctrl, input.receipts, input.oracleObservations),
  )
  const cleanControlFpCount = cleanControlResults.reduce((acc, r) => acc + r.fpCount, 0)

  const unmatchedFpCount = input.receipts.filter(
    (r) => !anchorIds.has(r.targetId) && !controlIds.has(r.targetId),
  ).length

  const totalFpCount = cleanControlFpCount + unmatchedFpCount + spuriousAnchorFpCount
  const totalAnchors = input.anchors.length
  const recall = totalAnchors > 0 ? tpCount / totalAnchors : 0
  const precision = tpCount + totalFpCount > 0 ? tpCount / (tpCount + totalFpCount) : 1
  const patchRetestClosureRate = tpCount > 0 ? patchRetestClosed / tpCount : 1
  const tpPerUsd = input.telemetry.costUsd > 0 ? tpCount / input.telemetry.costUsd : 0
  const tpPer10m = input.telemetry.durationMs > 0 ? tpCount / (input.telemetry.durationMs / 600_000) : 0

  const precisionGatePassed = precision === 1 && totalFpCount === 0
  const cleanControlGatePassed =
    cleanControlFpCount === 0 && cleanControlResults.every((c) => c.passed)
  const recallGatePassed = totalAnchors === 0 ? true : recall >= OSS_MIN_RECALL_GATE
  const patchRetestGatePassed =
    tpCount === 0 ? true : patchRetestClosureRate >= OSS_MIN_PATCH_CLOSURE_GATE

  const failures: string[] = []
  if (!precisionGatePassed) {
    failures.push(`Precision gate failed: precision=${(precision * 100).toFixed(1)}% (totalFpCount=${totalFpCount}).`)
  }
  if (!cleanControlGatePassed) {
    failures.push(`Clean negative-control 0-FP gate failed: cleanControlFpCount=${cleanControlFpCount}.`)
  }
  if (!recallGatePassed) {
    failures.push(
      `Recall gate failed: ${(recall * 100).toFixed(1)}% < ${(OSS_MIN_RECALL_GATE * 100).toFixed(0)}%.`,
    )
  }
  if (!patchRetestGatePassed) {
    failures.push(
      `Patch-retest closure gate failed: ${(patchRetestClosureRate * 100).toFixed(1)}% < ${(OSS_MIN_PATCH_CLOSURE_GATE * 100).toFixed(0)}%.`,
    )
  }

  return {
    schemaVersion: '1.0',
    runId: input.telemetry.runId,
    split: input.telemetry.split,
    mode: input.telemetry.mode,
    totalAnchors,
    tpCount,
    fnCount,
    unmatchedFpCount,
    spuriousAnchorFpCount,
    cleanControlCount: input.cleanControls.length,
    cleanControlFpCount,
    totalFpCount,
    recall,
    precision,
    patchRetestAttempted,
    patchRetestClosed,
    patchRetestClosureRate,
    tpPerUsd,
    tpPer10m,
    hopDepthFunnel: funnel,
    anchorResults,
    cleanControlResults,
    gates: {
      passed: failures.length === 0,
      precisionGatePassed,
      cleanControlGatePassed,
      recallGatePassed,
      patchRetestGatePassed,
      failures,
    },
  }
}

export function renderOssScorecardMarkdown(result: OssGradeResult): string {
  const lines: string[] = [
    `# OSS Multi-Hop Anchor Scorecard (${result.split} / ${result.mode})`,
    '',
    `- **Run ID:** \`${result.runId}\``,
    `- **Overall Gate:** ${result.gates.passed ? 'PASS' : 'FAIL'}`,
    `- **Recall:** ${(result.recall * 100).toFixed(1)}% (${result.tpCount}/${result.totalAnchors})`,
    `- **Precision:** ${(result.precision * 100).toFixed(1)}% (FPs: ${result.totalFpCount} total — ${result.cleanControlFpCount} clean-control, ${result.spuriousAnchorFpCount} spurious-anchor, ${result.unmatchedFpCount} unmatched)`,
    `- **Patch-Retest Closure:** ${(result.patchRetestClosureRate * 100).toFixed(1)}% (${result.patchRetestClosed}/${result.tpCount})`,
    `- **Efficiency:** ${result.tpPerUsd.toFixed(2)} TP/$ | ${result.tpPer10m.toFixed(2)} TP/10m`,
    `- **Hop-Depth Funnel:** H1=${result.hopDepthFunnel.h1} -> H2=${result.hopDepthFunnel.h2} -> H3=${result.hopDepthFunnel.h3} -> H4+=${result.hopDepthFunnel.h4Plus} -> Oracle=${result.hopDepthFunnel.oracleObserved} -> Confirmed=${result.hopDepthFunnel.twoSideConfirmed}`,
    '',
    '## Anchors',
    '',
    '| Anchor | Project | Outcome | Oracle | Receipt | Patch Retest | `patchBrokeHopId` |',
    '| --- | --- | --- | --- | --- | --- | --- |',
  ]

  for (const a of result.anchorResults) {
    lines.push(
      `| \`${a.anchorId}\` | ${a.project} | \`${a.status}\` | ${a.oracleConfirmed ? 'yes' : 'no'} | ${a.receiptConfirmed ? 'yes' : 'no'} | \`${a.patchRetestStatus}\` | ${a.patchBrokeHopId ? `\`${a.patchBrokeHopId}\`` : '—'} |`,
    )
  }

  lines.push('', '## Clean Negative Controls (0-FP Gate)', '', '| Control | Project | Status | FPs | Unexpected Oracles |', '| --- | --- | --- | --- | --- |')
  for (const c of result.cleanControlResults) {
    lines.push(
      `| \`${c.controlId}\` | ${c.project} | ${c.passed ? 'PASS' : 'FAIL'} | ${c.fpCount} | ${c.unexpectedOracleTriggers} |`,
    )
  }

  if (result.gates.failures.length > 0) {
    lines.push('', '## Gate Failures', '')
    for (const f of result.gates.failures) {
      lines.push(`- ${f}`)
    }
  }

  return `${lines.join('\n')}\n`
}
