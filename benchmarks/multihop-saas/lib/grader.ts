// Grader for the multi-hop suite. Strict accounting: only a chain that both the causal lineage
// verifier observed in full order AND the host-signed composite receipt confirms counts as a
// true positive. Any claim on a hardened counterpart or a benign early hop of a partial twin is a
// strict decoy false positive and fails the precision gate.
import type {
  ExpectedChain, FpCategory, GradeInput, Scorecard, TwinDecoy,
} from './types.ts'
import { hopFunnel as computeHopFunnel } from './chain-oracle.ts'

export const ANTI_HEURISTIC_FLOOR_MAX = 0.05

function emptyFp(): Record<FpCategory, number> {
  return { hardened_counterpart: 0, decoy_twin: 0, unmatched: 0, unconfirmed: 0 }
}

function twinFor(input: GradeInput): TwinDecoy | undefined {
  if (!input.groundTruth.twinId) return undefined
  return input.groundTruth.twinDecoys[0]
}

export function gradeRun(input: GradeInput): Scorecard {
  const { groundTruth, findings, oracle } = input
  const expectedById = new Map<string, ExpectedChain>(groundTruth.expectedChains.map((c) => [c.chainId, c]))
  const confirmedById = new Map(oracle.confirmed.filter((c) => c.receiptVerified).map((c) => [c.chainId, c]))
  const fpByCategory = emptyFp()
  const matched = new Set<string>()
  const twin = twinFor(input)
  let fp = 0

  for (const finding of findings) {
    if (groundTruth.labMode === 'hardened') {
      fpByCategory.hardened_counterpart += 1
      fp += 1
      continue
    }
    if (twin) {
      const touchesDecoy = finding.chainId === twin.chainId ||
        (finding.hopIds ?? []).some((hopId) => twin.benignHopIds.includes(hopId))
      fpByCategory[touchesDecoy ? 'decoy_twin' : 'unmatched'] += 1
      fp += 1
      continue
    }
    const expected = expectedById.get(finding.chainId)
    if (!expected) {
      fpByCategory.unmatched += 1
      fp += 1
      continue
    }
    if (matched.has(finding.chainId)) continue
    const confirmed = confirmedById.get(finding.chainId)
    const receiptAgrees = !finding.receipt || (
      finding.receipt.chainId === confirmed?.receipt.chainId &&
      finding.receipt.signature === confirmed?.receipt.signature
    )
    if (confirmed && confirmed.vulnClass === finding.terminalVulnClass && receiptAgrees) {
      matched.add(finding.chainId)
    } else {
      fpByCategory.unconfirmed += 1
      fp += 1
    }
  }

  const tp = matched.size
  const fn = groundTruth.expectedChains.filter((c) => !matched.has(c.chainId)).length
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp)
  const recall = groundTruth.expectedChains.length === 0 ? 1 : tp / groundTruth.expectedChains.length

  const hopFunnel = computeHopFunnel(oracle.evaluations)
  const dropReasons: Record<string, number> = {}
  for (const evaluation of oracle.evaluations) {
    if (evaluation.dropReason) dropReasons[evaluation.dropReason] = (dropReasons[evaluation.dropReason] ?? 0) + 1
  }

  const strictDecoyFps = fpByCategory.decoy_twin
  const precisionOk = precision === 1 && fp === 0
  const zeroDecoyFps = strictDecoyFps === 0
  const recallOk = groundTruth.expectedChains.length === 0 || tp === groundTruth.expectedChains.length

  return {
    app: groundTruth.app,
    seed: groundTruth.seed,
    seedSet: groundTruth.seedSet,
    mode: groundTruth.labMode,
    twin: groundTruth.twinId,
    tp,
    fp,
    fn,
    precision,
    recall,
    strictDecoyFps,
    fpByCategory,
    matchedChainIds: [...matched],
    missedChainIds: groundTruth.expectedChains.filter((c) => !matched.has(c.chainId)).map((c) => c.chainId),
    hopFunnel,
    dropReasons,
    gate: {
      precisionOk,
      zeroDecoyFps,
      pass: precisionOk && zeroDecoyFps && recallOk,
    },
  }
}

export function renderScorecard(card: Scorecard, format: 'json' | 'md'): string {
  if (format === 'json') return `${JSON.stringify(card, null, 2)}\n`
  const pct = (value: number): string => `${(value * 100).toFixed(1)}%`
  const lines = [
    `# multihop-saas scorecard — ${card.app}`,
    '',
    `- seed: ${card.seed} (${card.seedSet})`,
    `- mode: ${card.mode}${card.twin ? ` (${card.twin})` : ''}`,
    `- tp/fp/fn: ${card.tp}/${card.fp}/${card.fn}`,
    `- precision: ${pct(card.precision)}`,
    `- recall: ${pct(card.recall)}`,
    `- strict decoy fps: ${card.strictDecoyFps}`,
    `- fp categories: hardened=${card.fpByCategory.hardened_counterpart} decoy=${card.fpByCategory.decoy_twin} unmatched=${card.fpByCategory.unmatched} unconfirmed=${card.fpByCategory.unconfirmed}`,
    '',
    '## Hop-Depth Funnel',
    '',
    '| H1 | H2 | H3 | H4+ | FinalOracle | CompositeReceiptConfirmed |',
    '|---:|---:|---:|---:|---:|---:|',
    `| ${card.hopFunnel.h1} | ${card.hopFunnel.h2} | ${card.hopFunnel.h3} | ${card.hopFunnel.h4plus} | ${card.hopFunnel.finalOracle} | ${card.hopFunnel.receiptConfirmed} |`,
    '',
    `## Drop Reasons`,
    '',
    Object.keys(card.dropReasons).length === 0
      ? 'none'
      : Object.entries(card.dropReasons).map(([reason, count]) => `- ${reason}: ${count}`).join('\n'),
    '',
    `Gate: **${card.gate.pass ? 'PASS' : 'FAIL'}** (precision=${card.gate.precisionOk}, zero-decoy=${card.gate.zeroDecoyFps})`,
    '',
  ]
  return lines.join('\n')
}
