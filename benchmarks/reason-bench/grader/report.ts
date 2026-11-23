// Scorecard rendering to JSON or deterministic Markdown. No Date/random. See CONTRACTS.md.
// reason-bench adds family recall, causal-chain completion, decoy-FP rate and the heuristic floor /
// ΔReasoning headline rows.
import type { BenchmarkFunnel, Scorecard } from '../lib/types.ts'
import { failureTaxonomyBuckets } from '../lib/types.ts'
import { aggregateScorecards } from './aggregate.ts'

function pct(x: number | undefined): string {
  return x == null ? '-' : (x * 100).toFixed(1) + '%'
}
function usd(x: number): string {
  return '$' + x.toFixed(2)
}
function row(cells: Array<string | number>): string {
  return '| ' + cells.join(' | ') + ' |'
}

function headlineTable(s: Scorecard): string {
  const lines = [
    row(['metric', 'value']),
    row(['---', '---']),
    row(['recall', `${pct(s.recall)} (${s.confirmed}/${s.targets})`]),
    row(['precision', pct(s.precision)]),
    row(['decoyFP', `${s.decoyFalsePositives}/${s.decoys} (${pct(s.decoyFalsePositiveRate)})`]),
    row(['causal chains', `${s.chainsCompleted}/${s.chainsTotal}`]),
    row(['site chains', `${s.siteChainsCompleted}/${s.siteChainsTotal}`]),
    row(['heuristic floor (--no-llm)', pct(s.heuristicFloor)]),
    row(['ΔReasoning', s.deltaReasoning == null ? '-' : `${(s.deltaReasoning * 100).toFixed(1)}pp`]),
    row(['anti-heuristic gate', s.heuristicFloorPass == null ? '-' : s.heuristicFloorPass ? 'pass' : 'FAIL']),
    row(['cost', usd(s.totalCostUsd)]),
  ]
  return lines.join('\n')
}

function severityTable(s: Scorecard): string {
  const lines = [row(['severity', 'targets', 'confirmed', 'recall']), row(['---', '---', '---', '---'])]
  for (const sev of ['critical', 'high', 'medium', 'low'] as const) {
    const v = s.recallBySeverity[sev]
    lines.push(row([sev, v.targets, v.confirmed, pct(v.recall)]))
  }
  return lines.join('\n')
}

function familyTable(s: Scorecard): string {
  const lines = [row(['family', 'targets', 'confirmed', 'recall']), row(['---', '---', '---', '---'])]
  for (const k of Object.keys(s.recallByFamily).sort()) {
    const v = s.recallByFamily[k]
    lines.push(row([k, v.targets, v.confirmed, pct(v.recall)]))
  }
  return lines.join('\n')
}

function classTable(s: Scorecard): string {
  const lines = [row(['vulnClass', 'targets', 'confirmed']), row(['---', '---', '---'])]
  for (const k of Object.keys(s.recallByClass).sort()) {
    const v = s.recallByClass[k]
    lines.push(row([k, v.targets, v.confirmed]))
  }
  return lines.join('\n')
}

function funnelTable(f: BenchmarkFunnel): string {
  const stages: Array<[string, number]> = [
    ['targetVulns', f.targetVulns], ['surfaceDiscovered', f.surfaceDiscovered],
    ['hypothesisFormed', f.hypothesisFormed], ['signalObserved', f.signalObserved],
    ['specSubmitted', f.specSubmitted], ['zeroLlmConfirmed', f.zeroLlmConfirmed],
  ]
  const lines = [row(['stage', 'count']), row(['---', '---'])]
  for (const [k, v] of stages) lines.push(row([k, v]))
  return lines.join('\n')
}

function failureTable(s: Scorecard): string {
  const lines = [row(['bucket', 'count']), row(['---', '---'])]
  for (const b of failureTaxonomyBuckets) lines.push(row([b, s.failureBuckets[b]]))
  return lines.join('\n')
}

function budgetTable(s: Scorecard): string {
  const lines = [row(['usd', 'confirmed', 'recall']), row(['---', '---', '---'])]
  for (const p of s.budgetCurve) lines.push(row([usd(p.usd), p.confirmed, pct(p.recall)]))
  return lines.join('\n')
}

function chainTable(s: Scorecard): string {
  const lines = [row(['chainId', 'completed', 'hops', 'final', 'artifact']), row(['---', '---', '---', '---', '---'])]
  for (const c of s.chainResults) {
    lines.push(row([
      c.chainId, c.completed ? 'yes' : 'no', `${c.hopsObserved}/${c.hopsTotal}`,
      c.finalObserved ? 'yes' : 'no', c.artifact ?? '-',
    ]))
  }
  return lines.join('\n')
}

function vulnTable(s: Scorecard): string {
  const lines = [row(['siteId', 'class', 'family', 'severity', 'outcome', 'bucket', 'atUsd']), row(['---', '---', '---', '---', '---', '---', '---'])]
  for (const v of s.vulns) {
    lines.push(row([v.siteId, v.vulnClass, v.family ?? '-', v.severity, v.outcome, v.failureBucket ?? '-',
      v.confirmedAtUsd != null ? usd(v.confirmedAtUsd) : '-']))
  }
  return lines.join('\n')
}

function renderOne(s: Scorecard): string {
  return [
    `# Scorecard — ${s.app} seed ${s.seed} (${s.seedSet}, ${s.mode})`,
    '', '## Headline', headlineTable(s),
    '', '## Recall by severity', severityTable(s),
    '', '## Recall by family', familyTable(s),
    '', '## Recall by class', classTable(s),
    '', '## Causal chains', chainTable(s),
    '', '## Funnel', funnelTable(s.funnel),
    '', '## Failure buckets', failureTable(s),
    '', '## Budget curve', budgetTable(s),
    '', '## Per-vuln', vulnTable(s),
  ].join('\n')
}

function aggregateTable(list: Scorecard[]): string {
  const a = aggregateScorecards(list)
  const lines = [
    `# Aggregate — ${a.count} scorecards`, '',
    row(['metric', 'mean', 'min', 'max']), row(['---', '---', '---', '---']),
    row(['recall', pct(a.recall.mean), pct(a.recall.min), pct(a.recall.max)]),
    row(['precision', pct(a.precision.mean), pct(a.precision.min), pct(a.precision.max)]),
    row(['ΔReasoning', a.deltaReasoning ? pct(a.deltaReasoning.mean) : '-',
      a.deltaReasoning ? pct(a.deltaReasoning.min) : '-', a.deltaReasoning ? pct(a.deltaReasoning.max) : '-']),
    '', row(['pooled decoy FP rate', pct(a.pooledDecoyFpRate)]), row(['---', '---']),
    '', '## Pooled recall by family', row(['family', 'targets', 'confirmed', 'recall']), row(['---', '---', '---', '---']),
  ]
  for (const k of Object.keys(a.pooledRecallByFamily).sort()) {
    const v = a.pooledRecallByFamily[k]
    lines.push(row([k, v.targets, v.confirmed, pct(v.recall)]))
  }
  lines.push('', '## Pooled recall by class', row(['vulnClass', 'targets', 'confirmed', 'recall']), row(['---', '---', '---', '---']))
  for (const k of Object.keys(a.pooledRecallByClass).sort()) {
    const v = a.pooledRecallByClass[k]
    lines.push(row([k, v.targets, v.confirmed, pct(v.recall)]))
  }
  return lines.join('\n')
}

export function renderScorecard(s: Scorecard | Scorecard[], format: 'json' | 'md'): string {
  if (format === 'json') return JSON.stringify(s, null, 2)
  if (Array.isArray(s)) {
    return [aggregateTable(s), '', ...s.map(renderOne)].join('\n\n')
  }
  return renderOne(s)
}
