// Aggregate a set of scorecards across seeds/apps. Pure. See CONTRACTS.md "Grading". Adds pooled
// family recall and mean ΔReasoning for reason-bench.
import type { Scorecard } from '../lib/types.ts'

export interface AggregateScorecard {
  count: number
  recall: { mean: number; min: number; max: number }
  precision: { mean: number; min: number; max: number }
  deltaReasoning?: { mean: number; min: number; max: number }
  pooledDecoyFpRate: number
  pooledRecallByClass: Record<string, { targets: number; confirmed: number; recall: number }>
  pooledRecallByFamily: Record<string, { targets: number; confirmed: number; recall: number }>
}

export function aggregateScorecards(list: Scorecard[]): AggregateScorecard {
  if (list.length === 0) {
    return {
      count: 0,
      recall: { mean: 0, min: 0, max: 0 },
      precision: { mean: 0, min: 0, max: 0 },
      pooledDecoyFpRate: 0,
      pooledRecallByClass: {},
      pooledRecallByFamily: {},
    }
  }
  const stat = (xs: number[]) => ({
    mean: xs.reduce((a, b) => a + b, 0) / xs.length,
    min: Math.min(...xs),
    max: Math.max(...xs),
  })
  const totalDecoys = list.reduce((a, s) => a + s.decoys, 0)
  const totalDecoyFp = list.reduce((a, s) => a + s.decoyFalsePositives, 0)
  const pooledRecallByClass: AggregateScorecard['pooledRecallByClass'] = {}
  for (const s of list) {
    for (const [k, v] of Object.entries(s.recallByClass)) {
      const cur = pooledRecallByClass[k] ?? { targets: 0, confirmed: 0, recall: 0 }
      cur.targets += v.targets
      cur.confirmed += v.confirmed
      pooledRecallByClass[k] = cur
    }
  }
  for (const v of Object.values(pooledRecallByClass)) v.recall = v.targets > 0 ? v.confirmed / v.targets : 0

  const pooledRecallByFamily: AggregateScorecard['pooledRecallByFamily'] = {}
  for (const s of list) {
    for (const [k, v] of Object.entries(s.recallByFamily)) {
      const cur = pooledRecallByFamily[k] ?? { targets: 0, confirmed: 0, recall: 0 }
      cur.targets += v.targets
      cur.confirmed += v.confirmed
      pooledRecallByFamily[k] = cur
    }
  }
  for (const v of Object.values(pooledRecallByFamily)) v.recall = v.targets > 0 ? v.confirmed / v.targets : 0

  const deltas = list.map((s) => s.deltaReasoning).filter((x): x is number => x != null)
  return {
    count: list.length,
    recall: stat(list.map((s) => s.recall)),
    precision: stat(list.map((s) => s.precision)),
    deltaReasoning: deltas.length > 0 ? stat(deltas) : undefined,
    pooledDecoyFpRate: totalDecoys > 0 ? totalDecoyFp / totalDecoys : 0,
    pooledRecallByClass,
    pooledRecallByFamily,
  }
}
