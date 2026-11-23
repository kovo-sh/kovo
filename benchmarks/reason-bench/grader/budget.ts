// Budget curve: confirmed count + recall at each USD threshold. Pure. See CONTRACTS.md "Grading".
import type { RunTelemetry, SubmittedFinding } from '../lib/types.ts'
import { budgetThresholdsUsd } from '../lib/types.ts'

/** Cost attributed to a finding: costUsdAtSubmit if present, else linear interpolation of
 *  telemetry.totalCostUsd over [startedAtMs, endedAtMs] by submittedAtMs. */
export function findingCostUsd(finding: SubmittedFinding, telemetry: RunTelemetry): number {
  if (typeof finding.costUsdAtSubmit === 'number') return finding.costUsdAtSubmit
  const span = telemetry.endedAtMs - telemetry.startedAtMs
  if (span <= 0) return telemetry.totalCostUsd
  let frac = (finding.submittedAtMs - telemetry.startedAtMs) / span
  if (frac < 0) frac = 0
  if (frac > 1) frac = 1
  return frac * telemetry.totalCostUsd
}

export interface BudgetPoint {
  usd: number
  confirmed: number
  recall: number
}

/** For each threshold, count confirmed findings whose cost <= usd; recall = that / targets. */
export function budgetCurve(
  confirmedFindings: SubmittedFinding[],
  telemetry: RunTelemetry,
  targets: number,
  thresholds: readonly number[] = budgetThresholdsUsd,
): BudgetPoint[] {
  const costs = confirmedFindings.map((f) => findingCostUsd(f, telemetry))
  return thresholds.map((usd) => {
    const confirmed = costs.filter((c) => c <= usd).length
    return { usd, confirmed, recall: targets > 0 ? confirmed / targets : 0 }
  })
}
