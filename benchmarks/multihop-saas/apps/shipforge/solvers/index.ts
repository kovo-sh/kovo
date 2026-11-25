// Deterministic reference solver registry. Each solver returns a host-signed composite receipt
// only when the causal lineage verifier observed the full ordered chain.
import type { CompositeProofReceipt, Finding } from '../../../lib/types.ts'
import type { StartedShipforge } from '../index.ts'
import { createSolverContext } from './context.ts'
import type { SolverContext } from './context.ts'
import { solveC1 } from './c1.ts'
import { solveC2 } from './c2.ts'
import { solveC3 } from './c3.ts'
import { solveC4 } from './c4.ts'

const SOLVERS: Record<string, (ctx: SolverContext) => Promise<CompositeProofReceipt | null>> = {
  'SF-C1': solveC1,
  'SF-C2': solveC2,
  'SF-C3': solveC3,
  'SF-C4': solveC4,
}

export async function runReferenceSolvers(
  lab: StartedShipforge, chainIds?: readonly string[],
): Promise<Finding[]> {
  const ctx = createSolverContext(lab)
  const findings: Finding[] = []
  for (const [chainId, solve] of Object.entries(SOLVERS)) {
    if (chainIds && !chainIds.includes(chainId)) continue
    const receipt = await solve(ctx)
    if (!receipt) continue
    findings.push({
      chainId,
      terminalVulnClass: receipt.terminalVulnClass,
      hopIds: receipt.hops.map((hop) => hop.hopId),
      receipt,
      reportedBy: 'reference-solver',
    })
  }
  return findings
}

export { createSolverContext }
