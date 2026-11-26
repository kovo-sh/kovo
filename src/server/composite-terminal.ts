/**
 * Canonical terminal-exchange resolver for `CompositeProofReceipt` chains (`R2-11`).
 *
 * Shared by `src/server/composite-receipt.ts` (`deriveSignedTerminalOrigin`) and
 * `src/server/exec-verify.ts` (`inspectCompositeHostOrigin` / finding target derivation)
 * so both paths select the exact same host-signed terminal exchange when
 * `terminalImpact.terminalExchangeId` is present or omitted.
 */

export interface CompositeTerminalReceiptShape {
  hops: readonly {
    hopId: string
    exchangeIds: readonly string[]
  }[]
  terminalImpact?: {
    terminalHopId?: string
    terminalExchangeId?: string
  }
}

export interface CompositeTerminalExchangeCandidate {
  exchangeId: string
  origin?: string | null
  sessionRole?: string | null
  status?: number | null
  step?: {
    arm?: string | null
    status?: number | null
  }
}

function candidateArm(entry: CompositeTerminalExchangeCandidate): string | null {
  return entry.step?.arm ?? entry.sessionRole ?? null
}

function candidateStatus(entry: CompositeTerminalExchangeCandidate): number | null {
  if (typeof entry.step?.status === 'number') return entry.step.status
  if (typeof entry.status === 'number') return entry.status
  return null
}

function is2xxStatus(status: number | null): boolean {
  return status !== null && status >= 200 && status < 300
}

/**
 * Resolve the authoritative terminal exchange for a `CompositeProofReceipt` from host-recorded
 * transcript entries or exchange views using one deterministic precedence order:
 *   1. Explicit `terminalImpact.terminalExchangeId` (when present in the host index).
 *   2. Last cited exchange on the terminal hop with `probe` arm/role and 2xx HTTP status.
 *   3. Last cited exchange on the terminal hop with `probe` arm/role (any status).
 *   4. Last cited exchange on the terminal hop carrying a non-empty host-signed `origin`.
 *   5. Last cited exchange on the terminal hop (fallback when no entry carries an origin).
 */
export function resolveCompositeTerminalExchange<T extends CompositeTerminalExchangeCandidate>(
  receipt: CompositeTerminalReceiptShape,
  entries: readonly T[] | ReadonlyMap<string, T>,
): T | undefined {
  const byId: ReadonlyMap<string, T> = 'get' in entries
    ? entries
    : new Map(entries.map(entry => [entry.exchangeId, entry]))
  const explicitId = receipt.terminalImpact?.terminalExchangeId
  if (explicitId && byId.has(explicitId)) return byId.get(explicitId)
  const terminalHop = receipt.hops.find(hop => hop.hopId === receipt.terminalImpact?.terminalHopId)
    ?? receipt.hops[receipt.hops.length - 1]
  if (!terminalHop) return undefined
  const reversed = [...terminalHop.exchangeIds]
    .reverse()
    .map(id => byId.get(id))
    .filter((entry): entry is T => Boolean(entry))
  return (
    reversed.find(entry => candidateArm(entry) === 'probe' && is2xxStatus(candidateStatus(entry)))
    ?? reversed.find(entry => candidateArm(entry) === 'probe')
    ?? reversed.find(entry => Boolean(entry.origin?.trim()))
    ?? reversed[0]
  )
}
