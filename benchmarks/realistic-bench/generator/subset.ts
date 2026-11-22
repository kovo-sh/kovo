// Decoy-unit grouping and subset-sum enumeration shared by validate.ts and variant.ts.
// Chain members are grouped into a single unit so they always share a mode.
import type { SiteSpec } from '../lib/types.ts'

export interface DecoyUnit {
  siteIds: string[]
  size: number
  decoyable: boolean // true only if every member allows being a decoy
}

/** Group sites into decoy units: one per chain (members together) + singletons for the rest. */
export function groupUnits(sites: readonly SiteSpec[]): DecoyUnit[] {
  const byChain = new Map<string, SiteSpec[]>()
  const units: DecoyUnit[] = []
  for (const s of sites) {
    if (s.chain) {
      const arr = byChain.get(s.chain.id) ?? []
      arr.push(s)
      byChain.set(s.chain.id, arr)
    } else {
      units.push({ siteIds: [s.id], size: 1, decoyable: s.canBeDecoy !== false })
    }
  }
  for (const [, arr] of byChain) {
    units.push({
      siteIds: arr.map((s) => s.id),
      size: arr.length,
      decoyable: arr.every((s) => s.canBeDecoy !== false),
    })
  }
  return units
}

/** Map every reachable subset-sum of `sizes` to one achieving index list (insertion-ordered). */
export function reachableSubsets(sizes: readonly number[]): Map<number, number[]> {
  const reach = new Map<number, number[]>()
  reach.set(0, [])
  for (let i = 0; i < sizes.length; i++) {
    for (const [sum, idxs] of [...reach.entries()]) {
      const next = sum + sizes[i]!
      if (!reach.has(next)) reach.set(next, [...idxs, i])
    }
  }
  return reach
}

/** Decoy-count targets achievable within [min,max] given the decoyable units' sizes. */
export function feasibleDecoyTargets(units: readonly DecoyUnit[], min: number, max: number): number[] {
  const sizes = units.filter((u) => u.decoyable).map((u) => u.size)
  const reach = reachableSubsets(sizes)
  return [...reach.keys()].filter((t) => t >= min && t <= max).sort((a, b) => a - b)
}
