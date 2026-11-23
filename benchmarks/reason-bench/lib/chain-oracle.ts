// Causal-chain oracle: proves that a multi-hop exploit actually happened in order, with every hop
// tied to the same causal artifact (an opaque id/token produced by hop 1 and reused later). Pure;
// the grader feeds it the same OracleEvent stream the app emitted, so no FLAG strings are needed.
import type { CausalChainSpec, OracleEvent, ReasonOracleEventKind } from './types.ts'

export interface ChainHopEvent {
  seq: number
  ts: number
  hopId: string // matched hop, or '@final' / '@event' for unmapped observations
  routeKey: string
  kind: ReasonOracleEventKind
  actor: string
  artifact: string
  detail: Record<string, string | number | boolean>
}

export interface ChainCompletion {
  chainId: string
  completed: boolean
  hopsObserved: number
  hopsTotal: number
  missingHopIds: string[]
  completedHopIds: string[]
  finalObserved: boolean
  artifact?: string
  reason: string
}

export interface ChainRecordInput {
  hopId?: string
  routeKey: string
  kind: ReasonOracleEventKind
  actor?: string
  artifact: string
  ts?: number
  detail?: Record<string, string | number | boolean>
}

export interface ChainOracle {
  record(input: ChainRecordInput): ChainHopEvent
  /** Map one generic OracleEvent onto any chain hop it matches. Returns hops recorded (0..n). */
  recordOracleEvent(event: OracleEvent, chains: readonly CausalChainSpec[]): number
  completed(spec: CausalChainSpec): ChainCompletion
  completions(specs: readonly CausalChainSpec[]): ChainCompletion[]
  events(): ChainHopEvent[]
  reset(): void
}

const ARTIFACT_KEYS = ['artifact', 'causalArtifact', 'chainArtifact', 'correlationId', 'artifactId'] as const

/** Extract the causal artifact carried in an OracleEvent's detail bag (empty when absent). */
export function causalArtifactOf(detail: Record<string, string | number | boolean> | undefined): string {
  if (!detail) return ''
  for (const key of ARTIFACT_KEYS) {
    const v = detail[key]
    if (typeof v === 'string' && v.length > 0) return v
    if (typeof v === 'number' && Number.isFinite(v)) return String(v)
  }
  return ''
}

function better(a: ChainCompletion, b: ChainCompletion): ChainCompletion {
  if (a.completed !== b.completed) return a.completed ? a : b
  if (a.hopsObserved !== b.hopsObserved) return a.hopsObserved > b.hopsObserved ? a : b
  return a.finalObserved && !b.finalObserved ? a : b
}

/**
 * Evaluate a spec against the events recorded for one artifact. Hops must appear in spec order
 * (monotonic ts, insertion order breaks ties) with all `requiresPrior` hopIds already satisfied;
 * the final impact must follow the last hop and share the same artifact.
 */
function evaluate(spec: CausalChainSpec, events: readonly ChainHopEvent[], artifact: string): ChainCompletion {
  const ordered = events
    .filter((e) => e.artifact === artifact)
    .sort((x, y) => (x.ts - y.ts) || (x.seq - y.seq))
  const used = new Set<number>()
  const completedHopIds: string[] = []
  const satisfied = new Set<string>()
  let last: ChainHopEvent | undefined

  for (const hop of spec.hops) {
    const missingPrior = (hop.requiresPrior ?? []).filter((id) => !satisfied.has(id))
    if (missingPrior.length > 0) {
      return {
        chainId: spec.id, completed: false, hopsObserved: completedHopIds.length,
        hopsTotal: spec.hops.length, missingHopIds: spec.hops.map((h) => h.hopId).filter((id) => !satisfied.has(id)),
        completedHopIds, finalObserved: false, artifact,
        reason: `hop ${hop.hopId} requires prior ${missingPrior.join(',')}`,
      }
    }
    const found = ordered.find((e) => {
      if (used.has(e.seq)) return false
      if (e.kind !== hop.kind || e.routeKey !== hop.routeKey) return false
      if (!last) return true
      return e.ts > last.ts || (e.ts === last.ts && e.seq > last.seq)
    })
    if (!found) {
      return {
        chainId: spec.id, completed: false, hopsObserved: completedHopIds.length,
        hopsTotal: spec.hops.length, missingHopIds: spec.hops.map((h) => h.hopId).filter((id) => !satisfied.has(id)),
        completedHopIds, finalObserved: false, artifact,
        reason: `hop ${hop.hopId} (${hop.kind}@${hop.routeKey}) not observed in order`,
      }
    }
    used.add(found.seq)
    completedHopIds.push(hop.hopId)
    satisfied.add(hop.hopId)
    last = found
  }

  const finalEvent = ordered.find((e) => {
    if (used.has(e.seq)) return false
    if (e.kind !== spec.finalImpactKind || e.routeKey !== spec.finalRouteKey) return false
    return !last || e.ts > last.ts || (e.ts === last.ts && e.seq > last.seq)
  })
  return {
    chainId: spec.id,
    completed: !!finalEvent,
    hopsObserved: completedHopIds.length,
    hopsTotal: spec.hops.length,
    missingHopIds: [],
    completedHopIds,
    finalObserved: !!finalEvent,
    artifact,
    reason: finalEvent
      ? `completed via artifact ${artifact}`
      : `final impact ${spec.finalImpactKind}@${spec.finalRouteKey} not observed after hop ${last?.hopId ?? '-'}`,
  }
}

export function createChainOracle(): ChainOracle {
  const events: ChainHopEvent[] = []
  let seq = 0

  const record: ChainOracle['record'] = (input) => {
    if (!input.artifact) throw new Error('chain-oracle.record: artifact is required')
    const ev: ChainHopEvent = {
      seq: seq++,
      ts: input.ts ?? Date.now(),
      hopId: input.hopId ?? '@event',
      routeKey: input.routeKey,
      kind: input.kind,
      actor: input.actor ?? 'unknown',
      artifact: input.artifact,
      detail: input.detail ?? {},
    }
    events.push(ev)
    return ev
  }

  const completed: ChainOracle['completed'] = (spec) => {
    const artifacts = [...new Set(events.map((e) => e.artifact))]
    let best: ChainCompletion | undefined
    for (const artifact of artifacts) {
      const c = evaluate(spec, events, artifact)
      if (c.completed) return c
      best = best ? better(best, c) : c
    }
    return best ?? {
      chainId: spec.id, completed: false, hopsObserved: 0, hopsTotal: spec.hops.length,
      missingHopIds: spec.hops.map((h) => h.hopId), completedHopIds: [], finalObserved: false,
      reason: 'no causal artifacts observed',
    }
  }

  return {
    record,
    recordOracleEvent(event, chains) {
      const artifact = causalArtifactOf(event.detail)
      if (!artifact || event.routeKey == null) return 0
      let recorded = 0
      for (const chain of chains) {
        for (const hop of chain.hops) {
          if (hop.kind === event.kind && hop.routeKey === event.routeKey) {
            record({
              hopId: hop.hopId, routeKey: hop.routeKey, kind: hop.kind,
              actor: event.actor, artifact, ts: event.ts, detail: { ...event.detail, chainId: chain.id },
            })
            recorded++
          }
        }
      }
      if (recorded === 0) {
        const isFinal = chains.some((c) => c.finalImpactKind === event.kind && c.finalRouteKey === event.routeKey)
        record({
          hopId: isFinal ? '@final' : '@event', routeKey: event.routeKey, kind: event.kind,
          actor: event.actor, artifact, ts: event.ts, detail: event.detail,
        })
      }
      return recorded
    },
    completed,
    completions(specs) {
      return specs.map(completed)
    },
    events: () => events.slice(),
    reset() {
      events.length = 0
      seq = 0
    },
  }
}
