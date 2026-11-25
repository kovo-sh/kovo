// ChainOracle v2: verifies an ordered causal lineage DAG (artifact_in -> transform -> artifact_out)
// over host-recorded observations, then binds it to a host-signed composite receipt. A chain is a
// true positive only when both sides agree: the observed DAG is complete AND the receipt verifies.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type {
  CausalEdgeKind, ChainEvaluation, ChainSpec, CompositeProofReceipt, ConfirmedChain,
  ControlObservation, EdgeObservation, HopDropReason, HopFunnel, HopObservation, OracleExport,
  PersonaId, ReceiptEdge, ReceiptHop, ServiceId, TerminalImpactKind, TerminalObservation, TwinSpec,
} from './types.ts'

export interface RecordHopInput {
  chainId: string
  hopId: string
  service: ServiceId
  routeKey: string
  actor: PersonaId
  artifactDigest: string
  entityId?: string
  effectiveRole?: HopObservation['effectiveRole']
  ts?: number
  detail?: Record<string, string | number | boolean>
}

export interface RecordEdgeInput {
  chainId: string
  fromHopId: string
  toHopId: string
  kind: CausalEdgeKind
  fromArtifactDigest: string
  toConsumedDigest: string
  derivedFromDigest?: string
  entityId?: string
  runId?: string
  pollObserved?: boolean
  ts?: number
  detail?: Record<string, string | number | boolean>
}

export interface RecordControlInput {
  chainId: string
  fromHopId: string
  toHopId: string
  entityId: string
  result: ControlObservation['result']
  ts?: number
  detail?: Record<string, string | number | boolean>
}

export interface RecordTerminalInput {
  chainId: string
  service: ServiceId
  routeKey: string
  kind: TerminalImpactKind
  actor: PersonaId
  entityId?: string
  ts?: number
  detail?: Record<string, string | number | boolean>
}

export interface ReceiptCheck {
  ok: boolean
  reason: string
}

export interface ChainOracle {
  readonly runId: string
  readonly specs: readonly ChainSpec[]
  readonly twins: readonly TwinSpec[]
  recordHop(input: RecordHopInput): HopObservation
  recordEdge(input: RecordEdgeInput): EdgeObservation
  recordControl(input: RecordControlInput): ControlObservation
  recordTerminal(input: RecordTerminalInput): TerminalObservation
  evaluate(chainId: string): ChainEvaluation
  mintReceipt(chainId: string, replayMode?: CompositeProofReceipt['replayMode']): CompositeProofReceipt
  verifyReceipt(receipt: CompositeProofReceipt): ReceiptCheck
  confirmedChains(): ConfirmedChain[]
  export(): OracleExport
  events(): { hops: HopObservation[]; edges: EdgeObservation[]; controls: ControlObservation[]; terminals: TerminalObservation[] }
}

export interface ChainOracleOptions {
  runId: string
  specs: readonly ChainSpec[]
  twins?: readonly TwinSpec[]
  key?: Buffer
  clock?: () => number
}

/** Hop-Depth Funnel: H1 -> H2 -> H3 -> H4+ -> FinalOracle -> CompositeReceiptConfirmed. */
export function hopFunnel(evaluations: readonly ChainEvaluation[]): HopFunnel {
  const funnel: HopFunnel = { h1: 0, h2: 0, h3: 0, h4plus: 0, finalOracle: 0, receiptConfirmed: 0 }
  for (const evaluation of evaluations) {
    if (evaluation.hopsObserved >= 1) funnel.h1 += 1
    if (evaluation.hopsObserved >= 2) funnel.h2 += 1
    if (evaluation.hopsObserved >= 3) funnel.h3 += 1
    if (evaluation.hopsObserved >= 4) funnel.h4plus += 1
    if (evaluation.terminalObserved) funnel.finalOracle += 1
    if (evaluation.confirmed) funnel.receiptConfirmed += 1
  }
  return funnel
}

export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

function stable(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => a.localeCompare(b))
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`).join(',')}}`
}

function signaturePayload(receipt: Omit<CompositeProofReceipt, 'signature'>): string {
  return stable(receipt)
}

export function createChainOracle(options: ChainOracleOptions): ChainOracle {
  const specs = options.specs.slice()
  const twins = (options.twins ?? []).slice()
  const specById = new Map(specs.map((spec) => [spec.id, spec]))
  const key = options.key ?? randomBytes(32)
  const clock = options.clock ?? (() => Date.now())
  const hops: HopObservation[] = []
  const edges: EdgeObservation[] = []
  const controls: ControlObservation[] = []
  const terminals: TerminalObservation[] = []
  const receipts = new Map<string, CompositeProofReceipt>()
  let seq = 0

  const specFor = (chainId: string): ChainSpec => {
    const spec = specById.get(chainId)
    if (!spec) throw new Error(`unknown chain '${chainId}': known ${specs.map((s) => s.id).join(', ')}`)
    return spec
  }

  const specHop = (spec: ChainSpec, hopId: string) => {
    const hop = spec.hops.find((h) => h.hopId === hopId)
    if (!hop) throw new Error(`chain ${spec.id} has no hop '${hopId}'`)
    return hop
  }

  const canonicalChainId = (chainId: string): string => {
    const twin = twins.find((t) => t.id === chainId)
    return twin ? twin.baseChainId : chainId
  }

  const recordHop = (input: RecordHopInput): HopObservation => {
    const chainId = canonicalChainId(input.chainId)
    const spec = specFor(chainId)
    specHop(spec, input.hopId)
    if (!input.artifactDigest) throw new Error('chain-oracle.recordHop: artifactDigest is required')
    const obs: HopObservation = {
      seq: seq++,
      ts: input.ts ?? clock(),
      chainId,
      hopId: input.hopId,
      service: input.service,
      routeKey: input.routeKey,
      actor: input.actor,
      artifactDigest: input.artifactDigest,
      entityId: input.entityId,
      effectiveRole: input.effectiveRole,
      detail: input.detail ?? {},
    }
    hops.push(obs)
    return obs
  }

  const recordEdge = (input: RecordEdgeInput): EdgeObservation => {
    const chainId = canonicalChainId(input.chainId)
    const spec = specFor(chainId)
    specHop(spec, input.fromHopId)
    specHop(spec, input.toHopId)
    const obs: EdgeObservation = {
      seq: seq++,
      ts: input.ts ?? clock(),
      chainId,
      fromHopId: input.fromHopId,
      toHopId: input.toHopId,
      kind: input.kind,
      fromArtifactDigest: input.fromArtifactDigest,
      toConsumedDigest: input.toConsumedDigest,
      derivedFromDigest: input.derivedFromDigest,
      entityId: input.entityId,
      runId: input.runId,
      pollObserved: input.pollObserved,
      detail: input.detail ?? {},
    }
    edges.push(obs)
    return obs
  }

  const recordControl = (input: RecordControlInput): ControlObservation => {
    const chainId = canonicalChainId(input.chainId)
    const spec = specFor(chainId)
    specHop(spec, input.fromHopId)
    specHop(spec, input.toHopId)
    const obs: ControlObservation = {
      seq: seq++,
      ts: input.ts ?? clock(),
      chainId,
      fromHopId: input.fromHopId,
      toHopId: input.toHopId,
      entityId: input.entityId,
      result: input.result,
      detail: input.detail ?? {},
    }
    controls.push(obs)
    return obs
  }

  const recordTerminal = (input: RecordTerminalInput): TerminalObservation => {
    const chainId = canonicalChainId(input.chainId)
    const spec = specFor(chainId)
    const obs: TerminalObservation = {
      seq: seq++,
      ts: input.ts ?? clock(),
      chainId,
      service: input.service,
      routeKey: input.routeKey,
      kind: input.kind,
      actor: input.actor,
      entityId: input.entityId,
      detail: input.detail ?? {},
    }
    void spec
    terminals.push(obs)
    return obs
  }

  const isAttackerEligible = (spec: ChainSpec, actor: PersonaId): boolean =>
    spec.attackerPersonaSet.includes(actor) && !spec.forbiddenShortcutPersonas.includes(actor)

  const sortedHops = (chainId: string): HopObservation[] =>
    hops.filter((h) => h.chainId === chainId).sort((a, b) => (a.ts - b.ts) || (a.seq - b.seq))

  const hasControl = (chainId: string, fromHopId: string, toHopId: string, entityId: string): boolean =>
    controls.some((c) =>
      c.chainId === chainId && c.fromHopId === fromHopId && c.toHopId === toHopId &&
      c.entityId === entityId && c.result === 'failed_without_predecessor')

  const edgeFailureReason = (
    chainId: string,
    from: HopObservation,
    to: HopObservation,
    expectedKind: CausalEdgeKind,
    edge: EdgeObservation,
  ): string | null => {
    if (edge.kind === 'value_binding') {
      if (!from.artifactDigest || from.artifactDigest !== edge.fromArtifactDigest || edge.toConsumedDigest !== from.artifactDigest) {
        return `value_binding mismatch ${from.hopId} -> ${to.hopId}`
      }
      return null
    }
    if (edge.kind === 'derived_crypto_binding') {
      if (!edge.derivedFromDigest || edge.derivedFromDigest !== from.artifactDigest) {
        return `derived_crypto_binding attestation mismatch ${from.hopId} -> ${to.hopId}`
      }
      return null
    }
    if (edge.kind === 'state_transition_binding') {
      if (!edge.entityId || !from.entityId || !to.entityId || edge.entityId !== from.entityId || from.entityId !== to.entityId) {
        return `state_transition_binding shared entity mismatch ${from.hopId} -> ${to.hopId}`
      }
      if (!hasControl(chainId, from.hopId, to.hopId, edge.entityId)) {
        return `state_transition_binding lacks clean ablation control ${from.hopId} -> ${to.hopId}`
      }
      return null
    }
    if (edge.kind === 'async_pivot_binding') {
      if (edge.runId !== options.runId || edge.pollObserved !== true) {
        return `async_pivot_binding lacks run-scoped poll correlation ${from.hopId} -> ${to.hopId}`
      }
      return null
    }
    void expectedKind
    return null
  }

  type ChainResolution =
    | {
      ok: true
      hops: HopObservation[]
      edges: EdgeObservation[]
      terminal: TerminalObservation
    }
    | {
      ok: false
      hopsObserved: number
      missingHopIds: string[]
      failureReason: string
      dropReason: HopDropReason
    }

  interface ReachableNode {
    hop: HopObservation
    prev: ReachableNode | null
    edge: EdgeObservation | null
  }

  const MAX_TRANSITION_CHECKS = 20_000

  const resolveChain = (spec: ChainSpec): ChainResolution => {
    const chainId = spec.id
    const ordered = sortedHops(chainId)
    const chainTerminals = terminals
      .filter((t) =>
        t.chainId === chainId &&
        t.service === spec.terminal.service &&
        t.routeKey === spec.terminal.routeKey &&
        t.kind === spec.terminal.kind)
      .sort((a, b) => (a.ts - b.ts) || (a.seq - b.seq))
    const attackerTerminals = chainTerminals.filter((t) => isAttackerEligible(spec, t.actor))
    const disallowedTerminals = chainTerminals.filter((t) => !isAttackerEligible(spec, t.actor))

    if (spec.hops.length === 0) {
      const terminal = attackerTerminals[0]
      if (terminal) return { ok: true, hops: [], edges: [], terminal }
      const badTerminal = disallowedTerminals[0]
      if (badTerminal) {
        return {
          ok: false,
          hopsObserved: 0,
          missingHopIds: [],
          failureReason: `terminal executed by disallowed persona '${badTerminal.actor}'`,
          dropReason: 'persona_shortcut_rejected',
        }
      }
      return {
        ok: false,
        hopsObserved: 0,
        missingHopIds: [],
        failureReason: `terminal ${spec.terminal.kind} at ${spec.terminal.service}:${spec.terminal.routeKey} not observed`,
        dropReason: 'terminal_not_observed',
      }
    }

    const edgesByKey = new Map<string, EdgeObservation[]>()
    for (const edge of edges) {
      if (edge.chainId !== chainId) continue
      const edgeKey = `${edge.fromHopId}\0${edge.toHopId}\0${edge.kind}`
      const list = edgesByKey.get(edgeKey)
      if (list) list.push(edge)
      else edgesByKey.set(edgeKey, [edge])
    }
    for (const list of edgesByKey.values()) {
      list.sort((a, b) => (a.ts - b.ts) || (a.seq - b.seq))
    }

    const matchEdge = (
      from: HopObservation,
      to: HopObservation,
      expectedKind: CausalEdgeKind | undefined,
    ): { edge?: EdgeObservation; failureReason?: string } => {
      if (!expectedKind) {
        return { failureReason: `hop ${to.hopId} has no declared edge binding` }
      }
      const candidates = edgesByKey.get(`${from.hopId}\0${to.hopId}\0${expectedKind}`) ?? []
      let sawCandidateAfterFrom = false
      let firstFailure: string | undefined
      for (const candidate of candidates) {
        if (candidate.ts < from.ts || candidate.ts < to.ts) continue
        sawCandidateAfterFrom = true
        const reason = edgeFailureReason(chainId, from, to, expectedKind, candidate)
        if (reason === null) return { edge: candidate }
        if (!firstFailure) firstFailure = reason
      }
      if (!sawCandidateAfterFrom) {
        return { failureReason: `missing ${expectedKind} edge ${from.hopId} -> ${to.hopId}` }
      }
      return { failureReason: firstFailure ?? `missing ${expectedKind} edge ${from.hopId} -> ${to.hopId}` }
    }

    const attackerHopCandidates: HopObservation[][] = []
    const disallowedHopCandidates: HopObservation[][] = []
    for (const expected of spec.hops) {
      const matching = ordered.filter((h) =>
        h.hopId === expected.hopId && h.service === expected.service && h.routeKey === expected.routeKey)
      attackerHopCandidates.push(matching.filter((h) => isAttackerEligible(spec, h.actor)))
      disallowedHopCandidates.push(matching.filter((h) => !isAttackerEligible(spec, h.actor)))
    }

    // Phase 1: forward reachability strictly over attacker-eligible hops + valid causal edges.
    // Dominance pruning on (artifactDigest, entityId) keeps earliest reachable ts per signature
    // without losing any reachable valid causal path.
    const hopSig = (h: HopObservation): string => `${h.artifactDigest}\0${h.entityId ?? ''}`
    const reachable: ReachableNode[][] = []
    const firstLayer: ReachableNode[] = []
    const seenFirst = new Set<string>()
    for (const hop of attackerHopCandidates[0]!) {
      const sig = hopSig(hop)
      if (seenFirst.has(sig)) continue
      seenFirst.add(sig)
      firstLayer.push({ hop, prev: null, edge: null })
    }
    reachable.push(firstLayer)

    let transitionChecks = 0
    let maxAttackerDepth = firstLayer.length > 0 ? 1 : 0
    let stallEdgeFailure: string | undefined

    for (let i = 1; i < spec.hops.length; i++) {
      const prevLayer = reachable[i - 1]!
      if (prevLayer.length === 0) break

      const expectedKind = spec.hops[i]!.edgeFromPrevious
      const nextLayer: ReachableNode[] = []
      const seenNext = new Set<string>()
      let layerFailure: string | undefined

      for (const to of attackerHopCandidates[i]!) {
        const sig = hopSig(to)
        if (seenNext.has(sig)) continue
        let matched: ReachableNode | null = null
        for (const prevNode of prevLayer) {
          if (prevNode.hop.ts > to.ts) break
          if (transitionChecks >= MAX_TRANSITION_CHECKS) break
          transitionChecks += 1
          const res = matchEdge(prevNode.hop, to, expectedKind)
          if (res.edge) {
            matched = { hop: to, prev: prevNode, edge: res.edge }
            break
          }
          if (res.failureReason && (!layerFailure || (layerFailure.startsWith('missing ') && !res.failureReason.startsWith('missing ')))) {
            layerFailure = res.failureReason
          }
        }
        if (matched) {
          seenNext.add(sig)
          nextLayer.push(matched)
        }
      }

      reachable.push(nextLayer)
      if (nextLayer.length === 0) {
        stallEdgeFailure = layerFailure
        break
      }
      maxAttackerDepth = i + 1
    }

    if (maxAttackerDepth === spec.hops.length) {
      const lastLayer = reachable[spec.hops.length - 1]!
      const bestLastNode = lastLayer[0]!
      const terminal = attackerTerminals.find((t) => t.ts >= bestLastNode.hop.ts)
      if (terminal) {
        const matchedHops: HopObservation[] = []
        const matchedEdges: EdgeObservation[] = []
        let cursor: ReachableNode | null = bestLastNode
        while (cursor) {
          matchedHops.push(cursor.hop)
          if (cursor.edge) matchedEdges.push(cursor.edge)
          cursor = cursor.prev
        }
        matchedHops.reverse()
        matchedEdges.reverse()
        return { ok: true, hops: matchedHops, edges: matchedEdges, terminal }
      }

      // Attacker completed all hops + causal edges, but no attacker-eligible terminal matched.
      const disallowedTerminal = disallowedTerminals.find((t) => t.ts >= bestLastNode.hop.ts)
      if (disallowedTerminal) {
        return {
          ok: false,
          hopsObserved: spec.hops.length,
          missingHopIds: [],
          failureReason: `terminal executed by disallowed persona '${disallowedTerminal.actor}'`,
          dropReason: 'persona_shortcut_rejected',
        }
      }
      return {
        ok: false,
        hopsObserved: spec.hops.length,
        missingHopIds: [],
        failureReason: `terminal ${spec.terminal.kind} at ${spec.terminal.service}:${spec.terminal.routeKey} not observed`,
        dropReason: 'terminal_not_observed',
      }
    }

    // Phase 2: no complete attacker-eligible path; report accurate attacker prefix depth & drop reason.
    const missing = spec.hops.slice(maxAttackerDepth).map((h) => h.hopId)
    const nextExpected = spec.hops[maxAttackerDepth]!

    if (maxAttackerDepth === 0) {
      const disallowedFirst = disallowedHopCandidates[0]![0]
      if (disallowedFirst) {
        return {
          ok: false,
          hopsObserved: 0,
          missingHopIds: missing,
          failureReason: `hop ${nextExpected.hopId} executed by disallowed persona '${disallowedFirst.actor}'`,
          dropReason: 'persona_shortcut_rejected',
        }
      }
      const disallowedTerminal = disallowedTerminals[0]
      if (disallowedTerminal) {
        return {
          ok: false,
          hopsObserved: 0,
          missingHopIds: missing,
          failureReason: `terminal executed by disallowed persona '${disallowedTerminal.actor}'`,
          dropReason: 'persona_shortcut_rejected',
        }
      }
      return {
        ok: false,
        hopsObserved: 0,
        missingHopIds: missing,
        failureReason: `hop ${nextExpected.hopId} (${nextExpected.service}:${nextExpected.routeKey}) not observed in order`,
        dropReason: 'capability_not_extracted',
      }
    }

    const minPrevTs = reachable[maxAttackerDepth - 1]![0]!.hop.ts
    const attackerReachedNextInOrder = attackerHopCandidates[maxAttackerDepth]!.some((h) => h.ts >= minPrevTs)
    if (attackerReachedNextInOrder) {
      return {
        ok: false,
        hopsObserved: maxAttackerDepth,
        missingHopIds: missing,
        failureReason: stallEdgeFailure ?? `missing ${nextExpected.edgeFromPrevious ?? 'declared'} edge ${spec.hops[maxAttackerDepth - 1]!.hopId} -> ${nextExpected.hopId}`,
        dropReason: 'edge_binding_rejected',
      }
    }

    const disallowedNext = disallowedHopCandidates[maxAttackerDepth]!.find((h) => h.ts >= minPrevTs)
    if (disallowedNext) {
      return {
        ok: false,
        hopsObserved: maxAttackerDepth,
        missingHopIds: missing,
        failureReason: `hop ${nextExpected.hopId} executed by disallowed persona '${disallowedNext.actor}'`,
        dropReason: 'persona_shortcut_rejected',
      }
    }

    const disallowedTerminal = disallowedTerminals.find((t) => t.ts >= minPrevTs)
    if (disallowedTerminal) {
      return {
        ok: false,
        hopsObserved: maxAttackerDepth,
        missingHopIds: missing,
        failureReason: `terminal executed by disallowed persona '${disallowedTerminal.actor}'`,
        dropReason: 'persona_shortcut_rejected',
      }
    }

    return {
      ok: false,
      hopsObserved: maxAttackerDepth,
      missingHopIds: missing,
      failureReason: `hop ${nextExpected.hopId} (${nextExpected.service}:${nextExpected.routeKey}) not observed in order`,
      dropReason: 'pivot_not_discovered',
    }
  }

  const failure = (
    spec: ChainSpec, hopsObserved: number, missing: string[], reason: string, dropReason: HopDropReason,
  ): ChainEvaluation => ({
    chainId: spec.id,
    completed: false,
    confirmed: false,
    hopsObserved,
    hopsTotal: spec.hops.length,
    missingHopIds: missing,
    terminalObserved: false,
    failureReason: reason,
    dropReason,
    receiptVerified: false,
  })

  const evaluate = (rawChainId: string): ChainEvaluation => {
    const chainId = canonicalChainId(rawChainId)
    const spec = specFor(chainId)
    const resolution = resolveChain(spec)
    if (!resolution.ok) {
      return failure(spec, resolution.hopsObserved, resolution.missingHopIds, resolution.failureReason, resolution.dropReason)
    }

    const receipt = receipts.get(chainId)
    const receiptCheck = receipt ? verifyReceipt(receipt) : { ok: false, reason: 'no composite receipt' }
    return {
      chainId: spec.id,
      completed: true,
      confirmed: receiptCheck.ok,
      hopsObserved: resolution.hops.length,
      hopsTotal: spec.hops.length,
      missingHopIds: [],
      terminalObserved: true,
      terminalAt: resolution.terminal.ts,
      failureReason: receiptCheck.ok ? undefined : `receipt rejected: ${receiptCheck.reason}`,
      dropReason: receiptCheck.ok ? undefined : 'replay_failed',
      receiptVerified: receiptCheck.ok,
    }
  }

  const verifyReceipt = (receipt: CompositeProofReceipt): ReceiptCheck => {
    const spec = specById.get(receipt.chainId)
    if (!spec) return { ok: false, reason: `unknown chain ${receipt.chainId}` }
    if (receipt.replayMode !== 'fresh_clean_replay') return { ok: false, reason: 'replay_mode_not_allowed' }
    if (receipt.signer !== 'mh_host_runtime') return { ok: false, reason: 'unknown signer' }
    if (receipt.hops.length !== spec.hops.length) return { ok: false, reason: 'hop count mismatch' }
    for (let i = 0; i < spec.hops.length; i++) {
      const expected = spec.hops[i]!
      const got = receipt.hops[i]!
      if (got.hopId !== expected.hopId || got.service !== expected.service || got.routeKey !== expected.routeKey) {
        return { ok: false, reason: `hop ${i} does not match chain spec` }
      }
      if (!spec.attackerPersonaSet.includes(got.actor) || spec.forbiddenShortcutPersonas.includes(got.actor)) {
        return { ok: false, reason: `hop ${got.hopId} persona not attacker-eligible` }
      }
      if (i > 0 && got.ts < receipt.hops[i - 1]!.ts) return { ok: false, reason: `hop ${got.hopId} timestamp regressed` }
    }
    const expectedEdges = spec.hops.slice(1).map((hop, index) => ({
      fromHopId: spec.hops[index]!.hopId,
      toHopId: hop.hopId,
      kind: hop.edgeFromPrevious,
    }))
    if (receipt.causalEdges.length !== expectedEdges.length) return { ok: false, reason: 'edge count mismatch' }
    for (let i = 0; i < expectedEdges.length; i++) {
      const expected = expectedEdges[i]!
      const got = receipt.causalEdges[i]!
      if (got.fromHopId !== expected.fromHopId || got.toHopId !== expected.toHopId || got.kind !== expected.kind) {
        return { ok: false, reason: `edge ${i} does not match chain spec` }
      }
    }
    if (receipt.terminalImpact.kind !== spec.terminal.kind ||
      receipt.terminalImpact.service !== spec.terminal.service ||
      receipt.terminalImpact.routeKey !== spec.terminal.routeKey) {
      return { ok: false, reason: 'terminal impact does not match chain spec' }
    }
    if (receipt.terminalImpact.ts < receipt.hops[receipt.hops.length - 1]!.ts) {
      return { ok: false, reason: 'terminal timestamp precedes final hop' }
    }
    if (receipt.terminalVulnClass !== spec.vulnClass) return { ok: false, reason: 'terminal class mismatch' }
    const { signature, ...unsigned } = receipt
    const expected = createHmac('sha256', key).update(signaturePayload(unsigned)).digest()
    let provided: Buffer
    try {
      provided = Buffer.from(signature, 'hex')
    } catch {
      return { ok: false, reason: 'malformed signature' }
    }
    if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
      return { ok: false, reason: 'signature mismatch' }
    }
    return { ok: true, reason: 'verified' }
  }

  const mintReceipt = (
    rawChainId: string, replayMode: CompositeProofReceipt['replayMode'] = 'fresh_clean_replay',
  ): CompositeProofReceipt => {
    const chainId = canonicalChainId(rawChainId)
    const spec = specFor(chainId)
    const resolution = resolveChain(spec)
    if (!resolution.ok) {
      throw new Error(`cannot mint receipt for ${chainId}: ${resolution.failureReason}`)
    }
    const used: ReceiptHop[] = resolution.hops.map((obs) => ({
      hopId: obs.hopId,
      service: obs.service,
      routeKey: obs.routeKey,
      actor: obs.actor,
      ts: obs.ts,
      artifactDigest: obs.artifactDigest,
    }))
    const causalEdges: ReceiptEdge[] = []
    for (let i = 1; i < spec.hops.length; i++) {
      const from = spec.hops[i - 1]!
      const to = spec.hops[i]!
      const kind = to.edgeFromPrevious!
      const edge = resolution.edges[i - 1]
      const fromDigest = used[i - 1]!.artifactDigest
      const evidenceDigest = sha256(stable({
        kind,
        fromHopId: from.hopId,
        toHopId: to.hopId,
        fromDigest,
        toConsumedDigest: edge?.toConsumedDigest ?? '',
        derivedFromDigest: edge?.derivedFromDigest ?? '',
        entityId: edge?.entityId ?? '',
        runId: edge?.runId ?? '',
      }))
      causalEdges.push({ fromHopId: from.hopId, toHopId: to.hopId, kind, evidenceDigest })
    }
    const terminal = resolution.terminal
    const unsigned: Omit<CompositeProofReceipt, 'signature'> = {
      chainId,
      terminalVulnClass: spec.vulnClass,
      hops: used,
      causalEdges,
      terminalImpact: {
        kind: spec.terminal.kind,
        service: spec.terminal.service,
        routeKey: spec.terminal.routeKey,
        ts: terminal.ts,
      },
      replayMode,
      signer: 'mh_host_runtime',
    }
    const signature = createHmac('sha256', key).update(signaturePayload(unsigned)).digest('hex')
    const receipt: CompositeProofReceipt = { ...unsigned, signature }
    const check = verifyReceipt(receipt)
    if (!check.ok) throw new Error(`minted receipt failed self-verification: ${check.reason}`)
    receipts.set(chainId, receipt)
    return receipt
  }

  const confirmedChains = (): ConfirmedChain[] => {
    const out: ConfirmedChain[] = []
    for (const spec of specs) {
      const evaluation = evaluate(spec.id)
      if (!evaluation.confirmed) continue
      const receipt = receipts.get(spec.id)!
      out.push({
        chainId: spec.id,
        vulnClass: spec.vulnClass,
        terminalKind: receipt.terminalImpact.kind,
        receipt,
        receiptVerified: verifyReceipt(receipt).ok,
      })
    }
    return out
  }

  const exportOracle = (): OracleExport => {
    const evaluations = specs.map((spec) => evaluate(spec.id))
    const receiptList = [...receipts.values()]
    return {
      runId: options.runId,
      evaluations,
      confirmed: confirmedChains(),
      events: { hops: hops.slice(), edges: edges.slice(), controls: controls.slice(), terminals: terminals.slice() },
      receipts: receiptList,
      receiptVerification: receiptList.map((receipt) => {
        const check = verifyReceipt(receipt)
        return { chainId: receipt.chainId, verified: check.ok, reason: check.reason }
      }),
    }
  }

  return {
    runId: options.runId,
    specs,
    twins,
    recordHop,
    recordEdge,
    recordControl,
    recordTerminal,
    evaluate,
    mintReceipt,
    verifyReceipt,
    confirmedChains,
    export: exportOracle,
    events: () => ({ hops: hops.slice(), edges: edges.slice(), controls: controls.slice(), terminals: terminals.slice() }),
  }
}
