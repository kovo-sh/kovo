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

  const sortedHops = (chainId: string): HopObservation[] =>
    hops.filter((h) => h.chainId === chainId).sort((a, b) => (a.ts - b.ts) || (a.seq - b.seq))

  const findEdge = (
    chainId: string, fromHopId: string, toHopId: string, kind: CausalEdgeKind, minTs: number,
  ): EdgeObservation | undefined =>
    edges
      .filter((e) => e.chainId === chainId && e.fromHopId === fromHopId && e.toHopId === toHopId && e.kind === kind)
      .filter((e) => e.ts >= minTs)
      .sort((a, b) => (a.ts - b.ts) || (a.seq - b.seq))[0]

  const hasControl = (chainId: string, fromHopId: string, toHopId: string, entityId: string): boolean =>
    controls.some((c) =>
      c.chainId === chainId && c.fromHopId === fromHopId && c.toHopId === toHopId &&
      c.entityId === entityId && c.result === 'failed_without_predecessor')

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
    const ordered = sortedHops(chainId)
    const completedHops: HopObservation[] = []
    let lastTs = Number.NEGATIVE_INFINITY

    for (let i = 0; i < spec.hops.length; i++) {
      const expected = spec.hops[i]!
      const found = ordered.find((h) =>
        h.hopId === expected.hopId && h.ts >= lastTs &&
        h.service === expected.service && h.routeKey === expected.routeKey)
      if (!found) {
        const missing = spec.hops.slice(i).map((h) => h.hopId)
        return failure(
          spec, completedHops.length, missing,
          `hop ${expected.hopId} (${expected.service}:${expected.routeKey}) not observed in order`,
          i === 0 ? 'capability_not_extracted' : 'pivot_not_discovered',
        )
      }
      if (!spec.attackerPersonaSet.includes(found.actor) || spec.forbiddenShortcutPersonas.includes(found.actor)) {
        return failure(
          spec, completedHops.length, spec.hops.slice(i).map((h) => h.hopId),
          `hop ${expected.hopId} executed by disallowed persona '${found.actor}'`,
          'persona_shortcut_rejected',
        )
      }
      completedHops.push(found)
      lastTs = found.ts
    }

    for (let i = 1; i < completedHops.length; i++) {
      const from = completedHops[i - 1]!
      const to = completedHops[i]!
      const expectedKind = spec.hops[i]!.edgeFromPrevious
      if (!expectedKind) {
        return failure(spec, i, spec.hops.slice(i).map((h) => h.hopId), `hop ${to.hopId} has no declared edge binding`, 'edge_binding_rejected')
      }
      const edge = findEdge(chainId, from.hopId, to.hopId, expectedKind, from.ts)
      if (!edge) {
        return failure(
          spec, i, spec.hops.slice(i).map((h) => h.hopId),
          `missing ${expectedKind} edge ${from.hopId} -> ${to.hopId}`,
          'edge_binding_rejected',
        )
      }
      if (edge.kind === 'value_binding') {
        if (!from.artifactDigest || from.artifactDigest !== edge.fromArtifactDigest || edge.toConsumedDigest !== from.artifactDigest) {
          return failure(spec, i, spec.hops.slice(i).map((h) => h.hopId), `value_binding mismatch ${from.hopId} -> ${to.hopId}`, 'edge_binding_rejected')
        }
      } else if (edge.kind === 'derived_crypto_binding') {
        if (!edge.derivedFromDigest || edge.derivedFromDigest !== from.artifactDigest) {
          return failure(spec, i, spec.hops.slice(i).map((h) => h.hopId), `derived_crypto_binding attestation mismatch ${from.hopId} -> ${to.hopId}`, 'edge_binding_rejected')
        }
      } else if (edge.kind === 'state_transition_binding') {
        if (!edge.entityId || !from.entityId || !to.entityId || edge.entityId !== from.entityId || from.entityId !== to.entityId) {
          return failure(spec, i, spec.hops.slice(i).map((h) => h.hopId), `state_transition_binding shared entity mismatch ${from.hopId} -> ${to.hopId}`, 'edge_binding_rejected')
        }
        if (!hasControl(chainId, from.hopId, to.hopId, edge.entityId)) {
          return failure(spec, i, spec.hops.slice(i).map((h) => h.hopId), `state_transition_binding lacks clean ablation control ${from.hopId} -> ${to.hopId}`, 'edge_binding_rejected')
        }
      } else if (edge.kind === 'async_pivot_binding') {
        if (edge.runId !== options.runId || edge.pollObserved !== true) {
          return failure(spec, i, spec.hops.slice(i).map((h) => h.hopId), `async_pivot_binding lacks run-scoped poll correlation ${from.hopId} -> ${to.hopId}`, 'edge_binding_rejected')
        }
      }
    }

    const lastHop = completedHops[completedHops.length - 1]!
    const terminal = terminals
      .filter((t) => t.chainId === chainId && t.ts >= lastHop.ts &&
        t.service === spec.terminal.service && t.routeKey === spec.terminal.routeKey && t.kind === spec.terminal.kind)
      .sort((a, b) => (a.ts - b.ts) || (a.seq - b.seq))[0]
    if (!terminal) {
      return {
        chainId: spec.id,
        completed: false,
        confirmed: false,
        hopsObserved: completedHops.length,
        hopsTotal: spec.hops.length,
        missingHopIds: [],
        terminalObserved: false,
        failureReason: `terminal ${spec.terminal.kind} at ${spec.terminal.service}:${spec.terminal.routeKey} not observed`,
        dropReason: 'terminal_not_observed',
        receiptVerified: false,
      }
    }
    if (spec.forbiddenShortcutPersonas.includes(terminal.actor) || !spec.attackerPersonaSet.includes(terminal.actor)) {
      return failure(spec, completedHops.length, [], `terminal executed by disallowed persona '${terminal.actor}'`, 'persona_shortcut_rejected')
    }

    const receipt = receipts.get(chainId)
    const receiptCheck = receipt ? verifyReceipt(receipt) : { ok: false, reason: 'no composite receipt' }
    return {
      chainId: spec.id,
      completed: true,
      confirmed: receiptCheck.ok,
      hopsObserved: completedHops.length,
      hopsTotal: spec.hops.length,
      missingHopIds: [],
      terminalObserved: true,
      terminalAt: terminal.ts,
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
    const evaluation = evaluate(chainId)
    if (!evaluation.completed) {
      throw new Error(`cannot mint receipt for ${chainId}: ${evaluation.failureReason ?? 'incomplete'}`)
    }
    const ordered = sortedHops(chainId)
    const used: ReceiptHop[] = []
    let lastTs = Number.NEGATIVE_INFINITY
    for (const expected of spec.hops) {
      const obs = ordered.find((h) =>
        h.hopId === expected.hopId && h.ts >= lastTs && h.service === expected.service && h.routeKey === expected.routeKey
      )
      if (!obs) throw new Error(`cannot mint receipt for ${chainId}: hop ${expected.hopId} disappeared`)
      used.push({
        hopId: obs.hopId, service: obs.service, routeKey: obs.routeKey,
        actor: obs.actor, ts: obs.ts, artifactDigest: obs.artifactDigest,
      })
      lastTs = obs.ts
    }
    const causalEdges: ReceiptEdge[] = []
    for (let i = 1; i < spec.hops.length; i++) {
      const from = spec.hops[i - 1]!
      const to = spec.hops[i]!
      const kind = to.edgeFromPrevious!
      const edge = findEdge(chainId, from.hopId, to.hopId, kind, used[i - 1]!.ts)
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
    const terminal = terminals
      .filter((t) => t.chainId === chainId && t.ts >= used[used.length - 1]!.ts &&
        t.service === spec.terminal.service && t.routeKey === spec.terminal.routeKey && t.kind === spec.terminal.kind)
      .sort((a, b) => (a.ts - b.ts) || (a.seq - b.seq))[0]!
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
