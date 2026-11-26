/**
 * Host-Derived Causal Graph (Auto-DAG) & Normalized Control-Target Matcher.
 *
 * Deterministically infers missing verified `value_binding` and `derived_crypto_binding`
 * edges from the host-authoritative `HostFactLog` without weakening any downstream
 * `composite-receipt.ts` validation (chronology, provenance, replay mode, terminal impact).
 */
import type { CausalEdgeBinding, CompositeProofReceipt } from './composite-receipt.ts'
import type { HostFactLog } from './host-fact-log.ts'

const CAP_HANDLE_RE = /^cap:[A-Za-z0-9._:-]{1,180}$/
const SHA256_RE = /^[0-9a-f]{64}$/
const MAX_COMPOSITE_EDGES = 28

const isFiniteTs = (ts: unknown): ts is number =>
  typeof ts === 'number' && Number.isFinite(ts) && ts >= 0

const isExecArm = (arm: string | undefined, isTerm: boolean): boolean =>
  arm === 'probe' || (!isTerm && arm === 'setup')

interface CanonicalCapEmission {
  hopId: string
  sourceId: string
  isExchange: boolean
  timestampMs: number
  seq: number
}

function canReach(adj: ReadonlyMap<string, readonly string[]>, start: string, goal: string): boolean {
  if (start === goal) return true
  const visited = new Set<string>([start])
  const queue = [start]
  while (queue.length > 0) {
    const cur = queue.shift()!
    for (const next of adj.get(cur) ?? []) {
      if (next === goal) return true
      if (!visited.has(next)) {
        visited.add(next)
        queue.push(next)
      }
    }
  }
  return false
}

/**
 * Given a parsed `CompositeProofReceipt` and the host-authoritative `HostFactLog`,
 * deterministically derive missing `value_binding` and `derived_crypto_binding` edges
 * whenever `causalEdges` is empty or missing a kernel-observed capability edge between hops.
 *
 * Security invariants:
 * - Never alters 1-hop receipts or receipts with invalid/duplicate hopIds.
 * - Never deletes or rewrites explicit edges; only appends strictly chronological, acyclic,
 *   host-observed edges from non-control/non-cleanup execution arms.
 * - Canonical per-exchange ownership prevents duplicate/floating orphan hops that reuse an
 *   already-owned exchange ID from acquiring fabricated edges.
 * - Every auto-inferred edge still passes full `composite-receipt.ts` edge, provenance,
 *   replay-mode, and terminal-impact verification.
 */
export function augmentCompositeReceiptWithAutoDag(
  receipt: CompositeProofReceipt,
  factLog: HostFactLog,
): { receipt: CompositeProofReceipt; inferredEdges: CausalEdgeBinding[] } {
  if (receipt.hops.length < 2) return { receipt, inferredEdges: [] }
  const hopIds = new Set<string>()
  for (const hop of receipt.hops) {
    if (hopIds.has(hop.hopId)) return { receipt, inferredEdges: [] }
    hopIds.add(hop.hopId)
  }
  const termHopId = receipt.terminalImpact.terminalHopId
  if (!hopIds.has(termHopId)) return { receipt, inferredEdges: [] }

  const existingKeys = new Set<string>()
  const outAdj = new Map<string, string[]>(receipt.hops.map(h => [h.hopId, []]))
  const boundValueCapsByHop = new Map<string, Set<string>>()
  const boundCryptoCapsByHop = new Map<string, Set<string>>()
  const explicitProducerByCap = new Map<string, string>()

  const markBound = (map: Map<string, Set<string>>, hopId: string, cap: string): void => {
    let set = map.get(hopId)
    if (!set) {
      set = new Set<string>()
      map.set(hopId, set)
    }
    set.add(cap)
  }

  for (const edge of receipt.causalEdges) {
    existingKeys.add(`${edge.fromHopId}->${edge.toHopId}:${edge.kind}`)
    if (hopIds.has(edge.fromHopId) && hopIds.has(edge.toHopId) && edge.fromHopId !== edge.toHopId) {
      outAdj.get(edge.fromHopId)!.push(edge.toHopId)
    }
    if (edge.kind === 'value_binding' && edge.capabilityHandle) {
      markBound(boundValueCapsByHop, edge.toHopId, edge.capabilityHandle)
      if (!explicitProducerByCap.has(edge.capabilityHandle)) explicitProducerByCap.set(edge.capabilityHandle, edge.fromHopId)
    } else if (edge.kind === 'derived_crypto_binding') {
      markBound(boundCryptoCapsByHop, edge.toHopId, edge.sourceCapabilityId)
      if (!explicitProducerByCap.has(edge.sourceCapabilityId)) explicitProducerByCap.set(edge.sourceCapabilityId, edge.fromHopId)
    }
  }

  // Canonical single-owner map per exchange/OOB/trace ID (first citing hop owns it).
  const ownerHopByEx = new Map<string, string>()
  const ownerHopByOob = new Map<string, string>()
  const ownerHopByTrace = new Map<string, string>()
  const emissionsByCap = new Map<string, CanonicalCapEmission[]>()

  const recordEmission = (cap: string, em: CanonicalCapEmission): void => {
    if (!CAP_HANDLE_RE.test(cap)) return
    let list = emissionsByCap.get(cap)
    if (!list) {
      list = []
      emissionsByCap.set(cap, list)
    }
    list.push(em)
  }

  for (const hop of receipt.hops) {
    const isTerm = hop.hopId === termHopId
    for (const exId of hop.exchangeIds) {
      if (ownerHopByEx.has(exId)) continue
      ownerHopByEx.set(exId, hop.hopId)
      const flow = factLog.getExchangeCapabilityFlow(exId)
      if (!flow || !isExecArm(flow.arm, isTerm) || !isFiniteTs(flow.timestampMs)) continue
      for (const cap of flow.emitted) {
        recordEmission(cap, {
          hopId: hop.hopId,
          sourceId: exId,
          isExchange: true,
          timestampMs: flow.timestampMs,
          seq: flow.seq,
        })
      }
    }
    for (const oobId of hop.oobEventIds) {
      if (ownerHopByOob.has(oobId)) continue
      ownerHopByOob.set(oobId, hop.hopId)
      const oob = factLog.getOobEvent(oobId)
      if (!oob?.delivered || !isFiniteTs(oob.receivedAtMs)) continue
      for (const cap of oob.emittedCapabilities ?? []) {
        recordEmission(cap, {
          hopId: hop.hopId,
          sourceId: oobId,
          isExchange: false,
          timestampMs: oob.receivedAtMs,
          seq: -1,
        })
      }
    }
    for (const trId of hop.browserTraceIds) {
      if (ownerHopByTrace.has(trId)) continue
      ownerHopByTrace.set(trId, hop.hopId)
      const tr = factLog.getBrowserTrace(trId)
      if (!tr || !isFiniteTs(tr.timestampMs)) continue
      for (const cap of tr.emittedCapabilities ?? []) {
        recordEmission(cap, {
          hopId: hop.hopId,
          sourceId: trId,
          isExchange: false,
          timestampMs: tr.timestampMs,
          seq: -1,
        })
      }
    }
  }

  const pickEmitter = (
    cap: string,
    toHopId: string,
    targetTs: number,
    targetSeq: number,
    maxEmitTs = targetTs,
  ): CanonicalCapEmission | undefined => {
    const list = emissionsByCap.get(cap)
    if (!list?.length) return undefined
    const preferredHop = explicitProducerByCap.get(cap)
    const eligible = list.filter(em =>
      em.hopId !== toHopId
      && em.timestampMs <= maxEmitTs
      && (em.timestampMs < targetTs || (em.timestampMs === targetTs && em.seq < targetSeq)),
    )
    if (eligible.length === 0) return undefined
    if (preferredHop) {
      const pref = eligible.find(em => em.hopId === preferredHop)
      if (pref) return pref
    }
    return eligible[0]
  }

  const inferredEdges: CausalEdgeBinding[] = []
  const tryAppendEdge = (edge: CausalEdgeBinding): boolean => {
    if (receipt.causalEdges.length + inferredEdges.length >= MAX_COMPOSITE_EDGES) return false
    const key = `${edge.fromHopId}->${edge.toHopId}:${edge.kind}`
    if (existingKeys.has(key)) return false
    if (canReach(outAdj, edge.toHopId, edge.fromHopId)) return false
    existingKeys.add(key)
    outAdj.get(edge.fromHopId)!.push(edge.toHopId)
    inferredEdges.push(edge)
    return true
  }

  for (const hopB of receipt.hops) {
    const isTermB = hopB.hopId === termHopId
    for (const exId of hopB.exchangeIds) {
      if (ownerHopByEx.get(exId) !== hopB.hopId) continue
      const flow = factLog.getExchangeCapabilityFlow(exId)
      if (!flow || !isExecArm(flow.arm, isTermB) || !isFiniteTs(flow.timestampMs)) continue

      // 1. Derived cryptographic bindings (`derivedFromCapabilityId` -> `derived_crypto_binding`)
      for (const att of flow.cryptoAttestations) {
        const srcCap = att.derivedFromCapabilityId
        if (!CAP_HANDLE_RE.test(srcCap) || !SHA256_RE.test(att.artifactDigest.toLowerCase())) continue
        if (!isFiniteTs(att.timestampMs) || att.timestampMs > flow.timestampMs) continue
        if (boundCryptoCapsByHop.get(hopB.hopId)?.has(srcCap)) continue
        const em = pickEmitter(srcCap, hopB.hopId, flow.timestampMs, flow.seq, att.timestampMs)
        if (!em) continue
        const edge: CausalEdgeBinding = {
          kind: 'derived_crypto_binding',
          fromHopId: em.hopId,
          toHopId: hopB.hopId,
          sourceCapabilityId: srcCap,
          ...(att.derivedCapabilityId && CAP_HANDLE_RE.test(att.derivedCapabilityId)
            ? { derivedCapabilityId: att.derivedCapabilityId }
            : {}),
          ...(att.alg.trim() ? { alg: att.alg.trim().slice(0, 32) } : {}),
        }
        if (tryAppendEdge(edge)) {
          markBound(boundCryptoCapsByHop, hopB.hopId, srcCap)
        }
      }

      // 2. Direct capability value bindings (`consumedCapabilities` -> `value_binding`)
      for (const cap of flow.consumed) {
        if (!CAP_HANDLE_RE.test(cap)) continue
        if (boundValueCapsByHop.get(hopB.hopId)?.has(cap)) continue
        const em = pickEmitter(cap, hopB.hopId, flow.timestampMs, flow.seq)
        if (!em) continue
        const edge: CausalEdgeBinding = {
          kind: 'value_binding',
          fromHopId: em.hopId,
          toHopId: hopB.hopId,
          capabilityHandle: cap,
          ...(em.isExchange ? { sourceExchangeId: em.sourceId } : {}),
          targetExchangeId: exId,
        }
        if (tryAppendEdge(edge)) {
          markBound(boundValueCapsByHop, hopB.hopId, cap)
        }
      }
    }
  }

  if (inferredEdges.length === 0) return { receipt, inferredEdges }
  return {
    receipt: { ...receipt, causalEdges: [...receipt.causalEdges, ...inferredEdges] },
    inferredEdges,
  }
}

const STATIC_VERSION_PREFIX_RE = /^(?:v\d+|api|oauth\d*|http\d*|sha\d+|aes\d+|cwe|cve|rfc|iso|utf\d+)$/i
const UUID_SEG_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const HEX_ID_SEG_RE = /^(?:(?=[0-9a-f]*\d)[0-9a-f]{8,}|[0-9a-f]{16,})$/i
const OPAQUE_ALNUM_ID_RE = /^(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{8,}$/i

/** True when a decoded URL path segment is a dynamic resource/job/export identifier rather than a static route noun. */
export function isDynamicResourceIdSegment(rawSegment: string): boolean {
  let seg = rawSegment.trim()
  if (!seg) return false
  if (seg.includes('%')) {
    try { seg = decodeURIComponent(seg) } catch { /* keep raw */ }
  }
  const lower = seg.toLowerCase()
  if (/^\d+$/.test(lower)) return true
  if (UUID_SEG_RE.test(lower) || HEX_ID_SEG_RE.test(lower)) return true
  if (CAP_HANDLE_RE.test(seg) || /^\[redacted(?::[^\]]+)?\]$/i.test(seg)) return true
  if (OPAQUE_ALNUM_ID_RE.test(lower) && !STATIC_VERSION_PREFIX_RE.test(lower)) return true
  if ((lower.includes('-') || lower.includes('_')) && /\d/.test(lower)) {
    const parts = lower.split(/[-_]/).filter(Boolean)
    if (parts.length >= 2 && !STATIC_VERSION_PREFIX_RE.test(parts[0]!)) return true
  }
  return false
}

function splitCleanPathSegments(rawPath: string | null | undefined): string[] {
  const pathOnly = (rawPath ?? '').split(/[?#]/, 1)[0]!.replace(/\/+$/, '')
  return pathOnly.split('/').filter(Boolean).map(seg => {
    let decoded = seg
    if (seg.includes('%')) {
      try { decoded = decodeURIComponent(seg) } catch { decoded = seg }
    }
    return decoded.toLowerCase()
  })
}

/**
 * Match two request paths under strict canonical dynamic-ID normalization:
 * - Same non-empty segment count, at least one identical static segment.
 * - Every segment either matches literally OR both sides at that slot are dynamic resource IDs
 *   (preserving matching file extensions if present). Static route nouns never wildcard-match.
 */
export function matchesNormalizedCtrlPath(
  controlRawPath: string | null | undefined,
  refRawPath: string | null | undefined,
): boolean {
  const cSegs = splitCleanPathSegments(controlRawPath)
  const rSegs = splitCleanPathSegments(refRawPath)
  if (cSegs.length === 0 || cSegs.length !== rSegs.length) return false
  let staticMatches = 0
  let dynamicMatches = 0
  for (let i = 0; i < cSegs.length; i++) {
    const cs = cSegs[i]!
    const rs = rSegs[i]!
    if (cs === rs) {
      if (!isDynamicResourceIdSegment(cs)) staticMatches += 1
      continue
    }
    const cExt = /^([^./]+)(\.[a-z0-9]{1,8})$/i.exec(cs)
    const rExt = /^([^./]+)(\.[a-z0-9]{1,8})$/i.exec(rs)
    if (cExt && rExt) {
      if (cExt[2]!.toLowerCase() !== rExt[2]!.toLowerCase()) return false
      if (isDynamicResourceIdSegment(cExt[1]!) && isDynamicResourceIdSegment(rExt[1]!)) {
        dynamicMatches += 1
        continue
      }
      return false
    }
    if (isDynamicResourceIdSegment(cs) && isDynamicResourceIdSegment(rs)) {
      dynamicMatches += 1
      continue
    }
    return false
  }
  return staticMatches >= 1 && dynamicMatches >= 1
}
