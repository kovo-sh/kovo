/**
 * Host-Derived Causal Graph (Auto-DAG) & Normalized Control-Target Matcher.
 *
 * Delegates backwards causal DAG compilation and ancestor-cap rewiring to
 * `causal-proof-compiler.ts`, and provides strict canonical dynamic-ID control matching.
 */
import type { CompositeProofReceipt } from './composite-receipt.ts'
import type { HostFactLog } from './host-fact-log.ts'
import { compileCausalChainFromTranscript, isDynamicResourceIdSegment } from './causal-proof-compiler.ts'

export { isDynamicResourceIdSegment }

/**
 * Given a parsed `CompositeProofReceipt` and the host-authoritative `HostFactLog`,
 * deterministically rewire mis-anchored ancestor-cap `value_binding` edges and derive missing
 * `value_binding`, `derived_crypto_binding`, and valid mutating `state_transition_binding` edges.
 */
export function augmentCompositeReceiptWithAutoDag(
  receipt: CompositeProofReceipt,
  factLog: HostFactLog,
): ReturnType<typeof compileCausalChainFromTranscript> {
  return compileCausalChainFromTranscript(receipt, factLog)
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
