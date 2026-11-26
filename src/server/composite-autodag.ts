/**
 * Host-Derived Causal Graph (Auto-DAG) & Normalized Control-Target Matcher.
 *
 * Delegates backwards causal DAG compilation and ancestor-cap rewiring to
 * `causal-proof-compiler.ts`, and provides strict canonical dynamic-ID control matching.
 */
import type { CompositeProofReceipt, HostTranscriptEntry } from './composite-receipt.ts'
import type { HostFactLog } from './host-fact-log.ts'
import { compileCausalChainFromTranscript, isDynamicResourceIdSegment } from './causal-proof-compiler.ts'
import { extractTenantMarkers } from './v8-oracle-families.ts'
import { canonicalNonAuthQuery, cleanExactPath, entryMatchesEntity } from './v8-oracle-hydrate.ts'

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

export interface ControlTargetBindingContext {
  /** True ONLY when an explicit (non-auto-inferred) verified causal edge enters the terminal hop. */
  hasExplicitVerifiedTermEdge: boolean
  /** Host-signed transcript entries used to verify positive same-owner readback for sibling dynamic IDs. */
  entriesById: ReadonlyMap<string, HostTranscriptEntry>
  /** Attacker starting tenants (never credited as foreign owner). */
  attackerTenants: ReadonlySet<string>
}

const normOriginStr = (o: string | null | undefined): string => (o ?? '').trim().replace(/\/+$/, '').toLowerCase()
const is2xxStatus = (st: number | null | undefined): boolean => typeof st === 'number' && st >= 200 && st < 300

function extractDifferingDynamicIds(controlRawPath: string, refRawPath: string): string[] {
  const cSegs = splitCleanPathSegments(controlRawPath)
  const rSegs = splitCleanPathSegments(refRawPath)
  if (cSegs.length === 0 || cSegs.length !== rSegs.length) return []
  const ids: string[] = []
  for (let i = 0; i < cSegs.length; i++) {
    const cs = cSegs[i]!, rs = rSegs[i]!
    if (cs === rs) continue
    const cExt = /^([^./]+)(\.[a-z0-9]{1,8})$/i.exec(cs)
    const rExt = /^([^./]+)(\.[a-z0-9]{1,8})$/i.exec(rs)
    if (cExt && rExt && isDynamicResourceIdSegment(cExt[1]!) && isDynamicResourceIdSegment(rExt[1]!)) {
      ids.push(cExt[1]!)
    } else if (isDynamicResourceIdSegment(cs) && isDynamicResourceIdSegment(rs)) {
      ids.push(cs)
    }
  }
  return ids
}

function collectJsonLeavesForId(node: unknown, targetLower: string, depth = 0): boolean {
  if (depth > 5 || node == null) return false
  if (typeof node === 'string') return node.trim().toLowerCase() === targetLower
  if (typeof node === 'number') return String(node) === targetLower
  if (Array.isArray(node)) return node.slice(0, 64).some(x => collectJsonLeavesForId(x, targetLower, depth + 1))
  if (typeof node === 'object') {
    return Object.values(node as Record<string, unknown>).some(v => collectJsonLeavesForId(v, targetLower, depth + 1))
  }
  return false
}

function hasPositiveSameOwnerReadback(
  ctrl: HostTranscriptEntry,
  ref: HostTranscriptEntry,
  ctrlDynamicIds: readonly string[],
  ctx: ControlTargetBindingContext,
): boolean {
  const refOwners = new Set<string>(
    [...extractTenantMarkers(ref.step.json, ref.step.body)].filter(t => !ctx.attackerTenants.has(t)),
  )
  if (refOwners.size === 0) return false
  const candidateIds = new Set<string>(ctrlDynamicIds.map(id => id.trim().toLowerCase()).filter(Boolean))
  if (ctrl.entityId?.trim()) candidateIds.add(ctrl.entityId.trim().toLowerCase())
  if (candidateIds.size === 0) return false

  for (const entry of ctx.entriesById.values()) {
    if (entry.exchangeId === ctrl.exchangeId || entry.exchangeId === ref.exchangeId) continue
    if (!is2xxStatus(entry.step.status)) continue
    const entryOwners = extractTenantMarkers(entry.step.json, entry.step.body)
    if (entryOwners.size === 0 || ![...entryOwners].some(t => refOwners.has(t))) continue
    for (const cid of candidateIds) {
      if (entryMatchesEntity(entry, cid) || collectJsonLeavesForId(entry.step.json, cid)) {
        return true
      }
    }
  }
  return false
}

/**
 * R4-H-5 Authoritative terminal control-target binding primitive.
 *
 * Requires the denied control to target the SAME host-derived object as `ref`:
 *  1. Exact canonical path match (with entityId agreement when host-derived), OR
 *  2. Same host-derived `entityId` across matching normalized route shapes (non-404), OR
 *  3. Sibling dynamic-ID path ONLY when an EXPLICIT (non-auto-inferred) verified causal edge
 *     enters the terminal hop AND a host-signed 2xx readback positively binds the control's
 *     object to the SAME foreign owner/tenant as `ref`.
 *
 * Never accepts merely a sibling dynamic ID of the same route shape (honest per-object RBAC:
 * own object 200 + foreign object 403), and auto-inferred edges never unlock sibling matching.
 */
export function matchesBoundTerminalControl(
  control: HostTranscriptEntry,
  ref: HostTranscriptEntry,
  ctx: ControlTargetBindingContext,
): boolean {
  const cRaw = control.step.pathAndQuery ?? control.step.route ?? ''
  const rRaw = ref.step.pathAndQuery ?? ref.step.route ?? ''
  if (control.origin && ref.origin && normOriginStr(control.origin) !== normOriginStr(ref.origin)) return false
  if (control.step.method.toUpperCase() !== ref.step.method.toUpperCase()) return false
  if (canonicalNonAuthQuery(cRaw) !== canonicalNonAuthQuery(rRaw)) return false

  const hostEid = ref.entityId?.trim() ?? ''
  const ctrlEid = control.entityId?.trim() ?? ''
  const exactPath = Boolean(cleanExactPath(cRaw) && cleanExactPath(cRaw) === cleanExactPath(rRaw))
  if (exactPath) {
    if (hostEid && ctrlEid && ctrlEid.toLowerCase() !== hostEid.toLowerCase()) return false
    if (control.step.status === 404 && hostEid && !entryMatchesEntity(control, hostEid)) return false
    return true
  }

  if (control.step.status === 404 || !matchesNormalizedCtrlPath(cRaw, rRaw)) return false
  if (hostEid && ctrlEid && ctrlEid.toLowerCase() === hostEid.toLowerCase()) return true
  if (!ctx.hasExplicitVerifiedTermEdge) return false
  const dynIds = extractDifferingDynamicIds(cRaw, rRaw)
  return hasPositiveSameOwnerReadback(control, ref, dynIds, ctx)
}
