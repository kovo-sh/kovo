/**
 * Thin backward-compatibility shim for the retired own-org terminal guard (A2).
 *
 * Every boundary / readback / provenance invariant now lives in the universal Tier-1 primitives
 * (`v8-oracle-families.ts`: `access_differential`, `state_delta_and_conservation`, `causal_dag`) and the
 * economic normalization layer (`v8-oracle-hydrate.ts`). This module only re-exports those symbols for
 * legacy importers and keeps the non-verification capability-custody sync helpers used by
 * `exec-verify.ts` / `verify-rpc.ts` (seal producer metadata + base-persona resolution).
 */
import type { HydratableEntry } from './v8-oracle-hydrate.ts'

export {
  containsExactTenantToken,
  evaluateOwnScopeTerminalGuard as evaluateOwnOrgTerminalGuard,
  evaluateSignatureProvenanceGuard as evaluateForgedWebhookProvenanceGuard,
  findPreMutationDeniedControl,
  isZeroDeltaPostMutationReadback,
  matchesExactTenantIdentifier,
  normalizeTerminalVulnClass,
  resolveCompositeTerminalContract,
  resolveEntityLessReadStateTransition,
  selectVerifiedPostMutationReadback,
} from './v8-oracle-families.ts'
export {
  deriveBalanceConservationOperands as hydrateBalanceMintingOperands,
  extractLedgerBalanceMap,
  filterEconomicActionRecords,
  isControlDeniedAction,
  resolveEconomicActionRecords,
  resolveOpaqueDualCacheBleedTarget,
  selectAutoEconomicActions,
} from './v8-oracle-hydrate.ts'

/* ── Capability-custody sync helpers (seal producer metadata + base-persona lineage) ── */
const SEAL_META_ENDPOINT_HDR = 'x-kovo-seal-endpoint', SEAL_META_METHOD_HDR = 'x-kovo-seal-method', SEAL_META_FIELD_HDR = 'x-kovo-seal-field'
const SEAL_PSEUDO_PATH_RE = /^\/capability\/seal(?:\/|$)/i
const SEAL_PSEUDO_METHOD_RE = /^(?:SEAL|SIGN|DERIVE|MINT)$/i
const CAP_HANDLE_RE = /^cap:/i
const cleanEndpoint = (raw: string | null | undefined): string | undefined => { const p = (raw ?? '').split(/[?#]/, 1)[0]?.trim() ?? ''; return p && !SEAL_PSEUDO_PATH_RE.test(p) ? p : undefined }
const cleanMethod = (raw: string | null | undefined): string | undefined => { const m = (raw ?? '').trim().toUpperCase(); return m && !SEAL_PSEUDO_METHOD_RE.test(m) ? m : undefined }
const firstString = (...vals: unknown[]): string => { for (const v of vals) if (typeof v === 'string' && v.trim()) return v.trim(); return '' }
const normalizeSealJsonPathField = (raw: string): string => raw.trim().replace(/^\$\.?/, '').replace(/\[['"]([^'"]+)['"]\]/g, '.$1').replace(/\[\d+\]/g, '').replace(/^\.+|\.+$/g, '').replace(/\.{2,}/g, '.').slice(0, 64)

/** Non-secret structural producer metadata (`endpoint`, `method`, `fieldName`) for a `capability.seal` record. */
export function extractSealMetadataHeaders(args: Record<string, unknown>, sourceRequest?: { method?: string | null; pathAndQuery?: string | null } | null, extractedCookie?: string): Record<string, string> {
  const headers: Record<string, string> = {}
  const endpoint = (sourceRequest?.pathAndQuery ?? '').split(/[?#]/, 1)[0]?.trim() ?? ''
  if (endpoint && !SEAL_PSEUDO_PATH_RE.test(endpoint)) headers[SEAL_META_ENDPOINT_HDR] = endpoint.slice(0, 256)
  const method = (sourceRequest?.method ?? '').trim().toUpperCase()
  if (method && !SEAL_PSEUDO_METHOD_RE.test(method)) headers[SEAL_META_METHOD_HDR] = method.slice(0, 16)
  const field = typeof args.jsonPath === 'string' && args.jsonPath.trim() ? normalizeSealJsonPathField(args.jsonPath) : firstString(args.locationQuery, args.queryParam, args.header, args.setCookie, args.cookie, extractedCookie, args.defaultCookieName, args.defaultHeaderName)
  if (field) headers[SEAL_META_FIELD_HDR] = field.replace(/[\r\n\0]/g, '').slice(0, 64)
  return headers
}

export interface CapSyncTranscriptLike { exchangeId: string; op: string; request?: { origin?: string; method?: string; pathAndQuery?: string; headers?: Record<string, string>; personaHandle?: string | null; consumedCapabilityId?: string | null } }
export interface CapSyncMetaLike { handle: string; hopReceiptId: string; slot: string; derivedFromCapabilityId?: string; defaultHeaderName?: string; defaultCookieName?: string }
export interface CapSyncLedgerLike { getCapability(capId: string): { actorPersona?: string } | null | undefined }

/** Resolve an ephemeral `"cap:..."` handle back to its owning base persona (never stores a `"cap:..."` actor). */
export function resolveBasePersonaHandle(params: {
  rawPersona: string | null | undefined; defaultPersona: string; ledger: CapSyncLedgerLike; recordByCapHandle: ReadonlyMap<string, CapSyncTranscriptLike>
  hostEntryByEmittedCap: ReadonlyMap<string, HydratableEntry>; sealedMetaByHandle?: ReadonlyMap<string, CapSyncMetaLike>; normalizeCapId?: (handle: string) => string; seedCapIds?: readonly (string | null | undefined)[]
}): string {
  const def = params.defaultPersona.trim(), safeDefault = def && !CAP_HANDLE_RE.test(def) ? def : 'attacker'
  const start = params.rawPersona?.trim() ?? ''
  if (start && !CAP_HANDLE_RE.test(start)) return start
  const queue: string[] = [], visited = new Set<string>()
  const push = (h: string | null | undefined) => { const t = h?.trim(); if (t && CAP_HANDLE_RE.test(t) && !visited.has(t)) queue.push(t) }
  push(start); for (const s of params.seedCapIds ?? []) push(s)
  while (queue.length > 0 && visited.size < 16) {
    const cur = queue.shift()!
    if (visited.has(cur)) continue
    visited.add(cur)
    const rec = params.recordByCapHandle.get(cur), host = params.hostEntryByEmittedCap.get(cur)
    const ledgerActor = params.ledger.getCapability(cur)?.actorPersona ?? params.ledger.getCapability(params.normalizeCapId ? params.normalizeCapId(cur) : cur)?.actorPersona
    // Lineage BFS order: ledger node -> transcript record (+ its consumed cap) -> host entry (+ consumed caps) -> sealed meta.
    for (const [cand, extra] of [[ledgerActor, []], [rec?.request?.personaHandle, [rec?.request?.consumedCapabilityId]], [host?.actorPersona ?? host?.step.actor.handle, host?.consumedCapabilities ?? []]] as const) {
      const t = cand?.trim(); if (t && !CAP_HANDLE_RE.test(t)) return t
      push(t); for (const c of extra) push(c)
    }
    push(params.sealedMetaByHandle?.get(cur)?.derivedFromCapabilityId)
  }
  return safeDefault
}

/** Base `actorPersona` (never `"cap:..."`) + producer metadata (`endpoint`, `method`, `fieldName`) for a sealed capability. */
export function resolveSealedCapabilitySyncContext(params: {
  meta: CapSyncMetaLike; rec: CapSyncTranscriptLike | undefined; defaultPersona: string; ledger: CapSyncLedgerLike; recordByCapHandle: ReadonlyMap<string, CapSyncTranscriptLike>
  recordByExchangeId: ReadonlyMap<string, CapSyncTranscriptLike>; hostEntryByEmittedCap: ReadonlyMap<string, HydratableEntry>; sealedMetaByHandle: ReadonlyMap<string, CapSyncMetaLike>; normalizeCapId?: (handle: string) => string
}): { actorPersona: string; endpoint?: string; method?: string; fieldName?: string } {
  const { meta, rec } = params, src = params.hostEntryByEmittedCap.get(meta.handle)
  const actorPersona = resolveBasePersonaHandle({
    rawPersona: firstString(rec?.request?.personaHandle, src?.actorPersona, src?.step.actor.handle), defaultPersona: params.defaultPersona, ledger: params.ledger,
    recordByCapHandle: params.recordByCapHandle, hostEntryByEmittedCap: params.hostEntryByEmittedCap, sealedMetaByHandle: params.sealedMetaByHandle, normalizeCapId: params.normalizeCapId,
    seedCapIds: [meta.derivedFromCapabilityId, rec?.request?.consumedCapabilityId, ...(src?.consumedCapabilities ?? [])],
  })
  const hopRec = params.recordByExchangeId.get(meta.hopReceiptId)
  const nonSeal = (r: CapSyncTranscriptLike | undefined) => r && r.op !== 'capability' && !SEAL_PSEUDO_METHOD_RE.test(r.request?.method ?? '') ? r : undefined
  // Only trust host-stamped `x-kovo-seal-*` headers on host `op: 'capability'` SEAL records (never worker http headers).
  const sealHdrs = rec?.op === 'capability' ? rec.request?.headers : undefined
  const endpoint = cleanEndpoint(src?.step.pathAndQuery ?? src?.step.route) ?? cleanEndpoint(nonSeal(rec)?.request?.pathAndQuery) ?? cleanEndpoint(sealHdrs?.[SEAL_META_ENDPOINT_HDR]) ?? cleanEndpoint(nonSeal(hopRec)?.request?.pathAndQuery)
  const method = cleanMethod(src?.step.method) ?? cleanMethod(nonSeal(rec)?.request?.method) ?? cleanMethod(sealHdrs?.[SEAL_META_METHOD_HDR]) ?? cleanMethod(nonSeal(hopRec)?.request?.method)
  const fieldName = firstString(sealHdrs?.[SEAL_META_FIELD_HDR], meta.defaultHeaderName, meta.defaultCookieName) || undefined
  return { actorPersona, ...(endpoint ? { endpoint } : {}), ...(method ? { method } : {}), ...(fieldName ? { fieldName } : {}) }
}
