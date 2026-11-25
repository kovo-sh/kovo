/**
 * CompositeProofReceipt — unified multi-hop DAG confirmation verifier (v8).
 * Verifies 1..8 hop causal chains strictly over host-signed transcript records:
 * value_binding, derived_crypto_binding, state_transition_binding, async_pivot_binding,
 * attacker-origin provenance, Mode-A/Mode-B replay, and hardened terminal-impact oracles.
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { z } from 'zod'
import { scopedAssetOrigin } from '../domain.ts'
import { parseRoleLabel, routeFamily, stepReadsState } from './oracle-invariants.ts'
import { proofReceiptSchema, receiptIdSchema, verifyReceipt } from './proof-receipt.ts'
import { evaluateV8OracleFamily, isJobOrHandleStub } from './v8-oracle-families.ts'
import type { CrossSurfaceHop, CrossSurfacePivotInput, HostSignedRecord as V8OracleRecord, V8OracleFamily, V8OracleInputMap } from './v8-oracle-families.ts'
import type { ProofReceipt, ReceiptBrowserTrace, ReceiptOobEvent, ReceiptTranscript, ReceiptTranscriptEntry, ReceiptVerification } from './proof-receipt.ts'

export const HOP_SURFACES = ['http', 'graphql', 'ws', 'sse', 'browser', 'webhook', 'async_job', 'idp', 'cdn', 'storage'] as const
export type HopSurface = (typeof HOP_SURFACES)[number]
const V8_ORACLE_FAMILIES = ['dual_tenant_abac', 'temporal_revocation', 'economic_conservation', 'cryptographic_scope_replay', 'parser_cache_differential', 'cross_surface_pivot'] as const
const V8_ORACLE_FAMILY_SET: ReadonlySet<string> = new Set(V8_ORACLE_FAMILIES)
export const CAUSAL_EDGE_KINDS = ['value_binding', 'derived_crypto_binding', 'state_transition_binding', 'async_pivot_binding'] as const
export type CausalEdgeKind = (typeof CAUSAL_EDGE_KINDS)[number]
export const REPLAY_MODES = ['fresh_clean_replay', 'one_shot_transcript'] as const
export type ReplayMode = (typeof REPLAY_MODES)[number]
export const capabilityHandleSchema = z.string().trim().regex(/^cap:[A-Za-z0-9._:-]{1,180}$/)
export const sha256HexSchema = z.string().trim().regex(/^[0-9a-fA-F]{64}$/)

const idList = (max: number) => z.array(receiptIdSchema).max(max).default([])
const edgeEnds = { fromHopId: receiptIdSchema, toHopId: receiptIdSchema }
const nonEmpty = (max: number) => z.string().trim().min(1).max(max)

export const hopReceiptSchema = z.object({
  hopId: receiptIdSchema, surface: z.enum(HOP_SURFACES).default('http'),
  target: z.object({ origin: scopedAssetOrigin, method: z.string().trim().regex(/^[A-Z]{1,10}$/).optional(), pathAndQuery: nonEmpty(4096).optional(), param: nonEmpty(128).optional() }),
  exchangeIds: idList(32), oobEventIds: idList(16), browserTraceIds: idList(16), claimedDelta: nonEmpty(1200),
  producedCapabilities: z.array(capabilityHandleSchema).max(16).default([]), consumedCapabilities: z.array(capabilityHandleSchema).max(16).default([]),
  entityId: nonEmpty(256).optional(), canaryToken: nonEmpty(256).optional(), proofReceipt: proofReceiptSchema.optional(),
})
export type HopReceipt = z.output<typeof hopReceiptSchema>

export const valueBindingEdgeSchema = z.object({
  kind: z.literal('value_binding'), ...edgeEnds, capabilityHandle: capabilityHandleSchema.optional(), valueDigest: sha256HexSchema.optional(),
  sourceExchangeId: receiptIdSchema.optional(), targetExchangeId: receiptIdSchema.optional(),
}).refine(e => e.capabilityHandle !== undefined || e.valueDigest !== undefined, { message: 'value_binding requires capabilityHandle and/or valueDigest' })
export const derivedCryptoBindingEdgeSchema = z.object({
  kind: z.literal('derived_crypto_binding'), ...edgeEnds, sourceCapabilityId: capabilityHandleSchema,
  derivedCapabilityId: capabilityHandleSchema.optional(), alg: nonEmpty(32).optional(),
})
export const stateTransitionBindingEdgeSchema = z.object({
  kind: z.literal('state_transition_binding'), ...edgeEnds, entityId: nonEmpty(256),
  ablationExchangeIds: z.array(receiptIdSchema).min(1).max(16), mutationKind: nonEmpty(64).optional(),
})
export const asyncPivotBindingEdgeSchema = z.object({
  kind: z.literal('async_pivot_binding'), ...edgeEnds, correlationId: nonEmpty(256),
  channel: z.enum(['poll_convergence', 'oob_relay', 'browser_trace', 'async_job']),
  oobEventId: receiptIdSchema.optional(), browserTraceId: receiptIdSchema.optional(), pollRecordId: receiptIdSchema.optional(),
})
export const causalEdgeBindingSchema = z.discriminatedUnion('kind', [
  valueBindingEdgeSchema, derivedCryptoBindingEdgeSchema, stateTransitionBindingEdgeSchema, asyncPivotBindingEdgeSchema,
])
export type CausalEdgeBinding = z.output<typeof causalEdgeBindingSchema>

export const terminalImpactSchema = z.object({
  terminalHopId: receiptIdSchema, claimedImpact: z.string().trim().max(1200).optional(), summary: z.string().trim().max(1200).optional(),
  terminalExchangeId: receiptIdSchema.optional(), proofReceipt: proofReceiptSchema.optional(),
  oracleFamily: z.enum(V8_ORACLE_FAMILIES).optional(), oracleInput: z.record(z.string(), z.unknown()).optional(),
  preChainControlExchangeIds: idList(16), postChainReadbackExchangeIds: idList(16), modeAFailureExchangeId: receiptIdSchema.optional(),
}).transform(ti => ({ ...ti, claimedImpact: ti.claimedImpact && ti.claimedImpact.length > 0 ? ti.claimedImpact : (ti.summary ?? '') }))
export type TerminalImpact = z.output<typeof terminalImpactSchema>

export const compositeProofReceiptSchema = z.object({
  chainId: receiptIdSchema, terminalVulnClass: nonEmpty(64), hops: z.array(hopReceiptSchema).min(1).max(8),
  causalEdges: z.array(causalEdgeBindingSchema).max(28).default([]), terminalImpact: terminalImpactSchema,
  replayMode: z.enum(REPLAY_MODES).default('fresh_clean_replay'), benchmarkMode: z.boolean().optional(),
})
export type CompositeProofReceipt = z.output<typeof compositeProofReceiptSchema>

// --- Host-Signed Transcript Types (Superset of ReceiptTranscript) -----------

export interface HostCryptoAttestation { derivedFromCapabilityId: string; derivedCapabilityId?: string; alg: string; artifactDigest: string; timestampMs: number }
export interface HostTranscriptEntry extends ReceiptTranscriptEntry {
  timestampMs?: number; actorPersona?: string | null; actorRoleLabel?: string | null; emittedCapabilities?: readonly string[]
  observedResponseDigests?: readonly string[]; consumedCapabilities?: readonly string[]; injectedRequestDigests?: readonly string[]
  cryptoAttestations?: readonly HostCryptoAttestation[]; entityId?: string; correlationIds?: readonly string[]
  cleanSession?: boolean; replayAttempt?: 'mode_a' | 'ablation_control' | 'primary'; hostSignature?: string
}
export interface HostOobEvent extends ReceiptOobEvent { emittedCapabilities?: readonly string[]; observedValueDigests?: readonly string[]; correlationIds?: readonly string[]; hostSignature?: string }
export interface HostBrowserTrace extends ReceiptBrowserTrace { timestampMs?: number; actorPersona?: string | null; emittedCapabilities?: readonly string[]; observedValueDigests?: readonly string[]; correlationIds?: readonly string[]; hostSignature?: string }
export interface HostAsyncPollRecord { id: string; triggerExchangeId?: string; tTriggerMs: number; tObservedMs: number; converged: boolean; correlationIds?: readonly string[]; emittedCapabilities?: readonly string[]; observedValueDigests?: readonly string[]; entityId?: string; hostSignature?: string }
export interface HostSignedTranscript extends ReceiptTranscript { entries?: readonly HostTranscriptEntry[]; oobEvents?: readonly HostOobEvent[]; browserTraces?: readonly HostBrowserTrace[]; asyncPollRecords?: readonly HostAsyncPollRecord[] }
export type HostSignableRecord = HostTranscriptEntry | HostOobEvent | HostBrowserTrace | HostAsyncPollRecord
export interface CompositeVerifyOptions {
  attackerPersonas?: readonly string[]; forbiddenShortcutPersonas?: readonly string[]; benchmarkMode?: boolean; requireCleanSessionFlag?: boolean; signingKey?: string
  v8OracleInput?: Record<string, unknown>
  verifyTerminalImpact?: (receipt: CompositeProofReceipt, transcript: HostSignedTranscript) => { confirmed: boolean; reason: string; family?: string; evidence?: Record<string, unknown> }
}
export interface VerifiedEdgeResult { edgeIndex: number; kind: CausalEdgeKind; fromHopId: string; toHopId: string; verified: boolean; reason: string; evidence?: Record<string, unknown> }
export type CompositeFailureStage = 'schema' | 'dag_topology' | 'transcript_integrity' | 'edge_binding' | 'attacker_provenance' | 'replay_mode' | 'terminal_impact'
export interface CompositeReceiptVerification {
  confirmed: boolean; chainId: string; terminalVulnClass: string; replayMode: ReplayMode; modeBVerified: boolean; hopCount: number
  verifiedEdges: VerifiedEdgeResult[]; reason: string; failedStage?: CompositeFailureStage; rejectedBy?: string | null; missingEvidence?: string[]
  terminalVerification?: ReceiptVerification; evidence?: Record<string, unknown>
}

// --- Cryptographic, Hashing & Transcript Helpers ----------------------------

const CONSUMED_STATE_RE =
  /\b(?:already[_\s-]?(?:consumed|redeemed|used|claimed|applied|settled)|token[_\s-]?(?:consumed|used|redeemed|spent)|one[_\s-]?time|nonce[_\s-]?(?:used|replayed|consumed)|invite[_\s-]?(?:redeemed|consumed|used)|state[_\s-]?(?:consumed|exhausted|finalized))\b/i
const ABLATION_DENIED_STATUSES = new Set([401, 403, 404, 409, 412, 422])
const DENIED_CONTROL_STATUSES = new Set([401, 403, 404])
const SHA256_RE = /^[0-9a-f]{64}$/
const TENANT_KEYS = new Set(['tenant', 'tenantid', 'tenant_id', 'org', 'orgid', 'org_id', 'workspaceid', 'workspace_id', 'ownertenant', 'ownertenantid', 'owner_tenant_id'])
const STRICT_TERMINAL_CLASS_RE = /^(?:dual_tenant_abac|parser_cache_differential|temporal_revocation|economic_conservation|cryptographic_scope_replay|cross_surface_pivot)$|dual[_-]?tenant|abac|cache[_-]?(?:bleed|poison|deception|diff)|parser[_-]?diff|smuggl|cwe[-_]?444|cwe[-_]?639|\bidor\b|\bbola\b/i
const TERMINAL_IMPACT_UNPROVEN_HINT =
  "terminal_impact_unproven: creating a job/handle or priming cache is an intermediate capability, not terminal impact — follow the derived handle/URL to prove unauthorized foreign-tenant data read or privileged mutation, or call record_coverage(status='ruled_out', proofGapReason='invariant_enforced_hardened') if the terminal guard blocks access"

function collectTenantMarkers(value: unknown, out: Set<string>, depth = 0): void {
  if (depth > 3 || out.size > 32 || value == null) return
  if (Array.isArray(value)) { for (const x of value) collectTenantMarkers(x, out, depth + 1); return }
  if (typeof value !== 'object') return
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'string' && v.trim() && TENANT_KEYS.has(k.toLowerCase())) out.add(v.trim().toLowerCase())
    else if (v && typeof v === 'object') collectTenantMarkers(v, out, depth + 1)
  }
}
function entryTenants(entry: HostTranscriptEntry): Set<string> {
  const out = new Set<string>()
  let json = entry.step.json
  if (json === undefined && typeof entry.step.body === 'string' && entry.step.body.trim().startsWith('{')) try { json = JSON.parse(entry.step.body) } catch { json = undefined }
  collectTenantMarkers(json, out); return out
}
export const sha256Hex = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex')
function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(',')}]`
  return `{${Object.entries(value as Record<string, unknown>).filter(([k, v]) => k !== 'hostSignature' && v !== undefined).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => `${JSON.stringify(k)}:${canonicalStringify(v)}`).join(',')}}`
}
export const signHostRecord = (record: HostSignableRecord, signingKey: string): string => createHmac('sha256', signingKey).update(canonicalStringify(record), 'utf8').digest('hex')
export function verifyHostRecordSignature(record: HostSignableRecord, signingKey: string): boolean {
  if (!record.hostSignature || !SHA256_RE.test(record.hostSignature.toLowerCase())) return false
  const expected = Buffer.from(signHostRecord(record, signingKey), 'hex'), actual = Buffer.from(record.hostSignature.toLowerCase(), 'hex')
  return expected.length === actual.length && timingSafeEqual(expected, actual)
}
const is2xx = (st: number | null | undefined): boolean => typeof st === 'number' && st >= 200 && st < 300
const isFiniteTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts >= 0
const actorOf = (e: HostTranscriptEntry): string | null => (e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null))
const roleOf = (e: HostTranscriptEntry): string | null => (e.actorRoleLabel ? parseRoleLabel(e.actorRoleLabel).role : (e.step.actor.role ?? null))
function collectLeaves(value: unknown, out: Set<string>, depth = 0): void {
  if (depth > 5 || out.size > 256 || value == null) return
  if (typeof value === 'string') { const t = value.trim(); if (t.length > 0 && t.length <= 2048) out.add(t) }
  else if (typeof value === 'number' || typeof value === 'boolean') out.add(String(value))
  else if (Array.isArray(value)) for (const x of value) collectLeaves(x, out, depth + 1)
  else if (typeof value === 'object') for (const x of Object.values(value as Record<string, unknown>)) collectLeaves(x, out, depth + 1)
}
function collectHeaderTokens(headers: Record<string, string> | null | undefined, out: Set<string>): void {
  if (!headers) return
  for (const raw of Object.values(headers)) {
    const t = raw.trim(); if (!t) continue; out.add(t)
    const scheme = /^(?:Bearer|Basic|Token|ApiKey)\s+(.+)$/i.exec(t)
    if (scheme?.[1]) out.add(scheme[1].trim())
    if (t.includes('=')) for (const p of t.split(';')) { const eq = p.indexOf('='); if (eq > 0 && p.slice(eq + 1).trim()) out.add(p.slice(eq + 1).trim()) }
  }
}

function collectEntryDigests(entry: HostTranscriptEntry, side: 'response' | 'request'): Set<string> {
  const digests = new Set<string>(), leaves = new Set<string>()
  if (side === 'response') {
    for (const d of [...(entry.observedResponseDigests ?? []), ...(entry.step.secretMatches ?? [])]) digests.add(d.toLowerCase())
    collectLeaves(entry.step.json, leaves); collectHeaderTokens(entry.step.responseHeaders, leaves)
  } else {
    for (const d of entry.injectedRequestDigests ?? []) digests.add(d.toLowerCase())
    collectLeaves(entry.step.requestJson, leaves); collectHeaderTokens(entry.step.requestHeaders, leaves)
    const q = entry.step.pathAndQuery?.indexOf('?') ?? -1
    if (q >= 0 && entry.step.pathAndQuery) for (const v of new URLSearchParams(entry.step.pathAndQuery.slice(q + 1)).values()) if (v) leaves.add(v)
  }
  for (const leaf of leaves) digests.add(sha256Hex(leaf))
  return digests
}
function entryLeaves(entry: HostTranscriptEntry, withHeaders: boolean): Set<string> {
  const out = new Set<string>()
  collectLeaves(entry.step.requestJson, out); collectLeaves(entry.step.json, out)
  if (withHeaders) { collectHeaderTokens(entry.step.requestHeaders, out); collectHeaderTokens(entry.step.responseHeaders, out) }
  return out
}
function entryMatchesEntity(entry: HostTranscriptEntry, entityId: string): boolean {
  if (entry.entityId === entityId) return true
  const path = entry.step.pathAndQuery ?? entry.step.route ?? ''
  return (Boolean(path) && new RegExp(`(?:^|[/=?&])${entityId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|[/&?#])`).test(path)) || entryLeaves(entry, false).has(entityId)
}
function entryMatchesCorrelation(entry: HostTranscriptEntry, correlationId: string): boolean {
  if (entry.correlationIds?.includes(correlationId) || entry.entityId === correlationId || entry.carrierText?.includes(correlationId)) return true
  for (const leaf of entryLeaves(entry, true)) if (leaf === correlationId || leaf.includes(correlationId)) return true
  return false
}
function serializeBodyText(entry: HostTranscriptEntry): string {
  if (typeof entry.step.body === 'string' && entry.step.body.length > 0) return entry.step.body
  try { return entry.step.json !== undefined ? JSON.stringify(entry.step.json) : '' } catch { return '' }
}

// --- DAG Topology & Transcript Integrity ------------------------------------

interface DagTopology { hopsById: Map<string, HopReceipt>; topoOrder: string[]; roots: string[]; incomingByHop: Map<string, Array<{ edgeIndex: number; edge: CausalEdgeBinding }>> }
interface IndexedTranscript { entriesById: Map<string, HostTranscriptEntry>; oobById: Map<string, HostOobEvent>; tracesById: Map<string, HostBrowserTrace>; pollsById: Map<string, HostAsyncPollRecord>; allPolls: readonly HostAsyncPollRecord[] }

function validateDagTopology(receipt: CompositeProofReceipt): { ok: true; dag: DagTopology } | { ok: false; reason: string } {
  const hopsById = new Map<string, HopReceipt>()
  for (const hop of receipt.hops) {
    if (hopsById.has(hop.hopId)) return { ok: false, reason: `Duplicate hopId "${hop.hopId}".` }
    hopsById.set(hop.hopId, hop)
  }
  if (!hopsById.has(receipt.terminalImpact.terminalHopId)) return { ok: false, reason: `terminalHopId "${receipt.terminalImpact.terminalHopId}" not in hops.` }
  if (receipt.hops.length === 1 && receipt.causalEdges.length > 0) return { ok: false, reason: 'A 1-hop receipt cannot declare causalEdges.' }
  const inDeg = new Map<string, number>(receipt.hops.map(h => [h.hopId, 0]))
  const outAdj = new Map<string, string[]>(receipt.hops.map(h => [h.hopId, []]))
  const revAdj = new Map<string, string[]>(receipt.hops.map(h => [h.hopId, []]))
  const incomingByHop = new Map<string, Array<{ edgeIndex: number; edge: CausalEdgeBinding }>>(receipt.hops.map(h => [h.hopId, []]))
  const seen = new Set<string>()
  for (let i = 0; i < receipt.causalEdges.length; i++) {
    const e = receipt.causalEdges[i]!
    if (!hopsById.has(e.fromHopId) || !hopsById.has(e.toHopId)) return { ok: false, reason: `Edge #${i} references unknown hop.` }
    if (e.fromHopId === e.toHopId) return { ok: false, reason: `Edge #${i} forms a self-loop on "${e.fromHopId}".` }
    const key = `${e.fromHopId}->${e.toHopId}:${e.kind}`
    if (seen.has(key)) return { ok: false, reason: `Duplicate causal edge "${key}".` }
    seen.add(key); outAdj.get(e.fromHopId)!.push(e.toHopId); revAdj.get(e.toHopId)!.push(e.fromHopId)
    inDeg.set(e.toHopId, (inDeg.get(e.toHopId) ?? 0) + 1); incomingByHop.get(e.toHopId)!.push({ edgeIndex: i, edge: e })
  }
  const roots = receipt.hops.filter(h => inDeg.get(h.hopId) === 0).map(h => h.hopId)
  const queue = [...roots], rem = new Map(inDeg), topoOrder: string[] = []
  while (queue.length > 0) {
    const id = queue.shift()!; topoOrder.push(id)
    for (const next of outAdj.get(id) ?? []) { const d = (rem.get(next) ?? 0) - 1; rem.set(next, d); if (d === 0) queue.push(next) }
  }
  if (topoOrder.length !== receipt.hops.length) return { ok: false, reason: 'Causal DAG contains a cycle.' }
  const reachesTerminal = new Set<string>([receipt.terminalImpact.terminalHopId]), rq = [receipt.terminalImpact.terminalHopId]
  while (rq.length > 0) for (const prev of revAdj.get(rq.shift()!) ?? []) if (!reachesTerminal.has(prev)) { reachesTerminal.add(prev); rq.push(prev) }
  const orphan = receipt.hops.find(h => !reachesTerminal.has(h.hopId))
  return orphan ? { ok: false, reason: `Hop "${orphan.hopId}" does not reach terminalHopId.` } : { ok: true, dag: { hopsById, topoOrder, roots, incomingByHop } }
}

function indexAndVerifyCitations(receipt: CompositeProofReceipt, transcript: HostSignedTranscript, signingKey?: string): { ok: true; idx: IndexedTranscript } | { ok: false; reason: string } {
  const entriesById = new Map((transcript.entries ?? []).map(e => [e.exchangeId, e]))
  const oobById = new Map((transcript.oobEvents ?? []).map(o => [o.id, o]))
  const tracesById = new Map((transcript.browserTraces ?? []).map(t => [t.id, t]))
  const allPolls = transcript.asyncPollRecords ?? [], pollsById = new Map(allPolls.map(p => [p.id, p]))
  const checkAll = <T extends HostSignableRecord>(ids: readonly string[], map: Map<string, T>, label: string): string | null => {
    for (const id of ids) {
      const rec = map.get(id)
      if (!rec) return `Receipt cites ${label} "${id}" absent from host transcript.`
      if (signingKey && !verifyHostRecordSignature(rec, signingKey)) return `Host signature verification failed for ${label} "${id}".`
    }
    return null
  }
  for (const h of receipt.hops) {
    const err = checkAll(h.exchangeIds, entriesById, `hop "${h.hopId}" exchange`) ?? checkAll(h.oobEventIds, oobById, `hop "${h.hopId}" OOB event`) ?? checkAll(h.browserTraceIds, tracesById, `hop "${h.hopId}" browser trace`)
    if (err) return { ok: false, reason: err }
  }
  for (const e of receipt.causalEdges) {
    const err = e.kind === 'state_transition_binding' ? checkAll(e.ablationExchangeIds, entriesById, 'ablation exchange')
      : e.kind === 'async_pivot_binding' && e.pollRecordId ? checkAll([e.pollRecordId], pollsById, 'asyncPollRecord') : null
    if (err) return { ok: false, reason: err }
  }
  const ti = receipt.terminalImpact
  const tErr = checkAll(ti.preChainControlExchangeIds, entriesById, 'pre-chain control') ?? checkAll(ti.postChainReadbackExchangeIds, entriesById, 'post-chain readback')
    ?? (ti.terminalExchangeId ? checkAll([ti.terminalExchangeId], entriesById, 'terminal exchange') : null)
    ?? (ti.modeAFailureExchangeId ? checkAll([ti.modeAFailureExchangeId], entriesById, 'Mode-A failure') : null)
  return tErr ? { ok: false, reason: tErr } : { ok: true, idx: { entriesById, oobById, tracesById, pollsById, allPolls } }
}

function recordHopCapabilities(hop: HopReceipt, idx: IndexedTranscript, target: Set<string>): void {
  for (const id of hop.exchangeIds) {
    const e = idx.entriesById.get(id)!
    for (const c of e.emittedCapabilities ?? []) target.add(c)
    for (const a of e.cryptoAttestations ?? []) if (a.derivedCapabilityId) target.add(a.derivedCapabilityId)
  }
  for (const id of hop.oobEventIds) for (const c of idx.oobById.get(id)?.emittedCapabilities ?? []) target.add(c)
  for (const id of hop.browserTraceIds) for (const c of idx.tracesById.get(id)?.emittedCapabilities ?? []) target.add(c)
}

// --- Four Causal Edge Verifiers ---------------------------------------------

interface HopOutputEvent { sourceId: string; timestampMs: number; capabilities: Set<string>; digests: Set<string> }
type EdgeBase = { edgeIndex: number; kind: CausalEdgeKind; fromHopId: string; toHopId: string }

const edgeFail = (base: EdgeBase, reason: string): VerifiedEdgeResult => ({ ...base, verified: false, reason })
const edgeOk = (base: EdgeBase, reason: string, evidence?: Record<string, unknown>): VerifiedEdgeResult =>
  ({ ...base, verified: true, reason, ...(evidence ? { evidence } : {}) })

function collectHopOutputs(hop: HopReceipt, idx: IndexedTranscript): HopOutputEvent[] {
  const out: HopOutputEvent[] = []
  for (const id of hop.exchangeIds) {
    const e = idx.entriesById.get(id)!
    if (!isFiniteTs(e.timestampMs)) continue
    const caps = new Set<string>(e.emittedCapabilities ?? [])
    for (const a of e.cryptoAttestations ?? []) if (a.derivedCapabilityId) caps.add(a.derivedCapabilityId)
    out.push({ sourceId: id, timestampMs: e.timestampMs, capabilities: caps, digests: collectEntryDigests(e, 'response') })
  }
  for (const id of hop.oobEventIds) {
    const oob = idx.oobById.get(id)!
    if (!oob.delivered || !isFiniteTs(oob.receivedAtMs)) continue
    const digests = new Set<string>((oob.observedValueDigests ?? []).map(d => d.toLowerCase()))
    if (oob.token) digests.add(sha256Hex(oob.token))
    out.push({ sourceId: id, timestampMs: oob.receivedAtMs, capabilities: new Set(oob.emittedCapabilities ?? []), digests })
  }
  for (const id of hop.browserTraceIds) {
    const tr = idx.tracesById.get(id)!
    if (!isFiniteTs(tr.timestampMs)) continue
    out.push({ sourceId: id, timestampMs: tr.timestampMs, capabilities: new Set(tr.emittedCapabilities ?? []), digests: new Set((tr.observedValueDigests ?? []).map(d => d.toLowerCase())) })
  }
  return out
}

function matchOrderedPair(
  outputs: readonly HopOutputEvent[], reqs: readonly HostTranscriptEntry[],
  matchOut: (o: HopOutputEvent) => boolean, matchReq: (r: HostTranscriptEntry) => boolean,
): { ok: true; pair: { from: string; to: string; tFrom: number; tTo: number } } | { ok: false; outOfOrder: boolean; missingTs?: string } {
  let outOfOrder = false
  for (const o of outputs) {
    if (!matchOut(o)) continue
    for (const r of reqs) {
      if (!matchReq(r)) continue
      if (!isFiniteTs(r.timestampMs)) return { ok: false, outOfOrder: false, missingTs: r.exchangeId }
      if (o.timestampMs <= r.timestampMs) return { ok: true, pair: { from: o.sourceId, to: r.exchangeId, tFrom: o.timestampMs, tTo: r.timestampMs } }
      outOfOrder = true
    }
  }
  return { ok: false, outOfOrder }
}

function verifyValueBinding(
  base: EdgeBase, edge: Extract<CausalEdgeBinding, { kind: 'value_binding' }>,
  fromHop: HopReceipt, toHop: HopReceipt, idx: IndexedTranscript,
): VerifiedEdgeResult {
  const outputs = collectHopOutputs(fromHop, idx).filter(o => !edge.sourceExchangeId || o.sourceId === edge.sourceExchangeId)
  const reqs = toHop.exchangeIds.filter(id => !edge.targetExchangeId || id === edge.targetExchangeId).map(id => idx.entriesById.get(id)!)
  if (outputs.length === 0) return edgeFail(base, `fromHop "${fromHop.hopId}" has no timestamped host outputs.`)
  if (reqs.length === 0) return edgeFail(base, `toHop "${toHop.hopId}" has no host exchange records.`)

  const ev: Record<string, unknown> = {}
  if (edge.capabilityHandle) {
    const cap = edge.capabilityHandle
    const m = matchOrderedPair(outputs, reqs, o => o.capabilities.has(cap), r => r.consumedCapabilities?.includes(cap) ?? false)
    if (!m.ok) return edgeFail(base, m.missingTs ? `toHop "${m.missingTs}" missing timestampMs.` : m.outOfOrder ? `value_binding handle "${cap}" violated monotonic ordering (t_i > t_j).` : `value_binding handle "${cap}" not matched.`)
    ev.capabilityHandle = cap; ev.handlePair = m.pair
  }
  if (edge.valueDigest) {
    const dig = edge.valueDigest.toLowerCase()
    const m = matchOrderedPair(outputs, reqs, o => o.digests.has(dig), r => collectEntryDigests(r, 'request').has(dig))
    if (!m.ok) return edgeFail(base, m.missingTs ? `toHop "${m.missingTs}" missing timestampMs.` : m.outOfOrder ? 'value_binding digest violated monotonic ordering (t_i > t_j).' : 'value_binding sha256 digest not matched.')
    ev.valueDigest = dig; ev.digestPair = m.pair
  }
  return edgeOk(base, 'Host-signed value_binding verified with monotonic timestamps.', ev)
}

function verifyDerivedCryptoBinding(
  base: EdgeBase, edge: Extract<CausalEdgeBinding, { kind: 'derived_crypto_binding' }>,
  fromHop: HopReceipt, toHop: HopReceipt, idx: IndexedTranscript,
): VerifiedEdgeResult {
  const sources = collectHopOutputs(fromHop, idx).filter(o => o.capabilities.has(edge.sourceCapabilityId))
  if (sources.length === 0) return edgeFail(base, `sourceCapabilityId "${edge.sourceCapabilityId}" not emitted by "${fromHop.hopId}".`)
  let sawOutOfOrder = false
  for (const id of toHop.exchangeIds) {
    const entry = idx.entriesById.get(id)!
    if (!isFiniteTs(entry.timestampMs)) continue
    for (const att of entry.cryptoAttestations ?? []) {
      if (att.derivedFromCapabilityId !== edge.sourceCapabilityId) continue
      if (edge.derivedCapabilityId && att.derivedCapabilityId !== edge.derivedCapabilityId) continue
      if (edge.alg && att.alg.toLowerCase() !== edge.alg.toLowerCase()) continue
      if (!SHA256_RE.test(att.artifactDigest.toLowerCase()) || !isFiniteTs(att.timestampMs)) continue
      const src = sources.find(o => o.timestampMs <= att.timestampMs && att.timestampMs <= entry.timestampMs!)
      if (src) return edgeOk(base, 'Layer-1 derived_crypto_binding verified.', { sourceId: src.sourceId, targetExchangeId: entry.exchangeId, alg: att.alg, tSource: src.timestampMs, tDerive: att.timestampMs, tRequest: entry.timestampMs })
      sawOutOfOrder = true
    }
  }
  return edgeFail(base, sawOutOfOrder ? 'derived_crypto_binding violated monotonic ordering.' : `toHop "${toHop.hopId}" lacks Layer-1 derivedFromCapabilityId attestation.`)
}

function verifyStateTransitionBinding(
  base: EdgeBase, edge: Extract<CausalEdgeBinding, { kind: 'state_transition_binding' }>,
  fromHop: HopReceipt, toHop: HopReceipt, idx: IndexedTranscript, dagDerivedCaps: ReadonlySet<string>,
): VerifiedEdgeResult {
  const okOnEntity = (hop: HopReceipt) => hop.exchangeIds.map(id => idx.entriesById.get(id)!)
    .filter(e => is2xx(e.step.status) && isFiniteTs(e.timestampMs) && entryMatchesEntity(e, edge.entityId))
  const fromOk = okOnEntity(fromHop), toOk = okOnEntity(toHop)
  if (fromOk.length === 0) return edgeFail(base, `fromHop "${fromHop.hopId}" has no succeeding exchange on "${edge.entityId}".`)
  if (toOk.length === 0) return edgeFail(base, `toHop "${toHop.hopId}" has no succeeding exchange on "${edge.entityId}".`)
  const pair = fromOk.flatMap(f => toOk.filter(t => f.timestampMs! <= t.timestampMs!).map(t => ({ from: f, to: t })))[0]
  if (!pair) return edgeFail(base, `state_transition_binding on "${edge.entityId}" violated monotonic ordering (t_i > t_j).`)

  const hopExSet = new Set([...fromHop.exchangeIds, ...toHop.exchangeIds])
  const toUsesNewCap = (pair.to.consumedCapabilities ?? []).some(c => dagDerivedCaps.has(c))
  const toActor = actorOf(pair.to), toFam = routeFamily(pair.to.step.route ?? pair.to.step.pathAndQuery ?? '')
  let validAblation: HostTranscriptEntry | null = null

  for (const abId of edge.ablationExchangeIds) {
    if (hopExSet.has(abId)) return edgeFail(base, `Ablation exchange "${abId}" cannot reuse a hop exchange.`)
    const ab = idx.entriesById.get(abId)!
    if (!(ab.cleanSession === true && (ab.step.arm === 'control' || ab.replayAttempt === 'ablation_control'))) {
      return edgeFail(base, `Ablation exchange "${abId}" must be a clean-session control arm.`)
    }
    const st = ab.step.status
    if (typeof st === 'number' && st >= 500) return edgeFail(base, `Ablation exchange "${abId}" returned server error ${st}.`)
    if (is2xx(st) && ab.step.evidenceRole !== 'invariant_preserved') return edgeFail(base, `Ablation control "${abId}" succeeded (${st}); Hop j is not dependent on Hop i.`)
    if (!entryMatchesEntity(ab, edge.entityId) && !(toFam && routeFamily(ab.step.route ?? ab.step.pathAndQuery ?? '') === toFam)) continue
    const abActor = actorOf(ab)
    if (!toUsesNewCap && toActor && abActor && abActor !== toActor) return edgeFail(base, `Ablation "${abId}" actor "${abActor}" mismatches toHop actor "${toActor}".`)
    if ((typeof st === 'number' && ABLATION_DENIED_STATUSES.has(st)) || ab.step.evidenceRole === 'invariant_preserved') validAblation = ab
  }
  if (!validAblation) return edgeFail(base, `state_transition_binding on "${edge.entityId}" lacks a passing clean-session ablation control.`)
  return edgeOk(base, 'state_transition_binding verified with clean-session ablation control.', {
    entityId: edge.entityId, fromExchangeId: pair.from.exchangeId, toExchangeId: pair.to.exchangeId,
    ablationExchangeId: validAblation.exchangeId, ablationStatus: validAblation.step.status,
  })
}

function verifyAsyncPivotBinding(
  base: EdgeBase, edge: Extract<CausalEdgeBinding, { kind: 'async_pivot_binding' }>,
  fromHop: HopReceipt, toHop: HopReceipt, idx: IndexedTranscript, signingKey?: string,
): VerifiedEdgeResult {
  const triggers: number[] = []
  for (const id of fromHop.exchangeIds) {
    const e = idx.entriesById.get(id)!
    if (is2xx(e.step.status) && isFiniteTs(e.timestampMs) && entryMatchesCorrelation(e, edge.correlationId)) triggers.push(e.timestampMs)
  }
  for (const id of fromHop.browserTraceIds) {
    const tr = idx.tracesById.get(id)!
    if (isFiniteTs(tr.timestampMs) && tr.correlationIds?.includes(edge.correlationId)) triggers.push(tr.timestampMs)
  }
  if (triggers.length === 0) return edgeFail(base, `fromHop "${fromHop.hopId}" has no trigger matching "${edge.correlationId}".`)
  const minTrigger = Math.min(...triggers)

  if (edge.channel === 'oob_relay') {
    for (const id of edge.oobEventId ? [edge.oobEventId] : toHop.oobEventIds) {
      if (!toHop.oobEventIds.includes(id)) continue
      const oob = idx.oobById.get(id)
      const ok = oob?.delivered && isFiniteTs(oob.receivedAtMs) && (
        oob.token === edge.correlationId || oob.canaryId === edge.correlationId ||
        oob.callbackId === edge.correlationId || (oob.correlationIds?.includes(edge.correlationId) ?? false))
      if (!ok || !oob) continue
      if (oob.receivedAtMs < minTrigger) return edgeFail(base, `OOB event "${id}" preceded trigger (t_trigger > t_observed).`)
      return edgeOk(base, 'async_pivot_binding (oob_relay) verified.', { correlationId: edge.correlationId, oobEventId: id, tTrigger: minTrigger, tObserved: oob.receivedAtMs })
    }
    return edgeFail(base, `No delivered OOB event in "${toHop.hopId}" matches "${edge.correlationId}".`)
  }
  if (edge.channel === 'browser_trace') {
    for (const id of edge.browserTraceId ? [edge.browserTraceId] : toHop.browserTraceIds) {
      if (!toHop.browserTraceIds.includes(id)) continue
      const tr = idx.tracesById.get(id)
      const hasEffect = (tr?.sinks?.length ?? 0) > 0 || (tr?.emittedCapabilities?.length ?? 0) > 0
      if (!tr || !isFiniteTs(tr.timestampMs) || !hasEffect || !tr.correlationIds?.includes(edge.correlationId)) continue
      if (tr.timestampMs < minTrigger) return edgeFail(base, `Browser trace "${id}" preceded trigger (t_trigger > t_observed).`)
      return edgeOk(base, 'async_pivot_binding (browser_trace) verified.', { correlationId: edge.correlationId, browserTraceId: id, tTrigger: minTrigger, tObserved: tr.timestampMs })
    }
    return edgeFail(base, `No browser trace in "${toHop.hopId}" matches "${edge.correlationId}".`)
  }
  const polls = edge.pollRecordId ? [idx.pollsById.get(edge.pollRecordId)].filter((p): p is HostAsyncPollRecord => !!p) : idx.allPolls
  for (const poll of polls) {
    if (!poll.converged || (signingKey && !verifyHostRecordSignature(poll, signingKey))) continue
    if (poll.entityId !== edge.correlationId && !poll.correlationIds?.includes(edge.correlationId)) continue
    if (!isFiniteTs(poll.tTriggerMs) || !isFiniteTs(poll.tObservedMs)) continue
    if (poll.tObservedMs < poll.tTriggerMs || poll.tObservedMs < minTrigger) return edgeFail(base, `Async poll "${poll.id}" violated monotonic ordering.`)
    return edgeOk(base, `async_pivot_binding (${edge.channel}) verified via poll convergence.`, { correlationId: edge.correlationId, pollRecordId: poll.id, tTrigger: minTrigger, tObserved: poll.tObservedMs })
  }
  if (edge.channel === 'async_job') {
    for (const id of toHop.exchangeIds) {
      const e = idx.entriesById.get(id)!
      if (!is2xx(e.step.status) || !isFiniteTs(e.timestampMs) || !entryMatchesCorrelation(e, edge.correlationId)) continue
      if (e.timestampMs < minTrigger) return edgeFail(base, `Async job readback "${id}" preceded trigger.`)
      return edgeOk(base, 'async_pivot_binding (async_job) verified.', { correlationId: edge.correlationId, targetExchangeId: id, tTrigger: minTrigger, tObserved: e.timestampMs })
    }
  }
  return edgeFail(base, `No converged async record in "${toHop.hopId}" matches "${edge.correlationId}".`)
}

// --- Attacker-Origin Provenance & Replay Mode Policy ------------------------

function verifyAttackerProvenance(
  receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, options: CompositeVerifyOptions,
): { ok: true; derivedCapabilities: string[] } | { ok: false; reason: string } {
  const allowedSet = options.attackerPersonas?.length ? new Set(options.attackerPersonas) : null
  const forbiddenSet = new Set(options.forbiddenShortcutPersonas ?? [])
  const rootSet = new Set(dag.roots), dagCaps = new Set<string>()
  const isForbidden = (a: string | null, r: string | null) =>
    (a !== null && forbiddenSet.has(a)) || (allowedSet ? a !== null && !allowedSet.has(a) : r === 'owner')
  const isAllowed = (a: string | null, r: string | null) =>
    !(a !== null && forbiddenSet.has(a)) && (allowedSet ? a !== null && allowedSet.has(a) : r !== 'owner')

  for (const hopId of dag.topoOrder) {
    const hop = dag.hopsById.get(hopId)!
    const isRoot = rootSet.has(hopId)
    const probes = hop.exchangeIds.map(id => idx.entriesById.get(id)!).filter(e => e.step.arm === 'probe')
    if (isRoot && receipt.hops.length > 1 && probes.length === 0) return { ok: false, reason: `Root hop "${hopId}" requires an attacker-origin probe.` }
    for (const e of probes) {
      const a = actorOf(e), r = roleOf(e)
      if (isForbidden(a, r)) return { ok: false, reason: `Attacker-origin violation in "${hopId}" ("${e.exchangeId}"): pre-seeded persona "${a ?? r}" is forbidden.` }
      if (isRoot) {
        if (allowedSet && !isAllowed(a, r)) return { ok: false, reason: `Root hop "${hopId}" ("${e.exchangeId}") must start from an allowed attackerPersona.` }
      } else {
        const usesDag = (e.consumedCapabilities ?? []).some(c => dagCaps.has(c)) || (e.cryptoAttestations ?? []).some(x => dagCaps.has(x.derivedFromCapabilityId))
        if (!(a !== null && isAllowed(a, r)) && !usesDag) return { ok: false, reason: `Hop "${hopId}" ("${e.exchangeId}") lacks attacker persona or DAG-derived capability.` }
      }
    }
    recordHopCapabilities(hop, idx, dagCaps)
  }
  return { ok: true, derivedCapabilities: [...dagCaps] }
}

function verifyReplayMode(
  receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, options: CompositeVerifyOptions,
): { ok: true } | { ok: false; reason: string } {
  if (receipt.replayMode === 'fresh_clean_replay') {
    for (const hop of receipt.hops) for (const id of hop.exchangeIds) {
      const e = idx.entriesById.get(id)!
      if (e.step.arm !== 'probe') continue
      if (e.cleanSession === false) return { ok: false, reason: `Mode A rejected exchange "${id}" marked cleanSession=false.` }
      if (options.requireCleanSessionFlag && e.cleanSession !== true) return { ok: false, reason: `Mode A requires cleanSession=true on "${id}".` }
    }
    return { ok: true }
  }
  if (receipt.benchmarkMode === true || options.benchmarkMode === true) return { ok: false, reason: 'Mode B (one_shot_transcript) is forbidden in benchmarkMode.' }
  const ti = receipt.terminalImpact
  if (!ti.modeAFailureExchangeId) return { ok: false, reason: 'Mode B requires terminalImpact.modeAFailureExchangeId.' }
  const failEx = idx.entriesById.get(ti.modeAFailureExchangeId)!
  if (failEx.replayAttempt !== 'mode_a' && failEx.cleanSession !== true) return { ok: false, reason: 'modeAFailureExchangeId was not a clean-session Mode-A replay.' }
  const st = failEx.step.status
  if (!(st === 409 || st === 410 || ((st === 400 || st === 422) && CONSUMED_STATE_RE.test(serializeBodyText(failEx))))) {
    return { ok: false, reason: `Mode B rejected: Mode-A returned HTTP ${st ?? 'null'} (requires 409/410/consumed-token).` }
  }
  if (ti.preChainControlExchangeIds.length === 0) return { ok: false, reason: 'Mode B requires a pre-chain denied control on the terminal target.' }
  if (ti.postChainReadbackExchangeIds.length === 0) return { ok: false, reason: 'Mode B requires a post-chain readback proving persisted impact.' }

  const termHop = dag.hopsById.get(ti.terminalHopId)!
  const probeTs = termHop.exchangeIds.map(id => idx.entriesById.get(id)!).filter(e => e.step.arm === 'probe' && isFiniteTs(e.timestampMs)).map(e => e.timestampMs!)
  const refTs = probeTs.length > 0 ? Math.min(...probeTs) : null
  const termFam = routeFamily(termHop.target.pathAndQuery ?? '')

  const hasPre = ti.preChainControlExchangeIds.some(id => {
    const e = idx.entriesById.get(id)!
    if (e.step.arm !== 'control' || (e.step.status !== 401 && e.step.status !== 403) || !isFiniteTs(e.timestampMs)) return false
    if (refTs !== null && e.timestampMs > refTs) return false
    if (termFam && (e.step.route || e.step.pathAndQuery)) {
      const cf = routeFamily(e.step.route ?? e.step.pathAndQuery ?? '')
      if (cf && cf !== termFam && (!termHop.entityId || !entryMatchesEntity(e, termHop.entityId))) return false
    }
    return true
  })
  if (!hasPre) return { ok: false, reason: 'Mode B requires a pre-chain 401/403 control on the terminal target.' }

  const preSet = new Set(ti.preChainControlExchangeIds)
  const hasRead = ti.postChainReadbackExchangeIds.some(id => {
    if (preSet.has(id)) return false
    const e = idx.entriesById.get(id)!
    if (!is2xx(e.step.status) || !isFiniteTs(e.timestampMs) || (refTs !== null && e.timestampMs < refTs)) return false
    const isRead = stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'post_chain_readback'
    return isRead && (e.step.json !== undefined || (typeof e.step.body === 'string' && e.step.body.trim().length > 0))
  })
  return hasRead ? { ok: true } : { ok: false, reason: 'Mode B requires a post-chain 2xx readback proving persisted impact.' }
}

// --- Public Verifier & Single-Hop Bridge ------------------------------------

function toOracleRecord(e: HostTranscriptEntry, fallbackSig: string): V8OracleRecord {
  return {
    id: e.exchangeId, hostSignature: e.hostSignature ?? fallbackSig, timestampMs: isFiniteTs(e.timestampMs) && e.timestampMs > 0 ? e.timestampMs : 1,
    status: e.step.status, method: e.step.method, route: e.step.route ?? e.step.pathAndQuery, actorId: actorOf(e), tenantId: e.step.actor.tenant ?? null,
    body: e.step.body, json: e.step.json, requestHeaders: e.step.requestHeaders, responseHeaders: e.step.responseHeaders,
    capabilityHandle: e.emittedCapabilities?.[0] ?? e.consumedCapabilities?.[0] ?? null,
    artifactDigest: e.observedResponseDigests?.[0] ?? sha256Hex(e.step.body ?? JSON.stringify(e.step.json ?? null)),
    derivedFromCapabilityId: e.cryptoAttestations?.[0]?.derivedFromCapabilityId ?? null,
  }
}

function dispatchDefaultV8Oracle(
  receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, termEx: HostTranscriptEntry | undefined, options: CompositeVerifyOptions,
): { ok: true; family: V8OracleFamily } | { ok: false; reason: string; rejectedBy: string; missingEvidence: string[] } | null {
  const ti = receipt.terminalImpact
  const family = ti.oracleFamily ?? (V8_ORACLE_FAMILY_SET.has(receipt.terminalVulnClass) ? receipt.terminalVulnClass as V8OracleFamily : null)
  if (!family) return null
  const verifySignature = options.signingKey ? (rec: V8OracleRecord): boolean => { const e = idx.entriesById.get(rec.id); return e ? e.hostSignature === rec.hostSignature : rec.hostSignature.length >= 8 } : undefined
  const explicitInput = ti.oracleInput ?? options.v8OracleInput
  if (explicitInput) {
    const dec = evaluateV8OracleFamily(family, { ...explicitInput, ...(verifySignature ? { verifySignature } : {}) } as V8OracleInputMap[typeof family])
    return dec.satisfied ? { ok: true, family } : { ok: false, reason: `v8_oracle_failed (${family}): ${dec.reason}`, rejectedBy: `v8_oracle_${family}`, missingEvidence: [dec.reason] }
  }
  if (family !== 'cross_surface_pivot' || receipt.hops.length < 2) return null
  const sig = options.signingKey ? '' : 'host-verified-sig'
  const ctrl = ti.preChainControlExchangeIds.map(id => idx.entriesById.get(id)).find((e): e is HostTranscriptEntry => Boolean(e))
  const rootHop = dag.hopsById.get(dag.roots[0]!)!
  const rootEx = rootHop.exchangeIds.map(id => idx.entriesById.get(id)!).find(e => e.step.arm === 'probe') ?? idx.entriesById.get(rootHop.exchangeIds[0]!)
  if (!ctrl || !rootEx || !termEx) return { ok: false, reason: `v8_oracle_failed (${family}): missing_pivot_control_or_terminal_record`, rejectedBy: `v8_oracle_${family}`, missingEvidence: ['pre_chain_control_denied', 'cross_surface_pivot'] }
  const hops: CrossSurfaceHop[] = dag.topoOrder.map((hopId, i) => {
    const h = dag.hopsById.get(hopId)!, edge = (dag.incomingByHop.get(hopId) ?? [])[0]?.edge
    const ex = (i === dag.topoOrder.length - 1 ? termEx : h.exchangeIds.map(id => idx.entriesById.get(id)!).find(e => e.step.arm === 'probe')) ?? idx.entriesById.get(h.exchangeIds[0]!)!
    const rec = toOracleRecord(ex, sig), abl = edge?.kind === 'state_transition_binding' ? idx.entriesById.get(edge.ablationExchangeIds[0]!) : undefined
    return {
      surface: h.surface, role: i === dag.topoOrder.length - 1 ? 'terminal_impact' : h.surface === 'browser' ? 'browser_dom_trace' : h.surface === 'webhook' ? 'oob_callback' : 'trigger_write',
      record: rec, ...(edge ? { bindingKind: edge.kind } : {}), emittedArtifactDigest: h.producedCapabilities[0] ?? rec.artifactDigest,
      ...(edge?.kind === 'value_binding' ? { consumedArtifactDigest: edge.capabilityHandle ?? edge.valueDigest ?? h.consumedCapabilities[0] } : {}),
      ...(edge?.kind === 'derived_crypto_binding' ? { derivedFromCapabilityId: edge.sourceCapabilityId } : {}),
      ...(edge?.kind === 'async_pivot_binding' ? { correlationToken: edge.correlationId } : {}),
      ...(edge?.kind === 'state_transition_binding' ? { correlationToken: edge.entityId, ...(abl ? { ablationControlDenied: toOracleRecord(abl, sig) } : {}) } : {}),
    }
  })
  const postRb = ti.postChainReadbackExchangeIds.map(id => idx.entriesById.get(id)).find((e): e is HostTranscriptEntry => Boolean(e && e.exchangeId !== termEx.exchangeId))
  const dec = evaluateV8OracleFamily('cross_surface_pivot', {
    attackerOriginPersona: { actorId: actorOf(rootEx) ?? 'attacker', role: roleOf(rootEx) ?? 'member', tenantId: rootEx.step.actor.tenant ?? null, isPrivilegedPreSeeded: false },
    preChainControlDenied: toOracleRecord(ctrl, sig), hops, ...(verifySignature ? { verifySignature } : {}),
    terminalImpact: { kind: postRb ? 'privileged_mutation' : 'privileged_read', verified: true, impactDigest: sha256Hex(termEx.step.body ?? JSON.stringify(termEx.step.json ?? termEx.exchangeId)), ...(postRb ? { postImpactReadback: toOracleRecord(postRb, sig) } : {}) },
  } satisfies CrossSurfacePivotInput)
  return dec.satisfied ? { ok: true, family } : { ok: false, reason: `v8_oracle_failed (${family}): ${dec.reason}`, rejectedBy: `v8_oracle_${family}`, missingEvidence: [dec.reason] }
}

function verifyTerminalImpactGate(
  receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, verifiedEdges: VerifiedEdgeResult[],
  hostTranscript: HostSignedTranscript, options: CompositeVerifyOptions,
): { ok: true; terminalVerification?: ReceiptVerification } | { ok: false; reason: string; rejectedBy?: string; missingEvidence?: string[]; terminalVerification?: ReceiptVerification } {
  const ti = receipt.terminalImpact
  const effSummary = ti.summary !== undefined ? ti.summary : ti.claimedImpact
  if (effSummary.replace(/\s+/g, '').length < 12) {
    return { ok: false, reason: 'terminal_impact_summary_missing: terminalImpact.summary must be a meaningful non-empty description (>= 12 non-whitespace chars).', rejectedBy: 'terminal_impact_summary_missing', missingEvidence: ['terminal_impact_summary_missing'] }
  }
  const termHop = dag.hopsById.get(ti.terminalHopId)!
  if (ti.terminalExchangeId && !termHop.exchangeIds.includes(ti.terminalExchangeId)) {
    return { ok: false, reason: `terminalExchangeId "${ti.terminalExchangeId}" does not belong to terminal hop "${termHop.hopId}".`, rejectedBy: 'terminal_exchange_invalid', missingEvidence: ['terminal_exchange_in_final_hop'] }
  }
  let terminalVerification: ReceiptVerification | undefined
  if (ti.proofReceipt) {
    terminalVerification = verifyReceipt(ti.proofReceipt, hostTranscript)
    if (!terminalVerification.confirmed) return { ok: false, reason: terminalVerification.reason, terminalVerification }
  }
  if (options.verifyTerminalImpact) {
    const verdict = options.verifyTerminalImpact(receipt, hostTranscript)
    if (!verdict.confirmed) return { ok: false, reason: verdict.reason, terminalVerification }
  }
  if (ti.proofReceipt || options.verifyTerminalImpact) return { ok: true, terminalVerification }

  const termEx = ti.terminalExchangeId
    ? idx.entriesById.get(ti.terminalExchangeId)!
    : [...termHop.exchangeIds].reverse().map(id => idx.entriesById.get(id)!).find(e => e.step.arm === 'probe' && is2xx(e.step.status))
  const v8Default = dispatchDefaultV8Oracle(receipt, dag, idx, termEx, options)
  if (v8Default) return v8Default.ok ? { ok: true } : v8Default
  if (ti.terminalExchangeId && (!termEx || termEx.step.arm === 'control' || !is2xx(termEx.step.status))) {
    return { ok: false, reason: `terminalExchangeId "${ti.terminalExchangeId}" is not a succeeding probe exchange.`, rejectedBy: 'terminal_impact_unproven', missingEvidence: [TERMINAL_IMPACT_UNPROVEN_HINT] }
  }
  const hasOob = termHop.oobEventIds.some(id => idx.oobById.get(id)?.delivered === true)
  const hasBrowser = termHop.browserTraceIds.some(id => (idx.tracesById.get(id)?.sinks?.length ?? 0) > 0)
  const hasAsyncEdge = verifiedEdges.some(e => e.toHopId === termHop.hopId && e.kind === 'async_pivot_binding' && e.verified)
  const hasDerivedCryptoEdge = verifiedEdges.some(e => e.toHopId === termHop.hopId && e.kind === 'derived_crypto_binding' && e.verified)
  if (!termEx && !hasOob && !hasBrowser && !hasAsyncEdge) {
    return { ok: false, reason: `Terminal hop "${termHop.hopId}" has no succeeding terminal evidence.`, rejectedBy: 'terminal_impact_unproven', missingEvidence: [TERMINAL_IMPACT_UNPROVEN_HINT] }
  }
  const hasPostMutation = ti.postChainReadbackExchangeIds.some(id => {
    if (termEx && id === termEx.exchangeId) return false
    const e = idx.entriesById.get(id)!
    const mono = !termEx || !isFiniteTs(termEx.timestampMs) || (isFiniteTs(e.timestampMs) && e.timestampMs >= termEx.timestampMs)
    const isRead = stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'post_chain_readback'
    const hasData = e.step.json !== undefined || (typeof e.step.body === 'string' && e.step.body.trim().length > 0)
    return is2xx(e.step.status) && mono && isRead && hasData && !isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method)
  })
  const termFam = routeFamily(termEx?.step.route ?? termEx?.step.pathAndQuery ?? termHop.target.pathAndQuery ?? '')
  const ctrlCandidates = [...ti.preChainControlExchangeIds, ...termHop.exchangeIds, ...receipt.causalEdges.flatMap(ed => ed.kind === 'state_transition_binding' && ed.toHopId === termHop.hopId ? ed.ablationExchangeIds : [])]
  const hasCleanDeniedCtrl = ctrlCandidates.some(id => {
    if (termEx && id === termEx.exchangeId) return false
    const c = idx.entriesById.get(id)
    if (!c || (c.step.arm !== 'control' && c.replayAttempt !== 'ablation_control') || typeof c.step.status !== 'number' || !DENIED_CONTROL_STATUSES.has(c.step.status)) return false
    const cf = routeFamily(c.step.route ?? c.step.pathAndQuery ?? '')
    return !termFam || !cf || cf === termFam || Boolean(termHop.entityId && entryMatchesEntity(c, termHop.entityId))
  })
  const attackerTenants = new Set<string>()
  for (const rId of dag.roots) for (const exId of dag.hopsById.get(rId)!.exchangeIds) {
    const e = idx.entriesById.get(exId)!
    if (e.step.arm !== 'probe') continue
    const t = (e.step.actor.tenant ?? parseRoleLabel(e.actorRoleLabel ?? e.actorPersona ?? '').tenant ?? '').trim().toLowerCase()
    if (t) attackerTenants.add(t)
  }
  const respTenants = termEx ? entryTenants(termEx) : new Set<string>()
  const hasBody = Boolean(termEx && (termEx.step.json !== undefined || (typeof termEx.step.body === 'string' && termEx.step.body.trim().length > 0)))
  const isStub = Boolean(termEx && hasBody && isJobOrHandleStub(termEx.step.json, termEx.step.body, termEx.step.status, termEx.step.method))
  if (isStub && !hasPostMutation) return { ok: false, reason: TERMINAL_IMPACT_UNPROVEN_HINT, rejectedBy: 'terminal_impact_unproven', missingEvidence: [TERMINAL_IMPACT_UNPROVEN_HINT] }
  const ownTenantOnly = respTenants.size > 0 && attackerTenants.size > 0 && [...respTenants].every(t => attackerTenants.has(t))
  if (termEx && ownTenantOnly && !hasPostMutation && !hasCleanDeniedCtrl) return { ok: false, reason: TERMINAL_IMPACT_UNPROVEN_HINT, rejectedBy: 'terminal_impact_unproven', missingEvidence: [TERMINAL_IMPACT_UNPROVEN_HINT] }
  if (STRICT_TERMINAL_CLASS_RE.test(receipt.terminalVulnClass)) {
    if (!hasCleanDeniedCtrl && !hasOob && !hasBrowser && !(receipt.terminalVulnClass === 'cryptographic_scope_replay' && hasDerivedCryptoEdge)) {
      return { ok: false, reason: `Missing clean denied control (401/403/404) on terminal target for ${receipt.terminalVulnClass}. ${TERMINAL_IMPACT_UNPROVEN_HINT}`, rejectedBy: 'terminal_impact_unproven', missingEvidence: ['clean_denied_control_401_403_404', TERMINAL_IMPACT_UNPROVEN_HINT] }
    }
    if (termEx && !hasPostMutation && (!hasBody || isStub || ownTenantOnly)) return { ok: false, reason: TERMINAL_IMPACT_UNPROVEN_HINT, rejectedBy: 'terminal_impact_unproven', missingEvidence: [TERMINAL_IMPACT_UNPROVEN_HINT] }
  }
  return { ok: true }
}

export function verifyCompositeReceipt(rawReceipt: unknown, hostTranscript: HostSignedTranscript, options: CompositeVerifyOptions = {}): CompositeReceiptVerification {
  const parsed = compositeProofReceiptSchema.safeParse(rawReceipt)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    return { confirmed: false, chainId: 'invalid', terminalVulnClass: 'invalid', replayMode: 'fresh_clean_replay', modeBVerified: false, hopCount: 0, verifiedEdges: [], failedStage: 'schema', reason: `Schema validation failed: ${issue?.path.join('.') || 'receipt'} ${issue?.message ?? ''}`.slice(0, 400) }
  }
  const receipt = parsed.data
  const fail = (failedStage: CompositeFailureStage, reason: string, verifiedEdges: VerifiedEdgeResult[] = [], terminalVerification?: ReceiptVerification, rejectedBy?: string, missingEvidence?: string[]): CompositeReceiptVerification => ({
    confirmed: false, chainId: receipt.chainId, terminalVulnClass: receipt.terminalVulnClass, replayMode: receipt.replayMode,
    modeBVerified: false, hopCount: receipt.hops.length, verifiedEdges, failedStage, reason,
    ...(rejectedBy ? { rejectedBy } : {}), ...(missingEvidence?.length ? { missingEvidence } : {}), ...(terminalVerification ? { terminalVerification } : {}),
  })
  const dagRes = validateDagTopology(receipt)
  if (!dagRes.ok) return fail('dag_topology', dagRes.reason)
  const idxRes = indexAndVerifyCitations(receipt, hostTranscript, options.signingKey)
  if (!idxRes.ok) return fail('transcript_integrity', idxRes.reason)
  const { dag } = dagRes, { idx } = idxRes
  const verifiedEdges: VerifiedEdgeResult[] = [], knownCaps = new Set<string>()
  for (const hopId of dag.topoOrder) {
    for (const { edgeIndex, edge } of dag.incomingByHop.get(hopId) ?? []) {
      const base: EdgeBase = { edgeIndex, kind: edge.kind, fromHopId: edge.fromHopId, toHopId: edge.toHopId }
      const fromHop = dag.hopsById.get(edge.fromHopId)!, toHop = dag.hopsById.get(edge.toHopId)!
      const res = edge.kind === 'value_binding' ? verifyValueBinding(base, edge, fromHop, toHop, idx)
        : edge.kind === 'derived_crypto_binding' ? verifyDerivedCryptoBinding(base, edge, fromHop, toHop, idx)
          : edge.kind === 'state_transition_binding' ? verifyStateTransitionBinding(base, edge, fromHop, toHop, idx, knownCaps)
            : verifyAsyncPivotBinding(base, edge, fromHop, toHop, idx, options.signingKey)
      verifiedEdges.push(res)
      if (!res.verified) return fail('edge_binding', res.reason, verifiedEdges)
    }
    recordHopCapabilities(dag.hopsById.get(hopId)!, idx, knownCaps)
  }
  const provRes = verifyAttackerProvenance(receipt, dag, idx, options)
  if (!provRes.ok) return fail('attacker_provenance', provRes.reason, verifiedEdges)
  const replayRes = verifyReplayMode(receipt, dag, idx, options)
  if (!replayRes.ok) return fail('replay_mode', replayRes.reason, verifiedEdges)
  const termRes = verifyTerminalImpactGate(receipt, dag, idx, verifiedEdges, hostTranscript, options)
  if (!termRes.ok) return fail('terminal_impact', termRes.reason, verifiedEdges, termRes.terminalVerification, termRes.rejectedBy, termRes.missingEvidence)
  return {
    confirmed: true, chainId: receipt.chainId, terminalVulnClass: receipt.terminalVulnClass, replayMode: receipt.replayMode,
    modeBVerified: receipt.replayMode === 'one_shot_transcript', hopCount: receipt.hops.length, verifiedEdges,
    reason: `CompositeProofReceipt confirmed (${receipt.hops.length} hop(s), ${verifiedEdges.length} verified causal edge(s), mode=${receipt.replayMode}).`,
    ...(termRes.terminalVerification ? { terminalVerification: termRes.terminalVerification } : {}),
    evidence: { topoOrder: dag.topoOrder, roots: dag.roots, derivedCapabilities: provRes.derivedCapabilities },
  }
}

/** Wrap a single-hop v7 ProofReceipt as a valid 1-node CompositeProofReceipt DAG. */
export function singleReceiptToComposite(rawReceipt: ProofReceipt, options?: { chainId?: string; surface?: HopSurface; replayMode?: ReplayMode; benchmarkMode?: boolean }): CompositeProofReceipt {
  const receipt = proofReceiptSchema.parse(rawReceipt)
  const surface: HopSurface = options?.surface ?? (receipt.browserTraceIds.length > 0 ? 'browser' : receipt.oobEventIds.length > 0 ? 'webhook' : receipt.target.pathAndQuery?.includes('/graphql') ? 'graphql' : 'http')
  const digest = sha256Hex(JSON.stringify({ v: receipt.vulnClass, o: receipt.target.origin, p: receipt.target.pathAndQuery ?? '', ex: receipt.exchangeIds, oob: receipt.oobEventIds, tr: receipt.browserTraceIds })).slice(0, 16)
  return compositeProofReceiptSchema.parse({
    chainId: options?.chainId ?? `single:${digest}`, terminalVulnClass: receipt.vulnClass,
    hops: [{ hopId: 'hop_1', surface, target: receipt.target, exchangeIds: receipt.exchangeIds, oobEventIds: receipt.oobEventIds, browserTraceIds: receipt.browserTraceIds, claimedDelta: receipt.claimedDelta, proofReceipt: receipt }],
    causalEdges: [], terminalImpact: { terminalHopId: 'hop_1', claimedImpact: receipt.claimedDelta, proofReceipt: receipt, preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
    replayMode: options?.replayMode ?? 'fresh_clean_replay', ...(options?.benchmarkMode !== undefined ? { benchmarkMode: options.benchmarkMode } : {}),
  })
}
