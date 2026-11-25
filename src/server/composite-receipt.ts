/**
 * CompositeProofReceipt — unified multi-hop DAG confirmation verifier (v8).
 * Verifies 1..8 hop causal chains over host-signed transcripts, provenance, Mode-A/B replay, and terminal-impact oracles.
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { z } from 'zod'
import { scopedAssetOrigin } from '../domain.ts'
import { parseRoleLabel, routeFamily, stepReadsState } from './oracle-invariants.ts'
import { proofReceiptSchema, receiptIdSchema, verifyReceipt } from './proof-receipt.ts'
import { evaluateV8OracleFamily, extractTenantMarkers, isJobOrHandleStub } from './v8-oracle-families.ts'
import type { CrossSurfaceHop, CrossSurfacePivotInput, HostSignedRecord as V8OracleRecord, V8OracleFamily, V8OracleInputMap } from './v8-oracle-families.ts'
import { hydrateV8OracleInput, matchesHydratedRecord, selectStateTransitionPair, toOracleRecord } from './v8-oracle-hydrate.ts'
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
}).transform(ti => { const ci = ti.claimedImpact && ti.claimedImpact.length > 0 ? ti.claimedImpact : (ti.summary ?? ''); return { ...ti, claimedImpact: ci, ...(ti.summary === undefined && ci.length > 0 ? { summary: ci } : {}) } })
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
  terminalOracleFamily?: V8OracleFamily | string | null; terminalEndpoint?: string | null
  terminalVerification?: ReceiptVerification; evidence?: Record<string, unknown>
}

// --- Cryptographic, Hashing & Transcript Helpers ----------------------------
const CONSUMED_STATE_RE =
  /\b(?:already[_\s-]?(?:consumed|redeemed|used|claimed|applied|settled)|token[_\s-]?(?:consumed|used|redeemed|spent)|one[_\s-]?time|nonce[_\s-]?(?:used|replayed|consumed)|invite[_\s-]?(?:redeemed|consumed|used)|state[_\s-]?(?:consumed|exhausted|finalized))\b/i
const ABLATION_DENIED_STATUSES = new Set([401, 403, 404, 409, 412, 422])
const DENIED_CONTROL_STATUSES = new Set([401, 403, 404])
const SHA256_RE = /^[0-9a-f]{64}$/
const CROSS_TENANT_CLASS_RE =
  /^(?:dual_tenant_abac|parser_cache_differential)$|dual[_-]?tenant|cross[_-]?tenant|tenant[_-]?(?:isolation|bleed|leak|export)|abac|cache[_-]?(?:bleed|poison|deception|diff|bypass)|export[_-]?(?:bypass|leak|disclosure)|presign|cwe[-_]?(?:444|639)|\bidor\b|\bbola\b/i
const STRICT_TERMINAL_CLASS_RE =
  /^(?:dual_tenant_abac|parser_cache_differential|temporal_revocation|economic_conservation|cryptographic_scope_replay|cross_surface_pivot)$|dual[_-]?tenant|cross[_-]?tenant[_-]?(?:export|data|access|leak|bleed|disclosure|pivot)|tenant[_-]?(?:isolation|bleed|leak|export)|abac|cache[_-]?(?:bleed|poison|deception|diff|bypass)|parser[_-]?diff|smuggl|presign|export[_-]?(?:bypass|leak|disclosure)|broken[_-]?access|access[_-]?control|authz[_-]?bypass|authorization[_-]?bypass|info(?:rmation)?[_-]?disclosure|data[_-]?exposure|cwe[-_]?(?:200|269|284|285|345|436|444|522|639|668|862|863)|\bidor\b|\bbola\b/i
const TERMINAL_IMPACT_UNPROVEN_HINT =
  "terminal_impact_unproven: obtaining a job/export handle, signed URL, or cache ack is an intermediate capability (seal with ctx.seal_capability), NOT terminal impact — fetch the target resource with the derived URL/handle to prove unauthorized foreign-tenant data exposure or privileged state mutation, or settle with record_coverage(status='ruled_out', proofGapReason='invariant_enforced_hardened') if blocked"
const ANON_ACTOR_RE = /^(?:anon(?:ymous)?|unauth(?:enticated)?|guest)$/i
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
const normRouteFam = (p: string | null | undefined, eid?: string): string => !p ? '' : routeFamily(p.split(/[?#]/, 1)[0]!.split('/').map(s => (s && ((eid && s === eid) || /^\d+$/.test(s))) ? ':id' : s).join('/'))
const actorOf = (e: HostTranscriptEntry): string | null => (e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null))
const roleOf = (e: HostTranscriptEntry): string | null => (e.actorRoleLabel ? parseRoleLabel(e.actorRoleLabel).role : (e.step.actor.role ?? null))
const probeTenantOf = (e: HostTranscriptEntry): string | null => { const a = actorOf(e); return (!a || ANON_ACTOR_RE.test(a) || a.startsWith('cap:')) ? null : ((e.step.actor.tenant ?? parseRoleLabel(e.actorRoleLabel ?? e.actorPersona ?? '').tenant ?? '').trim().toLowerCase() || null) }
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
    const pq = entry.step.pathAndQuery ?? '', q = pq.indexOf('?')
    for (const seg of (q >= 0 ? pq.slice(0, q) : pq).split('/')) if (seg) { leaves.add(seg); try { const d = decodeURIComponent(seg); if (d !== seg) leaves.add(d) } catch { /* ignore */ } }
    if (q >= 0) for (const v of new URLSearchParams(pq.slice(q + 1)).values()) if (v) leaves.add(v)
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
  const eid = entityId.trim(), lid = eid.toLowerCase(), esc = eid.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), path = entry.step.pathAndQuery ?? entry.step.route ?? ''
  if (!eid) return false; if (entry.entityId?.trim().toLowerCase() === lid || entry.correlationIds?.some(c => c.trim().toLowerCase() === lid) || (path && new RegExp(`(?:^|[/=?&])${esc}(?:$|[/&?#])`, 'i').test(path))) return true
  for (const leaf of entryLeaves(entry, false)) if (leaf.toLowerCase() === lid) return true
  return eid.length >= 4 && new RegExp(`(?:^|[^A-Za-z0-9_-])${esc}(?:$|[^A-Za-z0-9_-])`, 'i').test(entry.carrierText ?? '')
}
const entryMatchesCorrelation = (entry: HostTranscriptEntry, correlationId: string): boolean => Boolean(entry.correlationIds?.includes(correlationId) || entry.entityId === correlationId || entry.carrierText?.includes(correlationId)) || [...entryLeaves(entry, true)].some(leaf => leaf.includes(correlationId))
function serializeBodyText(entry: HostTranscriptEntry): string {
  try { return typeof entry.step.body === 'string' && entry.step.body.length > 0 ? entry.step.body : entry.step.json !== undefined ? JSON.stringify(entry.step.json) : '' } catch { return '' }
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
  const checkProof = (pr: ProofReceipt | undefined, label: string): string | null => !pr ? null
    : checkAll(pr.exchangeIds, entriesById, `${label} exchange`) ?? checkAll(pr.oobEventIds, oobById, `${label} OOB event`) ?? checkAll(pr.browserTraceIds, tracesById, `${label} browser trace`)
  for (const h of receipt.hops) {
    const err = checkAll(h.exchangeIds, entriesById, `hop "${h.hopId}" exchange`) ?? checkAll(h.oobEventIds, oobById, `hop "${h.hopId}" OOB event`) ?? checkAll(h.browserTraceIds, tracesById, `hop "${h.hopId}" browser trace`) ?? checkProof(h.proofReceipt, `hop "${h.hopId}" proofReceipt`)
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
    ?? checkProof(ti.proofReceipt, 'terminal proofReceipt')
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
type EdgeBase = { edgeIndex: number; kind: CausalEdgeKind; fromHopId: string; toHopId: string; fromEx?: readonly string[]; toEx?: readonly string[] }
const EDGE_FIX_HINTS: Record<CausalEdgeKind, string> = {
  value_binding: 'Interpolate the sealed cap:... handle into the downstream request or pass capability: { handle } so the host attests consumedCapabilities / cryptoAttestations.',
  derived_crypto_binding: 'Derive via crypto.hmacSign/crypto.jwtSign and interpolate the signature or derived cap:... handle (or pass capability: { handle }) so the host attests consumedCapabilities / cryptoAttestations.',
  state_transition_binding: 'Pass entityId on both hops and cite a clean-session denied control (replayAttempt: "ablation_control") in ablationExchangeIds.',
  async_pivot_binding: 'Pass matching correlationId on the trigger and downstream OOB/browser/async.awaitResult exchange in monotonic timestamp order.',
}
const edgeFail = ({ fromEx = [], toEx = [], ...pub }: EdgeBase, reason: string): VerifiedEdgeResult => ({ ...pub, verified: false, reason: `Edge #${pub.edgeIndex} (${pub.kind} ${pub.fromHopId}->${pub.toHopId}, from=[${fromEx.join(',') || 'none'}] to=[${toEx.join(',') || 'none'}]): ${reason} Fix: ${EDGE_FIX_HINTS[pub.kind]}` })
const edgeOk = ({ fromEx: _f, toEx: _t, ...pub }: EdgeBase, reason: string, evidence?: Record<string, unknown>): VerifiedEdgeResult => ({ ...pub, verified: true, reason, ...(evidence ? { evidence } : {}) })

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
  matchOut: (o: HopOutputEvent) => boolean, matchReq: (r: HostTranscriptEntry, o: HopOutputEvent) => boolean | 'out_of_order',
): { ok: true; pair: { from: string; to: string; tFrom: number; tTo: number } } | { ok: false; outOfOrder: boolean; missingTs?: string } {
  let outOfOrder = false
  for (const o of outputs) if (matchOut(o)) for (const r of reqs) {
    const hit = matchReq(r, o)
    if (!hit) continue
    if (!isFiniteTs(r.timestampMs)) return { ok: false, outOfOrder: false, missingTs: r.exchangeId }
    if (hit === true && o.timestampMs <= r.timestampMs) return { ok: true, pair: { from: o.sourceId, to: r.exchangeId, tFrom: o.timestampMs, tTo: r.timestampMs } }
    outOfOrder = true
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
    const cap = edge.capabilityHandle, matchCap = (r: HostTranscriptEntry, o: HopOutputEvent): boolean | 'out_of_order' => {
      if ((r.consumedCapabilities?.includes(cap) ?? false) || r.actorPersona === cap) return true
      const atts = (r.cryptoAttestations ?? []).filter(a => (a.derivedFromCapabilityId === cap || a.derivedCapabilityId === cap) && SHA256_RE.test(a.artifactDigest.toLowerCase()) && isFiniteTs(a.timestampMs))
      return atts.length === 0 ? false : atts.some(a => o.timestampMs <= a.timestampMs && (!isFiniteTs(r.timestampMs) || a.timestampMs <= r.timestampMs)) ? true : 'out_of_order'
    }, m = matchOrderedPair(outputs, reqs, o => o.capabilities.has(cap), matchCap)
    if (!m.ok) return edgeFail(base, m.missingTs ? `toHop "${m.missingTs}" missing timestampMs.` : m.outOfOrder ? `value_binding handle "${cap}" violated monotonic ordering (t_i > t_j).` : `value_binding handle "${cap}" not matched.`)
    ev.capabilityHandle = cap; ev.handlePair = m.pair
  }
  if (edge.valueDigest) {
    const dig = edge.valueDigest.toLowerCase(), m = matchOrderedPair(outputs, reqs, o => o.digests.has(dig), r => collectEntryDigests(r, 'request').has(dig))
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
  const hopEntries = (hop: HopReceipt) => hop.exchangeIds.map(id => idx.entriesById.get(id)!)
  const hopDiag = (hop: HopReceipt, side: string) => { const es = hopEntries(hop); return `[${side}Ok=0: exchanges=${es.length}, 2xx=${es.filter(e => is2xx(e.step.status)).length}, timestamped=${es.filter(e => isFiniteTs(e.timestampMs)).length}, entityMatch=${es.filter(e => entryMatchesEntity(e, edge.entityId)).length}]` }
  const sel = selectStateTransitionPair(edge.entityId, hopEntries(fromHop), hopEntries(toHop), dagDerivedCaps, { actorOf, probeTenantOf, entryMatchesEntity, anonActorRe: ANON_ACTOR_RE })
  if (!sel.ok) {
    if (sel.reason === 'non_monotonic') return edgeFail(base, `state_transition_binding on "${edge.entityId}" violated monotonic ordering (t_i > t_j).`)
    const side = sel.reason === 'missing_to' || sel.missingSide === 'to' ? 'to' : 'from', hop = side === 'to' ? toHop : fromHop
    return edgeFail(base, `${side}Hop "${hop.hopId}" has no succeeding exchange on "${edge.entityId}" ${hopDiag(hop, side)}${sel.reason === 'actor_discontinuity' ? ' [actor_discontinuity]' : ''}.`)
  }
  const pair = { from: sel.from, to: sel.to }, { logicalFallback } = sel
  const hopExSet = new Set([...fromHop.exchangeIds, ...toHop.exchangeIds])
  const toUsesNewCap = (pair.to.consumedCapabilities ?? []).some(c => dagDerivedCaps.has(c)) || (pair.to.cryptoAttestations ?? []).some(x => dagDerivedCaps.has(x.derivedFromCapabilityId))
  const toActor = actorOf(pair.to), toFam = normRouteFam(pair.to.step.route ?? pair.to.step.pathAndQuery, edge.entityId)
  const normActor = (a: string | null) => (!a || ANON_ACTOR_RE.test(a.trim())) ? null : a.trim().toLowerCase()
  // Sibling is untouched when no succeeding state-changing exchange on it precedes the ablation (missing timestamps count as touched).
  const touchedBefore = (eid: string, ab: HostTranscriptEntry) => [...idx.entriesById.values()].some(e => e.exchangeId !== ab.exchangeId && is2xx(e.step.status) && !stepReadsState(e.step) && (!isFiniteTs(e.timestampMs) || !isFiniteTs(ab.timestampMs) || e.timestampMs <= ab.timestampMs) && entryMatchesEntity(e, eid))
  let validAblation: HostTranscriptEntry | null = null; const diags: string[] = []
  for (const abId of edge.ablationExchangeIds) {
    if (hopExSet.has(abId)) return edgeFail(base, `Ablation exchange "${abId}" cannot reuse a hop exchange [hop_exchange_reuse].`)
    const ab = idx.entriesById.get(abId)!, st = ab.step.status, denied = typeof st === 'number' && ABLATION_DENIED_STATUSES.has(st)
    if (ab.cleanSession === false) return edgeFail(base, `Ablation exchange "${abId}" had cleanSession=false (session/entity already mutated); run the ablation control BEFORE Hop "${fromHop.hopId}" or on a fresh untouched sibling entity (pass entityId).`)
    if (typeof st === 'number' && st >= 500) return edgeFail(base, `Ablation exchange "${abId}" returned server error ${st} [status=5xx].`)
    if (is2xx(st) && (logicalFallback || ab.step.evidenceRole !== 'invariant_preserved')) return edgeFail(base, `Ablation control "${abId}" succeeded (${st}) [status=2xx]; Hop j is not dependent on Hop i.`)
    const labeled = ab.cleanSession === true && (ab.step.arm === 'control' || ab.replayAttempt === 'ablation_control')
    const sameRouteFam = Boolean(toFam) && normRouteFam(ab.step.route ?? ab.step.pathAndQuery, ab.entityId ?? edge.entityId) === toFam
    if (logicalFallback ? !sameRouteFam : (!entryMatchesEntity(ab, edge.entityId) && !sameRouteFam)) { diags.push(`${abId}: route_family_mismatch (entity and toHop route family "${toFam || 'none'}" unmatched)`); continue }
    if (!labeled) { // unlabeled clean-session denial: sound only before Hop i ran or on a host-bound untouched sibling; never 2xx/dirty/mutated
      const before = isFiniteTs(ab.timestampMs) && ab.timestampMs < pair.from.timestampMs!
      const sibling = Boolean(ab.entityId && ab.entityId.trim().toLowerCase() !== edge.entityId.trim().toLowerCase() && !touchedBefore(ab.entityId, ab))
      if (ab.cleanSession !== true || !denied || !(before || sibling)) { diags.push(`${abId}: unlabeled_control (cleanSession=${ab.cleanSession ?? 'unset'}, status=${st ?? 'null'}, beforeFromHop=${before}, untouchedSibling=${sibling}; pass role: "control")`); continue }
    }
    const abActor = actorOf(ab)
    if (!toUsesNewCap && toActor && (logicalFallback ? normActor(abActor) !== normActor(toActor) : (abActor && abActor !== toActor))) return edgeFail(base, `Ablation "${abId}" actor "${abActor ?? 'anon'}" mismatches toHop actor "${toActor}" [actor_mismatch].`)
    if (denied || (!logicalFallback && labeled && ab.step.evidenceRole === 'invariant_preserved')) validAblation = ab
    else diags.push(`${abId}: status=${st ?? 'null'} not a denial (401/403/404/409/412/422)`)
  }
  if (!validAblation) return edgeFail(base, `state_transition_binding on "${edge.entityId}" lacks a passing clean-session ablation control [${diags.join('; ') || 'no ablationExchangeIds cited'}].`)
  return edgeOk(base, 'state_transition_binding verified with clean-session ablation control.', { entityId: edge.entityId, fromExchangeId: pair.from.exchangeId, toExchangeId: pair.to.exchangeId, ablationExchangeId: validAblation.exchangeId, ablationStatus: validAblation.step.status, ...(logicalFallback ? { bindingMode: 'logical_key_ablation' } : {}) })
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
): { ok: true; derivedCapabilities: string[]; attackerTenants: ReadonlySet<string> } | { ok: false; reason: string } {
  const allowedSet = options.attackerPersonas?.length ? new Set(options.attackerPersonas) : null
  const forbiddenSet = new Set(options.forbiddenShortcutPersonas ?? [])
  const rootSet = new Set(dag.roots), dagCaps = new Set<string>(), probeTenants = new Set<string>()
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
      const pt = probeTenantOf(e); if (pt) probeTenants.add(pt)
    }
    recordHopCapabilities(hop, idx, dagCaps)
  }
  if (probeTenants.size > 1) return { ok: false, reason: `Cross-tenant probe-arm persona mismatch: pre-seeded probe hops mixed distinct tenants (${[...probeTenants].sort().join(', ')}). All pre-seeded probe-arm hops must belong to a single starting tenant (or anonymous/DAG-minted credentials); use target-tenant personas only on control or readback arms.` }
  return { ok: true, derivedCapabilities: [...dagCaps], attackerTenants: probeTenants }
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
    return isRead && (e.step.json !== undefined || (typeof e.step.body === 'string' && e.step.body.trim().length > 0)) && !isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method, e.step.route ?? e.step.pathAndQuery)
  })
  return hasRead ? { ok: true } : { ok: false, reason: 'Mode B requires a post-chain 2xx readback proving persisted impact.' }
}

// --- Public Verifier & Single-Hop Bridge ------------------------------------
type DefaultV8Ctx = { termEndpoint: string; termFam: string; hasOob: boolean; hasBrowser: boolean; hasBody: boolean; isStub: boolean; ownTenantOnly: boolean }

function dispatchDefaultV8Oracle(
  receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, termEx: HostTranscriptEntry | undefined, options: CompositeVerifyOptions,
  terminalCtrl: HostTranscriptEntry | undefined, postMutRb: HostTranscriptEntry | undefined, ctx: DefaultV8Ctx,
): { ok: true; family: V8OracleFamily; explicit: boolean } | { ok: false; reason: string; rejectedBy: string; missingEvidence: string[] } | null {
  const ti = receipt.terminalImpact, normCls = receipt.terminalVulnClass.trim().toLowerCase()
  const family = ti.oracleFamily ?? (V8_ORACLE_FAMILY_SET.has(normCls) ? normCls as V8OracleFamily : null)
  if (!family) return null
  const sig = options.signingKey ? '' : 'host-verified-sig'
  const verifySignature = (rec: V8OracleRecord): boolean => {
    const e = idx.entriesById.get(rec.id) ?? idx.oobById.get(rec.id) ?? idx.tracesById.get(rec.id) ?? idx.pollsById.get(rec.id)
    if (!e || (options.signingKey && (e.hostSignature !== rec.hostSignature || !verifyHostRecordSignature(e, options.signingKey)))) return false
    return idx.pollsById.has(rec.id) || matchesHydratedRecord(rec, idx, sig)
  }
  const rejectFam = (reason: string, missingEvidence: string[], rejectedBy = `v8_oracle_${family}`) => ({ ok: false as const, reason, rejectedBy, missingEvidence })
  const mapFail = (reason: string) => (reason === 'terminal_impact_unproven_intermediate_stub' || reason === 'bled_access_own_tenant_only')
    ? rejectFam(TERMINAL_IMPACT_UNPROVEN_HINT, [TERMINAL_IMPACT_UNPROVEN_HINT], 'terminal_impact_unproven')
    : rejectFam(`v8_oracle_failed (${family}): ${reason}`, [reason])
  const econCtx = { preChainControlExchangeIds: ti.preChainControlExchangeIds, termHopExchangeIds: dag.hopsById.get(ti.terminalHopId)!.exchangeIds, postChainReadbackExchangeIds: ti.postChainReadbackExchangeIds }
  const explicitInput = ti.oracleInput ?? options.v8OracleInput
  if (explicitInput) {
    const hydrated = hydrateV8OracleInput(family, explicitInput, idx, sig, econCtx)
    const dec = evaluateV8OracleFamily(family, { ...hydrated, verifySignature } as V8OracleInputMap[typeof family])
    return dec.satisfied ? { ok: true, family, explicit: true } : mapFail(dec.reason)
  }
  if (family === 'economic_conservation') {
    const hydrated = hydrateV8OracleInput(family, {}, idx, sig, econCtx)
    const dec = evaluateV8OracleFamily(family, { ...hydrated, verifySignature } as V8OracleInputMap['economic_conservation'])
    const reason = dec.reason === 'unknown_economic_equation' ? 'missing_economic_oracle_input' : dec.reason
    return rejectFam(`v8_oracle_failed (economic_conservation): ${reason} — provide terminalImpact.oracleInput.`, [reason, 'terminalImpact.oracleInput'])
  }
  if (family === 'cross_surface_pivot') {
    if (receipt.hops.length < 2) return rejectFam('v8_oracle_failed (cross_surface_pivot): invalid_hop_count — requires >= 2 hops across distinct surfaces.', ['cross_surface_pivot_requires_2_plus_hops'])
    const rootHop = dag.hopsById.get(dag.roots[0]!)!
    const rootEx = rootHop.exchangeIds.map(id => idx.entriesById.get(id)!).find(e => e.step.arm === 'probe') ?? idx.entriesById.get(rootHop.exchangeIds[0]!)
    if (!terminalCtrl || !rootEx || !termEx) return rejectFam(`v8_oracle_failed (${family}): missing_pivot_control_or_terminal_record`, ['pre_chain_control_denied', TERMINAL_IMPACT_UNPROVEN_HINT])
    const hops: CrossSurfaceHop[] = dag.topoOrder.map((hopId, i) => {
      const h = dag.hopsById.get(hopId)!, edge = (dag.incomingByHop.get(hopId) ?? [])[0]?.edge
      const outCorr = receipt.causalEdges.find(e => e.fromHopId === hopId && (e.kind === 'async_pivot_binding' || e.kind === 'state_transition_binding'))
      const outArt = receipt.causalEdges.find(e => e.fromHopId === hopId && (e.kind === 'value_binding' || e.kind === 'derived_crypto_binding'))
      const ex = (i === dag.topoOrder.length - 1 ? termEx : h.exchangeIds.map(id => idx.entriesById.get(id)!).find(e => e.step.arm === 'probe')) ?? idx.entriesById.get(h.exchangeIds[0]!)!
      const rec = toOracleRecord(ex, sig), abl = edge?.kind === 'state_transition_binding' ? idx.entriesById.get(edge.ablationExchangeIds[0]!) : undefined
      const corr = (edge?.kind === 'async_pivot_binding' ? edge.correlationId : edge?.kind === 'state_transition_binding' ? edge.entityId : undefined) ?? (outCorr?.kind === 'async_pivot_binding' ? outCorr.correlationId : outCorr?.kind === 'state_transition_binding' ? outCorr.entityId : undefined) ?? ex.correlationIds?.[0] ?? h.entityId
      const emitted = (outArt?.kind === 'value_binding' ? (outArt.capabilityHandle ?? outArt.valueDigest) : outArt?.kind === 'derived_crypto_binding' ? outArt.sourceCapabilityId : undefined) ?? h.producedCapabilities[0] ?? rec.artifactDigest
      return {
        surface: h.surface, role: i === dag.topoOrder.length - 1 ? 'terminal_impact' : h.surface === 'browser' ? 'browser_dom_trace' : h.surface === 'webhook' ? 'oob_callback' : 'trigger_write',
        record: rec, ...(edge ? { bindingKind: edge.kind } : {}), emittedArtifactDigest: emitted, ...(corr ? { correlationToken: corr } : {}),
        ...(edge?.kind === 'value_binding' ? { consumedArtifactDigest: edge.capabilityHandle ?? edge.valueDigest ?? h.consumedCapabilities[0] } : {}),
        ...(edge?.kind === 'derived_crypto_binding' ? { derivedFromCapabilityId: edge.sourceCapabilityId } : {}), ...(edge?.kind === 'state_transition_binding' && abl ? { ablationControlDenied: toOracleRecord(abl, sig) } : {}),
      }
    })
    const dec = evaluateV8OracleFamily('cross_surface_pivot', {
      attackerOriginPersona: { actorId: actorOf(rootEx) ?? 'attacker', role: roleOf(rootEx) ?? 'member', tenantId: rootEx.step.actor.tenant ?? null, isPrivilegedPreSeeded: false },
      preChainControlDenied: toOracleRecord(terminalCtrl, sig), hops, verifySignature,
      terminalImpact: { kind: postMutRb ? 'privileged_mutation' : 'privileged_read', verified: true, impactDigest: sha256Hex(termEx.step.body ?? JSON.stringify(termEx.step.json ?? termEx.exchangeId)), ...(postMutRb ? { postImpactReadback: toOracleRecord(postMutRb, sig) } : {}) },
    } satisfies CrossSurfacePivotInput)
    return dec.satisfied ? { ok: true, family, explicit: false } : mapFail(dec.reason)
  }
  if (ctx.isStub && !postMutRb) return mapFail('terminal_impact_unproven_intermediate_stub')
  if (ctx.ownTenantOnly && !postMutRb && family !== 'temporal_revocation') return mapFail('bled_access_own_tenant_only')
  const isStrictFam = family === 'cryptographic_scope_replay' || family === 'temporal_revocation'
  const rejBy = isStrictFam ? `v8_oracle_${family}` : 'terminal_impact_unproven'
  if (!terminalCtrl && !ctx.hasOob && !ctx.hasBrowser) return rejectFam(`v8_oracle_failed (${family}): missing_denied_control_on_terminal_route — execute a clean denied control (401/403/404) on the exact terminal route family. ${TERMINAL_IMPACT_UNPROVEN_HINT}`, ['clean_denied_control_401_403_404', TERMINAL_IMPACT_UNPROVEN_HINT], rejBy)
  if (!ctx.hasOob && !ctx.hasBrowser && ((!termEx && !postMutRb) || !ctx.termEndpoint || !ctx.termFam || (termEx && !postMutRb && !ctx.hasBody))) return rejectFam(`v8_oracle_failed (${family}): missing_terminal_exchange_or_endpoint — provide a concrete succeeding terminal exchange with non-empty route and substantive payload (or verified post-mutation readback). ${TERMINAL_IMPACT_UNPROVEN_HINT}`, ['terminal_exchange_with_endpoint', TERMINAL_IMPACT_UNPROVEN_HINT], rejBy)
  if (isStrictFam && receipt.hops.length < 2) return rejectFam(`v8_oracle_failed (${family}): missing_upstream_hop — ${family} requires terminalImpact.oracleInput or a >= 2-hop causal chain.`, ['upstream_causal_hop_or_oracle_input'])
  return { ok: true, family, explicit: false }
}

function verifyTerminalImpactGate(
  receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, verifiedEdges: VerifiedEdgeResult[],
  hostTranscript: HostSignedTranscript, attackerTenants: ReadonlySet<string>, options: CompositeVerifyOptions,
): { ok: true; terminalVerification?: ReceiptVerification; terminalOracleFamily?: V8OracleFamily | string; terminalEndpoint?: string } | { ok: false; reason: string; rejectedBy?: string; missingEvidence?: string[]; terminalVerification?: ReceiptVerification } {
  const ti = receipt.terminalImpact, effSummary = ti.summary !== undefined ? ti.summary : ti.claimedImpact
  if (effSummary.replace(/\s+/g, '').length < 12) return { ok: false, reason: 'terminal_impact_summary_missing: terminalImpact.summary must be a meaningful non-empty description (>= 12 non-whitespace chars).', rejectedBy: 'terminal_impact_summary_missing', missingEvidence: ['terminal_impact_summary_missing'] }
  const termHop = dag.hopsById.get(ti.terminalHopId)!
  if (ti.terminalExchangeId && !termHop.exchangeIds.includes(ti.terminalExchangeId)) return { ok: false, reason: `terminalExchangeId "${ti.terminalExchangeId}" does not belong to terminal hop "${termHop.hopId}".`, rejectedBy: 'terminal_exchange_invalid', missingEvidence: ['terminal_exchange_in_final_hop'] }
  const termEx = ti.terminalExchangeId ? idx.entriesById.get(ti.terminalExchangeId)! : [...termHop.exchangeIds].reverse().map(id => idx.entriesById.get(id)!).find(e => e.step.arm === 'probe' && is2xx(e.step.status))
  const termEndpoint = (termEx?.step.route ?? termEx?.step.pathAndQuery ?? termHop.target.pathAndQuery ?? '').trim(), termFam = normRouteFam(termEndpoint, termEx?.entityId ?? termHop.entityId)
  let terminalVerification: ReceiptVerification | undefined
  if (ti.proofReceipt) { terminalVerification = verifyReceipt(ti.proofReceipt, hostTranscript); if (!terminalVerification.confirmed) return { ok: false, reason: terminalVerification.reason, terminalVerification } }
  if (options.verifyTerminalImpact) {
    const v = options.verifyTerminalImpact(receipt, hostTranscript); if (!v.confirmed) return { ok: false, reason: v.reason, terminalVerification }
    const normCls = receipt.terminalVulnClass.trim().toLowerCase(), fam = v.family ?? ti.oracleFamily ?? (V8_ORACLE_FAMILY_SET.has(normCls) ? normCls as V8OracleFamily : undefined)
    return { ok: true, terminalVerification, ...(fam ? { terminalOracleFamily: fam } : {}), ...(termEndpoint ? { terminalEndpoint: termEndpoint } : {}) }
  }
  const failUnproven = (reason = TERMINAL_IMPACT_UNPROVEN_HINT, extra?: string[]) => ({ ok: false as const, reason, rejectedBy: 'terminal_impact_unproven', missingEvidence: extra ? [...extra, TERMINAL_IMPACT_UNPROVEN_HINT] : [TERMINAL_IMPACT_UNPROVEN_HINT] })
  const hasEntryBody = (e: HostTranscriptEntry): boolean => e.step.json !== undefined || (typeof e.step.body === 'string' && e.step.body.trim().length > 0)
  const isStubEntry = (e: HostTranscriptEntry): boolean => hasEntryBody(e) && isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method, e.step.route ?? e.step.pathAndQuery)
  const isCrossTenantCls = CROSS_TENANT_CLASS_RE.test(receipt.terminalVulnClass)
  const isOwnTenantOnly = (e: HostTranscriptEntry): boolean => { const ts = extractTenantMarkers(e.step.json, e.step.body); return ts.size > 0 && attackerTenants.size > 0 && [...ts].every(t => attackerTenants.has(t)) }
  const postMutRb = (!termEx || !stepReadsState(termEx.step)) ? ti.postChainReadbackExchangeIds.map(id => idx.entriesById.get(id)).find((e): e is HostTranscriptEntry => {
    if (!e || (termEx && e.exchangeId === termEx.exchangeId)) return false
    const mono = !termEx || !isFiniteTs(termEx.timestampMs) || (isFiniteTs(e.timestampMs) && e.timestampMs >= termEx.timestampMs)
    const isRead = stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'post_chain_readback'
    return is2xx(e.step.status) && mono && isRead && hasEntryBody(e) && !isStubEntry(e) && (!isCrossTenantCls || !isOwnTenantOnly(e))
  }) : undefined
  const hasOob = termHop.oobEventIds.some(id => idx.oobById.get(id)?.delivered === true), hasBrowser = termHop.browserTraceIds.some(id => (idx.tracesById.get(id)?.sinks?.length ?? 0) > 0)
  const hasBody = Boolean(termEx && hasEntryBody(termEx)), isStub = Boolean(termEx && isStubEntry(termEx))
  if (ti.proofReceipt) {
    const proofOob = hasOob || ti.proofReceipt.oobEventIds.some(id => idx.oobById.get(id)?.delivered === true), proofBrowser = hasBrowser || ti.proofReceipt.browserTraceIds.some(id => (idx.tracesById.get(id)?.sinks?.length ?? 0) > 0)
    const proofStub = isStub || ti.proofReceipt.exchangeIds.some(id => { const e = idx.entriesById.get(id); return Boolean(e && e.step.arm !== 'control' && is2xx(e.step.status) && isStubEntry(e)) })
    if (proofStub && !postMutRb && !proofOob && !proofBrowser) return { ...failUnproven(), terminalVerification }
    const normCls = receipt.terminalVulnClass.trim().toLowerCase(), fam = ti.oracleFamily ?? (V8_ORACLE_FAMILY_SET.has(normCls) ? normCls as V8OracleFamily : undefined)
    return { ok: true, terminalVerification, ...(fam ? { terminalOracleFamily: fam } : {}), ...(termEndpoint ? { terminalEndpoint: termEndpoint } : {}) }
  }
  if (ti.terminalExchangeId && (!termEx || termEx.step.arm === 'control' || !is2xx(termEx.step.status))) return failUnproven(`terminalExchangeId "${ti.terminalExchangeId}" is not a succeeding probe exchange.`)
  if (termEx && (termEx.evidenceRole === 'host_capability_op' || termEx.evidenceRole === 'host_crypto_op')) return failUnproven()
  const hasPostMutation = Boolean(postMutRb), termHopSet = new Set(termHop.exchangeIds), nonTermExSet = new Set(receipt.hops.filter(h => h.hopId !== termHop.hopId).flatMap(h => h.exchangeIds).filter(id => !termHopSet.has(id)))
  const termActor = termEx ? actorOf(termEx) : null, termAuthd = Boolean(termActor && !ANON_ACTOR_RE.test(termActor))
  const ctrlCandidates = [...ti.preChainControlExchangeIds, ...termHop.exchangeIds, ...receipt.causalEdges.flatMap(ed => ed.kind === 'state_transition_binding' && ed.toHopId === termHop.hopId ? ed.ablationExchangeIds : [])]
  const terminalCtrl = ctrlCandidates.map(id => idx.entriesById.get(id)).find((c): c is HostTranscriptEntry => {
    if (!c || (termEx && c.exchangeId === termEx.exchangeId) || nonTermExSet.has(c.exchangeId)) return false
    if ((c.step.arm !== 'control' && c.replayAttempt !== 'ablation_control') || typeof c.step.status !== 'number' || !DENIED_CONTROL_STATUSES.has(c.step.status)) return false
    const ca = actorOf(c); if (c.step.status === 401 && termAuthd && (!ca || ANON_ACTOR_RE.test(ca))) return false
    const cf = normRouteFam(c.step.route ?? c.step.pathAndQuery, c.entityId ?? termEx?.entityId ?? termHop.entityId)
    return Boolean(termFam) && Boolean(cf) && cf === termFam
  })
  const hasCleanDeniedCtrl = Boolean(terminalCtrl), hasAsyncEdge = verifiedEdges.some(e => e.toHopId === termHop.hopId && e.kind === 'async_pivot_binding' && e.verified), hasAnyDerivedCrypto = verifiedEdges.some(e => e.kind === 'derived_crypto_binding' && e.verified)
  const ownTenantOnly = Boolean(termEx && isOwnTenantOnly(termEx))
  const v8Default = dispatchDefaultV8Oracle(receipt, dag, idx, termEx, options, terminalCtrl, postMutRb, { termEndpoint, termFam, hasOob, hasBrowser, hasBody, isStub, ownTenantOnly })
  if (v8Default && !v8Default.ok) return v8Default
  if (v8Default?.explicit && v8Default.family === 'economic_conservation') return { ok: true, terminalOracleFamily: v8Default.family, ...(termEndpoint ? { terminalEndpoint: termEndpoint } : {}) }
  if (!termEx && !hasOob && !hasBrowser && !hasAsyncEdge) return failUnproven(`Terminal hop "${termHop.hopId}" has no succeeding terminal evidence.`)
  if (isStub && !hasPostMutation) return failUnproven()
  const crossOrReplay = isCrossTenantCls || receipt.terminalVulnClass === 'cross_surface_pivot' || receipt.terminalVulnClass === 'cryptographic_scope_replay'
  if (termEx && ownTenantOnly && !hasPostMutation && (crossOrReplay || !hasCleanDeniedCtrl)) return failUnproven()
  const needsStrict = STRICT_TERMINAL_CLASS_RE.test(receipt.terminalVulnClass)
    || (hasBody && !hasOob && !hasBrowser && !hasAsyncEdge && !hasAnyDerivedCrypto && !['business_logic', 'ssrf'].includes(receipt.terminalVulnClass.toLowerCase()))
  if (needsStrict) {
    if (!hasCleanDeniedCtrl && !hasOob && !hasBrowser) return failUnproven(`Missing clean denied control (401/403/404) on exact terminal target for ${receipt.terminalVulnClass}. ${TERMINAL_IMPACT_UNPROVEN_HINT}`, ['clean_denied_control_401_403_404'])
    if (!hasOob && !hasBrowser && ((!termEx && !hasPostMutation) || !termEndpoint || !termFam)) return failUnproven(`Missing concrete terminal exchange or endpoint for ${receipt.terminalVulnClass}. ${TERMINAL_IMPACT_UNPROVEN_HINT}`, ['terminal_exchange_with_endpoint'])
    if (termEx && !hasPostMutation && (!hasBody || isStub || (ownTenantOnly && crossOrReplay))) return failUnproven()
  }
  return { ok: true, ...(v8Default?.family ? { terminalOracleFamily: v8Default.family } : {}), ...(termEndpoint ? { terminalEndpoint: termEndpoint } : {}) }
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
      const fromHop = dag.hopsById.get(edge.fromHopId)!, toHop = dag.hopsById.get(edge.toHopId)!
      const base: EdgeBase = { edgeIndex, kind: edge.kind, fromHopId: edge.fromHopId, toHopId: edge.toHopId, fromEx: [...fromHop.exchangeIds, ...fromHop.oobEventIds, ...fromHop.browserTraceIds], toEx: [...toHop.exchangeIds, ...toHop.oobEventIds, ...toHop.browserTraceIds] }
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
  const termRes = verifyTerminalImpactGate(receipt, dag, idx, verifiedEdges, hostTranscript, provRes.attackerTenants, options)
  if (!termRes.ok) return fail('terminal_impact', termRes.reason, verifiedEdges, termRes.terminalVerification, termRes.rejectedBy, termRes.missingEvidence)
  return {
    confirmed: true, chainId: receipt.chainId, terminalVulnClass: receipt.terminalVulnClass, replayMode: receipt.replayMode,
    modeBVerified: receipt.replayMode === 'one_shot_transcript', hopCount: receipt.hops.length, verifiedEdges,
    reason: `CompositeProofReceipt confirmed (${receipt.hops.length} hop(s), ${verifiedEdges.length} verified causal edge(s), mode=${receipt.replayMode}).`,
    ...(termRes.terminalOracleFamily ? { terminalOracleFamily: termRes.terminalOracleFamily } : {}),
    ...(termRes.terminalEndpoint ? { terminalEndpoint: termRes.terminalEndpoint } : {}),
    ...(termRes.terminalVerification ? { terminalVerification: termRes.terminalVerification } : {}),
    evidence: { topoOrder: dag.topoOrder, roots: dag.roots, derivedCapabilities: provRes.derivedCapabilities, ...(termRes.terminalOracleFamily ? { terminalOracleFamily: termRes.terminalOracleFamily } : {}), ...(termRes.terminalEndpoint ? { terminalEndpoint: termRes.terminalEndpoint } : {}) },
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
