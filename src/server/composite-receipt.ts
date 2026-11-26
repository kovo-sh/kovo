/**
 * CompositeProofReceipt — unified multi-hop DAG confirmation verifier (v8).
 * Verifies 1..8 hop causal chains over host-signed transcripts, provenance, Mode-A/B replay, and terminal-impact oracles.
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { z } from 'zod'
import { scopedAssetOrigin } from '../domain.ts'
import { parseRoleLabel, routeFamily, stepReadsState } from './oracle-invariants.ts'
import { augmentCompositeReceiptWithAutoDag, matchesNormalizedCtrlPath } from './composite-autodag.ts'
import { HostFactLog } from './host-fact-log.ts'
import { proofReceiptSchema, receiptIdSchema, verifyReceipt } from './proof-receipt.ts'
import { evaluateV8OracleFamily, extractTenantMarkers, isJobOrHandleStub, type HostSignedRecord as V8OracleRecord, type V8OracleFamily, type V8OracleInputMap } from './v8-oracle-families.ts'
import { TERMINAL_CLASS_CONTRACT, buildCapOriginIndex, canonicalNonAuthQuery, cleanExactPath, entryCarriesRequestToken, entryMatchesCorrelation, entryMatchesEntity, hydrateV8OracleInput, isHydratedStub, isPrivilegedActorOrRole, matchesHydratedRecord, resolveTerminalContract, sanitizeEmbeddedProofReceipt, selectStateTransitionPair, type CapOriginIndex, type EconomicAutoHydrateContext, type TerminalContractKind } from './v8-oracle-hydrate.ts'
export { TERMINAL_CLASS_CONTRACT, type TerminalContractKind }
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
export interface CompositeOracleEvaluator { evaluate: (factLog: HostFactLog, pointerRef: { kind: 'v8_family'; family: V8OracleFamily; rawInput?: Record<string, unknown>; econCtx?: EconomicAutoHydrateContext } | { kind: 'single_hop'; receipt: ProofReceipt | unknown }, policyContext?: { signingKey?: string; strictHostDerivation?: boolean }) => { confirmed: boolean; reason: string; singleHop?: ReceiptVerification } }
export interface CompositeVerifyOptions {
  attackerPersonas?: readonly string[]; forbiddenShortcutPersonas?: readonly string[]; benchmarkMode?: boolean; requireCleanSessionFlag?: boolean; signingKey?: string
  v8OracleInput?: Record<string, unknown>; strictHostDerivation?: boolean; factLog?: HostFactLog; oracleEvaluator?: CompositeOracleEvaluator
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
const CONSUMED_STATE_RE = /\b(?:already[_\s-]?(?:consumed|redeemed|used|claimed|applied|settled)|token[_\s-]?(?:consumed|used|redeemed|spent)|one[_\s-]?time|nonce[_\s-]?(?:used|replayed|consumed)|invite[_\s-]?(?:redeemed|consumed|used)|state[_\s-]?(?:consumed|exhausted|finalized))\b/i
const ABLATION_DENIED_STATUSES = new Set([401, 403, 404, 409, 412, 422]), DENIED_CONTROL_STATUSES = new Set([401, 403, 404]), SHA256_RE = /^[0-9a-f]{64}$/
const CROSS_TENANT_CLASS_RE = /^(?:dual_tenant_abac|parser_cache_differential)$|dual[_-]?tenant|cross[_-]?tenant|tenant[_-]?(?:isolation|bleed|leak|export)|abac|cache[_-]?(?:bleed|poison|deception|diff|bypass)|export[_-]?(?:bypass|leak|disclosure)|presign|cwe[-_]?(?:444|639)|\bidor\b|\bbola\b/i
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
const isExecArm = (e: HostTranscriptEntry, isTerm = false): boolean => e.step.arm === 'probe' || (!isTerm && e.step.arm === 'setup')
const normRouteFam = (p: string | null | undefined, eid?: string): string => !p ? '' : routeFamily(p.split(/[?#]/, 1)[0]!.split('/').map(s => (s && ((eid && s === eid) || /^\d+$/.test(s))) ? ':id' : s).join('/'))
const actorOf = (e: HostTranscriptEntry): string | null => (e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null))
const resolvedActorOf = (e: HostTranscriptEntry, capIdx: CapOriginIndex): string | null => { const a = actorOf(e); return a?.startsWith('cap:') ? (capIdx.actorOf(a) ?? a) : (a ?? (e.consumedCapabilities ?? []).map(c => capIdx.actorOf(c)).find(Boolean) ?? null) }
const roleOf = (e: HostTranscriptEntry): string | null => (e.actorRoleLabel ? parseRoleLabel(e.actorRoleLabel).role : (e.step.actor.role ?? null))
const probeTenantsOf = (e: HostTranscriptEntry, capIdx?: CapOriginIndex): string[] => { const out: string[] = [], a = actorOf(e), dt = (!a || ANON_ACTOR_RE.test(a) || a.startsWith('cap:')) ? null : ((e.step.actor.tenant ?? parseRoleLabel(e.actorRoleLabel ?? e.actorPersona ?? '').tenant ?? '').trim().toLowerCase() || null); if (dt) out.push(dt); if (capIdx) for (const c of [...(a?.startsWith('cap:') ? [a] : []), ...(e.consumedCapabilities ?? [])]) { const lt = capIdx.loginTenantOf(c); if (lt && !out.includes(lt)) out.push(lt) } return out }
const probeTenantOf = (e: HostTranscriptEntry, capIdx?: CapOriginIndex): string | null => probeTenantsOf(e, capIdx)[0] ?? null
function collectLeaves(v: unknown, out: Set<string>, d = 0): void {
  if (d > 5 || out.size > 256 || v == null) return
  if (typeof v === 'string') { const t = v.trim(); if (t.length > 0 && t.length <= 2048) out.add(t) }
  else if (typeof v === 'number' || typeof v === 'boolean') out.add(String(v))
  else if (typeof v === 'object') for (const x of Array.isArray(v) ? v : Object.values(v as Record<string, unknown>)) collectLeaves(x, out, d + 1)
}
function collectHeaderTokens(headers: Record<string, string> | null | undefined, out: Set<string>): void {
  for (const raw of Object.values(headers ?? {})) {
    const t = raw.trim(); if (!t) continue; out.add(t)
    const m = /^(?:Bearer|Basic|Token|ApiKey)\s+(.+)$/i.exec(t); if (m?.[1]) out.add(m[1].trim())
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
    for (const seg of (q >= 0 ? pq.slice(0, q) : pq).split('/')) if (seg) { leaves.add(seg); try { const d = decodeURIComponent(seg); if (d !== seg) leaves.add(d) } catch {} }
    if (q >= 0) for (const v of new URLSearchParams(pq.slice(q + 1)).values()) if (v) leaves.add(v)
  }
  for (const leaf of leaves) digests.add(sha256Hex(leaf))
  return digests
}
const serializeBodyText = (e: HostTranscriptEntry): string => { try { return typeof e.step.body === 'string' && e.step.body.length > 0 ? e.step.body : e.step.json !== undefined ? JSON.stringify(e.step.json) : '' } catch { return '' } }

// --- DAG Topology & Transcript Integrity ------------------------------------
interface DagTopology { hopsById: Map<string, HopReceipt>; topoOrder: string[]; roots: string[]; incomingByHop: Map<string, Array<{ edgeIndex: number; edge: CausalEdgeBinding }>> }
interface IndexedTranscript { entriesById: Map<string, HostTranscriptEntry>; oobById: Map<string, HostOobEvent>; tracesById: Map<string, HostBrowserTrace>; pollsById: Map<string, HostAsyncPollRecord>; allPolls: readonly HostAsyncPollRecord[] }

function validateDagTopology(receipt: CompositeProofReceipt): { ok: true; dag: DagTopology } | { ok: false; reason: string } {
  const hopsById = new Map<string, HopReceipt>()
  for (const hop of receipt.hops) { if (hopsById.has(hop.hopId)) return { ok: false, reason: `Duplicate hopId "${hop.hopId}".` }; hopsById.set(hop.hopId, hop) }
  if (!hopsById.has(receipt.terminalImpact.terminalHopId)) return { ok: false, reason: `terminalHopId "${receipt.terminalImpact.terminalHopId}" not in hops.` }
  if (receipt.hops.length === 1 && receipt.causalEdges.length > 0) return { ok: false, reason: 'A 1-hop receipt cannot declare causalEdges.' }
  const inDeg = new Map(receipt.hops.map(h => [h.hopId, 0])), outAdj = new Map<string, string[]>(receipt.hops.map(h => [h.hopId, []])), revAdj = new Map<string, string[]>(receipt.hops.map(h => [h.hopId, []]))
  const incomingByHop = new Map<string, Array<{ edgeIndex: number; edge: CausalEdgeBinding }>>(receipt.hops.map(h => [h.hopId, []])), seen = new Set<string>()
  for (let i = 0; i < receipt.causalEdges.length; i++) {
    const e = receipt.causalEdges[i]!, key = `${e.fromHopId}->${e.toHopId}:${e.kind}`
    if (!hopsById.has(e.fromHopId) || !hopsById.has(e.toHopId)) return { ok: false, reason: `Edge #${i} references unknown hop.` }
    if (e.fromHopId === e.toHopId) return { ok: false, reason: `Edge #${i} forms a self-loop on "${e.fromHopId}".` }
    if (seen.has(key)) return { ok: false, reason: `Duplicate causal edge "${key}".` }
    seen.add(key); outAdj.get(e.fromHopId)!.push(e.toHopId); revAdj.get(e.toHopId)!.push(e.fromHopId)
    inDeg.set(e.toHopId, (inDeg.get(e.toHopId) ?? 0) + 1); incomingByHop.get(e.toHopId)!.push({ edgeIndex: i, edge: e })
  }
  const roots = receipt.hops.filter(h => inDeg.get(h.hopId) === 0).map(h => h.hopId), queue = [...roots], rem = new Map(inDeg), topoOrder: string[] = []
  while (queue.length > 0) { const id = queue.shift()!; topoOrder.push(id); for (const next of outAdj.get(id) ?? []) { const d = (rem.get(next) ?? 0) - 1; rem.set(next, d); if (d === 0) queue.push(next) } }
  if (topoOrder.length !== receipt.hops.length) return { ok: false, reason: 'Causal DAG contains a cycle.' }
  const reachesTerminal = new Set([receipt.terminalImpact.terminalHopId]), rq = [receipt.terminalImpact.terminalHopId]
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

function recordHopCapabilities(hop: HopReceipt, idx: IndexedTranscript, target: Set<string>, isTerm = false): void {
  for (const id of hop.exchangeIds) {
    const e = idx.entriesById.get(id)!
    if (!isExecArm(e, isTerm)) continue
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
    if (!isExecArm(e) || !isFiniteTs(e.timestampMs)) continue
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
function verifyValueBinding(base: EdgeBase, edge: Extract<CausalEdgeBinding, { kind: 'value_binding' }>, fromHop: HopReceipt, toHop: HopReceipt, idx: IndexedTranscript): VerifiedEdgeResult {
  const allOut = collectHopOutputs(fromHop, idx), sealRec = edge.sourceExchangeId && edge.capabilityHandle ? idx.entriesById.get(edge.sourceExchangeId) : undefined
  const directOut = edge.sourceExchangeId ? allOut.filter(o => o.sourceId === edge.sourceExchangeId) : allOut
  const outputs = directOut.length > 0 ? directOut : (sealRec?.evidenceRole === 'host_capability_op' && sealRec.emittedCapabilities?.includes(edge.capabilityHandle!)) ? allOut.filter(o => o.capabilities.has(edge.capabilityHandle!)) : directOut
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

function verifyDerivedCryptoBinding(base: EdgeBase, edge: Extract<CausalEdgeBinding, { kind: 'derived_crypto_binding' }>, fromHop: HopReceipt, toHop: HopReceipt, idx: IndexedTranscript): VerifiedEdgeResult {
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

function verifyStateTransitionBinding(base: EdgeBase, edge: Extract<CausalEdgeBinding, { kind: 'state_transition_binding' }>, fromHop: HopReceipt, toHop: HopReceipt, idx: IndexedTranscript, dagDerivedCaps: ReadonlySet<string>, capIdx: CapOriginIndex, termHopId: string): VerifiedEdgeResult {
  const hopEntries = (hop: HopReceipt) => hop.exchangeIds.map(id => idx.entriesById.get(id)!)
  const asExecEntries = (hop: HopReceipt) => hopEntries(hop).map(e => (hop.hopId !== termHopId && e.step.arm === 'setup') ? { ...e, step: { ...e.step, arm: 'probe' as const } } : e)
  const hopDiag = (hop: HopReceipt, side: string) => { const es = hopEntries(hop); return `[${side}Ok=0: exchanges=${es.length}, 2xx=${es.filter(e => is2xx(e.step.status)).length}, timestamped=${es.filter(e => isFiniteTs(e.timestampMs)).length}, entityMatch=${es.filter(e => entryMatchesEntity(e, edge.entityId)).length}]` }
  const sel = selectStateTransitionPair(edge.entityId, asExecEntries(fromHop), asExecEntries(toHop), dagDerivedCaps, { actorOf, probeTenantOf: e => probeTenantOf(e, capIdx), entryMatchesEntity, anonActorRe: ANON_ACTOR_RE, resolveCapActor: c => capIdx.actorOf(c) })
  if (!sel.ok) {
    if (sel.reason === 'non_monotonic') return edgeFail(base, `state_transition_binding on "${edge.entityId}" violated monotonic ordering (t_i > t_j).`)
    const side = sel.reason === 'missing_to' || sel.missingSide === 'to' ? 'to' : 'from', hop = side === 'to' ? toHop : fromHop
    return edgeFail(base, `${side}Hop "${hop.hopId}" has no succeeding exchange on "${edge.entityId}" ${hopDiag(hop, side)}${sel.reason === 'actor_discontinuity' ? ' [actor_discontinuity]' : ''}.`)
  }
  const pair = { from: idx.entriesById.get(sel.from.exchangeId)!, to: idx.entriesById.get(sel.to.exchangeId)! }, { logicalFallback } = sel, toRawActor = actorOf(pair.to), toActor = resolvedActorOf(pair.to, capIdx), toFam = normRouteFam(pair.to.step.route ?? pair.to.step.pathAndQuery, edge.entityId)
  const hopExSet = new Set([...fromHop.exchangeIds, ...toHop.exchangeIds])
  const toUsesNewCap = (pair.to.consumedCapabilities ?? []).some(c => dagDerivedCaps.has(c)) || (pair.to.cryptoAttestations ?? []).some(x => dagDerivedCaps.has(x.derivedFromCapabilityId)) || Boolean(toRawActor && dagDerivedCaps.has(toRawActor))
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
    const abActor = resolvedActorOf(ab, capIdx)
    if (!toUsesNewCap && toActor && (logicalFallback ? normActor(abActor) !== normActor(toActor) : (abActor && normActor(abActor) !== normActor(toActor)))) return edgeFail(base, `Ablation "${abId}" actor "${abActor ?? 'anon'}" mismatches toHop actor "${toActor}" [actor_mismatch].`)
    if (denied || (!logicalFallback && labeled && ab.step.evidenceRole === 'invariant_preserved')) validAblation = ab
    else diags.push(`${abId}: status=${st ?? 'null'} not a denial (401/403/404/409/412/422)`)
  }
  if (!validAblation) return edgeFail(base, `state_transition_binding on "${edge.entityId}" lacks a passing clean-session ablation control [${diags.join('; ') || 'no ablationExchangeIds cited'}].`)
  return edgeOk(base, 'state_transition_binding verified with clean-session ablation control.', { entityId: edge.entityId, fromExchangeId: pair.from.exchangeId, toExchangeId: pair.to.exchangeId, ablationExchangeId: validAblation.exchangeId, ablationStatus: validAblation.step.status, ...(logicalFallback ? { bindingMode: 'logical_key_ablation' } : {}) })
}

function verifyAsyncPivotBinding(base: EdgeBase, edge: Extract<CausalEdgeBinding, { kind: 'async_pivot_binding' }>, fromHop: HopReceipt, toHop: HopReceipt, idx: IndexedTranscript, signingKey?: string, isTermTo = false): VerifiedEdgeResult {
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
      const e = idx.entriesById.get(id)!, body = serializeBodyText(e)
      if (!isExecArm(e, isTermTo) || !is2xx(e.step.status) || !isFiniteTs(e.timestampMs) || !entryMatchesCorrelation(e, edge.correlationId)) continue
      const stub = isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method, e.step.route ?? e.step.pathAndQuery)
      const submission = /^(?:POST|PUT|PATCH)$/i.test(e.step.method) && (e.step.status === 202 || stub)
      if (!submission && !(stepReadsState(e.step) && body.trim())) continue
      if (e.timestampMs <= minTrigger) return edgeFail(base, `Async job readback "${id}" did not follow trigger.`)
      return edgeOk(base, 'async_pivot_binding (async_job) verified.', { correlationId: edge.correlationId, targetExchangeId: id, tTrigger: minTrigger, tObserved: e.timestampMs })
    }
  }
  return edgeFail(base, `No converged async record in "${toHop.hopId}" matches "${edge.correlationId}".`)
}

// --- Attacker-Origin Provenance & Replay Mode Policy ------------------------
function verifyAttackerProvenance(
  receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, options: CompositeVerifyOptions, capIdx: CapOriginIndex,
): { ok: true; derivedCapabilities: string[]; attackerTenants: ReadonlySet<string> } | { ok: false; reason: string } {
  const allowedSet = options.attackerPersonas?.length ? new Set(options.attackerPersonas) : null, forbiddenSet = new Set(options.forbiddenShortcutPersonas ?? [])
  const rootSet = new Set(dag.roots), dagCaps = new Set<string>(), probeTenants = new Set<string>()
  const isForbidden = (a: string | null, r: string | null, rl?: string | null, tt?: string | null) =>
    (a !== null && forbiddenSet.has(a)) || (allowedSet ? (a !== null && !allowedSet.has(a)) || (Boolean(tt) && isPrivilegedActorOrRole(a, r, rl, tt)) : isPrivilegedActorOrRole(a, r, rl, tt))
  const isAllowed = (a: string | null, r: string | null, rl?: string | null) =>
    !(a !== null && forbiddenSet.has(a)) && (allowedSet ? a !== null && allowedSet.has(a) : !isPrivilegedActorOrRole(a, r, rl))
  const checkExternalCaps = (e: HostTranscriptEntry, label: string): string | null => {
    const a = actorOf(e)
    for (const c of [...(a?.startsWith('cap:') ? [a] : []), ...(e.consumedCapabilities ?? [])]) {
      if (dagCaps.has(c)) continue
      const em = capIdx.emitterActorOf(c)
      if (em && isForbidden(em.actor, em.role, em.roleLabel)) return `Attacker-origin violation in ${label} ("${e.exchangeId}"): capability "${c}" originated from forbidden persona "${em.actor ?? em.role}".`
      if (em && !em.isLogin && !em.actor && !em.role && !em.roleLabel && em.arm !== 'probe') return `Attacker-origin violation in ${label} ("${e.exchangeId}"): capability "${c}" has unattributed non-probe origin.`
    }
    return null
  }
  const resolveActor = (e: HostTranscriptEntry) => {
    const a = actorOf(e), r = roleOf(e), isCap = Boolean(a?.startsWith('cap:')), fromDag = Boolean(isCap && dagCaps.has(a!))
    if (!isCap || fromDag) return { a: fromDag ? null : a, r, rl: e.actorRoleLabel, isCap, fromDag, missingOrigin: false }
    const em = capIdx.emitterActorOf(a!)
    return em ? { a: em.actor, r: em.role ?? r, rl: em.roleLabel ?? e.actorRoleLabel, isCap, fromDag, missingOrigin: false } : { a, r, rl: e.actorRoleLabel, isCap, fromDag, missingOrigin: true }
  }
  for (const hopId of dag.topoOrder) {
    const hop = dag.hopsById.get(hopId)!, isRoot = rootSet.has(hopId), isTermHop = hopId === receipt.terminalImpact.terminalHopId
    const nonControls = hop.exchangeIds.map(id => idx.entriesById.get(id)!).filter(e => e.step.arm !== 'control'), probes = nonControls.filter(e => isExecArm(e, isTermHop))
    if (isRoot && (hop.exchangeIds.length > 0 || (hop.oobEventIds.length === 0 && hop.browserTraceIds.length === 0)) && probes.length === 0) return { ok: false, reason: `Root hop "${hopId}" requires an attacker-origin probe.` }
    for (const e of nonControls) {
      const ra = resolveActor(e), usesDag = ra.fromDag || (e.consumedCapabilities ?? []).some(c => dagCaps.has(c)) || (e.cryptoAttestations ?? []).some(x => dagCaps.has(x.derivedFromCapabilityId))
      const termMarkers = isTermHop && !ra.fromDag ? extractTenantMarkers(e.step.json, e.step.body) : new Set<string>(), tt = termMarkers.size === 1 ? [...termMarkers][0]! : null
      if (ra.missingOrigin) return { ok: false, reason: `Attacker-origin violation in "${hopId}" ("${e.exchangeId}"): capability "${ra.a}" has unknown origin.` }
      if (!ra.fromDag && (isForbidden(ra.a, ra.r, ra.rl, tt) || (ra.isCap && !allowedSet && isPrivilegedActorOrRole(null, roleOf(e), e.actorRoleLabel, tt)))) return { ok: false, reason: `Attacker-origin violation in "${hopId}" ("${e.exchangeId}"): pre-seeded persona "${ra.a ?? ra.r}" is forbidden.` }
      const capErr = checkExternalCaps(e, `"${hopId}"`); if (capErr) return { ok: false, reason: capErr }
      if (!isExecArm(e, isTermHop)) continue
      if (isRoot && allowedSet && !isAllowed(ra.a, ra.r, ra.rl)) return { ok: false, reason: `Root hop "${hopId}" ("${e.exchangeId}") must start from an allowed attackerPersona.` }
      if (!isRoot && !(ra.a !== null && isAllowed(ra.a, ra.r, ra.rl)) && !usesDag) return { ok: false, reason: `Hop "${hopId}" ("${e.exchangeId}") lacks attacker persona or DAG-derived capability.` }
      for (const pt of probeTenantsOf(e, capIdx)) probeTenants.add(pt)
    }
    recordHopCapabilities(hop, idx, dagCaps, isTermHop)
  }
  const extraIds = [...receipt.terminalImpact.postChainReadbackExchangeIds.filter(id => { const e = idx.entriesById.get(id); return Boolean(e && !stepReadsState(e.step)) }), ...(receipt.terminalImpact.modeAFailureExchangeId ? [receipt.terminalImpact.modeAFailureExchangeId] : []), ...(receipt.terminalImpact.proofReceipt?.exchangeIds ?? []), ...receipt.hops.flatMap(h => h.proofReceipt?.exchangeIds ?? [])]
  for (const id of extraIds) {
    const e = idx.entriesById.get(id); if (!e || e.step.arm === 'control') continue
    const ra = resolveActor(e)
    if (ra.missingOrigin) return { ok: false, reason: `Attacker-origin violation on cited non-control exchange "${id}": capability "${ra.a}" has unknown origin.` }
    if (!ra.fromDag && isForbidden(ra.a, ra.r, ra.rl)) return { ok: false, reason: `Attacker-origin violation on cited non-control exchange "${id}": pre-seeded persona "${ra.a ?? ra.r}" is forbidden.` }
    const capErr = checkExternalCaps(e, 'cited non-control'); if (capErr) return { ok: false, reason: capErr }
  }
  if (probeTenants.size > 1) return { ok: false, reason: `Cross-tenant probe-arm persona mismatch: pre-seeded probe hops mixed distinct tenants (${[...probeTenants].sort().join(', ')}). All pre-seeded probe-arm hops must belong to a single starting tenant (or anonymous/DAG-minted credentials); use target-tenant personas only on control or readback arms.` }
  return { ok: true, derivedCapabilities: [...dagCaps], attackerTenants: probeTenants }
}

function verifyReplayMode(receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, options: CompositeVerifyOptions): { ok: true } | { ok: false; reason: string } {
  if (receipt.replayMode === 'fresh_clean_replay') {
    for (const hop of receipt.hops) for (const id of hop.exchangeIds) {
      const e = idx.entriesById.get(id)!; if (!isExecArm(e, hop.hopId === receipt.terminalImpact.terminalHopId)) continue
      if (e.cleanSession === false) return { ok: false, reason: `Mode A rejected exchange "${id}" marked cleanSession=false.` }
      if (options.requireCleanSessionFlag && e.cleanSession !== true) return { ok: false, reason: `Mode A requires cleanSession=true on "${id}".` }
    }
    return { ok: true }
  }
  if (receipt.benchmarkMode === true || options.benchmarkMode === true) return { ok: false, reason: 'Mode B (one_shot_transcript) is forbidden in benchmarkMode.' }
  const ti = receipt.terminalImpact; if (!ti.modeAFailureExchangeId) return { ok: false, reason: 'Mode B requires terminalImpact.modeAFailureExchangeId.' }
  const failEx = idx.entriesById.get(ti.modeAFailureExchangeId)!, st = failEx.step.status
  if (failEx.replayAttempt !== 'mode_a' && failEx.cleanSession !== true) return { ok: false, reason: 'modeAFailureExchangeId was not a clean-session Mode-A replay.' }
  if (!(st === 409 || st === 410 || ((st === 400 || st === 422) && CONSUMED_STATE_RE.test(serializeBodyText(failEx))))) return { ok: false, reason: `Mode B rejected: Mode-A returned HTTP ${st ?? 'null'} (requires 409/410/consumed-token).` }
  if (ti.preChainControlExchangeIds.length === 0) return { ok: false, reason: 'Mode B requires a pre-chain denied control on the terminal target.' }
  if (ti.postChainReadbackExchangeIds.length === 0) return { ok: false, reason: 'Mode B requires a post-chain readback proving persisted impact.' }
  const termHop = dag.hopsById.get(ti.terminalHopId)!, probeTs = termHop.exchangeIds.map(id => idx.entriesById.get(id)!).filter(e => e.step.arm === 'probe' && isFiniteTs(e.timestampMs)).map(e => e.timestampMs!)
  const refTs = probeTs.length > 0 ? Math.min(...probeTs) : null, termFam = routeFamily(termHop.target.pathAndQuery ?? '')
  const hasPre = ti.preChainControlExchangeIds.some(id => {
    const e = idx.entriesById.get(id)!
    if (e.step.arm !== 'control' || (e.step.status !== 401 && e.step.status !== 403) || !isFiniteTs(e.timestampMs) || (refTs !== null && e.timestampMs > refTs)) return false
    const cf = termFam && (e.step.route || e.step.pathAndQuery) ? routeFamily(e.step.route ?? e.step.pathAndQuery ?? '') : ''
    return !cf || cf === termFam || Boolean(termHop.entityId && entryMatchesEntity(e, termHop.entityId))
  })
  if (!hasPre) return { ok: false, reason: 'Mode B requires a pre-chain 401/403 control on the terminal target.' }
  const preSet = new Set(ti.preChainControlExchangeIds)
  const hasRead = ti.postChainReadbackExchangeIds.some(id => {
    if (preSet.has(id)) return false
    const e = idx.entriesById.get(id)!
    if (!is2xx(e.step.status) || !isFiniteTs(e.timestampMs) || (refTs !== null && e.timestampMs < refTs)) return false
    return (stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'post_chain_readback') && (e.step.json !== undefined || (typeof e.step.body === 'string' && e.step.body.trim().length > 0)) && !isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method, e.step.route ?? e.step.pathAndQuery)
  })
  return hasRead ? { ok: true } : { ok: false, reason: 'Mode B requires a post-chain 2xx readback proving persisted impact.' }
}

// --- Public Verifier & Single-Hop Bridge ------------------------------------
type DefaultV8Ctx = { termEndpoint: string; termFam: string; hasOob: boolean; hasBrowser: boolean; hasBody: boolean; isStub: boolean; ownTenantOnly: boolean; hasForeignTenantData: boolean; hasVerifiedTermEdge: boolean }
let defaultOracleEvaluator: CompositeOracleEvaluator | null = null
export function registerDefaultCompositeOracleEvaluator(evaluator: CompositeOracleEvaluator | null): void { defaultOracleEvaluator = evaluator }
const fallbackOracleEvaluator: CompositeOracleEvaluator = {
  evaluate(factLog, ref, policy = {}) {
    const tr = factLog.toHostSignedTranscript()
    if (ref.kind === 'single_hop') { const p = proofReceiptSchema.safeParse(ref.receipt); if (!p.success) return { confirmed: false, reason: 'Receipt failed schema validation.' }; const v = verifyReceipt(p.data, tr, policy.signingKey ? { signingKey: policy.signingKey } : undefined); return { confirmed: v.confirmed, reason: v.reason, singleHop: v } }
    const signed = new Map((tr.entries ?? []).map(e => [e.exchangeId, e])), entriesById = new Map([...signed].map(([id, e]) => { const raw = factLog.getExchange(id)?.rawRequestBody; return [id, e.step.requestJson === undefined && raw != null ? { ...e, step: { ...e.step, requestJson: raw } } : e] as const }))
    const oobById = new Map((tr.oobEvents ?? []).map(o => [o.id, o])), tracesById = new Map((tr.browserTraces ?? []).map(t => [t.id, t])), pollsById = new Map((tr.asyncPollRecords ?? []).map(p => [p.id, p])), idx = { entriesById, oobById, tracesById }, fallbackSig = policy.signingKey ? '' : 'host-verified-sig'
    const verifySignature = (rec: V8OracleRecord): boolean => { const e = entriesById.get(rec.id) ?? oobById.get(rec.id) ?? tracesById.get(rec.id) ?? pollsById.get(rec.id); if (!e) return false; const s = signed.get(rec.id) ?? e; return (!policy.signingKey || (s.hostSignature === rec.hostSignature && verifyHostRecordSignature(s, policy.signingKey))) && (pollsById.has(rec.id) || matchesHydratedRecord(rec, idx, fallbackSig)) }
    const hydrated = hydrateV8OracleInput(ref.family, ref.rawInput ?? {}, idx, fallbackSig, ref.econCtx); if (ref.family === 'economic_conservation' && isHydratedStub(hydrated.finalReadback)) return { confirmed: false, reason: 'terminal_impact_unproven_intermediate_stub' }
    const dec = evaluateV8OracleFamily(ref.family, { ...hydrated, verifySignature } as V8OracleInputMap[typeof ref.family]); return { confirmed: dec.required && dec.satisfied, reason: dec.reason }
  },
}
const resolveOracleEvaluator = (options: CompositeVerifyOptions): CompositeOracleEvaluator => options.oracleEvaluator ?? defaultOracleEvaluator ?? fallbackOracleEvaluator

function dispatchDefaultV8Oracle(
  receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, factLog: HostFactLog, termEx: HostTranscriptEntry | undefined, options: CompositeVerifyOptions,
  terminalCtrl: HostTranscriptEntry | undefined, postMutRb: HostTranscriptEntry | undefined, ctx: DefaultV8Ctx,
): { ok: true; family: V8OracleFamily; explicit: boolean } | { ok: false; reason: string; rejectedBy: string; missingEvidence: string[] } | null {
  const ti = receipt.terminalImpact, normCls = receipt.terminalVulnClass.trim().toLowerCase()
  const family = ti.oracleFamily ?? (V8_ORACLE_FAMILY_SET.has(normCls) ? normCls as V8OracleFamily : null)
  if (!family) return null
  const policy = { signingKey: options.signingKey, strictHostDerivation: true }, evalOracle = resolveOracleEvaluator(options)
  const rejectFam = (reason: string, missingEvidence: string[], rejectedBy = `v8_oracle_${family}`) => ({ ok: false as const, reason, rejectedBy, missingEvidence })
  if (ti.oracleFamily && !ti.oracleInput) return rejectFam(`v8_oracle_failed (${family}): missing_v8_oracle_input — terminalImpact.oracleFamily requires terminalImpact.oracleInput.`, ['terminalImpact.oracleInput'])
  if (family === 'dual_tenant_abac' && receipt.hops.length < 2) return rejectFam('v8_oracle_failed (dual_tenant_abac): multi_hop_causal_chain_required', ['upstream_causal_hop_or_oracle_input'])
  if (family === 'dual_tenant_abac' && !terminalCtrl) return rejectFam('v8_oracle_failed (dual_tenant_abac): missing_denied_control_on_terminal_route', ['clean_denied_control_401_403_404'])
  const mapFail = (reason: string) => (reason === 'terminal_impact_unproven_intermediate_stub' || reason === 'bled_access_own_tenant_only')
    ? rejectFam(TERMINAL_IMPACT_UNPROVEN_HINT, [TERMINAL_IMPACT_UNPROVEN_HINT], 'terminal_impact_unproven')
    : rejectFam(`v8_oracle_failed (${family}): ${reason}`, [reason])
  const econCtx = { preChainControlExchangeIds: ti.preChainControlExchangeIds, termHopExchangeIds: dag.hopsById.get(ti.terminalHopId)!.exchangeIds, postChainReadbackExchangeIds: ti.postChainReadbackExchangeIds, citedExchangeIds: receipt.hops.flatMap(h => h.exchangeIds) }
  const explicitInput = ti.oracleInput ?? options.v8OracleInput
  if (explicitInput) {
    const res = evalOracle.evaluate(factLog, { kind: 'v8_family', family, rawInput: explicitInput, econCtx }, policy)
    return res.confirmed ? { ok: true, family, explicit: true } : mapFail(res.reason)
  }
  if (family === 'cross_surface_pivot') {
    if (receipt.hops.length < 2) return rejectFam('v8_oracle_failed (cross_surface_pivot): invalid_hop_count — requires >= 2 hops across distinct surfaces.', ['cross_surface_pivot_requires_2_plus_hops'])
    const rootHop = dag.hopsById.get(dag.roots[0]!)!, rootEx = rootHop.exchangeIds.map(id => idx.entriesById.get(id)!).find(e => isExecArm(e, rootHop.hopId === ti.terminalHopId)) ?? idx.entriesById.get(rootHop.exchangeIds[0]!)
    if (!terminalCtrl || !rootEx || !termEx) return rejectFam(`v8_oracle_failed (${family}): missing_pivot_control_or_terminal_record`, ['pre_chain_control_denied', TERMINAL_IMPACT_UNPROVEN_HINT])
    const hops = dag.topoOrder.map((hopId, i) => {
      const h = dag.hopsById.get(hopId)!, edge = (dag.incomingByHop.get(hopId) ?? [])[0]?.edge
      const outCorr = receipt.causalEdges.find(e => e.fromHopId === hopId && (e.kind === 'async_pivot_binding' || e.kind === 'state_transition_binding'))
      const outArt = receipt.causalEdges.find(e => e.fromHopId === hopId && (e.kind === 'value_binding' || e.kind === 'derived_crypto_binding'))
      const ex = (i === dag.topoOrder.length - 1 ? termEx : h.exchangeIds.map(id => idx.entriesById.get(id)!).find(e => isExecArm(e, hopId === ti.terminalHopId))) ?? idx.entriesById.get(h.exchangeIds[0]!)!
      const corr = (edge?.kind === 'async_pivot_binding' ? edge.correlationId : edge?.kind === 'state_transition_binding' ? edge.entityId : undefined) ?? (outCorr?.kind === 'async_pivot_binding' ? outCorr.correlationId : outCorr?.kind === 'state_transition_binding' ? outCorr.entityId : undefined) ?? ex.correlationIds?.[0] ?? h.entityId
      const emitted = (outArt?.kind === 'value_binding' ? (outArt.capabilityHandle ?? outArt.valueDigest) : outArt?.kind === 'derived_crypto_binding' ? outArt.sourceCapabilityId : undefined) ?? h.producedCapabilities[0]
      return {
        surface: h.surface, role: i === dag.topoOrder.length - 1 ? 'terminal_impact' : h.surface === 'browser' ? 'browser_dom_trace' : h.surface === 'webhook' ? 'oob_callback' : 'trigger_write',
        record: ex.exchangeId, ...(edge ? { bindingKind: edge.kind } : {}), ...(emitted ? { emittedArtifactDigest: emitted } : {}), ...(corr ? { correlationToken: corr } : {}),
        ...(edge?.kind === 'value_binding' ? { consumedArtifactDigest: edge.capabilityHandle ?? edge.valueDigest ?? h.consumedCapabilities[0] } : {}),
        ...(edge?.kind === 'derived_crypto_binding' ? { derivedFromCapabilityId: edge.sourceCapabilityId } : {}), ...(edge?.kind === 'state_transition_binding' && edge.ablationExchangeIds[0] ? { ablationControlDenied: edge.ablationExchangeIds[0] } : {}),
      }
    })
    const res = evalOracle.evaluate(factLog, { kind: 'v8_family', family: 'cross_surface_pivot', rawInput: { preChainControlDenied: terminalCtrl.exchangeId, hops, terminalImpact: { kind: postMutRb ? 'privileged_mutation' : 'privileged_read', ...(postMutRb ? { postImpactReadback: postMutRb.exchangeId } : {}) } } }, policy)
    return res.confirmed ? { ok: true, family, explicit: false } : mapFail(res.reason)
  }
  if (ctx.isStub && !postMutRb) return mapFail('terminal_impact_unproven_intermediate_stub')
  if (ctx.ownTenantOnly && !postMutRb && family !== 'temporal_revocation') return mapFail('bled_access_own_tenant_only')
  const multiHopDualDag = family === 'dual_tenant_abac' && !ti.oracleFamily && receipt.hops.length >= 2 && ctx.hasVerifiedTermEdge && Boolean(terminalCtrl && terminalCtrl.step.status !== 401 && actorOf(terminalCtrl)) && (ctx.hasForeignTenantData || Boolean(postMutRb))
  if (multiHopDualDag) return { ok: true, family, explicit: false }
  const miss = family === 'economic_conservation' ? 'missing_economic_oracle_input' : 'missing_v8_oracle_input'
  return rejectFam(`v8_oracle_failed (${family}): ${miss} — provide terminalImpact.oracleInput.`, [miss, 'terminalImpact.oracleInput'])
}

function verifyTerminalImpactGate(
  receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, factLog: HostFactLog, verifiedEdges: VerifiedEdgeResult[],
  hostTranscript: HostSignedTranscript, attackerTenants: ReadonlySet<string>, dagCaps: ReadonlySet<string>, capIdx: CapOriginIndex, options: CompositeVerifyOptions,
): { ok: true; terminalVerification?: ReceiptVerification; terminalOracleFamily?: V8OracleFamily | string; terminalEndpoint?: string } | { ok: false; reason: string; rejectedBy?: string; missingEvidence?: string[]; terminalVerification?: ReceiptVerification } {
  const ti = receipt.terminalImpact, effSummary = ti.summary !== undefined ? ti.summary : ti.claimedImpact
  if (effSummary.replace(/\s+/g, '').length < 12) return { ok: false, reason: 'terminal_impact_summary_missing: terminalImpact.summary must be a meaningful non-empty description (>= 12 non-whitespace chars).', rejectedBy: 'terminal_impact_summary_missing', missingEvidence: ['terminal_impact_summary_missing'] }
  const termHop = dag.hopsById.get(ti.terminalHopId)!
  if (ti.terminalExchangeId && !termHop.exchangeIds.includes(ti.terminalExchangeId)) return { ok: false, reason: `terminalExchangeId "${ti.terminalExchangeId}" does not belong to terminal hop "${termHop.hopId}".`, rejectedBy: 'terminal_exchange_invalid', missingEvidence: ['terminal_exchange_in_final_hop'] }
  const termEx = ti.terminalExchangeId ? idx.entriesById.get(ti.terminalExchangeId)! : [...termHop.exchangeIds].reverse().map(id => idx.entriesById.get(id)!).find(e => e.step.arm === 'probe' && is2xx(e.step.status))
  const termEndpoint = (termEx?.step.route ?? termEx?.step.pathAndQuery ?? termHop.target.pathAndQuery ?? '').trim(), termFam = normRouteFam(termEndpoint, termEx?.entityId), contract = resolveTerminalContract(receipt.terminalVulnClass)
  const evalEmbeddedProof = (pr: ProofReceipt, hop: HopReceipt, label: string) => {
    const hopEx = new Set(hop.exchangeIds), hopOob = new Set(hop.oobEventIds), hopTr = new Set(hop.browserTraceIds)
    if (pr.exchangeIds.some(id => !hopEx.has(id)) || pr.oobEventIds.some(id => !hopOob.has(id)) || pr.browserTraceIds.some(id => !hopTr.has(id))) return { ok: false as const, reason: `${label} cites exchange/OOB/trace ID outside hop "${hop.hopId}".`, rejectedBy: 'embedded_receipt_unbound' }
    const clean = sanitizeEmbeddedProofReceipt(pr), shRes = resolveOracleEvaluator(options).evaluate(factLog, { kind: 'single_hop', receipt: clean }, { signingKey: options.signingKey, strictHostDerivation: true })
    const ver = shRes.singleHop ?? { confirmed: shRes.confirmed, vulnClass: clean.vulnClass, rule: 'none' as const, reason: shRes.reason, observed: clean.claimedDelta, expected: 'host-custody verified terminal receipt' }
    return ver.confirmed ? { ok: true as const, ver } : { ok: false as const, reason: ver.reason, rejectedBy: 'embedded_receipt_rejected', ver }
  }
  let terminalVerification: ReceiptVerification | undefined
  for (const h of receipt.hops) {
    if (!h.proofReceipt || (h.hopId === termHop.hopId && ti.proofReceipt && h.proofReceipt === ti.proofReceipt)) continue
    const hr = evalEmbeddedProof(h.proofReceipt, h, `hop "${h.hopId}" proofReceipt`)
    if (!hr.ok) return { ok: false, reason: hr.reason, rejectedBy: hr.rejectedBy, ...(hr.ver ? { terminalVerification: hr.ver } : {}) }
  }
  if (ti.proofReceipt) {
    const prContract = resolveTerminalContract(ti.proofReceipt.vulnClass)
    if (!contract || !prContract || prContract !== contract) return { ok: false, reason: `terminal_proof_class_mismatch: proofReceipt.vulnClass "${ti.proofReceipt.vulnClass}" is incompatible with terminalVulnClass "${receipt.terminalVulnClass}".`, rejectedBy: 'terminal_proof_class_mismatch' }
    const tr = evalEmbeddedProof(ti.proofReceipt, termHop, 'terminalImpact.proofReceipt'); terminalVerification = tr.ver
    if (!tr.ok) return { ok: false, reason: tr.reason, rejectedBy: tr.rejectedBy, ...(terminalVerification ? { terminalVerification } : {}) }
  }
  if (options.verifyTerminalImpact) {
    const v = options.verifyTerminalImpact(receipt, hostTranscript); if (!v.confirmed) return { ok: false, reason: v.reason, terminalVerification }
    const normCls = receipt.terminalVulnClass.trim().toLowerCase(), fam = v.family ?? ti.oracleFamily ?? (V8_ORACLE_FAMILY_SET.has(normCls) ? normCls as V8OracleFamily : undefined)
    return { ok: true, terminalVerification, ...(fam ? { terminalOracleFamily: fam } : {}), ...(termEndpoint ? { terminalEndpoint: termEndpoint } : {}) }
  }
  if (!contract) return { ok: false, reason: `terminal_class_unmapped: "${receipt.terminalVulnClass}" is not in TERMINAL_CLASS_CONTRACT.`, rejectedBy: 'terminal_class_unmapped', missingEvidence: ['mapped_terminal_vuln_class'], ...(terminalVerification ? { terminalVerification } : {}) }
  const failUnproven = (reason = TERMINAL_IMPACT_UNPROVEN_HINT, extra?: string[]) => ({ ok: false as const, reason, rejectedBy: 'terminal_impact_unproven', missingEvidence: extra ? [...extra, TERMINAL_IMPACT_UNPROVEN_HINT] : [TERMINAL_IMPACT_UNPROVEN_HINT], ...(terminalVerification ? { terminalVerification } : {}) })
  const hasEntryBody = (e: HostTranscriptEntry): boolean => e.step.json !== undefined || (typeof e.step.body === 'string' && e.step.body.trim().length > 0)
  const isStubEntry = (e: HostTranscriptEntry): boolean => hasEntryBody(e) && isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method, e.step.route ?? e.step.pathAndQuery)
  const isCrossTenantCls = CROSS_TENANT_CLASS_RE.test(receipt.terminalVulnClass)
  const isOwnTenantOnly = (e: HostTranscriptEntry): boolean => { const ts = extractTenantMarkers(e.step.json, e.step.body); return ts.size > 0 && attackerTenants.size > 0 && [...ts].every(t => attackerTenants.has(t)) }
  const postMutRb = (!termEx || !stepReadsState(termEx.step)) ? ti.postChainReadbackExchangeIds.map(id => idx.entriesById.get(id)).find((e): e is HostTranscriptEntry => {
    if (!e || (termEx && e.exchangeId === termEx.exchangeId)) return false
    const mono = !termEx || !isFiniteTs(termEx.timestampMs) || (isFiniteTs(e.timestampMs) && e.timestampMs >= termEx.timestampMs)
    return is2xx(e.step.status) && mono && (stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'post_chain_readback') && hasEntryBody(e) && !isStubEntry(e) && (!isCrossTenantCls || !isOwnTenantOnly(e))
  }) : undefined
  const termEdgeOf = (ch: string) => verifiedEdges.some(e => e.toHopId === termHop.hopId && e.kind === 'async_pivot_binding' && e.verified && receipt.causalEdges[e.edgeIndex]?.kind === 'async_pivot_binding' && (receipt.causalEdges[e.edgeIndex] as { channel: string }).channel === ch)
  const hasOobEdge = termEdgeOf('oob_relay'), hasPollEdge = termEdgeOf('poll_convergence'), hasBrowserEdge = termEdgeOf('browser_trace')
  const termProbes = termHop.exchangeIds.map(id => idx.entriesById.get(id)!).filter(e => e.step.arm === 'probe')
  const hasBoundOob = contract === 'oob' && (hasOobEdge || termHop.oobEventIds.some(id => {
    const oob = idx.oobById.get(id); if (!oob?.delivered || !isFiniteTs(oob.receivedAtMs)) return false
    const toks = [oob.token, oob.canaryId, ...(oob.correlationIds ?? [])].filter((t): t is string => Boolean(t && t.trim().length >= 6))
    return toks.length > 0 && termProbes.some(p => isFiniteTs(p.timestampMs) && p.timestampMs <= oob.receivedAtMs! && toks.some(t => entryCarriesRequestToken(p, t)))
  }))
  const hasBoundBrowser = (contract === 'browser' && termHop.browserTraceIds.some(id => (idx.tracesById.get(id)?.sinks?.length ?? 0) > 0)) || (contract === 'oob' && hasBrowserEdge)
  const hasBody = Boolean(termEx && hasEntryBody(termEx)), isStub = Boolean(termEx && isStubEntry(termEx)) || Boolean(ti.proofReceipt?.exchangeIds.some(id => { const e = idx.entriesById.get(id); return Boolean(e && e.step.arm !== 'control' && is2xx(e.step.status) && isStubEntry(e)) }))
  if (ti.terminalExchangeId && (!termEx || termEx.step.arm !== 'probe' || !is2xx(termEx.step.status))) return failUnproven(`terminalExchangeId "${ti.terminalExchangeId}" is not a succeeding probe exchange.`)
  if (termEx && (termEx.evidenceRole === 'host_capability_op' || termEx.evidenceRole === 'host_crypto_op')) return failUnproven()
  const hasPostMutation = Boolean(postMutRb), termHopSet = new Set(termHop.exchangeIds), nonTermExSet = new Set(receipt.hops.filter(h => h.hopId !== termHop.hopId).flatMap(h => h.exchangeIds).filter(id => !termHopSet.has(id)))
  const termRawActor = termEx ? actorOf(termEx) : null, termActor = termEx ? resolvedActorOf(termEx, capIdx) : null, termAuthd = Boolean(termActor && !ANON_ACTOR_RE.test(termActor)), normAct = (a: string | null) => (!a || ANON_ACTOR_RE.test(a.trim())) ? null : a.trim().toLowerCase()
  const termUsesDagCap = Boolean(termEx && ((termEx.consumedCapabilities ?? []).some(c => dagCaps.has(c)) || (termEx.cryptoAttestations ?? []).some(x => dagCaps.has(x.derivedFromCapabilityId)) || (termRawActor && dagCaps.has(termRawActor))))
  const hasVerifiedTermEdge = verifiedEdges.some(e => e.toHopId === termHop.hopId && e.verified), hasTermDerivedCrypto = verifiedEdges.some(e => e.toHopId === termHop.hopId && e.kind === 'derived_crypto_binding' && e.verified), allowDynCtrl = receipt.hops.length >= 2 && hasVerifiedTermEdge
  const ctrlCandidates = [...ti.preChainControlExchangeIds, ...termHop.exchangeIds, ...receipt.causalEdges.flatMap(ed => ed.kind === 'state_transition_binding' && ed.toHopId === termHop.hopId ? ed.ablationExchangeIds : [])]
  const matchesCtrlTarget = (c: HostTranscriptEntry, ref: HostTranscriptEntry): boolean => {
    const cRaw = c.step.pathAndQuery ?? c.step.route ?? '', rRaw = ref.step.pathAndQuery ?? ref.step.route ?? '', hostEid = ref.entityId?.trim()
    if ((c.origin && ref.origin && c.origin.trim().toLowerCase() !== ref.origin.trim().toLowerCase()) || c.step.method.toUpperCase() !== ref.step.method.toUpperCase() || canonicalNonAuthQuery(cRaw) !== canonicalNonAuthQuery(rRaw)) return false
    const exactPath = Boolean(cleanExactPath(cRaw) && cleanExactPath(cRaw) === cleanExactPath(rRaw))
    if (!exactPath) return allowDynCtrl && c.step.status !== 404 && matchesNormalizedCtrlPath(cRaw, rRaw)
    return !(hostEid && c.entityId?.trim() && c.entityId.trim().toLowerCase() !== hostEid.toLowerCase()) && (c.step.status !== 404 || !hostEid || entryMatchesEntity(c, hostEid))
  }
  const terminalCtrl = ctrlCandidates.map(id => idx.entriesById.get(id)).find((c): c is HostTranscriptEntry => {
    if (!c || (termEx && c.exchangeId === termEx.exchangeId) || nonTermExSet.has(c.exchangeId) || (c.step.arm !== 'control' && c.replayAttempt !== 'ablation_control') || typeof c.step.status !== 'number' || !DENIED_CONTROL_STATUSES.has(c.step.status)) return false
    const ca = resolvedActorOf(c, capIdx)
    if ((c.step.status === 401 && termAuthd && (!ca || ANON_ACTOR_RE.test(ca))) || (!termUsesDagCap && termAuthd && normAct(ca) !== normAct(termActor))) return false
    return Boolean((termEx && matchesCtrlTarget(c, termEx)) || (postMutRb && matchesCtrlTarget(c, postMutRb)))
  })
  const hasCleanDeniedCtrl = Boolean(terminalCtrl)
  const termTenants = termEx ? extractTenantMarkers(termEx.step.json, termEx.step.body) : new Set<string>(), ownTenantOnly = Boolean(termEx && termTenants.size > 0 && attackerTenants.size > 0 && [...termTenants].every(t => attackerTenants.has(t))), hasForeignTenantData = Boolean(termEx && !isStub && hasBody && attackerTenants.size > 0 && [...termTenants].some(t => !attackerTenants.has(t)))
  const v8Default = dispatchDefaultV8Oracle(receipt, dag, idx, factLog, termEx, options, terminalCtrl, postMutRb, { termEndpoint, termFam, hasOob: hasBoundOob, hasBrowser: hasBoundBrowser, hasBody, isStub, ownTenantOnly, hasForeignTenantData, hasVerifiedTermEdge })
  if (v8Default && !v8Default.ok) return { ...v8Default, ...(terminalVerification ? { terminalVerification } : {}) }
  const okTerm = (fam?: V8OracleFamily | string) => ({ ok: true as const, ...(terminalVerification ? { terminalVerification } : {}), ...(fam ? { terminalOracleFamily: fam } : {}), ...(termEndpoint ? { terminalEndpoint: termEndpoint } : {}) })
  if (contract === 'oob') return (hasBoundOob || hasPollEdge || hasBoundBrowser || Boolean(ti.proofReceipt && terminalVerification?.confirmed)) ? okTerm() : failUnproven(`Class "${receipt.terminalVulnClass}" requires a hop-bound OOB callback, converged poll, or verified proofReceipt.`)
  if (contract === 'browser') return (hasBoundBrowser || Boolean(ti.proofReceipt && terminalVerification?.confirmed)) ? okTerm() : failUnproven(`Class "${receipt.terminalVulnClass}" requires a hop-bound browser sink trace or verified proofReceipt.`)
  if (contract === 'injection_or_redirect') return (ti.proofReceipt && terminalVerification?.confirmed && !isStub) ? okTerm() : failUnproven(`Class "${receipt.terminalVulnClass}" requires a verified class-matched proofReceipt.`)
  if (!termEx && !hasPostMutation) return failUnproven(`Terminal hop "${termHop.hopId}" has no succeeding terminal evidence.`)
  if (isStub && !hasPostMutation) return failUnproven()
  const crossOrReplay = isCrossTenantCls || contract === 'v8_pivot' || contract === 'v8_crypto'
  if (termEx && ownTenantOnly && !hasPostMutation && (crossOrReplay || !hasCleanDeniedCtrl)) return failUnproven()
  if (contract === 'v8_economic') return (v8Default?.explicit && v8Default.family === 'economic_conservation') ? okTerm('economic_conservation') : failUnproven('economic_conservation requires verified host-derived conservation oracle input.')
  const singleHopProofOk = Boolean(ti.proofReceipt && terminalVerification?.confirmed && receipt.hops.length === 1 && !v8Default)
  const hasDerivedTerminalProof = contract === 'auth_or_logic' && hasTermDerivedCrypto && (hasPostMutation || hasForeignTenantData)
  if (!singleHopProofOk) {
    if (!hasCleanDeniedCtrl && !hasDerivedTerminalProof) return failUnproven(`Missing clean denied control (401/403/404) bound to terminal target for ${receipt.terminalVulnClass}. ${TERMINAL_IMPACT_UNPROVEN_HINT}`, ['clean_denied_control_401_403_404'])
    if ((!termEx && !hasPostMutation) || !termEndpoint || !termFam) return failUnproven(`Missing concrete terminal exchange or endpoint for ${receipt.terminalVulnClass}. ${TERMINAL_IMPACT_UNPROVEN_HINT}`, ['terminal_exchange_with_endpoint'])
    if (termEx && !hasPostMutation && (!hasBody || isStub || (ownTenantOnly && crossOrReplay))) return failUnproven()
  }
  return okTerm(v8Default?.family)
}

export function verifyCompositeReceipt(rawReceipt: unknown, hostTranscript: HostSignedTranscript, options: CompositeVerifyOptions = {}): CompositeReceiptVerification {
  const parsed = compositeProofReceiptSchema.safeParse(rawReceipt)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    return { confirmed: false, chainId: 'invalid', terminalVulnClass: 'invalid', replayMode: 'fresh_clean_replay', modeBVerified: false, hopCount: 0, verifiedEdges: [], failedStage: 'schema', reason: `Schema validation failed: ${issue?.path.join('.') || 'receipt'} ${issue?.message ?? ''}`.slice(0, 400) }
  }
  const factLog = options.factLog ?? HostFactLog.fromTranscript(hostTranscript), { receipt, inferredEdges } = augmentCompositeReceiptWithAutoDag(parsed.data, factLog)
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
  const verifiedEdges: VerifiedEdgeResult[] = [], knownCaps = new Set<string>(), capIdx = buildCapOriginIndex(idx.entriesById.values(), ANON_ACTOR_RE)
  for (const hopId of dag.topoOrder) {
    for (const { edgeIndex, edge } of dag.incomingByHop.get(hopId) ?? []) {
      const fromHop = dag.hopsById.get(edge.fromHopId)!, toHop = dag.hopsById.get(edge.toHopId)!
      const base: EdgeBase = { edgeIndex, kind: edge.kind, fromHopId: edge.fromHopId, toHopId: edge.toHopId, fromEx: [...fromHop.exchangeIds, ...fromHop.oobEventIds, ...fromHop.browserTraceIds], toEx: [...toHop.exchangeIds, ...toHop.oobEventIds, ...toHop.browserTraceIds] }
      const res = edge.kind === 'value_binding' ? verifyValueBinding(base, edge, fromHop, toHop, idx)
        : edge.kind === 'derived_crypto_binding' ? verifyDerivedCryptoBinding(base, edge, fromHop, toHop, idx)
          : edge.kind === 'state_transition_binding' ? verifyStateTransitionBinding(base, edge, fromHop, toHop, idx, knownCaps, capIdx, receipt.terminalImpact.terminalHopId)
            : verifyAsyncPivotBinding(base, edge, fromHop, toHop, idx, options.signingKey, toHop.hopId === receipt.terminalImpact.terminalHopId)
      verifiedEdges.push(res)
      if (!res.verified) return fail('edge_binding', res.reason, verifiedEdges)
    }
    recordHopCapabilities(dag.hopsById.get(hopId)!, idx, knownCaps, hopId === receipt.terminalImpact.terminalHopId)
  }
  const provRes = verifyAttackerProvenance(receipt, dag, idx, options, capIdx)
  if (!provRes.ok) return fail('attacker_provenance', provRes.reason, verifiedEdges)
  const replayRes = verifyReplayMode(receipt, dag, idx, options)
  if (!replayRes.ok) return fail('replay_mode', replayRes.reason, verifiedEdges)
  const termRes = verifyTerminalImpactGate(receipt, dag, idx, factLog, verifiedEdges, hostTranscript, provRes.attackerTenants, new Set(provRes.derivedCapabilities), capIdx, options)
  if (!termRes.ok) return fail('terminal_impact', termRes.reason, verifiedEdges, termRes.terminalVerification, termRes.rejectedBy, termRes.missingEvidence)
  return {
    confirmed: true, chainId: receipt.chainId, terminalVulnClass: receipt.terminalVulnClass, replayMode: receipt.replayMode,
    modeBVerified: receipt.replayMode === 'one_shot_transcript', hopCount: receipt.hops.length, verifiedEdges,
    reason: `CompositeProofReceipt confirmed (${receipt.hops.length} hop(s), ${verifiedEdges.length} verified causal edge(s), mode=${receipt.replayMode}).`,
    ...(termRes.terminalOracleFamily ? { terminalOracleFamily: termRes.terminalOracleFamily } : {}),
    ...(termRes.terminalEndpoint ? { terminalEndpoint: termRes.terminalEndpoint } : {}),
    ...(termRes.terminalVerification ? { terminalVerification: termRes.terminalVerification } : {}),
    evidence: { topoOrder: dag.topoOrder, roots: dag.roots, derivedCapabilities: provRes.derivedCapabilities, ...(inferredEdges.length ? { autoInferredEdgeCount: inferredEdges.length } : {}), ...(termRes.terminalOracleFamily ? { terminalOracleFamily: termRes.terminalOracleFamily } : {}), ...(termRes.terminalEndpoint ? { terminalEndpoint: termRes.terminalEndpoint } : {}) },
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
