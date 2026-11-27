/**
 * CompositeProofReceipt — unified multi-hop DAG confirmation verifier (v8).
 * Verifies 1..8 hop causal chains over host-signed transcripts, provenance, Mode-A/B replay, and terminal-impact oracles.
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { z } from 'zod'
import { scopedAssetOrigin } from '../domain.ts'
import { routeFamily, stepReadsState, type RoleName } from './oracle-invariants.ts'
import { augmentCompositeReceiptWithAutoDag, matchesBoundTerminalControl, matchesNormalizedCtrlPath } from './composite-autodag.ts'
import { analyzeCrossTenantTerminalEvidence, collectCitedReceiptExchanges, deriveHostDualTenantRawInput, evaluateExchangeTenantPrivilege, inferV8OracleFamilyFromInput, isReadOnlyDirectoryOrMetadataImpact, normalizeCompositeTerminalEndpoint, parsePersonaPrivilegeProfile, verifyReadOnlyStateTransitionGuard } from './causal-proof-compiler.ts'
import { resolveCompositeTerminalExchange } from './composite-terminal.ts'
import { HostFactLog } from './host-fact-log.ts'
import { proofReceiptSchema, receiptIdSchema } from './proof-receipt.ts'
import { extractTenantMarkers, isJobOrHandleStub, type V8OracleFamily } from './v8-oracle-families.ts'
import { TERMINAL_CLASS_CONTRACT, buildCapOriginIndex, canonicalNonAuthQuery, cleanExactPath, collectUrlParamTokens, entryCarriesRequestToken, entryMatchesCorrelation, entryMatchesEntity, inferSupplementalHostCausalEdges, isHydratedStub, isPrivilegedActorOrRole, matchesNormalizedDotSegmentPath, normalizeV8OracleInputKeys, partitionNonCausalControlHops, resolveEntryIdentity, resolveTerminalContract, resolveV8OracleFamilyOrDiagnostic, sanitizeEmbeddedProofReceipt, selectStateTransitionPair, type CapOriginIndex, type EconomicAutoHydrateContext, type TerminalContractKind } from './v8-oracle-hydrate.ts'
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
  timestampMs?: number; actorPersona?: string | null; actorRoleLabel?: string | null; actorTenant?: string | null; actorPrivilege?: RoleName | null; emittedCapabilities?: readonly string[]
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
  attackerPersonas?: readonly string[]; forbiddenShortcutPersonas?: readonly string[]; dualTenantAbacPersonas?: readonly string[]; benchmarkMode?: boolean; requireCleanSessionFlag?: boolean; signingKey?: string
  v8OracleInput?: Record<string, unknown>; strictHostDerivation?: boolean; factLog?: HostFactLog; oracleEvaluator?: CompositeOracleEvaluator; personaRoleLabels?: Readonly<Record<string, string>>
  verifyTerminalImpact?: (receipt: CompositeProofReceipt, transcript: HostSignedTranscript) => { confirmed: boolean; reason: string; family?: string; evidence?: Record<string, unknown> }
}
export interface VerifiedEdgeResult { edgeIndex: number; kind: CausalEdgeKind; fromHopId: string; toHopId: string; verified: boolean; reason: string; evidence?: Record<string, unknown> }
export type CompositeFailureStage = 'schema' | 'dag_topology' | 'transcript_integrity' | 'edge_binding' | 'attacker_provenance' | 'replay_mode' | 'terminal_impact'
export interface CompositeReceiptVerification {
  confirmed: boolean; chainId: string; terminalVulnClass: string; replayMode: ReplayMode; modeBVerified: boolean; hopCount: number
  verifiedEdges: VerifiedEdgeResult[]; reason: string; failedStage?: CompositeFailureStage; rejectedBy?: string | null; missingEvidence?: string[]
  terminalOracleFamily?: V8OracleFamily | string | null; terminalEndpoint?: string | null; terminalOrigin?: string | null
  terminalVerification?: ReceiptVerification; evidence?: Record<string, unknown>
}

// --- Cryptographic, Hashing & Transcript Helpers ----------------------------
const CONSUMED_STATE_RE = /\b(?:already[_\s-]?(?:consumed|redeemed|used|claimed|applied|settled)|token[_\s-]?(?:consumed|used|redeemed|spent)|one[_\s-]?time|nonce[_\s-]?(?:used|replayed|consumed)|invite[_\s-]?(?:redeemed|consumed|used)|state[_\s-]?(?:consumed|exhausted|finalized))\b/i
const ABLATION_DENIED_STATUSES = new Set([401, 403, 404, 409, 412, 422]), DENIED_CONTROL_STATUSES = new Set([401, 403, 404]), SHA256_RE = /^[0-9a-f]{64}$/
const CROSS_TENANT_CLASS_RE = /^(?:dual_tenant_abac|parser_cache_differential)$|dual[_-]?tenant|cross[_-]?tenant|tenant[_-]?(?:isolation|bleed|leak|export)|abac|cache[_-]?(?:bleed|poison|deception|diff|bypass)|export[_-]?(?:bypass|leak|disclosure)|presign|cwe[-_]?(?:444|639)|\bidor\b|\bbola\b/i, PRIV_ESC_CLASS_RE = /^(?:privilege_escalation|bfla|authz_escalation)$/i
const TERMINAL_IMPACT_UNPROVEN_HINT = "terminal_impact_unproven: obtaining a job/export handle, signed URL, or cache ack is an intermediate capability (seal with ctx.seal_capability), NOT terminal impact — fetch the target resource with the derived URL/handle to prove unauthorized foreign-tenant data exposure or privileged state mutation, or settle with record_coverage(status='ruled_out', proofGapReason='invariant_enforced_hardened') if blocked"
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
const oobBoundToProbes = (oob: HostOobEvent | undefined, probes: readonly HostTranscriptEntry[]): boolean => {
  if (!oob?.delivered || !isFiniteTs(oob.receivedAtMs)) return false
  const toks = [oob.token, oob.canaryId, ...(oob.correlationIds ?? [])].filter((t): t is string => Boolean(t && t.trim().length >= 6))
  return toks.length > 0 && probes.some(p => isFiniteTs(p.timestampMs) && p.timestampMs <= oob.receivedAtMs! && toks.some(t => entryCarriesRequestToken(p, t)))
}
const is2xx = (st: number | null | undefined): boolean => typeof st === 'number' && st >= 200 && st < 300
const isFiniteTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts >= 0
const isExecArm = (e: HostTranscriptEntry, isTerm = false): boolean => e.step.arm === 'probe' || (!isTerm && e.step.arm === 'setup')
const normOrigin = (o: string | null | undefined): string => (o ?? '').trim().replace(/\/+$/, '').toLowerCase()
const normHopPath = (p: string | null | undefined): string => { const s = (p ?? '').trim(); return !s ? '' : (cleanExactPath(s) || '/') }
const matchesHopPath = (a: string, b: string): boolean => { const da = normHopPath(a), db = normHopPath(b); return Boolean(da && db && (da === db || matchesNormalizedCtrlPath(a, b))) }
const normRouteFam = (p: string | null | undefined, eid?: string): string => normalizeCompositeTerminalEndpoint(p, eid)
const normAct = (a: string | null | undefined): string | null => (!a || ANON_ACTOR_RE.test(a.trim())) ? null : a.trim().toLowerCase()
const actorOf = (e: HostTranscriptEntry): string | null => (e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null))
const isLoginCap = (cap: string, capIdx: CapOriginIndex): boolean => Boolean(capIdx.emitterActorOf(cap)?.isLogin)
const sessionActorOf = (e: HostTranscriptEntry, capIdx: CapOriginIndex): string | null => { const a = actorOf(e); return !a || ANON_ACTOR_RE.test(a) ? null : a.startsWith('cap:') ? (isLoginCap(a, capIdx) ? normAct(capIdx.actorOf(a)) : null) : normAct(a) }
const probeActorOf = (e: HostTranscriptEntry, capIdx: CapOriginIndex): string | null => { const a = actorOf(e); return !a || ANON_ACTOR_RE.test(a) ? null : a.startsWith('cap:') ? normAct(capIdx.actorOf(a)) : normAct(a) }
const sameCredIdentity = (a: HostTranscriptEntry, b: HostTranscriptEntry, capIdx: CapOriginIndex): boolean => { const ar = actorOf(a), br = actorOf(b); if (ar && br && ar === br) return true; const sa = sessionActorOf(a, capIdx), sb = sessionActorOf(b, capIdx) ?? probeActorOf(b, capIdx); return Boolean(sa && sb && sa === sb) }
const roleOf = (e: HostTranscriptEntry): string | null => resolveEntryIdentity(e).role
const probeTenantsOf = (e: HostTranscriptEntry, capIdx?: CapOriginIndex): string[] => { const out: string[] = [], a = actorOf(e), dt = (!a || ANON_ACTOR_RE.test(a) || a.startsWith('cap:')) ? null : resolveEntryIdentity(e).tenant; if (dt) out.push(dt); if (capIdx) for (const c of [...(a?.startsWith('cap:') ? [a] : []), ...(e.consumedCapabilities ?? [])]) { const lt = capIdx.loginTenantOf(c); if (lt && !out.includes(lt)) out.push(lt) } return out }
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
    if ((t.startsWith('/') || /^https?:\/\//i.test(t)) && (t.includes('?') || t.includes('#'))) collectUrlParamTokens(t, out)
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
    if (pq) { leaves.add(pq); if (entry.origin) leaves.add(`${entry.origin.trim().replace(/\/+$/, '')}${pq}`) }
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

export function deriveSignedTerminalOrigin(receipt: CompositeProofReceipt, entries: readonly Pick<HostTranscriptEntry, 'exchangeId' | 'origin' | 'step'>[] | ReadonlyMap<string, Pick<HostTranscriptEntry, 'exchangeId' | 'origin' | 'step'>>): string | null {
  return resolveCompositeTerminalExchange(receipt, entries)?.origin?.trim() || null
}
export function verifyHopTargetsAgainstExchanges(receipt: CompositeProofReceipt, entriesById: ReadonlyMap<string, HostTranscriptEntry>, tracesById?: ReadonlyMap<string, HostBrowserTrace>, oobById?: ReadonlyMap<string, HostOobEvent>): { ok: true } | { ok: false; reason: string } {
  const matchesEntry = (h: HopReceipt, e: HostTranscriptEntry): string | null => {
    if (e.origin && normOrigin(e.origin) !== normOrigin(h.target.origin)) return `origin "${h.target.origin}" disagrees with signed exchange "${e.exchangeId}" origin "${e.origin}"`
    if (h.target.method && e.step.method.toUpperCase() !== h.target.method.toUpperCase()) return `method "${h.target.method}" disagrees with signed exchange "${e.exchangeId}" method "${e.step.method}"`
    const exPaths = [e.step.pathAndQuery, e.step.route].filter((p): p is string => Boolean(p && p.trim()))
    return (h.target.pathAndQuery && exPaths.length > 0 && !exPaths.some(p => matchesHopPath(h.target.pathAndQuery!, p))) ? `route "${h.target.pathAndQuery}" disagrees with signed exchange "${e.exchangeId}" path "${exPaths[0]}"` : null
  }
  for (const h of receipt.hops) {
    const isTerm = h.hopId === receipt.terminalImpact.terminalHopId, hopOrigin = normOrigin(h.target.origin), ti = receipt.terminalImpact
    if (h.exchangeIds.length > 0) {
      const allEx = h.exchangeIds.map(id => entriesById.get(id)).filter((e): e is HostTranscriptEntry => Boolean(e))
      const tiTermEx = isTerm && ti.terminalExchangeId && h.exchangeIds.includes(ti.terminalExchangeId) ? entriesById.get(ti.terminalExchangeId) : undefined
      const execEx = allEx.filter(e => isExecArm(e, isTerm)), cands = tiTermEx ? [tiTermEx] : (execEx.length > 0 ? execEx : allEx)
      for (const e of cands) if (e.origin && normOrigin(e.origin) !== hopOrigin) return { ok: false, reason: `Hop "${h.hopId}" target origin "${h.target.origin}" disagrees with signed exchange "${e.exchangeId}" origin "${e.origin}".` }
      if (cands.length > 0 && !cands.some(e => matchesEntry(h, e) === null)) return { ok: false, reason: `Hop "${h.hopId}" target ${matchesEntry(h, cands[0]!)}.` }
      if (isTerm && !tiTermEx) { const termEx = [...allEx].reverse().find(e => e.step.arm === 'probe' && is2xx(e.step.status)); const err = termEx ? matchesEntry(h, termEx) : null; if (err) return { ok: false, reason: `Terminal hop "${h.hopId}" target ${err}.` } }
    } else if (h.browserTraceIds.length > 0 && tracesById) {
      const trs = h.browserTraceIds.map(id => tracesById.get(id)).filter((t): t is HostBrowserTrace => Boolean(t?.origin))
      if (trs.length > 0 && !trs.some(t => normOrigin(t.origin) === hopOrigin)) return { ok: false, reason: `Hop "${h.hopId}" target origin "${h.target.origin}" disagrees with cited browser trace origin "${trs[0]!.origin}".` }
    } else if (h.oobEventIds.length > 0 && oobById) {
      const oobs = h.oobEventIds.map(id => oobById.get(id)).filter((o): o is HostOobEvent => Boolean(o?.targetOrigin))
      if (oobs.length > 0 && !oobs.some(o => normOrigin(o.targetOrigin) === hopOrigin)) return { ok: false, reason: `Hop "${h.hopId}" target origin "${h.target.origin}" disagrees with cited OOB event origin "${oobs[0]!.targetOrigin}".` }
    }
  }
  return { ok: true }
}
function recordHopCapabilities(hop: HopReceipt, idx: IndexedTranscript, target: Set<string>, isTerm = false): void {
  for (const id of hop.exchangeIds) {
    const e = idx.entriesById.get(id)!; if (!isExecArm(e, isTerm)) continue
    for (const c of e.emittedCapabilities ?? []) target.add(c)
    for (const a of e.cryptoAttestations ?? []) if (a.derivedCapabilityId) target.add(a.derivedCapabilityId)
  }
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
    const e = idx.entriesById.get(id)!; if (!isExecArm(e) || !isFiniteTs(e.timestampMs)) continue
    const caps = new Set<string>(e.emittedCapabilities ?? []); for (const a of e.cryptoAttestations ?? []) if (a.derivedCapabilityId) caps.add(a.derivedCapabilityId)
    out.push({ sourceId: id, timestampMs: e.timestampMs, capabilities: caps, digests: collectEntryDigests(e, 'response') })
  }
  for (const id of hop.oobEventIds) {
    const oob = idx.oobById.get(id)!; if (!oob.delivered || !isFiniteTs(oob.receivedAtMs)) continue
    const digests = new Set<string>((oob.observedValueDigests ?? []).map(d => d.toLowerCase())); if (oob.token) digests.add(sha256Hex(oob.token))
    out.push({ sourceId: id, timestampMs: oob.receivedAtMs, capabilities: new Set(oob.emittedCapabilities ?? []), digests })
  }
  for (const id of hop.browserTraceIds) {
    const tr = idx.tracesById.get(id)!; if (!isFiniteTs(tr.timestampMs)) continue
    out.push({ sourceId: id, timestampMs: tr.timestampMs, capabilities: new Set(tr.emittedCapabilities ?? []), digests: new Set((tr.observedValueDigests ?? []).map(d => d.toLowerCase())) })
  }
  return out
}
function matchOrderedPair(outputs: readonly HopOutputEvent[], reqs: readonly HostTranscriptEntry[], matchOut: (o: HopOutputEvent) => boolean, matchReq: (r: HostTranscriptEntry, o: HopOutputEvent) => boolean | 'out_of_order'): { ok: true; pair: { from: string; to: string; tFrom: number; tTo: number } } | { ok: false; outOfOrder: boolean; missingTs?: string } {
  let outOfOrder = false
  for (const o of outputs) if (matchOut(o)) for (const r of reqs) {
    const hit = matchReq(r, o); if (!hit) continue
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
  const pair = { from: idx.entriesById.get(sel.from.exchangeId)!, to: idx.entriesById.get(sel.to.exchangeId)! }, { logicalFallback } = sel, toRawActor = actorOf(pair.to), toAuth = Boolean(toRawActor && !ANON_ACTOR_RE.test(toRawActor)), toFam = normRouteFam(pair.to.step.route ?? pair.to.step.pathAndQuery, edge.entityId)
  const hopExSet = new Set([...fromHop.exchangeIds, ...toHop.exchangeIds])
  const toUsesNewCap = (pair.to.consumedCapabilities ?? []).some(c => dagDerivedCaps.has(c)) || (pair.to.cryptoAttestations ?? []).some(x => dagDerivedCaps.has(x.derivedFromCapabilityId)) || Boolean(toRawActor && dagDerivedCaps.has(toRawActor))
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
    const abRaw = actorOf(ab)
    if (abRaw?.startsWith('cap:') && abRaw !== toRawActor && !isLoginCap(abRaw, capIdx)) return edgeFail(base, `Ablation "${abId}" uses unbound capability credential "${abRaw}" [actor_mismatch].`)
    if (!toUsesNewCap && toAuth && (logicalFallback ? !sameCredIdentity(ab, pair.to, capIdx) : (abRaw !== null && !sameCredIdentity(ab, pair.to, capIdx)))) return edgeFail(base, `Ablation "${abId}" actor "${abRaw ?? 'anon'}" mismatches toHop actor "${toRawActor}" [actor_mismatch].`)
    if (denied || (!logicalFallback && labeled && ab.step.evidenceRole === 'invariant_preserved')) validAblation = ab
    else diags.push(`${abId}: status=${st ?? 'null'} not a denial (401/403/404/409/412/422)`)
  }
  if (!validAblation) return edgeFail(base, `state_transition_binding on "${edge.entityId}" lacks a passing clean-session ablation control [${diags.join('; ') || 'no ablationExchangeIds cited'}].`)
  const roErr = verifyReadOnlyStateTransitionGuard(pair, edge.entityId, validAblation, logicalFallback); if (roErr) return edgeFail(base, roErr)
  return edgeOk(base, 'state_transition_binding verified with clean-session ablation control.', { entityId: edge.entityId, fromExchangeId: pair.from.exchangeId, toExchangeId: pair.to.exchangeId, ablationExchangeId: validAblation.exchangeId, ablationStatus: validAblation.step.status, ...(logicalFallback ? { bindingMode: 'logical_key_ablation' } : {}) })
}

function verifyAsyncPivotBinding(base: EdgeBase, edge: Extract<CausalEdgeBinding, { kind: 'async_pivot_binding' }>, fromHop: HopReceipt, toHop: HopReceipt, idx: IndexedTranscript, signingKey?: string, isTermTo = false): VerifiedEdgeResult {
  const triggers: number[] = []
  for (const id of fromHop.exchangeIds) { const e = idx.entriesById.get(id)!; if (is2xx(e.step.status) && isFiniteTs(e.timestampMs) && entryMatchesCorrelation(e, edge.correlationId)) triggers.push(e.timestampMs) }
  for (const id of fromHop.browserTraceIds) { const tr = idx.tracesById.get(id)!; if (isFiniteTs(tr.timestampMs) && tr.correlationIds?.includes(edge.correlationId)) triggers.push(tr.timestampMs) }
  if (triggers.length === 0) return edgeFail(base, `fromHop "${fromHop.hopId}" has no trigger matching "${edge.correlationId}".`)
  const minTrigger = Math.min(...triggers)
  if (edge.channel === 'oob_relay') {
    for (const id of edge.oobEventId ? [edge.oobEventId] : toHop.oobEventIds) {
      if (!toHop.oobEventIds.includes(id)) continue
      const oob = idx.oobById.get(id), ok = oob?.delivered && isFiniteTs(oob.receivedAtMs) && (oob.token === edge.correlationId || oob.canaryId === edge.correlationId || oob.callbackId === edge.correlationId || (oob.correlationIds?.includes(edge.correlationId) ?? false))
      if (!ok || !oob) continue
      return oob.receivedAtMs < minTrigger ? edgeFail(base, `OOB event "${id}" preceded trigger (t_trigger > t_observed).`) : edgeOk(base, 'async_pivot_binding (oob_relay) verified.', { correlationId: edge.correlationId, oobEventId: id, tTrigger: minTrigger, tObserved: oob.receivedAtMs })
    }
    return edgeFail(base, `No delivered OOB event in "${toHop.hopId}" matches "${edge.correlationId}".`)
  }
  if (edge.channel === 'browser_trace') {
    for (const id of edge.browserTraceId ? [edge.browserTraceId] : toHop.browserTraceIds) {
      if (!toHop.browserTraceIds.includes(id)) continue
      const tr = idx.tracesById.get(id), hasEffect = (tr?.sinks?.length ?? 0) > 0 || (tr?.emittedCapabilities?.length ?? 0) > 0
      if (!tr || !isFiniteTs(tr.timestampMs) || !hasEffect || !tr.correlationIds?.includes(edge.correlationId)) continue
      return tr.timestampMs < minTrigger ? edgeFail(base, `Browser trace "${id}" preceded trigger (t_trigger > t_observed).`) : edgeOk(base, 'async_pivot_binding (browser_trace) verified.', { correlationId: edge.correlationId, browserTraceId: id, tTrigger: minTrigger, tObserved: tr.timestampMs })
    }
    return edgeFail(base, `No browser trace in "${toHop.hopId}" matches "${edge.correlationId}".`)
  }
  const polls = edge.pollRecordId ? [idx.pollsById.get(edge.pollRecordId)].filter((p): p is HostAsyncPollRecord => !!p) : idx.allPolls
  for (const poll of polls) {
    if (!poll.converged || (signingKey && !verifyHostRecordSignature(poll, signingKey)) || (poll.entityId !== edge.correlationId && !poll.correlationIds?.includes(edge.correlationId)) || !isFiniteTs(poll.tTriggerMs) || !isFiniteTs(poll.tObservedMs)) continue
    return (poll.tObservedMs < poll.tTriggerMs || poll.tObservedMs < minTrigger) ? edgeFail(base, `Async poll "${poll.id}" violated monotonic ordering.`) : edgeOk(base, `async_pivot_binding (${edge.channel}) verified via poll convergence.`, { correlationId: edge.correlationId, pollRecordId: poll.id, tTrigger: minTrigger, tObserved: poll.tObservedMs })
  }
  if (edge.channel === 'async_job') for (const id of toHop.exchangeIds) {
    const e = idx.entriesById.get(id)!, body = serializeBodyText(e)
    if (!isExecArm(e, isTermTo) || !is2xx(e.step.status) || !isFiniteTs(e.timestampMs) || !entryMatchesCorrelation(e, edge.correlationId)) continue
    const stub = isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method, e.step.route ?? e.step.pathAndQuery)
    if (!(/^(?:POST|PUT|PATCH)$/i.test(e.step.method) && (e.step.status === 202 || stub)) && !(stepReadsState(e.step) && body.trim())) continue
    return e.timestampMs <= minTrigger ? edgeFail(base, `Async job readback "${id}" did not follow trigger.`) : edgeOk(base, 'async_pivot_binding (async_job) verified.', { correlationId: edge.correlationId, targetExchangeId: id, tTrigger: minTrigger, tObserved: e.timestampMs })
  }
  return edgeFail(base, `No converged async record in "${toHop.hopId}" matches "${edge.correlationId}".`)
}

// --- Attacker-Origin Provenance & Replay Mode Policy ------------------------
function verifyAttackerProvenance(receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, options: CompositeVerifyOptions, capIdx: CapOriginIndex, verifiedEdges: readonly VerifiedEdgeResult[]): { ok: true; derivedCapabilities: string[]; attackerTenants: ReadonlySet<string> } | { ok: false; reason: string } {
  const allowedSet = options.attackerPersonas?.length ? new Set(options.attackerPersonas) : null, forbiddenSet = new Set(options.forbiddenShortcutPersonas ?? []), dualAbacSet = new Set(options.dualTenantAbacPersonas ?? [])
  const ti = receipt.terminalImpact, normCls = receipt.terminalVulnClass.trim().toLowerCase(), rawOracleIn = ti.oracleInput ?? options.v8OracleInput
  const famRes = resolveV8OracleFamilyOrDiagnostic(ti.oracleFamily, normCls, rawOracleIn, inferV8OracleFamilyFromInput), inferredFam = famRes.ok && famRes.inferred ? famRes.family : null
  const isDualAbac = ti.oracleFamily === 'dual_tenant_abac' || normCls === 'dual_tenant_abac' || inferredFam === 'dual_tenant_abac', allowDualCrossTenant = isDualAbac || (CROSS_TENANT_CLASS_RE.test(normCls) && !/\b(?:bola|idor)\b/i.test(normCls))
  const dualAbacExempt = (a: string | null): boolean => Boolean(a && dualAbacSet.has(a) && allowDualCrossTenant), labelFor = (a: string | null, rl?: string | null): string | null => { const reg = a ? options.personaRoleLabels?.[a] : undefined; return reg && rl && reg !== rl ? `${reg}; ${rl}` : (reg ?? rl ?? null) }
  const rootSet = new Set(dag.roots), dagCaps = new Set<string>(), probeTenants = new Set<string>(), boundTraces = new Set<string>(), boundOobs = new Set<string>(), forbiddenTraceCaps = new Set<string>()
  const termHop = dag.hopsById.get(ti.terminalHopId)!, termExForDual = ti.terminalExchangeId ? idx.entriesById.get(ti.terminalExchangeId) : [...termHop.exchangeIds].reverse().map(id => idx.entriesById.get(id)!).find(e => e.step.arm === 'probe' && is2xx(e.step.status))
  const isBlockedByList = (a: string | null): boolean => Boolean(a !== null && ((forbiddenSet.has(a) && !dualAbacExempt(a)) || (allowedSet && !allowedSet.has(a) && !dualAbacExempt(a))))
  const isForbiddenStatic = (a: string | null, r: string | null, rl?: string | null) => isBlockedByList(a) || isPrivilegedActorOrRole(a, r, labelFor(a, rl))
  const isForbiddenOnEntry = (a: string | null, r: string | null, rl: string | null | undefined, e: HostTranscriptEntry, isTermHop: boolean): boolean => {
    if (isBlockedByList(a)) return true
    const prof = parsePersonaPrivilegeProfile(a, r, labelFor(a, rl)); if (prof.alwaysForbidden) return true; if (!prof.isMixedDual) return false
    const allowPrime = Boolean(allowDualCrossTenant && termExForDual && !evaluateExchangeTenantPrivilege(termExForDual, prof, capIdx, { isTermHop: true, isDualTenantAbac: true, allowDualAbacPrimeHop: false }).forbidden)
    return evaluateExchangeTenantPrivilege(e, prof, capIdx, { isTermHop, isDualTenantAbac: allowDualCrossTenant, allowDualAbacPrimeHop: allowPrime }).forbidden
  }
  const isAllowed = (a: string | null, r: string | null, rl?: string | null) => !(a !== null && forbiddenSet.has(a) && !dualAbacExempt(a)) && (allowedSet ? a !== null && (allowedSet.has(a) || dualAbacExempt(a)) : !isPrivilegedActorOrRole(a, r, labelFor(a, rl)))
  for (const ve of verifiedEdges) if (ve.verified && ve.kind === 'async_pivot_binding') { const ev = ve.evidence as { browserTraceId?: string; oobEventId?: string } | undefined; if (ev?.browserTraceId) boundTraces.add(`${ve.toHopId}:${ev.browserTraceId}`); if (ev?.oobEventId) boundOobs.add(`${ve.toHopId}:${ev.oobEventId}`) }
  for (const tr of idx.tracesById.values()) if (tr.actorPersona && isForbiddenStatic(tr.actorPersona, null, null)) for (const c of tr.emittedCapabilities ?? []) forbiddenTraceCaps.add(c)
  const checkEntry = (e: HostTranscriptEntry, label: string, isTermHop: boolean): { err: string } | { err: null; effActor: string | null; effRole: string | null; effRl: string | null; fromDag: boolean } => {
    const a = actorOf(e), r = roleOf(e), rl = e.actorRoleLabel ?? null, isCap = Boolean(a?.startsWith('cap:')), fromDag = Boolean(isCap && dagCaps.has(a!))
    for (const bp of [e.wireCredentialProvenance?.personaHandle, ...(isCap ? [e.step.actor.handle] : [])]) if (bp && !bp.startsWith('cap:') && !ANON_ACTOR_RE.test(bp) && isForbiddenOnEntry(bp, r, rl, e, isTermHop)) return { err: `Attacker-origin violation on ${label} ("${e.exchangeId}"): base persona "${bp}" is forbidden.` }
    if (!isCap) { if (isForbiddenOnEntry(a, r, rl, e, isTermHop)) return { err: `Attacker-origin violation on ${label} ("${e.exchangeId}"): pre-seeded persona "${a ?? r}" is forbidden.` } }
    else {
      if (forbiddenTraceCaps.has(a!)) return { err: `Attacker-origin violation on ${label} ("${e.exchangeId}"): capability "${a}" originated from forbidden browser trace.` }
      const em = capIdx.emitterActorOf(a!)
      if (isPrivilegedActorOrRole(null, r, rl) && (!allowedSet || !(em?.actor && allowedSet.has(em.actor) && em.role === r && em.roleLabel === rl))) return { err: `Attacker-origin violation on ${label} ("${e.exchangeId}"): privileged role "${rl ?? r}" on capability "${a}" is forbidden.` }
      if (!em && !fromDag) return { err: `Attacker-origin violation on ${label} ("${e.exchangeId}"): capability "${a}" has unknown origin.` }
      if (em && isForbiddenOnEntry(em.actor, em.role, em.roleLabel, e, isTermHop)) return { err: `Attacker-origin violation on ${label} ("${e.exchangeId}"): capability "${a}" originated from forbidden persona "${em.actor ?? em.role}".` }
    }
    for (const c of [...(isCap ? [a!] : []), ...(e.consumedCapabilities ?? []), ...(e.cryptoAttestations ?? []).map(x => x.derivedFromCapabilityId)]) {
      if (forbiddenTraceCaps.has(c) && !dagCaps.has(c)) return { err: `Attacker-origin violation on ${label} ("${e.exchangeId}"): capability "${c}" originated from forbidden browser trace.` }
      const em = capIdx.emitterActorOf(c)
      if (em && isForbiddenOnEntry(em.actor, em.role, em.roleLabel, e, isTermHop)) return { err: `Attacker-origin violation on ${label} ("${e.exchangeId}"): capability "${c}" originated from forbidden persona "${em.actor ?? em.role}".` }
      if (!dagCaps.has(c) && em && !em.isLogin && !em.actor && !em.role && !em.roleLabel && em.arm !== 'probe') return { err: `Attacker-origin violation on ${label} ("${e.exchangeId}"): capability "${c}" has unattributed non-probe origin.` }
    }
    const em = isCap ? capIdx.emitterActorOf(a!) : null
    return { err: null, effActor: isCap ? (em?.actor ?? null) : a, effRole: em?.role ?? r, effRl: em?.roleLabel ?? rl, fromDag }
  }
  for (const hopId of dag.topoOrder) {
    const hop = dag.hopsById.get(hopId)!, isRoot = rootSet.has(hopId), isTermHop = hopId === ti.terminalHopId
    const nonControls = hop.exchangeIds.map(id => idx.entriesById.get(id)!).filter(e => e.step.arm !== 'control'), probes = nonControls.filter(e => isExecArm(e, isTermHop))
    if (isRoot && probes.length === 0) return { ok: false, reason: `Root hop "${hopId}" requires an attacker-origin HTTP probe exchange.` }
    for (const e of nonControls) {
      const res = checkEntry(e, `"${hopId}"`, isTermHop); if (res.err !== null) return { ok: false, reason: res.err }
      const usesDag = res.fromDag || (e.consumedCapabilities ?? []).some(c => dagCaps.has(c)) || (e.cryptoAttestations ?? []).some(x => dagCaps.has(x.derivedFromCapabilityId))
      if (!isExecArm(e, isTermHop)) continue
      if (isRoot && allowedSet && !isAllowed(res.effActor, res.effRole, res.effRl)) return { ok: false, reason: `Root hop "${hopId}" ("${e.exchangeId}") must start from an allowed attackerPersona.` }
      if (!isRoot && !(res.effActor !== null && isAllowed(res.effActor, res.effRole, res.effRl)) && !usesDag) return { ok: false, reason: `Hop "${hopId}" ("${e.exchangeId}") lacks attacker persona or DAG-derived capability.` }
      for (const pt of probeTenantsOf(e, capIdx)) probeTenants.add(pt)
    }
    const verifiedAuxCaps: string[] = []
    for (const trId of hop.browserTraceIds) {
      const tr = idx.tracesById.get(trId)!, isBound = !isRoot && boundTraces.has(`${hopId}:${trId}`)
      if (!isBound && tr.actorPersona && isForbiddenStatic(tr.actorPersona, null, null)) return { ok: false, reason: `Attacker-origin violation in "${hopId}" (browser trace "${trId}"): persona "${tr.actorPersona}" is forbidden.` }
      if (isRoot && (tr.emittedCapabilities?.length ?? 0) > 0 && (!tr.actorPersona || !isAllowed(tr.actorPersona, null, null))) return { ok: false, reason: `Attacker-origin violation in root hop "${hopId}" (browser trace "${trId}"): unverified browser trace cannot emit capabilities.` }
      if (isBound || (!isRoot && (!tr.actorPersona || !isForbiddenStatic(tr.actorPersona, null, null))) || (isRoot && Boolean(tr.actorPersona && isAllowed(tr.actorPersona, null, null)))) for (const c of tr.emittedCapabilities ?? []) verifiedAuxCaps.push(c)
    }
    for (const oobId of hop.oobEventIds) { const oob = idx.oobById.get(oobId)!; if ((!isRoot && boundOobs.has(`${hopId}:${oobId}`)) || oobBoundToProbes(oob, probes)) for (const c of oob.emittedCapabilities ?? []) verifiedAuxCaps.push(c) }
    recordHopCapabilities(hop, idx, dagCaps, isTermHop)
    for (const c of verifiedAuxCaps) dagCaps.add(c)
  }
  const { extraProvenanceTargets } = collectCitedReceiptExchanges(ti.oracleInput ? { ...receipt, terminalImpact: { ...ti, oracleInput: normalizeV8OracleInputKeys(ti.oracleInput) } } : receipt, options.v8OracleInput ? normalizeV8OracleInputKeys(options.v8OracleInput) : undefined, idx.entriesById)
  for (const t of extraProvenanceTargets) { const e = idx.entriesById.get(t.exchangeId); if (!e || (!t.forceCheck && e.step.arm === 'control')) continue; const res = checkEntry(e, t.label, false); if (res.err) return { ok: false, reason: res.err } }
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
  const refTs = probeTs.length > 0 ? Math.min(...probeTs) : null, termFam = routeFamily(termHop.target.pathAndQuery ?? ''), preSet = new Set(ti.preChainControlExchangeIds)
  const hasPre = ti.preChainControlExchangeIds.some(id => {
    const e = idx.entriesById.get(id)!
    if (e.step.arm !== 'control' || (e.step.status !== 401 && e.step.status !== 403) || !isFiniteTs(e.timestampMs) || (refTs !== null && e.timestampMs > refTs)) return false
    const cf = termFam && (e.step.route || e.step.pathAndQuery) ? routeFamily(e.step.route ?? e.step.pathAndQuery ?? '') : ''
    return !cf || cf === termFam || Boolean(termHop.entityId && entryMatchesEntity(e, termHop.entityId))
  })
  if (!hasPre) return { ok: false, reason: 'Mode B requires a pre-chain 401/403 control on the terminal target.' }
  const hasRead = ti.postChainReadbackExchangeIds.some(id => {
    const e = preSet.has(id) ? undefined : idx.entriesById.get(id)
    return Boolean(e && is2xx(e.step.status) && isFiniteTs(e.timestampMs) && (refTs === null || e.timestampMs >= refTs) && (stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'post_chain_readback') && (e.step.json !== undefined || (typeof e.step.body === 'string' && e.step.body.trim().length > 0)) && !isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method, e.step.route ?? e.step.pathAndQuery))
  })
  return hasRead ? { ok: true } : { ok: false, reason: 'Mode B requires a post-chain 2xx readback proving persisted impact.' }
}

// --- Public Verifier & Single-Hop Bridge ------------------------------------
type DefaultV8Ctx = { termEndpoint: string; termFam: string; hasOob: boolean; hasBrowser: boolean; hasBody: boolean; isStub: boolean; ownTenantOnly: boolean; hasForeignTenantData: boolean; hasVerifiedTermEdge: boolean; upstreamEntries: readonly HostTranscriptEntry[]; capIdx: CapOriginIndex }
let defaultOracleEvaluator: CompositeOracleEvaluator | null = null
export function registerDefaultCompositeOracleEvaluator(evaluator: CompositeOracleEvaluator | null): void { defaultOracleEvaluator = evaluator }
export class UnregisteredOracleEvaluatorError extends Error {
  constructor(message = 'CompositeProofReceipt verification failed closed: no TerminalOracleRegistry evaluator is registered (unsanitized fallback evaluator removed in R3-16).') { super(message); this.name = 'UnregisteredOracleEvaluatorError' }
}
const resolveOracleEvaluator = (options: CompositeVerifyOptions): CompositeOracleEvaluator => { const evaluator = options.oracleEvaluator ?? defaultOracleEvaluator; if (!evaluator) throw new UnregisteredOracleEvaluatorError(); return evaluator }

function dispatchDefaultV8Oracle(
  receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, factLog: HostFactLog, termEx: HostTranscriptEntry | undefined, options: CompositeVerifyOptions,
  terminalCtrl: HostTranscriptEntry | undefined, postMutRb: HostTranscriptEntry | undefined, ctx: DefaultV8Ctx,
): { ok: true; family: V8OracleFamily; explicit: boolean } | { ok: false; reason: string; rejectedBy: string; missingEvidence: string[] } | null {
  const ti = receipt.terminalImpact, normCls = receipt.terminalVulnClass.trim().toLowerCase(), explicitInput = ti.oracleInput ?? options.v8OracleInput
  const famRes = resolveV8OracleFamilyOrDiagnostic(ti.oracleFamily, normCls, explicitInput, inferV8OracleFamilyFromInput); if (!famRes.ok) return famRes
  const family = famRes.family, inferredFam = famRes.inferred ? famRes.family : null; if (!family) return null
  const policy = { signingKey: options.signingKey, strictHostDerivation: true }, evalOracle = resolveOracleEvaluator(options)
  const rejectFam = (reason: string, missingEvidence: string[], rejectedBy = `v8_oracle_${family}`) => ({ ok: false as const, reason, rejectedBy, missingEvidence })
  if (ti.oracleFamily && !ti.oracleInput && family !== 'dual_tenant_abac') return rejectFam(`v8_oracle_failed (${family}): missing_v8_oracle_input — terminalImpact.oracleFamily requires terminalImpact.oracleInput.`, ['terminalImpact.oracleInput'])
  if (family === 'dual_tenant_abac' && receipt.hops.length < 2) return rejectFam('v8_oracle_failed (dual_tenant_abac): multi_hop_causal_chain_required', ['upstream_causal_hop_or_oracle_input'])
  if (family === 'dual_tenant_abac' && !terminalCtrl) {
    const received = ti.preChainControlExchangeIds.slice(0, 3).map(id => { const c = idx.entriesById.get(id); return c ? `${c.step.method} ${normRouteFam(c.step.route ?? c.step.pathAndQuery, c.entityId) || '/'} (${c.step.status ?? 'null'})` : `${id}(missing)` }).join(', ') || 'none'
    return rejectFam(`v8_oracle_failed (dual_tenant_abac): missing_denied_control_on_terminal_route (expected=${termEx?.step.method ?? 'ANY'} ${ctx.termFam || ctx.termEndpoint || 'unknown'}, received=[${received}])`, ['clean_denied_control_401_403_404'])
  }
  const mapFail = (reason: string) => (reason === 'terminal_impact_unproven_intermediate_stub' || reason === 'bled_access_own_tenant_only') ? rejectFam(TERMINAL_IMPACT_UNPROVEN_HINT, [TERMINAL_IMPACT_UNPROVEN_HINT], 'terminal_impact_unproven') : rejectFam(`v8_oracle_failed (${family}): ${reason}`, [reason])
  const econCtx = { preChainControlExchangeIds: ti.preChainControlExchangeIds, termHopExchangeIds: dag.hopsById.get(ti.terminalHopId)!.exchangeIds, postChainReadbackExchangeIds: ti.postChainReadbackExchangeIds, citedExchangeIds: receipt.hops.flatMap(h => h.exchangeIds), ...(options.personaRoleLabels ? { personaRoleLabels: options.personaRoleLabels } : {}) }
  const freeFormDualFallback = family === 'dual_tenant_abac' && !ti.oracleFamily && !options.v8OracleInput && !inferredFam && Boolean(explicitInput && typeof explicitInput.mode !== 'string')
  if (family === 'dual_tenant_abac' && !postMutRb) {
    if (ctx.isStub || isReadOnlyDirectoryOrMetadataImpact(termEx)) return mapFail('terminal_impact_unproven_intermediate_stub')
    if (ctx.ownTenantOnly) return mapFail('bled_access_own_tenant_only')
  }
  const effInput = (explicitInput && !freeFormDualFallback) ? explicitInput : (family === 'dual_tenant_abac' && !explicitInput ? deriveHostDualTenantRawInput({ entriesById: idx.entriesById, personaRoleLabels: options.personaRoleLabels }, econCtx) : null)
  if (effInput) { const res = evalOracle.evaluate(factLog, { kind: 'v8_family', family, rawInput: effInput, econCtx }, policy); return res.confirmed ? { ok: true, family, explicit: true } : mapFail(res.reason) }
  if (family === 'cross_surface_pivot') {
    if (receipt.hops.length < 2) return rejectFam('v8_oracle_failed (cross_surface_pivot): invalid_hop_count — requires >= 2 hops across distinct surfaces.', ['cross_surface_pivot_requires_2_plus_hops'])
    const rootHop = dag.hopsById.get(dag.roots[0]!)!, rootEx = rootHop.exchangeIds.map(id => idx.entriesById.get(id)!).find(e => isExecArm(e, rootHop.hopId === ti.terminalHopId)) ?? idx.entriesById.get(rootHop.exchangeIds[0]!)
    if (!terminalCtrl || !rootEx || !termEx) return rejectFam(`v8_oracle_failed (${family}): missing_pivot_control_or_terminal_record`, ['pre_chain_control_denied', TERMINAL_IMPACT_UNPROVEN_HINT])
    const hops = dag.topoOrder.map((hopId, i) => {
      const h = dag.hopsById.get(hopId)!, edge = (dag.incomingByHop.get(hopId) ?? [])[0]?.edge
      const outCorr = receipt.causalEdges.find(e => e.fromHopId === hopId && (e.kind === 'async_pivot_binding' || e.kind === 'state_transition_binding')), outArt = receipt.causalEdges.find(e => e.fromHopId === hopId && (e.kind === 'value_binding' || e.kind === 'derived_crypto_binding'))
      const ex = (i === dag.topoOrder.length - 1 ? termEx : h.exchangeIds.map(id => idx.entriesById.get(id)!).find(e => isExecArm(e, hopId === ti.terminalHopId))) ?? idx.entriesById.get(h.exchangeIds[0]!)!
      const corr = (edge?.kind === 'async_pivot_binding' ? edge.correlationId : edge?.kind === 'state_transition_binding' ? edge.entityId : undefined) ?? (outCorr?.kind === 'async_pivot_binding' ? outCorr.correlationId : outCorr?.kind === 'state_transition_binding' ? outCorr.entityId : undefined) ?? ex.correlationIds?.[0] ?? h.entityId
      const emitted = (outArt?.kind === 'value_binding' ? (outArt.capabilityHandle ?? outArt.valueDigest) : outArt?.kind === 'derived_crypto_binding' ? outArt.sourceCapabilityId : undefined) ?? h.producedCapabilities[0]
      return { surface: h.surface, role: i === dag.topoOrder.length - 1 ? 'terminal_impact' : h.surface === 'browser' ? 'browser_dom_trace' : h.surface === 'webhook' ? 'oob_callback' : 'trigger_write', record: ex.exchangeId, ...(edge ? { bindingKind: edge.kind } : {}), ...(emitted ? { emittedArtifactDigest: emitted } : {}), ...(corr ? { correlationToken: corr } : {}), ...(edge?.kind === 'value_binding' ? { consumedArtifactDigest: edge.capabilityHandle ?? edge.valueDigest ?? h.consumedCapabilities[0] } : {}), ...(edge?.kind === 'derived_crypto_binding' ? { derivedFromCapabilityId: edge.sourceCapabilityId } : {}), ...(edge?.kind === 'state_transition_binding' && edge.ablationExchangeIds[0] ? { ablationControlDenied: edge.ablationExchangeIds[0] } : {}) }
    })
    const res = evalOracle.evaluate(factLog, { kind: 'v8_family', family: 'cross_surface_pivot', rawInput: { preChainControlDenied: terminalCtrl.exchangeId, hops, terminalImpact: { kind: postMutRb ? 'privileged_mutation' : 'privileged_read', ...(postMutRb ? { postImpactReadback: postMutRb.exchangeId } : {}) } } }, policy)
    return res.confirmed ? { ok: true, family, explicit: false } : mapFail(res.reason)
  }
  if (ctx.isStub && !postMutRb) return mapFail('terminal_impact_unproven_intermediate_stub')
  if (ctx.ownTenantOnly && !postMutRb && family !== 'temporal_revocation') return mapFail('bled_access_own_tenant_only')
  const ctrlAct = terminalCtrl ? actorOf(terminalCtrl) : null, ctrlLbl = ctrlAct && options.personaRoleLabels?.[ctrlAct] ? `${options.personaRoleLabels[ctrlAct]}; ${terminalCtrl?.actorRoleLabel ?? ''}` : terminalCtrl?.actorRoleLabel
  const ctrlMatchesTerm = Boolean(terminalCtrl && termEx && (sameCredIdentity(terminalCtrl, termEx, ctx.capIdx) || (!actorOf(termEx) && [...(termEx.consumedCapabilities ?? []), ...(termEx.cryptoAttestations ?? []).map(a => a.derivedFromCapabilityId)].some(c => { const ca = normAct(ctx.capIdx.actorOf(c)), sa = sessionActorOf(terminalCtrl, ctx.capIdx); return Boolean(ca && sa && ca === sa) })))), ctrlValid401 = Boolean(terminalCtrl && ctrlAct && ctx.upstreamEntries.some(e => sameCredIdentity(terminalCtrl, e, ctx.capIdx)))
  const ctrlDualOk = !ti.oracleFamily || parsePersonaPrivilegeProfile(ctrlAct, terminalCtrl ? roleOf(terminalCtrl) : null, ctrlLbl).isMixedDual
  const multiHopDualDag = family === 'dual_tenant_abac' && ctrlDualOk && ctrlMatchesTerm && receipt.hops.length >= 2 && ctx.hasVerifiedTermEdge && Boolean(terminalCtrl && ctrlAct && !ANON_ACTOR_RE.test(ctrlAct) && (terminalCtrl.step.status === 403 || terminalCtrl.step.status === 404 || (terminalCtrl.step.status === 401 && ctrlValid401))) && (ctx.hasForeignTenantData || Boolean(postMutRb))
  if (multiHopDualDag) return { ok: true, family, explicit: false }
  const miss = family === 'economic_conservation' ? 'missing_economic_oracle_input' : 'missing_v8_oracle_input'
  return rejectFam(`v8_oracle_failed (${family}): ${miss} — provide terminalImpact.oracleInput.`, [miss, 'terminalImpact.oracleInput'])
}

function verifyTerminalImpactGate(
  receipt: CompositeProofReceipt, dag: DagTopology, idx: IndexedTranscript, factLog: HostFactLog, verifiedEdges: VerifiedEdgeResult[],
  hostTranscript: HostSignedTranscript, attackerTenants: ReadonlySet<string>, explicitEdgeCount: number, suppStart: number, capIdx: CapOriginIndex, options: CompositeVerifyOptions,
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
  const hasBoundOob = contract === 'oob' && (hasOobEdge || termHop.oobEventIds.some(id => oobBoundToProbes(idx.oobById.get(id), termProbes)))
  const hasBoundBrowser = (contract === 'browser' && termHop.browserTraceIds.some(id => (idx.tracesById.get(id)?.sinks?.length ?? 0) > 0)) || (contract === 'oob' && hasBrowserEdge)
  const hasBody = Boolean(termEx && hasEntryBody(termEx)), isStub = Boolean(termEx && isStubEntry(termEx)) || Boolean(ti.proofReceipt?.exchangeIds.some(id => { const e = idx.entriesById.get(id); return Boolean(e && e.step.arm !== 'control' && is2xx(e.step.status) && isStubEntry(e)) }))
  if (ti.terminalExchangeId && (!termEx || termEx.step.arm !== 'probe' || !is2xx(termEx.step.status))) return failUnproven(`terminalExchangeId "${ti.terminalExchangeId}" is not a succeeding probe exchange.`)
  if (termEx && (termEx.evidenceRole === 'host_capability_op' || termEx.evidenceRole === 'host_crypto_op')) return failUnproven()
  const hasPostMutation = Boolean(postMutRb), termHopSet = new Set(termHop.exchangeIds), nonTermExSet = new Set(receipt.hops.filter(h => h.hopId !== termHop.hopId).flatMap(h => h.exchangeIds).filter(id => !termHopSet.has(id)))
  const termRawActor = termEx ? actorOf(termEx) : null, termAuthd = Boolean(termRawActor && !ANON_ACTOR_RE.test(termRawActor))
  const hasVerifiedTermEdge = verifiedEdges.some(e => e.toHopId === termHop.hopId && e.verified && (e.edgeIndex < explicitEdgeCount || e.kind === 'derived_crypto_binding' || (e.kind === 'value_binding' && Boolean((receipt.causalEdges[e.edgeIndex] as { capabilityHandle?: string } | undefined)?.capabilityHandle || e.edgeIndex < suppStart)))), hasExplicitVerifiedTermEdge = verifiedEdges.some(e => e.toHopId === termHop.hopId && e.verified && e.edgeIndex < explicitEdgeCount), hasTermDerivedCrypto = verifiedEdges.some(e => e.toHopId === termHop.hopId && e.kind === 'derived_crypto_binding' && e.verified)
  const upstreamEntries = receipt.hops.filter(h => h.hopId !== termHop.hopId).flatMap(h => h.exchangeIds).map(id => idx.entriesById.get(id)!).filter(e => Boolean(e && isExecArm(e) && is2xx(e.step.status)))
  const { ownTenantOnly, hasForeignTenantData, crossTenantSatisfied } = analyzeCrossTenantTerminalEvidence(termEx, attackerTenants, isStub, hasBody, upstreamEntries, hasPostMutation, receipt.hops.length >= 2 && hasExplicitVerifiedTermEdge)
  const termAblationIds = new Set(verifiedEdges.filter(ve => ve.verified && ve.kind === 'state_transition_binding' && ve.toHopId === termHop.hopId).map(ve => (ve.evidence as { ablationExchangeId?: string } | undefined)?.ablationExchangeId).filter((id): id is string => Boolean(id)))
  const ctrlCandidates = [...ti.preChainControlExchangeIds, ...termHop.exchangeIds, ...receipt.causalEdges.flatMap(ed => ed.kind === 'state_transition_binding' && ed.toHopId === termHop.hopId ? ed.ablationExchangeIds : [])]
  const ctrlCtx = { hasExplicitVerifiedTermEdge, entriesById: idx.entriesById, attackerTenants }
  const terminalCtrl = ctrlCandidates.map(id => idx.entriesById.get(id)).find((c): c is HostTranscriptEntry => {
    const allowedStatus = c && typeof c.step.status === 'number' && (DENIED_CONTROL_STATUSES.has(c.step.status) || (termAblationIds.has(c.exchangeId) && ABLATION_DENIED_STATUSES.has(c.step.status)))
    if (!c || !allowedStatus || (termEx && c.exchangeId === termEx.exchangeId) || nonTermExSet.has(c.exchangeId) || (c.step.arm !== 'control' && c.replayAttempt !== 'ablation_control')) return false
    const cRaw = actorOf(c), isCapCtrl = Boolean(cRaw?.startsWith('cap:'))
    if (isCapCtrl && cRaw !== termRawActor && !isLoginCap(cRaw!, capIdx)) return false
    const anonFor401 = !cRaw || ANON_ACTOR_RE.test(cRaw) || (isCapCtrl && cRaw !== termRawActor)
    const sameTenantForeignPeer = Boolean(receipt.hops.length >= 2 && hasExplicitVerifiedTermEdge && c.step.status === 403 && termEx && hasForeignTenantData && !isPrivilegedActorOrRole(cRaw, roleOf(c), c.actorRoleLabel) && probeTenantOf(c, capIdx) && probeTenantOf(c, capIdx) === probeTenantOf(termEx, capIdx) && cleanExactPath(c.step.pathAndQuery ?? c.step.route ?? '') === cleanExactPath(termEx.step.pathAndQuery ?? termEx.step.route ?? ''))
    if ((c.step.status === 401 && termAuthd && anonFor401) || (termAuthd && (!termEx || (!sameCredIdentity(c, termEx, capIdx) && !sameTenantForeignPeer)))) return false
    const dotNorm = Boolean(termEx && (!c.origin || !termEx.origin || normOrigin(c.origin) === normOrigin(termEx.origin)) && c.step.method.toUpperCase() === termEx.step.method.toUpperCase() && canonicalNonAuthQuery(c.step.pathAndQuery ?? c.step.route ?? '') === canonicalNonAuthQuery(termEx.step.pathAndQuery ?? termEx.step.route ?? '') && matchesNormalizedDotSegmentPath(c.step.pathAndQuery ?? c.step.route, termEx.step.pathAndQuery ?? termEx.step.route))
    return Boolean((termEx && (matchesBoundTerminalControl(c, termEx, ctrlCtx) || dotNorm)) || (postMutRb && matchesBoundTerminalControl(c, postMutRb, ctrlCtx)))
  })
  const hasCleanDeniedCtrl = Boolean(terminalCtrl)
  const v8Default = dispatchDefaultV8Oracle(receipt, dag, idx, factLog, termEx, options, terminalCtrl, postMutRb, { termEndpoint, termFam, hasOob: hasBoundOob, hasBrowser: hasBoundBrowser, hasBody, isStub, ownTenantOnly, hasForeignTenantData, hasVerifiedTermEdge, upstreamEntries, capIdx })
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
    if (!v8Default && !hasPostMutation && (PRIV_ESC_CLASS_RE.test(receipt.terminalVulnClass) || isCrossTenantCls) && isReadOnlyDirectoryOrMetadataImpact(termEx)) return failUnproven('terminal_impact_unproven: privilege_escalation/bfla/cross-tenant cannot confirm on a read-only directory/roster/metadata listing GET without private payload content, a state-mutating terminal action + postChainReadbackExchangeIds, or a verified v8 oracle family.')
    if (!v8Default && isCrossTenantCls && !crossTenantSatisfied) return failUnproven('terminal_impact_unproven: cross-tenant class requires positive non-reflected foreign tenant data (request URL/query tokens stripped) or persisted mutation readback.')
    if (termEx && !hasPostMutation && (!hasBody || isStub || (ownTenantOnly && crossOrReplay))) return failUnproven()
  }
  return okTerm(v8Default?.family)
}

export function verifyCompositeReceipt(rawReceipt: unknown, hostTranscript: HostSignedTranscript, options: CompositeVerifyOptions = {}): CompositeReceiptVerification {
  const parsed = compositeProofReceiptSchema.safeParse(rawReceipt)
  if (!parsed.success) {
    const issues = parsed.error.issues.slice(0, 2).map(i => `${i.path.join('.') || 'receipt'} ${i.message}`).join('; ')
    const rawHops = rawReceipt && typeof rawReceipt === 'object' && !Array.isArray(rawReceipt) && Array.isArray((rawReceipt as Record<string, unknown>).hops) ? (rawReceipt as { hops: unknown[] }).hops : []
    const lastT = (rawHops[rawHops.length - 1] as { target?: { pathAndQuery?: unknown } } | undefined)?.target?.pathAndQuery
    const rawTerm = typeof lastT === 'string' ? normRouteFam(lastT) : ''
    return { confirmed: false, chainId: 'invalid', terminalVulnClass: 'invalid', replayMode: 'fresh_clean_replay', modeBVerified: false, hopCount: 0, verifiedEdges: [], failedStage: 'schema', reason: `Schema validation failed: ${issues}${rawTerm ? ` (terminalRoute=${rawTerm})` : ''}`.slice(0, 400) }
  }
  const factLog = options.factLog ?? HostFactLog.fromTranscript(hostTranscript), { receipt: autoReceipt, inferredEdges, rewiredEdges } = augmentCompositeReceiptWithAutoDag(parsed.data, factLog)
  const { causalReceipt, excludedControlHopIds, explicitEdgeCount } = partitionNonCausalControlHops(autoReceipt, hostTranscript, parsed.data.causalEdges.length), { receipt, extraInferredEdges } = inferSupplementalHostCausalEdges(causalReceipt, hostTranscript, { collectDigests: collectEntryDigests, normRouteFam, sameCredIdentity, probeActorOf, isLoginCap }), totalInferredCount = inferredEdges.length + extraInferredEdges.length
  const fail = (failedStage: CompositeFailureStage, reason: string, verifiedEdges: VerifiedEdgeResult[] = [], terminalVerification?: ReceiptVerification, rejectedBy?: string, missingEvidence?: string[]): CompositeReceiptVerification => ({
    confirmed: false, chainId: receipt.chainId, terminalVulnClass: receipt.terminalVulnClass, replayMode: receipt.replayMode, modeBVerified: false, hopCount: receipt.hops.length, verifiedEdges, failedStage, reason,
    ...(rejectedBy ? { rejectedBy } : {}), ...(missingEvidence?.length ? { missingEvidence } : {}), ...(terminalVerification ? { terminalVerification } : {}),
  })
  const dagRes = validateDagTopology(receipt); if (!dagRes.ok) return fail('dag_topology', dagRes.reason)
  const fullIdxRes = indexAndVerifyCitations(autoReceipt, hostTranscript, options.signingKey); if (!fullIdxRes.ok) return fail('transcript_integrity', fullIdxRes.reason)
  const idxRes = indexAndVerifyCitations(receipt, hostTranscript, options.signingKey); if (!idxRes.ok) return fail('transcript_integrity', idxRes.reason)
  const { dag } = dagRes, { idx } = idxRes, verifiedEdges: VerifiedEdgeResult[] = [], knownCaps = new Set<string>(), capIdx = buildCapOriginIndex(idx.entriesById.values(), ANON_ACTOR_RE)
  for (const hopId of dag.topoOrder) {
    for (const { edgeIndex, edge } of dag.incomingByHop.get(hopId) ?? []) {
      const fromHop = dag.hopsById.get(edge.fromHopId)!, toHop = dag.hopsById.get(edge.toHopId)!
      const base: EdgeBase = { edgeIndex, kind: edge.kind, fromHopId: edge.fromHopId, toHopId: edge.toHopId, fromEx: [...fromHop.exchangeIds, ...fromHop.oobEventIds, ...fromHop.browserTraceIds], toEx: [...toHop.exchangeIds, ...toHop.oobEventIds, ...toHop.browserTraceIds] }
      const res = edge.kind === 'value_binding' ? verifyValueBinding(base, edge, fromHop, toHop, idx) : edge.kind === 'derived_crypto_binding' ? verifyDerivedCryptoBinding(base, edge, fromHop, toHop, idx) : edge.kind === 'state_transition_binding' ? verifyStateTransitionBinding(base, edge, fromHop, toHop, idx, knownCaps, capIdx, receipt.terminalImpact.terminalHopId) : verifyAsyncPivotBinding(base, edge, fromHop, toHop, idx, options.signingKey, toHop.hopId === receipt.terminalImpact.terminalHopId)
      verifiedEdges.push(res); if (!res.verified) return fail('edge_binding', res.reason, verifiedEdges)
    }
    recordHopCapabilities(dag.hopsById.get(hopId)!, idx, knownCaps, hopId === receipt.terminalImpact.terminalHopId)
  }
  const targetRes = verifyHopTargetsAgainstExchanges(receipt, idx.entriesById, idx.tracesById, idx.oobById); if (!targetRes.ok) return fail('transcript_integrity', targetRes.reason, verifiedEdges)
  const provRes = verifyAttackerProvenance(receipt, dag, idx, options, capIdx, verifiedEdges); if (!provRes.ok) return fail('attacker_provenance', provRes.reason, verifiedEdges)
  const replayRes = verifyReplayMode(receipt, dag, idx, options); if (!replayRes.ok) return fail('replay_mode', replayRes.reason, verifiedEdges)
  const termRes = verifyTerminalImpactGate(receipt, dag, idx, factLog, verifiedEdges, hostTranscript, provRes.attackerTenants, explicitEdgeCount, causalReceipt.causalEdges.length, capIdx, options)
  if (!termRes.ok) return fail('terminal_impact', termRes.reason, verifiedEdges, termRes.terminalVerification, termRes.rejectedBy, termRes.missingEvidence)
  const terminalOrigin = deriveSignedTerminalOrigin(receipt, idx.entriesById)
  const termMeta = { ...(termRes.terminalOracleFamily ? { terminalOracleFamily: termRes.terminalOracleFamily } : {}), ...(termRes.terminalEndpoint ? { terminalEndpoint: termRes.terminalEndpoint } : {}), ...(terminalOrigin ? { terminalOrigin } : {}) }
  return { confirmed: true, chainId: receipt.chainId, terminalVulnClass: receipt.terminalVulnClass, replayMode: receipt.replayMode, modeBVerified: receipt.replayMode === 'one_shot_transcript', hopCount: receipt.hops.length, verifiedEdges, reason: `CompositeProofReceipt confirmed (${receipt.hops.length} hop(s), ${verifiedEdges.length} verified causal edge(s), mode=${receipt.replayMode}).`, ...termMeta, ...(termRes.terminalVerification ? { terminalVerification: termRes.terminalVerification } : {}), evidence: { topoOrder: dag.topoOrder, roots: dag.roots, derivedCapabilities: provRes.derivedCapabilities, ...(totalInferredCount ? { autoInferredEdgeCount: totalInferredCount } : {}), ...(rewiredEdges.length ? { rewiredEdgeCount: rewiredEdges.length } : {}), ...(excludedControlHopIds.length ? { excludedControlHopIds } : {}), ...termMeta } }
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
