/**
 * CapabilityLedger — v8 stateful causal attack graph backed by SQLite WAL.
 *
 * Enforces:
 * 1. Zero raw secrets: opaque `cap:hop_<id>:<slot>` handles + SHA-256 digests.
 * 2. Strict `capability_only` quarantine: `opaque_object_ref`, `policy_asymmetry`,
 *    `write_sink_handle`, and intermediate nodes fail closed in `assertPromotable`.
 * 3. Causal DAG integrity: 4 typed bindings, cycle rejection, monotonic timestamps.
 * 4. Attacker-origin lineage: `traceProvenanceToAttacker` rejects privileged shortcuts.
 * 5. Negative-edge 2-strike branch pruning & bounded `<= 2 KB` hop-checkpoint briefs.
 */
import { createHash, randomUUID } from 'node:crypto'
import { mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { redact, scanSecrets } from './redact.ts'

export const CAPABILITY_KINDS = [
  'identity_session', 'scoped_token', 'signing_material', 'signed_artifact_or_url',
  'opaque_object_ref', 'state_handle', 'write_sink_handle', 'internal_reach_handle',
  'parser_or_cache_primitive', 'policy_asymmetry',
] as const
export type CapabilityKind = (typeof CAPABILITY_KINDS)[number]

export const CAPABILITY_SURFACES = [
  'http', 'graphql', 'ws', 'sse', 'browser', 'webhook', 'async_job', 'idp', 'cdn', 'storage',
] as const
export type CapabilitySurface = (typeof CAPABILITY_SURFACES)[number]

export const CAPABILITY_TEMPORAL_STATES = [
  'active', 'pending', 'revoked', 'demoted', 'expired', 'primed_cache',
] as const
export type CapabilityTemporalState = (typeof CAPABILITY_TEMPORAL_STATES)[number]

export const PROMOTION_STATUSES = ['capability_only', 'terminal_eligible'] as const
export type PromotionStatus = (typeof PROMOTION_STATUSES)[number]

export const CAPABILITY_PROVENANCES = [
  'attacker_seed', 'derived_hop', 'floor_observation', 'static_analysis',
  'runtime_discovery', 'oob_callback', 'async_poll', 'browser_trace',
] as const
export type CapabilityProvenance = (typeof CAPABILITY_PROVENANCES)[number]

export const CAUSAL_EDGE_BINDING_KINDS = [
  'value_binding', 'derived_crypto_binding', 'state_transition_binding', 'async_pivot_binding',
] as const
export type CausalEdgeBindingKind = (typeof CAUSAL_EDGE_BINDING_KINDS)[number]

export const NEGATIVE_EDGE_REASONS = [
  'invariant_enforced_hardened', 'control_blocked_cleanly', 'decoy_guard_verified',
] as const
export type NegativeEdgeReason = (typeof NEGATIVE_EDGE_REASONS)[number]

export const ALWAYS_QUARANTINED_KINDS: ReadonlySet<CapabilityKind> = new Set([
  'opaque_object_ref', 'policy_asymmetry', 'write_sink_handle',
])
const AUTHORITY_GRANTING_KINDS: ReadonlySet<CapabilityKind> = new Set([
  'identity_session', 'scoped_token', 'signing_material', 'signed_artifact_or_url',
])

const KIND_SET: ReadonlySet<string> = new Set(CAPABILITY_KINDS)
const SURFACE_SET: ReadonlySet<string> = new Set(CAPABILITY_SURFACES)
const TEMPORAL_SET: ReadonlySet<string> = new Set(CAPABILITY_TEMPORAL_STATES)
const PROMOTION_SET: ReadonlySet<string> = new Set(PROMOTION_STATUSES)
const PROVENANCE_SET: ReadonlySet<string> = new Set(CAPABILITY_PROVENANCES)
const BINDING_SET: ReadonlySet<string> = new Set(CAUSAL_EDGE_BINDING_KINDS)
const NEGATIVE_REASON_SET: ReadonlySet<string> = new Set(NEGATIVE_EDGE_REASONS)

export const DERIVED_CAPABILITY_HANDLE_RE =
  /^cap:hop_[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const DERIVED_HANDLE_GLOBAL_RE =
  /cap:hop_[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._-]{0,63}/g
const SHA256_HEX_RE = /^[a-f0-9]{64}$/i

export const DEFAULT_PRUNE_STRIKE_THRESHOLD = 2
export const DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES = 2048
const MIN_CHECKPOINT_BRIEF_MAX_BYTES = 512

export type CapabilityLedgerErrorCode =
  | 'INVALID_ARGUMENT' | 'INVALID_HANDLE' | 'INVALID_DIGEST' | 'RAW_SECRET_REJECTED'
  | 'QUARANTINED_KIND' | 'UNVERIFIED_TERMINAL_PROMOTION' | 'CAPABILITY_QUARANTINED'
  | 'DUPLICATE_CAPABILITY' | 'DUPLICATE_EDGE' | 'CAPABILITY_NOT_FOUND'
  | 'NON_MONOTONIC_TIMESTAMP' | 'CYCLE_DETECTED'

export class CapabilityLedgerError extends Error {
  readonly code: CapabilityLedgerErrorCode
  constructor(code: CapabilityLedgerErrorCode, message: string) {
    super(message)
    this.name = 'CapabilityLedgerError'
    this.code = code
  }
}

export interface CapabilityNode {
  capId: string; runId: string; kind: CapabilityKind; promotionStatus: PromotionStatus
  terminalImpactOracleVerified: boolean; provenance: CapabilityProvenance
  tenantScope: string; actorPersona: string; serviceOrigin: string
  surface: CapabilitySurface; temporalState: CapabilityTemporalState
  validityTtlMs: number | null; parentHopReceiptIds: string[]; artifactDigest: string
  artifactSummary: string; metadata: Record<string, unknown>; createdAtMs: number; updatedAtMs: number
}

export interface AddCapabilityInput {
  capId: string; kind: CapabilityKind; promotionStatus?: PromotionStatus
  terminalImpactOracleVerified?: boolean; provenance: CapabilityProvenance
  tenantScope: string; actorPersona: string; serviceOrigin: string
  surface: CapabilitySurface; temporalState?: CapabilityTemporalState
  validityTtlMs?: number | null; parentHopReceiptIds?: readonly string[]
  artifactDigest: string; artifactSummary?: string
  metadata?: Record<string, unknown>; createdAtMs?: number
}

export interface CausalActorContext {
  persona: string; tenantScope?: string; roleLabel?: string; serviceOrigin?: string
}

export interface CausalEdge {
  edgeId: string; runId: string; preconditionCapIds: string[]; actorContext: CausalActorContext
  hopReceiptId: string; edgeBindingKind: CausalEdgeBindingKind; postconditionCapId: string | null
  terminalImpact: string | null; sourceTimestampMs: number; targetTimestampMs: number
  bindingDigest: string | null; metadata: Record<string, unknown>; createdAtMs: number
}

export interface AddCausalEdgeInput {
  edgeId?: string; preconditionCapIds: readonly string[]; actorContext: CausalActorContext
  hopReceiptId: string; edgeBindingKind: CausalEdgeBindingKind
  postconditionCapId?: string | null; terminalImpact?: string | null
  sourceTimestampMs: number; targetTimestampMs: number
  bindingDigest?: string | null; metadata?: Record<string, unknown>; createdAtMs?: number
}

export interface NegativeEdge {
  runId: string; preconditionKey: string; preconditionCapIds: string[]
  targetSurfaceKey: string; hypothesisClass: string; falsifiedByExchangeIds: string[]
  reason: NegativeEdgeReason; attemptCount: number; pruned: boolean
  notes: string; createdAtMs: number; updatedAtMs: number
}

export interface RecordNegativeEdgeInput {
  preconditionCapIds: readonly string[]; targetSurfaceKey: string; hypothesisClass: string
  falsifiedByExchangeIds: readonly string[]; reason: NegativeEdgeReason
  forcePrune?: boolean; notes?: string; timestampMs?: number
}

export interface AttackerProvenanceViolation {
  code: 'capability_not_found' | 'preseeded_privileged_root' | 'privileged_actor_shortcut'
  capId?: string; edgeId?: string; persona?: string; detail: string
}

export interface AttackerProvenanceResult {
  valid: boolean; capId: string; hopDepth: number; rootCapIds: string[]
  attackerRootPersonas: string[]; pathCapIds: string[]; pathEdgeIds: string[]
  violations: AttackerProvenanceViolation[]
}

export interface CompactCheckpointHop {
  hop: number; receiptId: string; capId: string; kind: CapabilityKind; surface: CapabilitySurface
  service: string; tenant: string; actor: string; role?: string; at?: string; binding?: CausalEdgeBindingKind
}
export interface HopCheckpointNextGoal {
  targetSurfaceKey: string; surface: CapabilitySurface; service: string; endpoint: string; method?: string
  hypothesisClass: string; expectedBinding?: CausalEdgeBindingKind; targetTenant?: string; targetRole?: string; goal: string
}
export interface HopWorkflowNotebook {
  discoveredRoutes?: string[]
  verifiedHypotheses?: string[]
  triedRecipes?: string[]
  openHypotheses?: string[]
}
export interface HopCheckpointBrief {
  schema: 'v8.hop_checkpoint.v1'; branchKey: string; depth: number; targetHop: number
  mode: 'pivot' | 'fuse' | 'discover' | 'sweep'; evi: number
  verifiedHops: CompactCheckpointHop[]; omittedEarlierHops?: number
  capabilityHandles: string[]; fuseWithBranchKey?: string
  nextGoal: HopCheckpointNextGoal
  prunedBranches?: Array<{ surface: string; hypothesis: string; reason: NegativeEdgeReason }>
  workflowNotebook?: HopWorkflowNotebook
  truncated?: boolean; doNotRediscover: true
}
export interface HopCheckpointBriefOptions {
  branchKey?: string; evi?: number; mode?: 'pivot' | 'fuse' | 'discover' | 'sweep'
  fuseWithBranchKey?: string; nextGoal?: Partial<HopCheckpointNextGoal>
  workflowNotebook?: HopWorkflowNotebook
}

const OPAQUE_BRIEF_HANDLE_RE = /^(?:cap|state|ref|hop|handle|secret|artifact|id):[A-Za-z0-9:._/-]{1,96}$/
const RAW_BRIEF_SECRET_RE = /(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|Bearer\s+\S+|\b(?:sk|pk|pat|ghp|tok|api)[_-][A-Za-z0-9_-]{12,}\b|[A-Fa-f0-9]{32,}|[A-Za-z0-9+/]{36,}={0,2})/g

export function truncateBriefText(text: string, maxLen: number): string {
  const t = text.trim()
  return t.length <= maxLen ? t : maxLen <= 1 ? t.slice(0, maxLen) : `${t.slice(0, maxLen - 1)}…`
}
function truncateUtf8Bytes(text: string, maxBytes: number): string {
  let out = text.trim()
  while (out.length > 0 && Buffer.byteLength(out, 'utf8') > maxBytes) out = [...out].slice(0, -1).join('')
  return out
}
export function sanitizeCheckpointHandleRef(raw: string, fallback: string): string {
  const t = raw.trim()
  if (!t) return fallback
  if (OPAQUE_BRIEF_HANDLE_RE.test(t)) return t
  if (RAW_BRIEF_SECRET_RE.test(t)) { RAW_BRIEF_SECRET_RE.lastIndex = 0; return fallback }
  return t.slice(0, 80)
}
export const sanitizeCheckpointText = (text: string, maxLen: number): string => truncateBriefText(text.replace(RAW_BRIEF_SECRET_RE, '[redacted-handle]'), maxLen)

function scrubNotebookItem(raw: string, maxLen: number): string {
  const handles: string[] = []
  let s = raw.replace(DERIVED_HANDLE_GLOBAL_RE, h => { handles.push(h); return `__CAP_H_${handles.length - 1}__` })
  s = redact(s).replace(RAW_BRIEF_SECRET_RE, '[redacted-handle]')
  for (const { pattern } of EXTRA_SECRET_PATTERNS) {
    const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`
    s = s.replace(new RegExp(pattern.source, flags), '[redacted-handle]')
  }
  if (scanSecrets(s, { jsonPaths: false, maxMatches: 1 }).length > 0) s = '[redacted-handle]'
  s = s.replace(/__CAP_H_(\d+)__/g, (_, i) => handles[Number(i)] ?? '[cap_handle]')
  return truncateBriefText(s, maxLen)
}

export function sanitizeWorkflowNotebook(nb?: HopWorkflowNotebook): HopWorkflowNotebook | undefined {
  if (!nb) return undefined
  const clean = (items: readonly string[] | undefined, maxItems: number, maxLen: number): string[] =>
    [...new Set((items ?? []).map(v => scrubNotebookItem(String(v ?? ''), maxLen)).filter(Boolean))].slice(0, maxItems)
  const discoveredRoutes = clean(nb.discoveredRoutes, 10, 88)
  const verifiedHypotheses = clean(nb.verifiedHypotheses, 6, 110)
  const triedRecipes = clean(nb.triedRecipes, 10, 110)
  const openHypotheses = clean(nb.openHypotheses, 6, 110)
  if (!discoveredRoutes.length && !verifiedHypotheses.length && !triedRecipes.length && !openHypotheses.length) return undefined
  return {
    ...(discoveredRoutes.length ? { discoveredRoutes } : {}),
    ...(verifiedHypotheses.length ? { verifiedHypotheses } : {}),
    ...(triedRecipes.length ? { triedRecipes } : {}),
    ...(openHypotheses.length ? { openHypotheses } : {}),
  }
}

/** Strictly bound a canonical `v8.hop_checkpoint.v1` brief to `<= maxBytes` UTF-8 (default 2 KB). */
export function finalizeHopCheckpointBrief(rawBrief: HopCheckpointBrief, maxBytes = DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES): { brief: HopCheckpointBrief; checkpointJson: string; checkpointBytes: number } {
  const cap = Math.max(256, Math.min(DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES, Math.floor(maxBytes)))
  const workflowNotebook = sanitizeWorkflowNotebook(rawBrief.workflowNotebook)
  const brief: HopCheckpointBrief = {
    ...rawBrief, schema: 'v8.hop_checkpoint.v1', verifiedHops: rawBrief.verifiedHops.map(h => ({ ...h })),
    capabilityHandles: [...rawBrief.capabilityHandles], nextGoal: { ...rawBrief.nextGoal },
    ...(rawBrief.prunedBranches ? { prunedBranches: rawBrief.prunedBranches.map(p => ({ ...p })) } : {}),
    ...(workflowNotebook ? { workflowNotebook } : {}),
    doNotRediscover: true,
  }
  if (!workflowNotebook) delete brief.workflowNotebook
  const measure = () => { const json = JSON.stringify(brief); return { json, bytes: Buffer.byteLength(json, 'utf8') } }
  let m = measure()
  if (m.bytes <= cap) return { brief, checkpointJson: m.json, checkpointBytes: m.bytes }
  brief.truncated = true
  while (m.bytes > cap && brief.prunedBranches?.length) { brief.prunedBranches.pop(); if (!brief.prunedBranches.length) delete brief.prunedBranches; m = measure() }
  if (brief.workflowNotebook) {
    const nbKeys: ReadonlyArray<keyof HopWorkflowNotebook> = ['triedRecipes', 'discoveredRoutes', 'openHypotheses', 'verifiedHypotheses']
    for (const k of nbKeys) {
      while (m.bytes > cap && brief.workflowNotebook?.[k]?.length) {
        brief.workflowNotebook[k]!.pop()
        if (!brief.workflowNotebook[k]!.length) delete brief.workflowNotebook[k]
        if (brief.workflowNotebook && Object.keys(brief.workflowNotebook).length === 0) delete brief.workflowNotebook
        m = measure()
      }
    }
  }
  while (m.bytes > cap && brief.verifiedHops.length > 0) { brief.verifiedHops.shift(); brief.omittedEarlierHops = (brief.omittedEarlierHops ?? 0) + 1; m = measure() }
  while (m.bytes > cap && brief.capabilityHandles.length > 1) { brief.capabilityHandles.shift(); m = measure() }
  if (m.bytes > cap) {
    brief.branchKey = truncateUtf8Bytes(brief.branchKey, 24)
    brief.capabilityHandles = brief.capabilityHandles.slice(-1).map(h => truncateUtf8Bytes(h, 32))
    brief.nextGoal = {
      targetSurfaceKey: truncateUtf8Bytes(brief.nextGoal.targetSurfaceKey, 32), surface: brief.nextGoal.surface,
      service: truncateUtf8Bytes(brief.nextGoal.service, 24), endpoint: truncateUtf8Bytes(brief.nextGoal.endpoint, 24),
      hypothesisClass: truncateUtf8Bytes(brief.nextGoal.hypothesisClass, 24), goal: truncateUtf8Bytes(brief.nextGoal.goal, 24),
    }
    delete brief.fuseWithBranchKey
    m = measure()
  }
  if (m.bytes > cap) { brief.nextGoal.goal = truncateUtf8Bytes(brief.nextGoal.goal, 12); brief.nextGoal.targetSurfaceKey = truncateUtf8Bytes(brief.nextGoal.targetSurfaceKey, 16); m = measure() }
  return { brief, checkpointJson: m.json, checkpointBytes: m.bytes }
}

export interface CapabilityLedgerStats {
  totalNodes: number; quarantinedNodes: number; terminalEligibleNodes: number
  positiveEdges: number; negativeEdges: number; prunedBranches: number
}

export interface CapabilityLedgerOptions {
  runId?: string
  pruneStrikeThreshold?: number
}

function fail(code: CapabilityLedgerErrorCode, message: string): never {
  throw new CapabilityLedgerError(code, message)
}

export const isDerivedCapabilityHandle = (value: string): boolean => DERIVED_CAPABILITY_HANDLE_RE.test(value)

export function formatDerivedCapabilityHandle(hopId: string, slot: string): string {
  const handle = `cap:hop_${hopId.trim()}:${slot.trim()}`
  if (!DERIVED_CAPABILITY_HANDLE_RE.test(handle)) fail('INVALID_HANDLE', `Invalid DerivedCapabilityHandle (hopId='${hopId}', slot='${slot}').`)
  return handle
}

export const computeArtifactDigest = (input: string | Uint8Array): string => createHash('sha256').update(input).digest('hex')

export const canonicalPreconditionKey = (capIds: readonly string[]): string =>
  JSON.stringify([...new Set(capIds.map(id => id.trim()).filter(Boolean))].sort())

const EXTRA_SECRET_PATTERNS: ReadonlyArray<{ kind: string; pattern: RegExp }> = [
  { kind: 'basic_auth', pattern: /\bBasic\s+[A-Za-z0-9+/=]{8,}/i },
  { kind: 'private_key', pattern: /-----BEGIN\s+[A-Z0-9 ]*(?:PRIVATE|RSA|EC|OPENSSH|PGP|SECRET)\s+KEY-----/i },
  { kind: 'api_key', pattern: /\b(?:AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b/ },
  { kind: 'cookie_pair', pattern: /\b(?:session(?:id|_id|_token)?|sid|connect\.sid|jsessionid|auth_token|csrf_?token)\s*=\s*[A-Za-z0-9._~%+/=-]{6,}/i },
  { kind: 'cookie_attributes', pattern: /\b[A-Za-z0-9_.-]{2,32}=[^;\s]{6,}\s*;\s*(?:HttpOnly|Secure|SameSite|Path=)/i },
  { kind: 'credential_header', pattern: /\b(?:x-api-key|x-auth-token|x-session-token)\s*:\s*\S{4,}/i },
  { kind: 'key_value', pattern: /\b(?:signing[_-]?(?:key|salt)|hmac[_-]?(?:key|secret)|access[_-]?token|refresh[_-]?token|id[_-]?token|private[_-]?key|passwd)\s*[:=]\s*(?:"[^"]{4,}"|'[^']{4,}'|[^\s&,;]{4,})/i },
]

const SENSITIVE_KEY_RE =
  /^(?:raw[_-].*|password|passwd|secret|signing[_-]?(?:key|salt)|hmac[_-]?(?:key|secret)|private[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|bearer|jwt|cookie|set[_-]?cookie|authorization|auth[_-]?header|session[_-]?(?:id|token|cookie|value)|client[_-]?secret|token|credential)$/i
const HANDLE_KEY_RE = /(?:^|[_-])handle$|Handle$/

function assertNoRawSecretsInString(text: string, fieldPath: string): void {
  if (!text) return
  const masked = text.replace(DERIVED_HANDLE_GLOBAL_RE, '[cap_handle]')
  const redactHits = scanSecrets(masked, { jsonPaths: false, maxMatches: 1 })
  if (redactHits.length > 0) fail('RAW_SECRET_REJECTED', `Raw secret (${redactHits[0]!.kind}) rejected in ${fieldPath}; use cap:hop_<id>:<slot> + SHA-256 digest.`)
  for (const { kind, pattern } of EXTRA_SECRET_PATTERNS) {
    if (pattern.test(masked)) fail('RAW_SECRET_REJECTED', `Raw secret (${kind}) rejected in ${fieldPath}; use cap:hop_<id>:<slot> + SHA-256 digest.`)
  }
}

function assertNoRawSecretsInMetadata(value: unknown, fieldPath: string, depth = 0): void {
  if (depth > 8) fail('INVALID_ARGUMENT', `Metadata depth limit exceeded at ${fieldPath}.`)
  if (value === null || value === undefined || typeof value === 'number' || typeof value === 'boolean') return
  if (typeof value === 'string') { assertNoRawSecretsInString(value, fieldPath); return }
  if (Array.isArray(value)) { value.forEach((v, i) => assertNoRawSecretsInMetadata(v, `${fieldPath}[${i}]`, depth + 1)); return }
  if (typeof value !== 'object') fail('INVALID_ARGUMENT', `Unsupported metadata value at ${fieldPath}.`)
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    const childPath = `${fieldPath}.${key}`
    if (HANDLE_KEY_RE.test(key) && typeof entry === 'string' && entry.length > 0) {
      if (!DERIVED_CAPABILITY_HANDLE_RE.test(entry)) fail('RAW_SECRET_REJECTED', `Handle field ${childPath} requires cap:hop_<id>:<slot>.`)
      continue
    }
    if (SENSITIVE_KEY_RE.test(key)) {
      if (typeof entry === 'string' && DERIVED_CAPABILITY_HANDLE_RE.test(entry)) continue
      if (entry !== null && entry !== undefined && entry !== '') fail('RAW_SECRET_REJECTED', `Raw value rejected under sensitive key ${childPath}; use cap:hop_<id>:<slot>.`)
      continue
    }
    assertNoRawSecretsInMetadata(entry, childPath, depth + 1)
  }
}

const reqStr = (value: string, field: string): string =>
  typeof value === 'string' && value.trim() ? value.trim() : fail('INVALID_ARGUMENT', `${field} must be a non-empty string.`)
const reqSha256 = (digest: string, field: string): string =>
  typeof digest === 'string' && SHA256_HEX_RE.test(digest.trim()) ? digest.trim().toLowerCase() : fail('INVALID_DIGEST', `${field} must be a 64-character hex SHA-256 digest.`)
const reqEnum = <T extends string>(value: string, allowed: ReadonlySet<string>, field: string): T =>
  allowed.has(value) ? (value as T) : fail('INVALID_ARGUMENT', `Invalid ${field}: '${value}'.`)
const reqTimestamp = (value: number, field: string): number =>
  Number.isInteger(value) && value >= 0 ? value : fail('INVALID_ARGUMENT', `${field} must be a non-negative integer.`)

function dedupeStrings(values: readonly string[] | undefined, field: string): string[] {
  if (!values) return []
  const out: string[] = []
  const seen = new Set<string>()
  for (const v of values) {
    const s = reqStr(v, field)
    if (!seen.has(s)) { seen.add(s); out.push(s) }
  }
  return out
}

/** Idempotently initializes the v8 CapabilityLedger SQLite tables and indexes. */
export function initCapabilityLedgerSchema(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS capability_nodes (
      run_id TEXT NOT NULL DEFAULT 'default', cap_id TEXT NOT NULL, kind TEXT NOT NULL,
      promotion_status TEXT NOT NULL DEFAULT 'capability_only',
      terminal_impact_oracle_verified INTEGER NOT NULL DEFAULT 0,
      provenance TEXT NOT NULL, tenant_scope TEXT NOT NULL, actor_persona TEXT NOT NULL,
      service_origin TEXT NOT NULL, surface TEXT NOT NULL,
      temporal_state TEXT NOT NULL DEFAULT 'active', validity_ttl_ms INTEGER,
      parent_hop_receipt_ids_json TEXT NOT NULL DEFAULT '[]', artifact_digest TEXT NOT NULL,
      artifact_summary TEXT NOT NULL DEFAULT '', metadata_json TEXT NOT NULL DEFAULT '{}',
      created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (run_id, cap_id),
      CHECK (promotion_status IN ('capability_only', 'terminal_eligible')),
      CHECK (kind NOT IN ('opaque_object_ref', 'policy_asymmetry', 'write_sink_handle') OR promotion_status = 'capability_only'),
      CHECK (promotion_status = 'capability_only' OR terminal_impact_oracle_verified = 1)
    );
    CREATE INDEX IF NOT EXISTS capability_nodes_run_kind ON capability_nodes (run_id, kind, temporal_state);
    CREATE INDEX IF NOT EXISTS capability_nodes_run_tenant_actor ON capability_nodes (run_id, tenant_scope, actor_persona);

    CREATE TABLE IF NOT EXISTS capability_causal_edges (
      run_id TEXT NOT NULL DEFAULT 'default', edge_id TEXT NOT NULL,
      precondition_cap_ids_json TEXT NOT NULL, actor_context_json TEXT NOT NULL,
      hop_receipt_id TEXT NOT NULL, edge_binding_kind TEXT NOT NULL,
      postcondition_cap_id TEXT, terminal_impact TEXT,
      source_timestamp_ms INTEGER NOT NULL, target_timestamp_ms INTEGER NOT NULL,
      binding_digest TEXT, metadata_json TEXT NOT NULL DEFAULT '{}', created_at_ms INTEGER NOT NULL,
      PRIMARY KEY (run_id, edge_id),
      CHECK (source_timestamp_ms <= target_timestamp_ms),
      CHECK (postcondition_cap_id IS NOT NULL OR terminal_impact IS NOT NULL),
      CHECK (edge_binding_kind IN ('value_binding', 'derived_crypto_binding', 'state_transition_binding', 'async_pivot_binding')),
      FOREIGN KEY (run_id, postcondition_cap_id) REFERENCES capability_nodes(run_id, cap_id)
    );
    CREATE INDEX IF NOT EXISTS capability_causal_edges_post ON capability_causal_edges (run_id, postcondition_cap_id);
    CREATE INDEX IF NOT EXISTS capability_causal_edges_hop ON capability_causal_edges (run_id, hop_receipt_id);

    CREATE TABLE IF NOT EXISTS capability_negative_edges (
      run_id TEXT NOT NULL DEFAULT 'default', precondition_key TEXT NOT NULL,
      precondition_cap_ids_json TEXT NOT NULL, target_surface_key TEXT NOT NULL,
      hypothesis_class TEXT NOT NULL, falsified_by_exchange_ids_json TEXT NOT NULL,
      reason TEXT NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 1,
      pruned INTEGER NOT NULL DEFAULT 0, notes TEXT NOT NULL DEFAULT '',
      created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (run_id, precondition_key, target_surface_key, hypothesis_class),
      CHECK (reason IN ('invariant_enforced_hardened', 'control_blocked_cleanly', 'decoy_guard_verified')),
      CHECK (attempt_count >= 1), CHECK (pruned IN (0, 1))
    );
    CREATE INDEX IF NOT EXISTS capability_negative_edges_pruned ON capability_negative_edges (run_id, pruned, target_surface_key);
  `)
}

type DbRow = Record<string, unknown>

const rowToNode = (r: DbRow): CapabilityNode => ({
  capId: r.cap_id as string, runId: r.run_id as string, kind: r.kind as CapabilityKind,
  promotionStatus: r.promotion_status as PromotionStatus,
  terminalImpactOracleVerified: r.terminal_impact_oracle_verified === 1,
  provenance: r.provenance as CapabilityProvenance, tenantScope: r.tenant_scope as string,
  actorPersona: r.actor_persona as string, serviceOrigin: r.service_origin as string,
  surface: r.surface as CapabilitySurface, temporalState: r.temporal_state as CapabilityTemporalState,
  validityTtlMs: (r.validity_ttl_ms as number | null) ?? null,
  parentHopReceiptIds: JSON.parse(r.parent_hop_receipt_ids_json as string) as string[],
  artifactDigest: r.artifact_digest as string, artifactSummary: r.artifact_summary as string,
  metadata: JSON.parse(r.metadata_json as string) as Record<string, unknown>,
  createdAtMs: r.created_at_ms as number, updatedAtMs: r.updated_at_ms as number,
})

const rowToEdge = (r: DbRow): CausalEdge => ({
  edgeId: r.edge_id as string, runId: r.run_id as string,
  preconditionCapIds: JSON.parse(r.precondition_cap_ids_json as string) as string[],
  actorContext: JSON.parse(r.actor_context_json as string) as CausalActorContext,
  hopReceiptId: r.hop_receipt_id as string, edgeBindingKind: r.edge_binding_kind as CausalEdgeBindingKind,
  postconditionCapId: (r.postcondition_cap_id as string | null) ?? null,
  terminalImpact: (r.terminal_impact as string | null) ?? null,
  sourceTimestampMs: r.source_timestamp_ms as number, targetTimestampMs: r.target_timestamp_ms as number,
  bindingDigest: (r.binding_digest as string | null) ?? null,
  metadata: JSON.parse(r.metadata_json as string) as Record<string, unknown>,
  createdAtMs: r.created_at_ms as number,
})

const rowToNegativeEdge = (r: DbRow): NegativeEdge => ({
  runId: r.run_id as string, preconditionKey: r.precondition_key as string,
  preconditionCapIds: JSON.parse(r.precondition_cap_ids_json as string) as string[],
  targetSurfaceKey: r.target_surface_key as string, hypothesisClass: r.hypothesis_class as string,
  falsifiedByExchangeIds: JSON.parse(r.falsified_by_exchange_ids_json as string) as string[],
  reason: r.reason as NegativeEdgeReason, attemptCount: r.attempt_count as number,
  pruned: r.pruned === 1, notes: r.notes as string,
  createdAtMs: r.created_at_ms as number, updatedAtMs: r.updated_at_ms as number,
})

interface ProofMemo {
  valid: boolean; hopDepth: number; rootCapIds: Set<string>; attackerRootPersonas: Set<string>
  derivedPersonas: Set<string>; pathCapIds: string[]; pathEdgeIds: string[]
  violations: AttackerProvenanceViolation[]
}

const failedProof = (violations: AttackerProvenanceViolation[], capId?: string): ProofMemo => ({
  valid: false, hopDepth: 0, rootCapIds: new Set(capId ? [capId] : []),
  attackerRootPersonas: new Set(), derivedPersonas: new Set(),
  pathCapIds: capId ? [capId] : [], pathEdgeIds: [], violations,
})

export class CapabilityLedger {
  readonly db: DatabaseSync
  readonly runId: string
  readonly pruneStrikeThreshold: number
  private readonly ownsClient: boolean

  constructor(dbOrPath: DatabaseSync | string, options: CapabilityLedgerOptions = {}) {
    this.runId = reqStr(options.runId ?? 'default', 'runId')
    const threshold = options.pruneStrikeThreshold ?? DEFAULT_PRUNE_STRIKE_THRESHOLD
    if (!Number.isInteger(threshold) || threshold < 1) fail('INVALID_ARGUMENT', 'pruneStrikeThreshold must be an integer >= 1.')
    this.pruneStrikeThreshold = threshold

    if (typeof dbOrPath === 'string') {
      const target = reqStr(dbOrPath, 'dbPath')
      if (target !== ':memory:') mkdirSync(dirname(resolve(target)), { recursive: true, mode: 0o700 })
      this.db = new DatabaseSync(target, { timeout: 5000 })
      this.ownsClient = true
      if (target !== ':memory:') this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;')
    } else {
      this.db = dbOrPath
      this.ownsClient = false
    }
    this.db.exec('PRAGMA foreign_keys = ON;')
    initCapabilityLedgerSchema(this.db)
  }

  close(): void { if (this.ownsClient) this.db.close() }

  addCapability(input: AddCapabilityInput): CapabilityNode {
    const capId = reqStr(input.capId, 'capId')
    if (!DERIVED_CAPABILITY_HANDLE_RE.test(capId)) fail('INVALID_HANDLE', `Capability ID '${capId}' must match cap:hop_<id>:<slot>.`)
    const kind = reqEnum<CapabilityKind>(input.kind, KIND_SET, 'kind')
    const provenance = reqEnum<CapabilityProvenance>(input.provenance, PROVENANCE_SET, 'provenance')
    const surface = reqEnum<CapabilitySurface>(input.surface, SURFACE_SET, 'surface')
    const temporalState = reqEnum<CapabilityTemporalState>(input.temporalState ?? 'active', TEMPORAL_SET, 'temporalState')
    const requestedStatus = reqEnum<PromotionStatus>(input.promotionStatus ?? 'capability_only', PROMOTION_SET, 'promotionStatus')

    let promotionStatus: PromotionStatus = 'capability_only'
    let oracleVerified = false
    if (ALWAYS_QUARANTINED_KINDS.has(kind)) {
      if (requestedStatus === 'terminal_eligible') fail('QUARANTINED_KIND', `Kind '${kind}' is permanently quarantined as 'capability_only'.`)
    } else if (requestedStatus === 'terminal_eligible') {
      if (input.terminalImpactOracleVerified !== true) fail('UNVERIFIED_TERMINAL_PROMOTION', `Capability '${capId}' requires terminalImpactOracleVerified=true.`)
      promotionStatus = 'terminal_eligible'
      oracleVerified = true
    } else {
      oracleVerified = input.terminalImpactOracleVerified === true
    }

    const tenantScope = reqStr(input.tenantScope, 'tenantScope')
    const actorPersona = reqStr(input.actorPersona, 'actorPersona')
    const serviceOrigin = reqStr(input.serviceOrigin, 'serviceOrigin')
    const artifactDigest = reqSha256(input.artifactDigest, 'artifactDigest')
    const artifactSummary = (input.artifactSummary ?? '').trim()
    const metadata = input.metadata ?? {}
    const parentHopReceiptIds = dedupeStrings(input.parentHopReceiptIds, 'parentHopReceiptIds')
    const validityTtlMs = input.validityTtlMs ?? null
    if (validityTtlMs !== null && (!Number.isInteger(validityTtlMs) || validityTtlMs < 0)) fail('INVALID_ARGUMENT', 'validityTtlMs must be a non-negative integer or null.')

    assertNoRawSecretsInString(tenantScope, 'tenantScope')
    assertNoRawSecretsInString(actorPersona, 'actorPersona')
    assertNoRawSecretsInString(serviceOrigin, 'serviceOrigin')
    assertNoRawSecretsInString(artifactSummary, 'artifactSummary')
    assertNoRawSecretsInMetadata(metadata, 'metadata')

    const createdAtMs = reqTimestamp(input.createdAtMs ?? Date.now(), 'createdAtMs')
    if (this.getCapability(capId)) fail('DUPLICATE_CAPABILITY', `Capability '${capId}' already exists.`)

    this.db.prepare(`
      INSERT INTO capability_nodes (
        run_id, cap_id, kind, promotion_status, terminal_impact_oracle_verified,
        provenance, tenant_scope, actor_persona, service_origin, surface,
        temporal_state, validity_ttl_ms, parent_hop_receipt_ids_json,
        artifact_digest, artifact_summary, metadata_json, created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      this.runId, capId, kind, promotionStatus, oracleVerified ? 1 : 0,
      provenance, tenantScope, actorPersona, serviceOrigin, surface,
      temporalState, validityTtlMs, JSON.stringify(parentHopReceiptIds),
      artifactDigest, artifactSummary, JSON.stringify(metadata), createdAtMs, createdAtMs,
    )
    return this.getCapability(capId)!
  }

  getCapability(capId: string): CapabilityNode | null {
    const row = this.db.prepare('SELECT * FROM capability_nodes WHERE run_id = ? AND cap_id = ?').get(this.runId, capId) as DbRow | undefined
    return row ? rowToNode(row) : null
  }

  listCapabilities(filter: {
    kind?: CapabilityKind; promotionStatus?: PromotionStatus; temporalState?: CapabilityTemporalState
    tenantScope?: string; actorPersona?: string; surface?: CapabilitySurface
  } = {}): CapabilityNode[] {
    return this.queryFiltered('capability_nodes', [
      ['kind', filter.kind], ['promotion_status', filter.promotionStatus],
      ['temporal_state', filter.temporalState], ['tenant_scope', filter.tenantScope],
      ['actor_persona', filter.actorPersona], ['surface', filter.surface],
    ], 'created_at_ms ASC, cap_id ASC').map(rowToNode)
  }

  updateTemporalState(capId: string, temporalState: CapabilityTemporalState, updatedAtMs = Date.now()): CapabilityNode {
    const state = reqEnum<CapabilityTemporalState>(temporalState, TEMPORAL_SET, 'temporalState')
    const ts = reqTimestamp(updatedAtMs, 'updatedAtMs')
    if (!this.getCapability(capId)) fail('CAPABILITY_NOT_FOUND', `Capability '${capId}' not found.`)
    this.db.prepare('UPDATE capability_nodes SET temporal_state = ?, updated_at_ms = ? WHERE run_id = ? AND cap_id = ?').run(state, ts, this.runId, capId)
    return this.getCapability(capId)!
  }

  markTerminalEligible(capId: string, oracleVerificationRef: string, updatedAtMs = Date.now()): CapabilityNode {
    const ref = reqStr(oracleVerificationRef, 'oracleVerificationRef')
    assertNoRawSecretsInString(ref, 'oracleVerificationRef')
    const ts = reqTimestamp(updatedAtMs, 'updatedAtMs')
    const existing = this.getCapability(capId) ?? fail('CAPABILITY_NOT_FOUND', `Capability '${capId}' not found.`)
    if (ALWAYS_QUARANTINED_KINDS.has(existing.kind)) fail('QUARANTINED_KIND', `Capability '${capId}' (${existing.kind}) is locked as 'capability_only'.`)
    this.db.prepare(`
      UPDATE capability_nodes
      SET promotion_status = 'terminal_eligible', terminal_impact_oracle_verified = 1, metadata_json = ?, updated_at_ms = ?
      WHERE run_id = ? AND cap_id = ?
    `).run(JSON.stringify({ ...existing.metadata, terminalOracleRef: ref }), ts, this.runId, capId)
    return this.getCapability(capId)!
  }

  assertPromotable(capId: string, hasVerifiedCompositeReceipt = false, options: { terminalImpactOracleVerified?: boolean } = {}): CapabilityNode {
    const node = this.getCapability(capId) ?? fail('CAPABILITY_NOT_FOUND', `Capability '${capId}' not found.`)
    if (hasVerifiedCompositeReceipt === true) return node
    if (
      !ALWAYS_QUARANTINED_KINDS.has(node.kind)
      && ((node.promotionStatus === 'terminal_eligible' && node.terminalImpactOracleVerified) || options.terminalImpactOracleVerified === true)
    ) return node
    fail('CAPABILITY_QUARANTINED', `Capability '${capId}' (${node.kind}, ${node.promotionStatus}) requires a verified CompositeProofReceipt or terminal impact oracle.`)
  }

  addCausalEdge(input: AddCausalEdgeInput): CausalEdge {
    const edgeId = reqStr(input.edgeId ?? `edge_${randomUUID()}`, 'edgeId')
    const preconditionCapIds = dedupeStrings(input.preconditionCapIds, 'preconditionCapIds')
    if (preconditionCapIds.length === 0) fail('INVALID_ARGUMENT', 'preconditionCapIds must be non-empty.')
    const hopReceiptId = reqStr(input.hopReceiptId, 'hopReceiptId')
    const edgeBindingKind = reqEnum<CausalEdgeBindingKind>(input.edgeBindingKind, BINDING_SET, 'edgeBindingKind')
    const postconditionCapId = input.postconditionCapId ? reqStr(input.postconditionCapId, 'postconditionCapId') : null
    const terminalImpact = input.terminalImpact ? reqStr(input.terminalImpact, 'terminalImpact') : null
    if (!postconditionCapId && !terminalImpact) fail('INVALID_ARGUMENT', 'Causal edge must specify postconditionCapId or terminalImpact.')

    const actorContext: CausalActorContext = {
      persona: reqStr(input.actorContext?.persona, 'actorContext.persona'),
      ...(input.actorContext.tenantScope ? { tenantScope: reqStr(input.actorContext.tenantScope, 'actorContext.tenantScope') } : {}),
      ...(input.actorContext.roleLabel ? { roleLabel: reqStr(input.actorContext.roleLabel, 'actorContext.roleLabel') } : {}),
      ...(input.actorContext.serviceOrigin ? { serviceOrigin: reqStr(input.actorContext.serviceOrigin, 'actorContext.serviceOrigin') } : {}),
    }

    const sourceTimestampMs = reqTimestamp(input.sourceTimestampMs, 'sourceTimestampMs')
    const targetTimestampMs = reqTimestamp(input.targetTimestampMs, 'targetTimestampMs')
    if (sourceTimestampMs > targetTimestampMs) fail('NON_MONOTONIC_TIMESTAMP', `Edge '${edgeId}' has sourceTimestampMs > targetTimestampMs.`)

    const bindingDigest = input.bindingDigest ? reqSha256(input.bindingDigest, 'bindingDigest') : null
    const metadata = input.metadata ?? {}
    assertNoRawSecretsInString(hopReceiptId, 'hopReceiptId')
    if (terminalImpact) assertNoRawSecretsInString(terminalImpact, 'terminalImpact')
    assertNoRawSecretsInMetadata(actorContext, 'actorContext')
    assertNoRawSecretsInMetadata(metadata, 'metadata')

    for (const preId of preconditionCapIds) if (!this.getCapability(preId)) fail('CAPABILITY_NOT_FOUND', `Precondition '${preId}' not found.`)
    if (postconditionCapId && !this.getCapability(postconditionCapId)) fail('CAPABILITY_NOT_FOUND', `Postcondition '${postconditionCapId}' not found.`)
    if (this.getCausalEdge(edgeId)) fail('DUPLICATE_EDGE', `Causal edge '${edgeId}' already exists.`)

    const allEdges = this.listCausalEdges()
    // Check DAG acyclicity before cross-hop timestamps so back-edges always report CYCLE_DETECTED.
    if (postconditionCapId) {
      if (preconditionCapIds.includes(postconditionCapId)) fail('CYCLE_DETECTED', `Self-loop rejected on '${postconditionCapId}'.`)
      const preSet = new Set(preconditionCapIds)
      const adj = new Map<string, string[]>()
      for (const e of allEdges) {
        if (!e.postconditionCapId) continue
        for (const pre of e.preconditionCapIds) { const list = adj.get(pre) ?? []; list.push(e.postconditionCapId); adj.set(pre, list) }
      }
      const visited = new Set<string>([postconditionCapId])
      const queue = [postconditionCapId]
      while (queue.length > 0) {
        for (const next of adj.get(queue.shift()!) ?? []) {
          if (preSet.has(next)) fail('CYCLE_DETECTED', `Edge '${edgeId}' would introduce a cycle via '${next}'.`)
          if (!visited.has(next)) { visited.add(next); queue.push(next) }
        }
      }
    }

    for (const edge of allEdges) {
      if (edge.postconditionCapId && preconditionCapIds.includes(edge.postconditionCapId) && edge.targetTimestampMs > sourceTimestampMs) {
        fail('NON_MONOTONIC_TIMESTAMP', `Edge '${edgeId}' (${sourceTimestampMs}) precedes upstream '${edge.edgeId}' (${edge.targetTimestampMs}).`)
      }
      if (postconditionCapId && edge.preconditionCapIds.includes(postconditionCapId) && targetTimestampMs > edge.sourceTimestampMs) {
        fail('NON_MONOTONIC_TIMESTAMP', `Edge '${edgeId}' (${targetTimestampMs}) follows downstream '${edge.edgeId}' (${edge.sourceTimestampMs}).`)
      }
    }

    const createdAtMs = reqTimestamp(input.createdAtMs ?? Date.now(), 'createdAtMs')
    this.db.prepare(`
      INSERT INTO capability_causal_edges (
        run_id, edge_id, precondition_cap_ids_json, actor_context_json,
        hop_receipt_id, edge_binding_kind, postcondition_cap_id, terminal_impact,
        source_timestamp_ms, target_timestamp_ms, binding_digest, metadata_json, created_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      this.runId, edgeId, JSON.stringify(preconditionCapIds), JSON.stringify(actorContext),
      hopReceiptId, edgeBindingKind, postconditionCapId, terminalImpact,
      sourceTimestampMs, targetTimestampMs, bindingDigest, JSON.stringify(metadata), createdAtMs,
    )
    return this.getCausalEdge(edgeId)!
  }

  getCausalEdge(edgeId: string): CausalEdge | null {
    const row = this.db.prepare('SELECT * FROM capability_causal_edges WHERE run_id = ? AND edge_id = ?').get(this.runId, edgeId) as DbRow | undefined
    return row ? rowToEdge(row) : null
  }

  getIncomingEdges(capId: string): CausalEdge[] {
    return (this.db.prepare(
      'SELECT * FROM capability_causal_edges WHERE run_id = ? AND postcondition_cap_id = ? ORDER BY target_timestamp_ms ASC, edge_id ASC',
    ).all(this.runId, capId) as DbRow[]).map(rowToEdge)
  }

  getOutgoingEdges(capId: string): CausalEdge[] {
    return this.listCausalEdges().filter(edge => edge.preconditionCapIds.includes(capId))
  }

  listCausalEdges(filter: { edgeBindingKind?: CausalEdgeBindingKind; terminalOnly?: boolean } = {}): CausalEdge[] {
    const clauses = ['run_id = ?']
    const params: Array<string | number> = [this.runId]
    if (filter.edgeBindingKind) { clauses.push('edge_binding_kind = ?'); params.push(filter.edgeBindingKind) }
    if (filter.terminalOnly) clauses.push('terminal_impact IS NOT NULL')
    return (this.db.prepare(
      `SELECT * FROM capability_causal_edges WHERE ${clauses.join(' AND ')} ORDER BY source_timestamp_ms ASC, target_timestamp_ms ASC, edge_id ASC`,
    ).all(...params) as DbRow[]).map(rowToEdge)
  }

  /** Verifies an unbroken causal lineage from `attackerPersonas` without privileged-persona shortcuts. */
  traceProvenanceToAttacker(capId: string, attackerPersonas: ReadonlySet<string> | readonly string[]): AttackerProvenanceResult {
    const attackerSet = new Set([...attackerPersonas].map(p => p.trim()).filter(Boolean))
    const nodes = new Map(this.listCapabilities().map(n => [n.capId, n]))
    if (!nodes.has(capId)) {
      return {
        valid: false, capId, hopDepth: 0, rootCapIds: [], attackerRootPersonas: [], pathCapIds: [], pathEdgeIds: [],
        violations: [{ code: 'capability_not_found', capId, detail: `Capability '${capId}' does not exist.` }],
      }
    }

    const incomingMap = new Map<string, CausalEdge[]>()
    for (const edge of this.listCausalEdges()) {
      if (!edge.postconditionCapId) continue
      const bucket = incomingMap.get(edge.postconditionCapId) ?? []
      bucket.push(edge)
      incomingMap.set(edge.postconditionCapId, bucket)
    }

    const memo = new Map<string, ProofMemo>()
    const visiting = new Set<string>()
    const solve = (targetId: string): ProofMemo => {
      const cached = memo.get(targetId)
      if (cached) return cached
      const node = nodes.get(targetId)
      if (!node || visiting.has(targetId)) {
        return failedProof([{ code: 'capability_not_found', capId: targetId, detail: `Unresolvable node '${targetId}'.` }])
      }
      visiting.add(targetId)
      const incoming = incomingMap.get(targetId) ?? []
      if (incoming.length === 0) {
        visiting.delete(targetId)
        const rootMemo = attackerSet.has(node.actorPersona)
          ? {
              valid: true, hopDepth: 0, rootCapIds: new Set([targetId]),
              attackerRootPersonas: new Set([node.actorPersona]), derivedPersonas: new Set([node.actorPersona]),
              pathCapIds: [targetId], pathEdgeIds: [], violations: [],
            }
          : failedProof([{
              code: 'preseeded_privileged_root', capId: targetId, persona: node.actorPersona,
              detail: `Root '${targetId}' belongs to non-attacker persona '${node.actorPersona}'.`,
            }], targetId)
        memo.set(targetId, rootMemo)
        return rootMemo
      }

      let best: ProofMemo | null = null
      const violations: AttackerProvenanceViolation[] = []
      for (const edge of incoming) {
        const preProofs = edge.preconditionCapIds.map(solve)
        const failed = preProofs.filter(p => !p.valid)
        if (failed.length > 0) { failed.forEach(f => violations.push(...f.violations)); continue }
        const available = new Set<string>(attackerSet)
        preProofs.forEach(p => p.derivedPersonas.forEach(persona => available.add(persona)))
        if (!available.has(edge.actorContext.persona) && edge.edgeBindingKind !== 'async_pivot_binding') {
          violations.push({
            code: 'privileged_actor_shortcut', capId: targetId, edgeId: edge.edgeId, persona: edge.actorContext.persona,
            detail: `Edge '${edge.edgeId}' (${edge.edgeBindingKind}) executed by '${edge.actorContext.persona}' without derived authority.`,
          })
          continue
        }

        const rootCapIds = new Set<string>()
        const attackerRootPersonas = new Set<string>()
        const derivedPersonas = new Set<string>(available)
        const pathCapIds: string[] = []
        const pathEdgeIds: string[] = []
        let maxPreDepth = 0
        for (const p of preProofs) {
          maxPreDepth = Math.max(maxPreDepth, p.hopDepth)
          p.rootCapIds.forEach(r => rootCapIds.add(r))
          p.attackerRootPersonas.forEach(a => attackerRootPersonas.add(a))
          p.pathCapIds.forEach(c => { if (!pathCapIds.includes(c)) pathCapIds.push(c) })
          p.pathEdgeIds.forEach(e => { if (!pathEdgeIds.includes(e)) pathEdgeIds.push(e) })
        }
        if (AUTHORITY_GRANTING_KINDS.has(node.kind)) derivedPersonas.add(node.actorPersona)
        if (!pathCapIds.includes(targetId)) pathCapIds.push(targetId)
        if (!pathEdgeIds.includes(edge.edgeId)) pathEdgeIds.push(edge.edgeId)

        const candidate: ProofMemo = {
          valid: true, hopDepth: maxPreDepth + 1, rootCapIds, attackerRootPersonas,
          derivedPersonas, pathCapIds, pathEdgeIds, violations: [],
        }
        if (!best || candidate.hopDepth < best.hopDepth) best = candidate
      }

      visiting.delete(targetId)
      const outcome = best ?? failedProof(violations)
      memo.set(targetId, outcome)
      return outcome
    }

    const res = solve(capId)
    return {
      valid: res.valid, capId, hopDepth: res.hopDepth,
      rootCapIds: [...res.rootCapIds].sort(), attackerRootPersonas: [...res.attackerRootPersonas].sort(),
      pathCapIds: res.pathCapIds, pathEdgeIds: res.pathEdgeIds, violations: res.violations,
    }
  }

  recordNegativeEdge(input: RecordNegativeEdgeInput): NegativeEdge {
    const preconditionCapIds = dedupeStrings(input.preconditionCapIds, 'preconditionCapIds').sort()
    const preconditionKey = canonicalPreconditionKey(preconditionCapIds)
    const targetSurfaceKey = reqStr(input.targetSurfaceKey, 'targetSurfaceKey')
    const hypothesisClass = reqStr(input.hypothesisClass, 'hypothesisClass')
    const reason = reqEnum<NegativeEdgeReason>(input.reason, NEGATIVE_REASON_SET, 'reason')
    const exchangeIds = dedupeStrings(input.falsifiedByExchangeIds, 'falsifiedByExchangeIds')
    if (exchangeIds.length === 0) fail('INVALID_ARGUMENT', 'falsifiedByExchangeIds must be non-empty.')
    const notes = (input.notes ?? '').trim()
    assertNoRawSecretsInString(targetSurfaceKey, 'targetSurfaceKey')
    assertNoRawSecretsInString(hypothesisClass, 'hypothesisClass')
    assertNoRawSecretsInString(notes, 'notes')
    const ts = reqTimestamp(input.timestampMs ?? Date.now(), 'timestampMs')

    const existing = this.getNegativeEdge(preconditionCapIds, targetSurfaceKey, hypothesisClass)
    if (!existing) {
      const pruned = input.forcePrune === true || 1 >= this.pruneStrikeThreshold
      this.db.prepare(`
        INSERT INTO capability_negative_edges (
          run_id, precondition_key, precondition_cap_ids_json, target_surface_key,
          hypothesis_class, falsified_by_exchange_ids_json, reason, attempt_count,
          pruned, notes, created_at_ms, updated_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
      `).run(
        this.runId, preconditionKey, JSON.stringify(preconditionCapIds), targetSurfaceKey,
        hypothesisClass, JSON.stringify(exchangeIds), reason, pruned ? 1 : 0, notes, ts, ts,
      )
    } else {
      const nextCount = existing.attemptCount + 1
      const pruned = existing.pruned || input.forcePrune === true || nextCount >= this.pruneStrikeThreshold
      const merged = [...new Set([...existing.falsifiedByExchangeIds, ...exchangeIds])]
      this.db.prepare(`
        UPDATE capability_negative_edges
        SET falsified_by_exchange_ids_json = ?, reason = ?, attempt_count = ?, pruned = ?, notes = ?, updated_at_ms = ?
        WHERE run_id = ? AND precondition_key = ? AND target_surface_key = ? AND hypothesis_class = ?
      `).run(
        JSON.stringify(merged), reason, nextCount, pruned ? 1 : 0, notes || existing.notes, ts,
        this.runId, preconditionKey, targetSurfaceKey, hypothesisClass,
      )
    }
    return this.getNegativeEdge(preconditionCapIds, targetSurfaceKey, hypothesisClass)!
  }

  getNegativeEdge(preconditionCapIds: readonly string[], targetSurfaceKey: string, hypothesisClass: string): NegativeEdge | null {
    const row = this.db.prepare(`
      SELECT * FROM capability_negative_edges
      WHERE run_id = ? AND precondition_key = ? AND target_surface_key = ? AND hypothesis_class = ?
    `).get(this.runId, canonicalPreconditionKey(preconditionCapIds), targetSurfaceKey.trim(), hypothesisClass.trim()) as DbRow | undefined
    return row ? rowToNegativeEdge(row) : null
  }

  isBranchPruned(preconditionCapIds: readonly string[], targetSurfaceKey: string, hypothesisClass: string): boolean {
    const record = this.getNegativeEdge(preconditionCapIds, targetSurfaceKey, hypothesisClass)
    return record !== null && (record.pruned || record.attemptCount >= this.pruneStrikeThreshold)
  }

  listNegativeEdges(filter: { prunedOnly?: boolean; targetSurfaceKey?: string; hypothesisClass?: string } = {}): NegativeEdge[] {
    return this.queryFiltered('capability_negative_edges', [
      ['pruned', filter.prunedOnly ? 1 : undefined],
      ['target_surface_key', filter.targetSurfaceKey?.trim()],
      ['hypothesis_class', filter.hypothesisClass?.trim()],
    ], 'updated_at_ms DESC, target_surface_key ASC').map(rowToNegativeEdge)
  }

  /** Exports the canonical `v8.hop_checkpoint.v1` brief (`<= maxBytes`, default 2048 B) from SQLite. */
  buildHopCheckpointBrief(capId: string, maxBytes = DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES, options: HopCheckpointBriefOptions = {}): HopCheckpointBrief {
    if (!Number.isInteger(maxBytes) || maxBytes < MIN_CHECKPOINT_BRIEF_MAX_BYTES) fail('INVALID_ARGUMENT', `maxBytes must be >= ${MIN_CHECKPOINT_BRIEF_MAX_BYTES}.`)
    const targetNode = this.getCapability(capId) ?? fail('CAPABILITY_NOT_FOUND', `Capability '${capId}' not found.`)
    const incomingByPost = new Map<string, CausalEdge[]>()
    for (const edge of this.listCausalEdges()) {
      if (!edge.postconditionCapId) continue
      const list = incomingByPost.get(edge.postconditionCapId) ?? []
      list.push(edge); incomingByPost.set(edge.postconditionCapId, list)
    }
    const ancestorCaps = new Set<string>([capId]), lineageEdgeMap = new Map<string, CausalEdge>(), depthByCap = new Map<string, number>([[capId, 0]]), queue = [capId]
    let maxDepth = 0
    while (queue.length > 0) {
      const curr = queue.shift()!, currDist = depthByCap.get(curr) ?? 0
      for (const edge of incomingByPost.get(curr) ?? []) {
        lineageEdgeMap.set(edge.edgeId, edge)
        for (const preId of edge.preconditionCapIds) {
          const nextDist = currDist + 1; maxDepth = Math.max(maxDepth, nextDist); ancestorCaps.add(preId)
          if (nextDist > (depthByCap.get(preId) ?? -1)) { depthByCap.set(preId, nextDist); queue.push(preId) }
        }
      }
    }
    const orderedEdges = [...lineageEdgeMap.values()].sort((a, b) => a.sourceTimestampMs - b.sourceTimestampMs || a.edgeId.localeCompare(b.edgeId))
    const prunedRelevant = this.listNegativeEdges({ prunedOnly: true }).filter(neg => neg.preconditionCapIds.some(id => ancestorCaps.has(id)))
    const orderedHandles = [...ancestorCaps].sort((a, b) => (depthByCap.get(b) ?? 0) - (depthByCap.get(a) ?? 0) || a.localeCompare(b))
    const incomingEdgeByCap = new Map<string, CausalEdge>()
    for (const edge of orderedEdges) if (edge.postconditionCapId) incomingEdgeByCap.set(edge.postconditionCapId, edge)
    const verifiedHops: CompactCheckpointHop[] = orderedHandles.map((id, idx) => {
      const node = this.getCapability(id), edge = incomingEdgeByCap.get(id)
      return {
        hop: idx + 1, receiptId: sanitizeCheckpointHandleRef(edge?.hopReceiptId ?? node?.parentHopReceiptIds[0] ?? `hop:${idx + 1}`, `hop:${idx + 1}`),
        capId: sanitizeCheckpointHandleRef(id, `cap:redacted:${idx + 1}`), kind: node?.kind ?? targetNode.kind, surface: node?.surface ?? targetNode.surface,
        service: truncateBriefText(node?.serviceOrigin ?? targetNode.serviceOrigin, 48), tenant: truncateBriefText(node?.tenantScope ?? targetNode.tenantScope, 36),
        actor: truncateBriefText(edge?.actorContext.persona ?? node?.actorPersona ?? targetNode.actorPersona, 36),
        ...(edge?.actorContext.roleLabel ? { role: truncateBriefText(edge.actorContext.roleLabel, 28) } : {}),
        ...(edge ? { binding: edge.edgeBindingKind } : {}),
      }
    })
    const ng = options.nextGoal, endpoint = sanitizeCheckpointText(ng?.endpoint ?? (typeof targetNode.metadata.endpoint === 'string' ? targetNode.metadata.endpoint : '/'), 96)
    const service = truncateBriefText(ng?.service ?? targetNode.serviceOrigin, 48), surface = ng?.surface ?? targetNode.surface
    return finalizeHopCheckpointBrief({
      schema: 'v8.hop_checkpoint.v1', branchKey: truncateBriefText(options.branchKey ?? capId, 64), depth: maxDepth, targetHop: Math.min(6, maxDepth + 1),
      mode: options.mode ?? (options.fuseWithBranchKey ? 'fuse' : 'pivot'), evi: Number((options.evi ?? 1).toFixed(6)), verifiedHops,
      capabilityHandles: orderedHandles.map((h, i) => sanitizeCheckpointHandleRef(h, `cap:redacted:${i + 1}`)),
      ...(options.fuseWithBranchKey ? { fuseWithBranchKey: truncateBriefText(options.fuseWithBranchKey, 64) } : {}),
      nextGoal: {
        targetSurfaceKey: truncateBriefText(ng?.targetSurfaceKey ?? `${service}|${surface}|${endpoint}`, 80), surface, service, endpoint,
        ...(ng?.method ? { method: ng.method.toUpperCase() } : {}), hypothesisClass: truncateBriefText(ng?.hypothesisClass ?? targetNode.kind, 48),
        ...(ng?.expectedBinding ? { expectedBinding: ng.expectedBinding } : {}),
        ...(ng?.targetTenant ? { targetTenant: truncateBriefText(ng.targetTenant, 36) } : {}),
        ...(ng?.targetRole ? { targetRole: truncateBriefText(ng.targetRole, 32) } : {}),
        goal: sanitizeCheckpointText(ng?.goal ?? (targetNode.artifactSummary || `Pivot from ${capId}`), 180),
      },
      ...(prunedRelevant.length > 0 ? { prunedBranches: prunedRelevant.map(n => ({ surface: truncateBriefText(n.targetSurfaceKey, 64), hypothesis: truncateBriefText(n.hypothesisClass, 48), reason: n.reason })) } : {}),
      ...(options.workflowNotebook ? { workflowNotebook: options.workflowNotebook } : {}),
      truncated: false, doNotRediscover: true,
    }, maxBytes).brief
  }

  getStats(): CapabilityLedgerStats {
    const nodes = this.db.prepare(
      `SELECT COUNT(*) AS total, SUM(CASE WHEN promotion_status = 'capability_only' THEN 1 ELSE 0 END) AS quarantined, SUM(CASE WHEN promotion_status = 'terminal_eligible' THEN 1 ELSE 0 END) AS terminal_eligible FROM capability_nodes WHERE run_id = ?`,
    ).get(this.runId) as { total: number; quarantined: number | null; terminal_eligible: number | null }
    const edges = this.db.prepare('SELECT COUNT(*) AS total FROM capability_causal_edges WHERE run_id = ?').get(this.runId) as { total: number }
    const negs = this.db.prepare('SELECT COUNT(*) AS total, SUM(CASE WHEN pruned = 1 THEN 1 ELSE 0 END) AS pruned FROM capability_negative_edges WHERE run_id = ?').get(this.runId) as { total: number; pruned: number | null }
    return { totalNodes: nodes.total, quarantinedNodes: nodes.quarantined ?? 0, terminalEligibleNodes: nodes.terminal_eligible ?? 0, positiveEdges: edges.total, negativeEdges: negs.total, prunedBranches: negs.pruned ?? 0 }
  }

  private queryFiltered(table: string, filters: ReadonlyArray<[string, string | number | undefined]>, orderBy: string): DbRow[] {
    const clauses = ['run_id = ?'], params: Array<string | number> = [this.runId]
    for (const [col, val] of filters) if (val !== undefined) { clauses.push(`${col} = ?`); params.push(val) }
    return this.db.prepare(`SELECT * FROM ${table} WHERE ${clauses.join(' AND ')} ORDER BY ${orderBy}`).all(...params) as DbRow[]
  }
}
