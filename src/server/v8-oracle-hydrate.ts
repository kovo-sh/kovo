/**
 * Host-transcript hydration for v8 extended oracle families and logical-key matching
 * for `state_transition_binding`.
 *
 * Pure, deterministic, fail-closed helpers. Verification scripts only observe exchange IDs
 * (`"gx-..."`) and can never know host HMAC signatures; this module resolves exchange-ID
 * references and stubs against the host-signed transcript without ever forging missing records.
 */
import { createHash } from 'node:crypto'
import { stepReadsState } from './oracle-invariants.ts'
import { isJobOrHandleStub, type HostSignedRecord, type V8OracleFamily } from './v8-oracle-families.ts'

export interface HydratableEntry {
  exchangeId: string
  timestampMs?: number
  actorPersona?: string | null
  actorRoleLabel?: string | null
  emittedCapabilities?: readonly string[]
  observedResponseDigests?: readonly string[]
  consumedCapabilities?: readonly string[]
  cryptoAttestations?: readonly { derivedFromCapabilityId: string; artifactDigest?: string }[]
  hostSignature?: string
  evidenceRole?: string
  step: {
    arm: string
    method: string
    route?: string
    pathAndQuery?: string
    status: number | null
    actor: { handle?: string | null; role?: string | null; tenant?: string | null; auth?: string }
    body?: string
    json?: unknown
    requestJson?: unknown
    requestHeaders?: Record<string, string> | null
    responseHeaders?: Record<string, string> | null
    evidenceRole?: string
  }
}

export interface HydratableOobEvent {
  id: string
  delivered: boolean
  receivedAtMs?: number
  token?: string
  emittedCapabilities?: readonly string[]
  observedValueDigests?: readonly string[]
  hostSignature?: string
}

export interface HydratableBrowserTrace {
  id: string
  timestampMs?: number
  actorPersona?: string | null
  emittedCapabilities?: readonly string[]
  observedValueDigests?: readonly string[]
  hostSignature?: string
}

export interface HydratableTranscriptIndex {
  entriesById: ReadonlyMap<string, HydratableEntry>
  oobById?: ReadonlyMap<string, HydratableOobEvent>
  tracesById?: ReadonlyMap<string, HydratableBrowserTrace>
}

export interface EconomicAutoHydrateContext {
  preChainControlExchangeIds: readonly string[]
  termHopExchangeIds: readonly string[]
  postChainReadbackExchangeIds: readonly string[]
}

const sha256Hex = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex')
const isFiniteTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts >= 0
const isPosTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts > 0
const is2xx = (st: number | null | undefined): boolean => typeof st === 'number' && st >= 200 && st < 300
const actorOfEntry = (e: HydratableEntry): string | null =>
  e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null)

/** Convert a host transcript entry into a `HostSignedRecord` for v8 oracle family evaluators. */
export function toOracleRecord(e: HydratableEntry, fallbackSig: string): HostSignedRecord {
  return {
    id: e.exchangeId,
    hostSignature: e.hostSignature ?? fallbackSig,
    timestampMs: isPosTs(e.timestampMs) ? e.timestampMs : 1,
    status: e.step.status,
    method: e.step.method,
    route: e.step.route ?? e.step.pathAndQuery,
    actorId: actorOfEntry(e),
    tenantId: e.step.actor.tenant ?? null,
    body: e.step.body,
    json: e.step.json,
    requestHeaders: e.step.requestHeaders ?? null,
    responseHeaders: e.step.responseHeaders ?? null,
    capabilityHandle: e.emittedCapabilities?.[0] ?? e.consumedCapabilities?.[0] ?? null,
    artifactDigest: e.observedResponseDigests?.[0] ?? e.cryptoAttestations?.[0]?.artifactDigest
      ?? sha256Hex(e.step.body ?? JSON.stringify(e.step.json ?? null)),
    derivedFromCapabilityId: e.cryptoAttestations?.[0]?.derivedFromCapabilityId ?? null,
  }
}

function lookupOracleRecord(id: string, idx: HydratableTranscriptIndex, fallbackSig: string): HostSignedRecord | undefined {
  const entry = idx.entriesById.get(id)
  if (entry) return toOracleRecord(entry, fallbackSig)
  const oob = idx.oobById?.get(id)
  if (oob) {
    return {
      id: oob.id,
      hostSignature: oob.hostSignature ?? fallbackSig,
      timestampMs: isPosTs(oob.receivedAtMs) ? oob.receivedAtMs : 1,
      surface: 'webhook',
      status: oob.delivered ? 200 : 0,
      capabilityHandle: oob.emittedCapabilities?.[0] ?? null,
      artifactDigest: oob.observedValueDigests?.[0] ?? (oob.token ? sha256Hex(oob.token) : null),
    }
  }
  const tr = idx.tracesById?.get(id)
  if (tr) {
    return {
      id: tr.id,
      hostSignature: tr.hostSignature ?? fallbackSig,
      timestampMs: isPosTs(tr.timestampMs) ? tr.timestampMs : 1,
      surface: 'browser',
      actorId: tr.actorPersona ?? null,
      capabilityHandle: tr.emittedCapabilities?.[0] ?? null,
      artifactDigest: tr.observedValueDigests?.[0] ?? null,
    }
  }
  return undefined
}

function hydrateRecordValue(raw: unknown, idx: HydratableTranscriptIndex, fallbackSig: string): unknown {
  if (raw === undefined || raw === null) return undefined
  if (typeof raw === 'string') {
    const id = raw.trim()
    return id ? lookupOracleRecord(id, idx, fallbackSig) : undefined
  }
  if (typeof raw === 'object' && !Array.isArray(raw)) {
    const obj = raw as Record<string, unknown>
    if (typeof obj.hostSignature === 'string') return raw
    if (typeof obj.exchangeId === 'string' && obj.exchangeId.trim()) {
      return lookupOracleRecord(obj.exchangeId.trim(), idx, fallbackSig)
    }
    if (typeof obj.id === 'string' && obj.id.trim()) {
      const found = lookupOracleRecord(obj.id.trim(), idx, fallbackSig)
      if (found) return found
      return 'timestampMs' in obj ? raw : undefined
    }
  }
  return raw
}

function hydrateSingleField(
  out: Record<string, unknown>,
  raw: Record<string, unknown>,
  field: string,
  aliases: readonly string[],
  idx: HydratableTranscriptIndex,
  fallbackSig: string,
): boolean {
  if (raw[field] !== undefined) {
    out[field] = hydrateRecordValue(raw[field], idx, fallbackSig)
    return true
  }
  for (const alias of aliases) {
    if (raw[alias] !== undefined) {
      out[field] = hydrateRecordValue(raw[alias], idx, fallbackSig)
      return true
    }
  }
  return false
}

function hydrateRecordArrayField(
  out: Record<string, unknown>,
  raw: Record<string, unknown>,
  field: string,
  aliases: readonly string[],
  idx: HydratableTranscriptIndex,
  fallbackSig: string,
): boolean {
  let src = raw[field]
  if (src === undefined) {
    for (const alias of aliases) {
      if (raw[alias] !== undefined) { src = raw[alias]; break }
    }
  }
  if (src === undefined) return false
  if (Array.isArray(src)) {
    out[field] = src.map(item => hydrateRecordValue(item, idx, fallbackSig))
  } else if (typeof src === 'string' || (typeof src === 'object' && src !== null)) {
    const hydrated = hydrateRecordValue(src, idx, fallbackSig)
    out[field] = hydrated !== undefined ? [hydrated] : []
  } else {
    out[field] = src
  }
  return true
}

const FAMILY_RECORD_FIELDS: Record<V8OracleFamily, readonly [string, readonly string[]][]> = {
  dual_tenant_abac: [
    ['transferRecord', ['transferRecordExchangeId', 'transferExchangeId']],
    ['postTransferReadback', ['postTransferReadbackExchangeId']],
    ['sourceControlDenied', ['sourceControlDeniedExchangeId', 'sourceControlExchangeId']],
    ['baselineDeniedControl', ['baselineDeniedControlExchangeId', 'baselineControlExchangeId']],
    ['primeAction', ['primeActionExchangeId']],
    ['bledAccess', ['bledAccessExchangeId']],
    ['singleForeignControlDenied', ['singleForeignControlDeniedExchangeId', 'singleForeignControlExchangeId']],
    ['batchRequest', ['batchRequestExchangeId']],
    ['postMutationReadback', ['postMutationReadbackExchangeId']],
  ],
  temporal_revocation: [
    ['preRevocationBaseline', ['preRevocationBaselineExchangeId']],
    ['revocationEvent', ['revocationEventExchangeId']],
    ['primaryDeniedCheck', ['primaryDeniedCheckExchangeId']],
    ['secondarySuccess', ['secondarySuccessExchangeId']],
  ],
  economic_conservation: [
    ['baselineReadback', ['baselineReadbackExchangeId', 'baselineExchangeId']],
    ['finalReadback', ['finalReadbackExchangeId', 'finalExchangeId']],
  ],
  cryptographic_scope_replay: [
    ['tamperedSignatureControl', ['tamperedSignatureControlExchangeId', 'tamperedControlExchangeId']],
    ['sourceValidIssuance', ['sourceValidIssuanceExchangeId', 'sourceIssuanceExchangeId']],
    ['replayedAcceptance', ['replayedAcceptanceExchangeId', 'replayedExchangeId']],
  ],
  parser_cache_differential: [
    ['cleanControl', ['cleanControlExchangeId']],
    ['differentialProbe', ['differentialProbeExchangeId']],
    ['postMutationReadback', ['postMutationReadbackExchangeId']],
    ['victimOrPrimeRequest', ['victimOrPrimeRequestExchangeId', 'victimPrimeExchangeId']],
    ['attackerProbe', ['attackerProbeExchangeId']],
  ],
  cross_surface_pivot: [
    ['preChainControlDenied', ['preChainControlDeniedExchangeId', 'preChainControlExchangeId']],
  ],
}

const hasEntryBody = (e: HydratableEntry): boolean =>
  e.step.json !== undefined || (typeof e.step.body === 'string' && e.step.body.trim().length > 0)

/**
 * Hydrate all `HostSignedRecord` fields inside a raw `oracleInput` from `HostSignedTranscript`.
 * For `economic_conservation`, auto-hydrates omitted `baselineReadback`, `actions`, and `finalReadback`
 * strictly from cited transcript exchanges — never forging missing records.
 */
export function hydrateV8OracleInput(
  family: V8OracleFamily,
  rawInput: Record<string, unknown>,
  idx: HydratableTranscriptIndex,
  fallbackSig: string,
  econCtx?: EconomicAutoHydrateContext,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...rawInput }
  const explicit = new Set<string>()
  for (const [field, aliases] of FAMILY_RECORD_FIELDS[family]) {
    if (hydrateSingleField(out, rawInput, field, aliases, idx, fallbackSig)) explicit.add(field)
  }

  if (family === 'cross_surface_pivot') {
    if (Array.isArray(rawInput.hops)) {
      out.hops = rawInput.hops.map(rawHop => {
        if (!rawHop || typeof rawHop !== 'object' || Array.isArray(rawHop)) return rawHop
        const hIn = rawHop as Record<string, unknown>, hOut: Record<string, unknown> = { ...hIn }
        hydrateSingleField(hOut, hIn, 'record', ['recordExchangeId', 'exchangeId'], idx, fallbackSig)
        hydrateSingleField(hOut, hIn, 'ablationControlDenied', ['ablationControlDeniedExchangeId', 'ablationExchangeId'], idx, fallbackSig)
        return hOut
      })
    }
    if (rawInput.terminalImpact && typeof rawInput.terminalImpact === 'object' && !Array.isArray(rawInput.terminalImpact)) {
      const tiIn = rawInput.terminalImpact as Record<string, unknown>, tiOut: Record<string, unknown> = { ...tiIn }
      hydrateSingleField(tiOut, tiIn, 'postImpactReadback', ['postImpactReadbackExchangeId'], idx, fallbackSig)
      out.terminalImpact = tiOut
    }
  }

  if (family === 'economic_conservation') {
    const hasExplicitActions = hydrateRecordArrayField(
      out, rawInput, 'actions', ['actionExchangeIds', 'actionsExchangeIds', 'actionExchangeId'], idx, fallbackSig,
    )
    if (econCtx) {
      if (!hasExplicitActions) {
        const actEntries = econCtx.termHopExchangeIds
          .map(id => idx.entriesById.get(id))
          .filter((e): e is HydratableEntry => Boolean(e && e.step.arm === 'probe' && is2xx(e.step.status) && isPosTs(e.timestampMs)))
        if (actEntries.length > 0) out.actions = actEntries.map(e => toOracleRecord(e, fallbackSig))
      }
      const validActs = Array.isArray(out.actions)
        ? (out.actions as unknown[]).filter((a): a is HostSignedRecord => Boolean(a && typeof a === 'object' && isPosTs((a as HostSignedRecord).timestampMs)))
        : []
      const actionIdSet = new Set(validActs.map(a => a.id))
      const minActTs = validActs.length > 0 ? Math.min(...validActs.map(a => a.timestampMs)) : null
      const maxActTs = validActs.length > 0 ? Math.max(...validActs.map(a => a.timestampMs)) : null

      if (!explicit.has('baselineReadback')) {
        const base = econCtx.preChainControlExchangeIds
          .map(id => idx.entriesById.get(id))
          .find((e): e is HydratableEntry => {
            if (!e || actionIdSet.has(e.exchangeId) || !is2xx(e.step.status) || !isPosTs(e.timestampMs)) return false
            if (minActTs !== null && e.timestampMs > minActTs) return false
            return stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'pre_chain_control' || e.step.evidenceRole === 'baseline_readback'
          })
        if (base) out.baselineReadback = toOracleRecord(base, fallbackSig)
      }
      if (!explicit.has('finalReadback')) {
        const baseId = out.baselineReadback && typeof out.baselineReadback === 'object' ? (out.baselineReadback as HostSignedRecord).id : null
        const fin = econCtx.postChainReadbackExchangeIds
          .map(id => idx.entriesById.get(id))
          .find((e): e is HydratableEntry => {
            if (!e || actionIdSet.has(e.exchangeId) || (baseId && e.exchangeId === baseId)) return false
            if (!is2xx(e.step.status) || !isPosTs(e.timestampMs)) return false
            if (maxActTs !== null && e.timestampMs < maxActTs) return false
            const isRead = stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'post_chain_readback'
            return isRead && hasEntryBody(e) && !isJobOrHandleStub(e.step.json, e.step.body, e.step.status, e.step.method, e.step.route ?? e.step.pathAndQuery)
          })
        if (fin) out.finalReadback = toOracleRecord(fin, fallbackSig)
      }
    }
  }

  return out
}

/** Extract normalized canonical suffix tokens from a logical/namespaced state key (e.g. `"perm:dual_member"` -> `["dual_member"]`). */
export function extractCanonicalEntityTokens(entityId: string): string[] {
  const trimmed = entityId.trim()
  if (!trimmed) return []
  const tokens: string[] = [], seen = new Set<string>()
  const push = (t: string) => { const n = t.trim().toLowerCase(); if (n.length >= 2 && !seen.has(n)) { seen.add(n); tokens.push(n) } }
  if (trimmed.includes(':')) {
    const parts = trimmed.split(':')
    for (let i = 1; i < parts.length; i++) push(parts[i]!)
  } else {
    push(trimmed)
  }
  return tokens
}

/**
 * Select a monotonic `(from, to)` exchange pair for `state_transition_binding`.
 * Uses literal `entryMatchesEntity` matches as the primary path; when either side has no literal match
 * (e.g. logical/namespaced state keys like `"perm:dual_member"` or `"org_b"`), falls back to canonical
 * token matches and succeeding probe exchanges with actor/session continuity or a DAG-derived capability.
 */
export function selectStateTransitionPair<T extends HydratableEntry>(
  entityId: string,
  fromEntries: readonly T[],
  toEntries: readonly T[],
  dagDerivedCaps: ReadonlySet<string>,
  helpers: {
    actorOf: (e: T) => string | null
    probeTenantOf: (e: T) => string | null
    entryMatchesEntity: (e: T, eid: string) => boolean
    anonActorRe: RegExp
  },
):
  | { ok: true; from: T; to: T; logicalFallback: boolean }
  | { ok: false; reason: 'missing_from' | 'missing_to' | 'non_monotonic' | 'actor_discontinuity'; missingSide?: 'from' | 'to' } {
  const okLit = (es: readonly T[]) => es.filter(e => is2xx(e.step.status) && isFiniteTs(e.timestampMs) && helpers.entryMatchesEntity(e, entityId))
  const fromLit = okLit(fromEntries), toLit = okLit(toEntries)
  if (fromLit.length > 0 && toLit.length > 0) {
    const lit = fromLit.flatMap(f => toLit.filter(t => f.timestampMs! <= t.timestampMs!).map(t => ({ from: f, to: t })))[0]
    return lit ? { ok: true, from: lit.from, to: lit.to, logicalFallback: false } : { ok: false, reason: 'non_monotonic' }
  }
  const okProbes = (es: readonly T[]) => es.filter(e => e.step.arm === 'probe' && is2xx(e.step.status) && isFiniteTs(e.timestampMs))
  const fromProbes = okProbes(fromEntries), toProbes = okProbes(toEntries)
  if (fromLit.length === 0 && fromProbes.length === 0) return { ok: false, reason: 'missing_from' }
  if (toLit.length === 0 && toProbes.length === 0) return { ok: false, reason: 'missing_to' }
  const tokens = extractCanonicalEntityTokens(entityId)
  const tokMatch = (e: T): boolean => {
    const a = helpers.actorOf(e)?.trim().toLowerCase() ?? ''
    const t1 = e.step.actor.tenant?.trim().toLowerCase() ?? ''
    const t2 = helpers.probeTenantOf(e) ?? ''
    return tokens.some(tok => a === tok || t1 === tok || t2 === tok || helpers.entryMatchesEntity(e, tok))
  }
  const rank = (lit: readonly T[], probes: readonly T[]): readonly T[] =>
    lit.length > 0 ? lit : [...probes.filter(tokMatch), ...probes.filter(e => !tokMatch(e))]
  const fCands = rank(fromLit, fromProbes), tCands = rank(toLit, toProbes)
  const monoPairs = fCands.flatMap(f => tCands.filter(t => f.timestampMs! <= t.timestampMs!).map(t => ({ from: f, to: t })))
  if (monoPairs.length === 0) return { ok: false, reason: 'non_monotonic' }
  const normAct = (e: T): string | null => {
    const a = helpers.actorOf(e)?.trim().toLowerCase() ?? ''
    return (!a || helpers.anonActorRe.test(a)) ? null : a
  }
  const matched = monoPairs.find(({ from: f, to: t }) => {
    const fa = normAct(f), ta = normAct(t)
    const sameActor = (fa !== null && fa === ta) || (fa === null && ta === null && f.step.actor.auth === t.step.actor.auth)
    const usesCap = (t.consumedCapabilities ?? []).some(c => dagDerivedCaps.has(c))
      || (t.cryptoAttestations ?? []).some(x => dagDerivedCaps.has(x.derivedFromCapabilityId))
    return sameActor || usesCap
  })
  return matched
    ? { ok: true, from: matched.from, to: matched.to, logicalFallback: true }
    : { ok: false, reason: 'actor_discontinuity', missingSide: fromLit.length === 0 ? 'from' : 'to' }
}
