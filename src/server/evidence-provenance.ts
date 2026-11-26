/**
 * Evidence Provenance & Host Custody Boundary (`R3-16`).
 *
 * Separates host-observed bytes, host-minted stamps/challenges, worker-selected pointers,
 * and worker-asserted prose at the TypeScript type level, and constructs the sealed
 * `HostEvidence` view via a strict allowlist so untrusted worker claim scalars
 * (`requiredRole`, `resourceTenant`, `expectControlDenied`, `proofPatterns`, `injectedAtMs`,
 * `conservedBalance`, `oracleEvents`) can never leak into oracle bodies.
 */
import type { ImpactClass, ImpactStep, RoleName } from './oracle-invariants.ts'
import type {
  ProofReceipt,
  ReceiptBrowserTrace,
  ReceiptOobEvent,
  ReceiptTranscript,
  ReceiptTranscriptEntry,
} from './proof-receipt.ts'

declare const HOST_OBSERVED_BRAND: unique symbol
declare const HOST_MINTED_BRAND: unique symbol
declare const WORKER_SELECTED_BRAND: unique symbol
declare const WORKER_ASSERTED_BRAND: unique symbol
declare const HOST_EVIDENCE_BRAND: unique symbol

/** N2: Module-private WeakSet seal so `{ ...genuine, receipt: forged }` fails `isHostEvidence`. */
const SEALED_HOST_EVIDENCE = new WeakSet<object>()

/** Immutable evidence recorded directly by the host broker/transport/store. */
export type HostObserved<T> = Readonly<T> & { readonly [HOST_OBSERVED_BRAND]: 'host_observed' }

/** Cryptographically bound nonce, challenge, or secret material minted by the host. */
export type HostMinted<T> = Readonly<T> & { readonly [HOST_MINTED_BRAND]: 'host_minted' }

/** Untrusted selector/pointer chosen by the worker (must be bound to host facts). */
export type WorkerSelected<T> = Readonly<T> & { readonly [WORKER_SELECTED_BRAND]: 'worker_selected' }

/** Untrusted free-text claim or summary authored by the worker (diagnostic display only). */
export type WorkerAsserted<T> = Readonly<T> & { readonly [WORKER_ASSERTED_BRAND]: 'worker_asserted' }

/** Provenance of an exchange's `ImpactStep['arm']` classification (`R3-16`). */
export type ArmProvenance = 'host_assigned' | 'worker_selected'

export function asHostObserved<T>(value: T): HostObserved<T> {
  return value as HostObserved<T>
}

export function asHostMinted<T>(value: T): HostMinted<T> {
  return value as HostMinted<T>
}

export function asWorkerSelected<T>(value: T): WorkerSelected<T> {
  return value as WorkerSelected<T>
}

export function asWorkerAsserted<T>(value: T): WorkerAsserted<T> {
  return value as WorkerAsserted<T>
}

/**
 * Exhaustive allowlist of `ProofReceipt` fields permitted across the host custody boundary.
 * Every worker scalar outside this set (`requiredRole`, `resourceTenant`, `expectControlDenied`,
 * `proofPatterns`, `injectedAtMs`, `conservedBalance`, untrusted `oracleEvents`, and any future
 * untrusted field) is stripped unconditionally before oracle evaluation.
 */
export const HOST_CUSTODY_RECEIPT_ALLOWLIST = Object.freeze([
  'vulnClass',
  'target',
  'exchangeIds',
  'oobEventIds',
  'browserTraceIds',
  'claimedDelta',
  'oracleEvents',
] as const)

export type HostCustodyAllowedReceiptKey = (typeof HOST_CUSTODY_RECEIPT_ALLOWLIST)[number]

/** Worker scalar fields explicitly excluded from `HostSanitizedReceipt` / `HostEvidence`. */
export const WORKER_STRIPPED_RECEIPT_SCALARS = Object.freeze([
  'requiredRole',
  'resourceTenant',
  'expectControlDenied',
  'proofPatterns',
  'injectedAtMs',
  'conservedBalance',
] as const)

export interface HostSanitizedTarget {
  readonly origin: WorkerSelected<string>
  readonly method?: WorkerSelected<string>
  readonly pathAndQuery?: WorkerSelected<string>
  readonly param?: WorkerSelected<string>
}

/**
 * Strict allowlist projection of a `ProofReceipt` carrying ZERO worker claim scalars.
 * Compile-time omits `requiredRole`, `resourceTenant`, `expectControlDenied`, `proofPatterns`,
 * `injectedAtMs`, and `conservedBalance`, and carries `oracleEvents` ONLY when injected by
 * host policy (`trustedOracleEvents`).
 */
export interface HostSanitizedReceipt {
  readonly vulnClass: WorkerSelected<string>
  readonly target: HostSanitizedTarget
  readonly exchangeIds: HostObserved<readonly string[]>
  readonly oobEventIds: WorkerSelected<readonly string[]>
  readonly browserTraceIds: WorkerSelected<readonly string[]>
  readonly claimedDelta: WorkerAsserted<string>
  readonly oracleEvents?: HostObserved<readonly string[]>
}

/**
 * Sealed host-custody view consumed by receipt/oracle evaluators.
 * Can ONLY be constructed through `constructHostEvidence` (runtime-checked via module-private
 * WeakSet seal — immune to `{ ...genuine, receipt: forged }` spread cloning — and compile-time
 * branded via `HOST_EVIDENCE_BRAND`).
 */
export interface HostEvidence {
  readonly [HOST_EVIDENCE_BRAND]: 'host_evidence'
  readonly receipt: HostSanitizedReceipt
  readonly entries: HostObserved<readonly ReceiptTranscriptEntry[]>
  readonly oobEvents: HostObserved<readonly ReceiptOobEvent[]>
  readonly browserTraces: HostObserved<readonly ReceiptBrowserTrace[]>
  readonly oobSigningKey?: HostMinted<string>
  readonly runId?: HostMinted<string>
}

/**
 * Strict allowlist sanitizer for single-hop `ProofReceipt` inputs (ZERO spread of untrusted keys).
 * Preserves only allowlisted routing/citation fields + host-ordered `exchangeIds` + explicitly
 * host-trusted `oracleEvents`. All worker scalars (`requiredRole`, `resourceTenant`,
 * `expectControlDenied`, `proofPatterns`, `injectedAtMs`, `conservedBalance`, worker
 * `oracleEvents`, and any unknown/future properties) are unconditionally dropped.
 */
const ALLOWED_RECEIPT_KEY_SET: ReadonlySet<string> = new Set(HOST_CUSTODY_RECEIPT_ALLOWLIST)
const STRIPPED_SCALAR_SET: ReadonlySet<string> = new Set(WORKER_STRIPPED_RECEIPT_SCALARS)

export function sanitizeReceiptByAllowlist(
  receipt: ProofReceipt,
  hostOrderedExchangeIds: readonly string[],
  trustedOracleEvents?: readonly string[],
): ProofReceipt {
  const cleanTarget: ProofReceipt['target'] = {
    origin: receipt.target.origin,
    ...(receipt.target.method !== undefined ? { method: receipt.target.method } : {}),
    ...(receipt.target.pathAndQuery !== undefined ? { pathAndQuery: receipt.target.pathAndQuery } : {}),
    ...(receipt.target.param !== undefined ? { param: receipt.target.param } : {}),
  }
  const cleanEvents = trustedOracleEvents && trustedOracleEvents.length > 0
    ? [...trustedOracleEvents]
    : undefined
  const out: ProofReceipt = {
    vulnClass: receipt.vulnClass,
    target: cleanTarget,
    exchangeIds: [...hostOrderedExchangeIds],
    oobEventIds: [...receipt.oobEventIds],
    browserTraceIds: [...receipt.browserTraceIds],
    claimedDelta: receipt.claimedDelta,
    ...(cleanEvents ? { oracleEvents: cleanEvents } : {}),
  }
  for (const key of Object.keys(out)) {
    if (!ALLOWED_RECEIPT_KEY_SET.has(key) || STRIPPED_SCALAR_SET.has(key)) {
      delete (out as unknown as Record<string, unknown>)[key]
    }
  }
  return out
}

export function buildHostSanitizedReceipt(
  receipt: ProofReceipt,
  hostOrderedExchangeIds: readonly string[],
  trustedOracleEvents?: readonly string[],
): HostSanitizedReceipt {
  const plain = sanitizeReceiptByAllowlist(receipt, hostOrderedExchangeIds, trustedOracleEvents)
  const target: HostSanitizedTarget = Object.freeze({
    origin: asWorkerSelected(plain.target.origin),
    ...(plain.target.method !== undefined ? { method: asWorkerSelected(plain.target.method) } : {}),
    ...(plain.target.pathAndQuery !== undefined ? { pathAndQuery: asWorkerSelected(plain.target.pathAndQuery) } : {}),
    ...(plain.target.param !== undefined ? { param: asWorkerSelected(plain.target.param) } : {}),
  })
  return Object.freeze({
    vulnClass: asWorkerSelected(plain.vulnClass),
    target,
    exchangeIds: asHostObserved(Object.freeze([...plain.exchangeIds])),
    oobEventIds: asWorkerSelected(Object.freeze([...plain.oobEventIds])),
    browserTraceIds: asWorkerSelected(Object.freeze([...plain.browserTraceIds])),
    claimedDelta: asWorkerAsserted(plain.claimedDelta),
    ...(plain.oracleEvents ? { oracleEvents: asHostObserved(Object.freeze([...plain.oracleEvents])) } : {}),
  })
}

export interface ConstructHostEvidenceInput {
  readonly receipt: ProofReceipt
  readonly transcript: ReceiptTranscript
  readonly hostOrderedExchangeIds?: readonly string[]
  readonly trustedOracleEvents?: readonly string[]
  readonly runId?: string
}

/**
 * Sole authorized host custody constructor for `HostEvidence`.
 * Applies the strict receipt allowlist, freezes host-observed transcript arrays, and registers the
 * frozen view in the module-private `SEALED_HOST_EVIDENCE` WeakSet (rejecting casts and spreads).
 */
export function constructHostEvidence(input: ConstructHostEvidenceInput): HostEvidence {
  const orderedIds = input.hostOrderedExchangeIds ?? input.receipt.exchangeIds
  const sanitized = buildHostSanitizedReceipt(input.receipt, orderedIds, input.trustedOracleEvents)
  const view = Object.freeze({
    receipt: sanitized,
    entries: asHostObserved(Object.freeze([...(input.transcript.entries ?? [])])),
    oobEvents: asHostObserved(Object.freeze([...(input.transcript.oobEvents ?? [])])),
    browserTraces: asHostObserved(Object.freeze([...(input.transcript.browserTraces ?? [])])),
    ...(input.transcript.oobSigningKey ? { oobSigningKey: asHostMinted(input.transcript.oobSigningKey) } : {}),
    ...(input.runId ? { runId: asHostMinted(input.runId) } : {}),
  })
  SEALED_HOST_EVIDENCE.add(view)
  return view as unknown as HostEvidence
}

/** Runtime verification that `value` is a genuine sealed `HostEvidence` (rejects casts and `{ ...genuine }` clones). */
export function isHostEvidence(value: unknown): value is HostEvidence {
  return Boolean(value && typeof value === 'object' && SEALED_HOST_EVIDENCE.has(value))
}

/** Strict host-owned secret-prefix patterns for disclosure verification (never generic handles, never worker `proofPatterns`). */
export const HOST_DISCLOSURE_SECRET_PATTERNS: readonly string[] = Object.freeze([
  '\\bsk_[a-zA-Z0-9]{2,12}_[0-9a-fA-F]{10,}\\b',
  '\\bpk_[a-zA-Z0-9]{2,12}_[0-9a-fA-F]{10,}\\b',
  '\\brk_[a-zA-Z0-9]{2,12}_[0-9a-fA-F]{10,}\\b',
  '\\brbs_[a-zA-Z0-9]{2,12}_[0-9a-fA-F]{10,}\\b',
  '\\bAKIA[0-9A-Z]{16}\\b',
])

const ADMIN_FUNCTION_SURFACE_RE = /\/(?:admin|manage|staff|internal|system|superuser|operator|roles?|permissions?|grants?|impersonat)\b/i
const HOST_ROLE_RANK: Readonly<Record<string, number>> = { viewer: 1, member: 2, admin: 3, owner: 4 }
const is2xxStep = (status: number | null): boolean => status !== null && status >= 200 && status < 300

/** Host-derived cross-tenant deletion target tenant from pre-2xx + post-404/410 control readbacks (zero worker scalars). */
export function deriveHostObservedDeletionTenant(steps: readonly ImpactStep[], mutatingProbe: ImpactStep | undefined): string | null {
  if (!mutatingProbe || mutatingProbe.method.toUpperCase() !== 'DELETE') return null
  const probeTenant = mutatingProbe.actor.tenant?.trim().toLowerCase() ?? null
  if (!probeTenant) return null
  const probeIdx = steps.indexOf(mutatingProbe)
  if (probeIdx < 0) return null
  const afterTombstone = steps.slice(probeIdx + 1).find(s => s.arm === 'control' && (s.status === 404 || s.status === 410) && s.actor.tenant && s.actor.tenant.trim().toLowerCase() !== probeTenant)
  const foreignTenant = afterTombstone?.actor.tenant?.trim().toLowerCase() ?? null
  if (!foreignTenant) return null
  const hasBefore = steps.slice(0, probeIdx).some(s => s.arm === 'control' && is2xxStep(s.status) && s.actor.tenant?.trim().toLowerCase() === foreignTenant)
  return hasBefore ? foreignTenant : null
}

/** True when an authenticated probe's JSON response body embeds its own actor's tenant marker (N3). */
export function stepHasOwnTenantMarker(step: ImpactStep): boolean {
  const pt = step.actor.tenant?.toLowerCase()
  if (!pt) return false
  const raw = step.json !== undefined ? JSON.stringify(step.json) : typeof step.body === 'string' ? step.body : ''
  return raw.toLowerCase().includes(`"${pt}"`)
}

/** Host-derived required role strictly from host-recorded transcript steps (zero worker `requiredRole` scalars). */
export function deriveHostObservedRequiredRole(
  steps: readonly ImpactStep[],
  impactClass: ImpactClass | undefined,
  mutatingProbe: ImpactStep | undefined,
  routeOfStep: (step: ImpactStep) => string,
): RoleName | null {
  if (mutatingProbe && mutatingProbe.method.toUpperCase() === 'DELETE' && ADMIN_FUNCTION_SURFACE_RE.test(mutatingProbe.route ?? mutatingProbe.pathAndQuery ?? '')) {
    const probeRank = HOST_ROLE_RANK[(mutatingProbe.actor.role ?? '').toLowerCase()] ?? 0
    const probeIdx = steps.indexOf(mutatingProbe)
    const hasPreRead = probeIdx > 0 && steps.slice(0, probeIdx).some(s => s.method.toUpperCase() === 'GET' && is2xxStep(s.status))
    const hasTombstone = probeIdx >= 0 && steps.slice(probeIdx + 1).some(s => s.method.toUpperCase() === 'GET' && (s.status === 404 || s.status === 410))
    if (probeRank > 0 && hasPreRead && hasTombstone) {
      let bestRole: RoleName | null = null
      let bestRank = probeRank
      for (const s of steps) {
        const r = (s.actor.role ?? '').toLowerCase()
        const rank = HOST_ROLE_RANK[r] ?? 0
        if (rank > bestRank) { bestRank = rank; bestRole = r as RoleName }
      }
      if (bestRole) return bestRole
    }
  }
  if (impactClass === 'disclosure' && !mutatingProbe) {
    const okProbes = steps.filter(s => s.arm === 'probe' && is2xxStep(s.status) && s.actor.handle !== null)
    const controls = steps.filter(s => s.arm === 'control')
    const secretRes = HOST_DISCLOSURE_SECRET_PATTERNS.map(p => new RegExp(p))
    const textOf = (s: ImpactStep) => typeof s.body === 'string' ? s.body : s.json !== undefined ? JSON.stringify(s.json) : ''
    for (const p of okProbes) {
      const pRank = HOST_ROLE_RANK[(p.actor.role ?? '').toLowerCase()] ?? 0
      if (pRank <= 0) continue
      const matched = secretRes.filter(re => re.test(textOf(p)))
      if (matched.length === 0) continue
      const pRoute = routeOfStep(p)
      const higherSameRouteCtrl = controls.find(c =>
        is2xxStep(c.status) && routeOfStep(c) === pRoute &&
        (HOST_ROLE_RANK[(c.actor.role ?? '').toLowerCase()] ?? 0) > pRank &&
        matched.every(re => !re.test(textOf(c))),
      )
      if (higherSameRouteCtrl?.actor.role) return higherSameRouteCtrl.actor.role.toLowerCase() as RoleName
    }
  }
  return null
}
