/**
 * Evidence Provenance & Host Custody Boundary (`R3-16`).
 *
 * Separates host-observed bytes, host-minted stamps/challenges, worker-selected pointers,
 * and worker-asserted prose at the TypeScript type level, and constructs the sealed
 * `HostEvidence` view via a strict allowlist so untrusted worker claim scalars
 * (`requiredRole`, `resourceTenant`, `expectControlDenied`, `proofPatterns`, `injectedAtMs`,
 * `conservedBalance`, `oracleEvents`) can never leak into oracle bodies.
 */
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

const HOST_EVIDENCE_SEAL = Symbol('kovo.HostEvidence.seal')

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
  readonly oobEventIds: HostObserved<readonly string[]>
  readonly browserTraceIds: HostObserved<readonly string[]>
  readonly claimedDelta: WorkerAsserted<string>
  readonly oracleEvents?: HostObserved<readonly string[]>
}

/**
 * Sealed host-custody view consumed by receipt/oracle evaluators.
 * Can ONLY be constructed through `constructHostEvidence` (runtime-checked via module-private
 * Symbol seal and compile-time branded via `HOST_EVIDENCE_BRAND`).
 */
export interface HostEvidence {
  readonly [HOST_EVIDENCE_BRAND]: 'host_evidence'
  readonly [HOST_EVIDENCE_SEAL]: true
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
    oobEventIds: asHostObserved(Object.freeze([...plain.oobEventIds])),
    browserTraceIds: asHostObserved(Object.freeze([...plain.browserTraceIds])),
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
 * Applies the strict receipt allowlist, freezes host-observed transcript arrays, and seals the
 * resulting view with the module-private `HOST_EVIDENCE_SEAL` symbol.
 */
export function constructHostEvidence(input: ConstructHostEvidenceInput): HostEvidence {
  const orderedIds = input.hostOrderedExchangeIds ?? input.receipt.exchangeIds
  const sanitized = buildHostSanitizedReceipt(input.receipt, orderedIds, input.trustedOracleEvents)
  const view = {
    [HOST_EVIDENCE_SEAL]: true as const,
    receipt: sanitized,
    entries: asHostObserved(Object.freeze([...(input.transcript.entries ?? [])])),
    oobEvents: asHostObserved(Object.freeze([...(input.transcript.oobEvents ?? [])])),
    browserTraces: asHostObserved(Object.freeze([...(input.transcript.browserTraces ?? [])])),
    ...(input.transcript.oobSigningKey ? { oobSigningKey: asHostMinted(input.transcript.oobSigningKey) } : {}),
    ...(input.runId ? { runId: asHostMinted(input.runId) } : {}),
  }
  return Object.freeze(view) as unknown as HostEvidence
}

/** Runtime verification that `value` was constructed by `constructHostEvidence` (rejects casts). */
export function isHostEvidence(value: unknown): value is HostEvidence {
  return Boolean(
    value &&
    typeof value === 'object' &&
    (value as Record<PropertyKey, unknown>)[HOST_EVIDENCE_SEAL] === true,
  )
}
