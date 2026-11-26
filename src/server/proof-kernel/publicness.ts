/**
 * Proof Kernel — Unified Budgeted Publicness (`must_be_non_public`) Stage (`R3-17`).
 *
 * Single concept-owned publicness oracle executed for EVERY confidentiality / authentication
 * boundary `OracleSpec` (`spec.publicnessPolicy === 'non_public_required'`):
 *   - `impact:authorization`
 *   - `impact:bfla`
 *   - `impact:disclosure`
 *   - `impact:signed_url_mint`
 *   - `auth_bypass`
 *   - `v8:dual_tenant_abac`
 *   - `v8:temporal_revocation`
 *   - `v8:cryptographic_scope_replay`
 *   - `v8:cross_surface_pivot`
 *
 * Also owns the bounded publicness replay policy (`PublicnessReplayBudgetLedger`) backed by
 * `src/server/run-safety-budgets.ts` with strict `prod_readonly` enforcement (zero mutating
 * or unauthorized probes; read-only GET/HEAD checks strictly bounded with truncation telemetry).
 */

import type { OracleSpec } from '../oracle-spec.ts'
import {
  RUN_SAFETY_BUDGET_DEFAULTS,
  RUN_SAFETY_BUDGET_ENV_KEYS,
  RUN_SAFETY_BUDGET_HARD_CEILINGS,
  resolveBoundedBudgetCap,
} from '../run-safety-budgets.ts'
import { flattenJson } from './reflection.ts'
import type { ActorIdentity, ImpactStep, RegisteredCanaryMarker } from '../oracle-invariants.ts'

export type PublicnessReplayEnvironmentMode = 'prod_readonly' | 'staging_isolated' | 'ephemeral_lab'

export interface PublicnessAssessment {
  public: boolean
  reason: string
  referenceId?: string
}

export interface PublicnessReplayTelemetry {
  readonly allowed: boolean
  readonly skippedReason:
    | 'budget_exhausted_run'
    | 'budget_exhausted_route'
    | 'prod_readonly_non_read_method'
    | 'non_read_method'
    | 'not_applicable'
    | null
  readonly truncated: boolean
  readonly runCount: number
  readonly runCap: number
  readonly routeCount: number
  readonly routeCap: number
  readonly environmentMode: PublicnessReplayEnvironmentMode
}

export interface PublicnessStageInput {
  readonly spec: OracleSpec
  readonly steps: readonly ImpactStep[]
  readonly probe?: ImpactStep | null
  readonly canaryMarkers?: ReadonlyArray<string | RegisteredCanaryMarker> | null
  /** Optional runtime canary matcher injected from `oracle-invariants.ts` to check global registered canaries. */
  readonly matchCanary?: (value: string, extra?: ReadonlyArray<string | RegisteredCanaryMarker> | null) => unknown
  /** Optional role differential flag (preserves existing role-differential exemption for BFLA). */
  readonly roleDifferential?: boolean
  /** Optional active replay budget ledger + environment mode for bounded GET/HEAD publicness checks. */
  readonly replayBudget?: PublicnessReplayBudgetLedger
  readonly runId?: string
  readonly environmentMode?: PublicnessReplayEnvironmentMode
}

export interface PublicnessStageResult {
  readonly required: boolean
  readonly executed: boolean
  readonly passed: boolean
  readonly public: boolean
  readonly specId: string
  readonly reason: string
  readonly referenceId?: string
  readonly replayTelemetry?: PublicnessReplayTelemetry
}

const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const SAFE_PUBLICNESS_REPLAY_METHODS = new Set(['GET', 'HEAD'])
const PRINCIPAL_IDENTITY_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:owner(?:_?id)?|tenant(?:_?id)?|user(?:_?id)?|email|username|created_?by)$/i
const ATTRIBUTION_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:author|subject)$/i
const EMAIL_VALUE_RE = /^[^\s@]{1,64}@[^\s@]{1,128}\.[a-z]{2,24}$/i

function isReadMethodLocal(method: string | null | undefined): boolean {
  return READ_METHODS.has((method ?? '').toUpperCase())
}

function isSuccessStatus(status: number | null | undefined): boolean {
  return typeof status === 'number' && status >= 200 && status < 300
}

function normRoute(step: Pick<ImpactStep, 'route' | 'pathAndQuery'>): string {
  const raw = step.route ?? step.pathAndQuery ?? ''
  return raw.split('?')[0]!.split('#')[0]!.replace(/\/+$/, '').toLowerCase()
}

function sameRouteSteps(a: ImpactStep, b: ImpactStep): boolean {
  const ar = normRoute(a)
  const br = normRoute(b)
  return ar !== '' && ar === br
}

function stepActorTenants(actor: Pick<ActorIdentity, 'tenant' | 'tenants'>): Set<string> {
  const out = new Set<string>()
  if (actor.tenant) out.add(actor.tenant.toLowerCase())
  for (const t of actor.tenants ?? []) if (t) out.add(t.toLowerCase())
  return out
}

function stepActorsShareTenant(a: Pick<ActorIdentity, 'tenant' | 'tenants'>, b: Pick<ActorIdentity, 'tenant' | 'tenants'>): boolean {
  const left = stepActorTenants(a)
  if (left.size === 0) return false
  const right = stepActorTenants(b)
  for (const t of left) if (right.has(t)) return true
  return false
}

function deRedactIdentityValue(value: string): string {
  return value.replace(/\[persona:([a-z0-9_.-]+):secret\]/gi, '$1').toLowerCase()
}

function matchesLocalCanary(value: string, extra?: ReadonlyArray<string | RegisteredCanaryMarker> | null): boolean {
  if (!value || !extra || extra.length === 0) return false
  for (const raw of extra) {
    const needle = typeof raw === 'string' ? raw.trim() : raw.value.trim()
    if (needle && value.includes(needle)) return true
  }
  return false
}

function isOwnerBoundIdentityLocal(
  leaf: string,
  value: string,
  reference: ImpactStep | null | undefined,
  canaryMarkers: ReadonlyArray<string | RegisteredCanaryMarker> | null | undefined,
  matchCanary?: (value: string, extra?: ReadonlyArray<string | RegisteredCanaryMarker> | null) => unknown,
): boolean {
  if (matchCanary ? matchCanary(value, canaryMarkers) !== null : matchesLocalCanary(value, canaryMarkers)) return true
  if (reference && reference.actor.handle === null) return false
  if (PRINCIPAL_IDENTITY_FIELD_RE.test(leaf)) return true
  if (ATTRIBUTION_FIELD_RE.test(leaf)) {
    const normalized = deRedactIdentityValue(value.trim())
    if (EMAIL_VALUE_RE.test(normalized)) return true
    if (reference) {
      const refHandle = reference.actor.handle?.toLowerCase() ?? null
      const refTenant = reference.actor.tenant?.toLowerCase() ?? null
      if ((refHandle !== null && normalized === refHandle) || (refTenant !== null && normalized === refTenant)) return true
    }
  }
  return false
}

function payloadKey(step: ImpactStep): string | null {
  if (step.json !== undefined && step.json !== null && typeof step.json === 'object') {
    const flat = flattenJson(step.json)
    if (flat.size === 0) return null
    return `json:${[...flat.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join('\u0000')}`
  }
  if (typeof step.body === 'string' && step.body.trim().length > 0) return `body:${step.body.trim()}`
  return null
}

function listingLeaves(steps: readonly ImpactStep[]): Set<string> {
  const leaves = new Set<string>()
  for (const step of steps) {
    if (!isReadMethodLocal(step.method) || !isSuccessStatus(step.status) || step.json === undefined) continue
    const flat = flattenJson(step.json)
    if (![...flat.keys()].some(path => path.includes('['))) continue
    for (const path of flat.keys()) {
      const leaf = (path.replace(/\[\d+\]/g, '').split('.').pop() ?? '').toLowerCase()
      if (leaf) leaves.add(leaf)
    }
  }
  return leaves
}

function hasPayload(step: ImpactStep): boolean {
  if (step.json !== undefined && step.json !== null) return true
  return typeof step.body === 'string' && step.body.trim().length > 0
}

function isAnonymousActor(actor: ActorIdentity): boolean {
  const handle = (actor.handle ?? '').trim().toLowerCase()
  const hasHandle = handle.length > 0 && !/^(?:anonymous|anon|unauthenticated|none|public)$/.test(handle)
  return !hasHandle && (actor.tenant ?? null) === null
}

/** True when an `OracleSpec` declares `publicnessPolicy: 'non_public_required'`. */
export function specRequiresNonPublic(spec: OracleSpec): boolean {
  return spec.publicnessPolicy === 'non_public_required'
}

/**
 * Core evidence-based publicness assessor (`assessPublicness`, moved from `oracle-invariants.ts` into `proof-kernel/publicness.ts`).
 * A surface readable without authentication, or one where a non-owner receives a payload identical
 * to the owner reference (without binding an owner-scoped identity or canary), is publicly readable.
 */
export function assessPublicness(args: {
  steps: readonly ImpactStep[]
  probe: ImpactStep
  canaryMarkers?: ReadonlyArray<string | RegisteredCanaryMarker> | null
  matchCanary?: (value: string, extra?: ReadonlyArray<string | RegisteredCanaryMarker> | null) => unknown
}): PublicnessAssessment {
  const { steps, probe, canaryMarkers, matchCanary } = args
  if (!isReadMethodLocal(probe.method) || !isSuccessStatus(probe.status)) return { public: false, reason: '' }
  const sameRouteReads = steps.filter(step =>
    step !== probe &&
    isReadMethodLocal(step.method) &&
    isSuccessStatus(step.status) &&
    sameRouteSteps(step, probe) &&
    step.json !== undefined &&
    step.json !== null)
  const anonymousRead = [probe, ...sameRouteReads].find(step =>
    isAnonymousActor(step.actor) && step.json !== undefined && step.json !== null)
  if (anonymousRead) {
    return {
      public: true,
      referenceId: anonymousRead.id,
      reason: `an unauthenticated caller was served a payload on the same route (${anonymousRead.id}), so the surface is publicly readable`,
    }
  }
  const probeKey = payloadKey(probe)
  if (!probeKey && probe.json === undefined) return { public: false, reason: '' }
  const references = sameRouteReads.filter(step =>
    step.arm === 'control' &&
    step.actor.handle !== probe.actor.handle &&
    (step.json !== undefined || typeof step.body === 'string') &&
    (step.pathAndQuery === undefined || probe.pathAndQuery === undefined || step.pathAndQuery === probe.pathAndQuery))
  if (references.length === 0) return { public: false, reason: '' }
  const controlFlats = sameRouteReads
    .filter(step => step.arm === 'control' && step.json !== undefined && step.json !== null && typeof step.json === 'object')
    .map(step => flattenJson(step.json))
  const listing = listingLeaves(steps)
  const probeFlat = probe.json !== undefined && probe.json !== null && typeof probe.json === 'object' ? flattenJson(probe.json) : null
  for (const reference of references) {
    if (stepActorsShareTenant(probe.actor, reference.actor)) continue
    if (stepActorTenants(probe.actor).size === 0 && stepActorTenants(reference.actor).size === 0) continue
    const same = payloadKey(reference) === probeKey
    let differingOnlyPublic = false
    if (!same) {
      if (!probeFlat) continue
      const referenceFlat = reference.json !== undefined && reference.json !== null && typeof reference.json === 'object'
        ? flattenJson(reference.json)
        : null
      if (!referenceFlat) continue
      const differing = new Set<string>()
      for (const [path, value] of probeFlat) if (referenceFlat.get(path) !== value) differing.add(path)
      for (const path of referenceFlat.keys()) if (!probeFlat.has(path)) differing.add(path)
      const leaves = [...differing].map(path => (path.replace(/\[\d+\]/g, '').split('.').pop() ?? '').toLowerCase())
      differingOnlyPublic = differing.size > 0 && leaves.every(leaf => listing.has(leaf)) && !leaves.some(leaf => PRINCIPAL_IDENTITY_FIELD_RE.test(leaf))
      if (!differingOnlyPublic) continue
    }
    const ownerBound = probeFlat
      ? [...probeFlat.entries()].some(([path, value]) => {
        if (!value || value === 'null') return false
        if (!controlFlats.some(flat => flat.get(path) === value)) return false
        const leaf = (path.replace(/\[\d+\]/g, '').split('.').pop() ?? '').toLowerCase()
        return isOwnerBoundIdentityLocal(leaf, value, reference, canaryMarkers, matchCanary)
      })
      : false
    if (ownerBound) continue
    return {
      public: true,
      referenceId: reference.id,
      reason: differingOnlyPublic
        ? `the ${probe.actor.tenant ? 'non-owner' : 'anonymous'} response matches the owner reference ${reference.id} on the same route except for fields the public listing already exposes, so the resource is publicly readable (publicness), not an access-control crossing`
        : `the ${probe.actor.tenant ? 'non-owner' : 'anonymous'} response is identical to the owner reference ${reference.id} on the same route, so the resource is publicly readable (publicness), not an access-control crossing`,
    }
  }
  return { public: false, reason: '' }
}

/**
 * Per-run, per-route finite budget ledger for active publicness replay probes (`R3-17`).
 * Enforces `run-safety-budgets.ts` caps (`maxPublicnessReplaysPerRun`, `maxPublicnessReplaysPerRoute`)
 * and strictly respects `prod_readonly` (zero mutating/non-read publicness probes; bounded GET/HEAD
 * probes with structured truncation telemetry).
 */
export class PublicnessReplayBudgetLedger {
  private readonly runCounts = new Map<string, number>()
  private readonly routeCounts = new Map<string, number>()
  private readonly env?: Readonly<Record<string, string | undefined>>
  private readonly maxPerRunOverride?: number
  private readonly maxPerRouteOverride?: number

  constructor(options: {
    maxPerRun?: number
    maxPerRoute?: number
    env?: Readonly<Record<string, string | undefined>>
  } = {}) {
    this.maxPerRunOverride = options.maxPerRun
    this.maxPerRouteOverride = options.maxPerRoute
    this.env = options.env
  }

  private resolveCaps(): { runCap: number; routeCap: number } {
    return {
      runCap: resolveBoundedBudgetCap(
        this.maxPerRunOverride,
        RUN_SAFETY_BUDGET_ENV_KEYS.maxPublicnessReplaysPerRun,
        RUN_SAFETY_BUDGET_DEFAULTS.maxPublicnessReplaysPerRun,
        RUN_SAFETY_BUDGET_HARD_CEILINGS.maxPublicnessReplaysPerRun,
        this.env,
      ),
      routeCap: resolveBoundedBudgetCap(
        this.maxPerRouteOverride,
        RUN_SAFETY_BUDGET_ENV_KEYS.maxPublicnessReplaysPerRoute,
        RUN_SAFETY_BUDGET_DEFAULTS.maxPublicnessReplaysPerRoute,
        RUN_SAFETY_BUDGET_HARD_CEILINGS.maxPublicnessReplaysPerRoute,
        this.env,
      ),
    }
  }

  /** Attempt to admit a single publicness replay request for `(runId, method, route, environmentMode)`. */
  admit(input: {
    runId: string
    method: string
    route: string
    environmentMode?: PublicnessReplayEnvironmentMode
  }): PublicnessReplayTelemetry {
    const environmentMode: PublicnessReplayEnvironmentMode = input.environmentMode ?? 'prod_readonly'
    const { runCap, routeCap } = this.resolveCaps()
    const runKey = input.runId.trim() || 'default'
    const routeKey = `${runKey}::${input.route.split('?')[0]!.replace(/\/+$/, '').toLowerCase() || '/'}`
    const runCount = this.runCounts.get(runKey) ?? 0
    const routeCount = this.routeCounts.get(routeKey) ?? 0
    const upperMethod = input.method.trim().toUpperCase()

    if (!SAFE_PUBLICNESS_REPLAY_METHODS.has(upperMethod)) {
      return {
        allowed: false,
        skippedReason: environmentMode === 'prod_readonly' ? 'prod_readonly_non_read_method' : 'non_read_method',
        truncated: false,
        runCount,
        runCap,
        routeCount,
        routeCap,
        environmentMode,
      }
    }
    if (runCount >= runCap) {
      return {
        allowed: false,
        skippedReason: 'budget_exhausted_run',
        truncated: true,
        runCount,
        runCap,
        routeCount,
        routeCap,
        environmentMode,
      }
    }
    if (routeCount >= routeCap) {
      return {
        allowed: false,
        skippedReason: 'budget_exhausted_route',
        truncated: true,
        runCount,
        runCap,
        routeCount,
        routeCap,
        environmentMode,
      }
    }
    this.runCounts.set(runKey, runCount + 1)
    this.routeCounts.set(routeKey, routeCount + 1)
    return {
      allowed: true,
      skippedReason: null,
      truncated: false,
      runCount: runCount + 1,
      runCap,
      routeCount: routeCount + 1,
      routeCap,
      environmentMode,
    }
  }

  getRunUsage(runId: string): number {
    return this.runCounts.get(runId.trim() || 'default') ?? 0
  }

  delete(runId?: string): void {
    if (runId === undefined) {
      this.runCounts.clear()
      this.routeCounts.clear()
      return
    }
    const key = runId.trim() || 'default'
    this.runCounts.delete(key)
    for (const rk of [...this.routeCounts.keys()]) {
      if (rk.startsWith(`${key}::`)) this.routeCounts.delete(rk)
    }
  }
}

const AUTH_OR_BYPASS_HEADER_RE = /^(?:authorization|proxy-authorization|cookie|x-api-key|api-key|x-auth(?:[-_][a-z0-9-]+)?|x-access-token|x-token|x-session(?:[-_][a-z0-9-]+)?|x-user(?:[-_][a-z0-9-]+)?|x-forwarded-(?:user|for|host|proto)|x-original-url|x-rewrite-url|x-real-ip|x-admin|x-role|x-roles|x-impersonate|x-internal(?:[-_][a-z0-9-]+)?|x-bypass(?:[-_][a-z0-9-]+)?|x-custom-ip-authorization|x-remote-user|x-signature|x-hub-signature(?:[-_][a-z0-9-]+)?)$/i
const SIGNED_OR_BYPASS_QUERY_RE = /[?&](?:sig|signature|hmac|mac|token|jwt|auth|access_token|id_token|api_key|apikey|x-amz-signature|x-goog-signature|bypass|impersonate|as_user)=/i

function stepCarriesAuthOrSignatureArtifact(step: ImpactStep): boolean {
  if (!isAnonymousActor(step.actor)) return true
  if (['cookie', 'bearer', 'header'].includes(step.actor.auth)) return true
  for (const [k, v] of Object.entries(step.requestHeaders ?? {})) {
    if (AUTH_OR_BYPASS_HEADER_RE.test(k.trim()) && v.trim().length > 0) return true
  }
  if (step.pathAndQuery && SIGNED_OR_BYPASS_QUERY_RE.test(step.pathAndQuery)) return true
  return false
}

function hasAnonymousSameRoutePublicAccess(
  spec: OracleSpec,
  steps: readonly ImpactStep[],
  probe: ImpactStep,
): { public: boolean; referenceId?: string; reason: string } {
  const probeRoute = normRoute(probe)
  if (!probeRoute || !isSuccessStatus(probe.status)) return { public: false, reason: '' }
  const probeKey = payloadKey(probe)
  const isV8OrSignedOrDisclosure =
    spec.kind === 'v8_family' ||
    spec.id === 'impact:signed_url_mint' ||
    spec.id === 'impact:disclosure' ||
    spec.id === 'auth_bypass'
  if (!isV8OrSignedOrDisclosure) return { public: false, reason: '' }

  for (const step of steps) {
    if (step === probe || step.id === probe.id) continue
    if (!isSuccessStatus(step.status)) continue
    if (normRoute(step) !== probeRoute) continue
    if (stepCarriesAuthOrSignatureArtifact(step)) continue
    if (!hasPayload(step)) continue
    const sameVerb = step.method.toUpperCase() === probe.method.toUpperCase()
    const readAccess = isReadMethodLocal(step.method)
    if (!sameVerb && !readAccess) continue
    const anonKey = payloadKey(step)
    const bodyMatches = Boolean(probeKey && anonKey && probeKey === anonKey)
    if (readAccess || bodyMatches) {
      return {
        public: true,
        referenceId: step.id,
        reason: `${spec.id} dismissed (publicness): bare unauthenticated exchange ${step.id} succeeded with ${step.status} on ${probeRoute}, proving the surface is publicly accessible.`,
      }
    }
  }
  return { public: false, reason: '' }
}

/**
 * Single `must_be_non_public` kernel stage (`R3-17`).
 * Executes for EVERY boundary spec declaring `publicnessPolicy: 'non_public_required'`
 * (`authorization`, `bfla`, `disclosure`, `signed_url_mint`, `auth_bypass`, `v8:dual_tenant_abac`,
 * `v8:temporal_revocation`, `v8:cryptographic_scope_replay`, `v8:cross_surface_pivot`).
 */
export function evaluateMustBeNonPublicStage(input: PublicnessStageInput): PublicnessStageResult {
  if (!specRequiresNonPublic(input.spec)) {
    return {
      required: false,
      executed: true,
      passed: true,
      public: false,
      specId: input.spec.id,
      reason: 'Spec does not require non-publicness.',
    }
  }

  const probe = input.probe ?? input.steps.find(s => s.arm === 'probe' && isSuccessStatus(s.status)) ?? null
  let replayTelemetry: PublicnessReplayTelemetry | undefined
  if (input.replayBudget && probe) {
    replayTelemetry = input.replayBudget.admit({
      runId: input.runId ?? 'default',
      method: probe.method,
      route: probe.route ?? probe.pathAndQuery ?? '/',
      environmentMode: input.environmentMode ?? 'prod_readonly',
    })
  }

  if (!probe) {
    return {
      required: true,
      executed: true,
      passed: true,
      public: false,
      specId: input.spec.id,
      reason: 'No 2xx probe step available for recorded publicness check.',
      ...(replayTelemetry ? { replayTelemetry } : {}),
    }
  }

  if (!input.roleDifferential) {
    // Specs whose probe legitimately runs without a vault persona handle (forged bypass header,
    // replayed cryptographic token/signature, or unauthenticated signed-URL mint) check sibling
    // bare-anonymous exchanges rather than flagging the bypassing probe itself as anonymous.
    const probeMayBeUnauthenticatedBypass =
      input.spec.id === 'auth_bypass' ||
      input.spec.id === 'v8:cryptographic_scope_replay' ||
      input.spec.id === 'impact:signed_url_mint'
    if (!probeMayBeUnauthenticatedBypass) {
      const core = assessPublicness({
        steps: input.steps,
        probe,
        canaryMarkers: input.canaryMarkers,
        matchCanary: input.matchCanary,
      })
      if (core.public) {
        return {
          required: true,
          executed: true,
          passed: false,
          public: true,
          specId: input.spec.id,
          reason: `${input.spec.id} dismissed (publicness): ${core.reason}.`,
          ...(core.referenceId ? { referenceId: core.referenceId } : {}),
          ...(replayTelemetry ? { replayTelemetry } : {}),
        }
      }
    }
    const boundaryAnon = hasAnonymousSameRoutePublicAccess(input.spec, input.steps, probe)
    if (boundaryAnon.public) {
      return {
        required: true,
        executed: true,
        passed: false,
        public: true,
        specId: input.spec.id,
        reason: boundaryAnon.reason,
        ...(boundaryAnon.referenceId ? { referenceId: boundaryAnon.referenceId } : {}),
        ...(replayTelemetry ? { replayTelemetry } : {}),
      }
    }
  }

  return {
    required: true,
    executed: true,
    passed: true,
    public: false,
    specId: input.spec.id,
    reason: 'Non-publicness stage passed.',
    ...(replayTelemetry ? { replayTelemetry } : {}),
  }
}
