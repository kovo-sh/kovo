#!/usr/bin/env node
/**
 * Kovo v6 Phase-1 certification runner.
 *
 * Turns the reviewer's Phase-1 matrix (ROADMAP check-in #4) into one reproducible
 * certificate. It does not grade anything itself: every number comes from the real
 * `scripts/benchmark-realistic.ts` / `scripts/benchmark-reason.ts` artifacts. The runner
 * either
 *
 *   --run       spawns the matrix (floor n=3/app dev + n=1/app held-out, unified agentic
 *               n=3/app dev + n=2-3/app held-out, reason-bench floor + agentic) with one
 *               isolated out-dir per cell, or
 *   --from-dir  ingests existing report JSONs (cheap reruns, no model spend).
 *
 * Metric definitions (ROADMAP check-in #3/#4):
 *   floor_recall            median [min-max] of `--no-llm` recall per app (seed 1 dev).
 *   floor spread            max-min confirmed targets across the floor dev runs (<= 1).
 *   total_product_recall    median [min-max] per-run total recall after deduping floor∩agent
 *                           targets by (origin, normalizedRoute, vulnClass, mutatedInput) when
 *                           the report exposes route/mutation; otherwise by site id. The union
 *                           across independent runs is reported separately as coverage.
 *   agentic_incremental_lift= provenance-derived: median per-run (agent_only + chain_from_floor) /
 *                           targets. If any unified report omits provenance the metric is
 *                           "unmeasured" and the completeness criterion fails (never inferred).
 *   floor_preservation_ratio= floorConfirmedInUnified / floorStandalone (median). The unified
 *                           floor count comes from the run's `deterministic_lane.metrics`
 *                           event / meta summary; the standalone baseline is the floor median.
 *   precision               worst-run confirmed precision across every realism cell (must be
 *                           100%). Only `verificationStatus === 'confirmed'` findings are TP;
 *                           static_only/open_proof_gap items are advisories, and a static-only
 *                           item inside confirmed findings is a contract leak counted as FP.
 *   leads invariant         floorLeadsEmitted > 0 => floorLeadsConsumed > 0.
 *   reason-bench            floor 0/28 is mandatory Phase 1. The agentic >=25% baseline is
 *                           Phase 3 and is reported informationally (non-blocking).
 *
 * Verdicts: PASS only when every criterion passes its stated threshold. Artifacts:
 * `certificate.json` (machine readable) + `certificate.md` (summary). Exit 1 on FAIL.
 *
 * Safety: the salted held-out salt is read only from KOVO_RB_HELDOUT_SALT, is never
 * written to any artifact, and every rendered artifact is scanned/redacted before disk.
 * Each cell gets its own out-dir/data-dir; SIGINT/SIGTERM kills the whole child process
 * group and removes per-cell data dirs (0 orphans).
 *
 * Usage:
 *   KOVO_ALLOW_LOCAL_LAB=1 npm run certify:phase1 -- --run \
 *     --data-dir "$HOME/guardian-data" --verifier docker --use-newgrp
 *   npm run certify:phase1 -- --from-dir /tmp/v6-floor-post --from-dir /tmp/preserve
 */
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import {
  chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs'
import { basename, dirname, join, relative, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { pathToFileURL } from 'node:url'
import { VERIFY_RPC_SDK_VERSION } from '../src/server/verify-rpc.ts'
import { MAX_RUN_WORKER_CONCURRENCY } from './benchmark-env.ts'
import {
  CERTIFYING_MIN_HELDOUT_SEEDS,
  DEFAULT_LEDGER_PATH,
  appendLedgerRow,
  appendPerRunLedgerRow,
  assertNoBurnedSeeds,
  computeBenchmarkVersion,
  computeEffectiveConfig,
  drawUnburnedHeldoutSeeds,
  drawUnburnedHeldoutSeedsWithMeta,
  loadBurnedSeeds,
  promoteLedgerRows,
  recordExposedHeldoutSeeds,
  resolveGitState,
  type EffectiveConfigSnapshot,
  type LedgerRow,
} from './bench-ledger.ts'
import {
  ScorecardReader,
  buildLedgerRow,
  ratioOrNull,
  type CellReadState,
} from './score-primitives.ts'

// ---------------------------------------------------------------------------------------------
// Constants and contract types
// ---------------------------------------------------------------------------------------------

export const CERTIFY_APPS = ['acme-saas', 'shopflow', 'opsportal'] as const
export const REASON_APPS = ['ledgerflow', 'forgecloud'] as const
export const DEV_SEED = 1
/** Legacy burned seed (demoted to dev-2 only in BURNED_SEEDS; refused for certification). */
export const HELDOUT_SEED = 1_000_042
export const DEFAULT_CERTIFY_HELDOUT_SEED_COUNT = CERTIFYING_MIN_HELDOUT_SEEDS
export const REASON_TARGETS = 28

export const DEFAULT_THRESHOLDS = {
  /** Floor runs are deterministic: max-min confirmed targets per app must be <= this. */
  floorSpreadMax: 1,
  /** Median floorConfirmedInUnified / floorStandalone across unified runs. */
  preservationMin: 0.95,
  /** Every realism cell must be perfectly precise (no decoy or unmatched FP). */
  worstPrecision: 1,
  /** Aggregate incremental lift over the standalone floor. */
  liftDevMin: 0.10,
  liftHeldoutMin: 0.08,
  /** Unified total must not sit below the floor on any app (both splits). */
  requireMonotonic: true,
  /** Reason-bench anti-heuristic floor must stay at 0 confirmed out of 28. */
  reasonFloorConfirmed: 0,
  reasonTargets: REASON_TARGETS,
  /** Reason-bench agentic recall at worst-run 100% precision. */
  reasonAgenticMin: 0.25,
} as const

export type Thresholds = typeof DEFAULT_THRESHOLDS

export type SeedSet = 'dev' | 'held-out'
export type LlmMode = 'agentic' | 'deterministic-no-llm'

export interface VulnLike {
  siteId: string
  vulnClass?: string
  outcome?: string
  origin?: string
  route?: string
  normalizedRoute?: string
  endpoint?: string
  mutatedInput?: unknown
  mutated?: unknown
  verificationStatus?: string
  verificationTier?: string
  provenance?: unknown
  findingStatus?: string
  matchedFindingIds?: string[]
}

export interface ScorecardLike {
  app: string
  seed: number
  seedSet?: string
  mode?: string
  status?: 'VALID' | 'INVALID'
  failed?: boolean
  inert?: boolean
  targets: number
  confirmed: number
  recall?: number | null
  precision?: number | null
  rawPrecision?: number | null
  decoys?: number
  decoyFalsePositives?: number
  unmatchedFalsePositives?: number
  /** Conservative precision that also charges uncharged misclassifications (Phase-1 gate). */
  strictPrecision?: number | null
  /** Class-incompatible claims on planted target endpoints (Phase-1 requires 0). */
  incompatibleClassCount?: number
  misclassifiedFindingIds?: string[]
  vulns?: VulnLike[]
  findings?: unknown[]
  advisories?: unknown[]
  advisoryFindings?: unknown[]
  provenance?: unknown
  provenanceCounts?: unknown
  llm?: string
  benchmarkVersion?: string | null
  effectiveConfigHash?: string | null
  effectiveConfig?: EffectiveConfigSnapshot | null
  reportable?: boolean
  wordlistOn?: boolean
  workerImageId?: string | null
  sdkVersion?: string | null
}

export type FindingProvenance = 'floor' | 'agent_only' | 'chain_from_floor'

export interface ProvenanceCounts {
  floor: number
  agentOnly: number
  chainFromFloor: number
}

/** One submitted finding parsed from a report/DB; advisory items never enter recall. */
export interface FindingRecord {
  id: string
  submittedStatus: string | null
  verificationStatus: string | null
  verificationTier: string | null
  provenance: FindingProvenance | null
  identity: string
  submittedConfirmed: boolean
  verifiedConfirmed: boolean
  advisory: boolean
  contractLeak: boolean
}

export interface FloorMetrics {
  floorConfirmed: number | null
  /**
   * Leads that reached a verdict (investigated). Queue-time counts live in
   * `floorLeadsQueued`; this field no longer means "queued".
   */
  floorLeadsConsumed: number | null
  floorLeadsEmitted: number | null
  /** Leads queued as upgrade steps (the old `floorLeadsConsumed` meaning). */
  floorLeadsQueued: number | null
  /** Leads whose upgrade assignment completed (verdict). */
  floorLeadsInvestigated: number | null
  source: string
}

export interface RealismRun {
  id: string
  dir: string
  file: string | null
  app: string
  seed: number
  seedSet: SeedSet
  mode: string
  llm: LlmMode
  targets: number
  confirmed: number
  recall: number
  precision: number | null
  rawPrecision?: number | null
  /** 3-state ScorecardReader classification (`ok_with_claims` | `ok_no_claims` | `failed_inert`). */
  cellState?: CellReadState
  failed?: boolean
  inert?: boolean
  /** Harness cell concurrency (parallel app/seed cells; scheduling only). */
  cellConcurrency: number | null
  /** In-run investigation worker slots handed to Execution for this cell. */
  workerConcurrency: number | null
  strictPrecision: number | null
  /** null = the artifact predates the class-hygiene field (gate treats it as unmeasured). */
  incompatibleClassCount: number | null
  misclassifiedFindingIds: string[]
  decoyFalsePositives: number
  unmatchedFalsePositives: number
  confirmedKeys: string[]
  floor: FloorMetrics
  provenance: ProvenanceCounts | null
  provenanceComplete: boolean
  provenanceSource: string
  advisories: number
  contractLeaks: number
  notes: string[]
  benchmarkVersion?: string | null
  effectiveConfigHash?: string | null
  effectiveConfig?: EffectiveConfigSnapshot | null
  reportable?: boolean
  wordlistOn?: boolean
  workerImageId?: string | null
  sdkVersion?: string | null
}

export interface ReasonSiteLike {
  siteId: string
  confirmed: boolean
}

export interface ReasonCellLike {
  app: string
  seed: number
  mode: string
  llm: LlmMode
  targets: number
  confirmed: number
  recall: number | null
  precision: number | null
  rawPrecision?: number | null
  cellState?: CellReadState
  failed?: boolean
  inert?: boolean
  decoyFalsePositives: number
  unmatchedFalsePositives: number
  sites: ReasonSiteLike[]
}

export interface ReasonRun {
  source: string
  cells: ReasonCellLike[]
}

export interface IngestResult {
  runs: RealismRun[]
  reason: ReasonRun[]
  notes: string[]
  filesScanned: number
}

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function asString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null
}

function asFiniteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function ratio(numerator: number, denominator: number): number {
  return denominator > 0 ? numerator / denominator : 0
}

export function median(values: number[]): number | null {
  if (!values.length) return null
  const sorted = [...values].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2
}

function sum(values: number[]): number {
  return values.reduce((n, v) => n + v, 0)
}

function pct(value: number | null | undefined): string {
  return value === null || value === undefined || !Number.isFinite(value) ? 'n/a' : `${(value * 100).toFixed(1)}%`
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)]
}

function seedSetOf(raw: unknown, seed: number): SeedSet {
  if (raw === 'held-out' || raw === 'heldout' || raw === 'heldOut') return 'held-out'
  if (raw === 'dev') return 'dev'
  return seed >= 1_000_000 ? 'held-out' : 'dev'
}

function llmOf(raw: unknown): LlmMode | null {
  if (raw === 'agentic') return 'agentic'
  if (raw === 'deterministic-no-llm' || raw === 'deterministic' || raw === 'no-llm') return 'deterministic-no-llm'
  return null
}

export function cellSlug(app: string, seed: number, mode: string): string {
  return `${app}-seed${seed}-${mode}`
}

// ---------------------------------------------------------------------------------------------
// Target identity (dedupe)
// ---------------------------------------------------------------------------------------------

export function normalizeOrigin(raw: string): string {
  const text = raw.trim()
  try {
    const url = new URL(text)
    return `${url.protocol.toLowerCase()}//${url.host.toLowerCase()}`
  } catch {
    return text.toLowerCase().replace(/\/+$/, '')
  }
}

/** Path-only normalizer: strips query/fragment, collapses separators, anonymous ids -> :id. */
export function normalizeRoute(raw: string): string {
  let pathname = raw.trim()
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(pathname)) {
    try {
      pathname = new URL(pathname).pathname || '/'
    } catch {
      // Keep the raw value; it is still a stable identity.
    }
  }
  const q = pathname.indexOf('?')
  if (q >= 0) pathname = pathname.slice(0, q)
  const h = pathname.indexOf('#')
  if (h >= 0) pathname = pathname.slice(0, h)
  if (!pathname.startsWith('/')) pathname = `/${pathname}`
  pathname = pathname.replace(/\/{2,}/g, '/')
  if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1)
  pathname = pathname
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi, '/:id')
    .replace(/\/\d+(?=\/|$)/g, '/:id')
  return pathname.toLowerCase()
}

export function normalizeMutatedInput(raw: unknown): string {
  if (raw === null || raw === undefined) return ''
  if (typeof raw === 'string') return raw.trim().toLowerCase()
  if (!isRecord(raw)) return ''
  const kind = typeof raw.kind === 'string' ? raw.kind.toLowerCase() : ''
  const name = typeof raw.name === 'string' ? raw.name : (typeof raw.param === 'string' ? raw.param : '')
  if (!kind && !name) return ''
  return `${kind}:${name.toLowerCase()}`.replace(/^:+/, '')
}

/**
 * Dedupe key for one confirmed site. Uses the four-part product identity when the report
 * exposes it; otherwise falls back to the benchmark site id (all current scorecards).
 */
export function targetKey(vuln: VulnLike, app: string): string {
  const origin = asString(vuln.origin)
  const route = asString(vuln.normalizedRoute) ?? asString(vuln.route) ?? asString(vuln.endpoint)
  const mutated = normalizeMutatedInput(vuln.mutatedInput ?? vuln.mutated)
  if (origin && route) {
    return `${normalizeOrigin(origin)}|${normalizeRoute(route)}|${(vuln.vulnClass ?? '').toLowerCase()}|${mutated || '-'}`
  }
  return `site:${app}|${vuln.siteId}`
}

export function confirmedTargetKeys(vulns: VulnLike[], app: string): string[] {
  const keys = new Set<string>()
  for (const vuln of vulns) {
    if (vuln.outcome !== 'confirmed') continue
    keys.add(targetKey(vuln, app))
  }
  return [...keys]
}

// ---------------------------------------------------------------------------------------------
// Finding provenance / confirmed-vs-advisory contract
// ---------------------------------------------------------------------------------------------

const CONFIRMED_STATUSES = new Set(['confirmed', 'runtime_confirmed'])
/** Anything the engine has not runtime-confirmed lives in advisories, never recall/precision TP. */
const ADVISORY_STATUSES = new Set(['static_verified', 'static_only', 'open_proof_gap', 'proposed', 'ruled_out'])
export const ADVISORY_NOISE_CAP_PER_APP = 10

export function normalizeProvenance(raw: unknown): FindingProvenance | null {
  if (typeof raw !== 'string') return null
  const value = raw.trim().toLowerCase().replace(/[\s-]+/g, '_')
  if (value === 'floor') return 'floor'
  if (value === 'agent_only' || value === 'agentonly') return 'agent_only'
  if (value === 'chain_from_floor' || value === 'chainfromfloor') return 'chain_from_floor'
  return null
}

function statusOf(raw: unknown): string | null {
  return typeof raw === 'string' && raw.trim() ? raw.trim().toLowerCase() : null
}

function numberField(source: Record<string, unknown>, keys: string[]): number | null {
  for (const key of keys) {
    const value = source[key]
    if (typeof value === 'number' && Number.isFinite(value)) return value
  }
  return null
}

/** Report/DB provenance summary: `{ floor, agent_only, chain_from_floor }` (counts). */
export function readProvenanceCounts(source: unknown): ProvenanceCounts | null {
  if (!isRecord(source)) return null
  const floor = numberField(source, ['floor', 'floorConfirmed', 'floor_confirmed'])
  const agentOnly = numberField(source, ['agentOnly', 'agent_only', 'agenticOnly', 'agentic_only'])
  const chainFromFloor = numberField(source, ['chainFromFloor', 'chain_from_floor', 'chain'])
  if (floor === null && agentOnly === null && chainFromFloor === null) return null
  return { floor: floor ?? 0, agentOnly: agentOnly ?? 0, chainFromFloor: chainFromFloor ?? 0 }
}

function findingIdentity(raw: Record<string, unknown>, fallback: string): string {
  const site = asString(raw.targetSiteId) ?? asString(raw.target_site_id) ?? asString(raw.siteId)
  if (site) return `site:${site}`
  const origin = asString(raw.origin)
  const route = asString(raw.normalizedRoute) ?? asString(raw.route) ?? asString(raw.endpoint)
  if (origin && route) {
    return targetKey({
      siteId: fallback,
      origin,
      route,
      ...(asString(raw.normalizedRoute) ? { normalizedRoute: asString(raw.normalizedRoute)! } : {}),
      vulnClass: asString(raw.vulnClass) ?? asString(raw.cwe) ?? undefined,
      ...(raw.mutatedInput !== undefined ? { mutatedInput: raw.mutatedInput } : {}),
    }, '')
  }
  return `finding:${fallback}`
}

/**
 * Parse one submitted finding. `verificationStatus` (or the legacy status/tier pair) decides
 * whether it is runtime-confirmed; static-only/open-proof-gap items never become TP.
 */
export function parseFindingRecord(raw: Record<string, unknown>, options: { forceAdvisory?: boolean; fallbackId?: string } = {}): FindingRecord {
  const id = asString(raw.id) ?? asString(raw.findingId) ?? options.fallbackId ?? 'unknown'
  const submittedStatus = statusOf(raw.status ?? raw.findingStatus ?? raw.submittedStatus)
  const verificationStatus = statusOf(raw.verificationStatus ?? raw.verification_status)
  const verificationTier = statusOf(raw.verificationTier ?? raw.verification_tier)
  const provenance = normalizeProvenance(raw.provenance ?? raw.findingProvenance ?? raw.finding_provenance)
  const advisory = options.forceAdvisory === true
    || (verificationStatus !== null && ADVISORY_STATUSES.has(verificationStatus))
    || (verificationTier !== null && ADVISORY_STATUSES.has(verificationTier))
    || (submittedStatus !== null && ADVISORY_STATUSES.has(submittedStatus))
  const submittedConfirmed = submittedStatus !== null && CONFIRMED_STATUSES.has(submittedStatus)
  const verifiedConfirmed = !advisory
    && (CONFIRMED_STATUSES.has(verificationStatus ?? '')
      || (verificationStatus === null && CONFIRMED_STATUSES.has(verificationTier ?? ''))
      || (verificationStatus === null && verificationTier === null && submittedConfirmed))
  return {
    id,
    submittedStatus,
    verificationStatus,
    verificationTier,
    provenance,
    identity: findingIdentity(raw, id),
    submittedConfirmed,
    verifiedConfirmed,
    advisory,
    contractLeak: submittedConfirmed && advisory,
  }
}

function recordArray(source: unknown): Record<string, unknown>[] {
  if (!Array.isArray(source)) return []
  return source.filter(isRecord)
}

export interface RunEvidence {
  provenance: ProvenanceCounts | null
  provenanceComplete: boolean
  provenanceSource: string
  advisories: number
  contractLeaks: number
  precision: number | null
  rawPrecision: number | null
  strictPrecision: number | null
  cellState: CellReadState
  registeredFindings: number
}

/**
 * Merge the run's finding-level contract into provenance counts, advisory noise and
 * confirmed precision. No inference: a missing provenance field leaves the metric unmeasured.
 */
export function buildRunEvidence(
  card: ScorecardLike,
  meta: Record<string, unknown> | null,
  dbFindings: FindingRecord[],
): RunEvidence {
  const records = new Map<string, FindingRecord>()
  const add = (record: FindingRecord): void => {
    if (!records.has(record.identity)) records.set(record.identity, record)
  }

  let source = 'none'
  const reportFindings = recordArray(card.findings)
  const metaFindings = recordArray(meta?.findings)
  if (reportFindings.length) {
    source = 'report-findings'
    reportFindings.forEach((raw, index) => add(parseFindingRecord(raw, { fallbackId: `${card.app}-f${index}` })))
  } else if (metaFindings.length) {
    source = 'meta-findings'
    metaFindings.forEach((raw, index) => add(parseFindingRecord(raw, { fallbackId: `${card.app}-f${index}` })))
  } else if (dbFindings.length) {
    source = 'events-db'
    dbFindings.forEach(record => add(record))
  }

  // Advisory arrays are explicit; never let their entries masquerade as TP.
  for (const [index, raw] of [...recordArray(card.advisories), ...recordArray(card.advisoryFindings), ...recordArray(meta?.advisories)].entries()) {
    add(parseFindingRecord(raw, { forceAdvisory: true, fallbackId: `${card.app}-advisory-${index}` }))
  }

  // Enriched scorecard site rows can carry the same contract fields.
  const vulns = Array.isArray(card.vulns) ? card.vulns.filter(isRecord) as unknown as VulnLike[] : []
  vulns.forEach((vuln, index) => {
    const enriched = vuln.verificationStatus !== undefined || vuln.verificationTier !== undefined
      || vuln.provenance !== undefined || vuln.findingStatus !== undefined || vuln.outcome === 'static_only'
    if (!enriched) return
    const submitted = vuln.findingStatus ?? (vuln.outcome === 'confirmed' ? 'confirmed' : vuln.outcome)
    add(parseFindingRecord({
      ...vuln,
      status: submitted,
      ...(vuln.verificationStatus !== undefined ? { verificationStatus: vuln.verificationStatus } : {}),
      ...(vuln.verificationTier !== undefined ? { verificationTier: vuln.verificationTier } : {}),
      ...(vuln.provenance !== undefined ? { provenance: vuln.provenance } : {}),
    }, { forceAdvisory: vuln.outcome === 'static_only', fallbackId: `${card.app}-vuln-${index}` }))
  })

  const allRecords = [...records.values()]
  const verified = allRecords.filter(record => record.verifiedConfirmed && !record.contractLeak)
  const verifiedIdentities = new Map<string, FindingProvenance | null>()
  for (const record of verified) if (!verifiedIdentities.has(record.identity)) verifiedIdentities.set(record.identity, record.provenance)
  const derived: ProvenanceCounts = { floor: 0, agentOnly: 0, chainFromFloor: 0 }
  let missingProvenance = 0
  for (const provenance of verifiedIdentities.values()) {
    if (provenance === 'floor') derived.floor += 1
    else if (provenance === 'agent_only') derived.agentOnly += 1
    else if (provenance === 'chain_from_floor') derived.chainFromFloor += 1
    else missingProvenance += 1
  }

  const explicit = readProvenanceCounts(card.provenance)
    ?? readProvenanceCounts(card.provenanceCounts)
    ?? readProvenanceCounts(meta?.provenance)
    ?? readProvenanceCounts(meta?.provenanceCounts)
  let provenance: ProvenanceCounts | null = null
  let provenanceComplete = false
  const explicitComplete = explicit !== null
    && explicit.floor + explicit.agentOnly + explicit.chainFromFloor >= card.confirmed
  if (explicit && explicitComplete) {
    provenance = explicit
    provenanceComplete = true
    source = 'report-counts'
  } else if (allRecords.length) {
    provenance = derived
    const classified = derived.floor + derived.agentOnly + derived.chainFromFloor
    provenanceComplete = missingProvenance === 0 && classified >= card.confirmed
  } else if (explicit) {
    provenance = explicit
    source = 'report-counts'
    provenanceComplete = false
  }

  const advisoryRecords = allRecords.filter(record => record.advisory)
  const leakRecords = allRecords.filter(record => record.contractLeak)
  const explicitAdvisories = typeof card.advisories === 'number'
    ? card.advisories
    : (Array.isArray(card.advisories) ? card.advisories.length + recordArray(card.advisoryFindings).length : null)
  const advisories = advisoryRecords.length > 0 ? advisoryRecords.length : (explicitAdvisories ?? 0)

  const readerCell = ScorecardReader.read(card, {
    failed: card.failed === true || card.status === 'INVALID' || meta?.failed === true,
    inert: card.inert === true || meta?.inert === true,
    contractLeaks: leakRecords.length,
  })

  return {
    provenance,
    provenanceComplete,
    provenanceSource: source,
    advisories,
    contractLeaks: leakRecords.length,
    precision: readerCell.headlinePrecision,
    rawPrecision: readerCell.rawPrecision,
    strictPrecision: readerCell.strictPrecision,
    cellState: readerCell.state,
    registeredFindings: allRecords.length,
  }
}

/** Union of confirmed targets across independent runs, deduped by the identity above. */
export function unionConfirmedTargets(runs: RealismRun[]): string[] {
  const keys = new Set<string>()
  for (const run of runs) for (const key of run.confirmedKeys) keys.add(key)
  return [...keys]
}

function maxTargets(runs: RealismRun[]): number {
  return runs.reduce((n, run) => Math.max(n, run.targets), 0)
}

// ---------------------------------------------------------------------------------------------
// Floor metrics (meta summary or per-run events DB)
// ---------------------------------------------------------------------------------------------

interface RawFloorMetrics {
  floorConfirmed?: number
  floorLeadsConsumed?: number
  floorLeadsEmitted?: number
  floorLeadsQueued?: number
  floorLeadsInvestigated?: number
}

function pickFloorMetrics(source: unknown): RawFloorMetrics | null {
  if (!isRecord(source)) return null
  const out: RawFloorMetrics = {}
  let found = false
  for (const key of ['floorConfirmed', 'floorLeadsConsumed', 'floorLeadsEmitted'] as const) {
    if (typeof source[key] === 'number' && Number.isFinite(source[key])) {
      out[key] = source[key] as number
      found = true
    }
  }
  for (const key of ['floorLeadsQueued', 'floorLeadsInvestigated'] as const) {
    if (typeof source[key] === 'number' && Number.isFinite(source[key])) {
      out[key] = source[key] as number
      found = true
    }
  }
  // The harness records the corrected funnel as meta.leadFunnel with short keys
  // (`{emitted, queued, dispatched, investigated}`); accept long-form keys too.
  if (isRecord(source.leadFunnel)) {
    for (const [from, to] of [
      ['leadsEmitted', 'floorLeadsEmitted'],
      ['emitted', 'floorLeadsEmitted'],
      ['leadsQueued', 'floorLeadsQueued'],
      ['queued', 'floorLeadsQueued'],
      ['leadsInvestigated', 'floorLeadsInvestigated'],
      ['investigated', 'floorLeadsInvestigated'],
    ] as const) {
      const value = source.leadFunnel[from]
      if (typeof value === 'number' && Number.isFinite(value)) {
        out[to] = value
        found = true
      }
    }
  }
  return found ? out : null
}

function floorMetricsFrom(picked: RawFloorMetrics, source: string): FloorMetrics {
  // `floorLeadsConsumed` is the corrected investigated count. Older artifacts may only carry the
  // queue-time value; then it is surfaced as `floorLeadsQueued` and consumed stays unmeasured,
  // because a queued lead is not evidence of investigation.
  const investigated = picked.floorLeadsInvestigated
    ?? (picked.floorLeadsQueued === undefined ? picked.floorLeadsConsumed : undefined)
  return {
    floorConfirmed: picked.floorConfirmed ?? null,
    floorLeadsConsumed: investigated ?? null,
    floorLeadsEmitted: picked.floorLeadsEmitted ?? null,
    floorLeadsQueued: picked.floorLeadsQueued
      ?? (picked.floorLeadsInvestigated === undefined ? picked.floorLeadsConsumed : null)
      ?? null,
    floorLeadsInvestigated: investigated ?? null,
    source,
  }
}

function metaFloorMetrics(meta: Record<string, unknown> | null, card: ScorecardLike): FloorMetrics {
  if (meta) {
    for (const candidate of [
      meta.floorMetrics, meta.deterministicLane, meta.deterministic_lane, meta.floor,
      { leadFunnel: meta.leadFunnel },
    ]) {
      const picked = pickFloorMetrics(candidate)
      if (picked) return floorMetricsFrom(picked, 'meta')
    }
    const direct = pickFloorMetrics(meta)
    if (direct) return floorMetricsFrom(direct, 'meta')
  }
  const cardLevel = pickFloorMetrics(card)
  if (cardLevel) return floorMetricsFrom(cardLevel, 'summary')
  return {
    floorConfirmed: null,
    floorLeadsConsumed: null,
    floorLeadsEmitted: null,
    floorLeadsQueued: null,
    floorLeadsInvestigated: null,
    source: 'none',
  }
}

function findRunDatabase(dir: string, slug: string): string | null {
  const direct = join(dir, 'data', slug, 'kovo.sqlite')
  if (existsSync(direct)) return direct
  const dataRoot = join(dir, 'data')
  const matches: string[] = []
  if (existsSync(dataRoot)) {
    try {
      for (const entry of readdirSync(dataRoot)) {
        if (entry === slug || entry.startsWith(`${slug}-`)) {
          const candidate = join(dataRoot, entry, 'kovo.sqlite')
          if (existsSync(candidate)) matches.push(candidate)
        }
      }
    } catch { /* unreadable data dir */ }
  }
  if (matches.length === 1) return matches[0]!
  // Last resort: exactly one kovo.sqlite under the cell's own directory tree.
  const found = collectFiles(dir, (path) => basename(path) === 'kovo.sqlite', 3)
  return found.length === 1 ? found[0]! : (matches.sort()[0] ?? null)
}

function collectFiles(root: string, accept: (path: string) => boolean, maxDepth: number): string[] {
  const out: string[] = []
  const walk = (dir: string, depth: number): void => {
    if (depth > maxDepth) return
    let entries: string[]
    try { entries = readdirSync(dir) } catch { return }
    for (const entry of entries) {
      if (entry === 'node_modules' || entry === '.git' || entry === 'credentials') continue
      const path = join(dir, entry)
      let stat
      try { stat = statSync(path) } catch { continue }
      if (stat.isDirectory()) walk(path, depth + 1)
      else if (stat.isFile() && accept(path)) out.push(path)
    }
  }
  walk(root, 0)
  return out
}

interface RunDatabaseEvidence {
  floor: FloorMetrics
  findings: FindingRecord[]
}

interface DerivedLeadFunnel {
  emitted: number
  queued: number
  dispatched: number
  investigated: number
}

/**
 * Derive the corrected lead funnel from an existing events DB. The engine's persisted
 * `floorLeadsConsumed` is a queue-time counter (execution.ts increments it inside
 * `queueDetLeadUpgradeSteps` when it emits `deterministic_lane.lead_consumed`), so this recomputes
 * "investigated" as the lead's bound step reaching a completed assignment (a verdict).
 */
function deriveLeadFunnelFromDatabase(db: DatabaseSync): DerivedLeadFunnel | null {
  try {
    const emitted = db.prepare(
      "select count(*) as n from events where kind = 'deterministic_engine.lead'",
    ).get() as { n?: unknown } | undefined
    const rows = db.prepare(
      "select detail from events where kind = 'deterministic_lane.lead_consumed'",
    ).all() as Array<{ detail?: unknown }>
    const queued = new Map<string, { factId: string | null; stepId: string | null }>()
    for (const row of rows) {
      const detail = typeof row.detail === 'string' ? JSON.parse(row.detail) as unknown : row.detail
      if (!isRecord(detail)) continue
      const factId = typeof detail.factId === 'string' ? detail.factId : null
      const stepId = typeof detail.stepId === 'string' ? detail.stepId : null
      const key = factId ?? stepId
      if (key) queued.set(key, { factId, stepId })
    }
    // No lead events at all: the legacy metrics payload is the only evidence available.
    if (queued.size === 0 && emitted?.n === 0) return null

    const upgradeStepsByFact = new Map<string, string[]>()
    try {
      const steps = db.prepare('select id, title, depends_on_fact_ids from chain_steps').all() as Array<{
        id?: unknown; title?: unknown; depends_on_fact_ids?: unknown
      }>
      for (const step of steps) {
        if (typeof step.id !== 'string' || typeof step.title !== 'string') continue
        if (!step.title.startsWith('det_lead upgrade')) continue
        const raw = typeof step.depends_on_fact_ids === 'string'
          ? JSON.parse(step.depends_on_fact_ids) as unknown
          : step.depends_on_fact_ids
        if (!Array.isArray(raw)) continue
        for (const factId of raw) {
          if (typeof factId !== 'string') continue
          const list = upgradeStepsByFact.get(factId) ?? []
          list.push(step.id)
          upgradeStepsByFact.set(factId, list)
        }
      }
    } catch { /* chain_steps unavailable in older stores */ }

    const statuses = new Map<string, string[]>()
    const assignments = db.prepare('select step_id, status from assignments').all() as Array<{ step_id?: unknown; status?: unknown }>
    for (const row of assignments) {
      if (typeof row.step_id !== 'string' || typeof row.status !== 'string') continue
      const list = statuses.get(row.step_id) ?? []
      list.push(row.status)
      statuses.set(row.step_id, list)
    }
    let dispatched = 0
    let investigated = 0
    for (const entry of queued.values()) {
      const candidateSteps = new Set<string>()
      if (entry.stepId) candidateSteps.add(entry.stepId)
      if (entry.factId) for (const stepId of upgradeStepsByFact.get(entry.factId) ?? []) candidateSteps.add(stepId)
      if (!candidateSteps.size) continue
      const values = [...candidateSteps].flatMap(stepId => statuses.get(stepId) ?? [])
      if (!values.length) continue
      dispatched += 1
      if (values.includes('complete')) investigated += 1
    }
    return {
      emitted: typeof emitted?.n === 'number' ? emitted.n : 0,
      queued: queued.size,
      dispatched,
      investigated,
    }
  } catch {
    return null
  }
}

function readMetricsFromDatabase(dbPath: string): RunDatabaseEvidence | null {
  let db: DatabaseSync | null = null
  try {
    db = new DatabaseSync(dbPath, { readOnly: true })
    const latest = db.prepare(
      "select detail from events where kind = 'deterministic_lane.metrics' order by rowid desc limit 1",
    ).get() as { detail?: unknown } | undefined
    let emitted: number | null = null
    try {
      const row = db.prepare(
        "select count(*) as n from facts where json_extract(data, '$.kind') = 'det_lead'",
      ).get() as { n?: unknown } | undefined
      if (typeof row?.n === 'number') emitted = row.n
    } catch { /* facts/data shape unavailable */ }

    let floor: FloorMetrics | null = null
    const derived = deriveLeadFunnelFromDatabase(db)
    if (!latest) {
      if (emitted !== null || derived) {
        floor = {
          floorConfirmed: null,
          floorLeadsConsumed: derived ? derived.investigated : null,
          floorLeadsEmitted: derived?.emitted ?? emitted,
          floorLeadsQueued: derived?.queued ?? null,
          floorLeadsInvestigated: derived ? derived.investigated : null,
          source: 'events-db',
        }
      }
    } else {
      const detail = typeof latest.detail === 'string' ? JSON.parse(latest.detail) as unknown : latest.detail
      if (isRecord(detail)) {
        // The persisted count is queue-time; prefer the derived verdict count when available.
        const investigated = derived ? derived.investigated : null
        floor = {
          floorConfirmed: typeof detail.floorConfirmed === 'number' ? detail.floorConfirmed : null,
          floorLeadsConsumed: investigated
            ?? (typeof detail.floorLeadsConsumed === 'number' ? detail.floorLeadsConsumed : null),
          floorLeadsEmitted: typeof detail.floorLeadsEmitted === 'number'
            ? detail.floorLeadsEmitted
            : (derived?.emitted ?? emitted),
          floorLeadsQueued: derived?.queued
            ?? (typeof detail.floorLeadsConsumed === 'number' ? detail.floorLeadsConsumed : null),
          floorLeadsInvestigated: investigated,
          source: 'events-db',
        }
      }
    }

    const findings: FindingRecord[] = []
    try {
      const columns = db.prepare("select name from pragma_table_info('findings')").all() as Array<{ name?: unknown }>
      const names = new Set(columns.map(row => String(row.name)))
      const extras = ['provenance', 'verification_status', 'verification_tier'].filter(name => names.has(name))
      const select = ['finding', ...extras].join(', ')
      const rows = db.prepare(`select ${select} from findings`).all() as Array<Record<string, unknown>>
      rows.forEach((row, index) => {
        const raw = typeof row.finding === 'string' ? JSON.parse(row.finding) as unknown : row.finding
        if (!isRecord(raw)) return
        const merged: Record<string, unknown> = { ...raw }
        if (merged.provenance == null && row.provenance != null) merged.provenance = row.provenance
        if (merged.verificationStatus == null && row.verification_status != null) merged.verificationStatus = row.verification_status
        if (merged.verificationTier == null && row.verification_tier != null) merged.verificationTier = row.verification_tier
        findings.push(parseFindingRecord(merged, { fallbackId: `${dbPath}#${index}` }))
      })
    } catch { /* findings table/columns unavailable */ }

    if (!floor && !findings.length) return null
    return {
      floor: floor ?? {
        floorConfirmed: null,
        floorLeadsConsumed: null,
        floorLeadsEmitted: null,
        floorLeadsQueued: null,
        floorLeadsInvestigated: null,
        source: 'events-db',
      },
      findings,
    }
  } catch {
    return null
  } finally {
    try { db?.close() } catch { /* already closed */ }
  }
}

function resolveRunDatabase(dir: string, card: ScorecardLike): RunDatabaseEvidence | null {
  const dbPath = findRunDatabase(dir, cellSlug(card.app, card.seed, card.mode ?? 'grey-box'))
  return dbPath ? readMetricsFromDatabase(dbPath) : null
}

function mergeFloorMetrics(meta: Record<string, unknown> | null, card: ScorecardLike, db: RunDatabaseEvidence | null): FloorMetrics {
  const fromMeta = metaFloorMetrics(meta, card)
  return {
    floorConfirmed: fromMeta.floorConfirmed ?? db?.floor.floorConfirmed ?? null,
    floorLeadsConsumed: fromMeta.floorLeadsConsumed ?? db?.floor.floorLeadsConsumed ?? null,
    floorLeadsEmitted: fromMeta.floorLeadsEmitted ?? db?.floor.floorLeadsEmitted ?? null,
    floorLeadsQueued: fromMeta.floorLeadsQueued ?? db?.floor.floorLeadsQueued ?? null,
    floorLeadsInvestigated: fromMeta.floorLeadsInvestigated ?? db?.floor.floorLeadsInvestigated ?? null,
    source: fromMeta.source !== 'none' ? fromMeta.source : (db?.floor.source ?? 'none'),
  }
}

// ---------------------------------------------------------------------------------------------
// Report ingestion
// ---------------------------------------------------------------------------------------------

function parseJsonFile(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as unknown
  } catch {
    return null
  }
}

function isScorecard(value: unknown): value is ScorecardLike {
  return isRecord(value)
    && typeof value.app === 'string'
    && typeof value.seed === 'number'
    && typeof value.targets === 'number'
    && typeof value.confirmed === 'number'
    && (Array.isArray(value.vulns) || typeof value.precision === 'number' || value.precision === null)
}

function isReasonReport(value: unknown): value is { cells: unknown[] } {
  return isRecord(value)
    && value.schemaVersion === 1
    && Array.isArray(value.cells)
    && ('agentic' in value || 'floorRun' in value || 'gate' in value)
}

function metaPathFor(dir: string, card: ScorecardLike): string {
  return join(dir, `${cellSlug(card.app, card.seed, card.mode ?? 'grey-box')}.meta.json`)
}

function readMeta(dir: string, card: ScorecardLike): Record<string, unknown> | null {
  const path = metaPathFor(dir, card)
  if (!existsSync(path)) return null
  const parsed = parseJsonFile(path)
  return isRecord(parsed) ? parsed : null
}

function inferLlm(card: ScorecardLike, meta: Record<string, unknown> | null, file: string): { llm: LlmMode; inferred: boolean } {
  const explicit = llmOf(card.llm)
    ?? llmOf(meta?.llm)
    ?? llmOf(isRecord(meta?.model) ? meta.model.mode : undefined)
  if (explicit) return { llm: explicit, inferred: false }
  const hint = file.toLowerCase()
  if (/floor|no-llm|deterministic/.test(hint)) return { llm: 'deterministic-no-llm', inferred: true }
  return { llm: 'agentic', inferred: true }
}

function realismRunFromCard(
  card: ScorecardLike,
  dir: string,
  file: string | null,
  meta: Record<string, unknown> | null,
  llm: LlmMode,
  notes: string[],
): RealismRun {
  const vulns = Array.isArray(card.vulns) ? card.vulns.filter(isRecord) as unknown as VulnLike[] : []
  const confirmedKeys = confirmedTargetKeys(vulns, card.app)
  const recall = asNumber(card.recall, ratio(card.confirmed, card.targets))
  const db = resolveRunDatabase(dir, card)
  const evidence = buildRunEvidence(card, meta, db?.findings ?? [])
  const rawBenchmarkVersion =
    'benchmarkVersion' in card
      ? (card.benchmarkVersion ?? null)
      : (meta && 'benchmarkVersion' in meta ? (typeof meta.benchmarkVersion === 'string' ? meta.benchmarkVersion : null) : undefined)
  const rawEffectiveConfigHash =
    'effectiveConfigHash' in card
      ? (card.effectiveConfigHash ?? null)
      : (meta && 'effectiveConfigHash' in meta ? (typeof meta.effectiveConfigHash === 'string' ? meta.effectiveConfigHash : null) : undefined)
  const rawEffectiveConfig =
    (isRecord(card.effectiveConfig) ? (card.effectiveConfig as unknown as EffectiveConfigSnapshot) : undefined)
    ?? (meta && isRecord(meta.effectiveConfig) ? (meta.effectiveConfig as unknown as EffectiveConfigSnapshot) : undefined)
  const rawReportable =
    typeof card.reportable === 'boolean'
      ? card.reportable
      : (typeof meta?.reportable === 'boolean' ? meta.reportable : undefined)
  const rawWordlistOn =
    typeof card.wordlistOn === 'boolean'
      ? card.wordlistOn
      : typeof meta?.wordlistOn === 'boolean'
        ? meta.wordlistOn
        : typeof rawEffectiveConfig?.wordlistOn === 'boolean'
          ? rawEffectiveConfig.wordlistOn
          : undefined
  const rawWorkerImageId =
    typeof card.workerImageId === 'string'
      ? card.workerImageId
      : typeof meta?.workerImageId === 'string'
        ? meta.workerImageId
        : (typeof rawEffectiveConfig?.workerImageId === 'string' ? rawEffectiveConfig.workerImageId : undefined)
  const rawSdkVersion =
    typeof card.sdkVersion === 'string'
      ? card.sdkVersion
      : typeof meta?.sdkVersion === 'string'
        ? meta.sdkVersion
        : (typeof rawEffectiveConfig?.sdkVersion === 'string' ? rawEffectiveConfig.sdkVersion : undefined)
  return {
    id: `${dir}#${file ?? 'summary'}#${cellSlug(card.app, card.seed, card.mode ?? 'grey-box')}`,
    dir,
    file,
    app: card.app,
    seed: card.seed,
    seedSet: seedSetOf(card.seedSet ?? meta?.seedSet, card.seed),
    mode: card.mode ?? 'grey-box',
    llm,
    targets: card.targets,
    confirmed: card.confirmed,
    recall,
    precision: evidence.precision,
    rawPrecision: evidence.rawPrecision,
    cellState: evidence.cellState,
    failed: evidence.cellState === 'failed_inert',
    inert: card.inert === true || meta?.inert === true,
    cellConcurrency: asFiniteNumber(meta?.cellConcurrency),
    workerConcurrency: asFiniteNumber(meta?.workerConcurrency),
    strictPrecision: evidence.strictPrecision,
    incompatibleClassCount: typeof card.incompatibleClassCount === 'number' ? card.incompatibleClassCount : null,
    misclassifiedFindingIds: Array.isArray(card.misclassifiedFindingIds) ? card.misclassifiedFindingIds.map(String) : [],
    decoyFalsePositives: asNumber(card.decoyFalsePositives),
    unmatchedFalsePositives: asNumber(card.unmatchedFalsePositives),
    confirmedKeys,
    floor: mergeFloorMetrics(meta, card, db),
    provenance: evidence.provenance,
    provenanceComplete: evidence.provenanceComplete,
    provenanceSource: evidence.provenanceSource,
    advisories: evidence.advisories,
    contractLeaks: evidence.contractLeaks,
    notes,
    ...(rawBenchmarkVersion !== undefined ? { benchmarkVersion: rawBenchmarkVersion } : {}),
    ...(rawEffectiveConfigHash !== undefined ? { effectiveConfigHash: rawEffectiveConfigHash } : {}),
    ...(rawEffectiveConfig !== undefined ? { effectiveConfig: rawEffectiveConfig } : {}),
    ...(rawReportable !== undefined ? { reportable: rawReportable } : {}),
    ...(rawWordlistOn !== undefined ? { wordlistOn: rawWordlistOn } : {}),
    ...(rawWorkerImageId !== undefined ? { workerImageId: rawWorkerImageId } : {}),
    ...(rawSdkVersion !== undefined ? { sdkVersion: rawSdkVersion } : {}),
  }
}

function reasonCellFromScorecard(
  card: ScorecardLike,
  meta: Record<string, unknown> | null,
  llm: LlmMode,
): ReasonCellLike {
  const vulns = Array.isArray(card.vulns) ? card.vulns : []
  const normalized = ScorecardReader.read(card, {
    failed: card.failed === true || card.status === 'INVALID' || meta?.failed === true,
    inert: card.inert === true || meta?.inert === true,
    llm,
  })
  return {
    app: card.app,
    seed: card.seed,
    mode: card.mode ?? 'grey-box',
    llm,
    targets: normalized.targets,
    confirmed: normalized.confirmed,
    recall: normalized.recall,
    precision: normalized.headlinePrecision,
    rawPrecision: normalized.rawPrecision,
    cellState: normalized.state,
    failed: normalized.failed,
    inert: normalized.inert,
    decoyFalsePositives: normalized.decoyFalsePositives,
    unmatchedFalsePositives: normalized.unmatchedFalsePositives,
    sites: vulns.map(v => ({ siteId: String(v.siteId), confirmed: v.outcome === 'confirmed' })),
  }
}

function reasonCellsFromReport(report: { cells: unknown[] }): ReasonCellLike[] {
  const cells: ReasonCellLike[] = []
  for (const raw of report.cells) {
    if (!isRecord(raw)) continue
    const llm = llmOf(raw.llm)
    if (!llm) continue
    const sitesRaw = Array.isArray(raw.sites) ? raw.sites : []
    const normalized = ScorecardReader.read(raw, {
      failed: raw.failed === true || raw.status === 'INVALID',
      inert: raw.inert === true,
      llm,
    })
    cells.push({
      app: normalized.app,
      seed: normalized.seed,
      mode: normalized.mode,
      llm,
      targets: normalized.targets,
      confirmed: normalized.confirmed,
      recall: normalized.recall,
      precision: normalized.headlinePrecision,
      rawPrecision: normalized.rawPrecision,
      cellState: normalized.state,
      failed: normalized.failed,
      inert: normalized.inert,
      decoyFalsePositives: normalized.decoyFalsePositives,
      unmatchedFalsePositives: normalized.unmatchedFalsePositives,
      sites: sitesRaw.filter(isRecord).map(site => ({
        siteId: String(site.siteId),
        confirmed: site.confirmed === true || site.outcome === 'confirmed',
      })),
    })
  }
  return cells
}

/**
 * Ingest one or more artifact directories. Recursively finds realistic scorecards
 * (`summary.json` / per-cell `<slug>.json`), reason reports (`reason-report.json`), and the
 * matching `.meta.json` / per-cell data DB. Report JSON is deduplicated per directory:
 * a `summary.json` wins over its sibling per-cell scorecards.
 */
export function ingestFromDirs(dirs: string[], env: NodeJS.ProcessEnv = process.env): IngestResult {
  const runs: RealismRun[] = []
  const reason: ReasonRun[] = []
  const notes: string[] = []
  const scanned = new Set<string>()
  const seenDirs = new Set<string>()

  for (const input of dirs) {
    const root = resolve(input)
    if (!existsSync(root)) throw new Error(`--from-dir path does not exist: ${input}`)
    const jsonFiles = collectFiles(root, path => path.endsWith('.json') && !basename(path).endsWith('.meta.json'), 6)
    for (const file of jsonFiles) scanned.add(file)

    const byDir = new Map<string, string[]>()
    for (const file of jsonFiles) {
      const list = byDir.get(dirname(file)) ?? []
      list.push(file)
      byDir.set(dirname(file), list)
    }

    for (const [dir, files] of byDir) {
      if (seenDirs.has(dir)) continue
      seenDirs.add(dir)
      const parsed = files.map(file => ({ file, value: parseJsonFile(file) }))
      const reasonReports = parsed.filter(entry => isReasonReport(entry.value))
      for (const entry of reasonReports) {
        const cells = reasonCellsFromReport(entry.value as { cells: unknown[] })
        if (cells.length) reason.push({ source: entry.file, cells })
      }
      const summary = parsed.find(entry => basename(entry.file) === 'summary.json' && Array.isArray(entry.value))
      const cards: Array<{ card: ScorecardLike; file: string }> = []
      if (summary && Array.isArray(summary.value)) {
        for (const value of summary.value) if (isScorecard(value)) cards.push({ card: value, file: summary.file })
      }
      if (!cards.length) {
        for (const entry of parsed) {
          if (isScorecard(entry.value)) cards.push({ card: entry.value, file: entry.file })
        }
      }
      for (const { card, file } of cards) {
        const meta = readMeta(dir, card)
        const { llm, inferred } = inferLlm(card, meta, `${relative(dir, file)} ${dir}`)
        const cardNotes: string[] = []
        if (inferred) cardNotes.push(`llm mode inferred from path (${llm}); report had no model metadata`)
        if (REASON_APPS.includes(card.app as typeof REASON_APPS[number])) {
          if (!reasonReports.length) {
            reason.push({ source: file, cells: [reasonCellFromScorecard(card, meta, llm)] })
          }
          continue
        }
        if (llm === 'deterministic-no-llm' && cardNotes.length === 0) {
          // no-op; keeps the branch explicit for future notes
        }
        runs.push(realismRunFromCard(card, dir, file, meta, llm, cardNotes))
      }
      if (reasonReports.length && cards.length) {
        notes.push(`${dir}: used reason-report.json cells (${reasonReports.length}); skipped ${cards.length} per-cell scorecard duplicate(s)`)
      }
    }
  }

  const salt = env.KOVO_RB_HELDOUT_SALT ?? ''
  if (runs.some(run => run.seedSet === 'held-out') && !salt) {
    notes.push('held-out cells ingested without KOVO_RB_HELDOUT_SALT (salt not needed to read finished reports)')
  }
  return { runs, reason, notes, filesScanned: scanned.size }
}

// ---------------------------------------------------------------------------------------------
// Certificate evaluation
// ---------------------------------------------------------------------------------------------

export interface Criterion {
  id: string
  description: string
  threshold: string
  observed: string
  status: 'PASS' | 'FAIL'
}

export interface RunStats {
  runs: number
  targets: number
  confirmed: number
  recall: number
  minRecall: number
  maxRecall: number
  spreadTargets: number
}

export interface UnifiedAppStats {
  runs: number
  targets: number
  /** Median per-run deduped confirmed targets (gate metric). */
  confirmed: number
  recall: number
  minRecall: number
  maxRecall: number
  /** Union across independent runs: capability coverage, informational. */
  coverageConfirmed: number
  coverageRecall: number
}

export interface ProvenanceSummary {
  runs: number
  completeRuns: number
  /** Median per-run counts over runs that expose provenance. */
  floor: number
  agentOnly: number
  chainFromFloor: number
  /** Median per-run `agent_only + chain_from_floor`; null when any run is unclassified. */
  incremental: number | null
}

export interface InformationalMetric {
  id: string
  description: string
  target: string
  observed: string
  status: 'MEETS' | 'BELOW' | 'UNMEASURED'
}

export interface SplitStats {
  floor: { perApp: Record<string, RunStats | null>; confirmed: number; targets: number; recall: number }
  unified: {
    perApp: Record<string, UnifiedAppStats | null>
    confirmed: number
    targets: number
    recall: number
    coverageConfirmed: number
    coverageRecall: number
  }
  lift: { perApp: Record<string, number | null>; aggregate: number | null }
}

export interface Certificate {
  schemaVersion: 1
  status: 'VALID' | 'INVALID'
  failedCells: number
  generatedAt: string
  gitSha: string
  benchmarkVersion: string | null
  effectiveConfigHash: string | null
  certifying: boolean
  nonCertifyingReason: string | null
  heldoutSeeds: number[]
  burnedSeedsDetected: number[]
  mode: 'from-dir' | 'run'
  verdict: 'PASS' | 'FAIL'
  thresholds: Thresholds
  matrix: {
    expected: {
      apps: string[]
      floorDevRuns: number
      floorHeldoutRuns: number
      unifiedDevRuns: number
      unifiedHeldoutRuns: number
    }
    observed: Record<string, { floorDev: number; floorHeldout: number; unifiedDev: number; unifiedHeldout: number }>
    complete: boolean
  }
  floor: { dev: SplitStats['floor']; heldout: SplitStats['floor']; spread: Record<string, number | null> }
  unified: { dev: SplitStats['unified']; heldout: SplitStats['unified'] }
  /** Harness concurrency, recorded separately: cells in parallel vs. workers inside a cell. */
  concurrency: {
    cell: { dev: number | null; heldout: number | null; runs: number; unmeasured: number }
    worker: { dev: number | null; heldout: number | null; runs: number; unmeasured: number }
    /** Unified agentic cells that ran with a single in-run worker slot (dispatch starvation). */
    singleWorkerRuns: string[]
  }
  lift: { dev: SplitStats['lift']; heldout: SplitStats['lift']; source: 'provenance' }
  provenance: {
    complete: boolean
    totalRuns: number
    completeRuns: number
    perApp: Record<string, { dev: ProvenanceSummary | null; heldout: ProvenanceSummary | null }>
    aggregate: { dev: ProvenanceSummary | null; heldout: ProvenanceSummary | null }
  }
  advisories: {
    noiseCapPerApp: number
    perApp: Record<string, { dev: number; heldout: number; devWorst: number; heldoutWorst: number; total: number }>
    total: number
    overCap: string[]
    contractLeaks: number
  }
  informational: InformationalMetric[]
  preservation: {
    median: number | null
    ratios: Array<{ app: string; seedSet: SeedSet; ratio: number; floorConfirmed: number; floorStandalone: number }>
    unmeasuredRuns: number
    keyBased: { dev: number | null; heldout: number | null }
  }
  precision: {
    worst: number | null
    worstRun: string | null
    decoyFalsePositives: number
    unmatchedFalsePositives: number
    runs: number
  }
  hygiene: {
    /** Class-incompatible claims on planted target endpoints. Must be 0 for Phase-1. */
    incompatibleClassCount: number
    /** Runs whose artifact predates the hygiene field (gate fails rather than assuming 0). */
    incompatibleClassUnmeasured: number
    /** Worst-run strict precision (charges uncharged misclassifications), or null when no claims. */
    worstStrictPrecision: number | null
    /** Runs that relied on the documented sibling tolerance (should be 0 for Phase-1). */
    misclassifiedRuns: number
    misclassifiedFindingIds: string[]
  }
  leads: {
    checkedRuns: number
    unmeasuredRuns: number
    violations: Array<{ app: string; seedSet: SeedSet; emitted: number; consumed: number }>
  }
  reason: {
    floor: { confirmed: number; targets: number; recall: number | null }
    agentic: { confirmed: number; targets: number; recall: number | null; worstPrecision: number | null; cells: number }
  }
  criteria: Criterion[]
  notes: string[]
}

export interface CertifyOptions {
  mode: 'from-dir' | 'run'
  apps?: string[]
  devRuns?: number
  floorHeldoutRuns?: number
  heldoutRuns?: number
  checkMatrix?: boolean
  /** Explicit dev-2 debugging escape hatch for burned seeds; always stamps certifying=false. */
  allowBurnedDev?: boolean
  thresholds?: Thresholds
  generatedAt?: string
  gitSha?: string
  notes?: string[]
}

function runStats(runs: RealismRun[]): RunStats | null {
  if (!runs.length) return null
  const recalls = runs.map(run => run.recall)
  const counts = runs.map(run => run.confirmed)
  return {
    runs: runs.length,
    targets: maxTargets(runs),
    confirmed: median(counts) ?? 0,
    recall: median(recalls) ?? 0,
    minRecall: Math.min(...recalls),
    maxRecall: Math.max(...recalls),
    spreadTargets: Math.max(...counts) - Math.min(...counts),
  }
}

function incrementalCount(run: RealismRun): number | null {
  if (!run.provenance || !run.provenanceComplete) return null
  return run.provenance.agentOnly + run.provenance.chainFromFloor
}

function splitStats(floorRuns: RealismRun[], unifiedRuns: RealismRun[], apps: string[]): SplitStats {
  const floorPerApp: Record<string, RunStats | null> = {}
  const unifiedPerApp: SplitStats['unified']['perApp'] = {}
  const liftPerApp: Record<string, number | null> = {}
  let floorConfirmed = 0
  let floorTargets = 0
  let unifiedConfirmed = 0
  let unifiedTargets = 0
  let coverageConfirmed = 0
  let aggregateIncremental = 0
  let aggregateIncrementalTargets = 0
  let unifiedApps = 0
  let incrementalComplete = true

  for (const app of apps) {
    const appFloor = floorRuns.filter(run => run.app === app)
    const appUnified = unifiedRuns.filter(run => run.app === app)
    const stats = runStats(appFloor)
    floorPerApp[app] = stats
    floorConfirmed += stats?.confirmed ?? 0
    floorTargets += stats?.targets ?? 0

    if (!appUnified.length) {
      unifiedPerApp[app] = null
      liftPerApp[app] = null
      continue
    }
    unifiedApps += 1
    const keys = unionConfirmedTargets(appUnified)
    const targets = maxTargets(appUnified)
    const perRunCounts = appUnified.map(run => new Set(run.confirmedKeys).size)
    const perRunRecalls = perRunCounts.map(count => ratio(count, targets))
    const medianConfirmed = median(perRunCounts) ?? 0
    const medianRecall = median(perRunRecalls) ?? 0
    unifiedPerApp[app] = {
      runs: appUnified.length,
      targets,
      confirmed: medianConfirmed,
      recall: medianRecall,
      minRecall: Math.min(...perRunRecalls),
      maxRecall: Math.max(...perRunRecalls),
      coverageConfirmed: keys.length,
      coverageRecall: ratio(keys.length, targets),
    }
    unifiedConfirmed += medianConfirmed
    unifiedTargets += targets
    coverageConfirmed += keys.length

    const increments = appUnified.map(incrementalCount)
    const medianIncrement = increments.every(value => value !== null)
      ? median(increments as number[])
      : null
    if (medianIncrement === null) {
      liftPerApp[app] = null
      incrementalComplete = false
    } else {
      liftPerApp[app] = medianIncrement / targets
      aggregateIncremental += medianIncrement
      aggregateIncrementalTargets += targets
    }
  }

  const floorRecall = ratio(floorConfirmed, floorTargets)
  const unifiedRecall = ratio(unifiedConfirmed, unifiedTargets)
  return {
    floor: { perApp: floorPerApp, confirmed: floorConfirmed, targets: floorTargets, recall: floorRecall },
    unified: {
      perApp: unifiedPerApp,
      confirmed: unifiedConfirmed,
      targets: unifiedTargets,
      recall: unifiedRecall,
      coverageConfirmed,
      coverageRecall: ratio(coverageConfirmed, unifiedTargets),
    },
    lift: {
      perApp: liftPerApp,
      aggregate: incrementalComplete && unifiedApps > 0 && aggregateIncrementalTargets > 0
        ? aggregateIncremental / aggregateIncrementalTargets
        : null,
    },
  }
}

function provenanceSummary(runs: RealismRun[]): ProvenanceSummary | null {
  const withProvenance = runs.filter(run => run.provenance !== null)
  if (!withProvenance.length) return null
  const floor = median(withProvenance.map(run => run.provenance!.floor)) ?? 0
  const agentOnly = median(withProvenance.map(run => run.provenance!.agentOnly)) ?? 0
  const chainFromFloor = median(withProvenance.map(run => run.provenance!.chainFromFloor)) ?? 0
  const complete = withProvenance.filter(run => run.provenanceComplete)
  const increments = complete.map(run => run.provenance!.agentOnly + run.provenance!.chainFromFloor)
  const allComplete = complete.length === runs.length
  return {
    runs: runs.length,
    completeRuns: complete.length,
    floor,
    agentOnly,
    chainFromFloor,
    incremental: allComplete ? (median(increments) ?? 0) : null,
  }
}


function aggregateReason(
  cells: ReasonCellLike[],
  expectedTargets?: number,
): { confirmed: number; targets: number; recall: number | null; precision: number | null; decoyFP: number; unmatchedFP: number; failedCells: number } {
  if (!cells.length) {
    return { confirmed: 0, targets: 0, recall: null, precision: null, decoyFP: 0, unmatchedFP: 0, failedCells: 0 }
  }
  const siteKeys = new Set<string>()
  const confirmedKeys = new Set<string>()
  const maxTargetsByApp = new Map<string, number>()
  const maxConfirmedByApp = new Map<string, number>()
  let decoyFP = 0
  let unmatchedFP = 0
  let failedCells = 0
  const measuredPrecisions: number[] = []

  for (const cell of cells) {
    const isFailed = cell.cellState === 'failed_inert' || cell.failed === true || cell.inert === true
    if (isFailed) {
      failedCells += 1
      continue
    }
    decoyFP += cell.decoyFalsePositives
    unmatchedFP += cell.unmatchedFalsePositives
    maxTargetsByApp.set(cell.app, Math.max(maxTargetsByApp.get(cell.app) ?? 0, cell.targets))
    maxConfirmedByApp.set(cell.app, Math.max(maxConfirmedByApp.get(cell.app) ?? 0, cell.confirmed))
    for (const site of cell.sites) {
      const key = `${cell.app}|${site.siteId}`
      siteKeys.add(key)
      if (site.confirmed) confirmedKeys.add(key)
    }
    const tpPlusFp = cell.confirmed + cell.decoyFalsePositives + cell.unmatchedFalsePositives
    if (tpPlusFp > 0) {
      const computed = ratioOrNull(cell.confirmed, tpPlusFp)
      const cellPrec =
        typeof cell.precision === 'number' && Number.isFinite(cell.precision) && computed !== null
          ? Math.min(cell.precision, computed)
          : computed
      if (cellPrec !== null) measuredPrecisions.push(cellPrec)
    }
  }
  let observedTargets = siteKeys.size
  let confirmed = confirmedKeys.size
  if (!siteKeys.size) {
    observedTargets = sum([...maxTargetsByApp.values()])
    confirmed = sum([...maxConfirmedByApp.values()])
  }
  // Never let a crashed or missing app cell shrink the reason-bench denominator!
  const targets =
    expectedTargets !== undefined && expectedTargets > 0
      ? Math.max(observedTargets, expectedTargets)
      : observedTargets
  const worst = measuredPrecisions.length > 0 ? Math.min(...measuredPrecisions) : null
  return {
    confirmed,
    targets,
    recall: failedCells > 0 ? null : ratioOrNull(confirmed, targets),
    precision: failedCells > 0 ? null : worst,
    decoyFP,
    unmatchedFP,
    failedCells,
  }
}

function criterion(
  id: string,
  description: string,
  threshold: string,
  observed: string,
  pass: boolean,
): Criterion {
  return { id, description, threshold, observed, status: pass ? 'PASS' : 'FAIL' }
}

export function evaluateCertification(
  runs: RealismRun[],
  reasonRuns: ReasonRun[],
  options: CertifyOptions,
): Certificate {
  const thresholds = options.thresholds ?? DEFAULT_THRESHOLDS
  const apps = options.apps ?? [...CERTIFY_APPS]
  const devRuns = options.devRuns ?? 3
  const floorHeldoutRuns = options.floorHeldoutRuns ?? 1
  const heldoutRuns = options.heldoutRuns ?? 2
  const notes = [...(options.notes ?? [])]

  const floorDev = runs.filter(run => run.llm === 'deterministic-no-llm' && run.seedSet === 'dev')
  const floorHeldout = runs.filter(run => run.llm === 'deterministic-no-llm' && run.seedSet === 'held-out')
  const unifiedDev = runs.filter(run => run.llm === 'agentic' && run.seedSet === 'dev')
  const unifiedHeldout = runs.filter(run => run.llm === 'agentic' && run.seedSet === 'held-out')

  const dev = splitStats(floorDev, unifiedDev, apps)
  const heldout = splitStats(floorHeldout, unifiedHeldout, apps)

  // Floor spread is the determinism gate; only app/split pairs with >= 2 runs are measurable.
  const spread: Record<string, number | null> = {}
  let spreadOk = true
  let spreadMeasured = 0
  for (const app of apps) {
    const appFloor = floorDev.filter(run => run.app === app)
    if (appFloor.length >= 2) {
      const counts = appFloor.map(run => run.confirmed)
      const value = Math.max(...counts) - Math.min(...counts)
      spread[app] = value
      spreadMeasured += 1
      if (value > thresholds.floorSpreadMax) spreadOk = false
    } else {
      spread[app] = null
      spreadOk = false
    }
  }
  const spreadObserved = apps.map(app => `${app} ${spread[app] === null ? 'unmeasured' : spread[app]}`).join(', ')

  // Preservation: unified floor count vs standalone floor median, per app/split.
  const preservationRatios: Certificate['preservation']['ratios'] = []
  let unmeasuredPreservation = 0
  for (const run of [...unifiedDev, ...unifiedHeldout]) {
    const baseline = (run.seedSet === 'dev' ? dev : heldout).floor.perApp[run.app]?.confirmed ?? null
    if (baseline === null || run.floor.floorConfirmed === null) {
      unmeasuredPreservation += 1
      continue
    }
    preservationRatios.push({
      app: run.app,
      seedSet: run.seedSet,
      ratio: ratio(run.floor.floorConfirmed, baseline),
      floorConfirmed: run.floor.floorConfirmed,
      floorStandalone: baseline,
    })
  }
  const preservationMedian = median(preservationRatios.map(row => row.ratio))
  const keyPreservation = (split: 'dev' | 'held-out'): number | null => {
    const floorKeys = new Set(unionConfirmedTargets(split === 'dev' ? floorDev : floorHeldout))
    if (!floorKeys.size) return null
    const unifiedKeys = new Set(unionConfirmedTargets(split === 'dev' ? unifiedDev : unifiedHeldout))
    let present = 0
    for (const key of floorKeys) if (unifiedKeys.has(key)) present += 1
    return present / floorKeys.size
  }

  // Worst-run precision and false-positive totals across every realism cell.
  // Normalize each run through ScorecardReader semantics: 0-claim runs report null (never 1),
  // and any failed/inert run marks the certificate INVALID.
  const failedRealismRuns = runs.filter(
    run => run.cellState === 'failed_inert' || run.failed === true || run.inert === true,
  )
  const precisionRuns = runs
  const measuredPrecisionRuns: Array<{ run: RealismRun; precision: number }> = []
  const measuredStrictPrecisions: number[] = []
  for (const run of precisionRuns) {
    if (run.cellState === 'failed_inert' || run.failed === true || run.inert === true) continue
    const headlineDenom = run.confirmed + run.decoyFalsePositives + run.unmatchedFalsePositives + run.contractLeaks
    const strictDenom = headlineDenom + run.misclassifiedFindingIds.length
    const computedHeadline = ratioOrNull(run.confirmed, headlineDenom)
    const computedStrict = ratioOrNull(run.confirmed, strictDenom)
    if (computedHeadline !== null) {
      const effectivePrec =
        typeof run.precision === 'number' && Number.isFinite(run.precision)
          ? Math.min(run.precision, computedHeadline)
          : computedHeadline
      measuredPrecisionRuns.push({ run, precision: effectivePrec })
    }
    if (computedStrict !== null) {
      const effectiveStrict =
        typeof run.strictPrecision === 'number' && Number.isFinite(run.strictPrecision)
          ? Math.min(run.strictPrecision, computedStrict)
          : computedStrict
      measuredStrictPrecisions.push(effectiveStrict)
    }
  }
  const worstEntry = measuredPrecisionRuns.reduce<{ run: RealismRun; precision: number } | null>(
    (worst, entry) => (worst === null || entry.precision < worst.precision ? entry : worst),
    null,
  )
  const worstRun = worstEntry?.run ?? null
  const worstPrecision: number | null = worstEntry ? worstEntry.precision : null
  const decoyFP = sum(runs.map(run => run.decoyFalsePositives))
  const unmatchedFP = sum(runs.map(run => run.unmatchedFalsePositives))
  // Class-label hygiene (reviewer gate): incompatible class claims on planted targets and the
  // conservative precision that charges every uncharged sibling misclassification.
  const incompatibleClassUnmeasured = runs.filter(run => run.incompatibleClassCount === null).length
  const incompatibleClassCount = sum(runs.map(run => run.incompatibleClassCount ?? 0))
  const misclassifiedRuns = runs.filter(run => run.misclassifiedFindingIds.length > 0).length
  const misclassifiedFindingIds = runs.flatMap(run => run.misclassifiedFindingIds)
  const worstStrictPrecision: number | null = measuredStrictPrecisions.length
    ? Math.min(...measuredStrictPrecisions)
    : null

  // Leads invariant on unified runs only.
  const leadViolations: Certificate['leads']['violations'] = []
  let leadsChecked = 0
  let leadsUnmeasured = 0
  for (const run of [...unifiedDev, ...unifiedHeldout]) {
    const emitted = run.floor.floorLeadsEmitted
    const consumed = run.floor.floorLeadsConsumed
    if (emitted === null || consumed === null) {
      leadsUnmeasured += 1
      continue
    }
    leadsChecked += 1
    if (emitted > 0 && consumed === 0) {
      leadViolations.push({ app: run.app, seedSet: run.seedSet, emitted, consumed })
    }
  }

  // Reason-bench (denominators ALWAYS count expected targets when reason cells are present).
  const reasonFloorCells = reasonRuns.flatMap(run => run.cells.filter(cell => cell.llm === 'deterministic-no-llm'))
  const reasonAgenticCells = reasonRuns.flatMap(run => run.cells.filter(cell => cell.llm === 'agentic'))
  const reasonFloor = aggregateReason(reasonFloorCells, reasonFloorCells.length > 0 ? thresholds.reasonTargets : undefined)
  const reasonAgentic = aggregateReason(reasonAgenticCells, reasonAgenticCells.length > 0 ? thresholds.reasonTargets : undefined)
  const failedCells = failedRealismRuns.length + reasonFloor.failedCells + reasonAgentic.failedCells
  const certStatus: 'VALID' | 'INVALID' = failedCells > 0 ? 'INVALID' : 'VALID'

  // Matrix coverage.
  const observed: Certificate['matrix']['observed'] = {}
  let matrixComplete = true
  for (const app of apps) {
    const row = {
      floorDev: floorDev.filter(run => run.app === app).length,
      floorHeldout: floorHeldout.filter(run => run.app === app).length,
      unifiedDev: unifiedDev.filter(run => run.app === app).length,
      unifiedHeldout: unifiedHeldout.filter(run => run.app === app).length,
    }
    observed[app] = row
    if (row.floorDev < devRuns || row.floorHeldout < floorHeldoutRuns
      || row.unifiedDev < devRuns || row.unifiedHeldout < heldoutRuns) matrixComplete = false
  }

  const liftDev = dev.lift.aggregate
  const liftHeldout = heldout.lift.aggregate
  const liftDevOk = liftDev !== null && liftDev >= thresholds.liftDevMin
  const liftHeldoutOk = liftHeldout !== null && liftHeldout >= thresholds.liftHeldoutMin
  const monotonicPairs: Array<{ split: string; app: string; total: number; floor: number }> = []
  for (const [splitName, split] of [['dev', dev], ['heldout', heldout]] as const) {
    for (const app of apps) {
      const unified = split.unified.perApp[app]
      const floor = split.floor.perApp[app]
      if (unified && floor) monotonicPairs.push({ split: splitName, app, total: unified.recall, floor: floor.recall })
    }
  }
  const monotonicFailures = monotonicPairs.filter(pair => pair.total + 1e-9 < pair.floor)
  const monotonicOk = !thresholds.requireMonotonic
    || (monotonicPairs.length >= apps.length * 2 && monotonicFailures.length === 0)

  const reasonFloorOk = reasonFloor.failedCells === 0
    && reasonFloor.confirmed === thresholds.reasonFloorConfirmed
    && reasonFloor.targets === thresholds.reasonTargets
    && reasonFloor.decoyFP === 0
    && reasonFloor.unmatchedFP === 0
  const reasonAgenticMeets = reasonAgentic.failedCells === 0
    && reasonAgentic.recall !== null
    && reasonAgentic.recall >= thresholds.reasonAgenticMin
    && reasonAgentic.precision !== null
    && reasonAgentic.precision >= thresholds.worstPrecision

  // Provenance is mandatory for the lift metric: never infer floor/agent attribution.
  const unifiedAll = [...unifiedDev, ...unifiedHeldout]
  const fullyClassified = unifiedAll.filter(run => run.provenance !== null && run.provenanceComplete)
  const provenanceComplete = unifiedAll.length > 0 && fullyClassified.length === unifiedAll.length
  const provenancePerApp: Certificate['provenance']['perApp'] = {}
  for (const app of apps) {
    provenancePerApp[app] = {
      dev: provenanceSummary(unifiedDev.filter(run => run.app === app)),
      heldout: provenanceSummary(unifiedHeldout.filter(run => run.app === app)),
    }
  }

  // Advisories (static_only / open_proof_gap) are a separate noise budget, never recall.
  const advisoryPerApp: Certificate['advisories']['perApp'] = {}
  const overCap: string[] = []
  let advisoryTotal = 0
  for (const app of apps) {
    const devAdvisory = unifiedDev.filter(run => run.app === app).map(run => run.advisories)
    const heldAdvisory = unifiedHeldout.filter(run => run.app === app).map(run => run.advisories)
    const devWorst = devAdvisory.length ? Math.max(...devAdvisory) : 0
    const heldWorst = heldAdvisory.length ? Math.max(...heldAdvisory) : 0
    const total = sum(devAdvisory) + sum(heldAdvisory)
    advisoryPerApp[app] = {
      dev: sum(devAdvisory),
      heldout: sum(heldAdvisory),
      devWorst,
      heldoutWorst: heldWorst,
      total,
    }
    advisoryTotal += total
    if (devWorst > ADVISORY_NOISE_CAP_PER_APP || heldWorst > ADVISORY_NOISE_CAP_PER_APP) overCap.push(app)
  }
  const contractLeaks = sum(unifiedAll.map(run => run.contractLeaks))
  const worstAdvisory = Math.max(0, ...Object.values(advisoryPerApp).map(row => Math.max(row.devWorst, row.heldoutWorst)))

  // Harness concurrency, reported separately from cell scheduling. A cell that runs alone can
  // still use several workers; the failure mode this records is cell concurrency leaking into
  // `runs.worker_concurrency` (one worker slot for a whole investigation).
  const concurrencyStat = (runsForStat: RealismRun[], key: 'cellConcurrency' | 'workerConcurrency') => {
    const values = runsForStat
      .map(run => run[key])
      .filter((value): value is number => value !== null)
    return {
      median: median(values),
      runs: values.length,
      unmeasured: runsForStat.length - values.length,
    }
  }
  const cellDev = concurrencyStat(unifiedDev, 'cellConcurrency')
  const cellHeldout = concurrencyStat(unifiedHeldout, 'cellConcurrency')
  const workerDev = concurrencyStat(unifiedDev, 'workerConcurrency')
  const workerHeldout = concurrencyStat(unifiedHeldout, 'workerConcurrency')
  const singleWorkerRuns = unifiedAll
    .filter(run => run.workerConcurrency !== null && run.workerConcurrency <= 1)
    .map(run => `${run.app}@${run.seed} (${run.seedSet})`)
  const workerValues = unifiedAll
    .map(run => run.workerConcurrency)
    .filter((value): value is number => value !== null)

  const informational: InformationalMetric[] = [{
    id: 'reason_bench_agentic_baseline',
    description: 'Reason-bench agentic baseline (Phase 3; non-blocking in Phase 1)',
    target: `>= ${(thresholds.reasonAgenticMin * 100).toFixed(0)}% at worst-run ${(thresholds.worstPrecision * 100).toFixed(0)}% precision`,
    observed: reasonAgenticCells.length
      ? `${reasonAgentic.recall === null ? 'unmeasured' : pct(reasonAgentic.recall)} (${reasonAgentic.confirmed}/${reasonAgentic.targets}), worst precision ${reasonAgentic.precision === null ? 'n/a' : reasonAgentic.precision.toFixed(3)}`
      : 'unmeasured (no agentic reason cells ingested)',
    status: !reasonAgenticCells.length ? 'UNMEASURED' : (reasonAgenticMeets ? 'MEETS' : 'BELOW'),
  }, {
    id: 'agentic_worker_concurrency',
    description: 'In-run investigation worker slots for unified agentic cells (dispatch capacity; non-blocking)',
    target: '>= 3 per cell',
    observed: workerValues.length
      ? `median ${median(workerValues) ?? 'n/a'} (${singleWorkerRuns.length}/${workerValues.length} single-slot run(s))`
      : 'unmeasured (no workerConcurrency in cell meta)',
    status: !workerValues.length ? 'UNMEASURED' : (singleWorkerRuns.length === 0 ? 'MEETS' : 'BELOW'),
  }]

  const criteria: Criterion[] = [
    criterion(
      'floor_spread',
      'Floor determinism: max-min confirmed targets per app across n=3 dev runs',
      `<= ${thresholds.floorSpreadMax} target`,
      spreadObserved,
      spreadOk,
    ),
    criterion(
      'floor_preservation',
      'Floor preservation: median floorConfirmedInUnified / floorStandalone',
      `>= ${thresholds.preservationMin}`,
      `${preservationMedian === null ? 'unmeasured' : preservationMedian.toFixed(3)} (${preservationRatios.length} run(s), ${unmeasuredPreservation} unmeasured)`,
      preservationMedian !== null && preservationMedian >= thresholds.preservationMin,
    ),
    criterion(
      'worst_run_precision',
      'Worst-run precision across every realism cell (decoy + unmatched FP = 0)',
      `== ${thresholds.worstPrecision}`,
      `${worstPrecision === null ? 'n/a' : worstPrecision.toFixed(3)} (${worstRun ? `${worstRun.app}@${worstRun.seed}` : precisionRuns.length ? 'no claims' : 'no runs'})`,
      failedCells === 0 && precisionRuns.length > 0 && decoyFP === 0 && unmatchedFP === 0 && (worstPrecision === null || worstPrecision >= thresholds.worstPrecision),
    ),
    criterion(
      'class_hygiene',
      'Class-label hygiene: incompatible class claims on planted targets must be 0; strict precision charges sibling tolerance',
      'incompatible_class_count == 0 (worst strict precision == 1)',
      `${incompatibleClassCount} incompatible class claim(s) across ${precisionRuns.length} run(s), ${incompatibleClassUnmeasured} unmeasured; worst strict precision ${worstStrictPrecision === null ? 'n/a' : worstStrictPrecision.toFixed(3)}; ${misclassifiedFindingIds.length} uncharged misclassification(s) in ${misclassifiedRuns} run(s)`,
      failedCells === 0 && incompatibleClassCount === 0 && incompatibleClassUnmeasured === 0 && (worstStrictPrecision === null || worstStrictPrecision >= thresholds.worstPrecision),
    ),
    criterion(
      'agentic_lift_dev',
      'Aggregate provenance-derived lift on dev (agent_only + chain_from_floor)',
      `>= +${(thresholds.liftDevMin * 100).toFixed(0)}pp`,
      liftDev === null ? 'unmeasured (provenance missing/incomplete)' : `${liftDev >= 0 ? '+' : ''}${(liftDev * 100).toFixed(1)}pp`,
      liftDevOk,
    ),
    criterion(
      'agentic_lift_heldout',
      'Aggregate provenance-derived lift on salted held-out (agent_only + chain_from_floor)',
      `>= +${(thresholds.liftHeldoutMin * 100).toFixed(0)}pp`,
      liftHeldout === null ? 'unmeasured (provenance missing/incomplete)' : `${liftHeldout >= 0 ? '+' : ''}${(liftHeldout * 100).toFixed(1)}pp`,
      liftHeldoutOk,
    ),
    criterion(
      'monotonicity',
      'Unified total >= standalone floor on every app, dev and held-out',
      '0 app/split regressions',
      monotonicFailures.length
        ? monotonicFailures.map(pair => `${pair.split}/${pair.app} ${pct(pair.total)} < ${pct(pair.floor)}`).join(', ')
        : `${monotonicPairs.length}/${apps.length * 2} pair(s) monotonic`,
      monotonicOk,
    ),
    criterion(
      'leads_invariant',
      'floorLeadsEmitted > 0 implies floorLeadsConsumed > 0 on every unified run',
      '0 violations, 0 unmeasured',
      `${leadViolations.length} violation(s), ${leadsUnmeasured} unmeasured, ${leadsChecked} checked`,
      leadViolations.length === 0 && leadsUnmeasured === 0 && leadsChecked > 0,
    ),
    criterion(
      'reason_bench_floor',
      'Reason-bench deterministic floor',
      `${thresholds.reasonFloorConfirmed}/${thresholds.reasonTargets} confirmed`,
      `${reasonFloor.confirmed}/${reasonFloor.targets}${reasonFloor.recall === null ? ' (unmeasured)' : ''}`,
      reasonFloorOk,
    ),
    criterion(
      'provenance_completeness',
      'Every unified confirmed finding exposes provenance (floor | agent_only | chain_from_floor)',
      '100% of unified runs fully classified',
      `${fullyClassified.length}/${unifiedAll.length} run(s) fully classified`,
      provenanceComplete,
    ),
    criterion(
      'advisory_noise',
      'Advisories (static_only / open_proof_gap) stay outside confirmed recall/precision',
      `<= ${ADVISORY_NOISE_CAP_PER_APP} per app, worst run`,
      `${advisoryTotal} total, worst ${worstAdvisory}${overCap.length ? `; over cap: ${overCap.join(', ')}` : ''}`,
      overCap.length === 0,
    ),
    criterion(
      'confirmed_contract',
      'A static-only/open-proof-gap finding never appears inside confirmed findings',
      '0 contract leaks',
      `${contractLeaks} leak(s)`,
      contractLeaks === 0,
    ),
  ]
  if (options.checkMatrix !== false) {
    criteria.push(criterion(
      'matrix_coverage',
      'Certification matrix completeness (per app)',
      `floor dev >= ${devRuns}, floor held-out >= ${floorHeldoutRuns}, unified dev >= ${devRuns}, unified held-out >= ${heldoutRuns}`,
      apps.map(app => {
        const row = observed[app]!
        return `${app} ${row.floorDev}/${row.floorHeldout}/${row.unifiedDev}/${row.unifiedHeldout}`
      }).join(', '),
      matrixComplete,
    ))
  }

  const burnedSet = loadBurnedSeeds()
  const heldoutSeedsObserved = unique([...floorHeldout, ...unifiedHeldout].map(run => run.seed)).sort((a, b) => a - b)
  const burnedSeedsDetected = heldoutSeedsObserved.filter(seed => burnedSet.has(seed))
  const allowBurnedDev = options.allowBurnedDev === true
  const hasEnoughHeldoutSeeds = heldoutSeedsObserved.length >= CERTIFYING_MIN_HELDOUT_SEEDS
  const certifying = !allowBurnedDev && burnedSeedsDetected.length === 0 && hasEnoughHeldoutSeeds
  const nonCertifyingReason = allowBurnedDev
    ? `allow-burned-dev (${burnedSeedsDetected.join(',') || 'dev-2 override'})`
    : burnedSeedsDetected.length > 0
      ? `burned-heldout-seed (${burnedSeedsDetected.join(',')})`
      : !hasEnoughHeldoutSeeds
        ? `insufficient-heldout-seeds (${heldoutSeedsObserved.length} < ${CERTIFYING_MIN_HELDOUT_SEEDS})`
        : null

  if (burnedSeedsDetected.length > 0) {
    criteria.push(criterion(
      'heldout_seed_hygiene',
      'Held-out certification uses only fresh unburned salted seeds (not in BURNED_SEEDS)',
      '0 burned seeds (n >= 3 fresh salted seeds)',
      allowBurnedDev
        ? `dev-2 override (--allow-burned-dev; NON-CERTIFYING): burned seed(s) [${burnedSeedsDetected.join(', ')}]`
        : `refused burned seed(s) [${burnedSeedsDetected.join(', ')}] in BURNED_SEEDS`,
      allowBurnedDev,
    ))
  }

  if (runs.some(run => run.notes.length)) {
    for (const run of runs) {
      for (const note of run.notes) {
        const text = `${run.app}@${run.seed}: ${note}`
        if (!notes.includes(text)) notes.push(text)
      }
    }
  }

  const ingestRefusals: string[] = []
  const explicitVersions = runs
    .filter(r => r.benchmarkVersion !== undefined)
    .map(r => (typeof r.benchmarkVersion === 'string' ? r.benchmarkVersion.trim() : ''))
  const nonEmptyVersions = [...new Set(explicitVersions.filter(Boolean))]
  const nullVersionCount = explicitVersions.filter(v => !v).length
  if (nullVersionCount > 0) ingestRefusals.push(`${nullVersionCount} run(s) have null/empty benchmarkVersion`)
  if (nonEmptyVersions.length > 1) {
    ingestRefusals.push(`mixed benchmarkVersion across runs (${nonEmptyVersions.map(v => v.slice(0, 12)).join(', ')})`)
  }
  const benchmarkVersion: string | null =
    nonEmptyVersions.length > 1
      ? 'MIXED'
      : nullVersionCount > 0
        ? null
        : nonEmptyVersions.length === 1
          ? nonEmptyVersions[0]!
          : computeBenchmarkVersion('realistic-bench').benchmarkVersion

  const explicitConfigs = runs
    .filter(r => r.effectiveConfigHash !== undefined)
    .map(r => (typeof r.effectiveConfigHash === 'string' ? r.effectiveConfigHash.trim() : ''))
  const nonEmptyConfigs = [...new Set(explicitConfigs.filter(Boolean))]
  const nullConfigCount = explicitConfigs.filter(v => !v).length
  if (nullConfigCount > 0) ingestRefusals.push(`${nullConfigCount} run(s) have null/empty effectiveConfigHash`)
  if (nonEmptyConfigs.length > 1) {
    ingestRefusals.push(`mixed effectiveConfigHash across runs (${nonEmptyConfigs.map(v => v.slice(0, 12)).join(', ')})`)
  }
  const effectiveConfigHash: string | null =
    nullConfigCount > 0 || nonEmptyConfigs.length > 1
      ? null
      : nonEmptyConfigs.length === 1
        ? nonEmptyConfigs[0]!
        : computeEffectiveConfig({
            deterministicOnly: false,
            environment: 'local-lab',
            approvalPolicy: 'auto_review',
            wordlistOn: false,
            mode: 'grey-box',
          }).effectiveConfigHash

  const nonReportableRuns = runs.filter(r => r.reportable === false)
  if (nonReportableRuns.length > 0) {
    ingestRefusals.push(`${nonReportableRuns.length} run(s) marked reportable=false`)
  }
  const wordlistOnRuns = runs.filter(r => r.wordlistOn === true || r.effectiveConfig?.wordlistOn === true)
  if (wordlistOnRuns.length > 0) {
    ingestRefusals.push(`${wordlistOnRuns.length} run(s) ran with wordlistOn=true`)
  }
  const observedSdks = [...new Set(
    runs
      .map(r => (r.sdkVersion ?? r.effectiveConfig?.sdkVersion ?? '').trim())
      .filter(Boolean),
  )]
  const wrongSdks = observedSdks.filter(v => v !== VERIFY_RPC_SDK_VERSION)
  if (wrongSdks.length > 0) {
    ingestRefusals.push(`sdkVersion mismatch (expected ${VERIFY_RPC_SDK_VERSION}, observed ${wrongSdks.join(', ')})`)
  }
  const observedImages = [...new Set(
    runs
      .map(r => (r.workerImageId ?? r.effectiveConfig?.workerImageId ?? '').trim())
      .filter(Boolean),
  )]
  if (observedImages.length > 1) {
    ingestRefusals.push(`mismatched workerImageId across runs (${observedImages.map(v => v.slice(0, 20)).join(', ')})`)
  }

  const finalCertStatus: 'VALID' | 'INVALID' =
    certStatus === 'INVALID' || ingestRefusals.length > 0 ? 'INVALID' : 'VALID'

  if (ingestRefusals.length > 0) {
    criteria.unshift(criterion(
      'provenance_integrity',
      'Runs share one non-null benchmarkVersion & effectiveConfigHash, reportable=true, wordlistOn=false, and matching worker image/sdkVersion',
      '0 provenance/ingest refusals',
      `REFUSED: ${ingestRefusals.join('; ')}`,
      false,
    ))
  }

  if (failedCells > 0) {
    criteria.unshift(criterion(
      'cell_validity',
      'All realism and reason cells completed validly (0 failed/inert cells)',
      '0 failed_inert cells (status VALID)',
      `INVALID (${failedCells} failed_inert cell(s): realism=${failedRealismRuns.length}, reasonFloor=${reasonFloor.failedCells}, reasonAgentic=${reasonAgentic.failedCells})`,
      false,
    ))
  }

  const verdict = finalCertStatus === 'VALID' && criteria.every(item => item.status === 'PASS') ? 'PASS' : 'FAIL'
  return {
    schemaVersion: 1,
    status: finalCertStatus,
    failedCells,
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    gitSha: options.gitSha ?? resolveGitSha(),
    benchmarkVersion,
    effectiveConfigHash,
    certifying,
    nonCertifyingReason,
    heldoutSeeds: heldoutSeedsObserved,
    burnedSeedsDetected,
    mode: options.mode,
    verdict,
    thresholds,
    matrix: {
      expected: { apps, floorDevRuns: devRuns, floorHeldoutRuns, unifiedDevRuns: devRuns, unifiedHeldoutRuns: heldoutRuns },
      observed,
      complete: matrixComplete,
    },
    floor: { dev: dev.floor, heldout: heldout.floor, spread },
    unified: { dev: dev.unified, heldout: heldout.unified },
    concurrency: {
      cell: {
        dev: cellDev.median,
        heldout: cellHeldout.median,
        runs: cellDev.runs + cellHeldout.runs,
        unmeasured: cellDev.unmeasured + cellHeldout.unmeasured,
      },
      worker: {
        dev: workerDev.median,
        heldout: workerHeldout.median,
        runs: workerDev.runs + workerHeldout.runs,
        unmeasured: workerDev.unmeasured + workerHeldout.unmeasured,
      },
      singleWorkerRuns,
    },
    lift: { dev: dev.lift, heldout: heldout.lift, source: 'provenance' },
    provenance: {
      complete: provenanceComplete,
      totalRuns: unifiedAll.length,
      completeRuns: fullyClassified.length,
      perApp: provenancePerApp,
      aggregate: {
        dev: provenanceSummary(unifiedDev),
        heldout: provenanceSummary(unifiedHeldout),
      },
    },
    advisories: {
      noiseCapPerApp: ADVISORY_NOISE_CAP_PER_APP,
      perApp: advisoryPerApp,
      total: advisoryTotal,
      overCap,
      contractLeaks,
    },
    informational,
    preservation: {
      median: preservationMedian,
      ratios: preservationRatios,
      unmeasuredRuns: unmeasuredPreservation,
      keyBased: { dev: keyPreservation('dev'), heldout: keyPreservation('held-out') },
    },
    precision: { worst: worstPrecision, worstRun: worstRun?.id ?? null, decoyFalsePositives: decoyFP, unmatchedFalsePositives: unmatchedFP, runs: runs.length },
    hygiene: { incompatibleClassCount, incompatibleClassUnmeasured, worstStrictPrecision, misclassifiedRuns, misclassifiedFindingIds },
    leads: { checkedRuns: leadsChecked, unmeasuredRuns: leadsUnmeasured, violations: leadViolations },
    reason: {
      floor: { confirmed: reasonFloor.confirmed, targets: reasonFloor.targets, recall: reasonFloor.recall },
      agentic: {
        confirmed: reasonAgentic.confirmed,
        targets: reasonAgentic.targets,
        recall: reasonAgentic.recall,
        worstPrecision: reasonAgentic.precision,
        cells: reasonAgenticCells.length,
      },
    },
    criteria,
    notes,
  }
}

// ---------------------------------------------------------------------------------------------
// Rendering and secret hygiene
// ---------------------------------------------------------------------------------------------

export function redactText(text: string, secrets: string[]): string {
  let out = text
  for (const secret of secrets) {
    if (secret && secret.length >= 8) out = out.split(secret).join('[redacted]')
  }
  return out
}

export function assertSecretFree(text: string, secrets: string[]): void {
  for (const secret of secrets) {
    if (secret && secret.length >= 8 && text.includes(secret)) {
      throw new Error('refusing to write an artifact containing a secret value')
    }
  }
}

function artifactSecrets(env: NodeJS.ProcessEnv): string[] {
  const salt = env.KOVO_RB_HELDOUT_SALT ?? ''
  return salt.length >= 8 ? [salt] : []
}

export function renderCertificateMarkdown(cert: Certificate): string {
  const lines: string[] = []
  lines.push('# Kovo v6 Phase-1 certification')
  lines.push('')
  lines.push(`**Verdict: ${cert.verdict}** (status: \`${cert.status}\`, failedCells: ${cert.failedCells})`)
  lines.push('')
  lines.push(`- mode: \`${cert.mode}\``)
  lines.push(`- generated: ${cert.generatedAt}`)
  lines.push(`- git: \`${cert.gitSha}\``)
  lines.push(`- realism cells: ${cert.precision.runs}, reason agentic baseline cells: ${cert.reason.agentic.cells}`)
  lines.push('')
  lines.push('## Harness concurrency')
  lines.push('')
  lines.push(`- cells in parallel (median): dev ${cert.concurrency.cell.dev ?? 'unmeasured'}, held-out ${cert.concurrency.cell.heldout ?? 'unmeasured'} (${cert.concurrency.cell.unmeasured} unmeasured)`)
  lines.push(`- workers inside each cell (median): dev ${cert.concurrency.worker.dev ?? 'unmeasured'}, held-out ${cert.concurrency.worker.heldout ?? 'unmeasured'} (${cert.concurrency.worker.unmeasured} unmeasured)`)
  if (cert.concurrency.singleWorkerRuns.length) {
    lines.push(`- single-worker runs: ${cert.concurrency.singleWorkerRuns.join(', ')}`)
  }
  lines.push('')
  lines.push('## Criteria')
  lines.push('')
  lines.push('| criterion | threshold | observed | status |')
  lines.push('| --- | --- | --- | --- |')
  for (const item of cert.criteria) {
    lines.push(`| ${item.id} | ${item.threshold} | ${item.observed} | **${item.status}** |`)
  }
  lines.push('')
  lines.push('## Floor recall (median [min-max])')
  lines.push('')
  lines.push('| app | dev | salted held-out | spread (targets) |')
  lines.push('| --- | --- | --- | --- |')
  for (const app of cert.matrix.expected.apps) {
    const dev = cert.floor.dev.perApp[app]
    const held = cert.floor.heldout.perApp[app]
    const fmt = (stats: RunStats | null) => stats
      ? `${stats.confirmed}/${stats.targets} ${pct(stats.recall)} [${pct(stats.minRecall)}-${pct(stats.maxRecall)}] (n=${stats.runs})`
      : 'unmeasured'
    lines.push(`| ${app} | ${fmt(dev)} | ${fmt(held)} | ${cert.floor.spread[app] ?? 'n/a'} |`)
  }
  lines.push(`| **aggregate** | ${cert.floor.dev.confirmed}/${cert.floor.dev.targets} ${pct(cert.floor.dev.recall)} | ${cert.floor.heldout.confirmed}/${cert.floor.heldout.targets} ${pct(cert.floor.heldout.recall)} | - |`)
  lines.push('')
  lines.push('## Provenance of confirmed findings')
  lines.push('')
  lines.push(`Provenance completeness: **${cert.provenance.complete ? 'complete' : 'incomplete'}** (${cert.provenance.completeRuns}/${cert.provenance.totalRuns} unified runs fully classified).`)
  lines.push('')
  lines.push('| app | split | classified runs | floor | agent_only | chain_from_floor | incremental | provenanced lift |')
  lines.push('| --- | --- | --- | --- | --- | --- | --- | --- |')
  const fmtProvenance = (summary: ProvenanceSummary | null, lift: number | null | undefined) => {
    if (!summary) return ['unmeasured', 'n/a', 'n/a', 'n/a', 'n/a', 'n/a']
    return [
      `${summary.completeRuns}/${summary.runs}`,
      String(summary.floor),
      String(summary.agentOnly),
      String(summary.chainFromFloor),
      summary.incremental === null ? 'unmeasured' : String(summary.incremental),
      lift === null || lift === undefined ? 'n/a' : `${lift >= 0 ? '+' : ''}${(lift * 100).toFixed(1)}pp`,
    ]
  }
  for (const app of cert.matrix.expected.apps) {
    for (const [split, summary, lift] of [
      ['dev', cert.provenance.perApp[app]?.dev ?? null, cert.lift.dev.perApp[app]],
      ['held-out', cert.provenance.perApp[app]?.heldout ?? null, cert.lift.heldout.perApp[app]],
    ] as const) {
      lines.push(`| ${app} | ${split} | ${fmtProvenance(summary, lift).join(' | ')} |`)
    }
  }
  for (const [split, summary, lift] of [
    ['dev', cert.provenance.aggregate.dev, cert.lift.dev.aggregate],
    ['held-out', cert.provenance.aggregate.heldout, cert.lift.heldout.aggregate],
  ] as const) {
    lines.push(`| **aggregate** | ${split} | ${fmtProvenance(summary, lift).join(' | ')} |`)
  }
  lines.push('')
  lines.push('## Unified product recall and lift')
  lines.push('')
  lines.push('Lift is provenance-derived (`agent_only + chain_from_floor`), not `total - floor`.')
  lines.push('| app | dev total | dev lift | held-out total | held-out lift |')
  lines.push('| --- | --- | --- | --- | --- |')
  for (const app of cert.matrix.expected.apps) {
    const dev = cert.unified.dev.perApp[app]
    const held = cert.unified.heldout.perApp[app]
    const fmt = (stats: UnifiedAppStats | null) => stats
      ? `${stats.confirmed}/${stats.targets} ${pct(stats.recall)} [${pct(stats.minRecall)}-${pct(stats.maxRecall)}] (cov ${stats.coverageConfirmed})`
      : 'unmeasured'
    const fmtLift = (value: number | null | undefined) => value === null || value === undefined ? 'n/a' : `${value >= 0 ? '+' : ''}${(value * 100).toFixed(1)}pp`
    lines.push(`| ${app} | ${fmt(dev)} | ${fmtLift(cert.lift.dev.perApp[app])} | ${fmt(held)} | ${fmtLift(cert.lift.heldout.perApp[app])} |`)
  }
  lines.push(`| **aggregate** | ${cert.unified.dev.confirmed}/${cert.unified.dev.targets} ${pct(cert.unified.dev.recall)} | ${cert.lift.dev.aggregate === null ? 'n/a' : `${cert.lift.dev.aggregate >= 0 ? '+' : ''}${(cert.lift.dev.aggregate * 100).toFixed(1)}pp`} | ${cert.unified.heldout.confirmed}/${cert.unified.heldout.targets} ${pct(cert.unified.heldout.recall)} | ${cert.lift.heldout.aggregate === null ? 'n/a' : `${cert.lift.heldout.aggregate >= 0 ? '+' : ''}${(cert.lift.heldout.aggregate * 100).toFixed(1)}pp`} |`)
  lines.push('')
  lines.push('## Preservation, precision and leads')
  lines.push('')
  lines.push(`- floor preservation (median): ${cert.preservation.median === null ? 'unmeasured' : cert.preservation.median.toFixed(3)}`
    + ` (${cert.preservation.ratios.length} measured, ${cert.preservation.unmeasuredRuns} unmeasured)`)
  lines.push(`- key-based floor retention: dev ${cert.preservation.keyBased.dev === null ? 'n/a' : pct(cert.preservation.keyBased.dev)}, held-out ${cert.preservation.keyBased.heldout === null ? 'n/a' : pct(cert.preservation.keyBased.heldout)}`)
  lines.push(`- worst-run precision: ${cert.precision.worst === null ? 'n/a' : cert.precision.worst.toFixed(3)}; decoy FP ${cert.precision.decoyFalsePositives}; unmatched FP ${cert.precision.unmatchedFalsePositives}`)
  lines.push(`- class hygiene: ${cert.hygiene.incompatibleClassCount} incompatible class claim(s) (${cert.hygiene.incompatibleClassUnmeasured} unmeasured); worst strict precision ${cert.hygiene.worstStrictPrecision === null ? 'n/a' : cert.hygiene.worstStrictPrecision.toFixed(3)}; ${cert.hygiene.misclassifiedFindingIds.length} uncharged misclassification(s) in ${cert.hygiene.misclassifiedRuns} run(s)`)
  lines.push(`- leads invariant: ${cert.leads.violations.length} violation(s), ${cert.leads.unmeasuredRuns} unmeasured, ${cert.leads.checkedRuns} checked`)
  lines.push('')
  lines.push('## Advisories (outside confirmed recall/precision)')
  lines.push('')
  lines.push(`Noise cap: <= ${cert.advisories.noiseCapPerApp}/app on the worst run; total advisories ${cert.advisories.total}; contract leaks ${cert.advisories.contractLeaks}.`)
  lines.push('')
  lines.push('| app | dev | held-out | dev worst run | held-out worst run | over cap |')
  lines.push('| --- | --- | --- | --- | --- | --- |')
  for (const app of cert.matrix.expected.apps) {
    const row = cert.advisories.perApp[app]
    if (!row) continue
    lines.push(`| ${app} | ${row.dev} | ${row.heldout} | ${row.devWorst} | ${row.heldoutWorst} | ${cert.advisories.overCap.includes(app) ? 'YES' : 'no'} |`)
  }
  lines.push('')
  lines.push('## Reason-bench (mandatory floor)')
  lines.push('')
  lines.push(`- floor: ${cert.reason.floor.confirmed}/${cert.reason.floor.targets} (must be 0/${cert.thresholds.reasonTargets})`)
  lines.push('')
  lines.push('## Non-blocking reason baseline (Phase 3)')
  lines.push('')
  for (const item of cert.informational) {
    lines.push(`- **${item.id}**: ${item.status} — ${item.observed} (target ${item.target}). ${item.description}`)
  }
  lines.push('')
  if (cert.notes.length) {
    lines.push('## Notes')
    lines.push('')
    for (const note of cert.notes) lines.push(`- ${note}`)
    lines.push('')
  }
  return `${lines.join('\n')}\n`
}

function resolveGitSha(): string {
  try {
    return execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], {
      cwd: resolve(import.meta.dirname, '..'),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim() || 'unknown'
  } catch {
    return 'unknown'
  }
}

// ---------------------------------------------------------------------------------------------
// Run mode
// ---------------------------------------------------------------------------------------------

export interface RunPlanCell {
  id: string
  kind: 'floor-dev' | 'floor-heldout' | 'unified-dev' | 'unified-heldout' | 'reason-floor' | 'reason-agentic'
  app: string
  seed: number
  heldOut: boolean
  outDir: string
  dataDir: string | null
  args: string[]
}

export interface RunPlanOptions {
  outDir: string
  apps: string[]
  devSeed: number
  /** Legacy single held-out seed (rejected if in BURNED_SEEDS unless allowBurnedDev=true). */
  heldoutSeed?: number
  /** Preferred n >= 3 fresh unburned salted held-out seeds for certification. */
  heldoutSeeds?: number[]
  /** Explicit dev-2 debugging override permitting burned seeds (stamps non-certifying). */
  allowBurnedDev?: boolean
  /** Optional held-out salt for drawing fresh seeds when heldoutSeeds/heldoutSeed are omitted. */
  heldOutSalt?: string
  devRuns: number
  floorHeldoutRuns: number
  heldoutRuns: number
  dataDir: string | null
  verifier: 'auto' | 'docker' | 'local-jq'
  budgetUsd: number
  maxDurationMs: number
  reasonRuns: number
  mode: string
  /** In-run worker slots passed to every agentic cell (null: harness default). */
  workerConcurrency?: number | null
}

export function buildRunPlan(options: RunPlanOptions): RunPlanCell[] {
  const allowBurnedDev = options.allowBurnedDev === true
  let heldoutSeeds: number[]
  if (options.heldoutSeeds && options.heldoutSeeds.length > 0) {
    heldoutSeeds = [...new Set(options.heldoutSeeds)]
  } else if (options.heldoutSeed !== undefined) {
    heldoutSeeds = [options.heldoutSeed]
  } else {
    const drawCount = Math.max(CERTIFYING_MIN_HELDOUT_SEEDS, options.heldoutRuns, options.floorHeldoutRuns)
    heldoutSeeds = drawUnburnedHeldoutSeeds(drawCount, options.heldOutSalt)
  }

  for (const seed of heldoutSeeds) {
    if (seed < 1_000_000) {
      throw new Error(`certify-phase1: held-out seeds must be >= 1000000 (got ${seed})`)
    }
  }
  assertNoBurnedSeeds(heldoutSeeds, { allowBurnedDev, context: 'certify-phase1' })
  if (!allowBurnedDev && heldoutSeeds.length < CERTIFYING_MIN_HELDOUT_SEEDS) {
    throw new Error(
      `certify-phase1: certifying held-out runs require >= ${CERTIFYING_MIN_HELDOUT_SEEDS} fresh unburned `
        + `salted seeds (got ${heldoutSeeds.length}: [${heldoutSeeds.join(', ')}]); omit --heldout-seed to draw `
        + `${CERTIFYING_MIN_HELDOUT_SEEDS} fresh seeds automatically or pass --allow-burned-dev for dev-2 debugging`,
    )
  }

  const cells: RunPlanCell[] = []
  const base = ['--mode', options.mode, '--verifier', options.verifier, '--keep-data-dirs']
  const workerArgs = options.workerConcurrency
    ? ['--worker-concurrency', String(options.workerConcurrency)]
    : []
  const realistic = (args: string[]) => [resolve(import.meta.dirname, 'benchmark-realistic.ts'), ...args]

  for (const app of options.apps) {
    for (let i = 1; i <= options.devRuns; i += 1) {
      const outDir = join(options.outDir, 'floor', 'dev', `${app}-r${i}`)
      cells.push({
        id: `floor-dev-${app}-r${i}`,
        kind: 'floor-dev', app, seed: options.devSeed, heldOut: false, outDir, dataDir: null,
        args: realistic(['--app', app, '--seed', String(options.devSeed), '--out-dir', outDir, ...base, '--no-llm']),
      })
    }
    for (let i = 1; i <= options.floorHeldoutRuns; i += 1) {
      const seed = heldoutSeeds[(i - 1) % heldoutSeeds.length]!
      const outDir = join(options.outDir, 'floor', 'heldout', `${app}-r${i}`)
      cells.push({
        id: `floor-heldout-${app}-r${i}`,
        kind: 'floor-heldout', app, seed, heldOut: true, outDir, dataDir: null,
        args: realistic(['--app', app, '--seed', String(seed), '--out-dir', outDir, ...base, '--no-llm', '--held-out']),
      })
    }
    for (let i = 1; i <= options.devRuns; i += 1) {
      const outDir = join(options.outDir, 'unified', 'dev', `${app}-r${i}`)
      cells.push({
        id: `unified-dev-${app}-r${i}`,
        kind: 'unified-dev', app, seed: options.devSeed, heldOut: false, outDir, dataDir: options.dataDir,
        args: realistic([
          '--app', app, '--seed', String(options.devSeed), '--out-dir', outDir, ...base,
          '--isolate-data-dir', '--budget-usd', String(options.budgetUsd),
          '--max-duration-ms', String(options.maxDurationMs), ...workerArgs,
          ...(options.dataDir ? ['--data-dir', options.dataDir] : []),
        ]),
      })
    }
    for (let i = 1; i <= options.heldoutRuns; i += 1) {
      const seed = heldoutSeeds[(i - 1) % heldoutSeeds.length]!
      const outDir = join(options.outDir, 'unified', 'heldout', `${app}-r${i}`)
      cells.push({
        id: `unified-heldout-${app}-r${i}`,
        kind: 'unified-heldout', app, seed, heldOut: true, outDir, dataDir: options.dataDir,
        args: realistic([
          '--app', app, '--seed', String(seed), '--out-dir', outDir, ...base,
          '--isolate-data-dir', '--budget-usd', String(options.budgetUsd),
          '--max-duration-ms', String(options.maxDurationMs), '--held-out', ...workerArgs,
          ...(options.dataDir ? ['--data-dir', options.dataDir] : []),
        ]),
      })
    }
  }

  const reason = (args: string[]) => [resolve(import.meta.dirname, 'benchmark-reason.ts'), ...args]
  for (let i = 1; i <= options.reasonRuns; i += 1) {
    const floorDir = join(options.outDir, 'reason', `floor-r${i}`)
    cells.push({
      id: `reason-floor-r${i}`,
      kind: 'reason-floor', app: 'all', seed: options.devSeed, heldOut: false, outDir: floorDir, dataDir: null,
      args: reason([
        '--app', 'all', '--seed', String(options.devSeed), '--out-dir', floorDir,
        '--json', join(floorDir, 'reason-report.json'), '--mode', options.mode,
        '--verifier', options.verifier, '--keep-data-dirs', '--no-llm',
      ]),
    })
  }
  for (let i = 1; i <= options.reasonRuns; i += 1) {
    const outDir = join(options.outDir, 'reason', `agentic-r${i}`)
    const floorDir = i === 1 ? join(options.outDir, 'reason', `floor-r${i}`) : join(options.outDir, 'reason', `floor-r1`)
    cells.push({
      id: `reason-agentic-r${i}`,
      kind: 'reason-agentic', app: 'all', seed: options.devSeed, heldOut: false, outDir, dataDir: options.dataDir,
      args: reason([
        '--app', 'all', '--seed', String(options.devSeed), '--out-dir', outDir,
        '--json', join(outDir, 'reason-report.json'), '--mode', options.mode,
        '--verifier', options.verifier, '--keep-data-dirs',
        '--budget-usd', String(options.budgetUsd), '--max-duration-ms', String(options.maxDurationMs),
        '--floor-from', floorDir,
        ...(options.dataDir ? ['--data-dir', options.dataDir, '--isolate-data-dir'] : []),
      ]),
    })
  }
  return cells
}

function shellQuote(args: string[]): string {
  return args.map(arg => (
    /^[A-Za-z0-9_./:=+-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`
  )).join(' ')
}

interface ExecuteOptions {
  useNewgrp: boolean
  concurrency: number
  abort: AbortSignal
  log: (line: string) => void
}

async function runCell(cell: RunPlanCell, options: ExecuteOptions): Promise<{ cell: RunPlanCell; code: number | null; signal: string | null; error?: string }> {
  mkdirSync(cell.outDir, { recursive: true, mode: 0o700 })
  cleanupCellIds.add(cell.id)
  const logPath = join(cell.outDir, 'run.log')
  let logFd: number | null = null
  try { logFd = openSync(logPath, 'w', 0o600) } catch { logFd = null }
  const node = process.execPath
  const command = [node, ...cell.args]
  const spawnArgs = options.useNewgrp
    ? { cmd: 'newgrp', args: ['docker', '-c', shellQuote(command)] }
    : { cmd: command[0]!, args: command.slice(1) }
  return await new Promise((resolvePromise) => {
    let child: ChildProcess
    try {
      child = spawn(spawnArgs.cmd, spawnArgs.args, {
        cwd: resolve(import.meta.dirname, '..'),
        detached: true,
        stdio: ['ignore', logFd ?? 'ignore', logFd ?? 'ignore'],
        env: { ...process.env, KOVO_ALLOW_LOCAL_LAB: '1', KOVO_CELL_ID: cell.id },
      })
    } catch (error) {
      if (logFd !== null) { try { closeSync(logFd) } catch { /* already closed */ } }
      resolvePromise({ cell, code: null, signal: null, error: (error as Error).message })
      return
    }
    liveChildren.add(child)
    const done = (code: number | null, signal: string | null, error?: string): void => {
      liveChildren.delete(child)
      if (logFd !== null) { try { closeSync(logFd) } catch { /* already closed */ } }
      resolvePromise({ cell, code, signal, ...(error ? { error } : {}) })
    }
    child.once('error', error => done(null, null, error.message))
    child.once('exit', (code, signal) => done(code, signal))
    options.abort.addEventListener('abort', () => {
      try { if (child.pid) process.kill(-child.pid, 'SIGTERM') } catch { /* already gone */ }
    }, { once: true })
    options.log(`[certify] started ${cell.id} -> ${relative(process.cwd(), cell.outDir)}`)
  })
}

const liveChildren = new Set<ChildProcess>()
const cleanupCellIds = new Set<string>()
let cleanupUseNewgrp = false

function runDocker(args: string[]): string {
  if (cleanupUseNewgrp) {
    return execFileSync('newgrp', ['docker', '-c', shellQuote(args)], {
      encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'ignore'],
    })
  }
  return execFileSync(args[0]!, args.slice(1), {
    encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'ignore'],
  })
}

/** Best-effort removal of worker containers labelled with this runner's own cell ids. */
function cleanupContainers(): void {
  if (!cleanupCellIds.size) return
  const ids: string[] = []
  for (const cell of cleanupCellIds) {
    try {
      const listed = runDocker(['docker', 'ps', '-aq', '--filter', `label=dev.kovo.cell=${cell}`])
      ids.push(...listed.split('\n').map(line => line.trim()).filter(Boolean))
    } catch { /* docker not reachable in this process (newgrp off / no group) */ }
  }
  const uniqueIds = [...new Set(ids)]
  if (!uniqueIds.length) return
  try { runDocker(['docker', 'rm', '-f', ...uniqueIds]) } catch { /* best effort */ }
}

function killLiveChildren(): void {
  for (const child of liveChildren) {
    try { if (child.pid) process.kill(-child.pid, 'SIGTERM') } catch { /* already gone */ }
  }
}

function cleanupDataDirs(root: string): void {
  const stack: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }]
  while (stack.length) {
    const item = stack.pop()!
    if (item.depth > 4) continue
    let entries: string[]
    try { entries = readdirSync(item.dir) } catch { continue }
    for (const entry of entries) {
      const path = join(item.dir, entry)
      let stat
      try { stat = statSync(path) } catch { continue }
      if (!stat.isDirectory()) continue
      if (entry === 'data') {
        try { rmSync(path, { recursive: true, force: true }) } catch { /* best effort */ }
        continue
      }
      stack.push({ dir: path, depth: item.depth + 1 })
    }
  }
}

async function executeRunPlan(plan: RunPlanCell[], options: ExecuteOptions): Promise<Array<{ id: string; code: number | null; signal: string | null; error?: string }>> {
  const results: Array<{ id: string; code: number | null; signal: string | null; error?: string }> = []
  let next = 0
  const workers = Array.from({ length: Math.max(1, Math.min(options.concurrency, plan.length)) }, async () => {
    while (true) {
      if (options.abort.aborted) return
      const index = next++
      if (index >= plan.length) return
      const result = await runCell(plan[index]!, options)
      results.push({ id: result.cell.id, code: result.code, signal: result.signal, ...(result.error ? { error: result.error } : {}) })
      options.log(`[certify] finished ${result.cell.id}: ${result.error ?? (result.signal ? `signal ${result.signal}` : `exit ${result.code}`)}`)
      if (result.code !== 0 && result.code !== 3) {
        // Keep going: the certificate reports the missing cell rather than hiding it.
        options.log(`[certify] warning: ${result.cell.id} exited ${result.code ?? result.signal}; certificate will fail unmeasured criteria`)
      }
    }
  })
  await Promise.all(workers)
  return results
}

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------

export interface CliOptions {
  fromDirs: string[]
  run: boolean
  dryRun: boolean
  outDir: string
  jsonPath: string | null
  mdPath: string | null
  apps: string[]
  devSeed: number
  heldoutSeeds: number[] | null
  allowBurnedDev: boolean
  certifying: boolean
  devRuns: number
  floorHeldoutRuns: number
  heldoutRuns: number
  concurrency: number
  /** In-run worker slots per agentic cell; null lets the harness default (6 agentic / 1 floor). */
  workerConcurrency: number | null
  dataDir: string | null
  verifier: 'auto' | 'docker' | 'local-jq'
  useNewgrp: boolean
  budgetUsd: number
  maxDurationMs: number
  reasonRuns: number
  skipReason: boolean
  keepDataDirs: boolean
  checkMatrix: boolean
  ledgerPath?: string | null
  promoteLedgerPath?: string | null
  help: boolean
}

const usage = `Kovo v6 Phase-1 certification

Usage:
  npm run certify:phase1 -- --run [flags]        execute the matrix
  npm run certify:phase1 -- --from-dir <dir>     ingest existing reports (no spend)

Flags:
  --run                     spawn floor + unified + reason harnesses with per-cell dirs
  --dry-run                 print the --run plan as JSON and exit (implies --run)
  --from-dir <dir>          artifact directory to ingest (repeatable)
  --out-dir <dir>           certificate directory (default .kovo/certify-phase1)
  --json <path>             certificate JSON path (default <out-dir>/certificate.json)
  --md <path>               certificate Markdown path (default <out-dir>/certificate.md)
  --apps <all|a,b>          apps for the realism matrix (default all three)
  --dev-seed <n>            dev seed (default ${DEV_SEED})
  --heldout-seeds <a,b,c>   >= ${CERTIFYING_MIN_HELDOUT_SEEDS} fresh unburned salted held-out seeds (default: auto-drawn via listSeeds)
  --heldout-seed <n>        single held-out seed (requires --allow-burned-dev; non-certifying)
  --allow-burned-dev        dev-2 debugging only: permit burned seeds in BURNED_SEEDS (stamps certifying=false)
  --dev-runs <n>            floor and unified runs per app on dev (default 3)
  --floor-heldout-runs <n>  floor runs per app on held-out (default ${CERTIFYING_MIN_HELDOUT_SEEDS})
  --heldout-runs <n>        unified runs per app on held-out (default ${CERTIFYING_MIN_HELDOUT_SEEDS})
  --concurrency <n>         concurrent harness processes (default 3) — cell scheduling only
  --worker-concurrency <n>  in-run worker slots per agentic cell (default: harness default:
                            6 agentic / 1 deterministic). Independent of --concurrency.
  --data-dir <path>         Kovo data dir with an enabled model profile
                            (default $KOVO_DATA_DIR); required for --run agentic
  --verifier <kind>         auto | docker | local-jq (default docker for --run)
  --use-newgrp              wrap harnesses in 'newgrp docker -c' (Docker socket group)
  --budget-usd <n>          per-cell agentic budget (default 5)
  --max-duration-ms <n>     per-cell wall clock (default 600000)
  --reason-runs <n>         reason-bench runs per mode (default 1)
  --skip-reason             do not schedule reason-bench in --run mode
  --keep-data-dirs          keep per-cell data dirs (default: removed after the certificate)
  --no-matrix-check         do not fail on incomplete n (still reports counts)
  --help                    show this help

Environment:
  KOVO_ALLOW_LOCAL_LAB=1   required by the harnesses (set automatically for children)
  KOVO_RB_HELDOUT_SALT     required for --run held-out cells; never written to artifacts
  KOVO_DATA_DIR            default Kovo data dir

Verdict thresholds:
  floor spread <= ${DEFAULT_THRESHOLDS.floorSpreadMax} target; preservation >= ${DEFAULT_THRESHOLDS.preservationMin};
  worst confirmed precision == ${DEFAULT_THRESHOLDS.worstPrecision}; provenance complete;
  provenance-derived lift >= +${(DEFAULT_THRESHOLDS.liftDevMin * 100).toFixed(0)}pp dev /
  +${(DEFAULT_THRESHOLDS.liftHeldoutMin * 100).toFixed(0)}pp held-out; advisories <= ${ADVISORY_NOISE_CAP_PER_APP}/app;
  reason floor 0/${DEFAULT_THRESHOLDS.reasonTargets}. The reason agentic ${(DEFAULT_THRESHOLDS.reasonAgenticMin * 100).toFixed(0)}%
  baseline is Phase 3 and non-blocking.

Artifacts (owner-only):
  <out-dir>/certificate.json   machine-readable certificate
  <out-dir>/certificate.md     Markdown summary
  <out-dir>/<cell>/run.log      child stdout/stderr (raw output stays out of the summary)
`

function fail(message: string): never {
  throw new Error(message)
}

function parsePositiveInt(raw: string, flag: string): number {
  const value = Number(raw)
  if (!Number.isInteger(value) || value <= 0) fail(`${flag} must be a positive integer (got '${raw}')`)
  return value
}

/** In-run worker slots are optional here: absent means "use the harness default". */
function parseOptionalWorkerConcurrency(raw: unknown): number | null {
  if (raw === undefined) return null
  if (raw === true) fail('--worker-concurrency requires a number')
  const value = parsePositiveInt(String(raw), '--worker-concurrency')
  if (value > MAX_RUN_WORKER_CONCURRENCY) {
    fail(`--worker-concurrency must be between 1 and ${MAX_RUN_WORKER_CONCURRENCY} (got '${String(raw)}')`)
  }
  return value
}

export function parseCli(argv: string[], env: NodeJS.ProcessEnv = process.env): CliOptions {
  const a: Record<string, string | boolean | string[]> = {}
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (!arg.startsWith('--')) fail(`unexpected argument '${arg}'`)
    const equal = arg.indexOf('=')
    const key = equal >= 0 ? arg.slice(2, equal) : arg.slice(2)
    if (!key) fail('empty flag')
    let value: string | boolean
    if (equal >= 0) value = arg.slice(equal + 1)
    else {
      const next = argv[i + 1]
      if (next === undefined || next.startsWith('--')) value = true
      else { value = next; i += 1 }
    }
    if (key === 'from-dir') {
      const list = Array.isArray(a[key]) ? a[key] as string[] : []
      list.push(String(value))
      a[key] = list
    } else a[key] = value
  }

  const known = new Set([
    'run', 'dry-run', 'from-dir', 'out-dir', 'json', 'md', 'apps', 'dev-seed',
    'heldout-seed', 'heldout-seeds', 'allow-burned-dev',
    'dev-runs', 'floor-heldout-runs', 'heldout-runs', 'concurrency', 'worker-concurrency', 'data-dir', 'verifier',
    'use-newgrp', 'budget-usd', 'max-duration-ms', 'reason-runs', 'skip-reason', 'keep-data-dirs',
    'no-matrix-check', 'ledger', 'promote-ledger', 'help',
  ])
  for (const key of Object.keys(a)) if (!known.has(key)) fail(`unknown flag --${key}`)
  if (a.help === true) {
    return {
      fromDirs: [], run: false, dryRun: false, outDir: resolve('.kovo/certify-phase1'),
      jsonPath: null, mdPath: null, apps: [...CERTIFY_APPS], devSeed: DEV_SEED,
      heldoutSeeds: null, allowBurnedDev: false, certifying: true,
      devRuns: 3, floorHeldoutRuns: CERTIFYING_MIN_HELDOUT_SEEDS, heldoutRuns: CERTIFYING_MIN_HELDOUT_SEEDS,
      concurrency: 3, workerConcurrency: null, dataDir: null,
      verifier: 'docker', useNewgrp: false, budgetUsd: 5, maxDurationMs: 600_000, reasonRuns: 1,
      skipReason: false, keepDataDirs: false, checkMatrix: true, help: true,
    }
  }

  const run = a.run === true
  const fromDirs = (a['from-dir'] as string[] | undefined) ?? []
  if (!run && !fromDirs.length) fail('use --run or --from-dir <dir>')
  if (run && fromDirs.length) fail('use either --run or --from-dir, not both')
  const dryRun = a['dry-run'] === true
  const allowBurnedDev = a['allow-burned-dev'] === true
  const appsRaw = typeof a.apps === 'string' ? a.apps : 'all'
  const apps = appsRaw === 'all' ? [...CERTIFY_APPS] : appsRaw.split(',').map(s => s.trim()).filter(Boolean)
  for (const app of apps) if (!CERTIFY_APPS.includes(app as typeof CERTIFY_APPS[number])) fail(`--apps must be ${CERTIFY_APPS.join(', ')} or all (got '${app}')`)
  const verifier = typeof a.verifier === 'string' ? a.verifier : 'docker'
  if (verifier !== 'auto' && verifier !== 'docker' && verifier !== 'local-jq') fail(`--verifier must be auto, docker or local-jq (got '${verifier}')`)
  const dataDir = typeof a['data-dir'] === 'string' ? resolve(a['data-dir']) : (env.KOVO_DATA_DIR ? resolve(env.KOVO_DATA_DIR) : null)

  const floorHeldoutRuns = parsePositiveInt(
    typeof a['floor-heldout-runs'] === 'string' ? a['floor-heldout-runs'] : String(CERTIFYING_MIN_HELDOUT_SEEDS),
    '--floor-heldout-runs',
  )
  const heldoutRuns = parsePositiveInt(
    typeof a['heldout-runs'] === 'string' ? a['heldout-runs'] : String(CERTIFYING_MIN_HELDOUT_SEEDS),
    '--heldout-runs',
  )

  if (a['heldout-seed'] !== undefined && a['heldout-seeds'] !== undefined) {
    fail('use either --heldout-seed or --heldout-seeds, not both')
  }
  let heldoutSeeds: number[] | null = null
  if (typeof a['heldout-seeds'] === 'string') {
    heldoutSeeds = [...new Set(
      a['heldout-seeds']
        .split(',')
        .map(s => s.trim())
        .filter(Boolean)
        .map(s => parsePositiveInt(s, '--heldout-seeds')),
    )]
    if (!heldoutSeeds.length) fail('--heldout-seeds requires at least one seed')
  } else if (typeof a['heldout-seed'] === 'string') {
    heldoutSeeds = [parsePositiveInt(a['heldout-seed'], '--heldout-seed')]
  } else if (run && (env.KOVO_RB_HELDOUT_SALT ?? '').length >= 16) {
    heldoutSeeds = drawUnburnedHeldoutSeeds(
      Math.max(CERTIFYING_MIN_HELDOUT_SEEDS, heldoutRuns, floorHeldoutRuns),
      env.KOVO_RB_HELDOUT_SALT,
    )
  }

  if (heldoutSeeds !== null) {
    for (const seed of heldoutSeeds) {
      if (seed < 1_000_000) fail(`--heldout-seeds must be >= 1000000 (salted held-out split; got ${seed})`)
    }
    assertNoBurnedSeeds(heldoutSeeds, { allowBurnedDev, context: 'certify-phase1' })
    if (!allowBurnedDev && heldoutSeeds.length < CERTIFYING_MIN_HELDOUT_SEEDS) {
      fail(
        `certify-phase1 requires >= ${CERTIFYING_MIN_HELDOUT_SEEDS} fresh unburned salted held-out seeds `
          + `(got ${heldoutSeeds.length}); omit --heldout-seed to auto-draw or pass --allow-burned-dev for dev-2 debugging`,
      )
    }
  }

  const certifying = !allowBurnedDev && (heldoutSeeds === null || heldoutSeeds.length >= CERTIFYING_MIN_HELDOUT_SEEDS)

  return {
    fromDirs: fromDirs.map(dir => resolve(dir)),
    run,
    dryRun,
    outDir: resolve(typeof a['out-dir'] === 'string' ? a['out-dir'] : '.kovo/certify-phase1'),
    jsonPath: typeof a.json === 'string' ? resolve(a.json) : null,
    mdPath: typeof a.md === 'string' ? resolve(a.md) : null,
    apps,
    devSeed: parsePositiveInt(typeof a['dev-seed'] === 'string' ? a['dev-seed'] : String(DEV_SEED), '--dev-seed'),
    heldoutSeeds,
    allowBurnedDev,
    certifying,
    devRuns: parsePositiveInt(typeof a['dev-runs'] === 'string' ? a['dev-runs'] : '3', '--dev-runs'),
    floorHeldoutRuns,
    heldoutRuns,
    concurrency: parsePositiveInt(typeof a.concurrency === 'string' ? a.concurrency : '3', '--concurrency'),
    workerConcurrency: parseOptionalWorkerConcurrency(a['worker-concurrency']),
    dataDir,
    verifier,
    useNewgrp: a['use-newgrp'] === true,
    budgetUsd: asNumber(Number(typeof a['budget-usd'] === 'string' ? a['budget-usd'] : 5), 5),
    maxDurationMs: parsePositiveInt(typeof a['max-duration-ms'] === 'string' ? a['max-duration-ms'] : '600000', '--max-duration-ms'),
    reasonRuns: parsePositiveInt(typeof a['reason-runs'] === 'string' ? a['reason-runs'] : '1', '--reason-runs'),
    skipReason: a['skip-reason'] === true,
    keepDataDirs: a['keep-data-dirs'] === true,
    checkMatrix: a['no-matrix-check'] !== true,
    ledgerPath: a.ledger === true ? DEFAULT_LEDGER_PATH : (typeof a.ledger === 'string' ? a.ledger : null),
    promoteLedgerPath: a['promote-ledger'] === true
      ? DEFAULT_LEDGER_PATH
      : (typeof a['promote-ledger'] === 'string' ? a['promote-ledger'] : null),
    help: false,
  }
}

export function writePhase1CertifyLedgerRows(input: {
  runs: readonly RealismRun[]
  certificate: Certificate
  runId?: string
  runsDir?: string
  ledgerPath?: string | null
  promoteLedgerPath?: string | null
  repoRoot?: string
}): { perRunPath: string; rows: LedgerRow[] } {
  const gitState = resolveGitState(input.repoRoot)
  const rows: LedgerRow[] = []
  let perRunPath = ''
  const runId = input.runId ?? `certify-phase1-${input.certificate.generatedAt.replace(/[:.]/g, '-')}-${process.pid}`
  for (const run of input.runs) {
    const readerCell = ScorecardReader.read(
      {
        app: run.app,
        seed: run.seed,
        seedSet: run.seedSet,
        mode: run.mode,
        llm: run.llm,
        targets: run.targets,
        confirmed: run.confirmed,
        precision: run.precision,
        rawPrecision: run.rawPrecision,
        strictPrecision: run.strictPrecision,
        decoyFalsePositives: run.decoyFalsePositives,
        unmatchedFalsePositives: run.unmatchedFalsePositives,
        misclassifiedFindingIds: run.misclassifiedFindingIds,
      },
      {
        failed: run.cellState === 'failed_inert' || run.failed === true,
        inert: run.inert === true,
        contractLeaks: run.contractLeaks,
      },
    )
    const rowBenchmarkVersion = run.benchmarkVersion ?? input.certificate.benchmarkVersion
    const rowConfigHash = run.effectiveConfigHash ?? input.certificate.effectiveConfigHash
    if (!rowBenchmarkVersion || !rowConfigHash) {
      throw new Error(
        `Refusing to write Phase-1 ledger row for ${run.app}@${run.seed}: missing benchmarkVersion or effectiveConfigHash.`,
      )
    }
    const row = buildLedgerRow({
      cell: readerCell,
      recordedAt: input.certificate.generatedAt,
      suite: 'realistic-bench',
      gitSha: input.certificate.gitSha,
      dirty: gitState.dirty,
      benchmarkVersion: rowBenchmarkVersion,
      effectiveConfigHash: rowConfigHash,
      app: run.app,
      split: run.seedSet,
      mode: run.mode,
      llm: run.llm,
      seed: run.seed,
      repeat: 1,
      certifying: input.certificate.certifying && input.certificate.verdict === 'PASS' && readerCell.state !== 'failed_inert',
      reportable: run.reportable !== false && run.wordlistOn !== true,
      preservationRatio: input.certificate.preservation.median,
      floorConfirmed: run.floor.floorConfirmed,
      agenticConfirmed: run.provenance ? run.provenance.agentOnly + run.provenance.chainFromFloor : null,
      ...(run.seedSet === 'held-out' ? { exposedHeldoutSeeds: [run.seed] } : {}),
    })
    const appended = appendPerRunLedgerRow(row, {
      runId,
      runsDir: input.runsDir,
      repoRoot: input.repoRoot,
    })
    perRunPath = appended.path
    if (input.ledgerPath) {
      appendLedgerRow(row, input.ledgerPath, input.repoRoot)
    }
    rows.push(row)
  }
  if (input.promoteLedgerPath && perRunPath) {
    promoteLedgerRows(perRunPath, {
      targetLedgerPath: input.promoteLedgerPath,
      repoRoot: input.repoRoot,
    })
  }
  return { perRunPath, rows }
}

function writeOwnerOnly(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  writeFileSync(path, text, { mode: 0o600 })
  try { chmodSync(path, 0o600) } catch { /* best effort */ }
}

async function main(): Promise<void> {
  const cli = parseCli(process.argv.slice(2))
  if (cli.help) {
    process.stdout.write(usage)
    return
  }
  if (cli.dryRun && !cli.run) fail('--dry-run requires --run')
  const secrets = artifactSecrets(process.env)
  const abort = new AbortController()
  let interrupted = false

  const onSignal = (signal: NodeJS.Signals): void => {
    interrupted = true
    process.stderr.write(`\n[certify] ${signal}: stopping child process groups and cleaning per-cell data dirs\n`)
    abort.abort()
    killLiveChildren()
    cleanupContainers()
    cleanupDataDirs(cli.outDir)
    process.exit(signal === 'SIGINT' ? 130 : 143)
  }
  process.once('SIGINT', onSignal)
  process.once('SIGTERM', onSignal)

  try {
    let certificate: Certificate
    let ingestedRuns: RealismRun[] = []
    let drawnHeldoutMeta: { seeds: number[]; startIndex: number; endIndex: number } | null = null
    const ingestNotes: string[] = []
    if (cli.run) {
      const salt = process.env.KOVO_RB_HELDOUT_SALT ?? ''
      if (!cli.heldoutSeeds && salt.length < 16) {
        fail('--run requires KOVO_RB_HELDOUT_SALT (>= 16 chars) to draw fresh unburned held-out seeds')
      }
      if (!cli.heldoutSeeds && salt.length >= 16) {
        const drawCount = Math.max(CERTIFYING_MIN_HELDOUT_SEEDS, cli.heldoutRuns, cli.floorHeldoutRuns)
        const drawn = drawUnburnedHeldoutSeedsWithMeta(drawCount, salt)
        drawnHeldoutMeta = { seeds: drawn.seeds, startIndex: drawn.startIndex, endIndex: drawn.endIndex }
      }
      const plan = buildRunPlan({
        outDir: cli.outDir,
        apps: cli.apps,
        devSeed: cli.devSeed,
        ...(cli.heldoutSeeds
          ? { heldoutSeeds: cli.heldoutSeeds }
          : drawnHeldoutMeta
            ? { heldoutSeeds: drawnHeldoutMeta.seeds }
            : { heldOutSalt: salt }),
        allowBurnedDev: cli.allowBurnedDev,
        devRuns: cli.devRuns,
        floorHeldoutRuns: cli.floorHeldoutRuns,
        heldoutRuns: cli.heldoutRuns,
        dataDir: cli.dataDir,
        verifier: cli.verifier,
        budgetUsd: cli.budgetUsd,
        maxDurationMs: cli.maxDurationMs,
        reasonRuns: cli.skipReason ? 0 : cli.reasonRuns,
        mode: 'grey-box',
        workerConcurrency: cli.workerConcurrency,
      })
      if (cli.dryRun) {
        process.stdout.write(`${JSON.stringify({
          certifying: cli.certifying,
          allowBurnedDev: cli.allowBurnedDev,
          cells: plan,
          concurrency: cli.concurrency,
          workerConcurrency: cli.workerConcurrency,
        }, null, 2)}\n`)
        return
      }
      if (salt.length < 16) fail('--run requires KOVO_RB_HELDOUT_SALT (>= 16 chars); the value is never written')
      if (!cli.dataDir) fail('--run agentic cells need --data-dir (or KOVO_DATA_DIR) with an enabled model profile')
      for (const sub of ['floor', 'unified', 'reason']) {
        if (existsSync(join(cli.outDir, sub))) {
          fail(`--run refuses to mix with existing matrix artifacts at ${join(cli.outDir, sub)}; use a fresh --out-dir`)
        }
      }
      mkdirSync(cli.outDir, { recursive: true, mode: 0o700 })
      cleanupUseNewgrp = cli.useNewgrp
      process.stdout.write(`[certify] executing ${plan.length} cell(s) with concurrency ${cli.concurrency} (worker-concurrency ${cli.workerConcurrency ?? 'harness default'})\n`)
      const results = await executeRunPlan(plan, {
        useNewgrp: cli.useNewgrp,
        concurrency: cli.concurrency,
        abort: abort.signal,
        log: line => process.stdout.write(`${line}\n`),
      })
      cleanupContainers()
      const failed = results.filter(result => result.code !== 0 && result.code !== 3)
      for (const result of failed) ingestNotes.push(`cell ${result.id} did not complete cleanly (${result.error ?? result.code ?? result.signal})`)
      const expectedGateFailure = results.filter(result => result.code === 3)
      if (expectedGateFailure.length) {
        ingestNotes.push(`${expectedGateFailure.length} reason floor cell(s) exited 3 (anti-heuristic gate violation recorded in the certificate)`)
      }
      const ingested = ingestFromDirs([cli.outDir], process.env)
      ingestedRuns = ingested.runs
      ingestNotes.push(...ingested.notes)
      certificate = evaluateCertification(ingested.runs, ingested.reason, {
        mode: 'run',
        apps: cli.apps,
        devRuns: cli.devRuns,
        floorHeldoutRuns: cli.floorHeldoutRuns,
        heldoutRuns: cli.heldoutRuns,
        checkMatrix: cli.checkMatrix,
        allowBurnedDev: cli.allowBurnedDev,
        notes: ingestNotes,
      })
      if (drawnHeldoutMeta && certificate.certifying) {
        recordExposedHeldoutSeeds({
          certificateId: `phase1-${certificate.generatedAt}-${certificate.gitSha}`,
          domain: 'certify',
          startIndex: drawnHeldoutMeta.startIndex,
          endIndex: drawnHeldoutMeta.endIndex,
          seeds: drawnHeldoutMeta.seeds,
          gitSha: certificate.gitSha,
        })
      }
      if (!cli.keepDataDirs) cleanupDataDirs(cli.outDir)
    } else {
      const ingested = ingestFromDirs(cli.fromDirs, process.env)
      ingestedRuns = ingested.runs
      ingestNotes.push(...ingested.notes)
      ingestNotes.push(`ingested ${ingested.runs.length} realism cell(s) and ${ingested.reason.length} reason report(s) from ${ingested.filesScanned} file(s)`)
      certificate = evaluateCertification(ingested.runs, ingested.reason, {
        mode: 'from-dir',
        apps: cli.apps,
        devRuns: cli.devRuns,
        floorHeldoutRuns: cli.floorHeldoutRuns,
        heldoutRuns: cli.heldoutRuns,
        checkMatrix: cli.checkMatrix,
        allowBurnedDev: cli.allowBurnedDev,
        notes: ingestNotes,
      })
    }

    if (ingestedRuns.length > 0) {
      writePhase1CertifyLedgerRows({
        runs: ingestedRuns,
        certificate,
        ledgerPath: cli.ledgerPath,
        promoteLedgerPath: cli.promoteLedgerPath,
      })
    }

    const jsonText = redactText(`${JSON.stringify(certificate, null, 2)}\n`, secrets)
    const mdText = redactText(renderCertificateMarkdown(certificate), secrets)
    assertSecretFree(jsonText, secrets)
    assertSecretFree(mdText, secrets)
    const jsonPath = cli.jsonPath ?? join(cli.outDir, 'certificate.json')
    const mdPath = cli.mdPath ?? join(cli.outDir, 'certificate.md')
    writeOwnerOnly(jsonPath, jsonText)
    writeOwnerOnly(mdPath, mdText)

    process.stdout.write(`\n${mdText}`)
    process.stdout.write(`\nwrote ${jsonPath}\nwrote ${mdPath}\n`)
    process.stdout.write(`certify:phase1 ${certificate.verdict}\n`)
    if (certificate.verdict === 'FAIL') process.exitCode = 1
  } finally {
    process.removeListener('SIGINT', onSignal)
    process.removeListener('SIGTERM', onSignal)
    if (interrupted) killLiveChildren()
    // Failure paths must not leave per-cell data dirs behind either.
    if (cli.run && !cli.dryRun && !cli.keepDataDirs) cleanupDataDirs(cli.outDir)
  }
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`error: ${(error as Error).message}\n`)
    process.exit(1)
  })
}
