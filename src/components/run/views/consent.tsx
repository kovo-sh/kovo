// Consent sheet for waiting runs (rendered by Overview), and the scope
// editor it shares with the header's "Edit scope" dialog (@base-ui/react Dialog).
import { Link } from '@tanstack/react-router'
import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { canReviewScope, maxBudgetRequests, maxRpsPerOriginCeiling, maxScopeHosts } from '../../../domain.ts'
import type { ApprovalPolicy, CapabilityTier } from '../../../domain.ts'
import { approvalPolicyMeta, capabilityTierMeta } from '../../run-state.ts'
import { Dialog, DialogContent, DialogTitle } from '../../ui/dialog.tsx'
import { useRun } from '../data.tsx'
import type { Command } from '../data.tsx'
import { Kbd } from '../display.tsx'
import { fmtN, fmtUsd, host, plural, words } from '../format.ts'
import { StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { PHASE_LABEL, runStatusLabel } from '../meta.ts'
import { useOverlays } from '../overlays.tsx'
import { useToast } from '../toast.tsx'
import { cn, runBtn, RW } from '../tw.ts'
import { LabPanel } from './lab.tsx'

const PUBLIC_MAX_RPS_CAP = 20
const MAX_AUTO_SELECT_HOSTS = 30
const LARGE_HOST_FILTER_THRESHOLD = 8
const CHK = 'm-0 size-[13px] accent-[var(--accent)]'
const NUM_PILL = 'inline-flex items-center gap-1 rounded-[5px] bg-panel px-1.5 py-[2px] shadow-hairline'
const NUM_IN = 'num border-0 bg-transparent p-0 font-sans text-[12px] font-medium text-fg outline-none'

const DEFAULT_SCAN_MODE_GOALS: ReadonlySet<string> = new Set([
  'Map endpoints, API routes, and client bundles, and verify read-only exposures and cross-account reads without state-changing requests.',
  'Run safe active checks, auth/access-control probes, and high-impact proofs while pausing for human approval before risky state-changing actions.',
  'Run all in-scope active probes, mutations, and race bursts automatically with full audit logs and no approval pauses.',
])

/** True when a run has an operator-authored goal distinct from the built-in scan mode presets. */
export function isCustomRunGoal(goal: string | null | undefined): boolean {
  const trimmed = (goal ?? '').trim()
  return trimmed.length > 0 && !DEFAULT_SCAN_MODE_GOALS.has(trimmed)
}

type ScanModeKey = 'passive' | 'supervised' | 'autonomous'

const SCAN_MODE_OPTIONS: readonly { key: ScanModeKey; label: string; summary: string }[] = [
  { key: 'passive', label: 'Passive Scan', summary: 'Read-only checks (plus bound test accounts); never mutates state.' },
  { key: 'supervised', label: 'Supervised Scan', summary: 'Safe active checks automatically; pauses for approval before risky writes.' },
  { key: 'autonomous', label: 'Autonomous Scan', summary: 'All in-scope active probes automatically with hard safety guardrails enforced.' },
]

function draftScanMode(d: { capabilityTier: CapabilityTier; approvalPolicy: ApprovalPolicy }): ScanModeKey {
  if (d.capabilityTier === 3 && d.approvalPolicy === 'yolo') return 'autonomous'
  if (d.capabilityTier === 3) return 'supervised'
  return 'passive'
}

/** Compact live summary shown on the left of the sticky Scope Review action bar. */
export function consentStickySummary(input: {
  discovery: boolean
  hostCount: number
  capabilityTier: CapabilityTier
  approvalPolicy: ApprovalPolicy
}): string {
  if (input.discovery) {
    return `${plural(input.hostCount, 'seed')} · Discovery`
  }
  const mode = draftScanMode({ capabilityTier: input.capabilityTier, approvalPolicy: input.approvalPolicy })
  const modeLabel = mode === 'passive' ? 'Passive' : mode === 'autonomous' ? 'Autonomous' : 'Supervised'
  const policyLabel = mode === 'passive'
    ? 'Read-only'
    : mode === 'autonomous'
      ? 'Auto-approve in scope'
      : input.approvalPolicy === 'strict'
        ? 'Approve every write'
        : 'Ask before risky actions'
  return `${plural(input.hostCount, 'host')} · ${modeLabel} · ${policyLabel}`
}

/** True when no test accounts exist and active/authenticated checks are enabled. */
export function shouldShowZeroPersonaWarning(
  detail: { personas?: readonly unknown[] | null; run?: { capabilityTier?: CapabilityTier } | null },
  capabilityTier?: CapabilityTier,
): boolean {
  return !detail.personas?.length && (capabilityTier ?? detail.run?.capabilityTier ?? 0) >= 2
}

interface Draft {
  assetIds: string[]
  capabilityTier: CapabilityTier
  approvalPolicy: ApprovalPolicy
  approvedPersonaIds: string[]
  budgetUsd: number
  budgetRequests: number
  maxRpsPerOrigin: number
}

// Lightweight client fallback for standalone unit tests when server-authoritative PSL
// ranking (`detail.recommendedScopeAssetIds` / `detail.highSignalScopeAssetIds`) is absent.
// Authoritative full-PSL ranking runs strictly on the server in `src/actions.ts`.
const PSL_RULES: ReadonlySet<string> = new Set(
  'co.uk org.uk gov.uk ac.uk com.au net.au org.au co.jp ne.jp or.jp com.br co.nz co.za co.in com.sg com.hk com.mx com.tw co.kr vercel.app netlify.app github.io pages.dev fly.dev herokuapp.com onrender.com workers.dev web.app firebaseapp.com run.app appspot.com azurewebsites.net cloudfront.net amazonaws.com railway.app glitch.me'.split(' '),
)
const FALLBACK_MULTI_TENANT_SUFFIXES: ReadonlySet<string> = new Set([...PSL_RULES].slice(19))

function extractFallbackHost(raw: string): string {
  const t = raw.trim()
  if (!t) return ''
  try {
    return (/^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? new URL(t).hostname : t.replace(/\/.*$/, '').replace(/:\d+$/, ''))
      .toLowerCase()
      .replace(/\.+$/, '')
  } catch {
    return ''
  }
}

export function isMultiTenantPublicSuffix(hostname: string): boolean {
  const h = extractFallbackHost(hostname)
  if (!h || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || h.includes(':')) return false
  for (const suffix of FALLBACK_MULTI_TENANT_SUFFIXES) {
    if (h === suffix || h.endsWith(`.${suffix}`)) return true
  }
  return false
}

export function registrableApex(hostOrOrigin: string): string | null {
  const h = extractFallbackHost(hostOrOrigin)
  if (!h || h === 'localhost' || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || h.includes(':')) return null
  const labels = h.split('.').filter(Boolean)
  if (labels.length < 2) return null
  const suffixLen = labels.length >= 2 && PSL_RULES.has(labels.slice(-2).join('.')) ? 2 : 1
  return labels.length <= suffixLen ? null : labels.slice(-(suffixLen + 1)).join('.')
}

const SCOPE_TIER1 = new Set([
  'api', 'app', 'auth', 'admin', 'billing', 'oauth', 'sso', 'login', 'portal',
  'dashboard', 'console', 'graphql', 'gateway', 'accounts', 'account',
])
const SCOPE_NOISY_RE = /(?:^|\.)(?:(?:pr|deploy-preview|preview)-\d+|[a-z0-9-]+-\d{3,})(?:\.|$)/i

export function rankScopeAssets<T extends { id?: string; origin: string; source?: string; thirdParty?: boolean; dnsSource?: unknown }>(
  assets: readonly T[],
  seedOrigins: readonly string[],
  options: { maxAssets?: number } = {},
): Array<{ asset: T; score: number; apex: string | null; sameApexAsSeed: boolean; depth: number; noisy: boolean }> {
  const seedHosts = new Set(seedOrigins.map(extractFallbackHost).filter(Boolean))
  const seedApexes = new Set(seedOrigins.map(registrableApex).filter((a): a is string => Boolean(a && !isMultiTenantPublicSuffix(a))))
  const ranked = assets.map((asset, idx) => {
    const h = extractFallbackHost(asset.origin)
    const apex = registrableApex(asset.origin)
    const isDisc = asset.source === 'subdomain_discovery' || asset.source === 'phase0_ct_discovery' || asset.source === 'phase0_subdomain_discovery'
    const exactSeed = seedHosts.has(h) && !isDisc
    const sameApexAsSeed = exactSeed || (!isMultiTenantPublicSuffix(h) && apex !== null && seedApexes.has(apex))
    const prefix = apex && h.endsWith(`.${apex}`) ? h.slice(0, -(apex.length + 1)) : ''
    const depth = prefix ? prefix.split('.').filter(Boolean).length : 0
    const noisy = prefix ? SCOPE_NOISY_RE.test(prefix) : false
    const src = (asset.source ?? '').toLowerCase()
    let score = exactSeed || src === 'project seed' || (!asset.dnsSource && !isDisc && src === '')
      ? 1000
      : /repo|spec|openapi|swagger|github|graphql/.test(src)
        ? 850
        : noisy
          ? 50
          : SCOPE_TIER1.has(prefix.split('.')[0] ?? '') ? 700 : Math.max(100, 440 - depth * 40)
    if (seedOrigins.length > 0 && !sameApexAsSeed) score -= 200
    if (asset.thirdParty) score -= 500
    return { asset, score, apex, sameApexAsSeed, depth, noisy, idx }
  }).sort((a, b) => (b.score - a.score) || (a.depth - b.depth) || a.asset.origin.localeCompare(b.asset.origin) || (a.idx - b.idx))
  const limited = options.maxAssets !== undefined ? ranked.slice(0, Math.max(0, Math.floor(options.maxAssets))) : ranked
  return limited.map(({ asset, score, apex, sameApexAsSeed, depth, noisy }) => ({ asset, score, apex, sameApexAsSeed, depth, noisy }))
}

/**
 * Resolve default checked candidate IDs for scope review.
 * Consumes server-authoritative `options.serverRecommendedIds` (computed with full PSL in
 * `src/actions.ts`) when present, with a small pure fallback for standalone unit tests.
 */
export function defaultScopeAssetIds(
  run: {
    scopeRevision: number
    approved: readonly string[]
    candidates: readonly {
      id: string
      origin: string
      source?: string
      thirdParty: boolean
      includeSubdomains?: boolean
      dnsSource?: unknown
    }[]
  },
  projectDefaultScope: readonly string[],
  options?: {
    includeSubdomainOrigins?: readonly string[]
    maxAutoSelect?: number
    serverRecommendedIds?: readonly string[]
  },
): string[] {
  if (run.scopeRevision > 0) return [...run.approved]
  if (options?.serverRecommendedIds) {
    const validIds = new Set(run.candidates.map(c => c.id))
    return options.serverRecommendedIds.filter(assetId => validIds.has(assetId))
  }

  const cap = Math.max(1, Math.min(options?.maxAutoSelect ?? 30, 30))
  const extractHostname = (origin: string): string => {
    try {
      return new URL(origin).hostname.toLowerCase().replace(/\.$/, '')
    } catch {
      return origin.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').toLowerCase().replace(/\.$/, '')
    }
  }
  const fallbackMultiTenant = new Set(
    'vercel.app netlify.app github.io pages.dev fly.dev herokuapp.com onrender.com workers.dev web.app firebaseapp.com run.app appspot.com azurewebsites.net cloudfront.net amazonaws.com railway.app glitch.me zendesk.com atlassian.net gitbook.io shopify.com myshopify.com statuspage.io'.split(' '),
  )
  const fallbackPublicSuffixes = new Set(
    'co.uk org.uk gov.uk ac.uk com.au net.au org.au co.jp ne.jp or.jp com.br co.nz co.za co.in com.sg com.hk com.mx com.tw co.kr'.split(' '),
  )
  const isMultiTenant = (hostname: string): boolean => {
    if (typeof isMultiTenantPublicSuffix === 'function' && isMultiTenantPublicSuffix(hostname)) return true
    for (const suffix of fallbackMultiTenant) {
      if (hostname === suffix || hostname.endsWith(`.${suffix}`)) return true
    }
    return false
  }
  const isLocalOrIp = (hostname: string): boolean =>
    !hostname
    || hostname === 'localhost'
    || hostname.endsWith('.localhost')
    || hostname.endsWith('.local')
    || hostname.endsWith('.internal')
    || hostname.endsWith('.home.arpa')
    || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)
    || hostname.includes(':')
  const isBarePublicSuffix = (hostname: string): boolean =>
    !hostname.includes('.')
    || fallbackPublicSuffixes.has(hostname)
    || (typeof PSL_RULES !== 'undefined' && PSL_RULES.has(hostname))
  /** Strict host-anchor fallback mirroring server `autoAdmitAnchorForOrigin` (R3-H-8). */
  const resolveAutoAdmitAnchor = (origin: string): string | null => {
    const h = extractHostname(origin)
    if (isLocalOrIp(h) || isMultiTenant(h) || isBarePublicSuffix(h)) return null
    const anchor = h.startsWith('www.') ? h.slice(4) : h
    if (!anchor || isLocalOrIp(anchor) || isMultiTenant(anchor) || isBarePublicSuffix(anchor)) return null
    return anchor
  }
  const isDiscoveredSubdomain = (source?: string): boolean =>
    source === 'subdomain_discovery' || source === 'phase0_ct_discovery' || source === 'phase0_subdomain_discovery'
  const isBulkDnsImport = (c: { source?: string; dnsSource?: unknown }): boolean =>
    Boolean(c.dnsSource) && !isDiscoveredSubdomain(c.source)

  const seedOriginsForRank: string[] = []
  const autoAdmitAnchors = new Set<string>()
  for (const origin of options?.includeSubdomainOrigins ?? []) {
    seedOriginsForRank.push(origin)
    const anchor = resolveAutoAdmitAnchor(origin)
    if (anchor) autoAdmitAnchors.add(anchor)
  }
  for (const c of run.candidates) {
    if (c.includeSubdomains && !c.thirdParty) {
      seedOriginsForRank.push(c.origin)
      const anchor = resolveAutoAdmitAnchor(c.origin)
      if (anchor) autoAdmitAnchors.add(anchor)
    } else if (!c.thirdParty && !isBulkDnsImport(c) && !isDiscoveredSubdomain(c.source)) {
      seedOriginsForRank.push(c.origin)
    }
  }

  const matchesAnchoredParent = (origin: string): boolean => {
    if (autoAdmitAnchors.size === 0) return false
    const h = extractHostname(origin)
    if (!h) return false
    for (const anchor of autoAdmitAnchors) {
      if (h.endsWith(`.${anchor}`)) return true
    }
    return false
  }

  const pickRanked = (
    list: readonly { id: string; origin: string; source?: string; thirdParty?: boolean; dnsSource?: unknown }[],
    limit: number,
  ): string[] => {
    if (list.length <= limit) return list.map(c => c.id)
    if (typeof rankScopeAssets === 'function') {
      const chosen = new Set(rankScopeAssets(list, seedOriginsForRank, { maxAssets: limit }).map(r => r.asset.id))
      return list.filter(c => chosen.has(c.id)).map(c => c.id)
    }
    const t1 = new Set(['api', 'app', 'auth', 'admin', 'billing', 'oauth', 'sso', 'login', 'portal', 'dashboard', 'console', 'graphql', 'gateway', 'accounts', 'account'])
    const noisyRe = /^(?:pr-\d+|deploy-preview-\d+|preview-\d+|[a-z0-9-]+-\d{3,})(?:\.|$)/i
    const scoreOf = (c: { origin: string; source?: string; dnsSource?: unknown }) => {
      const src = (c.source ?? '').toLowerCase()
      if (src === 'project seed' || (!c.dnsSource && !isDiscoveredSubdomain(c.source))) return 1000
      const h = extractHostname(c.origin)
      if (noisyRe.test(h)) return 50
      return t1.has(h.split('.')[0] ?? '') ? 700 : 300
    }
    const chosen = new Set(
      list.map((c, idx) => ({ id: c.id, score: scoreOf(c), idx })).sort((a, b) => (b.score - a.score) || (a.idx - b.idx)).slice(0, limit).map(r => r.id),
    )
    return list.filter(c => chosen.has(c.id)).map(c => c.id)
  }

  if (projectDefaultScope.length > 0) {
    const saved = new Set(projectDefaultScope)
    const savedIds = run.candidates.filter(a => saved.has(a.origin)).map(a => a.id)
    if (autoAdmitAnchors.size === 0) return savedIds
    const savedSet = new Set(savedIds)
    const extraSubs = run.candidates.filter(
      a => !savedSet.has(a.id) && !a.thirdParty && isDiscoveredSubdomain(a.source) && matchesAnchoredParent(a.origin),
    )
    const remaining = Math.max(0, cap - savedIds.length)
    if (remaining === 0 || extraSubs.length === 0) return savedIds
    return [...savedIds, ...pickRanked(extraSubs, remaining)]
  }

  const hasExplicitParentConfig = options?.includeSubdomainOrigins !== undefined
  const eligible = run.candidates.filter(a => {
    if (a.thirdParty) return false
    if (isBulkDnsImport(a)) return false
    if (isDiscoveredSubdomain(a.source)) {
      if (autoAdmitAnchors.size > 0) return matchesAnchoredParent(a.origin)
      return !hasExplicitParentConfig
    }
    return true
  })

  return pickRanked(eligible, cap)
}

/**
 * Determine whether a candidate host is a same-apex sibling outside every seed's
 * auto-admit host anchor (R3-H-8). Prefers server-authoritative `rankedAssets` metadata
 * from `runData` when present, with a deterministic client fallback.
 */
export function isSameApexOutsideAnchor(
  candidate: { id: string; origin: string; thirdParty: boolean; source?: string },
  rankedById: ReadonlyMap<string, { sameApexAsSeed: boolean; sameApexOutsideAnchor?: boolean }>,
  seedOrigins: readonly string[],
): boolean {
  if (candidate.thirdParty) return false
  const ranked = rankedById.get(candidate.id)
  if (ranked && typeof ranked.sameApexOutsideAnchor === 'boolean') {
    return ranked.sameApexOutsideAnchor
  }
  const h = extractFallbackHost(candidate.origin)
  if (!h || isMultiTenantPublicSuffix(h)) return false
  const seedHosts = new Set<string>()
  const seedAnchors = new Set<string>()
  const seedApexes = new Set<string>()
  for (const s of seedOrigins) {
    const sh = extractFallbackHost(s)
    if (!sh) continue
    seedHosts.add(sh)
    const anchor = sh.startsWith('www.') ? sh.slice(4) : sh
    if (anchor && !isMultiTenantPublicSuffix(anchor)) seedAnchors.add(anchor)
    const apex = registrableApex(s)
    if (apex && !isMultiTenantPublicSuffix(apex)) seedApexes.add(apex)
  }
  if (seedHosts.has(h)) return false
  for (const anchor of seedAnchors) {
    if (h === anchor || h.endsWith(`.${anchor}`)) return false
  }
  const candidateApex = registrableApex(candidate.origin)
  return Boolean(candidateApex && seedApexes.has(candidateApex))
}

/** Hosts and default selection for the scope sheet, per phase. */
function useScopeModel() {
  const { detail } = useRun()
  const r = detail.run
  const p = detail.project
  const includeSubdomainOrigins = detail.includeSubdomainOrigins ?? []
  const serverRecommendedIds = detail.recommendedScopeAssetIds
  const rankedAssets = detail.rankedAssets
  return useMemo(() => {
    const discovery = r.phase === 'consent'
    const rankedById = new Map((rankedAssets ?? []).map(a => [a.id, a]))
    const anchorSeeds = includeSubdomainOrigins.length > 0 ? includeSubdomainOrigins : p.seeds
    const hosts = discovery
      ? p.seeds.map(s => ({ id: s, origin: s, thirdParty: false, source: 'Project seed', externalCname: null as string | null, dnsSource: null as unknown, sameApexOutsideAnchor: false }))
      : r.candidates.map(c => ({
        id: c.id,
        origin: c.origin,
        thirdParty: c.thirdParty,
        source: c.source,
        externalCname: c.dnsSource?.externalAliases?.[0] ?? null,
        dnsSource: c.dnsSource ?? null,
        sameApexOutsideAnchor: isSameApexOutsideAnchor(c, rankedById, anchorSeeds),
      }))
    const defaults = defaultScopeAssetIds(r, p.defaultScope, {
      includeSubdomainOrigins,
      maxAutoSelect: MAX_AUTO_SELECT_HOSTS,
      serverRecommendedIds,
    })
    return { discovery, hosts, defaults, includeSubdomainOrigins }
  }, [r, p, includeSubdomainOrigins, serverRecommendedIds, rankedAssets])
}

function initialDraft(r: ReturnType<typeof useRun>['detail']['run'], defaults: string[], rpsMax: number): Draft {
  return {
    assetIds: defaults, capabilityTier: r.capabilityTier, approvalPolicy: r.approvalPolicy ?? 'auto_review',
    approvedPersonaIds: [...r.approvedPersonaIds], budgetUsd: r.budgetUsd, budgetRequests: r.budgetRequests,
    maxRpsPerOrigin: Math.min(r.maxRpsPerOrigin, rpsMax),
  }
}

export function scopeCommand(
  r: ReturnType<typeof useRun>['detail']['run'],
  d: Draft,
  opts: { saveProject?: boolean; scopeOnly?: boolean; expectedScopeRevision?: number } = {},
): Command {
  const { saveProject = false, scopeOnly = false, expectedScopeRevision = r.scopeRevision } = opts
  return {
    action: 'scope',
    assetIds: d.assetIds,
    expectedScopeRevision,
    consent: true,
    saveProject,
    capabilityTier: d.capabilityTier,
    approvalPolicy: d.approvalPolicy,
    approvedPersonaIds: d.capabilityTier >= 2 ? d.approvedPersonaIds : [],
    ...(scopeOnly
      ? {}
      : {
          budgetUsd: d.budgetUsd,
          budgetRequests: d.budgetRequests,
          maxRpsPerOrigin: d.maxRpsPerOrigin,
        }),
  }
}

/**
 * Determine whether background subdomain discovery is currently in flight for a run in review.
 * Combines the `runData` snapshot flag (`initialPending`) with live SSE events so the banner
 * shows immediately on instant navigation and clears as soon as `discovery.subdomains_discovered` arrives.
 */
export function isSubdomainDiscoveryActive(
  phase: string,
  initialPending: boolean | undefined,
  events: readonly { id: number; kind: string }[],
): boolean {
  if (phase !== 'review') return false
  let liveStartedId = -1
  let liveDiscoveredId = -1
  for (const ev of events) {
    if (ev.kind === 'discovery.subdomains_started' && ev.id > liveStartedId) liveStartedId = ev.id
    if (ev.kind === 'discovery.subdomains_discovered' && ev.id > liveDiscoveredId) liveDiscoveredId = ev.id
  }
  if (liveDiscoveredId > liveStartedId) return false
  if (liveStartedId > liveDiscoveredId) return true
  return Boolean(initialPending)
}

/**
 * The scope card: compact read-only-styled scan config KV bar, target domains & subdomains
 * checklist (with live discovery banner & search/quick-select bar), bind test accounts section,
 * and a footer with the primary action.
 */
function ScopeCard({
  editing,
  draft,
  setDraft,
  onHostsTouched,
  footer,
  inDialog = false,
  scopeOnly = false,
}: {
  editing: boolean
  draft: Draft
  setDraft: (fn: (d: Draft) => Draft) => void
  onHostsTouched?: () => void
  footer?: ReactNode
  inDialog?: boolean
  scopeOnly?: boolean
}) {
  const { detail, events } = useRun()
  const rpsMax = detail.project.environment === 'local-lab' ? maxRpsPerOriginCeiling : PUBLIC_MAX_RPS_CAP
  const { discovery, hosts, includeSubdomainOrigins } = useScopeModel()
  const [hostQuery, setHostQuery] = useState('')
  const [editingBudget, setEditingBudget] = useState(false)
  const discoveringSubdomains = isSubdomainDiscoveryActive(detail.run.phase, detail.subdomainDiscoveryPending, events)
  const selected = new Set(draft.assetIds)
  const shownHosts = editing || discovery ? hosts : hosts.filter(h => selected.has(h.id))
  const canEditConfig = editing && !discovery
  const scanMode = draftScanMode(draft)

  const trimmedQuery = hostQuery.trim().toLowerCase()
  const filteredHosts = useMemo(() => {
    if (!trimmedQuery) return hosts
    return hosts.filter(h =>
      host(h.origin).toLowerCase().includes(trimmedQuery)
      || h.origin.toLowerCase().includes(trimmedQuery)
      || h.source.toLowerCase().includes(trimmedQuery)
      || (h.externalCname ?? '').toLowerCase().includes(trimmedQuery),
    )
  }, [hosts, trimmedQuery])

  const setScanMode = (nextMode: ScanModeKey) => {
    setDraft(d => {
      if (nextMode === 'passive') {
        return {
          ...d,
          capabilityTier: d.approvedPersonaIds.length > 0 ? 2 : 1,
          approvalPolicy: 'auto_review',
        }
      }
      if (nextMode === 'supervised') {
        return {
          ...d,
          capabilityTier: 3,
          approvalPolicy: d.approvalPolicy === 'strict' ? 'strict' : 'auto_review',
        }
      }
      return {
        ...d,
        capabilityTier: 3,
        approvalPolicy: 'yolo',
      }
    })
  }

  const selectHighSignal = () => {
    onHostsTouched?.()
    const ranked = defaultScopeAssetIds(
      { scopeRevision: 0, approved: [], candidates: detail.run.candidates },
      [],
      {
        includeSubdomainOrigins: includeSubdomainOrigins.length > 0 ? includeSubdomainOrigins : detail.project.seeds,
        maxAutoSelect: MAX_AUTO_SELECT_HOSTS,
        serverRecommendedIds: detail.highSignalScopeAssetIds,
      },
    )
    setDraft(d => ({ ...d, assetIds: ranked }))
  }

  const selectAllFirstParty = () => {
    onHostsTouched?.()
    setDraft(d => ({
      ...d,
      assetIds: hosts.filter(h => !h.thirdParty).slice(0, maxScopeHosts).map(h => h.id),
    }))
  }

  const selectNone = () => {
    onHostsTouched?.()
    setDraft(d => ({ ...d, assetIds: [] }))
  }

  const toggleHost = (hostId: string, checked: boolean) => {
    onHostsTouched?.()
    setDraft(d => ({
      ...d,
      assetIds: checked
        ? (d.assetIds.includes(hostId) ? d.assetIds : [...d.assetIds, hostId])
        : d.assetIds.filter(x => x !== hostId),
    }))
  }

  const togglePersona = (personaId: string, checked: boolean) => {
    setDraft(d => {
      const nextPersonas = checked
        ? (d.approvedPersonaIds.includes(personaId) ? d.approvedPersonaIds : [...d.approvedPersonaIds, personaId])
        : d.approvedPersonaIds.filter(x => x !== personaId)
      const nextTier: CapabilityTier = d.capabilityTier === 0
        ? 0
        : d.capabilityTier === 3
          ? 3
          : nextPersonas.length > 0 ? 2 : 1
      return { ...d, approvedPersonaIds: nextPersonas, capabilityTier: nextTier }
    })
  }

  const modeSummary = scanMode === 'passive'
    ? capabilityTierMeta[draft.capabilityTier].summary
    : scanMode === 'supervised'
      ? approvalPolicyMeta[draft.approvalPolicy === 'strict' ? 'strict' : 'auto_review'].summary
      : approvalPolicyMeta.yolo.summary

  const quickBtns = <>
    <button type="button" className={runBtn({ variant: 'ghost', size: 'xs' })} onClick={selectHighSignal}>High-signal</button>
    <button type="button" className={runBtn({ variant: 'ghost', size: 'xs' })} onClick={selectAllFirstParty}>All first-party</button>
    <button type="button" className={runBtn({ variant: 'ghost', size: 'xs' })} onClick={selectNone}>None</button>
  </>

  return <div className={inDialog ? 'overflow-hidden bg-panel' : RW.sheet}>
    {/* Sheet header */}
    <div className={RW.sheetH}>
      <Icon name="globe" />
      {inDialog
        ? <DialogTitle className="text-[13px] font-medium text-fg">Proposed scope</DialogTitle>
        : <span>Proposed scope</span>}
      <span className="num font-normal text-fg-subtle">
        {discovery
          ? plural(hosts.length, 'host') + ' from project seeds'
          : `${selected.size} of ${plural(hosts.length, 'discovered host')} selected`}
      </span>
      {editing && !discovery && hosts.length <= LARGE_HOST_FILTER_THRESHOLD && (
        <span className="ml-auto flex gap-1">{quickBtns}</span>
      )}
    </div>

    {/* (a) Compact 2-column Scan Mode & Approval Policy grid */}
    <div className="num grid grid-cols-1 border-b border-line md:grid-cols-2" data-testid="scope-controls-grid">
      <div className="border-b border-line px-4 py-2.5 md:border-b-0 md:border-r">
        <div className="mb-1 text-[11.5px] text-fg-subtle">Scan mode</div>
        {canEditConfig
          ? <select
              className="h-[24px] w-full cursor-pointer rounded-[5px] border-0 bg-sunk px-2 font-sans text-[12px] font-medium text-fg shadow-hairline outline-none"
              value={scanMode}
              onChange={e => setScanMode(e.target.value as ScanModeKey)}
              aria-label="Scan mode"
              title={modeSummary}
            >
              {SCAN_MODE_OPTIONS.map(opt => (
                <option key={opt.key} value={opt.key} title={opt.summary}>
                  {opt.label}
                </option>
              ))}
            </select>
          : <div className="font-medium text-fg" title={modeSummary}>
              {SCAN_MODE_OPTIONS.find(o => o.key === scanMode)?.label ?? capabilityTierMeta[draft.capabilityTier].name}
            </div>}
      </div>

      {scopeOnly
        ? <div className="px-4 py-2.5">
            <div className="mb-1 text-[11.5px] text-fg-subtle">Test accounts</div>
            <div className="font-medium text-fg">
              {draft.approvedPersonaIds.length && draft.capabilityTier >= 2 ? plural(draft.approvedPersonaIds.length, 'test account') : 'None (anonymous)'}
            </div>
          </div>
        : <div className="px-4 py-2.5">
            <div className="mb-1 text-[11.5px] text-fg-subtle">Approval policy</div>
            {canEditConfig && scanMode === 'supervised'
              ? <select
                  className="h-[24px] w-full cursor-pointer rounded-[5px] border-0 bg-sunk px-2 font-sans text-[12px] font-medium text-fg shadow-hairline outline-none"
                  value={draft.approvalPolicy === 'strict' ? 'strict' : 'auto_review'}
                  onChange={e => setDraft(d => ({ ...d, approvalPolicy: e.target.value as ApprovalPolicy }))}
                  aria-label="Approval policy"
                >
                  <option value="auto_review">{approvalPolicyMeta.auto_review.label} — Ask before risky actions</option>
                  <option value="strict">{approvalPolicyMeta.strict.label} — Approve every write</option>
                </select>
              : <div className="font-medium text-fg" title={modeSummary}>
                  {scanMode === 'autonomous'
                    ? 'Auto-approve in scope'
                    : scanMode === 'supervised'
                      ? approvalPolicyMeta[draft.approvalPolicy].label
                      : <span className="font-normal text-fg-subtle">Not needed (read-only)</span>}
                </div>}
          </div>}
    </div>

    {/* Compact single-line Budget / RPS strip */}
    {!scopeOnly && (
      <div className="num flex flex-wrap items-center justify-between gap-2 border-b border-line bg-sunk/35 px-4 py-1.5 text-[12px]">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11.5px] text-fg-subtle">Budget / RPS</span>
          {canEditConfig && editingBudget
            ? <div className="flex flex-wrap items-center gap-1.5 text-[12px] text-fg-muted">
                <label className={NUM_PILL}>
                  <span className="text-fg-subtle">$</span>
                  <input
                    className={cn(NUM_IN, 'w-[46px]')}
                    type="number"
                    min={0.1}
                    max={500}
                    step="any"
                    value={draft.budgetUsd}
                    aria-label="Budget USD"
                    onChange={e => setDraft(d => ({ ...d, budgetUsd: Number(e.target.value) }))}
                  />
                </label>
                <label className={NUM_PILL} title="Requests per second per origin">
                  <input
                    className={cn(NUM_IN, 'w-[34px]')}
                    type="number"
                    min={1}
                    max={rpsMax}
                    step={1}
                    value={Math.min(draft.maxRpsPerOrigin, rpsMax)}
                    aria-label="Requests per second per origin"
                    onChange={e => setDraft(d => ({ ...d, maxRpsPerOrigin: Math.min(rpsMax, Math.max(1, Number(e.target.value))) }))}
                  />
                  <span className="text-fg-subtle">req/s</span>
                </label>
                <label className={NUM_PILL} title="Request cap (0 = uncapped)">
                  <input
                    className={cn(NUM_IN, 'w-[50px]')}
                    type="number"
                    min={0}
                    max={maxBudgetRequests}
                    step={1}
                    value={draft.budgetRequests}
                    aria-label="Request cap (0 = uncapped)"
                    onChange={e => setDraft(d => ({ ...d, budgetRequests: Number(e.target.value) }))}
                  />
                  <span className="text-fg-subtle">reqs</span>
                </label>
              </div>
            : <button
                type="button"
                disabled={!canEditConfig}
                onClick={() => canEditConfig && setEditingBudget(true)}
                className={cn(
                  'inline-flex items-center gap-1 border-0 bg-transparent p-0 text-left font-sans text-[12px] font-medium text-fg shadow-none',
                  canEditConfig && 'cursor-pointer rounded-[4px] hover:bg-transparent hover:underline',
                )}
                title={canEditConfig ? 'Click to adjust budget, request cap, and rate limit' : undefined}
              >
                <span>{fmtUsd(draft.budgetUsd)}</span>
                <span className="text-fg-subtle">·</span>
                <span>{Math.min(draft.maxRpsPerOrigin, rpsMax)} req/s</span>
                {draft.budgetRequests > 0 && <><span className="text-fg-subtle">·</span><span>{fmtN(draft.budgetRequests)} reqs</span></>}
              </button>}
        </div>
        {canEditConfig && (
          <button
            type="button"
            className={runBtn({ variant: 'ghost', size: 'xs' })}
            onClick={() => setEditingBudget(b => !b)}
          >
            {editingBudget ? 'Done' : 'Adjust'}
          </button>
        )}
      </div>
    )}

    {/* (b) Target Domains & Subdomains */}
    {discoveringSubdomains && (
      <div
        className="flex items-center gap-2 border-b border-line bg-accent-soft/40 px-4 py-2 text-[12px] text-fg-muted"
        role="status"
        aria-live="polite"
        data-testid="subdomain-discovery-banner"
      >
        <span
          className="inline-block size-3 flex-none animate-spin rounded-full border-[1.5px] border-accent border-t-transparent motion-reduce:animate-none"
          aria-hidden="true"
        />
        <span>
          Discovering subdomains (CT logs + DNS)…
          <span className="num ml-1.5 text-fg-subtle">· {plural(hosts.length, 'host')} found</span>
        </span>
      </div>
    )}

    {editing && !discovery && hosts.length > LARGE_HOST_FILTER_THRESHOLD && (
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-sunk/40 px-3 py-1.5">
        <div className="relative flex min-w-[160px] flex-1 items-center">
          <Icon name="search" size={12} className="pointer-events-none absolute left-2 text-fg-subtle" />
          <input
            type="search"
            value={hostQuery}
            onChange={e => setHostQuery(e.target.value)}
            placeholder={`Filter ${hosts.length} hosts…`}
            aria-label="Filter hosts"
            className="h-[24px] w-full rounded-[5px] border-0 bg-panel pl-7 pr-2 font-sans text-[12px] text-fg shadow-hairline outline-none placeholder:text-fg-faint focus:shadow-[0_0_0_1px_var(--accent-line),0_0_0_3px_var(--accent-soft)]"
          />
        </div>
        <div className="flex flex-none items-center gap-1">{quickBtns}</div>
      </div>
    )}

    {editing && !discovery
      ? <div className="grid max-h-[42vh] grid-cols-1 gap-x-1 overflow-y-auto p-2 font-mono text-[12px] sm:grid-cols-2 md:grid-cols-3" data-testid="scope-host-list">
          {filteredHosts.map(h => {
            const on = selected.has(h.id)
            return <label
              key={h.id}
              className={cn(
                'flex cursor-pointer items-center gap-[7px] overflow-hidden whitespace-nowrap rounded-[4px] px-2 py-[3px] hover:bg-hover',
                on ? 'text-fg-muted' : 'text-fg-faint',
              )}
              title={h.sameApexOutsideAnchor
                ? `${h.origin} · ${h.source} · Same apex (different host) — unchecked by default`
                : `${h.origin} · ${h.source}`}
            >
              <input
                className="m-0 flex-none accent-[var(--accent)]"
                type="checkbox"
                aria-label={'Include ' + host(h.origin)}
                checked={on}
                onChange={e => toggleHost(h.id, e.target.checked)}
              />
              <span className="min-w-0 flex-1 truncate">{host(h.origin)}</span>
              {h.thirdParty && <span className="flex-none rounded bg-sunk px-1 py-px font-sans text-[10px] font-medium text-fg-subtle" title={h.externalCname ? `Third-party CNAME (${h.externalCname}) — unchecked by default` : 'Third-party host — unchecked by default'}>
                3P
              </span>}
              {!h.thirdParty && h.sameApexOutsideAnchor && (
                <span
                  data-testid="scope-apex-sibling-badge"
                  className="flex-none rounded bg-warn-soft px-1 py-px font-sans text-[10px] font-medium text-warn"
                  title="Same apex (different host) — outside seed anchor; unchecked by default"
                >
                  Same apex
                </span>
              )}
            </label>
          })}
          {filteredHosts.length === 0 && (
            <span className="col-span-full px-2 py-2 font-sans text-[12px] text-fg-subtle">
              No hosts match “{hostQuery}”.
            </span>
          )}
        </div>
      : <div className="grid max-h-[42vh] grid-cols-1 gap-x-1 overflow-y-auto p-2 font-mono text-[12px] sm:grid-cols-2 md:grid-cols-3" data-testid="scope-host-list">
          {shownHosts.map(h => <span key={h.id} className="truncate px-2 py-[3px] text-fg-muted" title={`${h.origin} · ${h.source}`}>{host(h.origin)}</span>)}
          {!shownHosts.length && <span className="px-2 py-[3px] text-fg-subtle">No hosts selected.</span>}
          {!discovery && hosts.length > shownHosts.length && (
            <span className="col-span-full px-2 pt-1 font-sans text-[11.5px] text-fg-subtle">
              {plural(hosts.length - shownHosts.length, 'discovered host')} unchecked by default (e.g. third-party or subdomains). Click Edit scope to review all {hosts.length}.
            </span>
          )}
        </div>}

    {editing && discovery && <div className="flex flex-col gap-2 border-t border-line px-4 pb-3 pt-2.5">
      <span className="text-[12px] text-fg-subtle">
        Discovery runs on the project seeds. Hosts it finds come back here for scope review; edit the seeds on the{' '}
        <Link to="/projects/$projectId" params={{ projectId: detail.project.id }} className="underline">project page</Link>.
      </span>
    </div>}

    {/* (c) Bind Test Accounts — cleanly separated from Target Domains by a crisp divider */}
    {!discovery && !scopeOnly && shouldShowZeroPersonaWarning(detail, draft.capabilityTier) && <div
      data-testid="consent-zero-persona-warning"
      role="status"
      className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t border-line bg-warn-soft px-3 py-1.5 text-xs text-fg-muted"
    >
      <span className="min-w-0">No test accounts — auth, BOLA/BFLA, and race checks will only test public surfaces.</span>
      <Link
        to="/projects/$projectId"
        params={{ projectId: detail.project.id }}
        search={{ tab: 'personas' }}
        className="flex-none font-medium text-warn underline underline-offset-2 hover:text-fg"
      >
        Add test accounts →
      </Link>
    </div>}
    {canEditConfig && detail.personas.length > 0 && <div className="flex flex-col gap-2 border-t border-line px-4 pb-3 pt-2.5">
      <span className="text-[12px] font-medium text-fg-subtle">
        Bind test accounts
        {draft.capabilityTier === 0 ? ' (unavailable in Offline mode)' : draft.approvedPersonaIds.length > 0 ? ` · ${draft.approvedPersonaIds.length} selected` : ''}
      </span>
      <div className="flex flex-wrap gap-x-4 gap-y-1.5">
        {detail.personas.map(p => <label key={p.id} className="flex cursor-pointer select-none items-center gap-2 text-[12.5px] text-fg-muted">
          <input
            className={CHK}
            type="checkbox"
            disabled={draft.capabilityTier === 0}
            checked={draft.approvedPersonaIds.includes(p.id)}
            onChange={e => togglePersona(p.id, e.target.checked)}
          />
          <b className="font-medium text-fg">{p.handle}</b> · {p.roleLabel}
        </label>)}
      </div>
    </div>}

    {/* (d) Primary CTA footer */}
    {footer}
  </div>
}

const STEPS: [string, string][] = [
  ['Consent', 'Approve hosts, mode, and budget.'],
  ['Threat model', 'Rank hosts by attack surface.'],
  ['Investigation', 'Workers test through the safety proxy.'],
  ['Verification', 'Automated replay confirms every finding.'],
  ['Report', 'Findings, coverage, and gaps.'],
]

/** Why "Approve & start" is unavailable, or null when the only blocker is an in-flight approval. */
export function approveBlockReason(input: {
  reviewable: boolean
  discovery: boolean
  count: number
  overLimit: boolean
  phase: string
  status: string
}): string | null {
  if (input.overLimit) return `Choose up to ${maxScopeHosts} hosts.`
  if (!input.discovery && input.count === 0) return 'Select at least one host to start the assessment.'
  if (!input.reviewable) {
    const phase = PHASE_LABEL[input.phase] ?? input.phase
    return [
      'Scope can’t be approved from this view',
      phase && `during ${phase.toLowerCase()}`,
      `(run ${runStatusLabel(input.status).toLowerCase()}).`,
    ].filter(Boolean).join(' ')
  }
  return null
}

/** Assessment track: a continuous segment per step, the current step marked for AT (A-141). */
function ConsentStepper() {
  return <ol className="m-0 mt-5 grid list-none grid-cols-5 border-t border-line p-0" aria-label="Assessment steps" data-testid="consent-stepper">
    {STEPS.map((s, i) => {
      const cur = i === 0
      return <li
        key={s[0]}
        aria-current={cur ? 'step' : undefined}
        className={cn(
          'relative pr-3 pt-2.5 text-[12px] leading-[17px] text-fg-subtle before:absolute before:-top-px before:left-0 before:right-3 before:h-0.5 before:content-[""]',
          cur ? 'before:bg-accent' : 'before:bg-line-2',
        )}
      >
        <b className={cn('mb-0.5 block font-medium', cur ? 'text-fg' : 'text-fg-muted')}>{s[0]}</b>
        {s[1]}
      </li>
    })}
  </ol>
}

/** Overview for a waiting run: "Nothing has been sent yet." */
export function ConsentView() {
  const { detail, send } = useRun()
  const toast = useToast()
  const r = detail.run
  const rpsMax = detail.project.environment === 'local-lab' ? maxRpsPerOriginCeiling : PUBLIC_MAX_RPS_CAP
  const { discovery, hosts, defaults } = useScopeModel()
  // Default directly into editable scope review on `phase === 'review'` (no extra click required).
  const [editing, setEditing] = useState(!discovery)
  const [approving, setApproving] = useState(false)
  const [saveProject, setSaveProject] = useState(false)
  const [userTouchedHosts, setUserTouchedHosts] = useState(false)
  const runSyncKey = `${r.id}:${r.phase}:${r.scopeRevision}`
  const [syncedRunKey, setSyncedRunKey] = useState(runSyncKey)
  const defaultsKey = defaults.join(',')
  const [syncedDefaultsKey, setSyncedDefaultsKey] = useState(defaultsKey)
  const [draft, setDraftState] = useState<Draft>(() => initialDraft(r, defaults, rpsMax))
  const setDraft = (fn: (d: Draft) => Draft) => setDraftState(fn)

  // Reset full draft and default editing state when run/phase/revision transitions.
  if (syncedRunKey !== runSyncKey) {
    setSyncedRunKey(runSyncKey)
    setSyncedDefaultsKey(defaultsKey)
    setUserTouchedHosts(false)
    setSaveProject(false)
    setEditing(!discovery)
    setDraftState(initialDraft(r, defaults, rpsMax))
  } else if (syncedDefaultsKey !== defaultsKey && !userTouchedHosts) {
    // Auto-check newly streamed first-party subdomains (up to Top 30) unless the user has manually toggled hosts,
    // preserving any Scan Mode / Budget / RPS / Persona edits already made in `draft`.
    setSyncedDefaultsKey(defaultsKey)
    setDraftState(prev => ({ ...prev, assetIds: defaults }))
  }

  const nw = (r.goal || '').split(/\s+/).filter(Boolean).length
  const count = discovery ? hosts.length : draft.assetIds.length
  const overLimit = draft.assetIds.length > maxScopeHosts
  const reviewable = canReviewScope(r.phase, r.status)
  const canApprove = !approving && reviewable && (discovery || (count > 0 && !overLimit))
  // A disabled "Approve & start" always says why, in the sticky bar and on the button (A-140).
  const footerNote = approveBlockReason({ reviewable, discovery, count, overLimit, phase: r.phase, status: r.status })

  const approve = async () => {
    if (!canApprove) return
    const command: Command = discovery ? { action: 'discover', consent: true } : scopeCommand(r, draft, { saveProject })
    const message = discovery
      ? `Discovery approved for ${plural(hosts.length, 'host')}`
      : `Scope approved for ${plural(count, 'host')} (${capabilityTierMeta[draft.capabilityTier].short})`
    setApproving(true)
    try {
      await send(command)
      toast.show(message, { icon: 'check' })
    } catch (failure) {
      toast.show(failure instanceof Error ? failure.message : 'Could not approve scope.', { icon: 'alert', tone: 'error' })
    } finally {
      setApproving(false)
    }
  }
  useShortcuts([{ key: 'a', run: () => { if (!canApprove) return false; void approve() } }])

  const eyebrow = r.phase === 'review' ? 'Waiting on your scope approval' : 'Waiting on your consent'
  const customGoal = isCustomRunGoal(r.goal) ? r.goal.trim() : null
  const stickySummary = consentStickySummary({
    discovery,
    hostCount: count,
    capabilityTier: draft.capabilityTier,
    approvalPolicy: draft.approvalPolicy,
  })

  return <div className="relative flex min-h-0 flex-1 flex-col overflow-y-auto" data-testid="consent-scroll-container">
    <div className="mx-auto w-full max-w-[780px] flex-1 px-6 pb-5 pt-4">
      <header className="mb-3 flex flex-col gap-1">
        <span className="inline-flex items-center gap-2 text-[12px] font-medium text-fg-muted">
          <StatusGlyph status="waiting" />{eyebrow}
        </span>
        <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
          <h1 className="m-0 text-[20px] font-semibold leading-[26px] tracking-[-0.02em] text-fg">
            {discovery ? 'Approve discovery' : 'Review scope'}
          </h1>
          <p className="num m-0 text-[12.5px] leading-[18px] text-fg-muted" data-testid="consent-subtitle">
            {discovery
              ? `${plural(hosts.length, 'project seed')} ready · Nothing has been sent yet`
              : `${plural(hosts.length, 'candidate host')} found · ${count} selected`}
          </p>
        </div>
        {customGoal && (
          <div className="flex min-w-0 items-center pt-1">
            <span
              data-testid="consent-custom-goal-chip"
              className="inline-flex max-w-full items-center gap-1.5 rounded-control border border-line bg-sunk px-2 py-0.5 text-[11.5px] leading-[16px] text-fg-muted"
              title={customGoal}
            >
              <span className="flex-none font-medium text-fg-subtle">Goal</span>
              <span className="min-w-0 truncate">{customGoal}</span>
            </span>
          </div>
        )}
      </header>
      {customGoal && nw < 6 && <div className="mb-3.5 flex items-start gap-2.5 rounded-lg bg-warn-soft px-3 py-2 text-[12px] leading-[18px] text-fg-muted shadow-[inset_0_0_0_1px_var(--warn-line)]">
        <Icon name="alert" className="mt-[2px] flex-none text-warn" />
        <div>This goal is {words(nw)} word{nw === 1 ? '' : 's'} long. The coordinator will plan broadly across all {plural(count, 'host')}. Sharpen it in the coordinator chat to focus the {fmtUsd(draft.budgetUsd)} budget.</div>
      </div>}
      <ScopeCard
        editing={editing}
        draft={draft}
        setDraft={setDraft}
        onHostsTouched={() => setUserTouchedHosts(true)}
      />
      <ConsentStepper />
      <LabPanel className="mt-5 border-t border-line" />
    </div>

    {/* Option 1: Pinned Sticky Bottom Action Bar */}
    <div
      data-testid="consent-sticky-bar"
      className="sticky bottom-0 z-20 mt-auto border-t border-line bg-surface/95 backdrop-blur-sm"
    >
      <div className="mx-auto flex w-full max-w-[780px] items-center justify-between gap-3 px-6 py-2.5">
        <div className="min-w-0 flex-1 truncate text-[12px]" data-testid="consent-bar-summary">
          {footerNote
            ? <span className="inline-flex items-center gap-1.5 font-medium text-warn">
                <Icon name="alert" size={13} className="flex-none" />
                <span className="truncate" title={footerNote} data-testid="consent-footer-note">{footerNote}</span>
              </span>
            : <span className="num text-fg-muted">{stickySummary}</span>}
        </div>
        <div className="flex flex-none items-center gap-2">
          {!discovery && <label className="flex cursor-pointer select-none items-center gap-1.5 whitespace-nowrap text-[11.5px] text-fg-muted">
            <input data-testid="consent-save-default" className={CHK} type="checkbox" disabled={approving} checked={saveProject} onChange={e => setSaveProject(e.target.checked)} />
            Save as project default
          </label>}
          <Link
            to="/projects/$projectId"
            params={{ projectId: detail.project.id }}
            className={cn(runBtn({ variant: 'ghost' }), 'no-underline')}
          >
            Cancel
          </Link>
          {!discovery && <button type="button" className={runBtn({ variant: 'ghost' })} onClick={() => { if (editing) { setUserTouchedHosts(false); setDraftState(initialDraft(r, defaults, rpsMax)) } else { setEditing(true) } }}>{editing ? 'Reset' : 'Edit scope'}</button>}
          <button
            type="button"
            className={runBtn({ variant: 'primary' })}
            disabled={!canApprove}
            title={canApprove ? undefined : approving ? 'Starting the assessment…' : footerNote ?? undefined}
            data-testid="consent-approve"
            onClick={() => void approve()}
          >
            {approving ? 'Starting…' : <>Approve &amp; start<Kbd inverted className="ml-0.5">A</Kbd></>}
          </button>
        </div>
      </div>
    </div>
  </div>
}

/** Header "Edit scope" dialog for runs past consent: save a scope revision or add a candidate host. */
export function ScopeOverlay() {
  const { detail, send, refresh, pending } = useRun()
  const overlays = useOverlays()
  const toast = useToast()
  const r = detail.run
  const rpsMax = detail.project.environment === 'local-lab' ? maxRpsPerOriginCeiling : PUBLIC_MAX_RPS_CAP
  const { discovery, defaults } = useScopeModel()
  const [draft, setDraftState] = useState<Draft>(() => initialDraft(r, defaults, rpsMax))
  const [draftRevision, setDraftRevision] = useState(r.scopeRevision)
  const [saveProject, setSaveProject] = useState(false)
  const [adding, setAdding] = useState(false)
  const [origin, setOrigin] = useState('')
  const [source, setSource] = useState('')
  const [thirdParty, setThirdParty] = useState(false)
  const [err, setErr] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveErr, setSaveErr] = useState('')
  const [conflict, setConflict] = useState(false)
  const [reloading, setReloading] = useState(false)
  const [pendingReload, setPendingReload] = useState(false)
  const editable = canReviewScope(r.phase, r.status) && !discovery
  const isRevisionConflict = conflict || r.scopeRevision !== draftRevision

  useEffect(() => {
    if (!pendingReload) return
    setDraftState(initialDraft(r, defaults, rpsMax))
    setDraftRevision(r.scopeRevision)
    setPendingReload(false)
  }, [pendingReload, r, defaults, rpsMax])

  useShortcuts([{ key: 'Escape', allowInInput: true, run: () => { if (!saving) overlays.closeScope() } }], { priority: 100, exclusive: true })

  const reloadLatestScope = async () => {
    setReloading(true)
    setSaveErr('')
    setConflict(false)
    try {
      await refresh()
    } finally {
      setReloading(false)
      setPendingReload(true)
    }
  }

  const save = async () => {
    if (saving || !editable) return
    const command = scopeCommand(r, draft, {
      saveProject,
      scopeOnly: true,
      expectedScopeRevision: draftRevision,
    })
    setSaving(true)
    setSaveErr('')
    setConflict(false)
    try {
      await send(command)
      toast.show(`Saved scope revision ${draftRevision + 1} (${plural(draft.assetIds.length, 'host')})`, { icon: 'globe' })
      overlays.closeScope()
    } catch (failure) {
      const msg = failure instanceof Error ? failure.message : 'Could not save scope revision.'
      setSaveErr(msg)
      if (/scope changed|scope_revision|revision/i.test(msg)) {
        setConflict(true)
      }
    } finally {
      setSaving(false)
    }
  }

  return <Dialog open closeOnEscape={!saving} onOpenChange={open => { if (!open && !saving) overlays.closeScope() }}>
    <DialogContent className="max-h-[80vh] max-w-[720px] overflow-auto rounded-2xl border-line-2 p-0" aria-label="Edit scope">
      <ScopeCard
        inDialog
        scopeOnly
        editing={editable}
        draft={draft}
        setDraft={fn => setDraftState(fn)}
        footer={<>
          {adding && <form
            className="flex flex-col gap-2 border-t border-line px-4 pb-3 pt-2.5"
            onSubmit={e => {
              e.preventDefault()
              setErr('')
              send({ action: 'candidate', candidate: { origin, source, thirdParty } }).then(() => { setAdding(false); setOrigin(''); setSource('') }, (x: unknown) => setErr(x instanceof Error ? x.message : 'Could not add the host'))
            }}
          >
            <span className="text-[12px] text-fg-subtle">Add a candidate host for scope review</span>
            <div className="flex gap-1.5">
              <input className={cn(RW.fieldInput, 'flex-1')} required placeholder="docs.example.com" value={origin} onChange={e => setOrigin(e.target.value)} aria-label="Host" />
              <input className={cn(RW.fieldInput, 'flex-1')} required maxLength={160} placeholder="Source (e.g. service inventory)" value={source} onChange={e => setSource(e.target.value)} aria-label="Source" />
            </div>
            <label className="flex cursor-pointer select-none items-center gap-2 text-[12.5px] text-fg-muted">
              <input className={CHK} type="checkbox" checked={thirdParty} onChange={e => setThirdParty(e.target.checked)} />
              Third-party service
            </label>
            {err && <span className="text-[12px] text-danger">{err}</span>}
            <div className="flex justify-end gap-1.5">
              <button type="button" className={runBtn({ variant: 'ghost' })} onClick={() => setAdding(false)}>Cancel</button>
              <button type="submit" className={runBtn()} disabled={pending > 0}>Add for review</button>
            </div>
          </form>}
          {isRevisionConflict && <div className="flex items-center gap-2.5 border-t border-line bg-warn-soft px-4 py-2.5 text-[12px] leading-[17px] text-fg" role="alert">
            <Icon name="alert" className="flex-none text-warn" />
            <span className="min-w-0 flex-1">
              {saveErr || `Scope changed on the server (now revision ${r.scopeRevision}) while you were editing.`} Reload the latest scope before saving.
            </span>
            <button type="button" className={runBtn({ size: 'xs' })} disabled={reloading || saving} onClick={() => void reloadLatestScope()}>
              {reloading ? 'Reloading…' : 'Reload latest scope'}
            </button>
          </div>}
          {!isRevisionConflict && saveErr && <div className="flex items-center gap-2 border-t border-line px-4 py-2 text-[12px] text-danger" role="alert">
            <Icon name="alert" className="flex-none" />
            <span>{saveErr}</span>
          </div>}
          <div className={RW.sheetF}>
            {editable
              ? <label className="mr-auto flex cursor-pointer select-none items-center gap-2 text-[12px] text-fg-subtle">
                <input className={CHK} type="checkbox" disabled={saving} checked={saveProject} onChange={e => setSaveProject(e.target.checked)} />
                Save as the project default
              </label>
              : <span className="mr-auto text-[12px] text-fg-subtle">{discovery ? 'Scope is reviewed after discovery.' : `Scope can’t change while the run is ${runStatusLabel(r.status).toLowerCase()}.`}</span>}
            {r.phase !== 'complete' && !discovery && !adding && <button type="button" className={runBtn({ variant: 'ghost' })} disabled={saving} onClick={() => setAdding(true)}><Icon name="plus" />Add host</button>}
            <button type="button" className={runBtn({ variant: 'ghost' })} disabled={saving} onClick={() => overlays.closeScope()}>Close</button>
            {editable && <button type="button" className={runBtn({ variant: 'primary' })} disabled={saving || reloading || isRevisionConflict || !draft.assetIds.length || draft.assetIds.length > maxScopeHosts} onClick={() => void save()}>{saving ? 'Saving…' : (r.phase === 'review' ? 'Approve scope' : 'Save scope revision')}</button>}
          </div>
        </>}
      />
    </DialogContent>
  </Dialog>
}
