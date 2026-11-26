// Static vocabulary for the run workspace: views, severities, statuses,
// coverage categories and phases. Shared by every view; extend additively.
import type { IconName } from './icons.tsx'

export const VIEW_IDS = ['overview', 'queue', 'findings', 'report', 'workflow', 'surface', 'exchanges', 'activity'] as const
export type ViewId = typeof VIEW_IDS[number]
export type ViewGroup = 'investigation' | 'telemetry'

export const VIEWS: { id: ViewId; label: string; key: string; icon: IconName; group: ViewGroup }[] = [
  { id: 'overview', label: 'Overview', key: 'o', icon: 'overview', group: 'investigation' },
  { id: 'queue', label: 'Queue', key: 'q', icon: 'queue', group: 'investigation' },
  { id: 'findings', label: 'Findings', key: 'f', icon: 'findings', group: 'investigation' },
  { id: 'report', label: 'Report', key: 'r', icon: 'report', group: 'investigation' },
  { id: 'workflow', label: 'Workflow', key: 'w', icon: 'workflow', group: 'telemetry' },
  { id: 'surface', label: 'Surface', key: 's', icon: 'surface', group: 'telemetry' },
  { id: 'exchanges', label: 'Exchanges', key: 'e', icon: 'exchanges', group: 'telemetry' },
  { id: 'activity', label: 'Activity', key: 'a', icon: 'activity', group: 'telemetry' },
]
export const isViewId = (v: unknown): v is ViewId => typeof v === 'string' && (VIEW_IDS as readonly string[]).includes(v)

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export const SEV: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']
export const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4, info: 4 }
export const SEV_LABEL: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info', info: 'Info' }
export const SEV_COL: Record<string, string> = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--fg-2)', informational: 'var(--fg-4)' }

/** Display status for findings: runtime `confirmed` is strictly separated from `static_verified` advisories. */
export type FindingDisplayStatus = 'confirmed' | 'static_verified' | 'pending' | 'inconclusive' | 'dismissed'
export function normFStatus(s: string): FindingDisplayStatus {
  if (s === 'confirmed' || s === 'verified') return 'confirmed'
  if (s === 'static_verified') return 'static_verified'
  if (s === 'pending' || s === 'proposed') return 'pending'
  return s === 'dismissed' ? 'dismissed' : 'inconclusive'
}
export const FSTAT_ORDER: Record<string, number> = { confirmed: 0, verified: 0, static_verified: 1, pending: 2, proposed: 2, inconclusive: 3, dismissed: 4 }

export const ST_LABEL: Record<string, string> = {
  confirmed: 'Confirmed by replay', static_verified: 'Static advisory', verified: 'Verified', proposed: 'Proposed',
  pending: 'Awaiting verification', inconclusive: 'Inconclusive', dismissed: 'Dismissed', complete: 'Complete',
  failed: 'Failed', paused: 'Paused', budget_paused: 'Budget paused', stopped: 'Stopped', canceled: 'Canceled',
  tainted: 'Tainted', ready: 'Ready', waiting: 'Waiting', running: 'Running', queued: 'Queued',
  waiting_approval: 'Awaiting approval', blocked: 'Blocked',
  no_issue_found: 'No issue found', needs_follow_up: 'Needs follow-up', ruled_out: 'Ruled out',
  not_applicable: 'Not applicable', reported: 'Reported', untested: 'Not yet charted',
  approved: 'Approved', denied: 'Denied', expired: 'Expired',
}
export const stLabel = (s: string) => ST_LABEL[s] ?? (s.charAt(0).toUpperCase() + s.slice(1).replace(/_/g, ' '))

/** Run status label for the run line and rail. */
export const runStatusLabel = (s: string) => s === 'waiting' ? 'Waiting' : stLabel(s)

/** The 11 coverage categories, in matrix column order: [id, label, letter, short]. */
export const CATS: [string, string, string, string][] = [
  ['auth-identity', 'Auth & identity', 'A', 'Auth'],
  ['broken-access-control', 'Access control', 'B', 'Access'],
  ['injection-input', 'Injection & input', 'C', 'Injection'],
  ['cors-client-side', 'CORS & client-side', 'D', 'CORS'],
  ['misconfig-exposure', 'Misconfig & exposure', 'E', 'Config'],
  ['crypto-tls-transport', 'TLS & transport', 'F', 'TLS'],
  ['dns-takeover-infra', 'DNS & infra', 'G', 'DNS'],
  ['ssrf-redirects', 'SSRF & redirects', 'H', 'SSRF'],
  ['upload-storage', 'Upload & storage', 'I', 'Upload'],
  ['business-logic-race', 'Logic & race', 'J', 'Logic'],
  ['llm-ai-security', 'LLM & AI', 'K', 'LLM'],
]
export const CAT_IDX: Record<string, number> = Object.fromEntries(CATS.map((c, i) => [c[0], i]))
/** Finding category (free text) → coverage category. D's heuristic, extended. */
export const FCAT: Record<string, string> = {
  'Transport security': 'crypto-tls-transport', 'Browser hardening': 'misconfig-exposure',
  'UI redress protection': 'cors-client-side', 'Information exposure': 'misconfig-exposure', 'dom-xss': 'injection-input',
}
export const covCat = (c: string | null | undefined) => c == null ? null : CAT_IDX[c] != null ? c : (FCAT[c] ?? null)
const CATL: Record<string, string> = Object.fromEntries(CATS.map(c => [c[0], c[1]]))
export const prettyCat = (c: string | null | undefined) => (c && CATL[c]) || c || '—'

export type CoverageStatus = 'reported' | 'needs_follow_up' | 'no_issue_found' | 'ruled_out' | 'not_applicable' | 'untested'
export const COV_ST: [CoverageStatus, string][] = [
  ['reported', 'Reported'], ['needs_follow_up', 'Needs follow-up'], ['no_issue_found', 'No issue found'],
  ['ruled_out', 'Ruled out'], ['not_applicable', 'Not applicable'], ['untested', 'Not yet charted'],
]
export const COV_L: Record<string, string> = Object.fromEntries(COV_ST)

export const RISK = ['critical', 'high', 'medium', 'low', 'unranked'] as const
export type RiskTier = typeof RISK[number]
export const RISKL: Record<RiskTier, string> = { critical: 'Critical surface', high: 'High-risk surface', medium: 'Medium-risk surface', low: 'Low-risk surface', unranked: 'Unranked' }

/** Display names for run and worker phases. */
export const PHASE_LABEL: Record<string, string> = {
  consent: 'Consent', review: 'Scope review', discovery: 'Discovery', threat_model: 'Threat model',
  investigation: 'Investigation', verification: 'Verification', retest: 'Fix verification', complete: 'Complete', report: 'Report',
}
/** Worker phase order (columns in the workflow graph). */
export const PHASE_ORDER: Record<string, number> = { discovery: 0, threat_model: 1, investigation: 2, verification: 3, retest: 4 }

export const TIER_SHORT: Record<number, string> = { 0: 'Offline', 1: 'Read-only', 2: 'Authenticated', 3: 'Active, with approval' }

/** Response headers each baseline check inspects (for highlighting in exchange headers). */
export const CHECK_HEADERS: Record<string, string[]> = {
  hsts: ['strict-transport-security'], nosniff: ['x-content-type-options'],
  'content-security-policy': ['content-security-policy', 'content-security-policy-report-only'],
  'frame-protection': ['x-frame-options', 'content-security-policy'], 'referrer-policy': ['referrer-policy'],
  'server-disclosure': ['server', 'x-powered-by', 'via'],
}
