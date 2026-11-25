// Formatting helpers shared by every run view. Pure functions, no React.

export const host = (origin: string | null | undefined) =>
  String(origin ?? '').replace(/^https?:\/\//, '').replace(/\/$/, '')

export const fmtN = (n: number | null | undefined) => (n == null ? '—' : Number(n).toLocaleString('en-US'))
export const fmtUsd = (n: number | null | undefined) => '$' + Number(n || 0).toFixed(2)
export const fmtTok = (n: number) => n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? Math.round(n / 1e3) + 'k' : String(n || 0)
export const short = (id: string | null | undefined) => String(id ?? '').slice(0, 8)

const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
export const pad = (n: number) => String(n).padStart(2, '0')
export const fmtTime = (ms: number) => { const d = new Date(ms); return pad(d.getHours()) + ':' + pad(d.getMinutes()) }
export const fmtTimeS = (ms: number) => { const d = new Date(ms); return fmtTime(ms) + ':' + pad(d.getSeconds()) }
export const fmtDay = (ms: number) => { const d = new Date(ms); return MON[d.getMonth()] + ' ' + d.getDate() }
export const fmtDate = (ms: number) => fmtDay(ms) + ', ' + fmtTime(ms)
/** Full local date + time for `title` tooltips (e.g. "Nov 22, 2026, 2:15 PM"). */
export const fmtFullDateTime = (ms: number) => {
  if (!Number.isFinite(ms)) return ''
  try {
    return new Date(ms).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })
  } catch {
    return fmtDate(ms)
  }
}
/** Human relative time: `< 24h` -> "Just now" / "8m ago" / "3h ago"; `>= 24h` -> "Nov 22". */
export const fmtAgo = (ms: number, now = Date.now()) => {
  if (!Number.isFinite(ms)) return ''
  const diff = Math.max(0, now - ms)
  if (diff < 60_000) return 'Just now'
  if (diff < 3_600_000) return Math.floor(diff / 60_000) + 'm ago'
  if (diff < 86_400_000) return Math.floor(diff / 3_600_000) + 'h ago'
  return fmtDay(ms)
}

/** Known URL query params used by run view sub-modes (preserved across selection updates). */
export const RUN_SUBMODE_PARAMS = ['mode', 'version'] as const

/** Read a single URL query param from `window.location.search` (SSR-safe). */
export function readRunUrlParam(key: string): string | null {
  if (typeof window === 'undefined') return null
  return new URLSearchParams(window.location.search).get(key)
}

/** Sync a single URL query param via `history.replaceState` without disturbing TanStack Router state. */
export function syncRunUrlParam(key: string, value: string | null | undefined) {
  if (typeof window === 'undefined') return
  const url = new URL(window.location.href)
  const prev = url.searchParams.get(key)
  if (!value) {
    if (prev === null) return
    url.searchParams.delete(key)
  } else {
    if (prev === value) return
    url.searchParams.set(key, value)
  }
  const next = url.pathname + url.search + url.hash
  window.history.replaceState(window.history.state, '', next)
}

const EVENT_KIND_LABELS: Record<string, string> = {
  'broker.exchange': 'HTTP exchange',
  'broker.allowed': 'Request allowed',
  'broker.denied': 'Request blocked',
  'broker.circuit_open': 'Host rate-limited',
  'broker.route_circuit': 'Route paused',
  'broker.persona_scope_mismatch': 'Test account scope mismatch',
  'worker.started': 'Worker started',
  'worker.complete': 'Worker finished',
  'worker.failed': 'Worker failed',
  'worker.canceled': 'Worker canceled',
  'worker.stall_retry': 'Worker retry',
  'worker.stall_failed': 'Worker stalled',
  'worker.provider_stall': 'Model response stalled',
  'worker.warm_pool_rotated': 'Worker container refreshed',
  'finding.proposed': 'Finding drafted',
  'finding.verified': 'Finding confirmed',
  'finding.updated': 'Finding updated',
  'finding.confirmation_conflict': 'Verification conflict',
  'finding.floor_preserved': 'Verified finding preserved',
  'verification.started': 'Verification started',
  'retest.queued': 'Fix verification queued',
  'retest.complete': 'Fix verification finished',
  'planner.round': 'Planning round',
  'planner.dry_streak': 'Planning stalled',
  'planner.capped_reinvestigations': 'Re-investigation limit reached',
  'planner.ready_steps_stranded': 'Queued steps waiting',
  'chain_step.created': 'Plan step added',
  'chain_step.canceled': 'Plan step canceled',
  'graph.compacted': 'Memory compacted',
  'fact.recorded': 'Fact recorded',
  'evidence.reused': 'Evidence reused',
  'evidence.restricted': 'Evidence restricted',
  'approval.requested': 'Approval requested',
  'approval.decided': 'Approval decided',
  'approval.auto_approved': 'Auto-approved by policy',
  'approval.auto_denied': 'Auto-denied by policy',
  'approval.policy_changed': 'Approval policy updated',
  'approval.pattern_approved': 'Similar requests approved',
  'approval.batch_approved': 'Pending requests approved',
  'approval.lease_granted': 'Approval window granted',
  'approval.lease_revoked': 'Approval window revoked',
  'approval.worker_parked': 'Worker waiting for approval',
  'approval.worker_resumed': 'Worker resumed after approval',
  'run.created': 'Run created',
  'run.paused': 'Run paused',
  'run.resumed': 'Run resumed',
  'run.budget_paused': 'Paused at budget limit',
  'budget.raised': 'Budget updated',
  'scope.approved': 'Scope approved',
  'scope.revoked': 'Scope updated',
  'scope.environment_mode': 'Environment mode set',
  'scope.route_denylist': 'Route blocklist updated',
  'scope.origin_role': 'Host role updated',
  'goal.revised': 'Goal updated',
  'discovery.consented': 'Discovery started',
  'discovery.complete': 'Discovery finished',
  'threat_model.saved': 'Threat model saved',
  'threat_model.failed': 'Threat model failed',
  'review.planned': 'Review planned',
  'report.partial': 'Partial report saved',
  'report.complete': 'Final report ready',
  'board.message': 'Board message',
  'board.tainted': 'Board message marked outdated',
  'coordinator.message': 'Coordinator message',
  'hint.injected': 'Operator guidance added',
  'asset.candidate': 'Host discovered',
  'surface.probe': 'Surface check',
  'sast.run': 'Code scan',
  'code_audit.started': 'Code review started',
  'code_audit.complete': 'Code review finished',
  'patch.saved': 'Verified patch saved',
  'persona.authenticated': 'Test account signed in',
  'persona.auth_failed': 'Test account sign-in failed',
  'persona.refresh_failed': 'Test account session refresh failed',
  'scheduler.dispatch': 'Worker dispatched',
  'scheduler.queue_drain': 'Queue drained',
  'scheduler.multi_trial': 'Parallel verification',
  'trial.early_stopped': 'Trial stopped early',
  'deterministic_engine.confirmed': 'Automated check confirmed',
  'deterministic_engine.lead': 'Automated lead found',
  'deterministic_engine.summary': 'Automated scan summary',
  'deterministic_lane.started': 'Automated scan started',
  'deterministic_lane.failed': 'Automated scan failed',
  'deterministic_lane.aborting': 'Automated scan stopping',
  'deterministic_lane.metrics': 'Automated scan metrics',
  'deterministic_floor.summary': 'Baseline scan summary',
  'request_budget.phase_started': 'Request budget phase started',
  'request_budget.phase_ended': 'Request budget phase ended',
  'request_budget.floor_settled': 'Baseline budget settled',
  'request_budget.floor_exhausted': 'Baseline budget reached',
  'request_budget.agent_exhausted': 'Agent request budget reached',
  'agentic.assignment_metrics': 'Worker metrics',
  'agent.proof_obligation': 'Verification check',
  'agent.gap_validation': 'Coverage gap check',
  'agent.early_exit': 'Worker finished early',
  'oob.drain_complete': 'Callback check finished',
  'oob.receipt_confirmed': 'Callback verified',
  'proof_gaps.surfaced': 'Coverage gaps noted',
  'second_order_canary.surfaced': 'Delayed signal detected',
  'recovery.completed': 'Run recovered',
  'retention.pruned': 'Old records pruned',
  'staging.teardown': 'Lab teardown',
  'staging.untagged_skipped': 'Untagged route skipped',
  'interrupted': 'Run interrupted',
}

/** Convert raw dotted event keys (`broker.exchange`) into plain-English labels (`HTTP exchange`). */
export function fmtEventKind(kind: string): string {
  const exact = EVENT_KIND_LABELS[kind]
  if (exact) return exact
  const clean = kind.replace(/[._]+/g, ' ').trim()
  return clean ? clean.charAt(0).toUpperCase() + clean.slice(1) : 'Event'
}
/** "+mm:ss" / "h:mm:ss" offset from the run start, used in time columns. */
export const fmtRel = (ms: number, base: number) => {
  let s = Math.max(0, Math.round((ms - base) / 1000))
  const h = Math.floor(s / 3600); s -= h * 3600
  const m = Math.floor(s / 60); s -= m * 60
  return (h ? h + ':' + pad(m) : '+' + pad(m)) + ':' + pad(s)
}
export const fmtDur = (ms: number) => {
  const s = Math.round(ms / 1000)
  if (s < 60) return s + 's'
  const m = Math.floor(s / 60)
  if (m < 60) return m + 'm ' + pad(s % 60) + 's'
  return Math.floor(m / 60) + 'h ' + pad(m % 60) + 'm'
}
export const cap = (s: string | null | undefined) => String(s ?? '').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase())
export const capF = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)
export const plural = (n: number, w: string, p?: string) => fmtN(n) + ' ' + (n === 1 ? w : (p ?? w + 's'))
const WORDS = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen', 'twenty']
/** Small numbers as words ("two medium-severity weaknesses"), larger as digits. */
export const words = (n: number) => n < WORDS.length ? WORDS[n] : fmtN(n)
export const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v))

export const firstSentence = (input: string | null | undefined) => {
  const s = String(input ?? '').trim()
  const m = s.match(/^(.{20,150}?[.;:])(\s|$)/)
  let r = m ? m[1] : s.slice(0, 140)
  if (r.length >= 140 && !m) r = r.replace(/\s+\S*$/, '') + '…'
  return r.replace(/[.;:]$/, '')
}

/** Short label for a run in the rail / palette ("Tier 1 Deep Read-Only + Safe…"). */
export function runLabel(goal: string) {
  let g = String(goal || '').replace(/^(perform|conduct|run)\s+an?\s+/i, '').replace(/^strictly defensive,\s*non-destructive\s+/i, '')
  g = g.split(/[.:]/)[0]
  return g.charAt(0).toUpperCase() + g.slice(1)
}

/** Most common apex domain, if at least half the hosts share it (used to dim it in host labels). */
export function sharedApex(hosts: readonly string[]) {
  const cnt = new Map<string, number>()
  for (const h of hosts) {
    const k = h.split('.').slice(-2).join('.')
    cnt.set(k, (cnt.get(k) ?? 0) + 1)
  }
  const best = [...cnt.entries()].sort((a, b) => b[1] - a[1])[0]
  return best && best[1] >= hosts.length / 2 && hosts.length > 1 ? best[0] : null
}

export const isMac = () => typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)
export const modKey = () => (isMac() ? '⌘' : 'Ctrl')

/** Body text for display: JSON is pretty-printed, anything else is returned as is; empty → ''. */
export function prettyBody(body: unknown, mediaType = ''): string {
  if (body == null) return ''
  if (typeof body !== 'string') return JSON.stringify(body, null, 2)
  const t = body.trim()
  if (!t) return ''
  if (mediaType.includes('json') || t.startsWith('{') || t.startsWith('[')) {
    try { return JSON.stringify(JSON.parse(t), null, 2) } catch { return body }
  }
  return body
}
