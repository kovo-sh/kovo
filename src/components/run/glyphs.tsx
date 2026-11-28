// Status and severity glyphs. Shape always doubles colour (colour-blind safe).
import type { ReactNode } from 'react'
import { assertNever } from '../../server/run-status.ts'
import { getStepStatusMeta, STEP_STATUS, type ChainStepStatus } from '../../step-status.ts'
import { RISKL, SEV_COL, stLabel } from './meta.ts'
import type { CoverageStatus, RiskTier } from './meta.ts'
import { cn, covTileClass } from './tw.ts'

/** Severity: critical = filled red tile with "!", others = 3 signal bars, info = 3 dots. */
export function SevGlyph({ sev }: { sev: string | null | undefined }) {
  const s = sev || 'informational'
  if (s === 'critical') {
    return <svg className="block flex-none" viewBox="0 0 14 14" width="14" height="14" aria-hidden="true">
      <rect x="1" y="1" width="12" height="12" rx="3" fill="var(--crit)" />
      <path d="M7 4v3.5M7 9.75v.01" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  }
  const n = ({ high: 3, medium: 2, low: 1 } as Record<string, number>)[s] ?? 0
  const col = ({ high: 'var(--high)', medium: 'var(--med)', low: 'var(--fg-2)' } as Record<string, string>)[s] ?? 'var(--fg-3)'
  const bars: [number, number, number][] = [[1.5, 8, 4], [5.75, 5.5, 6.5], [10, 3, 9]]
  return <svg className="block flex-none" viewBox="0 0 14 14" width="14" height="14" aria-hidden="true">
    {bars.map((b, i) => n === 0
      ? <rect key={i} x={b[0]} y="6" width="2.5" height="2" rx="1" fill="var(--fg-3)" />
      : <rect key={i} x={b[0]} y={b[1]} width="2.5" height={b[2]} rx="1" fill={i < n ? col : 'var(--fg-4)'} />)}
  </svg>
}

function Ring({ stroke, dash, glyph, children }: { stroke: string; dash?: boolean; glyph?: string; children?: ReactNode }) {
  return <svg className="block flex-none" viewBox="0 0 14 14" width="14" height="14" aria-hidden="true" data-status-glyph={glyph}>
    <circle cx="7" cy="7" r="5.75" fill="none" stroke={stroke} strokeWidth="1.4" strokeDasharray={dash ? '2.1 1.9' : undefined} />
    {children}
  </svg>
}

function Solid({ fill, glyph, children }: { fill: string; glyph?: string; children: ReactNode }) {
  return <svg className="block flex-none" viewBox="0 0 14 14" width="14" height="14" aria-hidden="true" data-status-glyph={glyph}>
    <circle cx="7" cy="7" r="6.5" fill={fill} />
    {children}
  </svg>
}

const SLASH = <path d="M4.9 9.1l4.2-4.2" stroke="var(--fg-3)" strokeWidth="1.4" strokeLinecap="round" />
const CHECK = <path d="M4.4 7.2 6.2 9 9.7 5.3" fill="none" stroke="var(--panel)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
const CROSS = <path d="M5 5l4 4M9 5 5 9" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" />

/**
 * Exhaustive renderer for every `ChainStepStatus` driven by `STEP_STATUS[status].glyph`.
 * Adding a new status to `STEP_STATUS` forces a compile-time & `check-exhaustive` update here.
 */
function renderStepStatusGlyph(status: ChainStepStatus): ReactNode {
  const glyph = STEP_STATUS[status].glyph
  switch (status) {
    case 'pending':
    case 'ready':
      return <Ring stroke="var(--fg-2)" glyph={glyph}><path d="M7 3.5A3.5 3.5 0 0 1 7 10.5Z" fill="var(--fg-2)" /></Ring>
    case 'running':
      return <Ring stroke="var(--accent)" glyph={glyph}><path d="M7 3.5A3.5 3.5 0 0 1 10.5 7H7Z" fill="var(--accent)" /></Ring>
    case 'complete':
      return <Solid fill="var(--fg-4)" glyph={glyph}>{CHECK}</Solid>
    case 'canceled':
      return <Ring stroke="var(--fg-4)" glyph={glyph}>{SLASH}</Ring>
    case 'blocked':
    case 'tainted':
      return <Solid fill="var(--bad)" glyph={glyph}>{CROSS}</Solid>
    case 'infra_failed':
      return <Solid fill="var(--bad)" glyph={glyph}><path d="M7.6 3.5 4.8 7.3h2.1L6.4 10.5 9.2 6.7H7.1l.5-3.2Z" fill="#fff" /></Solid>
    case 'model_failure':
      return <Solid fill="var(--bad)" glyph={glyph}><path d="M7 4v3.4M7 9.6v.01" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" /></Solid>
    case 'turn_capped':
      return <Ring stroke="var(--warn)" glyph={glyph}><path d="M4.5 5h5M7 5v4.5" stroke="var(--warn)" strokeWidth="1.45" strokeLinecap="round" /></Ring>
    case 'nudged_out':
      return <Ring stroke="var(--warn)" dash glyph={glyph}><path d="M5.25 4.8 8.5 7 5.25 9.2" fill="none" stroke="var(--warn)" strokeWidth="1.45" strokeLinecap="round" strokeLinejoin="round" /></Ring>
    case 'rotated_partial':
      return <Ring stroke="var(--warn)" dash glyph={glyph}><path d="M7 3.8A3.2 3.2 0 1 1 3.8 7" fill="none" stroke="var(--warn)" strokeWidth="1.45" strokeLinecap="round" /></Ring>
    default:
      return assertNever(status, 'Unhandled ChainStepStatus glyph')
  }
}

/**
 * Status glyph for findings, workers, runs, steps, coverage and approvals.
 * Step statuses derive exhaustively from `STEP_STATUS`; "confirmed" is a quiet outlined check,
 * "fixed" (a verified retest) is the same check drawn in `--ok`.
 */
export function StatusGlyph({ status }: { status: string | null | undefined }) {
  const stepMeta = getStepStatusMeta(status)
  if (stepMeta) {
    return renderStepStatusGlyph(status as ChainStepStatus)
  }
  switch (status) {
    case 'confirmed': case 'verified': case 'approved':
      return <Ring stroke="var(--fg-3)" glyph={status}><path d="M4.6 7.1 6.3 8.8 9.5 5.4" fill="none" stroke="var(--fg-2)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></Ring>
    case 'fixed':
      return <Ring stroke="var(--ok)" glyph={status}><path d="M4.6 7.1 6.3 8.8 9.5 5.4" fill="none" stroke="var(--ok)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></Ring>
    case 'static_verified':
      return <Ring stroke="var(--fg-3)" dash glyph={status}><path d="M5.4 5.2 3.8 7l1.6 1.8M8.6 5.2 10.2 7 8.6 8.8" fill="none" stroke="var(--fg-2)" strokeWidth="1.35" strokeLinecap="round" strokeLinejoin="round" /></Ring>
    case 'needs_review':
      return <Ring stroke="var(--warn)" glyph={status}><path d="M7 4.2v3.3M7 9.7v.01" stroke="var(--warn)" strokeWidth="1.6" strokeLinecap="round" /></Ring>
    case 'reported':
      return <Ring stroke="var(--fg-3)" glyph={status}><path d="M7 4.25 9.75 7 7 9.75 4.25 7Z" fill="var(--fg-2)" /></Ring>
    case 'no_issue_found':
      return <Solid fill="var(--fg-4)" glyph={status}>{CHECK}</Solid>
    case 'proposed': case 'queued': case 'needs_follow_up': {
      const c = status === 'needs_follow_up' ? 'var(--warn)' : 'var(--fg-2)'
      return <Ring stroke={c} glyph={status}><path d="M7 3.5A3.5 3.5 0 0 1 7 10.5Z" fill={c} /></Ring>
    }
    case 'active':
      return <Ring stroke="var(--accent)" glyph={status}><path d="M7 3.5A3.5 3.5 0 0 1 10.5 7H7Z" fill="var(--accent)" /></Ring>
    case 'inconclusive':
      return <Ring stroke="var(--fg-3)" dash glyph={status}><path d="M7 7h.01" stroke="var(--fg-3)" strokeWidth="2" strokeLinecap="round" /></Ring>
    case 'dismissed': case 'ruled_out': case 'stopped': case 'expired':
      return <Ring stroke="var(--fg-4)" glyph={status}>{SLASH}</Ring>
    case 'not_applicable':
      return <Ring stroke="var(--fg-4)" dash glyph={status}><path d="M4.75 7h4.5" stroke="var(--fg-4)" strokeWidth="1.4" strokeLinecap="round" /></Ring>
    case 'failed': case 'denied':
      return <Solid fill="var(--bad)" glyph={status}>{CROSS}</Solid>
    case 'paused': case 'budget_paused': case 'waiting_approval':
      return <Ring stroke="var(--warn)" glyph={status}><path d="M5.75 5v4M8.25 5v4" stroke="var(--warn)" strokeWidth="1.4" strokeLinecap="round" /></Ring>
    case 'waiting': case 'consent':
      return <Ring stroke="var(--fg-2)" glyph={status}><path d="M7 4.5V7l1.75 1" fill="none" stroke="var(--fg-2)" strokeWidth="1.4" strokeLinecap="round" /></Ring>
    default:
      return <Ring stroke="var(--fg-3)" />
  }
}

/** Activity event dot, coloured by event family. */
export function EventGlyph({ kind }: { kind: string }) {
  const fam = kind.split('.')[0]
  let col = 'var(--fg-4)'
  if (kind === 'broker.denied' || kind === 'worker.failed') col = 'var(--bad)'
  else if (fam === 'finding') col = kind === 'finding.verified' ? 'var(--fg)' : 'var(--fg-2)'
  else if (['planner', 'report', 'run', 'approval'].includes(fam) || kind === 'interrupted') col = 'var(--fg-2)'
  else if (fam === 'worker') col = 'var(--fg-3)'
  return <svg className="block flex-none" viewBox="0 0 14 14" width="14" height="14" aria-hidden="true"><circle cx="7" cy="7" r="3" fill={col} /></svg>
}

/** Coverage status shape glyph (colour-blind safe: diamond, triangle, dot, slashed ring, dash, speck). */
export function CovGlyph({ status }: { status: CoverageStatus | string }) {
  switch (status) {
    case 'reported':
      return <span className="block size-2 flex-none rotate-45 rounded-[1px] bg-current" />
    case 'needs_follow_up':
      return <span className="block h-[9px] w-2.5 flex-none bg-current [clip-path:polygon(50%_0,100%_100%,0_100%)]" />
    case 'no_issue_found':
      return <span className="block size-[7px] flex-none rounded-full bg-current" />
    case 'ruled_out':
      return <span className="relative block size-[9px] flex-none rounded-full border-[1.5px] border-current after:absolute after:-bottom-px after:-top-px after:left-1/2 after:-ml-[0.75px] after:w-[1.5px] after:rotate-45 after:bg-current after:content-['']" />
    case 'not_applicable':
      return <span className="block h-[1.5px] w-2 flex-none rounded-[1px] bg-current" />
    default:
      return <span className="block size-[3px] flex-none rounded-full bg-current" />
  }
}

/** Coverage swatch: tinted tile + status shape (surface map, legends). */
export function CovSwatch({ status, size, className }: { status: CoverageStatus | string; size?: [number, number]; className?: string }) {
  return <span
    className={cn(
      'grid h-[14px] w-[18px] flex-none place-items-center rounded-[3px] border',
      covTileClass(status),
      status === 'untested' && 'border-line-2!',
      className,
    )}
    style={size ? { width: size[0], height: size[1] } : undefined}
  >
    <CovGlyph status={status} />
  </span>
}

/** Surface map severity pin: shape = severity, solid = confirmed, outline = unverified, slash = dismissed. */
export function PinGlyph({ sev, status, size = 10 }: { sev: string; status: string; size?: number }) {
  const col = SEV_COL[sev] || 'var(--fg-4)'
  const solid = status === 'confirmed' || status === 'verified'
  const dis = status === 'dismissed'
  const s = size, h = s / 2
  let shape: ReactNode
  if (sev === 'critical') shape = <path d={`M${h} .7 ${s - .7} ${h} ${h} ${s - .7} .7 ${h}Z`} />
  else if (sev === 'high') shape = <path d={`M${h} .8 ${s - .6} ${s - .9} .6 ${s - .9}Z`} />
  else if (sev === 'medium') shape = <rect x="1" y="1" width={s - 2} height={s - 2} rx="1" />
  else if (sev === 'low') shape = <circle cx={h} cy={h} r={h - 1} />
  else shape = <circle cx={h} cy={h} r={h - 2.2} />
  const c2 = sev === 'informational' ? 'var(--fg-3)' : sev === 'low' ? 'var(--fg-2)' : col
  return <svg className="block flex-none" viewBox={`0 0 ${s} ${s}`} width={s} height={s} style={{ overflow: 'visible' }} aria-hidden="true">
    <g fill={dis ? 'none' : solid ? c2 : 'none'} stroke={dis ? 'var(--fg-4)' : c2} strokeWidth={solid && !dis ? 0 : 1.3}>{shape}</g>
    {dis && <path d={`M0 ${s} ${s} 0`} stroke="var(--fg-4)" strokeWidth="1.2" />}
  </svg>
}

/** Threat-model risk as 4 rising bars. */
export function TierBars({ tier, className }: { tier: RiskTier; className?: string }) {
  const n = { critical: 4, high: 3, medium: 2, low: 1, unranked: 0 }[tier]
  return <span className={cn('inline-flex h-[9px] flex-none items-end gap-[1.5px]', className)} title={RISKL[tier]}>
    {[0, 1, 2, 3].map(i => <i key={i} className={cn('w-0.5 rounded-[1px]', i < n ? 'bg-fg-subtle' : 'bg-line-2')} style={{ height: 4 + i * 1.5 }} />)}
  </span>
}

/** Run phase track: 4 segments, done / current (accent) / future. */
export function PhaseTrack({ phase }: { phase: string }) {
  const order = ['consent', 'threat_model', 'investigation', 'verification']
  const map: Record<string, number> = { consent: 0, review: 0, discovery: 0, threat_model: 1, investigation: 2, verification: 3 }
  const pi = map[phase] ?? 0
  return <span className="inline-flex gap-0.5" aria-hidden="true">
    {order.map((p, i) => <i key={p} className={cn('h-1 w-2.5 rounded-[2px]', phase === 'complete' || i < pi ? 'bg-fg-subtle' : i === pi ? 'bg-accent' : 'bg-line-2')} />)}
  </span>
}

/** Pulsing live status indicator (accent when active, warn when paused). */
export function LiveDot({ paused, className }: { paused?: boolean; className?: string }) {
  return <span className={cn('relative inline-block size-2 flex-none', className)} aria-hidden="true">
    <span className={cn('absolute inset-0 rounded-full', paused ? 'bg-warn' : 'bg-accent')} />
    <span className={cn(
      'absolute -inset-1 rounded-full border-[1.5px] motion-reduce:animate-none',
      paused ? 'animate-pulse border-warn opacity-45' : 'animate-ping border-accent opacity-50',
    )} />
  </span>
}

/** Worker status glyph; live states render a dot (pulsing only when `pulse`, one per view — A-130). */
export function LiveGlyph({ status, pulse, dotClassName }: { status: string; pulse?: boolean; dotClassName?: string }) {
  const paused = status === 'paused' || status === 'waiting_approval'
  if (status !== 'running' && !paused) return <StatusGlyph status={status} />
  return <span className="inline-flex items-center justify-center" title={paused ? stLabel(status) : 'Running'}>
    {pulse
      ? <LiveDot paused={paused} className={dotClassName} />
      : <span className={cn('inline-block size-2 flex-none rounded-full', paused ? 'bg-warn' : 'bg-accent', dotClassName)} aria-hidden="true" />}
  </span>
}
