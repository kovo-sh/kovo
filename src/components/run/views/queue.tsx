// Queue view (E's triage inside F's frame), owned by Agent Q.
//
// Decide / Follow up / Done (model.queue + the shared decision store). The
// reading view lives in the right pane (`queue` inspector) with a sticky action
// bar. Every action sends a real server command (`decide_approval`,
// `approve_similar_endpoint`, `approve_all_pending`, `inject_hint`).
import { useEffect, useLayoutEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import type { ReactNode } from 'react'
import {
  approvalRouteDedupeKey,
  DEFAULT_APPROVAL_LEASE_TTL_MS,
  defaultMaxUsesForLeaseScope,
  defaultPrimaryApprovalScope,
  eligibleApprovalPrefixPattern,
  isHostNonDestructiveEligibleCard,
  normalizeClientApprovalPath,
} from '../../../domain.ts'
import type { ApprovalBlastRadiusPreview, ApprovalScope } from '../../../domain.ts'
import { previewApprovalBlastRadiusAction } from '../../../actions-run-controls.ts'
import { capabilityTierMeta } from '../../run-state.ts'
import { useRun, useRunModel } from '../data.tsx'
import { ACTIONS, actionsFor, approvalCommand, useDecisions } from '../decisions.tsx'
import type { DecisionAct, DecisionsApi } from '../decisions.tsx'
import type { Command } from '../data.tsx'
import { EmptyState, Kbd, Tag } from '../display.tsx'
import { cap, fmtTime, fmtTimeS, fmtUsd, host, plural } from '../format.ts'
import { StatusGlyph } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import type { IconName } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { prettyCat } from '../meta.ts'
import { isApprovalExpired, QSEC } from '../model.ts'
import type { Approval, QueueItem, QueueSection, RunModel } from '../model.ts'
import { AnimatedNumber, EASE_CSS, T } from '../motion.tsx'
import { useListNav, useNav, useViewState } from '../nav.tsx'
import type { NavApi } from '../nav.tsx'
import { PaneBody, PaneHeader } from '../pane.tsx'
import type { InspectorMap, InspectorProps } from '../pane.tsx'
import { usePaletteCommands } from '../palette.tsx'
import { cn, runBtn, runDec, runIconBtn, runStamp, RW } from '../tw.ts'
import { QGlyph, ReadApproval, ReadConsent, ReadFinding, ReadFollow, VState } from './queue-read.tsx'

// ---------------------------------------------------------------- decision motion store
// One tiny external store so the list row and the inspector's action bar
// stamp together, whichever of them started the decision.

interface Motion { key: string | null; act: DecisionAct | null; phase: 'idle' | 'stamp' | 'leave'; enter: string | null }
let motion: Motion = { key: null, act: null, phase: 'idle', enter: null }
const subs = new Set<() => void>()
const setMotion = (m: Partial<Motion>) => { motion = { ...motion, ...m }; subs.forEach(f => f()) }
const subscribe = (f: () => void) => { subs.add(f); return () => { subs.delete(f) } }
const useMotion = () => useSyncExternalStore(subscribe, () => motion, () => motion)
/** Keys of open rows in display order, published by the list (falls back to the sections). */
let visibleOrder: string[] = []

export interface DedupedQueueGroup {
  primary: QueueItem
  items: QueueItem[]
  count: number
  routePattern: string | null
}

/**
 * Deduplicate pending approval cards by `(origin, method, normalizedRoutePattern)` so repeated
 * queued requests for the exact same route collapse into one row with a `×N` badge.
 */
export function dedupePendingQueueItems(items: readonly QueueItem[]): DedupedQueueGroup[] {
  const groups: DedupedQueueGroup[] = []
  const byRouteKey = new Map<string, DedupedQueueGroup>()
  for (const item of items) {
    if (item.kind !== 'approval') {
      groups.push({ primary: item, items: [item], count: 1, routePattern: null })
      continue
    }
    const routeKey = approvalRouteDedupeKey(item.ap)
    const existing = byRouteKey.get(routeKey)
    if (existing) {
      existing.items.push(item)
      existing.count = existing.items.length
    } else {
      const group: DedupedQueueGroup = {
        primary: item,
        items: [item],
        count: 1,
        routePattern: normalizeClientApprovalPath(item.ap.pathAndQuery),
      }
      byRouteKey.set(routeKey, group)
      groups.push(group)
    }
  }
  return groups
}

const normOrg = (o: string) => o.trim().toLowerCase().replace(/\/+$/, '')

/**
 * Compute IDs of OTHER currently pending approvals that will ALSO be resolved by executing
 * `scope` on `ap` (used for both blast-radius preview counts and optimistic queue updates).
 */
export function matchingPendingApprovalIds(
  ap: Pick<Approval, 'id' | 'origin' | 'method' | 'pathAndQuery' | 'riskLevel'>,
  activePending: readonly Pick<Approval, 'id' | 'origin' | 'method' | 'pathAndQuery' | 'riskLevel'>[],
  scope: ApprovalScope,
): string[] {
  if (scope === 'once') return []
  const orig = normOrg(ap.origin)
  const meth = ap.method.trim().toUpperCase()
  const key = scope === 'route' ? approvalRouteDedupeKey(ap) : ''
  const pref = scope === 'prefix' ? eligibleApprovalPrefixPattern(ap) : null
  const base = pref ? pref.slice(0, -3) : ''
  if (scope === 'prefix' && !pref) return []
  if (scope === 'host_nondestructive' && !isHostNonDestructiveEligibleCard(ap)) return []
  return activePending.filter(o => {
    if (o.id === ap.id) return false
    if (scope === 'route') return approvalRouteDedupeKey(o) === key
    if (normOrg(o.origin) !== orig) return false
    if (scope === 'host_nondestructive') return isHostNonDestructiveEligibleCard(o)
    if (o.riskLevel === 'high' || o.method.trim().toUpperCase() !== meth) return false
    const n = normalizeClientApprovalPath(o.pathAndQuery)
    return Boolean(n) && !n.includes('%2a') && (n === base || n.startsWith(`${base}/`))
  }).map(o => o.id)
}

export function formatApprovalBlastRadius(opts: {
  ap: Pick<Approval, 'origin' | 'method' | 'pathAndQuery' | 'personaHandle'>
  scope: ApprovalScope
  routePattern: string
  prefixPattern: string | null
  extraResolvedCount: number
  serverPreview?: ApprovalBlastRadiusPreview | null
}): string {
  const m = opts.ap.method.trim().toUpperCase()
  const total = opts.serverPreview ? Math.max(1, opts.serverPreview.pendingApprovalCount) : opts.extraResolvedCount + 1
  const extra = total - 1
  if (opts.scope === 'once') return `Approve once: ${m} ${opts.routePattern} · single request only (no lease)`
  const tail = extra > 0 ? `also resolves ${plural(total, 'pending card')}` : null
  if (opts.scope === 'route') return `Approve route: ${m} ${opts.routePattern} · ${tail ?? 'reuses lease on this route'}`
  if (opts.scope === 'prefix') return `Approve prefix: ${m} ${opts.prefixPattern || opts.routePattern} · ${tail ?? 'future non-high-risk probes under prefix'}`
  return [`Approve host: POST/PUT/PATCH on ${host(opts.ap.origin)} (no DELETE or high-risk)`, tail].filter(Boolean).join(' · ')
}

function openKeys(q: DecisionsApi) {
  const dedupedDecide = dedupePendingQueueItems(q.sections.decide).map(g => g.primary.key)
  return [...dedupedDecide, ...q.sections.review.map(i => i.key), ...q.sections.follow.map(i => i.key)]
}

/** Real command for a decision. */
function commandFor(
  it: QueueItem,
  act: DecisionAct,
  model: RunModel,
  scope?: ApprovalScope,
  crossPersona?: boolean,
): Command | undefined {
  if (it.kind === 'approval' && (act === 'approve' || act === 'deny')) {
    const resolvedScope = act === 'approve' ? (scope ?? defaultPrimaryApprovalScope(it.ap)) : scope
    const base = approvalCommand(it.ap.id, act, resolvedScope)
    if (act === 'approve' && crossPersona && resolvedScope && resolvedScope !== 'once' && base.action === 'decide_approval') {
      return { ...base, crossPersona: true }
    }
    return base
  }
  if (it.kind === 'follow' && act === 'queue' && followIsLive(model)) {
    const x = it.cov
    const asset = model.run.candidates.find(c => c.origin === x.origin && model.run.approved.includes(c.id))
    return {
      action: 'inject_hint',
      hint: `Follow up on ${host(x.origin)} · ${prettyCat(x.category)}: ${x.summary}`.slice(0, 2000),
      ...(asset ? { targetAssetId: asset.id } : {}),
    }
  }
  return undefined
}
/** Follow-ups can only be scheduled while the run can still plan. */
export const followIsLive = (m: RunModel) => m.run.phase !== 'complete' && !['complete', 'stopped', 'failed'].includes(m.run.status)

function decisionMessage(it: QueueItem, act: DecisionAct, scope?: ApprovalScope, extraCount = 0): string {
  if (it.kind !== 'approval') return ACTIONS[act].label
  const h = host(it.ap.origin)
  const target = `${it.ap.method} ${h}${it.ap.pathAndQuery}`
  const extra = extraCount > 0 ? ` (+${extraCount} pending)` : ''
  if (act === 'deny') return `Denied ${target}${extra}`
  const s = scope ?? defaultPrimaryApprovalScope(it.ap)
  if (s === 'once') return `Approved once: ${target}`
  if (s === 'prefix') return `Approved prefix ${it.ap.method} ${h}${eligibleApprovalPrefixPattern(it.ap) ?? it.ap.pathAndQuery}${extra}`
  if (s === 'host_nondestructive') return `Approved host (non-destructive) on ${h}${extra}`
  return `Approved route: ${target}${extra}`
}

interface ActDeps { q: DecisionsApi; nav: NavApi; model: RunModel }

/** decide → advance immediately. Returns false when the action does not apply. */
function runDecision(
  deps: ActDeps,
  key: string,
  act: DecisionAct,
  opts: { scope?: ApprovalScope; alsoKeys?: readonly string[]; crossPersona?: boolean } = {},
) {
  const { q, nav, model } = deps
  const it = model.queueItem.get(key)
  if (!it) return false
  if (it.kind === 'consent') { nav.setView('overview'); return true }
  if (!q.canAct(key, act)) return false
  const resolvedScope: ApprovalScope | undefined = it.kind === 'approval'
    ? (act === 'approve' ? (opts.scope ?? defaultPrimaryApprovalScope(it.ap)) : opts.scope)
    : undefined
  const command = commandFor(it, act, model, resolvedScope, opts.crossPersona)
  if (!command) return false

  let alsoKeys: string[] = [...(opts.alsoKeys ?? [])]
  if (it.kind === 'approval' && resolvedScope && alsoKeys.length === 0) {
    const pendingPool = opts.crossPersona
      ? q.activePendingApprovals
      : q.activePendingApprovals.filter(other => (other.personaHandle?.trim() || null) === (it.ap.personaHandle?.trim() || null))
    alsoKeys = matchingPendingApprovalIds(it.ap, pendingPool, resolvedScope).map(id => 'ap:' + id)
  }
  const affectedSet = new Set([key, ...alsoKeys])
  const order = visibleOrder.length ? visibleOrder : openKeys(q)
  const idx = order.indexOf(key)
  const open = new Set(openKeys(q).filter(k => !affectedSet.has(k)))
  const nextKey = order.slice(idx + 1).find(k => open.has(k)) ?? order.slice(0, Math.max(0, idx)).reverse().find(k => open.has(k)) ?? null
  q.decide(key, act, {
    command,
    message: decisionMessage(it, act, resolvedScope, alsoKeys.length),
    alsoKeys,
  })
  setMotion({ key: null, act: null, phase: 'idle' })
  if (nav.view === 'queue' && nav.sel?.kind === 'queue' && affectedSet.has(nav.sel.id)) {
    if (nextKey) nav.select({ kind: 'queue', id: nextKey }, { anim: 'left' })
    else nav.close()
  }
  return true
}

function useDecide() {
  const q = useDecisions()
  const nav = useNav()
  const model = useRunModel()
  const deps = useRef<ActDeps>({ q, nav, model })
  deps.current = { q, nav, model }
  return (key: string, act: DecisionAct, opts?: { scope?: ApprovalScope; alsoKeys?: readonly string[]; crossPersona?: boolean }) =>
    runDecision(deps.current, key, act, opts)
}

/** Ask the coordinator about an item: chat in the pane with a context chip ("Back to item"). */
function useAsk() {
  const nav = useNav()
  const model = useRunModel()
  return (key: string) => {
    const it = model.queueItem.get(key)
    if (!it) return
    nav.openChat({ label: it.title, sel: { kind: 'queue', id: key } })
  }
}

/** Keyboard: A / D on the selected item, C to ask about it. */
function useQueueKeys(priority: number) {
  const nav = useNav()
  const model = useRunModel()
  const q = useDecisions()
  const decide = useDecide()
  const ask = useAsk()
  const cur = () => (nav.sel?.kind === 'queue' ? nav.sel.id : null)
  const letter = (l: string) => () => {
    const key = cur()
    if (!key || nav.chat) return false
    const it = model.queueItem.get(key)
    const a = actionsFor(it).find(x => x[2] === l)
    if (!a) return false
    if (it?.kind === 'approval' && a[0] === 'deny') {
      const siblingIds = matchingPendingApprovalIds(it.ap, q.activePendingApprovals, 'route')
      return decide(key, 'deny', siblingIds.length > 0 ? { scope: 'route' } : undefined) ? undefined : false
    }
    return decide(key, a[0]) ? undefined : false
  }
  useShortcuts([
    { key: 'a', run: letter('a') },
    { key: 'd', run: letter('d') },
    { key: 'c', run: () => { const key = cur(); if (!key || nav.chat) return false; ask(key) } },
  ], { priority })
}

// ---------------------------------------------------------------- list

const VISIBLE_QSEC = QSEC.filter(([k]) => k !== 'review')

const EMPTY: Record<QueueSection, string> = {
  decide: 'Nothing is waiting on you.',
  review: 'Findings are reviewed in the Findings view.',
  follow: 'No coverage flagged for follow-up.',
  done: 'Nothing here yet.',
}

function useEnterFlash(ref: React.RefObject<HTMLDivElement | null>, entering: boolean) {
  useLayoutEffect(() => {
    const el = ref.current
    const dur = T(420)
    if (!el || !entering || !dur || typeof el.animate !== 'function') return
    const anim = el.animate(
      [
        { opacity: 0, backgroundColor: 'var(--accent-soft)' },
        { opacity: 1, backgroundColor: 'var(--accent-soft)', offset: 0.4 },
        { backgroundColor: 'transparent' },
      ],
      { duration: dur, easing: EASE_CSS },
    )
    return () => anim.cancel()
  }, [ref, entering])
}

export function QueueView() {
  const { pending, now } = useRun()
  const model = useRunModel()
  const q = useDecisions()
  const nav = useNav()
  const m = useMotion()
  const decide = useDecide()
  const ask = useAsk()
  const [collapsed, setCollapsed] = useViewState<Partial<Record<QueueSection, boolean>>>('queue.collapsed', {})
  const listRef = useRef<HTMLDivElement>(null)

  const isCol = (k: QueueSection) => collapsed[k] ?? k === 'done'
  const dedupedDecide = useMemo(() => dedupePendingQueueItems(q.sections.decide), [q.sections.decide])
  const flat = useMemo(() => VISIBLE_QSEC.flatMap(([k]) => {
    if (isCol(k)) return []
    if (k === 'decide') return dedupedDecide.map(g => g.primary.key)
    return q.sections[k].map(i => i.key)
  }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [q.sections, dedupedDecide, collapsed])
  visibleOrder = flat
  const selKey = nav.sel?.kind === 'queue' ? nav.sel.id : null

  // Land on the first open item; drop selections that no longer exist.
  useEffect(() => {
    if (nav.chat) return
    if (selKey && model.queueItem.has(selKey)) return
    if (nav.sel && nav.sel.kind !== 'queue') return
    const first = openKeys(q)[0]
    if (first) nav.select({ kind: 'queue', id: first })
    else if (selKey) nav.close()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selKey, model])

  useListNav({ ids: flat, kind: 'queue', anim: 'left' })
  useQueueKeys(10)
  usePaletteCommands([
    ...VISIBLE_QSEC.map(([k, l]) => ({
      id: 'q.toggle.' + k, section: 'Actions', label: (isCol(k) ? 'Expand' : 'Collapse') + ' the ' + l + ' section', icon: 'queue' as IconName,
      run: () => setCollapsed(c => ({ ...c, [k]: !isCol(k) })),
    })),
  ])

  // Keep the current row in view (j/k, advance).
  useEffect(() => {
    if (!selKey) return
    const el = listRef.current?.querySelector<HTMLElement>(`[data-id="${CSS.escape(selKey)}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [selKey])

  const activePendingApprovals = q.activePendingApprovals
  const initial = q.initialCount
  const handled = q.handledCount
  const pct = initial ? Math.min(1, handled / initial) : 0
  const hero = <div className="flex flex-none items-center gap-3 border-b border-line px-[18px] py-3 text-[12.5px] tabular-nums text-fg-muted">
    <span className="min-w-0 truncate">
      <b className="font-medium text-fg"><AnimatedNumber id="q.open" value={q.openCount} /> open</b>
      <span className="text-fg-subtle"> · {handled} decided by you this session</span>
    </span>
    <span className="flex h-1 w-24 flex-none gap-0.5 max-[1320px]:hidden" title={`${handled} of ${initial} handled`}>
      {Array.from({ length: 12 }, (_, i) => (
        <i key={i} className={cn('flex-1 rounded-[2px] transition-colors duration-[var(--d3)]', i < Math.ceil(pct * 12) ? 'bg-fg-subtle' : 'bg-line-2')} />
      ))}
    </span>
    <span className="min-w-2 flex-1" />
    <span className="inline-flex flex-none items-center gap-1.5 whitespace-nowrap text-[11.5px] text-fg-subtle [&_.kbd]:ml-1.5">
      <Kbd>A</Kbd>approve<Kbd>D</Kbd>deny
    </span>
  </div>
  if (!initial && !q.sections.done.length) {
    return <>{hero}<EmptyState icon="queue" title="Queue is empty">State-change approvals and flagged coverage follow-ups collect here as the run progresses.</EmptyState></>
  }
  return <>
    {hero}
    <div className={RW.list} ref={listRef} tabIndex={-1}>
      {VISIBLE_QSEC.map(([k, label, sub]) => {
        const items = q.sections[k]
        const col = isCol(k)
        return <div key={k} data-sec={k}>
          <div
            className={RW.ghead}
            role="button"
            tabIndex={0}
            aria-expanded={!col}
            onClick={() => setCollapsed(c => ({ ...c, [k]: !col }))}
            onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setCollapsed(c => ({ ...c, [k]: !col })) } }}
          >
            <Icon name="chev" className={cn('text-fg-subtle transition-transform duration-[var(--d2)] ease-kovo', col && '-rotate-90')} />
            <span>{label}</span>
            <span className="font-normal tabular-nums text-fg-subtle"><AnimatedNumber id={'q.sec.' + k} value={items.length} /></span>
            <span className="text-[12px] font-normal text-fg-subtle">{sub}</span>
            {k === 'decide' && activePendingApprovals.length > 0 && (
              <button
                type="button"
                className={cn(runBtn({ size: 'sm' }), 'ml-auto')}
                disabled={pending > 0 || q.approvingAll}
                data-testid="queue-approve-all"
                onClick={e => {
                  e.stopPropagation()
                  void q.approveAllPending({ action: 'approve_all_pending' })
                }}
              >
                <Icon name="check" />{q.approvingAll ? 'Approving…' : `Approve all pending (${activePendingApprovals.length})`}
              </button>
            )}
          </div>
          {!col && (!items.length
            ? <div className="border-b border-line pb-3.5 pl-11 pr-[18px] pt-3 text-[12px] text-fg-subtle">{EMPTY[k]}</div>
            : k === 'done' ? <DoneRows items={items} selKey={selKey} now={now} />
              : k === 'decide' ? dedupedDecide.map(group => {
                  const it = group.primary
                  const cur = group.items.some(g => g.key === selKey)
                  return <QRow key={it.key} it={it} sec={k} cur={cur} count={group.count} motion={m} now={now}
                    onSelect={() => nav.select({ kind: 'queue', id: it.key })}
                    onAct={act => {
                      if (it.kind === 'approval' && act === 'deny' && group.count > 1) {
                        decide(it.key, 'deny', { scope: 'route', alsoKeys: group.items.slice(1).map(g => g.key) })
                      } else {
                        decide(it.key, act)
                      }
                    }}
                    onAsk={() => ask(it.key)} />
                })
                : items.map(it => <QRow key={it.key} it={it} sec={k} cur={it.key === selKey} count={1} motion={m} now={now}
                  onSelect={() => nav.select({ kind: 'queue', id: it.key })} onAct={act => decide(it.key, act)} onAsk={() => ask(it.key)} />))}
        </div>
      })}
    </div>
  </>
}

function QTitle({ it, done }: { it: QueueItem; done?: boolean }) {
  if (it.kind === 'approval') {
    const a = it.ap
    return <span className={cn('min-w-0 flex-initial truncate font-mono text-[12px]', done ? 'text-fg-muted' : 'text-fg')}>
      <span className={cn('mr-1.5 font-semibold', done ? 'text-fg-subtle' : 'text-warn')}>{a.method}</span>
      {host(a.origin)}
      <span className="text-fg-subtle">{a.pathAndQuery}</span>
    </span>
  }
  return <span className={cn('min-w-0 flex-initial truncate', done ? 'text-fg-muted' : 'text-fg')}>{it.title}</span>
}

function QMeta({ it, model, now }: { it: QueueItem; model: RunModel; now: number }): ReactNode[] {
  if (it.kind === 'approval') {
    const expired = isApprovalExpired(it.ap, now)
    return ['Approval request', expired ? <span key="exp" className="font-medium text-warn">Expired</span> : it.ap.status === 'pending' ? 'Expires ' + fmtTime(it.ap.expiresAt) : cap(it.ap.status)]
  }
  if (it.kind === 'consent') return [plural(model.detail.project.seeds.length, 'seed host'), capabilityTierMeta[model.run.capabilityTier].short, fmtUsd(model.run.budgetUsd)]
  if (it.kind === 'follow') return [<span key="h" className="font-mono text-[11.5px]">{host(it.cov.origin)}</span>, prettyCat(it.cov.category)]
  return [
    it.bundle ? <Tag key="o" className="h-[18px] text-[11px] tabular-nums">{it.origins.length} origins</Tag> : <span key="h" className="font-mono text-[11.5px]">{host(it.origins[0])}</span>,
    it.finding.findingKind === 'multi_step_chain' ? 'Chain' : 'Baseline',
    <VState key="v" status={it.status} />,
  ]
}

const ROW_CLS = 'h-10 cursor-pointer [contain-intrinsic-size:auto_40px]'
const META_CLS = 'flex flex-none items-center gap-2 whitespace-nowrap text-[12px] text-fg-subtle'

function QRow({ it, sec, cur, count = 1, motion: m, now, onSelect, onAct, onAsk }: {
  it: QueueItem
  sec: QueueSection
  cur: boolean
  count?: number
  motion: Motion
  now: number
  onSelect: () => void
  onAct: (act: DecisionAct) => void
  onAsk: () => void
}) {
  const model = useRunModel()
  const ref = useRef<HTMLDivElement>(null)
  const stamping = m.key === it.key && m.phase !== 'idle'
  const leaving = stamping && m.phase === 'leave'
  const A = stamping && m.act ? ACTIONS[m.act] : null
  useEnterFlash(ref, m.enter === it.key)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el || !leaving) return
    el.style.height = el.offsetHeight + 'px'
    void el.offsetHeight
    el.setAttribute('data-leaving', '')
    el.style.height = '0px'
    return () => { el.removeAttribute('data-leaving'); el.style.height = '' }
  }, [leaving])
  const meta = QMeta({ it, model, now })
  const acts = it.kind === 'consent' ? [['scope', 'Review scope', 'a', true] as const] : actionsFor(it, now)
  return <div
    ref={ref}
    className={cn(
      RW.row,
      'group/row',
      ROW_CLS,
      'data-[leaving]:overflow-hidden data-[leaving]:border-b-transparent data-[leaving]:opacity-0 data-[leaving]:[transition:height_var(--d3)_var(--ease),opacity_var(--d2)_var(--ease),border-color_var(--d2)]',
      cur && RW.rowCur,
    )}
    data-id={it.key}
    onClick={onSelect}
    aria-selected={cur}
  >
    <QGlyph it={it} />
    <span className={cn('flex min-w-0 flex-1 items-center gap-2', cur && sec !== 'done' && 'pr-[196px]')}>
      <QTitle it={it} />
      {count > 1 && (
        <span
          className="inline-flex h-[18px] flex-none items-center rounded-[10px] bg-warn-soft px-1.5 text-[11px] font-semibold leading-none tabular-nums text-warn shadow-[inset_0_0_0_1px_var(--warn-line)]"
          title={`${count} pending approval cards for this route`}
          data-testid="queue-dedupe-badge"
        >
          ×{count}
        </span>
      )}
    </span>
    <span className={cn(META_CLS, 'transition-opacity duration-[var(--d1)] group-hover/row:opacity-0', (cur || stamping) && 'opacity-0')}>
      {meta.map((x, i) => <span key={i} className="inline-flex items-center gap-2">{i > 0 && <span className="text-fg-faint">·</span>}{x}</span>)}
    </span>
    {sec !== 'done' && <span className={cn(
      'pointer-events-none absolute right-3 top-1/2 flex -translate-y-1/2 translate-x-1 gap-1 bg-gradient-to-r from-transparent pl-6 opacity-0 transition-[opacity,transform] duration-[var(--d1)] ease-kovo',
      cur ? 'via-[var(--row-s)] to-[var(--row-s)]' : 'via-[var(--row-h)] to-[var(--row-h)]',
      stamping
        ? 'opacity-0!'
        : cur
          ? 'pointer-events-auto translate-x-0 opacity-100'
          : 'group-hover/row:pointer-events-auto group-hover/row:translate-x-0 group-hover/row:opacity-100',
    )}>
      {acts.map(([a, l, k, p]) => <button
        key={a}
        type="button"
        className={cn(runBtn({ variant: p ? 'ink' : 'default', size: 'sm' }), !p && 'text-fg-muted hover:text-fg')}
        title={`${l} (${k.toUpperCase()})`}
        onClick={e => { e.stopPropagation(); onAct(a) }}
      >
        {l}<Kbd inverted={p} className="pointer-events-none h-[15px] min-w-[15px] text-[10px]">{k.toUpperCase()}</Kbd>
      </button>)}
      <button
        type="button"
        className={cn(runBtn({ variant: 'default', size: 'iconSm' }), 'text-fg-muted hover:text-fg')}
        title="Ask coordinator (C)"
        aria-label="Ask coordinator"
        onClick={e => { e.stopPropagation(); onAsk() }}
      >
        <Icon name="chat" />
      </button>
    </span>}
    {A && <span className={cn(runStamp({ tone: A.tone }), 'absolute right-4 top-1/2 z-[2] h-6 -translate-y-1/2 transition-[opacity,transform] duration-[var(--d2)] ease-spring')}>
      <Icon name={A.icon} />{A.label}
    </span>}
  </div>
}

function DoneRow({ it, cur, entering, now, onSelect }: { it: QueueItem; cur: boolean; entering: boolean; now: number; onSelect: () => void }) {
  const q = useDecisions()
  const ref = useRef<HTMLDivElement>(null)
  useEnterFlash(ref, entering)
  const dec = q.get(it.key)
  let right: ReactNode = null
  if (dec) {
    const A = ACTIONS[dec.act]
    right = <span className={cn(runDec({ tone: A.tone === 'no' ? 'default' : A.tone }), '[&_svg]:size-[13px]')}><Icon name={A.icon} />{A.label}</span>
  } else if (it.kind === 'finding') right = <VState status={it.status} />
  else if (it.kind === 'approval') {
    const expired = isApprovalExpired(it.ap, now)
    const status = expired ? 'expired' : it.ap.status
    right = <span className={cn(runDec(), '[&_svg]:size-[13px]')}><StatusGlyph status={status} />{cap(status)}{!expired && it.ap.decidedBy ? ' · ' + it.ap.decidedBy : ''}</span>
  }
  return <div ref={ref} className={cn(RW.row, ROW_CLS, cur && RW.rowCur)} data-id={it.key} onClick={onSelect} aria-selected={cur}>
    <QGlyph it={it} />
    <span className="flex min-w-0 flex-1 items-center gap-2"><QTitle it={it} done /></span>
    <span className={META_CLS}>{right}</span>
  </div>
}

function DoneRows({ items, selKey, now }: { items: QueueItem[]; selKey: string | null; now: number }) {
  const q = useDecisions()
  const nav = useNav()
  const m = useMotion()
  const auto = (it: QueueItem) => it.kind === 'approval' && !q.get(it.key) && (it.ap.decidedBy ?? '').startsWith('auto')
  const main = items.filter(it => !auto(it))
  const log = items.filter(auto)
  const render = (it: QueueItem) => <DoneRow key={it.key} it={it} cur={it.key === selKey} entering={m.enter === it.key} now={now} onSelect={() => nav.select({ kind: 'queue', id: it.key })} />
  return <>
    {main.map(render)}
    {log.length > 0 && <>
      <div className="flex h-[30px] items-center gap-2 border-b border-line bg-[color-mix(in_srgb,var(--sunk)_55%,transparent)] pl-11 pr-[18px] text-[12px] font-medium text-fg-muted">
        <Icon name="shield" className="text-fg-subtle" />
        <span>Auto-approved by policy</span>
        <span className="font-normal tabular-nums text-fg-subtle">{log.length}</span>
        <span className="truncate font-normal text-fg-subtle">Audit log of active test requests the policy approved automatically</span>
      </div>
      {log.map(render)}
    </>}
  </>
}

// ---------------------------------------------------------------- inspector

function QueueInspector({ sel }: InspectorProps) {
  const { now } = useRun()
  const model = useRunModel()
  const q = useDecisions()
  const nav = useNav()
  const m = useMotion()
  const decide = useDecide()
  const ask = useAsk()
  const [previewScope, setPreviewScope] = useState<ApprovalScope | null>(null)
  const [crossPersona, setCrossPersona] = useState(false)
  const [serverPreviews, setServerPreviews] = useState<Record<ApprovalScope, ApprovalBlastRadiusPreview> | null>(null)
  const it = model.queueItem.get(sel.id)
  const pendingApprovalId = it?.kind === 'approval' && it.ap.status === 'pending' ? it.ap.id : null
  useEffect(() => {
    setPreviewScope(null)
    setCrossPersona(false)
    setServerPreviews(null)
  }, [sel.id])
  useEffect(() => {
    if (!pendingApprovalId) return
    let active = true
    void previewApprovalBlastRadiusAction({
      data: { runId: model.run.id, approvalId: pendingApprovalId, crossPersona },
    }).then(
      res => { if (active) setServerPreviews(res) },
      () => { if (active) setServerPreviews(null) },
    )
    return () => { active = false }
  }, [model.run.id, pendingApprovalId, crossPersona, q.activePendingApprovals.length])
  if (!it) {
    return <>
      <PaneHeader title="Queue" />
      <PaneBody><EmptyState icon="queue" title="Item not found">It may have been decided or superseded since the run refreshed.</EmptyState></PaneBody>
    </>
  }
  const sec = q.sectionOf(it.key) ?? 'done'
  const inSec = q.sections[sec]
  const pos = inSec.findIndex(i => i.key === it.key)
  const secName = QSEC.find(s => s[0] === sec)?.[1] ?? ''
  const dec = q.get(it.key)
  const expiredApproval = it.kind === 'approval' && isApprovalExpired(it.ap, now)
  const order = visibleOrder.length ? visibleOrder : openKeys(q)
  const step = (d: number) => {
    const i = order.indexOf(it.key)
    const k = order[i < 0 ? 0 : Math.max(0, Math.min(order.length - 1, i + d))]
    if (k && k !== it.key) nav.select({ kind: 'queue', id: k }, { anim: d > 0 ? 'left' : 'up' })
  }
  const stamped = m.key === it.key && m.phase !== 'idle' && m.act ? ACTIONS[m.act] : null
  const acts = sec !== 'done' ? (it.kind === 'consent' ? [['scope', 'Review scope', 'a', true] as const] : actionsFor(it, now)) : []
  const icon = (a: DecisionAct): IconName => a === 'deny' ? 'x' : a === 'queue' ? 'follow' : 'check'
  const bannerBody: ReactNode = dec
    ? <><Icon name={ACTIONS[dec.act].icon} /><span>{ACTIONS[dec.act].label} by you · {fmtTimeS(dec.at)}{dec.state === 'sent' ? ' · sent to Kovo Hunter' : ''}</span></>
    : expiredApproval
      ? <><StatusGlyph status="expired" /><span>Expired · this approval window closed at {fmtTimeS(it.ap.expiresAt)}.</span></>
      : sec === 'done' && it.kind === 'approval'
        ? <><StatusGlyph status={it.ap.status} /><span>{cap(it.ap.status)}{it.ap.decidedBy ? ' by ' + it.ap.decidedBy : ''}{it.ap.decidedAt ? ' · ' + fmtTimeS(it.ap.decidedAt) : ''}.</span></>
        : null
  const banner = bannerBody && <div className="mb-3 flex items-center gap-2 rounded-[7px] bg-sunk px-2.5 py-2 text-[12px] text-fg-muted shadow-[inset_0_0_0_1px_var(--line)]">{bannerBody}</div>

  const activeApproval = it.kind === 'approval' && sec !== 'done' && !expiredApproval ? it.ap : null
  const primaryScope = activeApproval ? defaultPrimaryApprovalScope(activeApproval) : 'route'
  const routePattern = activeApproval ? normalizeClientApprovalPath(activeApproval.pathAndQuery) : ''
  const prefixPattern = activeApproval ? eligibleApprovalPrefixPattern(activeApproval) : null
  const hostEligible = activeApproval ? isHostNonDestructiveEligibleCard(activeApproval) : false
  const routeSiblings = activeApproval ? matchingPendingApprovalIds(activeApproval, q.activePendingApprovals, 'route') : []
  const effectivePreviewScope: ApprovalScope = previewScope ?? primaryScope
  const pendingPool = activeApproval
    ? (crossPersona ? q.activePendingApprovals : q.activePendingApprovals.filter(o => (o.personaHandle?.trim() || null) === (activeApproval.personaHandle?.trim() || null)))
    : []
  const activeServerPreview = serverPreviews?.[effectivePreviewScope] ?? null
  const blastRadiusText = activeApproval
    ? formatApprovalBlastRadius({
        ap: activeApproval,
        scope: effectivePreviewScope,
        routePattern,
        prefixPattern,
        extraResolvedCount: matchingPendingApprovalIds(activeApproval, pendingPool, effectivePreviewScope).length,
        serverPreview: activeServerPreview,
      })
    : null
  const leaseBoundsText = activeApproval && effectivePreviewScope !== 'once'
    ? [
        `${Math.max(1, Math.round((activeServerPreview?.defaultTtlMs ?? DEFAULT_APPROVAL_LEASE_TTL_MS) / 60_000))}m`,
        `max ${activeServerPreview?.defaultMaxUses ?? defaultMaxUsesForLeaseScope(effectivePreviewScope)} uses`,
        activeApproval.personaHandle ? (crossPersona ? 'all personas' : `@${activeApproval.personaHandle}`) : null,
        activeServerPreview?.matchingRouteCount ? `${plural(activeServerPreview.matchingRouteCount, 'route')} in inventory` : null,
      ].filter(Boolean).join(' · ')
    : null
  const blastRadiusTitle = activeServerPreview?.sampleRoutes.length && effectivePreviewScope !== 'once'
    ? `${blastRadiusText ?? ''}\nInventory: ${activeServerPreview.sampleRoutes.join(', ')}`
    : blastRadiusText ?? undefined

  const scopeBtn = (s: ApprovalScope, label: ReactNode, opts: { primary?: boolean; testId: string; title?: string; cls?: string }) => (
    <button
      key={s}
      type="button"
      className={cn(runBtn(opts.primary ? { variant: 'ink' } : { variant: 'default', size: 'sm' }), opts.cls)}
      data-testid={opts.testId}
      title={opts.title}
      onMouseEnter={() => setPreviewScope(s)}
      onMouseLeave={() => setPreviewScope(null)}
      onFocus={() => setPreviewScope(s)}
      onBlur={() => setPreviewScope(null)}
      onClick={() => decide(it.key, 'approve', { scope: s, ...(s !== 'once' && crossPersona ? { crossPersona: true } : {}) })}
    >
      {opts.primary && <Icon name="check" />}{label}{opts.primary && <Kbd inverted className="ml-0.5">A</Kbd>}
    </button>
  )

  const stampOverlay = stamped && (
    <span className={cn(runStamp({ tone: stamped.tone }), 'pointer-events-none absolute inset-x-3 inset-y-2.5 flex items-center gap-2 rounded-control px-3 text-[12.5px] font-semibold')}>
      <Icon name={stamped.icon} />{stamped.label} <span className="font-normal opacity-70">· next item</span>
    </span>
  )
  const askBtn = (opts: { compact?: boolean; label?: boolean }) => (
    <button
      type="button"
      className={cn(runBtn(opts.compact ? { variant: 'ghost', size: 'iconSm' } : { variant: 'ghost' }), opts.compact && 'ml-auto')}
      title="Ask the coordinator about this item (C)"
      aria-label="Ask the coordinator"
      onClick={() => ask(it.key)}
    >
      <Icon name="chat" />{opts.label && <>Ask<Kbd className="ml-0.5">C</Kbd></>}
    </button>
  )

  return <>
    <PaneHeader title={secName} sub={pos >= 0 ? <span className="tabular-nums">{pos + 1} of {inSec.length}</span> : undefined}
      extra={<>
        <button type="button" className={runIconBtn()} onClick={() => step(-1)} title="Previous (K)" aria-label="Previous item"><Icon name="chevU" /></button>
        <button type="button" className={runIconBtn()} onClick={() => step(1)} title="Next (J)" aria-label="Next item"><Icon name="chevD" /></button>
      </>} />
    <div className="flex min-h-0 flex-1 flex-col">
      <PaneBody><div className={cn(RW.detail, 'pb-6')}>
        {banner}
        {it.kind === 'finding' ? <ReadFinding it={it} />
          : it.kind === 'approval' ? <ReadApproval it={it} now={now} duplicateCount={routeSiblings.length + 1} />
            : it.kind === 'follow' ? <ReadFollow it={it} />
              : <ReadConsent />}
      </div></PaneBody>
      {activeApproval ? (
        <div className="relative flex flex-none flex-col gap-1.5 border-t border-line bg-panel px-3 py-2.5" data-testid="approval-action-bar">
          {blastRadiusText && (() => {
            const sep = blastRadiusText.lastIndexOf(' · ')
            const lead = sep >= 0 ? blastRadiusText.slice(0, sep) : blastRadiusText
            const tail = sep >= 0 ? blastRadiusText.slice(sep + 3) : ''
            return (
              <div className="flex flex-col gap-0.5">
                <div className="flex min-w-0 items-center gap-1.5 text-[11.5px] leading-[16px] text-fg-subtle" title={blastRadiusTitle} data-testid="approval-blast-radius">
                  <span className="min-w-0 truncate">{lead}</span>
                  {tail && <span className="flex-none whitespace-nowrap font-medium text-fg-muted">· {tail}</span>}
                </div>
                {leaseBoundsText && (
                  <div className="flex min-w-0 items-center justify-between gap-2 text-[11px] leading-[15px] text-fg-subtle" data-testid="approval-lease-bounds">
                    <span className="min-w-0 truncate" title={blastRadiusTitle}>{leaseBoundsText}</span>
                    {activeApproval.personaHandle && (
                      <label className="flex flex-none cursor-pointer items-center gap-1 whitespace-nowrap text-fg-muted" title="Opt in to cross-persona lease reuse (BOLA/IDOR)" data-testid="approval-cross-persona-toggle">
                        <input type="checkbox" className="h-3 w-3 accent-accent" checked={crossPersona} onChange={e => setCrossPersona(e.target.checked)} />
                        <span>All personas</span>
                      </label>
                    )}
                  </div>
                )}
              </div>
            )
          })()}
          <div className={cn('flex min-w-0 flex-wrap items-center gap-1.5 transition-opacity duration-[var(--d1)]', stamped && 'pointer-events-none opacity-0')}>
            {primaryScope === 'route' ? (
              <>
                {scopeBtn('route', 'Approve route', { primary: true, testId: 'approval-btn-route' })}
                {scopeBtn('once', 'Once', { testId: 'approval-btn-once', title: 'Single request only (no lease)' })}
              </>
            ) : (
              <>
                {scopeBtn('once', 'Approve once', { primary: true, testId: 'approval-btn-once' })}
                {scopeBtn('route', 'Route', { testId: 'approval-btn-route', title: `Exact route (${activeApproval.method} ${routePattern})` })}
              </>
            )}
            {prefixPattern && scopeBtn('prefix', <span className="truncate">Prefix ({prefixPattern})</span>, {
              testId: 'approval-btn-prefix',
              title: `Prefix ${activeApproval.method} ${prefixPattern}`,
              cls: 'max-w-[190px]',
            })}
            {hostEligible && scopeBtn('host_nondestructive', 'Host', {
              testId: 'approval-btn-host',
              title: `POST/PUT/PATCH on ${host(activeApproval.origin)} (no DELETE/high-risk)`,
            })}
            <button
              type="button"
              className={runBtn({ variant: 'default', size: 'sm' })}
              data-testid="approval-btn-deny"
              onClick={() => decide(it.key, 'deny', routeSiblings.length > 0 ? { scope: 'route' } : undefined)}
            >
              <Icon name="x" />Deny<Kbd className="ml-0.5">D</Kbd>
            </button>
            {askBtn({ compact: true })}
          </div>
          {stampOverlay}
        </div>
      ) : (
        <div className="relative flex min-h-12 flex-none items-center gap-1.5 border-t border-line bg-panel px-3 py-2.5">
          <div className={cn('flex min-w-0 flex-1 items-center gap-1.5 transition-opacity duration-[var(--d1)]', stamped && 'pointer-events-none opacity-0')}>
            {acts.map(([a, l, k, p]) => <button key={a} type="button" className={runBtn({ variant: p ? 'ink' : 'default' })} onClick={() => decide(it.key, a)}>
              <Icon name={icon(a)} />{l}<Kbd inverted={p} className="ml-0.5">{k.toUpperCase()}</Kbd>
            </button>)}
            {acts.length <= 2 && askBtn({ label: sec !== 'done' && it.kind !== 'approval' })}
            <span className="flex-1" />
          </div>
          {stampOverlay}
        </div>
      )}
    </div>
  </>
}

/** Inspectors this view owns, keyed by selection kind ('queue'). */
export const queueInspectors: InspectorMap = {
  queue: QueueInspector,
}
