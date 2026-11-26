// One decision store for the queue and the coordinator's pinned approvals
// (F: "Approvals in the coordinator card and in the queue share one decision store").
//
//   const q = useDecisions()
//   q.sections.decide / review / follow / done   // base queue minus decided items
//   q.decide('ap:<id>', 'approve', { command: approvalCommand(id, 'approve'), message: 'Approved POST …' })
//
// Every queue decision is a real server command: it stamps immediately and
// sends to the server right away. Local-only browser triage is intentionally
// absent so Queue never contradicts Report/SARIF/Overview.
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { useRun } from './data.tsx'
import type { Command } from './data.tsx'
import { plural } from './format.ts'
import type { IconName } from './icons.tsx'
import { isApprovalExpired } from './model.ts'
import type { Approval, QueueItem, QueueSection } from './model.ts'
import { useToast } from './toast.tsx'

export type DecisionAct = 'approve' | 'deny' | 'queue' | 'scope'
export const ACTIONS: Record<DecisionAct, { label: string; tone: 'ok' | 'no' | 'fp' | 'acc'; icon: IconName }> = {
  approve: { label: 'Approved', tone: 'ok', icon: 'check' },
  deny: { label: 'Denied', tone: 'no', icon: 'x' },
  queue: { label: 'Follow-up queued', tone: 'acc', icon: 'follow' },
  scope: { label: 'Scope approved', tone: 'ok', icon: 'check' },
}

/** Which real server actions an item offers: [act, button label, key, primary]. */
export function actionsFor(it: QueueItem | undefined | null, now = Date.now()): [DecisionAct, string, string, boolean][] {
  if (!it) return []
  if (it.kind === 'consent') return [['scope', 'Approve scope', 'a', true]]
  if (it.kind === 'approval') {
    if (isApprovalExpired(it.ap, now)) return []
    return [['approve', 'Approve', 'a', true], ['deny', 'Deny', 'd', false]]
  }
  if (it.kind === 'follow') return [['queue', 'Queue follow-up', 'a', true]]
  return []
}

/** The real command for an approval decision. */
export function approvalCommand(approvalId: string, act: 'approve' | 'deny'): Command {
  return { action: 'decide_approval', approvalId, decision: act === 'approve' ? 'approved' : 'denied' }
}

/** Queue progress summary ensuring `handledCount <= initialCount` and ratio stays within `[0, 1]`. */
export function computeQueueProgress(openCount: number, handledCount: number) {
  const safeOpen = Math.max(0, openCount)
  const safeHandled = Math.max(0, handledCount)
  const initialCount = safeOpen + safeHandled
  const ratio = initialCount > 0 ? Math.min(1, safeHandled / initialCount) : 0
  return { openCount: safeOpen, handledCount: safeHandled, initialCount, ratio }
}

export interface Decision {
  act: DecisionAct
  at: number
  /** sent = command delivered; failed = command rejected */
  state: 'sent' | 'failed'
}

/**
 * Derive active queue sections, blocking decision tally, and active pending approvals from the
 * run model and optimistic session decisions. Client-expired pending approvals move out of
 * `decide` into `done`, and `follow` items never inflate `activeDecideCount`.
 */
export function deriveQueueDecisions(
  base: Record<QueueSection, QueueItem[]>,
  queueItem: Map<string, QueueItem>,
  all: Record<string, Decision>,
  now = Date.now(),
) {
  const decide: QueueItem[] = []
  const expired: QueueItem[] = []
  for (const it of base.decide) {
    if (all[it.key]) continue
    if (it.kind === 'approval' && isApprovalExpired(it.ap, now)) {
      expired.push(it)
    } else {
      decide.push(it)
    }
  }
  const review = base.review.filter(it => !all[it.key])
  const follow = base.follow.filter(it => !all[it.key])
  const decided = Object.entries(all)
    .map(([k, d]) => ({ it: queueItem.get(k), d }))
    .filter(x => x.it)
    .sort((a, b) => b.d.at - a.d.at)
    .map(x => x.it!)
  const doneRest = expired.concat(base.done.filter(it => !all[it.key])).sort((a, b) => b.t - a.t)
  const sections: Record<QueueSection, QueueItem[]> = {
    decide,
    review,
    follow,
    done: decided.concat(doneRest),
  }
  const activePendingApprovals: Approval[] = []
  for (const it of decide) {
    if (it.kind === 'approval') activePendingApprovals.push(it.ap)
  }
  const activeDecideCount = decide.length
  const openCount = decide.length + review.length + follow.length
  const handledCount = Object.keys(all).filter(k => queueItem.has(k)).length
  const progress = computeQueueProgress(openCount, handledCount)
  return {
    sections,
    activePendingApprovals,
    activeDecideCount,
    openCount: progress.openCount,
    initialCount: progress.initialCount,
    handledCount: progress.handledCount,
    ratio: progress.ratio,
  }
}

export interface DecisionsApi {
  all: Record<string, Decision>
  get: (key: string) => Decision | undefined
  sections: Record<QueueSection, QueueItem[]>
  /** Open items (decide + review + follow) and items needing a decision. */
  openCount: number
  decideCount: number
  /** Active blocking decisions (waiting consent + non-expired pending approvals not yet decided). */
  activeDecideCount: number
  /** Non-expired pending approvals not yet optimistically decided. */
  activePendingApprovals: Approval[]
  /** Total actionable items (open + handled this session), always >= handledCount. */
  initialCount: number
  handledCount: number
  sectionOf: (key: string) => QueueSection | null
  canAct: (key: string, act: DecisionAct) => boolean
  decide: (key: string, act: DecisionAct, opts?: { command?: Command; message?: ReactNode; sub?: string; silent?: boolean }) => boolean
  approvingAll: boolean
  approveAllPending: (command?: Command) => Promise<boolean>
}

const DecisionsContext = createContext<DecisionsApi | null>(null)
export function useDecisions(): DecisionsApi {
  const v = useContext(DecisionsContext)
  if (!v) throw new Error('useDecisions() must be used inside <DecisionsProvider>')
  return v
}

export function DecisionsProvider({ children }: { children: ReactNode }) {
  const { model, send, pending } = useRun()
  const toast = useToast()
  const [all, setAll] = useState<Record<string, Decision>>({})
  const [approvingAll, setApprovingAll] = useState(false)
  const [now, setNow] = useState(() => Date.now())
  const hasQueuedApprovals = model.queue.decide.some(it => it.kind === 'approval')

  useEffect(() => {
    if (!hasQueuedApprovals) return
    setNow(Date.now())
    const id = window.setInterval(() => setNow(Date.now()), 15_000)
    return () => window.clearInterval(id)
  }, [hasQueuedApprovals])

  const derived = useMemo(
    () => deriveQueueDecisions(model.queue, model.queueItem, all, now),
    [model, all, now],
  )
  const { sections, activePendingApprovals, activeDecideCount, openCount, initialCount, handledCount } = derived

  const sectionOf = useCallback((key: string): QueueSection | null => {
    for (const k of ['decide', 'review', 'follow', 'done'] as const) if (sections[k].some(i => i.key === key)) return k
    return null
  }, [sections])

  const canAct = useCallback((key: string, act: DecisionAct) => {
    const it = model.queueItem.get(key)
    return !!it && actionsFor(it, now).some(a => a[0] === act) && !all[key] && sectionOf(key) !== 'done'
  }, [model, all, now, sectionOf])

  const decide = useCallback<DecisionsApi['decide']>((key, act, opts = {}) => {
    if (!canAct(key, act)) return false
    if (!opts.command) return false
    setAll(prev => ({ ...prev, [key]: { act, at: Date.now(), state: 'sent' } }))
    if (!opts.silent) {
      toast.show(opts.message ?? ACTIONS[act].label, {
        sub: opts.sub,
        icon: ACTIONS[act].icon,
      })
    }
    void send(opts.command).catch((e: unknown) => {
      setAll(prev => { const n = { ...prev }; delete n[key]; return n })
      toast.show(e instanceof Error ? e.message : 'Kovo Hunter could not complete the action.', { tone: 'error' })
    })
    return true
  }, [canAct, toast, send])

  const approveAllPending = useCallback<DecisionsApi['approveAllPending']>(async (command = { action: 'approve_all_pending' }) => {
    const count = activePendingApprovals.length
    if (count === 0 || approvingAll || pending > 0) return false
    const keys = activePendingApprovals.map(a => 'ap:' + a.id)
    setApprovingAll(true)
    try {
      await send(command)
      const at = Date.now()
      setAll(prev => {
        const next = { ...prev }
        for (const k of keys) next[k] = { act: 'approve', at, state: 'sent' }
        return next
      })
      toast.show(`Approved ${plural(count, 'pending request')}`, { icon: 'check' })
      return true
    } catch (err: unknown) {
      toast.show(err instanceof Error ? err.message : 'Could not approve pending requests.', { tone: 'error' })
      return false
    } finally {
      setApprovingAll(false)
    }
  }, [activePendingApprovals, approvingAll, pending, send, toast])

  const value = useMemo<DecisionsApi>(() => ({
    all,
    get: k => all[k],
    sections,
    openCount,
    decideCount: activeDecideCount,
    activeDecideCount,
    activePendingApprovals,
    initialCount,
    handledCount,
    sectionOf,
    canAct,
    decide,
    approvingAll,
    approveAllPending,
  }), [all, sections, openCount, activeDecideCount, activePendingApprovals, initialCount, handledCount, sectionOf, canAct, decide, approvingAll, approveAllPending])

  return <DecisionsContext.Provider value={value}>{children}</DecisionsContext.Provider>
}
