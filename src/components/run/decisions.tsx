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
import type { ApprovalScope } from '../../domain.ts'
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
    const isHighOrDelete = it.ap.riskLevel === 'high' || String(it.ap.method ?? '').trim().toUpperCase() === 'DELETE'
    return [['approve', isHighOrDelete ? 'Approve once' : 'Approve route', 'a', true], ['deny', 'Deny', 'd', false]]
  }
  if (it.kind === 'follow') return [['queue', 'Queue follow-up', 'a', true]]
  return []
}

/** The real command for an approval decision. */
export function approvalCommand(approvalId: string, act: 'approve' | 'deny', scope?: ApprovalScope): Command {
  return {
    action: 'decide_approval',
    approvalId,
    decision: act === 'approve' ? 'approved' : 'denied',
    ...(scope ? { scope } : {}),
  }
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
 * Reconcile optimistic local decisions against fresh server snapshots and the shared clock.
 * Drops any optimistic entry whose underlying server item has settled, expired, or disappeared
 * so stale client state can never shadow authoritative server truth on SSE reconnect/refresh.
 */
export function reconcileOptimisticDecisions(
  all: Record<string, Decision>,
  queueItem: Map<string, QueueItem>,
  now = Date.now(),
): Record<string, Decision> {
  const keys = Object.keys(all)
  if (!keys.length) return all
  let changed = false
  const next: Record<string, Decision> = {}
  for (const key of keys) {
    const entry = all[key]!
    const item = queueItem.get(key)
    if (!item) {
      changed = true
      continue
    }
    if (item.kind === 'approval') {
      if (item.ap.status !== 'pending' || isApprovalExpired(item.ap, now)) {
        changed = true
        continue
      }
    } else if (item.kind === 'follow') {
      if (item.cov.status !== 'needs_follow_up') {
        changed = true
        continue
      }
    }
    next[key] = entry
  }
  return changed ? next : all
}

/**
 * Derive active queue sections, blocking decision tally, and active pending approvals from the
 * run model and optimistic session decisions. Client-expired or server-settled approvals reconcile
 * immediately against server truth (never permanently shadowed by stale optimistic entries),
 * and `follow` items never inflate `activeDecideCount`.
 */
export function deriveQueueDecisions(
  base: Record<QueueSection, QueueItem[]>,
  queueItem: Map<string, QueueItem>,
  all: Record<string, Decision>,
  now = Date.now(),
  sessionHandledKeys?: ReadonlySet<string>,
) {
  // Reconcile optimistic decisions inline so standalone callers also drop settled/expired shadows.
  const activeAll: Record<string, Decision> = {}
  for (const [k, d] of Object.entries(all)) {
    const it = queueItem.get(k)
    if (!it) continue
    if (it.kind === 'approval' && (it.ap.status !== 'pending' || isApprovalExpired(it.ap, now))) continue
    if (it.kind === 'follow' && it.cov.status !== 'needs_follow_up') continue
    activeAll[k] = d
  }

  const decide: QueueItem[] = []
  const expired: QueueItem[] = []
  for (const it of base.decide) {
    if (activeAll[it.key]) continue
    if (it.kind === 'approval' && isApprovalExpired(it.ap, now)) {
      expired.push(it)
    } else {
      decide.push(it)
    }
  }
  const review = base.review.filter(it => !activeAll[it.key])
  const follow = base.follow.filter(it => !activeAll[it.key])
  const decided = Object.entries(activeAll)
    .map(([k, d]) => ({ it: queueItem.get(k), d }))
    .filter(x => x.it)
    .sort((a, b) => b.d.at - a.d.at)
    .map(x => x.it!)
  const doneRest = expired.concat(base.done.filter(it => !activeAll[it.key])).sort((a, b) => b.t - a.t)
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
  const handledSet = new Set<string>()
  for (const k of Object.keys(activeAll)) {
    if (queueItem.has(k)) handledSet.add(k)
  }
  if (sessionHandledKeys) {
    for (const k of sessionHandledKeys) {
      if (queueItem.has(k)) handledSet.add(k)
    }
  }
  const handledCount = handledSet.size
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
  /** Shared expiry clock from `RunDataProvider`, synchronized with banner, queue, and rail. */
  now: number
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
  decide: (key: string, act: DecisionAct, opts?: { command?: Command; message?: ReactNode; sub?: string; silent?: boolean; alsoKeys?: readonly string[] }) => boolean
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
  const { detail, model, send, pending, now } = useRun()
  const toast = useToast()
  const runId = detail.run.id
  const [all, setAll] = useState<Record<string, Decision>>({})
  const [sessionHandledKeys, setSessionHandledKeys] = useState<Set<string>>(() => new Set())
  const [approvingAll, setApprovingAll] = useState(false)

  // Reset optimistic overlays cleanly when switching runs.
  useEffect(() => {
    setAll({})
    setSessionHandledKeys(new Set())
    setApprovingAll(false)
  }, [runId])

  // Synchronously reconcile optimistic entries against the latest server snapshot + shared clock.
  const reconciledAll = useMemo(
    () => reconcileOptimisticDecisions(all, model.queueItem, now),
    [all, model.queueItem, now],
  )

  useEffect(() => {
    if (reconciledAll !== all) {
      setAll(prev => reconcileOptimisticDecisions(prev, model.queueItem, now))
    }
  }, [reconciledAll, all, model.queueItem, now])

  const derived = useMemo(
    () => deriveQueueDecisions(model.queue, model.queueItem, reconciledAll, now, sessionHandledKeys),
    [model, reconciledAll, now, sessionHandledKeys],
  )
  const { sections, activePendingApprovals, activeDecideCount, openCount, initialCount, handledCount } = derived

  const sectionOf = useCallback((key: string): QueueSection | null => {
    for (const k of ['decide', 'review', 'follow', 'done'] as const) if (sections[k].some(i => i.key === key)) return k
    return null
  }, [sections])

  const canAct = useCallback((key: string, act: DecisionAct) => {
    const it = model.queueItem.get(key)
    return !!it && actionsFor(it, now).some(a => a[0] === act) && !reconciledAll[key] && sectionOf(key) !== 'done'
  }, [model, reconciledAll, now, sectionOf])

  const decide = useCallback<DecisionsApi['decide']>((key, act, opts = {}) => {
    if (!canAct(key, act)) return false
    if (!opts.command) return false
    const affectedKeys = [key, ...(opts.alsoKeys ?? []).filter(k => k !== key && !reconciledAll[k])]
    const at = Date.now()
    setAll(prev => {
      const next = { ...prev }
      for (const k of affectedKeys) next[k] = { act, at, state: 'sent' }
      return next
    })
    if (!opts.silent) {
      toast.show(opts.message ?? ACTIONS[act].label, {
        sub: opts.sub,
        icon: ACTIONS[act].icon,
      })
    }
    void send(opts.command).then(
      () => {
        setSessionHandledKeys(prev => {
          const next = new Set(prev)
          for (const k of affectedKeys) next.add(k)
          return next
        })
      },
      (e: unknown) => {
        setAll(prev => {
          const n = { ...prev }
          for (const k of affectedKeys) delete n[k]
          return n
        })
        toast.show(e instanceof Error ? e.message : 'Kovo could not complete the action.', { tone: 'error' })
      },
    )
    return true
  }, [canAct, reconciledAll, toast, send])

  const approveAllPending = useCallback<DecisionsApi['approveAllPending']>(async (command = { action: 'approve_all_pending' }) => {
    const count = activePendingApprovals.length
    if (count === 0 || approvingAll || pending > 0) return false
    const keys = activePendingApprovals.map(a => 'ap:' + a.id)
    const at = Date.now()
    setApprovingAll(true)
    setAll(prev => {
      const next = { ...prev }
      for (const k of keys) next[k] = { act: 'approve', at, state: 'sent' }
      return next
    })
    try {
      await send(command)
      // Drop in-flight overlay after send()+refresh() settles so server truth (approved vs mid-flight expired) wins immediately.
      setAll(prev => {
        const next = { ...prev }
        for (const k of keys) delete next[k]
        return next
      })
      setSessionHandledKeys(prev => {
        const next = new Set(prev)
        for (const k of keys) next.add(k)
        return next
      })
      toast.show(`Approved ${plural(count, 'pending request')}`, { icon: 'check' })
      return true
    } catch (err: unknown) {
      setAll(prev => {
        const next = { ...prev }
        for (const k of keys) delete next[k]
        return next
      })
      toast.show(err instanceof Error ? err.message : 'Could not approve pending requests.', { tone: 'error' })
      return false
    } finally {
      setApprovingAll(false)
    }
  }, [activePendingApprovals, approvingAll, pending, send, toast])

  const value = useMemo<DecisionsApi>(() => ({
    all: reconciledAll,
    get: k => reconciledAll[k],
    now,
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
  }), [reconciledAll, now, sections, openCount, activeDecideCount, activePendingApprovals, initialCount, handledCount, sectionOf, canAct, decide, approvingAll, approveAllPending])

  return <DecisionsContext.Provider value={value}>{children}</DecisionsContext.Provider>
}
