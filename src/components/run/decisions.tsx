// One decision store for the queue, the coordinator's pinned approvals and
// the consent sheet (F: "Approvals in the coordinator card and in the queue
// share one decision store").
//
//   const q = useDecisions()
//   q.sections.decide / review / follow / done   // base queue minus decided items
//   q.decide('ap:<id>', 'approve', { command: approvalCommand(id, 'approve'), message: 'Approved POST …' })
//   q.reopen(key)                                // move back to the queue (not yet sent)
//
// Every queue decision is a real server command: it stamps immediately, shows an
// undo toast, and sends when the 6 s window closes (or when another toast
// replaces it). Undo inside the window sends nothing. Local-only browser triage
// is intentionally absent so Queue never contradicts Report/SARIF/Overview.
import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { useRun } from './data.tsx'
import type { Command } from './data.tsx'
import type { IconName } from './icons.tsx'
import { isApprovalExpired } from './model.ts'
import type { QueueItem, QueueSection } from './model.ts'
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
  /** pending = inside the undo window; sent = command delivered; failed = command rejected */
  state: 'pending' | 'sent' | 'failed'
}

export interface DecisionsApi {
  all: Record<string, Decision>
  get: (key: string) => Decision | undefined
  sections: Record<QueueSection, QueueItem[]>
  /** Open items (decide + review + follow) and items needing a decision. */
  openCount: number
  decideCount: number
  /** Total actionable items (open + handled this session), always >= handledCount. */
  initialCount: number
  handledCount: number
  sectionOf: (key: string) => QueueSection | null
  canAct: (key: string, act: DecisionAct) => boolean
  decide: (key: string, act: DecisionAct, opts?: { command?: Command; message?: ReactNode; sub?: string; onUndo?: () => void; silent?: boolean }) => boolean
  reopen: (key: string) => void
  /** Retained for compatibility; local-only triage has been removed so this is always false. */
  undoLastLocal: () => boolean
}

const DecisionsContext = createContext<DecisionsApi | null>(null)
export function useDecisions(): DecisionsApi {
  const v = useContext(DecisionsContext)
  if (!v) throw new Error('useDecisions() must be used inside <DecisionsProvider>')
  return v
}

export function DecisionsProvider({ children }: { children: ReactNode }) {
  const { model, send } = useRun()
  const toast = useToast()
  const [all, setAll] = useState<Record<string, Decision>>({})

  const sections = useMemo(() => {
    const base = model.queue
    const out: Record<QueueSection, QueueItem[]> = { decide: [], review: [], follow: [], done: [] }
    for (const k of ['decide', 'review', 'follow'] as const) out[k] = base[k].filter(it => !all[it.key])
    const decided = Object.entries(all).map(([k, d]) => ({ it: model.queueItem.get(k), d })).filter(x => x.it).sort((a, b) => b.d.at - a.d.at).map(x => x.it!)
    out.done = decided.concat(base.done.filter(it => !all[it.key]))
    return out
  }, [model, all])

  const sectionOf = useCallback((key: string): QueueSection | null => {
    for (const k of ['decide', 'review', 'follow', 'done'] as const) if (sections[k].some(i => i.key === key)) return k
    return null
  }, [sections])

  const canAct = useCallback((key: string, act: DecisionAct) => {
    const it = model.queueItem.get(key)
    return !!it && actionsFor(it).some(a => a[0] === act) && !all[key] && sectionOf(key) !== 'done'
  }, [model, all, sectionOf])

  const decide = useCallback<DecisionsApi['decide']>((key, act, opts = {}) => {
    if (!canAct(key, act)) return false
    if (!opts.command) return false
    setAll(prev => ({ ...prev, [key]: { act, at: Date.now(), state: 'pending' } }))
    const undo = () => {
      setAll(prev => { const n = { ...prev }; delete n[key]; return n })
      opts.onUndo?.()
    }
    if (opts.silent) return true
    toast.undoable({
      message: opts.message ?? ACTIONS[act].label,
      sub: opts.sub ?? 'Sends when this closes',
      icon: ACTIONS[act].icon,
      undo,
      commit: async () => {
        try {
          await send(opts.command!)
          setAll(prev => prev[key] ? { ...prev, [key]: { ...prev[key], state: 'sent' } } : prev)
        } catch (e) {
          setAll(prev => { const n = { ...prev }; delete n[key]; return n })
          throw e
        }
      },
    })
    return true
  }, [canAct, toast, send])

  const reopen = useCallback((key: string) => {
    const d = all[key]
    if (d && d.state === 'sent') { toast.show('Already sent to Kovo Hunter; it can’t be moved back.'); return }
    if (d?.state === 'pending') { toast.undoLast(); return }
    setAll(prev => { const n = { ...prev }; delete n[key]; return n })
    toast.show('Moved back to the queue', { icon: 'undo' })
  }, [all, toast])

  const undoLastLocal = useCallback(() => false, [])

  const value = useMemo<DecisionsApi>(() => {
    const openCount = sections.decide.length + sections.review.length + sections.follow.length
    const handledCount = Object.keys(all).filter(k => model.queueItem.has(k)).length
    const progress = computeQueueProgress(openCount, handledCount)
    return {
      all, get: k => all[k], sections,
      openCount: progress.openCount,
      decideCount: sections.decide.length,
      initialCount: progress.initialCount,
      handledCount: progress.handledCount,
      sectionOf, canAct, decide, reopen, undoLastLocal,
    }
  }, [model, all, sections, sectionOf, canAct, decide, reopen, undoLastLocal])

  return <DecisionsContext.Provider value={value}>{children}</DecisionsContext.Provider>
}
