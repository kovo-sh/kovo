// One decision store for the queue, the coordinator's pinned approvals and
// the consent sheet (F: "Approvals in the coordinator card and in the queue
// share one decision store").
//
//   const q = useDecisions()
//   q.sections.decide / review / follow / done   // base queue minus decided items
//   q.decide('ap:<id>', 'approve', { command: approvalCommand(id, 'approve'), message: 'Approved POST …' })
//   q.decide('b:hsts:pending', 'dismiss')        // local-only triage (no server API), persisted per run
//   q.reopen(key)                                // move back to the queue (local / not yet sent)
//
// Decisions with a `command` are real: they stamp immediately, show an undo
// toast, and the command is sent when the 6 s window closes (or when the
// next decision replaces the toast). Undo inside the window sends nothing.
// Local-only decisions persist in localStorage (`guardian-queue:<runId>`).
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useRun } from './data.tsx'
import type { Command } from './data.tsx'
import type { IconName } from './icons.tsx'
import type { QueueItem, QueueSection } from './model.ts'
import { useToast } from './toast.tsx'

export type DecisionAct = 'approve' | 'deny' | 'accept' | 'dismiss' | 'fp' | 'queue' | 'close' | 'scope'
export const ACTIONS: Record<DecisionAct, { label: string; tone: 'ok' | 'no' | 'fp' | 'acc'; icon: IconName }> = {
  approve: { label: 'Approved', tone: 'ok', icon: 'check' },
  deny: { label: 'Denied', tone: 'no', icon: 'x' },
  accept: { label: 'Accepted', tone: 'ok', icon: 'check' },
  dismiss: { label: 'Dismissed', tone: 'no', icon: 'archive' },
  fp: { label: 'False positive', tone: 'fp', icon: 'slash' },
  queue: { label: 'Follow-up queued', tone: 'acc', icon: 'follow' },
  close: { label: 'Not needed', tone: 'no', icon: 'archive' },
  scope: { label: 'Scope approved', tone: 'ok', icon: 'check' },
}

/** Which actions an item offers: [act, button label, key, primary]. */
export function actionsFor(it: QueueItem | undefined | null): [DecisionAct, string, string, boolean][] {
  if (!it) return []
  if (it.kind === 'consent') return [['scope', 'Approve scope', 'a', true]]
  if (it.kind === 'approval') return [['approve', 'Approve', 'a', true], ['deny', 'Deny', 'd', false]]
  if (it.kind === 'follow') return [['queue', 'Queue follow-up', 'a', true], ['close', 'Not needed', 'd', false]]
  return [['accept', 'Accept', 'a', true], ['dismiss', 'Dismiss', 'd', false], ['fp', 'False positive', 'f', false]]
}

/** The real command for an approval decision. */
export function approvalCommand(approvalId: string, act: 'approve' | 'deny'): Command {
  return { action: 'decide_approval', approvalId, decision: act === 'approve' ? 'approved' : 'denied' }
}

export interface Decision {
  act: DecisionAct
  at: number
  /** local = UI-only triage; pending = inside the undo window; sent = command delivered; failed = command rejected */
  state: 'local' | 'pending' | 'sent' | 'failed'
}

export interface DecisionsApi {
  all: Record<string, Decision>
  get: (key: string) => Decision | undefined
  sections: Record<QueueSection, QueueItem[]>
  /** Open items (decide + review + follow) and items needing a decision. */
  openCount: number
  decideCount: number
  /** Items present at load that could be acted on, and how many the operator handled this session. */
  initialCount: number
  handledCount: number
  sectionOf: (key: string) => QueueSection | null
  canAct: (key: string, act: DecisionAct) => boolean
  decide: (key: string, act: DecisionAct, opts?: { command?: Command; message?: ReactNode; sub?: string; onUndo?: () => void; silent?: boolean }) => boolean
  reopen: (key: string) => void
  /** Undo the most recent local decision (after its toast closed). */
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
  const runId = model.run.id
  const storageKey = 'guardian-queue:' + runId
  const [all, setAll] = useState<Record<string, Decision>>({})
  const order = useRef<string[]>([])

  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey) ?? '{}') as Record<string, Decision>
      setAll(saved)
      order.current = Object.entries(saved).sort((a, b) => a[1].at - b[1].at).map(([k]) => k)
    } catch { /* ignore */ }
  }, [storageKey])

  const persist = useCallback((next: Record<string, Decision>) => {
    const local = Object.fromEntries(Object.entries(next).filter(([, d]) => d.state === 'local'))
    try { localStorage.setItem(storageKey, JSON.stringify(local)) } catch { /* ignore */ }
  }, [storageKey])

  const update = useCallback((fn: (prev: Record<string, Decision>) => Record<string, Decision>) => {
    setAll(prev => { const next = fn(prev); persist(next); return next })
  }, [persist])

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
    const real = Boolean(opts.command)
    order.current = [...order.current.filter(k => k !== key), key]
    update(prev => ({ ...prev, [key]: { act, at: Date.now(), state: real ? 'pending' : 'local' } }))
    const undo = () => {
      order.current = order.current.filter(k => k !== key)
      update(prev => { const n = { ...prev }; delete n[key]; return n })
      opts.onUndo?.()
    }
    if (opts.silent) return true
    toast.undoable({
      message: opts.message ?? ACTIONS[act].label,
      sub: opts.sub ?? (real ? 'Sends when this closes' : undefined),
      icon: ACTIONS[act].icon,
      undo,
      commit: real ? async () => {
        try {
          await send(opts.command!)
          update(prev => prev[key] ? { ...prev, [key]: { ...prev[key], state: 'sent' } } : prev)
        } catch (e) {
          update(prev => { const n = { ...prev }; delete n[key]; return n })
          throw e
        }
      } : undefined,
    })
    return true
  }, [canAct, update, toast, send])

  const reopen = useCallback((key: string) => {
    const d = all[key]
    if (d && d.state === 'sent') { toast.show('Already sent to Guardian; it can’t be moved back.'); return }
    if (d?.state === 'pending') { toast.undoLast(); return }
    order.current = order.current.filter(k => k !== key)
    update(prev => { const n = { ...prev }; delete n[key]; return n })
    toast.show('Moved back to the queue', { icon: 'undo' })
  }, [all, update, toast])

  const undoLastLocal = useCallback(() => {
    for (let i = order.current.length - 1; i >= 0; i--) {
      const k = order.current[i]
      if (all[k]?.state === 'local') { reopen(k); return true }
    }
    return false
  }, [all, reopen])

  const value = useMemo<DecisionsApi>(() => {
    const base = model.queue
    const initialCount = base.decide.length + base.review.length + base.follow.length
    return {
      all, get: k => all[k], sections,
      openCount: sections.decide.length + sections.review.length + sections.follow.length,
      decideCount: sections.decide.length,
      initialCount,
      handledCount: Object.keys(all).filter(k => model.queueItem.has(k)).length,
      sectionOf, canAct, decide, reopen, undoLastLocal,
    }
  }, [model, all, sections, sectionOf, canAct, decide, reopen, undoLastLocal])

  return <DecisionsContext.Provider value={value}>{children}</DecisionsContext.Provider>
}
