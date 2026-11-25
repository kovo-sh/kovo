// Toasts and undo. One toast at a time, bottom centre, springs up.
//
//   const toast = useToast()
//   toast.show('Grouped by origin')                              // 2 s
//   toast.show('Could not send', { tone: 'error' })               // 4 s
//   toast.undoable({                                              // 6 s with progress bar
//     message: 'Approved POST engine.dyad.sh/…', icon: 'check',
//     commit: () => send({ action: 'decide_approval', … }),       // runs when the window closes
//     undo: () => restoreLocalState(),                            // runs on Undo / Z / ⌘Z
//   })
//
// Deferred commits: an undoable action's `commit` runs when its toast
// expires, when another undoable replaces it, or when the run unmounts.
// Until then Undo cancels it, so nothing is sent. This is how real,
// irreversible commands (approvals, consent, stop) get an undo window.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Icon } from './icons.tsx'
import type { IconName } from './icons.tsx'
import { Kbd } from './display.tsx'
import { T } from './motion.tsx'

export interface ToastOptions {
  icon?: IconName
  sub?: string
  tone?: 'default' | 'error'
  ms?: number
}
export interface UndoableOptions {
  message: ReactNode
  sub?: string
  icon?: IconName
  /** Window length in ms (default 6000). */
  ms?: number
  /** Runs when the window closes without undo. May be async; failures surface as an error toast. */
  commit?: () => unknown | Promise<unknown>
  /** Runs when the user undoes. */
  undo?: () => void
}
export interface ToastApi {
  show: (message: ReactNode, opts?: ToastOptions) => void
  undoable: (opts: UndoableOptions) => void
  /** Undo the open undoable action, if any. Returns false when there is nothing to undo. */
  undoLast: () => boolean
  /** Commit the open undoable action now (no-op if none). */
  flush: () => void
  dismiss: () => void
}

interface Item {
  id: number
  message: ReactNode
  sub?: string
  icon?: IconName
  tone: 'default' | 'error'
  ms: number
  undo?: () => void
  out: boolean
}

const ToastContext = createContext<ToastApi | null>(null)
export function useToast(): ToastApi {
  const v = useContext(ToastContext)
  if (!v) throw new Error('useToast() must be used inside <ToastProvider>')
  return v
}

let nextId = 1

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Item[]>([])
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const pendingRef = useRef<{ id: number; commit?: UndoableOptions['commit']; undo?: () => void } | null>(null)
  const apiRef = useRef<ToastApi | null>(null)

  const close = useCallback((id?: number) => {
    setItems(list => list.map(t => (id == null || t.id === id ? { ...t, out: true } : t)))
    setTimeout(() => setItems(list => list.filter(t => !t.out)), T(180))
  }, [])

  const runCommit = useCallback((p: { commit?: UndoableOptions['commit'] } | null) => {
    if (!p?.commit) return
    try {
      const r = p.commit()
      if (r && typeof (r as Promise<unknown>).then === 'function') {
        ;(r as Promise<unknown>).catch((e: unknown) => apiRef.current?.show(e instanceof Error ? e.message : 'Kovo Hunter could not complete the action.', { tone: 'error' }))
      }
    } catch (e) {
      apiRef.current?.show(e instanceof Error ? e.message : 'Kovo Hunter could not complete the action.', { tone: 'error' })
    }
  }, [])

  const flush = useCallback(() => {
    const p = pendingRef.current
    pendingRef.current = null
    runCommit(p)
  }, [runCommit])

  const push = useCallback((item: Omit<Item, 'id' | 'out'>) => {
    clearTimeout(timer.current)
    const id = nextId++
    setItems(list => [...list.map(t => ({ ...t, out: true })), { ...item, id, out: false }])
    setTimeout(() => setItems(list => list.filter(t => !t.out || t.id === id)), T(180))
    timer.current = setTimeout(() => {
      if (pendingRef.current?.id === id) flush()
      close(id)
    }, item.ms)
    return id
  }, [close, flush])

  const api = useMemo<ToastApi>(() => ({
    show(message, opts = {}) {
      push({ message, sub: opts.sub, icon: opts.icon ?? (opts.tone === 'error' ? 'alert' : undefined), tone: opts.tone ?? 'default', ms: opts.ms ?? (opts.tone === 'error' ? 4000 : 2000) })
    },
    undoable(opts) {
      flush() // a previous pending action commits when replaced
      const ms = opts.ms ?? 6000
      const id = push({ message: opts.message, sub: opts.sub, icon: opts.icon, tone: 'default', ms, undo: () => apiRef.current?.undoLast() })
      pendingRef.current = { id, commit: opts.commit, undo: opts.undo }
    },
    undoLast() {
      const p = pendingRef.current
      if (!p) return false
      pendingRef.current = null
      clearTimeout(timer.current)
      p.undo?.()
      close(p.id)
      return true
    },
    flush,
    dismiss() { close() },
  }), [push, flush, close])
  apiRef.current = api

  // Commit anything still pending when the run unmounts (navigating away).
  useEffect(() => () => { clearTimeout(timer.current); const p = pendingRef.current; pendingRef.current = null; runCommit(p) }, [runCommit])

  return <ToastContext.Provider value={api}>
    {children}
    <div className="toasts" role="status" aria-live="polite">
      {items.map(t => <div key={t.id} className={'toast' + (t.out ? ' out' : '')} style={t.tone === 'error' ? { background: 'var(--bad)' } : undefined}>
        {t.icon && <span style={{ display: 'flex', opacity: 0.8 }}><Icon name={t.icon} /></span>}
        <div className="tx">{t.message}{t.sub && <small>{t.sub}</small>}</div>
        {t.undo && <>
          <button type="button" className="undo" onClick={t.undo}>Undo <Kbd>Z</Kbd></button>
          <span className="prog" style={{ animationDuration: t.ms + 'ms' }} />
        </>}
      </div>)}
    </div>
  </ToastContext.Provider>
}
