// Toasts. One toast at a time, bottom centre, springs up.
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Icon } from './icons.tsx'
import type { IconName } from './icons.tsx'
import { T } from './motion.tsx'
import { cn } from './tw.ts'

export interface ToastOptions {
  icon?: IconName
  sub?: string
  tone?: 'default' | 'error'
  ms?: number
}
export interface ToastApi {
  show: (message: ReactNode, opts?: ToastOptions) => void
  dismiss: () => void
}

/**
 * Pure toast controller shared by `ToastProvider` and unit tests.
 */
export function createToastController(hooks: {
  onPush: (item: { id: number; message: ReactNode; sub?: string; icon?: IconName; tone: 'default' | 'error'; ms: number }) => void
  onClose: (id?: number) => void
  setTimer?: (fn: () => void, ms: number) => ReturnType<typeof setTimeout>
  clearTimer?: (handle: ReturnType<typeof setTimeout> | undefined) => void
}) {
  const schedule = hooks.setTimer ?? ((fn, ms) => setTimeout(fn, ms))
  const cancel = hooks.clearTimer ?? (h => { if (h !== undefined) clearTimeout(h) })
  let nextId = 1
  let timer: ReturnType<typeof setTimeout> | undefined

  const push = (item: { message: ReactNode; sub?: string; icon?: IconName; tone: 'default' | 'error'; ms: number }) => {
    cancel(timer)
    const id = nextId++
    hooks.onPush({ ...item, id })
    timer = schedule(() => {
      hooks.onClose(id)
    }, item.ms)
    return id
  }

  const api: ToastApi & { dispose: () => void } = {
    show(message, opts = {}) {
      push({
        message,
        sub: opts.sub,
        icon: opts.icon ?? (opts.tone === 'error' ? 'alert' : undefined),
        tone: opts.tone ?? 'default',
        ms: opts.ms ?? (opts.tone === 'error' ? 4000 : 2000),
      })
    },
    dismiss() {
      cancel(timer)
      hooks.onClose()
    },
    dispose() {
      cancel(timer)
    },
  }
  return api
}

interface Item {
  id: number
  message: ReactNode
  sub?: string
  icon?: IconName
  tone: 'default' | 'error'
  ms: number
  out: boolean
}

const ToastContext = createContext<ToastApi | null>(null)
export function useToast(): ToastApi {
  const v = useContext(ToastContext)
  if (!v) throw new Error('useToast() must be used inside <ToastProvider>')
  return v
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Item[]>([])

  const close = useCallback((id?: number) => {
    setItems(list => list.map(t => (id == null || t.id === id ? { ...t, out: true } : t)))
    setTimeout(() => setItems(list => list.filter(t => !t.out)), T(180))
  }, [])

  const controller = useMemo(() => createToastController({
    onPush(item) {
      const next: Item = {
        id: item.id,
        message: item.message,
        sub: item.sub,
        icon: item.icon,
        tone: item.tone,
        ms: item.ms,
        out: false,
      }
      setItems(list => [...list.map(t => ({ ...t, out: true })), next])
      setTimeout(() => setItems(list => list.filter(t => !t.out || t.id === item.id)), T(180))
    },
    onClose: close,
  }), [close])

  const api = useMemo<ToastApi>(() => ({
    show: controller.show,
    dismiss: controller.dismiss,
  }), [controller])

  useEffect(() => () => { controller.dispose() }, [controller])

  return <ToastContext.Provider value={api}>
    {children}
    <div className="pointer-events-none fixed bottom-5 left-1/2 z-[60] flex -translate-x-1/2 flex-col items-center gap-2" role="status" aria-live="polite">
      {items.map(t => <div
        key={t.id}
        className={cn(
          'pointer-events-auto relative flex min-w-[280px] max-w-[520px] items-center gap-2.5 overflow-hidden rounded-[9px] py-2 pl-3 pr-3 text-[12.5px] shadow-[0_10px_30px_-10px_rgba(0,0,0,.4)] transition-[opacity,transform] duration-[var(--d2)] ease-kovo',
          t.tone === 'error' ? 'bg-danger text-white' : 'bg-fg text-panel',
          t.out ? 'translate-y-2 opacity-0' : 'translate-y-0 opacity-100',
        )}
      >
        {t.icon && <span className="flex opacity-80"><Icon name={t.icon} /></span>}
        <div className="min-w-0 flex-1">
          {t.message}
          {t.sub && <small className="block truncate text-[11.5px] text-current opacity-65">{t.sub}</small>}
        </div>
      </div>)}
    </div>
  </ToastContext.Provider>
}
