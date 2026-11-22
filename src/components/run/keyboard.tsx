// Keyboard manager. One window keydown listener; components register
// bindings while mounted:
//
//   useShortcuts([
//     { key: ['j', 'ArrowDown'], run: () => move(1) },
//     { key: 'G', run: cycleGrouping },            // Shift+G (e.key is 'G')
//     { key: 'mod+z', run: undo, allowInInput: false },
//     { key: 'g w', run: () => setView('workflow') }, // chord: g then w
//   ], { priority: 10 })
//
// Resolution: exclusive layers (open overlays) first, then higher priority,
// then the most recently mounted. A handler that returns `false` lets the key
// fall through to the next binding. Bindings are skipped while typing in an
// input/textarea unless `allowInInput` is set; Escape in an input blurs it.
//
// Priorities: 0 = shell/global, 10 = views (default), 20 = inspector, 100 = overlays.
import { createContext, useContext, useEffect, useRef } from 'react'
import type { ReactNode } from 'react'

export interface Shortcut {
  /** 'j', 'ArrowDown', 'Enter', 'Escape', ' ', '?', 'G' (shift), 'mod+k', 'mod+z', or a chord 'g w'. */
  key: string | string[]
  run: (e: KeyboardEvent) => boolean | void
  when?: () => boolean
  allowInInput?: boolean
}
interface Layer { id: number; priority: number; exclusive: boolean; get: () => Shortcut[]; enabled: () => boolean }

interface KeyboardApi { register: (layer: Omit<Layer, 'id'>) => () => void }
const KeyboardContext = createContext<KeyboardApi | null>(null)

let layerSeq = 0
const CHORD_MS = 900

const isTyping = (t: EventTarget | null) => t instanceof HTMLElement && Boolean(t.closest('input, textarea, select, [contenteditable=""], [contenteditable=true]'))

function combo(e: KeyboardEvent) {
  if (e.metaKey || e.ctrlKey) return 'mod+' + e.key.toLowerCase()
  return e.key
}

export function KeyboardProvider({ children }: { children: ReactNode }) {
  const layers = useRef<Layer[]>([])
  const chordAt = useRef(0)
  const api = useRef<KeyboardApi>({
    register(layer) {
      const entry = { ...layer, id: ++layerSeq }
      layers.current = [...layers.current, entry]
      return () => { layers.current = layers.current.filter(l => l !== entry) }
    },
  })

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey || e.isComposing) return
      const typing = isTyping(e.target)
      const k = combo(e)
      const active = layers.current.filter(l => l.enabled())
      const exclusive = active.filter(l => l.exclusive)
      const pool = (exclusive.length ? exclusive : active).slice().sort((a, b) => b.priority - a.priority || b.id - a.id)
      const bindings = pool.flatMap(l => l.get())
      const matches = (s: Shortcut, key: string) => (Array.isArray(s.key) ? s.key : [s.key]).includes(key)

      // chords: "g" then a letter
      const chordLive = Date.now() - chordAt.current < CHORD_MS
      if (chordLive && !typing && !(e.metaKey || e.ctrlKey)) {
        chordAt.current = 0
        const seq = 'g ' + e.key.toLowerCase()
        for (const s of bindings) {
          if (matches(s, seq) && (!s.when || s.when())) {
            if (s.run(e) !== false) { e.preventDefault(); return }
          }
        }
        return
      }
      if (k === 'g' && !typing && bindings.some(s => (Array.isArray(s.key) ? s.key : [s.key]).some(x => x.startsWith('g ')))) {
        chordAt.current = Date.now()
        return
      }
      // Enter / Space on a focused control activate it; don't steal them.
      const onControl = (k === 'Enter' || k === ' ') && e.target instanceof HTMLElement && Boolean(e.target.closest('button, a[href], [role=button], [role=link], summary'))
      for (const s of bindings) {
        if (!matches(s, k)) continue
        if (typing && !s.allowInInput) continue
        if (onControl) continue
        if (s.when && !s.when()) continue
        if (s.run(e) !== false) { e.preventDefault(); return }
      }
      if (typing && e.key === 'Escape' && e.target instanceof HTMLElement) {
        e.target.blur()
        e.preventDefault()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return <KeyboardContext.Provider value={api.current}>{children}</KeyboardContext.Provider>
}

/**
 * Register bindings while the component is mounted. The latest `shortcuts`
 * array is always used (no need to memoise). `enabled: false` pauses them.
 */
export function useShortcuts(shortcuts: Shortcut[], opts: { priority?: number; exclusive?: boolean; enabled?: boolean } = {}) {
  const api = useContext(KeyboardContext)
  const ref = useRef(shortcuts)
  ref.current = shortcuts
  const enabled = useRef(opts.enabled ?? true)
  enabled.current = opts.enabled ?? true
  const priority = opts.priority ?? 10
  const exclusive = opts.exclusive ?? false
  useEffect(() => {
    if (!api) return
    return api.register({ priority, exclusive, get: () => ref.current, enabled: () => enabled.current })
  }, [api, priority, exclusive])
}
