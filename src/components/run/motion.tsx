// Motion primitives. One curve everywhere: cubic-bezier(.2,.8,.2,1) at
// 120 / 180 / 240 ms (CSS: var(--ease), var(--d1|d2|d3)), plus a subtle
// spring (var(--spring)) for toasts, switches and stamps.
// Every primitive honours prefers-reduced-motion (instant, no animation).
import { useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore } from 'react'
import type { CSSProperties } from 'react'
import { clamp } from './format.ts'
import { cn } from './tw.ts'

export const DUR = { d1: 120, d2: 180, d3: 240, counter: 420, camera: 320 } as const
export const EASE_CSS = 'cubic-bezier(.2,.8,.2,1)'

/** The same Bézier solved numerically, for JS-driven animation (counters, cameras). */
export const ease = (() => {
  const x1 = 0.2, y1 = 0.8, x2 = 0.2, y2 = 1
  const A = (a: number, b: number) => 1 - 3 * b + 3 * a
  const B = (a: number, b: number) => 3 * b - 6 * a
  const C = (a: number) => 3 * a
  const calc = (t: number, a: number, b: number) => ((A(a, b) * t + B(a, b)) * t + C(a)) * t
  const slope = (t: number, a: number, b: number) => 3 * A(a, b) * t * t + 2 * B(a, b) * t + C(a)
  return (x: number) => {
    if (x <= 0) return 0
    if (x >= 1) return 1
    let t = x
    for (let i = 0; i < 6; i++) {
      const s = slope(t, x1, x2)
      if (!s) break
      t -= (calc(t, x1, x2) - x) / s
    }
    return calc(t, y1, y2)
  }
})()

const RM_QUERY = '(prefers-reduced-motion: reduce)'
const subscribeRM = (cb: () => void) => {
  const mq = window.matchMedia(RM_QUERY)
  mq.addEventListener('change', cb)
  return () => mq.removeEventListener('change', cb)
}
/** Imperative check, for event handlers and rAF loops. */
export const reducedMotion = () => typeof window !== 'undefined' && window.matchMedia(RM_QUERY).matches
/** Reactive check, for render. */
export function useReducedMotion() {
  return useSyncExternalStore(subscribeRM, reducedMotion, () => false)
}
/** Duration helper: 0 when reduced motion is on. */
export const T = (ms: number) => (reducedMotion() ? 0 : ms)

/** Animate a number over time with the shared curve. */
export function tween(from: number, to: number, dur: number, onFrame: (v: number) => void) {
  if (reducedMotion() || dur <= 0 || from === to) { onFrame(to); return () => {} }
  const t0 = performance.now()
  let raf = 0
  const step = (now: number) => {
    const p = Math.min(1, (now - t0) / dur)
    onFrame(from + (to - from) * ease(p))
    if (p < 1) raf = requestAnimationFrame(step)
  }
  raf = requestAnimationFrame(step)
  return () => cancelAnimationFrame(raf)
}

// Last shown value per counter / meter key, kept across remounts so values
// tick from the previous run's numbers on run switch (F's behaviour).
const lastCounter = new Map<string, number>()
const lastMeter = new Map<string, number>()

/**
 * Counter that ticks (420 ms) from its previous value. `id` keys the memory:
 * reuse the same id across runs (e.g. "ov.requests") to tick on run switch.
 */
export function AnimatedNumber({ id, value, format = n => Math.round(n).toLocaleString('en-US') }: {
  id: string
  value: number
  format?: (n: number) => string
}) {
  const from = lastCounter.get(id)
  const [shown, setShown] = useState(from ?? value)
  const fmt = useRef(format)
  fmt.current = format
  useEffect(() => {
    const start = lastCounter.get(id)
    lastCounter.set(id, value)
    if (start == null || start === value) { setShown(value); return }
    return tween(start, value, DUR.counter, setShown)
  }, [id, value])
  return <span className="num">{fmt.current(shown)}</span>
}

/**
 * Thin meter that grows (scaleX) from its previous value. `wide` fills the row.
 * Warns above 80% unless `warn` is given explicitly.
 */
export function Meter({ id, value, warn, wide, className, style, title, barColor }: {
  id: string
  value: number
  warn?: boolean
  wide?: boolean
  className?: string
  style?: CSSProperties
  title?: string
  barColor?: string
}) {
  const target = clamp(Number.isFinite(value) ? value : 0, 0, 1)
  const ref = useRef<HTMLElement>(null)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const prev = lastMeter.get(id) ?? 0
    lastMeter.set(id, target)
    if (reducedMotion() || prev === target) { el.style.setProperty('--v', String(target)); return }
    el.style.transition = 'none'
    el.style.setProperty('--v', String(prev))
    void el.offsetWidth
    el.style.transition = ''
    el.style.setProperty('--v', String(target))
  }, [id, target])
  const w = warn ?? target > 0.8
  return <span
    className={cn('relative inline-block h-1 flex-none overflow-hidden rounded-[4px] bg-line-2', wide ? 'w-full' : 'w-11', className)}
    style={style}
    title={title}
    role="meter"
    aria-valuemin={0}
    aria-valuemax={1}
    aria-valuenow={Number(target.toFixed(3))}
  >
    <i
      ref={ref}
      className={cn(
        'absolute inset-0 origin-left rounded-[4px] transition-transform duration-500 ease-guardian motion-reduce:transition-none',
        w ? 'bg-warn' : 'bg-fg-muted',
      )}
      style={{ transform: 'scaleX(var(--v, 0))', ...(barColor ? { background: barColor } : undefined) }}
    />
  </span>
}

/** Briefly true after `value` changes (not on mount). Drives one-shot pulses. */
export function usePulse(value: unknown, ms = 600) {
  const [on, setOn] = useState(false)
  const first = useRef(true)
  useEffect(() => {
    if (first.current) { first.current = false; return }
    if (reducedMotion()) return
    setOn(true)
    const t = setTimeout(() => setOn(false), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return on
}
