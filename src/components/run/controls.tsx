// Shared toolbar and list controls (foundation; used by every list view):
// a dropdown menu, toolbar tabs that fold into "More · n", the `/` filter box,
// a variable-height virtual list with scroll anchoring, a cursor tooltip, and a debounce hook.
import { forwardRef, useCallback, useEffect, useImperativeHandle, useLayoutEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties, ReactNode, RefObject } from 'react'
import { Kbd } from './display.tsx'
import { fmtN } from './format.ts'
import { Icon } from './icons.tsx'
import type { IconName } from './icons.tsx'
import { useShortcuts } from './keyboard.tsx'
import { cn, runBtn, runDdItem, RW } from './tw.ts'

// ---------------------------------------------------------------- dropdown

/** Ghost button that opens a popover menu; closes on outside click / Esc. */
export function Dropdown({ label, icon, children, title, className, menuClassName, align = 'right', btnClassName }: {
  label: ReactNode
  icon?: IconName
  children: ReactNode | ((close: () => void) => ReactNode)
  title?: string
  className?: string
  menuClassName?: string
  align?: 'left' | 'right'
  btnClassName?: string
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const down = (e: PointerEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false) }
    window.addEventListener('pointerdown', down)
    return () => window.removeEventListener('pointerdown', down)
  }, [open])
  useShortcuts([{ key: 'Escape', allowInInput: true, run: () => { if (!open) return false; setOpen(false) } }], { priority: 90, enabled: open })
  const close = useCallback(() => setOpen(false), [])
  return <div ref={ref} className={cn('relative', className)}>
    <button
      type="button"
      className={btnClassName ?? runBtn({ variant: 'ghost' })}
      title={title}
      aria-haspopup="menu"
      aria-expanded={open}
      onClick={() => setOpen(o => !o)}
    >
      {icon && <Icon name={icon} />}{label}<Icon name="chev" className="text-fg-subtle" />
    </button>
    {open && <div
      className={cn(
        RW.ddMenu,
        align === 'left' && 'left-0 right-auto origin-top-left',
        menuClassName,
      )}
      role="menu"
    >
      {typeof children === 'function' ? children(close) : children}
    </div>}
  </div>
}

// ---------------------------------------------------------------- toolbar tabs + filter

/**
 * Toolbar tabs. Tabs that don't fit fold into "More · n" instead of clipping;
 * the current tab always stays visible.
 */
export function Tabs<T extends string>({ tabs, value, onChange, label }: { tabs: [T, string, number][]; value: T; onChange: (v: T) => void; label?: string }) {
  const wrap = useRef<HTMLDivElement>(null)
  const widths = useRef(new Map<string, number>())
  const [cut, setCut] = useState<Set<string>>(new Set())
  const sig = tabs.map(t => t[0] + t[2]).join(',') + '|' + value
  useLayoutEffect(() => {
    const el = wrap.current
    if (!el) return
    const measure = () => {
      el.querySelectorAll<HTMLElement>('[data-tab]').forEach(t => widths.current.set(t.dataset.tab!, t.offsetWidth))
      const avail = el.clientWidth
      const w = (k: string) => (widths.current.get(k) ?? 80) + 2
      const total = tabs.reduce((a, t) => a + w(t[0]), 0)
      const hidden = new Set<string>()
      if (total > avail + 1) {
        let used = 86 + (tabs.some(t => t[0] === value) ? w(value) : 0) // "More · n" + the current tab
        for (const [k] of tabs) {
          if (k === value) continue
          if (used + w(k) <= avail) used += w(k)
          else hidden.add(k)
        }
      }
      setCut(prev => (prev.size === hidden.size && [...hidden].every(k => prev.has(k)) ? prev : hidden))
    }
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [sig, value]) // eslint-disable-line react-hooks/exhaustive-deps
  const folded = tabs.filter(t => cut.has(t[0]))
  return <div className="flex min-w-0 flex-1 gap-0.5 overflow-visible" role="tablist" aria-label={label} ref={wrap}>
    {tabs.filter(t => !cut.has(t[0])).map(([k, l, n]) => {
      const on = value === k
      return <button
        key={k}
        data-tab={k}
        type="button"
        role="tab"
        aria-selected={on}
        className={cn(
          'inline-flex h-[26px] flex-none cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-control border-0 px-[9px] text-[12.5px] font-medium shadow-none transition-[background-color,color] duration-[var(--d1)]',
          on ? 'bg-press text-fg hover:bg-press' : 'bg-transparent text-fg-muted hover:bg-hover hover:text-fg',
        )}
        onClick={() => onChange(k)}
      >
        {l}<span className="num font-normal text-fg-subtle">{fmtN(n)}</span>
      </button>
    })}
    {folded.length > 0 && <Dropdown
      className="flex-none"
      btnClassName="inline-flex h-[26px] flex-none cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-control border-0 bg-transparent px-[9px] text-[12.5px] font-normal text-fg-subtle shadow-none transition-[background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg"
      label={'More · ' + folded.length}
      menuClassName="top-[30px] w-[200px] p-1.5"
      align="left"
    >
      {close => folded.map(([k, l, n]) => <button key={k} type="button" className={runDdItem()} onClick={() => { onChange(k); close() }}>
        {l}<span className="num ml-auto text-fg-subtle">{fmtN(n)}</span>
      </button>)}
    </Dropdown>}
  </div>
}

/**
 * List filter box. `/` focuses it; ↓ / ↵ jump to the first match (via onEnter);
 * Esc clears the text, a second Esc (or Esc when empty) leaves the box.
 */
export const FilterBox = forwardRef<HTMLInputElement, { value: string; onChange: (v: string) => void; onEnter?: () => void; placeholder?: string; label?: string; className?: string }>(
  function FilterBox({ value, onChange, onEnter, placeholder = 'Filter', label, className }, ref) {
    const inner = useRef<HTMLInputElement>(null)
    useImperativeHandle(ref, () => inner.current!, [])
    useShortcuts([{ key: '/', run: () => { inner.current?.focus(); inner.current?.select() } }])
    return <label className={cn(
      'flex h-[26px] w-[120px] flex-none items-center gap-1.5 rounded-control px-2 text-fg-subtle transition-[width,background-color,box-shadow] duration-[var(--d2)] ease-guardian hover:bg-hover focus-within:w-[200px] focus-within:bg-sunk focus-within:text-fg-muted focus-within:shadow-hairline',
      className,
    )}>
      <Icon name="search" />
      <input
        ref={inner}
        className={RW.rawInput}
        placeholder={placeholder}
        value={value}
        spellCheck={false}
        aria-label={label ?? placeholder}
        onChange={e => onChange(e.target.value)}
        onKeyDown={e => {
          if ((e.key === 'Enter' || e.key === 'ArrowDown') && onEnter) { e.preventDefault(); inner.current?.blur(); onEnter() }
          if (e.key === 'Escape' && value) { e.preventDefault(); e.stopPropagation(); onChange('') }
        }}
      />
      {!value
        ? <Kbd>/</Kbd>
        : <button
          type="button"
          className="inline-flex h-auto cursor-pointer items-center justify-center rounded-[4px] border-0 bg-transparent p-0.5 text-fg-subtle shadow-none hover:bg-hover hover:text-fg"
          aria-label="Clear filter"
          onClick={() => { onChange(''); inner.current?.focus() }}
        >
          <Icon name="close" size={12} />
        </button>}
    </label>
  })

/** Whitespace-separated terms, all must match. */
export function matchQ(q: string, text: string) {
  const s = q.trim().toLowerCase()
  if (!s) return true
  const t = text.toLowerCase()
  return s.split(/\s+/).every(w => t.includes(w))
}

// ---------------------------------------------------------------- virtual list

/**
 * Windowed list with per-item heights (rows 36px, group heads 32px).
 * - `scrollToIndex` keeps the cursor row in view.
 * - `anchor`: when items are prepended (live activity), the viewport stays on
 *   what the reader was looking at unless they are at the very top.
 */
export function VList<T>({ items, itemKey, height, render, overscan = 10, className, scrollToIndex, footer, anchor, listRef, empty }: {
  items: readonly T[]
  itemKey: (it: T) => string
  height: (it: T) => number
  render: (it: T, index: number, style: CSSProperties) => ReactNode
  overscan?: number
  className?: string
  scrollToIndex?: number
  footer?: ReactNode
  anchor?: boolean
  listRef?: RefObject<HTMLDivElement | null>
  empty?: ReactNode
}) {
  const own = useRef<HTMLDivElement>(null)
  const ref = listRef ?? own
  const offsets = useMemo(() => {
    const o = new Array<number>(items.length + 1)
    o[0] = 0
    for (let i = 0; i < items.length; i++) o[i + 1] = o[i] + height(items[i])
    return o
  }, [items, height])
  const total = offsets[items.length]
  const [range, setRange] = useState<[number, number]>([0, 40])
  const find = useCallback((y: number) => {
    let lo = 0, hi = items.length
    while (lo < hi) { const mid = (lo + hi) >> 1; if (offsets[mid + 1] <= y) lo = mid + 1; else hi = mid }
    return lo
  }, [offsets, items.length])
  const update = useCallback(() => {
    const el = ref.current
    if (!el) return
    const first = Math.max(0, find(el.scrollTop) - overscan)
    const last = Math.min(items.length, find(el.scrollTop + el.clientHeight) + 1 + overscan)
    setRange(r => (r[0] === first && r[1] === last ? r : [first, last]))
  }, [find, overscan, items.length, ref])
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    update()
    el.addEventListener('scroll', update, { passive: true })
    const ro = new ResizeObserver(update)
    ro.observe(el)
    return () => { el.removeEventListener('scroll', update); ro.disconnect() }
  }, [update, ref])

  // Scroll anchoring for prepends.
  const prevFirst = useRef<string | null>(null)
  useLayoutEffect(() => {
    const el = ref.current
    const firstKey = items.length ? itemKey(items[0]) : null
    if (anchor && el && prevFirst.current && firstKey !== prevFirst.current && el.scrollTop > 0) {
      const idx = items.findIndex(it => itemKey(it) === prevFirst.current)
      if (idx > 0) el.scrollTop += offsets[idx]
    }
    prevFirst.current = firstKey
  }, [items, itemKey, offsets, anchor, ref])

  useEffect(() => {
    const el = ref.current
    if (!el || scrollToIndex == null || scrollToIndex < 0 || scrollToIndex >= items.length) return
    const top = offsets[scrollToIndex], bot = offsets[scrollToIndex + 1]
    // keep the row clear of a sticky group head (32px)
    if (top < el.scrollTop + 32 && scrollToIndex > 0) el.scrollTop = Math.max(0, top - 32)
    else if (top < el.scrollTop) el.scrollTop = top
    else if (bot > el.scrollTop + el.clientHeight) el.scrollTop = bot - el.clientHeight
  }, [scrollToIndex]) // eslint-disable-line react-hooks/exhaustive-deps

  const rows: ReactNode[] = []
  for (let i = range[0]; i < Math.min(range[1], items.length); i++) {
    rows.push(render(items[i], i, { position: 'absolute', top: offsets[i], left: 0, right: 0, height: offsets[i + 1] - offsets[i] }))
  }
  return <div ref={ref} className={cn(RW.list, className)} tabIndex={-1}>
    {items.length ? <div className="relative w-full" style={{ height: total }}>{rows}</div> : empty}
    {footer}
  </div>
}

// ---------------------------------------------------------------- tooltip

export interface TipHandle { show: (content: ReactNode, x: number, y: number) => void; move: (x: number, y: number) => void; hide: () => void }

/** Cursor tooltip. Imperative so hovering a big table doesn't re-render it. */
export const Tip = forwardRef<TipHandle>(function Tip(_, ref) {
  const [content, setContent] = useState<ReactNode>(null)
  const [on, setOn] = useState(false)
  const el = useRef<HTMLDivElement>(null)
  const pos = useRef({ x: 0, y: 0 })
  const place = () => {
    const t = el.current
    if (!t) return
    const { x, y } = pos.current
    const w = t.offsetWidth, h = t.offsetHeight
    t.style.left = Math.min(window.innerWidth - w - 8, x + 14) + 'px'
    t.style.top = (y + 18 + h > window.innerHeight ? y - h - 10 : y + 18) + 'px'
  }
  useImperativeHandle(ref, () => ({
    show: (c, x, y) => { pos.current = { x, y }; setContent(c); setOn(true) },
    move: (x, y) => { pos.current = { x, y }; place() },
    hide: () => setOn(false),
  }), [])
  useLayoutEffect(place, [content, on])
  return <div
    ref={el}
    className={cn(
      'pointer-events-none fixed z-[80] max-w-[300px] rounded-[7px] bg-raise px-[9px] py-[7px] text-[12px] leading-[17px] text-fg-muted shadow-popover transition-[opacity,transform] duration-[var(--d1)] [&_b]:font-medium [&_b]:text-fg',
      on ? 'translate-y-0 opacity-100' : 'translate-y-0.5 opacity-0',
    )}
    role="tooltip"
    aria-hidden={!on}
  >
    {content}
  </div>
})

/** Debounced value (server search). */
export function useDebounced<T>(value: T, ms: number) {
  const [v, setV] = useState(value)
  useEffect(() => { const t = setTimeout(() => setV(value), ms); return () => clearTimeout(t) }, [value, ms])
  return v
}
