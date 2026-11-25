// Shared display components. Class names map 1:1 to prototype F (run.css).
import { useEffect, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'
import { modKey } from './format.ts'
import { Icon } from './icons.tsx'
import type { IconName } from './icons.tsx'

/** Keyboard key cap. `<Kbd>mod</Kbd>` renders ⌘ on macOS and Ctrl elsewhere. */
export function Kbd({ children, style }: { children: ReactNode; style?: CSSProperties }) {
  const [label, setLabel] = useState<ReactNode>(children === 'mod' ? 'Ctrl' : children)
  useEffect(() => { if (children === 'mod') setLabel(modKey()) }, [children])
  return <span className="kbd" style={style}>{label}</span>
}
/** A key sequence: `<KbdGroup keys={['mod', 'K']} />`, `<KbdGroup keys={['G', 'then', 'W']} />` */
export function KbdGroup({ keys, style }: { keys: string[]; style?: CSSProperties }) {
  return <span className="kbd-group" style={style}>{keys.map((k, i) => <Kbd key={i}>{k}</Kbd>)}</span>
}
/** Pill-shaped tag/chip. tone: accent (selection), warn (needs attention), solid (sunk bg). */
export function Tag({ children, tone, icon, title, className, mono }: {
  children: ReactNode
  tone?: 'accent' | 'warn' | 'solid'
  icon?: IconName
  title?: string
  className?: string
  mono?: boolean
}) {
  return <span className={'tag' + (tone ? ' ' + tone : '') + (mono ? ' mono' : '') + (className ? ' ' + className : '')} title={title}>
    {icon && <Icon name={icon} />}{children}
  </span>
}

/** Centered empty state (F style): icon, title, one-line explanation, optional action. */
export function EmptyState({ icon, title, children, action, style }: {
  icon: IconName
  title: string
  children?: ReactNode
  action?: ReactNode
  style?: CSSProperties
}) {
  return <div className="empty" style={style}><div className="empty-in">
    <Icon name={icon} />
    <h3>{title}</h3>
    {children && <p>{children}</p>}
    {action && <p style={{ marginTop: 8 }}>{action}</p>}
  </div></div>
}

/** Loading skeleton rows (shimmer), F's `.sk`. */
export function Skeleton({ rows = 12 }: { rows?: number }) {
  const widths = [62, 48, 70, 40, 56, 66, 44, 58, 50, 38, 64, 46]
  return <div className="sk" aria-busy="true" aria-label="Loading">
    {Array.from({ length: rows }, (_, i) => <i key={i} style={{ '--w': widths[i % widths.length] + '%' } as CSSProperties} />)}
  </div>
}

/**
 * Host label with smart truncation: the distinctive label stays bold, the
 * shared apex (e.g. ".dyad.sh") is dimmed and truncates first; very long
 * labels are middle-truncated. Hover shows the full host.
 */
export function HostLabel({ host, apex, max = 20, quiet, className }: {
  host: string
  apex?: string | null
  max?: number
  quiet?: boolean
  className?: string
}) {
  let lab = host
  let rest = ''
  if (apex && host !== apex && host.endsWith('.' + apex)) { lab = host.slice(0, -apex.length - 1); rest = '.' + apex }
  if (lab.length > max) lab = lab.slice(0, Math.ceil(max * 0.55)) + '…' + lab.slice(-Math.floor(max * 0.35))
  return <span className={'hostl' + (quiet ? ' quiet' : '') + (className ? ' ' + className : '')} title={host}><b>{lab}</b><span>{rest}</span></span>
}

/** Clickable cross-link row used in inspectors ("Found by", "On the surface map", …). */
export function LinkRow({ icon, glyph, children, sub, right, trailing = 'ext', onClick, title }: {
  icon?: IconName
  glyph?: ReactNode
  children: ReactNode
  sub?: ReactNode
  right?: ReactNode
  trailing?: IconName | null
  onClick?: () => void
  title?: string
}) {
  return <div className={'linkrow' + (sub ? ' two' : '')} role="button" tabIndex={0} title={title} onClick={onClick}
    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick?.() } }}>
    {glyph ? <span className="g" style={sub ? { marginTop: 3 } : undefined}>{glyph}</span> : icon ? <Icon name={icon} /> : null}
    <span className="p">{children}{sub && <>{' '}<small>{sub}</small></>}</span>
    {right != null && <>{' '}<span className="r">{right}</span></>}
    {trailing && <Icon name={trailing} />}
  </div>
}

/** Segmented control (F's `.seg`). */
export function Seg<T extends string>({ value, options, onChange, label, title }: {
  value: T
  options: { value: T; label: ReactNode; icon?: IconName }[]
  onChange: (v: T) => void
  label?: string
  title?: string
}) {
  return <div className="seg" title={title} role="radiogroup">
    {label && <span className="seg-l">{label}</span>}
    {options.map(o => <button key={o.value} type="button" role="radio" aria-checked={o.value === value} className={o.value === value ? 'on' : ''} onClick={() => onChange(o.value)}>
      {o.icon && <Icon name={o.icon} />}{o.label}
    </button>)}
  </div>
}

/** Section block inside an inspector: title row + content (F's `.sec`). */
export function Section({ title, right, children }: { title: ReactNode; right?: ReactNode; children: ReactNode }) {
  return <div className="sec"><h4>{title}{right != null && <>{' '}<span className="r">{right}</span></>}</h4>{children}</div>
}

/** Collapsible progressive-disclosure block (`.disc`). */
export function Disclosure({ title, right, defaultOpen = false, children }: {
  title: ReactNode
  right?: ReactNode
  defaultOpen?: boolean
  children: ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  return <div className={'disc' + (open ? ' open' : '')}>
    <button type="button" className="disc-h" aria-expanded={open} onClick={() => setOpen(o => !o)}>
      <Icon name="chev" />
      <span>{title}</span>
      {right != null && <span className="r">{right}</span>}
    </button>
    {open && <div className="disc-b">{children}</div>}
  </div>
}

/** Key/value property grid for inspectors (F's `.props`). */
export function Props({ rows }: { rows: [ReactNode, ReactNode, (() => void)?][] }) {
  return <div className="props">
    {rows.map(([k, v, onClick], i) => <div key={i} style={{ display: 'contents' }}>
      {/* spaces keep keys and values apart in copied text (grid ignores whitespace-only nodes) */}
      <span className="k">{k}</span>{' '}
      <span className={'v' + (onClick ? ' link' : '')} onClick={onClick}>{v}</span>{' '}
    </div>)}
  </div>
}
