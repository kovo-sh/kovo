// Shared display components for the Run workspace (Tailwind CSS v4 + Base UI).
import { Collapsible as CollapsiblePrimitive } from '@base-ui/react/collapsible'
import { cva } from 'class-variance-authority'
import { useEffect, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'
import { modKey } from './format.ts'
import { Icon } from './icons.tsx'
import type { IconName } from './icons.tsx'
import { cn } from './tw.ts'

/** Keyboard key cap. `<Kbd>mod</Kbd>` renders ⌘ on macOS and Ctrl elsewhere. */
export function Kbd({ children, style, className, inverted }: {
  children: ReactNode
  style?: CSSProperties
  className?: string
  inverted?: boolean
}) {
  const [label, setLabel] = useState<ReactNode>(children === 'mod' ? 'Ctrl' : children)
  useEffect(() => { if (children === 'mod') setLabel(modKey()) }, [children])
  return <span
    className={cn(
      'kbd inline-flex h-[17px] min-w-[17px] items-center justify-center rounded-[4px] px-1 font-sans text-[10.5px] font-medium leading-none',
      inverted
        ? 'bg-transparent text-current opacity-65 shadow-[inset_0_0_0_1px_currentColor]'
        : 'bg-[var(--kbd-bg)] text-fg-subtle shadow-[inset_0_0_0_1px_var(--kbd-line),0_1px_0_var(--kbd-line)]',
      className,
    )}
    style={style}
  >
    {label}
  </span>
}

/** A key sequence: `<KbdGroup keys={['mod', 'K']} />`, `<KbdGroup keys={['G', 'then', 'W']} />` */
export function KbdGroup({ keys, style, className }: { keys: string[]; style?: CSSProperties; className?: string }) {
  return <span className={cn('kbd-group inline-flex items-center gap-[3px]', className)} style={style}>
    {keys.map((k, i) => <Kbd key={i}>{k}</Kbd>)}
  </span>
}

const tagVariants = cva(
  'inline-flex h-5 max-w-full items-center gap-[5px] truncate whitespace-nowrap rounded-[10px] px-[7px] text-[11.5px] leading-none',
  {
    variants: {
      tone: {
        default: 'text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)]',
        accent: 'text-accent shadow-[inset_0_0_0_1px_var(--accent-line)]',
        warn: 'bg-warn-soft text-warn shadow-[inset_0_0_0_1px_var(--warn-line)]',
        solid: 'bg-sunk text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)]',
      },
    },
    defaultVariants: {
      tone: 'default',
    },
  },
)

/** Pill-shaped tag/chip. tone: accent (selection), warn (needs attention), solid (sunk bg). */
export function Tag({ children, tone, icon, title, className, mono }: {
  children: ReactNode
  tone?: 'accent' | 'warn' | 'solid'
  icon?: IconName
  title?: string
  className?: string
  mono?: boolean
}) {
  return <span className={cn(tagVariants({ tone: tone ?? 'default' }), mono && 'font-mono text-[11.5px]', className)} title={title}>
    {icon && <Icon name={icon} />}{children}
  </span>
}

/** Centered empty state: icon, title, one-line explanation, optional action. */
export function EmptyState({ icon, title, children, action, style, className }: {
  icon: IconName
  title: string
  children?: ReactNode
  action?: ReactNode
  style?: CSSProperties
  className?: string
}) {
  return <div className={cn('flex flex-1 items-center justify-center p-10 text-fg-subtle', className)} style={style}>
    <div className="flex max-w-[380px] flex-col items-center gap-2 text-center">
      <Icon name={icon} size={20} className="mb-1 text-fg-subtle" />
      <h3 className="m-0 text-[13.5px] font-medium text-fg">{title}</h3>
      {children && <p className="m-0 text-[12.5px] leading-[19px]">{children}</p>}
      {action && <p className="m-0 mt-2">{action}</p>}
    </div>
  </div>
}

/** Loading skeleton rows (pulse shimmer). */
export function Skeleton({ rows = 12 }: { rows?: number }) {
  const widths = [62, 48, 70, 40, 56, 66, 44, 58, 50, 38, 64, 46]
  return <div className="py-2" aria-busy="true" aria-label="Loading">
    {Array.from({ length: rows }, (_, i) => (
      <div key={i} className="relative flex h-9 items-center border-b border-line pl-11 pr-6">
        <span className="block h-2.5 animate-pulse rounded-[5px] bg-line motion-reduce:animate-none" style={{ width: widths[i % widths.length] + '%' }} />
      </div>
    ))}
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
  return <span className={cn('inline-flex min-w-0 max-w-full whitespace-nowrap', className)} title={host}>
    <b className={cn('max-w-full flex-none truncate', quiet ? 'font-inherit text-inherit' : 'font-medium text-fg')}>{lab}</b>
    <span className="min-w-0 truncate text-fg-subtle">{rest}</span>
  </span>
}

/** Clickable cross-link row used in inspectors ("Found by", "On the surface map", …). */
export function LinkRow({ icon, glyph, children, sub, right, trailing = 'ext', onClick, title, className }: {
  icon?: IconName
  glyph?: ReactNode
  children: ReactNode
  sub?: ReactNode
  right?: ReactNode
  trailing?: IconName | null
  onClick?: () => void
  title?: string
  className?: string
}) {
  return <div
    className={cn(
      'flex min-h-[30px] cursor-pointer items-center gap-2 -mx-2 rounded-control px-2 text-[12px] text-fg-muted transition-[background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg',
      sub && 'items-start py-1.5',
      className,
    )}
    role="button"
    tabIndex={0}
    title={title}
    onClick={onClick}
    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick?.() } }}
  >
    {glyph ? <span className={cn('inline-flex size-3.5 flex-none items-center justify-center', sub && 'mt-[3px]')}>{glyph}</span> : icon ? <Icon name={icon} /> : null}
    <span className={cn('min-w-0 flex-1', sub ? 'whitespace-normal' : 'truncate')}>
      {children}
      {sub && <>{' '}<small className="mt-px line-clamp-2 block text-[11.5px] leading-4 text-fg-subtle">{sub}</small></>}
    </span>
    {right != null && <>{' '}<span className="flex-none text-[11.5px] text-fg-subtle">{right}</span></>}
    {trailing && <Icon name={trailing} />}
  </div>
}

/** Segmented control. */
export function Seg<T extends string>({ value, options, onChange, label, title, fullWidth, className }: {
  value: T
  options: { value: T; label: ReactNode; icon?: IconName }[]
  onChange: (v: T) => void
  label?: string
  title?: string
  fullWidth?: boolean
  className?: string
}) {
  return <div
    className={cn(
      'h-[26px] flex-none items-center rounded-control bg-sunk p-0.5 shadow-[inset_0_0_0_1px_var(--line)]',
      fullWidth ? 'flex w-full' : 'inline-flex',
      className,
    )}
    title={title}
    role="radiogroup"
  >
    {label && <span className="pl-[7px] pr-1.5 text-[12px] text-fg-subtle">{label}</span>}
    {options.map(o => {
      const on = o.value === value
      return <button
        key={o.value}
        type="button"
        role="radio"
        aria-checked={on}
        className={cn(
          'inline-flex h-[22px] cursor-pointer items-center justify-center gap-[5px] rounded-[4px] border-0 px-2 text-[12px] font-medium transition-[background-color,color,box-shadow] duration-[var(--d1)]',
          fullWidth && 'flex-1',
          on
            ? 'bg-raise text-fg shadow-[0_0_0_1px_var(--line-2),0_1px_2px_rgba(0,0,0,.05)] hover:bg-raise'
            : 'bg-transparent text-fg-muted shadow-none hover:bg-transparent hover:text-fg',
        )}
        onClick={() => onChange(o.value)}
      >
        {o.icon && <Icon name={o.icon} />}{o.label}
      </button>
    })}
  </div>
}

/** Section block inside an inspector: title row + content. */
export function Section({ title, right, children, className }: {
  title: ReactNode
  right?: ReactNode
  children: ReactNode
  className?: string
}) {
  return <div className={cn('rw-sec border-t border-line pb-0.5 pt-3 [&_p]:m-0 [&_p]:mb-2.5 [&_p]:break-words [&_p]:text-[12.5px] [&_p]:leading-[19px] [&_p]:text-fg-muted', className)}>
    <h4 className="m-0 mb-1.5 flex items-center gap-1.5 text-[11.5px] font-medium text-fg-subtle">
      {title}
      {right != null && <>{' '}<span className="ml-auto font-normal">{right}</span></>}
    </h4>
    {children}
  </div>
}

/** Collapsible progressive-disclosure block built on @base-ui/react Collapsible. */
export function Disclosure({ title, right, defaultOpen = false, children }: {
  title: ReactNode
  right?: ReactNode
  defaultOpen?: boolean
  children: ReactNode
}) {
  return <CollapsiblePrimitive.Root defaultOpen={defaultOpen} className="mt-1 border-t border-line">
    <CollapsiblePrimitive.Trigger
      className="group flex min-h-[34px] w-full cursor-pointer items-center gap-1.5 rounded-none border-0 bg-transparent px-0 py-1.5 text-left text-[12px] font-medium text-fg-muted shadow-none transition-colors duration-[var(--d1)] hover:bg-transparent hover:text-fg"
    >
      <Icon name="chev" className="-rotate-90 text-fg-subtle transition-transform duration-[var(--d2)] ease-guardian group-data-[panel-open]:rotate-0 group-data-[panel-open]:text-fg-muted" />
      <span>{title}</span>
      {right != null && <span className="ml-auto text-[11.5px] font-normal text-fg-subtle">{right}</span>}
    </CollapsiblePrimitive.Trigger>
    <CollapsiblePrimitive.Panel className="pb-2 pt-0.5 [&>.rw-sec:first-child]:border-t-0 [&>.rw-sec:first-child]:pt-1">
      {children}
    </CollapsiblePrimitive.Panel>
  </CollapsiblePrimitive.Root>
}

/** Key/value property grid for inspectors. */
export function Props({ rows, className, wrap }: {
  rows: [ReactNode, ReactNode, (() => void)?][]
  className?: string
  wrap?: boolean
}) {
  return <div className={cn('mb-4 grid grid-cols-[96px_minmax(0,1fr)] gap-y-0.5 text-[12.5px]', className)}>
    {rows.map(([k, v, onClick], i) => <div key={i} className="contents">
      {/* spaces keep keys and values apart in copied text (grid ignores whitespace-only nodes) */}
      <span className="py-1 text-fg-subtle">{k}</span>{' '}
      <span
        className={cn(
          'flex min-w-0 items-center gap-1.5 py-1 text-fg',
          wrap ? 'whitespace-normal' : 'truncate whitespace-nowrap has-[.rw-wrap]:whitespace-normal',
          onClick && 'cursor-pointer hover:[&>span]:underline hover:[&>span]:decoration-fg-faint hover:[&>span]:underline-offset-2',
        )}
        onClick={onClick}
      >
        {v}
      </span>{' '}
    </div>)}
  </div>
}
