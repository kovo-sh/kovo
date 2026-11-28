// Shared Tailwind CSS v4 + cva primitives for the Run Investigation Workspace.
// Every token resolves via src/styles/tailwind.css -> src/styles/tokens.css so
// both light and dark themes stay 1:1 with the rest of the app.
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '../../lib/cn.ts'

export { cn }

/**
 * Run workspace button variants. Explicitly resets app.css bare `button`
 * (`background: var(--raise)`, `box-shadow: var(--shadow-sm)`, `button:hover`)
 * so ghost / link / primary / ink buttons never inherit legacy chrome.
 */
export const runBtn = cva(
  'inline-flex cursor-pointer items-center justify-center whitespace-nowrap border-0 font-sans font-medium transition-[background-color,color,box-shadow,scale,filter] duration-[var(--d1)] ease-kovo active:scale-[.98] disabled:cursor-default disabled:opacity-50 disabled:active:scale-100',
  {
    variants: {
      variant: {
        default: 'bg-raise text-fg shadow-hairline hover:bg-sunk',
        primary: 'bg-accent text-accent-fg shadow-none hover:bg-accent hover:brightness-[1.06]',
        ink: 'bg-fg text-panel shadow-none hover:bg-fg hover:brightness-[1.15]',
        ghost: 'bg-transparent text-fg-muted shadow-none hover:bg-hover hover:text-fg',
        ghostOn: 'bg-press text-fg shadow-none hover:bg-press hover:text-fg',
        dangerSolid: 'bg-danger text-white shadow-none hover:bg-danger hover:brightness-[1.08]',
        link: 'h-auto bg-transparent p-0 font-normal text-fg-subtle shadow-none hover:bg-transparent hover:text-fg active:scale-100',
      },
      size: {
        default: 'h-[26px] gap-1.5 rounded-control px-[9px] text-[12.5px]',
        sm: 'h-6 gap-1.5 rounded-[5px] px-[7px] text-[12px]',
        xs: 'h-[22px] gap-1 rounded-[5px] px-2 text-[12px]',
        icon: 'h-7 min-w-7 gap-1.5 rounded-control px-[7px] text-[12.5px]',
        iconSm: 'h-6 min-w-6 gap-1 rounded-control px-[5px] text-[12px]',
        iconXs: 'h-[22px] min-w-[22px] gap-1 rounded-control px-1 text-[12px]',
        none: 'gap-1 text-[12px]',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  },
)

export type RunBtnProps = VariantProps<typeof runBtn>

/** Toolbar icon button (ghost, quiet muted color, 28px square by default). */
export const runIconBtn = cva(
  'inline-flex cursor-pointer items-center justify-center gap-1.5 whitespace-nowrap rounded-control border-0 bg-transparent font-sans font-normal text-fg-subtle shadow-none transition-[background-color,color] duration-[var(--d1)] ease-kovo hover:bg-hover hover:text-fg disabled:cursor-default disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-fg-subtle',
  {
    variants: {
      size: {
        default: 'h-7 min-w-7 px-[7px] text-[12.5px]',
        sm: 'h-6 min-w-6 px-[5px] text-[12px]',
        xs: 'h-[22px] min-w-[22px] px-1 text-[11.5px]',
      },
      tone: {
        default: '',
        ok: 'hover:bg-ok-soft hover:text-ok',
        danger: 'hover:bg-danger-soft hover:text-danger',
      },
    },
    defaultVariants: {
      size: 'default',
      tone: 'default',
    },
  },
)

/** Dropdown / popover menu item. */
export const runDdItem = cva(
  'flex h-[30px] w-full cursor-pointer items-center gap-2 whitespace-nowrap rounded-control border-0 bg-transparent px-2 text-left font-sans text-[12.5px] font-normal shadow-none transition-[background-color,color] duration-[var(--d1)] ease-kovo hover:bg-hover hover:text-fg disabled:cursor-default disabled:opacity-45 disabled:hover:bg-transparent',
  {
    variants: {
      active: {
        true: 'bg-press text-fg hover:bg-press',
        false: 'text-fg-muted',
      },
      danger: {
        true: 'text-danger hover:text-danger',
        false: '',
      },
    },
    defaultVariants: {
      active: false,
      danger: false,
    },
  },
)

/** Stamp / verdict badge used in queue rows and inspector action bar. */
export const runStamp = cva(
  'inline-flex items-center gap-1.5 rounded-[5px] border px-[9px] text-[12px] font-semibold',
  {
    variants: {
      tone: {
        ok: 'border-ok/35 bg-ok-soft text-ok',
        no: 'border-line-strong bg-sunk text-fg-muted',
        fp: 'border-danger/35 bg-danger-soft text-danger',
        acc: 'border-accent-line bg-accent-soft text-accent',
      },
    },
    defaultVariants: {
      tone: 'no',
    },
  },
)

/** Decision inline label (`dec ok | fp | acc`). */
export const runDec = cva('inline-flex items-center gap-[5px] text-[11.5px]', {
  variants: {
    tone: {
      default: 'text-fg-subtle',
      ok: 'text-ok',
      fp: 'text-danger',
      acc: 'text-accent',
    },
  },
  defaultVariants: {
    tone: 'default',
  },
})

/** Standard Run workspace layout & surface classes. */
export const RW = {
  toolbar: 'flex h-[42px] flex-none min-w-0 items-center gap-1.5 border-b border-line pl-[18px] pr-3',
  list: 'relative min-h-0 flex-1 overflow-auto outline-none',
  ghead: 'sticky top-0 z-[2] flex h-8 cursor-pointer select-none items-center gap-2 border-b border-line bg-sunk px-[18px] text-[12.5px] font-medium text-fg-muted',
  row: 'relative flex h-9 cursor-default scroll-mt-[34px] scroll-mb-1 items-center gap-2.5 border-b border-line border-l-2 border-l-transparent pl-4 pr-[18px] [contain-intrinsic-size:auto_36px] [content-visibility:auto] hover:bg-hover',
  rowCur: 'bg-sel border-l-sel-line hover:bg-sel',
  listnote: 'flex items-center gap-2 px-[18px] pb-10 pt-3.5 text-[12px] text-fg-subtle',
  strip: 'flex flex-none items-center gap-4 overflow-hidden whitespace-nowrap border-b border-line px-[18px] py-2.5 text-[12px] text-fg-muted',
  detail: 'px-[18px] pb-10 pt-4',
  pre: 'm-0 mb-2.5 max-h-[320px] overflow-auto whitespace-pre-wrap [overflow-wrap:anywhere] rounded-lg border border-line bg-sunk px-3 py-2.5 font-mono text-[12px] leading-[18px] text-fg-muted',
  hdrs: 'mb-3 w-full border-collapse',
  cmp: 'mb-2.5 overflow-hidden rounded-lg border border-line',
  olist: '-mt-0.5 mb-2.5 overflow-hidden rounded-lg border border-line',
  sheet: 'overflow-hidden rounded-card border border-line bg-panel',
  sheetH: 'flex items-center gap-2.5 border-b border-line px-4 py-[11px] font-medium text-fg',
  sheetF: 'flex items-center gap-2 border-t border-line bg-sunk px-4 py-[11px]',
  fieldInput: 'h-7 min-w-0 rounded-control border-0 bg-panel px-[9px] text-[12.5px] text-fg shadow-hairline outline-none transition-shadow duration-[var(--d1)] focus:shadow-[0_0_0_1px_var(--accent-line),0_0_0_3px_var(--accent-soft)]',
  fieldTextarea: 'h-auto min-w-0 resize-y rounded-control border-0 bg-panel px-[9px] py-[7px] text-[12.5px] leading-[19px] text-fg shadow-hairline outline-none transition-shadow duration-[var(--d1)] focus:shadow-[0_0_0_1px_var(--accent-line),0_0_0_3px_var(--accent-soft)]',
  rawInput: 'h-full! min-w-0 flex-1 rounded-none! border-0! bg-transparent! p-0! text-[12.5px] text-fg shadow-none! outline-none! placeholder:text-fg-subtle focus:shadow-none!',
  ddMenu: 'absolute right-0 top-8 z-20 w-[300px] origin-top-right rounded-card bg-raise px-2.5 pb-3 pt-1.5 shadow-[0_0_0_1px_var(--line-2),var(--shadow-pop)]',
  ddSec: 'flex items-center px-0.5 pb-1.5 pt-2 text-[11.5px] font-medium text-fg-subtle',
  menuSep: 'my-[5px] mx-0.5 h-px bg-line',
  chip: 'inline-flex h-6 cursor-pointer items-center gap-1.5 rounded-control border-0 bg-transparent px-2 text-[12px] font-normal text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)] transition-[background-color,color] duration-[var(--d1)] hover:bg-hover hover:text-fg',
  chipOn: 'bg-press text-fg shadow-[inset_0_0_0_1px_var(--line-strong)] hover:bg-press',
} as const

/** HTTP status code color (2xx/3xx quiet, 4xx ink, 5xx danger). */
export function httpCodeClass(status: number | null | undefined): string {
  const first = String(status ?? 0)[0]
  if (first === '5') return 'text-danger'
  if (first === '4') return 'text-fg'
  return 'text-fg-subtle'
}

/** Coverage status tile colors (surface matrix cells, swatches, pills) — light & dark aware. */
export function covTileClass(status: string, opts?: { borderless?: boolean }): string {
  const b = opts?.borderless ? 'border-transparent' : ''
  switch (status) {
    case 'reported':
      return cn('bg-[#fbe7dc]/72 border-[#f0c3aa] text-[#c2410c] dark:bg-[#3a1d12]/72 dark:border-[#683420] dark:text-[#ff8a5b]', b)
    case 'needs_follow_up':
      return cn('bg-[#fbf0d4]/72 border-[#ecd39a] text-[#a86400] dark:bg-[#30250e]/72 dark:border-[#584219] dark:text-[#e9b04a]', b)
    case 'no_issue_found':
      return cn('bg-[#e7eef7]/68 border-[#c3d5ea] text-[#2e6aa6] dark:bg-[#15263a]/68 dark:border-[#244563] dark:text-[#79aee6]', b)
    case 'ruled_out':
      return cn('bg-[#efefed]/75 border-[#dadad6] text-[#6b7078] dark:bg-[#212325]/75 dark:border-[#36393d] dark:text-[#9a9fa6]', b)
    case 'not_applicable':
      return cn(
        'bg-[#f6f6f4] [background-image:repeating-linear-gradient(135deg,#dddcd6_0_1px,transparent_1px_5px)] border-line text-[#a0a09b]',
        'dark:bg-[#1a1a1a] dark:[background-image:repeating-linear-gradient(135deg,#2b2b2b_0_1px,transparent_1px_5px)] dark:text-[#62666b]',
        b,
      )
    default:
      return 'bg-transparent border-transparent text-[#cfcfca] dark:text-[#3a3a3a]'
  }
}

/** Coverage cell hover/selected border color when tile uses borderless rest state. */
export function covHoverBorderClass(status: string): string {
  switch (status) {
    case 'reported': return 'group-hover/cell:border-[#f0c3aa] dark:group-hover/cell:border-[#683420]'
    case 'needs_follow_up': return 'group-hover/cell:border-[#ecd39a] dark:group-hover/cell:border-[#584219]'
    case 'no_issue_found': return 'group-hover/cell:border-[#c3d5ea] dark:group-hover/cell:border-[#244563]'
    case 'ruled_out': return 'group-hover/cell:border-[#dadad6] dark:group-hover/cell:border-[#36393d]'
    case 'not_applicable': return 'group-hover/cell:border-line-2'
    default: return ''
  }
}

/** Solid bar fill color for coverage status stacks (overview, surface column bars). */
export function covBarBgClass(status: string): string {
  switch (status) {
    case 'reported': return 'bg-[#c2410c] dark:bg-[#ff8a5b]'
    case 'needs_follow_up': return 'bg-[#a86400] dark:bg-[#e9b04a]'
    case 'no_issue_found': return 'bg-[#2e6aa6] dark:bg-[#79aee6]'
    case 'ruled_out': return 'bg-[#6b7078] dark:bg-[#9a9fa6]'
    case 'not_applicable': return 'bg-[#dddcd6] dark:bg-[#2b2b2b]'
    default: return 'bg-line'
  }
}
