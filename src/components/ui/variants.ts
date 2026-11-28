import { cva, type VariantProps } from 'class-variance-authority'

/**
 * Button variants.
 *
 * The base metrics intentionally mirror the legacy bare `button` rule in
 * app.css (26px tall, 6px radius, 9px inline padding, 12.5px/500 text,
 * raise surface + hairline shadow) so existing routes render pixel-identical
 * while newer routes can rely on the utility classes alone.
 *
 * Press feedback (scale .97, 120ms ease-kovo) is the same curve the bare
 * `button` rule uses; reduced motion drops `scale` from the transition list.
 * On coarse pointers the control grows (36px / 40px icon) and an `after:`
 * pseudo element widens the hit area by 10px per side without changing
 * layout, so every target reaches 44px on phones. Fine pointers get no
 * expander: it would add scrollable overflow and break the desktop
 * `scrollHeight <= clientHeight + 2` geometry invariant.
 */
export const buttonVariants = cva(
  [
    'relative inline-flex cursor-pointer items-center justify-center gap-1.5 whitespace-nowrap rounded-control border-0 font-sans text-[12.5px] font-medium text-fg',
    'transition-[background-color,color,box-shadow,scale] duration-[var(--d1)] ease-kovo active:scale-[.97] disabled:active:scale-100',
    "pointer-coarse:after:absolute pointer-coarse:after:-inset-2.5 pointer-coarse:after:content-['']",
  ].join(' '),
  {
    variants: {
      variant: {
        default: 'bg-accent text-accent-fg shadow-none hover:brightness-[1.06]',
        outline: 'bg-raise text-fg shadow-hairline hover:bg-sunk',
        ghost: 'bg-transparent text-fg-muted shadow-none hover:bg-hover hover:text-fg',
      },
      size: {
        default: 'h-[26px] px-[9px] pointer-coarse:h-9 pointer-coarse:px-3',
        icon: 'inline-grid size-7 place-items-center p-0 pointer-coarse:size-10',
      },
    },
    defaultVariants: {
      variant: 'outline',
      size: 'default',
    },
  },
)

export type ButtonVariantProps = VariantProps<typeof buttonVariants>

/**
 * Badge variants — the `tag` primitive from app.css, expressed as a single
 * border (never an inset shadow ring) so it composes cleanly with cards.
 * Text tones use the text-only `*-text` tokens (AA on their soft fills);
 * truncation happens on the wrapped label span inside <Badge>, because
 * `text-overflow` never reaches the anonymous flex item of a bare string.
 */
export const badgeVariants = cva(
  'inline-flex h-5 max-w-full shrink-0 items-center gap-[5px] overflow-hidden whitespace-nowrap rounded-full border px-[7px] text-[11.5px] leading-none',
  {
    variants: {
      variant: {
        neutral: 'border-line-2 bg-transparent text-fg-muted',
        accent: 'border-accent-line bg-accent-soft text-accent-text',
        ok: 'border-ok/35 bg-ok-soft text-ok-text',
        warn: 'border-warn-line bg-warn-soft text-warn-text',
        danger: 'border-danger/35 bg-danger-soft text-danger',
        outline: 'border-line bg-transparent text-fg',
      },
    },
    defaultVariants: {
      variant: 'neutral',
    },
  },
)

export type BadgeVariantProps = VariantProps<typeof badgeVariants>
