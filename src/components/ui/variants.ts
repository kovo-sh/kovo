import { cva, type VariantProps } from 'class-variance-authority'

/**
 * Button variants.
 *
 * The base metrics intentionally mirror the legacy bare `button` rule in
 * app.css (26px tall, 6px radius, 9px inline padding, 12.5px/500 text,
 * raise surface + hairline shadow) so existing routes render pixel-identical
 * while newer routes can rely on the utility classes alone.
 */
export const buttonVariants = cva(
  'inline-flex cursor-pointer items-center justify-center gap-1.5 whitespace-nowrap rounded-control border-0 font-sans text-[12.5px] font-medium text-fg',
  {
    variants: {
      variant: {
        default: 'bg-accent text-accent-fg shadow-none hover:brightness-[1.06]',
        outline: 'bg-raise text-fg shadow-hairline hover:bg-sunk',
        ghost: 'bg-transparent text-fg-muted shadow-none hover:bg-hover hover:text-fg',
      },
      size: {
        default: 'h-[26px] px-[9px]',
        icon: 'inline-grid size-7 place-items-center p-0',
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
 */
export const badgeVariants = cva(
  'inline-flex h-5 max-w-full shrink-0 items-center gap-[5px] truncate rounded-full border px-[7px] text-[11.5px] leading-none',
  {
    variants: {
      variant: {
        neutral: 'border-line-2 bg-transparent text-fg-muted',
        accent: 'border-accent-line bg-accent-soft text-accent',
        ok: 'border-ok/35 bg-ok-soft text-ok',
        warn: 'border-warn-line bg-warn-soft text-warn',
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
