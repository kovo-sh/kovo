import { Children } from 'react'
import type { ComponentProps, ReactNode } from 'react'
import { cn } from '../../lib/cn.ts'
import { badgeVariants, type BadgeVariantProps } from './variants.ts'

export { badgeVariants }
export type { BadgeVariantProps }

export type BadgeProps = ComponentProps<'span'> & BadgeVariantProps

/** Wrap bare text in a shrinkable span so a long label ends in an ellipsis. */
function wrapTextChildren(children: ReactNode): ReactNode {
  return Children.map(children, child =>
    typeof child === 'string' || typeof child === 'number'
      ? <span data-slot="badge-label" className="min-w-0 truncate">{child}</span>
      : child,
  )
}

/** Plain-text label of a badge, used as its tooltip when the caller gave none. */
function textTitle(children: ReactNode): string | undefined {
  const parts = Children.toArray(children).filter(
    (child): child is string | number => typeof child === 'string' || typeof child === 'number',
  )
  const text = parts.join('').trim()
  return text || undefined
}

/**
 * Canonical status/label chip. Renders a single-border pill that matches the
 * legacy `.tag` metrics without relying on an inset box-shadow ring. Text
 * children truncate with an ellipsis and expose the full label via `title`.
 */
export function Badge({ variant = 'neutral', className, children, title, ...props }: BadgeProps) {
  return (
    <span
      data-slot="badge"
      data-variant={variant}
      className={cn(badgeVariants({ variant }), className)}
      title={title ?? textTitle(children)}
      {...props}
    >
      {wrapTextChildren(children)}
    </span>
  )
}
