import type { ComponentProps } from 'react'
import { cn } from '../../lib/cn.ts'
import { badgeVariants, type BadgeVariantProps } from './variants.ts'

export { badgeVariants }
export type { BadgeVariantProps }

export type BadgeProps = ComponentProps<'span'> & BadgeVariantProps

/**
 * Canonical status/label chip. Renders a single-border pill that matches the
 * legacy `.tag` metrics without relying on an inset box-shadow ring.
 */
export function Badge({ variant = 'neutral', className, ...props }: BadgeProps) {
  return (
    <span
      data-slot="badge"
      data-variant={variant}
      className={cn(badgeVariants({ variant }), className)}
      {...props}
    />
  )
}
