import type { ComponentProps } from 'react'
import { cn } from '../../lib/cn.ts'

/**
 * Flat card surface: one hairline border, panel background, no elevation.
 * Matches the current workspace card look (see .form-card / .panel in the
 * legacy stylesheets) so it can replace them without a visual jump.
 */
export function Card({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      data-slot="card"
      className={cn('rounded-card border border-line-2 bg-panel text-fg', className)}
      {...props}
    />
  )
}

export function CardHeader({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-header"
      className={cn('flex items-start justify-between gap-3 border-b border-line px-4 py-3', className)}
      {...props}
    />
  )
}

export function CardBody({ className, ...props }: ComponentProps<'div'>) {
  return <div data-slot="card-body" className={cn('px-4 py-3', className)} {...props} />
}

export function CardFooter({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-footer"
      className={cn('flex items-center justify-end gap-2 border-t border-line bg-sunk px-4 py-3', className)}
      {...props}
    />
  )
}
