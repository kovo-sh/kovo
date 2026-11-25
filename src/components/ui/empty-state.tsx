import type { ReactNode } from 'react'
import { cn } from '../../lib/cn.ts'

export type EmptyStateProps = {
  /** Optional SVG (or any node) rendered above the title. */
  icon?: ReactNode
  title: ReactNode
  description?: ReactNode
  /** Exactly one call-to-action is expected; pass a Button/Link. */
  action?: ReactNode
  className?: string
  children?: ReactNode
}

/**
 * Canonical empty state: optional icon slot, title, short description, and a
 * single CTA. Constrained width keeps long descriptions readable on wide pages.
 */
export function EmptyState({ icon, title, description, action, className, children }: EmptyStateProps) {
  return (
    <div
      data-slot="empty-state"
      className={cn('mx-auto flex w-full max-w-[360px] flex-col items-center gap-3 px-6 py-10 text-center', className)}
    >
      {icon ? (
        <div data-slot="empty-state-icon" className="flex size-8 flex-none items-center justify-center text-fg-faint [&>svg]:size-7">
          {icon}
        </div>
      ) : null}
      <div className="flex flex-col gap-1">
        <h3 data-slot="empty-state-title" className="text-[13px] font-medium leading-5 text-fg">{title}</h3>
        {description ? (
          <p data-slot="empty-state-description" className="text-[12px] leading-5 text-fg-subtle text-balance">
            {description}
          </p>
        ) : null}
      </div>
      {children}
      {action ? <div data-slot="empty-state-action" className="mt-1 flex items-center justify-center gap-2">{action}</div> : null}
    </div>
  )
}
