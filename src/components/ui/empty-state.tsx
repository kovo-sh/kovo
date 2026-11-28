import type { ReactNode } from 'react'
import { StatePanel } from './state-panel.tsx'

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
 * single CTA. A thin `StatePanel` (kind `empty`, section layout) that keeps the
 * historical `empty-state*` data slots callers style against.
 */
export function EmptyState({ icon, title, description, action, className, children }: EmptyStateProps) {
  return (
    <StatePanel
      kind="empty"
      variant="section"
      slot="empty-state"
      icon={icon ?? null}
      title={title}
      description={description}
      action={action}
      className={className}
    >
      {children}
    </StatePanel>
  )
}
