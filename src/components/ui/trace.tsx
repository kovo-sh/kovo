import type { ComponentProps } from 'react'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from './collapsible.tsx'

export function Trace(props: ComponentProps<'div'>) {
  return <div data-slot="trace" {...props} />
}

export function TraceLine({ status, ...props }: ComponentProps<'span'> & { status?: 'running' | 'error' | 'pending' }) {
  return <span data-slot="trace-line" data-status={status} {...props} />
}

export function TraceIcon(props: ComponentProps<'span'>) {
  return <span data-slot="trace-icon" aria-hidden="true" {...props} />
}

export function TraceTitle(props: ComponentProps<'span'>) {
  return <span data-slot="trace-title" {...props} />
}

export function TraceCollapsible(props: ComponentProps<typeof Collapsible>) {
  return <Collapsible data-slot="trace-collapsible" {...props} />
}

export function TraceCollapsibleTrigger({ children, ...props }: ComponentProps<typeof CollapsibleTrigger>) {
  return <CollapsibleTrigger data-slot="trace-collapsible-trigger" {...props}>
    {children}
    <TraceIcon className="trace-caret">›</TraceIcon>
  </CollapsibleTrigger>
}

export function TraceCollapsibleContent({ children, ...props }: ComponentProps<typeof CollapsibleContent>) {
  return <CollapsibleContent data-slot="trace-collapsible-content" {...props}>
    <div data-slot="trace-collapsible-content-inner">{children}</div>
  </CollapsibleContent>
}
