import { Collapsible as CollapsiblePrimitive } from '@base-ui/react/collapsible'
import { cn } from '../../lib/cn.ts'

export type DisclosureProps = CollapsiblePrimitive.Root.Props

/** Accessible collapsible disclosure root (uncontrolled by default). */
export function Disclosure({ ...props }: DisclosureProps) {
  return <CollapsiblePrimitive.Root data-slot="disclosure" {...props} />
}

/**
 * Disclosure trigger — renders a real button with aria-expanded / aria-controls
 * wired by Base UI, plus a chevron that flips when the panel is open.
 */
export function DisclosureTrigger({ className, children, ...props }: CollapsiblePrimitive.Trigger.Props) {
  return (
    <CollapsiblePrimitive.Trigger
      data-slot="disclosure-trigger"
      className={cn(
        'group flex h-auto w-full cursor-pointer items-center gap-2 rounded-control border-0 bg-transparent px-2 py-1.5 text-left font-sans text-[12.5px] font-medium text-fg shadow-none',
        'transition-colors duration-[var(--d1)] ease-guardian hover:bg-hover',
        className,
      )}
      {...props}
    >
      {children}
      <svg
        data-slot="disclosure-chevron"
        className="ms-auto size-3 flex-none text-fg-subtle transition-transform duration-150 ease-guardian group-data-[panel-open]:rotate-180"
        viewBox="0 0 12 12"
        fill="none"
        aria-hidden="true"
      >
        <path d="m2.5 4.5 3.5 3.5 3.5-3.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </CollapsiblePrimitive.Trigger>
  )
}

/** Region revealed by the trigger. Hidden/collapsed state is handled by Base UI. */
export function DisclosureContent({ className, ...props }: CollapsiblePrimitive.Panel.Props) {
  return (
    <CollapsiblePrimitive.Panel
      data-slot="disclosure-content"
      className={cn('pt-1.5 text-[12.5px] text-fg-muted', className)}
      {...props}
    />
  )
}

/** Convenience alias used by the legacy "Advanced configuration" summary. */
export const AdvancedDisclosure = Disclosure
export const AdvancedDisclosureTrigger = DisclosureTrigger
export const AdvancedDisclosureContent = DisclosureContent
