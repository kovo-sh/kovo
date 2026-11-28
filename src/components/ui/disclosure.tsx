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
        // Full-width row: press feedback comes from the fill, not a shrink.
        'transition-colors duration-[var(--d1)] ease-kovo hover:bg-hover active:scale-100',
        className,
      )}
      {...props}
    >
      {children}
      <svg
        data-slot="disclosure-chevron"
        className="ms-auto size-3 flex-none text-fg-subtle transition-[rotate] duration-150 ease-kovo group-data-[panel-open]:rotate-180"
        viewBox="0 0 12 12"
        fill="none"
        aria-hidden="true"
      >
        <path d="m2.5 4.5 3.5 3.5 3.5-3.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </CollapsiblePrimitive.Trigger>
  )
}

// Base UI measures the panel into --collapsible-panel-height, so the height
// animates once to a measured value (occasional, few children) together with
// an opacity fade. Under reduced motion the height snaps and opacity still fades.
// `overflow: clip` + a 4px clip margin hides the content while the height
// grows but never cuts the focus rings of fields that sit flush to the edge.
const PANEL_MOTION = [
  'overflow-clip [overflow-clip-margin:4px] h-[var(--collapsible-panel-height)] transition-[height,opacity] duration-[var(--d2)] ease-kovo',
  'data-[starting-style]:h-0 data-[ending-style]:h-0 data-[starting-style]:opacity-0 data-[ending-style]:opacity-0',
].join(' ')

/** Region revealed by the trigger. Hidden/collapsed state is handled by Base UI. */
export function DisclosureContent({ className, ...props }: CollapsiblePrimitive.Panel.Props) {
  return (
    <CollapsiblePrimitive.Panel
      data-slot="disclosure-content"
      className={cn(PANEL_MOTION, 'pt-1.5 text-[12.5px] text-fg-muted', className)}
      {...props}
    />
  )
}

/** Convenience alias used by the legacy "Advanced configuration" summary. */
export const AdvancedDisclosure = Disclosure
export const AdvancedDisclosureTrigger = DisclosureTrigger
export const AdvancedDisclosureContent = DisclosureContent
