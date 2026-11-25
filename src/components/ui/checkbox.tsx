import { Checkbox as CheckboxPrimitive } from '@base-ui/react/checkbox'
import { cn } from '../../lib/cn.ts'

/**
 * Checkbox. `flex-none` keeps the tick crisp inside flex rows (the legacy grid
 * label rule would otherwise let it stretch); colours and sizing stay with the
 * existing `[data-slot=checkbox]` styles in app.css.
 */
export function Checkbox({ className, ...props }: CheckboxPrimitive.Root.Props) {
  return (
    <CheckboxPrimitive.Root data-slot="checkbox" className={cn('flex-none', className)} {...props}>
      <CheckboxPrimitive.Indicator data-slot="checkbox-indicator">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true">
          <path d="m2.5 6.2 2.2 2.2 4.8-5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  )
}
