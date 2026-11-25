import { Button as ButtonPrimitive } from '@base-ui/react/button'
import { cn } from '../../lib/cn.ts'
import { buttonVariants, type ButtonVariantProps } from './variants.ts'

export { buttonVariants }
export type { ButtonVariantProps }

export type ButtonProps = ButtonPrimitive.Props & ButtonVariantProps

/**
 * Canonical button primitive.
 *
 * Backward compatible with the previous `data-slot`/`data-variant`/`data-size`
 * contract: legacy app.css rules keyed on those attributes keep working, and
 * the cva utilities mirror the same metrics for newly migrated routes.
 */
export function Button({ variant = 'outline', size = 'default', className, ...props }: ButtonProps) {
  return (
    <ButtonPrimitive
      data-slot="button"
      data-variant={variant}
      data-size={size}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  )
}
