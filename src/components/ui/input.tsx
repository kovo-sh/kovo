import { Input as InputPrimitive } from '@base-ui/react/input'
import type { ComponentProps } from 'react'
import { cn } from '../../lib/cn.ts'

/**
 * Text input. Visual styling still comes from the legacy
 * `input:not([type=checkbox]):not([type=range])` rule in app.css (higher
 * specificity than any utility), so existing routes are untouched; new
 * routes can layer `className` utilities on top.
 */
export function Input({ className, ...props }: ComponentProps<'input'>) {
  return <InputPrimitive data-slot="input" className={cn('min-w-0', className)} {...props} />
}

export function Textarea({ className, ...props }: ComponentProps<'textarea'>) {
  return <textarea data-slot="textarea" className={cn('min-w-0', className)} {...props} />
}

export function NativeSelect({ className, ...props }: ComponentProps<'select'>) {
  return <select data-slot="native-select" className={className} {...props} />
}
