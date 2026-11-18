import { Input as InputPrimitive } from '@base-ui/react/input'
import type { ComponentProps } from 'react'

export function Input(props: ComponentProps<'input'>) {
  return <InputPrimitive data-slot="input" {...props} />
}

export function Textarea(props: ComponentProps<'textarea'>) {
  return <textarea data-slot="textarea" {...props} />
}

export function NativeSelect(props: ComponentProps<'select'>) {
  return <select data-slot="native-select" {...props} />
}
