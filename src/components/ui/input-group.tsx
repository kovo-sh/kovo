import type { ComponentProps } from 'react'
import { Button } from './button.tsx'
import { Textarea } from './input.tsx'

export function InputGroup(props: ComponentProps<'div'>) {
  return <div role="group" data-slot="input-group" {...props} />
}

export function InputGroupAddon(props: ComponentProps<'div'>) {
  return <div data-slot="input-group-addon" data-align="inline-end" {...props} />
}

export function InputGroupTextarea(props: ComponentProps<'textarea'>) {
  return <Textarea data-slot="input-group-control" {...props} />
}

export function InputGroupButton(props: ComponentProps<typeof Button>) {
  return <Button size="icon" {...props} />
}
