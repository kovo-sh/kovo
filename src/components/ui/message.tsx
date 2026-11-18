import { MessageScroller as MessageScrollerPrimitive } from '@shadcn/react/message-scroller'
import type { ComponentProps } from 'react'

export const MessageScrollerProvider = MessageScrollerPrimitive.Provider

export function MessageScroller(props: ComponentProps<typeof MessageScrollerPrimitive.Root>) {
  return <MessageScrollerPrimitive.Root data-slot="message-scroller" {...props} />
}

export function MessageScrollerViewport(props: ComponentProps<typeof MessageScrollerPrimitive.Viewport>) {
  return <MessageScrollerPrimitive.Viewport data-slot="message-scroller-viewport" {...props} />
}

export function MessageScrollerContent(props: ComponentProps<typeof MessageScrollerPrimitive.Content>) {
  return <MessageScrollerPrimitive.Content data-slot="message-scroller-content" {...props} />
}

export function MessageScrollerItem(props: ComponentProps<typeof MessageScrollerPrimitive.Item>) {
  return <MessageScrollerPrimitive.Item data-slot="message-scroller-item" {...props} />
}

export function MessageScrollerButton(props: ComponentProps<typeof MessageScrollerPrimitive.Button>) {
  return <MessageScrollerPrimitive.Button data-slot="message-scroller-button" behavior="instant" {...props} />
}

export function Message({ align = 'start', ...props }: ComponentProps<'div'> & { align?: 'start' | 'end' }) {
  return <div data-slot="message" data-align={align} {...props} />
}

export function MessageHeader(props: ComponentProps<'div'>) {
  return <div data-slot="message-header" {...props} />
}

export function MessageContent(props: ComponentProps<'div'>) {
  return <div data-slot="message-content" {...props} />
}

export function Bubble({ variant = 'ghost', ...props }: ComponentProps<'div'> & { variant?: 'ghost' | 'muted' }) {
  return <div data-slot="bubble" data-variant={variant} {...props} />
}

export function BubbleContent(props: ComponentProps<'div'>) {
  return <div data-slot="bubble-content" {...props} />
}
