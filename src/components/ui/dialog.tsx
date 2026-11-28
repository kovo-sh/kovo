import { Dialog as DialogPrimitive } from '@base-ui/react/dialog'
import type { ComponentProps } from 'react'
import { cn } from '../../lib/cn.ts'

export type DialogProps = DialogPrimitive.Root.Props & {
  /**
   * When false, an Escape key press cannot dismiss the dialog (for example
   * while a destructive mutation is in flight). Base UI reports the reason on
   * `onOpenChange`, so the guard cancels only the escape-key path and still
   * allows close-button / outside-press dismissal.
   */
  closeOnEscape?: boolean
}

/** Accessible modal root over @base-ui/react Dialog. */
export function Dialog({ closeOnEscape = true, onOpenChange, ...props }: DialogProps) {
  return (
    <DialogPrimitive.Root
      {...props}
      onOpenChange={(open, details) => {
        if (!open && !closeOnEscape && details.reason === 'escape-key') {
          details.cancel()
          return
        }
        onOpenChange?.(open, details)
      }}
    />
  )
}

export const DialogTrigger = DialogPrimitive.Trigger
export const DialogClose = DialogPrimitive.Close

export function DialogTitle({ className, ...props }: DialogPrimitive.Title.Props) {
  return (
    <DialogPrimitive.Title
      data-slot="dialog-title"
      className={cn('text-[14px] font-semibold tracking-[-0.012em] text-fg', className)}
      {...props}
    />
  )
}

export function DialogDescription({ className, ...props }: DialogPrimitive.Description.Props) {
  return (
    <DialogPrimitive.Description
      data-slot="dialog-description"
      className={cn('text-[12px] leading-5 text-fg-muted', className)}
      {...props}
    />
  )
}

export type DialogContentProps = DialogPrimitive.Popup.Props & {
  /**
   * Skip the enter/exit transition entirely. Use for keyboard-triggered,
   * many-times-a-day surfaces (⌘K palette, `?` shortcut sheet) that must be
   * fully opaque on their first frame. Pointer-opened occasional modals keep
   * the default 150ms fade + scale.
   */
  instant?: boolean
}

// Enter: 150ms ease-kovo fade (+ .98 scale on the popup). Exit is shorter
// (100ms) so dismissal feels immediate. Origin stays centred for modals.
const BACKDROP_MOTION =
  'transition-opacity duration-150 ease-kovo data-[ending-style]:duration-100 data-[ending-style]:opacity-0 data-[starting-style]:opacity-0'
const POPUP_MOTION = [
  'transition-[opacity,scale] duration-150 ease-kovo data-[ending-style]:duration-100',
  'data-[ending-style]:scale-[.98] data-[ending-style]:opacity-0',
  'data-[starting-style]:scale-[.98] data-[starting-style]:opacity-0',
].join(' ')
const NO_MOTION = 'transition-none duration-0'

/**
 * Portal-rendered content: a single-border panel over a soft scrim, centred in
 * a scrollable viewport. Focus is trapped and restored by Base UI.
 */
export function DialogContent({ className, children, instant = false, ...props }: DialogContentProps) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Backdrop
        data-slot="dialog-backdrop"
        className={cn('fixed inset-0 z-[60] bg-scrim', instant ? NO_MOTION : BACKDROP_MOTION)}
      />
      <DialogPrimitive.Viewport
        data-slot="dialog-viewport"
        className="fixed inset-0 z-[60] flex items-center justify-center overflow-y-auto p-4"
      >
        <DialogPrimitive.Popup
          data-slot="dialog-content"
          className={cn(
            'w-full max-w-[520px] rounded-card border border-line-2 bg-panel text-fg shadow-popover outline-none',
            instant ? NO_MOTION : POPUP_MOTION,
            className,
          )}
          {...props}
        >
          {children}
        </DialogPrimitive.Popup>
      </DialogPrimitive.Viewport>
    </DialogPrimitive.Portal>
  )
}

export function DialogHeader({ className, ...props }: ComponentProps<'div'>) {
  return <div data-slot="dialog-header" className={cn('flex flex-col gap-1 px-4 pb-2 pt-4', className)} {...props} />
}

export function DialogBody({ className, ...props }: ComponentProps<'div'>) {
  return <div data-slot="dialog-body" className={cn('px-4 py-2 text-[12.5px] text-fg-muted', className)} {...props} />
}

export function DialogFooter({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      data-slot="dialog-footer"
      className={cn('flex items-center justify-end gap-2 border-t border-line bg-sunk px-4 py-2.5', className)}
      {...props}
    />
  )
}
