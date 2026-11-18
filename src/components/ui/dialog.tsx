import { Dialog as DialogPrimitive } from '@base-ui/react/dialog'

export const Dialog = DialogPrimitive.Root

export function DialogContent(props: DialogPrimitive.Popup.Props) {
  return <DialogPrimitive.Portal>
    <DialogPrimitive.Backdrop data-slot="dialog-overlay" />
    <DialogPrimitive.Popup data-slot="dialog-content" {...props} />
  </DialogPrimitive.Portal>
}

export function DialogTitle(props: DialogPrimitive.Title.Props) {
  return <DialogPrimitive.Title data-slot="dialog-title" {...props} />
}

export function DialogClose(props: DialogPrimitive.Close.Props) {
  return <DialogPrimitive.Close data-slot="dialog-close" {...props} />
}
