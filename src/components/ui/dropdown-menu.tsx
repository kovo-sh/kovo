import { Menu as MenuPrimitive } from '@base-ui/react/menu'
import { cn } from '../../lib/cn.ts'

export const DropdownMenu = MenuPrimitive.Root
export const DropdownMenuGroup = MenuPrimitive.Group
export const DropdownMenuRadioGroup = MenuPrimitive.RadioGroup
export const DropdownMenuSubmenu = MenuPrimitive.SubmenuRoot

export function DropdownMenuTrigger({ className, ...props }: MenuPrimitive.Trigger.Props) {
  return <MenuPrimitive.Trigger data-slot="dropdown-menu-trigger" className={className} {...props} />
}

export function DropdownMenuContent({ align = 'end', className, ...props }: MenuPrimitive.Popup.Props & {
  align?: MenuPrimitive.Positioner.Props['align']
}) {
  return (
    <MenuPrimitive.Portal>
      <MenuPrimitive.Positioner
        data-slot="dropdown-menu-positioner"
        className="z-[60]"
        align={align}
        sideOffset={5}
      >
        <MenuPrimitive.Popup
          data-slot="dropdown-menu-content"
          className={cn(
            'max-h-[var(--available-height)] min-w-[170px] overflow-auto rounded-card bg-raise p-1 text-fg shadow-popover outline-none',
            'transition-[opacity,transform] duration-150 ease-kovo',
            'data-[ending-style]:scale-[.98] data-[ending-style]:opacity-0',
            'data-[starting-style]:scale-[.98] data-[starting-style]:opacity-0',
            className,
          )}
          {...props}
        />
      </MenuPrimitive.Positioner>
    </MenuPrimitive.Portal>
  )
}

export function DropdownMenuItem({ variant = 'default', className, ...props }: MenuPrimitive.Item.Props & {
  variant?: 'default' | 'destructive'
}) {
  return (
    <MenuPrimitive.Item
      data-slot="dropdown-menu-item"
      data-variant={variant}
      className={cn(
        'flex cursor-pointer select-none items-center justify-between gap-4 rounded-control px-[9px] py-1.5 font-sans text-[12.5px] text-fg outline-none',
        'data-[highlighted]:bg-hover data-[disabled]:cursor-default data-[disabled]:opacity-50 data-[variant=destructive]:text-danger',
        className,
      )}
      {...props}
    />
  )
}

export function DropdownMenuLabel({ className, ...props }: MenuPrimitive.GroupLabel.Props) {
  return (
    <MenuPrimitive.GroupLabel
      data-slot="dropdown-menu-label"
      className={cn('px-2 pb-[3px] pt-[5px] text-[11px] font-medium text-fg-subtle', className)}
      {...props}
    />
  )
}

export function DropdownMenuSeparator({ className, ...props }: MenuPrimitive.Separator.Props) {
  return <MenuPrimitive.Separator data-slot="dropdown-menu-separator" className={cn('my-1 h-px bg-line', className)} {...props} />
}

export function DropdownMenuRadioItem({ children, className, ...props }: MenuPrimitive.RadioItem.Props) {
  return (
    <MenuPrimitive.RadioItem
      data-slot="dropdown-menu-radio-item"
      className={cn(
        'flex cursor-pointer select-none items-center justify-between gap-4 rounded-control px-[9px] py-1.5 font-sans text-[12.5px] text-fg outline-none',
        'data-[highlighted]:bg-hover data-[disabled]:cursor-default data-[disabled]:opacity-50',
        className,
      )}
      closeOnClick
      {...props}
    >
      {children}
      <MenuPrimitive.RadioItemIndicator data-slot="dropdown-menu-radio-item-indicator" aria-hidden="true">✓</MenuPrimitive.RadioItemIndicator>
    </MenuPrimitive.RadioItem>
  )
}
