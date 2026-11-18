import { Menu as MenuPrimitive } from '@base-ui/react/menu'

export const DropdownMenu = MenuPrimitive.Root
export const DropdownMenuGroup = MenuPrimitive.Group
export const DropdownMenuRadioGroup = MenuPrimitive.RadioGroup

export function DropdownMenuTrigger(props: MenuPrimitive.Trigger.Props) {
  return <MenuPrimitive.Trigger data-slot="dropdown-menu-trigger" {...props} />
}

export function DropdownMenuContent({ align = 'end', ...props }: MenuPrimitive.Popup.Props & {
  align?: MenuPrimitive.Positioner.Props['align']
}) {
  return <MenuPrimitive.Portal>
    <MenuPrimitive.Positioner data-slot="dropdown-menu-positioner" align={align} sideOffset={5}>
      <MenuPrimitive.Popup data-slot="dropdown-menu-content" {...props} />
    </MenuPrimitive.Positioner>
  </MenuPrimitive.Portal>
}

export function DropdownMenuItem({ variant = 'default', ...props }: MenuPrimitive.Item.Props & {
  variant?: 'default' | 'destructive'
}) {
  return <MenuPrimitive.Item data-slot="dropdown-menu-item" data-variant={variant} {...props} />
}

export function DropdownMenuLabel(props: MenuPrimitive.GroupLabel.Props) {
  return <MenuPrimitive.GroupLabel data-slot="dropdown-menu-label" {...props} />
}

export function DropdownMenuRadioItem({ children, ...props }: MenuPrimitive.RadioItem.Props) {
  return <MenuPrimitive.RadioItem data-slot="dropdown-menu-radio-item" closeOnClick {...props}>
    {children}
    <MenuPrimitive.RadioItemIndicator aria-hidden="true">✓</MenuPrimitive.RadioItemIndicator>
  </MenuPrimitive.RadioItem>
}
