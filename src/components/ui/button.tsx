import { Button as ButtonPrimitive } from '@base-ui/react/button'

type ButtonProps = ButtonPrimitive.Props & {
  variant?: 'default' | 'outline' | 'ghost'
  size?: 'default' | 'icon'
}

export function Button({ variant = 'outline', size = 'default', ...props }: ButtonProps) {
  return <ButtonPrimitive data-slot="button" data-variant={variant} data-size={size} {...props} />
}
