// Inline Kovo R2-06 crescent bow-and-arrow brand mark.
// Source geometry: public/brand/kovo-mark-{cobalt,light,dark}.svg & kovo-icon-cobalt.svg.
import type { CSSProperties } from 'react'

export type KovoMarkVariant = 'monochrome' | 'cobalt' | 'icon'

export function KovoMark({
  variant = 'monochrome',
  size = 18,
  className = 'mark',
  style,
  title,
}: {
  variant?: KovoMarkVariant
  size?: number
  className?: string
  style?: CSSProperties
  title?: string
}) {
  const strokeWidth = variant === 'icon' ? 4.3 : 4.6
  const color = variant === 'icon'
    ? '#FFFFFF'
    : variant === 'cobalt'
      ? 'var(--accent, #2F5FDF)'
      : 'currentColor'

  return <svg
    className={className}
    viewBox="0 0 64 64"
    width={size}
    height={size}
    fill="none"
    style={style}
    aria-hidden={title ? undefined : true}
    role={title ? 'img' : undefined}
    aria-label={title}
  >
    {variant === 'icon' && <rect width="64" height="64" rx="14.5" fill="var(--accent, #2F5FDF)" />}
    <path d="M 11.25 24.79 A 19.80 19.80 0 0 1 33.80 22.02" stroke={color} strokeWidth={strokeWidth} strokeLinecap="butt" />
    <path d="M 41.98 30.20 A 19.80 19.80 0 0 1 39.21 52.75" stroke={color} strokeWidth={strokeWidth} strokeLinecap="butt" />
    <path d="M 16.20 47.80 L 48.00 16.00" stroke={color} strokeWidth={strokeWidth} strokeLinecap="butt" />
    <path d="M 38.00 15.20 H 48.80 V 26.00" stroke={color} strokeWidth={strokeWidth} strokeLinecap="square" strokeLinejoin="miter" />
    <path d="M 10.20 47.80 L 14.20 43.80 H 19.60 L 20.20 44.40 V 49.80 L 16.20 53.80 V 47.80 Z" fill={color} />
  </svg>
}
