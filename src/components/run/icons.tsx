// One icon family: 16px grid, 1.5 stroke, round caps (from prototype F).
// Markup is static and trusted, so it is injected as inner SVG.
import type { CSSProperties } from 'react'

const P = {
  search: '<circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5 14 14"/>',
  overview: '<path d="M2.75 3.25h10.5M2.75 6.25h10.5M2.75 9.25h6.5M2.75 12.25h4.5"/>',
  queue: '<path d="M2.25 9.25 3.5 3.75A1 1 0 0 1 4.47 3h7.06a1 1 0 0 1 .97.75l1.25 5.5V12a1 1 0 0 1-1 1H3.25a1 1 0 0 1-1-1Z"/><path d="M2.25 9.25H5.5l.75 1.5h3.5l.75-1.5h3.25"/>',
  findings: '<path d="M8 1.75 13.25 4v4c0 3-2.25 5.25-5.25 6.25C5 13.25 2.75 11 2.75 8V4Z"/><path d="M8 5.5v3"/><path d="M8 10.75v.01"/>',
  workflow: '<rect x="1.75" y="2.5" width="4" height="3.5" rx="1"/><rect x="10.25" y="2.5" width="4" height="3.5" rx="1"/><rect x="10.25" y="10" width="4" height="3.5" rx="1"/><path d="M5.75 4.25h4.5M5.75 4.25c2.5 0 2 7.5 4.5 7.5"/>',
  workers: '<circle cx="4" cy="4" r="1.75"/><circle cx="4" cy="12" r="1.75"/><circle cx="12" cy="8" r="1.75"/><path d="M4 5.75v4.5M5.75 4H8a2 2 0 0 1 2 2v.25M5.75 12H8a2 2 0 0 0 2-2v-.25"/>',
  surface: '<rect x="2.25" y="2.25" width="4.5" height="4.5" rx="1"/><rect x="9.25" y="2.25" width="4.5" height="4.5" rx="1"/><rect x="2.25" y="9.25" width="4.5" height="4.5" rx="1"/><rect x="9.25" y="9.25" width="4.5" height="4.5" rx="1"/>',
  exchanges: '<path d="M2.5 5.5h10M10 3l2.5 2.5L10 8"/><path d="M13.5 10.5h-10M6 8l-2.5 2.5L6 13"/>',
  activity: '<path d="M1.75 8h2.5l2-4.5 3.5 9 2-4.5h2.5"/>',
  report: '<path d="M4 1.75h5.25L12.25 4.75v9.5H4Z"/><path d="M9 1.75V5h3.25"/><path d="M6.25 8.25h3.5M6.25 10.75h3.5"/>',
  chat: '<path d="M2.75 3.25h10.5v7.5H7L4.25 13v-2.25h-1.5Z"/>',
  sun: '<circle cx="8" cy="8" r="2.75"/><path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1.06 1.06M11.54 11.54l1.06 1.06M3.4 12.6l1.06-1.06M11.54 4.46l1.06-1.06"/>',
  moon: '<path d="M13.25 9.5A5.5 5.5 0 0 1 6.5 2.75a5.5 5.5 0 1 0 6.75 6.75Z"/>',
  keyboard: '<rect x="1.75" y="4" width="12.5" height="8" rx="1.5"/><path d="M4.5 6.75h.01M7 6.75h.01M9.5 6.75h.01M12 6.75h.01M5 9.5h6"/>',
  close: '<path d="M4 4l8 8M12 4l-8 8"/>',
  chev: '<path d="M4 6l4 4 4-4"/>',
  chevR: '<path d="M6 4l4 4-4 4"/>',
  chevL: '<path d="M10 4 6 8l4 4"/>',
  chevU: '<path d="M4 10l4-4 4 4"/>',
  chevD: '<path d="M4 6l4 4 4-4"/>',
  arrowR: '<path d="M3 8h10M9 4l4 4-4 4"/>',
  arrowL: '<path d="M13 8H3M7 4 3 8l4 4"/>',
  chain: '<path d="M6.5 9.5l3-3"/><path d="M7.25 4.5l1-1a2.47 2.47 0 0 1 3.5 3.5l-1 1M8.75 11.5l-1 1a2.47 2.47 0 0 1-3.5-3.5l1-1"/>',
  arrowUp: '<path d="M8 13V3M4 7l4-4 4 4"/>',
  pause: '<path d="M5.5 3.5v9M10.5 3.5v9"/>',
  play: '<path d="M5 3.25v9.5L12.5 8Z"/>',
  stop: '<rect x="4" y="4" width="8" height="8" rx="1"/>',
  dots: '<path d="M3.5 8h.01M8 8h.01M12.5 8h.01" stroke-width="2.2"/>',
  ext: '<path d="M6 3.5H3.5v9h9V10M9 3.5h3.5V7M12.5 3.5 7 9"/>',
  lock: '<rect x="3.25" y="7" width="9.5" height="6.75" rx="1.25"/><path d="M5.25 7V5a2.75 2.75 0 0 1 5.5 0v2"/>',
  globe: '<circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c1.75 1.75 2.5 3.75 2.5 6S9.75 12.25 8 14C6.25 12.25 5.5 10.25 5.5 8S6.25 3.75 8 2Z"/>',
  sliders: '<path d="M2.5 5h6M11.5 5h2M2.5 11h2M7.5 11h6"/><circle cx="10" cy="5" r="1.5"/><circle cx="6" cy="11" r="1.5"/>',
  check: '<path d="M3.5 8.5 6.5 11.5 12.5 4.5"/>',
  x: '<path d="M4.5 4.5l7 7M11.5 4.5l-7 7"/>',
  archive: '<rect x="2" y="3" width="12" height="3" rx=".75"/><path d="M3 6v6.25a.75.75 0 0 0 .75.75h8.5a.75.75 0 0 0 .75-.75V6M6.5 8.75h3"/>',
  slash: '<circle cx="8" cy="8" r="5.75"/><path d="M4 12 12 4"/>',
  follow: '<path d="M3 13V3M3 3.5h8.5l-1.75 2.75 1.75 2.75H3"/>',
  shield: '<path d="M8 1.75 13.25 4v4c0 3-2.25 5.25-5.25 6.25C5 13.25 2.75 11 2.75 8V4Z"/>',
  flag: '<path d="M3.5 14V2.5M3.5 3h8l-1.5 3 1.5 3h-8"/>',
  undo: '<path d="M5.5 3.5 2.5 6.5l3 3"/><path d="M2.5 6.5h7a4 4 0 0 1 0 8H7"/>',
  node: '<circle cx="8" cy="8" r="2.25"/><path d="M8 1.75v4M8 10.25v4M1.75 8h4M10.25 8h4"/>',
  fact: '<path d="M3.25 2.75h9.5v10.5h-9.5Z"/><path d="M5.75 6h4.5M5.75 8.5h4.5M5.75 11h2.5"/>',
  alert: '<path d="M8 2.25 14.25 13H1.75Z"/><path d="M8 6.5v3M8 11.25v.01"/>',
  fit: '<path d="M2.5 5.5v-3h3M10.5 2.5h3v3M13.5 10.5v3h-3M5.5 13.5h-3v-3"/>',
  plus: '<path d="M8 3.5v9M3.5 8h9"/>',
  minus: '<path d="M3.5 8h9"/>',
  replay: '<path d="M2.75 8a5.25 5.25 0 1 0 1.6-3.78"/><path d="M2.5 2.5v3h3"/><path d="M7 6v4l3-2Z" fill="currentColor" stroke="none"/>',
  list: '<path d="M5.5 4h8M5.5 8h8M5.5 12h8M2.5 4h.01M2.5 8h.01M2.5 12h.01"/>',
  graph: '<rect x="1.75" y="5.75" width="4" height="4.5" rx="1"/><rect x="10.25" y="2.25" width="4" height="4" rx="1"/><rect x="10.25" y="9.75" width="4" height="4" rx="1"/><path d="M5.75 8c2.25 0 2-3.75 4.5-3.75M5.75 8c2.25 0 2 3.75 4.5 3.75"/>',
  grid: '<path d="M2.5 2.5h11v11h-11ZM2.5 6.17h11M2.5 9.83h11M6.17 2.5v11M9.83 2.5v11"/>',
  edit: '<path d="M10.75 2.75 13.25 5.25 6 12.5H3.5V10Z"/>',
  download: '<path d="M8 2.5v8M4.5 7 8 10.5 11.5 7M3 13.5h10"/>',
  budget: '<circle cx="8" cy="8" r="5.75"/><path d="M9.75 6.1c-.35-.6-1-.95-1.75-.95-1 0-1.75.6-1.75 1.4 0 1.9 3.5 1 3.5 2.9 0 .8-.75 1.4-1.75 1.4-.8 0-1.45-.35-1.8-1M8 4v1.15M8 10.85V12"/>',
  sparkle: '<path d="M8 2.5v3M8 10.5v3M2.5 8h3M10.5 8h3"/>',
  panelR: '<rect x="2.25" y="2.75" width="11.5" height="10.5" rx="1.5"/><path d="M9.75 2.75v10.5"/>',
} as const

export type IconName = keyof typeof P

const SMALL: Partial<Record<IconName, number>> = { chev: 12, chevR: 12, chevL: 12, arrowR: 12, arrowL: 12, ext: 12, chain: 13 }

export function Icon({ name, size, className, style, title }: {
  name: IconName
  size?: number
  className?: string
  style?: CSSProperties
  title?: string
}) {
  const s = size ?? SMALL[name]
  return <svg
    className={'ico' + (name === 'chev' ? ' chev' : '') + (className ? ' ' + className : '')}
    viewBox="0 0 16 16"
    aria-hidden={title ? undefined : true}
    role={title ? 'img' : undefined}
    aria-label={title}
    style={s ? { width: s, height: s, ...style } : style}
    dangerouslySetInnerHTML={{ __html: P[name] }}
  />
}

/** Guardian mark (shield with a core), used in the rail brand. */
export function Mark() {
  return <svg className="mark" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
    <path d="M9 1.75 15.25 4.5v4.25c0 3.6-2.6 6.4-6.25 7.5-3.65-1.1-6.25-3.9-6.25-7.5V4.5Z" />
    <circle cx="9" cy="9" r="2.25" fill="currentColor" stroke="none" />
  </svg>
}
