// Theme integration. The app decides the theme with html[data-appearance]
// = light | dark | system and html[data-theme] = light | dark (localStorage
// `kovo-appearance`, applied before first paint by __root.tsx).
// Tailwind v4 dark: variants and tokens.css both key off these attributes.
import { useCallback, useEffect, useState } from 'react'

export type Theme = 'light' | 'dark'
const KEY = 'kovo-appearance'

function resolve(): Theme {
  if (typeof document === 'undefined') return 'light'
  const a = document.documentElement.dataset.appearance
  if (a === 'dark' || a === 'light') return a
  const t = document.documentElement.dataset.theme
  if (t === 'dark' || t === 'light') return t
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function syncTheme(mode?: Theme | 'system'): Theme {
  if (typeof document === 'undefined') return 'light'
  if (mode) document.documentElement.dataset.appearance = mode
  const resolved = resolve()
  if (document.documentElement.dataset.theme !== resolved) {
    document.documentElement.dataset.theme = resolved
  }
  return resolved
}

/**
 * Run `flip` with every CSS transition suspended for two frames, so a theme
 * change repaints all surfaces at once instead of rippling through dozens of
 * colour transitions with mixed durations (`.no-transitions` lives in app.css).
 */
function withoutTransitions<T>(flip: () => T): T {
  const root = document.documentElement
  root.classList.add('no-transitions')
  try {
    return flip()
  } finally {
    requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove('no-transitions')))
  }
}

/** Effective theme (resolved from `system`) and a toggle that persists an explicit choice. */
export function useTheme() {
  const [theme, setTheme] = useState<Theme>('light')
  useEffect(() => {
    setTheme(syncTheme())
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const sync = () => setTheme(syncTheme())
    mq.addEventListener('change', sync)
    const mo = new MutationObserver(sync)
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-appearance', 'data-theme'] })
    return () => { mq.removeEventListener('change', sync); mo.disconnect() }
  }, [])
  const toggle = useCallback(() => {
    const next: Theme = resolve() === 'dark' ? 'light' : 'dark'
    try { localStorage.setItem(KEY, next) } catch { /* private mode */ }
    setTheme(withoutTransitions(() => syncTheme(next)))
  }, [])
  return { theme, toggle }
}
