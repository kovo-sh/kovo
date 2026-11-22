// Theme integration. The app already decides the theme with
// html[data-appearance] = light | dark | system (localStorage
// `guardian-appearance`, applied before first paint by __root.tsx).
// The run workspace reads and writes that same setting; run.css keys its
// palettes off it. There is no second theme system.
import { useCallback, useEffect, useState } from 'react'

export type Theme = 'light' | 'dark'
const KEY = 'guardian-appearance'

function resolve(): Theme {
  if (typeof document === 'undefined') return 'light'
  const a = document.documentElement.dataset.appearance
  if (a === 'dark' || a === 'light') return a
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

/** Effective theme (resolved from `system`) and a toggle that persists an explicit choice. */
export function useTheme() {
  const [theme, setTheme] = useState<Theme>('light')
  useEffect(() => {
    setTheme(resolve())
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const sync = () => setTheme(resolve())
    mq.addEventListener('change', sync)
    const mo = new MutationObserver(sync)
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-appearance'] })
    return () => { mq.removeEventListener('change', sync); mo.disconnect() }
  }, [])
  const toggle = useCallback(() => {
    const next: Theme = resolve() === 'dark' ? 'light' : 'dark'
    try { localStorage.setItem(KEY, next) } catch { /* private mode */ }
    document.documentElement.dataset.appearance = next
  }, [])
  return { theme, toggle }
}
