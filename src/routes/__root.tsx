import { createRootRoute, HeadContent, Link, Outlet, Scripts, useRouterState } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { useEffect, useState } from 'react'
import { Brand } from '../components/common.tsx'
import { Button } from '../components/ui/button.tsx'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuGroup, DropdownMenuLabel,
  DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger,
} from '../components/ui/dropdown-menu.tsx'
import styles from '../app.css?url'

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'Kovo Guardian' },
    ],
    links: [{ rel: 'stylesheet', href: styles }],
  }),
  component: Shell,
  shellComponent: Document,
  errorComponent: ({ error }) => <main className="workspace-page">
    <h1>Guardian couldn’t open this view</h1>
    <p className="muted">{error instanceof Error ? error.message : 'This view is unavailable.'}</p>
    <Link to="/">Return to workspace</Link>
  </main>,
})

type Appearance = 'system' | 'light' | 'dark'

function ViewPreferences() {
  const [appearance, setAppearance] = useState<Appearance>('light')
  const [layout, setLayout] = useState('workspace')
  useEffect(() => {
    const saved = localStorage.getItem('guardian-appearance')
    if (saved === 'light' || saved === 'dark' || saved === 'system') {
      setAppearance(saved)
    }
    const savedLayout = localStorage.getItem('guardian-app-layout')
    if (savedLayout === 'canvas' || savedLayout === 'review') setLayout(savedLayout)
  }, [])
  useEffect(() => {
    document.documentElement.dataset.appearance = appearance
    document.documentElement.dataset.appLayout = layout
  }, [appearance, layout])

  const isDark = appearance === 'dark' ||
    (appearance === 'system' && typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: dark)').matches)

  function toggleTheme() {
    const next: Appearance = isDark ? 'light' : 'dark'
    localStorage.setItem('guardian-appearance', next)
    setAppearance(next)
  }

  return <>
    <button
      type="button"
      className="nav-icon-btn"
      onClick={toggleTheme}
      title={isDark ? 'Switch to Light mode (Arctic Canvas)' : 'Switch to Dark mode (Deep Slate-Cobalt)'}
      aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
    >
      {isDark
        ? <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <circle cx="8" cy="8" r="3.2" stroke="currentColor" strokeWidth="1.4" />
            <path d="M8 1.5v1.6M8 12.9v1.6M1.5 8h1.6M12.9 8h1.6M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M12.6 3.4l-1.1 1.1M4.5 11.5l-1.1 1.1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
          </svg>
        : <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path d="M13.2 9.8A5.4 5.4 0 0 1 6.2 2.8a5.5 5.5 0 1 0 7 7Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
          </svg>}
    </button>
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="ghost" className="nav-menu-btn" />}>View</DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuGroup>
          <DropdownMenuLabel>Appearance</DropdownMenuLabel>
          <DropdownMenuRadioGroup value={appearance} onValueChange={(choice: Appearance) => {
            localStorage.setItem('guardian-appearance', choice)
            setAppearance(choice)
          }}>
            <DropdownMenuRadioItem value="light">Light (D3 Arctic)</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="dark">Dark (D4 Slate-Cobalt)</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="system">System</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
        </DropdownMenuGroup>
        <DropdownMenuGroup>
          <DropdownMenuLabel>Layout</DropdownMenuLabel>
          <DropdownMenuRadioGroup value={layout} onValueChange={(choice: string) => {
            localStorage.setItem('guardian-app-layout', choice)
            setLayout(choice)
          }}>
            <DropdownMenuRadioItem value="workspace">Workspace</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="canvas">Canvas</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="review">Review</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  </>
}

function Shell() {
  // The run workspace is full-screen with its own rail and header.
  const runPage = useRouterState({ select: state => state.matches.some(match => match.routeId.startsWith('/runs/$runId')) })
  if (runPage) return <Outlet />
  return <>
    <header className="app-nav">
      <Brand />
      <span className="nav-divider" aria-hidden="true" />
      <nav aria-label="Workspace" className="nav-links">
        <Link to="/">Projects</Link>
      </nav>
      <div className="nav-right">
        <Link to="/settings" className="nav-link">Model settings</Link>
        <ViewPreferences />
      </div>
    </header>
    <Outlet />
  </>
}

function Document({ children }: { children: ReactNode }) {
  return <html lang="en" data-appearance="light">
    <head>
      <HeadContent />
      <script dangerouslySetInnerHTML={{
        __html: `(function(){try{var s=localStorage.getItem('guardian-appearance');if(s==='dark'||s==='light'||s==='system'){document.documentElement.dataset.appearance=s;}}catch(e){}})();`,
      }} />
    </head>
    <body>{children}<Scripts /></body>
  </html>
}
